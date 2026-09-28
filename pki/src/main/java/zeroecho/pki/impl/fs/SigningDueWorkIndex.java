/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *    display the following acknowledgement:
 *    This product includes software developed by the Egothor project.
 *
 * 4. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.impl.fs;

import java.time.Instant;
import java.util.AbstractMap;
import java.util.AbstractSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import zeroecho.pki.spi.store.SignWorkflowStore;

/** Bounded due-work ordering that shares the ledger's resident-byte budget. */
@SuppressWarnings({ "PMD.AvoidLiteralsInIfCondition", "PMD.CloseResource",
        "PMD.AvoidDuplicateLiterals", "PMD.AvoidInstantiatingObjectsInLoops",
        "PMD.CommentRequired", "PMD.CompareObjectsWithEquals",
        "PMD.ConfusingTernary", "PMD.ControlStatementBraces", "PMD.CyclomaticComplexity",
        "PMD.TooManyMethods", "PMD.UseTryWithResources" })
final class SigningDueWorkIndex implements AutoCloseable {
    /* default */ static final int FOUR_GIB_MAXIMUM_WORK = 100_000;
    /* default */ static final int FOUR_GIB_ORDERED_LIMIT = 1_000_000;
    private static final int MAX_OPERATION_ID_BYTES = 4096;
    /* Hash/tree/AVL nodes, ordering key, slots, descriptor and alignment. */
    private static final long ENTRY_FIXED_BYTES = 224L;
    private static final long SELECTION_FIXED_BYTES = 160L;
    private static final long SELECTION_ENTRY_BYTES = 16L;
    private static final long SELECTION_GENERATION_BYTES = 32L;

    private final int maximumWork;
    private final SigningIndexCapacityBudget capacity;
    private final SigningGenerationRegistry generations;
    private final SigningGenerationRegistry.Owner referenceOwner;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private final Lock readLock = lock.readLock();
    private final Lock writeLock = lock.writeLock();
    private NavigableMap<DueKey, DescriptorSlot> ordered = new TreeMap<>();
    private Map<CanonicalOperationId, OperationSlot> byOperation = new HashMap<>();
    private final Set<Admission> admissions = new HashSet<>();
    private IdentityNode identityRoot;
    private long lastIdentityPageNodesVisited;
    private long canonicalIdBytes;
    private long reservedBytes;
    private long admittedIdentities;
    private int outstandingAdmissions;
    private boolean closed;

    /* default */ SigningDueWorkIndex(int maximumWork, SigningIndexCapacityBudget capacity,
            SigningGenerationRegistry generations,
            SigningGenerationRegistry.Owner referenceOwner) {
        if (maximumWork <= 0 || maximumWork > FOUR_GIB_ORDERED_LIMIT) {
            throw new IllegalArgumentException("signing due-work capacity is invalid");
        }
        this.maximumWork = maximumWork;
        this.capacity = Objects.requireNonNull(capacity, "capacity");
        this.generations = Objects.requireNonNull(generations, "generations");
        this.referenceOwner = Objects.requireNonNull(referenceOwner, "referenceOwner");
        if (referenceOwner != SigningGenerationRegistry.Owner.DUE
                && referenceOwner != SigningGenerationRegistry.Owner.OWNER) {
            throw new IllegalArgumentException("signing ordered-work reference owner is invalid");
        }
    }

    /** Validates and encodes one boundary identity exactly once for later reuse. */
    /* default */ CanonicalOperationId admit(String operationId) {
        Objects.requireNonNull(operationId, "operationId");
        return new CanonicalOperationId(operationId,
                SigningFormatSupport.strictUtf8(operationId, MAX_OPERATION_ID_BYTES));
    }

    /** Installs identity-ordered recovered work with linear bulk construction. */
    /* default */ void recoverAll(List<RecoveryEntry> identityOrdered) {
        Objects.requireNonNull(identityOrdered, "identityOrdered");
        writeLock.lock();
        try {
            requireOpen();
            if (!ordered.isEmpty() || !byOperation.isEmpty() || identityRoot != null
                    || outstandingAdmissions != 0 || identityOrdered.size() > maximumWork) {
                throw new IllegalStateException("signing due-work recovery target is invalid");
            }
            long candidateCanonicalBytes = validateRecoveryIdentityOrder(identityOrdered);
            long candidateBytes = Math.multiplyExact(identityOrdered.size(), ENTRY_FIXED_BYTES);
            SigningIndexCapacityBudget.Reservation reservation = capacity.reserve(candidateBytes);
            try {
                List<OperationSlot> identitySlots = recoverySlots(identityOrdered);
                List<OperationSlot> dueOrdered = orderRecoveryByDueTime(identitySlots);
                NavigableMap<DueKey, DescriptorSlot> candidateOrdered =
                        new TreeMap<>(new SortedRecoveryMap(recoveryEntries(dueOrdered)));
                Map<CanonicalOperationId, OperationSlot> candidateByOperation =
                        new HashMap<>(hashCapacity(identitySlots.size()));
                Map<Long, Integer> generationCounts = new HashMap<>();
                for (OperationSlot slot : identitySlots) {
                    candidateByOperation.put(slot.operationId, slot);
                    generationCounts.merge(slot.publishedDescriptor.pointer.generationId(),
                            1, Math::addExact);
                }
                SigningGenerationRegistry.CurrentReferences references =
                        generations.acquireCurrentCounts(referenceOwner, generationCounts);
                try {
                    IdentityNode candidateRoot = buildBalancedIdentity(
                            identitySlots, 0, identitySlots.size(), null);
                    ordered = candidateOrdered;
                    byOperation = candidateByOperation;
                    identityRoot = candidateRoot;
                    canonicalIdBytes = candidateCanonicalBytes;
                    reservedBytes = candidateBytes;
                    admittedIdentities = identitySlots.size();
                    references.transfer();
                    reservation.transfer();
                } finally {
                    references.close();
                }
            } finally {
                reservation.close();
            }
        } finally {
            writeLock.unlock();
        }
    }

    /** Reserves one new due-work entry before its operation identity exists. */
    /* default */ Admission reserveAdmission() {
        writeLock.lock();
        try {
            requireOpen();
            if (byOperation.size() + outstandingAdmissions >= maximumWork) {
                throw new CapacityExhaustedException();
            }
            SigningIndexCapacityBudget.Reservation reservation = capacity.reserve(ENTRY_FIXED_BYTES);
            Admission admission = new Admission(reservation);
            admissions.add(admission);
            outstandingAdmissions++;
            return admission;
        } finally {
            writeLock.unlock();
        }
    }

    /** Internal typed boundary used by the filesystem store admission façade. */
    /* default */ static final class CapacityExhaustedException extends IllegalStateException {
        @java.io.Serial private static final long serialVersionUID = 1L;

        private CapacityExhaustedException() {
            super("signing due-work capacity is exhausted");
        }
    }

    /** Inserts or exactly replaces one non-retired work descriptor. */
    /* default */ void update(CanonicalOperationId operationId, Instant nextEligibleAt,
            SignWorkflowStore.State state, SigningMvccIndex.RecordPointer pointer) {
        try (PreparedChange prepared = prepareUpdate(operationId, nextEligibleAt, state, pointer)) {
            prepared.publish();
        }
    }

    /** Preallocates one hidden due-work replacement for later allocation-free publication. */
    /* default */ PreparedChange prepareUpdate(CanonicalOperationId operationId,
            Instant nextEligibleAt, SignWorkflowStore.State state,
            SigningMvccIndex.RecordPointer pointer) {
        return prepareUpdate(operationId, nextEligibleAt, state, pointer,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /* default */ PreparedChange prepareUpdate(CanonicalOperationId operationId,
            Instant nextEligibleAt, SignWorkflowStore.State state,
            SigningMvccIndex.RecordPointer pointer,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
        return prepareUpdate(null, operationId, nextEligibleAt, state, pointer, null, false,
                false, admissionClass);
    }

    /* default */ PreparedChange prepareUpdate(CanonicalOperationId operationId,
            Instant nextEligibleAt, SignWorkflowStore.State state,
            SigningMvccIndex.RecordPointer pointer,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass,
            SignWorkflowStore.SchedulingCoordinates scheduling) {
        return prepareUpdate(null, operationId, nextEligibleAt, state, pointer,
                Objects.requireNonNull(scheduling, "scheduling"), false, false, admissionClass);
    }

    /** Consumes one bound admission into a hidden initial due-work entry. */
    /* default */ PreparedChange prepareUpdate(Admission admission,
            CanonicalOperationId operationId, Instant nextEligibleAt,
            SignWorkflowStore.State state, SigningMvccIndex.RecordPointer pointer) {
        Objects.requireNonNull(admission, "admission");
        return prepareUpdate(admission, operationId, nextEligibleAt, state, pointer, null, false,
                false, SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /* default */ PreparedChange prepareUpdate(Admission admission,
            CanonicalOperationId operationId, Instant nextEligibleAt,
            SignWorkflowStore.State state, SigningMvccIndex.RecordPointer pointer,
            SignWorkflowStore.SchedulingCoordinates scheduling) {
        Objects.requireNonNull(admission, "admission");
        return prepareUpdate(admission, operationId, nextEligibleAt, state, pointer,
                Objects.requireNonNull(scheduling, "scheduling"), false, false,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /* default */ PreparedChange prepareRetained(CanonicalOperationId operationId,
            Instant orderedAt, SigningMvccIndex.RecordPointer pointer) {
        return prepareRetained(operationId, orderedAt, pointer,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /* default */ PreparedChange prepareRetained(CanonicalOperationId operationId,
            Instant orderedAt, SigningMvccIndex.RecordPointer pointer,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
        return prepareUpdate(null, operationId, orderedAt, SignWorkflowStore.State.RETIRED,
                pointer, null, true, false, admissionClass);
    }

    /* default */ PreparedChange prepareMalformed(CanonicalOperationId operationId,
            SigningMvccIndex.RecordPointer pointer) {
        return prepareUpdate(null, operationId, Instant.MIN, SignWorkflowStore.State.INTENT,
                pointer, null, true, true,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /* default */ PreparedChange prepareMalformed(CanonicalOperationId operationId,
            SigningMvccIndex.RecordPointer pointer,
            SignWorkflowStore.SchedulingCoordinates scheduling) {
        return prepareUpdate(null, operationId, Instant.MIN, SignWorkflowStore.State.INTENT,
                pointer, Objects.requireNonNull(scheduling, "scheduling"), true, true,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /* default */ PreparedChange prepareMalformed(Admission admission,
            CanonicalOperationId operationId, SigningMvccIndex.RecordPointer pointer) {
        Objects.requireNonNull(admission, "admission");
        return prepareUpdate(admission, operationId, Instant.MIN,
                SignWorkflowStore.State.INTENT, pointer, null, true, true,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /* default */ PreparedChange prepareMalformed(Admission admission,
            CanonicalOperationId operationId, SigningMvccIndex.RecordPointer pointer,
            SignWorkflowStore.SchedulingCoordinates scheduling) {
        Objects.requireNonNull(admission, "admission");
        return prepareUpdate(admission, operationId, Instant.MIN,
                SignWorkflowStore.State.INTENT, pointer,
                Objects.requireNonNull(scheduling, "scheduling"), true, true,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    private PreparedChange prepareUpdate(Admission admission,
            CanonicalOperationId operationId,
            Instant nextEligibleAt, SignWorkflowStore.State state,
            SigningMvccIndex.RecordPointer pointer,
            SignWorkflowStore.SchedulingCoordinates scheduling, boolean retainRetired,
            boolean malformed,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(pointer, "pointer");
        Objects.requireNonNull(admissionClass, "admissionClass");
        if (state == SignWorkflowStore.State.RETIRED && !retainRetired) {
            if (admission != null) {
                throw new IllegalArgumentException(
                        "signing due-work admission cannot prepare retirement");
            }
            return prepareRemove(operationId);
        }
        Objects.requireNonNull(nextEligibleAt, "nextEligibleAt");
        writeLock.lock();
        try {
            requireOpen();
            OperationSlot operationSlot = byOperation.get(operationId);
            requireReusedIdentity(operationId, operationSlot);
            DueKey previous = operationSlot == null ? null : operationSlot.published;
            validatePreparedUpdate(admission, operationId, operationSlot, previous);
            long delta = previous == null ? ENTRY_FIXED_BYTES : 0L;
            SigningIndexCapacityBudget.Reservation reservation = admission == null
                    ? capacity.reserve(delta, admissionClass) : admission.reservation;
            ReplacementTarget replacementTarget = new ReplacementTarget(
                    operationSlot, previous, reservation);
            return prepareReplacement(admission, operationId, nextEligibleAt, state, pointer,
                    scheduling, malformed, replacementTarget);
        } finally {
            writeLock.unlock();
        }
    }

    private void validatePreparedUpdate(Admission admission, CanonicalOperationId operationId,
            OperationSlot operationSlot, DueKey previous) {
        if (operationSlot != null && operationSlot.pending) {
            throw new IllegalStateException("signing due-work operation already has a prepared change");
        }
        if (previous != null) {
            if (admission != null) {
                throw new IllegalArgumentException(
                        "signing due-work admission cannot replace existing work");
            }
            return;
        }
        if (admission != null) {
            validateAdmission(admission, operationId);
            return;
        }
        if (byOperation.size() + outstandingAdmissions >= maximumWork) {
            throw new IllegalStateException("signing due-work capacity is exhausted");
        }
    }

    private PreparedChange prepareReplacement(Admission admission, CanonicalOperationId operationId,
            Instant nextEligibleAt, SignWorkflowStore.State state, SigningMvccIndex.RecordPointer pointer,
            SignWorkflowStore.SchedulingCoordinates scheduling, boolean malformed,
            ReplacementTarget replacementTarget) {
        OperationSlot operationSlot = replacementTarget.operationSlot;
        DueKey previous = replacementTarget.previous;
        SigningIndexCapacityBudget.Reservation reservation = replacementTarget.reservation;
        SigningGenerationRegistry.CurrentReferences reference = null;
        boolean transferred = false;
        boolean consumed = false;
        try {
            reference = generations.acquireCurrent(referenceOwner,
                    List.of(pointer.generationId()));
            DueKey replacement = new DueKey(nextEligibleAt, operationId);
            DescriptorSlot previousSlot = previousDescriptor(previous);
            SignWorkflowStore.SchedulingCoordinates effectiveScheduling = scheduling;
            if (effectiveScheduling == null && previousSlot != null) {
                effectiveScheduling = previousSlot.published.scheduling;
            }
            WorkDescriptor descriptor = new WorkDescriptor(operationId.value,
                    nextEligibleAt, state, pointer, effectiveScheduling, malformed);
            DescriptorSlot replacementSlot = ordered.get(replacement);
            boolean insertedReplacement = replacementSlot == null;
            replacementSlot = prepareDescriptorSlot(replacement, replacementSlot, previousSlot);
            OperationSlot target = operationSlot;
            if (target == null) {
                target = new OperationSlot(operationId);
                if (admission != null) {
                    consumeAdmission(admission, operationId);
                    consumed = true;
                }
                byOperation.put(operationId, target);
                insertIdentity(target);
            }
            target.pending = true;
            replacementSlot.pending = descriptor;
            long delta = previous == null ? ENTRY_FIXED_BYTES : 0L;
            PreparedChange result = new PreparedChange(target, previous, previousSlot,
                    replacement, replacementSlot, insertedReplacement, descriptor, delta,
                    reservation, reference);
            transferred = true;
            return result;
        } finally {
            if (!transferred) {
                if (reference != null) {
                    reference.close();
                }
                if (admission == null || consumed) {
                    reservation.close();
                }
            }
        }
    }

    private DescriptorSlot previousDescriptor(DueKey previous) {
        DescriptorSlot previousSlot = previous == null ? null : ordered.get(previous);
        if (previous != null && (previousSlot == null || previousSlot.published == null)) {
            throw new IllegalStateException("signing due-work index is inconsistent");
        }
        return previousSlot;
    }

    private DescriptorSlot prepareDescriptorSlot(DueKey replacement, DescriptorSlot replacementSlot,
            DescriptorSlot previousSlot) {
        if (replacementSlot == null) {
            DescriptorSlot inserted = new DescriptorSlot();
            ordered.put(replacement, inserted);
            return inserted;
        }
        if (replacementSlot != previousSlot || replacementSlot.pending != null) {
            throw new IllegalStateException("signing due-work ordering identity is duplicated");
        }
        return replacementSlot;
    }

    /* default */ boolean remove(CanonicalOperationId operationId) {
        return removeInternal(Objects.requireNonNull(operationId, "operationId"));
    }

    /* default */ void retire(CanonicalOperationId operationId) {
        removeInternal(Objects.requireNonNull(operationId, "operationId"));
    }

    /* default */ PreparedChange prepareRemove(CanonicalOperationId operationId) {
        Objects.requireNonNull(operationId, "operationId");
        writeLock.lock();
        try {
            requireOpen();
            OperationSlot slot = byOperation.get(operationId);
            requireReusedIdentity(operationId, slot);
            if (slot == null || slot.published == null) return new PreparedChange();
            if (slot.pending) {
                throw new IllegalStateException("signing due-work operation already has a prepared change");
            }
            DescriptorSlot previous = ordered.get(slot.published);
            if (previous == null || previous.published == null) {
                throw new IllegalStateException("signing due-work index is inconsistent");
            }
            slot.pending = true;
            return new PreparedChange(slot, slot.published, previous, null, null,
                    false, null, -ENTRY_FIXED_BYTES, null, null);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Pinned immutable selection ordered by time and admitted canonical identity.
     * Selection takes {@code O(log W + D)} time and returns {@code O(D)} memory,
     * where {@code W} is indexed work and {@code D} is the selection bound.
     */
    /* default */ Selection selectThrough(Instant cutoffInclusive, int maximumResults) {
        Objects.requireNonNull(cutoffInclusive, "cutoffInclusive");
        if (maximumResults <= 0) {
            throw new IllegalArgumentException("signing due-work selection bound is invalid");
        }
        readLock.lock();
        try {
            requireOpen();
            List<WorkDescriptor> result = new ArrayList<>(Math.min(maximumResults, ordered.size()));
            for (Map.Entry<DueKey, DescriptorSlot> entry : ordered.entrySet()) {
                if (entry.getKey().nextEligibleAt.isAfter(cutoffInclusive)
                        || result.size() == maximumResults) {
                    break;
                }
                WorkDescriptor descriptor = entry.getValue().published;
                if (descriptor != null) result.add(descriptor);
            }
            List<WorkDescriptor> immutable = List.copyOf(result);
            Set<Long> identities = new HashSet<>();
            for (WorkDescriptor descriptor : immutable) {
                identities.add(descriptor.pointer.generationId());
            }
            long bytes = Math.addExact(SELECTION_FIXED_BYTES,
                    Math.multiplyExact(immutable.size(), SELECTION_ENTRY_BYTES));
            bytes = Math.addExact(bytes,
                    Math.multiplyExact(identities.size(), SELECTION_GENERATION_BYTES));
            SigningIndexCapacityBudget.Reservation reservation = capacity.reserve(bytes);
            try {
                SigningGenerationRegistry.SnapshotPins pins = generations.pinSnapshot(identities);
                boolean installed = false;
                try {
                    Selection selection = new Selection(immutable, pins, capacity, bytes);
                    reservation.transfer();
                    installed = true;
                    return selection;
                } finally {
                    if (!installed) {
                        pins.close();
                    }
                }
            } finally {
                reservation.close();
            }
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Pinned due page ordered by canonical operation identity with augmented pruning.
     * For nonempty indexed work {@code W} and {@code R} returned records, define
     * {@code D = max(1, R)}, so {@code 1 <= D <= W}; the page-bound worst case uses
     * {@code D = min(maximumResults, W)}. Selection then takes worst-case
     * {@code Theta(log W + D + D log(W / D))} time, returns {@code O(D)} immutable
     * memory, and uses {@code O(D + log W)} total auxiliary memory. An empty index
     * returns an empty page in constant time and memory.
     */
    /* default */ IdentitySelection pageThrough(Instant cutoffInclusive,
            java.util.Optional<String> exclusiveCursor,
            java.util.Optional<String> inclusiveHighWatermark, int maximumResults) {
        Objects.requireNonNull(cutoffInclusive, "cutoffInclusive");
        Objects.requireNonNull(exclusiveCursor, "exclusiveCursor");
        Objects.requireNonNull(inclusiveHighWatermark, "inclusiveHighWatermark");
        if (maximumResults <= 0) {
            throw new IllegalArgumentException("signing due-work page bound is invalid");
        }
        byte[] lower = exclusiveCursor.map(value ->
                SigningFormatSupport.strictUtf8(value, MAX_OPERATION_ID_BYTES)).orElse(null);
        byte[] upper = inclusiveHighWatermark.map(value ->
                SigningFormatSupport.strictUtf8(value, MAX_OPERATION_ID_BYTES)).orElse(null);
        readLock.lock();
        try {
            requireOpen();
            PageCollector collector = new PageCollector(cutoffInclusive, lower, upper,
                    Math.addExact(maximumResults, 1));
            collectIdentity(identityRoot, collector);
            boolean endReached = collector.records.size() <= maximumResults;
            List<WorkDescriptor> result = endReached ? collector.records
                    : collector.records.subList(0, maximumResults);
            List<WorkDescriptor> immutable = List.copyOf(result);
            java.util.Optional<String> highWatermark = greatestEligible(identityRoot,
                    cutoffInclusive, upper, collector);
            lastIdentityPageNodesVisited = collector.visited;
            return identitySelection(immutable, highWatermark, endReached);
        } finally {
            readLock.unlock();
        }
    }

    /** Nodes inspected by the last identity page, including its high-watermark search. */
    /* default */ long lastIdentityPageNodesVisited() {
        readLock.lock();
        try {
            return lastIdentityPageNodesVisited;
        } finally {
            readLock.unlock();
        }
    }

    /* default */ boolean contains(CanonicalOperationId operationId) {
        Objects.requireNonNull(operationId, "operationId");
        readLock.lock();
        try {
            OperationSlot slot = byOperation.get(operationId);
            requireReusedIdentity(operationId, slot);
            return slot != null && slot.published != null;
        } finally {
            readLock.unlock();
        }
    }

    /* default */ Statistics statistics() {
        readLock.lock();
        try {
            requireOpen();
            return new Statistics(ordered.size(), maximumWork, canonicalIdBytes,
                    reservedBytes, reservedBytes, capacity.snapshot().reservedBytes(), admittedIdentities);
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public void close() {
        writeLock.lock();
        try {
            if (closed) {
                return;
            }
            closed = true;
            for (Admission admission : admissions) {
                admission.active = false;
                admission.reservation.close();
            }
            admissions.clear();
            outstandingAdmissions = 0;
            if (reservedBytes > 0L) {
                Map<Long, Integer> counts = new HashMap<>();
                for (DescriptorSlot slot : ordered.values()) {
                    if (slot.published != null) {
                        counts.merge(slot.published.pointer.generationId(), 1, Math::addExact);
                    }
                }
                generations.releaseCurrentCounts(referenceOwner, counts);
                capacity.releaseCommitted(reservedBytes);
                reservedBytes = 0L;
            }
            ordered.clear();
            byOperation.clear();
            identityRoot = null;
            canonicalIdBytes = 0L;
        } finally {
            writeLock.unlock();
        }
    }

    private boolean removeInternal(CanonicalOperationId operationId) {
        writeLock.lock();
        try {
            requireOpen();
            OperationSlot operationSlot = byOperation.get(operationId);
            requireReusedIdentity(operationId, operationSlot);
            if (operationSlot == null || operationSlot.published == null) {
                return false;
            }
            try (PreparedChange prepared = prepareRemove(operationId)) {
                prepared.publish();
            }
            return true;
        } finally {
            writeLock.unlock();
        }
    }

    private static void requireReusedIdentity(CanonicalOperationId supplied, OperationSlot existing) {
        if (existing != null && existing.operationId != supplied) {
            throw new IllegalArgumentException("signing operation identity object was not reused");
        }
    }

    private void bindAdmission(Admission admission, CanonicalOperationId operationId) {
        Objects.requireNonNull(operationId, "operationId");
        writeLock.lock();
        try {
            requireOpen();
            requireOwnedActiveAdmission(admission);
            if (admission.operationId != null) {
                throw new IllegalStateException("signing due-work admission is already bound");
            }
            admission.operationId = operationId;
        } finally {
            writeLock.unlock();
        }
    }

    private void validateAdmission(Admission admission, CanonicalOperationId operationId) {
        requireOwnedActiveAdmission(admission);
        if (admission.operationId != operationId) {
            throw new IllegalArgumentException("signing due-work admission identity is mismatched");
        }
    }

    private void requireOwnedActiveAdmission(Admission admission) {
        if (admission.owner != this) {
            throw new IllegalArgumentException("signing due-work admission is foreign");
        }
        if (!admission.active || !admissions.contains(admission)) {
            throw new IllegalStateException("signing due-work admission is not active");
        }
    }

    private void consumeAdmission(Admission admission, CanonicalOperationId operationId) {
        validateAdmission(admission, operationId);
        admission.active = false;
        if (!admissions.remove(admission) || outstandingAdmissions <= 0) {
            throw new IllegalStateException("signing due-work admission accounting is inconsistent");
        }
        outstandingAdmissions--;
    }

    private void closeAdmission(Admission admission) {
        writeLock.lock();
        try {
            if (!admission.active) return;
            requireOwnedActiveAdmission(admission);
            admission.active = false;
            admissions.remove(admission);
            outstandingAdmissions--;
            admission.reservation.close();
        } finally {
            writeLock.unlock();
        }
    }

    private IdentitySelection identitySelection(List<WorkDescriptor> records,
            java.util.Optional<String> highWatermark, boolean endReached) {
        Set<Long> identities = new HashSet<>();
        for (WorkDescriptor descriptor : records) identities.add(descriptor.pointer.generationId());
        long bytes = Math.addExact(SELECTION_FIXED_BYTES,
                Math.multiplyExact(records.size(), SELECTION_ENTRY_BYTES));
        bytes = Math.addExact(bytes,
                Math.multiplyExact(identities.size(), SELECTION_GENERATION_BYTES));
        SigningIndexCapacityBudget.Reservation reservation = capacity.reserve(bytes);
        try {
            SigningGenerationRegistry.SnapshotPins pins = generations.pinSnapshot(identities);
            boolean installed = false;
            try {
                IdentitySelection selection = new IdentitySelection(records, highWatermark,
                        endReached, pins, capacity, bytes);
                reservation.transfer();
                installed = true;
                return selection;
            } finally {
                if (!installed) pins.close();
            }
        } finally {
            reservation.close();
        }
    }

    private static long validateRecoveryIdentityOrder(List<RecoveryEntry> entries) {
        CanonicalOperationId previous = null;
        long bytes = 0L;
        for (RecoveryEntry entry : entries) {
            Objects.requireNonNull(entry, "recoveryEntry");
            if (previous != null && previous.compareTo(entry.operationId) >= 0) {
                throw new IllegalArgumentException(
                        "signing due-work recovery identity order is invalid");
            }
            previous = entry.operationId;
            bytes = Math.addExact(bytes, entry.operationId.bytes.length);
        }
        return bytes;
    }

    private static List<OperationSlot> recoverySlots(List<RecoveryEntry> entries) {
        List<OperationSlot> slots = new ArrayList<>(entries.size());
        for (RecoveryEntry entry : entries) {
            OperationSlot slot = new OperationSlot(entry.operationId);
            DueKey key = new DueKey(entry.nextEligibleAt, entry.operationId);
            WorkDescriptor descriptor = new WorkDescriptor(entry.operationId.value,
                    entry.nextEligibleAt, entry.state, entry.pointer, entry.scheduling,
                    entry.malformed);
            slot.published = key;
            slot.publishedDescriptor = descriptor;
            slots.add(slot);
        }
        return slots;
    }

    /** Stable fixed-width radix order; identity order breaks equal timestamps. */
    private static List<OperationSlot> orderRecoveryByDueTime(List<OperationSlot> identityOrdered) {
        OperationSlot[] ordered = identityOrdered.toArray(OperationSlot[]::new);
        OperationSlot[] scratch = new OperationSlot[ordered.length];
        int[] counts = new int[256];
        int[] positions = new int[counts.length];
        for (int pass = 0; pass < 12; pass++) {
            Arrays.fill(counts, 0);
            for (OperationSlot slot : ordered) {
                counts[timeSymbol(slot.published.nextEligibleAt, pass)]++;
            }
            int position = 0;
            for (int symbol = 0; symbol < counts.length; symbol++) {
                positions[symbol] = position;
                position += counts[symbol];
            }
            for (OperationSlot slot : ordered) {
                int symbol = timeSymbol(slot.published.nextEligibleAt, pass);
                scratch[positions[symbol]++] = slot;
            }
            OperationSlot[] exchanged = ordered;
            ordered = scratch;
            scratch = exchanged;
        }
        return List.copyOf(Arrays.asList(ordered));
    }

    private static int timeSymbol(Instant instant, int pass) {
        if (pass < Integer.BYTES) {
            return instant.getNano() >>> pass * Byte.SIZE & 0xff;
        }
        long sortableSeconds = instant.getEpochSecond() ^ Long.MIN_VALUE;
        return (int) (sortableSeconds >>> (pass - Integer.BYTES) * Byte.SIZE & 0xffL);
    }

    private static List<Map.Entry<DueKey, DescriptorSlot>> recoveryEntries(
            List<OperationSlot> orderedSlots) {
        List<Map.Entry<DueKey, DescriptorSlot>> entries = new ArrayList<>(orderedSlots.size());
        DueKey previous = null;
        for (OperationSlot slot : orderedSlots) {
            DueKey key = slot.published;
            if (previous != null && previous.compareTo(key) >= 0) {
                throw new IllegalArgumentException("signing due-work recovery order is invalid");
            }
            DescriptorSlot descriptor = new DescriptorSlot();
            descriptor.published = slot.publishedDescriptor;
            entries.add(Map.entry(key, descriptor));
            previous = key;
        }
        return entries;
    }

    private static IdentityNode buildBalancedIdentity(List<OperationSlot> slots,
            int from, int to, IdentityNode parent) {
        if (from >= to) {
            return null;
        }
        int middle = (from + to) >>> 1;
        OperationSlot slot = slots.get(middle);
        IdentityNode node = new IdentityNode(slot);
        slot.identityNode = node;
        node.parent = parent;
        node.left = buildBalancedIdentity(slots, from, middle, node);
        node.right = buildBalancedIdentity(slots, middle + 1, to, node);
        refresh(node);
        return node;
    }

    private static int hashCapacity(int entries) {
        if (entries == 0) {
            return 1;
        }
        long capacity = Math.addExact(entries, Math.max(1L, entries / 3L));
        return (int) Math.min(Integer.MAX_VALUE, capacity);
    }

    private void insertIdentity(OperationSlot operationSlot) {
        IdentityNode inserted = new IdentityNode(operationSlot);
        operationSlot.identityNode = inserted;
        if (identityRoot == null) {
            identityRoot = inserted;
            return;
        }
        IdentityNode cursor = identityRoot;
        while (true) {
            int order = compareIdentity(operationSlot.operationId.bytes,
                    cursor.operationSlot.operationId.bytes);
            if (order == 0) throw new IllegalStateException("signing identity ordering is duplicated");
            if (order < 0) {
                if (cursor.left == null) {
                    cursor.left = inserted;
                    inserted.parent = cursor;
                    break;
                }
                cursor = cursor.left;
            } else {
                if (cursor.right == null) {
                    cursor.right = inserted;
                    inserted.parent = cursor;
                    break;
                }
                cursor = cursor.right;
            }
        }
        rebalanceFrom(inserted.parent);
    }

    private void removeIdentity(IdentityNode node) {
        while (node.left != null && node.right != null) {
            if (height(node.left) > height(node.right)) rotateRight(node);
            else rotateLeft(node);
        }
        IdentityNode replacement = node.left == null ? node.right : node.left;
        IdentityNode parent = node.parent;
        replaceChild(parent, node, replacement);
        node.parent = null;
        node.left = null;
        node.right = null;
        if (parent != null) rebalanceFrom(parent);
        else if (identityRoot != null) refresh(identityRoot);
    }

    private void rebalanceFrom(IdentityNode start) {
        IdentityNode node = start;
        while (node != null) {
            refresh(node);
            int difference = height(node.left) - height(node.right);
            IdentityNode parent;
            if (difference > 1) {
                if (height(node.left.left) < height(node.left.right)) rotateLeft(node.left);
                parent = rotateRight(node).parent;
            } else if (difference < -1) {
                if (height(node.right.right) < height(node.right.left)) rotateRight(node.right);
                parent = rotateLeft(node).parent;
            } else {
                parent = node.parent;
            }
            node = parent;
        }
    }

    private IdentityNode rotateLeft(IdentityNode node) {
        IdentityNode pivot = node.right;
        IdentityNode parent = node.parent;
        replaceChild(parent, node, pivot);
        node.right = pivot.left;
        if (node.right != null) node.right.parent = node;
        pivot.left = node;
        node.parent = pivot;
        refresh(node);
        refresh(pivot);
        return pivot;
    }

    private IdentityNode rotateRight(IdentityNode node) {
        IdentityNode pivot = node.left;
        IdentityNode parent = node.parent;
        replaceChild(parent, node, pivot);
        node.left = pivot.right;
        if (node.left != null) node.left.parent = node;
        pivot.right = node;
        node.parent = pivot;
        refresh(node);
        refresh(pivot);
        return pivot;
    }

    private void replaceChild(IdentityNode parent, IdentityNode current, IdentityNode replacement) {
        if (parent == null) identityRoot = replacement;
        else if (parent.left == current) parent.left = replacement;
        else if (parent.right == current) parent.right = replacement;
        else throw new IllegalStateException("signing identity tree parent is inconsistent");
        if (replacement != null) replacement.parent = parent;
    }

    private static void refresh(IdentityNode node) {
        node.height = Math.max(height(node.left), height(node.right)) + 1;
        Instant minimum = node.operationSlot.publishedDescriptor == null ? null
                : node.operationSlot.publishedDescriptor.nextEligibleAt;
        minimum = minimum(minimum, node.left == null ? null : node.left.minimumEligibleAt);
        node.minimumEligibleAt = minimum(minimum,
                node.right == null ? null : node.right.minimumEligibleAt);
    }

    private static Instant minimum(Instant first, Instant second) {
        if (first == null) return second;
        if (second == null) return first;
        return first.compareTo(second) <= 0 ? first : second;
    }

    private static int height(IdentityNode node) { return node == null ? 0 : node.height; }

    private static int compareIdentity(byte[] first, byte[] second) {
        return Arrays.compareUnsigned(first, second);
    }

    private static void collectIdentity(IdentityNode node, PageCollector collector) {
        if (node == null) return;
        collector.visited++;
        if (collector.records.size() >= collector.maximum || node.minimumEligibleAt == null
                || node.minimumEligibleAt.isAfter(collector.cutoff)) return;
        byte[] identity = node.operationSlot.operationId.bytes;
        if (collector.lower == null || compareIdentity(identity, collector.lower) > 0) {
            collectIdentity(node.left, collector);
        }
        if (collector.records.size() >= collector.maximum) return;
        WorkDescriptor descriptor = node.operationSlot.publishedDescriptor;
        if (descriptor != null && !descriptor.nextEligibleAt.isAfter(collector.cutoff)
                && (collector.lower == null || compareIdentity(identity, collector.lower) > 0)
                && (collector.upper == null || compareIdentity(identity, collector.upper) <= 0)) {
            collector.records.add(descriptor);
        }
        if (collector.upper == null || compareIdentity(identity, collector.upper) < 0) {
            collectIdentity(node.right, collector);
        }
    }

    private static java.util.Optional<String> greatestEligible(IdentityNode node, Instant cutoff,
            byte[] upper, PageCollector collector) {
        if (node == null) return java.util.Optional.empty();
        collector.visited++;
        if (node.minimumEligibleAt == null
                || node.minimumEligibleAt.isAfter(cutoff)) return java.util.Optional.empty();
        byte[] identity = node.operationSlot.operationId.bytes;
        if (upper == null || compareIdentity(identity, upper) < 0) {
            java.util.Optional<String> right = greatestEligible(node.right, cutoff, upper, collector);
            if (right.isPresent()) return right;
        }
        WorkDescriptor descriptor = node.operationSlot.publishedDescriptor;
        if (descriptor != null && !descriptor.nextEligibleAt.isAfter(cutoff)
                && (upper == null || compareIdentity(identity, upper) <= 0)) {
            return java.util.Optional.of(descriptor.operationId);
        }
        return greatestEligible(node.left, cutoff, upper, collector);
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("signing due-work index is closed");
        }
    }

    /** Opaque one-shot ownership of one not-yet-published due-work entry. */
    /* default */ final class Admission implements AutoCloseable {
        private final SigningDueWorkIndex owner = SigningDueWorkIndex.this;
        private final SigningIndexCapacityBudget.Reservation reservation;
        private CanonicalOperationId operationId;
        private boolean active = true;

        private Admission(SigningIndexCapacityBudget.Reservation reservation) {
            this.reservation = reservation;
        }

        /* default */ void bind(CanonicalOperationId operationId) {
            bindAdmission(this, operationId);
        }

        @Override
        public void close() {
            closeAdmission(this);
        }
    }

    /** One decoded active state supplied in strict canonical-identity order. */
    /* default */ record RecoveryEntry(CanonicalOperationId operationId,
            Instant nextEligibleAt, SignWorkflowStore.State state,
            SigningMvccIndex.RecordPointer pointer,
            SignWorkflowStore.SchedulingCoordinates scheduling, boolean malformed) {
        /* default */ RecoveryEntry(CanonicalOperationId operationId, Instant nextEligibleAt,
                SignWorkflowStore.State state, SigningMvccIndex.RecordPointer pointer,
                boolean malformed) {
            this(operationId, nextEligibleAt, state, pointer, null, malformed);
        }
        RecoveryEntry {
            Objects.requireNonNull(operationId, "operationId");
            Objects.requireNonNull(nextEligibleAt, "nextEligibleAt");
            Objects.requireNonNull(state, "state");
            Objects.requireNonNull(pointer, "pointer");
        }
    }

    private record ReplacementTarget(OperationSlot operationSlot, DueKey previous,
            SigningIndexCapacityBudget.Reservation reservation) {
    }

    /** One validated identity object reused by all lifecycle transitions. */
    /* default */ static final class CanonicalOperationId {
        private final String value;
        private final byte[] bytes;
        private final int hashCode;

        private CanonicalOperationId(String value, byte[] bytes) {
            this.value = value;
            this.bytes = bytes;
            this.hashCode = Arrays.hashCode(bytes);
        }

        @Override
        public boolean equals(Object other) {
            return this == other || other instanceof CanonicalOperationId operation
                    && Arrays.equals(bytes, operation.bytes);
        }

        @Override
        public int hashCode() {
            return hashCode;
        }

        /* default */ String value() { return value; }

        /* default */ long sharedResidentBytes() {
            return Math.addExact(160L, Math.multiplyExact(bytes.length, 2L));
        }

        /* default */ int compareTo(CanonicalOperationId other) {
            return Arrays.compareUnsigned(bytes, other.bytes);
        }
    }

    /** Allocation-free ordering key after admission. */
    private static final class DueKey implements Comparable<DueKey> {
        private final Instant nextEligibleAt;
        private final CanonicalOperationId operationId;

        private DueKey(Instant nextEligibleAt, CanonicalOperationId operationId) {
            this.nextEligibleAt = nextEligibleAt;
            this.operationId = operationId;
        }

        @Override
        public int compareTo(DueKey other) {
            int time = nextEligibleAt.compareTo(other.nextEligibleAt);
            return time != 0 ? time
                    : Arrays.compareUnsigned(operationId.bytes, other.operationId.bytes);
        }
    }

    /** Stable operation-map slot allocated before its first publication. */
    private static final class OperationSlot {
        private final CanonicalOperationId operationId;
        private DueKey published;
        private WorkDescriptor publishedDescriptor;
        private IdentityNode identityNode;
        private boolean pending;
        private OperationSlot(CanonicalOperationId operationId) {
            this.operationId = operationId;
        }
    }

    /** Mutable identity AVL node augmented with the subtree's earliest eligibility. */
    private static final class IdentityNode {
        private final OperationSlot operationSlot;
        private IdentityNode parent;
        private IdentityNode left;
        private IdentityNode right;
        private int height = 1;
        private Instant minimumEligibleAt;
        private IdentityNode(OperationSlot operationSlot) { this.operationSlot = operationSlot; }
    }

    private static final class PageCollector {
        private final Instant cutoff;
        private final byte[] lower;
        private final byte[] upper;
        private final int maximum;
        private final List<WorkDescriptor> records = new ArrayList<>();
        private long visited;
        private PageCollector(Instant cutoff, byte[] lower, byte[] upper, int maximum) {
            this.cutoff = cutoff;
            this.lower = lower;
            this.upper = upper;
            this.maximum = maximum;
        }
    }

    /** Hidden ordered slot whose pending descriptor is invisible to selection. */
    private static final class DescriptorSlot {
        private WorkDescriptor published;
        private WorkDescriptor pending;
    }

    /** Read-only sorted view that lets {@link TreeMap} use its linear bulk builder. */
    private static final class SortedRecoveryMap extends AbstractMap<DueKey, DescriptorSlot>
            implements SortedMap<DueKey, DescriptorSlot> {
        private final List<Map.Entry<DueKey, DescriptorSlot>> entries;

        private SortedRecoveryMap(List<Map.Entry<DueKey, DescriptorSlot>> entries) {
            super();
            this.entries = List.copyOf(entries);
        }

        @Override public Comparator<? super DueKey> comparator() { return null; }
        @Override public DueKey firstKey() { return entries.getFirst().getKey(); }
        @Override public DueKey lastKey() { return entries.getLast().getKey(); }
        @Override public SortedMap<DueKey, DescriptorSlot> subMap(DueKey fromKey, DueKey toKey) {
            throw new UnsupportedOperationException("recovery map is a bulk-build view");
        }
        @Override public SortedMap<DueKey, DescriptorSlot> headMap(DueKey toKey) {
            throw new UnsupportedOperationException("recovery map is a bulk-build view");
        }
        @Override public SortedMap<DueKey, DescriptorSlot> tailMap(DueKey fromKey) {
            throw new UnsupportedOperationException("recovery map is a bulk-build view");
        }
        @Override public Set<Map.Entry<DueKey, DescriptorSlot>> entrySet() {
            return new AbstractSet<>() {
                @Override public Iterator<Map.Entry<DueKey, DescriptorSlot>> iterator() {
                    return entries.iterator();
                }
                @Override public int size() { return entries.size(); }
            };
        }
    }

    /** Rollback-capable due projection prepared before WAL admission. */
    /* default */ final class PreparedChange implements AutoCloseable {
        private final OperationSlot operationSlot;
        private final DueKey previousKey;
        private final DescriptorSlot previousSlot;
        private final DueKey replacementKey;
        private final DescriptorSlot replacementSlot;
        private final boolean insertedReplacement;
        private final WorkDescriptor replacement;
        private final long byteDelta;
        private final SigningIndexCapacityBudget.Reservation reservation;
        private final SigningGenerationRegistry.CurrentReferences reference;
        private boolean active;

        private PreparedChange(OperationSlot operationSlot, DueKey previousKey,
                DescriptorSlot previousSlot, DueKey replacementKey,
                DescriptorSlot replacementSlot, boolean insertedReplacement,
                WorkDescriptor replacement, long byteDelta,
                SigningIndexCapacityBudget.Reservation reservation,
                SigningGenerationRegistry.CurrentReferences reference) {
            this.operationSlot = operationSlot;
            this.previousKey = previousKey;
            this.previousSlot = previousSlot;
            this.replacementKey = replacementKey;
            this.replacementSlot = replacementSlot;
            this.insertedReplacement = insertedReplacement;
            this.replacement = replacement;
            this.byteDelta = byteDelta;
            this.reservation = reservation;
            this.reference = reference;
            active = operationSlot != null;
        }

        private PreparedChange() {
            this(null, null, null, null, null, false, null, 0L, null, null);
        }

        /* default */ void publish() {
            writeLock.lock();
            try {
                if (!active) return;
                requireOpen();
                if (!operationSlot.pending) {
                    throw new IllegalStateException("signing due-work prepared ownership is inconsistent");
                }
                WorkDescriptor previous = previousSlot == null ? null : previousSlot.published;
                if (replacement == null) {
                    previousSlot.published = null;
                    ordered.remove(previousKey, previousSlot);
                    operationSlot.published = null;
                    operationSlot.publishedDescriptor = null;
                    byOperation.remove(operationSlot.operationId, operationSlot);
                    removeIdentity(operationSlot.identityNode);
                    canonicalIdBytes -= operationSlot.operationId.bytes.length;
                    reservedBytes += byteDelta;
                    capacity.releaseCommitted(-byteDelta);
                } else {
                    replacementSlot.pending = null;
                    replacementSlot.published = replacement;
                    if (previousSlot != null && previousSlot != replacementSlot) {
                        previousSlot.published = null;
                        ordered.remove(previousKey, previousSlot);
                    }
                    operationSlot.published = replacementKey;
                    operationSlot.publishedDescriptor = replacement;
                    rebalanceFrom(operationSlot.identityNode);
                    if (previous == null) {
                        canonicalIdBytes = Math.addExact(canonicalIdBytes,
                                operationSlot.operationId.bytes.length);
                        reservedBytes = Math.addExact(reservedBytes, byteDelta);
                        admittedIdentities++;
                    }
                    reservation.transfer();
                    reference.transfer();
                }
                operationSlot.pending = false;
                active = false;
                if (previous != null) {
                    generations.releaseCurrent(referenceOwner,
                            List.of(previous.pointer.generationId()));
                }
                if (reference != null) reference.close();
                if (reservation != null) reservation.close();
            } finally {
                writeLock.unlock();
            }
        }

        @Override public void close() {
            writeLock.lock();
            try {
                if (!active) return;
                active = false;
                operationSlot.pending = false;
                if (replacementSlot != null) replacementSlot.pending = null;
                if (insertedReplacement) ordered.remove(replacementKey, replacementSlot);
                if (operationSlot.published == null) {
                    byOperation.remove(operationSlot.operationId, operationSlot);
                    removeIdentity(operationSlot.identityNode);
                }
                if (reference != null) reference.close();
                if (reservation != null) reservation.close();
            } finally {
                writeLock.unlock();
            }
        }
    }

    /* default */ record WorkDescriptor(String operationId, Instant nextEligibleAt,
            SignWorkflowStore.State state, SigningMvccIndex.RecordPointer pointer,
            SignWorkflowStore.SchedulingCoordinates scheduling, boolean malformed) {
        WorkDescriptor {
            Objects.requireNonNull(operationId, "operationId");
            Objects.requireNonNull(nextEligibleAt, "nextEligibleAt");
            Objects.requireNonNull(state, "state");
            Objects.requireNonNull(pointer, "pointer");
        }
    }

    /** Immutable due records with deterministic generation-pin ownership. */
    /* default */ static final class Selection implements AutoCloseable {
        private final List<WorkDescriptor> records;
        private final SigningGenerationRegistry.SnapshotPins pins;
        private final SigningIndexCapacityBudget capacity;
        private final long reservedBytes;
        private final AtomicBoolean closed = new AtomicBoolean();

        private Selection(List<WorkDescriptor> records,
                SigningGenerationRegistry.SnapshotPins pins,
                SigningIndexCapacityBudget capacity, long reservedBytes) {
            this.records = records;
            this.pins = pins;
            this.capacity = capacity;
            this.reservedBytes = reservedBytes;
        }

        /* default */ List<WorkDescriptor> records() {
            if (closed.get()) {
                throw new IllegalStateException("signing due-work selection is closed");
            }
            return records;
        }

        @Override
        public void close() {
            if (closed.compareAndSet(false, true)) {
                pins.close();
                capacity.releaseCommitted(reservedBytes);
            }
        }
    }

    /** Immutable identity-ordered due page with pinned descriptor generations. */
    /* default */ static final class IdentitySelection implements AutoCloseable {
        private final List<WorkDescriptor> records;
        private final java.util.Optional<String> highWatermark;
        private final boolean endReached;
        private final SigningGenerationRegistry.SnapshotPins pins;
        private final SigningIndexCapacityBudget capacity;
        private final long reservedBytes;
        private final AtomicBoolean closed = new AtomicBoolean();

        private IdentitySelection(List<WorkDescriptor> records,
                java.util.Optional<String> highWatermark, boolean endReached,
                SigningGenerationRegistry.SnapshotPins pins,
                SigningIndexCapacityBudget capacity, long reservedBytes) {
            this.records = records;
            this.highWatermark = highWatermark;
            this.endReached = endReached;
            this.pins = pins;
            this.capacity = capacity;
            this.reservedBytes = reservedBytes;
        }

        /* default */ List<WorkDescriptor> records() {
            requireOpen();
            return records;
        }
        /* default */ java.util.Optional<String> highWatermark() {
            requireOpen();
            return highWatermark;
        }
        /* default */ boolean endReached() {
            requireOpen();
            return endReached;
        }
        private void requireOpen() {
            if (closed.get()) throw new IllegalStateException("signing due-work page is closed");
        }
        @Override public void close() {
            if (closed.compareAndSet(false, true)) {
                pins.close();
                capacity.releaseCommitted(reservedBytes);
            }
        }
    }

    /* default */ record Statistics(int workCount, int maximumWork, long canonicalIdBytes,
            long estimatedResidentBytes, long reservedBytes,
            long sharedReservedBytes, long admittedIdentities) {
    }
}
