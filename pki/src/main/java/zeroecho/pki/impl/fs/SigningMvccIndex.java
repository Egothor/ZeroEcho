/* *****************************************************************************
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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.AbstractCollection;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.RandomAccess;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import zeroecho.pki.spi.store.MetadataKey;

/**
 * Bounded current-pointer hash index with persistent AVL snapshot roots.
 *
 * <p>The primary hash map contains current records only. Immutable path-copied
 * AVL roots retain historical snapshot values, so no separate version chain is
 * stored or traversed. An index lock is outermost; snapshot close then takes its
 * handle lock. The independent generation and capacity locks never call back
 * into this index or one another. Snapshot reads use only their handle read lock.
 * No uncontrolled callback executes under a lock.</p>
 *
 * <p>Current point lookup is expected {@code O(1)}; update is {@code O(log M)};
 * snapshot capture and close are {@code O(G + log L)} for current generations
 * and live allocation watermarks; range traversal is {@code O(log M + R)}.
 * A preallocated indexed min-heap keeps the oldest revision and correlated
 * allocation watermark at its root using {@code O(L)} scalar memory without
 * per-open collection nodes. Snapshot close never scans keys.</p>
 */
// The primary hash, immutable root, snapshot heap, capacity, and generation
// ownership form one atomic live-index boundary. Splitting that boundary further
// would expose mutable ownership or obscure the failure-free root publication.
@SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops",
        "PMD.AvoidLiteralsInIfCondition", "PMD.CloseResource", "PMD.ConfusingTernary",
        "PMD.CompareObjectsWithEquals", "PMD.ControlStatementBraces",
        "PMD.CyclomaticComplexity", "PMD.CouplingBetweenObjects",
        "PMD.NcssCount", "PMD.NPathComplexity", "PMD.TooManyMethods",
        "PMD.UseTryWithResources" })
final class SigningMvccIndex implements AutoCloseable {
    /* default */ static final int FOUR_GIB_MAXIMUM_KEYS = 1_000_000;
    private static final int MAX_MUTATIONS_PER_REVISION = SigningWalFrameCodec.MAX_BATCH_FRAMES;
    private static final long CURRENT_ENTRY_FIXED_BYTES = 320L;
    /* default */ static final long ORDERED_NODE_BYTES = 64L;
    private static final long SNAPSHOT_FIXED_BYTES = 160L;
    private static final long SNAPSHOT_GENERATION_BYTES = 32L;

    private final Configuration configuration;
    private final SigningGenerationRegistry generations;
    private final SigningIndexCapacityBudget capacity;
    private final SigningIndexCapacityBudget transientCapacity;
    private final boolean detachedCapacityAccounting;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);
    private final Lock readLock = lock.readLock();
    private final Lock writeLock = lock.writeLock();
    private Map<MetadataKey, PrimarySlot> primary = new HashMap<>();
    private Map<Long, Integer> currentGenerationReferences = new HashMap<>();
    private final SnapshotState[] snapshotHeap;
    private final Deque<PreparedApply> preparedApplies = new ArrayDeque<>();
    private OrderedNode orderedRoot;
    private long currentRevision;
    private long lastSequence = -1L;
    private long canonicalKeyBytes;
    private long checkpointIndexBytes;
    private long currentReservedBytes;
    private long retainedAllocationWatermark;
    private long releasedRetainedWatermark;
    private long protectedNodeWatermark;
    private long releasedProtectedWatermark;
    private long orderedNodeAllocations;
    private long detachedGroupApplications;
    private long detachedReferenceMapCopies;
    private Runnable snapshotCloseSignal;
    private boolean closed;
    private int currentKeys;
    private int liveSnapshots;
    private long lastSnapshotRevision = -1L;
    private long lastSnapshotWatermark;

    /* default */ SigningMvccIndex(Configuration configuration,
            SigningGenerationRegistry generations, SigningIndexCapacityBudget capacity,
            SigningIndexCapacityBudget transientCapacity) {
        this(configuration, generations, capacity, transientCapacity, false);
    }

    private SigningMvccIndex(Configuration configuration,
            SigningGenerationRegistry generations, SigningIndexCapacityBudget capacity,
            SigningIndexCapacityBudget transientCapacity, boolean detachedCapacityAccounting) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.generations = Objects.requireNonNull(generations, "generations");
        this.capacity = Objects.requireNonNull(capacity, "capacity");
        this.transientCapacity = Objects.requireNonNull(transientCapacity, "transientCapacity");
        this.detachedCapacityAccounting = detachedCapacityAccounting;
        if (!detachedCapacityAccounting && capacity == transientCapacity) {
            throw new IllegalArgumentException("signing index capacity budgets must be distinct");
        }
        snapshotHeap = new SnapshotState[configuration.maximumSnapshots];
    }

    /* default */ long currentRevision() {
        readLock.lock();
        try {
            requireOpen();
            return currentRevision;
        } finally {
            readLock.unlock();
        }
    }

    /* default */ long lastSequence() {
        readLock.lock();
        try {
            requireOpen();
            return lastSequence;
        } finally {
            readLock.unlock();
        }
    }

    /** Expected {@code O(1)} current point lookup. */
    /* default */ Optional<SnapshotRecord> lookup(MetadataKey key) {
        Objects.requireNonNull(key, "key");
        readLock.lock();
        try {
            requireOpen();
            PrimarySlot slot = primary.get(key);
            CurrentEntry entry = slot == null ? null : slot.published;
            return entry == null ? Optional.empty() : Optional.of(entry.record);
        } finally {
            readLock.unlock();
        }
    }

    /** Expected {@code O(log M)} lookup against the latest prepared publication. */
    /* default */ Optional<SnapshotRecord> lookupPrepared(MetadataKey key) {
        Objects.requireNonNull(key, "metadata key");
        writeLock.lock();
        try {
            requireOpen();
            PreparedApply tail = preparedApplies.peekLast();
            OrderedNode root = tail == null ? orderedRoot : tail.candidateRoot;
            OrderedNode found = find(root, key);
            return found == null ? Optional.empty() : Optional.of(found.entry.record);
        } finally {
            writeLock.unlock();
        }
    }

    /** Selects at most the first current record in one range in {@code O(log M)} time. */
    /* default */ SigningCurrentSelection selectCurrentFirst(String namespace,
            String lowerInclusive, Optional<String> upperExclusive) {
        MetadataKey lower = currentRangeLower(namespace, lowerInclusive, upperExclusive);
        readLock.lock();
        try {
            requireOpen();
            OrderedNode selected = lowerBound(orderedRoot, lower);
            SnapshotRecord record = selected != null && currentRangeContains(
                    selected.entry.record.key(), lower, upperExclusive)
                    ? selected.entry.record : null;
            return SigningCurrentSelection.single(capacity, generations, record);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Captures every current record in one range after one AVL lower-bound seek.
     * Pointer storage is capacity-reserved before each bounded growth step.
     */
    /* default */ SigningCurrentSelection selectCurrentRange(String namespace,
            String lowerInclusive, Optional<String> upperExclusive) {
        MetadataKey lower = currentRangeLower(namespace, lowerInclusive, upperExclusive);
        readLock.lock();
        try {
            requireOpen();
            try (SigningCurrentSelection.Builder selection =
                    SigningCurrentSelection.rangeBuilder(capacity)) {
                LowerBoundIterator iterator = new LowerBoundIterator(
                        orderedRoot, lower);
                while (iterator.hasNext()) {
                    SnapshotRecord candidate = iterator.next().record;
                    if (!currentRangeContains(candidate.key(), lower, upperExclusive)) {
                        break;
                    }
                    selection.add(candidate);
                }
                return selection.build(generations);
            }
        } finally {
            readLock.unlock();
        }
    }

    /** Applies one bounded committed revision atomically. */
    /* default */ void apply(long revision, List<Mutation> mutations) {
        long sequence = mutations.isEmpty() ? lastSequence : mutations.getLast().sequence();
        applyInternal(revision, sequence, mutations, false);
    }

    /** Applies one ledger frame; every mutation in the frame shares its sequence and revision. */
    /* default */ void apply(long revision, long sequence, List<Mutation> mutations) {
        applyInternal(revision, sequence, mutations, true);
    }

    private void applyInternal(long revision, long sequence, List<Mutation> mutations,
            boolean sharedFrameSequence) {
        try (PreparedApply prepared = prepare(revision, sequence, mutations,
                sharedFrameSequence,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY)) {
            prepared.publish();
        }
    }

    /** Applies one already validated WAL group with one reference-map copy. */
    /* default */ void applyDetachedGroup(List<CommittedFrame> frames) {
        List<CommittedFrame> detachedFrames = List.copyOf(
                Objects.requireNonNull(frames, "frames"));
        if (detachedFrames.isEmpty()
                || detachedFrames.size() > SigningWalFrameCodec.MAX_BATCH_FRAMES) {
            throw new IllegalArgumentException("signing detached group size is invalid");
        }
        writeLock.lock();
        try {
            requireOpen();
            if (!preparedApplies.isEmpty()) {
                throw new IllegalStateException("signing detached group has a prepared publication");
            }
            OrderedNode candidateRoot = orderedRoot;
            int candidateKeys = currentKeys;
            long candidateRevision = currentRevision;
            long candidateSequence = lastSequence;
            long baseDelta = 0L;
            AllocationCounter allocations = new AllocationCounter();
            Map<Long, Integer> candidateReferences =
                    new HashMap<>(currentGenerationReferences);
            List<UpdatePlan> allPlans = new ArrayList<>();
            for (CommittedFrame frame : detachedFrames) {
                requireNextRevision(candidateRevision, frame.revision);
                if (frame.sequence <= candidateSequence) {
                    throw new IllegalArgumentException(
                            "signing detached group sequence is not contiguous");
                }
                List<UpdatePlan> plans = validatePlans(candidateRoot, candidateKeys,
                        frame.revision, frame.sequence, frame.mutations, true);
                updateReferences(candidateReferences, plans);
                candidateRoot = applyToRoot(candidateRoot, plans, allocations);
                candidateKeys = candidateKeyCount(candidateKeys, plans);
                baseDelta = Math.addExact(baseDelta, baseReservationDelta(plans));
                candidateRevision = frame.revision;
                candidateSequence = frame.sequence;
                allPlans.addAll(plans);
            }
            long nodeBytes = Math.multiplyExact(allocations.count, ORDERED_NODE_BYTES);
            SigningIndexCapacityBudget.Reservation baseReservation =
                    capacity.reserve(Math.max(0L, baseDelta));
            try {
                SigningIndexCapacityBudget.Reservation nodeReservation = capacity.reserve(nodeBytes);
                try {
                    SigningGenerationRegistry.CurrentReferences newReferences =
                            generations.acquireCurrent(SigningGenerationRegistry.Owner.MVCC,
                                    new GenerationIds(allPlans));
                    List<PrimarySlot> slots = new ArrayList<>(allPlans.size());
                    boolean published = false;
                    try {
                        installGroupSlots(allPlans, slots);
                        publishDetachedGroup(allPlans, slots, candidateRoot, candidateKeys,
                                candidateReferences, candidateRevision, candidateSequence,
                                allocations.count, baseDelta);
                        published = true;
                        newReferences.transfer();
                        if (baseDelta > 0L) {
                            baseReservation.transfer();
                        }
                        generations.releaseCurrent(SigningGenerationRegistry.Owner.MVCC,
                                new PreviousGenerationIds(allPlans));
                        if (baseDelta < 0L) {
                            capacity.releaseCommitted(-baseDelta);
                        }
                        detachedGroupApplications = Math.incrementExact(
                                detachedGroupApplications);
                        detachedReferenceMapCopies = Math.incrementExact(
                                detachedReferenceMapCopies);
                    } finally {
                        if (!published) {
                            rollbackSlots(allPlans, slots);
                        }
                        newReferences.close();
                    }
                } finally {
                    nodeReservation.close();
                }
            } finally {
                baseReservation.close();
            }
        } finally {
            writeLock.unlock();
        }
    }

    private void installGroupSlots(List<UpdatePlan> plans, List<PrimarySlot> slots) {
        for (UpdatePlan plan : plans) {
            PrimarySlot slot = primary.get(plan.key.metadataKey);
            if (slot == null) {
                slot = new PrimarySlot(null);
                primary.put(plan.key.metadataKey, slot);
            }
            slot.pending = Math.incrementExact(slot.pending);
            slots.add(slot);
        }
    }

    private void publishDetachedGroup(List<UpdatePlan> plans, List<PrimarySlot> slots,
            OrderedNode candidateRoot,
            int candidateKeys, Map<Long, Integer> candidateReferences,
            long revision, long sequence, long allocations, long baseDelta) {
        int slotIndex = 0;
        for (UpdatePlan plan : plans) {
            PrimarySlot slot = slots.get(slotIndex++);
            if (plan.replacement == null) {
                slot.published = null;
                canonicalKeyBytes = Math.subtractExact(
                        canonicalKeyBytes, plan.key.byteLength());
                checkpointIndexBytes = Math.subtractExact(
                        checkpointIndexBytes, plan.key.checkpointIndexBytes());
            } else if (plan.existing == null) {
                slot.published = plan.replacementEntry;
                canonicalKeyBytes = Math.addExact(
                        canonicalKeyBytes, plan.key.byteLength());
                checkpointIndexBytes = Math.addExact(
                        checkpointIndexBytes, plan.key.checkpointIndexBytes());
            } else {
                slot.published = plan.replacementEntry;
            }
            releaseSlot(plan, slot);
        }
        currentKeys = candidateKeys;
        currentGenerationReferences = candidateReferences;
        orderedRoot = candidateRoot;
        currentRevision = revision;
        lastSequence = sequence;
        currentReservedBytes = Math.addExact(currentReservedBytes, baseDelta);
        orderedNodeAllocations = Math.addExact(orderedNodeAllocations, allocations);
    }

    private static void updateReferences(Map<Long, Integer> references,
            List<UpdatePlan> plans) {
        for (UpdatePlan plan : plans) {
            if (plan.existing != null) {
                decrementReference(references, plan.existing.record.pointer.generationId);
            }
            if (plan.replacement != null) {
                references.merge(plan.replacement.pointer.generationId, 1, Math::addExact);
            }
        }
    }

    /* default */ long detachedGroupApplications() {
        readLock.lock();
        try {
            requireOpen();
            return detachedGroupApplications;
        } finally {
            readLock.unlock();
        }
    }

    /* default */ long detachedReferenceMapCopies() {
        readLock.lock();
        try {
            requireOpen();
            return detachedReferenceMapCopies;
        } finally {
            readLock.unlock();
        }
    }

    /* default */ long steadyReservedBytes() {
        readLock.lock();
        try {
            requireOpen();
            return Math.addExact(Math.multiplyExact(canonicalKeyBytes, 2L),
                    Math.multiplyExact(currentKeys, CURRENT_ENTRY_FIXED_BYTES));
        } finally {
            readLock.unlock();
        }
    }

    /** Reports whether any short prepared publication still owns index state. */
    /* default */ boolean hasPreparedApplies() {
        readLock.lock();
        try {
            requireOpen();
            return !preparedApplies.isEmpty();
        } finally {
            readLock.unlock();
        }
    }

    /** Arms one engine-internal wake after the last external snapshot closes. */
    /* default */ void signalWhenSnapshotsClose(Runnable signal) {
        Objects.requireNonNull(signal, "signal");
        boolean signalNow = false;
        writeLock.lock();
        try {
            requireOpen();
            if (liveSnapshots == 0) {
                signalNow = true;
            } else if (snapshotCloseSignal == null) {
                snapshotCloseSignal = signal;
            }
        } finally {
            writeLock.unlock();
        }
        if (signalNow) {
            signal.run();
        }
    }

    /* default */ void clearSnapshotCloseSignal() {
        writeLock.lock();
        try {
            snapshotCloseSignal = null;
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Prebuilds one ordered publication and owns every fallible capacity and
     * generation reservation until it is published or closed.
     */
    /* default */ PreparedApply prepare(long revision, long sequence,
            List<Mutation> mutations) {
        return prepare(revision, sequence, mutations,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /* default */ PreparedApply prepare(long revision, long sequence,
            List<Mutation> mutations,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
        return prepare(revision, sequence, mutations, true, admissionClass);
    }

    private PreparedApply prepare(long revision, long sequence,
            List<Mutation> mutations, boolean sharedFrameSequence,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
        List<Mutation> detached = List.copyOf(Objects.requireNonNull(mutations, "mutations"));
        Objects.requireNonNull(admissionClass, "admissionClass");
        writeLock.lock();
        try {
            requireOpen();
            PreparedApply tail = preparedApplies.peekLast();
            long baseRevision = tail == null ? currentRevision : tail.revision;
            long baseSequence = tail == null ? lastSequence : tail.sequence;
            OrderedNode baseRoot = tail == null ? orderedRoot : tail.candidateRoot;
            int baseKeys = tail == null ? currentKeys : tail.candidateKeys;
            Map<Long, Integer> baseReferences = tail == null
                    ? currentGenerationReferences : tail.candidateReferences;
            requireNextRevision(baseRevision, revision);
            requireSnapshotSpan(revision);
            if ((sharedFrameSequence || !detached.isEmpty()) && sequence <= baseSequence) {
                throw new IllegalArgumentException("signing index frame sequence is not contiguous");
            }
            if (detached.size() > MAX_MUTATIONS_PER_REVISION) {
                throw new IllegalArgumentException("signing index mutation group is too large");
            }
            List<UpdatePlan> plans = validatePlans(baseRoot, baseKeys, revision, sequence,
                    detached, sharedFrameSequence);
            Map<Long, Integer> candidateReferences = candidateReferences(baseReferences, plans);
            AllocationCounter allocations = new AllocationCounter();
            OrderedNode candidateRoot = applyToRoot(baseRoot, plans, allocations);
            int candidateKeys = candidateKeyCount(baseKeys, plans);
            long baseDelta = baseReservationDelta(plans);
            long nodeBytes = Math.multiplyExact(allocations.count, ORDERED_NODE_BYTES);
            SigningIndexCapacityBudget.Reservation baseReservation =
                    capacity.reserve(Math.max(0L, baseDelta));
            SigningIndexCapacityBudget.Reservation nodeReservation = null;
            SigningGenerationRegistry.CurrentReferences newReferences = null;
            List<PrimarySlot> slots = new ArrayList<>(plans.size());
            boolean installed = false;
            try {
                nodeReservation = capacity.reserve(nodeBytes, admissionClass);
                newReferences = generations.acquireCurrent(
                        SigningGenerationRegistry.Owner.MVCC, new GenerationIds(plans));
                for (UpdatePlan plan : plans) {
                    PrimarySlot slot = primary.get(plan.key.metadataKey);
                    if (slot == null) {
                        slot = new PrimarySlot(null);
                        primary.put(plan.key.metadataKey, slot);
                    }
                    slot.pending = Math.incrementExact(slot.pending);
                    slots.add(slot);
                }
                PreparedApply result = new PreparedApply(revision, sequence, plans, slots,
                        candidateRoot, candidateKeys, candidateReferences,
                        allocations.count, baseDelta, nodeBytes,
                        baseReservation, nodeReservation, newReferences, admissionClass);
                preparedApplies.addLast(result);
                installed = true;
                return result;
            } finally {
                if (!installed) {
                    rollbackSlots(plans, slots);
                    if (newReferences != null) newReferences.close();
                    if (nodeReservation != null) nodeReservation.close();
                    baseReservation.close();
                }
            }
        } finally {
            writeLock.unlock();
        }
    }

    /** Captures one immutable ordered root and pins all generations it references. */
    /* default */ Snapshot snapshot() {
        writeLock.lock();
        try {
            requireOpen();
            if (liveSnapshots >= snapshotHeap.length) {
                throw new IllegalStateException("signing index snapshot capacity is exhausted");
            }
            long bytes = Math.addExact(SNAPSHOT_FIXED_BYTES,
                    Math.multiplyExact(currentGenerationReferences.size(), SNAPSHOT_GENERATION_BYTES));
            SigningIndexCapacityBudget.Reservation reservation = capacity.reserve(bytes);
            try {
                SigningGenerationRegistry.SnapshotPins pins = generations.pinSnapshot(
                        currentGenerationReferences.keySet());
                boolean installed = false;
                long allocationWatermark = retainedAllocationWatermark;
                SnapshotState state = new SnapshotState(currentRevision, lastSequence,
                        currentKeys, Math.addExact(SigningCheckpointCodec.HEADER_BYTES,
                                checkpointIndexBytes), canonicalKeyBytes,
                        checkpointIndexBytes, orderedRoot, pins, bytes,
                        allocationWatermark,
                        protectedNodeWatermark);
                boolean heapInstalled = false;
                try {
                    addSnapshotState(state);
                    heapInstalled = true;
                    reservation.transfer();
                    installed = true;
                    return new Snapshot(this, state);
                } finally {
                    if (!installed) {
                        if (heapInstalled) {
                            removeSnapshotState(state);
                        }
                        pins.close();
                    }
                }
            } finally {
                reservation.close();
            }
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Builds a physically relocated MVCC-only candidate from one immutable
     * snapshot without changing the live root or any non-MVCC owner.
     */
    /* default */ RelocationCapacity prepareRelocationCapacity(Snapshot snapshot) {
        Objects.requireNonNull(snapshot, "snapshot");
        if (!snapshot.owner.equals(this)) {
            throw new IllegalArgumentException("signing relocation snapshot owner is invalid");
        }
        SnapshotState state = snapshot.state;
        state.readAccess.lock();
        try {
            snapshot.requireOpen();
            // Canonical keys are immutable objects shared with the source root.
            // Only the candidate's distinct entry structures charge transient capacity.
            long bytes = Math.multiplyExact(state.size, CURRENT_ENTRY_FIXED_BYTES);
            return new RelocationCapacity(this, state, bytes,
                    transientCapacity.reserve(bytes));
        } finally {
            state.readAccess.unlock();
        }
    }

    /* default */ SigningMvccRelocationCandidate buildRelocationCandidate(Snapshot snapshot,
            long generationId, long firstFrameOffset,
            CommittedPrefixDescriptor acceptedBoundary, RelocationCapacity capacityClaim) {
        Objects.requireNonNull(snapshot, "snapshot");
        Objects.requireNonNull(acceptedBoundary, "acceptedBoundary");
        Objects.requireNonNull(capacityClaim, "capacityClaim");
        if (!snapshot.owner.equals(this) || generationId < 0L
                || firstFrameOffset < SigningCheckpointCodec.HEADER_BYTES) {
            throw new IllegalArgumentException("signing relocation-candidate fields are invalid");
        }
        SnapshotState state = snapshot.state;
        state.readAccess.lock();
        try {
            snapshot.requireOpen();
            if (acceptedBoundary.inclusiveForcedEndRevision() != state.revision
                    || acceptedBoundary.inclusiveForcedEndSequence()
                            != state.committedSequence) {
                throw new IllegalArgumentException(
                        "signing relocation accepted boundary is inconsistent");
            }
            long candidateBytes = capacityClaim.require(this, state);
            try {
                Map<Long, Integer> referenceCounts = state.size == 0
                        ? Map.of() : Map.of(generationId, state.size);
                SigningGenerationRegistry.CurrentReferences references =
                        generations.acquireCurrentCounts(
                                SigningGenerationRegistry.Owner.MVCC, referenceCounts);
                try {
                    RelocatedBuild relocated = buildRelocated(state, generationId,
                            firstFrameOffset, candidateBytes, referenceCounts);
                    SigningMvccIndex detached = new SigningMvccIndex(
                            configuration, generations, transientCapacity,
                            transientCapacity, true);
                    detached.installRelocated(relocated);
                    references.transfer();
                    capacityClaim.transfer();
                    boolean installed = false;
                    try {
                        SigningMvccRelocationCandidate candidate =
                                new SigningMvccRelocationCandidate(this, detached,
                                        acceptedBoundary, relocated.checkpointEndOffset);
                        installed = true;
                        return candidate;
                    } finally {
                        if (!installed) {
                            detached.close();
                        }
                    }
                } finally {
                    references.close();
                }
            } finally {
                capacityClaim.close();
            }
        } finally {
            state.readAccess.unlock();
        }
    }

    private static RelocatedBuild buildRelocated(SnapshotState snapshot,
            long generationId, long firstFrameOffset, long reservedBytes,
            Map<Long, Integer> referenceCounts) {
        Map<MetadataKey, PrimarySlot> primary = new HashMap<>(hashCapacity(snapshot.size));
        RelocatedBuildCursor cursor = new RelocatedBuildCursor(
                snapshot.root, generationId, firstFrameOffset);
        AllocationCounter allocations = new AllocationCounter();
        OrderedNode root = buildRelocatedBalanced(snapshot.size, cursor, primary, allocations);
        if (cursor.hasRemaining() || allocations.count != snapshot.size) {
            throw new IllegalStateException("signing relocation snapshot is inconsistent");
        }
        return new RelocatedBuild(primary, new HashMap<>(referenceCounts), root,
                snapshot.revision, snapshot.committedSequence, snapshot.canonicalKeyBytes,
                snapshot.checkpointIndexBytes, reservedBytes, allocations.count,
                snapshot.size, cursor.offset());
    }

    private static OrderedNode buildRelocatedBalanced(int count,
            RelocatedBuildCursor cursor, Map<MetadataKey, PrimarySlot> primary,
            AllocationCounter allocations) {
        if (count == 0) {
            return null;
        }
        int leftCount = count >>> 1;
        OrderedNode left = buildRelocatedBalanced(leftCount, cursor, primary, allocations);
        CurrentEntry entry = cursor.next();
        primary.put(entry.key.metadataKey, new PrimarySlot(entry));
        OrderedNode right = buildRelocatedBalanced(
                count - leftCount - 1, cursor, primary, allocations);
        allocations.count++;
        return new OrderedNode(entry, left, right,
                Math.max(height(left), height(right)) + 1);
    }

    private void installRelocated(RelocatedBuild relocated) {
        primary = relocated.primary;
        currentGenerationReferences = relocated.generationReferences;
        orderedRoot = relocated.root;
        currentRevision = relocated.revision;
        lastSequence = relocated.lastSequence;
        canonicalKeyBytes = relocated.canonicalKeyBytes;
        checkpointIndexBytes = relocated.checkpointIndexBytes;
        currentReservedBytes = relocated.reservedBytes;
        orderedNodeAllocations = relocated.orderedNodeAllocations;
        currentKeys = relocated.currentKeys;
    }

    /** Prevalidates an allocation-free root swap against one exact live endpoint. */
    /* default */ SigningMvccRelocationCandidate.PreparedRootSwap prepareRelocationSwap(
            SigningMvccRelocationCandidate candidate,
            long expectedLiveRevision, long expectedLiveSequence,
            byte[] expectedLiveCommitment) {
        Objects.requireNonNull(candidate, "candidate");
        writeLock.lock();
        try {
            requireOpen();
            if (!candidate.ownedBy(this) || currentRevision != expectedLiveRevision
                    || lastSequence != expectedLiveSequence) {
                throw new IllegalStateException(
                        "signing relocation swap endpoint is inconsistent");
            }
            if (!preparedApplies.isEmpty()) {
                throw new IllegalStateException(
                        "signing relocation swap has a live prepared publication");
            }
            if (liveSnapshots != 0) {
                throw new RelocationDeferredException(
                        "signing relocation swap is deferred by live snapshots");
            }
            SigningIndexCapacityBudget.CutoverPermit capacityPermit =
                    capacity.prepareCutover(currentReservedBytes,
                            candidate.steadyReservedBytes());
            boolean prepared = false;
            try {
                SigningMvccRelocationCandidate.PreparedRootSwap result = candidate.prepare(
                        expectedLiveRevision, expectedLiveSequence, expectedLiveCommitment);
                result.attachCapacityPermit(capacityPermit);
                prepared = true;
                return result;
            } finally {
                if (!prepared) {
                    capacityPermit.close();
                }
            }
        } finally {
            writeLock.unlock();
        }
    }

    /* default */ void publishRelocationSwap(
            SigningMvccRelocationCandidate.PreparedRootSwap prepared) {
        SigningMvccRelocationCandidate candidate = prepared.candidate();
        writeLock.lock();
        try {
            requireOpen();
            if (!prepared.active() || currentRevision != prepared.expectedRevision()
                    || lastSequence != prepared.expectedSequence()) {
                throw new IllegalStateException(
                        "signing relocation swap endpoint is inconsistent");
            }
            candidate.requirePrepared(prepared, prepared.expectedRevision(),
                    prepared.expectedSequence());
            if (!preparedApplies.isEmpty()) {
                throw new IllegalStateException(
                        "signing relocation swap has a live prepared publication");
            }
            if (liveSnapshots != 0 || retainedNodeBytes() != 0L) {
                throw new RelocationDeferredException(
                        "signing relocation swap is deferred by live snapshots");
            }
            RelocationRootState replacement = prepared.relocationRoot();
            replacement.requireOwned();
            long previousReservedBytes = currentReservedBytes;
            long nextOrderedNodeAllocations = Math.addExact(
                    orderedNodeAllocations, replacement.orderedNodeAllocations);
            long replacementSteadyBytes = replacement.steadyReservedBytes();
            Map<Long, Integer> previousReferences = currentGenerationReferences;
            try (SigningIndexCapacityBudget.Reclassification accounting =
                    SigningIndexCapacityBudget.reclassify(prepared.capacityPermit(),
                            transientCapacity, replacement.reservedBytes)) {
                primary = replacement.primary;
                currentGenerationReferences = replacement.generationReferences;
                orderedRoot = replacement.orderedRoot;
                currentRevision = replacement.revision;
                lastSequence = replacement.lastSequence;
                canonicalKeyBytes = replacement.canonicalKeyBytes;
                checkpointIndexBytes = replacement.checkpointIndexBytes;
                currentReservedBytes = replacementSteadyBytes;
                retainedAllocationWatermark = 0L;
                releasedRetainedWatermark = 0L;
                protectedNodeWatermark = 0L;
                releasedProtectedWatermark = 0L;
                resetSnapshotAdmissionBaseline();
                orderedNodeAllocations = nextOrderedNodeAllocations;
                currentKeys = replacement.currentKeys;
                replacement.transfer();
                accounting.commit();
            }
            prepared.published(previousReferences, previousReservedBytes, false);
            candidate.transferred(prepared);
        } finally {
            writeLock.unlock();
        }
    }

    /* default */ void releaseDisplacedRoot(Map<Long, Integer> references,
            long reservedBytes, boolean releaseReservation) {
        generations.releaseCurrentCounts(SigningGenerationRegistry.Owner.MVCC, references);
        if (releaseReservation && reservedBytes > 0L) {
            capacity.releaseCommitted(reservedBytes);
        }
    }

    /**
     * Relocates one physical pointer only when the logical record is still the
     * exact snapshot value. Logical revision and sequence remain unchanged.
     */
    /* default */ boolean relocateIfCurrent(SnapshotRecord expected, RecordPointer replacement) {
        Objects.requireNonNull(expected, "expected");
        Objects.requireNonNull(replacement, "replacement");
        if (replacement.sequence() != expected.pointer().sequence()
                || replacement.recordType() != expected.pointer().recordType()) {
            throw new IllegalArgumentException("signing relocation changes logical identity");
        }
        writeLock.lock();
        try {
            requireOpen();
            return relocateIfCurrentLocked(expected, replacement);
        } finally {
            writeLock.unlock();
        }
    }

    /** Relocates a complete snapshot in canonical order without reversing lock order. */
    /* default */ long relocateSnapshot(Snapshot snapshot, long generationId,
            long firstFrameOffset) {
        Objects.requireNonNull(snapshot, "snapshot");
        if (!snapshot.owner.equals(this) || generationId < 0L
                || firstFrameOffset < SigningCheckpointCodec.HEADER_BYTES) {
            throw new IllegalArgumentException("signing snapshot relocation fields are invalid");
        }
        writeLock.lock();
        try {
            requireOpen();
            SnapshotState state = snapshot.state;
            state.readAccess.lock();
            try {
                snapshot.requireOpen();
                long retainedBytes = Math.multiplyExact(currentKeys, ORDERED_NODE_BYTES);
                long nextAllocationWatermark = retainedWatermarkAfter(retainedBytes);
                SigningIndexCapacityBudget.Reservation reservation = capacity.reserve(retainedBytes);
                try {
                    RelocatingIterator relocating = new RelocatingIterator(orderedRoot,
                            state.root, generationId, firstFrameOffset);
                    AllocationCounter allocations = new AllocationCounter();
                    OrderedNode candidateRoot = buildBalanced(currentKeys, relocating,
                            allocations);
                    Map<Long, Integer> candidateReferences = relocating.generationReferences();
                    SigningGenerationRegistry.CurrentReferences references =
                            generations.acquireCurrentCounts(
                                    SigningGenerationRegistry.Owner.MVCC, candidateReferences);
                    try {
                        Map<Long, Integer> previousReferences = currentGenerationReferences;
                        replacePrimaryValues(candidateRoot);
                        currentGenerationReferences = new HashMap<>(candidateReferences);
                        orderedRoot = candidateRoot;
                        retainedAllocationWatermark = nextAllocationWatermark;
                        orderedNodeAllocations = Math.addExact(orderedNodeAllocations,
                                allocations.count);
                        references.transfer();
                        reservation.transfer();
                        generations.releaseCurrentCounts(SigningGenerationRegistry.Owner.MVCC,
                                Map.copyOf(previousReferences));
                        return relocating.checkpointEndOffset();
                    } finally {
                        references.close();
                    }
                } finally {
                    reservation.close();
                }
            } finally {
                state.readAccess.unlock();
            }
        } finally {
            writeLock.unlock();
        }
    }

    private static OrderedNode buildBalanced(int count, Iterator<CurrentEntry> entries,
            AllocationCounter allocations) {
        if (count == 0) {
            return null;
        }
        int leftCount = count >>> 1;
        OrderedNode left = buildBalanced(leftCount, entries, allocations);
        CurrentEntry entry = entries.next();
        OrderedNode right = buildBalanced(count - leftCount - 1, entries, allocations);
        allocations.count++;
        return new OrderedNode(entry, left, right, Math.max(height(left), height(right)) + 1);
    }

    private void replacePrimaryValues(OrderedNode candidateRoot) {
        OrderedIterator entries = new OrderedIterator(candidateRoot);
        int replaced = 0;
        while (entries.hasNext()) {
            CurrentEntry entry = entries.next();
            PrimarySlot slot = primary.get(entry.key.metadataKey);
            if (slot == null || slot.published == null) {
                throw new IllegalStateException("signing index relocation key set changed");
            }
            slot.published = entry;
            replaced++;
        }
        if (replaced != currentKeys) {
            throw new IllegalStateException("signing index relocation key count changed");
        }
    }

    private boolean relocateIfCurrentLocked(SnapshotRecord expected, RecordPointer replacement) {
        PrimarySlot slot = primary.get(expected.key());
        CurrentEntry existing = slot == null ? null : slot.published;
        if (existing == null || !existing.record.equals(expected)) {
            return false;
        }
        SnapshotRecord relocated = new SnapshotRecord(expected.key(), replacement,
                expected.revision());
        CanonicalKey key = existing.key;
        AllocationCounter allocations = new AllocationCounter();
        OrderedNode candidateRoot = put(orderedRoot,
                new CurrentEntry(key, relocated, existing.transientCanonicalShared), allocations);
        long retainedDelta = liveSnapshots == 0 ? 0L
                : Math.multiplyExact(allocations.count, ORDERED_NODE_BYTES);
        long nextAllocationWatermark = retainedWatermarkAfter(retainedDelta);
        SigningIndexCapacityBudget.Reservation reservation = capacity.reserve(retainedDelta);
        try {
            SigningGenerationRegistry.CurrentReferences newReference =
                    generations.acquireCurrent(SigningGenerationRegistry.Owner.MVCC,
                            List.of(replacement.generationId()));
            try {
                slot.published = new CurrentEntry(key, relocated,
                        existing.transientCanonicalShared);
                removeGeneration(existing);
                addGeneration(relocated);
                orderedRoot = candidateRoot;
                retainedAllocationWatermark = nextAllocationWatermark;
                orderedNodeAllocations = Math.addExact(orderedNodeAllocations, allocations.count);
                newReference.transfer();
                reservation.transfer();
                generations.releaseCurrent(SigningGenerationRegistry.Owner.MVCC,
                        List.of(expected.pointer().generationId()));
                return true;
            } finally {
                newReference.close();
            }
        } finally {
            reservation.close();
        }
    }

    /**
     * Installs one validated, strictly sorted checkpoint baseline in {@code O(M)}
     * node construction and expected {@code O(M)} hash insertion.
     */
    /* default */ void recover(long revision, long committedSequence,
            List<RecoveredRecord> records) {
        Objects.requireNonNull(records, "records");
        if (!(records instanceof RandomAccess)) {
            throw new IllegalArgumentException("signing index recovery input must support indexed access");
        }
        writeLock.lock();
        try {
            requireOpen();
            requireEmptyRecoveryTarget(revision, committedSequence, records.size());
            validateRecoveryOrder(revision, committedSequence, records);
            Map<MetadataKey, PrimarySlot> candidatePrimary = new HashMap<>(hashCapacity(records.size()));
            AllocationCounter allocations = new AllocationCounter();
            OrderedNode candidateRoot = buildBalanced(records, 0, records.size(),
                    candidatePrimary, allocations);
            long candidateCanonicalBytes = canonicalBytes(candidatePrimary.values());
            long candidateCheckpointBytes = checkpointIndexBytes(candidatePrimary.values());
            long candidateBytes = Math.addExact(Math.multiplyExact(candidateCanonicalBytes, 2L),
                    Math.multiplyExact(records.size(), CURRENT_ENTRY_FIXED_BYTES));
            SigningIndexCapacityBudget.Reservation reservation = capacity.reserve(candidateBytes);
            try {
                SigningGenerationRegistry.CurrentReferences references = generations.acquireCurrent(
                        SigningGenerationRegistry.Owner.MVCC,
                        new RecoveryGenerationIds(records));
                try {
                    Map<Long, Integer> candidateGenerationRefs =
                            countGenerationReferences(candidatePrimary.values());
                    primary = candidatePrimary;
                    currentKeys = records.size();
                    currentGenerationReferences = candidateGenerationRefs;
                    orderedRoot = candidateRoot;
                    currentRevision = revision;
                    lastSequence = committedSequence;
                    canonicalKeyBytes = candidateCanonicalBytes;
                    checkpointIndexBytes = candidateCheckpointBytes;
                    currentReservedBytes = candidateBytes;
                    orderedNodeAllocations = allocations.count;
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

    /** Detaches one candidate-only current root after all catch-up work is complete. */
    /* default */ RelocationRootState detachRelocationRoot() {
        writeLock.lock();
        try {
            requireOpen();
            if (!preparedApplies.isEmpty() || liveSnapshots != 0
                    || retainedNodeBytes() != 0L) {
                throw new IllegalStateException(
                        "signing relocation candidate is not detached");
            }
            RelocationRootState state = new RelocationRootState(this, primary,
                    currentGenerationReferences, orderedRoot, currentRevision,
                    lastSequence, canonicalKeyBytes, checkpointIndexBytes,
                    currentReservedBytes, orderedNodeAllocations, currentKeys);
            primary = null;
            currentGenerationReferences = null;
            orderedRoot = null;
            currentReservedBytes = 0L;
            currentKeys = 0;
            closed = true;
            return state;
        } finally {
            writeLock.unlock();
        }
    }

    /* default */ Statistics statistics() {
        readLock.lock();
        try {
            requireOpen();
            long snapshotBytes = 0L;
            for (int index = 0; index < liveSnapshots; index++) {
                snapshotBytes = Math.addExact(snapshotBytes, snapshotHeap[index].reservedBytes);
            }
            long retainedNodeBytes = retainedNodeBytes();
            long estimated = Math.addExact(currentReservedBytes,
                    Math.addExact(retainedNodeBytes, snapshotBytes));
            return new Statistics(currentRevision, lastSequence, currentKeys, liveSnapshots,
                    canonicalKeyBytes, orderedNodeAllocations, retainedNodeBytes / ORDERED_NODE_BYTES,
                    estimated, estimated, capacity.snapshot().reservedBytes(), 0L, 0L);
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
            snapshotCloseSignal = null;
            for (PreparedApply prepared : List.copyOf(preparedApplies)) {
                prepared.closeLocked();
            }
            for (int index = 0; index < liveSnapshots; index++) {
                closeSnapshotState(snapshotHeap[index]);
            }
            clearSnapshotHeap();
            generations.releaseCurrentCounts(SigningGenerationRegistry.Owner.MVCC,
                    Map.copyOf(currentGenerationReferences));
            long retainedNodeBytes = retainedNodeBytes();
            long protectedRetainedNodeBytes = protectedRetainedNodeBytes();
            long ordinaryReleased = Math.addExact(currentReservedBytes,
                    retainedNodeBytes - protectedRetainedNodeBytes);
            if (ordinaryReleased > 0L) {
                capacity.releaseCommitted(ordinaryReleased);
            }
            if (protectedRetainedNodeBytes > 0L) {
                capacity.releaseCommitted(protectedRetainedNodeBytes,
                        SigningTransitionWorkspaceSizing.AdmissionClass
                                .PROTECTED_ACCEPTED_SIGNING);
            }
            currentReservedBytes = 0L;
            retainedAllocationWatermark = 0L;
            releasedRetainedWatermark = 0L;
            protectedNodeWatermark = 0L;
            releasedProtectedWatermark = 0L;
            checkpointIndexBytes = 0L;
            primary.clear();
            currentKeys = 0;
            currentGenerationReferences.clear();
            orderedRoot = null;
        } finally {
            writeLock.unlock();
        }
    }

    private List<UpdatePlan> validatePlans(OrderedNode baseRoot, int baseKeys, long revision,
            long frameSequence, List<Mutation> mutations, boolean sharedFrameSequence) {
        Set<MetadataKey> distinct = new HashSet<>();
        List<UpdatePlan> result = new ArrayList<>(mutations.size());
        int candidateKeys = baseKeys;
        long candidateSequence = preparedApplies.isEmpty()
                ? lastSequence : preparedApplies.peekLast().sequence;
        for (Mutation mutation : mutations) {
            Objects.requireNonNull(mutation, "mutation");
            boolean invalidSequence = sharedFrameSequence
                    ? mutation.sequence != frameSequence : mutation.sequence <= candidateSequence;
            if (!distinct.add(mutation.key) || invalidSequence) {
                throw new IllegalArgumentException("signing index mutation order is invalid");
            }
            OrderedNode existingNode = find(baseRoot, mutation.key);
            CurrentEntry existing = existingNode == null ? null : existingNode.entry;
            if (mutation.pointer == null && existing == null) {
                throw new IllegalArgumentException("signing index delete has no current record");
            }
            if (mutation.pointer != null && mutation.pointer.sequence != mutation.sequence) {
                throw new IllegalArgumentException("signing index mutation sequence is invalid");
            }
            CanonicalKey key = existing == null ? CanonicalKey.of(mutation.key) : existing.key;
            SnapshotRecord replacement = mutation.pointer == null ? null
                    : new SnapshotRecord(mutation.key, mutation.pointer, revision);
            CurrentEntry replacementEntry = replacement == null
                    ? null : new CurrentEntry(key, replacement,
                            existing != null && existing.transientCanonicalShared);
            result.add(new UpdatePlan(existing, key, replacement, replacementEntry,
                    mutation.sequence));
            candidateSequence = mutation.sequence;
            if (existing == null) {
                candidateKeys++;
            } else if (replacement == null) {
                candidateKeys--;
            }
        }
        if (candidateKeys > configuration.maximumKeys) {
            throw new IllegalStateException("signing index key capacity is exhausted");
        }
        return result;
    }

    private static int candidateKeyCount(int baseKeys, List<UpdatePlan> plans) {
        int result = baseKeys;
        for (UpdatePlan plan : plans) {
            if (plan.existing == null && plan.replacement != null) {
                result++;
            } else if (plan.existing != null && plan.replacement == null) {
                result--;
            }
        }
        return result;
    }

    private static Map<Long, Integer> candidateReferences(Map<Long, Integer> base,
            List<UpdatePlan> plans) {
        Map<Long, Integer> result = new HashMap<>(base);
        for (UpdatePlan plan : plans) {
            if (plan.existing != null) {
                decrementReference(result, plan.existing.record.pointer.generationId);
            }
            if (plan.replacement != null) {
                result.merge(plan.replacement.pointer.generationId, 1, Math::addExact);
            }
        }
        return result;
    }

    private static void decrementReference(Map<Long, Integer> references, long generationId) {
        Integer count = references.get(generationId);
        if (count == null || count <= 0) {
            throw new IllegalStateException("signing index generation accounting is inconsistent");
        }
        if (count == 1) references.remove(generationId);
        else references.put(generationId, count - 1);
    }

    private void rollbackSlots(List<UpdatePlan> plans, List<PrimarySlot> slots) {
        for (int index = slots.size() - 1; index >= 0; index--) {
            releaseSlot(plans.get(index), slots.get(index));
        }
    }

    private void releaseSlot(UpdatePlan plan, PrimarySlot slot) {
        slot.pending--;
        if (slot.pending < 0) {
            throw new IllegalStateException("signing primary preparation accounting is inconsistent");
        }
        if (slot.pending == 0 && slot.published == null) {
            primary.remove(plan.key.metadataKey, slot);
        }
    }

    private void publish(long revision, long sequence, List<UpdatePlan> plans,
            List<PrimarySlot> slots, OrderedNode candidateRoot, long allocations,
            long baseDelta, long nextAllocationWatermark,
            long nextProtectedWatermark) {
        int planIndex = 0;
        for (UpdatePlan plan : plans) {
            PrimarySlot slot = slots.get(planIndex++);
            if (plan.replacement == null) {
                slot.published = null;
                currentKeys--;
                canonicalKeyBytes -= plan.key.byteLength();
                checkpointIndexBytes -= plan.key.checkpointIndexBytes();
            } else if (plan.existing == null) {
                slot.published = plan.replacementEntry;
                currentKeys++;
                canonicalKeyBytes += plan.key.byteLength();
                checkpointIndexBytes += plan.key.checkpointIndexBytes();
            } else {
                slot.published = plan.replacementEntry;
            }
            releaseSlot(plan, slot);
        }
        currentGenerationReferences = preparedApplies.peekFirst().candidateReferences;
        orderedRoot = candidateRoot;
        currentRevision = revision;
        lastSequence = sequence;
        currentReservedBytes = Math.addExact(currentReservedBytes, baseDelta);
        retainedAllocationWatermark = nextAllocationWatermark;
        protectedNodeWatermark = nextProtectedWatermark;
        orderedNodeAllocations = Math.addExact(orderedNodeAllocations, allocations);
    }

    private long retainedWatermarkAfter(long retainedBytes) {
        if (retainedBytes < 0L) {
            throw new IllegalArgumentException("signing retained-node allocation is invalid");
        }
        return Math.addExact(retainedAllocationWatermark, retainedBytes);
    }

    private long protectedWatermarkAfter(long retainedBytes,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
        return admissionClass
                == SigningTransitionWorkspaceSizing.AdmissionClass
                        .PROTECTED_ACCEPTED_SIGNING
                ? Math.addExact(protectedNodeWatermark, retainedBytes)
                : protectedNodeWatermark;
    }

    private long retainedNodeBytes() {
        return Math.subtractExact(retainedAllocationWatermark,
                releasedRetainedWatermark);
    }

    private long protectedRetainedNodeBytes() {
        return Math.subtractExact(protectedNodeWatermark,
                releasedProtectedWatermark);
    }

    private void addSnapshotState(SnapshotState state) {
        if (state.heapIndex >= 0 || liveSnapshots >= snapshotHeap.length
                || state.revision < lastSnapshotRevision
                || state.allocationWatermark < lastSnapshotWatermark) {
            throw new IllegalStateException("signing snapshot heap admission is inconsistent");
        }
        int index = liveSnapshots++;
        snapshotHeap[index] = state;
        state.heapIndex = index;
        siftSnapshotUp(index);
        lastSnapshotRevision = state.revision;
        lastSnapshotWatermark = state.allocationWatermark;
    }

    private void removeSnapshotState(SnapshotState state) {
        int index = state.heapIndex;
        if (index < 0 || index >= liveSnapshots || snapshotHeap[index] != state) {
            throw new IllegalStateException("signing snapshot heap ownership is inconsistent");
        }
        int lastIndex = --liveSnapshots;
        SnapshotState replacement = snapshotHeap[lastIndex];
        snapshotHeap[lastIndex] = null;
        state.heapIndex = -1;
        if (index == lastIndex) {
            return;
        }
        snapshotHeap[index] = replacement;
        replacement.heapIndex = index;
        int parent = (index - 1) >>> 1;
        if (index > 0 && snapshotPrecedes(replacement, snapshotHeap[parent])) {
            siftSnapshotUp(index);
        } else {
            siftSnapshotDown(index);
        }
    }

    private void siftSnapshotUp(int start) {
        int index = start;
        while (index > 0) {
            int parent = (index - 1) >>> 1;
            if (!snapshotPrecedes(snapshotHeap[index], snapshotHeap[parent])) {
                return;
            }
            swapSnapshots(index, parent);
            index = parent;
        }
    }

    private void siftSnapshotDown(int start) {
        int index = start;
        while (true) {
            int left = (index << 1) + 1;
            if (left >= liveSnapshots) {
                return;
            }
            int right = left + 1;
            int selected = right < liveSnapshots
                    && snapshotPrecedes(snapshotHeap[right], snapshotHeap[left]) ? right : left;
            if (!snapshotPrecedes(snapshotHeap[selected], snapshotHeap[index])) {
                return;
            }
            swapSnapshots(index, selected);
            index = selected;
        }
    }

    private void swapSnapshots(int first, int second) {
        SnapshotState value = snapshotHeap[first];
        snapshotHeap[first] = snapshotHeap[second];
        snapshotHeap[second] = value;
        snapshotHeap[first].heapIndex = first;
        snapshotHeap[second].heapIndex = second;
    }

    private static boolean snapshotPrecedes(SnapshotState first, SnapshotState second) {
        int revisionOrder = Long.compare(first.revision, second.revision);
        return revisionOrder < 0 || revisionOrder == 0
                && first.allocationWatermark < second.allocationWatermark;
    }

    private void clearSnapshotHeap() {
        for (int index = 0; index < liveSnapshots; index++) {
            snapshotHeap[index].heapIndex = -1;
            snapshotHeap[index] = null;
        }
        liveSnapshots = 0;
        resetSnapshotAdmissionBaseline();
    }

    private void resetSnapshotAdmissionBaseline() {
        lastSnapshotRevision = -1L;
        lastSnapshotWatermark = 0L;
    }

    private void releaseRetainedNodesBeforeOldestSnapshot() {
        long releaseWatermark = liveSnapshots == 0
                ? retainedAllocationWatermark : snapshotHeap[0].allocationWatermark;
        long protectedReleaseWatermark = liveSnapshots == 0
                ? protectedNodeWatermark
                : snapshotHeap[0].protectedAllocationWatermark;
        long releaseBytes = Math.subtractExact(releaseWatermark,
                releasedRetainedWatermark);
        long protectedReleaseBytes = Math.subtractExact(protectedReleaseWatermark,
                releasedProtectedWatermark);
        long ordinaryReleaseBytes = Math.subtractExact(releaseBytes, protectedReleaseBytes);
        if (ordinaryReleaseBytes > 0L) {
            capacity.releaseCommitted(ordinaryReleaseBytes);
        }
        if (protectedReleaseBytes > 0L) {
            capacity.releaseCommitted(protectedReleaseBytes,
                    SigningTransitionWorkspaceSizing.AdmissionClass
                            .PROTECTED_ACCEPTED_SIGNING);
        }
        releasedRetainedWatermark = releaseWatermark;
        releasedProtectedWatermark = protectedReleaseWatermark;
    }

    private void release(SnapshotState state) {
        Runnable signal = null;
        writeLock.lock();
        try {
            state.writeAccess.lock();
            try {
                if (!state.closed.compareAndSet(false, true)) {
                    return;
                }
                removeSnapshotState(state);
                state.pins.close();
                capacity.releaseCommitted(state.reservedBytes);
                releaseRetainedNodesBeforeOldestSnapshot();
                if (liveSnapshots == 0) {
                    signal = snapshotCloseSignal;
                    snapshotCloseSignal = null;
                }
            } finally {
                state.writeAccess.unlock();
            }
        } finally {
            writeLock.unlock();
        }
        if (signal != null) {
            signal.run();
        }
    }

    private void closeSnapshotState(SnapshotState state) {
        state.writeAccess.lock();
        try {
            if (state.closed.compareAndSet(false, true)) {
                state.pins.close();
                capacity.releaseCommitted(state.reservedBytes);
            }
        } finally {
            state.writeAccess.unlock();
        }
    }

    private static void requireNextRevision(long baseRevision, long revision) {
        if (baseRevision == Long.MAX_VALUE || revision != baseRevision + 1L) {
            throw new IllegalArgumentException("signing index revision is not contiguous");
        }
    }

    private void requireSnapshotSpan(long revision) {
        if (liveSnapshots > 0
                && revision - snapshotHeap[0].revision > configuration.maximumSnapshotRevisionSpan) {
            throw new IllegalStateException("signing index snapshot revision span is exhausted");
        }
    }

    private void requireEmptyRecoveryTarget(long revision, long sequence, int count) {
        if (currentRevision != 0L || lastSequence >= 0L || currentKeys != 0
                || revision < 0L || sequence < -1L || count > configuration.maximumKeys) {
            throw new IllegalStateException("signing index recovery baseline is invalid");
        }
    }

    private static void validateRecoveryOrder(long revision, long committedSequence,
            List<RecoveredRecord> records) {
        MetadataKey previous = null;
        for (RecoveredRecord record : records) {
            Objects.requireNonNull(record, "record");
            if (record.revision > revision || record.pointer.sequence > committedSequence
                    || previous != null && compare(previous, record.key) >= 0) {
                throw new IllegalArgumentException("signing index recovery record is invalid");
            }
            previous = record.key;
        }
    }

    private static OrderedNode buildBalanced(List<RecoveredRecord> records, int from, int to,
            Map<MetadataKey, PrimarySlot> candidatePrimary, AllocationCounter allocations) {
        if (from >= to) {
            return null;
        }
        int middle = (from + to) >>> 1;
        RecoveredRecord recovered = records.get(middle);
        CanonicalKey key = CanonicalKey.of(recovered.key);
        SnapshotRecord record = new SnapshotRecord(recovered.key, recovered.pointer, recovered.revision);
        CurrentEntry entry = new CurrentEntry(key, record);
        candidatePrimary.put(recovered.key, new PrimarySlot(entry));
        OrderedNode left = buildBalanced(records, from, middle, candidatePrimary, allocations);
        OrderedNode right = buildBalanced(records, middle + 1, to, candidatePrimary, allocations);
        allocations.count++;
        return new OrderedNode(entry, left, right, Math.max(height(left), height(right)) + 1);
    }

    private static int hashCapacity(int entries) {
        if (entries == 0) {
            return 1;
        }
        long capacity = Math.addExact(entries, Math.max(1L, entries / 3L));
        return (int) Math.min(Integer.MAX_VALUE, capacity);
    }

    private static long canonicalBytes(Iterable<PrimarySlot> entries) {
        long result = 0L;
        for (PrimarySlot slot : entries) {
            result = Math.addExact(result, slot.published.key.byteLength());
        }
        return result;
    }

    private static long checkpointIndexBytes(Iterable<PrimarySlot> entries) {
        long result = 0L;
        for (PrimarySlot slot : entries) {
            result = Math.addExact(result, slot.published.key.checkpointIndexBytes());
        }
        return result;
    }

    private static Map<Long, Integer> countGenerationReferences(Iterable<PrimarySlot> entries) {
        Map<Long, Integer> result = new HashMap<>();
        for (PrimarySlot slot : entries) {
            result.merge(slot.published.record.pointer.generationId, 1, Math::addExact);
        }
        return result;
    }

    private void addGeneration(SnapshotRecord record) {
        if (record != null) {
            currentGenerationReferences.merge(record.pointer.generationId, 1, Math::addExact);
        }
    }

    private void removeGeneration(CurrentEntry entry) {
        if (entry == null) {
            return;
        }
        long identity = entry.record.pointer.generationId;
        Integer count = currentGenerationReferences.get(identity);
        if (count == null || count <= 0) {
            throw new IllegalStateException("signing index generation accounting is inconsistent");
        }
        if (count == 1) {
            currentGenerationReferences.remove(identity);
        } else {
            currentGenerationReferences.put(identity, count - 1);
        }
    }

    private long baseReservationDelta(List<UpdatePlan> plans) {
        long result = 0L;
        for (UpdatePlan plan : plans) {
            if (plan.existing == null) {
                result = Math.addExact(result,
                        reservationBytes(plan.replacementEntry));
            } else if (plan.replacement == null) {
                result = Math.subtractExact(result,
                        reservationBytes(plan.existing));
            }
        }
        return result;
    }

    private long reservationBytes(CurrentEntry entry) {
        return detachedCapacityAccounting && entry.transientCanonicalShared
                ? CURRENT_ENTRY_FIXED_BYTES : entry.key.estimatedResidentBytes();
    }

    private static OrderedNode applyToRoot(OrderedNode root, List<UpdatePlan> plans,
            AllocationCounter allocations) {
        OrderedNode candidate = root;
        for (UpdatePlan plan : plans) {
            candidate = plan.replacement == null
                    ? remove(candidate, plan.key, allocations)
                    : put(candidate, plan.replacementEntry, allocations);
        }
        return candidate;
    }

    private static OrderedNode find(OrderedNode root, MetadataKey key) {
        OrderedNode cursor = root;
        while (cursor != null) {
            int order = compare(key, cursor.entry.key.metadataKey);
            if (order == 0) {
                return cursor;
            }
            cursor = order < 0 ? cursor.left : cursor.right;
        }
        return null;
    }

    private static OrderedNode lowerBound(OrderedNode root, MetadataKey key) {
        OrderedNode cursor = root;
        OrderedNode result = null;
        while (cursor != null) {
            if (compare(cursor.entry.key.metadataKey, key) >= 0) {
                result = cursor;
                cursor = cursor.left;
            } else {
                cursor = cursor.right;
            }
        }
        return result;
    }

    private static MetadataKey currentRangeLower(String namespace, String lowerInclusive,
            Optional<String> upperExclusive) {
        MetadataKey lower = new MetadataKey(
                Objects.requireNonNull(namespace, "namespace"),
                Objects.requireNonNull(lowerInclusive, "lowerInclusive"));
        Optional<String> upper = Objects.requireNonNull(upperExclusive, "upperExclusive");
        if (upper.isPresent() && lower.key().compareTo(upper.orElseThrow()) >= 0) {
            throw new IllegalArgumentException("signing current range is invalid");
        }
        return lower;
    }

    private static boolean currentRangeContains(MetadataKey candidate, MetadataKey lower,
            Optional<String> upperExclusive) {
        return candidate.namespace().equals(lower.namespace())
                && candidate.key().compareTo(lower.key()) >= 0
                && (upperExclusive.isEmpty()
                        || candidate.key().compareTo(upperExclusive.orElseThrow()) < 0);
    }

    private static OrderedNode put(OrderedNode node, CurrentEntry entry,
            AllocationCounter allocations) {
        if (node == null) {
            return newNode(entry, null, null, allocations);
        }
        int order = entry.key.compareTo(node.entry.key);
        if (order == 0) {
            return newNode(entry, node.left, node.right, allocations);
        }
        OrderedNode changed = order < 0
                ? newNode(node.entry, put(node.left, entry, allocations), node.right, allocations)
                : newNode(node.entry, node.left, put(node.right, entry, allocations), allocations);
        return balance(changed, allocations);
    }

    private static OrderedNode remove(OrderedNode node, CanonicalKey key,
            AllocationCounter allocations) {
        if (node == null) {
            throw new IllegalStateException("signing ordered index is inconsistent");
        }
        int order = key.compareTo(node.entry.key);
        if (order < 0) {
            return balance(newNode(node.entry, remove(node.left, key, allocations),
                    node.right, allocations), allocations);
        }
        if (order > 0) {
            return balance(newNode(node.entry, node.left,
                    remove(node.right, key, allocations), allocations), allocations);
        }
        if (node.left == null) {
            return node.right;
        }
        if (node.right == null) {
            return node.left;
        }
        OrderedNode successor = minimum(node.right);
        return balance(newNode(successor.entry, node.left,
                remove(node.right, successor.entry.key, allocations), allocations), allocations);
    }

    private static OrderedNode minimum(OrderedNode node) {
        OrderedNode cursor = node;
        while (cursor.left != null) {
            cursor = cursor.left;
        }
        return cursor;
    }

    private static OrderedNode balance(OrderedNode node, AllocationCounter allocations) {
        int difference = height(node.left) - height(node.right);
        if (difference > 1) {
            if (height(node.left.left) < height(node.left.right)) {
                OrderedNode adjusted = newNode(node.entry,
                        rotateLeft(node.left, allocations), node.right, allocations);
                return rotateRight(adjusted, allocations);
            }
            return rotateRight(node, allocations);
        }
        if (difference < -1) {
            if (height(node.right.right) < height(node.right.left)) {
                OrderedNode adjusted = newNode(node.entry, node.left,
                        rotateRight(node.right, allocations), allocations);
                return rotateLeft(adjusted, allocations);
            }
            return rotateLeft(node, allocations);
        }
        return node;
    }

    private static OrderedNode rotateLeft(OrderedNode node, AllocationCounter allocations) {
        OrderedNode pivot = node.right;
        OrderedNode moved = newNode(node.entry, node.left, pivot.left, allocations);
        return newNode(pivot.entry, moved, pivot.right, allocations);
    }

    private static OrderedNode rotateRight(OrderedNode node, AllocationCounter allocations) {
        OrderedNode pivot = node.left;
        OrderedNode moved = newNode(node.entry, pivot.right, node.right, allocations);
        return newNode(pivot.entry, pivot.left, moved, allocations);
    }

    private static OrderedNode newNode(CurrentEntry entry, OrderedNode left,
            OrderedNode right, AllocationCounter allocations) {
        allocations.count++;
        return new OrderedNode(entry, left, right, Math.max(height(left), height(right)) + 1);
    }

    private static int height(OrderedNode node) {
        return node == null ? 0 : node.height;
    }

    private static List<SnapshotRecord> range(OrderedNode root, MetadataKey lower,
            MetadataKey upper, byte[] prefix, int maximumResults) {
        if (maximumResults <= 0) {
            throw new IllegalArgumentException("signing index range bound is invalid");
        }
        Deque<OrderedNode> stack = new ArrayDeque<>();
        OrderedNode cursor = root;
        while (cursor != null) {
            if (compare(cursor.entry.key.metadataKey, lower) >= 0) {
                stack.push(cursor);
                cursor = cursor.left;
            } else {
                cursor = cursor.right;
            }
        }
        List<SnapshotRecord> result = new ArrayList<>(Math.min(maximumResults, stack.size()));
        while (!stack.isEmpty() && result.size() < maximumResults) {
            OrderedNode next = stack.pop();
            MetadataKey key = next.entry.key.metadataKey;
            if (upper != null && compare(key, upper) >= 0) {
                break;
            }
            if (prefix != null && (!key.namespace().equals(lower.namespace())
                    || !startsWith(next.entry.key.keyBytes, prefix))) {
                break;
            }
            result.add(next.entry.record);
            cursor = next.right;
            while (cursor != null) {
                stack.push(cursor);
                cursor = cursor.left;
            }
        }
        return List.copyOf(result);
    }

    private static int compare(MetadataKey first, MetadataKey second) {
        int namespace = first.namespace().compareTo(second.namespace());
        return namespace != 0 ? namespace : first.key().compareTo(second.key());
    }

    private static boolean startsWith(byte[] value, byte[] prefix) {
        if (value.length < prefix.length) {
            return false;
        }
        for (int index = 0; index < prefix.length; index++) {
            if (value[index] != prefix[index]) {
                return false;
            }
        }
        return true;
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("signing MVCC index is closed");
        }
    }

    /* default */ record Configuration(int maximumKeys, int maximumSnapshots,
            long maximumSnapshotRevisionSpan, long maxRetainedObsoleteVersions) {
        Configuration {
            if (maximumKeys <= 0 || maximumKeys > FOUR_GIB_MAXIMUM_KEYS
                    || maximumSnapshots <= 0 || maximumSnapshotRevisionSpan <= 0L
                    || maxRetainedObsoleteVersions != 0L) {
                throw new IllegalArgumentException("signing MVCC index configuration is invalid");
            }
        }
    }

    /* default */ record RecordPointer(long generationId, long sequence, long revision,
            SigningWalFrameCodec.RecordType recordType, SigningRecordPointerSlot pointerSlot) {
        RecordPointer {
            Objects.requireNonNull(recordType, "recordType");
            Objects.requireNonNull(pointerSlot, "pointerSlot");
            if (generationId < 0L || sequence < 0L || revision <= 0L) {
                throw new IllegalArgumentException("signing record pointer is invalid");
            }
        }

        /* default */ RecordPointer(long generationId, long frameOffset, int frameLength,
                long sequence, SigningWalFrameCodec.RecordType recordType) {
            this(generationId, frameOffset, frameLength, sequence,
                    Math.incrementExact(sequence), recordType);
        }

        /* default */ RecordPointer(long generationId, long frameOffset, int frameLength,
                long sequence, long revision, SigningWalFrameCodec.RecordType recordType) {
            this(generationId, sequence, revision, recordType,
                    SigningRecordPointerSlot.resolved(frameOffset, frameLength));
        }

        /* default */ long frameOffset() {
            return pointerSlot.offset();
        }

        /* default */ int frameLength() {
            return pointerSlot.length();
        }
    }

    /* default */ record Mutation(MetadataKey key, RecordPointer pointer, long sequence) {
        Mutation {
            Objects.requireNonNull(key, "key");
            if (sequence < 0L) {
                throw new IllegalArgumentException("signing mutation sequence is invalid");
            }
        }

        /* default */ static Mutation upsert(MetadataKey key, RecordPointer pointer) {
            RecordPointer checked = Objects.requireNonNull(pointer, "pointer");
            return new Mutation(key, checked, checked.sequence);
        }

        /* default */ static Mutation delete(MetadataKey key, long sequence) {
            return new Mutation(key, null, sequence);
        }
    }

    /** One validated committed frame supplied to a detached group application. */
    /* default */ record CommittedFrame(long revision, long sequence,
            List<Mutation> mutations) {
        CommittedFrame {
            mutations = List.copyOf(Objects.requireNonNull(mutations, "mutations"));
            if (revision <= 0L || sequence < 0L
                    || mutations.size() > MAX_MUTATIONS_PER_REVISION) {
                throw new IllegalArgumentException("signing committed frame is invalid");
            }
        }
    }

    /* default */ record SnapshotRecord(MetadataKey key, RecordPointer pointer, long revision) {
        SnapshotRecord {
            Objects.requireNonNull(key, "key");
            Objects.requireNonNull(pointer, "pointer");
            if (revision <= 0L) {
                throw new IllegalArgumentException("signing snapshot record revision is invalid");
            }
        }
    }

    /* default */ record RecoveredRecord(MetadataKey key, RecordPointer pointer, long revision) {
        RecoveredRecord {
            Objects.requireNonNull(key, "key");
            Objects.requireNonNull(pointer, "pointer");
            if (revision <= 0L) {
                throw new IllegalArgumentException("signing recovery record revision is invalid");
            }
        }
    }

    /** Opaque detached root owned by one relocation swap token. */
    /* default */ static final class RelocationRootState implements AutoCloseable {
        private final SigningMvccIndex detachedOwner;
        private final Map<MetadataKey, PrimarySlot> primary;
        private final Map<Long, Integer> generationReferences;
        private final OrderedNode orderedRoot;
        private final long revision;
        private final long lastSequence;
        private final long canonicalKeyBytes;
        private final long checkpointIndexBytes;
        private final long reservedBytes;
        private final long orderedNodeAllocations;
        private final int currentKeys;
        private RootOwnership ownership = RootOwnership.LOCAL;

        private RelocationRootState(SigningMvccIndex detachedOwner,
                Map<MetadataKey, PrimarySlot> primary,
                Map<Long, Integer> generationReferences, OrderedNode orderedRoot,
                long revision, long lastSequence, long canonicalKeyBytes,
                long checkpointIndexBytes, long reservedBytes,
                long orderedNodeAllocations, int currentKeys) {
            this.detachedOwner = detachedOwner;
            this.primary = primary;
            this.generationReferences = generationReferences;
            this.orderedRoot = orderedRoot;
            this.revision = revision;
            this.lastSequence = lastSequence;
            this.canonicalKeyBytes = canonicalKeyBytes;
            this.checkpointIndexBytes = checkpointIndexBytes;
            this.reservedBytes = reservedBytes;
            this.orderedNodeAllocations = orderedNodeAllocations;
            this.currentKeys = currentKeys;
        }

        /* default */ long revision() {
            return revision;
        }

        /* default */ long lastSequence() {
            return lastSequence;
        }

        private long steadyReservedBytes() {
            return Math.addExact(Math.multiplyExact(canonicalKeyBytes, 2L),
                    Math.multiplyExact(currentKeys, CURRENT_ENTRY_FIXED_BYTES));
        }

        private void requireOwned() {
            if (ownership != RootOwnership.PREPARED) {
                throw new IllegalStateException("signing relocation root is not owned");
            }
        }

        /* default */ void prepareTransfer() {
            if (ownership != RootOwnership.LOCAL) {
                throw new IllegalStateException("signing relocation root is not local");
            }
            ownership = RootOwnership.PREPARED;
        }

        private void transfer() {
            requireOwned();
            ownership = RootOwnership.LIVE;
        }

        /* default */ void rollbackPrepared() {
            if (ownership == RootOwnership.PREPARED) {
                ownership = RootOwnership.CLOSED;
                releaseOwnership();
            }
        }

        @Override
        public void close() {
            if (ownership == RootOwnership.LOCAL) {
                ownership = RootOwnership.CLOSED;
                releaseOwnership();
            }
        }

        private void releaseOwnership() {
            detachedOwner.generations.releaseCurrentCounts(
                    SigningGenerationRegistry.Owner.MVCC, generationReferences);
            if (reservedBytes > 0L) {
                detachedOwner.capacity.releaseCommitted(reservedBytes);
            }
        }

        /** Root stages guarded first by candidate preparation, then by its swap token. */
        private enum RootOwnership {
            LOCAL,
            PREPARED,
            LIVE,
            CLOSED
        }
    }

    /** Pre-side-effect transient reservation for one exact snapshot candidate. */
    /* default */ static final class RelocationCapacity implements AutoCloseable {
        private final SigningMvccIndex owner;
        private final SnapshotState state;
        private final long bytes;
        private final SigningIndexCapacityBudget.Reservation reservation;
        private final AtomicBoolean active = new AtomicBoolean(true);

        private RelocationCapacity(SigningMvccIndex owner, SnapshotState state,
                long bytes, SigningIndexCapacityBudget.Reservation reservation) {
            this.owner = owner;
            this.state = state;
            this.bytes = bytes;
            this.reservation = reservation;
        }

        @SuppressWarnings("PMD.CompareObjectsWithEquals") // Snapshot ownership is identity-based.
        private long require(SigningMvccIndex expectedOwner, SnapshotState expectedState) {
            if (!active.get() || owner != expectedOwner || state != expectedState) {
                throw new IllegalStateException("signing relocation capacity ownership is inconsistent");
            }
            return bytes;
        }

        private void transfer() {
            if (!active.compareAndSet(true, false)) {
                throw new IllegalStateException("signing relocation capacity is not active");
            }
            reservation.transfer();
        }

        @Override
        public void close() {
            if (active.compareAndSet(true, false)) {
                reservation.close();
            }
        }
    }

    /** Controlled cutover deferral caused by an external live snapshot. */
    /* default */ static final class RelocationDeferredException extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        private RelocationDeferredException(String message) {
            super(message);
        }
    }


    /**
     * Rollback-capable publication prepared entirely before WAL admission.
     * Closing is idempotent; successful publication transfers all reservations.
     */
    /* default */ final class PreparedApply implements AutoCloseable {
        private final long revision;
        private final long sequence;
        private final List<UpdatePlan> plans;
        private final List<PrimarySlot> slots;
        private final OrderedNode candidateRoot;
        private final int candidateKeys;
        private final Map<Long, Integer> candidateReferences;
        private final long allocations;
        private final long baseDelta;
        private final long nodeBytes;
        private final SigningIndexCapacityBudget.Reservation baseReservation;
        private final SigningIndexCapacityBudget.Reservation nodeReservation;
        private final SigningGenerationRegistry.CurrentReferences newReferences;
        private final SigningTransitionWorkspaceSizing.AdmissionClass admissionClass;
        private boolean active = true;

        private PreparedApply(long revision, long sequence, List<UpdatePlan> plans,
                List<PrimarySlot> slots, OrderedNode candidateRoot, int candidateKeys,
                Map<Long, Integer> candidateReferences, long allocations,
                long baseDelta, long nodeBytes,
                SigningIndexCapacityBudget.Reservation baseReservation,
                SigningIndexCapacityBudget.Reservation nodeReservation,
                SigningGenerationRegistry.CurrentReferences newReferences,
                SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
            this.revision = revision;
            this.sequence = sequence;
            this.plans = plans;
            this.slots = List.copyOf(slots);
            this.candidateRoot = candidateRoot;
            this.candidateKeys = candidateKeys;
            this.candidateReferences = candidateReferences;
            this.allocations = allocations;
            this.baseDelta = baseDelta;
            this.nodeBytes = nodeBytes;
            this.baseReservation = baseReservation;
            this.nodeReservation = nodeReservation;
            this.newReferences = newReferences;
            this.admissionClass = admissionClass;
        }

        /* default */ long revision() {
            return revision;
        }

        /* default */ void publish() {
            writeLock.lock();
            try {
                requireOpen();
                if (!active || preparedApplies.peekFirst() != this) {
                    throw new IllegalStateException("signing prepared publication order is invalid");
                }
                long retainedDelta = liveSnapshots == 0 ? 0L : nodeBytes;
                long nextAllocationWatermark = retainedWatermarkAfter(retainedDelta);
                long nextProtectedWatermark = protectedWatermarkAfter(
                        retainedDelta, admissionClass);
                SigningMvccIndex.this.publish(revision, sequence, plans, slots,
                        candidateRoot, allocations, baseDelta, nextAllocationWatermark,
                        nextProtectedWatermark);
                preparedApplies.removeFirst();
                active = false;
                newReferences.transfer();
                if (baseDelta > 0L) {
                    baseReservation.transfer();
                }
                if (retainedDelta > 0L) {
                    nodeReservation.transfer();
                }
                generations.releaseCurrent(SigningGenerationRegistry.Owner.MVCC,
                        new PreviousGenerationIds(plans));
                if (baseDelta < 0L) {
                    capacity.releaseCommitted(-baseDelta);
                }
                baseReservation.close();
                nodeReservation.close();
                newReferences.close();
            } finally {
                writeLock.unlock();
            }
        }

        @Override
        public void close() {
            writeLock.lock();
            try {
                closeLocked();
            } finally {
                writeLock.unlock();
            }
        }

        private void closeLocked() {
            if (!active) {
                return;
            }
            if (!preparedApplies.contains(this)) {
                throw new IllegalStateException("signing prepared publication ownership is inconsistent");
            }
            while (true) {
                PreparedApply rollback = preparedApplies.removeLast();
                rollback.rollbackOne();
                if (rollback == this) break;
            }
        }

        private void rollbackOne() {
            if (!active) return;
            active = false;
            rollbackSlots(plans, slots);
            newReferences.close();
            nodeReservation.close();
            baseReservation.close();
        }
    }

    /** Immutable snapshot handle with close-versus-read exclusion. */
    /* default */ static final class Snapshot implements AutoCloseable {
        private final SigningMvccIndex owner;
        private final SnapshotState state;

        private Snapshot(SigningMvccIndex owner, SnapshotState state) {
            this.owner = owner;
            this.state = state;
        }

        /* default */ long revision() {
            state.readAccess.lock();
            try {
                requireOpen();
                return state.revision;
            } finally {
                state.readAccess.unlock();
            }
        }

        /* default */ long committedSequence() {
            state.readAccess.lock();
            try {
                requireOpen();
                return state.committedSequence;
            } finally {
                state.readAccess.unlock();
            }
        }

        /* default */ int size() {
            state.readAccess.lock();
            try {
                requireOpen();
                return state.size;
            } finally {
                state.readAccess.unlock();
            }
        }

        /* default */ long checkpointDataOffset() {
            state.readAccess.lock();
            try {
                requireOpen();
                return state.checkpointDataOffset;
            } finally {
                state.readAccess.unlock();
            }
        }

        /* default */ Optional<SnapshotRecord> lookup(MetadataKey key) {
            state.readAccess.lock();
            try {
                requireOpen();
                OrderedNode node = find(state.root, Objects.requireNonNull(key, "key"));
                return node == null ? Optional.empty() : Optional.of(node.entry.record);
            } finally {
                state.readAccess.unlock();
            }
        }

        /* default */ List<SnapshotRecord> range(MetadataKey lowerInclusive,
                MetadataKey upperExclusive, int maximumResults) {
            state.readAccess.lock();
            try {
                requireOpen();
                Objects.requireNonNull(lowerInclusive, "lowerInclusive");
                Objects.requireNonNull(upperExclusive, "upperExclusive");
                if (compare(lowerInclusive, upperExclusive) >= 0) {
                    throw new IllegalArgumentException("signing index range is invalid");
                }
                return SigningMvccIndex.range(state.root, lowerInclusive,
                        upperExclusive, null, maximumResults);
            } finally {
                state.readAccess.unlock();
            }
        }

        /* default */ List<SnapshotRecord> prefix(String namespace, String prefix,
                int maximumResults) {
            state.readAccess.lock();
            try {
                requireOpen();
                Objects.requireNonNull(prefix, "prefix");
                String lowerKey = prefix.isEmpty() ? "!" : prefix;
                MetadataKey lower = new MetadataKey(namespace, lowerKey);
                byte[] prefixBytes = prefix.getBytes(StandardCharsets.US_ASCII);
                return SigningMvccIndex.range(state.root, lower, null,
                        prefixBytes, maximumResults);
            } finally {
                state.readAccess.unlock();
            }
        }

        /** Returns a bounded canonical page beginning at one inclusive key. */
        /* default */ List<SnapshotRecord> rangeFrom(MetadataKey lowerInclusive,
                int maximumResults) {
            state.readAccess.lock();
            try {
                requireOpen();
                return SigningMvccIndex.range(state.root,
                        Objects.requireNonNull(lowerInclusive, "lowerInclusive"),
                        null, null, maximumResults);
            } finally {
                state.readAccess.unlock();
            }
        }

        /** Returns the greatest key in one namespace in {@code O(log M)} time. */
        /* default */ Optional<MetadataKey> greatest(String namespace) {
            state.readAccess.lock();
            try {
                requireOpen();
                Objects.requireNonNull(namespace, "namespace");
                OrderedNode node = state.root;
                MetadataKey result = null;
                while (node != null) {
                    int order = node.entry.key.metadataKey.namespace().compareTo(namespace);
                    if (order <= 0) {
                        if (order == 0) {
                            result = node.entry.key.metadataKey;
                        }
                        node = node.right;
                    } else {
                        node = node.left;
                    }
                }
                return Optional.ofNullable(result);
            } finally {
                state.readAccess.unlock();
            }
        }

        /** Visits records in canonical order with {@code O(log M)} traversal state. */
        /* default */ void visit(RecordVisitor visitor) throws IOException {
            Objects.requireNonNull(visitor, "visitor");
            state.readAccess.lock();
            try {
                requireOpen();
                Deque<OrderedNode> stack = new ArrayDeque<>();
                OrderedNode cursor = state.root;
                while (cursor != null || !stack.isEmpty()) {
                    while (cursor != null) {
                        stack.push(cursor);
                        cursor = cursor.left;
                    }
                    OrderedNode next = stack.pop();
                    visitor.accept(next.entry.record);
                    cursor = next.right;
                }
            } finally {
                state.readAccess.unlock();
            }
        }

        @Override
        public void close() {
            owner.release(state);
        }

        private void requireOpen() {
            if (state.closed.get()) {
                throw new IllegalStateException("signing index snapshot is closed");
            }
        }
    }

    /** Bounded checked visitor used by package-owned checkpoint maintenance. */
    @FunctionalInterface
    @SuppressWarnings("PMD.CommentDefaultAccessModifier")
    /* default */ interface RecordVisitor {
        /** Accepts one canonical-order immutable snapshot record. */
        void accept(SnapshotRecord record) throws IOException;
    }

    /* default */ @SuppressWarnings("PMD.LongVariable")
    record Statistics(long revision, long lastSequence, int currentKeys,
            int liveSnapshots, long canonicalKeyBytes, long orderedNodeAllocations,
            long retainedOrderedNodeUpperBound, long estimatedResidentBytes,
            long reservedBytes, long sharedReservedBytes,
            long retainedObsoleteVersions, long fullMapCopies) {

        /* default */ int retainedKeys() {
            return currentKeys;
        }
    }

    /** One current identity representation shared by hash and ordered nodes. */
    private static final class CurrentEntry {
        private final CanonicalKey key;
        private final SnapshotRecord record;
        private final boolean transientCanonicalShared;

        private CurrentEntry(CanonicalKey key, SnapshotRecord record) {
            this(key, record, false);
        }

        private CurrentEntry(CanonicalKey key, SnapshotRecord record,
                boolean transientCanonicalShared) {
            this.key = key;
            this.record = record;
            this.transientCanonicalShared = transientCanonicalShared;
        }
    }

    /** Canonical admission-time ASCII bytes used by allocation-free AVL comparisons. */
    private static final class CanonicalKey implements Comparable<CanonicalKey> {
        private final MetadataKey metadataKey;
        private final byte[] namespaceBytes;
        private final byte[] keyBytes;
        private final int checkpointIndexBytes;

        private CanonicalKey(MetadataKey metadataKey, byte[] namespaceBytes, byte[] keyBytes) {
            this.metadataKey = metadataKey;
            this.namespaceBytes = namespaceBytes;
            this.keyBytes = keyBytes;
            checkpointIndexBytes = SigningCheckpointCodec.encodedIndexBytes(
                    metadataKey.canonical());
        }

        private static CanonicalKey of(MetadataKey metadataKey) {
            return new CanonicalKey(metadataKey,
                    metadataKey.namespace().getBytes(StandardCharsets.US_ASCII),
                    metadataKey.key().getBytes(StandardCharsets.US_ASCII));
        }

        private long byteLength() {
            return Math.addExact(namespaceBytes.length, keyBytes.length);
        }

        private long estimatedResidentBytes() {
            return Math.addExact(CURRENT_ENTRY_FIXED_BYTES,
                    Math.multiplyExact(byteLength(), 2L));
        }

        private int checkpointIndexBytes() {
            return checkpointIndexBytes;
        }

        @Override
        public int compareTo(CanonicalKey other) {
            int namespace = Arrays.compareUnsigned(namespaceBytes, other.namespaceBytes);
            return namespace != 0 ? namespace : Arrays.compareUnsigned(keyBytes, other.keyBytes);
        }
    }

    /** Immutable persistent AVL node. */
    private static final class OrderedNode {
        private final CurrentEntry entry;
        private final OrderedNode left;
        private final OrderedNode right;
        private final int height;

        private OrderedNode(CurrentEntry entry, OrderedNode left, OrderedNode right, int height) {
            this.entry = entry;
            this.left = left;
            this.right = right;
            this.height = height;
        }
    }

    /** Owner-tracked root, pins, lifecycle lock, and budget reservation. */
    private static final class SnapshotState {
        private final long revision;
        private final long committedSequence;
        private final int size;
        private final long checkpointDataOffset;
        private final long canonicalKeyBytes;
        private final long checkpointIndexBytes;
        private final OrderedNode root;
        private final SigningGenerationRegistry.SnapshotPins pins;
        private final long reservedBytes;
        private final long allocationWatermark;
        private final long protectedAllocationWatermark;
        private final AtomicBoolean closed = new AtomicBoolean();
        private final ReentrantReadWriteLock access = new ReentrantReadWriteLock();
        private final Lock readAccess = access.readLock();
        private final Lock writeAccess = access.writeLock();
        private int heapIndex = -1;

        private SnapshotState(long revision, long committedSequence, int size,
                long checkpointDataOffset, long canonicalKeyBytes,
                long checkpointIndexBytes, OrderedNode root,
                SigningGenerationRegistry.SnapshotPins pins, long reservedBytes,
                long allocationWatermark, long protectedAllocationWatermark) {
            this.revision = revision;
            this.committedSequence = committedSequence;
            this.size = size;
            this.checkpointDataOffset = checkpointDataOffset;
            this.canonicalKeyBytes = canonicalKeyBytes;
            this.checkpointIndexBytes = checkpointIndexBytes;
            this.root = root;
            this.pins = pins;
            this.reservedBytes = reservedBytes;
            this.allocationWatermark = allocationWatermark;
            this.protectedAllocationWatermark = protectedAllocationWatermark;
        }
    }

    /** Counts exactly constructed AVL nodes. */
    private static final class AllocationCounter {
        private long count;
    }

    /** One-pass cursor constructing relocated entries directly from the snapshot root. */
    private static final class RelocatedBuildCursor {
        private final OrderedIterator entries;
        private final long generationId;
        private long offset;

        private RelocatedBuildCursor(OrderedNode root, long generationId, long offset) {
            entries = new OrderedIterator(root);
            this.generationId = generationId;
            this.offset = offset;
        }

        private CurrentEntry next() {
            CurrentEntry source = entries.next();
            SnapshotRecord record = source.record;
            RecordPointer previous = record.pointer;
            RecordPointer pointer = new RecordPointer(generationId, offset,
                    previous.frameLength(), previous.sequence(), record.revision,
                    previous.recordType());
            offset = Math.addExact(offset, previous.frameLength());
            return new CurrentEntry(source.key,
                    new SnapshotRecord(record.key, pointer, record.revision), true);
        }

        private boolean hasRemaining() {
            return entries.hasNext();
        }

        private long offset() {
            return offset;
        }
    }

    /** Fully materialized detached root covered by one preowned reservation. */
    private record RelocatedBuild(Map<MetadataKey, PrimarySlot> primary,
            Map<Long, Integer> generationReferences, OrderedNode root,
            long revision, long lastSequence, long canonicalKeyBytes,
            long checkpointIndexBytes, long reservedBytes,
            long orderedNodeAllocations, int currentKeys, long checkpointEndOffset) {
    }

    private record UpdatePlan(CurrentEntry existing, CanonicalKey key,
            SnapshotRecord replacement, CurrentEntry replacementEntry, long sequence) {
    }

    /** Current hash slot that can be allocated before its durable publication. */
    private static final class PrimarySlot {
        private CurrentEntry published;
        private int pending;

        private PrimarySlot(CurrentEntry published) {
            this.published = published;
        }
    }

    /** Canonical merge that conditionally relocates exact boundary-snapshot values. */
    private static final class RelocatingIterator implements Iterator<CurrentEntry> {
        private final OrderedIterator current;
        private final OrderedIterator snapshot;
        private final long generationId;
        private long checkpointOffset;
        private CurrentEntry snapshotEntry;
        private final Map<Long, Integer> generationReferences = new HashMap<>();

        private RelocatingIterator(OrderedNode currentRoot, OrderedNode snapshotRoot,
                long generationId, long checkpointOffset) {
            current = new OrderedIterator(currentRoot);
            snapshot = new OrderedIterator(snapshotRoot);
            this.generationId = generationId;
            this.checkpointOffset = checkpointOffset;
            snapshotEntry = snapshot.hasNext() ? snapshot.next() : null;
        }

        @Override
        public boolean hasNext() {
            return current.hasNext();
        }

        @Override
        public CurrentEntry next() {
            CurrentEntry value = current.next();
            while (snapshotEntry != null
                    && snapshotEntry.key.compareTo(value.key) < 0) {
                advanceSnapshot();
            }
            if (snapshotEntry != null && snapshotEntry.key.compareTo(value.key) == 0) {
                SnapshotRecord expected = snapshotEntry.record;
                long offset = checkpointOffset;
                advanceSnapshot();
                if (value.record.equals(expected)) {
                    RecordPointer old = expected.pointer;
                    RecordPointer replacement = new RecordPointer(generationId, offset,
                            old.frameLength(), old.sequence, expected.revision, old.recordType);
                    CurrentEntry relocated = new CurrentEntry(value.key,
                            new SnapshotRecord(expected.key, replacement, expected.revision),
                            value.transientCanonicalShared);
                    count(relocated);
                    return relocated;
                }
            }
            count(value);
            return value;
        }

        private void count(CurrentEntry entry) {
            generationReferences.merge(entry.record.pointer.generationId, 1, Math::addExact);
        }

        private Map<Long, Integer> generationReferences() {
            return Map.copyOf(generationReferences);
        }

        private void advanceSnapshot() {
            checkpointOffset = Math.addExact(checkpointOffset,
                    snapshotEntry.record.pointer.frameLength());
            snapshotEntry = snapshot.hasNext() ? snapshot.next() : null;
        }

        private long checkpointEndOffset() {
            while (snapshotEntry != null) {
                advanceSnapshot();
            }
            return checkpointOffset;
        }
    }

    /** Allocation-bounded in-order iterator over one immutable AVL root. */
    private static final class OrderedIterator implements Iterator<CurrentEntry> {
        private final Deque<OrderedNode> stack = new ArrayDeque<>();

        private OrderedIterator(OrderedNode root) {
            pushLeft(root);
        }

        @Override public boolean hasNext() { return !stack.isEmpty(); }

        @Override
        public CurrentEntry next() {
            OrderedNode node = stack.pop();
            pushLeft(node.right);
            return node.entry;
        }

        private void pushLeft(OrderedNode node) {
            OrderedNode cursor = node;
            while (cursor != null) {
                stack.push(cursor);
                cursor = cursor.left;
            }
        }
    }

    /** In-order iterator positioned by one AVL lower-bound traversal. */
    private static final class LowerBoundIterator implements Iterator<CurrentEntry> {
        private final Deque<OrderedNode> stack = new ArrayDeque<>();

        private LowerBoundIterator(OrderedNode root, MetadataKey lowerInclusive) {
            OrderedNode cursor = root;
            while (cursor != null) {
                if (compare(cursor.entry.key.metadataKey, lowerInclusive) >= 0) {
                    stack.push(cursor);
                    cursor = cursor.left;
                } else {
                    cursor = cursor.right;
                }
            }
        }

        @Override public boolean hasNext() { return !stack.isEmpty(); }

        @Override
        public CurrentEntry next() {
            OrderedNode node = stack.pop();
            OrderedNode cursor = node.right;
            while (cursor != null) {
                stack.push(cursor);
                cursor = cursor.left;
            }
            return node.entry;
        }
    }

    /** Zero-copy generation-id view over update plans with new pointers. */
    private static final class GenerationIds extends AbstractCollection<Long> {
        private final List<UpdatePlan> plans;

        private GenerationIds(List<UpdatePlan> plans) {
            super();
            this.plans = plans;
        }

        @Override
        public Iterator<Long> iterator() {
            return plans.stream().filter(plan -> plan.replacement != null)
                    .map(plan -> plan.replacement.pointer.generationId).iterator();
        }

        @Override
        public int size() {
            int count = 0;
            for (UpdatePlan plan : plans) {
                if (plan.replacement != null) {
                    count++;
                }
            }
            return count;
        }
    }

    /** Zero-copy generation-id view over replaced or deleted pointers. */
    private static final class PreviousGenerationIds extends AbstractCollection<Long> {
        private final List<UpdatePlan> plans;

        private PreviousGenerationIds(List<UpdatePlan> plans) {
            super();
            this.plans = plans;
        }

        @Override
        public Iterator<Long> iterator() {
            return plans.stream().filter(plan -> plan.existing != null)
                    .map(plan -> plan.existing.record.pointer.generationId).iterator();
        }

        @Override
        public int size() {
            int count = 0;
            for (UpdatePlan plan : plans) {
                if (plan.existing != null) {
                    count++;
                }
            }
            return count;
        }
    }

    /** Zero-copy generation-id view over checkpoint input. */
    private static final class RecoveryGenerationIds extends AbstractCollection<Long> {
        private final List<RecoveredRecord> records;

        private RecoveryGenerationIds(List<RecoveredRecord> records) {
            super();
            this.records = records;
        }

        @Override
        public Iterator<Long> iterator() {
            return records.stream().map(record -> record.pointer.generationId).iterator();
        }

        @Override
        public int size() {
            return records.size();
        }
    }
}
