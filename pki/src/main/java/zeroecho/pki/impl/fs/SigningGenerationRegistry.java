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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Generation publication, current-pointer ownership, snapshot pins, and reclaim claims.
 *
 * <p>One short-held lock owns all state. New owner-scoped current references and
 * snapshot pin sets are acquired atomically. Reclaim eligibility requires every
 * fixed owner bucket and the pin counter to be zero and is maintained
 * incrementally in identity order; claiming never scans lifetime registrations.
 * Owner accounting is {@code O(1)} per generation operation and uses a fixed
 * number of primitive counters per registered generation. No caller callback or
 * filesystem operation runs under the registry lock.</p>
 */
// The fixed owner buckets and closed generation states are one atomic state
// machine. Its individual methods remain small; splitting it would obscure the
// single-lock accounting invariant solely to lower the aggregate class metric.
@SuppressWarnings({ "PMD.AvoidLiteralsInIfCondition", "PMD.CyclomaticComplexity" })
final class SigningGenerationRegistry implements AutoCloseable {
    private final ReentrantLock lock = new ReentrantLock();
    private final Map<Long, Generation> generations = new HashMap<>();
    private final NavigableSet<Long> reclaimable = new TreeSet<>();
    private boolean closed;

    /**
     * Registers a previously absent nonnegative artifact generation in CREATED state.
     *
     * @param generationId exact nonnegative artifact generation identity
     * @throws IllegalArgumentException if the identity is negative
     * @throws IllegalStateException if the registry is closed or the generation is already registered
     */
    /* default */ void create(long generationId) {
        requireGenerationId(generationId);
        lock.lock();
        try {
            requireOpen();
            if (generations.putIfAbsent(generationId,
                    new Generation(generationId, State.CREATED)) != null) {
                throw new IllegalStateException("signing generation identity is already registered");
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Makes one CREATED artifact generation available for exact current references and snapshot pins.
     *
     * @param generationId exact nonnegative artifact generation identity
     * @throws IllegalArgumentException if the identity is negative
     * @throws IllegalStateException if the registry is closed, identity is unregistered or state is not CREATED
     */
    /* default */ void publish(long generationId) {
        lock.lock();
        try {
            requireOpen();
            Generation generation = requireGeneration(generationId);
            if (generation.state != State.CREATED) {
                throw new IllegalStateException("signing generation publication state is invalid");
            }
            generation.state = State.PUBLISHED;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Marks one published generation superseded and updates its exact reclaim eligibility.
     *
     * @param generationId exact nonnegative artifact generation identity
     * @throws IllegalArgumentException if the identity is negative
     * @throws IllegalStateException if the registry is closed, identity is unregistered or state is not PUBLISHED
     */
    /* default */ void supersede(long generationId) {
        lock.lock();
        try {
            requireOpen();
            Generation generation = requireGeneration(generationId);
            if (generation.state != State.PUBLISHED) {
                throw new IllegalStateException("signing generation supersession state is invalid");
            }
            generation.state = State.SUPERSEDED;
            refreshEligibility(generation);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Removes one unpublished-authority candidate after all of its references close.
     * @param generationId exact registered PUBLISHED generation being discarded
     * @throws IllegalArgumentException if the identity is negative
     * @throws IllegalStateException if the registry is closed, state differs or any current reference or snapshot pin remains
     */
    /* default */ void discardPublished(long generationId) {
        lock.lock();
        try {
            requireOpen();
            Generation generation = requireGeneration(generationId);
            if (generation.state != State.PUBLISHED
                    || generation.hasCurrentReferences() || generation.snapshotPins != 0) {
                throw new IllegalStateException("signing generation discard state is invalid");
            }
            generations.remove(generationId);
            reclaimable.remove(generationId);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Closed internal owners of current-pointer references.
     */
    /* default */ enum Owner {
        /**
         * Ownership retained by the multiversion metadata index.
         */
        MVCC,
        /**
         * Ownership retained by the due-work index.
         */
        DUE,
        /**
         * Ownership retained by the content-owner projection.
         */
        OWNER,
        /**
         * Temporary ownership retained while recovery reconstructs projections.
         */
        RECOVERY_TEMPORARY
    }

    /**
     * Acquires one owner-scoped current-pointer reference per identity, atomically.
     * @param owner fixed reference-owner bucket
     * @param generationIds nonnegative generation identities; duplicate occurrences acquire repeated references
     * @return rollback token; close it or transfer exact reference-release responsibility
     * @throws NullPointerException if an input or identity is null
     * @throws IllegalArgumentException if an identity is negative
     * @throws IllegalStateException if the registry is closed or any generation is not PUBLISHED
     * @throws ArithmeticException if aggregation or reference counters overflow
     */
    /* default */ CurrentReferences acquireCurrent(Owner owner,
            Collection<Long> generationIds) {
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(generationIds, "generationIds");
        return acquireCurrentCounts(owner, countIdentities(generationIds));
    }

    /**
     * Acquires owner-scoped aggregated generation-reference counts atomically in O(G).
     * @param owner fixed reference-owner bucket
     * @param referenceCounts nonnegative generation identities mapped to positive reference counts
     * @return rollback token retaining the exact acquired owner counts
     * @throws NullPointerException if an input, identity or count is null
     * @throws IllegalArgumentException if an identity is negative or a count is not positive
     * @throws IllegalStateException if the registry is closed or any generation is not PUBLISHED
     * @throws ArithmeticException if owner or total reference counters overflow
     */
    /* default */ CurrentReferences acquireCurrentCounts(Owner owner,
            Map<Long, Integer> referenceCounts) {
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(referenceCounts, "referenceCounts");
        Map<Long, Integer> counts = Map.copyOf(referenceCounts);
        lock.lock();
        try {
            requireOpen();
            for (Map.Entry<Long, Integer> entry : counts.entrySet()) {
                requireGenerationId(Objects.requireNonNull(entry.getKey(), "generationId"));
                if (entry.getValue() == null || entry.getValue() <= 0) {
                    throw new IllegalArgumentException(
                            "signing generation reference count is invalid");
                }
                Generation generation = requireGeneration(entry.getKey());
                if (generation.state != State.PUBLISHED) {
                    throw accountingFailure("acquire", generation, owner,
                            entry.getValue(), generation.references(owner));
                }
                Math.addExact(generation.references(owner), entry.getValue());
                Math.addExact(generation.currentReferences, entry.getValue());
            }
            for (Map.Entry<Long, Integer> entry : counts.entrySet()) {
                Generation generation = requireGeneration(entry.getKey());
                generation.addReferences(owner, entry.getValue());
                generation.currentReferences += entry.getValue();
                reclaimable.remove(entry.getKey());
            }
            return new CurrentReferences(this, owner, counts);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Tests exact generation registration while requiring the registry to remain open.
     *
     * @param generationId nonnegative generation identity
     * @return true if that identity is currently registered
     * @throws IllegalArgumentException if the identity is negative
     * @throws IllegalStateException if the registry is closed
     */
    /* default */ boolean contains(long generationId) {
        requireGenerationId(generationId);
        lock.lock();
        try {
            requireOpen();
            return generations.containsKey(generationId);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Atomically releases one owner-scoped current reference for every supplied identity occurrence.
     *
     * @param owner exact fixed owner bucket from which references are released
     * @param generationIds nonnegative generation identities; repeated identities release repeated references
     * @throws NullPointerException if an input or identity is null
     * @throws IllegalArgumentException if an identity is negative
     * @throws IllegalStateException if registration or exact owner-reference accounting is inconsistent
     * @throws ArithmeticException if aggregation of repeated identity counts overflows
     */
    /* default */ void releaseCurrent(Owner owner, Collection<Long> generationIds) {
        Objects.requireNonNull(owner, "owner");
        releaseCurrentCounts(owner, countIdentities(generationIds));
    }

    /**
     * Pins each distinct generation. Published generations are pinnable; a
     * superseded generation remains pinnable only while a current pointer owns it.
     * @param generationIds distinct exact generation identities to pin atomically
     * @return owned idempotent pin set; caller closes it after snapshot reads finish
     * @throws NullPointerException if the collection or an identity is null
     * @throws IllegalArgumentException if an identity is negative or repeated
     * @throws IllegalStateException if the registry is closed or a generation is unavailable or its pin count is exhausted
     */
    /* default */ SnapshotPins pinSnapshot(Collection<Long> generationIds) {
        Objects.requireNonNull(generationIds, "generationIds");
        Set<Long> distinct = new HashSet<>(generationIds);
        if (distinct.size() != generationIds.size()) {
            throw new IllegalArgumentException("signing generation pin set contains a duplicate");
        }
        lock.lock();
        try {
            requireOpen();
            for (Long identity : distinct) {
                Generation generation = requireGeneration(Objects.requireNonNull(identity, "generationId"));
                boolean available = generation.state == State.PUBLISHED
                        || generation.state == State.SUPERSEDED
                        && generation.hasCurrentReferences();
                if (!available || generation.snapshotPins == Integer.MAX_VALUE) {
                    throw new IllegalStateException("signing generation is not available for a snapshot pin");
                }
            }
            for (Long identity : distinct) {
                Generation generation = requireGeneration(identity);
                generation.snapshotPins++;
                reclaimable.remove(identity);
            }
            return new SnapshotPins(this, List.copyOf(distinct));
        } finally {
            lock.unlock();
        }
    }

    /**
     * Claims at most {@code maximumActions} eligible identities in deterministic order.
     * @param maximumActions positive maximum number of identities claimed
     * @return immutable ascending-identity reclaim claims; filesystem deletion remains the caller's responsibility
     * @throws IllegalArgumentException if the limit is not positive
     * @throws IllegalStateException if the registry is closed or reclaim eligibility accounting is inconsistent
     */
    /* default */ List<ReclaimAction> claimReclaimable(int maximumActions) {
        if (maximumActions <= 0) {
            throw new IllegalArgumentException("signing generation reclaim bound is invalid");
        }
        lock.lock();
        try {
            requireOpen();
            int count = Math.min(maximumActions, reclaimable.size());
            List<ReclaimAction> actions = new ArrayList<>(count);
            for (int index = 0; index < count; index++) {
                long identity = reclaimable.pollFirst();
                Generation generation = requireGeneration(identity);
                if (generation.state != State.SUPERSEDED
                        || generation.hasCurrentReferences() || generation.snapshotPins != 0) {
                    throw new IllegalStateException("signing generation reclaim eligibility is inconsistent");
                }
                generation.state = State.RECLAIMING;
                actions.add(new ReclaimAction(identity));
            }
            return List.copyOf(actions);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns a failed external deletion claim to the ordered retry set.
     * @param action exact previously claimed generation whose external deletion failed
     * @throws NullPointerException if the action is null
     * @throws IllegalStateException if the registry is closed or the generation is not RECLAIMING
     */
    /* default */ void reclaimFailed(ReclaimAction action) {
        Objects.requireNonNull(action, "action");
        lock.lock();
        try {
            requireOpen();
            Generation generation = requireGeneration(action.generationId());
            if (generation.state != State.RECLAIMING) {
                throw new IllegalStateException("signing generation reclaim state is invalid");
            }
            generation.state = State.SUPERSEDED;
            refreshEligibility(generation);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Completes external deletion and removes all registry state for the identity.
     * @param action exact previously claimed generation whose external deletion completed
     * @throws NullPointerException if the action is null
     * @throws IllegalStateException if the registry is closed, state is not RECLAIMING or references remain
     */
    /* default */ void reclaimCompleted(ReclaimAction action) {
        Objects.requireNonNull(action, "action");
        lock.lock();
        try {
            requireOpen();
            Generation generation = requireGeneration(action.generationId());
            if (generation.state != State.RECLAIMING
                    || generation.hasCurrentReferences() || generation.snapshotPins != 0) {
                throw new IllegalStateException("signing generation reclaim state is invalid");
            }
            generations.remove(action.generationId());
        } finally {
            lock.unlock();
        }
    }

    /**
     * Captures registration, lifecycle, owner-reference and snapshot-pin counters under one registry lock.
     *
     * @return new immutable constant-size statistics snapshot
     * @throws ArithmeticException if aggregated reference totals cannot fit a signed long
     */
    /* default */ Snapshot statistics() {
        lock.lock();
        try {
            long currentReferences = 0L;
            long snapshotPins = 0L;
            long mvccReferences = 0L;
            long dueReferences = 0L;
            long ownerReferences = 0L;
            long recoveryTemporaryReferences = 0L;
            int published = 0;
            int superseded = 0;
            int reclaiming = 0;
            for (Generation generation : generations.values()) {
                currentReferences = Math.addExact(currentReferences, generation.currentReferences);
                snapshotPins = Math.addExact(snapshotPins, generation.snapshotPins);
                mvccReferences = Math.addExact(mvccReferences, generation.mvccReferences);
                dueReferences = Math.addExact(dueReferences, generation.dueReferences);
                ownerReferences = Math.addExact(ownerReferences, generation.ownerReferences);
                recoveryTemporaryReferences = Math.addExact(recoveryTemporaryReferences,
                        generation.recoveryTemporaryReferences);
                switch (generation.state) {
                    case PUBLISHED -> published++;
                    case SUPERSEDED -> superseded++;
                    case RECLAIMING -> reclaiming++;
                    case CREATED -> {
                        // Included only in registered count.
                    }
                }
            }
            return new Snapshot(generations.size(), published, superseded, reclaiming,
                    reclaimable.size(), currentReferences, snapshotPins,
                    mvccReferences, dueReferences, ownerReferences,
                    recoveryTemporaryReferences);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Closes registration admission only after every owner reference and snapshot pin is released.
     *
     * <p>Successful closure is idempotent. A rejected close leaves the registry open for cleanup.</p>
     *
     * @throws IllegalStateException if any generation still has current references or snapshot pins
     */
    @Override
    public void close() {
        lock.lock();
        try {
            if (closed) {
                return;
            }
            for (Generation generation : generations.values()) {
                for (Owner owner : Owner.values()) {
                    int references = generation.references(owner);
                    if (references != 0) {
                        throw accountingFailure("close", generation, owner,
                                references, references);
                    }
                }
                if (generation.snapshotPins != 0) {
                    throw new IllegalStateException(
                            "signing generation registry close is inconsistent: generationId="
                                    + generation.identity + " owner=SNAPSHOT state="
                                    + generation.state + " requested=" + generation.snapshotPins
                                    + " ownerAvailable=" + generation.snapshotPins
                                    + " totalAvailable=" + generation.currentReferences);
                }
            }
            closed = true;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Atomically releases exact aggregated current-reference counts from one fixed owner bucket.
     *
     * @param owner exact fixed bucket owning the references
     * @param counts generation-to-positive-count mapping validated completely before accounting changes
     * @throws NullPointerException if the owner, map or generation identity is null
     * @throws IllegalArgumentException if an identity is negative or a count is null or not positive
     * @throws IllegalStateException if registration or exact owner-reference accounting is inconsistent
     */
    /* default */ void releaseCurrentCounts(Owner owner, Map<Long, Integer> counts) {
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(counts, "counts");
        lock.lock();
        try {
            for (Map.Entry<Long, Integer> entry : counts.entrySet()) {
                requireGenerationId(Objects.requireNonNull(entry.getKey(), "generationId"));
                if (entry.getValue() == null || entry.getValue() <= 0) {
                    throw new IllegalArgumentException(
                            "signing generation reference count is invalid");
                }
                Generation generation = requireGeneration(entry.getKey());
                int ownerAvailable = generation.references(owner);
                if (entry.getValue() > ownerAvailable
                        || entry.getValue() > generation.currentReferences) {
                    throw accountingFailure("release", generation, owner,
                            entry.getValue(), ownerAvailable);
                }
            }
            for (Map.Entry<Long, Integer> entry : counts.entrySet()) {
                Generation generation = requireGeneration(entry.getKey());
                generation.removeReferences(owner, entry.getValue());
                generation.currentReferences -= entry.getValue();
                refreshEligibility(generation);
            }
        } finally {
            lock.unlock();
        }
    }

    private void releaseSnapshot(List<Long> identities) {
        lock.lock();
        try {
            for (Long identity : identities) {
                Generation generation = requireGeneration(identity);
                if (generation.snapshotPins <= 0) {
                    throw new IllegalStateException("signing generation pin accounting is inconsistent");
                }
            }
            for (Long identity : identities) {
                Generation generation = requireGeneration(identity);
                generation.snapshotPins--;
                refreshEligibility(generation);
            }
        } finally {
            lock.unlock();
        }
    }

    private void refreshEligibility(Generation generation) {
        if (generation.state == State.SUPERSEDED
                && !generation.hasCurrentReferences() && generation.snapshotPins == 0) {
            reclaimable.add(generation.identity);
        } else {
            reclaimable.remove(generation.identity);
        }
    }

    private static Map<Long, Integer> countIdentities(Collection<Long> identities) {
        Objects.requireNonNull(identities, "generationIds");
        Map<Long, Integer> counts = new HashMap<>();
        for (Long identity : identities) {
            requireGenerationId(Objects.requireNonNull(identity, "generationId"));
            counts.merge(identity, 1, Math::addExact);
        }
        return Map.copyOf(counts);
    }

    private static IllegalStateException accountingFailure(String operation,
            Generation generation, Owner owner, int requested, int ownerAvailable) {
        return new IllegalStateException("signing generation reference " + operation
                + " is inconsistent: generationId=" + generation.identity
                + " owner=" + owner + " state=" + generation.state
                + " requested=" + requested + " ownerAvailable=" + ownerAvailable
                + " totalAvailable=" + generation.currentReferences);
    }

    private Generation requireGeneration(long generationId) {
        requireGenerationId(generationId);
        Generation generation = generations.get(generationId);
        if (generation == null) {
            throw new IllegalStateException("signing generation identity is not registered");
        }
        return generation;
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("signing generation registry is closed");
        }
    }

    private static void requireGenerationId(long generationId) {
        if (generationId < 0L) {
            throw new IllegalArgumentException("signing generation identity is invalid");
        }
    }

    /**
     * Closed in-memory lifecycle states.
     */
    private enum State {
        CREATED,
        PUBLISHED,
        SUPERSEDED,
        RECLAIMING
    }

    /**
     * Mutable generation state owned by the registry lock.
     */
    private static final class Generation {
        private final long identity;
        private State state;
        private int mvccReferences;
        private int dueReferences;
        private int ownerReferences;
        private int recoveryTemporaryReferences;
        private int currentReferences;
        private int snapshotPins;

        private Generation(long identity, State state) {
            this.identity = identity;
            this.state = state;
        }

        private int references(Owner owner) {
            return switch (owner) {
                case MVCC -> mvccReferences;
                case DUE -> dueReferences;
                case OWNER -> ownerReferences;
                case RECOVERY_TEMPORARY -> recoveryTemporaryReferences;
            };
        }

        private void addReferences(Owner owner, int count) {
            switch (owner) {
                case MVCC -> mvccReferences += count;
                case DUE -> dueReferences += count;
                case OWNER -> ownerReferences += count;
                case RECOVERY_TEMPORARY -> recoveryTemporaryReferences += count;
            }
        }

        private void removeReferences(Owner owner, int count) {
            switch (owner) {
                case MVCC -> mvccReferences -= count;
                case DUE -> dueReferences -= count;
                case OWNER -> ownerReferences -= count;
                case RECOVERY_TEMPORARY -> recoveryTemporaryReferences -= count;
            }
        }

        private boolean hasCurrentReferences() {
            return mvccReferences != 0 || dueReferences != 0 || ownerReferences != 0
                    || recoveryTemporaryReferences != 0;
        }
    }

    /**
     * Rollback token for a batch of newly acquired current references.
     */
    /* default */ static final class CurrentReferences implements AutoCloseable {
        private final SigningGenerationRegistry owner;
        private final Owner referenceOwner;
        private final Map<Long, Integer> counts;
        private final AtomicBoolean rollback = new AtomicBoolean(true);

        private CurrentReferences(SigningGenerationRegistry owner, Owner referenceOwner,
                Map<Long, Integer> counts) {
            this.owner = owner;
            this.referenceOwner = referenceOwner;
            this.counts = counts;
        }

        /**
         * Transfers current-reference ownership out of this rollback token without releasing references.
         *
         * <p>Transfer is idempotent; the receiving owner later releases the exact bucket counts.</p>
         *
         */
        /* default */ void transfer() {
            rollback.set(false);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void close() {
            if (rollback.compareAndSet(true, false)) {
                owner.releaseCurrentCounts(referenceOwner, counts);
            }
        }
    }

    /**
     * Idempotent snapshot-generation pin set.
     */
    /* default */ static final class SnapshotPins implements AutoCloseable {
        private final SigningGenerationRegistry owner;
        private final List<Long> identities;
        private final AtomicBoolean closed = new AtomicBoolean();

        private SnapshotPins(SigningGenerationRegistry owner, List<Long> identities) {
            this.owner = owner;
            this.identities = identities;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void close() {
            if (closed.compareAndSet(false, true)) {
                owner.releaseSnapshot(identities);
            }
        }
    }

    /**
     * One generation selected for reclamation after its retained references have drained.
     *
     * @param generationId exact generation identity
     */
    /* default */ record ReclaimAction(long generationId) {
        /**
         * Creates one generation selected for reclamation after its retained references have drained.
         *
         * @param generationId exact generation identity
         */
        ReclaimAction {
            requireGenerationId(generationId);
        }
    }

    /**
     * Constant-size generation ownership and reclamation counters captured by the registry.
     *
     * @param registered number of registered generations
     * @param published number of published generations
     * @param superseded number of generations superseded by newer publication
     * @param reclaiming number of generations currently being reclaimed
     * @param reclaimable number of superseded generations with no retained references
     * @param currentReferences references retained by the current generation view
     * @param snapshotPins generation pins retained by open snapshots
     * @param mvccReferences references retained by the multiversion metadata index
     * @param dueReferences references retained by the due-work index
     * @param ownerReferences references retained by the content-owner projection
     * @param recoveryTemporaryReferences temporary references retained during recovery
     */
    /* default */ record Snapshot(int registered, int published, int superseded,
            int reclaiming, int reclaimable, long currentReferences, long snapshotPins,
            long mvccReferences, long dueReferences, long ownerReferences,
            long recoveryTemporaryReferences) {
    }
}
