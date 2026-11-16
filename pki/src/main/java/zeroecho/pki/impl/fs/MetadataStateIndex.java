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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataStoreException;

/**
 * Atomic current-record index reconstructed from committed mutation descriptors.
 */
@SuppressWarnings("PMD.CyclomaticComplexity")
final class MetadataStateIndex {
    private static final long INITIAL_STORE_REVISION = 0L;
    private static final long MINIMUM_VALUE_POSITION = 0L;

    private final ReentrantReadWriteLock stateLock = new ReentrantReadWriteLock();
    private final Lock readLock = stateLock.readLock();
    private final Lock writeLock = stateLock.writeLock();

    /*
     * Pin tracking uses a per-generation AtomicInteger rather than an IdentityHashMap so
     * that snapshot() needs only a read lock (shared with other snapshot() callers) and
     * releaseSnapshot() needs no lock at all. The write lock is still required exclusively
     * by publish() to swap currentGeneration.
     *
     * Invariant: currentGeneration is non-null after construction.
     */
    private Generation currentGeneration = new Generation(new TreeMap<>());
    private Object stateToken = new StateToken();
    private long storeRevision = INITIAL_STORE_REVISION;
    private long snapshotCopyCount;

    /**
     * Creates an isolated builder for one sequential committed-state replay.
     *
     * @return new unfinished builder with revision zero and no current records
     */
    /* default */ static RecoveryBuilder recoveryBuilder() {
        return new RecoveryBuilder();
    }

    /**
     * Reads the exact current committed revision under the index read lock.
     *
     * @return current authoritative store revision
     */
    /* default */ long storeRevision() {
        readLock.lock();
        try {
            return storeRevision;
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Looks up one exact current metadata descriptor under the read lock.
     *
     * @param key canonical non-null metadata identity
     * @return current descriptor, or an empty optional if absent
     * @throws NullPointerException if a required collaborator is null
     */
    /* default */ Optional<CurrentRecord> lookup(MetadataKey key) {
        Objects.requireNonNull(key, "key");
        readLock.lock();
        try {
            return Optional.ofNullable(currentGeneration.records.get(key));
        } finally {
            readLock.unlock();
        }
    }

    /*
     * snapshot() acquires the read lock (shared: N callers run concurrently) and atomically
     * increments the generation's pin counter. publish() holds the write lock exclusively, so
     * snapshot() and publish() never overlap. releaseSnapshot() decrements the AtomicInteger
     * without any lock — the decrement is always safe because the generation object outlives
     * every SnapshotView that references it.
     */
    /**
     * Pins the exact current map identity without copying its entries.
     *
     * @return immutable map view and release callback; invoke the callback exactly once after readers finish
     */
    /* default */ SnapshotView snapshot() {
        readLock.lock();
        try {
            Generation gen = currentGeneration;
            gen.pinCount.incrementAndGet();
            return new SnapshotView(
                    java.util.Collections.unmodifiableNavigableMap(gen.records),
                    gen.pinCount::decrementAndGet);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Detaches all current physical value descriptors in metadata key order.
     *
     * @return immutable list of current descriptors
     */
    /* default */ List<CurrentRecord> records() {
        readLock.lock();
        try {
            return List.copyOf(currentGeneration.records.values());
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Returns the number of full-map copies required by publication while prior snapshots were pinned.
     *
     * @return accumulated copy-on-publication map-copy count
     */
    /* default */ long snapshotCopyCount() {
        readLock.lock();
        try {
            return snapshotCopyCount;
        } finally {
            readLock.unlock();
        }
    }

    /*
     * Validate-then-publish keeps every conflict and validation failure invisible.
     * A full map copy occurs only while a stable snapshot pins the prior identity.
     * CREATE and REPLACE record revisions are the authoritative committed store
     * revision, never an independently incremented per-record counter.
     */
    /**
     * Validates and publishes a complete next-revision mutation batch.
     *
     * @param committedStoreRevision exact next contiguous authoritative store revision
     * @param mutations ordered bounded descriptors with distinct canonical identities and exact expected revisions
     * @throws MetadataStoreException if descriptors, revision continuity, expected identity state or record bounds are invalid
     */
    /* default */ void applyCommitted(
            long committedStoreRevision,
            List<MetadataMutationPayloadCodec.Descriptor> mutations) throws MetadataStoreException {
        publish(prepare(committedStoreRevision, mutations));
    }

    /**
     * Validates a next-revision mutation batch against the exact current state without publishing it.
     *
     * @param committedStoreRevision exact next contiguous authoritative store revision
     * @param mutations ordered bounded descriptors with distinct canonical identities and exact expected revisions
     * @return isolated update bound to its exact base token and revision
     * @throws MetadataStoreException if descriptors, revision continuity, expected identity state or record bounds are invalid
     */
    /* default */ PreparedUpdate prepare(
            long committedStoreRevision,
            List<MetadataMutationPayloadCodec.Descriptor> mutations) throws MetadataStoreException {
        List<ValidatedMutation> validated = validateAndDetach(mutations);
        readLock.lock();
        try {
            requireNextRevision(committedStoreRevision);
            rejectDuplicateKeys(validated);
            NavigableMap<MetadataKey, CurrentRecord> records = currentGeneration.records;
            for (ValidatedMutation mutation : validated) {
                validateAgainstCurrent(records, mutation);
            }
            return new PreparedUpdate(
                    stateToken,
                    storeRevision,
                    committedStoreRevision,
                    validated);
        } catch (ArithmeticException | IllegalArgumentException
                | NullPointerException | IndexOutOfBoundsException failure) {
            throw integrity("Committed metadata transaction contains a malformed descriptor", failure);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Publishes an update only while its exact prepared base token and revision still match.
     *
     * <p>A pinned previous map is copied before modification; otherwise its unpinned map can be reused.</p>
     *
     * @param update validated isolated candidate prepared against this index
     * @throws NullPointerException if a required collaborator is null
     * @throws MetadataStoreException if its original state token or revision no longer matches
     */
    /* default */ void publish(PreparedUpdate update) throws MetadataStoreException {
        Objects.requireNonNull(update, "update");
        writeLock.lock();
        try {
            if (!stateToken.equals(update.baseToken()) || storeRevision != update.baseRevision()) {
                throw integrity("Prepared metadata state no longer has its exact base revision");
            }
            Generation current = currentGeneration;
            boolean pinned = current.pinCount.get() > 0;
            NavigableMap<MetadataKey, CurrentRecord> target = pinned
                    ? new TreeMap<>(current.records) : current.records;
            if (pinned) {
                snapshotCopyCount++;
            }
            for (ValidatedMutation mutation : update.mutations()) {
                apply(target, update.targetRevision(), mutation);
            }
            currentGeneration = new Generation(target);
            storeRevision = update.targetRevision();
            stateToken = new StateToken();
        } finally {
            writeLock.unlock();
        }
    }

    private static List<ValidatedMutation> validateAndDetach(
            List<MetadataMutationPayloadCodec.Descriptor> mutations) throws MetadataStoreException {
        try {
            List<MetadataMutationPayloadCodec.Descriptor> detached = List.copyOf(
                    Objects.requireNonNull(mutations, "mutations"));
            List<ValidatedMutation> validated = new ArrayList<>(detached.size());
            for (MetadataMutationPayloadCodec.Descriptor descriptor : detached) {
                validated.add(validateDescriptor(descriptor));
            }
            return List.copyOf(validated);
        } catch (ArithmeticException | IllegalArgumentException
                | NullPointerException | IndexOutOfBoundsException failure) {
            throw integrity("Committed metadata transaction contains a malformed descriptor", failure);
        }
    }

    private static ValidatedMutation validateDescriptor(
            MetadataMutationPayloadCodec.Descriptor descriptor) throws MetadataStoreException {
        MetadataMutationPayloadCodec.Descriptor checked = Objects.requireNonNull(descriptor, "descriptor");
        MetadataMutationPayloadCodec.MutationKind kind = Objects.requireNonNull(checked.kind(), "kind");
        MetadataKey key = Objects.requireNonNull(checked.key(), "key");
        OptionalLong expectedRevision = Objects.requireNonNull(
                checked.expectedRevision(), "expectedRevision");
        OptionalLong valueOffset = Objects.requireNonNull(checked.valueOffset(), "valueOffset");
        OptionalLong valueLength = Objects.requireNonNull(checked.valueLength(), "valueLength");
        return switch (kind) {
            case CREATE -> validateCreate(key, expectedRevision, valueOffset, valueLength);
            case REPLACE -> validateReplace(key, expectedRevision, valueOffset, valueLength);
            case DELETE -> validateDelete(key, expectedRevision, valueOffset, valueLength);
        };
    }

    private static ValidatedMutation validateCreate(
            MetadataKey key,
            OptionalLong expectedRevision,
            OptionalLong valueOffset,
            OptionalLong valueLength) throws MetadataStoreException {
        if (expectedRevision.isPresent()) {
            throw integrity("Metadata create descriptor unexpectedly carries an expected revision");
        }
        ValueRegion region = requireValueRegion(valueOffset, valueLength);
        return new ValidatedMutation(
                MetadataMutationPayloadCodec.MutationKind.CREATE,
                key,
                OptionalLong.empty(),
                region);
    }

    private static ValidatedMutation validateReplace(
            MetadataKey key,
            OptionalLong expectedRevision,
            OptionalLong valueOffset,
            OptionalLong valueLength) throws MetadataStoreException {
        requireExpectedRevision(expectedRevision);
        ValueRegion region = requireValueRegion(valueOffset, valueLength);
        return new ValidatedMutation(
                MetadataMutationPayloadCodec.MutationKind.REPLACE,
                key,
                expectedRevision,
                region);
    }

    private static ValidatedMutation validateDelete(
            MetadataKey key,
            OptionalLong expectedRevision,
            OptionalLong valueOffset,
            OptionalLong valueLength) throws MetadataStoreException {
        requireExpectedRevision(expectedRevision);
        if (valueOffset.isPresent() || valueLength.isPresent()) {
            throw integrity("Metadata delete descriptor unexpectedly carries a value region");
        }
        return new ValidatedMutation(
                MetadataMutationPayloadCodec.MutationKind.DELETE,
                key,
                expectedRevision,
                null);
    }

    private static void requireExpectedRevision(OptionalLong expectedRevision)
            throws MetadataStoreException {
        if (expectedRevision.isEmpty() || expectedRevision.getAsLong() < INITIAL_STORE_REVISION) {
            throw integrity("Metadata mutation expected revision is missing or negative");
        }
    }

    private static ValueRegion requireValueRegion(
            OptionalLong valueOffset,
            OptionalLong valueLength) throws MetadataStoreException {
        if (valueOffset.isEmpty() || valueLength.isEmpty()) {
            throw integrity("Metadata value mutation has no value region");
        }
        long offset = valueOffset.getAsLong();
        long length = valueLength.getAsLong();
        if (offset < MINIMUM_VALUE_POSITION || length < MINIMUM_VALUE_POSITION) {
            throw integrity("Metadata record value region must be non-negative");
        }
        try {
            Math.addExact(offset, length);
        } catch (ArithmeticException failure) {
            throw integrity("Metadata record value region overflows", failure);
        }
        return new ValueRegion(offset, length);
    }

    private void requireNextRevision(long committedStoreRevision) throws MetadataStoreException {
        if (storeRevision == Long.MAX_VALUE) {
            throw new MetadataStoreException(
                    MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                    "Metadata store revision is exhausted");
        }
        long expected = storeRevision + 1L;
        if (committedStoreRevision != expected) {
            throw new MetadataStoreException(
                    MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE,
                    "Committed metadata store revision is not contiguous");
        }
    }

    private static void rejectDuplicateKeys(
            List<ValidatedMutation> mutations) throws MetadataStoreException {
        Set<MetadataKey> keys = new HashSet<>();
        for (ValidatedMutation mutation : mutations) {
            if (!keys.add(mutation.key())) {
                throw conflict("Metadata transaction mutates one key more than once");
            }
        }
    }

    private static void apply(
            Map<MetadataKey, CurrentRecord> candidate,
            long committedStoreRevision,
            ValidatedMutation mutation) throws MetadataStoreException {
        switch (mutation.kind()) {
            case CREATE -> create(candidate, committedStoreRevision, mutation);
            case REPLACE -> replace(candidate, committedStoreRevision, mutation);
            case DELETE -> delete(candidate, mutation);
        }
    }

    private static void validateAgainstCurrent(Map<MetadataKey, CurrentRecord> records,
            ValidatedMutation mutation) throws MetadataStoreException {
        CurrentRecord existing = records.get(mutation.key());
        switch (mutation.kind()) {
            case CREATE -> {
                if (existing != null) {
                    throw conflict("Metadata create precondition failed");
                }
            }
            case REPLACE, DELETE -> requireExpected(existing, mutation);
        }
    }

    private static void create(
            Map<MetadataKey, CurrentRecord> candidate,
            long committedStoreRevision,
            ValidatedMutation mutation) throws MetadataStoreException {
        if (candidate.containsKey(mutation.key())) {
            throw conflict("Metadata create precondition failed");
        }
        candidate.put(mutation.key(), record(committedStoreRevision, mutation));
    }

    private static void replace(
            Map<MetadataKey, CurrentRecord> candidate,
            long committedStoreRevision,
            ValidatedMutation mutation) throws MetadataStoreException {
        CurrentRecord existing = candidate.get(mutation.key());
        requireExpected(existing, mutation);
        candidate.put(mutation.key(), record(committedStoreRevision, mutation));
    }

    private static void delete(
            Map<MetadataKey, CurrentRecord> candidate,
            ValidatedMutation mutation) throws MetadataStoreException {
        CurrentRecord existing = candidate.get(mutation.key());
        requireExpected(existing, mutation);
        candidate.remove(mutation.key());
    }

    private static void requireExpected(
            CurrentRecord existing,
            ValidatedMutation mutation) throws MetadataStoreException {
        if (existing == null
                || mutation.expectedRevision().isEmpty()
                || existing.revision() != mutation.expectedRevision().getAsLong()) {
            throw conflict("Metadata expected-revision precondition failed");
        }
    }

    private static CurrentRecord record(
            long committedStoreRevision,
            ValidatedMutation mutation) {
        ValueRegion region = mutation.valueRegion();
        return new CurrentRecord(
                mutation.key(),
                committedStoreRevision,
                region.offset(),
                region.length());
    }

    private static MetadataStoreException conflict(String message) {
        return new MetadataStoreException(MetadataCommitResult.FailureCategory.CONFLICT, message);
    }

    private static MetadataStoreException integrity(String message) {
        return new MetadataStoreException(MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE, message);
    }

    private static MetadataStoreException integrity(String message, Throwable cause) {
        return new MetadataStoreException(
                MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE, message, cause);
    }

    /**
     * Replay-only unpublished reducer avoiding one full state copy per commit.
     */
    /* default */ static final class RecoveryBuilder {
        private final NavigableMap<MetadataKey, CurrentRecord> records = new TreeMap<>();
        private long revision = INITIAL_STORE_REVISION;
        private long discardedDescriptors;
        private boolean finished;

        /**
         * Applies one validated contiguous committed batch to the isolated recovery map.
         *
         * @param committedRevision exact next contiguous recovered store revision
         * @param descriptors bounded validated physical mutation descriptors
         * @throws IllegalStateException if the builder was already finished
         * @throws MetadataStoreException if revision, descriptors or expected record state are invalid
         * @throws ArithmeticException if the discarded-descriptor counter overflows
         */
        /* default */ void applyCommitted(
                long committedRevision,
                List<MetadataMutationPayloadCodec.Descriptor> descriptors)
                throws MetadataStoreException {
            requireUnfinished();
            List<ValidatedMutation> validated = validateAndDetach(descriptors);
            if (revision == Long.MAX_VALUE || committedRevision != revision + 1L) {
                throw integrity("Recovered metadata store revision is not contiguous");
            }
            rejectDuplicateKeys(validated);
            Map<MetadataKey, Optional<CurrentRecord>> delta = new HashMap<>();
            for (ValidatedMutation mutation : validated) {
                validateRecoveryMutation(delta, committedRevision, mutation);
            }
            for (Map.Entry<MetadataKey, Optional<CurrentRecord>> entry : delta.entrySet()) {
                if (entry.getValue().isPresent()) {
                    records.put(entry.getKey(), entry.getValue().orElseThrow());
                } else {
                    records.remove(entry.getKey());
                }
            }
            revision = committedRevision;
            discardedDescriptors = Math.addExact(discardedDescriptors, validated.size());
        }

        /**
         * Transfers the reconstructed map into a current-state index exactly once.
         *
         * @return new index owning the recovered map and exact committed revision
         * @throws IllegalStateException if the builder was already finished
         */
        /* default */ MetadataStateIndex finish() {
            requireUnfinished();
            finished = true;
            MetadataStateIndex result = new MetadataStateIndex();
            result.currentGeneration = new Generation(records);
            result.storeRevision = revision;
            result.stateToken = new StateToken();
            return result;
        }

        /**
         * Returns the full-map copy counter exposed by recovery diagnostics.
         *
         * @return zero, because the builder installs reconstructed state without full-map copies
         */
        /* default */ long fullMapCopyCount() {
            return 0L;
        }

        /**
         * Reports whether the isolated recovered map was installed in its final index.
         *
         * @return one after finish, otherwise zero
         */
        /* default */ long finalInstallCount() {
            return finished ? 1L : 0L;
        }

        /**
         * Returns the number of superseded mutation descriptors discarded during reconstruction.
         *
         * @return number of superseded mutation descriptors discarded during reconstruction
         */
        /* default */ long discardedDescriptorCount() {
            return discardedDescriptors;
        }

        private void requireUnfinished() {
            if (finished) {
                throw new IllegalStateException("Metadata recovery builder is finished");
            }
        }

        private void validateRecoveryMutation(
                Map<MetadataKey, Optional<CurrentRecord>> delta,
                long committedRevision,
                ValidatedMutation mutation) throws MetadataStoreException {
            CurrentRecord existing = records.get(mutation.key());
            switch (mutation.kind()) {
                case CREATE -> {
                    if (existing != null) {
                        throw conflict("Recovered metadata create precondition failed");
                    }
                    delta.put(mutation.key(), Optional.of(record(committedRevision, mutation)));
                }
                case REPLACE -> {
                    requireExpected(existing, mutation);
                    delta.put(mutation.key(), Optional.of(record(committedRevision, mutation)));
                }
                case DELETE -> {
                    requireExpected(existing, mutation);
                    delta.put(mutation.key(), Optional.empty());
                }
            }
        }
    }

    /**
     * One version of the current index together with its live snapshot reference count.
     */
    private static final class Generation {
        /* default */ final NavigableMap<MetadataKey, CurrentRecord> records;
        /*
         * Incremented under the read lock by snapshot(); decremented lock-free by
         * releaseSnapshot(). publish() reads this under the write lock to decide whether
         * to copy the map before mutation.
         */
        /* default */ final AtomicInteger pinCount = new AtomicInteger(0);

        /* default */ Generation(NavigableMap<MetadataKey, CurrentRecord> records) {
            this.records = records;
        }
    }

    private record ValidatedMutation(
            MetadataMutationPayloadCodec.MutationKind kind,
            MetadataKey key,
            OptionalLong expectedRevision,
            ValueRegion valueRegion) {
    }

    private record ValueRegion(long offset, long length) {
    }

    /**
     * Identity-semantic base token changed after every successful publication.
     */
    private static final class StateToken {
    }

    /**
     * Isolated immutable state candidate bound to one exact current-state identity.
     * @param baseToken opaque identity of the current state from which preparation began
     * @param baseRevision authoritative revision from which the update was prepared
     * @param targetRevision revision assigned if the prepared update commits
     * @param mutations ordered immutable mutation descriptors
     */
    /* default */ record PreparedUpdate(
            Object baseToken,
            long baseRevision,
            long targetRevision,
            List<ValidatedMutation> mutations) {
        /**
         * Creates the isolated immutable state candidate bound to one exact current-state identity.
         *
         * @param baseToken opaque identity of the current state from which preparation began
         * @param baseRevision authoritative revision from which the update was prepared
         * @param targetRevision revision assigned if the prepared update commits
         * @param mutations ordered immutable mutation descriptors
         * @throws NullPointerException if {@code baseToken} is null
         */
        PreparedUpdate {
            Objects.requireNonNull(baseToken, "baseToken");
            mutations = List.copyOf(mutations);
        }
    }

    /**
     * Pinned immutable map identity released when its snapshot closes.
     * @param records captured immutable current records keyed by exact metadata identity
     * @param release callback releasing the captured snapshot pin
     */
    /* default */ record SnapshotView(NavigableMap<MetadataKey, CurrentRecord> records, Runnable release) {
        /**
         * Creates the pinned immutable map identity released when its snapshot closes.
         *
         * @param records captured immutable current records keyed by exact metadata identity
         * @param release callback releasing the captured snapshot pin
         * @throws NullPointerException if {@code records} is null; or if {@code release} is null
         */
        SnapshotView {
            Objects.requireNonNull(records, "records");
            Objects.requireNonNull(release, "release");
        }
    }

    /**
     * Immutable current value location and its authoritative committed revision.
     * @param key exact logical metadata identity
     * @param revision authoritative metadata revision
     * @param valueOffset zero-based byte offset of the stored value
     * @param valueLength encoded value length in bytes
     */
    /* default */ record CurrentRecord(MetadataKey key, long revision, long valueOffset, long valueLength) {
        /**
         * Creates an immutable current value location and its authoritative committed revision.
         *
         * @param key exact logical metadata identity
         * @param revision authoritative metadata revision
         * @param valueOffset zero-based byte offset of the stored value
         * @param valueLength encoded value length in bytes
         * @throws NullPointerException if {@code key} is null
         * @throws IllegalArgumentException if {@code (revision <= INITIAL_STORE_REVISION)}; or if {@code (valueOffset < MINIMUM_VALUE_POSITION || valueLength < MINIMUM_VALUE_POSITION)}
         */
        CurrentRecord {
            Objects.requireNonNull(key, "key");
            if (revision <= INITIAL_STORE_REVISION) {
                throw new IllegalArgumentException("Metadata record revision must be positive");
            }
            if (valueOffset < MINIMUM_VALUE_POSITION || valueLength < MINIMUM_VALUE_POSITION) {
                throw new IllegalArgumentException("Metadata record value region must be non-negative");
            }
        }
    }
}
