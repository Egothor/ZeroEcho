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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataStoreException;

/** Atomic current-record index reconstructed from committed mutation descriptors. */
final class MetadataStateIndex {
    private static final long INITIAL_STORE_REVISION = 0L;
    private static final long MINIMUM_VALUE_POSITION = 0L;

    private final ReentrantReadWriteLock stateLock = new ReentrantReadWriteLock();
    private final Lock readLock = stateLock.readLock();
    private final Lock writeLock = stateLock.writeLock();
    private NavigableMap<MetadataKey, CurrentRecord> current = new TreeMap<>();
    private Object stateToken = new StateToken();
    private long storeRevision = INITIAL_STORE_REVISION;

    /* default */ static RecoveryBuilder recoveryBuilder() {
        return new RecoveryBuilder();
    }

    /* default */ long storeRevision() {
        readLock.lock();
        try {
            return storeRevision;
        } finally {
            readLock.unlock();
        }
    }

    /* default */ Optional<CurrentRecord> lookup(MetadataKey key) {
        Objects.requireNonNull(key, "key");
        readLock.lock();
        try {
            return Optional.ofNullable(current.get(key));
        } finally {
            readLock.unlock();
        }
    }

    /* default */ List<CurrentRecord> records() {
        readLock.lock();
        try {
            return List.copyOf(current.values());
        } finally {
            readLock.unlock();
        }
    }

    /*
     * Copy-then-publish keeps every conflict and validation failure invisible.
     * CREATE and REPLACE record revisions are the authoritative committed store
     * revision, never an independently incremented per-record counter.
     */
    /* default */ void applyCommitted(
            long committedStoreRevision,
            List<MetadataMutationPayloadCodec.Descriptor> mutations) throws MetadataStoreException {
        publish(prepare(committedStoreRevision, mutations));
    }

    /* default */ PreparedUpdate prepare(
            long committedStoreRevision,
            List<MetadataMutationPayloadCodec.Descriptor> mutations) throws MetadataStoreException {
        List<ValidatedMutation> validated = validateAndDetach(mutations);
        readLock.lock();
        try {
            requireNextRevision(committedStoreRevision);
            rejectDuplicateKeys(validated);
            NavigableMap<MetadataKey, CurrentRecord> candidate = new TreeMap<>(current);
            for (ValidatedMutation mutation : validated) {
                apply(candidate, committedStoreRevision, mutation);
            }
            return new PreparedUpdate(
                    stateToken,
                    storeRevision,
                    committedStoreRevision,
                    Collections.unmodifiableNavigableMap(candidate));
        } catch (ArithmeticException | IllegalArgumentException
                | NullPointerException | IndexOutOfBoundsException failure) {
            throw integrity("Committed metadata transaction contains a malformed descriptor", failure);
        } finally {
            readLock.unlock();
        }
    }

    /* default */ void publish(PreparedUpdate update) throws MetadataStoreException {
        Objects.requireNonNull(update, "update");
        writeLock.lock();
        try {
            if (!stateToken.equals(update.baseToken()) || storeRevision != update.baseRevision()) {
                throw integrity("Prepared metadata state no longer has its exact base revision");
            }
            current = update.candidate();
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

    /** Replay-only unpublished reducer avoiding one full state copy per commit. */
    /* default */ static final class RecoveryBuilder {
        private final NavigableMap<MetadataKey, CurrentRecord> records = new TreeMap<>();
        private long revision = INITIAL_STORE_REVISION;
        private long discardedDescriptors;
        private boolean finished;

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

        /* default */ MetadataStateIndex finish() {
            requireUnfinished();
            finished = true;
            MetadataStateIndex result = new MetadataStateIndex();
            result.current = records;
            result.storeRevision = revision;
            result.stateToken = new StateToken();
            return result;
        }

        /* default */ long fullMapCopyCount() {
            return 0L;
        }

        /* default */ long finalInstallCount() {
            return finished ? 1L : 0L;
        }

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

    private record ValidatedMutation(
            MetadataMutationPayloadCodec.MutationKind kind,
            MetadataKey key,
            OptionalLong expectedRevision,
            ValueRegion valueRegion) {
    }

    private record ValueRegion(long offset, long length) {
    }

    /** Identity-semantic base token changed after every successful publication. */
    private static final class StateToken {
    }

    /** Isolated immutable state candidate bound to one exact current-state identity. */
    /* default */ record PreparedUpdate(
            Object baseToken,
            long baseRevision,
            long targetRevision,
            NavigableMap<MetadataKey, CurrentRecord> candidate) {
        PreparedUpdate {
            Objects.requireNonNull(baseToken, "baseToken");
            Objects.requireNonNull(candidate, "candidate");
        }
    }

    /** Immutable current value location and its authoritative committed revision. */
    /* default */ record CurrentRecord(MetadataKey key, long revision, long valueOffset, long valueLength) {
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
