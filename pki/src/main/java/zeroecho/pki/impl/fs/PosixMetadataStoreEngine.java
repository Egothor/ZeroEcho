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

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataTransactionId;

/** Internal serialized transaction engine over the durable POSIX metadata log. */
final class PosixMetadataStoreEngine implements AutoCloseable {
    private static final int CONFLICT_FAILURE_CODE = 1;
    private static final long MINIMUM_VALUE_BOUNDARY = 0L;
    private static final Logger LOGGER = Logger.getLogger(PosixMetadataStoreEngine.class.getName());
    private static final String CLEANUP_WARNING =
            "POSIX metadata transaction resources could not be fully retired after a known outcome";

    private final PosixMetadataLog log;
    private final Path logPath;
    private final MetadataStateIndex stateIndex;
    private final FaultInjector faultInjector;
    private final ReentrantLock transactionLock = new ReentrantLock();
    private final Map<MetadataTransactionId, CommitResult> outcomes;
    private State state = State.OPEN;

    private PosixMetadataStoreEngine(
            Path logPath,
            PosixMetadataLog log,
            MetadataStateIndex stateIndex,
            FaultInjector faultInjector,
            Map<MetadataTransactionId, CommitResult> outcomes) {
        this.logPath = Objects.requireNonNull(logPath, "logPath")
                .toAbsolutePath().normalize();
        this.log = log;
        this.stateIndex = stateIndex;
        this.faultInjector = faultInjector;
        this.outcomes = new HashMap<>(outcomes);
    }

    /* default */ static PosixMetadataStoreEngine create(Path path, MetadataStoreId storeId)
            throws IOException {
        return create(path, storeId, PosixMetadataLog.FaultInjector.NONE, FaultInjector.NONE);
    }

    /* default */ static PosixMetadataStoreEngine create(
            Path path,
            MetadataStoreId storeId,
            PosixMetadataLog.FaultInjector logFaults,
            FaultInjector engineFaults) throws IOException {
        PosixMetadataLog log = PosixMetadataLog.create(
                path, storeId, defaultCapabilities(), logFaults);
        return new PosixMetadataStoreEngine(
                path, log, new MetadataStateIndex(), engineFaults, Map.of());
    }

    /* default */ static PosixMetadataStoreEngine open(Path path) throws IOException {
        return open(path, PosixMetadataLog.FaultInjector.NONE, FaultInjector.NONE);
    }

    /* default */ static PosixMetadataStoreEngine open(
            Path path,
            PosixMetadataLog.FaultInjector logFaults,
            FaultInjector engineFaults) throws IOException {
        PosixMetadataLog.EngineOpen opened =
                PosixMetadataLog.openEngine(path, defaultCapabilities(), logFaults);
        return new PosixMetadataStoreEngine(
                path,
                opened.log(),
                opened.stateIndex(),
                engineFaults,
                recoveredOutcomes(opened.outcomes()));
    }

    /* default */ MetadataStoreId storeId() {
        transactionLock.lock();
        try {
            requireOperational();
            return log.storeId();
        } finally {
            transactionLock.unlock();
        }
    }

    /* default */ MetadataTransactionId issue() throws IOException {
        transactionLock.lock();
        try {
            requireOperational();
            return log.issue();
        } finally {
            transactionLock.unlock();
        }
    }

    /* default */ CommitResult commit(
            MetadataTransactionId transactionId,
            List<PreparedMutation> mutations) throws IOException {
        transactionLock.lock();
        try {
            requireOperational();
            List<PreparedMutation> detached = List.copyOf(mutations);
            return commitOwned(transactionId, detached);
        } finally {
            transactionLock.unlock();
        }
    }

    private CommitResult commitOwned(
            MetadataTransactionId transactionId,
            List<PreparedMutation> mutations) throws IOException {
        try (PreparedResources resources = new PreparedResources(mutations)) {
            CommitResult result = commitBatch(transactionId, mutations);
            outcomes.put(transactionId, result);
            resources.outcomeEstablished();
            return result;
        }
    }

    private CommitResult commitBatch(
            MetadataTransactionId transactionId,
            List<PreparedMutation> detached) throws IOException {
            long revision = nextRevision();
            List<MetadataMutationPayloadCodec.Descriptor> predicted = predict(detached);
            Preparation preparation = Preparation.attempt(stateIndex, revision, predicted);
            if (preparation.failure() != null) {
                MetadataStoreException failure = preparation.failure();
                if (failure.category() != MetadataCommitResult.FailureCategory.CONFLICT) {
                    throw new MetadataStoreException(
                            failure.category(),
                            "Metadata state preparation failed",
                            failure);
                }
                try {
                    log.reject(transactionId, CONFLICT_FAILURE_CODE);
                    return CommitResult.notCommitted(CONFLICT_FAILURE_CODE);
                } catch (IOException uncertainty) {
                    enterRecoveryRequired();
                    throw uncertainty;
                }
            }
            appendAndVerify(transactionId, detached, predicted);
            try {
                log.commit(transactionId, revision);
                faultInjector.fail(FaultPoint.POST_FORCE_PUBLICATION);
                stateIndex.publish(preparation.update());
                return CommitResult.committed(revision);
            } catch (IOException failure) {
                enterRecoveryRequired();
                throw new OutcomeUnknownException(failure);
            }
    }

    private static void closePrepared(List<PreparedMutation> mutations) throws IOException {
        IOException failure = null;
        for (PreparedMutation mutation : mutations) {
            try {
                mutation.closeOwned();
            } catch (IOException cleanup) {
                failure = appendCleanupFailure(failure, cleanup);
            }
        }
        if (failure != null) {
            throw failure;
        }
    }

    private static IOException appendCleanupFailure(IOException first, IOException later) {
        if (first == null) {
            return later;
        }
        first.addSuppressed(later);
        return first;
    }

    /* default */ long storeRevision() throws IOException {
        transactionLock.lock();
        try {
            requireOperational();
            return stateIndex.storeRevision();
        } finally {
            transactionLock.unlock();
        }
    }

    /* default */ Optional<MetadataStateIndex.CurrentRecord> lookup(MetadataKey key)
            throws IOException {
        transactionLock.lock();
        try {
            requireOperational();
            return stateIndex.lookup(key);
        } finally {
            transactionLock.unlock();
        }
    }

    /* default */ SnapshotState snapshotState() throws IOException {
        transactionLock.lock();
        try {
            requireOperational();
            return new SnapshotState(stateIndex.storeRevision(), stateIndex.records());
        } finally {
            transactionLock.unlock();
        }
    }

    /* default */ InputStream openValueSlice(long offset, long length) throws IOException {
        transactionLock.lock();
        try {
            requireOperational();
            requireValueRegion(offset, length);
            final long end;
            try {
                end = Math.addExact(offset, length);
            } catch (ArithmeticException failure) {
                throw integrity("Metadata record value boundary overflows", failure);
            }
            FileChannel channel = FileChannel.open(
                    logPath,
                    Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS));
            if (end > channel.size()) {
                MetadataStoreException failure =
                        integrity("Metadata record value exceeds the durable log boundary");
                closeFailedSlice(channel, failure);
                throw failure;
            }
            return new ValueSliceInputStream(channel, offset, length);
        } finally {
            transactionLock.unlock();
        }
    }

    private static void closeFailedSlice(FileChannel channel, IOException failure) {
        try {
            channel.close();
        } catch (IOException cleanup) {
            failure.addSuppressed(cleanup);
        }
    }

    private static void requireValueRegion(long offset, long length)
            throws MetadataStoreException {
        if (offset < MINIMUM_VALUE_BOUNDARY || length < MINIMUM_VALUE_BOUNDARY) {
            throw integrity("Metadata record value region is negative");
        }
    }

    /* default */ CommitResult resolve(MetadataTransactionId transactionId) throws IOException {
        Objects.requireNonNull(transactionId, "transactionId");
        transactionLock.lock();
        try {
            requireOperational();
            if (!log.storeId().equals(transactionId.storeId())) {
                throw new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.FOREIGN_TRANSACTION,
                        "Metadata transaction belongs to another store");
            }
            CommitResult result = outcomes.get(transactionId);
            if (result == null) {
                throw new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.TRANSACTION_NOT_ISSUED,
                        "Metadata transaction has no retained terminal outcome");
            }
            return result;
        } finally {
            transactionLock.unlock();
        }
    }

    private long nextRevision() throws MetadataStoreException {
        try {
            return Math.addExact(stateIndex.storeRevision(), 1L);
        } catch (ArithmeticException failure) {
            throw new MetadataStoreException(
                    MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                    "POSIX metadata store revision is exhausted",
                    failure);
        }
    }

    private List<MetadataMutationPayloadCodec.Descriptor> predict(
            List<PreparedMutation> mutations) throws IOException {
        List<Long> payloadLengths = new ArrayList<>(mutations.size());
        for (PreparedMutation mutation : mutations) {
            payloadLengths.add(mutation.payloadLength());
        }
        List<PosixMetadataLog.MutationLocation> locations =
                log.predictMutationLocations(payloadLengths);
        List<MetadataMutationPayloadCodec.Descriptor> descriptors =
                new ArrayList<>(mutations.size());
        for (int index = 0; index < mutations.size(); index++) {
            descriptors.add(mutations.get(index).descriptor(locations.get(index).payloadOffset()));
        }
        return List.copyOf(descriptors);
    }

    private void appendAndVerify(
            MetadataTransactionId transactionId,
            List<PreparedMutation> mutations,
            List<MetadataMutationPayloadCodec.Descriptor> predicted) throws IOException {
        for (int index = 0; index < mutations.size(); index++) {
            PreparedMutation mutation = mutations.get(index);
            final MetadataFrameCodec.FrameMetadata frame;
            try {
                frame = log.appendMutation(
                        transactionId,
                        frameType(mutation.kind()),
                        mutation.payloadLength(),
                        mutation.payload(),
                        mutation.cancellation());
            } catch (IOException failure) {
                enterRecoveryRequired();
                throw failure;
            }
            MetadataMutationPayloadCodec.Descriptor actual;
            try {
                actual = log.decodeMutation(frame);
            } catch (IOException failure) {
                enterRecoveryRequired();
                throw failure;
            }
            if (!actual.equals(predicted.get(index))) {
                enterRecoveryRequired();
                throw integrity("Prepared metadata mutation differs from its durable frame");
            }
        }
    }

    private void requireOperational() {
        if (state == State.CLOSED) {
            throw new IllegalStateException("POSIX metadata store engine is closed");
        }
        if (state == State.RECOVERY_REQUIRED) {
            throw new IllegalStateException("POSIX metadata store engine requires recovery");
        }
    }

    private static MetadataFrameCodec.FrameType frameType(
            MetadataMutationPayloadCodec.MutationKind kind) {
        return switch (kind) {
            case CREATE -> MetadataFrameCodec.FrameType.MUTATION_CREATE;
            case REPLACE -> MetadataFrameCodec.FrameType.MUTATION_REPLACE;
            case DELETE -> MetadataFrameCodec.FrameType.MUTATION_DELETE;
        };
    }

    private void enterRecoveryRequired() {
        state = State.RECOVERY_REQUIRED;
    }

    @Override
    public void close() throws IOException {
        transactionLock.lock();
        try {
            if (state == State.CLOSED) {
                return;
            }
            state = State.CLOSED;
            log.close();
        } finally {
            transactionLock.unlock();
        }
    }

    private static PosixMetadataLog.CapabilityProfile defaultCapabilities() {
        return new PosixMetadataLog.CapabilityProfile() {
            @Override
            public boolean posixAvailable(Path parent) throws IOException {
                return Files.getFileStore(parent).supportsFileAttributeView("posix");
            }

            @Override
            public boolean localFileSystem(Path parent) {
                return true;
            }

            @Override
            public void forceParent(FileChannel parentDirectory) throws IOException {
                parentDirectory.force(true);
            }
        };
    }

    private static MetadataStoreException integrity(String message) {
        return new MetadataStoreException(
                MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE, message);
    }

    private static MetadataStoreException integrity(String message, Throwable cause) {
        return new MetadataStoreException(
                MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE, message, cause);
    }

    private static Map<MetadataTransactionId, CommitResult> recoveredOutcomes(
            Map<MetadataTransactionId, PosixMetadataLogScanner.Terminal> recovered) {
        Map<MetadataTransactionId, CommitResult> results = new HashMap<>();
        for (Map.Entry<MetadataTransactionId, PosixMetadataLogScanner.Terminal> entry
                : recovered.entrySet()) {
            results.put(entry.getKey(), CommitResult.fromTerminal(entry.getValue()));
        }
        return Map.copyOf(results);
    }

    /** Immutable finite current-state metadata captured under engine serialization. */
    /* default */ record SnapshotState(
            long revision, List<MetadataStateIndex.CurrentRecord> records) {
        SnapshotState {
            if (revision < MINIMUM_VALUE_BOUNDARY) {
                throw new IllegalArgumentException("Snapshot revision must not be negative");
            }
            records = List.copyOf(records);
        }
    }

    /** Exactly bounded reader over one immutable append-only value region. */
    private static final class ValueSliceInputStream extends InputStream {
        private final FileChannel channel;
        private long position;
        private long remaining;
        private boolean closed;

        private ValueSliceInputStream(FileChannel channel, long position, long remaining) {
            super();
            this.channel = channel;
            this.position = position;
            this.remaining = remaining;
        }

        @Override
        public int read() throws IOException {
            byte[] single = new byte[1];
            int count = read(single, 0, single.length);
            return count < 0 ? -1 : Byte.toUnsignedInt(single[0]);
        }

        @Override
        public int read(byte[] target, int offset, int length) throws IOException {
            Objects.checkFromIndexSize(offset, length, target.length);
            requireOpen();
            if (length == 0) {
                return 0;
            }
            if (remaining == MINIMUM_VALUE_BOUNDARY) {
                return -1;
            }
            int requested = (int) Math.min((long) length, remaining);
            ByteBuffer buffer = ByteBuffer.wrap(target, offset, requested);
            int count = channel.read(buffer, position);
            if (count < 0) {
                throw integrity("Metadata record value is truncated");
            }
            if (count == 0) {
                throw integrity("Metadata record value channel made no read progress");
            }
            position = Math.addExact(position, count);
            remaining -= count;
            return count;
        }

        @Override
        public void close() throws IOException {
            if (closed) {
                return;
            }
            closed = true;
            channel.close();
        }

        private void requireOpen() {
            if (closed) {
                throw new IllegalStateException("Metadata record value stream is closed");
            }
        }
    }

    /** Engine lifecycle forbidding semantic use after uncertainty or close. */
    private enum State {
        OPEN,
        RECOVERY_REQUIRED,
        CLOSED
    }

    /** Scope guard that preserves a primary commit failure and suppresses cleanup failure. */
    private static final class PreparedResources implements AutoCloseable {
        private final List<PreparedMutation> mutations;
        private boolean outcomeEstablished;

        private PreparedResources(List<PreparedMutation> mutations) {
            this.mutations = List.copyOf(mutations);
        }

        private void outcomeEstablished() {
            outcomeEstablished = true;
        }

        @Override
        public void close() throws IOException {
            try {
                closePrepared(mutations);
            } catch (IOException cleanup) {
                if (!outcomeEstablished) {
                    throw cleanup;
                }
                warnCleanupFailure();
            }
        }

        private static void warnCleanupFailure() {
            CleanupBoundary.warn();
        }
    }

    /** Same-thread boundary that converts non-fatal caller cleanup failures to checked state. */
    private static final class CleanupBoundary {
        private static IOException close(RepeatableContent content) {
            CompletableFuture<Void> completion = CompletableFuture.completedFuture(null)
                    .thenRun(() -> closeUnchecked(content));
            Throwable failure = completionFailure(completion);
            if (failure == null) {
                return null;
            }
            if (failure instanceof Error fatal) {
                throw fatal;
            }
            if (failure instanceof IOException ioFailure) {
                return ioFailure;
            }
            if (failure instanceof UncheckedIOException unchecked) {
                return unchecked.getCause();
            }
            return new MetadataStoreException(
                    MetadataCommitResult.FailureCategory.STORAGE_FAILURE,
                    "Metadata transaction resource cleanup failed",
                    failure);
        }

        private static void warn() {
            CompletableFuture<Void> completion = CompletableFuture.completedFuture(null)
                    .thenRun(() -> LOGGER.warning(CLEANUP_WARNING));
            Throwable failure = completionFailure(completion);
            if (failure instanceof Error fatal) {
                throw fatal;
            }
            // Non-fatal logging failures cannot replace an authoritative result.
        }

        private static void closeUnchecked(RepeatableContent content) {
            try {
                content.close();
            } catch (IOException failure) {
                throw new UncheckedIOException(failure);
            }
        }

        private static Throwable completionFailure(CompletableFuture<Void> completion) {
            try {
                completion.join();
                return null;
            } catch (CompletionException failed) {
                return failed.getCause();
            }
        }
    }

    /** Captures checked preparation without using exceptions as transaction flow. */
    private record Preparation(
            MetadataStateIndex.PreparedUpdate update, MetadataStoreException failure) {
        private static Preparation attempt(
                MetadataStateIndex index,
                long revision,
                List<MetadataMutationPayloadCodec.Descriptor> descriptors) {
            try {
                return new Preparation(index.prepare(revision, descriptors), null);
            } catch (MetadataStoreException failure) {
                return new Preparation(null, failure);
            }
        }
    }

    /** Closed internal result; it is not the provider-neutral store result. */
    /* default */ record CommitResult(
            boolean committed,
            OptionalLong revision,
            OptionalInt failureCode,
            Optional<PosixMetadataLogScanner.FailureReason> failureReason) {
        CommitResult {
            Objects.requireNonNull(revision, "revision");
            Objects.requireNonNull(failureCode, "failureCode");
            Objects.requireNonNull(failureReason, "failureReason");
        }

        private static CommitResult committed(long revision) {
            return new CommitResult(
                    true, OptionalLong.of(revision), OptionalInt.empty(), Optional.empty());
        }

        private static CommitResult notCommitted(int failureCode) {
            return new CommitResult(
                    false,
                    OptionalLong.empty(),
                    OptionalInt.of(failureCode),
                    PosixMetadataLogScanner.FailureReason.fromCode(failureCode));
        }

        private static CommitResult fromTerminal(PosixMetadataLogScanner.Terminal terminal) {
            if (terminal.kind() == PosixMetadataLogScanner.TerminalKind.COMMITTED) {
                return committed(terminal.committedRevision().orElseThrow());
            }
            return notCommitted(terminal.failureCode().orElseThrow());
        }
    }

    /** Store-owned semantic mutation plus its exact known-length encoded payload. */
    /* default */ record PreparedMutation(
            MetadataMutationPayloadCodec.MutationKind kind,
            MetadataKey key,
            OptionalLong expectedRevision,
            long valueLength,
            long payloadLength,
            RepeatableContent payload,
            CancellationSignal cancellation,
            RepeatableContent ownedValue,
            AtomicBoolean closed) {
        PreparedMutation {
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(key, "key");
            Objects.requireNonNull(expectedRevision, "expectedRevision");
            Objects.requireNonNull(payload, "payload");
            Objects.requireNonNull(cancellation, "cancellation");
            Objects.requireNonNull(closed, "closed");
            if (valueLength < 0L || payloadLength < valueLength) {
                throw new IllegalArgumentException("Prepared mutation lengths are invalid");
            }
        }

        /* default */ static PreparedMutation create(
                MetadataKey key,
                RepeatableContent storeOwnedValue,
                CancellationSignal cancellation) throws MetadataStoreException {
            long valueLength = storeOwnedValue.length().orElseThrow(
                    () -> new IllegalArgumentException("Prepared mutation value length is unknown"));
            RepeatableContent payload = MetadataMutationPayloadCodec.create(
                    key, storeOwnedValue, cancellation);
            return prepared(
                    MetadataMutationPayloadCodec.MutationKind.CREATE,
                    key,
                    OptionalLong.empty(),
                    valueLength,
                    payload,
                    cancellation,
                    storeOwnedValue);
        }

        /* default */ static PreparedMutation replace(
                MetadataKey key,
                long expectedRevision,
                RepeatableContent storeOwnedValue,
                CancellationSignal cancellation) throws MetadataStoreException {
            long valueLength = storeOwnedValue.length().orElseThrow(
                    () -> new IllegalArgumentException("Prepared mutation value length is unknown"));
            RepeatableContent payload = MetadataMutationPayloadCodec.replace(
                    key, expectedRevision, storeOwnedValue, cancellation);
            return prepared(
                    MetadataMutationPayloadCodec.MutationKind.REPLACE,
                    key,
                    OptionalLong.of(expectedRevision),
                    valueLength,
                    payload,
                    cancellation,
                    storeOwnedValue);
        }

        /* default */ static PreparedMutation delete(MetadataKey key, long expectedRevision) {
            RepeatableContent payload = MetadataMutationPayloadCodec.delete(key, expectedRevision);
            return prepared(
                    MetadataMutationPayloadCodec.MutationKind.DELETE,
                    key,
                    OptionalLong.of(expectedRevision),
                    0L,
                    payload,
                    CancellationSignal.NONE,
                    null);
        }

        private static PreparedMutation prepared(
                MetadataMutationPayloadCodec.MutationKind kind,
                MetadataKey key,
                OptionalLong expectedRevision,
                long valueLength,
                RepeatableContent payload,
                CancellationSignal cancellation,
                RepeatableContent ownedValue) {
            long payloadLength = payload.length().orElseThrow();
            return new PreparedMutation(
                    kind,
                    key,
                    expectedRevision,
                    valueLength,
                    payloadLength,
                    payload,
                    cancellation,
                    ownedValue,
                    new AtomicBoolean());
        }

        private void closeOwned() throws IOException {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            IOException failure = null;
            IOException payloadFailure = CleanupBoundary.close(payload);
            if (payloadFailure != null) {
                failure = appendCleanupFailure(failure, payloadFailure);
            }
            if (ownedValue != null) {
                IOException valueFailure = CleanupBoundary.close(ownedValue);
                if (valueFailure != null) {
                    failure = appendCleanupFailure(failure, valueFailure);
                }
            }
            if (failure != null) {
                throw failure;
            }
        }

        private MetadataMutationPayloadCodec.Descriptor descriptor(long payloadOffset) {
            if (kind == MetadataMutationPayloadCodec.MutationKind.DELETE) {
                return new MetadataMutationPayloadCodec.Descriptor(
                        kind, key, expectedRevision, OptionalLong.empty(), OptionalLong.empty());
            }
            long controlBytes = Math.subtractExact(payloadLength, valueLength);
            long valueOffset = Math.addExact(payloadOffset, controlBytes);
            return new MetadataMutationPayloadCodec.Descriptor(
                    kind,
                    key,
                    expectedRevision,
                    OptionalLong.of(valueOffset),
                    OptionalLong.of(valueLength));
        }
    }

    /** Deterministic fault boundary after a forced terminal and before publication. */
    /* default */ enum FaultPoint {
        POST_FORCE_PUBLICATION
    }

    /** Package-private fault seam for engine-only publication uncertainty. */
    /* default */
    @FunctionalInterface
    interface FaultInjector {
        FaultInjector NONE = point -> { };

        /** Fails the selected deterministic engine boundary. */
        void fail(FaultPoint point) throws IOException;
    }

    /** Outcome uncertainty requiring close and authoritative replay. */
    /* default */ static final class OutcomeUnknownException extends IOException {
        private static final long serialVersionUID = -5475791935837085729L;

        private OutcomeUnknownException(IOException cause) {
            super("POSIX metadata engine outcome requires recovery", cause);
        }
    }
}
