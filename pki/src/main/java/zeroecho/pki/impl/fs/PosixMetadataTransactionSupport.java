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
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.MetadataTransactionId;

/** Thread-confined transaction admission, staging, and outcome mapping. */
final class PosixMetadataTransactionSupport {
    private static final int TRANSFER_BUFFER_BYTES = 8192;
    private static final long MINIMUM_CONTENT_LENGTH = 0L;

    private final PosixMetadataStoreEngine engine;
    private final PosixMetadataAdapterLifecycle lifecycle;
    private final Path stagingDirectory;
    private final OptionalLong maximumRecordBytes;
    private final StagingOperations stagingOperations;

    /* default */ PosixMetadataTransactionSupport(
            PosixMetadataStoreEngine engine,
            PosixMetadataAdapterLifecycle lifecycle,
            Path stagingDirectory,
            OptionalLong maximumRecordBytes,
            StagingOperations stagingOperations) {
        this.engine = Objects.requireNonNull(engine, "engine");
        this.lifecycle = Objects.requireNonNull(lifecycle, "lifecycle");
        this.stagingDirectory = Objects.requireNonNull(stagingDirectory, "stagingDirectory");
        this.maximumRecordBytes = Objects.requireNonNull(
                maximumRecordBytes, "maximumRecordBytes");
        this.stagingOperations = Objects.requireNonNull(stagingOperations, "stagingOperations");
    }

    /* default */ MetadataTransaction begin() throws IOException {
        return lifecycle.openManaged(() -> new TransactionImpl(engine.issue()));
    }

    /* default */ MetadataCommitResult resolve(MetadataTransactionId transactionId)
            throws IOException {
        Objects.requireNonNull(transactionId, "transactionId");
        return lifecycle.read(() -> map(transactionId, engine.resolve(transactionId)));
    }

    /* default */ void acknowledge(MetadataTransactionId transactionId) throws IOException {
        MetadataCommitResult retained = resolve(transactionId);
        if (retained.outcome() == MetadataCommitResult.Outcome.UNKNOWN) {
            throw new MetadataStoreException(
                    MetadataCommitResult.FailureCategory.STORAGE_FAILURE,
                    "Unknown metadata transaction outcome cannot be acknowledged");
        }
    }

    private SpoolContent stage(
            RepeatableContent source, CancellationSignal cancellation) throws IOException {
        OptionalLong declared = requireKnownLength(source);
        long length = declared.orElseThrow();
        requireTechnicalLimit(length);
        throwIfCancelled(cancellation);
        Path spool = stagingOperations.create(stagingDirectory);
        try (SpoolContent owned = new SpoolContent(spool, length, stagingOperations)) {
            copyExact(source, cancellation, spool, length);
            return owned.transfer();
        }
    }

    private static OptionalLong requireKnownLength(RepeatableContent source)
            throws MetadataStoreException {
        Objects.requireNonNull(source, "content");
        OptionalLong declared;
        try {
            declared = Objects.requireNonNull(source.length(), "content length");
        } catch (IllegalArgumentException | IllegalStateException failure) {
            throw storage("Metadata content length could not be established", failure);
        }
        if (declared.isEmpty()) {
            throw new MetadataStoreException(
                    MetadataCommitResult.FailureCategory.UNSUPPORTED_CAPABILITY,
                    "POSIX metadata adapter requires known content length");
        }
        if (declared.getAsLong() < MINIMUM_CONTENT_LENGTH) {
            throw new MetadataStoreException(
                    MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE,
                    "Metadata content length is negative");
        }
        return declared;
    }

    private void requireTechnicalLimit(long length) throws MetadataStoreException {
        if (maximumRecordBytes.isPresent() && length > maximumRecordBytes.getAsLong()) {
            throw new MetadataStoreException(
                    MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                    "Metadata content exceeds the adapter technical limit");
        }
    }

    private void copyExact(
            RepeatableContent source,
            CancellationSignal cancellation,
            Path spool,
            long declaredLength) throws IOException {
        try (InputStream input = source.openStream();
                FileChannel output = stagingOperations.openWrite(spool)) {
            copyDeclared(input, output, cancellation, declaredLength);
            throwIfCancelled(cancellation);
            if (input.read() >= 0) {
                throw storage("Metadata content is longer than its declared length");
            }
        } catch (InterruptedIOException failure) {
            throw cancelled(failure);
        } catch (MetadataStoreException failure) {
            throw failure;
        } catch (IOException failure) {
            throw storage("Metadata content staging failed", failure);
        }
    }

    private void copyDeclared(
            InputStream input,
            FileChannel output,
            CancellationSignal cancellation,
            long declaredLength) throws IOException {
        byte[] transfer = new byte[TRANSFER_BUFFER_BYTES];
        long copied = MINIMUM_CONTENT_LENGTH;
        while (copied < declaredLength) {
            throwIfCancelled(cancellation);
            int requested = (int) Math.min((long) transfer.length, declaredLength - copied);
            int count = input.read(transfer, 0, requested);
            requireReadProgress(count);
            try {
                copied = Math.addExact(copied, count);
            } catch (ArithmeticException failure) {
                throw new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                        "Metadata content length is not representable",
                        failure);
            }
            requireTechnicalLimit(copied);
            writeFully(output, ByteBuffer.wrap(transfer, 0, count));
        }
    }

    private static void requireReadProgress(int count) throws MetadataStoreException {
        if (count < 0) {
            throw storage("Metadata content is shorter than its declared length");
        }
        if (count == 0) {
            throw storage("Metadata content stream made no read progress");
        }
    }

    private static void writeFully(FileChannel channel, ByteBuffer source) throws IOException {
        while (source.hasRemaining()) {
            if (channel.write(source) == 0) {
                throw storage("Metadata staging channel made no write progress");
            }
        }
    }

    private static void throwIfCancelled(CancellationSignal cancellation)
            throws MetadataStoreException {
        Objects.requireNonNull(cancellation, "cancellation");
        try {
            cancellation.throwIfCancelled();
        } catch (InterruptedIOException failure) {
            throw cancelled(failure);
        }
    }

    private static MetadataCommitResult map(
            MetadataTransactionId transactionId,
            PosixMetadataStoreEngine.CommitResult internal) {
        if (internal.committed()) {
            return new MetadataCommitResult(
                    transactionId,
                    MetadataCommitResult.Outcome.COMMITTED,
                    internal.revision(),
                    Optional.empty());
        }
        MetadataCommitResult.FailureCategory category = internal.failureReason()
                .map(PosixMetadataTransactionSupport::mapFailure)
                .orElse(MetadataCommitResult.FailureCategory.STORAGE_FAILURE);
        return new MetadataCommitResult(
                transactionId,
                MetadataCommitResult.Outcome.NOT_COMMITTED,
                OptionalLong.empty(),
                Optional.of(category));
    }

    private static MetadataCommitResult.FailureCategory mapFailure(
            PosixMetadataLogScanner.FailureReason reason) {
        return switch (reason) {
            case TRANSACTION_CONFLICT -> MetadataCommitResult.FailureCategory.CONFLICT;
            case ABANDONED_BY_RECOVERY ->
                    MetadataCommitResult.FailureCategory.ABANDONED_BY_RECOVERY;
        };
    }

    private static MetadataCommitResult unknown(MetadataTransactionId transactionId) {
        return new MetadataCommitResult(
                transactionId,
                MetadataCommitResult.Outcome.UNKNOWN,
                OptionalLong.empty(),
                Optional.of(MetadataCommitResult.FailureCategory.STORAGE_FAILURE));
    }

    private static MetadataStoreException cancelled(InterruptedIOException failure) {
        return new MetadataStoreException(
                MetadataCommitResult.FailureCategory.CANCELLED,
                "Metadata content staging was cancelled",
                failure);
    }

    private static MetadataStoreException storage(String message) {
        return new MetadataStoreException(
                MetadataCommitResult.FailureCategory.STORAGE_FAILURE, message);
    }

    private static MetadataStoreException storage(String message, Throwable failure) {
        return new MetadataStoreException(
                MetadataCommitResult.FailureCategory.STORAGE_FAILURE, message, failure);
    }

    /** Store-issued transaction whose owner lock provides exact thread identity. */
    private final class TransactionImpl
            implements MetadataTransaction, PosixMetadataAdapterLifecycle.ManagedResource {
        private final MetadataTransactionId transactionId;
        private final ReentrantLock owner = ownerLock();
        private final Map<MetadataKey, StagedMutation> staged = new LinkedHashMap<>();
        private final Set<MetadataKey> reserved = new java.util.HashSet<>();
        private TransactionState state = TransactionState.ACTIVE;

        private TransactionImpl(MetadataTransactionId transactionId) {
            super();
            this.transactionId = transactionId;
        }

        @Override
        public MetadataTransactionId id() {
            return transactionId;
        }

        @Override
        public void create(
                MetadataKey key,
                RepeatableContent content,
                CancellationSignal cancellation) throws IOException {
            admit(MetadataMutationPayloadCodec.MutationKind.CREATE,
                    key, MINIMUM_CONTENT_LENGTH, content, cancellation);
        }

        @Override
        public void replace(
                MetadataKey key,
                long expectedRevision,
                RepeatableContent content,
                CancellationSignal cancellation) throws IOException {
            requireRevision(expectedRevision);
            admit(MetadataMutationPayloadCodec.MutationKind.REPLACE,
                    key, expectedRevision, content, cancellation);
        }

        private void admit(
                MetadataMutationPayloadCodec.MutationKind kind,
                MetadataKey key,
                long expectedRevision,
                RepeatableContent content,
                CancellationSignal cancellation) throws IOException {
            Objects.requireNonNull(key, "key");
            PosixMetadataAdapterLifecycle.OperationReservation operation = reserve(key);
            boolean operationConsumed = false;
            try (SpoolContent stagedContent = stage(content, cancellation)) {
                boolean accepted;
                try {
                    accepted = operation.finish(
                            () -> install(
                                    kind, key, expectedRevision, stagedContent),
                            () -> reserved.remove(key));
                } finally {
                    operationConsumed = true;
                }
                requireAccepted(accepted);
            } finally {
                if (!operationConsumed) {
                    operation.cancel(() -> reserved.remove(key));
                }
            }
        }

        private void requireAccepted(boolean accepted) {
            if (!accepted) {
                throw new IllegalStateException("POSIX transactional metadata store is closed");
            }
        }

        private PosixMetadataAdapterLifecycle.OperationReservation reserve(MetadataKey key) {
            requireOwner();
            PosixMetadataAdapterLifecycle.OperationReservation operation =
                    lifecycle.beginOperation();
            boolean reservedHere = false;
            try {
                requireActive();
                requireNewKey(key);
                reservedHere = reserved.add(key);
                return operation;
            } finally {
                if (!reservedHere) {
                    operation.cancel(() -> reserved.remove(key));
                }
            }
        }

        private void install(
                MetadataMutationPayloadCodec.MutationKind kind,
                MetadataKey key,
                long expectedRevision,
                SpoolContent stagedContent) {
            requireOwnerAndActive();
            reserved.remove(key);
            staged.put(key, new StagedMutation(
                    kind, key, expectedRevision, stagedContent.transfer()));
        }

        @Override
        public void delete(MetadataKey key, long expectedRevision) {
            Objects.requireNonNull(key, "key");
            requireRevision(expectedRevision);
            requireOwner();
            PosixMetadataAdapterLifecycle.OperationReservation operation =
                    lifecycle.beginOperation();
            StagedMutation mutation = new StagedMutation(
                    MetadataMutationPayloadCodec.MutationKind.DELETE,
                    key,
                    expectedRevision,
                    null);
            boolean consumed = false;
            try {
                requireActive();
                requireNewKey(key);
                try {
                    boolean accepted = operation.finish(
                            () -> staged.put(key, mutation),
                            () -> { });
                    if (!accepted) {
                        throw new IllegalStateException(
                                "POSIX transactional metadata store is closed");
                    }
                } finally {
                    consumed = true;
                }
            } finally {
                if (!consumed) {
                    operation.cancel(() -> { });
                }
            }
        }

        @Override
        public MetadataCommitResult commit() throws IOException {
            requireOwner();
            PosixMetadataAdapterLifecycle.OperationReservation operation =
                    lifecycle.beginOperation();
            MetadataCommitResult result = null;
            IOException failure = null;
            boolean engineOwnsResources = false;
            boolean terminalAttempt = false;
            try {
                requireActive();
                if (!reserved.isEmpty()) {
                    throw new IllegalStateException(
                            "Metadata transaction has an admission in progress");
                }
                state = TransactionState.COMMITTING;
                terminalAttempt = true;
                List<StagedMutation> mutations = List.copyOf(staged.values());
                List<PosixMetadataStoreEngine.PreparedMutation> prepared = prepare(mutations);
                engineOwnsResources = true;
                result = map(transactionId, engine.commit(transactionId, prepared));
            } catch (MetadataStoreException checked) {
                failure = checked;
            } catch (IOException uncertainty) {
                result = unknown(transactionId);
                lifecycle.recoveryRequired();
            } finally {
                if (!engineOwnsResources) {
                    failure = PosixMetadataAdapterLifecycle.append(failure, retireStaged());
                }
                if (terminalAttempt) {
                    operation.finishTerminal(this::terminalize);
                } else {
                    operation.cancel(() -> { });
                }
            }
            if (failure != null) {
                throw failure;
            }
            return Objects.requireNonNull(result, "commit result");
        }

        private List<PosixMetadataStoreEngine.PreparedMutation> prepare(
                List<StagedMutation> mutations) throws MetadataStoreException {
            List<PosixMetadataStoreEngine.PreparedMutation> prepared =
                    new ArrayList<>(mutations.size());
            for (StagedMutation mutation : mutations) {
                prepared.add(mutation.prepare());
            }
            return List.copyOf(prepared);
        }

        private void terminalize() {
            state = TransactionState.TERMINAL;
            staged.clear();
            reserved.clear();
            lifecycle.unregister(this);
        }

        @Override
        public void abort() throws IOException {
            requireOwner();
            PosixMetadataAdapterLifecycle.OperationReservation operation =
                    lifecycle.beginCleanupOperation();
            IOException failure;
            boolean terminalAttempt = false;
            try {
                requireActive();
                state = TransactionState.TERMINAL;
                terminalAttempt = true;
                failure = retireStaged();
            } finally {
                if (terminalAttempt) {
                    operation.finishTerminal(this::terminalize);
                } else {
                    operation.cancel(() -> { });
                }
            }
            if (failure != null) {
                throw failure;
            }
        }

        @Override
        public void close() throws IOException {
            requireOwner();
            if (state != TransactionState.TERMINAL) {
                abort();
            }
        }

        @Override
        public IOException forceClose() {
            if (state == TransactionState.TERMINAL) {
                return null;
            }
            state = TransactionState.TERMINAL;
            reserved.clear();
            return retireStaged();
        }

        private IOException retireStaged() {
            IOException failure = null;
            for (StagedMutation mutation : staged.values()) {
                try {
                    mutation.retire();
                } catch (IOException cleanup) {
                    failure = PosixMetadataAdapterLifecycle.append(failure, cleanup);
                }
            }
            staged.clear();
            return failure;
        }

        private void requireOwnerAndActive() {
            requireOwner();
            requireActive();
        }

        private void requireActive() {
            if (state != TransactionState.ACTIVE) {
                throw new IllegalStateException("Metadata transaction is terminal");
            }
        }

        private void requireOwner() {
            if (!owner.isHeldByCurrentThread()) {
                throw new IllegalStateException("Metadata transaction is thread-confined");
            }
        }

        private void requireNewKey(MetadataKey key) {
            if (staged.containsKey(key) || reserved.contains(key)) {
                throw new IllegalArgumentException(
                        "Metadata transaction cannot mutate one key more than once");
            }
        }
    }

    private static ReentrantLock ownerLock() {
        ReentrantLock result = new ReentrantLock();
        result.lock();
        return result;
    }

    private static void requireRevision(long revision) {
        if (revision < MINIMUM_CONTENT_LENGTH) {
            throw new IllegalArgumentException("Expected metadata revision must not be negative");
        }
    }

    /** Store-owned staged mutation containing no caller content authority. */
    private record StagedMutation(
            MetadataMutationPayloadCodec.MutationKind kind,
            MetadataKey key,
            long expectedRevision,
            SpoolContent content) {
        private PosixMetadataStoreEngine.PreparedMutation prepare() throws MetadataStoreException {
            return switch (kind) {
                case CREATE -> PosixMetadataStoreEngine.PreparedMutation.create(
                        key, content, CancellationSignal.NONE);
                case REPLACE -> PosixMetadataStoreEngine.PreparedMutation.replace(
                        key, expectedRevision, content, CancellationSignal.NONE);
                case DELETE -> PosixMetadataStoreEngine.PreparedMutation.delete(key, expectedRevision);
            };
        }

        private void retire() throws IOException {
            if (content != null) {
                content.close();
            }
        }
    }

    /** Repeatable store-owned spool removed exactly once after ownership ends. */
    private static final class SpoolContent implements RepeatableContent {
        private final Path path;
        private final long length;
        private final StagingOperations operations;
        private final AtomicBoolean closed = new AtomicBoolean();
        private boolean transferred;

        private SpoolContent(Path path, long length, StagingOperations operations) {
            super();
            this.path = path;
            this.length = length;
            this.operations = operations;
        }

        @Override
        public InputStream openStream() throws IOException {
            if (closed.get()) {
                throw new IllegalStateException("Staged metadata content is closed");
            }
            return java.nio.channels.Channels.newInputStream(operations.openRead(path));
        }

        @Override
        public OptionalLong length() {
            return OptionalLong.of(length);
        }

        @Override
        public String contentId() {
            return "zeroecho-posix-metadata-staged-v1";
        }

        private SpoolContent transfer() {
            if (transferred || closed.get()) {
                throw new IllegalStateException("Staged metadata content ownership is unavailable");
            }
            transferred = true;
            return new SpoolContent(path, length, operations);
        }

        @Override
        public void close() throws IOException {
            if (!transferred && closed.compareAndSet(false, true)) {
                operations.delete(path);
            }
        }
    }

    /** Package-private deterministic staging seam; never part of the SPI. */
    /* default */ interface StagingOperations {
        /** Creates one unpredictable exclusive store-owned spool. */
        Path create(Path parent) throws IOException;

        /** Opens the spool for bounded transfer. */
        FileChannel openWrite(Path path) throws IOException;

        /** Opens a fresh repeatable spool reader. */
        FileChannel openRead(Path path) throws IOException;

        /** Removes one no-longer-authoritative spool. */
        void delete(Path path) throws IOException;
    }

    /** Real POSIX staging operations. */
    /* default */ enum DefaultStagingOperations implements StagingOperations {
        /** Singleton production implementation. */
        INSTANCE;

        private static final FileAttribute<?>[] OWNER_ONLY = {
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))
        };

        @Override
        public Path create(Path parent) throws IOException {
            return Files.createTempFile(parent, ".zeroecho-metadata-", ".stage", OWNER_ONLY);
        }

        @Override
        public FileChannel openWrite(Path path) throws IOException {
            return FileChannel.open(
                    path,
                    Set.of(StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING,
                            LinkOption.NOFOLLOW_LINKS));
        }

        @Override
        public FileChannel openRead(Path path) throws IOException {
            return FileChannel.open(
                    path,
                    Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS));
        }

        @Override
        public void delete(Path path) throws IOException {
            Files.deleteIfExists(path);
        }
    }

    /** Single-use transaction lifecycle. */
    private enum TransactionState {
        ACTIVE,
        COMMITTING,
        TERMINAL
    }
}
