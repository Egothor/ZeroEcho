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
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashMap;
import java.util.HashSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataTransactionId;

/** Exclusive-writer POSIX append-only metadata-log writer. */
final class PosixMetadataLog implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(PosixMetadataLog.class.getName());
    private static final String CAPABILITY_WARNING =
            "POSIX metadata-log durability capabilities are limited; continuing in documented best-effort mode";
    private static final String TAIL_REPAIR_WARNING =
            "POSIX metadata log had an incomplete final tail; the validated boundary was durably restored";
    private static final String ABANDONED_RESTART_INFO =
            "POSIX metadata log recovery durably retired incomplete transactions";
    private static final long FRAME_HEADER_BYTES = 72L;
    private static final long FRAME_DIGEST_BYTES = 32L;
    private static final Set<String> RECOGNIZED_LOCAL_FILE_SYSTEMS =
            Set.of("apfs", "btrfs", "ext2", "ext3", "ext4", "tmpfs", "ufs", "xfs", "zfs");
    private static final Set<java.nio.file.attribute.PosixFilePermission> OWNER_ONLY =
            PosixFilePermissions.fromString("rw-------");
    private static final long STORE_HEADER_SEQUENCE = 0L;
    private static final long ISSUANCE_SEQUENCE = 0L;
    private static final long FIRST_TRANSACTION_SEQUENCE = 1L;
    private static final long MINIMUM_PAYLOAD_LENGTH = 0L;

    private final FileChannel channel;
    private final FileLock writerLock;
    private final MetadataStoreId storeId;
    private final PosixMetadataLogScanner.TransactionCounter transactionCounter;
    private final MetadataFrameCodec codec = new MetadataFrameCodec();
    private final FaultInjector faultInjector;
    private final ReentrantLock operationLock = new ReentrantLock();
    private final Map<MetadataTransactionId, ActiveTransaction> active = new HashMap<>();
    private MetadataTransactionId activeBatch;
    private long recoveryEpoch;
    private State state = State.OPEN;
    private boolean capabilityWarningEmitted;

    private PosixMetadataLog(
            FileChannel channel,
            FileLock writerLock,
            MetadataStoreId storeId,
            PosixMetadataLogScanner.TransactionCounter transactionCounter,
            long recoveryEpoch,
            FaultInjector faultInjector) {
        this.channel = channel;
        this.writerLock = writerLock;
        this.storeId = storeId;
        this.transactionCounter = transactionCounter;
        this.recoveryEpoch = recoveryEpoch;
        this.faultInjector = faultInjector;
    }

    /* default */ static PosixMetadataLog create(Path logPath, MetadataStoreId storeId) throws IOException {
        return create(logPath, storeId, DefaultCapabilityProfile.INSTANCE, FaultInjector.NONE);
    }

    /* default */ static PosixMetadataLog open(Path logPath) throws IOException {
        return open(logPath, DefaultCapabilityProfile.INSTANCE, FaultInjector.NONE);
    }

    /* default */ static PosixMetadataLog create(
            Path logPath,
            MetadataStoreId storeId,
            CapabilityProfile capabilities,
            FaultInjector faults) throws IOException {
        return Lifecycle.create(logPath, storeId, capabilities, faults);
    }

    /* default */ static PosixMetadataLog open(
            Path logPath,
            CapabilityProfile capabilities,
            FaultInjector faults) throws IOException {
        return Lifecycle.open(logPath, capabilities, faults);
    }

    /* default */ static EngineOpen openEngine(
            Path logPath,
            CapabilityProfile capabilities,
            FaultInjector faults) throws IOException {
        return Lifecycle.openEngine(logPath, capabilities, faults);
    }

    /* default */ MetadataStoreId storeId() {
        return storeId;
    }

    /* default */ static long checkedWritableRecoveryEpoch(long currentEpoch)
            throws MetadataStoreException {
        return Lifecycle.checkedWritableRecoveryEpoch(currentEpoch);
    }

    /* default */ List<MutationLocation> predictMutationLocations(List<Long> payloadLengths)
            throws IOException {
        operationLock.lock();
        try {
            requireOperational();
            List<Long> detached = List.copyOf(payloadLengths);
            List<MutationLocation> locations = new ArrayList<>(detached.size());
            long frameOffset = channel.size();
            for (Long boxedLength : detached) {
                long payloadLength = Objects.requireNonNull(boxedLength, "payloadLength");
                if (payloadLength < MINIMUM_PAYLOAD_LENGTH) {
                    throw new IllegalArgumentException("Mutation payload length must be non-negative");
                }
                long payloadOffset = Math.addExact(frameOffset, FRAME_HEADER_BYTES);
                long frameEnd = Math.addExact(
                        Math.addExact(payloadOffset, payloadLength), FRAME_DIGEST_BYTES);
                locations.add(new MutationLocation(payloadOffset, frameEnd));
                frameOffset = frameEnd;
            }
            return List.copyOf(locations);
        } finally {
            operationLock.unlock();
        }
    }

    /* default */ MetadataMutationPayloadCodec.Descriptor decodeMutation(
            MetadataFrameCodec.FrameMetadata frame) throws IOException {
        operationLock.lock();
        try {
            requireOpenAuthority();
            return MetadataMutationPayloadCodec.decode(channel, frame);
        } finally {
            operationLock.unlock();
        }
    }

    /* default */ MetadataTransactionId issue() throws IOException {
        operationLock.lock();
        try {
            requireOperational();
            MetadataTransactionId transactionId = transactionCounter.issue(storeId);
            try {
                trip(FaultPoint.ISSUANCE_APPEND);
                MetadataFrameCodec.FrameMetadata frame = appendBounded(
                        MetadataFrameCodec.FrameType.TRANSACTION_ISSUED,
                        transactionId.token(), ISSUANCE_SEQUENCE,
                        PosixMetadataLogScanner.encodeIssuance(transactionId));
                byte[] chain = PosixMetadataLogScanner.advanceChain(
                        channel, frame, PosixMetadataLogScanner.initialChainState());
                forceFile();
                active.put(transactionId, new ActiveTransaction(chain));
                return transactionId;
            } catch (IOException failure) {
                state = State.RECOVERY_REQUIRED;
                throw failure;
            }
        } finally {
            operationLock.unlock();
        }
    }

    /* default */ MetadataFrameCodec.FrameMetadata appendMutation(
            MetadataTransactionId transactionId,
            MetadataFrameCodec.FrameType type,
            long payloadLength,
            RepeatableContent payload,
            CancellationSignal cancellation) throws IOException {
        operationLock.lock();
        try {
            requireOperational();
            ActiveTransaction transaction = requireActive(transactionId);
            requireMutationType(type);
            requireBatch(transactionId);
            try {
                trip(FaultPoint.MUTATION_APPEND);
                channel.position(channel.size());
                MetadataFrameCodec.FrameMetadata frame = codec.write(
                        channel, type, transactionId.token(), transaction.nextSequence,
                        payloadLength, payload, cancellation);
                byte[] next = PosixMetadataLogScanner.advanceChain(
                        channel, frame, transaction.chainState);
                transaction.chainState = next;
                transaction.nextSequence++;
                return frame;
            } catch (IOException failure) {
                state = State.RECOVERY_REQUIRED;
                throw failure;
            }
        } finally {
            operationLock.unlock();
        }
    }

    /* default */ PosixMetadataLogScanner.Terminal commit(
            MetadataTransactionId transactionId, long revision) throws IOException {
        operationLock.lock();
        try {
            requireOperational();
            ActiveTransaction transaction = requireActive(transactionId);
            requireTerminalBatch(transactionId, transaction);
            byte[] payload = PosixMetadataLogScanner.encodeCommitted(
                    transactionId, revision, transaction.chainState);
            PosixMetadataLogScanner.Terminal result = new PosixMetadataLogScanner.Terminal(
                    PosixMetadataLogScanner.TerminalKind.COMMITTED,
                    java.util.OptionalLong.of(revision), java.util.OptionalInt.empty());
            return appendTerminal(transactionId, transaction, MetadataFrameCodec.FrameType.TERMINAL_COMMITTED,
                    payload, result);
        } finally {
            operationLock.unlock();
        }
    }

    /* default */ PosixMetadataLogScanner.Terminal reject(
            MetadataTransactionId transactionId, int failureCode) throws IOException {
        operationLock.lock();
        try {
            requireOperational();
            ActiveTransaction transaction = requireActive(transactionId);
            if (transaction.nextSequence != FIRST_TRANSACTION_SEQUENCE || activeBatch != null) {
                throw new IllegalArgumentException(
                        "Rejected POSIX metadata transaction must contain no mutation frames");
            }
            byte[] payload = PosixMetadataLogScanner.encodeRejected(
                    transactionId, failureCode, transaction.chainState);
            PosixMetadataLogScanner.Terminal result = new PosixMetadataLogScanner.Terminal(
                    PosixMetadataLogScanner.TerminalKind.NOT_COMMITTED,
                    java.util.OptionalLong.empty(), java.util.OptionalInt.of(failureCode));
            return appendTerminal(transactionId, transaction,
                    MetadataFrameCodec.FrameType.TERMINAL_NOT_COMMITTED, payload, result);
        } finally {
            operationLock.unlock();
        }
    }

    /* default */ int activeTransactionCount() throws IOException {
        operationLock.lock();
        try {
            requireOpenAuthority();
            return active.size();
        } finally {
            operationLock.unlock();
        }
    }

    /* default */ PosixMetadataLogScanner.RecoveryResult scan() throws IOException {
        operationLock.lock();
        try {
            requireOpenAuthority();
            return PosixMetadataLogScanner.scan(channel);
        } finally {
            operationLock.unlock();
        }
    }

    private PosixMetadataLogScanner.Terminal appendTerminal(
            MetadataTransactionId transactionId,
            ActiveTransaction transaction,
            MetadataFrameCodec.FrameType type,
            byte[] payload,
            PosixMetadataLogScanner.Terminal result) throws IOException {
        try {
            trip(FaultPoint.TERMINAL_APPEND);
            appendBounded(type, transactionId.token(), transaction.nextSequence, payload);
            forceFile();
        } catch (IOException failure) {
            state = State.RECOVERY_REQUIRED;
            throw new OutcomeUnknownException(failure);
        }
        active.remove(transactionId);
        activeBatch = null;
        try {
            trip(FaultPoint.POST_FORCE_UNCERTAINTY);
        } catch (IOException hidden) {
            state = State.RECOVERY_REQUIRED;
            throw new OutcomeUnknownException(hidden);
        }
        return result;
    }

    private void appendStoreHeader() throws IOException {
        appendBounded(
                MetadataFrameCodec.FrameType.STORE_HEADER,
                PosixMetadataLogScanner.zeroToken(),
                STORE_HEADER_SEQUENCE,
                PosixMetadataLogScanner.encodeStoreHeader(storeId));
        forceFile();
    }

    private void appendRecoveryRestart(long abandonedOpenCount, long truncatedByteCount)
            throws IOException {
        long nextEpoch = checkedWritableRecoveryEpoch(recoveryEpoch);
        trip(FaultPoint.RECOVERY_RESTART_APPEND);
        appendBounded(
                MetadataFrameCodec.FrameType.RECOVERY_RESTART,
                PosixMetadataLogScanner.zeroToken(),
                nextEpoch,
                PosixMetadataLogScanner.encodeRestart(
                        nextEpoch, abandonedOpenCount, truncatedByteCount));
        forceFile();
        recoveryEpoch = nextEpoch;
    }

    private MetadataFrameCodec.FrameMetadata appendBounded(
            MetadataFrameCodec.FrameType type, String token, long sequence, byte[] payload) throws IOException {
        channel.position(channel.size());
        try (ImmutableByteContent content = new ImmutableByteContent(payload)) {
            return codec.write(channel, type, token, sequence, payload.length, content, CancellationSignal.NONE);
        }
    }

    private void forceFile() throws IOException {
        trip(FaultPoint.FILE_FORCE);
        channel.force(true);
    }

    private ActiveTransaction requireActive(MetadataTransactionId transactionId) {
        requireAuthority(transactionId);
        ActiveTransaction transaction = active.get(transactionId);
        if (transaction == null) {
            throw new IllegalArgumentException("POSIX metadata transaction is not active in this log instance");
        }
        return transaction;
    }

    private void requireBatch(MetadataTransactionId transactionId) {
        if (activeBatch == null) {
            activeBatch = transactionId;
        } else if (!activeBatch.equals(transactionId)) {
            throw new IllegalArgumentException("POSIX metadata mutation batches cannot interleave");
        }
    }

    private void requireTerminalBatch(
            MetadataTransactionId transactionId, ActiveTransaction transaction) {
        if (transaction.nextSequence == FIRST_TRANSACTION_SEQUENCE) {
            if (activeBatch != null) {
                throw new IllegalArgumentException(
                        "Empty terminal cannot interleave with a metadata mutation batch");
            }
        } else if (!transactionId.equals(activeBatch)) {
            throw new IllegalArgumentException("POSIX metadata terminal does not own the active batch");
        }
    }

    private void requireAuthority(MetadataTransactionId transactionId) {
        Objects.requireNonNull(transactionId, "transactionId");
        if (!storeId.equals(transactionId.storeId())) {
            throw new IllegalArgumentException("POSIX metadata transaction belongs to another store");
        }
    }

    private static void requireMutationType(MetadataFrameCodec.FrameType type) {
        Objects.requireNonNull(type, "type");
        if (type != MetadataFrameCodec.FrameType.MUTATION_CREATE
                && type != MetadataFrameCodec.FrameType.MUTATION_REPLACE
                && type != MetadataFrameCodec.FrameType.MUTATION_DELETE) {
            throw new IllegalArgumentException("POSIX metadata log requires an opaque mutation frame type");
        }
    }

    private void requireOperational() throws IOException {
        requireOpenAuthority();
        if (state == State.RECOVERY_REQUIRED) {
            throw new IOException("POSIX metadata log requires close and recovery");
        }
    }

    private void requireOpenAuthority() throws IOException {
        if (state == State.CLOSED || !channel.isOpen()) {
            throw new IllegalStateException("POSIX metadata log is closed");
        }
        // The retained lock is the sole writer authority for this log instance.
        if (!writerLock.isValid()) {
            state = State.RECOVERY_REQUIRED;
            throw new IOException("POSIX metadata log writer authority is invalid");
        }
    }

    private void warnIfLimited(boolean limited) {
        if (limited && !capabilityWarningEmitted) {
            LOGGER.warning(CAPABILITY_WARNING);
            capabilityWarningEmitted = true;
        }
    }

    private void trip(FaultPoint point) throws IOException {
        faultInjector.fail(point);
    }

    @Override
    public void close() throws IOException {
        operationLock.lock();
        try {
            if (state == State.CLOSED) {
                return;
            }
            IOException failure = null;
            try {
                if (writerLock.isValid()) {
                    writerLock.release();
                }
            } catch (IOException releaseFailure) {
                failure = releaseFailure;
            }
            try {
                channel.close();
            } catch (IOException closeFailure) {
                failure = appendFailure(failure, closeFailure);
            }
            active.clear();
            activeBatch = null;
            state = State.CLOSED;
            if (failure != null) {
                throw failure;
            }
        } finally {
            operationLock.unlock();
        }
    }

    private static IOException appendFailure(IOException first, IOException later) {
        if (first == null) {
            return later;
        }
        first.addSuppressed(later);
        return first;
    }

    /** Isolates create/reopen branching from the retained writer authority. */
    private static final class Lifecycle {
        private static PosixMetadataLog create(
                Path logPath,
                MetadataStoreId storeId,
                CapabilityProfile capabilities,
                FaultInjector faults) throws IOException {
            Objects.requireNonNull(storeId, "storeId");
            Objects.requireNonNull(capabilities, "capabilities");
            Objects.requireNonNull(faults, "faults");
            Path parent = SecureFiles.requireParent(logPath);
            boolean posix = capabilities.posixAvailable(parent);
            boolean local = capabilities.localFileSystem(parent);
            Resources resources = Resources.acquire(logPath, true, posix);
            try {
                PosixMetadataLog log = new PosixMetadataLog(
                        resources.channel, resources.writerLock, storeId,
                        PosixMetadataLogScanner.TransactionCounter.first(), 0L, faults);
                log.warnIfLimited(!posix || !local);
                log.appendStoreHeader();
                forceParent(capabilities, resources, log);
                resources.closeAnchors();
                return log;
            } catch (IOException failure) {
                resources.closeAfterFailure(failure);
                throw failure;
            }
        }

        private static PosixMetadataLog open(
                Path logPath,
                CapabilityProfile capabilities,
                FaultInjector faults) throws IOException {
            Objects.requireNonNull(capabilities, "capabilities");
            Objects.requireNonNull(faults, "faults");
            Path parent = SecureFiles.requireParent(logPath);
            boolean posix = capabilities.posixAvailable(parent);
            boolean local = capabilities.localFileSystem(parent);
            Resources resources = Resources.acquire(logPath, false, posix);
            try {
                PosixMetadataLogScanner.RecoveryResult recovered =
                        PosixMetadataLogScanner.scan(resources.channel);
                long removed = Math.subtractExact(
                        recovered.physicalEnd(), recovered.lastCompleteFrameBoundary());
                recovered = repair(resources.channel, recovered, faults);
                PosixMetadataLog log = recoveredLog(resources, recovered, faults);
                log.warnIfLimited(!posix || !local);
                log.appendRecoveryRestart(recovered.openTransactionCount(), removed);
                reportRestart(recovered.openTransactionCount(), removed);
                resources.closeAnchors();
                return log;
            } catch (IOException failure) {
                resources.closeAfterFailure(failure);
                throw failure;
            }
        }

        private static EngineOpen openEngine(
                Path logPath,
                CapabilityProfile capabilities,
                FaultInjector faults) throws IOException {
            Objects.requireNonNull(capabilities, "capabilities");
            Objects.requireNonNull(faults, "faults");
            Path parent = SecureFiles.requireParent(logPath);
            boolean posix = capabilities.posixAvailable(parent);
            boolean local = capabilities.localFileSystem(parent);
            Resources resources = Resources.acquire(logPath, false, posix);
            try {
                PosixMetadataLogScanner.ReplayResult recovered =
                        PosixMetadataLogScanner.replay(resources.channel);
                long removed = Math.subtractExact(
                        recovered.physicalEnd(), recovered.lastCompleteFrameBoundary());
                recovered = repair(resources.channel, recovered, faults);
                PosixMetadataLog log = recoveredLog(resources, recovered, faults);
                log.warnIfLimited(!posix || !local);
                resources.channel.position(recovered.lastCompleteFrameBoundary());
                log.appendRecoveryRestart(recovered.openTransactionCount(), removed);
                reportRestart(recovered.openTransactionCount(), removed);
                resources.closeAnchors();
                return new EngineOpen(
                        log,
                        recovered.stateIndex(),
                        mergeRestartOutcomes(recovered.outcomes(), recovered.restartOutcomes()));
            } catch (IOException failure) {
                resources.closeAfterFailure(failure);
                throw failure;
            }
        }

        private static PosixMetadataLog recoveredLog(
                Resources resources,
                PosixMetadataLogScanner.RecoveryResult recovered,
                FaultInjector faults) {
            return new PosixMetadataLog(
                    resources.channel, resources.writerLock, recovered.storeId(),
                    PosixMetadataLogScanner.TransactionCounter.recovered(
                            recovered.nextTransactionToken(), recovered.transactionTokensExhausted()),
                    recovered.recoveryEpoch(), faults);
        }

        private static PosixMetadataLog recoveredLog(
                Resources resources,
                PosixMetadataLogScanner.ReplayResult recovered,
                FaultInjector faults) {
            return new PosixMetadataLog(
                    resources.channel, resources.writerLock, recovered.storeId(),
                    PosixMetadataLogScanner.TransactionCounter.recovered(
                            recovered.nextTransactionToken(), recovered.transactionTokensExhausted()),
                    recovered.recoveryEpoch(), faults);
        }

        private static PosixMetadataLogScanner.RecoveryResult repair(
                FileChannel channel,
                PosixMetadataLogScanner.RecoveryResult recovered,
                FaultInjector faults) throws IOException {
            if (recovered.tail() == PosixMetadataLogScanner.Tail.INCOMPLETE_TAIL) {
                return TailRepair.repair(channel, recovered, faults);
            }
            return recovered;
        }

        private static PosixMetadataLogScanner.ReplayResult repair(
                FileChannel channel,
                PosixMetadataLogScanner.ReplayResult recovered,
                FaultInjector faults) throws IOException {
            if (recovered.tail() == PosixMetadataLogScanner.Tail.INCOMPLETE_TAIL) {
                return TailRepair.repair(channel, recovered, faults);
            }
            return recovered;
        }

        private static Map<MetadataTransactionId, PosixMetadataLogScanner.Terminal>
                mergeRestartOutcomes(
                        Map<MetadataTransactionId, PosixMetadataLogScanner.Terminal> outcomes,
                        Map<MetadataTransactionId, PosixMetadataLogScanner.Terminal> restartOutcomes) {
            Map<MetadataTransactionId, PosixMetadataLogScanner.Terminal> merged =
                    new HashMap<>(outcomes);
            merged.putAll(restartOutcomes);
            return Map.copyOf(merged);
        }

        private static void forceParent(
                CapabilityProfile capabilities,
                Resources resources,
                PosixMetadataLog log) throws IOException {
            try {
                capabilities.forceParent(resources.directoryChannel);
            } catch (IOException | UnsupportedOperationException unsupported) {
                log.warnIfLimited(true);
            }
        }

        private static void reportRestart(long abandonedOpenCount, long truncatedByteCount) {
            if (truncatedByteCount > MINIMUM_PAYLOAD_LENGTH) {
                LOGGER.warning(TAIL_REPAIR_WARNING);
            } else if (abandonedOpenCount > MINIMUM_PAYLOAD_LENGTH) {
                LOGGER.info(ABANDONED_RESTART_INFO);
            }
        }

        private static long checkedWritableRecoveryEpoch(long currentEpoch)
                throws MetadataStoreException {
            if (currentEpoch == Long.MAX_VALUE) {
                throw new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                        "POSIX metadata recovery epoch is exhausted");
            }
            return PosixMetadataLogScanner.checkedNextRecoveryEpoch(currentEpoch);
        }
    }

    /** O(1) repair of one scanner-authenticated incomplete final tail. */
    private static final class TailRepair {
        private static PosixMetadataLogScanner.RecoveryResult repair(
                FileChannel channel,
                PosixMetadataLogScanner.RecoveryResult before,
                FaultInjector faults) throws IOException {
            truncateAndVerify(channel, before.lastCompleteFrameBoundary(), faults);
            return new PosixMetadataLogScanner.RecoveryResult(
                    before.storeId(),
                    before.lastCompleteFrameBoundary(),
                    before.lastCompleteFrameBoundary(),
                    PosixMetadataLogScanner.Tail.CLEAN_END,
                    before.transactions(),
                    before.nextTransactionToken(),
                    before.transactionTokensExhausted(),
                    before.recoveryEpoch(),
                    before.openTransactionCount());
        }

        private static PosixMetadataLogScanner.ReplayResult repair(
                FileChannel channel,
                PosixMetadataLogScanner.ReplayResult before,
                FaultInjector faults) throws IOException {
            truncateAndVerify(channel, before.lastCompleteFrameBoundary(), faults);
            return new PosixMetadataLogScanner.ReplayResult(
                    before.storeId(),
                    before.lastCompleteFrameBoundary(),
                    before.lastCompleteFrameBoundary(),
                    PosixMetadataLogScanner.Tail.CLEAN_END,
                    before.nextTransactionToken(),
                    before.transactionTokensExhausted(),
                    before.stateIndex(),
                    before.outcomes(),
                    before.restartOutcomes(),
                    before.recoveryEpoch(),
                    before.openTransactionCount(),
                    before.recoveryFullMapCopies(),
                    before.recoveryFinalInstalls(),
                    before.discardedDescriptorCount());
        }

        private static void truncateAndVerify(
                FileChannel channel, long boundary, FaultInjector faults) throws IOException {
            faults.fail(FaultPoint.TAIL_TRUNCATE);
            channel.truncate(boundary);
            faults.fail(FaultPoint.TAIL_FORCE);
            channel.force(true);
            faults.fail(FaultPoint.TAIL_VERIFY);
            if (channel.size() != boundary) {
                throw new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE,
                        "POSIX metadata log tail repair verification failed");
            }
            channel.position(boundary);
        }
    }

    /** Live lifecycle of one retained POSIX log authority. */
    private enum State {
        OPEN,
        RECOVERY_REQUIRED,
        CLOSED
    }

    /** O(1) live control state for one transaction. */
    private static final class ActiveTransaction {
        private byte[] chainState;
        private long nextSequence = FIRST_TRANSACTION_SEQUENCE;

        private ActiveTransaction(byte[] chainState) {
            this.chainState = chainState;
        }
    }

    /** Caller-visible uncertainty requiring strict scanner classification. */
    /* default */ static final class OutcomeUnknownException extends IOException {
        private static final long serialVersionUID = -4335785072683425908L;

        private OutcomeUnknownException(IOException cause) {
            super("POSIX metadata transaction terminal outcome requires recovery", cause);
        }
    }

    /** Deterministic package-private fault boundaries. */
    /* default */ enum FaultPoint {
        ISSUANCE_APPEND,
        MUTATION_APPEND,
        TERMINAL_APPEND,
        FILE_FORCE,
        POST_FORCE_UNCERTAINTY,
        TAIL_TRUNCATE,
        TAIL_FORCE,
        TAIL_VERIFY,
        RECOVERY_RESTART_APPEND
    }

    /** Package-private deterministic fault injector; it is not a production extension point. */
    /* default */
    @FunctionalInterface
    interface FaultInjector {
        FaultInjector NONE = point -> { };

        /** Fails one selected append or durability boundary. */
        void fail(FaultPoint point) throws IOException;
    }

    /** Predicted immutable frame location used before one serialized append batch. */
    /* default */ record MutationLocation(long payloadOffset, long frameEndOffset) {
    }

    /** One-scan engine opening result retaining the reconstructed current state. */
    /* default */ record EngineOpen(
            PosixMetadataLog log,
            MetadataStateIndex stateIndex,
            Map<MetadataTransactionId, PosixMetadataLogScanner.Terminal> outcomes) {
        EngineOpen {
            Objects.requireNonNull(log, "log");
            Objects.requireNonNull(stateIndex, "stateIndex");
            outcomes = Map.copyOf(outcomes);
        }
    }

    /** Package-private capability seam used to verify fail-closed initialization behavior. */
    /* default */
    interface CapabilityProfile {
        /** Reports whether owner-only POSIX creation attributes are supported. */
        boolean posixAvailable(Path parent) throws IOException;

        /** Reports whether the filesystem is recognized as local. */
        boolean localFileSystem(Path parent) throws IOException;

        /** Forces the descriptor-relative parent-directory channel. */
        void forceParent(FileChannel parentDirectory) throws IOException;
    }

    /** Default capability observations for the active Java filesystem provider. */
    private enum DefaultCapabilityProfile implements CapabilityProfile {
        INSTANCE;

        @Override
        public boolean posixAvailable(Path parent) throws IOException {
            return Files.getFileStore(parent).supportsFileAttributeView("posix");
        }

        @Override
        public boolean localFileSystem(Path parent) throws IOException {
            String type = Files.getFileStore(parent).type().toLowerCase(Locale.ROOT);
            return RECOGNIZED_LOCAL_FILE_SYSTEMS.contains(type);
        }

        @Override
        public void forceParent(FileChannel parentDirectory) throws IOException {
            parentDirectory.force(true);
        }
    }

    /** Secure descriptor-relative opening for the trusted POSIX directory profile. */
    private static final class SecureFiles {

        private static Path requireParent(Path logPath) throws IOException {
            Objects.requireNonNull(logPath, "logPath");
            Path parent = logPath.getParent();
            if (parent == null || logPath.getFileName() == null
                    || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)
                    || Files.isSymbolicLink(parent)) {
                throw new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE,
                        "POSIX metadata log target has no trusted regular parent directory");
            }
            return parent;
        }

        private static SecureDirectoryStream<Path> openDirectory(Path parent) throws IOException {
            return requireSecureDirectory(Files.newDirectoryStream(parent));
        }

        private static SecureDirectoryStream<Path> requireSecureDirectory(DirectoryStream<Path> opened)
                throws IOException {
            if (opened instanceof SecureDirectoryStream<?>) {
                @SuppressWarnings("unchecked")
                SecureDirectoryStream<Path> secure = (SecureDirectoryStream<Path>) opened;
                return secure;
            }
            opened.close();
            throw new MetadataStoreException(
                    MetadataCommitResult.FailureCategory.UNSUPPORTED_CAPABILITY,
                    "Secure POSIX metadata directory access is unavailable");
        }

        private static FileChannel fileChannel(SeekableByteChannel selected) throws IOException {
            if (selected instanceof FileChannel) {
                return (FileChannel) selected;
            }
            selected.close();
            throw new MetadataStoreException(
                    MetadataCommitResult.FailureCategory.UNSUPPORTED_CAPABILITY,
                    "POSIX metadata file forcing is unavailable");
        }

        private static Set<OpenOption> logOptions(boolean create) {
            Set<OpenOption> options = new HashSet<>();
            options.add(StandardOpenOption.READ);
            options.add(StandardOpenOption.WRITE);
            options.add(LinkOption.NOFOLLOW_LINKS);
            if (create) {
                options.add(StandardOpenOption.CREATE_NEW);
            }
            return Set.copyOf(options);
        }

        private static FileAttribute<?>[] attributes(boolean posix) {
            if (posix) {
                return new FileAttribute<?>[] { PosixFilePermissions.asFileAttribute(OWNER_ONLY) };
            }
            return new FileAttribute<?>[0];
        }

        private static void requireRegularEntry(
                SecureDirectoryStream<Path> directory, Path name, boolean create) throws IOException {
            if (create) {
                return;
            }
            BasicFileAttributeView view = directory.getFileAttributeView(
                    name, BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            BasicFileAttributes attributes = view.readAttributes();
            if (!attributes.isRegularFile() || attributes.isSymbolicLink()) {
                throw new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE,
                        "POSIX metadata log entry is not a regular file");
            }
        }
    }

    /** Owns initialization anchors and transfers only the retained log authority. */
    private static final class Resources {
        private SecureDirectoryStream<Path> directory;
        private FileChannel directoryChannel;
        private FileChannel channel;
        private FileLock writerLock;

        private static Resources acquire(Path logPath, boolean create, boolean posix) throws IOException {
            Resources resources = new Resources();
            try {
                Path parent = SecureFiles.requireParent(logPath);
                resources.directory = SecureFiles.openDirectory(parent);
                resources.directoryChannel = SecureFiles.fileChannel(resources.directory.newByteChannel(
                        Path.of("."), Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)));
                Path name = logPath.getFileName();
                SecureFiles.requireRegularEntry(resources.directory, name, create);
                resources.channel = SecureFiles.fileChannel(resources.directory.newByteChannel(
                        name, SecureFiles.logOptions(create), SecureFiles.attributes(posix)));
                resources.writerLock = resources.acquireWriterLock();
                return resources;
            } catch (IOException failure) {
                resources.closeAfterFailure(failure);
                throw failure;
            }
        }

        private FileLock acquireWriterLock() throws IOException {
            final FileLock lock;
            try {
                lock = channel.tryLock();
            } catch (OverlappingFileLockException contention) {
                throw new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.STORAGE_FAILURE,
                        "POSIX metadata log exclusive writer authority is unavailable", contention);
            }
            if (lock == null) {
                throw new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.STORAGE_FAILURE,
                        "POSIX metadata log exclusive writer authority is unavailable");
            }
            return lock;
        }

        private void closeAnchors() throws IOException {
            IOException failure = null;
            try {
                if (directoryChannel != null) {
                    directoryChannel.close();
                }
            } catch (IOException closeFailure) {
                failure = closeFailure;
            }
            try {
                if (directory != null) {
                    directory.close();
                }
            } catch (IOException closeFailure) {
                failure = appendFailure(failure, closeFailure);
            }
            directoryChannel = null;
            directory = null;
            if (failure != null) {
                throw failure;
            }
        }

        private void closeAfterFailure(IOException primary) {
            IOException cleanup = closeAll();
            if (cleanup != null) {
                primary.addSuppressed(cleanup);
            }
        }

        private IOException closeAll() {
            IOException failure = null;
            try {
                if (writerLock != null && writerLock.isValid()) {
                    writerLock.release();
                }
            } catch (IOException closeFailure) {
                failure = closeFailure;
            }
            try {
                if (channel != null) {
                    channel.close();
                }
            } catch (IOException closeFailure) {
                failure = appendFailure(failure, closeFailure);
            }
            try {
                closeAnchors();
            } catch (IOException closeFailure) {
                failure = appendFailure(failure, closeFailure);
            }
            return failure;
        }
    }
}
