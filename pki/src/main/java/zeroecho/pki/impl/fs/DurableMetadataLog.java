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
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
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

/**
 * Exclusive-writer durable append-only metadata-log writer.
 */
final class DurableMetadataLog implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(DurableMetadataLog.class.getName());
    private static final String CAPABILITY_WARNING =
            "Durable metadata-log durability capabilities are limited; continuing in documented best-effort mode";
    private static final String TAIL_REPAIR_WARNING =
            "Durable metadata log had an incomplete final tail; the validated boundary was durably restored";
    private static final String ABANDONED_RESTART_INFO =
            "Durable metadata log recovery durably retired incomplete transactions";
    private static final long FRAME_HEADER_BYTES = 72L;
    private static final long FRAME_DIGEST_BYTES = 32L;
    private static final Set<String> LOCAL_FILE_SYSTEMS =
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
    private final DurableMetadataLogScanner.TransactionCounter transactionCounter;
    private final MetadataFrameCodec codec = new MetadataFrameCodec();
    private final FaultInjector faultInjector;
    private final ReentrantLock operationLock = new ReentrantLock();
    private final Map<MetadataTransactionId, ActiveTransaction> active = new HashMap<>();
    private MetadataTransactionId activeBatch;
    private long recoveryEpoch;
    private State state = State.OPEN;
    private boolean capabilityWarningEmitted;

    private DurableMetadataLog(
            FileChannel channel,
            FileLock writerLock,
            MetadataStoreId storeId,
            DurableMetadataLogScanner.TransactionCounter transactionCounter,
            long recoveryEpoch,
            FaultInjector faultInjector) {
        this.channel = channel;
        this.writerLock = writerLock;
        this.storeId = storeId;
        this.transactionCounter = transactionCounter;
        this.recoveryEpoch = recoveryEpoch;
        this.faultInjector = faultInjector;
    }

    /**
     * Creates a fresh exclusively locked log and forces its store header and parent namespace.
     *
     * @param logPath exact log file path in an existing secured parent directory
     * @param storeId exact store identity to persist in the new log header
     * @return owned durable log retaining the sole writer lock; caller must close it
     * @throws NullPointerException if a required input is null
     * @throws IOException if secure opening, locking, framing, integrity, tail repair or durability confirmation fails
     */
    /* default */ static DurableMetadataLog create(Path logPath, MetadataStoreId storeId) throws IOException {
        return create(logPath, storeId, DefaultCapabilityProfile.INSTANCE, FaultInjector.NONE);
    }

    /**
     * Opens an exclusively locked log, repairs its proven incomplete tail and forces a recovery restart marker.
     *
     * <p>Recovery abandons unfinished transactions in the new recovery epoch before accepting new work.</p>
     *
     * @param logPath exact log file path in an existing secured parent directory
     * @return owned durable log retaining the sole writer lock; caller must close it
     * @throws NullPointerException if a required input is null
     * @throws IOException if secure opening, locking, framing, integrity, tail repair or durability confirmation fails
     */
    /* default */ static DurableMetadataLog open(Path logPath) throws IOException {
        return open(logPath, DefaultCapabilityProfile.INSTANCE, FaultInjector.NONE);
    }

    /**
     * Creates a fresh exclusively locked log and forces its store header and parent namespace.
     *
     * @param logPath exact log file path in an existing secured parent directory
     * @param storeId exact store identity to persist in the new log header
     * @param capabilities filesystem capability and parent durability strategy
     * @param faults deterministic checked persistence fault injector
     * @return owned durable log retaining the sole writer lock; caller must close it
     * @throws NullPointerException if a required input is null
     * @throws IOException if secure opening, locking, framing, integrity, tail repair or durability confirmation fails
     */
    /* default */ static DurableMetadataLog create(
            Path logPath,
            MetadataStoreId storeId,
            CapabilityProfile capabilities,
            FaultInjector faults) throws IOException {
        return Lifecycle.create(logPath, storeId, capabilities, faults);
    }

    /**
     * Opens an exclusively locked log, repairs its proven incomplete tail and forces a recovery restart marker.
     *
     * <p>Recovery abandons unfinished transactions in the new recovery epoch before accepting new work.</p>
     *
     * @param logPath exact log file path in an existing secured parent directory
     * @param capabilities filesystem capability and parent durability strategy
     * @param faults deterministic checked persistence fault injector
     * @return owned durable log retaining the sole writer lock; caller must close it
     * @throws NullPointerException if a required input is null
     * @throws IOException if secure opening, locking, framing, integrity, tail repair or durability confirmation fails
     */
    /* default */ static DurableMetadataLog open(
            Path logPath,
            CapabilityProfile capabilities,
            FaultInjector faults) throws IOException {
        return Lifecycle.open(logPath, capabilities, faults);
    }

    /**
     * Replays current metadata state while opening and repairing an exclusively locked durable log.
     *
     * <p>Recovery abandons unfinished transactions in the new recovery epoch before accepting new work.</p>
     *
     * @param logPath exact log file path in an existing secured parent directory
     * @param capabilities filesystem capability and parent durability strategy
     * @param faults deterministic checked persistence fault injector
     * @return owned log with reconstructed current index and retained terminal outcomes
     * @throws NullPointerException if a required input is null
     * @throws IOException if secure opening, locking, framing, integrity, tail repair or durability confirmation fails
     */
    /* default */ static EngineOpen openEngine(
            Path logPath,
            CapabilityProfile capabilities,
            FaultInjector faults) throws IOException {
        return Lifecycle.openEngine(logPath, capabilities, faults);
    }

    /**
     * Returns the exact authoritative metadata store identity.
     *
     * @return exact authoritative metadata store identity
     */
    /* default */ MetadataStoreId storeId() {
        return storeId;
    }

    /**
     * Advances the recovery epoch while classifying writable epoch exhaustion as a capacity failure.
     *
     * @param currentEpoch validated current nonnegative recovery epoch
     * @return next recovery epoch
     * @throws MetadataStoreException if no writable next recovery epoch can be represented
     */
    /* default */ static long checkedWritableRecoveryEpoch(long currentEpoch)
            throws MetadataStoreException {
        return Lifecycle.checkedWritableRecoveryEpoch(currentEpoch);
    }

    /**
     * Predicts exact mutation payload and end offsets from the current serialized file boundary.
     *
     * @param payloadLengths ordered nonnegative encoded payload lengths for the intended contiguous mutation batch
     * @return immutable predicted payload and frame-end byte coordinates
     * @throws NullPointerException if a required input is null
     * @throws IllegalStateException if this log is closed
     * @throws IllegalArgumentException if a payload length is negative
     * @throws ArithmeticException if a predicted byte boundary overflows
     * @throws IOException if writer authority is invalid, recovery is required or file size cannot be read
     */
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

    /**
     * Decodes a bounded mutation descriptor while retaining this log's exact open writer authority.
     *
     * @param frame already validated metadata frame locator within this log
     * @return decoded semantic key, expected revision and borrowed physical value locator
     * @throws NullPointerException if a required input is null
     * @throws IllegalStateException if this log is closed
     * @throws IOException if writer authority or mutation framing is invalid or the payload cannot be read
     */
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

    /**
     * Appends and forces a fresh transaction identity before exposing it to callers.
     *
     * @return new exact store-bound active transaction identity
     * @throws IllegalStateException if the log is closed or transaction token space is exhausted
     * @throws IOException if writer authority, issuance append or force fails; append failure fences further writes
     */
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
                        DurableMetadataLogScanner.encodeIssuance(transactionId));
                byte[] chain = DurableMetadataLogScanner.advanceChain(
                        channel, frame, DurableMetadataLogScanner.initialChainState());
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

    /**
     * Appends one opaque mutation to the transaction's contiguous authenticated frame batch.
     *
     * @param transactionId active transaction issued by this exact store
     * @param type CREATE, REPLACE or DELETE structural mutation frame kind
     * @param payloadLength exact nonnegative encoded payload length in bytes
     * @param payload borrowed repeatable mutation content read during the append
     * @param cancellation cooperative cancellation signal checked during payload transfer
     * @return exact written frame location; durability is established by its terminal record
     * @throws NullPointerException if a required input is null
     * @throws IllegalStateException if this log is closed
     * @throws IllegalArgumentException if the transaction is foreign or inactive, frame kind is invalid or another transaction owns the active batch
     * @throws IOException if writer authority, payload framing, cancellation or append fails; append failure requires recovery
     */
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
                byte[] next = DurableMetadataLogScanner.advanceChain(
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

    /**
     * Appends and forces the transaction's committed terminal record with its exact chain commitment.
     *
     * @param transactionId active store-bound transaction owning its contiguous mutation batch
     * @param revision nonnegative committed metadata revision assigned by the caller
     * @return retained committed terminal result after the durability barrier
     * @throws NullPointerException if a required input is null
     * @throws IllegalStateException if this log is closed
     * @throws IllegalArgumentException if identity, active batch ownership or revision is invalid
     * @throws IOException if writer authority or terminal append durability fails
     */
    /* default */ DurableMetadataLogScanner.Terminal commit(
            MetadataTransactionId transactionId, long revision) throws IOException {
        operationLock.lock();
        try {
            requireOperational();
            ActiveTransaction transaction = requireActive(transactionId);
            requireTerminalBatch(transactionId, transaction);
            byte[] payload = DurableMetadataLogScanner.encodeCommitted(
                    transactionId, revision, transaction.chainState);
            DurableMetadataLogScanner.Terminal result = new DurableMetadataLogScanner.Terminal(
                    DurableMetadataLogScanner.TerminalKind.COMMITTED,
                    java.util.OptionalLong.of(revision), java.util.OptionalInt.empty());
            return appendTerminal(transactionId, transaction, MetadataFrameCodec.FrameType.TERMINAL_COMMITTED,
                    payload, result);
        } finally {
            operationLock.unlock();
        }
    }

    /**
     * Appends and forces a noncommitted terminal result for an issued transaction without mutations.
     *
     * @param transactionId active store-bound transaction with no mutation frames
     * @param failureCode positive stable terminal failure code
     * @return retained noncommitted terminal result after the durability barrier
     * @throws NullPointerException if a required input is null
     * @throws IllegalStateException if this log is closed
     * @throws IllegalArgumentException if identity, active mutation state or failure code is invalid
     * @throws IOException if writer authority or terminal append durability fails
     */
    /* default */ DurableMetadataLogScanner.Terminal reject(
            MetadataTransactionId transactionId, int failureCode) throws IOException {
        operationLock.lock();
        try {
            requireOperational();
            ActiveTransaction transaction = requireActive(transactionId);
            if (transaction.nextSequence != FIRST_TRANSACTION_SEQUENCE || activeBatch != null) {
                throw new IllegalArgumentException(
                        "Rejected Durable metadata transaction must contain no mutation frames");
            }
            byte[] payload = DurableMetadataLogScanner.encodeRejected(
                    transactionId, failureCode, transaction.chainState);
            DurableMetadataLogScanner.Terminal result = new DurableMetadataLogScanner.Terminal(
                    DurableMetadataLogScanner.TerminalKind.NOT_COMMITTED,
                    java.util.OptionalLong.empty(), java.util.OptionalInt.of(failureCode));
            return appendTerminal(transactionId, transaction,
                    MetadataFrameCodec.FrameType.TERMINAL_NOT_COMMITTED, payload, result);
        } finally {
            operationLock.unlock();
        }
    }

    /**
     * Counts issued transactions that do not yet have a retained terminal outcome.
     *
     * @return current active transaction count under the log operation lock
     * @throws IllegalStateException if this log is closed
     * @throws IOException if the retained writer lock is no longer valid
     */
    /* default */ int activeTransactionCount() throws IOException {
        operationLock.lock();
        try {
            requireOpenAuthority();
            return active.size();
        } finally {
            operationLock.unlock();
        }
    }

    /**
     * Validates and scans the complete log while holding exact open writer authority.
     *
     * @return immutable recovery facts including complete-prefix and incomplete-tail classification
     * @throws IllegalStateException if this log is closed
     * @throws IOException if writer authority, structural framing or semantic integrity fails
     */
    /* default */ DurableMetadataLogScanner.RecoveryResult scan() throws IOException {
        operationLock.lock();
        try {
            requireOpenAuthority();
            return DurableMetadataLogScanner.scan(channel);
        } finally {
            operationLock.unlock();
        }
    }

    private DurableMetadataLogScanner.Terminal appendTerminal(
            MetadataTransactionId transactionId,
            ActiveTransaction transaction,
            MetadataFrameCodec.FrameType type,
            byte[] payload,
            DurableMetadataLogScanner.Terminal result) throws IOException {
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
                DurableMetadataLogScanner.zeroToken(),
                STORE_HEADER_SEQUENCE,
                DurableMetadataLogScanner.encodeStoreHeader(storeId));
        forceFile();
    }

    private void appendRecoveryRestart(long abandonedOpenCount, long truncatedByteCount)
            throws IOException {
        long nextEpoch = checkedWritableRecoveryEpoch(recoveryEpoch);
        trip(FaultPoint.RECOVERY_RESTART_APPEND);
        appendBounded(
                MetadataFrameCodec.FrameType.RECOVERY_RESTART,
                DurableMetadataLogScanner.zeroToken(),
                nextEpoch,
                DurableMetadataLogScanner.encodeRestart(
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
            throw new IllegalArgumentException("Durable metadata transaction is not active in this log instance");
        }
        return transaction;
    }

    private void requireBatch(MetadataTransactionId transactionId) {
        if (activeBatch == null) {
            activeBatch = transactionId;
        } else if (!activeBatch.equals(transactionId)) {
            throw new IllegalArgumentException("Durable metadata mutation batches cannot interleave");
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
            throw new IllegalArgumentException("Durable metadata terminal does not own the active batch");
        }
    }

    private void requireAuthority(MetadataTransactionId transactionId) {
        Objects.requireNonNull(transactionId, "transactionId");
        if (!storeId.equals(transactionId.storeId())) {
            throw new IllegalArgumentException("Durable metadata transaction belongs to another store");
        }
    }

    private static void requireMutationType(MetadataFrameCodec.FrameType type) {
        Objects.requireNonNull(type, "type");
        if (type != MetadataFrameCodec.FrameType.MUTATION_CREATE
                && type != MetadataFrameCodec.FrameType.MUTATION_REPLACE
                && type != MetadataFrameCodec.FrameType.MUTATION_DELETE) {
            throw new IllegalArgumentException("Durable metadata log requires an opaque mutation frame type");
        }
    }

    private void requireOperational() throws IOException {
        requireOpenAuthority();
        if (state == State.RECOVERY_REQUIRED) {
            throw new IOException("Durable metadata log requires close and recovery");
        }
    }

    private void requireOpenAuthority() throws IOException {
        if (state == State.CLOSED || !channel.isOpen()) {
            throw new IllegalStateException("Durable metadata log is closed");
        }
        // The retained lock is the sole writer authority for this log instance.
        if (!writerLock.isValid()) {
            state = State.RECOVERY_REQUIRED;
            throw new IOException("Durable metadata log writer authority is invalid");
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

    /**
     * {@inheritDoc}
     */
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

    /**
     * Isolates create/reopen branching from the retained writer authority.
     */
    private static final class Lifecycle {
        private static DurableMetadataLog create(
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
                DurableMetadataLog log = new DurableMetadataLog(
                        resources.channel, resources.writerLock, storeId,
                        DurableMetadataLogScanner.TransactionCounter.first(), 0L, faults);
                log.warnIfLimited(!posix || !local);
                log.appendStoreHeader();
                forceParent(capabilities, parent, log);
                return log;
            } catch (IOException failure) {
                resources.closeAfterFailure(failure);
                throw failure;
            }
        }

        private static DurableMetadataLog open(
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
                DurableMetadataLogScanner.RecoveryResult recovered =
                        DurableMetadataLogScanner.scan(resources.channel);
                long removed = Math.subtractExact(
                        recovered.physicalEnd(), recovered.lastCompleteFrameBoundary());
                recovered = repair(resources.channel, recovered, faults);
                DurableMetadataLog log = recoveredLog(resources, recovered, faults);
                log.warnIfLimited(!posix || !local);
                log.appendRecoveryRestart(recovered.openTransactionCount(), removed);
                reportRestart(recovered.openTransactionCount(), removed);
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
                DurableMetadataLogScanner.ReplayResult recovered =
                        DurableMetadataLogScanner.replay(resources.channel);
                long removed = Math.subtractExact(
                        recovered.physicalEnd(), recovered.lastCompleteFrameBoundary());
                recovered = repair(resources.channel, recovered, faults);
                DurableMetadataLog log = recoveredLog(resources, recovered, faults);
                log.warnIfLimited(!posix || !local);
                resources.channel.position(recovered.lastCompleteFrameBoundary());
                log.appendRecoveryRestart(recovered.openTransactionCount(), removed);
                reportRestart(recovered.openTransactionCount(), removed);
                return new EngineOpen(
                        log,
                        recovered.stateIndex(),
                        mergeRestartOutcomes(recovered.outcomes(), recovered.restartOutcomes()));
            } catch (IOException failure) {
                resources.closeAfterFailure(failure);
                throw failure;
            }
        }

        private static DurableMetadataLog recoveredLog(
                Resources resources,
                DurableMetadataLogScanner.RecoveryResult recovered,
                FaultInjector faults) {
            return new DurableMetadataLog(
                    resources.channel, resources.writerLock, recovered.storeId(),
                    DurableMetadataLogScanner.TransactionCounter.recovered(
                            recovered.nextTransactionToken(), recovered.transactionTokensExhausted()),
                    recovered.recoveryEpoch(), faults);
        }

        private static DurableMetadataLog recoveredLog(
                Resources resources,
                DurableMetadataLogScanner.ReplayResult recovered,
                FaultInjector faults) {
            return new DurableMetadataLog(
                    resources.channel, resources.writerLock, recovered.storeId(),
                    DurableMetadataLogScanner.TransactionCounter.recovered(
                            recovered.nextTransactionToken(), recovered.transactionTokensExhausted()),
                    recovered.recoveryEpoch(), faults);
        }

        private static DurableMetadataLogScanner.RecoveryResult repair(
                FileChannel channel,
                DurableMetadataLogScanner.RecoveryResult recovered,
                FaultInjector faults) throws IOException {
            if (recovered.tail() == DurableMetadataLogScanner.Tail.INCOMPLETE_TAIL) {
                return TailRepair.repair(channel, recovered, faults);
            }
            return recovered;
        }

        private static DurableMetadataLogScanner.ReplayResult repair(
                FileChannel channel,
                DurableMetadataLogScanner.ReplayResult recovered,
                FaultInjector faults) throws IOException {
            if (recovered.tail() == DurableMetadataLogScanner.Tail.INCOMPLETE_TAIL) {
                return TailRepair.repair(channel, recovered, faults);
            }
            return recovered;
        }

        private static Map<MetadataTransactionId, DurableMetadataLogScanner.Terminal>
                mergeRestartOutcomes(
                        Map<MetadataTransactionId, DurableMetadataLogScanner.Terminal> outcomes,
                        Map<MetadataTransactionId, DurableMetadataLogScanner.Terminal> restartOutcomes) {
            Map<MetadataTransactionId, DurableMetadataLogScanner.Terminal> merged =
                    new HashMap<>(outcomes);
            merged.putAll(restartOutcomes);
            return Map.copyOf(merged);
        }

        private static void forceParent(
                CapabilityProfile capabilities,
                Path parent,
                DurableMetadataLog log) {
            try {
                capabilities.forceParent(parent);
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
                        "Durable metadata recovery epoch is exhausted");
            }
            return DurableMetadataLogScanner.checkedNextRecoveryEpoch(currentEpoch);
        }
    }

    /**
     * O(1) repair of one scanner-authenticated incomplete final tail.
     */
    private static final class TailRepair {
        private static DurableMetadataLogScanner.RecoveryResult repair(
                FileChannel channel,
                DurableMetadataLogScanner.RecoveryResult before,
                FaultInjector faults) throws IOException {
            truncateAndVerify(channel, before.lastCompleteFrameBoundary(), faults);
            return new DurableMetadataLogScanner.RecoveryResult(
                    before.storeId(),
                    before.lastCompleteFrameBoundary(),
                    before.lastCompleteFrameBoundary(),
                    DurableMetadataLogScanner.Tail.CLEAN_END,
                    before.transactions(),
                    before.nextTransactionToken(),
                    before.transactionTokensExhausted(),
                    before.recoveryEpoch(),
                    before.openTransactionCount());
        }

        private static DurableMetadataLogScanner.ReplayResult repair(
                FileChannel channel,
                DurableMetadataLogScanner.ReplayResult before,
                FaultInjector faults) throws IOException {
            truncateAndVerify(channel, before.lastCompleteFrameBoundary(), faults);
            return new DurableMetadataLogScanner.ReplayResult(
                    before.storeId(),
                    before.lastCompleteFrameBoundary(),
                    before.lastCompleteFrameBoundary(),
                    DurableMetadataLogScanner.Tail.CLEAN_END,
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
                        "Durable metadata log tail repair verification failed");
            }
            channel.position(boundary);
        }
    }

    /**
     * Live lifecycle of one retained metadata-log writer authority.
     */
    private enum State {
        OPEN,
        RECOVERY_REQUIRED,
        CLOSED
    }

    /**
     * O(1) live control state for one transaction.
     */
    private static final class ActiveTransaction {
        private byte[] chainState;
        private long nextSequence = FIRST_TRANSACTION_SEQUENCE;

        private ActiveTransaction(byte[] chainState) {
            this.chainState = chainState;
        }
    }

    /**
     * Caller-visible uncertainty requiring strict scanner classification.
     */
    /* default */ static final class OutcomeUnknownException extends IOException {
        private static final long serialVersionUID = -4335785072683425908L;

        private OutcomeUnknownException(IOException cause) {
            super("Durable metadata transaction terminal outcome requires recovery", cause);
        }
    }

    /**
     * Deterministic package-private fault boundaries.
     */
    /* default */ enum FaultPoint {
        /**
         * Fault injection point for appending a transaction issuance record.
         */
        ISSUANCE_APPEND,
        /**
         * Fault injection point for appending a mutation record.
         */
        MUTATION_APPEND,
        /**
         * Fault injection point for appending a transaction terminal record.
         */
        TERMINAL_APPEND,
        /**
         * Fault injection point for forcing file data and metadata.
         */
        FILE_FORCE,
        /**
         * Fault injection point for the uncertainty boundary after the file force.
         */
        POST_FORCE_UNCERTAINTY,
        /**
         * Fault injection point for truncating an incomplete uncommitted tail.
         */
        TAIL_TRUNCATE,
        /**
         * Fault injection point for forcing the repaired tail.
         */
        TAIL_FORCE,
        /**
         * Fault injection point for verifying a repaired tail.
         */
        TAIL_VERIFY,
        /**
         * Fault injection point for appending the recovery restart marker.
         */
        RECOVERY_RESTART_APPEND
    }

    /**
     * Package-private deterministic fault injector; it is not a production extension point.
     */
    /* default */
    @FunctionalInterface
    interface FaultInjector {
        /**
         * No-op injector that never introduces a synthetic failure.
         */
        FaultInjector NONE = point -> { };

        /**
         * Fails one selected append or durability boundary.
         * @param point exact deterministic failure boundary being observed
         * @throws IOException to inject a deterministic failure at the selected persistence boundary
         */
        void fail(FaultPoint point) throws IOException;
    }

    /**
     * Predicted immutable frame location used before one serialized append batch.
     * @param payloadOffset zero-based byte offset of the frame payload
     * @param frameEndOffset exclusive byte offset immediately after the frame
     */
    /* default */ record MutationLocation(long payloadOffset, long frameEndOffset) {
    }

    /**
     * One-scan engine opening result retaining the reconstructed current state.
     * @param log opened durable metadata log; resource ownership transfers with the opening result
     * @param stateIndex reconstructed current-state index
     * @param outcomes retained terminal outcomes keyed by exact transaction identity
     */
    /* default */ record EngineOpen(
            DurableMetadataLog log,
            MetadataStateIndex stateIndex,
            Map<MetadataTransactionId, DurableMetadataLogScanner.Terminal> outcomes) {
        /**
         * Creates the one-scan engine opening result retaining the reconstructed current state.
         *
         * @param log opened durable metadata log; resource ownership transfers with the opening result
         * @param stateIndex reconstructed current-state index
         * @param outcomes retained terminal outcomes keyed by exact transaction identity
         * @throws NullPointerException if {@code log} is null; or if {@code stateIndex} is null
         */
        EngineOpen {
            Objects.requireNonNull(log, "log");
            Objects.requireNonNull(stateIndex, "stateIndex");
            outcomes = Map.copyOf(outcomes);
        }
    }

    /**
     * Package-private capability seam used to verify fail-closed initialization behavior.
     */
    /* default */
    interface CapabilityProfile {
        /**
         * Reports whether owner-only POSIX creation attributes are supported.
         * @param parent existing parent directory whose filesystem capabilities are inspected
         * @return true when POSIX attribute support is available for the directory
         * @throws IOException if filesystem capabilities cannot be inspected
         */
        boolean posixAvailable(Path parent) throws IOException;

        /**
         * Reports whether the filesystem is recognized as local.
         * @param parent existing parent directory whose filesystem capabilities are inspected
         * @return true when the directory resides on an accepted local filesystem
         * @throws IOException if filesystem capabilities cannot be inspected
         */
        boolean localFileSystem(Path parent) throws IOException;

        /**
         * Forces the metadata log's parent-directory entry updates durable.
         *
         * <p>
         * On POSIX this is a directory {@code fsync}; on platforms that carry
         * directory durability through the write-through atomic publish it is a
         * correct no-op. The platform-appropriate behaviour is resolved by
         * {@link PlatformFs#forceDirectory(Path)}.
         * </p>
         *
         * @param parent the metadata log's existing parent directory
         * @throws IOException on a genuine directory durability failure
         */
        void forceParent(Path parent) throws IOException;
    }

    /**
     * Default capability observations for the active Java filesystem provider.
     */
    private enum DefaultCapabilityProfile implements CapabilityProfile {
        INSTANCE;

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean posixAvailable(Path parent) throws IOException {
            return Files.getFileStore(parent).supportsFileAttributeView("posix");
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean localFileSystem(Path parent) throws IOException {
            String type = Files.getFileStore(parent).type().toLowerCase(Locale.ROOT);
            return LOCAL_FILE_SYSTEMS.contains(type);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void forceParent(Path parent) throws IOException {
            PlatformFs.forceDirectory(parent);
        }
    }

    /**
     * Secure descriptor-relative opening for the trusted store directory profile.
     */
    private static final class SecureFiles {

        private static Path requireParent(Path logPath) throws IOException {
            Objects.requireNonNull(logPath, "logPath");
            Path parent = logPath.getParent();
            if (parent == null || logPath.getFileName() == null
                    || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)
                    || Files.isSymbolicLink(parent)) {
                throw new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE,
                        "Durable metadata log target has no trusted regular parent directory");
            }
            return parent;
        }

        private static FileChannel fileChannel(SeekableByteChannel selected) throws IOException {
            if (selected instanceof FileChannel) {
                return (FileChannel) selected;
            }
            selected.close();
            throw new MetadataStoreException(
                    MetadataCommitResult.FailureCategory.UNSUPPORTED_CAPABILITY,
                    "Durable metadata file forcing is unavailable");
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
                DurableDirectory directory, Path name, boolean create) throws IOException {
            if (create) {
                return;
            }
            BasicFileAttributeView view = directory.getFileAttributeView(
                    name, BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            BasicFileAttributes attributes = view.readAttributes();
            if (!attributes.isRegularFile() || attributes.isSymbolicLink()) {
                throw new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE,
                        "Durable metadata log entry is not a regular file");
            }
        }
    }

    /**
     * Owns initialization anchors and transfers only the retained log authority.
     */
    private static final class Resources {
        private FileChannel channel;
        private FileLock writerLock;

        private static Resources acquire(Path logPath, boolean create, boolean posix) throws IOException {
            Resources resources = new Resources();
            try {
                Path parent = SecureFiles.requireParent(logPath);
                Path name = logPath.getFileName();
                // On POSIX the log channel is opened relative to a secure
                // directory descriptor (race-safe); on filesystems without a
                // SecureDirectoryStream it is opened by resolving the name, with
                // NOFOLLOW_LINKS and the owner-only parent directory as the
                // protection boundary.
                try (DurableDirectory directory = DurableDirectory.open(parent)) {
                    SecureFiles.requireRegularEntry(directory, name, create);
                    resources.channel = SecureFiles.fileChannel(directory.newByteChannel(
                            name, SecureFiles.logOptions(create), SecureFiles.attributes(posix)));
                }
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
                lock = WriterExclusionLock.tryAcquire(channel);
            } catch (OverlappingFileLockException contention) {
                throw new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.STORAGE_FAILURE,
                        "Durable metadata log exclusive writer authority is unavailable", contention);
            }
            if (lock == null) {
                throw new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.STORAGE_FAILURE,
                        "Durable metadata log exclusive writer authority is unavailable");
            }
            return lock;
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
            return failure;
        }
    }
}
