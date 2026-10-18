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
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.BooleanSupplier;

/**
 * Package-owned active signing WAL and bounded single-writer group committer.
 *
 * <p>Submission copies the payload exactly once. Cancellation of the returned
 * acknowledgement does not cancel or reuse an admitted durable mutation. The
 * writer assigns consecutive sequences and revisions in admission order; no
 * caller-supplied revision can introduce a gap.</p>
 */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.AvoidInstantiatingObjectsInLoops",
        "PMD.AvoidLiteralsInIfCondition", "PMD.AvoidMessageDigestField", "PMD.AvoidSynchronizedStatement",
        "PMD.AvoidUsingVolatile", "PMD.CommentDefaultAccessModifier", "PMD.CommentRequired",
        "PMD.CloseResource", "PMD.CompareObjectsWithEquals", "PMD.ConfusingTernary",
        "PMD.CyclomaticComplexity", "PMD.DoNotUseThreads", "PMD.ExceptionAsFlowControl",
        "PMD.PreserveStackTrace" })
final class SigningActiveWal implements AutoCloseable {

    /* default */ static final int MAXIMUM_QUEUE_CAPACITY = 256;
    /* A large transaction remains admissible, while one force never owns a 64 MiB group. */
    /* default */ static final int MAXIMUM_BATCH_BYTES = 8 * 1024 * 1024;
    private static final long MAXIMUM_QUEUED_PAYLOAD_BYTES = 64L * 1024L * 1024L;
    private static final long MAXIMUM_WAIT_NANOS = Duration.ofMillis(2L).toNanos();
    private static final Operations SYSTEM_OPERATIONS = new SystemOperations();
    private static final NanoClock SYSTEM_CLOCK = System::nanoTime;
    private static final GroupWaitStrategy SYSTEM_WAIT = TimeUnit.NANOSECONDS::timedWait;
    private static final RecoveryOpenFaultInjector NO_RECOVERY_OPEN_FAULT = (stage, channel) -> { };

    private final Object lock = new Object();
    private final Configuration configuration;
    private final Descriptor descriptor;
    private final WalChannel channel;
    private final NanoClock clock;
    private final GroupWaitStrategy waitStrategy;
    private final Deque<Pending> queue;
    private final Thread writerThread;
    private final LongAdder committedGroups = new LongAdder();
    private final LongAdder committedRequests = new LongAdder();
    private final LongAdder forces = new LongAdder();
    private final LongAdder rejected = new LongAdder();
    private final LongAdder uncertain = new LongAdder();
    private final LongAdder bytesAppended = new LongAdder();
    private final LongAdder batchWaitNanos = new LongAdder();
    private final LongAdder writeNanos = new LongAdder();
    private final LongAdder forceNanos = new LongAdder();
    private final AtomicLong maximumBatchSize = new AtomicLong();
    private final AtomicLong maximumBatchWaitNanos = new AtomicLong();
    private final AtomicLong maximumWriteNanos = new AtomicLong();
    private final AtomicLong maximumForceNanos = new AtomicLong();

    private volatile State state = State.PASSIVE;
    private volatile IOException lifecycleFailure;
    private boolean writerStarted;
    private int outstandingSlots;
    private long outstandingPayloadBytes;
    private long outstandingEncodedBytes;
    private long position;
    private long lastCommittedSequence;
    private long lastCommittedRevision;
    private long lastReservedSequence;
    private long lastReservedRevision;
    private boolean frameReservationActive;
    private byte[] rollingCommitment;
    private final byte[] baselineCommitment;
    private volatile ForcedEnd forcedEnd;
    private final MessageDigest fileCommitment;
    private ByteBuffer aggregateWriteBuffer;

    private SigningActiveWal(Descriptor descriptor, Configuration configuration, WalChannel channel,
            RestoredState restored, NanoClock clock, GroupWaitStrategy waitStrategy) {
        this.descriptor = descriptor;
        this.configuration = configuration;
        this.channel = channel;
        this.clock = clock;
        this.waitStrategy = waitStrategy;
        this.queue = new ArrayDeque<>(configuration.queueCapacity());
        this.position = restored.position();
        this.lastCommittedSequence = restored.lastCommittedSequence();
        this.lastCommittedRevision = restored.lastCommittedRevision();
        this.lastReservedSequence = restored.lastCommittedSequence();
        this.lastReservedRevision = restored.lastCommittedRevision();
        this.rollingCommitment = restored.rollingCommitment();
        this.baselineCommitment = SigningFormatSupport.sha256().digest(
                SigningWalContainerCodec.encode(descriptor.header()));
        this.forcedEnd = new ForcedEnd(restored.position(), restored.lastCommittedSequence(),
                restored.lastCommittedRevision(), restored.rollingCommitment());
        this.fileCommitment = restored.fileCommitment();
        writerThread = new Thread(this::runWriter, "zeroecho-signing-wal-writer");
        writerThread.setDaemon(true);
    }

    /* default */ static SigningActiveWal open(Path path, Descriptor descriptor,
            Configuration configuration) throws IOException {
        return open(path, descriptor, configuration, SYSTEM_OPERATIONS, SYSTEM_CLOCK, SYSTEM_WAIT);
    }

    /** Opens a read-only validated WAL state, repairing only its proven suffix. */
    /* default */ static SigningActiveWal reopenValidated(Path path, Descriptor descriptor,
            Configuration configuration, ValidatedState validated) throws IOException {
        SigningActiveWal result = reopenValidatedPassive(path, descriptor, configuration,
                validated, SYSTEM_OPERATIONS, SYSTEM_CLOCK, SYSTEM_WAIT);
        return startAfterOpen(result);
    }

    /* default */ static SigningActiveWal reopenValidated(Path path, Descriptor descriptor,
            Configuration configuration, ValidatedState validated, Operations operations,
            NanoClock clock, GroupWaitStrategy waitStrategy) throws IOException {
        SigningActiveWal result = reopenValidatedPassive(path, descriptor, configuration,
                validated, operations, clock, waitStrategy);
        return startAfterOpen(result);
    }

    /** Opens and repairs a validated WAL without starting its writer. */
    /* default */ static SigningActiveWal reopenValidatedPassive(Path path,
            Descriptor descriptor, Configuration configuration, ValidatedState validated,
            Operations operations, NanoClock clock, GroupWaitStrategy waitStrategy)
            throws IOException {
        return reopenValidatedPassive(path, descriptor, configuration, validated, operations,
                clock, waitStrategy, NO_RECOVERY_OPEN_FAULT);
    }

    /* default */ static SigningActiveWal reopenValidatedPassive(Path path,
            Descriptor descriptor, Configuration configuration, ValidatedState validated,
            Operations operations, NanoClock clock, GroupWaitStrategy waitStrategy,
            RecoveryOpenFaultInjector faults) throws IOException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(descriptor, "descriptor");
        Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(validated, "validated");
        Objects.requireNonNull(operations, "operations");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(waitStrategy, "waitStrategy");
        Objects.requireNonNull(faults, "faults");
        WalChannel opened = null;
        try {
            if (!operations.exists(path) || !operations.isRegularFile(path)) {
                throw new IOException("signing active WAL validated identity is unavailable");
            }
            opened = operations.openExisting(path);
            faults.after(RecoveryOpenStage.AFTER_PASSIVE_WAL_OPEN, opened);
            if (opened.size() != validated.observedLength()) {
                throw new IOException("signing active WAL changed after validation");
            }
            opened.position(0L);
            ByteBuffer headerBytes = ByteBuffer.allocate(SigningWalContainerCodec.HEADER_BYTES);
            SigningFormatSupport.readFully(opened, headerBytes,
                    "signing active WAL container is truncated");
            SigningWalContainerCodec.Header header;
            try {
                header = SigningWalContainerCodec.decode(headerBytes.array());
            } catch (IOException malformed) {
                throw new MalformedRecoveryDataException();
            }
            if (!descriptor.header().equals(header)) {
                throw new MalformedRecoveryDataException();
            }
            if (validated.position() < SigningWalContainerCodec.HEADER_BYTES
                    || validated.position() > validated.observedLength()) {
                throw new IOException("signing active WAL validated boundary is invalid");
            }
            if (validated.position() != validated.observedLength()) {
                try {
                    opened.truncate(validated.position());
                    opened.force(true);
                } catch (IOException failure) {
                    throw new RecoveryRequiredException(
                            "signing active WAL tail repair durability is uncertain", failure);
                }
            }
            faults.after(RecoveryOpenStage.AFTER_TAIL_REPAIR, opened);
            MessageDigest fileCommitment = digestPrefix(opened, validated.position());
            opened.position(validated.position());
            RestoredState restored = new RestoredState(validated.position(),
                    validated.lastCommittedSequence(), validated.lastCommittedRevision(),
                    validated.rollingCommitment(), fileCommitment);
            return new SigningActiveWal(descriptor, configuration, opened, restored,
                    clock, waitStrategy);
        } catch (IOException | RuntimeException failure) {
            closeAfterOpenFailure(opened, failure);
            throw failure;
        }
    }

    /* default */ static SigningActiveWal open(Path path, Descriptor descriptor,
            Configuration configuration, Operations operations, NanoClock clock,
            GroupWaitStrategy waitStrategy) throws IOException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(descriptor, "descriptor");
        Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(operations, "operations");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(waitStrategy, "waitStrategy");
        Path parent = path.getParent();
        if (parent == null || path.getFileName() == null
                || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(parent)) {
            throw new IllegalArgumentException("signing active WAL directory is invalid");
        }
        WalChannel opened = null;
        try {
            boolean exists = operations.exists(path);
            if (exists && !operations.isRegularFile(path)) {
                throw new IOException("signing active WAL is not a regular file");
            }
            opened = exists ? operations.openExisting(path) : operations.createNew(path);
            RestoredState restored;
            if (exists) {
                restored = restore(opened, descriptor);
            } else {
                restored = initialize(opened, parent, descriptor, operations);
            }
            SigningActiveWal result = new SigningActiveWal(descriptor, configuration, opened,
                    restored, clock, waitStrategy);
            return startAfterOpen(result);
        } catch (IOException | RuntimeException failure) {
            closeAfterOpenFailure(opened, failure);
            throw failure;
        }
    }

    private static SigningActiveWal startAfterOpen(SigningActiveWal wal) throws IOException {
        try {
            wal.startWriter();
            return wal;
        } catch (RuntimeException failure) {
            try {
                wal.close();
            } catch (IOException closeFailure) {
                failure.addSuppressed(closeFailure);
            }
            throw failure;
        }
    }

    /** Starts the single writer exactly once after recovery validation completes. */
    /* default */ void startWriter() {
        synchronized (lock) {
            if (state != State.PASSIVE || writerStarted || outstandingSlots != 0
                    || frameReservationActive || !queue.isEmpty()) {
                throw new IllegalStateException("signing active WAL writer start is invalid");
            }
            writerStarted = true;
            state = State.OPEN;
            try {
                writerThread.start();
            } catch (RuntimeException failure) {
                state = State.RECOVERY_REQUIRED;
                try {
                    channel.close();
                } catch (IOException closeFailure) {
                    failure.addSuppressed(closeFailure);
                }
                throw failure;
            }
        }
    }

    private static RestoredState initialize(WalChannel channel, Path parent,
            Descriptor descriptor, Operations operations) throws IOException {
        byte[] header = SigningWalContainerCodec.encode(descriptor.header());
        try {
            SigningFormatSupport.writeFully(channel, ByteBuffer.wrap(header));
            channel.force(true);
            operations.forceDirectory(parent);
        } catch (IOException failure) {
            throw new RecoveryRequiredException(
                    "signing active WAL creation durability is uncertain", failure);
        }
        MessageDigest fileCommitment = SigningFormatSupport.sha256();
        fileCommitment.update(header);
        return new RestoredState(SigningWalContainerCodec.HEADER_BYTES,
                predecessor(descriptor.firstSequence()), descriptor.baselineRevision(),
                SigningFormatSupport.sha256().digest(header), fileCommitment);
    }

    private static RestoredState restore(WalChannel channel, Descriptor descriptor)
            throws IOException {
        channel.position(0L);
        ByteBuffer headerBytes = ByteBuffer.allocate(SigningWalContainerCodec.HEADER_BYTES);
        SigningFormatSupport.readFully(channel, headerBytes,
                "signing active WAL container is truncated");
        SigningWalContainerCodec.Header actual = SigningWalContainerCodec.decode(headerBytes.array());
        if (!descriptor.header().equals(actual)) {
            throw new IOException("signing active WAL descriptor is inconsistent");
        }
        SigningWalFrameCodec.ScanResult scan = SigningWalFrameCodec.scanGroups(channel,
                descriptor.firstSequence(), true, (frames, marker) -> { }, true);
        long restoredPosition = channel.size();
        if (scan.hasIncompleteTail()) {
            restoredPosition = scan.incompleteTailOffset();
            try {
                channel.truncate(restoredPosition);
                channel.force(true);
            } catch (IOException failure) {
                throw new RecoveryRequiredException(
                        "signing active WAL tail repair durability is uncertain", failure);
            }
        }
        channel.position(restoredPosition);
        long lastSequence = scan.frameCount() == 0L
                ? predecessor(descriptor.firstSequence()) : scan.lastSequence();
        MessageDigest fileCommitment = SigningFormatSupport.sha256();
        channel.position(0L);
        byte[] transfer = new byte[SigningFormatSupport.TRANSFER_BYTES];
        ByteBuffer input = ByteBuffer.wrap(transfer);
        while (channel.position() < restoredPosition) {
            input.clear();
            input.limit((int) Math.min(input.capacity(), restoredPosition - channel.position()));
            int count = channel.read(input);
            if (count <= 0) {
                throw new IOException("signing active WAL commitment read made no progress");
            }
            fileCommitment.update(transfer, 0, count);
        }
        channel.position(restoredPosition);
        return new RestoredState(restoredPosition, lastSequence,
                scan.committedRevision(), scan.rollingCommitment(), fileCommitment);
    }

    private static void closeAfterOpenFailure(WalChannel channel, Throwable failure) {
        if (channel != null) {
            try {
                channel.close();
            } catch (IOException closeFailure) {
                failure.addSuppressed(closeFailure);
            }
        }
    }

    private static MessageDigest digestPrefix(SeekableByteChannel channel, long length)
            throws IOException {
        MessageDigest result = SigningFormatSupport.sha256();
        channel.position(0L);
        byte[] transfer = new byte[SigningFormatSupport.TRANSFER_BYTES];
        ByteBuffer input = ByteBuffer.wrap(transfer);
        while (channel.position() < length) {
            input.clear();
            input.limit((int) Math.min(input.capacity(), length - channel.position()));
            int count = channel.read(input);
            if (count <= 0) {
                throw new IOException("signing active WAL commitment read made no progress");
            }
            result.update(transfer, 0, count);
        }
        return result;
    }

    /* default */ Acknowledgement submit(SigningWalFrameCodec.RecordType recordType,
            UUID transactionId, byte[] payload) {
        Objects.requireNonNull(recordType, "recordType");
        Objects.requireNonNull(transactionId, "transactionId");
        Objects.requireNonNull(payload, "payload");
        if (recordType == SigningWalFrameCodec.RecordType.BATCH_COMMIT
                || payload.length > SigningWalFrameCodec.MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("signing WAL request fields are invalid");
        }
        reserveAdmission(payload.length);
        byte[] ownedPayload;
        Acknowledgement acknowledgement = new Acknowledgement();
        try {
            ownedPayload = configuration.payloadCopier().copy(payload);
            if (Objects.equals(ownedPayload, payload) || ownedPayload.length != payload.length) {
                throw new IllegalStateException("signing WAL payload copy is invalid");
            }
        } catch (RuntimeException | Error failure) {
            rollbackReservation(payload.length);
            throw failure;
        }
        synchronized (lock) {
            if (state != State.OPEN || frameReservationActive) {
                releaseOutstanding(payload.length);
                rejected.increment();
                throw new UnavailableException();
            }
            long sequence;
            long revision;
            try {
                sequence = Math.incrementExact(lastReservedSequence);
                revision = Math.incrementExact(lastReservedRevision);
            } catch (ArithmeticException exhausted) {
                releaseOutstanding(payload.length);
                acknowledgement.completeExceptionally(new ValidationException(exhausted));
                return acknowledgement;
            }
            lastReservedSequence = sequence;
            lastReservedRevision = revision;
            queue.addLast(new Pending(recordType, transactionId, ownedPayload, acknowledgement,
                    clock.nanoTime(), sequence, revision, new SigningRecordPointerSlot()));
            lock.notifyAll();
            return acknowledgement;
        }
    }

    /** Appends and forces one deterministic recovery record before the writer starts. */
    /* default */ CommitResult appendRecovery(SigningWalFrameCodec.RecordType recordType,
            UUID transactionId, byte[] payload) throws IOException {
        Objects.requireNonNull(recordType, "recordType");
        Objects.requireNonNull(transactionId, "transactionId");
        Objects.requireNonNull(payload, "payload");
        if (recordType == SigningWalFrameCodec.RecordType.BATCH_COMMIT
                || payload.length > SigningWalFrameCodec.MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("signing WAL recovery fields are invalid");
        }
        Pending pending;
        synchronized (lock) {
            if (state != State.PASSIVE || writerStarted || frameReservationActive
                    || outstandingSlots != 0 || !queue.isEmpty()) {
                throw new IllegalStateException("signing WAL recovery append is invalid");
            }
            long encodedBytes = encodedReservationBytes(payload.length);
            if (payload.length > configuration.maximumQueuedPayloadBytes()
                    || encodedBytes > configuration.maximumBatchBytes()
                    || Math.addExact(position, encodedBytes)
                            > configuration.maximumSegmentBytes()) {
                throw new RotationRequiredException();
            }
            byte[] ownedPayload = configuration.payloadCopier().copy(payload);
            if (ownedPayload == payload || ownedPayload.length != payload.length) {
                throw new IllegalStateException("signing WAL payload copy is invalid");
            }
            long sequence = Math.incrementExact(lastReservedSequence);
            long revision = Math.incrementExact(lastReservedRevision);
            outstandingSlots = 1;
            outstandingPayloadBytes = payload.length;
            outstandingEncodedBytes = encodedBytes;
            lastReservedSequence = sequence;
            lastReservedRevision = revision;
            pending = new Pending(recordType, transactionId, ownedPayload,
                    new Acknowledgement(), clock.nanoTime(), sequence, revision,
                    new SigningRecordPointerSlot());
        }
        commit(new Batch(List.of(pending)));
        try {
            return pending.acknowledgement().get();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IOException("signing WAL recovery append was interrupted", interrupted);
        } catch (ExecutionException failed) {
            Throwable cause = failed.getCause();
            synchronized (lock) {
                if (state == State.PASSIVE) {
                    state = State.RECOVERY_REQUIRED;
                    lifecycleFailure = new RecoveryRequiredException(
                            "signing active WAL recovery append failed", cause);
                }
            }
            if (cause instanceof IOException ioFailure) {
                throw ioFailure;
            }
            if (cause instanceof RuntimeException runtimeFailure) {
                throw runtimeFailure;
            }
            throw new IOException("signing WAL recovery append failed", cause);
        }
    }

    /* default */ FrameReservation reserve(SigningWalFrameCodec.RecordType recordType,
            UUID transactionId, byte[] payload) {
        Objects.requireNonNull(recordType, "recordType");
        Objects.requireNonNull(transactionId, "transactionId");
        Objects.requireNonNull(payload, "payload");
        if (recordType == SigningWalFrameCodec.RecordType.BATCH_COMMIT
                || payload.length > SigningWalFrameCodec.MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("signing WAL request fields are invalid");
        }
        if (state != State.OPEN) {
            rejected.increment();
            throw new UnavailableException();
        }
        synchronized (lock) {
            if (frameReservationActive) {
                throw new OverloadedException();
            }
            frameReservationActive = true;
        }
        try {
            reserveAdmission(payload.length);
        } catch (RuntimeException failure) {
            synchronized (lock) { frameReservationActive = false; lock.notifyAll(); }
            throw failure;
        }
        byte[] ownedPayload;
        Acknowledgement acknowledgement;
        try {
            ownedPayload = configuration.payloadCopier().copy(payload);
            if (Objects.equals(ownedPayload, payload) || ownedPayload.length != payload.length) {
                throw new IllegalStateException("signing WAL payload copy is invalid");
            }
            acknowledgement = new Acknowledgement();
        } catch (RuntimeException | Error failure) {
            rollbackReservation(payload.length);
            synchronized (lock) { frameReservationActive = false; lock.notifyAll(); }
            throw failure;
        }
        synchronized (lock) {
            if (state != State.OPEN) {
                releaseOutstanding(payload.length);
                frameReservationActive = false;
                lock.notifyAll();
                rejected.increment();
                throw new UnavailableException();
            }
            long sequence;
            long revision;
            try {
                sequence = Math.incrementExact(lastReservedSequence);
                revision = Math.incrementExact(lastReservedRevision);
            } catch (ArithmeticException exhausted) {
                releaseOutstanding(payload.length);
                frameReservationActive = false;
                lock.notifyAll();
                throw exhausted;
            }
            return new FrameReservation(recordType, transactionId, ownedPayload,
                    acknowledgement, sequence, revision);
        }
    }

    private void reserveAdmission(int payloadBytes) {
        synchronized (lock) {
            if (state != State.OPEN) {
                rejected.increment();
                throw new UnavailableException();
            }
            long candidateBytes;
            long encodedBytes;
            long candidateEncodedBytes;
            try {
                candidateBytes = Math.addExact(outstandingPayloadBytes, payloadBytes);
                encodedBytes = encodedReservationBytes(payloadBytes);
                candidateEncodedBytes = Math.addExact(outstandingEncodedBytes, encodedBytes);
            } catch (ArithmeticException overflow) {
                rejected.increment();
                throw new OverloadedException();
            }
            if (outstandingSlots >= configuration.queueCapacity()
                    || candidateBytes > configuration.maximumQueuedPayloadBytes()) {
                rejected.increment();
                throw new OverloadedException();
            }
            if (Math.addExact(position, candidateEncodedBytes)
                    > configuration.maximumSegmentBytes()) {
                rejected.increment();
                throw new HeadroomExhaustedException();
            }
            outstandingSlots++;
            outstandingPayloadBytes = candidateBytes;
            outstandingEncodedBytes = candidateEncodedBytes;
        }
    }

    private static long encodedReservationBytes(int payloadBytes) {
        // A marker per request is an exact singleton cost and conservatively
        // dominates every possible grouping of the outstanding requests.
        return Math.addExact(SigningWalFrameCodec.BATCH_MARKER_BYTES,
                Math.addExact(SigningWalFrameCodec.HEADER_BYTES
                        + (long) SigningWalFrameCodec.CHECKSUM_BYTES, payloadBytes));
    }

    private void rollbackReservation(int payloadBytes) {
        synchronized (lock) {
            releaseOutstanding(payloadBytes);
            lock.notifyAll();
        }
    }

    private void releaseOutstanding(int payloadBytes) {
        long encodedBytes = encodedReservationBytes(payloadBytes);
        if (outstandingSlots <= 0 || outstandingPayloadBytes < payloadBytes
                || outstandingEncodedBytes < encodedBytes) {
            throw new IllegalStateException("signing WAL admission accounting is inconsistent");
        }
        outstandingSlots--;
        outstandingPayloadBytes -= payloadBytes;
        outstandingEncodedBytes -= encodedBytes;
    }

    private void runWriter() {
        try {
            while (true) {
                Batch batch = takeBatch();
                if (batch == null) {
                    break;
                }
                commit(batch);
                if (state == State.RECOVERY_REQUIRED) {
                    break;
                }
            }
            // Every admitted group was already forced before acknowledgement.
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            failBeforeAppendForShutdown(new IOException("signing active WAL writer was interrupted"));
        } finally {
            closeOwnedChannel();
        }
    }

    private Batch takeBatch() throws InterruptedException {
        List<Pending> requests = new ArrayList<>(configuration.maximumGroupSize());
        long started;
        synchronized (lock) {
            while (queue.isEmpty() && state == State.OPEN) {
                lock.wait();
            }
            if (queue.isEmpty()) {
                return null;
            }
            Pending first = removeFirst();
            requests.add(first);
            long encodedBytes = SigningWalFrameCodec.BATCH_MARKER_BYTES
                    + SigningWalFrameCodec.HEADER_BYTES + first.payload().length
                    + SigningWalFrameCodec.CHECKSUM_BYTES;
            started = first.admittedAtNanos();
            while (requests.size() < configuration.maximumGroupSize()) {
                if (!queue.isEmpty()) {
                    Pending next = queue.peekFirst();
                    long candidateBytes = encodedBytes + SigningWalFrameCodec.HEADER_BYTES
                            + next.payload().length + SigningWalFrameCodec.CHECKSUM_BYTES;
                    if (candidateBytes > configuration.maximumBatchBytes()) {
                        break;
                    }
                    requests.add(removeFirst());
                    encodedBytes = candidateBytes;
                    continue;
                }
                if (state != State.OPEN) {
                    break;
                }
                long elapsed = Math.max(0L, clock.nanoTime() - started);
                long remaining = configuration.maximumGroupWaitNanos() - elapsed;
                if (remaining <= 0L) {
                    break;
                }
                try {
                    waitStrategy.await(lock, remaining);
                } catch (InterruptedException failure) {
                    for (int index = requests.size() - 1; index >= 0; index--) {
                        Pending pending = requests.get(index);
                        queue.addFirst(pending);
                    }
                    throw failure;
                }
            }
        }
        long waited = Math.max(0L, clock.nanoTime() - started);
        batchWaitNanos.add(waited);
        updateMaximum(maximumBatchWaitNanos, waited);
        updateMaximum(maximumBatchSize, requests.size());
        return new Batch(requests);
    }

    private Pending removeFirst() {
        return queue.removeFirst();
    }

    private void commit(Batch batch) {
        PreparedBatch prepared;
        try {
            prepared = prepare(batch);
        } catch (RotationBoundaryException full) {
            transitionRotationRequired(batch.requests());
            return;
        } catch (RuntimeException validationFailure) {
            completeFailed(batch.requests(), new ValidationException(validationFailure));
            return;
        }

        try {
            channel.position(position);
        } catch (IOException failure) {
            transitionUnavailableBeforeAppend(batch.requests(), failure);
            return;
        }
        long appendStart = clock.nanoTime();
        ByteBuffer aggregate = null;
        int usedAggregateBytes = 0;
        try {
            int encodedBytes = Math.toIntExact(prepared.encodedBytes());
            aggregate = prepareAggregateWriteBuffer(encodedBytes);
            SigningWalFrameCodec.BatchCommit marker = SigningWalFrameCodec.encodeCommittedBatch(
                    aggregate, prepared.frames(), lastCommittedRevision,
                    prepared.finalRevision(), rollingCommitment);
            usedAggregateBytes = aggregate.position();
            if (usedAggregateBytes != encodedBytes) {
                throw new IOException("signing active WAL encoded batch boundary is inconsistent");
            }
            aggregate.flip();
            SigningFormatSupport.writeFully(
                    new DigestingChannel(channel, fileCommitment), aggregate);
            long appendEnd = clock.nanoTime();
            long written = channel.position() - position;
            if (written != prepared.encodedBytes()) {
                throw new IOException("signing active WAL append boundary is inconsistent");
            }
            long forceStart = appendEnd;
            forces.increment();
            channel.force(true);
            long forceEnd = clock.nanoTime();
            recordWriteMetrics(appendEnd - appendStart, forceEnd - forceStart, written);
            long committedPosition = channel.position();
            publishCommittedState(prepared, marker, committedPosition);
            committedGroups.increment();
            committedRequests.add(batch.requests().size());
            clearAggregateWriteBuffer(aggregate, usedAggregateBytes);
            aggregate = null;
            usedAggregateBytes = 0;
            completeSuccessful(prepared);
        } catch (IOException | RuntimeException failure) {
            transitionToRecoveryRequired(batch.requests(), failure);
        } finally {
            if (aggregate != null) {
                if (usedAggregateBytes == 0) {
                    usedAggregateBytes = aggregate.position();
                }
                clearAggregateWriteBuffer(aggregate, usedAggregateBytes);
            }
        }
    }

    private void publishCommittedState(PreparedBatch prepared,
            SigningWalFrameCodec.BatchCommit marker, long committedPosition) {
        synchronized (lock) {
            position = committedPosition;
            lastCommittedSequence = prepared.frames().getLast().sequence();
            lastCommittedRevision = prepared.finalRevision();
            rollingCommitment = marker.resultingCommitment();
            forcedEnd = new ForcedEnd(position, lastCommittedSequence,
                    lastCommittedRevision, rollingCommitment);
            for (Pending pending : prepared.requests()) {
                releaseOutstanding(pending.payload().length);
            }
            lock.notifyAll();
        }
    }

    private ByteBuffer prepareAggregateWriteBuffer(int requiredBytes) {
        if (requiredBytes < 0 || requiredBytes > MAXIMUM_BATCH_BYTES) {
            throw new IllegalArgumentException("signing active WAL aggregate size is invalid");
        }
        ByteBuffer current = aggregateWriteBuffer;
        if (current == null) {
            current = ByteBuffer.allocate(SigningFormatSupport.TRANSFER_BYTES);
        }
        int capacity = current.capacity();
        while (capacity < requiredBytes) {
            int doubled = Math.multiplyExact(capacity, 2);
            capacity = Math.min(doubled, MAXIMUM_BATCH_BYTES);
        }
        if (capacity != current.capacity()) {
            current = ByteBuffer.allocate(capacity);
        }
        aggregateWriteBuffer = current;
        current.clear();
        current.limit(requiredBytes);
        return current;
    }

    private static void clearAggregateWriteBuffer(ByteBuffer buffer, int usedBytes) {
        if (usedBytes < 0 || usedBytes > buffer.capacity()) {
            throw new IllegalStateException("signing active WAL aggregate use is inconsistent");
        }
        Arrays.fill(buffer.array(), 0, usedBytes, (byte) 0);
        buffer.clear();
    }

    private PreparedBatch prepare(Batch batch) {
        Set<UUID> transactionIds = new HashSet<>(batch.requests().size() * 2);
        List<SigningWalFrameCodec.Frame> frames = new ArrayList<>(batch.requests().size());
        List<FrameBoundary> boundaries = new ArrayList<>(batch.requests().size());
        long nextSequence = Math.incrementExact(lastCommittedSequence);
        long nextRevision = Math.incrementExact(lastCommittedRevision);
        long frameOffset = position;
        long encodedBytes = SigningWalFrameCodec.BATCH_MARKER_BYTES;
        for (int index = 0; index < batch.requests().size(); index++) {
            Pending pending = batch.requests().get(index);
            if (pending.sequence() != nextSequence || pending.revision() != nextRevision) {
                throw new IllegalArgumentException("reserved WAL sequence is not contiguous");
            }
            if (!transactionIds.add(pending.transactionId())) {
                throw new IllegalArgumentException("duplicate transaction");
            }
            SigningWalFrameCodec.Frame frame = SigningWalFrameCodec.Frame.owned(
                    pending.recordType(), pending.transactionId(), nextSequence, pending.payload());
            int frameLength = SigningWalFrameCodec.encodedLength(frame);
            encodedBytes = Math.addExact(encodedBytes, frameLength);
            boundaries.add(new FrameBoundary(frameOffset, frameLength, nextSequence, nextRevision));
            pending.pointerSlot().resolve(frameOffset, frameLength);
            frameOffset = Math.addExact(frameOffset, frameLength);
            frames.add(frame);
            if (index + 1 < batch.requests().size()) {
                nextSequence = Math.incrementExact(nextSequence);
                nextRevision = Math.incrementExact(nextRevision);
            }
        }
        if (encodedBytes > configuration.maximumBatchBytes()) {
            throw new IllegalArgumentException("batch bytes");
        }
        if (Math.addExact(position, encodedBytes) > configuration.maximumSegmentBytes()) {
            throw new RotationBoundaryException();
        }
        return new PreparedBatch(batch.requests(), frames, boundaries, nextRevision, encodedBytes);
    }

    private void recordWriteMetrics(long writeDuration, long forceDuration, long written) {
        long safeWrite = Math.max(0L, writeDuration);
        long safeForce = Math.max(0L, forceDuration);
        writeNanos.add(safeWrite);
        forceNanos.add(safeForce);
        updateMaximum(maximumWriteNanos, safeWrite);
        updateMaximum(maximumForceNanos, safeForce);
        bytesAppended.add(written);
    }

    private void completeSuccessful(PreparedBatch prepared) {
        byte[] commitment = rollingCommitment;
        long committedOffset = position;
        for (int index = 0; index < prepared.requests().size(); index++) {
            FrameBoundary boundary = prepared.boundaries().get(index);
            Pending pending = prepared.requests().get(index);
            pending.acknowledgement().complete(new CommitResult(
                    descriptor.identity(), boundary.sequence(), boundary.revision(),
                    boundary.offset(), boundary.length(),
                    committedOffset, commitment));
        }
    }

    private void transitionToRecoveryRequired(List<Pending> inFlight, Throwable failure) {
        List<Pending> notAttempted;
        synchronized (lock) {
            state = State.RECOVERY_REQUIRED;
            notAttempted = drainQueue();
            lock.notifyAll();
        }
        uncertain.add(inFlight.size());
        completeFailed(inFlight, new CommitFailure(
                FailureOutcome.DURABILITY_UNCERTAIN, failure));
        completeFailed(notAttempted, new CommitFailure(
                FailureOutcome.UNAVAILABLE_NOT_ATTEMPTED, failure));
        lifecycleFailure = new RecoveryRequiredException(
                "signing active WAL requires validated recovery", failure);
    }

    private void transitionUnavailableBeforeAppend(
            List<Pending> notAttemptedInFlight, Throwable failure) {
        List<Pending> notAttempted;
        synchronized (lock) {
            state = State.RECOVERY_REQUIRED;
            notAttempted = drainQueue();
            lock.notifyAll();
        }
        completeFailed(notAttemptedInFlight,
                new CommitFailure(FailureOutcome.UNAVAILABLE_NOT_ATTEMPTED, failure));
        completeFailed(notAttempted, new CommitFailure(
                FailureOutcome.UNAVAILABLE_NOT_ATTEMPTED, failure));
        lifecycleFailure = new RecoveryRequiredException(
                "signing active WAL storage is unavailable", failure);
    }

    private void transitionRotationRequired(List<Pending> notAttemptedInFlight) {
        List<Pending> notAttempted;
        synchronized (lock) {
            state = State.ROTATION_REQUIRED;
            notAttempted = drainQueue();
            lock.notifyAll();
        }
        completeFailed(notAttemptedInFlight, new RotationRequiredException());
        completeFailed(notAttempted, new RotationRequiredException());
    }

    private void failBeforeAppendForShutdown(IOException failure) {
        List<Pending> notAttempted;
        synchronized (lock) {
            state = State.RECOVERY_REQUIRED;
            notAttempted = drainQueue();
            lock.notifyAll();
        }
        completeFailed(notAttempted,
                new CommitFailure(FailureOutcome.UNAVAILABLE_NOT_ATTEMPTED, failure));
        lifecycleFailure = failure;
    }

    private List<Pending> drainQueue() {
        List<Pending> drained = new ArrayList<>(queue);
        queue.clear();
        return drained;
    }

    private void completeFailed(List<Pending> requests, Throwable failure) {
        for (Pending pending : requests) {
            releaseCompleted(pending);
            pending.acknowledgement().completeExceptionally(failure);
        }
    }

    private void releaseCompleted(Pending pending) {
        synchronized (lock) {
            releaseOutstanding(pending.payload().length);
            lock.notifyAll();
        }
    }

    private void closeOwnedChannel() {
        try {
            channel.close();
        } catch (IOException failure) {
            synchronized (lock) {
                state = State.RECOVERY_REQUIRED;
            }
            if (lifecycleFailure == null) {
                lifecycleFailure = new RecoveryRequiredException(
                        "signing active WAL close failed", failure);
            }
        } finally {
            synchronized (lock) {
                if (state == State.OPEN || state == State.CLOSING) {
                    state = State.CLOSED;
                }
                lock.notifyAll();
            }
        }
    }

    @Override
    public void close() throws IOException {
        boolean closePassive = false;
        synchronized (lock) {
            if (state == State.CLOSED) {
                return;
            }
            if (!writerStarted) {
                if (state == State.PASSIVE) {
                    state = State.CLOSING;
                }
                closePassive = channel.isOpen();
            } else if (state == State.OPEN) {
                state = State.CLOSING;
                lock.notifyAll();
            }
        }
        if (closePassive) {
            closeOwnedChannel();
        }
        boolean interrupted = false;
        while (writerThread.isAlive()) {
            try {
                writerThread.join();
            } catch (InterruptedException failure) {
                interrupted = true;
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
            throw new IOException("signing active WAL close was interrupted");
        }
        if (lifecycleFailure != null) {
            throw lifecycleFailure;
        }
    }

    /** Drains and returns the writer-owned immutable final descriptor without rereading bytes. */
    /* default */ Seal orderlySeal() throws IOException {
        close();
        MessageDigest commitment;
        try {
            commitment = (MessageDigest) fileCommitment.clone();
        } catch (CloneNotSupportedException failure) {
            throw new IOException("signing active WAL commitment state is unavailable", failure);
        }
        long frameCount = lastCommittedSequence < descriptor.firstSequence()
                ? 0L : Math.addExact(lastCommittedSequence - descriptor.firstSequence(), 1L);
        return new Seal(frameCount, lastCommittedSequence, lastCommittedRevision,
                position, commitment.digest());
    }

    /* default */ Snapshot snapshot() {
        synchronized (lock) {
            return new Snapshot(state, queue.size(), configuration.queueCapacity(),
                    outstandingSlots, outstandingPayloadBytes, outstandingEncodedBytes,
                    committedGroups.sum(), committedRequests.sum(), forces.sum(), rejected.sum(),
                    uncertain.sum(), maximumBatchSize.get(), batchWaitNanos.sum(),
                    maximumBatchWaitNanos.get(), writeNanos.sum(), maximumWriteNanos.get(),
                    forceNanos.sum(), maximumForceNanos.get(), bytesAppended.sum());
        }
    }

    /** Returns whether the lifecycle-owned channel remains open for cleanup verification. */
    /* default */ boolean channelOpen() {
        return channel.isOpen();
    }

    /** Returns one immutable forced prefix from the container baseline. */
    /* default */ CommittedPrefixDescriptor committedPrefix() {
        ForcedEnd end = forcedEnd;
        return new CommittedPrefixDescriptor(descriptor.identity(),
                SigningWalContainerCodec.HEADER_BYTES,
                predecessor(descriptor.firstSequence()), descriptor.baselineRevision(),
                baselineCommitment, end.offset(), end.sequence(), end.revision(),
                end.commitment());
    }

    /** Returns the currently forced suffix after a previously validated accepted prefix. */
    /* default */ CommittedPrefixDescriptor committedPrefixAfter(
            CommittedPrefixDescriptor acceptedPrefix) {
        Objects.requireNonNull(acceptedPrefix, "acceptedPrefix");
        ForcedEnd end = forcedEnd;
        if (acceptedPrefix.generationId() != descriptor.identity()
                || acceptedPrefix.inclusiveForcedEndOffset() > end.offset()
                || acceptedPrefix.inclusiveForcedEndSequence() > end.sequence()
                || acceptedPrefix.inclusiveForcedEndRevision() > end.revision()) {
            throw new IllegalArgumentException("signing accepted prefix is outside the active WAL");
        }
        if (acceptedPrefix.inclusiveForcedEndOffset() == end.offset()
                && (!MessageDigest.isEqual(acceptedPrefix.inclusiveForcedEndCommitment(),
                        end.commitment())
                || acceptedPrefix.inclusiveForcedEndSequence() != end.sequence()
                || acceptedPrefix.inclusiveForcedEndRevision() != end.revision())) {
            throw new IllegalArgumentException("signing accepted prefix endpoint is inconsistent");
        }
        return new CommittedPrefixDescriptor(descriptor.identity(),
                acceptedPrefix.inclusiveForcedEndOffset(),
                acceptedPrefix.inclusiveForcedEndSequence(),
                acceptedPrefix.inclusiveForcedEndRevision(),
                acceptedPrefix.inclusiveForcedEndCommitment(),
                end.offset(), end.sequence(), end.revision(), end.commitment());
    }

    private static long predecessor(long value) {
        return value == 0L ? -1L : value - 1L;
    }

    private static void updateMaximum(AtomicLong maximum, long candidate) {
        maximum.accumulateAndGet(candidate, Math::max);
    }

    /* default */ record Descriptor(long identity, long firstSequence, long baselineRevision) {
        Descriptor {
            if (identity < 0L || firstSequence < 0L || baselineRevision < 0L) {
                throw new IllegalArgumentException("signing active WAL descriptor is invalid");
            }
        }

        private SigningWalContainerCodec.Header header() {
            return new SigningWalContainerCodec.Header(identity, firstSequence, baselineRevision);
        }
    }

    /** Immutable result of the recovery owner's read-only validation pass. */
    /* default */ record ValidatedState(long observedLength, long position,
            long lastCommittedSequence, long lastCommittedRevision, byte[] rollingCommitment) {
        ValidatedState {
            Objects.requireNonNull(rollingCommitment, "rollingCommitment");
            if (observedLength < SigningWalContainerCodec.HEADER_BYTES
                    || position < SigningWalContainerCodec.HEADER_BYTES
                    || position > observedLength || lastCommittedSequence < -1L
                    || lastCommittedRevision < 0L
                    || rollingCommitment.length != SigningFormatSupport.SHA_256_BYTES) {
                throw new IllegalArgumentException("signing active WAL validated state is invalid");
            }
            rollingCommitment = rollingCommitment.clone();
        }

        @Override public byte[] rollingCommitment() { return rollingCommitment.clone(); }
    }

    /* default */ record Configuration(int queueCapacity, int maximumGroupSize,
            long maximumGroupWaitNanos, long maximumQueuedPayloadBytes, int maximumBatchBytes,
            long maximumSegmentBytes, PayloadCopier payloadCopier) {
        /* default */ static Configuration defaults() {
            return defaults(SigningWalFrameCodec.MAX_BATCH_FRAMES);
        }

        /* default */ static Configuration defaults(int maximumGroupSize) {
            return new Configuration(MAXIMUM_QUEUE_CAPACITY,
                    maximumGroupSize, MAXIMUM_WAIT_NANOS,
                    MAXIMUM_QUEUED_PAYLOAD_BYTES,
                    MAXIMUM_BATCH_BYTES, 256L * 1024L * 1024L, byte[]::clone);
        }

        /* default */ Configuration(int queueCapacity, int maximumGroupSize,
                long maximumGroupWaitNanos, long maximumQueuedPayloadBytes,
                int maximumBatchBytes) {
            this(queueCapacity, maximumGroupSize, maximumGroupWaitNanos,
                    maximumQueuedPayloadBytes, maximumBatchBytes,
                    256L * 1024L * 1024L, byte[]::clone);
        }

        /* default */ Configuration(int queueCapacity, int maximumGroupSize,
                long maximumGroupWaitNanos, long maximumQueuedPayloadBytes,
                int maximumBatchBytes, long maximumSegmentBytes) {
            this(queueCapacity, maximumGroupSize, maximumGroupWaitNanos,
                    maximumQueuedPayloadBytes, maximumBatchBytes,
                    maximumSegmentBytes, byte[]::clone);
        }

        /* default */ Configuration(int queueCapacity, int maximumGroupSize,
                long maximumGroupWaitNanos, long maximumQueuedPayloadBytes,
                int maximumBatchBytes, PayloadCopier payloadCopier) {
            this(queueCapacity, maximumGroupSize, maximumGroupWaitNanos,
                    maximumQueuedPayloadBytes, maximumBatchBytes,
                    256L * 1024L * 1024L, payloadCopier);
        }

        Configuration {
            if (queueCapacity <= 0 || queueCapacity > MAXIMUM_QUEUE_CAPACITY
                    || maximumGroupSize <= 0
                    || maximumGroupSize > SigningWalFrameCodec.MAX_BATCH_FRAMES
                    || maximumGroupWaitNanos < 0L || maximumGroupWaitNanos > MAXIMUM_WAIT_NANOS
                    || maximumQueuedPayloadBytes <= 0L
                    || maximumQueuedPayloadBytes > (long) MAXIMUM_QUEUE_CAPACITY
                            * SigningWalFrameCodec.MAX_PAYLOAD_BYTES
                    || maximumBatchBytes < SigningWalFrameCodec.BATCH_MARKER_BYTES
                            + SigningWalFrameCodec.HEADER_BYTES
                            + SigningWalFrameCodec.CHECKSUM_BYTES
                    || maximumBatchBytes > MAXIMUM_BATCH_BYTES
                    || maximumSegmentBytes < SigningWalContainerCodec.HEADER_BYTES
                            + SigningWalFrameCodec.BATCH_MARKER_BYTES
                            + SigningWalFrameCodec.HEADER_BYTES
                            + SigningWalFrameCodec.CHECKSUM_BYTES
                    || maximumSegmentBytes > SigningManifestCodec.MAX_FILE_BYTES
                    || payloadCopier == null) {
                throw new IllegalArgumentException("signing active WAL configuration is invalid");
            }
        }
    }

    /* default */ enum State {
        PASSIVE,
        OPEN,
        CLOSING,
        ROTATION_REQUIRED,
        CLOSED,
        RECOVERY_REQUIRED
    }

    /** Deterministic passive-open boundaries used by recovery cleanup tests. */
    /* default */ enum RecoveryOpenStage {
        AFTER_PASSIVE_WAL_OPEN,
        AFTER_TAIL_REPAIR
    }

    /** Package-local fault seam for passive recovery open. */
    /* default */
    @FunctionalInterface
    interface RecoveryOpenFaultInjector {
        void after(RecoveryOpenStage stage, WalChannel channel) throws IOException;
    }

    /* default */ enum FailureOutcome {
        DURABILITY_UNCERTAIN,
        UNAVAILABLE_NOT_ATTEMPTED
    }

    /* default */ record CommitResult(long generationIdentity, long sequence, long revision,
            long offset, int frameLength, long committedOffset, byte[] rollingCommitment) {
        CommitResult {
            if (generationIdentity < 0L) {
                throw new IllegalArgumentException("signing WAL commit generation is invalid");
            }
            rollingCommitment = rollingCommitment.clone();
        }

        @Override
        public byte[] rollingCommitment() {
            return rollingCommitment.clone();
        }
    }

    /* default */ record Snapshot(State state, int queueDepth, int queueCapacity,
            int outstandingRequests, long outstandingPayloadBytes,
            long outstandingEncodedBytes,
            long groupsCommitted, long requestsCommitted, long forces, long rejected,
            long uncertain, long maximumBatchSize, long batchWaitNanos,
            long maximumBatchWaitNanos, long writeNanos, long maximumWriteNanos,
            long forceNanos, long maximumForceNanos, long bytesAppended) {

        /**
         * Returns a zeroed writer baseline used to accumulate the counters of
         * sealed predecessor WALs before any rotation has occurred.
         *
         * <p>
         * Only the cumulative totals and high-water maxima of the baseline are
         * meaningful; its live state, queue, and outstanding-work fields are
         * placeholders that {@link #accumulate(Snapshot, Snapshot)} always
         * replaces with the live successor's values.
         * </p>
         *
         * @return a snapshot whose every counter is zero
         */
        /* default */ static Snapshot writerBaseline() {
            return new Snapshot(State.CLOSED, 0, 0, 0, 0L, 0L,
                    0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L);
        }

        /**
         * Merges the cumulative writer counters of all sealed predecessor WALs with
         * the live snapshot of the current active WAL so the shared writer metrics
         * remain monotone across WAL rotation.
         *
         * <p>
         * Live state, queue depth and capacity, and outstanding work are taken
         * verbatim from {@code live}, because they describe the currently active
         * writer. Monotone lifetime totals are summed and high-water maxima are
         * merged, so a snapshot taken after a rotation never reports a smaller
         * cumulative value than one taken before it.
         * </p>
         *
         * @param retired accumulated counters of every previously sealed WAL
         * @param live    live snapshot of the current active WAL
         * @return a snapshot whose cumulative writer counters span both WALs
         */
        /* default */ static Snapshot accumulate(Snapshot retired, Snapshot live) {
            Objects.requireNonNull(retired, "retired");
            Objects.requireNonNull(live, "live");
            return new Snapshot(live.state, live.queueDepth, live.queueCapacity,
                    live.outstandingRequests, live.outstandingPayloadBytes,
                    live.outstandingEncodedBytes,
                    Math.addExact(retired.groupsCommitted, live.groupsCommitted),
                    Math.addExact(retired.requestsCommitted, live.requestsCommitted),
                    Math.addExact(retired.forces, live.forces),
                    Math.addExact(retired.rejected, live.rejected),
                    Math.addExact(retired.uncertain, live.uncertain),
                    Math.max(retired.maximumBatchSize, live.maximumBatchSize),
                    Math.addExact(retired.batchWaitNanos, live.batchWaitNanos),
                    Math.max(retired.maximumBatchWaitNanos, live.maximumBatchWaitNanos),
                    Math.addExact(retired.writeNanos, live.writeNanos),
                    Math.max(retired.maximumWriteNanos, live.maximumWriteNanos),
                    Math.addExact(retired.forceNanos, live.forceNanos),
                    Math.max(retired.maximumForceNanos, live.maximumForceNanos),
                    Math.addExact(retired.bytesAppended, live.bytesAppended));
        }
    }

    /* default */ static final class Acknowledgement implements Future<CommitResult> {
        private final Object completionLock = new Object();
        private CommitResult result;
        private Throwable failure;
        private boolean complete;
        private boolean cancelled;

        private void complete(CommitResult completed) {
            synchronized (completionLock) {
                if (!cancelled) {
                    result = completed;
                }
                complete = true;
                completionLock.notifyAll();
            }
        }

        private void completeExceptionally(Throwable completedFailure) {
            synchronized (completionLock) {
                if (!cancelled) {
                    failure = completedFailure;
                }
                complete = true;
                completionLock.notifyAll();
            }
        }

        /* default */ CommitResult await() throws InterruptedException, ExecutionException {
            try {
                return get();
            } catch (InterruptedException failure) {
                Thread.currentThread().interrupt();
                throw failure;
            }
        }

        @Override
        public boolean cancel(boolean mayInterruptIfRunning) {
            synchronized (completionLock) {
                if (complete) {
                    return false;
                }
                cancelled = true;
                completionLock.notifyAll();
                return true;
            }
        }

        @Override public boolean isCancelled() { synchronized (completionLock) { return cancelled; } }
        @Override public boolean isDone() { synchronized (completionLock) { return complete || cancelled; } }

        @Override
        public CommitResult get() throws InterruptedException, ExecutionException {
            synchronized (completionLock) {
                while (!complete && !cancelled) {
                    completionLock.wait();
                }
                return completedResult();
            }
        }

        @Override
        public CommitResult get(long timeout, TimeUnit unit)
                throws InterruptedException, ExecutionException, TimeoutException {
            Objects.requireNonNull(unit, "unit");
            long remaining = unit.toNanos(timeout);
            long deadline = System.nanoTime() + remaining;
            synchronized (completionLock) {
                while (!complete && !cancelled) {
                    if (remaining <= 0L) {
                        throw new TimeoutException("signing WAL acknowledgement timed out");
                    }
                    TimeUnit.NANOSECONDS.timedWait(completionLock, remaining);
                    remaining = deadline - System.nanoTime();
                }
                return completedResult();
            }
        }

        private CommitResult completedResult() throws ExecutionException {
            if (cancelled) {
                throw new CancellationException("signing WAL acknowledgement was cancelled");
            }
            if (failure != null) {
                throw new ExecutionException(failure);
            }
            return result;
        }
    }

    /* default */ final class FrameReservation implements AutoCloseable {
        private final SigningWalFrameCodec.RecordType recordType;
        private final UUID transactionId;
        private final byte[] payload;
        private final Acknowledgement acknowledgement;
        private final long sequence;
        private final long revision;
        private final SigningRecordPointerSlot pointerSlot = new SigningRecordPointerSlot();
        private boolean active = true;

        private FrameReservation(SigningWalFrameCodec.RecordType recordType, UUID transactionId,
                byte[] payload, Acknowledgement acknowledgement, long sequence, long revision) {
            this.recordType = recordType;
            this.transactionId = transactionId;
            this.payload = payload;
            this.acknowledgement = acknowledgement;
            this.sequence = sequence;
            this.revision = revision;
        }

        /* default */ long generationIdentity() { return descriptor.identity(); }
        /* default */ long sequence() { return sequence; }
        /* default */ long revision() { return revision; }
        /* default */ int frameLength() {
            return SigningWalFrameCodec.HEADER_BYTES + payload.length
                    + SigningWalFrameCodec.CHECKSUM_BYTES;
        }
        /* default */ SigningRecordPointerSlot pointerSlot() { return pointerSlot; }

        /* default */ Acknowledgement admit() {
            synchronized (lock) {
                requireActive();
                if (state != State.OPEN) {
                    closeLocked();
                    throw new UnavailableException();
                }
                lastReservedSequence = sequence;
                lastReservedRevision = revision;
                active = false;
                frameReservationActive = false;
                queue.addLast(new Pending(recordType, transactionId, payload, acknowledgement,
                        clock.nanoTime(), sequence, revision, pointerSlot));
                lock.notifyAll();
                return acknowledgement;
            }
        }

        /**
         * Admits this reservation only when the guard still holds at the WAL
         * linearization point. A declined reservation consumes no sequence,
         * revision, or queue position. The guard must perform bounded in-memory
         * work only; it must not perform I/O, wait, or invoke further callbacks.
         */
        /* default */ Optional<Acknowledgement> admitIf(BooleanSupplier guard) {
            Objects.requireNonNull(guard, "guard");
            synchronized (lock) {
                requireActive();
                if (state != State.OPEN) {
                    closeLocked();
                    throw new UnavailableException();
                }
                if (!guard.getAsBoolean()) {
                    closeLocked();
                    return Optional.empty();
                }
                lastReservedSequence = sequence;
                lastReservedRevision = revision;
                active = false;
                frameReservationActive = false;
                queue.addLast(new Pending(recordType, transactionId, payload, acknowledgement,
                        clock.nanoTime(), sequence, revision, pointerSlot));
                lock.notifyAll();
                return Optional.of(acknowledgement);
            }
        }

        private void requireActive() {
            if (!active) {
                throw new IllegalStateException("signing WAL frame reservation is closed");
            }
        }

        private void closeLocked() {
            if (!active) {
                return;
            }
            active = false;
            frameReservationActive = false;
            releaseOutstanding(payload.length);
            lock.notifyAll();
        }

        @Override public void close() {
            synchronized (lock) { closeLocked(); }
        }
    }

    /* default */ static class OverloadedException extends RejectedExecutionException {
        private static final long serialVersionUID = 5948806617208825056L;

        /* default */ OverloadedException() {
            this("signing active WAL admission is full");
        }

        private OverloadedException(String message) {
            super(message);
        }
    }

    /* default */ static final class UnavailableException extends RejectedExecutionException {
        private static final long serialVersionUID = -4634554929264833338L;

        private UnavailableException() {
            super("signing active WAL is unavailable");
        }
    }

    /** Internal typed admission result indicating insufficient exact WAL headroom. */
    /* default */ static final class HeadroomExhaustedException
            extends OverloadedException {
        private static final long serialVersionUID = 3989905282541327710L;

        private HeadroomExhaustedException() {
            super("signing active WAL segment headroom is exhausted");
        }
    }

    /* default */ static final class CommitFailure extends IOException {
        private static final long serialVersionUID = -8837326524687673644L;
        private final FailureOutcome outcome;

        private CommitFailure(FailureOutcome outcome, Throwable cause) {
            super(outcome == FailureOutcome.DURABILITY_UNCERTAIN
                    ? "signing active WAL commit durability is uncertain"
                    : "signing active WAL commit was not attempted", cause);
            this.outcome = outcome;
        }

        /* default */ FailureOutcome outcome() {
            return outcome;
        }
    }

    /* default */ static final class ValidationException extends IOException {
        private static final long serialVersionUID = 5713459025104324087L;

        private ValidationException(Throwable cause) {
            super("signing active WAL batch validation failed before append", cause);
        }
    }

    /* default */ static final class RotationRequiredException extends IOException {
        private static final long serialVersionUID = -5674672998685456422L;

        private RotationRequiredException() {
            super("signing active WAL rotation is required");
        }
    }

    private static final class RotationBoundaryException extends RuntimeException {
        private static final long serialVersionUID = 6894733508425696909L;
    }

    /* default */ static final class RecoveryRequiredException extends IOException {
        private static final long serialVersionUID = 3493503317725205259L;

        private RecoveryRequiredException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Internal marker for malformed bytes discovered after the read-only preflight. */
    /* default */ static final class MalformedRecoveryDataException extends IOException {
        private static final long serialVersionUID = 1L;
    }

    @FunctionalInterface
    /* default */ interface NanoClock {
        long nanoTime();
    }

    @FunctionalInterface
    /* default */ interface GroupWaitStrategy {
        void await(Object monitor, long nanos) throws InterruptedException;
    }

    @FunctionalInterface
    /* default */ interface PayloadCopier {
        byte[] copy(byte[] payload);
    }

    /** Package-local filesystem and fault-injection seam. */
    @SuppressWarnings("PMD.CommentRequired")
    /* default */ interface Operations {
        boolean exists(Path path) throws IOException;
        boolean isRegularFile(Path path) throws IOException;
        WalChannel createNew(Path path) throws IOException;
        WalChannel openExisting(Path path) throws IOException;
        void forceDirectory(Path directory) throws IOException;
    }

    /** Minimal owned channel seam used to classify write and force failures. */
    /* default */ interface WalChannel extends SeekableByteChannel {
        void force(boolean metadata) throws IOException;
        @Override WalChannel position(long newPosition) throws IOException;
        @Override WalChannel truncate(long size) throws IOException;
    }

    private record Pending(SigningWalFrameCodec.RecordType recordType, UUID transactionId,
            byte[] payload, Acknowledgement acknowledgement, long admittedAtNanos,
            long sequence, long revision, SigningRecordPointerSlot pointerSlot) {
    }

    private record Batch(List<Pending> requests) {
    }

    private record FrameBoundary(long offset, int length, long sequence, long revision) {
    }

    private record PreparedBatch(List<Pending> requests, List<SigningWalFrameCodec.Frame> frames,
            List<FrameBoundary> boundaries, long finalRevision, long encodedBytes) {
    }

    /* default */ record Seal(long frameCount, long lastSequence, long committedRevision,
            long length, byte[] fileCommitment) {
        Seal {
            fileCommitment = fileCommitment.clone();
        }
        @Override public byte[] fileCommitment() { return fileCommitment.clone(); }
    }

    private record RestoredState(long position, long lastCommittedSequence,
            long lastCommittedRevision, byte[] rollingCommitment, MessageDigest fileCommitment) {
        RestoredState {
            rollingCommitment = rollingCommitment.clone();
            Objects.requireNonNull(fileCommitment, "fileCommitment");
        }

        @Override
        public byte[] rollingCommitment() {
            return rollingCommitment.clone();
        }
    }

    /** Atomically published only after the corresponding append is forced. */
    private record ForcedEnd(long offset, long sequence, long revision, byte[] commitment) {
        private ForcedEnd {
            commitment = commitment.clone();
        }

        @Override
        public byte[] commitment() {
            return commitment.clone();
        }
    }

    private record DigestingChannel(WalChannel delegate, MessageDigest digest)
            implements java.nio.channels.WritableByteChannel {
        @Override public int write(ByteBuffer source) throws IOException {
            ByteBuffer authenticated = source.asReadOnlyBuffer();
            int written = delegate.write(source);
            authenticated.limit(authenticated.position() + written);
            digest.update(authenticated);
            return written;
        }
        @Override public boolean isOpen() { return delegate.isOpen(); }
        @Override public void close() { throw new UnsupportedOperationException(); }
    }

    private static final class SystemOperations implements Operations {
        @Override
        public boolean exists(Path path) {
            return Files.exists(path, LinkOption.NOFOLLOW_LINKS);
        }

        @Override
        public boolean isRegularFile(Path path) {
            return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS);
        }

        @Override
        public WalChannel createNew(Path path) throws IOException {
            Set<OpenOption> options = Set.of(StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.READ, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
            FileAttribute<?>[] attributes = Files.getFileStore(path.getParent())
                    .supportsFileAttributeView("posix")
                            ? new FileAttribute<?>[] { PosixFilePermissions.asFileAttribute(
                                    PosixFilePermissions.fromString("rw-------")) }
                            : new FileAttribute<?>[0];
            return new SystemWalChannel(FileChannel.open(path, options, attributes));
        }

        @Override
        public WalChannel openExisting(Path path) throws IOException {
            Set<OpenOption> options = Set.of(StandardOpenOption.READ,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
            return new SystemWalChannel(FileChannel.open(path, options));
        }

        @Override
        public void forceDirectory(Path directory) throws IOException {
            SigningFormatSupport.forceDirectory(directory);
        }
    }

    private static final class SystemWalChannel implements WalChannel {
        private final FileChannel delegate;

        private SystemWalChannel(FileChannel delegate) {
            this.delegate = delegate;
        }

        @Override public int read(ByteBuffer target) throws IOException { return delegate.read(target); }
        @Override public int write(ByteBuffer source) throws IOException { return delegate.write(source); }
        @Override public long position() throws IOException { return delegate.position(); }
        @Override public WalChannel position(long newPosition) throws IOException {
            delegate.position(newPosition);
            return this;
        }
        @Override public long size() throws IOException { return delegate.size(); }
        @Override public WalChannel truncate(long size) throws IOException {
            delegate.truncate(size);
            return this;
        }
        @Override public boolean isOpen() { return delegate.isOpen(); }
        @Override public void close() throws IOException { delegate.close(); }
        @Override public void force(boolean metadata) throws IOException { delegate.force(metadata); }
    }
}
