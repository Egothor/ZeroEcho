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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

final class SigningActiveWalTest {

    private static final SigningActiveWal.Descriptor DESCRIPTOR =
            new SigningActiveWal.Descriptor(17L, 10L, 20L);
    private static final SigningActiveWal.GroupWaitStrategy NO_WAIT = (monitor, nanos) -> { };
    private static final SigningActiveWal.NanoClock FIXED_CLOCK = () -> 0L;

    @TempDir
    private Path temporaryDirectory;

    @Test
    void validatedRecoveryOpenRemainsPassiveUntilWriterStartsExactlyOnce() throws Exception {
        Path path = temporaryDirectory.resolve("passive-active.zew");
        byte[] header = SigningWalContainerCodec.encode(new SigningWalContainerCodec.Header(
                DESCRIPTOR.identity(), DESCRIPTOR.firstSequence(), DESCRIPTOR.baselineRevision()));
        Files.write(path, header);
        TestOperations operations = new TestOperations();
        SigningActiveWal.ValidatedState validated = new SigningActiveWal.ValidatedState(
                header.length, header.length, DESCRIPTOR.firstSequence() - 1L,
                DESCRIPTOR.baselineRevision(), SigningFormatSupport.sha256().digest(header));

        SigningActiveWal wal = SigningActiveWal.reopenValidatedPassive(path, DESCRIPTOR,
                configuration(4, 4, 0L), validated, operations, FIXED_CLOCK, NO_WAIT);
        assertEquals(SigningActiveWal.State.PASSIVE, wal.snapshot().state());
        assertArrayEquals(header, Files.readAllBytes(path));
        assertThrows(SigningActiveWal.UnavailableException.class, () -> wal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(1), new byte[] { 1 }));

        SigningActiveWal.CommitResult recovered = wal.appendRecovery(
                SigningWalFrameCodec.RecordType.INTENT, uuid(2), new byte[] { 2 });
        assertEquals(10L, recovered.sequence());
        assertEquals(SigningActiveWal.State.PASSIVE, wal.snapshot().state());
        assertEquals(1L, wal.snapshot().forces());
        wal.startWriter();
        assertEquals(SigningActiveWal.State.OPEN, wal.snapshot().state());
        assertThrows(IllegalStateException.class, wal::startWriter);
        assertEquals(11L, wal.submit(SigningWalFrameCodec.RecordType.INTENT, uuid(3),
                new byte[] { 3 }).get(5L, TimeUnit.SECONDS).sequence());
        wal.close();
    }

    @Test
    void closingPassiveRecoveryWalClosesChannelWithoutStartingWriter() throws Exception {
        Path path = temporaryDirectory.resolve("close-passive-active.zew");
        byte[] header = SigningWalContainerCodec.encode(new SigningWalContainerCodec.Header(
                DESCRIPTOR.identity(), DESCRIPTOR.firstSequence(), DESCRIPTOR.baselineRevision()));
        Files.write(path, header);
        TestOperations operations = new TestOperations();
        SigningActiveWal.ValidatedState validated = new SigningActiveWal.ValidatedState(
                header.length, header.length, DESCRIPTOR.firstSequence() - 1L,
                DESCRIPTOR.baselineRevision(), SigningFormatSupport.sha256().digest(header));

        SigningActiveWal wal = SigningActiveWal.reopenValidatedPassive(path, DESCRIPTOR,
                configuration(4, 4, 0L), validated, operations, FIXED_CLOCK, NO_WAIT);
        wal.close();
        wal.close();

        assertEquals(SigningActiveWal.State.CLOSED, wal.snapshot().state());
        assertFalse(operations.channel.isOpen());
        assertArrayEquals(header, Files.readAllBytes(path));
    }

    @Test
    void singletonTimeoutCommitsOneGroupWithOneForceAndStableBoundaries() throws Exception {
        Path path = temporaryDirectory.resolve("active.zew");
        TestOperations operations = new TestOperations();
        AtomicLong clock = new AtomicLong();
        SigningActiveWal wal = open(path, configuration(4, 32, 2_000_000L), operations,
                clock::get, (monitor, nanos) -> clock.addAndGet(nanos));
        CommittedPrefixDescriptor baseline = wal.committedPrefix();
        assertTrue(baseline.isEmpty());
        byte[] payload = { 1, 2, 3 };
        SigningActiveWal.Acknowledgement acknowledgement = wal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(1), payload);
        payload[0] = 99;

        SigningActiveWal.CommitResult result = acknowledgement.get(5L, TimeUnit.SECONDS);
        assertEquals(DESCRIPTOR.identity(), result.generationIdentity());
        assertEquals(10L, result.sequence());
        assertEquals(21L, result.revision());
        assertEquals(SigningWalContainerCodec.HEADER_BYTES, result.offset());
        assertEquals(SigningWalFrameCodec.HEADER_BYTES + 3 + SigningWalFrameCodec.CHECKSUM_BYTES,
                result.frameLength());
        assertEquals(Files.size(path), result.committedOffset());
        assertEquals(1L, wal.snapshot().groupsCommitted());
        assertEquals(1L, wal.snapshot().forces());
        assertEquals(1, wal.snapshot().maximumBatchSize());
        CommittedPrefixDescriptor forced = wal.committedPrefix();
        assertEquals(result.committedOffset(), forced.inclusiveForcedEndOffset());
        assertEquals(result.sequence(), forced.inclusiveForcedEndSequence());
        assertEquals(result.revision(), forced.inclusiveForcedEndRevision());
        assertArrayEquals(result.rollingCommitment(), forced.inclusiveForcedEndCommitment());
        assertTrue(wal.committedPrefixAfter(forced).isEmpty());
        wal.close();
        assertEquals(2, operations.channel.forceCalls);

        List<SigningWalFrameCodec.Frame> restored = scan(path);
        assertEquals(1, restored.size());
        assertArrayEquals(new byte[] { 1, 2, 3 }, restored.get(0).payload());
    }

    @Test
    void declinedGuardConsumesNoSequenceRevisionOrRecoveredFrame() throws Exception {
        Path path = temporaryDirectory.resolve("guarded-admission.zew");
        SigningActiveWal wal = open(path, configuration(2, 1, 0L),
                new TestOperations(), FIXED_CLOCK, NO_WAIT);
        long declinedSequence;
        long declinedRevision;
        try (SigningActiveWal.FrameReservation primary = wal.reserve(
                SigningWalFrameCodec.RecordType.MUTATION, uuid(1), new byte[] { 1 })) {
            declinedSequence = primary.sequence();
            declinedRevision = primary.revision();
            assertTrue(primary.admitIf(() -> false).isEmpty());
        }
        assertEquals(0, wal.snapshot().queueDepth());
        assertEquals(0, wal.snapshot().outstandingRequests());

        SigningActiveWal.CommitResult fallback;
        try (SigningActiveWal.FrameReservation reservation = wal.reserve(
                SigningWalFrameCodec.RecordType.MUTATION, uuid(2), new byte[] { 2 })) {
            assertEquals(declinedSequence, reservation.sequence());
            assertEquals(declinedRevision, reservation.revision());
            fallback = reservation.admit().get(5L, TimeUnit.SECONDS);
        }
        assertEquals(declinedSequence, fallback.sequence());
        assertEquals(declinedRevision, fallback.revision());
        wal.close();

        SigningActiveWal recovered = open(path, configuration(2, 1, 0L),
                new TestOperations(), FIXED_CLOCK, NO_WAIT);
        List<SigningWalFrameCodec.Frame> frames = scan(path);
        assertEquals(1, frames.size());
        assertEquals(uuid(2), frames.getFirst().transactionId());
        assertArrayEquals(new byte[] { 2 }, frames.getFirst().payload());
        SigningActiveWal.CommitResult next = recovered.submit(
                SigningWalFrameCodec.RecordType.MUTATION, uuid(3), new byte[] { 3 })
                .get(5L, TimeUnit.SECONDS);
        assertEquals(fallback.sequence() + 1L, next.sequence());
        assertEquals(fallback.revision() + 1L, next.revision());
        recovered.close();
    }

    @ParameterizedTest
    @MethodSource("supportedMaximumGroups")
    void configuredFullBatchAndConcurrentAdmissionProduceConsecutiveAssignments(int maximumGroupSize)
            throws Exception {
        Path path = temporaryDirectory.resolve("batch-" + maximumGroupSize + ".zew");
        TestOperations operations = new TestOperations();
        ControlledWait controlled = new ControlledWait();
        AtomicLong clock = new AtomicLong();
        SigningActiveWal wal = open(path, configuration(64, maximumGroupSize, 2_000_000L), operations,
                clock::get, controlled.withClock(clock));
        List<SigningActiveWal.Acknowledgement> acknowledgements = new ArrayList<>();
        acknowledgements.add(wal.submit(SigningWalFrameCodec.RecordType.MUTATION, uuid(0), new byte[0]));
        assertTrue(controlled.entered.await(5L, TimeUnit.SECONDS));
        for (int index = 1; index < maximumGroupSize; index++) {
            acknowledgements.add(wal.submit(SigningWalFrameCodec.RecordType.MUTATION,
                    uuid(index), new byte[] { (byte) index }));
        }
        controlled.release();

        for (int index = 0; index < acknowledgements.size(); index++) {
            SigningActiveWal.CommitResult result = acknowledgements.get(index).get(5L, TimeUnit.SECONDS);
            assertEquals(10L + index, result.sequence());
            assertEquals(21L + index, result.revision());
        }
        assertEquals(1L, wal.snapshot().groupsCommitted());
        assertEquals(maximumGroupSize, wal.snapshot().requestsCommitted());
        assertEquals(1L, wal.snapshot().forces());
        assertEquals(maximumGroupSize, wal.snapshot().maximumBatchSize());
        wal.close();
    }

    @Test
    void singletonMaximumNeverInvokesCoalescingWait() throws Exception {
        Path path = temporaryDirectory.resolve("singleton-no-wait.zew");
        AtomicLong waitCalls = new AtomicLong();
        SigningActiveWal.Configuration configuration = SigningActiveWal.Configuration.defaults(1);
        SigningActiveWal.Configuration defaults = SigningActiveWal.Configuration.defaults();
        assertEquals(defaults.queueCapacity(), configuration.queueCapacity());
        assertEquals(defaults.maximumGroupWaitNanos(), configuration.maximumGroupWaitNanos());
        assertEquals(defaults.maximumQueuedPayloadBytes(), configuration.maximumQueuedPayloadBytes());
        assertEquals(defaults.maximumBatchBytes(), configuration.maximumBatchBytes());
        assertEquals(defaults.maximumSegmentBytes(), configuration.maximumSegmentBytes());
        SigningActiveWal wal = open(path, configuration, new TestOperations(), FIXED_CLOCK,
                (monitor, nanos) -> waitCalls.incrementAndGet());

        wal.submit(SigningWalFrameCodec.RecordType.MUTATION, uuid(1), new byte[] { 1 })
                .get(5L, TimeUnit.SECONDS);

        assertEquals(0L, waitCalls.get());
        assertEquals(1L, wal.snapshot().maximumBatchSize());
        wal.close();
    }

    @ParameterizedTest
    @MethodSource("reopenMaximumGroups")
    void historicalMaximumGroupRemainsReadableUnderSmallerRuntimeMaximum(
            int reopenedMaximumGroupSize) throws Exception {
        Path path = temporaryDirectory.resolve("historical-32-runtime-"
                + reopenedMaximumGroupSize + ".zew");
        ControlledWait historicalWait = new ControlledWait();
        AtomicLong historicalClock = new AtomicLong();
        SigningActiveWal historical = open(path, configuration(64, 32, 2_000_000L),
                new TestOperations(), historicalClock::get, historicalWait.withClock(historicalClock));
        List<SigningActiveWal.Acknowledgement> historicalAcknowledgements = new ArrayList<>();
        historicalAcknowledgements.add(historical.submit(
                SigningWalFrameCodec.RecordType.MUTATION, uuid(0), new byte[] { 0 }));
        assertTrue(historicalWait.entered.await(5L, TimeUnit.SECONDS));
        for (int index = 1; index < 32; index++) {
            historicalAcknowledgements.add(historical.submit(
                    SigningWalFrameCodec.RecordType.MUTATION, uuid(index), new byte[] { (byte) index }));
        }
        historicalWait.release();
        for (SigningActiveWal.Acknowledgement acknowledgement : historicalAcknowledgements) {
            acknowledgement.get(5L, TimeUnit.SECONDS);
        }
        historical.close();

        SigningActiveWal reopened = open(path,
                configuration(64, reopenedMaximumGroupSize, 0L),
                new TestOperations(), FIXED_CLOCK, NO_WAIT);
        for (int index = 0; index < reopenedMaximumGroupSize; index++) {
            reopened.submit(SigningWalFrameCodec.RecordType.MUTATION,
                    uuid(32 + index), new byte[] { (byte) index }).get(5L, TimeUnit.SECONDS);
        }
        assertTrue(reopened.snapshot().maximumBatchSize() <= reopenedMaximumGroupSize);
        reopened.close();

        SigningActiveWal recovered = open(path,
                configuration(64, reopenedMaximumGroupSize, 0L),
                new TestOperations(), FIXED_CLOCK, NO_WAIT);
        assertEquals(32 + reopenedMaximumGroupSize, scan(path).size());
        recovered.close();
    }

    @Test
    void aggregateWriterGrowsReusesAndClearsOneContiguousBuffer() throws Exception {
        Path path = temporaryDirectory.resolve("aggregate-buffer.zew");
        TestOperations operations = new TestOperations();
        SigningActiveWal wal = open(path, configuration(4, 1, 0L), operations,
                FIXED_CLOCK, NO_WAIT);

        wal.submit(SigningWalFrameCodec.RecordType.MUTATION, uuid(1), new byte[] { 1 })
                .get(5L, TimeUnit.SECONDS);
        byte[] initial = operations.channel.appendArrays.get(0);
        assertEquals(SigningFormatSupport.TRANSFER_BYTES, initial.length);
        assertArrayEquals(new byte[initial.length], initial);

        wal.submit(SigningWalFrameCodec.RecordType.MUTATION, uuid(2), new byte[20 * 1024])
                .get(5L, TimeUnit.SECONDS);
        byte[] grown = operations.channel.appendArrays.get(1);
        assertEquals(2 * SigningFormatSupport.TRANSFER_BYTES, grown.length);
        assertArrayEquals(new byte[grown.length], grown);

        wal.submit(SigningWalFrameCodec.RecordType.MUTATION, uuid(3), new byte[] { 3 })
                .get(5L, TimeUnit.SECONDS);
        assertTrue(grown == operations.channel.appendArrays.get(2));
        assertEquals(3, operations.channel.appendWriteCalls);
        assertArrayEquals(new byte[grown.length], grown);
        wal.close();
    }

    @Test
    void groupByteBoundSplitsNearTwoMibTransactions() throws Exception {
        Path path = temporaryDirectory.resolve("byte-bounded-batch.zew");
        ControlledWait controlled = new ControlledWait();
        AtomicLong clock = new AtomicLong();
        SigningActiveWal wal = open(path, configuration(8, 8, 2_000_000L),
                new TestOperations(), clock::get, controlled.withClock(clock));
        byte[] payload = new byte[SigningWalFrameCodec.MAX_PAYLOAD_BYTES];
        List<SigningActiveWal.Acknowledgement> acknowledgements = new ArrayList<>();
        acknowledgements.add(wal.submit(SigningWalFrameCodec.RecordType.INTENT, uuid(0), payload));
        assertTrue(controlled.entered.await(5L, TimeUnit.SECONDS));
        for (int index = 1; index < 5; index++) {
            acknowledgements.add(wal.submit(SigningWalFrameCodec.RecordType.INTENT,
                    uuid(index), payload));
        }
        controlled.release();
        for (SigningActiveWal.Acknowledgement acknowledgement : acknowledgements) {
            acknowledgement.get(5L, TimeUnit.SECONDS);
        }
        assertEquals(2L, wal.snapshot().groupsCommitted());
        assertTrue(wal.snapshot().maximumBatchSize() <= 3L);
        wal.close();
    }

    @Test
    void boundedQueueRejectsBeforeAdmissionAndReportsDepth() throws Exception {
        Path path = temporaryDirectory.resolve("bounded.zew");
        ControlledWait controlled = new ControlledWait();
        AtomicLong clock = new AtomicLong();
        SigningActiveWal wal = open(path, configuration(3, 3, 2_000_000L),
                new TestOperations(), clock::get, controlled.withClock(clock));
        SigningActiveWal.Acknowledgement first = wal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(1), new byte[0]);
        assertTrue(controlled.entered.await(5L, TimeUnit.SECONDS));
        SigningActiveWal.Acknowledgement second = wal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(2), new byte[0]);
        SigningActiveWal.Acknowledgement third = wal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(3), new byte[0]);
        assertEquals(2, wal.snapshot().queueDepth());
        assertThrows(SigningActiveWal.OverloadedException.class, () -> wal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(4), new byte[0]));
        assertEquals(1L, wal.snapshot().rejected());
        controlled.release();
        first.get(5L, TimeUnit.SECONDS);
        second.get(5L, TimeUnit.SECONDS);
        third.get(5L, TimeUnit.SECONDS);
        SigningActiveWal.CommitResult afterRejection = wal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(5), new byte[0])
                .get(5L, TimeUnit.SECONDS);
        assertEquals(13L, afterRejection.sequence(),
                "pre-intent queue rejection must not consume a WAL sequence");
        wal.close();
    }

    @Test
    void cancelledPreAdmissionReservationCreatesNoSequenceGap() throws Exception {
        Path path = temporaryDirectory.resolve("reservation-no-gap.zew");
        SigningActiveWal wal = open(path, configuration(4, 4, 0L),
                new TestOperations(), FIXED_CLOCK, NO_WAIT);
        SigningActiveWal.FrameReservation cancelled = wal.reserve(
                SigningWalFrameCodec.RecordType.INTENT, uuid(1), new byte[] { 1 });
        assertEquals(DESCRIPTOR.identity(), cancelled.generationIdentity());
        assertEquals(10L, cancelled.sequence());
        assertEquals(21L, cancelled.revision());
        cancelled.close();
        SigningActiveWal.CommitResult committed = wal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(2), new byte[] { 2 })
                .get(5L, TimeUnit.SECONDS);
        assertEquals(10L, committed.sequence());
        assertEquals(21L, committed.revision());
        wal.close();
    }

    @Test
    void fullAdmissionRejectsBeforeCopyAndCloseRollsBackReservation() throws Exception {
        Path path = temporaryDirectory.resolve("reservation.zew");
        CountDownLatch copyEntered = new CountDownLatch(1);
        CountDownLatch releaseCopy = new CountDownLatch(1);
        AtomicLong copies = new AtomicLong();
        SigningActiveWal.PayloadCopier copier = payload -> {
            copies.incrementAndGet();
            copyEntered.countDown();
            try {
                releaseCopy.await();
            } catch (InterruptedException failure) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("copy interrupted");
            }
            return payload.clone();
        };
        SigningActiveWal.Configuration configuration = new SigningActiveWal.Configuration(
                1, 1, 0L, SigningWalFrameCodec.MAX_PAYLOAD_BYTES,
                SigningActiveWal.MAXIMUM_BATCH_BYTES, copier);
        SigningActiveWal wal = open(path, configuration, new TestOperations(),
                FIXED_CLOCK, NO_WAIT);
        AtomicReference<Throwable> submitFailure = new AtomicReference<>();
        Thread submitter = new Thread(() -> {
            try {
                wal.submit(SigningWalFrameCodec.RecordType.INTENT, uuid(1), new byte[1024]);
            } catch (Throwable failure) {
                submitFailure.set(failure);
            }
        });
        submitter.start();
        assertTrue(copyEntered.await(5L, TimeUnit.SECONDS));
        assertEquals(1, wal.snapshot().outstandingRequests());
        assertThrows(SigningActiveWal.OverloadedException.class, () -> wal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(2), new byte[1024]));
        assertEquals(1L, copies.get());
        wal.close();
        releaseCopy.countDown();
        submitter.join();
        assertInstanceOf(SigningActiveWal.UnavailableException.class, submitFailure.get());
        assertEquals(0, wal.snapshot().outstandingRequests());
        assertEquals(0L, wal.snapshot().outstandingPayloadBytes());
        assertEquals(0L, wal.snapshot().outstandingEncodedBytes());
    }

    @Test
    void failedPayloadCopyReleasesHeadroomWithoutConsumingSequence() throws Exception {
        Path path = temporaryDirectory.resolve("headroom-copy-failure.zew");
        byte[] payload = { 1 };
        long maximum = SigningWalContainerCodec.HEADER_BYTES
                + encodedReservationBytes(payload.length);
        AtomicLong copies = new AtomicLong();
        SigningActiveWal.PayloadCopier copier = source -> {
            if (copies.getAndIncrement() == 0L) {
                throw new IllegalStateException("injected payload copy failure");
            }
            return source.clone();
        };
        SigningActiveWal.Configuration bounded = new SigningActiveWal.Configuration(
                1, 1, 0L, SigningWalFrameCodec.MAX_PAYLOAD_BYTES,
                SigningActiveWal.MAXIMUM_BATCH_BYTES, maximum, copier);
        SigningActiveWal wal = open(path, bounded, new TestOperations(), FIXED_CLOCK, NO_WAIT);

        assertThrows(IllegalStateException.class, () -> wal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(1), payload));
        assertEquals(0, wal.snapshot().outstandingRequests());
        assertEquals(0L, wal.snapshot().outstandingPayloadBytes());
        assertEquals(0L, wal.snapshot().outstandingEncodedBytes());

        SigningActiveWal.CommitResult committed = wal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(2), payload)
                .get(5L, TimeUnit.SECONDS);
        assertEquals(10L, committed.sequence());
        assertEquals(21L, committed.revision());
        assertEquals(maximum, committed.committedOffset());
        assertEquals(0L, wal.snapshot().outstandingEncodedBytes());
        wal.close();
    }

    @Test
    void concurrentSubmitResultsMatchPersistedAdmissionOrder() throws Exception {
        Path path = temporaryDirectory.resolve("concurrent.zew");
        SigningActiveWal wal = open(path, configuration(32, 8, 0L), new TestOperations(),
                FIXED_CLOCK, NO_WAIT);
        int count = 16;
        CountDownLatch ready = new CountDownLatch(count);
        CountDownLatch start = new CountDownLatch(1);
        SigningActiveWal.Acknowledgement[] acknowledgements =
                new SigningActiveWal.Acknowledgement[count];
        Thread[] submitters = new Thread[count];
        for (int index = 0; index < count; index++) {
            int request = index;
            submitters[index] = new Thread(() -> {
                ready.countDown();
                try {
                    start.await();
                    acknowledgements[request] = wal.submit(
                            SigningWalFrameCodec.RecordType.MUTATION, uuid(request),
                            new byte[] { (byte) request });
                } catch (InterruptedException failure) {
                    Thread.currentThread().interrupt();
                }
            });
            submitters[index].start();
        }
        assertTrue(ready.await(5L, TimeUnit.SECONDS));
        start.countDown();
        for (Thread submitter : submitters) {
            submitter.join();
        }
        UUID[] transactionBySequence = new UUID[count];
        for (int index = 0; index < count; index++) {
            SigningActiveWal.CommitResult result = acknowledgements[index].get(5L, TimeUnit.SECONDS);
            int sequenceIndex = Math.toIntExact(result.sequence() - DESCRIPTOR.firstSequence());
            transactionBySequence[sequenceIndex] = uuid(index);
            assertEquals(DESCRIPTOR.baselineRevision() + sequenceIndex + 1L,
                    result.revision());
        }
        wal.close();
        List<SigningWalFrameCodec.Frame> frames = scan(path);
        assertEquals(count, frames.size());
        for (int index = 0; index < count; index++) {
            assertEquals(transactionBySequence[index], frames.get(index).transactionId());
        }
    }

    @Test
    void duplicateTransactionFailsButGroupByteBoundIsolatesValidRequests() throws Exception {
        Path duplicatePath = temporaryDirectory.resolve("duplicate.zew");
        ControlledWait controlled = new ControlledWait();
        AtomicLong clock = new AtomicLong();
        SigningActiveWal duplicateWal = open(duplicatePath, configuration(4, 2, 2_000_000L),
                new TestOperations(), clock::get, controlled.withClock(clock));
        SigningActiveWal.Acknowledgement first = duplicateWal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(1), new byte[0]);
        assertTrue(controlled.entered.await(5L, TimeUnit.SECONDS));
        SigningActiveWal.Acknowledgement duplicate = duplicateWal.submit(
                SigningWalFrameCodec.RecordType.MUTATION, uuid(1), new byte[0]);
        controlled.release();
        assertInstanceOf(SigningActiveWal.ValidationException.class, failure(first));
        assertInstanceOf(SigningActiveWal.ValidationException.class, failure(duplicate));
        assertEquals(SigningWalContainerCodec.HEADER_BYTES, Files.size(duplicatePath));
        assertEquals(SigningActiveWal.State.OPEN, duplicateWal.snapshot().state());
        duplicateWal.close();

        Path bytesPath = temporaryDirectory.resolve("bytes.zew");
        int oneFrameOnly = SigningWalFrameCodec.BATCH_MARKER_BYTES
                + SigningWalFrameCodec.HEADER_BYTES + SigningWalFrameCodec.CHECKSUM_BYTES;
        SigningActiveWal.Configuration bytesConfiguration = new SigningActiveWal.Configuration(
                4, 2, 2_000_000L, 1024L, oneFrameOnly);
        ControlledWait bytesWait = new ControlledWait();
        AtomicLong bytesClock = new AtomicLong();
        SigningActiveWal bytesWal = open(bytesPath, bytesConfiguration, new TestOperations(),
                bytesClock::get, bytesWait.withClock(bytesClock));
        SigningActiveWal.Acknowledgement tooLarge = bytesWal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(2), new byte[0]);
        assertTrue(bytesWait.entered.await(5L, TimeUnit.SECONDS));
        SigningActiveWal.Acknowledgement alsoTooLarge = bytesWal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(3), new byte[0]);
        bytesWait.release();
        assertEquals(10L, tooLarge.get(5L, TimeUnit.SECONDS).sequence());
        assertEquals(11L, alsoTooLarge.get(5L, TimeUnit.SECONDS).sequence());
        bytesWal.close();
        assertEquals(2, scan(bytesPath).size());
    }

    @Test
    void revisionExhaustionFailsWithoutDurabilityUncertainty() throws Exception {
        SigningActiveWal.Descriptor exhausted = new SigningActiveWal.Descriptor(
                1L, 0L, Long.MAX_VALUE);
        Path path = temporaryDirectory.resolve("exhausted.zew");
        SigningActiveWal wal = SigningActiveWal.open(path, exhausted,
                configuration(2, 1, 0L), new TestOperations(), FIXED_CLOCK, NO_WAIT);
        SigningActiveWal.Acknowledgement acknowledgement = wal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(1), new byte[0]);
        assertInstanceOf(SigningActiveWal.ValidationException.class, failure(acknowledgement));
        assertEquals(SigningActiveWal.State.OPEN, wal.snapshot().state());
        assertEquals(0L, wal.snapshot().uncertain());
        assertEquals(0L, wal.snapshot().outstandingEncodedBytes());
        assertThrows(ArithmeticException.class, () -> wal.reserve(
                SigningWalFrameCodec.RecordType.INTENT, uuid(2), new byte[0]));
        assertEquals(0, wal.snapshot().outstandingRequests());
        assertEquals(0L, wal.snapshot().outstandingEncodedBytes());
        wal.close();
    }

    @Test
    void cancellationDoesNotCancelAdmittedMutation() throws Exception {
        Path path = temporaryDirectory.resolve("cancel.zew");
        ControlledWait controlled = new ControlledWait();
        AtomicLong clock = new AtomicLong();
        SigningActiveWal wal = open(path, configuration(2, 2, 2_000_000L),
                new TestOperations(), clock::get, controlled.withClock(clock));
        SigningActiveWal.Acknowledgement acknowledgement = wal.submit(
                SigningWalFrameCodec.RecordType.TERMINAL, uuid(1), new byte[] { 7 });
        assertTrue(controlled.entered.await(5L, TimeUnit.SECONDS));
        assertTrue(acknowledgement.cancel(true));
        controlled.release();
        wal.close();
        assertTrue(acknowledgement.isCancelled());
        assertEquals(1, scan(path).size());
    }

    @Test
    void slowAcknowledgementConsumerCannotBlockLaterCommit() throws Exception {
        Path path = temporaryDirectory.resolve("slow-consumer.zew");
        SigningActiveWal wal = open(path, configuration(2, 1, 0L), new TestOperations(),
                FIXED_CLOCK, NO_WAIT);
        SigningActiveWal.Acknowledgement first = wal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(1), new byte[0]);
        CountDownLatch consuming = new CountDownLatch(1);
        CountDownLatch releaseConsumer = new CountDownLatch(1);
        Thread consumer = new Thread(() -> {
            try {
                first.get();
                consuming.countDown();
                releaseConsumer.await();
            } catch (InterruptedException failure) {
                Thread.currentThread().interrupt();
            } catch (ExecutionException failure) {
                throw new AssertionError(failure);
            }
        });
        consumer.start();
        assertTrue(consuming.await(5L, TimeUnit.SECONDS));
        SigningActiveWal.CommitResult second = wal.submit(
                SigningWalFrameCodec.RecordType.MUTATION, uuid(2), new byte[0])
                .get(5L, TimeUnit.SECONDS);
        assertEquals(11L, second.sequence());
        releaseConsumer.countDown();
        consumer.join();
        wal.close();
    }

    @Test
    void interruptedAwaitRestoresInterruptStatus() throws Exception {
        SigningActiveWal.Acknowledgement acknowledgement = new SigningActiveWal.Acknowledgement();
        Thread.currentThread().interrupt();
        try {
            assertThrows(InterruptedException.class, acknowledgement::await);
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void closeDrainsAdmissionIsRepeatableAndStopsNewSubmission() throws Exception {
        Path path = temporaryDirectory.resolve("close.zew");
        SigningActiveWal wal = open(path, configuration(8, 4, 0L), new TestOperations(),
                FIXED_CLOCK, NO_WAIT);
        List<SigningActiveWal.Acknowledgement> acknowledgements = new ArrayList<>();
        for (int index = 0; index < 8; index++) {
            acknowledgements.add(wal.submit(SigningWalFrameCodec.RecordType.PROVIDER_RESULT,
                    uuid(index), new byte[0]));
        }
        wal.close();
        wal.close();
        for (SigningActiveWal.Acknowledgement acknowledgement : acknowledgements) {
            assertTrue(acknowledgement.isDone());
            acknowledgement.get(5L, TimeUnit.SECONDS);
        }
        assertEquals(SigningActiveWal.State.CLOSED, wal.snapshot().state());
        assertThrows(SigningActiveWal.UnavailableException.class, () -> wal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(99), new byte[0]));
    }

    @Test
    void partialWritesSucceedAndNoProgressRequiresRecovery() throws Exception {
        Path partialPath = temporaryDirectory.resolve("partial.zew");
        TestOperations partialOperations = new TestOperations();
        SigningActiveWal partial = open(partialPath, configuration(2, 1, 0L),
                partialOperations, FIXED_CLOCK, NO_WAIT);
        partialOperations.channel.maximumWriteBytes = 3;
        partial.submit(SigningWalFrameCodec.RecordType.INTENT, uuid(1), new byte[31])
                .get(5L, TimeUnit.SECONDS);
        partial.close();
        assertEquals(1, scan(partialPath).size());

        Path stalledPath = temporaryDirectory.resolve("stalled.zew");
        TestOperations stalledOperations = new TestOperations();
        SigningActiveWal stalled = open(stalledPath, configuration(2, 1, 0L),
                stalledOperations, FIXED_CLOCK, NO_WAIT);
        stalledOperations.channel.noWriteProgress = true;
        SigningActiveWal.Acknowledgement failed = stalled.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(2), new byte[0]);
        SigningActiveWal.CommitFailure commitFailure = assertInstanceOf(
                SigningActiveWal.CommitFailure.class, failure(failed));
        assertEquals(SigningActiveWal.FailureOutcome.DURABILITY_UNCERTAIN,
                commitFailure.outcome());
        assertEquals(SigningActiveWal.State.RECOVERY_REQUIRED, stalled.snapshot().state());
        assertThrows(SigningActiveWal.UnavailableException.class, () -> stalled.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(3), new byte[0]));
        assertThrows(SigningActiveWal.RecoveryRequiredException.class, stalled::close);

        Path failedPath = temporaryDirectory.resolve("write-failed.zew");
        TestOperations failedOperations = new TestOperations();
        SigningActiveWal writeFailed = open(failedPath, configuration(2, 1, 0L),
                failedOperations, FIXED_CLOCK, NO_WAIT);
        failedOperations.channel.failWrites = true;
        SigningActiveWal.CommitFailure writeFailure = assertInstanceOf(
                SigningActiveWal.CommitFailure.class, failure(writeFailed.submit(
                        SigningWalFrameCodec.RecordType.INTENT, uuid(4), new byte[0])));
        assertEquals(SigningActiveWal.FailureOutcome.DURABILITY_UNCERTAIN,
                writeFailure.outcome());
        assertThrows(SigningActiveWal.RecoveryRequiredException.class, writeFailed::close);
    }

    @Test
    void forceFailureMakesInflightUncertainAndQueuedWorkNotAttempted() throws Exception {
        Path path = temporaryDirectory.resolve("force-failure.zew");
        TestOperations operations = new TestOperations();
        SigningActiveWal wal = open(path, configuration(4, 1, 0L), operations,
                FIXED_CLOCK, NO_WAIT);
        CommittedPrefixDescriptor beforeFailure = wal.committedPrefix();
        operations.channel.blockWrites = true;
        SigningActiveWal.Acknowledgement inFlight = wal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(1), new byte[0]);
        assertTrue(operations.channel.writeEntered.await(5L, TimeUnit.SECONDS));
        SigningActiveWal.Acknowledgement queued = wal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(2), new byte[0]);
        operations.channel.failForce = true;
        operations.channel.releaseWrites.countDown();
        SigningActiveWal.CommitFailure uncertain = assertInstanceOf(
                SigningActiveWal.CommitFailure.class, failure(inFlight));
        SigningActiveWal.CommitFailure notAttempted = assertInstanceOf(
                SigningActiveWal.CommitFailure.class, failure(queued));
        assertEquals(SigningActiveWal.FailureOutcome.DURABILITY_UNCERTAIN, uncertain.outcome());
        assertEquals(SigningActiveWal.FailureOutcome.UNAVAILABLE_NOT_ATTEMPTED,
                notAttempted.outcome());
        assertEquals(1L, wal.snapshot().uncertain());
        assertEquals(0, wal.snapshot().outstandingRequests());
        assertEquals(0L, wal.snapshot().outstandingPayloadBytes());
        assertEquals(0L, wal.snapshot().outstandingEncodedBytes());
        CommittedPrefixDescriptor afterFailure = wal.committedPrefix();
        assertEquals(beforeFailure.inclusiveForcedEndOffset(),
                afterFailure.inclusiveForcedEndOffset());
        assertEquals(beforeFailure.inclusiveForcedEndSequence(),
                afterFailure.inclusiveForcedEndSequence());
        assertEquals(beforeFailure.inclusiveForcedEndRevision(),
                afterFailure.inclusiveForcedEndRevision());
        assertArrayEquals(beforeFailure.inclusiveForcedEndCommitment(),
                afterFailure.inclusiveForcedEndCommitment());
        assertThrows(SigningActiveWal.RecoveryRequiredException.class, wal::close);
        assertFalse(uncertain.getMessage().contains(path.toString()));
        assertFalse(uncertain.getMessage().contains(uuid(1).toString()));
    }

    @Test
    void seekFailureBeforeAppendIsUnavailableNotAttempted() throws Exception {
        Path path = temporaryDirectory.resolve("seek-failure.zew");
        TestOperations operations = new TestOperations();
        SigningActiveWal wal = open(path, configuration(2, 1, 0L), operations,
                FIXED_CLOCK, NO_WAIT);
        long initialSize = Files.size(path);
        operations.channel.failPosition = true;
        SigningActiveWal.CommitFailure failure = assertInstanceOf(
                SigningActiveWal.CommitFailure.class, failure(wal.submit(
                        SigningWalFrameCodec.RecordType.INTENT, uuid(1), new byte[0])));
        assertEquals(SigningActiveWal.FailureOutcome.UNAVAILABLE_NOT_ATTEMPTED,
                failure.outcome());
        assertEquals(initialSize, Files.size(path));
        assertEquals(0L, wal.snapshot().uncertain());
        assertEquals(SigningActiveWal.State.RECOVERY_REQUIRED, wal.snapshot().state());
        assertThrows(SigningActiveWal.RecoveryRequiredException.class, wal::close);
    }

    @ParameterizedTest
    @MethodSource("restartCrashImages")
    void restartMatrixPublishesOnlyCompleteGroupsAndNeverReportsFalseSuccess(
            WalCrashImage crashImage, boolean committedAfterRestart,
            SigningActiveWal.FailureOutcome expectedOutcome) throws Exception {
        Path path = temporaryDirectory.resolve("restart-" + crashImage + ".zew");
        TestOperations faultOperations = new TestOperations();
        SigningActiveWal faulted = open(path, configuration(2, 1, 0L),
                faultOperations, FIXED_CLOCK, NO_WAIT);
        byte[] payload = { 42 };
        configureCrashImage(faultOperations.channel, crashImage, payload.length);

        SigningActiveWal.CommitFailure commitFailure = assertInstanceOf(
                SigningActiveWal.CommitFailure.class,
                failure(faulted.submit(SigningWalFrameCodec.RecordType.INTENT,
                        uuid(1), payload)));
        assertEquals(expectedOutcome, commitFailure.outcome());
        assertThrows(SigningActiveWal.RecoveryRequiredException.class, faulted::close);

        TestOperations restartOperations = new TestOperations();
        SigningActiveWal restarted = open(path, configuration(2, 1, 0L),
                restartOperations, FIXED_CLOCK, NO_WAIT);
        List<SigningWalFrameCodec.Frame> recovered = scan(path);
        assertEquals(committedAfterRestart ? 1 : 0, recovered.size());
        if (committedAfterRestart) {
            assertEquals(uuid(1), recovered.getFirst().transactionId());
            assertArrayEquals(payload, recovered.getFirst().payload());
        }
        SigningActiveWal.CommitResult next = restarted.submit(
                SigningWalFrameCodec.RecordType.MUTATION, uuid(2), new byte[] { 43 })
                .get(5L, TimeUnit.SECONDS);
        assertEquals(committedAfterRestart ? 11L : 10L, next.sequence());
        restarted.close();
        assertEquals(committedAfterRestart ? 2 : 1, scan(path).size());
    }

    @Test
    void reopenTruncatesOnlyActiveTailAndRestoresCommitState() throws Exception {
        Path path = temporaryDirectory.resolve("reopen.zew");
        SigningActiveWal wal = open(path, configuration(2, 1, 0L), new TestOperations(),
                FIXED_CLOCK, NO_WAIT);
        SigningActiveWal.CommitResult first = wal.submit(SigningWalFrameCodec.RecordType.INTENT,
                uuid(1), new byte[] { 1 }).get(5L, TimeUnit.SECONDS);
        wal.close();
        Files.write(path, SigningWalFrameCodec.encode(new SigningWalFrameCodec.Frame(
                SigningWalFrameCodec.RecordType.MUTATION, uuid(2), 11L, new byte[] { 2 })),
                StandardOpenOption.APPEND);

        TestOperations reopenedOperations = new TestOperations();
        SigningActiveWal reopened = open(path, configuration(2, 1, 0L), reopenedOperations,
                FIXED_CLOCK, NO_WAIT);
        assertEquals(1, reopenedOperations.channel.truncates);
        assertEquals(1, reopenedOperations.channel.forceCalls);
        SigningActiveWal.CommitResult second = reopened.submit(SigningWalFrameCodec.RecordType.MUTATION,
                uuid(3), new byte[] { 3 }).get(5L, TimeUnit.SECONDS);
        assertEquals(first.sequence() + 1L, second.sequence());
        assertEquals(first.revision() + 1L, second.revision());
        reopened.close();
        assertEquals(2, scan(path).size());
    }

    @Test
    void incompatibleContainerAndCorruptCommittedContentFailClosed() throws Exception {
        Path mismatch = temporaryDirectory.resolve("mismatch.zew");
        Files.write(mismatch, SigningWalContainerCodec.encode(
                new SigningWalContainerCodec.Header(99L, 10L, 20L)));
        assertThrows(IOException.class, () -> open(mismatch, configuration(2, 1, 0L),
                new TestOperations(), FIXED_CLOCK, NO_WAIT));

        Path corrupt = temporaryDirectory.resolve("corrupt.zew");
        SigningActiveWal wal = open(corrupt, configuration(2, 1, 0L), new TestOperations(),
                FIXED_CLOCK, NO_WAIT);
        wal.submit(SigningWalFrameCodec.RecordType.INTENT, uuid(1), new byte[] { 1 })
                .get(5L, TimeUnit.SECONDS);
        wal.close();
        byte[] bytes = Files.readAllBytes(corrupt);
        bytes[SigningWalContainerCodec.HEADER_BYTES + SigningWalFrameCodec.HEADER_BYTES] ^= 1;
        Files.write(corrupt, bytes, StandardOpenOption.TRUNCATE_EXISTING);
        assertThrows(IOException.class, () -> open(corrupt, configuration(2, 1, 0L),
                new TestOperations(), FIXED_CLOCK, NO_WAIT));
    }

    @Test
    void creationForcesFileThenDirectoryAndReportsUncertainDirectoryFailure() throws Exception {
        Path path = temporaryDirectory.resolve("created.zew");
        TestOperations operations = new TestOperations();
        SigningActiveWal wal = open(path, configuration(2, 1, 0L), operations,
                FIXED_CLOCK, NO_WAIT);
        assertEquals(List.of("file", "directory"), operations.creationEvents);
        wal.close();

        Path failedPath = temporaryDirectory.resolve("directory-failed.zew");
        TestOperations failed = new TestOperations();
        failed.failDirectoryForce = true;
        SigningActiveWal.RecoveryRequiredException failure = assertThrows(
                SigningActiveWal.RecoveryRequiredException.class,
                () -> open(failedPath, configuration(2, 1, 0L), failed, FIXED_CLOCK, NO_WAIT));
        assertEquals("signing active WAL creation durability is uncertain", failure.getMessage());
        assertTrue(Files.exists(failedPath));
        assertFalse(failure.getMessage().contains(failedPath.toString()));

        Path fileFailedPath = temporaryDirectory.resolve("file-force-failed.zew");
        TestOperations fileFailed = new TestOperations();
        fileFailed.failInitialForce = true;
        assertThrows(SigningActiveWal.RecoveryRequiredException.class,
                () -> open(fileFailedPath, configuration(2, 1, 0L), fileFailed,
                        FIXED_CLOCK, NO_WAIT));
    }

    @Test
    void exactHeadroomBoundaryRejectsBeforeAssignmentAndNeverRotatesAdmittedWork()
            throws Exception {
        Path path = temporaryDirectory.resolve("rotation-bound.zew");
        byte[] payload = { 1 };
        long reservationBytes = encodedReservationBytes(payload.length);
        long maximum = SigningWalContainerCodec.HEADER_BYTES + reservationBytes;
        SigningActiveWal.Configuration bounded = new SigningActiveWal.Configuration(
                2, 1, 0L, 2L * SigningWalFrameCodec.MAX_PAYLOAD_BYTES,
                SigningActiveWal.MAXIMUM_BATCH_BYTES, maximum);
        SigningActiveWal wal = open(path, bounded, new TestOperations(), FIXED_CLOCK, NO_WAIT);

        SigningActiveWal.FrameReservation held = wal.reserve(
                SigningWalFrameCodec.RecordType.INTENT, uuid(1), payload);
        assertEquals(reservationBytes, wal.snapshot().outstandingEncodedBytes());
        assertThrows(SigningActiveWal.HeadroomExhaustedException.class, () -> wal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(2), payload));
        assertEquals(SigningActiveWal.State.OPEN, wal.snapshot().state());
        held.close();
        assertEquals(0L, wal.snapshot().outstandingEncodedBytes());

        SigningActiveWal.CommitResult committed = wal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(3), payload)
                .get(5L, TimeUnit.SECONDS);
        assertEquals(10L, committed.sequence());
        assertEquals(21L, committed.revision());
        assertEquals(maximum, committed.committedOffset());
        assertEquals(maximum, Files.size(path));
        assertEquals(SigningActiveWal.State.OPEN, wal.snapshot().state());
        assertEquals(0L, wal.snapshot().outstandingEncodedBytes());
        assertThrows(SigningActiveWal.HeadroomExhaustedException.class, () -> wal.submit(
                SigningWalFrameCodec.RecordType.INTENT, uuid(4), payload));
        assertEquals(SigningActiveWal.State.OPEN, wal.snapshot().state());

        SigningActiveWal.Seal seal = wal.orderlySeal();
        assertEquals(1L, seal.frameCount());
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            assertArrayEquals(SigningFileCommitment.sha256(channel), seal.fileCommitment());
        }
    }

    private static long encodedReservationBytes(int payloadBytes) {
        return SigningWalFrameCodec.BATCH_MARKER_BYTES
                + SigningWalFrameCodec.HEADER_BYTES
                + (long) SigningWalFrameCodec.CHECKSUM_BYTES + payloadBytes;
    }

    private SigningActiveWal open(Path path, SigningActiveWal.Configuration configuration,
            TestOperations operations, SigningActiveWal.NanoClock clock,
            SigningActiveWal.GroupWaitStrategy wait) throws IOException {
        return SigningActiveWal.open(path, DESCRIPTOR, configuration, operations, clock, wait);
    }

    private static SigningActiveWal.Configuration configuration(int queue, int group, long wait) {
        return new SigningActiveWal.Configuration(queue, group, wait,
                Math.min((long) queue * SigningWalFrameCodec.MAX_PAYLOAD_BYTES,
                        64L * 1024L * 1024L), SigningActiveWal.MAXIMUM_BATCH_BYTES);
    }

    private static Stream<Arguments> supportedMaximumGroups() {
        return Stream.of(Arguments.of(8), Arguments.of(32));
    }

    private static Stream<Arguments> reopenMaximumGroups() {
        return Stream.of(Arguments.of(1), Arguments.of(8));
    }

    private static Stream<Arguments> restartCrashImages() {
        return Stream.of(
                Arguments.of(WalCrashImage.BEFORE_APPEND, false,
                        SigningActiveWal.FailureOutcome.UNAVAILABLE_NOT_ATTEMPTED),
                Arguments.of(WalCrashImage.PARTIAL_FRAME, false,
                        SigningActiveWal.FailureOutcome.DURABILITY_UNCERTAIN),
                Arguments.of(WalCrashImage.MISSING_GROUP_MARKER, false,
                        SigningActiveWal.FailureOutcome.DURABILITY_UNCERTAIN),
                Arguments.of(WalCrashImage.PARTIAL_GROUP_MARKER, false,
                        SigningActiveWal.FailureOutcome.DURABILITY_UNCERTAIN),
                Arguments.of(WalCrashImage.COMPLETE_MARKER_BEFORE_FORCE, true,
                        SigningActiveWal.FailureOutcome.DURABILITY_UNCERTAIN),
                Arguments.of(WalCrashImage.FORCE_BEFORE_PERSISTENCE, false,
                        SigningActiveWal.FailureOutcome.DURABILITY_UNCERTAIN),
                Arguments.of(WalCrashImage.FORCE_DELEGATE_THEN_FAIL, true,
                        SigningActiveWal.FailureOutcome.DURABILITY_UNCERTAIN));
    }

    private static void configureCrashImage(TestChannel channel, WalCrashImage crashImage,
            int payloadBytes) {
        int frameBytes = SigningWalFrameCodec.HEADER_BYTES + payloadBytes
                + SigningWalFrameCodec.CHECKSUM_BYTES;
        switch (crashImage) {
            case BEFORE_APPEND -> channel.failPosition = true;
            case PARTIAL_FRAME -> channel.failAfterAppendBytes = 7L;
            case MISSING_GROUP_MARKER -> channel.failAfterAppendBytes = frameBytes;
            case PARTIAL_GROUP_MARKER -> channel.failAfterAppendBytes = frameBytes + 7L;
            case COMPLETE_MARKER_BEFORE_FORCE -> {
                channel.failAfterAppendBytes = frameBytes
                        + SigningWalFrameCodec.BATCH_MARKER_BYTES;
                channel.failImmediatelyAtAppendBoundary = true;
            }
            case FORCE_BEFORE_PERSISTENCE -> channel.truncateBeforeFailedForce = true;
            case FORCE_DELEGATE_THEN_FAIL -> channel.failAfterSuccessfulForce = true;
        }
    }

    private static UUID uuid(int value) {
        return new UUID(0x1234L, value);
    }

    private static Throwable failure(SigningActiveWal.Acknowledgement acknowledgement)
            throws Exception {
        ExecutionException failure = assertThrows(ExecutionException.class,
                () -> acknowledgement.get(5L, TimeUnit.SECONDS));
        return failure.getCause();
    }

    private static List<SigningWalFrameCodec.Frame> scan(Path path) throws IOException {
        List<SigningWalFrameCodec.Frame> frames = new ArrayList<>();
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            SigningWalFrameCodec.scan(channel, DESCRIPTOR.firstSequence(), true, frames::add);
        }
        return frames;
    }

    private static final class ControlledWait {
        private final CountDownLatch entered = new CountDownLatch(1);
        private volatile boolean released;
        private volatile Object monitor;

        private SigningActiveWal.GroupWaitStrategy withClock(AtomicLong clock) {
            return (monitor, nanos) -> {
                this.monitor = monitor;
                entered.countDown();
                while (!released) {
                    monitor.wait();
                }
                clock.addAndGet(nanos);
            };
        }

        private void release() {
            released = true;
            Object current = monitor;
            if (current != null) {
                synchronized (current) {
                    current.notifyAll();
                }
            }
        }
    }

    private enum WalCrashImage {
        BEFORE_APPEND,
        PARTIAL_FRAME,
        MISSING_GROUP_MARKER,
        PARTIAL_GROUP_MARKER,
        COMPLETE_MARKER_BEFORE_FORCE,
        FORCE_BEFORE_PERSISTENCE,
        FORCE_DELEGATE_THEN_FAIL
    }

    private static final class TestOperations implements SigningActiveWal.Operations {
        private TestChannel channel;
        private boolean failDirectoryForce;
        private boolean failInitialForce;
        private final List<String> creationEvents = new ArrayList<>();

        @Override
        public boolean exists(Path path) {
            return Files.exists(path, LinkOption.NOFOLLOW_LINKS);
        }

        @Override
        public boolean isRegularFile(Path path) {
            return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS);
        }

        @Override
        public SigningActiveWal.WalChannel createNew(Path path) throws IOException {
            channel = new TestChannel(FileChannel.open(path, Set.<OpenOption>of(
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.READ, StandardOpenOption.WRITE)),
                    creationEvents);
            channel.failForce = failInitialForce;
            return channel;
        }

        @Override
        public SigningActiveWal.WalChannel openExisting(Path path) throws IOException {
            channel = new TestChannel(FileChannel.open(path, StandardOpenOption.READ,
                    StandardOpenOption.WRITE), creationEvents);
            channel.creation = false;
            return channel;
        }

        @Override
        public void forceDirectory(Path directory) throws IOException {
            creationEvents.add("directory");
            if (failDirectoryForce) {
                throw new IOException("injected directory force failure");
            }
        }
    }

    private static final class TestChannel implements SigningActiveWal.WalChannel {
        private final FileChannel delegate;
        private final List<String> creationEvents;
        private int maximumWriteBytes = Integer.MAX_VALUE;
        private boolean noWriteProgress;
        private boolean failWrites;
        private boolean failPosition;
        private boolean failForce;
        private boolean failImmediatelyAtAppendBoundary;
        private boolean truncateBeforeFailedForce;
        private boolean failAfterSuccessfulForce;
        private boolean blockWrites;
        private long failAfterAppendBytes = -1L;
        private boolean creation = true;
        private int truncates;
        private int forceCalls;
        private int appendWriteCalls;
        private final List<byte[]> appendArrays = new ArrayList<>();
        private final CountDownLatch writeEntered = new CountDownLatch(1);
        private final CountDownLatch releaseWrites = new CountDownLatch(1);

        private TestChannel(FileChannel delegate, List<String> creationEvents) {
            this.delegate = delegate;
            this.creationEvents = creationEvents;
        }

        @Override
        public int read(ByteBuffer target) throws IOException {
            return delegate.read(target);
        }

        @Override
        public int write(ByteBuffer source) throws IOException {
            if (!creation && source.hasArray()) {
                appendWriteCalls++;
                appendArrays.add(source.array());
            }
            if (blockWrites) {
                writeEntered.countDown();
                try {
                    releaseWrites.await();
                } catch (InterruptedException failure) {
                    Thread.currentThread().interrupt();
                    throw new IOException("injected write interruption");
                }
            }
            if (noWriteProgress) {
                return 0;
            }
            if (failWrites) {
                throw new IOException("injected write failure");
            }
            if (failAfterAppendBytes == 0L) {
                throw new IOException("injected append boundary failure");
            }
            if (failAfterAppendBytes > 0L) {
                int originalLimit = source.limit();
                source.limit(source.position() + (int) Math.min(
                        source.remaining(), failAfterAppendBytes));
                try {
                    int written = delegate.write(source);
                    failAfterAppendBytes -= written;
                    if (failAfterAppendBytes == 0L && failImmediatelyAtAppendBoundary) {
                        throw new IOException("injected append boundary failure");
                    }
                    return written;
                } finally {
                    source.limit(originalLimit);
                }
            }
            if (source.remaining() <= maximumWriteBytes) {
                return delegate.write(source);
            }
            int originalLimit = source.limit();
            source.limit(source.position() + maximumWriteBytes);
            try {
                return delegate.write(source);
            } finally {
                source.limit(originalLimit);
            }
        }

        @Override public long position() throws IOException { return delegate.position(); }
        @Override public SigningActiveWal.WalChannel position(long position) throws IOException {
            if (failPosition) {
                throw new IOException("injected position failure");
            }
            delegate.position(position);
            return this;
        }
        @Override public long size() throws IOException { return delegate.size(); }
        @Override public SigningActiveWal.WalChannel truncate(long size) throws IOException {
            truncates++;
            delegate.truncate(size);
            return this;
        }
        @Override public boolean isOpen() { return delegate.isOpen(); }
        @Override public void close() throws IOException { delegate.close(); }
        @Override public void force(boolean metadata) throws IOException {
            forceCalls++;
            if (creation) {
                creationEvents.add("file");
                creation = false;
            }
            if (failForce) {
                throw new IOException("injected force failure");
            }
            if (truncateBeforeFailedForce) {
                truncateBeforeFailedForce = false;
                delegate.truncate(SigningWalContainerCodec.HEADER_BYTES);
                throw new IOException("injected force-before-persistence failure");
            }
            if (failAfterSuccessfulForce) {
                failAfterSuccessfulForce = false;
                delegate.force(metadata);
                throw new IOException("injected post-force acknowledgement failure");
            }
            delegate.force(metadata);
        }
    }
}
