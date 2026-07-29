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
package zeroecho.pki.impl.crypto.zeroecholib;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.core.alg.rsa.RsaPrivateKeySpec;
import zeroecho.core.alg.rsa.RsaPublicKeySpec;
import zeroecho.core.storage.KeyringStore;

final class ZeroEchoLibSignatureWorkflowPersistenceTest {

    private static final String NAMESPACE = "0123456789abcdef0123456789abcdef.zeroecho-lib";

    @Test
    void signingVerificationPersistenceAndCallbackCopiesAreCleared(@TempDir Path root) throws Exception {
        System.out.println("signingVerificationPersistenceAndCallbackCopiesAreCleared");
        Instant now = Instant.parse("2026-02-03T04:05:06.789Z");
        Path keyring = root.resolve("keyring.txt");
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        KeyringStore keyringStore = new KeyringStore(new zeroecho.sdk.ZeroEchoSession());
        keyringStore.putPrivate("test.prv", "RSA", new RsaPrivateKeySpec(pair.getPrivate().getEncoded()));
        keyringStore.putPublic("test.pub", "RSA", new RsaPublicKeySpec(pair.getPublic().getEncoded()));
        keyringStore.save(keyring);

        List<ObservedBuffer> cleared = new ArrayList<>();
        List<LogRecord> records = new ArrayList<>();
        Logger logger = Logger.getLogger(ZeroEchoLibSignatureWorkflow.class.getName());
        Level previousLevel = logger.getLevel();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                records.add(record);
            }

            @Override
            public void flush() {
                // No buffered output.
            }

            @Override
            public void close() {
                // No resources.
            }
        };
        logger.setLevel(Level.FINE);
        handler.setLevel(Level.FINE);
        logger.addHandler(handler);
        try (ZeroEchoLibSignatureWorkflow workflow = new ZeroEchoLibSignatureWorkflow("zeroecho-lib", keyring,
                root.resolve("cleanup-operations"), Clock.fixed(now, ZoneOffset.UTC), Duration.ofDays(90),
                "zeroecho-lib:", true, (category, bytes) -> cleared.add(new ObservedBuffer(category, bytes)));
                SignatureWorkflow.Registration registration = workflow.register((operationId, status) -> {
                    throw new IllegalStateException("DO_NOT_LOG_SIGNATURE_SENTINEL");
                })) {
            byte[] message = new byte[] { 7, 8, 9, 10 };
            PkiId signId = SigningSubmissionId.create(NAMESPACE, now, new SecureRandom()).id();
            SignatureWorkflow.SignRequest signRequest = request(signId, 1L, message,
                    new KeyRef("zeroecho-lib:test.prv"), Optional.empty());
            workflow.submitSign(signRequest);
            EncodedObject signature = workflow.status(signId).result().orElseThrow().signature().orElseThrow();
            assertTrue(signature.bytes().length > 0);

            AccessContext access = signRequest.accessContext();
            SignatureWorkflow.VerifyRequest verifyRequest = new SignatureWorkflow.VerifyRequest(access,
                    "SHA256withRSA", new EncodedObject(Encoding.BINARY, message), signature,
                    Optional.of(new KeyRef("zeroecho-lib:test.pub")), Optional.empty(), Optional.empty());
            PkiId verifyId = workflow.submitVerify(verifyRequest);
            assertEquals(Optional.of(true),
                    workflow.status(verifyId).result().orElseThrow().verified());

            byte[] invalidBytes = signature.bytes();
            invalidBytes[0] ^= 0x01;
            SignatureWorkflow.VerifyRequest invalidRequest = new SignatureWorkflow.VerifyRequest(access,
                    "SHA256withRSA", new EncodedObject(Encoding.BINARY, message),
                    new EncodedObject(Encoding.BINARY, invalidBytes),
                    Optional.of(new KeyRef("zeroecho-lib:test.pub")), Optional.empty(), Optional.empty());
            PkiId invalidId = workflow.submitVerify(invalidRequest);
            assertEquals(Optional.of(false),
                    workflow.status(invalidId).result().orElseThrow().verified());

            assertTrue(cleared.stream().anyMatch(value -> "sign-payload".equals(value.category())));
            assertTrue(cleared.stream().anyMatch(value -> "sign-result-copy".equals(value.category())));
            assertTrue(cleared.stream().anyMatch(value -> "verify-payload".equals(value.category())));
            assertTrue(cleared.stream().anyMatch(value -> "verify-signature".equals(value.category())));
            assertTrue(cleared.stream().anyMatch(value -> "persisted-operation-buffer".equals(value.category())));
            assertTrue(cleared.stream().allMatch(value -> isCleared(value.bytes())));
            assertTrue(records.stream().allMatch(record -> record.getThrown() == null));
            assertTrue(records.stream().noneMatch(record -> String.valueOf(record.getMessage())
                    .contains("DO_NOT_LOG_SIGNATURE_SENTINEL")));
            System.out.println("...clearedBuffers=" + cleared.size());
        } finally {
            logger.removeHandler(handler);
            logger.setLevel(previousLevel);
        }
        System.out.println("signingVerificationPersistenceAndCallbackCopiesAreCleared...ok");
    }

    @Test
    void unsupportedProviderRecordVersionFailsClosedWithRedactedDiagnostic(@TempDir Path root) throws Exception {
        Instant now = Instant.parse("2026-02-03T04:05:06.789Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        Path operations = root.resolve("unsupported-version");
        PkiId id = SigningSubmissionId.create(NAMESPACE, now, new SecureRandom()).id();
        byte[] payload = new byte[] { 91, 92, 93 };
        try (ZeroEchoLibSignatureWorkflow workflow = workflow(root, operations, clock)) {
            workflow.submitSign(request(id, 1L, payload));
        }

        Path record = onlyOperationRecord(operations);
        byte[] encoded = Files.readAllBytes(record);
        ByteBuffer.wrap(encoded).putInt(99);
        Files.write(record, encoded);

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> workflow(root, operations, clock));
        assertFalse(failure.toString().contains(id.value()));
        assertFalse(failure.toString().contains(java.util.Base64.getEncoder().encodeToString(payload)));
    }

    @Test
    void signingDeadlineIsStrictAndSlowCryptoCannotCommitLate(@TempDir Path root) throws Exception {
        Instant base = Instant.parse("2026-02-03T04:05:06Z");
        Path keyring = root.resolve("keyring.txt");
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        KeyringStore keyringStore = new KeyringStore(new zeroecho.sdk.ZeroEchoSession());
        keyringStore.putPrivate("test.prv", "RSA", new RsaPrivateKeySpec(pair.getPrivate().getEncoded()));
        keyringStore.putPublic("test.pub", "RSA", new RsaPublicKeySpec(pair.getPublic().getEncoded()));
        keyringStore.save(keyring);

        PkiId onTimeId = SigningSubmissionId.create(NAMESPACE, base, new SecureRandom()).id();
        Clock onTimeClock = Clock.fixed(base, ZoneOffset.UTC);
        try (ZeroEchoLibSignatureWorkflow workflow = workflow(root, root.resolve("on-time"), keyring, onTimeClock)) {
            SignatureWorkflow.SignRequest onTime = request(onTimeId, 1L, new byte[] { 1 },
                    new KeyRef("zeroecho-lib:test.prv"), Optional.of(base.plusNanos(1)));
            workflow.submitSign(onTime);
            assertEquals(SignatureWorkflow.State.SUCCEEDED, workflow.status(onTimeId).state());
        }

        PkiId exactId = SigningSubmissionId.create(NAMESPACE, base, new SecureRandom()).id();
        Clock exactClock = Clock.fixed(base, ZoneOffset.UTC);
        try (ZeroEchoLibSignatureWorkflow workflow = workflow(root, root.resolve("exact"), keyring, exactClock)) {
            SignatureWorkflow.SignRequest exact = request(exactId, 1L, new byte[] { 2 },
                    new KeyRef("zeroecho-lib:test.prv"), Optional.of(base));
            workflow.submitSign(exact);
            assertEquals(SignatureWorkflow.State.EXPIRED, workflow.status(exactId).state());
            assertEquals(Optional.empty(), workflow.status(exactId).result());
        }

        PkiId crossingId = SigningSubmissionId.create(NAMESPACE, base, new SecureRandom()).id();
        Instant deadline = base.plusSeconds(1);
        StepClock crossingClock = new StepClock(base, deadline, 6);
        Path crossingOperations = root.resolve("crossing");
        try (ZeroEchoLibSignatureWorkflow workflow = workflow(root, crossingOperations, keyring, crossingClock)) {
            SignatureWorkflow.SignRequest crossing = request(crossingId, 1L, new byte[] { 3 },
                    new KeyRef("zeroecho-lib:test.prv"), Optional.of(deadline));
            workflow.submitSign(crossing);
            assertEquals(SignatureWorkflow.State.EXPIRED, workflow.status(crossingId).state());
            assertEquals(Optional.empty(), workflow.status(crossingId).result());
        }
        try (ZeroEchoLibSignatureWorkflow restarted = workflow(root, crossingOperations, keyring,
                Clock.fixed(deadline, ZoneOffset.UTC))) {
            assertEquals(SignatureWorkflow.State.EXPIRED, restarted.status(crossingId).state());
            assertEquals(Optional.empty(), restarted.status(crossingId).result());
        }
    }

    @Test
    void encodedObjectAndSigningRequestDefensivelySnapshotBytes() {
        byte[] source = new byte[] { 1, 2, 3 };
        EncodedObject encoded = new EncodedObject(Encoding.BINARY, source);
        source[0] = 9;
        byte[] exposed = encoded.bytes();
        exposed[1] = 9;
        assertEquals(1, encoded.bytes()[0]);
        assertEquals(2, encoded.bytes()[1]);

        PkiId id = SigningSubmissionId.create(NAMESPACE, Instant.parse("2026-02-03T04:05:06Z"),
                new SecureRandom()).id();
        SignatureWorkflow.SignRequest request = request(id, 1L, encoded.bytes());
        byte[] requestBytes = request.payload().bytes();
        requestBytes[2] = 9;
        assertEquals(3, request.payload().bytes()[2]);
        assertEquals(request.semanticFingerprint(), SignatureWorkflow.SignRequest.fingerprint(NAMESPACE,
                request.accessContext(), request.keyRef(), request.algorithmId(), request.payload(),
                request.preferredSignatureEncoding(), request.deadline()));
    }

    @Test
    void restartAttachConflictExpiryAndFence(@TempDir Path root) {
        Instant now = Instant.parse("2026-02-03T04:05:06.789Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        Path operations = root.resolve("operations");
        PkiId id = SigningSubmissionId.create(NAMESPACE, now, new SecureRandom()).id();
        SignatureWorkflow.SignRequest request = request(id, 2L, new byte[] { 1 });

        try (ZeroEchoLibSignatureWorkflow workflow = workflow(root, operations, clock)) {
            assertEquals(id, workflow.submitSign(request));
            assertEquals(SignatureWorkflow.State.FAILED, workflow.status(id).state());
        }

        try (ZeroEchoLibSignatureWorkflow restarted = workflow(root, operations, clock)) {
            assertEquals(SignatureWorkflow.State.FAILED, restarted.status(id).state());
            assertEquals(id, restarted.submitSign(request));
            assertThrows(IllegalStateException.class, () -> restarted.submitSign(request(id, 1L, new byte[] { 1 })));
            assertThrows(IllegalStateException.class, () -> restarted.submitSign(request(id, 3L, new byte[] { 2 })));
        }
        forcePersistedStateCode(operations, 50, 30);
        try (ZeroEchoLibSignatureWorkflow recovered = workflow(root, operations, clock)) {
            assertEquals(SignatureWorkflow.State.FAILED, recovered.status(id).state());
            assertEquals("RECOVERY_INCOMPLETE", recovered.status(id).detailCode().orElseThrow());
        }

        Clock expired = Clock.fixed(now.plus(Duration.ofDays(90)), ZoneOffset.UTC);
        try (ZeroEchoLibSignatureWorkflow restarted = workflow(root, operations, expired)) {
            assertEquals(SignatureWorkflow.State.EXPIRED, restarted.status(id).state());
            PkiId expiredId = SigningSubmissionId.create(NAMESPACE, now, new SecureRandom()).id();
            assertThrows(IllegalArgumentException.class,
                    () -> restarted.submitSign(request(expiredId, 1L, new byte[] { 3 })));
        }
    }

    @Test
    void concurrentAttachCancelAndReentrantCallbackAreOperationLocal(@TempDir Path root) throws Exception {
        Instant now = Instant.parse("2026-02-03T04:05:06.789Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        PkiId firstId = SigningSubmissionId.create(NAMESPACE, now, new SecureRandom()).id();
        PkiId secondId = SigningSubmissionId.create(NAMESPACE, now, new SecureRandom()).id();
        SignatureWorkflow.SignRequest first = request(firstId, 1L, new byte[] { 1 });
        SignatureWorkflow.SignRequest second = request(secondId, 1L, new byte[] { 2 });
        CountDownLatch callbackEntered = new CountDownLatch(1);
        CountDownLatch callbackRelease = new CountDownLatch(1);
        try (ZeroEchoLibSignatureWorkflow workflow = workflow(root, root.resolve("operations"), clock);
                ExecutorService executor = Executors.newFixedThreadPool(3);
                SignatureWorkflow.Registration registration = workflow.register((operationId, status) -> {
                    if (firstId.equals(operationId) && status.state() == SignatureWorkflow.State.RUNNING) {
                        assertEquals(SignatureWorkflow.State.RUNNING, workflow.status(operationId).state());
                        callbackEntered.countDown();
                        try {
                            callbackRelease.await();
                        } catch (InterruptedException ex) {
                            Thread.currentThread().interrupt();
                            throw new IllegalStateException(ex);
                        }
                    }
                })) {
            Future<PkiId> firstFuture = executor.submit(() -> workflow.submitSign(first));
            assertEquals(true, callbackEntered.await(5, TimeUnit.SECONDS));
            assertEquals(firstId, executor.submit(() -> workflow.submitSign(first)).get(5, TimeUnit.SECONDS));
            assertEquals(secondId, executor.submit(() -> workflow.submitSign(second)).get(5, TimeUnit.SECONDS));
            assertEquals(true, workflow.cancel(firstId, 2L, "test cancellation"));
            callbackRelease.countDown();
            assertEquals(firstId, firstFuture.get(5, TimeUnit.SECONDS));
            assertEquals(SignatureWorkflow.State.CANCELLED, workflow.status(firstId).state());
            assertEquals(false, workflow.cancel(firstId, 1L, "stale"));
        }
    }

    @Test
    void concurrentWatermarkWritesNeverRegressAcrossRestart(@TempDir Path root) throws Exception {
        Instant base = Instant.parse("2026-02-03T04:05:06.789Z");
        Instant high = base.plusSeconds(60);
        LatchClock clock = new LatchClock(base);
        Path operations = root.resolve("operations");
        try (ZeroEchoLibSignatureWorkflow workflow = workflow(root, operations, clock);
                ExecutorService executor = Executors.newFixedThreadPool(2)) {
            clock.arm(high);
            Future<?> highRead = executor.submit(() -> workflow.status(new PkiId("unknown-high")));
            assertEquals(true, clock.observed.await(5, TimeUnit.SECONDS));
            clock.set(base.minusSeconds(60));
            Future<?> rollbackRead = executor.submit(() -> workflow.status(new PkiId("unknown-low")));
            clock.release.countDown();
            highRead.get(5, TimeUnit.SECONDS);
            rollbackRead.get(5, TimeUnit.SECONDS);
            assertEquals(high.toEpochMilli(), Long.parseLong(Files.readString(
                    operations.resolve("TIME_WATERMARK")).trim()));
        }
        clock.set(base.minusSeconds(120));
        try (ZeroEchoLibSignatureWorkflow restarted = workflow(root, operations, clock)) {
            restarted.status(new PkiId("unknown-restart"));
            assertEquals(high.toEpochMilli(), Long.parseLong(Files.readString(
                    operations.resolve("TIME_WATERMARK")).trim()));
        }
    }

    private static ZeroEchoLibSignatureWorkflow workflow(Path root, Path operations, Clock clock) {
        return workflow(root, operations, root.resolve("missing-keyring"), clock);
    }

    private static ZeroEchoLibSignatureWorkflow workflow(Path root, Path operations, Path keyring, Clock clock) {
        return new ZeroEchoLibSignatureWorkflow("zeroecho-lib", keyring, operations, clock,
                Duration.ofDays(90), "zeroecho-lib:", true);
    }

    private static SignatureWorkflow.SignRequest request(PkiId id, long fence, byte[] payload) {
        return request(id, fence, payload, new KeyRef("zeroecho-lib:missing.prv"), Optional.empty());
    }

    private static SignatureWorkflow.SignRequest request(PkiId id, long fence, byte[] payload, KeyRef keyRef,
            Optional<Instant> deadline) {
        AccessContext access = new AccessContext(new Principal("TEST", "owner"), new Purpose("TEST"),
                Optional.empty(), Optional.empty());
        return SignatureWorkflow.SignRequest.create(id, NAMESPACE, fence, access,
                keyRef, "SHA256withRSA", new EncodedObject(Encoding.BINARY, payload),
                Optional.of(Encoding.BINARY), deadline);
    }

    private static void forcePersistedStateCode(Path operations, int from, int to) {
        try {
            Path record;
            try (java.util.stream.Stream<Path> paths = Files.list(operations.resolve("records"))) {
                record = paths.filter(Files::isRegularFile).findFirst().orElseThrow();
            }
            byte[] bytes = Files.readAllBytes(record);
            for (int index = bytes.length - Integer.BYTES; index >= 0; index--) {
                if (bytes[index] == 0 && bytes[index + 1] == 0 && bytes[index + 2] == 0
                        && Byte.toUnsignedInt(bytes[index + 3]) == from) {
                    bytes[index + 3] = (byte) to;
                    Files.write(record, bytes);
                    return;
                }
            }
            throw new IllegalStateException("Persisted state code not found");
        } catch (java.io.IOException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static Path onlyOperationRecord(Path operations) throws java.io.IOException {
        try (java.util.stream.Stream<Path> paths = Files.list(operations.resolve("records"))) {
            return paths.filter(Files::isRegularFile).findFirst().orElseThrow();
        }
    }

    private static boolean isCleared(byte[] bytes) {
        for (byte value : bytes) {
            if (value != 0) {
                return false;
            }
        }
        return true;
    }

    private record ObservedBuffer(String category, byte[] bytes) {
    }

    private static final class LatchClock extends Clock {
        private final AtomicBoolean block = new AtomicBoolean();
        private final CountDownLatch observed = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);
        private volatile Instant value;

        private LatchClock(Instant value) {
            this.value = value;
        }

        private void arm(Instant next) {
            value = next;
            block.set(true);
        }

        private void set(Instant next) {
            value = next;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            Instant observedValue = value;
            if (block.compareAndSet(true, false)) {
                observed.countDown();
                try {
                    release.await();
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(ex);
                }
            }
            return observedValue;
        }
    }

    private static final class StepClock extends Clock {
        private final Instant initial;
        private final Instant advanced;
        private final int initialReads;
        private final AtomicInteger reads = new AtomicInteger();

        private StepClock(Instant initial, Instant advanced, int initialReads) {
            this.initial = initial;
            this.advanced = advanced;
            this.initialReads = initialReads;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return reads.incrementAndGet() <= initialReads ? initial : advanced;
        }
    }
}
