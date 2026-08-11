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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
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

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.storage.KeyringStore;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.policy.CryptoPolicy;
import zeroecho.core.spec.ContextSpec;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.sdk.ZeroEchoSession;

final class ZeroEchoLibSignatureWorkflowPersistenceTest {

    private static final String NAMESPACE = "0123456789abcdef0123456789abcdef.zeroecho-lib";

    @Test
    void signingVerificationPersistenceAndCallbackCopiesAreCleared(@TempDir Path root) throws Exception {
        System.out.println("signingVerificationPersistenceAndCallbackCopiesAreCleared");
        Instant now = Instant.parse("2026-02-03T04:05:06.789Z");
        Path keyring = root.resolve("keyring.txt");
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        try (zeroecho.core.storage.KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keyringStore = KeyringStore.create(keyring, password)) {
            keyringStore.putPrivate("test.prv", "RSA", pair.getPrivate());
            keyringStore.putPublic("test.pub", "RSA", pair.getPublic());
        }

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
                "zeroecho-lib:", true, TestKeyringUnlocks.provider(),
                (category, bytes) -> cleared.add(new ObservedBuffer(category, bytes)));
                SignatureWorkflow.Registration registration = workflow.register((operationId, status) -> {
                    throw new IllegalStateException("DO_NOT_LOG_SIGNATURE_SENTINEL");
                })) {
            byte[] message = new byte[] { 7, 8, 9, 10 };
            PkiId signId = SigningSubmissionId.create(NAMESPACE, now, new SecureRandom()).id();
            SignatureWorkflow.SignRequest signRequest = request(signId, 1L, message,
                    new KeyRef("zeroecho-lib:test.prv"), Optional.empty());
            workflow.submitSign(signRequest, control());
            EncodedObject signature = workflow.status(signId, control()).result().orElseThrow().signature().orElseThrow();
            assertTrue(signature.bytes().length > 0);

            AccessContext access = signRequest.accessContext();
            SignatureWorkflow.VerifyRequest verifyRequest = new SignatureWorkflow.VerifyRequest(access, "SHA256withRSA",
                    new ImmutableByteContent(message), signature, Optional.of(new KeyRef("zeroecho-lib:test.pub")),
                    Optional.empty(), Optional.empty(), CancellationSignal.NONE);
            PkiId verifyId = workflow.submitVerify(verifyRequest, control());
            assertEquals(Optional.of(true), workflow.status(verifyId, control()).result().orElseThrow().verified());

            byte[] invalidBytes = signature.bytes();
            invalidBytes[0] ^= 0x01;
            SignatureWorkflow.VerifyRequest invalidRequest = new SignatureWorkflow.VerifyRequest(access,
                    "SHA256withRSA", new ImmutableByteContent(message),
                    new EncodedObject(Encoding.BINARY, invalidBytes), Optional.of(new KeyRef("zeroecho-lib:test.pub")),
                    Optional.empty(), Optional.empty(), CancellationSignal.NONE);
            PkiId invalidId = workflow.submitVerify(invalidRequest, control());
            assertEquals(Optional.of(false), workflow.status(invalidId, control()).result().orElseThrow().verified());

            assertTrue(cleared.stream().anyMatch(value -> "sign-result-copy".equals(value.category())));
            assertTrue(cleared.stream().anyMatch(value -> "verify-signature".equals(value.category())));
            assertTrue(cleared.stream().anyMatch(value -> "persisted-operation-buffer".equals(value.category())));
            assertTrue(cleared.stream().allMatch(value -> isCleared(value.bytes())));
            assertTrue(records.stream().allMatch(record -> record.getThrown() == null));
            assertTrue(records.stream().noneMatch(
                    record -> String.valueOf(record.getMessage()).contains("DO_NOT_LOG_SIGNATURE_SENTINEL")));
            System.out.println("...clearedBuffers=" + cleared.size());
        } finally {
            logger.removeHandler(handler);
            logger.setLevel(previousLevel);
        }
        byte[] privateEncoding = pair.getPrivate().getEncoded();
        try (java.util.stream.Stream<Path> paths = Files.walk(root.resolve("cleanup-operations"))) {
            for (Path path : paths.filter(Files::isRegularFile).toList()) {
                byte[] persisted = Files.readAllBytes(path);
                try {
                    assertFalse(contains(persisted, privateEncoding));
                } finally {
                    Arrays.fill(persisted, (byte) 0);
                }
            }
        } finally {
            Arrays.fill(privateEncoding, (byte) 0);
        }
        System.out.println("signingVerificationPersistenceAndCallbackCopiesAreCleared...ok");
    }

    @Test
    void signingMapsCanonicalInvalidMissingForeignAndMismatchedInputs(@TempDir Path root) throws Exception {
        System.out.println("signingMapsCanonicalInvalidMissingForeignAndMismatchedInputs");
        Instant now = Instant.parse("2026-02-03T04:05:06.789Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        Path keyring = root.resolve("mapping-keyring.zek");
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        try (zeroecho.core.storage.KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keyringStore = KeyringStore.create(keyring, password)) {
            keyringStore.putPrivate("test.prv", "RSA", pair.getPrivate());
            keyringStore.putPublic("test.pub", "RSA", pair.getPublic());
        }

        AtomicInteger terminalPublications = new AtomicInteger();
        try (ZeroEchoLibSignatureWorkflow workflow = workflow(root, root.resolve("mapping-operations"), keyring,
                clock);
                SignatureWorkflow.Registration registration = workflow.register((operationId, status) -> {
                    if (status.state() != SignatureWorkflow.State.RUNNING) {
                        terminalPublications.incrementAndGet();
                    }
                })) {
            PkiId canonicalId = SigningSubmissionId.create(NAMESPACE, now, new SecureRandom()).id();
            SignatureWorkflow.SignRequest canonical = request(canonicalId, 1L, new byte[] { 1, 2, 3 },
                    new KeyRef("zeroecho-lib:test.prv"), Optional.empty(),
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm());
            workflow.submitSign(canonical, control());
            assertEquals(SignatureWorkflow.State.SUCCEEDED, workflow.status(canonicalId, control()).state());

            assertSigningFailure(workflow, now, "SHA1withRSA", new KeyRef("zeroecho-lib:test.prv"),
                    ZeroEchoLibSignatureWorkflow.DC_INVALID_ALGORITHM_ID);
            assertSigningFailure(workflow, now, BootstrapAlgorithmIdentities.SHA256.canonicalForm(),
                    new KeyRef("zeroecho-lib:test.prv"), ZeroEchoLibSignatureWorkflow.DC_INVALID_ALGORITHM_ID);
            assertSigningFailure(workflow, now, "SHA256withRSA", new KeyRef("zeroecho-lib:missing.prv"),
                    ZeroEchoLibSignatureWorkflow.DC_KEY_NOT_FOUND);
            assertSigningFailure(workflow, now, "SHA256withRSA", new KeyRef("foreign:test.prv"),
                    ZeroEchoLibSignatureWorkflow.DC_INVALID_KEYREF_PREFIX);
            assertSigningFailure(workflow, now, "SHA256withECDSA", new KeyRef("zeroecho-lib:test.prv"),
                    ZeroEchoLibSignatureWorkflow.DC_ALGORITHM_MISMATCH);
            assertEquals(6, terminalPublications.get());
        }
        System.out.println("signingMapsCanonicalInvalidMissingForeignAndMismatchedInputs...ok");
    }

    @Test
    void signingCancellationIsTerminalOnlyForRequestedCancellation(@TempDir Path root) throws Exception {
        System.out.println("signingCancellationIsTerminalOnlyForRequestedCancellation");
        Instant now = Instant.parse("2026-02-03T04:05:06.789Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        Path keyring = root.resolve("cancellation-keyring.zek");
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        try (zeroecho.core.storage.KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keyringStore = KeyringStore.create(keyring, password)) {
            keyringStore.putPrivate("test.prv", "RSA", pair.getPrivate());
        }

        AtomicInteger terminalPublications = new AtomicInteger();
        try (ZeroEchoLibSignatureWorkflow workflow = workflow(root, root.resolve("cancellation-operations"), keyring,
                clock);
                SignatureWorkflow.Registration registration = workflow.register((operationId, status) -> {
                    if (status.state() != SignatureWorkflow.State.RUNNING) {
                        terminalPublications.incrementAndGet();
                    }
                })) {
            PkiId beforeId = SigningSubmissionId.create(NAMESPACE, now, new SecureRandom()).id();
            SignatureWorkflow.SignRequest beforeBase = request(beforeId, 1L, new byte[] { 1 });
            AtomicInteger cancellationChecks = new AtomicInteger();
            workflow.submitSign(withCancellation(beforeBase, () -> {
                if (cancellationChecks.incrementAndGet() > 1) {
                    throw new IllegalStateException("CANCELLATION_RECHECK_SENTINEL");
                }
                return true;
            }), control());
            assertEquals(1, cancellationChecks.get());
            assertEquals(SignatureWorkflow.State.CANCELLED, workflow.status(beforeId, control()).state());
            assertEquals(Optional.of(ZeroEchoLibSignatureWorkflow.DC_CANCELLED),
                    workflow.status(beforeId, control()).detailCode());

            AtomicBoolean armed = new AtomicBoolean();
            AtomicBoolean cancelled = new AtomicBoolean();
            byte[] payload = new byte[32 * 1024];
            RepeatableContent streaming = repeatableContent(payload, input -> {
                if (armed.get() && input > 0) {
                    cancelled.set(true);
                }
            });
            PkiId streamingId = SigningSubmissionId.create(NAMESPACE, now, new SecureRandom()).id();
            SignatureWorkflow.SignRequest streamingRequest = request(streamingId, 1L, streaming,
                    new KeyRef("zeroecho-lib:test.prv"), "SHA256withRSA", cancelled::get);
            armed.set(true);
            workflow.submitSign(streamingRequest, control());
            assertEquals(SignatureWorkflow.State.CANCELLED, workflow.status(streamingId, control()).state());
            assertEquals(Optional.of(ZeroEchoLibSignatureWorkflow.DC_CANCELLED),
                    workflow.status(streamingId, control()).detailCode());

            AtomicBoolean failReads = new AtomicBoolean();
            RepeatableContent interruptedIo = new RepeatableContent() {
                @Override
                public InputStream openStream() {
                    if (failReads.get()) {
                        return new InputStream() {
                            @Override
                            public int read() throws IOException {
                                throw new InterruptedIOException("controlled interruption");
                            }
                        };
                    }
                    return new ByteArrayInputStream(new byte[] { 4, 5, 6 });
                }

                @Override
                public OptionalLong length() {
                    return OptionalLong.of(3);
                }

                @Override
                public String contentId() {
                    return "interrupted-io-content";
                }

                @Override
                public void close() {
                    // Caller owns this test content.
                }
            };
            PkiId ioId = SigningSubmissionId.create(NAMESPACE, now, new SecureRandom()).id();
            SignatureWorkflow.SignRequest ioRequest = request(ioId, 1L, interruptedIo,
                    new KeyRef("zeroecho-lib:test.prv"), "SHA256withRSA", CancellationSignal.NONE);
            failReads.set(true);
            workflow.submitSign(ioRequest, control());
            assertEquals(SignatureWorkflow.State.FAILED, workflow.status(ioId, control()).state());
            assertEquals(Optional.of(ZeroEchoLibSignatureWorkflow.DC_KEYRING_IO_ERROR),
                    workflow.status(ioId, control()).detailCode());
            assertEquals(3, terminalPublications.get());
        }
        System.out.println("signingCancellationIsTerminalOnlyForRequestedCancellation...ok");
    }

    @Test
    void providerFailureTerminalizesExactlyOnce(@TempDir Path root) throws Exception {
        System.out.println("providerFailureTerminalizesExactlyOnce");
        Instant now = Instant.parse("2026-02-03T04:05:06.789Z");
        Path keyring = root.resolve("provider-keyring.zek");
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        try (zeroecho.core.storage.KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore created = KeyringStore.create(keyring, password)) {
            created.putPrivate("test.prv", "RSA", pair.getPrivate());
        }

        KeyringStore opened;
        try (zeroecho.core.storage.KeyringPassword password = TestKeyringUnlocks.provider().acquire()) {
            opened = KeyringStore.open(keyring, password);
        }
        ZeroEchoSession denied = new ZeroEchoSession().withPolicy(
                (CryptoPolicy<ContextSpec, Key>) (algorithm, role, key, spec) -> {
                    throw new ProviderException("PROVIDER_POLICY_RUNTIME_SENTINEL");
                });
        AtomicInteger terminalPublications = new AtomicInteger();
        try (ZeroEchoLibSignatureWorkflow workflow = new ZeroEchoLibSignatureWorkflow("zeroecho-lib", keyring,
                root.resolve("provider-operations"), Clock.fixed(now, ZoneOffset.UTC), Duration.ofDays(90),
                "zeroecho-lib:", true, TestKeyringUnlocks.provider(),
                new ZeroEchoLibSignatureWorkflow.SigningDependencies(opened, denied));
                SignatureWorkflow.Registration registration = workflow.register((operationId, status) -> {
                    if (status.state() != SignatureWorkflow.State.RUNNING) {
                        terminalPublications.incrementAndGet();
                    }
                })) {
            PkiId id = SigningSubmissionId.create(NAMESPACE, now, new SecureRandom()).id();
            workflow.submitSign(request(id, 1L, new byte[] { 6, 7, 8 }, new KeyRef("zeroecho-lib:test.prv"),
                    Optional.empty()), control());
            assertEquals(SignatureWorkflow.State.FAILED, workflow.status(id, control()).state());
            assertEquals(Optional.of(ZeroEchoLibSignatureWorkflow.DC_CRYPTO_FAILURE),
                    workflow.status(id, control()).detailCode());
            assertEquals(1, terminalPublications.get());
        }
        System.out.println("providerFailureTerminalizesExactlyOnce...ok");
    }

    @Test
    void unsupportedProviderRecordVersionFailsClosedWithRedactedDiagnostic(@TempDir Path root) throws Exception {
        Instant now = Instant.parse("2026-02-03T04:05:06.789Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        Path operations = root.resolve("unsupported-version");
        PkiId id = SigningSubmissionId.create(NAMESPACE, now, new SecureRandom()).id();
        byte[] payload = new byte[] { 91, 92, 93 };
        try (ZeroEchoLibSignatureWorkflow workflow = workflow(root, operations, clock)) {
            workflow.submitSign(request(id, 1L, payload), control());
        }

        Path record = onlyOperationRecord(operations);
        byte[] encoded = Files.readAllBytes(record);
        byte[] valid = encoded.clone();
        ByteBuffer.wrap(encoded).putInt(99);
        Files.write(record, encoded);

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> workflow(root, operations, clock));
        assertFalse(failure.toString().contains(id.value()));
        assertFalse(failure.toString().contains(java.util.Base64.getEncoder().encodeToString(payload)));

        Files.write(record, valid);
        try (ZeroEchoLibSignatureWorkflow reopened = workflow(root, operations, clock)) {
            assertEquals(SignatureWorkflow.State.FAILED, reopened.status(id, control()).state());
        }
    }

    @Test
    void signingDeadlineIsStrictAndSlowCryptoCannotCommitLate(@TempDir Path root) throws Exception {
        Instant base = Instant.parse("2026-02-03T04:05:06Z");
        Path keyring = root.resolve("keyring.txt");
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        try (zeroecho.core.storage.KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keyringStore = KeyringStore.create(keyring, password)) {
            keyringStore.putPrivate("test.prv", "RSA", pair.getPrivate());
            keyringStore.putPublic("test.pub", "RSA", pair.getPublic());
        }

        PkiId onTimeId = SigningSubmissionId.create(NAMESPACE, base, new SecureRandom()).id();
        Clock onTimeClock = Clock.fixed(base, ZoneOffset.UTC);
        try (ZeroEchoLibSignatureWorkflow workflow = workflow(root, root.resolve("on-time"), keyring, onTimeClock)) {
            SignatureWorkflow.SignRequest onTime = request(onTimeId, 1L, new byte[] { 1 },
                    new KeyRef("zeroecho-lib:test.prv"), Optional.of(base.plusNanos(1)));
            workflow.submitSign(onTime, control());
            assertEquals(SignatureWorkflow.State.SUCCEEDED, workflow.status(onTimeId, control()).state());
        }

        PkiId exactId = SigningSubmissionId.create(NAMESPACE, base, new SecureRandom()).id();
        Clock exactClock = Clock.fixed(base, ZoneOffset.UTC);
        try (ZeroEchoLibSignatureWorkflow workflow = workflow(root, root.resolve("exact"), keyring, exactClock)) {
            SignatureWorkflow.SignRequest exact = request(exactId, 1L, new byte[] { 2 },
                    new KeyRef("zeroecho-lib:test.prv"), Optional.of(base));
            workflow.submitSign(exact, control());
            assertEquals(SignatureWorkflow.State.EXPIRED, workflow.status(exactId, control()).state());
            assertEquals(Optional.empty(), workflow.status(exactId, control()).result());
        }

        PkiId crossingId = SigningSubmissionId.create(NAMESPACE, base, new SecureRandom()).id();
        Instant deadline = base.plusSeconds(1);
        StepClock crossingClock = new StepClock(base, deadline, 6);
        Path crossingOperations = root.resolve("crossing");
        try (ZeroEchoLibSignatureWorkflow workflow = workflow(root, crossingOperations, keyring, crossingClock)) {
            SignatureWorkflow.SignRequest crossing = request(crossingId, 1L, new byte[] { 3 },
                    new KeyRef("zeroecho-lib:test.prv"), Optional.of(deadline));
            workflow.submitSign(crossing, control());
            assertEquals(SignatureWorkflow.State.EXPIRED, workflow.status(crossingId, control()).state());
            assertEquals(Optional.empty(), workflow.status(crossingId, control()).result());
        }
        try (ZeroEchoLibSignatureWorkflow restarted = workflow(root, crossingOperations, keyring,
                Clock.fixed(deadline, ZoneOffset.UTC))) {
            assertEquals(SignatureWorkflow.State.EXPIRED, restarted.status(crossingId, control()).state());
            assertEquals(Optional.empty(), restarted.status(crossingId, control()).result());
        }
    }

    @Test
    void callDeadlineAfterDurableAcceptanceTerminalizesBeforePropagation(@TempDir Path root) throws Exception {
        Instant acceptedAt = Instant.parse("2026-02-03T04:05:06Z");
        Instant callDeadline = acceptedAt.plusSeconds(1);
        LatchClock clock = new LatchClock(acceptedAt);
        Path operations = root.resolve("post-accept-call-deadline");
        PkiId operationId = SigningSubmissionId.create(NAMESPACE, acceptedAt, new SecureRandom()).id();
        SignatureWorkflow.CallControl expiring = new SignatureWorkflow.CallControl(callDeadline,
                CancellationSignal.NONE);

        try (ZeroEchoLibSignatureWorkflow workflow = workflow(root, operations, clock);
                SignatureWorkflow.Registration ignored = workflow.register((id, status) -> {
                    if (operationId.equals(id) && status.state() == SignatureWorkflow.State.RUNNING) {
                        clock.set(callDeadline);
                    }
                })) {
            assertThrows(IllegalStateException.class,
                    () -> workflow.submitSign(request(operationId, 1L, new byte[] { 4 }), expiring));
            SignatureWorkflow.OperationStatus terminal = workflow.status(operationId, control());
            assertEquals(SignatureWorkflow.State.EXPIRED, terminal.state());
            assertEquals(Optional.empty(), terminal.result());
        }

        try (ZeroEchoLibSignatureWorkflow restarted = workflow(root, operations,
                Clock.fixed(callDeadline, ZoneOffset.UTC))) {
            assertEquals(SignatureWorkflow.State.EXPIRED, restarted.status(operationId, control()).state());
            assertEquals(Optional.empty(), restarted.status(operationId, control()).result());
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

        PkiId id = SigningSubmissionId.create(NAMESPACE, Instant.parse("2026-02-03T04:05:06Z"), new SecureRandom())
                .id();
        SignatureWorkflow.SignRequest request = request(id, 1L, encoded.bytes());
        byte[] requestBytes = ((ImmutableByteContent) request.content()).copyBytes();
        requestBytes[2] = 9;
        assertEquals(3, ((ImmutableByteContent) request.content()).copyBytes()[2]);
        assertEquals(request.semanticFingerprint(),
                SignatureWorkflow.SignRequest.fingerprint(NAMESPACE, request.accessContext(), request.keyRef(),
                        request.algorithmId(), request.content(), request.preferredSignatureEncoding(),
                        request.deadline()));
    }

    @Test
    void restartAttachConflictExpiryAndFence(@TempDir Path root) {
        Instant now = Instant.parse("2026-02-03T04:05:06.789Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        Path operations = root.resolve("operations");
        PkiId id = SigningSubmissionId.create(NAMESPACE, now, new SecureRandom()).id();
        SignatureWorkflow.SignRequest request = request(id, 2L, new byte[] { 1 });

        try (ZeroEchoLibSignatureWorkflow workflow = workflow(root, operations, clock)) {
            assertEquals(id, workflow.submitSign(request, control()));
            assertEquals(SignatureWorkflow.State.FAILED, workflow.status(id, control()).state());
        }

        try (ZeroEchoLibSignatureWorkflow restarted = workflow(root, operations, clock)) {
            assertEquals(SignatureWorkflow.State.FAILED, restarted.status(id, control()).state());
            assertEquals(id, restarted.submitSign(request, control()));
            assertThrows(IllegalStateException.class,
                    () -> restarted.submitSign(request(id, 1L, new byte[] { 1 }), control()));
            assertThrows(IllegalStateException.class,
                    () -> restarted.submitSign(request(id, 3L, new byte[] { 2 }), control()));
        }
        forcePersistedStateCode(operations, 50, 30);
        try (ZeroEchoLibSignatureWorkflow recovered = workflow(root, operations, clock)) {
            assertEquals(SignatureWorkflow.State.FAILED, recovered.status(id, control()).state());
            assertEquals("RECOVERY_INCOMPLETE", recovered.status(id, control()).detailCode().orElseThrow());
        }

        Clock expired = Clock.fixed(now.plus(Duration.ofDays(90)), ZoneOffset.UTC);
        try (ZeroEchoLibSignatureWorkflow restarted = workflow(root, operations, expired)) {
            assertEquals(SignatureWorkflow.State.EXPIRED, restarted.status(id, control()).state());
            PkiId expiredId = SigningSubmissionId.create(NAMESPACE, now, new SecureRandom()).id();
            assertThrows(IllegalArgumentException.class,
                    () -> restarted.submitSign(request(expiredId, 1L, new byte[] { 3 }), control()));
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
                        assertEquals(SignatureWorkflow.State.RUNNING, workflow.status(operationId, control()).state());
                        callbackEntered.countDown();
                        try {
                            callbackRelease.await();
                        } catch (InterruptedException ex) {
                            Thread.currentThread().interrupt();
                            throw new IllegalStateException(ex);
                        }
                    }
                })) {
            Future<PkiId> firstFuture = executor.submit(() -> workflow.submitSign(first, control()));
            assertEquals(true, callbackEntered.await(5, TimeUnit.SECONDS));
            assertEquals(firstId, executor.submit(() -> workflow.submitSign(first, control())).get(5, TimeUnit.SECONDS));
            assertEquals(secondId, executor.submit(() -> workflow.submitSign(second, control())).get(5, TimeUnit.SECONDS));
            assertEquals(true, workflow.cancel(firstId, 2L, "test cancellation", control()));
            callbackRelease.countDown();
            assertEquals(firstId, firstFuture.get(5, TimeUnit.SECONDS));
            assertEquals(SignatureWorkflow.State.CANCELLED, workflow.status(firstId, control()).state());
            assertTrue(workflow.cancel(firstId, 2L, "test cancellation", control()));
            assertTrue(workflow.cancel(firstId, 2L, "different cancellation", control()));
            assertEquals(false, workflow.cancel(firstId, 1L, "stale", control()));
        }
        try (ZeroEchoLibSignatureWorkflow restarted = workflow(root, root.resolve("operations"), clock)) {
            assertTrue(restarted.cancel(firstId, 2L, "different cancellation after restart", control()));
            assertFalse(restarted.cancel(firstId, 1L, "test cancellation", control()));
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
            Future<?> highRead = executor.submit(() -> workflow.status(new PkiId("unknown-high"), control()));
            assertEquals(true, clock.observed.await(5, TimeUnit.SECONDS));
            clock.set(base.minusSeconds(60));
            Future<?> rollbackRead = executor.submit(() -> workflow.status(new PkiId("unknown-low"), control()));
            clock.release.countDown();
            highRead.get(5, TimeUnit.SECONDS);
            rollbackRead.get(5, TimeUnit.SECONDS);
            assertEquals(high.toEpochMilli(),
                    Long.parseLong(Files.readString(operations.resolve("TIME_WATERMARK")).trim()));
        }
        clock.set(base.minusSeconds(120));
        try (ZeroEchoLibSignatureWorkflow restarted = workflow(root, operations, clock)) {
            restarted.status(new PkiId("unknown-restart"), control());
            assertEquals(high.toEpochMilli(),
                    Long.parseLong(Files.readString(operations.resolve("TIME_WATERMARK")).trim()));
        }
    }

    private static ZeroEchoLibSignatureWorkflow workflow(Path root, Path operations, Clock clock) {
        return workflow(root, operations, root.resolve("missing-keyring"), clock);
    }

    private static ZeroEchoLibSignatureWorkflow workflow(Path root, Path operations, Path keyring, Clock clock) {
        return new ZeroEchoLibSignatureWorkflow("zeroecho-lib", keyring, operations, clock, Duration.ofDays(90),
                "zeroecho-lib:", true, TestKeyringUnlocks.provider());
    }

    private static SignatureWorkflow.SignRequest request(PkiId id, long fence, byte[] payload) {
        return request(id, fence, payload, new KeyRef("zeroecho-lib:missing.prv"), Optional.empty());
    }

    private static SignatureWorkflow.SignRequest request(PkiId id, long fence, byte[] payload, KeyRef keyRef,
            Optional<Instant> deadline) {
        return request(id, fence, payload, keyRef, deadline, "SHA256withRSA");
    }

    private static SignatureWorkflow.SignRequest request(PkiId id, long fence, byte[] payload, KeyRef keyRef,
            Optional<Instant> deadline, String algorithmId) {
        AccessContext access = new AccessContext(new Principal("TEST", "owner"), new Purpose("TEST"), Optional.empty(),
                Optional.empty());
        return SignatureWorkflow.SignRequest.create(id, NAMESPACE, fence, access, keyRef, algorithmId,
                new ImmutableByteContent(payload), Optional.of(Encoding.BINARY), deadline);
    }

    private static SignatureWorkflow.SignRequest request(PkiId id, long fence, RepeatableContent content,
            KeyRef keyRef, String algorithmId, CancellationSignal cancellation) {
        AccessContext access = new AccessContext(new Principal("TEST", "owner"), new Purpose("TEST"), Optional.empty(),
                Optional.empty());
        Optional<Encoding> encoding = Optional.of(Encoding.BINARY);
        Optional<Instant> deadline = Optional.empty();
        String fingerprint = SignatureWorkflow.SignRequest.fingerprint(NAMESPACE, access, keyRef, algorithmId,
                content, encoding, deadline);
        return new SignatureWorkflow.SignRequest(id, NAMESPACE, fingerprint, fence, access, keyRef, algorithmId,
                content, encoding, deadline, cancellation);
    }

    private static SignatureWorkflow.SignRequest withCancellation(SignatureWorkflow.SignRequest request,
            CancellationSignal cancellation) {
        return new SignatureWorkflow.SignRequest(request.submissionId(), request.namespace(),
                request.semanticFingerprint(), request.fencingToken(), request.accessContext(), request.keyRef(),
                request.algorithmId(), request.content(), request.preferredSignatureEncoding(), request.deadline(),
                cancellation);
    }

    private static RepeatableContent repeatableContent(byte[] payload, java.util.function.IntConsumer readObserver) {
        return new RepeatableContent() {
            @Override
            public InputStream openStream() {
                return new ByteArrayInputStream(payload) {
                    @Override
                    public int read() {
                        int value = super.read();
                        readObserver.accept(value < 0 ? value : 1);
                        return value;
                    }

                    @Override
                    public int read(byte[] bytes, int offset, int length) {
                        int count = super.read(bytes, offset, length);
                        readObserver.accept(count);
                        return count;
                    }
                };
            }

            @Override
            public OptionalLong length() {
                return OptionalLong.of(payload.length);
            }

            @Override
            public String contentId() {
                return "streaming-cancellation-content";
            }

            @Override
            public void close() {
                // Caller owns this test content.
            }
        };
    }

    private static void assertSigningFailure(ZeroEchoLibSignatureWorkflow workflow, Instant now, String algorithmId,
            KeyRef keyRef, String expectedDetailCode) {
        PkiId id = SigningSubmissionId.create(NAMESPACE, now, new SecureRandom()).id();
        workflow.submitSign(request(id, 1L, new byte[] { 9 }, keyRef, Optional.empty(), algorithmId), control());
        assertEquals(SignatureWorkflow.State.FAILED, workflow.status(id, control()).state());
        assertEquals(Optional.of(expectedDetailCode), workflow.status(id, control()).detailCode());
    }

    private static SignatureWorkflow.CallControl control() {
        return new SignatureWorkflow.CallControl(Instant.MAX, CancellationSignal.NONE);
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        if (needle.length == 0 || needle.length > haystack.length) {
            return false;
        }
        for (int offset = 0; offset <= haystack.length - needle.length; offset++) {
            int index = 0;
            while (index < needle.length && haystack[offset + index] == needle[index]) {
                index++;
            }
            if (index == needle.length) {
                return true;
            }
        }
        return false;
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
