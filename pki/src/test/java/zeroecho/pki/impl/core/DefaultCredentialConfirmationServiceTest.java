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
package zeroecho.pki.impl.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteBinding;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef;
import zeroecho.pki.api.confirmation.ConfirmationRealmBinding;
import zeroecho.pki.api.confirmation.CredentialConfirmationChallenge;
import zeroecho.pki.api.confirmation.CredentialConfirmationInitialization;
import zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofCas;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofChallenge;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofChallengeRequest;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofResult;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofSubmission;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.application.CredentialConfirmationProofAudience;
import zeroecho.pki.application.CredentialConfirmationProofRuntimePolicy;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.confirmation.KeyPossessionProofChallengeContext;
import zeroecho.pki.spi.confirmation.KeyPossessionProofCredential;
import zeroecho.pki.spi.confirmation.KeyPossessionProofDescriptor;
import zeroecho.pki.spi.confirmation.KeyPossessionProofPresentation;
import zeroecho.pki.spi.confirmation.KeyPossessionProofProvider;
import zeroecho.pki.spi.confirmation.KeyPossessionProofResponse;
import zeroecho.pki.spi.confirmation.KeyPossessionProofVerification;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.testkit.PkiTestRuntime;

final class DefaultCredentialConfirmationServiceTest {
    private static final ConfirmationProofSuiteRef SUITE = new ConfirmationProofSuiteRef(
            "test.signature-pop.v1", "a".repeat(64));
    private static final ConfirmationRealmBinding REALM = new ConfirmationRealmBinding("test-realm");
    private static final String AUDIENCE = "urn:uuid:123e4567-e89b-42d3-a456-426614174000";
    private static final Instant NOW = Instant.parse("2026-08-30T12:00:00Z");
    private static final Clock AUDIT_CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final byte[] CERTIFICATE = certificate();

    @TempDir
    private Path temporary;

    @Test
    void issuesPersistedChallengeAndExactlyReplaysPublicPresentation() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        CapturingRandom random = new CapturingRandom((byte) 7);
        TestProvider provider = new TestProvider(binding(8_192));
        try (FilesystemPkiStore store = open("success", clock)) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "success");
            DefaultCredentialConfirmationService service = service(store, provider,
                    Optional.of(policy(8_192, Duration.ofSeconds(30L))), random);

            CredentialConfirmationProofChallenge first = service.issueProofChallenge(request(lifecycle));
            CredentialConfirmationChallenge persisted = store.getCredentialConfirmationChallenge(
                    lifecycle.credentialId()).orElseThrow();
            assertEquals(persisted.recordCommitment(), first.proofCas().expectedChallengeRecordCommitment());
            assertEquals(persisted.expiresAt(), first.expiresAt());
            assertEquals(persisted.proofSuiteBinding(), first.proofSuiteBinding());
            assertArrayEquals(persisted.rawChallenge(), first.presentation());
            assertTrue(random.lastBufferIsCleared());

            random.setFill((byte) 9);
            CredentialConfirmationProofChallenge replay = service.issueProofChallenge(request(lifecycle));
            assertEquals(first, replay);
            assertEquals(persisted, store.getCredentialConfirmationChallenge(lifecycle.credentialId()).orElseThrow());
            assertEquals(2, provider.validationCalls.get());
        }
    }

    @Test
    void emitsOnlyFixedChallengeAndSubmissionOutcomeTelemetry() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        CapturingAudit audit = new CapturingAudit();
        TestProvider provider = new TestProvider(binding(8_192));
        try (FilesystemPkiStore store = open("audit-outcomes", clock)) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "audit-outcomes");
            DefaultCredentialConfirmationService service = service(store, provider,
                    Optional.of(policy(8_192, Duration.ofSeconds(30L))),
                    new CapturingRandom((byte) 8), Optional.of(audit), clock);

            CredentialConfirmationProofChallenge challenge = service.issueProofChallenge(
                    request(lifecycle));
            CredentialConfirmationProofSubmission submission = submission(challenge, 64);
            assertEquals(CredentialConfirmationProofResult.REJECTED,
                    service.verifyAndComplete(submission));
            provider.verification.set(KeyPossessionProofVerification.VERIFIED);
            assertEquals(CredentialConfirmationProofResult.CONFIRMED,
                    service.verifyAndComplete(submission));
            assertEquals(CredentialConfirmationProofResult.CONFIRMED,
                    service.verifyAndComplete(submission));

            assertEquals(4, audit.events.size());
            assertAudit(audit.events.get(0), lifecycle.credentialId(),
                    "PROOF_CHALLENGE", "AVAILABLE");
            assertAudit(audit.events.get(1), lifecycle.credentialId(),
                    "PROOF_SUBMISSION", "REJECTED");
            assertAudit(audit.events.get(2), lifecycle.credentialId(),
                    "PROOF_SUBMISSION", "CONFIRMED");
            assertAudit(audit.events.get(3), lifecycle.credentialId(),
                    "PROOF_SUBMISSION", "CONFIRMED");
            assertEquals(2, provider.verificationCalls.get());
        }
    }

    @Test
    void failingAuditSinkCannotChangeProofResultsOrPersistedState() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        AuditSink failingAudit = event -> {
            throw new IllegalStateException("audit-unavailable");
        };
        TestProvider provider = new TestProvider(binding(8_192));
        try (FilesystemPkiStore store = open("audit-failure", clock)) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "audit-failure");
            DefaultCredentialConfirmationService service = service(store, provider,
                    Optional.of(policy(8_192, Duration.ofSeconds(30L))),
                    new CapturingRandom((byte) 9), Optional.of(failingAudit), clock);

            CredentialConfirmationProofChallenge challenge = service.issueProofChallenge(
                    request(lifecycle));
            assertTrue(store.getCredentialConfirmationChallenge(
                    lifecycle.credentialId()).isPresent());
            CredentialConfirmationProofSubmission submission = submission(challenge, 64);
            assertEquals(CredentialConfirmationProofResult.REJECTED,
                    service.verifyAndComplete(submission));
            assertEquals(CredentialConfirmationLifecycle.State.PENDING,
                    store.getCredentialConfirmation(lifecycle.credentialId()).orElseThrow().state());

            provider.verification.set(KeyPossessionProofVerification.VERIFIED);
            assertEquals(CredentialConfirmationProofResult.CONFIRMED,
                    service.verifyAndComplete(submission));
            assertEquals(CredentialConfirmationLifecycle.State.CONFIRMED,
                    store.getCredentialConfirmation(lifecycle.credentialId()).orElseThrow().state());
            assertTrue(store.getCredentialConfirmationChallenge(
                    lifecycle.credentialId()).isEmpty());
        }
    }

    @Test
    void missingPolicyProviderAndPreflightFailureDoNotPersistChallenge() throws Exception {
        try (FilesystemPkiStore store = open("preflight", new MutableClock(NOW))) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "preflight");
            TestProvider provider = new TestProvider(binding(8_192));
            assertThrows(IllegalStateException.class, () -> service(store, provider, Optional.empty(),
                    new CapturingRandom((byte) 1)).issueProofChallenge(request(lifecycle)));
            assertThrows(IllegalStateException.class, () -> new DefaultCredentialConfirmationService(
                    store, () -> { }, Map.of(), Optional.of(policy(8_192, Duration.ofSeconds(30L))),
                    new CapturingRandom((byte) 1), Optional.empty(), AUDIT_CLOCK)
                    .issueProofChallenge(request(lifecycle)));
            provider.rejectDescriptor.set(true);
            assertThrows(IllegalStateException.class, () -> service(store, provider,
                    Optional.of(policy(8_192, Duration.ofSeconds(30L))),
                    new CapturingRandom((byte) 1)).issueProofChallenge(request(lifecycle)));
            provider.rejectDescriptor.set(false);
            provider.rejectCredential.set(true);
            assertThrows(IllegalArgumentException.class, () -> service(store, provider,
                    Optional.of(policy(8_192, Duration.ofSeconds(30L))),
                    new CapturingRandom((byte) 1)).issueProofChallenge(request(lifecycle)));
            assertTrue(store.getCredentialConfirmationChallenge(lifecycle.credentialId()).isEmpty());
        }
    }

    @Test
    void mismatchingCredentialIdentityFailsBeforeChallengePersistence() throws Exception {
        try (FilesystemPkiStore store = open("credential-identity", new MutableClock(NOW))) {
            PkiId credentialId = new PkiId("x509:" + "0".repeat(64));
            putCredential(store, "credential-identity", credentialId);
            CredentialConfirmationLifecycle lifecycle = store.initializeCredentialConfirmation(
                    new CredentialConfirmationInitialization(credentialId,
                            ConfirmationDisclosurePolicy.AUTHENTICATED, "b".repeat(64), true,
                            NOW.plus(Duration.ofDays(1L)), SUITE));

            assertThrows(IllegalStateException.class, () -> service(store,
                    new TestProvider(binding(8_192)),
                    Optional.of(policy(8_192, Duration.ofSeconds(30L))),
                    new CapturingRandom((byte) 1)).issueProofChallenge(request(lifecycle)));
            assertTrue(store.getCredentialConfirmationChallenge(credentialId).isEmpty());
        }
    }

    @Test
    void malformedTrailingAndNoncanonicalCertificatesFailBeforePersistence() throws Exception {
        byte[] trailing = Arrays.copyOf(CERTIFICATE, CERTIFICATE.length + 1);
        byte[] noncanonical = noncanonicalOuterLength(CERTIFICATE);
        int index = 0;
        for (byte[] encoded : new byte[][] { new byte[] { 1, 2, 3 }, trailing, noncanonical }) {
            String suffix = "invalid-certificate-" + index++;
            try (FilesystemPkiStore store = open(suffix, new MutableClock(NOW))) {
                PkiId credentialId = credentialId(encoded);
                putCredential(store, suffix, credentialId, encoded);
                CredentialConfirmationLifecycle lifecycle = store.initializeCredentialConfirmation(
                        new CredentialConfirmationInitialization(credentialId,
                                ConfirmationDisclosurePolicy.AUTHENTICATED, "b".repeat(64), true,
                                NOW.plus(Duration.ofDays(1L)), SUITE));

                assertThrows(IllegalStateException.class, () -> service(store,
                        new TestProvider(binding(8_192)),
                        Optional.of(policy(8_192, Duration.ofSeconds(30L))),
                        new CapturingRandom((byte) 1)).issueProofChallenge(request(lifecycle)));
                assertTrue(store.getCredentialConfirmationChallenge(credentialId).isEmpty());
            }
        }
    }

    @Test
    void validEcCertificateReachesAcceptingProviderAndIssuesChallenge() throws Exception {
        byte[] ecCertificate = certificate("EC", "SHA256withECDSA");
        try (FilesystemPkiStore store = open("ec-credential", new MutableClock(NOW))) {
            PkiId credentialId = credentialId(ecCertificate);
            putCredential(store, "ec-credential", credentialId, ecCertificate);
            CredentialConfirmationLifecycle lifecycle = store.initializeCredentialConfirmation(
                    new CredentialConfirmationInitialization(credentialId,
                            ConfirmationDisclosurePolicy.AUTHENTICATED, "b".repeat(64), true,
                            NOW.plus(Duration.ofDays(1L)), SUITE));
            TestProvider provider = new TestProvider(binding(8_192));

            CredentialConfirmationProofChallenge challenge = service(store, provider,
                    Optional.of(policy(8_192, Duration.ofSeconds(30L))),
                    new CapturingRandom((byte) 8)).issueProofChallenge(request(lifecycle));

            assertEquals("EC", provider.lastPublicKeyAlgorithm.get());
            assertEquals(store.getCredentialConfirmationChallenge(credentialId).orElseThrow().recordCommitment(),
                    challenge.proofCas().expectedChallengeRecordCommitment());
        }
    }

    @Test
    void freezesExistingBindingAndLifetimeAcrossReopenAndExpiryReplacement() throws Exception {
        Path root = temporary.resolve("frozen");
        MutableClock clock = new MutableClock(NOW);
        CredentialConfirmationLifecycle lifecycle;
        CredentialConfirmationProofChallenge first;
        TestProvider provider = new TestProvider(binding(8_192));
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            lifecycle = pending(store, "frozen");
            first = service(store, provider, Optional.of(policy(8_192, Duration.ofSeconds(20L))),
                    new CapturingRandom((byte) 2)).issueProofChallenge(request(lifecycle));
        }

        clock.set(first.expiresAt().minusSeconds(1L));
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            DefaultCredentialConfirmationService changed = service(reopened, provider,
                    Optional.of(policy(4_096, Duration.ofSeconds(60L))), new CapturingRandom((byte) 3));
            assertEquals(first, changed.issueProofChallenge(request(lifecycle)));
            clock.set(first.expiresAt());
            CredentialConfirmationProofChallenge replacement = changed.issueProofChallenge(request(lifecycle));
            assertEquals(8_192, replacement.proofSuiteBinding().rsaMaximumModulusBits());
            assertEquals(first.expiresAt().plusSeconds(20L), replacement.expiresAt());
        }
    }

    @Test
    void presentationFailureLeavesExactChallengeRetryableByNewService() throws Exception {
        try (FilesystemPkiStore store = open("presentation", new MutableClock(NOW))) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "presentation");
            TestProvider provider = new TestProvider(binding(8_192));
            provider.rejectPresentation.set(true);
            DefaultCredentialConfirmationService failing = service(store, provider,
                    Optional.of(policy(8_192, Duration.ofSeconds(30L))), new CapturingRandom((byte) 4));
            assertThrows(IllegalStateException.class, () -> failing.issueProofChallenge(request(lifecycle)));
            CredentialConfirmationChallenge committed = store.getCredentialConfirmationChallenge(
                    lifecycle.credentialId()).orElseThrow();

            provider.rejectPresentation.set(false);
            CredentialConfirmationProofChallenge recovered = service(store, provider,
                    Optional.of(policy(4_096, Duration.ofSeconds(60L))), new CapturingRandom((byte) 5))
                    .issueProofChallenge(request(lifecycle));
            assertEquals(committed.recordCommitment(), recovered.proofCas().expectedChallengeRecordCommitment());
            assertArrayEquals(committed.rawChallenge(), recovered.presentation());
        }
    }

    @Test
    void concurrentSafeFacadeCallsConvergeOnOneExactPersistedChallenge() throws Exception {
        try (FilesystemPkiStore store = open("concurrent-facade", new MutableClock(NOW))) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "concurrent-facade");
            TestProvider provider = new TestProvider(binding(8_192));
            provider.validationBarrier = new CountDownLatch(2);
            provider.presentationBarrier = new CountDownLatch(2);
            DefaultCredentialConfirmationService service = service(store, provider,
                    Optional.of(policy(8_192, Duration.ofSeconds(30L))),
                    new CapturingRandom((byte) 6));
            CountDownLatch start = new CountDownLatch(1);

            try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
                Future<CredentialConfirmationProofChallenge> first = executor.submit(() -> {
                    start.await();
                    return service.issueProofChallenge(request(lifecycle));
                });
                Future<CredentialConfirmationProofChallenge> second = executor.submit(() -> {
                    start.await();
                    return service.issueProofChallenge(request(lifecycle));
                });
                start.countDown();
                CredentialConfirmationProofChallenge left = first.get();
                CredentialConfirmationProofChallenge right = second.get();

                assertEquals(left, right);
                CredentialConfirmationChallenge persisted = store.getCredentialConfirmationChallenge(
                        lifecycle.credentialId()).orElseThrow();
                assertEquals(persisted.recordCommitment(),
                        left.proofCas().expectedChallengeRecordCommitment());
                assertEquals(lifecycle, store.getCredentialConfirmation(lifecycle.credentialId()).orElseThrow());
                assertEquals(2, provider.validationCalls.get());
                assertEquals(2, provider.presentationCalls.get());
            }
        }
    }

    @Test
    void rejectedProofLeavesPendingLifecycleChallengeAndReviewUnchanged() throws Exception {
        try (FilesystemPkiStore store = open("rejected-proof", new MutableClock(NOW))) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "rejected-proof");
            TestProvider provider = new TestProvider(binding(8_192));
            AtomicInteger completionCalls = new AtomicInteger();
            DefaultCredentialConfirmationService service = service(
                    countingCompletionStore(store, completionCalls), provider,
                    Optional.of(policy(8_192, Duration.ofSeconds(30L))),
                    new CapturingRandom((byte) 1));
            CredentialConfirmationProofChallenge challenge = service.issueProofChallenge(request(lifecycle));

            CredentialConfirmationProofResult result = service.verifyAndComplete(
                    submission(challenge, 64));

            assertEquals(CredentialConfirmationProofResult.REJECTED, result);
            assertEquals(lifecycle, store.getCredentialConfirmation(lifecycle.credentialId()).orElseThrow());
            assertTrue(store.getCredentialConfirmationChallenge(lifecycle.credentialId()).isPresent());
            assertEquals(1, store.pagePendingCredentialConfirmationReviews(
                    store.getCredential(lifecycle.credentialId()).orElseThrow().issuerRef().caId(),
                    Optional.empty(), NOW.plus(Duration.ofDays(2L)), Optional.empty(), 10).reviews().size());
            assertEquals(1, provider.verificationCalls.get());
            assertEquals(0, completionCalls.get());
        }
    }

    @Test
    void providerNullAndExceptionFailClosedWithoutCompletion() throws Exception {
        try (FilesystemPkiStore store = open("verification-failure", new MutableClock(NOW))) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "verification-failure");
            TestProvider provider = new TestProvider(binding(8_192));
            DefaultCredentialConfirmationService service = service(store, provider,
                    Optional.of(policy(8_192, Duration.ofSeconds(30L))),
                    new CapturingRandom((byte) 2));
            CredentialConfirmationProofChallenge challenge = service.issueProofChallenge(request(lifecycle));
            CredentialConfirmationProofSubmission submission = submission(challenge, 64);

            provider.nullVerification.set(true);
            assertThrows(NullPointerException.class, () -> service.verifyAndComplete(submission));
            provider.nullVerification.set(false);
            provider.rejectVerification.set(true);
            assertThrows(IllegalStateException.class, () -> service.verifyAndComplete(submission));

            assertEquals(lifecycle, store.getCredentialConfirmation(lifecycle.credentialId()).orElseThrow());
            assertTrue(store.getCredentialConfirmationChallenge(lifecycle.credentialId()).isPresent());
        }
    }

    @Test
    void exactTerminalRetryBypassesProviderAndResponseSpecificValidation() throws Exception {
        try (FilesystemPkiStore store = open("terminal-retry", new MutableClock(NOW))) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "terminal-retry");
            TestProvider provider = new TestProvider(binding(8_192));
            provider.verification.set(KeyPossessionProofVerification.VERIFIED);
            DefaultCredentialConfirmationService service = service(store, provider,
                    Optional.of(policy(8_192, Duration.ofSeconds(30L))),
                    new CapturingRandom((byte) 3));
            CredentialConfirmationProofChallenge challenge = service.issueProofChallenge(request(lifecycle));
            assertEquals(CredentialConfirmationProofResult.CONFIRMED,
                    service.verifyAndComplete(submission(challenge, 64)));
            CredentialConfirmationLifecycle first = store.getCredentialConfirmation(
                    lifecycle.credentialId()).orElseThrow();

            DefaultCredentialConfirmationService withoutProvider = new DefaultCredentialConfirmationService(
                    store, () -> { }, Map.of(), Optional.empty(), new CapturingRandom((byte) 4),
                    Optional.empty(), AUDIT_CLOCK);
            assertEquals(CredentialConfirmationProofResult.CONFIRMED,
                    withoutProvider.verifyAndComplete(submission(challenge, 16_000)));
            assertEquals(first, store.getCredentialConfirmation(
                    lifecycle.credentialId()).orElseThrow());
            assertEquals(1, provider.verificationCalls.get());

            CredentialConfirmationProofCas wrong = new CredentialConfirmationProofCas(
                    challenge.proofCas().credentialId(), challenge.proofCas().expectedLifecycleRevision(),
                    challenge.proofCas().expectedLifecycleRecordCommitment(), "f".repeat(64));
            assertThrows(IllegalArgumentException.class, () -> withoutProvider.verifyAndComplete(
                    new CredentialConfirmationProofSubmission(wrong, new byte[] { 1 })));
        }
    }

    @Test
    void exactSuiteResponseBoundIsRejectedBeforeProviderVerification() throws Exception {
        try (FilesystemPkiStore store = open("response-bound", new MutableClock(NOW))) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "response-bound");
            TestProvider provider = new TestProvider(binding(2_048));
            DefaultCredentialConfirmationService service = service(store, provider,
                    Optional.of(policy(2_048, Duration.ofSeconds(30L))),
                    new CapturingRandom((byte) 4));
            CredentialConfirmationProofChallenge challenge = service.issueProofChallenge(request(lifecycle));

            assertThrows(IllegalArgumentException.class, () -> service.verifyAndComplete(
                    submission(challenge, 257)));
            assertEquals(0, provider.verificationCalls.get());
            assertEquals(lifecycle, store.getCredentialConfirmation(lifecycle.credentialId()).orElseThrow());
        }
    }

    @Test
    void verifiedProofPropagatesRotatedChallengeConflict() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = open("rotated-proof", clock)) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "rotated-proof");
            TestProvider provider = new TestProvider(binding(8_192));
            provider.verification.set(KeyPossessionProofVerification.VERIFIED);
            DefaultCredentialConfirmationService service = service(store, provider,
                    Optional.of(policy(8_192, Duration.ofSeconds(10L))),
                    new CapturingRandom((byte) 5));
            CredentialConfirmationProofChallenge challenge = service.issueProofChallenge(request(lifecycle));
            provider.verificationAction.set(() -> {
                clock.set(challenge.expiresAt());
                store.issueCredentialConfirmationChallenge(
                        new zeroecho.pki.api.confirmation.CredentialConfirmationChallengeIssuance(
                                REALM, AUDIENCE, lifecycle.credentialId(), lifecycle.revision(),
                                lifecycle.recordCommitment(), binding(8_192), bytes(32, 9),
                                Duration.ofSeconds(10L)));
            });

            assertThrows(IllegalArgumentException.class,
                    () -> service.verifyAndComplete(submission(challenge, 64)));
            assertEquals(lifecycle, store.getCredentialConfirmation(lifecycle.credentialId()).orElseThrow());
            assertNotEquals(challenge.proofCas().expectedChallengeRecordCommitment(),
                    store.getCredentialConfirmationChallenge(lifecycle.credentialId()).orElseThrow()
                            .recordCommitment());
        }
    }

    @Test
    void verifiedExpiredProofPropagatesExpiryInsteadOfRejection() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = open("expired-proof", clock)) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "expired-proof");
            TestProvider provider = new TestProvider(binding(8_192));
            provider.verification.set(KeyPossessionProofVerification.VERIFIED);
            DefaultCredentialConfirmationService issuingService = service(store, provider,
                    Optional.of(policy(8_192, Duration.ofSeconds(10L))),
                    new CapturingRandom((byte) 6));
            CredentialConfirmationProofChallenge challenge = issuingService.issueProofChallenge(
                    request(lifecycle));
            clock.set(challenge.expiresAt());
            AtomicInteger credentialReads = new AtomicInteger();
            DefaultCredentialConfirmationService verifyingService = service(
                    countingCredentialReadStore(store, credentialReads), provider,
                    Optional.of(policy(8_192, Duration.ofSeconds(10L))),
                    new CapturingRandom((byte) 7), Optional.empty(), clock);
            provider.resetInvocationCounts();

            assertThrows(IllegalStateException.class,
                    () -> verifyingService.verifyAndComplete(submission(challenge, 64)));
            assertEquals(0, provider.suiteIdCalls.get());
            assertEquals(0, provider.descriptorCalls.get());
            assertEquals(0, provider.validationCalls.get());
            assertEquals(0, provider.verificationCalls.get());
            assertEquals(0, credentialReads.get());
            assertEquals(lifecycle, store.getCredentialConfirmation(lifecycle.credentialId()).orElseThrow());
        }
    }

    @Test
    void proofVerificationRejectsClockRegressionBeforeCredentialOrProviderWork() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = open("proof-clock-regression", clock)) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "proof-clock-regression");
            TestProvider provider = new TestProvider(binding(8_192));
            DefaultCredentialConfirmationService issuingService = service(store, provider,
                    Optional.of(policy(8_192, Duration.ofSeconds(10L))),
                    new CapturingRandom((byte) 8));
            CredentialConfirmationProofChallenge challenge = issuingService.issueProofChallenge(
                    request(lifecycle));
            clock.set(NOW.minusSeconds(1L));
            AtomicInteger credentialReads = new AtomicInteger();
            DefaultCredentialConfirmationService verifyingService = service(
                    countingCredentialReadStore(store, credentialReads), provider,
                    Optional.of(policy(8_192, Duration.ofSeconds(10L))),
                    new CapturingRandom((byte) 9), Optional.empty(), clock);
            provider.resetInvocationCounts();

            assertThrows(IllegalStateException.class,
                    () -> verifyingService.verifyAndComplete(submission(challenge, 64)));
            assertEquals(0, provider.suiteIdCalls.get());
            assertEquals(0, provider.descriptorCalls.get());
            assertEquals(0, provider.validationCalls.get());
            assertEquals(0, provider.verificationCalls.get());
            assertEquals(0, credentialReads.get());
            assertEquals(lifecycle, store.getCredentialConfirmation(lifecycle.credentialId()).orElseThrow());
        }
    }

    @Test
    void concurrentVerifiedSubmissionsConvergeOnOneConfirmedLifecycle() throws Exception {
        try (FilesystemPkiStore store = open("concurrent-proof", new MutableClock(NOW))) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "concurrent-proof");
            TestProvider provider = new TestProvider(binding(8_192));
            provider.verification.set(KeyPossessionProofVerification.VERIFIED);
            provider.verificationBarrier = new CountDownLatch(2);
            DefaultCredentialConfirmationService service = service(store, provider,
                    Optional.of(policy(8_192, Duration.ofSeconds(30L))),
                    new CapturingRandom((byte) 7));
            CredentialConfirmationProofChallenge challenge = service.issueProofChallenge(request(lifecycle));
            CredentialConfirmationProofSubmission submission = submission(challenge, 64);
            CountDownLatch start = new CountDownLatch(1);

            try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
                Future<CredentialConfirmationProofResult> first = executor.submit(() -> {
                    start.await();
                    return service.verifyAndComplete(submission);
                });
                Future<CredentialConfirmationProofResult> second = executor.submit(() -> {
                    start.await();
                    return service.verifyAndComplete(submission);
                });
                start.countDown();
                CredentialConfirmationProofResult left = first.get();
                CredentialConfirmationProofResult right = second.get();

                assertEquals(CredentialConfirmationProofResult.CONFIRMED, left);
                assertEquals(left, right);
                CredentialConfirmationLifecycle committed = store.getCredentialConfirmation(
                        lifecycle.credentialId()).orElseThrow();
                assertEquals(CredentialConfirmationLifecycle.State.CONFIRMED,
                        committed.state());
                assertTrue(store.getCredentialConfirmationChallenge(lifecycle.credentialId()).isEmpty());
                assertTrue(store.pagePendingCredentialConfirmationReviews(
                        store.getCredential(lifecycle.credentialId()).orElseThrow().issuerRef().caId(),
                        Optional.empty(), NOW.plus(Duration.ofDays(2L)), Optional.empty(), 10)
                        .reviews().isEmpty());
                assertEquals(2, provider.verificationCalls.get());
            }
        }
    }

    @Test
    void missingChallengeRaceRecoversOnlyAnExactTerminalLifecycle() {
        CredentialConfirmationLifecycle pending = CredentialConfirmationLifecycle.initialize(
                new CredentialConfirmationInitialization(new PkiId("race-credential"),
                        ConfirmationDisclosurePolicy.AUTHENTICATED, "b".repeat(64), true,
                        NOW.plus(Duration.ofDays(1L)), SUITE));
        CredentialConfirmationProofCas proofCas = new CredentialConfirmationProofCas(
                pending.credentialId(), pending.revision(), pending.recordCommitment(), "c".repeat(64));
        CredentialConfirmationLifecycle confirmed = pending.deriveConfirmed(proofCas, NOW);
        AtomicInteger lifecycleReads = new AtomicInteger();
        AtomicInteger completions = new AtomicInteger();
        PkiStore racingStore = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class }, (proxy, method, arguments) -> {
                    return switch (method.getName()) {
                        case "getCredentialConfirmation" -> Optional.of(
                                lifecycleReads.getAndIncrement() == 0 ? pending : confirmed);
                        case "getCredentialConfirmationChallenge" -> Optional.empty();
                        case "completeCredentialConfirmation" -> {
                            assertEquals(proofCas, arguments[0]);
                            completions.incrementAndGet();
                            yield confirmed;
                        }
                        default -> throw new AssertionError("Unexpected store call: " + method.getName());
                    };
                });
        DefaultCredentialConfirmationService service = new DefaultCredentialConfirmationService(
                racingStore, () -> { }, Map.of(), Optional.empty(), new CapturingRandom((byte) 1),
                Optional.empty(), AUDIT_CLOCK);

        CredentialConfirmationProofResult result = service.verifyAndComplete(
                new CredentialConfirmationProofSubmission(proofCas, new byte[] { 1 }));

        assertEquals(CredentialConfirmationProofResult.CONFIRMED, result);
        assertEquals(2, lifecycleReads.get());
        assertEquals(1, completions.get());
    }

    private FilesystemPkiStore open(String name, Clock clock) {
        return new FilesystemPkiStore(temporary.resolve(name), FsPkiStoreOptions.defaults(), clock);
    }

    private static DefaultCredentialConfirmationService service(PkiStore store,
            TestProvider provider, Optional<CredentialConfirmationProofRuntimePolicy> policy,
            SecureRandom random) {
        return service(store, provider, policy, random, Optional.empty(), AUDIT_CLOCK);
    }

    private static DefaultCredentialConfirmationService service(PkiStore store,
            TestProvider provider, Optional<CredentialConfirmationProofRuntimePolicy> policy,
            SecureRandom random, Optional<AuditSink> auditSink, Clock clock) {
        return new DefaultCredentialConfirmationService(store, () -> { },
                Map.of(provider.suiteId(), provider), policy, random, auditSink, clock);
    }

    private static void assertAudit(AuditEvent event, PkiId credentialId,
            String action, String result) {
        assertEquals(NOW, event.time());
        assertEquals("CREDENTIAL_CONFIRMATION", event.category());
        assertEquals(action, event.action());
        assertEquals(new Principal("SYSTEM", "pki"), event.principal());
        assertEquals(new Purpose("CREDENTIAL_CONFIRMATION"), event.purpose());
        assertEquals(Optional.of(credentialId), event.objectId());
        assertTrue(event.formatId().isEmpty());
        assertEquals(Map.of("result", result), event.details());
    }

    private static PkiStore countingCompletionStore(PkiStore delegate, AtomicInteger completions) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class }, (proxy, method, arguments) -> {
                    if ("completeCredentialConfirmation".equals(method.getName())) {
                        completions.incrementAndGet();
                    }
                    try {
                        return method.invoke(delegate, arguments);
                    } catch (InvocationTargetException failure) {
                        throw failure.getCause();
                    }
                });
    }

    private static PkiStore countingCredentialReadStore(PkiStore delegate, AtomicInteger reads) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class }, (proxy, method, arguments) -> {
                    if ("getCredential".equals(method.getName())) {
                        reads.incrementAndGet();
                    }
                    try {
                        return method.invoke(delegate, arguments);
                    } catch (InvocationTargetException failure) {
                        throw failure.getCause();
                    }
                });
    }

    private static CredentialConfirmationLifecycle pending(FilesystemPkiStore store, String suffix)
            throws Exception {
        PkiId credentialId = putCredential(store, suffix);
        return store.initializeCredentialConfirmation(new CredentialConfirmationInitialization(
                credentialId, ConfirmationDisclosurePolicy.AUTHENTICATED, "b".repeat(64), true,
                NOW.plus(Duration.ofDays(1L)), SUITE));
    }

    private static PkiId putCredential(FilesystemPkiStore store, String suffix) throws Exception {
        PkiId credentialId = credentialId(CERTIFICATE);
        putCredential(store, suffix, credentialId);
        return credentialId;
    }

    private static void putCredential(FilesystemPkiStore store, String suffix,
            PkiId credentialId) throws Exception {
        putCredential(store, suffix, credentialId, CERTIFICATE);
    }

    private static void putCredential(FilesystemPkiStore store, String suffix,
            PkiId credentialId, byte[] encoded) throws Exception {
        DurableContentReference content = PkiTestRuntime.stageCredential(store, encoded);
        Credential credential = new Credential(credentialId, BcX509CredentialFramework.FORMAT_ID,
                new IssuerRef(new PkiId("issuer-" + suffix)), new SubjectRef("CN=" + suffix),
                new Validity(NOW.minus(Duration.ofDays(1L)), NOW.plus(Duration.ofDays(2L))),
                "1", new PkiId("spki-" + suffix),
                new EndEntityProfileBinding(new CertificateProfileRef("profile-" + suffix, 1L, new byte[32])),
                CredentialStatus.ISSUED, content, new SimpleAttributeSet());
        store.putCredential(credential);
    }

    private static PkiId credentialId(byte[] encoded) throws Exception {
        String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(encoded));
        return new PkiId("x509:" + digest);
    }

    private static CredentialConfirmationProofChallengeRequest request(
            CredentialConfirmationLifecycle lifecycle) {
        return new CredentialConfirmationProofChallengeRequest(lifecycle.credentialId(),
                lifecycle.revision(), lifecycle.recordCommitment());
    }

    private static CredentialConfirmationProofSubmission submission(
            CredentialConfirmationProofChallenge challenge, int responseBytes) {
        return new CredentialConfirmationProofSubmission(challenge.proofCas(),
                bytes(responseBytes, 3));
    }

    private static byte[] bytes(int length, int value) {
        byte[] result = new byte[length];
        Arrays.fill(result, (byte) value);
        return result;
    }

    private static CredentialConfirmationProofRuntimePolicy policy(int bits, Duration ttl) {
        return new CredentialConfirmationProofRuntimePolicy(REALM,
                new CredentialConfirmationProofAudience(AUDIENCE), ttl, binding(bits));
    }

    private static ConfirmationProofSuiteBinding binding(int bits) {
        return new ConfirmationProofSuiteBinding(SUITE, bits);
    }

    private static byte[] certificate() {
        return certificate("RSA", "SHA256withRSA");
    }

    private static byte[] certificate(String keyAlgorithm, String signatureAlgorithm) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(keyAlgorithm);
            if ("RSA".equals(keyAlgorithm)) {
                generator.initialize(2_048);
            } else {
                generator.initialize(256);
            }
            KeyPair keyPair = generator.generateKeyPair();
            X500Name name = new X500Name("CN=Proof Credential");
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name,
                    BigInteger.ONE, java.util.Date.from(NOW.minus(Duration.ofDays(1L))),
                    java.util.Date.from(NOW.plus(Duration.ofDays(2L))), name, keyPair.getPublic());
            return builder.build(new JcaContentSignerBuilder(signatureAlgorithm)
                    .build(keyPair.getPrivate())).getEncoded();
        } catch (Exception failure) {
            throw new ExceptionInInitializerError(failure);
        }
    }

    private static byte[] noncanonicalOuterLength(byte[] canonical) {
        int lengthBytes = canonical[1] & 0x7f;
        if ((canonical[1] & 0x80) == 0 || lengthBytes == 0 || lengthBytes >= 4) {
            throw new IllegalStateException("Test certificate does not use the expected DER length form");
        }
        byte[] result = new byte[canonical.length + 1];
        result[0] = canonical[0];
        result[1] = (byte) (0x80 | lengthBytes + 1);
        result[2] = 0;
        System.arraycopy(canonical, 2, result, 3, canonical.length - 2);
        return result;
    }

    private static final class TestProvider implements KeyPossessionProofProvider {
        private final ConfirmationProofSuiteBinding binding;
        private final AtomicInteger suiteIdCalls = new AtomicInteger();
        private final AtomicInteger descriptorCalls = new AtomicInteger();
        private final AtomicInteger validationCalls = new AtomicInteger();
        private final AtomicInteger presentationCalls = new AtomicInteger();
        private final AtomicReference<String> lastPublicKeyAlgorithm = new AtomicReference<>();
        private final AtomicBoolean rejectDescriptor = new AtomicBoolean();
        private final AtomicBoolean rejectCredential = new AtomicBoolean();
        private final AtomicBoolean rejectPresentation = new AtomicBoolean();
        private final AtomicBoolean rejectVerification = new AtomicBoolean();
        private final AtomicBoolean nullVerification = new AtomicBoolean();
        private final AtomicInteger verificationCalls = new AtomicInteger();
        private final AtomicReference<KeyPossessionProofVerification> verification =
                new AtomicReference<>(KeyPossessionProofVerification.REJECTED);
        private final AtomicReference<Runnable> verificationAction = new AtomicReference<>();
        private volatile CountDownLatch validationBarrier;
        private volatile CountDownLatch presentationBarrier;
        private volatile CountDownLatch verificationBarrier;

        private TestProvider(ConfirmationProofSuiteBinding binding) {
            this.binding = binding;
        }

        @Override
        public String suiteId() {
            suiteIdCalls.incrementAndGet();
            return binding.proofSuiteRef().suiteId();
        }

        @Override
        public KeyPossessionProofDescriptor descriptor(int rsaMaximumModulusBits) {
            descriptorCalls.incrementAndGet();
            int descriptorBits = rejectDescriptor.get() ? 2_048 : rsaMaximumModulusBits;
            return new KeyPossessionProofDescriptor(
                    new ConfirmationProofSuiteBinding(binding.proofSuiteRef(), descriptorBits),
                    CredentialConfirmationChallenge.RAW_CHALLENGE_BYTES, descriptorBits / 8);
        }

        @Override
        public void validateCredential(KeyPossessionProofCredential credential) {
            validationCalls.incrementAndGet();
            awaitBarrier(validationBarrier);
            if (rejectCredential.get()) {
                throw new IllegalArgumentException("unsupported credential");
            }
            if (!binding.proofSuiteRef().equals(credential.proofSuiteBinding().proofSuiteRef())
                    || credential.publicKey() == null) {
                throw new IllegalArgumentException("credential binding or key is invalid");
            }
            lastPublicKeyAlgorithm.set(credential.publicKey().getAlgorithm());
        }

        @Override
        public KeyPossessionProofPresentation createChallenge(KeyPossessionProofChallengeContext context) {
            presentationCalls.incrementAndGet();
            awaitBarrier(presentationBarrier);
            if (rejectPresentation.get()) {
                throw new IllegalStateException("presentation unavailable");
            }
            return new KeyPossessionProofPresentation(context.rawChallenge());
        }

        @Override
        public KeyPossessionProofVerification verify(KeyPossessionProofChallengeContext context,
                KeyPossessionProofCredential credential, KeyPossessionProofResponse response) {
            verificationCalls.incrementAndGet();
            awaitBarrier(verificationBarrier);
            if (!context.credentialId().equals(credential.credentialId())
                    || !context.proofSuiteBinding().equals(credential.proofSuiteBinding())
                    || credential.publicKey() == null || response.bytes().length == 0) {
                throw new IllegalArgumentException("verification context is inconsistent");
            }
            if (rejectVerification.get()) {
                throw new IllegalStateException("verification unavailable");
            }
            Runnable action = verificationAction.getAndSet(null);
            if (action != null) {
                action.run();
            }
            if (nullVerification.get()) {
                return null;
            }
            return verification.get();
        }

        private void resetInvocationCounts() {
            suiteIdCalls.set(0);
            descriptorCalls.set(0);
            validationCalls.set(0);
            verificationCalls.set(0);
        }

        private static void awaitBarrier(CountDownLatch barrier) {
            if (barrier == null) {
                return;
            }
            barrier.countDown();
            try {
                barrier.await();
            } catch (InterruptedException failure) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Test proof-provider barrier interrupted", failure);
            }
        }
    }

    private static final class CapturingRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;
        private byte fill;
        private byte[] last;

        private CapturingRandom(byte fill) {
            this.fill = fill;
        }

        @Override
        public void nextBytes(byte[] bytes) {
            last = bytes;
            Arrays.fill(bytes, fill);
        }

        private void setFill(byte value) {
            fill = value;
        }

        private boolean lastBufferIsCleared() {
            return last != null && Arrays.equals(last, new byte[last.length]);
        }
    }

    private static final class CapturingAudit implements AuditSink {
        private final List<AuditEvent> events = new ArrayList<>();

        @Override
        public void record(AuditEvent event) {
            events.add(event);
        }
    }

    private static final class MutableClock extends Clock {
        private final AtomicReference<Instant> current;

        private MutableClock(Instant initial) {
            current = new AtomicReference<>(initial);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            if (!ZoneOffset.UTC.equals(zone)) {
                throw new IllegalArgumentException("Test clock supports UTC only");
            }
            return this;
        }

        @Override
        public Instant instant() {
            return current.get();
        }

        private void set(Instant value) {
            current.set(value);
        }
    }
}
