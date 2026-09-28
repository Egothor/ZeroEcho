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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.HexFormat;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.security.auth.x500.X500Principal;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.CredentialLineage;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.issuance.EndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.CorrelatedEndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.CorrelatedIssuancePreparation;
import zeroecho.pki.api.issuance.IssuanceIntent;
import zeroecho.pki.api.issuance.EndEntityRenewalRequest;
import zeroecho.pki.api.issuance.EndEntityReplacementRequest;
import zeroecho.pki.api.issuance.EndEntityReissueRequest;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.SubjectRdnType;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.api.signing.SigningAcceptanceResult;
import zeroecho.pki.api.signing.SigningAcceptanceDisposition;
import zeroecho.pki.api.signing.SigningAcceptanceResolution;
import zeroecho.pki.api.signing.SigningOperationState;
import zeroecho.pki.application.PkiSessionConfiguration.SigningCoordinatorLimits;
import zeroecho.pki.application.PkiSessionConfiguration.SigningLanePool;
import zeroecho.pki.application.PkiSessionConfiguration.SigningTopology;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.impl.audit.InMemoryAuditSink;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainAttributeEncoding;
import zeroecho.pki.impl.core.continuation.SigningOuterTerminalDriver;
import zeroecho.pki.impl.core.signing.DefaultSemanticSigningService;
import zeroecho.pki.impl.core.signing.DefaultSigningService;
import zeroecho.pki.impl.core.signing.SigningReactor;
import zeroecho.pki.impl.core.signing.SigningStepExecutor;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.AuditEvidenceFeed;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.H7ProfileDocuments;
import zeroecho.pki.testkit.PkiTestRuntime;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.BasicConstraints;
import zeroecho.pkix.GeneralName;
import zeroecho.pkix.ExtendedKeyUsage;
import zeroecho.pkix.KeyUsage;
import zeroecho.pkix.Pkix;

final class EndEntitySigningLifecycleTest {
    private static final Instant NOW = Instant.parse("2026-09-20T12:00:00.123456789Z");
    private static final PkiId CA = new PkiId("ca:integration");
    private static final KeyRef KEY = new KeyRef("key:original-issuer");
    private static final String PROFILE = "h7-no-san-eku";
    private static final String ALGORITHM = BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm();
    private static final AlgorithmIdentifier X509_SIGNATURE = AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11");
    private static final AccessContext ACCESS = new AccessContext(new Principal("TEST", "operator"),
            new Purpose("ISSUE"), Optional.empty(), Optional.empty());
    private static KeyPair issuerKey;
    private static KeyPair leafKey;
    private static KeyPair replacementKey;
    private static KeyPair replacementLeafKey;
    private static byte[] csr;

    @BeforeAll
    static void generateKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        issuerKey = generator.generateKeyPair();
        leafKey = generator.generateKeyPair();
        replacementKey = generator.generateKeyPair();
        replacementLeafKey = generator.generateKeyPair();
        csr = Pkix.certificationRequestBuilder().subject(new X500Principal("CN=Applicant"))
                .publicKey(leafKey.getPublic()).build(Pkix.signer(leafKey.getPrivate(), X509_SIGNATURE)).encoded();
    }

    @Test
    void issuanceEvidenceSurvivesPublicationFeedAndRestart(@TempDir Path root) throws Exception {
        for (String variant : List.of("administrative", "acme", "embedded")) {
            Optional<IssuanceExecutionEvidence> evidence = switch (variant) {
                case "administrative" -> Optional.of(IssuanceExecutionEvidence.administrative(
                        "administrator", "realm", "administrative-invocation",
                        IssuanceExecutionEvidence.Authentication.TRUSTED_REVERSE_PROXY,
                        IssuanceExecutionEvidence.AuthorizationPath.BREAK_GLASS, "1".repeat(64), CA.value(), PROFILE));
                case "acme" -> Optional.of(IssuanceExecutionEvidence.acme(
                        "account", "realm", "acme-invocation", CA.value(), PROFILE));
                default -> Optional.empty();
            };
            AccessContext access = evidence.map(value -> new AccessContext(
                    new Principal(value.actorType().name(), value.actorId()), ACCESS.purpose(),
                    Optional.empty(), Optional.empty())).orElse(ACCESS);
            Path directory = root.resolve(variant);
            MutableClock clock = new MutableClock(NOW);
            PkiId credentialId;
            PkiId operationId;
            try (FilesystemPkiStore store = fixture(directory, clock)) {
                CountDownLatch terminal = new CountDownLatch(1);
                SigningOuterTerminalDriver outer = new SigningOuterTerminalDriver(store);
                try (RuntimeGraph graph = graph(store, clock, new RealProvider(clock, Mode.SIGN), workflow -> {
                    outer.advance(workflow);
                    terminal.countDown();
                }, false)) {
                    PreparedSemanticSigningRequest prepared = graph.service.prepareEndEntity(
                            access, request(), evidence, CancellationSignal.NONE);
                    operationId = graph.service.accept(prepared).receipt().operationId();
                    DomainCommandEncoding.Decoded frozen = command(store, operationId);
                    assertEquals(evidence, IssuanceExecutionEvidence.decode(DomainAttributeEncoding.decode(frozen.field(22))));
                    graph.reactor.start();
                    await(terminal);
                    assertEquals(SemanticSigningState.COMPLETED, graph.service.find(operationId).orElseThrow().state());
                    Credential credential = issued(store, frozen).orElseThrow();
                    credentialId = credential.credentialId();
                    assertEquals(evidence, IssuanceExecutionEvidence.decode(credential.attributes()));
                    assertIssuanceFeed(store, credentialId, evidence);
                }
            }
            try (FilesystemPkiStore store = open(directory, clock);
                    RuntimeGraph graph = graph(store, clock, new RealProvider(clock, Mode.SIGN),
                            new SigningOuterTerminalDriver(store), false)) {
                assertEquals(SemanticSigningState.COMPLETED, graph.service.find(operationId).orElseThrow().state());
                assertEquals(evidence, IssuanceExecutionEvidence.decode(store.getCredential(credentialId).orElseThrow().attributes()));
                assertIssuanceFeed(store, credentialId, evidence);
            }
        }
    }

    private static void assertIssuanceFeed(PkiStore store, PkiId credentialId,
            Optional<IssuanceExecutionEvidence> expected) throws Exception {
        try (AuditEvidenceFeed feed = store.openIssuanceEvidenceFeed(-1L)) {
            assertEquals(1L, feed.highWatermark());
            assertTrue(feed.next(CancellationSignal.NONE));
            assertEquals(credentialId, feed.current().objectId());
            assertEquals(expected, IssuanceExecutionEvidence.decode(DomainAttributeEncoding.decode(
                    new String(feed.current().evidence(), StandardCharsets.UTF_8))));
            assertFalse(feed.next(CancellationSignal.NONE));
        }
    }

    @Test
    void realReactiveIssuanceCompletesWithNormalizedTimeAndFrozenSelections(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = fixture(root, clock)) {
            CaRecord originalCa = store.getCa(CA).orElseThrow();
            CertificateProfileRef originalProfile = store.getActiveProfileRef(PROFILE).orElseThrow();
            CountDownLatch signed = new CountDownLatch(1);
            CountDownLatch publish = new CountDownLatch(1);
            CountDownLatch terminal = new CountDownLatch(1);
            SigningOuterTerminalDriver outer = new SigningOuterTerminalDriver(store);
            RealProvider provider = new RealProvider(clock, Mode.SIGN);
            try (RuntimeGraph graph = graph(store, clock, provider, workflow -> {
                signed.countDown();
                awaitUnchecked(publish);
                outer.advance(workflow);
                terminal.countDown();
            }, false)) {
                PreparedSemanticSigningRequest prepared = graph.service.prepareEndEntity(ACCESS, request(), Optional.empty(), CancellationSignal.NONE);
                graph.service.accept(prepared);
                DomainCommandEncoding.Decoded frozen = command(store, prepared.receipt().operationId());
                replaceCurrentSelections(store, clock);
                assertFalse(originalCa.currentIssuanceIssuerId().equals(store.getCa(CA).orElseThrow().currentIssuanceIssuerId()));
                assertEquals(2L, store.getActiveProfileRef(PROFILE).orElseThrow().profileVersion());
                graph.reactor.start();
                try {
                    await(signed);
                    SemanticSigningOperation signatureOnly = graph.service.find(prepared.receipt().operationId()).orElseThrow();
                    assertEquals(SigningOperationState.SUCCEEDED, signatureOnly.signingState());
                    assertEquals(SemanticSigningState.SIGNING, signatureOnly.state());
                    assertTrue(signatureOnly.result().isEmpty());
                } finally {
                    publish.countDown();
                }
                await(terminal);
                SemanticSigningOperation completed = graph.service.find(prepared.receipt().operationId()).orElseThrow();
                assertEquals(SemanticSigningState.COMPLETED, completed.state());
                X509Certificate certificate = Pkix.parseCertificate(completed.result().orElseThrow().bytes());
                certificate.verify(issuerKey.getPublic());
                assertArrayEquals(leafKey.getPublic().getEncoded(), Pkix.subjectPublicKeyInfo(certificate));
                assertEquals(new X500Principal("CN=Issuer"), certificate.getIssuerX500Principal());
                assertEquals(new X500Principal("CN=Applicant"), certificate.getSubjectX500Principal());
                assertEquals(NOW.truncatedTo(ChronoUnit.SECONDS).plusSeconds(1), certificate.getNotBefore().toInstant());
                assertEquals(NOW.truncatedTo(ChronoUnit.SECONDS).plusSeconds(365L * 86400), certificate.getNotAfter().toInstant());
                assertEquals(Set.of("2.5.29.19", "2.5.29.15"), certificate.getCriticalExtensionOIDs());
                assertTrue(certificate.getNonCriticalExtensionOIDs() == null || certificate.getNonCriticalExtensionOIDs().isEmpty());
                assertEquals(-1, certificate.getBasicConstraints());
                assertTrue(certificate.getKeyUsage()[0]);
                assertTrue(certificate.getKeyUsage()[2]);
                Credential issued = issued(store, frozen).orElseThrow();
                assertEquals(new EndEntityProfileBinding(originalProfile), issued.profileBinding());
                assertEquals(originalCa.currentIssuanceIssuerId(), issued.issuerRef().issuerId());
                assertEquals(originalCa.issuanceChainPathId(), issued.issuerRef().chainPathId());
                assertEquals(certificate.getNotBefore().toInstant(), issued.validity().notBefore());
                assertEquals(certificate.getNotAfter().toInstant(), issued.validity().notAfter());
                assertEquals(1, provider.dispatches.get());
            }
        }
    }

    @Test
    void cancellationExpiryDenialAndInvalidIssuerSignaturePublishNoCredential(@TempDir Path root) throws Exception {
        for (Mode mode : List.of(Mode.CANCEL, Mode.EXPIRE, Mode.DENY, Mode.WRONG_KEY)) {
            MutableClock clock = new MutableClock(NOW);
            try (FilesystemPkiStore store = fixture(root.resolve(mode.name()), clock)) {
                CountDownLatch terminal = new CountDownLatch(1);
                SigningOuterTerminalDriver outer = new SigningOuterTerminalDriver(store);
                RealProvider provider = new RealProvider(clock, mode);
                try (RuntimeGraph graph = graph(store, clock, provider, workflow -> {
                    outer.advance(workflow);
                    terminal.countDown();
                }, false)) {
                    PreparedSemanticSigningRequest prepared = graph.service.prepareEndEntity(ACCESS, request(), Optional.empty(), CancellationSignal.NONE);
                    graph.service.accept(prepared);
                    DomainCommandEncoding.Decoded frozen = command(store, prepared.receipt().operationId());
                    if (mode == Mode.CANCEL) { graph.service.cancel(prepared.receipt().operationId()); }
                    if (mode == Mode.EXPIRE) { clock.advance(Duration.ofMinutes(2)); }
                    graph.reactor.start();
                    await(terminal);
                    SemanticSigningOperation operation = graph.service.find(prepared.receipt().operationId()).orElseThrow();
                    assertEquals(mode == Mode.EXPIRE ? SemanticSigningState.EXPIRED : SemanticSigningState.FAILED,
                            operation.state());
                    assertTrue(operation.result().isEmpty());
                    assertTrue(issued(store, frozen).isEmpty());
                    if (mode == Mode.CANCEL || mode == Mode.EXPIRE) { assertEquals(0, provider.dispatches.get()); }
                    if (mode == Mode.WRONG_KEY) {
                        assertEquals(SigningOperationState.SUCCEEDED, operation.signingState());
                        assertEquals(Optional.of("CERTIFICATE_SIGNATURE_DIFFERS"), operation.detailCode());
                    }
                }
            }
        }
    }

    @Test
    void unknownAcceptanceUsesReceiptAndOrdinaryPreparationCreatesANewIdentity(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        SigningAcceptanceReceipt receipt;
        DomainCommandEncoding.Decoded first;
        try (FilesystemPkiStore store = fixture(root, clock)) {
            try (RuntimeGraph graph = graph(store, clock, new RealProvider(clock, Mode.SIGN),
                    new SigningOuterTerminalDriver(store), true)) {
                PreparedSemanticSigningRequest prepared = graph.service.prepareEndEntity(ACCESS, request(), Optional.empty(), CancellationSignal.NONE);
                receipt = prepared.receipt();
                assertThrows(IllegalStateException.class, () -> graph.service.accept(prepared));
                assertEquals(SigningAcceptanceResolution.MATCHED, graph.service.resolve(receipt));
                assertThrows(IllegalStateException.class, () -> graph.service.accept(prepared));
                assertThrows(IllegalStateException.class, () -> graph.service.discard(prepared));
                first = command(store, receipt.operationId());
                PreparedSemanticSigningRequest second = graph.service.prepareEndEntity(ACCESS, request(), Optional.empty(), CancellationSignal.NONE);
                assertFalse(receipt.operationId().equals(second.receipt().operationId()));
                // A separate ordinary request has no retry-deduplication authority.
                assertThrows(IllegalStateException.class, () -> graph.service.accept(second));
                DomainCommandEncoding.Decoded secondCommand = command(store, second.receipt().operationId());
                assertFalse(first.field(10).equals(secondCommand.field(10)));
                graph.service.cancel(second.receipt().operationId());
            }
        }
        try (FilesystemPkiStore reopened = open(root, clock)) {
            CountDownLatch terminal = new CountDownLatch(2);
            RealProvider provider = new RealProvider(clock, Mode.SIGN);
            SigningOuterTerminalDriver outer = new SigningOuterTerminalDriver(reopened);
            try (RuntimeGraph graph = graph(reopened, clock, provider, workflow -> {
                outer.advance(workflow);
                terminal.countDown();
            }, false)) {
                assertEquals(SigningAcceptanceResolution.MATCHED, graph.service.resolve(receipt));
                graph.reactor.start();
                await(terminal);
                assertEquals(SemanticSigningState.COMPLETED, graph.service.find(receipt.operationId()).orElseThrow().state());
                assertTrue(issued(reopened, first).isPresent());
                assertEquals(1, provider.dispatches.get());
            }
        }
    }

    @Test
    void restartAfterCredentialCommitResumesPublicationWithoutDuplicateOrResigning(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        AtomicInteger writes = new AtomicInteger();
        PkiId operationId;
        PkiId credentialId;
        DomainCommandEncoding.Decoded frozen;
        try (FilesystemPkiStore store = fixture(root, clock)) {
            CountDownLatch crash = new CountDownLatch(1);
            PkiStore crashing = afterCredentialCommit(store, writes, true);
            RealProvider provider = new RealProvider(clock, Mode.SIGN);
            SigningOuterTerminalDriver outer = new SigningOuterTerminalDriver(crashing);
            try (RuntimeGraph graph = graph(crashing, clock, provider, workflow -> {
                try { outer.advance(workflow); }
                catch (RuntimeException expected) {
                    // Post-commit cleanup may report the newly owned content instead of the injected crash.
                    crash.countDown();
                    throw expected;
                }
            }, false)) {
                PreparedSemanticSigningRequest prepared = graph.service.prepareEndEntity(ACCESS, request(), Optional.empty(), CancellationSignal.NONE);
                operationId = prepared.receipt().operationId();
                graph.service.accept(prepared);
                frozen = command(store, operationId);
                graph.reactor.start();
                await(crash);
                assertEquals(SemanticSigningState.PUBLISHING, graph.service.find(operationId).orElseThrow().state());
                credentialId = issued(store, frozen).orElseThrow().credentialId();
                assertEquals(1, writes.get());
                assertEquals(1, provider.dispatches.get());
            }
        }
        clock.advance(Duration.ofMinutes(2));
        try (FilesystemPkiStore store = open(root, clock)) {
            CountDownLatch terminal = new CountDownLatch(1);
            PkiStore observed = afterCredentialCommit(store, writes, false);
            SigningOuterTerminalDriver outer = new SigningOuterTerminalDriver(observed);
            RealProvider provider = new RealProvider(clock, Mode.SIGN);
            try (RuntimeGraph graph = graph(observed, clock, provider, workflow -> {
                outer.advance(workflow);
                terminal.countDown();
            }, false)) {
                graph.reactor.start();
                await(terminal);
                assertEquals(SemanticSigningState.COMPLETED, graph.service.find(operationId).orElseThrow().state());
                assertEquals(credentialId, issued(store, frozen).orElseThrow().credentialId());
                assertEquals(1, writes.get());
                assertEquals(0, provider.dispatches.get());
                SignWorkflowStore.Workflow retired = store.getSignWorkflow(operationId).orElseThrow();
                outer.advance(retired);
                outer.advance(retired);
                assertEquals(1, writes.get());
            }
        }
    }

    @Test
    void reactiveLifecycleCompletesWithRealSignaturesAndFrozenIdentity(@TempDir Path root) throws Exception {
        for (LifecycleCase lifecycle : LifecycleCase.values()) {
            MutableClock clock = new MutableClock(NOW);
            try (FilesystemPkiStore store = fixture(root.resolve(lifecycle.name()), clock)) {
                Credential predecessor = lifecyclePredecessor(store, clock);
                CaRecord selectedIssuer = store.getCa(CA).orElseThrow();
                CertificateProfileRef selectedProfile = store.getActiveProfileRef("h7-dns").orElseThrow();
                if (lifecycle == LifecycleCase.REPLACE_NEW_KEY) {
                    store.transitionRevocation(new RevocationCommand.RevokePermanently(predecessor.credentialId(),
                            RevocationReason.KEY_COMPROMISE, new SimpleAttributeSet()), clock.instant());
                }
                CountDownLatch terminal = new CountDownLatch(1);
                SigningOuterTerminalDriver outer = new SigningOuterTerminalDriver(store);
                RealProvider provider = new RealProvider(clock, Mode.SIGN);
                try (RuntimeGraph graph = graph(store, clock, provider, workflow -> {
                    outer.advance(workflow);
                    terminal.countDown();
                }, false)) {
                    PreparedSemanticSigningRequest prepared = prepareLifecycle(graph.service, lifecycle, predecessor);
                    graph.service.accept(prepared);
                    DomainCommandEncoding.Decoded frozen = command(store, prepared.receipt().operationId());
                    replaceCurrentSelections(store, clock);
                    DefaultProfileService profiles = new DefaultProfileService(store, clock, new InMemoryAuditSink());
                    profiles.importProfile(new String(H7ProfileDocuments.dnsProfile(), StandardCharsets.UTF_8)
                            .replace("\"profileVersion\":1", "\"profileVersion\":2")
                            .replace("PT8760H", "PT24H").getBytes(StandardCharsets.UTF_8));
                    profiles.activateProfile("h7-dns", 2);
                    graph.reactor.start();
                    await(terminal);
                    SemanticSigningOperation completed = graph.service.find(prepared.receipt().operationId()).orElseThrow();
                    assertEquals(SemanticSigningState.COMPLETED, completed.state());
                    X509Certificate certificate = Pkix.parseCertificate(completed.result().orElseThrow().bytes());
                    certificate.verify(issuerKey.getPublic());
                    assertArrayEquals((lifecycle == LifecycleCase.REPLACE_NEW_KEY ? replacementLeafKey : leafKey)
                            .getPublic().getEncoded(), Pkix.subjectPublicKeyInfo(certificate));
                    boolean replace = lifecycle == LifecycleCase.REPLACE_NEW_KEY || lifecycle == LifecycleCase.REPLACE_SAME_KEY;
                    assertEquals(new X500Principal(replace ? "CN=Replacement Applicant" : "CN=Applicant"), certificate.getSubjectX500Principal());
                    assertEquals(new X500Principal("CN=Issuer"), certificate.getIssuerX500Principal());
                    assertEquals(List.of(List.of(2, replace ? "new.example.test" : "app.example.test")),
                            List.copyOf(certificate.getSubjectAlternativeNames()));
                    assertEquals(NOW.truncatedTo(ChronoUnit.SECONDS).plusSeconds(1), certificate.getNotBefore().toInstant());
                    assertEquals(NOW.truncatedTo(ChronoUnit.SECONDS).plusSeconds(365L * 86400), certificate.getNotAfter().toInstant());
                    assertFalse(certificate.getSerialNumber().equals(new BigInteger(predecessor.serialOrUniqueId())));
                    Credential successor = issued(store, frozen).orElseThrow();
                    assertEquals(new EndEntityProfileBinding(selectedProfile), successor.profileBinding());
                    assertEquals(selectedIssuer.currentIssuanceIssuerId(), successor.issuerRef().issuerId());
                    assertEquals(selectedIssuer.issuanceChainPathId(), successor.issuerRef().chainPathId());
                    assertEquals(certificate.getNotBefore().toInstant(), successor.validity().notBefore());
                    assertEquals(certificate.getNotAfter().toInstant(), successor.validity().notAfter());
                    assertEquals(Optional.of(predecessor.credentialId()), completed.scope().accessContext().objectId());
                    assertLifecycleOutcome(store, lifecycle, predecessor.credentialId(), successor,
                            lifecycle == LifecycleCase.REPLACE_NEW_KEY ? RevocationReason.KEY_COMPROMISE : RevocationReason.SUPERSEDED);
                    assertEquals(1, provider.dispatches.get());
                }
            }
        }
    }

    @Test
    void lifecycleCancellationExpiryDenialAndInvalidSignatureHaveNoPublicationEffects(@TempDir Path root) throws Exception {
        for (LifecycleCase lifecycle : LifecycleCase.values()) {
            for (Mode mode : List.of(Mode.CANCEL, Mode.EXPIRE, Mode.DENY, Mode.WRONG_KEY)) {
                MutableClock clock = new MutableClock(NOW);
                try (FilesystemPkiStore store = fixture(root.resolve(lifecycle.name() + mode.name()), clock)) {
                    Credential predecessor = lifecyclePredecessor(store, clock);
                    CountDownLatch terminal = new CountDownLatch(1);
                    SigningOuterTerminalDriver outer = new SigningOuterTerminalDriver(store);
                    RealProvider provider = new RealProvider(clock, mode);
                    try (RuntimeGraph graph = graph(store, clock, provider, workflow -> {
                        outer.advance(workflow);
                        terminal.countDown();
                    }, false)) {
                        PreparedSemanticSigningRequest prepared = prepareLifecycle(graph.service, lifecycle, predecessor);
                        graph.service.accept(prepared);
                        DomainCommandEncoding.Decoded frozen = command(store, prepared.receipt().operationId());
                        if (mode == Mode.CANCEL) { graph.service.cancel(prepared.receipt().operationId()); }
                        if (mode == Mode.EXPIRE) { clock.advance(Duration.ofMinutes(2)); }
                        graph.reactor.start();
                        await(terminal);
                        SemanticSigningOperation completed = graph.service.find(prepared.receipt().operationId()).orElseThrow();
                        assertEquals(mode == Mode.EXPIRE ? SemanticSigningState.EXPIRED : SemanticSigningState.FAILED, completed.state());
                        assertTrue(completed.result().isEmpty());
                        assertTrue(issued(store, frozen).isEmpty());
                        assertTrue(store.getRevocation(predecessor.credentialId()).isEmpty());
                        assertEquals(mode == Mode.CANCEL || mode == Mode.EXPIRE ? 0 : 1, provider.dispatches.get());
                    }
                }
            }
        }
    }

    @Test
    void lifecycleRestartResumesSupersessionWithoutAnotherSignatureOrCredential(@TempDir Path root) throws Exception {
        for (LifecycleCase lifecycle : LifecycleCase.values()) {
            Path directory = root.resolve(lifecycle.name());
            MutableClock clock = new MutableClock(NOW);
            AtomicInteger writes = new AtomicInteger();
            PkiId operationId;
            PkiId predecessorId;
            PkiId successorId;
            DomainCommandEncoding.Decoded frozen;
            try (FilesystemPkiStore store = fixture(directory, clock)) {
                Credential predecessor = lifecyclePredecessor(store, clock);
                predecessorId = predecessor.credentialId();
                CountDownLatch crash = new CountDownLatch(1);
                PkiStore crashing = afterCredentialCommit(store, writes, true);
                SigningOuterTerminalDriver outer = new SigningOuterTerminalDriver(crashing);
                RealProvider provider = new RealProvider(clock, Mode.SIGN);
                try (RuntimeGraph graph = graph(crashing, clock, provider, workflow -> {
                    try { outer.advance(workflow); }
                    catch (RuntimeException failure) { crash.countDown(); throw failure; }
                }, false)) {
                    PreparedSemanticSigningRequest prepared = prepareLifecycle(graph.service, lifecycle, predecessor);
                    operationId = prepared.receipt().operationId();
                    graph.service.accept(prepared);
                    frozen = command(store, operationId);
                    graph.reactor.start();
                    await(crash);
                    assertEquals(SemanticSigningState.PUBLISHING, graph.service.find(operationId).orElseThrow().state());
                    successorId = issued(store, frozen).orElseThrow().credentialId();
                    assertTrue(store.getRevocation(predecessorId).isEmpty());
                    assertEquals(1, writes.get());
                    assertEquals(1, provider.dispatches.get());
                }
            }
            clock.advance(Duration.ofMinutes(2));
            try (FilesystemPkiStore store = open(directory, clock)) {
                CountDownLatch terminal = new CountDownLatch(1);
                PkiStore observed = afterCredentialCommit(store, writes, false);
                SigningOuterTerminalDriver outer = new SigningOuterTerminalDriver(observed);
                RealProvider provider = new RealProvider(clock, Mode.SIGN);
                try (RuntimeGraph graph = graph(observed, clock, provider, workflow -> {
                    outer.advance(workflow);
                    terminal.countDown();
                }, false)) {
                    graph.reactor.start();
                    await(terminal);
                    SemanticSigningOperation completed = graph.service.find(operationId).orElseThrow();
                    assertEquals(SemanticSigningState.COMPLETED, completed.state());
                    Pkix.parseCertificate(completed.result().orElseThrow().bytes()).verify(issuerKey.getPublic());
                    Credential successor = issued(store, frozen).orElseThrow();
                    assertEquals(successorId, successor.credentialId());
                    assertLifecycleOutcome(store, lifecycle, predecessorId, successor, RevocationReason.SUPERSEDED);
                    assertEquals(0, provider.dispatches.get());
                    outer.advance(store.getSignWorkflow(operationId).orElseThrow());
                    outer.advance(store.getSignWorkflow(operationId).orElseThrow());
                    assertEquals(1, writes.get());
                    if (lifecycle != LifecycleCase.RENEW) {
                        assertEquals(1L, store.getRevocation(predecessorId).orElseThrow().transition().revision());
                    }
                }
            }
        }
    }

    private static Credential lifecyclePredecessor(FilesystemPkiStore store, Clock clock) throws Exception {
        DefaultProfileService profiles = new DefaultProfileService(store, clock, new InMemoryAuditSink());
        profiles.importProfile(H7ProfileDocuments.dnsProfile());
        profiles.activateProfile("h7-dns", 1);
        List<SubjectRdn> subject = List.of(new SubjectRdn(SubjectRdnType.COMMON_NAME, "Applicant"));
        Instant before = NOW.truncatedTo(ChronoUnit.SECONDS).minusSeconds(60);
        Instant after = before.plusSeconds(3600);
        X509Certificate certificate = Pkix.certificateBuilder().issuer(new X500Principal("CN=Issuer"))
                .subject(BcX509ProfileSupport.subject(subject)).serialNumber(BigInteger.TEN).validity(before, after)
                .publicKey(leafKey.getPublic()).basicConstraints(BasicConstraints.endEntity(), true)
                .keyUsage(Set.of(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT), true)
                .extendedKeyUsage(new ExtendedKeyUsage(List.of("1.3.6.1.5.5.7.3.1")), false)
                .subjectAlternativeNames(List.of(new GeneralName.DnsName("app.example.test")), false)
                .build(Pkix.signer(issuerKey.getPrivate(), X509_SIGNATURE));
        byte[] der = certificate.getEncoded();
        CaRecord ca = store.getCa(CA).orElseThrow();
        Credential credential = new Credential(new PkiId("x509:" + digest(der)), new FormatId("x509"),
                new IssuerRef(CA, ca.currentIssuanceIssuerId(), ca.issuanceChainPathId()),
                new SubjectRef(BcX509ProfileSupport.subjectRefString(subject)), new Validity(before, after), "10",
                new PkiId("spki:" + digest(leafKey.getPublic().getEncoded())),
                new EndEntityProfileBinding(store.getActiveProfileRef("h7-dns").orElseThrow()), CredentialStatus.ISSUED,
                PkiTestRuntime.stageCredential(store, der), new SimpleAttributeSet());
        store.putCredential(credential);
        return credential;
    }

    private static PreparedSemanticSigningRequest prepareLifecycle(SemanticSigningService service,
            LifecycleCase lifecycle, Credential predecessor) {
        return switch (lifecycle) {
            case RENEW -> service.prepareRenewal(ACCESS,
                    new EndEntityRenewalRequest(predecessor.credentialId(), Optional.empty()), Optional.empty(), CancellationSignal.NONE);
            case REISSUE -> service.prepareReissue(ACCESS, new EndEntityReissueRequest(predecessor.credentialId()), Optional.empty(), CancellationSignal.NONE);
            case REPLACE_SAME_KEY, REPLACE_NEW_KEY -> {
                KeyPair key = lifecycle == LifecycleCase.REPLACE_NEW_KEY ? replacementLeafKey : leafKey;
                byte[] replacementCsr = Pkix.certificationRequestBuilder().subject(new X500Principal("CN=Replacement Applicant"))
                        .publicKey(key.getPublic()).subjectAlternativeNames(List.of(new GeneralName.DnsName("new.example.test")), false)
                        .build(Pkix.signer(key.getPrivate(), X509_SIGNATURE)).encoded();
                yield service.prepareReplacement(ACCESS, new EndEntityReplacementRequest(predecessor.credentialId(), replacementCsr,
                        "h7-dns"), Optional.empty(), CancellationSignal.NONE);
            }
        };
    }

    private static void assertLifecycleOutcome(PkiStore store, LifecycleCase lifecycle, PkiId predecessor,
            Credential successor, RevocationReason reason) {
        if (lifecycle == LifecycleCase.RENEW) {
            assertTrue(CredentialLineage.supersededCredentialId(successor.attributes()).isEmpty());
            assertTrue(store.getRevocation(predecessor).isEmpty());
        } else {
            assertEquals(Optional.of(predecessor), CredentialLineage.supersededCredentialId(successor.attributes()));
            assertEquals(RevocationState.PERMANENTLY_REVOKED, store.getRevocation(predecessor).orElseThrow().transition().state());
            assertEquals(Optional.of(reason), store.getRevocation(predecessor).orElseThrow().transition().permanentReason());
        }
    }

    private static String digest(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private enum LifecycleCase { RENEW, REPLACE_SAME_KEY, REPLACE_NEW_KEY, REISSUE }

    @Test
    void correlatedPreparationCrashLeavesNoAdmissionAndRecoveryCleansCandidate(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        CorrelatedEndEntityIssuanceRequest input;
        AtomicReference<DurableContentReference> candidate = new AtomicReference<>();
        AtomicInteger stages = new AtomicInteger();
        try (FilesystemPkiStore store = fixture(root, clock)) {
            input = correlatedRequest(store, csr);
            try (RuntimeGraph graph = graph(store, clock, new RealProvider(clock, Mode.SIGN),
                    new SigningOuterTerminalDriver(store), false)) {
                assertTrue(graph.service.findIssuance(input).isEmpty());
                assertTrue(store.listSignWorkflows().isEmpty());
            }
        }
        try (FilesystemPkiStore store = open(root, clock)) {
            PkiStore observed = EndEntityIssuancePreparationTest.observePreparation(store, stages, candidate,
                    new AtomicBoolean(), false);
            RealProvider provider = new RealProvider(clock, Mode.SIGN);
            try (RuntimeGraph graph = graph(observed, clock, provider, new SigningOuterTerminalDriver(observed), false)) {
                assertTrue(graph.service.findIssuance(input).isEmpty());
                CorrelatedIssuancePreparation prepared = graph.service.prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), CancellationSignal.NONE);
                assertTrue(prepared instanceof CorrelatedIssuancePreparation.Prepared);
                assertEquals(1, stages.get());
                assertTrue(PkiTestRuntime.readContent(store, candidate.get()).length > 0);
                assertTrue(store.listSignWorkflows().isEmpty());
                assertEquals(0, provider.dispatches.get());
                // Simulate process loss: the ephemeral carrier is deliberately not discarded.
            }
        }
        try (FilesystemPkiStore store = open(root, clock);
                RuntimeGraph graph = graph(store, clock, new RealProvider(clock, Mode.SIGN), new SigningOuterTerminalDriver(store), false)) {
            assertTrue(graph.service.findIssuance(input).isEmpty());
            assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, candidate.get()));
            CorrelatedIssuancePreparation retry = graph.service.prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), CancellationSignal.NONE);
            graph.service.discard(((CorrelatedIssuancePreparation.Prepared) retry).prepared());
            assertTrue(store.listSignWorkflows().isEmpty());
        }
    }

    @Test
    void correlatedAcceptedBeforeReplyReplaysFrozenSelectionAcrossRestartAndRetention(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        CorrelatedEndEntityIssuanceRequest input;
        SigningAcceptanceReceipt receipt;
        DomainCommandEncoding.Decoded frozen;
        AtomicInteger writes = new AtomicInteger();
        PkiId credentialId;
        try (FilesystemPkiStore store = fixture(root, clock)) {
            input = correlatedRequest(store, csr);
            try (RuntimeGraph graph = graph(store, clock, new RealProvider(clock, Mode.SIGN), new SigningOuterTerminalDriver(store), true)) {
                PreparedSemanticSigningRequest prepared = ((CorrelatedIssuancePreparation.Prepared)
                        graph.service.prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), CancellationSignal.NONE)).prepared();
                receipt = prepared.receipt();
                assertThrows(IllegalStateException.class, () -> graph.service.accept(prepared));
                assertEquals(SigningAcceptanceResolution.MATCHED, graph.service.resolve(receipt));
                frozen = command(store, receipt.operationId());
                replaceCurrentSelections(store, clock);
            }
        }
        try (FilesystemPkiStore store = open(root, clock)) {
            PkiStore observed = noInventoryScans(afterCredentialCommit(store, writes, false));
            SigningOuterTerminalDriver outer = new SigningOuterTerminalDriver(observed);
            CountDownLatch terminal = new CountDownLatch(1);
            RealProvider provider = new RealProvider(clock, Mode.SIGN);
            try (RuntimeGraph graph = graph(observed, clock, provider, workflow -> {
                outer.advance(workflow); terminal.countDown();
            }, false)) {
                CorrelatedIssuancePreparation replay = graph.service.prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), CancellationSignal.NONE);
                assertEquals(receipt.operationId(), ((CorrelatedIssuancePreparation.Existing) replay).operation().submissionId().id());
                assertEquals(SigningAcceptanceResolution.MATCHED, graph.service.resolve(receipt));
                assertEquals(0, provider.dispatches.get());
                graph.reactor.start();
                await(terminal);
                SemanticSigningOperation completed = graph.service.findIssuance(input).orElseThrow();
                assertEquals(SemanticSigningState.COMPLETED, completed.state());
                X509Certificate certificate = Pkix.parseCertificate(completed.result().orElseThrow().bytes());
                certificate.verify(issuerKey.getPublic());
                assertArrayEquals(leafKey.getPublic().getEncoded(), Pkix.subjectPublicKeyInfo(certificate));
                Credential credential = issued(store, frozen).orElseThrow();
                credentialId = credential.credentialId();
                assertEquals(new EndEntityProfileBinding(input.intent().expectedProfile()), credential.profileBinding());
                assertEquals(input.intent().expectedIssuerId(), credential.issuerRef().issuerId());
                assertEquals(input.intent().expectedChainPathId(), credential.issuerRef().chainPathId());
                assertEquals(Optional.of(new AttributeValue.StringValue(input.intent().issuanceId())),
                        credential.attributes().get(IssuanceIntent.ID_ATTRIBUTE));
                assertEquals(Optional.of(new AttributeValue.StringValue(CorrelatedIssuanceIdentity.derive(input).effectiveCommitment())),
                        credential.attributes().get(IssuanceIntent.COMMITMENT_ATTRIBUTE));
                assertEquals(1, provider.dispatches.get());
                assertEquals(1, writes.get());
            }
        }
        try (FilesystemPkiStore store = open(root, clock)) {
            PkiStore points = noInventoryScans(store);
            try (RuntimeGraph graph = graph(points, clock, new RealProvider(clock, Mode.SIGN), new SigningOuterTerminalDriver(points), false)) {
                assertEquals(SemanticSigningState.COMPLETED, graph.service.findIssuance(input).orElseThrow().state());
                assertEquals(receipt.operationId(), ((CorrelatedIssuancePreparation.Existing)
                        graph.service.prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), CancellationSignal.NONE)).operation().submissionId().id());
                clock.advance(Duration.ofDays(91));
                assertEquals(1, store.purgeExpiredSignRecords());
                assertTrue(graph.service.findIssuance(input).isEmpty());
                assertTrue(store.getCredential(credentialId).isPresent());
            }
        }
    }

    @Test
    void correlatedPublicationRestartPreservesOneSignatureAndCredential(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        AtomicInteger writes = new AtomicInteger();
        CorrelatedEndEntityIssuanceRequest input;
        PkiId operationId;
        PkiId credentialId;
        DomainCommandEncoding.Decoded frozen;
        try (FilesystemPkiStore store = fixture(root, clock)) {
            input = correlatedRequest(store, csr);
            CountDownLatch crash = new CountDownLatch(1);
            PkiStore crashing = noInventoryScans(afterCredentialCommit(store, writes, true));
            RealProvider provider = new RealProvider(clock, Mode.SIGN);
            SigningOuterTerminalDriver outer = new SigningOuterTerminalDriver(crashing);
            try (RuntimeGraph graph = graph(crashing, clock, provider, workflow -> {
                try { outer.advance(workflow); }
                catch (RuntimeException expected) { crash.countDown(); throw expected; }
            }, false)) {
                PreparedSemanticSigningRequest prepared = ((CorrelatedIssuancePreparation.Prepared)
                        graph.service.prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), CancellationSignal.NONE)).prepared();
                operationId = graph.service.accept(prepared).receipt().operationId();
                frozen = command(store, operationId);
                graph.reactor.start();
                await(crash);
                assertEquals(SemanticSigningState.PUBLISHING, graph.service.findIssuance(input).orElseThrow().state());
                credentialId = issued(store, frozen).orElseThrow().credentialId();
                assertEquals(1, writes.get());
                assertEquals(1, provider.dispatches.get());
            }
        }
        clock.advance(Duration.ofMinutes(2));
        try (FilesystemPkiStore store = open(root, clock)) {
            CountDownLatch terminal = new CountDownLatch(1);
            PkiStore observed = noInventoryScans(canonicalCredentialAttributes(
                    afterCredentialCommit(store, writes, false), credentialId));
            SigningOuterTerminalDriver outer = new SigningOuterTerminalDriver(observed);
            RealProvider provider = new RealProvider(clock, Mode.SIGN);
            try (RuntimeGraph graph = graph(observed, clock, provider, workflow -> {
                outer.advance(workflow); terminal.countDown();
            }, false)) {
                assertEquals(operationId, ((CorrelatedIssuancePreparation.Existing)
                        graph.service.prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), CancellationSignal.NONE)).operation().submissionId().id());
                graph.reactor.start();
                await(terminal);
                assertEquals(SemanticSigningState.COMPLETED, graph.service.findIssuance(input).orElseThrow().state());
                assertEquals(credentialId, issued(store, frozen).orElseThrow().credentialId());
                assertEquals(1, writes.get());
                assertEquals(0, provider.dispatches.get());
            }
        }
    }

    @Test
    void concurrentCorrelatedRealIssuancePublishesExactlyOnce(@TempDir Path root) throws Exception {
        for (boolean changedCsr : List.of(false, true)) {
            MutableClock clock = new MutableClock(NOW);
            AtomicInteger writes = new AtomicInteger();
            try (FilesystemPkiStore store = fixture(root.resolve(Boolean.toString(changedCsr)), clock);
                    ExecutorService callers = Executors.newFixedThreadPool(2)) {
                CorrelatedEndEntityIssuanceRequest input = correlatedRequest(store, csr);
                byte[] changed = Pkix.certificationRequestBuilder().subject(new X500Principal("CN=Different"))
                        .publicKey(leafKey.getPublic()).build(Pkix.signer(leafKey.getPrivate(), X509_SIGNATURE)).encoded();
                CorrelatedEndEntityIssuanceRequest other = changedCsr
                        ? new CorrelatedEndEntityIssuanceRequest(new EndEntityIssuanceRequest(CA, changed, PROFILE, Optional.empty()), input.intent())
                        : input;
                PkiStore observed = noInventoryScans(afterCredentialCommit(store, writes, false));
                SigningOuterTerminalDriver outer = new SigningOuterTerminalDriver(observed);
                CountDownLatch terminal = new CountDownLatch(1);
                RealProvider provider = new RealProvider(clock, Mode.SIGN);
                try (RuntimeGraph graph = graph(observed, clock, provider, workflow -> {
                    outer.advance(workflow); terminal.countDown();
                }, false)) {
                    CyclicBarrier ready = new CyclicBarrier(2);
                    Future<SigningAcceptanceResult> first = callers.submit(() -> correlatedAccept(graph.service, input, ready));
                    Future<SigningAcceptanceResult> second = callers.submit(() -> correlatedAccept(graph.service, other, ready));
                    SigningAcceptanceResult firstResult = first.get(15, TimeUnit.SECONDS);
                    SigningAcceptanceResult secondResult = second.get(15, TimeUnit.SECONDS);
                    boolean firstWon = firstResult.disposition() == SigningAcceptanceDisposition.ACCEPTED;
                    SigningAcceptanceResult winner = firstWon ? firstResult : secondResult;
                    SigningAcceptanceResult loser = firstWon ? secondResult : firstResult;
                    assertEquals(SigningAcceptanceDisposition.ACCEPTED, winner.disposition());
                    assertEquals(changedCsr ? SigningAcceptanceDisposition.CONFLICT : SigningAcceptanceDisposition.ATTACHED_EXISTING,
                            loser.disposition());
                    if (!changedCsr) assertEquals(winner.receipt(), loser.receipt());
                    assertEquals(1, store.listSignWorkflows().size());
                    graph.reactor.start();
                    await(terminal);
                    CorrelatedEndEntityIssuanceRequest winnerInput = firstWon ? input : other;
                    assertEquals(SemanticSigningState.COMPLETED, graph.service.findIssuance(winnerInput).orElseThrow().state());
                    if (changedCsr) {
                        CorrelatedEndEntityIssuanceRequest loserInput = firstWon ? other : input;
                        assertThrows(PkiException.class, () -> graph.service.findIssuance(loserInput));
                        assertThrows(PkiException.class,
                                () -> graph.service.prepareCorrelatedEndEntity(ACCESS, loserInput, Optional.empty(), CancellationSignal.NONE));
                    }
                    assertEquals(1, provider.dispatches.get());
                    assertEquals(1, writes.get());
                }
            }
        }
    }

    @Test
    void correlatedTerminalFailuresReplayAcrossRestartWithoutPublication(@TempDir Path root) throws Exception {
        for (Mode mode : List.of(Mode.CANCEL, Mode.EXPIRE, Mode.DENY, Mode.WRONG_KEY)) {
            Path directory = root.resolve(mode.name());
            MutableClock clock = new MutableClock(NOW);
            CorrelatedEndEntityIssuanceRequest input;
            PkiId operationId;
            DomainCommandEncoding.Decoded frozen;
            try (FilesystemPkiStore store = fixture(directory, clock)) {
                input = correlatedRequest(store, csr);
                CountDownLatch terminal = new CountDownLatch(1);
                SigningOuterTerminalDriver outer = new SigningOuterTerminalDriver(store);
                RealProvider provider = new RealProvider(clock, mode);
                try (RuntimeGraph graph = graph(store, clock, provider, workflow -> {
                    outer.advance(workflow); terminal.countDown();
                }, false)) {
                    PreparedSemanticSigningRequest prepared = ((CorrelatedIssuancePreparation.Prepared)
                            graph.service.prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), CancellationSignal.NONE)).prepared();
                    operationId = graph.service.accept(prepared).receipt().operationId();
                    frozen = command(store, operationId);
                    if (mode == Mode.CANCEL) graph.service.cancel(operationId);
                    if (mode == Mode.EXPIRE) clock.advance(Duration.ofMinutes(2));
                    graph.reactor.start();
                    await(terminal);
                    assertTrue(issued(store, frozen).isEmpty());
                    assertEquals(mode == Mode.CANCEL || mode == Mode.EXPIRE ? 0 : 1, provider.dispatches.get());
                }
            }
            try (FilesystemPkiStore store = open(directory, clock)) {
                RealProvider provider = new RealProvider(clock, Mode.SIGN);
                try (RuntimeGraph graph = graph(store, clock, provider, new SigningOuterTerminalDriver(store), false)) {
                    CorrelatedIssuancePreparation.Existing replay = (CorrelatedIssuancePreparation.Existing)
                            graph.service.prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), CancellationSignal.NONE);
                    assertEquals(operationId, replay.operation().submissionId().id());
                    assertEquals(mode == Mode.EXPIRE ? SemanticSigningState.EXPIRED : SemanticSigningState.FAILED,
                            replay.operation().state());
                    assertTrue(replay.operation().result().isEmpty());
                    assertTrue(issued(store, frozen).isEmpty());
                    assertEquals(0, provider.dispatches.get());
                }
            }
        }
    }

    private static CorrelatedEndEntityIssuanceRequest correlatedRequest(PkiStore store, byte[] requestDer) {
        CaRecord ca = store.getCa(CA).orElseThrow();
        IssuerChainPath path = store.getIssuerChainPath(ca.issuanceChainPathId()).orElseThrow();
        return new CorrelatedEndEntityIssuanceRequest(new EndEntityIssuanceRequest(CA, requestDer, PROFILE, Optional.empty()),
                new IssuanceIntent("acme-order-1", "1".repeat(64), store.getActiveProfileRef(PROFILE).orElseThrow(),
                        ca.currentIssuanceIssuerId(), path.pathId(), path.pathCommitment()));
    }

    private static SigningAcceptanceResult correlatedAccept(SemanticSigningService service,
            CorrelatedEndEntityIssuanceRequest request, CyclicBarrier ready) throws Exception {
        CorrelatedIssuancePreparation result = service.prepareCorrelatedEndEntity(ACCESS, request, Optional.empty(), CancellationSignal.NONE);
        PreparedSemanticSigningRequest prepared = ((CorrelatedIssuancePreparation.Prepared) result).prepared();
        ready.await(10, TimeUnit.SECONDS);
        return service.accept(prepared);
    }

    private static PkiStore noInventoryScans(PkiStore store) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, arguments) -> {
                    if (method.getName().equals("getCredentialByIssuanceIntent") || method.getName().startsWith("list")) {
                        throw new AssertionError("Unexpected inventory scan: " + method.getName());
                    }
                    try { return method.invoke(store, arguments); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
    }

    private static PkiStore canonicalCredentialAttributes(PkiStore store, PkiId credentialId) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, arguments) -> {
                    try {
                        Object result = method.invoke(store, arguments);
                        if (method.getName().equals("getCredential") && credentialId.equals(arguments[0])) {
                            Credential credential = (Credential) ((Optional<?>) result).orElseThrow();
                            // Equivalent persisted attribute ordering must replay independently
                            // of the JVM's immutable-set iteration randomization.
                            List<SimpleAttributeSet.Entry> entries = credential.attributes().ids().stream()
                                    .sorted(java.util.Comparator.comparing(zeroecho.pki.api.attr.AttributeId::value))
                                    .map(id -> new SimpleAttributeSet.Entry(id, credential.attributes().getAll(id))).toList();
                            return Optional.of(new Credential(credential.credentialId(), credential.formatId(),
                                    credential.issuerRef(), credential.subjectRef(), credential.validity(),
                                    credential.serialOrUniqueId(), credential.publicKeyId(), credential.profileBinding(),
                                    credential.status(), credential.content(), new SimpleAttributeSet(entries)));
                        }
                        return result;
                    } catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
    }

    private static RuntimeGraph graph(PkiStore store, Clock clock, RealProvider provider,
            SigningStepExecutor.OuterTerminalDriver outer, boolean loseAcknowledgement) {
        SigningTopology topology = new SigningTopology(new SigningCoordinatorLimits(8, Duration.ofSeconds(10),
                Duration.ofSeconds(5), Duration.ofDays(1), Duration.ofSeconds(5)), List.of(), new SigningLanePool(1, 8));
        SigningReactor reactor = new SigningReactor(store, provider, topology, outer);
        DefaultSigningService signing = new DefaultSigningService(store, provider, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, Duration.ofMinutes(1),
                new SecureRandom(), reactor::requireAccepting, (command, custody) -> {
                    SignWorkflowStore.AcceptanceResult result = reactor.acceptSign(command, custody);
                    if (loseAcknowledgement) { throw new IllegalStateException("Simulated lost acknowledgement"); }
                    return result;
                }, reactor::wake,
                (boundedWaitId, boundedWaitCancellation) -> { throw new UnsupportedOperationException("Fixture has no reactor wait"); });
        return new RuntimeGraph(reactor, new DefaultSemanticSigningService(store, signing,
                PkiTestRuntime.endEntityPreparation(store, clock)));
    }

    private static FilesystemPkiStore fixture(Path root, Clock clock) throws Exception {
        FilesystemPkiStore store = open(root, clock);
        DefaultProfileService profiles = new DefaultProfileService(store, clock, new InMemoryAuditSink());
        profiles.importProfile(H7ProfileDocuments.noSanOrEkuProfile());
        profiles.activateProfile(PROFILE, 1);
        putIssuer(store, issuerKey, KEY, "Issuer", 1);
        return store;
    }

    private static FilesystemPkiStore open(Path root, Clock clock) {
        return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock);
    }

    private static void replaceCurrentSelections(PkiStore store, Clock clock) throws Exception {
        DefaultProfileService profiles = new DefaultProfileService(store, clock, new InMemoryAuditSink());
        byte[] versionTwo = new String(H7ProfileDocuments.noSanOrEkuProfile(), StandardCharsets.UTF_8)
                .replace("\"profileVersion\":1", "\"profileVersion\":2")
                .replace("PT8760H", "PT24H").getBytes(StandardCharsets.UTF_8);
        profiles.importProfile(versionTwo);
        profiles.activateProfile(PROFILE, 2);
        putIssuer(store, replacementKey, new KeyRef("key:replacement"), "Replacement", 2);
    }

    private static void putIssuer(PkiStore store, KeyPair key, KeyRef keyRef, String name, int serial) throws Exception {
        Instant before = NOW.truncatedTo(ChronoUnit.SECONDS).minusSeconds(60);
        Instant after = NOW.truncatedTo(ChronoUnit.SECONDS).plusSeconds(800L * 86400);
        X500Principal subject = new X500Principal(store.getCa(CA).map(previous -> previous.subjectRef().value())
                .orElse("CN=" + name));
        X509Certificate certificate = Pkix.certificateBuilder().issuer(subject).subject(subject)
                .serialNumber(BigInteger.valueOf(serial)).validity(before, after).publicKey(key.getPublic())
                .basicConstraints(BasicConstraints.ca(), true).keyUsage(Set.of(KeyUsage.KEY_CERT_SIGN), true)
                .build(Pkix.signer(key.getPrivate(), X509_SIGNATURE));
        PkiId id = new PkiId("credential:issuer-" + serial);
        PkiId rootIssuer = IssuerGeneration.idFor(CA, id);
        Credential credential = new Credential(id, new FormatId("x509"),
                new IssuerRef(CA, rootIssuer, IssuerChainPath.create(CA, rootIssuer, List.of(id)).pathId()), new SubjectRef(subject.getName()),
                new Validity(before, after), Integer.toString(serial), new PkiId("spki:issuer-" + serial),
                new CaProfileBinding(new CertificateProfileRef("root", 1, new byte[32])), CredentialStatus.ISSUED,
                PkiTestRuntime.stageCredential(store, certificate.getEncoded()), SimpleAttributeSet.builder().build());
        store.putCredential(credential);
        IssuerGeneration generation = new IssuerGeneration(IssuerGeneration.idFor(CA, id), CA, id, keyRef,
                IssuerGenerationState.ACTIVE, "00".repeat(32), "00".repeat(32));
        IssuerChainPath path = IssuerChainPath.create(CA, generation.issuerId(), List.of(id));
        store.putIssuerGeneration(generation);
        store.putIssuerChainPath(path);
        List<PkiId> generations = store.getCa(CA).map(previous -> {
            java.util.ArrayList<PkiId> ids = new java.util.ArrayList<>(previous.issuerIds());
            ids.add(generation.issuerId());
            return List.copyOf(ids);
        }).orElse(List.of(generation.issuerId()));
        store.putCa(new CaRecord(CA, CaKind.ROOT, CaState.ACTIVE, keyRef, credential.subjectRef(), generations,
                generation.issuerId(), path.pathId()));
    }

    private static DomainCommandEncoding.Decoded command(PkiStore store, PkiId operationId) {
        return DomainCommandEncoding.decode(store.getSignWorkflow(operationId).orElseThrow().envelope().outer().orElseThrow().command());
    }

    private static Optional<Credential> issued(PkiStore store, DomainCommandEncoding.Decoded command) {
        return store.getCredentialByIssuerAndSerial(new PkiId(command.field(1)), new BigInteger(command.field(10)));
    }

    private static EndEntityIssuanceRequest request() {
        return new EndEntityIssuanceRequest(CA, csr, PROFILE, Optional.empty());
    }

    private static PkiStore afterCredentialCommit(PkiStore store, AtomicInteger writes, boolean crash) {
        AtomicBoolean first = new AtomicBoolean(true);
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, arguments) -> {
                    try {
                        boolean publication = method.getName().equals("putCredentialFromSigning")
                                && store.getCredential(((Credential) arguments[0]).credentialId()).isEmpty();
                        Object result = method.invoke(store, arguments);
                        if (publication) {
                            writes.incrementAndGet();
                            if (crash && first.getAndSet(false)) { throw new SimulatedCrash(); }
                        }
                        return result;
                    } catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
    }

    private static void await(CountDownLatch latch) throws InterruptedException {
        assertTrue(latch.await(10, TimeUnit.SECONDS), "Expected durable lifecycle boundary");
    }

    private static void awaitUnchecked(CountDownLatch latch) {
        try { await(latch); }
        catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new AssertionError(interrupted); }
    }

    private record RuntimeGraph(SigningReactor reactor, SemanticSigningService service) implements AutoCloseable {
        @Override public void close() { reactor.close(); }
    }

    private enum Mode { SIGN, CANCEL, EXPIRE, DENY, WRONG_KEY }

    private static final class RealProvider implements SigningProvider {
        @Override public zeroecho.pki.spi.crypto.SigningInputCapabilities inputCapabilities() {
            return new zeroecho.pki.spi.crypto.SigningInputCapabilities(Long.MAX_VALUE, java.util.Map.of());
        }
        private final Clock clock;
        private final Mode mode;
        private final AtomicInteger dispatches = new AtomicInteger();
        RealProvider(Clock clock, Mode mode) { this.clock = clock; this.mode = mode; }
        @Override public String id() { return "reactive-issuance-test"; }
        @Override public ConfigurationCommitment configurationCommitment() { return new ConfigurationCommitment(new byte[32]); }
        @Override public Set<String> supportedAlgorithms() { return Set.of(ALGORITHM); }
        @Override public OperationObservation dispatch(SignRequest request, CallControl control) {
            dispatches.incrementAndGet();
            assertEquals(KEY, request.keyRef());
            if (mode == Mode.DENY) {
                return new OperationObservation(request.operationId(), ObservationState.FAILED, clock.instant(),
                        DetailCode.DENIED, Optional.empty());
            }
            try (InputStream input = request.content().openStream()) {
                Signature signer = Signature.getInstance("SHA256withRSA");
                signer.initSign(mode == Mode.WRONG_KEY ? replacementKey.getPrivate() : issuerKey.getPrivate());
                signer.update(input.readAllBytes());
                return new OperationObservation(request.operationId(), ObservationState.SUCCEEDED, clock.instant(),
                        DetailCode.SIGNED, Optional.of(new EncodedObject(Encoding.BINARY, signer.sign())));
            } catch (Exception failure) { throw new AssertionError(failure); }
        }
        @Override public OperationObservation reconcile(PkiId operationId, CallControl control) { throw new AssertionError("Unexpected reconciliation"); }
        @Override public OperationObservation cancel(PkiId operationId, long fence, CancellationReason reason, CallControl control) {
            return new OperationObservation(operationId, ObservationState.CANCELLED, clock.instant(), DetailCode.CANCELLED, Optional.empty());
        }
        @Override public void close() { }
    }

    private static final class MutableClock extends Clock {
        private volatile Instant now;
        MutableClock(Instant now) { this.now = now; }
        void advance(Duration duration) { now = now.plus(duration); }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }

    private static final class SimulatedCrash extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }
}
