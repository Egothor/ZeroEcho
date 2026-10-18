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

package zeroecho.pki.application;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.OneShotContent;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.api.SigningService;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.api.signing.PreparedSigningRequest;
import zeroecho.pki.api.signing.SigningOperationState;
import zeroecho.pki.api.signing.SigningRequest;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.spi.crypto.SigningInputCapabilities;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProviderRuntimeDependencies;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.PkiStoreRuntimeDependencies;
import zeroecho.pki.spi.store.RevocationView;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.impl.fs.FilesystemPkiStoreTestAccess;
import zeroecho.pki.testkit.IntermediateCreationFixture;
import zeroecho.pki.testkit.IntermediateIssuanceFixture;
import zeroecho.pki.testkit.PkiTestRuntime;
import zeroecho.pkix.BasicConstraints;
import zeroecho.pkix.KeyUsage;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.crl.CrlReason;
import zeroecho.pkix.ocsp.CertStatus;
import zeroecho.pkix.ocsp.OcspResponse;

/** Real session/reactor OCSP signing and bounded failure/custody contracts. */
final class DefaultOcspResponseServiceTest {
    private static final String ALGORITHM = IntermediateCreationFixture.ALGORITHM;
    private static final String RESPONSE_FAILURE = "OCSP response generation failed: code=OCSP_RESPONSE_FAILED";
    private static final String BINDING_FAILURE = "OCSP signing binding validation failed: code=OCSP_SIGNING_BINDING_FAILED";

    @Test
    void mixedStatusesHashesResponderFormsNonceAndExactChainUseOneClosedSnapshot(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture();
        try (PkiSession session = fixture.open(root, true)) {
            Credential good = fixture.issue(3);
            Credential held = fixture.issue(4);
            Credential revoked = fixture.issue(5);
            fixture.store.transitionRevocation(new RevocationCommand.Hold(held.credentialId(), new SimpleAttributeSet()),
                    IntermediateCreationFixture.NOW.minusSeconds(2).plusNanos(123));
            fixture.store.transitionRevocation(new RevocationCommand.RevokePermanently(revoked.credentialId(),
                    RevocationReason.KEY_COMPROMISE, new SimpleAttributeSet()), IntermediateCreationFixture.NOW.minusSeconds(1));
            for (OcspResponseService.CertIdHash hash : OcspResponseService.CertIdHash.values()) {
                for (OcspResponseService.ResponderId responder : OcspResponseService.ResponderId.values()) {
                    fixture.resetReads();
                    OcspResponseService.CertId mismatch = new OcspResponseService.CertId(hash,
                            new byte[hash == OcspResponseService.CertIdHash.SHA1 ? 20 : 32],
                            new byte[hash == OcspResponseService.CertIdHash.SHA1 ? 20 : 32], BigInteger.valueOf(3));
                    List<OcspResponseService.CertId> requests = List.of(fixture.id(hash, 3), fixture.id(hash, 4),
                            fixture.id(hash, 5), fixture.id(hash, 99), mismatch);
                    OcspResponseService.Command command = fixture.command(requests, responder, Optional.of(new byte[] { 5, 6 }));
                    OcspResponseService.Response response = session.ocsp().orElseThrow().respond(command);
                    assertEquals(1, response.goodCount());
                    assertEquals(2, response.revokedCount());
                    assertEquals(2, response.unknownCount());
                    assertEquals(1, fixture.viewsOpened.get());
                    assertEquals(1, fixture.viewsClosed.get());
                    assertEquals(4, fixture.serialQueries.get());
                    assertEquals(Map.of(fixture.issuer.credentialId(), 1, fixture.parent.credentialId(), 1), fixture.certificateReads);
                    assertEquals(2, response.revocationRevision());
                    try (RevocationView view = fixture.store.openRevocationView()) {
                        assertEquals(view.commitment(), response.revocationCommitment());
                    }
                    OcspResponse decoded = Pkix.parseOcspResponse(response.der());
                    assertTrue(decoded.verifySignature(fixture.issuerCertificate.getPublicKey()));
                    assertEquals(command.producedAt(), decoded.producedAt());
                    assertArrayEquals(new byte[] { 5, 6 }, decoded.nonce().orElseThrow());
                    assertEquals(2, decoded.certificates().size());
                    assertArrayEquals(fixture.issuerCertificate.getEncoded(), decoded.certificates().get(0).getEncoded());
                    assertArrayEquals(fixture.parentCertificate.getEncoded(), decoded.certificates().get(1).getEncoded());
                    assertTrue(decoded.responses().get(0).status() instanceof CertStatus.Good);
                    assertEquals(Optional.of(CrlReason.CERTIFICATE_HOLD),
                            ((CertStatus.Revoked) decoded.responses().get(1).status()).reason());
                    assertEquals(Optional.of(CrlReason.KEY_COMPROMISE),
                            ((CertStatus.Revoked) decoded.responses().get(2).status()).reason());
                    assertEquals(Pkix.computeCertId(fixture.issuerCertificate, new BigInteger(good.serialOrUniqueId()),
                            hash == OcspResponseService.CertIdHash.SHA1 ? "1.3.14.3.2.26" : "2.16.840.1.101.3.4.2.1"),
                            decoded.responses().get(4).certId());
                    assertTrue(decoded.responses().get(4).status() instanceof CertStatus.Unknown);
                    SignWorkflowStore.Workflow signed = fixture.store.getSignWorkflow(fixture.provider.lastId).orElseThrow();
                    assertEquals(IntermediateIssuanceFixture.SUBJECT, signed.envelope().fairnessAuthorityId());
                    assertEquals("SYSTEM", signed.envelope().accessContext().principal().type());
                    assertEquals("pki", signed.envelope().accessContext().principal().name());
                    assertEquals("X509_SIGN", signed.envelope().accessContext().purpose().value());
                    assertTrue(signed.envelope().accessContext().objectId().isEmpty());
                    assertTrue(signed.envelope().accessContext().formatId().isEmpty());
                    assertEquals(ALGORITHM, signed.envelope().algorithmId());
                    assertEquals(SignWorkflowStore.Mode.BOUNDED_OBSERVATION, signed.mode());
                    assertTrue(signed.envelope().outer().isEmpty());
                }
            }
        }
    }

    @Test
    void bindingProofUsesExactChallengeExplicitIntermediateFairnessAndSelectedBinding(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture();
        try (PkiSession session = fixture.open(root, true)) {
            assertFalse(fixture.issuer.issuerRef().caId().equals(IntermediateIssuanceFixture.SUBJECT));
            session.ocsp().orElseThrow().validateSigningBinding(IntermediateIssuanceFixture.SUBJECT,
                    fixture.issuer.credentialId(), IntermediateCreationFixture.CHILD_KEY, ALGORITHM, fixture.binding());
            assertArrayEquals("ZeroEcho OCSP signing binding v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                    fixture.provider.lastContent);
            SignWorkflowStore.Workflow signed = fixture.store.getSignWorkflow(fixture.provider.lastId).orElseThrow();
            assertEquals(IntermediateIssuanceFixture.SUBJECT, signed.envelope().fairnessAuthorityId());
            assertEquals(Encoding.BINARY, signed.envelope().candidate().encoding());
            assertEquals(ALGORITHM, signed.envelope().algorithmId());
            fixture.provider.wrongKey = true;
            assertSafe(BINDING_FAILURE, () -> session.ocsp().orElseThrow().validateSigningBinding(
                    IntermediateIssuanceFixture.SUBJECT, fixture.issuer.credentialId(), IntermediateCreationFixture.CHILD_KEY,
                    ALGORITHM, Optional.empty()));
        }
    }

    @Test
    void authorityAlgorithmAndWrongKeyFailuresAreSafeAndNeverReturnUnverifiedDer(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture();
        try (PkiSession session = fixture.open(root, true)) {
            OcspResponseService service = session.ocsp().orElseThrow();
            OcspResponseService.Command original = fixture.command(List.of(fixture.id(OcspResponseService.CertIdHash.SHA256, 99)),
                    OcspResponseService.ResponderId.BY_NAME, Optional.empty());
            int before = fixture.provider.dispatches.get();
            assertSafe(RESPONSE_FAILURE, () -> service.respond(copy(original, IntermediateCreationFixture.CA,
                    original.signingKeyRef(), original.signatureAlgorithm(), original.signatureBindingId())));
            assertSafe(RESPONSE_FAILURE, () -> service.respond(copy(original, original.authorityId(),
                    IntermediateCreationFixture.PARENT_KEY, original.signatureAlgorithm(), original.signatureBindingId())));
            assertSafe(RESPONSE_FAILURE, () -> service.respond(copy(original, original.authorityId(), original.signingKeyRef(),
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(), Optional.empty())));
            assertSafe(RESPONSE_FAILURE, () -> service.respond(copy(original, original.authorityId(), original.signingKeyRef(),
                    ALGORITHM, Optional.of("not-an-installed-binding"))));
            assertEquals(before, fixture.provider.dispatches.get());
            fixture.provider.wrongKey = true;
            assertSafe(RESPONSE_FAILURE, () -> service.respond(original));
            assertEquals(before + 1, fixture.provider.dispatches.get());
        }
    }

    @Test
    void corruptionFailsBeforeSigningRatherThanBecomingUnknown(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture();
        try (PkiSession session = fixture.open(root, true)) {
            fixture.issue(3);
            fixture.corruptView = true;
            assertSafe(RESPONSE_FAILURE, () -> session.ocsp().orElseThrow().respond(fixture.command(
                    List.of(fixture.id(OcspResponseService.CertIdHash.SHA1, 3)),
                    OcspResponseService.ResponderId.BY_KEY, Optional.empty())));
            assertEquals(1, fixture.viewsClosed.get());
            assertEquals(0, fixture.provider.dispatches.get());
        }
    }

    @Test
    void alreadyCancelledResponseAndBindingFailSafelyBeforePreparationOrAcceptance(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture();
        try (PkiSession session = fixture.open(root, true)) {
            AtomicInteger signingCalls = new AtomicInteger();
            SigningService observed = signingProxy(session.signing().orElseThrow(), (method, arguments) -> signingCalls.incrementAndGet());
            DefaultOcspResponseService service = fixture.ocsp(observed);
            OcspResponseService.Command command = fixture.command(
                    List.of(fixture.id(OcspResponseService.CertIdHash.SHA256, 99)),
                    OcspResponseService.ResponderId.BY_NAME, Optional.empty());
            fixture.resetReads();
            CancellationSignal cancelled = () -> true;

            assertSafe(RESPONSE_FAILURE, () -> service.respond(command, cancelled));
            assertSafe(BINDING_FAILURE, () -> service.validateSigningBinding(IntermediateIssuanceFixture.SUBJECT,
                    fixture.issuer.credentialId(), IntermediateCreationFixture.CHILD_KEY, ALGORITHM,
                    fixture.binding(), cancelled));

            assertEquals(0, signingCalls.get());
            assertEquals(0, fixture.provider.dispatches.get());
            assertEquals(0, fixture.provider.initialObservations.get());
            assertTrue(fixture.certificateReads.isEmpty());
            assertEquals(0, fixture.viewsOpened.get());
        }
    }

    @Test
    void pendingDispositionSurvivesCancellationFailureWithoutDiscardOrResubmission(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture();
        try (PkiSession session = fixture.open(root, true)) {
            fixture.provider.pending = true;
            AtomicInteger accepts = new AtomicInteger();
            AtomicInteger cancels = new AtomicInteger();
            AtomicInteger discards = new AtomicInteger();
            SigningService observed = signingProxy(session.signing().orElseThrow(), (method, arguments) -> {
                if ("accept".equals(method)) accepts.incrementAndGet();
                if ("discard".equals(method)) discards.incrementAndGet();
                if ("cancel".equals(method)) {
                    cancels.incrementAndGet();
                    throw new PkiException("Cleanup-private diagnostic");
                }
            });
            DefaultOcspResponseService service = fixture.ocsp(observed);
            OcspResponseService.SigningPendingException failure = assertThrows(OcspResponseService.SigningPendingException.class,
                    () -> service.respond(fixture.command(List.of(fixture.id(OcspResponseService.CertIdHash.SHA1, 99)),
                            OcspResponseService.ResponderId.BY_NAME, Optional.empty())));
            assertEquals("OCSP signing remains pending", failure.getMessage());
            assertEquals(null, failure.getCause());
            assertEquals(1, accepts.get());
            assertEquals(1, cancels.get());
            assertEquals(0, discards.get());
            assertEquals(1, fixture.provider.dispatches.get());
            assertEquals(1, fixture.provider.initialObservations.get());
            session.signing().orElseThrow().cancel(fixture.provider.lastId);
        }
    }

    @Test
    void failedInitialAttemptRemainsOcspFailureWhenCleanupFindsSuccess(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture();
        try (PkiSession session = fixture.open(root, true)) {
            fixture.provider.pending = true;
            fixture.provider.failObservation = true;
            fixture.provider.cleanupSuccess = true;
            assertSafe(RESPONSE_FAILURE, () -> session.ocsp().orElseThrow().respond(fixture.command(
                    List.of(fixture.id(OcspResponseService.CertIdHash.SHA256, 99)),
                    OcspResponseService.ResponderId.BY_KEY, Optional.empty())));
            PkiId operation = fixture.provider.lastId;
            awaitRetired(fixture.store, operation);
            assertEquals(SignWorkflowStore.InitialAttemptPhase.FAILED,
                    fixture.store.getSignWorkflow(operation).orElseThrow().initialAttemptPhase());
            assertEquals(SigningOperationState.SUCCEEDED, session.signing().orElseThrow().find(operation).orElseThrow().state());
            assertEquals(1, fixture.provider.dispatches.get());
            assertEquals(1, fixture.provider.initialObservations.get());
        }
    }

    @Test
    void realDurableCapacityRejectionPreservesOverloadForResponseAndProof(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture();
        fixture.capacity = 1;
        try (PkiSession session = fixture.open(root, true)) {
            fixture.provider.blockDispatch = true;
            SigningService signing = session.signing().orElseThrow();
            SigningRequest request = new SigningRequest(signing.newSubmissionId(), IntermediateCreationFixture.ACCESS,
                    IntermediateCreationFixture.CHILD_KEY, IntermediateIssuanceFixture.SUBJECT,
                    BootstrapAlgorithmIdentities.ED25519_SIGNATURE, Encoding.BINARY, Encoding.BINARY);
            PreparedSigningRequest prepared = signing.prepare(request, oneShot(new byte[] { 1 }), CancellationSignal.NONE);
            signing.accept(prepared);
            assertTrue(fixture.provider.entered.await(5, TimeUnit.SECONDS));
            try {
                assertOverloaded(() -> session.ocsp().orElseThrow().respond(fixture.command(
                        List.of(fixture.id(OcspResponseService.CertIdHash.SHA1, 99)),
                        OcspResponseService.ResponderId.BY_NAME, Optional.empty())));
                assertOverloaded(() -> session.ocsp().orElseThrow().validateSigningBinding(IntermediateIssuanceFixture.SUBJECT,
                        fixture.issuer.credentialId(), IntermediateCreationFixture.CHILD_KEY, ALGORITHM, Optional.empty()));
                assertEquals(1, fixture.provider.dispatches.get());
            } finally {
                fixture.provider.release.countDown();
            }
        }
    }

    @Test
    void sessionAvailabilityAndClosedAccessFollowConfiguredSigning(@TempDir Path root) throws Exception {
        Fixture absent = new Fixture();
        PkiSession unconfigured = absent.open(root.resolve("unconfigured"), false);
        assertTrue(unconfigured.ocsp().isEmpty());
        unconfigured.close();
        assertThrows(IllegalStateException.class, unconfigured::ocsp);
        Fixture configured = new Fixture();
        PkiSession session = configured.open(root.resolve("configured"), true);
        OcspResponseService retained = session.ocsp().orElseThrow();
        session.close();
        assertThrows(IllegalStateException.class, session::ocsp);
        assertThrows(SigningExecutionException.class, () -> retained.validateSigningBinding(IntermediateIssuanceFixture.SUBJECT,
                configured.issuer.credentialId(), IntermediateCreationFixture.CHILD_KEY, ALGORITHM, Optional.empty()));
    }

    private static OcspResponseService.Command copy(OcspResponseService.Command command, PkiId authority,
            KeyRef key, String algorithm, Optional<String> binding) {
        return new OcspResponseService.Command(authority, command.issuerId(), command.issuerCredentialId(),
                command.responderCredentialId(), key, command.responseChain(), algorithm, binding, command.responderId(),
                command.producedAt(), command.thisUpdate(), command.nextUpdate(), command.nonce(), command.requests());
    }

    private static void assertSafe(String message, Action action) {
        PkiException failure = assertThrows(PkiException.class, action::run);
        assertEquals(message, failure.getMessage());
        assertEquals(null, failure.getCause());
        assertEquals(0, failure.getSuppressed().length);
    }
    private static void assertOverloaded(Action action) {
        SigningExecutionException failure = assertThrows(SigningExecutionException.class, action::run);
        assertEquals(SigningExecutionException.Classification.OVERLOADED, failure.classification());
    }
    private static void awaitRetired(PkiStore store, PkiId operation) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            if (store.getSignWorkflow(operation).orElseThrow().state() == SignWorkflowStore.State.RETIRED) return;
            Thread.sleep(5);
        }
        throw new AssertionError("OCSP raw signing did not retire");
    }
    private static OneShotContent oneShot(byte[] bytes) {
        return new OneShotContent() {
            @Override public InputStream openStream() { return new java.io.ByteArrayInputStream(bytes); }
            @Override public java.util.OptionalLong length() { return java.util.OptionalLong.of(bytes.length); }
            @Override public void close() { }
        };
    }
    private static SigningService signingProxy(SigningService delegate, BeforeCall before) {
        return (SigningService) Proxy.newProxyInstance(SigningService.class.getClassLoader(), new Class<?>[] { SigningService.class },
                (proxy, method, arguments) -> {
                    before.run(method.getName(), arguments);
                    try { return method.invoke(delegate, arguments); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
    }
    @FunctionalInterface private interface Action { void run() throws Exception; }
    @FunctionalInterface private interface BeforeCall { void run(String method, Object[] arguments); }

    private static final class Fixture implements DefaultPkiSession.Bootstrap {
        private final IntermediateIssuanceFixture certificates = new IntermediateIssuanceFixture();
        private final Provider provider = new Provider(this);
        private PkiStore store;
        private PkiStore observed;
        private CaRecord ca;
        private Credential issuer;
        private Credential parent;
        private X509Certificate issuerCertificate;
        private X509Certificate parentCertificate;
        private int capacity = 8;
        private boolean corruptView;
        private final AtomicInteger viewsOpened = new AtomicInteger();
        private final AtomicInteger viewsClosed = new AtomicInteger();
        private final AtomicInteger serialQueries = new AtomicInteger();
        private final Map<PkiId, Integer> certificateReads = new HashMap<>();

        private Fixture() throws Exception { }
        private PkiSession open(Path root, boolean configured) {
            PkiSessionConfiguration.SigningTopology topology = new PkiSessionConfiguration.SigningTopology(
                    new PkiSessionConfiguration.SigningCoordinatorLimits(8, Duration.ofSeconds(10), Duration.ofSeconds(5),
                            Duration.ofMillis(5), Duration.ofSeconds(2)), List.of(), new PkiSessionConfiguration.SigningLanePool(1, 8));
            PkiSessionConfiguration.SigningConfiguration signing = new PkiSessionConfiguration.SigningConfiguration(
                    new ProviderConfig("test", Map.of()), BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(),
                    IntermediateCreationFixture.TTL, Optional.empty(), topology, java.util.OptionalLong.empty());
            return DefaultPkiSession.open(new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                    new ProviderConfig("fs", Map.of("root", root.toString())), new ProviderConfig("memory", Map.of()),
                    configured ? Optional.of(signing) : Optional.empty(), List.of(), List.of()), IntermediateCreationFixture.CLOCK, this);
        }
        @Override public void validateStore(ProviderConfig config) { }
        @Override public void validateAudit(ProviderConfig config) { PkiBootstrap.validateAuditConfiguration(config); }
        @Override public void validateSigning(ProviderConfig config) { }
        @Override public PkiStore openStore(ProviderConfig config) {
            return openStore(config, new PkiStoreRuntimeDependencies(IntermediateCreationFixture.CLOCK));
        }
        @Override public PkiStore openStore(ProviderConfig config, PkiStoreRuntimeDependencies dependencies) {
            store = FilesystemPkiStoreTestAccess.open(Path.of(config.properties().get("root")), capacity, IntermediateCreationFixture.CLOCK);
            try {
                certificates.initialize(store);
                ca = store.getCa(IntermediateIssuanceFixture.SUBJECT).orElseThrow();
                issuer = store.getCredential(store.getIssuerGeneration(ca.currentIssuanceIssuerId()).orElseThrow().credentialId()).orElseThrow();
                CaRecord root = store.getCa(IntermediateCreationFixture.CA).orElseThrow();
                parent = store.getCredential(store.getIssuerGeneration(root.currentIssuanceIssuerId()).orElseThrow().credentialId()).orElseThrow();
                issuerCertificate = certificate(issuer);
                parentCertificate = certificate(parent);
            } catch (Exception failure) { throw new AssertionError("OCSP fixture initialization failed", failure); }
            observed = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                    (proxy, method, arguments) -> {
                        if (method.getName().startsWith("list") || method.getName().startsWith("pageCredential")) {
                            throw new AssertionError("OCSP must not enumerate inventory");
                        }
                        if ("getCredential".equals(method.getName())) certificateReads.merge((PkiId) arguments[0], 1, Integer::sum);
                        if ("getCredentialByIssuerAndSerial".equals(method.getName())) serialQueries.incrementAndGet();
                        Object result;
                        try { result = method.invoke(store, arguments); }
                        catch (InvocationTargetException failure) { throw failure.getCause(); }
                        return "openRevocationView".equals(method.getName()) ? view((RevocationView) result) : result;
                    });
            return observed;
        }
        private RevocationView view(RevocationView delegate) {
            viewsOpened.incrementAndGet();
            return new RevocationView() {
                @Override public long revision() { return delegate.revision(); }
                @Override public String commitment() { return delegate.commitment(); }
                @Override public Optional<RevocationRecord> get(PkiId id) throws IOException {
                    if (corruptView) throw new IOException("Private corrupt revocation bytes");
                    return delegate.get(id);
                }
                @Override public void close() throws IOException { delegate.close(); viewsClosed.incrementAndGet(); }
            };
        }
        @Override public AuditSink openAudit(ProviderConfig config) { return PkiBootstrap.openAudit(config); }
        @Override public PkiBootstrap.SigningComposition openSigningComposition(ProviderConfig config,
                SigningProviderRuntimeDependencies dependencies) {
            AlgorithmExecutionCapability capability = new AlgorithmExecutionCapability() {
                @Override public String implementationId() { return "ocsp-test.sign"; }
                @Override public String domainFingerprint() { return "ocsp-test:v1"; }
                @Override public boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction direction) {
                    return direction == Direction.SIGN && identity.equals(suite.signature())
                            && provider.supportedAlgorithms().contains(identity.canonicalForm());
                }
            };
            return new PkiBootstrap.SigningComposition(provider, List.of(capability));
        }
        private DefaultOcspResponseService ocsp(SigningService signing) {
            return new DefaultOcspResponseService(observed, signing, provider, PkiTestRuntime.signingAuthority(provider), () -> { });
        }
        private Optional<String> binding() {
            return certificates.base.bindings.standard(BootstrapAlgorithmIdentities.ED25519_SIGNATURE,
                    zeroecho.pki.api.algorithm.X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE).map(value -> value.bindingId());
        }
        private void resetReads() { viewsOpened.set(0); viewsClosed.set(0); serialQueries.set(0); certificateReads.clear(); }
        private OcspResponseService.CertId id(OcspResponseService.CertIdHash hash, long serial) {
            zeroecho.pkix.ocsp.CertId value = Pkix.computeCertId(issuerCertificate, BigInteger.valueOf(serial),
                    hash == OcspResponseService.CertIdHash.SHA1 ? "1.3.14.3.2.26" : "2.16.840.1.101.3.4.2.1");
            return new OcspResponseService.CertId(hash, value.issuerNameHash(), value.issuerKeyHash(), BigInteger.valueOf(serial));
        }
        private OcspResponseService.Command command(List<OcspResponseService.CertId> requests,
                OcspResponseService.ResponderId responder, Optional<byte[]> nonce) {
            return new OcspResponseService.Command(ca.caId(), ca.currentIssuanceIssuerId(), issuer.credentialId(),
                    issuer.credentialId(), IntermediateCreationFixture.CHILD_KEY, List.of(issuer.credentialId(), parent.credentialId()),
                    ALGORITHM, binding(), responder, IntermediateCreationFixture.NOW, IntermediateCreationFixture.NOW,
                    IntermediateCreationFixture.NOW.plusSeconds(30), nonce, requests);
        }
        private X509Certificate certificate(Credential credential) throws Exception {
            try (zeroecho.core.io.RepeatableContent content = store.stagedContent().openContent(credential.content());
                    InputStream input = content.openStream()) {
                return Pkix.parseCertificate(input.readAllBytes());
            }
        }
        private Credential issue(long serial) throws Exception {
            Validity validity = new Validity(IntermediateCreationFixture.NOW.minusSeconds(60),
                    IntermediateCreationFixture.NOW.plus(Duration.ofDays(1)));
            byte[] tbs = Pkix.certificateBuilder().serialNumber(BigInteger.valueOf(serial))
                    .issuer(issuerCertificate.getSubjectX500Principal()).subject(new X500Principal("CN=OCSP target"))
                    .publicKeyInfo(certificates.base.rotatedKey.getPublic().getEncoded()).validity(validity.notBefore(), validity.notAfter())
                    .basicConstraints(BasicConstraints.ca(0), true).keyUsage(Set.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN), true)
                    .buildTbs(Pkix.subjectPublicKeyAlgorithm(certificates.base.childKey.getPublic().getEncoded()));
            byte[] der = Pkix.assembleCertificateOrCrl(tbs, certificates.base.signature(tbs, IntermediateCreationFixture.CHILD_KEY).bytes(), false);
            Credential result = new Credential(new PkiId("x509:" + IntermediateCreationFixture.hash(der)), issuer.formatId(),
                    new zeroecho.pki.api.IssuerRef(ca.caId(), ca.currentIssuanceIssuerId(), ca.issuanceChainPathId()),
                    new SubjectRef("CN=OCSP target"), validity, Long.toString(serial),
                    new PkiId("spki:" + IntermediateCreationFixture.hash(certificates.base.rotatedKey.getPublic().getEncoded())),
                    issuer.profileBinding(), issuer.status(), PkiTestRuntime.stageCredential(store, der), new SimpleAttributeSet());
            store.putCredential(result);
            return result;
        }
    }

    private static final class Provider implements SigningProvider {
        private final Fixture fixture;
        private final AtomicInteger dispatches = new AtomicInteger();
        private final AtomicInteger initialObservations = new AtomicInteger();
        private volatile PkiId lastId;
        private volatile byte[] lastContent;
        private boolean wrongKey;
        private boolean pending;
        private boolean failObservation;
        private boolean cleanupSuccess;
        private boolean blockDispatch;
        private final CountDownLatch entered = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);
        private Provider(Fixture fixture) { this.fixture = fixture; }
        @Override public String id() { return "ocsp-test"; }
        @Override public ConfigurationCommitment configurationCommitment() { return new ConfigurationCommitment(new byte[32]); }
        @Override public Set<String> supportedAlgorithms() {
            return Set.of(ALGORITHM, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm());
        }
        @Override public SigningInputCapabilities inputCapabilities() { return new SigningInputCapabilities(4_000_000, Map.of()); }
        @Override public OperationObservation dispatch(SignRequest request, CallControl control) {
            assertTrue(Thread.currentThread().getName().startsWith("zeroecho-signing-pool-"));
            assertEquals(fixture.viewsOpened.get(), fixture.viewsClosed.get());
            dispatches.incrementAndGet();
            lastId = request.operationId();
            try (InputStream input = request.content().openStream()) {
                lastContent = input.readAllBytes();
                if (blockDispatch) { entered.countDown(); assertTrue(release.await(5, TimeUnit.SECONDS)); }
                if (pending) return observation(request.operationId(), ObservationState.PENDING, Optional.empty());
                Signature signer = Signature.getInstance("Ed25519");
                KeyPair pair = wrongKey ? fixture.certificates.base.parentKey : fixture.certificates.base.childKey;
                signer.initSign(pair.getPrivate());
                signer.update(lastContent);
                return observation(request.operationId(), ObservationState.SUCCEEDED,
                        Optional.of(new EncodedObject(Encoding.BINARY, signer.sign())));
            } catch (Exception failure) { throw new AssertionError("Controlled OCSP signing failed", failure); }
        }
        @Override public OperationObservation reconcile(PkiId operationId, CallControl control) {
            SignWorkflowStore.Workflow workflow = fixture.store.getSignWorkflow(operationId).orElseThrow();
            if (workflow.state() == SignWorkflowStore.State.DISPATCHED) {
                initialObservations.incrementAndGet();
                if (failObservation) throw new IllegalStateException("Private provider observation failure");
            } else if (cleanupSuccess) {
                return observation(operationId, ObservationState.SUCCEEDED,
                        Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 7 })));
            }
            return observation(operationId, ObservationState.PENDING, Optional.empty());
        }
        @Override public OperationObservation cancel(PkiId operationId, long fence, CancellationReason reason, CallControl control) {
            return observation(operationId, ObservationState.CANCELLED, Optional.empty());
        }
        private static OperationObservation observation(PkiId id, ObservationState state, Optional<EncodedObject> signature) {
            return new OperationObservation(id, state, IntermediateCreationFixture.NOW, switch (state) {
                case SUCCEEDED -> DetailCode.SIGNED;
                case CANCELLED -> DetailCode.CANCELLED;
                default -> DetailCode.PENDING;
            }, signature);
        }
        @Override public void close() { }
    }
}
