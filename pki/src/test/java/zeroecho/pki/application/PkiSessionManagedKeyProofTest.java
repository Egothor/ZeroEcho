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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.InputStream;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import zeroecho.pki.api.ca.CaRolloverCommand;
import zeroecho.pki.api.ca.CaKeyRotationCommand;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.signing.ManagedKeyProofRequest;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.pki.spi.crypto.SigningInputCapabilities;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProviderRuntimeDependencies;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.PkiStoreRuntimeDependencies;
import zeroecho.pki.testkit.IntermediateCreationFixture;
import zeroecho.pki.testkit.IntermediateIssuanceFixture;
import zeroecho.pki.testkit.PkiTestRuntime;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pkix.Pkix;

final class PkiSessionManagedKeyProofTest {
    private static final Instant NOW = Instant.parse("2026-09-21T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final AlgorithmIdentity ALGORITHM = BootstrapAlgorithmIdentities.ED25519_SIGNATURE;
    private static final AccessContext ACCESS = new AccessContext(new Principal("TEST", "session-proof"),
            new Purpose("PROVE"), Optional.empty(), Optional.empty());
    private static final ManagedKeyProofRequest REQUEST = new ManagedKeyProofRequest.OcspResponder(
            new PkiId("authority"), new PkiId("responder"), new KeyRef("managed-key"));

    @Test void composedExistingIntermediateIssuancePreservesPrincipalAndSelection(@TempDir Path root) throws Exception {
        IntermediateIssuanceFixture issuance = new IntermediateIssuanceFixture();
        Fixture fixture = new Fixture(issuance);
        SemanticSigningService semantic;
        PkiId operation;
        try (PkiSession session = fixture.open(root)) {
            semantic = session.semanticSigning().orElseThrow();
            CaRecord before = fixture.store.getCa(IntermediateIssuanceFixture.SUBJECT).orElseThrow();
            PreparedSemanticSigningRequest discarded = semantic.prepareIntermediateIssuance(IntermediateCreationFixture.ACCESS,
                    issuance.command(), CancellationSignal.NONE);
            semantic.discard(discarded);
            assertTrue(fixture.store.getSignWorkflow(discarded.receipt().operationId()).isEmpty());
            PreparedSemanticSigningRequest prepared = semantic.prepareIntermediateIssuance(IntermediateCreationFixture.ACCESS,
                    issuance.command(), CancellationSignal.NONE);
            assertEquals(0, fixture.dispatches.get());
            assertEquals(before, fixture.store.getCa(before.caId()).orElseThrow());
            operation = semantic.accept(prepared).receipt().operationId();
            SemanticSigningOperation result = await(semantic, operation);
            assertEquals(SemanticSigningState.COMPLETED, result.state());
            assertEquals("ISSUE_INTERMEDIATE", result.scope().operation());
            assertEquals(Optional.of(IntermediateCreationFixture.CA), result.scope().authorityId());
            assertEquals(Optional.of(before.caId()), result.scope().subjectAuthorityId());
            assertEquals(Optional.of(IntermediateIssuanceFixture.PROFILE), result.scope().profileId());
            assertEquals(IntermediateCreationFixture.ACCESS, result.scope().accessContext());
            CaRecord after = fixture.store.getCa(before.caId()).orElseThrow();
            assertEquals(2, after.issuerIds().size());
            assertEquals(before, new CaRecord(after.caId(), after.kind(), after.state(), after.issuerKeyRef(), after.subjectRef(),
                    List.of(after.issuerIds().getFirst()), after.currentIssuanceIssuerId(), after.issuanceChainPathId()));
            Credential certificate = fixture.store.getCredential(fixture.store.getIssuerGeneration(after.issuerIds().getLast())
                    .orElseThrow().credentialId()).orElseThrow();
            java.security.cert.X509Certificate parsed = Pkix.parseCertificate(PkiTestRuntime.readContent(fixture.store, certificate.content()));
            parsed.verify(issuance.base.parentKey.getPublic());
            assertArrayEquals(issuance.base.childKey.getPublic().getEncoded(), parsed.getPublicKey().getEncoded());
            assertEquals(IntermediateIssuanceFixture.PRINCIPAL, parsed.getSubjectX500Principal());
            assertEquals(parsed.getSubjectX500Principal(), new X500Principal(certificate.subjectRef().value()));
            assertEquals(before.subjectRef(), certificate.subjectRef());
            assertEquals(IntermediateIssuanceFixture.PROFILE, ((CaProfileBinding) certificate.profileBinding()).reference().profileId());
            assertEquals(2, fixture.dispatches.get());
        }
        assertThrows(SigningExecutionException.class, () -> semantic.prepareIntermediateIssuance(IntermediateCreationFixture.ACCESS,
                issuance.command(), CancellationSignal.NONE));
        try (PkiSession session = fixture.open(root)) {
            assertEquals(SemanticSigningState.COMPLETED, session.semanticSigning().orElseThrow().find(operation).orElseThrow().state());
            assertEquals(2, fixture.dispatches.get());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void composedIntermediateLifecycleSelectsNewGenerationAndKey(boolean rotation, @TempDir Path root) throws Exception {
        IntermediateIssuanceFixture issuance = new IntermediateIssuanceFixture();
        Fixture fixture = new Fixture(issuance);
        SemanticSigningService semantic;
        PkiId operation;
        KeyRef target = rotation ? IntermediateCreationFixture.ROTATED_KEY : IntermediateCreationFixture.CHILD_KEY;
        CaRolloverCommand rollover;
        CaKeyRotationCommand rotate;
        try (PkiSession session = fixture.open(root)) {
            semantic = session.semanticSigning().orElseThrow();
            CaRecord before = fixture.store.getCa(IntermediateIssuanceFixture.SUBJECT).orElseThrow();
            CertificateProfileRef active = issuance.activateLifecycleVersionTwo(fixture.store);
            rollover = new CaRolloverCommand.Intermediate(before.caId(), IntermediateCreationFixture.CA, target, Optional.empty(), new SimpleAttributeSet());
            rotate = new CaKeyRotationCommand.Intermediate(before.caId(), target, IntermediateCreationFixture.CA, new SimpleAttributeSet());
            assertThrows(PkiException.class, () -> {
                if (rotation) semantic.prepareCaKeyRotation(IntermediateCreationFixture.ACCESS, rotate, () -> true);
                else semantic.prepareCaRollover(IntermediateCreationFixture.ACCESS, rollover, () -> true);
            });
            PreparedSemanticSigningRequest discarded = rotation
                    ? semantic.prepareCaKeyRotation(IntermediateCreationFixture.ACCESS, rotate, CancellationSignal.NONE)
                    : semantic.prepareCaRollover(IntermediateCreationFixture.ACCESS, rollover, CancellationSignal.NONE);
            semantic.discard(discarded);
            assertTrue(fixture.store.getSignWorkflow(discarded.receipt().operationId()).isEmpty());
            int lookups = issuance.base.provider.lookups;
            PreparedSemanticSigningRequest prepared = rotation
                    ? semantic.prepareCaKeyRotation(IntermediateCreationFixture.ACCESS, rotate, CancellationSignal.NONE)
                    : semantic.prepareCaRollover(IntermediateCreationFixture.ACCESS, rollover, CancellationSignal.NONE);
            assertEquals(lookups + 1, issuance.base.provider.lookups, "Exactly one current SPKI export freezes the internal proof");
            assertEquals(0, fixture.dispatches.get());
            assertTrue(fixture.store.getSignWorkflow(prepared.receipt().operationId()).isEmpty());
            assertEquals(before, fixture.store.getCa(before.caId()).orElseThrow());
            operation = semantic.accept(prepared).receipt().operationId();
            SemanticSigningOperation result = await(semantic, operation);
            assertEquals(SemanticSigningState.COMPLETED, result.state());
            assertEquals("ROLLOVER_INTERMEDIATE", result.scope().operation());
            assertEquals(Optional.of(IntermediateCreationFixture.CA), result.scope().authorityId());
            assertEquals(Optional.of(before.caId()), result.scope().subjectAuthorityId());
            assertEquals(Optional.of(active.profileId()), result.scope().profileId());
            assertEquals(IntermediateCreationFixture.PARENT_KEY, result.scope().keyRef());
            assertEquals(IntermediateCreationFixture.ACCESS, result.scope().accessContext());
            assertEquals(IntermediateCreationFixture.CA, fixture.store.getSignWorkflow(operation).orElseThrow().envelope().fairnessAuthorityId());
            CaRecord after = fixture.store.getCa(before.caId()).orElseThrow();
            assertEquals(2, after.issuerIds().size());
            assertEquals(before.issuerIds().getFirst(), after.issuerIds().getFirst());
            assertEquals(after.issuerIds().getLast(), after.currentIssuanceIssuerId());
            assertTrue(!before.issuanceChainPathId().equals(after.issuanceChainPathId()));
            assertEquals(target, after.issuerKeyRef());
            assertEquals(before.subjectRef(), after.subjectRef());
            Credential certificate = fixture.store.getCredential(fixture.store.getIssuerGeneration(after.currentIssuanceIssuerId())
                    .orElseThrow().credentialId()).orElseThrow();
            assertEquals(active, ((CaProfileBinding) certificate.profileBinding()).reference());
            java.security.cert.X509Certificate parsed = Pkix.parseCertificate(PkiTestRuntime.readContent(fixture.store, certificate.content()));
            parsed.verify(issuance.base.parentKey.getPublic());
            assertArrayEquals((rotation ? issuance.base.rotatedKey : issuance.base.childKey).getPublic().getEncoded(), parsed.getPublicKey().getEncoded());
            assertEquals(IntermediateIssuanceFixture.PRINCIPAL, parsed.getSubjectX500Principal());
            assertEquals(parsed.getSubjectX500Principal(), new X500Principal(certificate.subjectRef().value()));
            assertEquals(2, fixture.dispatches.get());
        }
        assertThrows(SigningExecutionException.class, () -> {
            if (rotation) semantic.prepareCaKeyRotation(IntermediateCreationFixture.ACCESS, rotate, CancellationSignal.NONE);
            else semantic.prepareCaRollover(IntermediateCreationFixture.ACCESS, rollover, CancellationSignal.NONE);
        });
        try (PkiSession session = fixture.open(root)) {
            assertEquals(SemanticSigningState.COMPLETED, session.semanticSigning().orElseThrow().find(operation).orElseThrow().state());
            assertEquals(2, fixture.dispatches.get());
        }
    }

    @Test void composedIntermediatePreparationPublishesAndReopensWithoutRedispatch(@TempDir Path root) throws Exception {
        IntermediateCreationFixture intermediate = new IntermediateCreationFixture();
        Fixture fixture = new Fixture(true, intermediate);
        SemanticSigningService semantic;
        PkiId operation;
        try (PkiSession session = fixture.open(root)) {
            semantic = session.semanticSigning().orElseThrow();
            PreparedSemanticSigningRequest prepared = semantic.prepareIntermediateCreation(IntermediateCreationFixture.ACCESS,
                    intermediate.command("CN=Session Child"), CancellationSignal.NONE);
            assertEquals(0, fixture.dispatches.get());
            operation = semantic.accept(prepared).receipt().operationId();
            SemanticSigningOperation result = await(semantic, operation);
            assertEquals(SemanticSigningState.COMPLETED, result.state());
            assertEquals(Optional.of(IntermediateCreationFixture.CA), result.scope().authorityId());
            assertTrue(result.scope().subjectAuthorityId().isPresent());
            assertEquals(2, fixture.dispatches.get());
        }
        assertThrows(SigningExecutionException.class, () -> semantic.prepareIntermediateCreation(IntermediateCreationFixture.ACCESS,
                intermediate.command("CN=Session Child"), CancellationSignal.NONE));
        try (PkiSession session = fixture.open(root)) {
            assertEquals(SemanticSigningState.COMPLETED, session.semanticSigning().orElseThrow().find(operation).orElseThrow().state());
            assertEquals(2, fixture.dispatches.get());
        }
    }

    @Test void composedSessionPreparesWithoutDispatchCompletesAndRejectsAfterClose(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(true);
        SemanticSigningService semantic;
        PkiId operation;
        try (PkiSession session = fixture.open(root)) {
            semantic = session.semanticSigning().orElseThrow();
            PreparedSemanticSigningRequest prepared = semantic.prepareManagedKeyProof(ACCESS, REQUEST, CancellationSignal.NONE);
            assertEquals(0, fixture.dispatches.get());
            operation = semantic.accept(prepared).receipt().operationId();
            SemanticSigningOperation result = await(semantic, operation);
            assertEquals(SemanticSigningState.COMPLETED, result.state());
            assertEquals(70, result.result().orElseThrow().byteLength());
            assertEquals(Optional.of(new PkiId("responder")), result.scope().keyProof().orElseThrow().responderCredentialId());
            assertEquals(1, fixture.dispatches.get());
        }
        assertThrows(SigningExecutionException.class,
                () -> semantic.prepareManagedKeyProof(ACCESS, REQUEST, CancellationSignal.NONE));
        try (PkiSession reopened = fixture.open(root)) {
            assertEquals(SemanticSigningState.COMPLETED, reopened.semanticSigning().orElseThrow().find(operation).orElseThrow().state());
            assertEquals(1, fixture.dispatches.get());
        }
    }

    @Test void providerWithoutPublicKeySourceStillOpensButProofInvocationFails(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(false);
        try (PkiSession session = fixture.open(root)) {
            assertTrue(session.signing().isPresent());
            SemanticSigningService semantic = session.semanticSigning().orElseThrow();
            assertThrows(IllegalArgumentException.class,
                    () -> semantic.prepareManagedKeyProof(ACCESS, REQUEST, CancellationSignal.NONE));
            assertEquals(0, fixture.dispatches.get());
        }
    }

    private static SemanticSigningOperation await(SemanticSigningService service, PkiId operation) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (System.nanoTime() < deadline) {
            SemanticSigningOperation current = service.find(operation).orElseThrow();
            if (current.state() != SemanticSigningState.SIGNING && current.state() != SemanticSigningState.PUBLISHING) { return current; }
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5));
        }
        throw new AssertionError("Managed key proof did not complete");
    }

    private static final class Fixture implements DefaultPkiSession.Bootstrap {
        private final KeyPair key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        private final AtomicInteger dispatches = new AtomicInteger();
        private final SigningProvider provider;
        private final IntermediateCreationFixture intermediate;
        private IntermediateIssuanceFixture issuance;
        private PkiStore store;

        Fixture(IntermediateIssuanceFixture issuance) throws Exception {
            this(true, issuance.base);
            this.issuance = issuance;
        }

        Fixture(boolean source) throws Exception {
            this(source, null);
        }

        Fixture(boolean source, IntermediateCreationFixture intermediate) throws Exception {
            this.intermediate = intermediate;
            provider = (SigningProvider) Proxy.newProxyInstance(SigningProvider.class.getClassLoader(), source
                    ? new Class<?>[] {SigningProvider.class, PublicKeyInfoSource.class} : new Class<?>[] {SigningProvider.class},
                    (proxy, method, args) -> switch (method.getName()) {
                        case "id" -> intermediate == null ? "session-proof" : intermediate.provider.id();
                        case "configurationCommitment" -> new SigningProvider.ConfigurationCommitment(new byte[32]);
                        case "supportedAlgorithms" -> Set.of(ALGORITHM.canonicalForm());
                        case "inputCapabilities" -> new SigningInputCapabilities(4_000_000, Map.of());
                        case "validateSigningDomain", "close" -> null;
                        case "resolvePublicKeyInfo" -> intermediate == null ? new EncodedObject(Encoding.DER, key.getPublic().getEncoded())
                                : intermediate.provider.resolvePublicKeyInfo((KeyRef) args[0]);
                        case "dispatch" -> {
                            dispatches.incrementAndGet();
                            SigningProvider.SignRequest request = (SigningProvider.SignRequest) args[0];
                            try (InputStream input = request.content().openStream()) {
                                if (intermediate != null) {
                                    yield new SigningProvider.OperationObservation(request.operationId(), SigningProvider.ObservationState.SUCCEEDED,
                                            NOW, SigningProvider.DetailCode.SIGNED, Optional.of(intermediate.signature(input.readAllBytes(), request.keyRef())));
                                }
                                Signature signature = Signature.getInstance("Ed25519");
                                signature.initSign(key.getPrivate());
                                signature.update(input.readAllBytes());
                                yield new SigningProvider.OperationObservation(request.operationId(),
                                        SigningProvider.ObservationState.SUCCEEDED, NOW, SigningProvider.DetailCode.SIGNED,
                                        Optional.of(new EncodedObject(Encoding.BINARY, signature.sign())));
                            }
                        }
                        default -> throw new AssertionError("Unexpected provider call: " + method.getName());
                    });
        }

        PkiSession open(Path root) {
            PkiSessionConfiguration.SigningTopology topology = new PkiSessionConfiguration.SigningTopology(
                    new PkiSessionConfiguration.SigningCoordinatorLimits(2, Duration.ofSeconds(10), Duration.ofSeconds(5),
                            Duration.ofDays(1), Duration.ofSeconds(2)), List.of(),
                    new PkiSessionConfiguration.SigningLanePool(1, 4));
            PkiSessionConfiguration.SigningConfiguration signing = new PkiSessionConfiguration.SigningConfiguration(
                    new ProviderConfig("test", Map.of()), ALGORITHM.canonicalForm(), Duration.ofMinutes(1), Optional.empty(), topology,
                    java.util.OptionalLong.empty());
            return DefaultPkiSession.open(new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                    new ProviderConfig("fs", Map.of("root", root.toString())), new ProviderConfig("memory", Map.of()),
                    Optional.of(signing), List.of(), List.of()), CLOCK, this);
        }
        @Override public void validateStore(ProviderConfig config) { PkiBootstrap.validateStoreConfiguration(config); }
        @Override public void validateAudit(ProviderConfig config) { PkiBootstrap.validateAuditConfiguration(config); }
        @Override public void validateSigning(ProviderConfig config) { }
        @Override public PkiStore openStore(ProviderConfig config) { return PkiBootstrap.openStore(config, new PkiStoreRuntimeDependencies(CLOCK)); }
        @Override public PkiStore openStore(ProviderConfig config, PkiStoreRuntimeDependencies dependencies) {
            store = PkiBootstrap.openStore(config, dependencies);
            if (intermediate != null && store.getCa(IntermediateCreationFixture.CA).isEmpty()) {
                try {
                    if (issuance != null) issuance.initialize(store);
                    else intermediate.initialize(store, 1);
                }
                catch (Exception failure) {
                    try { store.close(); }
                    catch (Exception cleanup) { failure.addSuppressed(cleanup); }
                    throw new AssertionError("Intermediate fixture initialization failed", failure);
                }
            }
            return store;
        }
        @Override public AuditSink openAudit(ProviderConfig config) { return PkiBootstrap.openAudit(config); }
        @Override public PkiBootstrap.SigningComposition openSigningComposition(ProviderConfig config,
                SigningProviderRuntimeDependencies dependencies) {
            AlgorithmExecutionCapability capability = new AlgorithmExecutionCapability() {
                @Override public String implementationId() { return "session-proof.exact"; }
                @Override public String domainFingerprint() { return "session-proof:v1"; }
                @Override public boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction direction) {
                    return direction == Direction.SIGN && ALGORITHM.equals(identity) && ALGORITHM.equals(suite.signature());
                }
            };
            return new PkiBootstrap.SigningComposition(provider, List.of(capability));
        }
    }
}
