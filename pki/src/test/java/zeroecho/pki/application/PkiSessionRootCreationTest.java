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

package zeroecho.pki.application;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import zeroecho.pki.api.ca.CaRolloverCommand;
import zeroecho.pki.api.ca.CaKeyRotationCommand;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningKind;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.api.signing.SigningOperationState;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.spi.crypto.SigningProviderRuntimeDependencies;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.PkiStoreRuntimeDependencies;
import zeroecho.pki.testkit.PkiTestRuntime;
import zeroecho.pki.testkit.RootCreationFixture;
import zeroecho.pkix.Pkix;

final class PkiSessionRootCreationTest {
    @Test void realSessionReactorPublishesFrozenRootAndReopensWithoutRedispatch(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture();
        SemanticSigningService semantic;
        PkiId operation;
        try (PkiSession session = fixture.open(root)) {
            semantic = session.semanticSigning().orElseThrow();
            PreparedSemanticSigningRequest discarded = semantic.prepareRootCreation(RootCreationFixture.ACCESS,
                    fixture.root.command(), CancellationSignal.NONE);
            zeroecho.pki.api.ca.CaCreateCommand input = fixture.root.command();
            PkiSigningCommands commands = session.signingCommands().orElseThrow();
            PreparedSemanticSigningRequest prepared = commands.prepare(new PkiSigningOperation.CreateAuthority(
                    input.formatId(), input.subjectRef(), input.profileId(), input.keyRef()),
                    RootCreationFixture.ACCESS, Optional.empty(), CancellationSignal.NONE);
            assertNotEquals(discarded.receipt().operationId(), prepared.receipt().operationId());
            assertEquals(0, fixture.root.provider.dispatches.get());
            assertTrue(fixture.store.listCas().isEmpty());
            semantic.discard(discarded);
            fixture.root.exported = new EncodedObject(Encoding.DER, fixture.root.otherKey.getPublic().getEncoded());
            operation = semantic.accept(prepared).receipt().operationId();
            SemanticSigningOperation result = await(semantic, operation);
            assertEquals(SemanticSigningState.COMPLETED, result.state());
            assertEquals(SemanticSigningKind.CA, result.scope().kind());
            assertEquals("CREATE_ROOT", result.scope().operation());
            assertEquals(RootCreationFixture.ACCESS, result.scope().accessContext());
            assertEquals(RootCreationFixture.KEY, result.scope().keyRef());
            assertEquals(Optional.of("root-test"), result.scope().profileId());
            assertTrue(result.scope().authorityId().isEmpty());
            assertTrue(result.scope().subjectAuthorityId().isEmpty());
            PkiId authority = DomainCommandEncoding.rootAuthorityId(operation);
            assertEquals(authority, fixture.store.getSignWorkflow(operation).orElseThrow().envelope().fairnessAuthorityId());
            CaRecord ca = fixture.store.getCa(authority).orElseThrow();
            Credential credential = fixture.store.getCredential(fixture.store.getIssuerGeneration(ca.currentIssuanceIssuerId())
                    .orElseThrow().credentialId()).orElseThrow();
            assertEquals(Optional.of(credential.credentialId()), result.completedCredentialId());
            PkiOperationResult projected = commands.completedResult(result);
            assertEquals("signing.operation", projected.operationName());
            assertEquals(new PkiOperationValue.Text(credential.credentialId().value()),
                    projected.fields().get("credentialId"));
            X509Certificate certificate = Pkix.parseCertificate(PkiTestRuntime.readContent(fixture.store, credential.content()));
            certificate.verify(fixture.root.key.getPublic());
            assertArrayEquals(fixture.root.key.getPublic().getEncoded(), certificate.getPublicKey().getEncoded());
            assertEquals(credential.subjectRef(), ca.subjectRef());
            assertEquals(certificate.getSubjectX500Principal(), new X500Principal(ca.subjectRef().value()));
            assertEquals(certificate.getSubjectX500Principal(), new X500Principal(credential.subjectRef().value()));
            assertTrue(ca.subjectRef().value().contains("O=Frozen Organization"));
            assertEquals(fixture.store.requireActiveProfile("root-test").reference(),
                    ((CaProfileBinding) credential.profileBinding()).reference());
            assertEquals(1, fixture.root.provider.dispatches.get());
            assertEquals(2, fixture.root.provider.lookups.get());
        }
        assertThrows(SigningExecutionException.class, () -> semantic.prepareRootCreation(RootCreationFixture.ACCESS,
                fixture.root.command(), CancellationSignal.NONE));
        try (PkiSession session = fixture.open(root)) {
            assertEquals(SemanticSigningState.COMPLETED, session.semanticSigning().orElseThrow().find(operation).orElseThrow().state());
            assertEquals(1, fixture.root.provider.dispatches.get());
            assertEquals(2, fixture.root.provider.lookups.get());
        }
    }

    @Test void signatureFromAnotherPrivateKeyCannotPublishAnyAuthority(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture();
        fixture.root.wrongSigningKey = true;
        try (PkiSession session = fixture.open(root)) {
            SemanticSigningService semantic = session.semanticSigning().orElseThrow();
            PreparedSemanticSigningRequest prepared = semantic.prepareRootCreation(RootCreationFixture.ACCESS,
                    fixture.root.command(), CancellationSignal.NONE);
            PkiId operation = semantic.accept(prepared).receipt().operationId();
            SemanticSigningOperation result = await(semantic, operation);
            assertEquals(SemanticSigningState.FAILED, result.state());
            assertEquals(SigningOperationState.SUCCEEDED, result.signingState());
            assertTrue(fixture.store.getCa(DomainCommandEncoding.rootAuthorityId(operation)).isEmpty());
            assertTrue(fixture.store.listCas().isEmpty());
            assertEquals(1, fixture.root.provider.lookups.get());
            assertEquals(1, fixture.root.provider.dispatches.get());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void rootLifecycleDispatchesThroughSessionAndRetainsHistory(boolean rotation, @TempDir Path root) throws Exception {
        Fixture fixture = new Fixture();
        SemanticSigningService semantic;
        PkiId operation;
        PkiId authority;
        try (PkiSession session = fixture.open(root)) {
            semantic = session.semanticSigning().orElseThrow();
            PkiId creation = semantic.accept(semantic.prepareRootCreation(RootCreationFixture.ACCESS,
                    fixture.root.command(), CancellationSignal.NONE)).receipt().operationId();
            assertEquals(SemanticSigningState.COMPLETED, await(semantic, creation).state());
            authority = DomainCommandEncoding.rootAuthorityId(creation);
            CaRecord before = fixture.store.getCa(authority).orElseThrow();
            CertificateProfileDefinition old = fixture.store.requireActiveProfile("root-test").definition();
            CertificateProfileRef active = RootCreationFixture.install(fixture.store, new CertificateProfileDefinition(
                    old.certificateType(), old.profileId(), 2, old.formatId(), old.displayName(), Duration.ofDays(30),
                    old.subjectPolicy(), old.certificatePolicy(), old.algorithmBindingPolicy()));
            KeyRef target = rotation ? RootCreationFixture.REPLACEMENT_KEY : RootCreationFixture.KEY;
            CaRolloverCommand rollover = new CaRolloverCommand.Root(authority, Optional.empty(), new SimpleAttributeSet());
            CaKeyRotationCommand rotate = new CaKeyRotationCommand.Root(authority, target, new SimpleAttributeSet());
            assertThrows(PkiException.class, () -> {
                if (rotation) semantic.prepareCaKeyRotation(RootCreationFixture.ACCESS, rotate, () -> true);
                else semantic.prepareCaRollover(RootCreationFixture.ACCESS, rollover, () -> true);
            });
            PreparedSemanticSigningRequest discarded = rotation
                    ? semantic.prepareCaKeyRotation(RootCreationFixture.ACCESS, rotate, CancellationSignal.NONE)
                    : semantic.prepareCaRollover(RootCreationFixture.ACCESS, rollover, CancellationSignal.NONE);
            semantic.discard(discarded);
            assertTrue(fixture.store.getSignWorkflow(discarded.receipt().operationId()).isEmpty());
            PreparedSemanticSigningRequest prepared = rotation
                    ? semantic.prepareCaKeyRotation(RootCreationFixture.ACCESS, rotate, CancellationSignal.NONE)
                    : semantic.prepareCaRollover(RootCreationFixture.ACCESS, rollover, CancellationSignal.NONE);
            assertEquals(1, fixture.root.provider.dispatches.get());
            assertTrue(fixture.store.getSignWorkflow(prepared.receipt().operationId()).isEmpty());
            assertEquals(before, fixture.store.getCa(authority).orElseThrow());
            operation = semantic.accept(prepared).receipt().operationId();
            SemanticSigningOperation result = await(semantic, operation);
            assertEquals(SemanticSigningState.COMPLETED, result.state());
            assertEquals("ROLLOVER_ROOT", result.scope().operation());
            assertEquals(Optional.of(authority), result.scope().authorityId());
            assertEquals(Optional.of("root-test"), result.scope().profileId());
            assertEquals(target, result.scope().keyRef());
            assertEquals(RootCreationFixture.ACCESS, result.scope().accessContext());
            assertEquals(authority, fixture.store.getSignWorkflow(operation).orElseThrow().envelope().fairnessAuthorityId());
            CaRecord after = fixture.store.getCa(authority).orElseThrow();
            assertEquals(2, after.issuerIds().size());
            assertEquals(before.issuerIds().getFirst(), after.issuerIds().getFirst());
            assertEquals(after.issuerIds().getLast(), after.currentIssuanceIssuerId());
            assertNotEquals(before.issuanceChainPathId(), after.issuanceChainPathId());
            assertEquals(target, after.issuerKeyRef());
            assertEquals(before.subjectRef(), after.subjectRef());
            Credential selected = fixture.store.getCredential(fixture.store.getIssuerGeneration(after.currentIssuanceIssuerId())
                    .orElseThrow().credentialId()).orElseThrow();
            assertEquals(active, ((CaProfileBinding) selected.profileBinding()).reference());
            X509Certificate certificate = Pkix.parseCertificate(PkiTestRuntime.readContent(fixture.store, selected.content()));
            certificate.verify((rotation ? fixture.root.otherKey : fixture.root.key).getPublic());
            assertArrayEquals((rotation ? fixture.root.otherKey : fixture.root.key).getPublic().getEncoded(), certificate.getPublicKey().getEncoded());
            assertEquals(certificate.getSubjectX500Principal(), new X500Principal(after.subjectRef().value()));
            assertEquals(certificate.getSubjectX500Principal(), new X500Principal(selected.subjectRef().value()));
            assertEquals(2, fixture.root.provider.dispatches.get());
        }
        assertThrows(SigningExecutionException.class, () -> {
            if (rotation) semantic.prepareCaKeyRotation(RootCreationFixture.ACCESS,
                    new CaKeyRotationCommand.Root(authority, RootCreationFixture.REPLACEMENT_KEY, new SimpleAttributeSet()), CancellationSignal.NONE);
            else semantic.prepareCaRollover(RootCreationFixture.ACCESS,
                    new CaRolloverCommand.Root(authority, Optional.empty(), new SimpleAttributeSet()), CancellationSignal.NONE);
        });
        try (PkiSession session = fixture.open(root)) {
            assertEquals(SemanticSigningState.COMPLETED, session.semanticSigning().orElseThrow().find(operation).orElseThrow().state());
            assertEquals(2, fixture.root.provider.dispatches.get());
        }
    }

    private static SemanticSigningOperation await(SemanticSigningService service, PkiId operation) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (System.nanoTime() < deadline) {
            SemanticSigningOperation current = service.find(operation).orElseThrow();
            if (current.state() != SemanticSigningState.SIGNING && current.state() != SemanticSigningState.PUBLISHING) return current;
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5));
        }
        throw new AssertionError("Root creation did not complete");
    }

    private static final class Fixture implements DefaultPkiSession.Bootstrap {
        private final RootCreationFixture root = new RootCreationFixture();
        private PkiStore store;
        private Fixture() throws Exception { }

        private PkiSession open(Path path) {
            PkiSessionConfiguration.SigningTopology topology = new PkiSessionConfiguration.SigningTopology(
                    new PkiSessionConfiguration.SigningCoordinatorLimits(2, Duration.ofSeconds(10), Duration.ofSeconds(5),
                            Duration.ofDays(1), Duration.ofSeconds(2)), List.of(), new PkiSessionConfiguration.SigningLanePool(1, 4));
            PkiSessionConfiguration.SigningConfiguration signing = new PkiSessionConfiguration.SigningConfiguration(
                    new ProviderConfig("test", Map.of()), RootCreationFixture.ALGORITHM, RootCreationFixture.TTL,
                    Optional.empty(), topology, java.util.OptionalLong.empty());
            return DefaultPkiSession.open(new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                    new ProviderConfig("fs", Map.of("root", path.toString())), new ProviderConfig("memory", Map.of()),
                    Optional.of(signing), List.of(), List.of()), RootCreationFixture.CLOCK, this);
        }
        @Override public void validateStore(ProviderConfig configuration) { PkiBootstrap.validateStoreConfiguration(configuration); }
        @Override public void validateAudit(ProviderConfig configuration) { PkiBootstrap.validateAuditConfiguration(configuration); }
        @Override public void validateSigning(ProviderConfig configuration) { }
        @Override public PkiStore openStore(ProviderConfig configuration) {
            return openStore(configuration, new PkiStoreRuntimeDependencies(RootCreationFixture.CLOCK));
        }
        @Override public PkiStore openStore(ProviderConfig configuration, PkiStoreRuntimeDependencies dependencies) {
            store = PkiBootstrap.openStore(configuration, dependencies);
            if (store.getActiveProfileRef("root-test").isEmpty()) {
                try { root.initialize(store); }
                catch (Exception failure) {
                    try { store.close(); }
                    catch (Exception cleanup) { failure.addSuppressed(cleanup); }
                    throw new AssertionError("Root fixture initialization failed", failure);
                }
            }
            return store;
        }
        @Override public AuditSink openAudit(ProviderConfig configuration) { return PkiBootstrap.openAudit(configuration); }
        @Override public PkiBootstrap.SigningComposition openSigningComposition(ProviderConfig configuration,
                SigningProviderRuntimeDependencies dependencies) {
            AlgorithmExecutionCapability capability = new AlgorithmExecutionCapability() {
                @Override public String implementationId() { return "session-root.exact"; }
                @Override public String domainFingerprint() { return "session-root:v1"; }
                @Override public boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction direction) {
                    return direction == Direction.SIGN && BootstrapAlgorithmIdentities.ED25519_SIGNATURE.equals(identity)
                            && identity.equals(suite.signature());
                }
            };
            return new PkiBootstrap.SigningComposition(root.provider, List.of(capability));
        }
    }
}
