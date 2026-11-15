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

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Path;
import java.util.Optional;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.*;
import zeroecho.pki.api.hybrid.HybridCertificateMode;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.testkit.RootCreationFixture;

/** Native managed-key chains prove incoming and outgoing algorithms remain distinct in one realm. */
final class C034MixedIssuerHierarchyTest {
    @ParameterizedTest
    @CsvSource({"EC384,ECDSA,ML-DSA-87,ML-DSA", "ML-DSA-87,ML-DSA,RSA4096,RSA", "RSA4096,RSA,EC384,ECDSA"})
    void issuesAndReopensMixedAlgorithmRootIntermediateLeaf(String rootAlgorithm, String rootFamily,
            String childAlgorithm, String childFamily, @TempDir Path directory) throws Exception {
        AlgorithmIdentity rootSignature = signature(rootAlgorithm);
        AlgorithmIdentity childSignature = signature(childAlgorithm);
        HybridIssuanceFixture fixture = new HybridIssuanceFixture(directory, rootAlgorithm, rootFamily,
                rootSignature.canonicalForm(), HybridCertificateMode.None.INSTANCE, childAlgorithm, "ML-DSA-87");
        PkiId root;
        PkiId child;
        PkiId leaf;
        try (PkiSession session = fixture.open()) {
            fixture.execute(session, new PkiSigningOperation.CreateAuthority(HybridIssuanceFixture.X509,
                    new SubjectRef("CN=Mixed Root,C=CZ"), "matrix-root", HybridIssuanceFixture.key("root"),
                    Optional.of(rootSignature.canonicalForm())));
            root = fixture.store.listCas().getFirst().caId();
            RootCreationFixture.install(fixture.store, fixture.profile("mixed-child", 1,
                    CertificateProfileKind.INTERMEDIATE_CA, HybridCertificateMode.None.INSTANCE, Set.of(childFamily)));
            fixture.execute(session, new PkiSigningOperation.CreateIntermediate(HybridIssuanceFixture.X509, root,
                    new SubjectRef("CN=Mixed Child,C=CZ"), "mixed-child", Optional.of(HybridIssuanceFixture.key("child")),
                    Optional.of(childSignature.canonicalForm())));
            child = fixture.store.listCas().stream().filter(ca -> !ca.caId().equals(root)).findFirst().orElseThrow().caId();
            var childCertificate = fixture.certificate(fixture.current(child));
            childCertificate.verify(fixture.rootKey.getPublic(), "BC");
            assertArrayEquals(fixture.childKey.getPublic().getEncoded(), childCertificate.getPublicKey().getEncoded());
            var binding = fixture.store.getIssuerCryptographicBinding(fixture.store.getCa(child).orElseThrow().currentIssuanceIssuerId()).orElseThrow();
            assertEquals(childSignature, binding.primary().signatureAlgorithm());
            assertNotEquals(rootSignature, binding.primary().signatureAlgorithm());
            leaf = fixture.issueLeaf(session, child);
            fixture.certificate(leaf).verify(fixture.childKey.getPublic(), "BC");
            var certificate = fixture.certificate(leaf);
            assertThrows(java.security.GeneralSecurityException.class, () -> certificate.verify(fixture.rootKey.getPublic(), "BC"));
        }
        try (PkiSession reopened = fixture.open()) {
            assertTrue(reopened.signingCommands().isPresent());
            fixture.certificate(fixture.current(root)).verify(fixture.rootKey.getPublic(), "BC");
            fixture.certificate(fixture.current(child)).verify(fixture.rootKey.getPublic(), "BC");
            fixture.certificate(leaf).verify(fixture.childKey.getPublic(), "BC");
        }
    }
    @org.junit.jupiter.api.Test void managedHybridChildPreparationBindsBothProofRolesToFinalTbs(@TempDir Path directory) throws Exception {
        var rootMode = new HybridCertificateMode.AltSignature(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(),
                HybridIssuanceFixture.key("alt").value());
        var fixture = new HybridIssuanceFixture(directory, "EC384", "ECDSA", BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm(),
                rootMode, "RSA4096", "ML-DSA-87");
        var providerRef = new java.util.concurrent.atomic.AtomicReference<zeroecho.pki.spi.crypto.SigningProvider>();
        fixture.signingDecorator = provider -> { providerRef.set(provider); return provider; };
        try (var session = fixture.open()) {
            PkiId root = fixture.create(session);
            var childMode = new HybridCertificateMode.AltSignature(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(),
                    HybridIssuanceFixture.key("other-alt").value());
            RootCreationFixture.install(fixture.store, fixture.profile("dual-child", 1, CertificateProfileKind.INTERMEDIATE_CA,
                    childMode, Set.of("RSA")));
            var provider = providerRef.get();
            var signing = zeroecho.pki.testkit.PkiTestRuntime.signingAuthority(provider);
            var verifier = new zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor();
            var verification = zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot.compose(List.of(), List.of(verifier),
                    List.of(zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot.bindExecutor(
                            zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor.IMPLEMENTATION_ID,
                            zeroecho.core.spi.AlgorithmExecutionCapability.Direction.VERIFY, verifier)),
                    (suite, direction) -> direction == zeroecho.core.spi.AlgorithmExecutionCapability.Direction.VERIFY);
            var registry = zeroecho.pki.impl.framework.x509.ImmutableX509AlgorithmBindingRegistry.create(
                    zeroecho.pki.impl.framework.x509.StandardX509Bindings.descriptors());
            var proofs = new zeroecho.pki.impl.core.ManagedKeyProofPreparation(fixture.store, provider, signing, verification,
                    verifier, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384.canonicalForm(), new java.security.SecureRandom(), 1_048_576);
            var preparation = new zeroecho.pki.impl.core.IntermediateSigningPreparation(fixture.store, HybridIssuanceFixture.CLOCK,
                    provider, signing, registry, BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm(), 1_048_576, proofs);
            var submission = zeroecho.pki.api.orch.SigningSubmissionId.create(fixture.store.signingNamespace() + "." + provider.id(),
                    HybridIssuanceFixture.CLOCK.instant(), new java.security.SecureRandom());
            var domain = preparation.prepare(RootCreationFixture.ACCESS, new zeroecho.pki.api.ca.IntermediateCreateCommand(
                    HybridIssuanceFixture.X509, root, new SubjectRef("CN=Dual Child,C=CZ"), "dual-child", HybridIssuanceFixture.key("child"),
                    new zeroecho.pki.impl.core.attr.SimpleAttributeSet(), Optional.of(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384.canonicalForm())),
                    submission, java.time.Duration.ofMinutes(5), zeroecho.core.io.CancellationSignal.NONE);
            try {
                var primary = domain.proofStep().orElseThrow(); var alternative = domain.alternativeProofStep().orElseThrow();
                assertNotEquals(primary.operationId(), alternative.operationId());
                assertEquals(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384.canonicalForm(), primary.algorithmId());
                assertEquals(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(), alternative.algorithmId());
                var template = domain.domainTemplate();
                var envelope = zeroecho.pki.spi.store.SignWorkflowStore.AcceptanceEnvelope.from(new zeroecho.pki.spi.store.SignWorkflowStore.AcceptanceCommand(
                        domain.operationId(), fixture.store.signingNamespace() + "." + provider.id(), provider.configurationCommitment(),
                        domain.accessContext(), domain.keyRef(), root, domain.algorithmId(), Encoding.BINARY, submission.createdAt(),
                        submission.createdAt().plus(domain.ttl()), domain.content(), Optional.of(new zeroecho.pki.spi.store.SignWorkflowStore.OuterCommand(
                                template.kind(), template.correlationId().orElseThrow(), template.command(), template.commandCommitment())),
                        zeroecho.pki.spi.store.SignWorkflowStore.Mode.NORMAL, Optional.of(primary), Optional.of(alternative)));
                zeroecho.pki.impl.core.continuation.CaSubjectProofBindings.requireLiveCandidates(fixture.store.stagedContent(), envelope);
                assertEquals(Optional.of(zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole.PRIMARY),
                        zeroecho.pki.impl.core.continuation.CaSubjectProofBindings.context(envelope,
                                zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole.PRIMARY).role());
                assertEquals(Optional.of(zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole.ALTERNATIVE),
                        zeroecho.pki.impl.core.continuation.CaSubjectProofBindings.context(envelope,
                                zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole.ALTERNATIVE).role());
                assertEquals(HybridIssuanceFixture.key("other-alt").value(),
                        zeroecho.pki.impl.core.continuation.CaSubjectProofBindings.requireEnvelope(envelope,
                                zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole.ALTERNATIVE).field(5));
            } finally {
                for (var candidate : domain.candidates()) fixture.store.stagedContent().retireUnownedContent(candidate);
            }
        }
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"wrong-key", "changed-proof"})
    void invalidAlternativeSubjectProofPreventsPrimaryIssuerDispatch(String fault, @TempDir Path directory) throws Exception {
        var mode = new HybridCertificateMode.AltSignature(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(),
                HybridIssuanceFixture.key("alt").value());
        var fixture = new HybridIssuanceFixture(directory, "EC384", "ECDSA", BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm(),
                mode, "RSA4096", "ML-DSA-87");
        var armed = new java.util.concurrent.atomic.AtomicBoolean();
        var issuerDispatches = new java.util.concurrent.atomic.AtomicInteger();
        var alternativeDispatches = new java.util.concurrent.atomic.AtomicInteger();
        fixture.signingDecorator = provider -> (zeroecho.pki.spi.crypto.SigningProvider) java.lang.reflect.Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[] {zeroecho.pki.spi.crypto.SigningProvider.class,
                        zeroecho.pki.spi.crypto.PublicKeyInfoSource.class, zeroecho.pki.spi.crypto.AltSigningCapability.class},
                (proxy, method, arguments) -> {
                    try {
                        if (armed.get() && method.getName().equals("dispatch")) {
                            var request = (zeroecho.pki.spi.crypto.SigningProvider.SignRequest) arguments[0];
                            if (request.keyRef().equals(HybridIssuanceFixture.key("root"))) issuerDispatches.incrementAndGet();
                            if (request.keyRef().equals(HybridIssuanceFixture.key("other-alt"))) {
                                alternativeDispatches.incrementAndGet();
                                var observed = (zeroecho.pki.spi.crypto.SigningProvider.OperationObservation) method.invoke(provider, arguments);
                                byte[] signature = observed.signature().orElseThrow().bytes();
                                if (fault.equals("wrong-key")) {
                                    try (var input = request.content().openStream()) {
                                        signature = ((zeroecho.pki.spi.crypto.AltSigningCapability) provider).sign(
                                                HybridIssuanceFixture.key("alt"), request.algorithmId(), input.readAllBytes());
                                    }
                                } else signature[0] ^= 1;
                                return new zeroecho.pki.spi.crypto.SigningProvider.OperationObservation(observed.operationId(), observed.state(),
                                        observed.updatedAt(), observed.detailCode(), Optional.of(new EncodedObject(Encoding.BINARY, signature)));
                            }
                        }
                        return method.invoke(provider, arguments);
                    } catch (java.lang.reflect.InvocationTargetException failure) { throw failure.getCause(); }
                });
        PkiId operation;
        try (var session = fixture.open()) {
            PkiId root = fixture.create(session);
            var before = fixture.store.getCa(root).orElseThrow();
            RootCreationFixture.install(fixture.store, fixture.profile("dual-rejected", 1, CertificateProfileKind.INTERMEDIATE_CA,
                    new HybridCertificateMode.AltSignature(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(),
                            HybridIssuanceFixture.key("other-alt").value()), Set.of("RSA")));
            armed.set(true);
            var result = session.localSigning().orElseThrow().execute(new PkiSigningOperation.CreateIntermediate(
                    HybridIssuanceFixture.X509, root, new SubjectRef("CN=Rejected Dual,C=CZ"), "dual-rejected",
                    Optional.of(HybridIssuanceFixture.key("child")), Optional.of(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384.canonicalForm())),
                    zeroecho.core.io.CancellationSignal.NONE);
            var failed = assertInstanceOf(LocalSigningResult.Failed.class, result);
            operation = failed.receipt().orElseThrow().operationId();
            var workflow = fixture.store.getSignWorkflow(operation).orElseThrow();
            assertEquals(1, alternativeDispatches.get(), () -> "Expected alternative proof dispatch; actual="
                    + workflow.state() + "/" + workflow.stage() + "/" + workflow.detailCode()
                    + "; failure=" + failed.failure().code());
            assertEquals(0, issuerDispatches.get(), "Both subject proofs must verify before primary issuer dispatch");
            assertEquals(zeroecho.pki.spi.store.SignWorkflowStore.State.RETIRED, workflow.state());
            assertEquals(zeroecho.pki.api.signing.SemanticSigningState.FAILED,
                    session.semanticSigning().orElseThrow().find(operation).orElseThrow().state());
            assertTrue(workflow.proofOutcome().isPresent());
            assertEquals(Optional.of("FAILED"), workflow.detailCode());
            assertEquals(Optional.of("MANAGED_KEY_PROOF_SIGNATURE_INVALID"),
                    session.semanticSigning().orElseThrow().find(operation).orElseThrow().detailCode());
            assertEquals(before, fixture.store.getCa(root).orElseThrow());
            assertEquals(1, fixture.store.listCas().size());
        }
        try (var reopened = fixture.open()) {
            assertEquals(zeroecho.pki.api.signing.SemanticSigningState.FAILED,
                    reopened.semanticSigning().orElseThrow().find(operation).orElseThrow().state());
            assertEquals(1, alternativeDispatches.get()); assertEquals(0, issuerDispatches.get());
            assertEquals(1, fixture.store.listCas().size());
        }
    }

    private static AlgorithmIdentity signature(String algorithm) {
        return switch (algorithm) {
            case "EC384" -> BootstrapAlgorithmIdentities.ECDSA_SHA384;
            case "RSA4096" -> BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384;
            case "ML-DSA-87" -> BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE;
            default -> throw new IllegalArgumentException("Unsupported test algorithm");
        };
    }
}
