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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.alg.mldsa.MldsaKeyGenSpec;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.hybrid.HybridCertificateMode;
import zeroecho.pki.api.profile.CaCertificatePolicy;
import zeroecho.pki.api.profile.CaKeyUsage;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.IssuanceApprovalRequirement;
import zeroecho.pki.api.profile.SubjectPolicy;
import zeroecho.pki.api.profile.SubjectRdnRule;
import zeroecho.pki.api.profile.SubjectRdnType;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.impl.crypto.zeroecholib.TestKeyringUnlocks;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.spi.crypto.SigningProviderRuntimeDependencies;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.PkiStoreRuntimeDependencies;
import zeroecho.pki.testkit.RootCreationFixture;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * Integration test verifying end-to-end hybrid root CA creation using an ECDSA P-256
 * primary signature and an ML-DSA-65 alternative signature (X.509 2019 Amendment 2,
 * AltSignatureValue mode).
 *
 * <p>
 * Tests require completed issuance, persisted certificates, independent verification
 * and successful verification after reopening the store.
 * </p>
 *
 * @since 1.0
 */
final class HybridCertificateIssuanceTest {

    /**
     * Alternative intermediate retains its own subject key and both parent signatures.
     *
     * @param root isolated temporary store root supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void alternativeIntermediateRetainsItsOwnSubjectKeyAndBothParentSignatures(@TempDir Path root) throws Exception {
        HybridIssuanceFixture fixture = new HybridIssuanceFixture(root, "EC", "ECDSA", ECDSA_ALGORITHM,
                HybridIssuanceFixture.alternative());
        try (PkiSession session = fixture.open()) {
            zeroecho.pki.api.PkiId ca = fixture.create(session);
            RootCreationFixture.install(fixture.store, fixture.profile("hybrid-intermediate", 1,
                    CertificateProfileKind.INTERMEDIATE_CA, new HybridCertificateMode.AltSignature(
                            BootstrapAlgorithmIdentities.ML_DSA_65_SIGNATURE.canonicalForm(), HybridIssuanceFixture.key("other-alt").value())));
            LocalSigningResult result = session.localSigning().orElseThrow().execute(
                    new PkiSigningOperation.CreateIntermediate(X509, ca, new SubjectRef("CN=Hybrid Child,C=CZ"),
                            "hybrid-intermediate", Optional.of(HybridIssuanceFixture.key("child"))), CancellationSignal.NONE);
            LocalSigningResult.Completed completed = org.junit.jupiter.api.Assertions.assertInstanceOf(LocalSigningResult.Completed.class, result);
            var credentialId = new zeroecho.pki.api.PkiId(((PkiOperationValue.Text) completed.result().fields().get("credentialId")).value());
            var child = fixture.certificate(credentialId);
            child.verify(fixture.rootKey.getPublic(), "BC");
            assertTrue(zeroecho.pkix.Pkix.verifyAlternativeSignatureCor3(child, fixture.altKey.getPublic()));
            assertFalse(zeroecho.pkix.Pkix.verifyAlternativeSignatureCor3(child, fixture.childKey.getPublic()));
            assertEquals(2, fixture.store.listCas().size());
            var childCa = fixture.store.listCas().stream().filter(value -> !value.caId().equals(ca)).findFirst().orElseThrow();
            var binding = fixture.store.getIssuerCryptographicBinding(childCa.currentIssuanceIssuerId()).orElseThrow();
            assertEquals(HybridIssuanceFixture.key("child"), binding.primary().keyRef());
            assertEquals(HybridIssuanceFixture.key("other-alt"), binding.alternative().orElseThrow().keyRef());
            assertEquals(zeroecho.pki.api.ca.IssuerCryptographicBinding.HybridSignatureBaseline.COR3_SIGNED_WRAPPER,
                    binding.certificateHybridBaseline());
            var inspected = org.junit.jupiter.api.Assertions.assertInstanceOf(PkiOperationOutcome.Completed.class,
                    session.operations().execute(new PkiOperation.InspectIssuerGeneration(binding.issuerId()),
                            CancellationSignal.NONE)).result();
            var metadata = org.junit.jupiter.api.Assertions.assertInstanceOf(PkiOperationValue.ObjectValue.class,
                    inspected.fields().get("cryptographicBinding")).fields();
            assertEquals(new PkiOperationValue.Text(binding.commitment()), metadata.get("commitment"));
            assertEquals(new PkiOperationValue.Text("COR3_SIGNED_WRAPPER"), metadata.get("certificateHybridBaseline"));
            var primary = org.junit.jupiter.api.Assertions.assertInstanceOf(PkiOperationValue.ObjectValue.class,
                    metadata.get("primary")).fields();
            var alternative = org.junit.jupiter.api.Assertions.assertInstanceOf(PkiOperationValue.ObjectValue.class,
                    metadata.get("alternative")).fields();
            assertEquals(new PkiOperationValue.Text(HybridIssuanceFixture.key("child").value()), primary.get("keyRef"));
            assertEquals(new PkiOperationValue.Text(HybridIssuanceFixture.key("other-alt").value()), alternative.get("keyRef"));
            assertEquals(new PkiOperationValue.Text(binding.primary().signatureAlgorithm().canonicalForm()), primary.get("signatureAlgorithmId"));
            assertEquals(new PkiOperationValue.Text(binding.alternative().orElseThrow().signatureAlgorithm().canonicalForm()), alternative.get("signatureAlgorithmId"));
        }
    }

    /**
     * Rejects untrusted alternative provider output before acceptance.
     *
     * @param fault named failure injected at the selected lifecycle boundary
     * @param root isolated temporary store root supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"empty", "wrong-key", "changed-signature", "oversize-key", "malformed-key"})
    void rejectsUntrustedAlternativeProviderOutputBeforeAcceptance(String fault, @TempDir Path root) throws Exception {
        HybridIssuanceFixture fixture = new HybridIssuanceFixture(root, "EC", "ECDSA", ECDSA_ALGORITHM,
                HybridIssuanceFixture.alternative());
        fixture.alternativeFault = fault;
        try (PkiSession session = fixture.open()) {
            LocalSigningResult result = session.localSigning().orElseThrow().execute(
                    new PkiSigningOperation.CreateAuthority(X509, new SubjectRef("CN=Rejected Root,C=CZ"),
                            "matrix-root", HybridIssuanceFixture.key("root")), CancellationSignal.NONE);
            LocalSigningResult.Failed failed = org.junit.jupiter.api.Assertions.assertInstanceOf(LocalSigningResult.Failed.class, result);
            assertTrue(failed.receipt().isEmpty());
            assertTrue(fixture.store.listCas().isEmpty());
        }
    }

    /**
     * Alternative root lifecycle preserves current roles and rejects mode changes.
     *
     * @param root isolated temporary store root supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test
    void alternativeRootLifecyclePreservesCurrentRolesAndRejectsModeChanges(@TempDir Path root) throws Exception {
        HybridIssuanceFixture fixture = new HybridIssuanceFixture(root, "EC", "ECDSA", ECDSA_ALGORITHM,
                HybridIssuanceFixture.alternative());
        var changedCreationDefaults = new HybridCertificateMode.AltSignature(ML_DSA_65_ALGORITHM,
                HybridIssuanceFixture.key("other-alt").value());
        java.util.List<zeroecho.pki.api.PkiId> credentials = new java.util.ArrayList<>();
        try (PkiSession session = fixture.open()) {
            zeroecho.pki.api.PkiId ca = fixture.create(session);
            credentials.add(fixture.current(ca));
            fixture.execute(session, new PkiSigningOperation.RolloverCaCertificate(ca, Optional.empty()));
            credentials.add(fixture.current(ca));
            var beforeCandidate = fixture.store.getCaHeadSnapshot(ca).orElseThrow();
            var candidateResult = fixture.execute(session, new PkiSigningOperation.RotateCaKey(ca,
                    Optional.of(HybridIssuanceFixture.key("rotated")), Optional.empty()));
            var candidate = new zeroecho.pki.api.PkiId(((PkiOperationValue.Text) candidateResult.result().fields().get("credentialId")).value());
            credentials.add(candidate);
            assertEquals("PENDING_ACTIVATION", ((PkiOperationValue.Text) candidateResult.result().fields().get("activationState")).value());
            assertEquals(beforeCandidate, fixture.store.getCaHeadSnapshot(ca).orElseThrow());
            assertEquals(credentials.get(1), fixture.current(ca));
            for (int index = 0; index < credentials.size(); index++) {
                fixture.verifyRoot(credentials.get(index), index == 2 ? fixture.rotatedKey : fixture.rootKey);
            }
            var retainedRoles = fixture.store.getIssuerCryptographicBinding(
                    fixture.store.getCa(ca).orElseThrow().currentIssuanceIssuerId()).orElseThrow();
            RootCreationFixture.install(fixture.store, fixture.profile("matrix-root", 2,
                    CertificateProfileKind.ROOT_CA, changedCreationDefaults));
            fixture.execute(session, new PkiSigningOperation.RolloverCaCertificate(ca, Optional.empty()));
            credentials.add(fixture.current(ca));
            fixture.verifyRoot(fixture.current(ca), fixture.rootKey, changedCreationDefaults);
            var rolledRoles = fixture.store.getIssuerCryptographicBinding(
                    fixture.store.getCa(ca).orElseThrow().currentIssuanceIssuerId()).orElseThrow();
            assertEquals(retainedRoles.primary(), rolledRoles.primary());
            assertEquals(retainedRoles.alternative(), rolledRoles.alternative());
            RootCreationFixture.install(fixture.store, fixture.profile("matrix-root", 3,
                    CertificateProfileKind.ROOT_CA, HybridCertificateMode.None.INSTANCE));
            assertRejectedBeforeAcceptance(session, ca);
            RootCreationFixture.install(fixture.store, fixture.profile("matrix-root", 4,
                    CertificateProfileKind.ROOT_CA, fixture.mode));
            fixture.execute(session, new PkiSigningOperation.RolloverCaCertificate(ca, Optional.empty()));
            fixture.verifyRoot(fixture.current(ca), fixture.rootKey);
            fixture.execute(session, new PkiSigningOperation.CreateIntermediate(X509, ca,
                    new SubjectRef("CN=Ordinary Child,C=CZ"), "matrix-intermediate", Optional.of(HybridIssuanceFixture.key("child"))));
            zeroecho.pki.api.PkiId child = fixture.store.listCas().stream().filter(value -> !value.caId().equals(ca))
                    .findFirst().orElseThrow().caId();
            fixture.certificate(fixture.current(child)).verify(fixture.rootKey.getPublic(), "BC");
            zeroecho.pki.api.PkiId leaf = fixture.issueLeaf(session, ca);
            fixture.certificate(leaf).verify(fixture.rootKey.getPublic(), "BC");
            fixture.execute(session, new PkiSigningOperation.GenerateStatus(ca,
                    zeroecho.pki.api.status.StatusObjectType.CRL, X509));
            fixture.verifyCrl(ca, fixture.rootKey);
        }
        {
            PkiSession session = fixture.open();
            try (session) {
                for (int index = 0; index < credentials.size(); index++) {
                    fixture.verifyRoot(credentials.get(index), index == 2 ? fixture.rotatedKey : fixture.rootKey,
                            index == 3 ? changedCreationDefaults : fixture.mode);
                }
            }
        }
    }

    /**
     * Explicit hybrid rotation preserves roles and root activation boundary.
     *
     * @param intermediate whether the tested authority is an intermediate rather than a root
     * @param role algorithm role selected for the binding-policy case
     * @param directory isolated temporary test directory supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({"false,primary", "false,alternative", "false,both",
            "true,primary", "true,alternative", "true,both"})
    void explicitHybridRotationPreservesRolesAndRootActivationBoundary(boolean intermediate, String role,
            @TempDir Path directory) throws Exception {
        var initialMode = new HybridCertificateMode.AltSignature(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(),
                HybridIssuanceFixture.key("alt").value());
        var fixture = new HybridIssuanceFixture(directory, "EC384", "ECDSA", BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm(),
                initialMode, "RSA4096", "ML-DSA-87");
        zeroecho.pki.api.PkiId authority;
        zeroecho.pki.api.PkiId candidateCredential;
        byte[] candidateDer;
        zeroecho.pki.api.ca.CaHeadSnapshot originalHead;
        try (var session = fixture.open()) {
            var root = fixture.create(session);
            String profile = intermediate ? "rotation-child" : "matrix-root";
            var mode = intermediate ? new HybridCertificateMode.AltSignature(
                    BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(), HybridIssuanceFixture.key("other-alt").value()) : initialMode;
            RootCreationFixture.install(fixture.store, fixture.profile(profile, intermediate ? 1 : 2,
                    intermediate ? CertificateProfileKind.INTERMEDIATE_CA : CertificateProfileKind.ROOT_CA, mode, Set.of("ECDSA", "RSA")));
            authority = root;
            if (intermediate) {
                fixture.execute(session, new PkiSigningOperation.CreateIntermediate(X509, root,
                        new SubjectRef("CN=Rotating Child,C=CZ"), profile, Optional.of(HybridIssuanceFixture.key("child")),
                        Optional.of(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384.canonicalForm())));
                authority = fixture.store.listCas().stream().filter(ca -> !ca.caId().equals(root)).findFirst().orElseThrow().caId();
            }
            originalHead = fixture.store.getCaHeadSnapshot(authority).orElseThrow();
            var originalBinding = fixture.store.getIssuerCryptographicBinding(originalHead.issuerId()).orElseThrow();
            byte[] originalDer = fixture.certificate(fixture.current(authority)).getEncoded();
            boolean primaryChanges = !role.equals("alternative");
            boolean alternativeChanges = !role.equals("primary");
            var newPrimaryKey = intermediate ? HybridIssuanceFixture.key("rotated") : HybridIssuanceFixture.key("child");
            var newPrimaryAlgorithm = intermediate ? BootstrapAlgorithmIdentities.ECDSA_SHA384 : BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384;
            var selection = new zeroecho.pki.api.ca.CaRotationSelection(1, primaryChanges
                    ? Optional.of(new zeroecho.pki.api.ca.CaRotationSelection.RoleChange(Optional.of(newPrimaryKey),
                            Optional.of(newPrimaryAlgorithm.canonicalForm()))) : Optional.empty(), alternativeChanges
                    ? Optional.of(new zeroecho.pki.api.ca.CaRotationSelection.RoleChange(Optional.of(HybridIssuanceFixture.key("rotated-alt")),
                            Optional.empty())) : Optional.empty());
            var operation = new PkiSigningOperation.RotateCaKey(authority, selection, intermediate ? Optional.of(root) : Optional.empty(),
                    Optional.of(originalHead));
            var completed = fixture.execute(session, operation);
            candidateCredential = new zeroecho.pki.api.PkiId(((PkiOperationValue.Text) completed.result().fields().get("credentialId")).value());
            var after = fixture.store.getCa(authority).orElseThrow();
            var newIssuer = zeroecho.pki.api.ca.IssuerGeneration.idFor(authority, candidateCredential);
            var issuedBinding = fixture.store.getIssuerCryptographicBinding(newIssuer).orElseThrow();
            assertEquals(primaryChanges ? newPrimaryAlgorithm : originalBinding.primary().signatureAlgorithm(), issuedBinding.primary().signatureAlgorithm());
            assertEquals(primaryChanges ? newPrimaryKey : originalBinding.primary().keyRef(), issuedBinding.primary().keyRef());
            assertEquals(alternativeChanges ? HybridIssuanceFixture.key("rotated-alt") : originalBinding.alternative().orElseThrow().keyRef(),
                    issuedBinding.alternative().orElseThrow().keyRef());
            var certificate = fixture.certificate(candidateCredential);
            candidateDer = certificate.getEncoded();
            certificate.verify(intermediate ? fixture.rootKey.getPublic() : primaryChanges ? fixture.childKey.getPublic() : fixture.rootKey.getPublic(), "BC");
            assertTrue(zeroecho.pkix.Pkix.verifyAlternativeSignatureCor3(certificate,
                    !intermediate && alternativeChanges ? fixture.rotatedAltKey.getPublic() : fixture.altKey.getPublic()));
            assertArrayEquals(originalDer, fixture.certificate(originalBinding.credentialId()).getEncoded());
            assertEquals(originalBinding, fixture.store.getIssuerCryptographicBinding(originalHead.issuerId()).orElseThrow());
            if (intermediate) {
                assertEquals(newIssuer, after.currentIssuanceIssuerId());
                assertEquals(originalHead.epoch() + 1, fixture.store.getCaHeadSnapshot(authority).orElseThrow().epoch());
            } else {
                assertEquals(originalHead, fixture.store.getCaHeadSnapshot(authority).orElseThrow());
                assertEquals("PENDING_ACTIVATION", ((PkiOperationValue.Text) completed.result().fields().get("activationState")).value());
                var transition = fixture.store.getRootTrustAnchorTransitionForIssuer(newIssuer).orElseThrow();
                assertTrue(fixture.store.getRootTrustAnchorActivation(transition.transitionId()).isEmpty());
                try (var download = session.repository().openCredential(candidateCredential); var input = download.openStream()) {
                    assertArrayEquals(certificate.getEncoded(), input.readAllBytes());
                }
            }
        }
        try (var reopened = fixture.open()) {
            assertTrue(reopened.signingCommands().isPresent());
            assertArrayEquals(candidateDer, fixture.certificate(candidateCredential).getEncoded());
            if (!intermediate) assertEquals(originalHead, fixture.store.getCaHeadSnapshot(authority).orElseThrow());
        }
    }

    /**
     * Pure PQC root rotation publishes candidate and keeps selected issuer.
     *
     * @param directory isolated temporary test directory supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void purePqcRootRotationPublishesCandidateAndKeepsSelectedIssuer(@TempDir Path directory) throws Exception {
        var fixture = new HybridIssuanceFixture(directory, "ML-DSA-87", "ML-DSA",
                BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(), HybridCertificateMode.None.INSTANCE,
                "ML-DSA-87", "ML-DSA-87");
        zeroecho.pki.api.PkiId authority;
        zeroecho.pki.api.PkiId candidate;
        zeroecho.pki.api.ca.CaHeadSnapshot original;
        byte[] issued;
        try (var session = fixture.open()) {
            authority = fixture.create(session);
            original = fixture.store.getCaHeadSnapshot(authority).orElseThrow();
            var result = fixture.execute(session, new PkiSigningOperation.RotateCaKey(authority,
                    Optional.of(HybridIssuanceFixture.key("rotated")), Optional.empty()));
            candidate = new zeroecho.pki.api.PkiId(((PkiOperationValue.Text) result.result().fields().get("credentialId")).value());
            var certificate = fixture.certificate(candidate);
            certificate.verify(fixture.rotatedKey.getPublic(), "BC");
            issued = certificate.getEncoded();
            assertEquals(original, fixture.store.getCaHeadSnapshot(authority).orElseThrow());
            assertEquals("PENDING_ACTIVATION", ((PkiOperationValue.Text) result.result().fields().get("activationState")).value());
        }
        try (var reopened = fixture.open()) {
            assertTrue(reopened.signingCommands().isPresent());
            assertEquals(original, fixture.store.getCaHeadSnapshot(authority).orElseThrow());
            assertArrayEquals(issued, fixture.certificate(candidate).getEncoded());
        }
    }

    /**
     * Existing hybrid intermediate cannot drop alternative role through active profile.
     *
     * @param directory isolated temporary test directory supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void existingHybridIntermediateCannotDropAlternativeRoleThroughActiveProfile(@TempDir Path directory) throws Exception {
        var fixture = new HybridIssuanceFixture(directory, "EC384", "ECDSA", BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm(),
                new HybridCertificateMode.AltSignature(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(),
                        HybridIssuanceFixture.key("alt").value()), "EC384", "ML-DSA-87");
        var armed = new java.util.concurrent.atomic.AtomicBoolean();
        var signs = new java.util.concurrent.atomic.AtomicInteger(); var stages = new java.util.concurrent.atomic.AtomicInteger();
        fixture.signingDecorator = provider -> (zeroecho.pki.spi.crypto.SigningProvider) java.lang.reflect.Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[]{zeroecho.pki.spi.crypto.SigningProvider.class,
                        zeroecho.pki.spi.crypto.PublicKeyInfoSource.class, zeroecho.pki.spi.crypto.AltSigningCapability.class},
                (proxy, method, args) -> {
                    if (armed.get() && method.getName().equals("sign")) signs.incrementAndGet();
                    try { return method.invoke(provider, args); }
                    catch (java.lang.reflect.InvocationTargetException failure) { throw failure.getCause(); }
                });
        fixture.storeDecorator = actual -> {
            var content = (zeroecho.pki.spi.store.StagedContentStore) java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[]{zeroecho.pki.spi.store.StagedContentStore.class}, (proxy, method, args) -> {
                        if (armed.get() && method.getName().equals("beginContent")) stages.incrementAndGet();
                        try { return method.invoke(actual.stagedContent(), args); }
                        catch (java.lang.reflect.InvocationTargetException failure) { throw failure.getCause(); }
                    });
            return (PkiStore) java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{PkiStore.class},
                    (proxy, method, args) -> {
                        if (method.getName().equals("stagedContent")) return content;
                        try { return method.invoke(actual, args); }
                        catch (java.lang.reflect.InvocationTargetException failure) { throw failure.getCause(); }
                    });
        };
        try (var session = fixture.open()) {
            var root = fixture.create(session);
            RootCreationFixture.install(fixture.store, fixture.profile("mode-child", 1, CertificateProfileKind.INTERMEDIATE_CA,
                    new HybridCertificateMode.AltSignature(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(),
                            HybridIssuanceFixture.key("other-alt").value())));
            fixture.execute(session, new PkiSigningOperation.CreateIntermediate(X509, root, new SubjectRef("CN=Mode Child,C=CZ"),
                    "mode-child", Optional.of(HybridIssuanceFixture.key("child"))));
            var child = fixture.store.listCas().stream().filter(ca -> !ca.caId().equals(root)).findFirst().orElseThrow().caId();
            var before = fixture.store.getCaHeadSnapshot(child).orElseThrow();
            RootCreationFixture.install(fixture.store, fixture.profile("mode-child", 2, CertificateProfileKind.INTERMEDIATE_CA,
                    HybridCertificateMode.None.INSTANCE));
            armed.set(true);
            for (PkiSigningOperation operation : List.of(new PkiSigningOperation.RolloverCaCertificate(child, Optional.of(root)),
                    new PkiSigningOperation.RotateCaKey(child, Optional.of(HybridIssuanceFixture.key("rotated")), Optional.of(root)),
                    new PkiSigningOperation.IssueIntermediateCertificate(X509, root, child, "mode-child", Optional.empty()))) {
                var failure = org.junit.jupiter.api.Assertions.assertInstanceOf(LocalSigningResult.Failed.class,
                        session.localSigning().orElseThrow().execute(operation, CancellationSignal.NONE));
                assertTrue(failure.receipt().isEmpty());
            }
            assertEquals(HybridCertificateMode.None.INSTANCE, fixture.store.requireActiveProfile("mode-child").definition().hybridMode());
            assertEquals(before, fixture.store.getCaHeadSnapshot(child).orElseThrow());
            assertEquals(0, signs.get()); assertEquals(0, stages.get());
        }
    }

    private static void assertRejectedBeforeAcceptance(PkiSession session, zeroecho.pki.api.PkiId ca) {
        LocalSigningResult result = session.localSigning().orElseThrow().execute(
                new PkiSigningOperation.RolloverCaCertificate(ca, Optional.empty()), CancellationSignal.NONE);
        LocalSigningResult.Failed failed = org.junit.jupiter.api.Assertions.assertInstanceOf(LocalSigningResult.Failed.class, result);
        assertTrue(failed.receipt().isEmpty());
    }

    private static final FormatId X509 = new FormatId("x509");
    private static final String ECDSA_ALGORITHM =
            BootstrapAlgorithmIdentities.ECDSA_SHA256.canonicalForm();
    private static final String ML_DSA_65_ALGORITHM =
            BootstrapAlgorithmIdentities.ML_DSA_65_SIGNATURE.canonicalForm();
    private static final String PROFILE_ID = "hybrid-ecdsa-mldsa65-root";
    private static final KeyRef ROOT_KEY = new KeyRef("zeroecho-lib:root.prv");
    private static final String ALT_KEY_REF = "zeroecho-lib:alt.prv";
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-01T12:00:00Z"), ZoneOffset.UTC);

    /**
     * Registers the cryptographic providers required by the test cases.
     */
    @BeforeAll
    static void registerBouncyCastle() {
        BouncyCastleActivator.init();
    }

    /**
     * Verifies that a hybrid ECDSA+ML-DSA-65 root CA creation is accepted by the full
     * PKI session — i.e., that the hybrid profile with AltSignature mode passes all
     * profile-validation, algorithm-compatibility and signing-provider gates.
     *
     * @param root isolated filesystem store root supplied by the test
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test
    void hybridRootCaCreationIsAccepted(@TempDir Path root) throws Exception {
        Path keyring = createHybridKeyring(root);
        LocalSigningResult result;
        try (PkiSession session = openSession(root, keyring)) {
            LocalSigningExecutor executor = session.localSigning().orElseThrow();
            result = executor.execute(
                    new PkiSigningOperation.CreateAuthority(
                            X509, new SubjectRef("CN=Hybrid Root CA,C=CZ"), PROFILE_ID, ROOT_KEY),
                    CancellationSignal.NONE);
        }
        org.junit.jupiter.api.Assertions.assertInstanceOf(LocalSigningResult.Completed.class, result);
    }

    private static Path createHybridKeyring(Path root) throws Exception {
        Path keyring = root.resolve("keys.bin");
        // Generate ECDSA P-256 primary key using standard JCA (BC is registered via @BeforeAll).
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ecPair = kpg.generateKeyPair();
        // Generate ML-DSA-65 alt key using ZeroEcho SDK.
        KeyPair mlDsaPair = new ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("ML-DSA",
                MldsaKeyGenSpec.of("BC", MldsaKeyGenSpec.ParameterSet.ML_DSA_65, MldsaKeyGenSpec.PreHash.NONE));
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keys = KeyringStore.create(keyring, password)) {
            keys.putPrivate("root.prv", "ECDSA", ecPair.getPrivate());
            keys.putPublic("root.pub", "ECDSA", ecPair.getPublic());
            keys.putPrivate("alt.prv", "ML-DSA", mlDsaPair.getPrivate());
            keys.putPublic("alt.pub", "ML-DSA", mlDsaPair.getPublic());
        }
        return keyring;
    }

    private static PkiSession openSession(Path root, Path keyring) {
        LocalSigningConfiguration signing = new LocalSigningConfiguration(
                new ProviderConfig("zeroecho-lib", Map.of(
                        "keyringPath", keyring.toString(),
                        "operationHorizon", "P90D",
                        "keyRefPrefix", "zeroecho-lib:",
                        "requireComponentSuffix", "true")),
                ECDSA_ALGORITHM,
                Duration.ofMinutes(5),
                Optional.empty(),
                Duration.ofSeconds(10),
                Duration.ofSeconds(5),
                OptionalLong.empty());

        LocalPkiSessionConfiguration configuration = new LocalPkiSessionConfiguration(
                new ProviderConfig("fs", Map.of("root", root.resolve("store").toString())),
                new ProviderConfig("memory", Map.of()),
                "hybrid-test-operator",
                Optional.of(signing),
                List.of(),
                List.of());

        return DefaultPkiSession.openLocal(configuration,
                PkiSessionRuntimeDependencies.withKeyringUnlockProvider(TestKeyringUnlocks.provider()),
                CLOCK,
                new HybridBootstrap(root));
    }


    private static CertificateProfileDefinition hybridRootCaProfile() {
        return new CertificateProfileDefinition(
                CertificateProfileKind.ROOT_CA,
                PROFILE_ID,
                1,
                X509,
                "Hybrid Root CA (ECDSA P-256 + ML-DSA-65)",
                Duration.ofDays(3650),
                IssuanceApprovalRequirement.NONE,
                new SubjectPolicy(false, List.of(
                        new SubjectRdnRule(SubjectRdnType.COMMON_NAME, 1, 1, 128, Optional.empty(), true),
                        new SubjectRdnRule(SubjectRdnType.COUNTRY_NAME, 1, 1, 2, Optional.empty(), true))),
                new CaCertificatePolicy(true, 2, true,
                        Set.of(CaKeyUsage.KEY_CERT_SIGN, CaKeyUsage.CRL_SIGN),
                        Set.of("ECDSA")),
                X509AlgorithmBindingPolicy.standardOnly(),
                Optional.empty(),
                new HybridCertificateMode.AltSignature(ML_DSA_65_ALGORITHM, ALT_KEY_REF));
    }

    /**
     * Minimal bootstrap that installs the hybrid profile on first store open.
     */
    private static final class HybridBootstrap implements DefaultPkiSession.Bootstrap {
        private final Path root;

        HybridBootstrap(Path root) {
            this.root = root;
        }

        @Override
        public void validateStore(ProviderConfig configuration) {
            PkiBootstrap.validateStoreConfiguration(configuration);
        }

        @Override
        public void validateAudit(ProviderConfig configuration) {
            PkiBootstrap.validateAuditConfiguration(configuration);
        }

        @Override
        public PkiStore openStore(ProviderConfig configuration) {
            return openStore(configuration, new PkiStoreRuntimeDependencies(CLOCK));
        }

        @Override
        @SuppressWarnings("PMD.AvoidCatchingGenericException")
        public PkiStore openStore(ProviderConfig configuration, PkiStoreRuntimeDependencies dependencies) {
            PkiStore store = PkiBootstrap.openStore(configuration, dependencies);
            if (store.getActiveProfileRef(PROFILE_ID).isEmpty()) {
                try {
                    RootCreationFixture.install(store, hybridRootCaProfile());
                } catch (Exception failure) {
                    throw new AssertionError("Failed to install hybrid root CA profile", failure);
                }
            }
            return store;
        }

        @Override
        public AuditSink openAudit(ProviderConfig configuration) {
            return event -> { };
        }

        @Override
        public PkiBootstrap.SigningComposition openSigningComposition(ProviderConfig configuration,
                SigningProviderRuntimeDependencies dependencies) {
            return PkiBootstrap.openConfiguredSigningComposition(configuration, dependencies);
        }
    }
}
