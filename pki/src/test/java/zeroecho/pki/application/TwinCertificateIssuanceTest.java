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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.security.KeyPair;
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
 * Integration test verifying end-to-end PQC root CA creation using an ML-DSA-65
 * primary signature and {@link HybridCertificateMode.TwinCertificate} profile marker
 * (hybrid certificate variant A).
 *
 * <p>
 * In twin-certificate deployments the classical and PQC CA hierarchies are separate;
 * each individual certificate is a standard, single-algorithm X.509 certificate. The
 * {@code TwinCertificate} mode is a semantic marker in the profile — it adds no
 * extensions to the certificate. This test verifies that the mode passes all policy,
 * algorithm-compatibility and signing-provider gates.
 * </p>
 *
 * <p>
 * Both independent hierarchies must complete issuance and verify persisted
 * certificates and primary-signature CRLs after reopening the store.
 * </p>
 *
 * @since 1.0
 */
final class TwinCertificateIssuanceTest {

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    void independentClassicalAndPqcHierarchiesCompleteAndReopen(boolean pqc, @TempDir Path root) throws Exception {
        String algorithm = (pqc ? BootstrapAlgorithmIdentities.ML_DSA_65_SIGNATURE
                : BootstrapAlgorithmIdentities.ECDSA_SHA256).canonicalForm();
        HybridIssuanceFixture fixture = new HybridIssuanceFixture(root, pqc ? "ML-DSA-65" : "EC",
                pqc ? "ML-DSA" : "ECDSA", algorithm, HybridCertificateMode.TwinCertificate.INSTANCE);
        zeroecho.pki.api.PkiId rootId;
        zeroecho.pki.api.PkiId rootCredential;
        zeroecho.pki.api.PkiId childCredential;
        zeroecho.pki.api.PkiId leafCredential;
        try (PkiSession session = fixture.open()) {
            rootId = fixture.create(session);
            fixture.execute(session, new PkiSigningOperation.RolloverCaCertificate(rootId, Optional.empty()));
            fixture.execute(session, new PkiSigningOperation.RotateCaKey(rootId,
                    Optional.of(HybridIssuanceFixture.key("rotated")), Optional.empty()));
            rootCredential = fixture.current(rootId);
            fixture.verifyRoot(rootCredential, fixture.rotatedKey);
            fixture.execute(session, new PkiSigningOperation.CreateIntermediate(X509, rootId,
                    new SubjectRef("CN=Twin Child,C=CZ"), "matrix-intermediate", Optional.of(HybridIssuanceFixture.key("child"))));
            zeroecho.pki.api.PkiId child = fixture.store.listCas().stream().filter(ca -> !ca.caId().equals(rootId))
                    .findFirst().orElseThrow().caId();
            javax.security.auth.x500.X500Principal initialSubject = fixture.certificate(fixture.current(child)).getSubjectX500Principal();
            fixture.execute(session, new PkiSigningOperation.IssueIntermediateCertificate(X509, rootId,
                    child, "matrix-intermediate", Optional.empty()));
            fixture.execute(session, new PkiSigningOperation.RolloverCaCertificate(child, Optional.of(rootId)));
            childCredential = fixture.current(child);
            assertEquals(initialSubject, fixture.certificate(childCredential).getSubjectX500Principal());
            fixture.certificate(childCredential).verify(fixture.rotatedKey.getPublic(), "BC");
            leafCredential = fixture.issueLeaf(session, child);
            fixture.certificate(leafCredential).verify(fixture.childKey.getPublic(), "BC");
            fixture.execute(session, new PkiSigningOperation.GenerateStatus(rootId,
                    zeroecho.pki.api.status.StatusObjectType.CRL, X509));
            fixture.verifyCrl(rootId, fixture.rotatedKey);
            assertTrue(session.ocsp().isEmpty());
        }
        try (PkiSession session = fixture.open()) {
            fixture.verifyRoot(rootCredential, fixture.rotatedKey);
            fixture.certificate(childCredential).verify(fixture.rotatedKey.getPublic(), "BC");
            fixture.certificate(leafCredential).verify(fixture.childKey.getPublic(), "BC");
            fixture.verifyCrl(rootId, fixture.rotatedKey);
        }
    }

    private static final FormatId X509 = new FormatId("x509");
    private static final String ML_DSA_65_ALGORITHM =
            BootstrapAlgorithmIdentities.ML_DSA_65_SIGNATURE.canonicalForm();
    private static final String PROFILE_ID = "pqc-mldsa65-root-twin-test";
    private static final KeyRef ROOT_KEY = new KeyRef("zeroecho-lib:root.prv");
    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-10-01T12:00:00Z"), ZoneOffset.UTC);

    @BeforeAll
    static void registerBouncyCastle() {
        BouncyCastleActivator.init();
    }

    /**
     * Verifies that a PQC root CA creation using ML-DSA-65 and the
     * {@code TwinCertificate} hybrid mode is accepted by the full PKI session.
     */
    @Test
    void pqcRootCaWithTwinCertificateModeIsAccepted(@TempDir Path root) throws Exception {
        Path keyring = createPqcKeyring(root);
        LocalSigningResult result;
        try (PkiSession session = openSession(root, keyring)) {
            LocalSigningExecutor executor = session.localSigning().orElseThrow();
            result = executor.execute(
                    new PkiSigningOperation.CreateAuthority(
                            X509, new SubjectRef("CN=PQC Root CA,C=CZ"), PROFILE_ID, ROOT_KEY),
                    CancellationSignal.NONE);
        }
        org.junit.jupiter.api.Assertions.assertInstanceOf(LocalSigningResult.Completed.class, result);
    }

    private static Path createPqcKeyring(Path root) throws Exception {
        Path keyring = root.resolve("keys.bin");
        KeyPair mlDsaPair = new ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("ML-DSA",
                MldsaKeyGenSpec.of("BC", MldsaKeyGenSpec.ParameterSet.ML_DSA_65, MldsaKeyGenSpec.PreHash.NONE));
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keys = KeyringStore.create(keyring, password)) {
            keys.putPrivate("root.prv", "ML-DSA", mlDsaPair.getPrivate());
            keys.putPublic("root.pub", "ML-DSA", mlDsaPair.getPublic());
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
                ML_DSA_65_ALGORITHM,
                Duration.ofMinutes(5),
                Optional.empty(),
                Duration.ofSeconds(10),
                Duration.ofSeconds(5),
                OptionalLong.empty());

        LocalPkiSessionConfiguration configuration = new LocalPkiSessionConfiguration(
                new ProviderConfig("fs", Map.of("root", root.resolve("store").toString())),
                new ProviderConfig("memory", Map.of()),
                "pqc-twin-test-operator",
                Optional.of(signing),
                List.of(),
                List.of());

        return DefaultPkiSession.openLocal(configuration,
                PkiSessionRuntimeDependencies.withKeyringUnlockProvider(TestKeyringUnlocks.provider()),
                CLOCK,
                new TwinBootstrap(root));
    }


    private static CertificateProfileDefinition pqcRootCaProfile() {
        return new CertificateProfileDefinition(
                CertificateProfileKind.ROOT_CA,
                PROFILE_ID,
                1,
                X509,
                "PQC Root CA — ML-DSA-65, twin deployment",
                Duration.ofDays(3650),
                IssuanceApprovalRequirement.NONE,
                new SubjectPolicy(false, List.of(
                        new SubjectRdnRule(SubjectRdnType.COMMON_NAME, 1, 1, 128, Optional.empty(), true),
                        new SubjectRdnRule(SubjectRdnType.COUNTRY_NAME, 1, 1, 2, Optional.empty(), true))),
                new CaCertificatePolicy(true, 1, true,
                        Set.of(CaKeyUsage.KEY_CERT_SIGN, CaKeyUsage.CRL_SIGN),
                        Set.of("ML-DSA")),
                X509AlgorithmBindingPolicy.standardOnly(),
                Optional.empty(),
                HybridCertificateMode.TwinCertificate.INSTANCE);
    }

    /** Minimal bootstrap that installs the PQC profile on first store open. */
    private static final class TwinBootstrap implements DefaultPkiSession.Bootstrap {
        private final Path root;

        TwinBootstrap(Path root) {
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
                    RootCreationFixture.install(store, pqcRootCaProfile());
                } catch (Exception failure) {
                    throw new AssertionError("Failed to install PQC root CA profile", failure);
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
