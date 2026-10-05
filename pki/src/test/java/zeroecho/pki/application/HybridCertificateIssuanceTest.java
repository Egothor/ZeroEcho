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

    @Test void historicallyActiveAlternativeIntermediateCannotIssue(@TempDir Path root) throws Exception {
        HybridIssuanceFixture fixture = new HybridIssuanceFixture(root, "EC", "ECDSA", ECDSA_ALGORITHM,
                HybridIssuanceFixture.alternative());
        try (PkiSession session = fixture.open()) {
            zeroecho.pki.api.PkiId ca = fixture.create(session);
            RootCreationFixture.install(fixture.store, fixture.profile("unsupported-intermediate", 1,
                    CertificateProfileKind.INTERMEDIATE_CA, fixture.mode));
            LocalSigningResult result = session.localSigning().orElseThrow().execute(
                    new PkiSigningOperation.CreateIntermediate(X509, ca, new SubjectRef("CN=Rejected Child,C=CZ"),
                            "unsupported-intermediate", Optional.of(HybridIssuanceFixture.key("child"))), CancellationSignal.NONE);
            LocalSigningResult.Failed failed = org.junit.jupiter.api.Assertions.assertInstanceOf(LocalSigningResult.Failed.class, result);
            assertTrue(failed.receipt().isEmpty());
            assertEquals(1, fixture.store.listCas().size());
        }
    }

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

    @Test
    void alternativeRootLifecyclePersistsBothSignaturesAndRejectsModeOrKeyChanges(@TempDir Path root) throws Exception {
        HybridIssuanceFixture fixture = new HybridIssuanceFixture(root, "EC", "ECDSA", ECDSA_ALGORITHM,
                HybridIssuanceFixture.alternative());
        java.util.List<zeroecho.pki.api.PkiId> credentials = new java.util.ArrayList<>();
        try (PkiSession session = fixture.open()) {
            zeroecho.pki.api.PkiId ca = fixture.create(session);
            credentials.add(fixture.current(ca));
            fixture.execute(session, new PkiSigningOperation.RolloverCaCertificate(ca, Optional.empty()));
            credentials.add(fixture.current(ca));
            fixture.execute(session, new PkiSigningOperation.RotateCaKey(ca,
                    Optional.of(HybridIssuanceFixture.key("rotated")), Optional.empty()));
            credentials.add(fixture.current(ca));
            for (int index = 0; index < credentials.size(); index++) {
                fixture.verifyRoot(credentials.get(index), index == 2 ? fixture.rotatedKey : fixture.rootKey);
            }
            RootCreationFixture.install(fixture.store, fixture.profile("matrix-root", 2,
                    CertificateProfileKind.ROOT_CA, new HybridCertificateMode.AltSignature(ML_DSA_65_ALGORITHM,
                            HybridIssuanceFixture.key("other-alt").value())));
            assertRejectedBeforeAcceptance(session, ca);
            RootCreationFixture.install(fixture.store, fixture.profile("matrix-root", 3,
                    CertificateProfileKind.ROOT_CA, HybridCertificateMode.None.INSTANCE));
            assertRejectedBeforeAcceptance(session, ca);
            RootCreationFixture.install(fixture.store, fixture.profile("matrix-root", 4,
                    CertificateProfileKind.ROOT_CA, fixture.mode));
            fixture.execute(session, new PkiSigningOperation.RolloverCaCertificate(ca, Optional.empty()));
            fixture.verifyRoot(fixture.current(ca), fixture.rotatedKey);
            fixture.execute(session, new PkiSigningOperation.CreateIntermediate(X509, ca,
                    new SubjectRef("CN=Ordinary Child,C=CZ"), "matrix-intermediate", Optional.of(HybridIssuanceFixture.key("child"))));
            zeroecho.pki.api.PkiId child = fixture.store.listCas().stream().filter(value -> !value.caId().equals(ca))
                    .findFirst().orElseThrow().caId();
            fixture.certificate(fixture.current(child)).verify(fixture.rotatedKey.getPublic(), "BC");
            zeroecho.pki.api.PkiId leaf = fixture.issueLeaf(session, ca);
            fixture.certificate(leaf).verify(fixture.rotatedKey.getPublic(), "BC");
            fixture.execute(session, new PkiSigningOperation.GenerateStatus(ca,
                    zeroecho.pki.api.status.StatusObjectType.CRL, X509));
            fixture.verifyCrl(ca, fixture.rotatedKey);
        }
        try (PkiSession session = fixture.open()) {
            for (int index = 0; index < credentials.size(); index++) {
                fixture.verifyRoot(credentials.get(index), index == 2 ? fixture.rotatedKey : fixture.rootKey);
            }
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

    @BeforeAll
    static void registerBouncyCastle() {
        BouncyCastleActivator.init();
    }

    /**
     * Verifies that a hybrid ECDSA+ML-DSA-65 root CA creation is accepted by the full
     * PKI session — i.e., that the hybrid profile with AltSignature mode passes all
     * profile-validation, algorithm-compatibility and signing-provider gates.
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

    /** Minimal bootstrap that installs the hybrid profile on first store open. */
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
