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
import zeroecho.pki.api.profile.CaCertificatePolicy;
import zeroecho.pki.api.profile.CaKeyUsage;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileKind;
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
 * Integration test verifying end-to-end PQC root CA creation using ML-DSA-65 (FIPS 204).
 *
 * <p>
 * The test exercises: ML-DSA-65 key generation, keyring storage,
 * {@link LocalSigningConfiguration} with the ML-DSA-65 signing algorithm, and
 * root CA creation via {@link PkiSigningOperation.CreateAuthority}. It confirms
 * that the full local signing path works without classical (RSA/EC) keys.
 * </p>
 *
 * @since 1.0
 */
final class PqcCertificateIssuanceTest {

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
            "RSA,RSA,RSA_PKCS1_SHA256", "EC,ECDSA,ECDSA_SHA256",
            "ML-DSA-44,ML-DSA,ML_DSA_44_SIGNATURE", "ML-DSA-65,ML-DSA,ML_DSA_65_SIGNATURE",
            "ML-DSA-87,ML-DSA,ML_DSA_87_SIGNATURE", "SLH-DSA-SHA2-128F,SLH-DSA,SLH_DSA_SHA2_128F_SIGNATURE" })
    void persistedClassicalAndPqcRootsVerifyAfterRestart(String jca, String family, String identity,
            @TempDir Path root) throws Exception {
        zeroecho.core.spec.AlgorithmIdentity algorithm = (zeroecho.core.spec.AlgorithmIdentity)
                BootstrapAlgorithmIdentities.class.getField(identity).get(null);
        HybridIssuanceFixture fixture = new HybridIssuanceFixture(root, jca, family, algorithm.canonicalForm(),
                zeroecho.pki.api.hybrid.HybridCertificateMode.None.INSTANCE);
        zeroecho.pki.api.PkiId credential;
        try (PkiSession session = fixture.open()) {
            credential = fixture.current(fixture.create(session));
            fixture.verifyRoot(credential, fixture.rootKey);
        }
        {
            PkiSession session = fixture.open();
            try (session) {
     fixture.verifyRoot(credential, fixture.rootKey);
            }
        }
    }

    private static final FormatId X509 = new FormatId("x509");
    private static final String ML_DSA_65_ALGORITHM =
            BootstrapAlgorithmIdentities.ML_DSA_65_SIGNATURE.canonicalForm();
    private static final String PROFILE_ID = "pqc-root";
    private static final KeyRef ROOT_KEY = new KeyRef("zeroecho-lib:root.prv");
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-01T12:00:00Z"), ZoneOffset.UTC);

    @BeforeAll
    static void registerBouncyCastle() {
        BouncyCastleActivator.init();
    }

    @Test
    void mlDsa65AlgorithmIsAvailableInSession() {
        assertTrue(new ZeroEchoSession().available().contains("ML-DSA"),
                "ML-DSA must appear in the ZeroEchoSession algorithm catalog");
    }

    @Test
    void mlDsa65SignatureIdentityHasCorrectCanonicalForm() {
        String canonical = ML_DSA_65_ALGORITHM;
        assertTrue(canonical.contains("ml-dsa-65"),
                "ML-DSA-65 signature canonical form must contain 'ml-dsa-65', got: " + canonical);
    }

    /**
     * Verifies synchronous completion through the configured local PKI session.
     */
    @Test
    void mlDsa65RootCaCreationIsAccepted(@TempDir Path root) throws Exception {
        Path keyring = createMlDsa65Keyring(root);
        LocalSigningResult result;
        try (PkiSession session = openSession(root, keyring)) {
            LocalSigningExecutor executor = session.localSigning().orElseThrow();
            result = executor.execute(
                    new PkiSigningOperation.CreateAuthority(
                            X509, new SubjectRef("CN=PQC Root CA,C=CZ"), PROFILE_ID, ROOT_KEY),
                    CancellationSignal.NONE);
        }
        org.junit.jupiter.api.Assertions.assertInstanceOf(LocalSigningResult.Completed.class, result,
                () -> result instanceof LocalSigningResult.Failed failed ? failed.failure().code() : "Unexpected result");
    }

    private static Path createMlDsa65Keyring(Path root) throws Exception {
        Path keyring = root.resolve("keys.bin");
        KeyPair pair = new ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("ML-DSA",
                MldsaKeyGenSpec.of("BC", MldsaKeyGenSpec.ParameterSet.ML_DSA_65, MldsaKeyGenSpec.PreHash.NONE));
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keys = KeyringStore.create(keyring, password)) {
            keys.putPrivate("root.prv", "ML-DSA", pair.getPrivate());
            keys.putPublic("root.pub", "ML-DSA", pair.getPublic());
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
                "pqc-test-operator",
                Optional.of(signing),
                List.of(),
                List.of());

        return DefaultPkiSession.openLocal(configuration,
                PkiSessionRuntimeDependencies.withKeyringUnlockProvider(TestKeyringUnlocks.provider()),
                CLOCK,
                new PqcBootstrap(root));
    }


    private static CertificateProfileDefinition pqcRootCaProfile() {
        return new CertificateProfileDefinition(
                CertificateProfileKind.ROOT_CA,
                PROFILE_ID,
                1,
                X509,
                "PQC Root CA (ML-DSA-65)",
                Duration.ofDays(3650),
                new SubjectPolicy(false, List.of(
                        new SubjectRdnRule(SubjectRdnType.COMMON_NAME, 1, 1, 128, Optional.empty(), true),
                        new SubjectRdnRule(SubjectRdnType.COUNTRY_NAME, 1, 1, 2, Optional.empty(), true))),
                new CaCertificatePolicy(true, 2, true,
                        Set.of(CaKeyUsage.KEY_CERT_SIGN, CaKeyUsage.CRL_SIGN),
                        Set.of("ML-DSA")),
                X509AlgorithmBindingPolicy.standardOnly());
    }

    /** Minimal bootstrap that installs the PQC profile on first store open. */
    private static final class PqcBootstrap implements DefaultPkiSession.Bootstrap {
        private final Path root;

        PqcBootstrap(Path root) {
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
