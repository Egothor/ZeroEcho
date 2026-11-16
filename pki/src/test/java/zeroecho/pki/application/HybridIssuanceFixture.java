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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
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
import zeroecho.pki.impl.hybrid.AltSignatureExtensions;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.spi.crypto.SigningProviderRuntimeDependencies;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.PkiStoreRuntimeDependencies;
import zeroecho.pki.testkit.RootCreationFixture;
import zeroecho.pkix.Pkix;
import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * Real filesystem/keyring fixture with a clock deliberately unrelated to wall time.
 */
final class HybridIssuanceFixture implements DefaultPkiSession.Bootstrap {
    /**
     * Stable X.509 format identifier used by the hybrid fixture.
     */
    static final FormatId X509 = new FormatId("x509");
    /**
     * Fixed authoritative clock used to make fixture timestamps deterministic.
     */
    static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-01T12:00:00Z"), ZoneOffset.UTC);
    /**
     * Filesystem root retaining this fixture's keyring and PKI store.
     */
    final Path root;
    /**
     * Path of the encrypted fixture keyring.
     */
    final Path keyring;
    /**
     * Canonical algorithm family used for the root keys.
     */
    final String family;
    /**
     * Configured signature identity used by the local signing session.
     */
    final String signature;
    /**
     * Selected classical/alternative certificate-signature profile.
     */
    final HybridCertificateMode mode;
    /**
     * Primary root key pair retained for issuance and independent verification.
     */
    final KeyPair rootKey;
    /**
     * Replacement primary root key pair used by rotation cases.
     */
    final KeyPair rotatedKey;
    /**
     * Child authority key pair used by issuance and proof cases.
     */
    final KeyPair childKey;
    /**
     * Alternative-signature key pair used by the hybrid root.
     */
    final KeyPair altKey;
    /**
     * Replacement alternative-signature key pair used by hybrid rotation cases.
     */
    final KeyPair rotatedAltKey;
    /**
     * Clock supplied to newly opened fixture sessions; defaults to the fixed fixture clock.
     */
    Clock clock = CLOCK;
    /**
     * Store retained by the fixture for persisted-state assertions.
     */
    PkiStore store;
    /**
     * Store-opening function that tests may replace before creating the session.
     */
    java.util.function.BiFunction<ProviderConfig, PkiStoreRuntimeDependencies, PkiStore> storeFactory = PkiBootstrap::openStore;
    /**
     * Named alternative-signature failure injected by the fixture.
     */
    String alternativeFault;
    /**
     * Wrapper applied to the fixture store to observe or reject selected operations.
     */
    java.util.function.UnaryOperator<PkiStore> storeDecorator = java.util.function.UnaryOperator.identity();
    /**
     * Wrapper applied to the fixture signing provider before session composition.
     */
    java.util.function.UnaryOperator<zeroecho.pki.spi.crypto.SigningProvider> signingDecorator = java.util.function.UnaryOperator.identity();

    /**
     * Creates the encrypted-keyring fixture with real primary, replacement, child, and alternative keys.
     *
     * @param root filesystem root retaining the test store and keyring artifacts
     * @param jcaAlgorithm JCA algorithm selected for the primary root and replacement keys
     * @param family canonical algorithm-family identifier used when persisting primary keys
     * @param signature canonical signature algorithm identity configured for the fixture session
     * @param mode selected hybrid certificate-signature policy
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    HybridIssuanceFixture(Path root, String jcaAlgorithm, String family, String signature,
            HybridCertificateMode mode) throws Exception {
        this(root, jcaAlgorithm, family, signature, mode, jcaAlgorithm, "ML-DSA-65");
    }

    /**
     * Creates the encrypted-keyring fixture with real primary, replacement, child, and alternative keys.
     *
     * @param root filesystem root retaining the test store and keyring artifacts
     * @param jcaAlgorithm JCA algorithm selected for the primary root and replacement keys
     * @param family canonical algorithm-family identifier used when persisting primary keys
     * @param signature canonical signature algorithm identity configured for the fixture session
     * @param mode selected hybrid certificate-signature policy
     * @param childAlgorithm JCA algorithm selected for the child key pair
     * @param alternativeAlgorithm JCA algorithm selected for alternative-signature key pairs
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    HybridIssuanceFixture(Path root, String jcaAlgorithm, String family, String signature,
            HybridCertificateMode mode, String childAlgorithm, String alternativeAlgorithm) throws Exception {
        BouncyCastleActivator.init();
        this.root = root;
        this.family = family;
        this.signature = signature;
        this.mode = mode;
        keyring = root.resolve("keys.bin");
        rootKey = pair(jcaAlgorithm);
        rotatedKey = pair(jcaAlgorithm);
        childKey = pair(childAlgorithm);
        altKey = pair(alternativeAlgorithm);
        rotatedAltKey = pair(alternativeAlgorithm);
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keys = KeyringStore.create(keyring, password)) {
            put(keys, "root", family, rootKey);
            put(keys, "rotated", family, rotatedKey);
            put(keys, "child", familyOf(childAlgorithm), childKey);
            put(keys, "alt", "ML-DSA", altKey);
            put(keys, "rotated-alt", "ML-DSA", rotatedAltKey);
            put(keys, "other-alt", "ML-DSA", pair(alternativeAlgorithm));
        }
    }

    /**
     * Generates a real Bouncy Castle key pair using the selected fixture algorithm.
     *
     * @param algorithm algorithm identifier selected by this cryptographic fixture
     * @return newly generated key pair
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    static KeyPair pair(String algorithm) throws Exception {
        String jca = algorithm.equals("EC384") ? "EC" : algorithm.equals("RSA4096") ? "RSA" : algorithm;
        KeyPairGenerator generator = KeyPairGenerator.getInstance(jca, "BC");
        if (jca.equals("EC")) { generator.initialize(new ECGenParameterSpec(algorithm.equals("EC384") ? "secp384r1" : "secp256r1")); }
        if (jca.equals("RSA")) { generator.initialize(algorithm.equals("RSA4096") ? 4096 : 2048); }
        return generator.generateKeyPair();
    }

    private static String familyOf(String algorithm) {
        if (algorithm.startsWith("EC")) return "ECDSA";
        if (algorithm.startsWith("RSA")) return "RSA";
        if (algorithm.startsWith("ML-DSA")) return "ML-DSA";
        if (algorithm.startsWith("SLH-DSA")) return "SLH-DSA";
        return algorithm;
    }

    private static void put(KeyringStore store, String name, String algorithm, KeyPair pair) throws Exception {
        store.putPrivate(name + ".prv", algorithm, pair.getPrivate());
        store.putPublic(name + ".pub", algorithm, pair.getPublic());
    }

    /**
     * Maps a fixture alias to the private-key reference used by the local signing provider.
     *
     * @param name alias of the private key installed in the fixture keyring
     * @return private-key reference with the fixture provider prefix
     */
    static KeyRef key(String name) { return new KeyRef("zeroecho-lib:" + name + ".prv"); }

    /**
     * Opens an owned PKI session against the fixture store and encrypted signing keyring.
     *
     * @return open session that the caller must close
     */
    PkiSession open() {
        LocalSigningConfiguration signing = new LocalSigningConfiguration(new ProviderConfig("zeroecho-lib",
                Map.of("keyringPath", keyring.toString())), signature, Duration.ofMinutes(5), Optional.empty(),
                Duration.ofSeconds(10), Duration.ofSeconds(5), OptionalLong.empty());
        return DefaultPkiSession.openLocal(new LocalPkiSessionConfiguration(new ProviderConfig("fs",
                Map.of("root", root.resolve("store").toString())), new ProviderConfig("memory", Map.of()),
                "hybrid-test", Optional.of(signing), List.of(), List.of()),
                PkiSessionRuntimeDependencies.withKeyringUnlockProvider(TestKeyringUnlocks.provider()), clock, this);
    }

    /**
     * Executes local signing and requires a completed outcome.
     *
     * @param session borrowed open PKI session used to execute the fixture operation
     * @param operation retained signing operation or typed command being exercised
     * @return completed signing result; any other outcome fails the fixture assertion
     * @throws AssertionError if the operation did not complete successfully
     */
    LocalSigningResult.Completed execute(PkiSession session, PkiSigningOperation operation) {
        LocalSigningResult result = session.localSigning().orElseThrow().execute(operation, CancellationSignal.NONE);
        return assertInstanceOf(LocalSigningResult.Completed.class, result, () -> failureDescription(result));
    }

    /**
     * Collects retained workflow and recovery diagnostics for a failed fixture operation.
     *
     * @param result signing outcome inspected for the fixture assertion or diagnostic
     * @return fixture failure description, including available retained-state context
     */
    String failureDescription(LocalSigningResult result) {
        String description = result instanceof LocalSigningResult.Failed failed
                ? failed.failure().code() : "Unexpected result: " + result.getClass().getName();
        if (store instanceof zeroecho.pki.impl.fs.FilesystemPkiStore filesystem) {
            Throwable original = zeroecho.pki.impl.fs.FilesystemPkiStoreTestAccess.firstRecoveryFailure(filesystem);
            if (original != null) {
                original.printStackTrace(System.err);
                description += "; original ledger failure: " + original;
            }
        }
        if (result instanceof LocalSigningResult.Failed failed) {
            try {
                description += failed.receipt().flatMap(receipt -> store.getSignWorkflow(receipt.operationId()))
                        .map(workflow -> ": " + workflow.state() + "/" + workflow.stage() + "/"
                                + workflow.detailCode() + "/" + workflow.reconciliationFailureClass()).orElse("");
            } catch (RuntimeException fenced) {
                description += "; workflow unavailable: " + fenced.getClass().getSimpleName();
            }
        }
        return description;
    }

    /**
     * Creates the fixture root authority through the typed local signing path.
     *
     * @param session borrowed open PKI session used to execute the fixture operation
     * @return logical identity of the newly created root authority
     */
    PkiId create(PkiSession session) {
        execute(session, new PkiSigningOperation.CreateAuthority(X509, new SubjectRef("CN=Matrix Root,C=CZ"),
                "matrix-root", key("root")));
        return store.listCas().getFirst().caId();
    }

    /**
     * Resolves the selected current issuer generation to its credential identity.
     *
     * @param ca logical authority identifier whose current credential or CRL is inspected
     * @return current issuance credential identifier
     */
    PkiId current(PkiId ca) {
        return store.getIssuerGeneration(store.getCa(ca).orElseThrow().currentIssuanceIssuerId()).orElseThrow().credentialId();
    }

    /**
     * Reads and parses the exact retained fixture certificate.
     *
     * @param id profile, attribute, or credential identifier selected by the fixture
     * @return parsed X.509 certificate
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    X509Certificate certificate(PkiId id) throws Exception {
        Credential credential = store.getCredential(id).orElseThrow();
        try (RepeatableContent content = store.stagedContent().openContent(credential.content());
                InputStream input = content.openStream()) {
            byte[] der = input.readAllBytes();
            return (X509Certificate) CertificateFactory.getInstance("X.509", "BC")
                    .generateCertificate(new ByteArrayInputStream(der));
        }
    }

    /**
     * Checks primary/alternative signatures and retained profile mode of the fixture root certificate.
     *
     * @param id profile, attribute, or credential identifier selected by the fixture
     * @param expected key pair whose public component must verify the fixture certificate
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    void verifyRoot(PkiId id, KeyPair expected) throws Exception {
        verifyRoot(id, expected, mode);
    }

    /**
     * Checks primary/alternative signatures and retained profile mode of the fixture root certificate.
     *
     * @param id profile, attribute, or credential identifier selected by the fixture
     * @param expected key pair whose public component must verify the fixture certificate
     * @param expectedProfileMode hybrid signature mode required in the retained profile evidence
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    void verifyRoot(PkiId id, KeyPair expected, HybridCertificateMode expectedProfileMode) throws Exception {
        X509Certificate certificate = certificate(id);
        assertTrue(java.util.Arrays.equals(expected.getPublic().getEncoded(), certificate.getPublicKey().getEncoded()));
        certificate.verify(expected.getPublic(), "BC");
        CaProfileBinding binding = assertInstanceOf(CaProfileBinding.class, store.getCredential(id).orElseThrow().profileBinding());
        assertEquals(expectedProfileMode, store.getProfileVersion(binding.reference().profileId(), binding.reference().profileVersion())
                .orElseThrow().definition().hybridMode());
        if (mode instanceof HybridCertificateMode.AltSignature) {
            assertTrue(Pkix.verifyAlternativeSignatureCor3(certificate, altKey.getPublic()));
            assertTrue(java.util.Arrays.equals(altKey.getPublic().getEncoded(), AltSignatureExtensions.requiredValue(
                    certificate, AltSignatureExtensions.OID_SUBJECT_ALT_PUBLIC_KEY_INFO)));
        } else {
            assertNull(certificate.getExtensionValue(AltSignatureExtensions.OID_SUBJECT_ALT_PUBLIC_KEY_INFO));
            assertNull(certificate.getExtensionValue(AltSignatureExtensions.OID_ALT_SIGNATURE_ALGORITHM));
            assertNull(certificate.getExtensionValue(AltSignatureExtensions.OID_ALT_SIGNATURE_VALUE));
        }
    }

    /**
     * Installs a compatible leaf profile, stores a real CSR, and issues through the selected authority.
     *
     * @param session borrowed open PKI session used to execute the fixture operation
     * @param issuer issuer authority, key pair, or credential selected by the fixture
     * @return issued leaf credential identifier
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    PkiId issueLeaf(PkiSession session, PkiId issuer) throws Exception {
        byte[] document = new String(zeroecho.pki.testkit.H7ProfileDocuments.noSanOrEkuProfile(),
                java.nio.charset.StandardCharsets.UTF_8).replace("h7-no-san-eku", "matrix-leaf")
                .replace("PT8760H", "PT24H").getBytes(java.nio.charset.StandardCharsets.UTF_8);
        zeroecho.pki.api.profile.CertificateProfileDefinition base =
                zeroecho.pki.api.profile.CertificateProfileDocumentCodec.parse(document);
        HybridCertificateMode descendant = mode instanceof HybridCertificateMode.AltSignature
                ? HybridCertificateMode.None.INSTANCE : mode;
        RootCreationFixture.install(store, new CertificateProfileDefinition(base.certificateType(), base.profileId(),
                base.profileVersion(), base.formatId(), base.displayName(), base.maximumValidity(), base.approvalRequirement(),
                base.subjectPolicy(), base.certificatePolicy(), base.algorithmBindingPolicy(), base.confirmationPolicy(), descendant));
        KeyPair leaf = pair("RSA");
        byte[] csr = Pkix.certificationRequestBuilder().subject(new javax.security.auth.x500.X500Principal("CN=Matrix Leaf"))
                .publicKey(leaf.getPublic()).build(Pkix.signer(leaf.getPrivate(),
                        zeroecho.pkix.AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11"))).encoded();
        PkiId request = session.requests().orElseThrow().store(session.requests().orElseThrow().parse(
                new zeroecho.pki.api.request.CertificationRequest(X509,
                        new zeroecho.pki.api.EncodedObject(zeroecho.pki.api.Encoding.DER, csr))),
                zeroecho.pki.api.request.RequestStorePolicy.STORE_ALWAYS);
        var operation = new PkiSigningOperation.IssueCredential(issuer, request, "matrix-leaf");
        session.signingCommands().orElseThrow().validate(operation, RootCreationFixture.ACCESS, Optional.empty(), CancellationSignal.NONE);
        LocalSigningResult.Completed completed = execute(session, operation);
        return new PkiId(((PkiOperationValue.Text) completed.result().fields().get("credentialId")).value());
    }

    /**
     * Verifies the fixture authority's retained CRL, including its alternative signature when configured.
     *
     * @param ca logical authority identifier whose current credential or CRL is inspected
     * @param issuer issuer authority, key pair, or credential selected by the fixture
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    void verifyCrl(PkiId ca, KeyPair issuer) throws Exception {
        zeroecho.pki.api.status.StatusObject status = store.listStatusObjects(ca).getFirst();
        try (RepeatableContent content = store.stagedContent().openContent(status.content());
                InputStream input = content.openStream()) {
            java.security.cert.X509CRL crl = (java.security.cert.X509CRL) CertificateFactory.getInstance("X.509", "BC")
                    .generateCRL(input);
            crl.verify(issuer.getPublic(), "BC");
            if (mode instanceof HybridCertificateMode.AltSignature) {
                var holder = new org.bouncycastle.cert.X509CRLHolder(crl.getEncoded());
                assertTrue(holder.isAlternativeSignatureValid(new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
                        .setProvider("BC").build(altKey.getPublic())));
            } else {
                assertNull(crl.getExtensionValue(AltSignatureExtensions.OID_ALT_SIGNATURE_VALUE));
            }
        }
    }

    /**
     * Builds the selected versioned root or intermediate profile for the hybrid fixture.
     *
     * @param id profile, attribute, or credential identifier selected by the fixture
     * @param version certificate-profile version to construct
     * @param kind certificate-profile kind selected for this fixture
     * @param selected hybrid signature mode stored in the fixture profile
     * @return profile definition carrying the selected signature policy and subject-key constraints
     */
    CertificateProfileDefinition profile(String id, long version, CertificateProfileKind kind, HybridCertificateMode selected) {
        return profile(id, version, kind, selected, Set.of(family));
    }

    /**
     * Builds the selected versioned root or intermediate profile for the hybrid fixture.
     *
     * @param id profile, attribute, or credential identifier selected by the fixture
     * @param version certificate-profile version to construct
     * @param kind certificate-profile kind selected for this fixture
     * @param selected hybrid signature mode stored in the fixture profile
     * @param subjectAlgorithms accepted subject-key algorithm identifiers
     * @return profile definition carrying the selected signature policy and subject-key constraints
     */
    CertificateProfileDefinition profile(String id, long version, CertificateProfileKind kind, HybridCertificateMode selected,
            Set<String> subjectAlgorithms) {
        return new CertificateProfileDefinition(kind, id, version, X509, "Hybrid lifecycle matrix", Duration.ofDays(365),
                IssuanceApprovalRequirement.NONE, new SubjectPolicy(false, List.of(
                        new SubjectRdnRule(SubjectRdnType.COMMON_NAME, 1, 1, 128, Optional.empty(), true),
                        new SubjectRdnRule(SubjectRdnType.COUNTRY_NAME, 1, 1, 2, Optional.empty(), true))),
                new CaCertificatePolicy(true, kind == CertificateProfileKind.ROOT_CA ? 2 : 1, true,
                        Set.of(CaKeyUsage.KEY_CERT_SIGN, CaKeyUsage.CRL_SIGN), subjectAlgorithms),
                X509AlgorithmBindingPolicy.standardOnly(), Optional.empty(), selected);
    }

    /**
     * {@inheritDoc}
     */
    @Override public void validateStore(ProviderConfig configuration) { PkiBootstrap.validateStoreConfiguration(configuration); }
    /**
     * {@inheritDoc}
     */
    @Override public void validateAudit(ProviderConfig configuration) { PkiBootstrap.validateAuditConfiguration(configuration); }
    /**
     * {@inheritDoc}
     */
    @Override public PkiStore openStore(ProviderConfig configuration) {
        return openStore(configuration, new PkiStoreRuntimeDependencies(clock));
    }
    /**
     * {@inheritDoc}
     */
    @Override public PkiStore openStore(ProviderConfig configuration, PkiStoreRuntimeDependencies dependencies) {
        store = storeFactory.apply(configuration, dependencies);
        if (store.getActiveProfileRef("matrix-root").isEmpty()) {
            try {
                RootCreationFixture.install(store, profile("matrix-root", 1, CertificateProfileKind.ROOT_CA, mode));
                HybridCertificateMode descendant = mode instanceof HybridCertificateMode.AltSignature
                        ? HybridCertificateMode.None.INSTANCE : mode;
                RootCreationFixture.install(store, profile("matrix-intermediate", 1,
                        CertificateProfileKind.INTERMEDIATE_CA, descendant));
            } catch (Exception failure) { throw new AssertionError("Profile fixture failed", failure); }
        }
        PkiStore diagnosed = (PkiStore) java.lang.reflect.Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] {PkiStore.class}, (proxy, method, arguments) -> {
                    try { return method.invoke(store, arguments); }
                    catch (java.lang.reflect.InvocationTargetException failure) {
                        if (method.getName().equals("putStatusObjectFromSigning")) {
                            System.err.println("Native test status publication failed at " + method.getName());
                            failure.getCause().printStackTrace(System.err);
                        }
                        throw failure.getCause();
                    }
                });
        return storeDecorator.apply(diagnosed);
    }
    /**
     * {@inheritDoc}
     */
    @Override public AuditSink openAudit(ProviderConfig configuration) { return event -> { }; }
    /**
     * {@inheritDoc}
     */
    @Override public PkiBootstrap.SigningComposition openSigningComposition(ProviderConfig configuration,
            SigningProviderRuntimeDependencies dependencies) {
        PkiBootstrap.SigningComposition real = PkiBootstrap.openConfiguredSigningComposition(configuration, dependencies);
        if (alternativeFault == null) { return new PkiBootstrap.SigningComposition(signingDecorator.apply(real.provider()), real.capabilities()); }
        zeroecho.pki.spi.crypto.SigningProvider wrapped = (zeroecho.pki.spi.crypto.SigningProvider)
                java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {
                        zeroecho.pki.spi.crypto.SigningProvider.class, zeroecho.pki.spi.crypto.PublicKeyInfoSource.class,
                        zeroecho.pki.spi.crypto.AltSigningCapability.class }, (proxy, method, args) -> {
                    try {
                        if (method.getName().equals("sign") && args.length == 3) {
                            if (alternativeFault.equals("empty")) { return new byte[0]; }
                            if (alternativeFault.equals("wrong-key")) {
                                return ((zeroecho.pki.spi.crypto.AltSigningCapability) real.provider())
                                        .sign(key("other-alt"), (String) args[1], (byte[]) args[2]);
                            }
                            byte[] signed = (byte[]) method.invoke(real.provider(), args);
                            signed[0] ^= 1;
                            return signed;
                        }
                        if (method.getName().equals("resolvePublicKeyInfo") && args[0].equals(key("alt"))) {
                            if (alternativeFault.equals("oversize-key")) {
                                return new zeroecho.pki.api.EncodedObject(zeroecho.pki.api.Encoding.DER, new byte[1_048_577]);
                            }
                            if (alternativeFault.equals("malformed-key")) {
                                return new zeroecho.pki.api.EncodedObject(zeroecho.pki.api.Encoding.DER, new byte[]{0x30, 0});
                            }
                        }
                        return method.invoke(real.provider(), args);
                    } catch (java.lang.reflect.InvocationTargetException failure) { throw failure.getCause(); }
                });
        return new PkiBootstrap.SigningComposition(wrapped, real.capabilities());
    }

    /**
     * Selects the fixture ML-DSA-65 alternative-signature identity and key reference.
     *
     * @return alternative-signature certificate mode bound to the fixture alternative key
     */
    static HybridCertificateMode alternative() {
        return new HybridCertificateMode.AltSignature(BootstrapAlgorithmIdentities.ML_DSA_65_SIGNATURE.canonicalForm(),
                key("alt").value());
    }
}
