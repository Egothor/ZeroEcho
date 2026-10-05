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

/** Real filesystem/keyring fixture with a clock deliberately unrelated to wall time. */
final class HybridIssuanceFixture implements DefaultPkiSession.Bootstrap {
    static final FormatId X509 = new FormatId("x509");
    static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-01T12:00:00Z"), ZoneOffset.UTC);
    final Path root;
    final Path keyring;
    final String family;
    final String signature;
    final HybridCertificateMode mode;
    final KeyPair rootKey;
    final KeyPair rotatedKey;
    final KeyPair childKey;
    final KeyPair altKey;
    PkiStore store;
    String alternativeFault;

    HybridIssuanceFixture(Path root, String jcaAlgorithm, String family, String signature,
            HybridCertificateMode mode) throws Exception {
        BouncyCastleActivator.init();
        this.root = root;
        this.family = family;
        this.signature = signature;
        this.mode = mode;
        keyring = root.resolve("keys.bin");
        rootKey = pair(jcaAlgorithm);
        rotatedKey = pair(jcaAlgorithm);
        childKey = pair(jcaAlgorithm);
        altKey = pair("ML-DSA-65");
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keys = KeyringStore.create(keyring, password)) {
            put(keys, "root", family, rootKey);
            put(keys, "rotated", family, rotatedKey);
            put(keys, "child", family, childKey);
            put(keys, "alt", "ML-DSA", altKey);
            put(keys, "other-alt", "ML-DSA", pair("ML-DSA-65"));
        }
    }

    static KeyPair pair(String algorithm) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, "BC");
        if (algorithm.equals("EC")) { generator.initialize(new ECGenParameterSpec("secp256r1")); }
        if (algorithm.equals("RSA")) { generator.initialize(2048); }
        return generator.generateKeyPair();
    }

    private static void put(KeyringStore store, String name, String algorithm, KeyPair pair) throws Exception {
        store.putPrivate(name + ".prv", algorithm, pair.getPrivate());
        store.putPublic(name + ".pub", algorithm, pair.getPublic());
    }

    static KeyRef key(String name) { return new KeyRef("zeroecho-lib:" + name + ".prv"); }

    PkiSession open() {
        LocalSigningConfiguration signing = new LocalSigningConfiguration(new ProviderConfig("zeroecho-lib",
                Map.of("keyringPath", keyring.toString())), signature, Duration.ofMinutes(5), Optional.empty(),
                Duration.ofSeconds(10), Duration.ofSeconds(5), OptionalLong.empty());
        return DefaultPkiSession.openLocal(new LocalPkiSessionConfiguration(new ProviderConfig("fs",
                Map.of("root", root.resolve("store").toString())), new ProviderConfig("memory", Map.of()),
                "hybrid-test", Optional.of(signing), List.of(), List.of()),
                PkiSessionRuntimeDependencies.withKeyringUnlockProvider(TestKeyringUnlocks.provider()), CLOCK, this);
    }

    LocalSigningResult.Completed execute(PkiSession session, PkiSigningOperation operation) {
        LocalSigningResult result = session.localSigning().orElseThrow().execute(operation, CancellationSignal.NONE);
        return assertInstanceOf(LocalSigningResult.Completed.class, result,
                () -> result instanceof LocalSigningResult.Failed failed ? failed.failure().code()
                        + failed.receipt().flatMap(receipt -> store.getSignWorkflow(receipt.operationId()))
                                .map(workflow -> ": " + workflow.state() + "/" + workflow.stage() + "/"
                                        + workflow.detailCode() + "/" + workflow.reconciliationFailureClass()).orElse("")
                        : "Unexpected result");
    }

    PkiId create(PkiSession session) {
        execute(session, new PkiSigningOperation.CreateAuthority(X509, new SubjectRef("CN=Matrix Root,C=CZ"),
                "matrix-root", key("root")));
        return store.listCas().getFirst().caId();
    }

    PkiId current(PkiId ca) {
        return store.getIssuerGeneration(store.getCa(ca).orElseThrow().currentIssuanceIssuerId()).orElseThrow().credentialId();
    }

    X509Certificate certificate(PkiId id) throws Exception {
        Credential credential = store.getCredential(id).orElseThrow();
        try (RepeatableContent content = store.stagedContent().openContent(credential.content());
                InputStream input = content.openStream()) {
            byte[] der = input.readAllBytes();
            return (X509Certificate) CertificateFactory.getInstance("X.509", "BC")
                    .generateCertificate(new ByteArrayInputStream(der));
        }
    }

    void verifyRoot(PkiId id, KeyPair expected) throws Exception {
        X509Certificate certificate = certificate(id);
        assertTrue(java.util.Arrays.equals(expected.getPublic().getEncoded(), certificate.getPublicKey().getEncoded()));
        certificate.verify(expected.getPublic(), "BC");
        CaProfileBinding binding = assertInstanceOf(CaProfileBinding.class, store.getCredential(id).orElseThrow().profileBinding());
        assertEquals(mode, store.getProfileVersion(binding.reference().profileId(), binding.reference().profileVersion())
                .orElseThrow().definition().hybridMode());
        if (mode instanceof HybridCertificateMode.AltSignature) {
            assertTrue(Pkix.verifyAlternativeSignature(certificate, altKey.getPublic()));
            assertTrue(java.util.Arrays.equals(altKey.getPublic().getEncoded(), AltSignatureExtensions.requiredValue(
                    certificate, AltSignatureExtensions.OID_SUBJECT_ALT_PUBLIC_KEY_INFO)));
        } else {
            assertNull(certificate.getExtensionValue(AltSignatureExtensions.OID_SUBJECT_ALT_PUBLIC_KEY_INFO));
            assertNull(certificate.getExtensionValue(AltSignatureExtensions.OID_ALT_SIGNATURE_ALGORITHM));
            assertNull(certificate.getExtensionValue(AltSignatureExtensions.OID_ALT_SIGNATURE_VALUE));
        }
    }

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
        LocalSigningResult.Completed completed = execute(session,
                new PkiSigningOperation.IssueCredential(issuer, request, "matrix-leaf"));
        return new PkiId(((PkiOperationValue.Text) completed.result().fields().get("credentialId")).value());
    }

    void verifyCrl(PkiId ca, KeyPair issuer) throws Exception {
        zeroecho.pki.api.status.StatusObject status = store.listStatusObjects(ca).getFirst();
        try (RepeatableContent content = store.stagedContent().openContent(status.content());
                InputStream input = content.openStream()) {
            java.security.cert.X509CRL crl = (java.security.cert.X509CRL) CertificateFactory.getInstance("X.509", "BC")
                    .generateCRL(input);
            crl.verify(issuer.getPublic(), "BC");
            assertNull(crl.getExtensionValue(AltSignatureExtensions.OID_ALT_SIGNATURE_VALUE));
        }
    }

    CertificateProfileDefinition profile(String id, long version, CertificateProfileKind kind, HybridCertificateMode selected) {
        return new CertificateProfileDefinition(kind, id, version, X509, "Hybrid lifecycle matrix", Duration.ofDays(365),
                IssuanceApprovalRequirement.NONE, new SubjectPolicy(false, List.of(
                        new SubjectRdnRule(SubjectRdnType.COMMON_NAME, 1, 1, 128, Optional.empty(), true),
                        new SubjectRdnRule(SubjectRdnType.COUNTRY_NAME, 1, 1, 2, Optional.empty(), true))),
                new CaCertificatePolicy(true, kind == CertificateProfileKind.ROOT_CA ? 2 : 1, true,
                        Set.of(CaKeyUsage.KEY_CERT_SIGN, CaKeyUsage.CRL_SIGN), Set.of(family)),
                X509AlgorithmBindingPolicy.standardOnly(), Optional.empty(), selected);
    }

    @Override public void validateStore(ProviderConfig configuration) { PkiBootstrap.validateStoreConfiguration(configuration); }
    @Override public void validateAudit(ProviderConfig configuration) { PkiBootstrap.validateAuditConfiguration(configuration); }
    @Override public PkiStore openStore(ProviderConfig configuration) {
        return openStore(configuration, new PkiStoreRuntimeDependencies(CLOCK));
    }
    @Override public PkiStore openStore(ProviderConfig configuration, PkiStoreRuntimeDependencies dependencies) {
        store = PkiBootstrap.openStore(configuration, dependencies);
        if (store.getActiveProfileRef("matrix-root").isEmpty()) {
            try {
                RootCreationFixture.install(store, profile("matrix-root", 1, CertificateProfileKind.ROOT_CA, mode));
                HybridCertificateMode descendant = mode instanceof HybridCertificateMode.AltSignature
                        ? HybridCertificateMode.None.INSTANCE : mode;
                RootCreationFixture.install(store, profile("matrix-intermediate", 1,
                        CertificateProfileKind.INTERMEDIATE_CA, descendant));
            } catch (Exception failure) { throw new AssertionError("Profile fixture failed", failure); }
        }
        return store;
    }
    @Override public AuditSink openAudit(ProviderConfig configuration) { return event -> { }; }
    @Override public PkiBootstrap.SigningComposition openSigningComposition(ProviderConfig configuration,
            SigningProviderRuntimeDependencies dependencies) {
        PkiBootstrap.SigningComposition real = PkiBootstrap.openConfiguredSigningComposition(configuration, dependencies);
        if (alternativeFault == null) { return real; }
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

    static HybridCertificateMode alternative() {
        return new HybridCertificateMode.AltSignature(BootstrapAlgorithmIdentities.ML_DSA_65_SIGNATURE.canonicalForm(),
                key("alt").value());
    }
}
