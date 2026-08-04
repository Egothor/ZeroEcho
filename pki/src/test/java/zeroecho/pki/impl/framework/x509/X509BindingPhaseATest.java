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
package zeroecho.pki.impl.framework.x509;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.Security;
import java.security.PrivateKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.Test;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.alg.sphincsplus.SphincsPlusKeyGenSpec;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.issuance.VerificationPolicy;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.ProofOfPossessionStatus;
import zeroecho.pki.impl.framework.x509.bc.BcX509CertificationRequestParser;
import zeroecho.pki.impl.framework.x509.bc.BcX509ProofOfPossessionVerifier;
import zeroecho.pki.impl.framework.x509.bc.BcX509SignedObjectValidator;
import zeroecho.pki.impl.framework.x509.bc.BcX509PublicKeyAdapter;
import zeroecho.pki.testkit.TestX509AlgorithmBindingProvider;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.core.spi.AlgorithmExecutionCapabilityProvider;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;

/**
 * Phase A regression tests for immutable role-specific X.509 authority.
 */
public final class X509BindingPhaseATest {

    @Test
    void zeroEchoPrivateAssignmentsAreExactAndLocked() {
        System.out.println("zeroEchoPrivateAssignmentsAreExactAndLocked");
        List<X509AlgorithmBinding> bindings = ZeroEchoPrivateX509Bindings.descriptors();
        assertEquals(List.of("1.3.6.1.4.1.31424.1.1.1", "1.3.6.1.4.1.31424.1.1.2",
                "1.3.6.1.4.1.31424.1.1.3", "1.3.6.1.4.1.31424.1.1.4"),
                bindings.stream().map(X509AlgorithmBinding::oid).toList());
        assertEquals(4, bindings.stream().map(X509AlgorithmBinding::bindingId).distinct().count());
        assertThrows(UnsupportedOperationException.class, () -> bindings.add(bindings.get(0)));
        assertThrows(IllegalArgumentException.class,
                () -> ImmutableX509AlgorithmBindingRegistry.create(List.of(bindings.get(0), bindings.get(0))));
        System.out.println("...assignment-count=" + bindings.size());
        System.out.println("...ok");
    }

    @Test
    void productionSphincsPrivateBindingSignsAndVerifies() throws Exception {
        System.out.println("productionSphincsPrivateBindingSignsAndVerifies");
        Security.addProvider(new BouncyCastlePQCProvider());
        KeyPair keyPair = new ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("SPHINCS+",
                SphincsPlusKeyGenSpec.defaultSpec());
        BcX509VerificationExecutor verifier = new BcX509VerificationExecutor();
        X509AuthoritySnapshot authority = X509AuthoritySnapshot.compose(List.of(), List.of(verifier),
                List.of(X509AuthoritySnapshot.bindExecutor(BcX509VerificationExecutor.IMPLEMENTATION_ID,
                        AlgorithmExecutionCapability.Direction.VERIFY, verifier)), policy(true, "private-test-v1"));
        String signatureBinding = "zeroecho.private.sphincs-plus-default.certificate-signature.v1";
        String publicKeyBinding = "zeroecho.private.sphincs-plus-default.spki.v1";
        X509ExecutionPlan<BcX509VerificationExecutor> plan = authority.plan(
                BootstrapAlgorithmIdentities.SPHINCS_PLUS_SIGNATURE,
                BootstrapAlgorithmIdentities.SPHINCS_PLUS_PUBLIC_KEY,
                AlgorithmExecutionCapability.Direction.VERIFY, Optional.empty(), "explicit", signatureBinding,
                BcX509VerificationExecutor.class);
        SubjectPublicKeyInfo wrapped = new BcX509PublicKeyAdapter(authority.bindings()).wrap(
                keyPair.getPublic().getEncoded(), BootstrapAlgorithmIdentities.SPHINCS_PLUS_PUBLIC_KEY,
                publicKeyBinding);
        AlgorithmIdentifier identifier = BcX509AlgorithmAdapter.toBc(authority.bindings().resolve(signatureBinding,
                BootstrapAlgorithmIdentities.SPHINCS_PLUS_SIGNATURE, X509AlgorithmRole.SIGNATURE_ALGORITHM));
        byte[] payload = "ZeroEcho private X.509 binding".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SPHINCS+", new BouncyCastlePQCProvider());
        signer.initSign(keyPair.getPrivate());
        signer.update(payload);
        byte[] signature = signer.sign();
        try (RepeatableContent content = content(payload)) {
            assertTrue(verifier.verify(authority, plan, wrapped, identifier, content, signature));
        }

        AlgorithmIdentifier csrIdentifier = privateIdentifier(authority,
                "zeroecho.private.sphincs-plus-default.csr-signature.v1");
        PKCS10CertificationRequest csr = new PKCS10CertificationRequestBuilder(new X500Name("CN=Private Request"),
                wrapped).build(contentSigner(keyPair.getPrivate(), csrIdentifier));
        ParsedCertificationRequest parsed = new BcX509CertificationRequestParser().parse(new CertificationRequest(
                new FormatId("x509"), new EncodedObject(Encoding.DER, csr.getEncoded())));
        assertEquals(ProofOfPossessionStatus.VERIFIED,
                new BcX509ProofOfPossessionVerifier(authority, verifier)
                        .verify(parsed, new VerificationPolicy(true, Optional.empty())).status());

        Instant notBefore = Instant.parse("2026-08-04T00:00:00Z");
        X500Name issuer = new X500Name("CN=Private Root");
        X509CertificateHolder certificate = new X509v3CertificateBuilder(issuer, BigInteger.ONE,
                Date.from(notBefore), Date.from(notBefore.plusSeconds(3600)), issuer, wrapped)
                .build(contentSigner(keyPair.getPrivate(), identifier));
        try (RepeatableContent certificateContent = content(certificate.getEncoded())) {
            BcX509SignedObjectValidator.CertificateBindings validated = new BcX509SignedObjectValidator(authority)
                    .validateCertificate(certificateContent,
                            Optional.of(BootstrapAlgorithmIdentities.SPHINCS_PLUS_SIGNATURE),
                            zeroecho.core.io.CancellationSignal.NONE);
            assertEquals(BootstrapAlgorithmIdentities.SPHINCS_PLUS_PUBLIC_KEY, validated.subjectPublicKey());
        }
        try (RepeatableContent tbs = content(certificate.toASN1Structure().getTBSCertificate().getEncoded())) {
            assertTrue(verifier.verify(authority, plan, wrapped, identifier, tbs, certificate.getSignature()));
        }

        AlgorithmIdentifier crlIdentifier = privateIdentifier(authority,
                "zeroecho.private.sphincs-plus-default.crl-signature.v1");
        X509CRLHolder crl = new X509v2CRLBuilder(issuer, Date.from(notBefore))
                .setNextUpdate(Date.from(notBefore.plusSeconds(1800)))
                .build(contentSigner(keyPair.getPrivate(), crlIdentifier));
        X509ExecutionPlan<BcX509VerificationExecutor> crlPlan = authority.plan(
                BootstrapAlgorithmIdentities.SPHINCS_PLUS_SIGNATURE,
                BootstrapAlgorithmIdentities.SPHINCS_PLUS_PUBLIC_KEY,
                AlgorithmExecutionCapability.Direction.VERIFY, Optional.empty(), "explicit",
                "zeroecho.private.sphincs-plus-default.crl-signature.v1", BcX509VerificationExecutor.class);
        try (RepeatableContent tbs = content(crl.toASN1Structure().getTBSCertList().getEncoded())) {
            assertTrue(verifier.verify(authority, crlPlan, wrapped, crlIdentifier, tbs,
                    crl.toASN1Structure().getSignature().getOctets()));
        }
        assertThrows(IllegalArgumentException.class,
                () -> new BcX509AlgorithmAdapter(authority.bindings()).decode(
                        new AlgorithmIdentifier(identifier.getAlgorithm(), DERNull.INSTANCE),
                        X509AlgorithmRole.SIGNATURE_ALGORITHM));
        System.out.println("...oid=" + identifier.getAlgorithm().getId() + ", signature-bytes=" + signature.length);
        System.out.println("...ok");
    }

    @Test
    void deployerProviderBindingSignsAndVerifiesEndToEnd() throws Exception {
        System.out.println("deployerProviderBindingSignsAndVerifiesEndToEnd");
        TestX509AlgorithmBindingProvider deployer = new TestX509AlgorithmBindingProvider();
        X509BindingRuleProvider provider = new X509BindingRuleProvider() {
            @Override
            public List<X509BindingRule> rules() {
                return deployer.rules();
            }
        };
        BcX509VerificationExecutor verifier = new BcX509VerificationExecutor();
        X509AuthoritySnapshot authority = X509AuthoritySnapshot.compose(List.of(provider), List.of(verifier),
                List.of(X509AuthoritySnapshot.bindExecutor(BcX509VerificationExecutor.IMPLEMENTATION_ID,
                        AlgorithmExecutionCapability.Direction.VERIFY, verifier)), policy(true, "deployer-test-v1"));
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair pair = generator.generateKeyPair();
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());
        String bindingId = "test.ed25519.certificate.v1";
        AlgorithmIdentifier identifier = BcX509AlgorithmAdapter.toBc(authority.bindings().resolve(bindingId,
                BootstrapAlgorithmIdentities.ED25519_SIGNATURE, X509AlgorithmRole.SIGNATURE_ALGORITHM));
        X500Name name = new X500Name("CN=Deployer Binding");
        Instant start = Instant.parse("2026-08-04T00:00:00Z");
        X509CertificateHolder certificate = new X509v3CertificateBuilder(name, BigInteger.TWO, Date.from(start),
                Date.from(start.plusSeconds(3600)), name, spki)
                .build(contentSigner(pair.getPrivate(), identifier, "Ed25519"));
        X509ExecutionPlan<BcX509VerificationExecutor> plan = authority.plan(
                BootstrapAlgorithmIdentities.ED25519_SIGNATURE, BootstrapAlgorithmIdentities.ED25519_PUBLIC_KEY,
                AlgorithmExecutionCapability.Direction.VERIFY, Optional.empty(), "explicit", bindingId,
                BcX509VerificationExecutor.class);
        try (RepeatableContent tbs = content(certificate.toASN1Structure().getTBSCertificate().getEncoded())) {
            assertTrue(verifier.verify(authority, plan, spki, identifier, tbs, certificate.getSignature()));
        }
        System.out.println("...oid=" + identifier.getAlgorithm().getId());
        System.out.println("...ok");
    }

    @Test
    void bootstrapMatrixIsExactAndSymmetric() {
        System.out.println("bootstrapMatrixIsExactAndSymmetric");
        Map<AlgorithmIdentity, X509AlgorithmIdentifier> signatures = Map.ofEntries(
                Map.entry(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                        X509AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11")),
                Map.entry(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384,
                        X509AlgorithmIdentifier.derNull("1.2.840.113549.1.1.12")),
                Map.entry(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA512,
                        X509AlgorithmIdentifier.derNull("1.2.840.113549.1.1.13")),
                Map.entry(BootstrapAlgorithmIdentities.ECDSA_SHA256,
                        X509AlgorithmIdentifier.absent("1.2.840.10045.4.3.2")),
                Map.entry(BootstrapAlgorithmIdentities.ECDSA_SHA384,
                        X509AlgorithmIdentifier.absent("1.2.840.10045.4.3.3")),
                Map.entry(BootstrapAlgorithmIdentities.ECDSA_SHA512,
                        X509AlgorithmIdentifier.absent("1.2.840.10045.4.3.4")),
                Map.entry(BootstrapAlgorithmIdentities.ED25519_SIGNATURE,
                        X509AlgorithmIdentifier.absent("1.3.101.112")),
                Map.entry(BootstrapAlgorithmIdentities.ED448_SIGNATURE,
                        X509AlgorithmIdentifier.absent("1.3.101.113")));
        X509BindingCatalog catalog = StandardX509Bindings.catalog();
        for (Map.Entry<AlgorithmIdentity, X509AlgorithmIdentifier> entry : signatures.entrySet()) {
            assertEquals(entry.getValue(), catalog.resolve(entry.getKey(), X509AlgorithmRole.SIGNATURE_ALGORITHM));
            assertEquals(entry.getKey(),
                    catalog.reverse(entry.getValue(), X509AlgorithmRole.SIGNATURE_ALGORITHM));
        }
        assertEquals(BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY,
                catalog.reverse(X509AlgorithmIdentifier.derNull("1.2.840.113549.1.1.1"),
                        X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM));
        System.out.println("...signature-bindings=" + signatures.size());
        System.out.println("...ok");
    }

    @Test
    void parameterizedRsaPssRoundTripsAndRejectsWrongParameters() {
        System.out.println("parameterizedRsaPssRoundTripsAndRejectsWrongParameters");
        AlgorithmIdentity identity = BootstrapAlgorithmIdentities.rsaPss(BootstrapAlgorithmIdentities.SHA384,
                BootstrapAlgorithmIdentities.SHA512, 40);
        X509BindingCatalog catalog = StandardX509Bindings.catalog();
        X509AlgorithmIdentifier identifier = catalog.resolve(identity, X509AlgorithmRole.SIGNATURE_ALGORITHM);
        byte[] copy = identifier.parameters();
        copy[0] ^= 0x01;

        assertEquals("1.2.840.113549.1.1.10", identifier.oid());
        assertEquals(identity, catalog.reverse(identifier, X509AlgorithmRole.SIGNATURE_ALGORITHM));
        assertNotEquals(copy[0], identifier.parameters()[0]);
        assertThrows(IllegalArgumentException.class,
                () -> catalog.reverse(X509AlgorithmIdentifier.absent("1.2.840.113549.1.1.10"),
                        X509AlgorithmRole.SIGNATURE_ALGORITHM));
        byte[] trailing = java.util.Arrays.copyOf(identifier.parameters(), identifier.parameters().length + 1);
        assertThrows(IllegalArgumentException.class,
                () -> catalog.reverse(X509AlgorithmIdentifier.exact("1.2.840.113549.1.1.10", trailing),
                        X509AlgorithmRole.SIGNATURE_ALGORITHM));
        System.out.println("...pss-der-bytes=" + identifier.parameters().length);
        System.out.println("...ok");
    }

    @Test
    void ecdsaSignatureAndCurveResolveContextually() {
        System.out.println("ecdsaSignatureAndCurveResolveContextually");
        X509BindingCatalog catalog = StandardX509Bindings.catalog();
        AlgorithmIdentity signature = catalog.reverse(X509AlgorithmIdentifier.absent("1.2.840.10045.4.3.2"),
                X509AlgorithmRole.SIGNATURE_ALGORITHM);
        X509AlgorithmIdentifier spki = catalog.resolve(BootstrapAlgorithmIdentities.EC_P384_PUBLIC_KEY,
                X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        AlgorithmIdentity key = catalog.reverse(spki, X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        AlgorithmSuite suite = X509SuiteCompatibility.requireCompatible(signature, key);

        assertEquals(BootstrapAlgorithmIdentities.ECDSA_SHA256, suite.signature());
        assertEquals(BootstrapAlgorithmIdentities.EC_P384_PUBLIC_KEY, suite.publicKey());
        assertThrows(IllegalArgumentException.class,
                () -> X509SuiteCompatibility.requireCompatible(signature, BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY));
        System.out.println("...curve=" + key.parameters().canonicalForm());
        System.out.println("...ok");
    }

    @Test
    void defaultsAndCatalogConflictsAreImmutable() {
        System.out.println("defaultsAndCatalogConflictsAreImmutable");
        Map<String, AlgorithmSuite> before = X509BuiltInDefaults.snapshot();
        X509BindingRule collision = new TestCollisionRule();
        X509BindingCatalog extension = X509BindingCatalog.extension(List.of(collision));

        assertThrows(IllegalArgumentException.class,
                () -> StandardX509Bindings.catalog().merge(List.of(extension)));
        assertEquals(before, X509BuiltInDefaults.snapshot());
        assertEquals(BootstrapAlgorithmIdentities.PKI_SIGNATURE_DEFAULT_V1,
                X509BuiltInDefaults.resolve(X509BuiltInDefaults.PKI_SIGNATURE_DEFAULT_V1));
        assertThrows(IllegalArgumentException.class, () -> X509BuiltInDefaults.resolve("extension.default"));
        System.out.println("...defaults=" + before.size());
        System.out.println("...ok");
    }

    @Test
    void bcBoundaryPreservesExactParametersAndRejectsSha1() {
        System.out.println("bcBoundaryPreservesExactParametersAndRejectsSha1");
        BcX509AlgorithmAdapter adapter = new BcX509AlgorithmAdapter(StandardX509Bindings.catalog());
        AlgorithmIdentifier rsa = adapter.encode(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                X509AlgorithmRole.SIGNATURE_ALGORITHM);
        assertEquals(DERNull.INSTANCE, rsa.getParameters());
        assertEquals(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                adapter.decode(rsa, X509AlgorithmRole.SIGNATURE_ALGORITHM));
        assertThrows(IllegalArgumentException.class,
                () -> adapter.decode(new AlgorithmIdentifier(
                        new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.840.113549.1.1.5"), DERNull.INSTANCE),
                        X509AlgorithmRole.SIGNATURE_ALGORITHM));
        assertArrayEquals(new byte[] { 0x05, 0x00 },
                BcX509AlgorithmAdapter.fromBc(rsa).parameters());
        System.out.println("...oid=" + rsa.getAlgorithm().getId());
        System.out.println("...ok");
    }

    @Test
    void universalSnapshotComposesExtensionsAndRejectsCrossSnapshotUse() {
        System.out.println("universalSnapshotComposesExtensionsAndRejectsCrossSnapshotUse");
        AlgorithmIdentity digest = new AlgorithmIdentity(AlgorithmIdentity.Kind.DIGEST,
                new AlgorithmIdentity.Family("example", "digest-384"), AlgorithmIdentity.NoParameters.INSTANCE);
        AlgorithmIdentity pss = BootstrapAlgorithmIdentities.rsaPss(digest, digest, 40);
        AlgorithmIdentity curve = new AlgorithmIdentity(AlgorithmIdentity.Kind.PUBLIC_KEY,
                new AlgorithmIdentity.Family("zeroecho", "ec"),
                new AlgorithmIdentity.NamedParameters(new AlgorithmIdentity.Family("example", "curve-384")));
        X509BindingRuleProvider bindings = new X509BindingRuleProvider() {
            @Override
            public List<AlgorithmIdentity> identities() {
                return List.of(digest, pss, curve);
            }

            @Override
            public List<X509ComponentCatalog.Component> components() {
                return List.of(
                        new X509ComponentCatalog.Component("example.digest.384", X509ComponentCatalog.Kind.DIGEST,
                                digest, "1.3.6.1.4.1.55555.1", false),
                        new X509ComponentCatalog.Component("example.curve.384",
                                X509ComponentCatalog.Kind.NAMED_CURVE, curve, "1.3.6.1.4.1.55555.2", false));
            }
        };
        AlgorithmExecutionCapability capability = new AlgorithmExecutionCapability() {
            @Override
            public String implementationId() {
                return "example.synthetic";
            }

            @Override
            public String domainFingerprint() {
                return "example-pss-v1";
            }

            @Override
            public boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction direction) {
                return direction == Direction.SIGN && pss.equals(identity)
                        && BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY.equals(suite.publicKey());
            }
        };
        AlgorithmExecutionCapabilityProvider execution = () -> List.of(capability);
        X509AlgorithmResolver.Policy allow = policy(true, "example-policy:allow");
        X509AuthoritySnapshot first = X509AuthoritySnapshot.compose(List.of(bindings), List.of(execution), allow);
        X509AuthoritySnapshot equivalent = X509AuthoritySnapshot.compose(List.of(bindings), List.of(execution), allow);
        X509AlgorithmResolver.Selection selection = first.resolve(pss, BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY,
                AlgorithmExecutionCapability.Direction.SIGN, Optional.empty(), "explicit");
        assertThrows(X509AlgorithmResolver.ResolutionException.class,
                () -> first.plan(pss, BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY,
                        AlgorithmExecutionCapability.Direction.SIGN, Optional.empty(), "explicit", Object.class));

        Object executor = new Object();
        X509AuthoritySnapshot owning = X509AuthoritySnapshot.compose(List.of(bindings), List.of(execution),
                List.of(X509AuthoritySnapshot.bindExecutor("example.synthetic",
                        AlgorithmExecutionCapability.Direction.SIGN, executor)),
                allow);
        X509AuthoritySnapshot foreign = X509AuthoritySnapshot.compose(List.of(bindings), List.of(execution),
                List.of(X509AuthoritySnapshot.bindExecutor("example.synthetic",
                        AlgorithmExecutionCapability.Direction.SIGN, executor)),
                allow);
        X509ExecutionPlan<Object> plan = owning.plan(pss, BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY,
                AlgorithmExecutionCapability.Direction.SIGN, Optional.empty(), "explicit", Object.class);
        owning.authorize(plan, executor, AlgorithmExecutionCapability.Direction.SIGN);
        assertThrows(IllegalArgumentException.class,
                () -> foreign.authorize(plan, executor, AlgorithmExecutionCapability.Direction.SIGN));
        assertThrows(IllegalArgumentException.class,
                () -> owning.authorize(plan, executor, AlgorithmExecutionCapability.Direction.VERIFY));

        assertEquals(pss, first.resolveIdentity(pss.canonicalForm()));
        assertEquals(pss, first.bindings().reverse(
                first.bindings().resolve(pss, X509AlgorithmRole.SIGNATURE_ALGORITHM),
                X509AlgorithmRole.SIGNATURE_ALGORITHM));
        assertEquals(curve, first.bindings().reverse(
                first.bindings().resolve(curve, X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM),
                X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM));
        assertEquals(first.semanticFingerprint(), equivalent.semanticFingerprint());
        equivalent.requireAuthority(selection);

        X509AuthoritySnapshot denied = X509AuthoritySnapshot.compose(List.of(bindings), List.of(execution),
                policy(false, "example-policy:deny"));
        assertNotEquals(first.semanticFingerprint(), denied.semanticFingerprint());
        assertThrows(IllegalArgumentException.class, () -> denied.requireAuthority(selection));
        assertThrows(X509AlgorithmResolver.ResolutionException.class,
                () -> denied.resolve(pss, BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY,
                        AlgorithmExecutionCapability.Direction.SIGN, Optional.empty(), "explicit"));
        System.out.println("...snapshot=" + first.semanticFingerprint().substring(0, 16));
        System.out.println("...ok");
    }

    @Test
    void reconstructedPlanCannotRecoverAuthorityProvenance() {
        System.out.println("reconstructedPlanCannotRecoverAuthorityProvenance");
        Object executor = new Object();
        AlgorithmExecutionCapability capability = exactCapability("example.plan", executor);
        X509AuthoritySnapshot authority = X509AuthoritySnapshot.compose(List.of(),
                List.of(() -> List.of(capability)),
                List.of(X509AuthoritySnapshot.bindExecutor("example.plan",
                        AlgorithmExecutionCapability.Direction.SIGN, executor)),
                policy(true, "plan-policy"));
        X509ExecutionPlan<Object> plan = authority.plan(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY, AlgorithmExecutionCapability.Direction.SIGN,
                Optional.of("example.plan"), "explicit", Object.class);
        X509ExecutionPlan<Object> reconstructed = new X509ExecutionPlan<>(plan.selection(), plan.executor(),
                new Object());

        authority.authorize(plan, executor, AlgorithmExecutionCapability.Direction.SIGN);
        assertThrows(IllegalArgumentException.class,
                () -> authority.authorize(reconstructed, executor, AlgorithmExecutionCapability.Direction.SIGN));
        assertFalse(java.util.Arrays.stream(X509ExecutionPlan.class.getDeclaredMethods())
                .anyMatch(method -> "authorityToken".equals(method.getName())));
        System.out.println("...methods=" + X509ExecutionPlan.class.getDeclaredMethods().length);
        System.out.println("...ok");
    }

    @Test
    void bcExecutorRejectsSignatureAndSpkiSubstitutionBeforeExecution() throws Exception {
        System.out.println("bcExecutorRejectsSignatureAndSpkiSubstitutionBeforeExecution");
        BcX509VerificationExecutor executor = new BcX509VerificationExecutor();
        X509AuthoritySnapshot authority = X509AuthoritySnapshot.compose(List.of(), List.of(executor),
                List.of(X509AuthoritySnapshot.bindExecutor(BcX509VerificationExecutor.IMPLEMENTATION_ID,
                        AlgorithmExecutionCapability.Direction.VERIFY, executor)),
                policy(true, "bc-executor-policy"));
        X509ExecutionPlan<BcX509VerificationExecutor> plan = authority.plan(
                BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY,
                AlgorithmExecutionCapability.Direction.VERIFY,
                Optional.of(BcX509VerificationExecutor.IMPLEMENTATION_ID), "test",
                BcX509VerificationExecutor.class);
        KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
        rsaGenerator.initialize(2048);
        KeyPair rsa = rsaGenerator.generateKeyPair();
        SubjectPublicKeyInfo rsaSpki = SubjectPublicKeyInfo.getInstance(rsa.getPublic().getEncoded());
        BcX509AlgorithmAdapter adapter = new BcX509AlgorithmAdapter(authority.bindings());
        AlgorithmIdentifier correct = adapter.encode(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                X509AlgorithmRole.SIGNATURE_ALGORITHM);
        AlgorithmIdentifier wrongSignature = adapter.encode(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384,
                X509AlgorithmRole.SIGNATURE_ALGORITHM);
        AlgorithmIdentifier wrongParameters = new AlgorithmIdentifier(
                new ASN1ObjectIdentifier(StandardX509Bindings.OID_RSA_SHA256));
        AlgorithmIdentifier sha1 = new AlgorithmIdentifier(
                new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"), DERNull.INSTANCE);

        assertThrows(IllegalArgumentException.class,
                () -> executor.verify(authority, plan, rsaSpki, wrongSignature,
                        new ImmutableByteContent(new byte[0]), new byte[0]));
        assertThrows(IllegalArgumentException.class,
                () -> executor.verify(authority, plan, rsaSpki, wrongParameters,
                        new ImmutableByteContent(new byte[0]), new byte[0]));
        assertThrows(IllegalArgumentException.class,
                () -> executor.verify(authority, plan, rsaSpki, sha1, new ImmutableByteContent(new byte[0]),
                        new byte[0]));

        KeyPairGenerator ecGenerator = KeyPairGenerator.getInstance("EC");
        ecGenerator.initialize(256);
        SubjectPublicKeyInfo ecSpki = SubjectPublicKeyInfo
                .getInstance(ecGenerator.generateKeyPair().getPublic().getEncoded());
        assertThrows(IllegalArgumentException.class,
                () -> executor.verify(authority, plan, ecSpki, correct, new ImmutableByteContent(new byte[0]),
                        new byte[0]));
        System.out.println("...mismatches=4");
        System.out.println("...ok");
    }

    private static AlgorithmExecutionCapability exactCapability(String implementationId, Object executor) {
        return new AlgorithmExecutionCapability() {
            @Override
            public String implementationId() {
                return implementationId;
            }

            @Override
            public String domainFingerprint() {
                return "test-plan-capability-v1:" + executor.getClass().getName();
            }

            @Override
            public boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction direction) {
                return direction == Direction.SIGN
                        && BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.equals(identity)
                        && BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY.equals(suite.publicKey());
            }
        };
    }

    private static X509AlgorithmResolver.Policy policy(boolean permitted, String fingerprint) {
        return new X509AlgorithmResolver.Policy() {
            @Override
            public boolean permits(AlgorithmSuite suite, AlgorithmExecutionCapability.Direction direction) {
                return permitted;
            }

            @Override
            public String semanticFingerprint() {
                return fingerprint;
            }
        };
    }

    private static RepeatableContent content(byte[] bytes) {
        byte[] snapshot = bytes.clone();
        return new RepeatableContent() {
            @Override
            public ByteArrayInputStream openStream() {
                return new ByteArrayInputStream(snapshot);
            }

            @Override
            public OptionalLong length() {
                return OptionalLong.of(snapshot.length);
            }

            @Override
            public String contentId() {
                return "private-binding-test-content";
            }

            @Override
            public void close() throws IOException {
                // immutable in-memory test content owns no external resource
            }
        };
    }

    private static AlgorithmIdentifier privateIdentifier(X509AuthoritySnapshot authority, String bindingId) {
        return BcX509AlgorithmAdapter.toBc(authority.bindings().resolve(bindingId,
                BootstrapAlgorithmIdentities.SPHINCS_PLUS_SIGNATURE, X509AlgorithmRole.SIGNATURE_ALGORITHM));
    }

    private static ContentSigner contentSigner(PrivateKey privateKey, AlgorithmIdentifier identifier) {
        return contentSigner(privateKey, identifier, "SPHINCS+");
    }

    private static ContentSigner contentSigner(PrivateKey privateKey, AlgorithmIdentifier identifier,
            String jcaAlgorithm) {
        return new ContentSigner() {
            private final ByteArrayOutputStream output = new ByteArrayOutputStream();

            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return identifier;
            }

            @Override
            public OutputStream getOutputStream() {
                return output;
            }

            @Override
            public byte[] getSignature() {
                try {
                    Signature signature = "SPHINCS+".equals(jcaAlgorithm)
                            ? Signature.getInstance(jcaAlgorithm, new BouncyCastlePQCProvider())
                            : Signature.getInstance(jcaAlgorithm);
                    signature.initSign(privateKey);
                    signature.update(output.toByteArray());
                    return signature.sign();
                } catch (java.security.GeneralSecurityException failure) {
                    throw new IllegalStateException("Test signing failed", failure);
                }
            }
        };
    }

    /**
     * Test-only conflicting extension rule.
     */
    private static final class TestCollisionRule implements X509BindingRule {

        @Override
        public String id() {
            return "example.conflict";
        }

        @Override
        public X509AlgorithmRole role() {
            return X509AlgorithmRole.SIGNATURE_ALGORITHM;
        }

        @Override
        public String oid() {
            return StandardX509Bindings.OID_RSA_SHA256;
        }

        @Override
        public String semanticFingerprint() {
            return "test-conflict";
        }

        @Override
        public SignatureEncoding signatureEncoding() {
            return SignatureEncoding.OPAQUE;
        }

        @Override
        public PublicKeyEncoding publicKeyEncoding() {
            return PublicKeyEncoding.NOT_APPLICABLE;
        }

        @Override
        public java.util.Optional<X509AlgorithmIdentifier> encode(AlgorithmIdentity identity) {
            return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<AlgorithmIdentity> decode(X509AlgorithmIdentifier identifier) {
            return java.util.Optional.empty();
        }
    }
}
