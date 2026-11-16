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
package zeroecho.pki.impl.framework.x509.bc;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Map;
import java.util.TreeMap;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.hybrid.sdk.HybridSdkFrame;
import zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest;
import zeroecho.pki.api.request.CertificationRequest;

/**
 * Contract and regression tests for BC hybrid SDK proof verifier.
 */
class BcHybridSdkProofVerifierTest {
    private static final Instant NOW = Instant.parse("2026-11-14T12:00:00Z");

    /**
     * Verifies both client keys and returns the bound f3 commitment.
     *
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void verifiesBothClientKeysAndReturnsTheBoundF3Commitment() throws Exception {
        Fixture fixture = fixture();
        ParsedHybridSdkRequest parsed = new BcX509CertificationRequestParser().parseHybridSdk(request(fixture.csr));
        HybridSdkFrame frame = frame(fixture, parsed);
        byte[] primary = sign("SHA384withECDSA", fixture.primary, frame.encode(), new byte[0]);
        byte[] alternative = sign("ML-DSA-87", fixture.alternative, new HybridSdkFrame(2, frame.fields()).encode(), new byte[0]);
        var verifier = new BcHybridSdkProofVerifier();
        assertTrue(verifier.verify(parsed, frame, primary, alternative, NOW).matches("sha512:[0-9a-f]{128}"));
        assertEquals(verifier.verify(parsed, frame, primary, alternative, NOW), zeroecho.pki.api.hybrid.sdk.HybridSdkProofs.verify(
                zeroecho.pki.api.hybrid.sdk.HybridSdkProofs.parse(fixture.csr), frame, primary, alternative, NOW));
        assertThrows(PkiException.class, () -> verifier.verify(parsed, frame, primary, alternative, NOW.plusSeconds(300)));
        assertThrows(PkiException.class, () -> verifier.verify(parsed, frame, primary, alternative, NOW.minusSeconds(1)));
        assertThrows(PkiException.class, () -> verifier.verify(parsed, frame, alternative, primary, NOW));
        assertThrows(PkiException.class, () -> verifier.verify(parsed, frame, primary, new byte[0], NOW));
        byte[] corrupt = alternative.clone(); corrupt[10] ^= 1;
        assertThrows(PkiException.class, () -> verifier.verify(parsed, frame, primary, corrupt, NOW));
        byte[] wrongContext = sign("ML-DSA-87", fixture.alternative, new HybridSdkFrame(2, frame.fields()).encode(), new byte[] {1});
        assertThrows(PkiException.class, () -> verifier.verify(parsed, frame, primary, wrongContext, NOW));
        Map<Integer, byte[]> changed = frame.fields(); changed.put(17, new byte[64]);
        assertThrows(PkiException.class, () -> verifier.verify(parsed, new HybridSdkFrame(1, changed), primary, alternative, NOW));
        var wrong = new ParsedHybridSdkRequest(parsed.primary(), new EncodedObject(Encoding.DER, fixture().alternative.getPublic().getEncoded()));
        assertThrows(PkiException.class, () -> verifier.verify(wrong, frame, primary, alternative, NOW));
    }

    /**
     * Preserves ordinary parser and rejects missing duplicate and critical alternative requests.
     *
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void preservesOrdinaryParserAndRejectsMissingDuplicateAndCriticalAlternativeRequests() throws Exception {
        Fixture fixture = fixture(); var parser = new BcX509CertificationRequestParser();
        assertThrows(PkiException.class, () -> parser.parse(request(fixture.csr)));
        byte[] ordinary = builder(fixture.primary).build(new JcaContentSignerBuilder("SHA384withECDSA").build(fixture.primary.getPrivate())).getEncoded();
        assertNotNull(parser.parse(request(ordinary)));
        assertThrows(PkiException.class, () -> parser.parseHybridSdk(request(ordinary)));
        var extensions = new ExtensionsGenerator();
        extensions.addExtension(new ASN1ObjectIdentifier("2.5.29.72"), true, fixture.alternative.getPublic().getEncoded());
        byte[] critical = builder(fixture.primary).addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate())
                .build(new JcaContentSignerBuilder("SHA384withECDSA").build(fixture.primary.getPrivate())).getEncoded();
        assertThrows(PkiException.class, () -> parser.parseHybridSdk(request(critical)));
        extensions = new ExtensionsGenerator();
        extensions.addExtension(new ASN1ObjectIdentifier("2.5.29.72"), false, fixture.alternative.getPublic().getEncoded());
        var ext = extensions.generate();
        byte[] duplicate = builder(fixture.primary).addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, ext)
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, ext)
                .build(new JcaContentSignerBuilder("SHA384withECDSA").build(fixture.primary.getPrivate())).getEncoded();
        assertThrows(PkiException.class, () -> parser.parseHybridSdk(request(duplicate)));
        var repeatedExtension = ext.getExtension(new ASN1ObjectIdentifier("2.5.29.72"));
        byte[] repeated = builder(fixture.primary).addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                new DERSequence(new Extension[] {repeatedExtension, repeatedExtension}))
                .build(new JcaContentSignerBuilder("SHA384withECDSA").build(fixture.primary.getPrivate())).getEncoded();
        assertThrows(PkiException.class, () -> parser.parseHybridSdk(request(repeated)));
        byte[] invalidPrimary = fixture.csr.clone(); invalidPrimary[invalidPrimary.length - 1] ^= 1;
        assertThrows(PkiException.class, () -> parser.parseHybridSdk(request(invalidPrimary)));
        var badParameters = new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.19"), org.bouncycastle.asn1.DERNull.INSTANCE),
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(fixture.alternative.getPublic().getEncoded()).getPublicKeyData().getBytes());
        var invalidExtensions = new ExtensionsGenerator();
        invalidExtensions.addExtension(new ASN1ObjectIdentifier("2.5.29.72"), false, badParameters.getEncoded("DER"));
        byte[] nullParameters = builder(fixture.primary).addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, invalidExtensions.generate())
                .build(new JcaContentSignerBuilder("SHA384withECDSA").build(fixture.primary.getPrivate())).getEncoded();
        assertThrows(PkiException.class, () -> parser.parseHybridSdk(request(nullParameters)));
    }

    /**
     * Verifies canonical crmf original and fresh dual proofs without kind substitution.
     *
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void verifiesCanonicalCrmfOriginalAndFreshDualProofsWithoutKindSubstitution() throws Exception {
        Fixture original = fixture();
        byte[] crmf = new org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder(java.math.BigInteger.valueOf(7))
                .setSubject(new org.bouncycastle.asn1.x500.X500Name("CN=Alice Example"))
                .setPublicKey(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(original.primary.getPublic().getEncoded()))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.72"), false, original.alternative.getPublic().getEncoded())
                .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA384withECDSA").build(original.primary.getPrivate()))
                .build().getEncoded();
        var payload = new zeroecho.pki.api.request.X509EnrollmentPayload(
                zeroecho.pki.api.request.X509EnrollmentPayload.Kind.CRMF, crmf);
        var parsed = zeroecho.pki.api.hybrid.sdk.HybridSdkProofs.parse(payload);
        var fixture = new Fixture(original.primary, original.alternative, crmf);
        var frame = frame(fixture, parsed);
        byte[] primary = sign("SHA384withECDSA", fixture.primary, frame.encode(), new byte[0]);
        byte[] alternative = sign("ML-DSA-87", fixture.alternative, new HybridSdkFrame(2, frame.fields()).encode(), new byte[0]);
        assertTrue(zeroecho.pki.api.hybrid.sdk.HybridSdkProofs.verify(parsed, frame, primary, alternative, NOW)
                .matches("sha512:[0-9a-f]{128}"));
        var substituted = new ParsedHybridSdkRequest(parsed.primary(), parsed.alternativeSubjectPublicKeyInfo(),
                new zeroecho.pki.api.request.X509EnrollmentPayload(zeroecho.pki.api.request.X509EnrollmentPayload.Kind.PKCS10, crmf));
        assertThrows(PkiException.class, () -> zeroecho.pki.api.hybrid.sdk.HybridSdkProofs.verify(substituted, frame, primary, alternative, NOW));
        byte[] corrupt = crmf.clone(); corrupt[corrupt.length - 1] ^= 1;
        assertThrows(PkiException.class, () -> zeroecho.pki.api.hybrid.sdk.HybridSdkProofs.parse(
                new zeroecho.pki.api.request.X509EnrollmentPayload(payload.kind(), corrupt)));
        assertThrows(PkiException.class, () -> zeroecho.pki.api.hybrid.sdk.HybridSdkProofs.parse(crmf));
        byte[] badAlternative = alternative.clone(); badAlternative[0] ^= 1;
        assertThrows(PkiException.class, () -> zeroecho.pki.api.hybrid.sdk.HybridSdkProofs.verify(parsed, frame, primary, badAlternative, NOW));
    }

    private static Fixture fixture() throws Exception {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC"); ec.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair primary = ec.generateKeyPair();
        KeyPairGenerator ml = KeyPairGenerator.getInstance("ML-DSA", "BC"); ml.initialize(MLDSAParameterSpec.ml_dsa_87);
        KeyPair alternative = ml.generateKeyPair();
        var extensions = new ExtensionsGenerator();
        extensions.addExtension(new ASN1ObjectIdentifier("2.5.29.72"), false, alternative.getPublic().getEncoded());
        extensions.addExtension(Extension.subjectAlternativeName, false, new org.bouncycastle.asn1.x509.GeneralNames(
                new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x509.GeneralName.dNSName, "alice.example.invalid")));
        byte[] csr = builder(primary).addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate())
                .build(new JcaContentSignerBuilder("SHA384withECDSA").build(primary.getPrivate())).getEncoded();
        return new Fixture(primary, alternative, csr);
    }
    private static JcaPKCS10CertificationRequestBuilder builder(KeyPair pair) {
        return new JcaPKCS10CertificationRequestBuilder(new javax.security.auth.x500.X500Principal("CN=Alice Example"), pair.getPublic());
    }
    private static CertificationRequest request(byte[] bytes) {
        return new CertificationRequest(BcX509CredentialFramework.FORMAT_ID, new EncodedObject(Encoding.DER, bytes));
    }
    private static HybridSdkFrame frame(Fixture fixture, ParsedHybridSdkRequest request) {
        var fields = new TreeMap<Integer, byte[]>(); fields.put(1, text("zeroecho-hybrid-sdk-v1")); fields.put(2, text("example-realm"));
        for (int i = 3; i <= 6; i++) { byte[] value = new byte[32]; value[0] = (byte) i; fields.put(i, value); }
        fields.put(7, ByteBuffer.allocate(8).putLong(NOW.getEpochSecond()).array()); fields.put(8, ByteBuffer.allocate(8).putLong(NOW.plusSeconds(300).getEpochSecond()).array());
        fields.put(9, text("https://example.invalid:443")); fields.put(10, text("admin-http-v1"));
        fields.put(11, HybridSdkFrame.hash(fixture.csr)); fields.put(12, new byte[64]);
        fields.put(13, HybridSdkFrame.hash(request.primary().publicKeyInfo().bytes())); fields.put(14, HybridSdkFrame.hash(request.alternativeSubjectPublicKeyInfo().bytes()));
        fields.put(15, HybridSdkFrame.primaryAlgorithm()); fields.put(16, HybridSdkFrame.alternativeAlgorithm()); fields.put(17, HybridSdkFrame.hash(new byte[] {1}));
        return new HybridSdkFrame(1, fields);
    }
    private static byte[] sign(String algorithm, KeyPair key, byte[] bytes, byte[] context) throws Exception {
        Signature signer = algorithm.equals("ML-DSA-87") ? Signature.getInstance(algorithm, "BC") : Signature.getInstance(algorithm);
        if (algorithm.equals("ML-DSA-87")) signer.setParameter(new ContextParameterSpec(context));
        signer.initSign(key.getPrivate()); signer.update(bytes); return signer.sign();
    }
    private static byte[] text(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private record Fixture(KeyPair primary, KeyPair alternative, byte[] csr) { }
}
