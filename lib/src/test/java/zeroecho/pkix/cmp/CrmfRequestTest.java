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
package zeroecho.pkix.cmp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import zeroecho.pkix.Pkix;
import zeroecho.sdk.util.BouncyCastleActivator;

/** Independent BouncyCastle CRMF fixture and structural facade contracts. */
class CrmfRequestTest {
    private static KeyPair key;
    private static byte[] fixture;

    @BeforeAll
    static void fixture() throws Exception {
        BouncyCastleActivator.init();
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        random.setSeed(new byte[] { 19, 42, 73, 11, 9, 31, 5 });
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
        generator.initialize(2048, random);
        key = generator.generateKeyPair();
        fixture = new CertificateRequestMessageBuilder(BigInteger.valueOf(7))
                .setSubject(new X500Name("CN=leaf.example.test"))
                .setPublicKey(SubjectPublicKeyInfo.getInstance(key.getPublic().getEncoded()))
                .addExtension(Extension.subjectAlternativeName, false,
                        new GeneralNames(new GeneralName(GeneralName.dNSName, "leaf.example.test")))
                .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate()))
                .build().getEncoded();
    }

    @Test
    void extractsAndIndependentlyVerifiesCompleteSignedRequest() throws Exception {
        CrmfRequest request = CrmfRequest.parse(fixture);
        assertEquals(BigInteger.valueOf(7), request.requestId());
        assertEquals("CN=leaf.example.test", request.subject().getName());
        assertArrayEquals(key.getPublic().getEncoded(), request.subjectPublicKeyInfo());
        assertEquals(1, request.requestedExtensions().size());
        zeroecho.pkix.sign.ContentVerifier verifier = Pkix.verifier(key.getPublic(), request.signatureAlgorithm());
        try (java.io.OutputStream output = verifier.contentStream()) { output.write(request.signedRequest()); }
        assertTrue(verifier.verify(request.signature()));
        byte[] changed = request.encoded();
        changed[0] ^= 1;
        assertArrayEquals(fixture, request.encoded());
        assertTrue(request.toString().contains("redacted"));
    }

    @Test
    void rejectsTruncationTrailingBytesOversizeAndDeeplyNestedInput() {
        assertThrows(IllegalArgumentException.class, () -> CrmfRequest.parse(Arrays.copyOf(fixture, fixture.length - 1)));
        assertThrows(IllegalArgumentException.class, () -> CrmfRequest.parse(Arrays.copyOf(fixture, fixture.length + 1)));
        assertThrows(IllegalArgumentException.class, () -> CrmfRequest.parse(new byte[CrmfRequest.MAXIMUM_ENCODED_BYTES + 1]));
        byte[] nested = new byte[] { 5, 0 };
        for (int index = 0; index < 70; index++) {
            byte[] next = new byte[nested.length + (nested.length < 128 ? 2 : 3)];
            next[0] = 48;
            int offset;
            if (nested.length < 128) { next[1] = (byte) nested.length; offset = 2; }
            else { next[1] = (byte) 129; next[2] = (byte) nested.length; offset = 3; }
            System.arraycopy(nested, 0, next, offset, nested.length);
            nested = next;
        }
        byte[] deep = nested;
        assertThrows(IllegalArgumentException.class, () -> CrmfRequest.parse(deep));
    }

    @Test
    void rejectsMissingProofSubjectAndUnsupportedTemplateFields() throws Exception {
        CertReqMsg original = CertReqMsg.getInstance(fixture);
        byte[] noProof = new CertReqMsg(original.getCertReq(), null, null).getEncoded(ASN1Encoding.DER);
        assertThrows(IllegalArgumentException.class, () -> CrmfRequest.parse(noProof));
        CertRequest missingSubject = new CertRequest(1,
                new CertTemplateBuilder().setPublicKey(SubjectPublicKeyInfo.getInstance(key.getPublic().getEncoded())).build(), null);
        byte[] noSubject = new CertReqMsg(missingSubject, original.getPop(), null).getEncoded(ASN1Encoding.DER);
        assertThrows(IllegalArgumentException.class, () -> CrmfRequest.parse(noSubject));
        CertRequest requestedSerial = new CertRequest(1,
                new CertTemplateBuilder().setSubject(new X500Name("CN=leaf.example.test"))
                        .setPublicKey(SubjectPublicKeyInfo.getInstance(key.getPublic().getEncoded()))
                        .setSerialNumber(new org.bouncycastle.asn1.ASN1Integer(99)).build(), null);
        byte[] serial = new CertReqMsg(requestedSerial, original.getPop(), null).getEncoded(ASN1Encoding.DER);
        assertThrows(IllegalArgumentException.class, () -> CrmfRequest.parse(serial));
        POPOSigningKey originalProof = POPOSigningKey.getInstance(original.getPop().getObject());
        org.bouncycastle.asn1.crmf.POPOSigningKeyInput input = new org.bouncycastle.asn1.crmf.POPOSigningKeyInput(
                new GeneralName(new X500Name("CN=sender")), SubjectPublicKeyInfo.getInstance(key.getPublic().getEncoded()));
        byte[] inputProof = new CertReqMsg(original.getCertReq(), new ProofOfPossession(new POPOSigningKey(
                input, originalProof.getAlgorithmIdentifier(), new DERBitString(originalProof.getSignature().getOctets()))), null)
                .getEncoded(ASN1Encoding.DER);
        assertThrows(IllegalArgumentException.class, () -> CrmfRequest.parse(inputProof));
    }

    @Test
    void rejectsCorrectlySignedButReorderedTemplate() throws Exception {
        org.bouncycastle.asn1.ASN1Sequence fields = org.bouncycastle.asn1.ASN1Sequence.getInstance(
                CertReqMsg.getInstance(fixture).getCertReq().getCertTemplate().toASN1Primitive());
        org.bouncycastle.asn1.crmf.CertTemplate reordered = org.bouncycastle.asn1.crmf.CertTemplate.getInstance(
                new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
                        fields.getObjectAt(1), fields.getObjectAt(0), fields.getObjectAt(2) }));
        CertRequest request = new CertRequest(7, reordered, null);
        org.bouncycastle.operator.ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate());
        try (java.io.OutputStream output = signer.getOutputStream()) { output.write(request.getEncoded(ASN1Encoding.DER)); }
        byte[] invalid = new CertReqMsg(request, new ProofOfPossession(new POPOSigningKey(null,
                signer.getAlgorithmIdentifier(), new DERBitString(signer.getSignature()))), null).getEncoded(ASN1Encoding.DER);
        assertThrows(IllegalArgumentException.class, () -> CrmfRequest.parse(invalid));
    }

    @Test
    void emitsDeterministicPublicRequestFixtureForIndependentCoreTests() throws Exception {
        Path directory = Path.of("build", "generated", "crmf-test-fixtures");
        Files.createDirectories(directory);
        Files.write(directory.resolve("rsa2048-sha256.der"), fixture);
        byte[] noSan = new CertificateRequestMessageBuilder(BigInteger.valueOf(7))
                .setSubject(new X500Name("CN=Applicant"))
                .setPublicKey(SubjectPublicKeyInfo.getInstance(key.getPublic().getEncoded()))
                .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate()))
                .build().getEncoded();
        Files.write(directory.resolve("rsa2048-nosan.der"), noSan);
        byte[] sha384 = new CertificateRequestMessageBuilder(BigInteger.valueOf(7))
                .setSubject(new X500Name("CN=Applicant"))
                .setPublicKey(SubjectPublicKeyInfo.getInstance(key.getPublic().getEncoded()))
                .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA384withRSA").build(key.getPrivate()))
                .build().getEncoded();
        Files.write(directory.resolve("rsa2048-sha384.der"), sha384);
    }

    @Test
    void retainsSignedOldCertificateControlAndRejectsAmbiguousOrUnsupportedReferences() throws Exception {
        org.bouncycastle.asn1.crmf.CertId reference = new org.bouncycastle.asn1.crmf.CertId(
                new GeneralName(new X500Name("CN=Issuer")), BigInteger.TEN);
        org.bouncycastle.asn1.crmf.AttributeTypeAndValue control = new org.bouncycastle.asn1.crmf.AttributeTypeAndValue(
                org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers.id_regCtrl_oldCertID, reference);
        byte[] encoded = controlled(new org.bouncycastle.asn1.crmf.Controls(control));
        CrmfRequest parsed = CrmfRequest.parse(encoded);
        assertEquals(BigInteger.TEN, parsed.oldCertificate().orElseThrow().serialNumber());
        assertEquals(new javax.security.auth.x500.X500Principal("CN=Issuer"), parsed.oldCertificate().orElseThrow().issuer());
        assertArrayEquals(encoded, parsed.encoded());
        org.bouncycastle.asn1.crmf.Controls extraAtvField = org.bouncycastle.asn1.crmf.Controls.getInstance(
                new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.DERSequence(
                        new org.bouncycastle.asn1.ASN1Encodable[] { control.getType(), reference, org.bouncycastle.asn1.DERNull.INSTANCE })));
        assertThrows(IllegalArgumentException.class, () -> CrmfRequest.parse(controlled(extraAtvField)));
        zeroecho.pkix.sign.ContentVerifier verifier = Pkix.verifier(key.getPublic(), parsed.signatureAlgorithm());
        try (java.io.OutputStream output = verifier.contentStream()) { output.write(parsed.signedRequest()); }
        assertTrue(verifier.verify(parsed.signature()));
        assertThrows(IllegalArgumentException.class, () -> CrmfRequest.parse(controlled(new org.bouncycastle.asn1.crmf.Controls(
                new org.bouncycastle.asn1.crmf.AttributeTypeAndValue[] { control, control }))));
        assertThrows(IllegalArgumentException.class, () -> CrmfRequest.parse(controlled(new org.bouncycastle.asn1.crmf.Controls(
                new org.bouncycastle.asn1.crmf.AttributeTypeAndValue(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.3"), reference)))));
        for (org.bouncycastle.asn1.ASN1Encodable malformed : java.util.List.of(
                new org.bouncycastle.asn1.crmf.CertId(new GeneralName(GeneralName.dNSName, "issuer.example"), BigInteger.TEN),
                new org.bouncycastle.asn1.crmf.CertId(reference.getIssuer(), BigInteger.ZERO),
                new org.bouncycastle.asn1.crmf.CertId(reference.getIssuer(), BigInteger.ONE.shiftLeft(160)),
                new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
                        reference.getIssuer(), reference.getSerialNumber(), org.bouncycastle.asn1.DERNull.INSTANCE }))) {
            assertThrows(IllegalArgumentException.class, () -> CrmfRequest.parse(controlled(new org.bouncycastle.asn1.crmf.Controls(
                    new org.bouncycastle.asn1.crmf.AttributeTypeAndValue(org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers.id_regCtrl_oldCertID, malformed)))));
        }
    }

    private static byte[] controlled(org.bouncycastle.asn1.crmf.Controls controls) throws Exception {
        CertRequest request = new CertRequest(7, CertReqMsg.getInstance(fixture).getCertReq().getCertTemplate(), controls);
        org.bouncycastle.operator.ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate());
        try (java.io.OutputStream output = signer.getOutputStream()) { output.write(request.getEncoded()); }
        return new CertReqMsg(request, new ProofOfPossession(new POPOSigningKey(null,
                signer.getAlgorithmIdentifier(), new DERBitString(signer.getSignature()))), null).getEncoded();
    }
}
