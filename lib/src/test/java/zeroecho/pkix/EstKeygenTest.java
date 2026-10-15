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

package zeroecho.pkix;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.KeyAgreeRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import zeroecho.pkix.cmp.CmpProtectedMessage;
import zeroecho.pkix.sign.ContentSigner;

class EstKeygenTest {
    private static KeyPair rsa;
    private static X509Certificate generator;

    @BeforeAll static void material() throws Exception {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        rsa = key("RSA", null);
        generator = certificate(rsa, Set.of(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT));
    }

    @Test void rsaPackageHasExactNestedContentTypesAndVerifiedGeneratorAndPrivateKey() throws Exception {
        byte[] template = template(rsa, generator, rsaCapability(), false);
        byte[] body = EstKeygen.signedEncryptedPackage(template, rsa.getPrivate().getEncoded(), generator, List.of(generator),
                Pkix.signer(rsa.getPrivate(), AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11")));
        verifyPackage(body, rsa, rsa.getPrivate().getEncoded());
    }

    @Test void providerFailureNeverDisclosesItsMessageCauseOrSuppressedFailures() throws Exception {
        IllegalStateException sensitive = new IllegalStateException("SENSITIVE-PROVIDER-SENTINEL",
                new IllegalArgumentException("SENSITIVE-CAUSE-SENTINEL"));
        sensitive.addSuppressed(new IllegalStateException("SENSITIVE-CLEANUP-SENTINEL"));
        ContentSigner signer = new ContentSigner() {
            @Override public AlgorithmIdentifier algorithm() { throw sensitive; }
            @Override public OutputStream contentStream() { throw new AssertionError("Unexpected content stream"); }
            @Override public byte[] signature() { throw new AssertionError("Unexpected signature"); }
        };
        byte[] template = template(rsa, generator, rsaCapability(), false);
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> EstKeygen.signedEncryptedPackage(template, rsa.getPrivate().getEncoded(),
                        generator, List.of(generator), signer));
        assertEquals("Invalid EST key-generation template or recipient", failure.getMessage());
        assertNull(failure.getCause());
        assertEquals(0, failure.getSuppressed().length);
    }

    @Test void namedEcRecipientsUseTheirActualCurveWithoutTemplateProof() throws Exception {
        for (String curve : List.of("secp256r1", "secp384r1", "secp521r1")) {
            KeyPair recipient = key("EC", curve);
            X509Certificate certificate = certificate(recipient, Set.of(KeyUsage.KEY_AGREEMENT));
            byte[] template = template(rsa, certificate, ecCapability(), true);
            EstKeygen.requireRecipient(template, certificate);
            byte[] body = EstKeygen.signedEncryptedPackage(template, rsa.getPrivate().getEncoded(), certificate, List.of(generator),
                    Pkix.signer(rsa.getPrivate(), AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11")));
            verifyPackage(body, recipient, rsa.getPrivate().getEncoded());
        }
    }

    @Test void missingDuplicateUnknownRecipientAndWrongUsageOrNegotiationFail() throws Exception {
        byte[] valid = template(rsa, generator, rsaCapability(), false);
        KeyPair other = key("EC", "secp384r1");
        X509Certificate wrongRecipient = certificate(other, Set.of(KeyUsage.KEY_ENCIPHERMENT));
        assertThrows(IllegalArgumentException.class, () -> EstKeygen.requireRecipient(valid, wrongRecipient));
        X509Certificate signingOnly = certificate(rsa, Set.of(KeyUsage.DIGITAL_SIGNATURE));
        assertThrows(IllegalArgumentException.class, () -> EstKeygen.requireRecipient(
                template(rsa, signingOnly, rsaCapability(), false), signingOnly));
        assertThrows(IllegalArgumentException.class, () -> EstKeygen.requireRecipient(
                template(rsa, generator, ecCapability(), false), generator));
        assertThrows(IllegalArgumentException.class, () -> EstKeygen.requireAttributes(
                new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Applicant"), rsa.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256withRSA").build(rsa.getPrivate())).getEncoded()));
        for (ASN1Encodable malformed : List.of(
                new DERSequence(new ASN1Encodable[] { rsaCapability(), rsaCapability() }),
                new DERSequence(new DERSequence(new ASN1Encodable[] { PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE, DERNull.INSTANCE })),
                new DERSequence(new DERSequence(new ASN1Encodable[] { PKCSObjectIdentifiers.rsaEncryption, new DEROctetString(new byte[] {1}) })))) {
            assertThrows(IllegalArgumentException.class, () -> EstKeygen.requireAttributes(
                    request(rsa, generator, malformed, false, false)));
        }
        assertThrows(IllegalArgumentException.class, () -> EstKeygen.requireAttributes(request(rsa, generator,
                new DERSequence(rsaCapability()), true, false)));
        assertThrows(IllegalArgumentException.class, () -> EstKeygen.requireAttributes(request(rsa, generator,
                new DERSequence(rsaCapability()), false, true)));
    }

    @Test void templateSignatureIsIgnoredButItsPkcs10FieldTypesRemainStrict() throws Exception {
        byte[] valid = template(rsa, generator, rsaCapability(), true);
        EstKeygen.requireRecipient(valid, generator);
        ASN1Sequence request = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(valid));
        for (ASN1Encodable algorithm : List.of(new DEROctetString(new byte[] {1}), new DERSequence(),
                new DERSequence(new DEROctetString(new byte[] {1})),
                new DERSequence(new ASN1Encodable[] {PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE, DERNull.INSTANCE}))) {
            byte[] malformed = new DERSequence(new ASN1Encodable[] {request.getObjectAt(0), algorithm, request.getObjectAt(2)}).getEncoded("DER");
            assertThrows(IllegalArgumentException.class, () -> EstKeygen.requireAttributes(malformed));
        }
        for (ASN1Encodable signature : List.of(new DEROctetString(new byte[] {1}), new DERBitString(new byte[] {0}, 1))) {
            byte[] malformed = new DERSequence(new ASN1Encodable[] {request.getObjectAt(0), request.getObjectAt(1), signature}).getEncoded("DER");
            assertThrows(IllegalArgumentException.class, () -> EstKeygen.requireAttributes(malformed));
        }
    }

    private static void verifyPackage(byte[] body, KeyPair recipient, byte[] expectedKey) throws Exception {
        CMSEnvelopedData envelope = new CMSEnvelopedData(body);
        assertEquals(CMSAlgorithm.AES256_GCM.getId(), envelope.getEncryptionAlgOID());
        assertEquals(CMSObjectIdentifiers.signedData, org.bouncycastle.asn1.cms.EnvelopedData.getInstance(
                envelope.toASN1Structure().getContent()).getEncryptedContentInfo().getContentType());
        assertEquals(1, envelope.getRecipientInfos().size());
        RecipientInformation info = envelope.getRecipientInfos().getRecipients().iterator().next();
        byte[] signedDer = info instanceof KeyAgreeRecipientInformation
                ? info.getContent(new JceKeyAgreeEnvelopedRecipient(recipient.getPrivate()).setProvider("BC"))
                : info.getContent(new JceKeyTransEnvelopedRecipient(recipient.getPrivate()).setProvider("BC"));
        CMSSignedData signed = new CMSSignedData(new ContentInfo(CMSObjectIdentifiers.signedData, ASN1Primitive.fromByteArray(signedDer)));
        assertEquals("2.16.840.1.101.2.1.2.78.5", signed.getSignedContentTypeOID());
        assertEquals(1, signed.getSignerInfos().size());
        org.bouncycastle.asn1.cms.AttributeTable signedAttributes = signed.getSignerInfos().getSigners().iterator().next().getSignedAttributes();
        org.junit.jupiter.api.Assertions.assertNull(signedAttributes.get(org.bouncycastle.asn1.cms.CMSAttributes.signingTime));
        org.junit.jupiter.api.Assertions.assertNotNull(signedAttributes.get(org.bouncycastle.asn1.cms.CMSAttributes.contentType));
        org.junit.jupiter.api.Assertions.assertNotNull(signedAttributes.get(org.bouncycastle.asn1.cms.CMSAttributes.messageDigest));
        org.junit.jupiter.api.Assertions.assertNotNull(signedAttributes.get(org.bouncycastle.asn1.cms.CMSAttributes.cmsAlgorithmProtect));
        assertTrue(signed.getSignerInfos().getSigners().iterator().next().verify(
                new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(generator)));
        ASN1Sequence keys = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray((byte[]) signed.getSignedContent().getContent()));
        assertEquals(1, keys.size());
        assertArrayEquals(expectedKey, keys.getObjectAt(0).toASN1Primitive().getEncoded("DER"));
    }

    private static byte[] template(KeyPair key, X509Certificate recipient, ASN1Encodable capability, boolean invalidProof) throws Exception {
        byte[] result = request(key, recipient, new DERSequence(capability), false, false);
        if (!invalidProof) return result;
        ASN1Sequence original = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(result));
        return new DERSequence(new ASN1Encodable[] { original.getObjectAt(0), original.getObjectAt(1), new DERBitString(new byte[] {1}) }).getEncoded("DER");
    }

    private static byte[] request(KeyPair key, X509Certificate recipient, ASN1Encodable capabilities, boolean duplicate, boolean extraValue) throws Exception {
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Applicant"), key.getPublic());
        builder.addAttribute(new ASN1ObjectIdentifier(EstKeygen.CAPABILITIES_OID), capabilities);
        ASN1ObjectIdentifier id = new ASN1ObjectIdentifier(EstKeygen.RECIPIENT_KEY_ID_OID);
        DEROctetString value = new DEROctetString(CmpProtectedMessage.certificateKeyId(recipient));
        if (extraValue) builder.addAttribute(id, new ASN1Encodable[] {value, value});
        else builder.addAttribute(id, value);
        if (duplicate) builder.addAttribute(id, value);
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())).getEncoded();
    }

    private static ASN1Encodable rsaCapability() {
        return new DERSequence(new ASN1Encodable[] { PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE });
    }

    private static ASN1Encodable ecCapability() {
        return new DERSequence(new ASN1Encodable[] { CMSAlgorithm.ECDH_SHA256KDF, new DERSequence(CMSAlgorithm.AES256_WRAP) });
    }

    private static KeyPair key(String algorithm, String curve) throws Exception {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        random.setSeed((algorithm + String.valueOf(curve) + "est-keygen").getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, "BC");
        if (curve == null) generator.initialize(2048, random);
        else generator.initialize(new ECGenParameterSpec(curve), random);
        return generator.generateKeyPair();
    }

    private static X509Certificate certificate(KeyPair key, Set<KeyUsage> usages) throws Exception {
        X500Principal name = new X500Principal("CN=Generator or Recipient");
        return Pkix.certificateBuilder().subject(name).issuer(name).serialNumber(BigInteger.ONE).publicKey(key.getPublic())
                .validity(Instant.parse("2026-01-01T00:00:00Z"), Instant.parse("2028-01-01T00:00:00Z"))
                .basicConstraints(BasicConstraints.endEntity(), true).keyUsage(usages, true)
                .build(Pkix.signer(key.getPrivate(), "RSA".equals(key.getPublic().getAlgorithm())
                        ? AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11") : AlgorithmIdentifier.absent("1.2.840.10045.4.3.2")));
    }
}
