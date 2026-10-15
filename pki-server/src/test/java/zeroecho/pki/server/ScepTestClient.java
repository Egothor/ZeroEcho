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
package zeroecho.pki.server;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;

/** Independent BC client envelopes and response verification for SCEP wire tests. */
final class ScepTestClient {
    private ScepTestClient() { }
    static final ASN1ObjectIdentifier TYPE = new ASN1ObjectIdentifier("2.16.840.1.113733.1.9.2");
    static final ASN1ObjectIdentifier STATUS = new ASN1ObjectIdentifier("2.16.840.1.113733.1.9.3");
    static final ASN1ObjectIdentifier NONCE = new ASN1ObjectIdentifier("2.16.840.1.113733.1.9.5");
    static final ASN1ObjectIdentifier RECIPIENT_NONCE = new ASN1ObjectIdentifier("2.16.840.1.113733.1.9.6");
    static final ASN1ObjectIdentifier TRANSACTION = new ASN1ObjectIdentifier("2.16.840.1.113733.1.9.7");

    static byte[] csr(KeyPair key, String challenge) throws Exception {
        org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder builder =
                new org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder(new X500Principal("CN=localhost"), key.getPublic());
        builder.addAttribute(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                new org.bouncycastle.asn1.DERUTF8String(challenge));
        org.bouncycastle.asn1.x509.ExtensionsGenerator extensions = new org.bouncycastle.asn1.x509.ExtensionsGenerator();
        extensions.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false,
                new org.bouncycastle.asn1.x509.GeneralNames(new org.bouncycastle.asn1.x509.GeneralName(
                        org.bouncycastle.asn1.x509.GeneralName.dNSName, "localhost")));
        builder.addAttribute(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
        return builder.build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(key.getPrivate())).getEncoded();
    }

    static byte[] poll(X509Certificate issuer) throws Exception {
        return new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
                org.bouncycastle.asn1.x500.X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded()),
                new org.bouncycastle.asn1.x500.X500Name("CN=localhost") }).getEncoded();
    }

    static byte[] request(byte[] plaintext, String transaction, byte[] nonce, int type,
            KeyPair requesterKey, X509Certificate requester, X509Certificate recipient) throws Exception {
        return request(plaintext, transaction, nonce, type, requesterKey, requester, recipient, "valid");
    }

    static byte[] request(byte[] plaintext, String transaction, byte[] nonce, int type,
            KeyPair requesterKey, X509Certificate requester, X509Certificate recipient, String variant) throws Exception {
        org.bouncycastle.cms.CMSEnvelopedDataGenerator envelope = new org.bouncycastle.cms.CMSEnvelopedDataGenerator();
        envelope.addRecipientInfoGenerator(new org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator(recipient).setProvider("BC"));
        if ("duplicateRecipient".equals(variant)) envelope.addRecipientInfoGenerator(
                new org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator(recipient).setProvider("BC"));
        byte[] encrypted = envelope.generate(new CMSProcessableByteArray(plaintext),
                new org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder("aes256".equals(variant) ? CMSAlgorithm.AES256_CBC : CMSAlgorithm.AES128_CBC)
                        .setProvider("BC").build()).getEncoded();
        if ("wrongInnerType".equals(variant) || "wrongEncryptedType".equals(variant)) {
            org.bouncycastle.asn1.cms.ContentInfo inner = org.bouncycastle.asn1.cms.ContentInfo.getInstance(encrypted);
            org.bouncycastle.asn1.cms.EnvelopedData structure = org.bouncycastle.asn1.cms.EnvelopedData.getInstance(inner.getContent());
            if ("wrongEncryptedType".equals(variant)) {
                org.bouncycastle.asn1.cms.EncryptedContentInfo content = structure.getEncryptedContentInfo();
                structure = new org.bouncycastle.asn1.cms.EnvelopedData(structure.getOriginatorInfo(), structure.getRecipientInfos(),
                        new org.bouncycastle.asn1.cms.EncryptedContentInfo(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.signedData,
                                content.getContentEncryptionAlgorithm(), content.getEncryptedContent()), structure.getUnprotectedAttrs());
            }
            encrypted = new org.bouncycastle.asn1.cms.ContentInfo("wrongInnerType".equals(variant)
                    ? org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.data : inner.getContentType(), structure).getEncoded();
        }
        if ("trailingInner".equals(variant)) encrypted = java.util.Arrays.copyOf(encrypted, encrypted.length + 1);
        ASN1EncodableVector attributes = new ASN1EncodableVector();
        attributes.add(new Attribute(TYPE, new DERSet(new DERPrintableString(Integer.toString(type)))));
        attributes.add(new Attribute(TRANSACTION, new DERSet("wrongType".equals(variant)
                ? new org.bouncycastle.asn1.DERUTF8String(transaction) : new DERPrintableString(transaction))));
        attributes.add(new Attribute(NONCE, new DERSet(new DEROctetString(nonce))));
        if ("duplicateAttribute".equals(variant)) attributes.add(new Attribute(TYPE, new DERSet(new DERPrintableString("19"))));
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        org.bouncycastle.cms.SignerInfoGenerator signer = new org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder(
                new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(attributes)))
                .build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("sha1".equals(variant) ? "SHA1withRSA" : "SHA256withRSA")
                        .setProvider("BC").build(requesterKey.getPrivate()), requester);
        generator.addSignerInfoGenerator(signer);
        if ("duplicateSigner".equals(variant)) generator.addSignerInfoGenerator(signer);
        generator.addCertificates(new org.bouncycastle.cert.jcajce.JcaCertStore(List.of(requester)));
        byte[] result = generator.generate(new CMSProcessableByteArray(encrypted), true).getEncoded();
        if ("wrongOuterType".equals(variant)) {
            org.bouncycastle.asn1.cms.ContentInfo structure = org.bouncycastle.asn1.cms.ContentInfo.getInstance(result);
            result = new org.bouncycastle.asn1.cms.ContentInfo(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.data, structure.getContent()).getEncoded();
        }
        if ("badSignature".equals(variant)) {
            CMSSignedData data = new CMSSignedData(result);
            org.bouncycastle.asn1.cms.ContentInfo content = data.toASN1Structure();
            org.bouncycastle.asn1.cms.SignedData structure = org.bouncycastle.asn1.cms.SignedData.getInstance(content.getContent());
            org.bouncycastle.asn1.cms.SignerInfo info = org.bouncycastle.asn1.cms.SignerInfo.getInstance(structure.getSignerInfos().getObjectAt(0));
            byte[] signature = info.getEncryptedDigest().getOctets(); signature[0] ^= 1;
            org.bouncycastle.asn1.cms.SignerInfo changed = new org.bouncycastle.asn1.cms.SignerInfo(info.getSID(), info.getDigestAlgorithm(),
                    info.getAuthenticatedAttributes(), info.getDigestEncryptionAlgorithm(), new DEROctetString(signature), info.getUnauthenticatedAttributes());
            result = new org.bouncycastle.asn1.cms.ContentInfo(content.getContentType(), new org.bouncycastle.asn1.cms.SignedData(
                    structure.getDigestAlgorithms(), structure.getEncapContentInfo(), structure.getCertificates(), structure.getCRLs(),
                    new DERSet(changed))).getEncoded();
        }
        return result;
    }

    static Response response(byte[] encoded, X509Certificate ra, KeyPair requester, byte[] expectedNonce) throws Exception {
        CMSSignedData data = new CMSSignedData(encoded);
        if (data.getSignedContent() == null) data = new CMSSignedData(new CMSProcessableByteArray(new byte[0]), encoded);
        org.bouncycastle.cms.SignerInformation signer = data.getSignerInfos().getSigners().iterator().next();
        org.junit.jupiter.api.Assertions.assertEquals(1, data.getSignerInfos().size());
        org.junit.jupiter.api.Assertions.assertTrue(signer.verify(new org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder()
                .setProvider("BC").build(ra)));
        org.junit.jupiter.api.Assertions.assertArrayEquals(expectedNonce, org.bouncycastle.asn1.ASN1OctetString.getInstance(
                signer.getSignedAttributes().get(RECIPIENT_NONCE).getAttrValues().getObjectAt(0)).getOctets());
        String status = org.bouncycastle.asn1.ASN1PrintableString.getInstance(
                signer.getSignedAttributes().get(STATUS).getAttrValues().getObjectAt(0)).getString();
        X509Certificate certificate = null;
        if ("0".equals(status)) {
            org.bouncycastle.cms.CMSEnvelopedData envelope = new org.bouncycastle.cms.CMSEnvelopedData((byte[]) data.getSignedContent().getContent());
            org.junit.jupiter.api.Assertions.assertEquals(CMSAlgorithm.AES128_CBC.getId(), envelope.getEncryptionAlgOID());
            byte[] certs = envelope.getRecipientInfos().getRecipients().iterator().next().getContent(
                    new org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient(requester.getPrivate()).setProvider("BC"));
            CMSSignedData inner = new CMSSignedData(certs);
            org.junit.jupiter.api.Assertions.assertEquals(0, inner.getSignerInfos().size());
            certificate = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().setProvider("BC")
                    .getCertificate(inner.getCertificates().getMatches(null).iterator().next());
        } else org.junit.jupiter.api.Assertions.assertEquals(0, ((byte[]) data.getSignedContent().getContent()).length);
        return new Response(status, certificate);
    }

    record Response(String status, X509Certificate certificate) { }
}
