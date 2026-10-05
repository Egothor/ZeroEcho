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
package zeroecho.pkix.scep;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Store;

/**
 * BouncyCastle-backed codec for SCEP (RFC 8894) CMS message encoding and decoding.
 *
 * <p>All operations in this class use BouncyCastle CMS directly; no BouncyCastle
 * types are exposed in the method signatures so that callers in other modules do not
 * need a {@code requires org.bouncycastle.*} clause.</p>
 *
 * @since 1.0
 */
@SuppressWarnings("PMD.SignatureDeclareThrowsException")
public final class ScepCodec {

    // SCEP authenticated attribute OIDs (RFC 8894 / Cisco SCEP)
    private static final ASN1ObjectIdentifier ID_MESSAGE_TYPE =
            new ASN1ObjectIdentifier("2.16.840.1.113733.1.9.2");
    private static final ASN1ObjectIdentifier ID_PKI_STATUS =
            new ASN1ObjectIdentifier("2.16.840.1.113733.1.9.3");
    private static final ASN1ObjectIdentifier ID_FAIL_INFO =
            new ASN1ObjectIdentifier("2.16.840.1.113733.1.9.4");
    private static final ASN1ObjectIdentifier ID_SENDER_NONCE =
            new ASN1ObjectIdentifier("2.16.840.1.113733.1.9.5");
    private static final ASN1ObjectIdentifier ID_RECIPIENT_NONCE =
            new ASN1ObjectIdentifier("2.16.840.1.113733.1.9.6");
    private static final ASN1ObjectIdentifier ID_TRANS_ID =
            new ASN1ObjectIdentifier("2.16.840.1.113733.1.9.7");

    /** SCEP messageType value for PKCSReq. */
    public static final int MSG_PKCS_REQ = 19;
    /** SCEP messageType value for CertRep. */
    public static final int MSG_CERT_REP = 3;
    /** SCEP messageType value for GetCertInitial. */
    public static final int MSG_GET_CERT_INITIAL = 20;
    /** SCEP messageType value for GetCert. */
    public static final int MSG_GET_CERT = 21;
    /** SCEP messageType value for GetCRL. */
    public static final int MSG_GET_CRL = 22;

    /** pkiStatus value for success. */
    public static final String STATUS_SUCCESS = "0";
    /** pkiStatus value for failure. */
    public static final String STATUS_FAILURE = "2";
    /** pkiStatus value for pending. */
    public static final String STATUS_PENDING = "3";

    /** failInfo value for badRequest (challenge password mismatch). */
    public static final String FAIL_BAD_REQUEST = "2";
    /** failInfo value for badCertId (certificate not found). */
    public static final String FAIL_BAD_CERT_ID = "4";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private ScepCodec() {
    }

    /**
     * Parses a DER-encoded CMS SignedData SCEP PKIOperation message, decrypting
     * the inner EnvelopedData using the RA's private key for message types that
     * encrypt their content (PKCSReq, GetCertInitial).
     *
     * @param cmsDer       DER-encoded outer CMS SignedData
     * @param raPrivateKey RA private key for decrypting inner EnvelopedData content;
     *                     required only for PKCSReq and GetCertInitial
     * @return parsed SCEP PKIMessage
     * @throws ScepCodecException if the message is malformed or decryption fails
     */
    public static ScepPkiMessage parsePkiOperationDer(byte[] cmsDer, PrivateKey raPrivateKey)
            throws ScepCodecException {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        try {
            return parseSignedRequest(new CMSSignedData(cmsDer), raPrivateKey);
        } catch (Exception e) {
            throw new ScepCodecException("Failed to parse SCEP PKIOperation CMS message", e);
        }
    }

    private static ScepPkiMessage parseSignedRequest(CMSSignedData signedData, PrivateKey raPrivateKey)
            throws ScepCodecException {
        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
        if (signers.isEmpty()) {
            throw new ScepCodecException("SCEP PKIMessage has no signers");
        }
        SignerInformation signer = signers.iterator().next();
        AttributeTable attributes = signer.getSignedAttributes();
        if (attributes == null) {
            throw new ScepCodecException("SCEP PKIMessage has no authenticated attributes");
        }
        int messageType = messageType(attributes);
        String transactionId = getAttrPrintableString(attributes, ID_TRANS_ID);
        if (transactionId == null) {
            throw new ScepCodecException("SCEP PKIMessage missing transactionId attribute");
        }
        byte[] senderNonce = getAttrOctetString(attributes, ID_SENDER_NONCE);
        byte[] encapsulated = (byte[]) signedData.getSignedContent().getContent();
        byte[] innerContent = decryptContent(encapsulated, messageType, raPrivateKey);
        return new ScepPkiMessage(messageType, transactionId, senderNonce, innerContent,
                requesterCertificate(signedData, signer));
    }

    private static int messageType(AttributeTable attributes) throws ScepCodecException {
        String value = getAttrPrintableString(attributes, ID_MESSAGE_TYPE);
        if (value == null) {
            throw new ScepCodecException("SCEP PKIMessage missing messageType attribute");
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException invalid) {
            throw new ScepCodecException("SCEP messageType is not numeric: " + value, invalid);
        }
    }

    private static byte[] decryptContent(byte[] content, int messageType, PrivateKey raPrivateKey)
            throws ScepCodecException {
        if (messageType != MSG_PKCS_REQ && messageType != MSG_GET_CERT_INITIAL) {
            return content;
        }
        if (raPrivateKey == null) {
            throw new ScepCodecException("RA private key required to decrypt SCEP message type " + messageType);
        }
        try {
            CMSEnvelopedData envelope = new CMSEnvelopedData(content);
            Collection<org.bouncycastle.cms.RecipientInformation> recipients =
                    envelope.getRecipientInfos().getRecipients();
            if (recipients.isEmpty()) {
                throw new ScepCodecException("SCEP EnvelopedData has no recipients");
            }
            return recipients.iterator().next()
                    .getContent(new JceKeyTransEnvelopedRecipient(raPrivateKey).setProvider("BC"));
        } catch (CMSException failure) {
            throw new ScepCodecException("SCEP inner EnvelopedData decryption failed", failure);
        }
    }

    private static X509Certificate requesterCertificate(CMSSignedData signedData, SignerInformation signer) {
        try {
            Store<X509CertificateHolder> certificates = signedData.getCertificates();
            Collection<X509CertificateHolder> matches = certificates.getMatches(signer.getSID());
            if (!matches.isEmpty()) {
                return new JcaX509CertificateConverter().setProvider("BC")
                        .getCertificate(matches.iterator().next());
            }
        } catch (Exception absent) {
            // Non-fatal: CertRep encryption validates the optional requester certificate later.
            return null;
        }
        return null;
    }
    /**
     * Extracts the PKCS#9 challengePassword attribute string from a DER-encoded
     * PKCS#10 CSR. Returns {@code null} if the attribute is absent.
     *
     * @param csrDer DER-encoded PKCS#10 CSR
     * @return challengePassword string, or {@code null} if absent
     * @throws ScepCodecException if the CSR cannot be parsed
     */
    public static String extractChallengePassword(byte[] csrDer) throws ScepCodecException {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        try {
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrDer);
            org.bouncycastle.asn1.pkcs.Attribute[] attrs =
                    csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
            if (attrs == null || attrs.length == 0) {
                return null;
            }
            ASN1Encodable[] values = attrs[0].getAttributeValues();
            if (values == null || values.length == 0) {
                return null;
            }
            // DirectoryString: PrintableString, UTF8String, BMPString, etc.
            ASN1Encodable val = values[0];
            if (val instanceof DERPrintableString ps) {
                return ps.getString();
            } else if (val instanceof org.bouncycastle.asn1.DERUTF8String us) {
                return us.getString();
            } else if (val instanceof org.bouncycastle.asn1.DERIA5String is) {
                return is.getString();
            } else if (val instanceof org.bouncycastle.asn1.DERBMPString bs) {
                return bs.getString();
            }
            return val.toString();
        } catch (Exception e) {
            throw new ScepCodecException("Cannot extract challengePassword from CSR", e);
        }
    }

    /**
     * Builds a SCEP CertRep SUCCESS response signed by the RA.
     *
     * <p>The inner content is a CMS {@code EnvelopedData} wrapping a degenerate
     * {@code SignedData} containing the issued certificate, encrypted for the
     * requester's certificate (from the original PKCSReq message).</p>
     *
     * @param transactionId  SCEP transaction identifier from the request
     * @param recipientNonce senderNonce from the request (becomes recipientNonce in response)
     * @param issuedCertDer  DER-encoded issued certificate
     * @param requesterCert  requester's certificate (for encrypting the response)
     * @param raCert         RA signing certificate
     * @param raKey          RA private key for signing
     * @return DER-encoded CMS SignedData CertRep
     * @throws ScepCodecException if encoding fails
     */
    public static byte[] buildCertRepSuccess(String transactionId, byte[] recipientNonce,
            byte[] issuedCertDer, X509Certificate requesterCert,
            X509Certificate raCert, PrivateKey raKey) throws ScepCodecException {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        try {
            // Build degenerate certs-only CMS containing the issued cert
            X509Certificate issuedCert = parseCert(issuedCertDer);
            CMSSignedDataGenerator innerGen = new CMSSignedDataGenerator();
            innerGen.addCertificates(new JcaCertStore(List.of(issuedCert)));
            byte[] degenerateCmsDer = innerGen.generate(new CMSAbsentContent()).getEncoded();

            // Wrap in EnvelopedData encrypted for the requester's certificate
            CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
            edGen.addRecipientInfoGenerator(
                    new JceKeyTransRecipientInfoGenerator(requesterCert).setProvider("BC"));
            CMSEnvelopedData enveloped = edGen.generate(
                    new CMSProcessableByteArray(degenerateCmsDer),
                    new JceCMSContentEncryptorBuilder(org.bouncycastle.cms.CMSAlgorithm.AES256_CBC)
                            .setProvider("BC").build());
            byte[] envelopedDer = enveloped.toASN1Structure().getEncoded(
                    org.bouncycastle.asn1.ASN1Encoding.DER);

            // Build the outer CMS SignedData CertRep
            AttributeTable signedAttrs = certRepAttrs(MSG_CERT_REP, transactionId,
                    STATUS_SUCCESS, null, recipientNonce);
            return buildSignedData(envelopedDer, signedAttrs, raCert, raKey);
        } catch (Exception e) {
            throw new ScepCodecException("Failed to build SCEP CertRep SUCCESS", e);
        }
    }

    /**
     * Builds a SCEP CertRep FAILURE response signed by the RA.
     *
     * @param transactionId  SCEP transaction identifier from the request
     * @param recipientNonce senderNonce from the request
     * @param failInfo       SCEP failInfo value string (e.g., "2" for badRequest)
     * @param raCert         RA signing certificate
     * @param raKey          RA private key for signing
     * @return DER-encoded CMS SignedData CertRep
     * @throws ScepCodecException if encoding fails
     */
    public static byte[] buildCertRepFailure(String transactionId, byte[] recipientNonce,
            String failInfo, X509Certificate raCert, PrivateKey raKey) throws ScepCodecException {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        try {
            AttributeTable signedAttrs = certRepAttrs(MSG_CERT_REP, transactionId,
                    STATUS_FAILURE, failInfo, recipientNonce);
            return buildSignedData(null, signedAttrs, raCert, raKey);
        } catch (Exception e) {
            throw new ScepCodecException("Failed to build SCEP CertRep FAILURE", e);
        }
    }

    /**
     * Builds a SCEP CertRep PENDING response signed by the RA.
     *
     * @param transactionId  SCEP transaction identifier from the request
     * @param recipientNonce senderNonce from the request
     * @param raCert         RA signing certificate
     * @param raKey          RA private key for signing
     * @return DER-encoded CMS SignedData CertRep
     * @throws ScepCodecException if encoding fails
     */
    public static byte[] buildCertRepPending(String transactionId, byte[] recipientNonce,
            X509Certificate raCert, PrivateKey raKey) throws ScepCodecException {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        try {
            AttributeTable signedAttrs = certRepAttrs(MSG_CERT_REP, transactionId,
                    STATUS_PENDING, null, recipientNonce);
            return buildSignedData(null, signedAttrs, raCert, raKey);
        } catch (Exception e) {
            throw new ScepCodecException("Failed to build SCEP CertRep PENDING", e);
        }
    }

    /**
     * Builds a degenerate CMS certs-only {@code SignedData} from the given
     * DER-encoded certificates. Used for GetCACert and GetCACertChain responses.
     *
     * @param certsDer list of DER-encoded certificates in presentation order
     * @return DER-encoded CMS {@code ContentInfo} wrapping {@code SignedData}
     * @throws ScepCodecException if encoding fails
     */
    public static byte[] buildDegenerateCertsCms(List<byte[]> certsDer) throws ScepCodecException {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        try {
            List<X509Certificate> certs = certsDer.stream().map(ScepCodec::parseCertUnchecked).toList();
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addCertificates(new JcaCertStore(certs));
            return gen.generate(new CMSAbsentContent()).getEncoded();
        } catch (Exception e) {
            throw new ScepCodecException("Failed to build degenerate certs-only CMS", e);
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private static AttributeTable certRepAttrs(int messageType, String transactionId,
            String pkiStatus, String failInfo, byte[] recipientNonce) throws IOException {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new Attribute(CMSAttributes.contentType,
                new DERSet(new ASN1ObjectIdentifier("1.2.840.113549.1.7.1"))));
        v.add(new Attribute(ID_MESSAGE_TYPE, new DERSet(new DERPrintableString(String.valueOf(messageType)))));
        v.add(new Attribute(ID_TRANS_ID, new DERSet(new DERPrintableString(transactionId))));
        v.add(new Attribute(ID_PKI_STATUS, new DERSet(new DERPrintableString(pkiStatus))));
        if (failInfo != null) {
            v.add(new Attribute(ID_FAIL_INFO, new DERSet(new DERPrintableString(failInfo))));
        }
        byte[] newNonce = new byte[16];
        SECURE_RANDOM.nextBytes(newNonce);
        v.add(new Attribute(ID_SENDER_NONCE, new DERSet(new DEROctetString(newNonce))));
        if (recipientNonce != null && recipientNonce.length > 0) {
            v.add(new Attribute(ID_RECIPIENT_NONCE, new DERSet(new DEROctetString(recipientNonce))));
        }
        return new AttributeTable(new DERSet(v));
    }

    private static byte[] buildSignedData(byte[] encapContentDer, AttributeTable signedAttrs,
            X509Certificate raCert, PrivateKey raKey) throws Exception {
        String sigAlg = sigAlgorithm(raKey.getAlgorithm());
        org.bouncycastle.operator.ContentSigner raContentSigner =
                new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(raKey);
        org.bouncycastle.operator.DigestCalculatorProvider digestProvider =
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        org.bouncycastle.cms.SignerInfoGenerator sigInfoGen = new JcaSignerInfoGeneratorBuilder(digestProvider)
                .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(signedAttrs))
                .build(raContentSigner, new X509CertificateHolder(raCert.getEncoded()));
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(sigInfoGen);
        gen.addCertificates(new JcaCertStore(List.of(raCert)));
        CMSTypedData content = encapContentDer != null
                ? new CMSProcessableByteArray(encapContentDer)
                : new CMSAbsentContent();
        return gen.generate(content, encapContentDer != null).getEncoded();
    }

    private static String sigAlgorithm(String keyAlg) {
        return switch (keyAlg.toUpperCase(java.util.Locale.ROOT)) {
            case "RSA" -> "SHA256withRSA";
            case "EC", "ECDSA" -> "SHA256withECDSA";
            case "ED25519" -> "Ed25519";
            default -> "SHA256withRSA";
        };
    }

    private static String getAttrPrintableString(AttributeTable attrs, ASN1ObjectIdentifier oid) {
        Attribute attr = attrs.get(oid);
        if (attr == null) { return null; }
        ASN1Encodable[] values = attr.getAttributeValues();
        if (values == null || values.length == 0) { return null; }
        ASN1Encodable val = values[0];
        if (val instanceof DERPrintableString ps) { return ps.getString(); }
        return val.toString();
    }

    // Absent/malformed nonce is null; a present empty OCTET STRING is a distinct wire value.
    @SuppressWarnings("PMD.ReturnEmptyCollectionRatherThanNull")
    private static byte[] getAttrOctetString(AttributeTable attrs, ASN1ObjectIdentifier oid) {
        Attribute attr = attrs.get(oid);
        if (attr == null) { return null; }
        ASN1Encodable[] values = attr.getAttributeValues();
        if (values == null || values.length == 0) { return null; }
        ASN1Encodable val = values[0];
        if (val instanceof DEROctetString os) { return os.getOctets(); }
        return null;
    }

    private static X509Certificate parseCert(byte[] der) throws ScepCodecException {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new ScepCodecException("Cannot parse X.509 certificate", e);
        }
    }

    private static X509Certificate parseCertUnchecked(byte[] der) {
        try {
            return parseCert(der);
        } catch (ScepCodecException e) {
            throw new IllegalArgumentException("Cannot parse certificate", e);
        }
    }
}
