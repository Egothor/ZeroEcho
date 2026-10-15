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
public final class ScepCodec { // NOPMD CyclomaticComplexity - One closed SCEP cryptographic facade; individual message grammar and signing steps remain complexity-checked.
    private static final int MAXIMUM_CERTIFICATE_COUNT = 16;
    private static final int SINGLE_SIGNER_COUNT = 1;
    private static final int SINGLE_RECIPIENT_COUNT = 1;

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

    /** Maximum accepted encoded request size, before CMS parsing or decryption. */
    public static final int MAXIMUM_REQUEST_BYTES = 1_048_576;

    private ScepCodec() {
    }

    /**
     * Authenticated outer request. Instances can only be produced by successful
     * CMS verification; content remains encrypted until an exact RA is selected.
     */
    public static final class VerifiedRequest { // NOPMD DataClass - Private construction makes this immutable verified-message proof unforgeable; a publicly constructible record would lose that boundary.
        private final int messageType;
        private final String transactionId;
        private final byte[] senderNonce;
        private final byte[] encryptedContent;
        private final X509Certificate requesterCertificate;

        private VerifiedRequest(int type, String transaction, byte[] nonce, byte[] content, X509Certificate certificate) {
            messageType = type; transactionId = transaction; senderNonce = nonce.clone();
            encryptedContent = content.clone(); requesterCertificate = certificate;
        }
        /** Returns the authenticated operation.
         * @return supported message type
         */
        public int messageType() { return messageType; }
        /** Returns the authenticated transaction.
         * @return bounded transaction identifier
         */
        public String transactionId() { return transactionId; }
        /** Copies the current request nonce.
         * @return independent nonce bytes
         */
        public byte[] senderNonce() { return senderNonce.clone(); }
        /** Returns verified key-control evidence, without a trust assertion.
         * @return signer certificate
         */
        public X509Certificate requesterCertificate() { return requesterCertificate; }
        /** @return redacted message description */
        @Override public String toString() { return "VerifiedRequest[messageType=" + messageType + "]"; }
    }

    /**
     * Verifies a bounded CMS request before any private-key decryption. Requires
     * one signer and one matching certificate, SHA-256/RSA, authenticated
     * id-data content, and strictly typed singular SCEP attributes.
     * Certificate possession is proven; identity authorization is the caller's job.
     * @param cmsDer complete encoded CMS message
     * @return authenticated outer envelope
     * @throws ScepCodecException for malformed or unsupported messages or invalid signatures
     */
    public static VerifiedRequest verifyRequest(byte[] cmsDer) throws ScepCodecException {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        try {
            CMSSignedData data = signedRequest(cmsDer);
            SignerInformation signer = data.getSignerInfos().getSigners().iterator().next();
            requireSupportedSignature(signer);
            RequestAttributes attributes = requestAttributes(signer.getSignedAttributes());
            X509Certificate certificate = verifySigner(data, signer);
            byte[] encrypted = (byte[]) data.getSignedContent().getContent();
            requireBound(encrypted);
            return new VerifiedRequest(attributes.messageType(), attributes.transactionId(),
                    attributes.nonce(), encrypted, certificate);
        } catch (IOException | java.security.cert.CertificateException | org.bouncycastle.cms.CMSException
                | org.bouncycastle.operator.OperatorCreationException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException - Provider failures must not disclose raw enrollment input.
            throw invalid(); // NOPMD PreserveStackTrace - Malformed enrollment input may contain secrets; expose only the fixed protocol failure.
        }
    }

    private static CMSSignedData signedRequest(byte[] cmsDer)
            throws IOException, org.bouncycastle.cms.CMSException, ScepCodecException {
        requireBound(cmsDer);
        org.bouncycastle.asn1.cms.ContentInfo outer = org.bouncycastle.asn1.cms.ContentInfo.getInstance(
                org.bouncycastle.asn1.ASN1Primitive.fromByteArray(cmsDer));
        if (!PKCSObjectIdentifiers.signedData.equals(outer.getContentType())) {
            throw invalid();
        }
        CMSSignedData data = new CMSSignedData(outer);
        if (data.getSignerInfos().getSigners().size() != 1 || data.getSignedContent() == null
                || !PKCSObjectIdentifiers.data.getId().equals(data.getSignedContentTypeOID())
                || !data.getCRLs().getMatches(null).isEmpty()) {
            throw invalid();
        }
        return data;
    }

    private static void requireSupportedSignature(SignerInformation signer) throws IOException, ScepCodecException {
        if (!"2.16.840.1.101.3.4.2.1".equals(signer.getDigestAlgOID())
                || !nullParameters(signer.getDigestAlgParams())
                || !(PKCSObjectIdentifiers.rsaEncryption.getId().equals(signer.getEncryptionAlgOID())
                || PKCSObjectIdentifiers.sha256WithRSAEncryption.getId().equals(signer.getEncryptionAlgOID()))
                || !nullParameters(signer.getEncryptionAlgParams())
                || signer.getUnsignedAttributes() != null) {
            throw invalid();
        }
    }

    private static RequestAttributes requestAttributes(AttributeTable attributes) throws ScepCodecException {
        validateAttributeSet(attributes);
        if (!PKCSObjectIdentifiers.data.equals(single(attributes, CMSAttributes.contentType))) {
            throw invalid();
        }
        if (!(single(attributes, CMSAttributes.messageDigest) instanceof org.bouncycastle.asn1.ASN1OctetString digest)
                || digest.getOctets().length != 32) {
            throw invalid();
        }
        if (attributes.get(CMSAttributes.signingTime) != null) {
            org.bouncycastle.asn1.cms.Time.getInstance(single(attributes, CMSAttributes.signingTime)).getDate();
        }
        String type = printable(single(attributes, ID_MESSAGE_TYPE));
        int messageType = switch (type) {
            case "19" -> MSG_PKCS_REQ;
            case "20" -> MSG_GET_CERT_INITIAL;
            default -> throw invalid();
        };
        String transaction = printable(single(attributes, ID_TRANS_ID));
        if (transaction.isEmpty() || transaction.length() > 128) {
            throw invalid();
        }
        byte[] nonce = nonce(single(attributes, ID_SENDER_NONCE));
        if (attributes.get(ID_RECIPIENT_NONCE) != null) {
            nonce(single(attributes, ID_RECIPIENT_NONCE));
        }
        return new RequestAttributes(messageType, transaction, nonce);
    }

    private static void validateAttributeSet(AttributeTable attributes) throws ScepCodecException {
        if (attributes == null || attributes.size() < 5 || attributes.size() > 8) {
            throw invalid();
        }
        ASN1EncodableVector entries = attributes.toASN1EncodableVector();
        java.util.Set<ASN1ObjectIdentifier> seen = new java.util.HashSet<>();
        for (int index = 0; index < entries.size(); index++) {
            Attribute entry = Attribute.getInstance(entries.get(index));
            if (!seen.add(entry.getAttrType()) || entry.getAttrValues().size() != 1
                    || !supportedAttribute(entry.getAttrType())) {
                throw invalid();
            }
        }
    }

    private static boolean supportedAttribute(ASN1ObjectIdentifier oid) {
        return oid.equals(CMSAttributes.contentType) || oid.equals(CMSAttributes.messageDigest)
                || oid.equals(CMSAttributes.signingTime) || oid.equals(CMSAttributes.cmsAlgorithmProtect)
                || oid.equals(ID_MESSAGE_TYPE) || oid.equals(ID_TRANS_ID)
                || oid.equals(ID_SENDER_NONCE) || oid.equals(ID_RECIPIENT_NONCE);
    }

    private static X509Certificate verifySigner(CMSSignedData data, SignerInformation signer)
            throws java.security.cert.CertificateException, org.bouncycastle.cms.CMSException,
            org.bouncycastle.operator.OperatorCreationException, ScepCodecException {
        Store<X509CertificateHolder> certificates = data.getCertificates();
        if (certificates.getMatches(null).size() > MAXIMUM_CERTIFICATE_COUNT) {
            throw invalid();
        }
        Collection<X509CertificateHolder> matches = certificates.getMatches(signer.getSID());
        if (matches.size() != SINGLE_SIGNER_COUNT) {
            throw invalid();
        }
        X509CertificateHolder holder = matches.iterator().next();
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
        requireRsa(certificate);
        if (!signer.verify(new org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(holder))) {
            throw invalid();
        }
        return certificate;
    }

    private record RequestAttributes(int messageType, String transactionId, byte[] nonce) { }
    /**
     * Decrypts an already verified request using one exact provisioned RA recipient.
     * Requires AES-128-CBC, RSA key transport, and exactly one matching recipient;
     * there is no trial decryption or fallback to another credential.
     * @param request authenticated envelope
     * @param raCertificate exact provisioned recipient certificate
     * @param raPrivateKey matching private key borrowed under its custody lease
     * @return verified attributes and independently owned plaintext request
     * @throws ScepCodecException for an invalid envelope, recipient or decryption
     */
    public static ScepPkiMessage decryptRequest(VerifiedRequest request, X509Certificate raCertificate, PrivateKey raPrivateKey)
            throws ScepCodecException {
        try {
            java.util.Objects.requireNonNull(request, "request");
            requireRsa(raCertificate);
            org.bouncycastle.asn1.cms.ContentInfo inner = org.bouncycastle.asn1.cms.ContentInfo.getInstance(
                    org.bouncycastle.asn1.ASN1Primitive.fromByteArray(request.encryptedContent));
            if (!PKCSObjectIdentifiers.envelopedData.equals(inner.getContentType())
                    || !PKCSObjectIdentifiers.data.equals(org.bouncycastle.asn1.cms.EnvelopedData.getInstance(inner.getContent())
                    .getEncryptedContentInfo().getContentType())) {
                throw invalid();
            }
            CMSEnvelopedData envelope = new CMSEnvelopedData(inner);
            if (!org.bouncycastle.cms.CMSAlgorithm.AES128_CBC.getId().equals(envelope.getEncryptionAlgOID())
                    || !(org.bouncycastle.asn1.ASN1Primitive.fromByteArray(envelope.getEncryptionAlgParams())
                    instanceof org.bouncycastle.asn1.ASN1OctetString iv) || iv.getOctets().length != 16
                    || envelope.getUnprotectedAttributes() != null || envelope.getOriginatorInfo() != null) {
                throw invalid();
            }
            org.bouncycastle.cms.RecipientInformation recipient = recipient(envelope, raCertificate);
            byte[] plaintext = recipient.getContent(new JceKeyTransEnvelopedRecipient(raPrivateKey).setProvider("BC"));
            requireBound(plaintext);
            return new ScepPkiMessage(request.messageType, request.transactionId, request.senderNonce, plaintext, request.requesterCertificate);
        } catch (IOException | java.security.cert.CertificateEncodingException
                | org.bouncycastle.cms.CMSException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException - Recipient and provider failures share the fixed protocol failure.
            throw invalid(); // NOPMD PreserveStackTrace - Recipient and provider causes can expose protected content; preserve the fixed protocol failure.
        }
    }

    private static org.bouncycastle.cms.RecipientInformation recipient(CMSEnvelopedData envelope,
            X509Certificate raCertificate) throws IOException, java.security.cert.CertificateEncodingException, ScepCodecException {
        Collection<org.bouncycastle.cms.RecipientInformation> recipients = envelope.getRecipientInfos().getRecipients();
        if (recipients.size() != SINGLE_RECIPIENT_COUNT) {
            throw invalid();
        }
        org.bouncycastle.cms.RecipientInformation recipient = recipients.iterator().next();
        if (!(recipient instanceof org.bouncycastle.cms.KeyTransRecipientInformation)
                || !recipient.getRID().match(new X509CertificateHolder(raCertificate.getEncoded()))
                || !PKCSObjectIdentifiers.rsaEncryption.getId().equals(recipient.getKeyEncryptionAlgOID())
                || !nullParameters(recipient.getKeyEncryptionAlgParams())) {
            throw invalid();
        }
        return recipient;
    }

    /**
     * Validates an IssuerAndSubject poll against the frozen issuer and original CSR.
     * @param encoded exact decrypted poll
     * @param issuer frozen issuing CA subject
     * @param subject original CSR subject
     * @throws ScepCodecException if either name differs or the encoding is malformed
     */
    public static void requireIssuerAndSubject(byte[] encoded, javax.security.auth.x500.X500Principal issuer,
            javax.security.auth.x500.X500Principal subject) throws ScepCodecException {
        try {
            requireBound(encoded);
            org.bouncycastle.asn1.ASN1Sequence sequence = org.bouncycastle.asn1.ASN1Sequence.getInstance(
                    org.bouncycastle.asn1.ASN1Primitive.fromByteArray(encoded));
            if (sequence.size() != 2
                    || !new javax.security.auth.x500.X500Principal(org.bouncycastle.asn1.x500.X500Name.getInstance(sequence.getObjectAt(0)).getEncoded()).equals(issuer)
                    || !new javax.security.auth.x500.X500Principal(org.bouncycastle.asn1.x500.X500Name.getInstance(sequence.getObjectAt(1)).getEncoded()).equals(subject)) {
                throw invalid();
            }
        } catch (IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException - Provider and untrusted-input failures are normalized before crossing the public trust boundary.
            throw invalid(); // NOPMD PreserveStackTrace - Malformed enrollment input may contain secrets; expose only the fixed protocol failure.
        }
    }

    private static ASN1Encodable single(AttributeTable attributes, ASN1ObjectIdentifier oid) throws ScepCodecException {
        if (attributes.getAll(oid).size() != 1 || attributes.get(oid).getAttrValues().size() != 1) {
            throw invalid();
        }
        return attributes.get(oid).getAttrValues().getObjectAt(0);
    }

    private static String printable(ASN1Encodable value) throws ScepCodecException {
        if (!(value instanceof org.bouncycastle.asn1.ASN1PrintableString string)
                || !org.bouncycastle.asn1.ASN1PrintableString.isPrintableString(string.getString())) {
            throw invalid();
        }
        return string.getString();
    }

    private static byte[] nonce(ASN1Encodable value) throws ScepCodecException {
        if (!(value instanceof org.bouncycastle.asn1.ASN1OctetString octets) || octets.getOctets().length != 16) {
            throw invalid();
        }
        return octets.getOctets();
    }

    private static boolean nullParameters(byte[] parameters) throws IOException {
        return parameters == null || org.bouncycastle.asn1.ASN1Primitive.fromByteArray(parameters) instanceof org.bouncycastle.asn1.ASN1Null;
    }

    private static void requireRsa(X509Certificate certificate) throws ScepCodecException {
        if (!(certificate.getPublicKey() instanceof java.security.interfaces.RSAPublicKey key)
                || key.getModulus().bitLength() < 2048 || key.getModulus().bitLength() > 8192) {
            throw invalid();
        }
        zeroecho.pkix.PublicKeyIdentity.fromSubjectPublicKeyInfo(zeroecho.pkix.Pkix.subjectPublicKeyInfo(certificate));
    }

    private static void requireBound(byte[] value) throws ScepCodecException {
        if (value == null || value.length == 0 || value.length > MAXIMUM_REQUEST_BYTES) {
            throw invalid();
        }
    }

    private static ScepCodecException invalid() { return new ScepCodecException("Invalid or unsupported SCEP message"); }

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
            requireBound(csrDer);
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrDer);
            org.bouncycastle.asn1.pkcs.Attribute[] attrs =
                    csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
            if (attrs.length == 0) {
                return null;
            }
            if (attrs.length != 1 || attrs[0].getAttrValues().size() != 1) {
                throw invalid();
            }
            return new zeroecho.pkix.csr.CsrAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword.getId(),
                    List.of(attrs[0].getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded())).challengePassword();
        } catch (IOException | RuntimeException e) { // NOPMD AvoidCatchingGenericException - Provider and untrusted-input failures are normalized before crossing the public trust boundary.
            throw new ScepCodecException("Cannot extract challengePassword from CSR"); // NOPMD PreserveStackTrace - Malformed enrollment input may contain secrets; expose only the fixed protocol failure.
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
                    new JceCMSContentEncryptorBuilder(org.bouncycastle.cms.CMSAlgorithm.AES128_CBC)
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
            default -> throw new IllegalArgumentException("Unsupported SCEP response signing algorithm");
        };
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
