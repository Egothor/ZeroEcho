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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.GenRepContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.RevRepContentBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSSignedDataGenerator;

/**
 * BouncyCastle-backed codec for CMP (RFC 4210 / RFC 9480) ASN.1/DER message
 * encoding and decoding.
 *
 * <p>All operations use BouncyCastle ASN.1 classes directly; no BouncyCastle
 * types appear in method signatures, so callers in other modules do not need a
 * {@code requires org.bouncycastle.*} clause.</p>
 *
 * @since 1.0
 */

public final class CmpCodec {
    private static final int CERT_TEMPLATE_ISSUER_TAG = 3;

    /** CMP PKIBody type: ir (Initialization Request). */
    public static final int BODY_IR = 0;
    /** CMP PKIBody type: ip (Initialization Response). */
    public static final int BODY_IP = 1;
    /** CMP PKIBody type: cr (Certification Request). */
    public static final int BODY_CR = 2;
    /** CMP PKIBody type: cp (Certification Response). */
    public static final int BODY_CP = 3;
    /** CMP PKIBody type: kur (Key Update Request). */
    public static final int BODY_KUR = 7;
    /** CMP PKIBody type: kup (Key Update Response). */
    public static final int BODY_KUP = 8;
    /** CMP PKIBody type: rr (Revocation Request). */
    public static final int BODY_RR = 11;
    /** CMP PKIBody type: rp (Revocation Response). */
    public static final int BODY_RP = 12;
    /** CMP PKIBody type: genm (General Message). */
    public static final int BODY_GENM = 21;
    /** CMP PKIBody type: genp (General Response). */
    public static final int BODY_GENP = 22;
    /** CMP PKIBody type: error. */
    public static final int BODY_ERROR = 23;

    /** OID for the CA certificate infoType in GenMsg/GenRep (RFC 4210 Appendix D.2). */
    private static final String OID_CA_KEY_UPDATE = "1.3.6.1.5.5.7.4.11";

    private CmpCodec() {
    }

    /**
     * Parses a DER-encoded CMP {@code PKIMessage} and extracts key fields for
     * server-side dispatch.
     *
     * @param der DER-encoded CMP {@code PKIMessage}
     * @return parsed message summary
     * @throws CmpCodecException if the DER is malformed or missing required fields
     */
    public static CmpPkiMessage parseMessage(byte[] der) throws CmpCodecException {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        try {
            PKIMessage msg = PKIMessage.getInstance(
                    org.bouncycastle.asn1.ASN1Primitive.fromByteArray(der));
            if (msg == null) {
                throw new CmpCodecException("PKIMessage is null after parsing");
            }
            PKIHeader header = msg.getHeader();
            PKIBody body = msg.getBody();

            int bodyType = body.getType();
            byte[] senderNonce = octetsOrNull(header.getSenderNonce());
            byte[] transactionId = octetsOrNull(header.getTransactionID());

            TemplateFields fields = templateFields(body, bodyType);
            String genMsgOid = bodyType == BODY_GENM ? firstGeneralMessageOid(body) : null;
            return new CmpPkiMessage(bodyType, senderNonce, transactionId,
                    fields.encoded(), fields.issuer(), fields.serial(), genMsgOid, msg.getProtection() != null);
        } catch (CmpCodecException e) {
            throw e;
        } catch (Exception e) {
            throw new CmpCodecException("Failed to parse CMP PKIMessage", e);
        }
    }

    /** Extracted optional template fields retain the codec's best-effort semantics. */
    private record TemplateFields(byte[] encoded, byte[] issuer, BigInteger serial) { }

    private static TemplateFields templateFields(PKIBody body, int bodyType) throws IOException {
        ASN1Encodable template = firstTemplate(body, bodyType);
        if (template == null) {
            return new TemplateFields(null, null, null);
        }
        byte[] encoded = template.toASN1Primitive().getEncoded(ASN1Encoding.DER);
        byte[] issuer = null;
        BigInteger serial = null;
        int serialTag = bodyType == BODY_RR ? 1 : 0;
        try {
            ASN1Sequence sequence = (ASN1Sequence) template;
            for (ASN1Encodable element : sequence) {
                if (element instanceof org.bouncycastle.asn1.ASN1TaggedObject tagged) {
                    if (tagged.getTagNo() == CERT_TEMPLATE_ISSUER_TAG) {
                        issuer = tagged.getBaseObject().toASN1Primitive().getEncoded(ASN1Encoding.DER);
                    }
                    if (tagged.getTagNo() == serialTag) {
                        try {
                            serial = ASN1Integer.getInstance(tagged.getBaseObject()).getValue();
                        } catch (Exception ignored) {
                            // Preserve the last successfully decoded optional serial.
                        }
                    }
                }
            }
        } catch (Exception ignored) {
            // Optional field extraction retains fields decoded before an unsupported element.
        }
        return new TemplateFields(encoded, issuer, serial);
    }

    private static ASN1Encodable firstTemplate(PKIBody body, int bodyType) {
        if (bodyType == BODY_IR || bodyType == BODY_CR || bodyType == BODY_KUR) {
            ASN1Sequence messages = (ASN1Sequence) body.getContent();
            if (messages.size() == 0) { return null; }
            ASN1Sequence message = (ASN1Sequence) messages.getObjectAt(0);
            ASN1Sequence request = (ASN1Sequence) message.getObjectAt(0);
            return request.size() > 1 ? request.getObjectAt(1) : null;
        }
        if (bodyType == BODY_RR) {
            ASN1Sequence content = (ASN1Sequence) body.getContent();
            if (content.size() == 0) { return null; }
            ASN1Sequence details = (ASN1Sequence) content.getObjectAt(0);
            return details.size() > 0 ? details.getObjectAt(0) : null;
        }
        return null;
    }

    private static String firstGeneralMessageOid(PKIBody body) {
        try {
            InfoTypeAndValue[] values = GenMsgContent.getInstance(body.getContent()).toInfoTypeAndValueArray();
            return values != null && values.length > 0 ? values[0].getInfoType().getId() : null;
        } catch (Exception ignored) {
            // Unsupported general-message contents have no recognized OID.
            return null;
        }
    }

    /**
     * Builds a CMP ip (Initialization Response) or cp (Certification Response)
     * containing the issued certificate.
     *
     * @param request       the parsed ir/cr request (for header echoing)
     * @param issuedCertDer DER-encoded issued X.509 certificate
     * @param isIr          true for ir→ip response, false for cr→cp response
     * @return DER-encoded CMP {@code PKIMessage}
     * @throws CmpCodecException if encoding fails
     */
    public static byte[] buildCertResponse(CmpPkiMessage request, byte[] issuedCertDer, boolean isIr)
            throws CmpCodecException {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        try {
            Certificate bcCert = Certificate.getInstance(
                    org.bouncycastle.asn1.ASN1Primitive.fromByteArray(issuedCertDer));
            CMPCertificate cmpCert = new CMPCertificate(bcCert);
            PKIStatusInfo status = new PKIStatusInfo(PKIStatus.granted);
            CertOrEncCert certOrEnc = new CertOrEncCert(cmpCert);
            CertifiedKeyPair ckp = new CertifiedKeyPair(certOrEnc);
            CertResponse response = new CertResponse(new ASN1Integer(0), status, ckp, null);
            CertRepMessage certRep = new CertRepMessage(null, new CertResponse[] { response });
            int responseBodyType = isIr ? BODY_IP : BODY_CP;
            PKIBody body = new PKIBody(responseBodyType, certRep);
            PKIHeader header = buildHeader(request);
            return new PKIMessage(header, body).getEncoded(ASN1Encoding.DER);
        } catch (Exception e) {
            throw new CmpCodecException("Failed to build CMP cert response", e);
        }
    }

    /**
     * Builds a CMP rp (Revocation Response) for the given rr request.
     *
     * @param request the parsed rr request (for header echoing)
     * @return DER-encoded CMP {@code PKIMessage}
     * @throws CmpCodecException if encoding fails
     */
    public static byte[] buildRevocationResponse(CmpPkiMessage request) throws CmpCodecException {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        try {
            PKIStatusInfo status = new PKIStatusInfo(PKIStatus.granted);
            RevRepContentBuilder revRepBuilder = new RevRepContentBuilder();
            revRepBuilder.add(status);
            PKIBody body = new PKIBody(BODY_RP, revRepBuilder.build());
            PKIHeader header = buildHeader(request);
            return new PKIMessage(header, body).getEncoded(ASN1Encoding.DER);
        } catch (Exception e) {
            throw new CmpCodecException("Failed to build CMP revocation response", e);
        }
    }

    /**
     * Builds a CMP genp (General Response) containing the given CA certificate chain.
     *
     * @param request  the parsed genm request (for header echoing)
     * @param certsDer list of DER-encoded certificates in chain order
     * @return DER-encoded CMP {@code PKIMessage}
     * @throws CmpCodecException if encoding fails
     */
    public static byte[] buildGenp(CmpPkiMessage request, List<byte[]> certsDer)
            throws CmpCodecException {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        try {
            // Build a degenerate CMS certs-only SignedData to carry the chain
            List<X509Certificate> certs = new ArrayList<>();
            for (byte[] derCert : certsDer) {
                certs.add((X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(derCert)));
            }
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addCertificates(new JcaCertStore(certs));
            byte[] cmsDer = gen.generate(new CMSAbsentContent()).getEncoded(ASN1Encoding.DER);

            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(OID_CA_KEY_UPDATE);
            InfoTypeAndValue itv = new InfoTypeAndValue(oid,
                    org.bouncycastle.asn1.ASN1Primitive.fromByteArray(cmsDer));
            GenRepContent genRep = new GenRepContent(new InfoTypeAndValue[] { itv });
            PKIBody body = new PKIBody(BODY_GENP, genRep);
            PKIHeader header = buildHeader(request);
            return new PKIMessage(header, body).getEncoded(ASN1Encoding.DER);
        } catch (Exception e) {
            throw new CmpCodecException("Failed to build CMP genp", e);
        }
    }

    /**
     * Builds a CMP error response.
     *
     * @param senderNonce   the senderNonce from the request (becomes recipientNonce), nullable
     * @param transactionId the transactionId from the request, nullable
     * @param statusText    human-readable error description
     * @return DER-encoded CMP {@code PKIMessage}
     * @throws CmpCodecException if encoding fails
     */
    public static byte[] buildError(byte[] senderNonce, byte[] transactionId, String statusText)
            throws CmpCodecException {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        try {
            PKIFreeText freeText = new PKIFreeText(statusText);
            PKIStatusInfo statusInfo = new PKIStatusInfo(PKIStatus.rejection, freeText);
            org.bouncycastle.asn1.cmp.ErrorMsgContent errorMsg =
                    new org.bouncycastle.asn1.cmp.ErrorMsgContent(statusInfo);
            PKIBody body = new PKIBody(BODY_ERROR, errorMsg);
            PKIHeader header = buildErrorHeader(senderNonce, transactionId);
            return new PKIMessage(header, body).getEncoded(ASN1Encoding.DER);
        } catch (Exception e) {
            throw new CmpCodecException("Failed to build CMP error response", e);
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private static PKIHeader buildHeader(CmpPkiMessage request) throws IOException {
        return buildRawHeader(request.senderNonce(), request.transactionId());
    }

    private static PKIHeader buildErrorHeader(byte[] senderNonce, byte[] transactionId) throws IOException {
        return buildRawHeader(senderNonce, transactionId);
    }

    private static PKIHeader buildRawHeader(byte[] recipientNonce, byte[] transactionId) throws IOException {
        // CMP v2 header with null sender/recipient (anonymous server)
        GeneralName sender = new GeneralName(new X500Name("CN=CMP-Server"));
        GeneralName recipient = new GeneralName(new X500Name("CN=CMP-Client"));

        org.bouncycastle.asn1.cmp.PKIHeaderBuilder builder = new org.bouncycastle.asn1.cmp.PKIHeaderBuilder(
                PKIHeader.CMP_2000, sender, recipient);
        builder.setMessageTime(new org.bouncycastle.asn1.DERGeneralizedTime(new Date()));
        if (transactionId != null) {
            builder.setTransactionID(new DEROctetString(transactionId));
        }
        if (recipientNonce != null) {
            // Echo senderNonce as recipientNonce
            builder.setRecipNonce(new DEROctetString(recipientNonce));
        }
        // Generate fresh senderNonce
        byte[] ourNonce = new byte[16];
        new java.security.SecureRandom().nextBytes(ourNonce);
        builder.setSenderNonce(new DEROctetString(ourNonce));
        return builder.build();
    }

    private static byte[] octetsOrNull(ASN1OctetString octetString) {
        return octetString == null ? null : octetString.getOctets();
    }
}
