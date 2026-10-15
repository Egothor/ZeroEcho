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

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pkix.PublicKeyIdentity;

/**
 * Immutable bounded CMP request with exact canonical protected bytes. Parsing
 * grants no authentication; only a successful verification creates {@link Verified}.
 * A verified proof still grants no certificate trust, ownership or RA authority.
 * The server must apply those policies separately before any durable mutation.
 *
 * <p>Supports singular ir/cr/kur, rr, caCerts genm, pollReq and certConf requests
 * under CMP versions 2 and 3. Signature protection supports RSA 2048..8192 with
 * SHA-256/384/512 and named P-256/P-384/P-521 ECDSA with those digests. PSS,
 * explicit EC and alternative protection modes are rejected without fallback.</p>
 *
 * <p>Parsing and owned memory are O(N), bounded by one MiB and 64 ASN.1 levels.
 * PBM work is O(I + N), for configured bounded iterations I; no secret is retained.
 * Instances are thread-safe; callers exclusively own every returned byte array.</p>
 */
public final class CmpProtectedMessage { // NOPMD CyclomaticComplexity, TooManyMethods - One immutable CMP message/proof facade; individual grammar, verification and response methods remain complexity-checked.
    private static final int SINGLE_REQUEST_COUNT = 1;
    private static final int POLL_REQUEST_FIELD_COUNT = 1;
    private static final int CONFIRMATION_STATUS_FIELDS = 1;
    private static final int REVOCATION_TEMPLATE_FIELDS = 2;
    private static final int MESSAGE_WITH_CERT_FIELDS = 4;
    private static final int HEADER_GENERAL_INFO_TAG = 8;
    private static final int MAX_KEY_ID_EXTENSION_BYTES = 256;
    private static final int MAXIMUM_NAME_BYTES = 4_096;
    private static final String SHA_256 = "SHA-256";
    private static final String SHA_384 = "SHA-384";

    /** Maximum complete incoming message size. */
    public static final int MAXIMUM_MESSAGE_BYTES = 1_048_576;
    /** Maximum supported request certificate candidates. */
    public static final int MAXIMUM_EXTRA_CERTIFICATES = 33;
    private static final String PBM_OID = "1.2.840.113533.7.66.13";
    private final byte[] encoded;
    private final PKIMessage message;
    private final byte[] protectedBytes;
    private final BigInteger requestId;
    private final byte[] requestDer;
    private final Optional<CrmfRequest.CertificateReference> revoked;
    private final int revocationReason;
    private final byte[] confirmationHash;
    private final Optional<String> confirmationHashAlgorithm;
    private final boolean confirmationAccepted;
    private final boolean implicitConfirmation;

    private CmpProtectedMessage(byte[] encoded, PKIMessage message) throws IOException {
        this.encoded = encoded;
        this.message = message;
        protectedBytes = new DERSequence(new ASN1Encodable[] { message.getHeader(), message.getBody() })
                .getEncoded(ASN1Encoding.DER);
        validateHeader(message);
        implicitConfirmation = implicit(message.getHeader());
        ParsedBody body = parseBody(message.getBody(), message.getHeader().getPvno().intValueExact());
        if (implicitConfirmation && !isEnrollment(message.getBody().getType())) {
            throw invalid();
        }
        requestId = body.id();
        requestDer = body.original();
        revoked = body.revocation();
        revocationReason = body.reason();
        confirmationHash = body.hash();
        confirmationHashAlgorithm = body.hashAlgorithm();
        confirmationAccepted = body.accepted();
    }

    private static void validateHeader(PKIMessage message) {
        PKIHeader header = message.getHeader();
        int version = header.getPvno().intValueExact();
        if (version != PKIHeader.CMP_2000 && version != PKIHeader.CMP_2021) {
            throw invalid();
        }
        name(header.getSender());
        name(header.getRecipient());
        octets(header.getTransactionID(), 16, 128);
        octets(header.getSenderNonce(), 16, 32);
        if (header.getRecipNonce() != null) {
            octets(header.getRecipNonce(), 16, 32);
        }
        if (header.getSenderKID() != null) {
            octets(header.getSenderKID(), 1, 128);
        }
        if (header.getRecipKID() != null) {
            octets(header.getRecipKID(), 1, 128);
        }
        validateProtection(message);
        if (header.getFreeText() != null) {
            throw invalid();
        }
        if (header.getMessageTime() != null) {
            try {
                header.getMessageTime().getDate();
            } catch (java.text.ParseException failure) {
                throw invalid(); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
            }
        }
        validateExtraCertificates(message.getExtraCerts());
    }

    private static void validateProtection(PKIMessage message) {
        PKIHeader header = message.getHeader();
        if (header.getProtectionAlg() == null || message.getProtection() == null
                || message.getProtection().getPadBits() != 0 || message.getProtection().getOctets().length == 0
                || message.getProtection().getOctets().length > 1024) {
            throw invalid();
        }
        if (PBM_OID.equals(header.getProtectionAlg().getAlgorithm().getId()) && header.getSenderKID() == null) {
            throw invalid();
        }
    }

    private static void validateExtraCertificates(CMPCertificate... candidates) {
        if (candidates == null) {
            return;
        }
        if (candidates.length == 0 || candidates.length > MAXIMUM_EXTRA_CERTIFICATES) {
            throw invalid();
        }
        for (CMPCertificate candidate : candidates) {
            if (!candidate.isX509v3PKCert()) {
                throw invalid();
            }
        }
    }

    private static boolean isEnrollment(int type) {
        return type == PKIBody.TYPE_INIT_REQ || type == PKIBody.TYPE_CERT_REQ || type == PKIBody.TYPE_KEY_UPDATE_REQ;
    }

    private static ParsedBody parseBody(PKIBody body, int version) throws IOException {
        ASN1Sequence content = ASN1Sequence.getInstance(body.getContent());
        if (content.size() != SINGLE_REQUEST_COUNT) {
            throw invalid();
        }
        ASN1Encodable value = content.getObjectAt(0);
        return switch (body.getType()) {
            case PKIBody.TYPE_INIT_REQ, PKIBody.TYPE_CERT_REQ, PKIBody.TYPE_KEY_UPDATE_REQ ->
                    enrollmentBody(value, body.getType());
            case PKIBody.TYPE_POLL_REQ -> pollBody(value);
            case PKIBody.TYPE_CERT_CONFIRM -> confirmationBody(value, version);
            case PKIBody.TYPE_REVOCATION_REQ -> revocationBody(value);
            case PKIBody.TYPE_GEN_MSG -> generalBody(value);
            default -> throw invalid();
        };
    }

    private static ParsedBody enrollmentBody(ASN1Encodable value, int type) throws IOException {
        byte[] original = value.toASN1Primitive().getEncoded(ASN1Encoding.DER);
        CrmfRequest request = CrmfRequest.parse(original);
        if (type == PKIBody.TYPE_KEY_UPDATE_REQ != request.oldCertificate().isPresent()) {
            throw invalid();
        }
        return new ParsedBody(request.requestId(), original, Optional.empty(), 0, null, Optional.empty(), true);
    }

    private static ParsedBody pollBody(ASN1Encodable value) {
        ASN1Sequence entry = ASN1Sequence.getInstance(value);
        if (entry.size() != POLL_REQUEST_FIELD_COUNT) {
            throw invalid();
        }
        return new ParsedBody(identifier(entry.getObjectAt(0)), null, Optional.empty(), 0, null, Optional.empty(), true);
    }

    private static ParsedBody confirmationBody(ASN1Encodable value, int version) {
        ASN1Sequence entry = ASN1Sequence.getInstance(value);
        if (entry.size() < 2 || entry.size() > 4) {
            throw invalid();
        }
        byte[] hash = ASN1OctetString.getInstance(entry.getObjectAt(0)).getOctets();
        requireConfirmationHashLength(hash);
        BigInteger id = identifier(entry.getObjectAt(1));
        int next = 2;
        boolean accepted = true;
        if (entry.size() > next && entry.getObjectAt(next) instanceof ASN1Sequence) {
            accepted = confirmationStatus(ASN1Sequence.getInstance(entry.getObjectAt(next++)));
        }
        Optional<String> hashAlgorithm = Optional.empty();
        if (entry.size() > next) {
            if (version != PKIHeader.CMP_2021) {
                throw invalid();
            }
            hashAlgorithm = Optional.of(confirmationDigest(tagged(entry.getObjectAt(next++), 0).getExplicitBaseObject()));
        }
        if (next != entry.size()) {
            throw invalid();
        }
        if (hashAlgorithm.isPresent() && hash.length != switch (hashAlgorithm.orElseThrow()) {
            case SHA_256 -> 32;
            case SHA_384 -> 48;
            default -> 64;
        }) {
            throw invalid();
        }
        return new ParsedBody(id, null, Optional.empty(), 0, hash, hashAlgorithm, accepted);
    }

    private static void requireConfirmationHashLength(byte[] hash) {
        if (hash.length != 32 && hash.length != 48 && hash.length != 64) {
            throw invalid();
        }
    }

    private static boolean confirmationStatus(ASN1Sequence status) {
        if (status.size() != CONFIRMATION_STATUS_FIELDS) {
            throw invalid();
        }
        int code = ASN1Integer.getInstance(status.getObjectAt(0)).intValueExact();
        if (code != PKIStatus.GRANTED && code != PKIStatus.REJECTION) {
            throw invalid();
        }
        return code == PKIStatus.GRANTED;
    }

    private static ParsedBody revocationBody(ASN1Encodable value) throws IOException {
        ASN1Sequence details = ASN1Sequence.getInstance(value);
        if (details.size() < 1 || details.size() > 2) {
            throw invalid();
        }
        ASN1Sequence template = ASN1Sequence.getInstance(details.getObjectAt(0));
        if (template.size() != REVOCATION_TEMPLATE_FIELDS) {
            throw invalid();
        }
        ASN1TaggedObject serial = tagged(template.getObjectAt(0), 1);
        ASN1TaggedObject issuer = tagged(template.getObjectAt(1), 3);
        CrmfRequest.CertificateReference revocation = new CrmfRequest.CertificateReference(
                new X500Principal(org.bouncycastle.asn1.x500.X500Name.getInstance(issuer, true).getEncoded()),
                ASN1Integer.getInstance(serial, false).getValue());
        int reason = details.size() == 2 ? revocationReason(details.getObjectAt(1)) : 0;
        return new ParsedBody(BigInteger.ZERO, null, Optional.of(revocation), reason, null, Optional.empty(), true);
    }

    private static int revocationReason(ASN1Encodable value) {
        org.bouncycastle.asn1.x509.Extensions extensions = org.bouncycastle.asn1.x509.Extensions.getInstance(value);
        ASN1ObjectIdentifier[] ids = extensions.getExtensionOIDs();
        if (ids.length != 1 || !ids[0].equals(org.bouncycastle.asn1.x509.Extension.reasonCode)) {
            throw invalid();
        }
        org.bouncycastle.asn1.x509.Extension extension = extensions.getExtension(ids[0]);
        if (extension.isCritical()) {
            throw invalid();
        }
        int reason = org.bouncycastle.asn1.ASN1Enumerated.getInstance(extension.getParsedValue()).intValueExact();
        if (reason < 0 || reason > 10 || reason == 6 || reason == 7 || reason == 8) {
            throw invalid();
        }
        return reason;
    }

    private static ParsedBody generalBody(ASN1Encodable value) {
        ASN1Sequence info = ASN1Sequence.getInstance(value);
        if (info.size() != 1 || !CMPObjectIdentifiers.id_it_caCerts.equals(info.getObjectAt(0))) {
            throw invalid();
        }
        return new ParsedBody(BigInteger.ZERO, null, Optional.empty(), 0, null, Optional.empty(), true);
    }

    private record ParsedBody(BigInteger id, byte[] original, Optional<CrmfRequest.CertificateReference> revocation,
            int reason, byte[] hash, Optional<String> hashAlgorithm, boolean accepted) { }
    /**
     * Parses exactly one canonical DER request and the closed supported grammar.
     * Unknown fields, multiple requests, missing protection and trailing data fail.
     * @param der bounded caller-owned message, defensively copied
     * @return immutable unauthenticated message
     * @throws IllegalArgumentException if the message is malformed or unsupported
     */
    public static CmpProtectedMessage parse(byte[] der) {
        if (der == null || der.length == 0 || der.length > MAXIMUM_MESSAGE_BYTES) {
            throw invalid();
        }
        byte[] snapshot = der.clone();
        CrmfRequest.validateStructure(snapshot);
        try {
            ASN1Sequence outer = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(snapshot));
            if (outer.size() < 3 || outer.size() > 4) {
                throw invalid();
            }
            tagged(outer.getObjectAt(2), 0);
            if (outer.size() == MESSAGE_WITH_CERT_FIELDS) {
                tagged(outer.getObjectAt(3), 1);
            }
            validateHeaderFields(ASN1Sequence.getInstance(outer.getObjectAt(0)));
            PKIMessage message = PKIMessage.getInstance(outer);
            if (!Arrays.equals(snapshot, message.getEncoded(ASN1Encoding.DER))) {
                throw invalid();
            }
            return new CmpProtectedMessage(snapshot, message);
        } catch (IOException | RuntimeException failure) { throw invalid(); } // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl, PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }

    private static void validateHeaderFields(ASN1Sequence header) {
        if (header.size() < 3 || header.size() > 12) {
            throw invalid();
        }
        int previous = -1;
        for (int i = 3; i < header.size(); i++) {
            ASN1TaggedObject field = ASN1TaggedObject.getInstance(header.getObjectAt(i));
            if (field.getTagClass() != BERTags.CONTEXT_SPECIFIC || field.getTagNo() <= previous || field.getTagNo() > 8) {
                throw invalid();
            }
            if (field.getTagNo() == HEADER_GENERAL_INFO_TAG) {
                ASN1Sequence values = ASN1Sequence.getInstance(field.getExplicitBaseObject());
                if (values.size() != 1 || ASN1Sequence.getInstance(values.getObjectAt(0)).size() != 2) {
                    throw invalid();
                }
            }
            previous = field.getTagNo();
        }
    }

    /** {@return a defensive copy of the complete canonical request} */
    public byte[] encoded() { return encoded.clone(); }
    /** {@return the CMP body tag} */
    public int bodyType() { return message.getBody().getType(); }
    /** {@return the bounded request ID, or zero for requests without a CertReqId} */
    public BigInteger requestId() { return requestId; }
    /** {@return the exact original CertReqMsg, when this is an enrollment request} */
    public Optional<byte[]> certificationRequest() { return requestDer == null ? Optional.empty() : Optional.of(requestDer.clone()); }
    /** {@return the immutable revocation reference, when this is rr} */
    public Optional<CrmfRequest.CertificateReference> revokedCertificate() { return revoked; }
    /** {@return the requested permanent revocation reason, or unspecified zero} */
    public int revocationReason() { return revocationReason; }
    /** {@return a defensive confirmation hash, when this is certConf} */
    public Optional<byte[]> confirmationHash() { return confirmationHash == null ? Optional.empty() : Optional.of(confirmationHash.clone()); }
    /** {@return the explicit RFC 9480 confirmation hash name, present only in version-three certConf} */
    public Optional<String> confirmationHashAlgorithm() { return confirmationHashAlgorithm; }
    /** {@return whether a certConf accepts rather than rejects the certificate} */
    public boolean confirmationAccepted() { return confirmationAccepted; }
    /** {@return whether this enrollment explicitly requested implicit confirmation} */
    public boolean requestsImplicitConfirmation() { return implicitConfirmation; }
    /** {@return whether the declared protection mode is standard PBM; not proof validity} */
    public boolean isPbm() { return PBM_OID.equals(message.getHeader().getProtectionAlg().getAlgorithm().getId()); }
    /** {@return a defensive transaction identifier} */
    public byte[] transactionId() { return message.getHeader().getTransactionID().getOctets().clone(); }
    /** {@return a defensive sender nonce} */
    public byte[] senderNonce() { return message.getHeader().getSenderNonce().getOctets().clone(); }
    /** {@return the optional defensive recipient nonce} */
    public Optional<byte[]> recipientNonce() { return optional(message.getHeader().getRecipNonce()); }
    /** {@return the optional defensive sender key identifier} */
    public Optional<byte[]> senderKid() { return optional(message.getHeader().getSenderKID()); }
    /** {@return the optional defensive recipient key identifier for exact credential selection} */
    public Optional<byte[]> recipientKid() { return optional(message.getHeader().getRecipKID()); }
    /** {@return the sender's immutable distinguished name} */
    public X500Principal sender() { return name(message.getHeader().getSender()); }
    /** {@return the recipient's immutable distinguished name} */
    public X500Principal recipient() { return name(message.getHeader().getRecipient()); }
    /** {@return the optional sender time; the server applies its freshness policy} */
    public Optional<Instant> messageTime() {
        try { return message.getHeader().getMessageTime() == null ? Optional.empty() : Optional.of(message.getHeader().getMessageTime().getDate().toInstant()); }
        catch (java.text.ParseException impossible) { throw invalid(); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }
    /**
     * Returns untrusted certificate candidates; these are outside the protected bytes.
     * @return immutable list of defensive certificate DER arrays
     */
    public List<byte[]> extraCertificates() {
        List<byte[]> result = new ArrayList<>();
        CMPCertificate[] certificates = message.getExtraCerts();
        if (certificates != null) {
            for (CMPCertificate certificate : certificates) {
            try { result.add(certificate.getEncoded(ASN1Encoding.DER)); } catch (IOException failure) { throw invalid(); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
        }
        return List.copyOf(result);
    }

    /**
     * Returns the exact certificate key identifier used by signature protection.
     * A present subjectKeyIdentifier extension takes precedence and must contain
     * one through 128 bytes. If absent, SHA-256 of the exact encoded SPKI is used.
     * This identifier is only a routing constraint, never a trust assertion.
     * @param certificate selected certificate
     * @return caller-owned key identifier
     * @throws IllegalArgumentException if the extension or public key is malformed
     */
    public static byte[] certificateKeyId(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        try {
            byte[] extension = certificate.getExtensionValue(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier.getId());
            if (extension == null) {
                return MessageDigest.getInstance(SHA_256).digest(certificate.getPublicKey().getEncoded());
            }
            if (extension.length > MAX_KEY_ID_EXTENSION_BYTES) {
                throw invalid();
            }
            byte[] inner = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(extension)).getOctets();
            byte[] identifier = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(inner)).getOctets();
            if (identifier.length == 0 || identifier.length > 128) {
                throw invalid();
            }
            return identifier.clone();
        } catch (IOException | GeneralSecurityException | RuntimeException failure) { throw invalid(); } // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl, PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }

    /**
     * Computes the CMP certificate-confirmation hash using the hash component of
     * a supported RSA or ECDSA certificate signature. RSA-PSS uses its explicit
     * digest parameters. This operation does not verify certificate trust.
     * @param certificateDer exact issued DER certificate, at most one MiB
     * @return defensive SHA-256, SHA-384 or SHA-512 digest
     * @throws IllegalArgumentException if the certificate or digest selection is unsupported
     */
    public static byte[] certificateConfirmationHash(byte[] certificateDer) {
        return certificateConfirmationHash(certificateDer, Optional.empty());
    }

    /**
     * Hashes an exact certificate for confirmation. RSA, ECDSA and RSA-PSS use
     * their signature digest and any explicit choice must agree. Supported
     * signatures without an encoded digest require an explicit SHA-256,
     * SHA-384 or SHA-512 choice from a version-three certConf message. This
     * operation does not establish certificate trust or protocol authentication.
     * @param certificateDer exact DER certificate, at most one MiB
     * @param explicitDigest validated confirmation hash name, if supplied
     * @return digest of the complete original certificate DER
     * @throws IllegalArgumentException for malformed, inconsistent or unsupported input
     */
    public static byte[] certificateConfirmationHash(byte[] certificateDer, Optional<String> explicitDigest) {
        if (certificateDer == null || certificateDer.length == 0 || certificateDer.length > MAXIMUM_MESSAGE_BYTES) {
            throw invalid();
        }
        Objects.requireNonNull(explicitDigest, "explicitDigest");
        if (explicitDigest.filter(value -> !Set.of(SHA_256, SHA_384, "SHA-512").contains(value)).isPresent()) {
            throw invalid();
        }
        try {
            CrmfRequest.validateStructure(certificateDer);
            X509Certificate certificate = zeroecho.pkix.Pkix.parseCertificate(certificateDer);
            AlgorithmIdentifier algorithm = org.bouncycastle.asn1.x509.Certificate.getInstance(certificateDer).getSignatureAlgorithm();
            if (certificate.getSigAlgOID().startsWith("1.2.840.10045.4.3.") && algorithm.getParameters() != null) {
                throw invalid();
            }
            if (Set.of("1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13").contains(certificate.getSigAlgOID())) {
                nullOrAbsent(algorithm);
            }
            String digest = certificateDigest(certificate, algorithm, explicitDigest);
            if (!Set.of(SHA_256, SHA_384, "SHA-512").contains(digest)) {
                throw invalid();
            }
            if (explicitDigest.filter(value -> !value.equals(digest)).isPresent()) {
                throw invalid();
            }
            return MessageDigest.getInstance(digest).digest(certificateDer);
        } catch (IOException | GeneralSecurityException | RuntimeException failure) { throw invalid(); } // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl, PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }

    private static String certificateDigest(X509Certificate certificate, AlgorithmIdentifier algorithm,
            Optional<String> explicitDigest) throws GeneralSecurityException, IOException {
        return switch (certificate.getSigAlgOID()) {
            case "1.2.840.113549.1.1.11", "1.2.840.10045.4.3.2" -> SHA_256;
            case "1.2.840.113549.1.1.12", "1.2.840.10045.4.3.3" -> SHA_384;
            case "1.2.840.113549.1.1.13", "1.2.840.10045.4.3.4" -> "SHA-512";
            case "1.2.840.113549.1.1.10" -> {
                java.security.AlgorithmParameters parameters = java.security.AlgorithmParameters.getInstance("RSASSA-PSS");
                parameters.init(certificate.getSigAlgParams());
                yield parameters.getParameterSpec(java.security.spec.PSSParameterSpec.class).getDigestAlgorithm();
            }
            default -> {
                if (!confirmationRequiresExplicitDigest(certificate.getSigAlgOID()) || algorithm.getParameters() != null) {
                    throw invalid();
                }
                yield explicitDigest.orElseThrow(CmpProtectedMessage::invalid);
            }
        };
    }

    private static boolean confirmationRequiresExplicitDigest(String oid) {
        return Set.of(zeroecho.core.alg.EgothorAlgorithmOids.OID_SPHINCS_PLUS_CERTIFICATE_SIGNATURE,
                org.bouncycastle.asn1.edec.EdECObjectIdentifiers.id_Ed25519.getId(), org.bouncycastle.asn1.edec.EdECObjectIdentifiers.id_Ed448.getId(), "2.16.840.1.101.3.4.3.17", "2.16.840.1.101.3.4.3.18",
                "2.16.840.1.101.3.4.3.19", "2.16.840.1.101.3.4.3.20", "2.16.840.1.101.3.4.3.21",
                "2.16.840.1.101.3.4.3.22", "2.16.840.1.101.3.4.3.23", "2.16.840.1.101.3.4.3.24",
                "2.16.840.1.101.3.4.3.25", "2.16.840.1.101.3.4.3.26", "2.16.840.1.101.3.4.3.27",
                "2.16.840.1.101.3.4.3.28", "2.16.840.1.101.3.4.3.29", "2.16.840.1.101.3.4.3.30",
                "2.16.840.1.101.3.4.3.31").contains(oid);
    }

    private static String confirmationDigest(ASN1Encodable encoded) {
        ASN1Sequence sequence = ASN1Sequence.getInstance(encoded);
        if (sequence.size() < 1 || sequence.size() > 2) {
            throw invalid();
        }
        AlgorithmIdentifier algorithm = AlgorithmIdentifier.getInstance(sequence);
        nullOrAbsent(algorithm);
        return switch (algorithm.getAlgorithm().getId()) {
            case "2.16.840.1.101.3.4.2.1" -> SHA_256;
            case "2.16.840.1.101.3.4.2.2" -> SHA_384;
            case "2.16.840.1.101.3.4.2.3" -> "SHA-512";
            default -> throw invalid();
        };
    }

    /**
     * Verifies the exact protected bytes using one explicitly selected certificate.
     * Checks its key strength and algorithm grammar; trust, usage, validity, sender
     * binding and authority remain the caller's responsibility.
     * @param certificate externally selected candidate, never an implicit trust anchor
     * @return unforgeable proof token for this exact message
     * @throws IllegalArgumentException if mode, algorithm or signature is invalid
     */
    public Verified verifySignature(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        if (isPbm()) {
            throw invalid();
        }
        try {
            String algorithm = signatureAlgorithm(message.getHeader().getProtectionAlg(), certificate.getPublicKey());
            if (senderKid().filter(value -> !MessageDigest.isEqual(value, certificateKeyId(certificate))).isPresent()) {
                throw invalid();
            }
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(protectedBytes);
            if (!verifier.verify(message.getProtection().getOctets())) {
                throw invalid();
            }
            return new Verified(this);
        } catch (GeneralSecurityException failure) { throw invalid(); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }

    /**
     * Verifies binary-secret PBM after validating all work and algorithm bounds.
     * Secret bytes are never interpreted as characters or retained by the token.
     * @param policy explicit configured bounds
     * @param secret caller-owned 32..128 bytes, copied and never modified
     * @param cancellation cooperative signal checked during iterative derivation
     * @return proof token for this exact message
     * @throws IllegalArgumentException if bounds, mode, protection or cancellation fail
     */
    public Verified verifyPbm(CmpPbmPolicy policy, byte[] secret, CancellationSignal cancellation) {
        try {
            if (!isPbm()) {
                throw invalid();
            }
            Pbm parameters = pbm(message.getHeader().getProtectionAlg(), policy);
            byte[] actual = message.getProtection().getOctets();
            if (actual.length != parameters.macBytes()) {
                throw invalid();
            }
            byte[] expected = calculate(parameters, secret, protectedBytes, cancellation);
            try { if (!MessageDigest.isEqual(expected, actual)) {
                throw invalid();
            } }
            finally { Arrays.fill(expected, (byte) 0); }
            return new Verified(this);
        } catch (RuntimeException failure) { throw invalid(); } // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl, PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }

    /** {@return a redacted diagnostic representation} */
    @Override public String toString() { return "CmpProtectedMessage[redacted]"; }

    /**
     * Immutable proof token constructed only after exact message protection verification.
     * It does not assert certificate trust, CSR proof, requester ownership or permission.
     */
    public static final class Verified {
        private final CmpProtectedMessage request;
        private Verified(CmpProtectedMessage request) { this.request = request; }
        /** {@return the immutable message whose protection was verified} */
        public CmpProtectedMessage request() { return request; }

        /**
         * Creates a granted ip/cp/kup response for the retained original request.
         * A poll response supplies that original body type explicitly; its ID must match.
         * @param originalType original ir, cr or kur body tag
         * @param certificateDer issued certificate, at most one MiB
         * @param implicit whether the original enrollment explicitly requested implicit confirmation
         * @param confirmationDeadline explicit confirmation deadline when implicit is false
         * @return immutable unsigned body bound to this verified request
         * @throws IllegalArgumentException if any field or request type is inconsistent
         */
        public Response certificate(int originalType, byte[] certificateDer, boolean implicit, Instant confirmationDeadline) {
            if (certificateDer == null || certificateDer.length == 0 || certificateDer.length > MAXIMUM_MESSAGE_BYTES) {
                throw invalid();
            }
            if (request.bodyType() != 25 && implicit && !request.requestsImplicitConfirmation()) {
                throw invalid();
            }
            int responseType = certificateResponseType(originalType);
            try {
                CrmfRequest.validateStructure(certificateDer);
                org.bouncycastle.asn1.x509.Certificate certificate = org.bouncycastle.asn1.x509.Certificate.getInstance(
                        ASN1Primitive.fromByteArray(certificateDer.clone()));
                org.bouncycastle.asn1.cmp.CertifiedKeyPair pair = new org.bouncycastle.asn1.cmp.CertifiedKeyPair(
                        new org.bouncycastle.asn1.cmp.CertOrEncCert(new CMPCertificate(certificate)));
                org.bouncycastle.asn1.cmp.CertResponse response = new org.bouncycastle.asn1.cmp.CertResponse(
                        new ASN1Integer(request.requestId()), new PKIStatusInfo(
                                PKIStatus.granted), pair, null);
                return new Response(request, new PKIBody(responseType, new org.bouncycastle.asn1.cmp.CertRepMessage(null,
                        new org.bouncycastle.asn1.cmp.CertResponse[] {response})), implicit,
                        implicit ? null : Objects.requireNonNull(confirmationDeadline, "confirmationDeadline"));
            } catch (IOException | RuntimeException failure) { throw invalid(); } // NOPMD AvoidCatchingGenericException, PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }

        /**
         * Creates an initial waiting ip/cp/kup response with the exact request ID.
         * @return immutable response body without an invented certificate or signing receipt
         * @throws IllegalArgumentException unless the request is ir, cr or kur
         */
        public Response waiting() {
            if (request.bodyType() == PKIBody.TYPE_POLL_REQ) {
                throw invalid();
            }
            int type = certificateResponseType(request.bodyType());
            org.bouncycastle.asn1.cmp.CertResponse response = new org.bouncycastle.asn1.cmp.CertResponse(
                    new ASN1Integer(request.requestId()), new PKIStatusInfo(PKIStatus.waiting));
            return new Response(request, new PKIBody(type, new org.bouncycastle.asn1.cmp.CertRepMessage(null,
                    new org.bouncycastle.asn1.cmp.CertResponse[] {response})), false, null);
        }

        /**
         * Creates a pollRep using an explicit configured retry interval.
         * @param retrySeconds positive retry interval, at most thirty days
         * @return immutable poll response for the exact request ID
         * @throws IllegalArgumentException if the type or interval is invalid
         */
        public Response poll(int retrySeconds) {
            if (request.bodyType() != 25 || retrySeconds < 1 || retrySeconds > 2_592_000) {
                throw invalid();
            }
            return new Response(request, new PKIBody(26, new DERSequence(new DERSequence(new ASN1Encodable[] {
                    new ASN1Integer(request.requestId()), new ASN1Integer(retrySeconds) }))), false, null);
        }

        /**
         * Creates a successful permanent revocation response after caller-authorized revocation.
         * @return immutable rp body bound to the verified rr
         * @throws IllegalArgumentException unless this is rr
         */
        public Response revoked() {
            if (request.bodyType() != PKIBody.TYPE_REVOCATION_REQ) {
                throw invalid();
            }
            CrmfRequest.CertificateReference reference = request.revokedCertificate().orElseThrow();
            org.bouncycastle.asn1.cmp.RevRepContentBuilder builder = new org.bouncycastle.asn1.cmp.RevRepContentBuilder();
            builder.add(new PKIStatusInfo(PKIStatus.granted),
                    new org.bouncycastle.asn1.crmf.CertId(new GeneralName(org.bouncycastle.asn1.x500.X500Name.getInstance(
                            reference.issuer().getEncoded())), reference.serialNumber()));
            return new Response(request, new PKIBody(12, builder.build()), false, null);
        }

        /**
         * Creates pkiConf after the server has checked and durably recorded certConf.
         * @return immutable confirmation acknowledgement
         * @throws IllegalArgumentException unless this is certConf
         */
        public Response confirmed() {
            if (request.bodyType() != PKIBody.TYPE_CERT_CONFIRM) {
                throw invalid();
            }
            return new Response(request, new PKIBody(19, DERNull.INSTANCE), false, null);
        }

        /**
         * Creates the standard caCerts general response, preserving supplied chain order.
         * @param chain bounded leaf-to-anchor certificate DER list
         * @return immutable genp body; no certificate trust is inferred
         * @throws IllegalArgumentException if the request or chain is invalid
         */
        public Response caCertificates(List<byte[]> chain) {
            if (request.bodyType() != PKIBody.TYPE_GEN_MSG) {
                throw invalid();
            }
            CMPCertificate[] certificates = certificates(chain);
            return new Response(request, new PKIBody(22, new DERSequence(new InfoTypeAndValue(
                    CMPObjectIdentifiers.id_it_caCerts, new DERSequence(certificates)))), false, null);
        }

        /**
         * Creates a generic authenticated rejection without caller-controlled diagnostics.
         * @return immutable error response body
         */
        public Response rejected() {
            return new Response(request, new PKIBody(23, new org.bouncycastle.asn1.cmp.ErrorMsgContent(
                    new PKIStatusInfo(PKIStatus.rejection))), false, null);
        }

        /**
         * Signs one response using the supplied retained server credential.
         * Response nonce and time are explicit so the caller can commit the exact
         * result before sending. The supplied chain must begin with the signer.
         * @param response body created by this proof token
         * @param signer server certificate whose key must match the private key
         * @param privateKey borrowed private key, never retained
         * @param chain explicit certificate chain in leaf-to-anchor order
         * @param senderNonce fresh server nonce, sixteen through thirty-two bytes
         * @param time explicit response time
         * @return protected DER response, bounded by the configured chain and leaf sizes
         * @throws IllegalArgumentException if the request uses PBM or signing fails
         */
        public byte[] sign(Response response, X509Certificate signer, PrivateKey privateKey,
                List<byte[]> chain, byte[] senderNonce, Instant time) {
            if (request.isPbm()) {
                throw invalid();
            }
            Objects.requireNonNull(privateKey, "privateKey");
            try {
                CMPCertificate[] certificates = certificates(chain);
                if (!Arrays.equals(signer.getEncoded(), certificates[0].getEncoded())) {
                    throw invalid();
                }
                AlgorithmIdentifier algorithm = signer.getPublicKey() instanceof RSAPublicKey
                        ? new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"), DERNull.INSTANCE)
                        : new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"));
                String jca = signatureAlgorithm(algorithm, signer.getPublicKey());
                byte[] kid = certificateKeyId(signer);
                if (request.recipientKid().filter(value -> !MessageDigest.isEqual(value, kid)).isPresent()) {
                    throw invalid();
                }
                PKIHeader header = header(response, signer.getSubjectX500Principal(), kid, senderNonce, time, algorithm);
                byte[] protectedBytes = new DERSequence(new ASN1Encodable[] {header, response.body}).getEncoded(ASN1Encoding.DER);
                Signature signature = Signature.getInstance(jca);
                signature.initSign(privateKey);
                signature.update(protectedBytes);
                byte[] value = signature.sign();
                signature.initVerify(signer.getPublicKey());
                signature.update(protectedBytes);
                if (!signature.verify(value)) {
                    throw invalid();
                }
                return new PKIMessage(header, response.body, new DERBitString(value), certificates).getEncoded(ASN1Encoding.DER);
            } catch (GeneralSecurityException | IOException | RuntimeException failure) { throw invalid(); } // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl, PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }

        /**
         * Protects a response with the same verified binary PBM mode and parameters,
         * replacing its salt with caller-provided fresh random bytes.
         * @param response body created by this proof token
         * @param sender explicit authority-scoped server distinguished name
         * @param policy configured PBM bounds
         * @param secret caller-owned binary secret, never retained or modified
         * @param freshSalt fresh random salt satisfying the configured bounds
         * @param senderNonce fresh response nonce
         * @param time explicit response time
         * @param cancellation cooperative derivation cancellation
         * @return protected DER response without extra certificate candidates
         * @throws IllegalArgumentException if bounds, mode or MAC generation fail
         */
        public byte[] protectPbm(Response response, X500Principal sender, CmpPbmPolicy policy, byte[] secret,
                byte[] freshSalt, byte[] senderNonce, Instant time, CancellationSignal cancellation) {
            if (!request.isPbm()) {
                throw invalid();
            }
            try {
                Pbm original = pbm(request.message.getHeader().getProtectionAlg(), policy);
                if (freshSalt == null || freshSalt.length < policy.minimumSaltBytes() || freshSalt.length > policy.maximumSaltBytes()
                        || Arrays.equals(freshSalt, original.salt())) {
                    throw invalid();
                }
                PBMParameter replacement = new PBMParameter(freshSalt.clone(), original.encoded().getOwf(),
                        original.iterations(), original.encoded().getMac());
                AlgorithmIdentifier algorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier(PBM_OID), replacement);
                Pbm parameters = pbm(algorithm, policy);
                PKIHeader header = header(response, sender, request.senderKid().orElseThrow(), senderNonce, time, algorithm);
                byte[] content = new DERSequence(new ASN1Encodable[] { header, response.body }).getEncoded(ASN1Encoding.DER);
                byte[] mac = calculate(parameters, secret, content, cancellation);
                try { return new PKIMessage(header, response.body, new DERBitString(mac)).getEncoded(ASN1Encoding.DER); }
                finally { Arrays.fill(mac, (byte) 0); }
            } catch (IOException | RuntimeException failure) { throw invalid(); } // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl, PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }

        private int certificateResponseType(int original) {
            if (request.bodyType() != 25 && request.bodyType() != original) {
                throw invalid();
            }
            return switch (original) { case 0 -> 1; case 2 -> 3; case 7 -> 8; default -> throw invalid(); };
        }

        private PKIHeader header(Response response, X500Principal sender, byte[] senderKid, byte[] nonce,
                Instant time, AlgorithmIdentifier algorithm) {
            Objects.requireNonNull(sender, "sender");
            Objects.requireNonNull(time, "time");
        if (response == null || response.request != request || nonce == null || nonce.length < 16 || nonce.length > 32 // NOPMD CompareObjectsWithEquals - A response proof is bound to this exact parsed request instance, not an equivalent value.
                    || Arrays.equals(nonce, request.senderNonce())) {
            throw invalid();
        }
            PKIHeaderBuilder builder = new PKIHeaderBuilder(request.message.getHeader().getPvno().intValueExact(),
                    new GeneralName(org.bouncycastle.asn1.x500.X500Name.getInstance(sender.getEncoded())), request.message.getHeader().getSender());
            builder.setProtectionAlg(algorithm);
            builder.setMessageTime(new DERGeneralizedTime(Date.from(time)));
            builder.setTransactionID(request.transactionId());
            builder.setSenderNonce(nonce.clone());
            builder.setRecipNonce(request.senderNonce());
            builder.setSenderKID(senderKid.clone());
            request.senderKid().ifPresent(builder::setRecipKID);
            if (response.implicit) {
                builder.setGeneralInfo(new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE));
            }
            if (response.deadline != null) {
                if (!response.deadline.isAfter(time)) {
                    throw invalid();
                }
                builder.setGeneralInfo(new InfoTypeAndValue(CMPObjectIdentifiers.it_confirmWaitTime,
                        new DERGeneralizedTime(Date.from(response.deadline))));
            }
            return builder.build();
        }
        /** {@return a redacted diagnostic representation} */
        @Override public String toString() { return "VerifiedCmpProtection[redacted]"; }
    }

    /**
     * Immutable unsigned response bound to one verified request. Instances can
     * only be created by the token's typed body factories and cannot be re-bound.
     */
    public static final class Response {
        private final CmpProtectedMessage request;
        private final PKIBody body;
        private final boolean implicit;
        private final Instant deadline;
        private Response(CmpProtectedMessage request, PKIBody body, boolean implicit, Instant deadline) {
            this.request = request; this.body = body; this.implicit = implicit; this.deadline = deadline;
        }
        /** {@return a redacted diagnostic representation} */
        @Override public String toString() { return "CmpResponse[redacted]"; }
    }

    private static CMPCertificate[] certificates(List<byte[]> chain) {
        Objects.requireNonNull(chain, "chain");
        if (chain.isEmpty() || chain.size() > MAXIMUM_EXTRA_CERTIFICATES) {
            throw invalid();
        }
        CMPCertificate[] result = new CMPCertificate[chain.size()];
        for (int index = 0; index < result.length; index++) {
            byte[] der = chain.get(index);
            if (der == null || der.length == 0 || der.length > MAXIMUM_MESSAGE_BYTES) {
                throw invalid();
            }
            try {
                CrmfRequest.validateStructure(der);
                result[index] = new CMPCertificate(org.bouncycastle.asn1.x509.Certificate.getInstance(ASN1Primitive.fromByteArray(der.clone())));
            } catch (IOException | RuntimeException failure) { throw invalid(); } // NOPMD AvoidCatchingGenericException, PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
        return result;
    }

    private record Pbm(PBMParameter encoded, String digest, String mac, int macBytes, int iterations, byte[] salt) { }

    private static Pbm pbm(AlgorithmIdentifier algorithm, CmpPbmPolicy policy) {
        Objects.requireNonNull(policy, "policy");
        if (!PBM_OID.equals(algorithm.getAlgorithm().getId())
                || ASN1Sequence.getInstance(algorithm.getParameters()).size() != 4) {
            throw invalid();
        }
        PBMParameter parameter = PBMParameter.getInstance(algorithm.getParameters());
        int iterations = parameter.getIterationCount().intValueExact();
        byte[] salt = parameter.getSalt().getOctets();
        if (iterations < policy.minimumIterations() || iterations > policy.maximumIterations()
                || salt.length < policy.minimumSaltBytes() || salt.length > policy.maximumSaltBytes()) {
            throw invalid();
        }
        if (!policy.digestOids().contains(parameter.getOwf().getAlgorithm().getId())
                || !policy.macOids().contains(parameter.getMac().getAlgorithm().getId())) {
            throw invalid();
        }
        nullOrAbsent(parameter.getOwf()); nullOrAbsent(parameter.getMac());
        String mac = macName(parameter.getMac().getAlgorithm().getId());
        int bytes = switch (mac) { case "HmacSHA256" -> 32; case "HmacSHA384" -> 48; default -> 64; };
        return new Pbm(parameter, confirmationDigest(parameter.getOwf()), mac, bytes, iterations, salt);
    }

    private static String macName(String oid) {
        return switch (oid) {
            case "1.2.840.113549.2.9" -> "HmacSHA256";
            case "1.2.840.113549.2.10" -> "HmacSHA384";
            case "1.2.840.113549.2.11" -> "HmacSHA512";
            default -> throw invalid();
        };
    }

    private static byte[] calculate(Pbm parameters, byte[] secret, byte[] bytes, CancellationSignal cancellation) {
        Objects.requireNonNull(cancellation, "cancellation");
        if (secret == null || secret.length < 32 || secret.length > 128) {
            throw invalid();
        }
        byte[] key = new byte[secret.length + parameters.salt().length];
        System.arraycopy(secret, 0, key, 0, secret.length);
        System.arraycopy(parameters.salt(), 0, key, secret.length, parameters.salt().length);
        try {
            MessageDigest digest = MessageDigest.getInstance(parameters.digest());
            for (int iteration = 0; iteration < parameters.iterations(); iteration++) {
                if ((iteration & 63) == 0) {
                    cancellation.throwIfCancelled();
                }
                byte[] next = digest.digest(key);
                Arrays.fill(key, (byte) 0);
                key = next;
            }
            cancellation.throwIfCancelled();
            Mac mac = Mac.getInstance(parameters.mac());
            mac.init(new SecretKeySpec(key, parameters.mac()));
            return mac.doFinal(bytes);
        } catch (GeneralSecurityException | IOException failure) { throw invalid(); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        finally { Arrays.fill(key, (byte) 0); }
    }

    private static String signatureAlgorithm(AlgorithmIdentifier algorithm, PublicKey key) {
        PublicKeyIdentity.fromSubjectPublicKeyInfo(key.getEncoded());
        String oid = algorithm.getAlgorithm().getId();
        if (key instanceof RSAPublicKey rsa) {
            if (rsa.getModulus().bitLength() < 2048 || rsa.getModulus().bitLength() > 8192) {
                throw invalid();
            }
            nullOrAbsent(algorithm);
            return switch (oid) {
                case "1.2.840.113549.1.1.11" -> "SHA256withRSA";
                case "1.2.840.113549.1.1.12" -> "SHA384withRSA";
                case "1.2.840.113549.1.1.13" -> "SHA512withRSA";
                default -> throw invalid();
            };
        }
        if (key instanceof ECPublicKey) {
            if (algorithm.getParameters() != null) {
                throw invalid();
            }
            return switch (oid) {
                case "1.2.840.10045.4.3.2" -> "SHA256withECDSA";
                case "1.2.840.10045.4.3.3" -> "SHA384withECDSA";
                case "1.2.840.10045.4.3.4" -> "SHA512withECDSA";
                default -> throw invalid();
            };
        }
        throw invalid();
    }

    private static void nullOrAbsent(AlgorithmIdentifier algorithm) {
        if (algorithm.getParameters() != null && !(algorithm.getParameters() instanceof ASN1Null)) {
            throw invalid();
        }
    }
    private static boolean implicit(PKIHeader header) {
        InfoTypeAndValue[] values = header.getGeneralInfo();
        if (values == null) {
            return false;
        }
        if (values.length != 1 || !CMPObjectIdentifiers.it_implicitConfirm.equals(values[0].getInfoType())
                || !(values[0].getInfoValue() instanceof ASN1Null)
                || ASN1Sequence.getInstance(values[0].toASN1Primitive()).size() != 2) {
            throw invalid();
        }
        return true;
    }
    private static BigInteger identifier(ASN1Encodable value) {
        BigInteger id = ASN1Integer.getInstance(value).getValue();
        if (id.signum() < 0 || id.bitLength() > 64) {
            throw invalid();
        }
        return id;
    }
    private static ASN1TaggedObject tagged(ASN1Encodable value, int expected) {
        ASN1TaggedObject tag = ASN1TaggedObject.getInstance(value);
        if (tag.getTagClass() != BERTags.CONTEXT_SPECIFIC || tag.getTagNo() != expected) {
            throw invalid();
        }
        return tag;
    }
    private static X500Principal name(GeneralName value) {
        try {
            if (value.getTagNo() != GeneralName.directoryName) {
                throw invalid();
            }
            byte[] encoded = value.getName().toASN1Primitive().getEncoded(ASN1Encoding.DER);
            if (encoded.length > MAXIMUM_NAME_BYTES) {
                throw invalid();
            }
            return new X500Principal(encoded);
        } catch (IOException failure) { throw invalid(); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }
    private static byte[] octets(ASN1OctetString value, int minimum, int maximum) {
        if (value == null) {
            throw invalid();
        }
        byte[] bytes = value.getOctets();
        if (bytes.length < minimum || bytes.length > maximum) {
            throw invalid();
        }
        return bytes;
    }
    private static Optional<byte[]> optional(ASN1OctetString value) {
        return value == null ? Optional.empty() : Optional.of(value.getOctets().clone());
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("CMP protection or message is invalid"); }
}
