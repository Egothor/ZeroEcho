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
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;

import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.CertificateExtension;
import zeroecho.pkix.Pkix;

/**
 * Immutable structural projection of one canonical CRMF {@code CertReqMsg}.
 *
 * <p>The supported grammar requires a nonnegative request ID of at most 64 bits,
 * a subject and public key in the signed {@code CertRequest}, and signing-key
 * proof without {@code poposkInput}. Optional version 2 and requested extensions
 * are retained, as is a single standard {@code oldCertID} control when present;
 * other controls, registration information and other template fields are
 * rejected. Parsing does not verify the proof or grant issuance authority.
 * Callers must verify {@link #signature()} over {@link #signedRequest()} using
 * the exact {@link #subjectPublicKeyInfo()} and their algorithm policy.</p>
 *
 * <p>Input is limited to one MiB and 64 nesting levels. Parsing and owned storage
 * are O(N) in encoded length, with a bounded structural stack.</p>
 */
public final class CrmfRequest {
    private static final int CERTIFICATE_REFERENCE_FIELDS = 2;
    /** Maximum complete CertReqMsg size in bytes. */
    public static final int MAXIMUM_ENCODED_BYTES = 1_048_576;
    private final byte[] encoded;
    private final BigInteger requestId;
    private final X500Principal subject;
    private final byte[] publicKey;
    private final AlgorithmIdentifier signatureAlgorithm;
    private final byte[] signedRequest;
    private final byte[] signature;
    private final List<CertificateExtension> extensions;
    private final Optional<CertificateReference> oldCertificate;

    /**
     * Immutable structural predecessor reference; possession and authority are not asserted.
     * @param issuer certificate issuer distinguished name
     * @param serialNumber positive certificate serial of at most 160 bits
     */
    public record CertificateReference(X500Principal issuer, BigInteger serialNumber) {
        /** Validates nonnull bounded coordinates. */
        public CertificateReference {
            Objects.requireNonNull(issuer, "issuer");
            Objects.requireNonNull(serialNumber, "serialNumber");
            if (serialNumber.signum() <= 0 || serialNumber.bitLength() > 160) {
                throw invalid();
            }
        }
        /** @return a redacted diagnostic description */
        @Override public String toString() { return "CertificateReference[redacted]"; }
    }

    private CrmfRequest(byte[] encoded, CertReqMsg message) throws IOException {
        CertRequest request = message.getCertReq();
        CertTemplate template = request.getCertTemplate();
        ProofOfPossession proof = message.getPop();
        requestId = request.getCertReqId().getValue();
        if (requestId.signum() < 0 || requestId.bitLength() > 64
                || message.getRegInfo() != null || proof == null || proof.getType() != ProofOfPossession.TYPE_SIGNING_KEY
                || template.getSubject() == null || template.getPublicKey() == null) {
            throw invalid();
        }
        oldCertificate = parseOldCertificate(request);
        validateTemplate(template);
        POPOSigningKey signing = POPOSigningKey.getInstance(proof.getObject());
        if (signing.getPoposkInput() != null || signing.getSignature().getPadBits() != 0) {
            throw invalid();
        }
        this.encoded = encoded;
        subject = new X500Principal(template.getSubject().getEncoded(ASN1Encoding.DER));
        publicKey = template.getPublicKey().getEncoded(ASN1Encoding.DER);
        signatureAlgorithm = Pkix.parseAlgorithmIdentifier(signing.getAlgorithmIdentifier().getEncoded(ASN1Encoding.DER));
        signedRequest = request.getEncoded(ASN1Encoding.DER);
        signature = signing.getSignature().getOctets();
        if (signature.length == 0) {
            throw invalid();
        }
        extensions = template.getExtensions() == null ? List.of()
                : List.copyOf(Pkix.parseExtensions(template.getExtensions().getEncoded(ASN1Encoding.DER)));
    }

    /**
     * Parses one bounded canonical DER CertReqMsg with the supported signing proof.
     * @param der caller-owned exact CertReqMsg, copied before parsing
     * @return immutable structural projection without a proof-validity assertion
     * @throws IllegalArgumentException if size, DER, or the supported grammar is invalid
     */
    public static CrmfRequest parse(byte[] der) {
        Objects.requireNonNull(der, "der");
        if (der.length == 0 || der.length > MAXIMUM_ENCODED_BYTES) {
            throw invalid();
        }
        byte[] snapshot = der.clone();
        validateStructure(snapshot);
        try {
            CertReqMsg message = CertReqMsg.getInstance(ASN1Primitive.fromByteArray(snapshot));
            if (!Arrays.equals(snapshot, message.getEncoded(ASN1Encoding.DER))) {
                throw invalid();
            }
            return new CrmfRequest(snapshot, message);
        } catch (IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl - Invalid input is rejected here and normalized at the protocol boundary; exceptions do not represent successful control flow.
            throw new IllegalArgumentException("CRMF request is malformed or unsupported"); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
    }

    /**
     * Returns the exact request bytes.
     * @return defensive DER snapshot
     */
    public byte[] encoded() { return encoded.clone(); }
    /**
     * Returns the retained CRMF request identity.
     * @return immutable nonnegative request ID
     */
    public BigInteger requestId() { return requestId; }
    /**
     * Returns the requested subject.
     * @return immutable subject DN
     */
    public X500Principal subject() { return subject; }
    /**
     * Returns the proof's public key.
     * @return defensive SubjectPublicKeyInfo DER
     */
    public byte[] subjectPublicKeyInfo() { return publicKey.clone(); }
    /**
     * Returns the proof algorithm.
     * @return immutable signature algorithm identifier
     */
    public AlgorithmIdentifier signatureAlgorithm() { return signatureAlgorithm; }
    /**
     * Returns the exact signed CertRequest.
     * @return defensive canonical DER snapshot
     */
    public byte[] signedRequest() { return signedRequest.clone(); }
    /**
     * Returns the signing-key proof bytes.
     * @return defensive signature snapshot
     */
    public byte[] signature() { return signature.clone(); }
    /**
     * Returns requested extensions without policy approval.
     * @return immutable extension list
     */
    public List<CertificateExtension> requestedExtensions() { return extensions; }
    /**
     * Returns the signed standard predecessor reference, if supplied.
     * @return immutable structural reference without ownership or validity assertion
     */
    public Optional<CertificateReference> oldCertificate() { return oldCertificate; }
    /** Returns a diagnostic representation without request data. */
    @Override public String toString() { return "CrmfRequest[redacted]"; }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("CRMF request is malformed or unsupported");
    }

    private static void validateTemplate(CertTemplate template) {
        ASN1Sequence fields = ASN1Sequence.getInstance(template.toASN1Primitive());
        int previousTag = -1;
        for (int index = 0; index < fields.size(); index++) {
            ASN1TaggedObject field = ASN1TaggedObject.getInstance(fields.getObjectAt(index));
            int tag = field.getTagNo();
            if (field.getTagClass() != org.bouncycastle.asn1.BERTags.CONTEXT_SPECIFIC
                    || tag != 0 && tag != 5 && tag != 6 && tag != 9 || tag <= previousTag) {
                throw invalid();
            }
            if (tag == 0 && template.getVersion() != 2) {
                throw invalid();
            }
            previousTag = tag;
        }
    }

    private static Optional<CertificateReference> parseOldCertificate(CertRequest request) throws IOException {
        if (request.getControls() == null) {
            return Optional.empty();
        }
        ASN1Sequence raw = ASN1Sequence.getInstance(request.getControls().toASN1Primitive());
        if (raw.size() != 1 || ASN1Sequence.getInstance(raw.getObjectAt(0)).size() != 2) {
            throw invalid();
        }
        AttributeTypeAndValue[] controls = request.getControls().toAttributeTypeAndValueArray();
        if (controls.length != 1 || !CRMFObjectIdentifiers.id_regCtrl_oldCertID.equals(controls[0].getType())) {
            throw invalid();
        }
        ASN1Sequence value = ASN1Sequence.getInstance(controls[0].getValue());
        // BC's CertId accepts extra sequence members; require the exact standard shape.
        if (value.size() != CERTIFICATE_REFERENCE_FIELDS) {
            throw invalid();
        }
        CertId id = CertId.getInstance(value);
        if (id.getIssuer().getTagNo() != GeneralName.directoryName) {
            throw invalid();
        }
        return Optional.of(new CertificateReference(
                new X500Principal(id.getIssuer().getName().toASN1Primitive().getEncoded(ASN1Encoding.DER)),
                id.getSerialNumber().getValue()));
    }

    // Bound the ASN.1 provider's recursive parser before invoking it. Canonical DER
    // and the closed CRMF grammar are checked again by re-encoding the parsed value.
    /* default */ static void validateStructure(byte[] bytes) {
        int[] ends = new int[64];
        ends[0] = bytes.length;
        int depth = 0;
        DerCursor cursor = new DerCursor(bytes);
        boolean root = true;
        while (cursor.position < bytes.length) {
            while (depth > 0 && cursor.position == ends[depth]) {
                depth--;
            }
            if (!root && depth == 0) {
                throw invalid();
            }
            root = false;
            int parentEnd = ends[depth];
            int tag = cursor.tag(parentEnd);
            int length = cursor.length(parentEnd);
            if (length > parentEnd - cursor.position) {
                throw invalid();
            }
            int end = cursor.position + length;
            if ((tag & DerCursor.CONSTRUCTED) != 0 && length > 0) {
                if (++depth == ends.length) {
                    throw invalid();
                }
                ends[depth] = end;
            } else {
                cursor.position = end;
            }
        }
        if (root) {
            throw invalid();
        }
    }

    /** Bounded DER header reader; the enclosing traversal owns nesting and content boundaries. */
    private static final class DerCursor {
        private static final int HIGH_TAG = 31;
        private static final int CONSTRUCTED = 32;
        private static final int CONTINUATION = 128;
        private static final int PAYLOAD_MASK = 127;
        private final byte[] bytes;
        private int position;

        private DerCursor(byte[] bytes) {
            this.bytes = bytes;
        }

        private int tag(int end) {
            int tag = bytes[position++] & 255;
            if ((tag & HIGH_TAG) == HIGH_TAG) {
                int count = 0;
                int part;
                do {
                    if (position >= end || ++count > 5) {
                        throw invalid();
                    }
                    part = bytes[position++] & 255;
                    if (count == 1 && (part & PAYLOAD_MASK) == 0) {
                        throw invalid();
                    }
                } while ((part & CONTINUATION) != 0);
            }
            return tag;
        }

        private int length(int end) {
            if (position >= end) {
                throw invalid();
            }
            int length = bytes[position++] & 255;
            if ((length & CONTINUATION) == 0) {
                return length;
            }
            int count = length & PAYLOAD_MASK;
            if (count == 0 || count > 4 || end - position < count || bytes[position] == 0) {
                throw invalid();
            }
            long decoded = 0;
            for (int index = 0; index < count; index++) {
                decoded = (decoded << 8) | (bytes[position++] & 255);
            }
            if (decoded < CONTINUATION || decoded > Integer.MAX_VALUE) {
                throw invalid();
            }
            return (int) decoded;
        }
    }
}
