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
package zeroecho.pkix.ocsp;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;

import zeroecho.pkix.Pkix;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;

/**
 * Extracts a bounded structural view of a matching native OCSP request and response.
 *
 * <p>This class implements a restricted profile for successful basic OCSP responses.
 * It derives certificate status, nonce and time values from the supplied native
 * encodings and verifies their structural correspondence. The result is suitable
 * as input to a separate signature, responder-authorization and freshness check;
 * it is not evidence that those checks have succeeded. Standard AltSignature OCSP
 * is outside this profile.
 *
 * <p>Parsing does not consult a clock or perform network, file or trust-store
 * access. Input arrays are borrowed only for the duration of a call and must not
 * be modified concurrently. Returned projections own their mutable byte storage.
 * Direct construction of a {@link Status} or {@link Projection} provides that
 * storage ownership but does not perform the parser's structural validation.
 */
public final class StrictOcspProjection {
    private static final String DER = "DER";
    private static final int LIMIT_1 = 1;
    private static final int LIMIT_32 = 32;
    private static final int LIMIT_262_144 = 262_144;

    /**
     * Maximum accepted size, in bytes, of a complete response in this restricted profile.
     *
     * <p>The value is 1,455,101 bytes. It is derived from the DER envelope and the
     * permitted component bounds, including 819 status entries and the embedded
     * certificate envelope. For {@code D(n) = 1 + DER-length-octets(n) + n}, the
     * intermediate bounds are 171 bytes per status, 4,127 bytes for the nonce
     * extension, 406,357 bytes for ResponseData and 1,455,067 bytes for
     * BasicOCSPResponse. This is a parser allocation ceiling, not a general OCSP
     * response quota or a recommended response size.
     */
    public static final int MAXIMUM_RESPONSE_BYTES = responseLimit();

    private StrictOcspProjection() {}

    /**
     * Includes the one-byte tag and DER length field in a bounded content size.
     *
     * <p>Checked addition prevents the response-ceiling calculation from silently
     * wrapping if its component limits are changed in a future profile.
     *
     * @param bytes nonnegative content size used by this profile
     * @return complete encoded size for a one-byte-tagged DER value
     * @throws ArithmeticException if the resulting size exceeds the integer range
     */
    private static int der(int bytes) {
        int lengthBytes =
                bytes < 128
                        ? LIMIT_1
                        : LIMIT_1 + (Integer.SIZE - Integer.numberOfLeadingZeros(bytes) + 7) / 8;
        return Math.addExact(Math.addExact(LIMIT_1, lengthBytes), bytes);
    }

    /**
     * Derives the complete response ceiling from nested native component bounds.
     *
     * @return maximum complete response size, including all enclosing DER values
     * @throws ArithmeticException if a derived envelope size exceeds the integer range
     */
    private static int responseLimit() {
        int single = der(108 + der(17 + der(3)) + 17 + der(17));
        int nonce = der(der(der(11 + der(der(4_096)))));
        int data = der(5 + der(LIMIT_262_144) + 17 + der(819 * single) + nonce);
        int basic = der(data + 12 + der(105) + der(der(1_048_576)));
        return der(3 + der(der(11 + der(basic))));
    }

    /**
     * Parses a native request and response and validates their ordered structural correspondence.
     *
     * <p>The request is limited to one mebibyte and the response to
     * {@link #MAXIMUM_RESPONSE_BYTES}. The response must be successful and contain
     * a BasicOCSPResponse with the exact supplied signature AlgorithmIdentifier.
     * The signature must have bounded canonical ECDSA syntax; this method does
     * not cryptographically verify that signature.
     *
     * <p>There must be between one and 819 request entries and the same number of
     * response entries, in the same order. CertIDs must match without duplicates;
     * SHA-1 and SHA-256 are the supported issuer-hash algorithms. All entries must
     * share {@code thisUpdate} and a mandatory {@code nextUpdate}. The request and
     * response must either both omit the native nonce or contain identical nonces
     * of one through 4,096 bytes. Single-response extensions are not accepted.
     *
     * <p>Times must be supported whole-second values with thisUpdate no later than
     * producedAt and nextUpdate after thisUpdate. No clock is consulted, so these
     * relationships do not establish freshness at the caller's evaluation time.
     * Supported times range from the Unix epoch through the last second of year
     * 9999, inclusive. A parsed {@code GOOD} status is not certificate-path validity.
     *
     * @param requestDer the original complete native request; must be non-null and nonempty
     * @param responseDer the complete native response; must be non-null and nonempty
     * @param expectedSignatureAlgorithm the exact DER AlgorithmIdentifier required
     *     by the caller; must be non-null and nonempty
     * @return a structurally checked projection with defensively owned byte arrays
     * @throws IllegalArgumentException if an argument is null or empty, an encoding
     *     exceeds its bound, or native structure or correspondence violates this profile
     */
    // Untrusted parser/crypto exceptions are normalized to the existing finite safe failure.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public static Projection parse(byte[] requestDer, byte[] responseDer, byte[] expectedSignatureAlgorithm) {
        requireInputBounds(requestDer, responseDer);
        if (expectedSignatureAlgorithm == null || expectedSignatureAlgorithm.length == 0) { throw invalid(); }
        try {
            ParsedNative parsed = readNative(requestDer, responseDer, expectedSignatureAlgorithm);
            OCSPReq request = parsed.request();
            BasicOCSPResp response = parsed.response();
            OcspResponse nativeResponse = parsed.nativeResponse();
            OcspRequest nativeRequest = parsed.nativeRequest();
            Req[] wanted = request.getRequestList();
            SingleResp[] actual = response.getResponses();
            requireMatchingRequest(wanted, actual, nativeRequest, nativeResponse);
            List<Status> values = new ArrayList<>(actual.length);
            java.util.Set<String> seen = new HashSet<>();
            java.util.Set<String> requestedIds = new HashSet<>();
            Instant update = whole(actual[0].getThisUpdate().toInstant());
            if (actual[0].getNextUpdate() == null) {
                throw invalid();
            }
            Instant next = whole(actual[0].getNextUpdate().toInstant());
            for (int index = 0; index < actual.length; index++) {
                values.add(
                        statusValue(
                                actual[index], wanted[index], seen, requestedIds, update, next));
            }
            Instant produced = whole(response.getProducedAt().toInstant());
            if (update.isAfter(produced) || !next.isAfter(update)) {
                throw invalid();
            }
            return new Projection(produced, update, next, nativeResponse.nonce(), values,
                    response.getSignatureAlgorithmID().getEncoded(DER),
                    ResponseSyntax.requireCertificates(response));
        } catch (IOException | org.bouncycastle.cert.ocsp.OCSPException malformed) {
            throw invalid();
        }
    }

    /**
     * Requires a nonempty bounded one-to-one entry count and equal optional native nonces.
     *
     * <p>Individual identities are checked separately, in their original order,
     * when each status entry is projected.
     */
    private static void requireMatchingRequest(
            Req[] wanted,
            SingleResp[] actual,
            OcspRequest nativeRequest,
            OcspResponse nativeResponse) {
        if (wanted.length == 0
                || wanted.length > 819
                || actual.length != wanted.length
                || !equalNonce(nativeRequest.nonce(), nativeResponse.nonce())) {
            throw invalid();
        }
    }

    /**
     * Rejects absent, empty or oversized native inputs before creating parser objects.
     */
    private static void requireInputBounds(byte[] requestDer, byte[] responseDer) {
        if (requestDer == null
                || responseDer == null
                || requestDer.length == 0
                || responseDer.length == 0
                || requestDer.length > 1_048_576
                || responseDer.length > MAXIMUM_RESPONSE_BYTES) {
            throw invalid();
        }
    }

    /**
     * Holds the native parser views needed to compare exact wire values and typed projections.
     */
    private record ParsedNative(
            OCSPReq request,
            BasicOCSPResp response,
            OcspRequest nativeRequest,
            OcspResponse nativeResponse) {}

    /**
     * Reads canonical native envelopes and enforces response-shape and nonce-size limits.
     *
     * <p>Both low-level and provider-neutral parser views are retained so that
     * status matching uses native identities while nonce values use the library's
     * decoded representation. Neither view establishes signature validity.
     */
    private static ParsedNative readNative(byte[] requestDer, byte[] responseDer, byte[] expectedSignatureAlgorithm)
            throws IOException, org.bouncycastle.cert.ocsp.OCSPException {
        OCSPReq request = new OCSPReq(requestDer);
        OCSPResp outer = new OCSPResp(responseDer);
        if (!Arrays.equals(requestDer, request.getEncoded())
                || !Arrays.equals(responseDer, outer.getEncoded())
                || outer.getStatus() != 0
                || !(outer.getResponseObject() instanceof BasicOCSPResp response)) {
            throw invalid();
        }
        ResponseSyntax.requireResponseShape(response, expectedSignatureAlgorithm);
        OcspRequest nativeRequest = Pkix.parseOcspRequest(requestDer);
        OcspResponse nativeResponse = Pkix.parseOcspResponse(responseDer);
        if (nativeRequest
                        .nonce()
                        .filter(value -> value.length == 0 || value.length > 4_096)
                        .isPresent()
                || nativeResponse
                        .nonce()
                        .filter(value -> value.length == 0 || value.length > 4_096)
                        .isPresent()) {
            throw invalid();
        }
        return new ParsedNative(request, response, nativeRequest, nativeResponse);
    }

    /**
     * Converts one matched native entry while preserving its status and optional revocation details.
     *
     * <p>The shared identity sets reject duplicates in either sequence. Native
     * revocation times use the same supported whole-second range as other times;
     * reason values are absent or within the supported CRL reason range, excluding 7.
     */
    private static Status statusValue(
            SingleResp item,
            Req wanted,
            java.util.Set<String> seen,
            java.util.Set<String> requestedIds,
            Instant update,
            Instant next)
            throws IOException {
        if (item.hasExtensions()) {
            throw invalid();
        }
        byte[] certId = item.getCertID().toASN1Primitive().getEncoded(DER);
        ResponseSyntax.requireStatusIdentity(item, wanted, seen, requestedIds, update, next);
        String state = "GOOD";
        String revoked = "";
        int reason = -LIMIT_1;
        if (item.getCertStatus() instanceof RevokedStatus status) {
            state = "REVOKED";
            revoked = whole(status.getRevocationTime().toInstant()).toString();
            if (status.hasRevocationReason()) {
                reason = status.getRevocationReason();
            }
            if (reason < -LIMIT_1 || reason > 10 || reason == 7) {
                throw invalid();
            }
        } else if (item.getCertStatus() instanceof UnknownStatus) {
            state = "UNKNOWN";
        } else if (item.getCertStatus() != null) {
            throw invalid();
        }
        return new Status(certId, state, revoked, reason);
    }

    /**
     * Compares nonce presence and bytes without treating an absent nonce as an empty one.
     */
    private static boolean equalNonce(
            java.util.Optional<byte[]> left, java.util.Optional<byte[]> right) {
        return left.isPresent() == right.isPresent()
                && (left.isEmpty() || Arrays.equals(left.orElseThrow(), right.orElseThrow()));
    }

    /**
     * Requires a whole-second instant within the profile's epoch-through-year-9999 range.
     */
    private static Instant whole(Instant time) {
        if (time.getNano() != 0
                || time.getEpochSecond() < 0
                || time.getEpochSecond() > 253_402_300_799L) {
            throw invalid();
        }
        return time;
    }

    /**
     * Returns a representation-independent identity for a bounded native CertID.
     *
     * <p>The CertID must be canonical DER and use SHA-1 or SHA-256 with absent or
     * ASN.1 NULL parameters. Both issuer hashes must have the length required by
     * that digest, and the serial number must be positive and at most 160 bits.
     * Absent and NULL digest parameters intentionally yield the same identity.
     * This operation does not locate an issuer or verify a response signature.
     *
     * @param bytes the complete CertID DER; must be non-null, nonempty and at most 108 bytes
     * @return the digest OID, lowercase issuer-name-hash hex, lowercase issuer-key-hash
     *     hex and decimal serial number, in that order and separated by colons
     * @throws IllegalArgumentException if the input is null, empty, oversized,
     *     noncanonical or violates the supported digest, hash-length or serial-number rules
     */
    public static String certIdIdentity(byte[] bytes) {
        return CertIdSyntax.identity(bytes);
    }

    /**
     * Enforces the restricted CertID syntax before deriving an identity that ignores NULL parameters.
     */
    private static final class CertIdSyntax {
        // Preserve the finite safe parser failure without exposing untrusted causes.
        /**
         * Parses one bounded canonical CertID and encodes its validated semantic identity.
         */
        @SuppressWarnings("PMD.PreserveStackTrace")
        private static String identity(byte[] bytes) {
            if (bytes == null || bytes.length == 0 || bytes.length > 108) { throw invalid(); }
            try {
                CertID id = CertID.getInstance(bytes);
                if (!Arrays.equals(bytes, id.getEncoded(DER)) || bytes.length > 108) {
                    throw invalid();
                }
                AlgorithmIdentifier algorithm = id.getHashAlgorithm();
                requireComponents(id, hashLength(algorithm));
                return algorithm.getAlgorithm().getId()
                        + ":"
                        + HexFormat.of().formatHex(id.getIssuerNameHash().getOctets())
                        + ":"
                        + HexFormat.of().formatHex(id.getIssuerKeyHash().getOctets())
                        + ":"
                        + id.getSerialNumber().getValue();
            } catch (IOException malformed) {
                throw invalid();
            }
        }

        /**
         * Requires a supported digest with absent or NULL parameters and returns its hash size.
         */
        private static int hashLength(AlgorithmIdentifier algorithm) {
            if (algorithm.getParameters() != null
                    && !(algorithm.getParameters() instanceof org.bouncycastle.asn1.ASN1Null)) {
                throw invalid();
            }
            return switch (algorithm.getAlgorithm().getId()) {
                case "1.3.14.3.2.26" -> 20;
                case "2.16.840.1.101.3.4.2.1" -> 32;
                default -> throw invalid();
            };
        }

        /**
         * Requires digest-sized issuer hashes and a positive serial number of at most 160 bits.
         */
        private static void requireComponents(CertID id, int hashLength) {
            if (id.getIssuerNameHash().getOctets().length != hashLength
                    || id.getIssuerKeyHash().getOctets().length != hashLength
                    || id.getSerialNumber().getValue().signum() <= 0
                    || id.getSerialNumber().getValue().bitLength() > 160) {
                throw invalid();
            }
        }
    }

    /**
     * Creates the finite profile-validation failure without embedding untrusted native values.
     */
    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("OCSP projection invalid");
    }

    /**
     * Holds one native certificate-status entry without exposing its retained CertID array.
     *
     * <p>Entries returned by {@link StrictOcspProjection#parse(byte[], byte[], byte[])}
     * have status {@code GOOD}, {@code REVOKED} or {@code UNKNOWN}. Only a revoked
     * entry carries a whole-second ISO-8601 revocation time; other entries carry
     * an empty string. A missing revocation reason is represented by {@code -1}.
     * These are parsed assertions from a response, not independently authenticated status.
     *
     * <p>The public constructor copies {@code certIdDer} but does not validate its
     * DER or any status semantics. In particular, directly supplied strings may
     * be null and the reason need not be one of the parser's accepted values.
     *
     * @param certIdDer native CertID bytes; copied on construction and access
     * @param status parsed status text, or the unvalidated directly supplied value
     * @param revocationTime parsed revocation time or empty string, or the unvalidated
     *     directly supplied value
     * @param reason parsed CRL reason or {@code -1}, or the unvalidated directly supplied value
     */
    public record Status(byte[] certIdDer, String status, String revocationTime, int reason) {
        /**
         * Creates a status entry with an independently owned copy of its native identity.
         *
         * <p>Direct construction does not parse the CertID, validate the status
         * text or enforce a relationship between status, revocation time and reason.
         * Use the parser when the restricted native-profile checks are required.
         *
         * @param certIdDer native CertID bytes; must not be {@code null}
         * @param status status text, retained unchanged; may be {@code null}
         * @param revocationTime revocation-time text, retained unchanged; may be {@code null}
         * @param reason the reason value, retained without range validation
         * @throws NullPointerException if {@code certIdDer} is {@code null}
         */
        public Status { certIdDer = certIdDer.clone(); }

        /**
         * Returns the native certificate identity without exposing this entry's byte storage.
         *
         * <p>Each call creates a new array. Modifying it cannot change this entry.
         * Bytes from a directly constructed entry are not necessarily valid DER.
         *
         * @return a new copy of the retained native CertID bytes; never {@code null}
         */
        @Override public byte[] certIdDer() { return certIdDer.clone(); }
    }

    /**
     * Holds the native values needed for subsequent OCSP verification and policy evaluation.
     *
     * <p>Parser-produced instances contain matching, ordered status entries, common
     * update times, the native nonce, the response signature algorithm and embedded
     * certificates in their encoded order. They satisfy this class's structural
     * profile, but neither their signatures nor their trust and current freshness
     * have been established.
     *
     * <p>Construction copies mutable byte arrays and collection storage. Accessors
     * for byte-valued components return copies. Direct construction does not
     * validate DER, temporal relationships or status semantics, and permits null
     * time components. Consumers must not treat arbitrary constructed instances
     * as parser-validated responses.
     *
     * @param producedAt native production time; may be null on direct construction
     * @param thisUpdate common status time; may be null on direct construction
     * @param nextUpdate common mandatory expiry when parsed; may be null on direct construction
     * @param nonce the optional native nonce; its contained bytes are defensively copied
     * @param statuses ordered, non-null status entries retained in an unmodifiable list
     * @param algorithmIdentifier response signature AlgorithmIdentifier bytes; defensively copied
     * @param certificates ordered embedded certificate bytes; each array is defensively copied
     */
    public record Projection(Instant producedAt, Instant thisUpdate, Instant nextUpdate,
            java.util.Optional<byte[]> nonce, List<Status> statuses, byte[] algorithmIdentifier,
            List<byte[]> certificates) {
        /**
         * Creates a projection that owns copies of its mutable byte and collection inputs.
         *
         * <p>Times are retained as supplied, including nulls. Status entries are
         * immutable records and are retained in their original order. No native
         * syntax, signature, time relationship or trust check is performed here.
         *
         * @param producedAt supplied production time; may be {@code null}
         * @param thisUpdate supplied common status time; may be {@code null}
         * @param nextUpdate supplied common expiry; may be {@code null}
         * @param nonce optional native nonce; must not be {@code null}; present bytes are copied
         * @param statuses ordered entries; neither the list nor an entry may be {@code null}
         * @param algorithmIdentifier signature algorithm bytes; must not be {@code null}
         * @param certificates ordered certificate bytes; neither the list nor an array
         *     may be {@code null}
         * @throws NullPointerException if a required container, array or status entry is null
         */
        public Projection {
            nonce = nonce.map(byte[]::clone);
            statuses = List.copyOf(statuses);
            algorithmIdentifier = algorithmIdentifier.clone();
            certificates = certificates.stream().map(byte[]::clone).toList();
        }

        /**
         * Returns the optional native nonce without exposing the retained nonce bytes.
         *
         * <p>An absent nonce remains absent. When present, the returned optional
         * contains a new byte array, so modifying it cannot change this projection.
         * Direct construction does not enforce the parser's nonce-length bounds.
         *
         * @return an optional containing a new nonce-byte copy, or an empty optional;
         *     never {@code null}
         */
        @Override public java.util.Optional<byte[]> nonce() { return nonce.map(byte[]::clone); }

        /**
         * Returns the response signature algorithm representation in independently owned storage.
         *
         * <p>Each call creates a new array. The bytes are an exact native
         * AlgorithmIdentifier when the projection came from parsing; direct
         * construction does not establish that they are valid DER.
         *
         * @return a new copy of the retained signature algorithm bytes; never {@code null}
         */
        @Override public byte[] algorithmIdentifier() { return algorithmIdentifier.clone(); }

        /**
         * Returns the embedded certificates in their retained order without exposing their arrays.
         *
         * <p>The returned list is unmodifiable and contains a new array for every
         * certificate. Changing an array therefore cannot change this projection.
         * These certificates are untrusted response data; this accessor does not
         * parse them, select a certification path or verify their signatures.
         *
         * @return an unmodifiable ordered list of independently owned certificate
         *     byte arrays; never {@code null}, and empty when none were retained
         */
        @Override public List<byte[]> certificates() { return certificates.stream().map(byte[]::clone).toList(); }
    }

    /**
     * Enforces response, certificate-identity and signature-representation constraints before projection.
     */
    private static final class ResponseSyntax {
        /**
         * Requires the selected signature algorithm, bounded responder identity and nonce-only extensions.
         *
         * <p>The algorithm bytes must match exactly; no NULL-versus-absent
         * equivalence is applied to the response signature algorithm here.
         */
        private static void requireResponseShape(BasicOCSPResp response, byte[] expectedSignatureAlgorithm) throws IOException {
            if (!Arrays.equals(
                            response.getSignatureAlgorithmID().getEncoded(DER),
                            expectedSignatureAlgorithm)
                    || response.getSignature().length > 104
                    || response.getSignature().length < 8) {
                throw invalid();
            }
            requireSignature(response);
            ResponderID identity = response.getResponderId().toASN1Primitive();
            if (identity.getName() != null
                            && identity.getName().getEncoded(DER).length > LIMIT_262_144
                    || identity.getKeyHash() != null && identity.getKeyHash().length != 20) {
                throw invalid();
            }
            List<?> extensions = response.getExtensionOIDs();
            if (extensions.size() > LIMIT_1) {
                throw invalid();
            }
            for (Object value : extensions) {
                ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(value);
                if (!"1.3.6.1.5.5.7.48.1.2".equals(oid.getId())
                        || response.getExtension(oid).isCritical()) {
                    throw invalid();
                }
            }
        }

        /**
         * Forms the semantic identity of a CertID whose digest and component sizes were checked separately.
         */
        private static String certIdIdentity(CertID id) {
            return id.getHashAlgorithm().getAlgorithm().getId()
                    + ":"
                    + HexFormat.of().formatHex(id.getIssuerNameHash().getOctets())
                    + ":"
                    + HexFormat.of().formatHex(id.getIssuerKeyHash().getOctets())
                    + ":"
                    + id.getSerialNumber().getValue();
        }

        /**
         * Requires a supported issuer-hash algorithm and digest-sized native identity components.
         *
         * <p>Absent and NULL digest parameters are both accepted. Serial-number
         * constraints are checked with the complete ordered status correspondence.
         */
        private static void requireCertId(CertID id) {
            AlgorithmIdentifier algorithm = id.getHashAlgorithm();
            String oid = algorithm.getAlgorithm().getId();
            int size =
                    switch (oid) {
                        case "1.3.14.3.2.26" -> 20;
                        case "2.16.840.1.101.3.4.2.1" -> LIMIT_32;
                        default -> throw invalid();
                    };
            if (algorithm.getParameters() != null
                            && !(algorithm.getParameters()
                                    instanceof org.bouncycastle.asn1.ASN1Null)
                    || id.getIssuerNameHash().getOctets().length != size
                    || id.getIssuerKeyHash().getOctets().length != size) {
                throw invalid();
            }
        }

        /**
         * Requires an ordered matching identity, no duplicate identities and the shared update times.
         *
         * <p>Digest parameters may be absent or NULL without changing identity.
         * The supplied sets retain identities already accepted in either sequence
         * so later duplicate entries cannot be projected as independent statuses.
         */
        private static void requireStatusIdentity(
                SingleResp item,
                Req wanted,
                java.util.Set<String> seen,
                java.util.Set<String> requestedIds,
                Instant update,
                Instant next) {
            CertID responseId = item.getCertID().toASN1Primitive();
            CertID requestId = wanted.getCertID().toASN1Primitive();
            requireCertId(responseId);
            requireCertId(requestId);
            if (!responseId
                            .getHashAlgorithm()
                            .getAlgorithm()
                            .equals(requestId.getHashAlgorithm().getAlgorithm())
                    || !Arrays.equals(
                            responseId.getIssuerNameHash().getOctets(),
                            requestId.getIssuerNameHash().getOctets())
                    || !Arrays.equals(
                            responseId.getIssuerKeyHash().getOctets(),
                            requestId.getIssuerKeyHash().getOctets())
                    || !responseId
                            .getSerialNumber()
                            .hasValue(requestId.getSerialNumber().getValue())
                    || !seen.add(certIdIdentity(responseId))
                    || !requestedIds.add(certIdIdentity(requestId))
                    || item.getNextUpdate() == null
                    || !update.equals(whole(item.getThisUpdate().toInstant()))
                    || !next.equals(whole(item.getNextUpdate().toInstant()))
                    || item.getCertID().getSerialNumber().signum() <= 0
                    || item.getCertID().getSerialNumber().bitLength() > 160
                    || !java.util.Set.of("1.3.14.3.2.26", "2.16.840.1.101.3.4.2.1")
                            .contains(item.getCertID().getHashAlgOID().getId())) {
                throw invalid();
            }
        }

        /**
         * Requires version-zero response data and canonical, positive ECDSA signature integers.
         *
         * <p>The signature BIT STRING must be octet-aligned and both integers
         * must fit within 384 bits. These syntax bounds do not verify a signature
         * or replace the caller's curve-specific cryptographic checks.
         */
        private static void requireSignature(BasicOCSPResp response) throws IOException {
            BasicOCSPResponse nativeBasic = BasicOCSPResponse.getInstance(response.getEncoded());
            if (nativeBasic.getSignature().getPadBits() != 0
                    || nativeBasic.getTbsResponseData().getVersion().intValueExact() != 0) {
                throw invalid();
            }
            ASN1Sequence signature = ASN1Sequence.getInstance(response.getSignature());
            if (!Arrays.equals(signature.getEncoded(DER), response.getSignature())
                    || signature.size() != 2) {
                throw invalid();
            }
            for (ASN1Encodable item : signature) {
                BigInteger integer = org.bouncycastle.asn1.ASN1Integer.getInstance(item).getValue();
                if (integer.signum() <= 0 || integer.bitLength() > 384) {
                    throw invalid();
                }
            }
        }

        /**
         * Extracts ordered embedded certificates within the count and per-certificate allocation limits.
         *
         * <p>No more than 32 certificates are accepted, each at most 262,144
         * encoded bytes. The returned data is untrusted certificate material;
         * no certification path is selected or validated by this operation.
         */
        private static List<byte[]> requireCertificates(BasicOCSPResp response) throws IOException {
            X509CertificateHolder[] certificates = response.getCerts();
            if (certificates.length > LIMIT_32) {
                throw invalid();
            }
            List<byte[]> encoded = new ArrayList<>(certificates.length);
            for (X509CertificateHolder certificate : certificates) {
                byte[] bytes = certificate.getEncoded();
                if (bytes.length > LIMIT_262_144) {
                    throw invalid();
                }
                encoded.add(bytes);
            }
            return List.copyOf(encoded);
        }
    }
}
