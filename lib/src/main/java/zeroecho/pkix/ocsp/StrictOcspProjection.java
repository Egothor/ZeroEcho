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
 * Bounded, provider-neutral structural projection of native OCSP request/response pairs.
 *
 * <p>The parser derives status and native-nonce values from the exact original
 * request and response, not caller-supplied status assertions. It does not verify
 * responder signatures or discover trust and does not implement standard
 * AltSignature OCSP.</p>
 */
public final class StrictOcspProjection {
    private static final String DER = "DER";
    private static final int LIMIT_1 = 1;
    private static final int LIMIT_32 = 32;
    private static final int LIMIT_262_144 = 262_144;

    /**
     * Complete-response ceiling derived from the supported native DER component bounds.
     * For D(n)=1+DER-length-octets(n)+n: single=171, nonce-extension=4127,
     * responseData=406357, BasicOCSPResponse=1455067, outer response=1455101.
     * This is a preallocation ceiling for this strict profile, not an ordinary OCSP quota.
     */
    public static final int MAXIMUM_RESPONSE_BYTES = responseLimit();

    private StrictOcspProjection() {}

    private static int der(int bytes) {
        int lengthBytes =
                bytes < 128
                        ? LIMIT_1
                        : LIMIT_1 + (Integer.SIZE - Integer.numberOfLeadingZeros(bytes) + 7) / 8;
        return Math.addExact(Math.addExact(LIMIT_1, lengthBytes), bytes);
    }

    private static int responseLimit() {
        int single = der(108 + der(17 + der(3)) + 17 + der(17));
        int nonce = der(der(der(11 + der(der(4_096)))));
        int data = der(5 + der(LIMIT_262_144) + 17 + der(819 * single) + nonce);
        int basic = der(data + 12 + der(105) + der(der(1_048_576)));
        return der(3 + der(der(11 + der(basic))));
    }

    /**
     * Parses exact native bytes and verifies ordered CertID/nonce and shared time correspondence.
     * This pure operation verifies structure, not signer authorization or signatures.
     * Work and memory are bounded by one MiB/request, the derived response ceiling and 819 entries.
     *
     * <p>Inputs are borrowed for parsing and must not be mutated concurrently. Checks
     * include canonical native encoding, a successful BasicOCSPResponse, the caller's exact
     * signature algorithm and bounded P-384 ECDSA signature syntax, ordered nonduplicate matching
     * CertIDs, common mandatory nextUpdate and matching optional native nonces of
     * 1 through 4096 bytes. SHA-1 and SHA-256 are the permitted CertID hash identities.</p>
     *
     * <p>Times must be supported whole-second values with thisUpdate no later than
     * producedAt and nextUpdate after thisUpdate. No clock is consulted, so these
     * relationships do not establish freshness at the caller's evaluation time.
     * GOOD is a parsed status value, not certificate-path validity.</p>
     *
     * @param requestDer original complete native request
     * @param responseDer complete successful native response
     * @param expectedSignatureAlgorithm exact DER AlgorithmIdentifier required by the caller
     * @return structurally checked projection; no signature or trust verification is performed
     * @throws IllegalArgumentException for malformed, oversized or inconsistent native values
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

    private record ParsedNative(
            OCSPReq request,
            BasicOCSPResp response,
            OcspRequest nativeRequest,
            OcspResponse nativeResponse) {}

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

    private static boolean equalNonce(
            java.util.Optional<byte[]> left, java.util.Optional<byte[]> right) {
        return left.isPresent() == right.isPresent()
                && (left.isEmpty() || Arrays.equals(left.orElseThrow(), right.orElseThrow()));
    }

    private static Instant whole(Instant time) {
        if (time.getNano() != 0
                || time.getEpochSecond() < 0
                || time.getEpochSecond() > 253_402_300_799L) {
            throw invalid();
        }
        return time;
    }

    /**
     * Validates a canonical SHA-1/SHA-256 native CertID and returns its digest/serial identity.
     * Absent versus NULL digest parameters have the same returned identity.
     * @param bytes complete canonical DER CertID, at most 108 bytes
     * @return digest OID, issuer hash hex values and positive serial separated by colons
     * @throws IllegalArgumentException for malformed DER, unsupported digest, hash lengths or serial
     */
    public static String certIdIdentity(byte[] bytes) {
        return CertIdSyntax.identity(bytes);
    }

    /** Strict canonical CertID syntax and digest/serial identity checks. */
    private static final class CertIdSyntax {
        // Preserve the finite safe parser failure without exposing untrusted causes.
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

        private static void requireComponents(CertID id, int hashLength) {
            if (id.getIssuerNameHash().getOctets().length != hashLength
                    || id.getIssuerKeyHash().getOctets().length != hashLength
                    || id.getSerialNumber().getValue().signum() <= 0
                    || id.getSerialNumber().getValue().bitLength() > 160) {
                throw invalid();
            }
        }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("OCSP projection invalid");
    }

    /**
     * Parsed native status entry; parsing enforces the documented strict profile.
     * Direct construction copies DER but does not validate status semantics.
     * @param certIdDer canonical native CertID representation
     * @param status GOOD, REVOKED or UNKNOWN when returned by parsing
     * @param revocationTime whole-second ISO-8601 time, or empty for an unrevoked entry
     * @param reason CRL reason, or -1 when absent
     */
    public record Status(byte[] certIdDer, String status, String revocationTime, int reason) {
        /**
         * Copies the native identity; other fields are retained without validation.
         * @param certIdDer native identity bytes, not null
         * @param status supplied status text
         * @param revocationTime supplied revocation time text
         * @param reason supplied reason
         * @throws NullPointerException if identity bytes are null
         */
        public Status { certIdDer = certIdDer.clone(); }

        /** @return independently owned native CertID bytes */
        @Override public byte[] certIdDer() { return certIdDer.clone(); }
    }

    /**
     * Immutable snapshot of parsed native values. Direct construction copies arrays
     * but does not establish structural validity, signature validity or trust.
     * @param producedAt native production time
     * @param thisUpdate common status time
     * @param nextUpdate mandatory common expiry
     * @param nonce optional native nonce
     * @param statuses ordered status entries
     * @param algorithmIdentifier response signature AlgorithmIdentifier DER
     * @param certificates ordered embedded certificate DER values
     */
    public record Projection(Instant producedAt, Instant thisUpdate, Instant nextUpdate,
            java.util.Optional<byte[]> nonce, List<Status> statuses, byte[] algorithmIdentifier,
            List<byte[]> certificates) {
        /**
         * Copies all mutable inputs without validating their semantic relationships.
         * @param producedAt native production time
         * @param thisUpdate common status time
         * @param nextUpdate common expiry
         * @param nonce optional native nonce, not null
         * @param statuses ordered entries, not null
         * @param algorithmIdentifier native algorithm bytes, not null
         * @param certificates ordered certificate bytes, not null
         * @throws NullPointerException if an array, collection or contained array is null
         */
        public Projection {
            nonce = nonce.map(byte[]::clone);
            statuses = List.copyOf(statuses);
            algorithmIdentifier = algorithmIdentifier.clone();
            certificates = certificates.stream().map(byte[]::clone).toList();
        }

        /** @return optional independently owned native nonce */
        @Override public java.util.Optional<byte[]> nonce() { return nonce.map(byte[]::clone); }
        /** @return independently owned algorithm DER */
        @Override public byte[] algorithmIdentifier() { return algorithmIdentifier.clone(); }
        /** @return ordered independently owned embedded certificate DER values */
        @Override public List<byte[]> certificates() { return certificates.stream().map(byte[]::clone).toList(); }
    }

    /** Validates native OCSP response representation before exposing the immutable projection. */
    private static final class ResponseSyntax {
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

        private static String certIdIdentity(CertID id) {
            return id.getHashAlgorithm().getAlgorithm().getId()
                    + ":"
                    + HexFormat.of().formatHex(id.getIssuerNameHash().getOctets())
                    + ":"
                    + HexFormat.of().formatHex(id.getIssuerKeyHash().getOctets())
                    + ":"
                    + id.getSerialNumber().getValue();
        }

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
