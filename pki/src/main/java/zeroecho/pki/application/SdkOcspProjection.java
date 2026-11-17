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
package zeroecho.pki.application;

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

import zeroecho.pki.api.hybrid.sdk.HybridSdkValue;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.ocsp.OcspRequest;
import zeroecho.pkix.ocsp.OcspResponse;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * Bounded native-DER projection used by the separate SDK F4/F5 OCSP profile.
 *
 * <p>The parser derives status and native-nonce values from the exact original
 * request and response, not caller-supplied status assertions. It does not verify
 * responder signatures or discover trust and does not implement standard
 * AltSignature OCSP.</p>
 */
public final class SdkOcspProjection {
    private static final int LIMIT_1 = 1;
    private static final int LIMIT_32 = 32;
    private static final int LIMIT_262_144 = 262_144;

    /**
     * SDK-only complete-response ceiling derived from native DER component bounds.
     * For D(n)=1+DER-length-octets(n)+n: single=171, nonce-extension=4127,
     * responseData=406357, BasicOCSPResponse=1455067, outer response=1455101.
     * This is a preallocation ceiling, not a native request limit or an ordinary OCSP quota.
     */
    public static final int MAXIMUM_RESPONSE_BYTES = responseLimit();

    private SdkOcspProjection() {}

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
     * Work and memory are bounded by one MiB/request, the derived SDK response ceiling and 819 entries.
     *
     * <p>Inputs are borrowed for parsing and must not be mutated concurrently. Checks
     * include canonical native encoding, a successful BasicOCSPResponse, the fixed
     * primary signature algorithm and bounded syntax, ordered nonduplicate matching
     * CertIDs, common mandatory nextUpdate and matching optional native nonces of
     * 1 through 4096 bytes. The native nonce is distinct from the SDK challenge.
     * SHA-1 and SHA-256 are the permitted CertID hash identities.</p>
     *
     * <p>Times must be supported whole-second values with thisUpdate no later than
     * producedAt and nextUpdate after thisUpdate. No clock is consulted, so these
     * relationships do not establish freshness at the caller's evaluation time.
     * GOOD is a parsed status value, not certificate-path validity.</p>
     *
     * @param requestDer original complete native request
     * @param responseDer complete successful native response
     * @return canonical parsed projection; no caller status values are accepted
     * @throws IllegalArgumentException for malformed, oversized or inconsistent native values
     */
    // Untrusted parser/crypto exceptions are normalized to the existing finite safe failure.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public static Projection parse(byte[] requestDer, byte[] responseDer) {
        requireInputBounds(requestDer, responseDer);
        try {
            ParsedNative parsed = readNative(requestDer, responseDer);
            OCSPReq request = parsed.request();
            BasicOCSPResp response = parsed.response();
            OcspResponse nativeResponse = parsed.nativeResponse();
            OcspRequest nativeRequest = parsed.nativeRequest();
            Req[] wanted = request.getRequestList();
            SingleResp[] actual = response.getResponses();
            requireMatchingRequest(wanted, actual, nativeRequest, nativeResponse);
            List<HybridSdkValue> values = new ArrayList<>(actual.length);
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
            HybridSdkValue nonce =
                    HybridSdkValue.object(
                            Map.of(
                                    "present",
                                    HybridSdkValue.bool(nativeResponse.nonce().isPresent()),
                                    "value",
                                    HybridSdkValue.bytes(
                                            nativeResponse.nonce().orElseGet(() -> new byte[0]))));
            HybridSdkValue statuses = HybridSdkValue.list(values);
            if (statuses.encode().length > LIMIT_262_144 || nonce.encode().length > LIMIT_262_144) {
                throw invalid();
            }
            return new Projection(
                    produced,
                    update,
                    next,
                    nonce,
                    statuses,
                    response.getSignatureAlgorithmID().getEncoded("DER"));
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

    private static ParsedNative readNative(byte[] requestDer, byte[] responseDer)
            throws IOException, org.bouncycastle.cert.ocsp.OCSPException {
        OCSPReq request = new OCSPReq(requestDer);
        OCSPResp outer = new OCSPResp(responseDer);
        if (!Arrays.equals(requestDer, request.getEncoded())
                || !Arrays.equals(responseDer, outer.getEncoded())
                || outer.getStatus() != 0
                || !(outer.getResponseObject() instanceof BasicOCSPResp response)) {
            throw invalid();
        }
        ResponseSyntax.requireResponseShape(response);
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

    private static HybridSdkValue statusValue(
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
        byte[] certId = item.getCertID().toASN1Primitive().getEncoded("DER");
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
        return HybridSdkValue.object(
                Map.of(
                        "certIdDer",
                        HybridSdkValue.bytes(certId),
                        "status",
                        HybridSdkValue.text(state),
                        "revocationTime",
                        HybridSdkValue.text(revoked),
                        "reason",
                        HybridSdkValue.integer(reason)));
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

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("SDK OCSP projection invalid");
    }

    /**
     * Native public projection with defensively owned algorithm bytes.
     *
     * <p>{@link SdkOcspProjection#parse(byte[], byte[])} returns structurally checked values. Direct record
     * construction only clones the algorithm bytes; it does not enforce non-null
     * time/typed values, time order or the native projection schema. Consumers must
     * not treat arbitrary constructed instances as verified native responses.
     * Native signature verification remains separate.</p>
     * @param producedAt whole-second native production time
     * @param thisUpdate common whole-second status time
     * @param nextUpdate common mandatory whole-second expiry
     * @param nonce canonical closed native nonce value
     * @param statuses canonical ordered native status list
     * @param algorithmIdentifier exact native response signature AlgorithmIdentifier
     */
    public record Projection(
            Instant producedAt,
            Instant thisUpdate,
            Instant nextUpdate,
            HybridSdkValue nonce,
            HybridSdkValue statuses,
            byte[] algorithmIdentifier) {
        /**
         * Copies the algorithm bytes while retaining the other supplied value references.
         *
         * @param producedAt supplied production time; not validated here
         * @param thisUpdate supplied common status time; not validated here
         * @param nextUpdate supplied common expiry; not validated here
         * @param nonce supplied immutable typed nonce value; not validated here
         * @param statuses supplied immutable typed status list; not validated here
         * @param algorithmIdentifier supplied signature algorithm DER bytes; copied without parsing
         * @throws NullPointerException if the algorithm array is null
         */
        public Projection {
            algorithmIdentifier = algorithmIdentifier.clone();
        }

        /**
         * Returns a new copy of the retained signature algorithm representation.
         *
         * @return independently owned algorithm bytes
         */
        @Override
        public byte[] algorithmIdentifier() {
            return algorithmIdentifier.clone();
        }
    }

    /** Validates native OCSP response representation before exposing the immutable projection. */
    private static final class ResponseSyntax {
        private static void requireResponseShape(BasicOCSPResp response) throws IOException {
            if (!Arrays.equals(
                            response.getSignatureAlgorithmID().getEncoded("DER"),
                            zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.primaryAlgorithm())
                    || response.getSignature().length > 104
                    || response.getSignature().length < 8) {
                throw invalid();
            }
            requireSignature(response);
            ResponderID identity = response.getResponderId().toASN1Primitive();
            if (identity.getName() != null
                            && identity.getName().getEncoded("DER").length > LIMIT_262_144
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
            requireCertificates(response);
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
            if (!Arrays.equals(signature.getEncoded("DER"), response.getSignature())
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

        private static void requireCertificates(BasicOCSPResp response) throws IOException {
            X509CertificateHolder[] certificates = response.getCerts();
            if (certificates.length > LIMIT_32) {
                throw invalid();
            }
            List<HybridSdkValue> encoded = new ArrayList<>(certificates.length);
            for (X509CertificateHolder certificate : certificates) {
                byte[] bytes = certificate.getEncoded();
                if (bytes.length > LIMIT_262_144) {
                    throw invalid();
                }
                encoded.add(HybridSdkValue.bytes(bytes));
            }
            HybridSdkValue.list(encoded);
        }
    }
}
