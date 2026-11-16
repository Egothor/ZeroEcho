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

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import zeroecho.pki.api.hybrid.sdk.HybridSdkValue;
import zeroecho.pkix.Pkix;

/**
 * Bounded native-DER projection used by the separate SDK F4/F5 OCSP profile.
 *
 * <p>The parser derives status and native-nonce values from the exact original
 * request and response, not caller-supplied status assertions. It does not verify
 * responder signatures or discover trust and does not implement standard
 * AltSignature OCSP.</p>
 */
public final class SdkOcspProjection {
    /**
     * SDK-only complete-response ceiling derived from native DER component bounds.
     * For D(n)=1+DER-length-octets(n)+n: single=171, nonce-extension=4127,
     * responseData=406357, BasicOCSPResponse=1455067, outer response=1455101.
     * This is a preallocation ceiling, not a native request limit or an ordinary OCSP quota.
     */
    public static final int MAXIMUM_RESPONSE_BYTES = responseLimit();
    private SdkOcspProjection() { }
    private static int der(int bytes) {
        int lengthBytes = bytes < 128 ? 1 : 1 + (Integer.SIZE - Integer.numberOfLeadingZeros(bytes) + 7) / 8;
        return Math.addExact(Math.addExact(1, lengthBytes), bytes);
    }
    private static int responseLimit() {
        int single = der(108 + der(17 + der(3)) + 17 + der(17));
        int nonce = der(der(der(11 + der(der(4096)))));
        int data = der(5 + der(262144) + 17 + der(819 * single) + nonce);
        int basic = der(data + 12 + der(105) + der(der(1048576)));
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
    public static Projection parse(byte[] requestDer, byte[] responseDer) {
        if (requestDer == null || responseDer == null || requestDer.length == 0 || responseDer.length == 0
                || requestDer.length > 1048576 || responseDer.length > MAXIMUM_RESPONSE_BYTES) throw invalid();
        try {
            var request = new OCSPReq(requestDer); var outer = new OCSPResp(responseDer);
            if (!Arrays.equals(requestDer, request.getEncoded()) || !Arrays.equals(responseDer, outer.getEncoded())
                    || outer.getStatus() != 0 || !(outer.getResponseObject() instanceof BasicOCSPResp response)) throw invalid();
            requireResponseShape(response);
            var nativeRequest = Pkix.parseOcspRequest(requestDer); var nativeResponse = Pkix.parseOcspResponse(responseDer);
            if (nativeRequest.nonce().filter(value -> value.length == 0 || value.length > 4096).isPresent()
                    || nativeResponse.nonce().filter(value -> value.length == 0 || value.length > 4096).isPresent()) throw invalid();
            var wanted = request.getRequestList(); var actual = response.getResponses();
            if (wanted.length == 0 || wanted.length > 819 || actual.length != wanted.length
                    || !equalNonce(nativeRequest.nonce(), nativeResponse.nonce())) throw invalid();
            var values = new java.util.ArrayList<HybridSdkValue>(actual.length); var seen = new HashSet<String>(); var requestedIds = new HashSet<String>();
            Instant update = whole(actual[0].getThisUpdate().toInstant());
            if (actual[0].getNextUpdate() == null) throw invalid();
            Instant next = whole(actual[0].getNextUpdate().toInstant());
            for (int index = 0; index < actual.length; index++) {
                var item = actual[index]; if (item.hasExtensions()) throw invalid(); byte[] certId = item.getCertID().toASN1Primitive().getEncoded("DER");
                var responseId = item.getCertID().toASN1Primitive(); var requestId = wanted[index].getCertID().toASN1Primitive();
                requireCertId(responseId); requireCertId(requestId);
                if (!responseId.getHashAlgorithm().getAlgorithm().equals(requestId.getHashAlgorithm().getAlgorithm())
                        || !Arrays.equals(responseId.getIssuerNameHash().getOctets(), requestId.getIssuerNameHash().getOctets())
                        || !Arrays.equals(responseId.getIssuerKeyHash().getOctets(), requestId.getIssuerKeyHash().getOctets())
                        || !responseId.getSerialNumber().hasValue(requestId.getSerialNumber().getValue())
                        || !seen.add(certIdIdentity(responseId)) || !requestedIds.add(certIdIdentity(requestId)) || item.getNextUpdate() == null
                        || !update.equals(whole(item.getThisUpdate().toInstant())) || !next.equals(whole(item.getNextUpdate().toInstant()))
                        || item.getCertID().getSerialNumber().signum() <= 0 || item.getCertID().getSerialNumber().bitLength() > 160
                        || !java.util.Set.of("1.3.14.3.2.26", "2.16.840.1.101.3.4.2.1").contains(item.getCertID().getHashAlgOID().getId())) throw invalid();
                String state = "GOOD", revoked = ""; int reason = -1;
                if (item.getCertStatus() instanceof RevokedStatus status) {
                    state = "REVOKED"; revoked = whole(status.getRevocationTime().toInstant()).toString();
                    if (status.hasRevocationReason()) reason = status.getRevocationReason();
                    if (reason < -1 || reason > 10 || reason == 7) throw invalid();
                } else if (item.getCertStatus() instanceof UnknownStatus) state = "UNKNOWN";
                else if (item.getCertStatus() != null) throw invalid();
                values.add(HybridSdkValue.object(Map.of("certIdDer", HybridSdkValue.bytes(certId), "status", HybridSdkValue.text(state),
                        "revocationTime", HybridSdkValue.text(revoked), "reason", HybridSdkValue.integer(reason))));
            }
            Instant produced = whole(response.getProducedAt().toInstant());
            if (update.isAfter(produced) || !next.isAfter(update)) throw invalid();
            var nonce = HybridSdkValue.object(Map.of("present", HybridSdkValue.bool(nativeResponse.nonce().isPresent()),
                    "value", HybridSdkValue.bytes(nativeResponse.nonce().orElseGet(() -> new byte[0]))));
            var statuses = HybridSdkValue.list(values);
            if (statuses.encode().length > 262144 || nonce.encode().length > 262144) throw invalid();
            return new Projection(produced, update, next, nonce, statuses, response.getSignatureAlgorithmID().getEncoded("DER"));
        } catch (IOException | org.bouncycastle.cert.ocsp.OCSPException malformed) { throw invalid(); }
    }
    private static void requireResponseShape(BasicOCSPResp response) throws IOException {
        if (!Arrays.equals(response.getSignatureAlgorithmID().getEncoded("DER"), zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.primaryAlgorithm())
                || response.getSignature().length > 104 || response.getSignature().length < 8) throw invalid();
        var nativeBasic = org.bouncycastle.asn1.ocsp.BasicOCSPResponse.getInstance(response.getEncoded());
        if (nativeBasic.getSignature().getPadBits() != 0 || nativeBasic.getTbsResponseData().getVersion().intValueExact() != 0) throw invalid();
        var signature = org.bouncycastle.asn1.ASN1Sequence.getInstance(response.getSignature());
        if (!Arrays.equals(signature.getEncoded("DER"), response.getSignature()) || signature.size() != 2) throw invalid();
        for (var item : signature) {
            var integer = org.bouncycastle.asn1.ASN1Integer.getInstance(item).getValue();
            if (integer.signum() <= 0 || integer.bitLength() > 384) throw invalid();
        }
        var identity = response.getResponderId().toASN1Primitive();
        if (identity.getName() != null && identity.getName().getEncoded("DER").length > 262144
                || identity.getKeyHash() != null && identity.getKeyHash().length != 20) throw invalid();
        var extensions = response.getExtensionOIDs();
        if (extensions.size() > 1) throw invalid();
        for (var value : extensions) {
            var oid = org.bouncycastle.asn1.ASN1ObjectIdentifier.getInstance(value);
            if (!oid.getId().equals("1.3.6.1.5.5.7.48.1.2") || response.getExtension(oid).isCritical()) throw invalid();
        }
        var certificates = response.getCerts();
        if (certificates.length > 32) throw invalid();
        var encoded = new java.util.ArrayList<HybridSdkValue>(certificates.length);
        for (var certificate : certificates) {
            byte[] bytes = certificate.getEncoded(); if (bytes.length > 262144) throw invalid();
            encoded.add(HybridSdkValue.bytes(bytes));
        }
        HybridSdkValue.list(encoded);
    }
    private static String certIdIdentity(org.bouncycastle.asn1.ocsp.CertID id) {
        return id.getHashAlgorithm().getAlgorithm().getId() + ":" + HexFormat.of().formatHex(id.getIssuerNameHash().getOctets())
                + ":" + HexFormat.of().formatHex(id.getIssuerKeyHash().getOctets()) + ":" + id.getSerialNumber().getValue();
    }
    private static void requireCertId(org.bouncycastle.asn1.ocsp.CertID id) {
        var algorithm = id.getHashAlgorithm(); String oid = algorithm.getAlgorithm().getId();
        int size = switch (oid) { case "1.3.14.3.2.26" -> 20; case "2.16.840.1.101.3.4.2.1" -> 32; default -> throw invalid(); };
        if (algorithm.getParameters() != null && !(algorithm.getParameters() instanceof org.bouncycastle.asn1.ASN1Null)
                || id.getIssuerNameHash().getOctets().length != size || id.getIssuerKeyHash().getOctets().length != size) throw invalid();
    }
    private static boolean equalNonce(java.util.Optional<byte[]> left, java.util.Optional<byte[]> right) {
        return left.isPresent() == right.isPresent() && (left.isEmpty() || Arrays.equals(left.orElseThrow(), right.orElseThrow()));
    }
    private static Instant whole(Instant time) { if (time.getNano() != 0 || time.getEpochSecond() < 0 || time.getEpochSecond() > 253402300799L) throw invalid(); return time; }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("SDK OCSP projection invalid"); }

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
    public record Projection(Instant producedAt, Instant thisUpdate, Instant nextUpdate, HybridSdkValue nonce,
            HybridSdkValue statuses, byte[] algorithmIdentifier) {
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
        public Projection { algorithmIdentifier = algorithmIdentifier.clone(); }
        /**
         * Returns a new copy of the retained signature algorithm representation.
         *
         * @return independently owned algorithm bytes
         */
        @Override public byte[] algorithmIdentifier() { return algorithmIdentifier.clone(); }
    }
}
