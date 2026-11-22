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

import java.time.Instant;
import java.util.List;
import java.util.Map;
import zeroecho.pki.api.hybrid.sdk.HybridSdkFrame;
import zeroecho.pki.api.hybrid.sdk.HybridSdkValue;
import zeroecho.pkix.ocsp.StrictOcspProjection;

/**
 * Converts a structurally checked native OCSP exchange into the SDK F4/F5 value representation.
 *
 * <p>Native request and response parsing is delegated to the provider-neutral
 * library. This layer selects the SDK's fixed primary signature algorithm and
 * enforces the additional size limits of {@link HybridSdkValue}. It derives
 * statuses and nonce values from native bytes rather than caller-supplied
 * assertions. Signature verification, responder authorization and freshness
 * evaluation remain separate responsibilities.
 */
public final class SdkOcspProjection {
    /**
     * Maximum complete native response size accepted by the SDK structural parser, in bytes.
     *
     * <p>The native DER ceiling is shared with
     * {@link StrictOcspProjection#MAXIMUM_RESPONSE_BYTES}. Individual SDK typed
     * values and aggregates remain subject to stricter bounds during projection.
     */
    public static final int MAXIMUM_RESPONSE_BYTES = StrictOcspProjection.MAXIMUM_RESPONSE_BYTES;
    private SdkOcspProjection() {}

    /**
     * Parses a native OCSP exchange and constructs its bounded SDK projection.
     *
     * <p>The native profile requires canonical encodings, ordered matching and
     * nonduplicate CertIDs, common whole-second update times and equal optional
     * nonces. The signature AlgorithmIdentifier must match the SDK primary
     * algorithm. The resulting nonce and status values must also satisfy the
     * SDK encoding limits, including the 262,144-byte aggregate ceilings checked here.
     *
     * <p>No evaluation clock, trust discovery or signature verification is used.
     * Inputs are borrowed for the call and must not be modified concurrently.
     * The returned value does not authenticate the parsed status assertions.
     *
     * @param requestDer the original complete request; must be non-null, nonempty
     *     and at most one mebibyte
     * @param responseDer the original complete successful response; must be non-null,
     *     nonempty and no larger than {@link #MAXIMUM_RESPONSE_BYTES}
     * @return the structurally checked SDK projection derived from native values
     * @throws IllegalArgumentException if an input is null, empty, oversized or
     *     violates the native profile or SDK typed-value bounds
     */
    @SuppressWarnings("PMD.PreserveStackTrace") // Keep the finite safe SDK parser failure.
    public static Projection parse(byte[] requestDer, byte[] responseDer) {
        Projection projection;
        try {
            StrictOcspProjection.Projection parsed = StrictOcspProjection.parse(
                    requestDer, responseDer, HybridSdkFrame.primaryAlgorithm());
            // The SDK representation has stricter aggregate bounds than native DER.
            HybridSdkValue.list(parsed.certificates().stream().map(HybridSdkValue::bytes).toList());
            HybridSdkValue nonce = HybridSdkValue.object(Map.of(
                    "present", HybridSdkValue.bool(parsed.nonce().isPresent()),
                    "value", HybridSdkValue.bytes(parsed.nonce().orElseGet(() -> new byte[0]))));
            List<HybridSdkValue> values = parsed.statuses().stream().map(SdkOcspProjection::statusValue).toList();
            HybridSdkValue statuses = HybridSdkValue.list(values);
            projection = new Projection(parsed.producedAt(), parsed.thisUpdate(), parsed.nextUpdate(),
                    nonce, statuses, parsed.algorithmIdentifier());
        } catch (IllegalArgumentException malformed) {
            throw invalid();
        }
        if (projection.statuses().encode().length > 262_144
                || projection.nonce().encode().length > 262_144) {
            throw invalid();
        }
        return projection;
    }

    private static HybridSdkValue statusValue(StrictOcspProjection.Status status) {
        return HybridSdkValue.object(Map.of(
                "certIdDer", HybridSdkValue.bytes(status.certIdDer()),
                "status", HybridSdkValue.text(status.status()),
                "revocationTime", HybridSdkValue.text(status.revocationTime()),
                "reason", HybridSdkValue.integer(status.reason())));
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

}
