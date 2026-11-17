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
package zeroecho.pki.api.hybrid.sdk;

import java.util.List;
import java.util.Objects;

/**
 * Immutable complete SDK OCSP bundle. Construction establishes bounds, not trust.
 * Arrays are copied on entry and read; no private material or resources are owned.
 *
 * <p>This is the separate SDK F4/F5 OCSP profile, not standard AltSignature OCSP.
 * Construction does not parse the native response or certificates, verify either
 * signature, establish responder authorization, bind a query/nonce or check time.
 * A consumer must perform those checks against trusted context at its actual
 * evaluation time; a retained bundle does not establish current freshness.</p>
 *
 * @param primaryResponseDer complete native successful response, bounded by the derived SDK response ceiling
 * @param responderChain ordered responder followed by its exact issuer path, 2..32 certificates
 * @param primaryFrame canonical F4
 * @param alternativeFrame canonical F5 with identical fields
 * @param primarySignature canonical P384 signature, at most 104 bytes
 * @param alternativeSignature pure ML-DSA-87 signature, exactly 4627 bytes
 */
public record SdkOcspEvidence(byte[] primaryResponseDer, List<byte[]> responderChain,
        HybridSdkFrame primaryFrame, HybridSdkFrame alternativeFrame, byte[] primarySignature, byte[] alternativeSignature) {
    /**
     * Copies the response, both signatures and each certificate after bounded shape checks.
     *
     * <p>The immutable F4/F5 references are retained and must carry identical public
     * fields after changing the F4 kind to F5. The chain has 2 through 32 nonempty
     * certificates of at most 262144 bytes each and must also fit the aggregate typed
     * list encoding bound; the per-certificate ceilings do not imply a 32-times ceiling.</p>
     *
     * @param primaryResponseDer complete native successful response, bounded by the derived SDK response
     *     ceiling
     * @param responderChain ordered responder followed by its exact issuer path, 2..32 certificates
     * @param primaryFrame canonical F4
     * @param alternativeFrame canonical F5 with identical fields
     * @param primarySignature canonical P384 signature, at most 104 bytes
     * @param alternativeSignature pure ML-DSA-87 signature, exactly 4627 bytes
     * @throws NullPointerException if an array, frame, chain or certificate element is null
     * @throws IllegalArgumentException if an array is empty or oversized, the chain fails its
     * count/aggregate bounds, the alternative signature is not 4627 bytes or the frames disagree
     */
    public SdkOcspEvidence {
        primaryResponseDer = bounded(primaryResponseDer, zeroecho.pki.application.SdkOcspProjection.MAXIMUM_RESPONSE_BYTES); responderChain = copyChain(responderChain);
        Objects.requireNonNull(primaryFrame, "primaryFrame"); Objects.requireNonNull(alternativeFrame, "alternativeFrame");
        primarySignature = bounded(primarySignature, 104); alternativeSignature = bounded(alternativeSignature, 4_627);
        if (alternativeSignature.length != 4_627 || primaryFrame.kind() != 4 || alternativeFrame.kind() != 5
                || !java.util.Arrays.equals(new HybridSdkFrame(5, primaryFrame.fields()).encode(), alternativeFrame.encode())) { throw new IllegalArgumentException("Invalid SDK OCSP evidence"); }
    }
    /**
     * Returns a new copy of the retained native response bytes.
     *
     * @return independently owned byte array
     */
    @Override public byte[] primaryResponseDer() { return primaryResponseDer.clone(); }
    /**
     * Returns an unmodifiable chain list containing new copies of every certificate.
     *
     * @return independently owned certificate arrays in retained responder-to-issuer order
     */
    @Override public List<byte[]> responderChain() { return responderChain.stream().map(byte[]::clone).toList(); }
    /**
     * Returns a new copy of the retained primary signature bytes.
     *
     * @return independently owned byte array
     */
    @Override public byte[] primarySignature() { return primarySignature.clone(); }
    /**
     * Returns a new copy of the retained alternative signature bytes.
     *
     * @return independently owned byte array
     */
    @Override public byte[] alternativeSignature() { return alternativeSignature.clone(); }
    /**
     * Checks the nonempty encoded size and takes an independent copy.
     *
     * @param bytes encoded evidence to copy
     * @param maximum inclusive maximum length in bytes
     * @return newly allocated evidence bytes
     * @throws NullPointerException if the array is null
     * @throws IllegalArgumentException if its length is zero or exceeds the maximum
     */
    /* default */ static byte[] bounded(byte[] bytes, int maximum) {
        Objects.requireNonNull(bytes, "bytes"); if (bytes.length == 0 || bytes.length > maximum) { throw new IllegalArgumentException("SDK OCSP size invalid"); } return bytes.clone();
    }
    /**
     * Copies and bounds the responder chain before its SDK value representation is built.
     *
     * @param chain responder-to-issuer chain containing two to 32 certificate arrays
     * @return unmodifiable list containing independent copies of each certificate
     * @throws NullPointerException if the list or a certificate array is null
     * @throws IllegalArgumentException if the chain count, a certificate's nonempty 262,144-byte bound or
     * the SDK encoding bound is violated
     */
    /* default */ static List<byte[]> copyChain(List<byte[]> chain) {
        Objects.requireNonNull(chain, "chain"); if (chain.size() < 2 || chain.size() > 32) { throw new IllegalArgumentException("SDK OCSP chain invalid"); }
        List<byte[]> copied = chain.stream().map(value -> bounded(value, 262_144)).toList();
        HybridSdkValue.list(copied.stream().map(HybridSdkValue::bytes).toList()); return copied;
    }
}
