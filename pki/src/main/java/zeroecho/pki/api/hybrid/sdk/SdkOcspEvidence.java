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
 * @param primaryResponseDer complete native successful response, bounded by the derived SDK response ceiling
 * @param responderChain ordered responder followed by its exact issuer path, 2..32 certificates
 * @param primaryFrame canonical F4
 * @param alternativeFrame canonical F5 with identical fields
 * @param primarySignature canonical P384 signature, at most 104 bytes
 * @param alternativeSignature pure ML-DSA-87 signature, exactly 4627 bytes
 */
public record SdkOcspEvidence(byte[] primaryResponseDer, List<byte[]> responderChain,
        HybridSdkFrame primaryFrame, HybridSdkFrame alternativeFrame, byte[] primarySignature, byte[] alternativeSignature) {
    /** Validates finite envelope shape without authenticating its contents. */
    public SdkOcspEvidence {
        primaryResponseDer = bounded(primaryResponseDer, zeroecho.pki.application.SdkOcspProjection.MAXIMUM_RESPONSE_BYTES); responderChain = copyChain(responderChain);
        Objects.requireNonNull(primaryFrame, "primaryFrame"); Objects.requireNonNull(alternativeFrame, "alternativeFrame");
        primarySignature = bounded(primarySignature, 104); alternativeSignature = bounded(alternativeSignature, 4627);
        if (alternativeSignature.length != 4627 || primaryFrame.kind() != 4 || alternativeFrame.kind() != 5
                || !java.util.Arrays.equals(new HybridSdkFrame(5, primaryFrame.fields()).encode(), alternativeFrame.encode())) throw new IllegalArgumentException("Invalid SDK OCSP evidence");
    }
    /** @return independent native response bytes */
    @Override public byte[] primaryResponseDer() { return primaryResponseDer.clone(); }
    /** @return independent ordered chain and certificate bytes */
    @Override public List<byte[]> responderChain() { return responderChain.stream().map(byte[]::clone).toList(); }
    /** @return independent primary signature bytes */
    @Override public byte[] primarySignature() { return primarySignature.clone(); }
    /** @return independent alternative signature bytes */
    @Override public byte[] alternativeSignature() { return alternativeSignature.clone(); }
    static byte[] bounded(byte[] bytes, int maximum) {
        Objects.requireNonNull(bytes, "bytes"); if (bytes.length == 0 || bytes.length > maximum) throw new IllegalArgumentException("SDK OCSP size invalid"); return bytes.clone();
    }
    static List<byte[]> copyChain(List<byte[]> chain) {
        Objects.requireNonNull(chain, "chain"); if (chain.size() < 2 || chain.size() > 32) throw new IllegalArgumentException("SDK OCSP chain invalid");
        var copied = chain.stream().map(value -> bounded(value, 262144)).toList();
        HybridSdkValue.list(copied.stream().map(HybridSdkValue::bytes).toList()); return copied;
    }
}
