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
package zeroecho.core.alg.xmss;

import java.util.Base64;
import java.util.Objects;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.marshal.PairSeq.Cursor;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Encoded representation of an XMSS public key in X.509 (SubjectPublicKeyInfo)
 * format.
 *
 * <p>
 * XMSS public keys are stateless and can be freely shared. The BCPQC provider
 * encodes them as standard X.509 DER, compatible with
 * {@link java.security.KeyFactory#generatePublic(java.security.spec.KeySpec)}.
 * </p>
 *
 * @since 1.0
 */
public final class XmssPublicKeySpec implements AlgorithmKeySpec {

    private static final String X509_B64 = "x509.b64";
    private final byte[] x509;

    /**
     * Constructs a new spec from X.509 DER encoded XMSS public key bytes.
     *
     * @param x509Der X.509 DER bytes
     * @throws NullPointerException if {@code x509Der} is null
     */
    public XmssPublicKeySpec(byte[] x509Der) {
        this.x509 = Objects.requireNonNull(x509Der).clone();
    }

    /**
     * Returns a defensive copy of the X.509 encoded key bytes.
     *
     * @return X.509 DER bytes
     */
    public byte[] x509() {
        return x509.clone();
    }

    /**
     * Serializes this spec to a {@link PairSeq}.
     *
     * @param spec the spec to serialize
     * @return serialized representation
     */
    public static PairSeq marshal(XmssPublicKeySpec spec) {
        return PairSeq.of("type", "XmssPublicKeySpec", X509_B64,
                Base64.getEncoder().withoutPadding().encodeToString(spec.x509));
    }

    /**
     * Deserializes a spec from a {@link PairSeq}.
     *
     * @param p serialized representation
     * @return reconstructed spec
     * @throws IllegalArgumentException if required field is missing
     */
    public static XmssPublicKeySpec unmarshal(PairSeq p) {
        String b64 = null;
        for (Cursor cur = p.cursor(); cur.next();) {
            if (X509_B64.equals(cur.key())) {
                b64 = cur.value();
            }
        }
        if (b64 == null) {
            throw new IllegalArgumentException("XmssPublicKeySpec: missing x509.b64");
        }
        return new XmssPublicKeySpec(Base64.getDecoder().decode(b64));
    }

    @Override
    public String toString() {
        return "XmssPublicKeySpec[len=" + x509.length + "]";
    }
}
