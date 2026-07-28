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
package zeroecho.core.alg.hqc;

import java.util.Base64;
import java.util.Objects;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.marshal.PairSeq.Cursor;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>HQC Public Key Specification</h2>
 *
 * {@link zeroecho.core.spec.AlgorithmKeySpec} wrapper for HQC public keys,
 * encoded in standard X.509 DER format.
 *
 * <p>
 * This class is used to transport and import HQC public keys into the
 * {@link HqcAlgorithm}. The encoded form is immutable and defensively copied on
 * construction and retrieval.
 * </p>
 *
 * <h2>Serialization</h2>
 * <p>
 * {@link #marshal(HqcPublicKeySpec)} encodes the key material into a
 * {@link PairSeq} with Base64 (unpadded) representation. The inverse
 * {@link #unmarshal(PairSeq)} restores the specification from such a sequence.
 * </p>
 *
 * <h2>Security note</h2>
 * <ul>
 * <li>Public keys are not confidential, but integrity is critical. They should
 * only be distributed over authenticated or integrity-protected channels.</li>
 * <li>The contained byte array is immutable and returned as a defensive copy to
 * avoid accidental modification.</li>
 * </ul>
 *
 * <h2>Usage example</h2> <pre>{@code
 * // Wrap an existing X.509 HQC public key
 * HqcPublicKeySpec spec = new HqcPublicKeySpec(x509Bytes);
 *
 * // Import into a PublicKey via HqcAlgorithm
 * HqcAlgorithm hqc = new HqcAlgorithm();
 * PublicKey pub = hqc.publicKeyImporter(HqcPublicKeySpec.class).importPublic(spec);
 *
 * // Serialize for transport
 * PairSeq serialized = HqcPublicKeySpec.marshal(spec);
 *
 * // Reconstruct from serialized form
 * HqcPublicKeySpec restored = HqcPublicKeySpec.unmarshal(serialized);
 * }</pre>
 *
 * @since 1.0
 */
public final class HqcPublicKeySpec implements AlgorithmKeySpec {

    private static final String X509_B64 = "x509.b64";
    private final byte[] x509;

    /**
     * Constructs a new public key spec from an X.509-encoded byte array.
     *
     * @param x509Der DER-encoded X.509 public key
     * @throws NullPointerException if {@code x509Der} is {@code null}
     */
    public HqcPublicKeySpec(byte[] x509Der) {
        this.x509 = Objects.requireNonNull(x509Der).clone();
    }

    /**
     * Returns a defensive copy of the X.509-encoded key material.
     *
     * @return cloned X.509 byte array
     */
    public byte[] x509() {
        return x509.clone();
    }

    /**
     * Serializes this spec into a {@link PairSeq} with Base64-encoded key data.
     *
     * <p>
     * The resulting sequence has keys:
     * <ul>
     * <li>{@code type} = {@code "HqcPublicKeySpec"}</li>
     * <li>{@code x509.b64} = Base64 of the X.509 key</li>
     * </ul>
     *
     * @param spec the spec to serialize
     * @return serialized representation in a {@link PairSeq}
     */
    public static PairSeq marshal(HqcPublicKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.x509);
        return PairSeq.of("type", "HqcPublicKeySpec", X509_B64, b64);
    }

    /**
     * Reconstructs a spec from its {@link PairSeq} representation.
     *
     * @param p sequence containing {@code x509.b64}
     * @return reconstructed {@code HqcPublicKeySpec}
     * @throws IllegalArgumentException if required field {@code x509.b64} is
     *                                  missing
     */
    public static HqcPublicKeySpec unmarshal(PairSeq p) {
        String b64 = null;
        for (Cursor cur = p.cursor(); cur.next();) {
            if (X509_B64.equals(cur.key())) {
                b64 = cur.value();
            }
        }
        if (b64 == null) {
            throw new IllegalArgumentException("HqcPublicKeySpec: missing x509.b64");
        }
        return new HqcPublicKeySpec(Base64.getDecoder().decode(b64));
    }

    /**
     * Returns a diagnostic string containing the encoded length.
     *
     * <p>
     * The actual key material is not exposed in this representation.
     * </p>
     *
     * @return string with the X.509 byte length
     */
    @Override
    public String toString() {
        return "HqcPublicKeySpec[len=" + x509.length + "]";
    }
}
