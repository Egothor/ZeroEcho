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
package zeroecho.core.alg.ed448;

import java.util.Base64;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>Ed448 Public Key Specification</h2>
 *
 * Immutable specification for an Ed448 public key in X.509 encoding.
 *
 * <p>
 * This class acts as a typed carrier for encoded public key material, typically
 * used with {@link Ed448PublicKeyBuilder} to reconstruct a usable
 * {@link java.security.PublicKey}. It also provides marshal/unmarshal helpers
 * to serialize the key into a portable {@link PairSeq} representation.
 * </p>
 *
 * <h2>Encoding</h2>
 * <ul>
 * <li>The byte array is expected to contain a valid X.509-encoded Ed448 public
 * key.</li>
 * <li>The constructor defensively clones the provided array, and
 * {@link #encoded()} returns a fresh copy on each call.</li>
 * <li>The {@link #marshal(Ed448PublicKeySpec)} and {@link #unmarshal(PairSeq)}
 * methods wrap and unwrap the X.509 bytes using base64 without padding.</li>
 * </ul>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Wrap existing X.509-encoded bytes
 * Ed448PublicKeySpec spec = new Ed448PublicKeySpec(x509Bytes);
 *
 * // Import into JCA PublicKey via builder
 * PublicKey key = new Ed448PublicKeyBuilder().importPublic(spec);
 *
 * // Serialize to PairSeq (e.g., for transport)
 * PairSeq p = Ed448PublicKeySpec.marshal(spec);
 *
 * // Deserialize from PairSeq
 * Ed448PublicKeySpec restored = Ed448PublicKeySpec.unmarshal(p);
 * }</pre>
 *
 * <h2>Thread-safety</h2> Instances are immutable and safe to share across
 * threads.
 *
 * @since 1.0
 */
public final class Ed448PublicKeySpec implements AlgorithmKeySpec {

    private static final String X509_B64 = "x509.b64";
    private final byte[] encodedX509;

    /**
     * Constructs a new Ed448 public key spec from the given X.509-encoded bytes.
     *
     * @param encodedX509 X.509-encoded Ed448 public key (non-null)
     * @throws IllegalArgumentException if {@code encodedX509} is {@code null}
     */
    public Ed448PublicKeySpec(byte[] encodedX509) {
        if (encodedX509 == null) {
            throw new IllegalArgumentException("encodedX509 must not be null");
        }
        this.encodedX509 = encodedX509.clone();
    }

    /**
     * Returns a defensive copy of the X.509-encoded public key bytes.
     *
     * @return cloned X.509-encoded key bytes
     */
    public byte[] encoded() {
        return encodedX509.clone();
    }

    /**
     * Serializes this key spec into a {@link PairSeq} record.
     *
     * <p>
     * The encoding is base64 without padding. The {@code type} field is set to
     * {@code "Ed448-PUB"}, and the X.509 bytes are stored under the key
     * {@code "x509.b64"}.
     * </p>
     *
     * @param spec the key spec to serialize
     * @return a {@link PairSeq} containing the type and base64 data
     */
    public static PairSeq marshal(Ed448PublicKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.encodedX509);
        return PairSeq.of("type", "Ed448-PUB", X509_B64, b64);
    }

    /**
     * Deserializes a {@link PairSeq} into a new {@link Ed448PublicKeySpec}.
     *
     * <p>
     * Expects a field {@code "x509.b64"} containing the base64-encoded X.509 public
     * key bytes. Other fields are ignored.
     * </p>
     *
     * @param p the serialized pair sequence
     * @return a reconstructed {@link Ed448PublicKeySpec}
     * @throws IllegalArgumentException if {@code x509.b64} is missing
     */
    public static Ed448PublicKeySpec unmarshal(PairSeq p) {
        byte[] out = null;
        PairSeq.Cursor cur = p.cursor();
        while (cur.next()) {
            String k = cur.key();
            String v = cur.value();
            if (X509_B64.equals(k)) {
                out = Base64.getDecoder().decode(v);
            }
        }
        if (out == null) {
            throw new IllegalArgumentException("x509.b64 missing for Ed448 public key");
        }
        return new Ed448PublicKeySpec(out);
    }
}
