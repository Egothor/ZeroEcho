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
package zeroecho.core.alg.xdh;

import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Key specification for an XDH (elliptic curve Diffie-Hellman) public key.
 *
 * <p>
 * This class encapsulates the X.509-encoded representation of a public key used
 * in modern Diffie-Hellman style agreements such as X25519 or X448. It provides
 * safe construction, serialization, and deserialization utilities suitable for
 * persistence, transmission, or integration with
 * {@link zeroecho.core.CryptoAlgorithm} key builders.
 * </p>
 *
 * <h2>Design goals</h2>
 * <ul>
 * <li>Encapsulation: the encoded key bytes are cloned defensively on input and
 * output to prevent accidental modification.</li>
 * <li>Interoperability: supports round-trip conversion to/from
 * {@link zeroecho.core.marshal.PairSeq} with base64 encoding.</li>
 * <li>Validation: throws explicit exceptions when mandatory fields are
 * missing.</li>
 * </ul>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Construct from an X.509-encoded public key
 * byte[] encoded = ...; // obtained from a certificate or peer
 * XdhPublicKeySpec spec = new XdhPublicKeySpec(encoded);
 *
 * // Marshal to a serializable structure
 * PairSeq p = XdhPublicKeySpec.marshal(spec);
 *
 * // Unmarshal back from serialized form
 * XdhPublicKeySpec spec2 = XdhPublicKeySpec.unmarshal(p);
 *
 * assert Arrays.equals(spec.encoded(), spec2.encoded());
 * }</pre>
 *
 * @since 1.0
 */
public class XdhPublicKeySpec implements AlgorithmKeySpec {
    private static final String X509_B64 = "x509.b64";
    private final byte[] x509;

    /**
     * Constructs a new specification from the given X.509-encoded public key.
     *
     * @param key the raw encoded key bytes, must not be {@code null}
     * @throws NullPointerException if {@code key} is {@code null}
     */
    public XdhPublicKeySpec(byte[] key) {
        Objects.requireNonNull(key, "key must not be null");
        this.x509 = Arrays.copyOf(key, key.length);
    }

    /**
     * Returns a defensive copy of the X.509-encoded public key bytes.
     *
     * @return a clone of the internal key encoding
     */
    public byte[] encoded() {
        return x509.clone();
    }

    /**
     * Serializes the given key specification into a {@link PairSeq} with base64
     * encoding.
     *
     * <p>
     * The output contains two entries:
     * <ul>
     * <li>{@code type = "XDH-PUB"}</li>
     * <li>{@code x509.b64 = <base64-encoded key>}</li>
     * </ul>
     *
     * @param spec the specification to marshal
     * @return a pair sequence containing the encoded key
     * @throws NullPointerException if {@code spec} is {@code null}
     */
    public static PairSeq marshal(XdhPublicKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.x509);
        return PairSeq.of("type", "XDH-PUB", X509_B64, b64);
    }

    /**
     * Deserializes a specification from the given {@link PairSeq}.
     *
     * <p>
     * The sequence must contain an entry {@code x509.b64} with a base64-encoded
     * key. Additional entries are ignored.
     * </p>
     *
     * @param p the pair sequence containing serialized fields
     * @return a reconstructed {@code XdhPublicKeySpec}
     * @throws IllegalArgumentException if {@code x509.b64} is missing or cannot be
     *                                  decoded
     */
    public static XdhPublicKeySpec unmarshal(PairSeq p) {
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
            throw new IllegalArgumentException("x509.b64 missing for DH public key");
        }
        return new XdhPublicKeySpec(out);
    }
}
