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
package zeroecho.core.alg.dh;

import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Key specification for a Diffie-Hellman public key encoded in X.509 format.
 *
 * <p>
 * This spec carries the raw encoded public key bytes in the standard X.509
 * SubjectPublicKeyInfo form. It is intended for use with algorithms in the
 * {@link zeroecho.core.AlgorithmFamily#AGREEMENT} family, allowing safe
 * import/export of DH public keys across contexts.
 * </p>
 *
 * <h2>Design</h2>
 * <ul>
 * <li>Immutable: the internal byte array is defensively copied at construction
 * and when returned by {@link #encoded()}.</li>
 * <li>Encodable: supports marshaling to/from a
 * {@link zeroecho.core.marshal.PairSeq} so keys can be serialized in
 * human-readable or protocol-friendly formats.</li>
 * <li>Type-safe: used as a binding for asymmetric key builders within
 * {@code CryptoAlgorithm} definitions.</li>
 * </ul>
 *
 * <h2>Example</h2> <pre>{@code
 * // Import a DH public key from encoded bytes
 * DhPublicKeySpec spec = new DhPublicKeySpec(x509Bytes);
 * PublicKey pub = session.keyBuilders().asymmetric().importPublic("DH", spec);
 *
 * // Marshal to a text-friendly representation
 * PairSeq ps = DhPublicKeySpec.marshal(spec);
 *
 * // Unmarshal back to spec
 * DhPublicKeySpec parsed = DhPublicKeySpec.unmarshal(ps);
 * }</pre>
 *
 * @since 1.0
 */
public class DhPublicKeySpec implements AlgorithmKeySpec {

    private static final String X509_B64 = "x509.b64";
    private final byte[] x509;

    /**
     * Creates a new specification from an X.509 encoded DH public key.
     *
     * @param key the encoded public key bytes; must not be {@code null}
     * @throws NullPointerException if {@code key} is {@code null}
     */
    public DhPublicKeySpec(byte[] key) {
        Objects.requireNonNull(key, "key must not be null");
        this.x509 = Arrays.copyOf(key, key.length);
    }

    /**
     * Returns a clone of the encoded X.509 bytes.
     *
     * @return a defensive copy of the X.509 encoded DH public key
     */
    public byte[] encoded() {
        return x509.clone();
    }

    /**
     * Marshals the given DH public key spec into a {@link PairSeq}.
     *
     * <p>
     * The sequence contains a {@code type} field with value {@code "DH-PUB"} and an
     * {@code x509.b64} field with the Base64 encoding of the key.
     * </p>
     *
     * @param spec the spec to encode
     * @return a {@code PairSeq} representation of the spec
     * @throws NullPointerException if {@code spec} is {@code null}
     */
    public static PairSeq marshal(DhPublicKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.x509);
        return PairSeq.of("type", "DH-PUB", X509_B64, b64);
    }

    /**
     * Reconstructs a {@code DhPublicKeySpec} from a {@link PairSeq}.
     *
     * <p>
     * The sequence must contain an {@code x509.b64} field with the Base64-encoded
     * public key. If this field is missing, an {@link IllegalArgumentException} is
     * thrown.
     * </p>
     *
     * @param p the sequence to decode
     * @return a new spec containing the decoded X.509 bytes
     * @throws IllegalArgumentException if required fields are missing or malformed
     */
    public static DhPublicKeySpec unmarshal(PairSeq p) {
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
        return new DhPublicKeySpec(out);
    }
}
