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
package zeroecho.core.alg.saber;

import java.util.Base64;
import java.util.Objects;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.marshal.PairSeq.Cursor;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Encoded public key specification for the SABER post-quantum KEM algorithm.
 *
 * <p>
 * A {@code SaberPublicKeySpec} wraps a SABER public key in standard X.509
 * SubjectPublicKeyInfo format. It provides safe accessors for cloning, along
 * with serialization helpers to marshal and unmarshal from a compact
 * {@link PairSeq} representation.
 * </p>
 *
 * <h2>Immutability</h2>
 * <p>
 * The internal X.509 encoding is defensively copied on construction and when
 * returned by {@link #x509()}. Instances are therefore immutable and safe to
 * share across threads.
 * </p>
 *
 * <h2>Usage example</h2> <pre>{@code
 * // Import SABER public key from encoded form
 * byte[] x509Bytes = ...;
 * SaberPublicKeySpec spec = new SaberPublicKeySpec(x509Bytes);
 * PublicKey key = CryptoAlgorithms.publicKey("SABER", spec);
 * }</pre>
 */
public final class SaberPublicKeySpec implements AlgorithmKeySpec {
    private static final String X509_B64 = "x509.b64";
    private final byte[] x509;

    /**
     * Constructs a public key specification from an X.509-encoded SABER public key.
     *
     * @param x509Der the X.509 SubjectPublicKeyInfo bytes
     * @throws NullPointerException if {@code x509Der} is {@code null}
     */
    public SaberPublicKeySpec(byte[] x509Der) {
        this.x509 = Objects.requireNonNull(x509Der, "x509Der").clone();
    }

    /**
     * Returns a defensive copy of the X.509-encoded public key.
     *
     * @return cloned byte array containing the X.509 encoding
     */
    public byte[] x509() {
        return x509.clone();
    }

    /**
     * Serializes this specification into a compact {@link PairSeq} form.
     *
     * <p>
     * The encoding includes:
     * <ul>
     * <li>{@code type} = {@code SaberPublicKeySpec}</li>
     * <li>{@code x509.b64} = Base64 encoding of the X.509 bytes (no padding)</li>
     * </ul>
     *
     * @param spec the public key specification to serialize
     * @return a {@link PairSeq} containing the encoded data
     * @throws NullPointerException if {@code spec} is {@code null}
     */
    public static PairSeq marshal(SaberPublicKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.x509);
        return PairSeq.of("type", "SaberPublicKeySpec", X509_B64, b64);
    }

    /**
     * Deserializes a {@link SaberPublicKeySpec} from its {@link PairSeq} form.
     *
     * <p>
     * The sequence must contain a field {@code x509.b64} with the Base64-encoded
     * X.509 public key bytes. If the field is missing, an exception is thrown.
     * </p>
     *
     * @param p the pair sequence to parse
     * @return a reconstructed {@link SaberPublicKeySpec}
     * @throws IllegalArgumentException if the {@code x509.b64} field is missing
     */
    public static SaberPublicKeySpec unmarshal(PairSeq p) {
        String b64 = null;
        for (Cursor cur = p.cursor(); cur.next();) {
            if (X509_B64.equals(cur.key())) {
                b64 = cur.value();
            }
        }
        if (b64 == null) {
            throw new IllegalArgumentException("SaberPublicKeySpec: missing x509.b64");
        }
        return new SaberPublicKeySpec(Base64.getDecoder().decode(b64));
    }

    /**
     * Returns a diagnostic string showing the length of the encoded key.
     *
     * <p>
     * This string does not expose the key material itself and is safe for logs.
     * </p>
     *
     * @return string representation of this spec, including encoded length
     */
    @Override
    public String toString() {
        return "SaberPublicKeySpec[len=" + x509.length + "]";
    }
}
