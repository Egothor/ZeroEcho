/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.core.alg.saber;

import java.util.Base64;
import java.util.Objects;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.marshal.PairSeq.Cursor;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Encoded private key specification for the SABER post-quantum KEM algorithm.
 *
 * <p>
 * A {@code SaberPrivateKeySpec} wraps a SABER private key in standard PKCS#8
 * format. It provides safe accessors for cloning, along with serialization
 * helpers to marshal and unmarshal from a compact {@link PairSeq}
 * representation.
 * </p>
 *
 * <h2>Immutability</h2>
 * <p>
 * The internal PKCS#8 encoding is defensively copied on construction and on
 * retrieval via {@link #pkcs8()}. Instances are therefore immutable and
 * thread-safe.
 * </p>
 *
 * <h2>Usage example</h2> <pre>{@code
 * // Import SABER private key from encoded form
 * byte[] pkcs8Bytes = ...;
 * SaberPrivateKeySpec spec = new SaberPrivateKeySpec(pkcs8Bytes);
 * PrivateKey key = CryptoAlgorithms.privateKey("SABER", spec);
 * }</pre>
 */
public final class SaberPrivateKeySpec implements AlgorithmKeySpec {
    private static final String PKCS8_B64 = "pkcs8.b64";
    private final byte[] pkcs8;

    /**
     * Constructs a private key specification from a PKCS#8-encoded SABER private
     * key.
     *
     * @param pkcs8Der the PKCS#8-encoded private key bytes (DER format)
     * @throws NullPointerException if {@code pkcs8Der} is {@code null}
     */
    public SaberPrivateKeySpec(byte[] pkcs8Der) {
        this.pkcs8 = Objects.requireNonNull(pkcs8Der, "pkcs8Der").clone();
    }

    /**
     * Returns a defensive copy of the PKCS#8-encoded private key.
     *
     * @return cloned byte array containing the PKCS#8 encoding
     */
    public byte[] pkcs8() {
        return pkcs8.clone();
    }

    /**
     * Serializes this specification into a compact {@link PairSeq} form.
     *
     * <p>
     * The encoding includes:
     * <ul>
     * <li>{@code type} = {@code SaberPrivateKeySpec}</li>
     * <li>{@code pkcs8.b64} = Base64 encoding of the PKCS#8 bytes (no padding)</li>
     * </ul>
     *
     * @param spec the private key specification to serialize
     * @return a {@link PairSeq} containing the encoded data
     * @throws NullPointerException if {@code spec} is {@code null}
     */
    public static PairSeq marshal(SaberPrivateKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.pkcs8);
        return PairSeq.of("type", "SaberPrivateKeySpec", PKCS8_B64, b64);
    }

    /**
     * Deserializes a {@link SaberPrivateKeySpec} from its {@link PairSeq} form.
     *
     * <p>
     * The sequence must contain a field {@code pkcs8.b64} with the Base64-encoded
     * PKCS#8 private key bytes. If the field is missing, an exception is thrown.
     * </p>
     *
     * @param p the pair sequence to parse
     * @return a reconstructed {@link SaberPrivateKeySpec}
     * @throws IllegalArgumentException if the {@code pkcs8.b64} field is missing
     */
    public static SaberPrivateKeySpec unmarshal(PairSeq p) {
        String b64 = null;
        for (Cursor cur = p.cursor(); cur.next();) {
            if (PKCS8_B64.equals(cur.key())) {
                b64 = cur.value();
            }
        }
        if (b64 == null) {
            throw new IllegalArgumentException("SaberPrivateKeySpec: missing pkcs8.b64");
        }
        return new SaberPrivateKeySpec(Base64.getDecoder().decode(b64));
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
        return "SaberPrivateKeySpec[len=" + pkcs8.length + "]";
    }
}
