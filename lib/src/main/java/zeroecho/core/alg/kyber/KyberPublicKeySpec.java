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
package zeroecho.core.alg.kyber;

import java.util.Base64;
import java.util.Objects;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Specification wrapper for a Kyber (ML-KEM) public key encoded in X.509.
 *
 * <p>
 * Instances of this class carry an immutable copy of the X.509
 * SubjectPublicKeyInfo-encoded bytes. They are used with
 * {@link zeroecho.core.CryptoAlgorithm} key builders to import keys into the
 * provider’s native representation.
 * </p>
 *
 * <h2>Encoding</h2>
 * <ul>
 * <li>Format: X.509 DER encoding of a Kyber public key
 * (SubjectPublicKeyInfo).</li>
 * <li>Stored as a defensive clone to ensure immutability.</li>
 * <li>Marshalling/unmarshalling supported via {@link PairSeq} with Base64
 * encoding.</li>
 * </ul>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Import a public key into a CryptoAlgorithm
 * byte[] x509Bytes = ...; // obtained from storage
 * KyberPublicKeySpec spec = new KyberPublicKeySpec(x509Bytes);
 * PublicKey k = kyberAlg.publicKeyImporter(KyberPublicKeySpec.class).importPublic(spec);
 *
 * // Serialize for persistence
 * PairSeq seq = KyberPublicKeySpec.marshal(spec);
 *
 * // Deserialize back
 * KyberPublicKeySpec restored = KyberPublicKeySpec.unmarshal(seq);
 * }</pre>
 *
 * <p>
 * This class is immutable and thread-safe.
 * </p>
 *
 * @see KyberPrivateKeySpec
 * @see KyberKeyGenSpec
 */
public final class KyberPublicKeySpec implements AlgorithmKeySpec {

    private static final String X509_B64 = "x509.b64";
    private final byte[] x509;

    /**
     * Creates a new spec from X.509-encoded public key bytes.
     *
     * @param x509Der X.509 SubjectPublicKeyInfo DER-encoded public key, not null
     * @throws NullPointerException if {@code x509Der} is null
     */
    public KyberPublicKeySpec(byte[] x509Der) {
        this.x509 = Objects.requireNonNull(x509Der, "x509Der").clone();
    }

    /**
     * Returns a defensive copy of the X.509-encoded public key.
     *
     * @return cloned byte array of X.509 DER encoding
     */
    public byte[] x509() {
        return x509.clone();
    }

    /**
     * Serializes this spec into a {@link PairSeq} using Base64 encoding.
     *
     * <p>
     * The sequence contains:
     * <ul>
     * <li>{@code type} = {@code KyberPublicKey}</li>
     * <li>{@code x509.b64} = Base64 of X.509 bytes (no padding)</li>
     * </ul>
     *
     * @param spec the spec to marshal
     * @return key-value representation suitable for persistence
     */
    public static PairSeq marshal(KyberPublicKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.x509);
        return PairSeq.of("type", "KyberPublicKey", X509_B64, b64);
    }

    /**
     * Reconstructs a {@code KyberPublicKeySpec} from a {@link PairSeq}.
     *
     * @param p key-value sequence containing an {@code x509.b64} entry
     * @return a new spec with decoded X.509 bytes
     * @throws IllegalArgumentException if the required field is missing
     */
    public static KyberPublicKeySpec unmarshal(PairSeq p) {
        String x509b64 = null;

        PairSeq.Cursor cur = p.cursor();
        while (cur.next()) {
            String k = cur.key();
            String v = cur.value();
            if (X509_B64.equals(k)) {
                x509b64 = v;
            }
        }
        if (x509b64 == null) {
            throw new IllegalArgumentException("KyberPublicKeySpec: missing 'x509.b64'");
        }
        return new KyberPublicKeySpec(Base64.getDecoder().decode(x509b64));
    }

    /**
     * Returns a diagnostic string for logging and debugging.
     *
     * <p>
     * Does not expose key material; only length is shown.
     * </p>
     *
     * @return string with length of encoded key
     */
    @Override
    public String toString() {
        return "KyberPublicKeySpec[len=" + x509.length + "]";
    }
}
