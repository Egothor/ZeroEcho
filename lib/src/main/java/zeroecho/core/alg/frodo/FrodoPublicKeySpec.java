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
package zeroecho.core.alg.frodo;

import java.util.Base64;
import java.util.Objects;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.marshal.PairSeq.Cursor;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>Specification for importing a Frodo public key</h2>
 *
 * {@code FrodoPublicKeySpec} is a wrapper around an X.509-encoded FrodoKEM
 * public key. It provides immutable access to the raw encoding and utility
 * methods for serialization.
 *
 * <h2>Encoding format</h2>
 * <ul>
 * <li>Keys are stored in the standard X.509 SubjectPublicKeyInfo format as
 * produced by providers such as BouncyCastle PQC.</li>
 * <li>The encoding is preserved exactly as provided; no parsing or validation
 * is performed by this class.</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <ul>
 * <li>Instances of this spec can be passed to
 * {@link zeroecho.sdk.KeyBuilders.Asymmetric#importPublic(String, AlgorithmKeySpec)}
 * to construct a usable {@link java.security.PublicKey}.</li>
 * <li>The {@link #marshal(FrodoPublicKeySpec)} and {@link #unmarshal(PairSeq)}
 * methods allow safe serialization into and recovery from structured textual
 * form.</li>
 * </ul>
 *
 * <pre>{@code
 * // Import an existing Frodo public key
 * byte[] encoded = Files.readAllBytes(Paths.get("frodo.pub"));
 * FrodoPublicKeySpec spec = new FrodoPublicKeySpec(encoded);
 * PublicKey pub = session.keyBuilders().asymmetric().importPublic("FrodoKEM", spec);
 * }</pre>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This class is immutable; the internal byte array is cloned on construction
 * and when accessed via {@link #x509()}.
 * </p>
 *
 * @since 1.0
 */
public final class FrodoPublicKeySpec implements AlgorithmKeySpec {

    private static final String X509_B64 = "x509.b64";
    private final byte[] x509;

    /**
     * Creates a new specification from an X.509 DER-encoded public key.
     *
     * @param x509Der the encoded public key bytes (will be cloned)
     * @throws NullPointerException if {@code x509Der} is {@code null}
     */
    public FrodoPublicKeySpec(byte[] x509Der) {
        this.x509 = Objects.requireNonNull(x509Der).clone();
    }

    /**
     * Returns a clone of the underlying X.509 encoding.
     *
     * @return defensive copy of the X.509-encoded public key
     */
    public byte[] x509() {
        return x509.clone();
    }

    /**
     * Serializes this spec into a {@link PairSeq}, encoding the key in Base64
     * without padding.
     *
     * @param spec Frodo public key specification to serialize
     * @return a {@code PairSeq} with type and Base64-encoded key
     */
    public static PairSeq marshal(FrodoPublicKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.x509);
        return PairSeq.of("type", "FrodoPublicKeySpec", X509_B64, b64);
    }

    /**
     * Parses a {@link PairSeq} previously produced by
     * {@link #marshal(FrodoPublicKeySpec)}.
     *
     * @param p input sequence containing a {@code x509.b64} entry
     * @return a new public key spec initialized with the decoded bytes
     * @throws IllegalArgumentException if {@code x509.b64} entry is missing
     */
    public static FrodoPublicKeySpec unmarshal(PairSeq p) {
        String b64 = null;
        for (Cursor cur = p.cursor(); cur.next();) {
            if (X509_B64.equals(cur.key())) {
                b64 = cur.value();
            }
        }
        if (b64 == null) {
            throw new IllegalArgumentException("FrodoPublicKeySpec: missing x509.b64");
        }
        return new FrodoPublicKeySpec(Base64.getDecoder().decode(b64));
    }

    /**
     * Returns a diagnostic string containing the encoded length.
     *
     * @return string in the form {@code FrodoPublicKeySpec[len=N]}
     */
    @Override
    public String toString() {
        return "FrodoPublicKeySpec[len=" + x509.length + "]";
    }
}
