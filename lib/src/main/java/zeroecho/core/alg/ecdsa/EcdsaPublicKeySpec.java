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
package zeroecho.core.alg.ecdsa;

import java.util.Base64;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>ECDSA Public Key Specification</h2>
 *
 * An immutable wrapper around an X.509-encoded ECDSA public key. This
 * specification is used by {@link EcdsaPublicKeyBuilder} to import keys into
 * the JCA {@link java.security.PublicKey} representation.
 *
 * <h2>Encoding</h2>
 * <ul>
 * <li>Keys are stored internally in X.509 SubjectPublicKeyInfo DER format.</li>
 * <li>Instances are defensive: the internal byte array is cloned on
 * construction and on every access.</li>
 * <li>For serialization, {@link #marshal(EcdsaPublicKeySpec)} encodes the X.509
 * bytes in Base64 without padding.</li>
 * </ul>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Construct from X.509 DER
 * byte[] x509 = ...; // load from certificate or key file
 * EcdsaPublicKeySpec spec = new EcdsaPublicKeySpec(x509);
 *
 * // Import into a PublicKey
 * PublicKey pub = new EcdsaPublicKeyBuilder().importPublic(spec);
 *
 * // Marshal/unmarshal for transport or storage
 * PairSeq seq = EcdsaPublicKeySpec.marshal(spec);
 * EcdsaPublicKeySpec restored = EcdsaPublicKeySpec.unmarshal(seq);
 * }</pre>
 *
 * @since 1.0
 */
public final class EcdsaPublicKeySpec implements AlgorithmKeySpec {

    private static final String X509_B64 = "x509.b64";
    private final byte[] x509;

    /**
     * Creates a new public key specification from an X.509 encoded byte array.
     *
     * @param x509 X.509 SubjectPublicKeyInfo DER-encoded public key (must not be
     *             {@code null})
     * @throws IllegalArgumentException if {@code x509} is {@code null}
     */
    public EcdsaPublicKeySpec(byte[] x509) {
        if (x509 == null) {
            throw new IllegalArgumentException("x509 must not be null");
        }
        this.x509 = x509.clone();
    }

    /**
     * Returns a defensive copy of the encoded X.509 data.
     *
     * @return cloned X.509 byte array
     */
    public byte[] encoded() {
        return x509.clone();
    }

    /**
     * Serializes this specification into a {@link PairSeq}.
     *
     * <p>
     * The X.509 data is Base64-encoded (without padding) and emitted with the key
     * {@code "x509.b64"}.
     * </p>
     *
     * @param spec public key spec to marshal
     * @return serialized representation in key-value form
     */
    public static PairSeq marshal(EcdsaPublicKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.x509);
        return PairSeq.of("type", "ECDSA-PUB", X509_B64, b64);
    }

    /**
     * Reconstructs a public key specification from a {@link PairSeq}.
     *
     * <p>
     * The sequence must contain a {@code "x509.b64"} field with Base64-encoded
     * X.509 DER data. If missing, an {@link IllegalArgumentException} is thrown.
     * </p>
     *
     * @param p serialized key-value sequence
     * @return reconstructed {@code EcdsaPublicKeySpec}
     * @throws IllegalArgumentException if {@code x509.b64} is absent
     */
    public static EcdsaPublicKeySpec unmarshal(PairSeq p) {
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
            throw new IllegalArgumentException("x509.b64 missing for ECDSA public key");
        }
        return new EcdsaPublicKeySpec(out);
    }
}
