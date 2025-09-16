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
 * <h2>ECDSA Private Key Specification</h2>
 *
 * An immutable wrapper around a PKCS#8-encoded ECDSA private key. This
 * specification is used by {@link EcdsaPrivateKeyBuilder} to import keys into
 * the JCA {@link java.security.PrivateKey} representation.
 *
 * <h2>Encoding</h2>
 * <ul>
 * <li>Keys are stored internally in PKCS#8 DER format.</li>
 * <li>Instances are defensive: the internal byte array is cloned on
 * construction and on every access.</li>
 * <li>For serialization, {@link #marshal(EcdsaPrivateKeySpec)} encodes the
 * PKCS#8 bytes in Base64 without padding.</li>
 * </ul>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Construct from PKCS#8 DER
 * byte[] pkcs8 = ...; // load from file or keystore
 * EcdsaPrivateKeySpec spec = new EcdsaPrivateKeySpec(pkcs8);
 *
 * // Import into a PrivateKey
 * PrivateKey priv = new EcdsaPrivateKeyBuilder().importPrivate(spec);
 *
 * // Marshal/unmarshal for transport or storage
 * PairSeq seq = EcdsaPrivateKeySpec.marshal(spec);
 * EcdsaPrivateKeySpec restored = EcdsaPrivateKeySpec.unmarshal(seq);
 * }</pre>
 *
 * @since 1.0
 */
public final class EcdsaPrivateKeySpec implements AlgorithmKeySpec {

    private static final String PKCS8_B64 = "pkcs8.b64";
    private final byte[] pkcs8;

    /**
     * Creates a new private key specification from a PKCS#8 encoded byte array.
     *
     * @param pkcs8 PKCS#8 DER-encoded private key (must not be {@code null})
     * @throws IllegalArgumentException if {@code pkcs8} is {@code null}
     */
    public EcdsaPrivateKeySpec(byte[] pkcs8) {
        if (pkcs8 == null) {
            throw new IllegalArgumentException("pkcs8 must not be null");
        }
        this.pkcs8 = pkcs8.clone();
    }

    /**
     * Returns a defensive copy of the encoded PKCS#8 data.
     *
     * @return cloned PKCS#8 byte array
     */
    public byte[] encoded() {
        return pkcs8.clone();
    }

    /**
     * Serializes this specification into a {@link PairSeq}.
     *
     * <p>
     * The PKCS#8 data is Base64-encoded (without padding) and emitted with the key
     * {@code "pkcs8.b64"}.
     * </p>
     *
     * @param spec private key spec to marshal
     * @return serialized representation in key-value form
     */
    public static PairSeq marshal(EcdsaPrivateKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.pkcs8);
        return PairSeq.of("type", "ECDSA-PRIV", PKCS8_B64, b64);
    }

    /**
     * Reconstructs a private key specification from a {@link PairSeq}.
     *
     * <p>
     * The sequence must contain a {@code "pkcs8.b64"} field with Base64-encoded
     * PKCS#8 DER data. If missing, an {@link IllegalArgumentException} is thrown.
     * </p>
     *
     * @param p serialized key-value sequence
     * @return reconstructed {@code EcdsaPrivateKeySpec}
     * @throws IllegalArgumentException if {@code pkcs8.b64} is absent
     */
    public static EcdsaPrivateKeySpec unmarshal(PairSeq p) {
        byte[] out = null;
        PairSeq.Cursor cur = p.cursor();
        while (cur.next()) {
            String k = cur.key();
            String v = cur.value();
            if (PKCS8_B64.equals(k)) {
                out = Base64.getDecoder().decode(v);
            }
        }
        if (out == null) {
            throw new IllegalArgumentException("pkcs8.b64 missing for ECDSA private key");
        }
        return new EcdsaPrivateKeySpec(out);
    }
}
