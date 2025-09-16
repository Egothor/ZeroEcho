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
package zeroecho.core.alg.rsa;

import java.util.Base64;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Encoded RSA private key specification in PKCS#8 format.
 *
 * <p>
 * This spec wraps the DER-encoded PKCS#8 representation of an RSA private key
 * and is used for importing keys into {@link java.security.KeyFactory} or
 * algorithm builders (see {@code RsaAlgorithm}). It provides safe cloning of
 * the encoded form and supports simple marshal/unmarshal via {@link PairSeq}.
 * </p>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Import a PKCS#8 encoded key
 * byte[] pkcs8 = Files.readAllBytes(Path.of("rsa_private.der"));
 * RsaPrivateKeySpec spec = new RsaPrivateKeySpec(pkcs8);
 *
 * // Retrieve encoded form
 * byte[] encoded = spec.encoded();
 *
 * // Marshal for storage or transmission
 * PairSeq seq = RsaPrivateKeySpec.marshal(spec);
 *
 * // Rebuild from serialized representation
 * RsaPrivateKeySpec parsed = RsaPrivateKeySpec.unmarshal(seq);
 * }</pre>
 *
 * <p>
 * Instances are immutable and defensively copy their input. The encoded key
 * material remains sensitive and should be handled with care.
 * </p>
 *
 * @since 1.0
 */
public final class RsaPrivateKeySpec implements AlgorithmKeySpec {
    private static final String PKCS8_B64 = "pkcs8.b64";
    private final byte[] pkcs8;

    /**
     * Constructs a new RSA private key spec from a PKCS#8-encoded key.
     *
     * @param pkcs8 DER-encoded PKCS#8 private key; cloned internally
     * @throws NullPointerException if {@code pkcs8} is {@code null}
     */
    public RsaPrivateKeySpec(byte[] pkcs8) {
        this.pkcs8 = pkcs8.clone();
    }

    /**
     * Returns a clone of the PKCS#8-encoded private key.
     *
     * @return defensive copy of the encoded key
     */
    public byte[] encoded() {
        return pkcs8.clone();
    }

    /**
     * Marshals this spec to a {@link PairSeq}.
     *
     * <p>
     * The output sequence contains:
     * <ul>
     * <li>{@code type = "RSA-PRIV"}</li>
     * <li>{@code pkcs8.b64 = <Base64 encoding of PKCS#8 bytes>}</li>
     * </ul>
     *
     * @param spec RSA private key spec
     * @return pair sequence with type and base64-encoded key material
     */
    public static PairSeq marshal(RsaPrivateKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.pkcs8);
        return PairSeq.of("type", "RSA-PRIV", PKCS8_B64, b64);
    }

    /**
     * Reconstructs an RSA private key spec from a marshaled {@link PairSeq}.
     *
     * <p>
     * Expects an entry {@code pkcs8.b64} containing the Base64-encoded PKCS#8
     * private key. The {@code type} field is ignored for forward compatibility.
     * </p>
     *
     * @param p serialized pair sequence
     * @return RSA private key spec with decoded key material
     * @throws IllegalArgumentException if the sequence does not contain a
     *                                  {@code pkcs8.b64} entry
     */
    public static RsaPrivateKeySpec unmarshal(PairSeq p) {
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
            throw new IllegalArgumentException("pkcs8.b64 missing for RSA private key");
        }
        return new RsaPrivateKeySpec(out);
    }
}
