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
 * Encoded RSA public key specification in X.509 SubjectPublicKeyInfo format.
 *
 * <p>
 * This spec wraps the DER-encoded X.509 representation of an RSA public key and
 * is used for importing keys into {@link java.security.KeyFactory} or algorithm
 * builders (see {@code RsaAlgorithm}). It provides safe cloning of the encoded
 * form and supports simple marshal/unmarshal via {@link PairSeq}.
 * </p>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Import an X.509 encoded public key
 * byte[] x509 = Files.readAllBytes(Path.of("rsa_public.der"));
 * RsaPublicKeySpec spec = new RsaPublicKeySpec(x509);
 *
 * // Retrieve encoded form
 * byte[] encoded = spec.encoded();
 *
 * // Marshal for storage or transmission
 * PairSeq seq = RsaPublicKeySpec.marshal(spec);
 *
 * // Rebuild from serialized representation
 * RsaPublicKeySpec parsed = RsaPublicKeySpec.unmarshal(seq);
 * }</pre>
 *
 * <p>
 * Instances are immutable and defensively copy their input. Although public
 * keys are not secret, encoded values should still be treated as security
 * relevant data and preserved accurately.
 * </p>
 *
 * @since 1.0
 */
public final class RsaPublicKeySpec implements AlgorithmKeySpec {
    private static final String X509_B64 = "x509.b64";
    private final byte[] x509;

    /**
     * Constructs an RSA public key spec from an X.509-encoded key.
     *
     * @param x509 DER-encoded X.509 public key; cloned internally
     * @throws NullPointerException if {@code x509} is {@code null}
     */
    public RsaPublicKeySpec(byte[] x509) {
        this.x509 = x509.clone();
    }

    /**
     * Returns a clone of the X.509-encoded public key.
     *
     * @return defensive copy of the encoded key
     */
    public byte[] encoded() {
        return x509.clone();
    }

    /**
     * Marshals this spec to a {@link PairSeq}.
     *
     * <p>
     * The output sequence contains:
     * <ul>
     * <li>{@code type = "RSA-PUB"}</li>
     * <li>{@code x509.b64 = <Base64 encoding of X.509 bytes>}</li>
     * </ul>
     *
     * @param spec RSA public key spec
     * @return pair sequence with type and base64-encoded key material
     */
    public static PairSeq marshal(RsaPublicKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.x509);
        return PairSeq.of("type", "RSA-PUB", X509_B64, b64);
    }

    /**
     * Reconstructs an RSA public key spec from a marshaled {@link PairSeq}.
     *
     * <p>
     * Expects an entry {@code x509.b64} containing the Base64-encoded X.509 public
     * key. The {@code type} field is ignored for forward compatibility.
     * </p>
     *
     * @param p serialized pair sequence
     * @return RSA public key spec with decoded key material
     * @throws IllegalArgumentException if the sequence does not contain a
     *                                  {@code x509.b64} entry
     */
    public static RsaPublicKeySpec unmarshal(PairSeq p) {
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
            throw new IllegalArgumentException("x509.b64 missing for RSA public key");
        }
        return new RsaPublicKeySpec(out);
    }
}
