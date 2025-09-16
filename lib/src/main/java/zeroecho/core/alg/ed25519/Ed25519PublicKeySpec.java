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
package zeroecho.core.alg.ed25519;

import java.util.Base64;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>Specification for Ed25519 public keys</h2>
 *
 * {@link zeroecho.core.spec.AlgorithmKeySpec} representing an Ed25519 public
 * key in its encoded X.509 form.
 *
 * <p>
 * This spec is used by {@link Ed25519PublicKeyBuilder} and related APIs to
 * import and wrap Ed25519 public keys. The encoding is expected to conform to
 * the X.509 SubjectPublicKeyInfo structure as produced by standard JCA key
 * factories or external tooling.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Encapsulates the X.509-encoded public key bytes.</li>
 * <li>Provides safe cloning to avoid exposing mutable internal state.</li>
 * <li>Supports serialization to and from a compact base64-based {@link PairSeq}
 * representation via {@link #marshal(Ed25519PublicKeySpec)} and
 * {@link #unmarshal(PairSeq)}.</li>
 * </ul>
 *
 * <h2>Usage example</h2> <pre>{@code
 * // Wrap X.509 bytes in a spec
 * Ed25519PublicKeySpec spec = new Ed25519PublicKeySpec(x509Bytes);
 *
 * // Import into a PublicKey using ZeroEcho
 * PublicKey pub = CryptoAlgorithms.publicKey("Ed25519", spec);
 *
 * // Serialize to PairSeq (e.g., for configuration or transport)
 * PairSeq seq = Ed25519PublicKeySpec.marshal(spec);
 *
 * // Reconstruct from serialized form
 * Ed25519PublicKeySpec restored = Ed25519PublicKeySpec.unmarshal(seq);
 * }</pre>
 *
 * <h2>Thread-safety</h2> Instances are immutable. The internal key bytes are
 * defensively copied on construction and retrieval, making this class safe to
 * share across threads.
 *
 * @since 1.0
 */
public final class Ed25519PublicKeySpec implements AlgorithmKeySpec {

    private static final String X509_B64 = "x509.b64";
    private final byte[] encodedX509;

    /**
     * Creates a new Ed25519 public key specification from its X.509 encoding.
     *
     * @param encodedX509 X.509-encoded public key bytes; must not be null
     * @throws IllegalArgumentException if {@code encodedX509} is null
     */
    public Ed25519PublicKeySpec(byte[] encodedX509) {
        if (encodedX509 == null) {
            throw new IllegalArgumentException("encodedX509 must not be null");
        }
        this.encodedX509 = encodedX509.clone();
    }

    /**
     * Returns a defensive copy of the X.509-encoded public key bytes.
     *
     * @return clone of the X.509 encoding
     */
    public byte[] encoded() {
        return encodedX509.clone();
    }

    /**
     * Serializes the given public key spec to a base64-encoded {@link PairSeq}.
     *
     * <p>
     * The output includes a type marker ({@code "Ed25519-PUB"}) and the field
     * {@code "x509.b64"} containing the base64 representation of the key.
     * </p>
     *
     * @param spec public key spec to marshal
     * @return serialized representation as a {@link PairSeq}
     */
    public static PairSeq marshal(Ed25519PublicKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.encodedX509);
        return PairSeq.of("type", "Ed25519-PUB", X509_B64, b64);
    }

    /**
     * Reconstructs a public key spec from a base64-encoded {@link PairSeq}.
     *
     * <p>
     * The sequence must contain the field {@code "x509.b64"} with the base64
     * encoding of the X.509 key.
     * </p>
     *
     * @param p serialized key data
     * @return a new {@code Ed25519PublicKeySpec} instance
     * @throws IllegalArgumentException if the sequence does not contain
     *                                  {@code "x509.b64"}
     */
    public static Ed25519PublicKeySpec unmarshal(PairSeq p) {
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
            throw new IllegalArgumentException("x509.b64 missing for Ed25519 public key");
        }
        return new Ed25519PublicKeySpec(out);
    }
}
