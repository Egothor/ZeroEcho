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
package zeroecho.core.alg.elgamal;

import java.util.Base64;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>ElGamal Public Key Specification</h2>
 *
 * Wrapper for an X.509-encoded ElGamal public key.
 *
 * <p>
 * This specification serves as the input to key-import routines, providing a
 * portable representation of public key material. The encoding format is
 * assumed to be X.509 DER, as produced by standard JCA/JCE providers.
 * </p>
 *
 * <h2>Contents</h2>
 * <ul>
 * <li>{@link #encoded()} returns a defensive copy of the raw X.509 bytes.</li>
 * <li>{@link #marshal(ElgamalPublicKeySpec)} encodes the key into a
 * {@link PairSeq} structure for transport or logging.</li>
 * <li>{@link #unmarshal(PairSeq)} reconstructs the spec from a marshalled
 * representation.</li>
 * </ul>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Import from X.509 DER
 * byte[] der = Files.readAllBytes(Path.of("elgamal-pub.der"));
 * ElgamalPublicKeySpec spec = new ElgamalPublicKeySpec(der);
 * PublicKey pub = algo.publicKeyImporter(ElgamalPublicKeySpec.class).importPublic(spec);
 *
 * // Marshal for serialization
 * PairSeq ps = ElgamalPublicKeySpec.marshal(spec);
 *
 * // Unmarshal back
 * ElgamalPublicKeySpec restored = ElgamalPublicKeySpec.unmarshal(ps);
 * }</pre>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Public keys are not secret, but they must be bound to the correct
 * parameters (modulus and generator) to avoid substitution attacks.</li>
 * <li>Always validate public key encoding against trusted parameter sets before
 * using in protocols.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2> Instances are immutable and safe to share between
 * threads.
 *
 * @since 1.0
 */
public final class ElgamalPublicKeySpec implements AlgorithmKeySpec {

    private static final String X509_B64 = "x509.b64";
    private final byte[] x509;

    /**
     * Constructs a new public key spec from X.509-encoded bytes.
     *
     * @param x509 X.509 DER encoding of the public key; must not be {@code null}
     */
    public ElgamalPublicKeySpec(byte[] x509) {
        this.x509 = x509.clone();
    }

    /**
     * Returns a defensive copy of the X.509-encoded public key.
     *
     * @return X.509 DER encoding
     */
    public byte[] encoded() {
        return x509.clone();
    }

    /**
     * Serializes this spec into a {@link PairSeq}.
     *
     * <p>
     * The output includes:
     * <ul>
     * <li>{@code type} = {@code "ELGAMAL-PUB"}</li>
     * <li>{@code x509.b64} = Base64 encoding of the DER bytes (without
     * padding)</li>
     * </ul>
     *
     * @param spec ElGamal public key spec
     * @return marshalled key as {@link PairSeq}
     */
    public static PairSeq marshal(ElgamalPublicKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.x509);
        return PairSeq.of("type", "ELGAMAL-PUB", X509_B64, b64);
    }

    /**
     * Parses a {@link PairSeq} and reconstructs an {@code ElgamalPublicKeySpec}.
     *
     * @param p encoded pair sequence
     * @return new public key spec
     * @throws IllegalArgumentException if required field {@code x509.b64} is
     *                                  missing
     */
    public static ElgamalPublicKeySpec unmarshal(PairSeq p) {
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
            throw new IllegalArgumentException("x509.b64 missing for ElGamal public key");
        }
        return new ElgamalPublicKeySpec(out);
    }
}
