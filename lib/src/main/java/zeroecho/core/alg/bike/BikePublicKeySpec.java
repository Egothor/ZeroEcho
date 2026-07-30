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
package zeroecho.core.alg.bike;

import java.util.Base64;
import java.util.Objects;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.marshal.PairSeq.Cursor;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>Specification for a BIKE public key</h2>
 *
 * Wraps a BIKE public key encoded in standard X.509 format. Provides
 * marshalling and unmarshalling support for serialization.
 *
 * <h3>Usage</h3> <pre>{@code
 * // Import a BIKE public key
 * BikePublicKeySpec spec = new BikePublicKeySpec(x509Bytes);
 * PublicKey key = bikeAlgorithm.publicKeyImporter(BikePublicKeySpec.class).importPublic(spec);
 *
 * // Marshal for transport or storage
 * PairSeq seq = BikePublicKeySpec.marshal(spec);
 *
 * // Reconstruct from encoded representation
 * BikePublicKeySpec restored = BikePublicKeySpec.unmarshal(seq);
 * }</pre>
 *
 * @since 1.0
 */
public final class BikePublicKeySpec implements AlgorithmKeySpec {

    private static final String X509_B64 = "x509.b64";
    private final byte[] x509;

    /**
     * Constructs a new spec from an X.509 encoded public key.
     *
     * @param x509Der X.509 bytes (DER encoded)
     * @throws NullPointerException if {@code x509Der} is null
     */
    public BikePublicKeySpec(byte[] x509Der) {
        this.x509 = Objects.requireNonNull(x509Der).clone();
    }

    /**
     * Returns a defensive copy of the X.509 encoded key.
     *
     * @return cloned X.509 bytes
     */
    public byte[] x509() {
        return x509.clone();
    }

    /**
     * Serializes the spec to a {@link PairSeq} with base64 encoding.
     *
     * <p>
     * Fields:
     * </p>
     * <ul>
     * <li>{@code type} = "BikePublicKeySpec"</li>
     * <li>{@code x509.b64} = base64 of encoded key (no padding)</li>
     * </ul>
     *
     * @param spec public key specification
     * @return serialized representation
     */
    public static PairSeq marshal(BikePublicKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.x509);
        return PairSeq.of("type", "BikePublicKeySpec", X509_B64, b64);
    }

    /**
     * Deserializes a spec from a {@link PairSeq}.
     *
     * @param p serialized representation containing {@code x509.b64}
     * @return reconstructed public key spec
     * @throws IllegalArgumentException if required field is missing
     */
    public static BikePublicKeySpec unmarshal(PairSeq p) {
        String b64 = null;
        for (Cursor cur = p.cursor(); cur.next();) {
            if (X509_B64.equals(cur.key())) {
                b64 = cur.value();
            }
        }
        if (b64 == null) {
            throw new IllegalArgumentException("BikePublicKeySpec: missing x509.b64");
        }
        return new BikePublicKeySpec(Base64.getDecoder().decode(b64));
    }

    /**
     * Returns a diagnostic string including encoded length.
     *
     * @return human-readable description
     */
    @Override
    public String toString() {
        return "BikePublicKeySpec[len=" + x509.length + "]";
    }
}
