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
package zeroecho.core.alg.bike;

import java.util.Base64;
import java.util.Objects;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.marshal.PairSeq.Cursor;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>Specification for a BIKE private key</h2>
 *
 * Wraps a BIKE private key encoded in standard PKCS#8 format. Provides
 * marshalling and unmarshalling support for interchange.
 *
 * <h3>Usage</h3> <pre>{@code
 * // Import a BIKE private key
 * BikePrivateKeySpec spec = new BikePrivateKeySpec(pkcs8Bytes);
 * PrivateKey key = bikeAlgorithm.importPrivate(spec);
 *
 * // Marshal for storage or transport
 * PairSeq seq = BikePrivateKeySpec.marshal(spec);
 *
 * // Reconstruct from encoded representation
 * BikePrivateKeySpec restored = BikePrivateKeySpec.unmarshal(seq);
 * }</pre>
 *
 * @since 1.0
 */
public final class BikePrivateKeySpec implements AlgorithmKeySpec {

    private static final String PKCS8_B64 = "pkcs8.b64";
    private final byte[] pkcs8;

    /**
     * Constructs a new spec from a PKCS#8 encoded private key.
     *
     * @param pkcs8Der PKCS#8 bytes (DER encoded)
     * @throws NullPointerException if {@code pkcs8Der} is null
     */
    public BikePrivateKeySpec(byte[] pkcs8Der) {
        this.pkcs8 = Objects.requireNonNull(pkcs8Der).clone();
    }

    /**
     * Returns a defensive copy of the PKCS#8 encoded key.
     *
     * @return cloned PKCS#8 bytes
     */
    public byte[] pkcs8() {
        return pkcs8.clone();
    }

    /**
     * Serializes the spec to a {@link PairSeq} with base64 encoding.
     *
     * <p>
     * Fields:
     * </p>
     * <ul>
     * <li>{@code type} = "BikePrivateKeySpec"</li>
     * <li>{@code pkcs8.b64} = base64 of encoded key (no padding)</li>
     * </ul>
     *
     * @param spec private key specification
     * @return serialized key representation
     */
    public static PairSeq marshal(BikePrivateKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.pkcs8);
        return PairSeq.of("type", "BikePrivateKeySpec", PKCS8_B64, b64);
    }

    /**
     * Deserializes a spec from a {@link PairSeq}.
     *
     * @param p serialized representation containing {@code pkcs8.b64}
     * @return reconstructed private key spec
     * @throws IllegalArgumentException if required field is missing
     */
    public static BikePrivateKeySpec unmarshal(PairSeq p) {
        String b64 = null;
        for (Cursor cur = p.cursor(); cur.next();) {
            if (PKCS8_B64.equals(cur.key())) {
                b64 = cur.value();
            }
        }
        if (b64 == null) {
            throw new IllegalArgumentException("BikePrivateKeySpec: missing pkcs8.b64");
        }
        return new BikePrivateKeySpec(Base64.getDecoder().decode(b64));
    }

    /**
     * Returns a diagnostic string including encoded length.
     *
     * @return human-readable description
     */
    @Override
    public String toString() {
        return "BikePrivateKeySpec[len=" + pkcs8.length + "]";
    }
}
