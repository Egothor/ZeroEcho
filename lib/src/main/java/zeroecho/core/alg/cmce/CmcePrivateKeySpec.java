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
package zeroecho.core.alg.cmce;

import java.util.Base64;
import java.util.Objects;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.marshal.PairSeq.Cursor;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>Classic McEliece (CMCE) private key specification</h2>
 *
 * <p>
 * Wraps a CMCE private key in PKCS#8 (DER) encoding. This spec is used to
 * import or serialize private keys into the ZeroEcho SPI.
 * </p>
 *
 * <p>
 * Instances are immutable. The internal byte array is cloned on construction
 * and on every accessor to prevent accidental mutation.
 * </p>
 *
 * <h2>Marshalling</h2>
 * <ul>
 * <li>{@link #marshal(CmcePrivateKeySpec)} produces a {@link PairSeq} with
 * Base64-encoded PKCS#8.</li>
 * <li>{@link #unmarshal(PairSeq)} reconstructs a spec from that format.</li>
 * </ul>
 *
 * <p>
 * Example:
 * </p>
 * <pre>{@code
 * // Wrap an existing PKCS#8 byte array
 * CmcePrivateKeySpec spec = new CmcePrivateKeySpec(pkcs8Bytes);
 *
 * // Serialize to PairSeq for storage or transport
 * PairSeq encoded = CmcePrivateKeySpec.marshal(spec);
 *
 * // Reconstruct later
 * CmcePrivateKeySpec restored = CmcePrivateKeySpec.unmarshal(encoded);
 * }</pre>
 *
 * @since 1.0
 */
public final class CmcePrivateKeySpec implements AlgorithmKeySpec {

    private static final String PKCS8_B64 = "pkcs8.b64";
    private final byte[] pkcs8;

    /**
     * Creates a new specification from a PKCS#8-encoded CMCE private key.
     *
     * <p>
     * The input is defensively copied.
     * </p>
     *
     * @param pkcs8Der DER-encoded PKCS#8 private key
     * @throws NullPointerException if {@code pkcs8Der} is null
     */
    public CmcePrivateKeySpec(byte[] pkcs8Der) {
        this.pkcs8 = Objects.requireNonNull(pkcs8Der).clone();
    }

    /**
     * Returns a defensive copy of the PKCS#8 bytes.
     *
     * @return a fresh copy of the underlying PKCS#8 encoding
     */
    public byte[] pkcs8() {
        return pkcs8.clone();
    }

    /**
     * Serializes the given private key spec into a {@link PairSeq}.
     *
     * <p>
     * The PKCS#8 bytes are Base64-encoded (without padding) and stored under the
     * key {@code "pkcs8.b64"}. The type tag {@code "CmcePrivateKeySpec"} is also
     * included.
     * </p>
     *
     * @param spec the spec to serialize
     * @return a PairSeq containing type and Base64-encoded key
     * @throws NullPointerException if {@code spec} is null
     */
    public static PairSeq marshal(CmcePrivateKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.pkcs8);
        return PairSeq.of("type", "CmcePrivateKeySpec", PKCS8_B64, b64);
    }

    /**
     * Deserializes a {@link CmcePrivateKeySpec} from a {@link PairSeq}.
     *
     * <p>
     * The method scans for a key named {@code "pkcs8.b64"}, decodes its value from
     * Base64, and reconstructs the spec.
     * </p>
     *
     * @param p PairSeq containing serialized fields
     * @return reconstructed {@code CmcePrivateKeySpec}
     * @throws IllegalArgumentException if no {@code "pkcs8.b64"} field is found
     */
    public static CmcePrivateKeySpec unmarshal(PairSeq p) {
        String b64 = null;
        for (Cursor cur = p.cursor(); cur.next();) {
            if (PKCS8_B64.equals(cur.key())) {
                b64 = cur.value();
            }
        }
        if (b64 == null) {
            throw new IllegalArgumentException("CmcePrivateKeySpec: missing pkcs8.b64");
        }
        return new CmcePrivateKeySpec(Base64.getDecoder().decode(b64));
    }

    /**
     * Returns a diagnostic string with the length of the encoded key.
     *
     * <p>
     * The output is safe to log; it does not include key material.
     * </p>
     *
     * @return a string in the form {@code CmcePrivateKeySpec[len=N]}
     */
    @Override
    public String toString() {
        return "CmcePrivateKeySpec[len=" + pkcs8.length + "]";
    }
}
