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
package zeroecho.core.alg.sphincsplus;

import java.util.Base64;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Encoded representation of a SPHINCS+ public key.
 *
 * <p>
 * {@code SphincsPlusPublicKeySpec} wraps an X.509-encoded SPHINCS+ public key
 * along with the provider name that should be used for import. It is a simple
 * immutable holder designed for use with {@link SphincsPlusPublicKeyBuilder}.
 * </p>
 *
 * <h2>Encoding</h2>
 * <ul>
 * <li>The key is stored as a defensive copy of the provided X.509 byte
 * array.</li>
 * <li>Marshalling and unmarshalling methods convert between this object and a
 * {@link PairSeq} representation using Base64 encoding.</li>
 * <li>The {@code providerName} defaults to {@code "BC"} (Bouncy Castle
 * provider) if not explicitly supplied.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2> Instances are immutable and can be shared safely
 * across threads. Defensive copies are returned for all sensitive material.
 *
 * <h2>Example</h2> <pre>{@code
 * // Wrap an X.509-encoded public key
 * byte[] x509 = ...;
 * SphincsPlusPublicKeySpec spec = new SphincsPlusPublicKeySpec(x509);
 *
 * // Import the key via the builder
 * PublicKey pub = new SphincsPlusPublicKeyBuilder().importPublic(spec);
 *
 * // Serialize to PairSeq for transport or persistence
 * PairSeq seq = SphincsPlusPublicKeySpec.marshal(spec);
 *
 * // Reconstruct from PairSeq
 * SphincsPlusPublicKeySpec restored = SphincsPlusPublicKeySpec.unmarshal(seq);
 * }</pre>
 *
 * @since 1.0
 */
public final class SphincsPlusPublicKeySpec implements AlgorithmKeySpec {
    private static final String LEGACY_PROVIDER = "BCPQC";
    private final byte[] encodedX509;
    private final String providerName; // e.g. "BC"

    /**
     * Constructs a new specification with the default provider {@code "BC"}.
     *
     * @param encodedX509 X.509-encoded SPHINCS+ public key bytes
     * @throws IllegalArgumentException if {@code encodedX509} is {@code null}
     */
    public SphincsPlusPublicKeySpec(byte[] encodedX509) {
        this(encodedX509, "BC");
    }

    /**
     * Constructs a new specification with the given provider.
     *
     * @param encodedX509  X.509-encoded SPHINCS+ public key bytes
     * @param providerName JCA provider to use for import; if {@code null}, defaults
     *                     to {@code "BC"}
     * @throws IllegalArgumentException if {@code encodedX509} is {@code null}
     *                                  or the provider is legacy {@code "BCPQC"}
     */
    public SphincsPlusPublicKeySpec(byte[] encodedX509, String providerName) {
        if (encodedX509 == null) {
            throw new IllegalArgumentException("encodedX509 must not be null");
        }
        if (LEGACY_PROVIDER.equals(providerName)) {
            throw new IllegalArgumentException("Legacy BCPQC SPHINCS+ imports are unsupported; use SLH-DSA keys with BC");
        }
        this.encodedX509 = encodedX509.clone();
        this.providerName = (providerName == null ? "BC" : providerName);
    }

    /**
     * Returns a defensive copy of the X.509-encoded public key.
     *
     * @return clone of the encoded key bytes
     */
    public byte[] encoded() {
        return encodedX509.clone();
    }

    /**
     * Returns the provider name associated with this specification.
     *
     * @return provider name, never {@code null}
     */
    public String providerName() {
        return providerName;
    }

    /**
     * Serializes this specification into a {@link PairSeq}.
     *
     * <p>
     * The key bytes are Base64-encoded under the key {@code "x509.b64"}. The
     * provider name is stored under the key {@code "provider"}.
     * </p>
     *
     * @param spec public key spec to marshal
     * @return serialized {@link PairSeq} representation
     */
    public static PairSeq marshal(SphincsPlusPublicKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.encodedX509);
        return PairSeq.of("type", "SPHINCSPLUS-PUB", "x509.b64", b64, "provider", spec.providerName);
    }

    /**
     * Deserializes a {@code SphincsPlusPublicKeySpec} from a {@link PairSeq}.
     *
     * <p>
     * Expects keys {@code "x509.b64"} (required, Base64 string) and
     * {@code "provider"} (optional, defaults to {@code "BC"}).
     * </p>
     *
     * @param p serialized input
     * @return a reconstructed public key spec
     * @throws IllegalArgumentException if the encoded key is missing, malformed
     *                                  Base64, or the provider is legacy {@code "BCPQC"}
     */
    public static SphincsPlusPublicKeySpec unmarshal(PairSeq p) {
        byte[] out = null;
        String prov = "BC";
        PairSeq.Cursor c = p.cursor();
        while (c.next()) {
            String k = c.key();
            String v = c.value();
            switch (k) {
                case "x509.b64" -> out = Base64.getDecoder().decode(v);
                case "provider" -> prov = v;
                default -> {
                }
            }
        }
        if (out == null) {
            throw new IllegalArgumentException("x509.b64 missing for SPHINCS+ public key");
        }
        return new SphincsPlusPublicKeySpec(out, prov);
    }
}
