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
package zeroecho.core.alg.slhdsa;

import java.util.Base64;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Encoded representation of an SLH-DSA public key.
 *
 * <p>
 * {@code SlhDsaPublicKeySpec} is an immutable value object that wraps an X.509
 * (SubjectPublicKeyInfo) encoded SLH-DSA public key together with the JCA
 * provider name that should be used when importing the key.
 * </p>
 *
 * <h2>Encoding</h2>
 * <ul>
 * <li>The public key bytes are stored as a defensive copy of the provided X.509
 * byte array.</li>
 * <li>Marshalling/unmarshalling uses {@link PairSeq} with Base64 encoding under
 * {@code "x509.b64"}.</li>
 * </ul>
 *
 * <h2>Provider selection</h2>
 * <p>
 * The default provider is {@code "BC"} because SLH-DSA is registered by the
 * Bouncy Castle core provider.
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances are immutable and can be safely shared across threads.
 * </p>
 *
 * @since 1.0
 */
public final class SlhDsaPublicKeySpec implements AlgorithmKeySpec {

    private final byte[] encodedX509;
    private final String providerName;

    /**
     * Creates a new specification using the default provider {@code "BC"}.
     *
     * @param encodedX509 X.509-encoded SLH-DSA public key bytes
     * @throws IllegalArgumentException if {@code encodedX509} is {@code null}
     */
    public SlhDsaPublicKeySpec(byte[] encodedX509) {
        this(encodedX509, "BC");
    }

    /**
     * Creates a new specification using the supplied provider.
     *
     * <p>
     * If {@code providerName} is {@code null}, the default provider {@code "BC"} is
     * used.
     * </p>
     *
     * @param encodedX509  X.509-encoded SLH-DSA public key bytes
     * @param providerName JCA provider name to use for import; may be {@code null}
     * @throws IllegalArgumentException if {@code encodedX509} is {@code null}
     */
    public SlhDsaPublicKeySpec(byte[] encodedX509, String providerName) {
        if (encodedX509 == null) {
            throw new IllegalArgumentException("encodedX509 must not be null");
        }
        this.encodedX509 = encodedX509.clone();
        this.providerName = (providerName == null ? "BC" : providerName);
    }

    /**
     * Returns a defensive copy of the X.509-encoded public key bytes.
     *
     * @return a copy of the encoded public key
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
     * Serializes the given spec into a {@link PairSeq}.
     *
     * <p>
     * The encoded key is stored as Base64 without padding under {@code "x509.b64"}.
     * The provider is stored under {@code "provider"}.
     * </p>
     *
     * @param spec the public key specification to serialize
     * @return serialized representation
     * @throws NullPointerException if {@code spec} is {@code null}
     */
    public static PairSeq marshal(SlhDsaPublicKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.encodedX509);
        return PairSeq.of("type", "SLHDSA-PUB", "x509.b64", b64, "provider", spec.providerName);
    }

    /**
     * Deserializes a {@link SlhDsaPublicKeySpec} from a {@link PairSeq}.
     *
     * <p>
     * Expects key {@code "x509.b64"} (required) and {@code "provider"} (optional;
     * defaults to {@code "BC"}).
     * </p>
     *
     * @param p serialized input
     * @return reconstructed public key specification
     * @throws IllegalArgumentException if {@code "x509.b64"} is missing
     * @throws NullPointerException     if {@code p} is {@code null}
     */
    public static SlhDsaPublicKeySpec unmarshal(PairSeq p) {
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
            throw new IllegalArgumentException("x509.b64 missing for SLH-DSA public key");
        }
        return new SlhDsaPublicKeySpec(out, prov);
    }
}
