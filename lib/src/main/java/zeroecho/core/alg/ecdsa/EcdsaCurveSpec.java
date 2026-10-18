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
package zeroecho.core.alg.ecdsa;

import java.util.Optional;

import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spec.ContextSpec;

/**
 * <h2>ECDSA Curve Specifications</h2>
 *
 * Enumeration of supported elliptic curve domain parameters for the
 * {@link EcdsaAlgorithm}. Each value binds a named curve, its associated JCA
 * signature algorithm string, and the fixed-length of produced signatures in
 * bytes (P1363 format).
 *
 * <h2>Curves</h2>
 * <ul>
 * <li>{@link #P256} - NIST P-256 (secp256r1), 64-byte signatures, SHA-256
 * digest binding.</li>
 * <li>{@link #P384} - NIST P-384 (secp384r1), 96-byte signatures, SHA-384
 * digest binding.</li>
 * <li>{@link #P512} - NIST P-521 (secp521r1), 132-byte signatures, SHA-512
 * digest binding.</li>
 * </ul>
 *
 * <h2>Usage</h2> The specification is used both as a {@link ContextSpec} for
 * signature contexts and as an {@link AlgorithmKeySpec} for key pair generation
 * or import. It ensures consistent algorithm selection and enforces
 * deterministic signature lengths.
 *
 * <pre>{@code
 * // Example: select curve specification
 * EcdsaCurveSpec spec = EcdsaCurveSpec.P256;
 * String curve = spec.curveName(); // "secp256r1"
 * String jcaAlg = spec.jcaFactory(); // "SHA256withECDSAinP1363Format"
 * int sigLen = spec.signFixedLength(); // 64
 * }</pre>
 *
 * @since 1.0
 */
public enum EcdsaCurveSpec implements ContextSpec, AlgorithmKeySpec, Describable {
    /** NIST P-256 (secp256r1), SHA-256 binding, 64-byte signatures. */
    P256("secp256r1", "SHA256withECDSAinP1363Format", 64),
    /** NIST P-384 (secp384r1), SHA-384 binding, 96-byte signatures. */
    P384("secp384r1", "SHA384withECDSAinP1363Format", 96),
    /** NIST P-521 (secp521r1), SHA-512 binding, 132-byte signatures. */
    P512("secp521r1", "SHA512withECDSAinP1363Format", 132);

    private final String curveName;
    private final String jca;
    private final int tagLen;

    /**
     * Constructs a curve specification.
     *
     * @param curveName canonical JCA curve name (e.g., "secp256r1")
     * @param jca       JCA algorithm identifier for signature operations
     * @param tagLen    fixed signature length in bytes (P1363 format)
     */
    EcdsaCurveSpec(String curveName, String jca, int tagLen) {
        this.curveName = curveName;
        this.jca = jca;
        this.tagLen = tagLen;
    }

    /**
     * Returns the canonical JCA curve name.
     *
     * @return curve name string (e.g., {@code "secp256r1"})
     */
    public String curveName() {
        return curveName;
    }

    /**
     * Returns the JCA algorithm identifier for this curve.
     *
     * @return JCA signature algorithm string
     */
    public String jcaFactory() {
        return jca;
    }

    /**
     * Returns the fixed signature length for this curve in bytes.
     *
     * <p>
     * Lengths follow the IEEE P1363 format (raw concatenation of R and S).
     * </p>
     *
     * @return signature length in bytes
     */
    public int signFixedLength() {
        return tagLen;
    }

    /**
     * Resolves a standard external ECDSA signature algorithm identifier to the
     * corresponding curve specification used by ZeroEcho.
     *
     * <p>
     * Standard names such as {@code SHA256withECDSA} imply both the digest family
     * and the fixed-size IEEE P1363 signature layout used internally by ZeroEcho.
     * This helper makes the mapping explicit so callers do not need to duplicate
     * it.
     * </p>
     *
     * @param algorithmId canonical external ECDSA signature algorithm identifier
     * @return matching curve specification, or {@link Optional#empty()} when the
     *         identifier is not a supported ECDSA interop name
     */
    public static Optional<EcdsaCurveSpec> fromSignatureAlgorithmId(String algorithmId) {
        if (algorithmId == null || algorithmId.isBlank()) {
            return Optional.empty();
        }
        return switch (algorithmId) {
            case "SHA256withECDSA" -> Optional.of(P256);
            case "SHA384withECDSA" -> Optional.of(P384);
            case "SHA512withECDSA" -> Optional.of(P512);
            default -> Optional.empty();
        };
    }

    /**
     * Returns a short, human-readable description of this object.
     *
     * <p>
     * The description should be concise and stable enough for logging or display
     * purposes, while avoiding exposure of any sensitive information.
     * </p>
     *
     * @return non-null descriptive string
     */
    @Override
    public String description() {
        return curveName;
    }
}
