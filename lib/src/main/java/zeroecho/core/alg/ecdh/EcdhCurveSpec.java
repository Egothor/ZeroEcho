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
package zeroecho.core.alg.ecdh;

import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spec.ContextSpec;

/**
 * <h2>Standardized ECDH Curve Specifications</h2>
 *
 * Enumeration of commonly used NIST-recommended elliptic curves for ECDH
 * (Elliptic Curve Diffie-Hellman) and related algorithms.
 *
 * <p>
 * Each constant provides:
 * </p>
 * <ul>
 * <li><b>Curve name</b> - the JCA-standardized name, suitable for use with
 * {@link java.security.spec.ECGenParameterSpec}.</li>
 * <li><b>Signature algorithm name</b> - a JCA/JCE identifier combining the hash
 * function and ECDSA variant in P1363 encoding.</li>
 * <li><b>Fixed signature length</b> - the expected byte length of deterministic
 * ECDSA signatures for the curve, following the P1363 format.</li>
 * </ul>
 *
 * <h2>Curves</h2>
 * <ul>
 * <li>{@link #P256} - secp256r1, 128-bit security level.</li>
 * <li>{@link #P384} - secp384r1, 192-bit security level.</li>
 * <li>{@link #P512} - secp521r1, ~256-bit security level.</li>
 * </ul>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Generate a key pair on P-256
 * KeyPair kp = CryptoAlgorithms.generateKeyPair("ECDH", EcdhCurveSpec.P256);
 *
 * // Use curve metadata
 * String jcaName = EcdhCurveSpec.P256.curveName(); // "secp256r1"
 * int sigLen = EcdhCurveSpec.P256.signFixedLength(); // 64 bytes
 * }</pre>
 *
 * @since 1.0
 */
public enum EcdhCurveSpec implements ContextSpec, AlgorithmKeySpec {
    /** NIST P-256 (secp256r1), approx. 128-bit security. */
    P256("secp256r1", "SHA256withECDSAinP1363Format", 64),
    /** NIST P-384 (secp384r1), approx. 192-bit security. */
    P384("secp384r1", "SHA384withECDSAinP1363Format", 96),
    /** NIST P-521 (secp521r1), approx. 256-bit security. */
    P512("secp521r1", "SHA512withECDSAinP1363Format", 132);

    private final String curveName;
    private final String jca;
    private final int tagLen;

    EcdhCurveSpec(String curveName, String jca, int tagLen) {
        this.curveName = curveName;
        this.jca = jca;
        this.tagLen = tagLen;
    }

    /**
     * Returns the JCA-standardized name of the elliptic curve.
     *
     * @return curve name, e.g., {@code "secp256r1"}
     */
    public String curveName() {
        return curveName;
    }

    /**
     * Returns the JCA factory name of the corresponding signature algorithm (ECDSA
     * with hash, P1363 encoding).
     *
     * @return JCA algorithm name, e.g., {@code "SHA256withECDSAinP1363Format"}
     */
    public String jcaFactory() {
        return jca;
    }

    /**
     * Returns the fixed byte length of deterministic ECDSA signatures for this
     * curve in P1363 format.
     *
     * @return fixed signature length in bytes
     */
    public int signFixedLength() {
        return tagLen;
    }
}
