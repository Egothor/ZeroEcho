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
package zeroecho.core.alg.rsa;

import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Key generation specification for RSA key pairs.
 *
 * <p>
 * This spec defines the modulus length and public exponent used when generating
 * an RSA key pair. It is passed to the algorithm’s key builder (see
 * {@code RsaAlgorithm}) to produce a {@link java.security.KeyPair}.
 * </p>
 *
 * <h2>Parameters</h2>
 * <ul>
 * <li><b>keySize</b>: the RSA modulus size in bits. Must be at least 1024;
 * typical secure values are 2048 or 3072, with 4096 used for high-security
 * applications.</li>
 * <li><b>publicExponent</b>: the RSA public exponent. The common and
 * recommended value is 65537 (F4), balancing security and performance.</li>
 * </ul>
 *
 * <h2>Usage example</h2> <pre>{@code
 * // Create a spec for a 2048-bit key with exponent 65537
 * RsaKeyGenSpec spec = RsaKeyGenSpec.rsa2048();
 *
 * // Generate the key pair
 * KeyPair kp = rsaAlgorithm.asymmetricKeyPairGenerator(RsaKeyGenSpec.class)
 *                          .generateKeyPair(spec);
 * }</pre>
 *
 * @since 1.0
 */
public final class RsaKeyGenSpec implements AlgorithmKeySpec, Describable {
    private final int keySize;
    private final int publicExponent; // typical 65537

    /**
     * Constructs an RSA key generation spec with the given parameters.
     *
     * @param keySize        modulus size in bits; must be at least 1024
     * @param publicExponent RSA public exponent, usually 65537
     * @throws IllegalArgumentException if {@code keySize} is smaller than 1024
     */
    public RsaKeyGenSpec(int keySize, int publicExponent) {
        if (keySize < 1024) { // NOPMD
            throw new IllegalArgumentException("keySize too small");
        }
        this.keySize = keySize;
        this.publicExponent = publicExponent;
    }

    /**
     * Returns the modulus length in bits.
     *
     * @return RSA modulus size
     */
    public int keySize() {
        return keySize;
    }

    /**
     * Returns the public exponent.
     *
     * @return RSA public exponent (typically 65537)
     */
    public int publicExponent() {
        return publicExponent;
    }

    /**
     * Convenience factory for a 2048-bit RSA spec with exponent 65537.
     *
     * @return new {@code RsaKeyGenSpec} instance for 2048/65537
     */
    public static RsaKeyGenSpec rsa2048() {
        return new RsaKeyGenSpec(2_048, 65_537);
    }

    /**
     * Convenience factory for a 3072-bit RSA spec with exponent 65537.
     *
     * @return new {@code RsaKeyGenSpec} instance for 3072/65537
     */
    public static RsaKeyGenSpec rsa3072() {
        return new RsaKeyGenSpec(3_072, 65_537);
    }

    /**
     * Convenience factory for a 4096-bit RSA spec with exponent 65537.
     *
     * @return new {@code RsaKeyGenSpec} instance for 4096/65537
     */
    public static RsaKeyGenSpec rsa4096() {
        return new RsaKeyGenSpec(4_096, 65_537);
    }

    /**
     * Returns a short description string.
     *
     * <p>
     * Format is {@code "<keySize>:<publicExponent>"}, for example
     * {@code "2048:65537"}.
     * </p>
     *
     * @return human-readable description of this spec
     */
    @Override
    public String description() {
        return keySize + ":" + publicExponent;
    }
}
