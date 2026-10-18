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

import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>ElGamal Key Generation Specification</h2>
 *
 * Parameters controlling ElGamal key pair generation. This specification
 * provides the modulus size and the certainty parameter for primality testing.
 *
 * <p>
 * When generating a new ElGamal key pair, the modulus {@code p} must be chosen
 * as a large safe prime. The {@code keySize} determines the bit length of
 * {@code p}, and {@code certainty} controls the statistical strength of
 * Miller–Rabin primality checks.
 * </p>
 *
 * <h2>Validation rules</h2>
 * <ul>
 * <li>{@code keySize} must be at least 1024 bits.</li>
 * <li>{@code certainty} must be at least 64, which ensures negligible error
 * probability in primality testing.</li>
 * </ul>
 *
 * <h2>Factory</h2>
 * <ul>
 * <li>{@link #elgamal2048()} returns a commonly used default spec with a
 * 2048-bit modulus and 128 Miller–Rabin iterations.</li>
 * </ul>
 *
 * <h2>Usage</h2> <pre>{@code
 * ElgamalKeyGenSpec spec = ElgamalKeyGenSpec.elgamal2048();
 * KeyPair kp = algo.asymmetricKeyPairGenerator(ElgamalKeyGenSpec.class).generateKeyPair(spec);
 * }</pre>
 *
 * <h2>Thread-safety</h2> Instances are immutable and can be freely shared
 * between threads.
 *
 * @since 1.0
 */
public final class ElgamalKeyGenSpec implements AlgorithmKeySpec, Describable {
    private final int keySize; // bits for p
    private final int certainty; // Miller-Rabin certainty

    /**
     * Constructs a new ElGamal key generation spec.
     *
     * @param keySize   desired modulus size in bits (minimum 1024)
     * @param certainty number of Miller–Rabin iterations for primality testing
     *                  (minimum 64)
     * @throws IllegalArgumentException if {@code keySize} &lt; 1024 or
     *                                  {@code certainty} &lt; 64
     */
    public ElgamalKeyGenSpec(int keySize, int certainty) {
        if (keySize < 1024) { // NOPMD
            throw new IllegalArgumentException("keySize too small");
        }
        if (certainty < 64) { // NOPMD
            throw new IllegalArgumentException("certainty too small");
        }
        this.keySize = keySize;
        this.certainty = certainty;
    }

    /**
     * Returns the modulus size in bits.
     *
     * @return number of bits for the prime modulus p
     */
    public int keySize() {
        return keySize;
    }

    /**
     * Returns the Miller–Rabin certainty parameter.
     *
     * @return number of iterations used in primality testing
     */
    public int certainty() {
        return certainty;
    }

    /**
     * Returns a default ElGamal spec with a 2048-bit modulus and 128 iterations for
     * primality testing.
     *
     * @return default ElGamal key generation specification
     */
    public static ElgamalKeyGenSpec elgamal2048() {
        return new ElgamalKeyGenSpec(2048, 128);
    }

    /**
     * Human-readable description of this spec.
     *
     * <p>
     * Example: {@code "p=2048, certainty=128"}.
     * </p>
     *
     * @return descriptive string including modulus size and certainty
     */
    @Override
    public String description() {
        return "p=" + keySize + ", certainty=" + certainty;
    }
}
