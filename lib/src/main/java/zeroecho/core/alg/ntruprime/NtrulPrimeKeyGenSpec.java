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
package zeroecho.core.alg.ntruprime;

import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Algorithm-specific key generation parameters for NTRU LPRime.
 *
 * <p>
 * {@code NtrulPrimeKeyGenSpec} selects one of the standardized parameter
 * variants of the NTRU LPRime key encapsulation mechanism. Each variant
 * determines the security level, key sizes, and performance characteristics of
 * the generated key pair.
 * </p>
 *
 * <h2>Variants</h2>
 * <ul>
 * <li>{@link Variant#NTRULPR653}: ~128-bit classical security.</li>
 * <li>{@link Variant#NTRULPR761}: ~192-bit security.</li>
 * <li>{@link Variant#NTRULPR857}: ~256-bit security.</li>
 * <li>{@link Variant#NTRULPR953}, {@link Variant#NTRULPR1013},
 * {@link Variant#NTRULPR1277}: higher strength variants with progressively
 * larger keys and ciphertexts.</li>
 * </ul>
 *
 * <p>
 * Instances are immutable and typically passed to
 * {@link zeroecho.core.CryptoAlgorithm#generateKeyPair} or retrieved from a
 * {@code CryptoAlgorithm} builder. For convenience, static factory methods are
 * provided for each variant.
 * </p>
 *
 * <h2>Example</h2> <pre>{@code
 * CryptoAlgorithm alg = CryptoAlgorithms.require("NTRULPRime");
 * KeyPair kp = alg.generateKeyPair(NtrulPrimeKeyGenSpec.ntrulpr761());
 * }</pre>
 *
 * @since 1.0
 */
public final class NtrulPrimeKeyGenSpec implements AlgorithmKeySpec, Describable {
    /**
     * Enumeration of supported NTRU LPRime parameter sets.
     */
    public enum Variant {
        /** Variant with ~128-bit classical security. */
        NTRULPR653,
        /** Variant with ~192-bit classical security. */
        NTRULPR761,
        /** Variant with ~256-bit classical security. */
        NTRULPR857,
        /** Variant beyond 256-bit, with larger parameters. */
        NTRULPR953,
        /** Variant beyond 256-bit, with larger parameters. */
        NTRULPR1013,
        /** Highest-strength standardized variant. */
        NTRULPR1277
    }

    private final Variant variant;

    private NtrulPrimeKeyGenSpec(Variant v) {
        this.variant = v;
    }

    /**
     * Creates a specification from the given variant.
     *
     * @param v selected NTRU LPRime parameter set
     * @return new specification bound to {@code v}
     * @throws NullPointerException if {@code v} is {@code null}
     */
    public static NtrulPrimeKeyGenSpec of(Variant v) {
        return new NtrulPrimeKeyGenSpec(v);
    }

    /**
     * Creates a key generation specification for the {@link Variant#NTRULPR653}
     * parameter set.
     *
     * <p>
     * This variant offers around 128-bit classical security with relatively small
     * key and ciphertext sizes, making it suitable for constrained environments.
     * </p>
     *
     * @return a new specification targeting {@code NTRULPR653}
     */
    public static NtrulPrimeKeyGenSpec ntrulpr653() {
        return new NtrulPrimeKeyGenSpec(Variant.NTRULPR653);
    }

    /**
     * Creates a key generation specification for the {@link Variant#NTRULPR761}
     * parameter set.
     *
     * <p>
     * This variant balances efficiency and strength, offering roughly 192-bit
     * security. It is a common choice for post-quantum readiness in practical
     * deployments.
     * </p>
     *
     * @return a new specification targeting {@code NTRULPR761}
     */
    public static NtrulPrimeKeyGenSpec ntrulpr761() {
        return new NtrulPrimeKeyGenSpec(Variant.NTRULPR761);
    }

    /**
     * Creates a key generation specification for the {@link Variant#NTRULPR857}
     * parameter set.
     *
     * <p>
     * This variant aims for ~256-bit classical security with larger keys and
     * ciphertexts compared to the 653 and 761 sets, offering stronger margins.
     * </p>
     *
     * @return a new specification targeting {@code NTRULPR857}
     */
    public static NtrulPrimeKeyGenSpec ntrulpr857() {
        return new NtrulPrimeKeyGenSpec(Variant.NTRULPR857);
    }

    /**
     * Creates a key generation specification for the {@link Variant#NTRULPR953}
     * parameter set.
     *
     * <p>
     * Provides very high security beyond 256-bit classical strength, with larger
     * key material and ciphertexts. Suitable for highly conservative use cases.
     * </p>
     *
     * @return a new specification targeting {@code NTRULPR953}
     */
    public static NtrulPrimeKeyGenSpec ntrulpr953() {
        return new NtrulPrimeKeyGenSpec(Variant.NTRULPR953);
    }

    /**
     * Creates a key generation specification for the {@link Variant#NTRULPR1013}
     * parameter set.
     *
     * <p>
     * A higher-strength variant designed for long-term security horizons, offering
     * protection well above 256-bit security levels at the cost of larger keys.
     * </p>
     *
     * @return a new specification targeting {@code NTRULPR1013}
     */
    public static NtrulPrimeKeyGenSpec ntrulpr1013() {
        {
            return new NtrulPrimeKeyGenSpec(Variant.NTRULPR1013);
        }
    }

    /**
     * Creates a key generation specification for the {@link Variant#NTRULPR1277}
     * parameter set.
     *
     * <p>
     * The largest standardized parameter set, offering the highest security margin
     * and designed for long-term quantum resistance in highly sensitive
     * applications.
     * </p>
     *
     * @return a new specification targeting {@code NTRULPR1277}
     */
    public static NtrulPrimeKeyGenSpec ntrulpr1277() {
        {
            return new NtrulPrimeKeyGenSpec(Variant.NTRULPR1277);
        }
    }

    /**
     * Returns the selected variant for this specification.
     *
     * @return variant of NTRU LPRime key parameters
     */
    public Variant variant() {
        return variant;
    }

    /**
     * Returns a textual description of this specification.
     *
     * <p>
     * The description is the variant name (e.g., {@code "NTRULPR761"}).
     * </p>
     *
     * @return variant name string
     */
    @Override
    public String description() {
        return variant.toString();
    }
}
