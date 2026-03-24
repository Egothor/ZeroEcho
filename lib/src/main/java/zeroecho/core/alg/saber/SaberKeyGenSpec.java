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
package zeroecho.core.alg.saber;

import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Key generation specification for the SABER post-quantum KEM algorithm.
 *
 * <p>
 * A {@code SaberKeyGenSpec} selects one of the SABER parameter variants
 * standardized in round-3 submissions. Each variant balances performance,
 * bandwidth, and security level. This spec is passed to a registered
 * {@link zeroecho.core.spi.AsymmetricKeyBuilder} to generate a SABER key pair.
 * </p>
 *
 * <h2>Variants</h2> The {@link Variant} enumeration identifies supported SABER
 * parameter sets:
 * <ul>
 * <li>{@link Variant#LIGHTSABERKEM128R3}: lightweight security, smallest key
 * sizes.</li>
 * <li>{@link Variant#SABERKEM128R3}: standard security level, moderate key
 * sizes.</li>
 * <li>{@link Variant#FIRESABERKEM128R3}: strongest within 128-bit category,
 * largest key sizes.</li>
 * <li>{@link Variant#LIGHTSABERKEM192R3}, {@link Variant#SABERKEM192R3},
 * {@link Variant#FIRESABERKEM192R3}: parameter sets targeting ~192-bit
 * security.</li>
 * <li>{@link Variant#LIGHTSABERKEM256R3}, {@link Variant#SABERKEM256R3},
 * {@link Variant#FIRESABERKEM256R3}: parameter sets targeting ~256-bit
 * security.</li>
 * </ul>
 *
 * <h2>Usage example</h2> <pre>{@code
 * SaberKeyGenSpec spec = SaberKeyGenSpec.saberkem256r3();
 * KeyPair kp = CryptoAlgorithms.keyPair("SABER", spec);
 * }</pre>
 *
 * @since 1.0
 */
public final class SaberKeyGenSpec implements AlgorithmKeySpec, Describable {
    /**
     * Enumeration of SABER parameter set variants.
     *
     * <p>
     * Each constant maps directly to a standardized SABER submission parameter set.
     * They differ in module rank, polynomial dimension, and security level.
     * </p>
     */
    public enum Variant {
        /**
         * LightSaber KEM, round-3, targeting ~128-bit security with smallest footprint.
         */
        LIGHTSABERKEM128R3,
        /** Saber KEM, round-3, baseline 128-bit security parameter set. */
        SABERKEM128R3,
        /** FireSaber KEM, round-3, strong 128-bit security with larger parameters. */
        FIRESABERKEM128R3,
        /** LightSaber KEM, round-3, targeting ~192-bit security. */
        LIGHTSABERKEM192R3,
        /** Saber KEM, round-3, baseline 192-bit security parameter set. */
        SABERKEM192R3,
        /** FireSaber KEM, round-3, strong 192-bit security with larger parameters. */
        FIRESABERKEM192R3,
        /** LightSaber KEM, round-3, targeting ~256-bit security. */
        LIGHTSABERKEM256R3,
        /** Saber KEM, round-3, baseline 256-bit security parameter set. */
        SABERKEM256R3,
        /** FireSaber KEM, round-3, strong 256-bit security with larger parameters. */
        FIRESABERKEM256R3
    }

    private final Variant variant;

    private SaberKeyGenSpec(Variant v) {
        this.variant = v;
    }

    /**
     * Creates a specification for a given variant.
     *
     * @param v the SABER variant
     * @return new key generation spec for the variant
     */
    public static SaberKeyGenSpec of(Variant v) {
        return new SaberKeyGenSpec(v);
    }

    /**
     * Creates a specification for the LightSaberKEM128R3 variant.
     *
     * <p>
     * This is the smallest SABER parameter set at the 128-bit security level,
     * optimized for constrained environments. It trades some performance margin for
     * reduced bandwidth and memory footprint.
     * </p>
     *
     * @return a new {@code SaberKeyGenSpec} representing the LightSaberKEM128R3
     *         variant
     */
    public static SaberKeyGenSpec lightsaberkem128r3() {
        return new SaberKeyGenSpec(Variant.LIGHTSABERKEM128R3);
    }

    /**
     * Creates a specification for the SaberKEM128R3 variant.
     *
     * <p>
     * This is the baseline SABER parameter set at the 128-bit security level,
     * balancing efficiency and security margin. It is the recommended choice for
     * standard 128-bit use cases.
     * </p>
     *
     * @return a new {@code SaberKeyGenSpec} representing the SaberKEM128R3 variant
     */
    public static SaberKeyGenSpec saberkem128r3() {
        return new SaberKeyGenSpec(Variant.SABERKEM128R3);
    }

    /**
     * Creates a specification for the FireSaberKEM128R3 variant.
     *
     * <p>
     * This is the strongest SABER parameter set at the 128-bit security level,
     * using larger dimensions to maximize security margin. It comes with higher
     * computational and bandwidth cost than LightSaber or Saber.
     * </p>
     *
     * @return a new {@code SaberKeyGenSpec} representing the FireSaberKEM128R3
     *         variant
     */
    public static SaberKeyGenSpec firesaberkem128r3() {
        return new SaberKeyGenSpec(Variant.FIRESABERKEM128R3);
    }

    /**
     * Creates a specification for the LightSaberKEM192R3 variant.
     *
     * <p>
     * This variant targets approximately 192-bit security with minimized resource
     * usage. It is designed for higher security requirements while still
     * considering efficiency.
     * </p>
     *
     * @return a new {@code SaberKeyGenSpec} representing the LightSaberKEM192R3
     *         variant
     */
    public static SaberKeyGenSpec lightsaberkem192r3() {
        return new SaberKeyGenSpec(Variant.LIGHTSABERKEM192R3);
    }

    /**
     * Creates a specification for the SaberKEM192R3 variant.
     *
     * <p>
     * This is the balanced SABER parameter set at the 192-bit security level,
     * offering a midpoint between performance and conservative security margin.
     * </p>
     *
     * @return a new {@code SaberKeyGenSpec} representing the SaberKEM192R3 variant
     */
    public static SaberKeyGenSpec saberkem192r3() {
        return new SaberKeyGenSpec(Variant.SABERKEM192R3);
    }

    /**
     * Creates a specification for the FireSaberKEM192R3 variant.
     *
     * <p>
     * This is the strongest SABER configuration at the 192-bit security level,
     * providing the highest margin at the cost of larger keys and slower
     * operations.
     * </p>
     *
     * @return a new {@code SaberKeyGenSpec} representing the FireSaberKEM192R3
     *         variant
     */
    public static SaberKeyGenSpec firesaberkem192r3() {
        return new SaberKeyGenSpec(Variant.FIRESABERKEM192R3);
    }

    /**
     * Creates a specification for the LightSaberKEM256R3 variant.
     *
     * <p>
     * This variant targets approximately 256-bit security with reduced parameter
     * sizes compared to the full Saber/FireSaber sets. It favors efficiency in very
     * high-security applications.
     * </p>
     *
     * @return a new {@code SaberKeyGenSpec} representing the LightSaberKEM256R3
     *         variant
     */
    public static SaberKeyGenSpec lightsaberkem256r3() {
        return new SaberKeyGenSpec(Variant.LIGHTSABERKEM256R3);
    }

    /**
     * Creates a specification for the SaberKEM256R3 variant.
     *
     * <p>
     * This is the balanced SABER parameter set at the 256-bit security level,
     * recommended for long-term, high-assurance use cases where efficiency is still
     * important.
     * </p>
     *
     * @return a new {@code SaberKeyGenSpec} representing the SaberKEM256R3 variant
     */
    public static SaberKeyGenSpec saberkem256r3() {
        return new SaberKeyGenSpec(Variant.SABERKEM256R3);
    }

    /**
     * Creates a specification for the FireSaberKEM256R3 variant.
     *
     * <p>
     * This is the strongest SABER configuration at the 256-bit security level,
     * prioritizing maximum security margin over efficiency. It uses the largest
     * parameter sizes and yields the heaviest resource usage.
     * </p>
     *
     * @return a new {@code SaberKeyGenSpec} representing the FireSaberKEM256R3
     *         variant
     */
    public static SaberKeyGenSpec firesaberkem256r3() {
        return new SaberKeyGenSpec(Variant.FIRESABERKEM256R3);
    }

    /**
     * Returns the variant this spec represents.
     *
     * @return selected SABER variant
     */
    public Variant variant() {
        return variant;
    }

    /**
     * Returns a textual description of this spec.
     *
     * <p>
     * Currently this is the {@link Variant} name, e.g. {@code SABERKEM256R3}.
     * </p>
     *
     * @return string description of the spec
     */
    @Override
    public String description() {
        return variant.toString();
    }
}
