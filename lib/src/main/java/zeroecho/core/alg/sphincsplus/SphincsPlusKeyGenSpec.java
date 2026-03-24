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
package zeroecho.core.alg.sphincsplus;

import java.util.Objects;

import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Specification for generating SPHINCS+ key pairs.
 *
 * <p>
 * {@code SphincsPlusKeyGenSpec} selects the hash family, security strength,
 * signature variant, and mode for the SPHINCS+ post-quantum signature scheme.
 * It also carries an optional provider name and explicit Bouncy Castle
 * parameter constant for direct mapping.
 * </p>
 *
 * <h2>Parameters</h2>
 * <ul>
 * <li>{@link Hash}: underlying hash/XOF function ({@code SHA2}, {@code SHAKE},
 * or {@code HARAKA}).</li>
 * <li>{@link Security}: NIST security level, expressed as {@code 128},
 * {@code 192}, or {@code 256} bits.</li>
 * <li>{@link Variant}: tradeoff between {@code FAST} (smaller signatures,
 * higher signing speed) and {@code SMALL} (shorter signatures, slower signing).
 * Security is unaffected.</li>
 * <li>{@link Mode}: {@code ROBUST} (conservative construction) or
 * {@code SIMPLE} (more efficient, narrower assumptions).</li>
 * <li>{@code providerName}: JCA provider name (e.g., {@code "BCPQC"} for Bouncy
 * Castle PQC).</li>
 * <li>{@code explicitParamConstant}: optional override; the exact field name of
 * a {@code SPHINCSPlusParameterSpec} constant in the Bouncy Castle API. If
 * non-null, it bypasses the automatic mapping.</li>
 * </ul>
 *
 * <h2>Defaults</h2> The {@link #defaultSpec()} uses:
 * <ul>
 * <li>Provider: {@code "BCPQC"}</li>
 * <li>Hash: {@link Hash#SHAKE}</li>
 * <li>Security: {@link Security#L5_256}</li>
 * <li>Variant: {@link Variant#SMALL}</li>
 * <li>Mode: {@link Mode#ROBUST}</li>
 * </ul>
 *
 * <h2>Example</h2> <pre>{@code
 * // Conservative, NIST Level 3 security, SHA-2 based
 * SphincsPlusKeyGenSpec spec = SphincsPlusKeyGenSpec.of(
 *     "BCPQC", 
 *     SphincsPlusKeyGenSpec.Hash.SHA2,
 *     SphincsPlusKeyGenSpec.Security.L3_192,
 *     SphincsPlusKeyGenSpec.Variant.FAST,
 *     SphincsPlusKeyGenSpec.Mode.ROBUST);
 *
 * KeyPair kp = new SphincsPlusKeyGenBuilder().generateKeyPair(spec);
 * }</pre>
 *
 * @since 1.0
 */
public final class SphincsPlusKeyGenSpec implements AlgorithmKeySpec {
    /**
     * Hash function families supported by SPHINCS+.
     */
    public enum Hash {
        /** SHA-2 based instantiation. */
        SHA2,
        /** SHAKE (SHA-3 XOF) based instantiation. */
        SHAKE,
        /** Haraka (AES-based permutation) instantiation. */
        HARAKA
    }

    /**
     * Security levels as defined by NIST PQC (L1, L3, L5). The {@code bits} field
     * gives the claimed classical security level.
     */
    public enum Security {
        /** NIST Level 1 (~128-bit security). */
        L1_128(128),
        /** NIST Level 3 (~192-bit security). */
        L3_192(192),
        /** NIST Level 5 (~256-bit security). */
        L5_256(256);

        /** Claimed security level in bits. */
        public final int bits;

        Security(int b) {
            bits = b;
        }
    }

    /**
     * Signature variants trading performance against signature size.
     *
     * <p>
     * {@code FAST} variants are optimized for speed (larger signatures).
     * {@code SMALL} variants reduce signature size at some performance cost.
     * Security is equivalent.
     * </p>
     */
    public enum Variant {
        /** Larger, faster signatures. */
        FAST,
        /** Smaller, slower signatures. */
        SMALL
    } // f vs s (speed vs signature size), same security

    /**
     * Construction mode: conservative {@code ROBUST} vs. more efficient
     * {@code SIMPLE}.
     *
     * <p>
     * {@code ROBUST} is recommended when in doubt; {@code SIMPLE} offers smaller
     * signatures and faster signing under additional assumptions.
     * </p>
     */
    public enum Mode {
        /** Conservative construction (recommended default). */
        ROBUST,
        /** Simpler and more efficient construction. */
        SIMPLE
    } // ROBUST = conservative

    private final String providerName;
    private final Hash hash;
    private final Security security;
    private final Variant variant;
    private final Mode mode;
    private final String explicitParamConstant; // nullable

    private static final SphincsPlusKeyGenSpec DEFAULT = new SphincsPlusKeyGenSpec("BCPQC", Hash.SHAKE, Security.L5_256,
            Variant.SMALL, Mode.ROBUST, null);

    private SphincsPlusKeyGenSpec(String providerName, Hash hash, Security sec, Variant var, Mode mode,
            String explicit) {
        this.providerName = Objects.requireNonNull(providerName, "providerName");
        this.hash = Objects.requireNonNull(hash, "hash");
        this.security = Objects.requireNonNull(sec, "security");
        this.variant = Objects.requireNonNull(var, "variant");
        this.mode = Objects.requireNonNull(mode, "mode");
        this.explicitParamConstant = explicit;
    }

    /**
     * Returns the default SPHINCS+ key generation spec.
     *
     * @return a singleton default specification (SHAKE, L5, SMALL, ROBUST)
     */
    public static SphincsPlusKeyGenSpec defaultSpec() {
        return DEFAULT;
    }

    /**
     * Creates a new specification with explicit algorithm parameters.
     *
     * @param providerName JCA provider name (e.g., "BCPQC")
     * @param hash         hash function family
     * @param sec          security level
     * @param var          signature variant (FAST vs SMALL)
     * @param mode         construction mode (ROBUST vs SIMPLE)
     * @return a new {@code SphincsPlusKeyGenSpec}
     */
    public static SphincsPlusKeyGenSpec of(String providerName, Hash hash, Security sec, Variant var, Mode mode) {
        return new SphincsPlusKeyGenSpec(providerName, hash, sec, var, mode, null);
    }

    /**
     * Returns a copy of this specification with an explicit Bouncy Castle parameter
     * constant override.
     *
     * <p>
     * This bypasses automatic mapping of hash family, security, variant, and mode.
     * It is useful to test new or provider-specific constants.
     * </p>
     *
     * @param name the name of the static field in {@code SPHINCSPlusParameterSpec}
     * @return a new {@code SphincsPlusKeyGenSpec} with the override
     */
    public SphincsPlusKeyGenSpec withExplicitParamConstant(String name) {
        return new SphincsPlusKeyGenSpec(providerName, hash, security, variant, mode, name);
    }

    /**
     * Returns the provider name used for key generation.
     *
     * @return provider name (never {@code null})
     */
    public String providerName() {
        return providerName;
    }

    /**
     * Returns the hash family of this specification.
     *
     * @return hash family
     */
    public Hash hash() {
        return hash;
    }

    /**
     * Returns the security level of this specification.
     *
     * @return security level
     */
    public Security security() {
        return security;
    }

    /**
     * Returns the variant of this specification.
     *
     * @return signature variant
     */
    public Variant variant() {
        return variant;
    }

    /**
     * Returns the construction mode of this specification.
     *
     * @return construction mode
     */
    public Mode mode() {
        return mode;
    }

    /**
     * Returns the explicit parameter constant override, if set.
     *
     * @return constant name, or {@code null} if automatic mapping is used
     */
    public String explicitParamConstant() {
        return explicitParamConstant;
    }
}
