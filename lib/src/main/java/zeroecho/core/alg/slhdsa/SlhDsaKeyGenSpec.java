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
package zeroecho.core.alg.slhdsa;

import java.util.Objects;

import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Specification for generating SLH-DSA key pairs (FIPS 205).
 *
 * <p>
 * SLH-DSA is parameterized by hash family (SHA2 or SHAKE), a security strength
 * (128/192/256), and a variant (fast vs small). Additionally, Bouncy Castle
 * exposes pre-hash variants (e.g., "with SHA-256") as separate parameter specs.
 * </p>
 *
 * <p>
 * This spec intentionally restricts the available choices to SLH-DSA parameters
 * (i.e., no Haraka and no SPHINCS+ "simple/robust" split).
 * </p>
 *
 * @since 1.0
 */
public final class SlhDsaKeyGenSpec implements AlgorithmKeySpec {

    /**
     * SLH-DSA hash families (FIPS 205).
     */
    public enum Hash {
        /** SHA-2 based SLH-DSA parameter sets. */
        SHA2,
        /** SHAKE based SLH-DSA parameter sets. */
        SHAKE
    }

    /**
     * Security levels as defined by NIST PQC (L1, L3, L5).
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
     * Variant trading performance against signature size.
     *
     * <p>
     * {@code FAST} variants are optimized for speed (larger signatures).
     * {@code SMALL} variants reduce signature size at some performance cost.
     * </p>
     */
    public enum Variant {
        /** Larger, faster signatures. */
        FAST,
        /** Smaller, slower signatures. */
        SMALL
    }

    /**
     * Optional pre-hash variant selection.
     *
     * <p>
     * Bouncy Castle exposes "with hash" variants as distinct parameter specs, for
     * example {@code slh_dsa_sha2_128s_with_sha256}.
     * </p>
     *
     * <p>
     * Valid combinations depend on the hash family and security strength:
     * </p>
     * <ul>
     * <li>SHA2-128 uses SHA-256</li>
     * <li>SHA2-192/256 use SHA-512</li>
     * <li>SHAKE-128 uses SHAKE128</li>
     * <li>SHAKE-192/256 use SHAKE256</li>
     * </ul>
     */
    public enum PreHash {
        /** No pre-hash parameter set (pure SLH-DSA). */
        NONE,
        /** Pre-hash with SHA-256 (only for SHA2-128). */
        SHA256,
        /** Pre-hash with SHA-512 (only for SHA2-192/256). */
        SHA512,
        /** Pre-hash with SHAKE128 (only for SHAKE-128). */
        SHAKE128,
        /** Pre-hash with SHAKE256 (only for SHAKE-192/256). */
        SHAKE256
    }

    private static final SlhDsaKeyGenSpec DEFAULT = new SlhDsaKeyGenSpec("BC", Hash.SHAKE, Security.L5_256,
            Variant.SMALL, PreHash.NONE, null);

    private final String providerName;
    private final Hash hash;
    private final Security security;
    private final Variant variant;
    private final PreHash preHash;
    private final String explicitParamConstant; // nullable

    private SlhDsaKeyGenSpec(String providerName, Hash hash, Security security, Variant variant, PreHash preHash,
            String explicitParamConstant) {
        this.providerName = Objects.requireNonNull(providerName, "providerName");
        this.hash = Objects.requireNonNull(hash, "hash");
        this.security = Objects.requireNonNull(security, "security");
        this.variant = Objects.requireNonNull(variant, "variant");
        this.preHash = Objects.requireNonNull(preHash, "preHash");
        this.explicitParamConstant = explicitParamConstant;
    }

    /**
     * Returns the default SLH-DSA key generation spec.
     *
     * @return a singleton default specification (SHAKE, L5, SMALL, no pre-hash)
     */
    public static SlhDsaKeyGenSpec defaultSpec() {
        return DEFAULT;
    }

    /**
     * Creates a new specification with explicit algorithm parameters.
     *
     * @param providerName JCA provider name (e.g., "BC", "BCPQC")
     * @param hash         hash family (SHA2 or SHAKE)
     * @param security     security level
     * @param variant      variant (FAST vs SMALL)
     * @param preHash      optional pre-hash selection
     * @return a new {@code SlhDsaKeyGenSpec}
     */
    public static SlhDsaKeyGenSpec of(String providerName, Hash hash, Security security, Variant variant,
            PreHash preHash) {
        return new SlhDsaKeyGenSpec(providerName, hash, security, variant, preHash, null);
    }

    /**
     * Returns a copy of this specification with an explicit Bouncy Castle parameter
     * constant override.
     *
     * <p>
     * This bypasses automatic mapping. The name must match a static field in
     * {@code org.bouncycastle.jcajce.spec.SLHDSAParameterSpec}.
     * </p>
     *
     * @param name field name in {@code SLHDSAParameterSpec}
     * @return a new {@code SlhDsaKeyGenSpec} with the override
     */
    public SlhDsaKeyGenSpec withExplicitParamConstant(String name) {
        return new SlhDsaKeyGenSpec(providerName, hash, security, variant, preHash, name);
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
     * Returns the SLH-DSA hash family.
     *
     * @return hash family
     */
    public Hash hash() {
        return hash;
    }

    /**
     * Returns the security level.
     *
     * @return security level
     */
    public Security security() {
        return security;
    }

    /**
     * Returns the variant.
     *
     * @return variant
     */
    public Variant variant() {
        return variant;
    }

    /**
     * Returns the pre-hash selection.
     *
     * @return pre-hash selection
     */
    public PreHash preHash() {
        return preHash;
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
