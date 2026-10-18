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
package zeroecho.core.alg.mldsa;

import java.util.Objects;

import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Specification for generating ML-DSA key pairs (FIPS 204).
 *
 * <p>
 * ML-DSA is parameterized by a parameter set number (44/65/87). Bouncy Castle
 * may also expose pre-hash variants (e.g., "with SHA-512") as separate
 * parameter specs.
 * </p>
 *
 * <p>
 * This spec intentionally restricts choices to the standardized ML-DSA
 * parameter sets only.
 * </p>
 *
 * @since 1.0
 */
public final class MldsaKeyGenSpec implements AlgorithmKeySpec {

    /**
     * ML-DSA parameter sets as defined by FIPS 204.
     *
     * @since 1.0
     */
    public enum ParameterSet {
        /** ML-DSA-44 (~128-bit security). */
        ML_DSA_44(44, 128),
        /** ML-DSA-65 (~192-bit security). */
        ML_DSA_65(65, 192),
        /** ML-DSA-87 (~256-bit security). */
        ML_DSA_87(87, 256);

        /**
         * Parameter set number (44/65/87).
         */
        public final int number;

        /**
         * Claimed security strength in bits (128/192/256) used by policy.
         */
        public final int strengthBits;

        ParameterSet(int number, int strengthBits) {
            this.number = number;
            this.strengthBits = strengthBits;
        }
    }

    /**
     * Optional pre-hash variant selection.
     *
     * <p>
     * If the provider exposes "with hash" variants as distinct parameter specs,
     * they can be selected here.
     * </p>
     *
     * @since 1.0
     */
    public enum PreHash {
        /** No pre-hash parameter set (pure ML-DSA). */
        NONE,
        /** Pre-hash with SHA-512 (provider-specific variant). */
        SHA512
    }

    private static final MldsaKeyGenSpec DEFAULT = new MldsaKeyGenSpec("BC", ParameterSet.ML_DSA_65, PreHash.NONE,
            null);

    private final String providerName;
    private final ParameterSet parameterSet;
    private final PreHash preHash;
    private final String explicitParamConstant; // nullable

    private MldsaKeyGenSpec(String providerName, ParameterSet parameterSet, PreHash preHash,
            String explicitParamConstant) {
        this.providerName = Objects.requireNonNull(providerName, "providerName");
        this.parameterSet = Objects.requireNonNull(parameterSet, "parameterSet");
        this.preHash = Objects.requireNonNull(preHash, "preHash");
        this.explicitParamConstant = explicitParamConstant;
    }

    /**
     * Returns the default ML-DSA key generation spec.
     *
     * @return a singleton default specification (ML-DSA-65, no pre-hash)
     */
    public static MldsaKeyGenSpec defaultSpec() {
        return DEFAULT;
    }

    /**
     * Creates a new specification with explicit algorithm parameters.
     *
     * @param providerName JCA provider name (typically {@code "BC"})
     * @param parameterSet parameter set (44/65/87)
     * @param preHash      optional pre-hash selection
     * @return a new {@code MldsaKeyGenSpec}
     */
    public static MldsaKeyGenSpec of(String providerName, ParameterSet parameterSet, PreHash preHash) {
        return new MldsaKeyGenSpec(providerName, parameterSet, preHash, null);
    }

    /**
     * Returns a copy of this specification with an explicit Bouncy Castle parameter
     * constant override.
     *
     * <p>
     * This bypasses automatic mapping. The name must match a static field in
     * {@code org.bouncycastle.jcajce.spec.MLDSAParameterSpec}.
     * </p>
     *
     * @param name field name in {@code MLDSAParameterSpec}
     * @return a new {@code MldsaKeyGenSpec} with the override
     */
    public MldsaKeyGenSpec withExplicitParamConstant(String name) {
        return new MldsaKeyGenSpec(providerName, parameterSet, preHash, name);
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
     * Returns the ML-DSA parameter set.
     *
     * @return parameter set
     */
    public ParameterSet parameterSet() {
        return parameterSet;
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
