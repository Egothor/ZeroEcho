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
package zeroecho.core.alg.cmce;

import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>CMCE key generation specification</h2>
 *
 * <p>
 * Encapsulates the choice of Classic McEliece parameter set (variant) to be
 * used when generating new key pairs. Each variant corresponds to a
 * standardized security level and key size trade-off as defined in the
 * post-quantum KEM standardization process.
 * </p>
 *
 * <p>
 * Usage example:
 * </p>
 * <pre>{@code
 * // Generate a key pair for McEliece 8192128F (256-bit security, fast)
 * CmceKeyGenSpec spec = CmceKeyGenSpec.mceliece8192128f();
 * KeyPair kp = alg.asymmetricKeyPairGenerator(CmceKeyGenSpec.class).generateKeyPair(spec);
 * }</pre>
 *
 * @since 1.0
 */
public final class CmceKeyGenSpec implements AlgorithmKeySpec, Describable {
    /**
     * Enumeration of supported CMCE parameter set variants.
     *
     * <p>
     * Each value corresponds to a named parameter set from the Classic McEliece
     * post-quantum KEM standardization.
     * </p>
     */
    public enum Variant {
        /**
         * McEliece 348864, standard parameter set (128-bit security).
         */
        MCELIECE_348864,
        /**
         * McEliece 348864, fast parameter set (128-bit security).
         */
        MCELIECE_348864F,
        /**
         * McEliece 460896, standard parameter set (128-bit security, larger keys).
         */
        MCELIECE_460896,
        /**
         * McEliece 460896, fast parameter set (128-bit security, larger keys).
         */
        MCELIECE_460896F,
        /**
         * McEliece 6688128, standard parameter set (192-bit security).
         */
        MCELIECE_6688128,
        /**
         * McEliece 6688128, fast parameter set (192-bit security).
         */
        MCELIECE_6688128F,
        /**
         * McEliece 6960119, standard parameter set (192-bit security, alternative
         * form).
         */
        MCELIECE_6960119,
        /**
         * McEliece 6960119, fast parameter set (192-bit security, alternative form).
         */
        MCELIECE_6960119F,
        /**
         * McEliece 8192128, standard parameter set (256-bit security).
         */
        MCELIECE_8192128,
        /**
         * McEliece 8192128, fast parameter set (256-bit security).
         */
        MCELIECE_8192128F
    }

    private final Variant variant;

    private CmceKeyGenSpec(Variant v) {
        this.variant = v;
    }

    /**
     * Creates a new key generation spec bound to a specific variant.
     *
     * @param v variant to use
     * @return new specification for the given variant
     * @throws NullPointerException if {@code v} is null
     */
    public static CmceKeyGenSpec of(Variant v) {
        return new CmceKeyGenSpec(v);
    }

    /**
     * Convenience factory for {@link Variant#MCELIECE_348864}.
     *
     * @return a new specification for {@link Variant#MCELIECE_348864}
     */
    public static CmceKeyGenSpec mceliece348864() {
        return new CmceKeyGenSpec(Variant.MCELIECE_348864);
    }

    /**
     * Convenience factory for {@link Variant#MCELIECE_348864F}.
     *
     * @return a new specification for {@link Variant#MCELIECE_348864F}
     */
    public static CmceKeyGenSpec mceliece348864f() {
        return new CmceKeyGenSpec(Variant.MCELIECE_348864F);
    }

    /**
     * Convenience factory for {@link Variant#MCELIECE_460896}.
     *
     * @return a new specification for {@link Variant#MCELIECE_460896}
     */
    public static CmceKeyGenSpec mceliece460896() {
        return new CmceKeyGenSpec(Variant.MCELIECE_460896);
    }

    /**
     * Convenience factory for {@link Variant#MCELIECE_460896F}.
     *
     * @return a new specification for {@link Variant#MCELIECE_460896F}
     */
    public static CmceKeyGenSpec mceliece460896f() {
        return new CmceKeyGenSpec(Variant.MCELIECE_460896F);
    }

    /**
     * Convenience factory for {@link Variant#MCELIECE_6688128}.
     *
     * @return a new specification for {@link Variant#MCELIECE_6688128}
     */
    public static CmceKeyGenSpec mceliece6688128() {
        return new CmceKeyGenSpec(Variant.MCELIECE_6688128);
    }

    /**
     * Convenience factory for {@link Variant#MCELIECE_6688128F}.
     *
     * @return a new specification for {@link Variant#MCELIECE_6688128F}
     */
    public static CmceKeyGenSpec mceliece6688128f() {
        return new CmceKeyGenSpec(Variant.MCELIECE_6688128F);
    }

    /**
     * Convenience factory for {@link Variant#MCELIECE_6960119}.
     *
     * @return a new specification for {@link Variant#MCELIECE_6960119}
     */
    public static CmceKeyGenSpec mceliece6960119() {
        return new CmceKeyGenSpec(Variant.MCELIECE_6960119);
    }

    /**
     * Convenience factory for {@link Variant#MCELIECE_6960119F}.
     *
     * @return a new specification for {@link Variant#MCELIECE_6960119F}
     */
    public static CmceKeyGenSpec mceliece6960119f() {
        return new CmceKeyGenSpec(Variant.MCELIECE_6960119F);
    }

    /**
     * Convenience factory for {@link Variant#MCELIECE_8192128}.
     *
     * @return a new specification for {@link Variant#MCELIECE_8192128}
     */
    public static CmceKeyGenSpec mceliece8192128() {
        return new CmceKeyGenSpec(Variant.MCELIECE_8192128);
    }

    /**
     * Convenience factory for {@link Variant#MCELIECE_8192128F}.
     *
     * @return a new specification for {@link Variant#MCELIECE_8192128F}
     */
    public static CmceKeyGenSpec mceliece8192128f() {
        return new CmceKeyGenSpec(Variant.MCELIECE_8192128F);
    }

    /**
     * Returns the selected variant for this specification.
     *
     * @return non-null variant
     */
    public Variant variant() {
        return variant;
    }

    /**
     * Returns a human-readable description of this specification.
     *
     * <p>
     * The value is simply the {@link Variant#toString()} of the selected variant.
     * </p>
     *
     * @return string description of the variant
     */
    @Override
    public String description() {
        return variant.toString();
    }
}
