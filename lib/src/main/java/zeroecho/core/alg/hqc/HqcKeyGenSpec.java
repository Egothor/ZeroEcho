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
package zeroecho.core.alg.hqc;

import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>HQC Key Generation Specification</h2>
 *
 * Algorithm-specific {@link zeroecho.core.spec.AlgorithmKeySpec} for generating
 * HQC (Hamming Quasi-Cyclic) key pairs. HQC is a post-quantum key encapsulation
 * mechanism based on error-correcting codes and provides IND-CCA2 security.
 *
 * <p>
 * An {@code HqcKeyGenSpec} selects one of the parameter sets standardized for
 * HQC: 128-, 192-, or 256-bit security. The chosen variant determines key
 * sizes, ciphertext lengths, and shared secret size.
 * </p>
 *
 * <h2>Variants</h2>
 * <ul>
 * <li>{@link Variant#HQC_128} - 128-bit classical / ~64-bit quantum
 * security.</li>
 * <li>{@link Variant#HQC_192} - 192-bit classical / ~96-bit quantum
 * security.</li>
 * <li>{@link Variant#HQC_256} - 256-bit classical / ~128-bit quantum
 * security.</li>
 * </ul>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Create a spec for HQC-256 key generation
 * HqcKeyGenSpec spec = HqcKeyGenSpec.hqc256();
 *
 * // Generate a key pair via HqcAlgorithm
 * HqcAlgorithm hqc = new HqcAlgorithm();
 * KeyPair kp = hqc.asymmetricKeyPairGenerator(HqcKeyGenSpec.class).generateKeyPair(spec);
 * }</pre>
 *
 * @since 1.0
 */
public final class HqcKeyGenSpec implements AlgorithmKeySpec, Describable {
    /**
     * Enumeration of HQC parameter sets.
     *
     * <p>
     * Each variant specifies different code parameters and security levels as
     * defined in the HQC specification.
     * </p>
     */
    public enum Variant {
        /** HQC-128 parameter set (128-bit classical security). */
        HQC_128,
        /** HQC-192 parameter set (192-bit classical security). */
        HQC_192,
        /** HQC-256 parameter set (256-bit classical security). */
        HQC_256
    }

    private final Variant variant;

    private HqcKeyGenSpec(Variant v) {
        this.variant = v;
    }

    /**
     * Creates a specification for the given HQC parameter set.
     *
     * @param v selected variant
     * @return new {@code HqcKeyGenSpec} for the chosen variant
     */
    public static HqcKeyGenSpec of(Variant v) {
        return new HqcKeyGenSpec(v);
    }

    /**
     * Returns a specification for the HQC-128 parameter set.
     *
     * @return spec for HQC-128
     */
    public static HqcKeyGenSpec hqc128() {
        return new HqcKeyGenSpec(Variant.HQC_128);
    }

    /**
     * Returns a specification for the HQC-192 parameter set.
     *
     * @return spec for HQC-192
     */
    public static HqcKeyGenSpec hqc192() {
        return new HqcKeyGenSpec(Variant.HQC_192);
    }

    /**
     * Returns a specification for the HQC-256 parameter set.
     *
     * @return spec for HQC-256
     */
    public static HqcKeyGenSpec hqc256() {
        return new HqcKeyGenSpec(Variant.HQC_256);
    }

    /**
     * Returns the selected HQC variant.
     *
     * @return one of {@link Variant#HQC_128}, {@link Variant#HQC_192},
     *         {@link Variant#HQC_256}
     */
    public Variant variant() {
        return variant;
    }

    /**
     * Returns a textual description of this spec.
     *
     * <p>
     * The description is the {@link Variant#toString()} value, e.g.
     * {@code "HQC_256"}.
     * </p>
     *
     * @return human-readable description of the spec
     */
    @Override
    public String description() {
        return variant.toString();
    }
}
