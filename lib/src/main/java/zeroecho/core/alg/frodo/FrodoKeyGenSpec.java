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
package zeroecho.core.alg.frodo;

import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>Key generation specification for FrodoKEM</h2>
 *
 * {@code FrodoKeyGenSpec} defines the parameters required to generate a
 * FrodoKEM key pair. It encapsulates the choice of Frodo variant, which
 * determines security level, performance, and key sizes.
 *
 * <h2>Variants</h2> Each {@link Variant} corresponds to a standardized FrodoKEM
 * parameter set:
 * <ul>
 * <li>{@link Variant#FRODO_640_AES} - 128-bit security level using AES-based
 * pseudorandomness.</li>
 * <li>{@link Variant#FRODO_640_SHAKE} - 128-bit security level using SHAKE
 * instead of AES.</li>
 * <li>{@link Variant#FRODO_976_AES} - ~192-bit security level with AES-based
 * pseudorandomness.</li>
 * <li>{@link Variant#FRODO_976_SHAKE} - ~192-bit security level with
 * SHAKE.</li>
 * <li>{@link Variant#FRODO_1344_AES} - ~256-bit security level with AES-based
 * pseudorandomness.</li>
 * <li>{@link Variant#FRODO_1344_SHAKE} - ~256-bit security level with
 * SHAKE.</li>
 * </ul>
 *
 * <p>
 * AES-based and SHAKE-based variants differ only in the pseudorandom generator
 * used internally. Security levels are defined against both classical and
 * quantum adversaries under the Learning With Errors (LWE) assumption.
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This class is immutable and therefore safe to share across threads.
 * </p>
 *
 * @since 1.0
 */
public final class FrodoKeyGenSpec implements AlgorithmKeySpec, Describable {
    /**
     * Enumerates the standardized FrodoKEM parameter sets.
     *
     * <p>
     * Each variant fixes matrix dimensions, modulus, and error distribution
     * parameters. They balance security and performance at three target NIST
     * security levels (128, 192, 256 bits).
     * </p>
     */
    public enum Variant {
        /** 128-bit security, AES-based pseudorandomness. */
        FRODO_640_AES,
        /** 128-bit security, SHAKE-based pseudorandomness. */
        FRODO_640_SHAKE,
        /** ~192-bit security, AES-based pseudorandomness. */
        FRODO_976_AES,
        /** ~192-bit security, SHAKE-based pseudorandomness. */
        FRODO_976_SHAKE,
        /** ~256-bit security, AES-based pseudorandomness. */
        FRODO_1344_AES,
        /** ~256-bit security, SHAKE-based pseudorandomness. */
        FRODO_1344_SHAKE
    }

    private final Variant variant;

    private FrodoKeyGenSpec(Variant v) {
        this.variant = v;
    }

    /**
     * Creates a spec from a given variant.
     *
     * @param v Frodo variant to select
     * @return new key generation spec
     */
    public static FrodoKeyGenSpec of(Variant v) {
        return new FrodoKeyGenSpec(v);
    }

    /**
     * Convenience factory for the {@link Variant#FRODO_640_AES} parameter set.
     *
     * @return spec targeting 128-bit security with AES PRG
     */
    public static FrodoKeyGenSpec frodo640aes() {
        return new FrodoKeyGenSpec(Variant.FRODO_640_AES);
    }

    /**
     * Convenience factory for the {@link Variant#FRODO_640_SHAKE} parameter set.
     *
     * @return spec targeting 128-bit security with SHAKE PRG
     */
    public static FrodoKeyGenSpec frodo640shake() {
        return new FrodoKeyGenSpec(Variant.FRODO_640_SHAKE);
    }

    /**
     * Convenience factory for the {@link Variant#FRODO_976_AES} parameter set.
     *
     * @return spec targeting ~192-bit security with AES PRG
     */
    public static FrodoKeyGenSpec frodo976aes() {
        return new FrodoKeyGenSpec(Variant.FRODO_976_AES);
    }

    /**
     * Convenience factory for the {@link Variant#FRODO_976_SHAKE} parameter set.
     *
     * @return spec targeting ~192-bit security with SHAKE PRG
     */
    public static FrodoKeyGenSpec frodo976shake() {
        return new FrodoKeyGenSpec(Variant.FRODO_976_SHAKE);
    }

    /**
     * Convenience factory for the {@link Variant#FRODO_1344_AES} parameter set.
     *
     * @return spec targeting ~256-bit security with AES PRG
     */
    public static FrodoKeyGenSpec frodo1344aes() {
        return new FrodoKeyGenSpec(Variant.FRODO_1344_AES);
    }

    /**
     * Convenience factory for the {@link Variant#FRODO_1344_SHAKE} parameter set.
     *
     * @return spec targeting ~256-bit security with SHAKE PRG
     */
    public static FrodoKeyGenSpec frodo1344shake() {
        return new FrodoKeyGenSpec(Variant.FRODO_1344_SHAKE);
    }

    /**
     * Returns the Frodo variant.
     *
     * @return selected parameter set
     */
    public Variant variant() {
        return variant;
    }

    /**
     * Human-readable description of this spec.
     *
     * <p>
     * The value is simply the {@link Variant#toString()} of the chosen parameter
     * set (e.g., {@code "FRODO_640_AES"}).
     * </p>
     *
     * @return string description of the variant
     */
    @Override
    public String description() {
        return variant.toString();
    }
}
