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
package zeroecho.core.alg.ntruprime;

import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Algorithm-specific key generation parameters for SNTRU Prime.
 *
 * <p>
 * {@code SntruPrimeKeyGenSpec} selects one of the standardized parameter
 * variants of the SNTRU Prime key encapsulation mechanism. Each variant
 * determines the security level, key sizes, and performance characteristics of
 * the generated key pair.
 * </p>
 *
 * <h2>Variants</h2>
 * <ul>
 * <li>{@link Variant#SNTRUP653}: ~128-bit classical security.</li>
 * <li>{@link Variant#SNTRUP761}: ~192-bit security.</li>
 * <li>{@link Variant#SNTRUP857}: ~256-bit security.</li>
 * <li>{@link Variant#SNTRUP953}, {@link Variant#SNTRUP1013},
 * {@link Variant#SNTRUP1277}: larger sets providing higher security margins
 * with larger keys and ciphertexts.</li>
 * </ul>
 *
 * <p>
 * Instances are immutable and passed to
 * {@link zeroecho.sdk.KeyBuilders.Asymmetric#generateKeyPair(String, AlgorithmKeySpec)}.
 * Static factory methods are provided for each variant.
 * </p>
 *
 * <h2>Example</h2> <pre>{@code
 * KeyPair kp = session.keyBuilders().asymmetric()
 *         .generateKeyPair("SNTRUPrime", SntruPrimeKeyGenSpec.sntrup761());
 * }</pre>
 *
 * @since 1.0
 */
public final class SntruPrimeKeyGenSpec implements AlgorithmKeySpec, Describable {
    /**
     * Enumeration of supported SNTRU Prime parameter sets.
     */
    public enum Variant {
        /** Variant with ~128-bit classical security. */
        SNTRUP653,
        /** Variant with ~192-bit classical security. */
        SNTRUP761,
        /** Variant with ~256-bit classical security. */
        SNTRUP857,
        /** Variant beyond 256-bit with larger parameters. */
        SNTRUP953,
        /** Variant beyond 256-bit with even larger parameters. */
        SNTRUP1013,
        /** Largest standardized variant, with very high security margins. */
        SNTRUP1277
    }

    private final Variant variant;

    private SntruPrimeKeyGenSpec(Variant v) {
        this.variant = v;
    }

    /**
     * Creates a specification from the given variant.
     *
     * @param v selected SNTRU Prime parameter set
     * @return new specification bound to {@code v}
     * @throws NullPointerException if {@code v} is {@code null}
     */
    public static SntruPrimeKeyGenSpec of(Variant v) {
        return new SntruPrimeKeyGenSpec(v);
    }

    /**
     * Creates a key generation specification for the {@link Variant#SNTRUP653}
     * parameter set.
     *
     * @return a new specification targeting {@code SNTRUP653}
     */
    public static SntruPrimeKeyGenSpec sntrup653() {
        return new SntruPrimeKeyGenSpec(Variant.SNTRUP653);
    }

    /**
     * Creates a key generation specification for the {@link Variant#SNTRUP761}
     * parameter set.
     *
     * @return a new specification targeting {@code SNTRUP761}
     */
    public static SntruPrimeKeyGenSpec sntrup761() {
        return new SntruPrimeKeyGenSpec(Variant.SNTRUP761);
    }

    /**
     * Creates a key generation specification for the {@link Variant#SNTRUP857}
     * parameter set.
     *
     * @return a new specification targeting {@code SNTRUP857}
     */
    public static SntruPrimeKeyGenSpec sntrup857() {
        return new SntruPrimeKeyGenSpec(Variant.SNTRUP857);
    }

    /**
     * Creates a key generation specification for the {@link Variant#SNTRUP953}
     * parameter set.
     *
     * @return a new specification targeting {@code SNTRUP953}
     */
    public static SntruPrimeKeyGenSpec sntrup953() {
        return new SntruPrimeKeyGenSpec(Variant.SNTRUP953);
    }

    /**
     * Creates a key generation specification for the {@link Variant#SNTRUP1013}
     * parameter set.
     *
     * @return a new specification targeting {@code SNTRUP1013}
     */
    public static SntruPrimeKeyGenSpec sntrup1013() {
        {
            return new SntruPrimeKeyGenSpec(Variant.SNTRUP1013);
        }
    }

    /**
     * Creates a key generation specification for the {@link Variant#SNTRUP1277}
     * parameter set.
     *
     * @return a new specification targeting {@code SNTRUP1277}
     */
    public static SntruPrimeKeyGenSpec sntrup1277() {
        {
            return new SntruPrimeKeyGenSpec(Variant.SNTRUP1277);
        }
    }

    /**
     * Returns the selected variant for this specification.
     *
     * @return variant of SNTRU Prime key parameters
     */
    public Variant variant() {
        return variant;
    }

    /**
     * Returns a textual description of this specification.
     *
     * <p>
     * The description is the variant name (e.g., {@code "SNTRUP761"}).
     * </p>
     *
     * @return variant name string
     */
    @Override
    public String description() {
        return variant.toString();
    }
}
