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
package zeroecho.core.alg.bike;

import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>Specification for BIKE key generation</h2>
 *
 * Defines algorithm parameters for generating BIKE key pairs. Encapsulates a
 * chosen {@link Variant} (BIKE-128, BIKE-192, BIKE-256).
 *
 * <h3>Usage</h3> <pre>{@code
 * // Generate a BIKE-192 key pair
 * KeyPair kp = bikeAlgorithm.asymmetricKeyPairGenerator(BikeKeyGenSpec.class)
 *                           .generateKeyPair(BikeKeyGenSpec.bike192());
 * }</pre>
 *
 * @since 1.0
 */
public final class BikeKeyGenSpec implements AlgorithmKeySpec, Describable {
    /**
     * Available BIKE parameter sets.
     */
    public enum Variant {
        /** BIKE with 128-bit security strength. */
        BIKE_128,
        /** BIKE with 192-bit security strength. */
        BIKE_192,
        /** BIKE with 256-bit security strength. */
        BIKE_256
    }

    private final Variant variant;

    private BikeKeyGenSpec(Variant v) {
        this.variant = v;
    }

    /**
     * Creates a new specification for the given BIKE variant.
     *
     * @param v variant to use
     * @return a new key generation spec
     */
    public static BikeKeyGenSpec of(Variant v) {
        return new BikeKeyGenSpec(v);
    }

    /**
     * Returns a specification for BIKE-128.
     *
     * @return BIKE-128 key generation spec
     */
    public static BikeKeyGenSpec bike128() {
        return new BikeKeyGenSpec(Variant.BIKE_128);
    }

    /**
     * Returns a specification for BIKE-192.
     *
     * @return BIKE-192 key generation spec
     */
    public static BikeKeyGenSpec bike192() {
        return new BikeKeyGenSpec(Variant.BIKE_192);
    }

    /**
     * Returns a specification for BIKE-256.
     *
     * @return BIKE-256 key generation spec
     */
    public static BikeKeyGenSpec bike256() {
        return new BikeKeyGenSpec(Variant.BIKE_256);
    }

    /**
     * Returns the BIKE variant.
     *
     * @return configured variant
     */
    public Variant variant() {
        return variant;
    }

    /**
     * Returns a human-readable description of this spec.
     *
     * <p>
     * Implements {@link Describable} by returning the variant name.
     * </p>
     *
     * @return description string
     */
    @Override
    public String description() {
        return variant.toString();
    }
}
