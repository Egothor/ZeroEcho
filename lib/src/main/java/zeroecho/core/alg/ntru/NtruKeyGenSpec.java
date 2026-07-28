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
package zeroecho.core.alg.ntru;

import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * NtruKeyGenSpec selects an NTRU parameter set for key pair generation.
 *
 * <p>
 * This specification is consumed by the asymmetric key builder registered by
 * {@code NtruAlgorithm}. Each factory method corresponds to a concrete
 * parameter set from the NTRU-HPS or NTRU-HRSS families. Larger parameter sets
 * generally trade bigger keys and ciphertexts for higher security margins.
 * </p>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Choose a parameter set and generate a key pair
 * NtruAlgorithm alg = new NtruAlgorithm();
 * KeyPair kp = alg.asymmetricKeyPairGenerator(NtruKeyGenSpec.class)
 *                 .generateKeyPair(NtruKeyGenSpec.hrss701());
 * }</pre>
 *
 * <p>
 * Instances are immutable and can be safely reused across threads.
 * </p>
 *
 * @since 1.0
 */
public final class NtruKeyGenSpec implements AlgorithmKeySpec, Describable {

    /**
     * Variant enumerates supported NTRU parameter sets for key generation.
     *
     * <p>
     * The constants reflect the naming used by widely adopted implementations: HPS
     * denotes the NTRU-HPS family and HRSS denotes the NTRU-HRSS family. The
     * numeric suffixes indicate core polynomial dimensions and related parameters
     * used internally by the scheme.
     * </p>
     */
    public enum Variant {
        /**
         * NTRU-HPS-2048-509 parameter set.
         */
        HPS2048_509,
        /**
         * NTRU-HPS-2048-677 parameter set.
         */
        HPS2048_677,
        /**
         * NTRU-HPS-4096-821 parameter set.
         */
        HPS4096_821,
        /**
         * NTRU-HPS-4096-1229 parameter set.
         */
        HPS4096_1229,
        /**
         * NTRU-HRSS-701 parameter set. Common practical default when using HRSS.
         */
        HRSS701,
        /**
         * NTRU-HRSS-1373 parameter set.
         */
        HRSS1373
    }

    private final Variant variant;

    private NtruKeyGenSpec(Variant v) {
        this.variant = v;
    }

    /**
     * Returns a spec for the NTRU-HPS-2048-509 parameter set.
     *
     * @return a new key generation spec for HPS-2048-509
     */
    public static NtruKeyGenSpec hps2048_509() {
        return new NtruKeyGenSpec(Variant.HPS2048_509);
    }

    /**
     * Returns a spec for the NTRU-HPS-2048-677 parameter set.
     *
     * @return a new key generation spec for HPS-2048-677
     */
    public static NtruKeyGenSpec hps2048_677() {
        return new NtruKeyGenSpec(Variant.HPS2048_677);
    }

    /**
     * Returns a spec for the NTRU-HPS-4096-821 parameter set.
     *
     * @return a new key generation spec for HPS-4096-821
     */
    public static NtruKeyGenSpec hps4096_821() {
        return new NtruKeyGenSpec(Variant.HPS4096_821);
    }

    /**
     * Returns a spec for the NTRU-HPS-4096-1229 parameter set.
     *
     * @return a new key generation spec for HPS-4096-1229
     */
    public static NtruKeyGenSpec hps4096_1229() {
        return new NtruKeyGenSpec(Variant.HPS4096_1229);
    }

    /**
     * Returns a spec for the NTRU-HRSS-701 parameter set.
     *
     * <p>
     * This is a sensible default in many deployments when an HRSS choice is
     * desired.
     * </p>
     *
     * @return a new key generation spec for HRSS-701
     */
    public static NtruKeyGenSpec hrss701() {
        return new NtruKeyGenSpec(Variant.HRSS701);
    }

    /**
     * Returns a spec for the NTRU-HRSS-1373 parameter set.
     *
     * @return a new key generation spec for HRSS-1373
     */
    public static NtruKeyGenSpec hrss1373() {
        return new NtruKeyGenSpec(Variant.HRSS1373);
    }

    /**
     * Returns the selected NTRU parameter variant.
     *
     * @return the variant represented by this spec
     */
    public Variant variant() {
        return variant;
    }

    /**
     * Returns a short, human-readable description of the selected parameter set.
     *
     * @return the variant name as a string
     */
    @Override
    public String description() {
        return variant.toString();
    }
}
