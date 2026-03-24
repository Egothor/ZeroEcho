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
package zeroecho.core.alg.elgamal;

import java.util.Objects;

import zeroecho.core.annotation.Describable;
import zeroecho.core.annotation.DisplayName;
import zeroecho.core.spec.ContextSpec;

/**
 * <h2>ElGamal Encryption Parameters</h2>
 *
 * Specification for configuring ElGamal encryption contexts.
 *
 * <p>
 * {@code ElgamalEncSpec} selects the padding mode to apply when transforming
 * plaintext into group elements for ElGamal encryption. This affects both
 * security properties and maximum plaintext block size.
 * </p>
 *
 * <p>
 * <b>Note:</b> OAEP is not offered for ElGamal; for modern IND-CCA security
 * prefer KEM or KEM-DEM constructions such as DHIES, ECIES, or Cramer-Shoup, or
 * use a KEM provided elsewhere in the catalog.
 * </p>
 *
 * <h2>Padding modes</h2>
 * <ul>
 * <li>{@link Padding#NOPADDING} - raw ElGamal encryption of messages less than
 * the modulus {@code p}. Provides minimal security (plaintexts are only
 * randomized by ephemeral exponent) and must not be used directly in modern
 * protocols without additional safeguards (e.g., hybrid encryption or KEM
 * construction).</li>
 * <li>{@link Padding#PKCS1} - PKCS#1 v1.5-style padding applied to the
 * plaintext before encryption. Adds structural redundancy and prevents trivial
 * small-subgroup attacks. Still considered outdated for new protocols but
 * available for compatibility.</li>
 * </ul>
 *
 * <h2>Usage</h2> Instances are created via the static factories: <pre>{@code
 * ElgamalEncSpec spec = ElgamalEncSpec.pkcs1();
 * EncryptionContext ctx = algo.create(KeyUsage.ENCRYPT, pubKey, spec);
 * }</pre>
 *
 * <h2>Thread-safety</h2> {@code ElgamalEncSpec} is immutable and safe to share
 * across threads.
 *
 * @since 1.0
 */
@DisplayName("ElGamal encryption parameters")
public final class ElgamalEncSpec implements ContextSpec, Describable {
    /**
     * Supported padding modes for ElGamal encryption.
     */
    public enum Padding {
        /**
         * No padding applied.
         *
         * <p>
         * Plaintext must be strictly less than modulus {@code p}. Provides only
         * semantic security under chosen-plaintext attack if used in combination with
         * fresh random exponents. Not recommended for use outside compatibility
         * scenarios.
         * </p>
         */
        NOPADDING,
        /**
         * PKCS#1 v1.5-style padding.
         *
         * <p>
         * Adds structured redundancy to plaintext before encryption. Historically used
         * in RSA and adapted here for ElGamal. Provides limited protection against
         * certain classes of attacks but should be replaced by modern OAEP-style
         * constructions where available.
         * </p>
         */
        PKCS1
    }

    private final Padding padding;

    private ElgamalEncSpec(Padding padding) {
        this.padding = Objects.requireNonNull(padding, "padding");
    }

    /**
     * Returns an {@code ElgamalEncSpec} with no padding.
     *
     * @return specification with {@link Padding#NOPADDING}
     */
    public static ElgamalEncSpec noPadding() {
        return new ElgamalEncSpec(Padding.NOPADDING);
    }

    /**
     * Returns an {@code ElgamalEncSpec} with PKCS#1 v1.5-style padding.
     *
     * @return specification with {@link Padding#PKCS1}
     */
    public static ElgamalEncSpec pkcs1() {
        return new ElgamalEncSpec(Padding.PKCS1);
    }

    /**
     * Returns the selected padding mode.
     *
     * @return padding enumeration value
     */
    public Padding padding() {
        return padding;
    }

    /**
     * Human-readable description of this spec.
     *
     * <p>
     * Matches the transformation string used by the JCA provider (e.g.,
     * {@code "NOPADDING"} or {@code "PKCS1Padding"}).
     * </p>
     *
     * @return descriptive string for this padding mode
     */
    @Override
    public String description() {
        return (padding == Padding.NOPADDING) ? "NOPADDING" : "PKCS1Padding";
    }
}
