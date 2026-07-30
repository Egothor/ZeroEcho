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
package zeroecho.sdk;

/**
 * Explicit PBKDF2 work-factor limits for trusted configuration and decoded
 * data.
 *
 * @param operationalMaximum     largest iteration count accepted from trusted
 *                               local configuration
 * @param absoluteDecodedMaximum hard safety ceiling for untrusted decoded data
 * @since 1.0
 */
public record Pbkdf2Limits(int operationalMaximum, int absoluteDecodedMaximum) {
    /** Mandatory minimum PBKDF2 iteration count. */
    public static final int MINIMUM = 10_000;

    /**
     * Validates {@code minimum <= operationalMaximum <= absoluteDecodedMaximum}.
     *
     * @throws IllegalArgumentException if the limits violate the ordering
     */
    public Pbkdf2Limits {
        if (operationalMaximum < MINIMUM) {
            throw new IllegalArgumentException("operationalMaximum must be at least " + MINIMUM);
        }
        if (absoluteDecodedMaximum < operationalMaximum) {
            throw new IllegalArgumentException("absoluteDecodedMaximum must be at least operationalMaximum");
        }
    }

    /**
     * Validates trusted local configuration.
     *
     * @param iterations requested iteration count
     * @throws IllegalArgumentException if outside the operational range
     */
    public void validateTrusted(int iterations) {
        if (iterations < MINIMUM || iterations > operationalMaximum) {
            throw new IllegalArgumentException(
                    "PBKDF2 iterations must be in range " + MINIMUM + ".." + operationalMaximum + ": " + iterations);
        }
    }

    /**
     * Validates an untrusted decoded iteration count before KDF execution.
     *
     * @param iterations decoded iteration count
     * @throws IllegalArgumentException if outside the absolute safety range
     */
    public void validateDecoded(int iterations) {
        if (iterations < MINIMUM || iterations > absoluteDecodedMaximum) {
            throw new IllegalArgumentException("Decoded PBKDF2 iterations must be in range " + MINIMUM + ".."
                    + absoluteDecodedMaximum + ": " + iterations);
        }
        if (iterations > operationalMaximum) {
            throw new IllegalArgumentException("Decoded PBKDF2 iterations exceed the session policy maximum "
                    + operationalMaximum + ": " + iterations);
        }
    }
}
