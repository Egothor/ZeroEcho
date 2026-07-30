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
package zeroecho.pki.api;

import java.time.Instant;

/**
 * Validity interval for an issued credential.
 *
 * <p>
 * The PKI core requires {@code notAfter} to be strictly after
 * {@code notBefore}. Framework-specific interpretations (inclusive/exclusive)
 * are resolved by the framework backend.
 * </p>
 *
 * <p>
 * Policy and profile constraints (maximum lifetime, not-before skew) must be
 * enforced by the PKI runtime.
 * </p>
 *
 * @param notBefore start of validity interval (inclusive)
 * @param notAfter  end of validity interval (must be after {@code notBefore})
 */
public record Validity(Instant notBefore, Instant notAfter) {

    /**
     * Creates a validity interval.
     *
     * @param notBefore start of validity interval (inclusive)
     * @param notAfter  end of validity interval
     * @throws IllegalArgumentException if inputs are null or the interval is
     *                                  invalid
     */
    public Validity {
        if (notBefore == null || notAfter == null) {
            throw new IllegalArgumentException("notBefore/notAfter must not be null");
        }
        if (!notAfter.isAfter(notBefore)) {
            throw new IllegalArgumentException("notAfter must be after notBefore");
        }
    }
}
