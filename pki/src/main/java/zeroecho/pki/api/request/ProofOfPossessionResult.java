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
package zeroecho.pki.api.request;

import java.util.Optional;

/**
 * Result of proof-of-possession (PoP) verification.
 *
 * <p>
 * The stable {@link ProofOfPossessionReason} carries the machine-readable outcome;
 * the {@link #status()} is derived from it. The optional {@code details} field is
 * intended for operator diagnostics only, must not contain secrets, and carries no
 * machine semantics — callers must branch on {@link #reason()}, never on the text.
 * </p>
 *
 * @param reason  stable machine-readable verification reason
 * @param details optional non-sensitive diagnostic information
 */
public record ProofOfPossessionResult(ProofOfPossessionReason reason, Optional<String> details) {

    /**
     * Creates a PoP verification result.
     *
     * @param reason  stable verification reason
     * @param details optional diagnostic details (non-sensitive)
     * @throws IllegalArgumentException if {@code reason} or {@code details} is null
     */
    public ProofOfPossessionResult {
        if (reason == null) {
            throw new IllegalArgumentException("reason must not be null");
        }
        if (details == null) {
            throw new IllegalArgumentException("details must not be null");
        }
    }

    /**
     * Creates a result with no diagnostic details.
     *
     * @param reason stable verification reason
     * @return a result carrying only the reason
     */
    public static ProofOfPossessionResult of(ProofOfPossessionReason reason) {
        return new ProofOfPossessionResult(reason, Optional.empty());
    }

    /**
     * Creates a result with non-sensitive diagnostic details.
     *
     * @param reason  stable verification reason
     * @param details non-sensitive operator diagnostic text
     * @return a result carrying the reason and details
     */
    public static ProofOfPossessionResult of(ProofOfPossessionReason reason, String details) {
        return new ProofOfPossessionResult(reason, Optional.of(details));
    }

    /**
     * Returns the verification status implied by this result's reason.
     *
     * @return the derived proof-of-possession status
     */
    public ProofOfPossessionStatus status() {
        return reason.status();
    }
}
