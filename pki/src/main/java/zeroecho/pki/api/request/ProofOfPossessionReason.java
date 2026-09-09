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

import java.util.Objects;

/**
 * Closed set of stable, machine-readable proof-of-possession (PoP) verification
 * reason codes.
 *
 * <p>
 * Every verifier implementation reports the same reason for the same condition, so
 * callers branch on this typed value instead of parsing free-form diagnostic text.
 * Each reason declares exactly one {@link ProofOfPossessionStatus}; the optional
 * explanatory {@code details} on a {@link ProofOfPossessionResult} remains for
 * operator diagnostics only and carries no machine semantics.
 * </p>
 */
public enum ProofOfPossessionReason {

    /** Proof-of-possession evidence was successfully verified. */
    VERIFIED(ProofOfPossessionStatus.VERIFIED),

    /** No proof-of-possession evidence was present (acceptable only if policy allows). */
    NOT_PRESENT(ProofOfPossessionStatus.NOT_PRESENT),

    /** The certification-request payload required for verification was missing. */
    CSR_PAYLOAD_MISSING(ProofOfPossessionStatus.FAILED),

    /** The certification request could not be parsed or is structurally invalid. */
    CSR_MALFORMED(ProofOfPossessionStatus.FAILED),

    /** The proof-of-possession signature was present but did not verify. */
    SIGNATURE_INVALID(ProofOfPossessionStatus.FAILED),

    /** The request's algorithm is not supported for proof-of-possession verification. */
    UNSUPPORTED_ALGORITHM(ProofOfPossessionStatus.NOT_SUPPORTED),

    /** The verification operation did not reach a terminal outcome. */
    OPERATION_INCOMPLETE(ProofOfPossessionStatus.FAILED),

    /** The verification provider was unavailable or returned no usable status. */
    PROVIDER_UNAVAILABLE(ProofOfPossessionStatus.FAILED),

    /** Verification failed for an internal or otherwise unclassified reason. */
    INTERNAL_FAILURE(ProofOfPossessionStatus.FAILED);

    private final ProofOfPossessionStatus status;

    ProofOfPossessionReason(ProofOfPossessionStatus status) {
        this.status = Objects.requireNonNull(status, "status");
    }

    /**
     * Returns the single verification status that corresponds to this reason.
     *
     * @return proof-of-possession status
     */
    public ProofOfPossessionStatus status() {
        return status;
    }
}
