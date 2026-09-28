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

package zeroecho.pki.api.signing;

import java.util.Objects;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.store.SignWorkflowStore.AcceptanceCommitment;

/** Immutable redacted receipt for resolving a possibly uncertain acceptance. */
public final class SigningAcceptanceReceipt {
    private final PkiId operationId;
    private final AcceptanceCommitment commitment;

    private SigningAcceptanceReceipt(PkiId operationId, AcceptanceCommitment commitment) {
        this.operationId = Objects.requireNonNull(operationId, "operationId");
        this.commitment = Objects.requireNonNull(commitment, "commitment");
    }

    /**
     * Restores a receipt from its exact operation and canonical commitment.
     *
     * @param operationId durable operation identity
     * @param encodedCommitment canonical acceptance commitment
     * @return immutable recovery receipt
     */
    public static SigningAcceptanceReceipt parse(PkiId operationId, String encodedCommitment) {
        return new SigningAcceptanceReceipt(operationId,
                AcceptanceCommitment.parse(encodedCommitment));
    }

    /**
     * Returns the durable operation identity.
     *
     * @return durable operation identity
     */
    public PkiId operationId() { return operationId; }
    /**
     * Returns the canonical acceptance commitment.
     *
     * @return canonical acceptance commitment
     */
    public String encodedCommitment() { return commitment.encoded(); }

    @Override public boolean equals(Object other) {
        if (!(other instanceof SigningAcceptanceReceipt receipt)) {
            return false;
        }
        boolean sameOperation = operationId.equals(receipt.operationId);
        boolean sameCommitment = commitment.matches(receipt.commitment);
        return sameOperation & sameCommitment;
    }

    @Override public int hashCode() {
        return 31 * operationId.hashCode() + commitment.hashCode();
    }

    @Override public String toString() { return "SigningAcceptanceReceipt[redacted]"; }
}
