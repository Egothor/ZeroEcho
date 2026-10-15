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
package zeroecho.pki.application;

import java.util.Objects;

import zeroecho.core.io.CancellationSignal;

/** Narrow application seam for revocations that require authoritative evidence. */
@FunctionalInterface
public interface RevocationEvidenceExecutor {

    /**
     * Executes a revocation and atomically supplies its server-derived evidence.
     * @param operation validated permanent-revocation operation
     * @param evidence authenticated server-derived evidence
     * @param cancellation originating cooperative cancellation signal
     * @return completed, durable-pending, or safely classified outcome
     */
    PkiOperationOutcome executeRevocation(PkiOperation.RevokeCredential operation,
            RevocationExecutionEvidence evidence, CancellationSignal cancellation);

    /**
     * Reports whether both evidence-aware hold transition methods are implemented.
     * Administrative callers must require this capability before consuming an approval.
     * Implementations returning true must override both methods and preserve atomic evidence.
     * @return true when both hold and release are supported; false by default
     */
    default boolean supportsHoldTransitions() { return false; }

    /**
     * Executes a temporary hold with atomically retained server-derived evidence.
     * The default fails closed before any mutation.
     * @param operation validated hold operation
     * @param evidence authenticated server-derived evidence
     * @param cancellation originating cancellation signal
     * @return completed, durable-pending, or safely classified outcome
     */
    default PkiOperationOutcome executeHold(PkiOperation.HoldCredential operation,
            RevocationExecutionEvidence evidence, CancellationSignal cancellation) {
        throw new IllegalStateException("PKI executor does not support hold evidence");
    }

    /**
     * Executes release of an existing hold with atomically retained server-derived evidence.
     * The default fails closed before any mutation; permanent revocation cannot be released.
     * @param operation validated hold-release operation
     * @param evidence authenticated server-derived evidence
     * @param cancellation originating cancellation signal
     * @return completed, durable-pending, or safely classified outcome
     */
    default PkiOperationOutcome executeUnhold(PkiOperation.UnholdCredential operation,
            RevocationExecutionEvidence evidence, CancellationSignal cancellation) {
        throw new IllegalStateException("PKI executor does not support hold-release evidence");
    }

    /**
     * Executes an overdue pending-confirmation revocation with server-derived evidence.
     * @param operation validated pending-confirmation revocation operation
     * @param evidence authenticated server-derived evidence
     * @param cancellation originating cooperative cancellation signal
     * @return completed, durable-pending, or safely classified outcome
     */
    default PkiOperationOutcome executePendingConfirmationRevocation(
            PkiOperation.RevokePendingCredentialConfirmation operation,
            RevocationExecutionEvidence evidence, CancellationSignal cancellation) {
        throw new IllegalStateException(
                "PKI executor does not support pending-confirmation revocation evidence");
    }

    /**
     * Resolves the evidence-aware capability or fails closed.
     * @param executor typed PKI operation executor
     * @return same executor narrowed to the evidence-aware seam
     */
    static RevocationEvidenceExecutor require(PkiOperationExecutor executor) {
        Objects.requireNonNull(executor, "executor");
        if (executor instanceof RevocationEvidenceExecutor supported) {
            return supported;
        }
        throw new IllegalStateException("PKI executor does not support authoritative revocation evidence");
    }
}
