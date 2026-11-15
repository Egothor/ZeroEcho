/* *****************************************************************************
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

import zeroecho.core.io.CancellationSignal;

/**
 * Synchronous transport-neutral executor for the closed PKI operation model.
 *
 * <p>Implementations execute on the caller thread, perform no hidden retry and
 * create no thread or executor. A returned cancellation or failure never implies
 * rollback of an already committed backend transition.</p>
 */
@FunctionalInterface
public interface PkiOperationExecutor {

    /**
     * Freezes omitted operation fences before approval/hash capture without writes.
     * @param operation selected immutable operation
     * @return explicit normalized selection, or unchanged other operation
     */
    default PkiOperation normalize(PkiOperation operation) { return java.util.Objects.requireNonNull(operation, "operation"); }

    /**
     * Activates a root candidate with trusted server-retained execution evidence.
     * Wire actor/approval values must never be used to construct this evidence.
     * The default fails closed; ordinary execute does not substitute for this gate.
     * @param operation exact approved selection and acknowledgment
     * @param evidence deterministic retained request/actor/approval receipt
     * @param cancellation cooperative cancellation
     * @return activation outcome, including explicit unknown-commit recovery classification
     * @throws UnsupportedOperationException if trusted activation is unavailable
     */
    default PkiOperationOutcome executeRootActivation(PkiOperation.SelectIssuancePath operation,
            zeroecho.pki.api.ca.RootTrustAnchorActivation evidence, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("Trusted root activation execution context required");
    }

    /**
     * Observes an exact committed activation receipt without executing or checking today's head.
     * @param operation retained approved selection @param expected exact trusted expected receipt
     * @param cancellation cooperative read cancellation
     * @return original successful result if the exact receipt committed, otherwise empty
     * @throws UnsupportedOperationException if receipt observation is unavailable; not evidence of absence
     * @throws RuntimeException if retained evidence conflicts or cannot be read safely
     */
    default java.util.Optional<PkiOperationResult> observeRootActivation(PkiOperation.SelectIssuancePath operation,
            zeroecho.pki.api.ca.RootTrustAnchorActivation expected, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("Root activation receipt observation unavailable");
    }

    /**
     * Checks current input and state without committing the operation or emitting audit writes.
     * Execution must repeat all checks against its then-current authoritative state.
     * @param operation immutable typed input
     * @param cancellation cooperative cancellation
     * @throws UnsupportedOperationException if a pure validator is unavailable
     * @throws RuntimeException if input or authoritative state is invalid
     */
    default void validate(PkiOperation operation, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("Pure operation validation unavailable");
    }

    /**
     * Executes one typed operation synchronously.
     *
     * @param operation validated typed operation
     * @param cancellation cooperative cancellation signal
     * @return successful result or safely classified failure
     * @throws IllegalStateException if the owning session is closed
     */
    PkiOperationOutcome execute(PkiOperation operation, CancellationSignal cancellation);

    /**
     * Executes one typed operation synchronously, co-committing server-derived issuance evidence into
     * the durable record of issuance-family operations.
     *
     * <p>The evidence is written atomically with the issued credential (see
     * {@code IssuanceExecutionEvidence}); operations that are not issuance-family ignore it. The
     * default drops the evidence for executors that do not co-commit it, preserving compatibility.</p>
     *
     * @param operation validated typed operation
     * @param issuanceEvidence closed issuance-evidence attribute set (may be empty but not null)
     * @param cancellation cooperative cancellation signal
     * @return successful result or safely classified failure
     */
    default PkiOperationOutcome execute(PkiOperation operation,
            zeroecho.pki.api.attr.AttributeSet issuanceEvidence, CancellationSignal cancellation) {
        java.util.Objects.requireNonNull(issuanceEvidence, "issuanceEvidence");
        return execute(operation, cancellation);
    }
}
