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
package zeroecho.pki.cli;

import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.application.PkiOperationValue;

/**
 * Closed terminal (or bounded-wait-exhausted) outcome of one remote admin-API
 * operation exchange.
 *
 * <p>This model is intentionally richer than the local
 * {@code PkiOperationOutcome}: it carries the {@code APPROVAL_REQUIRED} outcome
 * with its operation commitment and the pending signing-operation identifier,
 * neither of which the closed local outcome model expresses.</p>
 */
sealed interface PkiRemoteResult permits PkiRemoteResult.Succeeded, PkiRemoteResult.Pending,
        PkiRemoteResult.ApprovalRequired, PkiRemoteResult.Failed {

    /**
     * Returns the requested semantic operation associated with this local result.
     *
     * @return stable nonblank requested operation identity
     */
    String operation();

    /**
     * Successful operation with the decoded structured result and optional durable identity.
     *
     * <p>Construction does not revalidate HTTP status, completion fields or remote
     * authenticity; the transport validates its envelope before creating this value.</p>
     *
     * @param operation requested nonblank semantic operation
     * @param result immutable decoded result fields, retained without rebuilding
     * @param operationId optional durable operation identity; present text is not validated here
     */
    record Succeeded(String operation, PkiOperationValue.ObjectValue result, Optional<String> operationId) implements PkiRemoteResult {
        /**
         * Requires a nonblank operation and non-null structured result/identity container.
         *
         * @param operation requested semantic operation
         * @param result immutable structured result
         * @param operationId optional durable identity
         * @throws NullPointerException if the result or identity container is null
         * @throws IllegalArgumentException if the operation is null or blank
         */
        public Succeeded {
            requireOperation(operation);
            Objects.requireNonNull(result, "result");
            Objects.requireNonNull(operationId, "operationId");
        }
    }

    /**
     * A signing hand-off that had not terminalized when the bounded wait elapsed;
     * the operator resumes it later using {@code operationId}.
     *
     * @param operation requested nonblank semantic operation
     * @param operationId nonblank identity of the already submitted operation
     * @param observationFailure optional local observation failure; it does not replace backend state
     */
    record Pending(String operation, String operationId, Optional<ObservationFailure> observationFailure) implements PkiRemoteResult {
        /**
         * Retains a pending identity without polling, resubmitting or mutating the remote operation.
         *
         * @param operation requested semantic operation
         * @param operationId already submitted operation identity
         * @param observationFailure optional local observation failure
         * @throws NullPointerException if the observation-failure container is null
         * @throws IllegalArgumentException if the operation or identifier is null or blank
         */
        public Pending {
            requireOperation(operation);
            Objects.requireNonNull(observationFailure, "observationFailure");
            if (operationId == null || operationId.isBlank()) {
                throw new IllegalArgumentException("operationId must not be blank");
            }
        }
    }

    /**
     * Local observation failure attached to an operation that remains pending.
     *
     * <p>The transport supplies finite safe classification/code values. The implicit
     * constructor does not validate those strings or constrain the exit code; this
     * carrier does not establish a terminal backend failure.</p>
     *
     * @param classification local observation classification, retained as supplied
     * @param code local observation detail, retained as supplied
     * @param exitCode CLI exit status selected by the transport
     */
    record ObservationFailure(String classification, String code, int exitCode) { }

    /**
     * The operation requires an out-of-band approval; the caller must obtain an
     * approval identifier for {@code operationCommitment} and re-submit it.
     *
     * @param operation requested nonblank semantic operation
     * @param operationCommitment nonblank immutable operation commitment to be approved
     */
    record ApprovalRequired(String operation, String operationCommitment) implements PkiRemoteResult {
        /**
         * Requires nonblank operation and commitment text without granting approval.
         *
         * <p>The transport checks the expected hexadecimal commitment format before
         * construction; this constructor does not repeat that syntax check.</p>
         *
         * @param operation requested semantic operation
         * @param operationCommitment commitment requiring an external approval decision
         * @throws IllegalArgumentException if either text value is null or blank
         */
        public ApprovalRequired {
            requireOperation(operation);
            if (operationCommitment == null || operationCommitment.isBlank()) {
                throw new IllegalArgumentException("operationCommitment must not be blank");
            }
        }
    }

    /**
     * Classified failure with explicit recovery/reconciliation flags and optional durable identity.
     *
     * <p>Construction checks nonblank text, not membership in a trusted finite error
     * vocabulary. It does not perform recovery or reconcile an unknown remote outcome.</p>
     *
     * @param operation requested nonblank semantic operation
     * @param classification nonblank failure classification
     * @param code nonblank failure detail code
     * @param recoveryRequired whether the reported outcome requires recovery handling
     * @param reconciliationRequired whether the reported outcome requires reconciliation
     * @param operationId optional retained durable operation identity; present text is not validated here
     */
    record Failed(String operation, String classification, String code, boolean recoveryRequired,
            boolean reconciliationRequired, Optional<String> operationId) implements PkiRemoteResult {
        /**
         * Creates a classified failure without a durable operation identity.
         *
         * @param operation requested semantic operation
         * @param classification nonblank failure classification
         * @param code nonblank failure detail code
         * @param recoveryRequired reported recovery requirement
         * @param reconciliationRequired reported reconciliation requirement
         * @throws IllegalArgumentException if the operation, classification or code is null or blank
         */
        public Failed(String operation, String classification, String code, boolean recoveryRequired,
                boolean reconciliationRequired) {
            this(operation, classification, code, recoveryRequired, reconciliationRequired, Optional.empty());
        }

        /**
         * Checks failure text and the optional identity container without acting on the flags.
         *
         * @param operation requested semantic operation
         * @param classification nonblank failure classification
         * @param code nonblank failure detail code
         * @param recoveryRequired reported recovery requirement
         * @param reconciliationRequired reported reconciliation requirement
         * @param operationId optional durable operation identity
         * @throws NullPointerException if the identity container is null
         * @throws IllegalArgumentException if the operation, classification or code is null or blank
         */
        public Failed {
            Objects.requireNonNull(operationId, "operationId");
            requireOperation(operation);
            if (classification == null || classification.isBlank()) {
                throw new IllegalArgumentException("classification must not be blank");
            }
            if (code == null || code.isBlank()) {
                throw new IllegalArgumentException("code must not be blank");
            }
        }
    }

    private static void requireOperation(String operation) {
        if (operation == null || operation.isBlank()) {
            throw new IllegalArgumentException("operation must not be blank");
        }
    }
}
