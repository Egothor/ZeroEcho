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
package zeroecho.pki.cli;

import java.util.Objects;

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

    /** @return stable operation identity the result belongs to */
    String operation();

    /** Successful operation with its safe structured result view. */
    record Succeeded(String operation, PkiOperationValue.ObjectValue result) implements PkiRemoteResult {
        /** Validates the successful result. */
        public Succeeded {
            requireOperation(operation);
            Objects.requireNonNull(result, "result");
        }
    }

    /**
     * A signing hand-off that had not terminalized when the bounded wait elapsed;
     * the operator resumes it later using {@code operationId}.
     */
    record Pending(String operation, String operationId) implements PkiRemoteResult {
        /** Validates the pending identity. */
        public Pending {
            requireOperation(operation);
            if (operationId == null || operationId.isBlank()) {
                throw new IllegalArgumentException("operationId must not be blank");
            }
        }
    }

    /**
     * The operation requires an out-of-band approval; the caller must obtain an
     * approval identifier for {@code operationCommitment} and re-submit it.
     */
    record ApprovalRequired(String operation, String operationCommitment) implements PkiRemoteResult {
        /** Validates the approval commitment. */
        public ApprovalRequired {
            requireOperation(operation);
            if (operationCommitment == null || operationCommitment.isBlank()) {
                throw new IllegalArgumentException("operationCommitment must not be blank");
            }
        }
    }

    /** A safely-classified server failure carrying the stable classification and code. */
    record Failed(String operation, String classification, String code, boolean recoveryRequired,
            boolean reconciliationRequired) implements PkiRemoteResult {
        /** Validates the failure identity. */
        public Failed {
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
