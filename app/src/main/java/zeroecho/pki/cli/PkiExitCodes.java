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

import zeroecho.pki.application.PkiOperationFailure;

/** Stable process exit-code mapping for the PKI command family. */
final class PkiExitCodes {

    /* default */ static final int SUCCESS = 0;
    /* default */ static final int INVALID_INVOCATION = 2;
    /* default */ static final int CONFIGURATION_FAILURE = 3;
    /* default */ static final int VALIDATION_OR_POLICY = 4;
    /* default */ static final int NOT_FOUND_OR_CONFLICT = 5;
    /* default */ static final int RECOVERY_REQUIRED = 6;
    /* default */ static final int EXTERNAL_OUTCOME_UNKNOWN = 7;
    /* default */ static final int RESOURCE_FAILURE = 8;
    /* default */ static final int INTERNAL_FAILURE = 9;
    /* default */ static final int CANCELLED = 130;

    private PkiExitCodes() {
    }

    /* default */ static int from(PkiPlanExecution execution) {
        int result = execution.planFailure().map(PkiExitCodes::from).orElse(SUCCESS);
        for (PkiPlanExecution.StepResult step : execution.steps()) {
            if (step.failure().isPresent()) {
                result = Math.max(result, from(step.failure().orElseThrow()));
            }
        }
        return result == SUCCESS && !execution.succeeded() ? VALIDATION_OR_POLICY : result;
    }

    private static int from(PkiOperationFailure failure) {
        return switch (failure) {
            case VALIDATION_FAILURE, POLICY_REJECTION -> VALIDATION_OR_POLICY;
            case NOT_FOUND, CONFLICT -> NOT_FOUND_OR_CONFLICT;
            case RECOVERY_REQUIRED -> RECOVERY_REQUIRED;
            case EXTERNAL_OUTCOME_UNKNOWN -> EXTERNAL_OUTCOME_UNKNOWN;
            case RESOURCE_FAILURE, OVERLOADED -> RESOURCE_FAILURE;
            case INTERNAL_FAILURE -> INTERNAL_FAILURE;
            case CANCELLED -> CANCELLED;
        };
    }
}
