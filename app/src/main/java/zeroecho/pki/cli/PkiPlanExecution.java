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

import java.util.List;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.application.PkiOperationFailure;
import zeroecho.pki.application.PkiOperationResult;

/** Ordered complete result of one single-command or batch plan execution. */
record PkiPlanExecution(List<StepResult> steps, Optional<PkiOperationFailure> planFailure, Optional<String> planCode) {

    /* default */ PkiPlanExecution {
        steps = List.copyOf(steps);
        Objects.requireNonNull(planFailure, "planFailure");
        Objects.requireNonNull(planCode, "planCode");
        if (steps.isEmpty()) {
            throw new IllegalArgumentException("execution requires at least one step");
        }
        if (planFailure.isPresent() != planCode.isPresent()) {
            throw new IllegalArgumentException("plan failure state is inconsistent");
        }
    }

    /* default */ PkiPlanExecution(List<StepResult> steps) {
        this(steps, Optional.empty(), Optional.empty());
    }

    /* default */ boolean succeeded() {
        return planFailure.isEmpty() && steps.stream().allMatch(step -> step.status() == StepStatus.SUCCEEDED);
    }

    /* default */ PkiPlanExecution withPlanFailure(PkiOperationFailure failure, String code) {
        return new PkiPlanExecution(steps, Optional.of(failure), Optional.of(code));
    }

    /** Step completion state. */
    /* default */ enum StepStatus {
        SUCCEEDED,
        FAILED,
        SKIPPED
    }

    /** One safe ordered step result. */
    /* default */ record StepResult(String id, String operation, StepStatus status,
            Optional<PkiOperationResult> output,
            Optional<PkiOperationFailure> failure, Optional<String> code, Optional<zeroecho.pki.api.PkiId> operationId) {
        StepResult {
            if (id == null || id.isBlank() || operation == null || operation.isBlank()) {
                throw new IllegalArgumentException("step result identity is invalid");
            }
            Objects.requireNonNull(status, "status");
            Objects.requireNonNull(output, "output");
            Objects.requireNonNull(failure, "failure");
            Objects.requireNonNull(code, "code");
            Objects.requireNonNull(operationId, "operationId");
            boolean valid = switch (status) {
                case SUCCEEDED -> output.isPresent() && failure.isEmpty() && code.isEmpty();
                case FAILED -> output.isEmpty() && failure.isPresent() && code.isPresent();
                case SKIPPED -> output.isEmpty() && failure.isEmpty() && code.isPresent();
            };
            if (!valid) {
                throw new IllegalArgumentException("step result state is inconsistent");
            }
        }

        /* default */ StepResult(String id, String operation, StepStatus status, Optional<PkiOperationResult> output,
                Optional<PkiOperationFailure> failure, Optional<String> code) {
            this(id, operation, status, output, failure, code, Optional.empty());
        }

        /* default */ StepResult withOperationId(zeroecho.pki.api.PkiId identity) {
            return new StepResult(id, operation, status, output, failure, code, Optional.of(identity));
        }

        /* default */ static StepResult success(String id, String operation, PkiOperationResult result) {
            return new StepResult(id, operation, StepStatus.SUCCEEDED, Optional.of(result), Optional.empty(),
                    Optional.empty());
        }

        /* default */ static StepResult failure(String id, String operation, PkiOperationFailure failure,
                String code) {
            return new StepResult(id, operation, StepStatus.FAILED, Optional.empty(), Optional.of(failure),
                    Optional.of(code));
        }

        /* default */ static StepResult skipped(String id, String operation, String code) {
            return new StepResult(id, operation, StepStatus.SKIPPED, Optional.empty(), Optional.empty(),
                    Optional.of(code));
        }
    }
}
