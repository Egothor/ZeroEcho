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

/**
 * Immutable ordered snapshot of a single-command or batch plan execution.
 *
 * @param steps nonempty ordered results, copied into an unmodifiable list
 * @param planFailure optional plan-level failure classification
 * @param planCode optional plan-level detail, present exactly with planFailure
 */
record PkiPlanExecution(List<StepResult> steps, Optional<PkiOperationFailure> planFailure, Optional<String> planCode) {

    /**
     * Snapshots the result list and checks nonempty/paired plan-failure structure.
     *
     * @param steps nonempty ordered result list
     * @param planFailure optional plan failure
     * @param planCode paired optional plan detail
     * @throws NullPointerException if a list, list element or optional container is null
     * @throws IllegalArgumentException if results are empty or plan failure/detail presence differs
     */
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

    /**
     * Creates a result with no separate plan-level failure.
     *
     * @param steps nonempty ordered result list
     * @throws NullPointerException if the list or an element is null
     * @throws IllegalArgumentException if the list is empty
     */
    /* default */ PkiPlanExecution(List<StepResult> steps) {
        this(steps, Optional.empty(), Optional.empty());
    }

    /**
     * Reports success only when every step succeeded and no plan failure is retained.
     *
     * @return true for a completely successful result snapshot
     */
    /* default */ boolean succeeded() {
        return planFailure.isEmpty() && steps.stream().allMatch(step -> step.status() == StepStatus.SUCCEEDED);
    }

    /**
     * Returns a new snapshot retaining the same steps and replacing plan-level failure evidence.
     *
     * @param failure required classification
     * @param code required detail text, retained without text validation
     * @return new immutable execution snapshot
     * @throws NullPointerException if either new failure coordinate is null
     */
    /* default */ PkiPlanExecution withPlanFailure(PkiOperationFailure failure, String code) {
        return new PkiPlanExecution(steps, Optional.of(failure), Optional.of(code));
    }

    /**
     * Step completion state.
     */
    /* default */ enum StepStatus {
        /**
         * The operation completed and its output is available to later step references.
         */
        SUCCEEDED,
        /**
         * The operation failed; the plan failure policy determines whether later independent steps run.
         */
        FAILED,
        /**
         * The operation was not submitted because cancellation, failure policy, or dependencies prevented it.
         */
        SKIPPED
    }

    /**
     * Ordered step result with mutually consistent output/failure/status presence.
     *
     * <p>The constructor checks local shape without establishing remote authenticity
     * or durable completion. Retained immutable output values are not revalidated.</p>
     *
     * @param id nonblank step identity
     * @param operation nonblank semantic operation name
     * @param status completion classification
     * @param output present exactly for success
     * @param failure present exactly for failure
     * @param code absent for success, present for failure or skipped work
     * @param operationId optional durable operation identity
     */
    /* default */ record StepResult(String id, String operation, StepStatus status,
            Optional<PkiOperationResult> output,
            Optional<PkiOperationFailure> failure, Optional<String> code, Optional<zeroecho.pki.api.PkiId> operationId) {
        /**
         * Checks identity text and status/output/failure/detail presence.
         *
         * @param id nonblank step identity
         * @param operation nonblank semantic operation
         * @param status completion classification
         * @param output optional immutable output
         * @param failure optional failure classification
         * @param code optional detail text
         * @param operationId optional durable operation identity
         * @throws NullPointerException if status or an optional container is null
         * @throws IllegalArgumentException if identity text is null/blank or status fields disagree
         */
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

        /**
         * Creates a checked step result without a durable operation identity.
         *
         * @param id nonblank step identity
         * @param operation nonblank semantic operation
         * @param status completion classification
         * @param output optional immutable output
         * @param failure optional failure classification
         * @param code optional detail text
         * @throws NullPointerException if status or an optional container is null
         * @throws IllegalArgumentException if identity text or status field presence is invalid
         */
        /* default */ StepResult(String id, String operation, StepStatus status, Optional<PkiOperationResult> output,
                Optional<PkiOperationFailure> failure, Optional<String> code) {
            this(id, operation, status, output, failure, code, Optional.empty());
        }

        /**
         * Returns a new result retaining the same outcome with the supplied durable identity.
         *
         * @param identity required durable operation identity
         * @return new immutable step result
         * @throws NullPointerException if the identity is null
         */
        /* default */ StepResult withOperationId(zeroecho.pki.api.PkiId identity) {
            return new StepResult(id, operation, status, output, failure, code, Optional.of(identity));
        }

        /**
         * Constructs a success step result without a durable operation identity.
         *
         * @param id nonblank step identity
         * @param operation nonblank semantic operation
         * @param result required immutable output
         * @return new checked immutable step result
         * @throws NullPointerException if the result is null
         * @throws IllegalArgumentException if identity text is null or blank
         */
        /* default */ static StepResult success(String id, String operation, PkiOperationResult result) {
            return new StepResult(id, operation, StepStatus.SUCCEEDED, Optional.of(result), Optional.empty(),
                    Optional.empty());
        }

        /**
         * Constructs a failure step result without a durable operation identity.
         *
         * @param id nonblank step identity
         * @param operation nonblank semantic operation
         * @param failure required failure classification
         * @param code required detail text
         * @return new checked immutable step result
         * @throws NullPointerException if the failure classification or code is null
         * @throws IllegalArgumentException if identity text is null or blank
         */
        /* default */ static StepResult failure(String id, String operation, PkiOperationFailure failure,
                String code) {
            return new StepResult(id, operation, StepStatus.FAILED, Optional.empty(), Optional.of(failure),
                    Optional.of(code));
        }

        /**
         * Constructs a skipped step result without a durable operation identity.
         *
         * @param id nonblank step identity
         * @param operation nonblank semantic operation
         * @param code required skip reason text
         * @return new checked immutable step result
         * @throws NullPointerException if the code is null
         * @throws IllegalArgumentException if identity text is null or blank
         */
        /* default */ static StepResult skipped(String id, String operation, String code) {
            return new StepResult(id, operation, StepStatus.SKIPPED, Optional.empty(), Optional.empty(),
                    Optional.of(code));
        }
    }
}
