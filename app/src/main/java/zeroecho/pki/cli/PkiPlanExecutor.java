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

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Objects;
import java.util.regex.Matcher;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.application.PkiOperationFailure;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.application.PkiOperationValue;

/** Sequential shared executor used by direct commands and batch plans. */
final class PkiPlanExecutor {

    private final PkiOperationRegistry registry;

    /* default */ PkiPlanExecutor(PkiOperationRegistry registry) {
        this.registry = Objects.requireNonNull(registry, "registry");
    }

    /* default */ PkiPlanExecution execute(PkiPlan plan, PkiOperationTransport transport,
            CancellationSignal cancellation) {
        List<PkiPlanExecution.StepResult> results = new ArrayList<>(plan.steps().size());
        Map<String, PkiOperationResult> successful = new LinkedHashMap<>();
        Map<String, PkiPlanExecution.StepStatus> states = new LinkedHashMap<>();
        boolean failFast = false;
        boolean cancelled = false;
        for (PkiPlan.Step step : plan.steps()) {
            if (failFast) {
                addSkipped(results, states, step, "FAIL_FAST");
                continue;
            }
            if (cancelled) {
                addSkipped(results, states, step, "CANCELLED");
                continue;
            }
            if (cancellation.isCancelled()) {
                PkiPlanExecution.StepResult result = PkiPlanExecution.StepResult.failure(step.id(), step.operation(),
                        PkiOperationFailure.CANCELLED, "OPERATION_CANCELLED");
                PkiOperationValue requested = step.arguments();
                try {
                    Resolution resolved = resolve(requested, successful, states);
                    if (!resolved.dependencyUnavailable()) { requested = resolved.value(); }
                } catch (IllegalArgumentException invalidReference) {
                    // Cancellation remains authoritative when an earlier output field is unavailable.
                    requested = step.arguments();
                }
                result = retainRequestedId(step.operation(), requested, result);
                results.add(result);
                states.put(step.id(), result.status());
                cancelled = true;
                continue;
            }
            Resolution resolution;
            try {
                resolution = resolve(step.arguments(), successful, states);
            } catch (IllegalArgumentException failure) {
                PkiPlanExecution.StepResult result = PkiPlanExecution.StepResult.failure(step.id(), step.operation(),
                        PkiOperationFailure.VALIDATION_FAILURE, "REFERENCE_FIELD_INVALID");
                results.add(result);
                states.put(step.id(), result.status());
                if (plan.failurePolicy() == PkiPlan.FailurePolicy.FAIL_FAST) {
                    failFast = true;
                }
                continue;
            }
            if (resolution.dependencyUnavailable()) {
                addSkipped(results, states, step, "DEPENDENCY_UNAVAILABLE");
                continue;
            }
            PkiPlanExecution.StepResult result = executeStep(step, resolution.value(), plan, transport, cancellation);
            results.add(result);
            states.put(step.id(), result.status());
            result.output().ifPresent(value -> successful.put(step.id(), value));
            if (result.failure().filter(value -> value == PkiOperationFailure.CANCELLED).isPresent()) {
                cancelled = true;
            }
            if (result.status() == PkiPlanExecution.StepStatus.FAILED
                    && plan.failurePolicy() == PkiPlan.FailurePolicy.FAIL_FAST) {
                failFast = true;
            }
        }
        return new PkiPlanExecution(results);
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException" })
    private PkiPlanExecution.StepResult executeStep(PkiPlan.Step step, PkiOperationValue value, PkiPlan plan,
            PkiOperationTransport transport, CancellationSignal cancellation) {
        PkiPlanExecution.StepResult result;
        try {
            PkiLocalCommand command = registry.bind(step.operation(), PkiCliConfiguration.object(value), plan.baseDirectory());
            PkiLocalResult executed = transport.execute(command, cancellation);
            PkiOperationOutcome outcome = executed.outcome();
            result = switch (outcome) {
                case PkiOperationOutcome.Completed success ->
                    PkiPlanExecution.StepResult.success(step.id(), step.operation(), success.result());
                case PkiOperationOutcome.Pending ignored ->
                    PkiPlanExecution.StepResult.failure(step.id(), step.operation(),
                            PkiOperationFailure.EXTERNAL_OUTCOME_UNKNOWN, "OPERATION_PENDING");
                case PkiOperationOutcome.Failed failure ->
                    PkiPlanExecution.StepResult.failure(step.id(), step.operation(), failure.classification(), failure.code());
            };
            if (executed.operationId().isPresent()) { result = result.withOperationId(executed.operationId().orElseThrow()); }
        } catch (IllegalArgumentException failure) {
            result = PkiPlanExecution.StepResult.failure(step.id(), step.operation(),
                    PkiOperationFailure.VALIDATION_FAILURE, "OPERATION_ARGUMENTS_INVALID");
        } catch (IOException failure) {
            result = PkiPlanExecution.StepResult.failure(step.id(), step.operation(),
                    PkiOperationFailure.RESOURCE_FAILURE, "OPERATION_INPUT_FAILED");
        } catch (RuntimeException failure) {
            result = PkiPlanExecution.StepResult.failure(step.id(), step.operation(),
                    PkiOperationFailure.INTERNAL_FAILURE, "INTERNAL_FAILURE");
        }
        return retainRequestedId(step.operation(), value, result);
    }

    private static PkiPlanExecution.StepResult retainRequestedId(String operation, PkiOperationValue arguments,
            PkiPlanExecution.StepResult result) {
        if (result.operationId().isEmpty()
                && (PkiLocalCommand.INSPECT.equals(operation) || PkiLocalCommand.COMPLETE.equals(operation))
                && arguments instanceof PkiOperationValue.ObjectValue object
                && object.fields().get("operationId") instanceof PkiOperationValue.Text text
                && !PkiPlanParser.REFERENCE.matcher(text.value()).matches()) {
            try {
                return result.withOperationId(new PkiId(text.value()));
            } catch (IllegalArgumentException invalid) {
                return result;
            }
        }
        return result;
    }

    private static Resolution resolve(PkiOperationValue value, Map<String, PkiOperationResult> successful,
            Map<String, PkiPlanExecution.StepStatus> states) {
        if (value instanceof PkiOperationValue.Text text) {
            Matcher matcher = PkiPlanParser.REFERENCE.matcher(text.value());
            if (!matcher.matches()) {
                return Resolution.available(value);
            }
            String stepId = matcher.group(1);
            if (states.get(stepId) != PkiPlanExecution.StepStatus.SUCCEEDED) {
                return Resolution.unavailable();
            }
            Optional<PkiOperationValue> field = successful.get(stepId).field(matcher.group(2));
            if (field.isEmpty()) {
                throw new IllegalArgumentException("Referenced output field does not exist");
            }
            return Resolution.available(field.orElseThrow());
        }
        if (value instanceof PkiOperationValue.ObjectValue object) {
            Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
            for (Map.Entry<String, PkiOperationValue> entry : object.fields().entrySet()) {
                Resolution child = resolve(entry.getValue(), successful, states);
                if (child.dependencyUnavailable()) {
                    return Resolution.unavailable();
                }
                fields.put(entry.getKey(), child.value());
            }
            return Resolution.available(new PkiOperationValue.ObjectValue(fields));
        }
        if (value instanceof PkiOperationValue.ListValue list) {
            List<PkiOperationValue> values = new ArrayList<>(list.values().size());
            for (PkiOperationValue item : list.values()) {
                Resolution child = resolve(item, successful, states);
                if (child.dependencyUnavailable()) {
                    return Resolution.unavailable();
                }
                values.add(child.value());
            }
            return Resolution.available(new PkiOperationValue.ListValue(values));
        }
        return Resolution.available(value);
    }

    private static void addSkipped(List<PkiPlanExecution.StepResult> results,
            Map<String, PkiPlanExecution.StepStatus> states, PkiPlan.Step step, String code) {
        results.add(PkiPlanExecution.StepResult.skipped(step.id(), step.operation(), code));
        states.put(step.id(), PkiPlanExecution.StepStatus.SKIPPED);
    }

    private record Resolution(PkiOperationValue value, boolean dependencyUnavailable) {
        /* default */ static Resolution available(PkiOperationValue value) {
            return new Resolution(value, false);
        }

        /* default */ static Resolution unavailable() {
            return new Resolution(new PkiOperationValue.BooleanValue(false), true);
        }
    }
}
