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
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import zeroecho.pki.application.PkiOperationValue;

/** Strict parser and reference-order validator for plan schema version 1. */
final class PkiPlanParser {

    /* default */ static final int MAXIMUM_STEPS = 1_000;
    /* default */ static final Pattern REFERENCE = Pattern
            .compile("\\$\\{([a-z][a-z0-9-]{0,63})\\.([a-z][a-zA-Z0-9]{0,63})}");

    private static final Pattern STEP_ID = Pattern.compile("[a-z][a-z0-9-]{0,63}");
    private static final Pattern OPERATION_NAME = Pattern.compile("[a-z][a-z0-9.-]{2,63}");
    private static final Set<String> ROOT_FIELDS = Set.of("version", "failurePolicy", "operations");
    private static final Set<String> STEP_FIELDS = Set.of("id", "operation", "arguments");

    private PkiPlanParser() {
    }

    /* default */ static PkiPlan read(Path path, Set<String> supportedOperations) throws IOException {
        Path exact = path.toAbsolutePath().normalize();
        PkiOperationValue.ObjectValue root = PkiCliConfiguration
                .object(PkiCliJson.parse(PkiCliFiles.readRegularFile(exact, PkiCliJson.MAXIMUM_DOCUMENT_BYTES)));
        PkiCliConfiguration.requireExactFields(root.fields(), ROOT_FIELDS);
        int version = Math.toIntExact(PkiCliConfiguration.integer(PkiCliConfiguration.required(root, "version")));
        if (version != PkiPlan.CURRENT_VERSION) {
            throw new IllegalArgumentException("Plan version is unsupported");
        }
        PkiPlan.FailurePolicy policy = parsePolicy(PkiCliConfiguration.text(
                PkiCliConfiguration.required(root, "failurePolicy")));
        List<PkiOperationValue> encodedSteps = list(PkiCliConfiguration.required(root, "operations"));
        if (encodedSteps.isEmpty() || encodedSteps.size() > MAXIMUM_STEPS) {
            throw new IllegalArgumentException("Plan step count is invalid");
        }
        List<PkiPlan.Step> steps = new ArrayList<>(encodedSteps.size());
        Set<String> ids = new HashSet<>();
        Map<String, Integer> positions = new HashMap<>();
        for (int index = 0; index < encodedSteps.size(); index++) {
            PkiPlan.Step step = parseStep(encodedSteps.get(index), supportedOperations);
            if (!ids.add(step.id())) {
                throw new IllegalArgumentException("Plan step identifiers must be unique");
            }
            positions.put(step.id(), index);
            steps.add(step);
        }
        validateReferences(steps, positions);
        Path parent = exact.getParent();
        return new PkiPlan(version, policy, steps, parent == null ? Path.of(".") : parent);
    }

    private static PkiPlan.Step parseStep(PkiOperationValue value, Set<String> supportedOperations) {
        PkiOperationValue.ObjectValue object = PkiCliConfiguration.object(value);
        PkiCliConfiguration.requireExactFields(object.fields(), STEP_FIELDS);
        String id = PkiCliConfiguration.text(PkiCliConfiguration.required(object, "id"));
        String operation = PkiCliConfiguration.text(PkiCliConfiguration.required(object, "operation"));
        if (!STEP_ID.matcher(id).matches() || !OPERATION_NAME.matcher(operation).matches()
                || !supportedOperations.contains(operation)) {
            throw new IllegalArgumentException("Plan step identity or operation is invalid");
        }
        PkiOperationValue.ObjectValue arguments = PkiCliConfiguration
                .object(PkiCliConfiguration.required(object, "arguments"));
        return new PkiPlan.Step(id, operation, arguments);
    }

    private static void validateReferences(List<PkiPlan.Step> steps, Map<String, Integer> positions) {
        for (int index = 0; index < steps.size(); index++) {
            validateValueReferences(steps.get(index).arguments(), index, positions);
        }
    }

    @SuppressWarnings("PMD.AvoidDeeplyNestedIfStmts")
    private static void validateValueReferences(PkiOperationValue value, int current,
            Map<String, Integer> positions) {
        if (value instanceof PkiOperationValue.Text text) {
            String raw = text.value();
            Matcher matcher = REFERENCE.matcher(raw);
            if (matcher.matches()) {
                Integer referenced = positions.get(matcher.group(1));
                if (referenced == null || referenced >= current) {
                    throw new IllegalArgumentException("Plan reference must target an earlier step");
                }
            } else if (raw.contains("${")) {
                throw new IllegalArgumentException("Plan interpolation is not supported");
            }
        } else if (value instanceof PkiOperationValue.ObjectValue object) {
            for (PkiOperationValue child : object.fields().values()) {
                validateValueReferences(child, current, positions);
            }
        } else if (value instanceof PkiOperationValue.ListValue list) {
            for (PkiOperationValue child : list.values()) {
                validateValueReferences(child, current, positions);
            }
        }
    }

    private static PkiPlan.FailurePolicy parsePolicy(String value) {
        return PkiPlan.FailurePolicy.valueOf(value);
    }

    private static List<PkiOperationValue> list(PkiOperationValue value) {
        if (value instanceof PkiOperationValue.ListValue list) {
            return list.values();
        }
        throw new IllegalArgumentException("CLI field has the wrong type");
    }
}
