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
package zeroecho.core;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

import zeroecho.core.spec.AlgorithmKeySpec;

/** Package-private validation shared by both template constructors. */
final class TemplateFactory<S extends AlgorithmKeySpec> implements Function<Map<String, Object>, S> {
    private final List<TemplateParameter> parameters;
    private final List<ParameterConstraint> constraints;
    private final Function<Map<String, Object>, S> delegate;

    /* default */ TemplateFactory(List<TemplateParameter> parameters, List<ParameterConstraint> constraints,
            Function<Map<String, Object>, S> delegate) {
        this.parameters = List.copyOf(parameters);
        this.constraints = List.copyOf(constraints);
        this.delegate = Objects.requireNonNull(delegate, "factory");
        if (parameters.size() != constraints.size()) {
            throw new IllegalArgumentException("Schema must cover every parameter");
        }
        Map<String, Boolean> names = new LinkedHashMap<>();
        for (int i = 0; i < parameters.size(); i++) {
            TemplateParameter parameter = parameters.get(i);
            ParameterConstraint constraint = constraints.get(i);
            if (names.put(parameter.name(), Boolean.TRUE) != null
                    || !parameter.name().equals(constraint.name())) {
                throw new IllegalArgumentException("Duplicate or mismatched parameter name");
            }
            Class<?> expected = switch (constraint.kind()) {
                case STRING -> String.class;
                case INTEGER -> Integer.class;
                case LONG -> Long.class;
                case BOOLEAN -> Boolean.class;
                case LEGACY -> parameter.type();
            };
            if (expected != parameter.type()) {
                throw new IllegalArgumentException("Schema type mismatch: " + parameter.name());
            }
        }
    }

    /* default */ List<ParameterConstraint> constraints() {
        return constraints;
    }

    /* default */ static List<ParameterConstraint> legacy(List<TemplateParameter> parameters) {
        return parameters.stream().map(parameter -> new ParameterConstraint(parameter.name(),
                ParameterConstraint.ValueKind.LEGACY, false, null, List.of(), null, null, 1, 0)).toList();
    }

    @Override
    public S apply(Map<String, Object> arguments) {
        if (arguments == null) {
            throw new IllegalArgumentException("Template arguments must not be null");
        }
        Map<String, Object> remaining = new LinkedHashMap<>(arguments);
        Map<String, Object> validated = new LinkedHashMap<>();
        for (int i = 0; i < parameters.size(); i++) {
            TemplateParameter parameter = parameters.get(i);
            ParameterConstraint constraint = constraints.get(i);
            String name = parameter.name();
            boolean supplied = remaining.containsKey(name);
            Object value = supplied ? remaining.remove(name) : constraint.defaultValue();
            if (!supplied && value == null && !constraint.required()) {
                continue;
            }
            if (value == null || !parameter.type().isInstance(value)) {
                throw new IllegalArgumentException("Missing or invalid argument: " + name);
            }
            constraint.validate(value);
            validated.put(name, value);
        }
        if (!remaining.isEmpty()) {
            throw new IllegalArgumentException("Unknown template argument");
        }
        return delegate.apply(Collections.unmodifiableMap(validated));
    }
}
