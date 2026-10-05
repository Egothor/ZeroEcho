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

import java.util.List;
import java.util.Objects;

/**
 * Immutable machine-readable validation for one template argument. Numeric bounds
 * are inclusive; an integer must satisfy {@code floorMod(value, step) == remainder}.
 * Empty choices mean unrestricted values of the declared kind. Null defaults mean
 * no default. Only immutable scalar values are accepted as defaults and choices.
 *
 * @param name parameter name
 * @param kind value kind
 * @param required whether omission without a default is rejected
 * @param defaultValue optional default
 * @param allowedValues ordered allowed values, or an empty list
 * @param minimum optional inclusive integer lower bound
 * @param maximum optional inclusive integer upper bound
 * @param step positive integer modulus
 * @param remainder required nonnegative remainder smaller than step
 */
public record ParameterConstraint(String name, ValueKind kind, boolean required,
        Object defaultValue, List<?> allowedValues, Long minimum, Long maximum,
        long step, long remainder) {

    /** Machine-readable scalar kind; legacy types retain their presentation type. */
    public enum ValueKind {
        /** Nonblank string. */ STRING,
        /** Exactly a boxed Java integer. */ INTEGER,
        /** Exactly a boxed Java long. */ LONG,
        /** Boolean. */ BOOLEAN,
        /** Legacy constructor metadata with no inferred domain constraints. */ LEGACY
    }

    /**
     * Validates and snapshots the constraint.
     * @throws IllegalArgumentException if the definition is inconsistent
     * @throws NullPointerException if name, kind or choices is null
     */
    public ParameterConstraint {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(kind, "kind");
        allowedValues = List.copyOf(allowedValues);
        if (name.isBlank() || step <= 0 || remainder < 0 || remainder >= step
                || minimum != null && maximum != null && minimum > maximum) {
            throw new IllegalArgumentException("Invalid parameter constraint");
        }
        boolean numeric = kind == ValueKind.INTEGER || kind == ValueKind.LONG;
        if (!numeric && (minimum != null || maximum != null || step != 1 || remainder != 0)
                || kind == ValueKind.LEGACY && (defaultValue != null || !allowedValues.isEmpty())) {
            throw new IllegalArgumentException("Constraints do not match value kind");
        }
        for (Object choice : allowedValues) {
            validateValue(name, kind, choice, minimum, maximum, step, remainder);
        }
        if (defaultValue != null) {
            validateValue(name, kind, defaultValue, minimum, maximum, step, remainder);
            if (!allowedValues.isEmpty() && !allowedValues.contains(defaultValue)) {
                throw new IllegalArgumentException("Default is not an allowed value: " + name);
            }
        }
    }

    /* default */ void validate(Object value) {
        validateValue(name, kind, value, minimum, maximum, step, remainder);
        if (!allowedValues.isEmpty() && !allowedValues.contains(value)) {
            throw new IllegalArgumentException("Value is not allowed: " + name);
        }
    }

    private static void validateValue(String name, ValueKind kind, Object value,
            Long minimum, Long maximum, long step, long remainder) {
        boolean valid = value != null && switch (kind) {
            case STRING -> value instanceof String text && !text.isBlank();
            case INTEGER -> value instanceof Integer;
            case LONG -> value instanceof Long;
            case BOOLEAN -> value instanceof Boolean;
            case LEGACY -> true;
        };
        if (!valid) {
            throw new IllegalArgumentException("Invalid value type: " + name);
        }
        if (kind == ValueKind.INTEGER || kind == ValueKind.LONG) {
            long number = ((Number) value).longValue();
            if (minimum != null && number < minimum || maximum != null && number > maximum
                    || Math.floorMod(number, step) != remainder) {
                throw new IllegalArgumentException("Value outside constraints: " + name);
            }
        }
    }
}
