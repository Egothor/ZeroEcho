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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import zeroecho.pki.application.PkiOperationValue;

/**
 * Parses remote-mode operation arguments into the closed
 * {@link PkiOperationValue.ObjectValue} model.
 *
 * <p>Remote mode expands coverage beyond the local typed registry: it accepts any
 * dotted operation identifier (including the server-control families such as
 * {@code security.*}, {@code acme.*}, {@code ocsp.*}, and {@code repository.*}).
 * Arguments may therefore be supplied generically:</p>
 *
 * <ul>
 *   <li>{@code --arg name=value} &mdash; a text field</li>
 *   <li>{@code --arg-int name=value} &mdash; an integer field</li>
 *   <li>{@code --arg-bool name=true|false} &mdash; a boolean field</li>
 *   <li>{@code --arg-json name=JSON} &mdash; a bounded structured value</li>
 * </ul>
 *
 * <p>For readability the known local option spellings (for example
 * {@code --credential-id}, {@code --profile-id}) are also accepted and mapped to
 * their canonical field names.</p>
 */
final class PkiRemoteArguments {

    private static final String ARG = "--arg";
    private static final String ARG_INT = "--arg-int";
    private static final String ARG_BOOL = "--arg-bool";
    private static final String ARG_JSON = "--arg-json";

    private static final Set<String> INTEGER_FIELDS = Set.of(
            "limit", "offset", "profileVersion", "expectedLifecycleRevision");
    private static final Set<String> BOOLEAN_FIELDS = Set.of(
            "requireApproval");
    private static final Set<String> SET_FIELDS = Set.of(
            "allowedAuthorityIds", "requiredSanDomains");

    private PkiRemoteArguments() {
    }

    /**
     * Parses option/value tokens into structured operation arguments.
     *
     * @param tokens operation argument tokens (option and value pairs)
     * @param mappedNames known option-to-field mappings reused from the local CLI
     * @return the structured argument object
     * @throws IllegalArgumentException when a token pair is malformed or unknown
     */
    /* default */ static PkiOperationValue.ObjectValue parse(List<String> tokens, Map<String, String> mappedNames) {
        if ((tokens.size() & 1) != 0) {
            throw new IllegalArgumentException("Operation arguments must be option-value pairs");
        }
        Map<String, PkiOperationValue> arguments = new LinkedHashMap<>();
        for (int index = 0; index < tokens.size(); index += 2) {
            String option = tokens.get(index);
            String raw = tokens.get(index + 1);
            Field field = field(option, raw, mappedNames);
            if (arguments.putIfAbsent(field.name(), field.value()) != null) {
                throw new IllegalArgumentException("Operation argument is duplicated");
            }
        }
        return new PkiOperationValue.ObjectValue(arguments);
    }

    private static Field field(String option, String raw, Map<String, String> mappedNames) {
        return switch (option) {
            case ARG_JSON -> new Field(nameOf(raw), PkiCliJson.parseArgument(valueOf(raw).getBytes(StandardCharsets.UTF_8)));
            case ARG -> new Field(nameOf(raw), new PkiOperationValue.Text(valueOf(raw)));
            case ARG_INT -> new Field(nameOf(raw), new PkiOperationValue.IntegerValue(parseLong(valueOf(raw))));
            case ARG_BOOL -> new Field(nameOf(raw), new PkiOperationValue.BooleanValue(parseBoolean(valueOf(raw))));
            default -> mappedField(option, raw, mappedNames);
        };
    }

    private static Field mappedField(String option, String raw, Map<String, String> mappedNames) {
        String name = mappedNames.get(option);
        if (name == null) {
            throw new IllegalArgumentException("Unknown remote operation argument");
        }
        PkiOperationValue value;
        if (INTEGER_FIELDS.contains(name)) {
            value = new PkiOperationValue.IntegerValue(parseLong(raw));
        } else if (BOOLEAN_FIELDS.contains(name)) {
            value = new PkiOperationValue.BooleanValue(parseBoolean(raw));
        } else if (SET_FIELDS.contains(name)) {
            value = new PkiOperationValue.ListValue(
                    Arrays.stream(raw.split(",")).map(String::trim)
                            .filter(s -> !s.isEmpty())
                            .<PkiOperationValue>map(PkiOperationValue.Text::new)
                            .toList());
        } else {
            value = new PkiOperationValue.Text(raw);
        }
        return new Field(name, value);
    }

    private static String nameOf(String pair) {
        int equals = pair.indexOf('=');
        if (equals <= 0) {
            throw new IllegalArgumentException("Generic argument must be name=value");
        }
        return pair.substring(0, equals);
    }

    private static String valueOf(String pair) {
        int equals = pair.indexOf('=');
        if (equals < 0) {
            throw new IllegalArgumentException("Generic argument must be name=value");
        }
        return pair.substring(equals + 1);
    }

    private static long parseLong(String raw) {
        try {
            return Long.parseLong(raw);
        } catch (NumberFormatException failure) {
            throw new IllegalArgumentException("Numeric remote argument is invalid", failure);
        }
    }

    private static boolean parseBoolean(String raw) {
        if (Boolean.TRUE.toString().equals(raw)) {
            return true;
        }
        if (Boolean.FALSE.toString().equals(raw)) {
            return false;
        }
        throw new IllegalArgumentException("Boolean remote argument must be true or false");
    }

    private record Field(String name, PkiOperationValue value) {
    }
}
