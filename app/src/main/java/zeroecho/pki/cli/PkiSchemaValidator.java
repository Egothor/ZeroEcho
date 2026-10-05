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

import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.json.JsonFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import zeroecho.pki.application.PkiOperationValue;

/**
 * Validates remote operation arguments against the bundled operation parameter schema.
 *
 * <p>The schema is loaded once from the classpath resource
 * {@code schema/operationSchema.json}, which is produced at build time by
 * {@code :pki-server:generateSchema} and bundled into the CLI distribution.
 * Validation is best-effort: if the operation is not in the schema (e.g., a
 * future operation in a newer server) validation is skipped and the server
 * remains the authoritative validator.</p>
 */
final class PkiSchemaValidator {

    /** Lazy-loaded index: operationId → list of (fieldName, required) pairs. */
    private static final AtomicReference<Map<String, List<RequiredField>>> SCHEMA =
            new AtomicReference<>();

    private record RequiredField(String name, boolean required) {}

    private PkiSchemaValidator() {}

    /**
     * Validates that all required fields declared in the bundled schema are
     * present in the argument map. Unknown fields are ignored; the server
     * validates field types and values.
     *
     * @param operationId the dotted operation identifier
     * @param arguments   the parsed argument object
     * @throws IllegalArgumentException when a required field is absent
     */
    /* default */ static void validateIfKnown(String operationId, PkiOperationValue.ObjectValue arguments) {
        Map<String, List<RequiredField>> schema = loadSchema();
        List<RequiredField> fields = schema.get(operationId);
        if (fields == null) { return; }
        for (RequiredField field : fields) {
            if (field.required() && !arguments.fields().containsKey(field.name())) {
                throw new IllegalArgumentException(
                        "Missing required argument for " + operationId + ": --" + camelToKebab(field.name()));
            }
        }
    }

    private static String camelToKebab(String camel) {
        return camel.replaceAll("([A-Z])", "-$1").toLowerCase(java.util.Locale.ROOT);
    }

    private static Map<String, List<RequiredField>> loadSchema() {
        Map<String, List<RequiredField>> existing = SCHEMA.get();
        if (existing != null) { return existing; }
        Map<String, List<RequiredField>> parsed = parseSchema();
        SCHEMA.compareAndSet(null, parsed);
        return SCHEMA.get();
    }

    private static Map<String, List<RequiredField>> parseSchema() {
        try (InputStream in = PkiSchemaValidator.class.getResourceAsStream("/schema/operationSchema.json")) {
            if (in == null) { return Map.of(); }
            return parse(in);
        } catch (IOException ignored) {
            return Map.of();
        }
    }

    private static Map<String, List<RequiredField>> parse(InputStream in) throws IOException {
        Map<String, List<RequiredField>> result = new HashMap<>();
        try (JsonParser parser = new JsonFactory().createParser(in)) {
            if (parser.nextToken() != JsonToken.START_ARRAY) { throw new IOException("Invalid operation schema root"); }
            while (parser.nextToken() != JsonToken.END_ARRAY) {
                readOperation(parser, result);
            }
            if (parser.nextToken() != null) { throw new IOException("Trailing schema data"); }
        }
        return Map.copyOf(result);
    }

    private static void readOperation(JsonParser parser, Map<String, List<RequiredField>> result) throws IOException {
        if (parser.currentToken() != JsonToken.START_OBJECT) {
            throw new IOException("Invalid operation schema entry");
        }
        String operationId = null;
        List<RequiredField> fields = new ArrayList<>();
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            if (parser.currentToken() != JsonToken.PROPERTY_NAME) {
                throw new IOException("Invalid operation schema property");
            }
            String key = parser.currentName();
            parser.nextToken();
            switch (key) {
                case "operationId" -> operationId = parser.getString();
                case "fields" -> readFields(parser, fields);
                default -> parser.skipChildren();
            }
        }
        if (operationId == null || result.putIfAbsent(operationId, List.copyOf(fields)) != null) {
            throw new IOException("Invalid schema identity");
        }
    }

    private static void readFields(JsonParser parser, List<RequiredField> fields) throws IOException {
        if (parser.currentToken() != JsonToken.START_ARRAY) {
            throw new IOException("Invalid schema fields");
        }
        while (parser.nextToken() != JsonToken.END_ARRAY) {
            fields.add(readField(parser));
        }
    }

    private static RequiredField readField(JsonParser parser) throws IOException {
        if (parser.currentToken() != JsonToken.START_OBJECT) {
            throw new IOException("Invalid schema field");
        }
        String name = null;
        boolean required = false;
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            if (parser.currentToken() != JsonToken.PROPERTY_NAME) {
                throw new IOException("Invalid field property");
            }
            String property = parser.currentName();
            parser.nextToken();
            switch (property) {
                case "name" -> name = parser.getString();
                case "required" -> required = parser.getBooleanValue();
                default -> parser.skipChildren();
            }
        }
        if (name == null) {
            throw new IOException("Missing schema field name");
        }
        return new RequiredField(name, required);
    }
}
