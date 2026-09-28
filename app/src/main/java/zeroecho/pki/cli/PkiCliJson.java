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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.json.JsonFactoryBuilder;
import tools.jackson.core.json.JsonReadFeature;
import zeroecho.pki.application.PkiOperationValue;

/** Strict bounded JSON reader for CLI configuration and operation plans. */
final class PkiCliJson {

    /* default */ static final int MAXIMUM_DOCUMENT_BYTES = 1_048_576;
    /* default */ static final int MAXIMUM_CONTAINER_ENTRIES = 2_048;

    private static final int MAXIMUM_DEPTH = 16;
    private static final int MAXIMUM_STRING_LENGTH = 4_096;
    private static final JsonFactory JSON_FACTORY = createFactory(MAXIMUM_DOCUMENT_BYTES, MAXIMUM_STRING_LENGTH);
    private static final JsonFactory ARGUMENT_FACTORY = createFactory(16 * MAXIMUM_DOCUMENT_BYTES, 21_846);
    private static final JsonFactory RESPONSE_FACTORY = createFactory(4 * MAXIMUM_DOCUMENT_BYTES, 4 * MAXIMUM_DOCUMENT_BYTES);

    private PkiCliJson() {
    }

    /* default */ static PkiOperationValue parse(byte[] document) {
        return parse(document, JSON_FACTORY, MAXIMUM_DOCUMENT_BYTES, false, false);
    }

    /* default */ static PkiOperationValue parseResponse(byte[] document) {
        return parse(document, RESPONSE_FACTORY, 4 * MAXIMUM_DOCUMENT_BYTES, true, true);
    }

    /* default */ static PkiOperationValue parseArgument(byte[] document) {
        return parse(document, ARGUMENT_FACTORY, 16 * MAXIMUM_DOCUMENT_BYTES, true, false);
    }

    private static PkiOperationValue parse(byte[] document, JsonFactory factory, int maximumBytes,
            boolean response, boolean envelope) {
        if (document == null || document.length == 0 || document.length > maximumBytes || hasBom(document)) {
            throw invalid();
        }
        try (JsonParser parser = factory.createParser(ObjectReadContext.empty(), document, 0, document.length)) {
            JsonToken first = parser.nextToken();
            if (first == null) {
                throw invalid();
            }
            PkiOperationValue value = first == JsonToken.START_OBJECT
                    ? readObject(parser, response, envelope) : readValue(parser, first, response);
            if (parser.nextToken() != null) {
                throw invalid();
            }
            return value;
        } catch (JacksonException failure) {
            throw invalid(failure);
        }
    }

    private static PkiOperationValue readValue(JsonParser parser, JsonToken token, boolean response) {
        return switch (token) {
            case START_OBJECT -> readObject(parser, response, false);
            case START_ARRAY -> readArray(parser, response);
            case VALUE_STRING -> new PkiOperationValue.Text(parser.getString());
            case VALUE_NUMBER_INT -> new PkiOperationValue.IntegerValue(parser.getLongValue());
            case VALUE_TRUE -> new PkiOperationValue.BooleanValue(true);
            case VALUE_FALSE -> new PkiOperationValue.BooleanValue(false);
            default -> throw invalid();
        };
    }

    private static PkiOperationValue.ObjectValue readObject(JsonParser parser, boolean response, boolean root) {
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        boolean resultSeen = false;
        boolean failureSeen = false;
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            if (parser.currentToken() != JsonToken.PROPERTY_NAME || fields.size() >= (response ? 4096 : MAXIMUM_CONTAINER_ENTRIES)) {
                throw invalid();
            }
            String name = parser.currentName();
            resultSeen |= "result".equals(name);
            failureSeen |= "failure".equals(name);
            JsonToken valueToken = parser.nextToken();
            if (root && valueToken == JsonToken.VALUE_NULL
                    && ("result".equals(name) || "failure".equals(name))) { continue; }
            if (valueToken == null || fields.putIfAbsent(name, readValue(parser, valueToken, response)) != null) {
                throw invalid();
            }
        }
        if (root && (!resultSeen || !failureSeen)) { throw invalid(); }
        return new PkiOperationValue.ObjectValue(fields);
    }

    private static PkiOperationValue.ListValue readArray(JsonParser parser, boolean response) {
        List<PkiOperationValue> values = new ArrayList<>();
        JsonToken token;
        while ((token = parser.nextToken()) != JsonToken.END_ARRAY) {
            if (token == null || values.size() >= (response ? 4096 : MAXIMUM_CONTAINER_ENTRIES)) {
                throw invalid();
            }
            values.add(readValue(parser, token, response));
        }
        return new PkiOperationValue.ListValue(values);
    }

    private static JsonFactory createFactory(int maximumBytes, int maximumStringLength) {
        StreamReadConstraints constraints = StreamReadConstraints.builder().maxNestingDepth(MAXIMUM_DEPTH)
                .maxDocumentLength(maximumBytes).maxTokenCount(maximumBytes > MAXIMUM_DOCUMENT_BYTES ? 65_536 : 32_768).maxNumberLength(20)
                .maxStringLength(maximumStringLength).maxNameLength(maximumBytes > MAXIMUM_DOCUMENT_BYTES ? 128 : 64).build();
        JsonFactoryBuilder builder = JsonFactory.builder().streamReadConstraints(constraints)
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).disable(StreamReadFeature.AUTO_CLOSE_SOURCE);
        for (JsonReadFeature feature : JsonReadFeature.values()) {
            builder.disable(feature);
        }
        return builder.build();
    }

    private static boolean hasBom(byte[] document) {
        return document.length >= 3 && document[0] == (byte) 0xef && document[1] == (byte) 0xbb
                && document[2] == (byte) 0xbf;
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("CLI JSON document is invalid");
    }

    private static IllegalArgumentException invalid(JacksonException failure) {
        return new IllegalArgumentException("CLI JSON document is invalid", failure);
    }
}
