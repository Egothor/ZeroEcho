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
package zeroecho.pki.server.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonGenerator;
import tools.jackson.core.ObjectWriteContext;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.json.JsonFactoryBuilder;
import tools.jackson.core.json.JsonReadFeature;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.PkiServerConfiguration;

/** Strict bounded UTF-8 JSON framing shared by server configuration and HTTP. */
@SuppressWarnings("PMD")
public final class StrictJson {
    /** Absolute technical JSON document ceiling. */
    public static final int MAXIMUM_DOCUMENT_BYTES = 16_777_216;
    private static final int MAXIMUM_CONTAINER_ENTRIES = 4_096;
    private static final JsonFactory FACTORY = createFactory();

    private StrictJson() {
    }

    /**
     * Parses exactly one complete strict JSON value with duplicate detection.
     *
     * @param document non-empty UTF-8 JSON without a byte-order mark
     * @param maximumBytes positive caller limit, no greater than {@link #MAXIMUM_DOCUMENT_BYTES}
     * @return immutable operation-value representation
     * @throws IllegalArgumentException if framing, size, encoding, or JSON syntax is invalid
     */
    public static PkiOperationValue parse(byte[] document, int maximumBytes) {
        if (document == null || document.length == 0 || maximumBytes < 1
                || maximumBytes > MAXIMUM_DOCUMENT_BYTES || document.length > maximumBytes || hasBom(document)) {
            throw invalid();
        }
        try (JsonParser parser = FACTORY.createParser(ObjectReadContext.empty(), document, 0, document.length)) {
            JsonToken first = parser.nextToken();
            if (first == null) throw invalid();
            PkiOperationValue result = read(parser, first);
            if (parser.nextToken() != null) throw invalid();
            return result;
        } catch (JacksonException failure) {
            throw invalid(failure);
        }
    }

    /**
     * Encodes one safe operation value deterministically as UTF-8 JSON.
     *
     * @param value safe operation value to encode
     * @return newly allocated UTF-8 JSON bytes
     * @throws IllegalStateException if the in-memory response cannot be encoded
     */
    public static byte[] encode(PkiOperationValue value) {
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            try (JsonGenerator generator = FACTORY.createGenerator(ObjectWriteContext.empty(), output)) {
                write(generator, value);
            }
            return output.toByteArray();
        } catch (IOException failure) {
            throw new IllegalStateException("Safe JSON response cannot be encoded");
        }
    }

    private static PkiOperationValue read(JsonParser parser, JsonToken token) {
        return switch (token) {
            case START_OBJECT -> readObject(parser);
            case START_ARRAY -> readArray(parser);
            case VALUE_STRING -> new PkiOperationValue.Text(parser.getString());
            case VALUE_NUMBER_INT -> new PkiOperationValue.IntegerValue(parser.getLongValue());
            case VALUE_TRUE -> new PkiOperationValue.BooleanValue(true);
            case VALUE_FALSE -> new PkiOperationValue.BooleanValue(false);
            default -> throw invalid();
        };
    }

    private static PkiOperationValue.ObjectValue readObject(JsonParser parser) {
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            if (parser.currentToken() != JsonToken.PROPERTY_NAME
                    || fields.size() >= MAXIMUM_CONTAINER_ENTRIES) throw invalid();
            String name = parser.currentName();
            JsonToken token = parser.nextToken();
            if (token == null || fields.putIfAbsent(name, read(parser, token)) != null) throw invalid();
        }
        return new PkiOperationValue.ObjectValue(fields);
    }

    private static PkiOperationValue.ListValue readArray(JsonParser parser) {
        List<PkiOperationValue> values = new ArrayList<>();
        JsonToken token;
        while ((token = parser.nextToken()) != JsonToken.END_ARRAY) {
            if (token == null || values.size() >= MAXIMUM_CONTAINER_ENTRIES) throw invalid();
            values.add(read(parser, token));
        }
        return new PkiOperationValue.ListValue(values);
    }

    static void write(JsonGenerator generator, PkiOperationValue value) throws IOException {
        switch (value) {
            case PkiOperationValue.Text text -> generator.writeString(text.value());
            case PkiOperationValue.IntegerValue integer -> generator.writeNumber(integer.value());
            case PkiOperationValue.BooleanValue bool -> generator.writeBoolean(bool.value());
            case PkiOperationValue.ObjectValue object -> {
                generator.writeStartObject();
                for (Map.Entry<String, PkiOperationValue> field : object.fields().entrySet()) {
                    generator.writeName(field.getKey());
                    write(generator, field.getValue());
                }
                generator.writeEndObject();
            }
            case PkiOperationValue.ListValue list -> {
                generator.writeStartArray();
                for (PkiOperationValue item : list.values()) write(generator, item);
                generator.writeEndArray();
            }
        }
    }

    private static JsonFactory createFactory() {
        StreamReadConstraints constraints = StreamReadConstraints.builder().maxNestingDepth(16)
                .maxDocumentLength(MAXIMUM_DOCUMENT_BYTES).maxTokenCount(65_536).maxNumberLength(20)
                .maxStringLength(PkiServerConfiguration.Listener.MAXIMUM_PROOF_RESPONSE_BASE64URL_CHARACTERS)
                .maxNameLength(128).build();
        JsonFactoryBuilder builder = JsonFactory.builder().streamReadConstraints(constraints)
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).disable(StreamReadFeature.AUTO_CLOSE_SOURCE);
        for (JsonReadFeature feature : JsonReadFeature.values()) builder.disable(feature);
        return builder.build();
    }

    private static boolean hasBom(byte[] value) {
        return value.length >= 3 && value[0] == (byte) 0xef && value[1] == (byte) 0xbb
                && value[2] == (byte) 0xbf;
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Server JSON document is invalid");
    }

    private static IllegalArgumentException invalid(JacksonException failure) {
        return new IllegalArgumentException("Server JSON document is invalid", failure);
    }
}
