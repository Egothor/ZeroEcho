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
package zeroecho.pki.impl.crypto.remote.http;

import java.io.ByteArrayOutputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

import tools.jackson.core.JsonGenerator;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.ObjectWriteContext;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.json.JsonFactory;

/**
 * Minimal, strict codec for the flat string-keyed JSON messages exchanged with a
 * remote signing service. Every value is a string (binary payloads are Base64),
 * so the wire is technology-neutral and any backend can produce it. Bounded and
 * non-nested: unknown/duplicate/typed structures are rejected.
 */
final class RemoteSigningJson {

    private static final int MAXIMUM_BYTES = 64 * 1024 * 1024;
    private static final JsonFactory FACTORY = JsonFactory.builder()
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(2)
                    .maxStringLength(MAXIMUM_BYTES).build())
            .build();

    private RemoteSigningJson() {
    }

    /**
     * Encodes a flat map as a deterministic JSON object (keys sorted).
     *
     * @param fields string field map
     * @return UTF-8 JSON bytes
     */
    /* default */ static byte[] write(Map<String, String> fields) {
        Map<String, String> sorted = new TreeMap<>(fields);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (JsonGenerator generator = FACTORY.createGenerator(ObjectWriteContext.empty(), out)) {
            generator.writeStartObject();
            for (Map.Entry<String, String> entry : sorted.entrySet()) {
                generator.writeStringProperty(entry.getKey(), entry.getValue());
            }
            generator.writeEndObject();
        }
        return out.toByteArray();
    }

    /**
     * Decodes a flat JSON object into a string map. Only string values are allowed.
     *
     * @param body UTF-8 JSON bytes
     * @return field map
     * @throws IllegalArgumentException if the body is not a flat string object
     */
    /* default */ static Map<String, String> read(byte[] body) {
        if (body == null || body.length == 0 || body.length > MAXIMUM_BYTES) {
            throw new IllegalArgumentException("Remote signing message is out of bounds");
        }
        Map<String, String> fields = new LinkedHashMap<>();
        try (JsonParser parser = FACTORY.createParser(ObjectReadContext.empty(), body, 0, body.length)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                throw new IllegalArgumentException("Remote signing message is not a JSON object");
            }
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                if (parser.currentToken() != JsonToken.PROPERTY_NAME) {
                    throw new IllegalArgumentException("Malformed remote signing message");
                }
                String name = parser.currentName();
                if (parser.nextToken() != JsonToken.VALUE_STRING) {
                    throw new IllegalArgumentException("Remote signing message field must be a string");
                }
                if (fields.put(name, parser.getString()) != null) {
                    throw new IllegalArgumentException("Duplicate remote signing message field");
                }
            }
        } catch (tools.jackson.core.JacksonException malformed) {
            throw new IllegalArgumentException("Remote signing message could not be parsed", malformed);
        }
        return fields;
    }
}
