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

import java.io.ByteArrayOutputStream;
import java.util.Objects;
import java.util.Optional;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonGenerator;
import tools.jackson.core.ObjectWriteContext;
import tools.jackson.core.json.JsonFactory;
import zeroecho.pki.application.PkiOperationValue;

/**
 * Codec for the admin-API request and response envelopes.
 *
 * <p>Requests are serialized with the same strict {@link PkiOperationValue} value
 * model the CLI already uses; responses are parsed with the shared strict reader
 * {@link PkiCliJson}. No additional JSON dependency is introduced.</p>
 *
 * <p>Request envelope:
 * {@code {"version":1,"authorityId"?:string,"approvalId"?:string,"deadline"?:string,"arguments":{...}}}.
 * The {@code version} is always {@code 1}; optional scope fields are omitted when
 * absent.</p>
 */
final class PkiRemoteEnvelope {

    /** Wire protocol version carried by every request and expected on every response. */
    /* default */ static final long PROTOCOL_VERSION = 1L;

    private static final JsonFactory JSON_FACTORY = JsonFactory.builder().build();

    private PkiRemoteEnvelope() {
    }

    /**
     * Encodes one operation request envelope.
     *
     * @param authorityId authority scope, absent for realm-wide operations
     * @param approvalId prior approval identifier, absent on the first submission
     * @param deadline ISO-8601 instant bounding server-side execution, when set
     * @param arguments typed operation arguments
     * @return canonical UTF-8 JSON request body
     */
    /* default */ static byte[] encodeRequest(Optional<String> authorityId, Optional<String> approvalId,
            Optional<String> deadline, PkiOperationValue.ObjectValue arguments) {
        Objects.requireNonNull(authorityId, "authorityId");
        Objects.requireNonNull(approvalId, "approvalId");
        Objects.requireNonNull(deadline, "deadline");
        Objects.requireNonNull(arguments, "arguments");
        ByteArrayOutputStream encoded = new BoundedRequestOutput();
        try (JsonGenerator generator = JSON_FACTORY.createGenerator(ObjectWriteContext.empty(), encoded)) {
            generator.writeStartObject();
            generator.writeNumberProperty("version", PROTOCOL_VERSION);
            authorityId.ifPresent(value -> generator.writeStringProperty("authorityId", value));
            approvalId.ifPresent(value -> generator.writeStringProperty("approvalId", value));
            deadline.ifPresent(value -> generator.writeStringProperty("deadline", value));
            generator.writeName("arguments");
            PkiCliValueJson.writeValue(generator, arguments);
            generator.writeEndObject();
        } catch (JacksonException failure) {
            throw new IllegalStateException("Remote request encoding failed", failure);
        }
        return encoded.toByteArray();
    }

    /**
     * Parses a version-1 typed response envelope; the transport validates its
     * status-specific fields against the HTTP response.
     *
     * @param body response body bytes
     * @return parsed response envelope
     * @throws IllegalArgumentException if the body is not a JSON object
     */
    /* default */ static ResponseEnvelope decodeResponse(byte[] body) {
        PkiOperationValue root = PkiCliJson.parseResponse(body);
        if (!(root instanceof PkiOperationValue.ObjectValue object)) {
            throw new IllegalArgumentException("Response envelope is not a JSON object");
        }
        requiredText(object, "requestId");
        Optional<Long> version = integerField(object, "version");
        if (version.isEmpty() || version.orElseThrow() != PROTOCOL_VERSION) {
            throw new IllegalArgumentException("Unsupported remote protocol version");
        }
        Optional<Failure> failure = objectField(object, "failure").map(PkiRemoteEnvelope::readFailure);
        return new ResponseEnvelope(version, Optional.of(requiredText(object, "operation")),
                Optional.of(requiredText(object, "status")), objectField(object, "result"), failure);
    }

    private static Failure readFailure(PkiOperationValue.ObjectValue object) {
        return new Failure(requiredText(object, "classification"),
                requiredText(object, "code"), textField(object, "messageKey"),
                booleanField(object, "recoveryRequired"), booleanField(object, "reconciliationRequired"));
    }

    private static Optional<String> textField(PkiOperationValue.ObjectValue object, String name) {
        PkiOperationValue value = object.fields().get(name);
        if (value == null) { return Optional.empty(); }
        if (!(value instanceof PkiOperationValue.Text text)) { throw invalid(); }
        return Optional.of(text.value());
    }

    private static Optional<Long> integerField(PkiOperationValue.ObjectValue object, String name) {
        PkiOperationValue value = object.fields().get(name);
        return value instanceof PkiOperationValue.IntegerValue integer ? Optional.of(integer.value())
                : Optional.empty();
    }

    private static boolean booleanField(PkiOperationValue.ObjectValue object, String name) {
        PkiOperationValue value = object.fields().get(name);
        if (!(value instanceof PkiOperationValue.BooleanValue bool)) { throw invalid(); }
        return bool.value();
    }

    private static Optional<PkiOperationValue.ObjectValue> objectField(PkiOperationValue.ObjectValue object,
            String name) {
        PkiOperationValue value = object.fields().get(name);
        if (value == null) { return Optional.empty(); }
        if (!(value instanceof PkiOperationValue.ObjectValue nested)) { throw invalid(); }
        return Optional.of(nested);
    }

    /** Signals a request exceeding the supported encoded envelope size. */
    /* default */ static final class RequestTooLargeException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
        /* default */ RequestTooLargeException() { super("Remote request exceeds the size limit"); }
    }

    /** Checks the request size before growing the in-memory encoding buffer. */
    private static final class BoundedRequestOutput extends ByteArrayOutputStream {
        private static final int MAXIMUM_BYTES = 16 * 1_048_576;

        // Keep the size check and inherited buffer write atomic on the same monitor.
        @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
        @Override
        public synchronized void write(int value) {
            if (count == MAXIMUM_BYTES) { throw new RequestTooLargeException(); }
            super.write(value);
        }

        // Keep the size check and inherited buffer write atomic on the same monitor.
        @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
        @Override
        public synchronized void write(byte[] bytes, int offset, int length) {
            if (length > MAXIMUM_BYTES - count) { throw new RequestTooLargeException(); }
            super.write(bytes, offset, length);
        }
    }

    private static String requiredText(PkiOperationValue.ObjectValue object, String name) {
        String value = textField(object, name).orElseThrow(PkiRemoteEnvelope::invalid);
        if (value.isBlank()) { throw invalid(); }
        return value;
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Invalid remote response envelope");
    }

    /**
     * Parsed version-1 response envelope.
     *
     * @param version protocol version, when present
     * @param operation stable operation identity, when present
     * @param status terminal status token, when present
     * @param result structured result view, when present
     * @param failure structured failure view, when present
     */
    /* default */ record ResponseEnvelope(Optional<Long> version, Optional<String> operation, Optional<String> status,
            Optional<PkiOperationValue.ObjectValue> result, Optional<Failure> failure) {
    }

    /**
     * Parsed server failure view.
     *
     * @param classification stable failure classification
     * @param code stable failure code
     * @param messageKey optional localizable message key
     * @param recoveryRequired whether durable recovery is required
     * @param reconciliationRequired whether external reconciliation is required
     */
    /* default */ record Failure(String classification, String code, Optional<String> messageKey, boolean recoveryRequired,
            boolean reconciliationRequired) {
    }
}
