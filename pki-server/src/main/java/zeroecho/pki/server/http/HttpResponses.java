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
package zeroecho.pki.server.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Objects;

import tools.jackson.core.JsonGenerator;
import tools.jackson.core.json.JsonFactory;
import zeroecho.pki.application.PkiOperationFailure;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.ServerOperationGateway;

/** Deterministic versioned transport response and status mapping. */
@SuppressWarnings("PMD")
final class HttpResponses {
    record Response(int statusCode, byte[] body) {
        Response { body = Objects.requireNonNull(body, "body").clone(); }
        @Override public byte[] body() { return body.clone(); }
    }

    private static final JsonFactory JSON = JsonFactory.builder().build();

    private HttpResponses() {
    }

    static Response gateway(String requestId, String operation, ServerOperationGateway.Outcome outcome) {
        return switch (outcome) {
            case ServerOperationGateway.Outcome.Executed executed -> backend(requestId, operation,
                    executed.outcome());
            case ServerOperationGateway.Outcome.Denied denied -> failure(403, requestId, operation,
                    "DENIED", "AUTHORIZATION_DENIED", denied.code().name(), false, false);
            case ServerOperationGateway.Outcome.ApprovalRequired required -> successLikeFailure(409, requestId,
                    operation, "APPROVAL_REQUIRED", "APPROVAL_REQUIRED", required.operationCommitment());
        };
    }

    static Response failure(int status, String requestId, String operation, String classification,
            String code, String messageKey, boolean recoveryRequired, boolean reconciliationRequired) {
        return encode(status, requestId, operation, "FAILED", null,
                new Failure(classification, code, messageKey, recoveryRequired, reconciliationRequired));
    }

    static Response minimal(int status, String requestId, String operation, String state) {
        return encode(status, requestId, operation, "SUCCEEDED",
                new PkiOperationValue.ObjectValue(java.util.Map.of("state", new PkiOperationValue.Text(state))),
                null);
    }

    static Response success(String requestId, String operation, PkiOperationValue.ObjectValue result) {
        return encode(200, requestId, operation, "SUCCEEDED", result, null);
    }

    private static Response backend(String requestId, String operation, PkiOperationOutcome outcome) {
        return switch (outcome) {
            case PkiOperationOutcome.Success success -> encode(200, requestId, operation, "SUCCEEDED",
                    new PkiOperationValue.ObjectValue(success.result().fields()), null);
            case PkiOperationOutcome.Failure failure -> {
                int status = status(failure.classification());
                boolean recovery = failure.classification() == PkiOperationFailure.RECOVERY_REQUIRED;
                boolean reconciliation = failure.classification() == PkiOperationFailure.EXTERNAL_OUTCOME_UNKNOWN;
                yield failure(status, requestId, operation, failure.classification().name(), failure.code(),
                        failure.code(), recovery, reconciliation);
            }
        };
    }

    private static Response successLikeFailure(int status, String requestId, String operation,
            String classification, String code, String commitment) {
        PkiOperationValue result = new PkiOperationValue.ObjectValue(java.util.Map.of(
                "operationCommitment", new PkiOperationValue.Text(commitment)));
        return encode(status, requestId, operation, classification, result,
                new Failure(classification, code, code, false, false));
    }

    private static int status(PkiOperationFailure failure) {
        return switch (failure) {
            case VALIDATION_FAILURE -> 400;
            case POLICY_REJECTION -> 422;
            case NOT_FOUND -> 404;
            case CONFLICT -> 409;
            case RECOVERY_REQUIRED, RESOURCE_FAILURE -> 503;
            case EXTERNAL_OUTCOME_UNKNOWN -> 409;
            case CANCELLED -> 504;
            case INTERNAL_FAILURE -> 500;
        };
    }

    private static Response encode(int status, String requestId, String operation, String outcome,
            PkiOperationValue result, Failure failure) {
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            try (JsonGenerator generator = JSON.createGenerator(output)) {
                generator.writeStartObject();
                generator.writeNumberProperty("version", 1);
                generator.writeStringProperty("requestId", requestId);
                generator.writeStringProperty("operation", operation);
                generator.writeStringProperty("status", outcome);
                generator.writeName("result");
                if (result == null) generator.writeNull(); else StrictJson.write(generator, result);
                generator.writeName("failure");
                if (failure == null) generator.writeNull(); else writeFailure(generator, failure);
                generator.writeEndObject();
            }
            return new Response(status, output.toByteArray());
        } catch (IOException impossible) {
            throw new IllegalStateException("Safe HTTP response cannot be encoded");
        }
    }

    private static void writeFailure(JsonGenerator generator, Failure failure) throws IOException {
        generator.writeStartObject();
        generator.writeStringProperty("classification", failure.classification());
        generator.writeStringProperty("code", failure.code());
        generator.writeStringProperty("messageKey", failure.messageKey());
        generator.writeBooleanProperty("recoveryRequired", failure.recoveryRequired());
        generator.writeBooleanProperty("reconciliationRequired", failure.reconciliationRequired());
        generator.writeEndObject();
    }

    private record Failure(String classification, String code, String messageKey,
            boolean recoveryRequired, boolean reconciliationRequired) { }
}
