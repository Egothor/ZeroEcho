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
import java.util.Objects;

import tools.jackson.core.JsonGenerator;
import tools.jackson.core.ObjectWriteContext;
import tools.jackson.core.json.JsonFactory;
import zeroecho.pki.application.PkiOperationFailure;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.ServerOperationGateway;
import zeroecho.pki.server.ServerControlOperationOutcome;

/**
 * Deterministic versioned transport response and status mapping.
 */
final class HttpResponses {
    /**
     * Buffered HTTP response with explicit one-time-body and transport metadata ownership.
     *
     * @param statusCode HTTP response status
     * @param body response entity bytes; defensively copied
     * @param oneTimeSensitive whether retained entity bytes must be erased after delivery
     * @param capabilityId disclosure capability bound to one-time delivery, if any
     * @param statusLocation relative polling location, if any
     * @param contentType validated media type, optionally with the supported UTF-8 charset suffix
     * @param attachmentFileName validated attachment name, if any
     */
    record Response(int statusCode, byte[] body, boolean oneTimeSensitive,
            java.util.Optional<String> capabilityId, java.util.Optional<String> statusLocation,
            String contentType,java.util.Optional<String> attachmentFileName) {
        /**
         * Snapshots entity bytes and validates header-safe media and attachment metadata.
         *
         * @param statusCode HTTP response status
         * @param body response bytes; copied
         * @param oneTimeSensitive whether delivery must erase the retained body
         * @param capabilityId optional disclosure capability identity
         * @param statusLocation optional polling location
         * @param contentType response media type with optional UTF-8 charset suffix
         * @param attachmentFileName optional filename containing at most 96 safe ASCII characters
         * @throws NullPointerException if a required reference or optional container is null
         * @throws IllegalArgumentException if media type or attachment filename syntax is invalid
         */
        Response { body = Objects.requireNonNull(body, "body").clone();
            capabilityId = Objects.requireNonNull(capabilityId, "capabilityId");
            statusLocation = Objects.requireNonNull(statusLocation, "statusLocation");
            contentType=Objects.requireNonNull(contentType,"contentType");attachmentFileName=Objects.requireNonNull(attachmentFileName,"attachmentFileName");
            if(!contentType.matches("[a-zA-Z0-9!#$&^_.+-]+/[a-zA-Z0-9!#$&^_.+-]+(?:; charset=utf-8)?")
                    ||attachmentFileName.filter(value -> !value.matches("[a-zA-Z0-9._-]{1,96}")).isPresent())throw new IllegalArgumentException("Invalid response metadata"); }
        /**
         * Creates a JSON response with optional disclosure and polling metadata.
         *
         * @param statusCode HTTP response status
         * @param body entity bytes; copied
         * @param sensitive whether retained entity bytes require erasure after delivery
         * @param capabilityId optional one-time disclosure capability identity
         * @param location optional relative polling location
         * @throws NullPointerException if the body or an optional container is null
         */
        Response(int statusCode,byte[] body,boolean sensitive,java.util.Optional<String> capabilityId,java.util.Optional<String> location) {
            this(statusCode,body,sensitive,capabilityId,location,"application/json; charset=utf-8",java.util.Optional.empty());
        }
        /**
         * Creates an ordinary JSON response without disclosure or polling metadata.
         *
         * @param statusCode HTTP response status
         * @param body response entity bytes; copied
         * @throws NullPointerException if the body is null
         */
        Response(int statusCode, byte[] body) { this(statusCode, body, false,
                java.util.Optional.empty(), java.util.Optional.empty()); }
        /**
         * Copies the current response entity for transport delivery.
         *
         * @return caller-owned entity bytes; zeroed if a sensitive body was already cleared
         */
        @Override public byte[] body() { return body.clone(); }
        /**
         * Erases the retained entity when this response is marked one-time sensitive.
         *
         * <p>Previously returned copies remain the caller's responsibility.</p>
         */
        void clearSensitiveBody() { if (oneTimeSensitive) java.util.Arrays.fill(body, (byte) 0); }
    }

    /**
     * Creates a successful binary attachment response.
     *
     * @param content attachment bytes; copied
     * @param mediaType header-safe response media type
     * @param fileName attachment name containing at most 96 safe ASCII characters
     * @return HTTP 200 response with attachment metadata
     * @throws NullPointerException if any argument is null
     * @throws IllegalArgumentException if media type or filename syntax is invalid
     */
    static Response attachment(byte[] content,String mediaType,String fileName) {
        return new Response(200,content,false,java.util.Optional.empty(),java.util.Optional.empty(),mediaType,java.util.Optional.of(fileName));
    }

    private static final JsonFactory JSON = JsonFactory.builder().build();

    private HttpResponses() {
    }

    /**
     * Maps an authorized gateway outcome into the versioned administrative HTTP envelope.
     *
     * <p>A one-time disclosure result is consumed exactly once and its temporary token
     * bytes are erased after encoding.</p>
     *
     * @param requestId transport correlation identity
     * @param operation semantic operation identity
     * @param outcome gateway result, denial or approval requirement
     * @return response with the status, result and polling metadata appropriate to the outcome
     */
    static Response gateway(String requestId, String operation, ServerOperationGateway.Outcome outcome) {
        return switch (outcome) {
            case ServerOperationGateway.Outcome.Executed executed -> backend(requestId, operation,
                    executed.outcome());
            case ServerOperationGateway.Outcome.ControlExecuted executed -> control(requestId, operation,
                    executed.outcome());
            case ServerOperationGateway.Outcome.Denied denied -> failure(403, requestId, operation,
                    "DENIED", "AUTHORIZATION_DENIED", denied.code().name(), false, false);
            case ServerOperationGateway.Outcome.ApprovalRequired required -> successLikeFailure(409, requestId,
                    operation, "APPROVAL_REQUIRED", "APPROVAL_REQUIRED", required.operationCommitment());
        };
    }

    private static Response control(String requestId, String operation, ServerControlOperationOutcome outcome) {
        if (outcome instanceof ServerControlOperationOutcome.Ordinary ordinary) {
            return backend(requestId, operation, ordinary.outcome());
        }
        ServerControlOperationOutcome.OneTimeSensitive sensitive =
                (ServerControlOperationOutcome.OneTimeSensitive) outcome;
        byte[] token = sensitive.consumeToken();
        try {
            MapBuilder result = new MapBuilder(sensitive.safeResult().fields());
            String capabilityId = ((PkiOperationValue.Text) sensitive.safeResult().fields()
                    .get("capabilityId")).value();
            result.put("token", new PkiOperationValue.Text(
                    zeroecho.pki.server.DisclosureService.bearerCredential(capabilityId, token)));
            Response encoded = encode(200, requestId, operation, "SUCCEEDED",
                    new PkiOperationValue.ObjectValue(result.values()), null);
            return new Response(encoded.statusCode(), encoded.body(), true, java.util.Optional.of(capabilityId),
                    java.util.Optional.empty());
        } finally {
            java.util.Arrays.fill(token, (byte) 0);
        }
    }

    /**
     * Encodes a classified administrative failure with explicit recovery guidance flags.
     *
     * @param status HTTP failure status
     * @param requestId transport correlation identity
     * @param operation semantic operation identity
     * @param classification stable failure category
     * @param code stable failure code
     * @param messageKey safe message lookup key
     * @param recoveryRequired whether operator recovery is required
     * @param reconciliationRequired whether the external outcome must be reconciled
     * @return versioned failed-result JSON response
     */
    static Response failure(int status, String requestId, String operation, String classification,
            String code, String messageKey, boolean recoveryRequired, boolean reconciliationRequired) {
        return encode(status, requestId, operation, "FAILED", null,
                new Failure(classification, code, messageKey, recoveryRequired, reconciliationRequired));
    }

    /**
     * Encodes a successful administrative response carrying one state field.
     *
     * @param status HTTP response status
     * @param requestId transport correlation identity
     * @param operation semantic operation identity
     * @param state state label exposed in the result
     * @return versioned success response
     */
    static Response minimal(int status, String requestId, String operation, String state) {
        return encode(status, requestId, operation, "SUCCEEDED",
                new PkiOperationValue.ObjectValue(java.util.Map.of("state", new PkiOperationValue.Text(state))),
                null);
    }

    /**
     * Encodes a retained administrative request that has not yet terminalized.
     *
     * @param trace transport correlation identity
     * @param result safe retained-request projection
     * @return HTTP 202 pending response
     */
    static Response administrativeAccepted(String trace, PkiOperationValue.ObjectValue result) {
        return encode(202,trace,"administrative.request.submit","PENDING",result,null);
    }

    /**
     * Encodes accepted responder provisioning with its canonical retained-request location.
     *
     * @param trace transport correlation identity
     * @param result safe retained-request projection
     * @param canonicalRequestId canonical administrative request identity
     * @return HTTP 202 pending response carrying a relative polling location
     */
    static Response administrativeProvisioningAccepted(String trace,PkiOperationValue.ObjectValue result,String canonicalRequestId) {
        var response=administrativeAccepted(trace,result);
        return new Response(response.statusCode(),response.body(),false,java.util.Optional.empty(),
                java.util.Optional.of("/admin/v1/requests/"+canonicalRequestId));
    }
    /**
     * Encodes a responder-provisioning target conflict and identifies the retained winner.
     *
     * @param trace transport correlation identity
     * @param canonicalRequestId identity of the canonical conflicting request
     * @return HTTP 409 response with the canonical request identity and polling location
     */
    static Response administrativeProvisioningConflict(String trace,String canonicalRequestId) {
        var response=encode(409,trace,"administrative.request.submit","FAILED",new PkiOperationValue.ObjectValue(java.util.Map.of(
                "canonicalRequestId",new PkiOperationValue.Text(canonicalRequestId))),
                new Failure("CONFLICT","OCSP_PROVISIONING_TARGET_CONFLICT","OCSP_PROVISIONING_TARGET_CONFLICT",false,false));
        return new Response(response.statusCode(),response.body(),false,java.util.Optional.empty(),
                java.util.Optional.of("/admin/v1/requests/"+canonicalRequestId));
    }

    /**
     * Encodes a completed administrative operation.
     *
     * @param requestId transport correlation identity
     * @param operation semantic operation identity
     * @param result safe structured operation result
     * @return HTTP 200 versioned success response
     */
    static Response success(String requestId, String operation, PkiOperationValue.ObjectValue result) {
        return encode(200, requestId, operation, "SUCCEEDED", result, null);
    }

    private static Response backend(String requestId, String operation, PkiOperationOutcome outcome) {
        return switch (outcome) {
            case PkiOperationOutcome.Completed success -> encode(200, requestId, operation, "SUCCEEDED",
                    new PkiOperationValue.ObjectValue(success.result().fields()), null);
            case PkiOperationOutcome.Pending pending -> {
                PkiOperationValue result = new PkiOperationValue.ObjectValue(java.util.Map.of(
                        "operationId", new PkiOperationValue.Text(pending.operationId().value())));
                Response encoded = encode(202, requestId, operation, "PENDING", result, null);
                yield new Response(encoded.statusCode(), encoded.body(), false, java.util.Optional.empty(),
                        java.util.Optional.of("/admin/v1/signing-operations/" + pending.operationId().value()));
            }
            case PkiOperationOutcome.Failed failure -> {
                int status = status(failure.classification());
                boolean recovery = failure.classification() == PkiOperationFailure.RECOVERY_REQUIRED;
                boolean reconciliation = failure.classification() == PkiOperationFailure.EXTERNAL_OUTCOME_UNKNOWN;
                yield failure(status, requestId, operation, failure.classification().name(), failure.code(),
                        failure.code(), recovery, reconciliation);
            }
        };
    }

    /**
     * Encodes a signing-operation observation with sensitive-body erasure enabled.
     *
     * @param requestId transport correlation identity
     * @param outcome current authoritative signing-operation outcome
     * @return mapped response retaining any pending-operation polling location
     */
    static Response signingOperation(String requestId, PkiOperationOutcome outcome) {
        Response encoded = backend(requestId, "signing.operation", outcome);
        return new Response(encoded.statusCode(), encoded.body(), true,
                java.util.Optional.empty(), encoded.statusLocation());
    }

    /**
     * Encodes an unavailable signing-operation observation without disclosing an identity.
     *
     * @param requestId transport correlation identity
     * @return HTTP 404 response marked for body erasure after delivery
     */
    static Response signingNotFound(String requestId) {
        Response encoded = failure(404, requestId, "operation", "NOT_FOUND", "OPERATION_NOT_FOUND",
                "OPERATION_NOT_FOUND", false, false);
        return new Response(encoded.statusCode(), encoded.body(), true,
                java.util.Optional.empty(), java.util.Optional.empty());
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
            case OVERLOADED -> 429;
            case INTERNAL_FAILURE -> 500;
        };
    }

    private static Response encode(int status, String requestId, String operation, String outcome,
            PkiOperationValue result, Failure failure) {
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            try (JsonGenerator generator = JSON.createGenerator(ObjectWriteContext.empty(), output)) {
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

    private static final class MapBuilder {
        private final java.util.Map<String, PkiOperationValue> values = new java.util.LinkedHashMap<>();
        private MapBuilder(java.util.Map<String, PkiOperationValue> initial) { values.putAll(initial); }
        private void put(String key, PkiOperationValue value) { values.put(key, value); }
        private java.util.Map<String, PkiOperationValue> values() { return values; }
    }
}
