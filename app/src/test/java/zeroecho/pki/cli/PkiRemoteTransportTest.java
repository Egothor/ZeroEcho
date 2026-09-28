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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

import org.junit.jupiter.api.Test;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.application.PkiOperationValue;

class PkiRemoteTransportTest {
    private static final CancellationSignal ACTIVE = () -> false;
    private static final String DIGEST = "a".repeat(64);

    @Test
    void encodesRequestScopeAndTypedArguments() {
        byte[] body = PkiRemoteEnvelope.encodeRequest(Optional.of("authority"), Optional.of("approval"),
                Optional.of("2030-01-01T00:00:00Z"), new PkiOperationValue.ObjectValue(Map.of(
                        "limit", new PkiOperationValue.IntegerValue(10))));
        PkiOperationValue.ObjectValue parsed = (PkiOperationValue.ObjectValue) PkiCliJson.parse(body);
        assertEquals(new PkiOperationValue.IntegerValue(1), parsed.fields().get("version"));
        assertEquals(new PkiOperationValue.Text("approval"), parsed.fields().get("approvalId"));
    }

    @Test
    void realSuccessAndFailureNullSlotsAndServerDenialArePreserved() throws Exception {
        PkiRemoteResult success = submit(new Script(request -> success("ca.list", "{}")), Duration.ZERO, ACTIVE);
        assertEquals(0, PkiRemoteExitCodes.from(success));
        PkiRemoteResult failure = submit(new Script(request -> failure("ca.list", "DENIED", true, true)),
                Duration.ZERO, ACTIVE);
        assertEquals(4, PkiRemoteExitCodes.from(failure));
        assertTrue(((PkiRemoteResult.Failed) failure).recoveryRequired());
        assertTrue(((PkiRemoteResult.Failed) failure).reconciliationRequired());
    }

    @Test
    void failureClassificationsRetainStableExitCodes() throws Exception {
        Map<String, Integer> cases = Map.ofEntries(Map.entry("VALIDATION_FAILURE", 4), Map.entry("POLICY_REJECTION", 4),
                Map.entry("DENIED", 4), Map.entry("AUTHORIZATION_DENIED", 4), Map.entry("NOT_FOUND", 5),
                Map.entry("CONFLICT", 5), Map.entry("RECOVERY_REQUIRED", 6), Map.entry("EXTERNAL_OUTCOME_UNKNOWN", 7),
                Map.entry("DEADLINE_EXCEEDED", 7), Map.entry("RESOURCE_FAILURE", 8), Map.entry("OVERLOADED", 8),
                Map.entry("CANCELLED", 130), Map.entry("INTERNAL_FAILURE", 9));
        for (Map.Entry<String, Integer> entry : cases.entrySet()) {
            PkiRemoteResult result = submit(new Script(request -> failure("ca.list", entry.getKey(), false, false)),
                    Duration.ZERO, ACTIVE);
            assertEquals(entry.getValue(), PkiRemoteExitCodes.from(result));
        }
    }

    @Test
    void invalidVersionTypesNullsDuplicatesAndHttpConflictsNeverSucceed() {
        String valid = json("ca.list", "SUCCEEDED", "{}", "null");
        List<String> invalid = List.of("", "{}", "null", valid.replace("\"version\":1", "\"version\":99"),
                valid.replace("\"version\":1,", ""), valid.replace("\"version\":1", "\"version\":\"1\""),
                valid.replace("\"requestId\":\"test\",", ""), valid.replace("\"requestId\":\"test\"", "\"requestId\":17"), valid.replace("\"SUCCEEDED\"", "17"),
                valid.replace("\"failure\":null", "\"failure\":false"), valid + "{}",
                valid.replace("\"version\":1", "\"version\":1,\"version\":1"),
                valid.replace("\"result\":{}", "\"result\":null"),
                valid.replace("\"result\":{}", "\"result\":{\"nested\":null}"));
        for (String body : invalid) {
            assertProtocol(new Script(request -> response(200, body)));
        }
        for (int http : List.of(202, 409, 500)) assertProtocol(new Script(request -> response(http, valid)));
        assertProtocol(new Script(request -> response(403, "")));
        assertProtocol(new Script(request -> response(409, "{}")));
        assertProtocol(new Script(request -> success("wrong.operation", "{}")));
        assertProtocol(new Script(request -> success("signing.operation", completion("sign-1"))));
        String badFlag = json("ca.list", "FAILED", "null", failureJson("NOT_FOUND", false, false))
                .replace("\"recoveryRequired\":false", "\"recoveryRequired\":\"false\"");
        assertProtocol(new Script(request -> response(404, badFlag)));
    }

    @Test
    void approvalRequiresExplicitTypedStatusAndCommitment() throws Exception {
        Script exchange = new Script(request -> response(409, json("ca.list", "APPROVAL_REQUIRED",
                "{\"operationCommitment\":\"" + DIGEST + "\"}", failureJson("APPROVAL_REQUIRED", false, false))));
        PkiRemoteResult result = submit(exchange, Duration.ZERO, ACTIVE);
        assertEquals(4, PkiRemoteExitCodes.from(result));
        assertEquals(DIGEST, ((PkiRemoteResult.ApprovalRequired) result).operationCommitment());
        assertEquals(1, exchange.requests.size());
    }

    @Test
    void receiptComesOnlyFromBodyAndZeroWaitNeverPolls() throws Exception {
        Script exchange = new Script(request -> pending("ca.list", "sign-1"));
        PkiRemoteResult result = submit(exchange, Duration.ZERO, ACTIVE);
        assertEquals(7, PkiRemoteExitCodes.from(result));
        assertEquals("sign-1", ((PkiRemoteResult.Pending) result).operationId());
        assertEquals(1, exchange.requests.size());
        assertProtocol(new Script(request -> new PkiHttpExchange.Response(202,
                Optional.of("https://attacker.example/sign-1"), json("ca.list", "PENDING", "{}", "null")
                        .getBytes(StandardCharsets.UTF_8))));
        for (String id : List.of("", " ", "a/b", "a".repeat(513))) {
            assertProtocol(new Script(request -> pending("ca.list", id)));
        }
    }

    @Test
    void signsOnceAndPollsOnlySameReceiptThroughCompletion() throws Exception {
        Script exchange = new Script(request -> request.method() == PkiHttpExchange.Method.POST
                ? pending("ca.list", "sign-1") : success("signing.operation", completion("sign-1")));
        PkiRemoteResult result = submit(exchange, Duration.ofSeconds(1), ACTIVE);
        assertEquals(0, PkiRemoteExitCodes.from(result));
        assertEquals(Optional.of("sign-1"), ((PkiRemoteResult.Succeeded) result).operationId());
        assertEquals(List.of(PkiHttpExchange.Method.POST, PkiHttpExchange.Method.GET),
                exchange.requests.stream().map(PkiHttpExchange.Request::method).toList());
        assertEquals("/admin/v1/signing-operations/sign-1", exchange.requests.get(1).path());
        assertTrue(exchange.requests.get(1).timeout().compareTo(Duration.ofSeconds(1)) <= 0);
        for (PkiOutputMode mode : PkiOutputMode.values()) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            new PkiRemoteReporter().render(result, mode, output);
            assertTrue(output.toString(StandardCharsets.UTF_8).contains("sign-1"));
        }
    }

    @Test
    void changedReceiptOrMalformedCompletionRetainsPendingReceipt() throws Exception {
        for (String body : List.of(completion("changed"), "{\"operationId\":\"sign-1\"}",
                completion("sign-1").replace("ISSUANCE", "INVALID"),
                completion("sign-1").replace(DIGEST, "bad"))) {
            Script exchange = new Script(request -> request.method() == PkiHttpExchange.Method.POST
                    ? pending("ca.list", "sign-1") : success("signing.operation", body));
            assertPending(submit(exchange, Duration.ofSeconds(1), ACTIVE), 9);
            assertEquals(2, exchange.requests.size());
        }
        Script exchange = new Script(request -> request.method() == PkiHttpExchange.Method.POST
                ? pending("ca.list", "sign-1") : pending("signing.operation", "changed"));
        assertPending(submit(exchange, Duration.ofSeconds(1), ACTIVE), 9);
        Script wrongOperation = new Script(request -> request.method() == PkiHttpExchange.Method.POST
                ? pending("ca.list", "sign-1") : success("ca.list", completion("sign-1")));
        assertPending(submit(wrongOperation, Duration.ofSeconds(1), ACTIVE), 9);
    }

    @Test
    void postAcceptanceFailureRetainsReceiptAndServerRecoveryFlags() throws Exception {
        Script exchange = new Script(request -> request.method() == PkiHttpExchange.Method.POST
                ? pending("ca.list", "sign-1") : failure("operation", "RECOVERY_REQUIRED", true, true));
        PkiRemoteResult.Failed result = (PkiRemoteResult.Failed) submit(exchange, Duration.ofSeconds(1), ACTIVE);
        assertEquals(Optional.of("sign-1"), result.operationId());
        assertEquals(6, PkiRemoteExitCodes.from(result));
        assertTrue(result.recoveryRequired());
        assertTrue(result.reconciliationRequired());
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        new PkiRemoteReporter().render(result, PkiOutputMode.JSON, output);
        assertTrue(output.toString(StandardCharsets.UTF_8).contains("\"operationId\":\"sign-1\""));
    }

    @Test
    void pollingNetworkAndProtocolFailuresRetainReceiptWithoutRetry() throws Exception {
        for (boolean protocol : List.of(true, false)) {
            Script exchange = new Script(request -> {
                if (request.method() == PkiHttpExchange.Method.POST) return pending("ca.list", "sign-1");
                if (protocol) return response(200, "broken");
                throw new IOException("sensitive provider diagnostic");
            });
            PkiRemoteResult result = submit(exchange, Duration.ofSeconds(1), ACTIVE);
            assertPending(result, protocol ? 9 : 8);
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            new PkiRemoteReporter().render(result, PkiOutputMode.JSON, output);
            assertTrue(output.toString(StandardCharsets.UTF_8).contains("observationFailure"));
            assertFalse(output.toString(StandardCharsets.UTF_8).contains("sensitive"));
            assertEquals(2, exchange.requests.size());
        }
    }

    @Test
    void inspectionUsesOneGetAndEncodesDotSegmentsWithoutRoutingFromLocation() {
        for (String id : List.of("sign-1", ".", "..", "a?b#c")) {
            Script exchange = new Script(request -> pending("signing.operation", id));
            PkiRemoteResult result = transport(exchange, Duration.ofSeconds(1)).inspect(id, ACTIVE);
            assertEquals(7, PkiRemoteExitCodes.from(result));
            assertEquals(1, exchange.requests.size());
            assertEquals(PkiHttpExchange.Method.GET, exchange.requests.getFirst().method());
            assertFalse(exchange.requests.getFirst().path().endsWith("/.."));
            assertEquals(Duration.ofSeconds(60), exchange.requests.getFirst().timeout());
        }
    }

    @Test
    void waitBudgetExpiryAndCancellationNeverResubmitOrCancelBackend() throws Exception {
        Script exchange = new Script(request -> pending("ca.list", "sign-1"));
        PkiRemoteResult result = new RemotePkiOperationTransport(exchange, Duration.ofMillis(1), Duration.ofSeconds(1))
                .submit("ca.list", empty(), Optional.empty(), Optional.empty(), Optional.empty(), ACTIVE);
        assertPending(result, 7);
        assertEquals(1, exchange.requests.size());
        AtomicBoolean cancelled = new AtomicBoolean();
        Script cancelledExchange = new Script(request -> { cancelled.set(true); return pending("ca.list", "sign-1"); });
        assertPending(submit(cancelledExchange, Duration.ofSeconds(1), cancelled::get), 130);
        assertEquals(1, cancelledExchange.requests.size());
        Script budgetExchange = new Script(request -> {
            if (request.method() == PkiHttpExchange.Method.POST) return pending("ca.list", "sign-1");
            throw new HttpTimeoutException("budget exhausted");
        });
        assertPending(submit(budgetExchange, Duration.ofMillis(100), ACTIVE), 7);
    }

    @Test
    void pollingInterruptionRestoresFlagAndKeepsReceipt() throws Exception {
        Script exchange = new Script(request -> {
            if (request.method() == PkiHttpExchange.Method.POST) return pending("ca.list", "sign-1");
            Thread.currentThread().interrupt();
            throw new IOException("interrupted");
        });
        try {
            assertPending(submit(exchange, Duration.ofSeconds(1), ACTIVE), 130);
            assertTrue(Thread.currentThread().isInterrupted());
        } finally { Thread.interrupted(); }
    }

    @Test
    void unknownSubmissionAcceptanceHasNoInventedReceiptWhileHandshakeIsConfigurationFailure() throws Exception {
        for (IOException error : List.of(new IOException("connection lost"), new SSLException("after handshake"))) {
            Script exchange = new Script(request -> { throw error; });
            PkiRemoteResult result = submit(exchange, Duration.ZERO, ACTIVE);
            assertEquals(7, PkiRemoteExitCodes.from(result));
            assertTrue(((PkiRemoteResult.Failed) result).operationId().isEmpty());
            assertEquals(1, exchange.requests.size());
        }
        Script handshake = new Script(request -> { throw new SSLHandshakeException("handshake"); });
        assertEquals(3, assertThrows(PkiRemoteTransportException.class,
                () -> submit(handshake, Duration.ZERO, ACTIVE)).exitCode());
        assertEquals(3, assertThrows(PkiRemoteTransportException.class,
                () -> submit(new Script(request -> response(401, "")), Duration.ZERO, ACTIVE)).exitCode());
    }

    @Test
    void cancellationBeforeSubmitSendsNothingAndSigningSubmissionCannotSucceedSynchronously() throws Exception {
        Script exchange = new Script(request -> success("ca.create", completion("sign-1")));
        assertEquals(130, PkiRemoteExitCodes.from(submit(exchange, Duration.ZERO, () -> true)));
        assertTrue(exchange.requests.isEmpty());
        assertEquals(9, assertThrows(PkiRemoteTransportException.class, () -> transport(exchange, Duration.ZERO)
                .submit("ca.create", empty(), Optional.empty(), Optional.empty(), Optional.empty(), ACTIVE)).exitCode());
    }

    @Test
    void responseLimitsAcceptRealLargeResultsWithoutRelaxingConfiguration() {
        String longString = "x".repeat(5000);
        String response = json("credential.export", "SUCCEEDED", "{\"encoded\":\"" + longString + "\"}", "null");
        assertTrue(PkiRemoteEnvelope.decodeResponse(response.getBytes(StandardCharsets.UTF_8)).result().isPresent());
        assertThrows(IllegalArgumentException.class, () -> PkiCliJson.parse(("\"" + longString + "\"")
                .getBytes(StandardCharsets.UTF_8)));
        String values = String.join(",", java.util.Collections.nCopies(2049, "1"));
        String inventory = json("request.list", "SUCCEEDED", "{\"items\":[" + values + "]}", "null");
        assertTrue(PkiRemoteEnvelope.decodeResponse(inventory.getBytes(StandardCharsets.UTF_8)).result().isPresent());
    }

    private static void assertPending(PkiRemoteResult result, int exit) {
        assertTrue(result instanceof PkiRemoteResult.Pending);
        assertEquals("sign-1", ((PkiRemoteResult.Pending) result).operationId());
        assertEquals(exit, PkiRemoteExitCodes.from(result));
    }

    private static void assertProtocol(Script exchange) {
        assertEquals(9, assertThrows(PkiRemoteTransportException.class,
                () -> submit(exchange, Duration.ZERO, ACTIVE)).exitCode());
    }

    private static PkiRemoteResult submit(Script exchange, Duration wait, CancellationSignal cancellation)
            throws PkiRemoteTransportException {
        return transport(exchange, wait).submit("ca.list", empty(), Optional.empty(), Optional.empty(), Optional.empty(), cancellation);
    }

    private static RemotePkiOperationTransport transport(Script exchange, Duration wait) {
        return new RemotePkiOperationTransport(exchange, wait, Duration.ofMillis(1));
    }

    private static PkiOperationValue.ObjectValue empty() { return new PkiOperationValue.ObjectValue(Map.of()); }

    private static String completion(String id) {
        return "{\"operationId\":\"" + id + "\",\"kind\":\"ISSUANCE\",\"encoding\":\"DER\",\"resultSha256\":\"" + DIGEST + "\"}";
    }

    private static String json(String operation, String status, String result, String failure) {
        return "{\"version\":1,\"requestId\":\"test\",\"operation\":\"" + operation + "\",\"status\":\""
                + status + "\",\"result\":" + result + ",\"failure\":" + failure + "}";
    }

    private static String failureJson(String classification, boolean recovery, boolean reconciliation) {
        return "{\"classification\":\"" + classification + "\",\"code\":\"" + classification + "\",\"messageKey\":\"safe\","
                + "\"recoveryRequired\":" + recovery + ",\"reconciliationRequired\":" + reconciliation + "}";
    }

    private static PkiHttpExchange.Response failure(String operation, String classification, boolean recovery, boolean reconciliation) {
        return response(409, json(operation, "FAILED", "null", failureJson(classification, recovery, reconciliation)));
    }

    private static PkiHttpExchange.Response success(String operation, String result) {
        return response(200, json(operation, "SUCCEEDED", result, "null"));
    }

    private static PkiHttpExchange.Response pending(String operation, String id) {
        return response(202, json(operation, "PENDING", "{\"operationId\":\"" + id + "\"}", "null"));
    }

    private static PkiHttpExchange.Response response(int status, String body) {
        return new PkiHttpExchange.Response(status, Optional.empty(), body.getBytes(StandardCharsets.UTF_8));
    }

    private static final class Script implements PkiHttpExchange {
        private final Responder responder;
        private final List<Request> requests = new ArrayList<>();
        private Script(Responder responder) { this.responder = responder; }
        @Override public Response send(Request request) throws IOException { requests.add(request); return responder.respond(request); }
    }

    @FunctionalInterface
    private interface Responder { PkiHttpExchange.Response respond(PkiHttpExchange.Request request) throws IOException; }
}
