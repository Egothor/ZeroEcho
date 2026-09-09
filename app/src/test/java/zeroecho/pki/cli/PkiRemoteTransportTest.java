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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLException;

import org.junit.jupiter.api.Test;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.application.PkiOperationValue;

class PkiRemoteTransportTest {

    private static final CancellationSignal NOT_CANCELLED = () -> false;
    private static final Duration FAST_POLL = Duration.ofMillis(5);

    @Test
    void encodesRequestEnvelopeWithVersionScopeAndArguments() {
        System.out.println("encodesRequestEnvelopeWithVersionScopeAndArguments");
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        fields.put("credentialId", new PkiOperationValue.Text("cred-1"));
        fields.put("limit", new PkiOperationValue.IntegerValue(10));
        byte[] body = PkiRemoteEnvelope.encodeRequest(Optional.of("authority-7"), Optional.empty(),
                Optional.empty(), new PkiOperationValue.ObjectValue(fields));
        PkiOperationValue.ObjectValue parsed = (PkiOperationValue.ObjectValue) PkiCliJson.parse(body);
        assertEquals(1L, ((PkiOperationValue.IntegerValue) parsed.fields().get("version")).value());
        assertEquals("authority-7", ((PkiOperationValue.Text) parsed.fields().get("authorityId")).value());
        assertTrue(parsed.fields().get("approvalId") == null);
        PkiOperationValue.ObjectValue arguments = (PkiOperationValue.ObjectValue) parsed.fields().get("arguments");
        assertEquals("cred-1", ((PkiOperationValue.Text) arguments.fields().get("credentialId")).value());
        System.out.println("...ok");
    }

    @Test
    void decodesFailureEnvelope() {
        System.out.println("decodesFailureEnvelope");
        byte[] body = ("{\"version\":1,\"operation\":\"credential.inspect\",\"status\":\"FAILED\","
                + "\"failure\":{\"classification\":\"NOT_FOUND\",\"code\":\"OBJECT_NOT_FOUND\","
                + "\"recoveryRequired\":false,\"reconciliationRequired\":true}}").getBytes(StandardCharsets.UTF_8);
        PkiRemoteEnvelope.ResponseEnvelope envelope = PkiRemoteEnvelope.decodeResponse(body);
        assertEquals(Optional.of("FAILED"), envelope.status());
        assertEquals("NOT_FOUND", envelope.failure().orElseThrow().classification());
        assertTrue(envelope.failure().orElseThrow().reconciliationRequired());
        System.out.println("...ok");
    }

    @Test
    void succeededExchangeMapsToSuccessExit() throws Exception {
        System.out.println("succeededExchangeMapsToSuccessExit");
        FakeExchange exchange = new FakeExchange(request -> ok("{\"version\":1,\"operation\":\"credential.inspect\","
                + "\"status\":\"SUCCEEDED\",\"result\":{\"credentialId\":\"cred-1\"}}"));
        PkiRemoteResult result = transport(exchange, Duration.ZERO).submit("credential.inspect", empty(),
                Optional.empty(), Optional.empty(), Optional.empty(), NOT_CANCELLED);
        assertTrue(result instanceof PkiRemoteResult.Succeeded);
        assertEquals(PkiExitCodes.SUCCESS, PkiRemoteExitCodes.from(result));
        assertEquals("/admin/v1/operations/credential.inspect", exchange.requests.get(0).path());
        System.out.println("...ok");
    }

    @Test
    void failureClassificationsMapToLocalExitCodes() throws Exception {
        System.out.println("failureClassificationsMapToLocalExitCodes");
        assertEquals(PkiExitCodes.VALIDATION_OR_POLICY, failureExit("VALIDATION_FAILURE"));
        assertEquals(PkiExitCodes.VALIDATION_OR_POLICY, failureExit("POLICY_REJECTION"));
        assertEquals(PkiExitCodes.VALIDATION_OR_POLICY, failureExit("AUTHORIZATION_DENIED"));
        assertEquals(PkiExitCodes.NOT_FOUND_OR_CONFLICT, failureExit("NOT_FOUND"));
        assertEquals(PkiExitCodes.NOT_FOUND_OR_CONFLICT, failureExit("CONFLICT"));
        assertEquals(PkiExitCodes.RECOVERY_REQUIRED, failureExit("RECOVERY_REQUIRED"));
        assertEquals(PkiExitCodes.EXTERNAL_OUTCOME_UNKNOWN, failureExit("EXTERNAL_OUTCOME_UNKNOWN"));
        assertEquals(PkiExitCodes.EXTERNAL_OUTCOME_UNKNOWN, failureExit("DEADLINE_EXCEEDED"));
        assertEquals(PkiExitCodes.RESOURCE_FAILURE, failureExit("RESOURCE_FAILURE"));
        assertEquals(PkiExitCodes.RESOURCE_FAILURE, failureExit("OVERLOADED"));
        assertEquals(PkiExitCodes.CANCELLED, failureExit("CANCELLED"));
        assertEquals(PkiExitCodes.INTERNAL_FAILURE, failureExit("INTERNAL_FAILURE"));
        System.out.println("...ok");
    }

    @Test
    void forbiddenHttpStatusMapsToPolicyExitWithoutEnvelope() throws Exception {
        System.out.println("forbiddenHttpStatusMapsToPolicyExitWithoutEnvelope");
        FakeExchange exchange = new FakeExchange(request -> new PkiHttpExchange.Response(403, Optional.empty(),
                new byte[0]));
        PkiRemoteResult result = transport(exchange, Duration.ZERO).submit("security.role.list", empty(),
                Optional.empty(), Optional.empty(), Optional.empty(), NOT_CANCELLED);
        assertEquals(PkiExitCodes.VALIDATION_OR_POLICY, PkiRemoteExitCodes.from(result));
        System.out.println("...ok");
    }

    @Test
    void unauthenticatedResponseIsAConfigurationFailure() {
        System.out.println("unauthenticatedResponseIsAConfigurationFailure");
        FakeExchange exchange = new FakeExchange(request -> new PkiHttpExchange.Response(401, Optional.empty(),
                new byte[0]));
        PkiRemoteTransportException failure = assertThrows(PkiRemoteTransportException.class,
                () -> transport(exchange, Duration.ZERO).submit("ca.list", empty(), Optional.empty(),
                        Optional.empty(), Optional.empty(), NOT_CANCELLED));
        assertEquals(PkiExitCodes.CONFIGURATION_FAILURE, failure.exitCode());
        System.out.println("...ok");
    }

    @Test
    void tlsFailureIsConfigurationAndNetworkFailureIsResource() {
        System.out.println("tlsFailureIsConfigurationAndNetworkFailureIsResource");
        PkiRemoteTransportException tls = assertThrows(PkiRemoteTransportException.class,
                () -> transport(new FakeExchange(request -> {
                    throw new SSLException("handshake");
                }), Duration.ZERO).submit("ca.list", empty(), Optional.empty(), Optional.empty(),
                        Optional.empty(), NOT_CANCELLED));
        PkiRemoteTransportException network = assertThrows(PkiRemoteTransportException.class,
                () -> transport(new FakeExchange(request -> {
                    throw new IOException("connection refused");
                }), Duration.ZERO).submit("ca.list", empty(), Optional.empty(), Optional.empty(),
                        Optional.empty(), NOT_CANCELLED));
        assertEquals(PkiExitCodes.CONFIGURATION_FAILURE, tls.exitCode());
        assertEquals(PkiExitCodes.RESOURCE_FAILURE, network.exitCode());
        System.out.println("...ok");
    }

    @Test
    void approvalRequiredSurfacesCommitmentAndExitsFour() throws Exception {
        System.out.println("approvalRequiredSurfacesCommitmentAndExitsFour");
        String commitment = "0".repeat(64);
        FakeExchange exchange = new FakeExchange(request -> new PkiHttpExchange.Response(409, Optional.empty(),
                ("{\"version\":1,\"operation\":\"credential.issue\",\"status\":\"APPROVAL_REQUIRED\","
                        + "\"result\":{\"operationCommitment\":\"" + commitment + "\"}}")
                        .getBytes(StandardCharsets.UTF_8)));
        PkiRemoteResult result = transport(exchange, Duration.ZERO).submit("credential.issue", empty(),
                Optional.of("authority-1"), Optional.empty(), Optional.empty(), NOT_CANCELLED);
        assertTrue(result instanceof PkiRemoteResult.ApprovalRequired);
        assertEquals(commitment, ((PkiRemoteResult.ApprovalRequired) result).operationCommitment());
        assertEquals(PkiExitCodes.VALIDATION_OR_POLICY, PkiRemoteExitCodes.from(result));
        System.out.println("...ok");
    }

    @Test
    void pendingWithZeroWaitExitsExternalOutcomeUnknown() throws Exception {
        System.out.println("pendingWithZeroWaitExitsExternalOutcomeUnknown");
        FakeExchange exchange = new FakeExchange(request -> new PkiHttpExchange.Response(202,
                Optional.of("/admin/v1/signing-operations/sign-9"),
                "{\"version\":1,\"operation\":\"credential.issue\",\"status\":\"PENDING\",\"result\":{}}"
                        .getBytes(StandardCharsets.UTF_8)));
        PkiRemoteResult result = transport(exchange, Duration.ZERO).submit("credential.issue", empty(),
                Optional.of("authority-1"), Optional.empty(), Optional.empty(), NOT_CANCELLED);
        assertTrue(result instanceof PkiRemoteResult.Pending);
        assertEquals("sign-9", ((PkiRemoteResult.Pending) result).operationId());
        assertEquals(PkiExitCodes.EXTERNAL_OUTCOME_UNKNOWN, PkiRemoteExitCodes.from(result));
        System.out.println("...ok");
    }

    @Test
    void pendingResolvesByPollingSigningOperation() throws Exception {
        System.out.println("pendingResolvesByPollingSigningOperation");
        AtomicInteger polls = new AtomicInteger();
        FakeExchange exchange = new FakeExchange(request -> {
            if (request.method() == PkiHttpExchange.Method.POST) {
                return new PkiHttpExchange.Response(202, Optional.of("/admin/v1/signing-operations/sign-3"),
                        "{\"version\":1,\"operation\":\"credential.issue\",\"status\":\"PENDING\",\"result\":{}}"
                                .getBytes(StandardCharsets.UTF_8));
            }
            int count = polls.incrementAndGet();
            String status = count >= 2 ? "SUCCEEDED" : "PENDING";
            String result = count >= 2 ? "{\"credentialId\":\"cred-9\"}" : "{}";
            return new PkiHttpExchange.Response(200, Optional.empty(),
                    ("{\"version\":1,\"operation\":\"credential.issue\",\"status\":\"" + status
                            + "\",\"result\":" + result + "}").getBytes(StandardCharsets.UTF_8));
        });
        PkiRemoteResult result = transport(exchange, Duration.ofSeconds(5)).submit("credential.issue", empty(),
                Optional.of("authority-1"), Optional.empty(), Optional.empty(), NOT_CANCELLED);
        System.out.println("...polls=" + polls.get());
        assertTrue(result instanceof PkiRemoteResult.Succeeded);
        assertEquals(PkiExitCodes.SUCCESS, PkiRemoteExitCodes.from(result));
        assertTrue(polls.get() >= 2);
        assertEquals("/admin/v1/signing-operations/sign-3", exchange.requests.get(1).path());
        System.out.println("...ok");
    }

    @Test
    void unsupportedProtocolVersionFallsBackToHttpStatusClassification() throws Exception {
        System.out.println("unsupportedProtocolVersionFallsBackToHttpStatusClassification");
        FakeExchange exchange = new FakeExchange(request -> ok("{\"version\":99,\"operation\":\"ca.list\","
                + "\"status\":\"SUCCEEDED\",\"result\":{}}"));
        PkiRemoteResult result = transport(exchange, Duration.ZERO).submit("ca.list", empty(), Optional.empty(),
                Optional.empty(), Optional.empty(), NOT_CANCELLED);
        // Version 99 causes decodeResponse to throw; tryDecode returns empty; synthesize falls back
        // to HTTP 200 → Succeeded (safe: the HTTP contract is honoured, not the unrecognised envelope).
        assertTrue(result instanceof PkiRemoteResult.Succeeded, "Expected Succeeded from HTTP 200 fallback");
        System.out.println("...ok");
    }

    @Test
    void cancellationBeforeSubmitYieldsCancelledExit() throws Exception {
        System.out.println("cancellationBeforeSubmitYieldsCancelledExit");
        FakeExchange exchange = new FakeExchange(request -> ok("{}"));
        PkiRemoteResult result = transport(exchange, Duration.ZERO).submit("ca.list", empty(), Optional.empty(),
                Optional.empty(), Optional.empty(), () -> true);
        assertEquals(PkiExitCodes.CANCELLED, PkiRemoteExitCodes.from(result));
        assertTrue(exchange.requests.isEmpty());
        System.out.println("...ok");
    }

    private static int failureExit(String classification) throws Exception {
        FakeExchange exchange = new FakeExchange(request -> ok("{\"version\":1,\"operation\":\"op.x\","
                + "\"status\":\"FAILED\",\"failure\":{\"classification\":\"" + classification + "\","
                + "\"code\":\"REMOTE_FAILURE\",\"recoveryRequired\":false,\"reconciliationRequired\":false}}"));
        PkiRemoteResult result = transport(exchange, Duration.ZERO).submit("op.x", empty(), Optional.empty(),
                Optional.empty(), Optional.empty(), NOT_CANCELLED);
        return PkiRemoteExitCodes.from(result);
    }

    private static RemotePkiOperationTransport transport(FakeExchange exchange, Duration pendingWait) {
        return new RemotePkiOperationTransport(exchange, pendingWait, FAST_POLL);
    }

    private static PkiHttpExchange.Response ok(String json) {
        return new PkiHttpExchange.Response(200, Optional.empty(), json.getBytes(StandardCharsets.UTF_8));
    }

    private static PkiOperationValue.ObjectValue empty() {
        return new PkiOperationValue.ObjectValue(new LinkedHashMap<>());
    }

    /** Scripted in-memory exchange used to exercise the transport without real TLS or sockets. */
    private static final class FakeExchange implements PkiHttpExchange {
        private final Responder responder;
        private final List<Request> requests = new ArrayList<>();

        private FakeExchange(Responder responder) {
            this.responder = responder;
        }

        @Override
        public Response send(Request request) throws IOException {
            requests.add(request);
            return responder.respond(request);
        }
    }

    /** Response supplier that may raise an {@link IOException} to model transport faults. */
    @FunctionalInterface
    private interface Responder {
        PkiHttpExchange.Response respond(PkiHttpExchange.Request request) throws IOException;
    }
}
