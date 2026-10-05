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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

class PkiCliRemoteTest {

    private static final PkiCli.SessionOpener FORBIDDEN_OPENER = configuration -> {
        throw new AssertionError("Remote mode must not open a local session");
    };

    @Test
    void remoteModeIsSelectedByUrlAndClientMaterialAndPostsEnvelope() {
        System.out.println("remoteModeIsSelectedByUrlAndClientMaterialAndPostsEnvelope");
        FakeExchange[] captured = new FakeExchange[1];
        PkiCli.RemoteExchangeFactory factory = target -> {
            captured[0] = new FakeExchange(request -> ok("{\"version\":1,\"requestId\":\"test\",\"failure\":null,"
                    + "\"operation\":\"credential.inspect\",\"status\":\"SUCCEEDED\","
                    + "\"result\":{\"credentialId\":\"cred-1\"}}"));
            return captured[0];
        };
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int code = PkiCli.execute(new String[] { "credential.inspect", "--url", "https://pki.example.org:8443",
                "--client-keystore", "client.p12", "--client-keystore-password-env", "PKI_PW",
                "--credential-id", "cred-1", "--output", "json" }, output, FORBIDDEN_OPENER, () -> false, factory);
        String rendered = output.toString(StandardCharsets.UTF_8);
        String requestBody = new String(captured[0].requests.get(0).body().orElseThrow(), StandardCharsets.UTF_8);
        System.out.println("...exit=" + code);
        assertEquals(PkiExitCodes.SUCCESS, code);
        assertTrue(rendered.contains("\"mode\":\"remote\""));
        assertTrue(rendered.contains("\"credentialId\":\"cred-1\""));
        assertEquals("/admin/v1/operations/credential.inspect", captured[0].requests.get(0).path());
        assertTrue(requestBody.contains("\"version\":1"));
        assertTrue(requestBody.contains("\"credentialId\":\"cred-1\""));
        System.out.println("...ok");
    }

    @Test
    void urlWithoutClientMaterialIsInvalidInvocation() {
        System.out.println("urlWithoutClientMaterialIsInvalidInvocation");
        PkiCli.RemoteExchangeFactory factory = target -> {
            throw new AssertionError("transport must not be built for an invalid invocation");
        };
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int code = PkiCli.execute(new String[] { "credential.inspect", "--url", "https://pki.example.org:8443",
                "--credential-id", "cred-1" }, output, FORBIDDEN_OPENER, () -> false, factory);
        assertEquals(PkiExitCodes.INVALID_INVOCATION, code);
        System.out.println("...ok");
    }

    @Test
    void clientMaterialWithoutUrlIsInvalidInvocation() {
        System.out.println("clientMaterialWithoutUrlIsInvalidInvocation");
        PkiCli.RemoteExchangeFactory factory = target -> {
            throw new AssertionError("transport must not be built for an invalid invocation");
        };
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int code = PkiCli.execute(new String[] { "configuration.validate", "--client-cert", "client.pem" },
                output, FORBIDDEN_OPENER, () -> false, factory);
        assertEquals(PkiExitCodes.INVALID_INVOCATION, code);
        System.out.println("...ok");
    }

    @Test
    void remotePendingExitsForResumeWhenWaitIsZero() {
        System.out.println("remotePendingExitsForResumeWhenWaitIsZero");
        PkiCli.RemoteExchangeFactory factory = target -> new FakeExchange(request -> new PkiHttpExchange.Response(
                202, Optional.of("/admin/v1/signing-operations/sign-1"),
                "{\"version\":1,\"requestId\":\"test\",\"failure\":null,\"operation\":\"credential.issue\",\"status\":\"PENDING\",\"result\":{\"operationId\":\"sign-1\"}}"
                        .getBytes(StandardCharsets.UTF_8)));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int code = PkiCli.execute(new String[] { "credential.issue", "--url", "https://pki.example.org:8443",
                "--client-cert", "client.pem", "--client-key", "client.key", "--authority-id", "authority-1",
                "--arg", "issuerCaId=authority-1", "--request-id", "request-1", "--profile-id", "profile-1",
                "--pending-wait", "0", "--output", "json" }, output, FORBIDDEN_OPENER, () -> false, factory);
        String rendered = output.toString(StandardCharsets.UTF_8);
        assertEquals(PkiExitCodes.EXTERNAL_OUTCOME_UNKNOWN, code);
        assertTrue(rendered.contains("\"status\":\"PENDING\""));
        assertTrue(rendered.contains("sign-1"));
        System.out.println("...ok");
    }

    @Test
    void remoteModeReachesControlFamilyOperationWithGenericArguments() {
        System.out.println("remoteModeReachesControlFamilyOperationWithGenericArguments");
        FakeExchange[] captured = new FakeExchange[1];
        PkiCli.RemoteExchangeFactory factory = target -> {
            captured[0] = new FakeExchange(request -> ok("{\"version\":1,\"requestId\":\"test\",\"failure\":null,"
                    + "\"operation\":\"security.principal.list\",\"status\":\"SUCCEEDED\",\"result\":{}}"));
            return captured[0];
        };
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int code = PkiCli.execute(new String[] { "security.principal.list", "--url",
                "https://pki.example.org:8443", "--client-keystore", "client.p12",
                "--client-keystore-password-env", "PKI_PW", "--arg", "role=admin", "--arg-int", "limit=25",
                "--arg-int", "offset=0",
                "--output", "json" }, output, FORBIDDEN_OPENER, () -> false, factory);
        String requestBody = new String(captured[0].requests.get(0).body().orElseThrow(), StandardCharsets.UTF_8);
        assertEquals(PkiExitCodes.SUCCESS, code);
        assertEquals("/admin/v1/operations/security.principal.list", captured[0].requests.get(0).path());
        assertTrue(requestBody.contains("\"role\":\"admin\""));
        assertTrue(requestBody.contains("\"limit\":25"));
        System.out.println("...ok");
    }

    @Test
    void helpDocumentsRemoteModeAndSelectionRule() {
        System.out.println("helpDocumentsRemoteModeAndSelectionRule");
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int code = PkiCli.execute(new String[] { "--help" }, output);
        String help = output.toString(StandardCharsets.UTF_8);
        assertEquals(PkiExitCodes.SUCCESS, code);
        assertTrue(help.contains("--url"));
        assertTrue(help.contains("--client-keystore"));
        assertTrue(help.contains("Mode selection"));
        System.out.println("...ok");
    }

    @Test
    void localModeStillOpensSessionWhenNoUrlSupplied() {
        System.out.println("localModeStillOpensSessionWhenNoUrlSupplied");
        boolean[] opened = { false };
        PkiCli.SessionOpener opener = configuration -> {
            opened[0] = true;
            throw new IllegalArgumentException("configuration rejected");
        };
        PkiCli.RemoteExchangeFactory factory = target -> {
            throw new AssertionError("remote transport must not be built in local mode");
        };
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int code = PkiCli.execute(new String[] { "configuration.validate", "--config", "missing-config.json" },
                output, opener, () -> false, factory);
        // The configuration file is missing, so the configuration read fails before the session opens.
        assertEquals(PkiExitCodes.CONFIGURATION_FAILURE, code);
        System.out.println("...opened=" + opened[0] + " ok");
    }

    @Test
    void rejectsConflictingDuplicateIncompleteAndDeferredOptionsBeforeOpeningAnything() {
        String[][] cases = {
            { "ca.list", "--url", "https://pki.example", "--client-keystore", "client.p12", "--config", "missing" },
            { "ca.list", "--url", "https://pki.example", "--url", "https://other", "--client-keystore", "client.p12" },
            { "ca.list", "--url", "https://pki.example", "--client-cert", "client.pem" },
            { "ca.list", "--url", "https://pki.example", "--client-keystore", "client.p12", "--limit", "1", "--arg-int", "limit=2" },
            { "ca.list", "--config", "missing", "--pending-wait", "0" },
            { "signing.operation.complete", "--url", "https://pki.example", "--client-keystore", "client.p12", "--operation-id", "id" },
            { "signing.operation.inspect", "--url", "https://pki.example", "--client-keystore", "client.p12", "--operation-id", "id", "--pending-wait", "0" },
            { "signing.operation.inspect", "--url", "https://pki.example", "--client-keystore", "client.p12", "--operation-id", "id", "--approval-id", "approval" }
        };
        for (String[] arguments : cases) {
            String[] json = java.util.Arrays.copyOf(arguments, arguments.length + 2);
            json[arguments.length] = "--output";
            json[arguments.length + 1] = "json";
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            assertEquals(2, PkiCli.execute(json, output, FORBIDDEN_OPENER, () -> false,
                    target -> { throw new AssertionError("Invalid invocation opened transport"); }));
            assertTrue(output.toString(StandardCharsets.UTF_8).contains("\"code\":\"INVOCATION_INVALID\""));
        }
    }

    @Test
    void malformedRemoteOperationNamesFailBeforeExchange() {
        for (String operation : List.of("abc", "a.", "profile.list--all", "profile.-list", "a".repeat(129) + ".b")) {
            assertEquals(2, PkiCli.execute(new String[] { operation, "--url", "https://pki.example",
                    "--client-keystore", "client.p12" }, new ByteArrayOutputStream(), FORBIDDEN_OPENER, () -> false,
                    target -> { throw new AssertionError("Malformed name opened exchange"); }));
        }
    }

    @Test
    void hyphenatedRemoteOperationsAndOptionLookingValuesRemainIntact() {
        FakeExchange[] captured = new FakeExchange[1];
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int code = PkiCli.execute(new String[] { "profile.list-all", "--url", "https://pki.example",
                "--client-keystore", "client.p12", "--subject-ref", "--url", "--expected-lifecycle-revision", "7",
                "--arg-int", "limit=25",
                "--output", "json" }, output, FORBIDDEN_OPENER, () -> false, target -> {
                    captured[0] = new FakeExchange(request -> ok("{\"version\":1,\"requestId\":\"test\",\"failure\":null,\"operation\":\"profile.list-all\","
                            + "\"status\":\"SUCCEEDED\",\"result\":{}}"));
                    return captured[0];
                });
        assertEquals(0, code);
        String body = new String(captured[0].requests.get(0).body().orElseThrow(), StandardCharsets.UTF_8);
        assertTrue(body.contains("\"subjectRef\":\"--url\""));
        assertTrue(body.contains("\"expectedLifecycleRevision\":7"));
        assertEquals("/admin/v1/operations/profile.list-all", captured[0].requests.get(0).path());
    }

    @Test
    void explicitInspectionUsesOnlyGetAndRetainsPendingReceipt() {
        FakeExchange[] exchange = new FakeExchange[1];
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int exit = PkiCli.execute(new String[] { "signing.operation.inspect", "--url", "https://pki.example",
                "--client-keystore", "client.p12", "--operation-id", "sign-1", "--output", "json" }, output,
                FORBIDDEN_OPENER, () -> false, target -> {
                    exchange[0] = new FakeExchange(request -> new PkiHttpExchange.Response(202, Optional.empty(),
                            ("{\"version\":1,\"requestId\":\"test\",\"operation\":\"signing.operation\","
                            + "\"status\":\"PENDING\",\"result\":{\"operationId\":\"sign-1\"},\"failure\":null}")
                            .getBytes(StandardCharsets.UTF_8)));
                    return exchange[0];
                });
        assertEquals(7, exit);
        assertEquals(1, exchange[0].requests.size());
        assertEquals(PkiHttpExchange.Method.GET, exchange[0].requests.getFirst().method());
        assertEquals("/admin/v1/signing-operations/sign-1", exchange[0].requests.getFirst().path());
        assertTrue(output.toString(StandardCharsets.UTF_8).contains("\"operationId\":\"sign-1\""));
    }

    @Test
    void structuredArgumentsRoundTripThroughCliWithoutOpeningLocalSession() {
        FakeExchange[] exchange = new FakeExchange[1];
        int exit = PkiCli.execute(new String[] { "security.approval.request", "--url", "https://pki.example",
                "--arg", "approvalId=approval-1", "--arg", "targetOperation=future.operation",
                "--client-keystore", "client.p12", "--arg-json", "targetArguments={\"names\":[\"one\",\"two\"],\"limit\":2,\"active\":true}" },
                new ByteArrayOutputStream(), FORBIDDEN_OPENER, () -> false, target -> {
                    exchange[0] = new FakeExchange(request -> ok("{\"version\":1,\"requestId\":\"test\","
                            + "\"operation\":\"security.approval.request\",\"status\":\"SUCCEEDED\",\"result\":{},\"failure\":null}"));
                    return exchange[0];
                });
        assertEquals(0, exit);
        String body = new String(exchange[0].requests.getFirst().body().orElseThrow(), StandardCharsets.UTF_8);
        assertTrue(body.contains("\"targetArguments\":{\"names\":[\"one\",\"two\"],\"limit\":2,\"active\":true}"));
    }

    @Test
    void missingKnownRequiredFieldIsInvalidBeforeOpeningRemoteExchange() {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int exit = PkiCli.execute(new String[] { "profile.inspect", "--url", "https://pki.example",
                "--client-keystore", "client.p12", "--output", "json" }, output, FORBIDDEN_OPENER,
                () -> false, target -> { throw new AssertionError("Invalid invocation opened exchange"); });
        assertEquals(PkiExitCodes.INVALID_INVOCATION, exit);
        assertTrue(output.toString(StandardCharsets.UTF_8).contains("INVOCATION_INVALID"));
    }

    private static PkiHttpExchange.Response ok(String json) {
        return new PkiHttpExchange.Response(200, Optional.empty(), json.getBytes(StandardCharsets.UTF_8));
    }

    /** Scripted exchange returned by the test remote-exchange factory. */
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

    /** Response supplier that may raise an {@link IOException}. */
    @FunctionalInterface
    private interface Responder {
        PkiHttpExchange.Response respond(PkiHttpExchange.Request request) throws IOException;
    }
}
