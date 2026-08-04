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
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.server.http.MutualTlsAuthenticator;
import zeroecho.pki.server.http.TestTlsProvider;
import zeroecho.pki.server.spi.PkiServerAuthenticationContext;
import zeroecho.pki.server.spi.PkiServerAuthenticationResult;

/** Mutual-TLS authentication, HTTPS framing, gateway and lifecycle integration tests. */
class PkiHttpsServerTest {
    @TempDir java.nio.file.Path temporaryDirectory;

    @Test
    void rejectsInsecureConfigurationAndStrictJsonFraming() throws Exception {
        System.out.println("rejectsInsecureConfigurationAndStrictJsonFraming");
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        PkiServerConfiguration valid = HttpServerTestSupport.configuration(temporaryDirectory,
                tls.clientCertificate());
        assertThrows(IllegalArgumentException.class, () -> new PkiServerConfiguration(valid.version(),
                valid.serverName(), valid.realm(), new PkiServerConfiguration.Listener(valid.listener().address(),
                        valid.listener().port(), valid.listener().tlsProvider(), false, 16_384, 65_536),
                valid.authentication(), valid.execution(), valid.runtime()));
        assertThrows(IllegalArgumentException.class, () -> PkiServerConfigurationCodec.decode(
                "{\"version\":1,\"version\":1}".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertThrows(IllegalArgumentException.class, () -> new PkiServerConfiguration.Execution(1, 1, 1, 1,
                1, Duration.ofSeconds(2), Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofSeconds(1)));
        System.out.println("...strict-security-fields=true");
        System.out.println("...ok");
    }

    @Test
    void authenticatesCryptographicCommitmentAndRejectsAmbiguityAndDisabledPrincipal() throws Exception {
        System.out.println("authenticatesCryptographicCommitmentAndRejectsAmbiguityAndDisabledPrincipal");
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(tls.clientCertificate().getEncoded()));
        PkiServerConfiguration.ClientCertificateMapping first = mapping("first", "enabled", digest);
        PkiServerAuthenticationContext context = new PkiServerAuthenticationContext(
                List.of(tls.clientCertificate()), "TLSv1.3", "TLS_AES_128_GCM_SHA256", "request-identifier1",
                ServerTestSupport.REALM);
        MutualTlsAuthenticator valid = new MutualTlsAuthenticator(List.of(first),
                ignored -> ServerTestSupport.principal("enabled"), ServerTestSupport.CLOCK);
        assertInstanceOf(PkiServerAuthenticationResult.Authenticated.class, valid.authenticate(context));
        MutualTlsAuthenticator ambiguous = new MutualTlsAuthenticator(
                List.of(first, mapping("second", "enabled", digest)),
                ignored -> ServerTestSupport.principal("enabled"), ServerTestSupport.CLOCK);
        PkiServerAuthenticationResult rejected = ambiguous.authenticate(context);
        assertEquals(PkiServerAuthenticationResult.Code.MAPPING_AMBIGUOUS,
                ((PkiServerAuthenticationResult.Rejected) rejected).code());
        MutualTlsAuthenticator disabled = new MutualTlsAuthenticator(List.of(first), ignored ->
                new SecurityPrincipal("enabled", SecurityPrincipal.Type.USER, "disabled", Optional.empty(),
                        Map.of(), false), ServerTestSupport.CLOCK);
        assertEquals(PkiServerAuthenticationResult.Code.PRINCIPAL_DISABLED,
                ((PkiServerAuthenticationResult.Rejected) disabled.authenticate(context)).code());
        System.out.println("...subject-string-authority=false");
        System.out.println("...ok");
    }

    @Test
    void servesAuthenticatedHealthRealmDiscoveryAndGatewayOperation() throws Exception {
        System.out.println("servesAuthenticatedHealthRealmDiscoveryAndGatewayOperation");
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        PkiServerConfiguration configuration = HttpServerTestSupport.configuration(temporaryDirectory,
                tls.clientCertificate());
        seed(configuration);
        PkiHttpsServer server = PkiHttpsServer.start(configuration, PkiSessionRuntimeDependencies.none(),
                ServerTestSupport.CLOCK, HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader());
        try {
            HttpClient client = HttpClient.newBuilder().sslContext(tls.clientContext()).build();
            URI base = URI.create("https://localhost:" + server.address().getPort());
            HttpResponse<String> live = get(client, base.resolve("/health/live"));
            assertEquals(200, live.statusCode());
            assertEquals(live.headers().firstValue("X-ZeroEcho-Request-Id").orElseThrow().length() >= 16, true);
            HttpResponse<String> ready = get(client, base.resolve("/health/ready"));
            assertEquals(200, ready.statusCode());
            HttpResponse<String> realm = get(client, base.resolve("/admin/v1/realm"));
            assertEquals(200, realm.statusCode());
            assertTrue(realm.body().contains("production"));
            HttpResponse<String> operations = get(client, base.resolve("/admin/v1/operations"));
            assertEquals(200, operations.statusCode());
            assertTrue(operations.body().contains("algorithm.binding.list"));
            HttpResponse<String> executed = post(client,
                    base.resolve("/admin/v1/operations/algorithm.binding.list"),
                    "{\"version\":1,\"arguments\":{\"limit\":10}}");
            assertEquals(200, executed.statusCode());
            assertTrue(executed.body().contains("\"status\":\"SUCCEEDED\""));
            HttpResponse<String> principalCreated = post(client,
                    base.resolve("/admin/v1/operations/security.principal.register"),
                    "{\"version\":1,\"arguments\":{\"principalId\":\"operator-b\",\"type\":\"USER\","
                            + "\"displayName\":\"Operator B\",\"enabled\":true}}");
            assertEquals(200, principalCreated.statusCode());
            HttpResponse<String> principalInspected = post(client,
                    base.resolve("/admin/v1/operations/security.principal.inspect"),
                    "{\"version\":1,\"arguments\":{\"principalId\":\"operator-b\"}}");
            assertEquals(200, principalInspected.statusCode());
            assertTrue(principalInspected.body().contains("operator-b"));
            HttpResponse<String> hidden = get(client, base.resolve("/admin/v1/operations/credential.issue"));
            assertEquals(404, hidden.statusCode());
            HttpResponse<String> malformed = post(client,
                    base.resolve("/admin/v1/operations/algorithm.binding.list"),
                    "{\"version\":1,\"version\":1,\"arguments\":{\"limit\":10}}");
            assertEquals(400, malformed.statusCode());
            System.out.println("...gateway-operation-status=" + executed.statusCode());
        } finally {
            server.close();
        }
        assertEquals(PkiHttpsServer.State.TERMINATED, server.state());
        assertFalse(Thread.getAllStackTraces().keySet().stream().anyMatch(thread -> thread.isAlive()
                && (thread.getName().startsWith("zeroecho-pki-https-")
                        || thread.getName().startsWith("zeroecho-pki-operation-"))));
        System.out.println("...ok");
    }

    @Test
    void rejectsClientWithoutCertificateBeforeGatewayInvocation() throws Exception {
        System.out.println("rejectsClientWithoutCertificateBeforeGatewayInvocation");
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        PkiServerConfiguration configuration = HttpServerTestSupport.configuration(temporaryDirectory,
                tls.clientCertificate());
        seed(configuration);
        try (PkiHttpsServer server = PkiHttpsServer.start(configuration, PkiSessionRuntimeDependencies.none(),
                ServerTestSupport.CLOCK, HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader())) {
            HttpClient client = HttpClient.newBuilder().sslContext(tls.anonymousContext()).build();
            URI uri = URI.create("https://localhost:" + server.address().getPort() + "/admin/v1/realm");
            assertThrows(java.io.IOException.class,
                    () -> client.send(HttpRequest.newBuilder(uri).GET().build(), HttpResponse.BodyHandlers.ofString()));
            System.out.println("...tls-client-certificate=required");
        }
        System.out.println("...ok");
    }

    @Test
    void packagedEntryPointProvidesHelpAndSafeValidationFailure() {
        System.out.println("packagedEntryPointProvidesHelpAndSafeValidationFailure");
        assertEquals(0, PkiServerMain.run(new String[] { "--help" }));
        assertEquals(0, PkiServerMain.run(new String[] { "--version" }));
        assertEquals(2, PkiServerMain.run(new String[] { "--config", temporaryDirectory.resolve("missing.json").toString(),
                "--validate-config" }));
        System.out.println("...listener-opened-in-validation=false");
        System.out.println("...ok");
    }

    private void seed(PkiServerConfiguration configuration) throws Exception {
        try (ServerRealmContext context = ServerRealmContext.open(configuration.realm(),
                PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, HttpServerTestSupport.random())) {
            context.createPrincipal(ServerTestSupport.principal("administrator"), "system");
            Permission.Scope realmScope = new Permission.Scope(ServerTestSupport.REALM, Optional.empty(),
                    Optional.empty(), Optional.empty());
            context.grant(ServerTestSupport.grant("realm-read", "administrator", Permission.Effect.ALLOW,
                    Permission.Action.REALM_READ, Permission.ResourceType.REALM, realmScope,
                    Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED), "system");
            context.grant(ServerTestSupport.grant("authority-list", "administrator", Permission.Effect.ALLOW,
                    Permission.Action.AUTHORITY_LIST, Permission.ResourceType.AUTHORITY, realmScope,
                    Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED), "system");
            context.grant(ServerTestSupport.grant("binding-read", "administrator", Permission.Effect.ALLOW,
                    Permission.Action.X509_BINDING_READ, Permission.ResourceType.X509_BINDING, realmScope,
                    Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED), "system");
            context.grant(ServerTestSupport.grant("principal-manage", "administrator", Permission.Effect.ALLOW,
                    Permission.Action.PRINCIPAL_MANAGE, Permission.ResourceType.PRINCIPAL, realmScope,
                    Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED), "system");
        }
    }

    private static PkiServerConfiguration.ClientCertificateMapping mapping(String id, String principal,
            String digest) {
        return new PkiServerConfiguration.ClientCertificateMapping(id, principal, Optional.of(digest),
                Optional.empty(), Optional.empty());
    }

    private static HttpResponse<String> get(HttpClient client, URI uri) throws Exception {
        return client.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> post(HttpClient client, URI uri, String body) throws Exception {
        return client.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }
}
