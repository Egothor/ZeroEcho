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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Base64;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.application.CredentialConfirmationProofAudience;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.impl.framework.x509.bc.SimpleAttributeSet;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.server.http.MutualTlsAuthenticator;
import zeroecho.pki.server.http.PkiHttpsTransport;
import zeroecho.pki.server.http.TestTlsProvider;
import zeroecho.pki.server.spi.PkiServerAuthenticationContext;
import zeroecho.pki.server.spi.PkiServerAuthenticationResult;
import zeroecho.pki.server.spi.PkiServerAuthenticator;

/** Mutual-TLS authentication, HTTPS framing, gateway and lifecycle integration tests. */
class PkiHttpsServerTest {
    @TempDir java.nio.file.Path temporaryDirectory;

    @Test
    void overlappingExternalCloseRunsOneSuccessfulAttempt() throws Exception {
        PkiServerConfiguration configuration = closeConfiguration();
        ServerRealmContext realm = mock(ServerRealmContext.class);
        PkiServerAuthenticator authenticator = mock(PkiServerAuthenticator.class);
        PkiHttpsTransport transport = mock(PkiHttpsTransport.class);
        PkiHttpsServer server = closeServer(configuration, realm, authenticator, transport);
        Duration graceful = configuration.execution().gracefulShutdown();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        doAnswer(invocation -> {
            entered.countDown();
            release.await();
            return null;
        }).when(transport).shutdown(graceful);

        try (ExecutorService callers = Executors.newFixedThreadPool(2)) {
            Future<?> owner = submitClose(callers, server, null);
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            AtomicReference<Thread> joiningThread = new AtomicReference<>();
            Future<?> joiner = submitClose(callers, server, joiningThread);
            awaitWaiting(joiningThread);
            release.countDown();
            owner.get(2, TimeUnit.SECONDS);
            joiner.get(2, TimeUnit.SECONDS);
        }
        server.close();
        assertEquals(PkiHttpsServer.State.TERMINATED, server.state());
        verify(transport, times(1)).shutdown(graceful);
        verify(realm, times(1)).close();
        verify(authenticator, times(1)).close();
    }

    @Test
    void concurrentDrainFailureIsSharedAndLaterRetryClosesDependenciesOnce() throws Exception {
        PkiServerConfiguration configuration = closeConfiguration();
        ServerRealmContext realm = mock(ServerRealmContext.class);
        PkiServerAuthenticator authenticator = mock(PkiServerAuthenticator.class);
        PkiHttpsTransport transport = mock(PkiHttpsTransport.class);
        PkiHttpsServer server = closeServer(configuration, realm, authenticator, transport);
        Duration graceful = configuration.execution().gracefulShutdown();
        CountDownLatch failedEntered = new CountDownLatch(1);
        CountDownLatch failedRelease = new CountDownLatch(1);
        CountDownLatch retryEntered = new CountDownLatch(1);
        CountDownLatch retryRelease = new CountDownLatch(1);
        AtomicReference<Boolean> first = new AtomicReference<>(true);
        IllegalStateException exact = new IllegalStateException("SERVER_EXECUTION_SHUTDOWN_TIMEOUT");
        doAnswer(invocation -> {
            if (first.getAndSet(false)) {
                failedEntered.countDown();
                failedRelease.await();
                throw exact;
            }
            retryEntered.countDown();
            retryRelease.await();
            return null;
        }).when(transport).shutdown(graceful);

        try (ExecutorService callers = Executors.newFixedThreadPool(2)) {
            Future<?> owner = submitClose(callers, server, null);
            assertTrue(failedEntered.await(2, TimeUnit.SECONDS));
            AtomicReference<Thread> joiningThread = new AtomicReference<>();
            Future<?> joiner = submitClose(callers, server, joiningThread);
            awaitWaiting(joiningThread);
            failedRelease.countDown();
            assertSame(exact, cause(owner));
            assertSame(exact, cause(joiner));
        }
        assertEquals(PkiHttpsServer.State.QUIESCING, server.state());
        verify(realm, never()).close();
        verify(authenticator, never()).close();

        try (ExecutorService callers = Executors.newFixedThreadPool(2)) {
            Future<?> owner = submitClose(callers, server, null);
            assertTrue(retryEntered.await(2, TimeUnit.SECONDS));
            AtomicReference<Thread> joiningThread = new AtomicReference<>();
            Future<?> joiner = submitClose(callers, server, joiningThread);
            awaitWaiting(joiningThread);
            retryRelease.countDown();
            owner.get(2, TimeUnit.SECONDS);
            joiner.get(2, TimeUnit.SECONDS);
        }
        assertEquals(PkiHttpsServer.State.TERMINATED, server.state());
        verify(transport, times(2)).shutdown(graceful);
        verify(realm, times(1)).close();
        verify(authenticator, times(1)).close();
    }

    @Test
    void workerCloseDuringExternalDrainUnwindsWithoutJoining() throws Exception {
        PkiServerConfiguration configuration = closeConfiguration();
        ServerRealmContext realm = mock(ServerRealmContext.class);
        PkiServerAuthenticator authenticator = mock(PkiServerAuthenticator.class);
        PkiHttpsTransport transport = mock(PkiHttpsTransport.class);
        PkiHttpsServer server = closeServer(configuration, realm, authenticator, transport);
        Duration graceful = configuration.execution().gracefulShutdown();
        CountDownLatch drainEntered = new CountDownLatch(1);
        CountDownLatch workerReturned = new CountDownLatch(1);
        doAnswer(invocation -> {
            drainEntered.countDown();
            assertTrue(workerReturned.await(2, TimeUnit.SECONDS));
            return null;
        }).when(transport).shutdown(graceful);

        AtomicReference<Throwable> workerFailure = new AtomicReference<>();
        try (ExecutorService callers = Executors.newSingleThreadExecutor()) {
            Future<?> owner = submitClose(callers, server, null);
            assertTrue(drainEntered.await(2, TimeUnit.SECONDS));
            Thread worker = new Thread(() -> {
                try {
                    server.closeFromServerWorker(true);
                } catch (Throwable failure) {
                    workerFailure.set(failure);
                } finally {
                    workerReturned.countDown();
                }
            });
            worker.start();
            worker.join(2_000L);
            assertFalse(worker.isAlive());
            assertTrue(workerFailure.get() instanceof IllegalStateException);
            assertTrue(workerFailure.get().getMessage().contains("SERVER_CLOSE_RETRY_REQUIRED"));
            owner.get(2, TimeUnit.SECONDS);
        }
        assertEquals(PkiHttpsServer.State.TERMINATED, server.state());
        verify(realm, times(1)).close();
        verify(authenticator, times(1)).close();
    }

    @Test
    void workerFirstOnlyQuiescesBeforeExternalCloseSucceeds() throws Exception {
        PkiServerConfiguration configuration = closeConfiguration();
        ServerRealmContext realm = mock(ServerRealmContext.class);
        PkiServerAuthenticator authenticator = mock(PkiServerAuthenticator.class);
        PkiHttpsTransport transport = mock(PkiHttpsTransport.class);
        PkiHttpsServer server = closeServer(configuration, realm, authenticator, transport);
        Duration graceful = configuration.execution().gracefulShutdown();

        IllegalStateException retry = assertThrows(IllegalStateException.class,
                () -> server.closeFromServerWorker(true));
        assertTrue(retry.getMessage().contains("SERVER_CLOSE_RETRY_REQUIRED"));
        assertEquals(PkiHttpsServer.State.QUIESCING, server.state());
        verify(transport, never()).shutdown(graceful);
        verify(realm, never()).close();
        verify(authenticator, never()).close();

        server.close();
        assertEquals(PkiHttpsServer.State.TERMINATED, server.state());
        verify(transport, times(1)).shutdown(graceful);
        verify(realm, times(1)).close();
        verify(authenticator, times(1)).close();
    }

    @Test
    void transportDrainTimeoutKeepsRealmOpenAndRetryClosesDependenciesOnce() throws Exception {
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        PkiServerConfiguration configuration = HttpServerTestSupport.configuration(temporaryDirectory,
                tls.clientCertificate());
        ServerRealmContext realm = mock(ServerRealmContext.class);
        PkiServerAuthenticator authenticator = mock(PkiServerAuthenticator.class);
        PkiHttpsTransport transport = mock(PkiHttpsTransport.class);
        doThrow(new IllegalStateException(
                "Server execution shutdown timed out: code=SERVER_EXECUTION_SHUTDOWN_TIMEOUT"))
                .doNothing().when(transport).shutdown(configuration.execution().gracefulShutdown());
        AtomicReference<PkiHttpsServer.State> state = new AtomicReference<>(PkiHttpsServer.State.READY);
        PkiHttpsServer server = new PkiHttpsServer(configuration, realm, authenticator, transport,
                Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), state);

        IllegalStateException timeout = assertThrows(IllegalStateException.class, server::close);
        assertTrue(timeout.getMessage().contains("SERVER_EXECUTION_SHUTDOWN_TIMEOUT"));
        assertEquals(PkiHttpsServer.State.QUIESCING, server.state());
        verify(realm, never()).close();
        verify(authenticator, never()).close();

        server.close();
        assertEquals(PkiHttpsServer.State.TERMINATED, server.state());
        verify(realm, times(1)).close();
        verify(authenticator, times(1)).close();
    }

    @Test
    void rejectsInsecureConfigurationAndStrictJsonFraming() throws Exception {
        System.out.println("rejectsInsecureConfigurationAndStrictJsonFraming");
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        PkiServerConfiguration valid = HttpServerTestSupport.configuration(temporaryDirectory,
                tls.clientCertificate());
        assertThrows(IllegalArgumentException.class, () -> new PkiServerConfiguration.Listener(
                valid.listener().address(), valid.listener().port(), valid.listener().tlsProvider(), true,
                16_384, PkiServerConfiguration.Listener.MINIMUM_BODY_BYTES - 1));
        new PkiServerConfiguration.Listener(valid.listener().address(), valid.listener().port(),
                valid.listener().tlsProvider(), true, 16_384,
                PkiServerConfiguration.Listener.MINIMUM_BODY_BYTES);
        assertThrows(IllegalArgumentException.class, () -> new PkiServerConfiguration(valid.version(),
                valid.serverName(), valid.realm(), new PkiServerConfiguration.Listener(valid.listener().address(),
                        valid.listener().port(), valid.listener().tlsProvider(), false, 16_384, 65_536),
                valid.authentication(), valid.execution(), valid.runtime()));
        assertThrows(IllegalArgumentException.class, () -> PkiServerConfigurationCodec.decode(
                "{\"version\":1,\"version\":1}".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertThrows(IllegalArgumentException.class, () -> new PkiServerConfiguration.Execution(1, 1, 1, 1,
                1, Duration.ofSeconds(2), Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofSeconds(1)));
        PkiServerConfiguration.Execution publicExecution = new PkiServerConfiguration.Execution(1, 1, 1, 1, 1,
                Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofSeconds(1));
        assertThrows(IllegalArgumentException.class, () -> new PkiServerConfiguration.PublicListener(
                java.net.InetAddress.getByName("192.0.2.1"), 8444, Optional.empty(), true,
                valid.authentication(), 4_096, 1_024, publicExecution, Duration.ofSeconds(1), Duration.ZERO,
                Duration.ZERO, true));
        PkiServerConfiguration.PublicListener conflicting = new PkiServerConfiguration.PublicListener(
                valid.listener().address(), 8443, Optional.of(valid.listener().tlsProvider()), false,
                valid.authentication(), 4_096, 1_024, publicExecution, Duration.ofSeconds(1), Duration.ZERO,
                Duration.ZERO, true);
        PkiServerConfiguration.Listener fixedAdministrative = new PkiServerConfiguration.Listener(
                valid.listener().address(), 8443, valid.listener().tlsProvider(), true, 16_384, 65_536);
        assertThrows(IllegalArgumentException.class, () -> new PkiServerConfiguration(valid.version(),
                valid.serverName(), valid.realm(), fixedAdministrative, valid.authentication(), valid.execution(),
                valid.runtime(), Optional.of(conflicting)));
        assertThrows(IllegalArgumentException.class, () -> new PkiServerConfiguration(2, valid.serverName(),
                valid.realm(), valid.listener(), valid.authentication(), valid.execution(), valid.runtime()));
        String production = java.nio.file.Files.readString(java.nio.file.Path.of(
                "..", "docs", "pki-server-production-example.json"));
        PkiServerConfiguration decoded = PkiServerConfigurationCodec.decode(production.getBytes(
                java.nio.charset.StandardCharsets.UTF_8));
        assertTrue(decoded.publicListener().isEmpty());
        assertEquals(PkiServerConfiguration.SigningReconciliation.defaults(), decoded.signingReconciliation());
        assertThrows(IllegalArgumentException.class, () -> PkiServerConfigurationCodec.decode(production
                .replace("\"version\": 7", "\"version\": 5")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertThrows(IllegalArgumentException.class, () -> PkiServerConfigurationCodec.decode(production
                .replace("\"version\": 7", "\"version\": 6")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertThrows(IllegalArgumentException.class,
                () -> new PkiServerConfiguration.SigningReconciliation(true, 4, 5, Duration.ofSeconds(30),
                        Duration.ofSeconds(10), Duration.ofSeconds(2)));
        assertThrows(IllegalArgumentException.class,
                () -> new PkiServerConfiguration.SigningReconciliation(true, 4, 4, Duration.ofSeconds(5),
                        Duration.ofSeconds(10), Duration.ofSeconds(2)));
        assertThrows(IllegalArgumentException.class, () -> new PkiServerConfiguration(valid.version(),
                valid.serverName(), valid.realm(), valid.listener(), valid.authentication(), valid.execution(),
                valid.runtime(), valid.publicListener(), valid.acmeListener(),
                new PkiServerConfiguration.SigningReconciliation(false, 4, 4, Duration.ofSeconds(5),
                        Duration.ofSeconds(5), Duration.ofSeconds(2))));
        assertThrows(IllegalArgumentException.class, () -> PkiServerConfigurationCodec.decode(production
                .replace("\"publicListener\": {\"enabled\": false},\n", "")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertThrows(IllegalArgumentException.class, () -> PkiServerConfigurationCodec.decode(production
                .replace("{\"enabled\": false}", "{\"enabled\":false,\"port\":8444}")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        System.out.println("...strict-security-fields=true");
        System.out.println("...ok");
    }

    @Test
    void decodesStrictConfirmationProofPolicyAndAllDocumentedExamples() throws Exception {
        String[] examples = {
                "pki-server-loopback-example.json",
                "pki-server-production-example.json",
                "pki-server-trusted-proxy-nginx-example.json",
                "pki-server-trusted-proxy-rfc9440-example.json" };
        Set<String> audiences = new java.util.HashSet<>();
        for (String example : examples) {
            String document = java.nio.file.Files.readString(java.nio.file.Path.of("..", "docs", example));
            PkiServerConfiguration decoded = PkiServerConfigurationCodec.decode(
                    document.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            assertEquals(PkiServerConfiguration.CURRENT_VERSION, decoded.version());
            assertEquals(Duration.ofMinutes(5L),
                    decoded.realm().confirmationProofPolicy().challengeTimeToLive());
            assertEquals(8_192, decoded.realm().confirmationProofPolicy().rsaMaximumModulusBits());
            audiences.add(decoded.realm().confirmationProofPolicy().audience().value());
        }
        assertEquals(examples.length, audiences.size());

        String production = java.nio.file.Files.readString(java.nio.file.Path.of(
                "..", "docs", "pki-server-production-example.json"));
        String defaults = production.replace(
                ",\n      \"challengeTtlMillis\": 300000,\n      \"rsaMaximumModulusBits\": 8192", "");
        CredentialConfirmationProofPolicy defaulted = PkiServerConfigurationCodec.decode(
                defaults.getBytes(java.nio.charset.StandardCharsets.UTF_8))
                .realm().confirmationProofPolicy();
        assertEquals(Duration.ofMinutes(5L), defaulted.challengeTimeToLive());
        assertEquals(8_192, defaulted.rsaMaximumModulusBits());

        assertInvalidServerConfiguration(production.replace(
                "\"audience\": \"urn:uuid:22222222-2222-4222-9222-222222222222\",",
                "\"audience\": \"urn:uuid:22222222-2222-4222-9222-222222222222\",\n"
                        + "      \"unknown\": true,"));
        assertInvalidServerConfiguration(production.replace(
                "      \"audience\": \"urn:uuid:22222222-2222-4222-9222-222222222222\",\n", ""));
        assertInvalidServerConfiguration(production.replace(
                "\"challengeTtlMillis\": 300000", "\"challengeTtlMillis\": 300000.5"));
        assertInvalidServerConfiguration(production.replace(
                "\"challengeTtlMillis\": 300000", "\"challengeTtlMillis\": 9000"));
        assertInvalidServerConfiguration(production.replace(
                "\"challengeTtlMillis\": 300000", "\"challengeTtlMillis\": 3601000"));
        assertInvalidServerConfiguration(production.replace(
                "\"challengeTtlMillis\": 300000", "\"challengeTtlMillis\": 10001"));
        assertInvalidServerConfiguration(production.replace(
                "urn:uuid:22222222-2222-4222-9222-222222222222",
                "URN:UUID:22222222-2222-4222-9222-222222222222"));
        assertInvalidServerConfiguration(production.replace(
                "\"urn:uuid:22222222-2222-4222-9222-222222222222\"", "42"));
        assertInvalidServerConfiguration(production.replace(
                "\"rsaMaximumModulusBits\": 8192", "\"rsaMaximumModulusBits\": 2047"));
        assertInvalidServerConfiguration(production.replace(
                "\"rsaMaximumModulusBits\": 8192", "\"rsaMaximumModulusBits\": 16385"));
        assertInvalidServerConfiguration(production.replace(
                "    \"confirmationProof\": {\n"
                        + "      \"audience\": \"urn:uuid:22222222-2222-4222-9222-222222222222\",\n"
                        + "      \"challengeTtlMillis\": 300000,\n"
                        + "      \"rsaMaximumModulusBits\": 8192\n"
                        + "    },\n", ""));

        CredentialConfirmationProofAudience audience = new CredentialConfirmationProofAudience(
                "urn:uuid:55555555-5555-4555-8555-555555555555");
        assertEquals(Duration.ofSeconds(10L), new CredentialConfirmationProofPolicy(
                audience, Duration.ofSeconds(10L), 2_048).challengeTimeToLive());
        assertEquals(16_384, new CredentialConfirmationProofPolicy(
                audience, Duration.ofHours(1L), 16_384).rsaMaximumModulusBits());
        assertThrows(NullPointerException.class,
                () -> new CredentialConfirmationProofPolicy(null, Duration.ofMinutes(5L), 8_192));
        assertThrows(IllegalArgumentException.class,
                () -> new CredentialConfirmationProofPolicy(audience, Duration.ofSeconds(9L), 8_192));
        assertThrows(NullPointerException.class,
                () -> new CredentialConfirmationProofPolicy(audience, null, 8_192));
        assertThrows(IllegalArgumentException.class, () -> new CredentialConfirmationProofPolicy(
                audience, Duration.ofSeconds(10L).plusNanos(1L), 8_192));
        assertThrows(IllegalArgumentException.class,
                () -> new CredentialConfirmationProofPolicy(audience, Duration.ofSeconds(10L), 2_047));
        assertThrows(IllegalArgumentException.class,
                () -> new CredentialConfirmationProofPolicy(audience, Duration.ofSeconds(10L), 16_385));
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
    void isolatedPublicListenerAllowsAnonymousMetadataWithoutAdminRouteOverlap() throws Exception {
        System.out.println("isolatedPublicListenerAllowsAnonymousMetadataWithoutAdminRouteOverlap");
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        PkiServerConfiguration administrative = HttpServerTestSupport.configuration(
                temporaryDirectory.resolve("public-direct"), tls.clientCertificate());
        PkiServerConfiguration configuration = HttpServerTestSupport.withPublicListener(administrative,
                administrative.authentication());
        seed(configuration);
        try (PkiHttpsServer server = PkiHttpsServer.start(configuration, PkiSessionRuntimeDependencies.none(),
                ServerTestSupport.CLOCK, HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader())) {
            HttpClient anonymous = HttpClient.newBuilder().sslContext(tls.anonymousContext()).build();
            URI publicBase = URI.create("https://localhost:" + server.publicAddress().orElseThrow().getPort());
            HttpResponse<String> authorities = get(anonymous, publicBase.resolve("/public/v1/authorities"));
            assertEquals(200, authorities.statusCode());
            assertTrue(authorities.body().contains("\"count\":0"));
            assertEquals(404, get(anonymous, publicBase.resolve("/admin/v1/realm")).statusCode());

            HttpClient administrator = HttpClient.newBuilder().sslContext(tls.clientContext()).build();
            URI adminBase = URI.create("https://localhost:" + server.address().getPort());
            assertEquals(404, get(administrator, adminBase.resolve("/public/v1/authorities")).statusCode());
            System.out.println("...adminPort=" + server.address().getPort() + " publicPort="
                    + server.publicAddress().orElseThrow().getPort());
        }
        assertFalse(Thread.getAllStackTraces().keySet().stream().anyMatch(thread -> thread.isAlive()
                && thread.getName().startsWith("zeroecho-pki-public-")));
        System.out.println("...ok");
    }

    @Test
    void trustedProxyPublicRequestMayRemainAnonymousButTransportIsAuthenticated() throws Exception {
        System.out.println("trustedProxyPublicRequestMayRemainAnonymousButTransportIsAuthenticated");
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        PkiServerConfiguration administrative = HttpServerTestSupport.proxyConfiguration(
                temporaryDirectory.resolve("public-proxy"), tls, ForwardedCertificateFormat.RFC9440);
        PkiServerConfiguration configuration = HttpServerTestSupport.withPublicListener(administrative,
                administrative.authentication());
        seed(configuration);
        try (PkiHttpsServer server = PkiHttpsServer.start(configuration, PkiSessionRuntimeDependencies.none(),
                ServerTestSupport.CLOCK, HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader())) {
            HttpClient proxy = HttpClient.newBuilder().sslContext(tls.proxyContext()).build();
            URI uri = URI.create("https://localhost:" + server.publicAddress().orElseThrow().getPort()
                    + "/public/v1/authorities");
            assertEquals(200, get(proxy, uri).statusCode());
            HttpClient untrusted = HttpClient.newBuilder().sslContext(tls.clientContext()).build();
            assertEquals(401, get(untrusted, uri).statusCode());
            System.out.println("...proxyTransport=authenticated,endClient=anonymous");
        }
        System.out.println("...ok");
    }

    @Test
    void publicIssuerAndAliasedChainUseExactAuthoritativeRecordsAndValidators() throws Exception {
        System.out.println("publicIssuerAndAliasedChainUseExactAuthoritativeRecordsAndValidators");
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        java.nio.file.Path directory = temporaryDirectory.resolve("public-content");
        PkiServerConfiguration administrative = HttpServerTestSupport.configuration(directory,
                tls.clientCertificate());
        PkiServerConfiguration configuration = HttpServerTestSupport.withPublicListener(administrative,
                administrative.authentication());
        SeededIssuer seeded = seedIssuer(directory.resolve("pki-store"), tls.rootCertificate());
        seed(configuration);
        try (PkiHttpsServer server = PkiHttpsServer.start(configuration, PkiSessionRuntimeDependencies.none(),
                ServerTestSupport.CLOCK, HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader())) {
            server.realm().repositoryAliases().setCurrentChain(seeded.authorityId(), seeded.issuerId(),
                    seeded.pathId(), Optional.empty(), "administrator");
            HttpClient anonymous = HttpClient.newBuilder().sslContext(tls.anonymousContext()).build();
            URI base = URI.create("https://localhost:" + server.publicAddress().orElseThrow().getPort());
            URI certificateUri = base.resolve("/public/v1/authorities/" + seeded.authorityId().value()
                    + "/issuers/" + seeded.issuerId().value() + "/certificate");
            HttpResponse<byte[]> certificate = anonymous.send(HttpRequest.newBuilder(certificateUri).GET().build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(200, certificate.statusCode());
            assertTrue(MessageDigest.isEqual(tls.rootCertificate().getEncoded(), certificate.body()));
            String etag = certificate.headers().firstValue("ETag").orElseThrow();
            HttpResponse<Void> head = anonymous.send(HttpRequest.newBuilder(certificateUri)
                    .method("HEAD", HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.discarding());
            assertEquals(200, head.statusCode());
            assertEquals(Long.toString(tls.rootCertificate().getEncoded().length),
                    head.headers().firstValue("Content-Length").orElseThrow());
            HttpResponse<Void> unchanged = anonymous.send(HttpRequest.newBuilder(certificateUri)
                    .header("If-None-Match", etag).GET().build(), HttpResponse.BodyHandlers.discarding());
            assertEquals(304, unchanged.statusCode());
            URI chainUri = base.resolve("/public/v1/authorities/" + seeded.authorityId().value() + "/chain");
            HttpResponse<String> chain = get(anonymous, chainUri);
            assertEquals(200, chain.statusCode());
            assertTrue(chain.body().contains(seeded.pathId().value()));
            assertTrue(chain.body().contains(seeded.credentialId().value()));
            server.realm().disclosure().register(seeded.credentialId(), DisclosureService.ObjectType.LEAF_CERTIFICATE,
                    DisclosureService.Policy.PUBLIC_UNLISTED, Optional.empty(), "2".repeat(64), "administrator");
            DisclosureService.IssuedCapability issued = server.realm().disclosure().issueCapability(
                    seeded.credentialId(), ServerTestSupport.CLOCK.instant().plusSeconds(600), "administrator");
            byte[] rawToken = issued.token();
            String bearer;
            try {
                bearer = DisclosureService.bearerCredential(issued.capability(), rawToken);
            } finally {
                java.util.Arrays.fill(rawToken, (byte) 0);
            }
            URI leafUri = base.resolve("/public/v1/certificates/" + seeded.credentialId().value());
            assertEquals(404, get(anonymous, leafUri).statusCode());
            HttpResponse<byte[]> capable = anonymous.send(HttpRequest.newBuilder(leafUri)
                    .header("Authorization", "Bearer " + bearer).GET().build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(200, capable.statusCode());
            assertEquals("private, no-store", capable.headers().firstValue("Cache-Control").orElseThrow());
            assertTrue(MessageDigest.isEqual(tls.rootCertificate().getEncoded(), capable.body()));
            assertEquals(400, get(anonymous, URI.create(leafUri + "?token=" + bearer)).statusCode());
            server.realm().disclosure().revokeCapability(issued.capability().capabilityId(), "administrator");
            assertEquals(404, anonymous.send(HttpRequest.newBuilder(leafUri)
                    .header("Authorization", "Bearer " + bearer).GET().build(),
                    HttpResponse.BodyHandlers.discarding()).statusCode());
            System.out.println("...issuer=" + seeded.issuerId().value().substring(0, 16)
                    + " path=" + seeded.pathId().value().substring(0, 16));
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

    @Test
    void acmeListenerIsLifecycleOwnedAndRouteIsolated() throws Exception {
        System.out.println("acmeListenerIsLifecycleOwnedAndRouteIsolated");
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        PkiServerConfiguration base = HttpServerTestSupport.configuration(
                temporaryDirectory.resolve("acme-isolation"), tls.clientCertificate());
        PkiServerConfiguration.Execution lane = new PkiServerConfiguration.Execution(1, 2, 1, 2, 2,
                Duration.ofSeconds(5), Duration.ofSeconds(5), Duration.ofSeconds(1), Duration.ofSeconds(1));
        PkiServerConfiguration.AcmeListener acme = new PkiServerConfiguration.AcmeListener("acme-test",
                java.net.InetAddress.getLoopbackAddress(), 0,
                new zeroecho.pki.spi.ProviderConfig("test-tls", Map.of()),
                PkiServerConfiguration.AcmeTransportMode.DIRECT_TLS, List.of(), Set.of(),
                URI.create("https://acme.example.test"), 16_384, 1_048_576, lane, lane,
                Duration.ofMinutes(5), 64, 16, 16, Duration.ofMinutes(1), 16, 16, 8, 16, 1,
                List.of(), List.of());
        PkiServerConfiguration configuration = new PkiServerConfiguration(base.version(), base.serverName(),
                base.realm(), base.listener(), base.authentication(), base.execution(), base.runtime(),
                Optional.empty(), Optional.of(acme));
        seed(configuration);
        try (PkiHttpsServer server = PkiHttpsServer.start(configuration, PkiSessionRuntimeDependencies.none(),
                ServerTestSupport.CLOCK, HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader())) {
            HttpClient anonymous = HttpClient.newBuilder().sslContext(tls.anonymousContext()).build();
            HttpClient administrator = HttpClient.newBuilder().sslContext(tls.clientContext()).build();
            URI acmeAdmin = URI.create("https://localhost:" + server.acmeAddress().orElseThrow().getPort()
                    + "/admin/v1/realm");
            URI adminAcme = URI.create("https://localhost:" + server.address().getPort()
                    + "/acme/internal/directory");
            assertEquals(404, get(anonymous, acmeAdmin).statusCode());
            assertEquals(404, get(administrator, adminAcme).statusCode());
            assertTrue(server.realm() == server.realm());
            System.out.println("...acme-port=" + server.acmeAddress().orElseThrow().getPort());
        }
        System.out.println("...ok");
    }

    @Test
    void authenticatesTrustedProxyWithRfc9440ForwardedClient() throws Exception {
        System.out.println("authenticatesTrustedProxyWithRfc9440ForwardedClient");
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        PkiServerConfiguration configuration = HttpServerTestSupport.proxyConfiguration(
                temporaryDirectory.resolve("rfc9440"), tls, ForwardedCertificateFormat.RFC9440);
        seed(configuration);
        try (PkiHttpsServer server = PkiHttpsServer.start(configuration, PkiSessionRuntimeDependencies.none(),
                ServerTestSupport.CLOCK, HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader())) {
            HttpClient proxy = HttpClient.newBuilder().sslContext(tls.proxyContext()).build();
            URI uri = URI.create("https://localhost:" + server.address().getPort() + "/admin/v1/realm");
            String leaf = ":" + Base64.getEncoder().encodeToString(tls.forwardedCertificate().getEncoded()) + ":";
            String root = ":" + Base64.getEncoder().encodeToString(tls.rootCertificate().getEncoded()) + ":";
            HttpResponse<String> response = proxy.send(HttpRequest.newBuilder(uri)
                    .header("Client-Cert", leaf).header("Client-Cert-Chain", root).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode());
            assertTrue(response.body().contains("production"));
            System.out.println("...transport=trusted-proxy,end=administrator");
        }
        System.out.println("...ok");
    }

    @Test
    void rejectsForwardedHeadersInDirectModeAndDuplicateProxyHeaders() throws Exception {
        System.out.println("rejectsForwardedHeadersInDirectModeAndDuplicateProxyHeaders");
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        PkiServerConfiguration direct = HttpServerTestSupport.configuration(temporaryDirectory.resolve("direct"),
                tls.clientCertificate());
        seed(direct);
        String leaf = ":" + Base64.getEncoder().encodeToString(tls.forwardedCertificate().getEncoded()) + ":";
        try (PkiHttpsServer server = PkiHttpsServer.start(direct, PkiSessionRuntimeDependencies.none(),
                ServerTestSupport.CLOCK, HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader())) {
            HttpClient client = HttpClient.newBuilder().sslContext(tls.clientContext()).build();
            URI uri = URI.create("https://localhost:" + server.address().getPort() + "/admin/v1/realm");
            assertEquals(400, client.send(HttpRequest.newBuilder(uri).header("Client-Cert", leaf).GET().build(),
                    HttpResponse.BodyHandlers.ofString()).statusCode());
        }
        PkiServerConfiguration proxyConfiguration = HttpServerTestSupport.proxyConfiguration(
                temporaryDirectory.resolve("proxy"), tls, ForwardedCertificateFormat.RFC9440);
        seed(proxyConfiguration);
        try (PkiHttpsServer server = PkiHttpsServer.start(proxyConfiguration,
                PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, HttpServerTestSupport.random(),
                TestTlsProvider.class.getClassLoader())) {
            HttpClient proxy = HttpClient.newBuilder().sslContext(tls.proxyContext()).build();
            URI uri = URI.create("https://localhost:" + server.address().getPort() + "/admin/v1/realm");
            HttpRequest duplicate = HttpRequest.newBuilder(uri).header("Client-Cert", leaf)
                    .header("Client-Cert", leaf).GET().build();
            assertEquals(401, proxy.send(duplicate, HttpResponse.BodyHandlers.ofString()).statusCode());
        }
        System.out.println("...duplicate-forwarded-identity=rejected");
        System.out.println("...ok");
    }

    @Test
    void acceptsOnlyStrictNginxEscapedPem() throws Exception {
        System.out.println("acceptsOnlyStrictNginxEscapedPem");
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        PkiServerConfiguration configuration = HttpServerTestSupport.proxyConfiguration(
                temporaryDirectory.resolve("nginx"), tls, ForwardedCertificateFormat.NGINX_ESCAPED_PEM_V1);
        seed(configuration);
        String pem = pem(tls.forwardedCertificate());
        String escaped = escape(pem);
        try (PkiHttpsServer server = PkiHttpsServer.start(configuration, PkiSessionRuntimeDependencies.none(),
                ServerTestSupport.CLOCK, HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader())) {
            HttpClient proxy = HttpClient.newBuilder().sslContext(tls.proxyContext()).build();
            URI uri = URI.create("https://localhost:" + server.address().getPort() + "/admin/v1/realm");
            assertEquals(200, proxy.send(HttpRequest.newBuilder(uri)
                    .header("X-ZeroEcho-Client-Cert", escaped).GET().build(),
                    HttpResponse.BodyHandlers.ofString()).statusCode());
            assertEquals(401, proxy.send(HttpRequest.newBuilder(uri)
                    .header("X-ZeroEcho-Client-Cert", pem.replace("\n", "" )).GET().build(),
                    HttpResponse.BodyHandlers.ofString()).statusCode());
        }
        System.out.println("...format-autodetection=false");
        System.out.println("...ok");
    }

    @Test
    void rejectsProxyWithoutForwardingPermission() throws Exception {
        System.out.println("rejectsProxyWithoutForwardingPermission");
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        PkiServerConfiguration configuration = HttpServerTestSupport.proxyConfiguration(
                temporaryDirectory.resolve("no-forwarding"), tls, ForwardedCertificateFormat.RFC9440);
        seed(configuration, false);
        try (PkiHttpsServer server = PkiHttpsServer.start(configuration, PkiSessionRuntimeDependencies.none(),
                ServerTestSupport.CLOCK, HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader())) {
            HttpClient proxy = HttpClient.newBuilder().sslContext(tls.proxyContext()).build();
            URI uri = URI.create("https://localhost:" + server.address().getPort() + "/admin/v1/realm");
            String leaf = ":" + Base64.getEncoder().encodeToString(tls.forwardedCertificate().getEncoded()) + ":";
            assertEquals(401, proxy.send(HttpRequest.newBuilder(uri).header("Client-Cert", leaf).GET().build(),
                    HttpResponse.BodyHandlers.ofString()).statusCode());
        }
        System.out.println("...gateway-invoked=false");
        System.out.println("...ok");
    }

    @Test
    void rejectsContradictoryAuthenticationModeConfiguration() throws Exception {
        System.out.println("rejectsContradictoryAuthenticationModeConfiguration");
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        PkiServerConfiguration direct = HttpServerTestSupport.configuration(temporaryDirectory.resolve("config"),
                tls.clientCertificate());
        PkiServerConfiguration.Authentication directAuthentication = direct.authentication();
        assertThrows(IllegalArgumentException.class, () -> new PkiServerConfiguration.Authentication(
                AdministrativeAuthenticationMode.DIRECT_MTLS, directAuthentication.directClientMappings(),
                List.of(), List.of(), Set.of(), Optional.of(ForwardedCertificateFormat.RFC9440),
                Optional.empty(), Optional.empty(), Optional.empty(), 0, 0));
        PkiServerConfiguration.Authentication proxy = HttpServerTestSupport.proxyConfiguration(
                temporaryDirectory.resolve("proxy-config"), tls, ForwardedCertificateFormat.RFC9440)
                .authentication();
        assertThrows(IllegalArgumentException.class, () -> new PkiServerConfiguration.Authentication(
                AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, List.of(),
                proxy.proxyTransportMappings(), proxy.forwardedClientMappings(),
                proxy.trustedProxyPrincipalIds(), proxy.forwardedCertificateFormat(),
                proxy.forwardedCertificateHeaderName(), proxy.forwardedCertificateChainHeaderName(),
                Optional.empty(), proxy.maximumForwardedCertificateBytes(), proxy.maximumForwardedChainBytes()));
        assertThrows(IllegalArgumentException.class, () -> new PkiServerConfiguration.Authentication(
                AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, List.of(),
                proxy.proxyTransportMappings(), proxy.forwardedClientMappings(),
                proxy.trustedProxyPrincipalIds(), Optional.of(ForwardedCertificateFormat.NGINX_ESCAPED_PEM_V1),
                Optional.of("Client-Cert"), Optional.empty(), proxy.administrativeClientTrust(), 16_384, 65_536));
        System.out.println("...implicit-mode=false");
        System.out.println("...ok");
    }

    private SeededIssuer seedIssuer(java.nio.file.Path root, java.security.cert.X509Certificate certificate)
            throws Exception {
        PkiId authorityId = new PkiId("authority-public-root");
        PkiId credentialId = new PkiId("credential-public-root");
        PkiId issuerId = IssuerGeneration.idFor(authorityId, credentialId);
        IssuerChainPath path = IssuerChainPath.create(authorityId, issuerId, List.of(credentialId));
        DurableContentReference reference;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(),
                ServerTestSupport.CLOCK);
                ContentSink sink = store.stagedContent().beginContent(Encoding.DER,
                        DurableContentReference.Lifecycle.PERSISTED);
                OutputStream output = sink.outputStream()) {
            output.write(certificate.getEncoded());
            reference = sink.complete();
            InstantBounds bounds = new InstantBounds(certificate.getNotBefore().toInstant(),
                    certificate.getNotAfter().toInstant());
            KeyRef key = new KeyRef("public-root-key");
            SubjectRef subject = new SubjectRef(certificate.getSubjectX500Principal().getName());
            Credential credential = new Credential(credentialId, new FormatId("x509"),
                    new IssuerRef(authorityId, issuerId, path.pathId()), subject,
                    new Validity(bounds.notBefore(), bounds.notAfter()), certificate.getSerialNumber().toString(),
                    new PkiId("public-key-public-root"),
                    new CaProfileBinding(new CertificateProfileRef("public-root-profile", 1, new byte[32])),
                    CredentialStatus.ISSUED, reference, new SimpleAttributeSet());
            store.putCredential(credential);
            store.putIssuerGeneration(new IssuerGeneration(issuerId, authorityId, credentialId, key,
                    IssuerGenerationState.ACTIVE, "0".repeat(64), "1".repeat(64)));
            store.putIssuerChainPath(path);
            store.putCa(new CaRecord(authorityId, CaKind.ROOT, CaState.ACTIVE, key, subject,
                    List.of(issuerId), issuerId, path.pathId()));
        }
        return new SeededIssuer(authorityId, credentialId, issuerId, path.pathId());
    }

    private void seed(PkiServerConfiguration configuration) throws Exception {
        seed(configuration, true);
    }

    private static PkiServerConfiguration closeConfiguration() {
        PkiServerConfiguration configuration = mock(PkiServerConfiguration.class);
        PkiServerConfiguration.Execution execution = new PkiServerConfiguration.Execution(1, 1, 1, 1, 1,
                Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofMillis(20), Duration.ofMillis(20));
        when(configuration.execution()).thenReturn(execution);
        return configuration;
    }

    private static void assertInvalidServerConfiguration(String document) {
        assertThrows(IllegalArgumentException.class, () -> PkiServerConfigurationCodec.decode(
                document.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }

    private static PkiHttpsServer closeServer(PkiServerConfiguration configuration, ServerRealmContext realm,
            PkiServerAuthenticator authenticator, PkiHttpsTransport transport) {
        return new PkiHttpsServer(configuration, realm, authenticator, transport, Optional.empty(), Optional.empty(),
                Optional.empty(), Optional.empty(), new AtomicReference<>(PkiHttpsServer.State.READY));
    }

    private static Future<?> submitClose(ExecutorService callers, PkiHttpsServer server,
            AtomicReference<Thread> thread) {
        return callers.submit(() -> {
            if (thread != null) thread.set(Thread.currentThread());
            server.close();
            return null;
        });
    }

    private static void awaitWaiting(AtomicReference<Thread> selected) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2L);
        while (selected.get() == null && System.nanoTime() < deadline) Thread.onSpinWait();
        Thread thread = selected.get();
        assertTrue(thread != null);
        while (thread.getState() != Thread.State.WAITING && System.nanoTime() < deadline) {
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1L));
        }
        assertEquals(Thread.State.WAITING, thread.getState());
    }

    private static Throwable cause(Future<?> future) {
        return assertThrows(ExecutionException.class, () -> future.get(2, TimeUnit.SECONDS)).getCause();
    }

    private void seed(PkiServerConfiguration configuration, boolean grantForwarding) throws Exception {
        try (ServerRealmContext context = ServerRealmContext.open(configuration.realm(),
                PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, HttpServerTestSupport.random())) {
            context.createPrincipal(ServerTestSupport.principal("administrator"), "system");
            if (configuration.authentication().mode()
                    == AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY) {
                context.createPrincipal(new SecurityPrincipal("trusted-proxy", SecurityPrincipal.Type.SERVICE,
                        "Trusted reverse proxy", Optional.empty(), Map.of(), true), "system");
            }
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
            if (grantForwarding && configuration.authentication().mode()
                    == AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY) {
                context.grant(ServerTestSupport.grant("proxy-forward", "trusted-proxy", Permission.Effect.ALLOW,
                        Permission.Action.FORWARD_AUTHENTICATED_CLIENT_IDENTITY, Permission.ResourceType.REALM,
                        realmScope, Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED), "system");
            }
        }
    }

    private static String pem(java.security.cert.X509Certificate certificate) throws Exception {
        String encoded = Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(certificate.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + encoded + "\n-----END CERTIFICATE-----\n";
    }

    private static String escape(String value) {
        StringBuilder result = new StringBuilder(value.length() * 3);
        for (byte item : value.getBytes(java.nio.charset.StandardCharsets.US_ASCII)) {
            int unsigned = item & 0xff;
            char character = (char) unsigned;
            if (character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
                    || character >= '0' && character <= '9' || character == '-' || character == '.'
                    || character == '_' || character == '~') {
                result.append(character);
            } else {
                result.append('%').append(HexFormat.of().withUpperCase().toHexDigits(item));
            }
        }
        return result.toString();
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

    private record SeededIssuer(PkiId authorityId, PkiId credentialId, PkiId issuerId, PkiId pathId) { }

    private record InstantBounds(java.time.Instant notBefore, java.time.Instant notAfter) { }
}
