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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;

import javax.net.ssl.SSLPeerUnverifiedException;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsExchange;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofChallenge;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofResult;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiRepositoryContent;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.acme.AcmeJwsVerifier;
import zeroecho.pki.server.acme.AcmeNonceService;
import zeroecho.pki.server.acme.AcmeRateAdmission;
import zeroecho.pki.server.acme.AcmeService;
import zeroecho.pki.server.acme.AcmeState;
import zeroecho.pki.server.acme.AcmeWireBounds;
import zeroecho.pki.server.spi.PkiServerAuthenticationContext;
import zeroecho.pki.server.spi.PkiServerAuthenticationResult;

/** Strict ACME route adapter; protocol state and PKI business rules remain in {@link AcmeService}. */
@SuppressWarnings("PMD")
final class AcmeHttpHandler implements HttpHandler {
    private static final String JOSE = "application/jose+json";
    private static final String JSON = "application/json";
    private static final String PROBLEM = "application/problem+json";
    private static final String PEM_CHAIN = "application/pem-certificate-chain";
    private static final int TRANSFER_BUFFER = 8192;
    private final PkiServerConfiguration.AcmeListener configuration;
    private final ServerRealmContext realm;
    private final AcmeService service;
    private final AcmeNonceService nonces;
    private final AcmeJwsVerifier verifier = new AcmeJwsVerifier();
    private final AcmeRateAdmission rates;
    private final ServerRuntime runtime;
    private final ServerRuntime.ChallengeRuntime validations;
    private final Clock clock;
    private final RequestIds requestIds;
    private final BooleanSupplier ready;
    private final MutualTlsAuthenticator proxyAuthenticator;

    AcmeHttpHandler(PkiServerConfiguration.AcmeListener configuration, ServerRealmContext realm,
            AcmeService service, AcmeNonceService nonces, ServerRuntime runtime,
            ServerRuntime.ChallengeRuntime validations, Clock clock, RequestIds requestIds,
            BooleanSupplier ready) {
        this.configuration = configuration; this.realm = realm; this.service = service; this.nonces = nonces;
        this.runtime = runtime; this.validations = validations; this.clock = clock;
        this.requestIds = requestIds; this.ready = ready;
        this.rates = new AcmeRateAdmission(configuration, clock);
        this.proxyAuthenticator = new MutualTlsAuthenticator(configuration.proxyTransportMappings(),
                realm::principal, clock);
    }

    @Override public void handle(HttpExchange exchange) throws IOException {
        String requestId = "unavailable-request";
        try {
            requestId = requestIds.resolve(exchange.getRequestHeaders().get(RequestIds.HEADER));
            requireHeaders(exchange.getRequestHeaders());
            if (!ready.getAsBoolean()) { send(exchange, problem(503, "serverInternal"), requestId, null); return; }
            if (!authenticateTransport((HttpsExchange) exchange, requestId)) {
                audit("ACME_TRANSPORT_AUTH", "system", requestId, "REJECTED");
                send(exchange, problem(401, "unauthorized"), requestId, null); return;
            }
            audit("ACME_TRANSPORT_AUTH", "system", requestId, "ACCEPTED");
            if (containsForwardedIdentity(exchange.getRequestHeaders())) {
                send(exchange, problem(400, "malformed"), requestId, null); return;
            }
            if (!runtime.tryAdmit()) { send(exchange, problem(429, "rateLimited"), requestId, null); return; }
            try {
                String exactRequestId = requestId;
                Instant requestDeadline = clock.instant().plus(configuration.execution().maximumDeadline());
                ServerRuntime.Submitted<Response> submitted = runtime.submit(cancellation -> route(exchange,
                        exactRequestId, cancellation, requestDeadline));
                Response response;
                try {
                    response = submitted.future().get(configuration.execution().maximumDeadline().toMillis(),
                            TimeUnit.MILLISECONDS);
                } catch (TimeoutException timeout) {
                    submitted.cancellation().cancel(); submitted.future().cancel(true);
                    response = problem(504, "serverInternal");
                } catch (InterruptedException interrupted) {
                    submitted.cancellation().cancel(); submitted.future().cancel(true);
                    Thread.currentThread().interrupt(); response = problem(504, "serverInternal");
                } catch (ExecutionException failure) {
                    response = protocolFailure(failure.getCause());
                }
                try {
                    send(exchange, response, requestId, response.directoryId());
                } finally {
                    submitted.finish();
                }
            } catch (RejectedExecutionException overloaded) {
                send(exchange, problem(429, "rateLimited"), requestId, null);
            } finally {
                runtime.releaseAdmission();
            }
        } catch (IllegalArgumentException malformed) {
            send(exchange, problem(400, "malformed"), requestId, null);
        } catch (RuntimeException failure) {
            send(exchange, problem(500, "serverInternal"), requestId, null);
        }
    }

    private Response route(HttpExchange exchange, String requestId,
            ServerRuntime.CancellationToken cancellation, Instant requestDeadline) throws Exception {
        URI requestUri = exchange.getRequestURI();
        if (requestUri.getRawQuery() != null || requestUri.getRawFragment() != null) return problem(400, "malformed");
        String[] parts = requestUri.getPath().split("/", -1);
        if (parts.length < 4 || !"".equals(parts[0]) || !"acme".equals(parts[1])) return problem(404, "malformed");
        String resource = parts[3];
        if (parts.length == 4 && "directory".equals(resource) && "GET".equals(exchange.getRequestMethod())) {
            AcmeState.Directory directory = activeDirectory(parts[2]);
            return json(200, directoryJson(directory), directory.directoryId());
        }
        if (parts.length == 4 && "new-nonce".equals(resource)
                && ("GET".equals(exchange.getRequestMethod()) || "HEAD".equals(exchange.getRequestMethod()))) {
            service.nonceScope(parts[2]);
            return new Response(204, JSON, new byte[0], Optional.empty(), null, Map.of());
        }
        if (!"POST".equals(exchange.getRequestMethod())) return problem(405, "malformed");
        if (!JOSE.equalsIgnoreCase(baseContentType(exchange.getRequestHeaders().getFirst("Content-Type")))) {
            return problem(415, "malformed");
        }
        byte[] body = readBody(exchange.getRequestBody(), configuration.maximumBodyBytes());
        URI exactUrl = configuration.externalBaseUri().resolve(requestUri.getRawPath());
        AcmeState.Directory directory = resolveRequestDirectory(parts, resource, body, exactUrl);
        AcmeJwsVerifier.KeyMode mode = "new-account".equals(resource)
                ? AcmeJwsVerifier.KeyMode.JWK : AcmeJwsVerifier.KeyMode.KID;
        AcmeJwsVerifier.Verified verified = verifier.verify(body, configuration.maximumBodyBytes(), exactUrl,
                directory.alias(), mode, nonces, kid -> accountKey(directory, kid));
        if (parts.length == 4 && "new-account".equals(resource)) return newAccount(directory, verified);
        AcmeJwsVerifier.AccountKey account = verified.account().orElseThrow();
        requireAccountDirectory(account.accountId(), directory);
        if (parts.length == 4 && "new-order".equals(resource)) return newOrder(directory, account, verified.payload());
        if (parts.length == 4 && "key-change".equals(resource)) {
            AcmeJwsVerifier.Verified replacement = verifier.verifyKeyChange(verified.payload(),
                    configuration.maximumBodyBytes(), exactUrl, account.kid(), account.keyThumbprint());
            AcmeState.Account updated = service.rolloverAccount(account.accountId(), account.recordCommitment(),
                    replacement.keyThumbprint(), replacement.publicKey().getEncoded());
            return json(200, accountJson(updated, directory), directory.directoryId());
        }
        if (parts.length == 4 && "revoke-cert".equals(resource)) {
            AcmePayloads.RevocationPayload revocation = AcmePayloads.revocation(verified.payload(),
                    configuration.maximumBodyBytes());
            byte[] certificate = revocation.certificateDer();
            try { service.revokeCertificate(account.accountId(), account.recordCommitment(), directory, certificate,
                    revocationReason(revocation.reasonCode()), requestId); }
            finally { java.util.Arrays.fill(certificate, (byte) 0); }
            return json(200, "{}", directory.directoryId());
        }
        if (parts.length == 7 && "credential-confirmation".equals(resource)
                && "v1".equals(parts[4])) {
            return switch (parts[5]) {
                case "challenge" -> credentialConfirmationChallenge(account, parts[6], verified.payload(), directory);
                case "complete" -> credentialConfirmationComplete(account, parts[6], verified.payload(), directory);
                default -> problem(404, "malformed");
            };
        }
        if (parts.length != 5) return problem(404, "malformed");
        return switch (resource) {
            case "account" -> account(account, parts[4], verified.payload(), directory);
            case "order" -> order(account, parts[4], verified.payload(), directory, cancellation);
            case "authz" -> authorization(account.accountId(), parts[4], verified.payload(), directory);
            case "challenge" -> challenge(account, parts[4], verified.payload(), directory, cancellation,
                    requestDeadline);
            case "finalize" -> finalizeOrder(account, parts[4], verified.payload(), directory, cancellation);
            case "certificate" -> certificate(account, parts[4], verified.payload(), directory,
                    cancellation, requestDeadline);
            default -> problem(404, "malformed");
        };
    }

    private AcmeState.Directory activeDirectory(String alias) {
        try {
            return service.activeDirectory(alias);
        } catch (RuntimeException unavailable) {
            throw new AcmeJwsVerifier.AcmeProblem("malformed");
        }
    }

    private AcmeState.Directory resolveRequestDirectory(String[] parts, String resource,
            byte[] body, URI exactUrl) {
        AcmeState.Directory directory;
        if (parts.length == 4 && ("new-account".equals(resource) || "new-order".equals(resource))) {
            directory = activeDirectory(parts[2]);
        } else if (parts.length == 4 && ("key-change".equals(resource) || "revoke-cert".equals(resource))) {
            String kid = verifier.kidRoutingHint(body, configuration.maximumBodyBytes(), exactUrl);
            directory = service.accountDirectory(accountIdFromKid(parts[2], kid));
        } else if (parts.length == 5) {
            directory = switch (resource) {
                case "account" -> service.accountDirectory(parts[4]);
                case "order", "finalize", "certificate" -> service.orderDirectory(parts[4]);
                case "authz" -> service.authorizationDirectory(parts[4]);
                case "challenge" -> service.challengeDirectory(parts[4]);
                default -> throw new AcmeJwsVerifier.AcmeProblem("malformed");
            };
        } else if (parts.length == 7 && "credential-confirmation".equals(resource)
                && "v1".equals(parts[4])
                && ("challenge".equals(parts[5]) || "complete".equals(parts[5]))) {
            directory = service.orderDirectory(parts[6]);
        } else {
            throw new AcmeJwsVerifier.AcmeProblem("malformed");
        }
        if (!directory.alias().equals(parts[2])) {
            throw new AcmeJwsVerifier.AcmeProblem("accountDoesNotExist");
        }
        return directory;
    }

    private String accountIdFromKid(String alias, String kid) {
        String prefix = configuration.externalBaseUri()
                .resolve("/acme/" + alias + "/account/").toASCIIString();
        if (!kid.startsWith(prefix)) {
            throw new AcmeJwsVerifier.AcmeProblem("accountDoesNotExist");
        }
        return kid.substring(prefix.length());
    }

    private Response newAccount(AcmeState.Directory directory, AcmeJwsVerifier.Verified verified) {
        PkiOperationValue.ObjectValue payload = object(StrictJson.parse(verified.payload(), 65_536));
        requireOnly(payload, "onlyReturnExisting", "contact", "termsOfServiceAgreed", "externalAccountBinding");
        boolean onlyExisting = bool(payload, "onlyReturnExisting", false);
        boolean terms = bool(payload, "termsOfServiceAgreed", false);
        List<String> contacts = textList(payload, "contact", 16, 512);
        Optional<byte[]> eabDocument = Optional.ofNullable(payload.fields().get("externalAccountBinding"))
                .map(StrictJson::encode);
        if (!rates.admitAccount(directory.directoryId())) return problem(429, "rateLimited");
        Optional<String> eab = service.verifyExternalAccountBinding(directory, verified.keyThumbprint(), eabDocument);
        boolean existing = service.accountByKey(directory.directoryId(), verified.keyThumbprint()).isPresent();
        AcmeState.Account account = service.createAccount(directory, verified.keyThumbprint(),
                verified.publicKey().getEncoded(), contacts, terms, eab, onlyExisting);
        return json(existing ? 200 : 201, accountJson(account, directory), directory.directoryId(),
                Map.of("Location", resourceUrl(directory, "account", account.accountId())));
    }

    private Response newOrder(AcmeState.Directory directory, AcmeJwsVerifier.AccountKey account, byte[] raw) {
        PkiOperationValue.ObjectValue payload = object(StrictJson.parse(raw, 65_536));
        requireOnly(payload, "identifiers", "notBefore", "notAfter");
        List<AcmeState.Identifier> identifiers = identifiers(payload.fields().get("identifiers"));
        Optional<Instant> notBefore = optionalInstant(payload, "notBefore");
        Optional<Instant> notAfter = optionalInstant(payload, "notAfter");
        if (notBefore.isPresent() != notAfter.isPresent()) throw new AcmeJwsVerifier.AcmeProblem("malformed");
        if (service.pendingOrderCount(account.accountId(), configuration.maximumPendingOrdersPerAccount())
                >= configuration.maximumPendingOrdersPerAccount()) return problem(429, "rateLimited");
        if (!rates.admitOrder(account.accountId())) return problem(429, "rateLimited");
        AcmeState.Order order = service.createOrder(account.accountId(), account.recordCommitment(), directory,
                identifiers,
                notBefore, notAfter, Duration.ofHours(24));
        return json(201, orderJson(order, directory), directory.directoryId(),
                Map.of("Location", resourceUrl(directory, "order", order.orderId())));
    }

    private Response account(AcmeJwsVerifier.AccountKey authenticated, String id, byte[] payload,
            AcmeState.Directory directory) {
        if (!authenticated.accountId().equals(id)) return problem(404, "accountDoesNotExist");
        PkiOperationValue.ObjectValue value = objectOrEmpty(payload);
        requireOnly(value, "status", "contact");
        if (value.fields().containsKey("status") && value.fields().containsKey("contact")) {
            throw new AcmeJwsVerifier.AcmeProblem("malformed");
        }
        AcmeState.Account account = service.account(id);
        if (value.fields().get("status") instanceof PkiOperationValue.Text status) {
            if (!"deactivated".equals(status.value())) throw new AcmeJwsVerifier.AcmeProblem("malformed");
            account = service.deactivateAccount(id, authenticated.recordCommitment());
        }
        if (value.fields().containsKey("contact")) {
            account = service.updateAccountContacts(id, authenticated.recordCommitment(),
                    textList(value, "contact", 16, 512));
        }
        return json(200, accountJson(account, directory), directory.directoryId());
    }

    private Response order(AcmeJwsVerifier.AccountKey account, String id, byte[] payload, AcmeState.Directory directory,
            ServerRuntime.CancellationToken cancellation) {
        requirePostAsGet(payload);
        return json(200, orderJson(service.order(account.accountId(), account.recordCommitment(), id, cancellation), directory), directory.directoryId());
    }

    private Response authorization(String accountId, String id, byte[] payload, AcmeState.Directory directory) {
        requirePostAsGet(payload);
        AcmeState.Authorization value = service.authorization(accountId, id);
        return json(200, authorizationJson(value, directory), directory.directoryId());
    }

    private Response challenge(AcmeJwsVerifier.AccountKey account, String id, byte[] payload,
            AcmeState.Directory directory, ServerRuntime.CancellationToken cancellation,
            Instant requestDeadline) throws Exception {
        objectOrEmpty(payload);
        if (!rates.admitValidation(account.accountId())) return problem(429, "rateLimited");
        if (!validations.tryAdmit()) return problem(429, "rateLimited");
        Future<AcmeState.Challenge> future = null;
        try {
            future = validations.submit(() -> service.validateChallenge(
                    account.accountId(), account.recordCommitment(), id, account.keyThumbprint(),
                    requestDeadline, cancellation));
            AcmeState.Challenge value = future.get(configuration.execution().maximumDeadline().toMillis(),
                    TimeUnit.MILLISECONDS);
            return json(200, challengeJson(value, directory), directory.directoryId());
        } catch (TimeoutException timeout) {
            if (future != null) {
                future.cancel(true);
            }
            return problem(504, "connection");
        } finally {
            validations.release();
        }
    }

    private Response finalizeOrder(AcmeJwsVerifier.AccountKey account, String id, byte[] payload,
            AcmeState.Directory directory, ServerRuntime.CancellationToken cancellation) {
        byte[] csr = AcmePayloads.requiredBase64Url(payload, "csr", configuration.maximumBodyBytes());
        if (!rates.tryAcquireFinalization()) {
            java.util.Arrays.fill(csr, (byte) 0);
            return problem(429, "rateLimited");
        }
        try {
            TransportCancellationGateway.finalizeAcme(service, account.accountId(), account.recordCommitment(),
                    id, csr, cancellation);
        } finally {
            java.util.Arrays.fill(csr, (byte) 0);
            rates.releaseFinalization();
        }
        return json(200, orderJson(service.order(account.accountId(), account.recordCommitment(), id, cancellation), directory), directory.directoryId());
    }

    private Response certificate(AcmeJwsVerifier.AccountKey account, String id, byte[] payload, AcmeState.Directory directory,
            ServerRuntime.CancellationToken cancellation, Instant requestDeadline) {
        requirePostAsGet(payload);
        AcmeState.Order order = service.order(account.accountId(), account.recordCommitment(), id, cancellation);
        if (order.status() != AcmeState.OrderStatus.VALID || order.credentialId().isEmpty()) {
            return problem(403, "orderNotReady");
        }
        return new Response(200, PEM_CHAIN, new byte[0],
                Optional.of(output -> writePemChain(output, order, cancellation, requestDeadline)),
                directory.directoryId(), Map.of());
    }

    private Response credentialConfirmationChallenge(AcmeJwsVerifier.AccountKey account, String orderId,
            byte[] payload, AcmeState.Directory directory) {
        if (!java.util.Arrays.equals(payload, new byte[] {'{', '}'})) {
            throw new AcmeJwsVerifier.AcmeProblem("malformed");
        }
        CredentialConfirmationProofChallenge challenge = service.issueCredentialConfirmationChallenge(
                account.accountId(), account.recordCommitment(), orderId);
        return json(200, confirmationChallengeJson(challenge), directory.directoryId());
    }

    private Response credentialConfirmationComplete(AcmeJwsVerifier.AccountKey account, String orderId,
            byte[] payload, AcmeState.Directory directory) {
        PkiOperationValue.ObjectValue value = object(StrictJson.parse(payload, configuration.maximumBodyBytes()));
        requireOnly(value, "expectedLifecycleRevision", "expectedLifecycleRecordCommitment",
                "expectedChallengeRecordCommitment", "response");
        String encodedResponse = requiredText(value, "response");
        byte[] response = decodeProofResponse(encodedResponse);
        try {
            CredentialConfirmationProofResult result = service.completeCredentialConfirmation(
                    account.accountId(), account.recordCommitment(), orderId,
                    requiredLong(value, "expectedLifecycleRevision"),
                    requiredText(value, "expectedLifecycleRecordCommitment"),
                    requiredText(value, "expectedChallengeRecordCommitment"), response);
            return json(200, "{\"version\":1,\"confirmationResult\":\"" + result.name() + "\"}",
                    directory.directoryId());
        } finally {
            java.util.Arrays.fill(response, (byte) 0);
        }
    }

    private void writePemChain(OutputStream output, AcmeState.Order order,
            ServerRuntime.CancellationToken cancellation, Instant deadline) throws IOException {
        writePem(output, order.credentialId().orElseThrow(), cancellation, deadline);
        IssuerChainPath path = realm.session().repository().chainPath(order.issuancePathId())
                .orElseThrow(() -> new IllegalStateException("ACME issuance path unavailable"));
        if (!path.pathCommitment().equals(order.issuancePathCommitment())) {
            throw new IllegalStateException("ACME issuance path changed");
        }
        for (PkiId credentialId : path.orderedCredentialIds()) {
            writePem(output, credentialId, cancellation, deadline);
        }
    }

    private void writePem(OutputStream output, PkiId credentialId,
            ServerRuntime.CancellationToken cancellation, Instant deadline) throws IOException {
        requireStreamActive(cancellation, deadline);
        output.write("-----BEGIN CERTIFICATE-----\n".getBytes(StandardCharsets.US_ASCII));
        try (PkiRepositoryContent content = realm.session().repository().openCredential(credentialId);
                InputStream input = content.openStream();
                OutputStream encoded = Base64.getMimeEncoder(64, new byte[] {'\n'}).wrap(new NonClosingOutput(output))) {
            byte[] buffer = new byte[TRANSFER_BUFFER];
            for (int count; (count = input.read(buffer)) >= 0;) {
                requireStreamActive(cancellation, deadline);
                if (count != 0) {
                    encoded.write(buffer, 0, count);
                }
            }
        }
        output.write("\n-----END CERTIFICATE-----\n".getBytes(StandardCharsets.US_ASCII));
    }

    private void requireStreamActive(ServerRuntime.CancellationToken cancellation, Instant deadline)
            throws IOException {
        if (cancellation.isCancelled() || !clock.instant().isBefore(deadline)) {
            throw new IOException("ACME certificate stream cancelled");
        }
    }

    private AcmeJwsVerifier.AccountKey accountKey(AcmeState.Directory directory, String kid) {
        String prefix = configuration.externalBaseUri().resolve("/acme/" + directory.alias() + "/account/").toASCIIString();
        if (!kid.startsWith(prefix)) throw new AcmeJwsVerifier.AcmeProblem("accountDoesNotExist");
        return service.accountKey(kid.substring(prefix.length()), kid);
    }

    private void requireAccountDirectory(String accountId, AcmeState.Directory directory) {
        AcmeState.Account account = service.account(accountId);
        if (!account.directoryId().equals(directory.directoryId()) || account.status() != AcmeState.AccountStatus.VALID) {
            throw new AcmeJwsVerifier.AcmeProblem("accountDoesNotExist");
        }
    }

    private boolean authenticateTransport(HttpsExchange exchange, String requestId) {
        if (configuration.transportMode() == PkiServerConfiguration.AcmeTransportMode.DIRECT_TLS) return true;
        try {
            List<X509Certificate> chain = new ArrayList<>();
            for (Certificate certificate : exchange.getSSLSession().getPeerCertificates()) {
                if (!(certificate instanceof X509Certificate x509)) return false;
                chain.add(x509);
            }
            PkiServerAuthenticationResult result = proxyAuthenticator.authenticate(new PkiServerAuthenticationContext(
                    chain, exchange.getSSLSession().getProtocol(), exchange.getSSLSession().getCipherSuite(),
                    requestId, realm.configuration().realmId()));
            if (!(result instanceof PkiServerAuthenticationResult.Authenticated authenticated)
                    || !configuration.trustedProxyPrincipalIds().contains(authenticated.endClientPrincipalId())) return false;
            return realm.gateway().authorizeForwardedIdentity(authenticated.endClientPrincipalId(), requestId).allowed();
        } catch (SSLPeerUnverifiedException | RuntimeException failure) {
            return false;
        }
    }

    private void send(HttpExchange exchange, Response response, String requestId, String directoryId)
            throws IOException {
        try {
            String nonceScope = directoryId == null
                    ? nonceScope(exchange.getRequestURI()) : service.directory(directoryId).alias();
            exchange.getResponseHeaders().set("Replay-Nonce", nonces.issue(nonceScope));
        }
        catch (RuntimeException unavailable) { /* Capacity failure is already represented by the response. */ }
        exchange.getResponseHeaders().set(RequestIds.HEADER, requestId);
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set("Content-Type", response.contentType());
        response.headers().forEach((name, value) -> exchange.getResponseHeaders().set(name, value));
        boolean delivered = false;
        try {
            if (response.writer().isPresent()) {
                exchange.sendResponseHeaders(response.status(), 0);
                try (OutputStream output = exchange.getResponseBody()) { response.writer().orElseThrow().write(output); }
            } else {
                exchange.sendResponseHeaders(response.status(), response.body().length);
                try (OutputStream output = exchange.getResponseBody()) { output.write(response.body()); }
            }
            delivered = true;
        } finally {
            audit("ACME_REQUEST", "system", requestId,
                    delivered ? "HTTP_" + response.status() : "DELIVERY_UNKNOWN");
            exchange.close();
        }
    }

    private String nonceScope(URI requestUri) {
        String[] parts = requestUri.getPath().split("/", -1);
        if (parts.length >= 3 && "acme".equals(parts[1])) {
            return service.nonceScope(parts[2]);
        }
        throw new IllegalArgumentException("ACME nonce scope is unavailable");
    }

    private void audit(String action, String actor, String requestId, String outcome) {
        realm.auditTransport(action, actor, Map.of("requestId", requestId, "outcome", outcome,
                "mode", configuration.transportMode().name()));
    }

    private static Response json(int status, String json, String directoryId) {
        return json(status, json, directoryId, Map.of());
    }
    private static Response json(int status, String json, String directoryId, Map<String, String> headers) {
        return new Response(status, JSON, json.getBytes(StandardCharsets.UTF_8), Optional.empty(), directoryId,
                headers);
    }
    private static Response problem(int status, String type) {
        return new Response(status, PROBLEM, ("{\"type\":\"urn:ietf:params:acme:error:" + type
                + "\",\"detail\":\"ACME request rejected\"}").getBytes(StandardCharsets.UTF_8),
                Optional.empty(), null, Map.of());
    }
    static Response protocolFailure(Throwable failure) {
        if (failure instanceof zeroecho.pki.api.SigningExecutionException signingFailure
                && signingFailure.classification()
                        == zeroecho.pki.api.SigningExecutionException.Classification.OVERLOADED) {
            return problem(429, "rateLimited");
        }
        if (failure instanceof AcmeJwsVerifier.AcmeProblem problem) {
            return problem(problemStatus(problem.type()), problem.type());
        }
        if (failure instanceof SecurityException || failure instanceof IllegalArgumentException) {
            return problem(403, "unauthorized");
        }
        if (failure instanceof zeroecho.pki.api.PkiException) {
            return problem(400, "badCSR");
        }
        if (failure instanceof IllegalStateException) {
            return problem(403, "orderNotReady");
        }
        return problem(500, "serverInternal");
    }
    private static int problemStatus(String type) {
        return switch (type) {
            case "unauthorized", "accountDoesNotExist", "orderNotReady", "userActionRequired" -> 403;
            case "rateLimited" -> 429;
            case "serverInternal" -> 500;
            default -> 400;
        };
    }
    private String resourceUrl(AcmeState.Directory directory, String type, String id) {
        return configuration.externalBaseUri().resolve("/acme/" + directory.alias() + "/" + type + "/" + id)
                .toASCIIString();
    }
    private String directoryJson(AcmeState.Directory value) {
        String base = configuration.externalBaseUri().resolve("/acme/" + value.alias() + "/").toASCIIString();
        return "{\"newNonce\":\"" + base + "new-nonce\",\"newAccount\":\"" + base
                + "new-account\",\"newOrder\":\"" + base + "new-order\",\"revokeCert\":\""
                + base + "revoke-cert\",\"keyChange\":\"" + base + "key-change\"}";
    }
    private String accountJson(AcmeState.Account value, AcmeState.Directory directory) {
        return "{\"status\":\"" + value.status().name().toLowerCase(java.util.Locale.ROOT) + "\"}";
    }
    private String orderJson(AcmeState.Order value, AcmeState.Directory directory) {
        StringBuilder out = new StringBuilder("{\"status\":\"").append(value.status().name().toLowerCase(java.util.Locale.ROOT))
                .append("\",\"identifiers\":[");
        for (int index = 0; index < value.identifiers().size(); index++) {
            if (index != 0) out.append(',');
            AcmeState.Identifier identifier = value.identifiers().get(index);
            out.append("{\"type\":\"dns\",\"value\":\"")
                    .append(escape(identifier.presentation())).append("\"}");
        }
        out.append("],\"authorizations\":[");
        appendUrls(out, value.authorizationIds(), base(directory) + "authz/");
        out.append("],\"finalize\":\"").append(base(directory)).append("finalize/").append(value.orderId()).append('"');
        value.credentialId().ifPresent(ignored -> out.append(",\"certificate\":\"").append(base(directory))
                .append("certificate/").append(value.orderId()).append('"'));
        if (requiresCredentialConfirmation(value)) {
            String confirmationBase = base(directory) + "credential-confirmation/v1/";
            out.append(",\"credentialConfirmation\":{\"version\":1,\"challenge\":\"")
                    .append(confirmationBase).append("challenge/").append(value.orderId())
                    .append("\",\"complete\":\"").append(confirmationBase).append("complete/")
                    .append(value.orderId()).append("\"}");
        }
        return out.append('}').toString();
    }

    private boolean requiresCredentialConfirmation(AcmeState.Order order) {
        if (order.status() != AcmeState.OrderStatus.VALID || order.credentialId().isEmpty()) {
            return false;
        }
        CredentialConfirmationLifecycle lifecycle = realm.session().confirmations()
                .get(order.credentialId().orElseThrow())
                .orElseThrow(() -> new IllegalStateException("ACME credential confirmation is unavailable"));
        return lifecycle.state() == CredentialConfirmationLifecycle.State.PENDING;
    }

    private static String confirmationChallengeJson(CredentialConfirmationProofChallenge challenge) {
        byte[] presentation = challenge.presentation();
        try {
            return "{\"version\":1,\"expectedLifecycleRevision\":"
                    + challenge.proofCas().expectedLifecycleRevision()
                    + ",\"expectedLifecycleRecordCommitment\":\""
                    + challenge.proofCas().expectedLifecycleRecordCommitment()
                    + "\",\"expectedChallengeRecordCommitment\":\""
                    + challenge.proofCas().expectedChallengeRecordCommitment()
                    + "\",\"proofSuiteId\":\"" + challenge.proofSuiteBinding().proofSuiteRef().suiteId()
                    + "\",\"proofSuiteConfigurationCommitment\":\""
                    + challenge.proofSuiteBinding().proofSuiteRef().configurationCommitment()
                    + "\",\"rsaMaximumModulusBits\":" + challenge.proofSuiteBinding().rsaMaximumModulusBits()
                    + ",\"expiresAt\":\"" + challenge.expiresAt()
                    + "\",\"maximumResponseBytes\":" + challenge.maximumResponseBytes()
                    + ",\"presentation\":\"" + Base64.getUrlEncoder().withoutPadding()
                            .encodeToString(presentation)
                    + "\"}";
        } finally {
            java.util.Arrays.fill(presentation, (byte) 0);
        }
    }
    private String authorizationJson(AcmeState.Authorization value, AcmeState.Directory directory) {
        StringBuilder out = new StringBuilder("{\"identifier\":{\"type\":\"dns\",\"value\":\"")
                .append(escape(value.identifier().value())).append("\"},\"status\":\"")
                .append(value.status().name().toLowerCase(java.util.Locale.ROOT));
        out.append('"');
        if (value.identifier().wildcard()) out.append(",\"wildcard\":true");
        out.append(",\"challenges\":[");
        appendUrls(out, value.challengeIds(), base(directory) + "challenge/");
        return out.append("]}").toString();
    }
    private String challengeJson(AcmeState.Challenge value, AcmeState.Directory directory) {
        return "{\"type\":\"" + challengeType(value.type()) + "\",\"url\":\"" + base(directory)
                + "challenge/" + value.challengeId() + "\",\"status\":\""
                + value.status().name().toLowerCase(java.util.Locale.ROOT) + "\",\"token\":\""
                + value.token() + "\"}";
    }
    private String base(AcmeState.Directory value) {
        return configuration.externalBaseUri().resolve("/acme/" + value.alias() + "/").toASCIIString();
    }

    private static void appendUrls(StringBuilder out, List<String> ids, String prefix) {
        for (int index = 0; index < ids.size(); index++) {
            if (index != 0) out.append(',');
            out.append('"').append(prefix).append(ids.get(index)).append('"');
        }
    }
    private static String challengeType(AcmeState.ChallengeType type) {
        return type == AcmeState.ChallengeType.HTTP_01 ? "http-01" : "dns-01";
    }
    private static RevocationReason revocationReason(int code) {
        return switch (code) {
            case 0 -> RevocationReason.UNSPECIFIED; case 1 -> RevocationReason.KEY_COMPROMISE;
            case 2 -> RevocationReason.CA_COMPROMISE; case 3 -> RevocationReason.AFFILIATION_CHANGED;
            case 4 -> RevocationReason.SUPERSEDED; case 5 -> RevocationReason.CESSATION_OF_OPERATION;
            case 9 -> RevocationReason.PRIVILEGE_WITHDRAWN; case 10 -> RevocationReason.AA_COMPROMISE;
            default -> throw new AcmeJwsVerifier.AcmeProblem("malformed");
        };
    }
    private static void requirePostAsGet(byte[] payload) {
        if (payload.length != 0) throw new AcmeJwsVerifier.AcmeProblem("malformed");
    }
    private static PkiOperationValue.ObjectValue objectOrEmpty(byte[] payload) {
        return payload.length == 0 ? new PkiOperationValue.ObjectValue(Map.of())
                : object(StrictJson.parse(payload, 65_536));
    }
    private static PkiOperationValue.ObjectValue object(PkiOperationValue value) {
        if (value instanceof PkiOperationValue.ObjectValue object) return object;
        throw new AcmeJwsVerifier.AcmeProblem("malformed");
    }
    private static void requireOnly(PkiOperationValue.ObjectValue value, String... fields) {
        if (!java.util.Set.of(fields).containsAll(value.fields().keySet())) {
            throw new AcmeJwsVerifier.AcmeProblem("malformed");
        }
    }
    private static boolean bool(PkiOperationValue.ObjectValue value, String field, boolean defaultValue) {
        PkiOperationValue item = value.fields().get(field);
        if (item == null) return defaultValue;
        if (item instanceof PkiOperationValue.BooleanValue flag) return flag.value();
        throw new AcmeJwsVerifier.AcmeProblem("malformed");
    }
    private static String requiredText(PkiOperationValue.ObjectValue value, String field) {
        if (value.fields().get(field) instanceof PkiOperationValue.Text text) return text.value();
        throw new AcmeJwsVerifier.AcmeProblem("malformed");
    }
    private static long requiredLong(PkiOperationValue.ObjectValue value, String field) {
        if (value.fields().get(field) instanceof PkiOperationValue.IntegerValue integer) return integer.value();
        throw new AcmeJwsVerifier.AcmeProblem("malformed");
    }
    private static byte[] decodeProofResponse(String encoded) {
        if (encoded.isEmpty()
                || encoded.length() > AcmeWireBounds.MAX_PROOF_B64URL_CHARS
                || !encoded.matches("[A-Za-z0-9_-]+")) {
            throw new AcmeJwsVerifier.AcmeProblem("malformed");
        }
        byte[] decoded;
        try {
            decoded = Base64.getUrlDecoder().decode(encoded);
        } catch (IllegalArgumentException malformed) {
            throw new AcmeJwsVerifier.AcmeProblem("malformed");
        }
        if (!encoded.equals(Base64.getUrlEncoder().withoutPadding().encodeToString(decoded))) {
            java.util.Arrays.fill(decoded, (byte) 0);
            throw new AcmeJwsVerifier.AcmeProblem("malformed");
        }
        return decoded;
    }
    private static List<String> textList(PkiOperationValue.ObjectValue value, String field, int maximum,
            int maximumLength) {
        PkiOperationValue item = value.fields().get(field);
        if (item == null) return List.of();
        if (!(item instanceof PkiOperationValue.ListValue list) || list.values().size() > maximum) {
            throw new AcmeJwsVerifier.AcmeProblem("malformed");
        }
        List<String> result = new ArrayList<>();
        for (PkiOperationValue element : list.values()) {
            if (!(element instanceof PkiOperationValue.Text text) || text.value().length() > maximumLength) {
                throw new AcmeJwsVerifier.AcmeProblem("malformed");
            }
            result.add(text.value());
        }
        return List.copyOf(result);
    }
    private static List<AcmeState.Identifier> identifiers(PkiOperationValue item) {
        if (!(item instanceof PkiOperationValue.ListValue list) || list.values().isEmpty() || list.values().size() > 64) {
            throw new AcmeJwsVerifier.AcmeProblem("rejectedIdentifier");
        }
        List<AcmeState.Identifier> result = new ArrayList<>();
        for (PkiOperationValue entry : list.values()) {
            PkiOperationValue.ObjectValue object = object(entry); requireOnly(object, "type", "value");
            if (!(object.fields().get("type") instanceof PkiOperationValue.Text type) || !"dns".equals(type.value())
                    || !(object.fields().get("value") instanceof PkiOperationValue.Text value)) {
                throw new AcmeJwsVerifier.AcmeProblem("rejectedIdentifier");
            }
            boolean wildcard = value.value().startsWith("*.");
            result.add(new AcmeState.Identifier(AcmeState.IdentifierType.DNS,
                    wildcard ? value.value().substring(2) : value.value(), wildcard));
        }
        return List.copyOf(result);
    }
    private static Optional<Instant> optionalInstant(PkiOperationValue.ObjectValue value, String field) {
        PkiOperationValue item = value.fields().get(field);
        if (item == null) return Optional.empty();
        if (item instanceof PkiOperationValue.Text text) {
            try { return Optional.of(Instant.parse(text.value())); }
            catch (RuntimeException invalid) { throw new AcmeJwsVerifier.AcmeProblem("malformed"); }
        }
        throw new AcmeJwsVerifier.AcmeProblem("malformed");
    }
    private static byte[] readBody(InputStream input, int maximum) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(Math.min(maximum, 16_384));
        byte[] buffer = new byte[8192]; int total = 0;
        for (int count; (count = input.read(buffer)) >= 0;) {
            if (count == 0) continue; total = Math.addExact(total, count);
            if (total > maximum) throw new IllegalArgumentException("ACME request body is too large");
            output.write(buffer, 0, count);
        }
        return output.toByteArray();
    }
    private void requireHeaders(Headers headers) {
        long count = 0;
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            count += entry.getKey().length();
            for (String value : entry.getValue()) count += value.length();
            if (count > configuration.maximumHeaderBytes()) throw new IllegalArgumentException("ACME headers too large");
        }
    }
    private static boolean containsForwardedIdentity(Headers headers) {
        return headers.containsKey(ForwardedClientCertificateParser.RFC_CERTIFICATE_HEADER)
                || headers.containsKey(ForwardedClientCertificateParser.RFC_CHAIN_HEADER)
                || headers.containsKey(ForwardedClientCertificateParser.DIRECT_REJECTED_NGINX_HEADER);
    }
    private static String baseContentType(String value) {
        return value == null ? "" : value.split(";", 2)[0].trim();
    }
    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    record Response(int status, String contentType, byte[] body, Optional<BodyWriter> writer,
            String directoryId, Map<String, String> headers) {
        Response {
            body = body.clone();
            writer = Objects.requireNonNull(writer, "writer");
            headers = Map.copyOf(headers);
        }
        @Override public byte[] body() { return body.clone(); }
    }
    @FunctionalInterface private interface BodyWriter { void write(OutputStream output) throws IOException; }
    private static final class NonClosingOutput extends java.io.FilterOutputStream {
        private NonClosingOutput(OutputStream output) { super(output); }
        @Override public void close() throws IOException { flush(); }
    }
}
