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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
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
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.application.OcspResponseService;
import zeroecho.pki.application.PkiRepositoryContent;
import zeroecho.pki.server.AdministrativeAuthenticationMode;
import zeroecho.pki.server.OcspResponderService;
import zeroecho.pki.server.OcspRequesterService;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.spi.PkiServerAuthenticationContext;

/** Strict anonymous OCSP protocol adapter on the public listener only. */
@SuppressWarnings("PMD")
final class OcspHttpHandler implements HttpHandler {
    private static final String MEDIA_REQUEST = "application/ocsp-request";
    private static final String MEDIA_RESPONSE = "application/ocsp-response";
    // OCSPResponseStatus values (RFC 6960, 4.2.1) for unsuccessful responses.
    private static final int OCSP_MALFORMED_REQUEST = 1;
    private static final int OCSP_TRY_LATER = 3;
    private static final int OCSP_SIG_REQUIRED = 5;
    private static final int OCSP_UNAUTHORIZED = 6;
    private final PkiServerConfiguration.PublicListener configuration;
    private final ServerRealmContext realm;
    private final AdministrativeAuthenticator authenticator;
    private final ServerRuntime runtime;
    private final Clock clock;
    private final RequestIds requestIds;
    private final BooleanSupplier ready;
    private final OcspRequesterService requesters;
    private final NonceReplayGuard nonceReplay = new NonceReplayGuard();

    OcspHttpHandler(PkiServerConfiguration.PublicListener configuration, ServerRealmContext realm,
            AdministrativeAuthenticator authenticator, ServerRuntime runtime, Clock clock,
            RequestIds requestIds, BooleanSupplier ready) {
        this.configuration = java.util.Objects.requireNonNull(configuration); this.realm = java.util.Objects.requireNonNull(realm);
        this.authenticator = java.util.Objects.requireNonNull(authenticator); this.runtime = java.util.Objects.requireNonNull(runtime);
        this.clock = java.util.Objects.requireNonNull(clock); this.requestIds = java.util.Objects.requireNonNull(requestIds);
        this.ready = java.util.Objects.requireNonNull(ready);
        this.requesters = new OcspRequesterService(realm, clock);
    }

    @Override public void handle(HttpExchange exchange) throws IOException {
        String requestId = "unavailable-request"; boolean admitted = false;
        OcspResponderService.Responder auditedResponder = null;
        Optional<String> transportPrincipal = Optional.empty();
        Optional<String> requesterPrincipal = Optional.empty();
        try {
            requestId = requestIds.resolve(exchange.getRequestHeaders().get(RequestIds.HEADER));
            if (!ready.getAsBoolean()) { transportFailure(exchange, 503); return; }
            requireHeadersBounded(exchange.getRequestHeaders());
            transportPrincipal = validateTransport(exchange, requestId);
            Route route = route(exchange);
            if (!runtime.tryAdmit()) { audit(requestId, Optional.empty(), transportPrincipal, Optional.empty(),
                    "OVERLOAD"); transportFailure(exchange, 429); return; }
            admitted = true;
            OcspResponderService.Responder responder = activeResponder(route.alias());
            auditedResponder = responder;
            audit(requestId, Optional.of(responder), transportPrincipal, Optional.empty(), "ACCEPTED");
            int maximumRequestBytes = Math.min(configuration.maximumBodyBytes(), responder.maximumRequestBytes());
            byte[] request = route.encoded().orElseGet(() -> read(exchange, maximumRequestBytes));
            if (request.length > maximumRequestBytes) { transportFailure(exchange, 413); return; }
            OcspRequestParser.Parsed parsed = OcspRequestParser.parse(request, responder.maximumEntries(),
                    responder.acceptedHashes(), responder.maximumNonceBytes(),
                    responder.requesterTrustPolicy().map(OcspResponderService.RequesterTrustPolicy
                            ::maximumSignerCertificates).orElse(16),
                    responder.requesterTrustPolicy().map(OcspResponderService.RequesterTrustPolicy
                            ::maximumSignerChainBytes).orElse(maximumRequestBytes));
            validateNonce(responder.noncePolicy(), parsed.nonce());
            requireAuthenticationMode(responder.requestAuthenticationMode(), parsed.signedRequest());
            Execution execution = execute(responder, parsed);
            requesterPrincipal = execution.requesterPrincipal();
            send(exchange, responder, execution.response(), parsed.nonce().isPresent(),
                    parsed.signedRequest().isPresent(), requestId);
            OcspResponseService.Response response = execution.response();
            audit(requestId, Optional.of(responder), transportPrincipal, requesterPrincipal,
                    "RESPONDED_GOOD_" + response.goodCount()
                    + "_REVOKED_" + response.revokedCount() + "_UNKNOWN_" + response.unknownCount());
        } catch (SignatureRequired required) { audit(requestId, Optional.ofNullable(auditedResponder),
                transportPrincipal, requesterPrincipal, "SIGNATURE_REQUIRED"); protocolFailure(exchange,
                        OCSP_SIG_REQUIRED);
        } catch (OcspRequesterService.UnauthorizedException unauthorized) { audit(requestId,
                Optional.ofNullable(auditedResponder), transportPrincipal, requesterPrincipal,
                "REQUESTER_UNAUTHORIZED_" + unauthorized.classification()); protocolFailure(exchange,
                        OCSP_UNAUTHORIZED);
        } catch (OcspRequesterService.UnavailableException unavailable) { audit(requestId,
                Optional.ofNullable(auditedResponder), transportPrincipal, requesterPrincipal,
                "REQUESTER_AUTHORITY_UNAVAILABLE"); protocolFailure(exchange, OCSP_TRY_LATER);
        } catch (UnknownAlias unavailable) { audit(requestId, Optional.empty(), transportPrincipal, requesterPrincipal, "UNKNOWN_RESPONDER"); transportFailure(exchange, 404);
        } catch (InactiveResponder inactive) { audit(requestId, Optional.empty(), transportPrincipal, requesterPrincipal, "INACTIVE_RESPONDER"); transportFailure(exchange, 503);
        } catch (MethodFailure method) { audit(requestId, Optional.ofNullable(auditedResponder), transportPrincipal, requesterPrincipal, "METHOD_REJECTED"); transportFailure(exchange, 405);
        } catch (MediaFailure media) { audit(requestId, Optional.ofNullable(auditedResponder), transportPrincipal, requesterPrincipal, "MEDIA_REJECTED"); transportFailure(exchange, 406);
        } catch (IllegalArgumentException malformed) { audit(requestId, Optional.ofNullable(auditedResponder), transportPrincipal, requesterPrincipal, "MALFORMED"); protocolFailure(exchange, OCSP_MALFORMED_REQUEST);
        } catch (RejectedExecutionException overload) { audit(requestId, Optional.ofNullable(auditedResponder), transportPrincipal, requesterPrincipal, "OVERLOAD"); transportFailure(exchange, 429);
        } catch (zeroecho.pki.api.SigningExecutionException signingFailure) { int status = signingFailureStatus(signingFailure); audit(requestId, Optional.ofNullable(auditedResponder), transportPrincipal, requesterPrincipal, status == 429 ? "OVERLOAD" : "UNAVAILABLE"); transportFailure(exchange, status);
        } catch (OcspResponseService.SigningPendingException pending) { audit(requestId,
                Optional.ofNullable(auditedResponder), transportPrincipal, requesterPrincipal,
                "SIGNING_PENDING"); protocolFailure(exchange,
                        OCSP_TRY_LATER);
        } catch (TimeoutException deadline) { audit(requestId, Optional.ofNullable(auditedResponder), transportPrincipal, requesterPrincipal, "DEADLINE"); transportFailure(exchange, 504);
        } catch (RuntimeException failure) { audit(requestId, Optional.ofNullable(auditedResponder), transportPrincipal, requesterPrincipal, "UNAVAILABLE"); transportFailure(exchange, 503);
        } finally { if (admitted) runtime.releaseAdmission(); exchange.close(); }
    }

    private OcspResponderService.Responder activeResponder(String alias) {
        try {
            OcspResponderService.Responder responder = realm.ocspResponders().requireAlias(alias);
            if (responder.state() != OcspResponderService.State.ACTIVE) throw new InactiveResponder();
            return realm.ocspResponders().requireActiveAlias(alias);
        } catch (IllegalArgumentException unavailable) {
            throw new UnknownAlias();
        }
    }

    private Execution execute(OcspResponderService.Responder responder,
            OcspRequestParser.Parsed parsed) throws TimeoutException {
        IssuerGeneration issuer = realm.session().repository().issuer(responder.issuerId()).orElseThrow();
        IssuerChainPath path = realm.session().repository().chainPath(responder.chainPathId()).orElseThrow();
        List<PkiId> chain = new ArrayList<>();
        if (responder.signingMode() == OcspResponderService.SigningMode.DELEGATED_RESPONDER) {
            chain.add(responder.responderCredentialId());
        }
        chain.addAll(path.orderedCredentialIds());
        Instant produced = producedAt(responder, parsed.nonce().isPresent());
        OcspResponseService.Command command = new OcspResponseService.Command(responder.authorityId(),
                responder.issuerId(), issuer.credentialId(), responder.responderCredentialId(),
                responder.signingKeyRef(), chain, responder.signatureAlgorithm(), responder.signatureBindingId(),
                responder.responderIdForm(), produced, produced, produced.plus(responder.responseValidity()),
                parsed.nonce(), parsed.requests());
        ServerRuntime.Submitted<Execution> submitted = runtime.submit(cancellation -> {
            cancellation.throwIfCancelled();
            Optional<String> requester = parsed.signedRequest().map(value -> requesters.authenticate(responder,
                    value, parsed.requests()).principalId());
            cancellation.throwIfCancelled();
            if (responder.noncePolicy() == OcspResponderService.NoncePolicy.REQUIRED
                    && !nonceReplay.accept(responder.responderId(), parsed.nonce().orElseThrow(), clock.instant(),
                            responder.responseValidity())) {
                throw new IllegalArgumentException("OCSP nonce was already used");
            }
            return new Execution(TransportCancellationGateway.respondOcsp(
                    realm.session().ocsp().orElseThrow(), command, cancellation), requester);
        });
        try {
            return submitted.future().get(configuration.maximumStreamDuration().toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException failure) {
            submitted.cancellation().cancel(); submitted.future().cancel(true); Thread.currentThread().interrupt();
            throw new TimeoutException("OCSP operation interrupted");
        } catch (TimeoutException failure) {
            submitted.cancellation().cancel(); submitted.future().cancel(true);
            throw failure;
        } catch (ExecutionException failure) {
            if (failure.getCause() instanceof RuntimeException runtimeFailure) throw runtimeFailure;
            throw new IllegalStateException("OCSP operation failed");
        } finally { submitted.finish(); }
    }

    private Instant producedAt(OcspResponderService.Responder responder, boolean nonce) {
        Instant now = clock.instant().truncatedTo(ChronoUnit.SECONDS);
        if (nonce) {
            return now;
        }
        long seconds = Math.max(1L, responder.cacheLifetime().toSeconds());
        long bucket = Math.multiplyExact(Math.floorDiv(now.getEpochSecond(), seconds), seconds);
        Instant produced = Instant.ofEpochSecond(bucket);
        try (PkiRepositoryContent content = realm.session().repository()
                .openCredential(responder.responderCredentialId()); InputStream input = content.openStream()) {
            byte[] encoded = input.readNBytes(1_048_577);
            if (encoded.length > 1_048_576 || input.read() != -1) {
                throw new IllegalStateException("OCSP responder certificate exceeds its finite bound");
            }
            Instant notBefore = zeroecho.pkix.Pkix.parseCertificate(encoded).getNotBefore().toInstant();
            return produced.isBefore(notBefore) ? notBefore : produced;
        } catch (IOException | RuntimeException failure) {
            throw new IllegalStateException("OCSP responder certificate is unavailable");
        }
    }

    private Optional<String> validateTransport(HttpExchange exchange, String requestId) {
        Map<String, List<String>> headers = Map.copyOf(exchange.getRequestHeaders());
        boolean forwarded = ForwardedClientCertificateParser.containsForwardedIdentity(headers);
        if (configuration.authentication().mode() == AdministrativeAuthenticationMode.DIRECT_MTLS) {
            if (forwarded) throw new IllegalArgumentException("Forwarded identity is prohibited");
            return Optional.empty();
        }
        Optional<PkiServerAuthenticationContext> context = tlsContext(exchange, requestId, headers);
        Optional<String> transport = context.flatMap(authenticator::authenticatePublicProxyTransport);
        if (transport.isEmpty()) {
            throw new IllegalArgumentException("Proxy transport is unauthenticated");
        }
        return transport;
    }

    private Optional<PkiServerAuthenticationContext> tlsContext(HttpExchange exchange, String requestId,
            Map<String, List<String>> headers) {
        if (!(exchange instanceof HttpsExchange https)) return Optional.empty();
        try {
            Certificate[] peers = https.getSSLSession().getPeerCertificates(); List<X509Certificate> chain = new ArrayList<>();
            for (Certificate peer : peers) { if (!(peer instanceof X509Certificate certificate)) return Optional.empty(); chain.add(certificate); }
            return Optional.of(new PkiServerAuthenticationContext(chain, https.getSSLSession().getProtocol(),
                    https.getSSLSession().getCipherSuite(), requestId, realm.configuration().realmId(), headers));
        } catch (SSLPeerUnverifiedException failure) { return Optional.empty(); }
    }

    private Route route(HttpExchange exchange) {
        String path = exchange.getRequestURI().getRawPath();
        if (exchange.getRequestURI().getRawQuery() != null || path.indexOf('%') >= 0) throw new IllegalArgumentException();
        String[] part = path.split("/", -1);
        if (part.length != 3 && part.length != 4 || !"".equals(part[0]) || !"ocsp".equals(part[1])
                || !part[2].matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) throw new UnknownAlias();
        if (part.length == 3) {
            if (!"POST".equals(exchange.getRequestMethod())) throw new MethodFailure();
            requireAccept(exchange.getRequestHeaders());
            List<String> type = exchange.getRequestHeaders().get("Content-Type");
            if (type == null || type.size() != 1 || !MEDIA_REQUEST.equalsIgnoreCase(type.getFirst())) throw new IllegalArgumentException();
            requireBodyFraming(exchange.getRequestHeaders());
            return new Route(part[2], Optional.empty());
        }
        if (!"GET".equals(exchange.getRequestMethod())) throw new MethodFailure();
        requireAccept(exchange.getRequestHeaders());
        return new Route(part[2], Optional.of(OcspRequestParser.decodeGet(part[3], configuration.maximumBodyBytes())));
    }

    private void requireHeadersBounded(Headers headers) {
        int total = 0;
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            total = Math.addExact(total, entry.getKey().getBytes(StandardCharsets.UTF_8).length);
            for (String value : entry.getValue()) {
                total = Math.addExact(total, value.getBytes(StandardCharsets.UTF_8).length);
                if (total > configuration.maximumHeaderBytes()) {
                    throw new IllegalArgumentException("OCSP request headers are oversized");
                }
            }
        }
    }

    private static void requireAccept(Headers headers) {
        List<String> accept = headers.get("Accept");
        if (accept != null && (accept.size() != 1 || !("*/*".equals(accept.getFirst())
                || MEDIA_RESPONSE.equalsIgnoreCase(accept.getFirst())))) {
            throw new MediaFailure();
        }
    }

    private static void requireBodyFraming(Headers headers) {
        if (headers.containsKey("Transfer-Encoding")) throw new IllegalArgumentException("OCSP framing is invalid");
        List<String> length = headers.get("Content-Length");
        if (length != null) {
            if (length.size() != 1 || !length.getFirst().matches("[0-9]{1,10}")) {
                throw new IllegalArgumentException("OCSP content length is invalid");
            }
        }
    }

    private static byte[] read(HttpExchange exchange, int maximum) {
        try (InputStream input = exchange.getRequestBody(); ByteArrayOutputStream output = new ByteArrayOutputStream(Math.min(maximum, 16_384))) {
            byte[] buffer = new byte[8192]; int total = 0;
            while (true) { int count = input.read(buffer); if (count < 0) break; if (count == 0) throw new IOException("No progress");
                total = Math.addExact(total, count); if (total > maximum) throw new IllegalArgumentException(); output.write(buffer, 0, count); }
            return output.toByteArray();
        } catch (IOException failure) { throw new IllegalArgumentException("OCSP request body is invalid"); }
    }

    private static void validateNonce(OcspResponderService.NoncePolicy policy, Optional<byte[]> nonce) {
        if (policy == OcspResponderService.NoncePolicy.REJECT && nonce.isPresent()
                || policy == OcspResponderService.NoncePolicy.REQUIRED && nonce.isEmpty()) throw new IllegalArgumentException();
    }

    private void send(HttpExchange exchange, OcspResponderService.Responder responder,
            OcspResponseService.Response response, boolean nonce, boolean signed, String requestId) throws IOException {
        Headers headers = exchange.getResponseHeaders(); headers.set("Content-Type", MEDIA_RESPONSE);
        headers.set("X-Content-Type-Options", "nosniff"); headers.set(RequestIds.HEADER, requestId);
        if (signed) { headers.set("Cache-Control", "private, no-store"); headers.set("Pragma", "no-cache"); }
        else if (nonce) { headers.set("Cache-Control", "no-store"); }
        else {
            long seconds = Math.min(responder.cacheLifetime().toSeconds(), responder.responseValidity().toSeconds());
            String validator = etag(response.der());
            headers.set("Cache-Control", "public, max-age=" + seconds);
            headers.set("Expires", java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME.format(
                    java.time.ZonedDateTime.ofInstant(clock.instant().plusSeconds(seconds), java.time.ZoneOffset.UTC)));
            headers.set("ETag", validator);
            List<String> conditional = exchange.getRequestHeaders().get("If-None-Match");
            if (conditional != null && conditional.size() == 1 && validator.equals(conditional.getFirst())) {
                exchange.sendResponseHeaders(304, -1);
                return;
            }
        }
        exchange.sendResponseHeaders(200, response.der().length);
        try (OutputStream output = exchange.getResponseBody()) { output.write(response.der()); }
    }

    private static void protocolFailure(HttpExchange exchange, int status) throws IOException {
        byte[] body = protocolFailureBody(status);
        exchange.getResponseHeaders().set("Content-Type", MEDIA_RESPONSE); exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(200, body.length); try (OutputStream output = exchange.getResponseBody()) { output.write(body); }
    }
    /* default */ static byte[] protocolFailureBody(int status) {
        // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED } with responseBytes absent.
        return new byte[] { 0x30, 0x03, 0x0A, 0x01, (byte) status };
    }
    private static void transportFailure(HttpExchange exchange, int status) throws IOException {
        exchange.getResponseHeaders().set("Cache-Control", "no-store"); exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.sendResponseHeaders(status, -1);
    }
    static int signingFailureStatus(zeroecho.pki.api.SigningExecutionException failure) {
        return failure.classification() == zeroecho.pki.api.SigningExecutionException.Classification.OVERLOADED
                ? 429 : 503;
    }
    private void audit(String requestId, Optional<OcspResponderService.Responder> responder,
            Optional<String> transportPrincipal, Optional<String> requesterPrincipal, String classification) {
        Map<String, String> details = new java.util.LinkedHashMap<>();
        details.put("request", requestId); details.put("classification", classification);
        responder.ifPresent(value -> details.put("responder", value.responderId()));
        transportPrincipal.ifPresent(value -> details.put("transportPrincipal", value));
        requesterPrincipal.ifPresent(value -> details.put("requesterPrincipal", value));
        realm.auditTransport("OCSP_REQUEST", requesterPrincipal.orElse("anonymous"), Map.copyOf(details));
    }
    private static String etag(byte[] value) {
        try { return '"' + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)) + '"'; }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); }
    }
    private record Route(String alias, Optional<byte[]> encoded) { Route { encoded = encoded.map(byte[]::clone); } }
    private record Execution(OcspResponseService.Response response, Optional<String> requesterPrincipal) {
        Execution { java.util.Objects.requireNonNull(response); requesterPrincipal = java.util.Objects.requireNonNull(requesterPrincipal); }
    }
    private static void requireAuthenticationMode(OcspResponderService.RequestAuthenticationMode mode,
            Optional<OcspRequesterService.SignedRequest> signed) {
        if (mode == OcspResponderService.RequestAuthenticationMode.AUTHORIZED_SIGNED_REQUIRED && signed.isEmpty()) {
            throw new SignatureRequired();
        }
        if (mode == OcspResponderService.RequestAuthenticationMode.UNSIGNED_ONLY && signed.isPresent()) {
            throw new OcspRequesterService.UnauthorizedException();
        }
    }
    private static final class UnknownAlias extends RuntimeException { private static final long serialVersionUID = 1L; }
    private static final class InactiveResponder extends RuntimeException { private static final long serialVersionUID = 1L; }
    private static final class MethodFailure extends RuntimeException { private static final long serialVersionUID = 1L; }
    private static final class MediaFailure extends RuntimeException { private static final long serialVersionUID = 1L; }
    private static final class SignatureRequired extends RuntimeException { private static final long serialVersionUID = 1L; }
    private static final class NonceReplayGuard {
        private static final int MAXIMUM_ENTRIES = 4096;
        private final java.util.LinkedHashMap<String, Instant> accepted = new java.util.LinkedHashMap<>();
        synchronized boolean accept(String responderId, byte[] nonce, Instant now, java.time.Duration lifetime) {
            accepted.entrySet().removeIf(entry -> !now.isBefore(entry.getValue()));
            String key = etag((responderId + ':' + HexFormat.of().formatHex(nonce))
                    .getBytes(StandardCharsets.US_ASCII));
            if (accepted.containsKey(key) || accepted.size() >= MAXIMUM_ENTRIES) return false;
            accepted.put(key, now.plus(lifetime));
            return true;
        }
    }
}
