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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsExchange;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.application.OcspResponseService;
import zeroecho.pki.application.PkiRepositoryContent;
import zeroecho.pki.server.AdministrativeAuthenticationMode;
import zeroecho.pki.server.OcspRequesterService;
import zeroecho.pki.server.OcspResponderService;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.spi.PkiServerAuthenticationContext;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;

import javax.net.ssl.SSLPeerUnverifiedException;

/**
 * Strict anonymous OCSP protocol adapter on the public listener only.
 */
/* default */ final class OcspHttpHandler implements HttpHandler {
    private static final String HTTP_POST = "POST";

    private static final String TEXT_CACHE_CONTROL = "Cache-Control";

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
    private final OcspNonceReplayGuard nonceReplay = new OcspNonceReplayGuard();

    /**
     * Composes the OCSP responder HTTP boundary from borrowed realm and execution services.
     *
     * @param configuration listener limits and exposure policy
     * @param realm lifecycle-owned realm context
     * @param authenticator transport identity authenticator
     * @param runtime lifecycle-owned admission and operation execution owner
     * @param clock deadline and audit time source
     * @param requestIds correlation-identifier validator/generator
     * @param ready readiness observation checked before request admission
     * @throws NullPointerException if a collaborator is null
     */
    /* default */ OcspHttpHandler(PkiServerConfiguration.PublicListener configuration, ServerRealmContext realm,
            AdministrativeAuthenticator authenticator, ServerRuntime runtime, Clock clock,
            RequestIds requestIds, BooleanSupplier ready) {
        this.configuration = java.util.Objects.requireNonNull(configuration); this.realm = java.util.Objects.requireNonNull(realm);
        this.authenticator = java.util.Objects.requireNonNull(authenticator); this.runtime = java.util.Objects.requireNonNull(runtime);
        this.clock = java.util.Objects.requireNonNull(clock); this.requestIds = java.util.Objects.requireNonNull(requestIds);
        this.ready = java.util.Objects.requireNonNull(ready);
        this.requesters = new OcspRequesterService(realm, clock);
    }

    /**
     * {@inheritDoc}
     */
    // This transport boundary must preserve cleanup and finite masking of provider/runtime
    // failures. Preserve the
    // exact exchange-finally ownership and close-failure precedence.
    @SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.UseTryWithResources"})
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        RequestState state = new RequestState();
        try {
            new Processing().handleRequest(exchange, state);
        } catch (SignatureRequired required) {
            audit(
                    state.requestId,
                    Optional.ofNullable(state.auditedResponder),
                    state.transportPrincipal,
                    state.requesterPrincipal,
                    "SIGNATURE_REQUIRED");
            protocolOrSdkFailure(exchange, state.sdkExchange, OCSP_SIG_REQUIRED, 401);
        } catch (OcspRequesterService.UnauthorizedException unauthorized) {
            audit(
                    state.requestId,
                    Optional.ofNullable(state.auditedResponder),
                    state.transportPrincipal,
                    state.requesterPrincipal,
                    "REQUESTER_UNAUTHORIZED_" + unauthorized.classification());
            protocolOrSdkFailure(exchange, state.sdkExchange, OCSP_UNAUTHORIZED, 403);
        } catch (OcspRequesterService.UnavailableException unavailable) {
            audit(
                    state.requestId,
                    Optional.ofNullable(state.auditedResponder),
                    state.transportPrincipal,
                    state.requesterPrincipal,
                    "REQUESTER_AUTHORITY_UNAVAILABLE");
            protocolOrSdkFailure(exchange, state.sdkExchange, OCSP_TRY_LATER, 503);
        } catch (UnknownAlias unavailable) {
            audit(
                    state.requestId,
                    Optional.empty(),
                    state.transportPrincipal,
                    state.requesterPrincipal,
                    "UNKNOWN_RESPONDER");
            transportFailure(exchange, 404);
        } catch (InactiveResponder inactive) {
            audit(
                    state.requestId,
                    Optional.empty(),
                    state.transportPrincipal,
                    state.requesterPrincipal,
                    "INACTIVE_RESPONDER");
            transportFailure(exchange, 503);
        } catch (MethodFailure method) {
            audit(
                    state.requestId,
                    Optional.ofNullable(state.auditedResponder),
                    state.transportPrincipal,
                    state.requesterPrincipal,
                    "METHOD_REJECTED");
            transportFailure(exchange, 405);
        } catch (MediaFailure media) {
            audit(
                    state.requestId,
                    Optional.ofNullable(state.auditedResponder),
                    state.transportPrincipal,
                    state.requesterPrincipal,
                    "MEDIA_REJECTED");
            transportFailure(exchange, 406);
        } catch (IllegalArgumentException malformed) {
            audit(
                    state.requestId,
                    Optional.ofNullable(state.auditedResponder),
                    state.transportPrincipal,
                    state.requesterPrincipal,
                    "MALFORMED");
            protocolOrSdkFailure(exchange, state.sdkExchange, OCSP_MALFORMED_REQUEST, 400);
        } catch (RejectedExecutionException overload) {
            audit(
                    state.requestId,
                    Optional.ofNullable(state.auditedResponder),
                    state.transportPrincipal,
                    state.requesterPrincipal,
                    "OVERLOAD");
            transportFailure(exchange, 429);
        } catch (zeroecho.pki.api.SigningExecutionException signingFailure) {
            int status = signingFailureStatus(signingFailure);
            audit(
                    state.requestId,
                    Optional.ofNullable(state.auditedResponder),
                    state.transportPrincipal,
                    state.requesterPrincipal,
                    status == 429 ? "OVERLOAD" : "UNAVAILABLE");
            transportFailure(exchange, status);
        } catch (OcspResponseService.SigningPendingException pending) {
            audit(
                    state.requestId,
                    Optional.ofNullable(state.auditedResponder),
                    state.transportPrincipal,
                    state.requesterPrincipal,
                    "SIGNING_PENDING");
            protocolOrSdkFailure(exchange, state.sdkExchange, OCSP_TRY_LATER, 503);
        } catch (TimeoutException deadline) {
            audit(
                    state.requestId,
                    Optional.ofNullable(state.auditedResponder),
                    state.transportPrincipal,
                    state.requesterPrincipal,
                    "DEADLINE");
            transportFailure(exchange, 504);
        } catch (RuntimeException failure) {
            audit(
                    state.requestId,
                    Optional.ofNullable(state.auditedResponder),
                    state.transportPrincipal,
                    state.requesterPrincipal,
                    "UNAVAILABLE");
            transportFailure(exchange, 503);
        } finally {
            if (state.admitted) {
                runtime.releaseAdmission();
            }
            exchange.close();
        }
    }

    // Untrusted transport/parser failures retain the existing finite safe HTTP diagnostics.
    @SuppressWarnings({"PMD.PreserveStackTrace"})
    private OcspResponderService.Responder activeResponder(String alias) {
        try {
            OcspResponderService.Responder responder = realm.ocspResponders().requireAlias(alias);
            if (responder.state() != OcspResponderService.State.ACTIVE) {
                throw new InactiveResponder();
            }
            return realm.ocspResponders().requireActiveAlias(alias);
        } catch (IllegalArgumentException unavailable) {
            throw new UnknownAlias();
        }
    }

    private Optional<String> validateTransport(HttpExchange exchange, String requestId) {
        Map<String, List<String>> headers = Map.copyOf(exchange.getRequestHeaders());
        boolean forwarded = ForwardedClientCertificateParser.containsForwardedIdentity(headers);
        if (configuration.authentication().mode() == AdministrativeAuthenticationMode.DIRECT_MTLS) {
            if (forwarded) {
                throw new IllegalArgumentException("Forwarded identity is prohibited");
            }
            return Optional.empty();
        }
        Optional<PkiServerAuthenticationContext> context = tlsContext(exchange, requestId, headers);
        Optional<String> transport =
                context.flatMap(authenticator::authenticatePublicProxyTransport);
        if (transport.isEmpty()) {
            throw new IllegalArgumentException("Proxy transport is unauthenticated");
        }
        return transport;
    }

    private Optional<PkiServerAuthenticationContext> tlsContext(
            HttpExchange exchange, String requestId, Map<String, List<String>> headers) {
        if (!(exchange instanceof HttpsExchange https)) {
            return Optional.empty();
        }
        try {
            Certificate[] peers = https.getSSLSession().getPeerCertificates();
            List<X509Certificate> chain = new ArrayList<>();
            for (Certificate peer : peers) {
                if (!(peer instanceof X509Certificate certificate)) {
                    return Optional.empty();
                }
                chain.add(certificate);
            }
            return Optional.of(
                    new PkiServerAuthenticationContext(
                            chain,
                            https.getSSLSession().getProtocol(),
                            https.getSSLSession().getCipherSuite(),
                            requestId,
                            realm.configuration().realmId(),
                            headers));
        } catch (SSLPeerUnverifiedException failure) {
            return Optional.empty();
        }
    }

    private void requireHeadersBounded(Map<String, List<String>> headers) {
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

    private static void validateNonce(
            OcspResponderService.NoncePolicy policy, Optional<byte[]> nonce) {
        if (policy == OcspResponderService.NoncePolicy.REJECT && nonce.isPresent()
                || policy == OcspResponderService.NoncePolicy.REQUIRED && nonce.isEmpty()) {
            throw new IllegalArgumentException();
        }
    }

    private void send(
            HttpExchange exchange,
            OcspResponderService.Responder responder,
            OcspResponseService.Response response,
            boolean nonce,
            boolean signed,
            String requestId)
            throws IOException {
        Map<String, List<String>> headers = exchange.getResponseHeaders();
        HttpHeaderFields.set(headers, "Content-Type", MEDIA_RESPONSE);
        HttpHeaderFields.set(headers, "X-Content-Type-Options", "nosniff");
        HttpHeaderFields.set(headers, RequestIds.HEADER, requestId);
        if (signed) {
            HttpHeaderFields.set(headers, TEXT_CACHE_CONTROL, "private, no-store");
            HttpHeaderFields.set(headers, "Pragma", "no-cache");
        } else if (nonce) {
            HttpHeaderFields.set(headers, TEXT_CACHE_CONTROL, "no-store");
        } else {
            long seconds =
                    Math.min(
                            responder.cacheLifetime().toSeconds(),
                            responder.responseValidity().toSeconds());
            String validator = OcspNonceReplayGuard.etag(response.der());
            HttpHeaderFields.set(headers, TEXT_CACHE_CONTROL, "public, max-age=" + seconds);
            HttpHeaderFields.set(
                    headers,
                    "Expires",
                    java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME.format(
                            java.time.ZonedDateTime.ofInstant(
                                    clock.instant().plusSeconds(seconds),
                                    java.time.ZoneOffset.UTC)));
            HttpHeaderFields.set(headers, "ETag", validator);
            List<String> conditional = exchange.getRequestHeaders().get("If-None-Match");
            if (conditional != null
                    && conditional.size() == 1
                    && validator.equals(conditional.getFirst())) {
                exchange.sendResponseHeaders(304, -1);
                return;
            }
        }
        exchange.sendResponseHeaders(200, response.der().length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(response.der());
        }
    }

    private static void sendSdk(HttpExchange exchange, byte[] body, String requestId)
            throws IOException {
        Map<String, List<String>> headers = exchange.getResponseHeaders();
        HttpHeaderFields.set(headers, "Content-Type", SdkOcspHttpCodec.MEDIA);
        HttpHeaderFields.set(headers, TEXT_CACHE_CONTROL, "no-store");
        HttpHeaderFields.set(headers, "Pragma", "no-cache");
        HttpHeaderFields.set(headers, "X-Content-Type-Options", "nosniff");
        HttpHeaderFields.set(headers, RequestIds.HEADER, requestId);
        exchange.sendResponseHeaders(200, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private static void protocolOrSdkFailure(
            HttpExchange exchange, boolean sdk, int nativeStatus, int httpStatus)
            throws IOException {
        if (sdk) {
            transportFailure(exchange, httpStatus);
        } else {
            protocolFailure(exchange, nativeStatus);
        }
    }

    private static void protocolFailure(HttpExchange exchange, int status) throws IOException {
        byte[] body = protocolFailureBody(status);
        exchange.getResponseHeaders().set("Content-Type", MEDIA_RESPONSE);
        exchange.getResponseHeaders().set(TEXT_CACHE_CONTROL, "no-store");
        exchange.sendResponseHeaders(200, body.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(body);
        }
    }

    /**
     * Encodes an OCSPResponse carrying only its protocol response-status value.
     *
     * @param status OCSP response-status enumeration value; caller validates its protocol range
     * @return newly allocated five-byte DER response without responseBytes
     */
    /* default */ static byte[] protocolFailureBody(int status) {
        // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED } with responseBytes absent.
        return new byte[] {0x30, 0x03, 0x0A, 0x01, (byte) status};
    }

    private static void transportFailure(HttpExchange exchange, int status) throws IOException {
        exchange.getResponseHeaders().set(TEXT_CACHE_CONTROL, "no-store");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.sendResponseHeaders(status, -1);
    }

    /**
     * Maps responder signing overload to HTTP admission guidance.
     *
     * @param failure classified signing execution failure
     * @return 429 for overload, otherwise 503
     * @throws NullPointerException if failure is null
     */
    /* default */ static int signingFailureStatus(zeroecho.pki.api.SigningExecutionException failure) {
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

    private record Route(String alias, Optional<byte[]> encoded,boolean sdk,boolean capability) { /* default */ Route { encoded = encoded.map(byte[]::clone); } }
    private record SdkExecution(zeroecho.pki.api.hybrid.sdk.SdkOcspEvidence evidence,Optional<String> requesterPrincipal) { }
    private record Execution(OcspResponseService.Response response, Optional<String> requesterPrincipal) {
        /* default */ Execution { java.util.Objects.requireNonNull(response); requesterPrincipal = java.util.Objects.requireNonNull(requesterPrincipal); }
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
    /** Signals an unavailable responder without disclosing registry state. */
    private static final class UnknownAlias extends RuntimeException { private static final long serialVersionUID = 1L; }
    /** Signals a configured responder that cannot currently serve responses. */
    private static final class InactiveResponder extends RuntimeException { private static final long serialVersionUID = 1L; }
    /** Preserves the native method-rejection status mapping. */
    private static final class MethodFailure extends RuntimeException { private static final long serialVersionUID = 1L; }
    /** Preserves the native media-rejection status mapping. */
    private static final class MediaFailure extends RuntimeException { private static final long serialVersionUID = 1L; }
    /** Preserves the native signature-required protocol response. */
    private static final class SignatureRequired extends RuntimeException { private static final long serialVersionUID = 1L; }

    /** Carries the same late-bound request/audit coordinates through failure mapping and release. */
    private static final class RequestState {
private String requestId = "unavailable-request"; private boolean admitted; private boolean sdkExchange;
        private OcspResponderService.Responder auditedResponder;
        private Optional<String> transportPrincipal = Optional.empty();
        private Optional<String> requesterPrincipal = Optional.empty();
    }

    /** Runs admitted native/SDK request parsing and bounded PKI execution. */
    private final class Processing {
        private void handleRequest(HttpExchange exchange, RequestState state)
                throws IOException, TimeoutException {

            state.requestId =
                    requestIds.resolve(exchange.getRequestHeaders().get(RequestIds.HEADER));
            if (!ready.getAsBoolean()) {
                transportFailure(exchange, 503);
                return;
            }
            requireHeadersBounded(exchange.getRequestHeaders());
            state.transportPrincipal = validateTransport(exchange, state.requestId);
            Route route = new Routing().route(exchange);
            state.sdkExchange = route.sdk();
            if (!runtime.tryAdmit()) {
                audit(
                        state.requestId,
                        Optional.empty(),
                        state.transportPrincipal,
                        Optional.empty(),
                        "OVERLOAD");
                transportFailure(exchange, 429);
                return;
            }
            state.admitted = true;
            OcspResponderService.Responder responder = activeResponder(route.alias());
            state.auditedResponder = responder;
            if (route.sdk() && responder.hybridSdk().isEmpty()) {
                throw new UnknownAlias();
            }
            if (route.capability()) {
                sendSdk(
                        exchange,
                        SdkOcspHttpCodec.capability(
                                configuration.hybridSdk().orElseThrow().canonicalOrigin(),
                                configuration.maximumBodyBytes(),
                                Math.min(
                                        configuration.maximumBodyBytes(),
                                        responder.maximumRequestBytes()),
                                Math.min(819, responder.maximumEntries())),
                        state.requestId);
                return;
            }
            audit(
                    state.requestId,
                    Optional.of(responder),
                    state.transportPrincipal,
                    Optional.empty(),
                    "ACCEPTED");
            int maximumRequestBytes =
                    Math.min(configuration.maximumBodyBytes(), responder.maximumRequestBytes());
            SdkOcspHttpCodec.Query sdkQuery =
                    route.sdk()
                            ? SdkOcspHttpCodec.decode(
                                    Routing.read(exchange, configuration.maximumBodyBytes()),
                                    configuration.maximumBodyBytes(),
                                    maximumRequestBytes)
                            : null;
            byte[] request =
                    route.sdk()
                            ? sdkQuery.requestDer()
                            : route.encoded()
                                    .orElseGet(() -> Routing.read(exchange, maximumRequestBytes));
            if (request.length > maximumRequestBytes) {
                transportFailure(exchange, 413);
                return;
            }
            OcspRequestParser.Parsed parsed =
                    OcspRequestParser.parse(
                            request,
                            route.sdk()
                                    ? Math.min(819, responder.maximumEntries())
                                    : responder.maximumEntries(),
                            responder.acceptedHashes(),
                            responder.maximumNonceBytes(),
                            responder
                                    .requesterTrustPolicy()
                                    .map(
                                            OcspResponderService.RequesterTrustPolicy
                                                    ::maximumSignerCertificates)
                                    .orElse(16),
                            responder
                                    .requesterTrustPolicy()
                                    .map(
                                            OcspResponderService.RequesterTrustPolicy
                                                    ::maximumSignerChainBytes)
                                    .orElse(maximumRequestBytes));
            validateNonce(responder.noncePolicy(), parsed.nonce());
            requireAuthenticationMode(
                    responder.requestAuthenticationMode(), parsed.signedRequest());
            if (route.sdk()) {
                SdkExecution execution = executeSdk(responder, parsed, sdkQuery);
                state.requesterPrincipal = execution.requesterPrincipal();
                sendSdk(exchange, SdkOcspHttpCodec.encode(execution.evidence()), state.requestId);
                audit(
                        state.requestId,
                        Optional.of(responder),
                        state.transportPrincipal,
                        state.requesterPrincipal,
                        "SDK_RESPONDED");
                return;
            }
            Execution execution = execute(responder, parsed);
            state.requesterPrincipal = execution.requesterPrincipal();
            send(
                    exchange,
                    responder,
                    execution.response(),
                    parsed.nonce().isPresent(),
                    parsed.signedRequest().isPresent(),
                    state.requestId);
            OcspResponseService.Response response = execution.response();
            audit(
                    state.requestId,
                    Optional.of(responder),
                    state.transportPrincipal,
                    state.requesterPrincipal,
                    "RESPONDED_GOOD_"
                            + response.goodCount()
                            + "_REVOKED_"
                            + response.revokedCount()
                            + "_UNKNOWN_"
                            + response.unknownCount());
        }

        private Execution execute(
                OcspResponderService.Responder responder, OcspRequestParser.Parsed parsed)
                throws TimeoutException {
            IssuerGeneration issuer =
                    realm.session().repository().issuer(responder.issuerId()).orElseThrow();
            IssuerChainPath path =
                    realm.session().repository().chainPath(responder.chainPathId()).orElseThrow();
            List<PkiId> chain = new ArrayList<>();
            if (responder.signingMode() == OcspResponderService.SigningMode.DELEGATED_RESPONDER) {
                chain.add(responder.responderCredentialId());
            }
            chain.addAll(path.orderedCredentialIds());
            Instant produced = producedAt(responder, parsed.nonce().isPresent());
            OcspResponseService.Command command =
                    new OcspResponseService.Command(
                            responder.authorityId(),
                            responder.issuerId(),
                            issuer.credentialId(),
                            responder.responderCredentialId(),
                            responder.signingKeyRef(),
                            chain,
                            responder.signatureAlgorithm(),
                            responder.signatureBindingId(),
                            responder.responderIdForm(),
                            produced,
                            produced,
                            produced.plus(responder.responseValidity()),
                            parsed.nonce(),
                            parsed.requests());
            ServerRuntime.Submitted<Execution> submitted =
                    runtime.submit(
                            cancellation -> {
                                cancellation.throwIfCancelled();
                                Optional<String> requester =
                                        authenticateNative(responder, parsed, cancellation);
                                return new Execution(
                                        TransportCancellationGateway.respondOcsp(
                                                realm.session().ocsp().orElseThrow(),
                                                command,
                                                cancellation),
                                        requester);
                            });
            return await(submitted);
        }

        private Optional<String> authenticateNative(
                OcspResponderService.Responder responder,
                OcspRequestParser.Parsed parsed,
                zeroecho.core.io.CancellationSignal cancellation)
                throws java.io.InterruptedIOException {
            Optional<String> requester =
                    parsed.signedRequest()
                            .map(
                                    value ->
                                            requesters
                                                    .authenticate(
                                                            responder, value, parsed.requests())
                                                    .principalId());
            cancellation.throwIfCancelled();
            if (responder.noncePolicy() == OcspResponderService.NoncePolicy.REQUIRED
                    && !nonceReplay.accept(
                            responder.responderId(),
                            parsed.nonce().orElseThrow(),
                            clock.instant(),
                            responder.responseValidity())) {
                throw new IllegalArgumentException("OCSP nonce was already used");
            }
            return requester;
        }

        private SdkExecution executeSdk(
                OcspResponderService.Responder responder,
                OcspRequestParser.Parsed parsed,
                SdkOcspHttpCodec.Query query)
                throws TimeoutException {
            ServerRuntime.Submitted<SdkExecution> submitted =
                    runtime.submit(
                            cancellation -> {
                                cancellation.throwIfCancelled();
                                Optional<String> requester =
                                        authenticateNative(responder, parsed, cancellation);
                                OcspResponderService.SdkConfiguration sdk =
                                        responder.hybridSdk().orElseThrow();
                                OcspResponseService service = realm.session().ocsp().orElseThrow();
                                OcspResponseService.SdkResponderBinding binding =
                                        service.captureSdkResponderBinding(
                                                realm.configuration().realmId().value(),
                                                configuration
                                                        .hybridSdk()
                                                        .orElseThrow()
                                                        .canonicalOrigin(),
                                                responder.authorityId(),
                                                responder.issuerId(),
                                                responder.responderCredentialId(),
                                                responder.chainPathId(),
                                                new OcspResponseService.SdkSigningRole(
                                                        responder.signingKeyRef(),
                                                        responder.signatureAlgorithm(),
                                                        responder.signatureBindingId()),
                                                new OcspResponseService.SdkSigningRole(
                                                        sdk.alternativeKeyRef(),
                                                        sdk.alternativeSignatureAlgorithm(),
                                                        sdk.alternativeSignatureBindingId()),
                                                responder.responderIdForm(),
                                                cancellation);
                                return new SdkExecution(
                                        TransportCancellationGateway.respondSdkOcsp(
                                                service,
                                                new OcspResponseService.SdkCommand(
                                                        binding,
                                                        query.requestDer(),
                                                        query.clientNonce(),
                                                        responder.responseValidity()),
                                                cancellation),
                                        requester);
                            });
            return await(submitted);
        }

        // The standalone transport owns bounded task executors and preserves cancellation/thread
        // lifetime. Untrusted
        // transport/parser failures retain the existing finite safe HTTP diagnostics.
        @SuppressWarnings({"PMD.DoNotUseThreads", "PMD.PreserveStackTrace"})
        private <T> T await(ServerRuntime.Submitted<T> submitted) throws TimeoutException {
            try {
                return submitted
                        .future()
                        .get(
                                configuration.maximumStreamDuration().toMillis(),
                                TimeUnit.MILLISECONDS);
            } catch (InterruptedException failure) {
                submitted.cancellation().cancel();
                submitted.future().cancel(true);
                Thread.currentThread().interrupt();
                throw new TimeoutException("OCSP operation interrupted");
            } catch (TimeoutException failure) {
                submitted.cancellation().cancel();
                submitted.future().cancel(true);
                throw failure;
            } catch (ExecutionException failure) {
                if (failure.getCause() instanceof RuntimeException runtimeFailure) {
                    throw runtimeFailure;
                }
                throw new IllegalStateException("OCSP operation failed");
            } finally {
                submitted.finish();
            }
        }

        // This transport boundary must preserve cleanup and finite masking of provider/runtime
        // failures. Untrusted
        // transport/parser failures retain the existing finite safe HTTP diagnostics.
        @SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace"})
        private Instant producedAt(OcspResponderService.Responder responder, boolean nonce) {
            Instant now = clock.instant().truncatedTo(ChronoUnit.SECONDS);
            if (nonce) {
                return now;
            }
            long seconds = Math.max(1L, responder.cacheLifetime().toSeconds());
            long bucket = Math.multiplyExact(Math.floorDiv(now.getEpochSecond(), seconds), seconds);
            Instant produced = Instant.ofEpochSecond(bucket);
            try (PkiRepositoryContent content =
                            realm.session()
                                    .repository()
                                    .openCredential(responder.responderCredentialId());
                    InputStream input = content.openStream()) {
                byte[] encoded = boundedCertificate(input);
                Instant notBefore =
                        zeroecho.pkix.Pkix.parseCertificate(encoded).getNotBefore().toInstant();
                return produced.isBefore(notBefore) ? notBefore : produced;
            } catch (IOException | RuntimeException failure) {
                throw new IllegalStateException("OCSP responder certificate is unavailable");
            }
        }

        private static byte[] boundedCertificate(InputStream input) throws IOException {
            byte[] encoded = input.readNBytes(1_048_577);
            if (encoded.length > 1_048_576 || input.read() != -1) {
                throw new IllegalStateException(
                        "OCSP responder certificate exceeds its finite bound");
            }
            return encoded;
        }
}

    /** Checks exact native and SDK HTTP routing/media grammar. */
    private final class Routing {
        private Route route(HttpExchange exchange) {
            String path = exchange.getRequestURI().getRawPath();
            if (exchange.getRequestURI().getRawQuery() != null || path.indexOf('%') >= 0) {
                throw new IllegalArgumentException();
            }
            String[] part = path.split("/", -1);
            if (sdkPath(part)) {
                return sdkRoute(exchange, part);
            }
            requireNativePath(part);
            if (part.length == OCSP_TRY_LATER) {
                if (!HTTP_POST.equals(exchange.getRequestMethod())) {
                    throw new MethodFailure();
                }
                requireAccept(exchange.getRequestHeaders());
                List<String> type = exchange.getRequestHeaders().get("Content-Type");
                if (type == null
                        || type.size() != 1
                        || !MEDIA_REQUEST.equalsIgnoreCase(type.getFirst())) {
                    throw new IllegalArgumentException();
                }
                requireBodyFraming(exchange.getRequestHeaders());
                return new Route(part[2], Optional.empty(), false, false);
            }
            if (!"GET".equals(exchange.getRequestMethod())) {
                throw new MethodFailure();
            }
            requireAccept(exchange.getRequestHeaders());
            return new Route(
                    part[2],
                    Optional.of(
                            OcspRequestParser.decodeGet(
                                    part[OCSP_TRY_LATER], configuration.maximumBodyBytes())),
                    false,
                    false);
        }

        private static void requireAccept(Map<String, List<String>> headers) {
            List<String> accept = headers.get("Accept");
            if (accept != null
                    && (accept.size() != 1
                            || !("*/*".equals(accept.getFirst())
                                    || MEDIA_RESPONSE.equalsIgnoreCase(accept.getFirst())))) {
                throw new MediaFailure();
            }
        }

        private static void requireBodyFraming(Map<String, List<String>> headers) {
            if (headers.containsKey("Transfer-Encoding")) {
                throw new IllegalArgumentException("OCSP framing is invalid");
            }
            List<String> length = headers.get("Content-Length");
            if (length != null
                    && (length.size() != 1 || !length.getFirst().matches("[0-9]{1,10}"))) {
                throw new IllegalArgumentException("OCSP content length is invalid");
            }
        }

        // Untrusted transport/parser failures retain the existing finite safe HTTP diagnostics.
        @SuppressWarnings({"PMD.PreserveStackTrace"})
        private static byte[] read(HttpExchange exchange, int maximum) {
            try (InputStream input = exchange.getRequestBody();
                    ByteArrayOutputStream output =
                            new ByteArrayOutputStream(Math.min(maximum, 16_384))) {
                byte[] buffer = new byte[8_192];
                int total = 0;
                while (true) {
                    int count = input.read(buffer);
                    if (count < 0) {
                        break;
                    }
                    requireProgress(count);
                    total = Math.addExact(total, count);
                    if (total > maximum) {
                        throw new IllegalArgumentException();
                    }
                    output.write(buffer, 0, count);
                }
                return output.toByteArray();
            } catch (IOException failure) {
                throw new IllegalArgumentException("OCSP request body is invalid");
            }
        }

        private static boolean sdkPath(String... part) {
            return part.length == 5
                    && part[0].isEmpty()
                    && "ocsp".equals(part[1])
                    && part[2].matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
                    && "hybrid-sdk".equals(part[OCSP_TRY_LATER])
                    && "v1".equals(part[4]);
        }

        private static void requireNativePath(String... part) {
            if (part.length != OCSP_TRY_LATER && part.length != 4
                    || !"".equals(part[0])
                    || !"ocsp".equals(part[1])
                    || !part[2].matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) {
                throw new UnknownAlias();
            }
        }

        private Route sdkRoute(HttpExchange exchange, String... part) {

            if (configuration.hybridSdk().isEmpty()) {
                throw new UnknownAlias();
            }
            String method = exchange.getRequestMethod();
            if (!"GET".equals(method) && !HTTP_POST.equals(method)) {
                throw new MethodFailure();
            }
            requireSdkAccept(exchange.getRequestHeaders().get("Accept"));
            requireBodyFraming(exchange.getRequestHeaders());
            if (HTTP_POST.equals(method)) {
                requireSdkMedia(exchange.getRequestHeaders().get("Content-Type"));
            } else if (exchange.getRequestHeaders().containsKey("Content-Length")
                    && !"0".equals(exchange.getRequestHeaders().getFirst("Content-Length"))) {
                throw new IllegalArgumentException("SDK capability carries no body");
            }
            return new Route(part[2], Optional.empty(), true, "GET".equals(method));
        }

        private static void requireSdkAccept(List<String> accept) {
            if (accept != null
                    && (accept.size() != 1
                            || !("*/*".equals(accept.getFirst())
                                    || SdkOcspHttpCodec.MEDIA.equalsIgnoreCase(
                                            accept.getFirst())))) {
                throw new MediaFailure();
            }
        }

        private static void requireSdkMedia(List<String> type) {
            if (type == null
                    || type.size() != 1
                    || !SdkOcspHttpCodec.MEDIA.equalsIgnoreCase(type.getFirst())) {
                throw new MediaFailure();
            }
        }

        private static void requireProgress(int count) throws IOException {
            if (count == 0) {
                throw new IOException("No progress");
            }
        }
}
}
