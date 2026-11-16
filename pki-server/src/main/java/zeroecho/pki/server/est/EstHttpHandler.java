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
package zeroecho.pki.server.est;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;

import javax.net.ssl.SSLPeerUnverifiedException;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsExchange;

import zeroecho.pki.server.ServerRealmContext;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.server.http.ServerRuntime;
import zeroecho.pki.server.http.RequestIds;
import zeroecho.pki.server.http.HybridSdkHttpCodec;
import zeroecho.pki.server.PkiServerConfiguration;

/**
 * HTTP handler for the EST RFC 7030 protocol.
 *
 * <p>URL structure: {@code /.well-known/est/{label}/{operation}} where {@code label} is
 * the registered endpoint label and {@code operation} is one of
 * {@code cacerts}, {@code simpleenroll}, {@code simplereenroll}, {@code csrattrs},
 * {@code serverkeygen}.</p>
 *
 * <p>Routed native EST and enabled SDK operations require a peer X.509 certificate
 * from the HTTPS session; absent peer identity produces HTTP 401. Readiness,
 * admission and disabled-route checks can return before that identity check.
 * The listener's TLS policy establishes peer validation; the handler does not
 * authenticate a supplied Java certificate object independently.</p>
 *
 * <p>Enabled SDK sidepaths require the exact configured origin/media type and
 * closed action grammar. Runtime cancellation and timeout handling do not prove
 * that a durable enrollment was rolled back. The realm service/coordinator owns
 * exact replay, admission and retained operation recovery.</p>
 *
 * @since 1.0
 */
@SuppressWarnings("PMD.AvoidCatchingGenericException")
public final class EstHttpHandler implements HttpHandler {

    private static final int MAX_BODY_BYTES = 64 * 1024;

    private final EstService service;
    private final ServerRuntime runtime;
    private final RequestIds requestIds;
    private final BooleanSupplier ready;
    private final int maximumBodyBytes;
    private final Duration maximumDeadline;
    private final Optional<PkiServerConfiguration.HybridSdkListener> hybridSdk;

    /**
     * Creates an EST boundary with mutual TLS and runtime admission control.
     *
     * @param realm owning realm
     * @param service EST operations
     * @param runtime admission controller
     * @param requestIds request correlation policy
     * @param ready readiness predicate
     * @param configuredMaximumBodyBytes listener request-body bound, capped at 64 KiB
     * @param maximumDeadline positive execution deadline, at most one hour
     * @throws NullPointerException if a required dependency, deadline or SDK option container is null
     * @throws IllegalArgumentException if the body limit is not positive or deadline is outside zero-exclusive
     *     through one hour
     */
    public EstHttpHandler(ServerRealmContext realm, EstService service, ServerRuntime runtime,
            RequestIds requestIds, BooleanSupplier ready, int configuredMaximumBodyBytes, Duration maximumDeadline) {
        this(realm, service, runtime, requestIds, ready, configuredMaximumBodyBytes, maximumDeadline, Optional.empty());
    }

    /**
     * Adds explicitly configured SDK sidepaths while preserving the existing native boundary.
     *
     * @param realm owning realm
     * @param service EST operations
     * @param runtime bounded execution
     * @param requestIds request correlation
     * @param ready readiness predicate
     * @param configuredMaximumBodyBytes existing body limit, still capped at64KiB
     * @param maximumDeadline existing execution deadline
     * @param hybridSdk explicit configured SDK origin
     * @throws NullPointerException if a required dependency, deadline or SDK option container is null
     * @throws IllegalArgumentException if the body limit is not positive or deadline is outside zero-exclusive
     *     through one hour
     */
    public EstHttpHandler(ServerRealmContext realm, EstService service, ServerRuntime runtime,
            RequestIds requestIds, BooleanSupplier ready, int configuredMaximumBodyBytes, Duration maximumDeadline,
            Optional<PkiServerConfiguration.HybridSdkListener> hybridSdk) {
        this.hybridSdk = Objects.requireNonNull(hybridSdk, "hybridSdk");
        Objects.requireNonNull(realm, "realm");
        this.service = Objects.requireNonNull(service, "service");
        this.runtime = Objects.requireNonNull(runtime, "runtime");
        this.requestIds = Objects.requireNonNull(requestIds, "requestIds");
        this.ready = Objects.requireNonNull(ready, "ready");
        if (configuredMaximumBodyBytes <= 0) {
            throw new IllegalArgumentException("EST body bound must be positive");
        }
        this.maximumBodyBytes = Math.min(MAX_BODY_BYTES, configuredMaximumBodyBytes);
        this.maximumDeadline = Objects.requireNonNull(maximumDeadline, "maximumDeadline");
        if (maximumDeadline.isNegative() || maximumDeadline.isZero() || maximumDeadline.compareTo(Duration.ofHours(1)) > 0) {
            throw new IllegalArgumentException("EST execution deadline is invalid");
        }
    }

    /**
     * Handles one exchange using readiness/rate admission and a bounded runtime task.
     *
     * <p>Request bodies and ordinary response streams are closed by the routed
     * helpers. Encrypted key delivery is claimed once for this exchange, streamed
     * with its lease and cancellation signal, and not replaced by an error body
     * after delivery was claimed. Admission capacity is released in a finally
     * block; this does not undo any already durable protocol operation.</p>
     *
     * @param exchange HTTPS exchange supplied by the server listener
     * @throws IOException if request/response transport cannot complete
     */
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String requestId = "unavailable-request";
        try {
            requestId = requestIds.resolve(exchange.getRequestHeaders().get(RequestIds.HEADER));
            if (!ready.getAsBoolean()) {
                send(exchange, requestId, 503, EstCmsCodec.CONTENT_TYPE_PKCS10,
                        "EST server is not ready".getBytes(StandardCharsets.UTF_8));
                return;
            }
            if (!runtime.tryAdmit()) {
                sendError(exchange, requestId, 429, "EST request rate limit exceeded");
                return;
            }
            try {
                String exactRequestId = requestId;
                java.util.concurrent.atomic.AtomicBoolean deliveryClaimed = new java.util.concurrent.atomic.AtomicBoolean();
                Response response;
                try {
                    response = runtime.execute(maximumDeadline, cancellation -> {
                        Response routed = route(exchange, cancellation);
                        if (routed.keygen().isPresent() && routed.status() == 200) {
                            cancellation.throwIfCancelled();
                            if (!deliveryClaimed.compareAndSet(false, true)) {
                                throw new java.io.InterruptedIOException("EST delivery cancelled");
                            }
                            sendKeygen(exchange, exactRequestId, routed.keygen().orElseThrow(), cancellation);
                            return null;
                        }
                        return routed;
                    });
                } catch (TimeoutException timeout) {
                    if (!deliveryClaimed.compareAndSet(false, true)) { exchange.close(); return; }
                    response = error(504, "EST request timed out");
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt(); // NOPMD DoNotUseThreads - Restores caller cancellation after interruption; this standalone component creates no thread.
                    if (!deliveryClaimed.compareAndSet(false, true)) { exchange.close(); return; }
                    response = error(503, "EST request interrupted");
                } catch (ExecutionException failure) {
                    if (!deliveryClaimed.compareAndSet(false, true)) { exchange.close(); return; }
                    Throwable cause = failure.getCause();
                    response = cause instanceof EstProtocolException protocol ? error(protocol.httpStatus(), protocol.getMessage())
                            : cause instanceof IllegalArgumentException ? error(400, "Invalid EST request") : error(503, "EST request unavailable");
                }
                if (response == null) {
                    return;
                }
                response.retryAfterSeconds().ifPresent(value -> exchange.getResponseHeaders().set("Retry-After", Long.toString(value)));
                send(exchange, requestId, response.status(), response.contentType(), response.body());
            } catch (RejectedExecutionException overloaded) {
                sendError(exchange, requestId, 503, "EST service is overloaded");
            } finally {
                runtime.releaseAdmission();
            }
        } catch (RuntimeException failure) {
            sendError(exchange, requestId, 500, "EST internal error");
        }
    }

    private Response route(HttpExchange exchange, CancellationSignal cancellation) throws IOException, EstProtocolException {
        cancellation.throwIfCancelled();
        String requestPath = exchange.getRequestURI().getPath();
        String[] sdkSegments = requestPath.startsWith("/.well-known/est/")
                ? requestPath.substring("/.well-known/est/".length()).split("/", -1) : new String[0];
        boolean sdkPath = sdkSegments.length >= 2 && "hybrid-sdk".equals(sdkSegments[1]);
        if (sdkPath && hybridSdk.isEmpty()) return error(404, "EST SDK is disabled");
        // Require mTLS client certificate.
        X509Certificate clientCert;
        try {
            clientCert = requireClientCert((HttpsExchange) exchange);
        } catch (EstProtocolException ex) {
            return error(ex.httpStatus(), ex.getMessage());
        }

        // Parse URL: /.well-known/est/{label}/{operation}
        String path = exchange.getRequestURI().getPath();
        if (exchange.getRequestURI().getRawQuery() != null) {
            return error(400, "EST does not accept query parameters");
        }
        // path must start with /.well-known/est/
        if (!path.startsWith("/.well-known/est/")) {
            return error(404, "EST endpoint not found");
        }
        String after = path.substring("/.well-known/est/".length());
        // split into label and operation
        int slash = after.indexOf('/');
        if (slash < 0) {
            return error(404, "EST operation not specified");
        }
        String label = after.substring(0, slash);
        String operation = after.substring(slash + 1);
        if (!label.isEmpty() && (operation.equals("hybrid-sdk") || operation.startsWith("hybrid-sdk/"))) {
            var endpoint = service.find(label).orElse(null);
            if (endpoint == null) return error(404, "EST endpoint is not registered");
            return sdkRoute(exchange, endpoint, operation, clientCert, cancellation);
        }
        if (label.isEmpty() || operation.isEmpty() || operation.contains("/")) {
            return error(404, "EST endpoint or operation not found");
        }

        Optional<EstEndpoint> maybeEndpoint = service.find(label);
        if (maybeEndpoint.isEmpty()) {
            return error(404, "EST endpoint is not registered");
        }
        EstEndpoint endpoint = maybeEndpoint.get();

        return dispatch(exchange, endpoint, operation, clientCert, cancellation);
    }

    private Response sdkRoute(HttpExchange exchange, EstEndpoint endpoint, String operation, X509Certificate certificate,
            CancellationSignal cancellation) throws IOException, EstProtocolException {
        if (hybridSdk.isEmpty() || !exchange.getRequestURI().getRawPath().equals(exchange.getRequestURI().getPath())
                || exchange.getRequestURI().getRawFragment() != null) return error(404, "EST SDK path not recognized");
        String[] parts = operation.split("/", -1);
        if (parts.length < 2 || !"v1".equals(parts[1])) return error(404, "EST SDK path not recognized");
        if (parts.length == 2) {
            if (!"GET".equals(exchange.getRequestMethod())) return error(405, "EST SDK capability requires GET");
            if (!service.hybridSdkAvailable(endpoint)) return error(404, "EST SDK profile unavailable");
            String base = "/.well-known/est/" + endpoint.label() + "/hybrid-sdk/v1";
            return new Response(200, HybridSdkHttpCodec.MEDIA_TYPE, HybridSdkHttpCodec.capability(base,
                    java.util.List.of("simpleenroll", "simplereenroll"), hybridSdk.orElseThrow().canonicalOrigin(), maximumBodyBytes), Optional.empty());
        }
        if (parts.length != 3 || !("challenge".equals(parts[2]) || "accept".equals(parts[2]))) return error(404, "EST SDK path not recognized");
        if (!"POST".equals(exchange.getRequestMethod())) return error(405, "EST SDK action requires POST");
        String media = exchange.getRequestHeaders().getFirst("Content-Type");
        if (media == null || !HybridSdkHttpCodec.MEDIA_TYPE.equalsIgnoreCase(media.trim())) return error(415, "EST SDK content type required");
        boolean acceptance = "accept".equals(parts[2]);
        var fields = HybridSdkHttpCodec.parse(readBody(exchange), maximumBodyBytes, acceptance, java.util.Set.of("operation", "requestDer"));
        String selected = HybridSdkHttpCodec.text(fields, "operation");
        byte[] der = HybridSdkHttpCodec.bytes(fields, "requestDer", 1, zeroecho.pki.api.request.X509EnrollmentPayload.MAXIMUM_DER_BYTES);
        String origin = hybridSdk.orElseThrow().canonicalOrigin();
        if (!acceptance) {
            var challenge = service.challengeSdk(endpoint, selected, der, certificate, HybridSdkHttpCodec.bytes(fields, "clientNonce", 32, 32), origin);
            return new Response(200, HybridSdkHttpCodec.MEDIA_TYPE, HybridSdkHttpCodec.challenge(challenge.intentId(), challenge.primaryFrame(), challenge.targetFrame()), Optional.empty());
        }
        return enrollment(service.acceptSdk(endpoint, selected, der, certificate, HybridSdkHttpCodec.text(fields, "intentId"), HybridSdkHttpCodec.text(fields, "sdkRequestId"),
                HybridSdkHttpCodec.bytes(fields, "primaryProof", 1, 104), HybridSdkHttpCodec.bytes(fields, "alternativeProof", 4627, 4627), origin, cancellation));
    }

    private Response dispatch(HttpExchange exchange, EstEndpoint endpoint,
            String operation, X509Certificate clientCert, CancellationSignal cancellation) throws IOException, EstProtocolException {
        String method = exchange.getRequestMethod();
        return switch (operation) {
            case "cacerts" -> {
                requireMethod(method, "GET", exchange);
                byte[] response = service.cacerts(endpoint);
                yield new Response(200, EstCmsCodec.CONTENT_TYPE_CERTS_ONLY, response, Optional.empty());
            }
            case "simpleenroll" -> {
                requireMethod(method, "POST", exchange);
                byte[] body = readBody(exchange);
                EstService.EnrollmentResult response = service.simpleenroll(endpoint, body, clientCert,
                        cancellation);
                yield enrollment(response);
            }
            case "simplereenroll" -> {
                requireMethod(method, "POST", exchange);
                byte[] body = readBody(exchange);
                EstService.EnrollmentResult response = service.simplereenroll(endpoint, body, clientCert,
                        cancellation);
                yield enrollment(response);
            }
            case "csrattrs" -> {
                requireMethod(method, "GET", exchange);
                byte[] response = service.csrattrs(endpoint);
                yield new Response(200, EstCmsCodec.CONTENT_TYPE_CSRATTRS, response, Optional.empty());
            }
            case "serverkeygen" -> {
                requireMethod(method, "POST", exchange);
                byte[] body = readBody(exchange);
                EstServerKeygenResponse keygenResponse = service.serverkeygen(endpoint, body, clientCert, cancellation);
                yield new Response(keygenResponse.status(), keygenResponse.contentType(), new byte[0], keygenResponse.retryAfterSeconds(), Optional.of(keygenResponse));
            }
            default -> error(404, "Unknown EST operation");
        };
    }

    private static Response enrollment(EstService.EnrollmentResult response) {
        return new Response(response.status(), response.status() == 200 ? EstCmsCodec.CONTENT_TYPE_CERTS_ONLY : "text/plain",
                response.body(), response.retryAfterSeconds());
    }

    private static Response error(int status, String message) {
        return new Response(status, "text/plain; charset=utf-8", message.getBytes(StandardCharsets.UTF_8), Optional.empty());
    }

    private record Response(int status, String contentType, byte[] body, Optional<Long> retryAfterSeconds, Optional<EstServerKeygenResponse> keygen) {
        /* default */ Response(int status, String contentType, byte[] body, Optional<Long> retryAfterSeconds) {
            this(status, contentType, body, retryAfterSeconds, Optional.empty());
        }
    }

    private void sendKeygen(HttpExchange exchange, String requestId, EstServerKeygenResponse response, CancellationSignal cancellation) throws IOException {
        try (exchange) {
            try (EstServerKeygenResponse.Body body = response.openDelivery()) {
                cancellation.throwIfCancelled();
                exchange.getResponseHeaders().set(RequestIds.HEADER, requestId);
                exchange.getResponseHeaders().set("Content-Type", response.contentType());
                exchange.getResponseHeaders().set("Cache-Control", "no-store");
                exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
                exchange.sendResponseHeaders(200, 0);
                try (OutputStream output = exchange.getResponseBody()) { body.writeTo(output, cancellation); }
            } catch (EstProtocolException unavailable) {
                cancellation.throwIfCancelled();
                sendError(exchange, requestId, unavailable.httpStatus(), unavailable.getMessage());
            }
        }
    }

    private void requireMethod(String actual, String expected, HttpExchange exchange)
            throws IOException, EstProtocolException {
        if (!expected.equalsIgnoreCase(actual)) {
            exchange.getResponseHeaders().set("Allow", expected);
            throw new EstProtocolException(405, "EST operation requires " + expected);
        }
    }

    private byte[] readBody(HttpExchange exchange) throws IOException, EstProtocolException {
        try (InputStream in = exchange.getRequestBody()) {
            byte[] body = in.readNBytes(maximumBodyBytes + 1);
            if (body.length > maximumBodyBytes) {
                throw new EstProtocolException(413, "EST request body exceeds maximum allowed size");
            }
            if (body.length == 0) {
                throw new EstProtocolException(400, "EST request body is empty");
            }
            return body;
        }
    }

    private static X509Certificate requireClientCert(HttpsExchange exchange) throws EstProtocolException {
        try {
            Certificate[] peer = exchange.getSSLSession().getPeerCertificates();
            if (peer == null || peer.length == 0 || !(peer[0] instanceof X509Certificate x509)) {
                throw new EstProtocolException(401, "EST requires a valid mTLS client certificate");
            }
            return x509;
        } catch (SSLPeerUnverifiedException failure) {
            throw new EstProtocolException(401, "EST mTLS client certificate is required but absent", failure);
        }
    }

    private void send(HttpExchange exchange, String requestId, int status, String contentType, byte[] body)
            throws IOException {
        exchange.getResponseHeaders().set(RequestIds.HEADER, requestId);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        if (EstCmsCodec.CONTENT_TYPE_CERTS_ONLY.equals(contentType)) {
            exchange.getResponseHeaders().set("Content-Transfer-Encoding", "base64");
        }
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
        exchange.close();
    }

    private void sendError(HttpExchange exchange, String requestId, int status, String message)
            throws IOException {
        byte[] body = message.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set(RequestIds.HEADER, requestId);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
        exchange.close();
    }
}
