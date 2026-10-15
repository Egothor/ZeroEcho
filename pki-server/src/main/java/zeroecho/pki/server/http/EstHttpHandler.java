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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;

import javax.net.ssl.SSLPeerUnverifiedException;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsExchange;

import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.est.EstEndpoint;
import zeroecho.pki.server.est.EstProtocolException;
import zeroecho.pki.server.est.EstServerKeygenResponse;
import zeroecho.pki.server.est.EstService;

/** Strict EST RFC 7030 route adapter; protocol state and PKI business rules remain in {@link EstService}. */
@SuppressWarnings("PMD")
final class EstHttpHandler implements HttpHandler {
    private static final String CERTS_ONLY = "application/pkcs7-mime; smime-type=certs-only";
    private static final String CSRATTRS = "application/csrattrs";
    private static final String TEXT_PLAIN = "text/plain; charset=utf-8";
    private static final String WELL_KNOWN_EST = "/.well-known/est";

    private final PkiServerConfiguration.EstListener configuration;
    private final ServerRealmContext realm;
    private final EstService service;
    private final ServerRuntime runtime;
    private final RequestIds requestIds;
    private final BooleanSupplier ready;

    EstHttpHandler(PkiServerConfiguration.EstListener configuration, ServerRealmContext realm,
            EstService service, ServerRuntime runtime, RequestIds requestIds, BooleanSupplier ready) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.realm = Objects.requireNonNull(realm, "realm");
        this.service = Objects.requireNonNull(service, "service");
        this.runtime = Objects.requireNonNull(runtime, "runtime");
        this.requestIds = Objects.requireNonNull(requestIds, "requestIds");
        this.ready = Objects.requireNonNull(ready, "ready");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String requestId = "unavailable-request";
        try {
            requestId = requestIds.resolve(exchange.getRequestHeaders().get(RequestIds.HEADER));
            requireHeaders(exchange.getRequestHeaders());
            if (!ready.getAsBoolean()) {
                send(exchange, 503, TEXT_PLAIN, "EST service is not ready".getBytes(StandardCharsets.UTF_8), requestId);
                return;
            }
            if (!runtime.tryAdmit()) {
                send(exchange, 503, TEXT_PLAIN, "EST service is overloaded".getBytes(StandardCharsets.UTF_8), requestId);
                return;
            }
            try {
                String exactRequestId = requestId;
                java.util.concurrent.atomic.AtomicBoolean deliveryClaimed = new java.util.concurrent.atomic.AtomicBoolean();
                EstResponse response;
                try {
                    response = runtime.execute(configuration.execution().maximumDeadline(), cancellation -> {
                        EstResponse routed = route((HttpsExchange) exchange, exactRequestId, cancellation);
                        if (routed.keygen().isPresent() && routed.status() == 200) {
                            cancellation.throwIfCancelled();
                            if (!deliveryClaimed.compareAndSet(false, true)) throw new java.io.InterruptedIOException("EST delivery cancelled");
                            sendKeygen(exchange, routed.keygen().orElseThrow(), exactRequestId, cancellation);
                            return null;
                        }
                        return routed;
                    });
                } catch (TimeoutException timeout) {
                    if (!deliveryClaimed.compareAndSet(false, true)) { exchange.close(); return; }
                    response = errorResponse(504, "EST request timed out");
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    if (!deliveryClaimed.compareAndSet(false, true)) { exchange.close(); return; }
                    response = errorResponse(503, "EST request interrupted");
                } catch (ExecutionException failure) {
                    if (!deliveryClaimed.compareAndSet(false, true)) { exchange.close(); return; }
                    response = protocolFailure(failure.getCause());
                }
                if (response == null) return;
                response.retryAfterSeconds().ifPresent(value -> exchange.getResponseHeaders().set("Retry-After", Long.toString(value)));
                send(exchange, response.status(), response.contentType(), response.body(), requestId);
            } catch (RejectedExecutionException overloaded) {
                send(exchange, 503, TEXT_PLAIN, "EST service is overloaded".getBytes(StandardCharsets.UTF_8), requestId);
            } finally {
                runtime.releaseAdmission();
            }
        } catch (IllegalArgumentException malformed) {
            send(exchange, 400, TEXT_PLAIN, "Bad request".getBytes(StandardCharsets.UTF_8), requestId);
        } catch (RuntimeException failure) {
            send(exchange, 500, TEXT_PLAIN, "Internal server error".getBytes(StandardCharsets.UTF_8), requestId);
        }
    }

    private EstResponse route(HttpsExchange exchange, String requestId, zeroecho.core.io.CancellationSignal cancellation) throws Exception {
        if (exchange.getRequestURI().getRawQuery() != null) {
            return errorResponse(400, "EST requests must not include query parameters");
        }
        String path = exchange.getRequestURI().getPath();
        if (!path.startsWith(WELL_KNOWN_EST)) {
            return errorResponse(404, "EST endpoint path not recognized");
        }
        String remainder = path.substring(WELL_KNOWN_EST.length());
        // remainder is either "", "/{operation}", or "/{label}/{operation}"
        String[] segments = remainder.isEmpty() ? new String[0] : remainder.substring(1).split("/", -1);
        String label;
        String operation;
        if (segments.length == 1) {
            label = "default";
            operation = segments[0];
        } else if (segments.length == 2) {
            label = segments[0];
            operation = segments[1];
        } else {
            return errorResponse(404, "EST path not recognized");
        }
        if (label.isEmpty() || operation.isEmpty()) {
            return errorResponse(404, "EST path not recognized");
        }
        EstEndpoint endpoint = service.find(label).orElse(null);
        String method = exchange.getRequestMethod();
        switch (operation) {
            case "cacerts": return handleCacerts(method, endpoint, label);
            case "simpleenroll": return handleSimpleenroll(method, endpoint, label, exchange, cancellation);
            case "simplereenroll": return handleSimplereenroll(method, endpoint, label, exchange, cancellation);
            case "csrattrs": return handleCsrattrs(method, endpoint, label);
            case "serverkeygen": return handleServerkeygen(method, endpoint, label, exchange, cancellation);
            default: return errorResponse(404, "EST operation not recognized: " + operation);
        }
    }

    private EstResponse handleCacerts(String method, EstEndpoint endpoint, String label) throws EstProtocolException {
        if (!"GET".equals(method)) return errorResponse(405, "Only GET is allowed for /cacerts");
        if (endpoint == null) return errorResponse(404, "EST label not registered: " + label);
        byte[] body = service.cacerts(endpoint);
        return new EstResponse(200, CERTS_ONLY, body);
    }

    private EstResponse handleSimpleenroll(String method, EstEndpoint endpoint, String label,
            HttpsExchange exchange, zeroecho.core.io.CancellationSignal cancellation) throws Exception {
        if (!"POST".equals(method)) return errorResponse(405, "Only POST is allowed for /simpleenroll");
        if (endpoint == null) return errorResponse(404, "EST label not registered: " + label);
        X509Certificate clientCert = extractClientCert(exchange);
        if (clientCert == null) return errorResponse(401, "EST simpleenroll requires a valid mTLS client certificate");
        byte[] csrBody = readBody(exchange.getRequestBody(), configuration.maximumBodyBytes());
        EstService.EnrollmentResult result = service.simpleenroll(endpoint, csrBody, clientCert, cancellation);
        return new EstResponse(result.status(), result.status() == 200 ? CERTS_ONLY : TEXT_PLAIN, result.body(), result.retryAfterSeconds());
    }

    private EstResponse handleSimplereenroll(String method, EstEndpoint endpoint, String label,
            HttpsExchange exchange, zeroecho.core.io.CancellationSignal cancellation) throws Exception {
        if (!"POST".equals(method)) return errorResponse(405, "Only POST is allowed for /simplereenroll");
        if (endpoint == null) return errorResponse(404, "EST label not registered: " + label);
        X509Certificate clientCert = extractClientCert(exchange);
        if (clientCert == null) return errorResponse(401, "EST simplereenroll requires a valid mTLS client certificate");
        byte[] csrBody = readBody(exchange.getRequestBody(), configuration.maximumBodyBytes());
        EstService.EnrollmentResult result = service.simplereenroll(endpoint, csrBody, clientCert, cancellation);
        return new EstResponse(result.status(), result.status() == 200 ? CERTS_ONLY : TEXT_PLAIN, result.body(), result.retryAfterSeconds());
    }

    private EstResponse handleCsrattrs(String method, EstEndpoint endpoint, String label) {
        if (!"GET".equals(method)) return errorResponse(405, "Only GET is allowed for /csrattrs");
        if (endpoint == null) return errorResponse(404, "EST label not registered: " + label);
        byte[] body = service.csrattrs(endpoint);
        return new EstResponse(200, CSRATTRS, body);
    }

    private EstResponse handleServerkeygen(String method, EstEndpoint endpoint, String label,
            HttpsExchange exchange, zeroecho.core.io.CancellationSignal cancellation) throws Exception {
        if (!"POST".equals(method)) return errorResponse(405, "Only POST is allowed for /serverkeygen");
        if (endpoint == null) return errorResponse(404, "EST label not registered: " + label);
        X509Certificate clientCert = extractClientCert(exchange);
        if (clientCert == null) return errorResponse(401, "EST serverkeygen requires a valid mTLS client certificate");
        byte[] csrBody = readBody(exchange.getRequestBody(), configuration.maximumBodyBytes());
        EstServerKeygenResponse keygen = service.serverkeygen(endpoint, csrBody, clientCert, cancellation);
        return new EstResponse(keygen.status(), keygen.contentType(), new byte[0], keygen.retryAfterSeconds(), java.util.Optional.of(keygen));
    }

    private static X509Certificate extractClientCert(HttpsExchange exchange) {
        try {
            Certificate[] certs = exchange.getSSLSession().getPeerCertificates();
            if (certs == null || certs.length == 0) return null;
            if (!(certs[0] instanceof X509Certificate x509)) return null;
            return x509;
        } catch (SSLPeerUnverifiedException absent) {
            return null;
        }
    }

    private static EstResponse protocolFailure(Throwable cause) {
        if (cause instanceof EstProtocolException ex) {
            return errorResponse(ex.httpStatus(), ex.getMessage());
        }
        return errorResponse(500, "EST internal error");
    }

    private static EstResponse errorResponse(int status, String message) {
        return new EstResponse(status, TEXT_PLAIN, message.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] readBody(InputStream input, int maximum) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(Math.min(maximum, 16_384));
        byte[] buffer = new byte[8192];
        int total = 0;
        for (int count; (count = input.read(buffer)) >= 0;) {
            if (count == 0) continue;
            total = Math.addExact(total, count);
            if (total > maximum) throw new IllegalArgumentException("EST request body is too large");
            output.write(buffer, 0, count);
        }
        return output.toByteArray();
    }

    private void requireHeaders(Headers headers) {
        long count = 0;
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            count += entry.getKey().length();
            for (String value : entry.getValue()) count += value.length();
            if (count > configuration.maximumHeaderBytes()) throw new IllegalArgumentException("EST headers too large");
        }
    }

    private static void send(HttpExchange exchange, int status, String contentType, byte[] body, String requestId)
            throws IOException {
        exchange.getResponseHeaders().set(RequestIds.HEADER, requestId);
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set("Content-Type", contentType);
        if (CERTS_ONLY.equals(contentType)) exchange.getResponseHeaders().set("Content-Transfer-Encoding", "base64");
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private static void sendKeygen(HttpExchange exchange, EstServerKeygenResponse response, String requestId,
            zeroecho.core.io.CancellationSignal cancellation) throws IOException {
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
            send(exchange, unavailable.httpStatus(), TEXT_PLAIN, unavailable.getMessage().getBytes(StandardCharsets.UTF_8), requestId);
        }
    }

    private record EstResponse(int status, String contentType, byte[] body, java.util.Optional<Long> retryAfterSeconds,
            java.util.Optional<EstServerKeygenResponse> keygen) {
        EstResponse(int status, String contentType, byte[] body) { this(status, contentType, body, java.util.Optional.empty()); }
        EstResponse(int status, String contentType, byte[] body, java.util.Optional<Long> retryAfterSeconds) {
            this(status, contentType, body, retryAfterSeconds, java.util.Optional.empty());
        }
        EstResponse {
            body = body.clone();
        }

        @Override
        public byte[] body() {
            return body.clone();
        }
    }
}
