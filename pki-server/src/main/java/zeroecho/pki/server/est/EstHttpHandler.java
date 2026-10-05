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
package zeroecho.pki.server.est;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BooleanSupplier;

import javax.net.ssl.SSLPeerUnverifiedException;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsExchange;

import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.http.ServerRuntime;
import zeroecho.pki.server.http.RequestIds;

/**
 * HTTP handler for the EST RFC 7030 protocol.
 *
 * <p>URL structure: {@code /.well-known/est/{label}/{operation}} where {@code label} is
 * the registered endpoint label and {@code operation} is one of
 * {@code cacerts}, {@code simpleenroll}, {@code simplereenroll}, {@code csrattrs},
 * {@code serverkeygen}.</p>
 *
 * <p>All EST operations require mutual TLS. Requests without a valid client certificate
 * are rejected with HTTP 401.</p>
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

    /** Creates an EST boundary with mutual TLS and runtime admission control.
     * @param realm owning realm
     * @param service EST operations
     * @param runtime admission controller
     * @param requestIds request correlation policy
     * @param ready readiness predicate
     */
    public EstHttpHandler(ServerRealmContext realm, EstService service, ServerRuntime runtime,
            RequestIds requestIds, BooleanSupplier ready) {
        Objects.requireNonNull(realm, "realm");
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
                route(exchange, requestId);
            } finally {
                runtime.releaseAdmission();
            }
        } catch (RuntimeException failure) {
            sendError(exchange, requestId, 500, "EST internal error");
        }
    }

    private void route(HttpExchange exchange, String requestId) throws IOException {
        // Require mTLS client certificate.
        X509Certificate clientCert;
        try {
            clientCert = requireClientCert((HttpsExchange) exchange);
        } catch (EstProtocolException ex) {
            sendError(exchange, requestId, ex.httpStatus(), ex.getMessage());
            return;
        }

        // Parse URL: /.well-known/est/{label}/{operation}
        String path = exchange.getRequestURI().getPath();
        if (exchange.getRequestURI().getRawQuery() != null) {
            sendError(exchange, requestId, 400, "EST does not accept query parameters");
            return;
        }
        // path must start with /.well-known/est/
        if (!path.startsWith("/.well-known/est/")) {
            sendError(exchange, requestId, 404, "EST endpoint not found");
            return;
        }
        String after = path.substring("/.well-known/est/".length());
        // split into label and operation
        int slash = after.indexOf('/');
        if (slash < 0) {
            sendError(exchange, requestId, 404, "EST operation not specified");
            return;
        }
        String label = after.substring(0, slash);
        String operation = after.substring(slash + 1);
        if (label.isEmpty() || operation.isEmpty() || operation.contains("/")) {
            sendError(exchange, requestId, 404, "EST endpoint or operation not found");
            return;
        }

        Optional<EstEndpoint> maybeEndpoint = service.find(label);
        if (maybeEndpoint.isEmpty()) {
            sendError(exchange, requestId, 404, "EST endpoint '" + label + "' is not registered");
            return;
        }
        EstEndpoint endpoint = maybeEndpoint.get();

        try {
            dispatch(exchange, requestId, endpoint, operation, clientCert);
        } catch (EstProtocolException ex) {
            sendError(exchange, requestId, ex.httpStatus(), ex.getMessage());
        }
    }

    private void dispatch(HttpExchange exchange, String requestId, EstEndpoint endpoint,
            String operation, X509Certificate clientCert) throws IOException, EstProtocolException {
        String method = exchange.getRequestMethod();
        switch (operation) {
            case "cacerts" -> {
                requireMethod(method, "GET", exchange);
                byte[] response = service.cacerts(endpoint);
                send(exchange, requestId, 200, EstCmsCodec.CONTENT_TYPE_CERTS_ONLY, response);
            }
            case "simpleenroll" -> {
                requireMethod(method, "POST", exchange);
                byte[] body = readBody(exchange);
                byte[] response = service.simpleenroll(endpoint, body, clientCert);
                send(exchange, requestId, 200, EstCmsCodec.CONTENT_TYPE_CERTS_ONLY, response);
            }
            case "simplereenroll" -> {
                requireMethod(method, "POST", exchange);
                byte[] body = readBody(exchange);
                byte[] response = service.simplereenroll(endpoint, body, clientCert);
                send(exchange, requestId, 200, EstCmsCodec.CONTENT_TYPE_CERTS_ONLY, response);
            }
            case "csrattrs" -> {
                requireMethod(method, "GET", exchange);
                byte[] response = service.csrattrs(endpoint);
                send(exchange, requestId, 200, EstCmsCodec.CONTENT_TYPE_CSRATTRS, response);
            }
            case "serverkeygen" -> {
                requireMethod(method, "POST", exchange);
                byte[] body = readBody(exchange);
                EstServerKeygenResponse keygenResponse = service.serverkeygen(endpoint, body, clientCert);
                String contentType = "multipart/mixed; boundary=\"" + keygenResponse.multipartBoundary() + "\"";
                send(exchange, requestId, 200, contentType, keygenResponse.encryptedPrivateKeyDer());
            }
            default -> sendError(exchange, requestId, 404, "Unknown EST operation: " + operation);
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
            byte[] body = in.readNBytes(MAX_BODY_BYTES + 1);
            if (body.length > MAX_BODY_BYTES) {
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
