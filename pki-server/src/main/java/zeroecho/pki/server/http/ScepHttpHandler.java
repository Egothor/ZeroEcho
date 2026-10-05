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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BooleanSupplier;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.scep.ScepEndpoint;
import zeroecho.pki.server.scep.ScepProtocolException;
import zeroecho.pki.server.scep.ScepService;

/**
 * SCEP RFC 8894 route adapter over the jdk.httpserver API.
 *
 * <p>Routes incoming requests by label and operation query parameter.
 * Supported operations: {@code GetCACert}, {@code GetCACertChain}, {@code PKIOperation}.
 * SCEP does not use mTLS — authentication is via the challenge password embedded
 * in the SCEP PKIMessage. The TLS layer provides confidentiality only.</p>
 *
 * <p>Content types per RFC 8894:</p>
 * <ul>
 *   <li>GetCACert (single CA): {@code application/x-x509-ca-cert}</li>
 *   <li>GetCACertChain: {@code application/x-x509-ca-ra-cert}</li>
 *   <li>PKIOperation: {@code application/x-pki-message}</li>
 * </ul>
 *
 * @since 1.0
 */
@SuppressWarnings("PMD")
final class ScepHttpHandler implements HttpHandler {

    private static final Logger LOG = Logger.getLogger(ScepHttpHandler.class.getName());

    private static final String TEXT_PLAIN = "text/plain; charset=utf-8";
    private static final String CONTENT_TYPE_CA_CERT = "application/x-x509-ca-cert";
    private static final String CONTENT_TYPE_CA_RA_CERT = "application/x-x509-ca-ra-cert";
    private static final String CONTENT_TYPE_PKI_MESSAGE = "application/x-pki-message";
    private static final String SCEP_PREFIX = "/scep/";

    private final PkiServerConfiguration.ScepListener configuration;
    private final ServerRealmContext realm;
    private final ScepService service;
    private final ServerRuntime runtime;
    private final RequestIds requestIds;
    private final BooleanSupplier ready;

    ScepHttpHandler(PkiServerConfiguration.ScepListener configuration, ServerRealmContext realm,
            ScepService service, ServerRuntime runtime, RequestIds requestIds, BooleanSupplier ready) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.realm = Objects.requireNonNull(realm, "realm");
        this.service = Objects.requireNonNull(service, "service");
        this.runtime = Objects.requireNonNull(runtime, "runtime");
        this.requestIds = Objects.requireNonNull(requestIds, "requestIds");
        this.ready = Objects.requireNonNull(ready, "ready");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            if (!ready.getAsBoolean()) {
                sendText(exchange, 503, "SCEP service is not ready");
                return;
            }
            String path = exchange.getRequestURI().getPath();
            if (!path.startsWith(SCEP_PREFIX)) {
                sendText(exchange, 404, "Not found");
                return;
            }
            String after = path.substring(SCEP_PREFIX.length());
            int slash = after.indexOf('/');
            String label = slash < 0 ? after : after.substring(0, slash);
            if (label.isEmpty()) {
                sendText(exchange, 404, "SCEP label is required");
                return;
            }
            Optional<ScepEndpoint> endpointOpt = service.find(label);
            if (endpointOpt.isEmpty()) {
                sendText(exchange, 404, "SCEP endpoint not found: " + label);
                return;
            }
            ScepEndpoint endpoint = endpointOpt.get();

            String query = exchange.getRequestURI().getQuery();
            String operation = extractOperation(query);
            if (operation == null) {
                sendText(exchange, 400, "SCEP operation query parameter is required");
                return;
            }

            switch (operation) {
                case "GetCACert" -> handleGetCaCert(exchange, endpoint);
                case "GetCACertChain" -> handleGetCaCertChain(exchange, endpoint);
                case "PKIOperation" -> handlePkiOperation(exchange, endpoint);
                default -> sendText(exchange, 400, "Unknown SCEP operation: " + operation);
            }
        } catch (Exception unexpected) {
            LOG.log(Level.WARNING, "Unexpected error in SCEP handler", unexpected);
            try {
                sendText(exchange, 500, "Internal SCEP error");
            } catch (IOException ignored) {
                // Already sent response; nothing to do
            }
        } finally {
            exchange.close();
        }
    }

    private void handleGetCaCert(HttpExchange exchange, ScepEndpoint endpoint) throws IOException {
        try {
            byte[] certDer = service.getCaCert(endpoint);
            sendBinary(exchange, 200, CONTENT_TYPE_CA_CERT, certDer);
        } catch (ScepProtocolException e) {
            LOG.log(Level.INFO, "SCEP GetCACert error: {0}", e.getMessage());
            sendText(exchange, e.httpStatus(), e.getMessage());
        }
    }

    private void handleGetCaCertChain(HttpExchange exchange, ScepEndpoint endpoint) throws IOException {
        try {
            byte[] chainCms = service.getCaCertChain(endpoint);
            sendBinary(exchange, 200, CONTENT_TYPE_CA_RA_CERT, chainCms);
        } catch (ScepProtocolException e) {
            LOG.log(Level.INFO, "SCEP GetCACertChain error: {0}", e.getMessage());
            sendText(exchange, e.httpStatus(), e.getMessage());
        }
    }

    private void handlePkiOperation(HttpExchange exchange, ScepEndpoint endpoint) throws IOException {
        byte[] messageData;
        String method = exchange.getRequestMethod().toUpperCase();
        if ("POST".equals(method)) {
            try (InputStream in = exchange.getRequestBody()) {
                messageData = in.readAllBytes();
            }
        } else if ("GET".equals(method)) {
            // RFC 8894 §4.1: GET with message parameter (base64-encoded)
            String query = exchange.getRequestURI().getQuery();
            String messageParam = extractParam(query, "message");
            if (messageParam == null) {
                sendText(exchange, 400, "SCEP PKIOperation GET requires message parameter");
                return;
            }
            try {
                messageData = java.util.Base64.getDecoder().decode(messageParam);
            } catch (IllegalArgumentException e) {
                sendText(exchange, 400, "SCEP PKIOperation message is not valid base64");
                return;
            }
        } else {
            exchange.getResponseHeaders().set("Allow", "GET, POST");
            sendText(exchange, 405, "SCEP PKIOperation requires GET or POST");
            return;
        }

        if (messageData == null || messageData.length == 0) {
            sendText(exchange, 400, "SCEP PKIOperation message body is empty");
            return;
        }

        try {
            byte[] response = service.processPkiOperation(endpoint, messageData);
            sendBinary(exchange, 200, CONTENT_TYPE_PKI_MESSAGE, response);
        } catch (ScepProtocolException e) {
            LOG.log(Level.INFO, "SCEP PKIOperation error: {0}", e.getMessage());
            sendText(exchange, e.httpStatus(), e.getMessage());
        }
    }

    private static String extractOperation(String query) {
        return extractParam(query, "operation");
    }

    private static String extractParam(String query, String name) {
        if (query == null || query.isBlank()) return null;
        String prefix = name + "=";
        for (String part : query.split("&")) {
            if (part.startsWith(prefix)) {
                return part.substring(prefix.length());
            }
        }
        return null;
    }

    private static void sendBinary(HttpExchange exchange, int status, String contentType, byte[] body)
            throws IOException {
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private static void sendText(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", TEXT_PLAIN);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
