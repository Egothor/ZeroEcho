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
import zeroecho.pki.server.cmp.CmpEndpoint;
import zeroecho.pki.server.cmp.CmpProtocolException;
import zeroecho.pki.server.cmp.CmpService;

/**
 * CMP RFC 4210/9480 route adapter over the jdk.httpserver API (RFC 6712 HTTP transport).
 *
 * <p>Routes POST requests to {@code /pkix/{label}} by label. Decodes the DER-encoded
 * PKIMessage body, dispatches to {@link CmpService#processMessage}, and returns a
 * DER-encoded PKIMessage response with content type {@code application/pkixcmp}.</p>
 *
 * @since 1.0
 */
@SuppressWarnings("PMD")
final class CmpHttpHandler implements HttpHandler {

    private static final Logger LOG = Logger.getLogger(CmpHttpHandler.class.getName());

    private static final String TEXT_PLAIN = "text/plain; charset=utf-8";
    private static final String CONTENT_TYPE_PKIXCMP = "application/pkixcmp";
    private static final String PKIX_PREFIX = "/pkix/";

    private final PkiServerConfiguration.CmpListener configuration;
    private final ServerRealmContext realm;
    private final CmpService service;
    private final ServerRuntime runtime;
    private final RequestIds requestIds;
    private final BooleanSupplier ready;

    CmpHttpHandler(PkiServerConfiguration.CmpListener configuration, ServerRealmContext realm,
            CmpService service, ServerRuntime runtime, RequestIds requestIds, BooleanSupplier ready) {
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
                sendText(exchange, 503, "CMP service is not ready");
                return;
            }
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.getResponseHeaders().set("Allow", "POST");
                sendText(exchange, 405, "CMP requires POST");
                return;
            }
            String path = exchange.getRequestURI().getPath();
            if (!path.startsWith(PKIX_PREFIX)) {
                sendText(exchange, 404, "Not found");
                return;
            }
            String after = path.substring(PKIX_PREFIX.length());
            int slash = after.indexOf('/');
            String label = slash < 0 ? after : after.substring(0, slash);
            if (label.isEmpty()) {
                sendText(exchange, 404, "CMP label is required");
                return;
            }
            Optional<CmpEndpoint> endpointOpt = service.find(label);
            if (endpointOpt.isEmpty()) {
                sendText(exchange, 404, "CMP endpoint not found: " + label);
                return;
            }
            CmpEndpoint endpoint = endpointOpt.get();

            byte[] body;
            try (InputStream in = exchange.getRequestBody()) {
                body = in.readAllBytes();
            }
            if (body.length == 0) {
                sendText(exchange, 400, "CMP request body is empty");
                return;
            }

            byte[] response;
            try {
                response = service.processMessage(endpoint, body);
            } catch (CmpProtocolException e) {
                LOG.log(Level.INFO, "CMP protocol error: {0}", e.getMessage());
                sendText(exchange, e.httpStatus(), e.getMessage());
                return;
            }

            sendBinary(exchange, 200, CONTENT_TYPE_PKIXCMP, response);
        } catch (Exception unexpected) {
            LOG.log(Level.WARNING, "Unexpected error in CMP handler", unexpected);
            try {
                sendText(exchange, 500, "Internal CMP error");
            } catch (IOException ignored) {
                // Already sent response; nothing to do
            }
        } finally {
            exchange.close();
        }
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
