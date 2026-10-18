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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.scep.ScepEndpoint;
import zeroecho.pki.server.scep.ScepProtocolException;
import zeroecho.pki.server.scep.ScepService;

/** Bounded RFC 8894 HTTPS transport; CMS authenticates requests before enrollment. */
final class ScepHttpHandler implements HttpHandler {
    private static final String HTTP_GET = "GET";
    private static final String HTTP_POST = "POST";
    private static final String TEXT = "text/plain; charset=utf-8";
    private final PkiServerConfiguration.ScepListener configuration;
    private final ScepService service;
    private final ServerRuntime runtime;
    private final RequestIds requestIds;
    private final BooleanSupplier ready;

    /* default */ ScepHttpHandler(PkiServerConfiguration.ScepListener configuration, ServerRealmContext realm,
            ScepService service, ServerRuntime runtime, RequestIds requestIds, BooleanSupplier ready) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(realm, "realm");
        this.service = Objects.requireNonNull(service, "service");
        this.runtime = Objects.requireNonNull(runtime, "runtime");
        this.requestIds = Objects.requireNonNull(requestIds, "requestIds");
        this.ready = Objects.requireNonNull(ready, "ready");
    }

    @Override public void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            try {
                exchange.getResponseHeaders().set(RequestIds.HEADER, requestIds.resolve(exchange.getRequestHeaders().get(RequestIds.HEADER)));
                long headerBytes = 0;
                for (java.util.Map.Entry<String, java.util.List<String>> header : exchange.getRequestHeaders().entrySet()) {
                    headerBytes += header.getKey().length();
                    for (String value : header.getValue()) {
                        headerBytes += value.length();
                    }
                    if (headerBytes > configuration.maximumHeaderBytes()) { send(exchange, error(431, "SCEP headers exceed the configured limit")); return; }
                }
                if (!ready.getAsBoolean()) { send(exchange, error(503, "SCEP service is not ready")); return; }
                if (!runtime.tryAdmit()) { send(exchange, error(503, "SCEP service is overloaded")); return; }
                try {
                    ServerRuntime.Submitted<Response> submitted = runtime.submit(cancellation -> route(exchange, cancellation));
                    try {
                        Response response;
                        try {
                            response = submitted.future().get(configuration.execution().maximumDeadline().toMillis(), TimeUnit.MILLISECONDS);
                        } catch (TimeoutException timeout) {
                            submitted.cancellation().cancel(); submitted.future().cancel(true);
                            response = error(504, "SCEP request timed out");
                        } catch (InterruptedException interrupted) {
                            submitted.cancellation().cancel(); submitted.future().cancel(true);
                            Thread.currentThread().interrupt(); // NOPMD DoNotUseThreads - Restores caller cancellation after interruption; this standalone component creates no thread.
                            response = error(503, "SCEP request interrupted");
                        } catch (ExecutionException failure) {
                            Throwable cause = failure.getCause();
                            response = cause instanceof ScepProtocolException protocol ? error(protocol.httpStatus(), protocol.getMessage())
                                    : cause instanceof IllegalArgumentException ? error(400, "Invalid SCEP request") : error(503, "SCEP request unavailable");
                        }
                        send(exchange, response);
                    } finally { submitted.finish(); }
                } catch (RejectedExecutionException overloaded) { send(exchange, error(503, "SCEP service is overloaded")); }
                finally { runtime.releaseAdmission(); }
            } catch (IllegalArgumentException invalid) { send(exchange, error(400, "Invalid SCEP request")); }
        }
    }

    private Response route(HttpExchange exchange, ServerRuntime.CancellationToken cancellation) throws IOException, ScepProtocolException {
        cancellation.throwIfCancelled();
        String path = exchange.getRequestURI().getPath();
        if (!path.startsWith("/scep/")) {
            return error(404, "SCEP endpoint not found");
        }
        String label = path.substring(6);
        if (label.endsWith("/")) {
            label = label.substring(0, label.length() - 1);
        }
        if (label.isEmpty() || label.contains("/")) {
            return error(404, "SCEP endpoint not found");
        }
        ScepEndpoint endpoint = service.find(label).orElse(null);
        if (endpoint == null) {
            return error(404, "SCEP endpoint not found");
        }
        int limit = Math.min(configuration.maximumBodyBytes(), zeroecho.pkix.scep.ScepCodec.MAXIMUM_REQUEST_BYTES);
        String query = exchange.getRequestURI().getRawQuery();
        if (query != null && query.length() > 4L * limit + 1024) {
            return error(413, "SCEP query exceeds the configured limit");
        }
        String operation = parameter(query, "operation");
        if (operation == null) {
            return error(400, "SCEP operation is required");
        }
        if (!"PKIOperation".equals(operation) && !HTTP_GET.equals(exchange.getRequestMethod())) {
            return error(405, "SCEP discovery requires GET");
        }
        return switch (operation) {
            case "GetCACaps" -> new Response(200, TEXT, service.getCaCaps());
            case "GetCACert", "GetCACertChain" -> {
                ScepService.CaCertificateResponse response = service.getCaCert(endpoint);
                yield new Response(200, response.contentType(), response.body());
            }
            case "PKIOperation" -> operation(exchange, endpoint, query, limit, cancellation);
            default -> error(400, "Unsupported SCEP operation");
        };
    }

    private Response operation(HttpExchange exchange, ScepEndpoint endpoint, String query, int limit,
            ServerRuntime.CancellationToken cancellation) throws IOException, ScepProtocolException {
        byte[] message;
        if (HTTP_POST.equals(exchange.getRequestMethod())) {
            try (InputStream input = exchange.getRequestBody()) { message = input.readNBytes(limit + 1); }
        } else if (HTTP_GET.equals(exchange.getRequestMethod())) {
            String encoded = parameter(query, "message");
            if (encoded == null) {
                return error(400, "SCEP message is required");
            }
            if (encoded.length() > 4L * ((limit + 2L) / 3)) {
                return error(413, "SCEP message exceeds the configured limit");
            }
            message = java.util.Base64.getDecoder().decode(encoded);
        } else {
            return error(405, "SCEP PKIOperation requires GET or POST");
        }
        if (message.length > limit) {
            return error(413, "SCEP message exceeds the configured limit");
        }
        if (message.length == 0) {
            return error(400, "SCEP message is empty");
        }
        cancellation.throwIfCancelled();
        return new Response(200, "application/x-pki-message", service.processPkiOperation(endpoint, message, cancellation));
    }

    private static String parameter(String query, String name) {
        if (query == null || query.isBlank()) {
            return null;
        }
        String result = null;
        for (String part : query.split("&")) {
            if (part.startsWith(name + "=")) {
                if (result != null) {
                    throw new IllegalArgumentException("Duplicate SCEP parameter");
                }
                result = java.net.URLDecoder.decode(part.substring(name.length() + 1), StandardCharsets.UTF_8);
            }
        }
        return result;
    }

    private static Response error(int status, String message) { return new Response(status, TEXT, message.getBytes(StandardCharsets.UTF_8)); }
    private static void send(HttpExchange exchange, Response response) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", response.contentType());
        exchange.sendResponseHeaders(response.status(), response.body().length);
        try (OutputStream output = exchange.getResponseBody()) { output.write(response.body()); }
    }
    private record Response(int status, String contentType, byte[] body) { }
}
