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
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.cmp.CmpEndpoint;
import zeroecho.pki.server.cmp.CmpProtocolException;
import zeroecho.pki.server.cmp.CmpService;
import zeroecho.pkix.cmp.CmpProtectedMessage;

/** Bounded RFC 6712 transport with owned admission, deadlines and cancellation. */
final class CmpHttpHandler implements HttpHandler {
    private static final int METHOD_NOT_ALLOWED_STATUS = 405;
    private static final String TEXT = "text/plain; charset=utf-8";
    private final PkiServerConfiguration.CmpListener configuration;
    private final CmpService service;
    private final ServerRuntime runtime;
    private final RequestIds requestIds;
    private final BooleanSupplier ready;

    /* default */ CmpHttpHandler(PkiServerConfiguration.CmpListener configuration, ServerRealmContext realm,
            CmpService service, ServerRuntime runtime, RequestIds requestIds, BooleanSupplier ready) {
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
                    if (headerBytes > configuration.maximumHeaderBytes()) { send(exchange, error(431, "CMP headers exceed the configured limit")); return; }
                }
                if (!ready.getAsBoolean()) { send(exchange, error(503, "CMP service is not ready")); return; }
                if (!runtime.tryAdmit()) { send(exchange, error(503, "CMP service is overloaded")); return; }
                try {
                    ServerRuntime.Submitted<Response> submitted = runtime.submit(cancellation -> route(exchange, cancellation));
                    try {
                        Response response;
                        try {
                            response = submitted.future().get(configuration.execution().maximumDeadline().toMillis(), TimeUnit.MILLISECONDS);
                        } catch (TimeoutException timeout) {
                            submitted.cancellation().cancel(); submitted.future().cancel(true);
                            response = error(504, "CMP request timed out");
                        } catch (InterruptedException interrupted) {
                            submitted.cancellation().cancel(); submitted.future().cancel(true);
                            Thread.currentThread().interrupt(); response = error(503, "CMP request interrupted"); // NOPMD DoNotUseThreads - Restores caller cancellation after interruption; this standalone component creates no thread.
                        } catch (ExecutionException failure) {
                            Throwable cause = failure.getCause();
                            response = cause instanceof CmpProtocolException protocol ? error(protocol.httpStatus(), protocol.getMessage())
                                    : cause instanceof IllegalArgumentException ? error(400, "Invalid CMP request") : error(503, "CMP request unavailable");
                        }
                        send(exchange, response);
                    } finally { submitted.finish(); }
                } catch (RejectedExecutionException overloaded) { send(exchange, error(503, "CMP service is overloaded")); }
                finally { runtime.releaseAdmission(); }
            } catch (IllegalArgumentException invalid) { send(exchange, error(400, "Invalid CMP request")); }
        }
    }

    private Response route(HttpExchange exchange, ServerRuntime.CancellationToken cancellation) throws IOException, CmpProtocolException {
        cancellation.throwIfCancelled();
        if (!"POST".equals(exchange.getRequestMethod())) {
            return error(405, "CMP requires POST");
        }
        String type = exchange.getRequestHeaders().getFirst("Content-Type");
        if (type == null || !"application/pkixcmp".equalsIgnoreCase(type.trim())) {
            return error(415, "CMP content type is required");
        }
        String path = exchange.getRequestURI().getPath();
        if (!path.startsWith("/pkix/")) {
            return error(404, "CMP endpoint not found");
        }
        String label = path.substring(6);
        if (label.isEmpty() || label.contains("/")) {
            return error(404, "CMP endpoint not found");
        }
        CmpEndpoint endpoint = service.find(label).orElse(null);
        if (endpoint == null) {
            return error(404, "CMP endpoint not found");
        }
        int limit = Math.min(configuration.maximumBodyBytes(), CmpProtectedMessage.MAXIMUM_MESSAGE_BYTES);
        byte[] body;
        try (InputStream input = exchange.getRequestBody()) { body = input.readNBytes(limit + 1); }
        if (body.length > limit) {
            return error(413, "CMP message exceeds the configured limit");
        }
        if (body.length == 0) {
            return error(400, "CMP message is empty");
        }
        cancellation.throwIfCancelled();
        return new Response(200, "application/pkixcmp", service.processMessage(endpoint, body, cancellation));
    }

    private static Response error(int status, String message) { return new Response(status, TEXT, message.getBytes(StandardCharsets.UTF_8)); }
    private static void send(HttpExchange exchange, Response response) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", response.contentType());
        if (response.status() == METHOD_NOT_ALLOWED_STATUS) {
            exchange.getResponseHeaders().set("Allow", "POST");
        }
        exchange.sendResponseHeaders(response.status(), response.body().length);
        try (OutputStream output = exchange.getResponseBody()) { output.write(response.body()); }
    }
    private record Response(int status, String contentType, byte[] body) { }
}
