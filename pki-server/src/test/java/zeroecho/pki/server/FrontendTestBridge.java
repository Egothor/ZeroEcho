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

package zeroecho.pki.server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** Test-only same-origin static host and fixed-route bridge to verified backend mTLS. */
final class FrontendTestBridge implements AutoCloseable {
    private static final int MAX_BYTES = 2 * 1024 * 1024;
    private static final Set<String> GET_ROUTES = Set.of("/admin/v1/realm", "/admin/v1/operations", "/admin/v1/health");
    private static final Set<String> OPERATIONS = new OperationSecurityDescriptors().descriptors().keySet();
    private final Path root;
    private volatile URI upstream;
    private java.util.function.Supplier<InetSocketAddress> restart;
    private final HttpClient administrator;
    private final HttpClient approver;
    private final HttpServer server;
    private final ThreadPoolExecutor executor = new ThreadPoolExecutor(4, 4, 0, TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(32), new ThreadPoolExecutor.AbortPolicy());

    FrontendTestBridge(Path root, InetSocketAddress backend, HttpServerTestSupport.Fixture tls) throws IOException {
        this.root = root.toRealPath();
        upstream = URI.create("https://localhost:" + backend.getPort());
        administrator = HttpClient.newBuilder().sslContext(tls.clientContext()).connectTimeout(Duration.ofSeconds(5)).build();
        approver = HttpClient.newBuilder().sslContext(tls.proxyContext()).connectTimeout(Duration.ofSeconds(5)).build();
        HttpServer opened = null;
        try {
            opened = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 16);
            opened.setExecutor(executor);
            opened.createContext("/", this::handle);
            opened.start();
            server = opened;
        } catch (IOException | RuntimeException failure) {
            if (opened != null) opened.stop(0);
            executor.shutdownNow();
            administrator.close();
            approver.close();
            throw failure;
        }
    }

    URI baseUri() { return URI.create("http://127.0.0.1:" + server.getAddress().getPort()); }

    void restartWith(java.util.function.Supplier<InetSocketAddress> callback) { restart = callback; }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            String host = exchange.getRequestHeaders().getFirst("Host");
            String origin = exchange.getRequestHeaders().getFirst("Origin");
            if (!baseUri().getAuthority().equals(host) || (origin != null && !baseUri().toString().equals(origin))) {
                reply(exchange, 403, "text/plain", new byte[0]);
                return;
            }
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();
            if (path.equals("/fixture/restart") && method.equals("POST") && restart != null) {
                upstream = URI.create("https://localhost:" + restart.get().getPort());
                reply(exchange, 200, "application/json", "{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
                return;
            }
            if (exchange.getRequestURI().getRawQuery() != null) {
                reply(exchange, 400, "text/plain", new byte[0]);
                return;
            }
            boolean approve = path.equals("/fixture/approve");
            boolean deniedEnrollment = path.equals("/fixture/enrollment-denied");
            boolean api = path.startsWith("/admin/") || approve || deniedEnrollment;
            if (method.equals("POST") && (path.equals("/admin/v1/backup/upload") || path.equals("/admin/v1/backup/download"))) {
                HttpRequest.Builder request = HttpRequest.newBuilder(upstream.resolve(path)).timeout(Duration.ofSeconds(30))
                        .POST(HttpRequest.BodyPublishers.ofInputStream(exchange::getRequestBody));
                for (String header : List.of("Content-Type", "Origin", "X-ZeroEcho-Transfer", "X-ZeroEcho-Artifact", "X-ZeroEcho-Approval")) {
                    String value = exchange.getRequestHeaders().getFirst(header);
                    if (value != null) request.header(header, value);
                }
                HttpResponse<java.io.InputStream> response = administrator.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
                try (java.io.InputStream body = response.body()) {
                    for (String header : List.of("Content-Type", "Content-Disposition")) {
                        response.headers().firstValue(header).ifPresent(value -> exchange.getResponseHeaders().set(header, value));
                    }
                    exchange.sendResponseHeaders(response.statusCode(), 0);
                    body.transferTo(exchange.getResponseBody());
                }
                return;
            }
            if (api) {
                boolean allowed = method.equals("GET") && (GET_ROUTES.contains(path)
                        || path.matches("/admin/v1/signing-operations/[A-Za-z0-9:%._-]+"))
                        || method.equals("POST") && (approve || deniedEnrollment
                        || (path.startsWith("/admin/v1/operations/")
                        && OPERATIONS.contains(path.substring("/admin/v1/operations/".length()))));
                if (!allowed) {
                    reply(exchange, 405, "text/plain", new byte[0]);
                    return;
                }
                byte[] body = exchange.getRequestBody().readNBytes(65_537);
                if (body.length > 65_536) {
                    reply(exchange, 413, "text/plain", new byte[0]);
                    return;
                }
                URI target = upstream.resolve(approve ? "/admin/v1/operations/security.approval.approve"
                        : deniedEnrollment ? "/admin/v1/operations/enrollment.profile.suspend" : exchange.getRequestURI().getRawPath());
                HttpRequest request = HttpRequest.newBuilder(target).timeout(Duration.ofSeconds(15))
                        .header("Accept", "application/json").header("Content-Type", "application/json")
                        .method(method, body.length == 0 ? HttpRequest.BodyPublishers.noBody()
                                : HttpRequest.BodyPublishers.ofByteArray(body)).build();
                HttpResponse<byte[]> response = (approve || deniedEnrollment ? approver : administrator).send(request,
                        ignored -> new LimitedBodySubscriber());
                reply(exchange, response.statusCode(), "application/json", response.body());
            } else {
                if (!method.equals("GET")) {
                    reply(exchange, 405, "text/plain", new byte[0]);
                    return;
                }
                Path file = root.resolve(path.substring(1)).normalize();
                if (!file.startsWith(root)) {
                    reply(exchange, 403, "text/plain", new byte[0]);
                    return;
                }
                if (!Files.isRegularFile(file)) file = root.resolve("index.html");
                file = file.toRealPath();
                if (!file.startsWith(root) || Files.size(file) > MAX_BYTES) {
                    reply(exchange, 403, "text/plain", new byte[0]);
                    return;
                }
                String type = file.toString().endsWith(".js") ? "text/javascript"
                        : file.toString().endsWith(".css") ? "text/css"
                        : file.toString().endsWith(".woff2") ? "font/woff2" : "text/html";
                reply(exchange, 200, type, Files.readAllBytes(file));
            }
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new IOException("Fixture upstream request interrupted", failure);
        }
    }

    private static void reply(HttpExchange exchange, int status, String type, byte[] body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", type);
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
        if (body.length > 0) exchange.getResponseBody().write(body);
    }

    @Override public void close() {
        server.stop(0);
        executor.shutdownNow();
        administrator.close();
        approver.close();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) throw new IllegalStateException("Fixture bridge did not stop");
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Fixture bridge shutdown interrupted", failure);
        }
    }

    private static final class LimitedBodySubscriber implements HttpResponse.BodySubscriber<byte[]> {
        private final HttpResponse.BodySubscriber<byte[]> delegate = HttpResponse.BodySubscribers.ofByteArray();
        private Flow.Subscription subscription;
        private long received;
        @Override public CompletionStage<byte[]> getBody() { return delegate.getBody(); }
        @Override public void onSubscribe(Flow.Subscription value) { subscription = value; delegate.onSubscribe(value); }
        @Override public void onNext(List<ByteBuffer> buffers) {
            for (ByteBuffer buffer : buffers) received += buffer.remaining();
            if (received > MAX_BYTES) {
                subscription.cancel();
                delegate.onError(new IOException("Fixture response exceeded its byte budget"));
            } else delegate.onNext(buffers);
        }
        @Override public void onError(Throwable failure) { delegate.onError(failure); }
        @Override public void onComplete() { delegate.onComplete(); }
    }
}
