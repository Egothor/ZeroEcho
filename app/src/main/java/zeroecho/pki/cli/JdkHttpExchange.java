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
package zeroecho.pki.cli;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.net.ssl.SSLContext;

/**
 * {@link PkiHttpExchange} backed by the JDK {@link HttpClient} over mutual TLS.
 *
 * <p>The client presents the supplied client certificate (auth mode
 * {@code DIRECT_MTLS}); no forwarded-identity headers are sent. The base URL is
 * resolved against each absolute request path.</p>
 */
final class JdkHttpExchange implements PkiHttpExchange {

    private static final String JSON_MEDIA_TYPE = "application/json";
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(20);
    private static final int MAXIMUM_RESPONSE_BYTES = 4 * 1_048_576;

    private final HttpClient client;
    private final URI baseUri;

    private JdkHttpExchange(HttpClient client, URI baseUri) {
        this.client = client;
        this.baseUri = baseUri;
    }

    /**
     * Opens an exchange bound to one base URL and mutual-TLS context.
     *
     * @param baseUri validated {@code https} base URL
     * @param sslContext context carrying the client key and server trust material
     * @return an open exchange
     */
    /* default */ static JdkHttpExchange open(URI baseUri, SSLContext sslContext) {
        Objects.requireNonNull(baseUri, "baseUri");
        Objects.requireNonNull(sslContext, "sslContext");
        HttpClient client = HttpClient.newBuilder().sslContext(sslContext)
                .connectTimeout(CONNECT_TIMEOUT).followRedirects(HttpClient.Redirect.NEVER).build();
        return new JdkHttpExchange(client, baseUri);
    }

    // HttpClient interruption must be observed and restored on the calling thread.
    // Typed rethrows preserve the original failure object; wrapped failures preserve their original cause.
    @SuppressWarnings({ "PMD.DoNotUseThreads", "PMD.PreserveStackTrace" })
    @Override
    public Response send(Request request) throws IOException {
        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(baseUri.resolve(request.path()))
                .timeout(request.timeout()).header("Accept", JSON_MEDIA_TYPE);
        if (request.method() == Method.POST) {
            byte[] body = request.body().orElse(new byte[0]);
            builder.header("Content-Type", JSON_MEDIA_TYPE)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        } else {
            builder.GET();
        }
        CompletableFuture<HttpResponse<byte[]>> pending = client.sendAsync(builder.build(),
                responseInfo -> new BoundedBodySubscriber());
        try {
            HttpResponse<byte[]> response = pending.get(request.timeout().toNanos(), TimeUnit.NANOSECONDS);
            return new Response(response.statusCode(), response.headers().firstValue("Location"), response.body());
        } catch (InterruptedException interrupted) {
            pending.cancel(true);
            Thread.currentThread().interrupt();
            throw new IOException("Remote request was interrupted", interrupted);
        } catch (TimeoutException timeout) {
            pending.cancel(true);
            HttpTimeoutException failure = new HttpTimeoutException("Remote response timed out");
            failure.initCause(timeout);
            throw failure;
        } catch (ExecutionException failed) {
            if (failed.getCause() instanceof IOException failure) { throw failure; }
            throw new IOException("Remote response failed", failed.getCause());
        }
    }

    /** Cancels the response subscription before exceeding the response size bound. */
    private static final class BoundedBodySubscriber implements HttpResponse.BodySubscriber<byte[]> {
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private final CompletableFuture<byte[]> body = new CompletableFuture<>();
        private Flow.Subscription subscription;

        @Override
        public CompletionStage<byte[]> getBody() { return body; }

        @Override
        public void onSubscribe(Flow.Subscription supplied) {
            if (subscription != null) { supplied.cancel(); return; }
            subscription = supplied;
            supplied.request(1);
        }

        // Each iteration requires its own immutable value or failure object; sharing would conflate distinct records or attempts.
        @SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops" })
        @Override
        public void onNext(List<ByteBuffer> buffers) {
            for (ByteBuffer buffer : buffers) {
                if (buffer.remaining() > MAXIMUM_RESPONSE_BYTES - bytes.size()) {
                    subscription.cancel();
                    body.completeExceptionally(new InvalidResponseException("Remote response exceeds the size limit"));
                    return;
                }
                byte[] chunk = new byte[buffer.remaining()];
                buffer.get(chunk);
                bytes.writeBytes(chunk);
            }
            subscription.request(1);
        }

        @Override
        public void onError(Throwable failure) { body.completeExceptionally(failure); }

        @Override
        public void onComplete() { body.complete(bytes.toByteArray()); }
    }

    @Override
    public void close() {
        client.shutdownNow();
    }
}
