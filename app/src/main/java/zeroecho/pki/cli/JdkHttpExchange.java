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
package zeroecho.pki.cli;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

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
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(60);
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
    @SuppressWarnings("PMD.DoNotUseThreads")
    @Override
    public Response send(Request request) throws IOException {
        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(baseUri.resolve(request.path()))
                .timeout(REQUEST_TIMEOUT).header("Accept", JSON_MEDIA_TYPE);
        if (request.method() == Method.POST) {
            byte[] body = request.body().orElse(new byte[0]);
            builder.header("Content-Type", JSON_MEDIA_TYPE)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        } else {
            builder.GET();
        }
        try {
            HttpResponse<byte[]> response = client.send(builder.build(), responseInfo ->
                    HttpResponse.BodySubscribers.mapping(
                            HttpResponse.BodySubscribers.ofInputStream(),
                            stream -> {
                                try (InputStream in = stream) {
                                    return in.readNBytes(MAXIMUM_RESPONSE_BYTES);
                                } catch (IOException failure) {
                                    throw new UncheckedIOException(failure);
                                }
                            }));
            Optional<String> location = response.headers().firstValue("Location");
            byte[] body = response.body();
            return new Response(response.statusCode(), location, body == null ? new byte[0] : body);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IOException("Remote request was interrupted", interrupted);
        }
    }

    @Override
    public void close() {
        client.close();
    }
}
