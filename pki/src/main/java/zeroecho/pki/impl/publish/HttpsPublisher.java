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
package zeroecho.pki.impl.publish;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.spi.publish.PublicationAttempt;
import zeroecho.pki.spi.publish.PublicationOutcome;
import zeroecho.pki.spi.publish.Publisher;

/** Bounded-timeout HTTPS publication endpoint. */
final class HttpsPublisher implements Publisher {
    private static final int HTTP_SERVER_ERROR = 500;
    private static final Logger LOG = Logger.getLogger(HttpsPublisher.class.getName());
    private static final Duration TIMEOUT = Duration.ofSeconds(30);

    private final PublicationTarget target;
    private final URI uri;
    private final String credentials;
    private final String method;
    private final HttpClient client;

    /* default */ HttpsPublisher(PublicationTarget target, URI uri, String credentials, String method) {
        this.target = Objects.requireNonNull(target, "target");
        this.uri = Objects.requireNonNull(uri, "uri");
        this.credentials = credentials;
        this.method = Objects.requireNonNull(method, "method");
        this.client = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
    }

    @Override
    public PublicationTarget target() {
        return target;
    }

    @Override
    public PublicationOutcome publish(PublicationAttempt attempt, RepeatableContent payload) {
        Objects.requireNonNull(attempt, "attempt");
        Objects.requireNonNull(payload, "payload");
        try {
            byte[] body = readFully(payload);
            HttpRequest.Builder req = HttpRequest.newBuilder()
                    .uri(uri)
                    .timeout(TIMEOUT)
                    .header("Content-Type", contentType(attempt.encoding()))
                    .header("X-Attempt-Token", attempt.attemptToken())
                    .method(method, HttpRequest.BodyPublishers.ofByteArray(body));
            if (credentials != null) {
                req.header("Authorization", credentials);
            }
            HttpResponse<Void> response = client.send(req.build(),
                    HttpResponse.BodyHandlers.discarding());
            int status = response.statusCode();
            if (status >= 200 && status < 300) {
                return PublicationOutcome.SUCCESS;
            }
            if (status >= HTTP_SERVER_ERROR) {
                if (LOG.isLoggable(Level.WARNING)) {
                    LOG.log(Level.WARNING, "HTTPS publisher received transient error {0} for target {1}",
                            new Object[]{status, target.targetId()});
                }
                return PublicationOutcome.RETRYABLE_FAILURE;
            }
            if (LOG.isLoggable(Level.SEVERE)) {
                LOG.log(Level.SEVERE, "HTTPS publisher received permanent error {0} for target {1}",
                        new Object[]{status, target.targetId()});
            }
            return PublicationOutcome.TERMINAL_FAILURE;
        } catch (IOException e) {
            LOG.log(Level.WARNING, e, () -> "HTTPS publisher I/O failure for target " + target.targetId());
            return PublicationOutcome.RETRYABLE_FAILURE;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // NOPMD DoNotUseThreads - Standalone Java service uses bounded polling/retry or preserves cancellation; no J2EE container.
            return PublicationOutcome.RETRYABLE_FAILURE;
        }
    }

    private static byte[] readFully(RepeatableContent content) throws IOException {
        try (InputStream in = content.openStream()) {
            return in.readAllBytes();
        }
    }

    private static String contentType(Encoding encoding) {
        return switch (encoding) {
            case DER -> "application/pkix-cert";
            case PEM -> "application/x-pem-file";
            case BINARY -> "application/octet-stream";
        };
    }
}
