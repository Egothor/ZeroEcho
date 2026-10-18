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
package zeroecho.pki.server.ct;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;

import zeroecho.pki.api.ct.CtLogDescriptor;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.ct.SignedCertificateTimestamp;

/**
 * HTTP implementation of {@link CtLogClient} using {@code java.net.http.HttpClient}.
 *
 * <p>Submits pre-certificates to the CT log endpoint {@code {baseUrl}ct/v1/add-pre-chain}
 * per RFC 6962 §4.1. On HTTP 5xx responses, retries up to {@value #MAX_RETRIES} times
 * with exponential backoff starting at {@value #INITIAL_BACKOFF_MS} ms.</p>
 *
 * <h2>Security note</h2>
 * <p>SCT signature verification against the log's public key is not performed in this
 * implementation. Parsing an SCT response does not establish its cryptographic
 * authenticity. Operators must configure trusted CT logs and treat independent
 * SCT signature verification as a separate requirement.</p>
 *
 * @since 1.0
 */
public final class HttpCtLogClient implements CtLogClient {
    private static final int HTTP_OK = 200;
    private static final int HTTP_SERVER_ERROR = 500;


    /* default */ static final int MAX_RETRIES = 3;
    /* default */ static final long INITIAL_BACKOFF_MS = 1000L;
    /* default */ static final int MAX_RESPONSE_BYTES = 65_536;

    private final String logId;
    private final String submitUrl;
    private final HttpClient httpClient;
    private final ExecutorService ownedExecutor; // NOPMD DoNotUseThreads - Owned JDK HTTP executor is deterministically terminated; bounded retries preserve interruption.
    private final AtomicBoolean closed = new AtomicBoolean(false);

    /**
     * Creates a client for the given CT log using the supplied HTTP client.
     * Closing this wrapper closes the supplied HTTP client. An executor supplied
     * to that HTTP client remains the caller's responsibility; this wrapper only
     * shuts down executors created by its own factory.
     *
     * @param descriptor describes the CT log endpoint; must not be {@code null}
     * @param httpClient caller-supplied HTTP client; must not be {@code null}
     */
    public HttpCtLogClient(final CtLogDescriptor descriptor, final HttpClient httpClient) {
        this(descriptor, httpClient, null);
    }

    private HttpCtLogClient(final CtLogDescriptor descriptor, final HttpClient httpClient,
            final ExecutorService ownedExecutor) { // NOPMD DoNotUseThreads - Owned JDK HTTP executor is deterministically terminated; bounded retries preserve interruption.
        Objects.requireNonNull(descriptor, "descriptor");
        Objects.requireNonNull(httpClient, "httpClient");
        this.logId = descriptor.logId();
        this.submitUrl = descriptor.baseUrl() + "ct/v1/add-pre-chain";
        this.httpClient = httpClient;
        this.ownedExecutor = ownedExecutor;
    }

    /**
     * Creates a client for the given CT log using a virtual-thread-based HTTP client.
     *
     * @param descriptor describes the CT log endpoint; must not be {@code null}
     * @return ready-to-use client
     */
    public static HttpCtLogClient create(final CtLogDescriptor descriptor) {
        Objects.requireNonNull(descriptor, "descriptor");
        ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor(); // NOPMD DoNotUseThreads, CloseResource - Ownership transfers to the returned client; failure cleanup closes the executor.
        boolean transferred = false;
        try { // NOPMD UseTryWithResources - Successful construction transfers lifetime to the returned client.
            HttpClient client = HttpClient.newBuilder() // NOPMD CloseResource - The returned client owns and closes this HTTP client.
                .executor(executor)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
            HttpCtLogClient result = new HttpCtLogClient(descriptor, client, executor);
            transferred = true;
            return result;
        } finally {
            if (!transferred) {
                executor.close(); // NOPMD DoNotUseThreads - Owned JDK HTTP executor is deterministically terminated; bounded retries preserve interruption.
            }
        }
    }

    @Override
    public String logId() {
        return logId;
    }

    @Override
    public SignedCertificateTimestamp submit(final byte[] preCert, final List<byte[]> chain,
            final Instant deadline) throws CtSubmissionException {
        Objects.requireNonNull(preCert, "preCert");
        Objects.requireNonNull(chain, "chain");
        Objects.requireNonNull(deadline, "deadline");
        requireOpen();

        String requestBody = buildRequestBody(preCert, chain);
        CtSubmissionException lastException = null;
        long backoffMs = INITIAL_BACKOFF_MS;

        for (int attempt = 0; attempt <= MAX_RETRIES; attempt++) {
            Duration remaining = Duration.between(Instant.now(), deadline);
            if (remaining.isNegative() || remaining.isZero()) {
                throw new CtSubmissionException("CT submission deadline elapsed after "
                        + attempt + " attempt(s)", logId);
            }
            try {
                byte[] responseBody = executeRequest(requestBody, remaining);
                return parseSctResponse(responseBody);
            } catch (CtSubmissionException failure) {
                lastException = failure;
                if (attempt < MAX_RETRIES && isRetryable(failure)) {
                    sleepBackoff(backoffMs, deadline);
                    backoffMs = Math.min(backoffMs * 2, 30_000L);
                } else {
                    throw failure;
                }
            }
        }
        throw lastException != null ? lastException
                : new CtSubmissionException("CT submission failed after " + MAX_RETRIES + " retries", logId);
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            try { // NOPMD UseTryWithResources - This lifecycle method terminates an instance-owned resource.
                httpClient.close();
            } finally {
                if (ownedExecutor != null) {
                    ownedExecutor.close(); // NOPMD DoNotUseThreads - Owned JDK HTTP executor is deterministically terminated; bounded retries preserve interruption.
                }
            }
        }
    }

    // Builds the JSON request body per RFC 6962 §4.1.
    private static String buildRequestBody(final byte[] preCert, final List<byte[]> chain) {
        Base64.Encoder encoder = Base64.getEncoder();
        StringBuilder sb = new StringBuilder("{\"chain\":[\"");
        sb.append(encoder.encodeToString(preCert)).append('"');
        for (byte[] chainEntry : chain) {
            sb.append(",\"").append(encoder.encodeToString(chainEntry)).append('"');
        }
        sb.append("]}");
        return sb.toString();
    }


    private byte[] executeRequest(final String requestBody, final Duration timeout)
            throws CtSubmissionException {
        byte[] bodyBytes = requestBody.getBytes(StandardCharsets.UTF_8);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(submitUrl))
                .timeout(timeout)
                .header("Content-Type", "application/json; charset=utf-8")
                .POST(HttpRequest.BodyPublishers.ofByteArray(bodyBytes))
                .build();
        try {
            HttpResponse<byte[]> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofByteArray());
            int status = response.statusCode();
            byte[] body = response.body();
            if (body != null && body.length > MAX_RESPONSE_BYTES) {
                throw new CtSubmissionException("CT log response body too large: " + body.length + " bytes", logId);
            }
            if (status == HTTP_OK) {
                return body;
            }
            if (status >= HTTP_SERVER_ERROR) {
                throw new CtSubmissionException("CT log HTTP " + status + " (retryable): " + submitUrl, logId);
            }
            throw new CtSubmissionException("CT log HTTP " + status + ": " + submitUrl, logId);
        } catch (CtSubmissionException rethrow) {
            throw rethrow;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt(); // NOPMD DoNotUseThreads - Owned JDK HTTP executor is deterministically terminated; bounded retries preserve interruption.
            throw new CtSubmissionException("CT submission interrupted: " + submitUrl, logId, interrupted);
        } catch (Exception failure) {
            throw new CtSubmissionException("CT submission I/O error: " + submitUrl, logId, failure);
        }
    }

    // Parses the RFC 6962 §4.1 JSON response into a SignedCertificateTimestamp.
    // Delegates to Pkix.parseSct() which has a hand-written JSON parser for this exact format.
    private SignedCertificateTimestamp parseSctResponse(final byte[] responseBody)
            throws CtSubmissionException {
        if (responseBody == null || responseBody.length == 0) {
            throw new CtSubmissionException("CT log returned empty response body", logId);
        }
        try {
            return Pkix.parseSct(responseBody);
        } catch (IllegalArgumentException failure) {
            throw new CtSubmissionException("Failed to parse CT log JSON response", logId, failure);
        }
    }

    // Returns true if the exception represents a transient server-side failure worth retrying.
    private static boolean isRetryable(final CtSubmissionException failure) {
        String message = failure.getMessage();
        return message != null && message.contains("retryable");
    }


    private void sleepBackoff(final long backoffMs, final Instant deadline) throws CtSubmissionException {
        long remaining = Duration.between(Instant.now(), deadline).toMillis();
        long sleep = Math.min(backoffMs, Math.max(0L, remaining - 100L));
        if (sleep <= 0) {
            return;
        }
        try {
            Thread.sleep(sleep); // NOPMD DoNotUseThreads - Owned JDK HTTP executor is deterministically terminated; bounded retries preserve interruption.
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt(); // NOPMD DoNotUseThreads - Owned JDK HTTP executor is deterministically terminated; bounded retries preserve interruption.
            throw new CtSubmissionException("CT submission interrupted during retry backoff", logId, interrupted);
        }
    }

    private void requireOpen() {
        if (closed.get()) {
            throw new IllegalStateException("CT log client is closed");
        }
    }
}
