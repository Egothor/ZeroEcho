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
package zeroecho.pki.impl.crypto.remote.http;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import javax.net.ssl.SSLContext;

import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport;

/**
 * Mutually-authenticated HTTPS/JSON binding of {@link RemoteSigningTransport}.
 *
 * <p>
 * Every call is a single {@code POST} of a flat JSON object to the configured
 * endpoint; the {@code op} field selects the remote action
 * ({@code submit}/{@code status}/{@code cancel}/{@code publicKey}/{@code capabilities}).
 * Binary payloads travel Base64-encoded. The transport speaks HTTP/1.1 over TLS
 * with a client certificate; the remote issuer is pinned by the supplied
 * {@link SSLContext}. It carries only opaque key handles and exact bytes, never
 * private key material.
 * </p>
 *
 * <h2>Status mapping</h2>
 * <ul>
 * <li>{@code 200} — the JSON body is the authoritative result.</li>
 * <li>{@code 409} — the remote service reports a fingerprint conflict or stale
 * fence; surfaced as {@link IllegalStateException} (a definite, safe negative).</li>
 * <li>anything else, or any I/O or parse uncertainty — surfaced as
 * {@link RemoteSigningException}; the caller never re-submits and reconciles via
 * {@link #status(String, RemoteCallControl)}.</li>
 * </ul>
 */
public final class HttpsRemoteSigningTransport implements RemoteSigningTransport {

    private static final String CONTENT_TYPE = "application/json";
    private static final int HTTP_OK = 200;
    private static final int HTTP_CONFLICT = 409;
    /** Delimiter joining advertised algorithm identities in the capabilities message. */
    /* default */ static final String ALGORITHM_SEPARATOR = "\u001f";

    private final HttpClient client;
    private final URI endpoint;
    private final Duration callTimeout;
    private final RemoteCapabilities capabilities;

    private HttpsRemoteSigningTransport(HttpClient client, URI endpoint, Duration callTimeout,
            RemoteCapabilities capabilities) {
        this.client = client;
        this.endpoint = endpoint;
        this.callTimeout = callTimeout;
        this.capabilities = capabilities;
    }

    /**
     * Opens a transport to a remote signing service and captures its advertised
     * capabilities during the initial handshake.
     *
     * @param endpoint absolute {@code https} endpoint of the remote service
     * @param sslContext mutually-authenticated TLS context (client identity + pinned trust)
     * @param connectTimeout TCP/TLS connect timeout
     * @param callTimeout maximum duration of any single request
     * @return an open transport with capabilities captured
     * @throws IllegalArgumentException if the endpoint is not absolute {@code https}
     * @throws RemoteSigningException if the capability handshake fails
     */
    // The construction guard owns and closes the client for every failed handshake runtime subtype.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public static HttpsRemoteSigningTransport open(URI endpoint, SSLContext sslContext, Duration connectTimeout,
            Duration callTimeout) {
        Objects.requireNonNull(endpoint, "endpoint");
        Objects.requireNonNull(sslContext, "sslContext");
        Objects.requireNonNull(connectTimeout, "connectTimeout");
        Objects.requireNonNull(callTimeout, "callTimeout");
        if (!"https".equalsIgnoreCase(endpoint.getScheme()) || endpoint.getHost() == null) {
            throw new IllegalArgumentException("Remote signing endpoint must be an absolute https URI");
        }
        HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(connectTimeout)
                .sslContext(sslContext)
                .build();
        try {
            RemoteCapabilities capabilities = decodeCapabilities(
                    exchange(client, endpoint, Map.of("op", "capabilities"), callTimeout));
            return new HttpsRemoteSigningTransport(client, endpoint, callTimeout, capabilities);
        } catch (RuntimeException handshakeFailure) {
            client.close();
            throw handshakeFailure;
        }
    }

    @Override
    public RemoteSigningStatus submit(RemoteSignRequest request, RemoteCallControl control) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(control, "control");
        Map<String, String> body = new LinkedHashMap<>();
        body.put("op", "submit");
        body.put("submissionId", request.submissionId());
        body.put("namespace", request.namespace());
        body.put("semanticFingerprint", request.semanticFingerprint());
        body.put("fencingToken", Long.toString(request.fencingToken()));
        body.put("keyHandle", request.keyHandle());
        body.put("algorithmId", request.algorithmId());
        body.put("contentSha256", request.contentSha256());
        body.put("contentLength", Long.toString(request.contentLength()));
        body.put("content", Base64.getEncoder().encodeToString(request.content()));
        body.put("principalType", request.principalType());
        body.put("principalName", request.principalName());
        body.put("purpose", request.purpose());
        body.put("deadline", request.deadline().map(Instant::toString).orElse(""));
        return decodeStatus(call(body, control));
    }

    @Override
    public RemoteSigningStatus status(String operationId, RemoteCallControl control) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(control, "control");
        return decodeStatus(call(Map.of("op", "status", "operationId", operationId), control));
    }

    @Override
    public boolean cancel(String operationId, long fencingToken, String reason, RemoteCallControl control) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(control, "control");
        Map<String, String> body = new LinkedHashMap<>();
        body.put("op", "cancel");
        body.put("operationId", operationId);
        body.put("fencingToken", Long.toString(fencingToken));
        body.put("reason", reason);
        return "true".equals(call(body, control).get("accepted"));
    }

    @Override
    public byte[] publicKeyInfo(String keyHandle, RemoteCallControl control) {
        Objects.requireNonNull(keyHandle, "keyHandle");
        Objects.requireNonNull(control, "control");
        String encoded = call(Map.of("op", "publicKey", "keyHandle", keyHandle), control).get("spki");
        if (encoded == null || encoded.isEmpty()) {
            throw new RemoteSigningException("Remote signing service returned no public key info");
        }
        return decodeBase64(encoded, "public key info");
    }

    @Override
    public RemoteCapabilities capabilities() {
        return capabilities;
    }

    @Override
    public void close() {
        client.close();
    }

    private Map<String, String> call(Map<String, String> body, RemoteCallControl control) {
        if (control.cancellation().isCancelled()) {
            throw new RemoteSigningException("Remote signing call cancelled before dispatch: op=" + body.get("op"));
        }
        Duration remaining = Duration.between(Instant.now(), control.deadline());
        if (remaining.isZero() || remaining.isNegative()) {
            throw new RemoteSigningException("Remote signing deadline exceeded before dispatch: op=" + body.get("op"));
        }
        Duration timeout = remaining.compareTo(callTimeout) < 0 ? remaining : callTimeout;
        return exchange(client, endpoint, body, timeout);
    }

    // Synchronous transport preserves interruption on the calling thread and maps malformed response failures.
    @SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.DoNotUseThreads"})
    private static Map<String, String> exchange(HttpClient client, URI endpoint, Map<String, String> body,
            Duration timeout) {
        String op = body.get("op");
        HttpRequest request = HttpRequest.newBuilder(endpoint)
                .timeout(timeout)
                .header("Content-Type", CONTENT_TYPE)
                .header("Accept", CONTENT_TYPE)
                .POST(HttpRequest.BodyPublishers.ofByteArray(RemoteSigningJson.write(body)))
                .build();
        HttpResponse<byte[]> response;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new RemoteSigningException("Remote signing call interrupted: op=" + op, interrupted);
        } catch (IOException communication) {
            throw new RemoteSigningException("Remote signing call failed: op=" + op, communication);
        }
        int code = response.statusCode();
        if (code == HTTP_OK) {
            try {
                return RemoteSigningJson.read(response.body());
            } catch (RuntimeException malformed) {
                throw new RemoteSigningException("Remote signing response is malformed: op=" + op, malformed);
            }
        }
        if (code == HTTP_CONFLICT) {
            throw new IllegalStateException("Remote signing service reported a conflict or stale fence: op=" + op);
        }
        throw new RemoteSigningException("Remote signing service returned HTTP " + code + ": op=" + op);
    }

    // Instant parsing can report multiple runtime subtypes, all representing the same malformed wire field.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private static RemoteSigningStatus decodeStatus(Map<String, String> fields) {
        String operationId = required(fields, "operationId");
        RemoteSigningState state;
        try {
            state = RemoteSigningState.valueOf(required(fields, "state"));
        } catch (IllegalArgumentException unknownState) {
            throw new RemoteSigningException("Remote signing state is unrecognized", unknownState);
        }
        Instant updatedAt;
        try {
            updatedAt = Instant.parse(required(fields, "updatedAt"));
        } catch (RuntimeException malformedInstant) {
            throw new RemoteSigningException("Remote signing timestamp is malformed", malformedInstant);
        }
        String reason = fields.getOrDefault("reason", "");
        Optional<String> reasonValue = reason.isEmpty() ? Optional.empty() : Optional.of(reason);
        String signature = fields.getOrDefault("signature", "");
        Optional<byte[]> signatureValue = signature.isEmpty() ? Optional.empty()
                : Optional.of(decodeBase64(signature, "signature"));
        String encoding = fields.getOrDefault("signatureEncoding", "BINARY");
        return new RemoteSigningStatus(operationId, state, updatedAt, reasonValue, signatureValue, encoding);
    }

    private static RemoteCapabilities decodeCapabilities(Map<String, String> fields) {
        String algorithms = fields.getOrDefault("algorithms", "");
        Set<String> supported = algorithms.isEmpty() ? Set.of()
                : new LinkedHashSet<>(Arrays.asList(algorithms.split(ALGORITHM_SEPARATOR, -1)));
        byte[] commitment = decodeBase64(required(fields, "configurationCommitment"), "configuration commitment");
        return new RemoteCapabilities(Set.copyOf(supported), commitment);
    }

    private static String required(Map<String, String> fields, String key) {
        String value = fields.get(key);
        if (value == null) {
            throw new RemoteSigningException("Remote signing response is missing field '" + key + "'");
        }
        return value;
    }

    private static byte[] decodeBase64(String value, String what) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException malformed) {
            throw new RemoteSigningException("Remote signing " + what + " is malformed", malformed);
        }
    }
}
