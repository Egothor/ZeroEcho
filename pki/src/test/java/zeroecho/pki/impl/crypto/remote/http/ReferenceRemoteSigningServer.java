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
package zeroecho.pki.impl.crypto.remote.http;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport.RemoteCallControl;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport.RemoteCapabilities;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport.RemoteSignRequest;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport.RemoteSigningStatus;

/**
 * Loopback HTTPS reference of a remote signing service. It terminates
 * mutually-authenticated TLS and maps the packaged JSON wire protocol onto an
 * in-process {@link RemoteSigningTransport} delegate (typically a
 * {@code ReferenceRemoteSigner}), proving {@link HttpsRemoteSigningTransport}
 * against a real socket, real TLS, and real client-certificate authentication.
 */
public final class ReferenceRemoteSigningServer implements AutoCloseable {

    private static final int HTTP_OK = 200;
    private static final int HTTP_BAD_REQUEST = 400;
    private static final int HTTP_CONFLICT = 409;
    private static final int HTTP_INTERNAL = 500;

    private final HttpsServer server;
    private final ExecutorService executor;
    private final RemoteSigningTransport delegate;
    private final Map<String, String> responseOverrides;

    private ReferenceRemoteSigningServer(HttpsServer server, ExecutorService executor,
            RemoteSigningTransport delegate, Map<String, String> responseOverrides) {
        this.server = server;
        this.executor = executor;
        this.delegate = delegate;
        this.responseOverrides = Map.copyOf(responseOverrides);
    }

    /**
     * Starts the reference server on an ephemeral loopback port.
     *
     * @param delegate in-process signing service to expose
     * @param serverContext mutually-authenticated server TLS context
     * @return a running server
     * @throws Exception if the server cannot bind or start
     */
    public static ReferenceRemoteSigningServer start(RemoteSigningTransport delegate, SSLContext serverContext)
            throws Exception {
        return start(delegate, serverContext, Map.of());
    }

    /**
     * Starts a server that injects untrusted reason text into every status wire response.
     *
     * @param delegate in-process signing service to expose
     * @param serverContext mutually-authenticated server TLS context
     * @param reason untrusted raw wire reason
     * @return a running server
     * @throws Exception if the server cannot bind or start
     */
    public static ReferenceRemoteSigningServer startWithResponseReason(RemoteSigningTransport delegate,
            SSLContext serverContext, String reason) throws Exception {
        return start(delegate, serverContext, Map.of("reason", reason));
    }

    /** Starts a server that overrides selected untrusted status response fields. */
    /* default */ static ReferenceRemoteSigningServer startWithStatusOverrides(RemoteSigningTransport delegate,
            SSLContext serverContext, Map<String, String> responseOverrides) throws Exception {
        return start(delegate, serverContext, responseOverrides);
    }

    private static ReferenceRemoteSigningServer start(RemoteSigningTransport delegate, SSLContext serverContext,
            Map<String, String> responseOverrides) throws Exception {
        HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverContext) {
            @Override
            public void configure(HttpsParameters parameters) {
                SSLParameters sslParameters = serverContext.getDefaultSSLParameters();
                sslParameters.setNeedClientAuth(true);
                parameters.setSSLParameters(sslParameters);
            }
        });
        ExecutorService executor = Executors.newFixedThreadPool(4);
        server.setExecutor(executor);
        ReferenceRemoteSigningServer instance = new ReferenceRemoteSigningServer(server, executor, delegate,
                responseOverrides);
        server.createContext("/v1/sign", instance::handle);
        server.start();
        return instance;
    }

    /** @return the absolute endpoint URI to configure the transport with */
    public URI endpoint() {
        return URI.create("https://127.0.0.1:" + server.getAddress().getPort() + "/v1/sign");
    }

    private void handle(HttpExchange exchange) {
        try {
            byte[] requestBody = exchange.getRequestBody().readAllBytes();
            int code = HTTP_OK;
            Map<String, String> response;
            try {
                response = dispatch(RemoteSigningJson.read(requestBody));
            } catch (IllegalStateException conflict) {
                code = HTTP_CONFLICT;
                response = Map.of("error", "conflict");
            } catch (IllegalArgumentException badRequest) {
                code = HTTP_BAD_REQUEST;
                response = Map.of("error", "bad-request");
            } catch (RuntimeException failure) {
                code = HTTP_INTERNAL;
                response = Map.of("error", "internal");
            }
            byte[] responseBody = RemoteSigningJson.write(response);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(code, responseBody.length);
            try (OutputStream output = exchange.getResponseBody()) {
                output.write(responseBody);
            }
        } catch (Exception transportFailure) {
            exchange.close();
        }
    }

    private Map<String, String> dispatch(Map<String, String> in) {
        String op = in.get("op");
        if (op == null) {
            throw new IllegalArgumentException("Missing op");
        }
        return switch (op) {
            case "capabilities" -> encodeCapabilities(delegate.capabilities());
            case "submit" -> encodeStatus(delegate.submit(decodeRequest(in), control()));
            case "status" -> encodeStatus(delegate.status(field(in, "operationId"), control()));
            case "cancel" -> encodeStatus(delegate.cancel(field(in, "operationId"),
                    Long.parseLong(field(in, "fencingToken")), field(in, "reason"), control()));
            case "publicKey" -> Map.of("spki", Base64.getEncoder()
                    .encodeToString(delegate.publicKeyInfo(field(in, "keyHandle"), control())));
            default -> throw new IllegalArgumentException("Unknown op: " + op);
        };
    }

    private static RemoteSignRequest decodeRequest(Map<String, String> in) {
        String deadline = in.getOrDefault("deadline", "");
        return new RemoteSignRequest(field(in, "submissionId"), field(in, "namespace"),
                field(in, "semanticFingerprint"), Long.parseLong(field(in, "fencingToken")), field(in, "keyHandle"),
                field(in, "algorithmId"), field(in, "contentSha256"), Long.parseLong(field(in, "contentLength")),
                Base64.getDecoder().decode(field(in, "content")), field(in, "principalType"),
                field(in, "principalName"), field(in, "purpose"),
                deadline.isEmpty() ? Optional.empty() : Optional.of(Instant.parse(deadline)),
                Integer.parseInt(field(in, "protocolVersion")),
                zeroecho.pki.spi.crypto.SigningInputCapabilities.Mode.valueOf(field(in, "inputMode")),
                field(in, "digestId"), new zeroecho.pki.spi.crypto.SigningProvider.ConfigurationCommitment(
                        Base64.getDecoder().decode(field(in, "configurationCommitment"))));
    }

    private Map<String, String> encodeStatus(RemoteSigningStatus status) {
        Map<String, String> out = new LinkedHashMap<>();
        out.put("operationId", status.operationId());
        out.put("state", status.state().name());
        out.put("updatedAt", status.updatedAt().toString());
        out.put("reason", "");
        out.put("signature", status.signature().map(Base64.getEncoder()::encodeToString).orElse(""));
        out.put("signatureEncoding", status.signatureEncoding());
        out.putAll(responseOverrides);
        return out;
    }

    private Map<String, String> encodeCapabilities(RemoteCapabilities capabilities) {
        List<String> algorithms = new ArrayList<>(capabilities.supportedAlgorithms());
        Collections.sort(algorithms);
        Map<String, String> out = new LinkedHashMap<>();
        out.put("algorithms", String.join(HttpsRemoteSigningTransport.ALGORITHM_SEPARATOR, algorithms));
        out.put("protocolVersion", Integer.toString(capabilities.protocolVersion()));
        out.put("rawMessageMaximum", Long.toString(capabilities.inputCapabilities().rawMessageMaximum()));
        java.util.Map<String, zeroecho.core.spec.AlgorithmIdentity> mappings =
                new java.util.TreeMap<>(capabilities.inputCapabilities().prehashedDigests());
        out.put("prehashCount", Integer.toString(mappings.size()));
        int index = 0;
        for (java.util.Map.Entry<String, zeroecho.core.spec.AlgorithmIdentity> entry : mappings.entrySet()) {
            out.put("prehashAlgorithm." + index, entry.getKey());
            out.put("prehashDigest." + index, entry.getValue().canonicalForm());
            index++;
        }
        out.put("configurationCommitment",
                Base64.getEncoder().encodeToString(capabilities.configurationCommitment()));
        responseOverrides.forEach((key, value) -> {
            if (out.containsKey(key)) {
                out.put(key, value);
            }
        });
        out.remove(responseOverrides.get("omitCapabilityField"));
        return out;
    }

    private static RemoteCallControl control() {
        return new RemoteCallControl(Instant.now().plusSeconds(60L), CancellationSignal.NONE);
    }

    private static String field(Map<String, String> in, String key) {
        String value = in.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Missing field: " + key);
        }
        return value;
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
        delegate.close();
    }
}
