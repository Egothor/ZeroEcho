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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;

import javax.net.ssl.SSLPeerUnverifiedException;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsExchange;

import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.AuthorizationEngine;
import zeroecho.pki.server.OperationSecurityDescriptors;
import zeroecho.pki.server.Permission;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.ServerOperationGateway;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.spi.PkiServerAuthenticationContext;
import zeroecho.pki.server.spi.PkiServerAuthenticationResult;
import zeroecho.pki.server.spi.PkiServerAuthenticator;

/** Single exact-path HTTPS adapter; all PKI execution delegates to the gateway. */
@SuppressWarnings("PMD")
final class AdminHttpHandler implements HttpHandler {
    private static final String JSON = "application/json; charset=utf-8";
    private final PkiServerConfiguration configuration;
    private final ServerRealmContext realm;
    private final PkiServerAuthenticator authenticator;
    private final ServerRuntime runtime;
    private final Clock clock;
    private final RequestIds requestIds;
    private final BooleanSupplier ready;

    AdminHttpHandler(PkiServerConfiguration configuration, ServerRealmContext realm,
            PkiServerAuthenticator authenticator, ServerRuntime runtime, Clock clock,
            RequestIds requestIds, BooleanSupplier ready) {
        this.configuration = configuration;
        this.realm = realm;
        this.authenticator = authenticator;
        this.runtime = runtime;
        this.clock = clock;
        this.requestIds = requestIds;
        this.ready = ready;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String requestId = "unavailable-request";
        HttpResponses.Response response;
        boolean admitted = false;
        try {
            requireHeadersBounded(exchange.getRequestHeaders());
            requestId = requestIds.resolve(exchange.getRequestHeaders().get(RequestIds.HEADER));
            if (configuration.authentication().mode()
                    == zeroecho.pki.server.AdministrativeAuthenticationMode.DIRECT_MTLS
                    && ForwardedClientCertificateParser.containsForwardedIdentity(
                            authenticationHeaders(exchange.getRequestHeaders()))) {
                realm.auditTransport("ADMIN_AUTHENTICATION_REJECTED", "system",
                        authenticationDetails(requestId, configuration.authentication().mode(),
                                Optional.empty(), Optional.empty(), "FORWARDED_IDENTITY_FORBIDDEN"));
                response = HttpResponses.failure(400, requestId, "authentication", "VALIDATION_FAILURE",
                        "FORWARDED_IDENTITY_FORBIDDEN", "FORWARDED_IDENTITY_FORBIDDEN", false, false);
                send(exchange, requestId, response);
                return;
            }
            URI uri = exchange.getRequestURI();
            if (uri.getRawQuery() != null || uri.getRawFragment() != null) throw malformed(requestId, "route");
            String path = uri.getPath();
            if ("/health/live".equals(path)) {
                response = requireMethod(exchange, "GET")
                        ? HttpResponses.minimal(200, requestId, "health.live", "LIVE")
                        : method(requestId, "health.live");
            } else if ("/health/ready".equals(path)) {
                boolean isReady = ready.getAsBoolean();
                response = requireMethod(exchange, "GET")
                        ? HttpResponses.minimal(isReady ? 200 : 503, requestId,
                                "health.ready", isReady ? "READY" : "NOT_READY")
                        : method(requestId, "health.ready");
            } else {
                if (!runtime.tryAdmit()) {
                    realm.auditTransport("REQUEST_REJECTED", "system", Map.of("request", requestId,
                            "classification", "ADMISSION_REJECTED"));
                    response = HttpResponses.failure(429, requestId, "request", "OVERLOADED",
                            "ADMISSION_REJECTED", "ADMISSION_REJECTED", false, false);
                } else {
                    admitted = true;
                    realm.auditTransport("REQUEST_ADMITTED", "system", Map.of("request", requestId));
                    response = admin((HttpsExchange) exchange, path, requestId);
                }
            }
        } catch (TransportFailure failure) {
            response = failure.response();
        } catch (IllegalArgumentException invalid) {
            response = HttpResponses.failure(400, requestId, "request", "VALIDATION_FAILURE",
                    "MALFORMED_REQUEST", "MALFORMED_REQUEST", false, false);
        } catch (RuntimeException failure) {
            response = HttpResponses.failure(500, requestId, "request", "INTERNAL_FAILURE",
                    "SAFE_INTERNAL_FAILURE", "SAFE_INTERNAL_FAILURE", false, false);
        } finally {
            if (admitted) runtime.releaseAdmission();
        }
        send(exchange, requestId, response);
    }

    private HttpResponses.Response admin(HttpsExchange exchange, String path, String requestId) throws IOException {
        PkiServerAuthenticationResult authentication = authenticate(exchange, requestId);
        if (!(authentication instanceof PkiServerAuthenticationResult.Authenticated authenticated)) {
            PkiServerAuthenticationResult.Rejected rejected =
                    (PkiServerAuthenticationResult.Rejected) authentication;
            String actor = rejected.transportPrincipalId().orElse("system");
            realm.auditTransport("ADMIN_AUTHENTICATION_REJECTED", actor,
                    authenticationDetails(requestId, rejected.mode(), rejected.transportPrincipalId(),
                            rejected.endClientPrincipalId(), rejected.code().name()));
            return HttpResponses.failure(401, requestId, "authentication", "AUTHENTICATION_FAILURE",
                    "CLIENT_AUTHENTICATION_FAILED", "CLIENT_AUTHENTICATION_FAILED", false, false);
        }
        String principalId = authenticated.endClientPrincipalId();
        realm.auditTransport("ADMIN_AUTHENTICATION_ACCEPTED", principalId,
                authenticationDetails(requestId, authenticated.mode(), authenticated.transportPrincipalId(),
                        Optional.of(principalId), "ACCEPTED"));
        if ("/admin/v1/realm".equals(path)) return realm(exchange, requestId, principalId);
        if ("/admin/v1/operations".equals(path)) return operations(exchange, requestId, principalId);
        String prefix = "/admin/v1/operations/";
        if (!path.startsWith(prefix) || path.length() == prefix.length()) return notFound(requestId);
        String operationId = path.substring(prefix.length());
        if (!operationId.matches("[a-z][a-z0-9.]{2,127}")) return notFound(requestId);
        Optional<OperationSecurityDescriptors.Descriptor> descriptor = realm.gateway()
                .discoverableOperations(principalId).stream()
                .filter(item -> item.operationId().equals(operationId)).findFirst();
        if (descriptor.isEmpty()) return notFound(requestId);
        if (requireMethod(exchange, "GET")) return descriptor(requestId, descriptor.orElseThrow());
        if (!requireMethod(exchange, "POST")) return method(requestId, operationId);
        return execute(exchange, requestId, authenticated, operationId);
    }

    private HttpResponses.Response realm(HttpsExchange exchange, String requestId, String principalId) {
        if (!requireMethod(exchange, "GET")) return method(requestId, "realm.inspect");
        Permission.Resource resource = new Permission.Resource(Permission.ResourceType.REALM,
                new Permission.Scope(configuration.realm().realmId(), Optional.empty(), Optional.empty(),
                        Optional.empty()), Optional.empty(), Optional.empty());
        AuthorizationEngine.Decision decision = realm.gateway().authorizeControl(principalId,
                Permission.Action.REALM_READ, resource, Permission.Context.empty(), requestId);
        if (!decision.allowed()) return denied(requestId, "realm.inspect");
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        fields.put("realmId", new PkiOperationValue.Text(configuration.realm().realmId().value()));
        fields.put("displayName", new PkiOperationValue.Text(configuration.realm().displayName()));
        fields.put("authorityExposure", new PkiOperationValue.Text(
                configuration.realm().authorityExposure().mode().name()));
        fields.put("authorityCreationPermitted", new PkiOperationValue.BooleanValue(
                configuration.realm().authorityExposure().authorityCreationPermitted()));
        return HttpResponses.success(requestId, "realm.inspect", new PkiOperationValue.ObjectValue(fields));
    }

    private HttpResponses.Response operations(HttpsExchange exchange, String requestId, String principalId) {
        if (!requireMethod(exchange, "GET")) return method(requestId, "operation.list");
        List<PkiOperationValue> values = realm.gateway().discoverableOperations(principalId).stream()
                .map(AdminHttpHandler::descriptorValue).map(PkiOperationValue.class::cast).toList();
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        fields.put("count", new PkiOperationValue.IntegerValue(values.size()));
        fields.put("operations", new PkiOperationValue.ListValue(values));
        return HttpResponses.success(requestId, "operation.list", new PkiOperationValue.ObjectValue(fields));
    }

    private HttpResponses.Response descriptor(String requestId, OperationSecurityDescriptors.Descriptor value) {
        return HttpResponses.success(requestId, "operation.inspect", descriptorValue(value));
    }

    private HttpResponses.Response execute(HttpsExchange exchange, String requestId,
            PkiServerAuthenticationResult.Authenticated authenticated, String operationId) throws IOException {
        String principalId = authenticated.endClientPrincipalId();
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null || !(contentType.equalsIgnoreCase("application/json")
                || contentType.equalsIgnoreCase(JSON))) {
            return HttpResponses.failure(415, requestId, operationId, "VALIDATION_FAILURE",
                    "UNSUPPORTED_MEDIA_TYPE", "UNSUPPORTED_MEDIA_TYPE", false, false);
        }
        byte[] body;
        try {
            body = body(exchange.getRequestBody(), exchange.getRequestHeaders().getFirst("Content-Length"));
        } catch (IllegalArgumentException invalid) {
            return HttpResponses.failure(413, requestId, operationId, "VALIDATION_FAILURE",
                    "REQUEST_BODY_REJECTED", "REQUEST_BODY_REJECTED", false, false);
        }
        HttpOperationCodec.Decoded decoded;
        try {
            decoded = HttpOperationCodec.decode(operationId, body, configuration.listener().maximumBodyBytes(),
                    configuration.realm().realmId(), realm.gateway()::descriptor);
        } catch (SecurityException unavailable) {
            return notFound(requestId);
        } catch (IllegalArgumentException invalid) {
            return HttpResponses.failure(400, requestId, operationId, "VALIDATION_FAILURE",
                    "INVALID_OPERATION_REQUEST", "INVALID_OPERATION_REQUEST", false, false);
        }
        Duration effective = decoded.requestedDeadline().orElse(configuration.execution().defaultDeadline());
        if (effective.compareTo(configuration.execution().maximumDeadline()) > 0) {
            effective = configuration.execution().maximumDeadline();
        }
        Instant deadline;
        try {
            deadline = clock.instant().plus(effective);
        } catch (RuntimeException overflow) {
            return HttpResponses.failure(400, requestId, operationId, "VALIDATION_FAILURE",
                    "INVALID_DEADLINE", "INVALID_DEADLINE", false, false);
        }
        if (!clock.instant().isBefore(deadline)) return deadline(requestId, operationId);
        ServerRuntime.Submitted<ServerOperationGateway.Outcome> submitted;
        try {
            submitted = runtime.submit(cancellation -> {
                if (!clock.instant().isBefore(deadline)) throw new DeadlineExceeded();
                ServerOperationGateway.Request gateway = new ServerOperationGateway.Request(
                        configuration.realm().realmId(), principalId, authenticated.mode(),
                        authenticated.transportPrincipalId(), decoded.operation(), decoded.resource(),
                        Permission.Relationship.ANY, decoded.context(), decoded.approvalId(), requestId);
                return realm.gateway().execute(gateway, cancellation);
            });
        } catch (RejectedExecutionException overloaded) {
            realm.auditTransport("REQUEST_OVERLOAD", principalId, Map.of("request", requestId,
                    "operation", operationId));
            return HttpResponses.failure(429, requestId, operationId, "OVERLOADED", "OPERATION_QUEUE_FULL",
                    "OPERATION_QUEUE_FULL", false, false);
        }
        try {
            long remaining = Math.max(1L, Duration.between(clock.instant(), deadline).toMillis());
            ServerOperationGateway.Outcome outcome = submitted.future().get(remaining, TimeUnit.MILLISECONDS);
            realm.auditTransport("REQUEST_COMPLETED", principalId,
                    Map.of("request", requestId, "operation", operationId));
            return HttpResponses.gateway(requestId, operationId, outcome);
        } catch (TimeoutException timeout) {
            submitted.cancellation().cancel();
            submitted.future().cancel(true);
            realm.auditTransport("REQUEST_DEADLINE", principalId,
                    Map.of("request", requestId, "operation", operationId));
            return deadline(requestId, operationId);
        } catch (InterruptedException interrupted) {
            submitted.cancellation().cancel();
            submitted.future().cancel(true);
            Thread.currentThread().interrupt();
            return deadline(requestId, operationId);
        } catch (ExecutionException failure) {
            if (failure.getCause() instanceof DeadlineExceeded) return deadline(requestId, operationId);
            return HttpResponses.failure(500, requestId, operationId, "INTERNAL_FAILURE",
                    "SAFE_INTERNAL_FAILURE", "SAFE_INTERNAL_FAILURE", false, false);
        } finally {
            submitted.finish();
        }
    }

    private PkiServerAuthenticationResult authenticate(HttpsExchange exchange, String requestId) {
        try {
            Certificate[] peer = exchange.getSSLSession().getPeerCertificates();
            List<X509Certificate> chain = new ArrayList<>();
            for (Certificate certificate : peer) {
                if (!(certificate instanceof X509Certificate x509)) {
                    return new PkiServerAuthenticationResult.Rejected(
                            PkiServerAuthenticationResult.Code.CERTIFICATE_INVALID);
                }
                chain.add(x509);
            }
            return authenticator.authenticate(new PkiServerAuthenticationContext(chain,
                    exchange.getSSLSession().getProtocol(), exchange.getSSLSession().getCipherSuite(),
                    requestId, configuration.realm().realmId(), authenticationHeaders(exchange.getRequestHeaders())));
        } catch (SSLPeerUnverifiedException failure) {
            return new PkiServerAuthenticationResult.Rejected(
                    configuration.authentication().mode(), Optional.empty(), Optional.empty(),
                    PkiServerAuthenticationResult.Code.CERTIFICATE_INVALID);
        } catch (RuntimeException failure) {
            return new PkiServerAuthenticationResult.Rejected(
                    configuration.authentication().mode(), Optional.empty(), Optional.empty(),
                    PkiServerAuthenticationResult.Code.INTERNAL_FAILURE);
        }
    }

    private Map<String, List<String>> authenticationHeaders(Headers headers) {
        java.util.Set<String> accepted = new java.util.TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        accepted.add(ForwardedClientCertificateParser.RFC_CERTIFICATE_HEADER);
        accepted.add(ForwardedClientCertificateParser.RFC_CHAIN_HEADER);
        accepted.add(ForwardedClientCertificateParser.DIRECT_REJECTED_NGINX_HEADER);
        configuration.authentication().forwardedCertificateHeaderName().ifPresent(accepted::add);
        configuration.authentication().forwardedCertificateChainHeaderName().ifPresent(accepted::add);
        Map<String, List<String>> result = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (accepted.contains(entry.getKey())) result.put(entry.getKey(), List.copyOf(entry.getValue()));
        }
        return Map.copyOf(result);
    }

    private static Map<String, String> authenticationDetails(String requestId,
            zeroecho.pki.server.AdministrativeAuthenticationMode mode, Optional<String> transport,
            Optional<String> endClient, String classification) {
        Map<String, String> details = new LinkedHashMap<>();
        details.put("request", requestId);
        details.put("mode", mode.name());
        transport.ifPresent(value -> details.put("transportPrincipal", value));
        endClient.ifPresent(value -> details.put("endClientPrincipal", value));
        details.put("classification", classification);
        return Map.copyOf(details);
    }

    private byte[] body(InputStream input, String contentLength) throws IOException {
        int maximum = configuration.listener().maximumBodyBytes();
        if (contentLength != null) {
            try {
                long length = Long.parseLong(contentLength);
                if (length < 0 || length > maximum) throw new IllegalArgumentException("Body is oversized");
            } catch (NumberFormatException failure) {
                throw new IllegalArgumentException("Content length is invalid");
            }
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream(Math.min(maximum, 8_192));
        byte[] buffer = new byte[8_192];
        int total = 0;
        int read;
        while ((read = input.read(buffer)) >= 0) {
            total = Math.addExact(total, read);
            if (total > maximum) throw new IllegalArgumentException("Body is oversized");
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }

    private void requireHeadersBounded(Headers headers) {
        int bytes = 0;
        for (Map.Entry<String, List<String>> header : headers.entrySet()) {
            bytes = Math.addExact(bytes, header.getKey().getBytes(StandardCharsets.UTF_8).length);
            for (String value : header.getValue()) {
                bytes = Math.addExact(bytes, value.getBytes(StandardCharsets.UTF_8).length);
                if (bytes > configuration.listener().maximumHeaderBytes()) {
                    throw new IllegalArgumentException("Request headers are oversized");
                }
            }
        }
    }

    private static PkiOperationValue.ObjectValue descriptorValue(OperationSecurityDescriptors.Descriptor value) {
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        fields.put("operation", new PkiOperationValue.Text(value.operationId()));
        fields.put("family", new PkiOperationValue.Text(value.family().name()));
        fields.put("mutating", new PkiOperationValue.BooleanValue(value.mutating()));
        fields.put("resourceType", new PkiOperationValue.Text(value.resourceType().name()));
        fields.put("approval", new PkiOperationValue.Text(value.approvalCategory().name()));
        fields.put("dataView", new PkiOperationValue.Text(value.dataView().name()));
        return new PkiOperationValue.ObjectValue(fields);
    }

    private static boolean requireMethod(HttpExchange exchange, String expected) {
        return expected.equals(exchange.getRequestMethod());
    }

    private static HttpResponses.Response method(String requestId, String operation) {
        return HttpResponses.failure(405, requestId, operation, "VALIDATION_FAILURE", "METHOD_NOT_ALLOWED",
                "METHOD_NOT_ALLOWED", false, false);
    }

    private static HttpResponses.Response notFound(String requestId) {
        return HttpResponses.failure(404, requestId, "operation", "NOT_FOUND", "OPERATION_NOT_FOUND",
                "OPERATION_NOT_FOUND", false, false);
    }

    private static HttpResponses.Response denied(String requestId, String operation) {
        return HttpResponses.failure(403, requestId, operation, "DENIED", "AUTHORIZATION_DENIED",
                "AUTHORIZATION_DENIED", false, false);
    }

    private static HttpResponses.Response deadline(String requestId, String operation) {
        return HttpResponses.failure(504, requestId, operation, "CANCELLED", "DEADLINE_EXCEEDED",
                "DEADLINE_EXCEEDED", false, false);
    }

    private static TransportFailure malformed(String requestId, String operation) {
        return new TransportFailure(HttpResponses.failure(400, requestId, operation, "VALIDATION_FAILURE",
                "MALFORMED_REQUEST", "MALFORMED_REQUEST", false, false));
    }

    private void send(HttpExchange exchange, String requestId, HttpResponses.Response response)
            throws IOException {
        byte[] body = response.body();
        exchange.getResponseHeaders().set("Content-Type", JSON);
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        if (response.oneTimeSensitive()) {
            exchange.getResponseHeaders().set("Pragma", "no-cache");
            exchange.getResponseHeaders().set("Referrer-Policy", "no-referrer");
        }
        exchange.getResponseHeaders().set(RequestIds.HEADER, requestId);
        exchange.sendResponseHeaders(response.statusCode(), body.length);
        try (java.io.OutputStream output = exchange.getResponseBody()) {
            output.write(body);
            classifyCapabilityDelivery(response, true, requestId);
        } catch (IOException failure) {
            if (response.oneTimeSensitive()) {
                try {
                    classifyCapabilityDelivery(response, false, requestId);
                } catch (RuntimeException classificationFailure) {
                    failure.addSuppressed(classificationFailure);
                }
                realm.auditTransport("CAPABILITY_DELIVERY_UNKNOWN", "system",
                        Map.of("request", requestId, "classification", "CAPABILITY_DELIVERY_UNKNOWN"));
            }
            throw failure;
        } finally {
            java.util.Arrays.fill(body, (byte) 0);
            response.clearSensitiveBody();
            exchange.close();
        }
    }

    private void classifyCapabilityDelivery(HttpResponses.Response response, boolean delivered,
            String requestId) {
        try {
            response.capabilityId().ifPresent(value -> realm.disclosure().classifyDelivery(value, delivered));
        } catch (RuntimeException failure) {
            realm.auditTransport("CAPABILITY_DELIVERY_UNKNOWN", "system",
                    Map.of("request", requestId, "classification", "CAPABILITY_DELIVERY_UNKNOWN"));
            if (!delivered) throw failure;
        }
    }

    private static final class TransportFailure extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final transient HttpResponses.Response response;
        private TransportFailure(HttpResponses.Response response) { this.response = response; }
        private HttpResponses.Response response() { return response; }
    }
    private static final class DeadlineExceeded extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }
}
