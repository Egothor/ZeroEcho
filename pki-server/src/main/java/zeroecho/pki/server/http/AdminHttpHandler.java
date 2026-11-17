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
import zeroecho.pki.server.jfr.AdminRequestEvent;
import zeroecho.pki.server.schema.GenerateOperationSchema;
import zeroecho.pki.server.spi.PkiServerAuthenticationResult;
import zeroecho.pki.server.spi.PkiServerAuthenticator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;

/**
 * Single exact-path HTTPS adapter; all PKI execution delegates to the gateway.
 */
/* default */ final class AdminHttpHandler implements HttpHandler {
    private static final String SDK_ISSUE = "credential.issue";

    private static final String TEXT_SYSTEM = "system";
    private static final String TEXT_VALIDATION_FAILURE = "VALIDATION_FAILURE";
    private static final String TEXT_HEALTH_LIVE = "/health/live";
    private static final String TEXT_GET = "GET";
    private static final String TEXT_HEALTH_READY = "/health/ready";
    private static final String TEXT_REQUEST = "request";
    private static final String TEXT_OVERLOADED = "OVERLOADED";
    private static final String TEXT_SAFE_INTERNAL_FAILURE = "SAFE_INTERNAL_FAILURE";
    private static final String TEXT_ADMIN_V1_REALM = "/admin/v1/realm";
    private static final String TEXT_ADMIN_V1_SCHEMA = "/admin/v1/schema";
    private static final String TEXT_ADMIN_V1_OPERATIONS = "/admin/v1/operations";
    private static final String TEXT_CONTENT_TYPE = "Content-Type";
    private static final String TEXT_UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE";
    private static final String TEXT_OPERATION = "operation";
    private static final String ADMIN_REQUEST_ACTION = "administrative.request.submit";
    private static final int BOUND_2 = 2;
    private static final String TEXT_OPERATION_QUEUE_FULL = "OPERATION_QUEUE_FULL";
    private static final int BOUND_1 = 1;

    private static final String JSON = "application/json; charset=utf-8";
    private final PkiServerConfiguration configuration;
    private final ServerRealmContext realm;
    private final PkiServerAuthenticator authenticator;
    private final ServerRuntime runtime;
    private final Clock clock;
    private final RequestIds requestIds;
    private final BooleanSupplier ready;

    /**
     * Composes the administrative HTTP boundary from borrowed realm and execution services.
     *
     * @param configuration listener limits and exposure policy
     * @param realm lifecycle-owned realm context
     * @param authenticator transport identity authenticator
     * @param runtime lifecycle-owned admission and operation execution owner
     * @param clock deadline and audit time source
     * @param requestIds correlation-identifier validator/generator
     * @param ready readiness observation checked before request admission
     */
    /* default */ AdminHttpHandler(PkiServerConfiguration configuration, ServerRealmContext realm,
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

    /**
     * {@inheritDoc}
     */
    // This transport boundary must preserve cleanup and finite masking of provider/runtime
    // failures.
    @SuppressWarnings({"PMD.AvoidCatchingGenericException"})
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if (exchange.getRequestURI().getPath().startsWith("/admin/")) {
            realm.recordAdminRequest();
        }
        AdminRequestEvent jfrEvent = new AdminRequestEvent();
        jfrEvent.operationId = "";
        jfrEvent.principalId = "";
        jfrEvent.begin();
        String requestId = "unavailable-request";
        HttpResponses.Response response;
        boolean admitted = false;
        try {
            new AdminTransportAuthentication(configuration, authenticator)
                    .requireHeadersBounded(exchange.getRequestHeaders());
            requestId = requestIds.resolve(exchange.getRequestHeaders().get(RequestIds.HEADER));
            if (configuration.authentication().mode()
                            == zeroecho.pki.server.AdministrativeAuthenticationMode.DIRECT_MTLS
                    && ForwardedClientCertificateParser.containsForwardedIdentity(
                            new AdminTransportAuthentication(configuration, authenticator)
                                    .authenticationHeaders(exchange.getRequestHeaders()))) {
                realm.auditTransport(
                        "ADMIN_AUTHENTICATION_REJECTED",
                        TEXT_SYSTEM,
                        AdminTransportAuthentication.authenticationDetails(
                                requestId,
                                configuration.authentication().mode(),
                                Optional.empty(),
                                Optional.empty(),
                                "FORWARDED_IDENTITY_FORBIDDEN"));
                response =
                        HttpResponses.failure(
                                400,
                                requestId,
                                "authentication",
                                TEXT_VALIDATION_FAILURE,
                                "FORWARDED_IDENTITY_FORBIDDEN",
                                "FORWARDED_IDENTITY_FORBIDDEN",
                                false,
                                false);
                new AdminResponseDelivery(realm).send(exchange, requestId, response);
                return;
            }
            String path = validatedRoute(exchange.getRequestURI(), requestId);
            response = new DiscoveryRoutes().health(exchange, path, requestId);
            if (response == null) {
                if (runtime.tryAdmit()) {
                    admitted = true;
                    realm.auditTransport(
                            "REQUEST_ADMITTED", TEXT_SYSTEM, Map.of(TEXT_REQUEST, requestId));
                    response = admin((HttpsExchange) exchange, path, requestId);
                } else {
                    realm.auditTransport(
                            "REQUEST_REJECTED",
                            TEXT_SYSTEM,
                            Map.of(
                                    TEXT_REQUEST,
                                    requestId,
                                    "classification",
                                    "ADMISSION_REJECTED"));
                    response =
                            HttpResponses.failure(
                                    429,
                                    requestId,
                                    TEXT_REQUEST,
                                    TEXT_OVERLOADED,
                                    "ADMISSION_REJECTED",
                                    "ADMISSION_REJECTED",
                                    false,
                                    false);
                }
            }
        } catch (TransportFailure failure) {
            response = failure.response();
        } catch (IllegalArgumentException invalid) {
            response =
                    HttpResponses.failure(
                            400,
                            requestId,
                            TEXT_REQUEST,
                            TEXT_VALIDATION_FAILURE,
                            "MALFORMED_REQUEST",
                            "MALFORMED_REQUEST",
                            false,
                            false);
        } catch (RuntimeException failure) {
            response =
                    HttpResponses.failure(
                            500,
                            requestId,
                            TEXT_REQUEST,
                            "INTERNAL_FAILURE",
                            TEXT_SAFE_INTERNAL_FAILURE,
                            TEXT_SAFE_INTERNAL_FAILURE,
                            false,
                            false);
        } finally {
            if (admitted) {
                runtime.releaseAdmission();
            }
        }
        if (jfrEvent.shouldCommit()) {
            jfrEvent.httpStatus =
                    response == null ? exchange.getResponseCode() : response.statusCode();
            jfrEvent.authorized = admitted;
            jfrEvent.commit();
        }
        if (response == null) {
            exchange.close();
        } else {
            new AdminResponseDelivery(realm).send(exchange, requestId, response);
        }
    }

    private HttpResponses.Response admin(HttpsExchange exchange, String path, String requestId)
            throws IOException {
        PkiServerAuthenticationResult authentication =
                new AdminTransportAuthentication(configuration, authenticator)
                        .authenticate(exchange, requestId);
        if (!(authentication
                instanceof PkiServerAuthenticationResult.Authenticated authenticated)) {
            PkiServerAuthenticationResult.Rejected rejected =
                    (PkiServerAuthenticationResult.Rejected) authentication;
            String actor = rejected.transportPrincipalId().orElse(TEXT_SYSTEM);
            realm.auditTransport(
                    "ADMIN_AUTHENTICATION_REJECTED",
                    actor,
                    AdminTransportAuthentication.authenticationDetails(
                            requestId,
                            rejected.mode(),
                            rejected.transportPrincipalId(),
                            rejected.endClientPrincipalId(),
                            rejected.code().name()));
            return HttpResponses.failure(
                    401,
                    requestId,
                    "authentication",
                    "AUTHENTICATION_FAILURE",
                    "CLIENT_AUTHENTICATION_FAILED",
                    "CLIENT_AUTHENTICATION_FAILED",
                    false,
                    false);
        }
        String principalId = authenticated.endClientPrincipalId();
        realm.auditTransport(
                "ADMIN_AUTHENTICATION_ACCEPTED",
                principalId,
                AdminTransportAuthentication.authenticationDetails(
                        requestId,
                        authenticated.mode(),
                        authenticated.transportPrincipalId(),
                        Optional.of(principalId),
                        "ACCEPTED"));
        return dispatchAdmin(exchange, path, requestId, authenticated);
    }

    /**
     * Observes a signing operation only after authorizing its exact authoritative scope.
     *
     * @param requestId transport correlation identity
     * @param principalId authenticated principal requesting observation
     * @param signingId retained signing-operation identity
     * @return current outcome, or an indistinguishable not-found response for absent/unauthorized operations
     */
    /* default */ HttpResponses.Response signingOperation(
            String requestId, String principalId, String signingId) {
        return new AdminSigningObservation(configuration, realm)
                .observe(requestId, principalId, signingId);
    }

    // A null response means the binary exchange was committed or closed by its deadline; the caller
    // must not
    // attempt a second JSON response. The standalone transport owns bounded task executors and
    // preserves
    // cancellation/thread lifetime.
    @SuppressWarnings({"PMD.DoNotUseThreads"})
    private HttpResponses.Response statusArtifact(
            HttpsExchange exchange, String trace, String principal) {
        if (!requireMethod(exchange, TEXT_GET)) {
            return method(trace, "status.artifact.inspect");
        }
        ServerRuntime.Submitted<HttpResponses.Response> submitted;
        try {
            submitted =
                    runtime.submit(
                            cancellation ->
                                    new StatusArtifactHttp(realm)
                                            .respond(exchange, principal, trace, cancellation));
        } catch (RejectedExecutionException overloaded) {
            return HttpResponses.failure(
                    429,
                    trace,
                    "status.artifact.inspect",
                    TEXT_OVERLOADED,
                    TEXT_OPERATION_QUEUE_FULL,
                    TEXT_OPERATION_QUEUE_FULL,
                    false,
                    false);
        }
        try {
            return submitted
                    .future()
                    .get(
                            configuration.execution().maximumDeadline().toMillis(),
                            TimeUnit.MILLISECONDS);
        } catch (TimeoutException timeout) {
            submitted.cancellation().cancel();
            submitted.future().cancel(true);
            exchange.close();
            return null;
        } catch (InterruptedException interrupted) {
            submitted.cancellation().cancel();
            submitted.future().cancel(true);
            exchange.close();
            Thread.currentThread().interrupt();
            return null;
        } catch (ExecutionException failed) {
            if (exchange.getResponseCode() != -BOUND_1) {
                exchange.close();
                return null;
            }
            return HttpResponses.failure(
                    500,
                    trace,
                    "status.artifact.inspect",
                    "INTERNAL_FAILURE",
                    TEXT_SAFE_INTERNAL_FAILURE,
                    TEXT_SAFE_INTERNAL_FAILURE,
                    false,
                    false);
        } finally {
            submitted.finish();
        }
    }

    // The standalone transport owns bounded task executors and preserves cancellation/thread
    // lifetime.
    @SuppressWarnings({"PMD.DoNotUseThreads"})
    private HttpResponses.Response certificateArtifact(
            HttpsExchange exchange, String trace, String principal) {
        if (!requireMethod(exchange, TEXT_GET)) {
            return method(trace, "certificate.artifact.inspect");
        }
        ServerRuntime.Submitted<HttpResponses.Response> submitted;
        try {
            submitted =
                    runtime.submit(
                            cancellation ->
                                    new CertificateArtifactHttp(realm)
                                            .respond(
                                                    exchange.getRequestURI().getRawPath(),
                                                    exchange.getRequestURI().getRawQuery(),
                                                    principal,
                                                    trace,
                                                    cancellation));
        } catch (RejectedExecutionException overloaded) {
            return HttpResponses.failure(
                    429,
                    trace,
                    "certificate.artifact.inspect",
                    TEXT_OVERLOADED,
                    TEXT_OPERATION_QUEUE_FULL,
                    TEXT_OPERATION_QUEUE_FULL,
                    false,
                    false);
        }
        try {
            return submitted
                    .future()
                    .get(
                            configuration.execution().defaultDeadline().toMillis(),
                            TimeUnit.MILLISECONDS);
        } catch (TimeoutException timeout) {
            submitted.cancellation().cancel();
            submitted.future().cancel(true);
            return deadline(trace, "certificate.artifact.inspect");
        } catch (InterruptedException interrupted) {
            submitted.cancellation().cancel();
            submitted.future().cancel(true);
            Thread.currentThread().interrupt();
            return deadline(trace, "certificate.artifact.inspect");
        } catch (ExecutionException failed) {
            return HttpResponses.failure(
                    500,
                    trace,
                    "certificate.artifact.inspect",
                    "INTERNAL_FAILURE",
                    TEXT_SAFE_INTERNAL_FAILURE,
                    TEXT_SAFE_INTERNAL_FAILURE,
                    false,
                    false);
        } finally {
            submitted.finish();
        }
    }

    private static boolean requireMethod(HttpExchange exchange, String expected) {
        return expected.equals(exchange.getRequestMethod());
    }

    private static HttpResponses.Response method(String requestId, String operation) {
        return HttpResponses.failure(
                405,
                requestId,
                operation,
                TEXT_VALIDATION_FAILURE,
                "METHOD_NOT_ALLOWED",
                "METHOD_NOT_ALLOWED",
                false,
                false);
    }

    private static HttpResponses.Response notFound(String requestId) {
        return HttpResponses.failure(
                404,
                requestId,
                TEXT_OPERATION,
                "NOT_FOUND",
                "OPERATION_NOT_FOUND",
                "OPERATION_NOT_FOUND",
                false,
                false);
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
        return new TransportFailure(
                HttpResponses.failure(
                        400,
                        requestId,
                        operation,
                        TEXT_VALIDATION_FAILURE,
                        "MALFORMED_REQUEST",
                        "MALFORMED_REQUEST",
                        false,
                        false));
    }

    /** Carries one prebuilt finite transport rejection to the owning response sender. */
    private static final class TransportFailure extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final transient HttpResponses.Response response;

        private TransportFailure(HttpResponses.Response response) {
            super();
            this.response = response;
        }

        private HttpResponses.Response response() { return response; }
    }
    /** Distinguishes an expired owned operation from an unrelated execution failure. */
    private static final class DeadlineExceeded extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    private static String validatedRoute(URI uri, String requestId) {
        if (uri.getRawFragment() != null
                || uri.getRawQuery() != null
                        && !"/admin/v1/requests".equals(uri.getPath())
                        && !uri.getRawPath()
                                .matches(
                                        "/admin/v1/(?:certificate|status)-artifacts/[^/]+/content")) {
            throw malformed(requestId, "route");
        }
        String path = uri.getPath();
        if ((path.startsWith("/admin/v1/hybrid-sdk")
                        || uri.getRawPath().startsWith("/admin/v1/hybrid-sdk"))
                && !uri.getRawPath().equals(path)) {
            throw malformed(requestId, "route");
        }
        return path;
    }

    private HttpResponses.Response dispatchAdmin(
            HttpsExchange exchange,
            String path,
            String requestId,
            PkiServerAuthenticationResult.Authenticated authenticated)
            throws IOException {
        String principalId = authenticated.endClientPrincipalId();
        HandledRoute handled =
                specializedRoute(exchange, path, requestId, authenticated, principalId);
        if (handled.matched()) {
            return handled.response();
        }
        if (TEXT_ADMIN_V1_REALM.equals(path)) {
            return new DiscoveryRoutes().realm(exchange, requestId, principalId);
        }
        if (TEXT_ADMIN_V1_SCHEMA.equals(path)) {
            return new DiscoveryRoutes().schema();
        }
        if (TEXT_ADMIN_V1_OPERATIONS.equals(path)) {
            return new DiscoveryRoutes().operations(exchange, requestId, principalId);
        }
        HttpResponses.Response signing = signingRoute(exchange, path, requestId, principalId);
        if (signing != null) {
            return signing;
        }
        String prefix = "/admin/v1/operations/";
        if (!path.startsWith(prefix) || path.length() == prefix.length()) {
            return notFound(requestId);
        }
        String operationId = path.substring(prefix.length());
        if (!operationId.matches("[a-z][a-z0-9.-]{2,127}")) {
            return notFound(requestId);
        }
        // Legacy unavailable operations still pass through authorization and approval.
        // Their descriptor remains hidden from GET/list/schema discovery.
        if (requireMethod(exchange, "POST")
                && zeroecho.pki.server.schema.OperationDescriptorCatalog.current()
                        .find(operationId)
                        .filter(entry -> !entry.available())
                        .isPresent()) {
            return new OperationExecution()
                    .execute(exchange, requestId, authenticated, operationId);
        }
        Optional<OperationSecurityDescriptors.Descriptor> descriptor =
                realm.gateway().discoverableOperations(principalId).stream()
                        .filter(item -> item.operationId().equals(operationId))
                        .findFirst();
        if (descriptor.isEmpty()) {
            return notFound(requestId);
        }
        if (requireMethod(exchange, TEXT_GET)) {
            return new DiscoveryRoutes().descriptor(requestId, descriptor.orElseThrow());
        }
        if (!requireMethod(exchange, "POST")) {
            return method(requestId, operationId);
        }
        return new OperationExecution().execute(exchange, requestId, authenticated, operationId);
    }

    /** Handles retained administrative and SDK requests after native authentication. */
    private final class RetainedRequestRoutes {
        private HttpResponses.Response hybridSdk(
                HttpsExchange exchange,
                String path,
                String trace,
                PkiServerAuthenticationResult.Authenticated actor)
                throws IOException {
            if (configuration.listener().hybridSdk().isEmpty() || realm.hybridSdkHttp().isEmpty()) {
                return notFound(trace);
            }
            String base = "/admin/v1/hybrid-sdk/v1";
            if (path.equals(base)) {
                if (!requireMethod(exchange, TEXT_GET)) {
                    return method(trace, "hybrid-sdk.capability");
                }
                return new HttpResponses.Response(
                        200,
                        HybridSdkHttpCodec.capability(
                                base,
                                List.of(
                                        SDK_ISSUE,
                                        "credential.renew",
                                        "credential.reissue",
                                        "credential.replace"),
                                configuration
                                        .listener()
                                        .hybridSdk()
                                        .orElseThrow()
                                        .canonicalOrigin(),
                                configuration.listener().maximumBodyBytes()));
            }
            if (!path.equals(base + "/challenge") && !path.equals(base + "/accept")) {
                return notFound(trace);
            }
            if (!requireMethod(exchange, "POST")) {
                return method(trace, "hybrid-sdk");
            }
            if (!HybridSdkHttpCodec.MEDIA_TYPE.equalsIgnoreCase(
                    exchange.getRequestHeaders().getFirst(TEXT_CONTENT_TYPE))) {
                return HttpResponses.failure(
                        415,
                        trace,
                        "hybrid-sdk",
                        TEXT_VALIDATION_FAILURE,
                        TEXT_UNSUPPORTED_MEDIA_TYPE,
                        TEXT_UNSUPPORTED_MEDIA_TYPE,
                        false,
                        false);
            }
            try {
                return sdkRequest(exchange, path, trace, actor);
            } catch (zeroecho.pki.server.AdministrativeRequestCoordinator.Conflict conflict) {
                return HttpResponses.failure(
                        409,
                        trace,
                        "hybrid-sdk",
                        "CONFLICT",
                        "SDK_INTENT_CONFLICT",
                        "SDK_INTENT_CONFLICT",
                        false,
                        false);
            } catch (zeroecho.pki.server.AdministrativeRequestCoordinator.Capacity full) {
                return HttpResponses.failure(
                        429,
                        trace,
                        "hybrid-sdk",
                        TEXT_OVERLOADED,
                        "SDK_CAPACITY",
                        "SDK_CAPACITY",
                        false,
                        false);
            } catch (SecurityException denied) {
                return notFound(trace);
            } catch (IllegalArgumentException | zeroecho.pki.api.PkiException invalid) {
                return HttpResponses.failure(
                        400,
                        trace,
                        "hybrid-sdk",
                        TEXT_VALIDATION_FAILURE,
                        "SDK_REQUEST_INVALID",
                        "SDK_REQUEST_INVALID",
                        false,
                        false);
            }
        }

        private HttpResponses.Response administrativeRequests(
                HttpsExchange exchange,
                String path,
                String trace,
                PkiServerAuthenticationResult.Authenticated actor)
                throws IOException {
            String viewer = actor.endClientPrincipalId();
            // The realm owns this shared coordinator; request handling must never close it.
            zeroecho.pki.server.AdministrativeRequestCoordinator coordinator =
                    realm.administrativeRequests();
            try {
                return requestCommand(exchange, path, trace, actor, viewer, coordinator);
            } catch (
                    zeroecho.pki.server.AdministrativeRequestCoordinator.ProvisioningConflict
                            conflict) {
                return HttpResponses.administrativeProvisioningConflict(
                        trace, conflict.canonicalRequestId());
            } catch (zeroecho.pki.server.AdministrativeRequestCoordinator.Conflict conflict) {
                return HttpResponses.failure(
                        409,
                        trace,
                        ADMIN_REQUEST_ACTION,
                        "CONFLICT",
                        "REQUEST_ID_CONFLICT",
                        "REQUEST_ID_CONFLICT",
                        false,
                        false);
            } catch (zeroecho.pki.server.AdministrativeRequestCoordinator.Capacity full) {
                return HttpResponses.failure(
                        429,
                        trace,
                        ADMIN_REQUEST_ACTION,
                        TEXT_OVERLOADED,
                        "ADMINISTRATIVE_REQUEST_CAPACITY",
                        "ADMINISTRATIVE_REQUEST_CAPACITY",
                        false,
                        false);
            } catch (
                    zeroecho.pki.server.AdministrativeRequestCoordinator.ValidationFailure
                            invalid) {
                return HttpResponses.failure(
                        400,
                        trace,
                        ADMIN_REQUEST_ACTION,
                        TEXT_VALIDATION_FAILURE,
                        invalid.code(),
                        invalid.code(),
                        false,
                        false);
            } catch (zeroecho.pki.api.PkiException invalid) {
                String code =
                        invalid.failureReason()
                                .filter(zeroecho.pki.api.PkiFailureReason::externalSafe)
                                .map(Enum::name)
                                .orElse("PKI_POLICY_REJECTED");
                return HttpResponses.failure(
                        400,
                        trace,
                        ADMIN_REQUEST_ACTION,
                        TEXT_VALIDATION_FAILURE,
                        code,
                        code,
                        false,
                        false);
            } catch (SecurityException unavailable) {
                return notFound(trace);
            } catch (IllegalArgumentException | ClassCastException invalid) {
                return HttpResponses.failure(
                        400,
                        trace,
                        ADMIN_REQUEST_ACTION,
                        TEXT_VALIDATION_FAILURE,
                        "INVALID_ADMINISTRATIVE_REQUEST",
                        "INVALID_ADMINISTRATIVE_REQUEST",
                        false,
                        false);
            }
        }

        private HttpResponses.Response sdkRequest(
                HttpsExchange exchange,
                String path,
                String trace,
                PkiServerAuthenticationResult.Authenticated actor)
                throws IOException {

            boolean acceptance = path.endsWith("/accept");
            Map<String, PkiOperationValue> fields =
                    HybridSdkHttpCodec.parse(
                            new OperationExecution()
                                    .body(
                                            exchange.getRequestBody(),
                                            exchange.getRequestHeaders()
                                                    .getFirst("Content-Length")),
                            configuration.listener().maximumBodyBytes(),
                            acceptance,
                            Set.of("operationId", "arguments", "requestDer"));
            String operation = HybridSdkHttpCodec.text(fields, "operationId");
            if (!Set.of(SDK_ISSUE, "credential.renew", "credential.reissue", "credential.replace")
                    .contains(operation)) {
                throw new IllegalArgumentException("Unsupported SDK operation");
            }
            if (!(fields.get("arguments") instanceof PkiOperationValue.ObjectValue arguments)) {
                throw new IllegalArgumentException("SDK arguments required");
            }
            Map<String, PkiOperationValue> envelopeFields = new LinkedHashMap<>();
            envelopeFields.put("version", new PkiOperationValue.IntegerValue(BOUND_1));
            envelopeFields.put("arguments", arguments);
            // Resolve the existing authorization scope; the SDK wire adds no authority override.
            PkiOperationValue authority;
            if (SDK_ISSUE.equals(operation)) {
                authority = arguments.fields().get("issuerCaId");
            } else {
                String name =
                        "credential.replace".equals(operation)
                                ? "existingCredentialId"
                                : "credentialId";
                if (!(arguments.fields().get(name) instanceof PkiOperationValue.Text id)) {
                    throw new IllegalArgumentException("SDK predecessor required");
                }
                zeroecho.pki.application.PkiResourceScopeResolver.CredentialScope scope =
                        realm.session()
                                .resourceScopes()
                                .credentialScope(new zeroecho.pki.api.PkiId(id.value()))
                                .orElseThrow(
                                        () ->
                                                new IllegalArgumentException(
                                                        "SDK predecessor unavailable"));
                authority = new PkiOperationValue.Text(scope.authorityId().value());
            }
            if (authority == null) {
                throw new IllegalArgumentException("SDK issuer required");
            }
            envelopeFields.put("authorityId", authority);
            PkiOperationValue.ObjectValue envelope =
                    new PkiOperationValue.ObjectValue(envelopeFields);
            HttpOperationCodec.Decoded decoded =
                    HttpOperationCodec.decode(
                            operation,
                            StrictJson.encode(envelope),
                            262_144,
                            configuration.realm().realmId(),
                            realm.gateway()::descriptor);
            ServerOperationGateway.Request request =
                    new ServerOperationGateway.Request(
                            configuration.realm().realmId(),
                            actor.endClientPrincipalId(),
                            actor.mode(),
                            actor.transportPrincipalId(),
                            actor.credentialEvidence(),
                            decoded.operation(),
                            decoded.resource(),
                            Permission.Relationship.ANY,
                            decoded.context(),
                            Optional.empty(),
                            trace);
            byte[] original = HybridSdkHttpCodec.bytes(fields, "requestDer", BOUND_1, 1_048_576);
            zeroecho.pki.server.HybridSdkHttpService service = realm.hybridSdkHttp().orElseThrow();
            if (!acceptance) {
                zeroecho.pki.server.HybridSdkHttpService.Challenge challenge =
                        service.challenge(
                                request,
                                envelope,
                                original,
                                HybridSdkHttpCodec.bytes(fields, "clientNonce", 32, 32));
                return new HttpResponses.Response(
                        200,
                        HybridSdkHttpCodec.challenge(
                                challenge.intentId(), challenge.primary(), challenge.target()));
            }
            Duration timeout = configuration.execution().defaultDeadline();
            if (timeout.compareTo(configuration.execution().maximumDeadline()) > 0) {
                timeout = configuration.execution().maximumDeadline();
            }
            if (timeout.compareTo(Duration.ofSeconds(120)) > 0) {
                timeout = Duration.ofSeconds(120);
            }
            zeroecho.pki.server.AdministrativeRequest accepted =
                    service.accept(
                            HybridSdkHttpCodec.text(fields, "intentId"),
                            HybridSdkHttpCodec.text(fields, "sdkRequestId"),
                            request,
                            envelope,
                            original,
                            HybridSdkHttpCodec.bytes(fields, "primaryProof", BOUND_1, 104),
                            HybridSdkHttpCodec.bytes(fields, "alternativeProof", 4_627, 4_627),
                            timeout);
            HttpResponses.Response response =
                    HttpResponses.administrativeAccepted(
                            trace,
                            realm.administrativeRequests()
                                    .projection(accepted, actor.endClientPrincipalId(), true));
            return new HttpResponses.Response(
                    response.statusCode(),
                    response.body(),
                    false,
                    Optional.empty(),
                    Optional.of("/admin/v1/requests/" + accepted.requestId()));
        }

        private HttpResponses.Response requestCommand(
                HttpsExchange exchange,
                String path,
                String trace,
                PkiServerAuthenticationResult.Authenticated actor,
                String viewer,
                zeroecho.pki.server.AdministrativeRequestCoordinator coordinator)
                throws IOException {

            if (path.startsWith("/admin/v1/requests/")) {
                if (!requireMethod(exchange, TEXT_GET)) {
                    return method(trace, "administrative.request.inspect");
                }
                String id = path.substring("/admin/v1/requests/".length());
                if (!id.matches("[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}")) {
                    return notFound(trace);
                }
                return HttpResponses.success(
                        trace,
                        "administrative.request.inspect",
                        coordinator.projection(coordinator.inspect(id, viewer), viewer, true));
            }
            if (requireMethod(exchange, TEXT_GET)) {
                return listRequests(exchange, trace, viewer, coordinator);
            }
            if (!requireMethod(exchange, "POST")) {
                return method(trace, ADMIN_REQUEST_ACTION);
            }
            if (exchange.getRequestURI().getRawQuery() != null) {
                throw new IllegalArgumentException("Submit query is forbidden");
            }
            if (!"application/json"
                    .equalsIgnoreCase(exchange.getRequestHeaders().getFirst(TEXT_CONTENT_TYPE))) {
                return HttpResponses.failure(
                        415,
                        trace,
                        ADMIN_REQUEST_ACTION,
                        TEXT_VALIDATION_FAILURE,
                        TEXT_UNSUPPORTED_MEDIA_TYPE,
                        TEXT_UNSUPPORTED_MEDIA_TYPE,
                        false,
                        false);
            }
            byte[] document =
                    new OperationExecution()
                            .body(
                                    exchange.getRequestBody(),
                                    exchange.getRequestHeaders().getFirst("Content-Length"));
            Map<String, PkiOperationValue> fields =
                    ((PkiOperationValue.ObjectValue)
                                    StrictJson.parse(
                                            document,
                                            Math.min(
                                                    262_144,
                                                    configuration.listener().maximumBodyBytes())))
                            .fields();
            if (!fields.keySet()
                            .containsAll(
                                    Set.of("version", "requestId", TEXT_OPERATION, "arguments"))
                    || !Set.of(
                                    "version",
                                    "requestId",
                                    TEXT_OPERATION,
                                    "arguments",
                                    "authorityId",
                                    "deadline")
                            .containsAll(fields.keySet())) {
                throw new IllegalArgumentException("Invalid request fields");
            }
            String id = ((PkiOperationValue.Text) fields.get("requestId")).value();
            String operation = ((PkiOperationValue.Text) fields.get(TEXT_OPERATION)).value();
            Map<String, PkiOperationValue> envelope = new LinkedHashMap<>(fields);
            envelope.remove("requestId");
            envelope.remove(TEXT_OPERATION);
            PkiOperationValue.ObjectValue encoded = new PkiOperationValue.ObjectValue(envelope);
            HttpOperationCodec.Decoded decoded =
                    HttpOperationCodec.decode(
                            operation,
                            StrictJson.encode(encoded),
                            262_144,
                            configuration.realm().realmId(),
                            realm.gateway()::descriptor);
            Duration duration =
                    decoded.requestedDeadline().orElse(configuration.execution().defaultDeadline());
            if (duration.compareTo(configuration.execution().maximumDeadline()) > 0) {
                duration = configuration.execution().maximumDeadline();
            }
            if (duration.compareTo(Duration.ofSeconds(120)) > 0) {
                duration = Duration.ofSeconds(120);
            }
            ServerOperationGateway.Request request =
                    new ServerOperationGateway.Request(
                            configuration.realm().realmId(),
                            viewer,
                            actor.mode(),
                            actor.transportPrincipalId(),
                            actor.credentialEvidence(),
                            decoded.operation(),
                            decoded.resource(),
                            Permission.Relationship.ANY,
                            decoded.context(),
                            Optional.empty(),
                            trace);
            zeroecho.pki.server.AdministrativeRequest accepted =
                    coordinator.submit(id, request, encoded, duration);
            return "ocsp.responder.issue-certificate".equals(accepted.operation())
                    ? HttpResponses.administrativeProvisioningAccepted(
                            trace,
                            coordinator.projection(accepted, viewer, true),
                            accepted.requestId())
                    : HttpResponses.administrativeAccepted(
                            trace, coordinator.projection(accepted, viewer, true));
        }

        private HttpResponses.Response listRequests(
                HttpsExchange exchange,
                String trace,
                String viewer,
                zeroecho.pki.server.AdministrativeRequestCoordinator coordinator) {
            Map<String, String> query = new java.util.HashMap<>();
            String raw = exchange.getRequestURI().getRawQuery();
            if (raw != null) {
                for (String pair : raw.split("&")) {
                    String[] item = pair.split("=", BOUND_2);
                    if (item.length != BOUND_2
                            || !Set.of("offset", "limit", "state", "requester", TEXT_OPERATION)
                                    .contains(item[0])
                            || query.putIfAbsent(
                                            item[0],
                                            java.net.URLDecoder.decode(
                                                    item[BOUND_1], StandardCharsets.UTF_8))
                                    != null) {
                        throw new IllegalArgumentException("Invalid request page");
                    }
                }
            }
            int offset = Integer.parseInt(query.getOrDefault("offset", "0"));
            int limit = Integer.parseInt(query.getOrDefault("limit", "25"));
            zeroecho.pki.server.ServerControlStore.Page<zeroecho.pki.server.AdministrativeRequest>
                    page =
                            coordinator.list(
                                    viewer,
                                    offset,
                                    limit,
                                    Optional.ofNullable(query.get("state"))
                                            .map(
                                                    zeroecho.pki.server.AdministrativeRequest.State
                                                            ::valueOf),
                                    Optional.ofNullable(query.get("requester")),
                                    Optional.ofNullable(query.get(TEXT_OPERATION)));
            Map<String, PkiOperationValue> result = new LinkedHashMap<>();
            result.put(
                    "requests",
                    new PkiOperationValue.ListValue(
                            page.values().stream()
                                    .map(
                                            v ->
                                                    (PkiOperationValue)
                                                            coordinator.projection(
                                                                    v, viewer, false))
                                    .toList()));
            result.put("nextOffset", new PkiOperationValue.IntegerValue(page.nextOffset()));
            result.put("hasMore", new PkiOperationValue.BooleanValue(page.hasMore()));
            return HttpResponses.success(
                    trace,
                    "administrative.request.list",
                    new PkiOperationValue.ObjectValue(result));
        }
}

    /** Executes an already authenticated ordinary gateway request under the original deadline. */
    private final class OperationExecution {
        @SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.DoNotUseThreads"})
        private HttpResponses.Response execute(
                HttpsExchange exchange,
                String requestId,
                PkiServerAuthenticationResult.Authenticated authenticated,
                String operationId)
                throws IOException {
            String principalId = authenticated.endClientPrincipalId();
            String contentType = exchange.getRequestHeaders().getFirst(TEXT_CONTENT_TYPE);
            if (contentType == null
                    || !("application/json".equalsIgnoreCase(contentType)
                            || JSON.equalsIgnoreCase(contentType))) {
                return HttpResponses.failure(
                        415,
                        requestId,
                        operationId,
                        TEXT_VALIDATION_FAILURE,
                        TEXT_UNSUPPORTED_MEDIA_TYPE,
                        TEXT_UNSUPPORTED_MEDIA_TYPE,
                        false,
                        false);
            }
            byte[] body;
            try {
                body =
                        body(
                                exchange.getRequestBody(),
                                exchange.getRequestHeaders().getFirst("Content-Length"));
            } catch (IllegalArgumentException invalid) {
                return HttpResponses.failure(
                        413,
                        requestId,
                        operationId,
                        TEXT_VALIDATION_FAILURE,
                        "REQUEST_BODY_REJECTED",
                        "REQUEST_BODY_REJECTED",
                        false,
                        false);
            }
            HttpOperationCodec.Decoded decoded;
            try {
                decoded =
                        HttpOperationCodec.decode(
                                operationId,
                                body,
                                configuration.listener().maximumBodyBytes(),
                                configuration.realm().realmId(),
                                realm.gateway()::descriptor);
            } catch (SecurityException unavailable) {
                return notFound(requestId);
            } catch (HttpOperationCodec.LegacyBackupLimitException oversized) {
                return HttpResponses.failure(
                        413,
                        requestId,
                        operationId,
                        TEXT_VALIDATION_FAILURE,
                        "BACKUP_LEGACY_LIMIT_USE_STREAMING",
                        "BACKUP_LEGACY_LIMIT_USE_STREAMING",
                        false,
                        false);
            } catch (IllegalArgumentException invalid) {
                return HttpResponses.failure(
                        400,
                        requestId,
                        operationId,
                        TEXT_VALIDATION_FAILURE,
                        "INVALID_OPERATION_REQUEST",
                        "INVALID_OPERATION_REQUEST",
                        false,
                        false);
            }
            Duration effective =
                    decoded.requestedDeadline().orElse(configuration.execution().defaultDeadline());
            if (effective.compareTo(configuration.execution().maximumDeadline()) > 0) {
                effective = configuration.execution().maximumDeadline();
            }
            Instant deadline;
            try {
                deadline = clock.instant().plus(effective);
            } catch (RuntimeException overflow) {
                return HttpResponses.failure(
                        400,
                        requestId,
                        operationId,
                        TEXT_VALIDATION_FAILURE,
                        "INVALID_DEADLINE",
                        "INVALID_DEADLINE",
                        false,
                        false);
            }
            if (!clock.instant().isBefore(deadline)) {
                return deadline(requestId, operationId);
            }
            ServerRuntime.Submitted<ServerOperationGateway.Outcome> submitted;
            try {
                submitted =
                        runtime.submit(
                                cancellation -> {
                                    if (!clock.instant().isBefore(deadline)) {
                                        throw new DeadlineExceeded();
                                    }
                                    ServerOperationGateway.Request gateway =
                                            new ServerOperationGateway.Request(
                                                    configuration.realm().realmId(),
                                                    principalId,
                                                    authenticated.mode(),
                                                    authenticated.transportPrincipalId(),
                                                    authenticated.credentialEvidence(),
                                                    decoded.operation(),
                                                    decoded.resource(),
                                                    Permission.Relationship.ANY,
                                                    decoded.context(),
                                                    decoded.approvalId(),
                                                    requestId);
                                    return TransportCancellationGateway.executeAdmin(
                                            realm.gateway(), gateway, cancellation);
                                });
            } catch (RejectedExecutionException overloaded) {
                realm.auditTransport(
                        "REQUEST_OVERLOAD",
                        principalId,
                        Map.of(TEXT_REQUEST, requestId, TEXT_OPERATION, operationId));
                return HttpResponses.failure(
                        429,
                        requestId,
                        operationId,
                        TEXT_OVERLOADED,
                        TEXT_OPERATION_QUEUE_FULL,
                        TEXT_OPERATION_QUEUE_FULL,
                        false,
                        false);
            }
            try {
                long remaining =
                        Math.max(1L, Duration.between(clock.instant(), deadline).toMillis());
                ServerOperationGateway.Outcome outcome =
                        submitted.future().get(remaining, TimeUnit.MILLISECONDS);
                realm.auditTransport(
                        "REQUEST_COMPLETED",
                        principalId,
                        Map.of(TEXT_REQUEST, requestId, TEXT_OPERATION, operationId));
                return HttpResponses.gateway(requestId, operationId, outcome);
            } catch (TimeoutException timeout) {
                submitted.cancellation().cancel();
                submitted.future().cancel(true);
                realm.auditTransport(
                        "REQUEST_DEADLINE",
                        principalId,
                        Map.of(TEXT_REQUEST, requestId, TEXT_OPERATION, operationId));
                return deadline(requestId, operationId);
            } catch (InterruptedException interrupted) {
                submitted.cancellation().cancel();
                submitted.future().cancel(true);
                Thread.currentThread().interrupt();
                return deadline(requestId, operationId);
            } catch (ExecutionException failure) {
                if (failure.getCause() instanceof DeadlineExceeded) {
                    return deadline(requestId, operationId);
                }
                return HttpResponses.failure(
                        500,
                        requestId,
                        operationId,
                        "INTERNAL_FAILURE",
                        TEXT_SAFE_INTERNAL_FAILURE,
                        TEXT_SAFE_INTERNAL_FAILURE,
                        false,
                        false);
            } finally {
                submitted.finish();
            }
        }

        @SuppressWarnings({"PMD.PreserveStackTrace"})
        private byte[] body(InputStream input, String contentLength) throws IOException {
            int maximum = configuration.listener().maximumBodyBytes();
            if (contentLength != null) {
                try {
                    long length = Long.parseLong(contentLength);
                    if (length < 0 || length > maximum) {
                        throw new IllegalArgumentException("Body is oversized");
                    }
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
                if (total > maximum) {
                    throw new IllegalArgumentException("Body is oversized");
                }
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        }
    }

    /** Distinguishes no route match from a matched streaming exchange that already owns its response. */
    private record HandledRoute(boolean matched, HttpResponses.Response response) {}

    private HandledRoute specializedRoute(
            HttpsExchange exchange,
            String path,
            String requestId,
            PkiServerAuthenticationResult.Authenticated authenticated,
            String principalId)
            throws IOException {
        if ("/admin/v1/hybrid-sdk/v1".equals(path) || path.startsWith("/admin/v1/hybrid-sdk/v1/")) {
            return new HandledRoute(
                    true,
                    new RetainedRequestRoutes()
                            .hybridSdk(exchange, path, requestId, authenticated));
        }
        if ("/admin/v1/backup/upload".equals(path) || "/admin/v1/backup/download".equals(path)) {
            return new HandledRoute(
                    true,
                    new AdminBackupRoute(configuration, realm, runtime)
                            .respond(exchange, path.endsWith("/upload"), requestId, authenticated));
        }
        if ("/admin/v1/requests".equals(path) || path.startsWith("/admin/v1/requests/")) {
            return new HandledRoute(
                    true,
                    new RetainedRequestRoutes()
                            .administrativeRequests(exchange, path, requestId, authenticated));
        }
        if (path.startsWith("/admin/v1/status-artifacts/")) {
            return new HandledRoute(true, statusArtifact(exchange, requestId, principalId));
        }
        if (path.startsWith("/admin/v1/certificate-artifacts/")
                || path.startsWith("/admin/v1/authorities/") && path.endsWith("/certificate")) {
            return new HandledRoute(true, certificateArtifact(exchange, requestId, principalId));
        }
        return new HandledRoute(false, null);
    }

    /** Projects the existing authorized realm, operation catalog and generated schema views. */
    private final class DiscoveryRoutes {
        private HttpResponses.Response schema() {
            try {
                byte[] json =
                        GenerateOperationSchema.serialize(
                                zeroecho.pki.server.schema.OperationDescriptorCatalog.current()
                                        .entries()
                                        .stream()
                                        .filter(
                                                zeroecho.pki.server.schema
                                                                .OperationDescriptorCatalog.Entry
                                                        ::available)
                                        .filter(
                                                entry ->
                                                        realm.gateway()
                                                                .operationAvailable(
                                                                        entry.parameters()
                                                                                .operationId()))
                                        .map(
                                                zeroecho.pki.server.schema
                                                                .OperationDescriptorCatalog.Entry
                                                        ::parameters)
                                        .toList());
                return new HttpResponses.Response(200, json);
            } catch (IOException failure) {
                throw new IllegalStateException("Schema serialization failed", failure);
            }
        }

        private HttpResponses.Response realm(
                HttpsExchange exchange, String requestId, String principalId) {
            if (!requireMethod(exchange, TEXT_GET)) {
                return method(requestId, "realm.inspect");
            }
            Permission.Resource resource =
                    new Permission.Resource(
                            Permission.ResourceType.REALM,
                            new Permission.Scope(
                                    configuration.realm().realmId(),
                                    Optional.empty(),
                                    Optional.empty(),
                                    Optional.empty()),
                            Optional.empty(),
                            Optional.empty());
            AuthorizationEngine.Decision decision =
                    realm.gateway()
                            .authorizeControl(
                                    principalId,
                                    Permission.Action.REALM_READ,
                                    resource,
                                    Permission.Context.empty(),
                                    requestId);
            if (!decision.allowed()) {
                return denied(requestId, "realm.inspect");
            }
            Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
            fields.put(
                    "realmId", new PkiOperationValue.Text(configuration.realm().realmId().value()));
            fields.put(
                    "displayName", new PkiOperationValue.Text(configuration.realm().displayName()));
            fields.put(
                    "authorityExposure",
                    new PkiOperationValue.Text(
                            configuration.realm().authorityExposure().mode().name()));
            fields.put(
                    "authorityCreationPermitted",
                    new PkiOperationValue.BooleanValue(
                            configuration
                                    .realm()
                                    .authorityExposure()
                                    .authorityCreationPermitted()));
            Map<String, PkiOperationValue> publicRepository = new LinkedHashMap<>();
            Optional<String> publicPath =
                    configuration
                            .publicListener()
                            .flatMap(PkiServerConfiguration.PublicListener::consoleBasePath);
            publicRepository.put(
                    "available", new PkiOperationValue.BooleanValue(publicPath.isPresent()));
            publicRepository.put(
                    "authorityListAvailable",
                    new PkiOperationValue.BooleanValue(
                            publicPath.isPresent()
                                    && configuration
                                            .publicListener()
                                            .map(
                                                    PkiServerConfiguration.PublicListener
                                                            ::authorityListExposed)
                                            .orElse(false)));
            publicPath.ifPresent(
                    value -> publicRepository.put("basePath", new PkiOperationValue.Text(value)));
            fields.put("publicRepository", new PkiOperationValue.ObjectValue(publicRepository));
            return HttpResponses.success(
                    requestId, "realm.inspect", new PkiOperationValue.ObjectValue(fields));
        }

        private HttpResponses.Response operations(
                HttpsExchange exchange, String requestId, String principalId) {
            if (!requireMethod(exchange, TEXT_GET)) {
                return method(requestId, "operation.list");
            }
            List<PkiOperationValue> values =
                    realm.gateway().discoverableOperations(principalId).stream()
                            .map(DiscoveryRoutes::descriptorValue)
                            .map(PkiOperationValue.class::cast)
                            .toList();
            Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
            fields.put("count", new PkiOperationValue.IntegerValue(values.size()));
            fields.put("operations", new PkiOperationValue.ListValue(values));
            return HttpResponses.success(
                    requestId, "operation.list", new PkiOperationValue.ObjectValue(fields));
        }

        private HttpResponses.Response descriptor(
                String requestId, OperationSecurityDescriptors.Descriptor value) {
            return HttpResponses.success(requestId, "operation.inspect", descriptorValue(value));
        }

        private static PkiOperationValue.ObjectValue descriptorValue(
                OperationSecurityDescriptors.Descriptor value) {
            Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
            fields.put(TEXT_OPERATION, new PkiOperationValue.Text(value.operationId()));
            fields.put("family", new PkiOperationValue.Text(value.family().name()));
            fields.put("mutating", new PkiOperationValue.BooleanValue(value.mutating()));
            fields.put(
                    "durableRequest",
                    new PkiOperationValue.BooleanValue(
                            zeroecho.pki.server.AdministrativeRequestCoordinator.supports(value)));
            fields.put("resourceType", new PkiOperationValue.Text(value.resourceType().name()));
            fields.put("approval", new PkiOperationValue.Text(value.approvalCategory().name()));
            fields.put("dataView", new PkiOperationValue.Text(value.dataView().name()));
            fields.put("permissionAction", new PkiOperationValue.Text(value.action().name()));
            fields.put("available", new PkiOperationValue.BooleanValue(value.available()));
            zeroecho.pki.server.schema.OperationDescriptorCatalog.current()
                    .find(value.operationId())
                    .ifPresent(
                            entry -> {
                                fields.put(
                                        "scope",
                                        new PkiOperationValue.Text(
                                                entry.presentation().transport().scope()));
                                fields.put(
                                        "authorityFrom",
                                        new PkiOperationValue.Text(
                                                entry.presentation().transport().authorityFrom()));
                                List<PkiOperationValue> parameters =
                                        entry.parameters().fields().stream()
                                                .map(
                                                        field -> {
                                                            Map<String, PkiOperationValue>
                                                                    parameter =
                                                                            new LinkedHashMap<>();
                                                            parameter.put(
                                                                    "name",
                                                                    new PkiOperationValue.Text(
                                                                            field.name()));
                                                            parameter.put(
                                                                    "type",
                                                                    new PkiOperationValue.Text(
                                                                            field.type()
                                                                                    .name()
                                                                                    .toLowerCase(
                                                                                            java
                                                                                                    .util
                                                                                                    .Locale
                                                                                                    .ROOT)
                                                                                    .replace(
                                                                                            '_',
                                                                                            '-')));
                                                            parameter.put(
                                                                    "required",
                                                                    new PkiOperationValue
                                                                            .BooleanValue(
                                                                            field.required()));
                                                            parameter.put(
                                                                    "choices",
                                                                    new PkiOperationValue.ListValue(
                                                                            field.choices().stream()
                                                                                    .map(
                                                                                            PkiOperationValue
                                                                                                            .Text
                                                                                                    ::new)
                                                                                    .map(
                                                                                            PkiOperationValue
                                                                                                            .class
                                                                                                    ::cast)
                                                                                    .toList()));
                                                            return (PkiOperationValue)
                                                                    new PkiOperationValue
                                                                            .ObjectValue(parameter);
                                                        })
                                                .toList();
                                fields.put("fields", new PkiOperationValue.ListValue(parameters));
                            });
            return new PkiOperationValue.ObjectValue(fields);
        }

        private HttpResponses.Response health(
                HttpExchange exchange, String path, String requestId) {
            if (TEXT_HEALTH_LIVE.equals(path)) {
                return requireMethod(exchange, TEXT_GET)
                        ? HttpResponses.minimal(200, requestId, "health.live", "LIVE")
                        : method(requestId, "health.live");
            } else if (TEXT_HEALTH_READY.equals(path)) {
                boolean isReady = ready.getAsBoolean();
                return requireMethod(exchange, TEXT_GET)
                        ? HttpResponses.minimal(
                                isReady ? 200 : 503,
                                requestId,
                                "health.ready",
                                isReady ? "READY" : "NOT_READY")
                        : method(requestId, "health.ready");
            }
            return null;
        }
    }

    private HttpResponses.Response signingRoute(
            HttpsExchange exchange, String path, String requestId, String principalId) {
        String signingPrefix = "/admin/v1/signing-operations/";
        if (path.startsWith(signingPrefix) && path.length() > signingPrefix.length()) {
            if (!requireMethod(exchange, TEXT_GET)) {
                return method(requestId, "signing.operation");
            }
            String signingId = path.substring(signingPrefix.length());
            if (signingId.length() > 512 || signingId.indexOf('/') >= 0) {
                return HttpResponses.signingNotFound(requestId);
            }
            return signingOperation(requestId, principalId, signingId);
        }
        return null;
    }
}
