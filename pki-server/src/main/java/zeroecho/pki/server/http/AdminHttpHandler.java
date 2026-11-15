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
import java.util.Set;
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
import zeroecho.pki.server.jfr.AdminRequestEvent;
import zeroecho.pki.server.schema.GenerateOperationSchema;
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
        if (exchange.getRequestURI().getPath().startsWith("/admin/")) realm.recordAdminRequest();
        AdminRequestEvent jfrEvent = new AdminRequestEvent();
        jfrEvent.operationId = "";
        jfrEvent.principalId = "";
        jfrEvent.begin();
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
            if (uri.getRawFragment() != null || uri.getRawQuery() != null && !"/admin/v1/requests".equals(uri.getPath())
                    && !uri.getRawPath().matches("/admin/v1/(?:certificate|status)-artifacts/[^/]+/content")) throw malformed(requestId, "route");
            String path = uri.getPath();
            if ((path.startsWith("/admin/v1/hybrid-sdk") || uri.getRawPath().startsWith("/admin/v1/hybrid-sdk"))
                    && !uri.getRawPath().equals(path)) throw malformed(requestId, "route");
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
        if (jfrEvent.shouldCommit()) {
            jfrEvent.httpStatus = response == null ? exchange.getResponseCode() : response.statusCode();
            jfrEvent.authorized = admitted;
            jfrEvent.commit();
        }
        if (response == null) exchange.close();
        else send(exchange, requestId, response);
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
        if (path.equals("/admin/v1/hybrid-sdk/v1") || path.startsWith("/admin/v1/hybrid-sdk/v1/")) {
            return hybridSdk(exchange, path, requestId, authenticated);
        }
        if ("/admin/v1/backup/upload".equals(path) || "/admin/v1/backup/download".equals(path)) {
            return backupTransfer(exchange, path.endsWith("/upload"), requestId, authenticated);
        }
        if (path.equals("/admin/v1/requests") || path.startsWith("/admin/v1/requests/")) return administrativeRequests(exchange,path,requestId,authenticated);
        if(path.startsWith("/admin/v1/status-artifacts/"))return statusArtifact(exchange,requestId,principalId);
        if(path.startsWith("/admin/v1/certificate-artifacts/")||path.startsWith("/admin/v1/authorities/")&&path.endsWith("/certificate"))return certificateArtifact(exchange,requestId,principalId);
        if ("/admin/v1/realm".equals(path)) return realm(exchange, requestId, principalId);
        if ("/admin/v1/schema".equals(path)) return schema(requestId);
        if ("/admin/v1/operations".equals(path)) return operations(exchange, requestId, principalId);
        String signingPrefix = "/admin/v1/signing-operations/";
        if (path.startsWith(signingPrefix) && path.length() > signingPrefix.length()) {
            if (!requireMethod(exchange, "GET")) return method(requestId, "signing.operation");
            String signingId = path.substring(signingPrefix.length());
            if (signingId.length() > 512 || signingId.indexOf('/') >= 0) {
                return HttpResponses.signingNotFound(requestId);
            }
            return signingOperation(requestId, principalId, signingId);
        }
        String prefix = "/admin/v1/operations/";
        if (!path.startsWith(prefix) || path.length() == prefix.length()) return notFound(requestId);
        String operationId = path.substring(prefix.length());
        if (!operationId.matches("[a-z][a-z0-9.-]{2,127}")) return notFound(requestId);
        // Legacy unavailable operations still pass through authorization and approval.
        // Their descriptor remains hidden from GET/list/schema discovery.
        if (requireMethod(exchange, "POST") && zeroecho.pki.server.schema.OperationDescriptorCatalog.current()
                .find(operationId).filter(entry -> !entry.available()).isPresent()) {
            return execute(exchange, requestId, authenticated, operationId);
        }
        Optional<OperationSecurityDescriptors.Descriptor> descriptor = realm.gateway()
                .discoverableOperations(principalId).stream()
                .filter(item -> item.operationId().equals(operationId)).findFirst();
        if (descriptor.isEmpty()) return notFound(requestId);
        if (requireMethod(exchange, "GET")) return descriptor(requestId, descriptor.orElseThrow());
        if (!requireMethod(exchange, "POST")) return method(requestId, operationId);
        return execute(exchange, requestId, authenticated, operationId);
    }

    private HttpResponses.Response hybridSdk(HttpsExchange exchange, String path, String trace,
            PkiServerAuthenticationResult.Authenticated actor) throws IOException {
        String base = "/admin/v1/hybrid-sdk/v1";
        if (configuration.listener().hybridSdk().isEmpty() || realm.hybridSdkHttp().isEmpty()) return notFound(trace);
        if (path.equals(base)) {
            if (!requireMethod(exchange, "GET")) return method(trace, "hybrid-sdk.capability");
            return new HttpResponses.Response(200, HybridSdkHttpCodec.capability(base,
                    java.util.List.of("credential.issue", "credential.renew", "credential.reissue", "credential.replace"),
                    configuration.listener().hybridSdk().orElseThrow().canonicalOrigin(), configuration.listener().maximumBodyBytes()));
        }
        if (!path.equals(base + "/challenge") && !path.equals(base + "/accept")) return notFound(trace);
        if (!requireMethod(exchange, "POST")) return method(trace, "hybrid-sdk");
        if (!HybridSdkHttpCodec.MEDIA_TYPE.equalsIgnoreCase(exchange.getRequestHeaders().getFirst("Content-Type"))) {
            return HttpResponses.failure(415, trace, "hybrid-sdk", "VALIDATION_FAILURE", "UNSUPPORTED_MEDIA_TYPE", "UNSUPPORTED_MEDIA_TYPE", false, false);
        }
        try {
            boolean acceptance = path.endsWith("/accept");
            var fields = HybridSdkHttpCodec.parse(body(exchange.getRequestBody(), exchange.getRequestHeaders().getFirst("Content-Length")),
                    configuration.listener().maximumBodyBytes(), acceptance, Set.of("operationId", "arguments", "requestDer"));
            String operation = HybridSdkHttpCodec.text(fields, "operationId");
            if (!Set.of("credential.issue", "credential.renew", "credential.reissue", "credential.replace").contains(operation)) {
                throw new IllegalArgumentException("Unsupported SDK operation");
            }
            if (!(fields.get("arguments") instanceof PkiOperationValue.ObjectValue arguments)) throw new IllegalArgumentException("SDK arguments required");
            var envelopeFields = new LinkedHashMap<String, PkiOperationValue>();
            envelopeFields.put("version", new PkiOperationValue.IntegerValue(1)); envelopeFields.put("arguments", arguments);
            // Resolve the existing authorization scope; the SDK wire adds no authority override.
            PkiOperationValue authority;
            if (operation.equals("credential.issue")) authority = arguments.fields().get("issuerCaId");
            else {
                String name = operation.equals("credential.replace") ? "existingCredentialId" : "credentialId";
                if (!(arguments.fields().get(name) instanceof PkiOperationValue.Text id)) throw new IllegalArgumentException("SDK predecessor required");
                var scope = realm.session().resourceScopes().credentialScope(new zeroecho.pki.api.PkiId(id.value()))
                        .orElseThrow(() -> new IllegalArgumentException("SDK predecessor unavailable"));
                authority = new PkiOperationValue.Text(scope.authorityId().value());
            }
            if (authority == null) throw new IllegalArgumentException("SDK issuer required");
            envelopeFields.put("authorityId", authority);
            var envelope = new PkiOperationValue.ObjectValue(envelopeFields);
            var decoded = HttpOperationCodec.decode(operation, StrictJson.encode(envelope), 262144,
                    configuration.realm().realmId(), realm.gateway()::descriptor);
            var request = new ServerOperationGateway.Request(configuration.realm().realmId(), actor.endClientPrincipalId(),
                    actor.mode(), actor.transportPrincipalId(), actor.credentialEvidence(), decoded.operation(), decoded.resource(),
                    Permission.Relationship.ANY, decoded.context(), Optional.empty(), trace);
            byte[] original = HybridSdkHttpCodec.bytes(fields, "requestDer", 1, 1_048_576);
            var service = realm.hybridSdkHttp().orElseThrow();
            if (!acceptance) {
                var challenge = service.challenge(request, envelope, original, HybridSdkHttpCodec.bytes(fields, "clientNonce", 32, 32));
                return new HttpResponses.Response(200, HybridSdkHttpCodec.challenge(challenge.intentId(), challenge.primary(), challenge.target()));
            }
            Duration timeout = configuration.execution().defaultDeadline();
            if (timeout.compareTo(configuration.execution().maximumDeadline()) > 0) timeout = configuration.execution().maximumDeadline();
            if (timeout.compareTo(Duration.ofSeconds(120)) > 0) timeout = Duration.ofSeconds(120);
            var accepted = service.accept(HybridSdkHttpCodec.text(fields, "intentId"), HybridSdkHttpCodec.text(fields, "sdkRequestId"),
                    request, envelope, original, HybridSdkHttpCodec.bytes(fields, "primaryProof", 1, 104),
                    HybridSdkHttpCodec.bytes(fields, "alternativeProof", 4627, 4627), timeout);
            var response = HttpResponses.administrativeAccepted(trace,
                    realm.administrativeRequests().projection(accepted, actor.endClientPrincipalId(), true));
            return new HttpResponses.Response(response.statusCode(), response.body(), false, Optional.empty(),
                    Optional.of("/admin/v1/requests/" + accepted.requestId()));
        } catch (zeroecho.pki.server.AdministrativeRequestCoordinator.Conflict conflict) {
            return HttpResponses.failure(409, trace, "hybrid-sdk", "CONFLICT", "SDK_INTENT_CONFLICT", "SDK_INTENT_CONFLICT", false, false);
        } catch (zeroecho.pki.server.AdministrativeRequestCoordinator.Capacity full) {
            return HttpResponses.failure(429, trace, "hybrid-sdk", "OVERLOADED", "SDK_CAPACITY", "SDK_CAPACITY", false, false);
        } catch (SecurityException denied) { return notFound(trace); }
        catch (IllegalArgumentException | zeroecho.pki.api.PkiException invalid) {
            return HttpResponses.failure(400, trace, "hybrid-sdk", "VALIDATION_FAILURE", "SDK_REQUEST_INVALID", "SDK_REQUEST_INVALID", false, false);
        }
    }

    private HttpResponses.Response administrativeRequests(HttpsExchange exchange,String path,String trace,
            PkiServerAuthenticationResult.Authenticated actor) throws IOException {
        String viewer=actor.endClientPrincipalId();
        var coordinator=realm.administrativeRequests();
        try {
            if (path.startsWith("/admin/v1/requests/")) {
                if (!requireMethod(exchange,"GET")) return method(trace,"administrative.request.inspect");
                String id=path.substring("/admin/v1/requests/".length());
                if(!id.matches("[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}")) return notFound(trace);
                return HttpResponses.success(trace,"administrative.request.inspect",coordinator.projection(coordinator.inspect(id,viewer),viewer,true));
            }
            if(requireMethod(exchange,"GET")) {
                Map<String,String> query=new java.util.HashMap<>();
                String raw=exchange.getRequestURI().getRawQuery();
                if(raw!=null) for(String pair:raw.split("&")) {
                    String[] item=pair.split("=",2);
                    if(item.length!=2 || !Set.of("offset","limit","state","requester","operation").contains(item[0]) || query.putIfAbsent(item[0],java.net.URLDecoder.decode(item[1],java.nio.charset.StandardCharsets.UTF_8))!=null) throw new IllegalArgumentException("Invalid request page");
                }
                int offset=Integer.parseInt(query.getOrDefault("offset","0")),limit=Integer.parseInt(query.getOrDefault("limit","25"));
                var page=coordinator.list(viewer,offset,limit,Optional.ofNullable(query.get("state")).map(zeroecho.pki.server.AdministrativeRequest.State::valueOf),Optional.ofNullable(query.get("requester")),Optional.ofNullable(query.get("operation")));
                Map<String,PkiOperationValue> result=new LinkedHashMap<>();
                result.put("requests",new PkiOperationValue.ListValue(page.values().stream().map(v->(PkiOperationValue)coordinator.projection(v,viewer,false)).toList()));
                result.put("nextOffset",new PkiOperationValue.IntegerValue(page.nextOffset()));result.put("hasMore",new PkiOperationValue.BooleanValue(page.hasMore()));
                return HttpResponses.success(trace,"administrative.request.list",new PkiOperationValue.ObjectValue(result));
            }
            if(!requireMethod(exchange,"POST")) return method(trace,"administrative.request.submit");
            if(exchange.getRequestURI().getRawQuery()!=null) throw new IllegalArgumentException("Submit query is forbidden");
            if(!"application/json".equalsIgnoreCase(exchange.getRequestHeaders().getFirst("Content-Type"))) return HttpResponses.failure(415,trace,"administrative.request.submit","VALIDATION_FAILURE","UNSUPPORTED_MEDIA_TYPE","UNSUPPORTED_MEDIA_TYPE",false,false);
            byte[] document=body(exchange.getRequestBody(),exchange.getRequestHeaders().getFirst("Content-Length"));
            var fields=((PkiOperationValue.ObjectValue)StrictJson.parse(document,Math.min(262144,configuration.listener().maximumBodyBytes()))).fields();
            if(!fields.keySet().containsAll(Set.of("version","requestId","operation","arguments"))
                    || !Set.of("version","requestId","operation","arguments","authorityId","deadline").containsAll(fields.keySet())) throw new IllegalArgumentException("Invalid request fields");
            String id=((PkiOperationValue.Text)fields.get("requestId")).value();String operation=((PkiOperationValue.Text)fields.get("operation")).value();
            Map<String,PkiOperationValue> envelope=new LinkedHashMap<>(fields);envelope.remove("requestId");envelope.remove("operation");
            var encoded=new PkiOperationValue.ObjectValue(envelope);
            var decoded=HttpOperationCodec.decode(operation,StrictJson.encode(encoded),262144,configuration.realm().realmId(),realm.gateway()::descriptor);
            Duration duration=decoded.requestedDeadline().orElse(configuration.execution().defaultDeadline());
            if(duration.compareTo(configuration.execution().maximumDeadline())>0) duration=configuration.execution().maximumDeadline();
            if(duration.compareTo(Duration.ofSeconds(120))>0) duration=Duration.ofSeconds(120);
            var request=new ServerOperationGateway.Request(configuration.realm().realmId(),viewer,actor.mode(),actor.transportPrincipalId(),actor.credentialEvidence(),
                    decoded.operation(),decoded.resource(),Permission.Relationship.ANY,decoded.context(),Optional.empty(),trace);
            var accepted=coordinator.submit(id,request,encoded,duration);
            return accepted.operation().equals("ocsp.responder.issue-certificate")
                    ?HttpResponses.administrativeProvisioningAccepted(trace,coordinator.projection(accepted,viewer,true),accepted.requestId())
                    :HttpResponses.administrativeAccepted(trace,coordinator.projection(accepted,viewer,true));
        } catch(zeroecho.pki.server.AdministrativeRequestCoordinator.ProvisioningConflict conflict) {
            return HttpResponses.administrativeProvisioningConflict(trace,conflict.canonicalRequestId());
        } catch(zeroecho.pki.server.AdministrativeRequestCoordinator.Conflict conflict) {
            return HttpResponses.failure(409,trace,"administrative.request.submit","CONFLICT","REQUEST_ID_CONFLICT","REQUEST_ID_CONFLICT",false,false);
        } catch(zeroecho.pki.server.AdministrativeRequestCoordinator.Capacity full) {
            return HttpResponses.failure(429,trace,"administrative.request.submit","OVERLOADED","ADMINISTRATIVE_REQUEST_CAPACITY","ADMINISTRATIVE_REQUEST_CAPACITY",false,false);
        } catch(zeroecho.pki.server.AdministrativeRequestCoordinator.ValidationFailure invalid) {
            return HttpResponses.failure(400,trace,"administrative.request.submit","VALIDATION_FAILURE",invalid.code(),invalid.code(),false,false);
        } catch(zeroecho.pki.api.PkiException invalid) {
            String code=invalid.failureReason().filter(zeroecho.pki.api.PkiFailureReason::externalSafe).map(Enum::name).orElse("PKI_POLICY_REJECTED");
            return HttpResponses.failure(400,trace,"administrative.request.submit","VALIDATION_FAILURE",code,code,false,false);
        } catch(SecurityException unavailable) { return notFound(trace); }
        catch(IllegalArgumentException | ClassCastException invalid) {
            return HttpResponses.failure(400,trace,"administrative.request.submit","VALIDATION_FAILURE","INVALID_ADMINISTRATIVE_REQUEST","INVALID_ADMINISTRATIVE_REQUEST",false,false);
        }
    }

    /* default */ HttpResponses.Response signingOperation(String requestId, String principalId, String signingId) {
        try {
            zeroecho.pki.api.SemanticSigningService service = realm.session().semanticSigning().orElseThrow();
            zeroecho.pki.api.signing.SemanticSigningOperation snapshot =
                    service.find(new zeroecho.pki.api.PkiId(signingId)).orElseThrow();
            zeroecho.pki.api.signing.SemanticSigningScope scope = snapshot.scope();
            PollScope poll = pollScope(scope);
            Permission.Resource resource = new Permission.Resource(poll.type(),
                    new Permission.Scope(configuration.realm().realmId(), poll.authority(), Optional.empty(),
                            poll.profile()), poll.object(), Optional.empty());
            AuthorizationEngine.Decision decision = realm.gateway().authorizeControl(principalId,
                    poll.action(), resource, Permission.Context.empty(), requestId);
            if (!decision.allowed()) return HttpResponses.signingNotFound(requestId);
            return HttpResponses.signingOperation(requestId, signingOutcome(snapshot));
        } catch (IllegalArgumentException | java.util.NoSuchElementException unavailable) {
            return HttpResponses.signingNotFound(requestId);
        }
    }

    private record PollScope(Permission.Action action, Permission.ResourceType type,
            Optional<zeroecho.pki.api.PkiId> authority, Optional<String> profile,
            Optional<zeroecho.pki.api.PkiId> object) { }

    private static PollScope pollScope(zeroecho.pki.api.signing.SemanticSigningScope scope) {
        return switch (scope.kind()) {
            case ISSUANCE -> new PollScope(Permission.Action.CERTIFICATE_ISSUE,
                    Permission.ResourceType.CERTIFICATE, scope.authorityId(), scope.profileId(), Optional.empty());
            case STATUS -> new PollScope(Permission.Action.CRL_GENERATE,
                    Permission.ResourceType.STATUS_OBJECT, scope.authorityId(), Optional.empty(), Optional.empty());
            case KEY_PROOF -> throw new IllegalArgumentException("Signing operation is not exposed");
            case CA -> switch (scope.operation()) {
                case "CREATE_ROOT" -> new PollScope(Permission.Action.AUTHORITY_CREATE,
                        Permission.ResourceType.AUTHORITY, Optional.empty(), Optional.empty(), Optional.empty());
                case "CREATE_INTERMEDIATE" -> new PollScope(Permission.Action.AUTHORITY_CREATE,
                        Permission.ResourceType.AUTHORITY, scope.authorityId(), scope.profileId(),
                        scope.subjectAuthorityId());
                case "ISSUE_INTERMEDIATE" -> new PollScope(Permission.Action.ISSUER_CREATE,
                        Permission.ResourceType.ISSUER, scope.subjectAuthorityId(), scope.profileId(), Optional.empty());
                case "ROLLOVER_ROOT" -> new PollScope(Permission.Action.AUTHORITY_READ,
                        Permission.ResourceType.AUTHORITY, scope.authorityId(), scope.profileId(), scope.authorityId());
                case "ROLLOVER_INTERMEDIATE" -> new PollScope(Permission.Action.AUTHORITY_READ,
                        Permission.ResourceType.AUTHORITY, scope.subjectAuthorityId(), scope.profileId(),
                        scope.subjectAuthorityId());
                default -> throw new IllegalArgumentException("Signing operation is not exposed");
            };
        };
    }

    private zeroecho.pki.application.PkiOperationOutcome signingOutcome(
            zeroecho.pki.api.signing.SemanticSigningOperation snapshot) {
        String name = "signing.operation";
        return switch (snapshot.state()) {
            case SIGNING, PUBLISHING -> new zeroecho.pki.application.PkiOperationOutcome.Pending(
                    name, snapshot.submissionId().id());
            case FAILED -> new zeroecho.pki.application.PkiOperationOutcome.Failed(name,
                    zeroecho.pki.application.PkiOperationFailure.POLICY_REJECTION,
                    snapshot.detailCode().orElse("SIGNING_FAILED"));
            case EXPIRED -> new zeroecho.pki.application.PkiOperationOutcome.Failed(name,
                    zeroecho.pki.application.PkiOperationFailure.CANCELLED, "SIGNING_EXPIRED");
            case COMPLETED -> new zeroecho.pki.application.PkiOperationOutcome.Completed(
                    realm.session().signingCommands().orElseThrow().completedResult(snapshot));
        };
    }

    // A null response means the binary exchange was committed or closed by its
    // deadline; the caller must not attempt a second JSON response.
    private HttpResponses.Response backupTransfer(HttpsExchange exchange, boolean upload, String requestId,
            PkiServerAuthenticationResult.Authenticated authenticated) throws IOException {
        Optional<zeroecho.pki.server.BackupTransferConfiguration> configured = realm.backupTransferConfiguration();
        if (configured.isEmpty()) return notFound(requestId);
        String operationId = upload ? "backup.stream.upload" : "backup.stream.download";
        if (!requireMethod(exchange, "POST")) return method(requestId, operationId);
        String origin = singleHeader(exchange, "Origin");
        if (origin != null ? !origin.equals(configured.orElseThrow().browserOrigin().toString())
                : !"1".equals(singleHeader(exchange, "X-ZeroEcho-Transfer"))) {
            return denied(requestId, operationId);
        }
        String contentType = singleHeader(exchange, "Content-Type");
        if (!(upload ? "application/zip" : "application/x-www-form-urlencoded").equalsIgnoreCase(contentType)) {
            return HttpResponses.failure(415, requestId, operationId, "VALIDATION_FAILURE",
                    "UNSUPPORTED_MEDIA_TYPE", "UNSUPPORTED_MEDIA_TYPE", false, false);
        }
        ServerRuntime.Submitted<ServerOperationGateway.Outcome> submitted;
        try {
            submitted = runtime.submit(cancellation -> {
                try {
                    String handle;
                    Optional<String> approval;
                    if (upload) {
                        handle = singleHeader(exchange, "X-ZeroEcho-Artifact");
                        approval = Optional.ofNullable(singleHeader(exchange, "X-ZeroEcho-Approval"));
                    } else {
                        byte[] form = exchange.getRequestBody().readNBytes(2049);
                        if (form.length > 2048) throw new IllegalArgumentException("Backup form too large");
                        Map<String, String> fields = new java.util.HashMap<>();
                        for (String entry : new String(form, StandardCharsets.UTF_8).split("&")) {
                            String[] pair = entry.split("=", 2);
                            if (pair.length != 2) throw new IllegalArgumentException("Invalid backup form");
                            String name = java.net.URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
                            String value = java.net.URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
                            if (!Set.of("artifactHandle", "approvalId").contains(name) || fields.putIfAbsent(name, value) != null) {
                                throw new IllegalArgumentException("Invalid backup form field");
                            }
                        }
                        handle = fields.get("artifactHandle");
                        approval = Optional.ofNullable(fields.get("approvalId")).filter(value -> !value.isEmpty());
                    }
                    zeroecho.pki.server.ServerControlOperation.BackupArtifactCommand command =
                            new zeroecho.pki.server.ServerControlOperation.BackupArtifactCommand(
                                    upload ? zeroecho.pki.server.ServerControlOperation.BackupArtifactCommand.Action.UPLOAD
                                            : zeroecho.pki.server.ServerControlOperation.BackupArtifactCommand.Action.DOWNLOAD,
                                    handle, Optional.empty());
                    Permission.Resource resource = new Permission.Resource(Permission.ResourceType.BACKUP,
                            new Permission.Scope(configuration.realm().realmId(), Optional.empty(), Optional.empty(), Optional.empty()),
                            Optional.empty(), Optional.empty());
                    ServerOperationGateway.Request request = new ServerOperationGateway.Request(configuration.realm().realmId(),
                            authenticated.endClientPrincipalId(), authenticated.mode(), authenticated.transportPrincipalId(),
                            authenticated.credentialEvidence(),
                            new zeroecho.pki.server.AdministrativeOperation.Control(command), resource, Permission.Relationship.ANY,
                            new Permission.Context(Optional.empty(), approval.isPresent(), false, Map.of()), approval, requestId);
                    return realm.gateway().executeBackupTransfer(request, cancellation, new zeroecho.pki.server.BackupTransferChannel() {
                        @Override public InputStream input() { return exchange.getRequestBody(); }
                        @Override public java.io.OutputStream output(long length) throws IOException {
                            exchange.getResponseHeaders().set("Content-Type", "application/zip");
                            exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"zeroecho-backup.zip\"");
                            exchange.getResponseHeaders().set("Cache-Control", "no-store");
                            exchange.getResponseHeaders().set("Referrer-Policy", "no-referrer");
                            exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
                            exchange.getResponseHeaders().set(RequestIds.HEADER, requestId);
                            exchange.sendResponseHeaders(200, length);
                            return exchange.getResponseBody();
                        }
                    });
                } catch (IOException failure) {
                    throw new java.io.UncheckedIOException("Backup transfer failed", failure);
                }
            });
        } catch (RejectedExecutionException overloaded) {
            return HttpResponses.failure(429, requestId, operationId, "OVERLOADED", "OPERATION_QUEUE_FULL",
                    "OPERATION_QUEUE_FULL", false, false);
        }
        try {
            ServerOperationGateway.Outcome outcome = submitted.future().get(
                    configured.orElseThrow().transferTimeout().toMillis(), TimeUnit.MILLISECONDS);
            return exchange.getResponseCode() == -1 ? HttpResponses.gateway(requestId, operationId, outcome) : null;
        } catch (TimeoutException timeout) {
            submitted.cancellation().cancel();
            submitted.future().cancel(true);
            // TLS close may wait for the writer's lock. Interrupt blocked channel
            // I/O first so exchange closure cannot deadlock the deadline thread.
            exchange.close();
            return null;
        } catch (InterruptedException interrupted) {
            submitted.cancellation().cancel();
            submitted.future().cancel(true);
            exchange.close();
            Thread.currentThread().interrupt();
            return null;
        } catch (ExecutionException failure) {
            return exchange.getResponseCode() == -1 ? HttpResponses.failure(400, requestId, operationId,
                    "VALIDATION_FAILURE", "BACKUP_TRANSFER_REJECTED", "BACKUP_TRANSFER_REJECTED", false, false) : null;
        } finally {
            submitted.finish();
        }
    }

    private static String singleHeader(HttpExchange exchange, String name) {
        List<String> values = exchange.getRequestHeaders().get(name);
        if (values == null) return null;
        if (values.size() != 1) throw new IllegalArgumentException("Duplicate transfer header");
        return values.getFirst();
    }

    private HttpResponses.Response schema(String requestId) {
        try {
            byte[] json = GenerateOperationSchema.serialize(zeroecho.pki.server.schema.OperationDescriptorCatalog.current()
                    .entries().stream().filter(zeroecho.pki.server.schema.OperationDescriptorCatalog.Entry::available)
                    .filter(entry -> realm.gateway().operationAvailable(entry.parameters().operationId()))
                    .map(zeroecho.pki.server.schema.OperationDescriptorCatalog.Entry::parameters).toList());
            return new HttpResponses.Response(200, json);
        } catch (java.io.IOException failure) {
            throw new IllegalStateException("Schema serialization failed", failure);
        }
    }

    private HttpResponses.Response statusArtifact(HttpsExchange exchange,String trace,String principal) {
        if(!requireMethod(exchange,"GET"))return method(trace,"status.artifact.inspect");
        ServerRuntime.Submitted<HttpResponses.Response> submitted;
        try {submitted=runtime.submit(cancellation -> new StatusArtifactHttp(realm).respond(exchange,principal,trace,cancellation));}
        catch(RejectedExecutionException overloaded){return HttpResponses.failure(429,trace,"status.artifact.inspect","OVERLOADED","OPERATION_QUEUE_FULL","OPERATION_QUEUE_FULL",false,false);}
        try {return submitted.future().get(configuration.execution().maximumDeadline().toMillis(),TimeUnit.MILLISECONDS);}
        catch(TimeoutException timeout){submitted.cancellation().cancel();submitted.future().cancel(true);exchange.close();return null;}
        catch(InterruptedException interrupted){submitted.cancellation().cancel();submitted.future().cancel(true);exchange.close();Thread.currentThread().interrupt();return null;}
        catch(ExecutionException failed){if(exchange.getResponseCode()!=-1){exchange.close();return null;}return HttpResponses.failure(500,trace,"status.artifact.inspect","INTERNAL_FAILURE","SAFE_INTERNAL_FAILURE","SAFE_INTERNAL_FAILURE",false,false);}
        finally{submitted.finish();}
    }

    private HttpResponses.Response certificateArtifact(HttpsExchange exchange,String trace,String principal) {
        if(!requireMethod(exchange,"GET"))return method(trace,"certificate.artifact.inspect");
        ServerRuntime.Submitted<HttpResponses.Response> submitted;
        try {
            submitted=runtime.submit(cancellation -> new CertificateArtifactHttp(realm).respond(
                    exchange.getRequestURI().getRawPath(),exchange.getRequestURI().getRawQuery(),principal,trace,cancellation));
        } catch(RejectedExecutionException overloaded) {
            return HttpResponses.failure(429,trace,"certificate.artifact.inspect","OVERLOADED","OPERATION_QUEUE_FULL","OPERATION_QUEUE_FULL",false,false);
        }
        try {
            return submitted.future().get(configuration.execution().defaultDeadline().toMillis(),TimeUnit.MILLISECONDS);
        } catch(TimeoutException timeout) {
            submitted.cancellation().cancel();submitted.future().cancel(true);return deadline(trace,"certificate.artifact.inspect");
        } catch(InterruptedException interrupted) {
            submitted.cancellation().cancel();submitted.future().cancel(true);Thread.currentThread().interrupt();return deadline(trace,"certificate.artifact.inspect");
        } catch(ExecutionException failed) {
            return HttpResponses.failure(500,trace,"certificate.artifact.inspect","INTERNAL_FAILURE","SAFE_INTERNAL_FAILURE","SAFE_INTERNAL_FAILURE",false,false);
        } finally {submitted.finish();}
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
        Map<String,PkiOperationValue> publicRepository = new LinkedHashMap<>();
        Optional<String> publicPath=configuration.publicListener().flatMap(PkiServerConfiguration.PublicListener::consoleBasePath);
        publicRepository.put("available",new PkiOperationValue.BooleanValue(publicPath.isPresent()));
        publicRepository.put("authorityListAvailable",new PkiOperationValue.BooleanValue(publicPath.isPresent()
                &&configuration.publicListener().map(PkiServerConfiguration.PublicListener::authorityListExposed).orElse(false)));
        publicPath.ifPresent(value -> publicRepository.put("basePath",new PkiOperationValue.Text(value)));
        fields.put("publicRepository",new PkiOperationValue.ObjectValue(publicRepository));
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
        } catch (HttpOperationCodec.LegacyBackupLimitException oversized) {
            return HttpResponses.failure(413, requestId, operationId, "VALIDATION_FAILURE",
                    "BACKUP_LEGACY_LIMIT_USE_STREAMING", "BACKUP_LEGACY_LIMIT_USE_STREAMING", false, false);
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
                        authenticated.transportPrincipalId(), authenticated.credentialEvidence(), decoded.operation(), decoded.resource(),
                        Permission.Relationship.ANY, decoded.context(), decoded.approvalId(), requestId);
                return TransportCancellationGateway.executeAdmin(realm.gateway(), gateway, cancellation);
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
        fields.put("durableRequest", new PkiOperationValue.BooleanValue(zeroecho.pki.server.AdministrativeRequestCoordinator.supports(value)));
        fields.put("resourceType", new PkiOperationValue.Text(value.resourceType().name()));
        fields.put("approval", new PkiOperationValue.Text(value.approvalCategory().name()));
        fields.put("dataView", new PkiOperationValue.Text(value.dataView().name()));
        fields.put("permissionAction", new PkiOperationValue.Text(value.action().name()));
        fields.put("available", new PkiOperationValue.BooleanValue(value.available()));
        zeroecho.pki.server.schema.OperationDescriptorCatalog.current().find(value.operationId()).ifPresent(entry -> {
            fields.put("scope", new PkiOperationValue.Text(entry.presentation().transport().scope()));
            fields.put("authorityFrom", new PkiOperationValue.Text(entry.presentation().transport().authorityFrom()));
            List<PkiOperationValue> parameters = entry.parameters().fields().stream().map(field -> {
                Map<String, PkiOperationValue> parameter = new LinkedHashMap<>();
                parameter.put("name", new PkiOperationValue.Text(field.name()));
                parameter.put("type", new PkiOperationValue.Text(field.type().name().toLowerCase(java.util.Locale.ROOT).replace('_', '-')));
                parameter.put("required", new PkiOperationValue.BooleanValue(field.required()));
                parameter.put("choices", new PkiOperationValue.ListValue(field.choices().stream()
                        .map(PkiOperationValue.Text::new).map(PkiOperationValue.class::cast).toList()));
                return (PkiOperationValue) new PkiOperationValue.ObjectValue(parameter);
            }).toList();
            fields.put("fields", new PkiOperationValue.ListValue(parameters));
        });
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
        exchange.getResponseHeaders().set("Content-Type", response.contentType());
        response.attachmentFileName().ifPresent(value -> exchange.getResponseHeaders().set("Content-Disposition","attachment; filename=\""+value+"\""));
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        if (response.oneTimeSensitive()) {
            exchange.getResponseHeaders().set("Pragma", "no-cache");
            exchange.getResponseHeaders().set("Referrer-Policy", "no-referrer");
        }
        exchange.getResponseHeaders().set(RequestIds.HEADER, requestId);
        response.statusLocation().ifPresent(value -> exchange.getResponseHeaders().set("Location", value));
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
