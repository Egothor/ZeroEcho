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
import com.sun.net.httpserver.HttpsExchange;

import zeroecho.pki.server.Permission;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.ServerOperationGateway;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.spi.PkiServerAuthenticationResult;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Handles administrative backup transfers with admission, authorization and channel ownership
 * checks.
 */
final class AdminBackupRoute {
    private static final String TEXT_VALIDATION_FAILURE = "VALIDATION_FAILURE";
    private static final String TEXT_OVERLOADED = "OVERLOADED";
    private static final String TEXT_CONTENT_TYPE = "Content-Type";
    private static final String TEXT_UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE";
    private static final String TEXT_OPERATION = "operation";
    private static final int BOUND_2048 = 2_048;
    private static final int BOUND_2 = 2;
    private static final String TEXT_OPERATION_QUEUE_FULL = "OPERATION_QUEUE_FULL";
    private static final int BOUND_1 = 1;
    private final PkiServerConfiguration configuration;
    private final ServerRealmContext realm;
    private final ServerRuntime runtime;

    /* default */ AdminBackupRoute(
            PkiServerConfiguration configuration, ServerRealmContext realm, ServerRuntime runtime) {
        this.configuration = configuration;
        this.realm = realm;
        this.runtime = runtime;
    }

    // The standalone transport owns bounded task executors and preserves cancellation/thread
    // lifetime.
    @SuppressWarnings({"PMD.DoNotUseThreads"})
    /* default */ HttpResponses.Response respond(
            HttpsExchange exchange,
            boolean upload,
            String requestId,
            PkiServerAuthenticationResult.Authenticated authenticated)
            throws IOException {
        Optional<zeroecho.pki.server.BackupTransferConfiguration> configured =
                realm.backupTransferConfiguration();
        if (configured.isEmpty()) {
            return notFound(requestId);
        }
        String operationId = upload ? "backup.stream.upload" : "backup.stream.download";
        if (!requireMethod(exchange, "POST")) {
            return method(requestId, operationId);
        }
        String origin = singleHeader(exchange, "Origin");
        if (origin != null
                ? !origin.equals(configured.orElseThrow().browserOrigin().toString())
                : !"1".equals(singleHeader(exchange, "X-ZeroEcho-Transfer"))) {
            return denied(requestId, operationId);
        }
        String contentType = singleHeader(exchange, TEXT_CONTENT_TYPE);
        if (!(upload ? "application/zip" : "application/x-www-form-urlencoded")
                .equalsIgnoreCase(contentType)) {
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
        ServerRuntime.Submitted<ServerOperationGateway.Outcome> submitted;
        try {
            submitted =
                    runtime.submit(
                            cancellation -> {
                                try {
                                    String handle;
                                    Optional<String> approval;
                                    if (upload) {
                                        handle = singleHeader(exchange, "X-ZeroEcho-Artifact");
                                        approval =
                                                Optional.ofNullable(
                                                        singleHeader(
                                                                exchange, "X-ZeroEcho-Approval"));
                                    } else {
                                        byte[] form = exchange.getRequestBody().readNBytes(2_049);
                                        if (form.length > BOUND_2048) {
                                            throw new IllegalArgumentException(
                                                    "Backup form too large");
                                        }
                                        Map<String, String> fields = new java.util.HashMap<>();
                                        for (String entry :
                                                new String(form, StandardCharsets.UTF_8)
                                                        .split("&")) {
                                            String[] pair = entry.split("=", BOUND_2);
                                            if (pair.length != BOUND_2) {
                                                throw new IllegalArgumentException(
                                                        "Invalid backup form");
                                            }
                                            String name =
                                                    java.net.URLDecoder.decode(
                                                            pair[0], StandardCharsets.UTF_8);
                                            String value =
                                                    java.net.URLDecoder.decode(
                                                            pair[BOUND_1], StandardCharsets.UTF_8);
                                            if (!Set.of("artifactHandle", "approvalId")
                                                            .contains(name)
                                                    || fields.putIfAbsent(name, value) != null) {
                                                throw new IllegalArgumentException(
                                                        "Invalid backup form field");
                                            }
                                        }
                                        handle = fields.get("artifactHandle");
                                        approval =
                                                Optional.ofNullable(fields.get("approvalId"))
                                                        .filter(value -> !value.isEmpty());
                                    }
                                    zeroecho.pki.server.ServerControlOperation.BackupArtifactCommand
                                            command =
                                                    new zeroecho.pki.server.ServerControlOperation
                                                            .BackupArtifactCommand(
                                                            upload
                                                                    ? zeroecho.pki.server
                                                                            .ServerControlOperation
                                                                            .BackupArtifactCommand
                                                                            .Action.UPLOAD
                                                                    : zeroecho.pki.server
                                                                            .ServerControlOperation
                                                                            .BackupArtifactCommand
                                                                            .Action.DOWNLOAD,
                                                            handle,
                                                            Optional.empty());
                                    Permission.Resource resource =
                                            new Permission.Resource(
                                                    Permission.ResourceType.BACKUP,
                                                    new Permission.Scope(
                                                            configuration.realm().realmId(),
                                                            Optional.empty(),
                                                            Optional.empty(),
                                                            Optional.empty()),
                                                    Optional.empty(),
                                                    Optional.empty());
                                    ServerOperationGateway.Request request =
                                            new ServerOperationGateway.Request(
                                                    configuration.realm().realmId(),
                                                    authenticated.endClientPrincipalId(),
                                                    authenticated.mode(),
                                                    authenticated.transportPrincipalId(),
                                                    authenticated.credentialEvidence(),
                                                    new zeroecho.pki.server.AdministrativeOperation
                                                            .Control(command),
                                                    resource,
                                                    Permission.Relationship.ANY,
                                                    new Permission.Context(
                                                            Optional.empty(),
                                                            approval.isPresent(),
                                                            false,
                                                            Map.of()),
                                                    approval,
                                                    requestId);
                                    return realm.gateway()
                                            .executeBackupTransfer(
                                                    request,
                                                    cancellation,
                                                    new zeroecho.pki.server
                                                            .BackupTransferChannel() {
                                                        @Override
                                                        public InputStream input() {
                                                            return exchange.getRequestBody();
                                                        }

                                                        @Override
                                                        public java.io.OutputStream output(
                                                                long length) throws IOException {
                                                            exchange.getResponseHeaders()
                                                                    .set(
                                                                            TEXT_CONTENT_TYPE,
                                                                            "application/zip");
                                                            exchange.getResponseHeaders()
                                                                    .set(
                                                                            "Content-Disposition",
                                                                            "attachment; filename=\"zeroecho-backup.zip\"");
                                                            exchange.getResponseHeaders()
                                                                    .set(
                                                                            "Cache-Control",
                                                                            "no-store");
                                                            exchange.getResponseHeaders()
                                                                    .set(
                                                                            "Referrer-Policy",
                                                                            "no-referrer");
                                                            exchange.getResponseHeaders()
                                                                    .set(
                                                                            "X-Content-Type-Options",
                                                                            "nosniff");
                                                            exchange.getResponseHeaders()
                                                                    .set(
                                                                            RequestIds.HEADER,
                                                                            requestId);
                                                            exchange.sendResponseHeaders(
                                                                    200, length);
                                                            return exchange.getResponseBody();
                                                        }
                                                    });
                                } catch (IOException failure) {
                                    throw new java.io.UncheckedIOException(
                                            "Backup transfer failed", failure);
                                }
                            });
        } catch (RejectedExecutionException overloaded) {
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
            ServerOperationGateway.Outcome outcome =
                    submitted
                            .future()
                            .get(
                                    configured.orElseThrow().transferTimeout().toMillis(),
                                    TimeUnit.MILLISECONDS);
            return exchange.getResponseCode() == -BOUND_1
                    ? HttpResponses.gateway(requestId, operationId, outcome)
                    : null;
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
            return exchange.getResponseCode() == -BOUND_1
                    ? HttpResponses.failure(
                            400,
                            requestId,
                            operationId,
                            TEXT_VALIDATION_FAILURE,
                            "BACKUP_TRANSFER_REJECTED",
                            "BACKUP_TRANSFER_REJECTED",
                            false,
                            false)
                    : null;
        } finally {
            submitted.finish();
        }
    }

    private static String singleHeader(HttpExchange exchange, String name) {
        List<String> values = exchange.getRequestHeaders().get(name);
        if (values == null) {
            return null;
        }
        if (values.size() != BOUND_1) {
            throw new IllegalArgumentException("Duplicate transfer header");
        }
        return values.getFirst();
    }

    private static boolean requireMethod(HttpExchange exchange, String expected) {
        return expected.equals(exchange.getRequestMethod());
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

    private static HttpResponses.Response denied(String requestId, String operation) {
        return HttpResponses.failure(
                403,
                requestId,
                operation,
                "DENIED",
                "AUTHORIZATION_DENIED",
                "AUTHORIZATION_DENIED",
                false,
                false);
    }
}
