/*
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
 */
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.server.http.StrictJson;
import zeroecho.pki.server.http.TestTlsProvider;

class BackupTransferHttpTest {
    @TempDir Path directory;

    private void seed(PkiServerConfiguration configuration) throws Exception {
        try (ServerRealmContext realm = ServerRealmContext.open(configuration.realm(),
                PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, HttpServerTestSupport.random())) {
            realm.createPrincipal(ServerTestSupport.principal("administrator"), "system");
            realm.createPrincipal(ServerTestSupport.principal("approver"), "system");
            Permission.Scope scope = new Permission.Scope(ServerTestSupport.REALM, Optional.empty(), Optional.empty(), Optional.empty());
            for (Permission.Action action : new Permission.Action[] {Permission.Action.BACKUP_EXPORT,
                    Permission.Action.BACKUP_VERIFY, Permission.Action.RESTORE_EXECUTE, Permission.Action.REQUEST_SUBMIT}) {
                Permission.ResourceType type = action == Permission.Action.RESTORE_EXECUTE ? Permission.ResourceType.RESTORE
                        : action == Permission.Action.REQUEST_SUBMIT ? Permission.ResourceType.APPROVAL : Permission.ResourceType.BACKUP;
                realm.grant(ServerTestSupport.grant("grant-" + action.name(), "administrator", Permission.Effect.ALLOW,
                        action, type, scope, Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED), "system");
            }
        }
    }

    private BackupTransferConfiguration transfers() throws Exception {
        Path spool = directory.resolve("artifacts");
        Files.createDirectory(spool, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")));
        return new BackupTransferConfiguration(spool, 8 * 1024 * 1024, 16 * 1024 * 1024,
                4, 2, 18L * 1024 * 1024 * 1024, Duration.ofHours(1), Duration.ofSeconds(10),
                URI.create("https://admin.example"));
    }

    private static HttpResponse<String> operation(HttpClient client, String base, String id, String arguments,
            Optional<String> approval) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(base + "/admin/v1/operations/" + id))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(
                        "{\"version\":1," + approval.map(value -> "\"approvalId\":\"" + value + "\",").orElse("")
                                + "\"arguments\":" + arguments + "}")).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static Map<String, PkiOperationValue> value(HttpResponse<String> response) throws Exception {
        assertEquals(200, response.statusCode(), response.body());
        try (tools.jackson.core.JsonParser parser = tools.jackson.core.json.JsonFactory.builder().build().createParser(response.body())) {
            while (parser.nextToken() != null) {
                if (parser.currentToken() == tools.jackson.core.JsonToken.PROPERTY_NAME && "value".equals(parser.currentName())) {
                    assertEquals(tools.jackson.core.JsonToken.START_OBJECT, parser.nextToken());
                    Map<String, PkiOperationValue> fields = new java.util.HashMap<>();
                    while (parser.nextToken() != tools.jackson.core.JsonToken.END_OBJECT) {
                        String name = parser.currentName();
                        tools.jackson.core.JsonToken token = parser.nextToken();
                        fields.put(name, token == tools.jackson.core.JsonToken.VALUE_NUMBER_INT
                                ? new PkiOperationValue.IntegerValue(parser.getLongValue()) : new PkiOperationValue.Text(parser.getString()));
                    }
                    return fields;
                }
            }
        }
        throw new AssertionError("Missing operation value");
    }
    private static String text(Map<String, PkiOperationValue> fields, String key) {
        return ((PkiOperationValue.Text) fields.get(key)).value();
    }
    private static String handleArguments(String handle) { return "{\"artifactHandle\":\"" + handle + "\"}"; }

    @Test void binaryRoutesEnforceOriginSingleUseAndHighRiskApprovalThenReportColdActivation() throws Exception {
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        PkiServerConfiguration configuration = HttpServerTestSupport.configuration(directory, tls.clientCertificate());
        seed(configuration);
        BackupTransferConfiguration transfer = transfers();
        String workflow;
        try (HttpClient client = HttpClient.newBuilder().sslContext(tls.clientContext()).build();
                PkiHttpsServer server = PkiHttpsServer.start(configuration, PkiSessionRuntimeDependencies.none(),
                        ServerTestSupport.CLOCK, HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader(),
                        Optional.of(transfer))) {
            String base = "https://localhost:" + server.address().getPort();
            Map<String, PkiOperationValue> exported = value(operation(client, base, "backup.stream.export",
                    "{\"label\":\"fixture\"}", Optional.empty()));
            String exportHandle = text(exported, "artifactHandle");
            Permission.Scope realmScope = new Permission.Scope(ServerTestSupport.REALM,
                    Optional.empty(), Optional.empty(), Optional.empty());
            server.realm().grant(ServerTestSupport.grant("other-export", "approver", Permission.Effect.ALLOW,
                    Permission.Action.BACKUP_EXPORT, Permission.ResourceType.BACKUP, realmScope,
                    Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED), "system");
            ServerControlOperation.BackupArtifactCommand foreign = new ServerControlOperation.BackupArtifactCommand(
                    ServerControlOperation.BackupArtifactCommand.Action.DOWNLOAD, exportHandle, Optional.empty());
            ServerOperationGateway.Request foreignRequest = new ServerOperationGateway.Request(ServerTestSupport.REALM,
                    "approver", new AdministrativeOperation.Control(foreign),
                    new Permission.Resource(Permission.ResourceType.BACKUP, realmScope, Optional.empty(), Optional.empty()),
                    Permission.Relationship.ANY, Permission.Context.empty(), Optional.empty(), "foreign-artifact");
            java.util.concurrent.atomic.AtomicInteger openedStreams = new java.util.concurrent.atomic.AtomicInteger();
            BackupTransferChannel forbiddenChannel = new BackupTransferChannel() {
                @Override public java.io.InputStream input() { openedStreams.incrementAndGet(); return java.io.InputStream.nullInputStream(); }
                @Override public java.io.OutputStream output(long length) { openedStreams.incrementAndGet(); return java.io.OutputStream.nullOutputStream(); }
            };
            org.junit.jupiter.api.Assertions.assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                    server.realm().gateway().executeBackupTransfer(foreignRequest,
                            zeroecho.core.io.CancellationSignal.NONE, forbiddenChannel));
            assertEquals(0, openedStreams.get());
            HttpRequest.Builder download = HttpRequest.newBuilder(URI.create(base + "/admin/v1/backup/download"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString("artifactHandle=" + exportHandle));
            assertEquals(403, client.send(download.copy().header("Origin", "https://other.example").build(),
                    HttpResponse.BodyHandlers.ofString()).statusCode());
            HttpResponse<byte[]> archive = client.send(download.copy().header("Origin", "https://admin.example").build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(200, archive.statusCode());
            assertEquals(archive.body().length, archive.headers().firstValueAsLong("Content-Length").orElseThrow());
            assertTrue(archive.headers().firstValue("Transfer-Encoding").isEmpty());
            assertEquals("application/zip", archive.headers().firstValue("Content-Type").orElseThrow());
            assertEquals(text(exported, "sha256"), HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(archive.body())));
            assertEquals(403, client.send(download.copy().header("Origin", "https://admin.example").build(),
                    HttpResponse.BodyHandlers.ofString()).statusCode());
            Map<String, PkiOperationValue> interrupted = value(operation(client, base, "backup.stream.export",
                    "{\"label\":\"interrupted-fixture\"}", Optional.empty()));
            String interruptedHandle = text(interrupted, "artifactHandle");
            // Inject an underlying short read after the durable length was committed.
            Files.write(directory.resolve("artifacts").resolve(interruptedHandle + ".zip"), new byte[]{1});
            HttpRequest partial = HttpRequest.newBuilder(URI.create(base + "/admin/v1/backup/download"))
                    .header("Content-Type", "application/x-www-form-urlencoded").header("X-ZeroEcho-Transfer", "1")
                    .POST(HttpRequest.BodyPublishers.ofString("artifactHandle=" + interruptedHandle)).build();
            org.junit.jupiter.api.Assertions.assertThrows(java.io.IOException.class,
                    () -> client.send(partial, HttpResponse.BodyHandlers.ofByteArray()));
            assertEquals(403, client.send(partial, HttpResponse.BodyHandlers.ofString()).statusCode());
            assertFalse(Files.exists(directory.resolve("artifacts").resolve(interruptedHandle + ".zip")));
            String declaration = "{\"backupId\":\"" + text(exported, "backupId") + "\",\"length\":"
                    + archive.body().length + ",\"sha256\":\"" + text(exported, "sha256") + "\"}";
            workflow = text(value(operation(client, base, "backup.stream.reserve", declaration, Optional.empty())), "artifactHandle");
            HttpRequest upload = HttpRequest.newBuilder(URI.create(base + "/admin/v1/backup/upload"))
                    .header("Content-Type", "application/zip").header("X-ZeroEcho-Transfer", "1")
                    .header("X-ZeroEcho-Artifact", workflow).POST(HttpRequest.BodyPublishers.ofByteArray(archive.body())).build();
            assertEquals(200, client.send(upload, HttpResponse.BodyHandlers.ofString()).statusCode());
            value(operation(client, base, "backup.stream.verify", handleArguments(workflow), Optional.empty()));
            assertEquals(409, operation(client, base, "backup.stream.restore", handleArguments(workflow), Optional.empty()).statusCode());
            HttpResponse<String> approval = operation(client, base, "security.approval.request",
                    "{\"approvalId\":\"restore-approval\",\"targetOperation\":\"backup.stream.restore\",\"targetArguments\":"
                            + handleArguments(workflow) + "}", Optional.empty());
            assertEquals(200, approval.statusCode(), approval.body());
            server.realm().approvals().decide("restore-approval", "approver", ApprovalService.Choice.APPROVE, "reviewed fixture");
            String swapped = text(value(operation(client, base, "backup.stream.reserve", declaration, Optional.empty())), "artifactHandle");
            HttpRequest swappedUpload = HttpRequest.newBuilder(URI.create(base + "/admin/v1/backup/upload"))
                    .header("Content-Type", "application/zip").header("X-ZeroEcho-Transfer", "1")
                    .header("X-ZeroEcho-Artifact", swapped).POST(HttpRequest.BodyPublishers.ofByteArray(archive.body())).build();
            assertEquals(200, client.send(swappedUpload, HttpResponse.BodyHandlers.ofString()).statusCode());
            value(operation(client, base, "backup.stream.verify", handleArguments(swapped), Optional.empty()));
            assertTrue(operation(client, base, "backup.stream.restore", handleArguments(swapped),
                    Optional.of("restore-approval")).statusCode() >= 400);
            assertEquals("VERIFIED", text(value(operation(client, base, "backup.stream.status",
                    handleArguments(swapped), Optional.empty())), "state"));
            Map<String, PkiOperationValue> staged = value(operation(client, base, "backup.stream.restore",
                    handleArguments(workflow), Optional.of("restore-approval")));
            assertEquals("STAGED", text(staged, "state"));
            assertFalse(text(staged, "restoreId").isBlank());
        }
        try (HttpClient client = HttpClient.newBuilder().sslContext(tls.clientContext()).build();
                PkiHttpsServer server = PkiHttpsServer.start(configuration, PkiSessionRuntimeDependencies.none(),
                        ServerTestSupport.CLOCK, HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader(),
                        Optional.of(transfer))) {
            String base = "https://localhost:" + server.address().getPort();
            assertEquals("ACTIVATED", text(value(operation(client, base, "backup.stream.status",
                    handleArguments(workflow), Optional.empty())), "state"));
            assertTrue(Files.exists(directory.resolve("artifacts").resolve(workflow + ".meta")));
        }
    }

    @Test void disabledServerHidesStreamingCatalogAndRejectsDirectReservation() throws Exception {
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        PkiServerConfiguration configuration = HttpServerTestSupport.configuration(directory, tls.clientCertificate());
        seed(configuration);
        try (HttpClient client = HttpClient.newBuilder().sslContext(tls.clientContext()).build();
                PkiHttpsServer server = PkiHttpsServer.start(configuration, PkiSessionRuntimeDependencies.none(),
                        ServerTestSupport.CLOCK, HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader())) {
            String base = "https://localhost:" + server.address().getPort();
            HttpResponse<String> schema = client.send(HttpRequest.newBuilder(URI.create(base + "/admin/v1/schema")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, schema.statusCode());
            assertFalse(schema.body().contains("backup.stream."));
            assertEquals(404, operation(client, base, "backup.stream.reserve",
                    "{\"backupId\":\"fixture\",\"length\":1,\"sha256\":\"" + "0".repeat(64) + "\"}", Optional.empty()).statusCode());
        }
    }

    @Test void stalledTlsUploadIsInterruptedAndReleasesArtifactLease() throws Exception {
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        PkiServerConfiguration configuration = HttpServerTestSupport.configuration(directory, tls.clientCertificate());
        seed(configuration);
        BackupTransferConfiguration standard = transfers();
        BackupTransferConfiguration transfer = new BackupTransferConfiguration(standard.directory(),
                standard.maximumArchiveBytes(), standard.maximumRetainedBytes(), 1, 1, standard.maximumWorkspaceBytes(),
                standard.lifetime(), Duration.ofSeconds(1), standard.browserOrigin());
        try (HttpClient client = HttpClient.newBuilder().sslContext(tls.clientContext()).build();
                PkiHttpsServer server = PkiHttpsServer.start(configuration, PkiSessionRuntimeDependencies.none(),
                        ServerTestSupport.CLOCK, HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader(),
                        Optional.of(transfer));
                javax.net.ssl.SSLSocket socket = (javax.net.ssl.SSLSocket) tls.clientContext().getSocketFactory()
                        .createSocket("localhost", server.address().getPort())) {
            String base = "https://localhost:" + server.address().getPort();
            String declaration = "{\"backupId\":\"stalled\",\"length\":1048576,\"sha256\":\"" + "0".repeat(64) + "\"}";
            String handle = text(value(operation(client, base, "backup.stream.reserve", declaration, Optional.empty())), "artifactHandle");
            socket.setSoTimeout(5000);
            socket.startHandshake();
            socket.getOutputStream().write(("POST /admin/v1/backup/upload HTTP/1.1\r\nHost: localhost\r\n"
                    + "Content-Type: application/zip\r\nX-ZeroEcho-Transfer: 1\r\nX-ZeroEcho-Artifact: " + handle
                    + "\r\nContent-Length: 1048576\r\n\r\nx").getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            try { assertEquals(-1, socket.getInputStream().read()); }
            catch (javax.net.ssl.SSLException closed) { /* A TLS abort also proves the deadline closed the exchange. */ }
            // One artifact/job is allowed. Successful reservation requires actual
            // worker exit and cleanup, not merely Future.isCancelled().
            org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
                HttpResponse<String> next;
                do {
                    next = operation(client, base, "backup.stream.reserve", declaration, Optional.empty());
                    if (next.statusCode() != 200) Thread.sleep(20);
                } while (next.statusCode() != 200);
                value(next);
            });
            assertFalse(Files.exists(standard.directory().resolve(handle + ".part")));
        }
    }

    @Test void stalledTlsDownloadReleasesJobBeforeClientCloses() throws Exception {
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        PkiServerConfiguration configuration = HttpServerTestSupport.configuration(directory, tls.clientCertificate());
        seed(configuration);
        try (zeroecho.pki.impl.fs.FilesystemPkiStore store = new zeroecho.pki.impl.fs.FilesystemPkiStore(
                Path.of(configuration.realm().pkiSessionConfiguration().store().require("root")),
                zeroecho.pki.impl.fs.FsPkiStoreOptions.defaults())) {
            java.util.Random random = new java.util.Random(7801);
            for (int index = 0; index < 3; index++) {
                byte[] bytes = new byte[1024 * 1024];
                random.nextBytes(bytes);
                store.putWorkflowState(new zeroecho.pki.api.orch.WorkflowStateRecord(new zeroecho.pki.api.PkiId("large-" + index),
                        "FIXTURE", new zeroecho.pki.api.audit.Principal("TEST", "fixture"),
                        zeroecho.pki.api.orch.OrchestrationDurabilityPolicy.DURABLE_MIN_STATE,
                        ServerTestSupport.CLOCK.instant(), ServerTestSupport.CLOCK.instant(),
                        ServerTestSupport.CLOCK.instant().plusSeconds(3600), zeroecho.pki.api.Encoding.BINARY,
                        Optional.of(new zeroecho.pki.api.EncodedObject(zeroecho.pki.api.Encoding.BINARY, bytes))));
            }
        }
        BackupTransferConfiguration standard = transfers();
        BackupTransferConfiguration transfer = new BackupTransferConfiguration(standard.directory(),
                standard.maximumArchiveBytes(), standard.maximumRetainedBytes(), 1, 1, standard.maximumWorkspaceBytes(),
                standard.lifetime(), Duration.ofSeconds(1), standard.browserOrigin());
        try (HttpClient client = HttpClient.newBuilder().sslContext(tls.clientContext()).build();
                PkiHttpsServer server = PkiHttpsServer.start(configuration, PkiSessionRuntimeDependencies.none(),
                        ServerTestSupport.CLOCK, HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader(),
                        Optional.of(transfer));
                javax.net.ssl.SSLSocket socket = (javax.net.ssl.SSLSocket) tls.clientContext().getSocketFactory().createSocket()) {
            String base = "https://localhost:" + server.address().getPort();
            Map<String, PkiOperationValue> exported = value(operation(client, base, "backup.stream.export",
                    "{\"label\":\"stalled-download\"}", Optional.empty()));
            String handle = text(exported, "artifactHandle");
            assertTrue(((PkiOperationValue.IntegerValue) exported.get("length")).value() > 4 * 1024 * 1024);
            socket.setReceiveBufferSize(1024);
            socket.connect(new java.net.InetSocketAddress("localhost", server.address().getPort()));
            socket.setSoTimeout(5000);
            socket.startHandshake();
            String form = "artifactHandle=" + handle;
            socket.getOutputStream().write(("POST /admin/v1/backup/download HTTP/1.1\r\nHost: localhost\r\n"
                    + "Content-Type: application/x-www-form-urlencoded\r\nX-ZeroEcho-Transfer: 1\r\n"
                    + "Content-Length: " + form.length() + "\r\n\r\n" + form).getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            // Never read or close this client until a new job proves cancellation
            // released the previous lease and its sole artifact slot.
            org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(Duration.ofSeconds(8), () -> {
                HttpResponse<String> next;
                do {
                    next = operation(client, base, "backup.stream.reserve",
                            "{\"backupId\":\"next\",\"length\":1,\"sha256\":\"" + "0".repeat(64) + "\"}", Optional.empty());
                    if (next.statusCode() != 200) Thread.sleep(20);
                } while (next.statusCode() != 200);
                value(next);
            });
            assertFalse(Files.exists(standard.directory().resolve(handle + ".zip")));
        }
    }
}
