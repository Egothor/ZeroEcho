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
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.file.Path;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.backup.BackupArtifact;
import zeroecho.pki.api.backup.BackupRequest;
import zeroecho.pki.api.backup.BackupVerificationReport;
import zeroecho.pki.api.backup.RestoreRequest;
import zeroecho.pki.api.backup.RestoreReport;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;

/** Verifies permission wiring and round-trip correctness for backup/restore operations. */
class BackupOperationsTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void exportBackupPermissionIsWiredToBackupExportAction() {
        System.out.println("exportBackupPermissionIsWiredToBackupExportAction");
        OperationSecurityDescriptors catalog = new OperationSecurityDescriptors();
        OperationSecurityDescriptors.Descriptor descriptor =
                catalog.require(ServerControlOperation.ExportBackup.NAME);
        assertEquals(Permission.Action.BACKUP_EXPORT, descriptor.action());
        assertEquals(Permission.ResourceType.BACKUP, descriptor.resourceType());
        assertTrue(descriptor.mutating(), "export is a mutating operation");
        assertEquals(OperationSecurityDescriptors.ApprovalCategory.NONE,
                descriptor.approvalCategory(), "export does not require approval");
        System.out.println("...ok");
    }

    @Test
    void verifyBackupPermissionIsWiredToBackupVerifyAction() {
        System.out.println("verifyBackupPermissionIsWiredToBackupVerifyAction");
        OperationSecurityDescriptors catalog = new OperationSecurityDescriptors();
        OperationSecurityDescriptors.Descriptor descriptor =
                catalog.require(ServerControlOperation.VerifyBackup.NAME);
        assertEquals(Permission.Action.BACKUP_VERIFY, descriptor.action());
        assertEquals(Permission.ResourceType.BACKUP, descriptor.resourceType());
        assertFalse(descriptor.mutating(), "verify is a read-only operation");
        assertEquals(OperationSecurityDescriptors.ApprovalCategory.NONE,
                descriptor.approvalCategory(), "verify does not require approval");
        System.out.println("...ok");
    }

    @Test
    void executeRestorePermissionIsWiredToRestoreExecuteAction() {
        System.out.println("executeRestorePermissionIsWiredToRestoreExecuteAction");
        OperationSecurityDescriptors catalog = new OperationSecurityDescriptors();
        OperationSecurityDescriptors.Descriptor descriptor =
                catalog.require(ServerControlOperation.ExecuteRestore.NAME);
        assertEquals(Permission.Action.RESTORE_EXECUTE, descriptor.action());
        assertEquals(Permission.ResourceType.RESTORE, descriptor.resourceType());
        assertTrue(descriptor.mutating(), "restore is a mutating operation");
        assertFalse(descriptor.available());
        assertTrue(zeroecho.pki.server.schema.OperationParameterSchemas.all().stream()
                .anyMatch(spec -> spec.operationId().equals(ServerControlOperation.ExecuteRestore.NAME)));
        assertEquals(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK,
                descriptor.approvalCategory(), "restore requires high-risk approval");
        System.out.println("...ok");
    }

    @Test
    void filesystemStoreSupportsBackup() throws Exception {
        System.out.println("filesystemStoreSupportsBackup");
        Path storeRoot = temporaryDirectory.resolve("store");
        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults())) {
            assertTrue(store.supportsBackup(), "FilesystemPkiStore must support backup");
        }
        System.out.println("...ok");
    }

    @Test
    void roundTripBackupProducesVerifiableArtifact() throws Exception {
        System.out.println("roundTripBackupProducesVerifiableArtifact");
        Path storeRoot = temporaryDirectory.resolve("store");
        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults())) {
            BackupRequest request = new BackupRequest("test-backup", emptyAttributes());

            BackupArtifact artifact = store.createBackup(request);

            assertNotNull(artifact, "artifact must not be null");
            assertNotNull(artifact.backupId(), "backupId must not be null");
            assertNotNull(artifact.payload(), "payload must not be null");
            assertTrue(artifact.payload().bytes().length > 0, "backup payload must be non-empty");

            BackupVerificationReport report = store.verifyBackup(artifact);

            assertTrue(report.valid(), "backup artifact must be structurally valid; issues: " + report.issues());
            assertTrue(report.issues().isEmpty(), "valid artifact must have no issues");
        }
        System.out.println("...ok");
    }

    @Test
    void localLegacyRestoreRejectsInvalidArchivesWithoutChangingStoreOrOutsideFiles() throws Exception {
        Path storeRoot = temporaryDirectory.resolve("store");
        Path staging = temporaryDirectory.resolve("store.restore-staging");
        Files.createDirectories(staging);
        Files.writeString(staging.resolve("sentinel"), "existing staging");
        Path outside = temporaryDirectory.resolve("outside");
        Files.writeString(outside, "outside sentinel");
        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults())) {
            Files.writeString(storeRoot.resolve("sentinel"), "live sentinel");
            BackupArtifact artifact = store.createBackup(new BackupRequest("restore-test", emptyAttributes()));
            Map<Path, byte[]> before = snapshot(temporaryDirectory);
            assertThrows(IllegalArgumentException.class, () -> artifact(new byte[0]));
            for (byte[] payload : List.of(artifact.payload().bytes(), new byte[] { 0, 1, 2 },
                    new byte[] { 'P', 'K', 3, 4 }, zip("../outside"), zip(outside.toString()),
                    zip("../store/sentinel"), zip("VERSION"))) {
                BackupArtifact supplied = artifact(payload);
                RestoreReport rejected = store.restoreBackup(new RestoreRequest(supplied, emptyAttributes()));
                assertFalse(rejected.success());
                assertFalse(rejected.errors().isEmpty());
                Map<Path, byte[]> after = snapshot(temporaryDirectory);
                assertEquals(before.keySet(), after.keySet());
                before.forEach((path, bytes) -> assertArrayEquals(bytes, after.get(path), path.toString()));
            }
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults())) {
            assertTrue(reopened.supportsBackup());
            assertEquals("live sentinel", Files.readString(storeRoot.resolve("sentinel")));
            assertEquals("existing staging", Files.readString(staging.resolve("sentinel")));
            assertEquals("outside sentinel", Files.readString(outside));
        }
    }

    @Test
    void remoteRestoreRetainsAuthorizationAndApprovalButNeverReportsSuccess() throws Exception {
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        PkiServerConfiguration configuration = HttpServerTestSupport.configuration(temporaryDirectory,
                tls.clientCertificate());
        Permission.Scope scope = new Permission.Scope(ServerTestSupport.REALM,
                Optional.empty(), Optional.empty(), Optional.empty());
        try (ServerRealmContext realm = ServerRealmContext.open(configuration.realm(),
                zeroecho.pki.application.PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK,
                HttpServerTestSupport.random())) {
            realm.createPrincipal(ServerTestSupport.principal("administrator"), "system");
            realm.createPrincipal(ServerTestSupport.principal("approver"), "system");
        }
        try (PkiHttpsServer server = PkiHttpsServer.start(configuration,
                zeroecho.pki.application.PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK,
                HttpServerTestSupport.random(), getClass().getClassLoader())) {
            java.net.http.HttpClient client = java.net.http.HttpClient.newBuilder().sslContext(tls.clientContext()).build();
            java.net.URI base = java.net.URI.create("https://localhost:" + server.address().getPort());
            java.net.URI endpoint = base.resolve("/admin/v1/operations/backup.restore");
            Path sentinel = temporaryDirectory.resolve("remote-sentinel");
            Files.writeString(sentinel, "remote sentinel");
            String encoded = java.util.Base64.getEncoder().encodeToString(zip("../remote-sentinel"));
            String body = "{\"version\":1,\"arguments\":{\"backupId\":\"test-backup\",\"payload\":\"" + encoded + "\"}}";
            assertEquals(403, post(client, endpoint, body).statusCode());
            server.realm().grant(ServerTestSupport.grant("restore-grant", "administrator", Permission.Effect.ALLOW,
                    Permission.Action.RESTORE_EXECUTE, Permission.ResourceType.RESTORE, scope,
                    Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED), "system");
            assertEquals(404, get(client, endpoint).statusCode());
            assertFalse(get(client, base.resolve("/admin/v1/operations")).body().contains("backup.restore"));
            assertFalse(get(client, base.resolve("/admin/v1/schema")).body().contains("backup.restore"));
            assertEquals(404, post(client, base.resolve("/admin/v1/operations/unknown.operation"),
                    "{\"version\":1,\"arguments\":{}}").statusCode());
            java.net.http.HttpResponse<String> required = post(client, endpoint, body);
            assertEquals(409, required.statusCode());
            assertTrue(required.body().contains("APPROVAL_REQUIRED"));
            java.util.regex.Matcher commitment = java.util.regex.Pattern.compile(
                    "\"operationCommitment\":\"([a-f0-9]{64})\"").matcher(required.body());
            assertTrue(commitment.find());
            ApprovalService.Policy policy = configuration.realm().approvalPolicies()
                    .get(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK);
            server.realm().approvals().request("restore-approval", "backup.restore", commitment.group(1),
                    scope, "administrator", policy);
            server.realm().approvals().decide("restore-approval", "approver", ApprovalService.Choice.APPROVE, "Reviewed");
            java.net.http.HttpResponse<String> rejected = post(client, endpoint,
                    body.replace("\"version\":1", "\"version\":1,\"approvalId\":\"restore-approval\""));
            assertEquals(422, rejected.statusCode());
            assertTrue(rejected.body().contains("BACKUP_RESTORE_UNAVAILABLE"));
            assertFalse(rejected.body().contains("SUCCEEDED"));
            assertEquals(400, post(client, endpoint, body.replace(encoded, "bad!base64")).statusCode());
            assertEquals("remote sentinel", Files.readString(sentinel));
            assertFalse(Files.exists(temporaryDirectory.resolve("pki-store.restore-staging")));
        }
    }

    private static java.net.http.HttpResponse<String> post(java.net.http.HttpClient client, java.net.URI uri,
            String body) throws Exception {
        return client.send(java.net.http.HttpRequest.newBuilder(uri).header("Content-Type", "application/json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body)).build(),
                java.net.http.HttpResponse.BodyHandlers.ofString());
    }

    private static java.net.http.HttpResponse<String> get(java.net.http.HttpClient client, java.net.URI uri)
            throws Exception {
        return client.send(java.net.http.HttpRequest.newBuilder(uri).GET().build(),
                java.net.http.HttpResponse.BodyHandlers.ofString());
    }

    private static BackupArtifact artifact(byte[] payload) {
        return new BackupArtifact(new zeroecho.pki.api.PkiId("test-backup"),
                new zeroecho.pki.api.EncodedObject(zeroecho.pki.api.Encoding.BINARY, payload));
    }

    private static byte[] zip(String entry) throws Exception {
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        try (java.util.zip.ZipOutputStream zip = new java.util.zip.ZipOutputStream(output)) {
            zip.putNextEntry(new java.util.zip.ZipEntry(entry));
            zip.write(new byte[] { 1, 2, 3 });
            zip.closeEntry();
        }
        return output.toByteArray();
    }

    private static Map<Path, byte[]> snapshot(Path directory) throws Exception {
        Map<Path, byte[]> result = new java.util.HashMap<>();
        try (java.util.stream.Stream<Path> files = Files.walk(directory)) {
            for (Path file : files.filter(Files::isRegularFile).toList()) result.put(file, Files.readAllBytes(file));
        }
        return result;
    }

    @Test
    void verifyRejectsInvalidZipPayload() throws Exception {
        System.out.println("verifyRejectsInvalidZipPayload");
        Path storeRoot = temporaryDirectory.resolve("store");
        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults())) {
            zeroecho.pki.api.EncodedObject badPayload = new zeroecho.pki.api.EncodedObject(
                    zeroecho.pki.api.Encoding.BINARY, new byte[] { 0x00, 0x01, 0x02 });
            BackupArtifact corrupt = new BackupArtifact(new zeroecho.pki.api.PkiId("bad-backup"), badPayload);
            BackupVerificationReport report = store.verifyBackup(corrupt);
            assertFalse(report.valid(), "corrupt artifact must not be valid");
            assertFalse(report.issues().isEmpty(), "corrupt artifact must have issues");
        }
        System.out.println("...ok");
    }

    private static AttributeSet emptyAttributes() {
        return new AttributeSet() {
            @Override public Set<AttributeId> ids() { return Set.of(); }
            @Override public java.util.Optional<AttributeValue> get(AttributeId id) { return java.util.Optional.empty(); }
            @Override public java.util.List<AttributeValue> getAll(AttributeId id) { return java.util.List.of(); }
        };
    }
}
