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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.api.BackupService;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.backup.BackupRequest;
import zeroecho.pki.api.backup.BackupSource;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;

class BackupTransferServiceTest {
    @TempDir Path directory;
    private static final Instant NOW = Instant.parse("2026-10-06T12:00:00Z");

    @Test void exportPinsExpiredReservationThroughVerificationAndSourceClose() throws Exception {
        java.util.concurrent.atomic.AtomicReference<Instant> instant = new java.util.concurrent.atomic.AtomicReference<>(NOW);
        Clock clock = new Clock() {
            @Override public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(java.time.ZoneId zone) { return this; }
            @Override public Instant instant() { return instant.get(); }
        };
        Path spool = Files.createDirectory(directory.resolve("pinned"), java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")));
        BackupTransferConfiguration config = new BackupTransferConfiguration(spool, 1, 1, 2, 1,
                8589934593L, Duration.ofSeconds(1), Duration.ofSeconds(1), java.net.URI.create("https://admin.example"));
        String digest = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(new byte[]{1}));
        try (BackupArtifactRepository repository = new BackupArtifactRepository(config, "realm", clock, new SecureRandom())) {
            BackupService backup = mock(BackupService.class);
            BackupSource source = mock(BackupSource.class);
            when(source.backupId()).thenReturn(new PkiId("backup"));
            when(source.contentLength()).thenReturn(1L);
            when(source.sha256()).thenReturn(digest);
            when(source.openStream()).thenAnswer(call -> new ByteArrayInputStream(new byte[]{1}));
            when(backup.createBackupSource(any())).thenReturn(source);
            when(backup.prepareBackup(source)).thenAnswer(call -> {
                instant.set(NOW.plusSeconds(2));
                repository.cleanup();
                assertThrows(IOException.class, () -> repository.reserve("owner", BackupArtifactRepository.Purpose.IMPORT,
                        new PkiId("other"), 1, digest));
                zeroecho.pki.api.backup.BackupPreparation verified = mock(zeroecho.pki.api.backup.BackupPreparation.class);
                when(verified.manifestSha256()).thenReturn(digest);
                return verified;
            });
            org.mockito.Mockito.doAnswer(call -> {
                assertThrows(IOException.class, repository::prepare);
                assertThrows(IOException.class, () -> repository.reserve("owner", BackupArtifactRepository.Purpose.IMPORT,
                        new PkiId("other"), 1, digest));
                return null;
            }).when(source).close();
            try (BackupTransferService service = new BackupTransferService(backup, repository, () -> { })) {
                assertThrows(IOException.class, () -> service.export("owner", new BackupRequest("fixture", mock(AttributeSet.class))));
                org.mockito.Mockito.verify(source).close();
                repository.reserve("owner", BackupArtifactRepository.Purpose.IMPORT, new PkiId("other"), 1, digest);
            }
        }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"none", "prior", "unrelated"})
    void crashBeforeDomainDispatchIsRejectedOnlyOnColdServiceOpen(String priorCase) throws Exception {
        Path spool = directory.resolve("before-dispatch");
        Files.createDirectory(spool, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")));
        BackupTransferConfiguration configuration = new BackupTransferConfiguration(spool,
                8 * 1024 * 1024, 16 * 1024 * 1024, 4, 1, 9L * 1024 * 1024 * 1024,
                Duration.ofHours(1), Duration.ofMinutes(1), java.net.URI.create("https://admin.example"));
        String handle;
        PkiId expected = new PkiId("ad52d431-4394-41e1-90d2-7e6ed0f59c44");
        String prior = priorCase.equals("none") ? "" : "349a6ee1-51a6-4a4c-94e5-3948a51cfc2a";
        String digest = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(new byte[]{1}));
        try (BackupArtifactRepository repository = new BackupArtifactRepository(configuration, "realm",
                Clock.fixed(NOW, ZoneOffset.UTC), new SecureRandom())) {
            handle = repository.reserve("owner", BackupArtifactRepository.Purpose.IMPORT,
                    new PkiId("backup"), 1, digest).handle();
            repository.receive("owner", handle, new ByteArrayInputStream(new byte[]{1}));
            try (BackupArtifactRepository.Lease lease = repository.source("owner", handle, BackupArtifactRepository.State.READY, true)) {
                lease.transition(BackupArtifactRepository.State.VERIFIED, digest);
                lease.beginRestore(expected.value(), prior);
            }
        }
        BackupService backup = mock(BackupService.class);
        String latest = priorCase.equals("unrelated") ? "645a65d7-6b4d-4caf-b187-491a3cac6e67" : prior;
        when(backup.latestRestoreIdentity()).thenReturn(latest.isEmpty() ? java.util.Optional.empty()
                : java.util.Optional.of(new zeroecho.pki.api.backup.RestoreIdentity(new PkiId("older"), digest,
                        new zeroecho.pki.api.backup.RestoreStatus(new PkiId(latest),
                                zeroecho.pki.api.backup.RestoreStatus.State.ACTIVATED, java.util.List.of()))));
        try (BackupTransferService service = new BackupTransferService(backup,
                new BackupArtifactRepository(configuration, "realm", Clock.fixed(NOW, ZoneOffset.UTC), new SecureRandom()), () -> { })) {
            if (priorCase.equals("unrelated")) {
                org.mockito.Mockito.verify(backup, org.mockito.Mockito.never()).discardUnpublishedRestore(any(), any(), any());
                assertEquals(BackupArtifactRepository.State.UNCERTAIN, service.status("owner", handle).state());
                assertThrows(IOException.class, () -> service.acknowledge("owner", handle));
            } else {
                org.mockito.Mockito.verify(backup).discardUnpublishedRestore(expected,
                        prior.isEmpty() ? java.util.Optional.empty() : java.util.Optional.of(new PkiId(prior)), digest);
                assertEquals(BackupArtifactRepository.State.REJECTED, service.status("owner", handle).state());
                service.acknowledge("owner", handle);
            }
        }
    }

    private BackupTransferService service(FilesystemPkiStore store, Instant now) throws Exception {
        Path spool = directory.resolve("artifacts");
        if (!Files.exists(spool)) {
            Files.createDirectory(spool, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                    java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")));
        }
        BackupTransferConfiguration configuration = new BackupTransferConfiguration(spool,
                8 * 1024 * 1024, 16 * 1024 * 1024, 4, 1, 9L * 1024 * 1024 * 1024,
                Duration.ofHours(1), Duration.ofMinutes(1), java.net.URI.create("https://admin.example"));
        BackupService backup = mock(BackupService.class);
        when(backup.createBackupSource(any())).thenAnswer(call -> store.createBackupSource(call.getArgument(0)));
        when(backup.prepareBackup(any())).thenAnswer(call -> store.prepareBackup(call.getArgument(0)));
        when(backup.stageRestore(any(BackupSource.class), any(PkiId.class)))
                .thenAnswer(call -> store.stageRestore(call.getArgument(0), call.getArgument(1)));
        when(backup.latestRestoreIdentity()).thenAnswer(call -> store.latestRestoreIdentity());
        return new BackupTransferService(backup, new BackupArtifactRepository(configuration, "realm",
                Clock.fixed(now, ZoneOffset.UTC), new SecureRandom()), () -> { });
    }

    @Test void exportUploadVerifyRestoreAndExpiredStatusSurviveColdActivation() throws Exception {
        String workflow;
        Path root = directory.resolve("store");
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults());
                BackupTransferService service = service(store, NOW)) {
            BackupArtifactRepository.Descriptor exported = service.export("owner",
                    new BackupRequest("fixture", mock(AttributeSet.class)));
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            service.download("owner", exported, bytes);
            assertThrows(IOException.class, () -> service.download("owner", exported, new ByteArrayOutputStream()));
            BackupArtifactRepository.Descriptor uploaded = service.reserveUpload("owner",
                    exported.backupId(), bytes.size(), exported.sha256());
            service.upload("owner", uploaded, new ByteArrayInputStream(bytes.toByteArray()));
            BackupArtifactRepository.Descriptor verified = service.verify("owner", service.bind("owner", uploaded.handle()));
            assertEquals(exported.manifest(), verified.manifest());
            BackupArtifactRepository.Descriptor staged = service.restore("owner", verified);
            assertEquals(BackupArtifactRepository.State.STAGED, staged.state());
            workflow = staged.handle();
            assertThrows(IOException.class, () -> service.restore("owner", verified));
            assertThrows(IOException.class, () -> service.acknowledge("owner", workflow));
        }
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults());
                BackupTransferService service = service(store, NOW.plusSeconds(3601))) {
            assertThrows(IOException.class, () -> service.bind("owner", workflow));
            assertThrows(IOException.class, () -> service.status("other", workflow));
            assertEquals(BackupArtifactRepository.State.ACTIVATED, service.status("owner", workflow).state());
            assertFalse(Files.exists(directory.resolve("artifacts").resolve(workflow + ".zip")));
            service.acknowledge("owner", workflow);
            assertThrows(IOException.class, () -> service.status("owner", workflow));
        }
    }
}
