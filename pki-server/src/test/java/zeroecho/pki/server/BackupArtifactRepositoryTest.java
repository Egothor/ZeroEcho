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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.api.PkiId;

class BackupArtifactRepositoryTest {
    @TempDir Path directory;
    private static final Instant NOW = Instant.parse("2026-10-06T10:00:00Z");
    private static final byte[] BODY = {1, 2, 3, 4};
    private BackupTransferConfiguration configuration() {
        return new BackupTransferConfiguration(directory, 8 * 1024 * 1024, 16 * 1024 * 1024,
                2, 1, 9L * 1024 * 1024 * 1024, Duration.ofHours(1), Duration.ofMinutes(1),
                java.net.URI.create("https://admin.example"));
    }
    private BackupArtifactRepository open(Instant now) throws IOException {
        return new BackupArtifactRepository(configuration(), "realm", Clock.fixed(now, ZoneOffset.UTC), new SecureRandom());
    }
    private static String digest(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    private BackupArtifactRepository.Descriptor reserve(BackupArtifactRepository repository) throws Exception {
        return repository.reserve("owner", BackupArtifactRepository.Purpose.IMPORT, new PkiId("backup"), BODY.length, digest(BODY));
    }

    @Test void completedTransferSurvivesRestartWithOwnershipAndSingleLease() throws Exception {
        String handle;
        try (BackupArtifactRepository repository = open(NOW)) {
            handle = reserve(repository).handle();
            repository.receive("owner", handle, new ByteArrayInputStream(BODY));
            assertThrows(IOException.class, () -> repository.inspect("other", handle));
            assertThrows(IOException.class, () -> repository.inspect("owner", "../escape"));
            assertThrows(IOException.class, () -> repository.receive("owner", handle, new ByteArrayInputStream(BODY)));
            try (BackupArtifactRepository.Lease lease = repository.source("owner", handle, BackupArtifactRepository.State.READY, true)) {
                assertThrows(IOException.class, () -> repository.source("owner", handle, BackupArtifactRepository.State.READY, true));
                try (InputStream input = lease.openStream()) { assertArrayEquals(BODY, input.readAllBytes()); }
                lease.transition(BackupArtifactRepository.State.VERIFIED, digest(BODY));
            }
        }
        try (BackupArtifactRepository repository = open(NOW)) {
            assertEquals(BackupArtifactRepository.State.VERIFIED, repository.inspect("owner", handle).state());
            assertEquals(digest(BODY), repository.inspect("owner", handle).manifest());
        }
    }

    @Test void failedHandoffRetainsPreparationAdmissionUntilSourceOwnerCloses() throws Exception {
        try (BackupArtifactRepository repository = open(NOW)) {
            BackupArtifactRepository.PreparationJob job = repository.prepare();
            try (job) {
                assertThrows(IOException.class, () -> job.handoff("owner", "0".repeat(64)));
                assertThrows(IOException.class, repository::prepare);
                assertThrows(IOException.class, repository::close);
                job.close();
                {
                    BackupArtifactRepository.PreparationJob next = repository.prepare();
                    if (next != null) {
                        next.close();
                    }
                }
            }
        }
    }

    @Test void interruptedAndOversizedInputsAreNeverReadyAndAreCleaned() throws Exception {
        try (BackupArtifactRepository repository = open(NOW)) {
            String interrupted = reserve(repository).handle();
            assertThrows(IOException.class, () -> repository.receive("owner", interrupted, new InputStream() {
                @Override public int read() throws IOException { throw new IOException("fixture"); }
            }));
            assertEquals(BackupArtifactRepository.State.FAILED, repository.inspect("owner", interrupted).state());
            String oversized = reserve(repository).handle();
            assertThrows(IOException.class, () -> repository.receive("owner", oversized, new ByteArrayInputStream(new byte[5])));
            repository.cleanup();
            assertThrows(IOException.class, () -> repository.inspect("owner", interrupted));
            assertThrows(IOException.class, () -> repository.inspect("owner", oversized));
        }
        try (java.util.stream.Stream<Path> entries = Files.list(directory)) {
            assertEquals(1, entries.count());
        }
    }

    @Test void expiryAndIncompleteReservationsAreReclaimedOnRestart() throws Exception {
        String ready;
        String incomplete;
        try (BackupArtifactRepository repository = open(NOW)) {
            ready = reserve(repository).handle();
            repository.receive("owner", ready, new ByteArrayInputStream(BODY));
            incomplete = reserve(repository).handle();
        }
        try (BackupArtifactRepository repository = open(NOW.plusSeconds(3600))) {
            assertThrows(IOException.class, () -> repository.inspect("owner", ready));
            assertThrows(IOException.class, () -> repository.inspect("owner", incomplete));
            reserve(repository);
        }
    }

    @Test void interruptedRestoreRemainsUncertainAfterRestart() throws Exception {
        String handle;
        try (BackupArtifactRepository repository = open(NOW)) {
            handle = reserve(repository).handle();
            repository.receive("owner", handle, new ByteArrayInputStream(BODY));
            try (BackupArtifactRepository.Lease lease = repository.source("owner", handle, BackupArtifactRepository.State.READY, true)) {
                lease.transition(BackupArtifactRepository.State.RESTORING, digest(BODY));
            }
        }
        try (BackupArtifactRepository repository = open(NOW)) {
            assertEquals(BackupArtifactRepository.State.UNCERTAIN, repository.inspect("owner", handle).state());
        }
    }

    @Test void rejectsDifferentRealmCorruptMetadataAndConcurrentOwner() throws Exception {
        String handle;
        try (BackupArtifactRepository repository = open(NOW)) {
            handle = reserve(repository).handle();
            repository.receive("owner", handle, new ByteArrayInputStream(BODY));
            assertThrows(java.nio.channels.OverlappingFileLockException.class, () -> open(NOW));
        }
        assertThrows(IOException.class, () -> new BackupArtifactRepository(configuration(), "other",
                Clock.fixed(NOW, ZoneOffset.UTC), new SecureRandom()));
        Files.write(directory.resolve(handle + ".meta"), new byte[] {0, 1, 2});
        assertThrows(IOException.class, () -> open(NOW));
    }

    @Test void streamedInputLargerThanFourMiBUsesBoundedReads() throws Exception {
        long size = 5L * 1024 * 1024;
        byte[] block = new byte[65536];
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (long n = 0; n < size; n += block.length) digest.update(block);
        try (BackupArtifactRepository repository = open(NOW)) {
            String handle = repository.reserve("owner", BackupArtifactRepository.Purpose.IMPORT,
                    new PkiId("large"), size, HexFormat.of().formatHex(digest.digest())).handle();
            repository.receive("owner", handle, new InputStream() {
                private long remaining = size;
                @Override public int read() { throw new AssertionError("Expected bounded bulk reads"); }
                @Override public int read(byte[] bytes, int offset, int length) {
                    assertTrue(length <= 65536);
                    if (remaining == 0) return -1;
                    int count = (int) Math.min(remaining, length);
                    java.util.Arrays.fill(bytes, offset, offset + count, (byte) 0);
                    remaining -= count;
                    return count;
                }
            });
            assertEquals(size, Files.size(directory.resolve(handle + ".zip")));
        }
    }

    @Test void closedLeaseCannotMutateSubsequentLease() throws Exception {
        try (BackupArtifactRepository repository = open(NOW)) {
            String handle = reserve(repository).handle();
            repository.receive("owner", handle, new ByteArrayInputStream(BODY));
            BackupArtifactRepository.Lease first = repository.source("owner", handle,
                    BackupArtifactRepository.State.READY, false);
            first.close();
            {
                BackupArtifactRepository.Lease second = repository.source("owner", handle,
                    BackupArtifactRepository.State.READY, false);
                try (second) {
                    assertThrows(IOException.class, () -> first.transition(BackupArtifactRepository.State.CONSUMED, ""));
                    assertEquals(BackupArtifactRepository.State.READY, repository.inspect("owner", handle).state());
                }
            }
        }
    }

    @Test void syntacticallyValidMetadataCorruptionIsRejected() throws Exception {
        String handle;
        try (BackupArtifactRepository repository = open(NOW)) {
            handle = reserve(repository).handle();
            repository.receive("owner", handle, new ByteArrayInputStream(BODY));
        }
        Path file = directory.resolve(handle + ".meta");
        byte[] bytes = Files.readAllBytes(file);
        // Header (8), token length (2), token (64), owner length (2):
        // changing the owner preserves filename, framing and field validation.
        bytes[76] = (byte) 'p';
        Files.write(file, bytes);
        assertEquals("Corrupt backup artifact descriptor", assertThrows(IOException.class, () -> open(NOW)).getMessage());
    }

    @Test void failedDeletionCannotReviveConsumedHandle() throws Exception {
        java.util.concurrent.atomic.AtomicBoolean fail = new java.util.concurrent.atomic.AtomicBoolean();
        String handle;
        try (BackupArtifactRepository repository = new BackupArtifactRepository(configuration(), "realm",
                Clock.fixed(NOW, ZoneOffset.UTC), new SecureRandom(), phase -> {
                    if (fail.get() && phase == BackupArtifactRepository.Phase.BEFORE_DELETE) throw new IOException("fixture");
                })) {
            handle = reserve(repository).handle();
            repository.receive("owner", handle, new ByteArrayInputStream(BODY));
            try (BackupArtifactRepository.Lease lease = repository.source("owner", handle,
                    BackupArtifactRepository.State.READY, false)) {
                lease.transition(BackupArtifactRepository.State.FAILED, "");
            }
            fail.set(true);
            assertThrows(IOException.class, repository::cleanup);
            assertThrows(IOException.class, () -> repository.inspect("owner", handle));
            assertThrows(IOException.class, () -> repository.source("owner", handle, BackupArtifactRepository.State.READY, false));
        }
        try (BackupArtifactRepository repository = open(NOW)) {
            assertThrows(IOException.class, () -> repository.inspect("owner", handle));
        }
        assertEquals(false, Files.exists(directory.resolve(handle + ".zip")));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.EnumSource(value = BackupArtifactRepository.Phase.class,
            names = {"METADATA_FORCED", "METADATA_RENAMED", "DIRECTORY_FORCED"})
    void uncertainPublicationFencesUntilRestart(BackupArtifactRepository.Phase crash) throws Exception {
        java.util.concurrent.atomic.AtomicBoolean fail = new java.util.concurrent.atomic.AtomicBoolean();
        try (BackupArtifactRepository repository = new BackupArtifactRepository(configuration(), "realm",
                Clock.fixed(NOW, ZoneOffset.UTC), new SecureRandom(), phase -> {
                    if (fail.get() && phase == crash) throw new IOException("fixture");
                })) {
            fail.set(true);
            assertThrows(IOException.class, () -> reserve(repository));
            assertThrows(IOException.class, () -> reserve(repository));
        }
        try (BackupArtifactRepository repository = open(NOW)) {
            reserve(repository);
        }
    }

    @Test void requiresPreexistingPrivateDirectory() throws Exception {
        Files.delete(directory);
        assertThrows(IOException.class, () -> open(NOW));
        Files.createDirectory(directory);
        org.junit.jupiter.api.Assumptions.assumeTrue(Files.getFileStore(directory).supportsFileAttributeView("posix"));
        Files.setPosixFilePermissions(directory, java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-x---"));
        assertThrows(IOException.class, () -> open(NOW));
        Files.setPosixFilePermissions(directory, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        try (BackupArtifactRepository repository = open(NOW)) { reserve(repository); }
    }

    @Test void rejectsSymlinkEntriesAndRoot() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(Files.getFileStore(directory).supportsFileAttributeView("posix"));
        Path link = directory.resolve("linked");
        Files.createSymbolicLink(link, directory);
        assertThrows(IOException.class, () -> open(NOW));
        Files.delete(link);
        Path actual = directory.resolveSibling(directory.getFileName() + "-actual");
        Files.move(directory, actual);
        try {
            Files.createSymbolicLink(directory, actual);
            assertThrows(IOException.class, () -> open(NOW));
        } finally {
            Files.deleteIfExists(directory);
            Files.move(actual, directory);
        }
    }

    @Test void expiredUncertainWorkflowRetainsExactCorrelationAndConsumesMetadataQuota() throws Exception {
        String handle;
        String restoreId = "66e46212-b0a0-4efe-9e96-81f266721f73";
        try (BackupArtifactRepository repository = open(NOW)) {
            handle = reserve(repository).handle();
            repository.receive("owner", handle, new ByteArrayInputStream(BODY));
            try (BackupArtifactRepository.Lease lease = repository.source("owner", handle,
                    BackupArtifactRepository.State.READY, true)) {
                lease.transition(BackupArtifactRepository.State.VERIFIED, digest(BODY));
                lease.beginRestore(restoreId, "");
            }
        }
        try (BackupArtifactRepository repository = open(NOW.plusSeconds(3601))) {
            assertThrows(IOException.class, () -> repository.inspect("owner", handle));
            assertEquals(BackupArtifactRepository.State.UNCERTAIN, repository.workflow("owner", handle).state());
            assertEquals(false, Files.exists(directory.resolve(handle + ".zip")));
            assertThrows(IOException.class, () -> repository.acknowledge("owner", handle));
            reserve(repository);
            assertThrows(IOException.class, () -> reserve(repository));
            zeroecho.pki.api.backup.RestoreIdentity other = new zeroecho.pki.api.backup.RestoreIdentity(
                    new PkiId("backup"), digest(BODY), new zeroecho.pki.api.backup.RestoreStatus(
                            new PkiId("645a65d7-6b4d-4caf-b187-491a3cac6e67"),
                            zeroecho.pki.api.backup.RestoreStatus.State.ACTIVATED, java.util.List.of()));
            assertEquals(BackupArtifactRepository.State.UNCERTAIN, repository.reconcile("owner", handle, other).state());
            zeroecho.pki.api.backup.RestoreIdentity exact = new zeroecho.pki.api.backup.RestoreIdentity(
                    new PkiId("backup"), digest(BODY), new zeroecho.pki.api.backup.RestoreStatus(
                            new PkiId(restoreId), zeroecho.pki.api.backup.RestoreStatus.State.ACTIVATED, java.util.List.of()));
            assertEquals(BackupArtifactRepository.State.ACTIVATED, repository.reconcile("owner", handle, exact).state());
            repository.acknowledge("owner", handle);
            reserve(repository);
        }
    }
}
