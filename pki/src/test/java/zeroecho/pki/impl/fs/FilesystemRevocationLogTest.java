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
package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.MetadataStoreId;

final class FilesystemRevocationLogTest {

    private static final MetadataStoreId STORE_ID =
            new MetadataStoreId("00112233445566778899aabbccddeeff");
    private static final MetadataStoreId FOREIGN_STORE_ID =
            new MetadataStoreId("ffeeddccbbaa99887766554433221100");
    private static final PkiId FIRST = new PkiId("credential:first");
    private static final PkiId SECOND = new PkiId("credential:second");
    private static final Set<PkiId> AUTHORIZED = Set.of(FIRST, SECOND);

    @TempDir
    Path temporaryDirectory;

    @Test
    void newLogReopenIdentityAndExclusiveWriterLifecycleAreStrict() throws Exception {
        System.out.print("newLogReopenIdentityAndExclusiveWriterLifecycleAreStrict ");
        Path path = logPath("lifecycle");
        FilesystemRevocationLog created = FilesystemRevocationLog.create(
                path, STORE_ID, authority());
        assertEquals(STORE_ID, created.storeId());
        assertEquals(new FsPaths(temporaryDirectory.resolve("lifecycle")).revocationTransitionLog(), path);
        assertThrows(IOException.class,
                () -> FilesystemRevocationLog.open(path, STORE_ID, authority()));
        created.close();
        created.close();
        assertThrows(IllegalStateException.class, created::scan);
        try (FilesystemRevocationLog reopened = FilesystemRevocationLog.open(
                path, STORE_ID, authority())) {
            assertEquals(STORE_ID, reopened.storeId());
            assertEquals(0L, reopened.scan().globalRevision());
        }
        try (FilesystemRevocationLog reopened = FilesystemRevocationLog.open(
                path, STORE_ID, authority())) {
            assertEquals(STORE_ID, reopened.storeId());
        }
        System.out.println("...ok");
    }

    @Test
    void firstAndInterleavedCredentialTransitionsRecoverDeterministically() throws Exception {
        System.out.print("firstAndInterleavedCredentialTransitionsRecoverDeterministically ");
        Path path = logPath("interleaved");
        try (FilesystemRevocationLog log = FilesystemRevocationLog.create(path, STORE_ID, authority())) {
            assertEquals(1L, log.append(FIRST, held(1L, 10L)).data().globalRevision());
            assertEquals(2L, log.append(SECOND, held(1L, 20L)).data().globalRevision());
            assertEquals(3L, log.append(FIRST, clear(2L, 21L)).data().globalRevision());
            assertEquals(4L, log.append(FIRST, held(3L, 22L)).data().globalRevision());
            assertEquals(5L, log.append(FIRST, permanent(4L, 23L)).data().globalRevision());
            assertEquals(2, log.activeCredentialCount());
            assertEquals(0L, log.scanInvocationCount());
        }
        AtomicInteger authorityCalls = new AtomicInteger();
        FilesystemRevocationLog.CredentialAuthority counting = credentialId -> {
            if (!AUTHORIZED.contains(credentialId)) {
                throw new IOException("foreign credential");
            }
            authorityCalls.incrementAndGet();
        };
        try (FilesystemRevocationLog reopened = FilesystemRevocationLog.open(
                path, STORE_ID, counting)) {
            FilesystemRevocationLog.RecoveryResult first = reopened.scan();
            FilesystemRevocationLog.RecoveryResult second = reopened.scan();
            assertEquals(first, second);
            assertEquals(5L, first.globalRevision());
            assertEquals(2, first.latestStates().size());
            assertFalse(first.incompleteTail());
            assertEquals(first.physicalEnd(), first.lastCompleteRecordBoundary());
        }
        assertEquals(6, authorityCalls.get());
        System.out.println("...ok");
    }

    @Test
    void existingRevocationLegalityAndTimeRulesRemainStrict() throws Exception {
        System.out.print("existingRevocationLegalityAndTimeRulesRemainStrict ");
        Path path = logPath("rules");
        try (FilesystemRevocationLog log = FilesystemRevocationLog.create(path, STORE_ID, authority())) {
            assertThrows(IllegalArgumentException.class, () -> log.append(FIRST, clear(1L, 1L)));
            log.append(FIRST, held(1L, 10L));
            assertThrows(IllegalArgumentException.class, () -> log.append(FIRST, held(2L, 11L)));
            assertThrows(IllegalArgumentException.class, () -> log.append(FIRST, clear(2L, 9L)));
            assertThrows(IllegalArgumentException.class, () -> log.append(FIRST,
                    new RevocationTransition(2L, RevocationState.CLEAR, Instant.ofEpochSecond(11L),
                            Optional.of(RevocationReason.REMOVE_FROM_CRL), new SimpleAttributeSet())));
            log.append(FIRST, permanent(2L, 12L));
            assertThrows(IllegalArgumentException.class, () -> log.append(FIRST, clear(3L, 13L)));
            assertEquals(2L, log.scan().globalRevision());
        }
        System.out.println("...ok");
    }

    @Test
    void wrongRevisionAndCommitmentChainsFailClosed() throws Exception {
        System.out.print("wrongRevisionAndCommitmentChainsFailClosed ");
        List<List<RevocationTransitionFrameCodec.TransitionData>> invalid = List.of(
                List.of(firstData(2L, FIRST, held(1L, 1L))),
                List.of(firstData(1L, FIRST, held(1L, 1L)),
                        linkedData(3L, FIRST, clear(2L, 2L), 1L,
                                RevocationTransitionFrameCodec.initialCommitment(STORE_ID),
                                RevocationTransitionFrameCodec.initialCommitment(STORE_ID))),
                List.of(firstData(1L, FIRST, held(1L, 1L)),
                        linkedData(2L, FIRST, clear(3L, 2L), 1L,
                                RevocationTransitionFrameCodec.initialCommitment(STORE_ID),
                                RevocationTransitionFrameCodec.initialCommitment(STORE_ID))),
                List.of(new RevocationTransitionFrameCodec.TransitionData(
                        1L, new RevocationTransitionFrameCodec.Commitment("1".repeat(64)), FIRST,
                        OptionalLong.empty(), Optional.empty(), held(1L, 1L))));
        for (int index = 0; index < invalid.size(); index++) {
            Path path = rawLog("invalid-" + index, invalid.get(index));
            assertThrows(FilesystemRevocationLog.CorruptLogException.class,
                    () -> FilesystemRevocationLog.open(path, STORE_ID, authority()));
        }

        Path validPath = logPath("wrong-local-link");
        RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
        try (FileChannel channel = rawChannel(validPath)) {
            codec.writePreamble(channel, STORE_ID);
            RevocationTransitionFrameCodec.CompleteRecord first = codec.write(
                    channel, firstData(1L, FIRST, held(1L, 1L)));
            codec.write(channel, linkedData(2L, FIRST, clear(2L, 2L), 99L,
                    first.commitment(), first.commitment()));
        }
        assertThrows(FilesystemRevocationLog.CorruptLogException.class,
                () -> FilesystemRevocationLog.open(validPath, STORE_ID, authority()));
        System.out.println("...ok");
    }

    @Test
    void incompleteFinalRecordIsRepairedWithoutSecondScanOrPrefixChange() throws Exception {
        System.out.print("incompleteFinalRecordIsRepairedWithoutSecondScanOrPrefixChange ");
        Path path = logPath("tail");
        RevocationTransitionFrameCodec.CompleteRecord first;
        try (FilesystemRevocationLog log = FilesystemRevocationLog.create(path, STORE_ID, authority())) {
            first = log.append(FIRST, held(1L, 1L));
        }
        byte[] validPrefix = java.util.Arrays.copyOf(Files.readAllBytes(path), Math.toIntExact(first.recordEnd()));
        try (FileChannel channel = FileChannel.open(path,
                StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            channel.position(channel.size());
            RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
            codec.write(channel, linkedData(2L, FIRST, clear(2L, 2L), 1L,
                    first.commitment(), first.commitment()));
            channel.truncate(channel.size() - 7L);
        }
        try (FilesystemRevocationLog reopened = FilesystemRevocationLog.open(
                path, STORE_ID, authority())) {
            assertEquals(1L, reopened.currentGlobalRevision());
            assertEquals(1L, reopened.scanInvocationCount());
            assertEquals(first.recordEnd(), Files.size(path));
            assertArrayEquals(validPrefix, Files.readAllBytes(path));
            reopened.append(FIRST, clear(2L, 3L));
        }
        System.out.println("...ok");
    }

    @Test
    void corruptCompleteRecordIsNeverTruncated() throws Exception {
        System.out.print("corruptCompleteRecordIsNeverTruncated ");
        Path path = logPath("corruption");
        try (FilesystemRevocationLog log = FilesystemRevocationLog.create(path, STORE_ID, authority())) {
            log.append(FIRST, held(1L, 1L));
        }
        byte[] corrupt = Files.readAllBytes(path);
        corrupt[corrupt.length - 1] ^= 0x01;
        Files.write(path, corrupt, StandardOpenOption.TRUNCATE_EXISTING);
        long size = Files.size(path);
        AtomicInteger truncations = new AtomicInteger();
        FilesystemRevocationLog.FaultInjector faults = point -> {
            if (point == FilesystemRevocationLog.FaultPoint.TAIL_TRUNCATE) {
                truncations.incrementAndGet();
            }
        };
        assertThrows(FilesystemRevocationLog.CorruptLogException.class,
                () -> FilesystemRevocationLog.open(path, STORE_ID, authority(), supportedProfile(), faults));
        assertEquals(0, truncations.get());
        assertEquals(size, Files.size(path));
        System.out.println("...ok");
    }

    @Test
    void completeRecordAfterForceUncertaintyIsAuthoritativeOnReopen() throws Exception {
        System.out.print("completeRecordAfterForceUncertaintyIsAuthoritativeOnReopen ");
        Path path = logPath("uncertain");
        AtomicInteger forces = new AtomicInteger();
        FilesystemRevocationLog.FaultInjector faults = point -> {
            if (point == FilesystemRevocationLog.FaultPoint.FILE_FORCE
                    && forces.incrementAndGet() == 2) {
                throw new IOException("injected force uncertainty");
            }
        };
        FilesystemRevocationLog log = FilesystemRevocationLog.create(
                path, STORE_ID, authority(), supportedProfile(), faults);
        assertThrows(FilesystemRevocationLog.OutcomeUnknownException.class,
                () -> log.append(FIRST, held(1L, 1L)));
        assertTrue(log.recoveryRequired());
        assertThrows(IOException.class, () -> log.append(SECOND, held(1L, 2L)));
        log.close();
        try (FilesystemRevocationLog reopened = FilesystemRevocationLog.open(
                path, STORE_ID, authority())) {
            assertEquals(1L, reopened.scan().globalRevision());
            assertEquals(1, reopened.activeCredentialCount());
        }
        System.out.println("...ok");
    }

    @Test
    void appendFailureFencesTheWriterAndRetainsThePriorPrefix() throws Exception {
        System.out.print("appendFailureFencesTheWriterAndRetainsThePriorPrefix ");
        Path path = logPath("append-failure");
        FilesystemRevocationLog.FaultInjector faults = point -> {
            if (point == FilesystemRevocationLog.FaultPoint.APPEND) {
                throw new IOException("injected append failure");
            }
        };
        FilesystemRevocationLog log = FilesystemRevocationLog.create(
                path, STORE_ID, authority(), supportedProfile(), faults);
        assertThrows(FilesystemRevocationLog.OutcomeUnknownException.class,
                () -> log.append(FIRST, held(1L, 1L)));
        assertTrue(log.recoveryRequired());
        log.close();
        try (FilesystemRevocationLog reopened = FilesystemRevocationLog.open(
                path, STORE_ID, authority())) {
            assertEquals(0L, reopened.scan().globalRevision());
        }
        System.out.println("...ok");
    }

    @Test
    @RequiresSymlinkCreation
    void authorityPreambleAndEntryTypeFailuresFailClosed() throws Exception {
        System.out.print("authorityPreambleAndEntryTypeFailuresFailClosed ");
        Path path = logPath("authority");
        try (FilesystemRevocationLog log = FilesystemRevocationLog.create(path, STORE_ID, authority())) {
            assertThrows(IOException.class,
                    () -> log.append(new PkiId("credential:foreign"), held(1L, 1L)));
        }
        assertThrows(FilesystemRevocationLog.CorruptLogException.class,
                () -> FilesystemRevocationLog.open(path, FOREIGN_STORE_ID, authority()));
        Path directoryEntry = temporaryDirectory.resolve("directory-entry");
        Files.createDirectories(directoryEntry);
        assertThrows(IOException.class,
                () -> FilesystemRevocationLog.open(directoryEntry, STORE_ID, authority()));
        Path symlink = temporaryDirectory.resolve("symlink.log");
        Files.createSymbolicLink(symlink, path);
        assertThrows(IOException.class,
                () -> FilesystemRevocationLog.open(symlink, STORE_ID, authority()));
        System.out.println("...ok");
    }

    @Test
    void firstRecordChainIsBoundToTheAuthenticatedStorePreamble() throws Exception {
        System.out.print("firstRecordChainIsBoundToTheAuthenticatedStorePreamble ");
        Path sourcePath = logPath("store-bound-source");
        try (FilesystemRevocationLog source = FilesystemRevocationLog.create(
                sourcePath, STORE_ID, authority())) {
            source.append(FIRST, held(1L, 1L));
        }
        byte[] sourceBytes = Files.readAllBytes(sourcePath);
        Path targetPath = logPath("store-bound-target");
        RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
        try (FileChannel target = rawChannel(targetPath)) {
            codec.writePreamble(target, FOREIGN_STORE_ID);
            java.nio.ByteBuffer record = java.nio.ByteBuffer.wrap(
                    sourceBytes, RevocationTransitionFrameCodec.PREAMBLE_BYTES,
                    sourceBytes.length - RevocationTransitionFrameCodec.PREAMBLE_BYTES);
            while (record.hasRemaining()) {
                target.write(record);
            }
        }
        long physicalEnd = Files.size(targetPath);
        assertThrows(FilesystemRevocationLog.CorruptLogException.class,
                () -> FilesystemRevocationLog.open(targetPath, FOREIGN_STORE_ID, authority()));
        assertEquals(physicalEnd, Files.size(targetPath));
        System.out.println("...ok");
    }

    @Test
    void advisoryParentForceFailureEmitsOneRedactedWarningAndCreationSucceeds() throws Exception {
        System.out.print("advisoryParentForceFailureEmitsOneRedactedWarningAndCreationSucceeds ");
        Path path = logPath("warning");
        Logger logger = Logger.getLogger(FilesystemRevocationLog.class.getName());
        AtomicInteger warnings = new AtomicInteger();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                if (record.getLevel().intValue() >= Level.WARNING.intValue()) {
                    assertEquals(
                            "Durable revocation-log creation durability is limited; continuing in best-effort mode",
                            record.getMessage());
                    assertEquals(null, record.getThrown());
                    warnings.incrementAndGet();
                }
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        logger.addHandler(handler);
        try {
            FilesystemRevocationLog.CapabilityProfile limited =
                    new FilesystemRevocationLog.CapabilityProfile() {
                        @Override
                        public boolean posixAvailable(Path parent) throws IOException {
                            return Files.getFileStore(parent).supportsFileAttributeView("posix");
                        }

                        @Override
                        public boolean localFileSystem(Path parent) {
                            return true;
                        }

                        @Override
                        public void forceParent(Path parent) throws IOException {
                            throw new IOException("sensitive path detail");
                        }
                    };
            try (FilesystemRevocationLog log = FilesystemRevocationLog.create(
                    path, STORE_ID, authority(), limited, FilesystemRevocationLog.FaultInjector.NONE)) {
                assertEquals(STORE_ID, log.storeId());
            }
            assertEquals(1, warnings.get());
        } finally {
            logger.removeHandler(handler);
        }
        System.out.println("...ok");
    }

    @Test
    void limitedCapabilitiesStillAttemptParentForceAndLoggingFailureIsAdvisory() throws Exception {
        System.out.print("limitedCapabilitiesStillAttemptParentForceAndLoggingFailureIsAdvisory ");
        Path path = logPath("limited-parent-force");
        AtomicInteger parentForces = new AtomicInteger();
        FilesystemRevocationLog.CapabilityProfile limited =
                new FilesystemRevocationLog.CapabilityProfile() {
                    @Override
                    public boolean posixAvailable(Path parent) {
                        return false;
                    }

                    @Override
                    public boolean localFileSystem(Path parent) {
                        return false;
                    }

                    @Override
                    public void forceParent(Path parent) {
                        parentForces.incrementAndGet();
                    }
                };
        Logger logger = Logger.getLogger(FilesystemRevocationLog.class.getName());
        Handler failing = new Handler() {
            @Override
            public void publish(LogRecord record) {
                throw new IllegalStateException("injected handler failure");
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        logger.addHandler(failing);
        try (FilesystemRevocationLog log = FilesystemRevocationLog.create(
                path, STORE_ID, authority(), limited, FilesystemRevocationLog.FaultInjector.NONE)) {
            assertEquals(STORE_ID, log.storeId());
        } finally {
            logger.removeHandler(failing);
        }
        assertEquals(1, parentForces.get());
        System.out.println("...ok");
    }

    @Test
    void streamingSinkIsProvisionalAndNoHistoryCollectionIsRetained() throws Exception {
        System.out.print("streamingSinkIsProvisionalAndNoHistoryCollectionIsRetained ");
        Path path = logPath("sink");
        try (FilesystemRevocationLog log = FilesystemRevocationLog.create(path, STORE_ID, authority())) {
            log.append(FIRST, held(1L, 1L));
            log.append(SECOND, held(1L, 2L));
            AtomicInteger accepted = new AtomicInteger();
            AtomicInteger completed = new AtomicInteger();
            log.scan(new FilesystemRevocationLog.RecoverySink() {
                @Override
                public void accept(RevocationTransitionFrameCodec.CompleteRecord record) {
                    accepted.incrementAndGet();
                }

                @Override
                public void complete() {
                    completed.incrementAndGet();
                }

                @Override
                public void abort() {
                    throw new AssertionError("valid scan must not abort");
                }
            });
            assertEquals(2, accepted.get());
            assertEquals(1, completed.get());
            assertEquals(2, log.activeCredentialCount());
        }
        String source = Files.readString(Path.of(
                "src/main/java/zeroecho/pki/impl/fs/FilesystemRevocationLog.java"));
        assertFalse(source.contains("List<RevocationTransition>"));
        assertFalse(source.contains("readAllBytes()"));
        assertFalse(source.contains("MAX_TRANSITIONS"));
        System.out.println("...ok");
    }

    @Test
    void recoverySinkFailuresRemainCallbackFailuresAndAlwaysAbort() throws Exception {
        System.out.print("recoverySinkFailuresRemainCallbackFailuresAndAlwaysAbort ");
        Path path = logPath("sink-failures");
        try (FilesystemRevocationLog log = FilesystemRevocationLog.create(path, STORE_ID, authority())) {
            log.append(FIRST, held(1L, 1L));
            IOException acceptFailure = new IOException("injected sink accept failure");
            AtomicInteger acceptAborts = new AtomicInteger();
            IOException observedAccept = assertThrows(IOException.class,
                    () -> log.scan(new FilesystemRevocationLog.RecoverySink() {
                        @Override
                        public void accept(RevocationTransitionFrameCodec.CompleteRecord record)
                                throws IOException {
                            throw acceptFailure;
                        }

                        @Override
                        public void complete() {
                            throw new AssertionError("failed replay must not complete");
                        }

                        @Override
                        public void abort() {
                            acceptAborts.incrementAndGet();
                        }
                    }));
            assertSame(acceptFailure, observedAccept);
            assertEquals(1, acceptAborts.get());

            IOException completeFailure = new IOException("injected sink completion failure");
            AtomicInteger completeAborts = new AtomicInteger();
            IOException observedComplete = assertThrows(IOException.class,
                    () -> log.scan(new FilesystemRevocationLog.RecoverySink() {
                        @Override
                        public void accept(RevocationTransitionFrameCodec.CompleteRecord record) {
                        }

                        @Override
                        public void complete() throws IOException {
                            throw completeFailure;
                        }

                        @Override
                        public void abort() {
                            completeAborts.incrementAndGet();
                        }
                    }));
            assertSame(completeFailure, observedComplete);
            assertEquals(1, completeAborts.get());
        }
        System.out.println("...ok");
    }

    private Path logPath(String name) throws IOException {
        Path root = temporaryDirectory.resolve(name);
        Path path = new FsPaths(root).revocationTransitionLog();
        Files.createDirectories(path.getParent());
        return path;
    }

    private Path rawLog(
            String name, List<RevocationTransitionFrameCodec.TransitionData> records) throws IOException {
        Path path = logPath(name);
        RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
        try (FileChannel channel = rawChannel(path)) {
            codec.writePreamble(channel, STORE_ID);
            for (RevocationTransitionFrameCodec.TransitionData record : records) {
                codec.write(channel, record);
            }
        }
        return path;
    }

    private static FileChannel rawChannel(Path path) throws IOException {
        return FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.READ, StandardOpenOption.WRITE);
    }

    private static FilesystemRevocationLog.CredentialAuthority authority() {
        return credentialId -> {
            if (!AUTHORIZED.contains(credentialId)) {
                throw new IOException("Credential does not belong to this store");
            }
        };
    }

    private static FilesystemRevocationLog.CapabilityProfile supportedProfile() {
        return new FilesystemRevocationLog.CapabilityProfile() {
            @Override
            public boolean posixAvailable(Path parent) throws IOException {
                return Files.getFileStore(parent).supportsFileAttributeView("posix");
            }

            @Override
            public boolean localFileSystem(Path parent) {
                return true;
            }

            @Override
            public void forceParent(Path parent) {
            }
        };
    }

    private static RevocationTransitionFrameCodec.TransitionData firstData(
            long globalRevision, PkiId credentialId, RevocationTransition transition) {
        return new RevocationTransitionFrameCodec.TransitionData(
                globalRevision, RevocationTransitionFrameCodec.initialCommitment(STORE_ID), credentialId,
                OptionalLong.empty(), Optional.empty(), transition);
    }

    private static RevocationTransitionFrameCodec.TransitionData linkedData(
            long globalRevision,
            PkiId credentialId,
            RevocationTransition transition,
            long previousCredentialGlobalRevision,
            RevocationTransitionFrameCodec.Commitment previousGlobal,
            RevocationTransitionFrameCodec.Commitment previousCredential) {
        return new RevocationTransitionFrameCodec.TransitionData(
                globalRevision, previousGlobal, credentialId,
                OptionalLong.of(previousCredentialGlobalRevision),
                Optional.of(previousCredential), transition);
    }

    private static RevocationTransition held(long revision, long second) {
        return new RevocationTransition(revision, RevocationState.HELD,
                Instant.ofEpochSecond(second), Optional.empty(), new SimpleAttributeSet());
    }

    private static RevocationTransition clear(long revision, long second) {
        return new RevocationTransition(revision, RevocationState.CLEAR,
                Instant.ofEpochSecond(second), Optional.empty(), new SimpleAttributeSet());
    }

    private static RevocationTransition permanent(long revision, long second) {
        return new RevocationTransition(revision, RevocationState.PERMANENTLY_REVOKED,
                Instant.ofEpochSecond(second), Optional.of(RevocationReason.KEY_COMPROMISE),
                new SimpleAttributeSet());
    }
}
