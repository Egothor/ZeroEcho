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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.MetadataStoreId;

final class FilesystemRevocationCurrentIndexRecoveryTest {

    private static final MetadataStoreId STORE_ID =
            new MetadataStoreId("1234567890abcdef1234567890abcdef");
    private static final PkiId FIRST = new PkiId("credential:recovery:first");
    private static final PkiId SECOND = new PkiId("credential:recovery:second");
    private static final PkiId THIRD = new PkiId("credential:recovery:third");
    private static final FilesystemRevocationCurrentIndex.Configuration INDEX_CONFIGURATION =
            new FilesystemRevocationCurrentIndex.Configuration(4L, 3, 4);

    @TempDir
    Path temporaryDirectory;

    @Test
    void scalarTargetTracksExactAuthoritativePrefix() throws Exception {
        System.out.print("scalarTargetTracksExactAuthoritativePrefix ");
        try (Fixture fixture = fixture("target")) {
            FilesystemRevocationLog.RecoveryTarget genesis = fixture.log.recoveryTarget();
            assertEquals(0L, genesis.globalRevision());
            assertTrue(genesis.finalRecordStart().isEmpty());
            RevocationTransitionFrameCodec.CompleteRecord record =
                    fixture.log.append(FIRST, held(1L, 1L));
            FilesystemRevocationLog.RecoveryTarget current = fixture.log.recoveryTarget();
            assertEquals(1L, current.globalRevision());
            assertEquals(record.recordOffset(), current.finalRecordStart().orElseThrow());
            assertEquals(record.recordEnd(), current.boundary());
            assertEquals(record.commitment(), current.globalCommitment());
        }
        System.out.println("...ok");
    }

    @Test
    void checkpointSeedsIndexAndOnlySuffixIsReplayed() throws Exception {
        System.out.print("checkpointSeedsIndexAndOnlySuffixIsReplayed ");
        try (Fixture fixture = fixture("checkpoint-suffix")) {
            fixture.log.append(FIRST, held(1L, 1L));
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                FilesystemRevocationCheckpointBuilder.build(
                        index, fixture.checkpoints, fixture.builderConfiguration());
            }
            fixture.log.append(SECOND, held(1L, 2L));
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                FilesystemRevocationCheckpointBuilder.build(
                        index, fixture.checkpoints, fixture.builderConfiguration());
            }
            Files.delete(fixture.indexPath);
            RevocationTransitionFrameCodec.CompleteRecord firstSuffix =
                    fixture.log.append(FIRST, clear(2L, 3L));
            RevocationTransitionFrameCodec.CompleteRecord secondSuffix =
                    fixture.log.append(SECOND, clear(2L, 4L));
            FilesystemRevocationLog.RecoveryTarget target = fixture.log.recoveryTarget();
            fixture.log.append(THIRD, held(1L, 5L));
            AtomicInteger suffixReads = new AtomicInteger();
            AtomicLong firstOffset = new AtomicLong(Long.MIN_VALUE);
            AtomicLong lastOffset = new AtomicLong(Long.MIN_VALUE);
            AtomicInteger checkpointEntries = new AtomicInteger();
            AtomicInteger checkpointCandidates = new AtomicInteger();
            FilesystemRevocationCurrentIndex.FaultInjector observer =
                    new FilesystemRevocationCurrentIndex.FaultInjector() {
                        @Override
                        public void fail(FilesystemRevocationCurrentIndex.FaultPoint point) {
                            // Observation-only seam.
                        }

                        @Override
                        public void observeRecoveryCheckpointEntry(long index) {
                            checkpointEntries.incrementAndGet();
                        }

                        @Override
                        public void observeRecoveryLogOffset(long offset) {
                            firstOffset.compareAndSet(Long.MIN_VALUE, offset);
                            lastOffset.set(offset);
                            suffixReads.incrementAndGet();
                        }

                        @Override
                        public void observeRecoveryCheckpointCandidate(long revision) {
                            checkpointCandidates.incrementAndGet();
                        }
                    };
            try (FilesystemRevocationCurrentIndex recovered = fixture.recover(
                    target, observer)) {
                assertEquals(4L, recovered.coveredGlobalRevision());
                assertEquals(2L, recovered.entryCount());
                assertEquals(RevocationState.CLEAR,
                        recovered.lookup(FIRST).orElseThrow().data().transition().state());
                assertEquals(RevocationState.CLEAR,
                        recovered.lookup(SECOND).orElseThrow().data().transition().state());
                assertTrue(recovered.lookup(THIRD).isEmpty());
            }
            assertEquals(1, checkpointCandidates.get());
            assertEquals(2, checkpointEntries.get());
            assertEquals(2, suffixReads.get());
            assertEquals(firstSuffix.recordOffset(), firstOffset.get());
            assertEquals(secondSuffix.recordOffset(), lastOffset.get());
            try (FilesystemRevocationCurrentIndex advanced =
                    FilesystemRevocationCurrentIndex.open(
                            fixture.indexPath, fixture.logPath, STORE_ID,
                            INDEX_CONFIGURATION)) {
                assertEquals(5L, advanced.coveredGlobalRevision());
                assertTrue(advanced.lookup(THIRD).isPresent());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void genesisTargetReplaysNoLaterAuthoritativeRecord() throws Exception {
        System.out.print("genesisTargetReplaysNoLaterAuthoritativeRecord ");
        try (Fixture fixture = fixture("genesis-target")) {
            FilesystemRevocationLog.RecoveryTarget genesis = fixture.log.recoveryTarget();
            fixture.log.append(FIRST, held(1L, 1L));
            AtomicInteger suffixReads = new AtomicInteger();
            FilesystemRevocationCurrentIndex.FaultInjector observer =
                    new FilesystemRevocationCurrentIndex.FaultInjector() {
                        @Override
                        public void fail(FilesystemRevocationCurrentIndex.FaultPoint point) {
                            // Observation-only seam.
                        }

                        @Override
                        public void observeRecoveryLogOffset(long offset) {
                            suffixReads.incrementAndGet();
                        }
                    };
            try (FilesystemRevocationCurrentIndex recovered = fixture.recover(
                    genesis, observer)) {
                assertEquals(0L, recovered.coveredGlobalRevision());
                assertEquals(0L, recovered.entryCount());
                assertTrue(recovered.lookup(FIRST).isEmpty());
            }
            assertEquals(0, suffixReads.get());
        }
        System.out.println("...ok");
    }

    @Test
    void clearStateSurvivesCheckpointSeed() throws Exception {
        System.out.print("clearStateSurvivesCheckpointSeed ");
        try (Fixture fixture = fixture("clear")) {
            fixture.log.append(FIRST, held(1L, 1L));
            fixture.log.append(FIRST, clear(2L, 2L));
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                FilesystemRevocationCheckpointBuilder.build(
                        index, fixture.checkpoints, fixture.builderConfiguration());
            }
            Files.delete(fixture.indexPath);
            try (FilesystemRevocationCurrentIndex recovered = fixture.recover(
                    fixture.log.recoveryTarget(),
                    FilesystemRevocationCurrentIndex.FaultInjector.NONE)) {
                assertEquals(1L, recovered.entryCount());
                assertEquals(RevocationState.CLEAR,
                        recovered.lookup(FIRST).orElseThrow().data().transition().state());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void appendAfterTargetCaptureIsExcludedUntilNormalOpen() throws Exception {
        System.out.print("appendAfterTargetCaptureIsExcludedUntilNormalOpen ");
        try (Fixture fixture = fixture("target-race")) {
            fixture.log.append(FIRST, held(1L, 1L));
            FilesystemRevocationLog.RecoveryTarget target = fixture.log.recoveryTarget();
            fixture.log.append(SECOND, held(1L, 2L));
            try (FilesystemRevocationCurrentIndex recovered = fixture.recover(
                    target, FilesystemRevocationCurrentIndex.FaultInjector.NONE)) {
                assertEquals(1L, recovered.coveredGlobalRevision());
                assertTrue(recovered.lookup(FIRST).isPresent());
                assertTrue(recovered.lookup(SECOND).isEmpty());
            }
            try (FilesystemRevocationCurrentIndex advanced =
                    FilesystemRevocationCurrentIndex.open(
                            fixture.indexPath, fixture.logPath, STORE_ID,
                            INDEX_CONFIGURATION)) {
                assertEquals(2L, advanced.coveredGlobalRevision());
                assertTrue(advanced.lookup(SECOND).isPresent());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void failedRecoveryPreservesPublishedIndex() throws Exception {
        System.out.print("failedRecoveryPreservesPublishedIndex ");
        try (Fixture fixture = fixture("preserve")) {
            fixture.log.append(FIRST, held(1L, 1L));
            try (FilesystemRevocationCurrentIndex ignored = fixture.rebuild()) {
                assertEquals(1L, ignored.coveredGlobalRevision());
            }
            byte[] before = Files.readAllBytes(fixture.indexPath);
            fixture.log.append(SECOND, held(1L, 2L));
            FilesystemRevocationCurrentIndex.FaultInjector faults = point -> {
                if (point == FilesystemRevocationCurrentIndex.FaultPoint.REBUILD_FORCE) {
                    throw new IOException("injected recovery force failure");
                }
            };
            assertThrows(IOException.class, () -> fixture.recover(
                    fixture.log.recoveryTarget(), faults));
            assertTrue(java.util.Arrays.equals(
                    before, Files.readAllBytes(fixture.indexPath)));
            try (FilesystemRevocationCurrentIndex opened =
                    FilesystemRevocationCurrentIndex.open(
                            fixture.indexPath, fixture.logPath, STORE_ID,
                            INDEX_CONFIGURATION)) {
                assertEquals(2L, opened.coveredGlobalRevision());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void validCurrentIndexIsPreferredWithoutCheckpointReads() throws Exception {
        System.out.print("validCurrentIndexIsPreferredWithoutCheckpointReads ");
        try (Fixture fixture = fixture("current-seed")) {
            fixture.log.append(FIRST, held(1L, 1L));
            try (FilesystemRevocationCurrentIndex ignored = fixture.rebuild()) {
                assertEquals(1L, ignored.coveredGlobalRevision());
            }
            fixture.log.append(FIRST, clear(2L, 2L));
            AtomicInteger checkpointReads = new AtomicInteger();
            FilesystemRevocationCurrentIndex.FaultInjector observer =
                    new FilesystemRevocationCurrentIndex.FaultInjector() {
                        @Override
                        public void fail(FilesystemRevocationCurrentIndex.FaultPoint point) {
                            // Observation-only seam.
                        }

                        @Override
                        public void observeRecoveryCheckpointEntry(long index) {
                            checkpointReads.incrementAndGet();
                        }
                    };
            try (FilesystemRevocationCurrentIndex recovered = fixture.recover(
                    fixture.log.recoveryTarget(), observer)) {
                assertEquals(2L, recovered.coveredGlobalRevision());
                assertEquals(RevocationState.CLEAR,
                        recovered.lookup(FIRST).orElseThrow().data().transition().state());
            }
            assertEquals(0, checkpointReads.get());
        }
        System.out.println("...ok");
    }

    @Test
    void corruptCurrentIndexFallsBackToValidatedCheckpoint() throws Exception {
        System.out.print("corruptCurrentIndexFallsBackToValidatedCheckpoint ");
        try (Fixture fixture = fixture("corrupt-current")) {
            fixture.log.append(FIRST, held(1L, 1L));
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild()) {
                FilesystemRevocationCheckpointBuilder.build(
                        index, fixture.checkpoints, fixture.builderConfiguration());
            }
            Files.write(fixture.indexPath, new byte[] {0x01, 0x02, 0x03});
            AtomicInteger checkpointEntries = new AtomicInteger();
            FilesystemRevocationCurrentIndex.FaultInjector observer =
                    new FilesystemRevocationCurrentIndex.FaultInjector() {
                        @Override
                        public void fail(FilesystemRevocationCurrentIndex.FaultPoint point) {
                            // Observation-only seam.
                        }

                        @Override
                        public void observeRecoveryCheckpointEntry(long index) {
                            checkpointEntries.incrementAndGet();
                        }
                    };
            try (FilesystemRevocationCurrentIndex recovered = fixture.recover(
                    fixture.log.recoveryTarget(), observer)) {
                assertEquals(1L, recovered.coveredGlobalRevision());
                assertEquals(RevocationState.HELD,
                        recovered.lookup(FIRST).orElseThrow().data().transition().state());
            }
            assertEquals(1, checkpointEntries.get());
        }
        System.out.println("...ok");
    }

    @Test
    void foreignAndFutureTargetsFailWithoutChangingAuthority() throws Exception {
        System.out.print("foreignAndFutureTargetsFailWithoutChangingAuthority ");
        try (Fixture fixture = fixture("targets")) {
            RevocationTransitionFrameCodec.CompleteRecord first =
                    fixture.log.append(FIRST, held(1L, 1L));
            byte[] logBytes = Files.readAllBytes(fixture.logPath);
            MetadataStoreId foreign =
                    new MetadataStoreId("abcdef1234567890abcdef1234567890");
            FilesystemRevocationLog.RecoveryTarget foreignTarget =
                    new FilesystemRevocationLog.RecoveryTarget(
                            foreign, 0L, java.util.OptionalLong.empty(),
                            RevocationTransitionFrameCodec.PREAMBLE_BYTES,
                            RevocationTransitionFrameCodec.initialCommitment(foreign));
            assertThrows(IOException.class, () -> fixture.recover(
                    foreignTarget, FilesystemRevocationCurrentIndex.FaultInjector.NONE));
            FilesystemRevocationLog.RecoveryTarget future =
                    new FilesystemRevocationLog.RecoveryTarget(
                            STORE_ID, 2L, java.util.OptionalLong.of(first.recordOffset()),
                            first.recordEnd(), first.commitment());
            assertThrows(IOException.class, () -> fixture.recover(
                    future, FilesystemRevocationCurrentIndex.FaultInjector.NONE));
            assertTrue(java.util.Arrays.equals(
                    logBytes, Files.readAllBytes(fixture.logPath)));
            assertFalse(Files.exists(fixture.indexPath));
        }
        System.out.println("...ok");
    }

    @Test
    void writeForceAndMoveFailuresLeaveNoPublishedPartialIndex() throws Exception {
        System.out.print("writeForceAndMoveFailuresLeaveNoPublishedPartialIndex ");
        List<FilesystemRevocationCurrentIndex.FaultPoint> points = List.of(
                FilesystemRevocationCurrentIndex.FaultPoint.REBUILD_WRITE,
                FilesystemRevocationCurrentIndex.FaultPoint.REBUILD_FORCE,
                FilesystemRevocationCurrentIndex.FaultPoint.PUBLISH_ATOMIC_MOVE);
        for (FilesystemRevocationCurrentIndex.FaultPoint selected : points) {
            try (Fixture fixture = fixture("fault-" + selected.name())) {
                fixture.log.append(FIRST, held(1L, 1L));
                byte[] logBytes = Files.readAllBytes(fixture.logPath);
                FilesystemRevocationCurrentIndex.FaultInjector faults = point -> {
                    if (point == selected) {
                        throw new IOException("injected recovery failure");
                    }
                };
                assertThrows(IOException.class, () -> fixture.recover(
                        fixture.log.recoveryTarget(), faults));
                assertFalse(Files.exists(fixture.indexPath));
                assertTrue(java.util.Arrays.equals(
                        logBytes, Files.readAllBytes(fixture.logPath)));
                assertFalse(hasRecoveryTemporary(fixture.indexPath.getParent()));
                try (FilesystemRevocationCurrentIndex recovered = fixture.recover(
                        fixture.log.recoveryTarget(),
                        FilesystemRevocationCurrentIndex.FaultInjector.NONE)) {
                    assertEquals(1L, recovered.coveredGlobalRevision());
                }
            }
        }
        System.out.println("...ok");
    }

    @Test
    void recoverySourcesHaveNoPopulationMapOrCollection() throws Exception {
        System.out.print("recoverySourcesHaveNoPopulationMapOrCollection ");
        String index = Files.readString(Path.of(
                "src/main/java/zeroecho/pki/impl/fs/FilesystemRevocationCurrentIndex.java"));
        String checkpoint = Files.readString(Path.of(
                "src/main/java/zeroecho/pki/impl/fs/FilesystemRevocationCheckpoint.java"));
        assertFalse(index.contains("Map<PkiId"));
        assertFalse(index.contains("List<RevocationTransition"));
        assertFalse(checkpoint.contains("RecoveryTarget target).latestStates"));
        assertFalse(index.contains("readAllBytes()"));
        System.out.println("...ok");
    }

    private Fixture fixture(String name) throws IOException {
        Path root = temporaryDirectory.resolve(name);
        FsPaths paths = new FsPaths(root);
        Path logPath = paths.revocationTransitionLog();
        Files.createDirectories(logPath.getParent());
        FilesystemRevocationLog log = FilesystemRevocationLog.create(
                logPath, STORE_ID, credential -> { });
        return new Fixture(
                logPath, paths.revocationCurrentIndex(),
                paths.revocationCheckpointDirectory(),
                paths.revocationCheckpointWorkDirectory(), log);
    }

    private static RevocationTransition held(long revision, long second) {
        return new RevocationTransition(
                revision, RevocationState.HELD, Instant.ofEpochSecond(second),
                Optional.empty(), new SimpleAttributeSet());
    }

    private static RevocationTransition clear(long revision, long second) {
        return new RevocationTransition(
                revision, RevocationState.CLEAR, Instant.ofEpochSecond(second),
                Optional.empty(), new SimpleAttributeSet());
    }

    private static boolean hasRecoveryTemporary(Path directory) throws IOException {
        try (java.nio.file.DirectoryStream<Path> entries =
                Files.newDirectoryStream(directory)) {
            for (Path entry : entries) {
                String name = entry.getFileName().toString();
                if (name.contains(".recovering-") || name.contains(".seed-")) {
                    return true;
                }
            }
            return false;
        }
    }

    private record Fixture(
            Path logPath,
            Path indexPath,
            Path checkpoints,
            Path work,
            FilesystemRevocationLog log) implements AutoCloseable {
        private FilesystemRevocationCurrentIndex rebuild() throws IOException {
            return FilesystemRevocationCurrentIndex.rebuild(
                    indexPath, logPath, STORE_ID, INDEX_CONFIGURATION);
        }

        private FilesystemRevocationCurrentIndex recover(
                FilesystemRevocationLog.RecoveryTarget target,
                FilesystemRevocationCurrentIndex.FaultInjector faults) throws IOException {
            return FilesystemRevocationCurrentIndex.recover(
                    indexPath, checkpoints, logPath, STORE_ID,
                    INDEX_CONFIGURATION, target, operations(), faults);
        }

        private FilesystemRevocationCheckpointBuilder.Configuration builderConfiguration() {
            return new FilesystemRevocationCheckpointBuilder.Configuration(
                    128L, 2, 31, work);
        }

        private static FilesystemRevocationCurrentIndex.PublicationOperations operations() {
            return new FilesystemRevocationCurrentIndex.PublicationOperations() {
                @Override
                public void atomicReplace(Path source, Path target) throws IOException {
                    Files.move(source, target,
                            java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                            java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }

                @Override
                public void forceDirectory(Path directory) {
                    // Test fixtures do not need an additional directory fsync.
                }
            };
        }

        @Override
        public void close() throws IOException {
            log.close();
        }
    }
}
