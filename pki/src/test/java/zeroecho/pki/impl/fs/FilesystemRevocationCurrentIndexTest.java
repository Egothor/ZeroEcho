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
package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.MetadataStoreId;

final class FilesystemRevocationCurrentIndexTest {

    private static final MetadataStoreId STORE_ID =
            new MetadataStoreId("102030405060708090a0b0c0d0e0f001");
    private static final PkiId FIRST = new PkiId("credential:first");
    private static final PkiId SECOND = new PkiId("credential:second");
    private static final PkiId THIRD = new PkiId("credential:third");
    private static final FilesystemRevocationCurrentIndex.Configuration CONFIGURATION =
            new FilesystemRevocationCurrentIndex.Configuration(4L, 3, 4);

    @TempDir
    private Path temporaryDirectory;

    @Test
    void rebuildProvidesExactAuthoritativeLookupAndStableReopen() throws Exception {
        System.out.print("rebuildProvidesExactAuthoritativeLookupAndStableReopen ");
        try (Fixture fixture = fixture("rebuild")) {
            RevocationTransitionFrameCodec.CompleteRecord first =
                    fixture.log().append(FIRST, held(1L, 1L));
            fixture.log().append(SECOND, permanent(1L, 2L));
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild(CONFIGURATION)) {
                assertEquals(2L, index.coveredGlobalRevision());
                assertEquals(2L, index.entryCount());
                assertEquals(first.commitment(), index.lookup(FIRST).orElseThrow().commitment());
                assertTrue(index.lookup(new PkiId("credential:missing")).isEmpty());
            }
            try (FilesystemRevocationCurrentIndex reopened = fixture.open(CONFIGURATION)) {
                assertEquals(RevocationState.PERMANENTLY_REVOKED,
                        reopened.lookup(SECOND).orElseThrow().data().transition().state());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void openAppliesAuthoritativeSuffixAndPersistsIt() throws Exception {
        System.out.print("openAppliesAuthoritativeSuffixAndPersistsIt ");
        try (Fixture fixture = fixture("suffix")) {
            fixture.log().append(FIRST, held(1L, 1L));
            try (FilesystemRevocationCurrentIndex ignored = fixture.rebuild(CONFIGURATION)) {
                assertEquals(1L, ignored.coveredGlobalRevision());
            }
            fixture.log().append(FIRST, clear(2L, 2L));
            fixture.log().append(SECOND, held(1L, 3L));
            try (FilesystemRevocationCurrentIndex opened = fixture.open(CONFIGURATION)) {
                assertEquals(3L, opened.coveredGlobalRevision());
                assertEquals(2L, opened.entryCount());
                assertEquals(RevocationState.CLEAR,
                        opened.lookup(FIRST).orElseThrow().data().transition().state());
            }
            try (FilesystemRevocationCurrentIndex reopened = fixture.open(CONFIGURATION)) {
                assertEquals(3L, reopened.coveredGlobalRevision());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void cellForceFailureLeavesPriorGenerationRecoverable() throws Exception {
        System.out.print("cellForceFailureLeavesPriorGenerationRecoverable ");
        try (Fixture fixture = fixture("cell-failure")) {
            fixture.log().append(FIRST, held(1L, 1L));
            AtomicInteger failures = new AtomicInteger();
            FilesystemRevocationCurrentIndex.FaultInjector faults = point -> {
                if (point == FilesystemRevocationCurrentIndex.FaultPoint.CELL_FORCE
                        && failures.getAndIncrement() == 0) {
                    throw new IOException("injected cell force failure");
                }
            };
            try (FilesystemRevocationCurrentIndex index =
                    fixture.rebuild(CONFIGURATION, faults)) {
                RevocationTransitionFrameCodec.CompleteRecord second =
                        fixture.log().append(FIRST, clear(2L, 2L));
                assertThrows(IOException.class, () -> index.update(second));
                assertTrue(index.unusable());
                assertThrows(IllegalStateException.class, () -> index.lookup(FIRST));
            }
            try (FilesystemRevocationCurrentIndex recovered = fixture.open(CONFIGURATION)) {
                assertEquals(2L, recovered.coveredGlobalRevision());
                assertEquals(RevocationState.CLEAR,
                        recovered.lookup(FIRST).orElseThrow().data().transition().state());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void superblockForceFailureNeverLosesAuthoritativeTransition() throws Exception {
        System.out.print("superblockForceFailureNeverLosesAuthoritativeTransition ");
        try (Fixture fixture = fixture("superblock-failure")) {
            fixture.log().append(FIRST, held(1L, 1L));
            FilesystemRevocationCurrentIndex.FaultInjector faults = point -> {
                if (point == FilesystemRevocationCurrentIndex.FaultPoint.SUPERBLOCK_FORCE) {
                    throw new IOException("injected superblock force failure");
                }
            };
            try (FilesystemRevocationCurrentIndex index =
                    fixture.rebuild(CONFIGURATION, faults)) {
                RevocationTransitionFrameCodec.CompleteRecord second =
                        fixture.log().append(SECOND, held(1L, 2L));
                assertThrows(IOException.class, () -> index.update(second));
                assertTrue(index.unusable());
            }
            try (FilesystemRevocationCurrentIndex recovered = fixture.open(CONFIGURATION)) {
                assertEquals(2L, recovered.coveredGlobalRevision());
                assertTrue(recovered.lookup(SECOND).isPresent());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void rebuildGrowsOnDiskWithoutAggregateState() throws Exception {
        System.out.print("rebuildGrowsOnDiskWithoutAggregateState ");
        FilesystemRevocationCurrentIndex.Configuration small =
                new FilesystemRevocationCurrentIndex.Configuration(2L, 1, 2);
        try (Fixture fixture = fixture("growth")) {
            fixture.log().append(FIRST, held(1L, 1L));
            fixture.log().append(SECOND, held(1L, 2L));
            fixture.log().append(THIRD, held(1L, 3L));
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild(small)) {
                assertEquals(3L, index.entryCount());
                assertTrue(index.lookup(FIRST).isPresent());
                assertTrue(index.lookup(SECOND).isPresent());
                assertTrue(index.lookup(THIRD).isPresent());
                assertTrue(Files.size(fixture.indexPath())
                        > 2L * FilesystemRevocationCurrentIndex.SUPERBLOCK_BYTES
                                + 2L * FilesystemRevocationCurrentIndex.CELLS_PER_SLOT
                                        * FilesystemRevocationCurrentIndex.CELL_BYTES);
            }
        }
        System.out.println("...ok");
    }

    @Test
    void failedRebuildPreservesPublishedIndex() throws Exception {
        System.out.print("failedRebuildPreservesPublishedIndex ");
        try (Fixture fixture = fixture("preserve")) {
            fixture.log().append(FIRST, held(1L, 1L));
            try (FilesystemRevocationCurrentIndex ignored = fixture.rebuild(CONFIGURATION)) {
                assertEquals(1L, ignored.coveredGlobalRevision());
            }
            byte[] before = Files.readAllBytes(fixture.indexPath());
            FilesystemRevocationCurrentIndex.FaultInjector faults = point -> {
                if (point == FilesystemRevocationCurrentIndex.FaultPoint.REBUILD_FORCE) {
                    throw new IOException("injected rebuild force failure");
                }
            };
            assertThrows(IOException.class, () -> fixture.rebuild(CONFIGURATION, faults));
            assertTrue(java.util.Arrays.equals(before, Files.readAllBytes(fixture.indexPath())));
            try (FilesystemRevocationCurrentIndex existing = fixture.open(CONFIGURATION)) {
                assertTrue(existing.lookup(FIRST).isPresent());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void corruptSuperblocksFailClosedAndRemainRebuildable() throws Exception {
        System.out.print("corruptSuperblocksFailClosedAndRemainRebuildable ");
        try (Fixture fixture = fixture("corrupt-superblocks")) {
            fixture.log().append(FIRST, held(1L, 1L));
            try (FilesystemRevocationCurrentIndex ignored = fixture.rebuild(CONFIGURATION)) {
                assertEquals(1L, ignored.coveredGlobalRevision());
            }
            try (FileChannel channel = FileChannel.open(
                    fixture.indexPath(), StandardOpenOption.READ, StandardOpenOption.WRITE)) {
                writeByte(channel, FilesystemRevocationCurrentIndex.SUPERBLOCK_BYTES - 1L, (byte) 0x44);
                writeByte(channel, 2L * FilesystemRevocationCurrentIndex.SUPERBLOCK_BYTES - 1L,
                        (byte) 0x55);
            }
            assertThrows(IOException.class, () -> fixture.open(CONFIGURATION));
            try (FilesystemRevocationCurrentIndex rebuilt = fixture.rebuild(CONFIGURATION)) {
                assertTrue(rebuilt.lookup(FIRST).isPresent());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void corruptNewestSuperblockFallsBackAndReappliesSuffix() throws Exception {
        System.out.print("corruptNewestSuperblockFallsBackAndReappliesSuffix ");
        try (Fixture fixture = fixture("fallback")) {
            fixture.log().append(FIRST, held(1L, 1L));
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild(CONFIGURATION)) {
                RevocationTransitionFrameCodec.CompleteRecord second =
                        fixture.log().append(SECOND, held(1L, 2L));
                index.update(second);
                assertEquals(2L, index.coveredGlobalRevision());
            }
            try (FileChannel channel = FileChannel.open(
                    fixture.indexPath(), StandardOpenOption.READ, StandardOpenOption.WRITE)) {
                writeByte(channel, 2L * FilesystemRevocationCurrentIndex.SUPERBLOCK_BYTES - 1L,
                        (byte) 0x33);
            }
            try (FilesystemRevocationCurrentIndex recovered = fixture.open(CONFIGURATION)) {
                assertEquals(2L, recovered.coveredGlobalRevision());
                assertTrue(recovered.lookup(SECOND).isPresent());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void exactFrameAndIdentityBindingRejectsForgedUpdate() throws Exception {
        System.out.print("exactFrameAndIdentityBindingRejectsForgedUpdate ");
        try (Fixture fixture = fixture("binding")) {
            RevocationTransitionFrameCodec.CompleteRecord record =
                    fixture.log().append(FIRST, held(1L, 1L));
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild(CONFIGURATION)) {
                RevocationTransitionFrameCodec.CompleteRecord forged =
                        new RevocationTransitionFrameCodec.CompleteRecord(
                                record.data(), record.recordOffset(), record.recordEnd() + 1L,
                                record.commitment());
                assertThrows(IOException.class, () -> index.update(forged));
                assertTrue(index.unusable());
            }
            try (FilesystemRevocationCurrentIndex recovered = fixture.open(CONFIGURATION)) {
                assertEquals(FIRST,
                        recovered.lookup(FIRST).orElseThrow().data().credentialId());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void secondWriterAndClosedUseAreRejected() throws Exception {
        System.out.print("secondWriterAndClosedUseAreRejected ");
        try (Fixture fixture = fixture("locking")) {
            fixture.log().append(FIRST, held(1L, 1L));
            FilesystemRevocationCurrentIndex first = fixture.rebuild(CONFIGURATION);
            assertThrows(IOException.class, () -> fixture.open(CONFIGURATION));
            first.close();
            first.close();
            assertThrows(IllegalStateException.class, () -> first.lookup(FIRST));
            try (FilesystemRevocationCurrentIndex reopened = fixture.open(CONFIGURATION)) {
                assertTrue(reopened.lookup(FIRST).isPresent());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void rebuildCannotReplaceIndexHeldByLiveWriter() throws Exception {
        System.out.print("rebuildCannotReplaceIndexHeldByLiveWriter ");
        try (Fixture fixture = fixture("rebuild-lock")) {
            fixture.log().append(FIRST, held(1L, 1L));
            FilesystemRevocationCurrentIndex existing = fixture.rebuild(CONFIGURATION);
            byte[] published = Files.readAllBytes(fixture.indexPath());
            assertThrows(IOException.class, () -> fixture.rebuild(CONFIGURATION));
            assertTrue(java.util.Arrays.equals(
                    published, Files.readAllBytes(fixture.indexPath())));
            assertThrows(IOException.class, () -> fixture.open(CONFIGURATION));
            assertTrue(existing.lookup(FIRST).isPresent());
            existing.close();
            try (FilesystemRevocationCurrentIndex rebuilt = fixture.rebuild(CONFIGURATION)) {
                assertTrue(rebuilt.lookup(FIRST).isPresent());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void suffixReplayUsesOneFinalDerivedForce() throws Exception {
        System.out.print("suffixReplayUsesOneFinalDerivedForce ");
        try (Fixture fixture = fixture("suffix-force")) {
            fixture.log().append(FIRST, held(1L, 1L));
            try (FilesystemRevocationCurrentIndex ignored = fixture.rebuild(CONFIGURATION)) {
                assertEquals(1L, ignored.coveredGlobalRevision());
            }
            fixture.log().append(FIRST, clear(2L, 2L));
            fixture.log().append(SECOND, held(1L, 3L));
            AtomicInteger cellForces = new AtomicInteger();
            AtomicInteger superblockForces = new AtomicInteger();
            AtomicInteger finalForces = new AtomicInteger();
            FilesystemRevocationCurrentIndex.FaultInjector faults = point -> {
                if (point == FilesystemRevocationCurrentIndex.FaultPoint.CELL_FORCE) {
                    cellForces.incrementAndGet();
                } else if (point == FilesystemRevocationCurrentIndex.FaultPoint.SUPERBLOCK_FORCE) {
                    superblockForces.incrementAndGet();
                } else if (point == FilesystemRevocationCurrentIndex.FaultPoint.REBUILD_FORCE) {
                    finalForces.incrementAndGet();
                }
            };
            try (FilesystemRevocationCurrentIndex index =
                    fixture.open(CONFIGURATION, faults)) {
                assertEquals(3L, index.coveredGlobalRevision());
            }
            assertEquals(0, cellForces.get());
            assertEquals(0, superblockForces.get());
            assertEquals(1, finalForces.get());
        }
        System.out.println("...ok");
    }

    @Test
    void liveAndSuffixUpdatesGrowAcrossMultipleDoublings() throws Exception {
        System.out.print("liveAndSuffixUpdatesGrowAcrossMultipleDoublings ");
        FilesystemRevocationCurrentIndex.Configuration small =
                new FilesystemRevocationCurrentIndex.Configuration(2L, 1, 2);
        try (Fixture live = fixture("live-multi-growth")) {
            try (FilesystemRevocationCurrentIndex index = live.rebuild(small)) {
                for (int number = 1; number <= 9; number++) {
                    PkiId identity = new PkiId("credential:live:" + number);
                    RevocationTransitionFrameCodec.CompleteRecord record =
                            live.log().append(identity, held(1L, number));
                    index.update(record);
                }
                assertEquals(9L, index.entryCount());
                assertTrue(index.lookup(new PkiId("credential:live:9")).isPresent());
            }
        }
        try (Fixture suffix = fixture("suffix-multi-growth")) {
            try (FilesystemRevocationCurrentIndex ignored = suffix.rebuild(small)) {
                assertEquals(0L, ignored.entryCount());
            }
            for (int number = 1; number <= 9; number++) {
                suffix.log().append(
                        new PkiId("credential:suffix:" + number), held(1L, number));
            }
            AtomicInteger intermediateForces = new AtomicInteger();
            AtomicInteger directoryForces = new AtomicInteger();
            FilesystemRevocationCurrentIndex.FaultInjector faults = point -> {
                if (point == FilesystemRevocationCurrentIndex.FaultPoint.GROW_FORCE) {
                    intermediateForces.incrementAndGet();
                }
            };
            try (FilesystemRevocationCurrentIndex index = suffix.open(
                    small, operations(directoryForces), faults)) {
                assertEquals(9L, index.entryCount());
                assertEquals(9L, index.coveredGlobalRevision());
                assertTrue(index.lookup(new PkiId("credential:suffix:9")).isPresent());
            }
            assertEquals(0, intermediateForces.get());
            assertEquals(1, directoryForces.get());
        }
        System.out.println("...ok");
    }

    @Test
    void collidingKeysProbeAcrossPhysicalWrapBoundary() throws Exception {
        System.out.print("collidingKeysProbeAcrossPhysicalWrapBoundary ");
        FilesystemRevocationCurrentIndex.Configuration configuration =
                new FilesystemRevocationCurrentIndex.Configuration(8L, 3, 4);
        List<PkiId> colliding = collidingIdentities(8L, 7L, 4);
        try (Fixture fixture = fixture("collision-wrap")) {
            int globalRevision = 1;
            for (PkiId identity : colliding) {
                fixture.log().append(identity, held(1L, globalRevision));
                globalRevision++;
            }
            try (FilesystemRevocationCurrentIndex index = fixture.rebuild(configuration)) {
                for (PkiId identity : colliding) {
                    assertEquals(identity,
                            index.lookup(identity).orElseThrow().data().credentialId());
                }
                assertTrue(index.lookup(new PkiId("credential:collision:missing")).isEmpty());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void structuralContractHasNoHistoryCollectionOrCheckpointDependency() throws Exception {
        System.out.print("structuralContractHasNoHistoryCollectionOrCheckpointDependency ");
        String source = Files.readString(Path.of(
                "src/main/java/zeroecho/pki/impl/fs/FilesystemRevocationCurrentIndex.java"));
        assertFalse(source.contains("List<RevocationTransition>"));
        assertFalse(source.contains("readAllBytes()"));
        assertFalse(source.contains("FilesystemRevocationCheckpoint"));
        assertFalse(source.contains("HashMap"));
        assertFalse(source.contains("new Thread"));
        assertFalse(source.contains("Executors."));
        assertEquals(1L, source.lines().filter(line ->
                line.startsWith("final class FilesystemRevocationCurrentIndex ")).count());
        System.out.println("...ok");
    }

    @Test
    void fsPathsUsesOneStableCurrentIndexLocation() {
        System.out.print("fsPathsUsesOneStableCurrentIndexLocation ");
        assertEquals(temporaryDirectory.resolve("revocations/current-state.idx"),
                new FsPaths(temporaryDirectory).revocationCurrentIndex());
        assertEquals(temporaryDirectory.resolve("revocations/current-state.idx.lock"),
                new FsPaths(temporaryDirectory).revocationCurrentIndexLock());
        System.out.println("...ok");
    }

    private Fixture fixture(String name) throws IOException {
        Path root = temporaryDirectory.resolve(name);
        FsPaths paths = new FsPaths(root);
        Path logPath = paths.revocationTransitionLog();
        Files.createDirectories(logPath.getParent());
        FilesystemRevocationLog log = FilesystemRevocationLog.create(
                logPath, STORE_ID, credential -> { });
        return new Fixture(logPath, paths.revocationCurrentIndex(), log);
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

    private static List<PkiId> collidingIdentities(
            long capacity, long targetSlot, int count) throws Exception {
        List<PkiId> result = new ArrayList<>();
        int candidate = 0;
        while (result.size() < count) {
            PkiId identity = new PkiId("credential:collision:" + candidate);
            if (initialSlot(identity, capacity) == targetSlot) {
                result.add(identity);
            }
            candidate++;
        }
        return result;
    }

    private static long initialSlot(PkiId identity, long capacity) throws Exception {
        byte[] raw = identity.value().getBytes(StandardCharsets.UTF_8);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update("ZeroEcho revocation current index key v1"
                .getBytes(StandardCharsets.US_ASCII));
        digest.update(ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.BIG_ENDIAN)
                .putInt(raw.length).array());
        digest.update(raw);
        long hash = ByteBuffer.wrap(digest.digest())
                .order(ByteOrder.BIG_ENDIAN).getLong();
        return Long.remainderUnsigned(hash, capacity);
    }

    private static void writeByte(FileChannel channel, long offset, byte value) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(new byte[] { value });
        while (buffer.hasRemaining()) {
            int written = channel.write(buffer, offset);
            if (written <= 0) {
                throw new IOException("test mutation made no progress");
            }
            offset += written;
        }
    }

    private static FilesystemRevocationCurrentIndex.PublicationOperations operations() {
        return operations(new AtomicInteger());
    }

    private static FilesystemRevocationCurrentIndex.PublicationOperations operations(
            AtomicInteger directoryForces) {
        return new FilesystemRevocationCurrentIndex.PublicationOperations() {
            @Override
            public void atomicReplace(Path source, Path target) throws IOException {
                Files.move(source, target,
                        StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            }

            @Override
            public void forceDirectory(Path directory) {
                directoryForces.incrementAndGet();
            }
        };
    }

    private record Fixture(
            Path logPath, Path indexPath, FilesystemRevocationLog log) implements AutoCloseable {
        private FilesystemRevocationCurrentIndex rebuild(
                FilesystemRevocationCurrentIndex.Configuration configuration) throws IOException {
            return FilesystemRevocationCurrentIndex.rebuild(
                    indexPath, logPath, STORE_ID, configuration, operations(),
                    FilesystemRevocationCurrentIndex.FaultInjector.NONE);
        }

        private FilesystemRevocationCurrentIndex rebuild(
                FilesystemRevocationCurrentIndex.Configuration configuration,
                FilesystemRevocationCurrentIndex.FaultInjector faults) throws IOException {
            return FilesystemRevocationCurrentIndex.rebuild(
                    indexPath, logPath, STORE_ID, configuration, operations(), faults);
        }

        private FilesystemRevocationCurrentIndex open(
                FilesystemRevocationCurrentIndex.Configuration configuration) throws IOException {
            return open(configuration, FilesystemRevocationCurrentIndex.FaultInjector.NONE);
        }

        private FilesystemRevocationCurrentIndex open(
                FilesystemRevocationCurrentIndex.Configuration configuration,
                FilesystemRevocationCurrentIndex.FaultInjector faults) throws IOException {
            return open(configuration, operations(), faults);
        }

        private FilesystemRevocationCurrentIndex open(
                FilesystemRevocationCurrentIndex.Configuration configuration,
                FilesystemRevocationCurrentIndex.PublicationOperations publicationOperations,
                FilesystemRevocationCurrentIndex.FaultInjector faults) throws IOException {
            return FilesystemRevocationCurrentIndex.open(
                    indexPath, logPath, STORE_ID, configuration, publicationOperations, faults);
        }

        @Override
        public void close() throws IOException {
            log.close();
        }
    }
}
