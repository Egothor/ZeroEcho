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
import java.io.InterruptedIOException;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.MetadataStoreId;

final class FilesystemRevocationCheckpointTest {

    private static final MetadataStoreId STORE_ID =
            new MetadataStoreId("00112233445566778899aabbccddeeff");
    private static final MetadataStoreId FOREIGN_ID =
            new MetadataStoreId("ffeeddccbbaa99887766554433221100");
    private static final PkiId FIRST = new PkiId("credential:a");
    private static final PkiId SECOND = new PkiId("credential:b");

    @TempDir
    Path temporaryDirectory;

    @Test
    void publicationDiscoveryAndOrderedCursorsPreserveAllCurrentStates() throws Exception {
        System.out.print("publicationDiscoveryAndOrderedCursorsPreserveAllCurrentStates ");
        try (Fixture fixture = fixture("publish")) {
            RevocationTransitionFrameCodec.CompleteRecord first = fixture.log.append(FIRST, held(1L, 1L));
            RevocationTransitionFrameCodec.CompleteRecord second = fixture.log.append(SECOND, held(1L, 2L));
            RevocationTransitionFrameCodec.CompleteRecord clear = fixture.log.append(FIRST, clear(2L, 3L));
            FilesystemRevocationLog.RecoveryResult recovery = fixture.log.scan();
            CountingSource source = source(List.of(entry(clear), entry(second)));
            FilesystemRevocationCheckpoint.PublishedGeneration published =
                    FilesystemRevocationCheckpoint.publish(
                            fixture.checkpoints, fixture.logPath, recovery, coverage(clear), source);
            assertTrue(published.path().getFileName().toString().matches("g-3-[0-9a-f]{64}\\.chk"));
            assertEquals(1, source.closeCount.get());
            try (FilesystemRevocationCheckpoint checkpoint =
                    FilesystemRevocationCheckpoint.discover(
                            fixture.checkpoints, fixture.logPath, recovery).orElseThrow()) {
                assertEquals(3L, checkpoint.coveredRevision());
                assertEquals(2L, checkpoint.entryCount());
                List<PkiId> all = collect(checkpoint.allCurrentStates());
                List<PkiId> revoked = collect(checkpoint.currentRevokedStates());
                assertEquals(List.of(FIRST, SECOND), all);
                assertEquals(List.of(SECOND), revoked);
            }
            assertTrue(first.recordEnd() < clear.recordEnd());
        }
        System.out.println("...ok");
    }

    @Test
    void revisionZeroAndStaleHistoricalCoverageBindWithoutPrefixReplay() throws Exception {
        System.out.print("revisionZeroAndStaleHistoricalCoverageBindWithoutPrefixReplay ");
        try (Fixture fixture = fixture("stale")) {
            FilesystemRevocationLog.RecoveryResult empty = fixture.log.scan();
            FilesystemRevocationCheckpoint.PublishedGeneration zero =
                    FilesystemRevocationCheckpoint.publish(
                            fixture.checkpoints, fixture.logPath, empty,
                            genesisCoverage(), source(List.of()));
            assertEquals(0L, zero.coveredRevision());
            RevocationTransitionFrameCodec.CompleteRecord first = fixture.log.append(FIRST, held(1L, 1L));
            FilesystemRevocationLog.RecoveryResult firstRecovery = fixture.log.scan();
            FilesystemRevocationCheckpoint.publish(
                    fixture.checkpoints, fixture.logPath, firstRecovery,
                    coverage(first), source(List.of(entry(first))));
            RevocationTransitionFrameCodec.CompleteRecord second = fixture.log.append(SECOND, held(1L, 2L));
            FilesystemRevocationLog.RecoveryResult recovery = fixture.log.scan();
            try (FilesystemRevocationCheckpoint stale = FilesystemRevocationCheckpoint.discover(
                    fixture.checkpoints, fixture.logPath, recovery).orElseThrow()) {
                assertEquals(1L, stale.coveredRevision());
                assertEquals(List.of(FIRST), collect(stale.allCurrentStates()));
            }
            assertEquals(2L, second.data().globalRevision());
        }
        System.out.println("...ok");
    }

    @Test
    void bindingRejectsForeignIdentityWrongFrameBoundaryCommitmentAndEntry() throws Exception {
        System.out.print("bindingRejectsForeignIdentityWrongFrameBoundaryCommitmentAndEntry ");
        try (Fixture fixture = fixture("binding")) {
            RevocationTransitionFrameCodec.CompleteRecord record = fixture.log.append(FIRST, held(1L, 1L));
            FilesystemRevocationLog.RecoveryResult recovery = fixture.log.scan();
            List<FilesystemRevocationCheckpoint.Coverage> invalid = List.of(
                    new FilesystemRevocationCheckpoint.Coverage(
                            FOREIGN_ID, 1L, OptionalLong.of(record.recordOffset()),
                            record.recordEnd(), record.commitment()),
                    new FilesystemRevocationCheckpoint.Coverage(
                            STORE_ID, 1L, OptionalLong.of(record.recordOffset() + 1L),
                            record.recordEnd(), record.commitment()),
                    new FilesystemRevocationCheckpoint.Coverage(
                            STORE_ID, 1L, OptionalLong.of(record.recordOffset()),
                            record.recordEnd() + 1L, record.commitment()),
                    new FilesystemRevocationCheckpoint.Coverage(
                            STORE_ID, 1L, OptionalLong.of(record.recordOffset()),
                            record.recordEnd(), commitment(9)));
            for (int index = 0; index < invalid.size(); index++) {
                final int caseIndex = index;
                Path directory = fixture.root.resolve("invalid-" + caseIndex);
                assertThrows(IOException.class, () -> FilesystemRevocationCheckpoint.publish(
                        directory, fixture.logPath, recovery, invalid.get(caseIndex),
                        source(List.of(entry(record)))));
            }
            RevocationCheckpointCodec.CurrentStateEntry wrong =
                    new RevocationCheckpointCodec.CurrentStateEntry(
                            SECOND, record.data().globalRevision(), 1L, record.commitment(),
                            held(1L, 1L), record.recordOffset(), record.recordEnd());
            assertThrows(IOException.class, () -> FilesystemRevocationCheckpoint.publish(
                    fixture.root.resolve("wrong-entry"), fixture.logPath, recovery,
                    coverage(record), source(List.of(wrong))));
            RevocationCheckpointCodec.CurrentStateEntry wrongEnd =
                    new RevocationCheckpointCodec.CurrentStateEntry(
                            FIRST, record.data().globalRevision(), 1L, record.commitment(),
                            held(1L, 1L), record.recordOffset(), record.recordEnd() + 1L);
            assertThrows(IOException.class, () -> FilesystemRevocationCheckpoint.publish(
                    fixture.root.resolve("wrong-end"), fixture.logPath, recovery,
                    coverage(record), source(List.of(wrongEnd))));
        }
        System.out.println("...ok");
    }

    @Test
    void sortedSourceCountAndLifecycleAreStrict() throws Exception {
        System.out.print("sortedSourceCountAndLifecycleAreStrict ");
        try (Fixture fixture = fixture("source")) {
            RevocationTransitionFrameCodec.CompleteRecord first = fixture.log.append(FIRST, held(1L, 1L));
            RevocationTransitionFrameCodec.CompleteRecord second = fixture.log.append(SECOND, held(1L, 2L));
            FilesystemRevocationLog.RecoveryResult recovery = fixture.log.scan();
            List<List<RevocationCheckpointCodec.CurrentStateEntry>> invalid = List.of(
                    List.of(entry(second), entry(first)),
                    List.of(entry(first), entry(first)));
            for (int index = 0; index < invalid.size(); index++) {
                final int caseIndex = index;
                assertThrows(IOException.class, () -> FilesystemRevocationCheckpoint.publish(
                        fixture.root.resolve("order-" + caseIndex), fixture.logPath, recovery,
                        coverage(second), source(invalid.get(caseIndex))));
            }
            CountingSource tooFew = new CountingSource(2L, List.of(entry(first)));
            assertThrows(IOException.class, () -> FilesystemRevocationCheckpoint.publish(
                    fixture.root.resolve("few"), fixture.logPath, recovery,
                    coverage(second), tooFew));
            assertEquals(1, tooFew.closeCount.get());
            CountingSource tooMany = new CountingSource(1L, List.of(entry(first), entry(second)));
            assertThrows(IOException.class, () -> FilesystemRevocationCheckpoint.publish(
                    fixture.root.resolve("many"), fixture.logPath, recovery,
                    coverage(second), tooMany));
            assertEquals(1, tooMany.closeCount.get());
        }
        System.out.println("...ok");
    }

    @Test
    void publicationFaultsNeverExposePartialGenerationAndDirectoryForceIsAdvisory() throws Exception {
        System.out.print("publicationFaultsNeverExposePartialGenerationAndDirectoryForceIsAdvisory ");
        try (Fixture fixture = fixture("faults")) {
            RevocationTransitionFrameCodec.CompleteRecord record = fixture.log.append(FIRST, held(1L, 1L));
            FilesystemRevocationLog.RecoveryResult recovery = fixture.log.scan();
            for (FilesystemRevocationCheckpoint.FaultPoint point : List.of(
                    FilesystemRevocationCheckpoint.FaultPoint.WRITE,
                    FilesystemRevocationCheckpoint.FaultPoint.FILE_FORCE,
                    FilesystemRevocationCheckpoint.FaultPoint.ATOMIC_MOVE)) {
                Path directory = fixture.root.resolve("fault-" + point);
                assertThrows(IOException.class, () -> FilesystemRevocationCheckpoint.publish(
                        directory, fixture.logPath, recovery, coverage(record),
                        source(List.of(entry(record))), operations(), candidate -> {
                            if (candidate == point) {
                                throw new IOException("injected");
                            }
                        }));
                assertFalse(hasFinalGeneration(directory));
                assertFalse(hasBuildingFile(directory));
            }
            Path advisory = fixture.root.resolve("directory-warning");
            FilesystemRevocationCheckpoint.PublishedGeneration published =
                    FilesystemRevocationCheckpoint.publish(
                            advisory, fixture.logPath, recovery, coverage(record),
                            source(List.of(entry(record))), operations(), point -> {
                                if (point == FilesystemRevocationCheckpoint.FaultPoint.DIRECTORY_FORCE) {
                                    throw new IOException("injected");
                                }
                            });
            assertTrue(Files.exists(published.path()));
        }
        System.out.println("...ok");
    }

    @Test
    void idempotentPublicationReusesIdenticalGenerationAndRejectsFilenameMismatch() throws Exception {
        System.out.print("idempotentPublicationReusesIdenticalGenerationAndRejectsFilenameMismatch ");
        try (Fixture fixture = fixture("idempotent")) {
            RevocationTransitionFrameCodec.CompleteRecord record = fixture.log.append(FIRST, held(1L, 1L));
            FilesystemRevocationLog.RecoveryResult recovery = fixture.log.scan();
            FilesystemRevocationCheckpoint.PublishedGeneration first =
                    FilesystemRevocationCheckpoint.publish(
                            fixture.checkpoints, fixture.logPath, recovery,
                            coverage(record), source(List.of(entry(record))));
            FilesystemRevocationCheckpoint.PublishedGeneration second =
                    FilesystemRevocationCheckpoint.publish(
                            fixture.checkpoints, fixture.logPath, recovery,
                            coverage(record), source(List.of(entry(record))));
            assertEquals(first.path(), second.path());
            assertFalse(second.newlyPublished());
            Path mismatched = fixture.checkpoints.resolve("g-1-" + "0".repeat(64) + ".chk");
            Files.copy(first.path(), mismatched);
            assertThrows(IOException.class, () -> FilesystemRevocationCheckpoint.open(
                    mismatched, fixture.logPath, recovery));
            Files.writeString(fixture.checkpoints.resolve(".building-ignored"), "partial");
            Files.writeString(fixture.checkpoints.resolve("unrelated"), "ignored");
            assertTrue(FilesystemRevocationCheckpoint.discover(
                    fixture.checkpoints, fixture.logPath, recovery).isPresent());
        }
        System.out.println("...ok");
    }

    @Test
    void incompleteCurrentGenerationIsRejectedAndOlderGenerationRemainsUsable() throws Exception {
        System.out.print("incompleteCurrentGenerationIsRejectedAndOlderGenerationRemainsUsable ");
        try (Fixture fixture = fixture("ambiguity")) {
            RevocationTransitionFrameCodec.CompleteRecord first = fixture.log.append(FIRST, held(1L, 1L));
            FilesystemRevocationLog.RecoveryResult firstRecovery = fixture.log.scan();
            FilesystemRevocationCheckpoint.publish(
                    fixture.checkpoints, fixture.logPath, firstRecovery,
                    coverage(first), source(List.of(entry(first))));
            RevocationTransitionFrameCodec.CompleteRecord second = fixture.log.append(SECOND, held(1L, 2L));
            FilesystemRevocationLog.RecoveryResult recovery = fixture.log.scan();
            FilesystemRevocationCheckpoint.publish(
                    fixture.checkpoints, fixture.logPath, recovery,
                    coverage(second), source(List.of(entry(first), entry(second))));
            assertThrows(IOException.class, () -> FilesystemRevocationCheckpoint.publish(
                    fixture.root.resolve("incomplete"), fixture.logPath, recovery,
                    coverage(second), source(List.of(entry(first)))));
            try (FilesystemRevocationCheckpoint selected = FilesystemRevocationCheckpoint.discover(
                    fixture.checkpoints, fixture.logPath, recovery).orElseThrow()) {
                assertEquals(2L, selected.coveredRevision());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void ambiguousHighestRevisionFallsBackToOlderUnambiguousGeneration() throws Exception {
        System.out.print("ambiguousHighestRevisionFallsBackToOlderUnambiguousGeneration ");
        try (Fixture fixture = fixture("ambiguous-fallback")) {
            FilesystemRevocationLog.RecoveryResult empty = fixture.log.scan();
            FilesystemRevocationCheckpoint.publish(
                    fixture.checkpoints, fixture.logPath, empty,
                    genesisCoverage(), source(List.of()));
            RevocationTransitionFrameCodec.CompleteRecord record =
                    fixture.log.append(FIRST, held(1L, 1L));
            FilesystemRevocationLog.RecoveryResult recovery = fixture.log.scan();
            FilesystemRevocationCheckpoint.publish(
                    fixture.checkpoints, fixture.logPath, recovery,
                    coverage(record), source(List.of(entry(record))));
            writeAlternateGeneration(fixture.checkpoints, coverage(record));
            try (FilesystemRevocationCheckpoint selected =
                    FilesystemRevocationCheckpoint.discover(
                            fixture.checkpoints, fixture.logPath, recovery).orElseThrow()) {
                assertEquals(0L, selected.coveredRevision());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void cursorCancellationCloseAndOwnerCloseAreStrict() throws Exception {
        System.out.print("cursorCancellationCloseAndOwnerCloseAreStrict ");
        try (Fixture fixture = fixture("cursor")) {
            fixture.log.append(FIRST, held(1L, 1L));
            RevocationTransitionFrameCodec.CompleteRecord first = fixture.log.append(FIRST, clear(2L, 2L));
            RevocationTransitionFrameCodec.CompleteRecord second = fixture.log.append(SECOND, held(1L, 3L));
            FilesystemRevocationLog.RecoveryResult recovery = fixture.log.scan();
            FilesystemRevocationCheckpoint.PublishedGeneration generation =
                    FilesystemRevocationCheckpoint.publish(
                            fixture.checkpoints, fixture.logPath, recovery,
                            coverage(second), source(List.of(entry(first), entry(second))));
            FilesystemRevocationCheckpoint checkpoint = FilesystemRevocationCheckpoint.open(
                    generation.path(), fixture.logPath, recovery);
            FilesystemRevocationCheckpoint.Cursor cursor = checkpoint.currentRevokedStates();
            AtomicInteger checks = new AtomicInteger();
            CancellationSignal cancellation = () -> checks.incrementAndGet() == 2;
            assertThrows(InterruptedIOException.class, () -> cursor.advance(cancellation));
            assertEquals(2, checks.get());
            assertThrows(IllegalStateException.class, cursor::current);
            FilesystemRevocationCheckpoint.Cursor exhausted = checkpoint.allCurrentStates();
            assertTrue(exhausted.advance(CancellationSignal.NONE));
            assertTrue(exhausted.advance(CancellationSignal.NONE));
            assertFalse(exhausted.advance(CancellationSignal.NONE));
            assertThrows(InterruptedIOException.class, () -> exhausted.advance(() -> true));
            exhausted.close();
            cursor.close();
            cursor.close();
            assertThrows(IllegalStateException.class,
                    () -> cursor.advance(CancellationSignal.NONE));
            FilesystemRevocationCheckpoint.Cursor child = checkpoint.allCurrentStates();
            checkpoint.close();
            checkpoint.close();
            assertThrows(IllegalStateException.class,
                    () -> child.advance(CancellationSignal.NONE));
        }
        System.out.println("...ok");
    }

    @Test
    void openReaderSurvivesPosixFilenameRetirement() throws Exception {
        System.out.print("openReaderSurvivesPosixFilenameRetirement ");
        try (Fixture fixture = fixture("retirement")) {
            RevocationTransitionFrameCodec.CompleteRecord first = fixture.log.append(FIRST, held(1L, 1L));
            FilesystemRevocationLog.RecoveryResult firstRecovery = fixture.log.scan();
            FilesystemRevocationCheckpoint.PublishedGeneration old =
                    FilesystemRevocationCheckpoint.publish(
                            fixture.checkpoints, fixture.logPath, firstRecovery,
                            coverage(first), source(List.of(entry(first))));
            FilesystemRevocationCheckpoint openOld = FilesystemRevocationCheckpoint.open(
                    old.path(), fixture.logPath, firstRecovery);
            RevocationTransitionFrameCodec.CompleteRecord second = fixture.log.append(SECOND, held(1L, 2L));
            FilesystemRevocationLog.RecoveryResult recovery = fixture.log.scan();
            FilesystemRevocationCheckpoint.PublishedGeneration current =
                    FilesystemRevocationCheckpoint.publish(
                            fixture.checkpoints, fixture.logPath, recovery,
                            coverage(second), source(List.of(entry(first), entry(second))));
            assertEquals(1L, FilesystemRevocationCheckpoint.retireObsolete(
                    fixture.checkpoints, current));
            assertFalse(Files.exists(old.path()));
            assertEquals(List.of(FIRST), collect(openOld.allCurrentStates()));
            openOld.close();
            assertTrue(Files.exists(current.path()));
        }
        System.out.println("...ok");
    }

    private Fixture fixture(String name) throws Exception {
        Path root = temporaryDirectory.resolve(name);
        Path logPath = new FsPaths(root).revocationTransitionLog();
        Files.createDirectories(logPath.getParent());
        FilesystemRevocationLog log = FilesystemRevocationLog.create(
                logPath, STORE_ID, credential -> { });
        return new Fixture(root, logPath, new FsPaths(root).revocationCheckpointDirectory(), log);
    }

    private static FilesystemRevocationCheckpoint.Coverage coverage(
            RevocationTransitionFrameCodec.CompleteRecord record) {
        return new FilesystemRevocationCheckpoint.Coverage(
                STORE_ID, record.data().globalRevision(), OptionalLong.of(record.recordOffset()),
                record.recordEnd(), record.commitment());
    }

    private static FilesystemRevocationCheckpoint.Coverage genesisCoverage() {
        return new FilesystemRevocationCheckpoint.Coverage(
                STORE_ID, 0L, OptionalLong.empty(), RevocationTransitionFrameCodec.PREAMBLE_BYTES,
                RevocationTransitionFrameCodec.initialCommitment(STORE_ID));
    }

    private static RevocationCheckpointCodec.CurrentStateEntry entry(
            RevocationTransitionFrameCodec.CompleteRecord record) {
        return new RevocationCheckpointCodec.CurrentStateEntry(
                record.data().credentialId(), record.data().globalRevision(),
                record.data().transition().revision(), record.commitment(),
                record.data().transition(), record.recordOffset(), record.recordEnd());
    }

    private static CountingSource source(
            List<RevocationCheckpointCodec.CurrentStateEntry> entries) {
        return new CountingSource(entries.size(), entries);
    }

    private static List<PkiId> collect(FilesystemRevocationCheckpoint.Cursor cursor) throws Exception {
        List<PkiId> values = new ArrayList<>();
        try (cursor) {
            while (cursor.advance(CancellationSignal.NONE)) {
                values.add(cursor.current().credentialId());
            }
        }
        return values;
    }

    private static boolean hasFinalGeneration(Path directory) throws IOException {
        if (!Files.isDirectory(directory)) {
            return false;
        }
        try (java.util.stream.Stream<Path> paths = Files.list(directory)) {
            return paths.anyMatch(path -> path.getFileName().toString().endsWith(".chk"));
        }
    }

    private static void writeAlternateGeneration(
            Path directory, FilesystemRevocationCheckpoint.Coverage coverage) throws IOException {
        Path building = directory.resolve(".building-test-alternate");
        RevocationCheckpointCodec codec = new RevocationCheckpointCodec();
        RevocationCheckpointCodec.ValidatedFile validated;
        try (FileChannel channel = FileChannel.open(building,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.READ,
                StandardOpenOption.WRITE)) {
            RevocationCheckpointCodec.HeaderData header =
                    new RevocationCheckpointCodec.HeaderData(
                            coverage.storeId(), coverage.coveredRevision(),
                            coverage.finalRecordStart(), coverage.coveredBoundary(),
                            coverage.globalCommitment(), 0L);
            codec.encoder(channel, header).finish();
            validated = codec.validate(channel);
        }
        Path target = directory.resolve(
                "g-" + coverage.coveredRevision() + "-" + validated.generationId() + ".chk");
        Files.move(building, target, StandardCopyOption.ATOMIC_MOVE);
    }

    private static boolean hasBuildingFile(Path directory) throws IOException {
        if (!Files.isDirectory(directory)) {
            return false;
        }
        try (java.util.stream.Stream<Path> paths = Files.list(directory)) {
            return paths.anyMatch(path -> path.getFileName().toString().startsWith(".building-"));
        }
    }

    private static FilesystemRevocationCheckpoint.PublicationOperations operations() {
        return new FilesystemRevocationCheckpoint.PublicationOperations() {
            @Override
            public void atomicMove(Path source, Path target) throws IOException {
                try {
                    Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException unsupported) {
                    throw unsupported;
                }
            }

            @Override
            public void forceDirectory(Path directory) {
                // File-content durability and atomic-move ordering are the behavior under test.
            }
        };
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

    private static RevocationTransitionFrameCodec.Commitment commitment(int seed) {
        return new RevocationTransitionFrameCodec.Commitment(
                String.format("%064x", Integer.toUnsignedLong(seed)));
    }

    private static final class CountingSource implements FilesystemRevocationCheckpoint.SortedSource {
        private final long declared;
        private final List<RevocationCheckpointCodec.CurrentStateEntry> entries;
        private final AtomicInteger closeCount = new AtomicInteger();

        private CountingSource(
                long declared, List<RevocationCheckpointCodec.CurrentStateEntry> entries) {
            this.declared = declared;
            this.entries = List.copyOf(entries);
        }

        @Override
        public long entryCount() {
            return declared;
        }

        @Override
        public FilesystemRevocationCheckpoint.SourceCursor openCursor() {
            return new FilesystemRevocationCheckpoint.SourceCursor() {
                private int index = -1;
                private boolean closed;

                @Override
                public boolean advance() {
                    if (closed) {
                        throw new IllegalStateException("source cursor is closed");
                    }
                    index++;
                    return index < entries.size();
                }

                @Override
                public RevocationCheckpointCodec.CurrentStateEntry current() {
                    if (closed || index < 0 || index >= entries.size()) {
                        throw new IllegalStateException("source cursor has no current entry");
                    }
                    return entries.get(index);
                }

                @Override
                public void close() {
                    closed = true;
                }
            };
        }

        @Override
        public void close() {
            closeCount.incrementAndGet();
        }
    }

    private record Fixture(
            Path root,
            Path logPath,
            Path checkpoints,
            FilesystemRevocationLog log) implements AutoCloseable {
        @Override
        public void close() throws IOException {
            log.close();
        }
    }
}
