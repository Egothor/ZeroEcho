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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataTransactionId;

final class PosixMetadataStoreEngineTest {
    private static final MetadataStoreId STORE_ID =
            new MetadataStoreId("00112233445566778899aabbccddeeff");

    @TempDir
    Path temporaryDirectory;

    @Test
    void createReplaceDeleteAndEmptyCommitsUseContiguousRevisions() throws IOException {
        System.out.print("createReplaceDeleteAndEmptyCommitsUseContiguousRevisions ");
        Path path = temporaryDirectory.resolve("lifecycle.log");
        MetadataKey key = key("record");
        try (PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.create(path, STORE_ID)) {
            MetadataTransactionId create = engine.issue();
            assertEquals(1L, engine.commit(create, List.of(create(key, "one")))
                    .revision().orElseThrow());
            assertEquals(1L, engine.lookup(key).orElseThrow().revision());

            MetadataTransactionId replace = engine.issue();
            assertEquals(2L, engine.commit(replace, List.of(replace(key, 1L, "two")))
                    .revision().orElseThrow());
            assertEquals(2L, engine.lookup(key).orElseThrow().revision());

            assertEquals(3L, engine.commit(engine.issue(), List.of()).revision().orElseThrow());
            assertEquals(3L, engine.storeRevision());
            assertTrue(engine.commit(engine.issue(), List.of(delete(key, 2L))).committed());
            assertTrue(engine.lookup(key).isEmpty());
        }
        try (PosixMetadataStoreEngine reopened = PosixMetadataStoreEngine.open(path)) {
            assertEquals(4L, reopened.storeRevision());
            assertTrue(reopened.lookup(key).isEmpty());
        }
        System.out.println("...ok");
    }

    @Test
    void multiKeyCommitIsAtomicAndConflictWritesOnlyForcedRejection() throws IOException {
        System.out.print("multiKeyCommitIsAtomicAndConflictWritesOnlyForcedRejection ");
        Path path = temporaryDirectory.resolve("atomic.log");
        MetadataKey first = key("first");
        MetadataKey second = new MetadataKey("example.other", "second");
        MetadataTransactionId conflict;
        try (PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.create(path, STORE_ID)) {
            MetadataTransactionId firstIssued = engine.issue();
            MetadataTransactionId secondIssued = engine.issue();
            assertTrue(engine.commit(secondIssued, List.of(create(first, "a"), create(second, "b")))
                    .committed());
            assertEquals(2, List.of(engine.lookup(first), engine.lookup(second)).stream()
                    .filter(java.util.Optional::isPresent).count());
            assertTrue(engine.commit(firstIssued, List.of()).committed());

            conflict = engine.issue();
            PosixMetadataStoreEngine.CommitResult rejected =
                    engine.commit(conflict, List.of(create(first, "duplicate")));
            assertFalse(rejected.committed());
            assertEquals(2L, engine.storeRevision());
        }
        PosixMetadataLogScanner.RecoveryResult recovered = scan(path);
        PosixMetadataLogScanner.RecoveredTransaction rejected = recovered.transactions().get(conflict);
        assertEquals(0L, rejected.mutationCount());
        assertEquals(PosixMetadataLogScanner.TerminalKind.NOT_COMMITTED,
                rejected.terminal().orElseThrow().kind());
        System.out.println("...ok");
    }

    @Test
    void durableValueOffsetsReadExactCommittedBytesAfterReopen() throws IOException {
        System.out.print("durableValueOffsetsReadExactCommittedBytesAfterReopen ");
        Path path = temporaryDirectory.resolve("offset.log");
        MetadataKey key = key("offset");
        byte[] expected = "durable-value".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        MetadataStateIndex.CurrentRecord record;
        try (PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.create(path, STORE_ID)) {
            try (ImmutableByteContent value = new ImmutableByteContent(expected)) {
                engine.commit(engine.issue(), List.of(
                        PosixMetadataStoreEngine.PreparedMutation.create(
                                key, value, CancellationSignal.NONE)));
            }
            record = engine.lookup(key).orElseThrow();
        }
        byte[] observed = new byte[Math.toIntExact(record.valueLength())];
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            channel.position(record.valueOffset());
            ByteBuffer target = ByteBuffer.wrap(observed);
            while (target.hasRemaining()) {
                assertTrue(channel.read(target) > 0);
            }
        }
        assertArrayEquals(expected, observed);
        try (PosixMetadataStoreEngine reopened = PosixMetadataStoreEngine.open(path)) {
            assertEquals(record, reopened.lookup(key).orElseThrow());
        }
        System.out.println("...ok");
    }

    @Test
    void postForcePublicationFailureRequiresRecoveryWithoutLivePublication() throws IOException {
        System.out.print("postForcePublicationFailureRequiresRecoveryWithoutLivePublication ");
        Path path = temporaryDirectory.resolve("uncertain.log");
        MetadataKey key = key("uncertain");
        PosixMetadataStoreEngine.FaultInjector fault = point -> {
            if (point == PosixMetadataStoreEngine.FaultPoint.POST_FORCE_PUBLICATION) {
                throw new IOException("injected");
            }
        };
        PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.create(
                path, STORE_ID, PosixMetadataLog.FaultInjector.NONE, fault);
        assertThrows(PosixMetadataStoreEngine.OutcomeUnknownException.class,
                () -> engine.commit(engine.issue(), List.of(create(key, "fixed"))));
        assertThrows(IllegalStateException.class, engine::storeRevision);
        engine.close();
        try (PosixMetadataStoreEngine reopened = PosixMetadataStoreEngine.open(path)) {
            assertEquals(1L, reopened.storeRevision());
            assertTrue(reopened.lookup(key).isPresent());
        }
        System.out.println("...ok");
    }

    @Test
    void incompleteTailIsRepairedAndPriorCommittedStateIsPreserved() throws IOException {
        System.out.print("incompleteTailIsRepairedAndPriorCommittedStateIsPreserved ");
        Path path = temporaryDirectory.resolve("tail.log");
        MetadataKey key = key("tail");
        long cleanLength;
        try (PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.create(path, STORE_ID)) {
            engine.commit(engine.issue(), List.of(create(key, "kept")));
        }
        cleanLength = Files.size(path);
        Files.write(path, new byte[] {1, 2, 3}, StandardOpenOption.APPEND);
        assertTrue(Files.size(path) > cleanLength);
        try (PosixMetadataStoreEngine reopened = PosixMetadataStoreEngine.open(path)) {
            assertEquals(1L, reopened.storeRevision());
            assertTrue(reopened.lookup(key).isPresent());
        }
        PosixMetadataLogScanner.RecoveryResult recovered = scan(path);
        assertTrue(Files.size(path) > cleanLength);
        assertEquals(PosixMetadataLogScanner.Tail.CLEAN_END, recovered.tail());
        assertEquals(1L, recovered.recoveryEpoch());
        assertEquals(0L, recovered.openTransactionCount());
        System.out.println("...ok");
    }

    @Test
    void repeatedWritableRecoveryPreservesStateRevisionAndTransactionAuthority() throws IOException {
        System.out.print("repeatedWritableRecoveryPreservesStateRevisionAndTransactionAuthority ");
        Path path = temporaryDirectory.resolve("epochs.log");
        MetadataKey first = key("first-epoch");
        try (PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.create(path, STORE_ID)) {
            engine.commit(engine.issue(), List.of(create(first, "one")));
        }
        assertEquals(0L, scan(path).recoveryEpoch());
        try (PosixMetadataStoreEngine reopened = PosixMetadataStoreEngine.open(path)) {
            assertEquals(1L, reopened.storeRevision());
            assertTrue(reopened.lookup(first).isPresent());
            MetadataTransactionId next = reopened.issue();
            assertEquals("00000000000000000000000000000002", next.token());
            reopened.commit(next, List.of());
        }
        assertEquals(1L, scan(path).recoveryEpoch());
        try (PosixMetadataStoreEngine reopened = PosixMetadataStoreEngine.open(path)) {
            assertEquals(2L, reopened.storeRevision());
            assertTrue(reopened.lookup(first).isPresent());
        }
        PosixMetadataLogScanner.ReplayResult replay = replay(path);
        assertEquals(2L, replay.recoveryEpoch());
        assertEquals(0L, replay.openTransactionCount());
        assertEquals(0L, replay.recoveryFullMapCopies());
        assertEquals(1L, replay.recoveryFinalInstalls());
        assertTrue(replay.discardedDescriptorCount() >= 1L);
        System.out.println("...ok");
    }

    @Test
    void terminalForceUncertaintyReplaysAuthoritativeBytes() throws IOException {
        System.out.print("terminalForceUncertaintyReplaysAuthoritativeBytes ");
        Path path = temporaryDirectory.resolve("force.log");
        MetadataKey key = key("force");
        AtomicInteger forces = new AtomicInteger();
        PosixMetadataLog.FaultInjector faults = point -> {
            if (point == PosixMetadataLog.FaultPoint.FILE_FORCE
                    && forces.incrementAndGet() == 3) {
                throw new IOException("injected");
            }
        };
        PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.create(
                path, STORE_ID, faults, PosixMetadataStoreEngine.FaultInjector.NONE);
        assertThrows(PosixMetadataStoreEngine.OutcomeUnknownException.class,
                () -> engine.commit(engine.issue(), List.of(create(key, "forced"))));
        assertThrows(IllegalStateException.class, engine::storeRevision);
        engine.close();
        try (PosixMetadataStoreEngine reopened = PosixMetadataStoreEngine.open(path)) {
            assertEquals(1L, reopened.storeRevision());
            assertTrue(reopened.lookup(key).isPresent());
        }
        System.out.println("...ok");
    }

    @Test
    void preparedContentIsClosedExactlyOnceAcrossTerminalPaths() throws IOException {
        System.out.print("preparedContentIsClosedExactlyOnceAcrossTerminalPaths ");
        Path successPath = temporaryDirectory.resolve("cleanup-success.log");
        CountingContent success = new CountingContent(new byte[] {1});
        try (PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.create(successPath, STORE_ID)) {
            engine.commit(engine.issue(), List.of(
                    PosixMetadataStoreEngine.PreparedMutation.create(
                            key("cleanup"), success, CancellationSignal.NONE)));
        }
        assertEquals(1, success.closeCount());

        Path conflictPath = temporaryDirectory.resolve("cleanup-conflict.log");
        CountingContent conflict = new CountingContent(new byte[] {2});
        try (PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.create(conflictPath, STORE_ID)) {
            engine.commit(engine.issue(), List.of(create(key("cleanup"), "present")));
            assertFalse(engine.commit(engine.issue(), List.of(
                    PosixMetadataStoreEngine.PreparedMutation.create(
                            key("cleanup"), conflict, CancellationSignal.NONE))).committed());
        }
        assertEquals(1, conflict.closeCount());

        Path failurePath = temporaryDirectory.resolve("cleanup-failure.log");
        CountingContent failure = new CountingContent(new byte[] {3});
        PosixMetadataLog.FaultInjector fault = point -> {
            if (point == PosixMetadataLog.FaultPoint.MUTATION_APPEND) {
                throw new IOException("injected");
            }
        };
        try (PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.create(
                failurePath, STORE_ID, fault, PosixMetadataStoreEngine.FaultInjector.NONE)) {
            assertThrows(IOException.class, () -> engine.commit(engine.issue(), List.of(
                    PosixMetadataStoreEngine.PreparedMutation.create(
                            key("cleanup"), failure, CancellationSignal.NONE))));
        }
        assertEquals(1, failure.closeCount());
        System.out.println("...ok");
    }

    @Test
    void restartAbandonsOrphanBatchWithoutChangingRecoveredState() throws IOException {
        System.out.print("restartAbandonsOrphanBatchWithoutChangingRecoveredState ");
        Path path = temporaryDirectory.resolve("orphan.log");
        MetadataKey orphan = key("orphan");
        MetadataTransactionId transactionId;
        try (PosixMetadataLog log = PosixMetadataLog.create(path, STORE_ID)) {
            transactionId = log.issue();
            try (ImmutableByteContent value = new ImmutableByteContent(new byte[] {9});
                    RepeatableContent payload = MetadataMutationPayloadCodec.create(
                            orphan, value, CancellationSignal.NONE)) {
                log.appendMutation(
                        transactionId,
                        MetadataFrameCodec.FrameType.MUTATION_CREATE,
                        payload.length().orElseThrow(),
                        payload,
                        CancellationSignal.NONE);
            }
        }
        assertEquals(1L, scan(path).openTransactionCount());
        try (PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.open(path)) {
            assertEquals(0L, engine.storeRevision());
            assertTrue(engine.lookup(orphan).isEmpty());
            PosixMetadataStoreEngine.CommitResult abandoned = engine.resolve(transactionId);
            assertFalse(abandoned.committed());
            assertEquals(
                    PosixMetadataLogScanner.FailureReason.ABANDONED_BY_RECOVERY,
                    abandoned.failureReason().orElseThrow());
            assertEquals(abandoned, engine.resolve(transactionId));
            MetadataStoreException unissued = assertThrows(
                    MetadataStoreException.class,
                    () -> engine.resolve(new MetadataTransactionId(
                            STORE_ID, "00000000000000000000000000000009")));
            assertEquals(
                    zeroecho.pki.spi.store.MetadataCommitResult.FailureCategory.TRANSACTION_NOT_ISSUED,
                    unissued.category());
            assertEquals("00000000000000000000000000000002", engine.issue().token());
        }
        PosixMetadataLogScanner.RecoveryResult recovered = scan(path);
        assertEquals(1L, recovered.recoveryEpoch());
        assertEquals(2, recovered.transactions().size());
        assertEquals(
                PosixMetadataLogScanner.FailureReason.ABANDONED_BY_RECOVERY.code(),
                recovered.transactions().get(transactionId).terminal().orElseThrow()
                        .failureCode().orElseThrow());
        assertEquals(1L, recovered.openTransactionCount());
        System.out.println("...ok");
    }

    @Test
    void committedOutcomeSurvivesOwnedContentCleanupFailure() throws IOException {
        System.out.print("committedOutcomeSurvivesOwnedContentCleanupFailure ");
        Path path = temporaryDirectory.resolve("cleanup-committed.log");
        MetadataKey key = key("cleanup-committed");
        CountingContent content = new CountingContent(new byte[] {4}, true);
        AtomicInteger warnings = new AtomicInteger();
        Logger logger = Logger.getLogger(PosixMetadataStoreEngine.class.getName());
        Handler handler = cleanupWarningHandler(warnings);
        logger.addHandler(handler);
        try (PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.create(path, STORE_ID)) {
            MetadataTransactionId transactionId = engine.issue();
            PosixMetadataStoreEngine.CommitResult committed = engine.commit(
                    transactionId,
                    List.of(PosixMetadataStoreEngine.PreparedMutation.create(
                            key, content, CancellationSignal.NONE)));
            assertTrue(committed.committed());
            assertEquals(committed, engine.resolve(transactionId));
            assertEquals(committed, engine.resolve(transactionId));
            assertTrue(engine.lookup(key).isPresent());
        } finally {
            logger.removeHandler(handler);
        }
        assertEquals(1, content.closeCount());
        assertEquals(1, warnings.get());
        System.out.println("...ok");
    }

    @Test
    void rejectedOutcomeSurvivesOwnedContentCleanupFailure() throws IOException {
        System.out.print("rejectedOutcomeSurvivesOwnedContentCleanupFailure ");
        Path path = temporaryDirectory.resolve("cleanup-rejected.log");
        MetadataKey key = key("cleanup-rejected");
        CountingContent content = new CountingContent(new byte[] {5}, true);
        AtomicInteger warnings = new AtomicInteger();
        Logger logger = Logger.getLogger(PosixMetadataStoreEngine.class.getName());
        Handler handler = cleanupWarningHandler(warnings);
        logger.addHandler(handler);
        try (PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.create(path, STORE_ID)) {
            engine.commit(engine.issue(), List.of(create(key, "existing")));
            MetadataTransactionId transactionId = engine.issue();
            PosixMetadataStoreEngine.CommitResult rejected = engine.commit(
                    transactionId,
                    List.of(PosixMetadataStoreEngine.PreparedMutation.create(
                            key, content, CancellationSignal.NONE)));
            assertFalse(rejected.committed());
            assertEquals(
                    PosixMetadataLogScanner.FailureReason.TRANSACTION_CONFLICT,
                    rejected.failureReason().orElseThrow());
            assertEquals(rejected, engine.resolve(transactionId));
            assertEquals(rejected, engine.resolve(transactionId));
            assertEquals(1L, engine.storeRevision());
            assertTrue(engine.lookup(key).isPresent());
        } finally {
            logger.removeHandler(handler);
        }
        assertEquals(1, content.closeCount());
        assertEquals(1, warnings.get());
        System.out.println("...ok");
    }

    @Test
    void committedOutcomeSurvivesRuntimeCleanupAndClosesRemainingResources() throws IOException {
        System.out.print("committedOutcomeSurvivesRuntimeCleanupAndClosesRemainingResources ");
        Path path = temporaryDirectory.resolve("cleanup-runtime-committed.log");
        MetadataKey firstKey = key("runtime-first");
        MetadataKey secondKey = key("runtime-second");
        CountingContent failing = new CountingContent(new byte[] {6}, CloseFailure.RUNTIME);
        CountingContent remaining = new CountingContent(new byte[] {7});
        AtomicInteger warnings = new AtomicInteger();
        Logger logger = Logger.getLogger(PosixMetadataStoreEngine.class.getName());
        Handler handler = cleanupWarningHandler(warnings);
        logger.addHandler(handler);
        try (PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.create(path, STORE_ID)) {
            MetadataTransactionId transactionId = engine.issue();
            PosixMetadataStoreEngine.CommitResult committed = engine.commit(
                    transactionId,
                    List.of(
                            PosixMetadataStoreEngine.PreparedMutation.create(
                                    firstKey, failing, CancellationSignal.NONE),
                            PosixMetadataStoreEngine.PreparedMutation.create(
                                    secondKey, remaining, CancellationSignal.NONE)));
            assertTrue(committed.committed());
            assertEquals(committed, engine.resolve(transactionId));
            assertTrue(engine.lookup(firstKey).isPresent());
            assertTrue(engine.lookup(secondKey).isPresent());
        } finally {
            logger.removeHandler(handler);
        }
        assertEquals(1, failing.closeCount());
        assertEquals(1, remaining.closeCount());
        assertEquals(1, warnings.get());
        System.out.println("...ok");
    }

    @Test
    void rejectedOutcomeSurvivesRuntimeCleanupAndClosesRemainingResources() throws IOException {
        System.out.print("rejectedOutcomeSurvivesRuntimeCleanupAndClosesRemainingResources ");
        Path path = temporaryDirectory.resolve("cleanup-runtime-rejected.log");
        MetadataKey existing = key("runtime-existing");
        MetadataKey untouched = key("runtime-untouched");
        CountingContent failing = new CountingContent(new byte[] {8}, CloseFailure.RUNTIME);
        CountingContent remaining = new CountingContent(new byte[] {9});
        AtomicInteger warnings = new AtomicInteger();
        Logger logger = Logger.getLogger(PosixMetadataStoreEngine.class.getName());
        Handler handler = cleanupWarningHandler(warnings);
        logger.addHandler(handler);
        try (PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.create(path, STORE_ID)) {
            engine.commit(engine.issue(), List.of(create(existing, "existing")));
            MetadataTransactionId transactionId = engine.issue();
            PosixMetadataStoreEngine.CommitResult rejected = engine.commit(
                    transactionId,
                    List.of(
                            PosixMetadataStoreEngine.PreparedMutation.create(
                                    existing, failing, CancellationSignal.NONE),
                            PosixMetadataStoreEngine.PreparedMutation.create(
                                    untouched, remaining, CancellationSignal.NONE)));
            assertFalse(rejected.committed());
            assertEquals(rejected, engine.resolve(transactionId));
            assertTrue(engine.lookup(existing).isPresent());
            assertTrue(engine.lookup(untouched).isEmpty());
        } finally {
            logger.removeHandler(handler);
        }
        assertEquals(1, failing.closeCount());
        assertEquals(1, remaining.closeCount());
        assertEquals(1, warnings.get());
        System.out.println("...ok");
    }

    @Test
    void throwingWarningHandlerCannotReplaceAuthoritativeOutcome() throws IOException {
        System.out.print("throwingWarningHandlerCannotReplaceAuthoritativeOutcome ");
        Path path = temporaryDirectory.resolve("cleanup-logging.log");
        CountingContent content = new CountingContent(new byte[] {10}, true);
        Logger logger = Logger.getLogger(PosixMetadataStoreEngine.class.getName());
        Handler throwing = new Handler() {
            @Override
            public void publish(LogRecord record) {
                throw new IllegalStateException("injected logging failure");
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        logger.addHandler(throwing);
        try (PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.create(path, STORE_ID)) {
            MetadataTransactionId transactionId = engine.issue();
            PosixMetadataStoreEngine.CommitResult committed = engine.commit(
                    transactionId,
                    List.of(PosixMetadataStoreEngine.PreparedMutation.create(
                            key("logging"), content, CancellationSignal.NONE)));
            assertTrue(committed.committed());
            assertEquals(committed, engine.resolve(transactionId));
        } finally {
            logger.removeHandler(throwing);
        }
        assertEquals(1, content.closeCount());
        System.out.println("...ok");
    }

    private static MetadataKey key(String logicalKey) {
        return new MetadataKey("example.engine", logicalKey);
    }

    private static PosixMetadataStoreEngine.PreparedMutation create(MetadataKey key, String value)
            throws IOException {
        return PosixMetadataStoreEngine.PreparedMutation.create(
                key,
                new ImmutableByteContent(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                CancellationSignal.NONE);
    }

    private static PosixMetadataStoreEngine.PreparedMutation replace(
            MetadataKey key, long revision, String value) throws IOException {
        return PosixMetadataStoreEngine.PreparedMutation.replace(
                key,
                revision,
                new ImmutableByteContent(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                CancellationSignal.NONE);
    }

    private static PosixMetadataStoreEngine.PreparedMutation delete(MetadataKey key, long revision) {
        return PosixMetadataStoreEngine.PreparedMutation.delete(key, revision);
    }

    private static PosixMetadataLogScanner.RecoveryResult scan(Path path) throws IOException {
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            return PosixMetadataLogScanner.scan(channel);
        }
    }

    private static PosixMetadataLogScanner.ReplayResult replay(Path path) throws IOException {
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            return PosixMetadataLogScanner.replay(channel);
        }
    }

    private static Handler cleanupWarningHandler(AtomicInteger warnings) {
        return new Handler() {
            @Override
            public void publish(LogRecord record) {
                if (record.getLevel().intValue() >= Level.WARNING.intValue()) {
                    assertEquals(
                            "POSIX metadata transaction resources could not be fully retired after a known outcome",
                            record.getMessage());
                    assertEquals(null, record.getThrown());
                    assertEquals(null, record.getParameters());
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
    }

    private static final class CountingContent implements RepeatableContent {
        private final byte[] bytes;
        private final CloseFailure closeFailure;
        private final AtomicInteger closes = new AtomicInteger();

        private CountingContent(byte[] bytes) {
            this(bytes, CloseFailure.NONE);
        }

        private CountingContent(byte[] bytes, boolean failOnClose) {
            this(bytes, failOnClose ? CloseFailure.IO : CloseFailure.NONE);
        }

        private CountingContent(byte[] bytes, CloseFailure closeFailure) {
            this.bytes = bytes.clone();
            this.closeFailure = closeFailure;
        }

        @Override
        public InputStream openStream() {
            return new ByteArrayInputStream(bytes);
        }

        @Override
        public OptionalLong length() {
            return OptionalLong.of(bytes.length);
        }

        @Override
        public String contentId() {
            return "counting:test";
        }

        @Override
        public void close() throws IOException {
            closes.incrementAndGet();
            if (closeFailure == CloseFailure.IO) {
                throw new IOException("injected cleanup detail");
            }
            if (closeFailure == CloseFailure.RUNTIME) {
                throw new IllegalStateException("injected runtime cleanup detail");
            }
        }

        private int closeCount() {
            return closes.get();
        }
    }

    private enum CloseFailure {
        NONE,
        IO,
        RUNTIME
    }
}
