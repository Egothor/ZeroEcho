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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataCursor;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataStoreCapabilities;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.MetadataTransactionId;

final class DurableTransactionalMetadataStoreTest {
    private static final MetadataStoreId STORE_ID =
            new MetadataStoreId("00112233445566778899aabbccddeeff");
    private static final MetadataKey FIRST = new MetadataKey("example.records", "a");
    private static final MetadataKey SECOND = new MetadataKey("example.records", "b");

    @TempDir
    Path temporaryDirectory;

    @Test
    void capabilitiesLifecycleAuthorityAndThreadConfinement() throws Exception {
        System.out.print("capabilitiesLifecycleAuthorityAndThreadConfinement ");
        Path path = temporaryDirectory.resolve("authority.log");
        MetadataTransactionId issued;
        try (DurableTransactionalMetadataStore store =
                DurableTransactionalMetadataStore.create(path, STORE_ID)) {
            assertEquals(STORE_ID, store.id());
            MetadataStoreCapabilities capabilities = store.capabilities();
            assertEquals(MetadataStoreCapabilities.WriterModel.EXCLUSIVE_WRITER,
                    capabilities.writerModel());
            assertEquals(MetadataStoreCapabilities.ContentLengthModel.KNOWN_LENGTH_ONLY,
                    capabilities.contentLengthModel());
            assertEquals(MetadataStoreCapabilities.OutcomeRetention.INDEFINITE,
                    capabilities.outcomeRetention());
            assertEquals(Set.of(MetadataStoreCapabilities.OptionalFeature.CROSS_PROCESS_COORDINATION),
                    capabilities.optionalFeatures());
            assertTrue(capabilities.maximumIndividualRecordBytes().isEmpty());

            MetadataTransaction transaction = store.beginTransaction();
            issued = transaction.id();
            try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
                Future<Void> foreignThread = executor.submit(() -> {
                    transaction.delete(FIRST, 0L);
                    return null;
                });
                assertTrue(assertThrows(ExecutionException.class, foreignThread::get)
                        .getCause() instanceof IllegalStateException);
            }
            transaction.abort();
            assertThrows(IllegalStateException.class, transaction::commit);
            transaction.close();

            MetadataTransactionId unissued = new MetadataTransactionId(
                    STORE_ID, "ffffffffffffffffffffffffffffffff");
            MetadataStoreException absent = assertThrows(
                    MetadataStoreException.class, () -> store.resolve(unissued));
            assertEquals(MetadataCommitResult.FailureCategory.TRANSACTION_NOT_ISSUED,
                    absent.category());
            MetadataStoreException foreign = assertThrows(
                    MetadataStoreException.class,
                    () -> store.resolve(new MetadataTransactionId(
                            new MetadataStoreId("ffeeddccbbaa99887766554433221100"),
                            issued.token())));
            assertEquals(MetadataCommitResult.FailureCategory.FOREIGN_TRANSACTION,
                    foreign.category());
        }
        try (DurableTransactionalMetadataStore reopened =
                DurableTransactionalMetadataStore.open(path)) {
            assertEquals(STORE_ID, reopened.id());
            assertCategory(reopened.resolve(issued), MetadataCommitResult.Outcome.NOT_COMMITTED,
                    MetadataCommitResult.FailureCategory.ABANDONED_BY_RECOVERY);
        }
        DurableTransactionalMetadataStore closed = DurableTransactionalMetadataStore.open(path);
        closed.close();
        closed.close();
        assertThrows(IllegalStateException.class, closed::beginTransaction);
        System.out.println("...ok");
    }

    @Test
    void admissionDetachesKnownContentAndRejectsUnsupportedOrInvalidSources() throws Exception {
        System.out.print("admissionDetachesKnownContentAndRejectsUnsupportedOrInvalidSources ");
        Path path = temporaryDirectory.resolve("admission.log");
        try (DurableTransactionalMetadataStore store = DurableTransactionalMetadataStore.create(
                        path, STORE_ID, OptionalLong.of(5L));
                MetadataTransaction transaction = store.beginTransaction()) {
            ProbeContent known = new ProbeContent("five", OptionalLong.of(4L));
            transaction.create(FIRST, known, CancellationSignal.NONE);
            known.invalidate();
            assertEquals(1, known.opens.get());

            ProbeContent unknown = new ProbeContent("x", OptionalLong.empty());
            MetadataStoreException unsupported = assertThrows(
                    MetadataStoreException.class,
                    () -> transaction.create(SECOND, unknown, CancellationSignal.NONE));
            assertEquals(MetadataCommitResult.FailureCategory.UNSUPPORTED_CAPABILITY,
                    unsupported.category());
            assertEquals(0, unknown.opens.get());

            MetadataStoreException limit = assertThrows(
                    MetadataStoreException.class,
                    () -> transaction.create(
                            new MetadataKey("example.records", "limit"),
                            new ProbeContent("123456", OptionalLong.of(6L)),
                            CancellationSignal.NONE));
            assertEquals(MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED, limit.category());

            ProbeContent cancelled = new ProbeContent("x", OptionalLong.of(1L));
            MetadataStoreException cancellation = assertThrows(
                    MetadataStoreException.class,
                    () -> transaction.create(
                            new MetadataKey("example.records", "cancel"),
                            cancelled,
                            () -> true));
            assertEquals(MetadataCommitResult.FailureCategory.CANCELLED, cancellation.category());
            assertEquals(0, cancelled.opens.get());

            MetadataStoreException shortValue = assertThrows(
                    MetadataStoreException.class,
                    () -> transaction.create(
                            new MetadataKey("example.records", "short"),
                            new ProbeContent("x", OptionalLong.of(2L)),
                            CancellationSignal.NONE));
            assertEquals(MetadataCommitResult.FailureCategory.STORAGE_FAILURE,
                    shortValue.category());
            MetadataStoreException excess = assertThrows(
                    MetadataStoreException.class,
                    () -> transaction.create(
                            new MetadataKey("example.records", "excess"),
                            new ProbeContent("xx", OptionalLong.of(1L)),
                            CancellationSignal.NONE));
            assertEquals(MetadataCommitResult.FailureCategory.STORAGE_FAILURE, excess.category());

            MetadataCommitResult committed = transaction.commit();
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, committed.outcome());
            assertTrue(committed.failureCategory().isEmpty());
            assertEquals("five", read(store.snapshot(), FIRST));
        }
        System.out.println("...ok");
    }

    @Test
    void createReplaceDeleteMultiKeyAndEmptyCommitUseExactRevisions() throws Exception {
        System.out.print("createReplaceDeleteMultiKeyAndEmptyCommitUseExactRevisions ");
        Path path = temporaryDirectory.resolve("transactions.log");
        try (DurableTransactionalMetadataStore store =
                DurableTransactionalMetadataStore.create(path, STORE_ID)) {
            try (MetadataTransaction transaction = store.beginTransaction()) {
                transaction.create(FIRST, content("one"), CancellationSignal.NONE);
                transaction.create(new MetadataKey("example.other", "two"),
                        content("two"), CancellationSignal.NONE);
                assertEquals(1L, transaction.commit().committedRevision().orElseThrow());
            }
            try (MetadataSnapshot snapshot = store.snapshot()) {
                assertEquals(1L, snapshot.revision());
                assertEquals(1L, snapshot.get(FIRST).orElseThrow().recordRevision());
            }
            try (MetadataTransaction transaction = store.beginTransaction()) {
                transaction.replace(FIRST, 1L, content("updated"), CancellationSignal.NONE);
                transaction.delete(new MetadataKey("example.other", "two"), 1L);
                assertEquals(2L, transaction.commit().committedRevision().orElseThrow());
            }
            try (MetadataTransaction transaction = store.beginTransaction()) {
                assertEquals(3L, transaction.commit().committedRevision().orElseThrow());
            }
            try (MetadataSnapshot snapshot = store.snapshot()) {
                assertEquals(3L, snapshot.revision());
                assertEquals("updated", read(snapshot, FIRST));
                assertTrue(snapshot.get(new MetadataKey("example.other", "two")).isEmpty());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void conflictIsAtomicTerminalResolvableAndDistinct() throws Exception {
        System.out.print("conflictIsAtomicTerminalResolvableAndDistinct ");
        Path path = temporaryDirectory.resolve("conflict.log");
        try (DurableTransactionalMetadataStore store =
                DurableTransactionalMetadataStore.create(path, STORE_ID)) {
            create(store, FIRST, "original");
            MetadataTransaction transaction = store.beginTransaction();
            transaction.create(FIRST, content("conflict"), CancellationSignal.NONE);
            transaction.create(SECOND, content("hidden"), CancellationSignal.NONE);
            MetadataCommitResult rejected = transaction.commit();
            assertCategory(rejected, MetadataCommitResult.Outcome.NOT_COMMITTED,
                    MetadataCommitResult.FailureCategory.CONFLICT);
            assertEquals(rejected, store.resolve(transaction.id()));
            assertEquals(rejected, store.resolve(transaction.id()));
            store.acknowledge(transaction.id());
            assertThrows(IllegalStateException.class, transaction::commit);
            try (MetadataSnapshot snapshot = store.snapshot()) {
                assertEquals("original", read(snapshot, FIRST));
                assertTrue(snapshot.get(SECOND).isEmpty());
            }
            transaction.close();
        }
        System.out.println("...ok");
    }

    @Test
    void abortAndConflictRetireEveryDetachedSpool() throws Exception {
        System.out.print("abortAndConflictRetireEveryDetachedSpool ");
        Path path = temporaryDirectory.resolve("cleanup.log");
        CountingStaging staging = new CountingStaging();
        try (DurableTransactionalMetadataStore store =
                DurableTransactionalMetadataStore.createForTest(
                        path, STORE_ID, OptionalLong.empty(), staging,
                        DurableMetadataLog.FaultInjector.NONE,
                        DurableMetadataStoreEngine.FaultInjector.NONE)) {
            try (MetadataTransaction aborted = store.beginTransaction()) {
                aborted.create(FIRST, content("aborted"), CancellationSignal.NONE);
                aborted.abort();
            }
            assertEquals(0, staging.liveFiles());
            create(store, FIRST, "existing");
            try (MetadataTransaction conflict = store.beginTransaction()) {
                conflict.create(FIRST, content("conflict"), CancellationSignal.NONE);
                assertEquals(MetadataCommitResult.Outcome.NOT_COMMITTED,
                        conflict.commit().outcome());
            }
            assertEquals(0, staging.liveFiles());
        }
        assertEquals(0, staging.liveFiles());
        System.out.println("...ok");
    }

    @Test
    void cleanupFailureCannotReplaceAuthoritativeOutcome() throws Exception {
        System.out.print("cleanupFailureCannotReplaceAuthoritativeOutcome ");
        Path path = temporaryDirectory.resolve("cleanup-failure.log");
        CountingStaging staging = new CountingStaging();
        staging.failNextDelete.set(true);
        MetadataTransactionId transactionId;
        try (DurableTransactionalMetadataStore store =
                DurableTransactionalMetadataStore.createForTest(
                        path, STORE_ID, OptionalLong.empty(), staging,
                        DurableMetadataLog.FaultInjector.NONE,
                        DurableMetadataStoreEngine.FaultInjector.NONE)) {
            MetadataTransaction transaction = store.beginTransaction();
            transactionId = transaction.id();
            transaction.create(FIRST, content("committed"), CancellationSignal.NONE);
            MetadataCommitResult committed = transaction.commit();
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, committed.outcome());
            assertEquals(committed, store.resolve(transactionId));
            assertEquals("committed", read(store.snapshot(), FIRST));
            transaction.close();
        }
        staging.removeResidue();
        assertEquals(0, staging.liveFiles());
        System.out.println("...ok");
    }

    @Test
    void snapshotsRemainStableAndRecordSlicesNeverReadLaterBytes() throws Exception {
        System.out.print("snapshotsRemainStableAndRecordSlicesNeverReadLaterBytes ");
        Path path = temporaryDirectory.resolve("snapshots.log");
        try (DurableTransactionalMetadataStore store =
                DurableTransactionalMetadataStore.create(path, STORE_ID)) {
            create(store, FIRST, "old");
            MetadataSnapshot old = store.snapshot();
            MetadataSnapshot.Record oldRecord = old.get(FIRST).orElseThrow();
            replace(store, FIRST, 1L, "new-value");
            create(store, SECOND, "later");
            assertEquals("old", read(oldRecord));
            assertEquals("old", read(oldRecord));
            assertEquals(3L, oldRecord.length().orElseThrow());
            try (MetadataSnapshot current = store.snapshot()) {
                assertEquals("new-value", read(current, FIRST));
                assertEquals("later", read(current, SECOND));
            }
            old.close();
            assertThrows(IllegalStateException.class, oldRecord::openStream);
        }
        System.out.println("...ok");
    }

    @Test
    void cursorIsLazyOrderedRangeBoundedAndInvalidatesCurrentRecord() throws Exception {
        System.out.print("cursorIsLazyOrderedRangeBoundedAndInvalidatesCurrentRecord ");
        Path path = temporaryDirectory.resolve("cursor.log");
        try (DurableTransactionalMetadataStore store =
                DurableTransactionalMetadataStore.create(path, STORE_ID)) {
            try (MetadataTransaction transaction = store.beginTransaction()) {
                transaction.create(new MetadataKey("example.records", "a"),
                        content("a"), CancellationSignal.NONE);
                transaction.create(new MetadataKey("example.records", "ab"),
                        content("ab"), CancellationSignal.NONE);
                transaction.create(new MetadataKey("example.records", "b"),
                        content("b"), CancellationSignal.NONE);
                transaction.create(new MetadataKey("example.other", "a"),
                        content("other"), CancellationSignal.NONE);
                transaction.commit();
            }
            MetadataSnapshot snapshot = store.snapshot();
            MetadataCursor cursor = snapshot.scan(
                    MetadataSnapshot.KeyRange.prefix("example.records", "a"),
                    CancellationSignal.NONE);
            MetadataSnapshot.Record first = cursor.next(CancellationSignal.NONE).orElseThrow();
            assertEquals("a", first.key().key());
            MetadataSnapshot.Record second = cursor.next(CancellationSignal.NONE).orElseThrow();
            assertThrows(IllegalStateException.class, first::key);
            assertEquals("ab", second.key().key());
            assertTrue(cursor.next(CancellationSignal.NONE).isEmpty());
            assertThrows(IOException.class, () -> cursor.next(() -> true));
            cursor.close();
            cursor.close();
            assertThrows(IllegalStateException.class,
                    () -> cursor.next(CancellationSignal.NONE));
            MetadataCursor child = snapshot.scan(
                    MetadataSnapshot.KeyRange.all("example.records"),
                    CancellationSignal.NONE);
            snapshot.close();
            assertThrows(IllegalStateException.class,
                    () -> child.next(CancellationSignal.NONE));
        }
        System.out.println("...ok");
    }

    @Test
    void uncertainCommitResolvesAfterReopenWithoutReexecution() throws Exception {
        System.out.print("uncertainCommitResolvesAfterReopenWithoutReexecution ");
        Path path = temporaryDirectory.resolve("unknown.log");
        DurableMetadataStoreEngine.FaultInjector fault = point -> {
            if (point == DurableMetadataStoreEngine.FaultPoint.POST_FORCE_PUBLICATION) {
                throw new IOException("injected");
            }
        };
        MetadataTransactionId transactionId;
        DurableTransactionalMetadataStore store = DurableTransactionalMetadataStore.createForTest(
                path, STORE_ID, OptionalLong.empty(), new CountingStaging(),
                DurableMetadataLog.FaultInjector.NONE, fault);
        try {
            MetadataTransaction transaction = store.beginTransaction();
            transactionId = transaction.id();
            transaction.create(FIRST, content("fixed"), CancellationSignal.NONE);
            MetadataCommitResult immediate = transaction.commit();
            assertCategory(immediate, MetadataCommitResult.Outcome.UNKNOWN,
                    MetadataCommitResult.FailureCategory.STORAGE_FAILURE);
            assertThrows(IllegalStateException.class, store::snapshot);
            transaction.close();
        } finally {
            store.close();
        }
        try (DurableTransactionalMetadataStore reopened =
                DurableTransactionalMetadataStore.open(path)) {
            MetadataCommitResult resolved = reopened.resolve(transactionId);
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, resolved.outcome());
            assertEquals(resolved, reopened.resolve(transactionId));
            assertEquals("fixed", read(reopened.snapshot(), FIRST));
        }
        System.out.println("...ok");
    }

    @Test
    void recoveryAbandonmentConflictStorageAndUnknownCategoriesRemainDistinct() throws Exception {
        System.out.print("recoveryAbandonmentConflictStorageAndUnknownCategoriesRemainDistinct ");
        Path path = temporaryDirectory.resolve("categories.log");
        MetadataTransactionId abandonedId;
        try (DurableTransactionalMetadataStore store =
                DurableTransactionalMetadataStore.create(path, STORE_ID)) {
            create(store, FIRST, "existing");
            MetadataTransaction abandoned = store.beginTransaction();
            abandonedId = abandoned.id();
        }
        try (DurableTransactionalMetadataStore reopened =
                DurableTransactionalMetadataStore.open(path)) {
            MetadataCommitResult abandoned = reopened.resolve(abandonedId);
            assertCategory(abandoned, MetadataCommitResult.Outcome.NOT_COMMITTED,
                    MetadataCommitResult.FailureCategory.ABANDONED_BY_RECOVERY);
            assertEquals(abandoned, reopened.resolve(abandonedId));

            MetadataTransaction conflict = reopened.beginTransaction();
            conflict.create(FIRST, content("duplicate"), CancellationSignal.NONE);
            MetadataCommitResult rejected = conflict.commit();
            assertCategory(rejected, MetadataCommitResult.Outcome.NOT_COMMITTED,
                    MetadataCommitResult.FailureCategory.CONFLICT);
            assertNotEquals(abandoned.failureCategory(), rejected.failureCategory());
            conflict.close();

            MetadataTransaction storage = reopened.beginTransaction();
            MetadataStoreException storageFailure = assertThrows(
                    MetadataStoreException.class,
                    () -> storage.create(SECOND, new FailingContent(), CancellationSignal.NONE));
            assertEquals(MetadataCommitResult.FailureCategory.STORAGE_FAILURE,
                    storageFailure.category());
            storage.abort();
        }
        System.out.println("...ok");
    }

    @Test
    void closeRejectsBlockedAdmissionAndConsumesReservationExactlyOnce() throws Exception {
        System.out.print("closeRejectsBlockedAdmissionAndConsumesReservationExactlyOnce ");
        Path path = temporaryDirectory.resolve("admission-close.log");
        CountingStaging staging = new CountingStaging();
        BlockingContent content = new BlockingContent("blocked");
        DurableTransactionalMetadataStore store = DurableTransactionalMetadataStore.createForTest(
                path, STORE_ID, OptionalLong.empty(), staging,
                DurableMetadataLog.FaultInjector.NONE,
                DurableMetadataStoreEngine.FaultInjector.NONE);
        try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
            Future<Void> admission = executor.submit(() -> {
                try (MetadataTransaction transaction = store.beginTransaction()) {
                    transaction.create(FIRST, content, CancellationSignal.NONE);
                }
                return null;
            });
            content.awaitRead();
            Future<Void> closing = executor.submit(() -> {
                store.close();
                return null;
            });
            store.awaitClosingForTest();
            content.release();
            ExecutionException rejected = assertThrows(ExecutionException.class, admission::get);
            assertTrue(rejected.getCause() instanceof IllegalStateException);
            closing.get();
        }
        assertEquals(0, store.activeOperationsForTest());
        assertEquals(1, staging.deleteAttempts.get());
        assertEquals(0, staging.liveFiles());
        assertEquals(1, content.closeCount.get());
        System.out.println("...ok");
    }

    @Test
    void closeRacesRejectDeleteAndCommitBeginFailureLeavesCleanupPossible() throws Exception {
        System.out.print("closeRacesRejectDeleteAndCommitBeginFailureLeavesCleanupPossible ");
        Path closePath = temporaryDirectory.resolve("delete-close.log");
        DurableTransactionalMetadataStore closingStore =
                DurableTransactionalMetadataStore.create(closePath, STORE_ID);
        MetadataTransaction deleting = closingStore.beginTransaction();
        try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
            Future<Void> closing = executor.submit(() -> {
                closingStore.close();
                return null;
            });
            closingStore.awaitClosingForTest();
            assertThrows(IllegalStateException.class, () -> deleting.delete(FIRST, 0L));
            closing.get();
        }
        deleting.close();
        assertEquals(0, closingStore.activeOperationsForTest());

        Path recoveryPath = temporaryDirectory.resolve("commit-recovery.log");
        CountingStaging staging = new CountingStaging();
        DurableMetadataStoreEngine.FaultInjector uncertainty = point -> {
            if (point == DurableMetadataStoreEngine.FaultPoint.POST_FORCE_PUBLICATION) {
                throw new IOException("injected publication uncertainty");
            }
        };
        DurableTransactionalMetadataStore recoveryStore =
                DurableTransactionalMetadataStore.createForTest(
                        recoveryPath, STORE_ID, OptionalLong.empty(), staging,
                        DurableMetadataLog.FaultInjector.NONE, uncertainty);
        try {
            MetadataTransaction uncertain = recoveryStore.beginTransaction();
            MetadataTransaction pending = recoveryStore.beginTransaction();
            uncertain.create(FIRST, content("one"), CancellationSignal.NONE);
            pending.create(SECOND, content("two"), CancellationSignal.NONE);
            assertEquals(MetadataCommitResult.Outcome.UNKNOWN, uncertain.commit().outcome());
            assertThrows(IllegalStateException.class, pending::commit);
            pending.abort();
            uncertain.close();
            pending.close();
            assertEquals(0, staging.liveFiles());
        } finally {
            recoveryStore.close();
        }
        System.out.println("...ok");
    }

    @Test
    void stagingCleanupFailureIsSuppressedBehindSourceAndWriteFailures() throws Exception {
        System.out.print("stagingCleanupFailureIsSuppressedBehindSourceAndWriteFailures ");
        Path path = temporaryDirectory.resolve("staging-suppression.log");
        CountingStaging staging = new CountingStaging();
        try (DurableTransactionalMetadataStore store =
                DurableTransactionalMetadataStore.createForTest(
                        path, STORE_ID, OptionalLong.empty(), staging,
                        DurableMetadataLog.FaultInjector.NONE,
                        DurableMetadataStoreEngine.FaultInjector.NONE)) {
            MetadataTransaction transaction = store.beginTransaction();
            staging.failNextDelete.set(true);
            MetadataStoreException sourceFailure = assertThrows(
                    MetadataStoreException.class,
                    () -> transaction.create(
                            FIRST, new FailingContent(), CancellationSignal.NONE));
            assertEquals(1, sourceFailure.getSuppressed().length);

            staging.failNextOpenWrite.set(true);
            staging.failNextDelete.set(true);
            MetadataStoreException writeFailure = assertThrows(
                    MetadataStoreException.class,
                    () -> transaction.create(SECOND, content("write"), CancellationSignal.NONE));
            assertEquals(1, writeFailure.getSuppressed().length);
            transaction.abort();
        }
        assertEquals(2, staging.deleteAttempts.get());
        staging.removeResidue();
        assertEquals(0, staging.liveFiles());
        System.out.println("...ok");
    }

    @Test
    void storeCloseContinuesAcrossThrowingChildrenAndReleasesWriter() throws Exception {
        System.out.print("storeCloseContinuesAcrossThrowingChildrenAndReleasesWriter ");
        Path path = temporaryDirectory.resolve("continued-close.log");
        DurableMetadataStoreEngine engine = DurableMetadataStoreEngine.create(path, STORE_ID);
        DurableMetadataAdapterLifecycle lifecycle = new DurableMetadataAdapterLifecycle();
        AtomicInteger attempts = new AtomicInteger();
        lifecycle.openManaged(() -> () -> {
            attempts.incrementAndGet();
            return new IOException("first cleanup failure");
        });
        lifecycle.openManaged(() -> () -> {
            attempts.incrementAndGet();
            return new IOException("second cleanup failure");
        });
        lifecycle.openManaged(() -> () -> {
            attempts.incrementAndGet();
            return new IOException("later cleanup failure");
        });
        IOException closeFailure = assertThrows(IOException.class, () -> lifecycle.close(engine));
        assertEquals(3, attempts.get());
        assertEquals(2, closeFailure.getSuppressed().length);
        try (DurableMetadataStoreEngine reopened = DurableMetadataStoreEngine.open(path)) {
            assertEquals(STORE_ID, reopened.storeId());
        }
        System.out.println("...ok");
    }

    @Test
    void snapshotCloseContinuesAfterChildFailuresAndContainsLoggerFailure() throws Exception {
        System.out.print("snapshotCloseContinuesAfterChildFailuresAndContainsLoggerFailure ");
        Path path = temporaryDirectory.resolve("snapshot-close-failure.log");
        AtomicInteger closeAttempts = new AtomicInteger();
        DurableMetadataSnapshotSupport.SliceOpener opener = (offset, length) ->
                new ThrowingCloseInputStream(closeAttempts);
        Logger logger = Logger.getLogger(DurableMetadataSnapshotSupport.class.getName());
        Handler throwingHandler = new ThrowingHandler();
        try (DurableTransactionalMetadataStore store =
                DurableTransactionalMetadataStore.createForTest(
                        path, STORE_ID, OptionalLong.empty(), new CountingStaging(),
                        DurableMetadataLog.FaultInjector.NONE,
                        DurableMetadataStoreEngine.FaultInjector.NONE,
                        opener)) {
            create(store, FIRST, "value");
            MetadataSnapshot snapshot = store.snapshot();
            MetadataSnapshot.Record record = snapshot.get(FIRST).orElseThrow();
            record.openStream();
            record.openStream();
            logger.addHandler(throwingHandler);
            try {
                snapshot.close();
            } finally {
                logger.removeHandler(throwingHandler);
            }
            assertEquals(2, closeAttempts.get());
            assertThrows(IllegalStateException.class, record::openStream);
        }
        System.out.println("...ok");
    }

    @Test
    void cursorCancellationRunsBeforeSnapshotLockAndRevalidatesClose() throws Exception {
        System.out.print("cursorCancellationRunsBeforeSnapshotLockAndRevalidatesClose ");
        Path path = temporaryDirectory.resolve("cursor-cancellation-lock.log");
        try (DurableTransactionalMetadataStore store =
                DurableTransactionalMetadataStore.create(path, STORE_ID)) {
            create(store, FIRST, "value");
            MetadataSnapshot snapshot = store.snapshot();
            MetadataCursor cursor = snapshot.scan(
                    MetadataSnapshot.KeyRange.all("example.records"),
                    CancellationSignal.NONE);
            CancellationSignal closesSnapshot = () -> {
                snapshot.close();
                return false;
            };
            assertThrows(IllegalStateException.class, () -> cursor.next(closesSnapshot));
            cursor.close();
        }
        System.out.println("...ok");
    }

    private static void create(
            DurableTransactionalMetadataStore store, MetadataKey key, String value) throws Exception {
        try (MetadataTransaction transaction = store.beginTransaction()) {
            transaction.create(key, content(value), CancellationSignal.NONE);
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
        }
    }

    private static void replace(
            DurableTransactionalMetadataStore store,
            MetadataKey key,
            long expectedRevision,
            String value) throws Exception {
        try (MetadataTransaction transaction = store.beginTransaction()) {
            transaction.replace(key, expectedRevision, content(value), CancellationSignal.NONE);
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
        }
    }

    private static RepeatableContent content(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        return new ProbeContent(bytes, OptionalLong.of(bytes.length));
    }

    private static String read(MetadataSnapshot snapshot, MetadataKey key) throws Exception {
        try (MetadataSnapshot.Record record = snapshot.get(key).orElseThrow()) {
            return read(record);
        }
    }

    private static String read(MetadataSnapshot.Record record) throws Exception {
        try (InputStream input = record.openStream()) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static void assertCategory(
            MetadataCommitResult result,
            MetadataCommitResult.Outcome outcome,
            MetadataCommitResult.FailureCategory category) {
        assertEquals(outcome, result.outcome());
        assertEquals(Optional.of(category), result.failureCategory());
    }

    private static final class ProbeContent implements RepeatableContent {
        private final byte[] bytes;
        private final OptionalLong length;
        private final AtomicBoolean valid = new AtomicBoolean(true);
        private final AtomicInteger opens = new AtomicInteger();

        private ProbeContent(String value, OptionalLong length) {
            this(value.getBytes(StandardCharsets.UTF_8), length);
        }

        private ProbeContent(byte[] bytes, OptionalLong length) {
            this.bytes = bytes.clone();
            this.length = length;
        }

        @Override
        public InputStream openStream() throws IOException {
            if (!valid.get()) {
                throw new IOException("invalidated probe");
            }
            opens.incrementAndGet();
            return new ByteArrayInputStream(bytes);
        }

        @Override
        public OptionalLong length() {
            return length;
        }

        @Override
        public String contentId() {
            return "probe";
        }

        @Override
        public void close() {
            valid.set(false);
        }

        private void invalidate() {
            valid.set(false);
        }
    }

    private static final class FailingContent implements RepeatableContent {
        @Override
        public InputStream openStream() throws IOException {
            throw new IOException("injected source failure");
        }

        @Override
        public OptionalLong length() {
            return OptionalLong.of(1L);
        }

        @Override
        public String contentId() {
            return "failing";
        }

        @Override
        public void close() {
        }
    }

    private static final class BlockingContent implements RepeatableContent {
        private final byte[] value;
        private final CountDownLatch readStarted = new CountDownLatch(1);
        private final CountDownLatch releaseRead = new CountDownLatch(1);
        private final AtomicInteger closeCount = new AtomicInteger();

        private BlockingContent(String value) {
            this.value = value.getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public InputStream openStream() {
            return new InputStream() {
                private int position;

                @Override
                public int read() throws IOException {
                    byte[] single = new byte[1];
                    int count = read(single, 0, 1);
                    return count < 0 ? -1 : Byte.toUnsignedInt(single[0]);
                }

                @Override
                public int read(byte[] target, int offset, int length) throws IOException {
                    if (position == value.length) {
                        return -1;
                    }
                    readStarted.countDown();
                    await(releaseRead);
                    int count = Math.min(length, value.length - position);
                    System.arraycopy(value, position, target, offset, count);
                    position += count;
                    return count;
                }

                @Override
                public void close() {
                    closeCount.incrementAndGet();
                }
            };
        }

        @Override
        public OptionalLong length() {
            return OptionalLong.of(value.length);
        }

        @Override
        public String contentId() {
            return "blocking-probe";
        }

        @Override
        public void close() {
        }

        private void awaitRead() throws InterruptedException {
            readStarted.await();
        }

        private void release() {
            releaseRead.countDown();
        }

        private static void await(CountDownLatch latch) throws IOException {
            try {
                latch.await();
            } catch (InterruptedException failure) {
                Thread.currentThread().interrupt();
                throw new IOException("Blocking content probe was interrupted", failure);
            }
        }
    }

    private static final class ThrowingCloseInputStream extends ByteArrayInputStream {
        private final AtomicInteger closeAttempts;

        private ThrowingCloseInputStream(AtomicInteger closeAttempts) {
            super(new byte[] {1});
            this.closeAttempts = closeAttempts;
        }

        @Override
        public void close() throws IOException {
            closeAttempts.incrementAndGet();
            throw new IOException("injected child close failure");
        }
    }

    private static final class ThrowingHandler extends Handler {
        @Override
        public void publish(LogRecord record) {
            throw new IllegalStateException("injected JUL handler failure");
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    }

    private final class CountingStaging
            implements DurableMetadataTransactionSupport.StagingOperations {
        private final List<Path> created = new ArrayList<>();
        private final AtomicBoolean failNextDelete = new AtomicBoolean();
        private final AtomicBoolean failNextOpenWrite = new AtomicBoolean();
        private final AtomicInteger deleteAttempts = new AtomicInteger();

        @Override
        public Path create(Path parent) throws IOException {
            Path path = Files.createTempFile(parent, ".adapter-test-", ".stage");
            created.add(path);
            return path;
        }

        @Override
        public FileChannel openWrite(Path path) throws IOException {
            if (failNextOpenWrite.compareAndSet(true, false)) {
                throw new IOException("injected staging write failure");
            }
            return FileChannel.open(path,
                    Set.of(StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING,
                            LinkOption.NOFOLLOW_LINKS));
        }

        @Override
        public FileChannel openRead(Path path) throws IOException {
            return FileChannel.open(path,
                    Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS));
        }

        @Override
        public void delete(Path path) throws IOException {
            deleteAttempts.incrementAndGet();
            if (failNextDelete.compareAndSet(true, false)) {
                throw new IOException("injected cleanup failure");
            }
            Files.deleteIfExists(path);
        }

        private int liveFiles() {
            return (int) created.stream().filter(Files::exists).count();
        }

        private void removeResidue() throws IOException {
            for (Path path : created) {
                Files.deleteIfExists(path);
            }
        }
    }
}
