/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataStoreCapabilities;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.MetadataTransactionId;

final class SegmentedTransactionalMetadataStoreTest {
    private static final MetadataStoreId STORE_ID =
            new MetadataStoreId("0123456789abcdef0123456789abcdef");

    @TempDir
    private Path temporaryDirectory;

    @Test
    void createAndReopenUseExactConfiguredActiveWal() throws Exception {
        Path root = Files.createDirectory(temporaryDirectory.resolve("configured-active-wal"));
        AtomicInteger copies = new AtomicInteger();
        SigningActiveWal.Configuration defaults = SigningActiveWal.Configuration.defaults(1);
        SigningActiveWal.Configuration configured = new SigningActiveWal.Configuration(
                defaults.queueCapacity(), defaults.maximumGroupSize(),
                defaults.maximumGroupWaitNanos(), defaults.maximumQueuedPayloadBytes(),
                defaults.maximumBatchBytes(), defaults.maximumSegmentBytes(), payload -> {
                    copies.incrementAndGet();
                    return payload.clone();
                });
        long residentIndexBudgetBytes = 768L * 1024L * 1024L;
        long compactionTransientBudgetBytes = 640L * 1024L * 1024L;
        try (SegmentedTransactionalMetadataStore created =
                SegmentedTransactionalMetadataStore.create(root, STORE_ID, null,
                        SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK, configured,
                        residentIndexBudgetBytes, compactionTransientBudgetBytes)) {
            commitValue(created, new MetadataKey("configured", "create"), 1);
            assertTrue(copies.get() > 0);
            assertTrue(created.writerSnapshot().maximumBatchSize() <= 1L);
            assertEquals(residentIndexBudgetBytes,
                    created.capacitySnapshot().steady().maximumBytes());
            assertEquals(compactionTransientBudgetBytes,
                    created.capacitySnapshot().transientBudget().maximumBytes());
            assertEquals(Math.addExact(residentIndexBudgetBytes, compactionTransientBudgetBytes),
                    created.capacitySnapshot().combinedMaximumBytes());
        }

        copies.set(0);
        try (SegmentedTransactionalMetadataStore reopened =
                SegmentedTransactionalMetadataStore.open(root, STORE_ID,
                        SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK, configured,
                        residentIndexBudgetBytes, compactionTransientBudgetBytes)) {
            commitValue(reopened, new MetadataKey("configured", "reopen"), 2);
            assertTrue(copies.get() > 0);
            assertTrue(reopened.writerSnapshot().maximumBatchSize() <= 1L);
            assertEquals(residentIndexBudgetBytes,
                    reopened.capacitySnapshot().steady().maximumBytes());
            assertEquals(compactionTransientBudgetBytes,
                    reopened.capacitySnapshot().transientBudget().maximumBytes());
            assertEquals(Math.addExact(residentIndexBudgetBytes, compactionTransientBudgetBytes),
                    reopened.capacitySnapshot().combinedMaximumBytes());
        }
    }

    @Test
    void recoveryFailsClosedWhenConfiguredResidentIndexBudgetIsTooSmall() throws Exception {
        Path root = Files.createDirectory(temporaryDirectory.resolve("recovery-index-budget"));
        try (SegmentedTransactionalMetadataStore created =
                SegmentedTransactionalMetadataStore.create(root, STORE_ID)) {
            commitValue(created, new MetadataKey("configured", "recovery-budget"), 1);
        }

        // A resident-index budget smaller than the mandatory protected accepted-signing
        // floor is rejected up front by the capacity budget as an invalid argument.
        assertThrows(IllegalArgumentException.class,
                () -> SegmentedTransactionalMetadataStore.open(root, STORE_ID,
                        SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK,
                        SigningActiveWal.Configuration.defaults(), 1L,
                        FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES));
    }

    @Test
    void internalTransactionCarriesAdmissionIntoInitialSigningProjection(@TempDir Path temporary)
            throws Exception {
        Path root = Files.createDirectory(temporary.resolve("admitted-transaction"));
        MetadataKey key = new MetadataKey(SigningWorkProjection.RECORD_NAMESPACE, "operation");
        try (SegmentedTransactionalMetadataStore store =
                    SegmentedTransactionalMetadataStore.create(root, STORE_ID);
                SigningLedgerStoreEngine.SigningAdmission admission =
                        store.reserveSigningAdmission();
                MetadataTransaction transaction = store.beginTransaction(admission)) {
            transaction.create(key, content(1), CancellationSignal.NONE);
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
            try (SegmentedTransactionalMetadataStore.SigningDuePage due = store.pageSigningDue(
                    Instant.EPOCH, Optional.empty(), Optional.empty(), 1)) {
                assertEquals(List.of(new SegmentedTransactionalMetadataStore.SigningDueCandidate(
                        "operation", true)), due.candidates());
            }
        }
    }

    @Test
    void ephemeralDirectContextDoesNotAlterDurableTransactionPayload(@TempDir Path temporary)
            throws Exception {
        Path admittedRoot = Files.createDirectory(temporary.resolve("admitted-direct"));
        Path unreservedRoot = Files.createDirectory(temporary.resolve("unreserved-direct"));
        SigningTransactionPayloadCodec.Mutation record = new SigningTransactionPayloadCodec.Mutation(
                SigningTransactionPayloadCodec.MutationKind.CREATE,
                new MetadataKey(SigningWorkProjection.RECORD_NAMESPACE, "operation"),
                -1L, new byte[] { 1 });
        try (SegmentedTransactionalMetadataStore admitted =
                    SegmentedTransactionalMetadataStore.create(admittedRoot, STORE_ID);
                SigningLedgerStoreEngine.SigningAdmission admission =
                        admitted.reserveSigningAdmission()) {
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    admitted.directCommit(List.of(record), admission).outcome());
        }
        try (SegmentedTransactionalMetadataStore unreserved =
                SegmentedTransactionalMetadataStore.create(unreservedRoot, STORE_ID)) {
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    unreserved.directCommit(List.of(record)).outcome());
        }
        assertArrayEquals(committedPayload(unreservedRoot), committedPayload(admittedRoot));
    }

    @Test
    void directCommitSurvivesWalRecoveryAndCheckpointExport(@TempDir Path temporary) throws Exception {
        Path sourceRoot = Files.createDirectory(temporary.resolve("direct-source"));
        Path targetRoot = Files.createDirectory(temporary.resolve("direct-target"));
        MetadataKey key = new MetadataKey("io.zeroecho.test", "direct-key");
        SigningTransactionPayloadCodec.Mutation create = new SigningTransactionPayloadCodec.Mutation(
                SigningTransactionPayloadCodec.MutationKind.CREATE, key, -1L, new byte[] { 6, 7 });
        try (SegmentedTransactionalMetadataStore source =
                SegmentedTransactionalMetadataStore.create(sourceRoot, STORE_ID)) {
            source.observeWatermark(9876L);
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    source.directCommit(List.of(create)).outcome());
        }
        try (SegmentedTransactionalMetadataStore recovered =
                SegmentedTransactionalMetadataStore.open(sourceRoot, STORE_ID)) {
            assertEquals(9876L, recovered.recoveredWatermark());
            assertValue(recovered, key, new byte[] { 6, 7 });
            recovered.exportSnapshotTo(targetRoot, Set.of());
        }
        try (SegmentedTransactionalMetadataStore checkpoint =
                SegmentedTransactionalMetadataStore.open(targetRoot, STORE_ID)) {
            assertEquals(9876L, checkpoint.recoveredWatermark());
            assertValue(checkpoint, key, new byte[] { 6, 7 });
        }
    }

    @Test
    void directCohortPreservesIndependentInputOrderedResults(@TempDir Path temporary)
            throws Exception {
        Path root = Files.createDirectory(temporary.resolve("direct-cohort"));
        MetadataKey firstKey = new MetadataKey("io.zeroecho.test", "cohort-first");
        MetadataKey secondKey = new MetadataKey("io.zeroecho.test", "cohort-second");
        SigningTransactionPayloadCodec.Mutation first = new SigningTransactionPayloadCodec.Mutation(
                SigningTransactionPayloadCodec.MutationKind.CREATE,
                firstKey, -1L, new byte[] { 1 });
        SigningTransactionPayloadCodec.Mutation conflicting =
                new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.CREATE,
                        firstKey, -1L, new byte[] { 2 });
        SigningTransactionPayloadCodec.Mutation second = new SigningTransactionPayloadCodec.Mutation(
                SigningTransactionPayloadCodec.MutationKind.CREATE,
                secondKey, -1L, new byte[] { 3 });

        try (SegmentedTransactionalMetadataStore store =
                SegmentedTransactionalMetadataStore.create(root, STORE_ID)) {
            List<MetadataCommitResult> results = store.directCommitCohort(List.of(
                    List.of(first), List.of(conflicting), List.of(second)));
            assertEquals(List.of(MetadataCommitResult.Outcome.COMMITTED,
                    MetadataCommitResult.Outcome.NOT_COMMITTED,
                    MetadataCommitResult.Outcome.COMMITTED),
                    results.stream().map(MetadataCommitResult::outcome).toList());
            assertEquals(MetadataCommitResult.FailureCategory.CONFLICT,
                    results.get(1).failureCategory().orElseThrow());
            assertEquals(results.get(0).committedRevision().orElseThrow() + 1L,
                    results.get(2).committedRevision().orElseThrow());
            assertValue(store, firstKey, new byte[] { 1 });
            assertValue(store, secondKey, new byte[] { 3 });
        }
    }

    @Test
    void conditionalDirectCommitRecoversOnlyFallbackWithoutRevisionGap(@TempDir Path temporary)
            throws Exception {
        Path root = Files.createDirectory(temporary.resolve("conditional-direct"));
        MetadataKey primaryKey = new MetadataKey("io.zeroecho.test", "primary");
        MetadataKey fallbackKey = new MetadataKey("io.zeroecho.test", "fallback");
        SigningTransactionPayloadCodec.Mutation primary =
                new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.CREATE,
                        primaryKey, -1L, new byte[] { 1 });
        SigningTransactionPayloadCodec.Mutation fallback =
                new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.CREATE,
                        fallbackKey, -1L, new byte[] { 2 });
        AtomicInteger observations = new AtomicInteger();
        long baseline;
        long committedRevision;
        try (SegmentedTransactionalMetadataStore store =
                SegmentedTransactionalMetadataStore.create(root, STORE_ID);
                MetadataSnapshot before = store.snapshot()) {
            baseline = before.revision();
            SigningLedgerStoreEngine.ConditionalDirectCommit alternatives =
                    new SigningLedgerStoreEngine.ConditionalDirectCommit(
                            List.of(primary), List.of(fallback), () -> false,
                            observations::incrementAndGet);
            SigningLedgerStoreEngine.ConditionalCommitResult committed =
                    store.directCommitAtAdmission(alternatives);
            assertFalse(committed.primaryAdmitted());
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    committed.result().outcome());
            committedRevision = committed.result().committedRevision().orElseThrow();
            assertEquals(baseline + 1L, committedRevision);
            assertEquals(1, observations.get());
        }

        try (SegmentedTransactionalMetadataStore recovered =
                SegmentedTransactionalMetadataStore.open(root, STORE_ID);
                MetadataSnapshot snapshot = recovered.snapshot()) {
            assertEquals(committedRevision, snapshot.revision());
            assertTrue(snapshot.get(primaryKey).isEmpty());
            try (MetadataSnapshot.Record record = snapshot.get(fallbackKey).orElseThrow()) {
                assertEquals(committedRevision, record.recordRevision());
                assertArrayEquals(new byte[] { 2 }, record.openStream().readAllBytes());
            }
        }
    }

    @Test
    void directCommitForceFailureNeverReportsSuccess(@TempDir Path temporary) throws Exception {
        Path root = Files.createDirectory(temporary.resolve("direct-uncertain"));
        SegmentedTransactionalMetadataStore store = SegmentedTransactionalMetadataStore.create(
                root, STORE_ID, new FailSecondWalForce());
        Throwable firstRecoveryFailure = null;
        try {
            SigningTransactionPayloadCodec.Mutation create = new SigningTransactionPayloadCodec.Mutation(
                    SigningTransactionPayloadCodec.MutationKind.CREATE,
                    new MetadataKey("io.zeroecho.test", "uncertain"), -1L, new byte[] { 1 });
            assertThrows(IOException.class, () -> store.directCommit(List.of(create)));
            firstRecoveryFailure = store.firstRecoveryFailure();
            SigningActiveWal.CommitFailure commitFailure = assertInstanceOf(
                    SigningActiveWal.CommitFailure.class, firstRecoveryFailure);
            assertEquals(SigningActiveWal.FailureOutcome.DURABILITY_UNCERTAIN,
                    commitFailure.outcome());
            IOException storageFailure = assertInstanceOf(IOException.class,
                    commitFailure.getCause());
            assertEquals("injected force boundary failure", storageFailure.getMessage());
            assertThrows(IllegalStateException.class, store::snapshot);
        } finally {
            try {
                store.close();
            } catch (IOException expectedRecoveryRequired) {
                // The failed force permanently closes this writer generation.
            }
        }
        assertNotNull(firstRecoveryFailure);
        assertSame(firstRecoveryFailure, store.firstRecoveryFailure());
    }

    @Test
    void admissionReleaseInvariantPublishesItsCauseWithRecoveryState(@TempDir Path temporary)
            throws Exception {
        Path root = Files.createDirectory(temporary.resolve("admission-release-invariant"));
        SigningLedgerStoreEngine engine = SigningLedgerStoreEngine.create(root, STORE_ID);
        try {
            Method projectionCompleted = SigningLedgerStoreEngine.class
                    .getDeclaredMethod("projectionCompleted");
            projectionCompleted.setAccessible(true);

            projectionCompleted.invoke(engine);

            IllegalStateException failure = assertInstanceOf(
                    IllegalStateException.class, engine.firstRecoveryFailure());
            assertEquals("Metadata WAL admission release is inconsistent", failure.getMessage());
        } finally {
            engine.close();
        }
    }

    @Test
    void activeWalCloseFailureIsRetainedAndReadableAfterEngineClose(@TempDir Path temporary)
            throws Exception {
        Path root = Files.createDirectory(temporary.resolve("close-recovery-cause"));
        CrashAtWalForce operations = new CrashAtWalForce(Integer.MAX_VALUE, false);
        SegmentedTransactionalMetadataStore store = SegmentedTransactionalMetadataStore.create(
                root, STORE_ID, operations);
        operations.failClose = true;

        IOException propagated = assertThrows(IOException.class, store::close);
        Throwable retained = store.firstRecoveryFailure();

        assertSame(propagated, retained);
        SigningActiveWal.RecoveryRequiredException recoveryFailure = assertInstanceOf(
                SigningActiveWal.RecoveryRequiredException.class, retained);
        IOException channelFailure = assertInstanceOf(
                IOException.class, recoveryFailure.getCause());
        assertEquals("injected WAL close failure", channelFailure.getMessage());
    }

    @Test
    void overlappingDirectCreatesValidateAgainstPreparedAdmissionOrder(@TempDir Path temporary)
            throws Exception {
        Path root = Files.createDirectory(temporary.resolve("direct-overlap"));
        BlockingSecondWalForce operations = new BlockingSecondWalForce();
        MetadataKey key = new MetadataKey("io.zeroecho.test", "overlap");
        SigningTransactionPayloadCodec.Mutation create = new SigningTransactionPayloadCodec.Mutation(
                SigningTransactionPayloadCodec.MutationKind.CREATE, key, -1L, new byte[] { 3 });
        try (SegmentedTransactionalMetadataStore store =
                    SegmentedTransactionalMetadataStore.create(root, STORE_ID, operations);
                ExecutorService executor = Executors.newFixedThreadPool(2)) {
            Future<MetadataCommitResult> first = executor.submit(() -> store.directCommit(List.of(create)));
            assertTrue(operations.forceEntered.await(5L, TimeUnit.SECONDS));
            Future<MetadataCommitResult> overlapping = executor.submit(
                    () -> store.directCommit(List.of(create)));
            MetadataCommitResult rejected = overlapping.get(5L, TimeUnit.SECONDS);
            assertEquals(MetadataCommitResult.Outcome.NOT_COMMITTED, rejected.outcome());
            assertEquals(MetadataCommitResult.FailureCategory.CONFLICT,
                    rejected.failureCategory().orElseThrow());
            operations.releaseForce.countDown();
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    first.get(5L, TimeUnit.SECONDS).outcome());
            assertValue(store, key, new byte[] { 3 });
        } finally {
            operations.releaseForce.countDown();
        }
    }

    @Test
    void malformedIntegrityValidDirectCommitsFailRecoveryWithoutMutation(@TempDir Path temporary)
            throws Exception {
        MetadataKey key = new MetadataKey("io.zeroecho.test", "malformed-direct");
        List<MalformedDirect> cases = List.of(
                new MalformedDirect("empty", rawDirect(List.of(), -1L)),
                new MalformedDirect("duplicate", rawDirect(List.of(
                        rawMutation(1, -1L, key, 0), rawMutation(1, -1L, key, 0)), -1L)),
                new MalformedDirect("delete-length", rawDirect(List.of(
                        rawMutation(3, 1L, key, 0)), -1L)),
                new MalformedDirect("watermark", rawDirect(List.of(
                        rawMutation(1, -1L, key, 0)), -2L)));
        for (MalformedDirect malformed : cases) {
            Path root = Files.createDirectory(temporary.resolve(malformed.name()));
            try (SegmentedTransactionalMetadataStore ignored =
                    SegmentedTransactionalMetadataStore.create(root, STORE_ID)) {
                // Establish a valid empty ledger before injecting an integrity-valid group.
            }
            SigningManifestCodec.Manifest manifest = SigningManifestCodec.decode(
                    Files.readAllBytes(root.resolve(SigningLedgerRecovery.MANIFEST_FILE)));
            Path active = root.resolve(manifest.activeWal().name());
            appendDirectGroup(active, malformed.payload());
            byte[] injected = Files.readAllBytes(active);

            assertThrows(IOException.class,
                    () -> SegmentedTransactionalMetadataStore.open(root, STORE_ID));
            assertArrayEquals(injected, Files.readAllBytes(active));
            assertThrows(IOException.class,
                    () -> SegmentedTransactionalMetadataStore.open(root, STORE_ID));
            assertArrayEquals(injected, Files.readAllBytes(active));
        }
    }

    @Test
    void exportsPinnedRevisionAsDirectCheckpointLedger(@TempDir Path temporary) throws Exception {
        Path sourceRoot = Files.createDirectory(temporary.resolve("source"));
        Path targetRoot = Files.createDirectory(temporary.resolve("target"));
        MetadataKey key = new MetadataKey("io.zeroecho.test", "key");
        try (SegmentedTransactionalMetadataStore source =
                SegmentedTransactionalMetadataStore.create(sourceRoot, STORE_ID)) {
            try (MetadataTransaction transaction = source.beginTransaction()) {
                transaction.create(key, content(7), CancellationSignal.NONE);
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
            }
            source.exportSnapshotTo(targetRoot, Set.of());
        }
        try (SegmentedTransactionalMetadataStore target =
                SegmentedTransactionalMetadataStore.open(targetRoot, STORE_ID);
                MetadataSnapshot snapshot = target.snapshot();
                MetadataSnapshot.Record record = snapshot.get(key).orElseThrow()) {
            assertArrayEquals(new byte[] { 7 }, record.openStream().readAllBytes());
        }
    }

    @Test
    void commitsMultiKeyAtomicallyRetainsOutcomeAndRestarts(@TempDir Path temporary) throws Exception {
        Path root = Files.createDirectory(temporary.resolve("metadata"));
        MetadataKey first = new MetadataKey("io.zeroecho.test", "a");
        MetadataKey second = new MetadataKey("io.zeroecho.test", "b");
        MetadataTransactionId transactionId;
        long revision;
        try (SegmentedTransactionalMetadataStore store =
                SegmentedTransactionalMetadataStore.create(root, STORE_ID);
                MetadataTransaction transaction = store.beginTransaction()) {
            assertEquals(MetadataStoreCapabilities.WriterModel.SERIALIZABLE_MULTI_WRITER,
                    store.capabilities().writerModel());
            transaction.create(first, content(1), CancellationSignal.NONE);
            transaction.create(second, content(2), CancellationSignal.NONE);
            MetadataCommitResult committed = transaction.commit();
            transactionId = committed.transactionId();
            revision = committed.committedRevision().orElseThrow();
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, committed.outcome());
            try (MetadataSnapshot snapshot = store.snapshot();
                    MetadataSnapshot.Record a = snapshot.get(first).orElseThrow();
                    MetadataSnapshot.Record b = snapshot.get(second).orElseThrow()) {
                assertEquals(revision, a.recordRevision());
                assertEquals(revision, b.recordRevision());
                assertArrayEquals(new byte[] { 1 }, a.openStream().readAllBytes());
                assertArrayEquals(new byte[] { 2 }, b.openStream().readAllBytes());
            }
        }
        try (SegmentedTransactionalMetadataStore reopened =
                SegmentedTransactionalMetadataStore.open(root, STORE_ID)) {
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    reopened.resolve(transactionId).outcome());
            reopened.acknowledge(transactionId);
            MetadataStoreException released = assertThrows(MetadataStoreException.class,
                    () -> reopened.resolve(transactionId));
            assertEquals(MetadataCommitResult.FailureCategory.TRANSACTION_NOT_ISSUED,
                    released.category());
        }
    }

    @Test
    void conflictChangesNoCallerKeyAndIsRetained(@TempDir Path temporary) throws Exception {
        Path root = Files.createDirectory(temporary.resolve("metadata"));
        MetadataKey key = new MetadataKey("io.zeroecho.test", "key");
        try (SegmentedTransactionalMetadataStore store =
                SegmentedTransactionalMetadataStore.create(root, STORE_ID)) {
            try (MetadataTransaction transaction = store.beginTransaction()) {
                transaction.create(key, content(1), CancellationSignal.NONE);
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
            }
            MetadataCommitResult rejected;
            try (MetadataTransaction transaction = store.beginTransaction()) {
                transaction.create(key, content(9), CancellationSignal.NONE);
                rejected = transaction.commit();
            }
            assertEquals(MetadataCommitResult.Outcome.NOT_COMMITTED, rejected.outcome());
            assertEquals(MetadataCommitResult.FailureCategory.CONFLICT,
                    rejected.failureCategory().orElseThrow());
            assertEquals(rejected, store.resolve(rejected.transactionId()));
            try (MetadataSnapshot snapshot = store.snapshot();
                    MetadataSnapshot.Record retained = snapshot.get(key).orElseThrow()) {
                assertArrayEquals(new byte[] { 1 }, retained.openStream().readAllBytes());
            }
        }
    }

    @ParameterizedTest
    @MethodSource("transactionRestartBoundaries")
    void transactionRestartMatrixResolvesUnknownAndNeverLosesCommittedBusinessState(
            TransactionBoundary boundary, boolean boundaryDurable) throws Exception {
        Path root = Files.createDirectory(temporaryDirectory.resolve(
                "transaction-" + boundary + '-' + boundaryDurable));
        MetadataKey key = new MetadataKey("io.zeroecho.test", "restart-matrix");
        CrashAtWalForce operations = new CrashAtWalForce(
                boundary.forceOrdinal(), boundaryDurable);
        MetadataTransactionId transactionId = null;
        SegmentedTransactionalMetadataStore faulted =
                SegmentedTransactionalMetadataStore.create(root, STORE_ID, operations);
        try {
            switch (boundary) {
                case ISSUE -> {
                    assertThrows(IOException.class, faulted::beginTransaction);
                    if (boundaryDurable) {
                        transactionId = issuedTransactionId(root);
                    }
                }
                case COMMIT -> {
                    try (MetadataTransaction transaction = faulted.beginTransaction()) {
                        transaction.create(key, content(1), CancellationSignal.NONE);
                        MetadataCommitResult immediate = transaction.commit();
                        assertEquals(MetadataCommitResult.Outcome.UNKNOWN,
                                immediate.outcome());
                        transactionId = immediate.transactionId();
                    }
                }
                case REJECT -> {
                    commitValue(faulted, key, 1);
                    try (MetadataTransaction transaction = faulted.beginTransaction()) {
                        transaction.create(key, content(9), CancellationSignal.NONE);
                        MetadataCommitResult immediate = transaction.commit();
                        assertEquals(MetadataCommitResult.Outcome.UNKNOWN,
                                immediate.outcome());
                        transactionId = immediate.transactionId();
                    }
                }
                case ACK -> {
                    transactionId = commitValue(faulted, key, 1).transactionId();
                    MetadataTransactionId acknowledged = transactionId;
                    assertThrows(IOException.class,
                            () -> faulted.acknowledge(acknowledged));
                }
            }
        } finally {
            try {
                faulted.close();
            } catch (IOException expectedRecoveryRequired) {
                // The injected ambiguous boundary requires validated restart.
            }
        }

        try (SegmentedTransactionalMetadataStore restarted =
                SegmentedTransactionalMetadataStore.open(root, STORE_ID)) {
            if (boundary == TransactionBoundary.ISSUE && !boundaryDurable) {
                assertAbsent(restarted, key);
                return;
            }
            MetadataTransactionId retainedId = transactionId;
            if (boundary == TransactionBoundary.ACK && boundaryDurable) {
                MetadataStoreException absent = assertThrows(MetadataStoreException.class,
                        () -> restarted.resolve(retainedId));
                assertEquals(MetadataCommitResult.FailureCategory.TRANSACTION_NOT_ISSUED,
                        absent.category());
                assertValue(restarted, key, new byte[] { 1 });
                return;
            }

            MetadataCommitResult resolved = restarted.resolve(retainedId);
            if ((boundary == TransactionBoundary.COMMIT && boundaryDurable)
                    || boundary == TransactionBoundary.ACK) {
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, resolved.outcome());
                assertValue(restarted, key, new byte[] { 1 });
            } else if (boundary == TransactionBoundary.REJECT && boundaryDurable) {
                assertEquals(MetadataCommitResult.Outcome.NOT_COMMITTED, resolved.outcome());
                assertEquals(MetadataCommitResult.FailureCategory.CONFLICT,
                        resolved.failureCategory().orElseThrow());
                assertValue(restarted, key, new byte[] { 1 });
            } else {
                assertEquals(MetadataCommitResult.Outcome.NOT_COMMITTED, resolved.outcome());
                assertEquals(MetadataCommitResult.FailureCategory.ABANDONED_BY_RECOVERY,
                        resolved.failureCategory().orElseThrow());
                if (boundary == TransactionBoundary.COMMIT) {
                    assertAbsent(restarted, key);
                }
            }
        }
    }

    @Test
    void rejectsLegacyOrUnknownRootBeforeMutation(@TempDir Path temporary) throws Exception {
        Path root = Files.createDirectory(temporary.resolve("metadata"));
        Path legacy = root.resolve("transactions.log");
        Files.write(legacy, new byte[] { 1 });
        assertThrows(java.io.IOException.class,
                () -> SegmentedTransactionalMetadataStore.open(root, STORE_ID));
        assertTrue(Files.exists(legacy));
        assertEquals(1L, Files.size(legacy));
    }

    @Test
    void snapshotCopiesPinnedValuesRetainedOutcomesAndWatermark(@TempDir Path temporary)
            throws Exception {
        Path sourceRoot = Files.createDirectory(temporary.resolve("source"));
        Path targetRoot = Files.createDirectory(temporary.resolve("target"));
        MetadataKey key = new MetadataKey("io.zeroecho.test", "snapshot");
        MetadataKey leadingKey = new MetadataKey("0", "leading");
        MetadataTransactionId committedId;
        MetadataTransactionId rejectedId;
        try (SegmentedTransactionalMetadataStore source =
                    SegmentedTransactionalMetadataStore.create(sourceRoot, STORE_ID);
                SegmentedTransactionalMetadataStore target =
                    SegmentedTransactionalMetadataStore.create(targetRoot, STORE_ID)) {
            try (MetadataTransaction transaction = source.beginTransaction()) {
                transaction.create(key, content(7), CancellationSignal.NONE);
                transaction.create(leadingKey, content(6), CancellationSignal.NONE);
                committedId = transaction.commit().transactionId();
            }
            try (MetadataTransaction transaction = source.beginTransaction()) {
                transaction.create(key, content(8), CancellationSignal.NONE);
                rejectedId = transaction.commit().transactionId();
            }
            source.advanceWatermark(123_456L);
            assertEquals(123_456L, source.advanceWatermark(123_000L));
            source.copySnapshotTo(target, java.util.Set.of());
            try (MetadataSnapshot snapshot = target.snapshot();
                    MetadataSnapshot.Record record = snapshot.get(key).orElseThrow();
                    MetadataSnapshot.Record leading = snapshot.get(leadingKey).orElseThrow()) {
                assertArrayEquals(new byte[] { 7 }, record.openStream().readAllBytes());
                assertArrayEquals(new byte[] { 6 }, leading.openStream().readAllBytes());
            }
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    target.resolve(committedId).outcome());
            assertEquals(MetadataCommitResult.FailureCategory.CONFLICT,
                    target.resolve(rejectedId).failureCategory().orElseThrow());
            assertEquals(123_456L, target.recoveredWatermark());
        }
        try (SegmentedTransactionalMetadataStore reopened =
                SegmentedTransactionalMetadataStore.open(targetRoot, STORE_ID)) {
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    reopened.resolve(committedId).outcome());
            assertEquals(MetadataCommitResult.FailureCategory.CONFLICT,
                    reopened.resolve(rejectedId).failureCategory().orElseThrow());
            assertEquals(123_456L, reopened.recoveredWatermark());
        }
    }

    @Test
    void interruptAfterAdmissionDoesNotReportCancelled(@TempDir Path temporary) throws Exception {
        Path root = Files.createDirectory(temporary.resolve("interrupt"));
        MetadataKey key = new MetadataKey("io.zeroecho.test", "interrupt");
        try (SegmentedTransactionalMetadataStore store =
                SegmentedTransactionalMetadataStore.create(root, STORE_ID);
                MetadataTransaction transaction = store.beginTransaction()) {
            transaction.create(key, content(4), CancellationSignal.NONE);
            Thread.currentThread().interrupt();
            MetadataCommitResult result;
            try {
                result = transaction.commit();
                assertTrue(Thread.currentThread().isInterrupted());
            } finally {
                Thread.interrupted();
            }
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, result.outcome());
        }
    }

    @Test
    void acknowledgedOrdinaryOutcomesRemainBoundedAcrossRestart(@TempDir Path temporary)
            throws Exception {
        Path root = Files.createDirectory(temporary.resolve("acknowledged"));
        MetadataTransactionId last = null;
        try (SegmentedTransactionalMetadataStore store =
                SegmentedTransactionalMetadataStore.create(root, STORE_ID)) {
            for (int index = 0; index < 128; index++) {
                try (MetadataTransaction transaction = store.beginTransaction()) {
                    transaction.create(new MetadataKey("io.zeroecho.test", "key-" + index),
                            content(index), CancellationSignal.NONE);
                    MetadataCommitResult result = transaction.commit();
                    last = result.transactionId();
                    store.acknowledge(last);
                }
            }
        }
        MetadataTransactionId acknowledged = last;
        try (SegmentedTransactionalMetadataStore reopened =
                SegmentedTransactionalMetadataStore.open(root, STORE_ID)) {
            MetadataStoreException absent = assertThrows(MetadataStoreException.class,
                    () -> reopened.resolve(acknowledged));
            assertEquals(MetadataCommitResult.FailureCategory.TRANSACTION_NOT_ISSUED,
                    absent.category());
        }
    }

    @Test
    @RequiresSymlinkCreation
    void unknownAndSymlinkEntriesFailClosedWithoutMutation(@TempDir Path temporary)
            throws Exception {
        Path unknownRoot = Files.createDirectory(temporary.resolve("unknown"));
        try (SegmentedTransactionalMetadataStore ignored =
                SegmentedTransactionalMetadataStore.create(unknownRoot, STORE_ID)) {
            // establish a valid root
        }
        Path unknown = unknownRoot.resolve("unexpected.bin");
        Files.write(unknown, new byte[] { 3, 4 });
        java.io.IOException failure = assertThrows(java.io.IOException.class,
                () -> SegmentedTransactionalMetadataStore.open(unknownRoot, STORE_ID));
        assertEquals("Metadata ledger format unsupported: code=METADATA_FORMAT_UNSUPPORTED",
                failure.getMessage());
        assertArrayEquals(new byte[] { 3, 4 }, Files.readAllBytes(unknown));

        Path linkRoot = Files.createDirectory(temporary.resolve("link"));
        Path outside = temporary.resolve("outside");
        Files.write(outside, new byte[] { 9 });
        Files.createSymbolicLink(linkRoot.resolve("FORMAT"), outside);
        assertThrows(java.io.IOException.class,
                () -> SegmentedTransactionalMetadataStore.open(linkRoot, STORE_ID));
        assertArrayEquals(new byte[] { 9 }, Files.readAllBytes(outside));
    }

    private static RepeatableContent content(int value) {
        return new RepeatableContent() {
            @Override public InputStream openStream() { return new ByteArrayInputStream(new byte[] { (byte) value }); }
            @Override public OptionalLong length() { return OptionalLong.of(1L); }
            @Override public String contentId() { return "test"; }
            @Override public void close() { }
        };
    }

    private static Stream<Arguments> transactionRestartBoundaries() {
        return Stream.of(
                Arguments.of(TransactionBoundary.ISSUE, false),
                Arguments.of(TransactionBoundary.ISSUE, true),
                Arguments.of(TransactionBoundary.COMMIT, false),
                Arguments.of(TransactionBoundary.COMMIT, true),
                Arguments.of(TransactionBoundary.REJECT, false),
                Arguments.of(TransactionBoundary.REJECT, true),
                Arguments.of(TransactionBoundary.ACK, false),
                Arguments.of(TransactionBoundary.ACK, true));
    }

    private static MetadataCommitResult commitValue(SegmentedTransactionalMetadataStore store,
            MetadataKey key, int value) throws Exception {
        try (MetadataTransaction transaction = store.beginTransaction()) {
            transaction.create(key, content(value), CancellationSignal.NONE);
            MetadataCommitResult committed = transaction.commit();
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, committed.outcome());
            return committed;
        }
    }

    private static MetadataTransactionId issuedTransactionId(Path root) throws IOException {
        SigningManifestCodec.ActiveWal active = SigningManifestCodec.decode(Files.readAllBytes(
                root.resolve(SigningLedgerRecovery.MANIFEST_FILE))).activeWal();
        List<SigningWalFrameCodec.Frame> frames = new ArrayList<>();
        try (FileChannel input = FileChannel.open(root.resolve(active.name()),
                StandardOpenOption.READ)) {
            SigningWalFrameCodec.scan(input, active.firstSequence(), true, frames::add);
        }
        UUID token = frames.stream()
                .filter(frame -> frame.recordType() == SigningWalFrameCodec.RecordType.ISSUE)
                .findFirst().orElseThrow().transactionId();
        String canonical = String.format(java.util.Locale.ROOT, "%016x%016x",
                token.getMostSignificantBits(), token.getLeastSignificantBits());
        return new MetadataTransactionId(STORE_ID, canonical);
    }

    private static void assertAbsent(SegmentedTransactionalMetadataStore store,
            MetadataKey key) throws IOException {
        try (MetadataSnapshot snapshot = store.snapshot()) {
            assertTrue(snapshot.get(key).isEmpty());
        }
    }

    private static void assertValue(SegmentedTransactionalMetadataStore store,
            MetadataKey key, byte[] expected) throws Exception {
        try (MetadataSnapshot snapshot = store.snapshot();
                MetadataSnapshot.Record record = snapshot.get(key).orElseThrow()) {
            assertArrayEquals(expected, record.openStream().readAllBytes());
        }
    }

    private static void appendDirectGroup(Path active, byte[] payload) throws IOException {
        byte[] previous;
        try (FileChannel input = FileChannel.open(active, StandardOpenOption.READ)) {
            previous = SigningFileCommitment.sha256(input);
        }
        SigningWalFrameCodec.Frame frame = new SigningWalFrameCodec.Frame(
                SigningWalFrameCodec.RecordType.COMMIT, UUID.randomUUID(), 0L, payload);
        try (FileChannel output = FileChannel.open(active, StandardOpenOption.APPEND)) {
            SigningWalFrameCodec.writeCommittedBatch(output, List.of(frame), 0L, 1L, previous);
        }
    }

    private static byte[] committedPayload(Path root) throws IOException {
        SigningManifestCodec.ActiveWal active = SigningManifestCodec.decode(Files.readAllBytes(
                root.resolve(SigningLedgerRecovery.MANIFEST_FILE))).activeWal();
        List<SigningWalFrameCodec.Frame> frames = new ArrayList<>();
        try (FileChannel input = FileChannel.open(root.resolve(active.name()),
                StandardOpenOption.READ)) {
            SigningWalFrameCodec.scan(input, active.firstSequence(), true, frames::add);
        }
        return frames.stream()
                .filter(frame -> frame.recordType() == SigningWalFrameCodec.RecordType.COMMIT)
                .findFirst().orElseThrow().payload();
    }

    private static byte[] rawMutation(int kind, long expected, MetadataKey key, int contentLength) {
        byte[] canonical = key.canonical().getBytes(StandardCharsets.US_ASCII);
        ByteBuffer output = ByteBuffer.allocate(1 + Long.BYTES + Integer.BYTES + canonical.length
                + Integer.BYTES + Math.max(0, contentLength)).order(ByteOrder.BIG_ENDIAN);
        output.put((byte) kind).putLong(expected).putInt(canonical.length).put(canonical)
                .putInt(contentLength);
        if (contentLength > 0) output.put(new byte[contentLength]);
        return output.array();
    }

    private static byte[] rawDirect(List<byte[]> mutations, long watermark) {
        int size = 12 + Long.BYTES;
        for (byte[] mutation : mutations) size += mutation.length;
        ByteBuffer output = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        output.putInt(0x5A455458).putShort((short) 1).putShort((short) 0)
                .put((byte) 6).put((byte) mutations.size()).putShort((short) 0);
        mutations.forEach(output::put);
        return output.putLong(watermark).array();
    }

    private record MalformedDirect(String name, byte[] payload) { }

    private enum TransactionBoundary {
        ISSUE(2),
        COMMIT(3),
        REJECT(5),
        ACK(4);

        private final int forceOrdinal;

        TransactionBoundary(int forceOrdinal) {
            this.forceOrdinal = forceOrdinal;
        }

        private int forceOrdinal() {
            return forceOrdinal;
        }
    }

    private static final class FailSecondWalForce extends CrashAtWalForce {
        private FailSecondWalForce() {
            super(2, false);
        }
    }

    private static class CrashAtWalForce implements SigningActiveWal.Operations {
        private final AtomicInteger forces = new AtomicInteger();
        private final int faultOrdinal;
        private final boolean durableBeforeFailure;
        private long durableLength;
        private boolean injected;
        private boolean failClose;

        private CrashAtWalForce(int faultOrdinal, boolean durableBeforeFailure) {
            this.faultOrdinal = faultOrdinal;
            this.durableBeforeFailure = durableBeforeFailure;
        }

        @Override public boolean exists(Path path) { return Files.exists(path, LinkOption.NOFOLLOW_LINKS); }
        @Override public boolean isRegularFile(Path path) {
            return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS);
        }
        @Override public SigningActiveWal.WalChannel createNew(Path path) throws IOException {
            return wrap(FileChannel.open(path, Set.of(StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.READ, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)));
        }
        @Override public SigningActiveWal.WalChannel openExisting(Path path) throws IOException {
            return wrap(FileChannel.open(path, Set.of(StandardOpenOption.READ,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)));
        }
        @Override public void forceDirectory(Path directory) throws IOException {
            SigningFormatSupport.forceDirectory(directory);
        }
        private SigningActiveWal.WalChannel wrap(FileChannel channel) {
            return new SigningActiveWal.WalChannel() {
                @Override public int read(ByteBuffer target) throws IOException { return channel.read(target); }
                @Override public int write(ByteBuffer source) throws IOException { return channel.write(source); }
                @Override public long position() throws IOException { return channel.position(); }
                @Override public SigningActiveWal.WalChannel position(long value) throws IOException {
                    channel.position(value);
                    return this;
                }
                @Override public long size() throws IOException { return channel.size(); }
                @Override public SigningActiveWal.WalChannel truncate(long size) throws IOException {
                    channel.truncate(size);
                    return this;
                }
                @Override public boolean isOpen() { return channel.isOpen(); }
                @Override public void close() throws IOException {
                    channel.close();
                    if (failClose) {
                        throw new IOException("injected WAL close failure");
                    }
                }
                @Override public void force(boolean metadata) throws IOException {
                    int ordinal = forces.incrementAndGet();
                    if (!injected && ordinal == faultOrdinal) {
                        injected = true;
                        if (durableBeforeFailure) {
                            channel.force(metadata);
                            durableLength = channel.size();
                        } else {
                            channel.truncate(durableLength);
                            channel.force(metadata);
                        }
                        throw new IOException("injected force boundary failure");
                    }
                    channel.force(metadata);
                    durableLength = channel.size();
                }
            };
        }
    }

    private static final class BlockingSecondWalForce implements SigningActiveWal.Operations {
        private final AtomicInteger forces = new AtomicInteger();
        private final CountDownLatch forceEntered = new CountDownLatch(1);
        private final CountDownLatch releaseForce = new CountDownLatch(1);

        @Override public boolean exists(Path path) { return Files.exists(path, LinkOption.NOFOLLOW_LINKS); }
        @Override public boolean isRegularFile(Path path) {
            return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS);
        }
        @Override public SigningActiveWal.WalChannel createNew(Path path) throws IOException {
            return wrap(FileChannel.open(path, Set.of(StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.READ, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)));
        }
        @Override public SigningActiveWal.WalChannel openExisting(Path path) throws IOException {
            return wrap(FileChannel.open(path, Set.of(StandardOpenOption.READ,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)));
        }
        @Override public void forceDirectory(Path directory) throws IOException {
            SigningFormatSupport.forceDirectory(directory);
        }
        private SigningActiveWal.WalChannel wrap(FileChannel channel) {
            return new SigningActiveWal.WalChannel() {
                @Override public int read(ByteBuffer target) throws IOException { return channel.read(target); }
                @Override public int write(ByteBuffer source) throws IOException { return channel.write(source); }
                @Override public long position() throws IOException { return channel.position(); }
                @Override public SigningActiveWal.WalChannel position(long value) throws IOException {
                    channel.position(value);
                    return this;
                }
                @Override public long size() throws IOException { return channel.size(); }
                @Override public SigningActiveWal.WalChannel truncate(long size) throws IOException {
                    channel.truncate(size);
                    return this;
                }
                @Override public boolean isOpen() { return channel.isOpen(); }
                @Override public void close() throws IOException { channel.close(); }
                @Override public void force(boolean metadata) throws IOException {
                    if (forces.incrementAndGet() == 2) {
                        forceEntered.countDown();
                        try {
                            if (!releaseForce.await(5L, TimeUnit.SECONDS)) {
                                throw new IOException("controlled force release timed out");
                            }
                        } catch (InterruptedException interrupted) {
                            Thread.currentThread().interrupt();
                            throw new IOException("controlled force interrupted", interrupted);
                        }
                    }
                    channel.force(metadata);
                }
            };
        }
    }
}
