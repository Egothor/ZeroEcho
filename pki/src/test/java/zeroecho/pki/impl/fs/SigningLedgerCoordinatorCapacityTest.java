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
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransactionId;

final class SigningLedgerCoordinatorCapacityTest {
    private static final MetadataStoreId STORE_ID =
            new MetadataStoreId("1234567890abcdef1234567890abcdef");

    @Test
    void liveCommitAvoidsDecodedPayloadCopyAndReleasesExactReservation(@TempDir Path temporary)
            throws Exception {
        Path root = Files.createDirectory(temporary.resolve("ledger"));
        try (SigningLedgerStoreEngine engine = SigningLedgerStoreEngine.create(root, STORE_ID)) {
            MetadataTransactionId transactionId = engine.issue();
            SigningTransactionPayloadCodec.Mutation mutation = mutation(new byte[1024]);
            long expected = SigningLedgerStoreEngine.coordinatorReservationBytes(List.of(mutation));
            assertEquals(2L * SigningTransactionPayloadCodec.encodedCommitSize(List.of(mutation))
                    + 1024L + 256L + 64L, expected);

            SigningTransactionPayloadCodec.resetContentCopyCount();
            MetadataCommitResult result = engine.commit(transactionId, List.of(mutation));

            assertEquals(MetadataCommitResult.Outcome.COMMITTED, result.outcome());
            assertEquals(0L, SigningTransactionPayloadCodec.contentCopyCount());
            SigningLedgerStoreEngine.CoordinatorStatistics statistics =
                    engine.coordinatorStatistics();
            assertEquals(0, statistics.reservedRequests());
            assertEquals(0L, statistics.reservedBytes());
            assertTrue(expected < statistics.maximumBytes());
        }
    }

    @Test
    void conservativeReservationSaturatesTheHardByteCap() {
        MetadataKey key = new MetadataKey("io.zeroecho.test", "maximum");
        SigningTransactionPayloadCodec.Mutation empty = mutation(new byte[0]);
        int overhead = SigningTransactionPayloadCodec.encodedCommitSize(List.of(empty));
        SigningTransactionPayloadCodec.Mutation maximum = new SigningTransactionPayloadCodec.Mutation(
                SigningTransactionPayloadCodec.MutationKind.CREATE, key, -1L,
                new byte[SigningWalFrameCodec.MAX_PAYLOAD_BYTES - overhead]);
        long reservation = SigningLedgerStoreEngine.coordinatorReservationBytes(List.of(maximum));
        long limit = 64L * 1024L * 1024L;
        long admitted = limit / reservation;
        assertTrue(admitted > 0L);
        assertTrue(admitted * reservation <= limit);
        assertTrue((admitted + 1L) * reservation > limit);
    }

    @Test
    void openRejectsRecoveredResidentStateAboveOrdinaryCeilingWithoutMutation(
            @TempDir Path temporary) throws Exception {
        Path root = Files.createDirectory(temporary.resolve("ordinary-open-ceiling"));
        try (SigningLedgerStoreEngine engine = SigningLedgerStoreEngine.create(root, STORE_ID)) {
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    engine.directCommit(List.of(mutation("recovered", 1))).outcome());
        }
        Path manifest = root.resolve(SigningLedgerRecovery.MANIFEST_FILE);
        byte[] manifestBefore = Files.readAllBytes(manifest);
        SigningActiveWal.Configuration configuration = SigningActiveWal.Configuration.defaults();
        long protectedFloor = SigningTransitionWorkspaceSizing.derive(
                SigningMvccIndex.FOUR_GIB_MAXIMUM_KEYS,
                configuration.queueCapacity()).workspaceFloorBytes();

        assertThrows(SigningIndexCapacityBudget.CapacityExceededException.class,
                () -> {
                    try (SigningLedgerStoreEngine ignored = SigningLedgerStoreEngine.open(
                            root, STORE_ID, SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK,
                            configuration, protectedFloor + 1L,
                            FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES)) {
                        // Opening must fail before a live engine is returned.
                    }
                });
        assertArrayEquals(manifestBefore, Files.readAllBytes(manifest));
    }

    @Test
    void genericRejectAndAcknowledgeCannotEnterProtectedProgressCapacity(
            @TempDir Path temporary) throws Exception {
        SigningActiveWal.Configuration configuration = SigningActiveWal.Configuration.defaults();
        long protectedFloor = SigningTransitionWorkspaceSizing.derive(
                SigningMvccIndex.FOUR_GIB_MAXIMUM_KEYS,
                configuration.queueCapacity()).workspaceFloorBytes();
        Path rejectRoot = Files.createDirectory(temporary.resolve("generic-reject"));
        long issuedResidentBytes;
        try (SigningLedgerStoreEngine engine = SigningLedgerStoreEngine.create(
                rejectRoot, STORE_ID)) {
            engine.issue();
            issuedResidentBytes = engine.capacitySnapshot().steady().reservedBytes();
        }
        long rejectBudget = Math.addExact(protectedFloor, issuedResidentBytes);

        MetadataStoreException rejectedOpen = assertThrows(MetadataStoreException.class,
                () -> SigningLedgerStoreEngine.open(rejectRoot, STORE_ID,
                        SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK, configuration,
                        rejectBudget,
                        FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES));
        assertEquals(MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                rejectedOpen.category());
        assertInstanceOf(SigningIndexCapacityBudget.CapacityExceededException.class,
                rejectedOpen.getCause());

        Path acknowledgeRoot = Files.createDirectory(temporary.resolve("generic-acknowledge"));
        MetadataTransactionId rejectedId;
        long rejectedResidentBytes;
        try (SigningLedgerStoreEngine engine = SigningLedgerStoreEngine.create(
                acknowledgeRoot, STORE_ID)) {
            rejectedId = engine.issue();
            assertEquals(MetadataCommitResult.Outcome.NOT_COMMITTED,
                    engine.reject(rejectedId,
                            MetadataCommitResult.FailureCategory.CANCELLED).outcome());
            for (int index = 0; index < 2; index++) {
                MetadataTransactionId additionalId = engine.issue();
                assertEquals(MetadataCommitResult.Outcome.NOT_COMMITTED,
                        engine.reject(additionalId,
                                MetadataCommitResult.FailureCategory.CANCELLED).outcome());
            }
            rejectedResidentBytes = engine.capacitySnapshot().steady().reservedBytes();
        }
        long acknowledgeBudget = Math.addExact(protectedFloor, rejectedResidentBytes);
        try (SigningLedgerStoreEngine engine = SigningLedgerStoreEngine.open(
                acknowledgeRoot, STORE_ID, SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK,
                configuration, acknowledgeBudget,
                FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES)) {
            MetadataStoreException rejectedAcknowledge = assertThrows(
                    MetadataStoreException.class,
                    () -> engine.acknowledge(rejectedId));
            assertEquals(MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                    rejectedAcknowledge.category());
            assertInstanceOf(SigningIndexCapacityBudget.CapacityExceededException.class,
                    rejectedAcknowledge.getCause());
            assertEquals(rejectedResidentBytes,
                    engine.capacitySnapshot().steady().reservedBytes());
        }
    }

    @Test
    void acceptedDirectProgressCanUseProtectedCapacityWhenOrdinaryReplacementCannot(
            @TempDir Path temporary) throws Exception {
        Path root = Files.createDirectory(temporary.resolve("protected-direct-progress"));
        MetadataKey key = new MetadataKey("io.zeroecho.test", "accepted-progress");
        SigningTransactionPayloadCodec.Mutation initial =
                new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.CREATE,
                        key, -1L, new byte[] { 1 });
        long initialRevision;
        long residentBytes;
        try (SigningLedgerStoreEngine engine = SigningLedgerStoreEngine.create(root, STORE_ID)) {
            MetadataCommitResult created = engine.directCommit(List.of(initial));
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, created.outcome());
            initialRevision = created.committedRevision().orElseThrow();
            residentBytes = engine.capacitySnapshot().steady().reservedBytes();
        }
        SigningActiveWal.Configuration configuration = SigningActiveWal.Configuration.defaults();
        long protectedFloor = SigningTransitionWorkspaceSizing.derive(
                SigningMvccIndex.FOUR_GIB_MAXIMUM_KEYS,
                configuration.queueCapacity()).workspaceFloorBytes();
        long exactBudget = Math.addExact(protectedFloor, residentBytes);
        SigningTransactionPayloadCodec.Mutation replacement =
                new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.REPLACE,
                        key, initialRevision, new byte[] { 2 });

        try (SigningLedgerStoreEngine engine = SigningLedgerStoreEngine.open(
                root, STORE_ID, SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK,
                configuration, exactBudget,
                FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES)) {
            SigningLedgerStoreEngine.CapacitySnapshot before = engine.capacitySnapshot();
            MetadataStoreException rejected = assertThrows(MetadataStoreException.class,
                    () -> engine.directCommit(List.of(replacement)));
            assertEquals(MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                    rejected.category());
            assertInstanceOf(SigningIndexCapacityBudget.CapacityExceededException.class,
                    rejected.getCause());
            assertEquals(before.steady().reservedBytes(),
                    engine.capacitySnapshot().steady().reservedBytes());

            MetadataCommitResult progressed = engine.directProgressCommit(List.of(replacement));
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, progressed.outcome());
            assertEquals(before.steady().reservedBytes(),
                    engine.capacitySnapshot().steady().reservedBytes());
        }
    }

    @Test
    void headroomPressureRotatesTinyWalAndLeavesRejectionRetryable(@TempDir Path temporary)
            throws Exception {
        Path root = Files.createDirectory(temporary.resolve("headroom-maintenance"));
        List<SigningTransactionPayloadCodec.Mutation> first = List.of(mutation("key0001"));
        List<SigningTransactionPayloadCodec.Mutation> next = List.of(mutation("key0002"));
        int payloadBytes = SigningTransactionPayloadCodec.directCommit(first, 0L).length;
        long maximumSegmentBytes = SigningWalContainerCodec.HEADER_BYTES
                + SigningWalFrameCodec.BATCH_MARKER_BYTES
                + SigningWalFrameCodec.HEADER_BYTES
                + (long) SigningWalFrameCodec.CHECKSUM_BYTES + payloadBytes;
        SigningActiveWal.Configuration configuration = new SigningActiveWal.Configuration(
                4, 1, 0L, 4L * SigningWalFrameCodec.MAX_PAYLOAD_BYTES,
                SigningActiveWal.MAXIMUM_BATCH_BYTES, maximumSegmentBytes);

        try (SigningLedgerStoreEngine engine = SigningLedgerStoreEngine.create(root, STORE_ID,
                null, SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK, configuration,
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES,
                FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES)) {
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    engine.directCommit(first).outcome());
            MetadataStoreException rejected = assertThrows(MetadataStoreException.class,
                    () -> engine.directCommit(next));
            assertEquals(MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                    rejected.category());

            awaitActiveGeneration(engine, root, 2L);
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    engine.directCommit(next).outcome());
            assertEquals(SigningActiveWal.State.OPEN, engine.writerSnapshot().state());
        }
    }

    @Test
    void headroomSignalRaisedDuringPassIsConsumedOnlyByFollowingRestoration() {
        SigningLedgerStoreEngine.MaintenancePressure pressure =
                new SigningLedgerStoreEngine.MaintenancePressure();
        pressure.signal();
        assertEquals(SigningLedgerStoreEngine.PressureReason.WAL, pressure.beginPass());
        pressure.signal();
        pressure.completePass(true, true);
        assertTrue(pressure.pending());

        assertEquals(SigningLedgerStoreEngine.PressureReason.WAL, pressure.beginPass());
        pressure.completePass(true, false);
        assertTrue(pressure.pending());
        assertEquals(SigningLedgerStoreEngine.PressureReason.WAL, pressure.beginPass());
        pressure.completePass(true, true);
        assertFalse(pressure.pending());
    }

    @Test
    void deferredPressureWaitsForANewExternalSignal() {
        SigningLedgerStoreEngine.MaintenancePressure pressure =
                new SigningLedgerStoreEngine.MaintenancePressure();
        pressure.signal();
        assertEquals(SigningLedgerStoreEngine.PressureReason.WAL, pressure.beginPass());
        pressure.deferPass(true);
        assertFalse(pressure.pending());
        assertNull(pressure.beginPass());

        pressure.signal();
        assertEquals(SigningLedgerStoreEngine.PressureReason.WAL, pressure.beginPass());
        pressure.completePass(true, true);
        assertFalse(pressure.pending());
    }

    @Test
    void protectedProgressPressureRemainsDistinctFromWalPressure() {
        SigningLedgerStoreEngine.MaintenancePressure wal =
                new SigningLedgerStoreEngine.MaintenancePressure();
        wal.signal();
        assertEquals(SigningLedgerStoreEngine.PressureReason.WAL, wal.reason());

        SigningLedgerStoreEngine.MaintenancePressure protectedProgress =
                new SigningLedgerStoreEngine.MaintenancePressure();
        protectedProgress.signalProtectedProgress();
        assertEquals(SigningLedgerStoreEngine.PressureReason.PROTECTED_PROGRESS,
                protectedProgress.reason());
        assertEquals(SigningLedgerStoreEngine.PressureReason.PROTECTED_PROGRESS,
                protectedProgress.beginPass());
        assertTrue(protectedProgress.completePass(true, true));
        assertFalse(protectedProgress.pending());
        assertNull(protectedProgress.reason());
    }

    @Test
    void protectedProgressYieldPreservesIndependentWalTrigger() {
        SigningLedgerStoreEngine.MaintenancePressure pressure =
                new SigningLedgerStoreEngine.MaintenancePressure();
        pressure.signal();
        pressure.signalProtectedProgress();

        assertEquals(SigningLedgerStoreEngine.PressureReason.PROTECTED_PROGRESS,
                pressure.beginPass());
        assertTrue(pressure.completePass(true, true));
        assertEquals(SigningLedgerStoreEngine.PressureReason.WAL, pressure.reason());
        assertEquals(SigningLedgerStoreEngine.PressureReason.WAL, pressure.beginPass());
        assertTrue(pressure.completePass(true, true));
        assertFalse(pressure.pending());
    }

    @Test
    void protectedProgressReleaseWakesAcceptedWorkWithoutRestartingMaintenance(
            @TempDir Path temporary) throws Exception {
        Path root = Files.createDirectory(temporary.resolve("protected-release"));
        CountDownLatch restored = new CountDownLatch(1);
        AtomicReference<Long> restoredEpoch = new AtomicReference<>();
        try (SigningLedgerStoreEngine engine = SigningLedgerStoreEngine.create(root, STORE_ID);
                AutoCloseable ignored = engine.registerHeadroomRestored(
                        new AtomicLocalSigningLedgerParticipant.HeadroomListener() {
                            @Override
                            public void restored(long epoch) {
                                restoredEpoch.set(epoch);
                                restored.countDown();
                            }

                            @Override
                            public void recoveryRequired() {
                                throw new AssertionError("store unexpectedly requires recovery");
                            }
                        })) {
            SigningIndexCapacityBudget probeBudget = new SigningIndexCapacityBudget(1L);
            SigningIndexCapacityBudget.CapacityExceededException exhausted = assertThrows(
                    SigningIndexCapacityBudget.CapacityExceededException.class,
                    () -> probeBudget.reserve(2L,
                            SigningTransitionWorkspaceSizing.AdmissionClass
                                    .PROTECTED_ACCEPTED_SIGNING));
            long initialPasses = engine.maintenanceCoordinatorSnapshot().passes();
            long initialEpoch = engine.headroomRestorationEpoch();

            engine.signalProtectedProgressPressure(exhausted);
            SigningLedgerStoreEngine.MaintenanceCoordinatorSnapshot yielded =
                    awaitMaintenanceState(engine, initialPasses + 1L, false, null);
            assertFalse(yielded.requested());

            SigningLedgerStoreEngine.ConditionalCommitResult committed =
                    engine.directCommitAtAdmission(
                            new SigningLedgerStoreEngine.ConditionalDirectCommit(
                                    List.of(mutation("protected-release-primary", 1)),
                                    List.of(mutation("protected-release-fallback", 1)),
                                    () -> false, () -> { }));
            assertFalse(committed.primaryAdmitted());
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    committed.result().outcome());
            assertTrue(restored.await(5L, TimeUnit.SECONDS));
            assertEquals(initialEpoch + 1L, restoredEpoch.get());
            // The fallback commit's post-publish signalMaintenance() briefly re-arms the
            // coordinator to re-check WAL rotation; that wake performs no pass. Wait for
            // the coordinator to quiesce at the unchanged pass count instead of sampling
            // the transient request, which otherwise races the maintenance thread. A
            // genuine maintenance restart would advance the pass count and time this out.
            SigningLedgerStoreEngine.MaintenanceCoordinatorSnapshot afterRelease =
                    awaitMaintenanceState(engine, yielded.passes(), false, null);
            assertEquals(yielded.passes(), afterRelease.passes());
            assertFalse(afterRelease.requested());
            assertFalse(afterRelease.deferred());
            assertNull(engine.firstRecoveryFailure());
        }
    }

    @Test
    void persistentTransientDeferralIgnoresUnrelatedCommitsWithoutTopologyChurn(
            @TempDir Path temporary) throws Exception {
        Path root = Files.createDirectory(temporary.resolve("transient-deferral"));
        SigningActiveWal.Configuration configuration = maintenanceConfiguration();
        try (SigningLedgerStoreEngine engine = SigningLedgerStoreEngine.create(root, STORE_ID,
                null, SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK, configuration,
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES, 319L)) {
            rotateSegments(engine, root, 8);
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    engine.directCommit(List.of(mutation("blocked-base", 1))).outcome());
            rejectForHeadroom(engine, "blocked-trigger");
            SigningLedgerStoreEngine.MaintenanceCoordinatorSnapshot deferred =
                    awaitMaintenanceState(engine, 9L, true,
                            SigningLedgerMaintenance.DeferralReason.TRANSIENT_CAPACITY);
            SigningManifestCodec.Manifest before = readManifest(root);
            int generationsBefore = engine.capacityObservation().registeredGenerations();

            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    engine.directCommit(List.of(mutation("unrelated", 1))).outcome());

            SigningLedgerStoreEngine.MaintenanceCoordinatorSnapshot after =
                    engine.maintenanceCoordinatorSnapshot();
            assertEquals(deferred.passes(), after.passes());
            assertTrue(after.deferred());
            assertFalse(after.requested());
            assertEquals(deferred.deferralReason(), after.deferralReason());
            SigningManifestCodec.Manifest current = readManifest(root);
            assertEquals(before.activeWal().identity(), current.activeWal().identity());
            assertEquals(before.sealedSegments().stream()
                    .map(SigningManifestCodec.Segment::name).toList(),
                    current.sealedSegments().stream()
                            .map(SigningManifestCodec.Segment::name).toList());
            assertEquals(generationsBefore,
                    engine.capacityObservation().registeredGenerations());
            assertNull(engine.firstRecoveryFailure());
        }
    }

    @Test
    void cumulativeWriterCountersStayMonotoneAcrossWalRotation(@TempDir Path temporary)
            throws Exception {
        Path root = Files.createDirectory(temporary.resolve("cumulative-writer"));
        try (SigningLedgerStoreEngine engine = SigningLedgerStoreEngine.create(root, STORE_ID,
                null, SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK, maintenanceConfiguration(),
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES,
                FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES)) {
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    engine.directCommit(List.of(mutation("cumulative-seed", 1))).outcome());
            SigningActiveWal.Snapshot beforeRotation = engine.cumulativeWriterSnapshot();
            assertTrue(beforeRotation.requestsCommitted() > 0L,
                    "the seed request must be counted before any rotation");

            rotateSegments(engine, root, 8);

            // The freshly published active WAL has reset its own counters to zero.
            SigningActiveWal.Snapshot activeAfter = engine.writerSnapshot();
            SigningActiveWal.Snapshot cumulativeAfter = engine.cumulativeWriterSnapshot();
            assertTrue(activeAfter.requestsCommitted() < beforeRotation.requestsCommitted(),
                    "the rotated active WAL alone must not retain the pre-rotation total");
            // The cumulative view folds every sealed WAL, so no counter regresses.
            assertTrue(cumulativeAfter.requestsCommitted() >= beforeRotation.requestsCommitted(),
                    "cumulative committed requests must not regress across WAL rotation");
            assertTrue(cumulativeAfter.groupsCommitted() >= beforeRotation.groupsCommitted(),
                    "cumulative committed groups must not regress across WAL rotation");
            assertTrue(cumulativeAfter.forces() >= beforeRotation.forces(),
                    "cumulative forces must not regress across WAL rotation");
            assertTrue(cumulativeAfter.bytesAppended() >= beforeRotation.bytesAppended(),
                    "cumulative appended bytes must not regress across WAL rotation");
            // Each of the eight rotations committed one further framed request, so the
            // cumulative total strictly exceeds the freshly rotated active WAL.
            assertTrue(cumulativeAfter.requestsCommitted() > activeAfter.requestsCommitted(),
                    "cumulative counters must span the sealed WALs, not only the active one");
            assertNull(engine.firstRecoveryFailure());
        }
    }

    @Test
    void snapshotCloseRearmsExactlyOneDeferredCoordinatorPass(
            @TempDir Path temporary) throws Exception {
        Path root = Files.createDirectory(temporary.resolve("snapshot-deferral"));
        SigningActiveWal.Configuration configuration = maintenanceConfiguration();
        try (SigningLedgerStoreEngine engine = SigningLedgerStoreEngine.create(root, STORE_ID,
                null, SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK, configuration,
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES,
                FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES)) {
            rotateSegments(engine, root, 8);
            SigningMvccIndex.Snapshot external = engine.snapshot();
            try {
                assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                        engine.directCommit(List.of(mutation("snapshot-base", 1))).outcome());
                rejectForHeadroom(engine, "snapshot-trigger");
                awaitMaintenanceState(engine, 9L, true,
                        SigningLedgerMaintenance.DeferralReason.SNAPSHOT);

                assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                        engine.directCommit(List.of(mutation("snapshot-unrelated", 1))).outcome());
                SigningLedgerStoreEngine.MaintenanceCoordinatorSnapshot stillDeferred =
                        engine.maintenanceCoordinatorSnapshot();
                assertEquals(9L, stillDeferred.passes());
                assertTrue(stillDeferred.deferred());
                assertFalse(stillDeferred.requested());
            } finally {
                external.close();
            }

            SigningLedgerStoreEngine.MaintenanceCoordinatorSnapshot completed =
                    awaitMaintenanceState(engine, 10L, false, null);
            assertEquals(10L, completed.passes());
            assertFalse(completed.requested());
            assertNull(engine.firstRecoveryFailure());
        }
    }

    @Test
    void reservationCapturesWaitForManifestCutoverInsteadOfLeakingCapacityFailure(
            @TempDir Path temporary) throws Exception {
        Path root = Files.createDirectory(temporary.resolve("cutover-captures"));
        CountDownLatch cutoverPaused = new CountDownLatch(1);
        CountDownLatch releaseCutover = new CountDownLatch(1);
        SigningLedgerMaintenance.FaultInjector faults = pauseCutover(
                cutoverPaused, releaseCutover);
        ExecutorService captures = Executors.newFixedThreadPool(5);
        try (SigningLedgerStoreEngine engine = SigningLedgerStoreEngine.create(root, STORE_ID,
                null, SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK, maintenanceConfiguration(),
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES,
                FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES, faults)) {
            rotateSegments(engine, root, 8);
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    engine.directCommit(List.of(mutation("capture-base", 1))).outcome());
            rejectForHeadroom(engine, "capture-trigger");
            assertTrue(cutoverPaused.await(5L, TimeUnit.SECONDS));

            List<Future<Boolean>> attempts = List.of(
                    captures.submit(() -> close(engine.snapshot())),
                    captures.submit(() -> close(engine.selectCurrentFirst(
                            MetadataSnapshot.KeyRange.prefix("io.zeroecho.test", "")))),
                    captures.submit(() -> close(engine.selectCurrentRange(
                            MetadataSnapshot.KeyRange.prefix("io.zeroecho.test", "")))),
                    captures.submit(() -> close(engine.pageDue(Instant.MAX,
                            Optional.empty(), Optional.empty(), 1))),
                    captures.submit(() -> close(engine.pageOwners(Optional.empty(), 1))));
            AtomicBoolean interruptedStatus = new AtomicBoolean();
            AtomicReference<Throwable> interruptedFailure = new AtomicReference<>();
            Thread interruptedCapture = new Thread(() -> {
                try (SigningMvccIndex.Snapshot ignored = engine.snapshot()) {
                    interruptedFailure.set(new AssertionError(
                            "Interrupted capture unexpectedly acquired a snapshot"));
                } catch (Throwable failure) {
                    interruptedFailure.set(failure);
                    interruptedStatus.set(Thread.currentThread().isInterrupted());
                }
            }, "signing-engine-interrupted-capture-test");
            try {
                for (Future<Boolean> attempt : attempts) {
                    assertThrows(TimeoutException.class,
                            () -> attempt.get(100L, TimeUnit.MILLISECONDS));
                }
                interruptedCapture.start();
                awaitWaiting(interruptedCapture);
                interruptedCapture.interrupt();
                interruptedCapture.join(TimeUnit.SECONDS.toMillis(5L));
                assertFalse(interruptedCapture.isAlive());
                MetadataStoreException cancellation = assertInstanceOf(
                        MetadataStoreException.class, interruptedFailure.get());
                assertEquals(MetadataCommitResult.FailureCategory.CANCELLED,
                        cancellation.category());
                assertInstanceOf(InterruptedException.class, cancellation.getCause());
                assertTrue(interruptedStatus.get());
                assertNull(engine.firstRecoveryFailure());
            } finally {
                interruptedCapture.interrupt();
                releaseCutover.countDown();
            }
            for (Future<Boolean> attempt : attempts) {
                assertTrue(attempt.get(5L, TimeUnit.SECONDS));
            }
            assertNull(engine.firstRecoveryFailure());
        } finally {
            releaseCutover.countDown();
            captures.shutdownNow();
            assertTrue(captures.awaitTermination(5L, TimeUnit.SECONDS));
        }
    }

    @Test
    void signingAdmissionRejectsNonblockinglyWhileManifestCutoverIsPaused(
            @TempDir Path temporary) throws Exception {
        Path root = Files.createDirectory(temporary.resolve("cutover-sign-admission"));
        CountDownLatch cutoverPaused = new CountDownLatch(1);
        CountDownLatch releaseCutover = new CountDownLatch(1);
        SigningLedgerMaintenance.FaultInjector faults = pauseCutover(
                cutoverPaused, releaseCutover);
        try (SigningLedgerStoreEngine engine = SigningLedgerStoreEngine.create(root, STORE_ID,
                null, SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK, maintenanceConfiguration(),
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES,
                FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES, faults)) {
            rotateSegments(engine, root, 8);
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    engine.directCommit(List.of(mutation("admission-base", 1))).outcome());
            rejectForHeadroom(engine, "admission-trigger");
            assertTrue(cutoverPaused.await(5L, TimeUnit.SECONDS));

            try {
                assertThrows(SigningActiveWal.OverloadedException.class,
                        engine::reserveSigningAdmission);
                assertNull(engine.firstRecoveryFailure());
            } finally {
                releaseCutover.countDown();
            }
        } finally {
            releaseCutover.countDown();
        }
    }

    private static SigningActiveWal.Configuration maintenanceConfiguration() {
        return new SigningActiveWal.Configuration(
                8, 8, 0L, 8L * SigningWalFrameCodec.MAX_PAYLOAD_BYTES,
                SigningActiveWal.MAXIMUM_BATCH_BYTES, 8L * 1024L);
    }

    private static SigningLedgerMaintenance.FaultInjector pauseCutover(
            CountDownLatch paused, CountDownLatch release) {
        return stage -> {
            if (stage != SigningLedgerMaintenance.Stage.COMPACTION_MANIFEST_READY) {
                return;
            }
            paused.countDown();
            try {
                release.await();
            } catch (InterruptedException failure) {
                Thread.currentThread().interrupt();
                throw new IOException("Test cutover pause was interrupted", failure);
            }
        };
    }

    private static boolean close(AutoCloseable closeable) throws Exception {
        closeable.close();
        return true;
    }

    private static void rotateSegments(SigningLedgerStoreEngine engine, Path root,
            int rotations) throws Exception {
        for (int index = 0; index < rotations; index++) {
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    engine.directCommit(List.of(mutation("segment-" + index, 3_000))).outcome());
            rejectForHeadroom(engine, "rotate-" + index);
            awaitActiveGeneration(engine, root, index + 2L);
        }
    }

    private static void rejectForHeadroom(SigningLedgerStoreEngine engine, String name)
            throws Exception {
        MetadataStoreException rejected = assertThrows(MetadataStoreException.class,
                () -> engine.directCommit(List.of(mutation(name, 8 * 1024))));
        assertEquals(MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                rejected.category());
    }

    private static SigningLedgerStoreEngine.MaintenanceCoordinatorSnapshot awaitMaintenanceState(
            SigningLedgerStoreEngine engine, long passes, boolean deferred,
            SigningLedgerMaintenance.DeferralReason reason) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5L);
        while (System.nanoTime() < deadline) {
            SigningLedgerStoreEngine.MaintenanceCoordinatorSnapshot snapshot =
                    engine.maintenanceCoordinatorSnapshot();
            if (snapshot.passes() == passes && snapshot.deferred() == deferred
                    && snapshot.deferralReason() == reason && !snapshot.requested()) {
                return snapshot;
            }
            Thread.onSpinWait();
        }
        throw new AssertionError("metadata maintenance did not reach the expected state");
    }

    private static void awaitWaiting(Thread thread) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5L);
        while (System.nanoTime() < deadline) {
            if (thread.getState() == Thread.State.WAITING) {
                return;
            }
            Thread.onSpinWait();
        }
        throw new AssertionError("capture waiter did not block");
    }

    private static SigningManifestCodec.Manifest readManifest(Path root) throws Exception {
        return SigningManifestCodec.decode(Files.readAllBytes(
                root.resolve(SigningLedgerRecovery.MANIFEST_FILE)));
    }

    private static void awaitActiveGeneration(SigningLedgerStoreEngine engine, Path root,
            long expectedIdentity) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5L);
        while (System.nanoTime() < deadline) {
            SigningManifestCodec.Manifest manifest = SigningManifestCodec.decode(Files.readAllBytes(
                    root.resolve(SigningLedgerRecovery.MANIFEST_FILE)));
            SigningActiveWal.Snapshot writer = engine.writerSnapshot();
            if (manifest.activeWal().identity() == expectedIdentity
                    && writer.state() == SigningActiveWal.State.OPEN
                    && writer.bytesAppended() == 0L) {
                return;
            }
            Thread.onSpinWait();
        }
        throw new AssertionError("metadata maintenance did not publish the expected active WAL");
    }

    private static SigningTransactionPayloadCodec.Mutation mutation(byte[] content) {
        return new SigningTransactionPayloadCodec.Mutation(
                SigningTransactionPayloadCodec.MutationKind.CREATE,
                new MetadataKey("io.zeroecho.test", "coordinator"), -1L, content);
    }

    private static SigningTransactionPayloadCodec.Mutation mutation(String name) {
        return mutation(name, 1);
    }

    private static SigningTransactionPayloadCodec.Mutation mutation(String name, int bytes) {
        return new SigningTransactionPayloadCodec.Mutation(
                SigningTransactionPayloadCodec.MutationKind.CREATE,
                new MetadataKey("io.zeroecho.test", name), -1L, new byte[bytes]);
    }
}
