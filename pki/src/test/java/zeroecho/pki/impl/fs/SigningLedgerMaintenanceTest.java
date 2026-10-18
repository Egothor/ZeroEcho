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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataStoreId;

final class SigningLedgerMaintenanceTest {
    private static final MetadataStoreId STORE_ID =
            new MetadataStoreId("0123456789abcdef0123456789abcdef");

    @TempDir
    private Path temporaryDirectory;

    @Test
    void rotateCopiesColdSegmentAndPublishesManifestLast() throws Exception {
        Fixture fixture = fixture("rotate");
        try (SigningLedgerMaintenance maintenance = fixture.maintenance()) {
            SigningLedgerMaintenance.Rotation rotation = maintenance.rotate(2L);
            assertEquals(0L, rotation.sealed().firstSequence());
            assertEquals(1L, rotation.sealed().sequenceCount());
            assertTrue(Files.exists(fixture.root().resolve(rotation.sealed().name())));
            assertTrue(Files.isSameFile(fixture.root().resolve(rotation.sealed().name()),
                    fixture.root().resolve(SigningManifestCodec.activeName(1L))));
            assertTrue(Files.exists(fixture.root().resolve(
                    SigningManifestCodec.activeName(1L))));
            assertEquals(2L, maintenance.manifest().activeWal().identity());
            assertEquals(1L, maintenance.manifest().activeWal().firstSequence());
        }
    }

    @Test
    void rotationPreservesExactActiveWalConfiguration() throws Exception {
        AtomicInteger copies = new AtomicInteger();
        SigningActiveWal.Configuration defaults = SigningActiveWal.Configuration.defaults(1);
        SigningActiveWal.Configuration configured = new SigningActiveWal.Configuration(
                defaults.queueCapacity(), defaults.maximumGroupSize(),
                defaults.maximumGroupWaitNanos(), defaults.maximumQueuedPayloadBytes(),
                defaults.maximumBatchBytes(), defaults.maximumSegmentBytes(), payload -> {
                    copies.incrementAndGet();
                    return payload.clone();
                });
        Fixture fixture = fixture("configured-rotation", configured);
        int copiesBeforeRotation = copies.get();
        try (SigningLedgerMaintenance maintenance = fixture.maintenance()) {
            maintenance.rotate(2L);
            maintenance.activeWal().submit(SigningWalFrameCodec.RecordType.MUTATION,
                    new UUID(2L, 2L), new byte[] { 8 }).await();
            assertTrue(copies.get() > copiesBeforeRotation);
            assertTrue(maintenance.activeWal().snapshot().maximumBatchSize() <= 1L);
        }
    }

    @Test
    void compactionIsSelfContainedRelocatesCurrentAndReclaimsOnlyAfterPinsRelease()
            throws Exception {
        Fixture fixture = fixture("compact");
        SigningMvccIndex.Snapshot oldSnapshot = fixture.index().snapshot();
        String checkpointName;
        try (SigningLedgerMaintenance maintenance = fixture.maintenance()) {
            SigningLedgerMaintenance.Compaction result = maintenance.compact(2L, 3L);
            checkpointName = result.checkpoint().name();
            assertEquals(1, result.liveRecords());
            assertEquals(2L, fixture.index().lookup(fixture.key()).orElseThrow()
                    .pointer().generationId());
            assertTrue(maintenance.manifest().sealedSegments().isEmpty());
            assertEquals(0, maintenance.reclaim(8));
            oldSnapshot.close();
            assertEquals(1, maintenance.reclaim(8));
            assertFalse(Files.exists(fixture.root().resolve(
                    SigningManifestCodec.activeName(1L))));
            assertFalse(Files.exists(fixture.root().resolve(
                    SigningManifestCodec.segmentName(0L, 0L))));
            assertTrue(Files.exists(fixture.root().resolve(checkpointName)));
        }
    }

    @Test
    void onlineCompactionReopensAdmissionThenDrainsAndPublishesExactCandidate()
            throws Exception {
        Fixture fixture = fixture("online-compact");
        MetadataKey postBoundary = new MetadataKey("example", "online");
        AtomicBoolean admissionReopened = new AtomicBoolean();
        AtomicBoolean finalGateDrained = new AtomicBoolean();
        SigningLedgerMaintenance[] holder = new SigningLedgerMaintenance[1];
        holder[0] = fixture.maintenance(stage -> {
            if (stage == SigningLedgerMaintenance.Stage.CHECKPOINT_PUBLISHED) {
                assertTrue(admissionReopened.get());
                SigningActiveWal.CommitResult committed = await(holder[0].activeWal().submit(
                        SigningWalFrameCodec.RecordType.MUTATION,
                        new UUID(4L, 1L), new byte[] { 11 }));
                fixture.index().apply(committed.revision(), committed.sequence(),
                        List.of(SigningMvccIndex.Mutation.upsert(
                                postBoundary, pointer(3L, committed))));
            }
        });
        try (SigningLedgerMaintenance maintenance = holder[0]) {
            maintenance.compactOnline(2L, 3L,
                    () -> admissionReopened.set(true),
                    () -> finalGateDrained.set(true), new Object(),
                    (frame, pointer) -> List.of(SigningMvccIndex.Mutation.upsert(
                            postBoundary, pointer)));
            assertTrue(finalGateDrained.get());
            assertFalse(fixture.index().hasPreparedApplies());
            assertEquals(2L, fixture.index().lookup(fixture.key()).orElseThrow()
                    .pointer().generationId());
            assertEquals(3L, fixture.index().lookup(postBoundary).orElseThrow()
                    .pointer().generationId());
            assertTrue(maintenance.manifest().checkpoint().isPresent());
            assertTrue(maintenance.manifest().sealedSegments().isEmpty());
            assertEquals(0L, fixture.generations().statistics().dueReferences());
            assertEquals(0L, fixture.generations().statistics().ownerReferences());
        }
    }

    @Test
    void transientCapacityPreflightDefersBeforeRotationOrCandidateArtifacts()
            throws Exception {
        SigningActiveWal.Configuration configuration = new SigningActiveWal.Configuration(
                8, 8, 0L, 8L * SigningWalFrameCodec.MAX_PAYLOAD_BYTES,
                SigningActiveWal.MAXIMUM_BATCH_BYTES);
        Fixture fixture = fixture("online-transient-capacity", configuration, 319L);
        try (SigningLedgerMaintenance maintenance = fixture.maintenance()) {
            SigningLedgerMaintenance.CompactionDeferredException deferred = assertThrows(
                    SigningLedgerMaintenance.CompactionDeferredException.class,
                    () -> maintenance.compactOnline(2L, 3L, () -> { }, () -> { },
                            new Object(), (frame, pointer) -> List.of()));
            assertEquals(SigningLedgerMaintenance.DeferralReason.TRANSIENT_CAPACITY,
                    deferred.reason());
            assertFalse(maintenance.recoveryRequired());
            assertEquals(1L, maintenance.manifest().activeWal().identity());
            assertTrue(maintenance.manifest().sealedSegments().isEmpty());
            assertFalse(fixture.artifacts().contains(2L));
            assertFalse(fixture.artifacts().contains(3L));
            assertEquals(0L, fixture.transientBudget().snapshot().reservedBytes());
            assertEquals(1, fixture.generations().statistics().registered());
            try (Stream<Path> entries = Files.list(fixture.root())) {
                assertFalse(entries.map(path -> path.getFileName().toString())
                        .anyMatch(name -> name.startsWith("checkpoint-")));
            }
        }
    }

    @Test
    @SuppressWarnings({ "PMD.UnitTestContainsTooManyAsserts",
            "PMD.UnitTestAssertionsShouldIncludeMessage" })
    void steadyCapacityPreflightDefersBeforeRotationOrCandidateArtifacts()
            throws Exception {
        Fixture fixture = fixture("online-steady-capacity");
        SigningIndexCapacityBudget.Snapshot before = fixture.budget().snapshot();
        long remaining = before.maximumBytes() - before.reservedBytes();
        {
            SigningIndexCapacityBudget.Reservation saturated = fixture.budget().reserve(remaining);
            try (saturated) {
                try (SigningLedgerMaintenance maintenance = fixture.maintenance()) {
                    SigningLedgerMaintenance.CompactionDeferredException deferred = assertThrows(
                            SigningLedgerMaintenance.CompactionDeferredException.class,
                            () -> maintenance.compactOnline(2L, 3L, () -> { }, () -> { },
                                    new Object(), (frame, pointer) -> List.of()));
                    assertEquals(SigningLedgerMaintenance.DeferralReason.STEADY_CAPACITY,
                            deferred.reason());
                    assertFalse(maintenance.recoveryRequired());
                    assertEquals(1L, maintenance.manifest().activeWal().identity());
                    assertTrue(maintenance.manifest().sealedSegments().isEmpty());
                    assertFalse(fixture.artifacts().contains(2L));
                    assertFalse(fixture.artifacts().contains(3L));
                    assertEquals(1, fixture.generations().statistics().registered());
                }
            }
        }
    }

    @Test
    void protectedProgressProbeDefersWithoutRecoveryOrTopologyChange() throws Exception {
        Fixture fixture = fixture("online-protected-progress");
        SigningIndexCapacityBudget pressureBudget = new SigningIndexCapacityBudget(1L);
        SigningIndexCapacityBudget.CapacityExceededException pressure = assertThrows(
                SigningIndexCapacityBudget.CapacityExceededException.class,
                () -> pressureBudget.reserve(2L,
                        SigningTransitionWorkspaceSizing.AdmissionClass
                                .PROTECTED_ACCEPTED_SIGNING));
        CountDownLatch probed = new CountDownLatch(1);
        try (SigningLedgerMaintenance maintenance = fixture.maintenance()) {
            SigningLedgerMaintenance.CompactionDeferredException deferred = assertThrows(
                    SigningLedgerMaintenance.CompactionDeferredException.class,
                    () -> maintenance.compactOnline(2L, 3L, () -> { }, () -> { },
                            new Object(), (frame, pointer) -> List.of(), () -> {
                                probed.countDown();
                                return pressure;
                            }));
            assertEquals(0L, probed.getCount());
            assertEquals(SigningLedgerMaintenance.DeferralReason.PROTECTED_PROGRESS,
                    deferred.reason());
            assertEquals(pressure, deferred.getCause());
            assertFalse(maintenance.recoveryRequired());
            assertEquals(1L, maintenance.manifest().activeWal().identity());
            assertTrue(maintenance.manifest().sealedSegments().isEmpty());
            assertFalse(fixture.artifacts().contains(2L));
            assertFalse(fixture.artifacts().contains(3L));
            assertEquals(1, fixture.generations().statistics().registered());
        }
    }

    @Test
    void catchUpCapacityDeferralRemovesCandidateArtifactsWithoutRequiringRecovery()
            throws Exception {
        SigningActiveWal.Configuration configuration = new SigningActiveWal.Configuration(
                8, 8, 0L, 8L * SigningWalFrameCodec.MAX_PAYLOAD_BYTES,
                SigningActiveWal.MAXIMUM_BATCH_BYTES);
        Fixture fixture = fixture("online-catch-up-capacity", configuration, 650L);
        MetadataKey catchUpKey = new MetadataKey("example", "online-capacity");
        SigningLedgerMaintenance[] holder = new SigningLedgerMaintenance[1];
        holder[0] = fixture.maintenance(stage -> {
            if (stage == SigningLedgerMaintenance.Stage.CHECKPOINT_PUBLISHED) {
                SigningActiveWal.CommitResult committed = await(holder[0].activeWal().submit(
                        SigningWalFrameCodec.RecordType.MUTATION,
                        new UUID(5L, 1L), new byte[] { 12 }));
                fixture.index().apply(committed.revision(), committed.sequence(),
                        List.of(SigningMvccIndex.Mutation.upsert(
                                catchUpKey, pointer(3L, committed))));
            }
        });
        try (SigningLedgerMaintenance maintenance = holder[0]) {
            SigningLedgerMaintenance.CompactionDeferredException deferred = assertThrows(
                    SigningLedgerMaintenance.CompactionDeferredException.class,
                    () -> maintenance.compactOnline(2L, 3L, () -> { }, () -> { },
                            new Object(), (frame, pointer) -> List.of(
                                    SigningMvccIndex.Mutation.upsert(catchUpKey, pointer))));
            assertEquals(SigningLedgerMaintenance.DeferralReason.TRANSIENT_CAPACITY,
                    deferred.reason());
            assertFalse(maintenance.recoveryRequired());
            assertEquals(3L, maintenance.manifest().activeWal().identity());
            assertFalse(fixture.artifacts().contains(2L));
            assertEquals(0L, fixture.transientBudget().snapshot().reservedBytes());
            assertEquals(2, fixture.generations().statistics().registered());
            try (Stream<Path> entries = Files.list(fixture.root())) {
                assertFalse(entries.map(path -> path.getFileName().toString())
                        .anyMatch(name -> name.startsWith("checkpoint-")));
            }
        }
    }

    @ParameterizedTest(name = "online compaction durable authority: {0}")
    @MethodSource("onlineCompactionCrashBoundaries")
    void onlineCompactionRestartUsesOnlyTheForcedManifestBoundary(
            SigningLedgerMaintenance.Stage faultStage) throws Exception {
        Fixture fixture = fixture("online-crash-" + faultStage);
        SigningLedgerMaintenance maintenance = fixture.maintenance(stage -> {
            if (stage == faultStage) {
                throw new IOException("injected online compaction boundary");
            }
        });
        try {
            assertThrows(SigningLedgerMaintenance.MaintenanceException.class,
                    () -> maintenance.compactOnline(2L, 3L, () -> { }, () -> { },
                            new Object(), (frame, pointer) -> List.of()));
            assertTrue(maintenance.recoveryRequired());
        } finally {
            maintenance.close();
        }
        boolean manifestForced = faultStage
                == SigningLedgerMaintenance.Stage.COMPACTION_MANIFEST_READY
                || faultStage == SigningLedgerMaintenance.Stage.COMPACTION_ROOT_SWAPPED
                || faultStage
                        == SigningLedgerMaintenance.Stage.COMPACTION_GENS_SUPERSEDED;
        try (SigningLedgerRecovery.Handle recovered = SigningLedgerRecovery.recover(
                fixture.root(), recoveryConfiguration(), emptySink())) {
            assertEquals(manifestForced, recovered.manifest().checkpoint().isPresent());
            assertManifestArtifactsExist(fixture.root(), recovered.manifest());
        }
    }

    @Test
    void failureBeforeManifestLeavesOldTopologyRecoverable() throws Exception {
        Fixture fixture = fixture("old-topology");
        SigningLedgerMaintenance maintenance = fixture.maintenance(stage -> {
            if (stage == SigningLedgerMaintenance.Stage.SEALED_PUBLISHED) {
                throw new IOException("injected");
            }
        });
        assertThrows(IOException.class, () -> maintenance.rotate(2L));
        assertTrue(maintenance.recoveryRequired());
        maintenance.close();

        try (SigningLedgerRecovery.Handle recovered = SigningLedgerRecovery.recover(
                fixture.root(), recoveryConfiguration(), emptySink())) {
            assertEquals(1L, recovered.manifest().activeWal().identity());
            assertEquals(1L, recovered.statistics().unreferencedArtifacts());
        }
    }

    @ParameterizedTest
    @MethodSource("rotationCrashBoundaries")
    void everyRotationCrashBoundaryRecoversExactlyOneTopology(
            SigningLedgerMaintenance.Stage faultStage, boolean newTopology) throws Exception {
        Fixture fixture = fixture("rotation-crash-" + faultStage);
        SigningLedgerMaintenance maintenance = fixture.maintenance(stage -> {
            if (stage == faultStage) {
                throw new IOException("injected");
            }
        });
        SigningLedgerMaintenance.MaintenanceException failure = assertThrows(
                SigningLedgerMaintenance.MaintenanceException.class,
                () -> maintenance.rotate(2L));
        assertEquals(SigningLedgerMaintenance.MaintenanceStage.ROTATE, failure.stage());
        assertTrue(maintenance.recoveryRequired());
        maintenance.close();

        try (SigningLedgerRecovery.Handle recovered = SigningLedgerRecovery.recover(
                fixture.root(), recoveryConfiguration(), emptySink())) {
            assertEquals(newTopology ? 2L : 1L,
                    recovered.manifest().activeWal().identity());
            assertEquals(newTopology ? 1 : 0,
                    recovered.manifest().sealedSegments().size());
            if (newTopology) {
                SigningManifestCodec.Segment segment = recovered.manifest()
                        .sealedSegments().getFirst();
                assertEquals(1L, segment.generationIdentity());
                assertEquals(0L, segment.firstSequence());
                assertEquals(1L, recovered.manifest().activeWal().firstSequence());
            }
            assertTrue(recovered.manifest().checkpoint().isEmpty());
        }
    }

    @ParameterizedTest(name = "maintenance restart/retry boundary: {0}")
    @MethodSource("maintenanceCrashBoundaries")
    void maintenanceCrashRestartMatrix(SigningLedgerMaintenance.Stage faultStage) throws Exception {
        if (faultStage == SigningLedgerMaintenance.Stage.CHECKPOINT_PUBLISHED
                || faultStage == SigningLedgerMaintenance.Stage.COMPACTION_MANIFEST_READY
                || faultStage == SigningLedgerMaintenance.Stage.COMPACTION_MEMORY_PUBLISHED) {
            assertCompactionCrashBoundary(faultStage);
        } else {
            assertReclamationCrashBoundary(faultStage);
        }
    }

    @ParameterizedTest(name = "direct reclamation restart boundary: {0}")
    @MethodSource("directReclamationRestartBoundaries")
    void directReclamationRestartMatrix(SigningLedgerMaintenance.Stage faultStage) throws Exception {
        Fixture fixture = fixture("direct-reclamation-restart-" + faultStage);
        SigningLedgerMaintenance maintenance = fixture.maintenance(stage -> {
            if (stage == faultStage) {
                throw new IOException("injected reclamation boundary");
            }
        });
        SigningLedgerMaintenance.MaintenanceException failure;
        try {
            {
                SigningGenerationRegistry.CurrentReferences current =
                    fixture.generations().acquireCurrent(
                    SigningGenerationRegistry.Owner.RECOVERY_TEMPORARY, List.of(1L));
                try (current) {
                    SigningGenerationRegistry.SnapshotPins pins =
                        fixture.generations().pinSnapshot(List.of(1L));
                    try (pins) {
                        maintenance.compact(2L, 3L);
                    }
                }
            }
            failure = assertThrows(SigningLedgerMaintenance.MaintenanceException.class,
                    () -> maintenance.reclaim(8));
        } finally {
            maintenance.close();
        }

        assertEquals(SigningLedgerMaintenance.MaintenanceStage.RECLAIM, failure.stage());
        assertEquals("signing ledger maintenance failed: RECLAIM", failure.getMessage());
        assertReclamationBoundaryArtifacts(fixture.root(), faultStage);
        byte[] authoritativeManifest = Files.readAllBytes(fixture.root().resolve(
                SigningLedgerRecovery.MANIFEST_FILE));

        RecoveredRecords firstRecords = new RecoveredRecords();
        try (SigningLedgerRecovery.Handle recovered = SigningLedgerRecovery.recover(
                fixture.root(), recoveryConfiguration(), firstRecords)) {
            assertCompactionTopology(recovered.manifest(), true);
            assertManifestArtifactsExist(fixture.root(), recovered.manifest());
            Set<String> expectedCandidates = expectedReclamationCandidates(faultStage);
            assertEquals(expectedCandidates, recovered.cleanupPlan().entries().stream()
                    .map(SigningLedgerRecovery.CleanupEntry::name).collect(java.util.stream.Collectors.toSet()));
            assertTrue(recovered.cleanupPlan().entries().stream().allMatch(entry -> entry.category()
                    == SigningLedgerRecovery.Category.ORPHAN_ARTIFACT_DEFERRED));
            assertEquals(expectedCandidates.size(), SigningLedgerMaintenance.cleanupDeferredArtifacts(
                    fixture.root(), recovered.manifest(), recovered.cleanupPlan()));
            assertManifestArtifactsExist(fixture.root(), recovered.manifest());
            assertEquals(1, recovered.statistics().checkpointEntries());
        }

        RecoveredRecords secondRecords = new RecoveredRecords();
        try (SigningLedgerRecovery.Handle restarted = SigningLedgerRecovery.recover(
                fixture.root(), recoveryConfiguration(), secondRecords)) {
            assertCompactionTopology(restarted.manifest(), true);
            assertManifestArtifactsExist(fixture.root(), restarted.manifest());
            assertTrue(restarted.cleanupPlan().entries().isEmpty());
            assertEquals(1, restarted.statistics().checkpointEntries());
        }
        assertArrayEquals(authoritativeManifest, Files.readAllBytes(fixture.root().resolve(
                SigningLedgerRecovery.MANIFEST_FILE)));
        assertEquals(firstRecords.records(), secondRecords.records());
        assertEquals(1, firstRecords.records().size());
    }

    @Test
    void invalidAndCollidingIdentitiesDoNotMutateTheActiveTopology() throws Exception {
        Fixture fixture = fixture("identity-prevalidation");
        byte[] manifestBefore = Files.readAllBytes(fixture.root().resolve(
                SigningLedgerRecovery.MANIFEST_FILE));
        long activeLength = Files.size(fixture.root().resolve(
                SigningManifestCodec.activeName(1L)));
        try (SigningLedgerMaintenance maintenance = fixture.maintenance()) {
            assertThrows(IllegalArgumentException.class, () -> maintenance.rotate(0L));
            assertThrows(IllegalArgumentException.class, () -> maintenance.rotate(1L));
            assertThrows(IllegalArgumentException.class, () -> maintenance.compact(2L, 2L));
            assertThrows(IllegalArgumentException.class, () -> maintenance.compact(1L, 2L));
            assertThrows(IllegalArgumentException.class, () -> maintenance.compact(2L, 1L));
            assertEquals(1L, maintenance.manifest().activeWal().identity());
        }
        assertTrue(java.util.Arrays.equals(manifestBefore, Files.readAllBytes(
                fixture.root().resolve(SigningLedgerRecovery.MANIFEST_FILE))));
        assertEquals(activeLength, Files.size(fixture.root().resolve(
                SigningManifestCodec.activeName(1L))));
    }

    @Test
    void activeSegmentMaximumIsEnforcedAtTheExactClosedLength() throws Exception {
        Fixture allowed = fixture("segment-boundary-allowed");
        long length = Files.size(allowed.root().resolve(SigningManifestCodec.activeName(1L)));
        try (SigningLedgerMaintenance maintenance = allowed.maintenance(
                new SigningLedgerMaintenance.Configuration(length), stage -> { })) {
            maintenance.rotate(2L);
        }

        Fixture rejected = fixture("segment-boundary-rejected");
        byte[] manifestBefore = Files.readAllBytes(rejected.root().resolve(
                SigningLedgerRecovery.MANIFEST_FILE));
        SigningLedgerMaintenance maintenance = rejected.maintenance(
                new SigningLedgerMaintenance.Configuration(length - 1L), stage -> { });
        assertThrows(SigningLedgerMaintenance.MaintenanceException.class,
                () -> maintenance.rotate(2L));
        assertTrue(maintenance.recoveryRequired());
        maintenance.close();
        assertTrue(java.util.Arrays.equals(manifestBefore, Files.readAllBytes(
                rejected.root().resolve(SigningLedgerRecovery.MANIFEST_FILE))));
    }

    @Test
    void compactionRelocationPreservesPostBoundaryUpdateAndDelete() throws Exception {
        Fixture fixture = fixture("post-boundary-mutations");
        MetadataKey deletedKey = new MetadataKey("example", "b");
        SigningActiveWal.CommitResult initialSecond = await(fixture.active().submit(
                SigningWalFrameCodec.RecordType.MUTATION, new UUID(2L, 1L),
                new byte[] { 8 }));
        fixture.index().apply(initialSecond.revision(), List.of(
                SigningMvccIndex.Mutation.upsert(deletedKey, pointer(1L, initialSecond))));

        SigningLedgerMaintenance[] holder = new SigningLedgerMaintenance[1];
        holder[0] = fixture.maintenance(stage -> {
            if (stage == SigningLedgerMaintenance.Stage.CHECKPOINT_PUBLISHED) {
                SigningActiveWal.CommitResult updated = await(holder[0].activeWal().submit(
                        SigningWalFrameCodec.RecordType.MUTATION, new UUID(3L, 1L),
                        new byte[] { 9 }));
                fixture.index().apply(updated.revision(), List.of(
                        SigningMvccIndex.Mutation.upsert(fixture.key(), pointer(3L, updated))));
                SigningActiveWal.CommitResult deleted = await(holder[0].activeWal().submit(
                        SigningWalFrameCodec.RecordType.MUTATION, new UUID(3L, 2L),
                        new byte[] { 10 }));
                fixture.index().apply(deleted.revision(), List.of(
                        SigningMvccIndex.Mutation.delete(deletedKey, deleted.sequence())));
            }
        });
        try (SigningLedgerMaintenance maintenance = holder[0]) {
            maintenance.compact(2L, 3L);
            assertEquals(3L, fixture.index().lookup(fixture.key()).orElseThrow()
                    .pointer().generationId());
            assertTrue(fixture.index().lookup(deletedKey).isEmpty());
        }
    }

    @Test
    void checkpointSourcesOpenOncePerLiveGenerationAcrossCompaction() throws Exception {
        Fixture fixture = fixture("source-generations");
        try (SigningLedgerMaintenance maintenance = fixture.maintenance(
                new SigningLedgerMaintenance.Configuration(256L * 1024L * 1024L, 2),
                stage -> { })) {
            maintenance.rotate(2L);
            SigningActiveWal.CommitResult second = await(maintenance.activeWal().submit(
                    SigningWalFrameCodec.RecordType.MUTATION, new UUID(2L, 2L),
                    new byte[] { 8 }));
            fixture.index().apply(second.revision(), List.of(SigningMvccIndex.Mutation.upsert(
                    new MetadataKey("example", "b"), pointer(2L, second))));
            maintenance.compact(3L, 4L);
            assertEquals(2L, maintenance.sourceChannelsOpened());
        }
    }

    @Test
    void committedDeleteIsAbsentButNoDeleteLeavesTheLiveRecord() throws Exception {
        Fixture deleted = fixture("retention-delete");
        long deletedRevision;
        try (SigningLedgerMaintenance maintenance = deleted.maintenance()) {
            SigningActiveWal.CommitResult tombstone = await(deleted.active().submit(
                    SigningWalFrameCodec.RecordType.MUTATION, new UUID(1L, 9L),
                    new byte[] { 0 }));
            deletedRevision = tombstone.revision();
            deleted.index().apply(tombstone.revision(), List.of(
                    SigningMvccIndex.Mutation.delete(deleted.key(), tombstone.sequence())));
            SigningLedgerMaintenance.Compaction compacted = maintenance.compact(2L, 3L);
            assertEquals(0, compacted.liveRecords());
        }
        try (SigningLedgerRecovery.Handle recovered = SigningLedgerRecovery.recover(
                deleted.root(), recoveryConfiguration(), emptySink())) {
            assertEquals(0, recovered.statistics().checkpointEntries());
        }
        try (SegmentedTransactionalMetadataStore restarted =
                SegmentedTransactionalMetadataStore.open(deleted.root(), STORE_ID)) {
            MetadataCommitResult next = restarted.directCommit(List.of(
                    new SigningTransactionPayloadCodec.Mutation(
                            SigningTransactionPayloadCodec.MutationKind.CREATE,
                            new MetadataKey("example", "after-empty-checkpoint"),
                            -1L, new byte[] { 11 })));
            assertEquals(deletedRevision + 1L, next.committedRevision().orElseThrow());
        }

        Fixture retained = fixture("retention-no-delete");
        SigningMvccIndex.Mutation unappliedDelete = SigningMvccIndex.Mutation.delete(
                retained.key(), 1L);
        assertEquals(retained.key(), unappliedDelete.key());
        try (SigningLedgerMaintenance maintenance = retained.maintenance()) {
            assertEquals(1, maintenance.compact(2L, 3L).liveRecords());
        }
    }

    private void assertCompactionCrashBoundary(SigningLedgerMaintenance.Stage faultStage)
            throws Exception {
        Fixture fixture = fixture("compaction-crash-" + faultStage);
        SigningLedgerMaintenance failed = fixture.maintenance(stage -> {
            if (stage == faultStage) {
                throw new IOException("injected");
            }
        });
        SigningLedgerMaintenance.MaintenanceException failure = assertThrows(
                SigningLedgerMaintenance.MaintenanceException.class,
                () -> failed.compact(2L, 3L));
        assertEquals(SigningLedgerMaintenance.MaintenanceStage.CHECKPOINT, failure.stage());
        assertTrue(failed.recoveryRequired());
        failed.close();

        boolean checkpointAuthoritative = faultStage
                != SigningLedgerMaintenance.Stage.CHECKPOINT_PUBLISHED;
        try (SigningLedgerRecovery.Handle recovered = SigningLedgerRecovery.recover(
                fixture.root(), recoveryConfiguration(), emptySink())) {
            assertCompactionTopology(recovered.manifest(), checkpointAuthoritative);
            assertManifestArtifactsExist(fixture.root(), recovered.manifest());
            assertTrue(recovered.cleanupPlan().unreferencedArtifactCount() >= 1L);
            for (SigningLedgerRecovery.CleanupEntry entry : recovered.cleanupPlan().entries()) {
                assertFalse(isManifestReferenced(recovered.manifest(), entry.name()));
            }
            assertTrue(SigningLedgerMaintenance.cleanupDeferredArtifacts(fixture.root(),
                    recovered.manifest(), recovered.cleanupPlan()) >= 1);
            assertManifestArtifactsExist(fixture.root(), recovered.manifest());
        }

        try (SigningLedgerRecovery.Handle restarted = SigningLedgerRecovery.recover(
                fixture.root(), recoveryConfiguration(), emptySink())) {
            assertCompactionTopology(restarted.manifest(), checkpointAuthoritative);
            assertEquals(0L, restarted.cleanupPlan().unreferencedArtifactCount());
            assertManifestArtifactsExist(fixture.root(), restarted.manifest());
            if (!checkpointAuthoritative) {
                try (SigningLedgerMaintenance retry = new SigningLedgerMaintenance(fixture.root(),
                        restarted.manifest(), restarted.activeWal(), fixture.configuration(),
                        fixture.generations(), fixture.index(), fixture.artifacts())) {
                    SigningActiveWal.CommitResult next = await(retry.activeWal().submit(
                            SigningWalFrameCodec.RecordType.MUTATION, new UUID(3L, 3L),
                            new byte[] { 9 }));
                    fixture.index().apply(next.revision(), List.of(SigningMvccIndex.Mutation.upsert(
                            fixture.key(), pointer(3L, next))));
                    SigningLedgerMaintenance.Compaction compacted = retry.compact(4L, 5L);
                    assertEquals(4L, compacted.checkpoint().generationIdentity());
                    assertManifestArtifactsExist(fixture.root(), retry.manifest());
                }
            }
        }
    }

    private void assertReclamationCrashBoundary(SigningLedgerMaintenance.Stage faultStage)
            throws Exception {
        Fixture fixture = fixture("reclamation-crash-" + faultStage);
        boolean[] armed = { true };
        int[] directoryForces = { 0 };
        try (SigningLedgerMaintenance maintenance = fixture.maintenance(stage -> {
            if (stage == SigningLedgerMaintenance.Stage.DELETE_DIRECTORY_FORCED) {
                directoryForces[0]++;
            }
            if (stage == faultStage && armed[0]) {
                armed[0] = false;
                throw new IOException("injected");
            }
        })) {
            {
                SigningGenerationRegistry.CurrentReferences current =
                    fixture.generations().acquireCurrent(
                    SigningGenerationRegistry.Owner.RECOVERY_TEMPORARY, List.of(1L));
                try (current) {
                    {
                        SigningGenerationRegistry.SnapshotPins pins =
                            fixture.generations().pinSnapshot(List.of(1L));
                        try (pins) {
                            maintenance.compact(2L, 3L);
                            assertEquals(0, maintenance.reclaim(8));
                            assertOldGenerationPresent(fixture.root());
                            assertManifestArtifactsExist(fixture.root(), maintenance.manifest());
                        }
                    }
                    assertEquals(0, maintenance.reclaim(8));
                    assertOldGenerationPresent(fixture.root());
                    assertManifestArtifactsExist(fixture.root(), maintenance.manifest());
                }
            }
            SigningLedgerMaintenance.MaintenanceException failure = assertThrows(
                    SigningLedgerMaintenance.MaintenanceException.class, () -> maintenance.reclaim(8));
            assertEquals(SigningLedgerMaintenance.MaintenanceStage.RECLAIM, failure.stage());
            assertEquals(1, fixture.generations().statistics().reclaimable());
            assertManifestArtifactsExist(fixture.root(), maintenance.manifest());
            if (faultStage == SigningLedgerMaintenance.Stage.BEFORE_DELETE) {
                assertOldGenerationPresent(fixture.root());
            }
            assertEquals(1, maintenance.reclaim(8));
            int expectedForces = faultStage == SigningLedgerMaintenance.Stage.DELETE_DIRECTORY_FORCED ? 2 : 1;
            assertEquals(expectedForces, directoryForces[0]);
            assertEquals(0, maintenance.reclaim(8));
            assertEquals(expectedForces, directoryForces[0]);
            assertFalse(Files.exists(fixture.root().resolve(SigningManifestCodec.activeName(1L))));
            assertFalse(Files.exists(fixture.root().resolve(SigningManifestCodec.segmentName(0L, 0L))));
            assertManifestArtifactsExist(fixture.root(), maintenance.manifest());
        }

        try (SigningLedgerRecovery.Handle restarted = SigningLedgerRecovery.recover(
                fixture.root(), recoveryConfiguration(), emptySink())) {
            assertCompactionTopology(restarted.manifest(), true);
            assertManifestArtifactsExist(fixture.root(), restarted.manifest());
        }
    }

    private static void assertCompactionTopology(SigningManifestCodec.Manifest manifest,
            boolean checkpointAuthoritative) {
        assertEquals(3L, manifest.activeWal().identity());
        assertEquals(1L, manifest.activeWal().firstSequence());
        if (checkpointAuthoritative) {
            assertEquals(2L, manifest.checkpoint().orElseThrow().generationIdentity());
            assertTrue(manifest.sealedSegments().isEmpty());
        } else {
            assertTrue(manifest.checkpoint().isEmpty());
            assertEquals(1, manifest.sealedSegments().size());
            assertEquals(1L, manifest.sealedSegments().getFirst().generationIdentity());
        }
    }

    private static void assertManifestArtifactsExist(Path root,
            SigningManifestCodec.Manifest manifest) {
        manifest.checkpoint().ifPresent(checkpoint ->
                assertTrue(Files.exists(root.resolve(checkpoint.name()))));
        for (SigningManifestCodec.Segment segment : manifest.sealedSegments()) {
            assertTrue(Files.exists(root.resolve(segment.name())));
        }
        assertTrue(Files.exists(root.resolve(manifest.activeWal().name())));
    }

    private static boolean isManifestReferenced(SigningManifestCodec.Manifest manifest,
            String name) {
        return manifest.checkpoint().map(checkpoint -> checkpoint.name().equals(name)).orElse(false)
                || manifest.sealedSegments().stream().anyMatch(segment -> segment.name().equals(name))
                || manifest.activeWal().name().equals(name);
    }

    private static void assertOldGenerationPresent(Path root) {
        assertTrue(Files.exists(root.resolve(SigningManifestCodec.activeName(1L))));
        assertTrue(Files.exists(root.resolve(SigningManifestCodec.segmentName(0L, 0L))));
    }

    private static Stream<Arguments> maintenanceCrashBoundaries() {
        return Stream.of(
                Arguments.of(SigningLedgerMaintenance.Stage.CHECKPOINT_PUBLISHED),
                Arguments.of(SigningLedgerMaintenance.Stage.COMPACTION_MANIFEST_READY),
                Arguments.of(SigningLedgerMaintenance.Stage.COMPACTION_MEMORY_PUBLISHED),
                Arguments.of(SigningLedgerMaintenance.Stage.BEFORE_DELETE),
                Arguments.of(SigningLedgerMaintenance.Stage.AFTER_DELETE),
                Arguments.of(SigningLedgerMaintenance.Stage.DELETE_DIRECTORY_FORCED));
    }

    private static Stream<Arguments> onlineCompactionCrashBoundaries() {
        return Stream.of(
                Arguments.of(SigningLedgerMaintenance.Stage.CHECKPOINT_PUBLISHED),
                Arguments.of(SigningLedgerMaintenance.Stage.CANDIDATE_BUILT),
                Arguments.of(SigningLedgerMaintenance.Stage.COMPACTION_MANIFEST_READY),
                Arguments.of(SigningLedgerMaintenance.Stage.COMPACTION_ROOT_SWAPPED),
                Arguments.of(
                        SigningLedgerMaintenance.Stage.COMPACTION_GENS_SUPERSEDED));
    }

    private static Stream<Arguments> directReclamationRestartBoundaries() {
        return Stream.of(
                Arguments.of(SigningLedgerMaintenance.Stage.BEFORE_DELETE),
                Arguments.of(SigningLedgerMaintenance.Stage.AFTER_DELETE),
                Arguments.of(SigningLedgerMaintenance.Stage.DELETE_DIRECTORY_FORCED));
    }

    private static void assertReclamationBoundaryArtifacts(Path root,
            SigningLedgerMaintenance.Stage faultStage) {
        boolean activeSurvives = faultStage == SigningLedgerMaintenance.Stage.BEFORE_DELETE;
        boolean segmentSurvives = faultStage != SigningLedgerMaintenance.Stage.DELETE_DIRECTORY_FORCED;
        assertEquals(activeSurvives, Files.exists(root.resolve(SigningManifestCodec.activeName(1L))));
        assertEquals(segmentSurvives, Files.exists(root.resolve(
                SigningManifestCodec.segmentName(0L, 0L))));
    }

    private static Set<String> expectedReclamationCandidates(
            SigningLedgerMaintenance.Stage faultStage) {
        return switch (faultStage) {
            case BEFORE_DELETE -> Set.of(SigningManifestCodec.activeName(1L),
                    SigningManifestCodec.segmentName(0L, 0L));
            case AFTER_DELETE -> Set.of(SigningManifestCodec.segmentName(0L, 0L));
            case DELETE_DIRECTORY_FORCED -> Set.of();
            default -> throw new IllegalArgumentException("not a reclamation restart boundary");
        };
    }

    private static Stream<Arguments> rotationCrashBoundaries() {
        return Stream.of(
                Arguments.of(SigningLedgerMaintenance.Stage.ACTIVE_DRAINED, false),
                Arguments.of(SigningLedgerMaintenance.Stage.SEALED_LINK_CREATED, false),
                Arguments.of(SigningLedgerMaintenance.Stage.SEALED_PUBLISHED, false),
                Arguments.of(SigningLedgerMaintenance.Stage.NEXT_ACTIVE_PUBLISHED, false),
                Arguments.of(SigningLedgerMaintenance.Stage.MANIFEST_PUBLISHED, true),
                Arguments.of(SigningLedgerMaintenance.Stage.MEMORY_PUBLISHED, true));
    }

    private Fixture fixture(String name) throws Exception {
        SigningActiveWal.Configuration configuration = new SigningActiveWal.Configuration(
                8, 8, 0L, 8L * SigningWalFrameCodec.MAX_PAYLOAD_BYTES,
                SigningActiveWal.MAXIMUM_BATCH_BYTES);
        return fixture(name, configuration);
    }

    private Fixture fixture(String name, SigningActiveWal.Configuration configuration)
            throws Exception {
        return fixture(name, configuration,
                FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES);
    }

    private Fixture fixture(String name, SigningActiveWal.Configuration configuration,
            long transientCapacityBytes) throws Exception {
        Path root = Files.createDirectory(temporaryDirectory.resolve(name));
        SigningLedgerRecovery.initializeFormat(root);
        SigningActiveWal.Descriptor activeDescriptor = new SigningActiveWal.Descriptor(1L, 0L, 0L);
        SigningActiveWal active = SigningActiveWal.open(
                root.resolve(SigningManifestCodec.activeName(1L)), activeDescriptor, configuration);
        SigningActiveWal.CommitResult committed = active.submit(
                SigningWalFrameCodec.RecordType.MUTATION, new UUID(1L, 1L),
                new byte[] { 7 }).await();
        SigningManifestCodec.ActiveWal manifestActive = manifestActive(activeDescriptor);
        SigningManifestCodec.Manifest manifest = new SigningManifestCodec.Manifest(
                0L, 0L, Optional.empty(), List.of(), manifestActive);
        Files.write(root.resolve(SigningLedgerRecovery.MANIFEST_FILE),
                SigningManifestCodec.encode(manifest));

        SigningGenerationRegistry generations = new SigningGenerationRegistry();
        generations.create(1L);
        generations.publish(1L);
        SigningIndexCapacityBudget budget = new SigningIndexCapacityBudget(
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES);
        SigningIndexCapacityBudget transientBudget = new SigningIndexCapacityBudget(
                transientCapacityBytes);
        SigningMvccIndex index = new SigningMvccIndex(new SigningMvccIndex.Configuration(
                100, 8, 100L, 0L), generations, budget, transientBudget);
        MetadataKey key = new MetadataKey("example", "a");
        index.apply(committed.revision(), List.of(SigningMvccIndex.Mutation.upsert(key,
                new SigningMvccIndex.RecordPointer(1L, committed.offset(),
                        committed.frameLength(), committed.sequence(),
                        SigningWalFrameCodec.RecordType.MUTATION))));
        SigningArtifactCatalog artifacts = new SigningArtifactCatalog();
        artifacts.register(new SigningArtifactCatalog.Artifact(1L, manifestActive.name(),
                SigningArtifactCatalog.Kind.ACTIVE_WAL));
        return new Fixture(root, configuration, manifest, active, generations, index,
                budget, transientBudget, artifacts, key);
    }

    private static SigningManifestCodec.ActiveWal manifestActive(
            SigningActiveWal.Descriptor descriptor) {
        byte[] header = SigningWalContainerCodec.encode(new SigningWalContainerCodec.Header(
                descriptor.identity(), descriptor.firstSequence(), descriptor.baselineRevision()));
        return new SigningManifestCodec.ActiveWal(descriptor.identity(),
                descriptor.firstSequence(), descriptor.baselineRevision(), header.length,
                SigningFormatSupport.sha256().digest(header),
                SigningManifestCodec.activeName(descriptor.identity()));
    }

    private static SigningMvccIndex.RecordPointer pointer(long generation,
            SigningActiveWal.CommitResult result) {
        return new SigningMvccIndex.RecordPointer(generation, result.offset(),
                result.frameLength(), result.sequence(),
                SigningWalFrameCodec.RecordType.MUTATION);
    }

    private static SigningActiveWal.CommitResult await(
            SigningActiveWal.Acknowledgement submission)
            throws IOException {
        try {
            return submission.await();
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while awaiting signing WAL test commit", failure);
        } catch (ExecutionException failure) {
            throw new IOException("signing WAL test commit failed", failure.getCause());
        }
    }

    private static SigningLedgerRecovery.Configuration recoveryConfiguration() {
        return new SigningLedgerRecovery.Configuration(64, 64L * 1024L * 1024L, 100,
                SigningActiveWal.Configuration.defaults());
    }

    private static SigningLedgerRecovery.RecoverySink emptySink() {
        return manifest -> new SigningLedgerRecovery.RecoverySink.Session() {
            @Override public void acceptCheckpoint(SigningCheckpointCodec.Header header,
                    SigningCheckpointCodec.EntryDescriptor entry,
                    SigningWalFrameCodec.Frame frame) { }
            @Override public void acceptCheckpointBoundary(SigningCheckpointCodec.Header header) { }
            @Override public void acceptWalGroup(List<SigningWalFrameCodec.ScannedFrame> frames,
                    long revision) { }
            @Override public SigningLedgerRecovery.RecoverySink.Prepared prepare() {
                return new SigningLedgerRecovery.RecoverySink.Prepared() {
                    @Override public void publish() { }
                    @Override public void close() { }
                };
            }
            @Override public void close() { }
        };
    }

    private static final class RecoveredRecords implements SigningLedgerRecovery.RecoverySink {
        private final List<String> records = new ArrayList<>();

        @Override
        public Session begin(SigningManifestCodec.Manifest manifest) {
            return new Session() {
                @Override
                public void acceptCheckpoint(SigningCheckpointCodec.Header header,
                        SigningCheckpointCodec.EntryDescriptor entry,
                        SigningWalFrameCodec.Frame frame) {
                    records.add(evidence(entry.key(), frame));
                }

                @Override
                public void acceptCheckpointBoundary(SigningCheckpointCodec.Header header) {
                    // This sink collects record evidence only.
                }

                @Override
                public void acceptWalGroup(List<SigningWalFrameCodec.ScannedFrame> frames,
                        long committedRevision) {
                    frames.forEach(frame -> records.add(evidence("wal", frame.frame())));
                }

                @Override
                public Prepared prepare() {
                    return new Prepared() {
                        @Override public void publish() { }
                        @Override public void close() { }
                    };
                }

                @Override public void close() { }
            };
        }

        private static String evidence(String key, SigningWalFrameCodec.Frame frame) {
            return key + '|' + frame.recordType() + '|' + frame.transactionId() + '|'
                    + frame.sequence() + '|' + HexFormat.of().formatHex(frame.payload());
        }

        private List<String> records() {
            return List.copyOf(records);
        }
    }

    private record Fixture(Path root, SigningActiveWal.Configuration configuration,
            SigningManifestCodec.Manifest manifest, SigningActiveWal active,
            SigningGenerationRegistry generations, SigningMvccIndex index,
            SigningIndexCapacityBudget budget, SigningIndexCapacityBudget transientBudget,
            SigningArtifactCatalog artifacts, MetadataKey key) {
        private SigningLedgerMaintenance maintenance() {
            return maintenance(stage -> { });
        }

        private SigningLedgerMaintenance maintenance(SigningLedgerMaintenance.FaultInjector faults) {
            return new SigningLedgerMaintenance(root, manifest, active, configuration,
                    generations, index, artifacts, faults);
        }

        private SigningLedgerMaintenance maintenance(
                SigningLedgerMaintenance.Configuration maintenanceConfiguration,
                SigningLedgerMaintenance.FaultInjector faults) {
            return new SigningLedgerMaintenance(root, manifest, active, configuration,
                    generations, index, artifacts, maintenanceConfiguration, faults);
        }
    }
}
