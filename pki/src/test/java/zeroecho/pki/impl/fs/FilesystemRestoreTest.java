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
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.backup.BackupRequest;
import zeroecho.pki.api.backup.BackupSource;
import zeroecho.pki.api.backup.RestoreStatus;
import zeroecho.pki.api.policy.PolicyTrace;
import zeroecho.pki.api.orch.WorkflowStateRecord;
import zeroecho.pki.api.orch.OrchestrationDurabilityPolicy;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.EncodedObject;
import java.util.Optional;

class FilesystemRestoreTest {
    @TempDir Path directory;
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-04T12:00:00Z"), ZoneOffset.UTC);
    private FilesystemPkiStore open() { return new FilesystemPkiStore(directory.resolve("store"), FsPkiStoreOptions.defaults(), CLOCK); }
    private static BackupRequest request() {
        return new BackupRequest("restore-test", FilesystemPkiStoreTest.TestObjects.emptyAttributes());
    }
    @AfterEach void clearObserver() { FsRestoreCoordinator.observeWith(null); }

    @ParameterizedTest
    @EnumSource(value = FsRestoreCoordinator.Phase.class,
            names = {"AFTER_STAGE_MOVE", "AFTER_CANDIDATE_MARKER", "AFTER_ORIGINAL_MARKER"})
    void unpublishedStageIsDiscardedExactlyAfterColdRecovery(FsRestoreCoordinator.Phase crash) throws Exception {
        PkiId expected = new PkiId("ad52d431-4394-41e1-90d2-7e6ed0f59c44");
        String manifest;
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) {
            try (zeroecho.pki.api.backup.BackupPreparation prepared = store.prepareBackup(source)) {
                manifest = prepared.manifestSha256();
            }
            FsRestoreCoordinator.observeWith(phase -> { if (phase == crash) throw new Crash(); });
            assertThrows(Crash.class, () -> store.stageRestore(source, expected));
        }
        FsRestoreCoordinator.observeWith(null);
        Path stage = directory.resolve(".store.restore-stage-" + expected.value());
        assertTrue(Files.isDirectory(stage));
        // A process crash can leave preparation workspace even before dispatch.
        Path work = directory.resolve(".store.restore-control/work");
        Files.createDirectories(work.resolve(".verification-abandoned"));
        Files.writeString(work.resolve(".verification-abandoned/input.zip"), "partial");
        try (FilesystemPkiStore store = open()) {
            assertTrue(store.latestRestoreIdentity().isEmpty());
            assertFalse(Files.exists(work.resolve(".verification-abandoned")));
            store.discardUnpublishedRestore(expected, Optional.empty(), manifest);
            store.discardUnpublishedRestore(expected, Optional.empty(), manifest);
            assertFalse(Files.exists(stage));
            assertFalse(Files.exists(directory.resolve("store/.restore-role-" + expected.value())));
            try (BackupSource next = store.createBackupSource(request())) {
                assertEquals(RestoreStatus.State.STAGED, store.stageRestore(next).state());
            }
        }
    }

    @Test void unpublishedCleanupRejectsMismatchedMarkerAndPublishedIdentity() throws Exception {
        PkiId expected = new PkiId("ad52d431-4394-41e1-90d2-7e6ed0f59c44");
        String manifest = "a".repeat(64);
        try (FilesystemPkiStore store = open()) {
            Path marker = directory.resolve("store/.restore-role-" + expected.value());
            Files.writeString(marker, "wrong marker");
            assertThrows(IOException.class, () -> store.discardUnpublishedRestore(expected, Optional.empty(), manifest));
            assertEquals("wrong marker", Files.readString(marker));
            Files.delete(marker);
            try (BackupSource source = store.createBackupSource(request())) { store.stageRestore(source, expected); }
        }
        try (FilesystemPkiStore store = open()) {
            assertThrows(IOException.class, () -> store.discardUnpublishedRestore(expected, Optional.empty(), manifest));
            assertEquals(expected, store.latestRestoreStatus().orElseThrow().restoreId());
            assertTrue(Files.exists(directory.resolve(".store.restore-old-" + expected.value())));
        }
    }

    @Test void callerRestoreIdentityIsPreservedAndCannotBeReused() throws Exception {
        PkiId chosen = new PkiId("ad52d431-4394-41e1-90d2-7e6ed0f59c44");
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) {
            assertThrows(IllegalArgumentException.class, () -> store.stageRestore(source, new PkiId("../escape")));
            assertTrue(store.latestRestoreIdentity().isEmpty());
            assertEquals(chosen, store.stageRestore(source, chosen).restoreId());
        }
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) {
            assertEquals(chosen, store.latestRestoreIdentity().orElseThrow().status().restoreId());
            assertEquals("RESTORE_IDENTIFIER_ALREADY_USED",
                    assertThrows(IOException.class, () -> store.stageRestore(source, chosen)).getMessage());
            assertEquals(RestoreStatus.State.ACTIVATED, store.latestRestoreStatus().orElseThrow().state());
            PkiId next = new PkiId("349a6ee1-51a6-4a4c-94e5-3948a51cfc2a");
            assertEquals(next, store.stageRestore(source, next).restoreId());
        }
    }

    @Test void stagedStatusBecomesActivatedOnlyAfterColdRecoveryAndRetainsRollback() throws Exception {
        PkiId restore;
        PkiId backup;
        String manifest;
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) {
            assertTrue(store.latestRestoreStatus().isEmpty());
            assertTrue(store.latestRestoreIdentity().isEmpty());
            backup = source.backupId();
            RestoreStatus status = store.stageRestore(source);
            zeroecho.pki.api.backup.RestoreIdentity identity = store.latestRestoreIdentity().orElseThrow();
            assertEquals(backup, identity.sourceBackupId());
            assertEquals(status, identity.status());
            manifest = identity.manifestSha256();
            assertTrue(manifest.matches("[0-9a-f]{64}"));
            assertEquals(RestoreStatus.State.STAGED, status.state());
            restore = status.restoreId();
            assertEquals(status, store.latestRestoreStatus().orElseThrow());
            assertThrows(IOException.class, () -> store.stageRestore(source));
        }
        for (int attempt = 0; attempt < 3; attempt++) {
            try (FilesystemPkiStore store = open()) {
                assertEquals(RestoreStatus.State.ACTIVATED, store.latestRestoreStatus().orElseThrow().state());
                assertEquals(restore, store.latestRestoreStatus().orElseThrow().restoreId());
                assertEquals(backup, store.latestRestoreIdentity().orElseThrow().sourceBackupId());
                assertEquals(manifest, store.latestRestoreIdentity().orElseThrow().manifestSha256());
                assertEquals(store.latestRestoreStatus().orElseThrow(),
                        store.latestRestoreIdentity().orElseThrow().status());
            }
        }
        assertTrue(Files.isDirectory(directory.resolve(".store.restore-old-" + restore)));
    }

    @ParameterizedTest
    @EnumSource(value = FsRestoreCoordinator.Phase.class, names = {"BEFORE_LIVE_MOVE", "AFTER_LIVE_MOVE", "BEFORE_PROMOTION",
            "AFTER_PROMOTION", "RECOVERY_STARTED", "BEFORE_RECOVERY", "AFTER_RECOVERY", "DIRECTORY_FORCE", "JOURNAL"})
    void crashAtActivationBoundaryReconcilesIdempotently(FsRestoreCoordinator.Phase crash) throws Exception {
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) {
            store.stageRestore(source);
        }
        FsRestoreCoordinator.observeWith(phase -> { if (phase == crash) throw new Crash(); });
        assertThrows(Crash.class, this::open);
        FsRestoreCoordinator.observeWith(null);
        try (FilesystemPkiStore store = open()) {
            assertEquals(RestoreStatus.State.ACTIVATED, store.latestRestoreStatus().orElseThrow().state());
        }
        try (FilesystemPkiStore store = open()) {
            assertEquals(RestoreStatus.State.ACTIVATED, store.latestRestoreStatus().orElseThrow().state());
        }
    }

    @Test void laterLiveMetadataChangeRejectsColdActivation() throws Exception {
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) {
            store.stageRestore(source);
            store.putPolicyTrace(new PolicyTrace(new PkiId("post-stage"), List.of()));
            // Policy is outside safety authority; use metadata-backed CA state as the regression trigger.
            store.putCa(FilesystemPkiStoreTest.TestObjects.minimalCaRecord(store, "late-ca", zeroecho.pki.api.ca.CaState.ACTIVE));
        }
        try (FilesystemPkiStore store = open()) {
            assertEquals(RestoreStatus.State.FAILED, store.latestRestoreStatus().orElseThrow().state());
            assertTrue(store.getPolicyTrace(new PkiId("post-stage")).isPresent());
        }
    }

    @Test void backupBeforeImportedRequestCannotEraseRetainedEnrollmentInput() throws Exception {
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) {
            store.putRequest(enrollmentRequest("after-backup"));
            assertEquals("RESTORE_SAFETY_AUTHORITY_MISMATCH",
                    assertThrows(IOException.class, () -> store.stageRestore(source)).getMessage());
            assertTrue(store.getRequest(new PkiId("after-backup")).isPresent());
        }
    }

    @Test void requestImportedAfterStagingPreventsColdActivation() throws Exception {
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) {
            store.stageRestore(source);
            store.putRequest(enrollmentRequest("after-stage"));
        }
        try (FilesystemPkiStore store = open()) {
            assertEquals(RestoreStatus.State.FAILED, store.latestRestoreStatus().orElseThrow().state());
            assertTrue(store.getRequest(new PkiId("after-stage")).isPresent());
        }
    }

    @Test void exactRequestProjectionSurvivesRestoreAndRejectsUnexpectedEntries() throws Exception {
        try (FilesystemPkiStore store = open()) {
            store.putRequest(enrollmentRequest("retained"));
            try (BackupSource source = store.createBackupSource(request())) { store.stageRestore(source); }
        }
        try (FilesystemPkiStore store = open()) {
            assertEquals(RestoreStatus.State.ACTIVATED, store.latestRestoreStatus().orElseThrow().state());
            org.junit.jupiter.api.Assertions.assertArrayEquals(FsCodec.encode(FsCodec.PARSED_REQUEST, enrollmentRequest("retained")),
                    FsCodec.encode(FsCodec.PARSED_REQUEST, store.getRequest(new PkiId("retained")).orElseThrow()));
        }
        Path unexpected = directory.resolve("store/requests/by-id/unexpected.txt");
        Files.writeString(unexpected, "invalid");
        assertThrows(IOException.class, () -> FsRestoreSafety.project(directory.resolve("store"),
                zeroecho.pki.api.backup.BackupLimits.defaults()));
    }

    private static zeroecho.pki.api.request.ParsedCertificationRequest enrollmentRequest(String id) {
        return new zeroecho.pki.api.request.ParsedCertificationRequest(new PkiId(id), new zeroecho.pki.api.FormatId("fmt-x509"),
                new zeroecho.pki.api.SubjectRef("CN=retained-input"), new EncodedObject(Encoding.DER, new byte[] { 1, 2, 3 }),
                Optional.empty(), Optional.empty(), FilesystemPkiStoreTest.TestObjects.emptyAttributes());
    }

    @Test void recoveryFailureRollsBackAndNeverClaimsActivation() throws Exception {
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) { store.stageRestore(source); }
        FsRestoreCoordinator.observeWith(phase -> { if (phase == FsRestoreCoordinator.Phase.BEFORE_RECOVERY) throw new IOException("fixture"); });
        try (FilesystemPkiStore store = open()) {
            assertEquals(RestoreStatus.State.FAILED, store.latestRestoreStatus().orElseThrow().state());
        }
        FsRestoreCoordinator.observeWith(null);
        try (FilesystemPkiStore store = open()) {
            assertEquals(RestoreStatus.State.FAILED, store.latestRestoreStatus().orElseThrow().state());
        }
    }

    @Test void corruptJournalCannotCreateFreshStoreOrAlterLive() throws Exception {
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) { store.stageRestore(source); }
        Path journal = directory.resolve(".store.restore-control/journal");
        byte[] bytes = Files.readAllBytes(journal);
        bytes[5] ^= 1;
        Files.write(journal, bytes);
        assertThrows(IllegalStateException.class, this::open);
        assertEquals("v18", Files.readString(directory.resolve("store/VERSION")));
        assertFalse(Files.exists(directory.resolve("store-2")));
    }

    @Test void populatedWorkflowAndMetadataArePreserved() throws Exception {
        WorkflowStateRecord workflow = new WorkflowStateRecord(new PkiId("workflow"), "ISSUANCE",
                new Principal("TEST", "owner"), OrchestrationDurabilityPolicy.DURABLE_MIN_STATE,
                CLOCK.instant(), CLOCK.instant(), CLOCK.instant().plusSeconds(60), Encoding.BINARY,
                Optional.of(new EncodedObject(Encoding.BINARY, new byte[] {9})));
        try (FilesystemPkiStore store = open()) {
            store.putWorkflowState(workflow);
            store.putCa(FilesystemPkiStoreTest.TestObjects.minimalCaRecord(store, "preserved-ca", zeroecho.pki.api.ca.CaState.ACTIVE));
            try (BackupSource source = store.createBackupSource(request())) { store.stageRestore(source); }
        }
        try (FilesystemPkiStore store = open()) {
            assertEquals(RestoreStatus.State.ACTIVATED, store.latestRestoreStatus().orElseThrow().state());
            WorkflowStateRecord restored = store.getWorkflowState(workflow.opId()).orElseThrow();
            assertEquals(workflow.opId(), restored.opId());
            assertEquals(workflow.owner(), restored.owner());
            assertEquals(workflow.expiresAt(), restored.expiresAt());
            org.junit.jupiter.api.Assertions.assertArrayEquals(workflow.payload().orElseThrow().bytes(), restored.payload().orElseThrow().bytes());
            assertTrue(store.getCa(new PkiId("preserved-ca")).isPresent());
        }
    }

    @Test void uncertainStagePublicationFencesRestagingAndReportsNoFailureOrActivation() throws Exception {
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) {
            FsRestoreCoordinator.observeWith(phase -> {
                if (phase == FsRestoreCoordinator.Phase.AFTER_JOURNAL_RENAME) throw new IOException("fixture");
            });
            IOException failure = assertThrows(IOException.class, () -> store.stageRestore(source));
            assertEquals("RESTORE_OUTCOME_UNCERTAIN", failure.getMessage());
            assertEquals(RestoreStatus.State.UNCERTAIN, store.latestRestoreStatus().orElseThrow().state());
            assertEquals(source.backupId(), store.latestRestoreIdentity().orElseThrow().sourceBackupId());
            assertEquals(RestoreStatus.State.UNCERTAIN,
                    store.latestRestoreIdentity().orElseThrow().status().state());
            assertEquals(List.of("RESTORE_OUTCOME_UNCERTAIN"), store.latestRestoreStatus().orElseThrow().issues());
            FsRestoreCoordinator.observeWith(null);
            assertThrows(IOException.class, () -> store.stageRestore(source));
        }
        try (FilesystemPkiStore store = open()) {
            assertEquals(RestoreStatus.State.ACTIVATED, store.latestRestoreStatus().orElseThrow().state());
        }
    }

    @Test void missingCandidateAfterFirstMoveRestoresOldRoot() throws Exception {
        PkiId id;
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) {
            id = store.stageRestore(source).restoreId();
        }
        FsRestoreCoordinator.observeWith(phase -> { if (phase == FsRestoreCoordinator.Phase.AFTER_LIVE_MOVE) throw new Crash(); });
        assertThrows(Crash.class, this::open);
        FsRestoreCoordinator.observeWith(null);
        Path stage = directory.resolve(".store.restore-stage-" + id);
        Files.move(stage, directory.resolve("preserved-missing-stage"));
        try (FilesystemPkiStore store = open()) {
            assertEquals(RestoreStatus.State.FAILED, store.latestRestoreStatus().orElseThrow().state());
        }
        assertTrue(Files.exists(directory.resolve("preserved-missing-stage/VERSION")));
    }

    @Test void unknownColocatedAuthorityRejectsStagingWithoutMovingLive() throws Exception {
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) {
            Files.createDirectories(directory.resolve("store/keyring"));
            Files.writeString(directory.resolve("store/keyring/private"), "legitimate external state");
            IOException failure = assertThrows(IOException.class, () -> store.stageRestore(source));
            assertEquals("RESTORE_EXTERNAL_AUTHORITY", failure.getMessage());
            assertTrue(store.latestRestoreStatus().isEmpty());
            assertEquals("legitimate external state", Files.readString(directory.resolve("store/keyring/private")));
        }
    }

    @Test void secondRestoreCanCrashAndReconcileWithoutLosingFirstIdentity() throws Exception {
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) { store.stageRestore(source); }
        PkiId second;
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) {
            second = store.stageRestore(source).restoreId();
        }
        FsRestoreCoordinator.observeWith(phase -> { if (phase == FsRestoreCoordinator.Phase.AFTER_PROMOTION) throw new Crash(); });
        assertThrows(Crash.class, this::open);
        FsRestoreCoordinator.observeWith(null);
        try (FilesystemPkiStore store = open()) {
            assertEquals(second, store.latestRestoreStatus().orElseThrow().restoreId());
            assertEquals(RestoreStatus.State.ACTIVATED, store.latestRestoreStatus().orElseThrow().state());
        }
    }

    @Test void existingLegacyRootLockExcludesNewCoordinatorOpen() throws Exception {
        try (FilesystemPkiStore store = open()) { assertTrue(store.latestRestoreStatus().isEmpty()); }
        try (FilesystemPkiStore.StoreOwnership legacy = FilesystemPkiStore.StoreOwnership.acquire(directory.resolve("store/.lock/store.lock"))) {
            assertThrows(IllegalStateException.class, this::open);
        }
        try (FilesystemPkiStore store = open()) { assertTrue(store.latestRestoreStatus().isEmpty()); }
    }

    @Test void everyActivationDurabilityEventCanBeInterruptedAndRetried() throws Exception {
        Path original = directory;
        directory = original.resolve("reference");
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) { store.stageRestore(source); }
        java.util.concurrent.atomic.AtomicInteger events = new java.util.concurrent.atomic.AtomicInteger();
        FsRestoreCoordinator.observeWith(phase -> events.incrementAndGet());
        try (FilesystemPkiStore store = open()) { assertEquals(RestoreStatus.State.ACTIVATED, store.latestRestoreStatus().orElseThrow().state()); }
        FsRestoreCoordinator.observeWith(null);
        for (int target = 1; target <= events.get(); target++) {
            directory = original.resolve("event-" + target);
            try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) { store.stageRestore(source); }
            int crashAt = target;
            java.util.concurrent.atomic.AtomicInteger observed = new java.util.concurrent.atomic.AtomicInteger();
            FsRestoreCoordinator.observeWith(phase -> { if (observed.incrementAndGet() == crashAt) throw new Crash(); });
            assertThrows(Crash.class, this::open, "event " + target);
            FsRestoreCoordinator.observeWith(null);
            for (int repeat = 0; repeat < 2; repeat++) {
                try (FilesystemPkiStore store = open()) {
                    assertEquals(RestoreStatus.State.ACTIVATED, store.latestRestoreStatus().orElseThrow().state(), "event " + target);
                }
            }
        }
    }

    @ParameterizedTest
    @EnumSource(value = FsRestoreCoordinator.Phase.class, names = {"BEFORE_ROLLBACK", "AFTER_ROLLBACK"})
    void rollbackIntentSurvivesInterruption(FsRestoreCoordinator.Phase crash) throws Exception {
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) { store.stageRestore(source); }
        FsRestoreCoordinator.observeWith(phase -> {
            if (phase == crash) throw new Crash();
            if (phase == FsRestoreCoordinator.Phase.BEFORE_RECOVERY) throw new IOException("fixture");
        });
        assertThrows(Crash.class, this::open);
        FsRestoreCoordinator.observeWith(null);
        for (int repeat = 0; repeat < 2; repeat++) {
            try (FilesystemPkiStore store = open()) { assertEquals(RestoreStatus.State.FAILED, store.latestRestoreStatus().orElseThrow().state()); }
        }
    }

    @Test void atomicPromotionUnavailableRollsBackWithoutCopyFallback() throws Exception {
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) { store.stageRestore(source); }
        FsRestoreCoordinator.observeWith(phase -> {
            if (phase == FsRestoreCoordinator.Phase.BEFORE_PROMOTION) {
                throw new java.nio.file.AtomicMoveNotSupportedException("fixture", "fixture", "fixture");
            }
        });
        try (FilesystemPkiStore store = open()) { assertEquals(RestoreStatus.State.FAILED, store.latestRestoreStatus().orElseThrow().state()); }
    }

    @Test void unexpectedLiveRootAfterFirstMoveIsPreservedAndFailsClosed() throws Exception {
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) { store.stageRestore(source); }
        FsRestoreCoordinator.observeWith(phase -> { if (phase == FsRestoreCoordinator.Phase.AFTER_LIVE_MOVE) throw new Crash(); });
        assertThrows(Crash.class, this::open);
        FsRestoreCoordinator.observeWith(null);
        Files.createDirectory(directory.resolve("store"));
        Files.writeString(directory.resolve("store/sentinel"), "unexpected owner");
        assertThrows(IllegalStateException.class, this::open);
        assertEquals("unexpected owner", Files.readString(directory.resolve("store/sentinel")));
        try (java.util.stream.Stream<Path> roots = Files.list(directory)) {
            assertEquals(1, roots.filter(path -> path.getFileName().toString().startsWith(".store.restore-old-")).count());
        }
    }

    @Test void earlyRollbackInterruptedAfterOriginalMoveDoesNotRequireQuarantinedCandidate() throws Exception {
        PkiId id;
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) {
            id = store.stageRestore(source).restoreId();
        }
        FsRestoreCoordinator.observeWith(phase -> { if (phase == FsRestoreCoordinator.Phase.AFTER_LIVE_MOVE) throw new Crash(); });
        assertThrows(Crash.class, this::open);
        FsRestoreCoordinator.observeWith(null);
        Files.move(directory.resolve(".store.restore-stage-" + id), directory.resolve("preserved-stage"));
        FsRestoreCoordinator.observeWith(phase -> { if (phase == FsRestoreCoordinator.Phase.AFTER_ROLLBACK) throw new Crash(); });
        assertThrows(Crash.class, this::open);
        FsRestoreCoordinator.observeWith(null);
        for (int repeat = 0; repeat < 2; repeat++) {
            try (FilesystemPkiStore store = open()) { assertEquals(RestoreStatus.State.FAILED, store.latestRestoreStatus().orElseThrow().state()); }
        }
    }

    @Test void retainedTransactionOutcomeSurvivesCheckpointNormalizationAndColdRestore() throws Exception {
        zeroecho.pki.spi.store.MetadataCommitResult retained;
        zeroecho.pki.spi.store.MetadataKey key = new zeroecho.pki.spi.store.MetadataKey("io.zeroecho.restore-test", "retained");
        try (FilesystemPkiStore store = open()) {
            try (zeroecho.pki.spi.store.MetadataTransaction transaction = store.metadataStore().beginTransaction();
                    zeroecho.core.io.RepeatableContent content = new zeroecho.core.io.RepeatableContent() {
                        @Override public java.io.InputStream openStream() { return new java.io.ByteArrayInputStream(new byte[] {4, 5}); }
                        @Override public java.util.OptionalLong length() { return java.util.OptionalLong.of(2); }
                        @Override public String contentId() { return "restore-fixture"; }
                        @Override public void close() { }
                    }) {
                transaction.create(key, content, zeroecho.core.io.CancellationSignal.NONE);
                retained = transaction.commit();
            }
            assertEquals(zeroecho.pki.spi.store.MetadataCommitResult.Outcome.COMMITTED, retained.outcome());
            try (BackupSource source = store.createBackupSource(request())) { store.stageRestore(source); }
        }
        try (FilesystemPkiStore store = open()) {
            assertEquals(RestoreStatus.State.ACTIVATED, store.latestRestoreStatus().orElseThrow().state());
            assertEquals(retained, store.metadataStore().resolve(retained.transactionId()));
            try (zeroecho.pki.spi.store.MetadataSnapshot snapshot = store.metadataStore().snapshot();
                    zeroecho.pki.spi.store.MetadataSnapshot.Record record = snapshot.get(key).orElseThrow();
                    java.io.InputStream input = record.openStream()) {
                assertEquals(retained.committedRevision().orElseThrow(), record.recordRevision());
                org.junit.jupiter.api.Assertions.assertArrayEquals(new byte[] {4, 5}, input.readAllBytes());
            }
        }
    }

    @Test void historicalCounterStateCannotBeStaged() throws Exception {
        try (FilesystemPkiStore store = open()) {
            zeroecho.pki.api.ca.CaRecord ca = FilesystemPkiStoreTest.TestObjects.minimalCaRecord(store, "counter-ca", zeroecho.pki.api.ca.CaState.ACTIVE);
            store.putCa(ca);
            store.reserveCrlNumber(ca.currentIssuanceIssuerId());
            try (BackupSource source = store.createBackupSource(request())) {
                java.math.BigInteger current = store.reserveCrlNumber(ca.currentIssuanceIssuerId());
                assertThrows(IOException.class, () -> store.stageRestore(source));
                assertTrue(store.latestRestoreStatus().isEmpty());
                assertEquals(current.add(java.math.BigInteger.ONE), store.reserveCrlNumber(ca.currentIssuanceIssuerId()));
            }
        }
    }

    @Test void missingOrCorruptPreparedCandidateFailsWithoutMovingLive() throws Exception {
        for (boolean missing : List.of(false, true)) {
            Path original = directory;
            directory = original.resolve(missing ? "missing" : "corrupt");
            PkiId id;
            try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) { id = store.stageRestore(source).restoreId(); }
            Path stage = directory.resolve(".store.restore-stage-" + id);
            if (missing) Files.move(stage, directory.resolve("retained-candidate"));
            else Files.writeString(stage.resolve("VERSION"), "bad");
            try (FilesystemPkiStore store = open()) { assertEquals(RestoreStatus.State.FAILED, store.latestRestoreStatus().orElseThrow().state()); }
            assertFalse(Files.exists(directory.resolve(".store.restore-old-" + id)));
            directory = original;
        }
    }

    @Test void nestedExternalAuthorityIsRejectedButKnownPublicationTemporaryIsAllowed() throws Exception {
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) {
            Path unexpected = directory.resolve("store/revocations/operator-notes");
            Files.writeString(unexpected, "legitimate colocated external authority");
            assertEquals("RESTORE_EXTERNAL_AUTHORITY", assertThrows(IOException.class, () -> store.stageRestore(source)).getMessage());
            Files.move(unexpected, directory.resolve("preserved-operator-notes"));
            Files.writeString(directory.resolve("store/.version-00000000-0000-0000-0000-000000000001.tmp"), "interrupted publication");
            assertEquals(RestoreStatus.State.STAGED, store.stageRestore(source).state());
        }
        try (FilesystemPkiStore store = open()) { assertEquals(RestoreStatus.State.ACTIVATED, store.latestRestoreStatus().orElseThrow().state()); }
        assertEquals("legitimate colocated external authority", Files.readString(directory.resolve("preserved-operator-notes")));
    }

    @Test void completeJournalNeverInitializesOverMissingActivatedRoot() throws Exception {
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) { store.stageRestore(source); }
        try (FilesystemPkiStore store = open()) { assertEquals(RestoreStatus.State.ACTIVATED, store.latestRestoreStatus().orElseThrow().state()); }
        Files.move(directory.resolve("store"), directory.resolve("preserved-activated"));
        assertThrows(IllegalStateException.class, this::open);
        assertFalse(Files.exists(directory.resolve("store")));
        assertTrue(Files.exists(directory.resolve("preserved-activated/VERSION")));
    }

    @Test void resumedVisibleMovesAreForcedBeforeJournalPublication() throws Exception {
        Path original = directory;
        for (int move = 1; move <= 2; move++) {
            directory = original.resolve("move-" + move);
            try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) { store.stageRestore(source); }
            int target = move;
            java.util.concurrent.atomic.AtomicInteger moves = new java.util.concurrent.atomic.AtomicInteger();
            FsRestoreCoordinator.observeWith(phase -> {
                if (phase == FsRestoreCoordinator.Phase.AFTER_ATOMIC_MOVE && moves.incrementAndGet() == target) throw new Crash();
            });
            assertThrows(Crash.class, this::open);
            List<FsRestoreCoordinator.Phase> events = new java.util.ArrayList<>();
            FsRestoreCoordinator.observeWith(events::add);
            try (FilesystemPkiStore store = open()) { assertEquals(RestoreStatus.State.ACTIVATED, store.latestRestoreStatus().orElseThrow().state()); }
            assertTrue(events.contains(FsRestoreCoordinator.Phase.DIRECTORY_FORCE));
            assertTrue(events.contains(FsRestoreCoordinator.Phase.BEFORE_RECORD_WRITE));
            assertTrue(events.indexOf(FsRestoreCoordinator.Phase.DIRECTORY_FORCE)
                    < events.indexOf(FsRestoreCoordinator.Phase.BEFORE_RECORD_WRITE));
            FsRestoreCoordinator.observeWith(null);
        }
        directory = original.resolve("rollback");
        PkiId id;
        try (FilesystemPkiStore store = open(); BackupSource source = store.createBackupSource(request())) { id = store.stageRestore(source).restoreId(); }
        FsRestoreCoordinator.observeWith(phase -> { if (phase == FsRestoreCoordinator.Phase.AFTER_LIVE_MOVE) throw new Crash(); });
        assertThrows(Crash.class, this::open);
        FsRestoreCoordinator.observeWith(null);
        Files.move(directory.resolve(".store.restore-stage-" + id), directory.resolve("preserved-stage"));
        FsRestoreCoordinator.observeWith(phase -> { if (phase == FsRestoreCoordinator.Phase.AFTER_ATOMIC_MOVE) throw new Crash(); });
        assertThrows(Crash.class, this::open);
        List<FsRestoreCoordinator.Phase> events = new java.util.ArrayList<>();
        FsRestoreCoordinator.observeWith(events::add);
        try (FilesystemPkiStore store = open()) { assertEquals(RestoreStatus.State.FAILED, store.latestRestoreStatus().orElseThrow().state()); }
        assertTrue(events.contains(FsRestoreCoordinator.Phase.DIRECTORY_FORCE));
        assertTrue(events.contains(FsRestoreCoordinator.Phase.BEFORE_RECORD_WRITE));
        assertTrue(events.indexOf(FsRestoreCoordinator.Phase.DIRECTORY_FORCE)
                < events.indexOf(FsRestoreCoordinator.Phase.BEFORE_RECORD_WRITE));
    }

    private static final class Crash extends Error { }
}
