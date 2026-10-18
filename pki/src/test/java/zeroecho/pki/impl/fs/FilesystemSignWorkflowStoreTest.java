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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProviderExecutor;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.PkiTestRuntime;
import zeroecho.pki.testkit.SigningTransitionRecorder;

/** Clean-format atomic signing acceptance and lifecycle persistence coverage. */
@SuppressWarnings({ "PMD.UnitTestContainsTooManyAsserts",
        "PMD.UnitTestAssertionsShouldIncludeMessage" })
final class FilesystemSignWorkflowStoreTest {
    private static final Instant NOW = Instant.parse("2026-01-02T03:04:05.123Z");
    private static final Principal OWNER = new Principal("TEST", "owner");
    private static final AccessContext ACCESS = new AccessContext(OWNER, new Purpose("SIGN"),
            Optional.empty(), Optional.empty());
    private static final KeyRef KEY = new KeyRef("test-key");

    @Test
    void acceptancePersistsSeparateImmutableEnvelopeIntentAndCandidateBindingAcrossRestart(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        SignWorkflowStore.AcceptanceCommand command;
        byte[] encodedEnvelope;
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            command = command(store, newOperationId(store), new byte[] { 1, 2, 3 },
                    "SHA256withRSA", Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(command));
            SignWorkflowStore.Workflow workflow = store.getSignWorkflow(command.operationId()).orElseThrow();
            assertEquals(SignWorkflowStore.State.INTENT, workflow.state());
            assertEquals(0L, workflow.revision());
            assertEquals(command.commitment(), workflow.envelope().acceptanceCommitment());
            assertEquals(command.candidate(), workflow.envelope().candidate());
            encodedEnvelope = FsCodec.encode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE, workflow.envelope());

            SignWorkflowStore.Workflow dispatched = store.claimSignStep(command.operationId(), 0L,
                    Duration.ofSeconds(30)).orElseThrow();
            assertEquals(SignWorkflowStore.State.DISPATCHED, dispatched.state());
            assertEquals(1L, dispatched.revision());
            assertEquals(1L, dispatched.fence());
            assertEquals(Optional.of(command.operationId()), dispatched.downstreamOperationId());
            assertTrue(dispatched.leaseUntil().isPresent());
            assertArrayEquals(encodedEnvelope,
                    FsCodec.encode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE, dispatched.envelope()),
                    "mutable transitions must not rewrite or overlap immutable envelope fields");
        }

        try (FilesystemPkiStore reopened = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            SignWorkflowStore.Workflow recovered = reopened.getSignWorkflow(command.operationId()).orElseThrow();
            assertEquals(SignWorkflowStore.State.DISPATCHED, recovered.state());
            assertArrayEquals(encodedEnvelope,
                    FsCodec.encode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE, recovered.envelope()));
            assertEquals(SignWorkflowStore.AcceptanceResolution.MATCHED,
                    reopened.resolveAcceptance(command.operationId(), command.commitment()));
        }
    }

    @Test
    void recoveryStreamsMaximumEnvelopesIntoExactDueTuples(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        String maximumAlgorithm = "A".repeat(FsCodec.MAX_COMPONENT_BYTES);
        List<SignWorkflowStore.AcceptanceCommand> commands = new ArrayList<>();
        long maximumEnvelopeBytes = 0L;
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            for (int index = 0; index < 3; index++) {
                SignWorkflowStore.AcceptanceCommand command = command(store,
                        newOperationId(store), new byte[] { (byte) index }, maximumAlgorithm,
                        Optional.empty());
                commands.add(command);
                maximumEnvelopeBytes = Math.max(maximumEnvelopeBytes,
                        FsCodec.encode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE,
                                SignWorkflowStore.AcceptanceEnvelope.from(command)).length);
                assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED,
                        store.acceptSign(command));
            }
        }

        try (FilesystemPkiStore reopened = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            SigningLedgerStoreEngine.RecoveryProjectionStatistics statistics =
                    reopened.metadataStore().recoveryProjectionStatistics();
            assertEquals(3L, statistics.envelopesVisited());
            assertTrue(statistics.peakTrackedEnvelopeWorkspaceBytes() > 0L);
            assertTrue(statistics.peakTrackedEnvelopeWorkspaceBytes()
                    <= maximumEnvelopeBytes);
            assertEquals(0L, statistics.currentTrackedEnvelopeWorkspaceBytes());

            SegmentedTransactionalMetadataStore.SigningDuePage due =
                    reopened.metadataStore().pageSigningDue(NOW, Optional.empty(),
                            Optional.empty(), commands.size());
            List<SegmentedTransactionalMetadataStore.SigningDueCandidate> expected = commands
                    .stream()
                    .sorted(java.util.Comparator.comparing(command -> command.operationId().value()))
                    .map(command -> new SegmentedTransactionalMetadataStore.SigningDueCandidate(
                            command.operationId().value(),
                            new SignWorkflowStore.SchedulingCoordinates(
                                    command.keyRef(), command.fairnessAuthorityId()), false))
                    .toList();
            assertEquals(expected, due.candidates());
        }
    }

    @Test
    void reopenRejectsMissingSigningCandidateBindingWithoutMutation(@TempDir Path root)
            throws Exception {
        assertRecoveredGraphRejected(root, RecoveredGraphCorruption.MISSING_BINDING);
    }

    @Test
    void reopenRejectsMissingOuterContinuationWithoutMutation(@TempDir Path root)
            throws Exception {
        assertRecoveredGraphRejected(root, RecoveredGraphCorruption.MISSING_CONTINUATION);
    }

    @Test
    void reopenRejectsMissingOuterCorrelationWithoutMutation(@TempDir Path root)
            throws Exception {
        assertRecoveredGraphRejected(root, RecoveredGraphCorruption.MISSING_CORRELATION);
    }

    @Test
    void reopenRejectsMismatchedOuterCorrelationTargetWithoutMutation(@TempDir Path root)
            throws Exception {
        assertRecoveredGraphRejected(root, RecoveredGraphCorruption.MISMATCHED_TARGET);
    }

    @Test
    void reopenRejectsEveryOuterRecoveryFieldMismatchWithoutMutation(@TempDir Path root)
            throws Exception {
        for (RecoveredGraphCorruption corruption : List.of(
                RecoveredGraphCorruption.MISMATCHED_OUTER_CREATED_AT,
                RecoveredGraphCorruption.MISMATCHED_OUTER_DEADLINE,
                RecoveredGraphCorruption.MISMATCHED_OUTER_SIGNING_CONTENT)) {
            assertRecoveredGraphRejected(root.resolve(corruption.name()), corruption);
        }
    }

    @Test
    void successfulRecoveryCleansEveryAbandonedStagedCandidate(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore ignored = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            // establish a valid persisted store
        }
        List<Path> candidates = createAbandonedStagedCandidates(root);
        try (FilesystemPkiStore ignored = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            for (Path candidate : candidates) {
                assertFalse(Files.exists(candidate));
            }
        }
    }

    @Test
    void malformedManifestAndWalParserFailuresAreCauseFreeAndRedacted(
            @TempDir Path temporary) throws Exception {
        for (boolean manifestFailure : List.of(true, false)) {
            Path root = temporary.resolve(manifestFailure ? "manifest" : "wal");
            MutableClock clock = new MutableClock(NOW);
            try (FilesystemPkiStore ignored =
                    FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
                // establish a valid persisted store
            }
            Path metadata = root.resolve("metadata");
            byte[] sentinel = "sensitive-parser-sentinel".getBytes(
                    java.nio.charset.StandardCharsets.US_ASCII);
            if (manifestFailure) {
                Files.write(metadata.resolve(SigningLedgerRecovery.MANIFEST_FILE), sentinel);
            } else {
                SigningManifestCodec.Manifest decoded = SigningManifestCodec.decode(
                        Files.readAllBytes(metadata.resolve(SigningLedgerRecovery.MANIFEST_FILE)));
                byte[] malformed = new byte[SigningWalContainerCodec.HEADER_BYTES];
                System.arraycopy(sentinel, 0, malformed, 0,
                        Math.min(sentinel.length, malformed.length));
                Files.write(metadata.resolve(decoded.activeWal().name()), malformed);
            }
            List<FileImage> before = fileImages(root);
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> FilesystemPkiStoreTestAccess.open(root, 4, clock));
            assertEquals("Filesystem store format unsupported: code=STORE_FORMAT_UNSUPPORTED",
                    failure.getMessage());
            assertEquals(null, failure.getCause());
            assertEquals(0, failure.getSuppressed().length);
            assertFalse(failure.toString().contains("sensitive-parser-sentinel"));
            assertEquals(before, fileImages(root));
        }
    }

    @Test
    void malformedOrphanCheckpointIsCauseFreeAndRedacted(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore ignored = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            // establish a valid persisted store
        }
        byte[] sentinel = "sensitive-orphan-checkpoint".getBytes(
                java.nio.charset.StandardCharsets.US_ASCII);
        Path orphan = root.resolve("metadata").resolve(
                "checkpoint-00000000000000000001-00000000000000000001.zec");
        Files.write(orphan, sentinel);
        List<FileImage> before = fileImages(root);

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> FilesystemPkiStoreTestAccess.open(root, 4, clock));

        assertEquals("Filesystem store format unsupported: code=STORE_FORMAT_UNSUPPORTED",
                failure.getMessage());
        assertEquals(null, failure.getCause());
        assertEquals(0, failure.getSuppressed().length);
        assertFalse(failure.toString().contains("sensitive-orphan-checkpoint"));
        assertEquals(before, fileImages(root));
    }

    @Test
    void orphanCheckpointOperationalReadFailureRemainsCauseful(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore ignored = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            // establish a valid persisted store
        }
        Path orphan = root.resolve("metadata").resolve(
                "checkpoint-00000000000000000001-00000000000000000001.zec");
        Files.write(orphan, new byte[
                SigningCheckpointCodec.HEADER_BYTES + SigningCheckpointCodec.FOOTER_BYTES]);
        SigningCheckpointCodec.installReadFault(
                () -> { throw new IOException("operational-checkpoint-read-sentinel"); });
        try {
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> FilesystemPkiStoreTestAccess.open(root, 4, clock));
            assertEquals("Filesystem store open failed: code=STORE_OPEN_FAILED",
                    failure.getMessage());
            assertEquals("operational-checkpoint-read-sentinel",
                    failure.getCause().getMessage());
        } finally {
            SigningCheckpointCodec.clearReadFault();
        }
    }

    @Test
    void validEnvelopeOperationalReadFailureRemainsCauseful(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            SignWorkflowStore.AcceptanceCommand command = command(store,
                    newOperationId(store), new byte[] { 31 }, "SHA256withRSA",
                    Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED,
                    store.acceptSign(command));
        }
        List<FileImage> before = fileImages(root);
        FilesystemStagedContentStore.installMetadataReadFault(metadata -> {
            throw new IOException("operational-envelope-read-sentinel");
        });
        try {
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> FilesystemPkiStoreTestAccess.open(root, 4, clock));
            assertEquals("Filesystem store open failed: code=STORE_OPEN_FAILED",
                    failure.getMessage());
            assertEquals("operational-envelope-read-sentinel",
                    failure.getCause().getMessage());
            assertEquals(before, fileImages(root));
        } finally {
            FilesystemStagedContentStore.clearMetadataReadFault();
        }
    }

    @Test
    void validEnvelopeOperationalAttributeReadFailureRemainsCauseful(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            SignWorkflowStore.AcceptanceCommand command = command(store,
                    newOperationId(store), new byte[] { 32 }, "SHA256withRSA",
                    Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED,
                    store.acceptSign(command));
        }
        List<FileImage> before = fileImages(root);
        FilesystemStagedContentStore.installMetadataAttributeReadFault(metadata -> {
            throw new IOException("operational-metadata-attribute-sentinel");
        });
        try {
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> FilesystemPkiStoreTestAccess.open(root, 4, clock));
            assertEquals("Filesystem store open failed: code=STORE_OPEN_FAILED",
                    failure.getMessage());
            assertEquals("operational-metadata-attribute-sentinel",
                    failure.getCause().getMessage());
            assertEquals(before, fileImages(root));
        } finally {
            FilesystemStagedContentStore.clearMetadataAttributeReadFault();
        }
    }

    @Test
    void passiveWalOperationalOpenFailureRemainsCausefulAndReleasesOwnership(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore ignored = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            // establish a valid persisted store
        }
        List<FileImage> before = fileImages(root);
        long threadsBefore = recoveryThreadCount();
        SigningGenerationRegistry[] observedRegistry = new SigningGenerationRegistry[1];
        SigningLedgerRecovery.installRecoveryFault((stage, registry) -> {
            observedRegistry[0] = registry;
            if (stage == SigningLedgerRecovery.RecoveryStage.AFTER_PASSIVE_WAL_OPEN) {
                throw new IOException("operational-passive-open-sentinel");
            }
        });
        try {
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> FilesystemPkiStoreTestAccess.open(root, 4, clock));
            assertEquals("Filesystem store open failed: code=STORE_OPEN_FAILED",
                    failure.getMessage());
            assertEquals("operational-passive-open-sentinel",
                    failure.getCause().getMessage());
            assertEquals(before, fileImages(root));
            assertEquals(threadsBefore, recoveryThreadCount());
            SigningGenerationRegistry.Snapshot snapshot = observedRegistry[0].statistics();
            assertEquals(0L, snapshot.currentReferences());
            assertEquals(0L, snapshot.snapshotPins());
            assertEquals(0L, snapshot.recoveryTemporaryReferences());
        } finally {
            SigningLedgerRecovery.clearRecoveryFault();
        }
    }

    @Test
    void metadataSymlinkAndNonDirectoryAreCauseFreeAndRedacted(
            @TempDir Path temporary) throws Exception {
        for (boolean symlink : List.of(true, false)) {
            Path root = temporary.resolve(symlink ? "symlink" : "non-directory");
            MutableClock clock = new MutableClock(NOW);
            try (FilesystemPkiStore ignored =
                    FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
                // establish a valid persisted store
            }
            Path metadata = root.resolve("metadata");
            Path retained = temporary.resolve(
                    symlink ? "symlink-metadata-target" : "non-directory-metadata-backup");
            Files.move(metadata, retained);
            if (symlink) {
                try {
                    Files.createSymbolicLink(metadata, retained.toAbsolutePath());
                } catch (java.nio.file.FileSystemException e) {
                    Assumptions.assumeTrue(false, "Symlink creation not supported on this platform: " + e.getMessage());
                }
            } else {
                Files.write(metadata, "sensitive-metadata-type".getBytes(
                        java.nio.charset.StandardCharsets.US_ASCII));
            }

            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> FilesystemPkiStoreTestAccess.open(root, 4, clock));
            assertEquals("Filesystem store format unsupported: code=STORE_FORMAT_UNSUPPORTED",
                    failure.getMessage());
            assertEquals(null, failure.getCause());
            assertEquals(0, failure.getSuppressed().length);
            assertFalse(failure.toString().contains("sensitive-metadata-type"));
        }
    }

    @Test
    void reopenRejectsEveryStateEnvelopeIdentityMismatchWithoutMutation(@TempDir Path root)
            throws Exception {
        for (RecoveredGraphCorruption corruption : List.of(
                RecoveredGraphCorruption.MISSING_ENVELOPE,
                RecoveredGraphCorruption.MISMATCHED_STATE_ID,
                RecoveredGraphCorruption.MISMATCHED_ENVELOPE_ID)) {
            assertRecoveredGraphRejected(root.resolve(corruption.name()), corruption);
        }
    }

    @Test
    void reopenRejectsEveryCandidateBindingMismatchWithoutMutation(@TempDir Path root)
            throws Exception {
        for (RecoveredGraphCorruption corruption : List.of(
                RecoveredGraphCorruption.MISMATCHED_BINDING_ID,
                RecoveredGraphCorruption.MISMATCHED_BINDING_OPERATION,
                RecoveredGraphCorruption.MISMATCHED_BINDING_LENGTH,
                RecoveredGraphCorruption.MISMATCHED_BINDING_DIGEST)) {
            assertRecoveredGraphRejected(root.resolve(corruption.name()), corruption);
        }
    }

    @Test
    void reopenRejectsEveryReverseSigningGraphOrphanWithoutMutation(@TempDir Path root)
            throws Exception {
        for (RecoveredGraphCorruption corruption : List.of(
                RecoveredGraphCorruption.ORPHAN_ENVELOPE,
                RecoveredGraphCorruption.ORPHAN_BINDING,
                RecoveredGraphCorruption.ORPHAN_CONTINUATION,
                RecoveredGraphCorruption.ORPHAN_CORRELATION)) {
            assertRecoveredGraphRejected(root.resolve(corruption.name()), corruption);
        }
    }

    @Test
    void concurrentSameCommandAcceptsOnceAndAttachesAllRacersEvenAtCapacity(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 1, clock);
                ExecutorService executor = Executors.newFixedThreadPool(8)) {
            SignWorkflowStore.AcceptanceCommand command = command(store, newOperationId(store),
                    new byte[] { 4, 5, 6 }, "SHA256withRSA", Optional.empty());
            CountDownLatch ready = new CountDownLatch(8);
            CountDownLatch start = new CountDownLatch(1);
            List<Future<SignWorkflowStore.AcceptanceResult>> futures = new ArrayList<>();
            for (int index = 0; index < 8; index++) {
                futures.add(executor.submit(() -> {
                    ready.countDown();
                    assertTrue(start.await(5, TimeUnit.SECONDS));
                    return store.acceptSign(command);
                }));
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            List<SignWorkflowStore.AcceptanceResult> results = new ArrayList<>();
            for (Future<SignWorkflowStore.AcceptanceResult> future : futures) {
                results.add(future.get(5, TimeUnit.SECONDS));
            }
            assertEquals(1L, results.stream()
                    .filter(SignWorkflowStore.AcceptanceResult.ACCEPTED::equals).count());
            assertEquals(7L, results.stream()
                    .filter(SignWorkflowStore.AcceptanceResult.ATTACHED_EXISTING::equals).count());
            assertEquals(1, store.listSignWorkflows().size());
        }
    }

    @Test
    void concurrentCandidateClaimHasOneWinnerAndLoserNeverDeletesWinnerContent(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock);
                ExecutorService executor = Executors.newFixedThreadPool(2)) {
            DurableContentReference candidate = candidate(store, new byte[] { 7, 8, 9 });
            SignWorkflowStore.AcceptanceCommand first = command(store, newOperationId(store), candidate,
                    "SHA256withRSA", Optional.empty());
            SignWorkflowStore.AcceptanceCommand second = command(store, newOperationId(store), candidate,
                    "SHA256withRSA", Optional.empty());
            CountDownLatch ready = new CountDownLatch(2);
            CountDownLatch start = new CountDownLatch(1);
            Future<SignWorkflowStore.AcceptanceResult> firstResult = executor.submit(() -> {
                ready.countDown();
                assertTrue(start.await(5, TimeUnit.SECONDS));
                return store.acceptSign(first);
            });
            Future<SignWorkflowStore.AcceptanceResult> secondResult = executor.submit(() -> {
                ready.countDown();
                assertTrue(start.await(5, TimeUnit.SECONDS));
                return store.acceptSign(second);
            });
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            List<SignWorkflowStore.AcceptanceResult> outcomes = List.of(
                    firstResult.get(5, TimeUnit.SECONDS), secondResult.get(5, TimeUnit.SECONDS));
            assertEquals(1L, outcomes.stream()
                    .filter(SignWorkflowStore.AcceptanceResult.ACCEPTED::equals).count());
            assertEquals(1L, outcomes.stream()
                    .filter(SignWorkflowStore.AcceptanceResult.CONFLICT::equals).count());
            assertEquals(1, store.listSignWorkflows().size());
            try (zeroecho.core.io.RepeatableContent content = store.stagedContent().openContent(candidate)) {
                assertEquals(candidate.length(), content.length().orElseThrow());
            }
        }
    }

    @Test
    void malformedAcceptanceCannotReclaimCandidateWhileValidAcceptanceClaimsIt(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 2, clock);
                ExecutorService executor = Executors.newFixedThreadPool(2)) {
            DurableContentReference candidate = candidate(store, new byte[] { 10, 11, 12 });
            SignWorkflowStore.AcceptanceCommand valid = command(store, newOperationId(store), candidate,
                    "SHA256withRSA", Optional.empty());
            SignWorkflowStore.OuterCommand exactOuter = outer("custody-race");
            SignWorkflowStore.OuterCommand malformedOuter = new SignWorkflowStore.OuterCommand(
                    exactOuter.kind(), exactOuter.correlationId(), exactOuter.command(),
                    "domain:v1:" + "0".repeat(64));
            SignWorkflowStore.AcceptanceCommand malformed = command(store, newOperationId(store), candidate,
                    "SHA256withRSA", Optional.of(malformedOuter));
            CountDownLatch validValidated = new CountDownLatch(1);
            CountDownLatch malformedAttempted = new CountDownLatch(1);

            Future<SignWorkflowStore.AcceptanceResult> accepted = executor.submit(() -> {
                FilesystemPkiStore.installSignAcceptanceValidatedObserver(() -> {
                    validValidated.countDown();
                    awaitLatch(malformedAttempted);
                });
                try {
                    return store.acceptSign(valid);
                } finally {
                    FilesystemPkiStore.clearSignAcceptanceValidatedObserver();
                }
            });
            awaitLatch(validValidated);
            Future<IllegalStateException> rejected = executor.submit(() -> {
                malformedAttempted.countDown();
                return assertThrows(IllegalStateException.class, () -> store.acceptSign(malformed));
            });

            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED,
                    accepted.get(5, TimeUnit.SECONDS));
            rejected.get(5, TimeUnit.SECONDS);
            assertEquals(SignWorkflowStore.AcceptanceResolution.MATCHED,
                    store.resolveAcceptance(valid.operationId(), valid.commitment()));
            assertEquals(SignWorkflowStore.AcceptanceResolution.NOT_ACCEPTED,
                    store.resolveAcceptance(malformed.operationId(), malformed.commitment()));
            try (zeroecho.core.io.RepeatableContent content = store.stagedContent().openContent(candidate)) {
                assertEquals(candidate.length(), content.length().orElseThrow());
            }
        }
    }

    @Test
    void identityConflictAndAttachmentAreResolvedBeforeFullCapacity(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 1, clock)) {
            PkiId operationId = newOperationId(store);
            SignWorkflowStore.AcceptanceCommand accepted = command(store, operationId,
                    new byte[] { 1 }, "SHA256withRSA", Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(accepted));
            assertEquals(SignWorkflowStore.AcceptanceResult.ATTACHED_EXISTING,
                    store.acceptSign(accepted));

            SignWorkflowStore.AcceptanceCommand conflict = command(store, operationId,
                    new byte[] { 2 }, "SHA512withRSA", Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.CONFLICT, store.acceptSign(conflict));
            assertThrows(IOException.class,
                    () -> store.stagedContent().openContent(conflict.candidate()));

            SignWorkflowStore.AcceptanceCommand full = command(store, newOperationId(store),
                    new byte[] { 3 }, "SHA256withRSA", Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.CAPACITY_REJECTED,
                    store.acceptSign(full));
            assertTrue(store.getSignWorkflow(full.operationId()).isEmpty());
            assertThrows(IOException.class,
                    () -> store.stagedContent().openContent(full.candidate()));
        }
    }

    @Test
    void outerTerminalControlsCapacityReleaseAndAcceptancePublishesExactCorrelation(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 1, clock)) {
            SignWorkflowStore.OuterCommand outer = outer("issue-17");
            SignWorkflowStore.AcceptanceCommand command = command(store, newOperationId(store),
                    new byte[] { 10 }, "SHA256withRSA", Optional.of(outer));
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(command));
            DomainContinuationStore.Record domain = store.getDomainContinuation(command.operationId())
                    .orElseThrow();
            assertEquals(Optional.of("issue-17"), domain.correlationId());
            assertEquals(DomainContinuationStore.State.SIGNING, domain.state());

            SignWorkflowStore.Workflow dispatched = store.claimSignStep(command.operationId(), 0L,
                    Duration.ofSeconds(30)).orElseThrow();
            SignWorkflowStore.Workflow succeeded = store.transitionSign(command.operationId(),
                    dispatched.revision(), dispatched.fence(), SignWorkflowStore.State.SUCCEEDED,
                    Optional.of("SIGNED"), Optional.of(new EncodedObject(Encoding.BINARY,
                            new byte[] { 1 })), Optional.of(NOW.plusSeconds(1))).orElseThrow();
            assertEquals(SignWorkflowStore.State.SUCCEEDED, succeeded.state());

            assertTrue(store.retireSign(command.operationId(), succeeded.revision(), succeeded.fence()).isEmpty(),
                    "retirement must remain blocked while the paired outer operation is non-terminal");
            try (zeroecho.core.io.RepeatableContent content =
                    store.stagedContent().openContent(command.candidate())) {
                assertEquals(command.candidate().length(), content.length().orElseThrow());
            }

            SignWorkflowStore.AcceptanceCommand blocked = command(store, newOperationId(store),
                    new byte[] { 20 }, "SHA256withRSA", Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.CAPACITY_REJECTED,
                    store.acceptSign(blocked), "signing terminal alone must not release an outer slot");

            store.transitionDomainContinuation(command.operationId(), domain.revision(),
                    DomainContinuationStore.State.FAILED, Optional.empty(),
                    Optional.of("PUBLICATION_FAILED")).orElseThrow();
            SignWorkflowStore.Workflow current = store.getSignWorkflow(command.operationId())
                    .orElseThrow();
            store.retireSign(command.operationId(), current.revision(), current.fence())
                    .orElseThrow();
            SignWorkflowStore.AcceptanceCommand admitted = command(store, newOperationId(store),
                    new byte[] { 21 }, "SHA256withRSA", Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(admitted));
        }
    }

    @Test
    void expiryAtomicallyTerminalizesRequiredOuterBeforeReleasingContentAndCapacity(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 1, clock)) {
            SignWorkflowStore.AcceptanceCommand command = command(store, newOperationId(store),
                    new byte[] { 22 }, "SHA256withRSA", Optional.of(outer("expiry-outer")));
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(command));

            clock.set(NOW.plusSeconds(31L));
            SignWorkflowStore.Workflow expired = store.getSignWorkflow(command.operationId()).orElseThrow();

            assertEquals(SignWorkflowStore.State.EXPIRED, expired.state());
            assertEquals(DomainContinuationStore.State.EXPIRED,
                    store.getDomainContinuation(command.operationId()).orElseThrow().state());
            assertThrows(IOException.class, () -> store.stagedContent().openContent(command.candidate()));
            SignWorkflowStore.AcceptanceCommand admitted = command(store, newOperationId(store),
                    new byte[] { 23 }, "SHA256withRSA", Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(admitted));
        }
    }

    @Test
    void malformedOuterIsRejectedBeforeAcceptanceAndItsCandidateIsReclaimed(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 1, clock)) {
            SignWorkflowStore.OuterCommand valid = outer("malformed-outer");
            SignWorkflowStore.OuterCommand malformed = new SignWorkflowStore.OuterCommand(
                    valid.kind(), valid.correlationId(), valid.command(), "domain:v1:" + "0".repeat(64));
            SignWorkflowStore.AcceptanceCommand command = command(store, newOperationId(store),
                    new byte[] { 24 }, "SHA256withRSA", Optional.of(malformed));

            assertThrows(IllegalStateException.class, () -> store.acceptSign(command));
            assertEquals(SignWorkflowStore.AcceptanceResolution.NOT_ACCEPTED,
                    store.resolveAcceptance(command.operationId(), command.commitment()));
            assertTrue(store.getDomainContinuation(command.operationId()).isEmpty());
            assertThrows(IOException.class, () -> store.stagedContent().openContent(command.candidate()));
        }
    }

    @Test
    void canonicalCommitmentValidOuterWithWrongKindIsRejectedAndReclaimed(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 1, clock)) {
            DomainContinuationTemplate template = DomainCommandEncoding.correlatedTemplate(
                    DomainContinuationStore.Kind.CA, "semantic-kind-mismatch", "GENERATE_STATUS");
            SignWorkflowStore.OuterCommand invalid = new SignWorkflowStore.OuterCommand(
                    template.kind(), template.correlationId().orElseThrow(), template.command(),
                    template.commandCommitment());
            SignWorkflowStore.AcceptanceCommand command = command(store, newOperationId(store),
                    new byte[] { 25 }, "SHA256withRSA", Optional.of(invalid));

            assertThrows(IllegalStateException.class, () -> store.acceptSign(command));
            assertEquals(SignWorkflowStore.AcceptanceResolution.NOT_ACCEPTED,
                    store.resolveAcceptance(command.operationId(), command.commitment()));
            assertTrue(store.getDomainContinuation(command.operationId()).isEmpty());
            assertThrows(IOException.class, () -> store.stagedContent().openContent(command.candidate()));
        }
    }

    @Test
    void transitionRecorderUsesReadOnlySnapshotAndKeepsFirstObservedDurableState(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 2, clock)) {
            PkiId operationId = newOperationId(store);
            SigningTransitionRecorder recorder = new SigningTransitionRecorder();
            assertEquals(Optional.empty(), recorder.sample(store, operationId).state());
            SignWorkflowStore.AcceptanceCommand command = command(store, operationId,
                    new byte[] { 31 }, "SHA256withRSA", Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(command));
            clock.set(NOW.plusSeconds(31));

            assertEquals(Optional.of(SignWorkflowStore.State.INTENT),
                    recorder.sample(store, operationId).state(),
                    "snapshot sampling must not perform deadline mutation");
            SignWorkflowStore.Workflow expired = store.getSignWorkflow(operationId).orElseThrow();
            assertEquals(SignWorkflowStore.State.EXPIRED, expired.state());
            assertEquals(Optional.of(SignWorkflowStore.State.INTENT),
                    recorder.sample(store, operationId).state(),
                    "the first durable observation is immutable");
        }
    }

    @Test
    void acceptanceAndMutableTransitionReportIsolatedWalAndCodecEvidence(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 2, clock)) {
            SignWorkflowStore.AcceptanceCommand compact = command(store, newOperationId(store),
                    new byte[] { 51 }, "SHA256withRSA", Optional.empty());
            SignWorkflowStore.AcceptanceCommand expanded = command(store, newOperationId(store),
                    new byte[] { 52 }, "A".repeat(65_536), Optional.empty());

            FilesystemPkiStore.LocalSigningWriterMetrics before = store.localSigningWriterMetrics();
            SignWorkflowStore.AcceptanceResult compactResult = store.acceptSign(compact);
            FilesystemPkiStore.LocalSigningWriterMetrics afterCompact = store.localSigningWriterMetrics();
            SignWorkflowStore.AcceptanceResult expandedResult = store.acceptSign(expanded);
            FilesystemPkiStore.LocalSigningWriterMetrics afterExpanded = store.localSigningWriterMetrics();

            FilesystemPkiStore.LocalSigningWriterMetrics beforeCompactTransition =
                    store.localSigningWriterMetrics();
            store.claimSignStep(compact.operationId(), 0L, Duration.ofSeconds(10)).orElseThrow();
            FilesystemPkiStore.LocalSigningWriterMetrics afterCompactTransition =
                    store.localSigningWriterMetrics();

            FilesystemPkiStore.LocalSigningWriterMetrics beforeExpandedTransition =
                    store.localSigningWriterMetrics();
            store.claimSignStep(expanded.operationId(), 0L, Duration.ofSeconds(10)).orElseThrow();
            FilesystemPkiStore.LocalSigningWriterMetrics afterExpandedTransition =
                    store.localSigningWriterMetrics();

            FilesystemPkiStore.LocalSigningWriterMetrics beforeNonAcceptingResults =
                    store.localSigningWriterMetrics();
            SignWorkflowStore.AcceptanceResult attached = store.acceptSign(compact);
            SignWorkflowStore.AcceptanceCommand conflict = command(store, compact.operationId(),
                    new byte[] { 53 }, "SHA512withRSA", Optional.empty());
            SignWorkflowStore.AcceptanceResult conflictResult = store.acceptSign(conflict);
            SignWorkflowStore.AcceptanceCommand rejected = command(store, newOperationId(store),
                    new byte[] { 54 }, "SHA256withRSA", Optional.empty());
            SignWorkflowStore.AcceptanceResult capacityResult = store.acceptSign(rejected);
            FilesystemPkiStore.LocalSigningWriterMetrics afterNonAcceptingResults =
                    store.localSigningWriterMetrics();

            Map<SignWorkflowStore.AcceptanceResult, Long> resultCounts =
                    new EnumMap<>(SignWorkflowStore.AcceptanceResult.class);
            for (SignWorkflowStore.AcceptanceResult result : List.of(compactResult,
                    expandedResult, attached, conflictResult, capacityResult)) {
                resultCounts.merge(result, 1L, Math::addExact);
            }
            AcceptanceStorageEvidence evidence = new AcceptanceStorageEvidence(
                    FsCodec.encode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE,
                            SignWorkflowStore.AcceptanceEnvelope.from(compact)).length,
                    FsCodec.encode(FsCodec.SIGN_MUTABLE_STATE,
                            SignWorkflowStore.MutableState.intent(compact.operationId(),
                            SignWorkflowStore.Mode.NORMAL, zeroecho.pki.spi.store.SignWorkflowStore.Stage.SINGLE)).length,
                    metricDelta(afterCompact.bytesAppended(), before.bytesAppended()),
                    metricDelta(afterCompactTransition.bytesAppended(),
                            beforeCompactTransition.bytesAppended()),
                    metricDelta(afterExpanded.bytesAppended(), afterCompact.bytesAppended()),
                    metricDelta(afterExpandedTransition.bytesAppended(),
                            beforeExpandedTransition.bytesAppended()),
                    2L,
                    metricDelta(afterExpanded.requestsCommitted(), before.requestsCommitted()),
                    metricDelta(afterExpanded.forces(), before.forces()),
                    Map.copyOf(resultCounts));

            assertTrue(evidence.acceptanceEnvelopeEncodedBytes() > 0L);
            assertTrue(evidence.initialStateEncodedBytes() > 0L);
            assertTrue(evidence.acceptanceWalBytes() > evidence.mutableTransitionWalBytes());
            assertTrue(evidence.expandedAcceptanceWalBytes() > evidence.acceptanceWalBytes());
            assertEquals(evidence.mutableTransitionWalBytes(),
                    evidence.expandedMutableTransitionWalBytes(),
                    "mutable transition WAL bytes must be independent of envelope size");
            assertEquals(2L, evidence.acceptanceTransactions(),
                    "only successful new acceptance commits count as acceptance transactions");
            assertEquals(6L, evidence.acceptanceRequestsCommitted(),
                    "one atomic acceptance transaction contains the three split-record requests");
            assertEquals(6L, evidence.acceptanceForces(),
                    "the snapshot reports one forced frame per split-record request");
            assertEquals(Map.of(SignWorkflowStore.AcceptanceResult.ACCEPTED, 2L,
                    SignWorkflowStore.AcceptanceResult.ATTACHED_EXISTING, 1L,
                    SignWorkflowStore.AcceptanceResult.CONFLICT, 1L,
                    SignWorkflowStore.AcceptanceResult.CAPACITY_REJECTED, 1L),
                    evidence.resultCounts());
            assertEquals(beforeNonAcceptingResults.requestsCommitted(),
                    afterNonAcceptingResults.requestsCommitted(),
                    "attachment, conflict, and capacity rejection must append no acceptance transaction");
            assertEquals(beforeNonAcceptingResults.forces(), afterNonAcceptingResults.forces());
            assertEquals(3L, metricDelta(afterCompact.requestsCommitted(), before.requestsCommitted()));
            assertEquals(3L, metricDelta(afterCompact.forces(), before.forces()));
            assertEquals(3L, metricDelta(afterCompactTransition.requestsCommitted(),
                    beforeCompactTransition.requestsCommitted()));
            assertEquals(3L, metricDelta(afterCompactTransition.forces(),
                    beforeCompactTransition.forces()));
        }
    }

    @Test
    void cancellationReopenAndRetirementPreserveStatePointerAndIdentityBinding(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        SignWorkflowStore.AcceptanceCommand command;
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 2, clock)) {
            command = command(store, newOperationId(store), new byte[] { 61, 62 },
                    "SHA256withRSA", Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(command));
            SignWorkflowStore.Workflow claimed = store.claimSignStep(command.operationId(), 0L,
                    Duration.ofSeconds(10)).orElseThrow();
            SignWorkflowStore.Workflow cancelling = store.requestSignCancellation(command.operationId(),
                    claimed.revision(), claimed.fence()).orElseThrow();
            assertEquals(SignWorkflowStore.State.CANCELLING, cancelling.state());
            assertEquals(SignWorkflowStore.State.CANCELLING,
                    store.selectDueSignWorkflows(NOW, 2).getFirst().state(),
                    "the active projection pointer must select the latest mutable state");
        }

        try (FilesystemPkiStore reopened = FilesystemPkiStoreTestAccess.open(root, 2, clock)) {
            SignWorkflowStore.Workflow cancelling = reopened.getSignWorkflow(command.operationId())
                    .orElseThrow();
            assertEquals(SignWorkflowStore.State.CANCELLING, cancelling.state());
            SignWorkflowStore.Workflow cancelled = reopened.transitionSign(command.operationId(),
                    cancelling.revision(), cancelling.fence(), SignWorkflowStore.State.CANCELLED,
                    Optional.of("CANCELLED"), Optional.empty(), Optional.of(NOW.plusSeconds(1)))
                    .orElseThrow();
            assertEquals(SignWorkflowStore.State.CANCELLED, cancelled.state());
            SignWorkflowStore.Workflow retired = reopened.retireSign(command.operationId(),
                    cancelled.revision(), cancelled.fence()).orElseThrow();
            assertEquals(SignWorkflowStore.State.RETIRED, retired.state());
            assertThrows(IOException.class,
                    () -> reopened.stagedContent().openContent(command.candidate()),
                    "retirement must reclaim candidate bytes");
            assertEquals(SignWorkflowStore.AcceptanceResolution.MATCHED,
                    reopened.resolveAcceptance(command.operationId(), command.commitment()),
                    "the candidate binding and acceptance identity survive content retirement");
            assertEquals(SignWorkflowStore.AcceptanceResult.ATTACHED_EXISTING,
                    reopened.acceptSign(command));
        }
    }

    @Test
    void cleanV16MarkerIsPublishedAndUnsupportedRootIsRejectedWithoutFurtherMutation(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore ignored = FilesystemPkiStoreTestAccess.open(root, 2, clock)) {
            assertArrayEquals("v18".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                    Files.readAllBytes(root.resolve("VERSION")));
        }
        Files.writeString(root.resolve("VERSION"), "v15");
        List<FileImage> before = fileImages(root);
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> FilesystemPkiStoreTestAccess.open(root, 2, clock));
        assertTrue(failure.getMessage().contains("STORE_FORMAT_UNSUPPORTED"));
        assertEquals(null, failure.getCause());
        assertEquals(0, failure.getSuppressed().length);
        assertEquals(before, fileImages(root),
                "unsupported preflight must complete before cleanup or recovery mutation");
    }

    @Test
    void codecSeparatesEnvelopeStateAndBindingSchemas() throws Exception {
        byte[] envelopeBytes;
        byte[] stateBytes;
        byte[] bindingBytes;
        Path root = Files.createTempDirectory("zeroecho-codec-");
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 2,
                new MutableClock(NOW))) {
            SignWorkflowStore.AcceptanceCommand command = command(store, newOperationId(store),
                    new byte[] { 41, 42 }, "SHA256withRSA", Optional.empty());
            SignWorkflowStore.AcceptanceEnvelope envelope =
                    SignWorkflowStore.AcceptanceEnvelope.from(command);
            SignWorkflowStore.MutableState state = SignWorkflowStore.MutableState.intent(
                    command.operationId(), SignWorkflowStore.Mode.NORMAL, zeroecho.pki.spi.store.SignWorkflowStore.Stage.SINGLE);
            SignWorkflowStore.CandidateBinding binding = new SignWorkflowStore.CandidateBinding(
                    command.candidate().contentId(), command.operationId(),
                    command.candidate().length(), command.candidate().sha256());
            envelopeBytes = FsCodec.encode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE, envelope);
            stateBytes = FsCodec.encode(FsCodec.SIGN_MUTABLE_STATE, state);
            bindingBytes = FsCodec.encode(FsCodec.SIGN_CANDIDATE_BINDING, binding);
            assertEquals(envelope,
                    FsCodec.decode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE, envelopeBytes,
                            store.stagedContent()));
            assertEquals(state, FsCodec.decode(FsCodec.SIGN_MUTABLE_STATE, stateBytes));
            assertEquals(binding, FsCodec.decode(FsCodec.SIGN_CANDIDATE_BINDING, bindingBytes));
        } finally {
            deleteRecursively(root);
        }
        assertNotEquals(Arrays.toString(envelopeBytes), Arrays.toString(stateBytes));
        assertNotEquals(Arrays.toString(envelopeBytes), Arrays.toString(bindingBytes));
    }

    @Test
    void leasedPrefixDoesNotFillBoundedDuePageAndExpiredLeaseReclaimsAfterRestart(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        PkiId firstId;
        long firstRevision;
        long firstFence;
        PkiId readyId;
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            SignWorkflowStore.AcceptanceCommand first = command(store, newOperationId(store),
                    new byte[] { 71 }, "SHA256withRSA", Optional.empty());
            SignWorkflowStore.AcceptanceCommand second = command(store, newOperationId(store),
                    new byte[] { 72 }, "SHA256withRSA", Optional.empty());
            SignWorkflowStore.AcceptanceCommand ready = command(store, newOperationId(store),
                    new byte[] { 73 }, "SHA256withRSA", Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(first));
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(second));
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(ready));
            SignWorkflowStore.Workflow firstClaim = store.claimSignStep(first.operationId(), 0L,
                    Duration.ofSeconds(10)).orElseThrow();
            store.claimSignStep(second.operationId(), 0L, Duration.ofSeconds(10)).orElseThrow();

            List<SignWorkflowStore.Workflow> due = store.selectDueSignWorkflows(NOW, 1);
            assertEquals(1, due.size());
            assertEquals(ready.operationId(), due.getFirst().operationId(),
                    "live leased entries must not consume the bounded ready page");
            firstId = first.operationId();
            firstRevision = firstClaim.revision();
            firstFence = firstClaim.fence();
            readyId = ready.operationId();
        }

        clock.set(NOW.plusSeconds(11));
        try (FilesystemPkiStore reopened = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            SignWorkflowStore.Workflow reclaimed = reopened.claimSignStep(firstId, firstRevision,
                    Duration.ofSeconds(10)).orElseThrow();
            assertEquals(SignWorkflowStore.State.DISPATCHED, reclaimed.state());
            assertEquals(firstFence + 1L, reclaimed.fence());
            assertEquals(Optional.of(firstId), reclaimed.downstreamOperationId());
            assertTrue(reopened.transitionSign(firstId, reclaimed.revision(), firstFence,
                    SignWorkflowStore.State.FAILED, Optional.of("STALE"), Optional.empty(),
                    Optional.empty()).isEmpty(), "a stale fence must not mutate reclaimed work");
            assertEquals(readyId, reopened.selectDueSignWorkflows(clock.instant(), 1).getFirst().operationId());
        }
    }

    @Test
    void lightweightDuePagesPreserveCursorAndStableHighWatermark(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        PkiId firstOperation;
        SignWorkflowStore.SchedulingCoordinates expectedScheduling;
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            List<SignWorkflowStore.AcceptanceCommand> commands = List.of(
                    command(store, newOperationId(store), new byte[] { 91 },
                            "SHA256withRSA", Optional.empty()),
                    command(store, newOperationId(store), new byte[] { 92 },
                            "SHA256withRSA", Optional.empty()),
                    command(store, newOperationId(store), new byte[] { 93 },
                            "SHA256withRSA", Optional.empty()));
            for (SignWorkflowStore.AcceptanceCommand command : commands) {
                assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED,
                        store.acceptSign(command));
            }
            List<PkiId> expected = commands.stream().map(SignWorkflowStore.AcceptanceCommand::operationId)
                    .sorted((first, second) -> first.value().compareTo(second.value())).toList();
            firstOperation = expected.getFirst();
            SignWorkflowStore.AcceptanceCommand firstCommand = commands.stream()
                    .filter(command -> command.operationId().equals(firstOperation))
                    .findFirst().orElseThrow();
            expectedScheduling = new SignWorkflowStore.SchedulingCoordinates(
                    firstCommand.keyRef(), firstCommand.fairnessAuthorityId());

            SignWorkflowStore.DuePage first = store.pageDueSignWorkflows(NOW,
                    Optional.empty(), Optional.empty(), 2, CancellationSignal.NONE);
            assertEquals(expected.subList(0, 2), first.candidates().stream()
                    .map(SignWorkflowStore.DueCandidate::operationId).toList());
            assertEquals(expectedScheduling, first.candidates().getFirst().scheduling());
            assertEquals(Optional.of(expected.get(1).value()), first.nextCursor());
            assertEquals(Optional.of(expected.get(2).value()), first.highWatermark());
            assertFalse(first.endReached());
            assertEquals(0, first.failures());

            SignWorkflowStore.DuePage second = store.pageDueSignWorkflows(NOW,
                    first.nextCursor(), first.highWatermark(), 2, CancellationSignal.NONE);
            assertEquals(List.of(expected.get(2)), second.candidates().stream()
                    .map(SignWorkflowStore.DueCandidate::operationId).toList());
            assertEquals(Optional.of(expected.get(2).value()), second.nextCursor());
            assertEquals(first.highWatermark(), second.highWatermark());
            assertTrue(second.endReached());
            assertEquals(SignWorkflowStore.State.INTENT,
                    store.getSignWorkflow(second.candidates().getFirst().operationId())
                            .orElseThrow().state());
        }
        try (FilesystemPkiStore reopened = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            SignWorkflowStore.DueCandidate recovered = reopened.pageDueSignWorkflows(NOW,
                    Optional.empty(), Optional.empty(), 4, CancellationSignal.NONE)
                    .candidates().stream()
                    .filter(candidate -> candidate.operationId().equals(firstOperation))
                    .findFirst().orElseThrow();
            assertEquals(expectedScheduling, recovered.scheduling());
        }
    }

    @Test
    void dispatchClaimIsDurableBeforeProviderHookObservesOperation(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 2, clock)) {
            SignWorkflowStore.AcceptanceCommand command = command(store, newOperationId(store),
                    new byte[] { 74 }, "SHA256withRSA", Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(command));
            SignWorkflowStore.Workflow claimed = store.claimSignStep(command.operationId(), 0L,
                    Duration.ofSeconds(10)).orElseThrow();

            Runnable providerHook = () -> {
                SignWorkflowStore.Workflow observed = store.getSignWorkflow(command.operationId()).orElseThrow();
                assertEquals(SignWorkflowStore.State.DISPATCHED, observed.state());
                assertEquals(claimed.revision(), observed.revision());
                assertEquals(claimed.fence(), observed.fence());
                assertEquals(Optional.of(command.operationId()), observed.downstreamOperationId());
                assertTrue(observed.leaseUntil().isPresent());
            };
            providerHook.run();
        }
    }

    @Test
    void providerBindingMismatchBlocksEveryProviderCall(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            SignWorkflowStore.AcceptanceCommand namespaceCommand = command(store, newOperationId(store),
                    new byte[] { 76 }, "SHA256withRSA", Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(namespaceCommand));
            CountingSigningProvider namespaceMismatch = new CountingSigningProvider("other", (byte) 17);
            assertBindingMismatchBlocksEveryCall(store, namespaceCommand, namespaceMismatch);
            assertEquals(0, namespaceMismatch.calls());

            SignWorkflowStore.AcceptanceCommand configurationCommand = command(store, newOperationId(store),
                    new byte[] { 77 }, "SHA256withRSA", Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(configurationCommand));
            CountingSigningProvider configurationMismatch = new CountingSigningProvider("test-signer", (byte) 18);
            assertBindingMismatchBlocksEveryCall(store, configurationCommand, configurationMismatch);
            assertEquals(0, configurationMismatch.calls());
        }
    }

    @Test
    void staleProviderClaimCannotInvokeProviderAfterLeaseReclaim(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 2, clock)) {
            SignWorkflowStore.AcceptanceCommand command = command(store, newOperationId(store),
                    new byte[] { 78 }, "SHA256withRSA", Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(command));
            SignWorkflowStore.Workflow stale = store.claimSignStep(command.operationId(), 0L,
                    Duration.ofSeconds(10)).orElseThrow();
            clock.set(NOW.plusSeconds(11));
            assertTrue(store.renewSignStep(command.operationId(), stale.revision(), stale.fence(),
                    Duration.ofSeconds(10)).isEmpty(), "an expired lease owner cannot renew");
            SignWorkflowStore.Workflow current = store.claimSignStep(command.operationId(), stale.revision(),
                    Duration.ofSeconds(10)).orElseThrow();
            assertEquals(stale.fence() + 1L, current.fence());

            CountingSigningProvider provider = new CountingSigningProvider("test-signer", (byte) 17);
            SigningProviderExecutor executor = new SigningProviderExecutor(store, provider, Duration.ofSeconds(5));
            try (RepeatableContent content = store.stagedContent().openContent(command.candidate())) {
                assertThrows(IllegalStateException.class,
                        () -> executor.dispatch(stale, content, CancellationSignal.NONE));
            }
            assertEquals(0, provider.calls());
        }
    }

    @Test
    void deferredDispatchIsValidNotDueUntilRetryAndThenReclaimableAcrossRestart(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        SignWorkflowStore.AcceptanceCommand command;
        SignWorkflowStore.Workflow deferred;
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 2, clock)) {
            command = command(store, newOperationId(store), new byte[] { 79 }, "SHA256withRSA", Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(command));
            SignWorkflowStore.Workflow claimed = store.claimSignStep(command.operationId(), 0L,
                    Duration.ofSeconds(10)).orElseThrow();
            deferred = store.deferSignReconciliation(command.operationId(), claimed.revision(), claimed.fence(),
                    SignWorkflowStore.ReconciliationFailureClass.STATUS_UNAVAILABLE).orElseThrow();
            assertEquals(SignWorkflowStore.State.DISPATCHED, deferred.state());
            assertTrue(deferred.leaseUntil().isEmpty());
            assertEquals(1, deferred.failureCount());
            assertTrue(deferred.nextEligibleAt().isPresent());
            assertTrue(deferred.reconciliationFailureClass().isPresent());
            assertTrue(store.selectDueSignWorkflows(deferred.nextEligibleAt().orElseThrow().minusNanos(1), 2)
                    .isEmpty());
            assertTrue(store.claimSignStep(command.operationId(), deferred.revision(), Duration.ofSeconds(10))
                    .isEmpty(), "durable retry eligibility must gate a direct claim");
            SignWorkflowStore.Workflow retained = store.getSignWorkflow(command.operationId()).orElseThrow();
            assertEquals(deferred.revision(), retained.revision());
            assertEquals(deferred.failureCount(), retained.failureCount());
            assertEquals(deferred.nextEligibleAt(), retained.nextEligibleAt());
            assertEquals(deferred.reconciliationFailureClass(), retained.reconciliationFailureClass());
        }

        try (FilesystemPkiStore reopened = FilesystemPkiStoreTestAccess.open(root, 2, clock)) {
            assertTrue(reopened.selectDueSignWorkflows(deferred.nextEligibleAt().orElseThrow().minusNanos(1), 2)
                    .isEmpty());
            clock.set(deferred.nextEligibleAt().orElseThrow());
            assertEquals(command.operationId(), reopened.selectDueSignWorkflows(clock.instant(), 2)
                    .getFirst().operationId());
            SignWorkflowStore.Workflow reclaimed = reopened.claimSignStep(command.operationId(),
                    deferred.revision(), Duration.ofSeconds(10)).orElseThrow();
            assertEquals(deferred.fence() + 1L, reclaimed.fence());
            assertTrue(reclaimed.leaseUntil().isPresent());
            assertEquals(0, reclaimed.failureCount());
            assertTrue(reclaimed.nextEligibleAt().isEmpty());
            assertTrue(reclaimed.reconciliationFailureClass().isEmpty());
        }
    }

    @Test
    void claimAndRenewLeaseClampToWorkflowDeadline(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW.plusSeconds(29));
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 2, clock)) {
            SignWorkflowStore.AcceptanceCommand command = command(store, newOperationId(store),
                    new byte[] { 80 }, "SHA256withRSA", Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(command));
            SignWorkflowStore.Workflow claimed = store.claimSignStep(command.operationId(), 0L,
                    Duration.ofDays(365)).orElseThrow();
            assertEquals(command.deadline(), claimed.leaseUntil().orElseThrow());
            clock.set(NOW.plusSeconds(29).plusMillis(500));
            SignWorkflowStore.Workflow renewed = store.renewSignStep(command.operationId(), claimed.revision(),
                    claimed.fence(), Duration.ofDays(365)).orElseThrow();
            assertEquals(command.deadline(), renewed.leaseUntil().orElseThrow());
            clock.set(command.deadline());
            assertTrue(store.renewSignStep(command.operationId(), renewed.revision(), renewed.fence(),
                    Duration.ofSeconds(1)).isEmpty());
            assertEquals(SignWorkflowStore.State.EXPIRED,
                    store.getSignWorkflow(command.operationId()).orElseThrow().state());
            assertTrue(store.claimSignStep(command.operationId(), renewed.revision() + 1L,
                    Duration.ofSeconds(1)).isEmpty());
            CountingSigningProvider provider = new CountingSigningProvider("test-signer", (byte) 17);
            SigningProviderExecutor executor = new SigningProviderExecutor(store, provider, Duration.ofSeconds(5));
            assertThrows(IllegalStateException.class, () -> executor.dispatch(renewed,
                    new ImmutableByteContent(new byte[] { 80 }), CancellationSignal.NONE));
            assertEquals(0, provider.calls());
        }
    }

    @Test
    void forgedCallerEnvelopeCannotReachProvider(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            SignWorkflowStore.AcceptanceCommand command = command(store, newOperationId(store),
                    new byte[] { 81 }, "SHA256withRSA", Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(command));
            SignWorkflowStore.Workflow claimed = store.claimSignStep(command.operationId(), 0L,
                    Duration.ofSeconds(10)).orElseThrow();
            CountingSigningProvider provider = new CountingSigningProvider("test-signer", (byte) 17);
            SigningProviderExecutor executor = new SigningProviderExecutor(store, provider, Duration.ofSeconds(5));
            assertDoesNotThrow(() -> new SigningProviderExecutor(store, provider, Duration.ofDays(1)));
            assertThrows(IllegalArgumentException.class,
                    () -> new SigningProviderExecutor(store, provider, Duration.ofDays(1).plusNanos(1)));

            DurableContentReference alternateCandidate = candidate(store, new byte[] { 82 });
            AccessContext alternateAccess = new AccessContext(new Principal("TEST", "forged"),
                    new Purpose("SIGN"), Optional.empty(), Optional.empty());
            List<SignWorkflowStore.AcceptanceEnvelope> forged = List.of(
                    envelope(command, "forged.test-signer", command.providerConfigurationCommitment(),
                            command.accessContext(), command.keyRef(), command.candidate()),
                    envelope(command, command.providerNamespace(),
                            new SigningProvider.ConfigurationCommitment(new byte[32]),
                            command.accessContext(), command.keyRef(), command.candidate()),
                    envelope(command, command.providerNamespace(), command.providerConfigurationCommitment(),
                            command.accessContext(), new KeyRef("forged-key"), command.candidate()),
                    envelope(command, command.providerNamespace(), command.providerConfigurationCommitment(),
                            command.accessContext(), command.keyRef(), alternateCandidate),
                    envelope(command, command.providerNamespace(), command.providerConfigurationCommitment(),
                            alternateAccess, command.keyRef(), command.candidate()));
            try (RepeatableContent content = store.stagedContent().openContent(command.candidate())) {
                for (SignWorkflowStore.AcceptanceEnvelope forgedEnvelope : forged) {
                    SignWorkflowStore.Workflow forgedWorkflow = new SignWorkflowStore.Workflow(
                            forgedEnvelope, claimed.mutableState());
                    assertThrows(IllegalStateException.class,
                            () -> executor.dispatch(forgedWorkflow, content, CancellationSignal.NONE));
                }
            }
            assertEquals(0, provider.calls());
        }
    }

    @Test
    void cancellationBeforeDispatchTerminalizesWithoutProviderStep(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 2, clock)) {
            SignWorkflowStore.AcceptanceCommand command = command(store, newOperationId(store),
                    new byte[] { 75 }, "SHA256withRSA", Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(command));
            assertTrue(store.transitionSign(command.operationId(), 0L, 0L,
                    SignWorkflowStore.State.FAILED, Optional.of("FAILED"), Optional.empty(), Optional.empty())
                    .isEmpty(), "unclaimed intent cannot acquire a provider-derived failure");
            SignWorkflowStore.Workflow cancelled = store.requestSignCancellation(command.operationId(), 0L, 0L)
                    .orElseThrow();
            assertEquals(SignWorkflowStore.State.CANCELLED, cancelled.state());
            assertEquals(1L, cancelled.revision());
            assertEquals(0L, cancelled.fence());
            assertTrue(cancelled.downstreamOperationId().isEmpty());
            assertTrue(store.claimSignStep(command.operationId(), cancelled.revision(), Duration.ofSeconds(10))
                    .isEmpty(), "store-terminal cancellation must never reach a provider claim");
        }
    }

    @Test
    void succeededOuterContinuationLocalFailureBackoffIsStrictAndDurable(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        PkiId retryId;
        Instant nextEligible;
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 6, clock)) {
            SignWorkflowStore.AcceptanceCommand retry = command(store, newOperationId(store),
                    new byte[] { 86 }, "SHA256withRSA", Optional.of(outer("outer-retry")));
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(retry));
            SignWorkflowStore.Workflow succeeded = succeed(store, retry);
            DomainContinuationStore.Record signing = store.getDomainContinuation(retry.operationId())
                    .orElseThrow();
            assertTrue(store.transitionDomainContinuation(retry.operationId(), signing.revision(),
                    DomainContinuationStore.State.PUBLISHING, Optional.empty(), Optional.empty()).isPresent());

            SignWorkflowStore.Workflow deferred = store.deferSignReconciliation(
                    retry.operationId(), succeeded.revision(), succeeded.fence(),
                    SignWorkflowStore.ReconciliationFailureClass.LOCAL_FAILURE).orElseThrow();
            assertEquals(SignWorkflowStore.State.SUCCEEDED, deferred.state());
            assertEquals(succeeded.result().orElseThrow().encoding(),
                    deferred.result().orElseThrow().encoding());
            assertArrayEquals(succeeded.result().orElseThrow().bytes(),
                    deferred.result().orElseThrow().bytes());
            assertEquals(succeeded.detailCode(), deferred.detailCode());
            assertEquals(succeeded.providerUpdatedAt(), deferred.providerUpdatedAt());
            assertEquals(succeeded.fence(), deferred.fence());
            assertEquals(succeeded.revision() + 1L, deferred.revision());
            assertTrue(deferred.leaseUntil().isEmpty());
            assertEquals(1, deferred.failureCount());
            assertEquals(Optional.of(SignWorkflowStore.ReconciliationFailureClass.LOCAL_FAILURE),
                    deferred.reconciliationFailureClass());
            nextEligible = NOW.plusSeconds(2L);
            assertEquals(Optional.of(nextEligible), deferred.nextEligibleAt());
            assertTrue(store.pageDueSignWorkflows(nextEligible.minusNanos(1L), Optional.empty(),
                    Optional.empty(), 6, CancellationSignal.NONE).candidates().isEmpty());
            assertTrue(store.deferSignReconciliation(retry.operationId(), succeeded.revision(),
                    succeeded.fence(), SignWorkflowStore.ReconciliationFailureClass.LOCAL_FAILURE).isEmpty());
            assertTrue(store.deferSignReconciliation(retry.operationId(), deferred.revision(),
                    deferred.fence(), SignWorkflowStore.ReconciliationFailureClass.STATUS_UNAVAILABLE).isEmpty());
            clock.set(nextEligible);
            SignWorkflowStore.Workflow deferredAgain = store.deferSignReconciliation(
                    retry.operationId(), deferred.revision(), deferred.fence(),
                    SignWorkflowStore.ReconciliationFailureClass.LOCAL_FAILURE).orElseThrow();
            assertEquals(2, deferredAgain.failureCount());
            nextEligible = NOW.plusSeconds(6L);
            assertEquals(Optional.of(nextEligible), deferredAgain.nextEligibleAt());
            retryId = retry.operationId();

            SignWorkflowStore.AcceptanceCommand signOnly = command(store, newOperationId(store),
                    new byte[] { 87 }, "SHA256withRSA", Optional.empty());
            store.acceptSign(signOnly);
            SignWorkflowStore.Workflow signOnlySucceeded = succeed(store, signOnly);
            assertTrue(store.deferSignReconciliation(signOnly.operationId(),
                    signOnlySucceeded.revision(), signOnlySucceeded.fence(),
                    SignWorkflowStore.ReconciliationFailureClass.LOCAL_FAILURE).isEmpty());
            store.retireSign(signOnly.operationId(), signOnlySucceeded.revision(),
                    signOnlySucceeded.fence()).orElseThrow();

            SignWorkflowStore.AcceptanceCommand terminalOuter = command(store, newOperationId(store),
                    new byte[] { 88 }, "SHA256withRSA", Optional.of(outer("outer-terminal")));
            store.acceptSign(terminalOuter);
            SignWorkflowStore.Workflow terminalSucceeded = succeed(store, terminalOuter);
            DomainContinuationStore.Record terminal = store.getDomainContinuation(
                    terminalOuter.operationId()).orElseThrow();
            store.transitionDomainContinuation(terminalOuter.operationId(), terminal.revision(),
                    DomainContinuationStore.State.FAILED, Optional.empty(), Optional.of("FAILED"))
                    .orElseThrow();
            assertTrue(store.deferSignReconciliation(terminalOuter.operationId(),
                    terminalSucceeded.revision(), terminalSucceeded.fence(),
                    SignWorkflowStore.ReconciliationFailureClass.LOCAL_FAILURE).isEmpty());
            store.retireSign(terminalOuter.operationId(), terminalSucceeded.revision(),
                    terminalSucceeded.fence()).orElseThrow();

            SignWorkflowStore.AcceptanceCommand failedOuter = command(store, newOperationId(store),
                    new byte[] { 89 }, "SHA256withRSA", Optional.of(outer("outer-failed-sign")));
            store.acceptSign(failedOuter);
            SignWorkflowStore.Workflow failedClaim = store.claimSignStep(failedOuter.operationId(),
                    0L, Duration.ofSeconds(10L)).orElseThrow();
            SignWorkflowStore.Workflow failed = store.transitionSign(failedOuter.operationId(),
                    failedClaim.revision(), failedClaim.fence(), SignWorkflowStore.State.FAILED,
                    Optional.of("DENIED"), Optional.empty(), Optional.of(NOW.plusSeconds(1L)))
                    .orElseThrow();
            assertTrue(store.deferSignReconciliation(failedOuter.operationId(), failed.revision(),
                    failed.fence(), SignWorkflowStore.ReconciliationFailureClass.LOCAL_FAILURE).isEmpty());
            DomainContinuationStore.Record failedDomain = store.getDomainContinuation(
                    failedOuter.operationId()).orElseThrow();
            store.transitionDomainContinuation(failedOuter.operationId(), failedDomain.revision(),
                    DomainContinuationStore.State.FAILED, Optional.empty(), Optional.of("FAILED"))
                    .orElseThrow();
            store.retireSign(failedOuter.operationId(), failed.revision(), failed.fence())
                    .orElseThrow();
        }

        try (FilesystemPkiStore reopened = FilesystemPkiStoreTestAccess.open(root, 6, clock)) {
            SignWorkflowStore.Workflow retained = reopened.getSignWorkflow(retryId).orElseThrow();
            assertEquals(SignWorkflowStore.State.SUCCEEDED, retained.state());
            assertEquals(2, retained.failureCount());
            assertEquals(Optional.of(nextEligible), retained.nextEligibleAt());
            assertEquals(Optional.of(SignWorkflowStore.ReconciliationFailureClass.LOCAL_FAILURE),
                    retained.reconciliationFailureClass());
            assertTrue(reopened.pageDueSignWorkflows(nextEligible.minusNanos(1L), Optional.empty(),
                    Optional.empty(), 6, CancellationSignal.NONE).candidates().isEmpty());
            assertEquals(List.of(retryId), reopened.pageDueSignWorkflows(nextEligible,
                    Optional.empty(), Optional.empty(), 6, CancellationSignal.NONE).candidates()
                    .stream().map(SignWorkflowStore.DueCandidate::operationId).toList());
        }
    }

    @Test
    void retirementPreservesTypedTerminalEvidenceAcrossReopen(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        PkiId succeededId;
        PkiId failedId;
        PkiId cancelledId;
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            SignWorkflowStore.AcceptanceCommand succeeded = command(store, newOperationId(store),
                    new byte[] { 90 }, "SHA256withRSA", Optional.empty());
            store.acceptSign(succeeded);
            SignWorkflowStore.Workflow succeededClaim = store.claimSignStep(
                    succeeded.operationId(), 0L, Duration.ofSeconds(10L)).orElseThrow();
            SignWorkflowStore.Workflow succeededTerminal = store.transitionSign(
                    succeeded.operationId(), succeededClaim.revision(), succeededClaim.fence(),
                    SignWorkflowStore.State.SUCCEEDED, Optional.of("SIGNED"),
                    Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 1 })),
                    Optional.of(NOW.plusSeconds(1L))).orElseThrow();
            store.retireSign(succeeded.operationId(), succeededTerminal.revision(),
                    succeededTerminal.fence()).orElseThrow();
            succeededId = succeeded.operationId();

            SignWorkflowStore.AcceptanceCommand failed = command(store, newOperationId(store),
                    new byte[] { 91 }, "SHA256withRSA", Optional.empty());
            store.acceptSign(failed);
            SignWorkflowStore.Workflow failedClaim = store.claimSignStep(
                    failed.operationId(), 0L, Duration.ofSeconds(10L)).orElseThrow();
            SignWorkflowStore.Workflow failedTerminal = store.transitionSign(failed.operationId(),
                    failedClaim.revision(), failedClaim.fence(), SignWorkflowStore.State.FAILED,
                    Optional.of("DENIED"), Optional.empty(), Optional.of(NOW.plusSeconds(1L)))
                    .orElseThrow();
            store.retireSign(failed.operationId(), failedTerminal.revision(),
                    failedTerminal.fence()).orElseThrow();
            failedId = failed.operationId();

            SignWorkflowStore.AcceptanceCommand cancelled = command(store, newOperationId(store),
                    new byte[] { 92 }, "SHA256withRSA", Optional.empty());
            store.acceptSign(cancelled);
            SignWorkflowStore.Workflow cancelledClaim = store.claimSignStep(
                    cancelled.operationId(), 0L, Duration.ofSeconds(10L)).orElseThrow();
            SignWorkflowStore.Workflow cancelling = store.requestSignCancellation(
                    cancelled.operationId(), cancelledClaim.revision(), cancelledClaim.fence())
                    .orElseThrow();
            SignWorkflowStore.Workflow cancelledTerminal = store.transitionSign(
                    cancelled.operationId(), cancelling.revision(), cancelling.fence(),
                    SignWorkflowStore.State.CANCELLED, Optional.of("CANCELLED"),
                    Optional.empty(), Optional.of(NOW.plusSeconds(1L))).orElseThrow();
            store.retireSign(cancelled.operationId(), cancelledTerminal.revision(),
                    cancelledTerminal.fence()).orElseThrow();
            cancelledId = cancelled.operationId();
        }

        try (FilesystemPkiStore reopened = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            SignWorkflowStore.Workflow succeeded = reopened.getSignWorkflow(succeededId).orElseThrow();
            assertEquals(Optional.of("SIGNED"), succeeded.detailCode());
            assertTrue(succeeded.result().isPresent());
            SignWorkflowStore.Workflow failed = reopened.getSignWorkflow(failedId).orElseThrow();
            assertEquals(Optional.of("DENIED"), failed.detailCode());
            assertTrue(failed.result().isEmpty());
            SignWorkflowStore.Workflow cancelled = reopened.getSignWorkflow(cancelledId).orElseThrow();
            assertEquals(Optional.of("CANCELLED"), cancelled.detailCode());
            assertTrue(cancelled.result().isEmpty());
        }
    }

    private static SignWorkflowStore.AcceptanceCommand command(FilesystemPkiStore store,
            PkiId operationId, byte[] payload, String algorithm,
            Optional<SignWorkflowStore.OuterCommand> outer) throws Exception {
        return command(store, operationId, candidate(store, payload), algorithm, outer);
    }

    private static SignWorkflowStore.Workflow succeed(FilesystemPkiStore store,
            SignWorkflowStore.AcceptanceCommand command) {
        SignWorkflowStore.Workflow claimed = store.claimSignStep(command.operationId(), 0L,
                Duration.ofSeconds(10L)).orElseThrow();
        return store.transitionSign(command.operationId(), claimed.revision(), claimed.fence(),
                SignWorkflowStore.State.SUCCEEDED, Optional.of("SIGNED"),
                Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 7 })),
                Optional.of(NOW.plusSeconds(1L))).orElseThrow();
    }

    private static SignWorkflowStore.AcceptanceCommand command(FilesystemPkiStore store,
            PkiId operationId, DurableContentReference candidate, String algorithm,
            Optional<SignWorkflowStore.OuterCommand> outer) {
        byte[] commitment = new byte[SigningProvider.ConfigurationCommitment.BYTE_LENGTH];
        Arrays.fill(commitment, (byte) 17);
        return new SignWorkflowStore.AcceptanceCommand(operationId,
                SigningSubmissionId.parse(operationId).namespace(),
                new SigningProvider.ConfigurationCommitment(commitment), ACCESS, KEY,
                operationId, algorithm, Encoding.BINARY, NOW, NOW.plusSeconds(30), candidate, outer,
                SignWorkflowStore.Mode.NORMAL, java.util.Optional.empty());
    }

    private static void assertBindingMismatchBlocksEveryCall(FilesystemPkiStore store,
            SignWorkflowStore.AcceptanceCommand command, CountingSigningProvider provider) throws Exception {
        SigningProviderExecutor executor = new SigningProviderExecutor(store, provider, Duration.ofSeconds(5));
        SignWorkflowStore.Workflow claimed = store.claimSignStep(command.operationId(), 0L,
                Duration.ofSeconds(10)).orElseThrow();
        try (RepeatableContent content = store.stagedContent().openContent(command.candidate())) {
            assertThrows(IllegalStateException.class,
                    () -> executor.dispatch(claimed, content, CancellationSignal.NONE));
        }
        assertThrows(IllegalStateException.class,
                () -> executor.reconcile(claimed, CancellationSignal.NONE));
        SignWorkflowStore.Workflow cancelling = store.requestSignCancellation(command.operationId(),
                claimed.revision(), claimed.fence()).orElseThrow();
        SignWorkflowStore.Workflow claimedCancellation = store.claimSignStep(command.operationId(),
                cancelling.revision(), Duration.ofSeconds(10)).orElseThrow();
        assertThrows(IllegalStateException.class,
                () -> executor.cancel(claimedCancellation,
                        SigningProvider.CancellationReason.CALLER_REQUESTED, CancellationSignal.NONE));
    }

    private static SignWorkflowStore.AcceptanceEnvelope envelope(SignWorkflowStore.AcceptanceCommand source,
            String namespace, SigningProvider.ConfigurationCommitment configurationCommitment,
            AccessContext accessContext, KeyRef keyRef, DurableContentReference candidate) {
        SignWorkflowStore.AcceptanceCommand command = new SignWorkflowStore.AcceptanceCommand(
                source.operationId(), namespace, configurationCommitment, accessContext, keyRef,
                source.fairnessAuthorityId(), source.algorithmId(), source.signatureEncoding(),
                source.createdAt(), source.deadline(), candidate, source.outer(), SignWorkflowStore.Mode.NORMAL, java.util.Optional.empty());
        return SignWorkflowStore.AcceptanceEnvelope.from(command);
    }

    private static void assertRecoveredGraphRejected(Path root,
            RecoveredGraphCorruption corruption) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        SigningTransactionPayloadCodec.Mutation orphan = null;
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            Optional<SignWorkflowStore.OuterCommand> outer =
                    corruption == RecoveredGraphCorruption.MISSING_BINDING
                            ? Optional.empty() : Optional.of(outer("recovery-graph"));
            SignWorkflowStore.AcceptanceCommand command = command(store, newOperationId(store),
                    new byte[] { 101 }, "SHA256withRSA", outer);
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED,
                    store.acceptSign(command));
            if (requiresUncheckedMutation(corruption)) {
                orphan = isOrphanCorruption(corruption)
                        ? orphanRecoveredGraphMutation(store, command, corruption)
                        : recoveredGraphMutation(store, command, corruption);
            } else {
                MetadataCommitResult result = store.metadataStore().directCommit(
                        List.of(recoveredGraphMutation(store, command, corruption)));
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, result.outcome());
            }
            store.metadataStore().beginTransaction();
        }
        if (orphan != null) {
            appendUncheckedMetadataMutation(root, orphan);
        }
        createAbandonedStagedCandidates(root);
        List<FileImage> before = fileImages(root);
        IllegalStateException failure = assertThrows(IllegalStateException.class, () -> {
            try (FilesystemPkiStore ignored =
                    FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
                // Recovery must reject before exposing an open store.
            }
        });
        assertEquals("Filesystem store format unsupported: code=STORE_FORMAT_UNSUPPORTED",
                failure.getMessage());
        assertEquals(null, failure.getCause());
        assertEquals(0, failure.getSuppressed().length);
        assertEquals(before, fileImages(root),
                "failed graph validation must not mutate the store");
    }

    private static SigningTransactionPayloadCodec.Mutation recoveredGraphMutation(
            FilesystemPkiStore store,
            SignWorkflowStore.AcceptanceCommand command,
            RecoveredGraphCorruption corruption) throws Exception {
        MetadataKey key;
        byte[] replacement = null;
        switch (corruption) {
            case MISSING_ENVELOPE -> key = new MetadataKey(
                    "io.zeroecho.pki.signing-envelope", command.operationId().value());
            case MISMATCHED_STATE_ID -> {
                key = new MetadataKey(
                        "io.zeroecho.pki.signing-state", command.operationId().value());
                replacement = FsCodec.encode(FsCodec.SIGN_MUTABLE_STATE,
                        SignWorkflowStore.MutableState.intent(newOperationId(store), SignWorkflowStore.Mode.NORMAL, zeroecho.pki.spi.store.SignWorkflowStore.Stage.SINGLE));
            }
            case MISMATCHED_ENVELOPE_ID -> {
                key = new MetadataKey(
                        "io.zeroecho.pki.signing-envelope", command.operationId().value());
                SignWorkflowStore.AcceptanceCommand mismatched = command(store,
                        newOperationId(store), command.candidate(), command.algorithmId(),
                        command.outer());
                replacement = FsCodec.encode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE,
                        SignWorkflowStore.AcceptanceEnvelope.from(mismatched));
            }
            case MISSING_BINDING -> key = new MetadataKey(
                    "io.zeroecho.pki.signing-candidate-binding",
                    command.candidate().contentId());
            case MISSING_CONTINUATION -> key = new MetadataKey(
                    "io.zeroecho.pki.domain-continuation", command.operationId().value());
            case MISSING_CORRELATION, MISMATCHED_TARGET -> {
                SignWorkflowStore.OuterCommand outer = command.outer().orElseThrow();
                key = domainCorrelationKey(outer.kind(), outer.correlationId());
                if (corruption == RecoveredGraphCorruption.MISMATCHED_TARGET) {
                    replacement = ("v1\n" + newOperationId(store).value())
                            .getBytes(java.nio.charset.StandardCharsets.UTF_8);
                }
            }
            case MISMATCHED_OUTER_CREATED_AT, MISMATCHED_OUTER_DEADLINE,
                    MISMATCHED_OUTER_SIGNING_CONTENT -> {
                key = new MetadataKey("io.zeroecho.pki.domain-continuation",
                        command.operationId().value());
                SignWorkflowStore.OuterCommand outer = command.outer().orElseThrow();
                Instant createdAt = corruption
                        == RecoveredGraphCorruption.MISMATCHED_OUTER_CREATED_AT
                                ? command.createdAt().plusNanos(1L) : command.createdAt();
                Instant deadline = corruption
                        == RecoveredGraphCorruption.MISMATCHED_OUTER_DEADLINE
                                ? command.deadline().minusNanos(1L) : command.deadline();
                DurableContentReference signingContent = corruption
                        == RecoveredGraphCorruption.MISMATCHED_OUTER_SIGNING_CONTENT
                                ? candidate(store, new byte[] { 102 }) : command.candidate();
                DomainContinuationStore.Record continuation =
                        new DomainContinuationStore.Record(command.operationId(), 2,
                                outer.kind(), Optional.of(outer.correlationId()),
                                DomainContinuationStore.State.SIGNING, 0L, createdAt,
                                deadline, outer.command(), outer.commandCommitment(),
                                Optional.of(signingContent), Optional.empty(), Optional.empty());
                replacement = FsCodec.encode(FsCodec.DOMAIN_CONTINUATION, continuation);
            }
            case MISMATCHED_BINDING_ID, MISMATCHED_BINDING_OPERATION,
                    MISMATCHED_BINDING_LENGTH, MISMATCHED_BINDING_DIGEST -> {
                key = new MetadataKey("io.zeroecho.pki.signing-candidate-binding",
                        command.candidate().contentId());
                PkiId operationId = corruption
                        == RecoveredGraphCorruption.MISMATCHED_BINDING_OPERATION
                                ? newOperationId(store) : command.operationId();
                long length = corruption == RecoveredGraphCorruption.MISMATCHED_BINDING_LENGTH
                        ? Math.incrementExact(command.candidate().length())
                        : command.candidate().length();
                String digest = corruption == RecoveredGraphCorruption.MISMATCHED_BINDING_DIGEST
                        ? "0".repeat(64) : command.candidate().sha256();
                String candidateId = corruption == RecoveredGraphCorruption.MISMATCHED_BINDING_ID
                        ? command.candidate().contentId() + "-mismatch"
                        : command.candidate().contentId();
                replacement = FsCodec.encode(FsCodec.SIGN_CANDIDATE_BINDING,
                        new SignWorkflowStore.CandidateBinding(candidateId, operationId,
                                length, digest));
            }
            default -> throw new IllegalStateException("Unknown graph corruption");
        }
        try (MetadataSnapshot snapshot = store.metadataStore().snapshot()) {
            MetadataSnapshot.Record record = snapshot.get(key).orElseThrow();
            return replacement == null
                    ? new SigningTransactionPayloadCodec.Mutation(
                            SigningTransactionPayloadCodec.MutationKind.DELETE,
                            key, record.recordRevision(), null)
                    : new SigningTransactionPayloadCodec.Mutation(
                            SigningTransactionPayloadCodec.MutationKind.REPLACE,
                            key, record.recordRevision(), replacement);
        }
    }

    private static boolean isOrphanCorruption(RecoveredGraphCorruption corruption) {
        return corruption == RecoveredGraphCorruption.ORPHAN_ENVELOPE
                || corruption == RecoveredGraphCorruption.ORPHAN_BINDING
                || corruption == RecoveredGraphCorruption.ORPHAN_CONTINUATION
                || corruption == RecoveredGraphCorruption.ORPHAN_CORRELATION;
    }

    private static boolean requiresUncheckedMutation(RecoveredGraphCorruption corruption) {
        return isOrphanCorruption(corruption)
                || corruption == RecoveredGraphCorruption.MISSING_ENVELOPE
                || corruption == RecoveredGraphCorruption.MISMATCHED_STATE_ID
                || corruption == RecoveredGraphCorruption.MISMATCHED_ENVELOPE_ID;
    }

    private static SigningTransactionPayloadCodec.Mutation orphanRecoveredGraphMutation(
            FilesystemPkiStore store,
            SignWorkflowStore.AcceptanceCommand command,
            RecoveredGraphCorruption corruption) throws Exception {
        MetadataKey source = switch (corruption) {
            case ORPHAN_ENVELOPE -> new MetadataKey(
                    "io.zeroecho.pki.signing-envelope", command.operationId().value());
            case ORPHAN_BINDING -> new MetadataKey(
                    "io.zeroecho.pki.signing-candidate-binding",
                    command.candidate().contentId());
            case ORPHAN_CONTINUATION -> new MetadataKey(
                    "io.zeroecho.pki.domain-continuation", command.operationId().value());
            case ORPHAN_CORRELATION -> {
                SignWorkflowStore.OuterCommand outer = command.outer().orElseThrow();
                yield domainCorrelationKey(outer.kind(), outer.correlationId());
            }
            default -> throw new IllegalStateException("Not an orphan graph corruption");
        };
        byte[] content;
        try (MetadataSnapshot snapshot = store.metadataStore().snapshot();
                MetadataSnapshot.Record record = snapshot.get(source).orElseThrow()) {
            content = record.openStream().readAllBytes();
        }
        MetadataKey orphan = new MetadataKey(source.namespace(), "orphan");
        return new SigningTransactionPayloadCodec.Mutation(
                SigningTransactionPayloadCodec.MutationKind.CREATE,
                orphan, -1L, content);
    }

    private static void appendUncheckedMetadataMutation(Path root,
            SigningTransactionPayloadCodec.Mutation mutation) throws Exception {
        Path metadataRoot = root.resolve("metadata");
        SigningManifestCodec.Manifest manifest = SigningManifestCodec.decode(
                Files.readAllBytes(metadataRoot.resolve(SigningLedgerRecovery.MANIFEST_FILE)));
        SigningManifestCodec.ActiveWal active = manifest.activeWal();
        Path wal = metadataRoot.resolve(active.name());
        SigningWalFrameCodec.ScanResult scan;
        try (java.nio.channels.FileChannel channel = java.nio.channels.FileChannel.open(
                wal, java.nio.file.StandardOpenOption.READ)) {
            scan = SigningWalFrameCodec.scanGroups(channel, active.firstSequence(), true,
                    (frames, marker) -> { });
        }
        long sequence = Math.incrementExact(scan.lastSequence());
        byte[] payload = SigningTransactionPayloadCodec.directCommit(
                List.of(mutation), -1L);
        SigningWalFrameCodec.Frame frame = new SigningWalFrameCodec.Frame(
                SigningWalFrameCodec.RecordType.COMMIT,
                new java.util.UUID(0x5232L, sequence), sequence, payload);
        try (java.nio.channels.FileChannel channel = java.nio.channels.FileChannel.open(
                wal, java.nio.file.StandardOpenOption.APPEND)) {
            SigningWalFrameCodec.writeCommittedBatch(channel, List.of(frame),
                    scan.committedRevision(), Math.incrementExact(scan.committedRevision()),
                    scan.rollingCommitment());
            channel.force(true);
        }
    }

    private static List<Path> createAbandonedStagedCandidates(Path root) throws IOException {
        Path staged = root.resolve("staged-content");
        String first = "00000000-0000-0000-0000-000000000001";
        String second = "00000000-0000-0000-0000-000000000002";
        String third = "00000000-0000-0000-0000-000000000003";
        Path incomplete = staged.resolve(first + ".incomplete");
        Path metadata = staged.resolve(".metadata-" + second + ".tmp");
        Path uniqueIndex = staged.resolve(third + ".unique-index");
        Files.write(incomplete, new byte[] { 91 });
        Files.write(metadata, new byte[] { 92 });
        Files.createDirectory(uniqueIndex);
        Files.write(uniqueIndex.resolve("candidate"), new byte[] { 93 });
        return List.of(incomplete, metadata, uniqueIndex);
    }

    private static MetadataKey domainCorrelationKey(DomainContinuationStore.Kind kind,
            String correlationId) throws Exception {
        byte[] encoded = (kind.name() + '\n' + correlationId)
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String digest = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(encoded));
        return new MetadataKey("io.zeroecho.pki.domain-correlation", digest);
    }

    private static DurableContentReference candidate(FilesystemPkiStore store, byte[] payload)
            throws IOException {
        return PkiTestRuntime.operationReference(store.stagedContent(), Encoding.BINARY, payload);
    }

    private static SignWorkflowStore.OuterCommand outer(String correlationId) {
        DomainContinuationTemplate template = DomainCommandEncoding.correlatedTemplate(
                DomainContinuationStore.Kind.CA, correlationId, "CREATE_ROOT",
                "format:test", "CN=Test", "root", "test-key", "profile", "1",
                "1".repeat(64), NOW.toString(), NOW.plusSeconds(30).toString(), "1",
                "", "", "", "authority");
        return new SignWorkflowStore.OuterCommand(template.kind(),
                template.correlationId().orElseThrow(), template.command(), template.commandCommitment());
    }

    private static PkiId newOperationId(FilesystemPkiStore store) {
        return SigningSubmissionId.create(store.signingNamespace() + ".test-signer", NOW,
                new SecureRandom()).id();
    }

    private static long metricDelta(long after, long before) {
        return Math.subtractExact(after, before);
    }

    private static void awaitLatch(CountDownLatch latch) {
        try {
            assertTrue(latch.await(5, TimeUnit.SECONDS));
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new AssertionError("Interrupted while awaiting deterministic test boundary", failure);
        }
    }

    private static List<FileImage> fileImages(Path root) throws IOException {
        try (java.util.stream.Stream<Path> paths = Files.walk(root)) {
            return paths.filter(Files::isRegularFile).sorted().map(path -> {
                try {
                    return new FileImage(root.relativize(path).toString(), Files.readAllBytes(path));
                } catch (IOException failure) {
                    throw new java.io.UncheckedIOException(failure);
                }
            }).toList();
        } catch (java.io.UncheckedIOException failure) {
            throw failure.getCause();
        }
    }

    private static long recoveryThreadCount() {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(Thread::isAlive)
                .map(Thread::getName)
                .filter(name -> name.startsWith("zeroecho-signing-wal-writer")
                        || name.startsWith("zeroecho-metadata-commit-coordinator")
                        || name.startsWith("zeroecho-metadata-maintenance-coordinator"))
                .count();
    }

    private static void deleteRecursively(Path root) throws IOException {
        try (java.util.stream.Stream<Path> paths = Files.walk(root)) {
            List<Path> ordered = paths.sorted(java.util.Comparator.reverseOrder()).toList();
            for (Path path : ordered) {
                Files.deleteIfExists(path);
            }
        }
    }

    private record FileImage(String relativePath, byte[] bytes) {
        private FileImage {
            bytes = bytes.clone();
        }

        @Override public byte[] bytes() {
            return bytes.clone();
        }

        @Override public boolean equals(Object other) {
            return other instanceof FileImage image
                    && relativePath.equals(image.relativePath)
                    && Arrays.equals(bytes, image.bytes);
        }

        @Override public int hashCode() {
            return 31 * relativePath.hashCode() + Arrays.hashCode(bytes);
        }
    }

    private enum RecoveredGraphCorruption {
        MISSING_ENVELOPE,
        MISMATCHED_STATE_ID,
        MISMATCHED_ENVELOPE_ID,
        MISSING_BINDING,
        MISSING_CONTINUATION,
        MISSING_CORRELATION,
        MISMATCHED_TARGET,
        MISMATCHED_OUTER_CREATED_AT,
        MISMATCHED_OUTER_DEADLINE,
        MISMATCHED_OUTER_SIGNING_CONTENT,
        MISMATCHED_BINDING_ID,
        MISMATCHED_BINDING_OPERATION,
        MISMATCHED_BINDING_LENGTH,
        MISMATCHED_BINDING_DIGEST,
        ORPHAN_ENVELOPE,
        ORPHAN_BINDING,
        ORPHAN_CONTINUATION,
        ORPHAN_CORRELATION
    }

    private record AcceptanceStorageEvidence(long acceptanceEnvelopeEncodedBytes,
            long initialStateEncodedBytes, long acceptanceWalBytes,
            long mutableTransitionWalBytes, long expandedAcceptanceWalBytes,
            long expandedMutableTransitionWalBytes, long acceptanceTransactions,
            long acceptanceRequestsCommitted, long acceptanceForces,
            Map<SignWorkflowStore.AcceptanceResult, Long> resultCounts) {
        private AcceptanceStorageEvidence {
            resultCounts = Map.copyOf(resultCounts);
        }
    }

    private static final class CountingSigningProvider implements SigningProvider {
        @Override public zeroecho.pki.spi.crypto.SigningInputCapabilities inputCapabilities() {
            return new zeroecho.pki.spi.crypto.SigningInputCapabilities(Long.MAX_VALUE, java.util.Map.of());
        }
        private final String id;
        private final ConfigurationCommitment commitment;
        private int calls;

        private CountingSigningProvider(String id, byte commitmentByte) {
            this.id = id;
            byte[] bytes = new byte[ConfigurationCommitment.BYTE_LENGTH];
            Arrays.fill(bytes, commitmentByte);
            commitment = new ConfigurationCommitment(bytes);
        }

        @Override public String id() {
            return id;
        }

        @Override public ConfigurationCommitment configurationCommitment() {
            return commitment;
        }

        @Override public java.util.Set<String> supportedAlgorithms() {
            return java.util.Set.of("SHA256withRSA");
        }

        @Override public OperationObservation dispatch(SignRequest request, CallControl control) {
            calls++;
            throw new AssertionError("Provider dispatch must not be called for a binding mismatch");
        }

        @Override public OperationObservation reconcile(PkiId operationId, CallControl control) {
            calls++;
            throw new AssertionError("Provider reconcile must not be called for a binding mismatch");
        }

        @Override public OperationObservation cancel(PkiId operationId, long fencingToken,
                CancellationReason reason, CallControl control) {
            calls++;
            throw new AssertionError("Provider cancel must not be called for a binding mismatch");
        }

        @Override public void close() {
            // Nothing retained.
        }

        private int calls() {
            return calls;
        }
    }

    private static final class MutableClock extends Clock {
        private volatile Instant value;

        private MutableClock(Instant value) {
            this.value = value;
        }

        private void set(Instant next) {
            value = next;
        }

        @Override public ZoneId getZone() {
            return java.time.ZoneOffset.UTC;
        }

        @Override public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override public Instant instant() {
            return value;
        }
    }
}
