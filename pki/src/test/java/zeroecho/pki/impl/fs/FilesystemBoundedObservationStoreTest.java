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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiFailureReason;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.SignWorkflowStore.InitialAttemptPhase;
import zeroecho.pki.spi.store.SignWorkflowStore.Mode;
import zeroecho.pki.spi.store.SignWorkflowStore.Workflow;
import zeroecho.pki.testkit.PkiTestRuntime;

/** Real-store evidence for the durable bounded initial attempt, without provider calls. */
final class FilesystemBoundedObservationStoreTest {
    private static final Instant NOW = Instant.parse("2026-09-01T10:00:00Z");
    private static final Duration LEASE = Duration.ofSeconds(5);

    @Test
    void pendingCheckpointsReserveOneObservationAndKeepCleanupDueAcrossReopen(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock();
        PkiId operation;
        Workflow ready;
        try (FilesystemPkiStore store = open(root, clock)) {
            Workflow claimed = acceptedClaim(store, Mode.BOUNDED_OBSERVATION);
            operation = claimed.operationId();
            assertEquals(InitialAttemptPhase.DISPATCH_OWED, claimed.initialAttemptPhase());
            assertTrue(store.selectDueSignWorkflows(NOW, 8).isEmpty());
            ready = store.checkpointPendingSignDispatch(operation, claimed.revision(), claimed.fence()).orElseThrow();
            assertEquals(claimed.revision() + 1, ready.revision());
            assertEquals(claimed.fence(), ready.fence());
            assertEquals(InitialAttemptPhase.OBSERVATION_OWED, ready.initialAttemptPhase());
            assertTrue(ready.leaseUntil().isEmpty());
            assertEquals(List.of(operation), due(store, NOW));
        }
        try (FilesystemPkiStore store = open(root, clock)) {
            assertEquals(Mode.BOUNDED_OBSERVATION, store.getSignWorkflow(operation).orElseThrow().mode());
            Workflow observation = store.claimSignStep(operation, ready.revision(), LEASE).orElseThrow();
            assertEquals(InitialAttemptPhase.OBSERVATION_CONSUMED, observation.initialAttemptPhase());
            Workflow complete = store.completeSignObservation(operation, observation.revision(), observation.fence())
                    .orElseThrow();
            assertEquals(InitialAttemptPhase.COMPLETED, complete.initialAttemptPhase());
            assertEquals(SignWorkflowStore.State.DISPATCHED, complete.state());
            assertEquals(observation.leaseUntil(), complete.leaseUntil());
            assertTrue(store.completeSignObservation(operation, complete.revision(), complete.fence()).isEmpty());
            assertTrue(due(store, NOW).isEmpty());
            assertEquals(List.of(operation), due(store, NOW.plus(LEASE)));
            clock.value = NOW.plus(LEASE);
            Workflow cleanup = store.claimSignStep(operation, complete.revision(), LEASE).orElseThrow();
            assertEquals(InitialAttemptPhase.COMPLETED, cleanup.initialAttemptPhase());
            Workflow renewed = store.renewSignStep(operation, cleanup.revision(), cleanup.fence(), LEASE).orElseThrow();
            assertEquals(InitialAttemptPhase.COMPLETED, renewed.initialAttemptPhase());
        }
        try (FilesystemPkiStore store = open(root, clock)) {
            assertEquals(InitialAttemptPhase.COMPLETED, store.getSignWorkflow(operation).orElseThrow().initialAttemptPhase());
        }
    }

    @Test
    void crashBeforeDispatchCheckpointReservesObservationAndCrashAfterClaimFailsClosed(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock();
        Workflow dispatch;
        Workflow observation;
        try (FilesystemPkiStore store = open(root, clock)) {
            dispatch = acceptedClaim(store, Mode.BOUNDED_OBSERVATION);
        }
        clock.value = NOW.plus(LEASE);
        try (FilesystemPkiStore store = open(root, clock)) {
            observation = store.claimSignStep(dispatch.operationId(), dispatch.revision(), LEASE).orElseThrow();
            assertEquals(InitialAttemptPhase.OBSERVATION_CONSUMED, observation.initialAttemptPhase());
            assertTrue(store.checkpointPendingSignDispatch(dispatch.operationId(), dispatch.revision(), dispatch.fence())
                    .isEmpty());
        }
        clock.value = NOW.plus(LEASE.multipliedBy(2));
        try (FilesystemPkiStore store = open(root, clock)) {
            Workflow cleanup = store.claimSignStep(observation.operationId(), observation.revision(), LEASE).orElseThrow();
            assertEquals(InitialAttemptPhase.FAILED, cleanup.initialAttemptPhase());
            assertEquals(SignWorkflowStore.State.DISPATCHED, cleanup.state());
            assertTrue(cleanup.leaseUntil().isPresent());
            assertEquals(0, cleanup.failureCount());
            assertTrue(store.completeSignObservation(observation.operationId(), observation.revision(), observation.fence())
                    .isEmpty());
            assertTrue(store.completeSignObservation(cleanup.operationId(), cleanup.revision(), cleanup.fence()).isEmpty());
            assertEquals(List.of(cleanup.operationId()), due(store, clock.value.plus(LEASE)));
        }
    }

    @Test
    void elapsedLeaseWithoutReclaimStillAllowsFencedCheckpoints(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock();
        try (FilesystemPkiStore store = open(root, clock)) {
            Workflow dispatch = acceptedClaim(store, Mode.BOUNDED_OBSERVATION);
            clock.value = NOW.plus(LEASE);
            Workflow ready = store.checkpointPendingSignDispatch(dispatch.operationId(), dispatch.revision(), dispatch.fence())
                    .orElseThrow();
            Workflow observation = store.claimSignStep(ready.operationId(), ready.revision(), LEASE).orElseThrow();
            assertTrue(store.completeSignObservation(observation.operationId(), observation.revision(), observation.fence() - 1)
                    .isEmpty());
            clock.value = clock.value.plus(LEASE);
            Workflow complete = store.completeSignObservation(observation.operationId(), observation.revision(), observation.fence())
                    .orElseThrow();
            assertEquals(InitialAttemptPhase.COMPLETED, complete.initialAttemptPhase());
            assertEquals(observation.leaseUntil(), complete.leaseUntil());
        }
    }

    @Test
    void exceptionOutcomeSurvivesRetryTupleClearingCancellationRetirementAndReopen(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock();
        PkiId operation;
        try (FilesystemPkiStore store = open(root, clock)) {
            Workflow dispatch = acceptedClaim(store, Mode.BOUNDED_OBSERVATION);
            operation = dispatch.operationId();
            Workflow deferred = store.deferSignReconciliation(operation, dispatch.revision(), dispatch.fence(),
                    SignWorkflowStore.ReconciliationFailureClass.SUBMISSION_UNCERTAIN).orElseThrow();
            assertEquals(InitialAttemptPhase.FAILED, deferred.initialAttemptPhase());
            assertEquals(1, deferred.failureCount());
            assertTrue(due(store, NOW).isEmpty());
            clock.value = deferred.nextEligibleAt().orElseThrow();
            assertEquals(List.of(operation), due(store, clock.value));
            Workflow cleanup = store.claimSignStep(operation, deferred.revision(), LEASE).orElseThrow();
            assertEquals(InitialAttemptPhase.FAILED, cleanup.initialAttemptPhase());
            assertEquals(0, cleanup.failureCount());
            assertTrue(cleanup.reconciliationFailureClass().isEmpty());
            Workflow cancelling = store.requestSignCancellation(operation, cleanup.revision(), cleanup.fence()).orElseThrow();
            assertEquals(InitialAttemptPhase.FAILED, cancelling.initialAttemptPhase());
            Workflow terminal = store.transitionSign(operation, cancelling.revision(), cancelling.fence(),
                    SignWorkflowStore.State.CANCELLED, Optional.of("CANCELLED"), Optional.empty(), Optional.of(clock.value))
                    .orElseThrow();
            Workflow retired = store.retireSign(operation, terminal.revision(), terminal.fence()).orElseThrow();
            assertEquals(InitialAttemptPhase.FAILED, retired.initialAttemptPhase());
        }
        try (FilesystemPkiStore store = open(root, clock)) {
            Workflow retained = store.getSignWorkflow(operation).orElseThrow();
            assertEquals(SignWorkflowStore.State.RETIRED, retained.state());
            assertEquals(InitialAttemptPhase.FAILED, retained.initialAttemptPhase());
        }
    }

    @Test
    void terminalOutcomesCompleteUnfinishedBudgetAtomically(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock();
        try (FilesystemPkiStore store = open(root, clock)) {
            Workflow dispatch = acceptedClaim(store, Mode.BOUNDED_OBSERVATION);
            Workflow signed = store.transitionSign(dispatch.operationId(), dispatch.revision(), dispatch.fence(),
                    SignWorkflowStore.State.SUCCEEDED, Optional.of("SIGNED"),
                    Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 7 })), Optional.of(NOW)).orElseThrow();
            assertEquals(InitialAttemptPhase.COMPLETED, signed.initialAttemptPhase());
            Workflow intent = accept(store, Mode.BOUNDED_OBSERVATION);
            Workflow cancelled = store.requestSignCancellation(intent.operationId(), intent.revision(), intent.fence()).orElseThrow();
            assertEquals(SignWorkflowStore.State.CANCELLED, cancelled.state());
            assertEquals(InitialAttemptPhase.COMPLETED, cancelled.initialAttemptPhase());
            Workflow failedDispatch = acceptedClaim(store, Mode.BOUNDED_OBSERVATION);
            Workflow denied = store.transitionSign(failedDispatch.operationId(), failedDispatch.revision(), failedDispatch.fence(),
                    SignWorkflowStore.State.FAILED, Optional.of("DENIED"), Optional.empty(), Optional.of(NOW)).orElseThrow();
            assertEquals(InitialAttemptPhase.COMPLETED, denied.initialAttemptPhase());
        }
    }

    @Test
    void deadlineAdmissionExpiresInsteadOfPublishingReadiness(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock();
        try (FilesystemPkiStore store = open(root, clock)) {
            Workflow dispatch = acceptedClaim(store, Mode.BOUNDED_OBSERVATION);
            FilesystemPkiStore.installSignTransitionAdmissionObserver(() -> clock.value = dispatch.deadline());
            try {
                assertTrue(store.checkpointPendingSignDispatch(dispatch.operationId(), dispatch.revision(), dispatch.fence())
                        .isEmpty());
            } finally {
                FilesystemPkiStore.clearSignTransitionAdmissionObserver();
            }
            Workflow expired = store.getSignWorkflow(dispatch.operationId()).orElseThrow();
            assertEquals(SignWorkflowStore.State.EXPIRED, expired.state());
            assertEquals(InitialAttemptPhase.COMPLETED, expired.initialAttemptPhase());
            assertTrue(due(store, clock.value).isEmpty());
        }
    }

    @Test
    void immutableModeChangesCommitmentAndCannotPairWithOuterCommand(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock();
        try (FilesystemPkiStore store = open(root, clock)) {
            SignWorkflowStore.AcceptanceCommand bounded = command(store, Mode.BOUNDED_OBSERVATION);
            SignWorkflowStore.AcceptanceCommand normal = copyMode(bounded, Mode.NORMAL, Optional.empty());
            assertNotEquals(normal.commitment(), bounded.commitment());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(bounded));
            assertEquals(SignWorkflowStore.AcceptanceResult.CONFLICT, store.acceptSign(normal));
            assertEquals(Mode.BOUNDED_OBSERVATION, store.getSignWorkflow(bounded.operationId()).orElseThrow().mode());
            SignWorkflowStore.OuterCommand outer = new SignWorkflowStore.OuterCommand(DomainContinuationStore.Kind.CA,
                    "correlation", new EncodedObject(Encoding.BINARY, new byte[] { 1 }), "domain:v1:" + "1".repeat(64));
            assertThrows(IllegalArgumentException.class,
                    () -> copyMode(bounded, Mode.BOUNDED_OBSERVATION, Optional.of(outer)));
        }
    }

    @Test
    void ordinarySigningNeverUsesBoundedCheckpoints(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock();
        try (FilesystemPkiStore store = open(root, clock)) {
            Workflow dispatch = acceptedClaim(store, Mode.NORMAL);
            assertEquals(InitialAttemptPhase.NOT_APPLICABLE, dispatch.initialAttemptPhase());
            assertTrue(store.checkpointPendingSignDispatch(dispatch.operationId(), dispatch.revision(), dispatch.fence()).isEmpty());
            assertTrue(store.completeSignObservation(dispatch.operationId(), dispatch.revision(), dispatch.fence()).isEmpty());
            clock.value = NOW.plus(LEASE);
            Workflow retry = store.claimSignStep(dispatch.operationId(), dispatch.revision(), LEASE).orElseThrow();
            assertEquals(InitialAttemptPhase.NOT_APPLICABLE, retry.initialAttemptPhase());
        }
    }

    @Test
    void malformedModePhaseCombinationsAndUnknownCodesAreRejected(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock();
        try (FilesystemPkiStore store = open(root, clock)) {
            Workflow intent = accept(store, Mode.BOUNDED_OBSERVATION);
            assertThrows(IllegalArgumentException.class, () -> withPhase(intent, InitialAttemptPhase.NOT_APPLICABLE));
            assertThrows(IllegalArgumentException.class, () -> withPhase(intent, InitialAttemptPhase.COMPLETED));
            Workflow ordinary = accept(store, Mode.NORMAL);
            assertThrows(IllegalArgumentException.class, () -> withPhase(ordinary, InitialAttemptPhase.DISPATCH_OWED));
            Workflow dispatch = store.claimSignStep(intent.operationId(), intent.revision(), LEASE).orElseThrow();
            assertThrows(IllegalArgumentException.class, () -> withPhase(dispatch, InitialAttemptPhase.OBSERVATION_OWED));
            Workflow ready = store.checkpointPendingSignDispatch(dispatch.operationId(), dispatch.revision(), dispatch.fence())
                    .orElseThrow();
            assertThrows(IllegalArgumentException.class, () -> withPhase(ready, InitialAttemptPhase.OBSERVATION_CONSUMED));
            assertEquals(ready.mutableState(), FsCodec.decode(FsCodec.SIGN_MUTABLE_STATE,
                    FsCodec.encode(FsCodec.SIGN_MUTABLE_STATE, ready.mutableState())));
            assertThrows(IllegalArgumentException.class, () -> Mode.fromPersistentCode(0));
            assertThrows(IllegalArgumentException.class, () -> InitialAttemptPhase.fromPersistentCode(0));
            assertThrows(IllegalArgumentException.class,
                    () -> SignWorkflowStore.AcceptanceCommitment.parse("accept-sign:v1:" + "1".repeat(64)));
        }
    }

    @Test
    void unknownCheckpointDurabilityFencesFacadeAndRecoveryResolvesBothCrashBoundaries(@TempDir Path root)
            throws Exception {
        for (boolean observation : List.of(false, true)) {
            for (boolean durable : List.of(false, true)) {
                assertUnknownCheckpoint(root.resolve(observation + "-" + durable), observation, durable);
            }
        }
    }

    private static void assertUnknownCheckpoint(Path root, boolean observation, boolean durable) throws Exception {
        MutableClock clock = new MutableClock();
        ArmedWalFailure operations = new ArmedWalFailure();
        Workflow claimed;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock, 8, operations)) {
            Workflow dispatch = acceptedClaim(store, Mode.BOUNDED_OBSERVATION);
            if (observation) {
                Workflow ready = store.checkpointPendingSignDispatch(dispatch.operationId(), dispatch.revision(), dispatch.fence())
                        .orElseThrow();
                claimed = store.claimSignStep(ready.operationId(), ready.revision(), LEASE).orElseThrow();
            } else {
                claimed = dispatch;
            }
            // Conditional direct commit has one WAL force; it does not append an outcome acknowledgement.
            operations.arm(1, durable);
            PkiException failure = assertThrows(PkiException.class, () -> checkpoint(store, claimed, observation));
            assertEquals(Optional.of(PkiFailureReason.STORE_DURABILITY_UNCONFIRMED), failure.failureReason());
            assertTrue(operations.injected);
            assertEquals(0, operations.remaining.get());
            assertThrows(PkiException.class, () -> store.getSignWorkflow(claimed.operationId()));
            assertThrows(PkiException.class, () -> store.claimSignStep(claimed.operationId(), claimed.revision(), LEASE));
            assertThrows(SigningActiveWal.RecoveryRequiredException.class, store::close);
        }
        try (FilesystemPkiStore store = open(root, clock)) {
            Workflow recovered = store.getSignWorkflow(claimed.operationId()).orElseThrow();
            InitialAttemptPhase expected = durable
                    ? observation ? InitialAttemptPhase.COMPLETED : InitialAttemptPhase.OBSERVATION_OWED
                    : claimed.initialAttemptPhase();
            assertEquals(expected, recovered.initialAttemptPhase());
            if (durable && !observation) {
                assertEquals(List.of(claimed.operationId()), due(store, NOW));
            } else {
                assertTrue(due(store, NOW).isEmpty());
            }
        }
    }

    private static Optional<Workflow> checkpoint(FilesystemPkiStore store, Workflow claimed, boolean observation) {
        return observation ? store.completeSignObservation(claimed.operationId(), claimed.revision(), claimed.fence())
                : store.checkpointPendingSignDispatch(claimed.operationId(), claimed.revision(), claimed.fence());
    }

    private static Workflow withPhase(Workflow workflow, InitialAttemptPhase phase) {
        SignWorkflowStore.MutableState state = workflow.mutableState();
        return new Workflow(workflow.envelope(), new SignWorkflowStore.MutableState(state.operationId(), state.state(),
                state.revision(), state.fence(), state.leaseUntil(), state.downstreamOperationId(), state.detailCode(),
                state.result(), state.providerUpdatedAt(), state.failureCount(), state.nextEligibleAt(),
                state.reconciliationFailureClass(), phase, zeroecho.pki.spi.store.SignWorkflowStore.Stage.SINGLE, java.util.Optional.empty()));
    }

    private static Workflow accept(FilesystemPkiStore store, Mode mode) throws IOException {
        SignWorkflowStore.AcceptanceCommand command = command(store, mode);
        assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(command));
        return store.getSignWorkflow(command.operationId()).orElseThrow();
    }

    private static Workflow acceptedClaim(FilesystemPkiStore store, Mode mode) throws IOException {
        Workflow intent = accept(store, mode);
        return store.claimSignStep(intent.operationId(), intent.revision(), LEASE).orElseThrow();
    }

    private static SignWorkflowStore.AcceptanceCommand command(FilesystemPkiStore store, Mode mode) throws IOException {
        String namespace = store.signingNamespace() + ".test-signer";
        PkiId operation = SigningSubmissionId.create(namespace, NOW, new SecureRandom()).id();
        DurableContentReference candidate = PkiTestRuntime.operationReference(store.stagedContent(), Encoding.BINARY,
                new byte[] { 1, 2, 3 });
        return new SignWorkflowStore.AcceptanceCommand(operation, namespace,
                new SigningProvider.ConfigurationCommitment(new byte[32]),
                new AccessContext(new Principal("TEST", "actor"), new Purpose("SIGN"), Optional.empty(), Optional.empty()),
                new KeyRef("test-key"), operation, "SHA256withRSA", Encoding.BINARY, NOW, NOW.plusSeconds(60),
                candidate, Optional.empty(), mode, java.util.Optional.empty());
    }

    private static SignWorkflowStore.AcceptanceCommand copyMode(SignWorkflowStore.AcceptanceCommand command,
            Mode mode, Optional<SignWorkflowStore.OuterCommand> outer) {
        return new SignWorkflowStore.AcceptanceCommand(command.operationId(), command.providerNamespace(),
                command.providerConfigurationCommitment(), command.accessContext(), command.keyRef(),
                command.fairnessAuthorityId(), command.algorithmId(), command.signatureEncoding(), command.createdAt(),
                command.deadline(), command.candidate(), outer, mode, java.util.Optional.empty());
    }

    private static List<PkiId> due(FilesystemPkiStore store, Instant time) {
        return store.selectDueSignWorkflows(time, 8).stream().map(Workflow::operationId).toList();
    }

    private static FilesystemPkiStore open(Path root, Clock clock) {
        return FilesystemPkiStoreTestAccess.open(root, 8, clock);
    }

    private static final class MutableClock extends Clock {
        private Instant value = NOW;
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return value; }
    }

    private static final class ArmedWalFailure implements SigningActiveWal.Operations {
        private final AtomicInteger remaining = new AtomicInteger();
        private boolean durableBeforeFailure;
        private boolean injected;

        private void arm(int forceOrdinal, boolean durable) {
            durableBeforeFailure = durable;
            remaining.set(forceOrdinal);
        }
        @Override public boolean exists(Path path) { return Files.exists(path, LinkOption.NOFOLLOW_LINKS); }
        @Override public boolean isRegularFile(Path path) { return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS); }
        @Override public SigningActiveWal.WalChannel createNew(Path path) throws IOException {
            return wrap(FileChannel.open(path, Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.READ,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)));
        }
        @Override public SigningActiveWal.WalChannel openExisting(Path path) throws IOException {
            return wrap(FileChannel.open(path, Set.of(StandardOpenOption.READ, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)));
        }
        @Override public void forceDirectory(Path directory) throws IOException { SigningFormatSupport.forceDirectory(directory); }
        private SigningActiveWal.WalChannel wrap(FileChannel channel) throws IOException {
            long initialLength = channel.size();
            return new SigningActiveWal.WalChannel() {
                private long durableLength = initialLength;
                @Override public int read(ByteBuffer target) throws IOException { return channel.read(target); }
                @Override public int write(ByteBuffer source) throws IOException { return channel.write(source); }
                @Override public long position() throws IOException { return channel.position(); }
                @Override public SigningActiveWal.WalChannel position(long value) throws IOException { channel.position(value); return this; }
                @Override public long size() throws IOException { return channel.size(); }
                @Override public SigningActiveWal.WalChannel truncate(long size) throws IOException { channel.truncate(size); return this; }
                @Override public boolean isOpen() { return channel.isOpen(); }
                @Override public void close() throws IOException { channel.close(); }
                @Override public void force(boolean metadata) throws IOException {
                    if (remaining.get() > 0 && remaining.decrementAndGet() == 0) {
                        injected = true;
                        if (!durableBeforeFailure) channel.truncate(durableLength);
                        channel.force(metadata);
                        throw new IOException("Injected signing checkpoint force failure");
                    }
                    channel.force(metadata);
                    durableLength = channel.size();
                }
            };
        }
    }
}
