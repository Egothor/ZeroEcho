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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.StandardOpenOption;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.application.SigningExecutionEvidence;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.AuditEvidenceFeed;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.IntermediateCreationFixture;
import zeroecho.pki.testkit.PkiTestRuntime;

final class FilesystemSigningEvidenceTest {
    private static final Instant NOW = IntermediateCreationFixture.NOW;
    private static final Duration TTL = Duration.ofMinutes(1);
    private static final Principal OWNER = new Principal("TEST", "owner");

    @Test void disabledAuditHasNoLogAndRetainedTerminalRecoverySurvivesPurge(@TempDir Path root) throws Exception {
        assertFalse(FsPkiStoreOptions.defaults().signingEvidenceAudit());
        for (SignWorkflowStore.State state : List.of(SignWorkflowStore.State.SUCCEEDED, SignWorkflowStore.State.FAILED,
                SignWorkflowStore.State.CANCELLED, SignWorkflowStore.State.EXPIRED)) {
            Path directory = root.resolve(state.name());
            MutableClock clock = new MutableClock();
            SignWorkflowStore.AcceptanceCommand accepted;
            try (FilesystemPkiStore store = open(directory, false, clock)) {
                assertFalse(store.supportsSigningEvidenceFeed());
                assertThrows(UnsupportedOperationException.class, () -> store.openSigningEvidenceFeed(-1));
                accepted = command(store, OWNER);
                SignWorkflowStore.Workflow terminal = terminal(store, accepted, state, clock, Optional.of(NOW));
                if (state != SignWorkflowStore.State.EXPIRED) {
                    assertEquals(SignWorkflowStore.State.RETIRED,
                            store.retireSign(terminal.operationId(), terminal.revision(), terminal.fence()).orElseThrow().state());
                }
                try (MetadataSnapshot snapshot = store.metadataStore().snapshot()) {
                    assertTrue(snapshot.get(new MetadataKey(FilesystemPkiStore.SIGNING_EVIDENCE_NAMESPACE, "head")).isEmpty());
                }
            }
            try (FilesystemPkiStore store = open(directory, true, clock)) {
                List<AuditEvidenceFeed.Entry> entries = entries(store);
                assertEquals(1, entries.size());
                assertEvidence(entries.getFirst(), accepted, switch (state) {
                    case SUCCEEDED -> SigningExecutionEvidence.Outcome.SIGNED;
                    case FAILED -> SigningExecutionEvidence.Outcome.FAILED;
                    case CANCELLED -> SigningExecutionEvidence.Outcome.CANCELLED;
                    case EXPIRED -> SigningExecutionEvidence.Outcome.EXPIRED;
                    default -> throw new AssertionError(state);
                });
                clock.now = NOW.plus(store.signingHorizon()).plusSeconds(1);
                assertEquals(1, store.purgeExpiredSignRecords());
                assertTrue(store.getSignWorkflow(accepted.operationId()).isEmpty());
                assertEquals(1, entries(store).size());
            }
            try (FilesystemPkiStore store = open(directory, true, clock)) {
                assertEquals(1, entries(store).size());
            }
        }
    }

    @Test void enabledParentEvidenceUsesProviderTimeAndFallbackWithoutDuplicateRetirementEntries(@TempDir Path root) throws Exception {
        for (boolean providerTime : new boolean[] {false, true}) {
            try (FilesystemPkiStore store = open(root.resolve(Boolean.toString(providerTime)), true, new MutableClock())) {
                SignWorkflowStore.AcceptanceCommand command = command(store, OWNER);
                Instant observed = NOW.minusSeconds(2);
                SignWorkflowStore.Workflow terminal = terminal(store, command, SignWorkflowStore.State.FAILED,
                        new MutableClock(), providerTime ? Optional.of(observed) : Optional.empty());
                assertEvidence(entries(store).getFirst(), command, SigningExecutionEvidence.Outcome.FAILED);
                assertEquals(providerTime ? observed : NOW, entries(store).getFirst().recordedAt());
                store.retireSign(terminal.operationId(), terminal.revision(), terminal.fence()).orElseThrow();
                assertEquals(1, entries(store).size());
            }
        }
    }

    @Test void proofEvidenceIsIndependentOfActiveThenCancelledParentAndSurvivesRetirement(@TempDir Path root) throws Exception {
        IntermediateCreationFixture fixture = new IntermediateCreationFixture();
        PkiId parent;
        PkiId proof;
        String fingerprint;
        try (FilesystemPkiStore store = open(root, true, new MutableClock())) {
            fixture.initialize(store, 1);
            DomainSigningRequest request = fixture.preparer(store).prepare(IntermediateCreationFixture.ACCESS,
                    fixture.command("CN=Audit Child"), fixture.submission(store), TTL, CancellationSignal.NONE);
            parent = request.operationId();
            proof = request.proofStep().orElseThrow().operationId();
            fixture.accept(store, request);
            fixture.checkpointProof(store, parent);
            SignWorkflowStore.Workflow verifying = store.getSignWorkflow(parent).orElseThrow();
            fingerprint = verifying.fingerprint();
            assertEquals(SignWorkflowStore.Stage.CA_PROOF_VERIFYING, verifying.stage());
            List<AuditEvidenceFeed.Entry> proofEntries = entries(store);
            assertEquals(1, proofEntries.size());
            assertEquals(proof, proofEntries.getFirst().objectId());
            assertEquals(SigningExecutionEvidence.Outcome.SIGNED, decode(proofEntries.getFirst()).outcome());
            assertEquals(Optional.of("SIGNED"), decode(proofEntries.getFirst()).detailCode());
            assertEquals(fingerprint, decode(proofEntries.getFirst()).fingerprint());
            SignWorkflowStore.Workflow cancelled = store.requestSignCancellation(parent, verifying.revision(), verifying.fence()).orElseThrow();
            assertEquals(SignWorkflowStore.State.CANCELLED, cancelled.state());
            assertEquals(List.of(proof, parent), entries(store).stream().map(AuditEvidenceFeed.Entry::objectId).toList());
            assertEquals(SigningExecutionEvidence.Outcome.CANCELLED, decode(entries(store).getLast()).outcome());
            DomainContinuationStore.Record outer = store.getDomainContinuation(parent).orElseThrow();
            store.transitionDomainContinuation(parent, outer.revision(), DomainContinuationStore.State.FAILED,
                    Optional.empty(), Optional.of("CANCELLED")).orElseThrow();
            store.retireSign(parent, cancelled.revision(), cancelled.fence()).orElseThrow();
            assertEquals(2, entries(store).size());
            assertEquals(0, fixture.provider.dispatches);
        }
        try (FilesystemPkiStore store = open(root, true, new MutableClock())) {
            List<AuditEvidenceFeed.Entry> entries = entries(store);
            assertEquals(List.of(proof, parent), entries.stream().map(AuditEvidenceFeed.Entry::objectId).toList());
            assertTrue(entries.stream().allMatch(entry -> decode(entry).fingerprint().equals(fingerprint)));
            assertEquals(SignWorkflowStore.State.RETIRED, store.getSignWorkflow(parent).orElseThrow().state());
        }
    }

    @Test void validLargePrincipalAndUnrepresentableProviderTimeCannotChangePrimaryFailure(@TempDir Path root) throws Exception {
        for (boolean hugePrincipal : new boolean[] {true, false}) {
            Path directory = root.resolve(Boolean.toString(hugePrincipal));
            PkiId operation;
            try (FilesystemPkiStore store = open(directory, true, new MutableClock())) {
                Principal owner = hugePrincipal ? new Principal("TEST", "x".repeat(1_048_576)) : OWNER;
                SignWorkflowStore.AcceptanceCommand command = command(store, owner);
                operation = command.operationId();
                SignWorkflowStore.Workflow failed = terminal(store, command, SignWorkflowStore.State.FAILED,
                        new MutableClock(), Optional.of(hugePrincipal ? NOW : Instant.MAX));
                assertEquals(SignWorkflowStore.State.FAILED, failed.state());
                assertEquals(owner, failed.owner());
                assertEquals(Optional.of(hugePrincipal ? NOW : Instant.MAX), failed.providerUpdatedAt());
                assertTrue(entries(store).isEmpty());
                store.retireSign(operation, failed.revision(), failed.fence()).orElseThrow();
            }
            try (FilesystemPkiStore store = open(directory, true, new MutableClock())) {
                assertEquals(SignWorkflowStore.State.RETIRED, store.getSignWorkflow(operation).orElseThrow().state());
                assertTrue(entries(store).isEmpty());
            }
        }
    }

    @Test void failedProofCanRetainInstantMaxWithoutReinterpretingConfirmedParentOutcome(@TempDir Path root) throws Exception {
        IntermediateCreationFixture fixture = new IntermediateCreationFixture();
        try (FilesystemPkiStore store = open(root, true, new MutableClock())) {
            fixture.initialize(store, 1);
            DomainSigningRequest request = fixture.preparer(store).prepare(IntermediateCreationFixture.ACCESS,
                    fixture.command("CN=Audit Time"), fixture.submission(store), TTL, CancellationSignal.NONE);
            fixture.accept(store, request);
            SignWorkflowStore.Workflow claimed = store.claimSignStep(request.operationId(), 0, Duration.ofSeconds(10)).orElseThrow();
            SignWorkflowStore.CaSubjectProofOutcome proof = new SignWorkflowStore.CaSubjectProofOutcome(
                    SigningProvider.ObservationState.FAILED, SigningProvider.DetailCode.DENIED, Optional.of(Instant.MAX));
            SignWorkflowStore.Workflow failed = store.checkpointCaProof(request.operationId(), claimed.revision(), claimed.fence(),
                    proof, Optional.empty()).orElseThrow();
            assertEquals(SignWorkflowStore.State.FAILED, failed.state());
            assertEquals(Optional.of(proof), failed.proofOutcome());
            assertTrue(entries(store).isEmpty());
        }
    }

    @Test void nonterminalProofDispositionsCannotBecomeRetainedAuditEvidence() {
        for (SigningProvider.ObservationState state : List.of(SigningProvider.ObservationState.PENDING,
                SigningProvider.ObservationState.RETRYABLE_UNKNOWN)) {
            assertThrows(IllegalArgumentException.class, () -> new SignWorkflowStore.CaSubjectProofOutcome(state,
                    SigningProvider.DetailCode.PENDING, Optional.of(NOW)));
        }
    }

    @Test void primaryUncertaintyAndAuditUncertaintyKeepDistinctOutcomesAcrossReopen(@TempDir Path root) throws Exception {
        for (boolean primaryFailure : new boolean[] {true, false}) {
            for (int forceOrdinal : primaryFailure ? new int[] {1} : new int[] {2, 3}) {
                for (boolean durable : new boolean[] {true, false}) {
                    Path directory = root.resolve(forceOrdinal + "-" + durable);
                    ArmedWalFailure operations = new ArmedWalFailure();
                    SignWorkflowStore.Workflow claim;
                    try (FilesystemPkiStore store = faultStore(directory, new MutableClock(), operations)) {
                        SignWorkflowStore.AcceptanceCommand command = command(store, OWNER);
                        assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(command));
                        claim = store.claimSignStep(command.operationId(), 0, Duration.ofSeconds(10)).orElseThrow();
                        // One primary DIRECT_COMMIT, then the audit transaction's separate ISSUE and COMMIT.
                        operations.arm(forceOrdinal, durable);
                        if (primaryFailure) {
                            zeroecho.pki.api.PkiException failure = assertThrows(zeroecho.pki.api.PkiException.class,
                                    () -> fail(store, claim, Optional.of(NOW)));
                            assertEquals(Optional.of(zeroecho.pki.api.PkiFailureReason.STORE_DURABILITY_UNCONFIRMED), failure.failureReason());
                        } else {
                            assertEquals(SignWorkflowStore.State.FAILED, fail(store, claim, Optional.of(NOW)).state());
                        }
                        assertTrue(operations.injected);
                        assertEquals(0, operations.remaining.get());
                        assertTrue(store.metadataStore().firstRecoveryFailure() != null);
                        assertThrows(IllegalStateException.class, () -> store.metadataStore().snapshot());
                        assertThrows(SigningActiveWal.RecoveryRequiredException.class, store::close);
                    }
                    try (FilesystemPkiStore store = open(directory, false, new MutableClock())) {
                        SignWorkflowStore.State expected = primaryFailure && !durable
                                ? SignWorkflowStore.State.DISPATCHED : SignWorkflowStore.State.FAILED;
                        assertEquals(expected, store.getSignWorkflow(claim.operationId()).orElseThrow().state());
                        try (MetadataSnapshot snapshot = store.metadataStore().snapshot();
                                MetadataSnapshot.Record head = snapshot.get(new MetadataKey(FilesystemPkiStore.SIGNING_EVIDENCE_NAMESPACE,
                                        "head")).orElse(null)) {
                            assertEquals(forceOrdinal == 3 && durable, head != null,
                                    "Only a durable audit COMMIT can publish the evidence head before reconciliation");
                        }
                    }
                    try (FilesystemPkiStore store = open(directory, true, new MutableClock())) {
                        List<AuditEvidenceFeed.Entry> recovered = entries(store);
                        assertEquals(primaryFailure && !durable ? 0 : 1, recovered.size());
                        if (!recovered.isEmpty()) {
                            assertEquals(claim.operationId(), recovered.getFirst().objectId());
                            assertEquals(SigningExecutionEvidence.Outcome.FAILED, decode(recovered.getFirst()).outcome());
                        }
                    }
                    try (FilesystemPkiStore store = open(directory, true, new MutableClock())) {
                        assertEquals(primaryFailure && !durable ? 0 : 1, entries(store).size());
                    }
                }
            }
        }
    }

    @Test void uncertainParentAuditStopsRemainingProofAppendAndReopenRestoresBoth(@TempDir Path root) throws Exception {
        IntermediateCreationFixture fixture = new IntermediateCreationFixture();
        ArmedWalFailure operations = new ArmedWalFailure();
        PkiId parent;
        PkiId proof;
        java.util.concurrent.atomic.AtomicInteger warnings = new java.util.concurrent.atomic.AtomicInteger();
        java.util.logging.Logger logger = java.util.logging.Logger.getLogger(FilesystemPkiStore.class.getName());
        java.util.logging.Handler handler = new java.util.logging.Handler() {
            @Override public void publish(java.util.logging.LogRecord record) {
                if (record.getMessage().equals("Signing evidence log append deferred: code=EVIDENCE_APPEND_UNCONFIRMED")) {
                    warnings.incrementAndGet();
                }
            }
            @Override public void flush() { }
            @Override public void close() { }
        };
        logger.addHandler(handler);
        try (FilesystemPkiStore store = faultStore(root, new MutableClock(), operations)) {
            fixture.initialize(store, 1);
            DomainSigningRequest request = fixture.preparer(store).prepare(IntermediateCreationFixture.ACCESS,
                    fixture.command("CN=Fault Audit"), fixture.submission(store), TTL, CancellationSignal.NONE);
            parent = request.operationId();
            proof = request.proofStep().orElseThrow().operationId();
            fixture.accept(store, request);
            SignWorkflowStore.Workflow claim = store.claimSignStep(parent, 0, Duration.ofSeconds(10)).orElseThrow();
            operations.arm(2, false); // Confirm the parent/proof checkpoint, then fail audit transaction issuance.
            SignWorkflowStore.Workflow failed = store.checkpointCaProof(parent, claim.revision(), claim.fence(),
                    new SignWorkflowStore.CaSubjectProofOutcome(SigningProvider.ObservationState.FAILED,
                            SigningProvider.DetailCode.DENIED, Optional.of(NOW)), Optional.empty()).orElseThrow();
            assertEquals(SignWorkflowStore.State.FAILED, failed.state());
            assertEquals(SigningProvider.ObservationState.FAILED, failed.proofOutcome().orElseThrow().disposition());
            assertEquals(1, warnings.get(), "A failed parent append must stop the remaining proof append");
            assertTrue(operations.injected);
            assertTrue(store.metadataStore().firstRecoveryFailure() != null);
            assertThrows(SigningActiveWal.RecoveryRequiredException.class, store::close);
        } finally { logger.removeHandler(handler); }
        try (FilesystemPkiStore store = open(root, true, new MutableClock())) {
            List<AuditEvidenceFeed.Entry> recovered = entries(store);
            assertEquals(List.of(parent, proof), recovered.stream().map(AuditEvidenceFeed.Entry::objectId).toList());
            assertTrue(recovered.stream().allMatch(entry -> decode(entry).outcome() == SigningExecutionEvidence.Outcome.FAILED));
        }
        try (FilesystemPkiStore store = open(root, true, new MutableClock())) {
            assertEquals(2, entries(store).size());
        }
    }

    @Test void concurrentlyConfirmedCallbackSurvivesAnotherCallbacksAuditFence(@TempDir Path root) throws Exception {
        AuditBarrierClock clock = new AuditBarrierClock();
        ArmedWalFailure operations = new ArmedWalFailure();
        PkiId firstId;
        PkiId secondId;
        try (FilesystemPkiStore store = faultStore(root, clock, operations)) {
            SignWorkflowStore.AcceptanceCommand first = command(store, OWNER);
            SignWorkflowStore.AcceptanceCommand second = command(store, OWNER);
            firstId = first.operationId();
            secondId = second.operationId();
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(first));
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(second));
            SignWorkflowStore.Workflow firstClaim = store.claimSignStep(firstId, 0, Duration.ofSeconds(10)).orElseThrow();
            SignWorkflowStore.Workflow secondClaim = store.claimSignStep(secondId, 0, Duration.ofSeconds(10)).orElseThrow();
            java.util.concurrent.FutureTask<SignWorkflowStore.Workflow> secondCallback = new java.util.concurrent.FutureTask<>(
                    () -> fail(store, secondClaim, Optional.empty()));
            Thread thread = new Thread(secondCallback, "confirmed-audit-callback");
            clock.target = thread;
            operations.afterNextForce = () -> clock.armed = true;
            thread.start();
            try {
                assertTrue(clock.entered.await(10, java.util.concurrent.TimeUnit.SECONDS));
                // The barrier is the fallback audit timestamp, after this primary commit and lock release.
                assertEquals(SignWorkflowStore.State.FAILED, store.getSignWorkflow(secondId).orElseThrow().state());
                operations.arm(2, false);
                assertEquals(SignWorkflowStore.State.FAILED, fail(store, firstClaim, Optional.of(NOW)).state());
                assertTrue(store.metadataStore().firstRecoveryFailure() != null);
                clock.release.countDown();
                assertEquals(SignWorkflowStore.State.FAILED, secondCallback.get(10, java.util.concurrent.TimeUnit.SECONDS).state());
                assertThrows(IllegalStateException.class, () -> store.metadataStore().snapshot());
                assertThrows(SigningActiveWal.RecoveryRequiredException.class, store::close);
            } finally {
                clock.release.countDown();
                thread.join(10_000);
                assertFalse(thread.isAlive());
            }
        }
        try (FilesystemPkiStore store = open(root, true, new MutableClock())) {
            assertEquals(java.util.Set.of(firstId, secondId), entries(store).stream().map(AuditEvidenceFeed.Entry::objectId)
                    .collect(java.util.stream.Collectors.toSet()));
            assertEquals(2, entries(store).size());
        }
    }

    @Test void unrelatedIllegalStateFromOptionalAuditIsNotHiddenWithoutRecoveryEvidence(@TempDir Path root) throws Exception {
        AuditBarrierClock clock = new AuditBarrierClock();
        ArmedWalFailure operations = new ArmedWalFailure();
        try (FilesystemPkiStore store = faultStore(root, clock, operations)) {
            SignWorkflowStore.AcceptanceCommand command = command(store, OWNER);
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(command));
            SignWorkflowStore.Workflow claim = store.claimSignStep(command.operationId(), 0, Duration.ofSeconds(10)).orElseThrow();
            IllegalStateException injected = new IllegalStateException("Controlled audit clock failure");
            clock.target = Thread.currentThread();
            clock.failure = injected;
            operations.afterNextForce = () -> clock.armed = true;
            try {
                org.junit.jupiter.api.Assertions.assertSame(injected,
                        assertThrows(IllegalStateException.class, () -> fail(store, claim, Optional.empty())));
            } finally { clock.armed = false; }
            org.junit.jupiter.api.Assertions.assertNull(store.metadataStore().firstRecoveryFailure());
            assertEquals(SignWorkflowStore.State.FAILED, store.getSignWorkflow(command.operationId()).orElseThrow().state());
            assertTrue(entries(store).isEmpty());
        }
    }

    private static SignWorkflowStore.Workflow fail(FilesystemPkiStore store, SignWorkflowStore.Workflow claim,
            Optional<Instant> time) {
        return store.transitionSign(claim.operationId(), claim.revision(), claim.fence(), SignWorkflowStore.State.FAILED,
                Optional.of("DENIED"), Optional.empty(), time).orElseThrow();
    }

    private static FilesystemPkiStore faultStore(Path root, Clock clock, ArmedWalFailure operations) {
        return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults().withSigningEvidenceAudit(true), clock, 8, operations);
    }

    private static final class AuditBarrierClock extends Clock {
        private volatile Thread target;
        private volatile boolean armed;
        private IllegalStateException failure;
        private final java.util.concurrent.CountDownLatch entered = new java.util.concurrent.CountDownLatch(1);
        private final java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() {
            if (armed && Thread.currentThread() == target) {
                if (failure != null) { throw failure; }
                entered.countDown();
                try { assertTrue(release.await(10, java.util.concurrent.TimeUnit.SECONDS)); }
                catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new AssertionError(interrupted);
                }
            }
            return NOW;
        }
    }

    private static SignWorkflowStore.AcceptanceCommand command(FilesystemPkiStore store, Principal owner) throws Exception {
        String namespace = store.signingNamespace() + ".audit-test";
        PkiId operation = SigningSubmissionId.create(namespace, NOW, new SecureRandom()).id();
        return new SignWorkflowStore.AcceptanceCommand(operation, namespace, new SigningProvider.ConfigurationCommitment(new byte[32]),
                new AccessContext(owner, new Purpose("SIGN"), Optional.empty(), Optional.empty()), new KeyRef("audit-key"),
                new PkiId("audit-authority"), "SHA256withRSA", Encoding.BINARY, NOW, NOW.plus(TTL),
                PkiTestRuntime.operationReference(store.stagedContent(), Encoding.BINARY, new byte[] {1, 2, 3}),
                Optional.empty(), SignWorkflowStore.Mode.NORMAL, Optional.empty());
    }

    private static SignWorkflowStore.Workflow terminal(FilesystemPkiStore store, SignWorkflowStore.AcceptanceCommand command,
            SignWorkflowStore.State state, MutableClock clock, Optional<Instant> providerTime) {
        assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(command));
        if (state == SignWorkflowStore.State.CANCELLED) {
            return store.requestSignCancellation(command.operationId(), 0, 0).orElseThrow();
        }
        if (state == SignWorkflowStore.State.EXPIRED) {
            clock.now = command.deadline();
            return store.getSignWorkflow(command.operationId()).orElseThrow();
        }
        SignWorkflowStore.Workflow claim = store.claimSignStep(command.operationId(), 0, Duration.ofSeconds(10)).orElseThrow();
        return store.transitionSign(command.operationId(), claim.revision(), claim.fence(), state, Optional.of(
                state == SignWorkflowStore.State.SUCCEEDED ? "SIGNED" : "DENIED"),
                state == SignWorkflowStore.State.SUCCEEDED ? Optional.of(new EncodedObject(Encoding.BINARY, new byte[] {9})) : Optional.empty(),
                providerTime).orElseThrow();
    }

    private static void assertEvidence(AuditEvidenceFeed.Entry entry, SignWorkflowStore.AcceptanceCommand command,
            SigningExecutionEvidence.Outcome outcome) {
        SigningExecutionEvidence evidence = decode(entry);
        assertEquals(command.operationId(), entry.objectId());
        assertEquals(command.providerNamespace(), evidence.namespace());
        assertEquals(command.commitment().encoded(), evidence.fingerprint());
        assertEquals(command.accessContext().principal().type(), evidence.ownerType());
        assertEquals(command.accessContext().principal().name(), evidence.ownerId());
        assertEquals(outcome, evidence.outcome());
    }

    private static SigningExecutionEvidence decode(AuditEvidenceFeed.Entry entry) {
        return SigningExecutionEvidence.decode(entry.evidence()).orElseThrow();
    }

    private static List<AuditEvidenceFeed.Entry> entries(FilesystemPkiStore store) throws Exception {
        List<AuditEvidenceFeed.Entry> result = new ArrayList<>();
        try (AuditEvidenceFeed feed = store.openSigningEvidenceFeed(-1)) {
            while (feed.next(CancellationSignal.NONE)) { result.add(feed.current()); }
            assertEquals(result.size(), feed.highWatermark());
        }
        return List.copyOf(result);
    }

    private static FilesystemPkiStore open(Path root, boolean enabled, Clock clock) {
        return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults().withSigningEvidenceAudit(enabled), clock);
    }

    private static final class MutableClock extends Clock {
        private Instant now = NOW;
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
    private static final class ArmedWalFailure implements SigningActiveWal.Operations {
        private final AtomicInteger remaining = new AtomicInteger();
        private boolean durableBeforeFailure;
        private boolean injected;
        private volatile Runnable afterNextForce;

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
                    Runnable observer = afterNextForce;
                    afterNextForce = null;
                    if (observer != null) { observer.run(); }
                }
            };
        }
    }
}
