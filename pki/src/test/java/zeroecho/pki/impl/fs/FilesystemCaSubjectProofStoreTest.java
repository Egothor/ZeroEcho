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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import zeroecho.pki.spi.store.StagedContentStore;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.util.Set;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.application.PkiSessionConfiguration.SigningKeyGroup;
import zeroecho.pki.impl.core.continuation.SigningOuterTerminalDriver;
import zeroecho.pki.spi.crypto.SigningInputCapabilities;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.pki.application.PkiSessionConfiguration.SigningCoordinatorLimits;
import zeroecho.pki.application.PkiSessionConfiguration.SigningLanePool;
import zeroecho.pki.application.PkiSessionConfiguration.SigningTopology;
import zeroecho.pki.impl.core.signing.SigningReactor;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProviderExecutor;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.impl.core.continuation.CaSubjectProofBindings;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.impl.core.continuation.CaSigningIntent;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.impl.core.continuation.IntermediateSigningCommand;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofChallenge;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofCommand;
import zeroecho.pki.spi.crypto.SigningProvider.DetailCode;
import zeroecho.pki.spi.crypto.SigningProvider.ObservationState;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.SignWorkflowStore.CaSubjectProofOutcome;
import zeroecho.pki.spi.store.SignWorkflowStore.Workflow;
import zeroecho.pki.testkit.IntermediateCreationFixture;
import zeroecho.pki.testkit.PkiTestRuntime;

/** Composite storage, two-step reactor execution and recovery evidence. */
final class FilesystemCaSubjectProofStoreTest {
    private static final Duration LEASE = Duration.ofSeconds(5);

    @Test
    void oneAcceptanceOwnsBothCandidatesAndReopensVerifierBeforeCertificateReadiness(@TempDir Path root)
            throws Exception {
        IntermediateCreationFixture fixture = new IntermediateCreationFixture();
        Prepared prepared;
        Workflow verifying;
        try (FilesystemPkiStore store = open(root)) {
            fixture.initialize(store, 2);
            prepared = prepare(store, fixture);
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(prepared.command()));
            assertEquals(SignWorkflowStore.AcceptanceResult.ATTACHED_EXISTING, store.acceptSign(prepared.command()));
            Workflow accepted = store.getSignWorkflow(prepared.command().operationId()).orElseThrow();
            assertEquals(SignWorkflowStore.Stage.CA_PROOF, accepted.stage());
            assertEquals(IntermediateCreationFixture.CHILD_KEY, dueKey(store, accepted.operationId()));
            assertEquals(List.of(prepared.command().candidate(), prepared.command().proofStep().orElseThrow().challenge()),
                    accepted.candidates());
            assertTrue(store.getSignWorkflow(prepared.command().proofStep().orElseThrow().operationId()).isEmpty());
            Workflow claimed = claim(store, accepted);
            assertEquals(prepared.command().proofStep().orElseThrow().operationId(), claimed.downstreamOperationId().orElseThrow());
            assertThrows(IllegalArgumentException.class, () -> store.transitionSign(claimed.operationId(), claimed.revision(), claimed.fence(),
                    SignWorkflowStore.State.SUCCEEDED, Optional.of("SIGNED"), Optional.of(prepared.signature()),
                    Optional.of(IntermediateCreationFixture.NOW)));
            verifying = store.checkpointCaProof(claimed.operationId(), claimed.revision(), claimed.fence(),
                    signed(), Optional.of(prepared.signature())).orElseThrow();
            assertEquals(SignWorkflowStore.Stage.CA_PROOF_VERIFYING, verifying.stage());
            assertEquals(SignWorkflowStore.State.DISPATCHED, verifying.state());
            assertSignature(prepared.signature(), verifying.result().orElseThrow());
            assertTrue(verifying.leaseUntil().isEmpty());
            assertTrue(store.completeCaProofVerification(verifying.operationId(), verifying.revision(), verifying.fence()).isEmpty());
        }
        try (FilesystemPkiStore store = open(root)) {
            Workflow recovered = store.getSignWorkflow(verifying.operationId()).orElseThrow();
            assertArrayEquals(FsCodec.encode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE, verifying.envelope()),
                    FsCodec.encode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE, recovered.envelope()));
            assertArrayEquals(FsCodec.encode(FsCodec.SIGN_MUTABLE_STATE, verifying.mutableState()),
                    FsCodec.encode(FsCodec.SIGN_MUTABLE_STATE, recovered.mutableState()));
            assertSignature(verifying.result().orElseThrow(), recovered.result().orElseThrow());
            assertEquals(IntermediateCreationFixture.CHILD_KEY, dueKey(store, recovered.operationId()));
            Workflow verifier = claim(store, recovered);
            Workflow renewed = store.renewSignStep(verifier.operationId(), verifier.revision(), verifier.fence(), LEASE).orElseThrow();
            assertSignature(verifying.result().orElseThrow(), renewed.result().orElseThrow());
            Workflow ready = store.completeCaProofVerification(renewed.operationId(), renewed.revision(), renewed.fence()).orElseThrow();
            assertEquals(SignWorkflowStore.Stage.CA_CERTIFICATE_READY, ready.stage());
            assertTrue(ready.result().isEmpty());
            assertTrue(ready.downstreamOperationId().isEmpty());
            assertTrue(ready.leaseUntil().isEmpty());
            assertEquals(verifying.proofOutcome(), ready.proofOutcome());
            assertEquals(IntermediateCreationFixture.PARENT_KEY, dueKey(store, ready.operationId()));
            Workflow certificate = claim(store, ready);
            assertEquals(SignWorkflowStore.Stage.CA_CERTIFICATE, certificate.stage());
            assertEquals(Optional.of(certificate.operationId()), certificate.downstreamOperationId());
            assertEquals(IntermediateCreationFixture.PARENT_KEY, certificate.envelope().keyRef());
            assertEquals(0, fixture.provider.dispatches);
        }
    }

    @Test
    void cancellingProofSuccessCannotAdvanceAndRejectsOldFence(@TempDir Path root) throws Exception {
        IntermediateCreationFixture fixture = new IntermediateCreationFixture();
        try (FilesystemPkiStore store = open(root)) {
            fixture.initialize(store, 2);
            Prepared prepared = prepare(store, fixture);
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(prepared.command()));
            Workflow first = claim(store, store.getSignWorkflow(prepared.command().operationId()).orElseThrow());
            Workflow cancelling = store.requestSignCancellation(first.operationId(), first.revision(), first.fence()).orElseThrow();
            Workflow cleanup = claim(store, cancelling);
            assertTrue(store.checkpointCaProof(first.operationId(), first.revision(), first.fence(),
                    signed(), Optional.of(prepared.signature())).isEmpty());
            Workflow terminal = store.checkpointCaProof(cleanup.operationId(), cleanup.revision(), cleanup.fence(),
                    signed(), Optional.of(prepared.signature())).orElseThrow();
            assertEquals(SignWorkflowStore.State.CANCELLED, terminal.state());
            assertEquals(SignWorkflowStore.Stage.CA_PROOF, terminal.stage());
            assertEquals(Optional.of(signed()), terminal.proofOutcome());
            assertTrue(terminal.result().isEmpty());
            assertTrue(terminal.leaseUntil().isEmpty());
            assertTrue(store.completeCaProofVerification(terminal.operationId(), terminal.revision(), terminal.fence()).isEmpty());
        }
    }

    @Test
    void verificationAndReadyCancellationClearSignatureWithoutLosingProofOutcome(@TempDir Path root) throws Exception {
        for (boolean makeReady : List.of(false, true)) {
            IntermediateCreationFixture fixture = new IntermediateCreationFixture();
            try (FilesystemPkiStore store = open(root.resolve(Boolean.toString(makeReady)))) {
                fixture.initialize(store, 2);
                Prepared prepared = prepare(store, fixture);
                assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(prepared.command()));
                Workflow proof = claim(store, store.getSignWorkflow(prepared.command().operationId()).orElseThrow());
                Workflow current = store.checkpointCaProof(proof.operationId(), proof.revision(), proof.fence(),
                        signed(), Optional.of(prepared.signature())).orElseThrow();
                if (makeReady) {
                    Workflow verifier = claim(store, current);
                    current = store.completeCaProofVerification(verifier.operationId(), verifier.revision(), verifier.fence()).orElseThrow();
                }
                Workflow terminal = store.requestSignCancellation(current.operationId(), current.revision(), current.fence()).orElseThrow();
                assertEquals(SignWorkflowStore.State.CANCELLED, terminal.state());
                assertEquals(Optional.of(signed()), terminal.proofOutcome());
                assertTrue(terminal.result().isEmpty());
                assertTrue(terminal.leaseUntil().isEmpty());
            }
        }
    }

    @Test
    void providerFailureTimestampDoesNotReplaceFailureWithExpiry(@TempDir Path root) throws Exception {
        for (ObservationState disposition : List.of(ObservationState.FAILED, ObservationState.UNRECOVERABLE)) {
            for (long delay : List.of(0L, 1L)) {
                IntermediateCreationFixture fixture = new IntermediateCreationFixture();
                try (FilesystemPkiStore store = open(root.resolve(disposition.name() + "-" + delay))) {
                    fixture.initialize(store, 2);
                Prepared prepared = prepare(store, fixture);
                assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(prepared.command()));
                Workflow proof = claim(store, store.getSignWorkflow(prepared.command().operationId()).orElseThrow());
                CaSubjectProofOutcome outcome = new CaSubjectProofOutcome(disposition,
                        disposition == ObservationState.FAILED ? DetailCode.DENIED : DetailCode.LOCAL_RESTART_UNRECOVERABLE,
                        Optional.of(prepared.command().deadline().plusSeconds(delay)));
                Workflow terminal = store.checkpointCaProof(proof.operationId(), proof.revision(), proof.fence(),
                        outcome, Optional.empty()).orElseThrow();
                assertEquals(SignWorkflowStore.State.FAILED, terminal.state());
                assertEquals(Optional.of(outcome), terminal.proofOutcome());
                assertTrue(terminal.result().isEmpty());
                }
            }
        }
    }

    @Test
    void successfulAndCancelledProviderTimeAtOrAfterDeadlineExpires(@TempDir Path root) throws Exception {
        for (ObservationState disposition : List.of(ObservationState.SUCCEEDED, ObservationState.CANCELLED)) {
            for (long delay : List.of(0L, 1L)) {
                IntermediateCreationFixture fixture = new IntermediateCreationFixture();
                try (FilesystemPkiStore store = open(root.resolve(disposition.name() + "-" + delay))) {
                    fixture.initialize(store, 2);
                    Prepared prepared = prepare(store, fixture);
                    assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(prepared.command()));
                    Workflow proof = claim(store, store.getSignWorkflow(prepared.command().operationId()).orElseThrow());
                    CaSubjectProofOutcome outcome = new CaSubjectProofOutcome(disposition,
                            disposition == ObservationState.SUCCEEDED ? DetailCode.SIGNED : DetailCode.CANCELLED,
                            Optional.of(prepared.command().deadline().plusSeconds(delay)));
                    Workflow terminal = store.checkpointCaProof(proof.operationId(), proof.revision(), proof.fence(),
                            outcome, disposition == ObservationState.SUCCEEDED ? Optional.of(prepared.signature()) : Optional.empty())
                            .orElseThrow();
                    assertEquals(SignWorkflowStore.State.EXPIRED, terminal.state());
                    assertTrue(terminal.result().isEmpty());
                }
            }
        }
    }

    @Test
    void oneCapacitySlotOwnsTwoBindingsAndRejectedCandidatesDoNotDeleteAcceptedBytes(@TempDir Path root) throws Exception {
        IntermediateCreationFixture fixture = new IntermediateCreationFixture();
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 1, IntermediateCreationFixture.CLOCK)) {
            fixture.initialize(store, 2);
            Prepared first = prepare(store, fixture);
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(first.command()));
            for (DurableContentReference reference : candidates(first)) { assertBinding(store, reference, true); }
            Prepared rejected = prepare(store, fixture, "CN=Capacity Child", "NONE");
            assertEquals(SignWorkflowStore.AcceptanceResult.CAPACITY_REJECTED, store.acceptSign(rejected.command()));
            assertTrue(store.getSignWorkflow(rejected.command().operationId()).isEmpty());
            for (DurableContentReference reference : candidates(rejected)) {
                assertBinding(store, reference, false);
                assertThrows(IOException.class, () -> PkiTestRuntime.readContent(store, reference));
            }
            for (DurableContentReference reference : candidates(first)) {
                assertBinding(store, reference, true);
                assertEquals(reference.length(), PkiTestRuntime.readContent(store, reference).length);
            }
            SignWorkflowStore.AcceptanceCommand different = new SignWorkflowStore.AcceptanceCommand(
                    first.command().operationId(), first.command().providerNamespace(), first.command().providerConfigurationCommitment(),
                    first.command().accessContext(), first.command().keyRef(), first.command().fairnessAuthorityId(), first.command().algorithmId(),
                    first.command().signatureEncoding(), first.command().createdAt(), first.command().deadline().plusSeconds(1),
                    first.command().candidate(), first.command().outer(), first.command().mode(), first.command().proofStep());
            assertEquals(SignWorkflowStore.AcceptanceResult.CONFLICT, store.acceptSign(different));
            for (DurableContentReference reference : candidates(first)) {
                assertBinding(store, reference, true);
                assertEquals(reference.length(), PkiTestRuntime.readContent(store, reference).length);
            }
        }
    }

    @Test
    void definiteAndUnknownAcceptanceKeepBothCandidatesConsistentAcrossRecovery(@TempDir Path root) throws Exception {
        for (FilesystemPkiStore.SignAcceptanceCommitFault fault : FilesystemPkiStore.SignAcceptanceCommitFault.values()) {
            Path directory = root.resolve(fault.name());
            IntermediateCreationFixture fixture = new IntermediateCreationFixture();
            Prepared prepared;
            try (FilesystemPkiStore store = open(directory)) {
                fixture.initialize(store, 2);
                prepared = prepare(store, fixture);
                FilesystemPkiStore.installSignAcceptanceCommitFault(fault);
                try { assertThrows(RuntimeException.class, () -> store.acceptSign(prepared.command())); }
                finally { FilesystemPkiStore.clearSignAcceptanceCommitFault(); }
                // The facade fences even a reported storage failure; recovery resolves candidate custody.
                assertThrows(zeroecho.pki.api.PkiException.class, store::signingNow);
            }
            try (FilesystemPkiStore store = open(directory)) {
                boolean committed = fault == FilesystemPkiStore.SignAcceptanceCommitFault.AFTER_COMMIT_AS_UNKNOWN;
                assertEquals(committed, store.getSignWorkflow(prepared.command().operationId()).isPresent());
                assertEquals(committed, store.getDomainContinuation(prepared.command().operationId()).isPresent());
                assertEquals(committed ? SignWorkflowStore.AcceptanceResolution.MATCHED : SignWorkflowStore.AcceptanceResolution.NOT_ACCEPTED,
                        store.resolveAcceptance(prepared.command().operationId(), prepared.command().commitment()));
                for (DurableContentReference reference : candidates(prepared)) {
                    assertBinding(store, reference, committed);
                    if (committed) { assertEquals(reference.length(), PkiTestRuntime.readContent(store, reference).length); }
                }
            }
        }
    }

    @Test
    void sixCompositeParentsRetireAndPurgeBothBindingsWithinMutationBound(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock();
        IntermediateCreationFixture fixture = new IntermediateCreationFixture();
        List<Prepared> prepared = new ArrayList<>();
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 16, clock)) {
            fixture.initialize(store, 2);
            for (int index = 0; index < 6; index++) {
                Prepared next = prepare(store, fixture, "CN=Purge Child " + index, "NONE");
                prepared.add(next);
                assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(next.command()));
                Workflow accepted = store.getSignWorkflow(next.command().operationId()).orElseThrow();
                Workflow cancelled = store.requestSignCancellation(accepted.operationId(), accepted.revision(), accepted.fence()).orElseThrow();
                DomainContinuationStore.Record outer = store.getDomainContinuation(accepted.operationId()).orElseThrow();
                store.transitionDomainContinuation(outer.operationId(), outer.revision(), DomainContinuationStore.State.FAILED,
                        Optional.empty(), Optional.of("FAILED")).orElseThrow();
                Workflow retired = store.retireSign(cancelled.operationId(), cancelled.revision(), cancelled.fence()).orElseThrow();
                assertEquals(SignWorkflowStore.State.RETIRED, retired.state());
                for (DurableContentReference reference : candidates(next)) {
                    assertBinding(store, reference, true);
                    assertThrows(IOException.class, () -> PkiTestRuntime.readContent(store, reference));
                }
            }
            clock.value = IntermediateCreationFixture.NOW.plus(store.signingHorizon()).plusSeconds(1);
            int first = store.purgeExpiredSignRecords();
            assertTrue(first > 0 && first <= 5);
            int second = store.purgeExpiredSignRecords();
            assertEquals(6, first + second); // Each composite parent owns two candidate bindings.
            assertEquals(0, store.purgeExpiredSignRecords());
            for (Prepared next : prepared) {
                assertTrue(store.getSignWorkflow(next.command().operationId()).isEmpty());
                for (DurableContentReference reference : candidates(next)) { assertBinding(store, reference, false); }
            }
        }
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 16, clock)) {
            for (Prepared next : prepared) { assertTrue(store.getSignWorkflow(next.command().operationId()).isEmpty()); }
        }
    }

    @Test
    void authoritativeDeadlineExpiresEvenFailureWithEarlierProviderTimestamp(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock();
        IntermediateCreationFixture fixture = new IntermediateCreationFixture();
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 16, clock)) {
            fixture.initialize(store, 2);
            Prepared prepared = prepare(store, fixture);
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(prepared.command()));
            Workflow proof = claim(store, store.getSignWorkflow(prepared.command().operationId()).orElseThrow());
            clock.value = prepared.command().deadline();
            Workflow expired = store.checkpointCaProof(proof.operationId(), proof.revision(), proof.fence(),
                    new CaSubjectProofOutcome(ObservationState.FAILED, DetailCode.DENIED, Optional.of(IntermediateCreationFixture.NOW)),
                    Optional.empty()).orElseThrow();
            assertEquals(SignWorkflowStore.State.EXPIRED, expired.state());
            for (DurableContentReference reference : candidates(prepared)) {
                assertThrows(IOException.class, () -> PkiTestRuntime.readContent(store, reference));
            }
        }
    }

    @Test
    void bindingRejectsProofSpkiAndAlgorithmDifferentFromExactFinalTbs(@TempDir Path root) throws Exception {
        for (String substitution : List.of("SPKI", "ALGORITHM")) {
            IntermediateCreationFixture fixture = new IntermediateCreationFixture();
            try (FilesystemPkiStore store = open(root.resolve(substitution))) {
                fixture.initialize(store, 2);
                Prepared prepared = prepare(store, fixture, "CN=Binding Child", substitution);
                SignWorkflowStore.AcceptanceEnvelope envelope = SignWorkflowStore.AcceptanceEnvelope.from(prepared.command());
                CaSubjectProofBindings.requireEnvelope(envelope); // Metadata is internally consistent; exact TBS bytes differ.
                assertThrows(IllegalArgumentException.class, () -> CaSubjectProofBindings.requireLiveCandidates(store.stagedContent(), envelope));
                assertEquals(0, fixture.provider.dispatches);
            }
        }
    }

    @Test
    void reactorSignsProofThenCertificateOnSeparateKeyLanesIncludingPendingProof(@TempDir Path root) throws Exception {
        for (boolean pendingProof : List.of(false, true)) {
            MutableClock clock = new MutableClock();
            IntermediateCreationFixture fixture = new IntermediateCreationFixture();
            try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root.resolve(Boolean.toString(pendingProof)), 1, clock)) {
                fixture.initialize(store, 2);
                Prepared prepared = prepare(store, fixture);
                assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(prepared.command()));
                TwoStepProvider provider = new TwoStepProvider(fixture, prepared, clock, pendingProof, false);
                runToRetirement(store, fixture, prepared, provider);
                assertEquals(2, provider.dispatches.size());
                ProviderCall proof = provider.dispatches.get(0);
                ProviderCall certificate = provider.dispatches.get(1);
                assertEquals(prepared.command().proofStep().orElseThrow().operationId(), proof.operationId());
                assertEquals(IntermediateCreationFixture.CHILD_KEY, proof.keyRef());
                assertEquals(prepared.command().operationId(), certificate.operationId());
                assertEquals(IntermediateCreationFixture.PARENT_KEY, certificate.keyRef());
                assertNotEquals(proof.threadName(), certificate.threadName());
                assertEquals(pendingProof ? List.of(proof.operationId()) : List.of(), provider.reconciles);
                assertPublished(store, prepared);
            }
        }
    }

    @Test
    void wrongProofSignatureTerminatesParentWithoutCertificateDispatchOrPublication(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock();
        IntermediateCreationFixture fixture = new IntermediateCreationFixture();
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 1, clock)) {
            fixture.initialize(store, 2);
            Prepared prepared = prepare(store, fixture);
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(prepared.command()));
            TwoStepProvider provider = new TwoStepProvider(fixture, prepared, clock, false, true);
            runToRetirement(store, fixture, prepared, provider);
            assertEquals(1, provider.dispatches.size());
            assertEquals(prepared.command().proofStep().orElseThrow().operationId(), provider.dispatches.getFirst().operationId());
            assertTrue(provider.reconciles.isEmpty());
            DomainContinuationStore.Record outer = store.getDomainContinuation(prepared.command().operationId()).orElseThrow();
            assertEquals(DomainContinuationStore.State.FAILED, outer.state());
            assertEquals(Optional.of("MANAGED_KEY_PROOF_SIGNATURE_INVALID"), outer.detailCode());
            assertTrue(store.getCa(new PkiId(DomainCommandEncoding.decode(outer.command()).field(2))).isEmpty());
            Workflow retained = store.getSignWorkflow(prepared.command().operationId()).orElseThrow();
            assertEquals(ObservationState.SUCCEEDED, retained.proofOutcome().orElseThrow().disposition());
            assertTrue(retained.result().isEmpty());
        }
    }

    @Test
    void restartResumesVerificationReadyAndClaimedCertificateWithoutRepeatingProof(@TempDir Path root) throws Exception {
        for (SignWorkflowStore.Stage stage : List.of(SignWorkflowStore.Stage.CA_PROOF_VERIFYING,
                SignWorkflowStore.Stage.CA_CERTIFICATE_READY, SignWorkflowStore.Stage.CA_CERTIFICATE)) {
            Path directory = root.resolve(stage.name());
            MutableClock clock = new MutableClock();
            IntermediateCreationFixture fixture = new IntermediateCreationFixture();
            Prepared prepared;
            EncodedObject certificateSignature;
            try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(directory, 1, clock)) {
                fixture.initialize(store, 2);
                prepared = prepare(store, fixture);
                assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(prepared.command()));
                Workflow verifying = proofSucceeded(store, prepared);
                if (stage != SignWorkflowStore.Stage.CA_PROOF_VERIFYING) {
                    driver(store, fixture).advance(claim(store, verifying));
                    assertEquals(SignWorkflowStore.Stage.CA_CERTIFICATE_READY,
                            store.getSignWorkflow(verifying.operationId()).orElseThrow().stage());
                }
                if (stage == SignWorkflowStore.Stage.CA_CERTIFICATE) {
                    Workflow certificate = claim(store, store.getSignWorkflow(verifying.operationId()).orElseThrow());
                    clock.value = certificate.leaseUntil().orElseThrow();
                }
                certificateSignature = fixture.signature(PkiTestRuntime.readContent(store, prepared.command().candidate()),
                        IntermediateCreationFixture.PARENT_KEY);
            }
            try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(directory, 1, clock)) {
                TwoStepProvider provider = new TwoStepProvider(fixture, prepared, clock, false, false);
                if (stage == SignWorkflowStore.Stage.CA_CERTIFICATE) {
                    provider.completed.put(prepared.command().operationId(), new SigningProvider.OperationObservation(
                            prepared.command().operationId(), ObservationState.SUCCEEDED, clock.instant(), DetailCode.SIGNED,
                            Optional.of(certificateSignature)));
                }
                runToRetirement(store, fixture, prepared, provider);
                assertEquals(stage == SignWorkflowStore.Stage.CA_CERTIFICATE ? 0 : 1, provider.dispatches.size());
                assertEquals(stage == SignWorkflowStore.Stage.CA_CERTIFICATE ? List.of(prepared.command().operationId()) : List.of(),
                        provider.reconciles);
                for (ProviderCall call : provider.dispatches) { assertEquals(prepared.command().operationId(), call.operationId()); }
                assertPublished(store, prepared);
            }
        }
    }

    @Test
    void executorRejectsLocalVerificationAndReadinessWithoutChangingClaims(@TempDir Path root) throws Exception {
        IntermediateCreationFixture fixture = new IntermediateCreationFixture();
        try (FilesystemPkiStore store = open(root)) {
            fixture.initialize(store, 2);
            Prepared prepared = prepare(store, fixture);
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(prepared.command()));
            Workflow verifier = claim(store, proofSucceeded(store, prepared));
            SigningProviderExecutor executor = new SigningProviderExecutor(store, fixture.provider, Duration.ofSeconds(5));
            for (Workflow local : List.of(verifier, store.completeCaProofVerification(verifier.operationId(),
                    verifier.revision(), verifier.fence()).orElseThrow())) {
                assertThrows(IllegalArgumentException.class, () -> executor.dispatch(local,
                        new ImmutableByteContent(new byte[0]), CancellationSignal.NONE));
                assertThrows(IllegalArgumentException.class, () -> executor.reconcile(local, CancellationSignal.NONE));
            }
            Workflow ready = store.getSignWorkflow(prepared.command().operationId()).orElseThrow();
            assertEquals(SignWorkflowStore.Stage.CA_CERTIFICATE_READY, ready.stage());
            assertTrue(ready.leaseUntil().isEmpty());
            assertEquals(0, fixture.provider.dispatches);
        }
    }

    @Test
    void verificationReadFailureRetainsProofSignatureAndRestartsWithoutAnotherProofCall(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock();
        IntermediateCreationFixture fixture = new IntermediateCreationFixture();
        Prepared prepared;
        EncodedObject retainedSignature;
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 1, clock)) {
            fixture.initialize(store, 2);
            prepared = prepare(store, fixture);
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(prepared.command()));
            AtomicBoolean failOnce = new AtomicBoolean(true);
            CountDownLatch deferred = new CountDownLatch(1);
            StagedContentStore staging = (StagedContentStore) Proxy.newProxyInstance(StagedContentStore.class.getClassLoader(),
                    new Class<?>[] {StagedContentStore.class}, (proxy, method, arguments) -> {
                        if (verificationRead(store, prepared, method.getName(), arguments) && failOnce.compareAndSet(true, false)) {
                            throw new IOException("Injected verification read failure");
                        }
                        try { return method.invoke(store.stagedContent(), arguments); }
                        catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
            PkiStore observed = observeStore(store, staging, (method, arguments, result) -> {
                if (method.equals("deferSignReconciliation") && arguments[0].equals(prepared.command().operationId())
                        && result instanceof Optional<?> optional && optional.isPresent()) { deferred.countDown(); }
            });
            TwoStepProvider provider = new TwoStepProvider(fixture, prepared, clock, false, false);
            try (SigningReactor reactor = new SigningReactor(observed, provider, topology(), driver(observed, fixture))) {
                reactor.start();
                assertTrue(deferred.await(10, TimeUnit.SECONDS));
            }
            Workflow failedRead = store.getSignWorkflow(prepared.command().operationId()).orElseThrow();
            assertEquals(SignWorkflowStore.Stage.CA_PROOF_VERIFYING, failedRead.stage());
            assertEquals(SignWorkflowStore.State.DISPATCHED, failedRead.state());
            assertEquals(Optional.of(SignWorkflowStore.ReconciliationFailureClass.LOCAL_FAILURE), failedRead.reconciliationFailureClass());
            retainedSignature = failedRead.result().orElseThrow();
            assertSignature(prepared.signature(), retainedSignature);
            assertEquals(1, provider.dispatches.size());
            assertTrue(provider.reconciles.isEmpty());
            clock.value = failedRead.nextEligibleAt().orElseThrow();
        }
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 1, clock)) {
            Workflow recovered = store.getSignWorkflow(prepared.command().operationId()).orElseThrow();
            assertSignature(retainedSignature, recovered.result().orElseThrow());
            TwoStepProvider provider = new TwoStepProvider(fixture, prepared, clock, false, false);
            runToRetirement(store, fixture, prepared, provider);
            assertEquals(List.of(prepared.command().operationId()), provider.dispatches.stream().map(ProviderCall::operationId).toList());
            assertTrue(provider.reconciles.isEmpty());
            assertPublished(store, prepared);
        }
    }

    @Test
    void cancellationAndExpiryDuringVerificationCannotReleaseCertificateSigning(@TempDir Path root) throws Exception {
        for (boolean expire : List.of(false, true)) {
            MutableClock clock = new MutableClock();
            IntermediateCreationFixture fixture = new IntermediateCreationFixture();
            try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root.resolve(Boolean.toString(expire)), 1, clock)) {
                fixture.initialize(store, 2);
                Prepared prepared = prepare(store, fixture);
                assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(prepared.command()));
                CountDownLatch entered = new CountDownLatch(1);
                CountDownLatch release = new CountDownLatch(1);
                CountDownLatch verificationFinished = new CountDownLatch(1);
                CountDownLatch retired = new CountDownLatch(1);
                StagedContentStore staging = (StagedContentStore) Proxy.newProxyInstance(StagedContentStore.class.getClassLoader(),
                        new Class<?>[] {StagedContentStore.class}, (proxy, method, arguments) -> {
                            if (verificationRead(store, prepared, method.getName(), arguments)) {
                                entered.countDown();
                                assertTrue(release.await(10, TimeUnit.SECONDS));
                            }
                            try { return method.invoke(store.stagedContent(), arguments); }
                            catch (InvocationTargetException failure) { throw failure.getCause(); }
                        });
                PkiStore observed = observeStore(store, staging, (method, arguments, result) -> {
                    if (method.equals("retireSign") && arguments[0].equals(prepared.command().operationId())
                            && result instanceof Optional<?> optional && optional.isPresent()) { retired.countDown(); }
                });
                SigningOuterTerminalDriver driver = driver(observed, fixture);
                TwoStepProvider provider = new TwoStepProvider(fixture, prepared, clock, false, false);
                try (SigningReactor reactor = new SigningReactor(observed, provider, topology(), workflow -> {
                    try { driver.advance(workflow); }
                    finally {
                        if (workflow.stage() == SignWorkflowStore.Stage.CA_PROOF_VERIFYING) { verificationFinished.countDown(); }
                    }
                })) {
                    reactor.start();
                    try {
                        assertTrue(entered.await(10, TimeUnit.SECONDS));
                        Workflow verifying = store.getSignWorkflow(prepared.command().operationId()).orElseThrow();
                        assertEquals(SignWorkflowStore.Stage.CA_PROOF_VERIFYING, verifying.stage());
                        if (expire) {
                            clock.value = prepared.command().deadline();
                            assertEquals(SignWorkflowStore.State.EXPIRED, store.getSignWorkflow(verifying.operationId()).orElseThrow().state());
                        } else {
                            assertEquals(SignWorkflowStore.State.CANCELLED, store.requestSignCancellation(verifying.operationId(),
                                    verifying.revision(), verifying.fence()).orElseThrow().state());
                        }
                    } finally { release.countDown(); }
                    assertTrue(verificationFinished.await(10, TimeUnit.SECONDS));
                    if (!expire) { assertTrue(retired.await(10, TimeUnit.SECONDS)); }
                }
                Workflow terminal = store.getSignWorkflow(prepared.command().operationId()).orElseThrow();
                assertEquals(expire ? SignWorkflowStore.State.EXPIRED : SignWorkflowStore.State.RETIRED, terminal.state());
                assertTrue(terminal.result().isEmpty());
                assertEquals(ObservationState.SUCCEEDED, terminal.proofOutcome().orElseThrow().disposition());
                DomainContinuationStore.Record outer = store.getDomainContinuation(terminal.operationId()).orElseThrow();
                assertEquals(expire ? DomainContinuationStore.State.EXPIRED : DomainContinuationStore.State.FAILED, outer.state());
                assertTrue(store.getCa(new PkiId(DomainCommandEncoding.decode(outer.command()).field(2))).isEmpty());
                assertEquals(1, provider.dispatches.size());
                assertTrue(provider.reconciles.isEmpty());
            }
        }
    }

    @Test
    void staleProofDispatchCallbackCannotOverrideNewCancellationClaim(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock();
        IntermediateCreationFixture fixture = new IntermediateCreationFixture();
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 1, clock)) {
            fixture.initialize(store, 2);
            Prepared prepared = prepare(store, fixture);
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(prepared.command()));
            AtomicInteger staleCheckpoints = new AtomicInteger();
            CountDownLatch retired = new CountDownLatch(1);
            PkiStore observed = observeStore(store, store.stagedContent(), (method, arguments, result) -> {
                if (arguments.length > 0 && arguments[0].equals(prepared.command().operationId()) && result instanceof Optional<?> optional) {
                    if (method.equals("checkpointCaProof") && optional.isEmpty()) { staleCheckpoints.incrementAndGet(); }
                    if (method.equals("retireSign") && optional.isPresent()) { retired.countDown(); }
                }
            });
            TwoStepProvider provider = new TwoStepProvider(fixture, prepared, clock, false, false);
            provider.blockProofDispatch = true;
            long originalFence;
            try (SigningReactor reactor = new SigningReactor(observed, provider, topology(), driver(observed, fixture))) {
                reactor.start();
                try {
                    assertTrue(provider.proofDispatchEntered.await(10, TimeUnit.SECONDS));
                    Workflow dispatched = store.getSignWorkflow(prepared.command().operationId()).orElseThrow();
                    originalFence = dispatched.fence();
                    store.requestSignCancellation(dispatched.operationId(), dispatched.revision(), dispatched.fence()).orElseThrow();
                } finally { provider.releaseProofDispatch.countDown(); }
                assertTrue(retired.await(10, TimeUnit.SECONDS));
            }
            assertEquals(1, staleCheckpoints.get());
            assertEquals(1, provider.dispatches.size());
            assertEquals(List.of(prepared.command().proofStep().orElseThrow().operationId()), provider.reconciles);
            Workflow terminal = store.getSignWorkflow(prepared.command().operationId()).orElseThrow();
            assertEquals(SignWorkflowStore.State.RETIRED, terminal.state());
            assertTrue(terminal.fence() > originalFence);
            assertEquals(Optional.of("CANCELLED"), terminal.detailCode());
            assertEquals(ObservationState.SUCCEEDED, terminal.proofOutcome().orElseThrow().disposition());
            assertTrue(terminal.result().isEmpty());
            assertEquals(DomainContinuationStore.State.FAILED, store.getDomainContinuation(terminal.operationId()).orElseThrow().state());
        }
    }

    private static boolean verificationRead(FilesystemPkiStore store, Prepared prepared, String method, Object[] arguments) {
        return method.equals("openContent") && arguments[0].equals(prepared.command().proofStep().orElseThrow().challenge())
                && store.getSignWorkflow(prepared.command().operationId()).orElseThrow().stage() == SignWorkflowStore.Stage.CA_PROOF_VERIFYING;
    }

    private static PkiStore observeStore(FilesystemPkiStore store, StagedContentStore staging, StoreObservation observation) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] {PkiStore.class},
                (proxy, method, arguments) -> {
                    if (method.getName().equals("stagedContent")) { return staging; }
                    Object result;
                    try { result = method.invoke(store, arguments); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                    observation.completed(method.getName(), arguments == null ? new Object[0] : arguments, result);
                    return result;
                });
    }

    @FunctionalInterface
    private interface StoreObservation {
        void completed(String method, Object[] arguments, Object result);
    }

    private static Workflow proofSucceeded(FilesystemPkiStore store, Prepared prepared) {
        Workflow claim = claim(store, store.getSignWorkflow(prepared.command().operationId()).orElseThrow());
        return store.checkpointCaProof(claim.operationId(), claim.revision(), claim.fence(), signed(),
                Optional.of(prepared.signature())).orElseThrow();
    }

    private static SigningOuterTerminalDriver driver(PkiStore store, IntermediateCreationFixture fixture) {
        return new SigningOuterTerminalDriver(store, fixture.verification, fixture.verifier, ManagedKeyProofCommand.MAX_CHALLENGE_BYTES);
    }

    private static void runToRetirement(FilesystemPkiStore store, IntermediateCreationFixture fixture, Prepared prepared,
            TwoStepProvider provider) throws Exception {
        CountDownLatch retired = new CountDownLatch(1);
        PkiStore observed = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] {PkiStore.class},
                (proxy, method, arguments) -> {
                    Object result;
                    try { result = method.invoke(store, arguments); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                    if (method.getName().equals("retireSign") && arguments[0].equals(prepared.command().operationId())
                            && result instanceof Optional<?> optional && optional.isPresent()) { retired.countDown(); }
                    return result;
                });
        try (SigningReactor reactor = new SigningReactor(observed, provider, topology(), driver(observed, fixture))) {
            reactor.start();
            assertTrue(retired.await(10, TimeUnit.SECONDS), "Composite parent did not retire");
        }
    }

    private static SigningTopology topology() {
        return new SigningTopology(new SigningCoordinatorLimits(2, Duration.ofSeconds(10), Duration.ofSeconds(5),
                Duration.ofMillis(5), Duration.ofSeconds(2)),
                List.of(new SigningKeyGroup(List.of(IntermediateCreationFixture.CHILD_KEY), new SigningLanePool(1, 1))),
                new SigningLanePool(1, 1));
    }

    private static void assertPublished(FilesystemPkiStore store, Prepared prepared) {
        DomainContinuationStore.Record outer = store.getDomainContinuation(prepared.command().operationId()).orElseThrow();
        assertEquals(DomainContinuationStore.State.COMPLETED, outer.state());
        assertTrue(store.getCa(new PkiId(DomainCommandEncoding.decode(outer.command()).field(2))).isPresent());
        Workflow retained = store.getSignWorkflow(prepared.command().operationId()).orElseThrow();
        assertEquals(SignWorkflowStore.State.RETIRED, retained.state());
        assertEquals(SignWorkflowStore.Stage.CA_CERTIFICATE, retained.stage());
        assertEquals(ObservationState.SUCCEEDED, retained.proofOutcome().orElseThrow().disposition());
    }

    private record ProviderCall(PkiId operationId, KeyRef keyRef, String threadName) { }

    private static final class TwoStepProvider implements SigningProvider {
        private final IntermediateCreationFixture fixture;
        private final Prepared prepared;
        private final MutableClock clock;
        private final boolean pendingProof;
        private final boolean wrongProof;
        private boolean blockProofDispatch;
        private final CountDownLatch proofDispatchEntered = new CountDownLatch(1);
        private final CountDownLatch releaseProofDispatch = new CountDownLatch(1);
        private final List<ProviderCall> dispatches = new CopyOnWriteArrayList<>();
        private final List<PkiId> reconciles = new CopyOnWriteArrayList<>();
        private final Map<PkiId, OperationObservation> completed = new ConcurrentHashMap<>();

        private TwoStepProvider(IntermediateCreationFixture fixture, Prepared prepared, MutableClock clock,
                boolean pendingProof, boolean wrongProof) {
            this.fixture = fixture;
            this.prepared = prepared;
            this.clock = clock;
            this.pendingProof = pendingProof;
            this.wrongProof = wrongProof;
        }
        @Override public String id() { return fixture.provider.id(); }
        @Override public ConfigurationCommitment configurationCommitment() { return fixture.provider.configurationCommitment(); }
        @Override public Set<String> supportedAlgorithms() { return fixture.provider.supportedAlgorithms(); }
        @Override public SigningInputCapabilities inputCapabilities() { return fixture.provider.inputCapabilities(); }
        @Override public OperationObservation dispatch(SignRequest request, CallControl control) {
            dispatches.add(new ProviderCall(request.operationId(), request.keyRef(), Thread.currentThread().getName()));
            assertEquals(IntermediateCreationFixture.ALGORITHM, request.algorithmId());
            assertEquals(Optional.of(prepared.command().deadline()), request.deadline());
            boolean proof = request.operationId().equals(prepared.command().proofStep().orElseThrow().operationId());
            assertEquals(proof ? IntermediateCreationFixture.CHILD_KEY : IntermediateCreationFixture.PARENT_KEY, request.keyRef());
            try (java.io.InputStream input = request.content().openStream()) {
                byte[] bytes = input.readAllBytes();
                assertEquals(proof ? prepared.command().proofStep().orElseThrow().challenge().sha256()
                        : prepared.command().candidate().sha256(), IntermediateCreationFixture.hash(bytes));
                EncodedObject signature = fixture.signature(bytes, proof && wrongProof ? IntermediateCreationFixture.PARENT_KEY : request.keyRef());
                OperationObservation result = new OperationObservation(request.operationId(), ObservationState.SUCCEEDED,
                        clock.instant(), DetailCode.SIGNED, Optional.of(signature));
                completed.put(request.operationId(), result);
                if (proof && blockProofDispatch) {
                    proofDispatchEntered.countDown();
                    assertTrue(releaseProofDispatch.await(10, TimeUnit.SECONDS));
                }
                if (proof && pendingProof) {
                    clock.value = clock.value.plusSeconds(10); // Make the existing claim lease due without wall-clock waiting.
                    return new OperationObservation(request.operationId(), ObservationState.PENDING, clock.instant(), DetailCode.PENDING, Optional.empty());
                }
                return result;
            } catch (Exception failure) { throw new IllegalStateException("Test signing failed", failure); }
        }
        @Override public OperationObservation reconcile(PkiId operation, CallControl control) {
            reconciles.add(operation);
            return java.util.Objects.requireNonNull(completed.get(operation), "Unexpected provider identity");
        }
        @Override public OperationObservation cancel(PkiId operation, long fence, CancellationReason reason, CallControl control) {
            throw new AssertionError("Unexpected cancellation");
        }
        @Override public void close() { }
    }

    private static zeroecho.pki.api.KeyRef dueKey(FilesystemPkiStore store, PkiId operationId) {
        return store.pageDueSignWorkflows(IntermediateCreationFixture.NOW, Optional.empty(), Optional.empty(), 32,
                CancellationSignal.NONE).candidates().stream().filter(candidate -> candidate.operationId().equals(operationId))
                .findFirst().orElseThrow().scheduling().keyRef();
    }

    private static List<DurableContentReference> candidates(Prepared prepared) {
        return List.of(prepared.command().candidate(), prepared.command().proofStep().orElseThrow().challenge());
    }

    private static void assertBinding(FilesystemPkiStore store, DurableContentReference reference, boolean present) throws IOException {
        try (MetadataSnapshot snapshot = store.metadataStore().snapshot();
                MetadataSnapshot.Record record = snapshot.get(new MetadataKey("io.zeroecho.pki.signing-candidate-binding",
                        reference.contentId())).orElse(null)) {
            assertEquals(present, record != null);
        }
    }

    private static final class MutableClock extends Clock {
        private volatile Instant value = IntermediateCreationFixture.NOW;
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return value; }
    }

    private static void assertSignature(EncodedObject expected, EncodedObject actual) {
        assertEquals(expected.encoding(), actual.encoding());
        assertArrayEquals(expected.bytes(), actual.bytes());
    }

    private static Workflow claim(FilesystemPkiStore store, Workflow current) {
        return store.claimSignStep(current.operationId(), current.revision(), LEASE).orElseThrow();
    }

    private static CaSubjectProofOutcome signed() {
        return new CaSubjectProofOutcome(ObservationState.SUCCEEDED, DetailCode.SIGNED,
                Optional.of(IntermediateCreationFixture.NOW));
    }

    private static FilesystemPkiStore open(Path root) {
        return FilesystemPkiStoreTestAccess.open(root, 16, IntermediateCreationFixture.CLOCK);
    }

    private static Prepared prepare(FilesystemPkiStore store, IntermediateCreationFixture fixture) throws Exception {
        return prepare(store, fixture, "CN=Composite Child", "NONE");
    }

    private static Prepared prepare(FilesystemPkiStore store, IntermediateCreationFixture fixture, String subject,
            String substitution) throws Exception {
        DomainSigningRequest original = fixture.preparer(store).prepare(IntermediateCreationFixture.ACCESS,
                fixture.command(subject), fixture.submission(store), IntermediateCreationFixture.TTL,
                CancellationSignal.NONE);
        if (substitution.equals("NONE")) {
            DomainContinuationTemplate outer = original.domainTemplate();
            SignWorkflowStore.AcceptanceCommand command = new SignWorkflowStore.AcceptanceCommand(original.operationId(),
                    store.signingNamespace() + "." + fixture.provider.id(), fixture.provider.configurationCommitment(),
                    original.accessContext(), original.keyRef(), IntermediateCreationFixture.CA, original.algorithmId(),
                    original.signatureEncoding(), IntermediateCreationFixture.NOW, IntermediateCreationFixture.NOW.plus(original.ttl()),
                    original.content(), Optional.of(new SignWorkflowStore.OuterCommand(outer.kind(), outer.correlationId().orElseThrow(),
                            outer.command(), outer.commandCommitment())), SignWorkflowStore.Mode.NORMAL, original.proofStep());
            return new Prepared(command, fixture.signature(PkiTestRuntime.readContent(store,
                    original.proofStep().orElseThrow().challenge()), IntermediateCreationFixture.CHILD_KEY));
        }
        DomainCommandEncoding.Decoded decoded = DomainCommandEncoding.decode(original.domainTemplate().command());
        List<String> fields = new ArrayList<>(decoded.fields());
        DomainCommandEncoding.Decoded oldProof = DomainCommandEncoding.decode(new EncodedObject(Encoding.BINARY,
                Base64.getUrlDecoder().decode(fields.get(19))));
        PkiId stepId = fixture.submission(store).id();
        byte[] spki = substitution.equals("SPKI") ? fixture.rotatedKey.getPublic().getEncoded() : fixture.childKey.getPublic().getEncoded();
        List<String> proofMetadata = new ArrayList<>(oldProof.fields().subList(0, 10));
        if (substitution.equals("SPKI")) { fields.set(17, IntermediateCreationFixture.hash(spki)); }
        if (substitution.equals("ALGORITHM")) { proofMetadata.set(9, "300d06092a864886f70d01010b0500"); }
        String intent = CaSigningIntent.commitment(new DomainCommandEncoding.Decoded(decoded.operation(), fields),
                BootstrapAlgorithmIdentities.ED25519_SIGNATURE);
        byte[] challenge = ManagedKeyProofChallenge.encode(stepId, IntermediateCreationFixture.NOW.plus(IntermediateCreationFixture.TTL),
                Optional.of(new ManagedKeyProofChallenge.CaContext(original.operationId(), intent)),
                proofMetadata, new byte[32], spki);
        DomainCommandEncoding.Decoded proof = ManagedKeyProofChallenge.decode(challenge).command();
        fields.set(18, stepId.value());
        fields.set(19, IntermediateSigningCommand.encodeProof(DomainCommandEncoding.template(DomainContinuationStore.Kind.KEY_PROOF,
                ManagedKeyProofCommand.OPERATION, proof.fields().toArray(String[]::new)).command()));
        DomainContinuationTemplate outer = IntermediateSigningCommand.template(decoded.operation(),
                original.domainTemplate().correlationId().orElseThrow(), fields);
        DurableContentReference stagedProof = PkiTestRuntime.operationReference(store.stagedContent(), Encoding.BINARY, challenge);
        store.stagedContent().retireUnownedContent(original.proofStep().orElseThrow().challenge());
        SignWorkflowStore.AcceptanceCommand command = new SignWorkflowStore.AcceptanceCommand(original.operationId(),
                store.signingNamespace() + "." + fixture.provider.id(), fixture.provider.configurationCommitment(),
                original.accessContext(), original.keyRef(), IntermediateCreationFixture.CA, original.algorithmId(),
                original.signatureEncoding(), IntermediateCreationFixture.NOW, IntermediateCreationFixture.NOW.plus(original.ttl()),
                original.content(), Optional.of(new SignWorkflowStore.OuterCommand(outer.kind(), outer.correlationId().orElseThrow(),
                        outer.command(), outer.commandCommitment())), SignWorkflowStore.Mode.NORMAL,
                Optional.of(new SignWorkflowStore.CaSubjectProofStep(stepId, IntermediateCreationFixture.CHILD_KEY,
                        original.algorithmId(), stagedProof)));
        return new Prepared(command, fixture.signature(challenge, IntermediateCreationFixture.CHILD_KEY));
    }

    private record Prepared(SignWorkflowStore.AcceptanceCommand command, EncodedObject signature) { }
}
