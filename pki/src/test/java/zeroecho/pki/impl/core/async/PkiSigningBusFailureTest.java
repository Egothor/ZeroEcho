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
package zeroecho.pki.impl.core.async;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static zeroecho.pki.testkit.PkiTestRuntime.signingAuthority;
import static zeroecho.pki.testkit.PkiTestRuntime.stage;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.orch.OrchestrationDurabilityPolicy;
import zeroecho.pki.api.orch.WorkflowStateRecord;
import zeroecho.pki.application.SigningReconciliationRequest;
import zeroecho.pki.application.SigningReconciliationResult;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.impl.framework.x509.X509AlgorithmResolver;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.InMemorySignatureWorkflow;
import zeroecho.pki.util.async.AsyncState;

final class PkiSigningBusFailureTest {

    @Test
    void reconciliationEnforcesIndependentScanAndProviderBudgetsAndWrapsFairly(@TempDir Path tempDir)
            throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-01T00:00:00Z"));
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            submit(bus);
            clock.set(clock.instant().plusMillis(1));
            submit(bus);
            clock.set(clock.instant().plusMillis(1));
            submit(bus);

            SigningReconciliationResult first = bus.reconcile(reconciliation(Optional.empty(), 2, 1, clock));
            assertEquals(2, first.examined());
            assertEquals(1, signer.submissions.get());
            assertEquals(1, first.progressed());
            assertEquals(2, first.unresolved());

            SigningReconciliationResult second = bus.reconcile(reconciliation(first.nextCursor(), 2, 1, clock));
            assertEquals(2, second.examined());
            assertEquals(2, signer.submissions.get());
            assertTrue(second.endReached());

            SigningReconciliationResult third = bus.reconcile(reconciliation(second.nextCursor(), 2, 1, clock));
            assertEquals(2, third.examined());
            assertEquals(3, signer.submissions.get());
        }
    }

    @Test
    void reconciliationDeadlineStopsPagingBeforeCandidateDecode(@TempDir Path tempDir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-01T01:00:00Z"));
        assertThrows(IllegalArgumentException.class, () -> new SigningReconciliationRequest(Optional.of("bad/cursor"),
                1, 1, clock.instant().plusSeconds(1), Duration.ofSeconds(1), CancellationSignal.NONE));
        assertThrows(IllegalArgumentException.class, () -> new SigningReconciliationRequest(Optional.of("bad-\u2603"),
                1, 1, clock.instant().plusSeconds(1), Duration.ofSeconds(1), CancellationSignal.NONE));
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            submit(bus);
            SigningReconciliationRequest expired = new SigningReconciliationRequest(Optional.empty(), 256, 64,
                    clock.instant(), Duration.ofSeconds(10), CancellationSignal.NONE);

            SigningReconciliationResult result = bus.reconcile(expired);

            assertEquals(0, result.examined());
            assertEquals(0, signer.submissions.get());
            assertFalse(result.endReached());
        }
    }

    @Test
    void reconciliationUsesStatusBeforeCancellationAndRetiresTerminalSamePass(@TempDir Path tempDir)
            throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-02T00:00:00Z"));
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            PkiId id = submit(bus);
            assertEquals(AsyncState.RUNNING, bus.status(id).orElseThrow().state());
            SignWorkflowStore.Record dispatched = store.getSignRecord(id).orElseThrow();
            store.transitionSign(id, dispatched.revision(), dispatched.fence(), SignWorkflowStore.State.CANCELLING,
                    Optional.of("CANCEL_REQUESTED"), Optional.empty(), Optional.empty()).orElseThrow();

            bus.reconcile(reconciliation(Optional.empty(), 1, 1, clock));
            assertEquals(0, signer.cancellations.get());
            assertEquals("CANCEL_REQUESTED", store.getSignRecord(id).orElseThrow().detailCode().orElseThrow());

            bus.reconcile(reconciliation(Optional.empty(), 2, 2, clock));
            assertEquals(1, signer.cancellations.get());
            assertEquals(SignWorkflowStore.State.CANCELLING, store.getSignRecord(id).orElseThrow().state());

            SigningReconciliationResult terminal = bus.reconcile(reconciliation(Optional.empty(), 1, 1, clock));
            assertEquals(SignWorkflowStore.State.RETIRED, store.getSignRecord(id).orElseThrow().state());
            assertEquals(1, terminal.progressed());
            assertEquals(0, terminal.unresolved());
        }
    }

    @Test
    void throwingCancellationConsumesExactTwoCallBudgetAndDoesNotTouchLaterRecord(@TempDir Path tempDir)
            throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-03T00:00:00Z"));
        ThrowingCancellationWorkflow signer = new ThrowingCancellationWorkflow(clock);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            PkiId first = submit(bus);
            clock.set(clock.instant().plusMillis(1));
            PkiId second = submit(bus);
            assertEquals(AsyncState.RUNNING, bus.status(first).orElseThrow().state());
            assertEquals(AsyncState.RUNNING, bus.status(second).orElseThrow().state());
            requestCancellation(store, first);
            requestCancellation(store, second);
            signer.resetObservations();

            SigningReconciliationResult result = bus.reconcile(reconciliation(Optional.empty(), 2, 2, clock));

            assertEquals(2, result.examined());
            assertEquals(1, signer.statusReads.get());
            assertEquals(1, signer.cancellations.get());
            assertEquals(1, store.getSignRecord(first).orElseThrow().failureCount()
                    + store.getSignRecord(second).orElseThrow().failureCount());
        }
    }

    @Test
    void pointReadFailureIsolatedAndLaterCandidateUsesRemainingProviderBudget(@TempDir Path tempDir)
            throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-03T01:00:00Z"));
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        AtomicReference<PkiId> faultTarget = new AtomicReference<>();
        AtomicBoolean faultArmed = new AtomicBoolean();
        try (FilesystemPkiStore delegate = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(
                        faultingStore(delegate, "getSignRecord", faultTarget, faultArmed), signer,
                        tempDir.resolve("bus.log"), signingAuthority(signer))) {
            PkiId first = submit(bus);
            clock.set(clock.instant().plusMillis(1));
            submit(bus);
            faultTarget.set(first);
            faultArmed.set(true);

            SigningReconciliationResult result = bus.reconcile(reconciliation(Optional.empty(), 2, 1, clock));

            assertEquals(2, result.examined());
            assertEquals(1, signer.submissions.get());
            assertEquals(2, result.unresolved());
            assertFalse(faultArmed.get());
        }
    }

    @Test
    void retirementFailureIsolatedAndLaterCandidateProgresses(@TempDir Path tempDir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-03T02:00:00Z"));
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        AtomicReference<PkiId> faultTarget = new AtomicReference<>();
        AtomicBoolean faultArmed = new AtomicBoolean();
        try (FilesystemPkiStore delegate = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(
                        faultingStore(delegate, "retireSign", faultTarget, faultArmed), signer,
                        tempDir.resolve("bus.log"), signingAuthority(signer))) {
            PkiId terminal = submit(bus);
            assertEquals(AsyncState.RUNNING, bus.status(terminal).orElseThrow().state());
            signer.succeedAt(terminal, clock.instant(), (byte) 7);
            assertEquals(AsyncState.SUCCEEDED, bus.status(terminal).orElseThrow().state());
            clock.set(clock.instant().plusMillis(1));
            submit(bus);
            faultTarget.set(terminal);
            faultArmed.set(true);

            SigningReconciliationResult result = bus.reconcile(reconciliation(Optional.empty(), 2, 1, clock));

            assertEquals(2, result.examined());
            assertEquals(2, signer.submissions.get());
            assertTrue(result.progressed() >= 1);
            assertTrue(result.retryable() >= 1);
            assertFalse(faultArmed.get());
        }
    }

    @Test
    void deferWriteFailureIsolatedWithExactProviderAttemptsAndLaterProgress(@TempDir Path tempDir)
            throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-03T03:00:00Z"));
        AcceptedThenThrowsWorkflow signer = new AcceptedThenThrowsWorkflow(clock);
        AtomicReference<PkiId> faultTarget = new AtomicReference<>();
        AtomicBoolean faultArmed = new AtomicBoolean();
        try (FilesystemPkiStore delegate = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(
                        faultingStore(delegate, "deferSignReconciliation", faultTarget, faultArmed), signer,
                        tempDir.resolve("bus.log"), signingAuthority(signer))) {
            PkiId first = submit(bus);
            clock.set(clock.instant().plusMillis(1));
            submit(bus);
            faultTarget.set(first);
            faultArmed.set(true);

            SigningReconciliationResult result = bus.reconcile(reconciliation(Optional.empty(), 2, 2, clock));

            assertEquals(2, result.examined());
            assertEquals(2, signer.submissions.get());
            assertEquals(1, result.progressed());
            assertEquals(2, result.retryable());
            assertFalse(faultArmed.get());
        }
    }

    @Test
    void durabilityUncertainStoreFailureFailsPassClosed(@TempDir Path tempDir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-03T04:00:00Z"));
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        AtomicReference<PkiId> faultTarget = new AtomicReference<>();
        AtomicBoolean faultArmed = new AtomicBoolean();
        try (FilesystemPkiStore delegate = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(
                        faultingStore(delegate, "getSignRecord", faultTarget, faultArmed,
                                new PkiException("Store durability unconfirmed: code=STORE_DURABILITY_UNCONFIRMED")),
                        signer, tempDir.resolve("bus.log"), signingAuthority(signer))) {
            PkiId first = submit(bus);
            faultTarget.set(first);
            faultArmed.set(true);

            PkiException failure = assertThrows(PkiException.class,
                    () -> bus.reconcile(reconciliation(Optional.empty(), 1, 1, clock)));

            assertTrue(failure.getMessage().contains("code=STORE_DURABILITY_UNCONFIRMED"));
            assertEquals(0, signer.submissions.get());
        }
    }

    @Test
    void acceptedUncertainIntentIsStatusReconciledAcrossRestartAndCancelledAfterDeadline(@TempDir Path tempDir)
            throws Exception {
        Instant createdAt = Instant.parse("2026-08-04T00:00:00Z");
        MutableClock clock = new MutableClock(createdAt);
        AcceptedThenThrowsWorkflow signer = new AcceptedThenThrowsWorkflow(clock);
        Path storeRoot = tempDir.resolve("store");
        Path busLog = tempDir.resolve("bus.log");
        PkiId id;
        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, busLog, signingAuthority(signer))) {
            id = submit(bus, Duration.ofSeconds(10));
            assertThrows(IllegalStateException.class, () -> bus.status(id));
            SignWorkflowStore.Record uncertain = store.getSignRecord(id).orElseThrow();
            assertEquals(SignWorkflowStore.State.INTENT, uncertain.state());
            assertTrue(uncertain.fence() > 0L);
            assertEquals(1, signer.submissions.get());
        }

        clock.set(createdAt.plusSeconds(10));
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus replayed = new PkiSigningBus(reopened, signer, busLog, signingAuthority(signer))) {
            SigningReconciliationResult cancellation = replayed.reconcile(
                    reconciliation(Optional.empty(), 2, 2, clock));
            assertEquals(1, cancellation.progressed());
            assertEquals(1, signer.submissions.get());
            assertEquals(1, signer.statusReads.get());
            assertEquals(1, signer.cancellations.get());

            replayed.reconcile(reconciliation(Optional.empty(), 1, 1, clock));
            assertEquals(SignWorkflowStore.State.RETIRED, reopened.getSignRecord(id).orElseThrow().state());
            assertEquals(1, signer.submissions.get());
        }
    }

    @Test
    void constructorsRequireExplicitOwningSignAuthority(@TempDir Path tempDir) throws Exception {
        System.out.println("constructorsRequireExplicitOwningSignAuthority");
        Constructor<?>[] constructors = PkiSigningBus.class.getConstructors();
        assertEquals(2, constructors.length);
        assertTrue(Arrays.stream(constructors)
                .allMatch(constructor -> constructor.getParameterTypes()[constructor.getParameterCount() - 1]
                        == X509AuthoritySnapshot.class));

        InMemorySignatureWorkflow signer = new InMemorySignatureWorkflow(Map.of(), false);
        InMemorySignatureWorkflow foreignSigner = new InMemorySignatureWorkflow(Map.of(), false);
        X509AuthoritySnapshot owning = signingAuthority(signer);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("owning.log"), owning)) {
            assertSame(owning, bus.authority());
            assertThrows(NullPointerException.class,
                    () -> new PkiSigningBus(store, signer, tempDir.resolve("null.log"), null));

            X509AuthoritySnapshot foreign = signingAuthority(foreignSigner);
            assertThrows(IllegalArgumentException.class,
                    () -> new PkiSigningBus(store, signer, tempDir.resolve("foreign.log"), foreign));

            X509AuthoritySnapshot missing = X509AuthoritySnapshot.compose(List.of(), List.of(),
                    allowPolicy("constructor-missing"));
            assertThrows(IllegalArgumentException.class,
                    () -> new PkiSigningBus(store, signer, tempDir.resolve("missing.log"), missing));

            String implementationId = "workflow." + signer.id();
            AlgorithmExecutionCapability verifyOnly = exactWorkflowCapability(implementationId,
                    AlgorithmExecutionCapability.Direction.VERIFY);
            X509AuthoritySnapshot verifyAuthority = X509AuthoritySnapshot.compose(List.of(),
                    List.of(() -> List.of(verifyOnly)),
                    List.of(X509AuthoritySnapshot.bindExecutor(implementationId,
                            AlgorithmExecutionCapability.Direction.VERIFY, signer)),
                    allowPolicy("constructor-verify-only"));
            assertThrows(IllegalArgumentException.class,
                    () -> new PkiSigningBus(store, signer, tempDir.resolve("verify.log"), verifyAuthority));

            AlgorithmExecutionCapability mismatched = exactWorkflowCapability("workflow.other",
                    AlgorithmExecutionCapability.Direction.SIGN);
            X509AuthoritySnapshot mismatchedAuthority = X509AuthoritySnapshot.compose(List.of(),
                    List.of(() -> List.of(mismatched)),
                    List.of(X509AuthoritySnapshot.bindExecutor("workflow.other",
                            AlgorithmExecutionCapability.Direction.SIGN, signer)),
                    allowPolicy("constructor-mismatch"));
            assertThrows(IllegalArgumentException.class,
                    () -> new PkiSigningBus(store, signer, tempDir.resolve("mismatch.log"), mismatchedAuthority));

            assertThrows(X509AlgorithmResolver.ResolutionException.class,
                    () -> owning.plan(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                            BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY,
                            AlgorithmExecutionCapability.Direction.VERIFY, Optional.of(implementationId), "test",
                            SignatureWorkflow.class));
        } finally {
            foreignSigner.close();
            signer.close();
        }
        System.out.println("...constructors=" + constructors.length);
        System.out.println("...ok");
    }

    @Test
    void preIntentValidationFailureReleasesTransferredContent(@TempDir Path tempDir) throws Exception {
        InMemorySignatureWorkflow signer = new InMemorySignatureWorkflow(Map.of(), false);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            Principal owner = new Principal("TEST", "owner");
            PkiId operationId = bus.newSubmissionId();
            DurableContentReference content = stage(bus,
                    new EncodedObject(Encoding.BINARY, new byte[] { 1, 2, 3 }));
            AccessContext access = new AccessContext(owner, new Purpose("TEST"), Optional.empty(), Optional.empty());
            PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(access,
                    "SHA256withRSA", content, new KeyRef("test"), Encoding.BINARY, Optional.empty());

            assertThrows(IllegalArgumentException.class,
                    () -> bus.submitSign(operationId, owner, new KeyRef("test"), "unsupported-signature",
                            content, Duration.ofSeconds(5), Optional.of(continuation.encode())));

            assertTrue(store.getSignRecord(operationId).isEmpty());
            assertThrows(PkiException.class, () -> bus.openContent(content));
            assertEquals(0, signer.submittedSignCount());
        } finally {
            signer.close();
        }
    }

    @Test
    void acceptedCancellationWaitsForObservedTerminalProviderState(@TempDir Path tempDir) throws Exception {
        AcceptedDelayedCancellationWorkflow signer = new AcceptedDelayedCancellationWorkflow();
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"), FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            PkiId id = submit(bus);
            assertEquals(AsyncState.RUNNING, bus.status(id).orElseThrow().state());

            bus.retireSignOperation(id, "accepted cancellation");

            assertEquals(SignWorkflowStore.State.CANCELLING, store.getSignRecord(id).orElseThrow().state());
            assertTrue(store.getSignRecord(id).orElseThrow().result().isEmpty());
            assertEquals(1, signer.cancellations.get());

            signer.completeSuccessfully(id);
            bus.retireSignOperation(id, "provider won cancellation race");

            SignWorkflowStore.Record retired = store.getSignRecord(id).orElseThrow();
            assertEquals(SignWorkflowStore.State.RETIRED, retired.state());
            assertArrayEquals(new byte[] { 21 }, retired.result().orElseThrow().bytes());
            assertEquals(1, signer.cancellations.get());
        }
    }

    @Test
    void deadlineAdvisoryStillRequiresProviderCancellationBeforeRetirement(@TempDir Path tempDir) throws Exception {
        Instant createdAt = Instant.parse("2026-06-07T08:09:10Z");
        MutableClock clock = new MutableClock(createdAt);
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"), FsPkiStoreOptions.defaults(),
                clock); PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            PkiId id = submit(bus, Duration.ofSeconds(10));
            assertEquals(AsyncState.RUNNING, bus.status(id).orElseThrow().state());
            clock.set(createdAt.plusSeconds(10));

            assertEquals(AsyncState.EXPIRED, bus.status(id).orElseThrow().state());
            assertEquals(SignWorkflowStore.State.DISPATCHED, store.getSignRecord(id).orElseThrow().state());

            bus.retireSignOperation(id, "deadline elapsed");

            assertEquals(1, signer.cancellations.get());
            assertEquals(SignWorkflowStore.State.RETIRED, store.getSignRecord(id).orElseThrow().state());
        }
    }

    @Test
    void providerCompletionTimestampControlsDeadlineAcrossRestart(@TempDir Path tempDir) throws Exception {
        Instant createdAt = Instant.parse("2026-06-07T08:09:10Z");
        Instant deadline = createdAt.plusSeconds(10);
        MutableClock clock = new MutableClock(createdAt);
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        Path storeRoot = tempDir.resolve("store");
        Path busLog = tempDir.resolve("bus.log");
        PkiId exact;
        PkiId late;
        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, busLog, signingAuthority(signer))) {
            PkiId onTime = submit(bus, Duration.ofSeconds(10));
            assertEquals(AsyncState.RUNNING, bus.status(onTime).orElseThrow().state());
            signer.succeedAt(onTime, deadline.minusNanos(1), (byte) 31);
            assertEquals(AsyncState.SUCCEEDED, bus.status(onTime).orElseThrow().state());
            assertEquals(31, bus.consumeResult(onTime).orElseThrow().bytes()[0]);

            exact = submit(bus, Duration.ofSeconds(10));
            assertEquals(AsyncState.RUNNING, bus.status(exact).orElseThrow().state());
            signer.succeedAt(exact, deadline, (byte) 32);
            assertEquals(AsyncState.EXPIRED, bus.status(exact).orElseThrow().state());
            assertTrue(bus.consumeResult(exact).isEmpty());
            assertEquals(deadline, store.getSignRecord(exact).orElseThrow().providerUpdatedAt().orElseThrow());

            late = submit(bus, Duration.ofSeconds(10));
            assertEquals(AsyncState.RUNNING, bus.status(late).orElseThrow().state());
            signer.succeedAt(late, deadline.plusNanos(1), (byte) 33);
            assertEquals(AsyncState.EXPIRED, bus.status(late).orElseThrow().state());
            assertTrue(bus.consumeResult(late).isEmpty());
        }

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus replayed = new PkiSigningBus(reopened, signer, busLog, signingAuthority(signer))) {
            assertEquals(AsyncState.EXPIRED, replayed.status(exact).orElseThrow().state());
            assertTrue(replayed.consumeResult(exact).isEmpty());
            assertEquals(AsyncState.EXPIRED, replayed.status(late).orElseThrow().state());
            assertTrue(replayed.consumeResult(late).isEmpty());
            replayed.retireSignOperation(late, "late completion cleanup");
            assertEquals(SignWorkflowStore.State.RETIRED, reopened.getSignRecord(late).orElseThrow().state());
        }
    }

    @Test
    void signResultAdmissionAcceptsExactLimitAndRejectsOversizeWrongMissingAndMixed(@TempDir Path tempDir)
            throws Exception {
        Instant createdAt = Instant.parse("2026-06-07T08:09:10Z");
        MutableClock clock = new MutableClock(createdAt);
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            PkiId exact = submit(bus);
            assertEquals(AsyncState.RUNNING, bus.status(exact).orElseThrow().state());
            signer.succeedWith(exact, createdAt.plusSeconds(1), new SignatureWorkflow.OperationResult(
                    Optional.of(new EncodedObject(Encoding.BINARY, new byte[1_048_576])), Optional.empty()));
            assertEquals(AsyncState.SUCCEEDED, bus.status(exact).orElseThrow().state());

            PkiId oversize = submit(bus);
            assertEquals(AsyncState.RUNNING, bus.status(oversize).orElseThrow().state());
            signer.succeedWith(oversize, createdAt.plusSeconds(1), new SignatureWorkflow.OperationResult(
                    Optional.of(new EncodedObject(Encoding.BINARY, new byte[1_048_577])), Optional.empty()));
            assertInvalidProviderResult(bus, store, oversize);

            PkiId wrongEncoding = submit(bus);
            assertEquals(AsyncState.RUNNING, bus.status(wrongEncoding).orElseThrow().state());
            signer.succeedWith(wrongEncoding, createdAt.plusSeconds(1), new SignatureWorkflow.OperationResult(
                    Optional.of(new EncodedObject(Encoding.DER, new byte[] { 1 })), Optional.empty()));
            assertInvalidProviderResult(bus, store, wrongEncoding);

            PkiId missing = submit(bus);
            assertEquals(AsyncState.RUNNING, bus.status(missing).orElseThrow().state());
            signer.succeedWith(missing, createdAt.plusSeconds(1),
                    new SignatureWorkflow.OperationResult(Optional.empty(), Optional.empty()));
            assertInvalidProviderResult(bus, store, missing);

            PkiId mixed = submit(bus);
            assertEquals(AsyncState.RUNNING, bus.status(mixed).orElseThrow().state());
            signer.succeedWith(mixed, createdAt.plusSeconds(1), new SignatureWorkflow.OperationResult(
                    Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 1 })), Optional.of(true)));
            assertInvalidProviderResult(bus, store, mixed);
        }
    }

    private static void assertInvalidProviderResult(PkiSigningBus bus, FilesystemPkiStore store, PkiId operationId) {
        assertEquals(AsyncState.FAILED, bus.status(operationId).orElseThrow().state());
        SignWorkflowStore.Record failed = store.getSignRecord(operationId).orElseThrow();
        assertEquals(Optional.of("PROVIDER_RESULT_INVALID"), failed.detailCode());
        assertEquals(Optional.empty(), failed.result());
    }

    @Test
    void rejectedCancellationReconcilesProviderSuccessBeforeRetirement(@TempDir Path tempDir) throws Exception {
        CancelRejectedAfterCompletionWorkflow signer = new CancelRejectedAfterCompletionWorkflow();
        Path storeRoot = tempDir.resolve("store");
        Path busLog = tempDir.resolve("bus.log");
        PkiId id;
        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, signer, busLog, signingAuthority(signer))) {
            id = submit(bus);
            assertEquals(AsyncState.RUNNING, bus.status(id).orElseThrow().state());
            bus.retireSignOperation(id, "provider completed");
            SignWorkflowStore.Record retired = store.getSignRecord(id).orElseThrow();
            assertEquals(SignWorkflowStore.State.RETIRED, retired.state());
            assertArrayEquals(new byte[] { 11, 12 }, retired.result().orElseThrow().bytes());
            assertFalse(PkiSigningBus.SignContinuation.decode(retired.request(), store.stagedContent())
                    .hasLiveContent());
            assertEquals(1, signer.cancellations.get());
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults());
                PkiSigningBus replayed = new PkiSigningBus(reopened, signer, busLog, signingAuthority(signer))) {
            assertEquals(AsyncState.SUCCEEDED, replayed.status(id).orElseThrow().state());
            assertArrayEquals(new byte[] { 11, 12 }, replayed.consumeResult(id).orElseThrow().bytes());
            assertFalse(PkiSigningBus.SignContinuation
                    .decode(reopened.getSignRecord(id).orElseThrow().request(), reopened.stagedContent())
                    .hasLiveContent());
        }
    }

    @Test
    void providerCallbackReturnsWhileSameOperationSubmissionIsBlocked(@TempDir Path tempDir) throws Exception {
        BlockingWorkflow signer = new BlockingWorkflow();
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"), FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer));
                ExecutorService executor = Executors.newFixedThreadPool(2)) {
            PkiId id = submit(bus);
            Future<?> submission = executor.submit(() -> bus.status(id));
            assertTrue(signer.entered.await(5, TimeUnit.SECONDS));
            Future<?> callback = executor.submit(() -> signer.completeAndNotify(id));
            callback.get(5, TimeUnit.SECONDS);
            signer.release.countDown();
            submission.get(5, TimeUnit.SECONDS);
            assertEquals(AsyncState.SUCCEEDED, bus.status(id).orElseThrow().state());
            assertArrayEquals(new byte[] { 13 }, bus.consumeResult(id).orElseThrow().bytes());
        }
    }

    @Test
    void cancellingOperationReplaysAfterRestart(@TempDir Path tempDir) throws Exception {
        RetirementRaceWorkflow signer = new RetirementRaceWorkflow();
        Path storeRoot = tempDir.resolve("store");
        Path busLog = tempDir.resolve("bus.log");
        PkiId id;
        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, signer, busLog, signingAuthority(signer))) {
            id = submit(bus);
            assertEquals(AsyncState.RUNNING, bus.status(id).orElseThrow().state());
            SignWorkflowStore.Record dispatched = store.getSignRecord(id).orElseThrow();
            store.transitionSign(id, dispatched.revision(), dispatched.fence(), SignWorkflowStore.State.CANCELLING,
                    Optional.of("CANCEL_REQUESTED"), Optional.empty(), Optional.empty()).orElseThrow();
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults());
                PkiSigningBus replayed = new PkiSigningBus(reopened, signer, busLog, signingAuthority(signer))) {
            assertEquals(AsyncState.RUNNING, replayed.status(id).orElseThrow().state());
            replayed.retireSignOperation(id, "restart cancellation");
            assertEquals(SignWorkflowStore.State.RETIRED, reopened.getSignRecord(id).orElseThrow().state());
            assertEquals(1, signer.cancellations.get());
        }
    }

    @Test
    void retirementReconcilesCompletionAndAdvisoryCallbackWithoutResultLoss(@TempDir Path tempDir) throws Exception {
        RetirementRaceWorkflow signer = new RetirementRaceWorkflow();
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"), FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer));
                ExecutorService executor = Executors.newFixedThreadPool(2)) {
            PkiId id = submit(bus);
            assertEquals(AsyncState.RUNNING, bus.status(id).orElseThrow().state());
            signer.armStatusBlock();

            Future<?> retirement = executor.submit(() -> bus.retireSignOperation(id, "completed concurrently"));
            assertTrue(signer.statusEntered.await(5, TimeUnit.SECONDS));
            Future<?> callback = executor.submit(signer::completeAndNotify);
            retirement.get(5, TimeUnit.SECONDS);
            callback.get(5, TimeUnit.SECONDS);

            assertEquals(SignWorkflowStore.State.RETIRED, store.getSignRecord(id).orElseThrow().state());
            assertEquals(7, store.getSignRecord(id).orElseThrow().result().orElseThrow().bytes()[0]);
            assertEquals(AsyncState.SUCCEEDED, bus.status(id).orElseThrow().state());
            assertEquals(7, bus.consumeResult(id).orElseThrow().bytes()[0]);
            assertEquals(1, signer.submissions.get());
            assertEquals(0, signer.cancellations.get());
        }
    }

    @Test
    void pollAndRetirementSerializeAndPreserveProviderCompletion(@TempDir Path tempDir) throws Exception {
        RetirementRaceWorkflow signer = new RetirementRaceWorkflow();
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"), FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer));
                ExecutorService executor = Executors.newFixedThreadPool(2)) {
            PkiId id = submit(bus);
            assertEquals(AsyncState.RUNNING, bus.status(id).orElseThrow().state());
            signer.armStatusBlock();

            Future<?> poll = executor.submit(() -> bus.status(id));
            assertTrue(signer.statusEntered.await(5, TimeUnit.SECONDS));
            Future<?> retirement = executor.submit(() -> bus.retireSignOperation(id, "poll race"));
            signer.completeWithoutNotification();
            poll.get(5, TimeUnit.SECONDS);
            retirement.get(5, TimeUnit.SECONDS);

            assertEquals(7, bus.consumeResult(id).orElseThrow().bytes()[0]);
            assertEquals(1, signer.submissions.get());
            assertEquals(0, signer.cancellations.get());
        }
    }

    @Test
    void consumeAndRetirementShareCoordinatorWithoutResultLoss(@TempDir Path tempDir) throws Exception {
        RetirementRaceWorkflow signer = new RetirementRaceWorkflow();
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"), FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer));
                ExecutorService executor = Executors.newFixedThreadPool(2)) {
            PkiId id = submit(bus);
            assertEquals(AsyncState.RUNNING, bus.status(id).orElseThrow().state());
            signer.completeWithoutNotification();
            CountDownLatch start = new CountDownLatch(1);
            Future<Optional<EncodedObject>> consumed = executor.submit(() -> {
                start.await();
                return bus.consumeResult(id);
            });
            Future<?> retirement = executor.submit(() -> {
                start.await();
                bus.retireSignOperation(id, "consume race");
                return null;
            });
            start.countDown();
            retirement.get(5, TimeUnit.SECONDS);
            Optional<EncodedObject> concurrentObservation = consumed.get(5, TimeUnit.SECONDS);
            concurrentObservation.ifPresent(result -> assertEquals(7, result.bytes()[0]));
            assertEquals(7, bus.consumeResult(id).orElseThrow().bytes()[0]);
            assertEquals(1, signer.submissions.get());
        }
    }

    @Test
    void preDispatchExpiryMakesNoProviderCallAndPurgesOnlyAfterRetirement(@TempDir Path tempDir) throws Exception {
        Instant createdAt = Instant.parse("2026-05-06T07:08:09Z");
        MutableClock clock = new MutableClock(createdAt);
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"), FsPkiStoreOptions.defaults(),
                clock); PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            PkiId id = submit(bus, Duration.ofSeconds(10));
            assertEquals(1, store.listWorkflowStates().size());
            clock.set(createdAt.plusSeconds(10));
            bus.sweep(clock.instant());
            assertEquals(0, signer.submissions.get());
            assertEquals(SignWorkflowStore.State.RETIRED, store.getSignRecord(id).orElseThrow().state());
            assertTrue(bus.consumeResult(id).isEmpty());
            assertTrue(store.listWorkflowStates().isEmpty());

            clock.set(createdAt.plus(Duration.ofDays(90)));
            bus.sweep(clock.instant());
            assertTrue(store.listSignRecords().isEmpty());
            assertEquals(AsyncState.EXPIRED, bus.status(id).orElseThrow().state());
        }
    }

    @Test
    void postDispatchExpiryRetainsAuthorityUntilProviderTerminalReconciliation(@TempDir Path tempDir) throws Exception {
        Instant createdAt = Instant.parse("2026-05-06T07:08:09Z");
        MutableClock clock = new MutableClock(createdAt);
        AcceptedDelayedCancellationWorkflow signer = new AcceptedDelayedCancellationWorkflow(clock);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"), FsPkiStoreOptions.defaults(),
                clock); PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            PkiId id = submit(bus, Duration.ofSeconds(10));
            assertEquals(AsyncState.RUNNING, bus.status(id).orElseThrow().state());
            assertEquals(1, signer.submissions.get());

            clock.set(createdAt.plusSeconds(10));
            bus.sweep(clock.instant());
            assertEquals(SignWorkflowStore.State.CANCELLING, store.getSignRecord(id).orElseThrow().state());
            assertEquals("CANCEL_SUBMITTED", store.getSignRecord(id).orElseThrow().detailCode().orElseThrow());
            assertEquals(1, signer.cancellations.get());
            assertEquals(1, store.listWorkflowStates().size());
            assertTrue(bus.consumeResult(id).isEmpty());

            bus.sweep(clock.instant());
            assertEquals(1, signer.cancellations.get());
            assertEquals(SignWorkflowStore.State.CANCELLING, store.getSignRecord(id).orElseThrow().state());

            signer.completeCancelled(id, clock.instant());
            bus.sweep(clock.instant());
            assertEquals(SignWorkflowStore.State.RETIRED, store.getSignRecord(id).orElseThrow().state());
            assertTrue(store.listWorkflowStates().isEmpty());
            assertTrue(bus.consumeResult(id).isEmpty());

            clock.set(createdAt.plus(Duration.ofDays(90)));
            bus.sweep(clock.instant());
            assertTrue(store.listSignRecords().isEmpty());
        }
    }

    @Test
    void blockedProviderCannotRedispatchAfterLeaseExpiry(@TempDir Path tempDir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-05-06T07:08:09Z"));
        BlockingWorkflow signer = new BlockingWorkflow();
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"), FsPkiStoreOptions.defaults(),
                clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer));
                ExecutorService executor = Executors.newFixedThreadPool(2)) {
            Principal owner = new Principal("TEST", "owner");
            PkiId id = bus.newSubmissionId();
            EncodedObject payload = new EncodedObject(Encoding.BINARY, new byte[] { 1 });
            DurableContentReference content = stage(bus, payload);
            AccessContext access = new AccessContext(owner, new Purpose("TEST"), Optional.empty(), Optional.empty());
            PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(access, "SHA256withRSA",
                    content, new KeyRef("test"), Encoding.BINARY, Optional.empty());
            bus.submitSign(id, owner, new KeyRef("test"), "SHA256withRSA", content, Duration.ofMinutes(5),
                    Optional.of(continuation.encode()));
            Future<?> first = executor.submit(() -> bus.status(id));
            assertTrue(signer.entered.await(5, TimeUnit.SECONDS));
            clock.set(clock.instant().plusSeconds(60));
            CountDownLatch secondStarted = new CountDownLatch(1);
            Future<?> second = executor.submit(() -> {
                secondStarted.countDown();
                return bus.status(id);
            });
            assertTrue(secondStarted.await(5, TimeUnit.SECONDS));
            assertEquals(1, signer.submissions.get());
            second.get(5, TimeUnit.SECONDS);
            signer.release.countDown();
            java.util.concurrent.ExecutionException late = assertThrows(java.util.concurrent.ExecutionException.class,
                    () -> first.get(5, TimeUnit.SECONDS));
            assertInstanceOf(IllegalStateException.class, late.getCause());
            assertEquals(SignWorkflowStore.State.INTENT, store.getSignRecord(id).orElseThrow().state());
            assertEquals(1, signer.submissions.get());
        }
    }

    @Test
    void providerCallsPermitCrossThreadReentryOutsideOperationLock(@TempDir Path tempDir) throws Exception {
        CrossThreadReentrantWorkflow signer = new CrossThreadReentrantWorkflow();
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"), FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            signer.attach(bus);
            PkiId id = submit(bus);
            assertEquals(AsyncState.RUNNING, bus.status(id).orElseThrow().state());
            bus.retireSignOperation(id, "reentrant cancellation");
            assertEquals(SignWorkflowStore.State.RETIRED, store.getSignRecord(id).orElseThrow().state());
            assertEquals(1, signer.submissions.get());
            assertTrue(signer.statusReads.get() >= 2);
            assertEquals(1, signer.cancellations.get());
        } finally {
            signer.close();
        }
    }

    @Test
    void blockedSubmissionDoesNotBlockAnotherOperation(@TempDir Path tempDir) throws Exception {
        SelectiveBlockingWorkflow signer = new SelectiveBlockingWorkflow();
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"), FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer));
                ExecutorService executor = Executors.newFixedThreadPool(2)) {
            PkiId blocked = submit(bus);
            Future<?> first = executor.submit(() -> bus.status(blocked));
            assertTrue(signer.blockedEntered.await(5, TimeUnit.SECONDS));

            PkiId independent = submit(bus);
            Future<Optional<zeroecho.pki.util.async.AsyncStatus>> second = executor
                    .submit(() -> bus.status(independent));
            assertEquals(AsyncState.RUNNING, second.get(5, TimeUnit.SECONDS).orElseThrow().state());
            assertEquals(2, signer.submissions.get());

            signer.blockedRelease.countDown();
            first.get(5, TimeUnit.SECONDS);
        }
    }

    @Test
    void providerStatusExceptionReleasesSingleFlightReservation(@TempDir Path tempDir) throws Exception {
        ThrowOnceStatusWorkflow signer = new ThrowOnceStatusWorkflow();
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"), FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            PkiId id = submit(bus);
            PkiException sanitized = assertThrows(PkiException.class, () -> bus.status(id));
            assertTrue(sanitized.getMessage().contains("PROVIDER_STATUS_FAILED"));
            assertFalse(sanitized.getMessage().contains("injected status failure"));
            assertNull(sanitized.getCause());
            assertEquals(0, sanitized.getSuppressed().length);
            assertEquals(AsyncState.RUNNING, bus.status(id).orElseThrow().state());
            assertEquals(2, signer.statusReads.get());
        }
    }

    @Test
    void unsupportedContinuationVersionCannotActivate(@TempDir Path tempDir) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults())) {
            Principal owner = new Principal("SYSTEM", "pki");
            Instant now = Instant.now();
            EncodedObject unsupported = new EncodedObject(Encoding.BINARY, new byte[] { 99 });
            store.putWorkflowState(new WorkflowStateRecord(new PkiId("unsupported-sign"), PkiSigningBus.TYPE_SIGN,
                    owner, OrchestrationDurabilityPolicy.DURABLE_MIN_STATE, now, now, now.plusSeconds(60),
                    Encoding.BINARY, Optional.of(unsupported)));
            InMemorySignatureWorkflow signer = new InMemorySignatureWorkflow(Map.of(), false);
            try {
                assertThrows(PkiException.class,
                        () -> new PkiSigningBus(store, signer, tempDir.resolve("unsupported-bus.log"),
                                signingAuthority(signer)));
            } finally {
                signer.close();
            }
        }
    }

    @Test
    void advisoryProjectionFailureDoesNotOverrideAuthoritativeWorkflow(@TempDir Path tempDir) throws Exception {
        FilesystemPkiStore delegate = new FilesystemPkiStore(tempDir.resolve("store"), FsPkiStoreOptions.defaults());
        AtomicInteger writes = new AtomicInteger();
        PkiStore failingStore = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class }, (proxy, method, arguments) -> {
                    if ("putWorkflowState".equals(method.getName()) && writes.incrementAndGet() == 1) {
                        throw new IllegalStateException("injected continuation failure");
                    }
                    try {
                        return method.invoke(delegate, arguments);
                    } catch (InvocationTargetException ex) {
                        throw ex.getCause();
                    }
                });

        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        KeyRef keyRef = new KeyRef("kref:v1:keyring:test:failure");
        InMemorySignatureWorkflow signer = new InMemorySignatureWorkflow(Map.of(keyRef.value(), keyPair), false);
        Path busLog = tempDir.resolve("bus.log");
        Principal owner = new Principal("SYSTEM", "pki");
        PkiId operationId;
        try (PkiSigningBus bus = new PkiSigningBus(failingStore, signer, busLog, signingAuthority(signer))) {
            operationId = bus.canonicalizeOperationId(new PkiId("sign:failure"), owner);
            EncodedObject payload = new EncodedObject(Encoding.BINARY, new byte[] { 1, 2, 3 });
            DurableContentReference content = stage(bus, payload);
            AccessContext access = new AccessContext(owner, new Purpose("TEST"), Optional.empty(), Optional.empty());
            PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(access, "SHA256withRSA",
                    content, keyRef, Encoding.BINARY, Optional.empty());
            bus.submitSign(operationId, owner, keyRef, "SHA256withRSA", content, Duration.ofSeconds(5),
                    Optional.of(continuation.encode()));
            bus.sweep(java.time.Instant.now());

            assertEquals(AsyncState.RUNNING, bus.status(operationId).orElseThrow().state());
            assertTrue(delegate.listWorkflowStates().isEmpty());
            assertTrue(signer.hasRunningOperations());
            bus.retireSignOperation(operationId, "test complete");
            assertFalse(signer.hasRunningOperations());
        }

        try (PkiSigningBus replayed = new PkiSigningBus(delegate, signer, busLog, signingAuthority(signer))) {
            assertEquals(AsyncState.CANCELLED, replayed.status(operationId).orElseThrow().state());
        } finally {
            signer.close();
            delegate.close();
        }
    }

    private static PkiId submit(PkiSigningBus bus) {
        return submit(bus, Duration.ofMinutes(5));
    }

    private static SigningReconciliationRequest reconciliation(Optional<String> cursor, int maximumRecords,
            int maximumCalls, Clock clock) {
        return new SigningReconciliationRequest(cursor, maximumRecords, maximumCalls,
                clock.instant().plusSeconds(30), Duration.ofSeconds(10), () -> false);
    }

    private static PkiStore faultingStore(PkiStore delegate, String methodName,
            AtomicReference<PkiId> target, AtomicBoolean armed) {
        return faultingStore(delegate, methodName, target, armed,
                new IllegalStateException("injected candidate-local store failure"));
    }

    private static PkiStore faultingStore(PkiStore delegate, String methodName,
            AtomicReference<PkiId> target, AtomicBoolean armed, RuntimeException injectedFailure) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, arguments) -> {
                    if (methodName.equals(method.getName()) && arguments != null && arguments.length > 0
                            && target.get() != null && target.get().equals(arguments[0])
                            && armed.compareAndSet(true, false)) {
                        throw injectedFailure;
                    }
                    try {
                        return method.invoke(delegate, arguments);
                    } catch (InvocationTargetException failure) {
                        throw failure.getCause();
                    }
                });
    }

    private static void requestCancellation(SignWorkflowStore store, PkiId id) {
        SignWorkflowStore.Record dispatched = store.getSignRecord(id).orElseThrow();
        store.transitionSign(id, dispatched.revision(), dispatched.fence(), SignWorkflowStore.State.CANCELLING,
                Optional.of("CANCEL_REQUESTED"), Optional.empty(), Optional.empty()).orElseThrow();
    }

    private static PkiId submit(PkiSigningBus bus, Duration ttl) {
        Principal owner = new Principal("TEST", "owner");
        PkiId id = bus.newSubmissionId();
        EncodedObject payload = new EncodedObject(Encoding.BINARY, new byte[] { 1 });
        DurableContentReference content;
        try {
            content = stage(bus, payload);
        } catch (java.io.IOException exception) {
            throw new IllegalStateException("Test content staging failed", exception);
        }
        AccessContext access = new AccessContext(owner, new Purpose("TEST"), Optional.empty(), Optional.empty());
        PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(access, "SHA256withRSA",
                content, new KeyRef("test"), Encoding.BINARY, Optional.empty());
        bus.submitSign(id, owner, new KeyRef("test"), "SHA256withRSA", content, ttl,
                Optional.of(continuation.encode()));
        return id;
    }

    private static AlgorithmExecutionCapability exactWorkflowCapability(String implementationId,
            AlgorithmExecutionCapability.Direction supportedDirection) {
        return new AlgorithmExecutionCapability() {
            @Override
            public String implementationId() {
                return implementationId;
            }

            @Override
            public String domainFingerprint() {
                return "constructor-test-v1:" + supportedDirection;
            }

            @Override
            public boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction direction) {
                return direction == supportedDirection
                        && BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.equals(identity)
                        && BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY.equals(suite.publicKey());
            }
        };
    }

    private static X509AlgorithmResolver.Policy allowPolicy(String fingerprint) {
        return new X509AlgorithmResolver.Policy() {
            @Override
            public boolean permits(AlgorithmSuite suite, AlgorithmExecutionCapability.Direction direction) {
                return true;
            }

            @Override
            public String semanticFingerprint() {
                return fingerprint;
            }
        };
    }

    private static final class ThrowingCancellationWorkflow implements SignatureWorkflow {
        private final Clock clock;
        private final Map<PkiId, OperationStatus> statuses = new java.util.concurrent.ConcurrentHashMap<>();
        private final AtomicInteger statusReads = new AtomicInteger();
        private final AtomicInteger cancellations = new AtomicInteger();

        private ThrowingCancellationWorkflow(Clock clock) {
            this.clock = clock;
        }

        @Override
        public String id() {
            return "throwing-cancellation";
        }

        @Override
        public PkiId submitSign(SignRequest request, CallControl control) {
            statuses.put(request.submissionId(),
                    new OperationStatus(State.RUNNING, clock.instant(), Optional.of("RUNNING"), Optional.empty()));
            return request.submissionId();
        }

        @Override
        public PkiId submitVerify(VerifyRequest request, CallControl control) {
            throw new UnsupportedOperationException();
        }

        @Override
        public OperationStatus status(PkiId operationId, CallControl control) {
            statusReads.incrementAndGet();
            return statuses.get(operationId);
        }

        @Override
        public boolean cancel(PkiId operationId, long fencingToken, String reason, CallControl control) {
            cancellations.incrementAndGet();
            throw new IllegalStateException("accepted outcome is deliberately uncertain");
        }

        @Override
        public Registration register(NotificationSink sink) {
            return () -> { };
        }

        @Override
        public Set<String> supportedAlgorithms() {
            return Set.of("SHA256withRSA");
        }

        @Override
        public void close() {
            // No owned resources.
        }

        private void resetObservations() {
            statusReads.set(0);
            cancellations.set(0);
        }
    }

    private static final class AcceptedThenThrowsWorkflow implements SignatureWorkflow {
        private final Clock clock;
        private final Map<PkiId, OperationStatus> statuses = new java.util.concurrent.ConcurrentHashMap<>();
        private final AtomicInteger submissions = new AtomicInteger();
        private final AtomicInteger statusReads = new AtomicInteger();
        private final AtomicInteger cancellations = new AtomicInteger();

        private AcceptedThenThrowsWorkflow(Clock clock) {
            this.clock = clock;
        }

        @Override
        public String id() {
            return "accepted-then-throws";
        }

        @Override
        public PkiId submitSign(SignRequest request, CallControl control) {
            submissions.incrementAndGet();
            statuses.putIfAbsent(request.submissionId(),
                    new OperationStatus(State.RUNNING, clock.instant(), Optional.of("RUNNING"), Optional.empty()));
            throw new IllegalStateException("accepted before transport failure");
        }

        @Override
        public PkiId submitVerify(VerifyRequest request, CallControl control) {
            throw new UnsupportedOperationException();
        }

        @Override
        public OperationStatus status(PkiId operationId, CallControl control) {
            statusReads.incrementAndGet();
            return statuses.get(operationId);
        }

        @Override
        public boolean cancel(PkiId operationId, long fencingToken, String reason, CallControl control) {
            cancellations.incrementAndGet();
            statuses.put(operationId,
                    new OperationStatus(State.CANCELLED, clock.instant(), Optional.of("CANCELLED"), Optional.empty()));
            return true;
        }

        @Override
        public Registration register(NotificationSink sink) {
            return () -> { };
        }

        @Override
        public Set<String> supportedAlgorithms() {
            return Set.of("SHA256withRSA");
        }

        @Override
        public void close() {
            // Shared durable-provider simulation remains available across bus restart.
        }
    }

    private static final class AcceptedDelayedCancellationWorkflow implements SignatureWorkflow {
        private final Clock clock;
        private final Map<PkiId, OperationStatus> statuses = new java.util.concurrent.ConcurrentHashMap<>();
        private final AtomicInteger submissions = new AtomicInteger();
        private final AtomicInteger cancellations = new AtomicInteger();

        private AcceptedDelayedCancellationWorkflow() {
            this(Clock.systemUTC());
        }

        private AcceptedDelayedCancellationWorkflow(Clock clock) {
            this.clock = clock;
        }

        @Override
        public String id() {
            return "accepted-delayed-cancellation";
        }

        @Override
        public PkiId submitSign(SignRequest request, CallControl control) {
            submissions.incrementAndGet();
            statuses.put(request.submissionId(),
                    new OperationStatus(State.RUNNING, clock.instant(), Optional.of("RUNNING"), Optional.empty()));
            return request.submissionId();
        }

        @Override
        public PkiId submitVerify(VerifyRequest request, CallControl control) {
            throw new UnsupportedOperationException();
        }

        @Override
        public OperationStatus status(PkiId operationId, CallControl control) {
            return statuses.get(operationId);
        }

        @Override
        public boolean cancel(PkiId operationId, long fencingToken, String reason, CallControl control) {
            cancellations.incrementAndGet();
            return true;
        }

        @Override
        public Registration register(NotificationSink sink) {
            return () -> {
                // Polling is authoritative.
            };
        }

        @Override
        public Set<String> supportedAlgorithms() {
            return Set.of("SHA256withRSA");
        }

        @Override
        public void close() {
            // No owned resources.
        }

        private void completeSuccessfully(PkiId operationId) {
            OperationResult result = new OperationResult(
                    Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 21 })), Optional.empty());
            statuses.put(operationId,
                    new OperationStatus(State.SUCCEEDED, Instant.now(), Optional.of("SIGNED"), Optional.of(result)));
        }

        private void completeCancelled(PkiId operationId, Instant completedAt) {
            statuses.put(operationId,
                    new OperationStatus(State.CANCELLED, completedAt, Optional.of("CANCELLED"), Optional.empty()));
        }
    }

    private static final class ControlledWorkflow implements SignatureWorkflow {
        private final Clock clock;
        private final Map<PkiId, OperationStatus> statuses = new java.util.concurrent.ConcurrentHashMap<>();
        private final AtomicInteger submissions = new AtomicInteger();
        private final AtomicInteger cancellations = new AtomicInteger();

        private ControlledWorkflow(Clock clock) {
            this.clock = clock;
        }

        @Override
        public String id() {
            return "controlled";
        }

        @Override
        public PkiId submitSign(SignRequest request, CallControl control) {
            submissions.incrementAndGet();
            statuses.put(request.submissionId(),
                    new OperationStatus(State.RUNNING, clock.instant(), Optional.of("RUNNING"), Optional.empty()));
            return request.submissionId();
        }

        @Override
        public PkiId submitVerify(VerifyRequest request, CallControl control) {
            throw new UnsupportedOperationException();
        }

        @Override
        public OperationStatus status(PkiId operationId, CallControl control) {
            return statuses.get(operationId);
        }

        @Override
        public boolean cancel(PkiId operationId, long fencingToken, String reason, CallControl control) {
            cancellations.incrementAndGet();
            statuses.put(operationId,
                    new OperationStatus(State.CANCELLED, clock.instant(), Optional.of("CANCELLED"), Optional.empty()));
            return true;
        }

        @Override
        public Registration register(NotificationSink sink) {
            return () -> {
                // Polling is authoritative.
            };
        }

        @Override
        public Set<String> supportedAlgorithms() {
            return Set.of("SHA256withRSA");
        }

        @Override
        public void close() {
            // No owned resources.
        }

        private void succeedAt(PkiId operationId, Instant completedAt, byte value) {
            OperationResult result = new OperationResult(
                    Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { value })), Optional.empty());
            succeedWith(operationId, completedAt, result);
        }

        private void succeedWith(PkiId operationId, Instant completedAt, OperationResult result) {
            statuses.put(operationId,
                    new OperationStatus(State.SUCCEEDED, completedAt, Optional.of("SIGNED"), Optional.of(result)));
        }
    }

    private static final class RetirementRaceWorkflow implements SignatureWorkflow {
        private final AtomicReference<OperationStatus> status = new AtomicReference<>(
                new OperationStatus(State.RUNNING, Instant.EPOCH, Optional.of("RUNNING"), Optional.empty()));
        private final AtomicReference<PkiId> operationId = new AtomicReference<>();
        private final AtomicReference<NotificationSink> sink = new AtomicReference<>();
        private final AtomicBoolean blockStatus = new AtomicBoolean();
        private final CountDownLatch statusEntered = new CountDownLatch(1);
        private final CountDownLatch statusRelease = new CountDownLatch(1);
        private final AtomicInteger submissions = new AtomicInteger();
        private final AtomicInteger cancellations = new AtomicInteger();

        @Override
        public String id() {
            return "retirement-race";
        }

        @Override
        public PkiId submitSign(SignRequest request, CallControl control) {
            submissions.incrementAndGet();
            operationId.set(request.submissionId());
            status.set(new OperationStatus(State.RUNNING, Instant.now(), Optional.of("RUNNING"), Optional.empty()));
            return request.submissionId();
        }

        @Override
        public PkiId submitVerify(VerifyRequest request, CallControl control) {
            throw new UnsupportedOperationException();
        }

        @Override
        public OperationStatus status(PkiId operationId, CallControl control) {
            if (blockStatus.compareAndSet(true, false)) {
                statusEntered.countDown();
                try {
                    statusRelease.await();
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(ex);
                }
            }
            return status.get();
        }

        @Override
        public boolean cancel(PkiId operationId, long fencingToken, String reason, CallControl control) {
            OperationStatus current = status.get();
            if (current.isTerminal()) {
                return false;
            }
            cancellations.incrementAndGet();
            status.set(new OperationStatus(State.CANCELLED, Instant.now(), Optional.of("CANCELLED"), Optional.empty()));
            return true;
        }

        @Override
        public Registration register(NotificationSink notificationSink) {
            sink.set(notificationSink);
            return () -> sink.compareAndSet(notificationSink, null);
        }

        @Override
        public Set<String> supportedAlgorithms() {
            return Set.of("SHA256withRSA");
        }

        @Override
        public void close() {
            statusRelease.countDown();
        }

        private void armStatusBlock() {
            blockStatus.set(true);
        }

        private void completeWithoutNotification() {
            OperationResult result = new OperationResult(
                    Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 7 })), Optional.empty());
            status.set(new OperationStatus(State.SUCCEEDED, Instant.now(), Optional.of("SIGNED"), Optional.of(result)));
            statusRelease.countDown();
        }

        private void completeAndNotify() {
            completeWithoutNotification();
            NotificationSink registered = sink.get();
            if (registered != null) {
                registered.onStatusChanged(operationId.get(),
                        new OperationStatus(State.FAILED, Instant.now(), Optional.of("ADVISORY"), Optional.empty()));
            }
        }
    }

    private static final class CancelRejectedAfterCompletionWorkflow implements SignatureWorkflow {
        private final AtomicReference<OperationStatus> status = new AtomicReference<>(
                new OperationStatus(State.RUNNING, Instant.EPOCH, Optional.of("RUNNING"), Optional.empty()));
        private final AtomicInteger cancellations = new AtomicInteger();

        @Override
        public String id() {
            return "cancel-rejected-after-completion";
        }

        @Override
        public PkiId submitSign(SignRequest request, CallControl control) {
            status.set(new OperationStatus(State.RUNNING, Instant.now(), Optional.of("RUNNING"), Optional.empty()));
            return request.submissionId();
        }

        @Override
        public PkiId submitVerify(VerifyRequest request, CallControl control) {
            throw new UnsupportedOperationException();
        }

        @Override
        public OperationStatus status(PkiId operationId, CallControl control) {
            return status.get();
        }

        @Override
        public boolean cancel(PkiId operationId, long fencingToken, String reason, CallControl control) {
            cancellations.incrementAndGet();
            OperationResult result = new OperationResult(
                    Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 11, 12 })), Optional.empty());
            status.set(new OperationStatus(State.SUCCEEDED, Instant.now(), Optional.of("SIGNED"), Optional.of(result)));
            return false;
        }

        @Override
        public Registration register(NotificationSink sink) {
            return () -> {
                // No callback is required for authoritative reconciliation.
            };
        }

        @Override
        public Set<String> supportedAlgorithms() {
            return Set.of("SHA256withRSA");
        }

        @Override
        public void close() {
            // No owned resources.
        }
    }

    private static final class BlockingWorkflow implements SignatureWorkflow {
        private final CountDownLatch entered = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);
        private final AtomicInteger submissions = new AtomicInteger();
        private final Map<PkiId, OperationStatus> statuses = new java.util.concurrent.ConcurrentHashMap<>();
        private final AtomicReference<NotificationSink> sink = new AtomicReference<>();

        @Override
        public String id() {
            return "blocking-test";
        }

        @Override
        public PkiId submitSign(SignRequest request, CallControl control) {
            submissions.incrementAndGet();
            statuses.put(request.submissionId(),
                    new OperationStatus(State.RUNNING, Instant.now(), Optional.of("RUNNING"), Optional.empty()));
            entered.countDown();
            try {
                release.await();
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(ex);
            }
            return request.submissionId();
        }

        @Override
        public PkiId submitVerify(VerifyRequest request, CallControl control) {
            throw new UnsupportedOperationException();
        }

        @Override
        public OperationStatus status(PkiId operationId, CallControl control) {
            return statuses.get(operationId);
        }

        @Override
        public boolean cancel(PkiId operationId, long fencingToken, String reason, CallControl control) {
            return false;
        }

        @Override
        public Registration register(NotificationSink sink) {
            this.sink.set(sink);
            return () -> this.sink.compareAndSet(sink, null);
        }

        @Override
        public Set<String> supportedAlgorithms() {
            return Set.of("SHA256withRSA");
        }

        @Override
        public void close() {
            release.countDown();
        }

        private void completeAndNotify(PkiId operationId) {
            OperationResult result = new OperationResult(
                    Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 13 })), Optional.empty());
            OperationStatus succeeded = new OperationStatus(State.SUCCEEDED, Instant.now(), Optional.of("SIGNED"),
                    Optional.of(result));
            statuses.put(operationId, succeeded);
            NotificationSink registered = sink.get();
            if (registered != null) {
                registered.onStatusChanged(operationId, succeeded);
            }
        }
    }

    private static final class CrossThreadReentrantWorkflow implements SignatureWorkflow {
        private final AtomicReference<PkiSigningBus> bus = new AtomicReference<>();
        private final AtomicReference<OperationStatus> status = new AtomicReference<>();
        private final ExecutorService reentrantExecutor = Executors.newSingleThreadExecutor();
        private final AtomicInteger submissions = new AtomicInteger();
        private final AtomicInteger statusReads = new AtomicInteger();
        private final AtomicInteger cancellations = new AtomicInteger();

        private void attach(PkiSigningBus attached) {
            bus.set(attached);
        }

        @Override
        public String id() {
            return "cross-thread-reentrant";
        }

        @Override
        public PkiId submitSign(SignRequest request, CallControl control) {
            submissions.incrementAndGet();
            status.set(new OperationStatus(State.RUNNING, Instant.now(), Optional.of("RUNNING"), Optional.empty()));
            reenterStatus(request.submissionId());
            return request.submissionId();
        }

        @Override
        public PkiId submitVerify(VerifyRequest request, CallControl control) {
            throw new UnsupportedOperationException();
        }

        @Override
        public OperationStatus status(PkiId requested, CallControl control) {
            statusReads.incrementAndGet();
            reenterStatus(requested);
            return status.get();
        }

        @Override
        public boolean cancel(PkiId requested, long fencingToken, String reason, CallControl control) {
            cancellations.incrementAndGet();
            reenterStatus(requested);
            status.set(new OperationStatus(State.CANCELLED, Instant.now(), Optional.of("CANCELLED"), Optional.empty()));
            return true;
        }

        private void reenterStatus(PkiId requested) {
            try {
                reentrantExecutor.submit(() -> bus.get().status(requested)).get(5, TimeUnit.SECONDS);
            } catch (Exception failure) {
                throw new IllegalStateException("Cross-thread provider reentry failed", failure);
            }
        }

        @Override
        public Registration register(NotificationSink sink) {
            return () -> {
                // Polling is authoritative.
            };
        }

        @Override
        public Set<String> supportedAlgorithms() {
            return Set.of("SHA256withRSA");
        }

        @Override
        public void close() {
            reentrantExecutor.shutdownNow();
        }
    }

    private static final class SelectiveBlockingWorkflow implements SignatureWorkflow {
        private final AtomicReference<PkiId> blockedOperation = new AtomicReference<>();
        private final Map<PkiId, OperationStatus> statuses = new java.util.concurrent.ConcurrentHashMap<>();
        private final CountDownLatch blockedEntered = new CountDownLatch(1);
        private final CountDownLatch blockedRelease = new CountDownLatch(1);
        private final AtomicInteger submissions = new AtomicInteger();

        @Override
        public String id() {
            return "selective-blocking";
        }

        @Override
        public PkiId submitSign(SignRequest request, CallControl control) {
            submissions.incrementAndGet();
            statuses.put(request.submissionId(),
                    new OperationStatus(State.RUNNING, Instant.now(), Optional.of("RUNNING"), Optional.empty()));
            if (blockedOperation.compareAndSet(null, request.submissionId())
                    || blockedOperation.get().equals(request.submissionId())) {
                blockedEntered.countDown();
                try {
                    blockedRelease.await();
                } catch (InterruptedException failure) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(failure);
                }
            }
            return request.submissionId();
        }

        @Override
        public PkiId submitVerify(VerifyRequest request, CallControl control) {
            throw new UnsupportedOperationException();
        }

        @Override
        public OperationStatus status(PkiId operationId, CallControl control) {
            return statuses.get(operationId);
        }

        @Override
        public boolean cancel(PkiId operationId, long fencingToken, String reason, CallControl control) {
            statuses.put(operationId,
                    new OperationStatus(State.CANCELLED, Instant.now(), Optional.of("CANCELLED"), Optional.empty()));
            return true;
        }

        @Override
        public Registration register(NotificationSink sink) {
            return () -> {
                // Polling is authoritative.
            };
        }

        @Override
        public Set<String> supportedAlgorithms() {
            return Set.of("SHA256withRSA");
        }

        @Override
        public void close() {
            blockedRelease.countDown();
        }
    }

    private static final class ThrowOnceStatusWorkflow implements SignatureWorkflow {
        private final AtomicReference<OperationStatus> status = new AtomicReference<>();
        private final AtomicInteger statusReads = new AtomicInteger();

        @Override
        public String id() {
            return "throw-once-status";
        }

        @Override
        public PkiId submitSign(SignRequest request, CallControl control) {
            status.set(new OperationStatus(State.RUNNING, Instant.now(), Optional.of("RUNNING"), Optional.empty()));
            return request.submissionId();
        }

        @Override
        public PkiId submitVerify(VerifyRequest request, CallControl control) {
            throw new UnsupportedOperationException();
        }

        @Override
        public OperationStatus status(PkiId operationId, CallControl control) {
            if (statusReads.incrementAndGet() == 1) {
                throw new IllegalStateException("injected status failure");
            }
            return status.get();
        }

        @Override
        public boolean cancel(PkiId operationId, long fencingToken, String reason, CallControl control) {
            status.set(new OperationStatus(State.CANCELLED, Instant.now(), Optional.of("CANCELLED"), Optional.empty()));
            return true;
        }

        @Override
        public Registration register(NotificationSink sink) {
            return () -> {
                // Polling is authoritative.
            };
        }

        @Override
        public Set<String> supportedAlgorithms() {
            return Set.of("SHA256withRSA");
        }

        @Override
        public void close() {
            // No owned resources.
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

        @Override
        public ZoneId getZone() {
            return java.time.ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return value;
        }
    }
}
