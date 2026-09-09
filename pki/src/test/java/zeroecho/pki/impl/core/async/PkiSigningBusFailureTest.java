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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

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
import zeroecho.pki.api.PkiFailureReason;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.orch.OrchestrationDurabilityPolicy;
import zeroecho.pki.api.orch.WorkflowStateRecord;
import zeroecho.pki.application.SigningReconciliationContinuation;
import zeroecho.pki.application.SigningReconciliationRequest;
import zeroecho.pki.application.SigningReconciliationResult;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.impl.framework.x509.X509AlgorithmResolver;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.bc.PkiBusContentSigner;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.InMemorySignatureWorkflow;
import zeroecho.pki.util.async.AsyncState;

final class PkiSigningBusFailureTest {

    @Test
    void initialMetadataLimitMapsToOverloadWithoutReclassifyingOtherFailures() {
        MetadataStoreException limit = new MetadataStoreException(
                MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                "test metadata capacity rejection");
        PkiException limited = new PkiException("test initial metadata failure", limit);
        SigningExecutionException overload = assertInstanceOf(SigningExecutionException.class,
                PkiSigningBus.translateInitialMetadataFailure(limited));
        assertEquals(SigningExecutionException.Classification.OVERLOADED,
                overload.classification());
        assertSame(limited, overload.getCause());

        MetadataStoreException cancelled = new MetadataStoreException(
                MetadataCommitResult.FailureCategory.CANCELLED,
                "test metadata cancellation");
        PkiException cancelledCommit = new PkiException("test initial metadata failure", cancelled);
        assertSame(cancelledCommit,
                PkiSigningBus.translateInitialMetadataFailure(cancelledCommit));
    }

    @ParameterizedTest(name = "callback/cancellation restart boundary: {0}")
    @EnumSource(CallbackCancellationBoundary.class)
    void callbackAndCancellationRestartMatrix(CallbackCancellationBoundary boundary, @TempDir Path tempDir)
            throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-14T12:00:00Z"));
        if (boundary.callbackBoundary()) {
            assertCallbackBoundary(boundary, tempDir, clock);
        } else {
            assertCancellationBoundary(boundary, tempDir, clock);
        }
    }

    private static void assertCallbackBoundary(CallbackCancellationBoundary boundary, Path tempDir,
            MutableClock clock) throws Exception {
        MatrixWorkflow targetWorkflow = new MatrixWorkflow("matrix-target", clock, false);
        MatrixWorkflow otherWorkflow = new MatrixWorkflow("matrix-other", clock, false);
        Path targetRoot = tempDir.resolve("target-store");
        Path otherRoot = tempDir.resolve("other-store");
        PkiId targetId;
        PkiId otherId;
        try (FilesystemPkiStore targetStore = new FilesystemPkiStore(targetRoot, FsPkiStoreOptions.defaults(), clock);
                FilesystemPkiStore otherStore = new FilesystemPkiStore(otherRoot, FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus targetBus = new PkiSigningBus(targetStore, targetWorkflow,
                        signingAuthority(targetWorkflow));
                PkiSigningBus otherBus = new PkiSigningBus(otherStore, otherWorkflow,
                        signingAuthority(otherWorkflow))) {
            targetId = submit(targetBus, new KeyRef("matrix:key:target"), (byte) 1);
            otherId = submit(otherBus, new KeyRef("matrix:key:other"), (byte) 2);
            assertEquals(AsyncState.RUNNING, targetBus.status(targetId).orElseThrow().state());
            assertEquals(AsyncState.RUNNING, otherBus.status(otherId).orElseThrow().state());

            targetWorkflow.complete(targetId, (byte) 41);
            otherWorkflow.complete(otherId, (byte) 91);
            if (boundary == CallbackCancellationBoundary.CALLBACK_LATE) {
                assertEquals(AsyncState.SUCCEEDED, targetBus.status(targetId).orElseThrow().state());
            }
            assertCallbackDelivery(boundary, targetWorkflow, targetBus, targetId);

            assertEquals(AsyncState.SUCCEEDED, targetBus.status(targetId).orElseThrow().state());
            assertArrayEquals(new byte[] { 41 }, targetBus.consumeResult(targetId).orElseThrow().bytes());
            assertEquals(AsyncState.SUCCEEDED, otherBus.status(otherId).orElseThrow().state());
            assertArrayEquals(new byte[] { 91 }, otherBus.consumeResult(otherId).orElseThrow().bytes());
            assertNamespaceIsolation(targetStore, targetId, otherStore, otherId);
            String targetNamespace = targetStore.getSignRecord(targetId).orElseThrow().namespace();
            String otherNamespace = otherStore.getSignRecord(otherId).orElseThrow().namespace();
            assertTrue(targetNamespace.endsWith(".matrix-target"));
            assertTrue(otherNamespace.endsWith(".matrix-other"));
            assertFalse(targetNamespace.equals(otherNamespace));
        }

        assertRestartedResults(targetRoot, targetWorkflow, targetId, (byte) 41,
                otherRoot, otherWorkflow, otherId, (byte) 91, clock);
        assertEquals(1, targetWorkflow.submissions.get());
        assertEquals(1, otherWorkflow.submissions.get());
    }

    private static void assertCallbackDelivery(CallbackCancellationBoundary boundary, MatrixWorkflow workflow,
            PkiSigningBus bus, PkiId operationId) {
        switch (boundary) {
            case CALLBACK_DROPPED -> {
                // Deliberately omit the advisory; polling remains authoritative.
            }
            case CALLBACK_DUPLICATED -> {
                workflow.notifyStatus(operationId);
                workflow.notifyStatus(operationId);
            }
            case CALLBACK_LATE -> workflow.notifyStatus(operationId);
            case CALLBACK_THROWING -> assertThrows(IllegalStateException.class,
                    () -> workflow.notifyThenFail(operationId));
            case CALLBACK_REENTRANT -> workflow.notifyThenReenter(operationId, bus);
            default -> throw new IllegalArgumentException("Not a callback boundary: " + boundary);
        }
    }

    private static void assertCancellationBoundary(CallbackCancellationBoundary boundary, Path tempDir,
            MutableClock clock) throws Exception {
        boolean delayedAcknowledgement = boundary == CallbackCancellationBoundary.CANCEL_DURING_EXECUTION;
        MatrixWorkflow targetWorkflow = new MatrixWorkflow("matrix-target", clock, delayedAcknowledgement);
        MatrixWorkflow otherWorkflow = new MatrixWorkflow("matrix-other", clock, false);
        Path targetRoot = tempDir.resolve("target-store");
        Path otherRoot = tempDir.resolve("other-store");
        PkiId targetId;
        PkiId otherId;
        try (FilesystemPkiStore targetStore = new FilesystemPkiStore(targetRoot, FsPkiStoreOptions.defaults(), clock);
                FilesystemPkiStore otherStore = new FilesystemPkiStore(otherRoot, FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus targetBus = new PkiSigningBus(targetStore, targetWorkflow,
                        signingAuthority(targetWorkflow));
                PkiSigningBus otherBus = new PkiSigningBus(otherStore, otherWorkflow,
                        signingAuthority(otherWorkflow))) {
            targetId = submit(targetBus, new KeyRef("matrix:key:target"), (byte) 1);
            otherId = submit(otherBus, new KeyRef("matrix:key:other"), (byte) 2);
            assertEquals(AsyncState.RUNNING, otherBus.status(otherId).orElseThrow().state());
            otherWorkflow.complete(otherId, (byte) 91);
            assertEquals(AsyncState.SUCCEEDED, otherBus.status(otherId).orElseThrow().state());

            switch (boundary) {
                case CANCEL_BEFORE_EXECUTION -> targetBus.retireSignOperation(targetId, "cancel before execution");
                case CANCEL_DURING_EXECUTION -> {
                    assertEquals(AsyncState.RUNNING, targetBus.status(targetId).orElseThrow().state());
                    targetBus.retireSignOperation(targetId, "cancel during execution");
                    SignWorkflowStore.Record cancelling = targetStore.getSignRecord(targetId).orElseThrow();
                    assertEquals(SignWorkflowStore.State.CANCELLING, cancelling.state());
                    assertTrue(PkiSigningBus.SignContinuation.decode(cancelling.request(), targetStore.stagedContent())
                            .hasLiveContent());
                    targetWorkflow.complete(targetId, (byte) 42);
                }
                case CANCEL_AFTER_TERMINAL_COMPUTATION -> {
                    assertEquals(AsyncState.RUNNING, targetBus.status(targetId).orElseThrow().state());
                    targetWorkflow.complete(targetId, (byte) 42);
                    targetBus.retireSignOperation(targetId, "terminal computation won");
                }
                case CANCEL_COMPLETION_RACE -> assertCompletionRace(targetBus, targetWorkflow, targetId);
                default -> throw new IllegalArgumentException("Not a cancellation boundary: " + boundary);
            }
            assertNamespaceIsolation(targetStore, targetId, otherStore, otherId);
        }

        try (FilesystemPkiStore targetStore = new FilesystemPkiStore(targetRoot, FsPkiStoreOptions.defaults(), clock);
                FilesystemPkiStore otherStore = new FilesystemPkiStore(otherRoot, FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus targetBus = new PkiSigningBus(targetStore, targetWorkflow,
                        signingAuthority(targetWorkflow));
                PkiSigningBus otherBus = new PkiSigningBus(otherStore, otherWorkflow,
                        signingAuthority(otherWorkflow))) {
            if (boundary == CallbackCancellationBoundary.CANCEL_BEFORE_EXECUTION) {
                assertEquals(AsyncState.CANCELLED, targetBus.status(targetId).orElseThrow().state());
                assertTrue(targetBus.consumeResult(targetId).isEmpty());
                assertEquals(0, targetWorkflow.submissions.get());
            } else {
                assertEquals(AsyncState.SUCCEEDED, targetBus.status(targetId).orElseThrow().state());
                targetBus.retireSignOperation(targetId, "restart reconciliation");
                assertArrayEquals(new byte[] { 42 }, targetBus.consumeResult(targetId).orElseThrow().bytes());
                assertEquals(1, targetWorkflow.submissions.get());
                assertFalse(PkiSigningBus.SignContinuation.decode(
                        targetStore.getSignRecord(targetId).orElseThrow().request(), targetStore.stagedContent())
                        .hasLiveContent());
            }
            assertEquals(AsyncState.SUCCEEDED, otherBus.status(otherId).orElseThrow().state());
            assertArrayEquals(new byte[] { 91 }, otherBus.consumeResult(otherId).orElseThrow().bytes());
            assertEquals(1, otherWorkflow.submissions.get());
            assertNamespaceIsolation(targetStore, targetId, otherStore, otherId);
        }
    }

    private static void assertCompletionRace(PkiSigningBus bus, MatrixWorkflow workflow, PkiId operationId)
            throws Exception {
        assertEquals(AsyncState.RUNNING, bus.status(operationId).orElseThrow().state());
        workflow.armStatusBlock(operationId);
        try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
            Future<?> retirement = executor.submit(() -> bus.retireSignOperation(operationId, "completion race"));
            assertTrue(workflow.statusEntered.await(1, TimeUnit.SECONDS));
            workflow.complete(operationId, (byte) 42);
            workflow.notifyStatus(operationId);
            workflow.releaseStatus();
            retirement.get(1, TimeUnit.SECONDS);
        }
    }

    private static void assertRestartedResults(Path targetRoot, MatrixWorkflow targetWorkflow, PkiId targetId,
            byte targetResult, Path otherRoot, MatrixWorkflow otherWorkflow, PkiId otherId, byte otherResult,
            Clock clock) throws Exception {
        try (FilesystemPkiStore targetStore = new FilesystemPkiStore(targetRoot, FsPkiStoreOptions.defaults(), clock);
                FilesystemPkiStore otherStore = new FilesystemPkiStore(otherRoot, FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus targetBus = new PkiSigningBus(targetStore, targetWorkflow,
                        signingAuthority(targetWorkflow));
                PkiSigningBus otherBus = new PkiSigningBus(otherStore, otherWorkflow,
                        signingAuthority(otherWorkflow))) {
            assertEquals(AsyncState.SUCCEEDED, targetBus.status(targetId).orElseThrow().state());
            assertArrayEquals(new byte[] { targetResult }, targetBus.consumeResult(targetId).orElseThrow().bytes());
            assertEquals(AsyncState.SUCCEEDED, otherBus.status(otherId).orElseThrow().state());
            assertArrayEquals(new byte[] { otherResult }, otherBus.consumeResult(otherId).orElseThrow().bytes());
            assertNamespaceIsolation(targetStore, targetId, otherStore, otherId);
        }
    }

    private static void assertNamespaceIsolation(FilesystemPkiStore targetStore, PkiId targetId,
            FilesystemPkiStore otherStore, PkiId otherId) {
        assertFalse(targetId.equals(otherId));
        assertTrue(targetStore.getSignRecord(otherId).isEmpty());
        assertTrue(otherStore.getSignRecord(targetId).isEmpty());
    }

    @Test
    void reconciliationAndRetirementProviderCallsWaitForSharedLane(@TempDir Path tempDir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-14T01:00:00Z"));
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 2,
                        Duration.ofMillis(100), Duration.ofMillis(100));
                PkiSigningBus bus = PkiSigningBus.attach(store, signer, signingAuthority(signer), runtime);
                SigningExecutionRuntime.Reservation blocker = runtime.reserve()) {
            PkiId operationId = submit(bus, Duration.ofMinutes(1));
            assertEquals(AsyncState.RUNNING, bus.status(operationId).orElseThrow().state());

            CountDownLatch firstEntered = new CountDownLatch(1);
            CountDownLatch firstRelease = new CountDownLatch(1);
            CompletableFuture<String> firstBlocker = CompletableFuture.supplyAsync(() -> runtime.executeStep(blocker,
                    () -> {
                        firstEntered.countDown();
                        firstRelease.await();
                        return "released";
                    }, Instant.now().plusSeconds(2), CancellationSignal.NONE));
            assertTrue(firstEntered.await(1, TimeUnit.SECONDS));
            int statusBefore = signer.statusReads.get();
            CompletableFuture<SigningReconciliationResult> reconciliation = CompletableFuture.supplyAsync(
                    () -> bus.reconcile(reconciliation(Optional.empty(), 1, 1, clock)));
            awaitReady(runtime, 1);
            assertEquals(statusBefore, signer.statusReads.get());
            firstRelease.countDown();
            assertEquals("released", firstBlocker.get(1, TimeUnit.SECONDS));
            reconciliation.get(1, TimeUnit.SECONDS);

            CountDownLatch secondEntered = new CountDownLatch(1);
            CountDownLatch secondRelease = new CountDownLatch(1);
            CompletableFuture<String> secondBlocker = CompletableFuture.supplyAsync(() -> runtime.executeStep(blocker,
                    () -> {
                        secondEntered.countDown();
                        secondRelease.await();
                        return "released";
                    }, Instant.now().plusSeconds(2), CancellationSignal.NONE));
            assertTrue(secondEntered.await(1, TimeUnit.SECONDS));
            int statusBeforeRetirement = signer.statusReads.get();
            CompletableFuture<Void> retirement = CompletableFuture.runAsync(
                    () -> bus.retireSignOperation(operationId, "test-retirement"));
            awaitReady(runtime, 1);
            assertEquals(statusBeforeRetirement, signer.statusReads.get());
            assertEquals(0, signer.cancellations.get());
            secondRelease.countDown();
            assertEquals("released", secondBlocker.get(1, TimeUnit.SECONDS));
            retirement.get(1, TimeUnit.SECONDS);
        }
    }

    @Test
    void providerStatusQueuedAcrossExactDeadlineNeverInvokesProvider(@TempDir Path tempDir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-14T01:15:00.123Z"));
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        CountDownLatch laneEntered = new CountDownLatch(1);
        CountDownLatch releaseLane = new CountDownLatch(1);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 1,
                        Duration.ofMillis(100), Duration.ofMillis(100));
                PkiSigningBus bus = PkiSigningBus.attach(store, signer, signingAuthority(signer), runtime)) {
            PkiId operationId = submit(bus, Duration.ofSeconds(10L));
            assertEquals(AsyncState.RUNNING, bus.status(operationId).orElseThrow().state());
            SignWorkflowStore.Record dispatched = store.getSignRecord(operationId).orElseThrow();
            int statusCalls = signer.statusReads.get();
            CompletableFuture<Void> occupied = CompletableFuture.runAsync(() -> runtime.executeOperationStep(
                    new PkiId("deadline-lane-blocker"), () -> {
                        laneEntered.countDown();
                        releaseLane.await();
                        return null;
                    }, Instant.now().plusSeconds(5L), CancellationSignal.NONE));
            assertTrue(laneEntered.await(2L, TimeUnit.SECONDS));
            CompletableFuture<Optional<zeroecho.pki.util.async.AsyncStatus>> queued =
                    CompletableFuture.supplyAsync(() -> bus.status(operationId));
            awaitReady(runtime, 1);

            clock.set(dispatched.deadline());
            releaseLane.countDown();
            occupied.get(2L, TimeUnit.SECONDS);
            assertThrows(java.util.concurrent.ExecutionException.class,
                    () -> queued.get(2L, TimeUnit.SECONDS));
            assertEquals(statusCalls, signer.statusReads.get());
            assertEquals(SignWorkflowStore.State.EXPIRED,
                    store.getSignRecord(operationId).orElseThrow().state());
        } finally {
            releaseLane.countDown();
            signer.close();
        }
    }

    @Test
    void schedulerSaturationLeavesRecoveredIntentAndCursorUndispositioned(@TempDir Path tempDir)
            throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-14T01:30:00Z"));
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                        Duration.ofMillis(100), Duration.ofMillis(100));
                PkiSigningBus bus = PkiSigningBus.attach(store, signer, signingAuthority(signer), runtime)) {
            PkiId operationId = submit(bus, Duration.ofMinutes(1));
            SignWorkflowStore.Record pending = store.getSignRecord(operationId).orElseThrow();
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            CompletableFuture<Void> blocker = CompletableFuture.runAsync(() -> runtime.executeOperationStep(
                    new PkiId("runtime-blocker"), () -> {
                        entered.countDown();
                        release.await();
                        return null;
                    }, Instant.now().plusSeconds(2), CancellationSignal.NONE));
            assertTrue(entered.await(1, TimeUnit.SECONDS));

            SigningReconciliationResult saturated = bus.reconcile(
                    reconciliation(Optional.empty(), 1, 1, clock));

            assertEquals(Optional.empty(), saturated.continuation().cursor());
            assertEquals(0, saturated.progressed());
            assertEquals(1, saturated.retryable());
            SignWorkflowStore.Record retained = store.getSignRecord(operationId).orElseThrow();
            assertEquals(pending.state(), retained.state());
            assertEquals(pending.revision(), retained.revision());
            assertEquals(pending.fence(), retained.fence());
            assertEquals(pending.nextEligibleAt(), retained.nextEligibleAt());
            assertEquals(pending.reconciliationFailureClass(), retained.reconciliationFailureClass());
            assertEquals(0, signer.submissions.get());

            release.countDown();
            blocker.get(1, TimeUnit.SECONDS);
            SigningReconciliationResult admitted = bus.reconcile(
                    reconciliation(Optional.empty(), 1, 1, clock));
            assertEquals(1, admitted.progressed());
            assertEquals(1, signer.submissions.get());
            assertEquals(0, runtime.metrics().schedulerReserved());
        }
    }

    @Test
    void recoveredPopulationBeyondSchedulerCapacityProgressesWithoutRuntimeRetention(@TempDir Path tempDir)
            throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-14T01:45:00Z"));
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                        Duration.ofMillis(100), Duration.ofMillis(100));
                PkiSigningBus bus = PkiSigningBus.attach(store, signer, signingAuthority(signer), runtime)) {
            for (int operation = 0; operation < 5; operation++) {
                submit(bus, Duration.ofMinutes(1));
            }

            SigningReconciliationResult result = bus.reconcile(
                    reconciliation(Optional.empty(), 5, 5, clock));

            assertEquals(5, result.progressed());
            assertEquals(5, signer.submissions.get());
            assertEquals(0, runtime.metrics().schedulerReserved());
            assertEquals(5, store.listSignRecords().size());
        }
    }

    @Test
    void nonterminalRemoteCancellationReleasesSchedulerAdmissionUntilReconciliation(@TempDir Path tempDir)
            throws Exception {
        AcceptedDelayedCancellationWorkflow signer = new AcceptedDelayedCancellationWorkflow();
        signer.statusAvailable = false;
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults());
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                        Duration.ofMillis(100), Duration.ofMillis(100));
                PkiSigningBus bus = PkiSigningBus.attach(store, signer, signingAuthority(signer), runtime)) {
            try (PkiBusContentSigner contentSigner = new PkiBusContentSigner(bus, new KeyRef("test"),
                    "SHA256withRSA", Duration.ofSeconds(5))) {
                contentSigner.getOutputStream().write(1);
                assertThrows(PkiException.class, contentSigner::getSignature);
            }
            PkiId operationId = store.listSignRecords().getFirst().submissionId();
            SignWorkflowStore.Record cancellationPending = store.getSignRecord(operationId).orElseThrow();
            assertEquals(SignWorkflowStore.State.CANCELLING,
                    cancellationPending.state(), () -> "unexpected state=" + cancellationPending.state()
                            + ", detail=" + cancellationPending.detailCode().orElse("missing")
                            + ", fence=" + cancellationPending.fence()
                            + ", created=" + cancellationPending.createdAt()
                            + ", deadline=" + cancellationPending.deadline()
                            + ", now=" + store.signingNow()
                            + ", submissions=" + signer.submissions.get()
                            + ", cancellations=" + signer.cancellations.get());
            assertEquals(0, runtime.metrics().schedulerReserved());
            try (PkiBusContentSigner next = new PkiBusContentSigner(bus, new KeyRef("test"),
                    "SHA256withRSA", Duration.ofSeconds(1))) {
                assertEquals(1, runtime.metrics().schedulerReserved());
            }
            assertEquals(0, runtime.metrics().schedulerReserved());
            assertEquals(1, store.listSignRecords().size());

            signer.completeSuccessfully(operationId);
            signer.statusAvailable = true;
            bus.reconcile(new SigningReconciliationRequest(SigningReconciliationContinuation.start(), 1, 1,
                    Instant.now().plusSeconds(1), Duration.ofSeconds(1), CancellationSignal.NONE));

            assertEquals(SignWorkflowStore.State.RETIRED,
                    store.getSignRecord(operationId).orElseThrow().state());
            assertEquals(0, runtime.metrics().schedulerReserved());
        }
    }

    @Test
    void providerControlsClampToRecordDeadlineAndCarryPassCancellation(@TempDir Path tempDir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-14T00:00:00Z"));
        ControlCapturingWorkflow signer = new ControlCapturingWorkflow(clock);
        AtomicBoolean cancelled = new AtomicBoolean();
        CancellationSignal cancellation = cancelled::get;
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, signingAuthority(signer))) {
            PkiId operationId = submit(bus, Duration.ofSeconds(2));
            bus.status(operationId);
            SignWorkflowStore.Record record = store.getSignRecord(operationId).orElseThrow();
            assertEquals(record.deadline(), signer.submitControl.get().deadline());

            signer.statusControl.set(null);
            bus.reconcile(new SigningReconciliationRequest(SigningReconciliationContinuation.start(), 1, 1,
                    clock.instant().plusSeconds(30), Duration.ofSeconds(10), cancellation));

            SignatureWorkflow.CallControl statusControl = signer.statusControl.get();
            assertEquals(record.deadline(), statusControl.deadline());
            assertFalse(statusControl.cancellation().isCancelled());
            cancelled.set(true);
            assertTrue(statusControl.cancellation().isCancelled());
        }
    }

    @Test
    void midPageProviderBudgetPublishesOnlyDispositionedCursorAndWrapsFairly(@TempDir Path tempDir)
            throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-01T00:00:00Z"));
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            PkiId firstId = submit(bus);
            clock.set(clock.instant().plusMillis(1));
            PkiId secondId = submit(bus);
            clock.set(clock.instant().plusMillis(1));
            PkiId thirdId = submit(bus);

            SigningReconciliationResult first = bus.reconcile(reconciliation(Optional.empty(), 3, 1, clock));
            assertEquals(1, first.examined());
            assertEquals(Optional.of(firstId.value()), first.continuation().cursor());
            assertEquals(1, signer.submissions.get());
            assertEquals(1, first.progressed());
            assertEquals(1, first.unresolved());
            assertFalse(first.endReached());

            SigningReconciliationResult second = bus.reconcile(reconciliation(first, 3, 1, clock));
            assertEquals(1, second.examined());
            assertEquals(Optional.of(secondId.value()), second.continuation().cursor());
            assertEquals(2, signer.submissions.get());
            assertFalse(second.endReached());

            SigningReconciliationResult third = bus.reconcile(reconciliation(second, 3, 1, clock));
            assertEquals(1, third.examined());
            assertEquals(Optional.of(thirdId.value()), third.continuation().cursor());
            assertEquals(3, signer.submissions.get());
            assertTrue(third.endReached());

            SigningReconciliationResult wrapped = bus.reconcile(
                    reconciliation(third, 3, 1, clock));
            assertEquals(1, wrapped.examined());
            assertEquals(Optional.of(firstId.value()), wrapped.continuation().cursor());
            assertFalse(wrapped.endReached());
        }
    }

    @Test
    void pageDivisiblePopulationReachesBoundaryWithoutSkipping(@TempDir Path tempDir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-01T00:30:00Z"));
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            PkiId firstId = submit(bus);
            clock.set(clock.instant().plusMillis(1));
            PkiId secondId = submit(bus);
            clock.set(clock.instant().plusMillis(1));
            PkiId thirdId = submit(bus);
            clock.set(clock.instant().plusMillis(1));
            PkiId fourthId = submit(bus);

            SigningReconciliationResult first = bus.reconcile(reconciliation(Optional.empty(), 2, 2, clock));
            assertEquals(2, first.examined());
            assertEquals(Optional.of(secondId.value()), first.continuation().cursor());
            assertFalse(first.endReached());

            SigningReconciliationResult second = bus.reconcile(reconciliation(first, 2, 2, clock));
            assertEquals(2, second.examined());
            assertEquals(Optional.of(fourthId.value()), second.continuation().cursor());
            assertTrue(second.endReached());
            assertEquals(4, signer.submissions.get());
            assertTrue(firstId.value().compareTo(secondId.value()) < 0);
            assertTrue(thirdId.value().compareTo(fourthId.value()) < 0);
        }
    }

    @Test
    void cancellationAfterCandidateLeavesPrefetchedSuccessForNextPass(@TempDir Path tempDir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-01T00:40:00Z"));
        AtomicBoolean cancelled = new AtomicBoolean();
        ControlledWorkflow signer = new ControlledWorkflow(clock, () -> cancelled.set(true));
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            PkiId firstId = submit(bus);
            clock.set(clock.instant().plusMillis(1));
            PkiId secondId = submit(bus);
            SigningReconciliationRequest request = new SigningReconciliationRequest(
                    SigningReconciliationContinuation.start(), 2, 2, clock.instant().plusSeconds(30),
                    Duration.ofSeconds(10), cancelled::get);

            SigningReconciliationResult result = bus.reconcile(request);

            assertEquals(1, result.examined());
            assertEquals(Optional.of(firstId.value()), result.continuation().cursor());
            assertFalse(result.endReached());
            assertEquals(1, signer.submissions.get());

            cancelled.set(false);
            SigningReconciliationResult resumed = bus.reconcile(reconciliation(result, 1, 1, clock));
            assertEquals(Optional.of(secondId.value()), resumed.continuation().cursor());
            assertEquals(2, signer.submissions.get());
        }
    }

    @Test
    void deadlineAfterCandidateLeavesPrefetchedSuccessForNextPass(@TempDir Path tempDir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-01T00:50:00Z"));
        Instant deadline = clock.instant().plusSeconds(1);
        AtomicBoolean advanceToDeadline = new AtomicBoolean(true);
        ControlledWorkflow signer = new ControlledWorkflow(clock, () -> {
            if (advanceToDeadline.compareAndSet(true, false)) {
                clock.set(deadline);
            }
        });
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            PkiId firstId = submit(bus);
            clock.set(clock.instant().plusMillis(1));
            PkiId secondId = submit(bus);
            SigningReconciliationRequest request = new SigningReconciliationRequest(
                    SigningReconciliationContinuation.start(), 2, 2, deadline, Duration.ofSeconds(10),
                    CancellationSignal.NONE);

            SigningReconciliationResult result = bus.reconcile(request);

            assertEquals(1, result.examined());
            assertEquals(Optional.of(firstId.value()), result.continuation().cursor());
            assertFalse(result.endReached());
            assertEquals(1, signer.submissions.get());

            clock.set(clock.instant().plusMillis(1));
            SigningReconciliationResult resumed = bus.reconcile(reconciliation(result, 1, 1, clock));
            assertEquals(Optional.of(secondId.value()), resumed.continuation().cursor());
            assertEquals(2, signer.submissions.get());
        }
    }

    @Test
    void continuousInsertsBeyondPublishedCursorAreObservedWithoutWrap(@TempDir Path tempDir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-01T00:55:00Z"));
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            PkiId firstId = submit(bus);
            SigningReconciliationResult first = bus.reconcile(reconciliation(Optional.empty(), 1, 1, clock));
            assertEquals(Optional.of(firstId.value()), first.continuation().cursor());
            assertTrue(first.endReached());

            Optional<String> cursor = first.continuation().cursor();
            for (int index = 0; index < 3; index++) {
                clock.set(clock.instant().plusMillis(1));
                PkiId insertedId = submit(bus);
                SigningReconciliationResult inserted = bus.reconcile(reconciliation(cursor, 1, 1, clock));
                assertEquals(1, inserted.examined());
                assertEquals(Optional.of(insertedId.value()), inserted.continuation().cursor());
                cursor = inserted.continuation().cursor();
            }
            assertEquals(4, signer.submissions.get());
        }
    }

    @Test
    void wrappedCycleVisitsEachOriginalCandidateOnceDespiteContinuousInserts(@TempDir Path tempDir)
            throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-01T00:58:00Z"));
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            PkiId first = submit(bus);
            clock.set(clock.instant().plusMillis(1));
            PkiId cursorRecord = submit(bus);
            clock.set(clock.instant().plusMillis(1));
            PkiId initialHighWatermark = submit(bus);

            SigningReconciliationResult cycle = bus.reconcile(
                    reconciliation(Optional.of(cursorRecord.value()), 1, 1, clock));
            assertEquals(Optional.of(initialHighWatermark.value()), cycle.continuation().cursor());
            assertEquals(Optional.of(initialHighWatermark.value()), cycle.continuation().cycleHighWatermark());
            assertEquals(Optional.of(cursorRecord.value()), cycle.continuation().cycleWrapUpperBound());
            assertEquals(List.of(initialHighWatermark), signer.submissionAttempts);

            for (int pass = 0; pass < 2; pass++) {
                clock.set(clock.instant().plusMillis(1));
                submit(bus);
                cycle = bus.reconcile(reconciliation(cycle, 1, 1, clock));
            }

            assertEquals(Optional.of(cursorRecord.value()), cycle.continuation().cursor());
            assertEquals(Optional.empty(), cycle.continuation().cycleHighWatermark());
            assertEquals(Optional.empty(), cycle.continuation().cycleWrapUpperBound());
            assertFalse(cycle.continuation().cycleWrapped());
            assertEquals(List.of(initialHighWatermark, first, cursorRecord), signer.submissionAttempts);
        }
    }

    @Test
    void advisoryCursorBeyondHighWatermarkNormalizesBeforeWrappedScan(@TempDir Path tempDir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-01T00:59:00Z"));
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            PkiId record = submit(bus);

            SigningReconciliationResult result = bus.reconcile(reconciliation(Optional.of("~"), 1, 1, clock));

            assertEquals(1, result.examined());
            assertEquals(Optional.of(record.value()), result.continuation().cursor());
            assertEquals(Optional.empty(), result.continuation().cycleHighWatermark());
            assertEquals(Optional.empty(), result.continuation().cycleWrapUpperBound());
            assertFalse(result.continuation().cycleWrapped());
        }
    }

    @Test
    void advisorySnapshotAttemptsEachIdOnceAndDefersPassTimeArrivals(@TempDir Path tempDir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-01T00:59:30Z"));
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        CountDownLatch laneEntered = new CountDownLatch(1);
        CountDownLatch releaseLane = new CountDownLatch(1);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 1,
                        Duration.ofMillis(100), Duration.ofMillis(100));
                PkiSigningBus bus = PkiSigningBus.attach(store, signer, signingAuthority(signer), runtime)) {
            PkiId stuck = submit(bus);
            PkiId advisoryTerminal = submit(bus);
            PkiId pageTerminal = submit(bus);
            assertEquals(AsyncState.RUNNING, bus.status(stuck).orElseThrow().state());
            assertEquals(AsyncState.RUNNING, bus.status(advisoryTerminal).orElseThrow().state());
            assertEquals(AsyncState.RUNNING, bus.status(pageTerminal).orElseThrow().state());
            signer.succeedAt(advisoryTerminal, clock.instant(), (byte) 31);
            signer.succeedAt(pageTerminal, clock.instant(), (byte) 32);
            assertEquals(AsyncState.SUCCEEDED, bus.status(advisoryTerminal).orElseThrow().state());
            assertEquals(AsyncState.SUCCEEDED, bus.status(pageTerminal).orElseThrow().state());

            CompletableFuture<Void> occupied = CompletableFuture.runAsync(() -> runtime.executeOperationStep(
                    new PkiId("fairness-active"), () -> {
                        laneEntered.countDown();
                        releaseLane.await();
                        return null;
                    }, Instant.now().plusSeconds(5), CancellationSignal.NONE));
            assertTrue(laneEntered.await(2, TimeUnit.SECONDS));
            SigningExecutionRuntime.StepSubmission<Void> ready = runtime.scheduleStep(
                    new PkiId("fairness-ready"), () -> null, CancellationSignal.NONE);
            assertEquals(SigningExecutionRuntime.StepDisposition.ACCEPTED, ready.disposition());
            runtime.advisory(stuck);
            runtime.advisory(advisoryTerminal);
            long rejectedBefore = runtime.metrics().schedulingRejected();
            int statusBefore = signer.statusReads.get();

            SigningReconciliationResult first = bus.reconcile(reconciliation(Optional.empty(), 3, 3, clock));

            assertEquals(3, first.examined());
            assertEquals(2, first.progressed());
            assertEquals(rejectedBefore + 1L, runtime.metrics().schedulingRejected());
            assertEquals(statusBefore, signer.statusReads.get());
            assertEquals(SignWorkflowStore.State.RETIRED,
                    store.getSignRecord(advisoryTerminal).orElseThrow().state());
            assertEquals(SignWorkflowStore.State.RETIRED,
                    store.getSignRecord(pageTerminal).orElseThrow().state());
            assertEquals(1, runtime.metrics().pendingAdvisories());

            assertTrue(ready.future().orElseThrow().cancel(false));
            releaseLane.countDown();
            occupied.get(2, TimeUnit.SECONDS);
            PkiId passTimeArrival = bus.newSubmissionId();
            signer.afterNextStatus(() -> runtime.advisory(passTimeArrival));
            SigningReconciliationResult second = bus.reconcile(
                    reconciliation(Optional.empty(), 1, 1, clock));
            assertEquals(1, second.examined());
            assertEquals(statusBefore + 1, signer.statusReads.get());
            assertEquals(2, runtime.metrics().pendingAdvisories());

            SigningReconciliationResult third = bus.reconcile(
                    reconciliation(Optional.empty(), 1, 1, clock));
            assertEquals(1, third.examined());
            assertEquals(statusBefore + 1, signer.statusReads.get());
            assertEquals(1, runtime.metrics().pendingAdvisories());

            SigningReconciliationResult fourth = bus.reconcile(
                    reconciliation(Optional.empty(), 1, 1, clock));
            assertEquals(1, fourth.examined());
            assertEquals(statusBefore + 2, signer.statusReads.get());
            assertEquals(1, runtime.metrics().pendingAdvisories());
        } finally {
            releaseLane.countDown();
            signer.close();
        }
    }

    @Test
    void reconciliationDeadlineStopsPagingBeforeCandidateDecode(@TempDir Path tempDir) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-01T01:00:00Z"));
        assertThrows(IllegalArgumentException.class,
                () -> SigningReconciliationContinuation.start(Optional.of("bad/cursor")));
        assertThrows(IllegalArgumentException.class,
                () -> SigningReconciliationContinuation.start(Optional.of("bad-\u2603")));
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            submit(bus);
            SigningReconciliationRequest expired = new SigningReconciliationRequest(
                    SigningReconciliationContinuation.start(), 256, 64, clock.instant(),
                    Duration.ofSeconds(10), CancellationSignal.NONE);

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

            assertEquals(1, result.examined());
            assertEquals(1, signer.statusReads.get());
            assertEquals(1, signer.cancellations.get());
            assertEquals(1, store.getSignRecord(first).orElseThrow().failureCount()
                    + store.getSignRecord(second).orElseThrow().failureCount());
        }
    }

    @Test
    void hostileCancellationFailureIsRedactedAndRestartConvergesWithoutResubmission(@TempDir Path tempDir)
            throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-03T00:30:00Z"));
        ThrowingCancellationWorkflow signer = new ThrowingCancellationWorkflow(clock);
        Path storeRoot = tempDir.resolve("store");
        KeyRef keyRef = new KeyRef("hostile:key-reference");
        Path hostilePath = tempDir.resolve("provider-private-path");
        PkiId operationId;
        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, signingAuthority(signer))) {
            operationId = submit(bus, keyRef, (byte) 17);
            assertEquals(AsyncState.RUNNING, bus.status(operationId).orElseThrow().state());
            signer.armHostileCancellationFailure(operationId, keyRef, hostilePath);

            PkiException failure = assertThrows(PkiException.class,
                    () -> bus.retireSignOperation(operationId, "hostile provider cancellation"));

            assertEquals("Provider cancellation failed: code=PROVIDER_CANCEL_FAILED", failure.getMessage());
            assertNull(failure.getCause());
            assertEquals(0, failure.getSuppressed().length);
            for (String hostileDetail : signer.hostileDetails(operationId, keyRef, hostilePath)) {
                assertFalse(failure.getMessage().contains(hostileDetail));
            }
            assertEquals(SignWorkflowStore.State.CANCELLING,
                    store.getSignRecord(operationId).orElseThrow().state());
            assertEquals(1, signer.submissions.get());
            assertEquals(1, signer.cancellations.get());
        }

        signer.allowCancellation();
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus replayed = new PkiSigningBus(reopened, signer, signingAuthority(signer))) {
            assertEquals(SignWorkflowStore.State.CANCELLING,
                    reopened.getSignRecord(operationId).orElseThrow().state());
            replayed.retireSignOperation(operationId, "restart cancellation reconciliation");

            assertEquals(SignWorkflowStore.State.RETIRED,
                    reopened.getSignRecord(operationId).orElseThrow().state());
            assertEquals(1, signer.submissions.get());
            assertEquals(2, signer.cancellations.get());
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
            PkiId second = submit(bus);
            faultTarget.set(first);
            faultArmed.set(true);

            SigningReconciliationResult result = bus.reconcile(reconciliation(Optional.empty(), 2, 1, clock));

            assertEquals(2, result.examined());
            assertEquals(1, signer.submissions.get());
            assertEquals(2, result.unresolved());
            assertEquals(Optional.of(second.value()), result.continuation().cursor());
            assertFalse(faultArmed.get());
        }
    }

    @Test
    void malformedScanCandidateIsReportedAndLaterCandidateUsesProviderBudget(@TempDir Path tempDir)
            throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-03T01:30:00Z"));
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        try (FilesystemPkiStore delegate = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(malformedFirstPageStore(delegate), signer,
                        tempDir.resolve("bus.log"), signingAuthority(signer))) {
            submit(bus);
            clock.set(clock.instant().plusMillis(1));
            PkiId second = submit(bus);

            SigningReconciliationResult result = bus.reconcile(reconciliation(Optional.empty(), 2, 1, clock));

            assertEquals(2, result.examined());
            assertEquals(2, result.unresolved());
            assertEquals(1, result.retryable());
            assertEquals(1, signer.submissions.get());
            assertEquals(Optional.of(second.value()), result.continuation().cursor());
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
                                new PkiException("Store durability unconfirmed: code=STORE_DURABILITY_UNCONFIRMED",
                                        PkiFailureReason.STORE_DURABILITY_UNCONFIRMED)),
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
    void acceptedUncertainIntentIsStatusReconciledAfterLeaseExpiryWithoutResubmission(@TempDir Path tempDir)
            throws Exception {
        Instant createdAt = Instant.parse("2026-08-04T00:00:00Z");
        MutableClock clock = new MutableClock(createdAt);
        AcceptedThenThrowsWorkflow signer = new AcceptedThenThrowsWorkflow(clock);
        Path storeRoot = tempDir.resolve("store");
        Path busLog = tempDir.resolve("bus.log");
        PkiId id;
        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, signingAuthority(signer))) {
            id = submit(bus, Duration.ofSeconds(60));
            PkiException uncertainFailure = assertThrows(PkiException.class, () -> bus.status(id));
            assertEquals("Provider submission uncertain: code=PROVIDER_SUBMISSION_UNCERTAIN",
                    uncertainFailure.getMessage());
            assertFalse(uncertainFailure.getMessage().contains("hostile-provider-secret"));
            assertNull(uncertainFailure.getCause());
            assertEquals(0, uncertainFailure.getSuppressed().length);
            SignWorkflowStore.Record uncertain = store.getSignRecord(id).orElseThrow();
            assertEquals(SignWorkflowStore.State.INTENT, uncertain.state());
            assertTrue(uncertain.fence() > 0L);
            assertEquals(1, signer.submissions.get());
        }

        clock.set(createdAt.plusSeconds(31));
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus replayed = new PkiSigningBus(reopened, signer, signingAuthority(signer))) {
            assertEquals(AsyncState.RUNNING, replayed.status(id).orElseThrow().state());
            assertEquals(SignWorkflowStore.State.DISPATCHED, reopened.getSignRecord(id).orElseThrow().state());
            assertEquals(1, signer.submissions.get());
            assertEquals(1, signer.statusReads.get());
        }

        clock.set(createdAt.plusSeconds(60));
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus replayed = new PkiSigningBus(reopened, signer, signingAuthority(signer))) {
            SigningReconciliationResult expiry = replayed.reconcile(
                    reconciliation(Optional.empty(), 2, 2, clock));
            assertEquals(1, expiry.progressed());
            assertEquals(SignWorkflowStore.State.EXPIRED,
                    reopened.getSignRecord(id).orElseThrow().state());
            assertEquals(1, signer.submissions.get());
            assertEquals(1, signer.statusReads.get());
            assertEquals(0, signer.cancellations.get());
        }
    }

    @Test
    void providerCallbackDropsMalformedAdvisoriesWithoutThrowing(@TempDir Path tempDir) throws Exception {
        BlockingWorkflow signer = new BlockingWorkflow();
        Logger logger = Logger.getLogger(PkiSigningBus.class.getName());
        Level previousLevel = logger.getLevel();
        boolean previousUseParentHandlers = logger.getUseParentHandlers();
        List<LogRecord> records = new ArrayList<>();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                records.add(record);
            }

            @Override
            public void flush() {
                // In-memory only.
            }

            @Override
            public void close() {
                // No owned resources.
            }
        };
        handler.setLevel(Level.FINE);
        logger.setLevel(Level.FINE);
        logger.setUseParentHandlers(false);
        logger.addHandler(handler);
        try {
            try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                    FsPkiStoreOptions.defaults());
                    PkiSigningBus ignored = new PkiSigningBus(store, signer, signingAuthority(signer))) {
                assertDoesNotThrow(signer::emitMalformedAdvisories);
            }
        } finally {
            logger.removeHandler(handler);
            logger.setUseParentHandlers(previousUseParentHandlers);
            logger.setLevel(previousLevel);
            handler.close();
        }

        assertEquals(2, records.size());
        for (LogRecord record : records) {
            assertEquals(Level.FINE, record.getLevel());
            assertEquals("Provider signing advisory ignored: code=PROVIDER_ADVISORY_INVALID",
                    record.getMessage());
            assertNull(record.getThrown());
            assertTrue(record.getParameters() == null || record.getParameters().length == 0);
            assertFalse(record.getMessage().contains(BlockingWorkflow.HOSTILE_ADVISORY_ID));
        }
    }

    @Test
    void constructorsRequireExplicitOwningSignAuthority(@TempDir Path tempDir) throws Exception {
        System.out.println("constructorsRequireExplicitOwningSignAuthority");
        Constructor<?>[] constructors = PkiSigningBus.class.getConstructors();
        assertEquals(3, constructors.length);
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
    void authoritativeDeadlineExpiresWithoutProviderCancellation(@TempDir Path tempDir) throws Exception {
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
            assertEquals(SignWorkflowStore.State.EXPIRED, store.getSignRecord(id).orElseThrow().state());

            bus.retireSignOperation(id, "deadline elapsed");

            assertEquals(0, signer.cancellations.get());
            assertEquals(SignWorkflowStore.State.EXPIRED, store.getSignRecord(id).orElseThrow().state());
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
                PkiSigningBus bus = new PkiSigningBus(store, signer, signingAuthority(signer))) {
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
            assertTrue(store.getSignRecord(exact).orElseThrow().providerUpdatedAt().isEmpty());

            late = submit(bus, Duration.ofSeconds(10));
            assertEquals(AsyncState.RUNNING, bus.status(late).orElseThrow().state());
            signer.succeedAt(late, deadline.plusNanos(1), (byte) 33);
            assertEquals(AsyncState.EXPIRED, bus.status(late).orElseThrow().state());
            assertTrue(bus.consumeResult(late).isEmpty());
        }

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus replayed = new PkiSigningBus(reopened, signer, signingAuthority(signer))) {
            assertEquals(AsyncState.EXPIRED, replayed.status(exact).orElseThrow().state());
            assertTrue(replayed.consumeResult(exact).isEmpty());
            assertEquals(AsyncState.EXPIRED, replayed.status(late).orElseThrow().state());
            assertTrue(replayed.consumeResult(late).isEmpty());
            replayed.retireSignOperation(late, "late completion cleanup");
            assertEquals(SignWorkflowStore.State.EXPIRED, reopened.getSignRecord(late).orElseThrow().state());
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
                PkiSigningBus bus = new PkiSigningBus(store, signer, signingAuthority(signer))) {
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
                PkiSigningBus replayed = new PkiSigningBus(reopened, signer, signingAuthority(signer))) {
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
                PkiSigningBus bus = new PkiSigningBus(store, signer, signingAuthority(signer))) {
            id = submit(bus);
            assertEquals(AsyncState.RUNNING, bus.status(id).orElseThrow().state());
            SignWorkflowStore.Record dispatched = store.getSignRecord(id).orElseThrow();
            store.transitionSign(id, dispatched.revision(), dispatched.fence(), SignWorkflowStore.State.CANCELLING,
                    Optional.of("CANCEL_REQUESTED"), Optional.empty(), Optional.empty()).orElseThrow();
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults());
                PkiSigningBus replayed = new PkiSigningBus(reopened, signer, signingAuthority(signer))) {
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
    void preDispatchExpiryMakesNoProviderCallAndPurgesAfterHorizon(@TempDir Path tempDir) throws Exception {
        Instant createdAt = Instant.parse("2026-05-06T07:08:09Z");
        MutableClock clock = new MutableClock(createdAt);
        ControlledWorkflow signer = new ControlledWorkflow(clock);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"), FsPkiStoreOptions.defaults(),
                clock); PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"),
                        signingAuthority(signer))) {
            PkiId id = submit(bus, Duration.ofSeconds(10));
            assertTrue(store.listWorkflowStates().isEmpty());
            clock.set(createdAt.plusSeconds(10));
            bus.sweep(clock.instant());
            assertEquals(0, signer.submissions.get());
            assertEquals(SignWorkflowStore.State.EXPIRED, store.getSignRecord(id).orElseThrow().state());
            assertTrue(bus.consumeResult(id).isEmpty());
            assertTrue(store.listWorkflowStates().isEmpty());

            clock.set(createdAt.plus(Duration.ofDays(90)));
            bus.sweep(clock.instant());
            assertTrue(store.listSignRecords().isEmpty());
            assertEquals(AsyncState.EXPIRED, bus.status(id).orElseThrow().state());
        }
    }

    @Test
    void postDispatchExpiryStopsProviderReconciliation(@TempDir Path tempDir) throws Exception {
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
            assertEquals(SignWorkflowStore.State.EXPIRED, store.getSignRecord(id).orElseThrow().state());
            assertEquals("EXPIRED", store.getSignRecord(id).orElseThrow().detailCode().orElseThrow());
            assertEquals(0, signer.cancellations.get());
            assertTrue(store.listWorkflowStates().isEmpty());
            assertTrue(bus.consumeResult(id).isEmpty());

            bus.sweep(clock.instant());
            assertEquals(0, signer.cancellations.get());
            assertEquals(SignWorkflowStore.State.EXPIRED, store.getSignRecord(id).orElseThrow().state());

            signer.completeCancelled(id, clock.instant());
            bus.sweep(clock.instant());
            assertEquals(SignWorkflowStore.State.EXPIRED, store.getSignRecord(id).orElseThrow().state());
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
            PkiException uncertain = assertInstanceOf(PkiException.class, late.getCause());
            assertEquals("Provider submission uncertain: code=PROVIDER_SUBMISSION_UNCERTAIN",
                    uncertain.getMessage());
            assertNull(uncertain.getCause());
            assertEquals(0, uncertain.getSuppressed().length);
            assertEquals(SignWorkflowStore.State.INTENT, store.getSignRecord(id).orElseThrow().state());
            assertEquals(1, signer.submissions.get());
        }
    }

    @Test
    void providerReturnAfterExactDeadlineCannotPublish(@TempDir Path tempDir) throws Exception {
        Instant createdAt = Instant.parse("2026-08-14T12:00:00.123Z");
        MutableClock clock = new MutableClock(createdAt);
        BlockingWorkflow signer = new BlockingWorkflow();
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, signingAuthority(signer));
                ExecutorService executor = Executors.newFixedThreadPool(2)) {
            PkiId id = submit(bus, Duration.ofSeconds(10L));
            Future<?> providerCall = executor.submit(() -> bus.status(id));
            assertTrue(signer.entered.await(5, TimeUnit.SECONDS));

            clock.set(createdAt.plusSeconds(10L));
            assertEquals(AsyncState.EXPIRED, bus.status(id).orElseThrow().state());
            assertEquals(SignWorkflowStore.State.EXPIRED, store.getSignRecord(id).orElseThrow().state());
            assertEquals(1, signer.submissions.get());

            signer.release.countDown();
            assertThrows(java.util.concurrent.ExecutionException.class,
                    () -> providerCall.get(5, TimeUnit.SECONDS));
            assertEquals(SignWorkflowStore.State.EXPIRED, store.getSignRecord(id).orElseThrow().state());
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
    void genericWorkflowStateDoesNotParticipateInSigningActivation(@TempDir Path tempDir) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults())) {
            Principal owner = new Principal("SYSTEM", "pki");
            Instant now = Instant.now();
            EncodedObject unsupported = new EncodedObject(Encoding.BINARY, new byte[] { 99 });
            store.putWorkflowState(new WorkflowStateRecord(new PkiId("generic-async"), "GENERIC.ASYNC",
                    owner, OrchestrationDurabilityPolicy.DURABLE_MIN_STATE, now, now, now.plusSeconds(60),
                    Encoding.BINARY, Optional.of(unsupported)));
            InMemorySignatureWorkflow signer = new InMemorySignatureWorkflow(Map.of(), false);
            try {
                try (PkiSigningBus bus = new PkiSigningBus(store, signer, signingAuthority(signer))) {
                    assertTrue(store.listSignRecords().isEmpty());
                    assertEquals(1, store.listWorkflowStates().size());
                }
            } finally {
                signer.close();
            }
        }
    }

    @Test
    void signingNeverTouchesGenericWorkflowOrLegacyLinePersistence(@TempDir Path tempDir) throws Exception {
        FilesystemPkiStore delegate = new FilesystemPkiStore(tempDir.resolve("store"), FsPkiStoreOptions.defaults());
        AtomicInteger genericWorkflowCalls = new AtomicInteger();
        PkiStore failingStore = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class }, (proxy, method, arguments) -> {
                    if (Set.of("putWorkflowState", "getWorkflowState", "listWorkflowStates", "deleteWorkflowState")
                            .contains(method.getName())) {
                        genericWorkflowCalls.incrementAndGet();
                        throw new AssertionError("signing touched generic workflow persistence");
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
        try (PkiSigningBus bus = new PkiSigningBus(failingStore, signer, signingAuthority(signer))) {
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
            assertEquals(0, genericWorkflowCalls.get());
            assertFalse(Files.exists(busLog));
            assertTrue(signer.hasRunningOperations());
            bus.retireSignOperation(operationId, "test complete");
            assertFalse(signer.hasRunningOperations());
            assertEquals(0, genericWorkflowCalls.get());
        }

        try (PkiSigningBus replayed = new PkiSigningBus(delegate, signer, signingAuthority(signer))) {
            assertEquals(AsyncState.CANCELLED, replayed.status(operationId).orElseThrow().state());
            assertTrue(delegate.listWorkflowStates().isEmpty());
            assertFalse(Files.exists(busLog));
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
        return new SigningReconciliationRequest(SigningReconciliationContinuation.start(cursor), maximumRecords,
                maximumCalls, clock.instant().plusSeconds(30), Duration.ofSeconds(10), () -> false);
    }

    private static SigningReconciliationRequest reconciliation(SigningReconciliationResult previous,
            int maximumRecords, int maximumCalls, Clock clock) {
        return SigningReconciliationRequest.continueFrom(previous, maximumRecords, maximumCalls,
                clock.instant().plusSeconds(30), Duration.ofSeconds(10), () -> false);
    }

    private static void awaitReady(SigningExecutionRuntime runtime, int expected) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
        while (runtime.metrics().ready() != expected && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        assertEquals(expected, runtime.metrics().ready());
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

    private static PkiStore malformedFirstPageStore(PkiStore delegate) {
        AtomicBoolean armed = new AtomicBoolean(true);
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, arguments) -> {
                    Object result;
                    try {
                        result = method.invoke(delegate, arguments);
                    } catch (InvocationTargetException failure) {
                        throw failure.getCause();
                    }
                    if (!("pageSignRecords".equals(method.getName())
                            || "pageDueSignRecords".equals(method.getName()))) {
                        return result;
                    }
                    SignWorkflowStore.Page page = (SignWorkflowStore.Page) result;
                    if (page.candidates().isEmpty() || !armed.compareAndSet(true, false)) {
                        return result;
                    }
                    List<SignWorkflowStore.PageCandidate> candidates = new ArrayList<>(page.candidates());
                    SignWorkflowStore.PageCandidate first = candidates.getFirst();
                    candidates.set(0, new SignWorkflowStore.PageCandidate(first.cursor(), Optional.empty()));
                    List<SignWorkflowStore.Record> records = new ArrayList<>(page.records());
                    records.removeFirst();
                    return new SignWorkflowStore.Page(records, page.nextCursor(), page.examined(),
                            page.failures() + 1, page.endReached(), candidates, page.highWatermark());
                });
    }

    private static void requestCancellation(SignWorkflowStore store, PkiId id) {
        SignWorkflowStore.Record dispatched = store.getSignRecord(id).orElseThrow();
        store.transitionSign(id, dispatched.revision(), dispatched.fence(), SignWorkflowStore.State.CANCELLING,
                Optional.of("CANCEL_REQUESTED"), Optional.empty(), Optional.empty()).orElseThrow();
    }

    private static PkiId submit(PkiSigningBus bus, Duration ttl) {
        return submit(bus, ttl, new KeyRef("test"), (byte) 1);
    }

    private static PkiId submit(PkiSigningBus bus, KeyRef keyRef, byte payloadByte) {
        return submit(bus, Duration.ofMinutes(5), keyRef, payloadByte);
    }

    private static PkiId submit(PkiSigningBus bus, Duration ttl, KeyRef keyRef, byte payloadByte) {
        Principal owner = new Principal("TEST", "owner");
        PkiId id = bus.newSubmissionId();
        EncodedObject payload = new EncodedObject(Encoding.BINARY, new byte[] { payloadByte });
        DurableContentReference content;
        try {
            content = stage(bus, payload);
        } catch (java.io.IOException exception) {
            throw new IllegalStateException("Test content staging failed", exception);
        }
        AccessContext access = new AccessContext(owner, new Purpose("TEST"), Optional.empty(), Optional.empty());
        PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(access, "SHA256withRSA",
                content, keyRef, Encoding.BINARY, Optional.empty());
        bus.submitSign(id, owner, keyRef, "SHA256withRSA", content, ttl,
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

    private static SignatureWorkflow.ConfigurationCommitment testConfigurationCommitment() {
        return new SignatureWorkflow.ConfigurationCommitment(
                new byte[SignatureWorkflow.ConfigurationCommitment.BYTE_LENGTH]);
    }

    private enum CallbackCancellationBoundary {
        CALLBACK_DROPPED,
        CALLBACK_DUPLICATED,
        CALLBACK_LATE,
        CALLBACK_THROWING,
        CALLBACK_REENTRANT,
        CANCEL_BEFORE_EXECUTION,
        CANCEL_DURING_EXECUTION,
        CANCEL_AFTER_TERMINAL_COMPUTATION,
        CANCEL_COMPLETION_RACE;

        private boolean callbackBoundary() {
            return ordinal() <= CALLBACK_REENTRANT.ordinal();
        }
    }

    private static final class MatrixWorkflow implements SignatureWorkflow {
        private final String workflowId;
        private final Clock clock;
        private final boolean delayedCancellationAcknowledgement;
        private final Map<PkiId, OperationStatus> statuses = new java.util.concurrent.ConcurrentHashMap<>();
        private final AtomicReference<NotificationSink> sink = new AtomicReference<>();
        private final AtomicReference<PkiId> blockedStatus = new AtomicReference<>();
        private final CountDownLatch statusEntered = new CountDownLatch(1);
        private final CountDownLatch statusRelease = new CountDownLatch(1);
        private final AtomicInteger submissions = new AtomicInteger();

        private MatrixWorkflow(String workflowId, Clock clock, boolean delayedCancellationAcknowledgement) {
            this.workflowId = workflowId;
            this.clock = clock;
            this.delayedCancellationAcknowledgement = delayedCancellationAcknowledgement;
        }

        @Override
        public String id() {
            return workflowId;
        }

        @Override
        public ConfigurationCommitment configurationCommitment() {
            return testConfigurationCommitment();
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
            PkiId blockedOperation = blockedStatus.get();
            if (operationId.equals(blockedOperation) && blockedStatus.compareAndSet(blockedOperation, null)) {
                statusEntered.countDown();
                try {
                    statusRelease.await();
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("Interrupted while awaiting deterministic status release",
                            exception);
                }
            }
            return statuses.get(operationId);
        }

        @Override
        public boolean cancel(PkiId operationId, long fencingToken, String reason, CallControl control) {
            if (!delayedCancellationAcknowledgement) {
                statuses.put(operationId, new OperationStatus(State.CANCELLED, clock.instant(),
                        Optional.of("CANCELLED"), Optional.empty()));
            }
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

        private void complete(PkiId operationId, byte resultByte) {
            OperationResult result = new OperationResult(
                    Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { resultByte })), Optional.empty());
            statuses.put(operationId, new OperationStatus(State.SUCCEEDED, clock.instant(),
                    Optional.of("SIGNED"), Optional.of(result)));
        }

        private void notifyStatus(PkiId operationId) {
            NotificationSink registered = sink.get();
            if (registered != null) {
                registered.onStatusChanged(operationId, statuses.get(operationId));
            }
        }

        private void notifyThenFail(PkiId operationId) {
            notifyStatus(operationId);
            throw new IllegalStateException("injected provider callback dispatch failure");
        }

        private void notifyThenReenter(PkiId operationId, PkiSigningBus bus) {
            notifyStatus(operationId);
            assertEquals(AsyncState.SUCCEEDED, bus.status(operationId).orElseThrow().state());
        }

        private void armStatusBlock(PkiId operationId) {
            blockedStatus.set(operationId);
        }

        private void releaseStatus() {
            statusRelease.countDown();
        }
    }

    private static final class ThrowingCancellationWorkflow implements SignatureWorkflow {
        private static final String HOSTILE_PROVIDER_TEXT = "hostile-provider-cancellation-text";
        private static final String HOSTILE_CAUSE = "hostile-provider-cause";
        private static final String HOSTILE_SUPPRESSED = "hostile-provider-suppressed-detail";
        private final Clock clock;
        private final Map<PkiId, OperationStatus> statuses = new java.util.concurrent.ConcurrentHashMap<>();
        private final AtomicInteger submissions = new AtomicInteger();
        private final AtomicInteger statusReads = new AtomicInteger();
        private final AtomicInteger cancellations = new AtomicInteger();
        private final AtomicReference<RuntimeException> cancellationFailure = new AtomicReference<>(
                new IllegalStateException("accepted outcome is deliberately uncertain"));

        private ThrowingCancellationWorkflow(Clock clock) {
            this.clock = clock;
        }

        @Override
        public String id() {
            return "throwing-cancellation";
        }

        @Override
        public ConfigurationCommitment configurationCommitment() {
            return testConfigurationCommitment();
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
            statusReads.incrementAndGet();
            return statuses.get(operationId);
        }

        @Override
        public boolean cancel(PkiId operationId, long fencingToken, String reason, CallControl control) {
            cancellations.incrementAndGet();
            RuntimeException failure = cancellationFailure.get();
            if (failure != null) {
                throw failure;
            }
            statuses.put(operationId, new OperationStatus(State.CANCELLED, clock.instant(),
                    Optional.of("CANCELLED"), Optional.empty()));
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
            // No owned resources.
        }

        private void resetObservations() {
            statusReads.set(0);
            cancellations.set(0);
        }

        private void armHostileCancellationFailure(PkiId operationId, KeyRef keyRef, Path hostilePath) {
            IllegalStateException cause = new IllegalStateException(HOSTILE_CAUSE + " operation="
                    + operationId.value());
            IllegalStateException failure = new IllegalStateException(HOSTILE_PROVIDER_TEXT + " operation="
                    + operationId.value() + " key=" + keyRef.value() + " path=" + hostilePath, cause);
            failure.addSuppressed(new IllegalArgumentException(HOSTILE_SUPPRESSED));
            cancellationFailure.set(failure);
        }

        private void allowCancellation() {
            cancellationFailure.set(null);
        }

        private List<String> hostileDetails(PkiId operationId, KeyRef keyRef, Path hostilePath) {
            return List.of(HOSTILE_PROVIDER_TEXT, operationId.value(), keyRef.value(), hostilePath.toString(),
                    HOSTILE_CAUSE, HOSTILE_SUPPRESSED);
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
        public ConfigurationCommitment configurationCommitment() {
            return testConfigurationCommitment();
        }

        @Override
        public PkiId submitSign(SignRequest request, CallControl control) {
            submissions.incrementAndGet();
            statuses.putIfAbsent(request.submissionId(),
                    new OperationStatus(State.RUNNING, clock.instant(), Optional.of("RUNNING"), Optional.empty()));
            IllegalStateException hostile = new IllegalStateException("hostile-provider-secret",
                    new IllegalArgumentException("hostile-provider-cause"));
            hostile.addSuppressed(new IllegalStateException("hostile-provider-suppressed"));
            throw hostile;
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
        private volatile boolean statusAvailable = true;

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
        public ConfigurationCommitment configurationCommitment() {
            return testConfigurationCommitment();
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
            if (!statusAvailable) {
                throw new IllegalStateException("injected status unavailability");
            }
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

    private static final class ControlCapturingWorkflow implements SignatureWorkflow {
        private final Clock clock;
        private final AtomicReference<CallControl> submitControl = new AtomicReference<>();
        private final AtomicReference<CallControl> statusControl = new AtomicReference<>();

        private ControlCapturingWorkflow(Clock clock) {
            this.clock = clock;
        }

        @Override public String id() { return "control-capturing"; }
        @Override public ConfigurationCommitment configurationCommitment() { return testConfigurationCommitment(); }
        @Override public PkiId submitSign(SignRequest request, CallControl control) {
            submitControl.set(control);
            return request.submissionId();
        }
        @Override public PkiId submitVerify(VerifyRequest request, CallControl control) {
            throw new UnsupportedOperationException();
        }
        @Override public OperationStatus status(PkiId operationId, CallControl control) {
            statusControl.set(control);
            return new OperationStatus(State.RUNNING, clock.instant(), Optional.of("RUNNING"), Optional.empty());
        }
        @Override public boolean cancel(PkiId operationId, long fencingToken, String reason, CallControl control) {
            return true;
        }
        @Override public Registration register(NotificationSink sink) { return () -> { }; }
        @Override public Set<String> supportedAlgorithms() { return Set.of("SHA256withRSA"); }
        @Override public void close() { }
    }

    private static final class ControlledWorkflow implements SignatureWorkflow {
        private final Clock clock;
        private final Runnable afterSubmission;
        private final Map<PkiId, OperationStatus> statuses = new java.util.concurrent.ConcurrentHashMap<>();
        private final AtomicInteger submissions = new AtomicInteger();
        private final AtomicInteger statusReads = new AtomicInteger();
        private final AtomicInteger cancellations = new AtomicInteger();
        private final List<PkiId> submissionAttempts = java.util.Collections.synchronizedList(new ArrayList<>());
        private final AtomicReference<Runnable> afterStatus = new AtomicReference<>(() -> { });

        private ControlledWorkflow(Clock clock) {
            this(clock, () -> { });
        }

        private ControlledWorkflow(Clock clock, Runnable afterSubmission) {
            this.clock = clock;
            this.afterSubmission = afterSubmission;
        }

        @Override
        public String id() {
            return "controlled";
        }

        @Override
        public ConfigurationCommitment configurationCommitment() {
            return testConfigurationCommitment();
        }

        @Override
        public PkiId submitSign(SignRequest request, CallControl control) {
            submissions.incrementAndGet();
            submissionAttempts.add(request.submissionId());
            statuses.put(request.submissionId(),
                    new OperationStatus(State.RUNNING, clock.instant(), Optional.of("RUNNING"), Optional.empty()));
            afterSubmission.run();
            return request.submissionId();
        }

        @Override
        public PkiId submitVerify(VerifyRequest request, CallControl control) {
            throw new UnsupportedOperationException();
        }

        @Override
        public OperationStatus status(PkiId operationId, CallControl control) {
            statusReads.incrementAndGet();
            afterStatus.getAndSet(() -> { }).run();
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

        private void afterNextStatus(Runnable action) {
            afterStatus.set(action);
        }
    }

    private static final class RetirementRaceWorkflow implements SignatureWorkflow {
        private final AtomicReference<OperationStatus> status = new AtomicReference<>(
                new OperationStatus(State.RUNNING, Instant.EPOCH, Optional.of("RUNNING"), Optional.empty()));
        private final AtomicReference<PkiId> operationId = new AtomicReference<>();
        private final AtomicReference<NotificationSink> sink = new AtomicReference<>();
        private final AtomicBoolean blockStatus = new AtomicBoolean();
        private final AtomicBoolean nonCooperativeStatus = new AtomicBoolean();
        private final CountDownLatch statusEntered = new CountDownLatch(1);
        private final CountDownLatch statusRelease = new CountDownLatch(1);
        private final CountDownLatch statusExited = new CountDownLatch(1);
        private final AtomicInteger submissions = new AtomicInteger();
        private final AtomicInteger cancellations = new AtomicInteger();

        @Override
        public String id() {
            return "retirement-race";
        }

        @Override
        public ConfigurationCommitment configurationCommitment() {
            return testConfigurationCommitment();
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
                boolean interrupted = false;
                try {
                    while (statusRelease.getCount() != 0L) {
                        try {
                            statusRelease.await();
                        } catch (InterruptedException ex) {
                            if (!nonCooperativeStatus.get()) {
                                Thread.currentThread().interrupt();
                                throw new IllegalStateException(ex);
                            }
                            interrupted = true;
                        }
                    }
                } finally {
                    statusExited.countDown();
                    if (interrupted) {
                        Thread.currentThread().interrupt();
                    }
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

        private void armNonCooperativeStatusBlock() {
            nonCooperativeStatus.set(true);
            blockStatus.set(true);
        }

        private void releaseStatusBlock() {
            statusRelease.countDown();
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
        public ConfigurationCommitment configurationCommitment() {
            return testConfigurationCommitment();
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
        private static final String HOSTILE_ADVISORY_ID =
                "hostile-advisory-id key=provider:key path=/provider/private cause=secret suppressed=detail";
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
        public ConfigurationCommitment configurationCommitment() {
            return testConfigurationCommitment();
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

        private void emitMalformedAdvisories() {
            NotificationSink registered = sink.get();
            if (registered != null) {
                registered.onStatusChanged(null, null);
                registered.onStatusChanged(new PkiId(HOSTILE_ADVISORY_ID), null);
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
        public ConfigurationCommitment configurationCommitment() {
            return testConfigurationCommitment();
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
        public ConfigurationCommitment configurationCommitment() {
            return testConfigurationCommitment();
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
        public ConfigurationCommitment configurationCommitment() {
            return testConfigurationCommitment();
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
