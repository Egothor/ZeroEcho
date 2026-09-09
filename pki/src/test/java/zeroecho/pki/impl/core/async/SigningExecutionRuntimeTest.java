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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import org.junit.jupiter.api.Test;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.application.PkiSessionConfiguration;
import zeroecho.pki.impl.core.async.SigningExecutionRuntime.InitialStepReservation;
import zeroecho.pki.impl.core.async.SigningExecutionRuntime.StepDisposition;
import zeroecho.pki.impl.core.async.SigningExecutionRuntime.StepSubmission;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataStoreException;

final class SigningExecutionRuntimeTest {

    @Test
    void queuedTerminalPreparationReservesSlotAtCentralHandoffAndCanSuspend() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 1);
                InitialStepReservation initial = runtime.reserveInitialStep()) {
            SigningExecutionRuntime.TerminalOwner owner = runtime.attachTerminalOwner();
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            StepSubmission<String> blocker = scheduleAccepted(runtime, id(10), blocking(entered, release));
            assertTrue(entered.await(1, TimeUnit.SECONDS));
            ControlledTerminal completion = new ControlledTerminal("accepted");
            StepSubmission<String> terminal = runtime.scheduleInitialTerminalStep(owner, initial, id(11),
                    () -> completion, CancellationSignal.NONE);
            assertEquals(1, runtime.metrics().ready());

            release.countDown();
            assertEquals("done", blocker.future().orElseThrow().get(1, TimeUnit.SECONDS));
            assertEquals("accepted", terminal.future().orElseThrow().get(1, TimeUnit.SECONDS));
            assertEquals(1, runtime.terminalSlotsInUse());
            assertEquals(1, runtime.suspendedTerminalCount());
        }
    }

    @Test
    void sharedRuntimeRestorationRecoveryAndLateCallbacksAreOwnerIsolated() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(2, 2);
                InitialStepReservation first = runtime.reserveInitialStep();
                InitialStepReservation second = runtime.reserveInitialStep()) {
            SigningExecutionRuntime.TerminalOwner firstOwner = runtime.attachTerminalOwner();
            SigningExecutionRuntime.TerminalOwner secondOwner = runtime.attachTerminalOwner();
            ControlledTerminal firstCompletion = new ControlledTerminal("first");
            ControlledTerminal secondCompletion = new ControlledTerminal("second");
            StepSubmission<String> firstTerminal = runtime.scheduleInitialTerminalStep(firstOwner, first, id(20),
                    () -> firstCompletion, CancellationSignal.NONE);
            StepSubmission<String> secondTerminal = runtime.scheduleInitialTerminalStep(secondOwner, second, id(21),
                    () -> secondCompletion, CancellationSignal.NONE);
            assertEquals("first", firstTerminal.future().orElseThrow().get(1, TimeUnit.SECONDS));
            assertEquals("second", secondTerminal.future().orElseThrow().get(1, TimeUnit.SECONDS));
            awaitSuspended(runtime, 2);

            firstCompletion.allowCommit.set(true);
            runtime.headroomRestored(firstOwner, 1L);
            awaitSuspended(runtime, 1);
            assertTrue(firstCompletion.closed.get());
            assertFalse(secondCompletion.closed.get());

            runtime.headroomRecoveryRequired(secondOwner);
            awaitScheduled(runtime, 0);
            assertTrue(secondCompletion.closed.get());
            runtime.detachTerminalOwner(secondOwner);
            runtime.headroomRestored(secondOwner, 2L);
            runtime.headroomRecoveryRequired(secondOwner);
            assertEquals(0, runtime.metrics().schedulerReserved());
        }
    }

    @Test
    void queuedPreparationSkipsCryptoAfterOwnerRecoveryWithoutAffectingOtherOwner() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 2);
                InitialStepReservation recoveringInitial = runtime.reserveInitialStep();
                InitialStepReservation healthyInitial = runtime.reserveInitialStep()) {
            SigningExecutionRuntime.TerminalOwner recoveringOwner = runtime.attachTerminalOwner();
            SigningExecutionRuntime.TerminalOwner healthyOwner = runtime.attachTerminalOwner();
            CountDownLatch blockerEntered = new CountDownLatch(1);
            CountDownLatch releaseBlocker = new CountDownLatch(1);
            StepSubmission<String> blocker = scheduleAccepted(runtime, id(30),
                    blocking(blockerEntered, releaseBlocker));
            assertTrue(blockerEntered.await(1, TimeUnit.SECONDS));
            AtomicInteger recoveringCrypto = new AtomicInteger();
            AtomicInteger healthyCrypto = new AtomicInteger();
            ControlledTerminal recoveringCompletion = new ControlledTerminal("recovering");
            ControlledTerminal healthyCompletion = new ControlledTerminal("healthy");
            healthyCompletion.allowCommit.set(true);
            StepSubmission<String> recovering = runtime.scheduleInitialTerminalStep(recoveringOwner,
                    recoveringInitial, id(31), () -> prepared(recoveringCrypto, recoveringCompletion),
                    CancellationSignal.NONE);
            StepSubmission<String> healthy = runtime.scheduleInitialTerminalStep(healthyOwner,
                    healthyInitial, id(32), () -> prepared(healthyCrypto, healthyCompletion),
                    CancellationSignal.NONE);

            runtime.headroomRecoveryRequired(recoveringOwner);
            releaseBlocker.countDown();
            assertEquals("done", blocker.future().orElseThrow().get(1, TimeUnit.SECONDS));
            ExecutionException recovery = assertThrows(ExecutionException.class,
                    () -> recovering.future().orElseThrow().get(1, TimeUnit.SECONDS));
            assertTrue(recovery.getCause() instanceof SigningExecutionException);
            assertEquals("healthy", healthy.future().orElseThrow().get(1, TimeUnit.SECONDS));
            awaitScheduled(runtime, 0);
            assertEquals(0, runtime.terminalSlotsInUse());
            assertEquals(0, recoveringCrypto.get());
            assertEquals(1, healthyCrypto.get());
            assertFalse(recoveringCompletion.closed.get());
            assertTrue(healthyCompletion.closed.get());
        }
    }

    @Test
    void suspendedTerminalReleasesWorkerAndResumesWithoutRepeatingPreparation() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 1);
                InitialStepReservation initial = runtime.reserveInitialStep()) {
            SigningExecutionRuntime.TerminalOwner owner = runtime.attachTerminalOwner();
            AtomicInteger preparations = new AtomicInteger();
            ControlledTerminal completion = new ControlledTerminal("accepted");
            StepSubmission<String> terminal = runtime.scheduleInitialTerminalStep(owner, initial, id(1), () -> {
                preparations.incrementAndGet();
                return completion;
            }, CancellationSignal.NONE);

            assertEquals("accepted", terminal.future().orElseThrow().get(1, TimeUnit.SECONDS));
            assertEquals(1, runtime.suspendedTerminalCount());
            assertEquals(1, runtime.terminalSlotsInUse());
            assertEquals(1, preparations.get());

            StepSubmission<String> ordinary = scheduleAccepted(runtime, id(2), () -> "ordinary");
            assertEquals("ordinary", ordinary.future().orElseThrow().get(1, TimeUnit.SECONDS));
            completion.allowCommit.set(true);
            runtime.headroomRestored(owner, 1L);
            awaitScheduled(runtime, 0);

            assertEquals(1, preparations.get());
            assertEquals(2, completion.commitAttempts.get());
            assertTrue(completion.closed.get());
        }
    }

    @Test
    void terminalSlotBoundEqualsLaneCountAndBlocksAdditionalCryptography() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(2, 2);
                InitialStepReservation first = runtime.reserveInitialStep();
                InitialStepReservation second = runtime.reserveInitialStep();
                InitialStepReservation third = runtime.reserveInitialStep()) {
            SigningExecutionRuntime.TerminalOwner owner = runtime.attachTerminalOwner();
            AtomicInteger preparations = new AtomicInteger();
            ControlledTerminal firstCompletion = new ControlledTerminal("first");
            ControlledTerminal secondCompletion = new ControlledTerminal("second");
            ControlledTerminal thirdCompletion = new ControlledTerminal("third");
            runtime.scheduleInitialTerminalStep(owner, first, id(1),
                    () -> prepared(preparations, firstCompletion), CancellationSignal.NONE);
            runtime.scheduleInitialTerminalStep(owner, second, id(2),
                    () -> prepared(preparations, secondCompletion), CancellationSignal.NONE);
            runtime.scheduleInitialTerminalStep(owner, third, id(3),
                    () -> prepared(preparations, thirdCompletion), CancellationSignal.NONE);

            awaitSuspended(runtime, 2);
            assertEquals(runtime.terminalSlotCapacity(), runtime.terminalSlotsInUse());
            assertEquals(2, preparations.get());
            assertEquals(1, runtime.metrics().ready());
        }
    }

    @Test
    void restoredTerminalRunsBeforeOrdinaryReadyWork() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 2);
                InitialStepReservation initial = runtime.reserveInitialStep()) {
            SigningExecutionRuntime.TerminalOwner owner = runtime.attachTerminalOwner();
            List<String> order = java.util.Collections.synchronizedList(new ArrayList<>());
            ControlledTerminal completion = new ControlledTerminal("accepted", order);
            StepSubmission<String> terminal = runtime.scheduleInitialTerminalStep(owner, initial, id(1),
                    () -> completion, CancellationSignal.NONE);
            assertEquals("accepted", terminal.future().orElseThrow().get(1, TimeUnit.SECONDS));

            CountDownLatch blockerEntered = new CountDownLatch(1);
            CountDownLatch releaseBlocker = new CountDownLatch(1);
            StepSubmission<String> blocker = scheduleAccepted(runtime, id(2), () -> {
                blockerEntered.countDown();
                releaseBlocker.await();
                return "blocker";
            });
            assertTrue(blockerEntered.await(1, TimeUnit.SECONDS));
            StepSubmission<String> ordinary = scheduleAccepted(runtime, id(3), () -> {
                order.add("ordinary");
                return "ordinary";
            });
            completion.allowCommit.set(true);
            runtime.headroomRestored(owner, 1L);
            releaseBlocker.countDown();

            assertEquals("blocker", blocker.future().orElseThrow().get(1, TimeUnit.SECONDS));
            assertEquals("ordinary", ordinary.future().orElseThrow().get(1, TimeUnit.SECONDS));
            awaitScheduled(runtime, 0);
            assertEquals(List.of("terminal", "ordinary"), order);
        }
    }

    @Test
    void closeClearsSuspendedTerminalOwnership() throws Exception {
        SigningExecutionRuntime runtime = runtime(1, 0);
        SigningExecutionRuntime.TerminalOwner owner = runtime.attachTerminalOwner();
        ControlledTerminal completion = new ControlledTerminal("accepted");
        try (InitialStepReservation initial = runtime.reserveInitialStep()) {
            StepSubmission<String> terminal = runtime.scheduleInitialTerminalStep(owner, initial, id(1),
                    () -> completion, CancellationSignal.NONE);
            assertEquals("accepted", terminal.future().orElseThrow().get(1, TimeUnit.SECONDS));
            runtime.close();
            assertTrue(completion.closed.get());
            assertEquals(0, runtime.terminalSlotsInUse());
            assertEquals(0, runtime.suspendedTerminalCount());
        }
    }

    @Test
    void initialReservationsClaimExactSchedulerCapacityAndCloseReusesIt() {
        try (SigningExecutionRuntime runtime = runtime(2, 2);
                InitialStepReservation first = runtime.reserveInitialStep();
                InitialStepReservation second = runtime.reserveInitialStep();
                InitialStepReservation third = runtime.reserveInitialStep();
                InitialStepReservation fourth = runtime.reserveInitialStep()) {
            assertEquals(4, runtime.metrics().schedulerReserved());
            SigningExecutionException saturated = assertThrows(SigningExecutionException.class,
                    runtime::reserveInitialStep);
            assertEquals(SigningExecutionException.Classification.OVERLOADED,
                    saturated.classification());
            first.close();
            first.close();
            try (InitialStepReservation reused = runtime.reserveInitialStep()) {
                assertEquals(4, runtime.metrics().schedulerReserved());
            }
        }
    }

    @Test
    void ordinarySchedulingCannotStealPromisedInitialSlot() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 1);
                InitialStepReservation initial = runtime.reserveInitialStep()) {
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            StepSubmission<String> active = scheduleAccepted(
                    runtime, id(1), blocking(entered, release));
            assertTrue(entered.await(1, TimeUnit.SECONDS));
            assertEquals(StepDisposition.SATURATED,
                    runtime.scheduleStep(id(2), () -> "stolen", CancellationSignal.NONE)
                            .disposition());

            StepSubmission<String> promised = runtime.scheduleInitialStep(
                    initial, id(3), () -> "initial", CancellationSignal.NONE);
            assertEquals(StepDisposition.ACCEPTED, promised.disposition());
            assertEquals(1, runtime.metrics().ready());
            release.countDown();
            assertEquals("done", active.future().orElseThrow().get(1, TimeUnit.SECONDS));
            assertEquals("initial", promised.future().orElseThrow().get(1, TimeUnit.SECONDS));
            awaitScheduled(runtime, 0);
        }
    }

    @Test
    void consumedInitialReservationIsOneShotAndReleasesAfterStepNotWorkflowLifetime()
            throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 1);
                InitialStepReservation initial = runtime.reserveInitialStep()) {
            PkiId durableOperation = id(1);
            StepSubmission<String> step = runtime.scheduleInitialStep(
                    initial, durableOperation, () -> "submitted", CancellationSignal.NONE);
            assertEquals("submitted", step.future().orElseThrow().get(1, TimeUnit.SECONDS));
            awaitScheduled(runtime, 0);
            assertThrows(IllegalStateException.class, () -> runtime.scheduleInitialStep(
                    initial, durableOperation, () -> "again", CancellationSignal.NONE));
            try (InitialStepReservation next = runtime.reserveInitialStep()) {
                assertEquals(1, runtime.metrics().schedulerReserved());
            }
        }
    }

    @Test
    void zeroQueueInitialReservationGuaranteesDirectHandoffWithoutCallerRun() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 0);
                InitialStepReservation initial = runtime.reserveInitialStep()) {
            AtomicReference<Thread> providerThread = new AtomicReference<>();
            Thread caller = Thread.currentThread();
            assertEquals(StepDisposition.SATURATED,
                    runtime.scheduleStep(id(2), () -> "ordinary", CancellationSignal.NONE)
                            .disposition());
            StepSubmission<String> step = runtime.scheduleInitialStep(initial, id(1), () -> {
                providerThread.set(Thread.currentThread());
                return "done";
            }, CancellationSignal.NONE);
            assertEquals("done", step.future().orElseThrow().get(1, TimeUnit.SECONDS));
            assertTrue(providerThread.get() != caller);
            awaitScheduled(runtime, 0);
        }
    }

    @Test
    void zeroQueueRepeatedlyHandsOffToFixedLaneWithoutCallerExecution() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 0)) {
            Thread caller = Thread.currentThread();
            for (int index = 0; index < 100; index++) {
                AtomicReference<Thread> providerThread = new AtomicReference<>();
                StepSubmission<String> step = runtime.scheduleStep(id(index), () -> {
                    providerThread.set(Thread.currentThread());
                    return "done";
                }, CancellationSignal.NONE);
                assertEquals(StepDisposition.ACCEPTED, step.disposition());
                assertEquals("done", step.future().orElseThrow().get(1, TimeUnit.SECONDS));
                assertTrue(providerThread.get() != caller);
                awaitScheduled(runtime, 0);
            }
        }
    }

    @Test
    void naturalSuccessAndFailureReleaseCapacityBeforeFuturePublication() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 0)) {
            StepSubmission<String> success = scheduleAccepted(
                    runtime, id(1), () -> "success");

            assertEquals("success", success.future().orElseThrow().get(1, TimeUnit.SECONDS));
            assertSchedulerReleased(runtime);

            IllegalStateException injected = new IllegalStateException("injected failure");
            StepSubmission<String> failure = runtime.scheduleStep(id(2), () -> {
                throw injected;
            }, CancellationSignal.NONE);
            assertEquals(StepDisposition.ACCEPTED, failure.disposition());
            ExecutionException observed = assertThrows(ExecutionException.class,
                    () -> failure.future().orElseThrow().get(1, TimeUnit.SECONDS));
            assertEquals(injected, observed.getCause());
            assertSchedulerReleased(runtime);

            StepSubmission<String> replacement = runtime.scheduleStep(
                    id(3), () -> "replacement", CancellationSignal.NONE);
            assertEquals(StepDisposition.ACCEPTED, replacement.disposition());
            assertEquals("replacement", replacement.future().orElseThrow().get(1, TimeUnit.SECONDS));
            assertSchedulerReleased(runtime);
        }
    }

    @Test
    void initialSuccessAndFailureReleaseCapacityBeforeFuturePublication() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 0)) {
            try (InitialStepReservation successReservation = runtime.reserveInitialStep()) {
                StepSubmission<String> success = runtime.scheduleInitialStep(
                        successReservation, id(1), () -> "success", CancellationSignal.NONE);
                assertEquals("success", success.future().orElseThrow().get(1, TimeUnit.SECONDS));
                assertSchedulerReleased(runtime);
            }

            try (InitialStepReservation failureReservation = runtime.reserveInitialStep()) {
                IllegalArgumentException injected = new IllegalArgumentException("injected initial failure");
                StepSubmission<String> failure = runtime.scheduleInitialStep(
                        failureReservation, id(2), () -> {
                            throw injected;
                        }, CancellationSignal.NONE);
                ExecutionException observed = assertThrows(ExecutionException.class,
                        () -> failure.future().orElseThrow().get(1, TimeUnit.SECONDS));
                assertEquals(injected, observed.getCause());
                assertSchedulerReleased(runtime);
            }

            try (InitialStepReservation replacementReservation = runtime.reserveInitialStep()) {
                StepSubmission<String> replacement = runtime.scheduleInitialStep(
                        replacementReservation, id(3), () -> "replacement", CancellationSignal.NONE);
                assertEquals("replacement", replacement.future().orElseThrow().get(1, TimeUnit.SECONDS));
                assertSchedulerReleased(runtime);
            }
        }
    }

    @Test
    void fifoReadyHandoffPrecedesNaturalFuturePublication() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 1)) {
            CountDownLatch firstEntered = new CountDownLatch(1);
            CountDownLatch releaseFirst = new CountDownLatch(1);
            CountDownLatch secondEntered = new CountDownLatch(1);
            CountDownLatch releaseSecond = new CountDownLatch(1);
            StepSubmission<String> first = scheduleAccepted(
                    runtime, id(1), blocking(firstEntered, releaseFirst));
            assertTrue(firstEntered.await(1, TimeUnit.SECONDS));
            StepSubmission<String> second = runtime.scheduleStep(id(2), () -> {
                secondEntered.countDown();
                releaseSecond.await();
                return "second";
            }, CancellationSignal.NONE);
            assertEquals(StepDisposition.ACCEPTED, second.disposition());
            assertEquals(1, runtime.metrics().ready());

            releaseFirst.countDown();
            assertEquals("done", first.future().orElseThrow().get(1, TimeUnit.SECONDS));
            assertEquals(1, runtime.metrics().schedulerReserved());
            assertEquals(0, runtime.metrics().ready());
            assertTrue(secondEntered.await(1, TimeUnit.SECONDS));

            releaseSecond.countDown();
            assertEquals("second", second.future().orElseThrow().get(1, TimeUnit.SECONDS));
            assertSchedulerReleased(runtime);
        }
    }

    @Test
    void successAndFailureCancellationRacesReleaseExactlyOnce() throws Exception {
        assertCompletionCancellationRace(false);
        assertCompletionCancellationRace(true);
    }

    @Test
    void cancelledInitialStepNeverEntersProviderAndReleasesCapacity() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 1);
                InitialStepReservation initial = runtime.reserveInitialStep()) {
            AtomicBoolean providerEntered = new AtomicBoolean();
            StepSubmission<String> cancelled = runtime.scheduleInitialStep(initial, id(1), () -> {
                providerEntered.set(true);
                return "unexpected";
            }, () -> true);
            assertEquals(StepDisposition.ACCEPTED, cancelled.disposition());
            assertThrows(ExecutionException.class,
                    () -> cancelled.future().orElseThrow().get(1, TimeUnit.SECONDS));
            assertFalse(providerEntered.get());
            awaitScheduled(runtime, 0);
            try (InitialStepReservation reused = runtime.reserveInitialStep()) {
                assertEquals(1, runtime.metrics().schedulerReserved());
            }
        }
    }

    @Test
    void shutdownCancelsUnconsumedInitialReservationAndRejectsConsumption() {
        SigningExecutionRuntime runtime = runtime(1, 1);
        InitialStepReservation initial = runtime.reserveInitialStep();
        runtime.close();
        assertEquals(0, runtime.metrics().schedulerReserved());
        assertEquals(SigningExecutionRuntime.State.CLOSED, runtime.state());
        assertThrows(IllegalStateException.class, () -> runtime.scheduleInitialStep(
                initial, id(1), () -> "unexpected", CancellationSignal.NONE));
        initial.close();
    }

    @Test
    void configuredLanesAndReadyQueueAreExactBounds() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(2, 2)) {
            CountDownLatch entered = new CountDownLatch(2);
            CountDownLatch release = new CountDownLatch(1);
            List<StepSubmission<String>> accepted = new ArrayList<>();
            accepted.add(runtime.scheduleStep(id(1), blocking(entered, release), CancellationSignal.NONE));
            accepted.add(runtime.scheduleStep(id(2), blocking(entered, release), CancellationSignal.NONE));
            assertTrue(entered.await(1, TimeUnit.SECONDS));
            accepted.add(runtime.scheduleStep(id(3), () -> "third", CancellationSignal.NONE));
            accepted.add(runtime.scheduleStep(id(4), () -> "fourth", CancellationSignal.NONE));

            assertEquals(2, runtime.metrics().running());
            assertEquals(2, runtime.metrics().ready());
            assertEquals(4, runtime.metrics().schedulerReserved());
            assertEquals(StepDisposition.SATURATED,
                    runtime.scheduleStep(id(5), () -> "rejected", CancellationSignal.NONE).disposition());

            release.countDown();
            for (StepSubmission<String> step : accepted) {
                assertEquals(StepDisposition.ACCEPTED, step.disposition());
                step.future().orElseThrow().get(1, TimeUnit.SECONDS);
            }
            awaitScheduled(runtime, 0);
        }
    }

    @Test
    void durablePendingIdentitiesConsumeNoRuntimeCapacity() {
        try (SigningExecutionRuntime runtime = runtime(1, 1)) {
            for (int index = 0; index < 10_000; index++) {
                runtime.completeOperation(id(index));
            }
            assertEquals(0, runtime.metrics().schedulerReserved());
            assertEquals(0, runtime.metrics().ready());
            assertEquals(0, runtime.metrics().running());
        }
    }

    @Test
    void duplicateOperationStepIsBusyAndDoesNotCreateAWaiter() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 1)) {
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            StepSubmission<String> active = scheduleAccepted(runtime, id(1), blocking(entered, release));
            assertTrue(entered.await(1, TimeUnit.SECONDS));

            StepSubmission<String> duplicate = runtime.scheduleStep(id(1), () -> "duplicate",
                    CancellationSignal.NONE);
            assertEquals(StepDisposition.BUSY, duplicate.disposition());
            assertEquals(1, runtime.metrics().schedulerReserved());
            assertEquals(0, runtime.metrics().ready());

            release.countDown();
            assertEquals("done", active.future().orElseThrow().get(1, TimeUnit.SECONDS));
        }
    }

    @Test
    void zeroQueueReturnsSaturationWithoutSpinOrCallerRun() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 0)) {
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            StepSubmission<String> active = scheduleAccepted(runtime, id(1), blocking(entered, release));
            assertTrue(entered.await(1, TimeUnit.SECONDS));
            AtomicBoolean callerRan = new AtomicBoolean();

            StepSubmission<String> saturated = runtime.scheduleStep(id(2), () -> {
                callerRan.set(true);
                return "unexpected";
            }, CancellationSignal.NONE);

            assertEquals(StepDisposition.SATURATED, saturated.disposition());
            assertFalse(callerRan.get());
            assertEquals(0, runtime.metrics().ready());
            release.countDown();
            active.future().orElseThrow().get(1, TimeUnit.SECONDS);
        }
    }

    @Test
    void queuedCancellationPreventsProviderEntry() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 1)) {
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            StepSubmission<String> active = runtime.scheduleStep(id(1), blocking(entered, release),
                    CancellationSignal.NONE);
            assertTrue(entered.await(1, TimeUnit.SECONDS));
            AtomicBoolean cancelled = new AtomicBoolean();
            AtomicBoolean providerEntered = new AtomicBoolean();
            StepSubmission<String> queued = runtime.scheduleStep(id(2), () -> {
                providerEntered.set(true);
                return "unexpected";
            }, cancelled::get);
            assertEquals(StepDisposition.ACCEPTED, queued.disposition());
            cancelled.set(true);
            release.countDown();

            active.future().orElseThrow().get(1, TimeUnit.SECONDS);
            assertThrows(ExecutionException.class,
                    () -> queued.future().orElseThrow().get(1, TimeUnit.SECONDS));
            assertFalse(providerEntered.get());
            awaitScheduled(runtime, 0);
        }
    }

    @Test
    void explicitQueuedCancellationImmediatelyReusesExactSlot() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 1)) {
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            StepSubmission<String> active = runtime.scheduleStep(id(1), blocking(entered, release),
                    CancellationSignal.NONE);
            assertTrue(entered.await(1, TimeUnit.SECONDS));
            StepSubmission<String> queued = runtime.scheduleStep(id(2), () -> "cancelled",
                    CancellationSignal.NONE);
            assertEquals(1, runtime.metrics().ready());

            assertTrue(queued.future().orElseThrow().cancel(false));
            assertEquals(0, runtime.metrics().ready());
            assertEquals(1, runtime.metrics().schedulerReserved());
            StepSubmission<String> replacement = runtime.scheduleStep(id(3), () -> "replacement",
                    CancellationSignal.NONE);
            assertEquals(StepDisposition.ACCEPTED, replacement.disposition());
            assertEquals(1, runtime.metrics().ready());

            release.countDown();
            assertEquals("done", active.future().orElseThrow().get(1, TimeUnit.SECONDS));
            assertEquals("replacement", replacement.future().orElseThrow().get(1, TimeUnit.SECONDS));
            awaitScheduled(runtime, 0);
        }
    }

    @Test
    void readyStepsRemainFifoAcrossLanePromotion() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 3)) {
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            List<Integer> order = new ArrayList<>();
            StepSubmission<String> active = runtime.scheduleStep(id(1), blocking(entered, release),
                    CancellationSignal.NONE);
            assertTrue(entered.await(1, TimeUnit.SECONDS));
            List<StepSubmission<Integer>> queued = new ArrayList<>();
            for (int index = 2; index <= 4; index++) {
                int value = index;
                queued.add(runtime.scheduleStep(id(index), () -> {
                    order.add(value);
                    return value;
                }, CancellationSignal.NONE));
            }

            release.countDown();
            active.future().orElseThrow().get(1, TimeUnit.SECONDS);
            for (StepSubmission<Integer> step : queued) {
                step.future().orElseThrow().get(1, TimeUnit.SECONDS);
            }
            assertEquals(List.of(2, 3, 4), order);
            awaitScheduled(runtime, 0);
        }
    }

    @Test
    void runningCancellationRetainsLaneAndSlotUntilCallableExits() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 0)) {
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            StepSubmission<String> active = runtime.scheduleStep(id(1), () -> {
                entered.countDown();
                boolean finished = false;
                while (!finished) {
                    try {
                        finished = release.await(1, TimeUnit.SECONDS);
                    } catch (InterruptedException ignored) {
                        // Deliberately retain the lane until the deterministic release.
                    }
                }
                return "ignored-by-cancelled-future";
            }, CancellationSignal.NONE);
            assertTrue(entered.await(1, TimeUnit.SECONDS));

            assertTrue(active.future().orElseThrow().cancel(true));
            assertTrue(active.future().orElseThrow().isCancelled());
            assertEquals(1, runtime.metrics().schedulerReserved());
            assertEquals(1, runtime.metrics().running());
            assertEquals(StepDisposition.SATURATED,
                    runtime.scheduleStep(id(2), () -> "must-wait", CancellationSignal.NONE).disposition());

            release.countDown();
            awaitScheduled(runtime, 0);
        }
    }

    @Test
    void interruptedSynchronousWaitCancelsQueuedStepAndRestoresInterrupt() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 1)) {
            CountDownLatch activeEntered = new CountDownLatch(1);
            CountDownLatch activeRelease = new CountDownLatch(1);
            StepSubmission<String> active = runtime.scheduleStep(id(1), blocking(activeEntered, activeRelease),
                    CancellationSignal.NONE);
            assertTrue(activeEntered.await(1, TimeUnit.SECONDS));
            AtomicReference<Thread> callerThread = new AtomicReference<>();
            CompletableFuture<Boolean> caller = CompletableFuture.supplyAsync(() -> {
                callerThread.set(Thread.currentThread());
                try {
                    runtime.executeOperationStep(id(2), () -> "unexpected", Instant.now().plusSeconds(2),
                            CancellationSignal.NONE);
                    return false;
                } catch (SigningExecutionException failure) {
                    return Thread.currentThread().isInterrupted();
                }
            });
            awaitReady(runtime, 1);
            callerThread.get().interrupt();
            assertTrue(caller.get(1, TimeUnit.SECONDS));
            activeRelease.countDown();
            active.future().orElseThrow().get(1, TimeUnit.SECONDS);
            awaitScheduled(runtime, 0);
        }
    }

    @Test
    void callbacksAreBoundedAndIndependentOfScheduledMembership() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 1)) {
            CountDownLatch wake = new CountDownLatch(1);
            try (AutoCloseable registration = runtime.registerWakeListener(wake::countDown)) {
                runtime.advisory(id(1));
                runtime.advisory(id(1));
                runtime.advisory(id(2));
                runtime.advisory(id(3));
                assertTrue(wake.await(1, TimeUnit.SECONDS));
                assertEquals(2, runtime.metrics().pendingAdvisories());
                assertEquals(1, runtime.metrics().callbackCoalesced());
                assertEquals(1, runtime.metrics().callbackDropped());
                assertEquals(Optional.of(id(1)), runtime.pollAdvisory());
            }
        }
    }

    @Test
    void blockedListenerCannotBlockProviderAdvisoryAndWakeDuringInvocationFollowsOnce() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 1)) {
            CountDownLatch firstEntered = new CountDownLatch(1);
            CountDownLatch releaseFirst = new CountDownLatch(1);
            CountDownLatch twoInvocations = new CountDownLatch(2);
            AtomicInteger invocations = new AtomicInteger();
            try (AutoCloseable registration = runtime.registerWakeListener(() -> {
                int invocation = invocations.incrementAndGet();
                twoInvocations.countDown();
                if (invocation == 1) {
                    firstEntered.countDown();
                    try {
                        releaseFirst.await();
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                    }
                }
            })) {
                runtime.advisory(id(1));
                assertTrue(firstEntered.await(1, TimeUnit.SECONDS));
                CompletableFuture<Void> callback = CompletableFuture.runAsync(() -> runtime.advisory(id(2)));
                callback.get(1, TimeUnit.SECONDS);
                releaseFirst.countDown();
                assertTrue(twoInvocations.await(1, TimeUnit.SECONDS));
                assertEquals(2, invocations.get());
                assertEquals(2, runtime.metrics().callbackWake());
            }
        }
    }

    @Test
    void concurrentDistinctAdvisoriesNeverExceedExactBound() throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 1);
                AutoCloseable registration = runtime.registerWakeListener(() -> { });
                ExecutorService callbacks = Executors.newFixedThreadPool(8)) {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<?>> submitted = new ArrayList<>();
            for (int index = 0; index < 32; index++) {
                int value = index;
                submitted.add(callbacks.submit(() -> {
                    start.await();
                    runtime.advisory(id(value));
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> callback : submitted) {
                callback.get(1, TimeUnit.SECONDS);
            }
            assertEquals(2, runtime.metrics().pendingAdvisories());
            assertEquals(30, runtime.metrics().callbackDropped());
        }
    }

    @Test
    void nonCooperativeNotifierLeavesRetryableDrainingLifecycle() throws Exception {
        SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                Duration.ofMillis(1), Duration.ofMillis(1));
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        runtime.registerWakeListener(() -> {
            entered.countDown();
            boolean finished = false;
            while (!finished) {
                try {
                    finished = release.await(1, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                    // Deliberately non-cooperative notifier listener.
                }
            }
        });
        runtime.advisory(id(1));
        assertTrue(entered.await(1, TimeUnit.SECONDS));

        SigningExecutionException timeout = assertThrows(SigningExecutionException.class, runtime::close);
        assertEquals(SigningExecutionException.Classification.SHUTDOWN_TIMEOUT, timeout.classification());
        assertEquals(SigningExecutionRuntime.State.DRAINING, runtime.state());
        release.countDown();
        runtime.close();
        assertEquals(SigningExecutionRuntime.State.CLOSED, runtime.state());
    }

    @Test
    void nonCooperativeStepLeavesRetryableDrainingLifecycle() throws Exception {
        SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                Duration.ofMillis(1), Duration.ofMillis(1));
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        StepSubmission<String> active = scheduleAccepted(runtime, id(1), () -> {
            entered.countDown();
            boolean done = false;
            while (!done) {
                try {
                    done = release.await(1, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                    // Deliberately non-cooperative provider.
                }
            }
            return "released";
        });
        assertTrue(entered.await(1, TimeUnit.SECONDS));

        SigningExecutionException timeout = assertThrows(SigningExecutionException.class, runtime::close);
        assertEquals(SigningExecutionException.Classification.SHUTDOWN_TIMEOUT, timeout.classification());
        assertEquals(SigningExecutionRuntime.State.DRAINING, runtime.state());
        assertTrue(active.future().orElseThrow().isCancelled());
        assertThrows(CancellationException.class, () -> active.future().orElseThrow().get());
        assertEquals(1, runtime.metrics().schedulerReserved());
        release.countDown();
        awaitScheduled(runtime, 0);
        runtime.close();
        assertEquals(SigningExecutionRuntime.State.CLOSED, runtime.state());
    }

    @Test
    void forcedShutdownCancelsQueuedStepFuture() throws Exception {
        SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 1,
                Duration.ofMillis(1), Duration.ofSeconds(1));
        CountDownLatch activeEntered = new CountDownLatch(1);
        StepSubmission<String> active = runtime.scheduleStep(id(1), () -> {
            activeEntered.countDown();
            new CountDownLatch(1).await();
            return "unexpected";
        }, CancellationSignal.NONE);
        assertTrue(activeEntered.await(1, TimeUnit.SECONDS));
        StepSubmission<String> queued = runtime.scheduleStep(id(2), () -> "must-not-run", CancellationSignal.NONE);
        awaitReady(runtime, 1);

        runtime.close();

        assertTrue(active.future().orElseThrow().isDone());
        assertTrue(queued.future().orElseThrow().isCancelled());
        assertEquals(SigningExecutionRuntime.State.CLOSED, runtime.state());
    }

    @Test
    void signingConfigurationValidatesDerivedCapacityAndFiniteDurations() {
        ProviderConfig provider = new ProviderConfig("test", java.util.Map.of());
        assertThrows(IllegalArgumentException.class, () -> new PkiSessionConfiguration.SigningConfiguration(
                provider, provider, "SHA256withRSA", Duration.ofSeconds(1), Optional.empty(), Optional.empty(),
                Optional.empty(), Optional.empty(), 256, 65_535, Duration.ofSeconds(1), Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class, () -> new PkiSessionConfiguration.SigningConfiguration(
                provider, provider, "SHA256withRSA", Duration.ofSeconds(1), Optional.empty(), Optional.empty(),
                Optional.empty(), Optional.empty(), 1, 0, Duration.ZERO, Duration.ofSeconds(1)));
    }

    private static SigningExecutionRuntime runtime(int lanes, int queue) {
        return new SigningExecutionRuntime(lanes, queue, Duration.ofMillis(100), Duration.ofMillis(100));
    }

    private static PkiId id(int value) {
        return new PkiId("operation-" + value);
    }

    private static Callable<String> blocking(CountDownLatch entered, CountDownLatch release) {
        return () -> {
            entered.countDown();
            release.await();
            return "done";
        };
    }

    private static void assertCompletionCancellationRace(boolean fail) throws Exception {
        try (SigningExecutionRuntime runtime = runtime(1, 1)) {
            CountDownLatch firstEntered = new CountDownLatch(1);
            CountDownLatch releaseFirst = new CountDownLatch(1);
            CountDownLatch secondEntered = new CountDownLatch(1);
            CountDownLatch releaseSecond = new CountDownLatch(1);
            StepSubmission<String> first = scheduleAccepted(runtime, id(fail ? 11 : 1), () -> {
                firstEntered.countDown();
                boolean released = false;
                while (!released) {
                    try {
                        releaseFirst.await();
                        released = true;
                    } catch (InterruptedException ignored) {
                        // The race outcome must not change the callable's selected natural result.
                    }
                }
                if (fail) {
                    throw new IllegalStateException("racing failure");
                }
                return "racing success";
            });
            assertTrue(firstEntered.await(1, TimeUnit.SECONDS));
            StepSubmission<String> second = runtime.scheduleStep(id(fail ? 12 : 2), () -> {
                secondEntered.countDown();
                releaseSecond.await();
                return "replacement";
            }, CancellationSignal.NONE);
            assertEquals(StepDisposition.ACCEPTED, second.disposition());

            CountDownLatch startRace = new CountDownLatch(1);
            CompletableFuture<Boolean> cancellation = CompletableFuture.supplyAsync(() -> {
                try {
                    startRace.await();
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return false;
                }
                return first.future().orElseThrow().cancel(true);
            });
            startRace.countDown();
            releaseFirst.countDown();
            boolean cancellationWon = cancellation.get(1, TimeUnit.SECONDS);
            if (cancellationWon) {
                assertThrows(CancellationException.class, () -> first.future().orElseThrow().get());
            } else if (fail) {
                assertThrows(ExecutionException.class, () -> first.future().orElseThrow().get());
            } else {
                assertEquals("racing success", first.future().orElseThrow().get());
            }
            assertTrue(secondEntered.await(1, TimeUnit.SECONDS));
            assertEquals(1, runtime.metrics().schedulerReserved());
            assertEquals(1, runtime.metrics().running());
            assertEquals(0, runtime.metrics().ready());

            releaseSecond.countDown();
            assertEquals("replacement", second.future().orElseThrow().get(1, TimeUnit.SECONDS));
            assertSchedulerReleased(runtime);
        }
    }

    private static void assertSchedulerReleased(SigningExecutionRuntime runtime) {
        assertEquals(0, runtime.metrics().schedulerReserved());
        assertEquals(0, runtime.metrics().running());
        assertEquals(0, runtime.metrics().ready());
    }

    private static <T> StepSubmission<T> scheduleAccepted(SigningExecutionRuntime runtime, PkiId operationId,
            Callable<T> action) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
        StepSubmission<T> submission;
        do {
            submission = runtime.scheduleStep(operationId, action, CancellationSignal.NONE);
            if (submission.disposition() == StepDisposition.SATURATED) {
                LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1));
            }
        } while (submission.disposition() == StepDisposition.SATURATED && System.nanoTime() < deadline);
        assertEquals(StepDisposition.ACCEPTED, submission.disposition());
        return submission;
    }

    private static void awaitReady(SigningExecutionRuntime runtime, int expected) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
        while (runtime.metrics().ready() != expected && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        assertEquals(expected, runtime.metrics().ready());
    }

    private static void awaitScheduled(SigningExecutionRuntime runtime, int expected) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
        while (runtime.metrics().schedulerReserved() != expected && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        assertEquals(expected, runtime.metrics().schedulerReserved());
    }

    private static void awaitSuspended(SigningExecutionRuntime runtime, int expected) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
        while (runtime.suspendedTerminalCount() != expected && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        assertEquals(expected, runtime.suspendedTerminalCount());
    }

    private static ControlledTerminal prepared(AtomicInteger counter,
            ControlledTerminal completion) {
        counter.incrementAndGet();
        return completion;
    }

    private static void awaitCounter(AtomicInteger counter, int expected) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
        while (counter.get() != expected && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        assertEquals(expected, counter.get());
    }

    private static final class ControlledTerminal
            implements SigningExecutionRuntime.TerminalCompletion<String> {
        private final String accepted;
        private final List<String> order;
        private final AtomicBoolean allowCommit = new AtomicBoolean();
        private final AtomicBoolean closed = new AtomicBoolean();
        private final AtomicInteger commitAttempts = new AtomicInteger();

        private ControlledTerminal(String accepted) {
            this(accepted, new ArrayList<>());
        }

        private ControlledTerminal(String accepted, List<String> order) {
            this.accepted = accepted;
            this.order = order;
        }

        @Override
        public String commit() {
            commitAttempts.incrementAndGet();
            if (!allowCommit.get()) {
                MetadataStoreException limit = new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                        "injected metadata headroom exhaustion");
                throw new IllegalStateException("injected terminal persistence limit", limit);
            }
            order.add("terminal");
            return accepted;
        }

        @Override public String acceptedResult() { return accepted; }
        @Override public void close() { closed.set(true); }
    }

}
