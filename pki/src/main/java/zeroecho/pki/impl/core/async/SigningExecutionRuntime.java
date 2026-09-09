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

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.application.PkiSessionConfiguration;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataStoreException;

/**
 * Session-owned bounded scheduler for short signing-provider steps.
 *
 * <p>Durable workflows are store-owned and consume no runtime capacity while
 * pending. Runtime state is retained only for active and ready steps, so memory
 * is {@code O(lanes + queue + lanes * resultSize)} including bounded suspended
 * terminal results. At most one step per operation identifier may be active or
 * queued. The scheduler never caller-runs and a full ready queue is a transient,
 * typed result.</p>
 *
 * <p>For natural success or failure, {@link Future} completion is published only
 * after scheduler ownership and capacity are released and any FIFO ready-step
 * handoff is established. Future cancellation retains its standard semantics;
 * a cancelled running action may retain its lane and slot until the callable
 * physically exits.</p>
 *
 * <p>This type is thread-safe. Advisory callbacks use an independent bounded
 * coalescing queue and do not require a scheduled or otherwise live operation.</p>
 *
 * <p>Normal scheduling, handoff, and completion paths remain {@code O(1)}.
 * Owner cancellation and close inspect only the configured lanes and bounded
 * suspended terminal population; cascading slot release makes their total CPU
 * cost {@code O(lanes^2)} in the worst case, with lanes bounded to 256.</p>
 */
// The scheduler deliberately keeps its bounded state machine and worker ownership
// in one class; splitting collaborators solely at the metric boundary would hide
// the lock and lifecycle invariants without reducing runtime coupling.
@SuppressWarnings({ "PMD.CouplingBetweenObjects", "PMD.CyclomaticComplexity",
        "PMD.DoNotUseThreads", "PMD.NPathComplexity", "PMD.TooManyMethods" })
public final class SigningExecutionRuntime implements AutoCloseable {

    private static final long NO_CLOSE_ATTEMPT = -1L;
    private static final long NO_WAIT_NANOS = 0L;
    private static final long NO_READY_SEQUENCE = 0L;
    private static final String CANCELLATION_PARAMETER = "cancellation";

    private final Duration gracefulDrain;
    private final Duration forcedCancellation;
    private final int laneCount;
    private final int queueCapacity;
    private final int schedulerCapacity;
    private final Map<PkiId, StepTask<?>> scheduled = new LinkedHashMap<>();
    private final ReadyQueue ordinaryReady = new ReadyQueue();
    private final ReadyQueue terminalPreparationReady = new ReadyQueue();
    private final ReadyQueue terminalRetryReady = new ReadyQueue();
    private final RestoredRetryQueue restoredTerminalRetries = new RestoredRetryQueue();
    private final Map<PkiId, SuspendedTerminal<?>> suspendedTerminals = new LinkedHashMap<>();
    private final Set<InitialStepReservation> initialReservations = new HashSet<>();
    private final Deque<Worker> idleWorkers = new ArrayDeque<>();
    private final List<Worker> workers = new ArrayList<>();
    private final AtomicReference<State> state = new AtomicReference<>(State.OPEN);
    private final ThreadLocal<ExecutionContext> executionContext = new ThreadLocal<>();
    private final AtomicInteger highWaterScheduled = new AtomicInteger();
    private final AtomicLong rejected = new AtomicLong();
    private final AtomicLong compatibilityIds = new AtomicLong();
    private final ReentrantLock closeLock = new ReentrantLock();
    private final ReentrantLock admissionLock = new ReentrantLock();
    private final Condition closeCompleted = closeLock.newCondition();
    private final Condition workAvailable = admissionLock.newCondition();
    private final Condition schedulerChanged = admissionLock.newCondition();
    private final SigningAdvisoryRuntime advisories;
    private int freeSlots;
    private int running;
    private int terminalSlotsInUse;
    private int readyCount;
    private int terminalRetryHandoffs;
    private long readySequence;
    private int startedWorkers;
    private int liveWorkers;
    private boolean stopWorkers;
    private boolean closeInProgress;
    private long closeAttempt;
    private long completedCloseAttempt;
    private RuntimeException completedCloseFailure;

    /** Runtime lifecycle. */
    public enum State {
        /** Step scheduling and execution are available. */
        OPEN,
        /** New scheduling stopped while accepted steps drain. */
        QUIESCING,
        /** Accepted steps were cancelled and termination is retryable. */
        DRAINING,
        /** All worker resources and bounded state are closed. */
        CLOSED
    }

    /** Result of one non-blocking scheduling attempt. */
    public enum StepDisposition {
        /** The step was accepted into a lane or the ready queue. */
        ACCEPTED,
        /** The same operation already has one queued or active step. */
        BUSY,
        /** All lanes and configured ready slots are occupied. */
        SATURATED,
        /** Runtime lifecycle no longer accepts steps. */
        SHUTTING_DOWN
    }

    /**
     * Immutable non-blocking scheduling result.
     *
     * <p>For an accepted step's natural success or failure, {@link Future}
     * completion is published only after scheduler ownership and capacity are
     * released and any FIFO ready-step handoff is established. Future cancellation
     * retains its standard semantics; a cancelled running action may retain its lane
     * and slot until the callable physically exits.</p>
     *
     * @param <T> provider result type
     * @param disposition explicit outcome of the scheduling attempt
     * @param future accepted step future, present exactly for {@link StepDisposition#ACCEPTED}
     */
    public record StepSubmission<T>(StepDisposition disposition, Optional<Future<T>> future) {
        /** Validates disposition/future consistency. */
        public StepSubmission {
            Objects.requireNonNull(disposition, "disposition");
            Objects.requireNonNull(future, "future");
            if (disposition == StepDisposition.ACCEPTED != future.isPresent()) {
                throw new IllegalArgumentException("Only accepted steps carry a future");
            }
        }
    }

    /** Prepares one locally computed terminal result for bounded persistence. */
    /* default */
    @FunctionalInterface
    interface TerminalPreparation<T> {
        /** Returns the sole owner of the computed terminal result. */
        TerminalCompletion<T> prepare();
    }

    /** Runtime-owned terminal result that can be persisted without repeating cryptography. */
    /* default */ interface TerminalCompletion<T> extends AutoCloseable {
        /** Attempts one terminal metadata commit. */
        T commit();

        /** Returns the already accepted caller result while persistence is suspended. */
        T acceptedResult();

        @Override
        void close();
    }

    /** Opaque owner of one attached bus's bounded terminal work. */
    /* default */ final class TerminalOwner {
        private final SigningExecutionRuntime runtime = SigningExecutionRuntime.this;
        private boolean attached = true;
        private boolean recoveryRequired;
        private long restoredHeadroomEpoch;

        private TerminalOwner() {
            // Created only by this runtime while open.
        }
    }

    /**
     * Immutable bounded runtime counters.
     *
     * @param schedulerReserved held initial reservations plus assigned/running and ready steps
     * @param running currently executing provider steps
     * @param ready provider steps queued for a lane
     * @param pendingAdvisories unique queued provider advisories
     * @param highWaterSchedulerReserved largest observed scheduler-reserved population
     * @param schedulingRejected lifecycle- or capacity-rejected scheduling attempts, excluding busy operations
     * @param callbackCoalesced duplicate advisories already queued
     * @param callbackDropped null, lifecycle-rejected, capacity-rejected, or listener-failed advisories
     * @param callbackWake actual advisory-listener invocations
     * @param state current runtime lifecycle state
     */
    public record Metrics(int schedulerReserved, int running, int ready, int pendingAdvisories,
            int highWaterSchedulerReserved, long schedulingRejected, long callbackCoalesced,
            long callbackDropped, long callbackWake, State state) {
    }

    /**
     * Creates a runtime from the exact configured bounds and starts its workers.
     *
     * @param configuration validated signing scheduler, queue, and shutdown bounds
     */
    public SigningExecutionRuntime(PkiSessionConfiguration.SigningConfiguration configuration) {
        this(Objects.requireNonNull(configuration, "configuration").laneCount(),
                configuration.queueCapacity(), configuration.gracefulDrain(),
                configuration.forcedCancellation());
    }

    /**
     * Creates a runtime with finite validated bounds and starts its workers.
     *
     * @param laneCount number of concurrently executing provider lanes
     * @param queueCapacity maximum ready steps retained outside the lanes
     * @param gracefulDrain maximum natural-drain duration during close
     * @param forcedCancellation maximum drain duration after cancellation
     */
    public SigningExecutionRuntime(int laneCount, int queueCapacity, Duration gracefulDrain,
            Duration forcedCancellation) {
        PkiSessionConfiguration.SigningConfiguration bounds = SigningExecutionSupport.executionBounds(
                laneCount, queueCapacity,
                gracefulDrain, forcedCancellation);
        this.gracefulDrain = bounds.gracefulDrain();
        this.forcedCancellation = bounds.forcedCancellation();
        this.laneCount = bounds.laneCount();
        this.queueCapacity = bounds.queueCapacity();
        this.schedulerCapacity = bounds.admissionCapacity();
        this.freeSlots = schedulerCapacity;
        this.advisories = new SigningAdvisoryRuntime(schedulerCapacity, () -> state.get() == State.OPEN);
        startWorkers();
        advisories.start();
    }

    private void startWorkers() {
        admissionLock.lock();
        try {
            liveWorkers = laneCount;
            for (int index = 1; index <= laneCount; index++) {
                createAndStartWorker(index);
            }
            boolean interrupted = false;
            while (startedWorkers < laneCount) {
                try {
                    schedulerChanged.await();
                } catch (InterruptedException interruption) {
                    interrupted = true;
                }
            }
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        } finally {
            admissionLock.unlock();
        }
    }

    private void createAndStartWorker(int number) {
        Worker worker = new Worker(number);
        workers.add(worker);
        worker.thread.start();
    }

    /**
     * Attempts to schedule one short provider step without blocking.
     *
     * @param <T> provider-step result type
     * @param operationId durable operation identifier
     * @param action at-most-one provider call
     * @param cancellation cooperative cancellation signal
     * @return explicit accepted, busy, saturated, or shutting-down result
     */
    public <T> StepSubmission<T> scheduleStep(PkiId operationId, Callable<T> action,
            CancellationSignal cancellation) {
        PkiId exactId = Objects.requireNonNull(operationId, "operationId");
        Callable<T> exactAction = Objects.requireNonNull(action, "action");
        CancellationSignal exactCancellation = Objects.requireNonNull(cancellation, CANCELLATION_PARAMETER);
        StepTask<T> task = new StepTask<>(exactId, exactAction, exactCancellation);
        StepDisposition unavailable = admitOrdinary(task);
        return unavailable == null
                ? new StepSubmission<>(StepDisposition.ACCEPTED, Optional.of(task))
                : rejected(unavailable);
    }

    private StepDisposition admitOrdinary(StepTask<?> task) {
        admissionLock.lock();
        try {
            if (state.get() != State.OPEN) {
                rejected.incrementAndGet();
                return StepDisposition.SHUTTING_DOWN;
            }
            if (scheduled.containsKey(task.operationId)) {
                return StepDisposition.BUSY;
            }
            if (freeSlots == 0) {
                rejected.incrementAndGet();
                return StepDisposition.SATURATED;
            }
            freeSlots--;
            scheduled.put(task.operationId, task);
            assignOrEnqueue(task);
            updateHighWaterLocked();
            return null;
        } finally {
            admissionLock.unlock();
        }
    }

    private void updateHighWaterLocked() {
        highWaterScheduled.accumulateAndGet(schedulerCapacity - freeSlots, Math::max);
    }

    private void assignOrEnqueue(StepTask<?> task) {
        Worker worker = canAssign(task) ? idleWorkers.pollFirst() : null;
        if (worker != null) {
            handoffLocked(worker, task);
            return;
        }
        enqueueReadyLocked(task, false);
    }

    private void enqueueReadyLocked(StepTask<?> task, boolean first) {
        if (readyCount >= queueCapacity) {
            throw new IllegalStateException("Signing scheduler physical capacity invariant failed");
        }
        task.phase = TaskPhase.READY;
        if (task.readySequence == NO_READY_SEQUENCE) {
            task.readySequence = Math.incrementExact(readySequence);
        }
        ReadyQueue queue = readyQueue(task);
        if (first) {
            queue.addFirst(task);
        } else {
            queue.addLast(task);
        }
        readyCount++;
    }

    private ReadyQueue readyQueue(StepTask<?> task) {
        if (!task.terminalGuarded) {
            return ordinaryReady;
        }
        return task.terminalRetry ? terminalRetryReady : terminalPreparationReady;
    }

    private void handoffLocked(Worker worker, StepTask<?> task) {
        if (worker.mailbox != null) {
            throw new IllegalStateException("Signing scheduler lane mailbox is occupied");
        }
        worker.mailbox = task;
        task.worker = worker;
        task.phase = TaskPhase.ASSIGNED;
        if (task.terminalGuarded && !task.terminalSlotReserved) {
            terminalSlotsInUse++;
            task.terminalSlotReserved = true;
        }
        requireTerminalSlotBoundsLocked();
        workAvailable.signalAll();
    }

    private boolean canAssign(StepTask<?> task) {
        return !task.terminalGuarded || task.terminalSlotReserved || terminalSlotsInUse < laneCount;
    }

    private boolean terminalPreparationUnavailable(TerminalOwner owner) {
        admissionLock.lock();
        try {
            return !owner.attached || owner.recoveryRequired;
        } finally {
            admissionLock.unlock();
        }
    }

    private void requireTerminalSlotBoundsLocked() {
        if (terminalSlotsInUse < 0 || terminalSlotsInUse > laneCount) {
            throw new IllegalStateException("Signing terminal slot accounting is inconsistent");
        }
    }

    /**
     * Nonblockingly reserves one scheduler slot for a pre-staging initial step.
     *
     * @return one-shot reservation that must be consumed or closed
     */
    public InitialStepReservation reserveInitialStep() {
        admissionLock.lock();
        try {
            if (state.get() != State.OPEN) {
                rejected.incrementAndGet();
                throw SigningExecutionSupport.schedulingFailure(StepDisposition.SHUTTING_DOWN);
            }
            if (freeSlots == 0) {
                rejected.incrementAndGet();
                throw SigningExecutionSupport.schedulingFailure(StepDisposition.SATURATED);
            }
            freeSlots--;
            InitialStepReservation reservation = new InitialStepReservation();
            initialReservations.add(reservation);
            updateHighWaterLocked();
            return reservation;
        } finally {
            admissionLock.unlock();
        }
    }

    /**
     * Atomically consumes one initial reservation into one operation-keyed step.
     *
     * @param <T> provider result type
     * @param reservation held reservation owned by this runtime
     * @param operationId durable operation identifier
     * @param action at-most-once provider step
     * @param cancellation cooperative cancellation signal
     * @return explicit accepted, busy, or shutting-down result
     */
    public <T> StepSubmission<T> scheduleInitialStep(InitialStepReservation reservation,
            PkiId operationId, Callable<T> action, CancellationSignal cancellation) {
        InitialStepReservation exactReservation = Objects.requireNonNull(reservation, "reservation");
        PkiId exactId = Objects.requireNonNull(operationId, "operationId");
        Callable<T> exactAction = Objects.requireNonNull(action, "action");
        CancellationSignal exactCancellation = Objects.requireNonNull(cancellation, CANCELLATION_PARAMETER);
        StepTask<T> task = new StepTask<>(exactId, exactAction, exactCancellation);
        StepDisposition unavailable = consumeInitial(exactReservation, task);
        return unavailable == null
                ? new StepSubmission<>(StepDisposition.ACCEPTED, Optional.of(task))
                : rejected(unavailable);
    }

    /* default */ TerminalOwner attachTerminalOwner() {
        admissionLock.lock();
        try {
            if (state.get() != State.OPEN) {
                throw SigningExecutionSupport.schedulingFailure(StepDisposition.SHUTTING_DOWN);
            }
            return new TerminalOwner();
        } finally {
            admissionLock.unlock();
        }
    }

    /* default */ <T> StepSubmission<T> scheduleInitialTerminalStep(
            TerminalOwner owner, InitialStepReservation reservation, PkiId operationId,
            TerminalPreparation<T> preparation, CancellationSignal cancellation) {
        TerminalOwner exactOwner = requireAttachedOwner(owner);
        InitialStepReservation exactReservation = Objects.requireNonNull(reservation, "reservation");
        PkiId exactId = Objects.requireNonNull(operationId, "operationId");
        TerminalPreparation<T> exactPreparation = Objects.requireNonNull(preparation, "preparation");
        CancellationSignal exactCancellation = Objects.requireNonNull(cancellation, CANCELLATION_PARAMETER);
        StepTask<T> task = new StepTask<>(exactId,
                () -> executeTerminalPreparation(exactPreparation), exactCancellation, true, false,
                exactOwner);
        StepDisposition unavailable = consumeInitial(exactReservation, task);
        return unavailable == null
                ? new StepSubmission<>(StepDisposition.ACCEPTED, Optional.of(task))
                : rejected(unavailable);
    }

    /* default */ <T> T executeInitialTerminalStep(TerminalOwner owner,
            InitialStepReservation reservation, PkiId operationId,
            TerminalPreparation<T> preparation, Instant deadline,
            CancellationSignal cancellation) {
        Objects.requireNonNull(deadline, "deadline");
        CancellationSignal exactCancellation = Objects.requireNonNull(cancellation, CANCELLATION_PARAMETER);
        return SigningExecutionSupport.await(scheduleInitialTerminalStep(owner, reservation, operationId,
                preparation, exactCancellation), deadline, exactCancellation);
    }

    private TerminalOwner requireAttachedOwner(TerminalOwner owner) {
        TerminalOwner exact = requireTerminalOwner(owner);
        admissionLock.lock();
        try {
            if (state.get() != State.OPEN || !exact.attached || exact.recoveryRequired) {
                throw new IllegalStateException("Signing terminal owner is detached");
            }
            return exact;
        } finally {
            admissionLock.unlock();
        }
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals") // Capability ownership requires exact runtime identity.
    private TerminalOwner requireTerminalOwner(TerminalOwner owner) {
        TerminalOwner exact = Objects.requireNonNull(owner, "owner");
        if (exact.runtime != this) {
            throw new IllegalArgumentException("Signing terminal owner belongs to another runtime");
        }
        return exact;
    }

    /**
     * Consumes one initial reservation, executes its step, and awaits its deadline.
     *
     * @param <T> provider result type
     * @param reservation held reservation owned by this runtime
     * @param operationId durable operation identifier
     * @param action at-most-once provider step
     * @param deadline absolute completion deadline
     * @param cancellation cooperative cancellation signal
     * @return completed provider result
     */
    public <T> T executeInitialStep(InitialStepReservation reservation, PkiId operationId,
            Callable<T> action, Instant deadline, CancellationSignal cancellation) {
        Objects.requireNonNull(deadline, "deadline");
        CancellationSignal exactCancellation = Objects.requireNonNull(cancellation, CANCELLATION_PARAMETER);
        return SigningExecutionSupport.await(
                scheduleInitialStep(reservation, operationId, action, exactCancellation),
                deadline, exactCancellation);
    }

    private StepDisposition consumeInitial(InitialStepReservation reservation, StepTask<?> task) {
        admissionLock.lock();
        try {
            reservation.requireOwner(this);
            reservation.requireHeld();
            reservation.state.set(InitialStepReservation.CONSUMED);
            initialReservations.remove(reservation);
            if (state.get() != State.OPEN) {
                freeSlots++;
                rejected.incrementAndGet();
                return StepDisposition.SHUTTING_DOWN;
            }
            if (task.terminalOwner != null
                    && (!task.terminalOwner.attached || task.terminalOwner.recoveryRequired)) {
                freeSlots++;
                return StepDisposition.SHUTTING_DOWN;
            }
            if (scheduled.containsKey(task.operationId)) {
                freeSlots++;
                return StepDisposition.BUSY;
            }
            scheduled.put(task.operationId, task);
            assignOrEnqueue(task);
            return null;
        } finally {
            admissionLock.unlock();
        }
    }

    private static <T> StepSubmission<T> rejected(StepDisposition disposition) {
        return new StepSubmission<>(disposition, Optional.empty());
    }

    /**
     * Executes one provider step and waits within the supplied absolute deadline.
     *
     * @param <T> provider result type
     * @param operationId durable operation identifier
     * @param action at-most-once provider step
     * @param deadline absolute completion deadline
     * @param cancellation cooperative cancellation signal
     * @return completed provider result
     */
    public <T> T executeOperationStep(PkiId operationId, Callable<T> action, Instant deadline,
            CancellationSignal cancellation) {
        PkiId exactId = Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(deadline, "deadline");
        CancellationSignal exactCancellation = Objects.requireNonNull(cancellation, CANCELLATION_PARAMETER);
        ExecutionContext context = executionContext.get();
        if (context != null && context.operationId().equals(exactId)) {
            return SigningExecutionSupport.callNested(action);
        }
        StepSubmission<T> submission = scheduleStep(exactId, action, exactCancellation);
        return SigningExecutionSupport.await(submission, deadline, exactCancellation);
    }

    /**
     * Combines a provider signal with cancellation of the current runtime lane.
     *
     * @param fallback provider or caller cancellation outside a runtime lane
     * @return combined signal inside a lane, otherwise {@code fallback}
     */
    public CancellationSignal currentCancellation(CancellationSignal fallback) {
        CancellationSignal exact = Objects.requireNonNull(fallback, "fallback");
        ExecutionContext context = executionContext.get();
        return context == null ? exact : () -> exact.isCancelled() || context.cancellation().isCancelled();
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals") // Callback routing requires exact owner identity.
    /* default */ void headroomRestored(TerminalOwner owner, long epoch) {
        TerminalOwner exact = requireTerminalOwner(owner);
        admissionLock.lock();
        try {
            if (state.get() != State.OPEN || !exact.attached || exact.recoveryRequired
                    || epoch <= exact.restoredHeadroomEpoch) {
                return;
            }
            exact.restoredHeadroomEpoch = epoch;
            for (SuspendedTerminal<?> suspended : suspendedTerminals.values()) {
                StepTask<?> task = suspended.task;
                if (task.terminalOwner == exact && task.phase == TaskPhase.SUSPENDED
                        && suspended.attemptEpoch < epoch && !task.restorationEligible) {
                    task.restorationEligible = true;
                    restoredTerminalRetries.addLast(task);
                }
            }
            fillTerminalRetryReadyLocked();
            promoteIdleWorkers();
        } finally {
            admissionLock.unlock();
        }
    }

    /* default */ void headroomRecoveryRequired(TerminalOwner owner) {
        cancelTerminalOwner(requireTerminalOwner(owner), false);
    }

    /* default */ void detachTerminalOwner(TerminalOwner owner) {
        cancelTerminalOwner(requireTerminalOwner(owner), true);
    }

    /* default */ void awaitTerminalOwnerDrain(TerminalOwner owner,
            Duration gracefulDuration, Duration forcedDuration) {
        TerminalOwner exact = requireTerminalOwner(owner);
        Duration exactGraceful = Objects.requireNonNull(gracefulDuration, "gracefulDuration");
        Duration exactForced = Objects.requireNonNull(forcedDuration, "forcedDuration");
        cancelTerminalOwnerWork(exact);
        long gracefulDeadline = System.nanoTime() + exactGraceful.toNanos();
        if (awaitTerminalOwnerDrain(exact, remaining(gracefulDeadline))) {
            return;
        }
        cancelTerminalOwnerWork(exact);
        long forcedDeadline = System.nanoTime() + exactForced.toNanos();
        if (!awaitTerminalOwnerDrain(exact, remaining(forcedDeadline))) {
            throw failure(SigningExecutionException.Classification.SHUTDOWN_TIMEOUT,
                    "Signing bus terminal drain timed out: code=SIGNING_SHUTDOWN_TIMEOUT");
        }
    }

    private boolean awaitTerminalOwnerDrain(TerminalOwner owner, Duration duration) {
        return awaitSchedulerCondition(duration, () -> !hasPhysicalTerminalOwnerWorkLocked(owner));
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals") // Physical lane ownership uses opaque owner identity.
    private boolean hasPhysicalTerminalOwnerWorkLocked(TerminalOwner owner) {
        for (Worker worker : workers) {
            StepTask<?> task = worker.mailbox;
            if (task != null && task.terminalOwner == owner
                    && (task.phase == TaskPhase.ASSIGNED || task.phase == TaskPhase.RUNNING)) {
                return true;
            }
        }
        return false;
    }

    private void cancelTerminalOwner(TerminalOwner owner, boolean detach) {
        admissionLock.lock();
        try {
            if (state.get() == State.CLOSED || !owner.attached) {
                return;
            }
            if (!detach) {
                owner.recoveryRequired = true;
            }
            if (detach) {
                owner.attached = false;
            }
        } finally {
            admissionLock.unlock();
        }
        if (!detach) {
            cancelTerminalOwnerWork(owner);
        }
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals") // Cancellation is scoped by opaque owner identity.
    private void cancelTerminalOwnerWork(TerminalOwner owner) {
        List<StepTask<?>> tasks = new ArrayList<>(laneCount);
        admissionLock.lock();
        try {
            for (SuspendedTerminal<?> suspended : suspendedTerminals.values()) {
                StepTask<?> task = suspended.task;
                if (task.terminalOwner == owner
                        && (task.phase == TaskPhase.SUSPENDED || task.phase == TaskPhase.READY)) {
                    tasks.add(task);
                }
            }
            for (Worker worker : workers) {
                StepTask<?> task = worker.mailbox;
                if (task != null && task.terminalOwner == owner
                        && (task.phase == TaskPhase.ASSIGNED || task.phase == TaskPhase.RUNNING)) {
                    tasks.add(task);
                }
            }
        } finally {
            admissionLock.unlock();
        }
        for (StepTask<?> task : tasks) {
            task.cancel(true);
        }
    }

    /* default */ int terminalSlotCapacity() {
        return laneCount;
    }

    /* default */ int terminalSlotsInUse() {
        admissionLock.lock();
        try {
            return terminalSlotsInUse;
        } finally {
            admissionLock.unlock();
        }
    }

    /* default */ int suspendedTerminalCount() {
        admissionLock.lock();
        try {
            return suspendedTerminals.size();
        } finally {
            admissionLock.unlock();
        }
    }

    private <T> T executeTerminalPreparation(TerminalPreparation<T> preparation) {
        TerminalCompletion<T> completion = Objects.requireNonNull(preparation.prepare(), "terminal completion");
        return commitTerminal(completion);
    }

    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.UseTryWithResources" })
    private <T> T commitTerminal(TerminalCompletion<T> completion) {
        long attemptEpoch = currentTerminalOwnerEpoch();
        boolean retained = false;
        try {
            return completion.commit();
        } catch (RuntimeException failure) {
            if (!isLimitExceeded(failure)) {
                throw failure;
            }
            suspendCurrentTerminal(completion, attemptEpoch);
            retained = true;
            return completion.acceptedResult();
        } finally {
            if (!retained) {
                dispositionTerminal(completion);
                completion.close();
            }
        }
    }

    private long currentTerminalOwnerEpoch() {
        ExecutionContext context = executionContext.get();
        if (context == null) {
            throw completionInvariantFailure();
        }
        admissionLock.lock();
        try {
            StepTask<?> current = scheduled.get(context.operationId());
            if (current == null || current.terminalOwner == null || !current.terminalOwner.attached) {
                throw completionInvariantFailure();
            }
            return current.terminalOwner.restoredHeadroomEpoch;
        } finally {
            admissionLock.unlock();
        }
    }

    private static boolean isLimitExceeded(Throwable failure) {
        Throwable current = failure;
        while (current != null) {
            if (current instanceof MetadataStoreException metadataFailure) {
                return metadataFailure.category() == MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED;
            }
            current = current.getCause();
        }
        return false;
    }

    private <T> void suspendCurrentTerminal(TerminalCompletion<T> completion, long attemptEpoch) {
        ExecutionContext context = executionContext.get();
        if (context == null) {
            throw completionInvariantFailure();
        }
        admissionLock.lock();
        try {
            @SuppressWarnings("unchecked")
            StepTask<T> current = (StepTask<T>) scheduled.get(context.operationId());
            if (state.get() != State.OPEN) {
                throw failure(SigningExecutionException.Classification.SHUTTING_DOWN,
                        "Signing execution is shutting down: code=SIGNING_SHUTTING_DOWN");
            }
            if (current == null || current.phase != TaskPhase.RUNNING
                    || !current.terminalGuarded || !current.terminalSlotReserved) {
                throw completionInvariantFailure();
            }
            if (!current.terminalOwner.attached || current.terminalOwner.recoveryRequired) {
                throw failure(SigningExecutionException.Classification.SHUTTING_DOWN,
                        "Signing terminal owner requires recovery: code=SIGNING_SHUTTING_DOWN");
            }
            StepTask<T> retry = new StepTask<>(current.operationId,
                    () -> commitTerminal(completion), CancellationSignal.NONE, true, true,
                    current.terminalOwner);
            retry.terminalSlotReserved = true;
            retry.phase = TaskPhase.SUSPENDED;
            current.terminalOwnershipTransferred = true;
            current.terminalSlotReserved = false;
            scheduled.put(current.operationId, retry);
            SuspendedTerminal<T> suspended = new SuspendedTerminal<>(completion, retry, attemptEpoch);
            suspendedTerminals.put(current.operationId, suspended);
            long currentEpoch = current.terminalOwner.restoredHeadroomEpoch;
            if (currentEpoch > attemptEpoch) {
                retry.restorationEligible = true;
                restoredTerminalRetries.addLast(retry);
                fillTerminalRetryReadyLocked();
                promoteIdleWorkers();
            }
        } finally {
            admissionLock.unlock();
        }
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals") // Ownership transfer requires exact identities.
    private void dispositionTerminal(TerminalCompletion<?> completion) {
        ExecutionContext context = executionContext.get();
        if (context == null) {
            return;
        }
        admissionLock.lock();
        try {
            StepTask<?> current = scheduled.get(context.operationId());
            SuspendedTerminal<?> suspended = suspendedTerminals.get(context.operationId());
            if (current != null && current.terminalRetry && suspended != null
                    && suspended.completion == completion && suspended.task == current) {
                suspendedTerminals.remove(context.operationId());
                removeReadyLocked(current);
                removeRestoredRetryLocked(current);
            }
        } finally {
            admissionLock.unlock();
        }
    }

    /**
     * Temporary source-compatibility handle for the next bus-integration checkpoint.
     * It owns no permit and is not retained by this runtime.
     *
     * @return a new non-retained compatibility handle
     */
    public Reservation reserve() {
        if (state.get() != State.OPEN) {
            throw SigningExecutionSupport.schedulingFailure(StepDisposition.SHUTTING_DOWN);
        }
        return new Reservation(new PkiId("runtime-step:" + compatibilityIds.incrementAndGet()));
    }

    /**
     * Executes through the operation-keyed scheduler using a compatibility handle.
     *
     * @param <T> provider result type
     * @param reservation open compatibility handle
     * @param action at-most-once provider step
     * @param deadline absolute completion deadline
     * @param cancellation cooperative cancellation signal
     * @return completed provider result
     */
    public <T> T executeStep(Reservation reservation, Callable<T> action, Instant deadline,
            CancellationSignal cancellation) {
        Reservation exact = Objects.requireNonNull(reservation, "reservation");
        exact.requireOpen();
        return executeOperationStep(exact.operationId.get(), action, deadline, cancellation);
    }

    /**
     * Registers the single session reconciliation wake listener.
     *
     * @param listener callback invoked when bounded advisory work becomes available
     * @return registration whose close operation removes the listener
     */
    public AutoCloseable registerWakeListener(Runnable listener) {
        return advisories.registerWakeListener(listener);
    }

    /**
     * Records one best-effort bounded advisory in expected O(1).
     *
     * @param operationId durable operation identifier to reconcile
     */
    public void advisory(PkiId operationId) {
        advisories.advisory(operationId);
    }

    /** Captures at most {@code limit} FIFO advisories for one reconciliation pass. */
    /* default */ List<PkiId> snapshotAdvisories(int limit) {
        return advisories.snapshot(limit);
    }

    /** Finalizes one snapshot and moves retained identifiers behind pass-time arrivals. */
    /* default */ void completeAdvisoryPass(List<PkiId> snapshot, Set<PkiId> retained) {
        advisories.completePass(snapshot, retained);
    }

    /**
     * Returns and removes one bounded advisory for reconciliation.
     *
     * @return oldest advisory, or empty when none is queued
     */
    public Optional<PkiId> pollAdvisory() {
        return advisories.poll();
    }

    /**
     * Requeues an undispositioned advisory without exceeding scheduler capacity.
     *
     * @param operationId durable operation identifier to retain
     */
    public void retainAdvisory(PkiId operationId) {
        advisory(operationId);
    }

    /** Removes advisory residue after durable retirement; no workflow permit exists. */
    /* default */ void completeOperation(PkiId operationId) {
        advisories.completeOperation(operationId);
    }

    /**
     * Returns an immutable instantaneous metrics snapshot.
     *
     * @return scheduler and advisory counters with current lifecycle state
     */
    public Metrics metrics() {
        admissionLock.lock();
        try {
            SigningAdvisoryRuntime.AdvisoryMetrics advisoryMetrics = advisories.metrics();
            return new Metrics(schedulerCapacity - freeSlots, running, readyCount, advisoryMetrics.pending(),
                    highWaterScheduled.get(), rejected.get(), advisoryMetrics.coalesced(),
                    advisoryMetrics.dropped(), advisoryMetrics.wake(), state.get());
        } finally {
            admissionLock.unlock();
        }
    }

    /**
     * Returns the current retryable lifecycle state.
     *
     * @return current lifecycle state
     */
    public State state() {
        return state.get();
    }

    /** Returns the immutable total scheduler admission capacity. */
    /* default */ int schedulerCapacity() {
        return schedulerCapacity;
    }

    @Override
    public void close() {
        long attempt = beginCloseAttempt();
        if (attempt == NO_CLOSE_ATTEMPT) {
            return;
        }
        RuntimeException closeFailure = null;
        try {
            closeOwnedAttempt();
        } catch (SigningExecutionException failure) {
            closeFailure = failure;
        } finally {
            finishCloseAttempt(attempt, closeFailure);
        }
        if (closeFailure != null) {
            throw closeFailure;
        }
    }

    private long beginCloseAttempt() {
        closeLock.lock();
        try {
            if (state.get() == State.CLOSED) {
                return NO_CLOSE_ATTEMPT;
            }
            if (closeInProgress) {
                long observedAttempt = closeAttempt;
                boolean interrupted = false;
                while (completedCloseAttempt < observedAttempt) {
                    try {
                        closeCompleted.await();
                    } catch (InterruptedException interruption) {
                        interrupted = true;
                    }
                }
                if (interrupted) {
                    Thread.currentThread().interrupt();
                }
                if (completedCloseFailure != null) {
                    throw completedCloseFailure;
                }
                return NO_CLOSE_ATTEMPT;
            }
            closeInProgress = true;
            return ++closeAttempt;
        } finally {
            closeLock.unlock();
        }
    }

    private void finishCloseAttempt(long attempt, RuntimeException failure) {
        closeLock.lock();
        try {
            completedCloseFailure = failure;
            completedCloseAttempt = attempt;
            closeInProgress = false;
            closeCompleted.signalAll();
        } finally {
            closeLock.unlock();
        }
    }

    private void closeOwnedAttempt() {
        if (state.compareAndSet(State.OPEN, State.QUIESCING)) {
            cancelInitialReservations();
            cancelSuspendedTerminals();
            advisories.quiesce();
        }
        if (state.get() == State.QUIESCING) {
            long gracefulDeadline = System.nanoTime() + gracefulDrain.toNanos();
            boolean drained = awaitScheduledDrain(remaining(gracefulDeadline));
            if (drained) {
                stopWorkers();
            }
            boolean workersStopped = drained && awaitWorkerTermination(remaining(gracefulDeadline));
            boolean notifierStopped = advisories.awaitTermination(remaining(gracefulDeadline));
            if (workersStopped && notifierStopped) {
                finishClosed();
                return;
            }
            state.set(State.DRAINING);
        }
        if (state.get() == State.DRAINING) {
            cancelOutstandingAndStopWorkers();
            advisories.forceStop();
        }
        long forcedDeadline = System.nanoTime() + forcedCancellation.toNanos();
        boolean workersStopped = awaitWorkerTermination(remaining(forcedDeadline));
        boolean notifierStopped = advisories.awaitTermination(remaining(forcedDeadline));
        if (!workersStopped || !notifierStopped) {
            throw failure(SigningExecutionException.Classification.SHUTDOWN_TIMEOUT,
                    "Signing shutdown timed out: code=SIGNING_SHUTDOWN_TIMEOUT");
        }
        finishClosed();
    }

    private static Duration remaining(long deadline) {
        return Duration.ofNanos(Math.max(NO_WAIT_NANOS, deadline - System.nanoTime()));
    }

    @SuppressWarnings("PMD.CloseResource") // Runtime-owned reservations release themselves under this scheduler lock.
    private void cancelInitialReservations() {
        admissionLock.lock();
        try {
            for (InitialStepReservation reservation : List.copyOf(initialReservations)) {
                reservation.cancelLocked();
            }
            schedulerChanged.signalAll();
        } finally {
            admissionLock.unlock();
        }
    }

    private void cancelSuspendedTerminals() {
        List<StepTask<?>> tasks;
        admissionLock.lock();
        try {
            tasks = new ArrayList<>(suspendedTerminals.size());
            for (SuspendedTerminal<?> suspended : suspendedTerminals.values()) {
                tasks.add(suspended.task);
            }
        } finally {
            admissionLock.unlock();
        }
        for (StepTask<?> task : tasks) {
            task.cancel(true);
        }
    }

    private boolean awaitScheduledDrain(Duration duration) {
        return awaitSchedulerCondition(duration, scheduled::isEmpty);
    }

    private boolean awaitWorkerTermination(Duration duration) {
        return awaitSchedulerCondition(duration, () -> liveWorkers == 0);
    }

    private boolean awaitSchedulerCondition(Duration duration, BooleanSupplier condition) {
        long remaining = duration.toNanos();
        admissionLock.lock();
        try {
            while (!condition.getAsBoolean()) {
                if (remaining <= NO_WAIT_NANOS) {
                    return false;
                }
                try {
                    remaining = schedulerChanged.awaitNanos(remaining);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new SigningExecutionException(SigningExecutionException.Classification.SHUTDOWN_TIMEOUT,
                            "Signing shutdown interrupted: code=SIGNING_SHUTDOWN_TIMEOUT", interrupted);
                }
            }
            return true;
        } finally {
            admissionLock.unlock();
        }
    }

    private void stopWorkers() {
        admissionLock.lock();
        try {
            stopWorkers = true;
            workAvailable.signalAll();
            schedulerChanged.signalAll();
        } finally {
            admissionLock.unlock();
        }
    }

    private void cancelOutstandingAndStopWorkers() {
        List<StepTask<?>> tasks;
        admissionLock.lock();
        try {
            stopWorkers = true;
            tasks = List.copyOf(scheduled.values());
            workAvailable.signalAll();
        } finally {
            admissionLock.unlock();
        }
        for (StepTask<?> task : tasks) {
            task.cancel(true);
        }
        admissionLock.lock();
        try {
            workAvailable.signalAll();
            schedulerChanged.signalAll();
        } finally {
            admissionLock.unlock();
        }
    }

    private void workerExited(Worker worker) {
        admissionLock.lock();
        try {
            idleWorkers.remove(worker);
            liveWorkers--;
            schedulerChanged.signalAll();
        } finally {
            admissionLock.unlock();
        }
    }

    @SuppressWarnings("PMD.CloseResource") // Completion ownership is closed after releasing the scheduler lock.
    private void finishTask(Worker worker, StepTask<?> task) {
        TerminalCompletion<?> completion = null;
        admissionLock.lock();
        try {
            if (task.phase == TaskPhase.RUNNING) {
                completion = terminalCompletion(task);
                completeRunningTask(worker, task);
            }
        } finally {
            admissionLock.unlock();
        }
        if (completion != null) {
            completion.close();
        }
    }

    @SuppressWarnings({ "PMD.CompareObjectsWithEquals", "PMD.AvoidCatchingGenericException" })
    // Exact identity and stable publication boundary are intentional.
    private RuntimeException releaseRunningBeforePublication(StepTask<?> task) {
        admissionLock.lock();
        try {
            Worker worker = task.worker;
            if (task.phase != TaskPhase.RUNNING
                    || worker == null
                    || worker.thread != Thread.currentThread()
                    || worker.mailbox != task
                    || !task.terminalOwnershipTransferred && scheduled.get(task.operationId) != task
                    || task.terminalOwnershipTransferred
                            && (scheduled.get(task.operationId) == task
                                    || !suspendedTerminals.containsKey(task.operationId))
                    || task.readyQueue != null
                    || running <= 0
                    || running > laneCount
                    || freeSlots < 0
                    || freeSlots >= schedulerCapacity
                    || running > scheduled.size()
                    || scheduled.size() + initialReservations.size() != schedulerCapacity - freeSlots) {
                return completionInvariantFailure();
            }
            if (task.terminalOwnershipTransferred) {
                running--;
                task.phase = TaskPhase.FINISHED;
                task.worker = null;
                worker.mailbox = null;
                if (!stopWorkers) {
                    assignNextOrIdle(worker);
                }
                schedulerChanged.signalAll();
                return null;
            }
            completeRunningTask(worker, task);
            return null;
        } catch (RuntimeException failure) {
            IllegalStateException invariant = completionInvariantFailure();
            invariant.addSuppressed(failure);
            return invariant;
        } finally {
            admissionLock.unlock();
        }
    }

    private static IllegalStateException completionInvariantFailure() {
        return new IllegalStateException("Signing scheduler completion invariant failed");
    }

    private void completeRunningTask(Worker worker, StepTask<?> task) {
        running--;
        scheduled.remove(task.operationId, task);
        removeReadyLocked(task);
        removeRestoredRetryLocked(task);
        suspendedTerminals.remove(task.operationId);
        task.phase = TaskPhase.FINISHED;
        task.worker = null;
        worker.mailbox = null;
        releaseTerminalSlot(task);
        freeSlots++;
        if (!stopWorkers) {
            assignNextOrIdle(worker);
        }
        schedulerChanged.signalAll();
    }

    private void assignNextOrIdle(Worker worker) {
        StepTask<?> next = pollReady();
        if (next == null) {
            idleWorkers.addLast(worker);
            return;
        }
        handoffLocked(worker, next);
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals") // Displacement preserves exact intrusive task ownership.
    private StepTask<?> pollReady() {
        if (queueCapacity == 0 && !restoredTerminalRetries.isEmpty()) {
            StepTask<?> direct = restoredTerminalRetries.removeFirst();
            direct.restorationEligible = false;
            terminalRetryHandoffs++;
            return direct;
        }
        StepTask<?> displaced = null;
        if (terminalRetryReady.isEmpty() && !restoredTerminalRetries.isEmpty()
                && readyCount == queueCapacity) {
            displaced = removeOldestFreshLocked();
            if (displaced != null) {
                fillOneTerminalRetryReadyLocked();
            }
        }
        StepTask<?> retry = terminalRetryReady.peekFirst();
        StepTask<?> fresh = oldestEligibleFreshLocked(displaced);
        boolean chooseRetry = retry != null
                && (fresh == null || terminalRetryHandoffs < laneCount);
        StepTask<?> selected;
        if (chooseRetry) {
            selected = terminalRetryReady.removeFirst();
            readyCount--;
            terminalRetryHandoffs++;
        } else if (fresh != null) {
            selected = fresh;
            if (selected != displaced) {
                removeReadyLocked(selected);
            }
            terminalRetryHandoffs = 0;
        } else {
            selected = null;
        }
        if (displaced != null && selected != displaced) {
            enqueueReadyLocked(displaced, true);
        }
        fillOneTerminalRetryReadyLocked();
        return selected;
    }

    private StepTask<?> oldestEligibleFreshLocked(StepTask<?> displaced) {
        StepTask<?> ordinary = ordinaryReady.peekFirst();
        StepTask<?> preparation = terminalPreparationReady.peekFirst();
        if (preparation != null && !canAssign(preparation)) {
            preparation = null;
        }
        StepTask<?> queued = older(ordinary, preparation);
        return displaced != null && canAssign(displaced) ? older(displaced, queued) : queued;
    }

    private StepTask<?> removeOldestFreshLocked() {
        StepTask<?> selected = older(ordinaryReady.peekFirst(), terminalPreparationReady.peekFirst());
        if (selected != null) {
            removeReadyLocked(selected);
        }
        return selected;
    }

    private static StepTask<?> older(StepTask<?> first, StepTask<?> second) {
        if (first == null) {
            return second;
        }
        if (second == null) {
            return first;
        }
        return first.readySequence < second.readySequence ? first : second;
    }

    private void fillTerminalRetryReadyLocked() {
        while (readyCount < queueCapacity && !restoredTerminalRetries.isEmpty()) {
            fillOneTerminalRetryReadyLocked();
        }
    }

    private void fillOneTerminalRetryReadyLocked() {
        if (readyCount >= queueCapacity || restoredTerminalRetries.isEmpty()) {
            return;
        }
        StepTask<?> task = restoredTerminalRetries.removeFirst();
        task.restorationEligible = false;
        enqueueReadyLocked(task, false);
    }

    private void removeReadyLocked(StepTask<?> task) {
        if (task.readyQueue != null) {
            task.readyQueue.remove(task);
            readyCount--;
        }
    }

    private void removeRestoredRetryLocked(StepTask<?> task) {
        if (task.restorationEligible) {
            restoredTerminalRetries.remove(task);
            task.restorationEligible = false;
        }
    }

    private void promoteIdleWorkers() {
        while (!idleWorkers.isEmpty()) {
            StepTask<?> next = pollReady();
            if (next == null) {
                return;
            }
            Worker worker = idleWorkers.removeFirst();
            handoffLocked(worker, next);
        }
    }

    private void releaseTerminalSlot(StepTask<?> task) {
        if (task.terminalSlotReserved) {
            task.terminalSlotReserved = false;
            terminalSlotsInUse--;
            requireTerminalSlotBoundsLocked();
            promoteIdleWorkers();
        }
    }

    private void finishClosed() {
        advisories.finishClosed();
        admissionLock.lock();
        try {
            restoredTerminalRetries.clear();
            state.set(State.CLOSED);
        } finally {
            admissionLock.unlock();
        }
    }

    private static SigningExecutionException failure(SigningExecutionException.Classification classification,
            String message) {
        return new SigningExecutionException(classification, message);
    }

    /** One-shot scheduler-capacity claim for exactly one initial provider step. */
    public final class InitialStepReservation implements AutoCloseable {
        private static final int HELD = 0;
        private static final int CONSUMED = 1;
        private static final int CLOSED = 2;

        private final SigningExecutionRuntime owner = SigningExecutionRuntime.this;
        private final AtomicInteger state = new AtomicInteger(HELD);

        private InitialStepReservation() {
            // Created only after its scheduler permit is acquired.
        }

        private void requireHeld() {
            int current = state.get();
            if (current != HELD) {
                throw new IllegalStateException(current == CONSUMED
                        ? "Initial step reservation is already consumed"
                        : "Initial step reservation is closed");
            }
        }

        @SuppressWarnings("PMD.CompareObjectsWithEquals") // Capability ownership requires exact runtime identity.
        private void requireOwner(SigningExecutionRuntime expectedOwner) {
            if (owner != expectedOwner) {
                throw new IllegalArgumentException("Initial step reservation belongs to another runtime");
            }
        }

        private void cancelLocked() {
            if (state.compareAndSet(HELD, CLOSED)) {
                initialReservations.remove(this);
                freeSlots++;
                schedulerChanged.signalAll();
            }
        }

        @Override public void close() {
            admissionLock.lock();
            try {
                cancelLocked();
            } finally {
                admissionLock.unlock();
            }
        }
    }

    /** Temporary non-retained compatibility handle. */
    public final class Reservation implements AutoCloseable {
        private final AtomicReference<PkiId> operationId;
        private final AtomicBoolean closed = new AtomicBoolean();

        private Reservation(PkiId initialOperationId) {
            this.operationId = new AtomicReference<>(initialOperationId);
        }

        /**
         * Associates this handle with a durable operation identifier.
         *
         * @param identifier durable operation identifier
         */
        public void bind(PkiId identifier) {
            requireOpen();
            operationId.set(Objects.requireNonNull(identifier, "identifier"));
        }

        /** Compatibility no-op: workflows have no runtime lifetime ownership. */
        public void transferToRuntime() {
            requireOpen();
        }

        private void requireOpen() {
            if (closed.get()) {
                throw new IllegalStateException("Signing step handle is closed");
            }
        }

        @Override
        public void close() {
            closed.set(true);
        }
    }

    /** Scheduler-owned phase of one bounded provider step. */
    private enum TaskPhase {
        NEW,
        READY,
        SUSPENDED,
        ASSIGNED,
        RUNNING,
        FINISHED
    }

    /** One bounded queued or active operation step. */
    private final class StepTask<T> extends FutureTask<T> {
        private final PkiId operationId;
        private final boolean terminalGuarded;
        private final boolean terminalRetry;
        private final TerminalOwner terminalOwner;
        private TaskPhase phase = TaskPhase.NEW;
        private Worker worker;
        private ReadyQueue readyQueue;
        private StepTask<?> readyPrevious;
        private StepTask<?> readyNext;
        private StepTask<?> restoredPrevious;
        private StepTask<?> restoredNext;
        private long readySequence;
        private boolean terminalSlotReserved;
        private boolean terminalOwnershipTransferred;
        private boolean restorationEligible;

        private StepTask(PkiId operationId, Callable<T> action, CancellationSignal cancellation) {
            this(operationId, action, cancellation, false, false, null);
        }

        private StepTask(PkiId operationId, Callable<T> action, CancellationSignal cancellation,
                boolean terminalGuarded, boolean terminalRetry, TerminalOwner terminalOwner) {
            super(() -> {
                CancellationSignal laneCancellation = () -> cancellation.isCancelled()
                        || Thread.currentThread().isInterrupted();
                executionContext.set(new ExecutionContext(operationId, laneCancellation));
                try {
                    if (laneCancellation.isCancelled()) {
                        throw failure(SigningExecutionException.Classification.SHUTTING_DOWN,
                                "Signing execution cancelled: code=SIGNING_SHUTTING_DOWN");
                    }
                    if (terminalGuarded && !terminalRetry
                            && terminalPreparationUnavailable(terminalOwner)) {
                        throw failure(SigningExecutionException.Classification.SHUTTING_DOWN,
                                "Signing terminal owner requires recovery: code=SIGNING_SHUTTING_DOWN");
                    }
                    return action.call();
                } finally {
                    executionContext.remove();
                }
            });
            this.operationId = operationId;
            this.terminalGuarded = terminalGuarded;
            this.terminalRetry = terminalRetry;
            this.terminalOwner = terminalOwner;
        }

        @Override
        protected void set(T value) {
            RuntimeException invariant = releaseRunningBeforePublication(this);
            if (invariant == null) {
                super.set(value);
            } else {
                super.setException(invariant);
            }
        }

        @Override
        protected void setException(Throwable failure) {
            RuntimeException invariant = releaseRunningBeforePublication(this);
            if (invariant == null) {
                super.setException(failure);
            } else {
                if (failure != null) {
                    invariant.addSuppressed(failure);
                }
                super.setException(invariant);
            }
        }

        @Override
        protected void done() {
            if (isCancelled()) {
                releaseCancelledBeforeRunning(this);
            }
        }
    }

    /** Intrusive insertion-ordered queue with constant-time task removal. */
    private final class ReadyQueue {
        private StepTask<?> first;
        private StepTask<?> last;

        private boolean isEmpty() {
            return first == null;
        }

        private StepTask<?> peekFirst() {
            return first;
        }

        private void addFirst(StepTask<?> task) {
            requireDetached(task);
            task.readyQueue = this;
            task.readyNext = first;
            if (first == null) {
                last = task;
            } else {
                first.readyPrevious = task;
            }
            first = task;
        }

        private void addLast(StepTask<?> task) {
            requireDetached(task);
            task.readyQueue = this;
            task.readyPrevious = last;
            if (last == null) {
                first = task;
            } else {
                last.readyNext = task;
            }
            last = task;
        }

        private StepTask<?> removeFirst() {
            StepTask<?> selected = first;
            if (selected == null) {
                return null;
            }
            remove(selected);
            return selected;
        }

        @SuppressWarnings("PMD.CompareObjectsWithEquals") // Intrusive ownership requires exact queue identity.
        private void remove(StepTask<?> task) {
            if (task.readyQueue != this) {
                throw new IllegalStateException("Signing ready queue ownership is inconsistent");
            }
            StepTask<?> previous = task.readyPrevious;
            StepTask<?> next = task.readyNext;
            if (previous == null) {
                first = next;
            } else {
                previous.readyNext = next;
            }
            if (next == null) {
                last = previous;
            } else {
                next.readyPrevious = previous;
            }
            task.readyQueue = null;
            task.readyPrevious = null;
            task.readyNext = null;
        }

        private void requireDetached(StepTask<?> task) {
            if (task.readyQueue != null || task.readyPrevious != null || task.readyNext != null) {
                throw new IllegalStateException("Signing task is already ready");
            }
        }
    }

    /** Intrusive restoration queue with constant-time task removal. */
    private final class RestoredRetryQueue {
        private StepTask<?> first;
        private StepTask<?> last;

        private boolean isEmpty() {
            return first == null;
        }

        @SuppressWarnings("PMD.CompareObjectsWithEquals") // Intrusive ownership uses exact task identity.
        private void addLast(StepTask<?> task) {
            if (!task.restorationEligible || task.restoredPrevious != null || task.restoredNext != null
                    || last == task) {
                throw new IllegalStateException("Signing restored retry ownership is inconsistent");
            }
            task.restoredPrevious = last;
            if (last == null) {
                first = task;
            } else {
                last.restoredNext = task;
            }
            last = task;
        }

        private StepTask<?> removeFirst() {
            StepTask<?> selected = first;
            if (selected != null) {
                remove(selected);
            }
            return selected;
        }

        @SuppressWarnings("PMD.CompareObjectsWithEquals") // Intrusive ownership uses exact task identity.
        private void remove(StepTask<?> task) {
            StepTask<?> previous = task.restoredPrevious;
            StepTask<?> next = task.restoredNext;
            if (previous == null) {
                if (first != task) {
                    throw new IllegalStateException("Signing restored retry ownership is inconsistent");
                }
                first = next;
            } else {
                previous.restoredNext = next;
            }
            if (next == null) {
                if (last != task) {
                    throw new IllegalStateException("Signing restored retry ownership is inconsistent");
                }
                last = previous;
            } else {
                next.restoredPrevious = previous;
            }
            task.restoredPrevious = null;
            task.restoredNext = null;
        }

        private void clear() {
            StepTask<?> detached;
            while ((detached = removeFirst()) != null) {
                detached.restorationEligible = false;
            }
        }
    }

    @SuppressWarnings("PMD.CloseResource") // Completion ownership is closed after releasing the scheduler lock.
    private void releaseCancelledBeforeRunning(StepTask<?> task) {
        TerminalCompletion<?> completion = null;
        admissionLock.lock();
        try {
            if (!task.isCancelled()) {
                return;
            }
            if (task.phase == TaskPhase.READY) {
                removeReadyLocked(task);
                completion = terminalCompletion(task);
                releaseUnstarted(task);
            } else if (task.phase == TaskPhase.SUSPENDED) {
                completion = terminalCompletion(task);
                releaseUnstarted(task);
            } else if (task.phase == TaskPhase.ASSIGNED) {
                Worker worker = task.worker;
                if (worker != null && worker.owns(task)) {
                    worker.mailbox = null;
                    completion = terminalCompletion(task);
                    releaseUnstarted(task);
                    promoteOrIdle(worker);
                }
            }
        } finally {
            admissionLock.unlock();
        }
        if (completion != null) {
            completion.close();
        }
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals") // Ownership lookup requires exact scheduled task identity.
    private TerminalCompletion<?> terminalCompletion(StepTask<?> task) {
        SuspendedTerminal<?> suspended = suspendedTerminals.get(task.operationId);
        return suspended != null && suspended.task == task ? suspended.completion : null;
    }

    private void releaseUnstarted(StepTask<?> task) {
        scheduled.remove(task.operationId, task);
        removeReadyLocked(task);
        removeRestoredRetryLocked(task);
        suspendedTerminals.remove(task.operationId);
        task.phase = TaskPhase.FINISHED;
        task.worker = null;
        releaseTerminalSlot(task);
        freeSlots++;
        schedulerChanged.signalAll();
    }

    private void promoteOrIdle(Worker worker) {
        StepTask<?> next = stopWorkers ? null : pollReady();
        if (next == null) {
            if (!stopWorkers) {
                idleWorkers.addLast(worker);
            }
        } else {
            handoffLocked(worker, next);
        }
        schedulerChanged.signalAll();
    }

    /** One fixed provider lane with a single scheduler-owned mailbox. */
    private final class Worker implements Runnable {
        private final Thread thread;
        private StepTask<?> mailbox;

        private Worker(int number) {
            thread = new Thread(this, "zeroecho-signing-lane-" + number);
            thread.setDaemon(true);
        }

        @SuppressWarnings("PMD.CompareObjectsWithEquals") // Mailbox removal requires exact scheduled task identity.
        private boolean owns(StepTask<?> task) {
            return mailbox == task;
        }

        @Override
        public void run() {
            try {
                workerLoop();
            } finally {
                workerExited(this);
            }
        }

        private void workerLoop() {
            admissionLock.lock();
            try {
                idleWorkers.addLast(this);
                startedWorkers++;
                schedulerChanged.signalAll();
            } finally {
                admissionLock.unlock();
            }
            while (true) {
                StepTask<?> task = awaitTask();
                if (task == null) {
                    return;
                }
                task.run();
                Thread.interrupted(); // A cancelled provider cannot contaminate the next lane assignment.
                if (task.isCancelled()) {
                    finishTask(this, task);
                }
            }
        }

        private StepTask<?> awaitTask() {
            admissionLock.lock();
            try {
                while (mailbox == null && !stopWorkers) {
                    try {
                        workAvailable.await();
                    } catch (InterruptedException interrupted) {
                        if (stopWorkers) {
                            Thread.currentThread().interrupt();
                            return null;
                        }
                    }
                }
                if (mailbox == null) {
                    return null;
                }
                StepTask<?> task = mailbox;
                task.phase = TaskPhase.RUNNING;
                running++;
                schedulerChanged.signalAll();
                return task;
            } finally {
                admissionLock.unlock();
            }
        }
    }

    private record ExecutionContext(PkiId operationId, CancellationSignal cancellation) { }

    /** One bounded result retained only while its terminal metadata commit lacks headroom. */
    private final class SuspendedTerminal<T> {
        private final TerminalCompletion<T> completion;
        private final StepTask<T> task;
        private final long attemptEpoch;

        private SuspendedTerminal(TerminalCompletion<T> completion, StepTask<T> task,
                long attemptEpoch) {
            this.completion = completion;
            this.task = task;
            this.attemptEpoch = attemptEpoch;
        }
    }
}
