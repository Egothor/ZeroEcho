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
package zeroecho.pki.performance;

import java.util.Objects;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import zeroecho.pki.api.PkiId;

/**
 * Benchmark-private fixed-capacity scheduler for short native workflow steps.
 *
 * <p>Each resident context is either in the due-time heap or exclusively owned
 * by one worker. A worker invokes exactly one step outside the scheduler lock
 * and then completes or requeues the context. The scheduler retains no thread,
 * future, lease, or other execution resource per waiting workflow.</p>
 *
 * <p>At most one idle worker performs a timed wait for the earliest due
 * context. Other idle workers wait without deadlines and are released as due
 * contexts are dequeued.</p>
 *
 * <p>Queue insertion and removal are {@code O(log W)}, earliest-due inspection
 * is {@code O(1)}, and total scheduling work is {@code O(T log W)} for
 * {@code T} state transitions, including bounded polling transitions.
 * Auxiliary context storage is {@code O(W)} and thread use is {@code O(E)},
 * where {@code W} is the context capacity and {@code E} is the fixed worker
 * count.</p>
 */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.AvoidInstantiatingObjectsInLoops",
        "PMD.CommentDefaultAccessModifier", "PMD.DoNotUseThreads" })
final class NativeWorkflowMultiplexer implements AutoCloseable {

    private final int capacity;
    private final StepHandler handler;
    private final WorkflowContext[] dueHeap;
    private final Thread[] workers;
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition workAvailable = lock.newCondition();
    private final Condition leaderChanged = lock.newCondition();
    private final Condition idle = lock.newCondition();
    private Lifecycle lifecycle = Lifecycle.RUNNING;
    private Throwable firstFailure;
    // Only this worker uses a timed wait; all other idle workers wait without a deadline.
    private Thread leader;
    private int heapSize;
    private int resident;
    private int peakResident;
    private long enqueueOrder;

    NativeWorkflowMultiplexer(int maximumContexts, int stepWorkers, StepHandler handler) {
        if (maximumContexts <= 0) {
            throw new IllegalArgumentException("maximumContexts must be positive");
        }
        if (stepWorkers <= 0 || stepWorkers > maximumContexts) {
            throw new IllegalArgumentException("stepWorkers must be in range [1, maximumContexts]");
        }
        this.capacity = maximumContexts;
        this.handler = Objects.requireNonNull(handler, "handler");
        this.dueHeap = new WorkflowContext[maximumContexts];
        this.workers = new Thread[stepWorkers];
        for (int index = 0; index < stepWorkers; index++) {
            workers[index] = new Thread(this::runWorker,
                    "signing-performance-multiplexer-" + (index + 1));
        }
        startWorkers();
    }

    /**
     * Attempts to admit one context without waiting for capacity.
     *
     * @return {@code true} when admitted, or {@code false} when all context
     *         slots are resident
     * @throws IllegalStateException      if the same context is already owned
     * @throws RejectedExecutionException if the multiplexer is stopping or a
     *                                    worker has failed
     */
    boolean trySubmit(WorkflowContext context, long dueNanos) {
        WorkflowContext exact = Objects.requireNonNull(context, "context");
        lock.lock();
        try {
            requireRunningLocked();
            if (exact.owner != Owner.NEW) {
                throw new IllegalStateException("workflow context was already submitted");
            }
            if (resident == capacity) {
                return false;
            }
            exact.dueNanos = dueNanos;
            exact.enqueueOrder = enqueueOrder++;
            exact.owner = Owner.QUEUED;
            resident++;
            peakResident = Math.max(peakResident, resident);
            enqueueLocked(exact);
            return true;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Waits until every admitted context reaches {@link WorkflowState#DONE}.
     *
     * @return {@code true} when idle, or {@code false} when the timeout elapsed
     * @throws InterruptedException if the waiting thread is interrupted
     * @throws IllegalStateException if a worker failed
     */
    boolean awaitIdle(long timeout, TimeUnit unit) throws InterruptedException {
        return awaitIdleOrRemaining(timeout, unit) == 0;
    }

    /**
     * Waits for idle and returns the exact resident count observed at timeout.
     *
     * @return zero when idle, otherwise the positive resident count at timeout
     * @throws InterruptedException if the waiting thread is interrupted
     * @throws IllegalStateException if a worker failed
     */
    int awaitIdleOrRemaining(long timeout, TimeUnit unit) throws InterruptedException {
        Objects.requireNonNull(unit, "unit");
        if (timeout < 0L) {
            throw new IllegalArgumentException("timeout must not be negative");
        }
        long remaining = unit.toNanos(timeout);
        lock.lockInterruptibly();
        try {
            while (resident != 0 && firstFailure == null) {
                if (remaining <= 0L) {
                    return resident;
                }
                remaining = idle.awaitNanos(remaining);
            }
            requireHealthyLocked();
            return resident;
        } finally {
            lock.unlock();
        }
    }

    /** Returns the exact peak resident count since construction or the last idle reset. */
    int peakResidentContexts() {
        lock.lock();
        try {
            return peakResident;
        } finally {
            lock.unlock();
        }
    }

    /** Resets peak accounting only at a phase boundary with no resident context. */
    void resetPeakResidentContextsWhenIdle() {
        lock.lock();
        try {
            requireHealthyLocked();
            if (resident != 0) {
                throw new IllegalStateException("peak resident contexts can be reset only while idle");
            }
            peakResident = 0;
        } finally {
            lock.unlock();
        }
    }

    @Override public void close() throws InterruptedException {
        if (isWorker(Thread.currentThread())) {
            throw new IllegalStateException("a multiplexer worker cannot close its owner");
        }
        beginClose();
        InterruptedException interrupted = joinWorkers();
        Throwable failure;
        lock.lock();
        try {
            lifecycle = Lifecycle.CLOSED;
            failure = firstFailure;
            idle.signalAll();
        } finally {
            lock.unlock();
        }
        if (failure != null) {
            IllegalStateException reported = workerFailure(failure);
            if (interrupted != null) {
                reported.addSuppressed(interrupted);
            }
            throw reported;
        }
        if (interrupted != null) {
            throw interrupted;
        }
    }

    private void startWorkers() {
        int started = 0;
        try {
            for (Thread worker : workers) {
                worker.start();
                started++;
            }
        } catch (RuntimeException | Error failure) {
            stopPartiallyStartedWorkers(started);
            throw failure;
        }
    }

    private void stopPartiallyStartedWorkers(int started) {
        lock.lock();
        try {
            lifecycle = Lifecycle.CLOSING;
            signalAllWorkersLocked();
        } finally {
            lock.unlock();
        }
        for (int index = 0; index < started; index++) {
            workers[index].interrupt();
        }
        boolean interrupted = false;
        for (int index = 0; index < started; index++) {
            while (workers[index].isAlive()) {
                try {
                    workers[index].join();
                } catch (InterruptedException problem) {
                    interrupted = true;
                }
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private void runWorker() {
        try {
            WorkflowContext context;
            while ((context = takeDueContext()) != null) {
                executeOneStep(context);
            }
        } catch (InterruptedException problem) {
            if (!stopping()) {
                recordWorkerFailure(null, problem);
            }
            Thread.currentThread().interrupt();
        } catch (Throwable problem) {
            recordWorkerFailure(null, problem);
        }
    }

    private WorkflowContext takeDueContext() throws InterruptedException {
        lock.lockInterruptibly();
        try {
            while (lifecycle == Lifecycle.RUNNING) {
                if (heapSize == 0) {
                    workAvailable.await();
                    continue;
                }
                long waitNanos = dueHeap[0].dueNanos - System.nanoTime();
                if (waitNanos <= 0L) {
                    WorkflowContext context = removeFirstLocked();
                    context.owner = Owner.WORKER;
                    return context;
                }
                if (leader != null) {
                    workAvailable.await();
                } else {
                    Thread current = Thread.currentThread();
                    leader = current;
                    try {
                        leaderChanged.awaitNanos(waitNanos);
                    } finally {
                        if (leader == current) {
                            leader = null;
                        }
                    }
                }
            }
            return null;
        } finally {
            if (lifecycle == Lifecycle.RUNNING && leader == null && heapSize != 0) {
                workAvailable.signal();
            }
            lock.unlock();
        }
    }

    private void executeOneStep(WorkflowContext context) {
        try {
            StepResult result = Objects.requireNonNull(handler.execute(context), "step result");
            finishStep(context, result);
        } catch (Throwable problem) {
            if (problem instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            recordWorkerFailure(context, problem);
        }
    }

    private void finishStep(WorkflowContext context, StepResult result) {
        lock.lock();
        try {
            requireWorkerOwnership(context);
            if (lifecycle != Lifecycle.RUNNING || result.complete()) {
                completeLocked(context);
                return;
            }
            context.state = result.nextState();
            context.dueNanos = result.dueNanos();
            context.enqueueOrder = enqueueOrder++;
            context.owner = Owner.QUEUED;
            enqueueLocked(context);
        } finally {
            lock.unlock();
        }
    }

    private void recordWorkerFailure(WorkflowContext context, Throwable problem) {
        lock.lock();
        try {
            if (context != null && context.owner == Owner.WORKER) {
                completeLocked(context);
            }
            boolean closingInterruption = problem instanceof InterruptedException
                    && lifecycle != Lifecycle.RUNNING;
            if (!closingInterruption && firstFailure == null) {
                firstFailure = problem;
            }
            if (lifecycle == Lifecycle.RUNNING) {
                lifecycle = Lifecycle.FAILED;
                cancelQueuedLocked();
            }
            signalAllWorkersLocked();
            idle.signalAll();
        } finally {
            lock.unlock();
        }
    }

    private boolean stopping() {
        lock.lock();
        try {
            return lifecycle != Lifecycle.RUNNING;
        } finally {
            lock.unlock();
        }
    }

    private void beginClose() {
        lock.lock();
        try {
            if (lifecycle != Lifecycle.CLOSED) {
                lifecycle = Lifecycle.CLOSING;
                cancelQueuedLocked();
                signalAllWorkersLocked();
                idle.signalAll();
            }
        } finally {
            lock.unlock();
        }
        for (Thread worker : workers) {
            worker.interrupt();
        }
    }

    private InterruptedException joinWorkers() {
        InterruptedException interrupted = null;
        for (Thread worker : workers) {
            while (worker.isAlive()) {
                try {
                    worker.join();
                } catch (InterruptedException problem) {
                    if (interrupted == null) {
                        interrupted = problem;
                    } else {
                        interrupted.addSuppressed(problem);
                    }
                }
            }
        }
        return interrupted;
    }

    private boolean isWorker(Thread candidate) {
        for (Thread worker : workers) {
            if (worker == candidate) {
                return true;
            }
        }
        return false;
    }

    private void requireRunningLocked() {
        if (firstFailure != null) {
            throw new RejectedExecutionException("native workflow multiplexer worker failed",
                    firstFailure);
        }
        if (lifecycle != Lifecycle.RUNNING) {
            throw new RejectedExecutionException("native workflow multiplexer is not running");
        }
    }

    private void requireHealthyLocked() {
        if (firstFailure != null) {
            throw workerFailure(firstFailure);
        }
    }

    private static IllegalStateException workerFailure(Throwable problem) {
        return new IllegalStateException("native workflow multiplexer worker failed", problem);
    }

    private void completeLocked(WorkflowContext context) {
        requireWorkerOwnership(context);
        context.complete();
        context.owner = Owner.DONE;
        resident--;
        if (resident == 0) {
            idle.signalAll();
        }
    }

    private static void requireWorkerOwnership(WorkflowContext context) {
        if (context.owner != Owner.WORKER) {
            throw new IllegalStateException("workflow context is not owned by a worker");
        }
    }

    private void cancelQueuedLocked() {
        for (int index = 0; index < heapSize; index++) {
            WorkflowContext context = dueHeap[index];
            dueHeap[index] = null;
            context.complete();
            context.owner = Owner.DONE;
            resident--;
        }
        heapSize = 0;
        if (resident == 0) {
            idle.signalAll();
        }
    }

    private void addLocked(WorkflowContext context) {
        int index = heapSize++;
        while (index > 0) {
            int parent = (index - 1) >>> 1;
            WorkflowContext parentContext = dueHeap[parent];
            if (compare(parentContext, context) <= 0) {
                break;
            }
            dueHeap[index] = parentContext;
            index = parent;
        }
        dueHeap[index] = context;
    }

    private void enqueueLocked(WorkflowContext context) {
        boolean earliest = heapSize == 0 || compare(context, dueHeap[0]) < 0;
        addLocked(context);
        if (earliest) {
            if (leader == null) {
                workAvailable.signal();
            } else {
                leaderChanged.signal();
            }
        }
    }

    private void signalAllWorkersLocked() {
        workAvailable.signalAll();
        leaderChanged.signalAll();
    }

    private WorkflowContext removeFirstLocked() {
        WorkflowContext first = dueHeap[0];
        int lastIndex = --heapSize;
        WorkflowContext last = dueHeap[lastIndex];
        dueHeap[lastIndex] = null;
        if (lastIndex != 0) {
            int index = 0;
            int half = heapSize >>> 1;
            while (index < half) {
                int child = (index << 1) + 1;
                int right = child + 1;
                if (right < heapSize && compare(dueHeap[right], dueHeap[child]) < 0) {
                    child = right;
                }
                if (compare(last, dueHeap[child]) <= 0) {
                    break;
                }
                dueHeap[index] = dueHeap[child];
                index = child;
            }
            dueHeap[index] = last;
        }
        return first;
    }

    private static int compare(WorkflowContext left, WorkflowContext right) {
        int dueComparison = Long.compare(left.dueNanos, right.dueNanos);
        if (dueComparison != 0) {
            return dueComparison;
        }
        return Long.compareUnsigned(left.enqueueOrder, right.enqueueOrder);
    }

    enum WorkflowState {
        SUBMIT,
        OBSERVE,
        CONSUME,
        RETIRE_SUCCESS,
        RETIRE_FAILURE,
        DONE
    }

    @FunctionalInterface
    interface StepHandler {
        StepResult execute(WorkflowContext context) throws Exception;
    }

    static final class WorkflowContext {
        private final long sequence;
        private final long scheduledNanos;
        private final boolean measured;
        private volatile WorkflowState state = WorkflowState.SUBMIT;
        private Owner owner = Owner.NEW;
        private PkiId operationId;
        private byte[] expectedSignature;
        private AdmissionState admissionState = AdmissionState.NONE;
        private boolean submissionInvoked;
        private boolean admittedWithinWindow;
        private boolean postAcceptFailureRecorded;
        private long terminalNanos;
        private long dueNanos;
        private long enqueueOrder;

        WorkflowContext(long sequence, long scheduledNanos, boolean measured) {
            this.sequence = sequence;
            this.scheduledNanos = scheduledNanos;
            this.measured = measured;
        }

        long sequence() {
            return sequence;
        }

        long scheduledNanos() {
            return scheduledNanos;
        }

        boolean measured() {
            return measured;
        }

        WorkflowState state() {
            return state;
        }

        void assignOperationId(PkiId value) {
            if (operationId != null) {
                throw new IllegalStateException("workflow operation identifier is already assigned");
            }
            operationId = Objects.requireNonNull(value, "operationId");
        }

        PkiId operationId() {
            if (operationId == null) {
                throw new IllegalStateException("workflow operation identifier is not assigned");
            }
            return operationId;
        }

        void markSubmissionInvoked() {
            operationId();
            if (submissionInvoked) {
                throw new IllegalStateException("workflow submission was already invoked");
            }
            submissionInvoked = true;
        }

        boolean submissionInvoked() {
            return submissionInvoked;
        }

        void recordAdmission(boolean withinWindow) {
            if (admissionState != AdmissionState.NONE) {
                throw new IllegalStateException("workflow admission is already recorded");
            }
            admissionState = AdmissionState.UNCONFIRMED;
            admittedWithinWindow = withinWindow;
        }

        boolean confirmAcceptance() {
            if (!submissionInvoked) {
                throw new IllegalStateException("workflow submission was not invoked");
            }
            if (admissionState == AdmissionState.ACCEPTED) {
                return false;
            }
            if (admissionState != AdmissionState.UNCONFIRMED) {
                throw new IllegalStateException("workflow admission cannot be accepted");
            }
            admissionState = AdmissionState.ACCEPTED;
            return true;
        }

        boolean acceptanceConfirmed() {
            return admissionState == AdmissionState.ACCEPTED;
        }

        boolean rollbackUnconfirmedAdmission() {
            if (admissionState == AdmissionState.NONE || admissionState == AdmissionState.ROLLED_BACK) {
                return false;
            }
            if (admissionState != AdmissionState.UNCONFIRMED) {
                throw new IllegalStateException("accepted workflow admission cannot be rolled back");
            }
            admissionState = AdmissionState.ROLLED_BACK;
            return true;
        }

        boolean admittedWithinWindow() {
            return admittedWithinWindow;
        }

        boolean recordPostAcceptFailure() {
            if (!submissionInvoked) {
                throw new IllegalStateException("workflow submission was not invoked");
            }
            if (postAcceptFailureRecorded) {
                return false;
            }
            postAcceptFailureRecorded = true;
            return true;
        }

        void takeOwnershipOfExpectedSignature(byte[] signature, long observedTerminalNanos) {
            Objects.requireNonNull(signature, "signature");
            if (signature.length == 0) {
                throw new IllegalArgumentException("signature must not be empty");
            }
            if (expectedSignature != null) {
                throw new IllegalStateException("workflow signature is already retained");
            }
            expectedSignature = signature;
            terminalNanos = observedTerminalNanos;
        }

        byte[] takeExpectedSignature() {
            if (expectedSignature == null) {
                throw new IllegalStateException("workflow signature is not retained");
            }
            byte[] result = expectedSignature;
            expectedSignature = null;
            return result;
        }

        long terminalNanos() {
            return terminalNanos;
        }

        private void complete() {
            state = WorkflowState.DONE;
            expectedSignature = null;
        }
    }

    record StepResult(boolean complete, WorkflowState nextState, long dueNanos) {
        StepResult {
            Objects.requireNonNull(nextState, "nextState");
            if (complete != (nextState == WorkflowState.DONE)) {
                throw new IllegalArgumentException("only a completed step may enter DONE");
            }
        }

        static StepResult requeue(WorkflowState nextState, long dueNanos) {
            return new StepResult(false, nextState, dueNanos);
        }

        static StepResult completed() {
            return new StepResult(true, WorkflowState.DONE, 0L);
        }
    }

    private enum Owner {
        NEW,
        QUEUED,
        WORKER,
        DONE
    }

    private enum AdmissionState {
        NONE,
        UNCONFIRMED,
        ACCEPTED,
        ROLLED_BACK
    }

    private enum Lifecycle {
        RUNNING,
        FAILED,
        CLOSING,
        CLOSED
    }
}
