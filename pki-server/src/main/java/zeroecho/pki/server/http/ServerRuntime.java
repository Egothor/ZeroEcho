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
package zeroecho.pki.server.http;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.server.PkiServerConfiguration;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Centralized owner of all bounded server-created threads, queues and permits.
 */
public final class ServerRuntime implements AutoCloseable {
    /**
     * Name prefix for administrative HTTPS dispatch threads.
     */
    /* default */ static final String TRANSPORT_PREFIX = "zeroecho-pki-https-";
    /**
     * Name prefix for bounded administrative operation workers.
     */
    /* default */ static final String OPERATION_PREFIX = "zeroecho-pki-operation-";
    /**
     * Name prefix for public repository HTTPS dispatch threads.
     */
    /* default */ static final String PUBLIC_TRANSPORT_PREFIX = "zeroecho-pki-public-https-";
    /**
     * Name prefix for bounded public repository streaming workers.
     */
    /* default */ static final String PUBLIC_STREAM_PREFIX = "zeroecho-pki-public-stream-";
    /**
     * Name prefix for ACME HTTPS dispatch threads.
     */
    /* default */ static final String ACME_TRANSPORT_PREFIX = "zeroecho-pki-acme-https-";
    /**
     * Name prefix for bounded ACME protocol workers.
     */
    /* default */ static final String ACME_PROTOCOL_PREFIX = "zeroecho-pki-acme-protocol-";
    /**
     * Name prefix for separately admitted ACME challenge-validation workers.
     */
    /* default */ static final String ACME_VALIDATION_PREFIX = "zeroecho-pki-acme-validation-";
    /**
     * Name prefix for OCSP HTTPS dispatch threads.
     */
    /* default */ static final String OCSP_TRANSPORT_PREFIX = "zeroecho-pki-ocsp-https-";
    /**
     * Name prefix for bounded OCSP response workers.
     */
    /* default */ static final String OCSP_OPERATION_PREFIX = "zeroecho-pki-ocsp-response-";
    /**
     * Name prefix for SCEP HTTPS dispatch threads.
     */
    /* default */ static final String SCEP_TRANSPORT_PREFIX = "zeroecho-pki-scep-https-";
    /**
     * Name prefix for bounded SCEP operation workers.
     */
    /* default */ static final String SCEP_OPERATION_PREFIX = "zeroecho-pki-scep-operation-";
    /**
     * Name prefix for CMP HTTPS dispatch threads.
     */
    /* default */ static final String CMP_TRANSPORT_PREFIX = "zeroecho-pki-cmp-https-";
    /**
     * Name prefix for bounded CMP operation workers.
     */
    /* default */ static final String CMP_OPERATION_PREFIX = "zeroecho-pki-cmp-operation-";
    /**
     * Name assigned to the server lifecycle shutdown-hook thread.
     */
    /* default */ static final String SHUTDOWN_NAME = "zeroecho-pki-shutdown";
    private static final ThreadLocal<WorkerType> WORKER_MARKER = new ThreadLocal<>();

    // Virtual threads handle transport dispatch — no sizing needed; each request gets its own VT. The standalone
    // runtime owns this bounded executor and its shutdown lifecycle.
    @SuppressWarnings("PMD.DoNotUseThreads")
    private final ExecutorService transport;
    // The standalone runtime owns this bounded executor and its shutdown lifecycle.
    @SuppressWarnings("PMD.DoNotUseThreads")
    private final ThreadPoolExecutor operations;
    private final Semaphore admitted;
    private final Set<CancellationToken> cancellations = ConcurrentHashMap.newKeySet();
    private final Set<Future<?>> futures = ConcurrentHashMap.newKeySet();
    private final PkiServerConfiguration.Execution configuration;
    private final AtomicBoolean accepting = new AtomicBoolean(true);

    /**
     * Creates the administrative transport and bounded operation execution owners.
     *
     * @param configuration admission, worker, queue, deadline and shutdown limits
     * @throws NullPointerException if the configuration is null
     */
    /* default */ ServerRuntime(PkiServerConfiguration.Execution configuration) {
        this(configuration, Lane.ADMIN);
    }

    /**
     * Creates administrative or public-repository execution owners.
     *
     * @param configuration admission, worker, queue, deadline and shutdown limits
     * @param publicLane whether to use public repository thread names
     * @throws NullPointerException if the configuration is null
     */
    /* default */ ServerRuntime(PkiServerConfiguration.Execution configuration, boolean publicLane) {
        this(configuration, publicLane ? Lane.PUBLIC : Lane.ADMIN);
    }

    /**
     * Starts execution owners with thread names identifying their protocol lane.
     *
     * @param configuration admission, worker, queue, deadline and shutdown limits
     * @param lane protocol lane used for transport and operation thread naming
     * @throws NullPointerException if the configuration is null
     */
    // The standalone transport owns bounded task executors and preserves cancellation/thread
    // lifetime.
    /* default */ @SuppressWarnings({"PMD.DoNotUseThreads"})
    ServerRuntime(PkiServerConfiguration.Execution configuration, Lane lane) {
        this.configuration = configuration;
        String transportPrefix =
                lane == Lane.PUBLIC
                        ? PUBLIC_TRANSPORT_PREFIX
                        : lane == Lane.ACME
                                ? ACME_TRANSPORT_PREFIX
                                : lane == Lane.OCSP
                                        ? OCSP_TRANSPORT_PREFIX
                                        : lane == Lane.EST
                                                ? "zeroecho-pki-est-https-"
                                                : lane == Lane.SCEP
                                                        ? SCEP_TRANSPORT_PREFIX
                                                        : lane == Lane.CMP
                                                                ? CMP_TRANSPORT_PREFIX
                                                                : TRANSPORT_PREFIX;
        // Virtual threads: each incoming HTTP request dispatches on its own VT; no pool sizing
        // needed.
        transport =
                Executors.newThreadPerTaskExecutor(
                        new NamedThreadFactory(transportPrefix, WorkerType.TRANSPORT, true));
        operations =
                pool(
                        configuration.operationWorkers(),
                        configuration.operationQueueCapacity(),
                        new NamedThreadFactory(
                                lane == Lane.PUBLIC
                                        ? PUBLIC_STREAM_PREFIX
                                        : lane == Lane.ACME
                                                ? ACME_PROTOCOL_PREFIX
                                                : lane == Lane.OCSP
                                                        ? OCSP_OPERATION_PREFIX
                                                        : lane == Lane.EST
                                                                ? "zeroecho-pki-est-operation-"
                                                                : lane == Lane.SCEP
                                                                        ? SCEP_OPERATION_PREFIX
                                                                        : lane == Lane.CMP
                                                                                ? CMP_OPERATION_PREFIX
                                                                                : OPERATION_PREFIX,
                                WorkerType.OPERATION));
        admitted = new Semaphore(configuration.maximumAdmittedRequests(), true);
    }

    /**
     * Returns the transport executor borrowed by the HTTP listener.
     *
     * @return runtime-owned executor; callers must not shut it down independently
     */
    // The standalone transport owns bounded task executors and preserves cancellation/thread
    // lifetime.
    /* default */ @SuppressWarnings({"PMD.DoNotUseThreads"})
    ExecutorService transportExecutor() {
        return transport;
    }

    /**
     * Tries to reserve one request-admission permit without waiting.
     * A successful caller must invoke {@link #releaseAdmission()} exactly once.
     * Shutdown may start after this check, so later submission can still fail.
     *
     * @return whether a permit was acquired while acceptance was observed enabled
     */
    public boolean tryAdmit() {
        return accepting.get() && admitted.tryAcquire();
    }

    /**
     * Returns a permit previously acquired by {@link #tryAdmit()}.
     * Calling without a matching acquisition increases capacity incorrectly;
     * the caller must enforce pairing even when request processing fails.
     */
    public void releaseAdmission() {
        admitted.release();
    }

    /**
     * Executes one operation through the owned bounded queue and waits for its result.
     * The caller owns admission pairing. A timeout or interruption requests cooperative
     * cancellation and interrupts the worker; execution tracking remains until the
     * worker actually exits. Already committed side effects are not rolled back.
     *
     * <p>The operation must release its resources itself and must not transfer a live
     * resource through the return value: a result produced after cancellation can be
     * discarded. The caller must restore or propagate interruption.</p>
     *
     * @param <T> independently owned, resource-free result type
     * @param deadline positive wait bound no greater than the configured maximum
     * @param operation operation receiving the lifecycle-owned cancellation signal
     * @return completed operation result
     * @throws IllegalArgumentException if the deadline is outside the configured bound
     * @throws RejectedExecutionException if the runtime is closing or its queue is full
     * @throws TimeoutException if the deadline expires
     * @throws InterruptedException if the waiting caller is interrupted
     * @throws ExecutionException if operation execution fails
     * @throws NullPointerException if any of {@code deadline}, {@code operation} is null
     */
    public <T> T execute(Duration deadline, CancellableOperation<T> operation)
            throws TimeoutException, InterruptedException, ExecutionException {
        Objects.requireNonNull(deadline, "deadline");
        Objects.requireNonNull(operation, "operation");
        if (deadline.isNegative() || deadline.isZero() || deadline.compareTo(configuration.maximumDeadline()) > 0) {
            throw new IllegalArgumentException("Operation deadline exceeds the configured bound");
        }
        Submitted<T> submitted = submit(operation::call);
        try {
            return submitted.future().get(deadline.toNanos(), TimeUnit.NANOSECONDS);
        } catch (TimeoutException | InterruptedException failure) {
            submitted.cancellation().cancel();
            submitted.future().cancel(true);
            throw failure;
        } finally { submitted.finish(); }
    }

    /**
     * Operation executed on this runtime's bounded worker lane.
     * @param <T> independently owned, resource-free result type
     */
    @FunctionalInterface
    public interface CancellableOperation<T> {
        /**
         * Computes a result, releasing every acquired resource before returning.
         * @param cancellation cooperative cancellation and interruption signal
         * @return resource-free result; a late result may be discarded
         * @throws Exception if execution fails
         */
        // Preserve the existing Callable-like callback contract for arbitrary checked task
        // failures.
        @SuppressWarnings("PMD.SignatureDeclareThrowsException")
        T call(CancellationSignal cancellation) throws Exception;
    }

    /**
     * Queues an operation with tracked future and cooperative cancellation ownership.
     *
     * @param <T> operation result type
     * @param task operation invoked with its runtime-owned cancellation token
     * @return tracked submission; callers invoke its finish hook after observing the result
     * @throws RejectedExecutionException if the runtime is quiescing or its bounded queue is full
     */
    // The standalone transport owns bounded task executors and preserves cancellation/thread
    // lifetime.
    /* default */ @SuppressWarnings({"PMD.DoNotUseThreads"})
    <T> Submitted<T> submit(CancellableCallable<T> task) {
        if (!accepting.get()) {
            throw new RejectedExecutionException("Server is not accepting operations");
        }
        CancellationToken cancellation = new CancellationToken();
        TrackedFutureTask<T> future =
                new TrackedFutureTask<>(
                        operations,
                        () -> {
                            cancellation.throwIfCancelled();
                            return task.call(cancellation);
                        },
                        futures,
                        () -> cancellations.remove(cancellation));
        cancellations.add(cancellation);
        futures.add(future);
        try {
            operations.execute(future);
        } catch (RejectedExecutionException failure) {
            future.cancel(false);
            throw failure;
        }
        return new Submitted<>(future, cancellation, future::cleanupIfComplete);
    }

    /**
     * Stops accepting new operation submissions and request-admission attempts.
     *
     * <p>Already admitted requests and running operations are not cancelled.</p>
     */
    /* default */ void quiesce() {
        accepting.set(false);
    }

    /**
     * Returns a snapshot of the runtime execution state.
     *
     * @return whether new work is currently accepted
     */
    /* default */ boolean accepting() {
        return accepting.get();
    }

    /**
     * Returns a snapshot of the runtime execution state.
     *
     * @return current number of queued operation tasks
     */
    // The standalone transport owns bounded task executors and preserves cancellation/thread
    // lifetime.
    /* default */ @SuppressWarnings({"PMD.DoNotUseThreads"})
    int operationQueueSize() {
        return operations.getQueue().size();
    }

    /**
     * Returns a snapshot of the runtime execution state.
     *
     * @return approximate number of operation workers executing tasks
     */
    // The standalone transport owns bounded task executors and preserves cancellation/thread
    // lifetime.
    /* default */ @SuppressWarnings({"PMD.DoNotUseThreads"})
    int activeOperations() {
        return operations.getActiveCount();
    }

    /**
     * Returns a snapshot of the runtime execution state.
     *
     * @return number of operation futures still tracked for lifecycle cleanup
     */
    /* default */ int trackedOperationFutures() {
        return futures.size();
    }

    /**
     * Returns a snapshot of the runtime execution state.
     *
     * @return number of cancellation tokens still tracked for executing or queued work
     */
    /* default */ int trackedCancellationTokens() {
        return cancellations.size();
    }

    /**
     * Returns a snapshot of the runtime execution state.
     *
     * @return whether the current thread carries a server-runtime worker marker
     */
    /* default */ static boolean isWorkerThread() {
        return WORKER_MARKER.get() != null;
    }

    /**
     * Creates an unstarted platform thread for server shutdown handling.
     *
     * @param task shutdown action executed when the returned thread starts
     * @return unstarted thread with the stable server shutdown name
     */
    // The standalone transport owns bounded task executors and preserves cancellation/thread
    // lifetime.
    /* default */ @SuppressWarnings({"PMD.DoNotUseThreads"})
    static Thread shutdownHook(Runnable task) {
        return new Thread(task, SHUTDOWN_NAME);
    }

    /**
     * Stops new admission and shuts down the owned operation and transport executors.
     *
     * <p>External callers wait for configured graceful bounds before requesting
     * cooperative cancellation, interrupting work and waiting for forced-shutdown bounds.
     * An owned worker avoids waiting for its own execution lane; it may therefore report
     * incomplete shutdown while its task is still running. Cancellation does not roll back
     * already committed side effects. Interrupted waiters retain their interrupt status.</p>
     *
     * <p>If termination is incomplete, the runtime stays quiescent and an external owner
     * can retry closure after outstanding work exits.</p>
     *
     * @throws IllegalStateException if either executor remains live after the applicable shutdown attempts
     */
    // The standalone transport owns bounded task executors and preserves cancellation/thread
    // lifetime.
    @SuppressWarnings({"PMD.DoNotUseThreads"})
    @Override
    public void close() {
        quiesce();
        transport.shutdown();
        operations.shutdown();
        boolean transportWorker = WORKER_MARKER.get() == WorkerType.TRANSPORT;
        boolean operationWorker = WORKER_MARKER.get() == WorkerType.OPERATION;
        closeOperations(operationWorker);
        closeTransport(transportWorker);
        if (!operations.isTerminated() || !transport.isTerminated()) {
            throw shutdownTimeout();
        }
    }

    /**
     * Protocol identity used to name and isolate runtime execution owners.
     */
    /* default */ enum Lane {
        /**
         * Administrative API dispatch and operation execution.
         */
        ADMIN,
        /**
         * Public repository dispatch and streaming.
         */
        PUBLIC,
        /**
         * ACME protocol dispatch and operation execution.
         */
        ACME,
        /**
         * OCSP responder dispatch and response execution.
         */
        OCSP,
        /**
         * EST enrollment dispatch and operation execution.
         */
        EST,
        /**
         * SCEP enrollment dispatch and operation execution.
         */
        SCEP,
        /**
         * CMP enrollment dispatch and operation execution.
         */
        CMP
    }

    /**
     * One separately admitted bounded challenge-validation execution lane.
     */
    /* default */ static final class ChallengeRuntime implements AutoCloseable {
        // The standalone runtime owns this bounded executor and its shutdown lifecycle.
        @SuppressWarnings("PMD.DoNotUseThreads")
        private final ThreadPoolExecutor executor;
        private final Semaphore admitted;
        private final Duration graceful;
        private final Duration forced;
        private final AtomicBoolean accepting = new AtomicBoolean(true);
        private final Set<Future<?>> futures = ConcurrentHashMap.newKeySet();

        /**
         * Starts a bounded worker lane dedicated to ACME challenge validation.
         *
         * @param configuration admission, queue, worker and shutdown bounds
         * @throws NullPointerException if configuration is null
         */
        /* default */ ChallengeRuntime(PkiServerConfiguration.Execution configuration) {
            executor = pool(configuration.operationWorkers(), configuration.operationQueueCapacity(),
                    new NamedThreadFactory(ACME_VALIDATION_PREFIX, WorkerType.VALIDATION));
            admitted = new Semaphore(configuration.maximumAdmittedRequests(), true);
            graceful = configuration.gracefulShutdown(); forced = configuration.forcedShutdown();
        }

        /**
         * Tries to reserve a validation-admission permit without waiting.
         *
         * @return whether a permit was acquired; a successful caller must invoke {@link #release()}
         */
        /* default */ boolean tryAdmit() { return accepting.get() && admitted.tryAcquire(); }
        /**
         * Returns exactly one validation permit previously acquired by {@link #tryAdmit()}.
         */
        /* default */ void release() { admitted.release(); }

        /**
         * Queues tracked challenge-validation work on the bounded validation lane.
         *
         * @param <T> validation result type
         * @param work validation operation
         * @return future supporting result observation and interruption-based cancellation
         * @throws RejectedExecutionException if the lane is quiescing or its queue is full
         */
        // The standalone transport owns bounded task executors and preserves cancellation/thread
        // lifetime. This
        // standalone validation lane owns submission to its bounded managed executor.
        /* default */
        @SuppressWarnings("PMD.DoNotUseThreads")
        <T> Future<T> submit(Callable<T> work) {
            if (!accepting.get()) {
                throw new RejectedExecutionException("ACME validation is not accepting work");
            }
            TrackedFutureTask<T> future =
                    new TrackedFutureTask<>(executor, work, futures, () -> {});
            futures.add(future);
            try {
                executor.execute(future);
                return future;
            } catch (RejectedExecutionException failure) {
                future.cancel(false);
                throw failure;
            }
        }

        /**
         * Returns the number of validation futures retained for lifecycle cleanup.
         *
         * @return current tracking count
         */
        /* default */ int trackedFutures() { return futures.size(); }
        /**
         * Stops accepting new validation work and admission attempts.
         */
        /* default */ void quiesce() { accepting.set(false); }

        /**
         * Stops validation admission and shuts down the bounded challenge-validation executor.
         *
         * <p>An external caller waits for graceful termination, then cancels tracked futures,
         * interrupts queued/running work and waits for the configured forced bound. A validation
         * worker avoids waiting for itself. Interrupted callers retain their interrupt status.</p>
         *
         * @throws IllegalStateException if validation execution remains live after the applicable shutdown
         *         attempts
         */
        // This managed validation lane owns executor cancellation and shutdown. The standalone
        // transport owns
        // bounded task executors and preserves cancellation/thread lifetime.
        @SuppressWarnings({"PMD.DoNotUseThreads"})
        @Override
        public void close() {
            quiesce();
            executor.shutdown();
            boolean worker = WORKER_MARKER.get() == WorkerType.VALIDATION;
            if (!worker) {
                await(executor, graceful);
            }
            if (!executor.isTerminated()) {
                futures.forEach(value -> value.cancel(true));
                cancelNeverStarted(executor.shutdownNow());
                if (!worker) {
                    await(executor, forced);
                }
            }
            if (!executor.isTerminated()) {
                throw shutdownTimeout();
            }
        }
    }

    // The standalone transport owns bounded task executors and preserves cancellation/thread
    // lifetime.
    @SuppressWarnings({"PMD.DoNotUseThreads"})
    private static ThreadPoolExecutor pool(int workers, int queueCapacity, ThreadFactory factory) {
        ThreadPoolExecutor result =
                new ThreadPoolExecutor(
                        workers,
                        workers,
                        0L,
                        TimeUnit.MILLISECONDS,
                        new ArrayBlockingQueue<>(queueCapacity),
                        factory,
                        new ThreadPoolExecutor.AbortPolicy());
        result.prestartAllCoreThreads();
        return result;
    }

    private static void cancelNeverStarted(List<Runnable> work) {
        for (Runnable task : work) {
            if (task instanceof Future<?> future) {
                future.cancel(false);
            }
        }
    }

    // The standalone transport owns bounded task executors and preserves cancellation/thread
    // lifetime.
    @SuppressWarnings({"PMD.DoNotUseThreads"})
    private static void await(ThreadPoolExecutor executor, Duration duration) {
        awaitService(executor, duration);
    }

    // The standalone transport owns bounded task executors and preserves cancellation/thread
    // lifetime.
    @SuppressWarnings({"PMD.DoNotUseThreads"})
    private static void awaitService(ExecutorService executor, Duration duration) {
        try {
            executor.awaitTermination(duration.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static IllegalStateException shutdownTimeout() {
        return new IllegalStateException(
                "Server execution shutdown timed out: code=SERVER_EXECUTION_SHUTDOWN_TIMEOUT");
    }

    /**
     * Tracked operation handle with cooperative cancellation and completion cleanup.
     *
     * @param <T> operation result type
     * @param future queued or executing operation result
     * @param cancellation runtime-owned cancellation token
     * @param completed idempotent tracking-retirement callback
     */
    /* default */ record Submitted<T>(Future<T> future, CancellationToken cancellation, Runnable completed) {
        /**
         * Requires all submission ownership components.
         *
         * @param future operation result handle; must not be null
         * @param cancellation cooperative cancellation token; must not be null
         * @param completed tracking-retirement callback; must not be null
         * @throws NullPointerException if any ownership component is null
         */
        /* default */ Submitted {
            Objects.requireNonNull(future, "Submitted operation fields must not be null");
            Objects.requireNonNull(cancellation, "Submitted operation fields must not be null");
            Objects.requireNonNull(completed, "Submitted operation fields must not be null");
        }

        /**
         * Runs tracking retirement once the future has completed execution.
         *
         * <p>The supplied callback leaves a cancelled but still executing operation tracked.</p>
         */
        /* default */ void finish() { completed.run(); }
    }

    /**
     * Future whose exact task and optional companion state retire at execution completion.
     */
    private static final class TrackedFutureTask<T> extends FutureTask<T> {
        // The standalone runtime owns this bounded executor and its shutdown lifecycle.
        @SuppressWarnings("PMD.DoNotUseThreads")
        private final ThreadPoolExecutor executor;
        private final Set<Future<?>> futures;
        private final Runnable additionalCleanup;
        private final AtomicBoolean started = new AtomicBoolean();
        private final AtomicBoolean executionComplete = new AtomicBoolean();
        private final AtomicBoolean cleaned = new AtomicBoolean();

        // The standalone transport owns bounded task executors and preserves cancellation/thread
        // lifetime.
        @SuppressWarnings({"PMD.DoNotUseThreads"})
        private TrackedFutureTask(
                ThreadPoolExecutor executor,
                Callable<T> callable,
                Set<Future<?>> futures,
                Runnable additionalCleanup) {
            super(callable);
            this.executor = executor;
            this.futures = futures;
            this.additionalCleanup = additionalCleanup;
        }

        /**
         * {@inheritDoc}
         */
        @Override public void run() {
            started.set(true);
            try {
                super.run();
            } finally {
                executionComplete.set(true);
                cleanup();
            }
        }

        /**
         * {@inheritDoc}
         */
        // The standalone transport owns bounded task executors and preserves cancellation/thread
        // lifetime.
        @SuppressWarnings({"PMD.DoNotUseThreads"})
        @Override
        protected void done() {
            if (!started.get()) {
                executor.remove(this);
            }
            cleanupIfComplete();
        }

        private void cleanupIfComplete() {
            if (!started.get() || executionComplete.get() || isDone() && !isCancelled()) {
                cleanup();
            }
        }

        private void cleanup() {
            if (cleaned.compareAndSet(false, true)) {
                futures.remove(this);
                additionalCleanup.run();
            }
        }
    }

    /**
     * Internal worker operation receiving the mutable runtime cancellation token.
     *
     * @param <T> independently owned operation result type
     */
    /* default */ @FunctionalInterface
    interface CancellableCallable<T> {
        /**
         * Executes the operation while observing lifecycle cancellation.
         *
         * @param cancellation runtime-owned token; must not be retained beyond execution
         * @return independently owned result
         * @throws Exception if execution fails or cancellation is propagated
         */
        // Preserve the existing Callable-like callback contract for arbitrary checked task
        // failures.
        @SuppressWarnings("PMD.SignatureDeclareThrowsException")
        T call(CancellationToken cancellation) throws Exception;
    }

    /**
     * Thread-safe cooperative cancellation signal combined with the current thread's interrupt status.
     */
    /* default */ static final class CancellationToken implements CancellationSignal {
        private final AtomicBoolean cancelled = new AtomicBoolean();

        /**
         * Returns whether cancellation was requested or the observing thread is interrupted.
         *
         * @return whether this operation should stop cooperatively
         */
        // The standalone transport owns bounded task executors and preserves cancellation/thread
        // lifetime.
        @SuppressWarnings({"PMD.DoNotUseThreads"})
        @Override
        public boolean isCancelled() {
            return cancelled.get() || Thread.currentThread().isInterrupted();
        }

        /**
         * Permanently requests cooperative cancellation for this operation.
         */
        /* default */ void cancel() { cancelled.set(true); }
    }

    /** Names and marks runtime-owned worker threads for lane-aware shutdown. */
    private static final class NamedThreadFactory implements ThreadFactory {
        private final String prefix;
        private final WorkerType workerType;
        private final boolean virtual;
        private final AtomicInteger sequence = new AtomicInteger();
        private NamedThreadFactory(String prefix, WorkerType workerType) {
            this(prefix, workerType, false);
        }
        private NamedThreadFactory(String prefix, WorkerType workerType, boolean virtual) {
            this.prefix = prefix;
            this.workerType = workerType;
            this.virtual = virtual;
        }

        /**
         * {@inheritDoc}
         */
        // The standalone transport owns bounded task executors and preserves cancellation/thread
        // lifetime.
        @SuppressWarnings({"PMD.DoNotUseThreads"})
        @Override
        public Thread newThread(Runnable task) {
            Runnable marked =
                    () -> {
                        WORKER_MARKER.set(workerType);
                        try {
                            task.run();
                        } finally {
                            WORKER_MARKER.remove();
                        }
                    };
            if (virtual) {
                return Thread.ofVirtual()
                        .name(prefix + sequence.incrementAndGet())
                        .unstarted(marked);
            }
            Thread thread = new Thread(marked, prefix + sequence.incrementAndGet());
            thread.setDaemon(false);
            return thread;
        }
    }

    /** Identifies the current owned worker lane when deciding whether shutdown may wait. */
    private enum WorkerType {
        TRANSPORT,
        OPERATION,
        VALIDATION
    }

    // The standalone runtime owns the existing bounded cancellation/wait/shutdown sequence.
    @SuppressWarnings("PMD.DoNotUseThreads")
    private void closeOperations(boolean operationWorker) {
        if (!operationWorker) {
            await(operations, configuration.gracefulShutdown());
        }
        if (!operations.isTerminated()) {
            for (CancellationToken cancellation : cancellations) {
                cancellation.cancel();
            }
            if (!operationWorker) {
                for (Future<?> future : futures) {
                    future.cancel(true);
                }
            }
            cancelNeverStarted(operations.shutdownNow());
            if (!operationWorker) {
                await(operations, configuration.forcedShutdown());
            }
        }
    }

    // The standalone runtime owns the existing bounded transport wait/shutdown sequence.
    @SuppressWarnings("PMD.DoNotUseThreads")
    private void closeTransport(boolean transportWorker) {
        if (!transportWorker) {
            awaitService(transport, configuration.gracefulShutdown());
        }
        if (!transport.isTerminated()) {
            transport.shutdownNow();
            if (!transportWorker) {
                awaitService(transport, configuration.forcedShutdown());
            }
        }
    }
}
