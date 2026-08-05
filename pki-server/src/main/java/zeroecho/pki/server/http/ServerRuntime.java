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
package zeroecho.pki.server.http;

import java.time.Duration;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.server.PkiServerConfiguration;

/** Centralized owner of all bounded server-created threads, queues and permits. */
@SuppressWarnings("PMD")
final class ServerRuntime implements AutoCloseable {
    static final String TRANSPORT_PREFIX = "zeroecho-pki-https-";
    static final String OPERATION_PREFIX = "zeroecho-pki-operation-";
    static final String PUBLIC_TRANSPORT_PREFIX = "zeroecho-pki-public-https-";
    static final String PUBLIC_STREAM_PREFIX = "zeroecho-pki-public-stream-";
    static final String ACME_TRANSPORT_PREFIX = "zeroecho-pki-acme-https-";
    static final String ACME_PROTOCOL_PREFIX = "zeroecho-pki-acme-protocol-";
    static final String ACME_VALIDATION_PREFIX = "zeroecho-pki-acme-validation-";
    static final String SHUTDOWN_NAME = "zeroecho-pki-shutdown";

    private final ThreadPoolExecutor transport;
    private final ThreadPoolExecutor operations;
    private final Semaphore admitted;
    private final Set<CancellationToken> cancellations = ConcurrentHashMap.newKeySet();
    private final Set<Future<?>> futures = ConcurrentHashMap.newKeySet();
    private final PkiServerConfiguration.Execution configuration;
    private final AtomicBoolean accepting = new AtomicBoolean(true);

    ServerRuntime(PkiServerConfiguration.Execution configuration) {
        this(configuration, Lane.ADMIN);
    }

    ServerRuntime(PkiServerConfiguration.Execution configuration, boolean publicLane) {
        this(configuration, publicLane ? Lane.PUBLIC : Lane.ADMIN);
    }

    ServerRuntime(PkiServerConfiguration.Execution configuration, Lane lane) {
        this.configuration = configuration;
        transport = pool(configuration.transportWorkers(), configuration.transportQueueCapacity(),
                new NamedThreadFactory(lane == Lane.PUBLIC ? PUBLIC_TRANSPORT_PREFIX
                        : lane == Lane.ACME ? ACME_TRANSPORT_PREFIX : TRANSPORT_PREFIX));
        operations = pool(configuration.operationWorkers(), configuration.operationQueueCapacity(),
                new NamedThreadFactory(lane == Lane.PUBLIC ? PUBLIC_STREAM_PREFIX
                        : lane == Lane.ACME ? ACME_PROTOCOL_PREFIX : OPERATION_PREFIX));
        admitted = new Semaphore(configuration.maximumAdmittedRequests(), true);
    }

    ThreadPoolExecutor transportExecutor() {
        return transport;
    }

    boolean tryAdmit() {
        return accepting.get() && admitted.tryAcquire();
    }

    void releaseAdmission() {
        admitted.release();
    }

    <T> Submitted<T> submit(CancellableCallable<T> task) {
        if (!accepting.get()) throw new RejectedExecutionException("Server is not accepting operations");
        CancellationToken cancellation = new CancellationToken();
        cancellations.add(cancellation);
        Future<T> future;
        try {
            future = operations.submit(() -> {
                try {
                    cancellation.throwIfCancelled();
                    return task.call(cancellation);
                } finally {
                    cancellations.remove(cancellation);
                }
            });
        } catch (RejectedExecutionException failure) {
            cancellations.remove(cancellation);
            throw failure;
        }
        futures.add(future);
        return new Submitted<>(future, cancellation, () -> futures.remove(future));
    }

    void quiesce() {
        accepting.set(false);
    }

    boolean accepting() {
        return accepting.get();
    }

    int operationQueueSize() {
        return operations.getQueue().size();
    }

    int activeOperations() {
        return operations.getActiveCount();
    }

    static Thread shutdownHook(Runnable task) {
        return new Thread(task, SHUTDOWN_NAME);
    }

    @Override
    public void close() {
        quiesce();
        transport.shutdown();
        operations.shutdown();
        boolean transportWorker = Thread.currentThread().getName().startsWith(TRANSPORT_PREFIX)
                || Thread.currentThread().getName().startsWith(PUBLIC_TRANSPORT_PREFIX)
                || Thread.currentThread().getName().startsWith(ACME_TRANSPORT_PREFIX);
        boolean operationWorker = Thread.currentThread().getName().startsWith(OPERATION_PREFIX)
                || Thread.currentThread().getName().startsWith(PUBLIC_STREAM_PREFIX)
                || Thread.currentThread().getName().startsWith(ACME_PROTOCOL_PREFIX);
        if (!operationWorker) {
            await(operations, configuration.gracefulShutdown());
        }
        if (!operations.isTerminated()) {
            for (CancellationToken cancellation : cancellations) cancellation.cancel();
            if (!operationWorker) {
                for (Future<?> future : futures) future.cancel(true);
            }
            operations.shutdownNow();
            if (!operationWorker) {
                await(operations, configuration.forcedShutdown());
            }
        }
        if (!transportWorker) await(transport, configuration.gracefulShutdown());
        if (!transport.isTerminated()) {
            transport.shutdownNow();
            if (!transportWorker) await(transport, configuration.forcedShutdown());
        }
    }

    enum Lane { ADMIN, PUBLIC, ACME }

    /** One separately admitted bounded challenge-validation execution lane. */
    static final class ChallengeRuntime implements AutoCloseable {
        private final ThreadPoolExecutor executor;
        private final Semaphore admitted;
        private final Duration graceful;
        private final Duration forced;
        private final AtomicBoolean accepting = new AtomicBoolean(true);
        private final Set<Future<?>> futures = ConcurrentHashMap.newKeySet();

        ChallengeRuntime(PkiServerConfiguration.Execution configuration) {
            executor = pool(configuration.operationWorkers(), configuration.operationQueueCapacity(),
                    new NamedThreadFactory(ACME_VALIDATION_PREFIX));
            admitted = new Semaphore(configuration.maximumAdmittedRequests(), true);
            graceful = configuration.gracefulShutdown(); forced = configuration.forcedShutdown();
        }

        boolean tryAdmit() { return accepting.get() && admitted.tryAcquire(); }
        void release() { admitted.release(); }
        <T> Future<T> submit(java.util.concurrent.Callable<T> work) {
            if (!accepting.get()) throw new RejectedExecutionException("ACME validation is not accepting work");
            Future<T> future = executor.submit(work); futures.add(future); return future;
        }
        void quiesce() { accepting.set(false); }
        @Override public void close() {
            quiesce(); executor.shutdown();
            boolean worker = Thread.currentThread().getName().startsWith(ACME_VALIDATION_PREFIX);
            if (!worker) await(executor, graceful);
            if (!executor.isTerminated()) {
                futures.forEach(value -> value.cancel(true)); executor.shutdownNow();
                if (!worker) await(executor, forced);
            }
        }
    }

    private static ThreadPoolExecutor pool(int workers, int queueCapacity, ThreadFactory factory) {
        ThreadPoolExecutor result = new ThreadPoolExecutor(workers, workers, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(queueCapacity), factory, new ThreadPoolExecutor.AbortPolicy());
        result.prestartAllCoreThreads();
        return result;
    }

    private static void await(ThreadPoolExecutor executor, Duration duration) {
        try {
            if (!executor.awaitTermination(duration.toMillis(), TimeUnit.MILLISECONDS)) return;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    record Submitted<T>(Future<T> future, CancellationToken cancellation, Runnable completed) {
        Submitted {
            if (future == null || cancellation == null || completed == null) {
                throw new NullPointerException("Submitted operation fields must not be null");
            }
        }
        void finish() { completed.run(); }
    }

    @FunctionalInterface
    interface CancellableCallable<T> {
        T call(CancellationToken cancellation) throws Exception;
    }

    static final class CancellationToken implements CancellationSignal {
        private final AtomicBoolean cancelled = new AtomicBoolean();
        @Override public boolean isCancelled() { return cancelled.get() || Thread.currentThread().isInterrupted(); }
        void cancel() { cancelled.set(true); }
    }

    private static final class NamedThreadFactory implements ThreadFactory {
        private final String prefix;
        private final AtomicInteger sequence = new AtomicInteger();
        private NamedThreadFactory(String prefix) { this.prefix = prefix; }
        @Override public Thread newThread(Runnable task) {
            Thread thread = new Thread(task, prefix + sequence.incrementAndGet());
            thread.setDaemon(false);
            return thread;
        }
    }
}
