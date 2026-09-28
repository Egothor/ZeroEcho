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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import zeroecho.pki.server.PkiServerConfiguration;

/** Deterministic bounded-admission, queue, cancellation and worker-close tests. */
class ServerRuntimeTest {
    @Test
    void queuedCancellationAndRejectionRetireExactOperationTracking() throws Exception {
        ServerRuntime runtime = new ServerRuntime(configuration());
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger queuedInvocations = new AtomicInteger();
        try {
            ServerRuntime.Submitted<String> active = runtime.submit(cancellation -> {
                started.countDown();
                release.await();
                return "active";
            });
            assertTrue(started.await(2, TimeUnit.SECONDS));

            ServerRuntime.Submitted<String> queued = runtime.submit(cancellation -> {
                queuedInvocations.incrementAndGet();
                return "queued";
            });
            assertEquals(2, runtime.trackedOperationFutures());
            assertEquals(2, runtime.trackedCancellationTokens());
            assertTrue(queued.future().cancel(false));
            queued.finish();
            assertEquals(0, runtime.operationQueueSize());
            assertEquals(1, runtime.trackedOperationFutures());
            assertEquals(1, runtime.trackedCancellationTokens());

            for (int iteration = 0; iteration < 16; iteration++) {
                ServerRuntime.Submitted<String> cancelled = runtime.submit(cancellation -> {
                    queuedInvocations.incrementAndGet();
                    return "unexpected";
                });
                assertTrue(cancelled.future().cancel(false));
                cancelled.finish();
                assertEquals(1, runtime.trackedOperationFutures());
                assertEquals(1, runtime.trackedCancellationTokens());
            }

            ServerRuntime.Submitted<String> fullQueue = runtime.submit(cancellation -> "full");
            AtomicBoolean rejectedInvoked = new AtomicBoolean();
            assertThrows(RejectedExecutionException.class,
                    () -> runtime.submit(cancellation -> {
                        rejectedInvoked.set(true);
                        return "rejected";
                    }));
            assertFalse(rejectedInvoked.get(),
                    "operation-queue rejection must occur before the task can create durable intent");
            assertEquals(2, runtime.trackedOperationFutures());
            assertEquals(2, runtime.trackedCancellationTokens());
            assertTrue(fullQueue.future().cancel(false));
            fullQueue.finish();

            release.countDown();
            assertEquals("active", active.future().get(2, TimeUnit.SECONDS));
            active.finish();
            assertEquals(0, queuedInvocations.get());
            assertEquals(0, runtime.trackedOperationFutures());
            assertEquals(0, runtime.trackedCancellationTokens());
        } finally {
            release.countDown();
            runtime.close();
        }
    }

    @Test
    void shutdownCancelsQueuedOperationsAndCleansTracking() throws Exception {
        ServerRuntime runtime = new ServerRuntime(configuration());
        CountDownLatch started = new CountDownLatch(1);
        AtomicBoolean queuedInvoked = new AtomicBoolean();
        runtime.submit(cancellation -> {
            started.countDown();
            while (!cancellation.isCancelled()) {
                try {
                    TimeUnit.MILLISECONDS.sleep(10L);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
            }
            return null;
        });
        assertTrue(started.await(2, TimeUnit.SECONDS));
        runtime.submit(cancellation -> {
            queuedInvoked.set(true);
            return null;
        });

        runtime.close();

        assertFalse(queuedInvoked.get());
        assertEquals(0, runtime.trackedOperationFutures());
        assertEquals(0, runtime.trackedCancellationTokens());
    }

    @Test
    void challengeCancellationRejectionAndShutdownRetireExactTracking() throws Exception {
        ServerRuntime.ChallengeRuntime runtime = new ServerRuntime.ChallengeRuntime(configuration());
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger queuedInvocations = new AtomicInteger();
        try {
            Future<String> active = runtime.submit(() -> {
                started.countDown();
                release.await();
                return "active";
            });
            assertTrue(started.await(2, TimeUnit.SECONDS));
            Future<String> queued = runtime.submit(() -> {
                queuedInvocations.incrementAndGet();
                return "queued";
            });
            assertEquals(2, runtime.trackedFutures());
            assertTrue(queued.cancel(false));
            assertEquals(1, runtime.trackedFutures());

            for (int iteration = 0; iteration < 16; iteration++) {
                Future<String> cancelled = runtime.submit(() -> {
                    queuedInvocations.incrementAndGet();
                    return "unexpected";
                });
                assertTrue(cancelled.cancel(false));
                assertEquals(1, runtime.trackedFutures());
            }

            Future<String> fullQueue = runtime.submit(() -> "full");
            assertThrows(RejectedExecutionException.class, () -> runtime.submit(() -> "rejected"));
            assertEquals(2, runtime.trackedFutures());
            assertTrue(fullQueue.cancel(false));
            release.countDown();
            assertEquals("active", active.get(2, TimeUnit.SECONDS));
            runtime.close();
            assertEquals(0, queuedInvocations.get());
            assertEquals(0, runtime.trackedFutures());
        } finally {
            release.countDown();
            runtime.close();
        }
    }

    @Test
    void enforcesFixedWorkersBoundedQueueAndPermitRelease() throws Exception {
        System.out.println("enforcesFixedWorkersBoundedQueueAndPermitRelease");
        ServerRuntime runtime = new ServerRuntime(configuration());
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try {
            assertTrue(runtime.tryAdmit());
            AtomicBoolean rejectedIngressBodyInvoked = new AtomicBoolean();
            assertFalse(runAfterIngressAdmission(runtime,
                    () -> rejectedIngressBodyInvoked.set(true)));
            assertFalse(rejectedIngressBodyInvoked.get(),
                    "transport-permit rejection must occur before the request body can create durable intent");
            runtime.releaseAdmission();
            ServerRuntime.Submitted<String> first = runtime.submit(cancellation -> {
                started.countDown();
                release.await();
                return Thread.currentThread().getName();
            });
            assertTrue(started.await(2, TimeUnit.SECONDS));
            ServerRuntime.Submitted<String> waiting = runtime.submit(cancellation -> "queued");
            assertEquals(1, runtime.activeOperations());
            assertEquals(1, runtime.operationQueueSize());
            AtomicBoolean rejectedOperationBodyInvoked = new AtomicBoolean();
            assertThrows(RejectedExecutionException.class, () -> runtime.submit(cancellation -> {
                rejectedOperationBodyInvoked.set(true);
                return "rejected";
            }));
            assertFalse(rejectedOperationBodyInvoked.get(),
                    "operation-queue rejection must occur before the task can create durable intent");
            release.countDown();
            assertTrue(first.future().get(2, TimeUnit.SECONDS).startsWith(ServerRuntime.OPERATION_PREFIX));
            assertEquals("queued", waiting.future().get(2, TimeUnit.SECONDS));
            first.finish();
            waiting.finish();
            System.out.println("...maximum-concurrent=1");
        } finally {
            release.countDown();
            runtime.close();
        }
        System.out.println("...ok");
    }

    @Test
    void operationWorkerCloseReportsTimeoutAndRemainsRetryable() throws Exception {
        System.out.println("operationWorkerCloseReportsTimeoutAndRemainsRetryable");
        ServerRuntime runtime = new ServerRuntime(configuration());
        ServerRuntime.Submitted<String> submitted = runtime.submit(cancellation -> {
            try {
                runtime.close();
                return "unexpected-success";
            } catch (IllegalStateException timeout) {
                return timeout.getMessage();
            }
        });
        assertTrue(submitted.future().get(2, TimeUnit.SECONDS).contains("SERVER_EXECUTION_SHUTDOWN_TIMEOUT"));
        submitted.finish();
        runtime.close();
        assertEquals(false, runtime.accepting());
        assertTrue(runtime.transportExecutor().isTerminated());
        System.out.println("...retry-close=true");
        System.out.println("...ok");
    }

    @Test
    void forcedTimeoutKeepsCancellationVisibleUntilRetry() throws Exception {
        ServerRuntime runtime = new ServerRuntime(configuration());
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ServerRuntime.Submitted<Void> submitted = runtime.submit(cancellation -> {
            entered.countDown();
            while (release.getCount() != 0L) {
                try {
                    release.await();
                } catch (InterruptedException ignored) {
                    // Deliberately non-cooperative until the test releases it.
                }
            }
            return null;
        });
        assertTrue(entered.await(2, TimeUnit.SECONDS));

        IllegalStateException timeout = assertThrows(IllegalStateException.class, runtime::close);
        assertTrue(timeout.getMessage().contains("SERVER_EXECUTION_SHUTDOWN_TIMEOUT"));
        assertTrue(submitted.cancellation().isCancelled());
        release.countDown();
        runtime.close();
        submitted.finish();
        assertTrue(runtime.transportExecutor().isTerminated());
    }

    @Test
    void marksOperationAndValidationWorkersWithoutUsingNames() throws Exception {
        assertFalse(ServerRuntime.isWorkerThread());
        ServerRuntime runtime = new ServerRuntime(configuration());
        ServerRuntime.ChallengeRuntime validation = new ServerRuntime.ChallengeRuntime(configuration());
        try {
            ServerRuntime.Submitted<Boolean> operation = runtime.submit(cancellation ->
                    ServerRuntime.isWorkerThread());
            Future<Boolean> transport = runtime.transportExecutor().submit(ServerRuntime::isWorkerThread);
            Future<Boolean> challenge = validation.submit(ServerRuntime::isWorkerThread);
            assertTrue(operation.future().get(2, TimeUnit.SECONDS));
            assertTrue(transport.get(2, TimeUnit.SECONDS));
            assertTrue(challenge.get(2, TimeUnit.SECONDS));
            operation.finish();
        } finally {
            validation.close();
            runtime.close();
        }
        assertFalse(ServerRuntime.isWorkerThread());
    }

    private static PkiServerConfiguration.Execution configuration() {
        return new PkiServerConfiguration.Execution(1, 1, 1, 1, 1,
                Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofMillis(100),
                Duration.ofMillis(100));
    }

    private static boolean runAfterIngressAdmission(ServerRuntime runtime, Runnable task) {
        if (!runtime.tryAdmit()) {
            return false;
        }
        try {
            task.run();
            return true;
        } finally {
            runtime.releaseAdmission();
        }
    }
}
