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
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

final class RetryableCloseGateTest {
    @Test
    void overlappingSuccessRunsOneAttemptAndBecomesTerminal() throws Exception {
        RetryableCloseGate gate = new RetryableCloseGate();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger attempts = new AtomicInteger();
        try (ExecutorService callers = Executors.newFixedThreadPool(2)) {
            Future<?> owner = callers.submit(() -> {
                gate.close(false, () -> { }, result(() -> {
                    attempts.incrementAndGet();
                    entered.countDown();
                    release.await();
                }));
                return null;
            });
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            CountDownLatch joining = new CountDownLatch(1);
            AtomicReference<Thread> joiningThread = new AtomicReference<>();
            Future<?> joiner = callers.submit(() -> {
                joiningThread.set(Thread.currentThread());
                joining.countDown();
                gate.close(false, () -> { }, result(attempts::incrementAndGet));
                return null;
            });
            assertTrue(joining.await(2, TimeUnit.SECONDS));
            awaitWaiting(joiningThread.get());
            release.countDown();
            owner.get(2, TimeUnit.SECONDS);
            joiner.get(2, TimeUnit.SECONDS);
        }
        gate.close(false, () -> { }, result(attempts::incrementAndGet));
        assertEquals(1, attempts.get());
    }

    @Test
    void concurrentFailureIsExactAndOneLaterGenerationMayRetry() throws Exception {
        RetryableCloseGate gate = new RetryableCloseGate();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger attempts = new AtomicInteger();
        ClassifiedFailure exact = new ClassifiedFailure("DRAIN_TIMEOUT");
        try (ExecutorService callers = Executors.newFixedThreadPool(2)) {
            Future<?> owner = callers.submit(() -> {
                gate.close(false, () -> { }, result(() -> {
                    attempts.incrementAndGet();
                    entered.countDown();
                    release.await();
                    throw exact;
                }));
                return null;
            });
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            CountDownLatch joining = new CountDownLatch(1);
            AtomicReference<Thread> joiningThread = new AtomicReference<>();
            Future<?> joiner = callers.submit(() -> {
                joiningThread.set(Thread.currentThread());
                joining.countDown();
                gate.close(false, () -> { }, result(attempts::incrementAndGet));
                return null;
            });
            assertTrue(joining.await(2, TimeUnit.SECONDS));
            awaitWaiting(joiningThread.get());
            release.countDown();
            assertSame(exact, cause(owner));
            assertSame(exact, cause(joiner));
        }
        gate.close(false, () -> { }, result(attempts::incrementAndGet));
        gate.close(false, () -> { }, result(attempts::incrementAndGet));
        assertEquals(2, attempts.get());
    }

    @Test
    void interruptedWaiterRestoresInterruptAfterSharedCompletion() throws Exception {
        RetryableCloseGate gate = new RetryableCloseGate();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicBoolean interrupted = new AtomicBoolean();
        Thread owner = new Thread(() -> closeUnchecked(gate, result(() -> {
            entered.countDown();
            release.await();
        })));
        owner.start();
        assertTrue(entered.await(2, TimeUnit.SECONDS));
        CountDownLatch joining = new CountDownLatch(1);
        Thread joiner = new Thread(() -> {
            joining.countDown();
            closeUnchecked(gate, result(() -> { }));
            interrupted.set(Thread.currentThread().isInterrupted());
        });
        joiner.start();
        assertTrue(joining.await(2, TimeUnit.SECONDS));
        awaitWaiting(joiner);
        joiner.interrupt();
        release.countDown();
        owner.join(2_000L);
        joiner.join(2_000L);
        assertTrue(interrupted.get());
    }

    @Test
    void reentrantOwnerFailsFast() {
        RetryableCloseGate gate = new RetryableCloseGate();
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> gate.close(false, () -> { }, result(
                        () -> gate.close(false, () -> { }, result(() -> { })))));
        assertTrue(failure.getMessage().contains("SERVER_CLOSE_REENTRANT"));
    }

    @Test
    void workerNeverOwnsOrJoinsAndSignalsQuiesce() throws Exception {
        RetryableCloseGate gate = new RetryableCloseGate();
        AtomicInteger quiesces = new AtomicInteger();
        AtomicInteger attempts = new AtomicInteger();
        IllegalStateException first = assertThrows(IllegalStateException.class,
                () -> gate.close(true, quiesces::incrementAndGet, result(attempts::incrementAndGet)));
        assertTrue(first.getMessage().contains("SERVER_CLOSE_RETRY_REQUIRED"));
        assertEquals(1, quiesces.get());
        assertEquals(0, attempts.get());

        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Thread owner = new Thread(() -> closeUnchecked(gate, result(() -> {
            attempts.incrementAndGet();
            entered.countDown();
            release.await();
        })));
        owner.start();
        assertTrue(entered.await(2, TimeUnit.SECONDS));
        IllegalStateException joining = assertThrows(IllegalStateException.class,
                () -> gate.close(true, quiesces::incrementAndGet, result(attempts::incrementAndGet)));
        assertTrue(joining.getMessage().contains("SERVER_CLOSE_RETRY_REQUIRED"));
        assertEquals(2, quiesces.get());
        release.countDown();
        owner.join(2_000L);
        assertFalse(owner.isAlive());
        assertEquals(1, attempts.get());
    }

    private static Throwable cause(Future<?> future) throws Exception {
        return assertThrows(ExecutionException.class, () -> future.get(2, TimeUnit.SECONDS)).getCause();
    }

    private static void closeUnchecked(RetryableCloseGate gate, RetryableCloseGate.CloseAttempt attempt) {
        try {
            gate.close(false, () -> { }, attempt);
        } catch (Throwable failure) {
            throw new AssertionError(failure);
        }
    }

    private static RetryableCloseGate.CloseAttempt result(CheckedCloseAttempt attempt) {
        return () -> {
            try {
                attempt.close();
                return null;
            } catch (Throwable failure) {
                return failure;
            }
        };
    }

    @FunctionalInterface
    private interface CheckedCloseAttempt {
        void close() throws Exception;
    }

    private static void awaitWaiting(Thread thread) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2L);
        while (thread.getState() != Thread.State.WAITING && System.nanoTime() < deadline) {
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1L));
        }
        assertEquals(Thread.State.WAITING, thread.getState());
    }

    private static final class ClassifiedFailure extends Exception {
        private static final long serialVersionUID = 1L;
        private final String classification;

        private ClassifiedFailure(String classification) {
            this.classification = classification;
        }

        @Override public String getMessage() {
            return classification;
        }
    }
}
