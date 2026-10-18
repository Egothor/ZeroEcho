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
package zeroecho.pki.server;

import java.util.Objects;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/** Serializes retryable close attempts without holding its lock during teardown. */
final class RetryableCloseGate {
    private static final String REENTRANT =
            "Close attempt cannot join its owner: code=SERVER_CLOSE_REENTRANT";
    private static final String WORKER_RETRY =
            "Server worker cannot perform blocking close: code=SERVER_CLOSE_RETRY_REQUIRED";

    private final ReentrantLock lock = new ReentrantLock();
    private final Condition completed = lock.newCondition();
    private Attempt current;
    private long generation;
    private boolean terminal;

    /**
     * Runs or joins one close attempt.
     *
     * @param workerThread whether the caller is a marked server worker
     * @param quiesce idempotent nonblocking signal used only by a worker caller
     * @param teardown blocking teardown that returns its original failure, if any
     * @throws java.io.IOException if checked shutdown fails
     */
    /* default */ void close(boolean workerThread, Runnable quiesce, CloseAttempt teardown) throws java.io.IOException {
        Runnable signal = Objects.requireNonNull(quiesce, "quiesce");
        CloseAttempt action = Objects.requireNonNull(teardown, "teardown");
        if (workerThread) {
            signal.run();
            throw new IllegalStateException(WORKER_RETRY);
        }

        Attempt selected;
        boolean owner;
        lock.lock();
        try {
            if (terminal) {
                return;
            }
            if (current != null && !current.completed) {
                current.requireExternalJoiner(currentThread());
                selected = current;
                owner = false;
            } else {
                selected = new Attempt(Math.addExact(generation, 1L), currentThread());
                generation = selected.generation;
                current = selected;
                owner = true;
            }
        } finally {
            lock.unlock();
        }

        if (!owner) {
            await(selected);
            rethrowExact(selected.failure);
            return;
        }

        Throwable failure = normalize(action.close());
        publish(selected, failure);
        rethrowExact(failure);
    }

    private void await(Attempt selected) {
        lock.lock();
        try {
            while (!selected.completed) {
                completed.awaitUninterruptibly();
            }
        } finally {
            lock.unlock();
        }
    }

    private void publish(Attempt selected, Throwable failure) {
        lock.lock();
        try {
            selected.failure = failure;
            selected.completed = true;
            if (failure == null) {
                terminal = true;
            }
            completed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Translates one interrupted join while retaining the original failure as cause.
     * @param failure interrupted resource shutdown
     * @return I/O failure with interruption restored on the calling thread
     */
    /* default */ static java.io.InterruptedIOException interruptedClose(InterruptedException failure) {
        restoreInterruption(failure);
        java.io.InterruptedIOException translated = new java.io.InterruptedIOException("Server close interrupted");
        translated.initCause(failure);
        return translated;
    }

    /** Normalizes a shared attempt once so owner and joiners observe the same failure. */
    private static Throwable normalize(Throwable failure) {
        if (failure == null || failure instanceof java.io.IOException
                || failure instanceof RuntimeException || failure instanceof Error) {
            return failure;
        }
        if (failure instanceof InterruptedException interrupted) {
            return interruptedClose(interrupted);
        }
        return new java.io.IOException("Server close failed", failure);
    }

    /** Restores cancellation throughout the original cause and suppression graph. */
    private static void restoreInterruption(Throwable failure) {
        java.util.Set<Throwable> visited = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        java.util.Deque<Throwable> pending = new java.util.ArrayDeque<>();
        pending.add(failure);
        while (!pending.isEmpty()) {
            Throwable current = pending.removeFirst();
            if (visited.add(current)) {
                if (current instanceof InterruptedException) {
                    Thread.currentThread().interrupt(); // NOPMD DoNotUseThreads - Standalone server restores caller cancellation; no J2EE container.
                }
                java.util.Collections.addAll(pending, current.getSuppressed());
                if (current.getCause() != null) {
                    pending.add(current.getCause());
                }
            }
        }
    }

    /** Rethrows a published failure without creating caller-specific wrappers. */
    private static void rethrowExact(Throwable failure) throws java.io.IOException {
        if (failure == null) {
            return;
        }
        restoreInterruption(failure);
        if (failure instanceof java.io.IOException exception) {
            throw exception;
        }
        if (failure instanceof RuntimeException exception) {
            throw exception;
        }
        if (failure instanceof Error error) {
            throw error;
        }
        throw new IllegalStateException("Unnormalized server close failure", failure);
    }

    @SuppressWarnings("PMD.DoNotUseThreads") // The gate serializes ownership by exact calling thread.
    private static Thread currentThread() {
        return Thread.currentThread();
    }

    /**
     * Nonthrowing close attempt returning an original failure. Checked failures
     * are translated once before publication; all callers share the published
     * failure, whose cause retains the original checked failure and suppression.
     */
    @FunctionalInterface
    public interface CloseAttempt {
        /** @return original failure to normalize and publish, or {@code null} on success */
        Throwable close();
    }

    /** One write-once result retained directly by every caller that joined it. */
    @SuppressWarnings("PMD.DoNotUseThreads") // Attempt ownership is intentionally an exact Thread capability.
    private static final class Attempt {
        private final long generation;
        private final Thread owner;
        private boolean completed;
        private Throwable failure;

        private Attempt(long generation, Thread owner) {
            this.generation = generation;
            this.owner = owner;
        }

        @SuppressWarnings("PMD.CompareObjectsWithEquals") // Close ownership requires exact thread identity.
        private void requireExternalJoiner(Thread caller) {
            if (owner == caller) {
                throw new IllegalStateException(REENTRANT);
            }
        }
    }
}
