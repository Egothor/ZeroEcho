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
     * @param teardown blocking teardown that returns its exact failure, if any
     */
    /* default */ void close(boolean workerThread, Runnable quiesce, CloseAttempt teardown) {
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

        Throwable failure = action.close();
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

    @SuppressWarnings("unchecked")
    private static <Failure extends Throwable> void rethrowExact(Throwable failure) throws Failure {
        if (failure != null) {
            throw (Failure) failure;
        }
    }

    @SuppressWarnings("PMD.DoNotUseThreads") // The gate serializes ownership by exact calling thread.
    private static Thread currentThread() {
        return Thread.currentThread();
    }

    /** Nonthrowing close attempt whose result retains exact failure identity. */
    @FunctionalInterface
    public interface CloseAttempt {
        /** @return the exact failure to publish, or {@code null} on success */
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
