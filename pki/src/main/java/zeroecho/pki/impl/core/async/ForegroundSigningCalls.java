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

import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.SigningExecutionException;

/** Lifecycle-owned aggregate drain gate for active synchronous signing stacks. */
final class ForegroundSigningCalls {
    private static final long NO_WAIT_NANOS = 0L;
    private final AtomicBoolean forcedCancellation = new AtomicBoolean();
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition changed = lock.newCondition();
    private State state = State.OPEN;
    private int activeCalls;

    /* default */ ForegroundCall register(CancellationSignal callerCancellation) {
        CancellationSignal exact = Objects.requireNonNull(callerCancellation, "callerCancellation");
        lock.lock();
        try {
            if (state != State.OPEN) {
                throw failure(SigningExecutionException.Classification.SHUTTING_DOWN,
                        "Signing foreground admission is closed: code=SIGNING_SHUTTING_DOWN");
            }
            ForegroundCall call = new ForegroundCall(exact);
            activeCalls++;
            return call;
        } finally {
            lock.unlock();
        }
    }

    /* default */ void quiesce() {
        lock.lock();
        try {
            if (state == State.OPEN) {
                state = State.QUIESCING;
            }
        } finally {
            lock.unlock();
        }
    }

    /* default */ void forceCancellationPhase() {
        lock.lock();
        try {
            if (state == State.QUIESCING) {
                state = State.CANCELLING;
                forcedCancellation.set(true);
                changed.signalAll();
            }
        } finally {
            lock.unlock();
        }
    }

    /* default */ boolean awaitDrained(long deadline) {
        boolean interrupted = false;
        lock.lock();
        try {
            interrupted = awaitEmpty(deadline);
            return activeCalls == 0;
        } finally {
            lock.unlock();
            if (interrupted) {
                restoreInterrupt();
            }
        }
    }

    /* default */ void finishClosed() {
        lock.lock();
        try {
            if (activeCalls != 0) {
                throw new IllegalStateException("Signing foreground close invariant failed: "
                        + "code=SIGNING_FOREGROUND_STATE_INVALID");
            }
            state = State.CLOSED;
        } finally {
            lock.unlock();
        }
    }

    private boolean awaitEmpty(long deadline) {
        boolean interrupted = false;
        while (activeCalls != 0) {
            long remaining = deadline - System.nanoTime();
            if (remaining <= NO_WAIT_NANOS) {
                return interrupted;
            }
            try {
                changed.awaitNanos(remaining);
            } catch (InterruptedException interruption) {
                interrupted = true;
            }
        }
        return interrupted;
    }

    private static SigningExecutionException failure(SigningExecutionException.Classification classification,
            String message) {
        return new SigningExecutionException(classification, message);
    }

    @SuppressWarnings("PMD.DoNotUseThreads") // Interruption is part of the foreground cancellation contract.
    private static boolean currentThreadInterrupted() {
        return Thread.currentThread().isInterrupted();
    }

    @SuppressWarnings("PMD.DoNotUseThreads") // Restoring a consumed interrupt is required by the close contract.
    private static void restoreInterrupt() {
        Thread.currentThread().interrupt();
    }

    /** Caller-owned lexical scope for one active synchronous signing stack. */
    /* default */ final class ForegroundCall implements AutoCloseable {
        private final CancellationSignal callerCancellation;
        private final AtomicBoolean closed = new AtomicBoolean();

        private ForegroundCall(CancellationSignal callerCancellation) {
            this.callerCancellation = callerCancellation;
        }

        /* default */ CancellationSignal cancellation() {
            return () -> callerCancellation.isCancelled() || forcedCancellation.get()
                    || currentThreadInterrupted();
        }

        /* default */ void requireActive() {
            if (cancellation().isCancelled()) {
                throw failure(SigningExecutionException.Classification.SHUTTING_DOWN,
                        "Signing foreground call is cancelled: code=SIGNING_SHUTTING_DOWN");
            }
        }

        /* default */ void requireCommitAllowed() {
            requireActive();
            lock.lock();
            try {
                if (closed.get() || forcedCancellation.get() || currentThreadInterrupted()) {
                    throw failure(SigningExecutionException.Classification.SHUTTING_DOWN,
                            "Signing foreground call is cancelled: code=SIGNING_SHUTTING_DOWN");
                }
            } finally {
                lock.unlock();
            }
        }

        @Override public void close() {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            lock.lock();
            try {
                if (activeCalls <= 0) {
                    throw new IllegalStateException("Signing foreground accounting is inconsistent");
                }
                activeCalls--;
                changed.signalAll();
            } finally {
                lock.unlock();
            }
        }
    }

    /** Registry lifecycle. */
    private enum State {
        OPEN, QUIESCING, CANCELLING, CLOSED
    }
}
