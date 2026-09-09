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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SigningExecutionException;

/**
 * Bounded advisory queue and its single lifecycle-owned asynchronous notifier.
 * Provider scheduling and durable workflow state remain outside this component.
 */
@SuppressWarnings("PMD.DoNotUseThreads") // This object explicitly owns and joins its one notifier thread.
final class SigningAdvisoryRuntime {
    private static final long NO_WAIT_NANOS = 0L;

    private final int capacity;
    private final BooleanSupplier accepting;
    private final Set<PkiId> ready = new LinkedHashSet<>();
    private final Set<PkiId> inFlight = new HashSet<>();
    private final AtomicLong coalesced = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong wake = new AtomicLong();
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition notifierSignal = lock.newCondition();
    private final Condition notifierChanged = lock.newCondition();
    private final Thread notifierThread;
    private Runnable wakeListener;
    private boolean wakePending;
    private boolean notifierStarted;
    private boolean notifierStop;
    private boolean notifierExited;

    /* default */ SigningAdvisoryRuntime(int capacity, BooleanSupplier accepting) {
        this.capacity = capacity;
        this.accepting = Objects.requireNonNull(accepting, "accepting");
        notifierThread = new Thread(this::notifierLoop, "zeroecho-signing-advisory-notifier");
        notifierThread.setDaemon(true);
    }

    /* default */ void start() {
        lock.lock();
        try {
            notifierThread.start();
            boolean interrupted = false;
            while (!notifierStarted) {
                try {
                    notifierChanged.await();
                } catch (InterruptedException interruption) {
                    interrupted = true;
                }
            }
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        } finally {
            lock.unlock();
        }
    }

    /* default */ AutoCloseable registerWakeListener(Runnable listener) {
        Runnable exact = Objects.requireNonNull(listener, "listener");
        lock.lock();
        try {
            if (!accepting.getAsBoolean() || notifierStop) {
                throw new IllegalStateException("Signing advisory notifier is unavailable");
            }
            if (wakeListener != null) {
                throw new IllegalStateException("Signing advisory wake listener is already registered");
            }
            wakeListener = exact;
            if (!ready.isEmpty()) {
                wakePending = true;
                notifierSignal.signal();
            }
        } finally {
            lock.unlock();
        }
        AtomicBoolean registrationClosed = new AtomicBoolean();
        return () -> closeRegistration(registrationClosed, exact);
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals") // Registration removal requires exact callback identity.
    private void closeRegistration(AtomicBoolean registrationClosed, Runnable listener) {
        if (!registrationClosed.compareAndSet(false, true)) {
            return;
        }
        lock.lock();
        try {
            if (wakeListener == listener) {
                wakeListener = null;
            }
        } finally {
            lock.unlock();
        }
    }

    /* default */ void advisory(PkiId operationId) {
        if (operationId == null || !accepting.getAsBoolean()) {
            dropped.incrementAndGet();
            return;
        }
        lock.lock();
        try {
            if (!accepting.getAsBoolean() || notifierStop) {
                dropped.incrementAndGet();
            } else if (ready.contains(operationId)) {
                coalesced.incrementAndGet();
            } else if (ready.size() >= capacity) {
                dropped.incrementAndGet();
            } else {
                ready.add(operationId);
                wakePending = true;
                notifierSignal.signal();
            }
        } finally {
            lock.unlock();
        }
    }

    /* default */ List<PkiId> snapshot(int limit) {
        if (limit < 0) {
            throw new IllegalArgumentException("Advisory snapshot limit must not be negative");
        }
        lock.lock();
        try {
            int boundedLimit = Math.min(limit, capacity);
            if (boundedLimit == 0) {
                return List.of();
            }
            List<PkiId> snapshot = new ArrayList<>(Math.min(boundedLimit, ready.size()));
            for (PkiId operationId : ready) {
                if (inFlight.add(operationId)) {
                    snapshot.add(operationId);
                    if (snapshot.size() == boundedLimit) {
                        break;
                    }
                }
            }
            return List.copyOf(snapshot);
        } finally {
            lock.unlock();
        }
    }

    /* default */ void completePass(List<PkiId> snapshot, Set<PkiId> retained) {
        List<PkiId> exactSnapshot = Objects.requireNonNull(snapshot, "snapshot");
        Set<PkiId> exactRetained = Objects.requireNonNull(retained, "retained");
        lock.lock();
        try {
            for (PkiId operationId : exactSnapshot) {
                if (inFlight.remove(operationId)) {
                    boolean stillQueued = ready.remove(operationId);
                    if (stillQueued && exactRetained.contains(operationId)) {
                        ready.add(operationId);
                    }
                }
            }
        } finally {
            lock.unlock();
        }
    }

    /* default */ Optional<PkiId> poll() {
        lock.lock();
        try {
            Iterator<PkiId> iterator = ready.iterator();
            if (!iterator.hasNext()) {
                return Optional.empty();
            }
            PkiId operationId = iterator.next();
            iterator.remove();
            return Optional.of(operationId);
        } finally {
            lock.unlock();
        }
    }

    /* default */ void completeOperation(PkiId operationId) {
        PkiId exact = Objects.requireNonNull(operationId, "operationId");
        lock.lock();
        try {
            ready.remove(exact);
            inFlight.remove(exact);
        } finally {
            lock.unlock();
        }
    }

    /* default */ AdvisoryMetrics metrics() {
        lock.lock();
        try {
            return new AdvisoryMetrics(ready.size(), coalesced.get(), dropped.get(), wake.get());
        } finally {
            lock.unlock();
        }
    }

    /* default */ void quiesce() {
        lock.lock();
        try {
            notifierStop = true;
            wakePending = false;
            notifierSignal.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /* default */ void forceStop() {
        quiesce();
        notifierThread.interrupt();
    }

    /* default */ boolean awaitTermination(Duration duration) {
        long remaining = duration.toNanos();
        lock.lock();
        try {
            while (!notifierExited) {
                if (remaining <= NO_WAIT_NANOS) {
                    return false;
                }
                try {
                    remaining = notifierChanged.awaitNanos(remaining);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new SigningExecutionException(
                            SigningExecutionException.Classification.SHUTDOWN_TIMEOUT,
                            "Signing shutdown interrupted: code=SIGNING_SHUTDOWN_TIMEOUT", interrupted);
                }
            }
            return true;
        } finally {
            lock.unlock();
        }
    }

    /* default */ void finishClosed() {
        lock.lock();
        try {
            ready.clear();
            inFlight.clear();
            wakeListener = null;
            wakePending = false;
        } finally {
            lock.unlock();
        }
    }

    private void notifierLoop() {
        lock.lock();
        try {
            notifierStarted = true;
            notifierChanged.signalAll();
        } finally {
            lock.unlock();
        }
        try {
            runNotifications();
        } finally {
            lock.lock();
            try {
                notifierExited = true;
                notifierChanged.signalAll();
            } finally {
                lock.unlock();
            }
        }
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException") // Listener failure is isolated from notifier authority.
    private void runNotifications() {
        while (true) {
            Runnable listener = awaitWakeListener();
            if (listener == null) {
                return;
            }
            wake.incrementAndGet();
            try {
                listener.run();
            } catch (RuntimeException listenerFailure) {
                dropped.incrementAndGet();
            }
        }
    }

    private Runnable awaitWakeListener() {
        lock.lock();
        try {
            while (!notifierStop && (!wakePending || wakeListener == null)) {
                try {
                    notifierSignal.await();
                } catch (InterruptedException interrupted) {
                    if (notifierStop) {
                        Thread.currentThread().interrupt();
                        return null;
                    }
                }
            }
            if (notifierStop) {
                return null;
            }
            wakePending = false;
            return wakeListener;
        } finally {
            lock.unlock();
        }
    }

    /** Immutable advisory counter snapshot. */
    /* default */ record AdvisoryMetrics(int pending, long coalesced, long dropped, long wake) { }
}
