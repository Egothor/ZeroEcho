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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.LockSupport;

/**
 * Single-threaded, self-rescheduling status-schedule owner for one realm.
 */
@SuppressWarnings({ "PMD.DoNotUseThreads", "PMD.CommentDefaultAccessModifier" })
final class StatusScheduleWorker implements AutoCloseable {
    private static final Duration IDLE_INTERVAL = Duration.ofMinutes(1);

    private final ScheduleGateway gateway;
    private final Duration forcedShutdown;
    private final Clock clock;
    private final java.util.function.Consumer<String> failure;
    private final Thread workerThread;
    private final AtomicBoolean cancelled = new AtomicBoolean();
    private final AtomicBoolean wakeRequested = new AtomicBoolean();
    private final AtomicBoolean started = new AtomicBoolean();

    /**
     * Creates an unstarted daemon owner for one realm's status-schedule passes.
     *
     * @param gateway synchronous schedule evaluation/generation boundary
     * @param forcedShutdown maximum worker-join duration
     * @param clock schedule eligibility time source
     * @param failure safe failure-code recorder
     * @throws NullPointerException if a collaborator is null
     */
    /* default */ StatusScheduleWorker(ScheduleGateway gateway, Duration forcedShutdown, Clock clock,
            java.util.function.Consumer<String> failure) {
        this.gateway = Objects.requireNonNull(gateway, "gateway");
        this.forcedShutdown = Objects.requireNonNull(forcedShutdown, "forcedShutdown");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.failure = Objects.requireNonNull(failure, "failure");
        this.workerThread = new Thread(this::runLoop, "zeroecho-status-schedule");
        this.workerThread.setDaemon(true);
    }

    /**
     * Starts the daemon worker exactly once.
     *
     * @throws IllegalStateException if already started or shutdown was requested
     */
    /* default */ void start() {
        if (cancelled.get() || !started.compareAndSet(false, true)) {
            throw new IllegalStateException("Status schedule worker cannot start");
        }
        workerThread.start();
    }

    /**
     * Requests an immediate pass unless shutdown has already been requested.
     *
     * <p>Repeated wake requests are coalesced; this method performs no schedule generation.</p>
     */
    /* default */ void wake() {
        if (cancelled.get()) {
            return;
        }
        wakeRequested.set(true);
        LockSupport.unpark(workerThread);
    }

    private void runLoop() {
        Duration delay = Duration.ZERO;
        while (!cancelled.get()) {
            awaitNextPass(delay);
            if (cancelled.get()) {
                return;
            }
            PassHints hints = runPass();
            delay = nextDelay(hints, wakeRequested.getAndSet(false));
        }
    }

    private void awaitNextPass(Duration delay) {
        long remaining = delay.toNanos();
        long deadline = System.nanoTime() + remaining;
        while (!cancelled.get() && remaining > 0L && !wakeRequested.getAndSet(false)) {
            LockSupport.parkNanos(this, remaining);
            if (Thread.interrupted() && cancelled.get()) {
                return;
            }
            remaining = deadline - System.nanoTime();
        }
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException") // A pass failure must not stop scheduling.
    private PassHints runPass() {
        if (cancelled.get()) {
            return PassHints.idle();
        }
        try {
            return gateway.execute(cancelled::get);
        } catch (java.util.concurrent.CancellationException cancelledPass) {
            return PassHints.idle();
        } catch (RuntimeException failed) {
            if (!cancelled.get()) { failure.accept("STATUS_SCHEDULE_PASS_FAILED"); }
            return PassHints.idle();
        }
    }

    /**
     * Chooses the next work-conserving delay, bounded by the one-minute idle interval.
     *
     * @param hints immediate-work flag and optional next eligible schedule instant
     * @param coalescedWake whether a wake arrived during the previous pass
     * @return nonnegative delay, using the idle interval if clock evaluation fails
     */
    @SuppressWarnings("PMD.AvoidCatchingGenericException") // A faulty clock degrades scheduling to the idle interval.
    /* default */ Duration nextDelay(PassHints hints, boolean coalescedWake) {
        if (hints.immediate() || coalescedWake) {
            return Duration.ZERO;
        }
        if (hints.nextEligible().isEmpty()) {
            return IDLE_INTERVAL;
        }
        try {
            Duration due = Duration.between(clock.instant(), hints.nextEligible().orElseThrow());
            if (due.isNegative() || due.isZero()) {
                return Duration.ZERO;
            }
            return due.compareTo(IDLE_INTERVAL) < 0 ? due : IDLE_INTERVAL;
        } catch (RuntimeException failure) {
            this.failure.accept("STATUS_SCHEDULE_CLOCK_FAILED");
            return IDLE_INTERVAL;
        }
    }

    /**
     * Observes whether the daemon is alive and has not received a shutdown request.
     *
     * @return whether schedule execution remains active
     */
    boolean isRunning() { return workerThread.isAlive() && !cancelled.get(); }

    /**
     * Requests cancellation before waiting for the configured forced-shutdown bound.
     *
     * <p>Interrupted waiters have their interrupt status restored and receive an I/O
     * failure. A timed-out worker remains owned so an external caller can retry closure.</p>
     *
     * @throws java.io.IOException if the waiting caller is interrupted
     * @throws IllegalStateException if the worker remains alive after the configured bound
     */
    @Override
    public void close() throws java.io.IOException {
        stopScheduling();
        try {
            awaitStopped();
        } catch (InterruptedException failure) {
            throw RetryableCloseGate.interruptedClose(failure);
        }
    }

    /**
     * Idempotently requests cancellation and interrupts/unparks the schedule worker.
     */
    /* default */ void stopScheduling() {
        if (cancelled.compareAndSet(false, true)) {
            workerThread.interrupt();
            LockSupport.unpark(workerThread);
        }
    }

    /**
     * Waits at most the configured forced-shutdown bound after scheduling stops.
     *
     * @throws InterruptedException if the waiting caller is interrupted
     * @throws IllegalStateException if shutdown was not requested or the worker does not stop in time
     */
    /* default */ void awaitStopped() throws InterruptedException {
        if (!cancelled.get()) {
            throw new IllegalStateException("Status schedule worker is still accepting work");
        }
        workerThread.join(forcedShutdown.toMillis(), forcedShutdown.toNanosPart() % 1_000_000);
        if (workerThread.isAlive()) {
            throw new IllegalStateException(
                    "Status schedule worker shutdown timed out: code=STATUS_SCHEDULE_SHUTDOWN_TIMEOUT");
        }
    }

    /**
     * Boundary for per-pass schedule evaluation and generation.
     */
    @FunctionalInterface
    /* default */ interface ScheduleGateway {
        /** Evaluates one cancellable pass and returns the next scheduling hints.
         * @param cancellation shutdown signal
         * @return scheduling hints
         */
        PassHints execute(zeroecho.core.io.CancellationSignal cancellation);
    }

    /**
     * Work-conserving scheduling observations from one status-generation pass.
     *
     * @param immediate whether another pass can run immediately
     * @param nextEligible earliest known schedule eligibility instant, or empty
     */
    /* default */ record PassHints(boolean immediate, Optional<Instant> nextEligible) {
        /**
         * Requires an explicit optional eligibility container.
         *
         * @param immediate whether another pass can run immediately
         * @param nextEligible earliest known eligibility instant, or empty
         * @throws NullPointerException if the eligibility container is null
         */
        PassHints {
            nextEligible = Objects.requireNonNull(nextEligible, "nextEligible");
        }
        /**
         * Creates scheduling hints without immediate work or a known eligibility instant.
         *
         * @return idle scheduling observation
         */
        /* default */ static PassHints idle() { return new PassHints(false, Optional.empty()); }
    }
}
