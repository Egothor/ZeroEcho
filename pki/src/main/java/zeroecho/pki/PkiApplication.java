/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.util.async.AsyncBus;

/**
 * Minimal bootstrap entry point for the {@code pki} module.
 *
 * <p>
 * This class is intentionally limited to process bootstrap and hosting
 * concerns:
 * </p>
 * <ul>
 * <li>initializes JUL logging conventions (without leaking secrets),</li>
 * <li>installs an uncaught-exception handler,</li>
 * <li>composes PKI runtime components using {@link PkiBootstrap},</li>
 * <li>hosts the async-bus maintenance loop via periodic
 * {@code sweep(...)},</li>
 * <li>waits until process termination (Ctrl+C) and performs orderly
 * shutdown.</li>
 * </ul>
 *
 * <h2>Async bus sweep</h2>
 * <p>
 * The async bus requires periodic {@link AsyncBus#sweep(Instant)} calls to:
 * expire operations past their deadline and re-synchronize open operations
 * after restart (depending on the bus implementation).
 * </p>
 *
 * <h2>Security</h2>
 * <p>
 * Command-line arguments and configuration values are never logged because they
 * can contain sensitive material (paths, tokens, passphrases).
 * </p>
 */
@SuppressWarnings("PMD.DoNotUseThreads")
public final class PkiApplication {

    private static final Logger LOG = Logger.getLogger(PkiApplication.class.getName());

    /**
     * System property controlling the async sweep interval in milliseconds.
     *
     * <p>
     * If missing or invalid, a safe default is used.
     * </p>
     */
    private static final String PROP_ASYNC_SWEEP_INTERVAL_MS = "zeroecho.pki.async.sweepIntervalMs";

    /**
     * Default async sweep interval used when not configured.
     */
    private static final Duration DEFAULT_ASYNC_SWEEP_INTERVAL = Duration.ofSeconds(2L);

    /**
     * Shutdown grace time for the sweep executor.
     */
    private static final Duration SWEEP_SHUTDOWN_GRACE = Duration.ofSeconds(10L);

    private PkiApplication() {
        throw new AssertionError("No instances.");
    }

    /**
     * Starts the PKI process.
     *
     * <p>
     * Security note: command-line arguments are not logged because they can contain
     * sensitive material (paths, tokens, passphrases).
     * </p>
     *
     * @param args command-line arguments (never logged)
     */
    public static void main(String[] args) {
        Objects.requireNonNull(args, "args");

        PkiLogging.configureIfPresent();
        PkiLogging.installUncaughtExceptionHandler();

        LOG.info("ZeroEcho PKI starting.");

        CountDownLatch shutdownLatch = new CountDownLatch(1);

        // closed in the shutdown routine
        ScheduledExecutorService sweepExecutor = Executors.newSingleThreadScheduledExecutor(new SweepThreadFactory()); // NOPMD

        Runtime.getRuntime()
                .addShutdownHook(new Thread(new ShutdownHook(sweepExecutor, shutdownLatch), "zeroecho-pki-shutdown"));

        try {
            AsyncBus<PkiId, Principal, String, Object> asyncBus = PkiBootstrap.openAsyncBus();

            Duration sweepInterval = readSweepInterval(DEFAULT_ASYNC_SWEEP_INTERVAL);

            if (LOG.isLoggable(Level.INFO)) {
                LOG.log(Level.INFO, "Async bus sweep enabled; intervalMs={0}", sweepInterval.toMillis());
            }

            sweepExecutor.scheduleWithFixedDelay(new SweepTask(asyncBus), 0L, sweepInterval.toMillis(),
                    TimeUnit.MILLISECONDS);

            LOG.info("ZeroEcho PKI started.");

            // Keep process alive until Ctrl+C (or other shutdown signal).
            awaitShutdown(shutdownLatch);
        } catch (RuntimeException ex) { // NOPMD
            // Do not include user-provided inputs in the message; log the exception object.
            LOG.log(Level.SEVERE, "Fatal error during PKI bootstrap.", ex);
            throw ex;
        }
    }

    private static void awaitShutdown(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            if (LOG.isLoggable(Level.WARNING)) {
                LOG.log(Level.WARNING, "Interrupted while awaiting shutdown.", ex);
            }
        }
    }

    private static Duration readSweepInterval(Duration defaultValue) {
        String raw = System.getProperty(PROP_ASYNC_SWEEP_INTERVAL_MS);
        if (raw == null || raw.isBlank()) {
            return defaultValue;
        }
        try {
            long ms = Long.parseLong(raw);
            if (ms <= 0L) { // NOPMD
                return defaultValue;
            }
            return Duration.ofMillis(ms);
        } catch (NumberFormatException ex) {
            if (LOG.isLoggable(Level.WARNING)) {
                LOG.log(Level.WARNING, "Invalid async sweep interval system property; using default.", ex);
            }
            return defaultValue;
        }
    }

    /**
     * Periodic maintenance task for asynchronous PKI infrastructure.
     *
     * <p>
     * {@code SweepTask} represents a resilient, repeatable unit of work that
     * invokes time-based maintenance logic on an {@link AsyncBus} instance. It is
     * intended to be scheduled at a fixed rate by a background executor and must
     * tolerate partial failures without disrupting the surrounding runtime
     * environment.
     * </p>
     *
     * <p>
     * The task uses the current wall-clock time as a reference for sweep operations
     * and deliberately suppresses runtime failures, logging them for diagnostic
     * purposes while allowing future executions to proceed.
     * </p>
     *
     * <p>
     * This class is internal to the PKI bootstrap and lifecycle management logic
     * and is not part of the public API surface.
     * </p>
     */
    private static final class SweepTask implements Runnable {

        private final AsyncBus<PkiId, Principal, String, Object> asyncBus;

        private SweepTask(AsyncBus<PkiId, Principal, String, Object> asyncBus) {
            this.asyncBus = Objects.requireNonNull(asyncBus, "asyncBus");
        }

        @Override
        public void run() {
            Instant now = Instant.now();
            try {
                asyncBus.sweep(now);
            } catch (RuntimeException ex) { // NOPMD
                // Sweep must be resilient; log and continue.
                if (LOG.isLoggable(Level.WARNING)) {
                    LOG.log(Level.WARNING, "Async sweep failed.", ex);
                }
            }
        }
    }

    /**
     * JVM shutdown hook coordinating termination of asynchronous sweep services.
     *
     * <p>
     * {@code ShutdownHook} is responsible for orchestrating an orderly shutdown of
     * background sweep execution during JVM termination. It emits a structured
     * shutdown message, initiates executor shutdown, and enforces a bounded grace
     * period for task completion.
     * </p>
     *
     * <p>
     * The hook guarantees that shutdown coordination always completes by
     * decrementing the associated {@link CountDownLatch}, regardless of whether
     * shutdown is graceful, forced, or interrupted.
     * </p>
     *
     * <p>
     * This class must never throw exceptions or prevent JVM termination. All
     * failure modes are handled internally.
     * </p>
     */
    private static final class ShutdownHook implements Runnable {

        private final ScheduledExecutorService sweepExecutor;
        private final CountDownLatch latch;

        private ShutdownHook(ScheduledExecutorService sweepExecutor, CountDownLatch latch) {
            this.sweepExecutor = Objects.requireNonNull(sweepExecutor, "sweepExecutor");
            this.latch = Objects.requireNonNull(latch, "latch");
        }

        @Override
        public void run() {
            Logger shutdownLogger = Logger.getLogger(PkiApplication.class.getName());
            PkiLogging.emitShutdownMessage(shutdownLogger, "ZeroEcho PKI stopping.");

            sweepExecutor.shutdown();
            try {
                boolean ok = sweepExecutor.awaitTermination(SWEEP_SHUTDOWN_GRACE.toMillis(), TimeUnit.MILLISECONDS);
                if (!ok) {
                    sweepExecutor.shutdownNow();
                }
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                sweepExecutor.shutdownNow();
            } finally {
                latch.countDown();
            }
        }
    }

    /**
     * Thread factory for asynchronous sweep execution.
     *
     * <p>
     * {@code SweepThreadFactory} creates daemon threads with a stable and
     * descriptive naming convention suitable for operational diagnostics and log
     * correlation. Threads produced by this factory are intentionally marked as
     * daemon threads so that they do not prolong JVM lifetime.
     * </p>
     *
     * <p>
     * The factory performs no additional customization such as priority changes or
     * uncaught-exception handlers, relying instead on executor-level policies.
     * </p>
     */
    private static final class SweepThreadFactory implements ThreadFactory {

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r, "zeroecho-pki-async-sweep");
            t.setDaemon(true);
            return t;
        }
    }
}
