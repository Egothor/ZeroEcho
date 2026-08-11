/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.server;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import zeroecho.pki.application.SigningReconciliationRequest;
import zeroecho.pki.application.SigningReconciliationResult;
import zeroecho.pki.application.PkiSession;

/** Single-threaded, self-rescheduling signing recovery owner for one realm. */
@SuppressWarnings({ "PMD.DoNotUseThreads", "PMD.AvoidUsingVolatile", "PMD.CommentDefaultAccessModifier" })
final class SigningReconciliationWorker implements AutoCloseable {
    private final PkiSession session;
    private final AuditTransport audit;
    private final PkiServerConfiguration.SigningReconciliation configuration;
    private final Duration forcedShutdown;
    private final Clock clock;
    private final ScheduledExecutorService executor;
    private final AtomicBoolean cancelled = new AtomicBoolean();
    private Optional<String> cursor = Optional.empty();
    private volatile Future<?> scheduled;

    /* default */ SigningReconciliationWorker(ServerRealmContext realm,
            PkiServerConfiguration.SigningReconciliation configuration, Duration forcedShutdown, Clock clock) {
        this(Objects.requireNonNull(realm, "realm").session(), realm::auditTransport, configuration, forcedShutdown,
                clock);
    }

    /* default */ SigningReconciliationWorker(PkiSession session, AuditTransport audit,
            PkiServerConfiguration.SigningReconciliation configuration, Duration forcedShutdown, Clock clock) {
        this.session = Objects.requireNonNull(session, "session");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.forcedShutdown = Objects.requireNonNull(forcedShutdown, "forcedShutdown");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.executor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "zeroecho-signing-reconciliation");
            thread.setDaemon(true);
            return thread;
        });
    }

    /* default */ void start() {
        if (cancelled.get() || scheduled != null) {
            throw new IllegalStateException("Signing reconciliation worker cannot start");
        }
        scheduled = executor.submit(this::runPass);
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private void runPass() {
        if (cancelled.get()) {
            return;
        }
        Instant deadline = clock.instant().plus(configuration.passTimeout());
        Map<String, String> auditDetails;
        try {
            SigningReconciliationResult result = session.reconcileSigning(new SigningReconciliationRequest(
                    cursor, configuration.maximumRecords(), configuration.maximumProviderCalls(), deadline,
                    configuration.providerCallTimeout(), cancelled::get));
            cursor = result.nextCursor();
            auditDetails = Map.of(
                    "code", result.retryable() == 0 ? "SIGNING_RECONCILIATION_OK" : "SIGNING_RECONCILIATION_RETRY",
                    "examined", Integer.toString(result.examined()),
                    "progressed", Integer.toString(result.progressed()),
                    "unresolved", Integer.toString(result.unresolved()),
                    "retryable", Integer.toString(result.retryable()),
                    "endReached", Boolean.toString(result.endReached()));
        } catch (RuntimeException failure) {
            auditDetails = Map.of("code", "SIGNING_RECONCILIATION_PASS_FAILED");
        }
        try {
            audit.record("SIGNING_RECONCILIATION_PASS", "system", auditDetails);
        } catch (RuntimeException ignored) {
            // The pass remains bounded and future passes remain authoritative.
        } finally {
            if (!cancelled.get()) {
                scheduled = executor.schedule(this::runPass, configuration.idleInterval().toNanos(),
                        TimeUnit.NANOSECONDS);
            }
        }
    }

    @Override
    public void close() throws InterruptedException {
        stopScheduling();
        awaitStopped();
    }

    /* default */ void stopScheduling() {
        if (cancelled.compareAndSet(false, true)) {
            Future<?> current = scheduled;
            if (current != null) {
                current.cancel(true);
            }
            executor.shutdownNow();
        }
    }

    /* default */ void awaitStopped() throws InterruptedException {
        if (!cancelled.get()) {
            throw new IllegalStateException("Signing reconciliation worker is still accepting work");
        }
        if (!executor.awaitTermination(forcedShutdown.toNanos(), TimeUnit.NANOSECONDS)) {
            throw new IllegalStateException(
                    "Signing reconciliation shutdown timed out: code=SIGNING_RECONCILIATION_SHUTDOWN_TIMEOUT");
        }
    }

    /** Safe aggregate reconciliation audit boundary. */
    @FunctionalInterface
    /* default */
    interface AuditTransport {
        /** Records one aggregate event without record or provider details. */
        void record(String eventType, String principal, Map<String, String> details);
    }
}
