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

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.LockSupport;

import zeroecho.pki.application.SigningReconciliationContinuation;
import zeroecho.pki.application.SigningReconciliationRequest;
import zeroecho.pki.application.SigningReconciliationResult;
import zeroecho.pki.application.PkiSession;

/** Single-threaded, self-rescheduling signing recovery and revocation-audit owner for one realm. */
@SuppressWarnings({ "PMD.DoNotUseThreads", "PMD.AvoidUsingVolatile", "PMD.CommentDefaultAccessModifier" })
final class SigningReconciliationWorker implements AutoCloseable {
    private final PkiSession session;
    private final AuditTransport audit;
    private final AuditProjection auditProjection;
    private final EvidenceProjection evidenceProjection;
    private final RealmReconciliationWakeSignal realmWake;
    private final PkiServerConfiguration.SigningReconciliation configuration;
    private final Duration forcedShutdown;
    private final Clock clock;
    private final Thread workerThread;
    private final AtomicBoolean cancelled = new AtomicBoolean();
    private final AtomicBoolean wakeRequested = new AtomicBoolean();
    private SigningReconciliationContinuation continuation = SigningReconciliationContinuation.start();
    private Optional<Instant> auditNextEligible = Optional.empty();
    private volatile AutoCloseable signingWakeRegistration;
    private volatile AutoCloseable realmWakeRegistration;
    private volatile boolean started;

    /* default */ SigningReconciliationWorker(ServerRealmContext realm,
            PkiServerConfiguration.SigningReconciliation configuration, Duration forcedShutdown, Clock clock) {
        this(Objects.requireNonNull(realm, "realm").session(), realm::auditTransport,
                realm.revocationAuditProjector()::project, realm::runEvidenceProjections,
                realm.reconciliationWakeSignal(), configuration, forcedShutdown, clock);
    }

    /* default */ SigningReconciliationWorker(PkiSession session, AuditTransport audit, AuditProjection auditProjection,
            PkiServerConfiguration.SigningReconciliation configuration, Duration forcedShutdown, Clock clock) {
        this(session, audit, auditProjection, (records, sinkCalls, cancellation) -> EvidenceHint.idle(),
                new RealmReconciliationWakeSignal(), configuration, forcedShutdown, clock);
    }

    /* default */ SigningReconciliationWorker(PkiSession session, AuditTransport audit, AuditProjection auditProjection,
            RealmReconciliationWakeSignal realmWake, PkiServerConfiguration.SigningReconciliation configuration,
            Duration forcedShutdown, Clock clock) {
        this(session, audit, auditProjection, (records, sinkCalls, cancellation) -> EvidenceHint.idle(),
                realmWake, configuration, forcedShutdown, clock);
    }

    /* default */ SigningReconciliationWorker(PkiSession session, AuditTransport audit, AuditProjection auditProjection,
            EvidenceProjection evidenceProjection, RealmReconciliationWakeSignal realmWake,
            PkiServerConfiguration.SigningReconciliation configuration, Duration forcedShutdown, Clock clock) {
        this.session = Objects.requireNonNull(session, "session");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.auditProjection = Objects.requireNonNull(auditProjection, "auditProjection");
        this.evidenceProjection = Objects.requireNonNull(evidenceProjection, "evidenceProjection");
        this.realmWake = Objects.requireNonNull(realmWake, "realmWake");
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.forcedShutdown = Objects.requireNonNull(forcedShutdown, "forcedShutdown");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.workerThread = new Thread(this::runLoop, "zeroecho-signing-reconciliation");
        this.workerThread.setDaemon(true);
    }

    @SuppressWarnings({ "PMD.CloseResource", "PMD.AvoidCatchingGenericException" })
    /* default */ void start() {
        if (cancelled.get() || started) {
            throw new IllegalStateException("Signing reconciliation worker cannot start");
        }
        started = true;
        AutoCloseable signingRegistration = null;
        AutoCloseable realmRegistration = null;
        try {
            signingRegistration = Objects.requireNonNull(session.registerSigningAdvisoryWake(this::wake),
                    "signing wake registration");
            realmRegistration = realmWake.register(this::wake);
            signingWakeRegistration = signingRegistration;
            realmWakeRegistration = realmRegistration;
            workerThread.start();
        } catch (RuntimeException | Error failure) {
            closeRegistration(realmRegistration);
            closeRegistration(signingRegistration);
            signingWakeRegistration = null;
            realmWakeRegistration = null;
            throw failure;
        }
    }

    private void wake() {
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

    @SuppressWarnings("PMD.AvoidCatchingGenericException") // A faulty clock degrades scheduling to the idle interval.
    private PassHints runPass() {
        if (cancelled.get()) {
            return PassHints.idle();
        }
        SigningHint signing = runSigningPhase();
        if (cancelled.get()) {
            return new PassHints(signing.immediate(), false, auditNextEligible, signing.clockFailed());
        }
        boolean clockFailed = signing.clockFailed();
        boolean skipAudit = false;
        if (signing.immediate() && auditNextEligible.isPresent()) {
            try {
                skipAudit = auditNextEligible.orElseThrow().isAfter(clock.instant());
            } catch (RuntimeException failure) {
                clockFailed = true;
            }
        }
        AuditHint auditHint = skipAudit ? new AuditHint(false, auditNextEligible) : runAuditProjectionPhase();
        EvidenceHint evidenceHint = runEvidenceProjectionPhase();
        boolean immediate = auditHint.immediate() || evidenceHint.immediate();
        Optional<Instant> nextEligible = earliest(auditHint.nextEligible(), evidenceHint.nextEligible());
        return new PassHints(signing.immediate(), immediate, nextEligible, clockFailed);
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException") // A projection failure must not stop scheduling.
    private EvidenceHint runEvidenceProjectionPhase() {
        try {
            return evidenceProjection.run(configuration.maximumRecords(), configuration.maximumProviderCalls(),
                    cancelled::get);
        } catch (RuntimeException failure) {
            recordAggregate("EVIDENCE_PROJECTION_PASS", Map.of("code", "EVIDENCE_PROJECTION_PASS_FAILED"));
            return EvidenceHint.idle();
        }
    }

    private static Optional<Instant> earliest(Optional<Instant> first, Optional<Instant> second) {
        if (first.isEmpty()) {
            return second;
        }
        if (second.isEmpty()) {
            return first;
        }
        return Optional.of(first.orElseThrow().isBefore(second.orElseThrow())
                ? first.orElseThrow() : second.orElseThrow());
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException") // A phase failure must not suppress audit projection.
    private SigningHint runSigningPhase() {
        Map<String, String> auditDetails;
        boolean deadlineCreated = false;
        boolean immediate = false;
        try {
            Instant deadline = clock.instant().plus(configuration.passTimeout());
            deadlineCreated = true;
            SigningReconciliationResult result = session.reconcileSigning(new SigningReconciliationRequest(
                    continuation, configuration.maximumRecords(),
                    configuration.maximumProviderCalls(), deadline, configuration.providerCallTimeout(),
                    cancelled::get));
            continuation = result.continuation();
            auditDetails = Map.of(
                    "code", result.retryable() == 0 ? "SIGNING_RECONCILIATION_OK" : "SIGNING_RECONCILIATION_RETRY",
                    "examined", Integer.toString(result.examined()),
                    "progressed", Integer.toString(result.progressed()),
                    "unresolved", Integer.toString(result.unresolved()),
                    "retryable", Integer.toString(result.retryable()),
                    "endReached", Boolean.toString(result.endReached()));
            immediate = signingImmediate(result);
        } catch (RuntimeException failure) {
            auditDetails = Map.of("code", "SIGNING_RECONCILIATION_PASS_FAILED");
        }
        recordAggregate("SIGNING_RECONCILIATION_PASS", auditDetails);
        return new SigningHint(immediate, !deadlineCreated);
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException") // Projector and I/O failures must not stop scheduling.
    private AuditHint runAuditProjectionPhase() {
        Map<String, String> auditDetails;
        AuditHint hint;
        try {
            RevocationAuditProjector.PassResult result = auditProjection.project(configuration.maximumRecords(),
                    configuration.maximumProviderCalls(), cancelled::get);
            auditNextEligible = result.nextEligible();
            hint = new AuditHint(auditImmediate(result), auditNextEligible);
            auditDetails = Map.of(
                    "code", result.blocked() ? "REVOCATION_AUDIT_PROJECTION_BLOCKED"
                            : "REVOCATION_AUDIT_PROJECTION_OK",
                    "examined", Integer.toString(result.examined()),
                    "sinkCalls", Integer.toString(result.sinkCalls()),
                    "advanced", Integer.toString(result.advanced()),
                    "endReached", Boolean.toString(result.endReached()),
                    "blocked", Boolean.toString(result.blocked()));
        } catch (IOException | RuntimeException failure) {
            auditNextEligible = Optional.empty();
            hint = new AuditHint(false, auditNextEligible);
            auditDetails = Map.of("code", "REVOCATION_AUDIT_PROJECTION_PASS_FAILED");
        }
        recordAggregate("REVOCATION_AUDIT_PROJECTION_PASS", auditDetails);
        return hint;
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException") // A faulty clock degrades scheduling to the idle interval.
    /* default */ Duration nextDelay(PassHints hints, boolean coalescedWake) {
        if (hints.clockFailed()) {
            return configuration.idleInterval();
        }
        if (hints.signingImmediate() || hints.auditImmediate() || coalescedWake) {
            return Duration.ZERO;
        }
        if (hints.auditNextEligible().isEmpty()) {
            return configuration.idleInterval();
        }
        try {
            Duration due = Duration.between(clock.instant(), hints.auditNextEligible().orElseThrow());
            if (due.isNegative() || due.isZero()) {
                return Duration.ZERO;
            }
            return due.compareTo(configuration.idleInterval()) < 0 ? due : configuration.idleInterval();
        } catch (RuntimeException failure) {
            return configuration.idleInterval();
        }
    }

    /* default */ static boolean signingImmediate(SigningReconciliationResult result) {
        return Objects.requireNonNull(result, "result").continuation().cycleHighWatermark().isPresent();
    }

    /* default */ static boolean auditImmediate(RevocationAuditProjector.PassResult result) {
        RevocationAuditProjector.PassResult exact = Objects.requireNonNull(result, "result");
        return !exact.blocked() && !exact.endReached();
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException") // Aggregate telemetry is explicitly best effort.
    private void recordAggregate(String eventType, Map<String, String> auditDetails) {
        try {
            audit.record(eventType, "system", auditDetails);
        } catch (RuntimeException ignored) {
            // Each phase and future scheduled passes remain independent of aggregate telemetry.
        }
    }

    @Override
    public void close() throws InterruptedException {
        stopScheduling();
        awaitStopped();
    }

    /* default */ void stopScheduling() {
        if (cancelled.compareAndSet(false, true)) {
            closeRegistration(realmWakeRegistration);
            closeRegistration(signingWakeRegistration);
            workerThread.interrupt();
            LockSupport.unpark(workerThread);
        }
    }

    private static void closeRegistration(AutoCloseable registration) {
        if (registration == null) {
            return;
        }
        try {
            registration.close();
        } catch (Exception ignored) {
            // Advisory registration close is local and idempotent; rollback or shutdown proceeds.
        }
    }

    /* default */ void awaitStopped() throws InterruptedException {
        if (!cancelled.get()) {
            throw new IllegalStateException("Signing reconciliation worker is still accepting work");
        }
        workerThread.join(forcedShutdown.toMillis(), forcedShutdown.toNanosPart() % 1_000_000);
        if (workerThread.isAlive()) {
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

    /** Synchronous thread-confined authoritative-revocation audit projection boundary. */
    @FunctionalInterface
    /* default */
    interface AuditProjection {
        /** Projects one independently bounded pass on the worker thread. */
        RevocationAuditProjector.PassResult project(int maximumRecords, int maximumSinkCalls,
                zeroecho.core.io.CancellationSignal cancellation) throws IOException;
    }

    /** Synchronous thread-confined boundary for the generic per-family success-evidence projections. */
    @FunctionalInterface
    /* default */
    interface EvidenceProjection {
        /** Runs one bounded pass over every registered evidence projector on the worker thread. */
        EvidenceHint run(int maximumRecords, int maximumSinkCalls,
                zeroecho.core.io.CancellationSignal cancellation);
    }

    /** Evidence-projection scheduling classification. */
    /* default */ record EvidenceHint(boolean immediate, Optional<Instant> nextEligible) {
        /* default */ EvidenceHint {
            nextEligible = Objects.requireNonNull(nextEligible, "nextEligible");
        }
        private static EvidenceHint idle() { return new EvidenceHint(false, Optional.empty()); }
    }

    /** Work-conserving scheduling hints from one full two-phase pass. */
    /* default */ record PassHints(boolean signingImmediate, boolean auditImmediate,
            Optional<Instant> auditNextEligible, boolean clockFailed) {
        PassHints {
            auditNextEligible = Objects.requireNonNull(auditNextEligible, "auditNextEligible");
        }
        private static PassHints idle() { return new PassHints(false, false, Optional.empty(), false); }
    }

    /** Signing phase scheduling classification. */
    private record SigningHint(boolean immediate, boolean clockFailed) { }

    /** Audit phase scheduling classification. */
    private record AuditHint(boolean immediate, Optional<Instant> nextEligible) {
        private AuditHint { nextEligible = Objects.requireNonNull(nextEligible, "nextEligible"); }
    }
}
