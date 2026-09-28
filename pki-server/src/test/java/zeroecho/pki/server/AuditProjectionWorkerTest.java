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

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import org.junit.jupiter.api.Test;

import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.RevocationTransitionFeed;

final class AuditProjectionWorkerTest {
    @Test
    void onlyUnblockedBacklogRequestsImmediateContinuation() {
        assertTrue(AuditProjectionWorker.auditImmediate(result(false, false, Optional.empty())));
        assertFalse(AuditProjectionWorker.auditImmediate(result(true, false, Optional.of(now().plusSeconds(5)))));
        assertFalse(AuditProjectionWorker.auditImmediate(emptyResult()));
    }

    @Test
    void delayUsesWakeBacklogRetryDueAndIdleCeiling() throws Exception {
        try (AuditProjectionWorker worker = worker(emptyProjection(), Duration.ofSeconds(30), fixedClock())) {
            assertEquals(Duration.ofSeconds(5), worker.nextDelay(hints(false, now().plusSeconds(5)), false));
            assertEquals(Duration.ofSeconds(30), worker.nextDelay(hints(false, now().plusSeconds(60)), false));
            assertEquals(Duration.ZERO, worker.nextDelay(hints(false, now().minusSeconds(1)), false));
            assertEquals(Duration.ZERO, worker.nextDelay(hints(false, now()), false));
            assertEquals(Duration.ZERO, worker.nextDelay(hints(true, now().plusSeconds(5)), false));
            assertEquals(Duration.ZERO, worker.nextDelay(hints(false, now().plusSeconds(5)), true));
            assertEquals(Duration.ofSeconds(30), worker.nextDelay(
                    new AuditProjectionWorker.PassHints(false, Optional.empty()), false));
        }
    }

    @Test
    void realmWakeStormCoalescesWithoutOverlapAndReleasesListener() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch second = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        AtomicInteger active = new AtomicInteger();
        AtomicInteger maximumActive = new AtomicInteger();
        RealmReconciliationWakeSignal signal = new RealmReconciliationWakeSignal();
        AuditProjectionWorker worker = new AuditProjectionWorker((type, principal, details) -> { },
                (records, sinks, cancellation) -> {
                    maximumActive.accumulateAndGet(active.incrementAndGet(), Math::max);
                    try {
                        if (calls.incrementAndGet() == 1) {
                            entered.countDown();
                            await(release);
                        } else {
                            second.countDown();
                        }
                        return emptyResult();
                    } finally {
                        active.decrementAndGet();
                    }
                }, signal, configuration(Duration.ofSeconds(30)), Duration.ofSeconds(1), fixedClock());
        try {
            worker.start();
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            for (int index = 0; index < 10_000; index++) signal.signal();
            release.countDown();
            assertTrue(second.await(5, TimeUnit.SECONDS));
        } finally {
            release.countDown();
            worker.close();
        }
        assertEquals(2, calls.get());
        assertEquals(1, maximumActive.get());
        try (AutoCloseable ignored = signal.register(() -> { })) {
            signal.signal();
            assertEquals(2, calls.get());
        }
    }

    @Test
    void failedRegistrationLeavesExistingListenerOwnedByItsRegistrant() throws Exception {
        RealmReconciliationWakeSignal signal = new RealmReconciliationWakeSignal();
        AtomicInteger existingWake = new AtomicInteger();
        try (AutoCloseable ignored = signal.register(existingWake::incrementAndGet);
                AuditProjectionWorker worker = new AuditProjectionWorker((type, principal, details) -> { },
                        emptyProjection(), signal, configuration(Duration.ofSeconds(30)),
                        Duration.ofSeconds(1), fixedClock())) {
            assertThrows(IllegalStateException.class, worker::start);
            worker.close();
            signal.signal();
            assertEquals(1, existingWake.get());
        }
    }

    @Test
    void auditBacklogRunsImmediately() throws Exception {
        CountDownLatch consumed = new CountDownLatch(2);
        AtomicInteger calls = new AtomicInteger();
        try (AuditProjectionWorker worker = worker((records, sinks, cancellation) -> {
            int call = calls.incrementAndGet();
            consumed.countDown();
            return result(false, call >= 2, Optional.empty());
        }, Duration.ofSeconds(30), fixedClock())) {
            worker.start();
            assertTrue(consumed.await(5, TimeUnit.SECONDS));
        }
        assertEquals(2, calls.get());
    }

    @Test
    void evidenceBacklogContinuesEvenWhileRevocationReportsFutureRetry() throws Exception {
        CountDownLatch consumed = new CountDownLatch(2);
        AtomicInteger revocationCalls = new AtomicInteger();
        AtomicInteger evidenceCalls = new AtomicInteger();
        try (AuditProjectionWorker worker = new AuditProjectionWorker((type, principal, details) -> { },
                (records, sinks, cancellation) -> {
                    revocationCalls.incrementAndGet();
                    return result(true, false, Optional.of(now().plusSeconds(60)));
                }, (records, sinks, cancellation) -> {
                    int call = evidenceCalls.incrementAndGet();
                    consumed.countDown();
                    return new AuditProjectionWorker.EvidenceHint(call < 2, Optional.empty());
                }, new RealmReconciliationWakeSignal(), configuration(Duration.ofSeconds(30)),
                Duration.ofSeconds(1), fixedClock())) {
            worker.start();
            assertTrue(consumed.await(5, TimeUnit.SECONDS));
        }
        assertEquals(2, evidenceCalls.get());
        assertEquals(2, revocationCalls.get());
    }

    @Test
    void pollingConvergesWithoutWakeWithSubMillisecondInterval() throws Exception {
        CountDownLatch twice = new CountDownLatch(2);
        AtomicInteger active = new AtomicInteger();
        AtomicInteger maximumActive = new AtomicInteger();
        try (AuditProjectionWorker worker = worker((records, sinks, cancellation) -> {
            maximumActive.accumulateAndGet(active.incrementAndGet(), Math::max);
            twice.countDown();
            active.decrementAndGet();
            return emptyResult();
        }, Duration.ofNanos(1), fixedClock())) {
            worker.start();
            assertTrue(twice.await(5, TimeUnit.SECONDS));
        }
        assertEquals(1, maximumActive.get());
    }

    @Test
    void projectionsShareOneDaemonThreadAndReceiveIndependentBudgets() throws Exception {
        CountDownLatch projected = new CountDownLatch(1);
        AtomicReference<Thread> auditThread = new AtomicReference<>();
        AtomicReference<Thread> evidenceThread = new AtomicReference<>();
        AtomicInteger auditRecords = new AtomicInteger();
        AtomicInteger auditSinks = new AtomicInteger();
        AtomicInteger evidenceRecords = new AtomicInteger();
        AtomicInteger evidenceSinks = new AtomicInteger();
        try (AuditProjectionWorker worker = new AuditProjectionWorker((type, principal, details) -> { },
                (records, sinks, cancellation) -> {
                    auditThread.set(Thread.currentThread());
                    auditRecords.set(records);
                    auditSinks.set(sinks);
                    return emptyResult();
                }, (records, sinks, cancellation) -> {
                    evidenceThread.set(Thread.currentThread());
                    evidenceRecords.set(records);
                    evidenceSinks.set(sinks);
                    projected.countDown();
                    return new AuditProjectionWorker.EvidenceHint(false, Optional.empty());
                }, new RealmReconciliationWakeSignal(),
                new PkiServerConfiguration.AuditProjection(7, 3, Duration.ofSeconds(30)),
                Duration.ofSeconds(1), fixedClock())) {
            worker.start();
            assertTrue(projected.await(5, TimeUnit.SECONDS));
        }
        assertSame(auditThread.get(), evidenceThread.get());
        assertEquals("zeroecho-audit-projection", auditThread.get().getName());
        assertTrue(auditThread.get().isDaemon());
        assertEquals(7, auditRecords.get());
        assertEquals(3, auditSinks.get());
        assertEquals(7, evidenceRecords.get());
        assertEquals(3, evidenceSinks.get());
    }

    @Test
    void projectionAndTelemetryFailuresDoNotSuppressOtherPhaseOrLaterPasses() throws Exception {
        CountDownLatch auditTwice = new CountDownLatch(2);
        CountDownLatch evidenceTwice = new CountDownLatch(2);
        try (AuditProjectionWorker worker = new AuditProjectionWorker((type, principal, details) -> {
            throw new IllegalStateException("test telemetry failure");
        }, (records, sinks, cancellation) -> {
            auditTwice.countDown();
            throw new IOException("test projection failure");
        }, (records, sinks, cancellation) -> {
            evidenceTwice.countDown();
            throw new IllegalStateException("test evidence failure");
        }, new RealmReconciliationWakeSignal(), configuration(Duration.ofMillis(1)),
                Duration.ofSeconds(1), fixedClock())) {
            worker.start();
            assertTrue(auditTwice.await(5, TimeUnit.SECONDS));
            assertTrue(evidenceTwice.await(5, TimeUnit.SECONDS));
        }
    }

    @Test
    void cancellationReachesActiveProjectionAndPreventsFollowingPhase() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        AtomicBoolean observedCancellation = new AtomicBoolean();
        AtomicInteger evidenceCalls = new AtomicInteger();
        try (AuditProjectionWorker worker = new AuditProjectionWorker((type, principal, details) -> { },
                (records, sinks, cancellation) -> {
                    entered.countDown();
                    while (!cancellation.isCancelled()) Thread.onSpinWait();
                    observedCancellation.set(true);
                    return emptyResult();
                }, (records, sinks, cancellation) -> {
                    evidenceCalls.incrementAndGet();
                    return new AuditProjectionWorker.EvidenceHint(false, Optional.empty());
                }, new RealmReconciliationWakeSignal(), configuration(Duration.ofSeconds(30)),
                Duration.ofSeconds(1), fixedClock())) {
            worker.start();
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            worker.stopScheduling();
            worker.awaitStopped();
        }
        assertTrue(observedCancellation.get());
        assertEquals(0, evidenceCalls.get());
    }

    @Test
    void noncooperativeProjectionTimesOutAndCloseCanBeRetried() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        AtomicBoolean release = new AtomicBoolean();
        AtomicInteger calls = new AtomicInteger();
        AuditProjectionWorker worker = new AuditProjectionWorker((type, principal, details) -> { },
                (records, sinks, cancellation) -> {
                    calls.incrementAndGet();
                    entered.countDown();
                    while (!release.get()) {
                        LockSupport.parkNanos(100_000L);
                        Thread.interrupted();
                    }
                    return emptyResult();
                }, configuration(Duration.ofSeconds(30)), Duration.ofMillis(20), fixedClock());
        try {
            worker.start();
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            IllegalStateException timeout = assertThrows(IllegalStateException.class, worker::close);
            assertTrue(timeout.getMessage().contains("AUDIT_PROJECTION_SHUTDOWN_TIMEOUT"));
            assertEquals(1, calls.get());
        } finally {
            release.set(true);
            worker.close();
        }
        worker.close();
        assertEquals(1, calls.get());
        assertThrows(IllegalStateException.class, worker::start);
    }

    @Test
    void clockFailureDegradesToPollingWithoutSuppressingProjection() throws Exception {
        AtomicInteger clockCalls = new AtomicInteger();
        Clock faulty = new Clock() {
            @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(ZoneId zone) { return this; }
            @Override public Instant instant() {
                clockCalls.incrementAndGet();
                throw new IllegalStateException("test clock unavailable");
            }
        };
        CountDownLatch twice = new CountDownLatch(2);
        try (AuditProjectionWorker worker = worker((records, sinks, cancellation) -> {
            twice.countDown();
            return result(true, false, Optional.of(now().plusSeconds(5)));
        }, Duration.ofMillis(1), faulty)) {
            assertEquals(Duration.ofMillis(1), worker.nextDelay(hints(false, now().plusSeconds(5)), false));
            worker.start();
            assertTrue(twice.await(5, TimeUnit.SECONDS));
        }
        assertTrue(clockCalls.get() >= 2);
    }

    private static AuditProjectionWorker worker(AuditProjectionWorker.AuditProjection projection,
            Duration idle, Clock clock) {
        return new AuditProjectionWorker((type, principal, details) -> { }, projection,
                configuration(idle), Duration.ofSeconds(1), clock);
    }

    private static PkiServerConfiguration.AuditProjection configuration(Duration idle) {
        return new PkiServerConfiguration.AuditProjection(1, 1, idle);
    }

    private static AuditProjectionWorker.PassHints hints(boolean immediate, Instant nextEligible) {
        return new AuditProjectionWorker.PassHints(immediate, Optional.of(nextEligible));
    }

    private static AuditProjectionWorker.AuditProjection emptyProjection() {
        return (records, sinks, cancellation) -> emptyResult();
    }

    private static RevocationAuditProjector.PassResult emptyResult() {
        return result(false, true, Optional.empty());
    }

    private static RevocationAuditProjector.PassResult result(boolean blocked, boolean endReached,
            Optional<Instant> nextEligible) {
        RevocationTransitionFeed.HighWatermark head = new RevocationTransitionFeed.HighWatermark(
                new MetadataStoreId("abcdefabcdefabcdefabcdefabcdefab"), 0L, "0".repeat(64));
        return new RevocationAuditProjector.PassResult(0, 0, 0, endReached, blocked, nextEligible, head);
    }

    private static Instant now() { return Instant.parse("2026-08-05T00:00:00Z"); }

    private static Clock fixedClock() { return Clock.fixed(now(), ZoneOffset.UTC); }

    private static void await(CountDownLatch latch) throws IOException {
        try {
            if (!latch.await(5, TimeUnit.SECONDS)) throw new IOException("Test latch timed out");
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new IOException("Test latch interrupted", failure);
        }
    }
}
