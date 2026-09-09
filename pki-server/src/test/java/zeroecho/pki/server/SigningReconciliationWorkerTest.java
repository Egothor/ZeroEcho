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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.SigningReconciliationContinuation;
import zeroecho.pki.application.SigningReconciliationRequest;
import zeroecho.pki.application.SigningReconciliationResult;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.RevocationTransitionFeed;

final class SigningReconciliationWorkerTest {

    @Test
    void schedulingPredicatesUseOnlyApprovedContinuationAndProjectionState() {
        SigningReconciliationContinuation activeWrapped = new SigningReconciliationContinuation(
                Optional.of("z"), Optional.of("z"), Optional.of("a"), true);
        SigningReconciliationResult wrappedEnd = new SigningReconciliationResult(
                activeWrapped, 1, 1, 0, 0, true);
        SigningReconciliationResult deferred = new SigningReconciliationResult(
                SigningReconciliationContinuation.start(), 1, 1, 1, 1, false);

        assertTrue(SigningReconciliationWorker.signingImmediate(wrappedEnd));
        assertFalse(SigningReconciliationWorker.signingImmediate(deferred));
        assertTrue(SigningReconciliationWorker.auditImmediate(projectionResult(false, false, Optional.empty())));
        assertFalse(SigningReconciliationWorker.auditImmediate(projectionResult(true, false,
                Optional.of(Instant.parse("2026-08-05T00:00:05Z")))));
        assertFalse(SigningReconciliationWorker.auditImmediate(projectionResult(false, true, Optional.empty())));
    }

    @Test
    void nextDelayHonorsWakeAndAuditDueTime() {
        SigningReconciliationWorker worker = new SigningReconciliationWorker(session((method, arguments) -> null),
                (type, principal, details) -> { }, emptyProjection(), configuration(Duration.ofSeconds(30)),
                Duration.ofSeconds(1), fixedClock());
        Instant due = Instant.parse("2026-08-05T00:00:05Z");

        assertEquals(Duration.ofSeconds(5), worker.nextDelay(new SigningReconciliationWorker.PassHints(
                false, false, Optional.of(due), false), false));
        assertEquals(Duration.ZERO, worker.nextDelay(new SigningReconciliationWorker.PassHints(
                false, false, Optional.of(due), false), true));
        assertEquals(Duration.ZERO, worker.nextDelay(new SigningReconciliationWorker.PassHints(
                true, false, Optional.of(due), false), false));
        assertEquals(Duration.ofSeconds(30), worker.nextDelay(new SigningReconciliationWorker.PassHints(
                false, false, Optional.of(due), true), true));
    }

    @Test
    void timeoutStopsSchedulingAndNeverClosesSessionUnderViolatingCall() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        AtomicBoolean release = new AtomicBoolean();
        AtomicInteger calls = new AtomicInteger();
        AtomicInteger closes = new AtomicInteger();
        PkiSession session = session((method, arguments) -> {
            if ("reconcileSigning".equals(method)) {
                calls.incrementAndGet();
                entered.countDown();
                while (!release.get()) {
                    try {
                        Thread.sleep(1L);
                    } catch (InterruptedException ignored) {
                        // Deliberately violates cooperative cancellation for this lifecycle test.
                    }
                }
                return emptyResult();
            }
            if ("close".equals(method)) {
                closes.incrementAndGet();
            }
            return null;
        });
        SigningReconciliationWorker worker = new SigningReconciliationWorker(session, (type, principal, details) -> {
            // Aggregate audit is irrelevant to the blocking lifecycle assertion.
        }, emptyProjection(), configuration(Duration.ofSeconds(1)), Duration.ofMillis(20), fixedClock());
        worker.start();
        assertTrue(entered.await(5, TimeUnit.SECONDS));

        worker.stopScheduling();
        IllegalStateException timeout = assertThrows(IllegalStateException.class, worker::awaitStopped);
        assertTrue(timeout.getMessage().contains("SIGNING_RECONCILIATION_SHUTDOWN_TIMEOUT"));
        assertEquals(1, calls.get());
        assertEquals(0, closes.get());

        release.set(true);
        worker.awaitStopped();
        assertEquals(1, calls.get());
        assertEquals(0, closes.get());
    }

    @Test
    void subMillisecondIdleIntervalSelfSchedulesWithoutOverlap() throws Exception {
        AtomicInteger active = new AtomicInteger();
        AtomicInteger maximumActive = new AtomicInteger();
        CountDownLatch twoPasses = new CountDownLatch(2);
        PkiSession session = session((method, arguments) -> {
            if ("reconcileSigning".equals(method)) {
                int current = active.incrementAndGet();
                maximumActive.accumulateAndGet(current, Math::max);
                twoPasses.countDown();
                active.decrementAndGet();
                return emptyResult();
            }
            return null;
        });
        SigningReconciliationWorker worker = new SigningReconciliationWorker(session, (type, principal, details) -> {
            // Safe aggregate event accepted.
        }, emptyProjection(), configuration(Duration.ofNanos(1)), Duration.ofSeconds(1), fixedClock());
        worker.start();
        assertTrue(twoPasses.await(5, TimeUnit.SECONDS));
        worker.close();
        assertEquals(1, maximumActive.get());
    }

    @Test
    void callbackStormDuringPassProducesOneNonoverlappingFollowup() throws Exception {
        CountDownLatch firstEntered = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        CountDownLatch twoPasses = new CountDownLatch(2);
        AtomicInteger calls = new AtomicInteger();
        AtomicInteger active = new AtomicInteger();
        AtomicInteger maximumActive = new AtomicInteger();
        AtomicReference<Runnable> wake = new AtomicReference<>();
        PkiSession session = session((method, arguments) -> {
            if ("registerSigningAdvisoryWake".equals(method)) {
                wake.set((Runnable) arguments[0]);
                return (AutoCloseable) () -> wake.set(null);
            }
            if ("reconcileSigning".equals(method)) {
                int current = active.incrementAndGet();
                maximumActive.accumulateAndGet(current, Math::max);
                int call = calls.incrementAndGet();
                twoPasses.countDown();
                if (call == 1) {
                    firstEntered.countDown();
                    releaseFirst.await();
                }
                active.decrementAndGet();
                return emptyResult();
            }
            return null;
        });
        SigningReconciliationWorker worker = new SigningReconciliationWorker(session,
                (type, principal, details) -> { }, emptyProjection(), configuration(Duration.ofSeconds(30)),
                Duration.ofSeconds(1), fixedClock());
        worker.start();
        assertTrue(firstEntered.await(1, TimeUnit.SECONDS));

        Runnable callback = wake.get();
        for (int index = 0; index < 10_000; index++) {
            callback.run();
        }
        releaseFirst.countDown();
        assertTrue(twoPasses.await(1, TimeUnit.SECONDS));
        worker.close();

        assertEquals(2, calls.get());
        assertEquals(1, maximumActive.get());
    }

    @Test
    void realmWakeStormCoalescesAndListenerIsReleasedOnStop() throws Exception {
        CountDownLatch firstEntered = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        CountDownLatch twoPasses = new CountDownLatch(2);
        AtomicInteger calls = new AtomicInteger();
        RealmReconciliationWakeSignal signal = new RealmReconciliationWakeSignal();
        PkiSession session = session((method, arguments) -> {
            if ("registerSigningAdvisoryWake".equals(method)) {
                return (AutoCloseable) () -> { };
            }
            if ("reconcileSigning".equals(method)) {
                int call = calls.incrementAndGet();
                twoPasses.countDown();
                if (call == 1) {
                    firstEntered.countDown();
                    releaseFirst.await();
                }
                return emptyResult();
            }
            return null;
        });
        SigningReconciliationWorker worker = new SigningReconciliationWorker(session,
                (type, principal, details) -> { }, emptyProjection(), signal,
                configuration(Duration.ofSeconds(30)), Duration.ofSeconds(1), fixedClock());
        worker.start();
        assertTrue(firstEntered.await(1, TimeUnit.SECONDS));

        for (int index = 0; index < 10_000; index++) {
            signal.signal();
        }
        releaseFirst.countDown();
        assertTrue(twoPasses.await(1, TimeUnit.SECONDS));
        worker.close();

        assertEquals(2, calls.get());
        try (AutoCloseable ignored = signal.register(() -> { })) {
            // Worker shutdown released the realm's sole lifecycle listener.
        }
    }

    @Test
    void realmRegistrationFailureRollsBackSigningRegistration() {
        AtomicInteger signingCloses = new AtomicInteger();
        RealmReconciliationWakeSignal signal = new RealmReconciliationWakeSignal();
        PkiSession session = session((method, arguments) -> {
            if ("registerSigningAdvisoryWake".equals(method)) {
                return (AutoCloseable) signingCloses::incrementAndGet;
            }
            return null;
        });
        SigningReconciliationWorker worker = new SigningReconciliationWorker(session,
                (type, principal, details) -> { }, emptyProjection(), signal,
                configuration(Duration.ofSeconds(30)), Duration.ofSeconds(1), fixedClock());

        try (AutoCloseable ignored = signal.register(() -> { })) {
            assertThrows(IllegalStateException.class, worker::start);
        } catch (Exception unexpected) {
            throw new AssertionError(unexpected);
        }
        assertEquals(1, signingCloses.get());
    }

    @Test
    void auditBacklogRunsImmediatelyAndFutureBackoffIsSkippedDuringSigningContinuation() throws Exception {
        CountDownLatch auditBacklogConsumed = new CountDownLatch(2);
        AtomicInteger auditCalls = new AtomicInteger();
        PkiSession idleSession = session((method, arguments) ->
                "reconcileSigning".equals(method) ? emptyResult() : null);
        SigningReconciliationWorker backlogWorker = new SigningReconciliationWorker(idleSession,
                (type, principal, details) -> { }, (maximumRecords, maximumSinkCalls, cancellation) -> {
                    int call = auditCalls.incrementAndGet();
                    auditBacklogConsumed.countDown();
                    return projectionResult(false, call >= 2, Optional.empty());
                }, configuration(Duration.ofSeconds(30)), Duration.ofSeconds(1), fixedClock());
        backlogWorker.start();
        assertTrue(auditBacklogConsumed.await(1, TimeUnit.SECONDS));
        backlogWorker.close();

        CountDownLatch signingContinued = new CountDownLatch(3);
        AtomicInteger backedOffAuditCalls = new AtomicInteger();
        SigningReconciliationContinuation active = new SigningReconciliationContinuation(
                Optional.of("a"), Optional.of("z"), Optional.empty(), false);
        SigningReconciliationResult continuing = new SigningReconciliationResult(active, 1, 1, 0, 0, false);
        PkiSession activeSession = session((method, arguments) -> {
            if ("reconcileSigning".equals(method)) {
                signingContinued.countDown();
                return continuing;
            }
            return null;
        });
        SigningReconciliationWorker backoffWorker = new SigningReconciliationWorker(activeSession,
                (type, principal, details) -> { }, (maximumRecords, maximumSinkCalls, cancellation) -> {
                    backedOffAuditCalls.incrementAndGet();
                    return projectionResult(true, false,
                            Optional.of(Instant.parse("2026-08-05T00:00:05Z")));
                }, configuration(Duration.ofSeconds(30)), Duration.ofSeconds(1), fixedClock());
        backoffWorker.start();
        assertTrue(signingContinued.await(1, TimeUnit.SECONDS));
        backoffWorker.close();
        assertEquals(1, backedOffAuditCalls.get());
    }

    @Test
    void missedCallbackStillConvergesOnPeriodicPass() throws Exception {
        CountDownLatch twoPasses = new CountDownLatch(2);
        AtomicInteger calls = new AtomicInteger();
        PkiSession session = session((method, arguments) -> {
            if ("registerSigningAdvisoryWake".equals(method)) {
                return (AutoCloseable) () -> { };
            }
            if ("reconcileSigning".equals(method)) {
                calls.incrementAndGet();
                twoPasses.countDown();
                return emptyResult();
            }
            return null;
        });
        SigningReconciliationWorker worker = new SigningReconciliationWorker(session,
                (type, principal, details) -> { }, emptyProjection(), configuration(Duration.ofMillis(1)),
                Duration.ofSeconds(1), fixedClock());
        worker.start();

        assertTrue(twoPasses.await(1, TimeUnit.SECONDS));
        worker.close();
        assertTrue(calls.get() >= 2);
    }

    @Test
    void bothPhasesShareOneThreadAndReceiveIndependentBudgets() throws Exception {
        CountDownLatch projected = new CountDownLatch(1);
        AtomicReference<Thread> signingThread = new AtomicReference<>();
        AtomicReference<Thread> projectionThread = new AtomicReference<>();
        AtomicReference<SigningReconciliationRequest> request = new AtomicReference<>();
        AtomicInteger projectionRecords = new AtomicInteger();
        AtomicInteger projectionSinkCalls = new AtomicInteger();
        PkiSession session = session((method, arguments) -> {
            if ("reconcileSigning".equals(method)) {
                signingThread.set(Thread.currentThread());
                request.set((SigningReconciliationRequest) arguments[0]);
                return emptyResult();
            }
            return null;
        });
        PkiServerConfiguration.SigningReconciliation configuration =
                new PkiServerConfiguration.SigningReconciliation(true, 7, 3, Duration.ofSeconds(1),
                        Duration.ofMillis(100), Duration.ofSeconds(30));
        SigningReconciliationWorker worker = new SigningReconciliationWorker(session,
                (type, principal, details) -> { }, (maximumRecords, maximumSinkCalls, cancellation) -> {
                    projectionThread.set(Thread.currentThread());
                    projectionRecords.set(maximumRecords);
                    projectionSinkCalls.set(maximumSinkCalls);
                    projected.countDown();
                    return emptyProjectionResult();
                }, configuration, Duration.ofSeconds(1), fixedClock());

        worker.start();
        assertTrue(projected.await(1, TimeUnit.SECONDS));
        worker.close();

        assertTrue(signingThread.get() == projectionThread.get());
        assertEquals("zeroecho-signing-reconciliation", projectionThread.get().getName());
        assertEquals(7, request.get().maximumRecords());
        assertEquals(3, request.get().maximumProviderCalls());
        assertEquals(7, projectionRecords.get());
        assertEquals(3, projectionSinkCalls.get());
    }

    @Test
    void signingFailureDoesNotSuppressAuditProjection() throws Exception {
        CountDownLatch projected = new CountDownLatch(1);
        PkiSession session = session((method, arguments) -> {
            if ("reconcileSigning".equals(method)) {
                throw new IllegalStateException("signing test failure");
            }
            return null;
        });
        SigningReconciliationWorker worker = new SigningReconciliationWorker(session,
                (type, principal, details) -> { }, (maximumRecords, maximumSinkCalls, cancellation) -> {
                    projected.countDown();
                    return emptyProjectionResult();
                }, configuration(Duration.ofSeconds(30)), Duration.ofSeconds(1), fixedClock());

        worker.start();
        assertTrue(projected.await(1, TimeUnit.SECONDS));
        worker.close();
    }

    @Test
    void projectionFailureDoesNotSuppressFutureSigningPasses() throws Exception {
        CountDownLatch twoSigningPasses = new CountDownLatch(2);
        PkiSession session = session((method, arguments) -> {
            if ("reconcileSigning".equals(method)) {
                twoSigningPasses.countDown();
                return emptyResult();
            }
            return null;
        });
        SigningReconciliationWorker worker = new SigningReconciliationWorker(session,
                (type, principal, details) -> { }, (maximumRecords, maximumSinkCalls, cancellation) -> {
                    throw new IllegalStateException("projection test failure");
                }, configuration(Duration.ofMillis(1)), Duration.ofSeconds(1), fixedClock());

        worker.start();
        assertTrue(twoSigningPasses.await(1, TimeUnit.SECONDS));
        worker.close();
    }

    @Test
    void shutdownCancellationReachesActiveProjection() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch returned = new CountDownLatch(1);
        PkiSession session = session((method, arguments) ->
                "reconcileSigning".equals(method) ? emptyResult() : null);
        SigningReconciliationWorker worker = new SigningReconciliationWorker(session,
                (type, principal, details) -> { }, (maximumRecords, maximumSinkCalls, cancellation) -> {
                    entered.countDown();
                    while (!cancellation.isCancelled()) {
                        Thread.onSpinWait();
                    }
                    returned.countDown();
                    return emptyProjectionResult();
                }, configuration(Duration.ofSeconds(30)), Duration.ofSeconds(1), fixedClock());

        worker.start();
        assertTrue(entered.await(1, TimeUnit.SECONDS));
        worker.stopScheduling();
        worker.awaitStopped();

        assertTrue(returned.await(1, TimeUnit.SECONDS));
    }

    @Test
    void clockFailureOrDeadlineOverflowCannotSuppressProjectionOrLaterPass() throws Exception {
        assertClockFailureIsolated(failFirstClock(false));
        assertClockFailureIsolated(failFirstClock(true));
    }

    private static PkiServerConfiguration.SigningReconciliation configuration(Duration idle) {
        return new PkiServerConfiguration.SigningReconciliation(true, 1, 1, Duration.ofSeconds(1),
                Duration.ofMillis(100), idle);
    }

    private static SigningReconciliationResult emptyResult() {
        return new SigningReconciliationResult(SigningReconciliationContinuation.start(), 0, 0, 0, 0, true);
    }

    private static SigningReconciliationWorker.AuditProjection emptyProjection() {
        return (maximumRecords, maximumSinkCalls, cancellation) -> emptyProjectionResult();
    }

    private static void assertClockFailureIsolated(Clock clock) throws Exception {
        CountDownLatch projectedTwice = new CountDownLatch(2);
        CountDownLatch signingSucceeded = new CountDownLatch(1);
        PkiSession session = session((method, arguments) -> {
            if ("reconcileSigning".equals(method)) {
                signingSucceeded.countDown();
                return emptyResult();
            }
            return null;
        });
        SigningReconciliationWorker worker = new SigningReconciliationWorker(session,
                (type, principal, details) -> { }, (maximumRecords, maximumSinkCalls, cancellation) -> {
                    projectedTwice.countDown();
                    return emptyProjectionResult();
                }, configuration(Duration.ofMillis(1)), Duration.ofSeconds(1), clock);
        worker.start();
        assertTrue(projectedTwice.await(1, TimeUnit.SECONDS));
        assertTrue(signingSucceeded.await(1, TimeUnit.SECONDS));
        worker.close();
    }

    private static Clock failFirstClock(boolean overflow) {
        return new Clock() {
            private final AtomicBoolean first = new AtomicBoolean(true);
            @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(java.time.ZoneId zone) { return this; }
            @Override public Instant instant() {
                if (!first.getAndSet(false)) {
                    return Instant.parse("2026-08-05T00:00:00Z");
                }
                if (overflow) {
                    return Instant.MAX;
                }
                throw new IllegalStateException("test clock unavailable");
            }
        };
    }

    private static RevocationAuditProjector.PassResult emptyProjectionResult() {
        return projectionResult(false, true, Optional.empty());
    }

    private static RevocationAuditProjector.PassResult projectionResult(boolean blocked, boolean endReached,
            Optional<Instant> nextEligible) {
        RevocationTransitionFeed.HighWatermark head = new RevocationTransitionFeed.HighWatermark(
                new MetadataStoreId("abcdefabcdefabcdefabcdefabcdefab"), 0L, "0".repeat(64));
        return new RevocationAuditProjector.PassResult(0, 0, 0, endReached, blocked, nextEligible, head);
    }

    private static Clock fixedClock() {
        return Clock.fixed(Instant.parse("2026-08-05T00:00:00Z"), ZoneOffset.UTC);
    }

    private static PkiSession session(SessionInvocation invocation) {
        return (PkiSession) Proxy.newProxyInstance(PkiSession.class.getClassLoader(), new Class<?>[] { PkiSession.class },
                (proxy, method, arguments) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        return switch (method.getName()) {
                            case "toString" -> "test-pki-session";
                            case "hashCode" -> System.identityHashCode(proxy);
                            case "equals" -> proxy == arguments[0];
                            default -> null;
                        };
                    }
                    Object result = invocation.invoke(method.getName(), arguments);
                    if (result == null && "registerSigningAdvisoryWake".equals(method.getName())) {
                        return (AutoCloseable) () -> { };
                    }
                    return result;
                });
    }

    @FunctionalInterface
    private interface SessionInvocation {
        Object invoke(String method, Object[] arguments) throws Throwable;
    }
}
