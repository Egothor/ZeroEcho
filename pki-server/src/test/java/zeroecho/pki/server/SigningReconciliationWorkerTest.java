/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

import org.junit.jupiter.api.Test;

import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.SigningReconciliationResult;

final class SigningReconciliationWorkerTest {

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
        }, configuration(Duration.ofSeconds(1)), Duration.ofMillis(20), fixedClock());
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
        }, configuration(Duration.ofNanos(1)), Duration.ofSeconds(1), fixedClock());
        worker.start();
        assertTrue(twoPasses.await(5, TimeUnit.SECONDS));
        worker.close();
        assertEquals(1, maximumActive.get());
    }

    private static PkiServerConfiguration.SigningReconciliation configuration(Duration idle) {
        return new PkiServerConfiguration.SigningReconciliation(true, 1, 1, Duration.ofSeconds(1),
                Duration.ofMillis(100), idle);
    }

    private static SigningReconciliationResult emptyResult() {
        return new SigningReconciliationResult(Optional.empty(), 0, 0, 0, 0, true);
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
                    return invocation.invoke(method.getName(), arguments);
                });
    }

    @FunctionalInterface
    private interface SessionInvocation {
        Object invoke(String method, Object[] arguments) throws Throwable;
    }
}
