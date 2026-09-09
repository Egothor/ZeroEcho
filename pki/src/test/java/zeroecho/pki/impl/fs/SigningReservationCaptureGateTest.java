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
package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

final class SigningReservationCaptureGateTest {

    @Test
    void cutoverDrainsOnlyInflightCaptureAndReopenWakesWaiter() throws Exception {
        SigningReservationCaptureGate gate = new SigningReservationCaptureGate();
        SigningReservationCaptureGate.Capture active = gate.enter();
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<?> cutover = executor.submit(() -> {
                gate.closeCutoverAndDrain();
                return null;
            });
            awaitCutover(gate);
            assertEquals(1, gate.snapshot().activeCaptures());
            assertThrows(TimeoutException.class,
                    () -> cutover.get(100L, TimeUnit.MILLISECONDS));

            active.close();
            cutover.get(5L, TimeUnit.SECONDS);
            assertEquals(new SigningReservationCaptureGate.Snapshot(0, true, false),
                    gate.snapshot());
            assertNull(gate.tryEnter());

            CountDownLatch waiterStarted = new CountDownLatch(1);
            Future<SigningReservationCaptureGate.Capture> waiter = executor.submit(() -> {
                waiterStarted.countDown();
                return gate.enter();
            });
            assertTrue(waiterStarted.await(5L, TimeUnit.SECONDS));
            assertThrows(TimeoutException.class,
                    () -> waiter.get(100L, TimeUnit.MILLISECONDS));
            gate.reopenCutover();
            try (SigningReservationCaptureGate.Capture reopened =
                    waiter.get(5L, TimeUnit.SECONDS)) {
                assertEquals(1, gate.snapshot().activeCaptures());
            }
            assertEquals(0, gate.snapshot().activeCaptures());
        } finally {
            active.close();
            gate.close();
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(5L, TimeUnit.SECONDS));
        }
    }

    @Test
    void interruptedDrainPreservesCallerSignalAndPermanentCloseWakesWaiter()
            throws Exception {
        SigningReservationCaptureGate gate = new SigningReservationCaptureGate();
        SigningReservationCaptureGate.Capture active = gate.enter();
        AtomicBoolean interrupted = new AtomicBoolean();
        Thread drainer = new Thread(() -> {
            try {
                gate.closeCutoverAndDrain();
            } catch (InterruptedException failure) {
                Thread.currentThread().interrupt();
                interrupted.set(Thread.currentThread().isInterrupted());
            }
        }, "signing-capture-drainer-test");
        drainer.start();
        awaitCutover(gate);
        drainer.interrupt();
        drainer.join(TimeUnit.SECONDS.toMillis(5L));
        assertFalse(drainer.isAlive());
        assertTrue(interrupted.get());

        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<SigningReservationCaptureGate.Capture> waiter =
                    executor.submit(gate::enter);
            assertThrows(TimeoutException.class,
                    () -> waiter.get(100L, TimeUnit.MILLISECONDS));
            gate.close();
            assertThrows(java.util.concurrent.ExecutionException.class,
                    () -> waiter.get(5L, TimeUnit.SECONDS));
        } finally {
            active.close();
            gate.close();
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(5L, TimeUnit.SECONDS));
        }
        assertEquals(new SigningReservationCaptureGate.Snapshot(0, false, true),
                gate.snapshot());
        assertThrows(IllegalStateException.class, gate::enter);
    }

    @Test
    void interruptedBlockedCaptureTerminatesWithoutAcquisitionOrLeak() throws Exception {
        SigningReservationCaptureGate gate = new SigningReservationCaptureGate();
        gate.closeCutoverAndDrain();
        AtomicBoolean acquired = new AtomicBoolean();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread waiter = new Thread(() -> {
            try (SigningReservationCaptureGate.Capture ignored = gate.enter()) {
                acquired.set(true);
            } catch (InterruptedException interrupted) {
                failure.set(interrupted);
            }
        }, "signing-capture-interrupted-waiter-test");
        try {
            waiter.start();
            awaitWaiting(waiter);
            waiter.interrupt();
            waiter.join(TimeUnit.SECONDS.toMillis(5L));

            assertFalse(waiter.isAlive());
            assertFalse(acquired.get());
            assertTrue(failure.get() instanceof InterruptedException);
            assertEquals(new SigningReservationCaptureGate.Snapshot(0, true, false),
                    gate.snapshot());
        } finally {
            gate.close();
            waiter.interrupt();
            waiter.join(TimeUnit.SECONDS.toMillis(5L));
        }
    }

    private static void awaitCutover(SigningReservationCaptureGate gate) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5L);
        while (System.nanoTime() < deadline) {
            if (gate.snapshot().cutover()) {
                return;
            }
            Thread.onSpinWait();
        }
        throw new AssertionError("capture gate did not close for cutover");
    }

    private static void awaitWaiting(Thread thread) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5L);
        while (System.nanoTime() < deadline) {
            if (thread.getState() == Thread.State.WAITING) {
                return;
            }
            Thread.onSpinWait();
        }
        throw new AssertionError("capture waiter did not block");
    }
}
