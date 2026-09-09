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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

final class SigningLedgerLifecycleSlotsTest {

    @Test
    void preparedToAdmittedTransferPreservesOneBoundedLifecycleSlot() {
        SigningLedgerStoreEngine.LifecycleSlots slots =
                new SigningLedgerStoreEngine.LifecycleSlots(2);

        slots.acquirePrepared();
        slots.acquirePrepared();
        assertEquals(new SigningLedgerStoreEngine.LifecycleSnapshot(2, 0, 2),
                slots.snapshot());
        assertThrows(SigningActiveWal.OverloadedException.class, slots::acquirePrepared);

        slots.transferPreparedToAdmitted();
        assertEquals(new SigningLedgerStoreEngine.LifecycleSnapshot(1, 1, 2),
                slots.snapshot());
        assertThrows(SigningActiveWal.OverloadedException.class, slots::acquirePrepared);

        assertTrue(slots.releaseAdmitted());
        slots.acquirePrepared();
        assertEquals(new SigningLedgerStoreEngine.LifecycleSnapshot(2, 0, 2),
                slots.snapshot());
        assertTrue(slots.releasePrepared());
        assertTrue(slots.releasePrepared());
        assertFalse(slots.releasePrepared());
        assertFalse(slots.releaseAdmitted());
        assertThrows(IllegalStateException.class, slots::transferPreparedToAdmitted);
        assertEquals(new SigningLedgerStoreEngine.LifecycleSnapshot(0, 0, 2),
                slots.snapshot());
    }

    @Test
    void cohortPreparedAcquisitionIsAllOrNone() {
        SigningLedgerStoreEngine.AdmissionMaintenanceGate gate = gate(4);

        List<SigningLedgerStoreEngine.AdmissionMaintenanceGate.Preparation> preparations =
                assertDoesNotInterrupt(() -> gate.beginCohort(3));
        assertEquals(new SigningLedgerStoreEngine.LifecycleSnapshot(3, 0, 4),
                gate.snapshot().lifecycle());
        assertThrows(SigningActiveWal.OverloadedException.class,
                () -> gate.beginCohort(2));
        assertEquals(new SigningLedgerStoreEngine.LifecycleSnapshot(3, 0, 4),
                gate.snapshot().lifecycle());
        preparations.forEach(
                SigningLedgerStoreEngine.AdmissionMaintenanceGate.Preparation::close);
    }

    @Test
    void maintenanceWinsBeforeCohortOwnsAnySlot() throws Exception {
        SigningLedgerStoreEngine.AdmissionMaintenanceGate gate = gate(4);
        assertTrue(gate.beginMaintenanceAndDrain());
        AtomicReference<Thread> worker = new AtomicReference<>();
        CountDownLatch started = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
            Future<List<SigningLedgerStoreEngine.AdmissionMaintenanceGate.Preparation>> cohort =
                    executor.submit(() -> {
                        worker.set(Thread.currentThread());
                        started.countDown();
                        return gate.beginCohort(2);
                    });
            assertTrue(started.await(5L, TimeUnit.SECONDS));
            awaitWaiting(worker.get());
            assertEquals(new SigningLedgerStoreEngine.LifecycleSnapshot(0, 0, 4),
                    gate.snapshot().lifecycle());

            gate.reopenBoundary();
            List<SigningLedgerStoreEngine.AdmissionMaintenanceGate.Preparation> preparations =
                    cohort.get(5L, TimeUnit.SECONDS);
            assertEquals(new SigningLedgerStoreEngine.LifecycleSnapshot(2, 0, 4),
                    gate.snapshot().lifecycle());
            preparations.forEach(
                    SigningLedgerStoreEngine.AdmissionMaintenanceGate.Preparation::close);
        }
    }

    @Test
    void cohortWinsAndMaintenanceDrainsTheCompleteCount() throws Exception {
        SigningLedgerStoreEngine.AdmissionMaintenanceGate gate = gate(4);
        List<SigningLedgerStoreEngine.AdmissionMaintenanceGate.Preparation> preparations =
                gate.beginCohort(3);
        AtomicReference<Thread> worker = new AtomicReference<>();
        CountDownLatch started = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
            Future<Boolean> maintenance = executor.submit(() -> {
                worker.set(Thread.currentThread());
                started.countDown();
                return gate.beginMaintenanceAndDrain();
            });
            assertTrue(started.await(5L, TimeUnit.SECONDS));
            awaitWaiting(worker.get());
            assertEquals(new SigningLedgerStoreEngine.GateSnapshot(
                    new SigningLedgerStoreEngine.LifecycleSnapshot(3, 0, 4), true, false),
                    gate.snapshot());

            preparations.forEach(
                    SigningLedgerStoreEngine.AdmissionMaintenanceGate.Preparation::close);
            assertTrue(maintenance.get(5L, TimeUnit.SECONDS));
            gate.reopenBoundary();
            assertEquals(new SigningLedgerStoreEngine.LifecycleSnapshot(0, 0, 4),
                    gate.snapshot().lifecycle());
        }
    }

    @Test
    void closeWakesCohortWaiterWithoutOwnership() throws Exception {
        SigningLedgerStoreEngine.AdmissionMaintenanceGate gate = gate(4);
        assertTrue(gate.beginMaintenanceAndDrain());
        AtomicReference<Thread> worker = new AtomicReference<>();
        CountDownLatch started = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
            Future<?> cohort = executor.submit(() -> {
                worker.set(Thread.currentThread());
                started.countDown();
                return gate.beginCohort(2);
            });
            assertTrue(started.await(5L, TimeUnit.SECONDS));
            awaitWaiting(worker.get());
            gate.closeAdmissions();
            ExecutionException failure = assertThrows(ExecutionException.class,
                    () -> cohort.get(5L, TimeUnit.SECONDS));
            assertInstanceOf(IllegalStateException.class, failure.getCause());
            assertEquals(new SigningLedgerStoreEngine.LifecycleSnapshot(0, 0, 4),
                    gate.snapshot().lifecycle());
        }
    }

    @Test
    void interruptionLeavesWaitingCohortWithoutOwnership() throws Exception {
        SigningLedgerStoreEngine.AdmissionMaintenanceGate gate = gate(4);
        assertTrue(gate.beginMaintenanceAndDrain());
        AtomicReference<Thread> worker = new AtomicReference<>();
        CountDownLatch started = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
            Future<?> cohort = executor.submit(() -> {
                worker.set(Thread.currentThread());
                started.countDown();
                return gate.beginCohort(2);
            });
            assertTrue(started.await(5L, TimeUnit.SECONDS));
            awaitWaiting(worker.get());
            worker.get().interrupt();
            ExecutionException failure = assertThrows(ExecutionException.class,
                    () -> cohort.get(5L, TimeUnit.SECONDS));
            assertInstanceOf(InterruptedException.class, failure.getCause());
            assertEquals(new SigningLedgerStoreEngine.LifecycleSnapshot(0, 0, 4),
                    gate.snapshot().lifecycle());
            gate.reopenBoundary();
        }
    }

    private static SigningLedgerStoreEngine.AdmissionMaintenanceGate gate(int capacity) {
        return new SigningLedgerStoreEngine.AdmissionMaintenanceGate(new Object(), capacity);
    }

    private static List<SigningLedgerStoreEngine.AdmissionMaintenanceGate.Preparation>
            assertDoesNotInterrupt(InterruptedPreparation operation) {
        try {
            return operation.run();
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new AssertionError("unexpected interruption", failure);
        }
    }

    private static void awaitWaiting(Thread worker) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5L);
        while (System.nanoTime() < deadline) {
            if (worker.getState() == Thread.State.WAITING) {
                return;
            }
            Thread.onSpinWait();
        }
        throw new AssertionError("gate worker did not reach the deterministic wait state");
    }

    @FunctionalInterface
    private interface InterruptedPreparation {
        List<SigningLedgerStoreEngine.AdmissionMaintenanceGate.Preparation> run()
                throws InterruptedException;
    }

}
