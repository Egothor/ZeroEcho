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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class SigningIndexCapacityBudgetTest {

    @Test
    void exactBoundaryAndRollbackAreDeterministic() {
        SigningIndexCapacityBudget budget = new SigningIndexCapacityBudget(256L);
        try (SigningIndexCapacityBudget.Reservation first = budget.reserve(128L)) {
            first.transfer();
        }
        try (SigningIndexCapacityBudget.Reservation rollback = budget.reserve(128L)) {
            assertEquals(256L, budget.snapshot().reservedBytes());
            assertEquals(256L, budget.snapshot().highWaterReservedBytes());
        }
        assertEquals(128L, budget.snapshot().reservedBytes());
        assertThrows(IllegalStateException.class, () -> budget.reserve(129L));
        assertEquals(128L, budget.snapshot().reservedBytes());
        assertEquals(256L, budget.snapshot().highWaterReservedBytes());
        budget.releaseCommitted(128L);
        assertEquals(0L, budget.snapshot().reservedBytes());
        assertEquals(256L, budget.snapshot().highWaterReservedBytes());
    }

    @Test
    void nearLongMaximumReservationCannotOverflowOrChangeFailedAccounting() {
        SigningIndexCapacityBudget budget = new SigningIndexCapacityBudget(Long.MAX_VALUE);
        try (SigningIndexCapacityBudget.Reservation reservation = budget.reserve(Long.MAX_VALUE - 1L)) {
            reservation.transfer();
        }
        SigningIndexCapacityBudget.Snapshot beforeFailure = budget.snapshot();
        assertThrows(IllegalStateException.class, () -> budget.reserve(2L));
        assertEquals(beforeFailure, budget.snapshot());
        budget.releaseCommitted(Long.MAX_VALUE - 1L);
        assertEquals(0L, budget.snapshot().reservedBytes());
        assertEquals(Long.MAX_VALUE - 1L, budget.snapshot().highWaterReservedBytes());
    }

    @Test
    void maximumMustBePositive() {
        assertThrows(IllegalArgumentException.class, () -> new SigningIndexCapacityBudget(0L));
        assertThrows(IllegalArgumentException.class, () -> new SigningIndexCapacityBudget(-1L));
    }

    @Test
    void protectedProgressCapacityCannotBeConsumedByOrdinaryAdmission() {
        SigningIndexCapacityBudget budget = new SigningIndexCapacityBudget(256L, 64L);
        assertEquals(64L, budget.protectedProgressBytes());
        assertEquals(192L, budget.ordinaryMaximumBytes());
        try (SigningIndexCapacityBudget.Reservation ordinary = budget.reserve(192L)) {
            ordinary.transfer();
        }

        assertThrows(SigningIndexCapacityBudget.CapacityExceededException.class,
                () -> budget.reserve(1L));
        try (SigningIndexCapacityBudget.Reservation zero = budget.reserve(0L)) {
            zero.transfer();
        }
        try (SigningIndexCapacityBudget.Reservation progress = budget.reserve(64L,
                SigningTransitionWorkspaceSizing.AdmissionClass
                        .PROTECTED_ACCEPTED_SIGNING)) {
            progress.transfer();
        }

        assertEquals(256L, budget.snapshot().reservedBytes());
        assertThrows(SigningIndexCapacityBudget.CapacityExceededException.class,
                () -> budget.reserve(1L,
                        SigningTransitionWorkspaceSizing.AdmissionClass
                                .PROTECTED_ACCEPTED_SIGNING));
        budget.releaseCommitted(192L);
        budget.releaseCommitted(64L,
                SigningTransitionWorkspaceSizing.AdmissionClass
                        .PROTECTED_ACCEPTED_SIGNING);
        assertEquals(0L, budget.snapshot().reservedBytes());
    }

    @Test
    void ordinaryCapacityIsIndependentOfProtectedAllocationOrder() {
        SigningIndexCapacityBudget budget = new SigningIndexCapacityBudget(256L, 64L);
        try (SigningIndexCapacityBudget.Reservation progress = budget.reserve(64L,
                SigningTransitionWorkspaceSizing.AdmissionClass
                        .PROTECTED_ACCEPTED_SIGNING)) {
            progress.transfer();
        }
        try (SigningIndexCapacityBudget.Reservation ordinary = budget.reserve(192L)) {
            ordinary.transfer();
        }

        assertEquals(256L, budget.snapshot().reservedBytes());
        assertEquals(192L, budget.ordinaryReservedBytes());
        assertEquals(64L, budget.protectedReservedBytes());
        budget.releaseCommitted(192L);
        budget.releaseCommitted(64L,
                SigningTransitionWorkspaceSizing.AdmissionClass
                        .PROTECTED_ACCEPTED_SIGNING);
        assertEquals(0L, budget.snapshot().reservedBytes());
    }

    @Test
    void protectedProgressPartitionMustFitTheExistingTotalBudget() {
        assertThrows(IllegalArgumentException.class,
                () -> new SigningIndexCapacityBudget(256L, -1L));
        assertThrows(IllegalArgumentException.class,
                () -> new SigningIndexCapacityBudget(256L, 257L));
        SigningIndexCapacityBudget entireBudgetProtected =
                new SigningIndexCapacityBudget(256L, 256L);
        assertEquals(0L, entireBudgetProtected.ordinaryMaximumBytes());
    }

    @Test
    void crossBudgetReclassificationCommitsAtomically() {
        SigningIndexCapacityBudget steady = committedBudget(1_024L, 600L);
        SigningIndexCapacityBudget transientBudget = committedBudget(1_024L, 400L);

        try (SigningIndexCapacityBudget.CutoverPermit permit =
                steady.prepareCutover(600L, 700L);
                SigningIndexCapacityBudget.Reclassification exchange =
                        SigningIndexCapacityBudget.reclassify(
                                permit, transientBudget, 400L)) {
            assertEquals(700L, steady.snapshot().reservedBytes());
            assertEquals(0L, transientBudget.snapshot().reservedBytes());
            exchange.commit();
        }

        assertEquals(700L, steady.snapshot().reservedBytes());
        assertEquals(0L, transientBudget.snapshot().reservedBytes());
        steady.releaseCommitted(700L);
    }

    @Test
    void cutoverUsesOrdinarySubtotalWhileProtectedWorkspaceIsReserved() {
        SigningIndexCapacityBudget steady = new SigningIndexCapacityBudget(1_024L, 200L);
        try (SigningIndexCapacityBudget.Reservation ordinary = steady.reserve(600L)) {
            ordinary.transfer();
        }
        try (SigningIndexCapacityBudget.Reservation progress = steady.reserve(100L,
                SigningTransitionWorkspaceSizing.AdmissionClass
                        .PROTECTED_ACCEPTED_SIGNING)) {
            progress.transfer();
        }
        SigningIndexCapacityBudget transientBudget = committedBudget(1_024L, 400L);

        try (SigningIndexCapacityBudget.CutoverPermit permit =
                steady.prepareCutover(600L, 700L);
                SigningIndexCapacityBudget.Reclassification exchange =
                        SigningIndexCapacityBudget.reclassify(
                                permit, transientBudget, 400L)) {
            assertEquals(800L, steady.snapshot().reservedBytes());
            assertEquals(700L, steady.ordinaryReservedBytes());
            assertEquals(100L, steady.protectedReservedBytes());
            assertEquals(0L, transientBudget.snapshot().reservedBytes());
            exchange.commit();
        }

        steady.releaseCommitted(700L);
        steady.releaseCommitted(100L,
                SigningTransitionWorkspaceSizing.AdmissionClass
                        .PROTECTED_ACCEPTED_SIGNING);
        assertEquals(0L, steady.snapshot().reservedBytes());
    }

    @Test
    void crossBudgetReclassificationRollsBackOrRejectsWithoutChangingAccounting() {
        SigningIndexCapacityBudget steady = committedBudget(700L, 600L);
        SigningIndexCapacityBudget transientBudget = committedBudget(500L, 400L);
        SigningIndexCapacityBudget.Snapshot steadyBefore = steady.snapshot();
        SigningIndexCapacityBudget.Snapshot transientBefore = transientBudget.snapshot();

        assertThrows(SigningIndexCapacityBudget.CapacityExceededException.class,
                () -> steady.prepareCutover(100L, 300L));
        assertEquals(steadyBefore, steady.snapshot());
        assertEquals(transientBefore, transientBudget.snapshot());

        try (SigningIndexCapacityBudget.CutoverPermit permit =
                steady.prepareCutover(600L, 650L);
                SigningIndexCapacityBudget.Reclassification ignored =
                        SigningIndexCapacityBudget.reclassify(
                                permit, transientBudget, 400L)) {
            assertEquals(650L, steady.snapshot().reservedBytes());
            assertEquals(0L, transientBudget.snapshot().reservedBytes());
        }
        assertEquals(steadyBefore, steady.snapshot());
        assertEquals(transientBefore, transientBudget.snapshot());
        steady.releaseCommitted(600L);
        transientBudget.releaseCommitted(400L);
    }

    @Test
    void cutoverPermitLeavesReservationAdmissionToTheEngineCaptureGate() {
        SigningIndexCapacityBudget steady = committedBudget(1_024L, 600L);
        try (SigningIndexCapacityBudget.CutoverPermit ignored =
                steady.prepareCutover(600L, 700L)) {
            try (SigningIndexCapacityBudget.Reservation reservation = steady.reserve(1L)) {
                assertEquals(601L, steady.snapshot().reservedBytes());
            }
            steady.releaseCommitted(100L);
            assertEquals(500L, steady.snapshot().reservedBytes());
        }
        try (SigningIndexCapacityBudget.Reservation reservation = steady.reserve(100L)) {
            reservation.transfer();
        }
        assertEquals(600L, steady.snapshot().reservedBytes());
        steady.releaseCommitted(600L);
    }

    @Test
    void deferredCapacitySignalRunsOnceAfterARealRelease() {
        SigningIndexCapacityBudget budget = committedBudget(1_024L, 600L);
        AtomicInteger signals = new AtomicInteger();
        SigningIndexCapacityBudget.CapacityExceededException exhausted = assertThrows(
                SigningIndexCapacityBudget.CapacityExceededException.class,
                () -> budget.reserve(500L));
        budget.signalOnReleaseAfter(exhausted.releaseEpoch(), signals::incrementAndGet);
        assertEquals(0, signals.get());
        budget.releaseCommitted(100L);
        assertEquals(1, signals.get());
        budget.releaseCommitted(100L);
        assertEquals(1, signals.get());
        budget.releaseCommitted(400L);
    }

    @Test
    void releaseBetweenFailureAndRegistrationSignalsExactlyOnce() {
        SigningIndexCapacityBudget budget = committedBudget(1_024L, 600L);
        AtomicInteger signals = new AtomicInteger();
        SigningIndexCapacityBudget.CapacityExceededException exhausted = assertThrows(
                SigningIndexCapacityBudget.CapacityExceededException.class,
                () -> budget.reserve(500L));

        budget.releaseCommitted(100L);
        budget.signalOnReleaseAfter(exhausted.releaseEpoch(), signals::incrementAndGet);

        assertEquals(1, signals.get());
        budget.releaseCommitted(500L);
        assertEquals(1, signals.get());
    }

    @Test
    void combinedCapacityObservationFailsClosedOnOverflow() {
        SigningLedgerStoreEngine.CapacitySnapshot observation =
                new SigningLedgerStoreEngine.CapacitySnapshot(
                        new SigningIndexCapacityBudget.Snapshot(0L, 0L, Long.MAX_VALUE),
                        new SigningIndexCapacityBudget.Snapshot(0L, 0L, 1L));
        assertThrows(ArithmeticException.class, observation::combinedMaximumBytes);
    }

    private static SigningIndexCapacityBudget committedBudget(long maximum, long reserved) {
        SigningIndexCapacityBudget result = new SigningIndexCapacityBudget(maximum);
        try (SigningIndexCapacityBudget.Reservation reservation = result.reserve(reserved)) {
            reservation.transfer();
        }
        return result;
    }
}
