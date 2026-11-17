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
package zeroecho.pki.impl.fs;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

/**
 * One conservative resident-index byte budget for one signing ledger.
 */
@SuppressWarnings("PMD.AvoidLiteralsInIfCondition")
final class SigningIndexCapacityBudget {
    private final long maximumBytes;
    private final long protectedProgressBytes;
    private final long ordinaryMaximumBytes;
    private final ReentrantLock lock = new ReentrantLock();
    private long reservedBytes;
    private long ordinaryReservedBytes;
    private long protectedReservedBytes;
    private long highWaterReservedBytes;
    private long releaseEpoch;
    private Runnable releaseSignal;
    private final ThreadLocal<PreparationLoan> preparationLoan = new ThreadLocal<>();

    /**
     * Creates a conservative byte budget with explicit total and ordinary-admission ceilings.
     *
     * @param maximumBytes positive inclusive total reservation limit in bytes
     * @throws IllegalArgumentException if the total is not positive or the protected floor falls outside
     * zero through the total
     */
    /* default */ SigningIndexCapacityBudget(long maximumBytes) {
        this(maximumBytes, 0L);
    }

    /**
     * Creates a conservative byte budget with explicit total and ordinary-admission ceilings.
     *
     * @param maximumBytes positive inclusive total reservation limit in bytes
     * @param protectedProgressBytes nonnegative byte floor excluded from ordinary admission, no greater
     * than the total limit
     * @throws IllegalArgumentException if the total is not positive or the protected floor falls outside
     * zero through the total
     */
    /* default */ SigningIndexCapacityBudget(long maximumBytes,
            long protectedProgressBytes) {
        if (maximumBytes <= 0L) {
            throw new IllegalArgumentException("signing index byte budget is invalid");
        }
        if (protectedProgressBytes < 0L || protectedProgressBytes > maximumBytes) {
            throw new IllegalArgumentException(
                    "signing index protected progress capacity is invalid");
        }
        this.maximumBytes = maximumBytes;
        this.protectedProgressBytes = protectedProgressBytes;
        ordinaryMaximumBytes = maximumBytes - protectedProgressBytes;
    }

    /**
     * Reserves bytes atomically or changes no accounting.
     *
     * @param bytes nonnegative byte count requested from ordinary admission
     * @return owned rollback reservation; close it or transfer responsibility for its bytes
     * @throws IllegalArgumentException if the requested count is negative
     * @throws CapacityExceededException if ordinary capacity or the current preparation loan is insufficient
     */
    /* default */ Reservation reserve(long bytes) {
        return reserve(bytes, SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /**
     * Reserves bytes against the admission class's ceiling or changes no accounting.
     *
     * @param bytes nonnegative byte count to reserve
     * @param admissionClass ordinary or protected accepted-signing admission class
     * @return owned rollback reservation, supplied by thread-local escrow when a preparation loan is active
     * @throws NullPointerException if the admission class is null
     * @throws IllegalArgumentException if the requested count is negative
     * @throws CapacityExceededException if total, selected-class or preparation-loan capacity is insufficient
     */
    /* default */ Reservation reserve(long bytes,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
        if (bytes < 0L) {
            throw new IllegalArgumentException("signing index byte reservation is invalid");
        }
        Objects.requireNonNull(admissionClass, "admissionClass");
        lock.lock();
        try {
            if (preparationLoan.get() != null) { return preparationLoan.get().borrow(bytes, admissionClass); }
            long ceiling = admissionClass
                    == SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY
                            ? ordinaryMaximumBytes : maximumBytes;
            long classReserved = admissionClass
                    == SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY
                            ? ordinaryReservedBytes : protectedReservedBytes;
            if (bytes > maximumBytes - reservedBytes
                    || bytes > ceiling - classReserved) {
                throw new CapacityExceededException("signing index resident byte budget is exhausted: requested="
                        + bytes + " current=" + reservedBytes + " highWater=" + highWaterReservedBytes
                        + " ceiling=" + ceiling + " maximum=" + maximumBytes,
                        releaseEpoch);
            }
            reservedBytes += bytes;
            if (admissionClass == SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY) {
                ordinaryReservedBytes += bytes;
            } else {
                protectedReservedBytes += bytes;
            }
            highWaterReservedBytes = Math.max(highWaterReservedBytes, reservedBytes);
            return new Reservation(this, bytes, admissionClass);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Captures current, peak and configured byte reservations under the budget lock.
     *
     * @return new immutable constant-size budget observation
     */
    /* default */ Snapshot snapshot() {
        lock.lock();
        try {
            return new Snapshot(reservedBytes, highWaterReservedBytes, maximumBytes);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns the byte reservation floor protected for already accepted signing progress.
     *
     * @return byte reservation floor protected for already accepted signing progress
     */
    /* default */ long protectedProgressBytes() {
        return protectedProgressBytes;
    }

    /**
     * Returns the maximum bytes available for ordinary admission outside the protected progress floor.
     *
     * @return maximum bytes available for ordinary admission outside the protected progress floor
     */
    /* default */ long ordinaryMaximumBytes() {
        return ordinaryMaximumBytes;
    }

    /**
     * Reads the current ordinary-admission byte reservation under the budget lock.
     *
     * @return current ordinary-admission accounted bytes
     */
    /* default */ long ordinaryReservedBytes() {
        lock.lock();
        try {
            return ordinaryReservedBytes;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Reads the current protected accepted-signing byte reservation under the budget lock.
     *
     * @return current protected accepted-signing accounted bytes
     */
    /* default */ long protectedReservedBytes() {
        lock.lock();
        try {
            return protectedReservedBytes;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Releases previously transferred byte ownership and signals an armed capacity waiter after unlocking.
     *
     * <p>The overload without a class releases ordinary-admission bytes.</p>
     *
     * @param bytes nonnegative committed byte count to release
     * @throws RuntimeException if the armed release callback fails after accounting changed; bytes are not restored
     * @throws IllegalStateException if the release exceeds the total or selected-class reservation
     */
    /* default */ void releaseCommitted(long bytes) {
        release(bytes, SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /**
     * Releases previously transferred byte ownership and signals an armed capacity waiter after unlocking.
     *
     * @param bytes nonnegative committed byte count to release
     * @param admissionClass exact class against which these bytes were originally reserved
     * @throws NullPointerException if an explicit admission class is null
     * @throws IllegalStateException if the release exceeds the total or selected-class reservation
     * @throws RuntimeException if the armed release callback fails after accounting changed; bytes are not restored
     */
    /* default */ void releaseCommitted(long bytes,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
        release(bytes, admissionClass);
    }

    /**
     * Arms one wake after the observed failure, or signals immediately when a
     * release already occurred between failure observation and registration.
     *
     * <p>Only one callback can be armed. An existing callback wins when the observed
     * epoch still matches; a newer release triggers this callback immediately.
     * Registration never replaces an already armed callback.</p>
     *
     * @param observedReleaseEpoch release epoch captured by the failed admission
     * @param signal non-null one-shot callback; immediate delivery occurs after unlocking
     * @throws NullPointerException if the callback is null
     * @throws RuntimeException if an immediately delivered callback fails
     */
    /* default */ void signalOnReleaseAfter(long observedReleaseEpoch, Runnable signal) {
        Objects.requireNonNull(signal, "signal");
        boolean signalNow = false;
        lock.lock();
        try {
            if (releaseEpoch == observedReleaseEpoch) {
                if (releaseSignal == null) {
                    releaseSignal = signal;
                }
            } else {
                signalNow = true;
            }
        } finally {
            lock.unlock();
        }
        if (signalNow) {
            signal.run();
        }
    }

    /**
     * Disarms the current one-shot capacity-release callback without changing reservations.
     *
     */
    /* default */ void clearReleaseSignal() {
        lock.lock();
        try {
            releaseSignal = null;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Reserves a stable steady-budget cutover endpoint without performing I/O.
     *
     * @param displacedBytes nonnegative ordinary bytes owned by the root being displaced
     * @param replacementBytes nonnegative ordinary bytes required by the replacement root
     * @return owned active cutover permit; accounting is revalidated when reclassification begins
     * @throws IllegalArgumentException if either byte count is negative
     * @throws IllegalStateException if displaced bytes exceed current ordinary ownership
     * @throws CapacityExceededException if the resulting steady root exceeds ordinary or total limits
     */
    /* default */ CutoverPermit prepareCutover(long displacedBytes, long replacementBytes) {
        if (displacedBytes < 0L || replacementBytes < 0L) {
            throw new IllegalArgumentException("signing index cutover capacity is invalid");
        }
        lock.lock();
        try {
            if (displacedBytes > ordinaryReservedBytes) {
                throw new IllegalStateException("signing index cutover ownership is inconsistent");
            }
            long remainingOrdinary = ordinaryReservedBytes - displacedBytes;
            long remainingTotal = reservedBytes - displacedBytes;
            if (replacementBytes > ordinaryMaximumBytes - remainingOrdinary
                    || replacementBytes > maximumBytes - remainingTotal) {
                throw new CapacityExceededException(
                        "signing index steady byte budget cannot own compacted root: replacement="
                                + replacementBytes + " remaining=" + remainingTotal
                                + " maximum=" + ordinaryMaximumBytes, releaseEpoch);
            }
            return new CutoverPermit(this, displacedBytes, replacementBytes);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Atomically moves a detached root from {@code transientBudget} into the
     * steady envelope while removing its displaced steady root.
     *
     * <p>The fixed lock order is steady then transient. The returned token keeps
     * both locks until commit or rollback, so root-field publication can neither
     * race another reservation nor expose partially reclassified accounting.</p>
     * @param steadyPermit active permit identifying displaced and replacement steady ownership
     * @param transientBudget distinct budget currently owning the detached replacement root
     * @param replacementTransientBytes nonnegative bytes of transient ownership transferred into the steady envelope
     * @return rollback-capable token retaining both budget locks until same-thread closure
     * @throws NullPointerException if the permit or transient budget is null
     * @throws IllegalArgumentException if budgets are identical or a byte count is negative
     * @throws IllegalStateException if ownership or permit lifecycle is inconsistent
     * @throws CapacityExceededException if the resulting steady accounting exceeds its limits
     */
    @SuppressWarnings("PMD.CompareObjectsWithEquals") // Distinct lock identities are required.
    /* default */ static Reclassification reclassify(CutoverPermit steadyPermit,
            SigningIndexCapacityBudget transientBudget, long replacementTransientBytes) {
        Objects.requireNonNull(steadyPermit, "steadyPermit");
        SigningIndexCapacityBudget steadyBudget = steadyPermit.owner;
        if (steadyBudget == transientBudget) {
            throw new IllegalArgumentException("signing index capacity budgets must be distinct");
        }
        long displacedSteadyBytes = steadyPermit.displacedBytes;
        long replacementSteadyBytes = steadyPermit.replacementBytes;
        if (displacedSteadyBytes < 0L || replacementTransientBytes < 0L
                || replacementSteadyBytes < 0L) {
            throw new IllegalArgumentException("signing index reclassification is invalid");
        }
        steadyBudget.lock.lock();
        transientBudget.lock.lock();
        boolean retained = false;
        try {
            if (displacedSteadyBytes > steadyBudget.ordinaryReservedBytes
                    || replacementTransientBytes > transientBudget.ordinaryReservedBytes) {
                throw new IllegalStateException("signing index reclassification ownership is inconsistent");
            }
            steadyPermit.requireActive();
            long remainingSteady = steadyBudget.reservedBytes - displacedSteadyBytes;
            long remainingOrdinary = steadyBudget.ordinaryReservedBytes
                    - displacedSteadyBytes;
            if (replacementSteadyBytes
                            > steadyBudget.ordinaryMaximumBytes - remainingOrdinary
                    || replacementSteadyBytes
                            > steadyBudget.maximumBytes - remainingSteady) {
                throw new CapacityExceededException(
                        "signing index steady byte budget cannot own compacted root: replacement="
                                + replacementSteadyBytes + " remaining=" + remainingSteady
                                + " maximum=" + steadyBudget.ordinaryMaximumBytes,
                        steadyBudget.releaseEpoch);
            }
            steadyBudget.reservedBytes = remainingSteady + replacementSteadyBytes;
            steadyBudget.ordinaryReservedBytes = remainingOrdinary + replacementSteadyBytes;
            long previousSteadyHighWater = steadyBudget.highWaterReservedBytes;
            long previousTransientHighWater = transientBudget.highWaterReservedBytes;
            steadyBudget.highWaterReservedBytes = Math.max(steadyBudget.highWaterReservedBytes,
                    steadyBudget.reservedBytes);
            transientBudget.reservedBytes -= replacementTransientBytes;
            transientBudget.ordinaryReservedBytes -= replacementTransientBytes;
            retained = true;
            return new Reclassification(steadyBudget, displacedSteadyBytes,
                    transientBudget, replacementTransientBytes, replacementSteadyBytes,
                    previousSteadyHighWater, previousTransientHighWater, steadyPermit);
        } finally {
            if (!retained) {
                transientBudget.lock.unlock();
                steadyBudget.lock.unlock();
            }
        }
    }

    private void release(long bytes,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
        Objects.requireNonNull(admissionClass, "admissionClass");
        Runnable signal = null;
        lock.lock();
        try {
            long classReserved = admissionClass
                    == SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY
                            ? ordinaryReservedBytes : protectedReservedBytes;
            if (bytes < 0L || bytes > reservedBytes || bytes > classReserved) {
                throw new IllegalStateException("signing index byte accounting is inconsistent");
            }
            reservedBytes -= bytes;
            if (admissionClass == SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY) {
                ordinaryReservedBytes -= bytes;
            } else {
                protectedReservedBytes -= bytes;
            }
            if (bytes > 0L) {
                releaseEpoch++;
                signal = releaseSignal;
                releaseSignal = null;
            }
        } finally {
            lock.unlock();
        }
        if (signal != null) {
            signal.run();
        }
    }

    /**
     * Rollback-capable reservation; transfer is idempotent and retains the bytes.
     */
    /* default */ static final class Reservation implements AutoCloseable {
        private final SigningIndexCapacityBudget owner;
        private final long bytes;
        private final SigningTransitionWorkspaceSizing.AdmissionClass admissionClass;
        private final AtomicBoolean active = new AtomicBoolean(true);
        private PreparationLoan loan;

        private Reservation(SigningIndexCapacityBudget owner, long bytes,
                SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
            this.owner = owner;
            this.bytes = bytes;
            this.admissionClass = admissionClass;
        }

        /**
         * Transfers byte-release responsibility away from this rollback-capable reservation.
         *
         * <p>Transfer is idempotent; closing the reservation afterward retains its committed bytes.</p>
         *
         */
        /* default */ void transfer() {
            active.set(false);
        }

        /**
         * Releases this reservation once unless byte ownership was already transferred.
         *
         * <p>An uncommitted preparation loan receives an escrow refund; otherwise the
         * global reservation is released. Callback failure propagates after accounted
         * release and does not restore the bytes or reactivate this token.</p>
         *
         * @throws IllegalStateException if reservation accounting or loan lifecycle is inconsistent
         * @throws ArithmeticException if an escrow refund counter overflows
         * @throws RuntimeException if an armed global release callback fails
         */
        @Override
        public void close() {
            if (active.compareAndSet(true, false)) {
                if (loan == null || loan.committed) { owner.release(bytes, admissionClass); }
                else { loan.refund(bytes, admissionClass); }
            }
        }
    }

    /**
     * Opens a single-operation preparation scope over already committed ordinary
     * bytes. No bytes are freed globally; allocations borrow only this owner's
     * escrow. The scope must leave the preparing thread before publication.
     * @param bytes nonnegative ordinary committed bytes owned by this operation
     * @return owned thread-local preparation loan; detach before publication and close to roll back unused ownership
     * @throws IllegalStateException if another preparation loan is active, the count is negative or
     * ordinary ownership is insufficient
     */
    /* default */ PreparationLoan borrowCommitted(long bytes) {
        if (bytes < 0L || preparationLoan.get() != null) {
            throw new IllegalStateException("signing future-capacity loan scope is invalid");
        }
        lock.lock();
        try {
            if (bytes > ordinaryReservedBytes) {
                throw new IllegalStateException("signing future-capacity ownership is invalid");
            }
            PreparationLoan loan = new PreparationLoan(bytes);
            preparationLoan.set(loan);
            return loan;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Parent-owned byte conversion with rollback before authoritative publication.
     */
    /* default */ final class PreparationLoan implements AutoCloseable {
        private final long initial;
        private long remaining;
        private boolean detached;
        private boolean committed;
        private boolean closed;

        private PreparationLoan(long bytes) { initial = bytes; remaining = bytes; }

        private Reservation borrow(long bytes,
                SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
            if (detached || closed || bytes > remaining) {
                throw new CapacityExceededException(
                        "hybrid CRL owner future-capacity allowance is exhausted", releaseEpoch);
            }
            remaining -= bytes;
            if (admissionClass != SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY) {
                ordinaryReservedBytes -= bytes;
                protectedReservedBytes += bytes;
            }
            Reservation result = new Reservation(SigningIndexCapacityBudget.this,
                    bytes, admissionClass);
            result.loan = this;
            return result;
        }

        private void refund(long bytes,
                SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
            lock.lock();
            try {
                if (closed) { throw new IllegalStateException("closed signing capacity loan"); }
                remaining = Math.addExact(remaining, bytes);
                if (admissionClass != SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY) {
                    protectedReservedBytes -= bytes;
                    ordinaryReservedBytes += bytes;
                }
            } finally { lock.unlock(); }
        }

        /**
         * Ends ambient preparation eligibility without retaining a thread lock.
         *
         * @throws IllegalStateException if called outside the preparing thread or after ambient loan ownership changed
         */
        /* default */ void detach() {
            if (!equals(preparationLoan.get())) {
                throw new IllegalStateException("signing capacity loan thread differs");
            }
            preparationLoan.remove();
            detached = true;
        }

        /**
         * Checks the remaining phase allowance before irreversible WAL admission.
         *
         * @param residual nonnegative bytes required for the next retained phase
         * @throws CapacityExceededException if this loan is not detached, is closed or lacks the requested residual
         */
        /* default */ void requireResidual(long residual) {
            lock.lock();
            try {
                if (!detached || closed || residual < 0L || residual > remaining) {
                    throw new CapacityExceededException("hybrid CRL future phase allowance is insufficient", releaseEpoch);
                }
            } finally { lock.unlock(); }
        }

        /**
         * Converts borrowed allocations and retains exactly the next phase's escrow.
         *
         * @param residual nonnegative bytes retained for the next phase, no greater than the remaining loan
         * @throws IllegalStateException if the loan is not detached, is closed or its residual is invalid
         * @throws RuntimeException if an armed release callback fails after committed accounting changed
         */
        /* default */ void publish(long residual) {
            lock.lock();
            try {
                if (!detached || closed || residual < 0L || residual > remaining) {
                    throw new IllegalStateException("signing future-capacity residual is invalid");
                }
                committed = true;
                closed = true;
                release(remaining - residual, SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
            } finally { lock.unlock(); }
        }

        /**
         * Rolls back a preparation loan after all borrowed allocations have been refunded.
         *
         * <p>An attached loan first detaches on its preparing thread. Outstanding
         * allocations leave the loan detached and open: release those allocations,
         * then retry closure. Successful closure and previously published closure
         * are idempotent.</p>
         *
         * @throws IllegalStateException if an attached loan is closed from the wrong
         *     preparing scope or borrowed allocations still remain outstanding
         */
        @Override public void close() {
            lock.lock();
            try {
                if (closed) { return; }
                if (!detached) { detach(); }
                if (remaining != initial) {
                    throw new IllegalStateException("signing future-capacity rollback has outstanding allocations");
                }
                closed = true;
            } finally { lock.unlock(); }
        }
    }

    /**
     * Current, peak and maximum byte reservations for one capacity budget.
     *
     * @param reservedBytes current accounted reservation in bytes
     * @param highWaterReservedBytes highest accounted byte reservation observed
     * @param maximumBytes inclusive configured byte reservation limit
     */
    /* default */ record Snapshot(long reservedBytes, long highWaterReservedBytes,
            long maximumBytes) {
    }

    /**
     * Validated steady-budget endpoint consumed by locked reclassification.
     *
     * <p>This permit retains no budget lock. {@link Reclassification} revalidates
     * its endpoint and owns both budget locks across root publication.</p>
     */
    /* default */ static final class CutoverPermit implements AutoCloseable {
        private final SigningIndexCapacityBudget owner;
        private final long displacedBytes;
        private final long replacementBytes;
        private boolean active = true;

        private CutoverPermit(SigningIndexCapacityBudget owner,
                long displacedBytes, long replacementBytes) {
            this.owner = owner;
            this.displacedBytes = displacedBytes;
            this.replacementBytes = replacementBytes;
        }

        private void requireActive() {
            if (!active) {
                throw new IllegalStateException("signing index cutover capacity is not active");
            }
        }

        private void transferred() {
            requireActive();
            active = false;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void close() {
            owner.lock.lock();
            try {
                if (active) {
                    requireActive();
                    active = false;
                }
            } finally {
                owner.lock.unlock();
            }
        }
    }

    /**
     * Controlled capacity result suitable for maintenance deferral.
     */
    /* default */ static final class CapacityExceededException extends IllegalStateException {
        private static final long serialVersionUID = 1L;
        private final long releaseEpoch;

        private CapacityExceededException(String message, long releaseEpoch) {
            super(message);
            this.releaseEpoch = releaseEpoch;
        }

        /**
         * Returns the capacity release epoch captured when admission was rejected.
         *
         * @return capacity release epoch captured when admission was rejected
         */
        /* default */ long releaseEpoch() {
            return releaseEpoch;
        }
    }

    /**
     * Rollback token retaining both budget locks across root publication.
     */
    /* default */ static final class Reclassification implements AutoCloseable {
        private final SigningIndexCapacityBudget steadyBudget;
        private final long displacedSteadyBytes;
        private final SigningIndexCapacityBudget transientBudget;
        private final long replacementTransientBytes;
        private final long replacementSteadyBytes;
        private final long previousSteadyHighWater;
        private final long previousTransientHighWater;
        private final CutoverPermit steadyPermit;
        private boolean active = true;
        private boolean closed;

        private Reclassification(SigningIndexCapacityBudget steadyBudget,
                long displacedSteadyBytes, SigningIndexCapacityBudget transientBudget,
                long replacementTransientBytes, long replacementSteadyBytes,
                long previousSteadyHighWater, long previousTransientHighWater,
                CutoverPermit steadyPermit) {
            this.steadyBudget = steadyBudget;
            this.displacedSteadyBytes = displacedSteadyBytes;
            this.transientBudget = transientBudget;
            this.replacementTransientBytes = replacementTransientBytes;
            this.replacementSteadyBytes = replacementSteadyBytes;
            this.previousSteadyHighWater = previousSteadyHighWater;
            this.previousTransientHighWater = previousTransientHighWater;
            this.steadyPermit = steadyPermit;
        }

        /**
         * Commits the reclassified accounting and consumes its steady cutover permit.
         *
         * <p>Both budget locks remain held until this token is closed on the acquiring thread.</p>
         *
         * @throws IllegalStateException if the steady cutover permit is no longer active
         */
        /* default */ void commit() {
            steadyPermit.transferred();
            active = false;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void close() {
            if (closed) {
                return;
            }
            try {
                if (active) {
                    steadyBudget.reservedBytes = Math.addExact(
                            steadyBudget.reservedBytes - replacementSteadyBytes,
                            displacedSteadyBytes);
                    steadyBudget.ordinaryReservedBytes = Math.addExact(
                            steadyBudget.ordinaryReservedBytes - replacementSteadyBytes,
                            displacedSteadyBytes);
                    transientBudget.reservedBytes = Math.addExact(
                            transientBudget.reservedBytes, replacementTransientBytes);
                    transientBudget.ordinaryReservedBytes = Math.addExact(
                            transientBudget.ordinaryReservedBytes,
                            replacementTransientBytes);
                    steadyBudget.highWaterReservedBytes = previousSteadyHighWater;
                    transientBudget.highWaterReservedBytes = previousTransientHighWater;
                    active = false;
                }
            } finally {
                closed = true;
                transientBudget.lock.unlock();
                steadyBudget.lock.unlock();
            }
        }
    }
}
