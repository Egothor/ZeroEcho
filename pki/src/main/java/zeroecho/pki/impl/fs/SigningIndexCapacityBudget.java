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

/** One conservative resident-index byte budget for one signing ledger. */
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

    /* default */ SigningIndexCapacityBudget(long maximumBytes) {
        this(maximumBytes, 0L);
    }

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

    /** Reserves bytes atomically or changes no accounting. */
    /* default */ Reservation reserve(long bytes) {
        return reserve(bytes, SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /** Reserves bytes against the admission class's ceiling or changes no accounting. */
    /* default */ Reservation reserve(long bytes,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
        if (bytes < 0L) {
            throw new IllegalArgumentException("signing index byte reservation is invalid");
        }
        Objects.requireNonNull(admissionClass, "admissionClass");
        lock.lock();
        try {
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

    /* default */ Snapshot snapshot() {
        lock.lock();
        try {
            return new Snapshot(reservedBytes, highWaterReservedBytes, maximumBytes);
        } finally {
            lock.unlock();
        }
    }

    /* default */ long protectedProgressBytes() {
        return protectedProgressBytes;
    }

    /* default */ long ordinaryMaximumBytes() {
        return ordinaryMaximumBytes;
    }

    /* default */ long ordinaryReservedBytes() {
        lock.lock();
        try {
            return ordinaryReservedBytes;
        } finally {
            lock.unlock();
        }
    }

    /* default */ long protectedReservedBytes() {
        lock.lock();
        try {
            return protectedReservedBytes;
        } finally {
            lock.unlock();
        }
    }

    /* default */ void releaseCommitted(long bytes) {
        release(bytes, SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /* default */ void releaseCommitted(long bytes,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
        release(bytes, admissionClass);
    }

    /**
     * Arms one wake after the observed failure, or signals immediately when a
     * release already occurred between failure observation and registration.
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

    /* default */ void clearReleaseSignal() {
        lock.lock();
        try {
            releaseSignal = null;
        } finally {
            lock.unlock();
        }
    }

    /** Reserves a stable steady-budget cutover endpoint without performing I/O. */
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

    /** Rollback-capable reservation; transfer is idempotent and retains the bytes. */
    /* default */ static final class Reservation implements AutoCloseable {
        private final SigningIndexCapacityBudget owner;
        private final long bytes;
        private final SigningTransitionWorkspaceSizing.AdmissionClass admissionClass;
        private final AtomicBoolean active = new AtomicBoolean(true);

        private Reservation(SigningIndexCapacityBudget owner, long bytes,
                SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
            this.owner = owner;
            this.bytes = bytes;
            this.admissionClass = admissionClass;
        }

        /* default */ void transfer() {
            active.set(false);
        }

        @Override
        public void close() {
            if (active.compareAndSet(true, false)) {
                owner.release(bytes, admissionClass);
            }
        }
    }

    /* default */ record Snapshot(long reservedBytes, long highWaterReservedBytes,
            long maximumBytes) {
    }

    /** Short-lived steady-budget exclusion held across manifest publication. */
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

    /** Controlled capacity result suitable for maintenance deferral. */
    /* default */ static final class CapacityExceededException extends IllegalStateException {
        private static final long serialVersionUID = 1L;
        private final long releaseEpoch;

        private CapacityExceededException(String message, long releaseEpoch) {
            super(message);
            this.releaseEpoch = releaseEpoch;
        }

        /* default */ long releaseEpoch() {
            return releaseEpoch;
        }
    }

    /** Rollback token retaining both budget locks across root publication. */
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

        /* default */ void commit() {
            steadyPermit.transferred();
            active = false;
        }

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
