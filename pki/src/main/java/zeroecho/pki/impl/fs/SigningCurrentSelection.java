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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Capacity-reserved current pointers with exact short-lived generation pins.
 */
final class SigningCurrentSelection implements AutoCloseable {
    private static final long FIXED_BYTES = 128L;
    private static final long RECORD_BYTES = 128L;
    private static final int INITIAL_RECORDS = 16;

    private final List<SigningMvccIndex.SnapshotRecord> records;
    private final SigningGenerationRegistry.SnapshotPins pins;
    private final List<SigningIndexCapacityBudget.Reservation> reservations;
    private final AtomicBoolean closed = new AtomicBoolean();

    private SigningCurrentSelection(List<SigningMvccIndex.SnapshotRecord> records,
            SigningGenerationRegistry.SnapshotPins pins,
            List<SigningIndexCapacityBudget.Reservation> reservations) {
        this.records = records;
        this.pins = pins;
        this.reservations = reservations;
    }

    // Success transfers both resources to the returned closeable; failure closes them here.
    /**
     * Captures one current record while reserving capacity and pinning its exact artifact generation.
     *
     * <p>Failure before ownership transfer releases every reservation and pin already acquired.</p>
     *
     * @param capacity shared index byte budget
     * @param generations registry retaining exact generation reference ownership
     * @param record current immutable pointer descriptor, or null for an empty selection
     * @return owned immutable selection; caller closes it to release capacity and generation pins
     * @throws NullPointerException if a required collaborator is null
     * @throws SigningIndexCapacityBudget.CapacityExceededException if the fixed selection reservation exceeds the budget
     * @throws IllegalStateException if the selected generation cannot be pinned
     */
    @SuppressWarnings({ "PMD.CloseResource", "PMD.UseTryWithResources" })
    /* default */ static SigningCurrentSelection single(
            SigningIndexCapacityBudget capacity, SigningGenerationRegistry generations,
            SigningMvccIndex.SnapshotRecord record) {
        SigningIndexCapacityBudget.Reservation reservation = capacity.reserve(FIXED_BYTES);
        SigningGenerationRegistry.SnapshotPins pins = null;
        boolean transferred = false;
        try {
            pins = generations.pinSnapshot(record == null
                    ? Set.of() : Set.of(record.pointer().generationId()));
            SigningCurrentSelection result = new SigningCurrentSelection(
                    record == null ? List.of() : List.of(record), pins,
                    List.of(reservation));
            transferred = true;
            return result;
        } finally {
            if (!transferred) {
                if (pins != null) {
                    pins.close();
                }
                reservation.close();
            }
        }
    }

    /**
     * Creates an owned range builder that reserves capacity before capturing pointer growth.
     *
     * @param capacity shared index budget used for fixed and per-record reservations
     * @return owned one-lock-scope builder; close it unless its resources transfer to the built selection
     * @throws NullPointerException if a required collaborator is null
     * @throws SigningIndexCapacityBudget.CapacityExceededException if the fixed builder reservation exceeds the budget
     */
    /* default */ static Builder rangeBuilder(SigningIndexCapacityBudget capacity) {
        return new Builder(capacity);
    }

    /**
     * Returns the immutable selected current-state pointers while this selection remains open.
     *
     * @return retained immutable pointer descriptors in selection order
     * @throws IllegalStateException if this selection was closed
     */
    /* default */ List<SigningMvccIndex.SnapshotRecord> records() {
        requireOpen();
        return records;
    }

    /**
     * Releases the exact generation pins and capacity reservations once.
     *
     * <p>The selection becomes unavailable before cleanup; repeated closure has no effect.</p>
     */
    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            try {
                pins.close();
            } finally {
                release(reservations);
            }
        }
    }

    private void requireOpen() {
        if (closed.get()) {
            throw new IllegalStateException("signing current selection is closed");
        }
    }

    private static void release(List<SigningIndexCapacityBudget.Reservation> reservations) {
        for (int index = reservations.size() - 1; index >= 0; index--) {
            reservations.get(index).close();
        }
    }

    /**
     * One-lock-scope builder that reserves capacity before capturing each growth block.
     */
    /* default */ static final class Builder implements AutoCloseable {
        private final SigningIndexCapacityBudget capacity;
        private final List<SigningIndexCapacityBudget.Reservation> reservations = new ArrayList<>();
        private final List<SigningMvccIndex.SnapshotRecord> records = new ArrayList<>();
        private final Set<Long> generationIds = new HashSet<>();
        private int reservedRecords;
        private boolean transferred;

        private Builder(SigningIndexCapacityBudget capacity) {
            this.capacity = Objects.requireNonNull(capacity, "capacity");
            addReservation(FIXED_BYTES);
        }

        /**
         * Reserves growth capacity before retaining one exact current-state record pointer.
         *
         * @param record non-null current record descriptor; the builder must remain open and untransferred
         * @throws NullPointerException if the record is null
         * @throws SigningIndexCapacityBudget.CapacityExceededException if the next growth block exceeds the capacity budget
         * @throws ArithmeticException if the growth count or byte calculation overflows
         */
        /* default */ void add(SigningMvccIndex.SnapshotRecord record) {
            Objects.requireNonNull(record, "record");
            reserveBeforeCapture();
            records.add(record);
            generationIds.add(record.pointer().generationId());
        }

        // Success transfers pins to the returned closeable; failure releases them here.
        /**
         * Pins the captured generations and transfers all builder capacity reservations to an immutable selection.
         *
         * @param generations registry owning all captured physical pointer generations
         * @return owned selection; caller closes it to release pins and reservations
         * @throws NullPointerException if a required collaborator is null
         * @throws IllegalStateException if the builder already transferred ownership or a captured generation cannot be pinned
         */
        @SuppressWarnings({ "PMD.CloseResource", "PMD.UseTryWithResources" })
        /* default */ SigningCurrentSelection build(SigningGenerationRegistry generations) {
            if (transferred) {
                throw new IllegalStateException("signing current selection builder is closed");
            }
            SigningGenerationRegistry.SnapshotPins pins = generations.pinSnapshot(generationIds);
            boolean built = false;
            try {
                SigningCurrentSelection result = new SigningCurrentSelection(
                        List.copyOf(records), pins, List.copyOf(reservations));
                transferred = true;
                built = true;
                return result;
            } finally {
                if (!built) {
                    pins.close();
                }
            }
        }

        private void reserveBeforeCapture() {
            if (records.size() < reservedRecords) {
                return;
            }
            int increment = reservedRecords == 0 ? INITIAL_RECORDS : reservedRecords;
            addReservation(Math.multiplyExact(increment, RECORD_BYTES));
            reservedRecords = Math.addExact(reservedRecords, increment);
        }

        // The builder owns the reservation after insertion; failed insertion releases it.
        @SuppressWarnings({ "PMD.CloseResource", "PMD.UseTryWithResources" })
        private void addReservation(long bytes) {
            SigningIndexCapacityBudget.Reservation reservation = capacity.reserve(bytes);
            boolean added = false;
            try {
                reservations.add(reservation);
                added = true;
            } finally {
                if (!added) {
                    reservation.close();
                }
            }
        }

        /**
         * Releases capacity still owned by this builder unless it transferred to a selection.
         *
         * <p>Closure is idempotent and prevents another successful build.</p>
         */
        @Override
        public void close() {
            if (!transferred) {
                transferred = true;
                release(reservations);
            }
        }
    }
}
