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
package zeroecho.pki.performance;

import java.util.Objects;

/** Checked deterministic persisted-population plan for one fixed grid cell. */
@SuppressWarnings({ "PMD.AvoidLiteralsInIfCondition", "PMD.CommentDefaultAccessModifier",
        "PMD.PreserveStackTrace" })
final class SigningPopulationPlan {
    private SigningPopulationPlan() {
    }

    static Plan forCell(SigningBenchmarkGrid.Cell cell, SigningBenchmarkConfig configuration) {
        Objects.requireNonNull(cell, "cell");
        Objects.requireNonNull(configuration, "configuration");
        if (!cell.supported() || cell.groupSize() > 32) {
            throw new SigningBenchmarkGrid.ContractException("UNSUPPORTED_MAX_32");
        }
        if (!cell.id().equals(configuration.cellId())
                || cell.retainedPopulation() != configuration.retainedPopulation()
                || cell.activePopulation() != configuration.activePopulation()
                || cell.lanes() != configuration.lanes()
                || cell.groupSize() != configuration.groupSize()) {
            throw new SigningBenchmarkGrid.ContractException("CELL_FINGERPRINT_MISMATCH");
        }
        boolean retainedAxis = cell.retainedPopulation() != SigningBenchmarkGrid.ANCHOR_RETAINED
                && cell.activePopulation() == SigningBenchmarkGrid.ANCHOR_ACTIVE
                && cell.lanes() == SigningBenchmarkGrid.ANCHOR_LANES
                && cell.groupSize() == SigningBenchmarkGrid.ANCHOR_GROUP;
        try {
            if (retainedAxis) {
                return new Plan(Mode.RETAINED_ONLY,
                        Math.subtractExact((long) cell.retainedPopulation(), 1L),
                        0L, 0L, 0L, 1L, cell.retainedPopulation(), cell.retainedPopulation());
            }
            long contextCapacity = cell.activePopulation();
            long preload = 0L;
            long arrivals = Math.addExact(configuration.warmupArrivals(),
                    configuration.measurementArrivals());
            long occupied = Math.addExact(arrivals, contextCapacity);
            occupied = Math.addExact(occupied, 1L);
            long generic = Math.subtractExact((long) cell.retainedPopulation(), occupied);
            if (generic < 0L) {
                throw new SigningBenchmarkGrid.ContractException("POPULATION_SHAPE_IMPOSSIBLE");
            }
            return new Plan(Mode.COMBINED_WORKLOAD, generic, preload, contextCapacity,
                    arrivals, 1L, cell.retainedPopulation(),
                    Math.subtractExact((long) cell.retainedPopulation(), contextCapacity));
        } catch (ArithmeticException overflow) {
            throw new SigningBenchmarkGrid.ContractException("POPULATION_ARITHMETIC_OVERFLOW");
        }
    }

    /** Fixed population/workload relationship for one axis family. */
    enum Mode {
        RETAINED_ONLY,
        COMBINED_WORKLOAD
    }

    /** Immutable checked population counts for one cell. */
    record Plan(Mode mode, long genericRecords, long activePreload, long contextCapacity,
            long arrivals, long watermarkRecords, long maximumCurrentRecords,
            long drainedCurrentRecords) {
        Plan {
            Objects.requireNonNull(mode, "mode");
            if (genericRecords < 0L || activePreload < 0L || contextCapacity < 0L
                    || arrivals < 0L || watermarkRecords != 1L || maximumCurrentRecords <= 0L
                    || drainedCurrentRecords <= 0L || drainedCurrentRecords > maximumCurrentRecords) {
                throw new IllegalArgumentException("signing population plan is invalid");
            }
            if (mode == Mode.RETAINED_ONLY
                    && (activePreload != 0L || contextCapacity != 0L || arrivals != 0L)) {
                throw new IllegalArgumentException("retained-only plan contains active work");
            }
        }
    }
}
