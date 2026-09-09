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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Fixed orthogonal Increment-13 benchmark-cell contract. */
final class SigningBenchmarkGrid {
    static final int ANCHOR_RETAINED = 1_000_000;
    static final int ANCHOR_ACTIVE = 100_000;
    static final int ANCHOR_LANES = 16;
    static final int ANCHOR_GROUP = 32;
    static final int CELL_COUNT = 11;
    static final String ANCHOR_ID = id(ANCHOR_RETAINED, ANCHOR_ACTIVE, ANCHOR_LANES, ANCHOR_GROUP);

    private static final List<Cell> CELLS = buildCells();

    private SigningBenchmarkGrid() {
    }

    static List<Cell> cells() {
        verifyDefinition(CELLS);
        return CELLS;
    }

    static Cell requireSelected(SigningBenchmarkConfig configuration) {
        Objects.requireNonNull(configuration, "configuration");
        verifyDefinition(CELLS);
        if (configuration.groupSize() == 64) {
            throw new ContractException("UNSUPPORTED_MAX_32");
        }
        if (configuration.cellMode() != SigningBenchmarkConfig.CellMode.GRID) {
            throw new ContractException("CELL_MODE_NOT_GRID");
        }
        Cell selected = CELLS.stream().filter(cell -> cell.id().equals(configuration.cellId()))
                .findFirst().orElseThrow(() -> new ContractException("CELL_ID_UNKNOWN"));
        if (!selected.supported()) {
            throw new ContractException("UNSUPPORTED_MAX_32");
        }
        if (selected.retainedPopulation() != configuration.retainedPopulation()
                || selected.activePopulation() != configuration.activePopulation()
                || selected.lanes() != configuration.lanes()
                || selected.groupSize() != configuration.groupSize()) {
            throw new ContractException("CELL_FINGERPRINT_MISMATCH");
        }
        return selected;
    }

    static void verifyDefinition(List<Cell> cells) {
        Objects.requireNonNull(cells, "cells");
        if (cells.size() != CELL_COUNT) {
            throw new ContractException("GRID_INCOMPLETE");
        }
        Set<String> ids = new HashSet<>();
        Set<String> fingerprints = new HashSet<>();
        for (Cell cell : cells) {
            if (!ids.add(cell.id()) || !fingerprints.add(cell.fingerprint())) {
                throw new ContractException("GRID_DUPLICATE");
            }
        }
        requireAxis(cells, Axis.RETAINED, Set.of(1_000, 100_000, ANCHOR_RETAINED));
        requireAxis(cells, Axis.ACTIVE, Set.of(10, 1_000, ANCHOR_ACTIVE));
        requireAxis(cells, Axis.LANES, Set.of(1, 8, ANCHOR_LANES, 32));
        requireAxis(cells, Axis.GROUP, Set.of(1, 8, ANCHOR_GROUP, 64));
        if (!cells.getFirst().id().equals(ANCHOR_ID)
                || cells.stream().filter(cell -> !cell.supported()).count() != 1L
                || cells.stream().filter(cell -> !cell.supported()).findFirst().orElseThrow().groupSize() != 64) {
            throw new ContractException("GRID_ORDER_OR_BOUNDARY_INVALID");
        }
    }

    private static List<Cell> buildCells() {
        List<Cell> cells = new ArrayList<>(CELL_COUNT);
        cells.add(cell(ANCHOR_RETAINED, ANCHOR_ACTIVE, ANCHOR_LANES, ANCHOR_GROUP, true));
        cells.add(cell(1_000, ANCHOR_ACTIVE, ANCHOR_LANES, ANCHOR_GROUP, true));
        cells.add(cell(100_000, ANCHOR_ACTIVE, ANCHOR_LANES, ANCHOR_GROUP, true));
        cells.add(cell(ANCHOR_RETAINED, 10, ANCHOR_LANES, ANCHOR_GROUP, true));
        cells.add(cell(ANCHOR_RETAINED, 1_000, ANCHOR_LANES, ANCHOR_GROUP, true));
        cells.add(cell(ANCHOR_RETAINED, ANCHOR_ACTIVE, 1, ANCHOR_GROUP, true));
        cells.add(cell(ANCHOR_RETAINED, ANCHOR_ACTIVE, 8, ANCHOR_GROUP, true));
        cells.add(cell(ANCHOR_RETAINED, ANCHOR_ACTIVE, 32, ANCHOR_GROUP, true));
        cells.add(cell(ANCHOR_RETAINED, ANCHOR_ACTIVE, ANCHOR_LANES, 1, true));
        cells.add(cell(ANCHOR_RETAINED, ANCHOR_ACTIVE, ANCHOR_LANES, 8, true));
        cells.add(cell(ANCHOR_RETAINED, ANCHOR_ACTIVE, ANCHOR_LANES, 64, false));
        return List.copyOf(cells);
    }

    private static Cell cell(int retained, int active, int lanes, int group, boolean supported) {
        return new Cell(id(retained, active, lanes, group), retained, active, lanes, group, supported);
    }

    private static String id(int retained, int active, int lanes, int group) {
        return "m" + retained + "-w" + active + "-l" + lanes + "-g" + group;
    }

    private static void requireAxis(List<Cell> cells, Axis axis, Set<Integer> expected) {
        Set<Integer> actual = new HashSet<>();
        for (Cell cell : cells) {
            if (axis.isAxisCell(cell)) {
                actual.add(axis.value(cell));
            }
        }
        if (!actual.equals(expected)) {
            throw new ContractException("GRID_INCOMPLETE");
        }
    }

    record Cell(String id, int retainedPopulation, int activePopulation, int lanes,
            int groupSize, boolean supported) {
        Cell {
            Objects.requireNonNull(id, "id");
            if (retainedPopulation <= 0 || activePopulation <= 0 || lanes <= 0 || groupSize <= 0) {
                throw new IllegalArgumentException("benchmark cell fields must be positive");
            }
        }

        private String fingerprint() {
            return retainedPopulation + ":" + activePopulation + ":" + lanes + ":" + groupSize;
        }
    }

    static final class ContractException extends IllegalArgumentException {
        private static final long serialVersionUID = -218412902463347323L;
        private final String reasonCode;
        private final List<String> details;

        ContractException(String reasonCode) {
            this(reasonCode, List.of());
        }

        ContractException(String reasonCode, List<String> details) {
            super(message(reasonCode, details));
            this.reasonCode = Objects.requireNonNull(reasonCode, "reasonCode");
            this.details = List.copyOf(details);
        }

        private static String message(String reasonCode, List<String> details) {
            String checkedReasonCode = Objects.requireNonNull(reasonCode, "reasonCode");
            List<String> checkedDetails = List.copyOf(details);
            if (checkedDetails.isEmpty()) {
                return "signing benchmark contract rejected: code=" + checkedReasonCode;
            }
            return "signing benchmark contract rejected: code=" + checkedReasonCode
                    + ", details=" + String.join("; ", checkedDetails);
        }

        String reasonCode() {
            return reasonCode;
        }

        List<String> details() {
            return details;
        }
    }

    private enum Axis {
        RETAINED {
            @Override boolean isAxisCell(Cell cell) {
                return cell.activePopulation() == ANCHOR_ACTIVE && cell.lanes() == ANCHOR_LANES
                        && cell.groupSize() == ANCHOR_GROUP;
            }
            @Override int value(Cell cell) { return cell.retainedPopulation(); }
        },
        ACTIVE {
            @Override boolean isAxisCell(Cell cell) {
                return cell.retainedPopulation() == ANCHOR_RETAINED && cell.lanes() == ANCHOR_LANES
                        && cell.groupSize() == ANCHOR_GROUP;
            }
            @Override int value(Cell cell) { return cell.activePopulation(); }
        },
        LANES {
            @Override boolean isAxisCell(Cell cell) {
                return cell.retainedPopulation() == ANCHOR_RETAINED
                        && cell.activePopulation() == ANCHOR_ACTIVE && cell.groupSize() == ANCHOR_GROUP;
            }
            @Override int value(Cell cell) { return cell.lanes(); }
        },
        GROUP {
            @Override boolean isAxisCell(Cell cell) {
                return cell.retainedPopulation() == ANCHOR_RETAINED
                        && cell.activePopulation() == ANCHOR_ACTIVE && cell.lanes() == ANCHOR_LANES;
            }
            @Override int value(Cell cell) { return cell.groupSize(); }
        };

        abstract boolean isAxisCell(Cell cell);
        abstract int value(Cell cell);
    }
}
