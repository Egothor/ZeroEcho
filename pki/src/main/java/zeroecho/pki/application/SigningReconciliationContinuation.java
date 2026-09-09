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
package zeroecho.pki.application;

import java.util.Objects;
import java.util.Optional;

/**
 * Validated continuation state for an ordered signing-reconciliation scan cycle.
 *
 * <p>The cursor and frozen cycle boundaries form one indivisible value. Callers
 * continuing a scan must carry this value unchanged from
 * {@link SigningReconciliationResult#continuation()} into the next request.
 * Use {@link SigningReconciliationRequest#continueFrom} when pass bounds also
 * need to be replaced.</p>
 *
 * @param cursor opaque exclusive cursor after the last candidate dispositioned;
 *        while unwrapped it does not exceed the high-watermark; while wrapped
 *        it lies within the prefix, except that it may equal the high-watermark
 *        during the transition into the prefix
 * @param cycleHighWatermark stable greatest key captured for the active cycle,
 *        or empty before a cycle begins and after it completes
 * @param cycleWrapUpperBound inclusive upper bound of the wrapped prefix,
 *        captured from the cursor that began the cycle; empty when the cycle
 *        began at the first key or is complete; when present it does not exceed
 *        the cycle high-watermark
 * @param cycleWrapped whether the active cycle is scanning its wrapped prefix
 */
public record SigningReconciliationContinuation(Optional<String> cursor,
        Optional<String> cycleHighWatermark, Optional<String> cycleWrapUpperBound,
        boolean cycleWrapped) {

    /**
     * Creates continuation state for a scan beginning at the first key.
     *
     * @return initial continuation state
     */
    public static SigningReconciliationContinuation start() {
        return start(Optional.empty());
    }

    /**
     * Creates continuation state for a new scan cycle.
     *
     * @param cursor advisory exclusive starting cursor
     * @return validated new-cycle continuation
     */
    public static SigningReconciliationContinuation start(Optional<String> cursor) {
        return new SigningReconciliationContinuation(cursor, Optional.empty(), Optional.empty(), false);
    }

    /** Validates and snapshots the complete continuation value. */
    public SigningReconciliationContinuation {
        cursor = Objects.requireNonNull(cursor, "cursor");
        cycleHighWatermark = Objects.requireNonNull(cycleHighWatermark, "cycleHighWatermark");
        cycleWrapUpperBound = Objects.requireNonNull(cycleWrapUpperBound, "cycleWrapUpperBound");
        if (cycleWrapped && (cycleHighWatermark.isEmpty() || cycleWrapUpperBound.isEmpty())) {
            throw new IllegalArgumentException("A wrapped signing cycle requires both cycle boundaries");
        }
        if (cycleHighWatermark.isEmpty() && cycleWrapUpperBound.isPresent()) {
            throw new IllegalArgumentException("A signing cycle wrap boundary requires a high-watermark");
        }
        cursor.ifPresent(SigningReconciliationContinuation::validateCursor);
        cycleHighWatermark.ifPresent(SigningReconciliationContinuation::validateCursor);
        cycleWrapUpperBound.ifPresent(SigningReconciliationContinuation::validateCursor);
        validateOrdering(cursor, cycleHighWatermark, cycleWrapUpperBound, cycleWrapped);
    }

    private static void validateOrdering(Optional<String> cursor, Optional<String> highWatermark,
            Optional<String> wrapUpperBound, boolean wrapped) {
        if (highWatermark.isEmpty()) {
            return;
        }
        String high = highWatermark.orElseThrow();
        if (wrapUpperBound.filter(bound -> bound.compareTo(high) > 0).isPresent()) {
            throw new IllegalArgumentException("The signing cycle wrap boundary exceeds its high-watermark");
        }
        if (!wrapped) {
            if (cursor.filter(current -> current.compareTo(high) > 0).isPresent()) {
                throw new IllegalArgumentException("An unwrapped signing cycle cursor exceeds its high-watermark");
            }
            if (wrapUpperBound.isPresent() && (cursor.isEmpty()
                    || cursor.orElseThrow().compareTo(wrapUpperBound.orElseThrow()) < 0)) {
                throw new IllegalArgumentException("An unwrapped signing cycle cursor precedes its wrap boundary");
            }
            return;
        }
        if (cursor.isEmpty()) {
            throw new IllegalArgumentException("A wrapped signing cycle requires a cursor");
        }
        String current = cursor.orElseThrow();
        String wrap = wrapUpperBound.orElseThrow();
        if (current.compareTo(wrap) > 0 && !current.equals(high)) {
            throw new IllegalArgumentException("A wrapped signing cycle cursor is outside its prefix");
        }
    }

    private static void validateCursor(String value) {
        if (value.isBlank() || value.length() > 4096) {
            throw new IllegalArgumentException("cursor is invalid");
        }
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (current < 0x21 || current > 0x7e || current == '/' || current == '\\') {
                throw new IllegalArgumentException("cursor is invalid");
            }
        }
    }
}
