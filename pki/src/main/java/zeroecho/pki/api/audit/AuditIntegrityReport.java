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
package zeroecho.pki.api.audit;

import java.util.Optional;

/**
 * Safe result of verifying the tamper-evident hash chain over an append-only
 * audit log.
 *
 * <p>
 * The report is deliberately payload-free: it names only the outcome, the number
 * of chained records inspected, the observed head, and — when the chain is
 * broken — the sequence at which verification first failed. It never carries an
 * event's actor, object, or details, so it can be surfaced to operators and
 * regulators without disclosing audited content.
 * </p>
 *
 * @param status               closed outcome classification
 * @param recordCount          number of chained records inspected
 * @param firstBrokenSequence  sequence at which verification first failed; empty
 *                             when {@link Status#INTACT}
 * @param head                 observed head recomputed from the log
 */
public record AuditIntegrityReport(Status status, long recordCount, Optional<Long> firstBrokenSequence,
        AuditChainHead head) {

    /** Closed classification of an audit integrity verification. */
    public enum Status {
        /** The chain is contiguous, correctly linked, and matches the expected head. */
        INTACT,
        /** A record's recomputed hash does not match its stored hash (content altered). */
        RECORD_MUTATED,
        /** A record's stored previous-hash does not link to the prior record (insertion/reorder). */
        CHAIN_BROKEN,
        /** The sequence is not contiguous from zero (a record was deleted). */
        SEQUENCE_GAP,
        /** The same sequence appears more than once (a record was duplicated). */
        DUPLICATE_SEQUENCE,
        /** The chain is internally consistent but the head differs from the trusted anchor (truncation). */
        HEAD_MISMATCH
    }

    /**
     * Validates the report.
     *
     * @throws IllegalArgumentException if required values are absent or inconsistent
     */
    public AuditIntegrityReport {
        if (status == null) {
            throw new IllegalArgumentException("status must not be null");
        }
        if (isNegative(recordCount)) {
            throw new IllegalArgumentException("recordCount must not be negative");
        }
        firstBrokenSequence = firstBrokenSequence == null ? Optional.empty() : firstBrokenSequence;
        if (head == null) {
            throw new IllegalArgumentException("head must not be null");
        }
        if (status == Status.INTACT && firstBrokenSequence.isPresent()) {
            throw new IllegalArgumentException("an intact chain has no broken sequence");
        }
    }

    private static boolean isNegative(long value) {
        return value < 0L;
    }

    /**
     * Indicates whether the chain verified cleanly.
     *
     * @return {@code true} only when the status is {@link Status#INTACT}
     */
    public boolean intact() {
        return status == Status.INTACT;
    }
}
