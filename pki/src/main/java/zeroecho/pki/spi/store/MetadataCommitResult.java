/* *****************************************************************************
 * Copyright (C) 2025, Leo Galambos
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
package zeroecho.pki.spi.store;

import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

/**
 * Immutable immediate or resolved metadata-transaction result.
 *
 * <p>A {@link Outcome#COMMITTED} outcome is the only immediate result that
 * authorizes durable metadata success. {@link Outcome#UNKNOWN} is uncertainty
 * about an already fixed attempt; it implies neither commit nor rollback and
 * must be resolved through the owning store.</p>
 *
 * @param transactionId store-issued transaction identity
 * @param outcome semantic outcome
 * @param committedRevision committed store revision when known
 * @param failureCategory stable safe failure category when applicable
 */
public record MetadataCommitResult(MetadataTransactionId transactionId, Outcome outcome,
        OptionalLong committedRevision, Optional<FailureCategory> failureCategory) {
    /** Closed commit-outcome model. */
    public enum Outcome {
        /** Every mutation was durably committed and atomically visible. */ COMMITTED,
        /** No mutation from the transaction became committed. */ NOT_COMMITTED,
        /** The immediate caller cannot yet determine the fixed durable outcome. */ UNKNOWN
    }

    /** Stable non-sensitive metadata failure categories. */
    public enum FailureCategory {
        /** Create or expected-revision precondition failed. */ CONFLICT,
        /** Transaction identity belongs to another store. */ FOREIGN_TRANSACTION,
        /** Transaction identity was never issued by this store. */ TRANSACTION_NOT_ISSUED,
        /**
         * The transaction was durably issued but had no authoritative terminal
         * outcome when recovery closed its preceding recovery epoch.
         *
         * <p>This category is a definitive non-commit. It is neither an
         * uncertain outcome nor a storage failure.</p>
         */
        ABANDONED_BY_RECOVERY,
        /** Durable storage or content I/O failed. */ STORAGE_FAILURE,
        /** Adapter technical representability limit was exceeded. */ LIMIT_EXCEEDED,
        /** Adapter lacks an optional requested capability. */ UNSUPPORTED_CAPABILITY,
        /** Stored metadata failed integrity validation. */ INTEGRITY_FAILURE,
        /** Cooperative cancellation was requested. */ CANCELLED
    }

    /** Validates result invariants and checked revision semantics. */
    public MetadataCommitResult {
        Objects.requireNonNull(transactionId, "transactionId");
        Objects.requireNonNull(outcome, "outcome");
        Objects.requireNonNull(committedRevision, "committedRevision");
        Objects.requireNonNull(failureCategory, "failureCategory");
        if (committedRevision.isPresent() && committedRevision.getAsLong() < 0L) {
            throw new IllegalArgumentException("Committed revision must not be negative");
        }
        if (outcome == Outcome.COMMITTED
                && (committedRevision.isEmpty() || failureCategory.isPresent())) {
            throw new IllegalArgumentException(
                    "COMMITTED requires one revision and no failure category");
        }
        if (outcome != Outcome.COMMITTED && committedRevision.isPresent()) {
            throw new IllegalArgumentException("Only COMMITTED may carry a revision");
        }
    }
}
