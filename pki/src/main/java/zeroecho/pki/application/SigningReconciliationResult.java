/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.application;

import java.util.Objects;
import java.util.Optional;

/**
 * Aggregate safe outcome of one bounded signing reconciliation pass.
 *
 * @param nextCursor opaque exclusive cursor for the next pass
 * @param examined records examined
 * @param progressed records whose durable state progressed
 * @param unresolved records still requiring reconciliation
 * @param retryable records deferred after an isolated retryable failure
 * @param endReached whether the pass reached the end of the ordered record set
 */
public record SigningReconciliationResult(Optional<String> nextCursor, int examined,
        int progressed, int unresolved, int retryable, boolean endReached) {

    /** Validates aggregate counts. */
    public SigningReconciliationResult {
        nextCursor = Objects.requireNonNull(nextCursor, "nextCursor");
        if (examined < 0 || progressed < 0 || unresolved < 0 || retryable < 0
                || progressed > examined || unresolved > examined || retryable > examined) {
            throw new IllegalArgumentException("Signing reconciliation counts are inconsistent");
        }
    }
}
