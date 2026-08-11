/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.application;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.io.CancellationSignal;

/**
 * Immutable bounds for one transport-neutral signing reconciliation pass.
 *
 * @param cursor opaque exclusive cursor returned by an earlier pass
 * @param maximumRecords maximum records examined, from 1 through 4096
 * @param maximumProviderCalls maximum provider calls, from 1 through
 *        {@code maximumRecords}
 * @param deadline absolute pass deadline
 * @param providerCallTimeout positive timeout for each provider call; the
 *        reconciler clamps each call to the absolute pass deadline
 * @param cancellation cooperative pass cancellation
 */
public record SigningReconciliationRequest(Optional<String> cursor, int maximumRecords,
        int maximumProviderCalls, Instant deadline, Duration providerCallTimeout,
        CancellationSignal cancellation) {

    /** Validates and snapshots one pass request. */
    public SigningReconciliationRequest {
        cursor = Objects.requireNonNull(cursor, "cursor");
        if (maximumRecords < 1 || maximumRecords > 4096) {
            throw new IllegalArgumentException("maximumRecords must be between 1 and 4096");
        }
        if (maximumProviderCalls < 1 || maximumProviderCalls > maximumRecords) {
            throw new IllegalArgumentException("maximumProviderCalls must be between 1 and maximumRecords");
        }
        Objects.requireNonNull(deadline, "deadline");
        Objects.requireNonNull(providerCallTimeout, "providerCallTimeout");
        Objects.requireNonNull(cancellation, "cancellation");
        if (providerCallTimeout.isZero() || providerCallTimeout.isNegative()) {
            throw new IllegalArgumentException("providerCallTimeout must be positive");
        }
        cursor.ifPresent(value -> {
            if (value.isBlank() || value.length() > 4096) {
                throw new IllegalArgumentException("cursor is invalid");
            }
            for (int index = 0; index < value.length(); index++) {
                char current = value.charAt(index);
                if (current < 0x21 || current > 0x7e || current == '/' || current == '\\') {
                    throw new IllegalArgumentException("cursor is invalid");
                }
            }
        });
    }
}
