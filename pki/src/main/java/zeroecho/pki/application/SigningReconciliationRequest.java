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

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import zeroecho.core.io.CancellationSignal;

/**
 * Immutable bounds for one transport-neutral signing reconciliation pass.
 *
 * @param continuation complete scan-cycle continuation returned by the preceding
 *        pass, or {@link SigningReconciliationContinuation#start()} for the
 *        first pass
 * @param maximumRecords maximum records examined, from 1 through 4096
 * @param maximumProviderCalls maximum provider calls, from 1 through
 *        {@code maximumRecords}
 * @param deadline absolute pass deadline
 * @param providerCallTimeout positive timeout for each provider call; the
 *        reconciler clamps each call to the absolute pass deadline
 * @param cancellation cooperative pass cancellation
 */
public record SigningReconciliationRequest(SigningReconciliationContinuation continuation,
        int maximumRecords, int maximumProviderCalls, Instant deadline,
        Duration providerCallTimeout, CancellationSignal cancellation) {

    /**
     * Creates the next bounded pass while carrying the preceding result's
     * complete continuation state.
     *
     * @param previous preceding pass result
     * @param maximumRecords maximum records examined, from 1 through 4096
     * @param maximumProviderCalls maximum provider calls, from 1 through
     *        {@code maximumRecords}
     * @param deadline absolute pass deadline
     * @param providerCallTimeout positive timeout for each provider call
     * @param cancellation cooperative pass cancellation
     * @return validated request continuing the same scan cycle
     */
    public static SigningReconciliationRequest continueFrom(SigningReconciliationResult previous,
            int maximumRecords, int maximumProviderCalls, Instant deadline,
            Duration providerCallTimeout, CancellationSignal cancellation) {
        Objects.requireNonNull(previous, "previous");
        return new SigningReconciliationRequest(previous.continuation(), maximumRecords,
                maximumProviderCalls, deadline, providerCallTimeout, cancellation);
    }

    /** Validates and snapshots one pass request. */
    public SigningReconciliationRequest {
        continuation = Objects.requireNonNull(continuation, "continuation");
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
    }
}
