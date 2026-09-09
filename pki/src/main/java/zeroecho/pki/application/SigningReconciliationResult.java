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

/**
 * Aggregate safe outcome of one bounded signing reconciliation pass.
 *
 * <p>{@link #continuation()} is the indivisible state of the ordered scan. Pass
 * it unchanged to the next request, preferably through
 * {@link SigningReconciliationRequest#continueFrom}; carrying only its cursor
 * would begin a different scan cycle and forfeit the frozen fairness boundary.</p>
 *
 * @param continuation complete continuation after the last metadata candidate
 *        dispositioned by this pass, or the request continuation when none was
 *        dispositioned
 * @param examined metadata candidates dispositioned, including malformed entries
 * @param progressed records whose durable state progressed
 * @param unresolved records still requiring reconciliation plus metadata
 *        candidates that could not be decoded
 * @param retryable records deferred after an isolated retryable failure plus
 *        metadata candidates that could not be decoded
 * @param endReached whether the pass reached the end of the ordered record set
 */
public record SigningReconciliationResult(SigningReconciliationContinuation continuation,
        int examined, int progressed, int unresolved, int retryable, boolean endReached) {

    /** Validates aggregate counts. */
    public SigningReconciliationResult {
        continuation = Objects.requireNonNull(continuation, "continuation");
        if (examined < 0 || progressed < 0 || unresolved < 0 || retryable < 0
                || progressed > examined || unresolved > examined || retryable > examined) {
            throw new IllegalArgumentException("Signing reconciliation counts are inconsistent");
        }
    }
}
