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
package zeroecho.pki.util.async;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Non-sensitive status snapshot of an asynchronous operation.
 *
 * <p>
 * This object is safe to expose via APIs and logs (assuming the producer
 * respects the no-secrets constraint for detail fields).
 * </p>
 *
 * @param state      lifecycle state (never {@code null})
 * @param updatedAt  last update time (never {@code null})
 * @param detailCode optional stable, non-sensitive code suitable for audit and
 *                   transport
 * @param details    optional key/value details; values MUST NOT contain secrets
 */
public record AsyncStatus(AsyncState state, Instant updatedAt, Optional<String> detailCode,
        Map<String, String> details) {

    /**
     * Creates a status record and validates invariants.
     *
     * @throws IllegalArgumentException if any mandatory field is null
     */
    public AsyncStatus {
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(updatedAt, "updatedAt");
        Objects.requireNonNull(detailCode, "detailCode");
        Objects.requireNonNull(details, "details");
    }

    /**
     * Returns whether this status is terminal.
     *
     * @return true if terminal
     */
    public boolean isTerminal() {
        return state == AsyncState.SUCCEEDED || state == AsyncState.FAILED || state == AsyncState.CANCELLED
                || state == AsyncState.EXPIRED;
    }
}
