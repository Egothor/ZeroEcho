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
package zeroecho.pki.spi.ct;

import java.util.List;
import java.util.Objects;

/**
 * Result of a {@link CtJournalStore#verify(long, long)} integrity check.
 *
 * <p>When {@code intact} is {@code true}, every entry in the checked range has a
 * valid hash chain. When {@code intact} is {@code false}, {@code brokenAtSequences}
 * lists the sequence numbers at which the chain is broken — either because the
 * stored {@code entryHash} does not match the re-computed value, or because the
 * {@code previousHash} does not match the prior entry's {@code entryHash}.</p>
 *
 * @param checkedFrom        inclusive first sequence number checked
 * @param checkedTo          inclusive last sequence number checked
 * @param intact             {@code true} if all entries in the range have valid hash chains
 * @param brokenAtSequences  sequence numbers at which chain violations were found;
 *                           empty when {@code intact} is {@code true}
 * @since 1.0
 */
public record CtJournalVerificationResult(
        long checkedFrom,
        long checkedTo,
        boolean intact,
        List<Long> brokenAtSequences) {

    /**
     * Validates the result state.
     *
     * @throws NullPointerException     if {@code brokenAtSequences} is {@code null}
     * @throws IllegalArgumentException if {@code checkedFrom} is not positive,
     *                                  if {@code checkedTo} is less than {@code checkedFrom},
     *                                  or if {@code intact} is {@code true} but {@code brokenAtSequences}
     *                                  is non-empty
     */
    public CtJournalVerificationResult {
        Objects.requireNonNull(brokenAtSequences, "brokenAtSequences");
        if (checkedFrom <= 0) {
            throw new IllegalArgumentException("checkedFrom must be positive");
        }
        if (checkedTo < checkedFrom) {
            throw new IllegalArgumentException("checkedTo must not be less than checkedFrom");
        }
        if (intact && !brokenAtSequences.isEmpty()) {
            throw new IllegalArgumentException("intact result must have an empty brokenAtSequences list");
        }
        brokenAtSequences = List.copyOf(brokenAtSequences);
    }
}
