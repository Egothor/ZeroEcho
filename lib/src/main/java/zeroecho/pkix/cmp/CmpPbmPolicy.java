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

package zeroecho.pkix.cmp;

import java.util.Set;

/**
 * Immutable PBM work and algorithm limits, checked before iterative derivation.
 * Supported algorithms are SHA-256/384/512 and HMAC-SHA-256/384/512, expressed by
 * standard OIDs. This policy owns no secret and grants no requester authority.
 *
 * @param minimumIterations positive work floor
 * @param maximumIterations work ceiling, at most one million
 * @param minimumSaltBytes salt floor, at least sixteen
 * @param maximumSaltBytes salt ceiling, at most sixty-four
 * @param digestOids nonempty allowed standard digest OIDs
 * @param macOids nonempty allowed standard HMAC OIDs
 */
public record CmpPbmPolicy(int minimumIterations, int maximumIterations,
        int minimumSaltBytes, int maximumSaltBytes, Set<String> digestOids, Set<String> macOids) {
    /**
     * Validates and snapshots the bounded policy.
     * @throws IllegalArgumentException if a work, salt or algorithm bound is invalid
     * @throws NullPointerException if a set or its member is null
     */
    public CmpPbmPolicy {
        digestOids = Set.copyOf(digestOids);
        macOids = Set.copyOf(macOids);
        if (minimumIterations < 1 || maximumIterations < minimumIterations || maximumIterations > 1_000_000
                || minimumSaltBytes < 16 || maximumSaltBytes < minimumSaltBytes || maximumSaltBytes > 64
                || digestOids.isEmpty() || macOids.isEmpty()
                || !Set.of("2.16.840.1.101.3.4.2.1", "2.16.840.1.101.3.4.2.2", "2.16.840.1.101.3.4.2.3").containsAll(digestOids)
                || !Set.of("1.2.840.113549.2.9", "1.2.840.113549.2.10", "1.2.840.113549.2.11").containsAll(macOids)) {
            throw new IllegalArgumentException("CMP PBM policy is invalid");
        }
    }
}

