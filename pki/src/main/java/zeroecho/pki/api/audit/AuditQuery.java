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
package zeroecho.pki.api.audit;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.PkiId;

/**
 * Query constraints for searching audit events.
 *
 * <p>
 * Every search is bounded: {@code limit} is clamped to {@link #MAXIMUM_LIMIT} so
 * a query can never materialize an unbounded result. {@code requiredDetails}
 * matches events whose {@link AuditEvent#details()} contain every supplied
 * key/value pair, which lets callers reconstruct one operation's evidence chain
 * by its shared operation commitment without exposing event payloads.
 * </p>
 *
 * @param category        optional category filter
 * @param action          optional action filter
 * @param after           optional lower bound for event time
 * @param before          optional upper bound for event time
 * @param objectId        optional object id filter
 * @param principalName   optional principal name filter
 * @param requiredDetails detail key/value pairs that must all be present
 * @param limit           maximum number of events returned (bounded)
 */
public record AuditQuery(Optional<String> category, Optional<String> action, Optional<Instant> after,
        Optional<Instant> before, Optional<PkiId> objectId, Optional<String> principalName,
        Map<String, String> requiredDetails, int limit) {

    /** Hard upper bound enforced on every audit search result. */
    public static final int MAXIMUM_LIMIT = 10_000;

    /**
     * Creates a bounded audit query.
     *
     * @throws IllegalArgumentException if any optional container is null
     */
    public AuditQuery {
        if (category == null || action == null || after == null || before == null || objectId == null
                || principalName == null) {
            throw new IllegalArgumentException("optional fields must not be null");
        }
        requiredDetails = Map.copyOf(Objects.requireNonNull(requiredDetails, "requiredDetails"));
        if (limit <= 0 || limit > MAXIMUM_LIMIT) {
            limit = MAXIMUM_LIMIT;
        }
    }

    /**
     * Creates a query with no detail filter and the maximum bound; retained so
     * existing six-argument callers remain source-compatible.
     *
     * @param category      optional category filter
     * @param action        optional action filter
     * @param after         optional lower bound for event time
     * @param before        optional upper bound for event time
     * @param objectId      optional object id filter
     * @param principalName optional principal name filter
     */
    public AuditQuery(Optional<String> category, Optional<String> action, Optional<Instant> after,
            Optional<Instant> before, Optional<PkiId> objectId, Optional<String> principalName) {
        this(category, action, after, before, objectId, principalName, Map.of(), MAXIMUM_LIMIT);
    }
}
