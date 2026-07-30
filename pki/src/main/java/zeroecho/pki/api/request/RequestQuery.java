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
package zeroecho.pki.api.request;

import java.time.Instant;
import java.util.Optional;

import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.SubjectRef;

/**
 * Query constraints for searching stored certification requests.
 *
 * @param formatId      optional framework filter
 * @param subjectRef    optional subject filter
 * @param createdAfter  optional lower bound (inclusive) for request creation
 *                      time
 * @param createdBefore optional upper bound (exclusive) for request creation
 *                      time
 * @param profileId     optional profile filter (requested or resolved profile
 *                      id depending on implementation)
 */
public record RequestQuery(Optional<FormatId> formatId, Optional<SubjectRef> subjectRef, Optional<Instant> createdAfter,
        Optional<Instant> createdBefore, Optional<String> profileId) {

    /**
     * Creates a request query.
     *
     * @param formatId      optional format filter
     * @param subjectRef    optional subject filter
     * @param createdAfter  optional lower time bound
     * @param createdBefore optional upper time bound
     * @param profileId     optional profile id filter
     * @throws IllegalArgumentException if any optional container is null
     */
    public RequestQuery {
        if (formatId == null || subjectRef == null || createdAfter == null || createdBefore == null
                || profileId == null) {
            throw new IllegalArgumentException("optional fields must not be null");
        }
    }
}
