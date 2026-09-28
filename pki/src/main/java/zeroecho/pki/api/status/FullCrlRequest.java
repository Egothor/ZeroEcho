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

package zeroecho.pki.api.status;

import java.time.Duration;
import java.util.Objects;
import zeroecho.pki.api.PkiId;

/**
 * Immutable request to prepare a full X.509 CRL for one explicitly selected
 * issuer generation. This is status signing, not new credential issuance:
 * active and retired generations and authorities are eligible, subject to
 * credential validity, CRL signing usage and current algorithm policy.
 *
 * <p>The preparation time is captured by the runtime. {@code thisUpdate} is
 * that time truncated to whole seconds; {@code nextUpdate} is
 * {@code thisUpdate + validity}, also truncated to whole seconds. Preparation
 * rejects arithmetic or X.509 time overflow, an empty encoded interval, or an
 * interval extending beyond the selected issuer credential's expiration.
 * There is no fixed maximum duration independent of that credential.</p>
 *
 * @param issuerGenerationId exact generation, never an implicit current selection
 * @param validity positive requested interval from thisUpdate to nextUpdate
 */
public record FullCrlRequest(PkiId issuerGenerationId, Duration validity) {
    /**
     * Creates a request without performing store access or reserving a CRL number.
     * Subsecond and large positive durations are checked against the captured
     * time and exact credential during preparation.
     *
     * @throws NullPointerException if either argument is null
     * @throws IllegalArgumentException if validity is zero or negative
     */
    public FullCrlRequest {
        Objects.requireNonNull(issuerGenerationId, "issuerGenerationId");
        Objects.requireNonNull(validity, "validity");
        if (validity.isZero() || validity.isNegative()) {
            throw new IllegalArgumentException("Full CRL validity must be positive");
        }
    }
}
