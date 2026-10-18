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
package zeroecho.pki.server.cmp;

import java.util.Objects;

/**
 * Immutable binding that maps a CMP path suffix to a CA authority, an issuance profile,
 * and a required PKIMessage protection policy.
 *
 * <p>Endpoints are registered and de-registered via the admin API and held in the
 * {@link CmpService} endpoint registry. The {@code label} value appears in the CMP
 * URL path under {@code /pkix/{label}}.</p>
 *
 * @param label            URL-safe identifier, 1–64 characters, matching {@code [A-Za-z0-9._-]+}
 * @param authorityId      the CA authority identifier whose chain is served on this endpoint
 * @param profileId        the issuance profile identifier applied to enrollment requests
 * @param enrollmentProfileId mandatory enrollment policy identity, distinct from the issuance profile
 * @param protectionPolicy the PKIMessage protection policy required for this endpoint
 * @since 1.0
 */
public record CmpEndpoint(
        String label,
        String authorityId,
        String profileId,
        String enrollmentProfileId,
        CmpProtectionPolicy protectionPolicy) implements zeroecho.pki.server.enrollment.EnrollmentEndpoint {

    /** Maximum permitted label length. */
    public static final int MAX_LABEL_LENGTH = 64;

    /** Validates all fields. */
    public CmpEndpoint {
        Objects.requireNonNull(label, "label");
        Objects.requireNonNull(authorityId, "authorityId");
        Objects.requireNonNull(profileId, "profileId");
        zeroecho.pki.server.enrollment.EnrollmentEndpoint.requireProfileId(authorityId);
        zeroecho.pki.server.enrollment.EnrollmentEndpoint.requireProfileId(profileId);
        zeroecho.pki.server.enrollment.EnrollmentEndpoint.requireProfileId(enrollmentProfileId);
        Objects.requireNonNull(protectionPolicy, "protectionPolicy");
        if (label.isBlank() || label.length() > MAX_LABEL_LENGTH
                || !label.matches("[A-Za-z0-9._-]+")) {
            throw new IllegalArgumentException(
                    "CMP label must be 1–" + MAX_LABEL_LENGTH + " URL-safe characters: " + label);
        }
        if (authorityId.isBlank()) {
            throw new IllegalArgumentException("authorityId must not be blank");
        }
        if (profileId.isBlank()) {
            throw new IllegalArgumentException("profileId must not be blank");
        }
    }
}
