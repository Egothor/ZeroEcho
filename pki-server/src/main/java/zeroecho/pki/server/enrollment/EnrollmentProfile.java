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
package zeroecho.pki.server.enrollment;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable enrollment profile.
 *
 * <p>An enrollment profile groups the policy constraints applied to
 * certificate requests arriving through any enrollment protocol
 * (SCEP, CMP, EST, ACME). Endpoints reference a profile by its
 * {@code id} rather than duplicating policy inline.</p>
 *
 * @param id                 URL-safe profile identity, unique within the realm
 * @param displayName        human-readable label
 * @param state              current lifecycle state
 * @param certificateProfileId certificate profile applied to issued credentials
 * @param allowedAuthorityIds set of CA identities that may issue under this profile;
 *                            empty means any authority is permitted
 * @param subjectDnPattern   optional regex that the requested Subject DN must match
 * @param requiredSanDomains DNS suffixes that must appear as SANs; empty = unconstrained
 * @param requireApproval    whether issuance requires an out-of-band approval
 */
public record EnrollmentProfile(
        String id,
        String displayName,
        EnrollmentProfileState state,
        String certificateProfileId,
        Set<String> allowedAuthorityIds,
        Optional<String> subjectDnPattern,
        List<String> requiredSanDomains,
        boolean requireApproval) {

    /** Validates and defensively copies the record. */
    public EnrollmentProfile {
        if (id == null || !id.matches("[a-zA-Z0-9][a-zA-Z0-9._:-]{0,255}")) {
            throw new IllegalArgumentException("enrollment profile identity is not canonical");
        }
        Objects.requireNonNull(displayName, "displayName");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(certificateProfileId, "certificateProfileId");
        allowedAuthorityIds = Set.copyOf(Objects.requireNonNull(allowedAuthorityIds, "allowedAuthorityIds"));
        Objects.requireNonNull(subjectDnPattern, "subjectDnPattern");
        requiredSanDomains = List.copyOf(Objects.requireNonNull(requiredSanDomains, "requiredSanDomains"));
    }

    /**
     * Returns a copy of this profile with the given state.
     * @param newState non-null replacement state
     * @return a new profile retaining every other field
     * @throws NullPointerException if the state is null
     */
    public EnrollmentProfile withState(EnrollmentProfileState newState) {
        return new EnrollmentProfile(id, displayName, newState, certificateProfileId,
                allowedAuthorityIds, subjectDnPattern, requiredSanDomains, requireApproval);
    }
}
