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
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

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
 * @param subjectDnPattern optional bounded pattern of literal text and {@code .*}
 *                         wildcards; see {@link EnrollmentSubjectPattern}
 * @param requiredSanDomains DNS suffixes each requiring at least one matching DNS SAN;
 *                           normalized to sorted lowercase ASCII; empty = unconstrained
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
    private static final int MAXIMUM_AUTHORITY_COUNT = 256;
    private static final int MAXIMUM_SAN_DOMAIN_COUNT = 256;

    /** Validates and defensively copies the record. */
    public EnrollmentProfile {
        if (id == null || !id.matches("[a-zA-Z0-9][a-zA-Z0-9._:-]{0,255}")) {
            throw new IllegalArgumentException("enrollment profile identity is not canonical");
        }
        if (displayName == null || displayName.isBlank() || displayName.length() > 256) {
            throw new IllegalArgumentException("Enrollment profile display name must contain 1 through 256 characters");
        }
        Objects.requireNonNull(state, "state");
        EnrollmentEndpoint.requireProfileId(certificateProfileId);
        allowedAuthorityIds = Set.copyOf(Objects.requireNonNull(allowedAuthorityIds, "allowedAuthorityIds"));
        if (allowedAuthorityIds.size() > MAXIMUM_AUTHORITY_COUNT) {
            throw new IllegalArgumentException("Too many enrollment authorities");
        }
        allowedAuthorityIds.forEach(EnrollmentEndpoint::requireProfileId);
        Objects.requireNonNull(subjectDnPattern, "subjectDnPattern");
        subjectDnPattern.ifPresent(EnrollmentSubjectPattern::compile);
        Objects.requireNonNull(requiredSanDomains, "requiredSanDomains");
        if (requiredSanDomains.size() > MAXIMUM_SAN_DOMAIN_COUNT) {
            throw new IllegalArgumentException("Too many enrollment DNS suffixes");
        }
        SortedSet<String> domains = new TreeSet<>();
        for (String domain : requiredSanDomains) {
            String canonical = canonicalDomain(domain);
            if (!domains.add(canonical)) {
                throw new IllegalArgumentException("Duplicate enrollment DNS suffix");
            }
        }
        requiredSanDomains = List.copyOf(domains);
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

    private static String canonicalDomain(String value) {
        Objects.requireNonNull(value, "DNS suffix");
        if (value.length() > 254 || !value.matches("[A-Za-z0-9.-]+")) {
            throw new IllegalArgumentException("Enrollment DNS suffix must contain canonical ASCII labels");
        }
        String domain = value.toLowerCase(Locale.ROOT);
        if (domain.endsWith(".")) {
            domain = domain.substring(0, domain.length() - 1);
        }
        if (domain.isEmpty() || domain.length() > 253) {
            throw new IllegalArgumentException("Invalid enrollment DNS suffix");
        }
        for (String label : domain.split("\\.", -1)) {
            if (!label.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")) {
                throw new IllegalArgumentException("Enrollment DNS suffix must contain canonical ASCII labels");
            }
        }
        return domain;
    }
}
