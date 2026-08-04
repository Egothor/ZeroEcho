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
package zeroecho.pki.api.profile;

import java.time.Duration;

import zeroecho.pki.api.FormatId;

/**
 * Defines issuance constraints and mapping hints for a class of credentials.
 *
 * <p>
 * A profile is referenced by {@code profileId} during issuance. It defines the
 * complete deny-by-default identity and extension policy for an end-entity
 * credential. Requester fields absent from the profile are forbidden.
 * </p>
 *
 * <p>
 * Profiles must not include secrets.
 * </p>
 *
 * @param profileId       stable profile identifier
 * @param formatId        framework/format supported by the profile
 * @param displayName     human-readable name
 * @param maximumValidity positive maximum validity
 * @param subjectPolicy   complete end-entity subject policy
 * @param leafPolicy      complete end-entity extension policy
 * @param algorithmBindingPolicy explicit role-specific X.509 representation policy
 */
public record CertificateProfile(String profileId, FormatId formatId, String displayName, Duration maximumValidity,
        SubjectPolicy subjectPolicy, LeafCertificatePolicy leafPolicy,
        X509AlgorithmBindingPolicy algorithmBindingPolicy) {

    /** Creates a standard-only runtime profile. */
    public CertificateProfile(String profileId, FormatId formatId, String displayName, Duration maximumValidity,
            SubjectPolicy subjectPolicy, LeafCertificatePolicy leafPolicy) {
        this(profileId, formatId, displayName, maximumValidity, subjectPolicy, leafPolicy,
                X509AlgorithmBindingPolicy.standardOnly());
    }

    /**
     * Creates a certificate profile.
     *
     * @throws IllegalArgumentException if inputs are invalid or optional container
     *                                  is null
     */
    public CertificateProfile {
        if (profileId == null || profileId.isBlank()) {
            throw new IllegalArgumentException("profileId must not be null/blank");
        }
        if (formatId == null) {
            throw new IllegalArgumentException("formatId must not be null");
        }
        if (displayName == null || displayName.isBlank()) {
            throw new IllegalArgumentException("displayName must not be null/blank");
        }
        if (maximumValidity == null || maximumValidity.isZero() || maximumValidity.isNegative() || subjectPolicy == null
                || leafPolicy == null || algorithmBindingPolicy == null) {
            throw new IllegalArgumentException("profile policies and maximum validity must be valid");
        }
    }

    /**
     * Creates the deterministic runtime projection of a validated definition.
     *
     * @param definition authoritative profile definition
     * @return runtime profile projection
     */
    public static CertificateProfile fromDefinition(CertificateProfileDefinition definition) {
        if (definition == null) {
            throw new IllegalArgumentException("definition must not be null");
        }
        if (definition.certificateType() != CertificateProfileKind.END_ENTITY) {
            throw new IllegalArgumentException("Only end-entity definitions have a runtime issuance projection");
        }
        return new CertificateProfile(definition.profileId(), definition.formatId(), definition.displayName(),
                definition.maximumValidity(), definition.subjectPolicy(), definition.leafPolicy(),
                definition.algorithmBindingPolicy());
    }
}
