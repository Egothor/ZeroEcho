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
package zeroecho.pki.api;

import java.util.List;

import zeroecho.pki.api.profile.CertificateProfile;
import zeroecho.pki.api.profile.ProfileQuery;

/**
 * Profile registry for credential issuance.
 *
 * <p>
 * Profiles define required/optional attributes, validity limits, and other
 * constraints used by policy and framework mapping. Profiles are referenced by
 * id during issuance.
 * </p>
 */
public interface ProfileService {

    /**
     * Registers or updates a profile.
     *
     * @param profile profile definition
     * @throws IllegalArgumentException if {@code profile} is null
     * @throws PkiException             if registration fails
     */
    void register(CertificateProfile profile);

    /**
     * Retrieves a profile by id.
     *
     * @param profileId profile id
     * @return profile
     * @throws IllegalArgumentException if {@code profileId} is null/blank
     * @throws PkiException             if not found or retrieval fails
     */
    CertificateProfile get(String profileId);

    /**
     * Lists profiles matching query constraints.
     *
     * @param query query constraints
     * @return list of profiles
     * @throws IllegalArgumentException if {@code query} is null
     * @throws PkiException             if listing fails
     */
    List<CertificateProfile> list(ProfileQuery query);

    /**
     * Retires a profile to prevent further issuance.
     *
     * @param profileId profile id
     * @param reason    non-empty reason suitable for audit
     * @throws IllegalArgumentException if inputs are invalid
     * @throws PkiException             if retire fails
     */
    void retire(String profileId, String reason);
}
