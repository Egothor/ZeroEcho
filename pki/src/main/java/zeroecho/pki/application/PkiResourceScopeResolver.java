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
package zeroecho.pki.application;

import java.util.Optional;

import zeroecho.pki.api.PkiId;

/**
 * Read-only transport-neutral resolver for authorization scope cross-checks.
 *
 * <p>Resolved identifiers are metadata, not access authority. Callers must still
 * authorize the requested action and must not reveal an empty result to an
 * unauthorized principal.</p>
 */
public interface PkiResourceScopeResolver {
    /**
     * Exact authorization coordinates frozen into one committed credential.
     *
     * @param authorityId issuing authority
     * @param profileId frozen logical profile
     */
    record CredentialScope(PkiId authorityId, String profileId) {
        /** Validates the immutable authority and profile coordinates. */
        public CredentialScope {
            java.util.Objects.requireNonNull(authorityId, "authorityId");
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalArgumentException("profileId must not be blank");
            }
        }
    }

    /**
     * Returns the exact logical authority and frozen profile of one committed credential.
     *
     * @param credentialId credential identifier
     * @return scope, or empty
     */
    Optional<CredentialScope> credentialScope(PkiId credentialId);

    /**
     * Returns frozen authorization coordinates for a temporary hold or release,
     * including CA certificates when supported by the implementation.
     * The default retains the existing credential resolver's fail-closed scope.
     * This lookup does not grant permission or change confirmation eligibility.
     * @param credentialId exact committed certificate identifier
     * @return authoritative scope, or empty when absent
     */
    default Optional<CredentialScope> holdCredentialScope(PkiId credentialId) {
        return credentialScope(credentialId);
    }

    /**
     * Returns the exact logical issuer authority of one committed status object.
     *
     * @param statusObjectId object identifier
     * @return authority, or empty
     */
    Optional<PkiId> statusObjectAuthority(PkiId statusObjectId);

    /**
     * Returns the authority of the immutable source behind one publication operation.
     *
     * @param publicationId operation identifier
     * @return authority, or empty
     */
    Optional<PkiId> publicationAuthority(PkiId publicationId);
}
