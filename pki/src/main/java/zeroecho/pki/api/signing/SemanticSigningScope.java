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

package zeroecho.pki.api.signing;

import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;

/**
 * Immutable persisted coordinates for a caller's authorization cross-check.
 * The containing session supplies the realm boundary. Scheduling authority never
 * supplies authorization scope; absence of an authority means a realm-scoped
 * root-creation command, not unrestricted permission.
 *
 * @param kind semantic domain
 * @param operation validated canonical outer-command discriminator
 * @param accessContext original trusted actor and audit context from the envelope
 * @param keyRef exact signing key from the envelope and validated outer command
 * @param authorityId issuing or existing authority, absent for root creation
 * @param subjectAuthorityId target authority for intermediate operations or CA subject-key proofs, otherwise empty
 * @param profileId frozen logical certificate profile, absent for status and OCSP responder proof operations
 * @param keyProof purpose-specific scope, present exactly for {@link SemanticSigningKind#KEY_PROOF}
 */
public record SemanticSigningScope(SemanticSigningKind kind, String operation,
        AccessContext accessContext, KeyRef keyRef, Optional<PkiId> authorityId,
        Optional<PkiId> subjectAuthorityId, Optional<String> profileId,
        Optional<ManagedKeyProofScope> keyProof) {
    /**
     * Validates immutable scope coordinates and the exact proof-kind combination.
     * @throws NullPointerException if a mandatory coordinate or optional container is null
     * @throws IllegalArgumentException if operation/profile text or the proof-kind combination is invalid
     */
    public SemanticSigningScope {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(accessContext, "accessContext");
        Objects.requireNonNull(keyRef, "keyRef");
        authorityId = Objects.requireNonNull(authorityId, "authorityId");
        subjectAuthorityId = Objects.requireNonNull(subjectAuthorityId, "subjectAuthorityId");
        profileId = Objects.requireNonNull(profileId, "profileId");
        keyProof = Objects.requireNonNull(keyProof, "keyProof");
        if (operation == null || operation.isBlank() || profileId.filter(String::isBlank).isPresent()) {
            throw new IllegalArgumentException("Semantic scope is invalid");
        }
        if (kind == SemanticSigningKind.KEY_PROOF != keyProof.isPresent()) {
            throw new IllegalArgumentException("Semantic domain and managed key proof scope differ");
        }
    }

    /** Returns a representation that omits privileged scope coordinates. */
    @Override public String toString() { return "SemanticSigningScope[redacted]"; }
}
