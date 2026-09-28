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
import zeroecho.pki.api.PkiId;

/**
 * Immutable, thread-safe purpose-specific coordinates of a managed key proof.
 * This value carries authorization metadata, not proof of authorization.
 *
 * @param purpose exact managed key role
 * @param responderCredentialId present exactly for {@link ManagedKeyProofPurpose#OCSP_RESPONDER_KEY};
 *        its identifier is limited to 4,096 strict UTF-8 bytes
 */
public record ManagedKeyProofScope(ManagedKeyProofPurpose purpose, Optional<PkiId> responderCredentialId) {
    /**
     * Validates the exact purpose/credential combination and bounded identity.
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if the combination or credential identity is invalid
     */
    public ManagedKeyProofScope {
        Objects.requireNonNull(purpose, "purpose");
        responderCredentialId = Objects.requireNonNull(responderCredentialId, "responderCredentialId");
        if (purpose == ManagedKeyProofPurpose.OCSP_RESPONDER_KEY != responderCredentialId.isPresent()) {
            throw new IllegalArgumentException("Managed key proof purpose and responder scope differ");
        }
        responderCredentialId.ifPresent(ManagedKeyProofInputs::identifier);
    }

    /** Returns a diagnostic representation without privileged coordinates. */
    @Override public String toString() { return "ManagedKeyProofScope[redacted]"; }
}
