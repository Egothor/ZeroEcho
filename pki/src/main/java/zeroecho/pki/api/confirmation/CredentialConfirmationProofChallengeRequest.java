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
package zeroecho.pki.api.confirmation;

import java.util.Objects;
import java.util.regex.Pattern;

import zeroecho.pki.api.PkiId;

/**
 * Minimal caller expectation for issuing a credential-confirmation proof challenge.
 *
 * <p>Realm, audience, TTL, nonce, provider selection, certificate material,
 * keys, and transcript bytes are deliberately server-controlled and absent.</p>
 *
 * @param credentialId exact target credential
 * @param expectedLifecycleRevision expected pending lifecycle revision, always 1
 * @param expectedLifecycleRecordCommitment exact pending lifecycle-record commitment
 */
// The commitment component name defines the exported record accessor and wire vocabulary.
@SuppressWarnings("PMD.LongVariable")
public record CredentialConfirmationProofChallengeRequest(PkiId credentialId,
        long expectedLifecycleRevision, String expectedLifecycleRecordCommitment) {
    private static final Pattern SHA_256 = Pattern.compile("[0-9a-f]{64}");

    /**
     * Validates the exact pending lifecycle expectation.
     *
     * @throws NullPointerException if a reference component is {@code null}
     * @throws IllegalArgumentException if the identity, revision, or commitment is not canonical
     */
    public CredentialConfirmationProofChallengeRequest {
        credentialId = CredentialConfirmationInitialization.requireCanonicalCredentialId(credentialId);
        if (expectedLifecycleRevision != CredentialConfirmationLifecycle.INITIAL_REVISION) {
            throw new IllegalArgumentException("Proof challenge request must expect the pending revision");
        }
        Objects.requireNonNull(expectedLifecycleRecordCommitment,
                "expectedLifecycleRecordCommitment");
        if (!SHA_256.matcher(expectedLifecycleRecordCommitment).matches()) {
            throw new IllegalArgumentException("Expected lifecycle commitment is not canonical");
        }
    }
}
