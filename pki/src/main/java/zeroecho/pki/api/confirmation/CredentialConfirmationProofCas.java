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
package zeroecho.pki.api.confirmation;

import zeroecho.pki.api.PkiId;

/**
 * Immutable compare-and-set input binding completion to one pending lifecycle and challenge.
 *
 * @param credentialId exact credential expected by the caller
 * @param expectedLifecycleRevision expected pending lifecycle revision, always 1
 * @param expectedLifecycleRecordCommitment exact expected pending lifecycle-record commitment
 * @param expectedChallengeRecordCommitment lowercase hexadecimal SHA-256 commitment of the exact challenge record
 */
// Exact expectation names are exported record accessors used for compare-and-set semantics.
@SuppressWarnings("PMD.LongVariable")
public record CredentialConfirmationProofCas(PkiId credentialId, long expectedLifecycleRevision,
        String expectedLifecycleRecordCommitment,
        String expectedChallengeRecordCommitment) {

    /**
     * Validates both exact pending-record expectations.
     *
     * @throws NullPointerException if either component is {@code null}
     * @throws IllegalArgumentException if the challenge commitment is not canonical
     */
    public CredentialConfirmationProofCas {
        credentialId = ConfirmationModelSupport.requireCredentialId(credentialId);
        if (expectedLifecycleRevision != CredentialConfirmationLifecycle.INITIAL_REVISION) {
            throw new IllegalArgumentException("Confirmation proof CAS must expect the pending revision");
        }
        expectedLifecycleRecordCommitment = ConfirmationModelSupport.requireCommitment(
                expectedLifecycleRecordCommitment, "expectedLifecycleRecordCommitment");
        expectedChallengeRecordCommitment = ConfirmationModelSupport.requireCommitment(
                expectedChallengeRecordCommitment, "expectedChallengeRecordCommitment");
    }
}
