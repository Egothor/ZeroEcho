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

import java.time.Instant;
import java.util.Objects;

import zeroecho.pki.api.PkiId;

/**
 * Immutable frozen inputs for the initial credential-confirmation lifecycle record.
 *
 * @param credentialId exact issued credential encoded as 1 through
 *        {@link #MAXIMUM_CREDENTIAL_ID_UTF8_BYTES} strict UTF-8 bytes
 * @param initialPolicy disclosure policy frozen at initialization
 * @param initialPolicyCommitment lowercase hexadecimal SHA-256 commitment of the exact policy configuration
 * @param confirmationRequired {@code false} exactly for {@link ConfirmationDisclosurePolicy#PUBLIC}; otherwise {@code true}
 * @param confirmationReviewAt authoritative timeliness review boundary in the UTC range from the epoch through year 9999
 * @param proofSuite exact proof-suite profile frozen at initialization
 */
public record CredentialConfirmationInitialization(PkiId credentialId,
        ConfirmationDisclosurePolicy initialPolicy, String initialPolicyCommitment,
        boolean confirmationRequired, Instant confirmationReviewAt,
        ConfirmationProofSuiteRef proofSuite) {

    /** Maximum strict UTF-8 byte length of a credential identifier in the confirmation model. */
    @SuppressWarnings("PMD.LongVariable")
    public static final int MAXIMUM_CREDENTIAL_ID_UTF8_BYTES = 256;

    /**
     * Validates the exact immutable initialization inputs.
     *
     * @throws NullPointerException if a component is {@code null}
     * @throws IllegalArgumentException if a commitment, instant, or required-policy relationship is invalid
     */
    public CredentialConfirmationInitialization {
        credentialId = ConfirmationModelSupport.requireCredentialId(credentialId);
        Objects.requireNonNull(initialPolicy, "initialPolicy");
        initialPolicyCommitment = ConfirmationModelSupport.requireCommitment(initialPolicyCommitment,
                "initialPolicyCommitment");
        confirmationReviewAt = ConfirmationModelSupport.requireCanonicalInstant(confirmationReviewAt,
                "confirmationReviewAt");
        Objects.requireNonNull(proofSuite, "proofSuite");
        if (confirmationRequired != (initialPolicy != ConfirmationDisclosurePolicy.PUBLIC)) {
            throw new IllegalArgumentException("Confirmation requirement does not match the initial policy");
        }
    }

    /**
     * Validates one opaque credential identifier against the confirmation API's
     * strict UTF-8 contract without normalizing or otherwise changing it.
     *
     * @param credentialId identifier to validate
     * @return the exact validated identifier
     * @throws NullPointerException if {@code credentialId} is {@code null}
     * @throws IllegalArgumentException if it is not 1 through 256 strict UTF-8 bytes
     */
    public static PkiId requireCanonicalCredentialId(PkiId credentialId) {
        return ConfirmationModelSupport.requireCredentialId(credentialId);
    }
}
