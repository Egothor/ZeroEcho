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
import java.util.Arrays;
import java.util.Objects;

import zeroecho.pki.api.PkiId;

/**
 * Immutable portable challenge record for one pending credential confirmation.
 *
 * <p>The version-1 record commitment is SHA-256 over the following sequence in
 * network byte order: length-framed ASCII domain
 * {@code zeroecho:credential-confirmation-challenge:v1}, length-framed ASCII
 * realm identity, length-framed strict UTF-8 server audience, length-framed
 * strict UTF-8 credential identity, 64-bit expected lifecycle revision,
 * length-framed ASCII lifecycle-record commitment, 32-bit disclosure-policy
 * code, length-framed ASCII confirmation-policy commitment, length-framed ASCII
 * proof-suite identity, length-framed ASCII proof-suite commitment, 32-bit RSA
 * maximum modulus size, length-framed raw challenge, and issued and expiry
 * epoch seconds and nanoseconds as 64-bit and 32-bit integers. Every length is
 * an unsigned non-negative 32-bit byte count. No delimiter or general-purpose
 * serialization participates in the commitment.</p>
 *
 * <p>Instances are immutable and thread-safe. Caller-owned challenge arrays are
 * copied on input and output.</p>
 *
 * @param realm exact portable realm identity
 * @param serverAudience exact strict UTF-8 server audience, 1 through 512 bytes and without ISO controls
 * @param credentialId exact credential identity
 * @param expectedLifecycleRevision expected lifecycle revision, exactly
 *        {@link CredentialConfirmationLifecycle#INITIAL_REVISION}
 * @param expectedLifecycleRecordCommitment exact expected pending lifecycle-record commitment
 * @param initialDisclosurePolicy exact non-public disclosure policy frozen into the lifecycle
 * @param confirmationPolicyCommitment exact immutable profile confirmation-policy commitment
 * @param proofSuiteBinding exact proof-suite coordinates
 * @param rawChallenge exactly 32 challenge bytes, defensively owned
 * @param issuedAt authoritative whole-second issue time in the supported UTC range
 * @param expiresAt authoritative whole-second expiry time strictly after {@code issuedAt}
 * @param recordCommitment lowercase hexadecimal SHA-256 commitment of every preceding component
 */
// The record component and unit-explicit limit name are part of the exported immutable model.
@SuppressWarnings("PMD.LongVariable")
public record CredentialConfirmationChallenge(ConfirmationRealmBinding realm, String serverAudience,
        PkiId credentialId, long expectedLifecycleRevision, String expectedLifecycleRecordCommitment,
        ConfirmationDisclosurePolicy initialDisclosurePolicy, String confirmationPolicyCommitment,
        ConfirmationProofSuiteBinding proofSuiteBinding, byte[] rawChallenge,
        Instant issuedAt, Instant expiresAt, String recordCommitment) {

    /** Exact raw challenge length in bytes. */
    public static final int RAW_CHALLENGE_BYTES = 32;
    /** Maximum strict UTF-8 server-audience length in bytes. */
    public static final int MAXIMUM_SERVER_AUDIENCE_UTF8_BYTES = 512;

    /**
     * Validates every frozen coordinate, defensively copies the challenge, and
     * verifies the exact canonical record commitment.
     *
     * @throws NullPointerException if a reference component is {@code null}
     * @throws IllegalArgumentException if any component or the record commitment is invalid
     */
    public CredentialConfirmationChallenge {
        Objects.requireNonNull(realm, "realm");
        serverAudience = ConfirmationModelSupport.requireServerAudience(serverAudience);
        credentialId = ConfirmationModelSupport.requireCredentialId(credentialId);
        if (expectedLifecycleRevision != CredentialConfirmationLifecycle.INITIAL_REVISION) {
            throw new IllegalArgumentException("Confirmation challenge must expect the initial lifecycle revision");
        }
        expectedLifecycleRecordCommitment = ConfirmationModelSupport.requireCommitment(
                expectedLifecycleRecordCommitment, "expectedLifecycleRecordCommitment");
        Objects.requireNonNull(initialDisclosurePolicy, "initialDisclosurePolicy");
        if (initialDisclosurePolicy == ConfirmationDisclosurePolicy.PUBLIC) {
            throw new IllegalArgumentException("A public credential does not require a confirmation challenge");
        }
        confirmationPolicyCommitment = ConfirmationModelSupport.requireCommitment(
                confirmationPolicyCommitment, "confirmationPolicyCommitment");
        Objects.requireNonNull(proofSuiteBinding, "proofSuiteBinding");
        rawChallenge = ConfirmationModelSupport.requireRawChallenge(rawChallenge);
        issuedAt = requireWholeSecond(issuedAt, "issuedAt");
        expiresAt = requireWholeSecond(expiresAt, "expiresAt");
        if (!issuedAt.isBefore(expiresAt)) {
            throw new IllegalArgumentException("Confirmation challenge expiry must be after its issue time");
        }
        recordCommitment = ConfirmationModelSupport.requireCommitment(recordCommitment, "recordCommitment");
        ConfirmationChallengeCommitment.Input commitmentInput = new ConfirmationChallengeCommitment.Input(
                realm, serverAudience, credentialId, expectedLifecycleRevision,
                expectedLifecycleRecordCommitment, initialDisclosurePolicy, confirmationPolicyCommitment,
                proofSuiteBinding, rawChallenge, issuedAt, expiresAt);
        String expected = ConfirmationChallengeCommitment.calculate(commitmentInput);
        if (!recordCommitment.equals(expected)) {
            throw new IllegalArgumentException("Credential confirmation challenge commitment does not match");
        }
    }

    /**
     * Creates the canonical challenge record from exact frozen inputs.
     *
     * @param realm exact portable realm identity
     * @param serverAudience exact strict UTF-8 server audience
     * @param lifecycle exact pending initial lifecycle record whose coordinates are frozen into the challenge
     * @param proofSuiteBinding exact proof-suite coordinates
     * @param rawChallenge exactly 32 caller-owned challenge bytes; never retained
     * @param issuedAt authoritative whole-second issue time
     * @param expiresAt authoritative whole-second expiry time strictly after {@code issuedAt}
     * @return immutable challenge with its calculated canonical commitment
     * @throws NullPointerException if a reference component is {@code null}
     * @throws IllegalArgumentException if any component is invalid
     */
    public static CredentialConfirmationChallenge create(ConfirmationRealmBinding realm, String serverAudience,
            CredentialConfirmationLifecycle lifecycle, ConfirmationProofSuiteBinding proofSuiteBinding,
            byte[] rawChallenge, Instant issuedAt, Instant expiresAt) {
        CredentialConfirmationLifecycle exactLifecycle = Objects.requireNonNull(lifecycle, "lifecycle");
        ConfirmationProofSuiteBinding exactSuite = Objects.requireNonNull(proofSuiteBinding, "proofSuiteBinding");
        if (exactLifecycle.state() != CredentialConfirmationLifecycle.State.PENDING) {
            throw new IllegalArgumentException("A confirmation challenge requires a pending initial lifecycle");
        }
        if (!exactLifecycle.proofSuite().equals(exactSuite.proofSuiteRef())) {
            throw new IllegalArgumentException("Challenge proof suite does not match the pending lifecycle");
        }
        byte[] exactChallenge = ConfirmationModelSupport.requireRawChallenge(rawChallenge);
        try {
            ConfirmationChallengeCommitment.Input input = new ConfirmationChallengeCommitment.Input(
                    realm, serverAudience,
                    exactLifecycle.credentialId(), exactLifecycle.revision(), exactLifecycle.recordCommitment(),
                    exactLifecycle.initialPolicy(), exactLifecycle.initialPolicyCommitment(), exactSuite,
                    exactChallenge, issuedAt, expiresAt);
            String commitment = ConfirmationChallengeCommitment.calculate(input);
            return new CredentialConfirmationChallenge(realm, serverAudience, exactLifecycle.credentialId(),
                    exactLifecycle.revision(), exactLifecycle.recordCommitment(), exactLifecycle.initialPolicy(),
                    exactLifecycle.initialPolicyCommitment(), exactSuite, exactChallenge, issuedAt, expiresAt,
                    commitment);
        } finally {
            Arrays.fill(exactChallenge, (byte) 0);
        }
    }

    /**
     * Returns a defensive copy of the raw challenge.
     *
     * @return newly allocated 32-byte challenge copy
     */
    @Override
    public byte[] rawChallenge() {
        return rawChallenge.clone();
    }

    /**
     * Tests whether this challenge is live at an authoritative observation time.
     *
     * <p>The validity interval is exclusively {@code [issuedAt, expiresAt)}:
     * issuance is included and expiry is excluded.</p>
     *
     * @param observation authoritative whole-second observation time in the supported UTC range
     * @return {@code true} exactly when the observation is not before issuance and is before expiry
     * @throws NullPointerException if {@code observation} is {@code null}
     * @throws IllegalArgumentException if {@code observation} is not a supported whole-second instant
     */
    public boolean isLiveAt(Instant observation) {
        Instant exact = requireWholeSecond(observation, "observation");
        return !exact.isBefore(issuedAt) && exact.isBefore(expiresAt);
    }

    /** Compares challenge bytes by content while preserving normal record component semantics. */
    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof CredentialConfirmationChallenge candidate)) {
            return false;
        }
        return expectedLifecycleRevision == candidate.expectedLifecycleRevision
                && realm.equals(candidate.realm)
                && serverAudience.equals(candidate.serverAudience)
                && credentialId.equals(candidate.credentialId)
                && expectedLifecycleRecordCommitment.equals(candidate.expectedLifecycleRecordCommitment)
                && initialDisclosurePolicy == candidate.initialDisclosurePolicy
                && confirmationPolicyCommitment.equals(candidate.confirmationPolicyCommitment)
                && proofSuiteBinding.equals(candidate.proofSuiteBinding)
                && Arrays.equals(rawChallenge, candidate.rawChallenge)
                && issuedAt.equals(candidate.issuedAt)
                && expiresAt.equals(candidate.expiresAt)
                && recordCommitment.equals(candidate.recordCommitment);
    }

    /** Returns a content-based hash code for every record component. */
    @Override
    public int hashCode() {
        int result = Objects.hash(realm, serverAudience, credentialId, expectedLifecycleRevision,
                expectedLifecycleRecordCommitment, initialDisclosurePolicy, confirmationPolicyCommitment,
                proofSuiteBinding, issuedAt, expiresAt, recordCommitment);
        return 31 * result + Arrays.hashCode(rawChallenge);
    }

    /** Returns a safe structural description without disclosing raw challenge bytes. */
    @Override
    public String toString() {
        return "CredentialConfirmationChallenge[realm=" + realm + ", serverAudience=" + serverAudience
                + ", credentialId=" + credentialId + ", expectedLifecycleRevision="
                + expectedLifecycleRevision + ", expectedLifecycleRecordCommitment="
                + expectedLifecycleRecordCommitment + ", initialDisclosurePolicy=" + initialDisclosurePolicy
                + ", confirmationPolicyCommitment=" + confirmationPolicyCommitment + ", proofSuiteBinding="
                + proofSuiteBinding + ", rawChallenge=<32 bytes>, issuedAt=" + issuedAt + ", expiresAt="
                + expiresAt + ", recordCommitment=" + recordCommitment + ']';
    }

    private static Instant requireWholeSecond(Instant value, String name) {
        Instant exact = ConfirmationModelSupport.requireCanonicalInstant(value, name);
        if (exact.getNano() != 0) {
            throw new IllegalArgumentException(name + " must be a whole second");
        }
        return exact;
    }
}
