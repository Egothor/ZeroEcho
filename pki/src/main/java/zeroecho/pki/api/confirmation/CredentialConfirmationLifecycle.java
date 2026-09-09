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

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.PkiId;

/**
 * Immutable committed credential-confirmation lifecycle record.
 *
 * <p>Revision 1 is either {@link State#NOT_REQUIRED} or {@link State#PENDING};
 * revision 2 is {@link State#CONFIRMED}. The initial policy, policy commitment,
 * review time, and proof-suite reference are frozen across the transition. The
 * record contains no owner, requester, actor, challenge, or proof bytes.</p>
 *
 * <p>The version-2 record commitment is SHA-256 over the following sequence in
 * network byte order: length-framed UTF-8 domain
 * {@code zeroecho:credential-confirmation-lifecycle:v2}, length-framed UTF-8
 * credential ID, 64-bit revision, 32-bit policy code, length-framed UTF-8 policy
 * commitment, one-byte confirmation-required code, review epoch seconds and
 * nanos as 64-bit and 32-bit integers, length-framed UTF-8 suite ID, length-framed
 * UTF-8 suite commitment, one-byte consumed-challenge-commitment presence code
 * and its length-framed UTF-8 value when present, followed by the confirmed-time presence code and,
 * when present, confirmed epoch seconds and nanos as 64-bit and 32-bit integers.
 * Every UTF-8 length is an unsigned non-negative 32-bit byte count. No delimiter
 * or general-purpose serialization participates in the commitment.</p>
 *
 * @param credentialId exact issued credential, within the confirmation model's strict UTF-8 bound
 * @param revision closed lifecycle revision, 1 or 2
 * @param initialPolicy disclosure policy frozen at initialization
 * @param initialPolicyCommitment lowercase hexadecimal SHA-256 commitment of the exact policy configuration
 * @param confirmationRequired {@code false} exactly for {@link ConfirmationDisclosurePolicy#PUBLIC}
 * @param confirmationReviewAt authoritative timeliness review boundary in the UTC range from the epoch through year 9999
 * @param proofSuite exact proof-suite profile frozen at initialization
 * @param consumedChallengeRecordCommitment empty at revision 1; exact consumed challenge commitment at revision 2
 * @param confirmedAt empty at revision 1; authoritative confirmation time at revision 2
 * @param recordCommitment lowercase canonical SHA-256 commitment of every preceding component
 */
// The commitment component name defines the exported record accessor and persisted model vocabulary.
@SuppressWarnings("PMD.LongVariable")
public record CredentialConfirmationLifecycle(PkiId credentialId, long revision,
        ConfirmationDisclosurePolicy initialPolicy, String initialPolicyCommitment,
        boolean confirmationRequired, Instant confirmationReviewAt,
        ConfirmationProofSuiteRef proofSuite, Optional<String> consumedChallengeRecordCommitment,
        Optional<Instant> confirmedAt,
        String recordCommitment) {

    /** Initial pending or not-required revision. */
    public static final long INITIAL_REVISION = 1L;
    /** Terminal confirmed revision. */
    public static final long CONFIRMED_REVISION = 2L;

    /** Derived closed lifecycle states. */
    public enum State {
        /** Public disclosure requires no credential confirmation. */
        NOT_REQUIRED,
        /** Non-public disclosure awaits credential confirmation. */
        PENDING,
        /** Credential confirmation was committed. */
        CONFIRMED
    }

    /** Derived confirmation timeliness classifications. */
    public enum Timeliness {
        /** No confirmation time exists yet or confirmation is not required. */
        NOT_APPLICABLE,
        /** Confirmation occurred at or before the timeliness review boundary. */
        TIMELY,
        /** Confirmation occurred after the timeliness review boundary. */
        LATE
    }

    /**
     * Validates the lifecycle state and verifies its exact canonical commitment.
     *
     * @throws NullPointerException if a reference component is {@code null}
     * @throws IllegalArgumentException if state invariants or the canonical commitment are invalid
     */
    public CredentialConfirmationLifecycle {
        credentialId = ConfirmationModelSupport.requireCredentialId(credentialId);
        Objects.requireNonNull(initialPolicy, "initialPolicy");
        initialPolicyCommitment = ConfirmationModelSupport.requireCommitment(initialPolicyCommitment,
                "initialPolicyCommitment");
        confirmationReviewAt = ConfirmationModelSupport.requireCanonicalInstant(confirmationReviewAt,
                "confirmationReviewAt");
        Objects.requireNonNull(proofSuite, "proofSuite");
        consumedChallengeRecordCommitment = Objects.requireNonNull(
                consumedChallengeRecordCommitment, "consumedChallengeRecordCommitment")
                .map(value -> ConfirmationModelSupport.requireCommitment(
                        value, "consumedChallengeRecordCommitment"));
        confirmedAt = Objects.requireNonNull(confirmedAt, "confirmedAt")
                .map(value -> ConfirmationModelSupport.requireCanonicalInstant(value, "confirmedAt"));
        if (confirmationRequired != (initialPolicy != ConfirmationDisclosurePolicy.PUBLIC)) {
            throw new IllegalArgumentException("Confirmation requirement does not match the initial policy");
        }
        validateState(revision, confirmationRequired, consumedChallengeRecordCommitment, confirmedAt);
        recordCommitment = ConfirmationModelSupport.requireCommitment(recordCommitment, "recordCommitment");
        String expected = ConfirmationLifecycleCommitment.calculate(credentialId, revision, initialPolicy,
                initialPolicyCommitment, confirmationRequired, confirmationReviewAt, proofSuite,
                consumedChallengeRecordCommitment, confirmedAt);
        if (!recordCommitment.equals(expected)) {
            throw new IllegalArgumentException("Credential confirmation record commitment does not match");
        }
    }

    /**
     * Creates the canonical revision-1 lifecycle from frozen initialization inputs.
     *
     * @param initialization exact initialization inputs
     * @return committed in-memory lifecycle value with its calculated commitment
     * @throws NullPointerException if {@code initialization} is {@code null}
     */
    public static CredentialConfirmationLifecycle initialize(
            CredentialConfirmationInitialization initialization) {
        CredentialConfirmationInitialization exact = Objects.requireNonNull(initialization, "initialization");
        return create(exact.credentialId(), INITIAL_REVISION, exact.initialPolicy(),
                exact.initialPolicyCommitment(), exact.confirmationRequired(), exact.confirmationReviewAt(),
                exact.proofSuite(), Optional.empty(), Optional.empty());
    }

    /**
     * Derives a confirmed lifecycle value without mutating this pending record.
     *
     * <p>This pure derivation is not proof verification, authorization,
     * persistence, a clock read, or an assertion that {@code confirmedAt} is
     * authoritative. Callers must establish those properties before invoking it.</p>
     *
     * @param proofCas exact pending lifecycle and consumed challenge expectation
     * @param confirmedAt externally established authoritative confirmation time
     * @return new canonical revision-2 confirmed record
     * @throws NullPointerException if an argument is {@code null}
     * @throws IllegalStateException if this record is not pending
     * @throws IllegalArgumentException if the credential, revision, or commitment expectation differs
     */
    public CredentialConfirmationLifecycle deriveConfirmed(CredentialConfirmationProofCas proofCas,
            Instant confirmedAt) {
        CredentialConfirmationProofCas exact = Objects.requireNonNull(proofCas, "proofCas");
        if (state() != State.PENDING) {
            throw new IllegalStateException("Only a pending credential confirmation can be confirmed");
        }
        if (!credentialId.equals(exact.credentialId()) || revision != exact.expectedLifecycleRevision()
                || !recordCommitment.equals(exact.expectedLifecycleRecordCommitment())) {
            throw new IllegalArgumentException("Credential confirmation CAS expectation does not match");
        }
        return create(credentialId, CONFIRMED_REVISION, initialPolicy, initialPolicyCommitment,
                confirmationRequired, confirmationReviewAt, proofSuite,
                Optional.of(exact.expectedChallengeRecordCommitment()),
                Optional.of(ConfirmationModelSupport.requireCanonicalInstant(confirmedAt, "confirmedAt")));
    }

    /**
     * Returns the state derived exclusively from revision and confirmation requirement.
     *
     * @return closed lifecycle state
     */
    public State state() {
        if (revision == CONFIRMED_REVISION) {
            return State.CONFIRMED;
        }
        return confirmationRequired ? State.PENDING : State.NOT_REQUIRED;
    }

    /**
     * Returns confirmation timeliness derived from the authoritative times.
     *
     * @return {@link Timeliness#NOT_APPLICABLE} before confirmation or when confirmation is not required;
     *         otherwise timely at the exact review-time boundary and late after it
     */
    public Timeliness timeliness() {
        if (state() != State.CONFIRMED) {
            return Timeliness.NOT_APPLICABLE;
        }
        return confirmedAt.orElseThrow().isAfter(confirmationReviewAt) ? Timeliness.LATE : Timeliness.TIMELY;
    }

    private static CredentialConfirmationLifecycle create(PkiId credentialId, long revision,
            ConfirmationDisclosurePolicy initialPolicy, String initialPolicyCommitment,
            boolean confirmationRequired, Instant confirmationReviewAt,
            ConfirmationProofSuiteRef proofSuite, Optional<String> consumedChallengeCommitment,
            Optional<Instant> confirmedAt) {
        String commitment = ConfirmationLifecycleCommitment.calculate(credentialId, revision, initialPolicy,
                initialPolicyCommitment, confirmationRequired, confirmationReviewAt, proofSuite,
                consumedChallengeCommitment, confirmedAt);
        return new CredentialConfirmationLifecycle(credentialId, revision, initialPolicy, initialPolicyCommitment,
                confirmationRequired, confirmationReviewAt, proofSuite, consumedChallengeCommitment,
                confirmedAt, commitment);
    }

    private static void validateState(long revision, boolean confirmationRequired,
            Optional<String> consumedChallengeCommitment, Optional<Instant> confirmedAt) {
        if (revision == INITIAL_REVISION && consumedChallengeCommitment.isEmpty()
                && confirmedAt.isEmpty()) {
            return;
        }
        if (revision == CONFIRMED_REVISION && confirmationRequired
                && consumedChallengeCommitment.isPresent() && confirmedAt.isPresent()) {
            return;
        }
        throw new IllegalArgumentException("Credential confirmation lifecycle state is inconsistent");
    }
}
