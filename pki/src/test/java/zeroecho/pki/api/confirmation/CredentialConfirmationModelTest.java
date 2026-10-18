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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.PkiId;

final class CredentialConfirmationModelTest {
    private static final PkiId CREDENTIAL = new PkiId("x509:" + "a".repeat(64));
    private static final String POLICY_COMMITMENT = "b".repeat(64);
    private static final String CHALLENGE_COMMITMENT = "e".repeat(64);
    private static final ConfirmationProofSuiteRef PROOF_SUITE =
            new ConfirmationProofSuiteRef("x509-signature.v1", "c".repeat(64));
    private static final Instant REVIEW_AT = Instant.ofEpochSecond(1_767_225_600L, 123_456_789L);

    @Test
    void profilePolicyHasCanonicalCommitmentAndBoundedWindow() {
        CredentialConfirmationPolicy policy = new CredentialConfirmationPolicy(
                ConfirmationDisclosurePolicy.OWNER_ONLY, Duration.ofHours(24L),
                new ConfirmationProofSuiteRef("zeroecho.signature-pop.v1",
                        "5ab6ec453561975d8978076cb31227cd68bc1f66da417bfb500002704be5ef11"));
        assertEquals("4933b3d9a9dd31b972d5835884ed8ef9218f8d331928e6ac0feb802d28ab9a30",
                policy.configurationCommitment());
        assertThrows(IllegalArgumentException.class, () -> new CredentialConfirmationPolicy(
                ConfirmationDisclosurePolicy.OWNER_ONLY, Duration.ZERO, policy.proofSuite()));
        assertThrows(IllegalArgumentException.class, () -> new CredentialConfirmationPolicy(
                ConfirmationDisclosurePolicy.OWNER_ONLY,
                CredentialConfirmationPolicy.MAXIMUM_CONFIRMATION_WINDOW.plusNanos(1L),
                policy.proofSuite()));
    }

    @Test
    void exposesSixStablePoliciesAndExactRequirementStates() {
        ConfirmationDisclosurePolicy[] policies = ConfirmationDisclosurePolicy.values();
        assertEquals(6, policies.length);
        for (int index = 0; index < policies.length; index++) {
            ConfirmationDisclosurePolicy policy = policies[index];
            assertEquals(index + 1, policy.code());
            assertEquals(policy, ConfirmationDisclosurePolicy.fromCode(policy.code()));
            boolean required = policy != ConfirmationDisclosurePolicy.PUBLIC;
            CredentialConfirmationLifecycle lifecycle = CredentialConfirmationLifecycle.initialize(
                    initialization(CREDENTIAL, policy, POLICY_COMMITMENT, required, REVIEW_AT, PROOF_SUITE));
            assertEquals(required ? CredentialConfirmationLifecycle.State.PENDING
                    : CredentialConfirmationLifecycle.State.NOT_REQUIRED, lifecycle.state());
            assertEquals(CredentialConfirmationLifecycle.Timeliness.NOT_APPLICABLE, lifecycle.timeliness());
        }
        assertThrows(IllegalArgumentException.class, () -> ConfirmationDisclosurePolicy.fromCode(0));
        assertThrows(IllegalArgumentException.class, () -> ConfirmationDisclosurePolicy.fromCode(7));
        assertThrows(IllegalArgumentException.class, () -> initialization(CREDENTIAL,
                ConfirmationDisclosurePolicy.PUBLIC, POLICY_COMMITMENT, true, REVIEW_AT, PROOF_SUITE));
        assertThrows(IllegalArgumentException.class, () -> initialization(CREDENTIAL,
                ConfirmationDisclosurePolicy.OWNER_ONLY, POLICY_COMMITMENT, false, REVIEW_AT, PROOF_SUITE));
    }

    @Test
    void rejectsNoncanonicalSuiteCommitmentAndInstantBounds() {
        String maximumSuiteId = "a".repeat(125) + ".v1";
        assertEquals(maximumSuiteId, new ConfirmationProofSuiteRef(maximumSuiteId, "a".repeat(64)).suiteId());
        assertThrows(IllegalArgumentException.class,
                () -> new ConfirmationProofSuiteRef("a".repeat(126) + ".v1", "a".repeat(64)));
        assertThrows(IllegalArgumentException.class,
                () -> new ConfirmationProofSuiteRef("x509-signature", "a".repeat(64)));
        assertThrows(IllegalArgumentException.class,
                () -> new ConfirmationProofSuiteRef("X509-signature.v1", "a".repeat(64)));
        assertThrows(IllegalArgumentException.class,
                () -> new ConfirmationProofSuiteRef("x509-signature.v1", "A".repeat(64)));
        assertThrows(IllegalArgumentException.class, () -> initialization(CREDENTIAL,
                ConfirmationDisclosurePolicy.OWNER_ONLY, "a".repeat(63), true, REVIEW_AT, PROOF_SUITE));
        assertThrows(IllegalArgumentException.class, () -> initialization(CREDENTIAL,
                ConfirmationDisclosurePolicy.OWNER_ONLY, POLICY_COMMITMENT, true,
                Instant.ofEpochSecond(-1L), PROOF_SUITE));
        assertThrows(IllegalArgumentException.class, () -> initialization(CREDENTIAL,
                ConfirmationDisclosurePolicy.OWNER_ONLY, POLICY_COMMITMENT, true,
                Instant.ofEpochSecond(253_402_300_800L), PROOF_SUITE));
    }

    @Test
    void enforcesStrictUtf8CredentialIdentityAtEveryBoundaryWithoutNormalization() {
        PkiId asciiMaximum = new PkiId("a".repeat(
                CredentialConfirmationInitialization.MAXIMUM_CREDENTIAL_ID_UTF8_BYTES));
        CredentialConfirmationLifecycle maximum = CredentialConfirmationLifecycle.initialize(initialization(
                asciiMaximum, ConfirmationDisclosurePolicy.OWNER_ONLY, POLICY_COMMITMENT, true,
                REVIEW_AT, PROOF_SUITE));
        assertEquals(asciiMaximum, maximum.credentialId());
        assertEquals(asciiMaximum, new CredentialConfirmationProofCas(asciiMaximum, 1L,
                maximum.recordCommitment(), CHALLENGE_COMMITMENT).credentialId());

        PkiId asciiTooLong = new PkiId("a".repeat(257));
        assertThrows(IllegalArgumentException.class, () -> initialization(asciiTooLong,
                ConfirmationDisclosurePolicy.OWNER_ONLY, POLICY_COMMITMENT, true, REVIEW_AT, PROOF_SUITE));
        assertThrows(IllegalArgumentException.class,
                () -> new CredentialConfirmationProofCas(asciiTooLong, 1L,
                        "a".repeat(64), CHALLENGE_COMMITMENT));
        assertThrows(IllegalArgumentException.class, () -> new CredentialConfirmationLifecycle(asciiTooLong, 1L,
                ConfirmationDisclosurePolicy.OWNER_ONLY, POLICY_COMMITMENT, true, REVIEW_AT, PROOF_SUITE,
                Optional.empty(), Optional.empty(), "0".repeat(64)));

        PkiId multibyteMaximum = new PkiId("é".repeat(128));
        assertEquals(multibyteMaximum, CredentialConfirmationLifecycle.initialize(initialization(multibyteMaximum,
                ConfirmationDisclosurePolicy.OWNER_ONLY, POLICY_COMMITMENT, true, REVIEW_AT, PROOF_SUITE))
                .credentialId());
        assertThrows(IllegalArgumentException.class, () -> initialization(new PkiId("é".repeat(128) + "a"),
                ConfirmationDisclosurePolicy.OWNER_ONLY, POLICY_COMMITMENT, true, REVIEW_AT, PROOF_SUITE));
        assertThrows(IllegalArgumentException.class, () -> initialization(new PkiId("\ud800"),
                ConfirmationDisclosurePolicy.OWNER_ONLY, POLICY_COMMITMENT, true, REVIEW_AT, PROOF_SUITE));
        assertThrows(IllegalArgumentException.class, () -> initialization(new PkiId("\udc00"),
                ConfirmationDisclosurePolicy.OWNER_ONLY, POLICY_COMMITMENT, true, REVIEW_AT, PROOF_SUITE));

        CredentialConfirmationLifecycle composed = CredentialConfirmationLifecycle.initialize(initialization(
                new PkiId("é"), ConfirmationDisclosurePolicy.OWNER_ONLY, POLICY_COMMITMENT, true,
                REVIEW_AT, PROOF_SUITE));
        CredentialConfirmationLifecycle decomposed = CredentialConfirmationLifecycle.initialize(initialization(
                new PkiId("e\u0301"), ConfirmationDisclosurePolicy.OWNER_ONLY, POLICY_COMMITMENT, true,
                REVIEW_AT, PROOF_SUITE));
        assertNotEquals(composed.recordCommitment(), decomposed.recordCommitment());
    }

    @Test
    void enforcesRevisionStateAndExactCasInvariants() {
        CredentialConfirmationLifecycle pending = pending();
        assertEquals(1L, pending.revision());
        assertEquals(Optional.empty(), pending.confirmedAt());
        assertEquals(CredentialConfirmationLifecycle.State.PENDING, pending.state());

        CredentialConfirmationProofCas exact = proof(pending);
        CredentialConfirmationLifecycle confirmed = pending.deriveConfirmed(exact, REVIEW_AT);
        assertEquals(2L, confirmed.revision());
        assertEquals(Optional.of(REVIEW_AT), confirmed.confirmedAt());
        assertEquals(Optional.of(CHALLENGE_COMMITMENT), confirmed.consumedChallengeRecordCommitment());
        assertEquals(CredentialConfirmationLifecycle.State.CONFIRMED, confirmed.state());
        assertThrows(IllegalStateException.class, () -> confirmed.deriveConfirmed(exact, REVIEW_AT));
        assertThrows(IllegalArgumentException.class, () -> pending.deriveConfirmed(
                new CredentialConfirmationProofCas(new PkiId("x509:" + "d".repeat(64)), 1L,
                        pending.recordCommitment(), CHALLENGE_COMMITMENT), REVIEW_AT));
        assertThrows(IllegalArgumentException.class, () -> pending.deriveConfirmed(
                new CredentialConfirmationProofCas(CREDENTIAL, 1L, "d".repeat(64),
                        CHALLENGE_COMMITMENT), REVIEW_AT));
        assertThrows(IllegalArgumentException.class,
                () -> new CredentialConfirmationProofCas(CREDENTIAL, 2L,
                        pending.recordCommitment(), CHALLENGE_COMMITMENT));

        assertThrows(IllegalArgumentException.class, () -> new CredentialConfirmationLifecycle(CREDENTIAL, 0L,
                ConfirmationDisclosurePolicy.OWNER_ONLY, POLICY_COMMITMENT, true, REVIEW_AT, PROOF_SUITE,
                Optional.empty(), Optional.empty(), "0".repeat(64)));
        assertThrows(IllegalArgumentException.class, () -> new CredentialConfirmationLifecycle(CREDENTIAL, 1L,
                ConfirmationDisclosurePolicy.OWNER_ONLY, POLICY_COMMITMENT, true, REVIEW_AT, PROOF_SUITE,
                Optional.empty(), Optional.of(REVIEW_AT), "0".repeat(64)));
        assertThrows(IllegalArgumentException.class, () -> new CredentialConfirmationLifecycle(CREDENTIAL, 1L,
                ConfirmationDisclosurePolicy.OWNER_ONLY, POLICY_COMMITMENT, true, REVIEW_AT, PROOF_SUITE,
                Optional.of(CHALLENGE_COMMITMENT), Optional.empty(), "0".repeat(64)));
        assertThrows(IllegalArgumentException.class, () -> new CredentialConfirmationLifecycle(CREDENTIAL, 2L,
                ConfirmationDisclosurePolicy.OWNER_ONLY, POLICY_COMMITMENT, true, REVIEW_AT, PROOF_SUITE,
                Optional.empty(), Optional.empty(), "0".repeat(64)));
        assertThrows(IllegalArgumentException.class, () -> new CredentialConfirmationLifecycle(CREDENTIAL, 2L,
                ConfirmationDisclosurePolicy.OWNER_ONLY, POLICY_COMMITMENT, true, REVIEW_AT, PROOF_SUITE,
                Optional.of(CHALLENGE_COMMITMENT), Optional.empty(), "0".repeat(64)));
        CredentialConfirmationLifecycle notRequired = CredentialConfirmationLifecycle.initialize(initialization(
                CREDENTIAL, ConfirmationDisclosurePolicy.PUBLIC, POLICY_COMMITMENT, false, REVIEW_AT, PROOF_SUITE));
        assertThrows(IllegalStateException.class, () -> notRequired.deriveConfirmed(
                new CredentialConfirmationProofCas(CREDENTIAL, 1L,
                        notRequired.recordCommitment(), CHALLENGE_COMMITMENT), REVIEW_AT));
    }

    @Test
    void classifiesExactReviewBoundaryAsTimelyAndLaterConfirmationAsLate() {
        CredentialConfirmationLifecycle pending = pending();
        CredentialConfirmationLifecycle timely = pending.deriveConfirmed(proof(pending), REVIEW_AT);
        CredentialConfirmationLifecycle late = pending.deriveConfirmed(
                proof(pending), REVIEW_AT.plusNanos(1L));

        assertEquals(CredentialConfirmationLifecycle.Timeliness.TIMELY, timely.timeliness());
        assertEquals(CredentialConfirmationLifecycle.Timeliness.LATE, late.timeliness());
    }

    @Test
    void producesExactV2CommitmentAndSeparatesEveryMutation() {
        CredentialConfirmationLifecycle baseline = pending();
        assertEquals("6c33c7e30760059178096befe377df7b1cfff5381eb4eadc79f918d16b82c8e6",
                baseline.recordCommitment());
        CredentialConfirmationLifecycle restored = new CredentialConfirmationLifecycle(baseline.credentialId(),
                baseline.revision(), baseline.initialPolicy(), baseline.initialPolicyCommitment(),
                baseline.confirmationRequired(), baseline.confirmationReviewAt(), baseline.proofSuite(),
                baseline.consumedChallengeRecordCommitment(), baseline.confirmedAt(),
                baseline.recordCommitment());
        assertEquals(baseline, restored);
        assertThrows(IllegalArgumentException.class, () -> new CredentialConfirmationLifecycle(
                baseline.credentialId(), baseline.revision(), baseline.initialPolicy(),
                baseline.initialPolicyCommitment(), baseline.confirmationRequired(), baseline.confirmationReviewAt(),
                baseline.proofSuite(), baseline.consumedChallengeRecordCommitment(),
                baseline.confirmedAt(), "0".repeat(64)));

        assertCommitmentDiffers(baseline, initialization(new PkiId("x509:" + "d".repeat(64)),
                baseline.initialPolicy(), baseline.initialPolicyCommitment(), true, REVIEW_AT, PROOF_SUITE));
        assertCommitmentDiffers(baseline, initialization(CREDENTIAL, ConfirmationDisclosurePolicy.RESTRICTED,
                baseline.initialPolicyCommitment(), true, REVIEW_AT, PROOF_SUITE));
        assertCommitmentDiffers(baseline, initialization(CREDENTIAL, baseline.initialPolicy(), "d".repeat(64),
                true, REVIEW_AT, PROOF_SUITE));
        assertCommitmentDiffers(baseline, initialization(CREDENTIAL, baseline.initialPolicy(),
                baseline.initialPolicyCommitment(), true, REVIEW_AT.plusNanos(1L), PROOF_SUITE));
        assertCommitmentDiffers(baseline, initialization(CREDENTIAL, baseline.initialPolicy(),
                baseline.initialPolicyCommitment(), true, REVIEW_AT,
                new ConfirmationProofSuiteRef("x509-signature.v2", PROOF_SUITE.configurationCommitment())));
        assertCommitmentDiffers(baseline, initialization(CREDENTIAL, baseline.initialPolicy(),
                baseline.initialPolicyCommitment(), true, REVIEW_AT,
                new ConfirmationProofSuiteRef(PROOF_SUITE.suiteId(), "d".repeat(64))));
        assertNotEquals(baseline.recordCommitment(), baseline.deriveConfirmed(
                proof(baseline), REVIEW_AT).recordCommitment());
    }

    @Test
    void producesExactRevisionTwoVectorWithNanosecondConfirmationTime() {
        CredentialConfirmationLifecycle baseline = pending();
        Instant confirmedAt = Instant.ofEpochSecond(1_767_225_601L, 987_654_321L);
        CredentialConfirmationLifecycle confirmed = baseline.deriveConfirmed(proof(baseline), confirmedAt);
        CredentialConfirmationLifecycle otherChallenge = baseline.deriveConfirmed(
                new CredentialConfirmationProofCas(CREDENTIAL, baseline.revision(),
                        baseline.recordCommitment(), "f".repeat(64)), confirmedAt);

        assertEquals("611e206ce338dbfa1badb2eafdca17e08b804c4cb366df2756c470e798e9516b",
                confirmed.recordCommitment());
        assertNotEquals(confirmed.recordCommitment(), otherChallenge.recordCommitment());
    }

    private static CredentialConfirmationLifecycle pending() {
        return CredentialConfirmationLifecycle.initialize(initialization(CREDENTIAL,
                ConfirmationDisclosurePolicy.OWNER_ONLY, POLICY_COMMITMENT, true, REVIEW_AT, PROOF_SUITE));
    }

    private static CredentialConfirmationProofCas proof(CredentialConfirmationLifecycle pending) {
        return new CredentialConfirmationProofCas(pending.credentialId(), pending.revision(),
                pending.recordCommitment(), CHALLENGE_COMMITMENT);
    }

    private static CredentialConfirmationInitialization initialization(PkiId credentialId,
            ConfirmationDisclosurePolicy policy, String policyCommitment, boolean required, Instant reviewAt,
            ConfirmationProofSuiteRef proofSuite) {
        return new CredentialConfirmationInitialization(credentialId, policy, policyCommitment, required,
                reviewAt, proofSuite);
    }

    private static void assertCommitmentDiffers(CredentialConfirmationLifecycle baseline,
            CredentialConfirmationInitialization mutation) {
        assertNotEquals(baseline.recordCommitment(),
                CredentialConfirmationLifecycle.initialize(mutation).recordCommitment());
    }
}
