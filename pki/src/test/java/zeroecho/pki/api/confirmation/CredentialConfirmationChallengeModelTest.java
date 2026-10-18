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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.PkiId;

final class CredentialConfirmationChallengeModelTest {
    private static final ConfirmationRealmBinding REALM = new ConfirmationRealmBinding("prod-eu");
    private static final String AUDIENCE = "https://pki.example.test/confirmation";
    private static final PkiId CREDENTIAL = new PkiId("x509:" + "a".repeat(64));
    private static final String LIFECYCLE_COMMITMENT = "b".repeat(64);
    private static final String POLICY_COMMITMENT = "c".repeat(64);
    private static final ConfirmationProofSuiteBinding SUITE = new ConfirmationProofSuiteBinding(
            new ConfirmationProofSuiteRef("zeroecho.signature-pop.v1",
                    "5ab6ec453561975d8978076cb31227cd68bc1f66da417bfb500002704be5ef11"),
            8_192);
    private static final Instant ISSUED_AT = Instant.ofEpochSecond(1_767_225_600L);
    private static final Instant EXPIRES_AT = Instant.ofEpochSecond(1_767_225_900L);

    @Test
    void acceptsExactRealmAndSuiteBoundaries() {
        assertEquals("a", new ConfirmationRealmBinding("a").value());
        assertEquals("a".repeat(128), new ConfirmationRealmBinding("a".repeat(128)).value());
        assertThrows(IllegalArgumentException.class, () -> new ConfirmationRealmBinding(""));
        assertThrows(IllegalArgumentException.class, () -> new ConfirmationRealmBinding("A"));
        assertThrows(IllegalArgumentException.class, () -> new ConfirmationRealmBinding("a".repeat(129)));

        assertEquals(2_048, new ConfirmationProofSuiteBinding(SUITE.proofSuiteRef(), 2_048)
                .rsaMaximumModulusBits());
        assertEquals(16_384, new ConfirmationProofSuiteBinding(SUITE.proofSuiteRef(), 16_384)
                .rsaMaximumModulusBits());
        assertThrows(IllegalArgumentException.class,
                () -> new ConfirmationProofSuiteBinding(SUITE.proofSuiteRef(), 2_047));
        assertThrows(IllegalArgumentException.class,
                () -> new ConfirmationProofSuiteBinding(SUITE.proofSuiteRef(), 16_385));
    }

    @Test
    void ownsRawChallengeDefensivelyAndUsesContentValueSemantics() {
        byte[] callerOwned = rawChallenge();
        CredentialConfirmationChallenge challenge = challenge(callerOwned);
        byte[] expected = rawChallenge();

        callerOwned[0] = 99;
        assertArrayEquals(expected, challenge.rawChallenge());
        byte[] returned = challenge.rawChallenge();
        returned[1] = 99;
        assertArrayEquals(expected, challenge.rawChallenge());

        CredentialConfirmationChallenge reconstructed = new CredentialConfirmationChallenge(
                challenge.realm(), challenge.serverAudience(), challenge.credentialId(),
                challenge.expectedLifecycleRevision(), challenge.expectedLifecycleRecordCommitment(),
                challenge.initialDisclosurePolicy(), challenge.confirmationPolicyCommitment(),
                challenge.proofSuiteBinding(), expected, challenge.issuedAt(), challenge.expiresAt(),
                challenge.recordCommitment());
        assertEquals(challenge, reconstructed);
        assertEquals(challenge.hashCode(), reconstructed.hashCode());
    }

    @Test
    void producesExactVersionOneCommitmentVectorAndSeparatesMutation() {
        CredentialConfirmationChallenge baseline = challenge(rawChallenge());
        assertEquals("0c3bee03b4f1875fb042388d5f39aae70ec42df8afeb8e492c4e080a64286bcb",
                baseline.recordCommitment());

        byte[] changedRaw = rawChallenge();
        changedRaw[31] ^= 1;
        CredentialConfirmationChallenge changed = challenge(changedRaw);
        assertNotEquals(baseline.recordCommitment(), changed.recordCommitment());
        assertThrows(IllegalArgumentException.class, () -> new CredentialConfirmationChallenge(
                baseline.realm(), baseline.serverAudience(), baseline.credentialId(),
                baseline.expectedLifecycleRevision(), baseline.expectedLifecycleRecordCommitment(),
                baseline.initialDisclosurePolicy(), baseline.confirmationPolicyCommitment(),
                baseline.proofSuiteBinding(), baseline.rawChallenge(), baseline.issuedAt(), baseline.expiresAt(),
                "0".repeat(64)));
    }

    @Test
    void rejectsInvalidAudienceLifecyclePolicyChallengeAndTimes() {
        assertEquals("a".repeat(512), challenge("a".repeat(512), rawChallenge()).serverAudience());
        assertThrows(IllegalArgumentException.class, () -> challenge("", rawChallenge()));
        assertThrows(IllegalArgumentException.class, () -> challenge("a".repeat(513), rawChallenge()));
        assertThrows(IllegalArgumentException.class, () -> challenge("line\nbreak", rawChallenge()));
        assertThrows(IllegalArgumentException.class, () -> challenge("\ud800", rawChallenge()));
        assertThrows(IllegalArgumentException.class, () -> create(2L,
                ConfirmationDisclosurePolicy.OWNER_ONLY, rawChallenge(), ISSUED_AT, EXPIRES_AT));
        assertThrows(IllegalArgumentException.class, () -> create(1L,
                ConfirmationDisclosurePolicy.PUBLIC, rawChallenge(), ISSUED_AT, EXPIRES_AT));
        assertThrows(IllegalArgumentException.class, () -> create(1L,
                ConfirmationDisclosurePolicy.OWNER_ONLY, new byte[31], ISSUED_AT, EXPIRES_AT));
        assertThrows(IllegalArgumentException.class, () -> create(1L,
                ConfirmationDisclosurePolicy.OWNER_ONLY, rawChallenge(), ISSUED_AT.plusNanos(1L), EXPIRES_AT));
        assertThrows(IllegalArgumentException.class, () -> create(1L,
                ConfirmationDisclosurePolicy.OWNER_ONLY, rawChallenge(), ISSUED_AT, ISSUED_AT));
        assertThrows(IllegalArgumentException.class, () -> create(1L,
                ConfirmationDisclosurePolicy.OWNER_ONLY, rawChallenge(), EXPIRES_AT, ISSUED_AT));
    }

    @Test
    void proofCasComposesExactLifecycleAndChallengeExpectations() {
        CredentialConfirmationChallenge challenge = challenge(rawChallenge());
        CredentialConfirmationProofCas proof = new CredentialConfirmationProofCas(CREDENTIAL,
                CredentialConfirmationLifecycle.INITIAL_REVISION, LIFECYCLE_COMMITMENT,
                challenge.recordCommitment());

        assertEquals(CREDENTIAL, proof.credentialId());
        assertEquals(LIFECYCLE_COMMITMENT, proof.expectedLifecycleRecordCommitment());
        assertEquals(challenge.recordCommitment(), proof.expectedChallengeRecordCommitment());
        assertThrows(IllegalArgumentException.class,
                () -> new CredentialConfirmationProofCas(CREDENTIAL,
                        CredentialConfirmationLifecycle.INITIAL_REVISION,
                        LIFECYCLE_COMMITMENT, "0".repeat(63)));
    }

    @Test
    void usesExclusiveExpiryValidityIntervalAtWholeSeconds() {
        CredentialConfirmationChallenge challenge = challenge(rawChallenge());

        assertFalse(challenge.isLiveAt(ISSUED_AT.minusSeconds(1L)));
        assertTrue(challenge.isLiveAt(ISSUED_AT));
        assertTrue(challenge.isLiveAt(EXPIRES_AT.minusSeconds(1L)));
        assertFalse(challenge.isLiveAt(EXPIRES_AT));
        assertFalse(challenge.isLiveAt(EXPIRES_AT.plusSeconds(1L)));
        assertThrows(NullPointerException.class, () -> challenge.isLiveAt(null));
        assertThrows(IllegalArgumentException.class, () -> challenge.isLiveAt(ISSUED_AT.plusNanos(1L)));
    }

    @Test
    void everyCommittedCoordinateRejectsSubstitutionAndChangesCommitment() {
        CredentialConfirmationChallenge baseline = challenge(rawChallenge());
        List<CommitmentMutation> mutations = List.of(
                new CommitmentMutation("realm", value -> value.realm = new ConfirmationRealmBinding("prod-us"),
                        true),
                new CommitmentMutation("audience", value -> value.serverAudience = "pki.example.test", true),
                new CommitmentMutation("credential", value -> value.credentialId =
                        new PkiId("x509:" + "d".repeat(64)), true),
                new CommitmentMutation("lifecycle revision", value -> value.expectedLifecycleRevision =
                        CredentialConfirmationLifecycle.CONFIRMED_REVISION, false),
                new CommitmentMutation("lifecycle commitment", value -> value.expectedLifecycleCommitment =
                        "d".repeat(64), true),
                new CommitmentMutation("disclosure policy", value -> value.initialPolicy =
                        ConfirmationDisclosurePolicy.RESTRICTED, true),
                new CommitmentMutation("policy commitment", value -> value.policyCommitment =
                        "d".repeat(64), true),
                new CommitmentMutation("suite id", value -> value.suite = new ConfirmationProofSuiteBinding(
                        new ConfirmationProofSuiteRef("zeroecho.signature-pop.v2",
                                value.suite.proofSuiteRef().configurationCommitment()),
                        value.suite.rsaMaximumModulusBits()), true),
                new CommitmentMutation("suite commitment", value -> value.suite =
                        new ConfirmationProofSuiteBinding(new ConfirmationProofSuiteRef(
                                value.suite.proofSuiteRef().suiteId(), "d".repeat(64)),
                                value.suite.rsaMaximumModulusBits()), true),
                new CommitmentMutation("RSA maximum", value -> value.suite =
                        new ConfirmationProofSuiteBinding(value.suite.proofSuiteRef(), 2_048), true),
                new CommitmentMutation("raw challenge", value -> value.rawChallenge[0] ^= 1, true),
                new CommitmentMutation("issued at", value -> value.issuedAt = value.issuedAt.plusSeconds(1L), true),
                new CommitmentMutation("expires at", value -> value.expiresAt = value.expiresAt.plusSeconds(1L),
                        true));

        for (CommitmentMutation mutation : mutations) {
            MutableCommitmentInput changed = new MutableCommitmentInput(baseline);
            mutation.substitution().accept(changed);
            ConfirmationChallengeCommitment.Input input = changed.input();
            String replacementCommitment = ConfirmationChallengeCommitment.calculate(input);
            assertNotEquals(baseline.recordCommitment(), replacementCommitment, mutation.name());
            assertThrows(IllegalArgumentException.class,
                    () -> changed.challenge(baseline.recordCommitment()), mutation.name());
            if (mutation.validModel()) {
                CredentialConfirmationChallenge replacement = assertDoesNotThrow(
                        () -> changed.challenge(replacementCommitment), mutation.name());
                assertEquals(replacementCommitment, replacement.recordCommitment(), mutation.name());
            } else {
                assertThrows(IllegalArgumentException.class,
                        () -> changed.challenge(replacementCommitment), mutation.name());
            }
        }
    }

    @Test
    void challengeIssuanceEnforcesInclusiveWholeSecondTtlBounds() {
        assertEquals(Duration.ofSeconds(10L), issuance(Duration.ofSeconds(10L), rawChallenge()).timeToLive());
        assertEquals(Duration.ofHours(1L), issuance(Duration.ofSeconds(3_600L), rawChallenge()).timeToLive());
        assertThrows(IllegalArgumentException.class,
                () -> issuance(Duration.ofSeconds(9L), rawChallenge()));
        assertThrows(IllegalArgumentException.class,
                () -> issuance(Duration.ofSeconds(3_601L), rawChallenge()));
        assertThrows(IllegalArgumentException.class,
                () -> issuance(Duration.ofSeconds(10L).plusNanos(1L), rawChallenge()));
    }

    @Test
    void challengeIssuanceOwnsAndRedactsCallerNonce() {
        byte[] callerOwned = rawChallenge();
        CredentialConfirmationChallengeIssuance issuance = issuance(Duration.ofSeconds(10L), callerOwned);
        byte[] expected = rawChallenge();

        callerOwned[0] = 99;
        assertArrayEquals(expected, issuance.rawChallenge());
        byte[] returned = issuance.rawChallenge();
        returned[1] = 99;
        assertArrayEquals(expected, issuance.rawChallenge());
        assertTrue(issuance.toString().contains("rawChallenge=<32 bytes>"));
        assertFalse(issuance.toString().contains(Arrays.toString(expected)));
    }

    private static CredentialConfirmationChallenge challenge(byte[] raw) {
        return challenge(AUDIENCE, raw);
    }

    private static CredentialConfirmationChallenge challenge(String audience, byte[] raw) {
        return CredentialConfirmationChallenge.create(REALM, audience,
                lifecycle(ConfirmationDisclosurePolicy.OWNER_ONLY), SUITE, raw, ISSUED_AT, EXPIRES_AT);
    }

    private static CredentialConfirmationChallenge create(long revision,
            ConfirmationDisclosurePolicy policy, byte[] raw, Instant issuedAt, Instant expiresAt) {
        CredentialConfirmationLifecycle lifecycle = lifecycle(policy);
        if (revision == CredentialConfirmationLifecycle.CONFIRMED_REVISION) {
            lifecycle = lifecycle.deriveConfirmed(new CredentialConfirmationProofCas(CREDENTIAL,
                    CredentialConfirmationLifecycle.INITIAL_REVISION, lifecycle.recordCommitment(),
                    "d".repeat(64)), issuedAt);
        }
        return CredentialConfirmationChallenge.create(REALM, AUDIENCE, lifecycle, SUITE, raw,
                issuedAt, expiresAt);
    }

    private static CredentialConfirmationLifecycle lifecycle(ConfirmationDisclosurePolicy policy) {
        return CredentialConfirmationLifecycle.initialize(new CredentialConfirmationInitialization(
                CREDENTIAL, policy, POLICY_COMMITMENT, policy != ConfirmationDisclosurePolicy.PUBLIC,
                EXPIRES_AT, SUITE.proofSuiteRef()));
    }

    private static byte[] rawChallenge() {
        byte[] result = new byte[CredentialConfirmationChallenge.RAW_CHALLENGE_BYTES];
        for (int index = 0; index < result.length; index++) {
            result[index] = (byte) index;
        }
        return result;
    }

    private static CredentialConfirmationChallengeIssuance issuance(Duration timeToLive, byte[] raw) {
        CredentialConfirmationLifecycle lifecycle = lifecycle(ConfirmationDisclosurePolicy.OWNER_ONLY);
        return new CredentialConfirmationChallengeIssuance(REALM, AUDIENCE, CREDENTIAL,
                lifecycle.revision(), lifecycle.recordCommitment(), SUITE, raw, timeToLive);
    }

    private record CommitmentMutation(String name, Consumer<MutableCommitmentInput> substitution,
            boolean validModel) { }

    private static final class MutableCommitmentInput {
        private ConfirmationRealmBinding realm;
        private String serverAudience;
        private PkiId credentialId;
        private long expectedLifecycleRevision;
        private String expectedLifecycleCommitment;
        private ConfirmationDisclosurePolicy initialPolicy;
        private String policyCommitment;
        private ConfirmationProofSuiteBinding suite;
        private byte[] rawChallenge;
        private Instant issuedAt;
        private Instant expiresAt;

        private MutableCommitmentInput(CredentialConfirmationChallenge source) {
            realm = source.realm();
            serverAudience = source.serverAudience();
            credentialId = source.credentialId();
            expectedLifecycleRevision = source.expectedLifecycleRevision();
            expectedLifecycleCommitment = source.expectedLifecycleRecordCommitment();
            initialPolicy = source.initialDisclosurePolicy();
            policyCommitment = source.confirmationPolicyCommitment();
            suite = source.proofSuiteBinding();
            rawChallenge = source.rawChallenge();
            issuedAt = source.issuedAt();
            expiresAt = source.expiresAt();
        }

        private ConfirmationChallengeCommitment.Input input() {
            return new ConfirmationChallengeCommitment.Input(realm, serverAudience, credentialId,
                    expectedLifecycleRevision, expectedLifecycleCommitment, initialPolicy, policyCommitment,
                    suite, rawChallenge, issuedAt, expiresAt);
        }

        private CredentialConfirmationChallenge challenge(String commitment) {
            return new CredentialConfirmationChallenge(realm, serverAudience, credentialId,
                    expectedLifecycleRevision, expectedLifecycleCommitment, initialPolicy, policyCommitment,
                    suite, rawChallenge, issuedAt, expiresAt, commitment);
        }
    }
}
