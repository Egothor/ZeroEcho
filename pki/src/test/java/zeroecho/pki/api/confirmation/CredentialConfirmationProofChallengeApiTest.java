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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.confirmation.KeyPossessionProofPresentation;
import zeroecho.pki.spi.confirmation.KeyPossessionProofResponse;

final class CredentialConfirmationProofChallengeApiTest {
    private static final PkiId CREDENTIAL = new PkiId("credential");
    private static final String LIFECYCLE_COMMITMENT = "a".repeat(64);
    private static final String CHALLENGE_COMMITMENT = "b".repeat(64);
    private static final ConfirmationProofSuiteBinding BINDING = new ConfirmationProofSuiteBinding(
            new ConfirmationProofSuiteRef("zeroecho.signature-pop.v1", "c".repeat(64)), 8_192);

    @Test
    void serviceExposesOnlySafeProofChallengeIssuance() {
        Set<String> methods = Arrays.stream(CredentialConfirmationService.class.getDeclaredMethods())
                .map(java.lang.reflect.Method::getName).collect(Collectors.toSet());
        assertEquals(Set.of("initialize", "get", "issueProofChallenge", "verifyAndComplete",
                "pagePendingReviews"), methods);
    }

    @Test
    void requestContainsOnlyAndValidatesExactPendingExpectation() {
        CredentialConfirmationProofChallengeRequest request =
                new CredentialConfirmationProofChallengeRequest(CREDENTIAL,
                        CredentialConfirmationLifecycle.INITIAL_REVISION, LIFECYCLE_COMMITMENT);
        assertEquals(CREDENTIAL, request.credentialId());
        assertEquals(LIFECYCLE_COMMITMENT, request.expectedLifecycleRecordCommitment());

        assertThrows(NullPointerException.class,
                () -> new CredentialConfirmationProofChallengeRequest(null, 1L, LIFECYCLE_COMMITMENT));
        assertThrows(IllegalArgumentException.class,
                () -> new CredentialConfirmationProofChallengeRequest(
                        new PkiId("a".repeat(257)), 1L, LIFECYCLE_COMMITMENT));
        assertThrows(IllegalArgumentException.class,
                () -> new CredentialConfirmationProofChallengeRequest(CREDENTIAL, 2L, LIFECYCLE_COMMITMENT));
        assertThrows(NullPointerException.class,
                () -> new CredentialConfirmationProofChallengeRequest(CREDENTIAL, 1L, null));
        assertThrows(IllegalArgumentException.class,
                () -> new CredentialConfirmationProofChallengeRequest(CREDENTIAL, 1L, "A".repeat(64)));
    }

    @Test
    void outputOwnsPresentationUsesValueSemanticsAndRedactsBytes() {
        byte[] source = bytes(64, 7);
        CredentialConfirmationProofChallenge challenge = challenge(source, 1_024);
        CredentialConfirmationProofChallenge equal = challenge(bytes(64, 7), 1_024);
        source[0] = 9;

        assertArrayEquals(bytes(64, 7), challenge.presentation());
        byte[] returned = challenge.presentation();
        returned[0] = 8;
        assertArrayEquals(bytes(64, 7), challenge.presentation());
        assertEquals(equal, challenge);
        assertEquals(equal.hashCode(), challenge.hashCode());
        assertNotEquals(challenge, challenge(bytes(64, 8), 1_024));
        assertTrue(challenge.toString().contains("presentation=<64 bytes>"));
        assertFalse(challenge.toString().contains(Arrays.toString(bytes(64, 7))));
        assertEquals(CHALLENGE_COMMITMENT,
                challenge.proofCas().expectedChallengeRecordCommitment());
    }

    @Test
    void outputEnforcesExactExpiryResponseAndPresentationBounds() {
        assertEquals(KeyPossessionProofPresentation.MAXIMUM_BYTES,
                challenge(new byte[KeyPossessionProofPresentation.MAXIMUM_BYTES],
                        KeyPossessionProofResponse.MAXIMUM_BYTES).presentation().length);
        assertThrows(NullPointerException.class, () -> new CredentialConfirmationProofChallenge(
                null, BINDING, Instant.ofEpochSecond(100L), 1, new byte[] { 1 }));
        assertThrows(NullPointerException.class, () -> new CredentialConfirmationProofChallenge(
                proofCas(), null, Instant.ofEpochSecond(100L), 1, new byte[] { 1 }));
        assertThrows(NullPointerException.class, () -> new CredentialConfirmationProofChallenge(
                proofCas(), BINDING, null, 1, new byte[] { 1 }));
        assertThrows(IllegalArgumentException.class, () -> new CredentialConfirmationProofChallenge(
                proofCas(), BINDING, Instant.ofEpochSecond(100L, 1L), 1, new byte[] { 1 }));
        assertThrows(IllegalArgumentException.class, () -> challenge(new byte[] { 1 }, 0));
        assertThrows(IllegalArgumentException.class,
                () -> challenge(new byte[] { 1 }, KeyPossessionProofResponse.MAXIMUM_BYTES + 1));
        assertThrows(IllegalArgumentException.class, () -> challenge(null, 1));
        assertThrows(IllegalArgumentException.class, () -> challenge(new byte[0], 1));
        assertThrows(IllegalArgumentException.class, () -> challenge(
                new byte[KeyPossessionProofPresentation.MAXIMUM_BYTES + 1], 1));
    }

    @Test
    void submissionOwnsAndRedactsItsGloballyBoundedResponse() {
        byte[] source = bytes(64, 7);
        CredentialConfirmationProofSubmission submission =
                new CredentialConfirmationProofSubmission(proofCas(), source);
        CredentialConfirmationProofSubmission equal =
                new CredentialConfirmationProofSubmission(proofCas(), bytes(64, 7));
        source[0] = 9;

        assertArrayEquals(bytes(64, 7), submission.response());
        byte[] returned = submission.response();
        returned[0] = 8;
        assertArrayEquals(bytes(64, 7), submission.response());
        assertEquals(equal, submission);
        assertEquals(equal.hashCode(), submission.hashCode());
        assertNotEquals(submission,
                new CredentialConfirmationProofSubmission(proofCas(), bytes(64, 8)));
        assertTrue(submission.toString().contains("response=<64 bytes>"));
        assertFalse(submission.toString().contains(Arrays.toString(bytes(64, 7))));

        assertThrows(NullPointerException.class,
                () -> new CredentialConfirmationProofSubmission(null, new byte[] { 1 }));
        assertThrows(IllegalArgumentException.class,
                () -> new CredentialConfirmationProofSubmission(proofCas(), null));
        assertThrows(IllegalArgumentException.class,
                () -> new CredentialConfirmationProofSubmission(proofCas(), new byte[0]));
        assertEquals(KeyPossessionProofResponse.MAXIMUM_BYTES,
                new CredentialConfirmationProofSubmission(proofCas(),
                        new byte[KeyPossessionProofResponse.MAXIMUM_BYTES]).response().length);
        assertThrows(IllegalArgumentException.class,
                () -> new CredentialConfirmationProofSubmission(proofCas(),
                        new byte[KeyPossessionProofResponse.MAXIMUM_BYTES + 1]));
    }

    @Test
    void resultIsClosedAndDataFree() {
        assertArrayEquals(new CredentialConfirmationProofResult[] {
                CredentialConfirmationProofResult.CONFIRMED,
                CredentialConfirmationProofResult.REJECTED },
                CredentialConfirmationProofResult.values());
    }

    private static CredentialConfirmationProofChallenge challenge(byte[] presentation,
            int maximumResponseBytes) {
        return new CredentialConfirmationProofChallenge(proofCas(), BINDING,
                Instant.ofEpochSecond(100L), maximumResponseBytes, presentation);
    }

    private static CredentialConfirmationProofCas proofCas() {
        return new CredentialConfirmationProofCas(CREDENTIAL,
                CredentialConfirmationLifecycle.INITIAL_REVISION,
                LIFECYCLE_COMMITMENT, CHALLENGE_COMMITMENT);
    }

    private static byte[] bytes(int length, int value) {
        byte[] result = new byte[length];
        Arrays.fill(result, (byte) value);
        return result;
    }
}
