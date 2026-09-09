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

import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;

import zeroecho.pki.api.PkiId;

/**
 * Immutable transient command for issuing one credential-confirmation challenge.
 *
 * <p>The command carries no disclosure policy, authoritative timestamp, or
 * persisted record commitment. Those values are derived under the store's
 * credential-state lock from authoritative lifecycle state and the store clock.
 * Caller-owned nonce arrays are copied on input and output.</p>
 *
 * @param realm exact portable realm identity
 * @param serverAudience exact strict UTF-8 server audience, 1 through 512 bytes and without ISO controls
 * @param credentialId exact credential identity
 * @param expectedLifecycleRevision expected lifecycle revision, exactly
 *        {@link CredentialConfirmationLifecycle#INITIAL_REVISION}
 * @param expectedLifecycleRecordCommitment exact expected pending lifecycle-record commitment
 * @param proofSuiteBinding exact proof-suite coordinates
 * @param rawChallenge exactly 32 caller-generated nonce bytes, defensively owned
 * @param timeToLive whole-second challenge lifetime from {@code PT10S} through {@code PT1H}, inclusive
 */
// The commitment component name defines the exported record accessor and JSON mapping vocabulary.
@SuppressWarnings("PMD.LongVariable")
public record CredentialConfirmationChallengeIssuance(ConfirmationRealmBinding realm,
        String serverAudience, PkiId credentialId, long expectedLifecycleRevision,
        String expectedLifecycleRecordCommitment, ConfirmationProofSuiteBinding proofSuiteBinding,
        byte[] rawChallenge, Duration timeToLive) {

    /** Minimum permitted challenge lifetime. */
    public static final Duration MINIMUM_TIME_TO_LIVE = Duration.ofSeconds(10L);
    /** Maximum permitted challenge lifetime. */
    public static final Duration MAXIMUM_TIME_TO_LIVE = Duration.ofHours(1L);

    /**
     * Validates the exact lifecycle expectation, bounded lifetime, and immutable nonce ownership.
     *
     * @throws NullPointerException if a reference component is {@code null}
     * @throws IllegalArgumentException if any component is outside its canonical bound
     */
    public CredentialConfirmationChallengeIssuance {
        Objects.requireNonNull(realm, "realm");
        serverAudience = ConfirmationModelSupport.requireServerAudience(serverAudience);
        credentialId = ConfirmationModelSupport.requireCredentialId(credentialId);
        if (expectedLifecycleRevision != CredentialConfirmationLifecycle.INITIAL_REVISION) {
            throw new IllegalArgumentException("Challenge issuance must expect the initial lifecycle revision");
        }
        expectedLifecycleRecordCommitment = ConfirmationModelSupport.requireCommitment(
                expectedLifecycleRecordCommitment, "expectedLifecycleRecordCommitment");
        Objects.requireNonNull(proofSuiteBinding, "proofSuiteBinding");
        rawChallenge = ConfirmationModelSupport.requireRawChallenge(rawChallenge);
        Objects.requireNonNull(timeToLive, "timeToLive");
        if (timeToLive.getNano() != 0 || timeToLive.compareTo(MINIMUM_TIME_TO_LIVE) < 0
                || timeToLive.compareTo(MAXIMUM_TIME_TO_LIVE) > 0) {
            throw new IllegalArgumentException("Challenge lifetime must be a whole second from PT10S through PT1H");
        }
    }

    /**
     * Returns a defensive copy of the caller-generated nonce.
     *
     * @return newly allocated 32-byte nonce copy
     */
    @Override
    public byte[] rawChallenge() {
        return rawChallenge.clone();
    }

    /** Compares nonce bytes by content while preserving normal record component semantics. */
    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof CredentialConfirmationChallengeIssuance candidate)) {
            return false;
        }
        return expectedLifecycleRevision == candidate.expectedLifecycleRevision
                && realm.equals(candidate.realm)
                && serverAudience.equals(candidate.serverAudience)
                && credentialId.equals(candidate.credentialId)
                && expectedLifecycleRecordCommitment.equals(candidate.expectedLifecycleRecordCommitment)
                && proofSuiteBinding.equals(candidate.proofSuiteBinding)
                && Arrays.equals(rawChallenge, candidate.rawChallenge)
                && timeToLive.equals(candidate.timeToLive);
    }

    /** Returns a content-based hash code for every command component. */
    @Override
    public int hashCode() {
        int result = Objects.hash(realm, serverAudience, credentialId, expectedLifecycleRevision,
                expectedLifecycleRecordCommitment, proofSuiteBinding, timeToLive);
        return 31 * result + Arrays.hashCode(rawChallenge);
    }

    /** Returns a structural description without disclosing nonce bytes. */
    @Override
    public String toString() {
        return "CredentialConfirmationChallengeIssuance[realm=" + realm + ", serverAudience="
                + serverAudience + ", credentialId=" + credentialId + ", expectedLifecycleRevision="
                + expectedLifecycleRevision + ", expectedLifecycleRecordCommitment="
                + expectedLifecycleRecordCommitment + ", proofSuiteBinding=" + proofSuiteBinding
                + ", rawChallenge=<32 bytes>, timeToLive=" + timeToLive + ']';
    }
}
