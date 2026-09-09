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
import java.util.Optional;

import zeroecho.pki.api.PkiId;

/** Session-owned application facade for authoritative credential confirmation. */
public interface CredentialConfirmationService {
    /**
     * Initializes or exactly replays one frozen confirmation lifecycle.
     *
     * @param initialization exact immutable initialization inputs
     * @return committed initial or identical existing lifecycle
     */
    CredentialConfirmationLifecycle initialize(CredentialConfirmationInitialization initialization);

    /**
     * Returns one authoritative lifecycle when initialized.
     *
     * @param credentialId exact credential identity
     * @return current lifecycle, or empty when not initialized
     */
    Optional<CredentialConfirmationLifecycle> get(PkiId credentialId);

    /**
     * Issues or exactly replays one authoritative key-possession proof challenge.
     *
     * <p>The session derives realm, audience, lifetime, proof provider, nonce,
     * and certificate material from trusted runtime and persisted state. Callers
     * supply only the exact pending lifecycle expectation.</p>
     *
     * @param request exact pending lifecycle expectation
     * @return bounded public proof challenge correlated to the persisted challenge
     * @throws NullPointerException if {@code request} is {@code null}
     * @throws IllegalArgumentException if the expectation conflicts with authoritative state
     * @throws IllegalStateException if required policy, provider, credential, or persistence is unavailable
     */
    CredentialConfirmationProofChallenge issueProofChallenge(
            CredentialConfirmationProofChallengeRequest request);

    /**
     * Resolves one bounded key-possession response against its exact
     * confirmation lifecycle.
     *
     * <p>{@link CredentialConfirmationProofResult#CONFIRMED} means the
     * authoritative lifecycle is confirmed. This includes an exact terminal
     * replay, for which the supplied response is not cryptographically
     * reverified. {@link CredentialConfirmationProofResult#REJECTED} means only
     * that a bounded proof cryptographically failed verification while the
     * lifecycle was pending; rejection does not mutate the lifecycle.
     * Persistence conflicts, expired or rotated challenges, unavailable
     * providers, and verification failures propagate as exceptions.</p>
     *
     * @param submission exact proof coordinates and bounded suite response
     * @return data-free confirmed-lifecycle or pending-proof-rejection classification
     * @throws NullPointerException if {@code submission} is {@code null}
     * @throws IllegalArgumentException if exact persisted coordinates conflict
     * @throws IllegalStateException if authoritative verification or completion cannot be established
     */
    CredentialConfirmationProofResult verifyAndComplete(
            CredentialConfirmationProofSubmission submission);

    /**
     * Returns one bounded snapshot-consistent page of reduced pending reviews.
     * The query is confined to the exact authority and optional profile before
     * traversal, and the cursor cannot be reused for another scope or cutoff.
     *
     * @param authorityId mandatory exact issuing-authority scope
     * @param profileId optional exact profile scope
     * @param cutoffInclusive latest review time included
     * @param afterExclusive optional exclusive store-issued cursor
     * @param limit page size from 1 through 4096
     * @return immutable review page in canonical order
     */
    CredentialConfirmationReviewPage pagePendingReviews(PkiId authorityId, Optional<String> profileId,
            Instant cutoffInclusive,
            Optional<CredentialConfirmationReviewCursor> afterExclusive, int limit);
}
