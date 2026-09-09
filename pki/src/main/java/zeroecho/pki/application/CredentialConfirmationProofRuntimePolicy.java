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
package zeroecho.pki.application;

import java.time.Duration;
import java.util.Objects;

import zeroecho.pki.api.confirmation.ConfirmationProofSuiteBinding;
import zeroecho.pki.api.confirmation.ConfirmationRealmBinding;

/**
 * Immutable server-controlled runtime policy for credential key-possession challenges.
 *
 * <p>The audience is an exact lowercase ASCII RFC 4122 version-4 UUID URN.
 * Values are compared byte-for-byte without normalization.</p>
 *
 * @param realm exact portable realm binding
 * @param audience exact public deployment or cluster proof audience
 * @param challengeTimeToLive whole-second challenge lifetime from 10 seconds through 1 hour
 * @param proofSuiteBinding exact configured proof-suite binding
 */
// Unit-explicit public limit names are retained for source compatibility.
@SuppressWarnings("PMD.LongVariable")
public record CredentialConfirmationProofRuntimePolicy(ConfirmationRealmBinding realm,
        CredentialConfirmationProofAudience audience, Duration challengeTimeToLive,
        ConfirmationProofSuiteBinding proofSuiteBinding) {
    /** Minimum supported challenge lifetime. */
    public static final Duration MINIMUM_CHALLENGE_TIME_TO_LIVE = Duration.ofSeconds(10L);
    /** Maximum supported challenge lifetime. */
    public static final Duration MAXIMUM_CHALLENGE_TIME_TO_LIVE = Duration.ofHours(1L);

    /**
     * Validates exact realm, audience, lifetime, and suite coordinates.
     *
     * @throws NullPointerException if a component is {@code null}
     * @throws IllegalArgumentException if the audience or lifetime is outside the approved contract
     */
    public CredentialConfirmationProofRuntimePolicy {
        Objects.requireNonNull(realm, "realm");
        Objects.requireNonNull(audience, "audience");
        Objects.requireNonNull(challengeTimeToLive, "challengeTimeToLive");
        if (challengeTimeToLive.getNano() != 0
                || challengeTimeToLive.compareTo(MINIMUM_CHALLENGE_TIME_TO_LIVE) < 0
                || challengeTimeToLive.compareTo(MAXIMUM_CHALLENGE_TIME_TO_LIVE) > 0) {
            throw new IllegalArgumentException("Credential confirmation proof TTL is outside the supported range");
        }
        Objects.requireNonNull(proofSuiteBinding, "proofSuiteBinding");
    }
}
