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
package zeroecho.pki.impl.core;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

import zeroecho.pki.api.confirmation.CredentialConfirmationChallenge;

/** Stateless authoritative-clock preflight for persisted proof challenges. */
final class CredentialConfirmationProofLiveness {
    private CredentialConfirmationProofLiveness() { }

    /* default */ static void requireLive(CredentialConfirmationChallenge challenge, Clock clock) {
        CredentialConfirmationChallenge exactChallenge = Objects.requireNonNull(challenge, "challenge");
        Instant observed = Objects.requireNonNull(
                Objects.requireNonNull(clock, "clock").instant(), "session clock instant");
        Instant wholeSecond = Instant.ofEpochSecond(observed.getEpochSecond());
        boolean live;
        try {
            live = exactChallenge.isLiveAt(wholeSecond);
        } catch (IllegalArgumentException failure) {
            throw new IllegalStateException(
                    "Credential confirmation session clock is outside the supported range", failure);
        }
        if (wholeSecond.isBefore(exactChallenge.issuedAt())) {
            throw new IllegalStateException(
                    "Credential confirmation session clock regressed before challenge issuance");
        }
        if (!live) {
            throw new IllegalStateException("Credential confirmation challenge is expired");
        }
    }
}
