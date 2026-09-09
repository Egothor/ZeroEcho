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
package zeroecho.pki.server;

import java.time.Duration;
import java.util.Objects;

import zeroecho.pki.api.confirmation.ConfirmationProofSuiteBinding;
import zeroecho.pki.application.CredentialConfirmationProofAudience;
import zeroecho.pki.application.CredentialConfirmationProofRuntimePolicy;

/**
 * Immutable realm configuration for credential-confirmation proof challenges.
 *
 * <p>The audience is a public deployment or cluster identifier. Operators must
 * provision its exact mapping into clients and keep it unique across
 * independently administered deployments that may accept the same proof
 * protocol. It is never derived from a request or generated at startup.</p>
 *
 * @param audience exact public proof audience
 * @param challengeTimeToLive whole-second challenge lifetime from 10 seconds through 1 hour
 * @param rsaMaximumModulusBits inclusive configured RSA modulus ceiling from 2048 through 16384 bits
 */
public record CredentialConfirmationProofPolicy(CredentialConfirmationProofAudience audience,
        Duration challengeTimeToLive, int rsaMaximumModulusBits) {

    /** Validates the exact audience and shared portable proof bounds. */
    public CredentialConfirmationProofPolicy {
        Objects.requireNonNull(audience, "audience");
        Objects.requireNonNull(challengeTimeToLive, "challengeTimeToLive");
        if (challengeTimeToLive.getNano() != 0
                || challengeTimeToLive.compareTo(
                        CredentialConfirmationProofRuntimePolicy.MINIMUM_CHALLENGE_TIME_TO_LIVE) < 0
                || challengeTimeToLive.compareTo(
                        CredentialConfirmationProofRuntimePolicy.MAXIMUM_CHALLENGE_TIME_TO_LIVE) > 0) {
            throw new IllegalArgumentException(
                    "Credential confirmation proof TTL is outside the supported range");
        }
        if (rsaMaximumModulusBits < ConfirmationProofSuiteBinding.MINIMUM_RSA_MAXIMUM_MODULUS_BITS
                || rsaMaximumModulusBits > ConfirmationProofSuiteBinding.MAXIMUM_RSA_MAXIMUM_MODULUS_BITS) {
            throw new IllegalArgumentException(
                    "Credential confirmation proof RSA maximum is outside the supported range");
        }
    }
}
