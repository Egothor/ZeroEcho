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
package zeroecho.pki.server.spi.v2;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.spi.ProviderConfig;

/**
 * Explicit evidence-producing ACME challenge-provider SPI.
 *
 * <p>A provider receives no persistence or order-mutation authority. It may
 * only evaluate the exact immutable attempt and return a finite result. The
 * ACME service constructs and persists authoritative evidence after verifying
 * every returned binding.
 *
 * <h2>Thread safety</h2>
 * <p>Implementations must be thread-safe; {@link #validate} may be called
 * concurrently for independent authorization attempts.
 *
 * @since 1.0
 */
public interface AcmeChallengeProvider {
    /** Supported ACME identifier kinds. */
    enum IdentifierType {
        /** Domain Name System identifier. */ DNS
    }

    /** Supported challenge mechanisms. */
    enum ChallengeType {
        /** HTTP token-file validation. */ HTTP_01,
        /** DNS TXT-record validation. */ DNS_01
    }

    /**
     * Immutable canonical DNS identifier.
     *
     * @param type identifier kind
     * @param value lowercase ASCII DNS name without a wildcard prefix
     * @param wildcard whether the identifier represents wildcard subdomains
     */
    record Identifier(IdentifierType type, String value, boolean wildcard) {
        /** Validates the complete canonical DNS representation. */
        public Identifier {
            Objects.requireNonNull(type, "type");
            Objects.requireNonNull(value, "value");
            if (!value.equals(value.toLowerCase(java.util.Locale.ROOT)) || value.length() > 253
                    || value.startsWith(".") || value.endsWith(".")) {
                throw new IllegalArgumentException("ACME DNS identifier is not canonical");
            }
            for (String label : value.split("\\.", -1)) {
                if (label.isEmpty() || label.length() > 63
                        || !label.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")) {
                    throw new IllegalArgumentException("ACME DNS label is invalid");
                }
            }
        }

        /**
         * Returns the canonical wire presentation.
         *
         * @return DNS value with a wildcard prefix when applicable
         */
        public String presentation() {
            return wildcard ? "*." + value : value;
        }
    }

    /**
     * Returns the stable provider identity.
     *
     * @return the identity used by explicit provider configuration
     */
    String id();
    /**
     * Returns the exact challenge types supported by this provider.
     *
     * @return an immutable set of supported challenge types
     */
    Set<ChallengeType> challengeTypes();

    /**
     * Performs one bounded external validation attempt.
     *
     * @param context immutable challenge and timing input
     * @param configuration explicit provider configuration
     * @param cancellation signal checked while external work is in progress
     * @return a finite, non-sensitive validation result
     */
    Result validate(Context context, ProviderConfig configuration, CancellationSignal cancellation);

    /**
     * Exact immutable challenge input; values are sensitive and must never be logged.
     *
     * @param directoryId stable directory identity
     * @param authorizationId stable authorization identity
     * @param identifier identifier being authorized
     * @param challengeType challenge mechanism to validate
     * @param token canonical ACME challenge token
     * @param expectedKeyAuthorization expected account-bound key authorization
     * @param attempt positive validation-attempt number
     * @param validationTime authoritative start time for this attempt
     * @param deadline exclusive deadline for the bounded attempt
     */
    record Context(String directoryId, String authorizationId, Identifier identifier,
            ChallengeType challengeType, String token, String expectedKeyAuthorization,
            int attempt, Instant validationTime, Instant deadline) {
        /** Validates complete attempt binding. */
        public Context {
            requireId(directoryId); requireId(authorizationId); Objects.requireNonNull(identifier, "identifier");
            Objects.requireNonNull(challengeType, "challengeType");
            if (token == null || !token.matches("[A-Za-z0-9_-]{43,128}")) { throw new IllegalArgumentException("Invalid ACME token"); }
            if (expectedKeyAuthorization == null || expectedKeyAuthorization.length() > 512) { throw new IllegalArgumentException("Invalid key authorization"); }
            if (attempt <= 0) { throw new IllegalArgumentException("Invalid ACME attempt"); }
            Objects.requireNonNull(validationTime, "validationTime"); Objects.requireNonNull(deadline, "deadline");
            if (!deadline.isAfter(validationTime)) { throw new IllegalArgumentException("Invalid validation deadline"); }
        }

        /** Returns a redacted diagnostic without challenge credentials. */
        @Override public String toString() { return "AcmeChallengeContext[redacted]"; }
    }

    /**
     * Finite provider result without raw network, DNS, token or response data.
     *
     * @param valid whether the challenge evidence satisfied provider policy
     * @param classification stable, non-sensitive result classification
     * @param observedAt time at which the evidence was observed
     * @param expiresAt exclusive evidence expiry, after {@code observedAt}
     */
    record Result(boolean valid, String classification, Instant observedAt, Instant expiresAt) {
        /** Validates the safe evidence draft. */
        public Result {
            if (classification == null || !classification.matches("[A-Z0-9_]{1,64}")) { throw new IllegalArgumentException("Invalid ACME result classification"); }
            Objects.requireNonNull(observedAt, "observedAt"); Objects.requireNonNull(expiresAt, "expiresAt");
            if (!expiresAt.isAfter(observedAt)) { throw new IllegalArgumentException("Invalid ACME evidence lifetime"); }
        }
    }

    private static void requireId(String value) {
        if (value == null || !value.matches("[a-z0-9][a-z0-9._:-]{0,127}")) { throw new IllegalArgumentException("Invalid ACME identity"); }
    }
}
