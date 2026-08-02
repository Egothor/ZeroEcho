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
package zeroecho.pki.impl.core;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.CredentialUse;
import zeroecho.pki.api.credential.EffectiveCredentialStatus;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Store-backed authoritative resolver for runtime credential status.
 *
 * <p>
 * Revocation lookup errors and inconsistent current records fail closed with a
 * stable redacted error. The resolver never falls back to persisted inventory
 * status when revocation state cannot be read safely.
 * </p>
 */
public final class StoreBackedEffectiveCredentialStatusResolver implements EffectiveCredentialStatusResolver {

    /**
     * Stable status-resolution failure code.
     */
    public static final String RESOLUTION_FAILED_CODE = "CREDENTIAL_STATUS_RESOLUTION_FAILED";

    /**
     * Stable unusable-credential failure code.
     */
    public static final String NOT_USABLE_CODE = "CREDENTIAL_NOT_USABLE";

    private final PkiStore store;
    private final Clock clock;

    /**
     * Creates a resolver using the supplied authoritative store and clock.
     *
     * @param store current PKI store
     * @param clock authoritative status-evaluation clock
     * @throws NullPointerException if an argument is {@code null}
     */
    public StoreBackedEffectiveCredentialStatusResolver(PkiStore store, Clock clock) {
        this.store = Objects.requireNonNull(store, "store");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    // Clock implementations are external boundaries; their causes are deliberately
    // removed from the stable redacted status-resolution exception.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    @Override
    public Evaluation beginEvaluation() {
        Instant evaluationTime;
        try {
            evaluationTime = Objects.requireNonNull(clock.instant(), "clock instant");
        } catch (RuntimeException exception) {
            throw resolutionFailure();
        }
        return new StoreEvaluation(evaluationTime);
    }

    /**
     * Evaluation session bound to one captured authoritative instant.
     */
    private final class StoreEvaluation implements Evaluation {
        private final Instant evaluationTime;

        private StoreEvaluation(Instant evaluationTime) {
            this.evaluationTime = evaluationTime;
        }

        @Override
        public Instant evaluationTime() {
            return evaluationTime;
        }

        @Override
        public EffectiveCredentialStatus resolve(Credential credential) {
            Objects.requireNonNull(credential, "credential");
            RevocationTransition revocation = currentRevocation(credential);
            return resolveStatus(credential, revocation);
        }

        // Store implementations are external boundaries; their causes are deliberately
        // removed from the stable redacted status-resolution exception.
        @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
        private RevocationTransition currentRevocation(Credential credential) {
            Optional<RevocationRecord> current;
            try {
                current = store.getRevocation(credential.credentialId());
            } catch (RuntimeException exception) {
                throw resolutionFailure();
            }
            if (current == null) {
                throw resolutionFailure();
            }
            if (current.isEmpty()) {
                return null;
            }
            RevocationRecord record = current.get();
            if (!credential.credentialId().equals(record.credentialId())) {
                throw resolutionFailure();
            }
            RevocationTransition latest;
            try {
                latest = record.transition();
            } catch (RuntimeException exception) {
                throw resolutionFailure();
            }
            if (latest.time().isAfter(evaluationTime)) {
                throw resolutionFailure();
            }
            return latest;
        }

        private EffectiveCredentialStatus resolveStatus(Credential credential, RevocationTransition revocation) {
            if (credential.status() == CredentialStatus.REVOKED) {
                return EffectiveCredentialStatus.PERMANENTLY_REVOKED;
            }
            if (revocation != null) {
                if (revocation.state() == RevocationState.PERMANENTLY_REVOKED) {
                    return EffectiveCredentialStatus.PERMANENTLY_REVOKED;
                }
                if (revocation.state() == RevocationState.HELD) {
                    return EffectiveCredentialStatus.HELD;
                }
            }
            return resolveValidity(credential, revocation);
        }

        private EffectiveCredentialStatus resolveValidity(Credential credential, RevocationTransition revocation) {
            if (credential.status() == CredentialStatus.EXPIRED
                    || evaluationTime.isAfter(credential.validity().notAfter())) {
                return EffectiveCredentialStatus.EXPIRED;
            }
            if (evaluationTime.isBefore(credential.validity().notBefore())) {
                return EffectiveCredentialStatus.NOT_YET_VALID;
            }
            if (credential.status() == CredentialStatus.ISSUED
                    && (revocation == null || revocation.state() == RevocationState.CLEAR)) {
                return EffectiveCredentialStatus.USABLE;
            }
            throw resolutionFailure();
        }

        @Override
        public Credential requireUsable(Credential credential, CredentialUse use) {
            Objects.requireNonNull(use, "use");
            if (resolve(credential) != EffectiveCredentialStatus.USABLE) {
                throw new PkiException("Credential trust rejected: code=" + NOT_USABLE_CODE);
            }
            return credential;
        }

    }

    private static PkiException resolutionFailure() {
        return new PkiException("Credential status resolution failed: code=" + RESOLUTION_FAILED_CODE);
    }
}
