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
package zeroecho.pki.spi.crypto;

import java.util.Objects;
import java.util.Optional;

import zeroecho.core.spi.KeyringUnlockProvider;
/**
 * Immutable runtime dependencies supplied when opening a signature workflow.
 *
 * <p>
 * These dependencies are process-local capabilities. They are never encoded in
 * {@link zeroecho.pki.spi.ProviderConfig}, persisted, or discovered through
 * {@link java.util.ServiceLoader}. An absent keyring unlock provider is valid
 * only for workflow implementations that do not use a software keyring.
 * </p>
 *
 * <p>
 * Instances are immutable and safe for concurrent use. This object does not
 * acquire or retain password material.
 * </p>
 */
public final class SignatureWorkflowRuntimeDependencies {
    private static final SignatureWorkflowRuntimeDependencies NONE = new SignatureWorkflowRuntimeDependencies(null,
            null);

    private final KeyringUnlockProvider keyringUnlockProvider;
    private final LocalSigningLedgerParticipant localLedgerParticipant;

    private SignatureWorkflowRuntimeDependencies(KeyringUnlockProvider keyringUnlockProvider,
            LocalSigningLedgerParticipant localLedgerParticipant) {
        this.keyringUnlockProvider = keyringUnlockProvider;
        this.localLedgerParticipant = localLedgerParticipant;
    }

    /**
     * Returns dependencies without a software-keyring unlock provider.
     *
     * @return immutable empty runtime dependencies
     */
    public static SignatureWorkflowRuntimeDependencies none() {
        return NONE;
    }

    /**
     * Creates dependencies containing an explicit software-keyring unlock provider.
     *
     * @param provider provider returning a fresh destroyable password for each
     *                 keyring open
     * @return immutable runtime dependencies containing {@code provider}
     * @throws NullPointerException if {@code provider} is {@code null}
     */
    public static SignatureWorkflowRuntimeDependencies withKeyringUnlockProvider(KeyringUnlockProvider provider) {
        return new SignatureWorkflowRuntimeDependencies(Objects.requireNonNull(provider, "provider must not be null"),
                null);
    }

    /**
     * Creates dependencies for a built-in workflow borrowing its owning store's
     * local signing ledger participant.
     *
     * @param provider keyring unlock provider
     * @param participant store-owned local signing ledger participant
     * @return immutable dependencies
     */
    public static SignatureWorkflowRuntimeDependencies local(KeyringUnlockProvider provider,
            LocalSigningLedgerParticipant participant) {
        return new SignatureWorkflowRuntimeDependencies(Objects.requireNonNull(provider, "provider must not be null"),
                Objects.requireNonNull(participant, "participant must not be null"));
    }

    /**
     * Returns the explicitly supplied software-keyring unlock provider.
     *
     * @return provider when one was supplied, otherwise an empty optional
     */
    public Optional<KeyringUnlockProvider> keyringUnlockProvider() {
        return Optional.ofNullable(keyringUnlockProvider);
    }

    /**
     * Returns the borrowed store-owned local signing ledger participant.
     *
     * @return participant when one was supplied, otherwise an empty optional
     */
    public Optional<LocalSigningLedgerParticipant> localSigningLedgerParticipant() {
        return Optional.ofNullable(localLedgerParticipant);
    }
}
