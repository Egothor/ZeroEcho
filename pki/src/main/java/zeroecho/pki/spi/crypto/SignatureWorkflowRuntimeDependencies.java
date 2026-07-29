/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.spi.crypto;

import java.util.Objects;
import java.util.Optional;

import zeroecho.core.spi.KeyringUnlockProvider;

/**
 * Immutable runtime dependencies supplied when opening a signature workflow.
 *
 * <p>These dependencies are process-local capabilities. They are never encoded
 * in {@link zeroecho.pki.spi.ProviderConfig}, persisted, or discovered through
 * {@link java.util.ServiceLoader}. An absent keyring unlock provider is valid
 * only for workflow implementations that do not use a software keyring.</p>
 *
 * <p>Instances are immutable and safe for concurrent use. This object does not
 * acquire or retain password material.</p>
 */
public final class SignatureWorkflowRuntimeDependencies {
    private static final SignatureWorkflowRuntimeDependencies NONE =
            new SignatureWorkflowRuntimeDependencies(null);

    private final KeyringUnlockProvider keyringUnlockProvider;

    private SignatureWorkflowRuntimeDependencies(KeyringUnlockProvider keyringUnlockProvider) {
        this.keyringUnlockProvider = keyringUnlockProvider;
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
     * Creates dependencies containing an explicit software-keyring unlock
     * provider.
     *
     * @param provider provider returning a fresh destroyable password for each
     *        keyring open
     * @return immutable runtime dependencies containing {@code provider}
     * @throws NullPointerException if {@code provider} is {@code null}
     */
    public static SignatureWorkflowRuntimeDependencies withKeyringUnlockProvider(
            KeyringUnlockProvider provider) {
        return new SignatureWorkflowRuntimeDependencies(
                Objects.requireNonNull(provider, "provider must not be null"));
    }

    /**
     * Returns the explicitly supplied software-keyring unlock provider.
     *
     * @return provider when one was supplied, otherwise an empty optional
     */
    public Optional<KeyringUnlockProvider> keyringUnlockProvider() {
        return Optional.ofNullable(keyringUnlockProvider);
    }
}
