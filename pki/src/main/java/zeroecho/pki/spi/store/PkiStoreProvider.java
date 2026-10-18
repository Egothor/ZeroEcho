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
package zeroecho.pki.spi.store;

import java.util.Objects;

import zeroecho.pki.spi.ConfigurableProvider;
import zeroecho.pki.spi.ProviderConfig;

/**
 * {@link java.util.ServiceLoader} provider for {@link PkiStore}
 * implementations.
 *
 * <p>
 * This interface is a PKI-specific specialization of
 * {@link ConfigurableProvider} for the persistence backend. See
 * {@link ConfigurableProvider} and {@link ProviderConfig} for the generic
 * provider and configuration contract.
 * </p>
 *
 * <p>
 * Implementations must be discoverable via {@link java.util.ServiceLoader} and
 * therefore must provide a public no-arg constructor.
 * </p>
 *
 * <p>
 * Security note: configuration values may contain sensitive material. Providers
 * must not log configuration values.
 * </p>
 */
public interface PkiStoreProvider extends ConfigurableProvider<PkiStore> {
    /**
     * Opens a store with explicit process-local runtime dependencies.
     * Providers without runtime requirements may rely on this default adapter.
     *
     * @param config structural provider configuration
     * @param dependencies authoritative process-local runtime dependencies
     * @return opened store
     */
    default PkiStore allocate(ProviderConfig config, PkiStoreRuntimeDependencies dependencies) {
        Objects.requireNonNull(dependencies, "dependencies");
        return allocate(config);
    }

    /**
     * Opens a new {@link PkiStore} instance using the provided configuration.
     *
     * <p>
     * Implementations must validate required keys and throw
     * {@link IllegalArgumentException} if configuration is incomplete or invalid.
     * Before returning, the provider must also satisfy the exclusive publication
     * recovery contract documented by {@link PkiStore}; no external publication
     * call may occur during allocation.
     * </p>
     *
     * @param config configuration (never {@code null})
     * @return opened store (never {@code null})
     * @throws IllegalArgumentException if required configuration is missing/invalid
     * @throws RuntimeException         if opening fails
     */
    @Override
    PkiStore allocate(ProviderConfig config);
}
