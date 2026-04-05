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
package zeroecho.pki.spi.framework;

import zeroecho.pki.spi.ConfigurableProvider;
import zeroecho.pki.spi.ProviderConfig;

/**
 * Service provider for {@link CredentialFramework} instances.
 *
 * <p>
 * The PKI runtime selects a framework provider using
 * {@link java.util.ServiceLoader} and instantiates it through
 * {@link #validateConfig(ProviderConfig)} and
 * {@link #allocate(ProviderConfig)}. Provider selection is performed by
 * {@code PkiBootstrap} using configuration properties (similarly to store,
 * audit, async bus, and signature workflow providers).
 * </p>
 *
 * <h2>Dependency boundary</h2>
 * <p>
 * Framework implementations may internally rely on third-party toolkits (for
 * example Bouncy Castle), but such dependencies must not leak through this SPI.
 * The SPI must remain stable and independent of a particular cryptographic
 * provider.
 * </p>
 */
public interface CredentialFrameworkProvider extends ConfigurableProvider<CredentialFramework> {

    /**
     * Allocates a credential framework instance using the provided configuration.
     *
     * <p>
     * Implementations must validate that {@link ProviderConfig#backendId()} matches
     * {@link #id()}. A mismatch must be reported as
     * {@link IllegalArgumentException}. Implementations should invoke
     * {@link #validateConfig(ProviderConfig)} from this method so that the same
     * enforcement applies even when a provider is used outside bootstrap.
     * </p>
     *
     * @param config provider configuration (never {@code null})
     * @return allocated framework (never {@code null})
     * @throws NullPointerException     if {@code config} is {@code null}
     * @throws IllegalArgumentException if {@code config.backendId()} does not match
     *                                  {@link #id()}
     * @throws RuntimeException         if allocation fails
     */
    @Override
    CredentialFramework allocate(ProviderConfig config);

}
