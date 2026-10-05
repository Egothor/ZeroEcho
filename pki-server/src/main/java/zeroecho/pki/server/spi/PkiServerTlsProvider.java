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
package zeroecho.pki.server.spi;

import javax.net.ssl.SSLContext;

import zeroecho.pki.spi.ProviderConfig;

/**
 * Explicit server-local boundary for lifecycle-confined JSSE key and trust
 * material.
 *
 * <p>Implementations may load a private key only inside JSSE key-manager
 * construction. They must not return key stores, keys, passwords, aliases, or
 * provider exception details. Providers are discovered deterministically but
 * are activated only by an exact configured {@link #id()}.
 *
 * <h2>Thread safety</h2>
 * <p>Implementations must be thread-safe; the same provider instance may be
 * called from multiple threads during server startup.
 *
 * @since 1.0
 */
@SuppressWarnings("PMD.SignatureDeclareThrowsException") // SPI boundary: provider-specific failures are opaque
public interface PkiServerTlsProvider {
    /**
     * Returns the stable explicit provider identity.
     *
     * @return provider identity used in configuration; never {@code null}
     */
    String id();

    /**
     * Creates one fully initialized mutual-TLS context.
     *
     * @param configuration opaque provider configuration that must be validated
     *                      strictly; never {@code null}
     * @return initialized JSSE context containing server identity and client
     *         trust; never {@code null}
     * @throws Exception when material is unavailable, expired, or invalid
     */
    SSLContext create(ProviderConfig configuration) throws Exception;
}
