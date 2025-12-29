/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.spi.audit;

import zeroecho.pki.spi.ConfigurableProvider;
import zeroecho.pki.spi.ProviderConfig;

/**
 * ServiceLoader provider for {@link AuditSink} implementations.
 *
 * <p>
 * {@link java.util.ServiceLoader} cannot construct {@link AuditSink} instances
 * directly because stores typically require backend-specific configuration
 * (filesystem root, etc.). This SPI provides a uniform instantiation mechanism.
 * </p>
 *
 * <p>
 * Implementations must provide a public no-arg constructor to be discoverable
 * via {@link java.util.ServiceLoader}.
 * </p>
 *
 * <p>
 * Security note: providers and bootstraps must never log configuration values
 * because they can contain sensitive material (passwords, tokens, endpoints).
 * </p>
 */
public interface AuditSinkProvider extends ConfigurableProvider<AuditSink> {
    /**
     * Opens a new {@link AuditSink} instance using the provided configuration.
     *
     * <p>
     * Implementations must validate required keys and throw
     * {@link IllegalArgumentException} if configuration is incomplete or invalid.
     * </p>
     *
     * @param config configuration (never {@code null})
     * @return opened store (never {@code null})
     * @throws IllegalArgumentException if required configuration is missing/invalid
     * @throws RuntimeException         if opening fails
     */
    @Override
    AuditSink allocate(ProviderConfig config);
}
