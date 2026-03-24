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
package zeroecho.pki.spi;

import java.util.Set;

/**
 * ServiceLoader provider for configurable implementations.
 *
 * <p>
 * {@link java.util.ServiceLoader} instantiates providers using a public no-arg
 * constructor. However, the <em>produced</em> instances (stores, audit sinks,
 * publishers, framework adapters) typically require backend-specific
 * configuration (filesystem root, JDBC URL, remote endpoints, credentials,
 * etc.). This SPI standardizes that configuration handoff.
 * </p>
 *
 * <h2>Provider identity</h2>
 * <p>
 * {@link #id()} must return a stable identifier that is unique among providers
 * of the same service type. Identifiers are used for deterministic selection
 * (e.g. via system properties) and must not change across releases once
 * published.
 * </p>
 *
 * <h2>Configuration</h2>
 * <p>
 * Configuration is provided as string properties through
 * {@link ProviderConfig}. Providers must validate required keys and reject
 * invalid configurations with {@link IllegalArgumentException}. Unknown keys
 * must be ignored for forward compatibility. {@link #supportedKeys()} is
 * informational and may be used for diagnostics or help output.
 * </p>
 *
 * <h2>Security</h2>
 * <p>
 * Configuration values may contain sensitive material (passwords, tokens,
 * endpoints). Providers and bootstraps must never log configuration values. If
 * logging is required, log provider id and configuration <em>keys only</em>.
 * </p>
 *
 * @param <T> the type produced by the provider (e.g. {@code PkiStore},
 *            {@code AuditSink})
 */
public interface ConfigurableProvider<T> {

    /**
     * Returns a stable backend identifier (e.g. {@code "fs"}, {@code "jdbc"}).
     *
     * @return backend identifier (never {@code null}, never blank)
     */
    String id();

    /**
     * Returns the configuration keys understood by this backend.
     *
     * <p>
     * Keys are informational (diagnostics/validation/help). Unknown keys must be
     * ignored by implementations for forward compatibility.
     * </p>
     *
     * @return supported configuration keys (never {@code null})
     */
    Set<String> supportedKeys();

    /**
     * Allocates a new instance using the provided configuration.
     *
     * <p>
     * Implementations must validate required keys and throw
     * {@link IllegalArgumentException} if configuration is incomplete or invalid.
     * </p>
     *
     * @param config configuration (never {@code null})
     * @return new instance (never {@code null})
     * @throws IllegalArgumentException if required configuration is missing/invalid
     * @throws RuntimeException         if opening fails
     */
    T allocate(ProviderConfig config);
}
