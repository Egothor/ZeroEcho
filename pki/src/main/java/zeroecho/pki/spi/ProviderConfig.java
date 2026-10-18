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
package zeroecho.pki.spi;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Backend configuration for {@link ConfigurableProvider} instances.
 *
 * <p>
 * Values are stringly-typed by design to keep the SPI generic and stable across
 * different backends (filesystem, JDBC, remote services). Providers interpret
 * keys relevant to their backend and must ignore unknown keys for forward
 * compatibility.
 * </p>
 *
 * <p>
 * The {@code backendId} is the selected provider identifier
 * ({@link ConfigurableProvider#id()}), used for diagnostics and selection
 * correlation. It is not a URL, driver name, nor any secret.
 * </p>
 *
 * <p>
 * This record is immutable and safe to share. Configuration values may be
 * sensitive and must not be logged. If diagnostics are needed, log keys only.
 * </p>
 *
 * @param backendId  selected backend id (never blank)
 * @param properties backend properties (never {@code null})
 */
public record ProviderConfig(String backendId, Map<String, String> properties) {

    /**
     * Canonical constructor with validation and defensive wrapping.
     *
     * @param backendId  backend id (never blank)
     * @param properties properties (never {@code null})
     */
    public ProviderConfig {
        Objects.requireNonNull(backendId, "backendId");
        Objects.requireNonNull(properties, "properties");
        if (backendId.isBlank()) {
            throw new IllegalArgumentException("backendId must not be blank");
        }
        properties = Map.copyOf(properties);
    }

    /**
     * Returns an optional value for the given key.
     *
     * @param key key (never {@code null})
     * @return optional value (never {@code null})
     */
    public Optional<String> get(String key) {
        Objects.requireNonNull(key, "key");
        return Optional.ofNullable(properties.get(key));
    }

    /**
     * Returns a required non-blank value for the given key.
     *
     * @param key key (never {@code null})
     * @return value (never {@code null}, never blank)
     * @throws IllegalArgumentException if missing or blank
     */
    public String require(String key) {
        Objects.requireNonNull(key, "key");
        String v = properties.get(key);
        if (v == null || v.isBlank()) {
            throw new IllegalArgumentException("Missing required config key: " + key);
        }
        return v;
    }
}
