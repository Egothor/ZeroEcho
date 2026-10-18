/* ******************************************************************************
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
package zeroecho.pki.impl.secrets;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.pki.spi.ProviderConfig;

/**
 * Resolves secret references in publisher provider configurations.
 *
 * <p>
 * Property values with a recognised scheme prefix are replaced with the
 * resolved secret value before the publisher is allocated:
 * </p>
 * <ul>
 * <li>{@code keyring:<id>} — secret looked up by identifier in the decrypted
 * {@link PublisherSecretsStore}</li>
 * <li>{@code env:<VAR>} — value read from the named environment variable</li>
 * <li>{@code dev-plaintext:<value>} — literal value used as-is; emits a
 * {@link Level#SEVERE} warning. <strong>Must not be used in
 * production.</strong></li>
 * </ul>
 *
 * <p>
 * Resolved secret values must never be logged. Only prefixes and identifier
 * keys may appear in log output.
 * </p>
 */
public final class PublisherSecretResolver {
    private static final Logger LOG = Logger.getLogger(PublisherSecretResolver.class.getName());

    private static final String PREFIX_KEYRING = "keyring:";
    private static final String PREFIX_ENV = "env:";
    private static final String PREFIX_DEV = "dev-plaintext:";

    private final Map<String, String> store;

    /**
     * Creates a resolver backed by the given decrypted secrets.
     *
     * @param store immutable map of secret identifier to secret value (may be
     *              empty)
     */
    public PublisherSecretResolver(Map<String, String> store) {
        this.store = Map.copyOf(store);
    }

    /**
     * Returns a new {@link ProviderConfig} with all secret references in property
     * values resolved to their plaintext equivalents.
     *
     * @param config non-null provider configuration; the input is not modified
     * @return a new configuration containing resolved secrets; do not log its
     *         properties
     * @throws IllegalArgumentException if a {@code keyring:} reference is not found
     *                                  in the store or an {@code env:} variable is
     *                                  unset or empty
     */
    public ProviderConfig resolve(ProviderConfig config) {
        Map<String, String> resolved = new LinkedHashMap<>(config.properties());
        for (Map.Entry<String, String> entry : config.properties().entrySet()) {
            String value = entry.getValue();
            if (value.startsWith(PREFIX_KEYRING)) {
                String secretId = value.substring(PREFIX_KEYRING.length());
                String secret = store.get(secretId);
                if (secret == null) {
                    throw new IllegalArgumentException("Publisher secret not found in store: " + secretId);
                }
                resolved.put(entry.getKey(), secret);
            } else if (value.startsWith(PREFIX_ENV)) {
                String envName = value.substring(PREFIX_ENV.length());
                String envVal = System.getenv(envName);
                if (envVal == null || envVal.isEmpty()) {
                    throw new IllegalArgumentException("Publisher secret environment variable is not set: " + envName);
                }
                resolved.put(entry.getKey(), envVal);
            } else if (value.startsWith(PREFIX_DEV)) {
                if (LOG.isLoggable(Level.SEVERE)) {
                    LOG.log(Level.SEVERE,
                            "SECURITY WARNING: plaintext publisher credential in configuration "
                                    + "for property [{0}]. This is UNSAFE and MUST NOT be used in production.",
                            entry.getKey());
                }
                resolved.put(entry.getKey(), value.substring(PREFIX_DEV.length()));
            }
        }
        return new ProviderConfig(config.backendId(), Map.copyOf(resolved));
    }
}
