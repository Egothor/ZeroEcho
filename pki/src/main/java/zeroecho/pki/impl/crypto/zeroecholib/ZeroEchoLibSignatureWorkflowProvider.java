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
package zeroecho.pki.impl.crypto.zeroecholib;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.crypto.SignatureWorkflowProvider;

/**
 * Production provider bridging PKI signature workflow to ZeroEcho lib based on
 * {@code KeyringStore}.
 *
 * <p>
 * Configuration keys:
 * </p>
 * <ul>
 * <li>{@code keyringPath} (required): filesystem path to the KeyringStore
 * file</li>
 * <li>{@code operationRoot} (required): exclusively owned durable signing
 * operation directory</li>
 * <li>{@code operationHorizon} (optional ISO-8601 duration, default
 * {@code P90D})</li>
 * <li>{@code keyRefPrefix} (optional, default {@code "zeroecho-lib:"})</li>
 * <li>{@code requireComponentSuffix} (optional, default {@code true})</li>
 * </ul>
 *
 * <h2>Security</h2>
 * <p>
 * Configuration values may be sensitive and must not be logged. This provider
 * performs no value logging.
 * </p>
 */
public final class ZeroEchoLibSignatureWorkflowProvider implements SignatureWorkflowProvider {
    private static final Logger LOG = Logger.getLogger(ZeroEchoLibSignatureWorkflowProvider.class.getName());

    private static final String KEY_KEYRING_PATH = "keyringPath";
    private static final String KEY_OPERATION_ROOT = "operationRoot";
    private static final String KEY_OPERATION_HORIZON = "operationHorizon";
    private static final String KEY_KEYREF_PREFIX = "keyRefPrefix";
    private static final String KEY_REQUIRE_SUFFIX = "requireComponentSuffix";

    @Override
    public String id() {
        return "zeroecho-lib";
    }

    @Override
    public Set<String> supportedKeys() {
        return Set.of(KEY_KEYRING_PATH, KEY_OPERATION_ROOT, KEY_OPERATION_HORIZON, KEY_KEYREF_PREFIX,
                KEY_REQUIRE_SUFFIX);
    }

    /**
     * Validates configuration for the ZeroEcho-lib signature workflow provider.
     *
     * @param config provider configuration (never {@code null})
     * @throws IllegalArgumentException if the configuration is incomplete or
     *                                  invalid
     */
    @Override
    public void validateConfig(final ProviderConfig config) {
        SignatureWorkflowProvider.super.validateConfig(config);
        String keyringPath = config.require(KEY_KEYRING_PATH);
        Path.of(keyringPath);
        Path.of(config.require(KEY_OPERATION_ROOT));
        config.get(KEY_OPERATION_HORIZON).ifPresent(value -> {
            Duration horizon = Duration.parse(value);
            if (horizon.isZero() || horizon.isNegative()) {
                throw new IllegalArgumentException("Configuration key '" + KEY_OPERATION_HORIZON + "' must be positive.");
            }
        });
        config.get(KEY_KEYREF_PREFIX).ifPresent(value -> {
            if (value.isBlank()) {
                throw new IllegalArgumentException("Configuration key '" + KEY_KEYREF_PREFIX + "' must not be blank.");
            }
        });
        config.get(KEY_REQUIRE_SUFFIX).ifPresent(value -> {
            if (!("true".equalsIgnoreCase(value) || "false".equalsIgnoreCase(value))) {
                throw new IllegalArgumentException(
                        "Configuration key '" + KEY_REQUIRE_SUFFIX + "' must be 'true' or 'false'.");
            }
        });
        for (String key : config.properties().keySet()) {
            if (!supportedKeys().contains(key) && LOG.isLoggable(Level.WARNING)) {
                LOG.warning("Ignoring unknown signature workflow configuration key: " + key);
            }
        }
    }

    @Override
    public SignatureWorkflow allocate(final ProviderConfig config) {
        validateConfig(config);
        String keyringPath = config.require(KEY_KEYRING_PATH);
        Path operationRoot = Path.of(config.require(KEY_OPERATION_ROOT));
        Duration operationHorizon = config.get(KEY_OPERATION_HORIZON).map(Duration::parse).orElse(Duration.ofDays(90));
        String prefix = config.get(KEY_KEYREF_PREFIX).orElse("zeroecho-lib:");
        boolean requireSuffix = config.get(KEY_REQUIRE_SUFFIX).map(Boolean::parseBoolean).orElse(Boolean.TRUE);

        return new ZeroEchoLibSignatureWorkflow(id(), Path.of(keyringPath), operationRoot, Clock.systemUTC(),
                operationHorizon, prefix, requireSuffix);
    }
}
