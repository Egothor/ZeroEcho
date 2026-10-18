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
package zeroecho.pki.impl.crypto.zeroecholib;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.core.spi.AlgorithmExecutionCapabilityProvider;
import zeroecho.core.spi.KeyringUnlockProvider;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProviderFactory;
import zeroecho.pki.spi.crypto.SigningProviderRuntimeDependencies;

/**
 * Production signing-provider factory bridging PKI requests to ZeroEcho lib based on
 * {@code KeyringStore}.
 *
 * <p>
 * Configuration keys:
 * </p>
 * <ul>
 * <li>{@code keyringPath} (required): filesystem path to the KeyringStore
 * file</li>
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
public final class ZeroEchoLibSigningProviderFactory
        implements SigningProviderFactory, AlgorithmExecutionCapabilityProvider {
    /** Stable failure code for a missing explicit keyring unlock provider. */
    @SuppressWarnings("PMD.LongVariable")
    public static final String DC_KEYRING_UNLOCK_PROVIDER_REQUIRED = "KEYRING_UNLOCK_PROVIDER_REQUIRED";
    /** Stable failure code for an unlock-provider acquisition failure. */
    @SuppressWarnings("PMD.LongVariable")
    public static final String DC_KEYRING_UNLOCK_PROVIDER_FAILED = "KEYRING_UNLOCK_PROVIDER_FAILED";
    /** Stable failure code for an I/O failure while opening the keyring. */
    public static final String DC_KEYRING_OPEN_FAILED = "KEYRING_OPEN_FAILED";

    private static final Logger LOG = Logger.getLogger(ZeroEchoLibSigningProviderFactory.class.getName());

    private static final String KEY_KEYRING_PATH = "keyringPath";
    private static final String KEY_OPERATION_HORIZON = "operationHorizon";
    private static final String KEY_KEYREF_PREFIX = "keyRefPrefix";
    private static final String KEY_REQUIRE_SUFFIX = "requireComponentSuffix";
    private final KeyringUnlockProvider keyringUnlockProvider;

    /**
     * Creates a service-loadable provider without unlock material.
     *
     * <p>
     * {@link #allocate(ProviderConfig)} fails until an explicitly injected provider
     * instance is used. Service configuration text can never contain an unlock
     * secret.
     * </p>
     */
    public ZeroEchoLibSigningProviderFactory() {
        this.keyringUnlockProvider = null;
    }

    /**
     * Creates a provider with an explicit headless unlock source.
     *
     * @param keyringUnlockProvider provider returning a fresh destroyable password
     *                              for each keyring open
     */
    public ZeroEchoLibSigningProviderFactory(KeyringUnlockProvider keyringUnlockProvider) {
        this.keyringUnlockProvider = java.util.Objects.requireNonNull(keyringUnlockProvider,
                "keyringUnlockProvider must not be null");
    }

    @Override
    public String id() {
        return "zeroecho-lib";
    }

    @Override
    public Set<String> supportedKeys() {
        return Set.of(KEY_KEYRING_PATH, KEY_OPERATION_HORIZON, KEY_KEYREF_PREFIX,
                KEY_REQUIRE_SUFFIX);
    }

    /**
     * Declares the exact classic signature domain implemented by the provider.
     *
     * <p>
     * This metadata describes the same provider implementation allocated by this
     * provider. It does not select an OID, redefine an identity, or claim key
     * availability.
     * </p>
     *
     * @return immutable execution capability contribution
     */
    @Override
    public java.util.List<AlgorithmExecutionCapability> capabilities() {
        Set<AlgorithmIdentity> signatures = Set.of(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA512,
                BootstrapAlgorithmIdentities.RSA_PSS_SHA256, BootstrapAlgorithmIdentities.ECDSA_SHA256,
                BootstrapAlgorithmIdentities.ECDSA_SHA384, BootstrapAlgorithmIdentities.ECDSA_SHA512,
                BootstrapAlgorithmIdentities.ED25519_SIGNATURE, BootstrapAlgorithmIdentities.ED448_SIGNATURE,
                BootstrapAlgorithmIdentities.SPHINCS_PLUS_SIGNATURE,
                BootstrapAlgorithmIdentities.ML_DSA_44_SIGNATURE,
                BootstrapAlgorithmIdentities.ML_DSA_65_SIGNATURE,
                BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE,
                BootstrapAlgorithmIdentities.SLH_DSA_SHA2_128S_SIGNATURE,
                BootstrapAlgorithmIdentities.SLH_DSA_SHA2_128F_SIGNATURE,
                BootstrapAlgorithmIdentities.SLH_DSA_SHA2_192S_SIGNATURE,
                BootstrapAlgorithmIdentities.SLH_DSA_SHA2_192F_SIGNATURE,
                BootstrapAlgorithmIdentities.SLH_DSA_SHA2_256S_SIGNATURE,
                BootstrapAlgorithmIdentities.SLH_DSA_SHA2_256F_SIGNATURE,
                BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_128S_SIGNATURE,
                BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_128F_SIGNATURE,
                BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_192S_SIGNATURE,
                BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_192F_SIGNATURE,
                BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_256S_SIGNATURE,
                BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_256F_SIGNATURE);
        return java.util.List.of(new AlgorithmExecutionCapability() {
            @Override
            public String implementationId() {
                return "zeroecho-lib.signing-provider";
            }

            @Override
            public String domainFingerprint() {
                return "zeroecho-lib-signature-v2:bootstrap-classic+pqc:sign,verify";
            }

            @Override
            public boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction direction) {
                return signatures.contains(identity) && identity.equals(suite.signature());
            }
        });
    }

    /**
     * Validates configuration for the ZeroEcho-lib signing provider.
     *
     * @param config provider configuration (never {@code null})
     * @throws IllegalArgumentException if the configuration is incomplete or
     *                                  invalid
     */
    @Override
    public void validateConfig(final ProviderConfig config) {
        SigningProviderFactory.super.validateConfig(config);
        String keyringPath = config.require(KEY_KEYRING_PATH);
        Path.of(keyringPath);
        if (config.properties().containsKey("operationRoot")) {
            throw new IllegalArgumentException("Configuration key 'operationRoot' is not supported");
        }
        config.get(KEY_OPERATION_HORIZON).ifPresent(value -> {
            Duration horizon = Duration.parse(value);
            if (horizon.isZero() || horizon.isNegative()) {
                throw new IllegalArgumentException(
                        "Configuration key '" + KEY_OPERATION_HORIZON + "' must be positive.");
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
                LOG.warning("Ignoring unknown signing provider configuration key: " + key);
            }
        }
    }

    @Override
    public SigningProvider allocate(final ProviderConfig config) {
        KeyringUnlockProvider provider = keyringUnlockProvider;
        if (provider == null) {
            throw new PkiException(DC_KEYRING_UNLOCK_PROVIDER_REQUIRED);
        }
        return allocate(config, provider);
    }

    /**
     * Allocates a signing provider using explicit runtime dependencies.
     *
     * @param config       structural provider configuration
     * @param dependencies explicit process-local runtime dependencies
     * @return opened provider owning an unlocked keyring
     * @throws PkiException     if the keyring unlock provider is absent or fails
     * @throws RuntimeException if provider allocation otherwise fails
     */
    @Override
    public SigningProvider allocate(final ProviderConfig config, SigningProviderRuntimeDependencies dependencies) {
        java.util.Objects.requireNonNull(dependencies, "dependencies must not be null");
        KeyringUnlockProvider provider = dependencies.keyringUnlockProvider().orElse(keyringUnlockProvider);
        if (provider == null) {
            throw new PkiException(DC_KEYRING_UNLOCK_PROVIDER_REQUIRED);
        }
        return allocate(config, provider, dependencies.clock());
    }


    private SigningProvider allocate(final ProviderConfig config, KeyringUnlockProvider unlockProvider) {
        return allocate(config, unlockProvider, Clock.systemUTC());
    }

    private SigningProvider allocate(final ProviderConfig config, KeyringUnlockProvider unlockProvider, Clock clock) {
        validateConfig(config);
        String keyringPath = config.require(KEY_KEYRING_PATH);
        Duration operationHorizon = config.get(KEY_OPERATION_HORIZON).map(Duration::parse).orElse(Duration.ofDays(90));
        String prefix = config.get(KEY_KEYREF_PREFIX).orElse("zeroecho-lib:");
        boolean requireSuffix = config.get(KEY_REQUIRE_SUFFIX).map(Boolean::parseBoolean).orElse(Boolean.TRUE);

        KeyringStore keyring = openKeyring(Path.of(keyringPath), unlockProvider);
        try {
            return new ZeroEchoLibSigningProvider(id(), Path.of(keyringPath), Path.of(keyringPath),
                    clock, operationHorizon, prefix, requireSuffix, unlockProvider, keyring);
        } catch (RuntimeException | Error failure) { // NOPMD AvoidCatchingGenericException - Construction failure must release transferred keyring ownership and retain the original failure.
            try {
                keyring.close();
            } catch (RuntimeException cleanup) { // NOPMD AvoidCatchingGenericException - Cleanup must not mask the original construction failure.
                if (cleanup != failure) { failure.addSuppressed(cleanup); } // NOPMD CompareObjectsWithEquals - Throwable self-suppression requires identity comparison.
            }
            throw failure;
        }
    }

    /*
     * The unlock provider is arbitrary application code. Its throwable message and
     * cause are intentionally removed at this security boundary.
     */
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    private static KeyringStore openKeyring(Path keyringPath, KeyringUnlockProvider unlockProvider) {
        KeyringPassword password;
        try {
            password = unlockProvider.acquire();
        } catch (IOException | RuntimeException failure) {
            throw new PkiException(DC_KEYRING_UNLOCK_PROVIDER_FAILED);
        }
        if (password == null) {
            throw new PkiException(DC_KEYRING_UNLOCK_PROVIDER_FAILED);
        }
        try (password) {
            try {
                return KeyringStore.open(keyringPath, password);
            } catch (IOException | GeneralSecurityException failure) {
                throw new PkiException(DC_KEYRING_OPEN_FAILED);
            }
        }
    }
}
