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
package zeroecho.pki.impl.crypto.pkcs11;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.DigestOutputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.pki.api.PkiException;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProvider.ConfigurationCommitment;
import zeroecho.pki.spi.crypto.SigningProviderFactory;
import zeroecho.pki.spi.crypto.SigningProviderRuntimeDependencies;

/**
 * ServiceLoader factory for the PKCS#11 / HSM signing provider.
 *
 * <p>Keys are generated on the HSM and never exported. Cryptographic operations
 * execute on the HSM token via the JDK's built-in {@code SunPKCS11} provider.
 * This satisfies FIPS 140-3 Level 3 requirements for key non-exportability.</p>
 *
 * <h2>Configuration keys</h2>
 * <ul>
 *   <li>{@code pkcs11ConfigFile} (required): path to the SunPKCS11 library config file</li>
 *   <li>{@code pinVariable} (required): name of the environment variable holding the HSM PIN</li>
 *   <li>{@code slot} (optional, default {@code 0}): PKCS#11 slot index</li>
 *   <li>{@code keyLabelPattern} (optional, default {@code zeroecho-{authorityId}}): key label template</li>
 *   <li>{@code keyRefPrefix} (optional): prefix applied to key references</li>
 *   <li>{@code operationHorizon} (optional, ISO-8601 duration, default {@code P90D})</li>
 *   <li>{@code sessionPoolSize} (optional, default {@code 2}): number of PKCS#11 sessions</li>
 *   <li>{@code supportedAlgorithms} (optional, comma-separated JCA names)</li>
 * </ul>
 *
 * <h2>Security</h2>
 * <p>The PIN is read from the environment variable named by {@code pinVariable},
 * never from the config file itself. Configuration values must not be logged.</p>
 *
 * @since 1.0
 */
public final class Pkcs11SigningProviderFactory implements SigningProviderFactory {

    /** Stable failure code when the HSM PIN environment variable is absent or empty. */
    public static final String DC_PIN_ENV_NOT_SET = "HSM_PIN_ENV_NOT_SET";
    /** Stable failure code when the PKCS#11 provider cannot be loaded. */
    public static final String DC_PKCS11_PROVIDER_LOAD_FAILED = "PKCS11_PROVIDER_LOAD_FAILED"; // NOPMD LongVariable - Preserve the exported stable diagnostic code name.
    /** Stable failure code when the HSM KeyStore cannot be opened. */
    public static final String DC_HSM_KEYSTORE_OPEN_FAILED = "HSM_KEYSTORE_OPEN_FAILED";

    private static final Logger LOG = Logger.getLogger(Pkcs11SigningProviderFactory.class.getName());

    /** Default JCA algorithm names supported by FIPS-validated HSMs. */
    /* default */ static final Set<String> DEFAULT_ALGORITHMS = Set.of(
            "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA", "RSASSA-PSS");

    private static final String KEY_PKCS11_CONFIG_FILE = "pkcs11ConfigFile";
    private static final String KEY_PIN_VARIABLE = "pinVariable";
    private static final String KEY_SLOT = "slot";
    private static final String KEY_KEY_LABEL_PATTERN = "keyLabelPattern";
    private static final String KEY_KEY_REF_PREFIX = "keyRefPrefix";
    private static final String KEY_OPERATION_HORIZON = "operationHorizon";
    private static final String KEY_SESSION_POOL_SIZE = "sessionPoolSize";
    private static final String KEY_SUPPORTED_ALGORITHMS = "supportedAlgorithms";

    /**
     * Guards against duplicate SunPKCS11 provider registration for the same config file.
     * Key is the canonical path of the PKCS#11 config file.
     */
    private static final java.util.concurrent.ConcurrentMap<String, Provider> REGISTERED_PROVIDERS = new ConcurrentHashMap<>();

    @Override
    public String id() {
        return "pkcs11";
    }

    @Override
    public Set<String> supportedKeys() {
        return Set.of(KEY_PKCS11_CONFIG_FILE, KEY_PIN_VARIABLE, KEY_SLOT,
                KEY_KEY_LABEL_PATTERN, KEY_KEY_REF_PREFIX, KEY_OPERATION_HORIZON,
                KEY_SESSION_POOL_SIZE, KEY_SUPPORTED_ALGORITHMS);
    }

    /**
     * Validates configuration for the PKCS#11 signing provider.
     *
     * @param config provider configuration (never {@code null})
     * @throws IllegalArgumentException if the configuration is incomplete or invalid
     */
    @Override
    public void validateConfig(ProviderConfig config) {
        SigningProviderFactory.super.validateConfig(config);
        String configFile = config.require(KEY_PKCS11_CONFIG_FILE);
        Path.of(configFile); // validates it is a syntactically valid path
        config.require(KEY_PIN_VARIABLE); // must be present and non-blank
        config.get(KEY_SLOT).ifPresent(value -> {
            try {
                int slot = Integer.parseInt(value);
                if (slot < 0) {
                    throw new IllegalArgumentException("Configuration key 'slot' must be non-negative.");
                }
            } catch (NumberFormatException invalid) {
                throw new IllegalArgumentException("Configuration key 'slot' must be an integer: " + value, invalid);
            }
        });
        config.get(KEY_SESSION_POOL_SIZE).ifPresent(value -> {
            try {
                int size = Integer.parseInt(value);
                if (size < 1 || size > 64) {
                    throw new IllegalArgumentException(
                            "Configuration key 'sessionPoolSize' must be between 1 and 64.");
                }
            } catch (NumberFormatException invalid) {
                throw new IllegalArgumentException(
                        "Configuration key 'sessionPoolSize' must be an integer: " + value, invalid);
            }
        });
        config.get(KEY_OPERATION_HORIZON).ifPresent(value -> {
            Duration horizon = Duration.parse(value);
            if (horizon.isZero() || horizon.isNegative()) {
                throw new IllegalArgumentException(
                        "Configuration key 'operationHorizon' must be positive.");
            }
        });
        for (String key : config.properties().keySet()) {
            if (!supportedKeys().contains(key) && LOG.isLoggable(Level.WARNING)) {
                LOG.warning("Ignoring unknown PKCS#11 signing provider configuration key: " + key);
            }
        }
    }

    @Override
    public SigningProvider allocate(ProviderConfig config) {
        return allocate(config, SigningProviderRuntimeDependencies.none());
    }

    @Override
    public SigningProvider allocate(ProviderConfig config, SigningProviderRuntimeDependencies dependencies) {
        validateConfig(config);
        String pkcs11ConfigFile = config.require(KEY_PKCS11_CONFIG_FILE);
        String pinVariable = config.require(KEY_PIN_VARIABLE);
        int slot = Integer.parseInt(config.get(KEY_SLOT).orElse("0"));
        int sessionPoolSize = Integer.parseInt(config.get(KEY_SESSION_POOL_SIZE).orElse("2"));
        Duration operationHorizon = config.get(KEY_OPERATION_HORIZON)
                .map(Duration::parse).orElse(Duration.ofDays(90));
        String keyRefPrefix = config.get(KEY_KEY_REF_PREFIX).orElse("");
        String keyLabelPattern = config.get(KEY_KEY_LABEL_PATTERN).orElse("zeroecho-{authorityId}");
        Set<String> algorithms = config.get(KEY_SUPPORTED_ALGORITHMS)
                .map(Pkcs11SigningProviderFactory::parseAlgorithms)
                .orElse(DEFAULT_ALGORITHMS);

        char[] pin = readPinFromEnv(pinVariable);
        Provider provider = acquireProvider(pkcs11ConfigFile);
        ConfigurationCommitment commitment = computeCommitment(pkcs11ConfigFile, slot, algorithms);
        KeyStore keyStore = openKeyStore(provider, pin);
        return new Pkcs11SigningProvider(id(), keyStore, provider, algorithms, commitment,
                operationHorizon, keyRefPrefix, keyLabelPattern, sessionPoolSize);
    }

    /**
     * Reads the HSM PIN from the named environment variable.
     *
     * <p>The returned {@code char[]} must be zeroed by the caller after use.
     * The source {@code String} from the environment cannot be zeroed (JVM heap),
     * but will be garbage-collected.</p>
     *
     * @param variableName environment variable name (never {@code null})
     * @return PIN characters (caller must zero after use)
     * @throws PkiException if the variable is absent or empty
     */
    /* default */ static char[] readPinFromEnv(String variableName) {
        String value = System.getenv(variableName);
        if (value == null || value.isEmpty()) {
            throw new PkiException(DC_PIN_ENV_NOT_SET + ": " + variableName);
        }
        return value.toCharArray();
    }

    private static Provider acquireProvider(String pkcs11ConfigFile) {
        return REGISTERED_PROVIDERS.computeIfAbsent(Path.of(pkcs11ConfigFile).toAbsolutePath().toString(),
                key -> {
                    Provider prototype = Security.getProvider("SunPKCS11");
                    if (prototype == null) {
                        throw new PkiException(DC_PKCS11_PROVIDER_LOAD_FAILED + ": SunPKCS11 not available");
                    }
                    Provider configured = prototype.configure(pkcs11ConfigFile);
                    Security.addProvider(configured);
                    return configured;
                });
    }


    private static KeyStore openKeyStore(Provider provider, char... pin) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
            try {
                keyStore.load(null, pin);
            } finally {
                Arrays.fill(pin, '\0');
            }
            return keyStore;
        } catch (Exception failure) {
            throw new PkiException(DC_HSM_KEYSTORE_OPEN_FAILED, failure);
        }
    }

    private static Set<String> parseAlgorithms(String csv) {
        Set<String> result = new LinkedHashSet<>();
        for (String part : csv.split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        if (result.isEmpty()) {
            throw new IllegalArgumentException("supportedAlgorithms must not be empty");
        }
        return Set.copyOf(result);
    }

    /* default */ static ConfigurationCommitment computeCommitment(String pkcs11ConfigFile, int slot,
            Set<String> algorithms) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (DataOutputStream out = new DataOutputStream(
                    new DigestOutputStream(OutputStream.nullOutputStream(), digest))) {
                out.writeUTF("pkcs11-provider-v1");
                out.writeUTF(Path.of(pkcs11ConfigFile).toAbsolutePath().toString());
                out.writeInt(slot);
                out.writeInt(algorithms.size());
                for (String alg : new TreeSet<>(algorithms)) {
                    out.writeUTF(alg);
                }
            }
            return new ConfigurationCommitment(digest.digest());
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 is unavailable", unavailable);
        } catch (IOException impossible) {
            throw new IllegalStateException("In-memory commitment computation failed", impossible);
        }
    }
    /** Creates a provider factory without opening an HSM session. */
    public Pkcs11SigningProviderFactory() {
        super();
    }
}
