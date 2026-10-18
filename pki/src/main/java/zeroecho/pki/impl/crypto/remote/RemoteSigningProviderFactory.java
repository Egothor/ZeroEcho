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
package zeroecho.pki.impl.crypto.remote;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import javax.net.ssl.SSLContext;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.core.spi.AlgorithmExecutionCapabilityProvider;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.impl.crypto.remote.http.HttpsRemoteSigningTransport;
import zeroecho.pki.impl.crypto.remote.http.MutualTlsContext;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProviderFactory;
import zeroecho.pki.spi.crypto.SigningProviderRuntimeDependencies;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport;

/**
 * Service-loadable factory that binds the PKI to a remote signing service
 * through {@link SigningProvider}.
 *
 * <p>
 * The remote service is attached by a unique endpoint identifier stating where it
 * is remotely reachable; its internal implementation is free (any technology) and
 * it may gate each signature behind an external operator. Private keys never leave
 * the remote side: this provider requires no process-local keyring.
 * </p>
 *
 * <h2>Configuration</h2>
 * <ul>
 * <li>{@code endpoint} (required) — unique identifier/address of the remote service</li>
 * <li>{@code keyRefPrefix} (optional, default {@code "zeroecho-remote:"})</li>
 * <li>{@code operationHorizon} (optional ISO-8601, fixed at {@code P90D})</li>
 * </ul>
 * <p>Transport-specific keys (trust anchors, client credential) are consumed by the
 * concrete {@link RemoteSigningTransport} opened for the endpoint.</p>
 *
 * <h2>Capability registration</h2>
 * <p>
 * This provider also declares its signature capabilities under a distinct
 * implementation id ({@code zeroecho-remote.signing-provider}). Because the
 * signing-plan resolver binds exactly one implementation per algorithm, the remote
 * and local ({@code zeroecho-lib}) providers are mutually exclusive signing
 * backends: a deployment registers this provider's
 * {@code AlgorithmExecutionCapabilityProvider} entry in place of the local one,
 * never alongside it.
 * </p>
 */
public class RemoteSigningProviderFactory
        implements SigningProviderFactory, AlgorithmExecutionCapabilityProvider {

    /** Stable implementation id for capability binding. */
    public static final String IMPLEMENTATION_ID = "zeroecho-remote.signing-provider";
    /** Stable failure code when no concrete transport is configured for the endpoint. */
    @SuppressWarnings("PMD.LongVariable")
    public static final String DC_REMOTE_TRANSPORT_UNCONFIGURED = "REMOTE_TRANSPORT_UNCONFIGURED";

    private static final String KEY_ENDPOINT = "endpoint";
    private static final String KEY_KEYREF_PREFIX = "keyRefPrefix";
    private static final String KEY_OPERATION_HORIZON = "operationHorizon";
    private static final String KEY_TLS_KEYSTORE = "tlsKeystore";
    private static final String KEY_TLS_KEYSTORE_PASSWORD = "tlsKeystorePassword";
    private static final String KEY_TLS_TRUSTSTORE = "tlsTruststore";
    private static final String KEY_TLS_TRUSTSTORE_PASSWORD = "tlsTruststorePassword";
    private static final String KEY_TLS_PROTOCOL = "tlsProtocol";

    private static final String KEY_CONNECT_TIMEOUT_MS = "connectTimeoutMillis";
    private static final String KEY_CALL_TIMEOUT_MS = "callTimeoutMillis";
    private static final String DEFAULT_TLS_PROTOCOL = "TLSv1.3";
    private static final long DEFAULT_CONNECT_TIMEOUT_MS = 10_000L;
    private static final long DEFAULT_CALL_TIMEOUT_MS = 30_000L;
    private static final Duration FIXED_HORIZON = Duration.ofDays(90);

    /** Creates a remote signing-provider factory. */
    public RemoteSigningProviderFactory() {
        // Stateless provider descriptor.
    }

    @Override
    public String id() {
        return "zeroecho-remote";
    }

    @Override
    public Set<String> supportedKeys() {
        return Set.of(KEY_ENDPOINT, KEY_KEYREF_PREFIX, KEY_OPERATION_HORIZON, KEY_TLS_KEYSTORE,
                KEY_TLS_KEYSTORE_PASSWORD, KEY_TLS_TRUSTSTORE, KEY_TLS_TRUSTSTORE_PASSWORD, KEY_TLS_PROTOCOL,
                KEY_CONNECT_TIMEOUT_MS, KEY_CALL_TIMEOUT_MS);
    }

    @Override
    public List<AlgorithmExecutionCapability> capabilities() {
        Set<AlgorithmIdentity> signatures = Set.of(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA512,
                BootstrapAlgorithmIdentities.RSA_PSS_SHA256, BootstrapAlgorithmIdentities.ECDSA_SHA256,
                BootstrapAlgorithmIdentities.ECDSA_SHA384, BootstrapAlgorithmIdentities.ECDSA_SHA512,
                BootstrapAlgorithmIdentities.ED25519_SIGNATURE, BootstrapAlgorithmIdentities.ED448_SIGNATURE,
                BootstrapAlgorithmIdentities.SPHINCS_PLUS_SIGNATURE);
        return List.of(new AlgorithmExecutionCapability() {
            @Override
            public String implementationId() {
                return IMPLEMENTATION_ID;
            }

            @Override
            public String domainFingerprint() {
                return "zeroecho-remote-signature-v1:bootstrap-classic:sign,verify";
            }

            @Override
            public boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction direction) {
                return signatures.contains(identity) && identity.equals(suite.signature());
            }
        });
    }

    @Override
    public void validateConfig(ProviderConfig config) {
        SigningProviderFactory.super.validateConfig(config);
        config.require(KEY_ENDPOINT);
        config.get(KEY_KEYREF_PREFIX).ifPresent(value -> {
            if (value.isBlank()) {
                throw new IllegalArgumentException("Configuration key '" + KEY_KEYREF_PREFIX + "' must not be blank.");
            }
        });
        config.get(KEY_OPERATION_HORIZON).ifPresent(value -> {
            if (!FIXED_HORIZON.equals(Duration.parse(value))) {
                throw new IllegalArgumentException(
                        "Configuration key '" + KEY_OPERATION_HORIZON + "' must equal P90D.");
            }
        });
    }

    @Override
    public SigningProvider allocate(ProviderConfig config) {
        validateConfig(config);
        String keyRefPrefix = config.get(KEY_KEYREF_PREFIX).orElse("zeroecho-remote:");
        RemoteSigningTransport transport = openTransport(config);
        return new RemoteSigningProvider(id(), transport, keyRefPrefix, FIXED_HORIZON);
    }

    @Override
    public SigningProvider allocate(ProviderConfig config, SigningProviderRuntimeDependencies dependencies) {
        Objects.requireNonNull(dependencies, "dependencies must not be null");
        // A remote provider keeps keys on the remote side and needs no process-local capability.
        return allocate(config);
    }

    /**
     * Opens the concrete transport for the configured remote endpoint.
     *
     * <p>
     * The default binds the packaged mutually-authenticated HTTPS transport
     * ({@link HttpsRemoteSigningTransport}), building its TLS context from the
     * configured PKCS#12 client keystore and trust store. When no TLS keystore is
     * configured the endpoint has no packaged transport and this fails with
     * {@link #DC_REMOTE_TRANSPORT_UNCONFIGURED}; deployments (or tests) may override
     * this method to attach an alternative technology behind the endpoint identifier.
     * </p>
     *
     * @param config validated provider configuration
     * @return an open transport to the remote signing service
     */
    protected RemoteSigningTransport openTransport(ProviderConfig config) {
        if (config.get(KEY_TLS_KEYSTORE).isEmpty()) {
            throw new PkiException("Remote signing transport is not configured: code="
                    + DC_REMOTE_TRANSPORT_UNCONFIGURED);
        }
        URI endpoint = parseUri(config.require(KEY_ENDPOINT));
        SSLContext sslContext = MutualTlsContext.fromPkcs12(Path.of(config.require(KEY_TLS_KEYSTORE)),
                config.require(KEY_TLS_KEYSTORE_PASSWORD).toCharArray(), Path.of(config.require(KEY_TLS_TRUSTSTORE)),
                config.require(KEY_TLS_TRUSTSTORE_PASSWORD).toCharArray(),
                config.get(KEY_TLS_PROTOCOL).orElse(DEFAULT_TLS_PROTOCOL));
        return HttpsRemoteSigningTransport.open(endpoint, sslContext,
                positiveDuration(config, KEY_CONNECT_TIMEOUT_MS, DEFAULT_CONNECT_TIMEOUT_MS),
                positiveDuration(config, KEY_CALL_TIMEOUT_MS, DEFAULT_CALL_TIMEOUT_MS));
    }

    private static Duration positiveDuration(ProviderConfig config, String key, long defaultMillis) {
        long millis = config.get(key).map(value -> {
            try {
                return Long.parseLong(value);
            } catch (NumberFormatException invalid) {
                throw new IllegalArgumentException("Configuration key '" + key + "' must be a positive integer.",
                        invalid);
            }
        }).orElse(defaultMillis);
        if (!isPositive(millis)) {
            throw new IllegalArgumentException("Configuration key '" + key + "' must be a positive integer.");
        }
        return Duration.ofMillis(millis);
    }

    // URISyntaxException diagnostics repeat the raw endpoint, which may contain user-info or query secrets.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private static URI parseUri(String endpoint) {
        try {
            return new URI(endpoint);
        } catch (URISyntaxException invalid) {
            throw new IllegalArgumentException("Configuration key '" + KEY_ENDPOINT + "' is not a valid URI");
        }
    }

    private static boolean isPositive(long value) {
        return value > 0L;
    }
}
