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
package zeroecho.pki.spi.bootstrap;

import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.spi.ConfigurableProvider;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.async.AsyncBusProvider;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.audit.AuditSinkProvider;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.crypto.SignatureWorkflowProvider;
import zeroecho.pki.spi.crypto.SignatureWorkflowRuntimeDependencies;
import zeroecho.pki.spi.framework.CredentialFramework;
import zeroecho.pki.spi.framework.CredentialFrameworkProvider;
import zeroecho.pki.spi.publish.Publisher;
import zeroecho.pki.spi.publish.PublisherProvider;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.PkiStoreProvider;
import zeroecho.pki.util.async.AsyncBus;

/**
 * PKI bootstrap utilities for ServiceLoader-based components.
 *
 * <p>
 * This class provides deterministic selection and instantiation rules for
 * components discovered via {@link java.util.ServiceLoader}. It is designed to
 * scale as more SPIs are introduced (audit, publish, credential frameworks,
 * crypto/workflows, async orchestration, etc.).
 * </p>
 *
 * <h2>System property conventions</h2>
 * <ul>
 * <li>Select store provider: {@code -Dzeroecho.pki.store=&lt;id&gt;}</li>
 * <li>Configure store provider:
 * {@code -Dzeroecho.pki.store.&lt;key&gt;=&lt;value&gt;}</li>
 * <li>Select audit provider: {@code -Dzeroecho.pki.audit=&lt;id&gt;}</li>
 * <li>Configure audit provider:
 * {@code -Dzeroecho.pki.audit.&lt;key&gt;=&lt;value&gt;}</li>
 * <li>Select crypto workflow provider:
 * {@code -Dzeroecho.pki.crypto.workflow=&lt;id&gt;}</li>
 * <li>Configure crypto workflow provider:
 * {@code -Dzeroecho.pki.crypto.workflow.&lt;key&gt;=&lt;value&gt;}</li>
 * <li>Select async bus provider: {@code -Dzeroecho.pki.async=&lt;id&gt;}</li>
 * <li>Configure async bus provider:
 * {@code -Dzeroecho.pki.async.&lt;key&gt;=&lt;value&gt;}</li>
 * <li>Select credential framework provider:
 * {@code -Dzeroecho.pki.framework=&lt;id&gt;}</li>
 * <li>Configure credential framework provider:
 * {@code -Dzeroecho.pki.framework.&lt;key&gt;=&lt;value&gt;}</li>
 * </ul>
 *
 * <p>
 * Security note: configuration values may be sensitive and must not be logged.
 * This bootstrap logs only provider ids and configuration keys.
 * </p>
 */
public final class PkiBootstrap {

    private static final Logger LOG = Logger.getLogger(PkiBootstrap.class.getName());

    private static final String PROP_STORE_BACKEND = "zeroecho.pki.store";
    private static final String PROP_STORE_PREFIX = "zeroecho.pki.store.";

    private static final String PROP_AUDIT_BACKEND = "zeroecho.pki.audit";
    private static final String PROP_AUDIT_PREFIX = "zeroecho.pki.audit.";

    private static final String PROP_CRYPTO_WORKFLOW_BACKEND = "zeroecho.pki.crypto.workflow";
    private static final String PROP_CRYPTO_WORKFLOW_PREFIX = "zeroecho.pki.crypto.workflow.";

    private static final String PROP_ASYNC_BACKEND = "zeroecho.pki.async";
    private static final String PROP_ASYNC_PREFIX = "zeroecho.pki.async.";

    private static final String PROP_FRAMEWORK_BACKEND = "zeroecho.pki.framework";
    private static final String PROP_FRAMEWORK_PREFIX = "zeroecho.pki.framework.";

    private PkiBootstrap() {
        throw new AssertionError("No instances.");
    }

    /**
     * Opens a {@link PkiStore} using {@link PkiStoreProvider} discovered via
     * ServiceLoader.
     *
     * <p>
     * Provider selection is deterministic and fail-fast:
     * </p>
     * <ul>
     * <li>If {@code -Dzeroecho.pki.store=&lt;id&gt;} is specified, the provider
     * with the matching id is selected.</li>
     * <li>If no id is specified and exactly one provider exists, that provider is
     * selected.</li>
     * <li>If multiple providers exist and no id is specified, bootstrap fails as
     * configuration is ambiguous.</li>
     * </ul>
     *
     * <p>
     * Configuration properties are read from {@link System#getProperties()} using
     * the prefix {@code zeroecho.pki.store.}. Values are treated as sensitive and
     * are never logged; only keys may be logged.
     * </p>
     *
     * @return store (never {@code null})
     */
    public static PkiStore openStore() {
        String requestedId = System.getProperty(PROP_STORE_BACKEND);
        Map<String, String> props = SpiSystemProperties.readPrefixed(PROP_STORE_PREFIX);
        PkiStoreProvider provider = selectStoreProvider(requestedId);
        if ("fs".equals(provider.id()) && !props.containsKey("root")) {
            props.put("root", Path.of("pki-store").toString());
        }
        ProviderConfig config = new ProviderConfig(provider.id(), props);
        if (LOG.isLoggable(Level.INFO)) {
            LOG.info("Selected store provider: " + provider.id() + " (keys: " + props.keySet() + ")");
        }
        return provider.allocate(config);
    }

    /**
     * Validates an explicit store configuration without allocating a store.
     *
     * <p>This entry point is intended for lifecycle composition that must reject
     * every invalid configuration before exposing or allocating backend
     * resources. Unknown provider properties are rejected because an explicit
     * application configuration is versioned and closed.</p>
     *
     * @param config immutable store-provider configuration
     * @throws NullPointerException if {@code config} is {@code null}
     * @throws IllegalArgumentException if the provider or configuration is invalid
     */
    public static void validateStoreConfiguration(ProviderConfig config) {
        PkiStoreProvider provider = selectStoreProvider(Objects.requireNonNull(config, "config").backendId());
        requireKnownKeys(provider, config);
        provider.validateConfig(config);
    }

    /**
     * Opens a store from an explicit, strictly validated configuration.
     *
     * @param config immutable store-provider configuration
     * @return opened store owned by the caller
     * @throws IllegalArgumentException if the configuration is invalid
     * @throws RuntimeException if store allocation fails
     */
    public static PkiStore openStore(ProviderConfig config) {
        validateStoreConfiguration(config);
        PkiStoreProvider provider = selectStoreProvider(config.backendId());
        return provider.allocate(config);
    }

    /**
     * Opens an {@link AuditSink} using {@link AuditSinkProvider} discovered via
     * ServiceLoader.
     *
     * @return audit sink (never {@code null})
     */
    public static AuditSink openAudit() {
        String requestedId = System.getProperty(PROP_AUDIT_BACKEND);

        if (requestedId == null) {
            requestedId = "stdout";
        }

        AuditSinkProvider provider = SpiSelector.select(AuditSinkProvider.class, requestedId,
                new SpiSelector.ProviderId<>() {
                    @Override
                    public String id(AuditSinkProvider p) {
                        return p.id();
                    }
                });

        Map<String, String> props = SpiSystemProperties.readPrefixed(PROP_AUDIT_PREFIX);

        if ("file".equals(provider.id()) && !props.containsKey("root")) {
            props.put("root", Path.of("pki-audit").toString());
        }

        ProviderConfig config = new ProviderConfig(provider.id(), props);

        if (LOG.isLoggable(Level.INFO)) {
            LOG.info("Selected audit provider: " + provider.id() + " (keys: " + props.keySet() + ")");
        }

        return provider.allocate(config);
    }

    /**
     * Validates an explicit audit configuration without allocating a sink.
     *
     * @param config immutable audit-provider configuration
     * @throws NullPointerException if {@code config} is {@code null}
     * @throws IllegalArgumentException if the provider or configuration is invalid
     */
    public static void validateAuditConfiguration(ProviderConfig config) {
        AuditSinkProvider provider = selectAuditProvider(Objects.requireNonNull(config, "config").backendId());
        requireKnownKeys(provider, config);
        provider.validateConfig(config);
    }

    /**
     * Opens an audit sink from an explicit, strictly validated configuration.
     *
     * @param config immutable audit-provider configuration
     * @return configured audit sink
     * @throws IllegalArgumentException if the configuration is invalid
     * @throws RuntimeException if sink allocation fails
     */
    public static AuditSink openAudit(ProviderConfig config) {
        validateAuditConfiguration(config);
        return selectAuditProvider(config.backendId()).allocate(config);
    }

    /**
     * Opens a {@link SignatureWorkflow} using {@link SignatureWorkflowProvider}
     * discovered via ServiceLoader.
     *
     * <p>
     * Runtime capabilities are supplied explicitly and are not represented in
     * system properties or {@link ProviderConfig}. Providers that do not use a
     * software keyring ignore an absent keyring dependency; a keyring-backed
     * provider rejects it before allocating a workflow.
     * </p>
     *
     * @param dependencies explicit process-local runtime dependencies
     * @return signature workflow (never {@code null})
     * @throws NullPointerException if {@code dependencies} is {@code null}
     * @throws RuntimeException     if provider selection or workflow allocation
     *                              fails
     */
    public static SignatureWorkflow openSignatureWorkflow(SignatureWorkflowRuntimeDependencies dependencies) {
        Objects.requireNonNull(dependencies, "dependencies must not be null");
        String requestedId = System.getProperty(PROP_CRYPTO_WORKFLOW_BACKEND);

        SignatureWorkflowProvider provider = SpiSelector.select(SignatureWorkflowProvider.class, requestedId,
                new SpiSelector.ProviderId<>() {
                    @Override
                    public String id(SignatureWorkflowProvider p) {
                        return p.id();
                    }
                });

        Map<String, String> props = SpiSystemProperties.readPrefixed(PROP_CRYPTO_WORKFLOW_PREFIX);

        ProviderConfig config = new ProviderConfig(provider.id(), props);

        if (LOG.isLoggable(Level.INFO)) {
            LOG.info("Selected crypto workflow provider: " + provider.id() + " (keys: " + props.keySet() + ")");
        }

        return provider.allocate(config, dependencies);
    }

    /**
     * Validates one explicit signature-workflow provider configuration without
     * allocating key access or workflow resources.
     *
     * @param config immutable workflow-provider configuration
     * @throws RuntimeException if the provider identity, property set, or
     *         provider-specific values are invalid
     */
    public static void validateSignatureWorkflowConfiguration(ProviderConfig config) {
        SignatureWorkflowProvider provider = selectSignatureWorkflowProvider(
                Objects.requireNonNull(config, "config").backendId());
        requireKnownKeys(provider, config);
        provider.validateConfig(config);
    }

    /**
     * Opens one explicitly configured signature workflow with process-local key
     * access supplied outside persistent configuration.
     *
     * @param config immutable workflow-provider configuration
     * @param dependencies process-local security capabilities
     * @return opened workflow owned by the caller
     * @throws IllegalArgumentException if configuration or capabilities are invalid
     * @throws RuntimeException if secure workflow allocation fails
     */
    public static SignatureWorkflow openConfiguredSignatureWorkflow(ProviderConfig config,
            SignatureWorkflowRuntimeDependencies dependencies) {
        validateSignatureWorkflowConfiguration(config);
        return selectSignatureWorkflowProvider(config.backendId()).allocate(config,
                Objects.requireNonNull(dependencies, "dependencies"));
    }

    /**
     * Opens an async operation bus using {@link AsyncBusProvider} discovered via
     * ServiceLoader.
     *
     * <p>
     * Defaulting rule: if no backend id is specified, defaults to {@code file}.
     * </p>
     *
     * <p>
     * Configuration properties are read from {@link System#getProperties()} using
     * the prefix {@code zeroecho.pki.async.}. Values are treated as sensitive and
     * are never logged; only keys may be logged.
     * </p>
     *
     * @return async bus (never {@code null})
     */
    public static AsyncBus<PkiId, Principal, String, Object> openAsyncBus() {
        String requestedId = System.getProperty(PROP_ASYNC_BACKEND);

        if (requestedId == null) {
            requestedId = "file";
        }

        AsyncBusProvider provider = SpiSelector.select(AsyncBusProvider.class, requestedId,
                new SpiSelector.ProviderId<>() {
                    @Override
                    public String id(AsyncBusProvider p) {
                        return p.id();
                    }
                });

        Map<String, String> props = SpiSystemProperties.readPrefixed(PROP_ASYNC_PREFIX);

        if ("file".equals(provider.id()) && !props.containsKey("logPath")) {
            props.put("logPath", Path.of("pki-async").resolve("async.log").toString());
        }

        ProviderConfig config = new ProviderConfig(provider.id(), props);

        if (LOG.isLoggable(Level.INFO)) {
            LOG.info("Selected async bus provider: " + provider.id() + " (keys: " + props.keySet() + ")");
        }

        return provider.allocate(config);
    }

    /**
     * Opens a {@link CredentialFramework} using {@link CredentialFrameworkProvider}
     * discovered via ServiceLoader.
     * 
     * <p>
     * Provider selection is deterministic and fail-fast:
     * </p>
     * <ul>
     * <li>If {@code -Dzeroecho.pki.framework=&lt;id&gt;} is specified, the provider
     * with the matching id is selected.</li>
     * <li>If no id is specified and exactly one provider exists, that provider is
     * selected.</li>
     * <li>If multiple providers exist and no id is specified, bootstrap fails as
     * configuration is ambiguous.</li>
     * </ul>
     * 
     * <p>
     * Configuration properties are read from {@link System#getProperties()} using
     * the prefix {@code zeroecho.pki.framework.}. Values are treated as sensitive
     * and are never logged; only keys may be logged.
     * </p>
     * 
     * @return credential framework (never {@code null})
     * @throws IllegalArgumentException if unsupported configuration keys are
     *                                  provided
     * @throws IllegalStateException    if provider selection fails
     */
    public static CredentialFramework openCredentialFramework() {
        String requestedId = System.getProperty(PROP_FRAMEWORK_BACKEND);

        CredentialFrameworkProvider provider = SpiSelector.select(CredentialFrameworkProvider.class, requestedId,
                new SpiSelector.ProviderId<>() {
                    @Override
                    public String id(CredentialFrameworkProvider p) {
                        return p.id();
                    }
                });

        Map<String, String> props = SpiSystemProperties.readPrefixed(PROP_FRAMEWORK_PREFIX);
        ProviderConfig config = new ProviderConfig(provider.id(), props);

        if (LOG.isLoggable(Level.INFO)) {
            LOG.info("Selected credential framework provider: " + provider.id() + " (keys: " + props.keySet() + ")");
        }

        return provider.allocate(config);
    }

    /**
     * Validates one explicit credential-framework provider configuration without
     * constructing a framework instance.
     *
     * @param config immutable framework-provider configuration
     * @throws RuntimeException if provider selection or configuration is invalid
     */
    public static void validateCredentialFrameworkConfiguration(ProviderConfig config) {
        CredentialFrameworkProvider provider = selectCredentialFrameworkProvider(
                Objects.requireNonNull(config, "config").backendId());
        requireKnownKeys(provider, config);
        provider.validateConfig(config);
    }

    /**
     * Validates one explicitly enabled publication destination without opening it.
     *
     * @param config immutable publisher-provider configuration
     * @throws RuntimeException if provider selection or configuration is invalid
     */
    public static void validatePublisherConfiguration(ProviderConfig config) {
        PublisherProvider provider = selectPublisherProvider(Objects.requireNonNull(config, "config").backendId());
        requireKnownKeys(provider, config);
        provider.validateConfig(config);
    }

    /**
     * Opens one explicitly configured publication destination.
     *
     * @param config immutable publisher-provider configuration
     * @return configured publisher selected by stable provider identity
     * @throws RuntimeException if provider selection, configuration, or allocation fails
     */
    public static Publisher openPublisher(ProviderConfig config) {
        validatePublisherConfiguration(config);
        return selectPublisherProvider(config.backendId()).allocate(config);
    }

    /**
     * Logs provider help information (supported keys) for diagnostics.
     *
     * <p>
     * This method is safe: it does not log configuration values.
     * </p>
     *
     * @param provider provider (never {@code null})
     */
    public static <T> void logSupportedKeys(ConfigurableProvider<T> provider) {
        Objects.requireNonNull(provider, "provider");
        if (LOG.isLoggable(Level.FINE)) {
            LOG.fine("Provider '" + provider.id() + "' supports keys: " + provider.supportedKeys());
        }
    }

    private static PkiStoreProvider selectStoreProvider(String requestedId) {
        return SpiSelector.select(PkiStoreProvider.class, requestedId, new SpiSelector.ProviderId<>() {
            @Override
            public String id(PkiStoreProvider provider) {
                return provider.id();
            }
        });
    }

    private static AuditSinkProvider selectAuditProvider(String requestedId) {
        return SpiSelector.select(AuditSinkProvider.class, requestedId, new SpiSelector.ProviderId<>() {
            @Override
            public String id(AuditSinkProvider provider) {
                return provider.id();
            }
        });
    }

    private static SignatureWorkflowProvider selectSignatureWorkflowProvider(String requestedId) {
        return SpiSelector.select(SignatureWorkflowProvider.class, requestedId, new SpiSelector.ProviderId<>() {
            @Override
            public String id(SignatureWorkflowProvider provider) {
                return provider.id();
            }
        });
    }

    private static CredentialFrameworkProvider selectCredentialFrameworkProvider(String requestedId) {
        return SpiSelector.select(CredentialFrameworkProvider.class, requestedId, new SpiSelector.ProviderId<>() {
            @Override
            public String id(CredentialFrameworkProvider provider) {
                return provider.id();
            }
        });
    }

    private static PublisherProvider selectPublisherProvider(String requestedId) {
        return SpiSelector.select(PublisherProvider.class, requestedId, new SpiSelector.ProviderId<>() {
            @Override
            public String id(PublisherProvider provider) {
                return provider.id();
            }
        });
    }

    private static void requireKnownKeys(ConfigurableProvider<?> provider, ProviderConfig config) {
        for (String key : config.properties().keySet()) {
            if (!provider.supportedKeys().contains(key)) {
                throw new IllegalArgumentException("Unknown provider configuration key: " + key);
            }
        }
    }
}
