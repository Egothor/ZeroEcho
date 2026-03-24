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
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.PkiStoreProvider;
import zeroecho.pki.util.async.AsyncBus;

/**
 * PKI bootstrap utilities for ServiceLoader-based components.
 *
 * <p>
 * This class provides deterministic selection and instantiation rules for
 * components discovered via {@link java.util.ServiceLoader}. It is designed to
 * scale as more SPIs are introduced (audit, publish, framework integrations,
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

        PkiStoreProvider provider = SpiSelector.select(PkiStoreProvider.class, requestedId,
                new SpiSelector.ProviderId<>() {
                    @Override
                    public String id(PkiStoreProvider p) {
                        return p.id();
                    }
                });

        Map<String, String> props = SpiSystemProperties.readPrefixed(PROP_STORE_PREFIX);

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
     * Opens a {@link SignatureWorkflow} using {@link SignatureWorkflowProvider}
     * discovered via ServiceLoader.
     *
     * @return signature workflow (never {@code null})
     */
    public static SignatureWorkflow openSignatureWorkflow() {
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

        return provider.allocate(config);
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
}
