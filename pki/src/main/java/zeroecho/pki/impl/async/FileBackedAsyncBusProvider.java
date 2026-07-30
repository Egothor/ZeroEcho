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
package zeroecho.pki.impl.async;

import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.async.AsyncBusProvider;
import zeroecho.pki.util.async.AsyncBus;
import zeroecho.pki.util.async.codec.ResultCodec;
import zeroecho.pki.util.async.impl.AppendOnlyLineStore;
import zeroecho.pki.util.async.impl.DurableAsyncBus;

/**
 * Default async bus provider: in-memory state with append-only file
 * persistence.
 *
 * <p>
 * This provider instantiates the generic durable bus with PKI-specific
 * identifier codecs and disables result persistence. Results should be stored
 * in dedicated PKI storage (credential store, export store, etc.) and the bus
 * should carry only status and references.
 * </p>
 *
 * <h2>Configuration keys</h2>
 * <ul>
 * <li>{@code logPath} (optional): append-only log file path. Default:
 * {@code pki-async/async.log} relative to the working directory.</li>
 * </ul>
 *
 * <h2>Security</h2>
 * <p>
 * The log contains operation metadata and must be protected. The underlying
 * store applies best-effort restrictive permissions (POSIX when available).
 * </p>
 */
public final class FileBackedAsyncBusProvider implements AsyncBusProvider {
    private static final Logger LOG = Logger.getLogger(FileBackedAsyncBusProvider.class.getName());

    /**
     * Configuration key for the log file path.
     */
    public static final String KEY_LOG_PATH = "logPath";

    @Override
    public String id() {
        return "file";
    }

    @Override
    public Set<String> supportedKeys() {
        return Set.of(KEY_LOG_PATH);
    }

    /**
     * Validates configuration for the durable file-backed async bus provider.
     *
     * @param config provider configuration (never {@code null})
     * @throws IllegalArgumentException if the configuration is invalid
     */
    @Override
    public void validateConfig(final ProviderConfig config) {
        AsyncBusProvider.super.validateConfig(config);
        Map<String, String> props = config.properties();
        String logPath = props.getOrDefault(KEY_LOG_PATH, Path.of("pki-async").resolve("async.log").toString());
        Path.of(logPath);
        for (String key : props.keySet()) {
            if (!supportedKeys().contains(key) && LOG.isLoggable(Level.WARNING)) {
                LOG.warning("Ignoring unknown async bus configuration key: " + key);
            }
        }
    }

    @Override
    public AsyncBus<PkiId, Principal, String, Object> allocate(ProviderConfig config) {
        Objects.requireNonNull(config, "config");
        validateConfig(config);

        Map<String, String> props = config.properties();
        String logPath = props.getOrDefault(KEY_LOG_PATH, Path.of("pki-async").resolve("async.log").toString());

        AppendOnlyLineStore store = new AppendOnlyLineStore(Path.of(logPath));

        // Default: do not persist results in the bus log.
        ResultCodec<Object> resultCodec = ResultCodec.none();

        DurableAsyncBus<PkiId, Principal, String, Object> bus = new DurableAsyncBus<>(PkiCodecs.PKI_ID,
                PkiCodecs.PRINCIPAL, PkiCodecs.STRING, resultCodec, store);

        return bus;
    }
}
