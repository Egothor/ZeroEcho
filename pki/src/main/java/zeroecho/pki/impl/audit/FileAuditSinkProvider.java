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
package zeroecho.pki.impl.audit;

import java.nio.file.Path;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.audit.AuditSinkProvider;

/**
 * {@link AuditSinkProvider} for the file-backed audit sink.
 *
 * <p>
 * Supported configuration keys:
 * </p>
 * <ul>
 * <li>{@code root} - audit storage root directory (required)</li>
 * </ul>
 */
public class FileAuditSinkProvider implements AuditSinkProvider {
    private static final Logger LOG = Logger.getLogger(FileAuditSinkProvider.class.getName());

    @Override
    public String id() {
        return "file";
    }

    @Override
    public Set<String> supportedKeys() {
        return Set.of("root");
    }

    /**
     * Validates configuration for the file-backed audit sink provider.
     *
     * @param config provider configuration (never {@code null})
     * @throws IllegalArgumentException if the configuration is incomplete or
     *                                  invalid
     */
    @Override
    public void validateConfig(final ProviderConfig config) {
        AuditSinkProvider.super.validateConfig(config);
        String rootString = config.require("root");
        Path.of(rootString);
        for (String key : config.properties().keySet()) {
            if (!supportedKeys().contains(key) && LOG.isLoggable(Level.WARNING)) {
                LOG.warning("Ignoring unknown audit sink configuration key: " + key);
            }
        }
    }

    @Override
    public AuditSink allocate(ProviderConfig config) {
        Objects.requireNonNull(config, "config");
        validateConfig(config);

        String rootString = config.require("root");
        Path root = Path.of(rootString);

        return new FileAuditSink(root);
    }
}
