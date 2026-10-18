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
package zeroecho.pki.impl.audit;

import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.audit.AuditSinkProvider;

/**
 * {@link AuditSinkProvider} for the in-memory audit sink.
 *
 * <p>
 * Supported configuration keys:
 * </p>
 * <ul>
 * <li>{@code size} - maximum retained event count (optional, positive
 * integer)</li>
 * </ul>
 */
public class InMemoryAuditSinkProvider implements AuditSinkProvider {
    private static final Logger LOG = Logger.getLogger(InMemoryAuditSinkProvider.class.getName());

    /** Creates an in-memory audit-sink provider descriptor. */
    public InMemoryAuditSinkProvider() {
        // Stateless provider descriptor.
    }

    @Override
    public String id() {
        return "memory";
    }

    @Override
    public Set<String> supportedKeys() {
        return Set.of("size");
    }

    /**
     * Validates configuration for the in-memory audit sink provider.
     *
     * @param config provider configuration (never {@code null})
     * @throws IllegalArgumentException if the configuration contains an invalid
     *                                  {@code size} value
     */
    @Override
    public void validateConfig(final ProviderConfig config) {
        AuditSinkProvider.super.validateConfig(config);
        Optional<String> sizeStr = config.get("size");
        if (sizeStr.isPresent()) {
            int size = parseInt(sizeStr.get(), "size");
            if (size <= 0) {
                throw new IllegalArgumentException("Configuration key 'size' must be positive.");
            }
        }
        for (String key : config.properties().keySet()) {
            if (!supportedKeys().contains(key) && LOG.isLoggable(Level.WARNING)) {
                LOG.warning("Ignoring unknown audit sink configuration key: " + key);
            }
        }
    }

    @Override
    public AuditSink allocate(ProviderConfig config) {
        validateConfig(config);
        Optional<String> sizeStr = config.get("size");
        if (sizeStr.isPresent()) {
            return new InMemoryAuditSink(parseInt(sizeStr.get(), "size"));
        } else {
            return new InMemoryAuditSink();
        }
    }

    /**
     * Parses an integer configuration value.
     *
     * @param value   raw configuration value
     * @param keyName configuration key name
     * @return parsed integer value
     * @throws IllegalArgumentException if the value is not a valid integer
     */
    private static int parseInt(final String value, final String keyName) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("Configuration key '" + keyName + "' must be an integer.", ex);
        }
    }
}
