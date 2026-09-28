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
package zeroecho.pki.impl.fs;

import java.nio.file.Path;
import java.math.BigInteger;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.PkiStoreProvider;
import zeroecho.pki.spi.store.PkiStoreRuntimeDependencies;

/**
 * {@link PkiStoreProvider} for the filesystem-backed {@link PkiStore}.
 *
 * <p>
 * Supported configuration keys:
 * </p>
 * <ul>
 * <li>{@code root} - store root directory (required)</li>
 * <li>{@code initialCrlNumber} - initial number for new CRL scope counters;
 * canonical unsigned decimal from zero through {@code 2^159 - 1}, default one.
 * Existing counters are not reset.</li>
 * </ul>
 */
public final class FilesystemPkiStoreProvider implements PkiStoreProvider {
    private static final Logger LOG = Logger.getLogger(FilesystemPkiStoreProvider.class.getName());

    /**
     * Public no-arg constructor required by {@link java.util.ServiceLoader}.
     */
    public FilesystemPkiStoreProvider() {
        // no-op
    }

    @Override
    public String id() {
        return "fs";
    }

    @Override
    public Set<String> supportedKeys() {
        return Set.of("root", "initialCrlNumber");
    }

    /**
     * Validates configuration for the filesystem-backed PKI store provider.
     *
     * <p>
     * Required configuration:
     * </p>
     * <ul>
     * <li>{@code root}</li>
     * </ul>
     *
     * <p>
     * Unknown keys are ignored for forward compatibility and are reported by key
     * name only.
     * </p>
     *
     * @param config provider configuration (never {@code null})
     * @throws IllegalArgumentException if the configuration is incomplete or
     *                                  invalid
     */
    @Override
    public void validateConfig(final ProviderConfig config) {
        PkiStoreProvider.super.validateConfig(config);
        String rootString = config.require("root");
        Path.of(rootString);
        options(config);
        for (String key : config.properties().keySet()) {
            if (!supportedKeys().contains(key) && LOG.isLoggable(Level.WARNING)) {
                LOG.warning("Ignoring unknown PKI store configuration key: " + key);
            }
        }
    }

    @Override
    public PkiStore allocate(final ProviderConfig config) {
        return allocate(config, PkiStoreRuntimeDependencies.systemUtc());
    }

    @Override
    public PkiStore allocate(final ProviderConfig config, final PkiStoreRuntimeDependencies dependencies) {
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(dependencies, "dependencies");
        validateConfig(config);

        String rootString = config.require("root");
        Path root = Path.of(rootString);

        return new FilesystemPkiStore(root, options(config), dependencies.clock());
    }

    /* default */ static FsPkiStoreOptions options(ProviderConfig config) {
        String value = config.get("initialCrlNumber").orElse("1");
        if (value.isEmpty() || value.length() > 48 || value.length() > 1 && value.charAt(0) == '0') {
            throw new IllegalArgumentException("initialCrlNumber must be a canonical unsigned decimal integer");
        }
        for (int index = 0; index < value.length(); index++) {
            char digit = value.charAt(index);
            if (digit < '0' || digit > '9') {
                throw new IllegalArgumentException("initialCrlNumber must be a canonical unsigned decimal integer");
            }
        }
        return FsPkiStoreOptions.defaults().withInitialCrlNumber(new BigInteger(value));
    }
}
