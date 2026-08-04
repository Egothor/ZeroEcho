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
package zeroecho.pki.server.http;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.ServiceLoader;
import java.util.Set;

import javax.net.ssl.SSLContext;

import zeroecho.pki.server.spi.PkiServerTlsProvider;
import zeroecho.pki.spi.ProviderConfig;

/** Deterministic explicit TLS-provider selection. */
@SuppressWarnings("PMD")
final class TlsProviders {
    private TlsProviders() {
    }

    static SSLContext create(ProviderConfig configuration, ClassLoader loader) {
        Objects.requireNonNull(configuration, "configuration");
        List<PkiServerTlsProvider> providers = new ArrayList<>();
        ServiceLoader.load(PkiServerTlsProvider.class, Objects.requireNonNull(loader, "loader"))
                .forEach(providers::add);
        providers.sort(Comparator.comparing(PkiServerTlsProvider::id));
        Set<String> ids = new HashSet<>();
        if (providers.stream().anyMatch(provider -> provider.id() == null || provider.id().isBlank()
                || !ids.add(provider.id()))) {
            throw new IllegalStateException("TLS provider identities are ambiguous");
        }
        PkiServerTlsProvider selected = providers.stream()
                .filter(provider -> provider.id().equals(configuration.backendId()))
                .findFirst().orElseThrow(() -> new IllegalStateException("Configured TLS provider is unavailable"));
        try {
            return selected.create(configuration);
        } catch (RuntimeException failure) {
            throw failure;
        } catch (Exception failure) {
            throw new IllegalStateException("TLS provider initialization failed");
        }
    }
}
