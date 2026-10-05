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
import java.util.List;
import java.util.HashSet;
import java.util.Set;
import java.util.Objects;
import java.util.ServiceLoader;

import javax.net.ssl.X509TrustManager;

import zeroecho.pki.server.spi.PkiServerClientTrustProvider;
import zeroecho.pki.spi.ProviderConfig;

/** Deterministic explicit provider resolver for forwarded-client trust. */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
final class ClientTrustProviders {
    private ClientTrustProviders() {
    }

    /* default */ static X509TrustManager create(ProviderConfig configuration, ClassLoader loader) {
        ProviderConfig exact = Objects.requireNonNull(configuration, "configuration");
        List<PkiServerClientTrustProvider> providers = new ArrayList<>();
        ServiceLoader.load(PkiServerClientTrustProvider.class, Objects.requireNonNull(loader, "loader"))
                .forEach(providers::add);
        ServiceLoader.load(zeroecho.pki.server.spi.v2.PkiServerClientTrustProvider.class, loader)
                .forEach(provider -> providers.add(new PkiServerClientTrustProvider() {
                    @Override public String id() { return provider.id(); }
                    @Override public X509TrustManager create(ProviderConfig config) throws Exception {
                        return provider.create(config);
                    }
                }));
        Set<String> ids = new HashSet<>();
        if (providers.stream().anyMatch(provider -> provider.id() == null || provider.id().isBlank()
                || !ids.add(provider.id()))) {
            throw new IllegalStateException("Administrative-client trust provider identities are ambiguous");
        }
        providers.sort(Comparator.comparing(PkiServerClientTrustProvider::id));
        PkiServerClientTrustProvider selected = providers.stream()
                .filter(provider -> provider.id().equals(exact.backendId())).findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "Administrative-client trust provider is unavailable"));
        try {
            return Objects.requireNonNull(selected.create(exact),
                    "Administrative-client trust provider returned no trust manager");
        } catch (RuntimeException failure) {
            throw failure;
        } catch (Exception failure) {
            throw new IllegalStateException("Administrative-client trust initialization failed");
        }
    }
}
