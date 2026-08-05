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
package zeroecho.pki.server.acme;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceLoader;

import zeroecho.pki.server.spi.AcmeChallengeProvider;
import zeroecho.pki.server.spi.AcmeExternalAccountBindingProvider;
import zeroecho.pki.spi.ProviderConfig;

/** Deterministic explicitly enabled ACME ServiceLoader composition. */
@SuppressWarnings("PMD.ControlStatementBraces")
public final class AcmeProviders {
    private AcmeProviders() { }

    /** Resolves only explicitly configured challenge-provider identities. */
    public static Map<String, AcmeChallengeProvider> challenges(List<ProviderConfig> enabled,
            ClassLoader loader) {
        return resolve(enabled, ServiceLoader.load(AcmeChallengeProvider.class, loader).stream()
                .map(ServiceLoader.Provider::get).toList(), AcmeChallengeProvider::id);
    }

    /** Resolves only explicitly configured EAB-provider identities. */
    public static Map<String, AcmeExternalAccountBindingProvider> eab(List<ProviderConfig> enabled,
            ClassLoader loader) {
        return resolve(enabled, ServiceLoader.load(AcmeExternalAccountBindingProvider.class, loader).stream()
                .map(ServiceLoader.Provider::get).toList(), AcmeExternalAccountBindingProvider::id);
    }

    private static <T> Map<String, T> resolve(List<ProviderConfig> enabled, List<T> discovered,
            java.util.function.Function<T, String> identity) {
        Objects.requireNonNull(loaderMarker(enabled), "enabled");
        Map<String, T> available = new LinkedHashMap<>();
        for (T provider : discovered.stream().sorted(java.util.Comparator.comparing(identity)).toList()) {
            String id = identity.apply(provider);
            if (available.putIfAbsent(id, provider) != null) throw new IllegalStateException("Duplicate ACME provider identity");
        }
        Map<String, T> result = new LinkedHashMap<>();
        for (ProviderConfig configuration : enabled.stream().sorted(java.util.Comparator.comparing(ProviderConfig::backendId)).toList()) {
            T provider = available.get(configuration.backendId());
            if (provider == null || result.putIfAbsent(configuration.backendId(), provider) != null) {
                throw new IllegalArgumentException("Configured ACME provider is unavailable or duplicated");
            }
        }
        return Map.copyOf(result);
    }

    private static List<ProviderConfig> loaderMarker(List<ProviderConfig> enabled) {
        return List.copyOf(Objects.requireNonNull(enabled, "enabled"));
    }
}
