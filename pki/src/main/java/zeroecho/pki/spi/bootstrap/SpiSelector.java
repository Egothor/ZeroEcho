/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.spi.bootstrap;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.ServiceLoader;

/**
 * Utility for selecting ServiceLoader providers by a stable identifier.
 *
 * <p>
 * This class centralizes deterministic provider-selection rules:
 * </p>
 * <ul>
 * <li>If an id is requested and exactly one provider matches it, that provider
 * is selected.</li>
 * <li>If no id is requested and exactly one provider exists, it is
 * selected.</li>
 * <li>Otherwise selection fails fast with a descriptive exception.</li>
 * </ul>
 *
 * <p>
 * This utility is intended to be used by multiple bootstraps (store, audit,
 * publish, framework components). It is deliberately small and has no logging
 * side-effects.
 * </p>
 * 
 * <p>
 * Note: provider iteration order from {@link java.util.ServiceLoader} must not
 * be relied upon. Determinism is achieved by explicit id selection or by
 * requiring a single available provider.
 * </p>
 */
public final class SpiSelector {

    private SpiSelector() {
        throw new AssertionError("No instances.");
    }

    /**
     * Provider id accessor used by the selector.
     *
     * @param <T> provider type
     */
    @FunctionalInterface
    public interface ProviderId<T> {

        /**
         * Returns the stable id for a provider instance.
         *
         * @param provider provider instance (never {@code null})
         * @return stable id (never {@code null})
         */
        String id(T provider);
    }

    /**
     * Selects a provider for the given service type.
     *
     * @param <T>         provider type
     * @param service     service class (never {@code null})
     * @param requestedId requested id (may be {@code null})
     * @param idAccessor  id accessor (never {@code null})
     * @return selected provider (never {@code null})
     * @throws IllegalStateException if no providers exist, selection is ambiguous,
     *                               or id not found
     */
    public static <T> T select(Class<T> service, String requestedId, ProviderId<T> idAccessor) {
        Objects.requireNonNull(service, "service");
        Objects.requireNonNull(idAccessor, "idAccessor");

        ServiceLoader<T> loader = ServiceLoader.load(service);
        List<T> providers = new ArrayList<>();
        for (T p : loader) {
            providers.add(p);
        }

        if (providers.isEmpty()) {
            throw new IllegalStateException("No providers found for service: " + service.getName());
        }

        if (requestedId != null) {
            List<T> matches = new ArrayList<>();
            for (T p : providers) {
                String id = idAccessor.id(p);
                if (requestedId.equals(id)) {
                    matches.add(p);
                }
            }
            if (matches.isEmpty()) {
                throw new IllegalStateException(
                        "No provider found for service " + service.getName() + " with id '" + requestedId + "'.");
            }
            if (matches.size() > 1) { // NOPMD
                throw new IllegalStateException("Multiple providers found for service " + service.getName()
                        + " with id '" + requestedId + "'.");
            }
            return matches.get(0);
        }

        if (providers.size() == 1) { // NOPMD
            return providers.get(0);
        }

        throw new IllegalStateException(
                "Multiple providers found for service " + service.getName() + "; specify explicit selection.");
    }
}
