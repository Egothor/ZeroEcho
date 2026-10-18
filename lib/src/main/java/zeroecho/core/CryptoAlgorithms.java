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
package zeroecho.core;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.TreeMap;

/**
 * Immutable registry of {@link CryptoAlgorithm} providers.
 *
 * <p>
 * Providers are discovered once through {@link ServiceLoader}, sorted by
 * canonical algorithm identifier, and retained in one immutable registry.
 * Runtime policy and auditing belong exclusively to explicitly created
 * {@link zeroecho.sdk.ZeroEchoSession} instances.
 * </p>
 *
 * @since 1.0
 */
public final class CryptoAlgorithms {
    private static final Map<String, CryptoAlgorithm> BY_ID = loadRegistry();

    private CryptoAlgorithms() {
    }

    private static Map<String, CryptoAlgorithm> loadRegistry() {
        Map<String, CryptoAlgorithm> algorithms = new TreeMap<>();
        for (CryptoAlgorithm algorithm : ServiceLoader.load(CryptoAlgorithm.class)) {
            ParameterSetDescriptor.snapshot(algorithm.parameterSets());
            CryptoAlgorithm previous = algorithms.put(algorithm.id(), algorithm);
            if (previous != null) {
                throw new IllegalStateException("Duplicate algorithm id: " + algorithm.id());
            }
        }
        return Collections.unmodifiableMap(new LinkedHashMap<>(algorithms));
    }

    /* default */ static Map<String, CryptoAlgorithm> registry() {
        return BY_ID;
    }

    /**
     * Returns registered algorithm identifiers in deterministic order.
     *
     * @return unmodifiable set of canonical identifiers
     */
    public static Set<String> available() {
        return BY_ID.keySet();
    }

    /**
     * Resolves an algorithm by canonical identifier.
     *
     * @param id canonical algorithm identifier
     * @return registered algorithm
     * @throws IllegalArgumentException if no algorithm is registered with
     *                                  {@code id}
     */
    public static CryptoAlgorithm require(String id) {
        CryptoAlgorithm algorithm = BY_ID.get(id);
        if (algorithm == null) {
            throw new IllegalArgumentException("Unknown algorithm id: " + id);
        }
        return algorithm;
    }
}
