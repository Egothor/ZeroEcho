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
package zeroecho.core.spi;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.ServiceLoader;
import java.util.Set;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;

/**
 * Immutable deterministic snapshot of installed execution capabilities.
 *
 * <p>
 * Multiple implementations may support one semantic identity. Callers must
 * select an implementation explicitly when more than one remains after policy;
 * classpath or provider order never supplies precedence.
 * </p>
 */
public final class AlgorithmExecutionCapabilities {

    private final List<AlgorithmExecutionCapability> capabilities;

    /**
     * Creates a validated immutable snapshot.
     *
     * @param capabilities installed trusted-code capabilities
     * @throws IllegalArgumentException if implementation identifiers collide or a
     *                                  fingerprint is blank
     */
    public AlgorithmExecutionCapabilities(List<AlgorithmExecutionCapability> capabilities) {
        Objects.requireNonNull(capabilities, "capabilities");
        List<AlgorithmExecutionCapability> copy = new ArrayList<>(capabilities);
        copy.sort(Comparator.comparing(AlgorithmExecutionCapability::implementationId));
        Set<String> identifiers = new HashSet<>();
        for (AlgorithmExecutionCapability capability : copy) {
            Objects.requireNonNull(capability, "capability");
            if (capability.implementationId() == null || capability.implementationId().isBlank()
                    || !identifiers.add(capability.implementationId())) {
                throw new IllegalArgumentException("Execution capability identifier collision");
            }
            if (capability.domainFingerprint() == null || capability.domainFingerprint().isBlank()) {
                throw new IllegalArgumentException("Execution capability fingerprint must not be blank");
            }
        }
        this.capabilities = List.copyOf(copy);
    }

    /**
     * Discovers installed providers using the existing ServiceLoader convention.
     *
     * @return deterministic immutable capability snapshot
     */
    public static AlgorithmExecutionCapabilities installed() {
        List<AlgorithmExecutionCapabilityProvider> providers = new ArrayList<>();
        ServiceLoader.load(AlgorithmExecutionCapabilityProvider.class).forEach(providers::add);
        return fromProviders(providers);
    }

    /**
     * Builds one deterministic snapshot from already selected trusted providers.
     *
     * @param providers provider instances belonging to the runtime graph
     * @return immutable capability snapshot
     */
    public static AlgorithmExecutionCapabilities fromProviders(
            Collection<? extends AlgorithmExecutionCapabilityProvider> providers) {
        Objects.requireNonNull(providers, "providers");
        List<AlgorithmExecutionCapability> discovered = new ArrayList<>();
        List<AlgorithmExecutionCapabilityProvider> ordered = new ArrayList<>(providers);
        ordered.sort(Comparator.comparing(provider -> provider.getClass().getName()));
        for (AlgorithmExecutionCapabilityProvider provider : ordered) {
            List<AlgorithmExecutionCapability> contribution = Objects.requireNonNull(provider.capabilities(),
                    "provider capabilities");
            discovered.addAll(contribution);
        }
        return new AlgorithmExecutionCapabilities(discovered);
    }

    /**
     * Finds all installed implementations supporting an exact tuple.
     *
     * @param identity  exact operation identity
     * @param suite     complete suite
     * @param direction operation direction
     * @return deterministic immutable matching list
     */
    public List<AlgorithmExecutionCapability> supporting(AlgorithmIdentity identity, AlgorithmSuite suite,
            AlgorithmExecutionCapability.Direction direction) {
        Objects.requireNonNull(identity, "identity");
        Objects.requireNonNull(suite, "suite");
        Objects.requireNonNull(direction, "direction");
        return capabilities.stream().filter(capability -> capability.supports(identity, suite, direction)).toList();
    }

    /**
     * Returns the immutable installed snapshot.
     *
     * @return capabilities sorted by implementation identifier
     */
    public List<AlgorithmExecutionCapability> all() {
        return capabilities;
    }
}
