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
package zeroecho.core.spec;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Deeply immutable snapshot of installed algorithm identities.
 *
 * <p>
 * Built-in identities reserve the {@code zeroecho} namespace. Trusted installed
 * code may contribute identities under another namespace. Duplicate canonical
 * representations fail closed; registration order never supplies precedence.
 * Administrative configuration is not a registration mechanism.
 * </p>
 */
public final class AlgorithmIdentityCatalog {

    /** Namespace reserved for immutable built-in identities. */
    public static final String BUILTIN_NAMESPACE = "zeroecho";

    private final Map<String, AlgorithmIdentity> identities;

    private AlgorithmIdentityCatalog(Map<String, AlgorithmIdentity> identities) {
        this.identities = Map.copyOf(identities);
    }

    /**
     * Creates the immutable built-in catalog.
     *
     * @param identities built-in identities
     * @return immutable catalog
     * @throws IllegalArgumentException if an identity is outside the reserved
     *                                  namespace or collides
     */
    public static AlgorithmIdentityCatalog builtIn(Collection<AlgorithmIdentity> identities) {
        return create(identities, true);
    }

    /**
     * Creates a trusted extension catalog.
     *
     * @param identities extension identities
     * @return immutable catalog
     * @throws IllegalArgumentException if an extension uses the built-in namespace
     *                                  or contains a collision
     */
    public static AlgorithmIdentityCatalog extension(Collection<AlgorithmIdentity> identities) {
        return create(identities, false);
    }

    /**
     * Returns a new additive snapshot containing this catalog and all extensions.
     *
     * @param extensions trusted installed extension catalogs
     * @return immutable merged snapshot
     * @throws IllegalArgumentException if any canonical identity collides
     */
    public AlgorithmIdentityCatalog merge(List<AlgorithmIdentityCatalog> extensions) {
        Objects.requireNonNull(extensions, "extensions");
        Map<String, AlgorithmIdentity> merged = new LinkedHashMap<>(identities);
        for (AlgorithmIdentityCatalog extension : extensions) {
            Objects.requireNonNull(extension, "extension");
            for (AlgorithmIdentity identity : extension.identities.values()) {
                if (BUILTIN_NAMESPACE.equals(identity.family().namespace())
                        && identities.values().stream().noneMatch(builtIn -> builtIn.kind() == identity.kind()
                                && builtIn.family().equals(identity.family()))) {
                    throw new IllegalArgumentException("Extension identity uses unknown reserved family");
                }
                AlgorithmIdentity previous = merged.putIfAbsent(identity.canonicalForm(), identity);
                if (previous != null && !previous.equals(identity)) {
                    throw new IllegalArgumentException("Algorithm identity collision");
                }
                if (previous != null) {
                    throw new IllegalArgumentException("Duplicate algorithm identity");
                }
            }
        }
        return new AlgorithmIdentityCatalog(merged);
    }

    /**
     * Adds exact parameter combinations to this authority snapshot.
     *
     * <p>
     * A trusted extension may add a tuple within an existing reserved family, but
     * cannot introduce a new family under the built-in namespace.
     * </p>
     *
     * @param additions exact additive identities
     * @return new immutable catalog
     */
    public AlgorithmIdentityCatalog add(Collection<AlgorithmIdentity> additions) {
        Objects.requireNonNull(additions, "additions");
        Map<String, AlgorithmIdentity> merged = new LinkedHashMap<>(identities);
        for (AlgorithmIdentity identity : additions) {
            Objects.requireNonNull(identity, "identity");
            if (BUILTIN_NAMESPACE.equals(identity.family().namespace())
                    && identities.values().stream().noneMatch(builtIn -> builtIn.kind() == identity.kind()
                            && builtIn.family().equals(identity.family()))) {
                throw new IllegalArgumentException("Extension identity uses unknown reserved family");
            }
            if (merged.putIfAbsent(identity.canonicalForm(), identity) != null) {
                throw new IllegalArgumentException("Duplicate algorithm identity");
            }
        }
        return new AlgorithmIdentityCatalog(merged);
    }

    /**
     * Resolves a canonical identity without provider alias fallback.
     *
     * @param canonicalForm complete canonical representation
     * @return registered exact identity, or empty when unknown
     */
    public Optional<AlgorithmIdentity> resolve(String canonicalForm) {
        Objects.requireNonNull(canonicalForm, "canonicalForm");
        return Optional.ofNullable(identities.get(canonicalForm));
    }

    /**
     * Returns identities in deterministic canonical order.
     *
     * @return immutable identity list
     */
    public List<AlgorithmIdentity> identities() {
        return identities.values().stream().sorted((left, right) -> left.canonicalForm()
                .compareTo(right.canonicalForm())).toList();
    }

    private static AlgorithmIdentityCatalog create(Collection<AlgorithmIdentity> source, boolean builtIn) {
        Objects.requireNonNull(source, "identities");
        Map<String, AlgorithmIdentity> result = new LinkedHashMap<>();
        for (AlgorithmIdentity identity : source) {
            Objects.requireNonNull(identity, "identity");
            boolean reserved = BUILTIN_NAMESPACE.equals(identity.family().namespace());
            if (builtIn != reserved) {
                throw new IllegalArgumentException(
                        builtIn ? "Built-in identity must use reserved namespace"
                                : "Extension identity must not use reserved namespace");
            }
            if (result.putIfAbsent(identity.canonicalForm(), identity) != null) {
                throw new IllegalArgumentException("Duplicate algorithm identity");
            }
        }
        return new AlgorithmIdentityCatalog(result);
    }
}
