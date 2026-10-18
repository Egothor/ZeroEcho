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
package zeroecho.pki.impl.framework.x509;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;

/**
 * Deeply immutable snapshot of authoritative X.509 binding rules.
 *
 * <p>
 * One rule exclusively owns each role and OID parameter domain. The current
 * implementation requires one authoritative rule for a role/OID pair; that rule
 * may itself be parameterized. This permits RSA-PSS and named-curve EC while
 * rejecting order-dependent overlapping contributions.
 * </p>
 */
public final class X509BindingCatalog {

    /** Prefix reserved for built-in binding identifiers. */
    public static final String BUILTIN_PREFIX = "zeroecho.";
    private static final Set<String> FORBIDDEN_SIGNATURE_OIDS = Set.of("1.2.840.113549.1.1.5",
            "1.2.840.10045.4.1");

    private final List<X509BindingRule> rules;
    private final Map<String, X509BindingRule> byRoleAndOid;
    private final Map<String, X509BindingRule> byBindingId;
    private final Map<IdentityKey, X509BindingRule> fixedByIdentity;
    private final List<X509BindingRule> fallbackRules;

    private X509BindingCatalog(List<X509BindingRule> rules) {
        List<X509BindingRule> snapshots = new ArrayList<>(rules.size());
        Map<String, X509BindingRule> reverse = new HashMap<>();
        Map<String, X509BindingRule> identifiers = new HashMap<>();
        Map<IdentityKey, X509BindingRule> fixed = new HashMap<>();
        List<X509BindingRule> fallback = new ArrayList<>();
        for (X509BindingRule rule : rules) {
            SnapshotRule snapshot = rule instanceof SnapshotRule existing ? existing
                    : new SnapshotRule(rule, List.copyOf(rule.bindings())); // NOPMD AvoidInstantiatingObjectsInLoops - Each catalog rule, archive entry or schedule snapshot must retain distinct state.
            snapshots.add(snapshot);
            reverse.put(key(snapshot.role(), snapshot.oid()), snapshot);
            indexIdentifier(identifiers, snapshot.id(), snapshot);
            for (X509AlgorithmBinding binding : snapshot.bindings()) {
                indexIdentifier(identifiers, binding.bindingId(), snapshot);
            }
            if (!snapshot.bindings().isEmpty() && snapshot.bindings().stream()
                    .noneMatch(binding -> binding.origin() == X509AlgorithmBinding.Origin.STANDARD)) {
                continue;
            }
            Optional<AlgorithmIdentity> identity = StandardX509Bindings.fixedIdentity(snapshot.delegate());
            if (identity.isPresent()) {
                if (fixed.putIfAbsent(new IdentityKey(snapshot.role(), identity.get()), snapshot) != null) { // NOPMD AvoidInstantiatingObjectsInLoops - Each catalog rule, archive entry or schedule snapshot must retain distinct state.
                    throw new IllegalArgumentException("Ambiguous fixed X.509 identity binding");
                }
            } else {
                fallback.add(snapshot);
            }
        }
        this.rules = List.copyOf(snapshots);
        this.byRoleAndOid = Map.copyOf(reverse);
        this.byBindingId = Map.copyOf(identifiers);
        this.fixedByIdentity = Map.copyOf(fixed);
        this.fallbackRules = List.copyOf(fallback);
    }

    private static void indexIdentifier(Map<String, X509BindingRule> identifiers, String id,
            X509BindingRule rule) {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("X.509 binding identifier must not be blank");
        }
        X509BindingRule previous = identifiers.putIfAbsent(id, rule);
        if (previous != null && previous != rule) { // NOPMD CompareObjectsWithEquals - Only the same rule instance may repeat an alias; distinct rule identities conflict.
            throw new IllegalArgumentException("Duplicate X.509 binding identifier or alias");
        }
    }

    private record IdentityKey(X509AlgorithmRole role, AlgorithmIdentity identity) { }

    /** Retains the provider's immutable metadata once without memoizing its encoding domain. */
    private record SnapshotRule(X509BindingRule delegate, List<X509AlgorithmBinding> bindings)
            implements X509BindingRule {
        @Override public String id() { return delegate.id(); }
        @Override public X509AlgorithmRole role() { return delegate.role(); }
        @Override public String oid() { return delegate.oid(); }
        @Override public String semanticFingerprint() { return delegate.semanticFingerprint(); }
        @Override public SignatureEncoding signatureEncoding() { return delegate.signatureEncoding(); }
        @Override public PublicKeyEncoding publicKeyEncoding() { return delegate.publicKeyEncoding(); }
        @Override public Optional<X509AlgorithmIdentifier> encode(AlgorithmIdentity identity) {
            return delegate.encode(identity);
        }
        @Override public Optional<AlgorithmIdentity> decode(X509AlgorithmIdentifier identifier) {
            return delegate.decode(identifier);
        }
    }

    /**
     * Creates the immutable built-in catalog.
     *
     * @param rules fixed standard rules
     * @return built-in catalog
     */
    public static X509BindingCatalog builtIn(List<X509BindingRule> rules) {
        return create(rules, true);
    }

    /**
     * Creates a trusted additive extension catalog.
     *
     * @param rules extension rules
     * @return extension catalog
     */
    public static X509BindingCatalog extension(List<X509BindingRule> rules) {
        return create(rules, false);
    }

    /**
     * Produces a new immutable additive snapshot.
     *
     * @param extensions installed extension catalogs
     * @return merged catalog
     * @throws IllegalArgumentException if a rule identifier or role/OID domain
     *                                  collides
     */
    public X509BindingCatalog merge(List<X509BindingCatalog> extensions) {
        Objects.requireNonNull(extensions, "extensions");
        List<X509BindingRule> merged = new ArrayList<>(rules);
        for (X509BindingCatalog extension : extensions) {
            Objects.requireNonNull(extension, "extension");
            merged.addAll(extension.rules);
        }
        return validate(merged);
    }

    /**
     * Resolves one exact identity for a closed role.
     *
     * @param identity exact identity
     * @param role     X.509 role
     * @return canonical X.509 representation
     * @implNote Fixed standard lookup uses one expected constant-time hash lookup,
     * followed by every applicable parameterized or extension rule. Hashing costs
     * are proportional to identity size; fallback work is proportional to the
     * number and encoding cost of those rules. No descriptor graph is rebuilt.
     * @throws IllegalArgumentException if no rule or more than one rule resolves
     */
    public X509AlgorithmIdentifier resolve(AlgorithmIdentity identity, X509AlgorithmRole role) {
        Objects.requireNonNull(identity, "identity");
        Objects.requireNonNull(role, "role");
        if (role == X509AlgorithmRole.SIGNATURE_ALGORITHM) {
            X509SecurityFloor.requirePermitted(identity);
        }
        X509BindingRule fixed = fixedByIdentity.get(new IdentityKey(role, identity));
        X509AlgorithmIdentifier resolved = fixed == null ? null : fixed.encode(identity).orElseThrow();
        for (X509BindingRule rule : fallbackRules) {
            if (rule.role() != role) {
                continue;
            }
            Optional<X509AlgorithmIdentifier> candidate = rule.encode(identity);
            if (candidate.isPresent()) {
                if (resolved != null) {
                    throw new IllegalArgumentException("Ambiguous X.509 identity binding");
                }
                resolved = candidate.get();
            }
        }
        if (resolved == null) {
            throw new IllegalArgumentException("No authoritative X.509 binding");
        }
        return resolved;
    }

    /**
     * Resolves one exact identity through an explicitly selected binding.
     *
     * @param bindingId stable binding identifier
     * @param identity exact cryptographic identity
     * @param role internal structural role
     * @return canonical identifier
     * @throws IllegalArgumentException if the binding is absent, has the wrong
     *         role, or cannot encode the identity
     */
    public X509AlgorithmIdentifier resolve(String bindingId, AlgorithmIdentity identity, X509AlgorithmRole role) {
        Objects.requireNonNull(bindingId, "bindingId");
        Objects.requireNonNull(identity, "identity");
        Objects.requireNonNull(role, "role");
        X509BindingRule rule = byBindingId.get(bindingId);
        if (rule == null) {
            throw new IllegalArgumentException("Unknown X.509 binding identifier");
        }
        if (rule.role() != role) {
            throw new IllegalArgumentException("X.509 binding role mismatch");
        }
        return rule.encode(identity).orElseThrow(() -> new IllegalArgumentException("X.509 binding identity mismatch"));
    }

    /**
     * Reverse-resolves an exact role-specific representation.
     *
     * @param identifier canonical X.509 representation
     * @param role       X.509 role
     * @return exact identity
     * @throws IllegalArgumentException if the representation is unknown or invalid
     */
    public AlgorithmIdentity reverse(X509AlgorithmIdentifier identifier, X509AlgorithmRole role) {
        Objects.requireNonNull(identifier, "identifier");
        Objects.requireNonNull(role, "role");
        X509BindingRule rule = byRoleAndOid.get(key(role, identifier.oid()));
        if (rule == null) {
            throw new IllegalArgumentException("Unknown X.509 algorithm identifier");
        }
        AlgorithmIdentity identity = rule.decode(identifier)
                .orElseThrow(() -> new IllegalArgumentException("Invalid X.509 parameters"));
        if (role == X509AlgorithmRole.SIGNATURE_ALGORITHM) {
            X509SecurityFloor.requirePermitted(identity);
        }
        return identity;
    }

    /**
     * Returns the stable binding identifier owning an exact representation.
     *
     * @param identifier canonical representation
     * @param role structural role
     * @return stable binding identifier
     */
    public String bindingId(X509AlgorithmIdentifier identifier, X509AlgorithmRole role) {
        Objects.requireNonNull(identifier, "identifier");
        Objects.requireNonNull(role, "role");
        X509BindingRule rule = byRoleAndOid.get(key(role, identifier.oid()));
        if (rule == null || rule.decode(identifier).isEmpty()) {
            throw new IllegalArgumentException("Unknown X.509 algorithm identifier");
        }
        return rule.id();
    }

    /**
     * Returns deterministic immutable binding rules.
     *
     * @return rule snapshot
     */
    public List<X509BindingRule> rules() {
        return rules;
    }

    private static X509BindingCatalog create(List<X509BindingRule> rules, boolean builtIn) {
        Objects.requireNonNull(rules, "rules");
        for (X509BindingRule rule : rules) {
            Objects.requireNonNull(rule, "rule");
            if (rule.role() == X509AlgorithmRole.SIGNATURE_ALGORITHM
                    && FORBIDDEN_SIGNATURE_OIDS.contains(rule.oid())) {
                throw new IllegalArgumentException("SHA-1 X.509 signature binding is forbidden");
            }
            if (builtIn != rule.id().startsWith(BUILTIN_PREFIX)) {
                throw new IllegalArgumentException(
                        builtIn ? "Built-in rule must use reserved identifier"
                                : "Extension rule must not use reserved identifier");
            }
        }
        return validate(rules);
    }

    private static X509BindingCatalog validate(List<X509BindingRule> rules) {
        Set<String> ids = new HashSet<>();
        Set<String> domains = new HashSet<>();
        for (X509BindingRule rule : rules) {
            if (!ids.add(rule.id())) {
                throw new IllegalArgumentException("Duplicate X.509 binding rule identifier");
            }
            if (!domains.add(key(rule.role(), rule.oid()))) {
                throw new IllegalArgumentException("Overlapping X.509 binding rule domain");
            }
            if (rule.semanticFingerprint() == null || rule.semanticFingerprint().isBlank()) {
                throw new IllegalArgumentException("Binding rule fingerprint must not be blank");
            }
        }
        return new X509BindingCatalog(rules);
    }

    private static String key(X509AlgorithmRole role, String oid) {
        return role + "|" + oid;
    }
}
