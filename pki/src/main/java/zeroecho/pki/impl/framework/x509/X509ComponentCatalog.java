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
package zeroecho.pki.impl.framework.x509;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;

/**
 * Immutable additive catalog of X.509 component identities used inside
 * parameterized binding rules.
 *
 * <p>
 * Digest, mask-generation, and named-curve OIDs are structural components rather
 * than complete signature or SPKI bindings. Identity and OID collisions fail
 * closed and the SHA-1 component OID is prohibited structurally.
 * </p>
 */
public final class X509ComponentCatalog {

    private static final Set<String> FORBIDDEN_DIGEST_OIDS = Set.of("1.3.14.3.2.26");
    private static final X509ComponentCatalog BUILT_INS = create(List.of(
            new Component("zeroecho.digest.sha256", Kind.DIGEST, BootstrapAlgorithmIdentities.SHA256,
                    "2.16.840.1.101.3.4.2.1", true),
            new Component("zeroecho.digest.sha384", Kind.DIGEST, BootstrapAlgorithmIdentities.SHA384,
                    "2.16.840.1.101.3.4.2.2", true),
            new Component("zeroecho.digest.sha512", Kind.DIGEST, BootstrapAlgorithmIdentities.SHA512,
                    "2.16.840.1.101.3.4.2.3", true),
            new Component("zeroecho.mask.mgf1", Kind.MASK_GENERATION, BootstrapAlgorithmIdentities.MGF1,
                    "1.2.840.113549.1.1.8", true),
            new Component("zeroecho.curve.p256", Kind.NAMED_CURVE,
                    BootstrapAlgorithmIdentities.EC_P256_PUBLIC_KEY, "1.2.840.10045.3.1.7", true),
            new Component("zeroecho.curve.p384", Kind.NAMED_CURVE,
                    BootstrapAlgorithmIdentities.EC_P384_PUBLIC_KEY, "1.3.132.0.34", true),
            new Component("zeroecho.curve.p521", Kind.NAMED_CURVE,
                    BootstrapAlgorithmIdentities.EC_P521_PUBLIC_KEY, "1.3.132.0.35", true)));

    private final List<Component> components;
    private final Map<String, Component> byIdentity;
    private final Map<String, Component> byOid;

    /**
     * Closed component role.
     */
    public enum Kind {
        /** Digest AlgorithmIdentifier component. */
        DIGEST,
        /** Mask-generation AlgorithmIdentifier component. */
        MASK_GENERATION,
        /** Named-curve OBJECT IDENTIFIER component. */
        NAMED_CURVE
    }

    /**
     * Immutable component binding.
     *
     * @param id       stable namespaced contribution identifier
     * @param kind     closed component kind
     * @param identity exact provider-independent identity
     * @param oid      standard dotted-decimal OID
     * @param builtIn  whether the entry is non-overridable built-in authority
     */
    public record Component(String id, Kind kind, AlgorithmIdentity identity, String oid, boolean builtIn) {

        /**
         * Creates a component.
         *
         * @throws NullPointerException if a required field is {@code null}
         */
        public Component {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(identity, "identity");
            Objects.requireNonNull(oid, "oid");
        }
    }

    private X509ComponentCatalog(List<Component> components) {
        this.components = List.copyOf(components);
        Map<String, Component> identityIndex = new HashMap<>();
        Map<String, Component> oidIndex = new HashMap<>();
        for (Component component : components) {
            identityIndex.put(key(component.kind(), component.identity().canonicalForm()), component);
            oidIndex.put(key(component.kind(), component.oid()), component);
        }
        this.byIdentity = Map.copyOf(identityIndex);
        this.byOid = Map.copyOf(oidIndex);
    }

    /**
     * Returns immutable built-in components.
     *
     * @return built-in catalog
     */
    public static X509ComponentCatalog builtIn() {
        return BUILT_INS;
    }

    /**
     * Creates a trusted additive extension catalog.
     *
     * @param components extension components
     * @return validated extension catalog
     */
    public static X509ComponentCatalog extension(List<Component> components) {
        for (Component component : components) {
            if (component.builtIn() || component.id().startsWith("zeroecho.")) {
                throw new IllegalArgumentException("Extension component uses reserved authority");
            }
        }
        return create(components);
    }

    /**
     * Produces a new immutable additive snapshot.
     *
     * @param extensions extension catalogs
     * @return merged catalog
     */
    public X509ComponentCatalog merge(List<X509ComponentCatalog> extensions) {
        Objects.requireNonNull(extensions, "extensions");
        List<Component> merged = new ArrayList<>(components);
        for (X509ComponentCatalog extension : extensions) {
            merged.addAll(Objects.requireNonNull(extension, "extension").components);
        }
        return create(merged);
    }

    /**
     * Resolves the OID of an exact component identity.
     *
     * @param kind     component kind
     * @param identity exact identity
     * @return component OID
     */
    public String oid(Kind kind, AlgorithmIdentity identity) {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(identity, "identity");
        X509SecurityFloor.requirePermitted(identity);
        Component component = byIdentity.get(key(kind, identity.canonicalForm()));
        if (component == null) {
            throw new IllegalArgumentException("Unknown X.509 component identity");
        }
        return component.oid();
    }

    /**
     * Reverse-resolves an exact component OID.
     *
     * @param kind component kind
     * @param oid  dotted-decimal OID
     * @return exact component identity
     */
    public AlgorithmIdentity identity(Kind kind, String oid) {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(oid, "oid");
        Component component = byOid.get(key(kind, oid));
        if (component == null) {
            throw new IllegalArgumentException("Unknown X.509 component OID");
        }
        X509SecurityFloor.requirePermitted(component.identity());
        return component.identity();
    }

    /**
     * Returns a deterministic semantic fingerprint.
     *
     * @return immutable canonical component inventory
     */
    public String semanticFingerprint() {
        return String.join("|", components.stream().sorted(Comparator.comparing(Component::id))
                .map(component -> component.id() + ":" + component.kind() + ":"
                        + component.identity().canonicalForm() + ":" + component.oid())
                .toList());
    }

    /**
     * Resolves a component when present.
     *
     * @param kind component kind
     * @param oid  OID
     * @return component or empty
     */
    public Optional<Component> find(Kind kind, String oid) {
        return Optional.ofNullable(byOid.get(key(kind, oid)));
    }

    private static X509ComponentCatalog create(List<Component> source) {
        Objects.requireNonNull(source, "components");
        Set<String> ids = new HashSet<>();
        Set<String> identities = new HashSet<>();
        Set<String> oids = new HashSet<>();
        List<Component> copy = new ArrayList<>(source);
        for (Component component : copy) {
            Objects.requireNonNull(component, "component");
            if (!ids.add(component.id())
                    || !identities.add(key(component.kind(), component.identity().canonicalForm()))
                    || !oids.add(key(component.kind(), component.oid()))) {
                throw new IllegalArgumentException("X.509 component catalog collision");
            }
            if (component.kind() == Kind.DIGEST && FORBIDDEN_DIGEST_OIDS.contains(component.oid())) {
                throw new IllegalArgumentException("SHA-1 X.509 component is forbidden");
            }
            X509SecurityFloor.requirePermitted(component.identity());
        }
        copy.sort(Comparator.comparing(Component::id));
        return new X509ComponentCatalog(copy);
    }

    private static String key(Kind kind, String value) {
        return kind + "|" + value;
    }
}
