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
package zeroecho.core;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

import javax.crypto.SecretKey;

import zeroecho.core.context.CryptoContext;
import zeroecho.core.err.UnsupportedRoleException;
import zeroecho.core.err.UnsupportedSpecException;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spec.ContextSpec;
import zeroecho.core.spi.AsymmetricKeyBuilder;
import zeroecho.core.spi.ContextConstructorKS;
import zeroecho.core.spi.SymmetricKeyBuilder;

/**
 * Abstract base class for all cryptographic algorithm definitions in ZeroEcho.
 * <p>
 * A {@code CryptoAlgorithm} declares:
 * <ul>
 * <li>Metadata: an identifier, display name, provider, and priority.</li>
 * <li>Capabilities: declared features such as AEAD, streaming, or deterministic
 * signatures.</li>
 * <li>Roles: supported {@link KeyUsage} operations (e.g., ENCRYPT, SIGN) bound
 * to concrete {@link CryptoContext} constructors.</li>
 * <li>Key builders: factories for symmetric and asymmetric key material via
 * {@link SymmetricKeyBuilder} and {@link AsymmetricKeyBuilder}.</li>
 * </ul>
 *
 * <h2>Metadata</h2> Each algorithm instance is uniquely identified by
 * {@link #id()}, a canonical string such as {@code "AES/GCM/NOPADDING"} or
 * {@code "Ed25519"}. A human-readable {@link #displayName()} is provided for
 * logs and diagnostics.
 *
 * <h2>Capabilities</h2> Algorithms may declare extra {@link Capability} flags
 * that can be inspected by higher layers. This allows adaptive protocols to
 * choose the right primitive (e.g., preferring AEAD over raw block ciphers).
 *
 * <h2>Roles and contexts</h2> Each algorithm may support multiple
 * {@link KeyUsage} roles. For each role, the algorithm binds a key type,
 * context type, and optional {@link ContextSpec}. When
 * {@link #create(KeyUsage, Key, ContextSpec)} is called:
 * <ol>
 * <li>The binding for the role is located.</li>
 * <li>The supplied key and spec are validated against the expected types.</li>
 * <li>A new {@link CryptoContext} is constructed using the registered
 * factory.</li>
 * </ol>
 *
 * <h2>Key builders</h2>
 * <ul>
 * <li>Asymmetric builders: registered via {@link #registerAsymmetricKeyBuilder}
 * and accessed through {@link #asymmetricKeyBuilder(Class)} or convenience
 * methods like {@link #generateKeyPair(AlgorithmKeySpec)}.</li>
 * <li>Symmetric builders: registered via {@link #registerSymmetricKeyBuilder}
 * and accessed through {@link #symmetricKeyBuilder(Class)} or convenience
 * methods like {@link #generateSecret(AlgorithmKeySpec)}.</li>
 * </ul>
 *
 * <h2>Provider model</h2> Each algorithm belongs to a {@code providerName},
 * allowing multiple providers (e.g., JCA, BouncyCastle, ZeroEcho-native) to
 * coexist. {@link #priority()} can be used to prefer one provider over another
 * when resolving duplicates.
 *
 * <h2>Thread safety</h2> {@code CryptoAlgorithm} instances are immutable once
 * constructed and are safe to share across threads. The created
 * {@link CryptoContext} instances, however, are not necessarily thread-safe.
 *
 * <p>
 * <b>Security note:</b> Algorithms must enforce strong validation of keys and
 * specs during registration and {@link #create(KeyUsage, Key, ContextSpec)} to
 * prevent downgrade or misuse attacks.
 * </p>
 *
 * @since 1.0
 */
public abstract class CryptoAlgorithm { // NOPMD

    private final String _id;
    private final String _displayName;
    private final int _priority;
    private final String _providerName;

    private final List<Capability> capabilities = new ArrayList<>();
    private final Map<KeyUsage, List<RoleBinding<?, ?, ?>>> ctxBindings = new EnumMap<>(KeyUsage.class);
    private final Map<Class<? extends AlgorithmKeySpec>, AsymEntry<?>> asymBuilders = new HashMap<>();
    private final Map<Class<? extends AlgorithmKeySpec>, SymEntry<?>> symBuilders = new HashMap<>();

    /**
     * Create a new algorithm with default priority and provider.
     *
     * @param id          unique canonical identifier
     * @param displayName human-readable name
     */
    protected CryptoAlgorithm(String id, String displayName) {
        this(id, displayName, 0, "default");
    }

    /**
     * Create a new algorithm with default priority and a named provider.
     *
     * @param id           unique canonical identifier
     * @param displayName  human-readable name
     * @param providerName provider or implementation source
     */
    protected CryptoAlgorithm(String id, String displayName, String providerName) {
        this(id, displayName, 0, providerName);
    }

    /**
     * Create a new algorithm with explicit metadata.
     *
     * @param id           unique canonical identifier
     * @param displayName  human-readable name
     * @param priority     preference when multiple providers offer the same
     *                     algorithm
     * @param providerName provider or implementation source
     */
    protected CryptoAlgorithm(String id, String displayName, int priority, String providerName) {
        this._id = Objects.requireNonNull(id, "id must not be null");
        this._displayName = Objects.requireNonNull(displayName, "displayName must not be null");
        this._priority = priority;
        this._providerName = Objects.requireNonNull(providerName, "providerName must not be null");
    }

    /**
     * Returns the canonical identifier of this algorithm.
     * <p>
     * The identifier is a stable, implementation-independent string such as
     * {@code "AES/GCM/NOPADDING"} or {@code "Ed25519"}. It is suitable for
     * persistence in configuration files, protocol negotiation, or audit logs.
     * <p>
     * Unlike {@link #displayName()}, the identifier is not localized and should be
     * treated as a primary key across providers.
     *
     * @return canonical, provider-independent algorithm identifier
     */
    public final String id() {
        return _id;
    }

    /**
     * Returns a human-readable display name for this algorithm.
     * <p>
     * This name is intended for logs, error messages, and user interfaces. Unlike
     * {@link #id()}, the display name may vary by provider and is not guaranteed to
     * be stable across versions.
     *
     * @return human-friendly algorithm name
     */
    public final String displayName() {
        return _displayName;
    }

    /**
     * Returns the priority of this algorithm within its provider.
     * <p>
     * When multiple providers expose the same {@link #id()}, the priority is used
     * as a tiebreaker. Higher values indicate stronger preference.
     * <p>
     * Priority values are advisory; applications may still override selection based
     * on policy.
     *
     * @return numeric provider preference (higher means more preferred)
     */
    public int priority() {
        return _priority;
    }

    /**
     * Returns the provider that supplies this algorithm implementation.
     * <p>
     * Typical values include {@code "default"}, {@code "JCA"},
     * {@code "BouncyCastle"}, or a project-specific label.
     * <p>
     * Provider names allow coexistence of multiple implementations of the same
     * algorithm identifier.
     *
     * @return provider or implementation source name
     */
    public String providerName() {
        return _providerName;
    }

    /**
     * Adds a capability flag to this algorithm.
     *
     * <p>
     * Intended for use by concrete subclasses during construction to advertise
     * features (e.g., AEAD support, deterministic signatures). Adding capabilities
     * after publication is discouraged as callers may have already inspected them.
     * </p>
     *
     * @param capability non-null capability to add
     * @throws NullPointerException if {@code capability} is {@code null}
     */
    protected final void addCapability(Capability capability) {
        capabilities.add(Objects.requireNonNull(capability, "capability must not be null"));
    }

    /**
     * Returns an immutable view of the algorithm’s declared capabilities.
     *
     * @return unmodifiable list of capability flags
     */
    public final List<Capability> listCapabilities() {
        return Collections.unmodifiableList(capabilities);
    }

    /**
     * Internal binding record connecting a role to its required types and
     * constructor.
     * <p>
     * For a given {@link KeyUsage} role, the binding specifies the expected
     * {@link CryptoContext} type, the accepted {@link Key} type, the optional
     * {@link ContextSpec} type, a constructor factory, and a default spec supplier.
     *
     * @param <C> context type
     * @param <K> key type
     * @param <S> spec type
     */
    private static final class RoleBinding<C extends CryptoContext, K extends Key, S extends ContextSpec> {
        private final Class<C> ctxType;
        private final Class<K> keyType;
        private final Class<S> specType;
        private final ContextConstructorKS<C, K, S> ctor;
        private final Supplier<? extends S> defaultSpec;

        private RoleBinding(Class<C> ctxType, Class<K> keyType, Class<S> specType, ContextConstructorKS<C, K, S> ctor,
                Supplier<? extends S> defaultSpec) {
            this.ctxType = ctxType;
            this.keyType = keyType;
            this.specType = specType;
            this.ctor = ctor;
            this.defaultSpec = defaultSpec;
        }

        private boolean accepts(Key key, ContextSpec spec) {
            return keyType.isInstance(key) && (spec == null || specType.isInstance(spec));
        }
    }

    /**
     * Binds a role to a concrete context factory and its expected key/spec types.
     *
     * <p>
     * Concrete algorithms call this during construction to declare support for
     * specific roles (e.g., {@code ENCRYPT}, {@code VERIFY}). When
     * {@link #create(KeyUsage, Key, ContextSpec)} is later invoked, the provided
     * {@code key} and optional {@code spec} are matched against these bindings.
     * </p>
     *
     * @param role        supported {@link KeyUsage} role
     * @param ctxType     context type to be returned by the factory
     * @param keyType     key type accepted by the factory
     * @param specType    spec type accepted by the factory (may be a marker type)
     * @param factory     constructor that creates a context for (key, spec)
     * @param defaultSpec default spec supplier used when {@code spec} is
     *                    {@code null}
     * @param <C>         context type
     * @param <K>         key type
     * @param <S>         spec type
     * @throws NullPointerException if any class or factory argument is {@code null}
     */
    protected final <C extends CryptoContext, K extends Key, S extends ContextSpec> void bind(KeyUsage role,
            Class<C> ctxType, Class<K> keyType, Class<S> specType, ContextConstructorKS<C, K, S> factory,
            Supplier<? extends S> defaultSpec) {
        ctxBindings.computeIfAbsent(role, r -> new ArrayList<>())
                .add(new RoleBinding<>(ctxType, keyType, specType, factory, defaultSpec));
    }

    /**
     * Returns whether this algorithm supports the given role.
     *
     * @param role a {@link KeyUsage} role
     * @return {@code true} if a binding exists, otherwise {@code false}
     */
    public final boolean supports(KeyUsage role) {
        return ctxBindings.containsKey(role);
    }

    /**
     * Returns the set of roles supported by this algorithm.
     *
     * @return unmodifiable set of supported {@link KeyUsage} values
     */
    public final Set<KeyUsage> roles() {
        return Collections.unmodifiableSet(ctxBindings.keySet());
    }

    /**
     * Creates a new {@link CryptoContext} for the given role, key, and optional
     * spec.
     *
     * <p>
     * Resolution proceeds as follows:
     * </p>
     * <ol>
     * <li>Locate bindings for {@code role}; if none exist, throw
     * {@link UnsupportedRoleException}.</li>
     * <li>For each binding, check that {@code key} is an instance of the required
     * key type and {@code spec} is either {@code null} or an instance of the
     * required spec type.</li>
     * <li>If matched, resolve the effective spec: use the provided {@code spec} or
     * obtain one from the binding’s {@code defaultSpec} supplier.</li>
     * <li>Invoke the factory to create a context and verify the returned type
     * matches the declared {@code ctxType}.</li>
     * </ol>
     *
     * @param role the intended {@link KeyUsage} for the created context
     * @param key  key instance compatible with the binding
     * @param spec optional context spec; if {@code null}, the binding’s default is
     *             used
     * @param <C>  context type
     * @param <K>  key type
     * @param <S>  spec type
     * @return a newly constructed context suitable for the requested role
     * @throws UnsupportedRoleException if the algorithm does not support
     *                                  {@code role}
     * @throws UnsupportedSpecException if no binding accepts the provided key/spec
     * @throws IllegalStateException    if the factory returns an unexpected context
     *                                  type
     * @throws IOException              if the factory encounters I/O while
     *                                  constructing the context
     */
    @SuppressWarnings("unchecked")
    public final <C extends CryptoContext, K extends Key, S extends ContextSpec> C create(KeyUsage role, K key, S spec)
            throws IOException {

        List<RoleBinding<?, ?, ?>> list = ctxBindings.get(role);
        if (list == null || list.isEmpty()) {
            throw new UnsupportedRoleException(_id + " does not support role " + role);
        }
        for (RoleBinding<?, ?, ?> rb0 : list) {
            RoleBinding<C, K, S> rb = (RoleBinding<C, K, S>) rb0;
            if (rb.accepts(key, spec)) {
                S resolved = (spec != null) ? spec : rb.defaultSpec.get();
                C ctx = rb.ctor.create(key, resolved);
                // Enforce the declared context type contract:
                if (!rb.ctxType.isInstance(ctx)) {
                    throw new IllegalStateException(_id + " factory returned " + ctx.getClass().getName()
                            + " but capability declares " + rb.ctxType.getName());
                }
                return ctx;
            }
        }
        throw new UnsupportedSpecException(_id + " cannot create for " + role + " with key=" + key.getClass().getName()
                + (spec == null ? " (default spec)" : " and spec=" + spec.getClass().getName()));
    }

    /**
     * Immutable descriptor for an asymmetric builder registered with this
     * algorithm.
     * <p>
     * Used for discovery and documentation (e.g., tool UIs).
     * </p>
     */
    public static final class AsymBuilderInfo {
        public final Class<? extends AlgorithmKeySpec> specType;
        public final Object defaultKeySpec;

        private AsymBuilderInfo(Class<? extends AlgorithmKeySpec> specType, Object defaultKeySpec) {
            this.specType = specType;
            this.defaultKeySpec = defaultKeySpec;
        }
    }

    /**
     * Internal entry binding a registered asymmetric key builder to its default key
     * specification supplier.
     *
     * <p>
     * Each {@code AsymEntry} is keyed by a specific {@link AlgorithmKeySpec}
     * subtype. It holds the {@link AsymmetricKeyBuilder} instance capable of
     * generating or importing keys for that spec, and an optional supplier that
     * provides a safe default spec (if the algorithm wants to support "generate
     * with defaults").
     * </p>
     *
     * <h2>Usage</h2>
     * <ul>
     * <li>Created during calls to
     * {@link #registerAsymmetricKeyBuilder(Class, AsymmetricKeyBuilder, Supplier)}.</li>
     * <li>Looked up later by {@link #asymmetricKeyBuilder(Class)} and used by
     * key-generation/import convenience methods such as
     * {@link #generateKeyPair(AlgorithmKeySpec)}.</li>
     * </ul>
     *
     * <h2>Thread-safety</h2> Immutable once constructed; safe to share between
     * threads.
     *
     * @param <S> the type of {@link AlgorithmKeySpec} handled by this entry
     */
    private record AsymEntry<S extends AlgorithmKeySpec>(AsymmetricKeyBuilder<S> builder,
            Supplier<? extends S> defaultKeySpec) {

        /**
         * Creates a new binding between a key builder and its optional default spec.
         *
         * @throws NullPointerException if {@code builder} is {@code null}
         */
        AsymEntry {
            Objects.requireNonNull(builder, "builder must not be null");
        }
    }

    /**
     * Registers an asymmetric key builder for a specific spec type.
     *
     * <p>
     * Concrete algorithms call this during construction. The {@code specType} acts
     * as a key for later lookup and must be unique within this algorithm.
     * </p>
     *
     * @param specType             the spec class accepted by {@code builder}
     * @param builder              builder that can generate/import keys for
     *                             {@code specType}
     * @param defaultKeySpecOrNull optional supplier for a default spec (may be
     *                             {@code null})
     * @param <S>                  spec type
     * @throws NullPointerException if {@code specType} or {@code builder} is
     *                              {@code null}
     */
    protected final <S extends AlgorithmKeySpec> void registerAsymmetricKeyBuilder(Class<S> specType,
            AsymmetricKeyBuilder<S> builder, Supplier<? extends S> defaultKeySpecOrNull) {
        Objects.requireNonNull(specType, "specType must not be null");
        asymBuilders.put(specType, new AsymEntry<>(builder, defaultKeySpecOrNull));
    }

    /**
     * Returns the asymmetric key builder associated with the given spec type.
     *
     * @param specType spec class used as a lookup key
     * @param <S>      spec type
     * @return the registered {@link AsymmetricKeyBuilder}
     * @throws IllegalArgumentException if no builder is registered for
     *                                  {@code specType}
     */
    @SuppressWarnings("unchecked")
    public final <S extends AlgorithmKeySpec> AsymmetricKeyBuilder<S> asymmetricKeyBuilder(Class<S> specType) {
        AsymEntry<?> e = asymBuilders.get(specType);
        if (e == null) {
            throw new IllegalArgumentException(_id + " has no asymmetric key builder for " + specType.getName());
        }
        return (AsymmetricKeyBuilder<S>) e.builder;
    }

    /**
     * Returns metadata about all registered asymmetric builders.
     *
     * <p>
     * The default spec value is best-effort; suppliers may throw, in which case
     * {@code defaultKeySpec} is reported as {@code null}.
     * </p>
     *
     * @return immutable list of {@link AsymBuilderInfo} descriptors
     */
    public final List<AsymBuilderInfo> asymmetricBuildersInfo() {
        List<AsymBuilderInfo> out = new ArrayList<>();
        for (Map.Entry<Class<? extends AlgorithmKeySpec>, AsymEntry<?>> e : asymBuilders.entrySet()) {
            Object def = null;
            if (e.getValue().defaultKeySpec != null) {
                try {
                    def = e.getValue().defaultKeySpec.get();
                } catch (Throwable t) { // NOPMD
                    def = null;
                }
            }
            out.add(new AsymBuilderInfo(e.getKey(), def));
        }
        return Collections.unmodifiableList(out);
    }

    /**
     * Immutable descriptor for a symmetric key builder registered with this
     * algorithm.
     *
     * <p>
     * Each {@code SymBuilderInfo} describes the specification type that a
     * {@link SymmetricKeyBuilder} can handle, along with an optional default
     * specification object. These descriptors are used for discovery and
     * documentation purposes, for example when rendering catalog information in
     * tooling or UIs.
     * </p>
     *
     * <h2>Usage</h2>
     * <ul>
     * <li>Produced by {@link #symmetricBuildersInfo()}.</li>
     * <li>Displayed to clients for inspection and documentation, but not used
     * directly in cryptographic operations.</li>
     * </ul>
     *
     * <h2>Thread-safety</h2> Being a {@code record}, this type is immutable and
     * safe to share between threads.
     *
     * @param specType       the specification type supported by the builder
     * @param defaultKeySpec an optional default key specification instance, or
     *                       {@code null} if no default is provided
     */
    public record SymBuilderInfo(Class<? extends AlgorithmKeySpec> specType, Object defaultKeySpec) {
    }

    /**
     * Internal entry binding a registered symmetric key builder to its optional
     * default key specification supplier.
     *
     * <p>
     * Each {@code SymEntry} is keyed by a specific {@link AlgorithmKeySpec}
     * subtype. It holds the {@link SymmetricKeyBuilder} instance capable of
     * generating or importing keys for that spec, and a supplier that may produce a
     * default spec when none is provided explicitly.
     * </p>
     *
     * <h2>Usage</h2>
     * <ul>
     * <li>Created during calls to
     * {@link #registerSymmetricKeyBuilder(Class, SymmetricKeyBuilder, Supplier)}.</li>
     * <li>Looked up internally when methods such as
     * {@link #generateSecret(AlgorithmKeySpec)} or
     * {@link #importSecret(AlgorithmKeySpec)} are invoked.</li>
     * </ul>
     *
     * <h2>Thread-safety</h2> Immutable and thread-safe by design as a
     * {@code record}.
     *
     * @param builder        the builder instance that can create or import keys;
     *                       must not be {@code null}
     * @param defaultKeySpec supplier for a default specification, or {@code null}
     *                       if no sensible default exists
     * @param <S>            the type of {@link AlgorithmKeySpec} handled by this
     *                       entry
     */
    private record SymEntry<S extends AlgorithmKeySpec>(SymmetricKeyBuilder<S> builder,
            Supplier<? extends S> defaultKeySpec) {

        /**
         * Compact constructor that enforces non-null builder.
         *
         * @throws NullPointerException if {@code builder} is {@code null}
         */
        SymEntry {
            Objects.requireNonNull(builder, "builder must not be null");
        }
    }

    /**
     * Registers a symmetric key builder for a specific spec type.
     *
     * @param specType             the spec class accepted by {@code builder}
     * @param builder              builder that can generate/import keys for
     *                             {@code specType}
     * @param defaultKeySpecOrNull optional supplier for a default spec (may be
     *                             {@code null})
     * @param <S>                  spec type
     * @throws NullPointerException if {@code specType} or {@code builder} is
     *                              {@code null}
     */
    protected final <S extends AlgorithmKeySpec> void registerSymmetricKeyBuilder(Class<S> specType,
            SymmetricKeyBuilder<S> builder, Supplier<? extends S> defaultKeySpecOrNull) {
        Objects.requireNonNull(specType, "specType must not be null");
        symBuilders.put(specType, new SymEntry<>(builder, defaultKeySpecOrNull));
    }

    /**
     * Returns the symmetric key builder associated with the given spec type.
     *
     * @param specType spec class used as a lookup key
     * @param <S>      spec type
     * @return the registered {@link SymmetricKeyBuilder}
     * @throws IllegalArgumentException if no builder is registered for
     *                                  {@code specType}
     */
    @SuppressWarnings("unchecked")
    public final <S extends AlgorithmKeySpec> SymmetricKeyBuilder<S> symmetricKeyBuilder(Class<S> specType) {
        SymEntry<?> e = symBuilders.get(specType);
        if (e == null) {
            throw new IllegalArgumentException(_id + " has no symmetric key builder for " + specType.getName());
        }
        return (SymmetricKeyBuilder<S>) e.builder;
    }

    /**
     * Returns metadata about all registered symmetric builders.
     *
     * <p>
     * The default spec value is best-effort; suppliers may throw, in which case
     * {@code defaultKeySpec} is reported as {@code null}.
     * </p>
     *
     * @return immutable list of {@link SymBuilderInfo} descriptors
     */
    public final List<SymBuilderInfo> symmetricBuildersInfo() {
        List<SymBuilderInfo> out = new ArrayList<>();
        for (Map.Entry<Class<? extends AlgorithmKeySpec>, SymEntry<?>> e : symBuilders.entrySet()) {
            Object def = null;
            if (e.getValue().defaultKeySpec != null) {
                try {
                    def = e.getValue().defaultKeySpec.get();
                } catch (Throwable t) { // NOPMD
                    def = null;
                }
            }
            out.add(new SymBuilderInfo(e.getKey(), def));
        }
        return Collections.unmodifiableList(out);
    }

    /**
     * Generates a fresh symmetric {@link SecretKey} using the registered builder
     * for {@code spec}.
     *
     * @param spec algorithm-specific key specification (must match a registered
     *             symmetric builder)
     * @param <S>  spec type
     * @return newly generated secret key
     * @throws NullPointerException     if {@code spec} is {@code null}
     * @throws IllegalArgumentException if no symmetric builder is registered for
     *                                  {@code spec.getClass()}
     * @throws GeneralSecurityException if key generation fails or parameters are
     *                                  unsupported
     */
    @SuppressWarnings("unchecked")
    public final <S extends AlgorithmKeySpec> SecretKey generateSecret(S spec) throws GeneralSecurityException {
        Objects.requireNonNull(spec, "spec must not be null");
        SymmetricKeyBuilder<S> b = symmetricKeyBuilder((Class<S>) spec.getClass());
        return b.generateSecret(spec);
    }

    /**
     * Imports an existing symmetric {@link SecretKey} using the registered builder
     * for {@code spec}.
     *
     * @param spec algorithm-specific key specification including raw
     *             material/format
     * @param <S>  spec type
     * @return wrapped secret key validated against the spec
     * @throws NullPointerException     if {@code spec} is {@code null}
     * @throws IllegalArgumentException if no symmetric builder is registered for
     *                                  {@code spec.getClass()}
     * @throws GeneralSecurityException if the material is invalid or does not match
     *                                  the algorithm
     */
    @SuppressWarnings("unchecked")
    public final <S extends AlgorithmKeySpec> SecretKey importSecret(S spec) throws GeneralSecurityException {
        Objects.requireNonNull(spec, "spec must not be null");
        SymmetricKeyBuilder<S> b = symmetricKeyBuilder((Class<S>) spec.getClass());
        return b.importSecret(spec);
    }

    /**
     * Attempts to generate a {@link KeyPair} using the given asymmetric builder's
     * default key spec. This method is fully generic and avoids raw types by
     * capturing the concrete spec type parameter.
     *
     * @param specType the spec class label used for diagnostics
     * @param entry    the typed asymmetric builder entry
     * @param <S>      concrete {@link AlgorithmKeySpec} type
     * @return a freshly generated key pair
     * @throws GeneralSecurityException if the supplier or builder fails
     */
    private <S extends AlgorithmKeySpec> KeyPair tryGenerateWithDefault(Class<? extends AlgorithmKeySpec> specType,
            AsymEntry<S> entry) throws GeneralSecurityException {

        if (entry.defaultKeySpec == null) {
            throw new GeneralSecurityException("no default spec supplier");
        }

        final S spec;
        try {
            spec = entry.defaultKeySpec.get();
        } catch (Throwable t) { // NOPMD
            throw new GeneralSecurityException("defaultSpec supplier failed for " + specType.getSimpleName() + ": "
                    + t.getClass().getSimpleName() + ": " + t.getMessage(), t);
        }
        if (spec == null) {
            throw new GeneralSecurityException("defaultSpec supplier returned null for " + specType.getSimpleName());
        }

        // No raw types here: S is captured from entry.
        return entry.builder.generateKeyPair(spec);
    }

    /**
     * Generates a fresh {@link KeyPair} using the first asymmetric builder that
     * successfully provides a default key specification.
     *
     * <p>
     * This convenience method iterates over all registered asymmetric key builders
     * that declare a non-null default {@link AlgorithmKeySpec} supplier. For each,
     * it attempts to obtain the default spec and generate a key pair. If a builder
     * fails (e.g., the builder only supports import or rejects the parameters), the
     * method records the failure and continues with the next candidate.
     * </p>
     *
     * <h4>Example</h4> <pre>{@code
     * CryptoAlgorithm algo = CryptoAlgorithms.require("Ed25519");
     * KeyPair kp = algo.generateKeyPair();
     * }</pre>
     *
     * @return a newly generated key pair using a default spec from one of the
     *         registered asymmetric builders
     * @throws IllegalStateException    if no builder declares a default spec
     *                                  supplier
     * @throws GeneralSecurityException if all candidate builders fail to generate a
     *                                  key pair; the exception message details
     *                                  individual causes
     */
    public final KeyPair generateKeyPair() throws GeneralSecurityException {
        StringBuilder reasons = new StringBuilder(128);
        boolean attempted = false;

        for (Map.Entry<Class<? extends AlgorithmKeySpec>, AsymEntry<?>> e : asymBuilders.entrySet()) {
            AsymEntry<?> entry = e.getValue();
            if (entry.defaultKeySpec == null) {
                continue;
            }
            attempted = true;
            try {
                // Wildcard capture lets the compiler infer <S> without casts.
                return tryGenerateWithDefault(e.getKey(), entry);
            } catch (GeneralSecurityException ex) {
                reasons.append(" - ").append(e.getKey().getSimpleName()).append(": ")
                        .append(ex.getClass().getSimpleName()).append(": ").append(String.valueOf(ex.getMessage()))
                        .append('\n');
                // keep trying other builders
            }
        }

        if (!attempted) {
            throw new IllegalStateException(_id + " has no default asymmetric key spec");
        }
        throw new GeneralSecurityException(
                _id + " failed to generate a default key pair. Reasons:\n" + reasons.toString().trim());
    }

    /**
     * Generates a fresh {@link KeyPair} using the registered asymmetric builder for
     * {@code spec}.
     *
     * @param spec algorithm-specific key specification (must match a registered
     *             asymmetric builder)
     * @param <S>  spec type
     * @return newly generated key pair
     * @throws NullPointerException     if {@code spec} is {@code null}
     * @throws IllegalArgumentException if no asymmetric builder is registered for
     *                                  {@code spec.getClass()}
     * @throws GeneralSecurityException if key generation fails or parameters are
     *                                  unsupported
     */
    @SuppressWarnings("unchecked")
    public final <S extends AlgorithmKeySpec> KeyPair generateKeyPair(S spec) throws GeneralSecurityException {
        Objects.requireNonNull(spec, "spec must not be null");
        AsymmetricKeyBuilder<S> b = asymmetricKeyBuilder((Class<S>) spec.getClass());
        return b.generateKeyPair(spec);
    }

    /**
     * Imports a {@link PublicKey} using the registered asymmetric builder for
     * {@code spec}.
     *
     * @param spec algorithm-specific key specification including encoded public
     *             material/format
     * @param <S>  spec type
     * @return wrapped public key validated against the spec
     * @throws NullPointerException     if {@code spec} is {@code null}
     * @throws IllegalArgumentException if no asymmetric builder is registered for
     *                                  {@code spec.getClass()}
     * @throws GeneralSecurityException if the material is invalid or does not match
     *                                  the algorithm
     */
    @SuppressWarnings("unchecked")
    public final <S extends AlgorithmKeySpec> PublicKey importPublic(S spec) throws GeneralSecurityException {
        Objects.requireNonNull(spec, "spec must not be null");
        AsymmetricKeyBuilder<S> b = asymmetricKeyBuilder((Class<S>) spec.getClass());
        return b.importPublic(spec);
    }

    /**
     * Imports a {@link PrivateKey} using the registered asymmetric builder for
     * {@code spec}.
     *
     * @param spec algorithm-specific key specification including encoded private
     *             material/format
     * @param <S>  spec type
     * @return wrapped private key validated against the spec
     * @throws NullPointerException     if {@code spec} is {@code null}
     * @throws IllegalArgumentException if no asymmetric builder is registered for
     *                                  {@code spec.getClass()}
     * @throws GeneralSecurityException if the material is invalid or does not match
     *                                  the algorithm
     */
    @SuppressWarnings("unchecked")
    public final <S extends AlgorithmKeySpec> PrivateKey importPrivate(S spec) throws GeneralSecurityException {
        Objects.requireNonNull(spec, "spec must not be null");
        AsymmetricKeyBuilder<S> b = asymmetricKeyBuilder((Class<S>) spec.getClass());
        return b.importPrivate(spec);
    }
}
