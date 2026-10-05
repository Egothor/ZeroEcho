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

import java.security.Key;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

import zeroecho.core.context.CryptoContext;
import zeroecho.core.err.UnsupportedRoleException;
import zeroecho.core.err.UnsupportedSpecException;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spec.ContextSpec;
import zeroecho.core.spi.AsymmetricKeyPairGenerator;
import zeroecho.core.spi.ContextFactoryKS;
import zeroecho.core.spi.PrivateKeyImporter;
import zeroecho.core.spi.PublicKeyImporter;
import zeroecho.core.spi.SymmetricKeyGenerator;
import zeroecho.core.spi.SymmetricKeyImporter;

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
 * <li>Key operations: exact generation and import capabilities.</li>
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
 * {@link #createContext(KeyUsage, Key, ContextSpec)} is called:
 * <ol>
 * <li>The binding for the role is located.</li>
 * <li>The supplied key and spec are validated against the expected types.</li>
 * <li>A new {@link CryptoContext} is constructed using the registered
 * factory.</li>
 * </ol>
 *
 * <h2>Key operations</h2> Providers register generation and import operations
 * independently. Lookup returns an interface that guarantees the requested
 * operation.
 *
 * <h2>Parameter sets</h2> An algorithm may advertise named, discoverable
 * key-generation configurations via {@link #parameterSets()}. Each entry is
 * either a {@link ParameterSetDescriptor.Concrete} (a ready-to-use spec with a
 * fixed security level) or a {@link ParameterSetDescriptor.Template} (a
 * parameterised family where the caller supplies named values and a factory
 * produces the spec). Callers such as UIs, provisioning tools, and policy
 * engines can enumerate these without prior knowledge of the concrete algorithm.
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
 * specs during registration and
 * {@link #createContext(KeyUsage, Key, ContextSpec)} to prevent downgrade or
 * misuse attacks.
 * </p>
 *
 * @since 1.0
 */
public abstract class CryptoAlgorithm { // NOPMD

    private static final String SPEC_TYPE_NULL = "specType must not be null";

    private final String _id;
    private final String _displayName;
    private final int _priority;
    private final String _providerName;

    private final List<Capability> capabilities = new ArrayList<>();
    private final Map<KeyUsage, List<RoleBinding<?, ?, ?>>> ctxBindings = new EnumMap<>(KeyUsage.class);
    private final Map<Class<? extends AlgorithmKeySpec>, AsymmetricKeyPairGenerator<?>> keyPairGenerators = new LinkedHashMap<>();
    private final Map<Class<? extends AlgorithmKeySpec>, PublicKeyImporter<?>> publicKeyImporters = new LinkedHashMap<>();
    private final Map<Class<? extends AlgorithmKeySpec>, PrivateKeyImporter<?>> privateKeyImporters = new LinkedHashMap<>();
    private final Map<Class<? extends AlgorithmKeySpec>, SymmetricKeyGenerator<?>> symmetricKeyGenerators = new LinkedHashMap<>();
    private final Map<Class<? extends AlgorithmKeySpec>, SymmetricKeyImporter<?>> symmetricKeyImporters = new LinkedHashMap<>();
    private final Map<Class<? extends AlgorithmKeySpec>, AlgorithmKeySpec> asymmetricDefaults = new LinkedHashMap<>();
    private final Map<Class<? extends AlgorithmKeySpec>, AlgorithmKeySpec> symmetricDefaults = new LinkedHashMap<>();

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
        private final ContextFactoryKS<C, K, S> factory;
        private final Supplier<? extends S> defaultSpec;

        private RoleBinding(Class<C> ctxType, Class<K> keyType, Class<S> specType, ContextFactoryKS<C, K, S> factory,
                Supplier<? extends S> defaultSpec) {
            this.ctxType = ctxType;
            this.keyType = keyType;
            this.specType = specType;
            this.factory = factory;
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
     * {@link #createContext(KeyUsage, Key, ContextSpec)} is later invoked, the
     * provided {@code key} and optional {@code spec} are matched against these
     * bindings.
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
    protected final <C extends CryptoContext, K extends Key, S extends ContextSpec> void bindContext(KeyUsage role,
            Class<C> ctxType, Class<K> keyType, Class<S> specType, ContextFactoryKS<C, K, S> factory,
            Supplier<? extends S> defaultSpec) {
        Objects.requireNonNull(role, "role must not be null");
        Objects.requireNonNull(ctxType, "ctxType must not be null");
        Objects.requireNonNull(keyType, "keyType must not be null");
        Objects.requireNonNull(specType, SPEC_TYPE_NULL);
        Objects.requireNonNull(factory, "factory must not be null");
        Objects.requireNonNull(defaultSpec, "defaultSpec must not be null");
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
     */
    @SuppressWarnings("unchecked")
    public final <C extends CryptoContext, K extends Key, S extends ContextSpec> C createContext(KeyUsage role, K key,
            S spec) {
        return createContextInternal(role, key, spec);
    }

    @SuppressWarnings("unchecked")
    private <C extends CryptoContext, K extends Key, S extends ContextSpec> C createContextInternal(KeyUsage role,
            K key, S spec) {
        Objects.requireNonNull(role, "role must not be null");
        Objects.requireNonNull(key, "key must not be null");
        List<RoleBinding<?, ?, ?>> list = ctxBindings.get(role);
        if (list == null || list.isEmpty()) {
            throw new UnsupportedRoleException(_id + " does not support role " + role);
        }
        for (RoleBinding<?, ?, ?> rb0 : list) {
            RoleBinding<C, K, S> rb = (RoleBinding<C, K, S>) rb0;
            if (rb.accepts(key, spec)) {
                S resolved = (spec != null) ? spec
                        : Objects.requireNonNull(rb.defaultSpec.get(), "defaultSpec value must not be null");
                C ctx = Objects.requireNonNull(rb.factory.createContext(key, resolved), _id + " factory returned null");
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

    private <S extends AlgorithmKeySpec> S resolveDefault(Class<S> specType, Supplier<? extends S> defaultSpecOrNull) {
        if (defaultSpecOrNull == null) {
            return null;
        }
        S value = Objects.requireNonNull(defaultSpecOrNull.get(), "defaultSpec value must not be null");
        if (!specType.isInstance(value)) {
            throw new IllegalArgumentException("defaultSpec must be an instance of " + specType.getName());
        }
        return value;
    }

    /**
     * Registers asymmetric key-pair generation for one exact specification class.
     *
     * <p>
     * The optional default is resolved and validated during registration.
     * Registered generators must be safe for concurrent invocation after the
     * algorithm is published.
     * </p>
     *
     * @param specType          exact specification class
     * @param generator         non-null generator
     * @param defaultSpecOrNull optional default supplier, evaluated once
     * @param <S>               specification type
     * @throws NullPointerException     if a required argument or supplied default
     *                                  is {@code null}
     * @throws IllegalArgumentException if the supplied default has the wrong type
     */
    protected final <S extends AlgorithmKeySpec> void registerAsymmetricKeyPairGenerator(Class<S> specType,
            AsymmetricKeyPairGenerator<S> generator, Supplier<? extends S> defaultSpecOrNull) {
        Objects.requireNonNull(specType, SPEC_TYPE_NULL);
        keyPairGenerators.put(specType, Objects.requireNonNull(generator, "generator must not be null"));
        asymmetricDefaults.put(specType, resolveDefault(specType, defaultSpecOrNull));
    }

    /**
     * Registers public-key import for one exact specification class.
     *
     * @param specType exact specification class
     * @param importer non-null importer safe for concurrent invocation
     * @param <S>      specification type
     * @throws NullPointerException if an argument is {@code null}
     */
    protected final <S extends AlgorithmKeySpec> void registerPublicKeyImporter(Class<S> specType,
            PublicKeyImporter<S> importer) {
        Objects.requireNonNull(specType, SPEC_TYPE_NULL);
        publicKeyImporters.put(specType, Objects.requireNonNull(importer, "importer must not be null"));
    }

    /**
     * Registers private-key import for one exact specification class.
     *
     * @param specType exact specification class
     * @param importer non-null importer safe for concurrent invocation
     * @param <S>      specification type
     * @throws NullPointerException if an argument is {@code null}
     */
    protected final <S extends AlgorithmKeySpec> void registerPrivateKeyImporter(Class<S> specType,
            PrivateKeyImporter<S> importer) {
        Objects.requireNonNull(specType, SPEC_TYPE_NULL);
        privateKeyImporters.put(specType, Objects.requireNonNull(importer, "importer must not be null"));
    }

    /**
     * Registers symmetric-key generation for one exact specification class.
     *
     * <p>
     * The optional default is resolved and validated during registration.
     * </p>
     *
     * @param specType          exact specification class
     * @param generator         non-null generator safe for concurrent invocation
     * @param defaultSpecOrNull optional default supplier, evaluated once
     * @param <S>               specification type
     * @throws NullPointerException     if a required argument or supplied default
     *                                  is {@code null}
     * @throws IllegalArgumentException if the supplied default has the wrong type
     */
    protected final <S extends AlgorithmKeySpec> void registerSymmetricKeyGenerator(Class<S> specType,
            SymmetricKeyGenerator<S> generator, Supplier<? extends S> defaultSpecOrNull) {
        Objects.requireNonNull(specType, SPEC_TYPE_NULL);
        symmetricKeyGenerators.put(specType, Objects.requireNonNull(generator, "generator must not be null"));
        symmetricDefaults.put(specType, resolveDefault(specType, defaultSpecOrNull));
    }

    /**
     * Registers symmetric-key import for one exact specification class.
     *
     * @param specType exact specification class
     * @param importer non-null importer safe for concurrent invocation
     * @param <S>      specification type
     * @throws NullPointerException if an argument is {@code null}
     */
    protected final <S extends AlgorithmKeySpec> void registerSymmetricKeyImporter(Class<S> specType,
            SymmetricKeyImporter<S> importer) {
        Objects.requireNonNull(specType, SPEC_TYPE_NULL);
        symmetricKeyImporters.put(specType, Objects.requireNonNull(importer, "importer must not be null"));
    }

    private IllegalArgumentException missing(String operation, Class<?> specType) {
        return new IllegalArgumentException(_id + " has no " + operation + " for exact spec " + specType.getName());
    }

    /**
     * Returns the asymmetric key-pair generator registered for an exact
     * specification class.
     *
     * <p>
     * The returned implementation may be shared and invoked concurrently.
     * </p>
     *
     * @param specType exact specification class; subclasses are not matched
     * @param <S>      specification type
     * @return registered generator
     * @throws NullPointerException     if {@code specType} is {@code null}
     * @throws IllegalArgumentException if no generator is registered
     */
    @SuppressWarnings("unchecked")
    public final <S extends AlgorithmKeySpec> AsymmetricKeyPairGenerator<S> asymmetricKeyPairGenerator(
            Class<S> specType) {
        Objects.requireNonNull(specType, SPEC_TYPE_NULL);
        AsymmetricKeyPairGenerator<?> generator = keyPairGenerators.get(specType);
        if (generator == null) {
            throw missing("asymmetric key-pair generator", specType);
        }
        return (AsymmetricKeyPairGenerator<S>) generator;
    }

    /**
     * Returns the public-key importer registered for an exact specification class.
     *
     * <p>
     * The returned implementation may be shared and invoked concurrently.
     * </p>
     *
     * @param specType exact specification class; subclasses are not matched
     * @param <S>      specification type
     * @return registered importer
     * @throws NullPointerException     if {@code specType} is {@code null}
     * @throws IllegalArgumentException if no importer is registered
     */
    @SuppressWarnings("unchecked")
    public final <S extends AlgorithmKeySpec> PublicKeyImporter<S> publicKeyImporter(Class<S> specType) {
        Objects.requireNonNull(specType, SPEC_TYPE_NULL);
        PublicKeyImporter<?> importer = publicKeyImporters.get(specType);
        if (importer == null) {
            throw missing("public-key importer", specType);
        }
        return (PublicKeyImporter<S>) importer;
    }

    /**
     * Returns the private-key importer registered for an exact specification class.
     *
     * <p>
     * The returned implementation may be shared and invoked concurrently.
     * </p>
     *
     * @param specType exact specification class; subclasses are not matched
     * @param <S>      specification type
     * @return registered importer
     * @throws NullPointerException     if {@code specType} is {@code null}
     * @throws IllegalArgumentException if no importer is registered
     */
    @SuppressWarnings("unchecked")
    public final <S extends AlgorithmKeySpec> PrivateKeyImporter<S> privateKeyImporter(Class<S> specType) {
        Objects.requireNonNull(specType, SPEC_TYPE_NULL);
        PrivateKeyImporter<?> importer = privateKeyImporters.get(specType);
        if (importer == null) {
            throw missing("private-key importer", specType);
        }
        return (PrivateKeyImporter<S>) importer;
    }

    /**
     * Returns the symmetric-key generator registered for an exact specification
     * class.
     *
     * <p>
     * The returned implementation may be shared and invoked concurrently.
     * </p>
     *
     * @param specType exact specification class; subclasses are not matched
     * @param <S>      specification type
     * @return registered generator
     * @throws NullPointerException     if {@code specType} is {@code null}
     * @throws IllegalArgumentException if no generator is registered
     */
    @SuppressWarnings("unchecked")
    public final <S extends AlgorithmKeySpec> SymmetricKeyGenerator<S> symmetricKeyGenerator(Class<S> specType) {
        Objects.requireNonNull(specType, SPEC_TYPE_NULL);
        SymmetricKeyGenerator<?> generator = symmetricKeyGenerators.get(specType);
        if (generator == null) {
            throw missing("symmetric-key generator", specType);
        }
        return (SymmetricKeyGenerator<S>) generator;
    }

    /**
     * Returns the symmetric-key importer registered for an exact specification
     * class.
     *
     * <p>
     * The returned implementation may be shared and invoked concurrently.
     * </p>
     *
     * @param specType exact specification class; subclasses are not matched
     * @param <S>      specification type
     * @return registered importer
     * @throws NullPointerException     if {@code specType} is {@code null}
     * @throws IllegalArgumentException if no importer is registered
     */
    @SuppressWarnings("unchecked")
    public final <S extends AlgorithmKeySpec> SymmetricKeyImporter<S> symmetricKeyImporter(Class<S> specType) {
        Objects.requireNonNull(specType, SPEC_TYPE_NULL);
        SymmetricKeyImporter<?> importer = symmetricKeyImporters.get(specType);
        if (importer == null) {
            throw missing("symmetric-key importer", specType);
        }
        return (SymmetricKeyImporter<S>) importer;
    }

    /**
     * Returns the discoverable parameter sets (or parameterized templates)
     * supported by this algorithm.
     *
     * <p>
     * Callers (UIs, provisioning tools, policy engines) use this list to present
     * users with valid, named key-generation options without prior knowledge of the
     * concrete algorithm. Each entry is either a pre-built {@link ParameterSetDescriptor.Concrete}
     * (ready spec) or a {@link ParameterSetDescriptor.Template} (user-supplied
     * arguments produce the spec).
     * </p>
     *
     * <p>
     * The default implementation returns an empty list. Algorithms with finite,
     * enumerable parameter sets should override this method. Overrides must return
     * immutable lists in stable order, with unique nonblank descriptor identifiers.
     * Registry loading validates a snapshot; external providers remain responsible
     * for maintaining the contract on subsequent calls. Implementations may use
     * {@link ParameterSetDescriptor#snapshot(List)} to validate and copy their list.
     * </p>
     *
     * @return immutable list of parameter set descriptors; never {@code null}
     */
    public List<ParameterSetDescriptor<? extends AlgorithmKeySpec>> parameterSets() {
        return List.of();
    }

    /**
     * Indicates that signing consumes durable private-key state. This declaration
     * does not enable the ordinary SIGN role: callers need a keyring-owned
     * {@link zeroecho.core.storage.StatefulSigner} capability.
     * @return whether durable state ownership is required for signing
     */
    public boolean requiresStatefulSigning() {
        return false;
    }

    /**
     * Returns deterministic metadata for every exact key operation.
     *
     * @return immutable metadata ordered by operation and specification class
     */
    public final List<KeyOperationInfo> keyOperations() {
        List<KeyOperationInfo> result = new ArrayList<>();
        addOperationInfo(result, KeyOperation.ASYMMETRIC_KEY_PAIR_GENERATE, keyPairGenerators, asymmetricDefaults);
        addOperationInfo(result, KeyOperation.ASYMMETRIC_PUBLIC_IMPORT, publicKeyImporters, Map.of());
        addOperationInfo(result, KeyOperation.ASYMMETRIC_PRIVATE_IMPORT, privateKeyImporters, Map.of());
        addOperationInfo(result, KeyOperation.SYMMETRIC_GENERATE, symmetricKeyGenerators, symmetricDefaults);
        addOperationInfo(result, KeyOperation.SYMMETRIC_IMPORT, symmetricKeyImporters, Map.of());
        result.sort(Comparator.comparing(KeyOperationInfo::operation).thenComparing(info -> info.specType().getName()));
        return List.copyOf(result);
    }

    private static void addOperationInfo(List<KeyOperationInfo> result, KeyOperation operation,
            Map<Class<? extends AlgorithmKeySpec>, ?> operations,
            Map<Class<? extends AlgorithmKeySpec>, AlgorithmKeySpec> defaults) {
        for (Class<? extends AlgorithmKeySpec> specType : operations.keySet()) {
            result.add(new KeyOperationInfo(operation, specType, defaults.get(specType)));
        }
    }
}
