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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.Set;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmIdentityCatalog;
import zeroecho.core.spec.AlgorithmIdentityCodec;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapabilities;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.core.spi.AlgorithmExecutionCapabilityProvider;

/**
 * One immutable internally consistent runtime authority snapshot.
 *
 * <p>
 * The snapshot composes identities, X.509 components, binding rules, installed
 * execution capabilities, aliases, immutable defaults, security floor, and
 * configured policy once. It owns the effective resolver and a stable semantic
 * fingerprint. It contains no key material and is not persisted in Phase A.
 * </p>
 */
public final class X509AuthoritySnapshot {

    private final AlgorithmIdentityCatalog identities;
    private final X509ComponentCatalog components;
    private final X509BindingCatalog bindings;
    private final AlgorithmExecutionCapabilities capabilities;
    private final List<AlgorithmIdentityCodec> codecs;
    private final Map<String, AlgorithmIdentity> aliases;
    private final Map<String, AlgorithmSuite> defaults;
    private final X509AlgorithmResolver.Policy policy;
    private final X509AlgorithmResolver resolver;
    private final String semanticFingerprint;
    private final Map<ExecutorKey, Object> executors;
    private final Object provenanceToken;

    /**
     * Creates a consistent authority snapshot.
     *
     * @param identities   exact identity catalog
     * @param components   parameter component catalog
     * @param bindings     role-specific binding catalog
     * @param capabilities installed execution capabilities
     * @param policy       configured restrictive policy
     */
    public X509AuthoritySnapshot(AlgorithmIdentityCatalog identities, X509ComponentCatalog components,
            X509BindingCatalog bindings, AlgorithmExecutionCapabilities capabilities,
            X509AlgorithmResolver.Policy policy) {
        this(identities, components, bindings, capabilities, List.of(),
                BootstrapAlgorithmIdentities.compatibilityAliases(), X509BuiltInDefaults.snapshot(), policy,
                List.of());
    }

    private X509AuthoritySnapshot(AlgorithmIdentityCatalog identities, X509ComponentCatalog components,
            X509BindingCatalog bindings, AlgorithmExecutionCapabilities capabilities,
            Collection<AlgorithmIdentityCodec> codecs, Map<String, AlgorithmIdentity> aliases,
            Map<String, AlgorithmSuite> defaults, X509AlgorithmResolver.Policy policy,
            Collection<ExecutorBinding> executorBindings) {
        this.identities = Objects.requireNonNull(identities, "identities");
        this.components = Objects.requireNonNull(components, "components");
        this.bindings = Objects.requireNonNull(bindings, "bindings");
        this.capabilities = Objects.requireNonNull(capabilities, "capabilities");
        this.codecs = immutableCodecs(codecs);
        this.aliases = immutableAliases(aliases, identities);
        this.defaults = immutableDefaults(defaults);
        this.policy = Objects.requireNonNull(policy, "policy");
        this.resolver = new X509AlgorithmResolver(bindings, capabilities, policy);
        this.executors = immutableExecutors(executorBindings, capabilities);
        this.provenanceToken = new Object();
        this.semanticFingerprint = fingerprint();
    }

    /**
     * Creates the installed runtime snapshot with an explicit policy.
     *
     * @param policy configured restrictive policy
     * @return installed snapshot
     */
    public static X509AuthoritySnapshot installed(X509AlgorithmResolver.Policy policy) {
        List<X509BindingRuleProvider> bindingProviders = ServiceLoader.load(X509BindingRuleProvider.class).stream()
                .map(ServiceLoader.Provider::get).sorted(Comparator.comparing(provider -> provider.getClass().getName()))
                .toList();
        List<AlgorithmExecutionCapabilityProvider> capabilityProviders = ServiceLoader
                .load(AlgorithmExecutionCapabilityProvider.class).stream().map(ServiceLoader.Provider::get)
                .sorted(Comparator.comparing(provider -> provider.getClass().getName())).toList();
        return compose(bindingProviders, capabilityProviders, policy);
    }

    /**
     * Composes one runtime graph from explicitly selected trusted providers.
     *
     * @param bindingProviders binding and identity contributors
     * @param capabilityProviders execution contributors used by this runtime
     * @param policy restrictive policy
     * @return immutable authority snapshot
     */
    public static X509AuthoritySnapshot compose(List<X509BindingRuleProvider> bindingProviders,
            List<AlgorithmExecutionCapabilityProvider> capabilityProviders, X509AlgorithmResolver.Policy policy) {
        return compose(bindingProviders, capabilityProviders, List.of(), policy);
    }

    /**
     * Composes one runtime graph with exact process-local executor bindings.
     *
     * @param bindingProviders binding and identity contributors
     * @param capabilityProviders semantic execution contributors
     * @param executorBindings actual process-local executors
     * @param policy restrictive policy
     * @return immutable authority snapshot
     */
    public static X509AuthoritySnapshot compose(List<X509BindingRuleProvider> bindingProviders,
            List<AlgorithmExecutionCapabilityProvider> capabilityProviders,
            List<ExecutorBinding> executorBindings, X509AlgorithmResolver.Policy policy) {
        Objects.requireNonNull(bindingProviders, "bindingProviders");
        Objects.requireNonNull(capabilityProviders, "capabilityProviders");
        List<X509BindingRuleProvider> ordered = bindingProviders.stream()
                .sorted(Comparator.comparing(provider -> provider.getClass().getName())).toList();

        AlgorithmIdentityCatalog identities = BootstrapAlgorithmIdentities.catalog();
        List<X509ComponentCatalog> componentExtensions = new ArrayList<>();
        List<X509BindingCatalog> bindingExtensions = new ArrayList<>();
        List<AlgorithmIdentityCodec> codecs = new ArrayList<>();
        Map<String, AlgorithmIdentity> aliases = new LinkedHashMap<>(
                BootstrapAlgorithmIdentities.compatibilityAliases());
        Map<String, AlgorithmSuite> defaults = new LinkedHashMap<>(X509BuiltInDefaults.snapshot());
        for (X509BindingRuleProvider provider : ordered) {
            Collection<AlgorithmIdentity> contributedIdentities = List.copyOf(provider.identities());
            if (!contributedIdentities.isEmpty()) {
                identities = identities.add(contributedIdentities);
            }
            List<X509ComponentCatalog.Component> contributedComponents = List.copyOf(provider.components());
            if (!contributedComponents.isEmpty()) {
                componentExtensions.add(X509ComponentCatalog.extension(contributedComponents));
            }
            codecs.addAll(List.copyOf(provider.codecs()));
            mergeAliases(aliases, provider.aliases());
            mergeDefaults(defaults, provider.defaults());
        }
        X509ComponentCatalog components = X509ComponentCatalog.builtIn().merge(componentExtensions);
        X509BindingCatalog builtInBindings = StandardX509Bindings.catalog(components);
        for (X509BindingRuleProvider provider : ordered) {
            List<X509BindingRule> rules = List.copyOf(provider.rules());
            if (!rules.isEmpty()) {
                bindingExtensions.add(X509BindingCatalog.extension(rules));
            }
        }
        X509BindingCatalog bindings = builtInBindings.merge(bindingExtensions);
        AlgorithmExecutionCapabilities capabilities = AlgorithmExecutionCapabilities
                .fromProviders(capabilityProviders);
        return new X509AuthoritySnapshot(identities, components, bindings, capabilities, codecs, aliases, defaults,
                policy, executorBindings);
    }

    /**
     * Resolves a canonical identity or finite built-in compatibility alias.
     *
     * @param value canonical identity or approved legacy alias
     * @return exact identity
     */
    public AlgorithmIdentity resolveIdentity(String value) {
        Objects.requireNonNull(value, "value");
        Optional<AlgorithmIdentity> canonical = identities.resolve(value);
        if (canonical.isEmpty() && value.startsWith("zealg:2:")) {
            AlgorithmIdentity parsed = AlgorithmIdentity.parse(value, codecs);
            canonical = identities.resolve(parsed.canonicalForm());
        }
        return canonical.or(() -> Optional.ofNullable(aliases.get(value)))
                .orElseThrow(() -> new IllegalArgumentException("Unknown algorithm identity"));
    }

    /**
     * Resolves an immutable built-in default without extension override.
     *
     * @param identifier versioned default identifier
     * @return exact default suite
     */
    public AlgorithmSuite resolveDefault(String identifier) {
        AlgorithmSuite suite = defaults.get(Objects.requireNonNull(identifier, "identifier"));
        if (suite == null) {
            throw new IllegalArgumentException("Unknown default identifier");
        }
        return suite;
    }

    /**
     * Resolves one effective operation and binds it to this snapshot fingerprint.
     *
     * @param signature exact signature identity
     * @param key exact public-key identity
     * @param direction execution direction
     * @param implementation optional implementation selection
     * @param provenance explicit or default provenance
     * @return effective immutable selection
     */
    public X509AlgorithmResolver.Selection resolve(AlgorithmIdentity signature, AlgorithmIdentity key,
            AlgorithmExecutionCapability.Direction direction, Optional<String> implementation, String provenance) {
        return resolver.resolve(signature, key, direction, implementation, provenance, semanticFingerprint);
    }

    /**
     * Resolves and authorizes one process-local execution plan.
     *
     * @param signature exact signature identity
     * @param key exact public-key identity
     * @param direction operation direction
     * @param implementation optional exact implementation identifier
     * @param provenance explicit or default provenance
     * @param executorType required runtime executor type
     * @param <E> executor type
     * @return unforgeable process-local plan
     */
    public <E> X509ExecutionPlan<E> plan(AlgorithmIdentity signature, AlgorithmIdentity key,
            AlgorithmExecutionCapability.Direction direction, Optional<String> implementation, String provenance,
            Class<E> executorType) {
        X509AlgorithmResolver.Selection selection = resolve(signature, key, direction, implementation, provenance);
        ExecutorKey executorKey = new ExecutorKey(selection.implementation().implementationId(), direction);
        Object executor = executors.get(executorKey);
        if (executor == null || !executorType.isInstance(executor)) {
            throw new X509AlgorithmResolver.ResolutionException(X509AlgorithmResolver.Failure.NO_EXECUTOR);
        }
        return new X509ExecutionPlan<>(selection, executorType.cast(executor), provenanceToken);
    }

    /**
     * Resolves a signing plan for a legacy upper API that carries only the
     * signature identity.
     *
     * @param value canonical identity or approved finite alias
     * @param implementation exact implementation identifier
     * @param executorType required executor type
     * @param <E> executor type
     * @return exact process-local signing plan
     */
    public <E> X509ExecutionPlan<E> planSigning(String value, String implementation, Class<E> executorType) {
        AlgorithmIdentity signature = resolveIdentity(value);
        AlgorithmIdentity key = bootstrapKeyFor(signature);
        return plan(signature, key, AlgorithmExecutionCapability.Direction.SIGN, Optional.of(implementation),
                "explicit", executorType);
    }

    /**
     * Resolves a signing plan when exactly one implementation is available.
     *
     * @param value canonical identity or approved finite alias
     * @param executorType required executor type
     * @param <E> executor type
     * @return exact process-local signing plan
     */
    public <E> X509ExecutionPlan<E> planSigning(String value, Class<E> executorType) {
        AlgorithmIdentity signature = resolveIdentity(value);
        AlgorithmIdentity key = bootstrapKeyFor(signature);
        return plan(signature, key, AlgorithmExecutionCapability.Direction.SIGN, Optional.empty(), "explicit",
                executorType);
    }

    /**
     * Validates an execution plan immediately before invoking its executor.
     *
     * @param plan plan minted by this snapshot
     * @param expectedExecutor exact executor reference expected by the boundary
     * @param direction required operation direction
     * @throws IllegalArgumentException if provenance, executor, implementation, or
     *                                  direction differs
     */
    public void authorize(X509ExecutionPlan<?> plan, Object expectedExecutor,
            AlgorithmExecutionCapability.Direction direction) {
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(expectedExecutor, "expectedExecutor");
        Objects.requireNonNull(direction, "direction");
        X509AlgorithmResolver.Selection selection = plan.selection();
        ExecutorKey key = new ExecutorKey(selection.implementation().implementationId(), direction);
        if (!plan.isOwnedBy(provenanceToken) || !sameInstance(plan.executor(), expectedExecutor)
                || selection.direction() != direction || !sameInstance(executors.get(key), expectedExecutor)
                || !semanticFingerprint.equals(selection.authorityFingerprint())) {
            throw new IllegalArgumentException("X.509 execution plan authority mismatch");
        }
    }

    /**
     * Mints the live completion of an X.509 status-object SIGN operation.
     *
     * @param statusObject immutable generated status object
     * @param signingPlan exact live SIGN plan used to produce its content
     * @return non-forgeable process-local completion
     * @throws IllegalArgumentException if the plan is foreign or not an authorized
     *                                  SIGN plan
     */
    public X509SignedObjectCompletion completeStatusObject(StatusObject statusObject,
            X509ExecutionPlan<SignatureWorkflow> signingPlan) {
        Objects.requireNonNull(statusObject, "statusObject");
        authorize(signingPlan, signingPlan.executor(), AlgorithmExecutionCapability.Direction.SIGN);
        return new X509SignedObjectCompletion(statusObject, signingPlan, provenanceToken);
    }

    /**
     * Validates and unwraps a status completion minted by this live authority.
     *
     * @param completion signed-object completion
     * @return immutable completed status object
     * @throws IllegalArgumentException if provenance or executor binding differs
     */
    public StatusObject requireStatusCompletion(X509SignedObjectCompletion completion) {
        Objects.requireNonNull(completion, "completion");
        if (!completion.isOwnedBy(provenanceToken)) {
            throw new IllegalArgumentException("X.509 status completion authority mismatch");
        }
        X509ExecutionPlan<SignatureWorkflow> plan = completion.signingPlan();
        authorize(plan, plan.executor(), AlgorithmExecutionCapability.Direction.SIGN);
        return completion.statusObject();
    }

    /**
     * Returns the exact live SIGN plan after validating status completion
     * provenance.
     *
     * @param completion status completion minted by this authority
     * @return exact authorized SIGN plan
     * @throws IllegalArgumentException if the completion belongs to another live
     *                                  runtime
     */
    public X509ExecutionPlan<SignatureWorkflow> requireStatusSigningPlan(X509SignedObjectCompletion completion) {
        requireStatusCompletion(completion);
        return completion.signingPlan();
    }

    /**
     * Validates a persisted signature identity against the complete runtime
     * authority intersection.
     *
     * @param value canonical identity or approved compatibility alias
     * @param direction execution direction
     * @return exact canonical signature identity
     */
    public AlgorithmIdentity requireExecutableSignature(String value,
            AlgorithmExecutionCapability.Direction direction) {
        AlgorithmIdentity signature = resolveIdentity(value);
        X509SecurityFloor.requirePermitted(signature);
        bindings.resolve(signature, X509AlgorithmRole.SIGNATURE_ALGORITHM);
        List<AlgorithmIdentity> keys = identities.identities().stream()
                .filter(identity -> identity.kind() == AlgorithmIdentity.Kind.PUBLIC_KEY).toList();
        for (AlgorithmIdentity key : keys) {
            try {
                AlgorithmSuite suite = X509SuiteCompatibility.requireCompatible(signature, key);
                if (policy.permits(suite, direction)
                        && !capabilities.supporting(signature, suite, direction).isEmpty()) {
                    return signature;
                }
            } catch (IllegalArgumentException incompatible) {
                continue;
            }
        }
        throw new IllegalArgumentException("Signature identity is unavailable for execution");
    }

    /**
     * Rejects a selection produced by a semantically different authority snapshot.
     *
     * @param selection effective selection
     */
    public void requireAuthority(X509AlgorithmResolver.Selection selection) {
        Objects.requireNonNull(selection, "selection");
        if (!semanticFingerprint.equals(selection.authorityFingerprint())) {
            throw new IllegalArgumentException("X.509 authority snapshot mismatch");
        }
    }

    /**
     * Creates one exact process-local executor binding.
     *
     * @param implementationId semantic capability implementation identifier
     * @param direction supported execution direction
     * @param executor actual runtime executor
     * @return immutable binding contribution
     */
    public static ExecutorBinding bindExecutor(String implementationId,
            AlgorithmExecutionCapability.Direction direction, Object executor) {
        return new ExecutorBinding(implementationId, direction, executor);
    }

    /**
     * Returns the owned effective resolver.
     *
     * @return immutable resolver
     */
    public X509AlgorithmResolver resolver() {
        return resolver;
    }

    /**
     * Returns the binding catalog snapshot.
     *
     * @return immutable bindings
     */
    public X509BindingCatalog bindings() {
        return bindings;
    }

    /**
     * Returns the component catalog snapshot.
     *
     * @return immutable components
     */
    public X509ComponentCatalog components() {
        return components;
    }

    /**
     * Returns the stable snapshot fingerprint.
     *
     * @return SHA-256 hexadecimal semantic fingerprint
     */
    public String semanticFingerprint() {
        return semanticFingerprint;
    }

    private String fingerprint() {
        StringBuilder semantic = new StringBuilder();
        addFields(semantic, "identity", identities.identities().stream().map(AlgorithmIdentity::canonicalForm).toList());
        addFields(semantic, "codec", codecs.stream().map(AlgorithmIdentityCodec::id).toList());
        addFields(semantic, "component", List.of(components.semanticFingerprint()));
        addFields(semantic, "binding",
                bindings.rules().stream().map(X509BindingRule::semanticFingerprint).sorted().toList());
        addFields(semantic, "capability", capabilities.all().stream()
                .map(capability -> capability.implementationId() + ":" + capability.domainFingerprint()).toList());
        addFields(semantic, "alias", aliases.entrySet().stream().sorted(Map.Entry.comparingByKey())
                .map(entry -> entry.getKey() + ":" + entry.getValue().canonicalForm()).toList());
        addFields(semantic, "default", defaults.entrySet().stream().sorted(Map.Entry.comparingByKey())
                .map(entry -> entry.getKey() + ":" + entry.getValue().canonicalForm()).toList());
        addFields(semantic, "floor", List.of(X509SecurityFloor.semanticFingerprint()));
        addFields(semantic, "policy", List.of(policy.semanticFingerprint()));
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(semantic.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }

    private static List<AlgorithmIdentityCodec> immutableCodecs(Collection<AlgorithmIdentityCodec> source) {
        Map<String, AlgorithmIdentityCodec> byId = new LinkedHashMap<>();
        source.stream().sorted(Comparator.comparing(AlgorithmIdentityCodec::id)).forEach(codec -> {
            if (byId.putIfAbsent(codec.id(), codec) != null) {
                throw new IllegalArgumentException("Algorithm identity codec collision");
            }
        });
        return List.copyOf(byId.values());
    }

    private static Map<String, AlgorithmIdentity> immutableAliases(Map<String, AlgorithmIdentity> source,
            AlgorithmIdentityCatalog identities) {
        Map<String, AlgorithmIdentity> copy = new LinkedHashMap<>();
        source.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(entry -> {
            AlgorithmIdentity identity = Objects.requireNonNull(entry.getValue(), "alias identity");
            if (entry.getKey().isBlank() || identities.resolve(identity.canonicalForm()).isEmpty()) {
                throw new IllegalArgumentException("Invalid algorithm alias contribution");
            }
            X509SecurityFloor.requirePermitted(identity);
            copy.put(entry.getKey(), identity);
        });
        return Map.copyOf(copy);
    }

    private static Map<String, AlgorithmSuite> immutableDefaults(Map<String, AlgorithmSuite> source) {
        Map<String, AlgorithmSuite> copy = new LinkedHashMap<>();
        source.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(entry -> {
            if (entry.getKey().isBlank()) {
                throw new IllegalArgumentException("Invalid default identifier");
            }
            X509SecurityFloor.requirePermitted(entry.getValue().signature());
            copy.put(entry.getKey(), Objects.requireNonNull(entry.getValue(), "default suite"));
        });
        return Map.copyOf(copy);
    }

    private static Map<ExecutorKey, Object> immutableExecutors(Collection<ExecutorBinding> source,
            AlgorithmExecutionCapabilities capabilities) {
        Map<ExecutorKey, Object> copy = new LinkedHashMap<>();
        Set<String> known = capabilities.all().stream().map(AlgorithmExecutionCapability::implementationId)
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        source.forEach(binding -> {
            if (!known.contains(binding.implementationId())) {
                throw new IllegalArgumentException("Executor binding has no semantic capability");
            }
            ExecutorKey key = new ExecutorKey(binding.implementationId(), binding.direction());
            if (copy.putIfAbsent(key, binding.executor()) != null) {
                throw new IllegalArgumentException("Duplicate execution binding");
            }
        });
        return Map.copyOf(copy);
    }

    private static boolean sameInstance(Object first, Object second) {
        Map<Object, Boolean> identity = new IdentityHashMap<>();
        identity.put(first, Boolean.TRUE);
        return identity.containsKey(second);
    }

    private static AlgorithmIdentity bootstrapKeyFor(AlgorithmIdentity signature) {
        if (signature.equals(BootstrapAlgorithmIdentities.ECDSA_SHA256)) {
            return BootstrapAlgorithmIdentities.EC_P256_PUBLIC_KEY;
        }
        if (signature.equals(BootstrapAlgorithmIdentities.ECDSA_SHA384)) {
            return BootstrapAlgorithmIdentities.EC_P384_PUBLIC_KEY;
        }
        if (signature.equals(BootstrapAlgorithmIdentities.ECDSA_SHA512)) {
            return BootstrapAlgorithmIdentities.EC_P521_PUBLIC_KEY;
        }
        if (signature.equals(BootstrapAlgorithmIdentities.ED25519_SIGNATURE)) {
            return BootstrapAlgorithmIdentities.ED25519_PUBLIC_KEY;
        }
        if (signature.equals(BootstrapAlgorithmIdentities.ED448_SIGNATURE)) {
            return BootstrapAlgorithmIdentities.ED448_PUBLIC_KEY;
        }
        if ("rsa-pkcs1-v1_5".equals(signature.family().name())
                || "rsa-pss".equals(signature.family().name())) {
            return BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY;
        }
        throw new IllegalArgumentException("Exact public-key identity is required");
    }

    private static void mergeAliases(Map<String, AlgorithmIdentity> target, Map<String, AlgorithmIdentity> addition) {
        addition.forEach((alias, identity) -> {
            if (target.putIfAbsent(alias, identity) != null) {
                throw new IllegalArgumentException("Algorithm alias collision");
            }
        });
    }

    private static void mergeDefaults(Map<String, AlgorithmSuite> target, Map<String, AlgorithmSuite> addition) {
        addition.forEach((identifier, suite) -> {
            if (identifier.startsWith("zeroecho.") || target.putIfAbsent(identifier, suite) != null) {
                throw new IllegalArgumentException("Default identifier collision");
            }
        });
    }

    private static void addFields(StringBuilder target, String category, List<String> values) {
        List<String> sorted = values.stream().sorted().toList();
        appendField(target, category);
        for (String value : sorted) {
            appendField(target, value);
        }
    }

    /**
     * Immutable process-local executor contribution.
     */
    public static final class ExecutorBinding {

        private final String implementationId;
        private final AlgorithmExecutionCapability.Direction direction;
        private final Object executor;

        private ExecutorBinding(String implementationId, AlgorithmExecutionCapability.Direction direction,
                Object executor) {
            this.implementationId = Objects.requireNonNull(implementationId, "implementationId");
            this.direction = Objects.requireNonNull(direction, "direction");
            this.executor = Objects.requireNonNull(executor, "executor");
            if (implementationId.isBlank()) {
                throw new IllegalArgumentException("implementationId must not be blank");
            }
        }

        /* default */ String implementationId() {
            return implementationId;
        }

        /* default */ AlgorithmExecutionCapability.Direction direction() {
            return direction;
        }

        /* default */ Object executor() {
            return executor;
        }
    }

    private record ExecutorKey(String implementationId, AlgorithmExecutionCapability.Direction direction) {
    }

    private static void appendField(StringBuilder target, String value) {
        int length = value.getBytes(StandardCharsets.UTF_8).length;
        target.append(length).append(':').append(value);
    }
}
