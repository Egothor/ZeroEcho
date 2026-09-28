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
package zeroecho.pki.application; // NOPMD - CouplingBetweenObjects: session composition owns explicit component wiring and lifetime.

import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.PublicationService;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.SigningService;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.confirmation.CredentialConfirmationService;
import zeroecho.pki.impl.core.DefaultCertificationRequestService;
import zeroecho.pki.impl.core.DefaultCredentialConfirmationService;
import zeroecho.pki.impl.core.DefaultProfileService;
import zeroecho.pki.impl.core.DefaultPublicationService;
import zeroecho.pki.impl.core.DefaultRevocationService;
import zeroecho.pki.impl.core.FullCrlSigningPreparation;
import zeroecho.pki.impl.core.continuation.SigningOuterTerminalDriver;
import zeroecho.pki.impl.core.signing.SigningReactor;
import zeroecho.pki.impl.core.signing.DefaultSigningService;
import zeroecho.pki.impl.core.signing.DefaultSemanticSigningService;
import zeroecho.pki.impl.framework.x509.ImmutableX509AlgorithmBindingRegistry;
import zeroecho.pki.impl.framework.x509.StandardX509Bindings;
import zeroecho.pki.impl.framework.x509.X509AlgorithmResolver;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509BindingRuleProvider;
import zeroecho.pki.impl.framework.x509.ZeroEchoPrivateX509Bindings;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.algorithm.X509AlgorithmBindingProvider;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProviderRuntimeDependencies;
import zeroecho.pki.spi.publish.Publisher;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.PkiStoreRuntimeDependencies;

/** Default lifecycle-owned PKI session composition. */
final class DefaultPkiSession implements PkiSession { // NOPMD - CyclomaticComplexity totals cohesive independent operations; method-level checks remain enabled.

    private final PkiStore store;
    private final AuditSink audit;
    private final ProfileService profiles;
    private final CredentialConfirmationService confirmations;
    private final RevocationService revocations;
    private final Optional<CertificationRequestService> requests;
    private final Optional<PublicationService> publications;
    private final SigningGraph signingGraph;
    private final X509AlgorithmBindingRegistry algorithmBindings;
    private final PkiResourceScopeResolver resourceScopes;
    private final PkiOperationExecutor operations;
    private final PkiRepository repository;
    private final Optional<PkiSigningCommands> signingCommands;
    private final AtomicReference<Lifecycle> lifecycle;
    private final Optional<LocalSigningExecutor> localSigning;
    private final ReentrantLock closeLock = new ReentrantLock();

    private DefaultPkiSession(DefaultPkiOperationExecutor.ConfigurationSummary configuration, PkiStore store, AuditSink audit,
            ProfileService profiles, RevocationService revocations, X509AlgorithmBindingRegistry algorithmBindings,
            KeyPossessionProofProviderComposition proofProviders,
            Optional<CredentialConfirmationProofRuntimePolicy> proofPolicy, Clock clock,
            ServiceGraph graph, SigningGraph signingGraph, List<zeroecho.pki.api.KeyRef> configuredKeys,
            Optional<LocalSigningConfiguration> localConfiguration, Optional<zeroecho.pki.api.audit.Principal> operator,
            zeroecho.pki.impl.core.signing.SigningStepExecutor.OuterTerminalDriver localDriver,
            AtomicReference<Lifecycle> lifecycle) {
        this.lifecycle = Objects.requireNonNull(lifecycle, "lifecycle");
        this.store = Objects.requireNonNull(store, "store");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.profiles = Objects.requireNonNull(profiles, "profiles");
        this.confirmations = new DefaultCredentialConfirmationService(store, this::requireOpen,
                proofProviders.providersBySuiteId(), proofPolicy, new SecureRandom(), Optional.of(audit), clock);
        this.revocations = Objects.requireNonNull(revocations, "revocations");
        this.requests = graph.requests();
        this.publications = graph.publications();
        this.signingGraph = Objects.requireNonNull(signingGraph, "signingGraph");
        this.algorithmBindings = Objects.requireNonNull(algorithmBindings, "algorithmBindings");
        this.resourceScopes = new DefaultPkiResourceScopeResolver(store, this::requireOpen);
        this.repository = new DefaultPkiRepository(store, this::requireOpen);
        this.signingCommands = signingGraph.semanticService()
                .map(service -> new DefaultPkiSigningCommands(service, repository, requests, this::requireOpen));
        DefaultPkiConfigurationChoices choices = new DefaultPkiConfigurationChoices(configuredKeys, store,
                Optional.ofNullable(signingGraph.provider()), graph.targets(), this::requireOpen);
        PkiOperationExecutor coreOperations = new DefaultPkiOperationExecutor(configuration, store, profiles, revocations,
                requests, publications, confirmations, algorithmBindings, this::requireOpen, choices);
        Optional<LocalInvocationAudit> localAudit = operator.map(value -> new LocalInvocationAudit(audit, clock, value));
        this.operations = localAudit.<PkiOperationExecutor>map(value ->
                new LocalPkiOperationExecutor(coreOperations, choices, value, this::requireOpen)).orElse(coreOperations);
        this.localSigning = localConfiguration.map(value -> new DefaultLocalSigningExecutor(store,
                signingGraph.provider(), signingGraph.semanticService().orElseThrow(), signingCommands.orElseThrow(),
                value, localDriver,
                localAudit.orElseThrow(), this::requireOpen));
    }

    /* default */ static PkiSession open(PkiSessionConfiguration configuration) {
        return open(configuration, PkiSessionRuntimeDependencies.none(), Clock.systemUTC(),
                ProductionBootstrap.INSTANCE);
    }

    /* default */ static PkiSession open(PkiSessionConfiguration configuration,
            PkiSessionRuntimeDependencies dependencies) {
        return open(configuration, dependencies, Clock.systemUTC(), ProductionBootstrap.INSTANCE);
    }

    /* default */ static PkiSession open(PkiSessionConfiguration configuration,
            PkiSessionRuntimeDependencies dependencies, Clock clock) {
        return open(configuration, dependencies, clock, ProductionBootstrap.INSTANCE);
    }

    /* default */ static PkiSession open(PkiSessionConfiguration configuration, Clock clock, Bootstrap bootstrap) {
        return open(configuration, PkiSessionRuntimeDependencies.none(), clock, bootstrap);
    }

    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.CloseResource" })
    /* default */ static PkiSession open(PkiSessionConfiguration configuration,
            PkiSessionRuntimeDependencies dependencies, Clock clock, Bootstrap bootstrap) {
        PkiSessionConfiguration exact = Objects.requireNonNull(configuration, "configuration");
        PkiSessionRuntimeDependencies runtime = Objects.requireNonNull(dependencies, "dependencies");
        Clock exactClock = Objects.requireNonNull(clock, "clock");
        Bootstrap exactBootstrap = Objects.requireNonNull(bootstrap, "bootstrap");
        KeyPossessionProofProviderComposition proofProviders =
                KeyPossessionProofProviderComposition.compose(runtime.keyPossessionProofProviders());
        proofProviders.validatePolicy(runtime.credentialConfirmationProofPolicy());
        exactBootstrap.validateStore(exact.store());
        exactBootstrap.validateAudit(exact.audit());
        exact.publishers().forEach(exactBootstrap::validatePublisher);
        exact.signing().ifPresent(value -> exactBootstrap.validateSigning(value.provider()));
        BindingComposition bindings = composeBindings(exact.bindingProviders());
        BcX509VerificationExecutor verification = new BcX509VerificationExecutor();
        X509AuthoritySnapshot authority = verificationAuthority(verification, bindings.providers());

        PkiStore store = null;
        AuditSink audit = null;
        ServiceGraph graph = ServiceGraph.empty();
        SigningGraph signingGraph = null;
        try {
            store = Objects.requireNonNull(exactBootstrap.openStore(exact.store(),
                    new PkiStoreRuntimeDependencies(exactClock)), "opened store");
            audit = runtime.auditSink().orElseGet(
                    () -> Objects.requireNonNull(exactBootstrap.openAudit(exact.audit()), "opened audit sink"));
            ProfileService profiles = new DefaultProfileService(store, exactClock, audit, bindings.registry(),
                    false, Optional.empty(), Optional.empty(), Optional.empty());
            RevocationService revocations = new DefaultRevocationService(store, exactClock, audit);
            graph = composeGraph(exact.publishers(), store, exactClock, exactBootstrap, authority, verification);
            signingGraph = composeSigning(exact, runtime, store, exactBootstrap, exactClock,
                    authority, verification, bindings);
            DefaultPkiSession session = new DefaultPkiSession(new DefaultPkiOperationExecutor.ConfigurationSummary(
                    exact.version(), exact.store().backendId(), exact.audit().backendId()), store, audit, profiles,
                    revocations, bindings.registry(), proofProviders,
                    runtime.credentialConfirmationProofPolicy(), exactClock, graph, signingGraph,
                    exact.signing().stream().flatMap(value -> value.topology().exactGroups().stream())
                            .flatMap(group -> group.keyRefs().stream()).toList(),
                    Optional.empty(), Optional.empty(), null, new AtomicReference<>(Lifecycle.OPEN));
            signingGraph.start();
            return session;
        } catch (RuntimeException | Error primary) {
            closeResource(signingGraph, primary);
            closeGraphAfterConstructionFailure(graph, primary);
            closeAfterConstructionFailure(audit, store, primary);
            throw primary;
        }
    }

    /* default */ static PkiSession openLocal(LocalPkiSessionConfiguration configuration,
            PkiSessionRuntimeDependencies dependencies, Clock clock) {
        return openLocal(configuration, dependencies, clock, ProductionBootstrap.INSTANCE);
    }

    /* default */ // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
                  @SuppressWarnings({ "PMD.AvoidCatchingGenericException" })
                  static PkiSession openLocal(LocalPkiSessionConfiguration configuration,
            PkiSessionRuntimeDependencies dependencies, Clock clock, Bootstrap bootstrap) {
        LocalPkiSessionConfiguration exact = Objects.requireNonNull(configuration, "configuration");
        PkiSessionRuntimeDependencies runtime = Objects.requireNonNull(dependencies, "dependencies");
        Clock exactClock = Objects.requireNonNull(clock, "clock");
        Bootstrap exactBootstrap = Objects.requireNonNull(bootstrap, "bootstrap");
        AtomicReference<Lifecycle> lifecycle = new AtomicReference<>(Lifecycle.OPEN);
        Runnable requireOpen = () -> {
            if (lifecycle.get() != Lifecycle.OPEN) { throw new IllegalStateException("PKI session is closed"); }
        };
        KeyPossessionProofProviderComposition proofProviders =
                KeyPossessionProofProviderComposition.compose(runtime.keyPossessionProofProviders());
        proofProviders.validatePolicy(runtime.credentialConfirmationProofPolicy());
        exactBootstrap.validateStore(exact.store());
        exactBootstrap.validateAudit(exact.audit());
        exact.publishers().forEach(exactBootstrap::validatePublisher);
        exact.signing().ifPresent(value -> exactBootstrap.validateSigning(value.provider()));
        BindingComposition bindings = composeBindings(exact.bindingProviders());
        BcX509VerificationExecutor verification = new BcX509VerificationExecutor();
        X509AuthoritySnapshot authority = verificationAuthority(verification, bindings.providers());
        PkiStore store = null;
        AuditSink audit = null;
        ServiceGraph graph = ServiceGraph.empty();
        SigningGraph signingGraph = null;
        try {
            store = Objects.requireNonNull(exactBootstrap.openStore(exact.store(),
                    new PkiStoreRuntimeDependencies(exactClock)), "opened store");
            audit = runtime.auditSink().orElseGet(
                    () -> Objects.requireNonNull(exactBootstrap.openAudit(exact.audit()), "opened audit sink"));
            ProfileService profiles = new DefaultProfileService(store, exactClock, audit, bindings.registry(),
                    false, Optional.empty(), Optional.empty(), Optional.empty());
            RevocationService revocations = new DefaultRevocationService(store, exactClock, audit);
            graph = composeGraph(exact.publishers(), store, exactClock, exactBootstrap, authority, verification);
            signingGraph = composeLocalSigning(exact.signing(), runtime, store, exactBootstrap, exactClock,
                    authority, verification, bindings, requireOpen);
            SigningOuterTerminalDriver driver = exact.signing().isEmpty() ? null : new SigningOuterTerminalDriver(
                    store, authority, verification, exact.signing().orElseThrow()
                            .resolvePureEdDsaMaximumTbsBytes(Runtime.getRuntime().maxMemory()));
            return new DefaultPkiSession(new DefaultPkiOperationExecutor.ConfigurationSummary(
                    LocalPkiSessionConfiguration.CURRENT_VERSION, exact.store().backendId(), exact.audit().backendId()),
                    store, audit, profiles, revocations, bindings.registry(), proofProviders,
                    runtime.credentialConfirmationProofPolicy(), exactClock, graph, signingGraph, List.of(),
                    exact.signing(), Optional.of(new zeroecho.pki.api.audit.Principal("LOCAL_OPERATOR", exact.operatorId())),
                    driver, lifecycle);
        } catch (RuntimeException | Error primary) {
            closeResource(signingGraph, primary);
            closeGraphAfterConstructionFailure(graph, primary);
            closeAfterConstructionFailure(audit, store, primary);
            throw primary;
        }
    }

    // Exceptional cleanup retains ownership and releases resources after failed validation or provider invocation.
    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.ExceptionAsFlowControl" })
    private static SigningGraph composeLocalSigning(Optional<LocalSigningConfiguration> configured,
            PkiSessionRuntimeDependencies runtime, PkiStore store, Bootstrap bootstrap, Clock clock,
            X509AuthoritySnapshot authority, BcX509VerificationExecutor verification,
            BindingComposition bindings, Runnable requireOpen) {
        if (configured.isEmpty()) { return SigningGraph.empty(); }
        LocalSigningConfiguration signing = configured.orElseThrow();
        SigningProviderRuntimeDependencies providerDependencies = runtime.keyringUnlockProvider()
                .map(SigningProviderRuntimeDependencies::withKeyringUnlockProvider)
                .orElseGet(SigningProviderRuntimeDependencies::none);
        PkiBootstrap.SigningComposition allocation = bootstrap.openSigningComposition(signing.provider(), providerDependencies);
        SigningProvider provider = allocation.provider();
        try {
            AlgorithmIdentity defaultSignature = authority.resolveIdentity(signing.signatureAlgorithm());
            X509AuthoritySnapshot signingAuthority = signingAuthority(allocation, bindings.providers());
            long pureEdDsaMaximum = signing.resolvePureEdDsaMaximumTbsBytes(Runtime.getRuntime().maxMemory());
            DefaultSigningService service = new DefaultSigningService(store, provider,
                    defaultSignature, signing.signingTtl(), new SecureRandom(), requireOpen,
                    (command, transferCustody) -> {
                        requireOpen.run();
                        transferCustody.run();
                        return store.acceptSign(command);
                    }, () -> { }, (operationId, cancellation) -> {
                        throw new UnsupportedOperationException("Local signing does not support bounded observation waits");
                    });
            DefaultSemanticSigningService semantic = composeSemantic(store, clock, authority, verification,
                    bindings, signing.signatureAlgorithm(), provider, signingAuthority, pureEdDsaMaximum, service);
            return new SigningGraph(Optional.of(service), Optional.of(semantic), Optional.empty(), provider, null);
        } catch (RuntimeException | Error primary) {
            closeResource(provider, primary);
            throw primary;
        }
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private static SigningGraph composeSigning(PkiSessionConfiguration configuration,
            PkiSessionRuntimeDependencies runtime, PkiStore store, Bootstrap bootstrap, Clock clock,
            X509AuthoritySnapshot authority, BcX509VerificationExecutor verification,
            BindingComposition bindings) {
        if (configuration.signing().isEmpty()) {
            return SigningGraph.empty();
        }
        PkiSessionConfiguration.SigningConfiguration signing = configuration.signing().orElseThrow();
        SigningProviderRuntimeDependencies providerDependencies = runtime.keyringUnlockProvider()
                .map(SigningProviderRuntimeDependencies::withKeyringUnlockProvider)
                .orElseGet(SigningProviderRuntimeDependencies::none);
        PkiBootstrap.SigningComposition allocation = bootstrap.openSigningComposition(signing.provider(), providerDependencies);
        SigningProvider provider = allocation.provider();
        try {
            AlgorithmIdentity defaultSignature = authority.resolveIdentity(signing.signatureAlgorithm());
            X509AuthoritySnapshot signingAuthority = signingAuthority(allocation, bindings.providers());
            long pureEdDsaMaximum = signing.resolvePureEdDsaMaximumTbsBytes(Runtime.getRuntime().maxMemory());
            SigningReactor reactor = new SigningReactor(store, provider,
                    signing.topology(), new SigningOuterTerminalDriver(store, authority, verification, pureEdDsaMaximum));
            DefaultSigningService service = new DefaultSigningService(store, provider,
                    defaultSignature, signing.signingTtl(), new SecureRandom(),
                    reactor::requireAccepting, reactor::acceptSign, reactor::wake, reactor::awaitBoundedObservation);
            DefaultSemanticSigningService semantic = composeSemantic(store, clock, authority, verification,
                    bindings, signing.signatureAlgorithm(), provider, signingAuthority, pureEdDsaMaximum, service);
            return new SigningGraph(Optional.of(service), Optional.of(semantic),
                    Optional.of(new DefaultOcspResponseService(store, service, provider, signingAuthority,
                            reactor::requireAccepting)), provider, reactor);
        } catch (RuntimeException | Error primary) {
            closeResource(provider, primary);
            throw primary;
        }
    }

    // Explicit collaborators or atomic persisted coordinates remain visible at this boundary.
    @SuppressWarnings("PMD.ExcessiveParameterList")
    private static DefaultSemanticSigningService composeSemantic(PkiStore store, Clock clock,
            X509AuthoritySnapshot authority, BcX509VerificationExecutor verification, BindingComposition bindings,
            String signatureAlgorithm, SigningProvider provider, X509AuthoritySnapshot signingAuthority,
            long pureEdDsaMaximum, DefaultSigningService service) {
        zeroecho.pki.impl.core.ManagedKeyProofPreparation proofPreparation = new zeroecho.pki.impl.core.ManagedKeyProofPreparation(
                store, provider, signingAuthority, authority, verification, signatureAlgorithm, new SecureRandom(), pureEdDsaMaximum);
        return new DefaultSemanticSigningService(store, service,
                new zeroecho.pki.impl.core.EndEntitySigningPreparation(store, clock, authority, verification,
                        bindings.registry(), signatureAlgorithm), pureEdDsaMaximum,
                Optional.of(new FullCrlSigningPreparation(store, clock, signingAuthority,
                        bindings.registry(), signatureAlgorithm)),
                Optional.of(proofPreparation),
                Optional.of(new zeroecho.pki.impl.core.IntermediateSigningPreparation(store, clock, provider,
                        signingAuthority, bindings.registry(), signatureAlgorithm, pureEdDsaMaximum, proofPreparation)),
                Optional.of(new zeroecho.pki.impl.core.RootSigningPreparation(store, clock, provider,
                        signingAuthority, bindings.registry(), signatureAlgorithm, pureEdDsaMaximum)));
    }

    /* default */ static X509AuthoritySnapshot signingAuthority(PkiBootstrap.SigningComposition allocation,
            List<X509BindingRuleProvider> bindingProviders) {
        List<AlgorithmExecutionCapability> capabilities = new ArrayList<>();
        List<X509AuthoritySnapshot.ExecutorBinding> executors = new ArrayList<>();
        for (AlgorithmExecutionCapability declared : allocation.capabilities()) {
            capabilities.add(new AlgorithmExecutionCapability() {
                @Override public String implementationId() { return declared.implementationId(); }
                @Override public String domainFingerprint() {
                    return "pki-session-sign-v2:declared-signature-suite:" + declared.domainFingerprint();
                }
                @Override public boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction direction) {
                    return direction == Direction.SIGN && identity.kind() == AlgorithmIdentity.Kind.SIGNATURE
                            && identity.equals(suite.signature())
                            && declared.supports(identity, suite, direction);
                }
            });
            executors.add(X509AuthoritySnapshot.bindExecutor(declared.implementationId(),
                    AlgorithmExecutionCapability.Direction.SIGN, allocation.provider()));
        }
        X509AlgorithmResolver.Policy policy = new X509AlgorithmResolver.Policy() {
            @Override public boolean permits(AlgorithmSuite suite, AlgorithmExecutionCapability.Direction direction) {
                return direction == AlgorithmExecutionCapability.Direction.SIGN
                        && suite.signature().kind() == AlgorithmIdentity.Kind.SIGNATURE;
            }
            @Override public String semanticFingerprint() { return "pki-session-sign-v2:declared-signature-suite"; }
        };
        return X509AuthoritySnapshot.compose(bindingProviders, List.of(() -> List.copyOf(capabilities)), executors, policy);
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private static ServiceGraph composeGraph(List<ProviderConfig> publishers, PkiStore store, Clock clock,
            Bootstrap bootstrap, X509AuthoritySnapshot authority, BcX509VerificationExecutor verification) {
        Optional<PublicationService> publications = Optional.empty();
        try {
            CertificationRequestService requests = new DefaultCertificationRequestService(store,
                    new BcX509CredentialFramework(authority, verification));
            List<Publisher> configuredPublishers = new ArrayList<>();
            for (ProviderConfig publisher : publishers) {
                configuredPublishers.add(bootstrap.openPublisher(publisher));
            }
            publications = configuredPublishers.isEmpty() ? Optional.empty()
                    : Optional.of(new DefaultPublicationService(store, clock, configuredPublishers));
            return new ServiceGraph(Optional.of(requests), publications,
                    configuredPublishers.stream().map(Publisher::target).toList());
        } catch (RuntimeException | Error primary) {
            closeResource(publications.orElse(null), primary);
            throw primary;
        }
    }

    private static X509AuthoritySnapshot verificationAuthority(BcX509VerificationExecutor verification,
            List<X509BindingRuleProvider> bindingProviders) {
        X509AlgorithmResolver.Policy policy = new X509AlgorithmResolver.Policy() {
            @Override
            public boolean permits(AlgorithmSuite suite,
                    AlgorithmExecutionCapability.Direction direction) {
                return direction == AlgorithmExecutionCapability.Direction.VERIFY;
            }

            @Override
            public String semanticFingerprint() {
                return "pki-session-verification-only-v1";
            }
        };
        return X509AuthoritySnapshot.compose(bindingProviders, List.of(verification),
                List.of(X509AuthoritySnapshot.bindExecutor(BcX509VerificationExecutor.IMPLEMENTATION_ID,
                        AlgorithmExecutionCapability.Direction.VERIFY, verification)), policy);
    }

    private static BindingComposition composeBindings(List<PkiSessionConfiguration.BindingProviderConfiguration> activations) {
        List<X509AlgorithmBindingProvider> discovered = ServiceLoader.load(X509AlgorithmBindingProvider.class)
                .stream().map(ServiceLoader.Provider::get)
                .sorted(Comparator.comparing(X509AlgorithmBindingProvider::providerId)).toList();
        Map<String, X509AlgorithmBindingProvider> byId = new LinkedHashMap<>();
        for (X509AlgorithmBindingProvider provider : discovered) {
            if (provider.providerId() == null || provider.providerId().isBlank()
                    || byId.putIfAbsent(provider.providerId(), provider) != null) {
                throw new IllegalArgumentException("Duplicate or invalid X.509 binding-provider identity");
            }
        }
        List<X509AlgorithmBinding> descriptors = new ArrayList<>(StandardX509Bindings.descriptors());
        descriptors.addAll(ZeroEchoPrivateX509Bindings.descriptors());
        List<X509BindingRuleProvider> ruleProviders = new ArrayList<>();
        for (PkiSessionConfiguration.BindingProviderConfiguration activation : activations) {
            X509AlgorithmBindingProvider provider = byId.get(activation.providerId());
            if (provider == null) {
                throw new IllegalArgumentException("Configured X.509 binding provider is unavailable");
            }
            activation.expectedBindingSetVersion().ifPresent(expected -> {
                if (!expected.equals(provider.bindingSetVersion())) {
                    throw new IllegalArgumentException("X.509 binding-provider version changed");
                }
            });
            List<X509AlgorithmBinding> additions = List.copyOf(provider.bindings());
            validateProviderBindings(provider, activation, additions);
            descriptors.addAll(additions);
            List<zeroecho.pki.impl.framework.x509.X509BindingRule> rules = List.copyOf(provider.rules());
            Set<String> descriptorIds = additions.stream().map(X509AlgorithmBinding::bindingId)
                    .collect(java.util.stream.Collectors.toUnmodifiableSet());
            Set<String> ruleIds = rules.stream().flatMap(rule -> rule.bindings().stream())
                    .map(X509AlgorithmBinding::bindingId)
                    .collect(java.util.stream.Collectors.toUnmodifiableSet());
            if (rules.isEmpty() || !ruleIds.equals(descriptorIds)) {
                throw new IllegalArgumentException("Deployer binding provider has inconsistent codecs");
            }
            ruleProviders.add(new X509BindingRuleProvider() {
                @Override
                public List<zeroecho.pki.impl.framework.x509.X509BindingRule> rules() {
                    return rules;
                }
            });
        }
        return new BindingComposition(ImmutableX509AlgorithmBindingRegistry.create(descriptors),
                List.copyOf(ruleProviders));
    }

    private static boolean authorizedRoot(String root, String oid) {
        boolean egothorDeployment = ImmutableX509AlgorithmBindingRegistry.isWithin(root,
                ImmutableX509AlgorithmBindingRegistry.ZEROECHO_DEPLOYMENT_ROOT)
                && !ImmutableX509AlgorithmBindingRegistry.ZEROECHO_DEPLOYMENT_ROOT.equals(root);
        boolean externalPen = root.matches("1\\.3\\.6\\.1\\.4\\.1\\.(?!31424(?:\\.|$))[0-9]+(?:\\.[0-9]+)*");
        return (egothorDeployment || externalPen)
                && ImmutableX509AlgorithmBindingRegistry.isWithin(oid, root);
    }

    @Override
    public ProfileService profiles() {
        requireOpen();
        return profiles;
    }

    @Override
    public CredentialConfirmationService confirmations() {
        requireOpen();
        return confirmations;
    }

    @Override
    public RevocationService revocations() {
        requireOpen();
        return revocations;
    }

    @Override
    public Optional<CertificationRequestService> requests() {
        requireOpen();
        return requests;
    }

    @Override
    public Optional<PublicationService> publications() {
        requireOpen();
        return publications;
    }

    @Override public Optional<SigningService> signing() {
        requireOpen();
        return signingGraph.service();
    }

    @Override public Optional<SemanticSigningService> semanticSigning() {
        requireOpen();
        return signingGraph.semanticService();
    }

    @Override public Optional<PkiSigningCommands> signingCommands() {
        requireOpen();
        return signingCommands;
    }

    @Override public Optional<LocalSigningExecutor> localSigning() {
        requireOpen();
        return localSigning;
    }

    @Override public Optional<OcspResponseService> ocsp() {
        requireOpen();
        return signingGraph.ocspService();
    }

    @Override
    public X509AlgorithmBindingRegistry algorithmBindings() {
        requireOpen();
        return algorithmBindings;
    }

    @Override
    public PkiResourceScopeResolver resourceScopes() {
        requireOpen();
        return resourceScopes;
    }

    @Override
    public PkiOperationExecutor operations() {
        requireOpen();
        return operations;
    }

    @Override
    public PkiRepository repository() {
        requireOpen();
        return repository;
    }

    @Override
    public boolean supportsSigningEvidenceFeed() {
        requireOpen();
        return store.supportsSigningEvidenceFeed();
    }

    @Override
    public zeroecho.pki.spi.store.AuditEvidenceFeed openSigningEvidenceFeed(long afterSequenceExclusive) {
        requireOpen();
        return store.openSigningEvidenceFeed(afterSequenceExclusive);
    }

    @Override
    public zeroecho.pki.spi.store.AuditEvidenceFeed openIssuanceEvidenceFeed(long afterSequenceExclusive) {
        requireOpen();
        return store.openIssuanceEvidenceFeed(afterSequenceExclusive);
    }

    @Override
    public zeroecho.pki.spi.store.AuditEvidenceFeed openStatusEvidenceFeed(long afterSequenceExclusive) {
        requireOpen();
        return store.openStatusEvidenceFeed(afterSequenceExclusive);
    }

    @Override
    public zeroecho.pki.spi.store.AuditEvidenceFeed openPublicationEvidenceFeed(long afterSequenceExclusive) {
        requireOpen();
        return store.openPublicationEvidenceFeed(afterSequenceExclusive);
    }

    @Override
    public void close() throws Exception {
        closeLock.lock();
        try {
            if (lifecycle.get() == Lifecycle.CLOSED) {
                return;
            }
            lifecycle.set(Lifecycle.QUIESCING);
            Throwable reactorFailure = signingGraph.closeReactor();
            if (reactorFailure != null) {
                rethrow(reactorFailure);
            }
            Throwable primary = closeResource(publications.orElse(null), null);
            primary = closeResource(signingGraph.provider(), primary);
            primary = closeResource(audit, primary);
            primary = closeResource(store, primary);
            lifecycle.set(Lifecycle.CLOSED);
            rethrow(primary);
        } finally {
            closeLock.unlock();
        }
    }

    private void requireOpen() {
        if (lifecycle.get() != Lifecycle.OPEN) {
            throw new IllegalStateException("PKI session is closed");
        }
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private static Throwable closeResource(AutoCloseable resource, Throwable primary) {
        if (resource == null) {
            return primary;
        }
        try {
            resource.close();
        } catch (Throwable failure) {
            if (primary == null) {
                return failure;
            }
            primary.addSuppressed(failure);
        }
        return primary;
    }

    private static void closeGraphAfterConstructionFailure(ServiceGraph graph, Throwable primary) {
        closeResource(graph.publications().orElse(null), primary);
    }

    private static void closeAfterConstructionFailure(AuditSink audit, PkiStore store, Throwable primary) {
        closeResource(store, closeResource(audit, primary));
    }

    @SuppressWarnings("PMD.SignatureDeclareThrowsException")
    private static void rethrow(Throwable failure) throws Exception {
        if (failure == null) {
            return;
        }
        if (failure instanceof Exception exception) {
            throw exception;
        }
        if (failure instanceof Error error) {
            throw error;
        }
        throw new IllegalStateException("PKI session close failed", failure);
    }

    /** Resource bootstrap seam used for deterministic lifecycle verification. */
    /* default */ interface Bootstrap {
        /** Validates store configuration without allocating a store. */
        void validateStore(ProviderConfig configuration);

        /** Validates audit configuration without allocating a sink. */
        void validateAudit(ProviderConfig configuration);

        /** Opens the configured store. */
        PkiStore openStore(ProviderConfig configuration);

        /** Opens the store with the session's authoritative clock. */
        default PkiStore openStore(ProviderConfig configuration, PkiStoreRuntimeDependencies dependencies) {
            Objects.requireNonNull(dependencies, "dependencies");
            return openStore(configuration);
        }

        /** Opens the configured audit sink. */
        AuditSink openAudit(ProviderConfig configuration);

        /** Validates a configured signing provider without allocation. */
        default void validateSigning(ProviderConfig configuration) {
            PkiBootstrap.validateSigningProviderConfiguration(configuration);
        }

        /** Opens one configured signing provider. */
        default SigningProvider openSigning(ProviderConfig configuration,
                SigningProviderRuntimeDependencies dependencies) {
            return PkiBootstrap.openConfiguredSigningProvider(configuration, dependencies);
        }

        /** Opens the exact provider with its allocating factory's contribution. */
        default PkiBootstrap.SigningComposition openSigningComposition(ProviderConfig configuration,
                SigningProviderRuntimeDependencies dependencies) {
            return new PkiBootstrap.SigningComposition(openSigning(configuration, dependencies), List.of());
        }

        /** Validates publisher configuration. */
        default void validatePublisher(ProviderConfig configuration) {
            PkiBootstrap.validatePublisherConfiguration(configuration);
        }

        /** Opens one configured publisher. */
        default Publisher openPublisher(ProviderConfig configuration) {
            return PkiBootstrap.openPublisher(configuration);
        }
    }

    private record ServiceGraph(Optional<CertificationRequestService> requests,
            Optional<PublicationService> publications, List<zeroecho.pki.api.publication.PublicationTarget> targets) {
        private ServiceGraph {
            requests = Objects.requireNonNull(requests, "requests");
            publications = Objects.requireNonNull(publications, "publications");
            targets = List.copyOf(targets);
        }

        private static ServiceGraph empty() {
            return new ServiceGraph(Optional.empty(), Optional.empty(), List.of());
        }
    }

    private record SigningGraph(Optional<SigningService> service,
            Optional<SemanticSigningService> semanticService, Optional<OcspResponseService> ocspService,
            SigningProvider provider, SigningReactor reactor) implements AutoCloseable {
        private SigningGraph {
            service = Objects.requireNonNull(service, "service");
            semanticService = Objects.requireNonNull(semanticService, "semanticService");
            ocspService = Objects.requireNonNull(ocspService, "ocspService");
            if (service.isPresent() != semanticService.isPresent()
                    || service.isPresent() != (provider != null)
                    || ocspService.isPresent() != (reactor != null)
                    || reactor != null && service.isEmpty()) {
                throw new IllegalArgumentException("Signing graph is incomplete");
            }
        }

        private static SigningGraph empty() {
            return new SigningGraph(Optional.empty(), Optional.empty(), Optional.empty(), null, null);
        }

        private void start() {
            if (reactor != null) {
                reactor.start();
            }
        }

        private Throwable closeReactor() {
            return closeResource(reactor, null);
        }

        @Override public void close() {
            Throwable primary = closeResource(reactor, null);
            primary = closeResource(provider, primary);
            if (primary instanceof RuntimeException runtime) {
                throw runtime;
            }
            if (primary != null) {
                throw new IllegalStateException("Signing graph close failed", primary);
            }
        }
    }

    private record BindingComposition(X509AlgorithmBindingRegistry registry,
            List<X509BindingRuleProvider> providers) {
        private BindingComposition {
            Objects.requireNonNull(registry, "registry");
            providers = List.copyOf(providers);
        }
    }

    /** Session-owned resource lifecycle. */
    private enum Lifecycle {
        OPEN,
        QUIESCING,
        CLOSED
    }

    /** Production service-loader bootstrap. */
    private enum ProductionBootstrap implements Bootstrap {
        INSTANCE;

        @Override
        public void validateStore(ProviderConfig configuration) {
            PkiBootstrap.validateStoreConfiguration(configuration);
        }

        @Override
        public void validateAudit(ProviderConfig configuration) {
            PkiBootstrap.validateAuditConfiguration(configuration);
        }

        @Override
        public PkiStore openStore(ProviderConfig configuration) {
            return PkiBootstrap.openStore(configuration);
        }

        @Override
        public PkiStore openStore(ProviderConfig configuration, PkiStoreRuntimeDependencies dependencies) {
            return PkiBootstrap.openStore(configuration, dependencies);
        }

        @Override
        public AuditSink openAudit(ProviderConfig configuration) {
            return PkiBootstrap.openAudit(configuration);
        }

        @Override public void validateSigning(ProviderConfig configuration) {
            PkiBootstrap.validateSigningProviderConfiguration(configuration);
        }

        @Override public SigningProvider openSigning(ProviderConfig configuration,
                SigningProviderRuntimeDependencies dependencies) {
            return PkiBootstrap.openConfiguredSigningProvider(configuration, dependencies);
        }

        @Override public PkiBootstrap.SigningComposition openSigningComposition(ProviderConfig configuration,
                SigningProviderRuntimeDependencies dependencies) {
            return PkiBootstrap.openConfiguredSigningComposition(configuration, dependencies);
        }
    }

    private static void validateProviderBindings(X509AlgorithmBindingProvider provider,
            PkiSessionConfiguration.BindingProviderConfiguration activation, List<X509AlgorithmBinding> additions) {
        for (X509AlgorithmBinding binding : additions) {
            if (binding.origin() != X509AlgorithmBinding.Origin.DEPLOYER_PRIVATE
                    || !binding.providerId().orElse("").equals(provider.providerId())
                    || BootstrapAlgorithmIdentities.catalog()
                            .resolve(binding.algorithmIdentity().canonicalForm()).isEmpty()
                    || activation.authorizedOidRoots().stream()
                            .noneMatch(root -> authorizedRoot(root, binding.oid()))) {
                throw new IllegalArgumentException("Unauthorized deployer X.509 binding");
            }
        }
    }
}
