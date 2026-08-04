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
package zeroecho.pki.application;

import java.nio.file.Path;
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
import java.util.concurrent.atomic.AtomicBoolean;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.core.spi.AlgorithmExecutionCapabilityProvider;
import zeroecho.core.spi.KeyringUnlockProvider;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.pki.api.CaService;
import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.IssuanceService;
import zeroecho.pki.api.PublicationService;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.StatusObjectService;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.impl.core.DefaultProfileService;
import zeroecho.pki.impl.core.DefaultRevocationService;
import zeroecho.pki.impl.core.DefaultCaService;
import zeroecho.pki.impl.core.DefaultCertificationRequestService;
import zeroecho.pki.impl.core.DefaultIssuanceService;
import zeroecho.pki.impl.core.DefaultPublicationService;
import zeroecho.pki.impl.core.DefaultStatusObjectService;
import zeroecho.pki.impl.core.StoreBackedEffectiveCredentialStatusResolver;
import zeroecho.pki.impl.core.PublicKeyInfoResolver;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.impl.framework.x509.X509AlgorithmResolver;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.ImmutableX509AlgorithmBindingRegistry;
import zeroecho.pki.impl.framework.x509.StandardX509Bindings;
import zeroecho.pki.impl.framework.x509.ZeroEchoPrivateX509Bindings;
import zeroecho.pki.impl.framework.x509.X509BindingRuleProvider;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialIssuerBackend;
import zeroecho.pki.impl.framework.x509.bc.BcX509ProofOfPossessionVerifier;
import zeroecho.pki.impl.framework.x509.bc.BcX509PublicKeyAdapter;
import zeroecho.pki.impl.framework.x509.bc.BcX509StatusObjectGenerator;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.algorithm.X509AlgorithmBindingProvider;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.crypto.SignatureWorkflowRuntimeDependencies;
import zeroecho.pki.spi.publish.Publisher;
import zeroecho.pki.spi.store.PkiStore;

/** Default synchronous session composition. */
@SuppressWarnings({ "PMD.CouplingBetweenObjects", "PMD.CyclomaticComplexity" })
final class DefaultPkiSession implements PkiSession {

    private final PkiStore store;
    private final AuditSink audit;
    private final ProfileService profiles;
    private final RevocationService revocations;
    private final Optional<CaService> authorities;
    private final Optional<CertificationRequestService> requests;
    private final Optional<IssuanceService> issuance;
    private final Optional<StatusObjectService> statusObjects;
    private final Optional<PublicationService> publications;
    private final Optional<PkiSigningBus> signingBus;
    private final Optional<SignatureWorkflow> signatureWorkflow;
    private final X509AlgorithmBindingRegistry algorithmBindings;
    private final PkiResourceScopeResolver resourceScopes;
    private final PkiOperationExecutor operations;
    private final AtomicBoolean closed = new AtomicBoolean();

    private DefaultPkiSession(PkiSessionConfiguration configuration, PkiStore store, AuditSink audit,
            ProfileService profiles, RevocationService revocations, X509AlgorithmBindingRegistry algorithmBindings,
            ServiceGraph graph) {
        this.store = store;
        this.audit = audit;
        this.profiles = Objects.requireNonNull(profiles, "profiles");
        this.revocations = Objects.requireNonNull(revocations, "revocations");
        this.authorities = graph.authorities();
        this.requests = graph.requests();
        this.issuance = graph.issuance();
        this.statusObjects = graph.statusObjects();
        this.publications = graph.publications();
        this.signingBus = graph.signingBus();
        this.signatureWorkflow = graph.signatureWorkflow();
        this.algorithmBindings = Objects.requireNonNull(algorithmBindings, "algorithmBindings");
        this.resourceScopes = new DefaultPkiResourceScopeResolver(store, this::requireOpen);
        this.operations = new DefaultPkiOperationExecutor(configuration, store, profiles, revocations, authorities,
                requests, issuance, statusObjects, publications, algorithmBindings, this::requireOpen);
    }

    /* default */ static PkiSession open(PkiSessionConfiguration configuration) {
        return open(configuration, runtimeDependencies(configuration), Clock.systemUTC(), ProductionBootstrap.INSTANCE);
    }

    /* default */ static PkiSession open(PkiSessionConfiguration configuration,
            PkiSessionRuntimeDependencies dependencies) {
        return open(configuration, dependencies, Clock.systemUTC(), ProductionBootstrap.INSTANCE);
    }

    /* default */ static PkiSession open(PkiSessionConfiguration configuration, Clock clock, Bootstrap bootstrap) {
        return open(configuration, PkiSessionRuntimeDependencies.none(), clock, bootstrap);
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    /* default */ static PkiSession open(PkiSessionConfiguration configuration,
            PkiSessionRuntimeDependencies dependencies, Clock clock, Bootstrap bootstrap) {
        PkiSessionConfiguration exact = Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(bootstrap, "bootstrap");
        Objects.requireNonNull(dependencies, "dependencies");
        bootstrap.validateStore(exact.store());
        bootstrap.validateAudit(exact.audit());
        exact.signing().ifPresent(signing -> {
            bootstrap.validateSignatureWorkflow(signing.workflow());
            bootstrap.validateCredentialFramework(signing.framework());
            if (!"x509-bc".equals(signing.framework().backendId())) {
                throw new IllegalArgumentException("Configured framework cannot compose the X.509 service graph");
            }
        });
        exact.publishers().forEach(bootstrap::validatePublisher);
        BindingComposition bindingComposition = composeBindings(exact);
        X509AlgorithmBindingRegistry algorithmBindings = bindingComposition.registry();
        exact.signing().ifPresent(signing -> validateConfiguredBindings(signing, algorithmBindings));

        PkiStore store = null;
        AuditSink audit = null;
        ServiceGraph graph = ServiceGraph.empty();
        try {
            store = Objects.requireNonNull(bootstrap.openStore(exact.store()), "opened store");
            audit = dependencies.auditSink().orElseGet(
                    () -> Objects.requireNonNull(bootstrap.openAudit(exact.audit()), "opened audit sink"));
            ProfileService profiles = new DefaultProfileService(store, clock, audit, algorithmBindings,
                    exact.signing().isPresent(),
                    exact.signing().flatMap(PkiSessionConfiguration.SigningConfiguration::certificateSignatureBinding),
                    exact.signing().flatMap(PkiSessionConfiguration.SigningConfiguration::crlSignatureBinding),
                    exact.signing().flatMap(PkiSessionConfiguration.SigningConfiguration::subjectPublicKeyBinding));
            RevocationService revocations = new DefaultRevocationService(store, clock, audit);
            graph = composeGraph(exact, dependencies, store, audit, profiles, clock, bootstrap,
                    bindingComposition.providers());
            return new DefaultPkiSession(exact, store, audit, profiles, revocations, algorithmBindings, graph);
        } catch (RuntimeException | Error primary) {
            closeGraphAfterConstructionFailure(graph, primary);
            closeAfterConstructionFailure(audit, store, primary);
            throw primary;
        }
    }

    @Override
    public ProfileService profiles() {
        requireOpen();
        return profiles;
    }

    @Override
    public RevocationService revocations() {
        requireOpen();
        return revocations;
    }

    @Override
    public Optional<CaService> authorities() {
        requireOpen();
        return authorities;
    }

    @Override
    public Optional<CertificationRequestService> requests() {
        requireOpen();
        return requests;
    }

    @Override
    public Optional<IssuanceService> issuance() {
        requireOpen();
        return issuance;
    }

    @Override
    public Optional<StatusObjectService> statusObjects() {
        requireOpen();
        return statusObjects;
    }

    @Override
    public Optional<PublicationService> publications() {
        requireOpen();
        return publications;
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
    public void close() throws Exception {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        Throwable primary = null;
        primary = closeResource(publications.orElse(null), primary);
        primary = closeResource(signingBus.orElse(null), primary);
        primary = closeResource(signatureWorkflow.orElse(null), primary);
        try {
            audit.close();
        } catch (Throwable failure) { // NOPMD - preserve Error and checked close failures.
            primary = failure;
        }
        try {
            store.close();
        } catch (Throwable failure) { // NOPMD - preserve Error and checked close failures.
            if (primary == null) {
                primary = failure;
            } else {
                primary.addSuppressed(failure);
            }
        }
        rethrow(primary);
    }

    private void requireOpen() {
        if (closed.get()) {
            throw new IllegalStateException("PKI session is closed");
        }
    }

    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.CloseResource", "PMD.ExceptionAsFlowControl" })
    private static ServiceGraph composeGraph(PkiSessionConfiguration configuration,
            PkiSessionRuntimeDependencies dependencies, PkiStore store, AuditSink audit, ProfileService profiles,
            Clock clock, Bootstrap bootstrap, List<X509BindingRuleProvider> bindingProviders) {
        Optional<SignatureWorkflow> workflow = Optional.empty();
        Optional<PkiSigningBus> bus = Optional.empty();
        Optional<CaService> authorities = Optional.empty();
        Optional<CertificationRequestService> requests = Optional.empty();
        Optional<IssuanceService> issuance = Optional.empty();
        Optional<StatusObjectService> statuses = Optional.empty();
        Optional<PublicationService> publications = Optional.empty();
        try {
            if (configuration.signing().isPresent()) {
                PkiSessionConfiguration.SigningConfiguration signing = configuration.signing().orElseThrow();
                KeyringUnlockProvider unlock = dependencies.keyringUnlockProvider().orElseThrow(
                        () -> new IllegalStateException("Configured signing requires key-unlock capability"));
                SignatureWorkflow openedWorkflow = bootstrap.openSignatureWorkflow(signing.workflow(),
                        SignatureWorkflowRuntimeDependencies.withKeyringUnlockProvider(unlock));
                workflow = Optional.of(openedWorkflow);
                if (!(openedWorkflow instanceof PublicKeyInfoSource publicKeys)) {
                    throw new IllegalStateException("Signature workflow lacks managed public-key capability");
                }
                BcX509VerificationExecutor verification = new BcX509VerificationExecutor();
                X509AuthoritySnapshot authority = authority(openedWorkflow, verification, bindingProviders);
                PkiSigningBus openedBus = new PkiSigningBus(store, openedWorkflow, Path.of(signing.busPath()),
                        authority);
                bus = Optional.of(openedBus);
                AlgorithmIdentity signatureIdentity = authority.resolveIdentity(signing.signatureAlgorithm());
                BcX509CredentialIssuerBackend issuerBackend = new BcX509CredentialIssuerBackend(openedBus,
                        signatureIdentity, signing.certificateSignatureBinding(), signing.signingTtl());
                BcX509StatusObjectGenerator statusGenerator = new BcX509StatusObjectGenerator(openedBus,
                        signatureIdentity, signing.crlSignatureBinding(), signing.signingTtl());
                BcX509CredentialFramework framework = new BcX509CredentialFramework(authority, verification)
                        .wired(statusGenerator, new BcX509ProofOfPossessionVerifier(authority, verification));
                EffectiveCredentialStatusResolver statusResolver = new StoreBackedEffectiveCredentialStatusResolver(
                        store, clock);
                requests = Optional.of(new DefaultCertificationRequestService(store, framework));
                issuance = Optional.of(new DefaultIssuanceService(store, framework, issuerBackend, audit,
                        statusResolver, profiles, clock));
                statuses = Optional.of(new DefaultStatusObjectService(store, framework, audit, statusResolver,
                        authority));
                authorities = Optional.of(new DefaultCaService(store, framework, issuerBackend,
                        publicKeySource(publicKeys, authority, signing), openedBus, audit, statusResolver, profiles, clock,
                        signing.signatureAlgorithm(), signing.certificateSignatureBinding(), signing.signingTtl()));
            }
            List<Publisher> configuredPublishers = new ArrayList<>();
            for (ProviderConfig publisher : configuration.publishers()) {
                configuredPublishers.add(bootstrap.openPublisher(publisher));
            }
            publications = configuredPublishers.isEmpty() ? Optional.empty()
                    : Optional.of(new DefaultPublicationService(store, clock, configuredPublishers));
            return new ServiceGraph(authorities, requests, issuance, statuses, publications, bus, workflow);
        } catch (RuntimeException | Error primary) {
            Throwable cleanup = closeResource(publications.orElse(null), primary);
            cleanup = closeResource(bus.orElse(null), cleanup);
            closeResource(workflow.orElse(null), cleanup);
            throw primary;
        }
    }

    private static X509AuthoritySnapshot authority(SignatureWorkflow workflow,
            BcX509VerificationExecutor verification, List<X509BindingRuleProvider> bindingProviders) {
        Set<String> supported = Set.copyOf(workflow.supportedAlgorithms());
        Set<AlgorithmIdentity> identities = BootstrapAlgorithmIdentities.catalog().identities().stream()
                .filter(identity -> identity.kind() == AlgorithmIdentity.Kind.SIGNATURE)
                .filter(identity -> supported.contains(identity.canonicalForm())
                        || BootstrapAlgorithmIdentities.compatibilityAliases().entrySet().stream()
                                .anyMatch(entry -> entry.getValue().equals(identity) && supported.contains(entry.getKey())))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        String implementationId = "workflow." + workflow.id();
        AlgorithmExecutionCapability signing = new AlgorithmExecutionCapability() {
            @Override
            public String implementationId() {
                return implementationId;
            }

            @Override
            public String domainFingerprint() {
                return "session-signing-v1:" + workflow.id() + ":" + identities.stream()
                        .map(AlgorithmIdentity::canonicalForm).sorted().reduce("", String::concat);
            }

            @Override
            public boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction direction) {
                return direction == Direction.SIGN && identities.contains(identity) && identity.equals(suite.signature());
            }
        };
        AlgorithmExecutionCapabilityProvider signingProvider = () -> List.of(signing);
        X509AlgorithmResolver.Policy policy = new X509AlgorithmResolver.Policy() {
            @Override
            public boolean permits(AlgorithmSuite suite, AlgorithmExecutionCapability.Direction direction) {
                return true;
            }

            @Override
            public String semanticFingerprint() {
                return "pki-session-bootstrap-policy-v1:configured-capabilities-only";
            }
        };
        return X509AuthoritySnapshot.compose(bindingProviders, List.of(signingProvider, verification),
                List.of(X509AuthoritySnapshot.bindExecutor(implementationId,
                                AlgorithmExecutionCapability.Direction.SIGN, workflow),
                        X509AuthoritySnapshot.bindExecutor(BcX509VerificationExecutor.IMPLEMENTATION_ID,
                                AlgorithmExecutionCapability.Direction.VERIFY, verification)), policy);
    }

    private static BindingComposition composeBindings(PkiSessionConfiguration configuration) {
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
        for (PkiSessionConfiguration.BindingProviderConfiguration activation : configuration.bindingProviders()) {
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
            descriptors.addAll(additions);
            List<zeroecho.pki.impl.framework.x509.X509BindingRule> rules = List.copyOf(provider.rules());
            Set<String> descriptorIds = additions.stream().map(X509AlgorithmBinding::bindingId)
                    .collect(java.util.stream.Collectors.toUnmodifiableSet());
            Set<String> ruleIds = rules.stream().flatMap(rule -> rule.bindings().stream())
                    .map(X509AlgorithmBinding::bindingId).collect(java.util.stream.Collectors.toUnmodifiableSet());
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

    private static void validateConfiguredBindings(PkiSessionConfiguration.SigningConfiguration signing,
            X509AlgorithmBindingRegistry registry) {
        if (signing.certificateSignatureBinding().isEmpty() && signing.crlSignatureBinding().isEmpty()
                && signing.subjectPublicKeyBinding().isEmpty()) {
            return;
        }
        AlgorithmIdentity identity = BootstrapAlgorithmIdentities.resolve(signing.signatureAlgorithm())
                .orElseThrow(() -> new IllegalArgumentException("Configured signature identity is unknown"));
        validateConfiguredBinding(registry, signing.certificateSignatureBinding(), identity,
                X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE);
        validateConfiguredBinding(registry, signing.crlSignatureBinding(), identity,
                X509AlgorithmBinding.Role.CRL_SIGNATURE);
        validateConfiguredBinding(registry, signing.subjectPublicKeyBinding(),
                BootstrapAlgorithmIdentities.SPHINCS_PLUS_SIGNATURE.equals(identity)
                        ? BootstrapAlgorithmIdentities.SPHINCS_PLUS_PUBLIC_KEY
                        : bootstrapPublicKey(identity), X509AlgorithmBinding.Role.SUBJECT_PUBLIC_KEY);
        boolean privateAlgorithm = identity.equals(BootstrapAlgorithmIdentities.SPHINCS_PLUS_SIGNATURE);
        if (privateAlgorithm && (signing.certificateSignatureBinding().isEmpty()
                || signing.crlSignatureBinding().isEmpty() || signing.subjectPublicKeyBinding().isEmpty())) {
            throw new IllegalArgumentException("Private X.509 signature identity requires explicit bindings");
        }
    }

    private static AlgorithmIdentity bootstrapPublicKey(AlgorithmIdentity signature) {
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
        return BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY;
    }

    @SuppressWarnings("PMD.PreserveStackTrace")
    private static PublicKeyInfoResolver publicKeySource(PublicKeyInfoSource source, X509AuthoritySnapshot authority,
            PkiSessionConfiguration.SigningConfiguration signing) {
        if (signing.subjectPublicKeyBinding().isEmpty()) {
            return source::resolvePublicKeyInfo;
        }
        return keyRef -> {
            EncodedObject nativeKey = source.resolvePublicKeyInfo(keyRef);
            if (nativeKey.encoding() != Encoding.DER) {
                throw new PkiException("Managed public key is not canonical DER: code=PUBLIC_KEY_ENCODING_INVALID");
            }
            try {
                byte[] wrapped = new BcX509PublicKeyAdapter(authority.bindings())
                        .wrap(nativeKey.bytes(), BootstrapAlgorithmIdentities.SPHINCS_PLUS_PUBLIC_KEY,
                                signing.subjectPublicKeyBinding().orElseThrow())
                        .getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER);
                return new EncodedObject(Encoding.DER, wrapped);
            } catch (java.io.IOException | IllegalArgumentException failure) {
                throw new PkiException("Managed public key binding failed: code=PUBLIC_KEY_BINDING_FAILED");
            }
        };
    }

    private static void validateConfiguredBinding(X509AlgorithmBindingRegistry registry,
            Optional<String> bindingId, AlgorithmIdentity identity, X509AlgorithmBinding.Role role) {
        bindingId.ifPresent(value -> {
            X509AlgorithmBinding binding = registry.find(value)
                    .orElseThrow(() -> new IllegalArgumentException("Configured X.509 binding is inactive"));
            if (binding.role() != role || !binding.algorithmIdentity().equals(identity)) {
                throw new IllegalArgumentException("Configured X.509 binding does not match the signing role");
            }
        });
    }

    private static boolean authorizedRoot(String root, String oid) {
        boolean egothorDeployment = ImmutableX509AlgorithmBindingRegistry.isWithin(root,
                ImmutableX509AlgorithmBindingRegistry.ZEROECHO_DEPLOYMENT_ROOT)
                && !ImmutableX509AlgorithmBindingRegistry.ZEROECHO_DEPLOYMENT_ROOT.equals(root);
        boolean externalPen = root.matches("1\\.3\\.6\\.1\\.4\\.1\\.(?!31424(?:\\.|$))[0-9]+(?:\\.[0-9]+)*");
        return (egothorDeployment || externalPen)
                && ImmutableX509AlgorithmBindingRegistry.isWithin(oid, root);
    }

    private static PkiSessionRuntimeDependencies runtimeDependencies(PkiSessionConfiguration configuration) {
        Optional<String> environment = configuration.signing()
                .flatMap(PkiSessionConfiguration.SigningConfiguration::unlockEnvironmentVariable);
        if (environment.isEmpty()) {
            return PkiSessionRuntimeDependencies.none();
        }
        KeyringUnlockProvider provider = () -> {
            String value = System.getenv(environment.orElseThrow());
            if (value == null || value.isEmpty()) {
                throw new java.io.IOException("Configured key-unlock source is unavailable");
            }
            char[] password = value.toCharArray();
            try {
                return new KeyringPassword(password);
            } finally {
                java.util.Arrays.fill(password, '\0');
            }
        };
        return PkiSessionRuntimeDependencies.withKeyringUnlockProvider(provider);
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
        Throwable ignored = closeResource(graph.publications().orElse(null), primary);
        ignored = closeResource(graph.signingBus().orElse(null), ignored);
        closeResource(graph.signatureWorkflow().orElse(null), ignored);
    }

    private static void closeAfterConstructionFailure(AuditSink audit, PkiStore store, Throwable primary) {
        if (audit != null) {
            try {
                audit.close();
            } catch (Throwable failure) { // NOPMD - construction failure remains primary.
                primary.addSuppressed(failure);
            }
        }
        if (store != null) {
            try {
                store.close();
            } catch (Throwable failure) { // NOPMD - construction failure remains primary.
                primary.addSuppressed(failure);
            }
        }
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

        /** Opens the configured audit sink. */
        AuditSink openAudit(ProviderConfig configuration);

        /** Validates signing-workflow configuration. */
        default void validateSignatureWorkflow(ProviderConfig configuration) {
            PkiBootstrap.validateSignatureWorkflowConfiguration(configuration);
        }

        /** Validates credential-framework configuration. */
        default void validateCredentialFramework(ProviderConfig configuration) {
            PkiBootstrap.validateCredentialFrameworkConfiguration(configuration);
        }

        /** Validates publisher configuration. */
        default void validatePublisher(ProviderConfig configuration) {
            PkiBootstrap.validatePublisherConfiguration(configuration);
        }

        /** Opens the configured signature workflow. */
        default SignatureWorkflow openSignatureWorkflow(ProviderConfig configuration,
                SignatureWorkflowRuntimeDependencies dependencies) {
            return PkiBootstrap.openConfiguredSignatureWorkflow(configuration, dependencies);
        }

        /** Opens one configured publisher. */
        default Publisher openPublisher(ProviderConfig configuration) {
            return PkiBootstrap.openPublisher(configuration);
        }
    }

    private record ServiceGraph(Optional<CaService> authorities, Optional<CertificationRequestService> requests,
            Optional<IssuanceService> issuance, Optional<StatusObjectService> statusObjects,
            Optional<PublicationService> publications, Optional<PkiSigningBus> signingBus,
            Optional<SignatureWorkflow> signatureWorkflow) {
        private static ServiceGraph empty() {
            return new ServiceGraph(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                    Optional.empty(), Optional.empty(), Optional.empty());
        }
    }

    private record BindingComposition(X509AlgorithmBindingRegistry registry,
            List<X509BindingRuleProvider> providers) {
        private BindingComposition {
            Objects.requireNonNull(registry, "registry");
            providers = List.copyOf(providers);
        }
    }

    /** Production provider bootstrap implementation. */
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
        public AuditSink openAudit(ProviderConfig configuration) {
            return PkiBootstrap.openAudit(configuration);
        }
    }
}
