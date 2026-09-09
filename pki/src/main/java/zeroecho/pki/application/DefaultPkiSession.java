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
import zeroecho.pki.api.confirmation.CredentialConfirmationService;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.impl.core.DefaultProfileService;
import zeroecho.pki.impl.core.DefaultRevocationService;
import zeroecho.pki.impl.core.DefaultCaService;
import zeroecho.pki.impl.core.DefaultCertificationRequestService;
import zeroecho.pki.impl.core.DefaultCredentialConfirmationService;
import zeroecho.pki.impl.core.DefaultIssuanceService;
import zeroecho.pki.impl.core.DefaultPublicationService;
import zeroecho.pki.impl.core.DefaultStatusObjectService;
import zeroecho.pki.impl.core.StoreBackedEffectiveCredentialStatusResolver;
import zeroecho.pki.impl.core.PublicKeyInfoResolver;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.impl.core.async.SigningExecutionRuntime;
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
import zeroecho.pki.spi.store.PkiStoreRuntimeDependencies;
import zeroecho.pki.spi.store.DomainContinuationStore;

/** Default synchronous session composition. */
@SuppressWarnings({ "PMD.CouplingBetweenObjects", "PMD.CyclomaticComplexity", "PMD.TooManyMethods" })
final class DefaultPkiSession implements PkiSession {

    private static final String SIGNING_OPERATION_NAME = "signing.operation";
    private static final String CREATE_ROOT = "CREATE_ROOT";
    private static final String CREATE_INTERMEDIATE = "CREATE_INTERMEDIATE";
    private static final String ISSUE_INTERMEDIATE = "ISSUE_INTERMEDIATE";

    private final PkiStore store;
    private final AuditSink audit;
    private final ProfileService profiles;
    private final CredentialConfirmationService confirmations;
    private final RevocationService revocations;
    private final Optional<CaService> authorities;
    private final Optional<CertificationRequestService> requests;
    private final Optional<IssuanceService> issuance;
    private final Optional<StatusObjectService> statusObjects;
    private final Optional<OcspResponseService> ocsp;
    private final Optional<PublicationService> publications;
    private final Optional<PkiSigningBus> signingBus;
    private final List<SignatureWorkflow> signatureWorkflows;
    private final Optional<SigningExecutionRuntime> signingRuntime;
    private final X509AlgorithmBindingRegistry algorithmBindings;
    private final PkiResourceScopeResolver resourceScopes;
    private final PkiOperationExecutor operations;
    private final PkiRepository repository;
    private final AtomicReference<Lifecycle> lifecycle = new AtomicReference<>(Lifecycle.OPEN);
    private final ReentrantLock closeLock = new ReentrantLock();

    private DefaultPkiSession(PkiSessionConfiguration configuration, PkiStore store, AuditSink audit,
            ProfileService profiles, RevocationService revocations, X509AlgorithmBindingRegistry algorithmBindings,
            KeyPossessionProofProviderComposition proofProviders,
            Optional<CredentialConfirmationProofRuntimePolicy> proofPolicy, Clock clock, ServiceGraph graph) {
        this.store = store;
        this.audit = audit;
        this.profiles = Objects.requireNonNull(profiles, "profiles");
        this.confirmations = new DefaultCredentialConfirmationService(store, this::requireOpen,
                proofProviders.providersBySuiteId(), proofPolicy, new SecureRandom(),
                Optional.of(audit), clock);
        this.revocations = Objects.requireNonNull(revocations, "revocations");
        this.authorities = graph.authorities();
        this.requests = graph.requests();
        this.issuance = graph.issuance();
        this.statusObjects = graph.statusObjects();
        this.ocsp = graph.signingBus().map(bus -> new DefaultOcspResponseService(store, bus,
                configuration.signing().orElseThrow().signingTtl(), this::requireOpen));
        this.publications = graph.publications();
        this.signingBus = graph.signingBus();
        this.signatureWorkflows = graph.signatureWorkflows();
        this.signingRuntime = graph.signingRuntime();
        this.algorithmBindings = Objects.requireNonNull(algorithmBindings, "algorithmBindings");
        this.resourceScopes = new DefaultPkiResourceScopeResolver(store, this::requireOpen);
        this.repository = new DefaultPkiRepository(store, this::requireOpen);
        this.operations = new DefaultPkiOperationExecutor(configuration, store, profiles, revocations, authorities,
                requests, issuance, statusObjects, publications, Optional.of(confirmations),
                algorithmBindings, this::requireOpen);
    }

    @Override
    public PkiRepository repository() {
        requireOpen();
        return repository;
    }

    @Override
    public PkiOperationOutcome signingOperation(zeroecho.pki.api.PkiId operationId) {
        requireOpen();
        zeroecho.pki.api.PkiId exact = Objects.requireNonNull(operationId, "operationId");
        Optional<DomainContinuationStore.Record> continuation = store.getDomainContinuation(exact);
        if (continuation.isEmpty()) {
            return new PkiOperationOutcome.Failed(SIGNING_OPERATION_NAME, PkiOperationFailure.NOT_FOUND,
                    "OBJECT_NOT_FOUND");
        }
        return signingOperation(continuation.orElseThrow());
    }

    @Override
    public PkiOperationOutcome signingOperation(String correlationId) {
        requireOpen();
        if (correlationId == null || correlationId.isBlank()) {
            throw new IllegalArgumentException("correlationId must not be blank");
        }
        Optional<DomainContinuationStore.Record> match = Optional.empty();
        for (DomainContinuationStore.Kind kind : DomainContinuationStore.Kind.values()) {
            Optional<DomainContinuationStore.Record> candidate = store.getDomainContinuation(kind, correlationId);
            if (candidate.isPresent()) {
                if (match.isPresent()) {
                    throw new IllegalStateException("Domain correlation identity is ambiguous");
                }
                match = candidate;
            }
        }
        if (match.isEmpty()) {
            return new PkiOperationOutcome.Failed(SIGNING_OPERATION_NAME, PkiOperationFailure.NOT_FOUND,
                    "OBJECT_NOT_FOUND");
        }
        return signingOperation(match.orElseThrow());
    }

    @Override
    public Optional<zeroecho.pki.api.PkiId> signingOperationId(String correlationId) {
        requireOpen();
        if (correlationId == null || correlationId.isBlank()) {
            throw new IllegalArgumentException("correlationId must not be blank");
        }
        Optional<zeroecho.pki.api.PkiId> match = Optional.empty();
        for (DomainContinuationStore.Kind kind : DomainContinuationStore.Kind.values()) {
            Optional<DomainContinuationStore.Record> candidate = store.getDomainContinuation(kind, correlationId);
            if (candidate.isPresent()) {
                if (match.isPresent()) {
                    throw new IllegalStateException("Domain correlation identity is ambiguous");
                }
                match = Optional.of(candidate.orElseThrow().operationId());
            }
        }
        return match;
    }

    @Override
    public Optional<SigningOperationAuthorization> signingOperationAuthorization(
            zeroecho.pki.api.PkiId operationId) {
        requireOpen();
        return store.getDomainContinuation(Objects.requireNonNull(operationId, "operationId"))
                .map(DefaultPkiSession::authorizationProjection);
    }

    @Override
    public Optional<zeroecho.pki.api.PkiId> issuanceSigningOperationId(SigningIssuanceBinding binding) {
        requireOpen();
        SigningIssuanceBinding exact = Objects.requireNonNull(binding, "binding");
        return store.getDomainContinuation(DomainContinuationStore.Kind.ISSUANCE,
                exact.intent().issuanceId()).map(value -> requireIssuanceBinding(value, exact).operationId());
    }

    @Override
    public PkiOperationOutcome issuanceSigningOperation(zeroecho.pki.api.PkiId operationId,
            SigningIssuanceBinding binding) {
        requireOpen();
        DomainContinuationStore.Record record = store.getDomainContinuation(
                Objects.requireNonNull(operationId, "operationId"))
                .orElseThrow(() -> new IllegalStateException("Issuance signing operation is unavailable"));
        return signingOperation(requireIssuanceBinding(record, Objects.requireNonNull(binding, "binding")));
    }

    private static DomainContinuationStore.Record requireIssuanceBinding(
            DomainContinuationStore.Record record, SigningIssuanceBinding binding) {
        zeroecho.pki.impl.core.async.DomainCommandEncoding.Decoded command =
                zeroecho.pki.impl.core.async.DomainCommandEncoding.decode(record.command()).requireFields(23);
        zeroecho.pki.api.issuance.IssuanceIntent intent = binding.intent();
        boolean exact = record.kind() == DomainContinuationStore.Kind.ISSUANCE
                && "ISSUE_END_ENTITY".equals(command.operation())
                && record.correlationId().filter(intent.issuanceId()::equals).isPresent()
                && command.field(0).equals(binding.authorityId().value())
                && command.field(1).equals(intent.expectedIssuerId().value())
                && command.field(2).equals(intent.expectedChainPathId().value())
                && command.field(3).equals(intent.expectedChainPathCommitment())
                && command.field(4).equals(intent.expectedProfile().profileId())
                && command.field(5).equals(Long.toString(intent.expectedProfile().profileVersion()))
                && command.field(6).equals(java.util.HexFormat.of()
                        .formatHex(intent.expectedProfile().canonicalSha256()))
                && command.field(15).equals(intent.issuanceId())
                && command.field(16).equals(intent.commandCommitment());
        if (!exact) {
            throw new IllegalStateException("Issuance signing operation binding differs");
        }
        return record;
    }

    /* default */ static SigningOperationAuthorization authorizationProjection(
            DomainContinuationStore.Record record) {
        zeroecho.pki.impl.core.async.DomainCommandEncoding.Decoded command =
                zeroecho.pki.impl.core.async.DomainCommandEncoding.decode(record.command());
        return switch (record.kind()) {
            case ISSUANCE -> issuanceAuthorization(command.requireFields(23));
            case STATUS -> statusAuthorization(command.requireFields(9));
            case CA -> caAuthorization(command);
        };
    }

    private static SigningOperationAuthorization issuanceAuthorization(
            zeroecho.pki.impl.core.async.DomainCommandEncoding.Decoded command) {
        if (!"ISSUE_END_ENTITY".equals(command.operation())) {
            throw new IllegalStateException("Durable issuance authorization operation is invalid");
        }
        return new SigningOperationAuthorization(SigningOperationAuthorization.Action.CERTIFICATE_ISSUE,
                SigningOperationAuthorization.ResourceType.CERTIFICATE,
                Optional.of(new zeroecho.pki.api.PkiId(command.field(0))),
                Optional.of(command.field(4)), Optional.empty());
    }

    private static SigningOperationAuthorization statusAuthorization(
            zeroecho.pki.impl.core.async.DomainCommandEncoding.Decoded command) {
        if (!"GENERATE_STATUS".equals(command.operation())) {
            throw new IllegalStateException("Durable status authorization operation is invalid");
        }
        return new SigningOperationAuthorization(SigningOperationAuthorization.Action.STATUS_GENERATE,
                SigningOperationAuthorization.ResourceType.STATUS_OBJECT,
                Optional.of(new zeroecho.pki.api.PkiId(command.field(0))),
                Optional.empty(), Optional.empty());
    }

    private static SigningOperationAuthorization caAuthorization(
            zeroecho.pki.impl.core.async.DomainCommandEncoding.Decoded command) {
        if (CREATE_ROOT.equals(command.operation())) {
            command.requireFields(13);
            return new SigningOperationAuthorization(SigningOperationAuthorization.Action.AUTHORITY_CREATE,
                    SigningOperationAuthorization.ResourceType.AUTHORITY,
                    Optional.empty(), Optional.empty(), Optional.empty());
        }
        command.requireFields(21);
        if (CREATE_INTERMEDIATE.equals(command.operation())) {
            return new SigningOperationAuthorization(SigningOperationAuthorization.Action.AUTHORITY_CREATE,
                    SigningOperationAuthorization.ResourceType.AUTHORITY,
                    Optional.of(new zeroecho.pki.api.PkiId(command.field(1))),
                    Optional.of(command.field(7)),
                    Optional.of(new zeroecho.pki.api.PkiId(command.field(2))));
        }
        if (ISSUE_INTERMEDIATE.equals(command.operation())) {
            return new SigningOperationAuthorization(SigningOperationAuthorization.Action.ISSUER_CREATE,
                    SigningOperationAuthorization.ResourceType.ISSUER,
                    Optional.of(new zeroecho.pki.api.PkiId(command.field(2))),
                    Optional.of(command.field(7)), Optional.empty());
        }
        throw new IllegalStateException("Durable CA authorization operation is invalid");
    }

    private static PkiOperationOutcome signingOperation(DomainContinuationStore.Record record) {
        zeroecho.pki.api.PkiId exact = record.operationId();
        return switch (record.state()) {
            case SIGNING, PUBLISHING -> new PkiOperationOutcome.Pending(SIGNING_OPERATION_NAME, exact);
            case FAILED -> new PkiOperationOutcome.Failed(SIGNING_OPERATION_NAME,
                    PkiOperationFailure.POLICY_REJECTION,
                    record.detailCode().orElse("SIGNING_FAILED"));
            case EXPIRED -> new PkiOperationOutcome.Failed(SIGNING_OPERATION_NAME,
                    PkiOperationFailure.CANCELLED, "SIGNING_EXPIRED");
            case COMPLETED -> {
                EncodedObject result = record.result().orElseThrow();
                Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
                fields.put("operationId", new PkiOperationValue.Text(exact.value()));
                fields.put("kind", new PkiOperationValue.Text(record.kind().name()));
                fields.put("encoding", new PkiOperationValue.Text(result.encoding().name()));
                String resultSha256 = sha256(result.bytes());
                fields.put("resultSha256", new PkiOperationValue.Text(resultSha256));
                if (record.kind() == DomainContinuationStore.Kind.ISSUANCE) {
                    fields.put("credentialId", new PkiOperationValue.Text("x509:" + resultSha256));
                }
                yield new PkiOperationOutcome.Completed(new PkiOperationResult(SIGNING_OPERATION_NAME, fields));
            }
        };
    }

    private static String sha256(byte[] value) {
        try {
            return java.util.HexFormat.of().formatHex(
                    java.security.MessageDigest.getInstance("SHA-256").digest(value));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    /* default */ static PkiSession open(PkiSessionConfiguration configuration) {
        return open(configuration, runtimeDependencies(configuration), Clock.systemUTC(), ProductionBootstrap.INSTANCE);
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

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    /* default */ static PkiSession open(PkiSessionConfiguration configuration,
            PkiSessionRuntimeDependencies dependencies, Clock clock, Bootstrap bootstrap) {
        PkiSessionConfiguration exact = Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(bootstrap, "bootstrap");
        Objects.requireNonNull(dependencies, "dependencies");
        KeyPossessionProofProviderComposition proofProviders =
                KeyPossessionProofProviderComposition.compose(dependencies.keyPossessionProofProviders());
        proofProviders.validatePolicy(dependencies.credentialConfirmationProofPolicy());
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
            store = Objects.requireNonNull(bootstrap.openStore(exact.store(),
                    new PkiStoreRuntimeDependencies(clock)), "opened store");
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
            return new DefaultPkiSession(exact, store, audit, profiles, revocations, algorithmBindings,
                    proofProviders, dependencies.credentialConfirmationProofPolicy(), clock, graph);
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
    public zeroecho.pki.spi.store.AuditEvidenceFeed openSigningEvidenceFeed(long afterSequenceExclusive) {
        requireOpen();
        return store.openSigningEvidenceFeed(afterSequenceExclusive);
    }

    @Override
    public boolean supportsSigningEvidenceFeed() {
        requireOpen();
        return store.supportsSigningEvidenceFeed();
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

    @Override public Optional<OcspResponseService> ocsp() { requireOpen(); return ocsp; }

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
    public SigningReconciliationResult reconcileSigning(SigningReconciliationRequest request) {
        requireOpen();
        Objects.requireNonNull(request, "request");
        return signingBus.map(value -> value.reconcile(request))
                .orElseGet(() -> new SigningReconciliationResult(SigningReconciliationContinuation.start(),
                        0, 0, 0, 0, true));
    }

    @Override
    public AutoCloseable registerSigningAdvisoryWake(Runnable listener) {
        requireOpen();
        Objects.requireNonNull(listener, "listener");
        return signingBus.map(value -> value.executionRuntime().registerWakeListener(listener))
                .orElseGet(() -> () -> { });
    }

    @Override
    public Optional<SigningExecutionMetrics> signingExecutionMetrics() {
        requireOpen();
        return signingBus.map(value -> {
            SigningExecutionRuntime.Metrics metrics = value.executionRuntime().metrics();
            return new SigningExecutionMetrics(metrics.schedulerReserved(), metrics.running(), metrics.ready(),
                    metrics.pendingAdvisories(), metrics.highWaterSchedulerReserved(), metrics.schedulingRejected(),
                    metrics.callbackCoalesced(), metrics.callbackDropped(), metrics.callbackWake(),
                    metrics.state().name());
        });
    }

    // Explicit aggregation closes every owned resource while preserving the first failure and later suppressions.
    @SuppressWarnings("PMD.CloseResource")
    @Override
    public void close() throws Exception {
        closeLock.lock();
        try {
            if (lifecycle.get() == Lifecycle.CLOSED) {
                return;
            }
            lifecycle.compareAndSet(Lifecycle.OPEN, Lifecycle.QUIESCING);
            if (signingBus.isPresent()) {
                signingBus.orElseThrow().close();
                signingRuntime.orElseThrow().close();
            } else {
                signingRuntime.ifPresent(SigningExecutionRuntime::close);
            }
            Throwable primary = null;
            primary = closeResource(publications.orElse(null), primary);
            for (SignatureWorkflow closingWorkflow : signatureWorkflows) {
                primary = closeResource(closingWorkflow, primary);
            }
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

    /* default */ PkiSigningBus.ForegroundCall registerForegroundSigningCall(
            zeroecho.core.io.CancellationSignal cancellation) {
        return signingBus.orElseThrow().registerForegroundCall(cancellation);
    }

    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.CloseResource", "PMD.ExceptionAsFlowControl" })
    private static ServiceGraph composeGraph(PkiSessionConfiguration configuration,
            PkiSessionRuntimeDependencies dependencies, PkiStore store, AuditSink audit, ProfileService profiles,
            Clock clock, Bootstrap bootstrap, List<X509BindingRuleProvider> bindingProviders) {
        List<SignatureWorkflow> openedWorkflows = new ArrayList<>();
        Optional<SigningExecutionRuntime> runtime = Optional.empty();
        Optional<PkiSigningBus> bus = Optional.empty();
        Optional<CaService> authorities = Optional.empty();
        Optional<CertificationRequestService> requests = Optional.empty();
        Optional<IssuanceService> issuance = Optional.empty();
        Optional<StatusObjectService> statuses = Optional.empty();
        Optional<PublicationService> publications = Optional.empty();
        try {
            if (configuration.signing().isPresent()) {
                PkiSessionConfiguration.SigningConfiguration signing = configuration.signing().orElseThrow();
                SignatureWorkflow defaultWorkflow = openServiceWorkflow(bootstrap, signing.workflow(), dependencies,
                        store);
                openedWorkflows.add(defaultWorkflow);
                List<SignatureWorkflow> serviceWorkflows = new ArrayList<>();
                serviceWorkflows.add(defaultWorkflow);
                Map<String, PublicKeyInfoSource> keySources = new java.util.HashMap<>();
                keySources.put(defaultWorkflow.id(), requireManagedPublicKeys(defaultWorkflow));
                for (PkiSessionConfiguration.SigningServiceConfiguration serviceConfiguration
                        : signing.signingServices()) {
                    SignatureWorkflow serviceWorkflow = openServiceWorkflow(bootstrap,
                            serviceConfiguration.workflow(), dependencies, store);
                    openedWorkflows.add(serviceWorkflow);
                    if (!serviceWorkflow.id().equals(serviceConfiguration.serviceId())) {
                        throw new IllegalStateException(
                                "Configured signing service id does not match its workflow identity: "
                                        + serviceConfiguration.serviceId());
                    }
                    serviceWorkflows.add(serviceWorkflow);
                    keySources.put(serviceWorkflow.id(), requireManagedPublicKeys(serviceWorkflow));
                }
                BcX509VerificationExecutor verification = new BcX509VerificationExecutor();
                X509AuthoritySnapshot authority = authority(serviceWorkflows, verification, bindingProviders);
                PkiSigningBus.SigningRoutingPolicy routing = new PkiSigningBus.SigningRoutingPolicy(
                        signing.caRouting(), defaultWorkflow.id());
                SigningExecutionRuntime openedRuntime = new SigningExecutionRuntime(signing);
                runtime = Optional.of(openedRuntime);
                PkiSigningBus openedBus = PkiSigningBus.attach(store, serviceWorkflows, routing, authority,
                        openedRuntime, signing.gracefulDrain(), signing.forcedCancellation());
                bus = Optional.of(openedBus);
                PublicKeyInfoSource routedKeys = routedManagedPublicKeys(keySources, signing.caRouting(),
                        defaultWorkflow.id());
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
                        statusResolver, profiles, clock, new DefaultRevocationService(store, clock, audit)));
                statuses = Optional.of(new DefaultStatusObjectService(store, framework, audit, statusResolver,
                        authority));
                authorities = Optional.of(new DefaultCaService(store, framework, issuerBackend,
                        publicKeySource(routedKeys, authority, signing), openedBus, audit, statusResolver, profiles,
                        clock, signing.signatureAlgorithm(), signing.certificateSignatureBinding(),
                        signing.signingTtl()));
            }
            List<Publisher> configuredPublishers = new ArrayList<>();
            for (ProviderConfig publisher : configuration.publishers()) {
                configuredPublishers.add(bootstrap.openPublisher(publisher));
            }
            publications = configuredPublishers.isEmpty() ? Optional.empty()
                    : Optional.of(new DefaultPublicationService(store, clock, configuredPublishers));
            return new ServiceGraph(authorities, requests, issuance, statuses, publications, bus,
                    List.copyOf(openedWorkflows), runtime);
        } catch (RuntimeException | Error primary) {
            Throwable cleanup = closeResource(publications.orElse(null), primary);
            cleanup = closeResource(bus.orElse(null), cleanup);
            cleanup = closeResource(runtime.orElse(null), cleanup);
            for (SignatureWorkflow openedWorkflow : openedWorkflows) {
                cleanup = closeResource(openedWorkflow, cleanup);
            }
            throw primary;
        }
    }

    private static SignatureWorkflow openServiceWorkflow(Bootstrap bootstrap, ProviderConfig workflowConfig,
            PkiSessionRuntimeDependencies dependencies, PkiStore store) {
        SignatureWorkflowRuntimeDependencies workflowDependencies;
        if ("zeroecho-lib".equals(workflowConfig.backendId())
                && store instanceof zeroecho.pki.impl.fs.AtomicLocalSigningLedgerParticipant participant
                && dependencies.keyringUnlockProvider().isPresent()) {
            workflowDependencies = SignatureWorkflowRuntimeDependencies.local(
                    dependencies.keyringUnlockProvider().orElseThrow(), participant);
        } else {
            workflowDependencies = dependencies.keyringUnlockProvider()
                    .map(SignatureWorkflowRuntimeDependencies::withKeyringUnlockProvider)
                    .orElseGet(SignatureWorkflowRuntimeDependencies::none);
        }
        return bootstrap.openSignatureWorkflow(workflowConfig, workflowDependencies);
    }

    private static PublicKeyInfoSource requireManagedPublicKeys(SignatureWorkflow workflow) {
        if (!(workflow instanceof PublicKeyInfoSource publicKeys)) {
            throw new IllegalStateException("Signature workflow lacks managed public-key capability");
        }
        return publicKeys;
    }

    private static PublicKeyInfoSource routedManagedPublicKeys(Map<String, PublicKeyInfoSource> keySources,
            Map<String, String> caRouting, String defaultServiceId) {
        Map<String, PublicKeyInfoSource> sources = Map.copyOf(keySources);
        Map<String, String> routing = Map.copyOf(caRouting);
        return keyRef -> {
            String serviceId = routing.getOrDefault(keyRef.value(), defaultServiceId);
            PublicKeyInfoSource source = sources.get(serviceId);
            if (source == null) {
                throw new PkiException(
                        "No signing service resolves the managed public key: code=SIGNING_ROUTE_UNRESOLVED");
            }
            return source.resolvePublicKeyInfo(keyRef);
        };
    }

    // Each configured workflow requires independent immutable capability and executor-binding objects.
    @SuppressWarnings({"PMD.AvoidInstantiatingObjectsInLoops", "PMD.CloseResource"})
    private static X509AuthoritySnapshot authority(List<SignatureWorkflow> workflows,
            BcX509VerificationExecutor verification, List<X509BindingRuleProvider> bindingProviders) {
        List<AlgorithmExecutionCapabilityProvider> capabilityProviders = new ArrayList<>();
        List<X509AuthoritySnapshot.ExecutorBinding> executorBindings = new ArrayList<>();
        for (SignatureWorkflow workflow : workflows) {
            Set<String> supported = Set.copyOf(workflow.supportedAlgorithms());
            Set<AlgorithmIdentity> identities = BootstrapAlgorithmIdentities.catalog().identities().stream()
                    .filter(identity -> identity.kind() == AlgorithmIdentity.Kind.SIGNATURE)
                    .filter(identity -> supported.contains(identity.canonicalForm())
                            || BootstrapAlgorithmIdentities.compatibilityAliases().entrySet().stream()
                                    .anyMatch(entry -> entry.getValue().equals(identity)
                                            && supported.contains(entry.getKey())))
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
                    return direction == Direction.SIGN && identities.contains(identity)
                            && identity.equals(suite.signature());
                }
            };
            capabilityProviders.add(() -> List.of(signing));
            executorBindings.add(X509AuthoritySnapshot.bindExecutor(implementationId,
                    AlgorithmExecutionCapability.Direction.SIGN, workflow));
        }
        capabilityProviders.add(verification);
        executorBindings.add(X509AuthoritySnapshot.bindExecutor(BcX509VerificationExecutor.IMPLEMENTATION_ID,
                AlgorithmExecutionCapability.Direction.VERIFY, verification));
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
        return X509AuthoritySnapshot.compose(bindingProviders, capabilityProviders, executorBindings, policy);
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
                                signing.subjectPublicKeyBinding().orElseThrow());
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

    // Explicit aggregation attempts every partially constructed resource and attaches all cleanup failures.
    @SuppressWarnings("PMD.CloseResource")
    private static void closeGraphAfterConstructionFailure(ServiceGraph graph, Throwable primary) {
        Throwable ignored = closeResource(graph.publications().orElse(null), primary);
        ignored = closeResource(graph.signingBus().orElse(null), ignored);
        ignored = closeResource(graph.signingRuntime().orElse(null), ignored);
        for (SignatureWorkflow closingWorkflow : graph.signatureWorkflows()) {
            ignored = closeResource(closingWorkflow, ignored);
        }
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

        /** Opens the configured store with the owning session's authoritative runtime dependencies. */
        default PkiStore openStore(ProviderConfig configuration, PkiStoreRuntimeDependencies dependencies) {
            Objects.requireNonNull(dependencies, "dependencies");
            return openStore(configuration);
        }

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
            List<SignatureWorkflow> signatureWorkflows, Optional<SigningExecutionRuntime> signingRuntime) {
        private static ServiceGraph empty() {
            return new ServiceGraph(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                    Optional.empty(), Optional.empty(), List.of(), Optional.empty());
        }
    }

    /** Session close state used to preserve retryable runtime drain. */
    private enum Lifecycle {
        OPEN,
        QUIESCING,
        CLOSED
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
        public PkiStore openStore(ProviderConfig configuration, PkiStoreRuntimeDependencies dependencies) {
            return PkiBootstrap.openStore(configuration, dependencies);
        }

        @Override
        public AuditSink openAudit(ProviderConfig configuration) {
            return PkiBootstrap.openAudit(configuration);
        }
    }
}
