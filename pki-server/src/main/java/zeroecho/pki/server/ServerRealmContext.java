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
package zeroecho.pki.server;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import zeroecho.pki.api.confirmation.ConfirmationRealmBinding;
import zeroecho.pki.application.CredentialConfirmationProofRuntimePolicy;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.impl.fs.DurableTransactionalMetadataStore;
import zeroecho.pki.server.acme.AcmeControlStore;
import zeroecho.pki.server.confirmation.SignatureKeyPossessionProofProvider;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.spi.confirmation.KeyPossessionProofDescriptor;

/**
 * Lifecycle owner for one server realm, one long-lived PKI session, and one
 * dedicated durable server-control authority.
 *
 * <p>The context is transport-neutral and synchronous. It creates no execution
 * lane, queue, thread, scheduler, retry loop, HTTP type, or ACME object. A future
 * transport can retain one instance for its process lifetime and submit existing
 * typed operations through {@link #gateway()}.</p>
 */
// Realm services share one lifecycle and authorization boundary; splitting them would duplicate state.
@SuppressWarnings({ "PMD.CommentDefaultAccessModifier", "PMD.CloseResource", "PMD.UseProperClassLoader",
        "PMD.AvoidCatchingGenericException", "PMD.LinguisticNaming", "PMD.ControlStatementBraces",
        "PMD.PreserveStackTrace", "PMD.SignatureDeclareThrowsException", "PMD.CommentRequired",
        "PMD.AvoidSynchronizedAtMethodLevel", "PMD.AvoidInstantiatingObjectsInLoops",
        "PMD.CyclomaticComplexity", "PMD.CouplingBetweenObjects" })
public final class ServerRealmContext implements AutoCloseable { // NOPMD TooManyMethods - One cohesive gateway, realm ownership boundary, or durable store SPI implementation.
    /** Closed lifecycle states. */
    public enum State {
        /** Realm accepts operations. */ OPEN,
        /** Realm rejects new work while owned resources close. */ CLOSING,
        /** All realm-owned resources are closed. */ CLOSED
    }

    private final ServerRealmConfiguration configuration;
    private BackupTransferService backupTransfers;
    private BackupTransferConfiguration backupTransferConfiguration;
    private zeroecho.pki.server.enrollment.EnrollmentRuntime enrollmentRuntime;
    private zeroecho.pki.server.enrollment.EnrollmentCoordinator enrollmentCoordinator;
    private final ServerControlStore control;
    private final zeroecho.pki.server.enrollment.EnrollmentProfileService enrollmentProfiles;
    private final zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry enrollmentEndpoints;
    private final PkiSession session;
    private final RoleTemplateCatalog roles;
    private final AuthorizationEngine authorization;
    private final ApprovalService approvals;
    private final BreakGlassService breakGlass;
    private final DisclosureService disclosure;
    private final CredentialPublicationGate credentialPublication;
    private final RepositoryAliasService repositoryAliases;
    private final AcmeControlStore acmeControl;
    private final OcspResponderService ocspResponders;
    private final PublicRepositoryGateway publicRepository;
    private final AuditorViews auditorViews;
    private final ServerOperationGateway gateway;
    private final RevocationAuditProjector revocationAuditProjector;
    private final AuditEvidenceProjector issuanceAuditProjector;
    private final AuditEvidenceProjector statusAuditProjector;
    private final AuditEvidenceProjector publicationAuditProjector;
    private final java.util.List<AuditEvidenceProjector> evidenceProjectors = new java.util.ArrayList<>();
    private final RealmReconciliationWakeSignal reconciliationWake = new RealmReconciliationWakeSignal();
    private final SafeAudit audit;
    private final AtomicReference<State> state = new AtomicReference<>(State.OPEN);
    private final RetryableCloseGate closeGate = new RetryableCloseGate();
    private final AtomicBoolean closeAuditAttempted = new AtomicBoolean();
    private final AtomicBoolean sessionClosed = new AtomicBoolean();
    private final AtomicBoolean controlClosed = new AtomicBoolean();
    private final java.util.concurrent.atomic.AtomicLong adminRequests = new java.util.concurrent.atomic.AtomicLong();
    private final java.util.concurrent.atomic.AtomicLong scheduleFailures = new java.util.concurrent.atomic.AtomicLong();
    private static final java.util.logging.Logger SCHEDULE_LOG = java.util.logging.Logger.getLogger("zeroecho.pki.server.status-schedule");
    private final AtomicReference<zeroecho.pki.api.audit.AuditIntegrityService> auditIntegrity =
            new AtomicReference<>();
    private final AtomicReference<String> auditAnchorCommitment = new AtomicReference<>();

    private static final String AUDIT_ANCHOR_NAMESPACE = ServerControlStore.AUDIT_ANCHOR;
    private static final String AUDIT_ANCHOR_RECORD_ID = "head";
    private static final long FIRST_AUDIT_SEQUENCE = 0L;

    private ServerRealmContext(ServerRealmConfiguration configuration, ServerControlStore control,
            PkiSession session, RoleTemplateCatalog roles, AuthorizationEngine authorization,
            ApprovalService approvals, BreakGlassService breakGlass, DisclosureService disclosure,
            RepositoryAliasService repositoryAliases,
            AuditorViews auditorViews, AuditSink auditSink, Clock clock) {
        this.configuration = configuration;
        this.control = control;
        this.enrollmentProfiles = new zeroecho.pki.server.enrollment.EnrollmentProfileService(control);
        this.enrollmentEndpoints = new zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry(control, enrollmentProfiles);
        this.session = session;
        this.roles = roles;
        this.authorization = authorization;
        this.approvals = approvals;
        this.breakGlass = breakGlass;
        this.disclosure = disclosure;
        this.credentialPublication = new CredentialPublicationGate(session.repository(), session.profiles(),
                session.confirmations(), disclosure, clock, this::requireOpen);
        this.repositoryAliases = repositoryAliases;
        this.acmeControl = new AcmeControlStore(control);
        this.acmeControl.validateAndRecover(clock);
        this.ocspResponders = new OcspResponderService(configuration.realmId(), control, session.repository(),
                session.algorithmBindings(), session.ocsp(), clock);
        this.ocspResponders.validateAll();
        this.publicRepository = new PublicRepositoryGateway(configuration.realmId(), configuration.authorityExposure(),
                session.repository(), control, roles, authorization, breakGlass, disclosure, repositoryAliases,
                this::requireOpen);
        this.auditorViews = auditorViews;
        this.audit = new SafeAudit(clock, auditSink);
        this.revocationAuditProjector = new RevocationAuditProjector(configuration.realmId(), session.revocations(),
                control, clock, auditSink);
        this.issuanceAuditProjector = new AuditEvidenceProjector(control, IssuanceAuditProjection.recordId(),
                session::openIssuanceEvidenceFeed, IssuanceAuditProjection::toEvent, auditSink, clock);
        this.evidenceProjectors.add(this.issuanceAuditProjector);
        this.statusAuditProjector = new AuditEvidenceProjector(control, StatusAuditProjection.recordId(),
                session::openStatusEvidenceFeed, StatusAuditProjection::toEvent, auditSink, clock);
        this.evidenceProjectors.add(this.statusAuditProjector);
        this.publicationAuditProjector = new AuditEvidenceProjector(control, PublicationAuditProjection.recordId(),
                session::openPublicationEvidenceFeed, PublicationAuditProjection::toEvent, auditSink, clock);
        this.evidenceProjectors.add(this.publicationAuditProjector);
        // Signing (CA key-usage) audit is an operator opt-in; register its projector only when the store
        // maintains the signing evidence feed, otherwise the feed opener would throw.
        if (session.supportsSigningEvidenceFeed()) {
            this.evidenceProjectors.add(new AuditEvidenceProjector(control, SigningAuditProjection.recordId(),
                    session::openSigningEvidenceFeed, SigningAuditProjection::toEvent, auditSink, clock));
        }
        this.gateway = new ServerOperationGateway(configuration.realmId(), configuration.authorityExposure(),
                control, roles, authorization, approvals, breakGlass, disclosure, credentialPublication,
                auditorViews, Optional.of(repositoryAliases),
                new OperationSecurityDescriptors(),
                session.operations(), new ServerSigningExecutor(session), session.resourceScopes(),
                configuration.approvalPolicies(),
                profileId -> session.profiles().requireActiveProfile(profileId).definition().approvalRequirement(),
                clock, auditSink, reconciliationWake::signal, this::requireOpen);
        this.gateway.installOcsp(ocspResponders);
        this.gateway.installEnrollmentProfiles(enrollmentProfiles);
    }

    /**
     * Opens one production realm using explicit process-local capabilities.
     *
     * @param configuration validated immutable realm configuration
     * @param dependencies key-access capabilities, never secret values
     * @return fully recovered realm context
     * @throws IllegalArgumentException if a restore coordinator exists and server-control
     *         storage is nested inside the replaceable PKI root
     */
    public static ServerRealmContext open(ServerRealmConfiguration configuration,
            PkiSessionRuntimeDependencies dependencies) {
        return open(configuration, dependencies, Clock.systemUTC(), new SecureRandom());
    }

    static ServerRealmContext open(ServerRealmConfiguration configuration,
            PkiSessionRuntimeDependencies dependencies, Clock clock, SecureRandom random) {
        ServerRealmConfiguration exact = Objects.requireNonNull(configuration, "configuration");
        zeroecho.pki.server.schema.OperationDescriptorCatalog.current();
        PkiSessionRuntimeDependencies runtime = confirmationProofRuntime(exact,
                Objects.requireNonNull(dependencies, "dependencies"));
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(random, "random");
        rejectColocatedRestoreAuthority(exact);
        if (Files.isSymbolicLink(exact.controlLogPath())) {
            throw new IllegalArgumentException("Server-control log must not be a symbolic link");
        }
        ServerControlStore control = null;
        SharedAuditSink audit = null;
        PkiSession session = null;
        try {
            control = new ServerControlStore(openControl(exact));
            ServerControlStore.RealmRecord realm = new ServerControlStore.RealmRecord(exact.realmId(),
                    exact.displayName(), exact.authorityExposure(), exact.authorizationCommitment(),
                    exact.approvalCommitment(), exact.extendedApprovalCommitment(), exact.disclosureCommitment(),
                    exact.controlStoreId());
            control.ensureRealm(realm);
            RoleTemplateCatalog roles = RoleTemplateCatalog.load(ServerRealmContext.class.getClassLoader());
            control.validateAll();
            control.validateReferences(roles);
            audit = new SharedAuditSink(PkiBootstrap.openAudit(exact.pkiSessionConfiguration().audit()));
            session = PkiSession.open(exact.pkiSessionConfiguration(), runtime.withAuditSink(audit), clock);
            validateExposure(exact.authorityExposure(), session);
            AuthorizationEngine authorization = new AuthorizationEngine(clock);
            ApprovalService approvals = new ApprovalService(control, clock, audit);
            BreakGlassService breakGlass = new BreakGlassService(control, clock, audit);
            DisclosureService disclosure = new DisclosureService(exact.realmId(), control,
                    exact.disclosureDefaults(), clock, random, audit);
            RepositoryAliasService aliases = new RepositoryAliasService(exact.realmId(), control,
                    session.repository(), disclosure, clock, audit);
            AuditorViews views = new AuditorViews(clock, audit);
            ServerRealmContext result = new ServerRealmContext(exact, control, session, roles, authorization,
                    approvals, breakGlass, disclosure, aliases, views, audit, clock);
            if (audit.supportsQuery()) {
                result.gateway.installAudit(audit, audit);
                result.auditIntegrity.set(audit);
                result.reconcileAuditAnchor();
            }
            session.backup().ifPresent(result.gateway::installBackup);
            result.audit.record("REALM_OPEN", "system", Optional.empty(), Map.of("realm", exact.realmId().value()));
            return result;
        } catch (RuntimeException | Error primary) {
            closeAfterFailure(session, audit, control, primary);
            throw primary;
        }
    }

    private static void rejectColocatedRestoreAuthority(ServerRealmConfiguration configuration) {
        zeroecho.pki.spi.ProviderConfig store = configuration.pkiSessionConfiguration().store();
        if (!"fs".equals(Objects.requireNonNull(store.backendId()))) { return; }
        Path root = Path.of(store.require("root")).toAbsolutePath().normalize();
        if (root.getParent() == null) return;
        Path journal = root.getParent().resolve("." + root.getFileName() + ".restore-control/journal");
        if (!Files.exists(journal)) return;
        if (configuration.controlLogPath().startsWith(root)) {
            throw new IllegalArgumentException("RESTORE_COLOCATED_SERVER_AUTHORITY");
        }
        configuration.pkiSessionConfiguration().audit().get("root").ifPresent(path -> {
            if (Path.of(path).toAbsolutePath().normalize().startsWith(root)) {
                throw new IllegalArgumentException("RESTORE_COLOCATED_SERVER_AUTHORITY");
            }
        });
        configuration.pkiSessionConfiguration().signing().ifPresent(signing -> signing.provider().get("keyringPath").ifPresent(path -> {
            if (Path.of(path).toAbsolutePath().normalize().startsWith(root)) {
                throw new IllegalArgumentException("RESTORE_COLOCATED_SERVER_AUTHORITY");
            }
        }));
    }

    void installBackupTransfer(BackupTransferConfiguration transfer, Clock clock, SecureRandom random) throws IOException {
        if (backupTransfers != null) throw new IllegalStateException("Backup transfer already installed");
        validateTransferTopology(transfer);
        BackupArtifactRepository repository = new BackupArtifactRepository(transfer,
                configuration.realmId().value(), clock, random);
        try {
            backupTransfers = new BackupTransferService(session.backup().orElseThrow(
                    () -> new IllegalStateException("Streaming backup is unavailable")), repository,
                    () -> validateTransferTopology(transfer));
            gateway.installBackupTransfers(backupTransfers);
            backupTransferConfiguration = transfer;
        } catch (IOException | RuntimeException failure) {
            try { repository.close(); } catch (IOException cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }

    void installEnrollmentRuntime(zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration configured,
            PkiSessionRuntimeDependencies dependencies, Clock clock) {
        requireOpen();
        if (enrollmentRuntime != null) throw new IllegalStateException("Enrollment runtime already installed");
        enrollmentRuntime = zeroecho.pki.server.enrollment.EnrollmentRuntime.open(configured, configuration,
                session.repository(), control, enrollmentEndpoints, dependencies, clock, backupTransferConfiguration());
    }

    /**
     * Returns explicitly installed enrollment custody and resource limits.
     * @return empty when the server has no enrollment companion
     */
    public Optional<zeroecho.pki.server.enrollment.EnrollmentRuntime> enrollmentRuntime() {
        requireOpen();
        return Optional.ofNullable(enrollmentRuntime);
    }

    void installEnrollmentCoordinator(PkiServerConfiguration.Authentication authentication, Clock clock) {
        requireOpen();
        if (enrollmentCoordinator != null) throw new IllegalStateException("Enrollment coordinator already installed");
        enrollmentCoordinator = new zeroecho.pki.server.enrollment.EnrollmentCoordinator(control, configuration, session,
                enrollmentEndpoints, enrollmentProfiles, acmeControl, enrollmentRuntime().orElseThrow(),
                new zeroecho.pki.server.enrollment.EnrollmentIdentityAliases(configuration.realmId(), authentication), clock);
        gateway.installEnrollmentCoordinator(enrollmentCoordinator);
    }

    /** Returns the coordinator installed for this realm's enrollment services.
     * @return installed durable coordinator, empty for deployments without enrollment */
    public Optional<zeroecho.pki.server.enrollment.EnrollmentCoordinator> enrollmentCoordinator() {
        requireOpen(); return Optional.ofNullable(enrollmentCoordinator);
    }

    /**
     * Returns explicitly installed binary transfer settings.
     * @return empty when remote backup transfer is disabled
     */
    public Optional<BackupTransferConfiguration> backupTransferConfiguration() {
        return Optional.ofNullable(backupTransferConfiguration);
    }

    private void validateTransferTopology(BackupTransferConfiguration transfer) throws IOException {
        zeroecho.pki.spi.ProviderConfig store = configuration.pkiSessionConfiguration().store();
        if (!"fs".equals(store.backendId())) throw new IOException("Backup transfer requires the filesystem store");
        Path root = Path.of(store.require("root")).toRealPath();
        Path spool = transfer.directory().toRealPath();
        if (spool.startsWith(root) || root.startsWith(spool)) throw new IOException("BACKUP_STORAGE_OVERLAP");
        java.util.List<Path> authorities = new java.util.ArrayList<>();
        authorities.add(configuration.controlLogPath());
        configuration.pkiSessionConfiguration().audit().get("root").ifPresent(value -> authorities.add(Path.of(value)));
        configuration.pkiSessionConfiguration().signing().ifPresent(signing -> signing.provider().get("keyringPath")
                .ifPresent(value -> authorities.add(Path.of(value))));
        for (Path authority : authorities) {
            Path resolved = authority.toRealPath();
            if (resolved.startsWith(root) || resolved.startsWith(spool)) {
                throw new IOException("RESTORE_COLOCATED_SERVER_AUTHORITY");
            }
        }
    }

    static PkiSessionRuntimeDependencies confirmationProofRuntime(
            ServerRealmConfiguration configuration, PkiSessionRuntimeDependencies dependencies) {
        ServerRealmConfiguration exact = Objects.requireNonNull(configuration, "configuration");
        PkiSessionRuntimeDependencies runtime = Objects.requireNonNull(dependencies, "dependencies");
        CredentialConfirmationProofPolicy configured = exact.confirmationProofPolicy();
        SignatureKeyPossessionProofProvider provider = new SignatureKeyPossessionProofProvider();
        KeyPossessionProofDescriptor descriptor =
                provider.descriptor(configured.rsaMaximumModulusBits());
        CredentialConfirmationProofRuntimePolicy policy =
                new CredentialConfirmationProofRuntimePolicy(
                        new ConfirmationRealmBinding(exact.realmId().value()),
                        configured.audience(), configured.challengeTimeToLive(),
                        descriptor.proofSuiteBinding());
        return runtime.withKeyPossessionProofProviders(java.util.List.of(provider))
                .withCredentialConfirmationProofPolicy(policy);
    }

    /**
     * Returns exact realm configuration without rendering provider values.
     *
     * @return exact realm configuration without rendering provider values
     */
    public ServerRealmConfiguration configuration() { requireOpen(); return configuration; }
    /**
     * Returns the one long-lived PKI session.
     *
     * @return the one long-lived PKI session
     */
    public PkiSession session() { requireOpen(); return session; }
    /**
     * Returns immutable built-in role template catalog.
     *
     * @return immutable built-in role template catalog
     */
    public RoleTemplateCatalog roleTemplates() { requireOpen(); return roles; }
    /**
     * Returns deterministic authorization engine.
     *
     * @return deterministic authorization engine
     */
    public AuthorizationEngine authorization() { requireOpen(); return authorization; }
    /**
     * Returns durable approval service.
     *
     * @return durable approval service
     */
    public ApprovalService approvals() { requireOpen(); return approvals; }
    /**
     * Returns durable break-glass service.
     *
     * @return durable break-glass service
     */
    public BreakGlassService breakGlass() { requireOpen(); return breakGlass; }
    /**
     * Returns durable disclosure decision service.
     *
     * @return durable disclosure decision service
     */
    public DisclosureService disclosure() { requireOpen(); return disclosure; }
    /**
     * Returns synchronous authoritative credential publication gate.
     *
     * @return synchronous authoritative credential publication gate
     */
    public CredentialPublicationGate credentialPublication() { requireOpen(); return credentialPublication; }
    /**
     * Returns durable non-authoritative public repository alias service.
     *
     * @return durable non-authoritative public repository alias service
     */
    public RepositoryAliasService repositoryAliases() { requireOpen(); return repositoryAliases; }
    /**
     * Returns typed ACME records in the realm's sole durable control authority.
     *
     * @return typed ACME records in the realm's sole durable control authority
     */
    public AcmeControlStore acmeControl() { requireOpen(); return acmeControl; }
    /**
     * Returns durable exact OCSP responder bindings.
     *
     * @return durable exact OCSP responder bindings
     */
    public OcspResponderService ocspResponders() { requireOpen(); return ocspResponders; }
    /**
     * Returns read-only disclosed public repository gateway.
     *
     * @return read-only disclosed public repository gateway
     */
    public PublicRepositoryGateway publicRepository() { requireOpen(); return publicRepository; }
    /**
     * Returns explicit auditor projection service.
     *
     * @return explicit auditor projection service
     */
    public AuditorViews auditorViews() { requireOpen(); return auditorViews; }
    /**
     * Returns authorized typed-operation gateway.
     *
     * @return authorized typed-operation gateway
     */
    public ServerOperationGateway gateway() { requireOpen(); return gateway; }

    /**
     * Returns the realm-owned durable enrollment endpoint authority.
     * @return shared thread-safe registry, usable only while this realm is open
     */
    public zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry enrollmentEndpoints() {
        requireOpen();
        return enrollmentEndpoints;
    }

    /**
     * Returns the realm-owned durable enrollment policy authority.
     * @return shared thread-safe policy registry, usable only while this realm is open
     */
    public zeroecho.pki.server.enrollment.EnrollmentProfileService enrollmentProfiles() {
        requireOpen();
        return enrollmentProfiles;
    }
    /**
     * Returns synchronous authoritative-revocation audit projector owned by this realm.
     *
     * @return synchronous authoritative-revocation audit projector owned by this realm
     */
    /* default */ RevocationAuditProjector revocationAuditProjector() {
        requireOpen();
        return revocationAuditProjector;
    }

    /** Runs one bounded pass of every per-family success-evidence projector and folds their scheduling hints. */
    @SuppressWarnings("PMD.AvoidCatchingGenericException") // A projector failure must not stop scheduling.
    /* default */ AuditProjectionWorker.EvidenceHint runEvidenceProjections(int maximumRecords,
            int maximumSinkCalls, zeroecho.core.io.CancellationSignal cancellation) {
        boolean immediate = false;
        Optional<java.time.Instant> earliest = Optional.empty();
        for (AuditEvidenceProjector projector : evidenceProjectors) {
            try {
                AuditEvidenceProjector.PassResult result = projector.project(maximumRecords, maximumSinkCalls,
                        cancellation);
                if (!result.endReached() && !result.blocked()) {
                    immediate = true;
                }
                earliest = earliestInstant(earliest, result.nextEligible());
            } catch (IOException | RuntimeException ignored) {
                // A projector failure is retried on the next cycle; it must not abort scheduling.
            }
        }
        return new AuditProjectionWorker.EvidenceHint(immediate, earliest);
    }

    private static Optional<java.time.Instant> earliestInstant(Optional<java.time.Instant> first,
            Optional<java.time.Instant> second) {
        if (first.isEmpty()) {
            return second;
        }
        if (second.isEmpty()) {
            return first;
        }
        return Optional.of(first.orElseThrow().isBefore(second.orElseThrow())
                ? first.orElseThrow() : second.orElseThrow());
    }
    /**
     * Returns realm-scoped payload-free reconciliation wake capability.
     *
     * @return realm-scoped payload-free reconciliation wake capability
     */
    /* default */ RealmReconciliationWakeSignal reconciliationWakeSignal() {
        requireOpen();
        return reconciliationWake;
    }
    /** Signals committed reconciliation work without retaining its identity. */
    /* default */ void signalReconciliation() { reconciliationWake.signal(); }
    /**
     * Resolves one persisted principal for transport authentication.
     *
     * @param principalId canonical principal identity
     * @return persisted identity metadata without credentials or grants
     * @throws IllegalArgumentException when the principal is unavailable
     * @throws IllegalStateException when this realm is not open
     */
    public SecurityPrincipal principal(String principalId) {
        requireOpen();
        return control.requirePrincipal(principalId);
    }

    /**
     * Evaluates the protocol-only OCSP query permission for one exact responder
     * and issuer generation. The signed-request identity remains independent of
     * administrative and transport authentication.
     *
     * @param principalId cryptographically mapped requester principal
     * @param responder exact active responder binding
     * @return default-deny authorization decision
     */
    public AuthorizationEngine.Decision authorizeOcspQuery(String principalId,
            OcspResponderService.Responder responder) {
        requireOpen();
        SecurityPrincipal principal = control.requirePrincipal(principalId);
        java.util.List<Permission.Grant> grants = new java.util.ArrayList<>(control.grantsFor(principalId));
        for (RoleTemplateCatalog.Assignment assignment : control.assignmentsFor(principalId)) {
            grants.addAll(roles.instantiate(assignment));
        }
        BreakGlassService.ActiveGrants emergency = breakGlass.activeFor(principalId);
        grants.addAll(emergency.grants());
        Permission.Scope scope = new Permission.Scope(configuration.realmId(),
                Optional.of(responder.authorityId()), Optional.of(responder.issuerId()), Optional.empty(),
                Optional.of(responder.responderId()));
        Permission.Resource resource = new Permission.Resource(Permission.ResourceType.OCSP_RESPONDER,
                scope, Optional.empty(), Optional.empty());
        AuthorizationEngine.Decision decision = authorization.authorize(new AuthorizationEngine.Request(
                configuration.realmId(), configuration.authorityExposure(), principal,
                Permission.Action.OCSP_STATUS_QUERY, resource, Permission.Relationship.ANY,
                Permission.DataView.METADATA_REDACTED, Permission.Context.empty(), grants,
                emergency.grantIds()));
        if (decision.usedBreakGlass()) breakGlass.auditUse(principalId);
        return decision;
    }
    /**
     * Records one transport-safe lifecycle or request classification through the
     * shared realm audit authority.
     *
     * @param action stable transport action
     * @param principalId authenticated principal or {@code system}
     * @param safeDetails finite pre-redacted details
     */
    public void auditTransport(String action, String principalId, Map<String, String> safeDetails) {
        requireOpen();
        Permission.requireBounded(action, 128, "audit action");
        Permission.requirePrincipal(principalId);
        audit.record(action, principalId, Optional.empty(), Map.copyOf(safeDetails));
    }

    /** Records an administrative HTTP request upon handler entry, including rejected requests. */
    public void recordAdminRequest() { adminRequests.updateAndGet(value -> value == Long.MAX_VALUE ? value : value + 1); }

    long adminRequestsTotal() { return adminRequests.get(); }
    long scheduleFailureTotal() { return scheduleFailures.get(); }
    long pendingApprovalCount(java.time.Instant now) { requireOpen(); return control.pendingApprovalCount(now); }

    long auditProjectionFailureTotal() {
        requireOpen();
        long count = RevocationAuditProjectionState.load(control).map(value -> (long) value.state().failureCount()).orElse(0L);
        for (AuditEvidenceProjector projector : evidenceProjectors) count = Math.addExact(count, projector.failureCount());
        return count;
    }

    void recordScheduleFailure(String code) {
        scheduleFailures.updateAndGet(value -> value == Long.MAX_VALUE ? value : value + 1);
        SCHEDULE_LOG.log(java.util.logging.Level.WARNING, "Status schedule failure: code={0}", code);
        audit.record("STATUS_SCHEDULE_FAILURE", "system", Optional.empty(), Map.of("code", code));
    }
    /**
     * Returns current lifecycle state.
     *
     * @return current lifecycle state
     */
    public State state() { return state.get(); }

    /**
     * Creates a principal and records only safe administrative audit metadata.
     *
     * @param principal validated principal to create
     * @param actorPrincipalId authenticated administrative actor
     */
    public void createPrincipal(SecurityPrincipal principal, String actorPrincipalId) {
        requireOpen();
        control.createPrincipal(principal);
        audit.record("PRINCIPAL_CREATE", actorPrincipalId, Optional.empty(),
                Map.of("principal", principal.principalId(), "enabled", Boolean.toString(principal.enabled())));
    }

    /**
     * Changes only the enabled state of an existing principal.
     *
     * @param principalId stable principal identifier
     * @param enabled desired enabled state
     * @param actorPrincipalId authenticated administrative actor
     * @return durably updated principal
     */
    public SecurityPrincipal setPrincipalEnabled(String principalId, boolean enabled, String actorPrincipalId) {
        requireOpen();
        SecurityPrincipal current = control.requirePrincipal(principalId);
        SecurityPrincipal updated = new SecurityPrincipal(current.principalId(), current.type(),
                current.displayName(), current.organization(), current.attributes(), enabled);
        control.replacePrincipal(current, updated);
        audit.record("PRINCIPAL_STATE", actorPrincipalId, Optional.empty(),
                Map.of("principal", principalId, "enabled", Boolean.toString(enabled)));
        return updated;
    }

    /**
     * Creates one scoped role assignment; templates remain non-authoritative alone.
     *
     * @param assignment validated scoped role assignment
     * @param actorPrincipalId authenticated administrative actor
     */
    public void assignRole(RoleTemplateCatalog.Assignment assignment, String actorPrincipalId) {
        requireOpen();
        roles.instantiate(assignment);
        control.requirePrincipal(assignment.principalId());
        control.createAssignment(assignment);
        audit.record("ROLE_ASSIGNMENT_CREATE", actorPrincipalId, Optional.empty(),
                Map.of("assignment", assignment.assignmentId(), "template", assignment.templateId()));
    }

    /**
     * Creates one explicit scoped direct grant.
     *
     * @param grant validated scoped permission grant
     * @param actorPrincipalId authenticated administrative actor
     */
    public void grant(Permission.Grant grant, String actorPrincipalId) {
        requireOpen();
        control.requirePrincipal(grant.principalId());
        control.createGrant(grant);
        audit.record("PERMISSION_GRANT_CREATE", actorPrincipalId, Optional.empty(),
                Map.of("grant", grant.grantId(), "effect", grant.effect().name()));
    }

    /**
     * Rejects new work and closes session then server-control authority. Repeated
     * calls are harmless and failure suppression preserves causal order.
     */
    // Cross-store tamper-evidence: verify the audit log against the durably anchored trusted head, then
    // advance the anchor. A consistent full rewrite of the audit file alone (which its self-contained hash
    // chain cannot reveal) is detected because the rewritten head no longer matches the separately stored
    // anchor. Runs once at boot before any operation writes.
    private void reconcileAuditAnchor() {
        zeroecho.pki.api.audit.AuditIntegrityService service = auditIntegrity.get();
        Optional<ServerControlStore.ProtocolRecord> stored = control.protocolRecord(
                AUDIT_ANCHOR_NAMESPACE, AUDIT_ANCHOR_RECORD_ID);
        zeroecho.pki.api.audit.AuditIntegrityReport report = stored.isPresent()
                ? service.verifyAnchoredPrefix(decodeAuditAnchor(stored.orElseThrow()))
                : service.verifyIntegrity(Optional.empty());
        if (report.status() != zeroecho.pki.api.audit.AuditIntegrityReport.Status.INTACT) {
            throw new IllegalStateException("Audit log integrity verification failed: " + report.status());
        }
        writeAuditAnchor(report.head(), stored.map(ServerControlStore.ProtocolRecord::commitment));
    }

    private void advanceAuditAnchorOnClose() {
        zeroecho.pki.api.audit.AuditIntegrityService service = auditIntegrity.get();
        if (service == null) {
            return;
        }
        zeroecho.pki.api.audit.AuditIntegrityReport report = service.verifyIntegrity(Optional.empty());
        if (report.status() == zeroecho.pki.api.audit.AuditIntegrityReport.Status.INTACT) {
            writeAuditAnchor(report.head(), Optional.ofNullable(auditAnchorCommitment.get()));
        }
    }

    private void writeAuditAnchor(zeroecho.pki.api.audit.AuditChainHead head,
            Optional<String> expectedCommitment) {
        // Never persist a genesis (empty-log) anchor: verifyAnchoredPrefix accepts any consistent chain for a
        // sequence < 0 anchor, so blessing one would let a first-boot-empty-log-then-crash window skip
        // detection. Leaving no anchor until the first real record forces presence+hash verification.
        if (head.sequence() < FIRST_AUDIT_SEQUENCE) {
            return;
        }
        byte[] payload = (head.sequence() + "\n" + head.recordHash())
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String commitment = ApprovalService.digest(head.sequence() + ":" + head.recordHash());
        control.mutateProtocol(java.util.List.of(new ServerControlStore.ProtocolMutation(
                new ServerControlStore.ProtocolRecord(AUDIT_ANCHOR_NAMESPACE, AUDIT_ANCHOR_RECORD_ID,
                        commitment, payload), expectedCommitment)));
        auditAnchorCommitment.set(commitment);
    }

    private static zeroecho.pki.api.audit.AuditChainHead decodeAuditAnchor(
            ServerControlStore.ProtocolRecord record) {
        String payload = new String(record.payload(), java.nio.charset.StandardCharsets.UTF_8);
        int separator = payload.indexOf('\n');
        if (separator < 0) {
            throw new IllegalStateException("Audit anchor record is malformed");
        }
        return new zeroecho.pki.api.audit.AuditChainHead(Long.parseLong(payload.substring(0, separator)),
                payload.substring(separator + 1));
    }

    @Override
    public void close() throws Exception {
        closeFromServerWorker(false);
    }

    void closeFromServerWorker(boolean workerThread) throws Exception {
        closeGate.close(workerThread, this::quiesce, this::closeAttempt);
    }

    private void quiesce() {
        state.compareAndSet(State.OPEN, State.CLOSING);
    }

    private Throwable closeAttempt() {
        quiesce();
        Throwable primary = null;
        if (closeAuditAttempted.compareAndSet(false, true)) {
            try {
                audit.record("REALM_CLOSE", "system", Optional.empty(),
                        Map.of("realm", configuration.realmId().value()));
                advanceAuditAnchorOnClose();
            } catch (Throwable failure) {
                primary = failure;
            }
        }
        if (backupTransfers != null) {
            try { backupTransfers.close(); }
            catch (Throwable failure) { return preferFailure(failure, primary); }
        }
        if (enrollmentRuntime != null) {
            if (enrollmentCoordinator != null) {
                try { enrollmentCoordinator.close(); }
                catch (Throwable failure) { return preferFailure(failure, primary); }
            }
            try { enrollmentRuntime.close(); }
            catch (Throwable failure) { return preferFailure(failure, primary); }
        }
        if (!sessionClosed.get()) {
            try {
                session.close();
                sessionClosed.set(true);
            } catch (Throwable failure) {
                return preferFailure(failure, primary);
            }
        }
        if (!controlClosed.get()) {
            try {
                control.close();
                controlClosed.set(true);
            } catch (Throwable failure) {
                primary = suppress(primary, failure);
            }
        }
        if (primary == null) {
            state.set(State.CLOSED);
        }
        return primary;
    }

    private void requireOpen() {
        if (state.get() != State.OPEN) throw new IllegalStateException("Server realm is not open");
    }

    private static DurableTransactionalMetadataStore openControl(ServerRealmConfiguration configuration) {
        try {
            if (Files.exists(configuration.controlLogPath())) {
                DurableTransactionalMetadataStore opened = DurableTransactionalMetadataStore.open(
                        configuration.controlLogPath(), OptionalLong.of(1_048_576));
                if (!opened.id().equals(configuration.controlStoreId())) {
                    opened.close();
                    throw new IllegalStateException("Server-control store identity differs");
                }
                return opened;
            }
            return DurableTransactionalMetadataStore.create(configuration.controlLogPath(),
                    configuration.controlStoreId(), OptionalLong.of(1_048_576));
        } catch (IOException failure) {
            throw new IllegalStateException("Server-control metadata authority cannot be opened");
        }
    }

    private static void validateExposure(AuthorityExposurePolicy exposure, PkiSession session) {
        if (exposure.mode() == AuthorityExposurePolicy.Mode.EXPLICIT_AUTHORITIES) {
            for (zeroecho.pki.api.PkiId authorityId : exposure.authorityIds()) {
                PkiOperationOutcome outcome = session.operations().execute(
                        new PkiOperation.InspectAuthority(authorityId), zeroecho.core.io.CancellationSignal.NONE);
                if (!(outcome instanceof PkiOperationOutcome.Completed)) {
                    throw new IllegalStateException("Configured authority exposure contains an unavailable authority");
                }
            }
        }
    }

    private static void closeAfterFailure(PkiSession session, AuditSink audit, ServerControlStore control,
            Throwable primary) {
        Throwable result = closeOne(session, primary);
        if (session == null) result = closeOne(audit, result);
        closeOne(control, result);
    }

    private static Throwable closeOne(AutoCloseable resource, Throwable primary) {
        if (resource == null) return primary;
        try {
            resource.close();
        } catch (Throwable failure) {
            return suppress(primary, failure);
        }
        return primary;
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals") // Suppression must not attach a Throwable to itself.
    private static Throwable suppress(Throwable primary, Throwable failure) {
        if (primary == null) {
            return failure;
        }
        if (primary != failure) {
            primary.addSuppressed(failure);
        }
        return primary;
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals") // Suppression must preserve exact primary identity.
    private static Throwable preferFailure(Throwable failure, Throwable prior) {
        if (prior != null && prior != failure) {
            failure.addSuppressed(prior);
        }
        return failure;
    }

    private static final class SharedAuditSink implements AuditSink,
            zeroecho.pki.api.audit.AuditService, zeroecho.pki.api.audit.AuditIntegrityService {
        private final AuditSink delegate;
        private boolean closed;

        private SharedAuditSink(AuditSink delegate) { this.delegate = Objects.requireNonNull(delegate, "delegate"); }
        @Override public synchronized void record(zeroecho.pki.api.audit.AuditEvent event) {
            if (closed) throw new IllegalStateException("Audit sink is closed");
            delegate.record(event);
        }
        @Override public synchronized void close() {
            if (!closed) { closed = true; delegate.close(); }
        }

        /** @return whether the underlying sink supports bounded search and hash-chain verification */
        synchronized boolean supportsQuery() {
            return delegate instanceof zeroecho.pki.api.audit.AuditService
                    && delegate instanceof zeroecho.pki.api.audit.AuditIntegrityService;
        }

        // Reads are serialized against writes so a bounded admin query never races an in-progress append.
        @Override public synchronized java.util.List<zeroecho.pki.api.audit.AuditEvent> search(
                zeroecho.pki.api.audit.AuditQuery query) {
            if (closed) throw new IllegalStateException("Audit sink is closed");
            return ((zeroecho.pki.api.audit.AuditService) delegate).search(query);
        }
        @Override public synchronized Optional<zeroecho.pki.api.audit.AuditEvent> get(
                zeroecho.pki.api.PkiId eventId) {
            if (closed) throw new IllegalStateException("Audit sink is closed");
            return ((zeroecho.pki.api.audit.AuditService) delegate).get(eventId);
        }
        @Override public synchronized zeroecho.pki.api.audit.AuditIntegrityReport verifyIntegrity(
                Optional<zeroecho.pki.api.audit.AuditChainHead> expectedHead) {
            if (closed) throw new IllegalStateException("Audit sink is closed");
            return ((zeroecho.pki.api.audit.AuditIntegrityService) delegate).verifyIntegrity(expectedHead);
        }
        @Override public synchronized zeroecho.pki.api.audit.AuditIntegrityReport verifyAnchoredPrefix(
                zeroecho.pki.api.audit.AuditChainHead anchor) {
            if (closed) throw new IllegalStateException("Audit sink is closed");
            return ((zeroecho.pki.api.audit.AuditIntegrityService) delegate).verifyAnchoredPrefix(anchor);
        }
    }
}
