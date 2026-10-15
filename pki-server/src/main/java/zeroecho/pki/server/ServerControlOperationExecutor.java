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

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import java.util.Base64;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.BackupService;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.AuditIntegrityReport;
import zeroecho.pki.api.audit.AuditIntegrityService;
import zeroecho.pki.api.audit.AuditService;
import zeroecho.pki.application.PkiOperationFailure;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.acme.AcmeService;
import zeroecho.pki.server.acme.AcmeState;

/** Sole closed dispatcher for transport-neutral server-control operations. */
@SuppressWarnings({ "PMD.CouplingBetweenObjects", "PMD.ExcessiveParameterList",
        "PMD.ControlStatementBraces", "PMD.CyclomaticComplexity", "PMD.TooManyMethods" })
public final class ServerControlOperationExecutor {
    private static final String FIELD_STATE = "state";
    private static final String FIELD_EXPIRES_AT = "expiresAt";
    private static final String TEXT_SERVICE = "service";
    private static final String TEXT_ITEMS = "items";
    private static final String TEXT_NEXT_OFFSET = "nextOffset";
    private static final String TEXT_HAS_MORE = "hasMore";
    private static final String TEXT_AUTHORITY_ID = "authorityId";

    private static final String DISPLAY_NAME = "displayName";

    private final zeroecho.pki.application.PkiOperationExecutor pkiExecutor;
    private final RealmId realmId;
    private final AuthorityExposurePolicy exposure;
    private final ServerControlStore store;
    private final RoleTemplateCatalog roles;
    private final AuthorizationEngine authorization;
    private final ApprovalService approvals;
    private final BreakGlassService breakGlass;
    private final DisclosureService disclosure;
    private final CredentialPublicationGate credentialPublication;
    private final AuditorViews auditorViews;
    private final Optional<RepositoryAliasService> repositoryAliases;
    private final OperationSecurityDescriptors descriptors;
    private final Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> approvalPolicies;
    private final java.util.concurrent.atomic.AtomicReference<AcmeService> acme = new java.util.concurrent.atomic.AtomicReference<>();
    private final java.util.concurrent.atomic.AtomicReference<OcspResponderService> ocsp = new java.util.concurrent.atomic.AtomicReference<>();
    private final java.util.concurrent.atomic.AtomicReference<zeroecho.pki.server.est.EstService> est = new java.util.concurrent.atomic.AtomicReference<>();
    private final java.util.concurrent.atomic.AtomicReference<zeroecho.pki.server.scep.ScepService> scep = new java.util.concurrent.atomic.AtomicReference<>();
    private final java.util.concurrent.atomic.AtomicReference<zeroecho.pki.server.cmp.CmpService> cmp = new java.util.concurrent.atomic.AtomicReference<>();
    private final java.util.concurrent.atomic.AtomicReference<zeroecho.pki.server.enrollment.EnrollmentProfileService> enrollmentProfiles = new java.util.concurrent.atomic.AtomicReference<>();
    private final java.util.concurrent.atomic.AtomicReference<zeroecho.pki.server.enrollment.EnrollmentCoordinator> enrollment = new java.util.concurrent.atomic.AtomicReference<>();
    private final java.util.concurrent.atomic.AtomicReference<AuditService> auditSearch = new java.util.concurrent.atomic.AtomicReference<>();
    private final java.util.concurrent.atomic.AtomicReference<AuditIntegrityService> auditIntegrity = new java.util.concurrent.atomic.AtomicReference<>();
    private final java.util.concurrent.atomic.AtomicReference<BackupService> backup = new java.util.concurrent.atomic.AtomicReference<>();
    private final java.util.concurrent.atomic.AtomicReference<BackupTransferService> transfers = new java.util.concurrent.atomic.AtomicReference<>();

    /**
     * Creates the one control dispatcher over existing durable authorities.
     *
     * <p>The credential-publication gate must use the same disclosure service
     * supplied to this constructor.</p>
     *
     * @param pkiExecutor realm-owned executor supplying typed safe runtime choices
     * @param realmId exact realm identity
     * @param exposure authority exposure policy for the realm
     * @param store durable server-control store
     * @param roles role-template catalog
     * @param authorization authorization engine
     * @param approvals durable approval service
     * @param breakGlass emergency-access service
     * @param disclosure durable disclosure service
     * @param credentialPublication authoritative credential-publication gate
     * @param auditorViews audit-view service
     * @param repositoryAliases optional repository-alias capability
     * @param descriptors closed operation-security descriptor catalog
     * @param approvalPolicies approval policy by operation category
     */
    public ServerControlOperationExecutor(zeroecho.pki.application.PkiOperationExecutor pkiExecutor, RealmId realmId, AuthorityExposurePolicy exposure,
            ServerControlStore store, RoleTemplateCatalog roles, AuthorizationEngine authorization,
            ApprovalService approvals, BreakGlassService breakGlass, DisclosureService disclosure,
            CredentialPublicationGate credentialPublication, AuditorViews auditorViews,
            Optional<RepositoryAliasService> repositoryAliases,
            OperationSecurityDescriptors descriptors,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> approvalPolicies) {
        this.pkiExecutor = Objects.requireNonNull(pkiExecutor, "pkiExecutor");
        this.realmId = Objects.requireNonNull(realmId, "realmId");
        this.exposure = Objects.requireNonNull(exposure, "exposure");
        this.store = Objects.requireNonNull(store, "store");
        this.roles = Objects.requireNonNull(roles, "roles");
        this.authorization = Objects.requireNonNull(authorization, "authorization");
        this.approvals = Objects.requireNonNull(approvals, "approvals");
        this.breakGlass = Objects.requireNonNull(breakGlass, "breakGlass");
        this.disclosure = Objects.requireNonNull(disclosure, "disclosure");
        this.credentialPublication = Objects.requireNonNull(credentialPublication, "credentialPublication");
        this.auditorViews = Objects.requireNonNull(auditorViews, "auditorViews");
        this.repositoryAliases = Objects.requireNonNull(repositoryAliases, "repositoryAliases");
        this.descriptors = Objects.requireNonNull(descriptors, "descriptors");
        this.approvalPolicies = Map.copyOf(Objects.requireNonNull(approvalPolicies, "approvalPolicies"));
    }

    /**
     * Executes exactly one already-authorized control operation synchronously.
     *
     * @param operation exact control operation
     * @param actorPrincipalId authenticated actor identity
     * @param authorizedResource resource proven by gateway authorization
     * @param approvalId optional approval identity presented for the operation
     * @param cancellation cancellation signal checked before dispatch
     * @return finite control-operation outcome
     */
    public ServerControlOperationOutcome execute(ServerControlOperation operation, String actorPrincipalId,
            Permission.Resource authorizedResource, Optional<String> approvalId, CancellationSignal cancellation) {
        return executeAuthorized(operation, actorPrincipalId, authorizedResource, approvalId, Optional.empty(),
                cancellation);
    }

    /** Executes one gateway-authorized control operation with proven target approval eligibility. */
    /* default */ ServerControlOperationOutcome executeAuthorized(ServerControlOperation operation,
            String actorPrincipalId,
            Permission.Resource authorizedResource, Optional<String> approvalId,
            Optional<OperationSecurityDescriptors.ApprovalCategory> approvedTargetCategory,
            CancellationSignal cancellation) {
        return executeAuthorized(operation, actorPrincipalId, authorizedResource, approvalId,
                approvedTargetCategory, cancellation, null);
    }

    /* default */ ServerControlOperationOutcome executeAuthorized(ServerControlOperation operation,
            String actorPrincipalId, Permission.Resource authorizedResource, Optional<String> approvalId,
            Optional<OperationSecurityDescriptors.ApprovalCategory> approvedTargetCategory,
            CancellationSignal cancellation, BackupTransferChannel channel) {
        return executeAuthorized(operation, new AdministrativeDecisionActor(actorPrincipalId, Optional.empty()),
                authorizedResource, approvalId, approvedTargetCategory, cancellation, channel);
    }

    /* default */ ServerControlOperationOutcome executeAuthorized(ServerControlOperation operation,
            AdministrativeDecisionActor actor, Permission.Resource authorizedResource, Optional<String> approvalId,
            Optional<OperationSecurityDescriptors.ApprovalCategory> approvedTargetCategory,
            CancellationSignal cancellation, BackupTransferChannel channel) {
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(actor, "actor");
        actor.credentialEvidence().ifPresent(evidence -> {
            if (!realmId.equals(evidence.realmId())) throw new IllegalArgumentException("Decision evidence realm differs");
        });
        Objects.requireNonNull(authorizedResource, "authorizedResource");
        Optional<OperationSecurityDescriptors.ApprovalCategory> exactTargetCategory = Objects.requireNonNull(
                approvedTargetCategory, "approvedTargetCategory");
        if (Objects.requireNonNull(cancellation, "cancellation").isCancelled()) {
            return failure(operation, PkiOperationFailure.CANCELLED, "CONTROL_OPERATION_CANCELLED");
        }
        try {
            return dispatch(operation, actor, authorizedResource,
                    Objects.requireNonNull(approvalId, "approvalId"), exactTargetCategory, cancellation, channel);
        } catch (java.io.IOException failure) {
            String code = failure.getMessage();
            return failure(operation, PkiOperationFailure.CONFLICT,
                    code != null && code.matches("BACKUP_[A-Z_]+") ? code : "BACKUP_TRANSFER_OUTCOME_REQUIRES_STATUS");
        } catch (java.util.concurrent.CancellationException cancelled) {
            return failure(operation, PkiOperationFailure.CANCELLED, "CONTROL_OPERATION_CANCELLED");
        } catch (IllegalArgumentException unavailable) {
            return failure(operation, PkiOperationFailure.NOT_FOUND, "CONTROL_OBJECT_UNAVAILABLE");
        } catch (SecurityException denied) {
            return failure(operation, PkiOperationFailure.POLICY_REJECTION, "CONTROL_POLICY_REJECTED");
        } catch (IllegalStateException conflict) {
            return failure(operation, PkiOperationFailure.CONFLICT,
                    "BACKUP_LEGACY_LIMIT".equals(conflict.getMessage())
                            ? "BACKUP_LEGACY_LIMIT_USE_STREAMING" : "CONTROL_STATE_CONFLICT");
        }
    }

    /**
     * Installs the explicitly configured ACME capability exactly once before listener readiness.
     *
     * @param service realm-owned ACME service
     * @throws IllegalStateException if an ACME service is already installed
     */
    public void installAcme(AcmeService service) {
        if (!acme.compareAndSet(null, Objects.requireNonNull(service, TEXT_SERVICE))) {
            throw new IllegalStateException("ACME administration capability is already installed");
        }
    }

    /**
     * Installs the realm-owned durable OCSP responder capability exactly once.
     *
     * @param service realm-owned OCSP responder service
     * @throws IllegalStateException if an OCSP service is already installed
     */
    public void installOcsp(OcspResponderService service) {
        if (!ocsp.compareAndSet(null, Objects.requireNonNull(service, TEXT_SERVICE))) {
            throw new IllegalStateException("OCSP administration capability is already installed");
        }
    }

    /**
     * Installs the EST RFC 7030 endpoint registry exactly once before listener readiness.
     *
     * @param service realm-owned EST service
     * @throws IllegalStateException if an EST service is already installed
     */
    public void installEst(zeroecho.pki.server.est.EstService service) {
        if (!est.compareAndSet(null, Objects.requireNonNull(service, TEXT_SERVICE))) {
            throw new IllegalStateException("EST administration capability is already installed");
        }
    }

    /**
     * Installs the SCEP RFC 8894 endpoint registry exactly once before listener readiness.
     *
     * @param service realm-owned SCEP service
     * @throws IllegalStateException if a SCEP service is already installed
     */
    public void installScep(zeroecho.pki.server.scep.ScepService service) {
        if (!scep.compareAndSet(null, Objects.requireNonNull(service, TEXT_SERVICE))) {
            throw new IllegalStateException("SCEP administration capability is already installed");
        }
    }

    /**
     * Installs the CMP RFC 4210/9480 endpoint registry exactly once before listener readiness.
     *
     * @param service realm-owned CMP service
     * @throws IllegalStateException if a CMP service is already installed
     */
    public void installCmp(zeroecho.pki.server.cmp.CmpService service) {
        if (!cmp.compareAndSet(null, Objects.requireNonNull(service, TEXT_SERVICE))) {
            throw new IllegalStateException("CMP administration capability is already installed");
        }
    }

    /** Whether the configured service for a protocol operation is installed. */
    /* default */ boolean protocolAvailable(String operationId) {
        if (operationId.startsWith("est.")) return est.get() != null;
        if (operationId.startsWith("scep.")) return scep.get() != null;
        return !operationId.startsWith("cmp.") || cmp.get() != null;
    }

    /**
     * Installs the enrollment profile registry exactly once before listener readiness.
     *
     * @param service realm-owned enrollment profile service
     * @throws IllegalStateException if an enrollment profile service is already installed
     */
    public void installEnrollmentProfiles(zeroecho.pki.server.enrollment.EnrollmentProfileService service) {
        if (!enrollmentProfiles.compareAndSet(null, Objects.requireNonNull(service, TEXT_SERVICE))) {
            throw new IllegalStateException("Enrollment profile administration capability is already installed");
        }
    }

    /**
     * Installs the realm-owned durable protocol approval coordinator exactly once.
     * @param service validated coordinator
     */
    public void installEnrollmentCoordinator(zeroecho.pki.server.enrollment.EnrollmentCoordinator service) {
        if (!enrollment.compareAndSet(null, Objects.requireNonNull(service, "service"))) throw new IllegalStateException("Enrollment coordinator already installed");
    }

    /**
     * Resolves scope from the retained request before gateway authorization.
     * @param id persisted enrollment identity
     * @return exact authoritative realm/authority/issuer/profile scope
     */
    public Permission.Scope enrollmentScope(String id) {
        return zeroecho.pki.server.enrollment.EnrollmentCoordinator.scope(enrollment().find(id)
                .orElseThrow(() -> new IllegalStateException("Enrollment request is unavailable")));
    }

    /**
     * Installs the queryable/verifiable audit capability exactly once.
     *
     * <p>Only invoked when the configured audit sink supports bounded search and
     * hash-chain verification; otherwise the audit admin operations fail closed as
     * unsupported.</p>
     *
     * @param search bounded audit-log search capability
     * @param integrity audit-log integrity-verification capability
     */
    public void installAudit(AuditService search, AuditIntegrityService integrity) {
        Objects.requireNonNull(search, "search");
        Objects.requireNonNull(integrity, "integrity");
        if (!auditSearch.compareAndSet(null, search)) {
            throw new IllegalStateException("Audit query capability is already installed");
        }
        auditIntegrity.set(integrity);
    }

    /**
     * Installs the backup capability exactly once.
     *
     * @param backupService backup service backed by the store
     * @throws NullPointerException if {@code backupService} is {@code null}
     * @throws IllegalStateException if a backup service is already installed
     */
    public void installBackup(BackupService backupService) {
        Objects.requireNonNull(backupService, "backupService");
        if (!backup.compareAndSet(null, backupService)) {
            throw new IllegalStateException("Backup capability is already installed");
        }
    }

    /* default */ void installBackupTransfers(BackupTransferService service) {
        if (!transfers.compareAndSet(null, Objects.requireNonNull(service))) {
            throw new IllegalStateException("Backup transfer service already installed");
        }
    }

    /* default */ boolean backupTransfersAvailable() { return transfers.get() != null; }

    /* default */ ServerControlOperation.BackupArtifactCommand bindBackup(String owner,
            ServerControlOperation.BackupArtifactCommand operation) {
        try {
            BackupTransferService service = transfers(); // NOPMD CloseResource - Borrowed realm transfer service; its lifecycle owner closes it.
            return new ServerControlOperation.BackupArtifactCommand(operation.action(), operation.artifactHandle(),
                    Optional.of(service.commitment(service.bind(owner, operation))));
        } catch (java.io.IOException failure) {
            throw new SecurityException("Backup artifact unavailable"); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
    }

    private BackupTransferService transfers() {
        BackupTransferService service = transfers.get();
        if (service == null) throw new IllegalStateException("Backup transfer is disabled");
        return service;
    }

    /** Resolves the authoritative credential authorization resource before admission. */
    /* default */ Permission.Resource credentialPublicationResource(
            ServerControlOperation.EnrollCredentialPublication operation) {
        return credentialPublication.publicationResource(realmId, operation.credentialId(),
                operation.ownerPrincipalId().map(DisclosureService.Owner::principal));
    }

    /** Resolves exact ACME authority/profile scope from durable records. */
    /* default */ Permission.Scope acmeScope(ServerControlOperation operation) {
        AcmeState.Directory directory = switch (operation) {
            case ServerControlOperation.RegisterAcmeDirectory ignored -> null;
            case ServerControlOperation.InspectAcmeDirectory value -> acme().directory(value.directoryId());
            case ServerControlOperation.SetAcmeDirectoryActive value -> acme().directory(value.directoryId());
            case ServerControlOperation.InspectAcmeAccount value -> acme().directory(acme().account(value.accountId()).directoryId());
            case ServerControlOperation.DeactivateAcmeAccount value -> acme().directory(acme().account(value.accountId()).directoryId());
            default -> null;
        };
        if (operation instanceof ServerControlOperation.RegisterAcmeDirectory registration) {
            return new Permission.Scope(realmId, Optional.of(registration.registration().authorityId()),
                    Optional.empty(), Optional.of(registration.registration().profileId()));
        }
        if (directory == null) return new Permission.Scope(realmId, Optional.empty(), Optional.empty(), Optional.empty());
        return new Permission.Scope(realmId, Optional.of(directory.authorityId()), Optional.empty(),
                Optional.of(directory.profile().profileId()));
    }

    /** Resolves the exact active profile precondition before approval canonicalization. */
    /* default */ ServerControlOperation.RegisterAcmeDirectory bindAcmeDirectoryRegistration(
            ServerControlOperation.RegisterAcmeDirectory operation) {
        AcmeService service = acme();
        return new ServerControlOperation.RegisterAcmeDirectory(operation.registration(),
                Optional.of(service.resolveDirectoryProfilePrecondition(operation.registration())));
    }

    private ServerControlOperationOutcome dispatch(ServerControlOperation operation, AdministrativeDecisionActor decisionActor,
            Permission.Resource authorizedResource, Optional<String> approvalId,
            Optional<OperationSecurityDescriptors.ApprovalCategory> approvedTargetCategory, CancellationSignal cancellation,
            BackupTransferChannel channel) throws java.io.IOException {
        String actor = decisionActor.principalId();
        return switch (operation) {
            case ServerControlOperation.ConfigurationChoices value -> ordinary(operation, configurationChoices(value, cancellation));
            case ServerControlOperation.ListCapabilities value -> ordinary(operation, capabilities(value, cancellation));
            case ServerControlOperation.RegisterPrincipal value -> ordinary(operation, register(value));
            case ServerControlOperation.InspectPrincipal value -> ordinary(operation,
                    principal(store.requirePrincipal(value.principalId())));
            case ServerControlOperation.ListPrincipals value -> ordinary(operation,
                    page(store.principals(value.offset(), value.limit()), ServerControlOperationExecutor::principal));
            case ServerControlOperation.SetPrincipalEnabled value -> ordinary(operation,
                    principal(changePrincipalEnabled(value)));
            case ServerControlOperation.ListRoleTemplates ignored -> ordinary(operation, templatesValue());
            case ServerControlOperation.InspectRoleTemplate value -> ordinary(operation,
                    template(roles.require(value.templateId(), value.version())));
            case ServerControlOperation.CreateRoleAssignment value -> ordinary(operation,
                    assignment(createAssignment(value.assignment())));
            case ServerControlOperation.InspectRoleAssignment value -> ordinary(operation,
                    assignment(store.requireAssignment(value.assignmentId())));
            case ServerControlOperation.ListRoleAssignments value -> ordinary(operation,
                    scopedPage(store.assignments(value.offset(), value.limit()), authorizedResource.scope(),
                            RoleTemplateCatalog.Assignment::scope, ServerControlOperationExecutor::assignment));
            case ServerControlOperation.RevokeRoleAssignment value -> ordinary(operation,
                    assignment(revokeAssignment(value.assignmentId())));
            case ServerControlOperation.CreateGrant value -> ordinary(operation,
                    grant(createGrant(value.grant())));
            case ServerControlOperation.InspectGrant value -> ordinary(operation,
                    grant(store.requireGrant(value.grantId())));
            case ServerControlOperation.ListGrants value -> ordinary(operation,
                    scopedPage(store.grants(value.offset(), value.limit()), authorizedResource.scope(),
                            Permission.Grant::scope, ServerControlOperationExecutor::grant));
            case ServerControlOperation.RevokeGrant value -> ordinary(operation, grant(revokeGrant(value.grantId())));
            case ServerControlOperation.EvaluateAuthorization value -> ordinary(operation, evaluate(value));
            case ServerControlOperation.RequestApproval value -> ordinary(operation,
                    approval(request(value, actor, approvedTargetCategory)));
            case ServerControlOperation.InspectApproval value -> ordinary(operation,
                    approval(approvals.requireCurrent(value.approvalId())));
            case ServerControlOperation.ListApprovals value -> ordinary(operation,
                    approvalPage(store.approvals(value.offset(), value.limit()), authorizedResource.scope(), value));
            case ServerControlOperation.DecideApproval value -> ordinary(operation,
                    approval(approvals.decide(value.approvalId(), actor, value.choice(), value.justification())));
            case ServerControlOperation.CancelApproval value -> ordinary(operation,
                    approval(approvals.cancel(value.approvalId(), actor)));
            case ServerControlOperation.CreateBreakGlass value -> ordinary(operation,
                    breakGlass(breakGlass.create(value.breakGlassId(), value.principalId(), value.grant(),
                            value.reason(), actor, approvalId, value.expiresAt())));
            case ServerControlOperation.ActivateBreakGlass value -> ordinary(operation,
                    breakGlass(breakGlass.activatePending(value.breakGlassId(), actor, approvalId)));
            case ServerControlOperation.InspectBreakGlass value -> ordinary(operation,
                    breakGlass(breakGlass.requireCurrent(value.breakGlassId())));
            case ServerControlOperation.ListBreakGlass value -> ordinary(operation,
                    scopedPage(store.breakGlass(value.offset(), value.limit()), authorizedResource.scope(),
                            item -> item.grant().scope(), ServerControlOperationExecutor::breakGlass));
            case ServerControlOperation.RevokeBreakGlass value -> ordinary(operation,
                    breakGlass(breakGlass.revoke(value.breakGlassId(), actor)));
            case ServerControlOperation.InspectDisclosure value -> ordinary(operation,
                    disclosure(store.requireDisclosure(value.objectId())));
            case ServerControlOperation.SetDisclosure value -> ordinary(operation,
                    disclosure(disclosure.change(value.objectId(), value.policy(), true, approvalId.isPresent(), actor)));
            case ServerControlOperation.EnrollCredentialPublication value -> ordinary(operation,
                    disclosure(credentialPublication.register(value.credentialId(),
                            value.ownerPrincipalId().map(DisclosureService.Owner::principal),
                            new CredentialPublicationGate.AuditActor(actor))));
            case ServerControlOperation.IssueCapability value -> capability(operation,
                    disclosure.issueCapability(value.objectId(), value.expiresAt(), actor));
            case ServerControlOperation.RevokeCapability value -> ordinary(operation,
                    capability(disclosure.revokeCapability(value.capabilityId(), actor)));
            case ServerControlOperation.InspectAuditView value -> ordinary(operation, auditView(value, actor));
            case ServerControlOperation.SearchAudit value -> ordinary(operation, auditSearch(value));
            case ServerControlOperation.VerifyAuditIntegrity value -> ordinary(operation, auditVerify(value));
            case ServerControlOperation.ExportBackup value -> ordinary(operation, exportBackup(value));
            case ServerControlOperation.ReserveBackupUpload value -> ordinary(operation,
                    artifactValue(transfers().reserveUpload(actor, value.backupId(), value.length(), value.sha256())));
            case ServerControlOperation.ExportBackupStream value -> ordinary(operation,
                    artifactValue(transfers().export(actor, new zeroecho.pki.api.backup.BackupRequest(value.label(), emptyBackupAttributes()))));
            case ServerControlOperation.BackupArtifactCommand value -> ordinary(operation, transfer(actor, value, channel));
            case ServerControlOperation.VerifyBackup value -> ordinary(operation, verifyBackup(value));
            case ServerControlOperation.ExecuteRestore _ ->
                    failure(operation, PkiOperationFailure.POLICY_REJECTION, "BACKUP_RESTORE_UNAVAILABLE");
            case ServerControlOperation.InspectRepositoryAlias value -> ordinary(operation,
                    alias(aliases().require(value.authorityId(), value.type())));
            case ServerControlOperation.ListRepositoryAliases value -> ordinary(operation,
                    page(aliases().list(value.offset(), value.limit()), ServerControlOperationExecutor::alias));
            case ServerControlOperation.SetRepositoryAlias value -> ordinary(operation,
                    alias(publishAlias(value, actor)));
            case ServerControlOperation.RemoveRepositoryAlias value -> ordinary(operation,
                    alias(aliases().remove(value.authorityId(), value.type(), value.expectedCurrentCommitment(), actor)));
            case ServerControlOperation.RegisterAcmeDirectory value -> ordinary(operation,
                    directory(acme().registerDirectory(value.registration(), value.profilePrecondition()
                            .orElseThrow(() -> new IllegalStateException(
                                    "ACME directory profile precondition is unresolved")))));
            case ServerControlOperation.InspectAcmeDirectory value -> ordinary(operation,
                    directory(acme().directory(value.directoryId())));
            case ServerControlOperation.ListAcmeDirectories value -> ordinary(operation,
                    page(acme().directories(value.offset(), value.limit()), ServerControlOperationExecutor::directory));
            case ServerControlOperation.SetAcmeDirectoryActive value -> ordinary(operation,
                    directory(value.active() ? acme().activateDirectory(value.directoryId())
                            : acme().deactivateDirectory(value.directoryId())));
            case ServerControlOperation.InspectAcmeAccount value -> ordinary(operation,
                    account(acme().account(value.accountId())));
            case ServerControlOperation.ListAcmeAccounts value -> ordinary(operation,
                    page(acme().accounts(value.offset(), value.limit()), ServerControlOperationExecutor::account));
            case ServerControlOperation.DeactivateAcmeAccount value -> ordinary(operation,
                    account(acme().deactivateAccount(value.accountId())));
            case ServerControlOperation.RegisterOcspResponder value -> ordinary(operation,
                    responder(ocsp().register(value.registration())));
            case ServerControlOperation.InspectOcspResponder value -> ordinary(operation,
                    responder(ocsp().require(value.responderId())));
            case ServerControlOperation.ListOcspResponders value -> ordinary(operation,
                    page(ocsp().list(value.offset(), value.limit()), ServerControlOperationExecutor::responder));
            case ServerControlOperation.SetOcspResponderActive value -> ordinary(operation,
                    responder(ocsp().setActive(value.responderId(), value.active())));
            case ServerControlOperation.RegisterEstEndpoint value -> {
                est().register(value.endpoint());
                yield ordinary(operation, estEndpoint(value.endpoint()));
            }
            case ServerControlOperation.DeregisterEstEndpoint value -> ordinary(operation,
                    est().deregister(value.label())
                            .map(ServerControlOperationExecutor::estEndpoint)
                            .orElseThrow(() -> new IllegalArgumentException("EST endpoint not found: " + value.label())));
            case ServerControlOperation.InspectEstEndpoint value -> ordinary(operation,
                    est().find(value.label())
                            .map(ServerControlOperationExecutor::estEndpoint)
                            .orElseThrow(() -> new IllegalArgumentException("EST endpoint not found: " + value.label())));
            case ServerControlOperation.ListEstEndpoints value -> {
                List<zeroecho.pki.server.est.EstEndpoint> all = est().list();
                List<zeroecho.pki.server.est.EstEndpoint> slice =
                        all.stream().skip(value.offset()).limit(value.limit()).toList();
                boolean hasMore = all.size() > value.offset() + slice.size();
                yield ordinary(operation, object(TEXT_ITEMS,
                        new PkiOperationValue.ListValue(slice.stream()
                                .<PkiOperationValue>map(ServerControlOperationExecutor::estEndpoint).toList()),
                        TEXT_NEXT_OFFSET, integer(value.offset() + slice.size()),
                        TEXT_HAS_MORE, bool(hasMore)));
            }
            case ServerControlOperation.RegisterScepEndpoint value -> {
                scep().register(value.endpoint());
                yield ordinary(operation, scepEndpoint(value.endpoint()));
            }
            case ServerControlOperation.DeregisterScepEndpoint value -> ordinary(operation,
                    scep().deregister(value.label())
                            .map(ServerControlOperationExecutor::scepEndpoint)
                            .orElseThrow(() -> new IllegalArgumentException("SCEP endpoint not found: " + value.label())));
            case ServerControlOperation.InspectScepEndpoint value -> ordinary(operation,
                    scep().find(value.label())
                            .map(ServerControlOperationExecutor::scepEndpoint)
                            .orElseThrow(() -> new IllegalArgumentException("SCEP endpoint not found: " + value.label())));
            case ServerControlOperation.ListScepEndpoints value -> {
                List<zeroecho.pki.server.scep.ScepEndpoint> allScep = scep().list();
                List<zeroecho.pki.server.scep.ScepEndpoint> scepSlice =
                        allScep.stream().skip(value.offset()).limit(value.limit()).toList();
                boolean scepHasMore = allScep.size() > value.offset() + scepSlice.size();
                yield ordinary(operation, object(TEXT_ITEMS,
                        new PkiOperationValue.ListValue(scepSlice.stream()
                                .<PkiOperationValue>map(ServerControlOperationExecutor::scepEndpoint).toList()),
                        TEXT_NEXT_OFFSET, integer(value.offset() + scepSlice.size()),
                        TEXT_HAS_MORE, bool(scepHasMore)));
            }
            case ServerControlOperation.RegisterCmpEndpoint value -> {
                cmp().register(value.endpoint());
                yield ordinary(operation, cmpEndpoint(value.endpoint()));
            }
            case ServerControlOperation.DeregisterCmpEndpoint value -> ordinary(operation,
                    cmp().deregister(value.label())
                            .map(ServerControlOperationExecutor::cmpEndpoint)
                            .orElseThrow(() -> new IllegalArgumentException("CMP endpoint not found: " + value.label())));
            case ServerControlOperation.InspectCmpEndpoint value -> ordinary(operation,
                    cmp().find(value.label())
                            .map(ServerControlOperationExecutor::cmpEndpoint)
                            .orElseThrow(() -> new IllegalArgumentException("CMP endpoint not found: " + value.label())));
            case ServerControlOperation.ListCmpEndpoints value -> {
                List<zeroecho.pki.server.cmp.CmpEndpoint> allCmp = cmp().list();
                List<zeroecho.pki.server.cmp.CmpEndpoint> cmpSlice =
                        allCmp.stream().skip(value.offset()).limit(value.limit()).toList();
                boolean cmpHasMore = allCmp.size() > value.offset() + cmpSlice.size();
                yield ordinary(operation, object(TEXT_ITEMS,
                        new PkiOperationValue.ListValue(cmpSlice.stream()
                                .<PkiOperationValue>map(ServerControlOperationExecutor::cmpEndpoint).toList()),
                        TEXT_NEXT_OFFSET, integer(value.offset() + cmpSlice.size()),
                        TEXT_HAS_MORE, bool(cmpHasMore)));
            }
            case ServerControlOperation.RegisterEnrollmentProfile value -> {
                enrollmentProfiles().register(value.profile());
                yield ordinary(operation, enrollmentProfile(value.profile()));
            }
            case ServerControlOperation.InspectEnrollmentRequest value -> ordinary(operation, inspectEnrollmentRequest(value.id()));
            case ServerControlOperation.ListEnrollmentRequests value -> ordinary(operation, scopedPage(enrollment().list(value.offset(), value.limit()),
                    authorizedResource.scope(), zeroecho.pki.server.enrollment.EnrollmentCoordinator::scope, ServerControlOperationExecutor::enrollmentRequest));
            case ServerControlOperation.DecideEnrollmentRequest value -> ordinary(operation, enrollmentRequest(enrollment().decide(value.id(),
                    value.expectedCommitment(), decisionActor, value.choice(), value.justification())));
            case ServerControlOperation.UpdateEnrollmentProfile value -> ordinary(operation,
                    enrollmentProfile(enrollmentProfiles().update(value.profile())));
            case ServerControlOperation.InspectEnrollmentProfile value -> ordinary(operation,
                    enrollmentProfiles().find(value.id())
                            .map(ServerControlOperationExecutor::enrollmentProfile)
                            .orElseThrow(() -> new IllegalArgumentException("Enrollment profile not found: " + value.id())));
            case ServerControlOperation.ListEnrollmentProfiles value -> {
                ServerControlStore.Page<zeroecho.pki.server.enrollment.EnrollmentProfile> epPage =
                        enrollmentProfiles().list(value.offset(), value.limit());
                yield ordinary(operation, object(TEXT_ITEMS,
                        new PkiOperationValue.ListValue(epPage.values().stream()
                                .<PkiOperationValue>map(ServerControlOperationExecutor::enrollmentProfile).toList()),
                        TEXT_NEXT_OFFSET, integer(epPage.nextOffset()),
                        TEXT_HAS_MORE, bool(epPage.hasMore())));
            }
            case ServerControlOperation.ActivateEnrollmentProfile value -> ordinary(operation,
                    enrollmentProfile(enrollmentProfiles().setState(value.id(),
                            zeroecho.pki.server.enrollment.EnrollmentProfileState.ACTIVE)));
            case ServerControlOperation.SuspendEnrollmentProfile value -> ordinary(operation,
                    enrollmentProfile(enrollmentProfiles().setState(value.id(),
                            zeroecho.pki.server.enrollment.EnrollmentProfileState.SUSPENDED)));
        };
    }

    private PkiOperationValue configurationChoices(ServerControlOperation.ConfigurationChoices query,
            CancellationSignal cancellation) {
        if (!(pkiExecutor instanceof zeroecho.pki.application.PkiConfigurationChoicesSource source)) {
            throw new IllegalStateException("Configuration choice metadata is unavailable");
        }
        zeroecho.pki.application.PkiConfigurationChoicesSource.Choices choices =
                source.configurationChoices(query.limit(), query.after(), cancellation);
        Map<String, PkiOperationValue> keys = new LinkedHashMap<>();
        keys.put(TEXT_ITEMS, new PkiOperationValue.ListValue(choices.keys().stream()
                .<PkiOperationValue>map(key -> object("keyRef", text(key.value()), DISPLAY_NAME, text(key.value()))).toList()));
        keys.put("count", integer(choices.keys().size()));
        keys.put("truncated", bool(choices.nextCursor().isPresent()));
        choices.nextCursor().ifPresent(value -> keys.put("nextCursor", text(value)));
        AcmeService service = acme.get();
        List<PkiOperationValue> challengeProviders = service == null ? List.of()
                : service.configuredChallengeProviders().entrySet().stream().sorted(Map.Entry.comparingByKey())
                        .<PkiOperationValue>map(entry -> object("providerId", text(entry.getKey()), DISPLAY_NAME, text(entry.getKey()),
                                "challengeTypes", new PkiOperationValue.ListValue(entry.getValue().stream()
                                        .map(Enum::name).sorted(). <PkiOperationValue>map(ServerControlOperationExecutor::text).toList())))
                        .toList();
        List<PkiOperationValue> eabProviders = service == null ? List.of()
                : service.configuredEabProviders().stream().sorted()
                        .<PkiOperationValue>map(id -> object("providerId", text(id), DISPLAY_NAME, text(id))).toList();
        return object("formats", new PkiOperationValue.ListValue(choices.formats().stream()
                        .<PkiOperationValue>map(format -> object("formatId", text(format.value()), DISPLAY_NAME,
                                text("x509".equals(format.value()) ? "X.509" : format.value()))).toList()),
                "signingProviders", new PkiOperationValue.ListValue(choices.signingProviders().stream()
                        .<PkiOperationValue>map(id -> object("providerId", text(id), DISPLAY_NAME, text(id))).toList()),
                "publicationTargets", new PkiOperationValue.ListValue(choices.publicationTargets().stream()
                        .sorted(Comparator.comparing(target -> target.type().name() + ":" + target.targetId()))
                        .<PkiOperationValue>map(target -> object("targetType", text(target.type().name()), "targetId", text(target.targetId()),
                                DISPLAY_NAME, text(target.targetId()))).toList()),
                "keys", new PkiOperationValue.ObjectValue(keys),
                "algorithms", new PkiOperationValue.ListValue(choices.algorithms().stream()
                        .<PkiOperationValue>map(id -> object("algorithmId", text(id), DISPLAY_NAME, text(id))).toList()),
                "acmeChallengeProviders", new PkiOperationValue.ListValue(challengeProviders),
                "acmeEabProviders", new PkiOperationValue.ListValue(eabProviders));
    }

    private PkiOperationValue capabilities(ServerControlOperation.ListCapabilities query, CancellationSignal cancellation) {
        // Every row concerns the exact same authoritative object resource already authorized by the gateway.
        List<DisclosureService.Capability> selected = store.selectCapabilities(query.objectId(), query.after(),
                query.limit() + 1, cancellation);
        boolean more = selected.size() > query.limit();
        List<DisclosureService.Capability> rows = selected.subList(0, Math.min(selected.size(), query.limit()));
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        fields.put(TEXT_ITEMS, new PkiOperationValue.ListValue(rows.stream().map(ServerControlOperationExecutor::capability).toList()));
        fields.put("count", integer(rows.size()));
        fields.put("truncated", bool(more));
        if (more) { fields.put("nextCursor", text(rows.getLast().capabilityId())); }
        return new PkiOperationValue.ObjectValue(fields);
    }

    private AcmeService acme() {
        return Optional.ofNullable(acme.get()).orElseThrow(() -> new IllegalStateException("ACME capability unavailable"));
    }

    private OcspResponderService ocsp() {
        return Optional.ofNullable(ocsp.get()).orElseThrow(() -> new IllegalStateException("OCSP capability unavailable"));
    }

    private zeroecho.pki.server.est.EstService est() {
        return Optional.ofNullable(est.get()).orElseThrow(() -> new IllegalStateException("EST capability unavailable"));
    }

    private zeroecho.pki.server.scep.ScepService scep() {
        return Optional.ofNullable(scep.get()).orElseThrow(() -> new IllegalStateException("SCEP capability unavailable"));
    }

    private zeroecho.pki.server.cmp.CmpService cmp() {
        return Optional.ofNullable(cmp.get()).orElseThrow(() -> new IllegalStateException("CMP capability unavailable"));
    }

    private zeroecho.pki.server.enrollment.EnrollmentProfileService enrollmentProfiles() {
        return Optional.ofNullable(enrollmentProfiles.get())
                .orElseThrow(() -> new IllegalStateException("Enrollment profile capability unavailable"));
    }

    private zeroecho.pki.server.enrollment.EnrollmentCoordinator enrollment() {
        return Optional.ofNullable(enrollment.get()).orElseThrow(() -> new IllegalStateException("Enrollment coordinator is unavailable"));
    }

    private static PkiOperationValue enrollmentRequest(zeroecho.pki.server.enrollment.EnrollmentTransaction value) {
        zeroecho.pki.server.enrollment.EnrollmentTransaction.Intent intent = value.intent();
        return new PkiOperationValue.ObjectValue(Map.ofEntries(Map.entry("id", text(value.id())), Map.entry("revision", integer(value.revision())),
                Map.entry(FIELD_STATE, text(value.state().name())), Map.entry("commitment", text(value.commitment())),
                Map.entry("intentCommitment", text(value.intentCommitment())), Map.entry("protocol", text(intent.source().protocol().name())),
                Map.entry("operation", text(intent.operation().name())), Map.entry("requesterType", text(intent.requester().type().name())),
                Map.entry("requesterId", text(intent.requester().actorId())), Map.entry("approvalThreshold", integer(intent.approvalPolicy().map(ApprovalService.Policy::threshold).orElse(0))),
                Map.entry("predecessorId", text(intent.predecessorId().map(zeroecho.pki.api.PkiId::value).orElse(""))),
                Map.entry("endpoint", text(intent.source().label())), Map.entry("enrollmentProfileId", text(intent.source().enrollmentProfileId())),
                Map.entry("authorityId", text(intent.authorityId().value())), Map.entry("issuerId", text(intent.issuerId().value())),
                Map.entry("profileId", text(intent.profile().profileId())), Map.entry("profileVersion", integer(intent.profile().profileVersion())),
                Map.entry("requestId", text(intent.requestId().value())), Map.entry("requestKind", text(intent.requestKind().name())),
                Map.entry("requestSha256", text(intent.requestSha256())), Map.entry("createdAt", text(intent.createdAt().toString())),
                Map.entry(FIELD_EXPIRES_AT, text(intent.expiresAt().toString())), Map.entry("approvalCategory", text(intent.approvalCategory().name())),
                Map.entry("decisions", new PkiOperationValue.ListValue(value.decisions().stream().<PkiOperationValue>map(decision -> new PkiOperationValue.ObjectValue(Map.of(
                        "principalId", text(decision.principalId()), "choice", text(decision.choice().name()), "decidedAt", text(decision.decidedAt().toString())))).toList())),
                Map.entry("credentialId", value.credentialId().map(zeroecho.pki.api.PkiId::value).map(ServerControlOperationExecutor::text).orElse(text("")))));
    }

    private PkiOperationValue inspectEnrollmentRequest(String id) {
        zeroecho.pki.server.enrollment.EnrollmentTransaction value = enrollment().find(id).orElseThrow(() -> new IllegalStateException("Enrollment request is unavailable"));
        zeroecho.pki.api.request.ParsedCertificationRequest parsed = enrollment().inspectIdentity(id);
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>(((PkiOperationValue.ObjectValue) enrollmentRequest(value)).fields());
        fields.put("subject", text(parsed.subjectRef().value()));
        fields.put("subjectRdns", new PkiOperationValue.ListValue(parsed.subjectRdns().stream().<PkiOperationValue>map(rdn -> object(
                "type", text(rdn.type().oid()), "value", text(rdn.value()))).toList()));
        fields.put("subjectAlternativeNames", new PkiOperationValue.ListValue(parsed.subjectAlternativeNames().stream().<PkiOperationValue>map(name -> {
            String nameValue = switch (name) {
                case zeroecho.pki.api.request.SubjectAlternativeName.DnsName dns -> dns.value();
                case zeroecho.pki.api.request.SubjectAlternativeName.UriName uri -> uri.value();
                case zeroecho.pki.api.request.SubjectAlternativeName.Rfc822Name email -> email.value();
                case zeroecho.pki.api.request.SubjectAlternativeName.IpAddress address -> java.util.HexFormat.of().formatHex(address.bytes());
            };
            return object("type", text(name.type().name()), "value", text(nameValue));
        }).toList()));
        try {
            fields.put("subjectPublicKeyInfoSha256", text(java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(parsed.publicKeyInfo().bytes()))));
        } catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); }
        return new PkiOperationValue.ObjectValue(fields);
    }

    /* default */ OcspResponderService.Responder ocspResponder(String responderId) {
        return ocsp().require(responderId);
    }

    private RepositoryAliasService aliases() {
        return repositoryAliases.orElseThrow(() -> new IllegalStateException("Repository aliases are unavailable"));
    }

    private RepositoryAliasService.Record publishAlias(ServerControlOperation.SetRepositoryAlias value,
            String actor) {
        return switch (value.type()) {
            case CURRENT_CRL -> aliases().setCurrentCrl(value.authorityId(), value.targetObjectId(),
                    value.expectedCurrentCommitment(), actor);
            case CURRENT_DELTA_CRL -> aliases().setCurrentDeltaCrl(value.authorityId(), value.targetObjectId(),
                    value.expectedCurrentCommitment(), actor);
            case CURRENT_CHAIN -> aliases().setCurrentChain(value.authorityId(),
                    value.issuerId().orElseThrow(() -> new IllegalArgumentException("issuerId is required")),
                    value.targetObjectId(), value.expectedCurrentCommitment(), actor);
        };
    }

    private PkiOperationValue register(ServerControlOperation.RegisterPrincipal operation) {
        try { store.createPrincipal(operation.principal()); }
        catch (IllegalStateException existing) {
            if (!store.requirePrincipal(operation.principal().principalId()).equals(operation.principal())) throw existing;
        }
        return principal(operation.principal());
    }

    private SecurityPrincipal changePrincipalEnabled(ServerControlOperation.SetPrincipalEnabled operation) {
        SecurityPrincipal current = store.requirePrincipal(operation.principalId());
        SecurityPrincipal updated = new SecurityPrincipal(current.principalId(), current.type(),
                current.displayName(), current.organization(), current.attributes(), operation.enabled());
        store.replacePrincipal(current, updated);
        return updated;
    }

    private RoleTemplateCatalog.Assignment createAssignment(RoleTemplateCatalog.Assignment value) {
        if (!value.scope().realmId().equals(realmId)) throw new SecurityException("Assignment realm differs");
        roles.instantiate(value); store.requirePrincipal(value.principalId()); store.createAssignment(value); return value;
    }

    private RoleTemplateCatalog.Assignment revokeAssignment(String id) {
        RoleTemplateCatalog.Assignment current = store.requireAssignment(id);
        RoleTemplateCatalog.Assignment revoked = new RoleTemplateCatalog.Assignment(current.assignmentId(),
                current.principalId(), current.templateId(), current.templateVersion(), current.scope(),
                current.expiresAt(), false);
        store.replaceAssignment(current, revoked); return revoked;
    }

    private Permission.Grant createGrant(Permission.Grant value) {
        if (!value.scope().realmId().equals(realmId)) throw new SecurityException("Grant realm differs");
        store.requirePrincipal(value.principalId()); store.createGrant(value); return value;
    }

    private Permission.Grant revokeGrant(String id) {
        Permission.Grant current = store.requireGrant(id);
        Permission.Grant revoked = new Permission.Grant(current.grantId(), current.principalId(), current.effect(),
                current.action(), current.resourceType(), current.scope(), current.relationship(), current.dataView(),
                current.conditions(), current.expiresAt(), false);
        store.replaceGrant(current, revoked); return revoked;
    }

    private PkiOperationValue evaluate(ServerControlOperation.EvaluateAuthorization value) {
        SecurityPrincipal principal = store.requirePrincipal(value.principalId());
        List<Permission.Grant> grants = grants(principal.principalId());
        BreakGlassService.ActiveGrants emergency = breakGlass.activeFor(principal.principalId());
        grants.addAll(emergency.grants());
        AuthorizationEngine.Decision decision = authorization.authorize(new AuthorizationEngine.Request(realmId,
                exposure, principal, value.action(), value.resource(), value.relationship(), value.dataView(),
                value.context(), grants, emergency.grantIds()));
        return object("allowed", bool(decision.allowed()), "code", text(decision.code().name()));
    }

    private ApprovalService.Request request(ServerControlOperation.RequestApproval value, String actor,
            Optional<OperationSecurityDescriptors.ApprovalCategory> approvedTargetCategory) {
        OperationSecurityDescriptors.Descriptor descriptor = descriptors.require(value.targetOperation());
        OperationSecurityDescriptors.ApprovalCategory approvalCategory = approvedTargetCategory
                .orElseThrow(() -> new SecurityException("Target approval eligibility was not proven"));
        if (!descriptor.mutating() || approvalCategory == OperationSecurityDescriptors.ApprovalCategory.NONE) {
            throw new IllegalStateException("Target operation does not require approval");
        }
        ApprovalService.Policy policy = approvalPolicies.get(approvalCategory);
        if (policy == null) throw new IllegalStateException("Approval policy is unavailable");
        String commitment = descriptors.commitment(realmId, value.targetOperation(), value.targetResource());
        return approvals.request(value.approvalId(), value.targetOperation().name(), commitment,
                value.targetResource().scope(), actor, policy);
    }

    private List<Permission.Grant> grants(String principalId) {
        List<Permission.Grant> result = new ArrayList<>(store.grantsFor(principalId));
        for (RoleTemplateCatalog.Assignment assignment : store.assignmentsFor(principalId)) {
            result.addAll(roles.instantiate(assignment));
        }
        return result;
    }

    private PkiOperationValue auditView(ServerControlOperation.InspectAuditView value, String actor) {
        DisclosureService.Record record = store.requireDisclosure(value.objectId());
        AuditorViews.Source source = new AuditorViews.Source(record.objectId(), Permission.ResourceType.DISCLOSURE,
                new Permission.Scope(realmId, Optional.empty(), Optional.empty(), Optional.empty()),
                record.policy().name(), record.updatedAt(), "NOT_APPLICABLE", Optional.empty(),
                record.policyCommitment(), false, 0, Optional.empty(), List.of(), Optional.empty());
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        fields.put("objectId", text(record.objectId().value())); fields.put("objectType", text(record.objectType().name()));
        fields.put("policy", text(record.policy().name())); fields.put("updatedAt", text(record.updatedAt().toString()));
        if (value.view() == Permission.DataView.PII_FULL) {
            String reason = value.reasonReference().orElseThrow(() -> new SecurityException("PII reason is required"));
            auditorViews.pii(source, store.requirePrincipal(actor), reason, true, true);
        } else if (value.view() == Permission.DataView.METADATA_FULL) {
            auditorViews.fullMetadata(source, true);
        } else {
            auditorViews.redacted(source);
        }
        fields.put("view", text(value.view().name())); return new PkiOperationValue.ObjectValue(fields);
    }

    private PkiOperationValue auditSearch(ServerControlOperation.SearchAudit value) {
        AuditService service = auditSearch.get();
        if (service == null) {
            throw new IllegalStateException("Audit search is not supported by the configured audit sink");
        }
        List<PkiOperationValue> events = service.search(value.query()).stream()
                .map(ServerControlOperationExecutor::auditEventValue).map(PkiOperationValue.class::cast).toList();
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        fields.put("count", integer(events.size()));
        fields.put("events", new PkiOperationValue.ListValue(events));
        return new PkiOperationValue.ObjectValue(fields);
    }

    private PkiOperationValue auditVerify(ServerControlOperation.VerifyAuditIntegrity value) {
        AuditIntegrityService service = auditIntegrity.get();
        if (service == null) {
            throw new IllegalStateException("Audit integrity verification is not supported by the configured sink");
        }
        AuditIntegrityReport report = service.verifyIntegrity(value.expectedHead());
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        fields.put("status", text(report.status().name()));
        fields.put("recordCount", integer(report.recordCount()));
        report.firstBrokenSequence().ifPresent(sequence -> fields.put("firstBrokenSequence", integer(sequence)));
        fields.put("headSequence", integer(report.head().sequence()));
        fields.put("headRecordHash", text(report.head().recordHash()));
        return new PkiOperationValue.ObjectValue(fields);
    }

    private PkiOperationValue transfer(String actor, ServerControlOperation.BackupArtifactCommand operation,
            BackupTransferChannel channel) throws java.io.IOException {
        BackupTransferService service = transfers(); // NOPMD CloseResource - Borrowed realm transfer service; its lifecycle owner closes it.
        BackupArtifactRepository.Descriptor descriptor = service.bind(actor, operation);
        if (!operation.commitment().equals(Optional.of(service.commitment(descriptor)))) {
            throw new SecurityException("Backup artifact identity changed");
        }
        return switch (operation.action()) {
            case VERIFY -> artifactValue(service.verify(actor, descriptor));
            case RESTORE -> artifactValue(service.restore(actor, descriptor));
            case STATUS -> artifactValue(service.status(actor, descriptor.handle()));
            case ACKNOWLEDGE -> {
                service.acknowledge(actor, descriptor.handle());
                yield text("ACKNOWLEDGED");
            }
            case UPLOAD -> {
                if (channel == null) throw new IllegalStateException("Binary backup transfer route required");
                service.upload(actor, descriptor, channel.input());
                yield artifactValue(service.bind(actor, descriptor.handle()));
            }
            case DOWNLOAD -> {
                if (channel == null) throw new IllegalStateException("Binary backup transfer route required");
                service.download(actor, descriptor, channel::output);
                yield text("DOWNLOADED");
            }
        };
    }

    private static PkiOperationValue artifactValue(BackupArtifactRepository.Descriptor descriptor) {
        return new PkiOperationValue.ObjectValue(Map.of(
                "artifactHandle", text(descriptor.handle()), "backupId", text(descriptor.backupId().value()),
                "length", integer(descriptor.length()), "sha256", text(descriptor.sha256()),
                "manifestSha256", text(descriptor.manifest()), FIELD_EXPIRES_AT, text(descriptor.expiresAt().toString()),
                FIELD_STATE, text(descriptor.state().name()), "restoreId", text(descriptor.restoreId()),
                "contentType", text("application/zip"), "purpose", text(descriptor.purpose().name())));
    }

    private static zeroecho.pki.api.attr.AttributeSet emptyBackupAttributes() {
        return new zeroecho.pki.api.attr.AttributeSet() {
            @Override public Set<zeroecho.pki.api.attr.AttributeId> ids() { return Set.of(); }
            @Override public Optional<zeroecho.pki.api.attr.AttributeValue> get(zeroecho.pki.api.attr.AttributeId id) { return Optional.empty(); }
            @Override public List<zeroecho.pki.api.attr.AttributeValue> getAll(zeroecho.pki.api.attr.AttributeId id) { return List.of(); }
        };
    }

    private PkiOperationValue exportBackup(ServerControlOperation.ExportBackup value) {
        BackupService service = backup.get();
        if (service == null) {
            throw new IllegalStateException("Backup is not supported by the configured store");
        }
        zeroecho.pki.api.backup.BackupArtifact artifact = service.createBackup(
                new zeroecho.pki.api.backup.BackupRequest(value.label(), value.attributes()));
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        fields.put("backupId", text(artifact.backupId().value()));
        fields.put("payload", text(Base64.getEncoder().encodeToString(artifact.payload().bytes())));
        return new PkiOperationValue.ObjectValue(fields);
    }

    private PkiOperationValue verifyBackup(ServerControlOperation.VerifyBackup value) {
        BackupService service = backup.get();
        if (service == null) {
            throw new IllegalStateException("Backup is not supported by the configured store");
        }
        zeroecho.pki.api.backup.BackupVerificationReport report = service.verifyBackup(value.artifact());
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        fields.put("valid", bool(report.valid()));
        fields.put("issues", new PkiOperationValue.ListValue(
                report.issues().stream().map(s -> (PkiOperationValue) text(s)).toList()));
        return new PkiOperationValue.ObjectValue(fields);
    }

    // Payload-free safe projection of one audit event: scalar metadata only, never the free-form details map.
    private static PkiOperationValue auditEventValue(AuditEvent event) {
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        fields.put("time", text(event.time().toString()));
        fields.put("category", text(event.category()));
        fields.put("action", text(event.action()));
        fields.put("principalType", text(event.principal().type()));
        fields.put("principalName", text(event.principal().name()));
        fields.put("purpose", text(event.purpose().value()));
        event.objectId().ifPresent(objectId -> fields.put("objectId", text(objectId.value())));
        event.formatId().ifPresent(formatId -> fields.put("formatId", text(formatId.value())));
        return new PkiOperationValue.ObjectValue(fields);
    }

    private static ServerControlOperationOutcome ordinary(ServerControlOperation operation,
            PkiOperationValue value) {
        return new ServerControlOperationOutcome.Ordinary(new PkiOperationOutcome.Completed(
                new PkiOperationResult(operation.name(), Map.of("value", value))));
    }

    private static ServerControlOperationOutcome capability(ServerControlOperation operation,
            DisclosureService.IssuedCapability issued) {
        PkiOperationResult safe = new PkiOperationResult(operation.name(), Map.of(
                "capabilityId", text(issued.capability().capabilityId()),
                "objectId", text(issued.capability().objectId().value()),
                FIELD_EXPIRES_AT, text(issued.capability().expiresAt().toString())));
        byte[] token = issued.token();
        try {
            return new ServerControlOperationOutcome.OneTimeSensitive(safe, token);
        } finally {
            java.util.Arrays.fill(token, (byte) 0);
        }
    }

    private static ServerControlOperationOutcome failure(ServerControlOperation operation,
            PkiOperationFailure failure, String code) {
        return new ServerControlOperationOutcome.Ordinary(new PkiOperationOutcome.Failed(
                operation.name(), failure, code));
    }

    private static PkiOperationValue principal(SecurityPrincipal value) {
        return object("principalId", text(value.principalId()), "type", text(value.type().name()),
                DISPLAY_NAME, text(value.displayName()), "enabled", bool(value.enabled()));
    }

    private static PkiOperationValue alias(RepositoryAliasService.Record value) {
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        fields.put("aliasId", text(value.aliasId()));
        fields.put(TEXT_AUTHORITY_ID, text(value.authorityId().value()));
        fields.put("type", text(value.type().name()));
        fields.put("targetObjectId", text(value.targetObjectId().value()));
        value.issuerId().ifPresent(id -> fields.put("issuerId", text(id.value())));
        value.pathId().ifPresent(id -> fields.put("pathId", text(id.value())));
        fields.put(FIELD_STATE, text(value.state().name()));
        fields.put("recordCommitment", text(value.recordCommitment()));
        return new PkiOperationValue.ObjectValue(fields);
    }
    private static PkiOperationValue directory(AcmeState.Directory value) {
        return object("directoryId", text(value.directoryId()), "alias", text(value.alias()),
                "revision", integer(value.revision()), TEXT_AUTHORITY_ID, text(value.authorityId().value()),
                "profileId", text(value.profile().profileId()), "enrollmentProfileId", text(value.enrollmentProfileId()),
                "issuerId", text(value.issuerId().value()),
                "pathId", text(value.issuancePathId().value()), "status", text(value.status().name()),
                "policyCommitment", text(value.policyCommitment()));
    }
    private static PkiOperationValue account(AcmeState.Account value) {
        return object("accountId", text(value.accountId()), "directoryId", text(value.directoryId()),
                "directoryRevision", integer(value.directoryRevision()), "status", text(value.status().name()),
                "createdAt", text(value.createdAt().toString()), "updatedAt", text(value.updatedAt().toString()));
    }
    private static PkiOperationValue estEndpoint(zeroecho.pki.server.est.EstEndpoint value) {
        return object("label", text(value.label()), TEXT_AUTHORITY_ID, text(value.authorityId()),
                "profileId", text(value.profileId()),
                "enrollmentProfileId", text(value.enrollmentProfileId()),
                "keygenEnabled", bool(value.keygen().enabled()),
                "keygenAlgorithms", new PkiOperationValue.ListValue(
                        value.keygen().permittedAlgorithms().stream()
                                .<PkiOperationValue>map(ServerControlOperationExecutor::text).toList()),
                "keygenMaxKeySizeBits", integer(value.keygen().maximumKeySizeBits()),
                "keygenStoreKeys", bool(value.keygen().storeGeneratedKeys()));
    }

    private static PkiOperationValue scepEndpoint(zeroecho.pki.server.scep.ScepEndpoint value) {
        return object("label", text(value.label()), TEXT_AUTHORITY_ID, text(value.authorityId()),
                "profileId", text(value.profileId()),
                "enrollmentProfileId", text(value.enrollmentProfileId()),
                "challengePasswordHash", text(value.challengePasswordHash()));
    }

    private static PkiOperationValue cmpEndpoint(zeroecho.pki.server.cmp.CmpEndpoint value) {
        return object("label", text(value.label()), TEXT_AUTHORITY_ID, text(value.authorityId()),
                "profileId", text(value.profileId()),
                "enrollmentProfileId", text(value.enrollmentProfileId()),
                "protectionPolicy", text(value.protectionPolicy().name()));
    }

    private static PkiOperationValue enrollmentProfile(zeroecho.pki.server.enrollment.EnrollmentProfile value) {
        List<PkiOperationValue> allowedAuthorities = value.allowedAuthorityIds().stream()
                .<PkiOperationValue>map(ServerControlOperationExecutor::text).toList();
        List<PkiOperationValue> requiredSans = value.requiredSanDomains().stream()
                .<PkiOperationValue>map(ServerControlOperationExecutor::text).toList();
        return object("id", text(value.id()),
                "displayName", text(value.displayName()),
                FIELD_STATE, text(value.state().name()),
                "certificateProfileId", text(value.certificateProfileId()),
                "allowedAuthorityIds", new PkiOperationValue.ListValue(allowedAuthorities),
                "subjectDnPattern", value.subjectDnPattern().map(ServerControlOperationExecutor::text)
                        .orElse(text("")),
                "requiredSanDomains", new PkiOperationValue.ListValue(requiredSans),
                "requireApproval", bool(value.requireApproval()));
    }

    private static PkiOperationValue responder(OcspResponderService.Responder value) {
        return object("responderId", text(value.responderId()), "alias", text(value.alias()),
                TEXT_AUTHORITY_ID, text(value.authorityId().value()), "issuerId", text(value.issuerId().value()),
                "signingMode", text(value.signingMode().name()), "responderCredentialId",
                text(value.responderCredentialId().value()), FIELD_STATE, text(value.state().name()),
                "requestAuthenticationMode", text(value.requestAuthenticationMode().name()),
                "requesterRevocationPolicy", text(value.requesterTrustPolicy()
                        .map(policy -> policy.revocationPolicy().name()).orElse("NOT_APPLICABLE")),
                "configurationCommitment", text(value.configurationCommitment()));
    }
    private static PkiOperationValue template(RoleTemplateCatalog.Template value) {
        List<PkiOperationValue> actions = value.actions().stream().sorted(Comparator.comparingInt(Permission.Action::code))
                .map(item -> (PkiOperationValue) text(item.name())).toList();
        return object("templateId", text(value.templateId()), "version", integer(value.version()),
                "actions", new PkiOperationValue.ListValue(actions));
    }
    private PkiOperationValue templatesValue() {
        return new PkiOperationValue.ListValue(roles.templates().stream()
                .map(ServerControlOperationExecutor::template).toList());
    }
    private static PkiOperationValue assignment(RoleTemplateCatalog.Assignment value) {
        return object("assignmentId", text(value.assignmentId()), "principalId", text(value.principalId()),
                "templateId", text(value.templateId()), "enabled", bool(value.enabled()));
    }
    private static PkiOperationValue grant(Permission.Grant value) {
        return object("grantId", text(value.grantId()), "principalId", text(value.principalId()),
                "effect", text(value.effect().name()), "action", text(value.action().name()),
                "enabled", bool(value.enabled()));
    }
    private static PkiOperationValue approval(ApprovalService.Request value) {
        return object("approvalId", text(value.approvalId()), "operation", text(value.operationId()),
                "requesterId", text(value.requesterPrincipalId()), FIELD_STATE, text(value.state().name()),
                FIELD_EXPIRES_AT, text(value.expiresAt().toString()));
    }
    private static PkiOperationValue breakGlass(BreakGlassService.Record value) {
        return object("breakGlassId", text(value.breakGlassId()), "principalId", text(value.principalId()),
                FIELD_STATE, text(value.state().name()), FIELD_EXPIRES_AT, text(value.expiresAt().toString()));
    }
    private static PkiOperationValue disclosure(DisclosureService.Record value) {
        return object("objectId", text(value.objectId().value()), "objectType", text(value.objectType().name()),
                "policy", text(value.policy().name()), "policyCommitment", text(value.policyCommitment()));
    }
    private static PkiOperationValue capability(DisclosureService.Capability value) {
        return object("capabilityId", text(value.capabilityId()), "objectId", text(value.objectId().value()),
                FIELD_EXPIRES_AT, text(value.expiresAt().toString()), "revoked", bool(value.revoked()));
    }
    private static <T> PkiOperationValue page(ServerControlStore.Page<T> page,
            java.util.function.Function<T, PkiOperationValue> renderer) {
        return object(TEXT_ITEMS, new PkiOperationValue.ListValue(page.values().stream().map(renderer).toList()),
                TEXT_NEXT_OFFSET, integer(page.nextOffset()), TEXT_HAS_MORE, bool(page.hasMore()));
    }
    private static <T> PkiOperationValue scopedPage(ServerControlStore.Page<T> page,
            Permission.Scope requested, java.util.function.Function<T, Permission.Scope> scope,
            java.util.function.Function<T, PkiOperationValue> renderer) {
        List<PkiOperationValue> values = page.values().stream()
                .filter(item -> contains(requested, scope.apply(item))).map(renderer).toList();
        return object(TEXT_ITEMS, new PkiOperationValue.ListValue(values), TEXT_NEXT_OFFSET,
                integer(page.nextOffset()), TEXT_HAS_MORE, bool(page.hasMore()));
    }
    private static PkiOperationValue approvalPage(ServerControlStore.Page<ApprovalService.Request> page,
            Permission.Scope requested, ServerControlOperation.ListApprovals filter) {
        List<PkiOperationValue> values = page.values().stream()
                .filter(item -> contains(requested, item.scope()))
                .filter(item -> filter.state().map(item.state()::equals).orElse(true))
                .filter(item -> filter.requesterPrincipalId().map(item.requesterPrincipalId()::equals).orElse(true))
                .filter(item -> filter.targetOperationId().map(item.operationId()::equals).orElse(true))
                .map(ServerControlOperationExecutor::approval).toList();
        return object(TEXT_ITEMS, new PkiOperationValue.ListValue(values), TEXT_NEXT_OFFSET,
                integer(page.nextOffset()), TEXT_HAS_MORE, bool(page.hasMore()));
    }
    private static boolean contains(Permission.Scope requested, Permission.Scope actual) {
        return requested.realmId().equals(actual.realmId())
                && requested.authorityId().map(value -> actual.authorityId().filter(value::equals).isPresent()).orElse(true)
                && requested.issuerId().map(value -> actual.issuerId().filter(value::equals).isPresent()).orElse(true)
                && requested.profileId().map(value -> actual.profileId().filter(value::equals).isPresent()).orElse(true);
    }
    private static PkiOperationValue.ObjectValue object(Object... entries) {
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        for (int index = 0; index < entries.length; index += 2) {
            fields.put((String) entries[index], (PkiOperationValue) entries[index + 1]);
        }
        return new PkiOperationValue.ObjectValue(fields);
    }
    private static PkiOperationValue.Text text(String value) { return new PkiOperationValue.Text(value); }
    private static PkiOperationValue.BooleanValue bool(boolean value) { return new PkiOperationValue.BooleanValue(value); }
    private static PkiOperationValue.IntegerValue integer(long value) { return new PkiOperationValue.IntegerValue(value); }
}
