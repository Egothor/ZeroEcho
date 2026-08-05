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

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.application.PkiOperationFailure;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.acme.AcmeService;
import zeroecho.pki.server.acme.AcmeState;

/** Sole closed dispatcher for transport-neutral server-control operations. */
@SuppressWarnings({ "PMD.CouplingBetweenObjects", "PMD.ExcessiveParameterList",
        "PMD.ControlStatementBraces" })
public final class ServerControlOperationExecutor {
    private final RealmId realmId;
    private final AuthorityExposurePolicy exposure;
    private final ServerControlStore store;
    private final RoleTemplateCatalog roles;
    private final AuthorizationEngine authorization;
    private final ApprovalService approvals;
    private final BreakGlassService breakGlass;
    private final DisclosureService disclosure;
    private final AuditorViews auditorViews;
    private final Optional<RepositoryAliasService> repositoryAliases;
    private final OperationSecurityDescriptors descriptors;
    private final Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> approvalPolicies;
    private final java.util.concurrent.atomic.AtomicReference<AcmeService> acme = new java.util.concurrent.atomic.AtomicReference<>();
    private final java.util.concurrent.atomic.AtomicReference<OcspResponderService> ocsp = new java.util.concurrent.atomic.AtomicReference<>();

    /** Creates the one control dispatcher over existing durable authorities. */
    public ServerControlOperationExecutor(RealmId realmId, AuthorityExposurePolicy exposure,
            ServerControlStore store, RoleTemplateCatalog roles, AuthorizationEngine authorization,
            ApprovalService approvals, BreakGlassService breakGlass, DisclosureService disclosure,
            AuditorViews auditorViews,
            Optional<RepositoryAliasService> repositoryAliases,
            OperationSecurityDescriptors descriptors,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> approvalPolicies) {
        this.realmId = Objects.requireNonNull(realmId, "realmId");
        this.exposure = Objects.requireNonNull(exposure, "exposure");
        this.store = Objects.requireNonNull(store, "store");
        this.roles = Objects.requireNonNull(roles, "roles");
        this.authorization = Objects.requireNonNull(authorization, "authorization");
        this.approvals = Objects.requireNonNull(approvals, "approvals");
        this.breakGlass = Objects.requireNonNull(breakGlass, "breakGlass");
        this.disclosure = Objects.requireNonNull(disclosure, "disclosure");
        this.auditorViews = Objects.requireNonNull(auditorViews, "auditorViews");
        this.repositoryAliases = Objects.requireNonNull(repositoryAliases, "repositoryAliases");
        this.descriptors = Objects.requireNonNull(descriptors, "descriptors");
        this.approvalPolicies = Map.copyOf(Objects.requireNonNull(approvalPolicies, "approvalPolicies"));
    }

    /** Executes exactly one already-authorized control operation synchronously. */
    public ServerControlOperationOutcome execute(ServerControlOperation operation, String actorPrincipalId,
            Permission.Resource authorizedResource, Optional<String> approvalId, CancellationSignal cancellation) {
        Objects.requireNonNull(operation, "operation");
        Permission.requirePrincipal(actorPrincipalId);
        Objects.requireNonNull(authorizedResource, "authorizedResource");
        if (Objects.requireNonNull(cancellation, "cancellation").isCancelled()) {
            return failure(operation, PkiOperationFailure.CANCELLED, "CONTROL_OPERATION_CANCELLED");
        }
        try {
            return dispatch(operation, actorPrincipalId, authorizedResource,
                    Objects.requireNonNull(approvalId, "approvalId"));
        } catch (IllegalArgumentException unavailable) {
            return failure(operation, PkiOperationFailure.NOT_FOUND, "CONTROL_OBJECT_UNAVAILABLE");
        } catch (SecurityException denied) {
            return failure(operation, PkiOperationFailure.POLICY_REJECTION, "CONTROL_POLICY_REJECTED");
        } catch (IllegalStateException conflict) {
            return failure(operation, PkiOperationFailure.CONFLICT, "CONTROL_STATE_CONFLICT");
        }
    }

    /** Installs the explicitly configured ACME capability exactly once before listener readiness. */
    public void installAcme(AcmeService service) {
        if (!acme.compareAndSet(null, Objects.requireNonNull(service, "service"))) {
            throw new IllegalStateException("ACME administration capability is already installed");
        }
    }

    /** Installs the realm-owned durable OCSP responder capability exactly once. */
    public void installOcsp(OcspResponderService service) {
        if (!ocsp.compareAndSet(null, Objects.requireNonNull(service, "service"))) {
            throw new IllegalStateException("OCSP administration capability is already installed");
        }
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

    private ServerControlOperationOutcome dispatch(ServerControlOperation operation, String actor,
            Permission.Resource authorizedResource, Optional<String> approvalId) {
        return switch (operation) {
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
            case ServerControlOperation.RequestApproval value -> ordinary(operation, approval(request(value, actor)));
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
            case ServerControlOperation.IssueCapability value -> capability(operation,
                    disclosure.issueCapability(value.objectId(), value.expiresAt(), actor));
            case ServerControlOperation.RevokeCapability value -> ordinary(operation,
                    capability(disclosure.revokeCapability(value.capabilityId(), actor)));
            case ServerControlOperation.InspectAuditView value -> ordinary(operation, auditView(value, actor));
            case ServerControlOperation.InspectRepositoryAlias value -> ordinary(operation,
                    alias(aliases().require(value.authorityId(), value.type())));
            case ServerControlOperation.ListRepositoryAliases value -> ordinary(operation,
                    page(aliases().list(value.offset(), value.limit()), ServerControlOperationExecutor::alias));
            case ServerControlOperation.SetRepositoryAlias value -> ordinary(operation,
                    alias(publishAlias(value, actor)));
            case ServerControlOperation.RemoveRepositoryAlias value -> ordinary(operation,
                    alias(aliases().remove(value.authorityId(), value.type(), value.expectedCurrentCommitment(), actor)));
            case ServerControlOperation.RegisterAcmeDirectory value -> ordinary(operation,
                    directory(acme().registerDirectory(value.registration())));
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
        };
    }

    private AcmeService acme() {
        return Optional.ofNullable(acme.get()).orElseThrow(() -> new IllegalStateException("ACME capability unavailable"));
    }

    private OcspResponderService ocsp() {
        return Optional.ofNullable(ocsp.get()).orElseThrow(() -> new IllegalStateException("OCSP capability unavailable"));
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

    private ApprovalService.Request request(ServerControlOperation.RequestApproval value, String actor) {
        OperationSecurityDescriptors.Descriptor descriptor = descriptors.require(value.targetOperation());
        if (!descriptor.mutating() || descriptor.approvalCategory() == OperationSecurityDescriptors.ApprovalCategory.NONE) {
            throw new IllegalStateException("Target operation does not require approval");
        }
        ApprovalService.Policy policy = approvalPolicies.get(descriptor.approvalCategory());
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

    private static ServerControlOperationOutcome ordinary(ServerControlOperation operation,
            PkiOperationValue value) {
        return new ServerControlOperationOutcome.Ordinary(new PkiOperationOutcome.Success(
                new PkiOperationResult(operation.name(), Map.of("value", value))));
    }

    private static ServerControlOperationOutcome capability(ServerControlOperation operation,
            DisclosureService.IssuedCapability issued) {
        PkiOperationResult safe = new PkiOperationResult(operation.name(), Map.of(
                "capabilityId", text(issued.capability().capabilityId()),
                "objectId", text(issued.capability().objectId().value()),
                "expiresAt", text(issued.capability().expiresAt().toString())));
        byte[] token = issued.token();
        try {
            return new ServerControlOperationOutcome.OneTimeSensitive(safe, token);
        } finally {
            java.util.Arrays.fill(token, (byte) 0);
        }
    }

    private static ServerControlOperationOutcome failure(ServerControlOperation operation,
            PkiOperationFailure failure, String code) {
        return new ServerControlOperationOutcome.Ordinary(new PkiOperationOutcome.Failure(
                operation.name(), failure, code));
    }

    private static PkiOperationValue principal(SecurityPrincipal value) {
        return object("principalId", text(value.principalId()), "type", text(value.type().name()),
                "displayName", text(value.displayName()), "enabled", bool(value.enabled()));
    }

    private static PkiOperationValue alias(RepositoryAliasService.Record value) {
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        fields.put("aliasId", text(value.aliasId()));
        fields.put("authorityId", text(value.authorityId().value()));
        fields.put("type", text(value.type().name()));
        fields.put("targetObjectId", text(value.targetObjectId().value()));
        value.issuerId().ifPresent(id -> fields.put("issuerId", text(id.value())));
        value.pathId().ifPresent(id -> fields.put("pathId", text(id.value())));
        fields.put("state", text(value.state().name()));
        fields.put("recordCommitment", text(value.recordCommitment()));
        return new PkiOperationValue.ObjectValue(fields);
    }
    private static PkiOperationValue directory(AcmeState.Directory value) {
        return object("directoryId", text(value.directoryId()), "alias", text(value.alias()),
                "revision", integer(value.revision()), "authorityId", text(value.authorityId().value()),
                "profileId", text(value.profile().profileId()), "issuerId", text(value.issuerId().value()),
                "pathId", text(value.issuancePathId().value()), "status", text(value.status().name()),
                "policyCommitment", text(value.policyCommitment()));
    }
    private static PkiOperationValue account(AcmeState.Account value) {
        return object("accountId", text(value.accountId()), "directoryId", text(value.directoryId()),
                "directoryRevision", integer(value.directoryRevision()), "status", text(value.status().name()),
                "createdAt", text(value.createdAt().toString()), "updatedAt", text(value.updatedAt().toString()));
    }
    private static PkiOperationValue responder(OcspResponderService.Responder value) {
        return object("responderId", text(value.responderId()), "alias", text(value.alias()),
                "authorityId", text(value.authorityId().value()), "issuerId", text(value.issuerId().value()),
                "signingMode", text(value.signingMode().name()), "responderCredentialId",
                text(value.responderCredentialId().value()), "state", text(value.state().name()),
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
                "requesterId", text(value.requesterPrincipalId()), "state", text(value.state().name()),
                "expiresAt", text(value.expiresAt().toString()));
    }
    private static PkiOperationValue breakGlass(BreakGlassService.Record value) {
        return object("breakGlassId", text(value.breakGlassId()), "principalId", text(value.principalId()),
                "state", text(value.state().name()), "expiresAt", text(value.expiresAt().toString()));
    }
    private static PkiOperationValue disclosure(DisclosureService.Record value) {
        return object("objectId", text(value.objectId().value()), "objectType", text(value.objectType().name()),
                "policy", text(value.policy().name()), "policyCommitment", text(value.policyCommitment()));
    }
    private static PkiOperationValue capability(DisclosureService.Capability value) {
        return object("capabilityId", text(value.capabilityId()), "objectId", text(value.objectId().value()),
                "expiresAt", text(value.expiresAt().toString()), "revoked", bool(value.revoked()));
    }
    private static <T> PkiOperationValue page(ServerControlStore.Page<T> page,
            java.util.function.Function<T, PkiOperationValue> renderer) {
        return object("items", new PkiOperationValue.ListValue(page.values().stream().map(renderer).toList()),
                "nextOffset", integer(page.nextOffset()), "hasMore", bool(page.hasMore()));
    }
    private static <T> PkiOperationValue scopedPage(ServerControlStore.Page<T> page,
            Permission.Scope requested, java.util.function.Function<T, Permission.Scope> scope,
            java.util.function.Function<T, PkiOperationValue> renderer) {
        List<PkiOperationValue> values = page.values().stream()
                .filter(item -> contains(requested, scope.apply(item))).map(renderer).toList();
        return object("items", new PkiOperationValue.ListValue(values), "nextOffset",
                integer(page.nextOffset()), "hasMore", bool(page.hasMore()));
    }
    private static PkiOperationValue approvalPage(ServerControlStore.Page<ApprovalService.Request> page,
            Permission.Scope requested, ServerControlOperation.ListApprovals filter) {
        List<PkiOperationValue> values = page.values().stream()
                .filter(item -> contains(requested, item.scope()))
                .filter(item -> filter.state().map(item.state()::equals).orElse(true))
                .filter(item -> filter.requesterPrincipalId().map(item.requesterPrincipalId()::equals).orElse(true))
                .filter(item -> filter.targetOperationId().map(item.operationId()::equals).orElse(true))
                .map(ServerControlOperationExecutor::approval).toList();
        return object("items", new PkiOperationValue.ListValue(values), "nextOffset",
                integer(page.nextOffset()), "hasMore", bool(page.hasMore()));
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
