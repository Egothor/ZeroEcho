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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationExecutor;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiResourceScopeResolver;

/**
 * In-process transport-neutral security gateway for existing typed PKI
 * operations.
 *
 * <p>The gateway owns no executor, thread, queue, retry, or PKI business rule. It
 * serially validates realm/scope, authorizes, applies approval policy, delegates
 * exactly once to the session executor, and preserves the returned outcome.</p>
 */
@SuppressWarnings({ "PMD.ControlStatementBraces", "PMD.FieldDeclarationsShouldBeAtStartOfClass",
        "PMD.ExcessiveParameterList", "PMD.CyclomaticComplexity", "PMD.AvoidInstantiatingObjectsInLoops",
        "PMD.NcssCount", "PMD.ConfusingTernary", "PMD.ExceptionAsFlowControl" })
public final class ServerOperationGateway {
    /**
     * Complete transport-neutral request admission input.
     *
     * @param realmId exact realm identity
     * @param principalId authenticated end-client principal identity
     * @param authenticationMode explicit administrative authentication mode
     * @param transportPrincipalId trusted proxy identity, present only in proxy mode
     * @param operation existing typed operation
     * @param resource exact non-bearer resource reference
     * @param relationship established object relationship
     * @param context safe closed-condition context
     * @param approvalId optional durable approval reference
     * @param correlationId safe finite request correlation identity
     */
    public record Request(RealmId realmId, String principalId,
            AdministrativeAuthenticationMode authenticationMode, Optional<String> transportPrincipalId,
            AdministrativeOperation operation,
            Permission.Resource resource, Permission.Relationship relationship, Permission.Context context,
            Optional<String> approvalId, String correlationId) {
        /** Validates the immutable request. */
        public Request {
            Objects.requireNonNull(realmId, "realmId");
            Permission.requirePrincipal(principalId);
            Objects.requireNonNull(authenticationMode, "authenticationMode");
            transportPrincipalId = Objects.requireNonNull(transportPrincipalId, "transportPrincipalId");
            transportPrincipalId.ifPresent(Permission::requirePrincipal);
            if (authenticationMode == AdministrativeAuthenticationMode.DIRECT_MTLS
                    && transportPrincipalId.isPresent()
                    || authenticationMode == AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY
                    && transportPrincipalId.isEmpty()) {
                throw new IllegalArgumentException("Gateway authentication identity context is invalid");
            }
            Objects.requireNonNull(operation, "operation");
            Objects.requireNonNull(resource, "resource");
            Objects.requireNonNull(relationship, "relationship");
            Objects.requireNonNull(context, "context");
            approvalId = Objects.requireNonNull(approvalId, "approvalId");
            Permission.requireBounded(correlationId, 256, "correlation ID");
        }

        /** Wraps an existing PKI operation for source-compatible embedded callers. */
        public Request(RealmId realmId, String principalId, PkiOperation operation,
                Permission.Resource resource, Permission.Relationship relationship, Permission.Context context,
                Optional<String> approvalId, String correlationId) {
            this(realmId, principalId, AdministrativeAuthenticationMode.DIRECT_MTLS, Optional.empty(),
                    new AdministrativeOperation.Pki(operation), resource, relationship, context, approvalId,
                    correlationId);
        }

        /** Creates a direct-mTLS request for existing embedded control callers. */
        public Request(RealmId realmId, String principalId, AdministrativeOperation operation,
                Permission.Resource resource, Permission.Relationship relationship, Permission.Context context,
                Optional<String> approvalId, String correlationId) {
            this(realmId, principalId, AdministrativeAuthenticationMode.DIRECT_MTLS, Optional.empty(), operation,
                    resource, relationship, context, approvalId, correlationId);
        }
    }

    /** Closed gateway outcome preserving typed backend results. */
    public sealed interface Outcome permits Outcome.Executed, Outcome.ControlExecuted,
            Outcome.Denied, Outcome.ApprovalRequired {
        /** Successfully admitted operation and exact backend outcome. */
        record Executed(PkiOperationOutcome outcome) implements Outcome {
            /** Validates the backend result. */ public Executed { Objects.requireNonNull(outcome, "outcome"); }
        }
        /** Successfully admitted server-control result. */
        record ControlExecuted(ServerControlOperationOutcome outcome) implements Outcome {
            /** Validates the control result. */ public ControlExecuted { Objects.requireNonNull(outcome, "outcome"); }
        }
        /** Safe denial without protected-object existence information. */
        record Denied(AuthorizationEngine.Code code) implements Outcome {
            /** Validates the safe code. */ public Denied { Objects.requireNonNull(code, "code"); }
        }
        /** High-risk operation requires a separately created durable approval. */
        record ApprovalRequired(String operationCommitment) implements Outcome {
            /** Validates the safe exact-operation commitment. */
            public ApprovalRequired {
                if (operationCommitment == null || !operationCommitment.matches("[0-9a-f]{64}"))
                    throw new IllegalArgumentException("Operation commitment is invalid");
            }
        }
    }

    private final RealmId realmId;
    private final AuthorityExposurePolicy exposure;
    private final ServerControlStore control;
    private final RoleTemplateCatalog roles;
    private final AuthorizationEngine authorization;
    private final ApprovalService approvals;
    private final BreakGlassService breakGlass;
    private final OperationSecurityDescriptors descriptors;
    private final PkiOperationExecutor executor;
    private final ServerControlOperationExecutor controlExecutor;
    private final PkiResourceScopeResolver resourceScopes;
    private final Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> approvalPolicies;
    private final SafeAudit audit;
    private final Runnable openCheck;

    /** Creates one gateway bound to one realm and one session executor. */
    public ServerOperationGateway(RealmId realmId, AuthorityExposurePolicy exposure, ServerControlStore control,
            RoleTemplateCatalog roles, AuthorizationEngine authorization, ApprovalService approvals,
            BreakGlassService breakGlass, DisclosureService disclosure, AuditorViews auditorViews,
            Optional<RepositoryAliasService> repositoryAliases,
            OperationSecurityDescriptors descriptors, PkiOperationExecutor executor,
            PkiResourceScopeResolver resourceScopes,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> approvalPolicies,
            java.time.Clock clock, zeroecho.pki.spi.audit.AuditSink auditSink, Runnable openCheck) {
        this.realmId = Objects.requireNonNull(realmId, "realmId");
        this.exposure = Objects.requireNonNull(exposure, "exposure");
        this.control = Objects.requireNonNull(control, "control");
        this.roles = Objects.requireNonNull(roles, "roles");
        this.authorization = Objects.requireNonNull(authorization, "authorization");
        this.approvals = Objects.requireNonNull(approvals, "approvals");
        this.breakGlass = Objects.requireNonNull(breakGlass, "breakGlass");
        this.descriptors = Objects.requireNonNull(descriptors, "descriptors");
        this.executor = Objects.requireNonNull(executor, "executor");
        this.controlExecutor = new ServerControlOperationExecutor(realmId, exposure, control, roles,
                authorization, approvals, breakGlass, disclosure, auditorViews, repositoryAliases, descriptors,
                approvalPolicies);
        this.resourceScopes = Objects.requireNonNull(resourceScopes, "resourceScopes");
        this.approvalPolicies = Map.copyOf(Objects.requireNonNull(approvalPolicies, "approvalPolicies"));
        this.audit = new SafeAudit(clock, auditSink);
        this.openCheck = Objects.requireNonNull(openCheck, "openCheck");
    }

    /** Creates the pre-control-plane gateway surface for embedded source compatibility. */
    public ServerOperationGateway(RealmId realmId, AuthorityExposurePolicy exposure, ServerControlStore control,
            RoleTemplateCatalog roles, AuthorizationEngine authorization, ApprovalService approvals,
            BreakGlassService breakGlass, OperationSecurityDescriptors descriptors, PkiOperationExecutor executor,
            PkiResourceScopeResolver resourceScopes,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> approvalPolicies,
            java.time.Clock clock, zeroecho.pki.spi.audit.AuditSink auditSink, Runnable openCheck) {
        this(realmId, exposure, control, roles, authorization, approvals, breakGlass,
                new DisclosureService(realmId, control, DisclosureService.Defaults.recommended(), clock,
                        new java.security.SecureRandom(), auditSink), new AuditorViews(clock, auditSink),
                Optional.empty(), descriptors, executor, resourceScopes, approvalPolicies, clock, auditSink,
                openCheck);
    }

    /**
     * Admits and synchronously executes one operation.
     *
     * @param request complete security request
     * @param cancellation cooperative cancellation signal passed unchanged to PKI
     * @return safe gateway outcome
     */
    public Outcome execute(Request request, CancellationSignal cancellation) {
        openCheck.run();
        Request exact = Objects.requireNonNull(request, "request");
        Objects.requireNonNull(cancellation, "cancellation");
        if (!realmId.equals(exact.realmId()) || !realmId.equals(exact.resource().scope().realmId())) {
            return denied(exact, AuthorizationEngine.Code.OUTSIDE_REALM);
        }
        OperationSecurityDescriptors.Descriptor descriptor;
        try {
            descriptor = descriptors.require(exact.operation());
            if (exact.operation() instanceof AdministrativeOperation.Pki pki) {
                descriptors.validateResource(pki.operation(), exact.resource());
                validateAuthoritativeScope(pki.operation(), exact.resource());
            } else if (descriptor.resourceType() != exact.resource().type()) {
                throw new SecurityException("Control operation resource type differs");
            } else {
                validateControlScope(((AdministrativeOperation.Control) exact.operation()).operation(),
                        exact.resource());
            }
        } catch (SecurityException | IllegalArgumentException invalid) {
            return denied(exact, AuthorizationEngine.Code.NO_MATCHING_GRANT);
        }
        if (exact.operation() instanceof AdministrativeOperation.Pki pki
                && pki.operation() instanceof PkiOperation.CreateAuthority
                && !exposure.authorityCreationPermitted()) {
            return denied(exact, AuthorizationEngine.Code.OUTSIDE_AUTHORITY_SCOPE);
        }
        SecurityPrincipal principal;
        try {
            principal = control.requirePrincipal(exact.principalId());
        } catch (IllegalArgumentException unavailable) {
            return denied(exact, AuthorizationEngine.Code.NO_MATCHING_GRANT);
        }
        List<Permission.Grant> grants = new ArrayList<>(control.grantsFor(principal.principalId()));
        for (RoleTemplateCatalog.Assignment assignment : control.assignmentsFor(principal.principalId())) {
            grants.addAll(roles.instantiate(assignment));
        }
        BreakGlassService.ActiveGrants emergency = breakGlass.activeFor(principal.principalId());
        grants.addAll(emergency.grants());
        Permission.Action action = exact.operation() instanceof AdministrativeOperation.Pki pki
                ? action(pki.operation(), descriptor.action()) : descriptor.action();
        Permission.Context conditionContext = approvalContext(exact);
        AuthorizationEngine.Decision decision = authorization.authorize(new AuthorizationEngine.Request(realmId,
                exposure, principal, action, exact.resource(), exact.relationship(), descriptor.dataView(),
                conditionContext, grants, emergency.grantIds()));
        boolean filterableList = exact.operation() instanceof AdministrativeOperation.Pki pki
                && pki.operation() instanceof PkiOperation.ListAuthorities
                && decision.code() == AuthorizationEngine.Code.NO_MATCHING_GRANT;
        if (!decision.allowed() && !filterableList) {
            return denied(exact, decision.code());
        }
        if (exact.operation() instanceof AdministrativeOperation.Control controlOperation
                && controlOperation.operation() instanceof ServerControlOperation.RequestApproval requestApproval) {
            OperationSecurityDescriptors.Descriptor target = descriptors.require(requestApproval.targetOperation());
            if (target.resourceType() != requestApproval.targetResource().type()) {
                return denied(exact, AuthorizationEngine.Code.NO_MATCHING_GRANT);
            }
            if (requestApproval.targetOperation() instanceof AdministrativeOperation.Pki targetPki) {
                try {
                    descriptors.validateResource(targetPki.operation(), requestApproval.targetResource());
                } catch (SecurityException mismatch) {
                    return denied(exact, AuthorizationEngine.Code.NO_MATCHING_GRANT);
                }
            }
            AuthorizationEngine.Decision targetDecision = authorization.authorize(new AuthorizationEngine.Request(
                    realmId, exposure, principal, target.action(), requestApproval.targetResource(),
                    exact.relationship(), target.dataView(), exact.context(), grants, emergency.grantIds()));
            if (!targetDecision.allowed()) return denied(exact, targetDecision.code());
        }
        if (decision.usedBreakGlass()) breakGlass.auditUse(principal.principalId());
        String commitment = descriptors.commitment(realmId, exact.operation(), exact.resource());
        Optional<String> claimedApproval = Optional.empty();
        if (descriptor.approvalCategory() == OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK) {
            ApprovalService.Policy expected = approvalPolicies.get(descriptor.approvalCategory());
            if (expected == null) throw new IllegalStateException("High-risk approval policy is not configured");
            if (exact.approvalId().isEmpty()) return new Outcome.ApprovalRequired(commitment);
            ApprovalService.Request current = approvals.requireCurrent(exact.approvalId().orElseThrow());
            if (!current.policyCommitment().equals(expected.commitment())) {
                return denied(exact, AuthorizationEngine.Code.APPROVAL_REQUIRED);
            }
            approvals.claim(current.approvalId(), exact.operation().name(), commitment, exact.resource().scope());
            claimedApproval = Optional.of(current.approvalId());
        }
        if (exact.operation() instanceof AdministrativeOperation.Pki pki) {
            PkiOperationOutcome backend = executor.execute(pki.operation(), cancellation);
            if (pki.operation() instanceof PkiOperation.ListAuthorities) {
                backend = filterAuthorities(backend, principal, grants, emergency.grantIds(), exact.context());
            }
            if (claimedApproval.isPresent()) approvals.complete(claimedApproval.orElseThrow(), classification(backend));
            audit.record("GATEWAY_RESULT", principal.principalId(), exact.resource().objectId(),
                    gatewayDetails(exact, "result", classification(backend)));
            return new Outcome.Executed(backend);
        }
        ServerControlOperation controlOperation = ((AdministrativeOperation.Control) exact.operation()).operation();
        ServerControlOperationOutcome controlResult = controlExecutor.execute(controlOperation,
                principal.principalId(), exact.resource(), exact.approvalId(), cancellation);
        String result = classification(controlResult);
        if (claimedApproval.isPresent()) approvals.complete(claimedApproval.orElseThrow(), result);
        audit.record("GATEWAY_RESULT", principal.principalId(), exact.resource().objectId(),
                gatewayDetails(exact, "result", result));
        return new Outcome.ControlExecuted(controlResult);
    }

    /**
     * Authorizes one non-PKI administrative control resource through the same
     * default-deny engine used for typed operations.
     *
     * @param principalId authenticated persisted principal
     * @param action exact control action
     * @param resource exact realm control resource
     * @param context safe closed-condition context
     * @param correlationId bounded request correlation identity
     * @return safe authorization decision
     */
    public AuthorizationEngine.Decision authorizeControl(String principalId, Permission.Action action,
            Permission.Resource resource, Permission.Context context, String correlationId) {
        openCheck.run();
        Permission.requirePrincipal(principalId);
        Permission.requireBounded(correlationId, 256, "correlation ID");
        SecurityPrincipal principal = control.requirePrincipal(principalId);
        List<Permission.Grant> grants = grants(principal);
        BreakGlassService.ActiveGrants emergency = breakGlass.activeFor(principalId);
        grants.addAll(emergency.grants());
        AuthorizationEngine.Decision decision = authorization.authorize(new AuthorizationEngine.Request(realmId,
                exposure, principal, action, resource, Permission.Relationship.ANY,
                Permission.DataView.METADATA_REDACTED, context, grants, emergency.grantIds()));
        audit.record(decision.allowed() ? "AUTHORIZATION_ALLOW" : "AUTHORIZATION_DENY", principalId,
                Optional.empty(), Map.of("action", action.name(), "code", decision.code().name(),
                        "correlation", correlationId));
        if (decision.usedBreakGlass()) breakGlass.auditUse(principalId);
        return decision;
    }

    /**
     * Authorizes a dedicated service principal to attest one forwarded client
     * identity. Break-glass grants are deliberately excluded from this transport
     * trust decision.
     *
     * @param principalId authenticated backend TLS peer identity
     * @param correlationId bounded request correlation identity
     * @return default-deny decision with explicit-deny precedence
     */
    public AuthorizationEngine.Decision authorizeForwardedIdentity(String principalId, String correlationId) {
        openCheck.run();
        Permission.requirePrincipal(principalId);
        Permission.requireBounded(correlationId, 256, "correlation ID");
        SecurityPrincipal principal = control.requirePrincipal(principalId);
        if (principal.type() != SecurityPrincipal.Type.SERVICE) {
            return new AuthorizationEngine.Decision(AuthorizationEngine.Code.NO_MATCHING_GRANT, false);
        }
        List<Permission.Grant> principalGrants = grants(principal);
        if (principalGrants.stream().anyMatch(grant -> grant.enabled()
                && grant.effect() == Permission.Effect.ALLOW
                && grant.action() != Permission.Action.FORWARD_AUTHENTICATED_CLIENT_IDENTITY)
                || !breakGlass.activeFor(principalId).grants().isEmpty()) {
            return new AuthorizationEngine.Decision(AuthorizationEngine.Code.NO_MATCHING_GRANT, false);
        }
        Permission.Resource resource = new Permission.Resource(Permission.ResourceType.REALM,
                new Permission.Scope(realmId, Optional.empty(), Optional.empty(), Optional.empty()),
                Optional.empty(), Optional.empty());
        AuthorizationEngine.Decision decision = authorization.authorize(new AuthorizationEngine.Request(realmId,
                exposure, principal, Permission.Action.FORWARD_AUTHENTICATED_CLIENT_IDENTITY, resource,
                Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED, Permission.Context.empty(),
                principalGrants, java.util.Set.of()));
        audit.record(decision.allowed() ? "PROXY_FORWARD_ALLOW" : "PROXY_FORWARD_DENY", principalId,
                Optional.empty(), Map.of("action", Permission.Action.FORWARD_AUTHENTICATED_CLIENT_IDENTITY.name(),
                        "code", decision.code().name(), "correlation", correlationId));
        return decision;
    }

    /**
     * Fails startup when a configured proxy service principal has any enabled
     * allowing authority beyond forwarded-identity attestation.
     *
     * @param principalId configured trusted proxy principal
     */
    public void validateForwardingPrincipal(String principalId) {
        openCheck.run();
        SecurityPrincipal principal = control.requirePrincipal(principalId);
        if (!principal.enabled() || principal.type() != SecurityPrincipal.Type.SERVICE
                || grants(principal).stream().anyMatch(grant -> grant.enabled()
                        && grant.effect() == Permission.Effect.ALLOW
                        && grant.action() != Permission.Action.FORWARD_AUTHENTICATED_CLIENT_IDENTITY)) {
            throw new IllegalArgumentException("Trusted proxy principal authority is not narrowly scoped");
        }
    }

    /**
     * Returns operation descriptors discoverable by one principal without
     * returning grant scopes or protected resource identities.
     *
     * @param principalId authenticated persisted principal
     * @return descriptors ordered by stable operation identity
     */
    public List<OperationSecurityDescriptors.Descriptor> discoverableOperations(String principalId) {
        openCheck.run();
        SecurityPrincipal principal = control.requirePrincipal(principalId);
        List<Permission.Grant> grants = grants(principal);
        BreakGlassService.ActiveGrants emergency = breakGlass.activeFor(principalId);
        grants.addAll(emergency.grants());
        return descriptors.descriptors().values().stream()
                .filter(descriptor -> discoverable(descriptor, principal, grants, emergency.grantIds()))
                .sorted(java.util.Comparator.comparing(OperationSecurityDescriptors.Descriptor::operationId))
                .toList();
    }

    /**
     * Resolves the existing security descriptor for a decoded typed operation.
     *
     * @param operation decoded transport-neutral operation
     * @return immutable descriptor from the sole gateway descriptor authority
     * @throws SecurityException when the operation is not remotely exposed
     */
    public OperationSecurityDescriptors.Descriptor descriptor(PkiOperation operation) {
        openCheck.run();
        return descriptors.require(operation);
    }

    /** Resolves one descriptor by its immutable administrative operation family. */
    public OperationSecurityDescriptors.Descriptor descriptor(AdministrativeOperation operation) {
        openCheck.run();
        return descriptors.require(operation);
    }

    /** Resolves one descriptor by stable ID before closed typed decoding. */
    public OperationSecurityDescriptors.Descriptor descriptor(String operationId) {
        openCheck.run();
        return descriptors.require(operationId);
    }

    private List<Permission.Grant> grants(SecurityPrincipal principal) {
        List<Permission.Grant> grants = new ArrayList<>(control.grantsFor(principal.principalId()));
        for (RoleTemplateCatalog.Assignment assignment : control.assignmentsFor(principal.principalId())) {
            grants.addAll(roles.instantiate(assignment));
        }
        return grants;
    }

    private boolean discoverable(OperationSecurityDescriptors.Descriptor descriptor,
            SecurityPrincipal principal, List<Permission.Grant> grants,
            java.util.Set<String> breakGlassIds) {
        for (Permission.Grant grant : grants) {
            if (grant.action() != descriptor.action() || grant.resourceType() != descriptor.resourceType()) {
                continue;
            }
            Permission.Resource resource = new Permission.Resource(descriptor.resourceType(), grant.scope(),
                    Optional.empty(), Optional.empty());
            AuthorizationEngine.Decision decision = authorization.authorize(new AuthorizationEngine.Request(
                    realmId, exposure, principal, descriptor.action(), resource, Permission.Relationship.ANY,
                    descriptor.dataView(), Permission.Context.empty(), grants, breakGlassIds));
            if (decision.allowed()) return true;
        }
        return false;
    }

    private PkiOperationOutcome filterAuthorities(PkiOperationOutcome outcome, SecurityPrincipal principal,
            List<Permission.Grant> grants, java.util.Set<String> breakGlassIds, Permission.Context context) {
        if (!(outcome instanceof PkiOperationOutcome.Success success)) return outcome;
        PkiOperationValue value = success.result().fields().get("authorities");
        if (!(value instanceof PkiOperationValue.ListValue list)) return outcome;
        List<PkiOperationValue> allowed = list.values().stream().filter(item -> authorityAllowed(item, principal,
                grants, breakGlassIds, context)).toList();
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>(success.result().fields());
        fields.put("count", new PkiOperationValue.IntegerValue(allowed.size()));
        fields.put("authorities", new PkiOperationValue.ListValue(allowed));
        return new PkiOperationOutcome.Success(new PkiOperationResult(success.result().operationName(), fields));
    }

    private boolean authorityAllowed(PkiOperationValue value, SecurityPrincipal principal,
            List<Permission.Grant> grants, java.util.Set<String> breakGlassIds, Permission.Context context) {
        if (!(value instanceof PkiOperationValue.ObjectValue object)
                || !(object.fields().get("caId") instanceof PkiOperationValue.Text id)) return false;
        PkiId authorityId = new PkiId(id.value());
        if (!exposure.allows(authorityId)) return false;
        Permission.Resource resource = new Permission.Resource(Permission.ResourceType.AUTHORITY,
                new Permission.Scope(realmId, Optional.of(authorityId), Optional.empty(), Optional.empty()),
                Optional.of(authorityId), Optional.empty());
        return authorization.authorize(new AuthorizationEngine.Request(realmId, exposure, principal,
                Permission.Action.AUTHORITY_LIST, resource, Permission.Relationship.ANY,
                Permission.DataView.METADATA_REDACTED, context, grants, breakGlassIds)).allowed();
    }

    private Permission.Context approvalContext(Request request) {
        return new Permission.Context(request.context().reason(), request.approvalId().isPresent(),
                request.context().authorityActive(), request.context().safeAttributes());
    }

    private void validateAuthoritativeScope(PkiOperation operation, Permission.Resource resource) {
        Optional<PkiId> actual = switch (operation) {
            case PkiOperation.InspectCredential value -> resourceScopes.credentialAuthority(value.credentialId());
            case PkiOperation.RevokeCredential value -> resourceScopes.credentialAuthority(value.credentialId());
            case PkiOperation.ReadRevocationHistory value -> resourceScopes.credentialAuthority(value.credentialId());
            case PkiOperation.InspectPublication value -> resourceScopes.publicationAuthority(value.publicationId());
            case PkiOperation.ProcessPublication value -> resourceScopes.publicationAuthority(value.publicationId());
            default -> resource.scope().authorityId();
        };
        if (requiresResolvedAuthority(operation)
                && (actual.isEmpty() || !actual.equals(resource.scope().authorityId()))) {
            throw new SecurityException("Authoritative object scope does not match the request");
        }
    }

    private void validateControlScope(ServerControlOperation operation, Permission.Resource resource) {
        Permission.Scope actual = switch (operation) {
            case ServerControlOperation.CreateRoleAssignment value -> value.assignment().scope();
            case ServerControlOperation.InspectRoleAssignment value -> control.requireAssignment(value.assignmentId()).scope();
            case ServerControlOperation.RevokeRoleAssignment value -> control.requireAssignment(value.assignmentId()).scope();
            case ServerControlOperation.CreateGrant value -> value.grant().scope();
            case ServerControlOperation.InspectGrant value -> control.requireGrant(value.grantId()).scope();
            case ServerControlOperation.RevokeGrant value -> control.requireGrant(value.grantId()).scope();
            case ServerControlOperation.EvaluateAuthorization value -> value.resource().scope();
            case ServerControlOperation.RequestApproval value -> value.targetResource().scope();
            case ServerControlOperation.InspectApproval value -> approvals.requireCurrent(value.approvalId()).scope();
            case ServerControlOperation.DecideApproval value -> approvals.requireCurrent(value.approvalId()).scope();
            case ServerControlOperation.CancelApproval value -> approvals.requireCurrent(value.approvalId()).scope();
            case ServerControlOperation.CreateBreakGlass value -> value.grant().scope();
            case ServerControlOperation.ActivateBreakGlass value -> breakGlass.requireCurrent(value.breakGlassId()).grant().scope();
            case ServerControlOperation.InspectBreakGlass value -> breakGlass.requireCurrent(value.breakGlassId()).grant().scope();
            case ServerControlOperation.RevokeBreakGlass value -> breakGlass.requireCurrent(value.breakGlassId()).grant().scope();
            default -> resource.scope();
        };
        if (!actual.equals(resource.scope())) throw new SecurityException("Control scope differs");
    }

    private static boolean requiresResolvedAuthority(PkiOperation operation) {
        return operation instanceof PkiOperation.InspectCredential
                || operation instanceof PkiOperation.RevokeCredential
                || operation instanceof PkiOperation.ReadRevocationHistory
                || operation instanceof PkiOperation.InspectPublication
                || operation instanceof PkiOperation.ProcessPublication;
    }

    private Outcome denied(Request request, AuthorizationEngine.Code code) {
        audit.record("AUTHORIZATION_DENY", request.principalId(), Optional.empty(),
                gatewayDetails(request, "code", code.name()));
        return new Outcome.Denied(code);
    }

    private static Map<String, String> gatewayDetails(Request request, String resultName, String result) {
        Map<String, String> details = new LinkedHashMap<>();
        details.put("operation", request.operation().name());
        details.put(resultName, result);
        details.put("correlation", request.correlationId());
        details.put("authenticationMode", request.authenticationMode().name());
        details.put("endClientPrincipal", request.principalId());
        request.transportPrincipalId().ifPresent(value -> details.put("transportPrincipal", value));
        return Map.copyOf(details);
    }

    private static Permission.Action action(PkiOperation operation, Permission.Action defaultAction) {
        if (operation instanceof PkiOperation.TransitionAuthority transition) {
            return switch (transition.state()) {
                case ACTIVE -> Permission.Action.AUTHORITY_ACTIVATE;
                case RETIRED -> Permission.Action.AUTHORITY_RETIRE;
                case COMPROMISED, DISABLED -> Permission.Action.AUTHORITY_SUSPEND;
            };
        }
        return defaultAction;
    }

    private static String classification(PkiOperationOutcome outcome) {
        return switch (outcome) {
            case PkiOperationOutcome.Success ignored -> "SUCCEEDED";
            case PkiOperationOutcome.Failure failure -> failure.classification().name();
        };
    }

    private static String classification(ServerControlOperationOutcome outcome) {
        if (outcome instanceof ServerControlOperationOutcome.OneTimeSensitive) return "SUCCEEDED";
        PkiOperationOutcome ordinary = ((ServerControlOperationOutcome.Ordinary) outcome).outcome();
        return classification(ordinary);
    }
}
