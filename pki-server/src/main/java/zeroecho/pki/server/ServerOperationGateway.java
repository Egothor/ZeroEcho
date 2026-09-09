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
import java.util.function.Function;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.publication.PublicationSourceType;
import zeroecho.pki.api.profile.IssuanceApprovalRequirement;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationExecutor;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.application.RevocationEvidenceExecutor;
import zeroecho.pki.application.RevocationExecutionEvidence;
import zeroecho.pki.server.acme.AcmeService;
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
        "PMD.NcssCount", "PMD.ConfusingTernary", "PMD.ExceptionAsFlowControl",
        "PMD.CouplingBetweenObjects" })
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

        /**
         * Wraps an existing PKI operation for source-compatible embedded callers.
         *
         * @param realmId target realm
         * @param principalId authenticated principal identifier
         * @param operation exact typed PKI operation
         * @param resource exact target resource
         * @param relationship requester-to-resource relationship
         * @param context closed authorization context
         * @param approvalId optional execution approval
         * @param correlationId bounded non-secret request correlation identifier
         */
        public Request(RealmId realmId, String principalId, PkiOperation operation,
                Permission.Resource resource, Permission.Relationship relationship, Permission.Context context,
                Optional<String> approvalId, String correlationId) {
            this(realmId, principalId, AdministrativeAuthenticationMode.DIRECT_MTLS, Optional.empty(),
                    new AdministrativeOperation.Pki(operation), resource, relationship, context, approvalId,
                    correlationId);
        }

        /**
         * Creates a direct-mTLS request for existing embedded control callers.
         *
         * @param realmId target realm
         * @param principalId authenticated principal identifier
         * @param operation exact typed administrative operation
         * @param resource exact target resource
         * @param relationship requester-to-resource relationship
         * @param context closed authorization context
         * @param approvalId optional execution approval
         * @param correlationId bounded non-secret request correlation identifier
         */
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
        /**
         * Successfully admitted operation and exact backend outcome.
         *
         * @param outcome exact typed PKI backend outcome
         */
        record Executed(PkiOperationOutcome outcome) implements Outcome {
            /** Validates the backend result. */ public Executed { Objects.requireNonNull(outcome, "outcome"); }
        }
        /**
         * Successfully admitted server-control result.
         *
         * @param outcome exact typed server-control outcome
         */
        record ControlExecuted(ServerControlOperationOutcome outcome) implements Outcome {
            /** Validates the control result. */ public ControlExecuted { Objects.requireNonNull(outcome, "outcome"); }
        }
        /**
         * Safe denial without protected-object existence information.
         *
         * @param code stable non-sensitive denial code
         */
        record Denied(AuthorizationEngine.Code code) implements Outcome {
            /** Validates the safe code. */ public Denied { Objects.requireNonNull(code, "code"); }
        }
        /**
         * High-risk operation requires a separately created durable approval.
         *
         * @param operationCommitment exact safe operation commitment to approve
         */
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
    private final Function<String, IssuanceApprovalRequirement> issuanceApprovalRequirements;
    private final SafeAudit audit;
    private final Runnable reconciliationWake;
    private final Runnable openCheck;

    /**
     * Creates one gateway bound to one realm and one session executor.
     *
     * <p>The credential-publication gate must be realm-owned and use the same
     * disclosure service supplied to this constructor.</p>
     *
     * @param realmId exact realm identity
     * @param exposure authority exposure policy for the realm
     * @param control durable server-control store
     * @param roles role-template catalog
     * @param authorization authorization engine
     * @param approvals durable approval service
     * @param breakGlass emergency-access service
     * @param disclosure durable disclosure service
     * @param credentialPublication authoritative credential-publication gate
     * @param auditorViews audit-view service
     * @param repositoryAliases optional repository-alias capability
     * @param descriptors closed operation-security descriptor catalog
     * @param executor session-owned PKI operation executor
     * @param resourceScopes authoritative PKI resource-scope resolver
     * @param approvalPolicies approval policy by operation category
     * @param issuanceApprovalRequirements resolves the active certificate profile's issuance
     *            approval requirement by profile identifier
     * @param clock authoritative realm clock
     * @param auditSink safe audit sink
     * @param reconciliationWake signal for newly actionable reconciliation work
     * @param openCheck realm lifecycle guard
     */
    public ServerOperationGateway(RealmId realmId, AuthorityExposurePolicy exposure, ServerControlStore control,
            RoleTemplateCatalog roles, AuthorizationEngine authorization, ApprovalService approvals,
            BreakGlassService breakGlass, DisclosureService disclosure,
            CredentialPublicationGate credentialPublication, AuditorViews auditorViews,
            Optional<RepositoryAliasService> repositoryAliases,
            OperationSecurityDescriptors descriptors, PkiOperationExecutor executor,
            PkiResourceScopeResolver resourceScopes,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> approvalPolicies,
            Function<String, IssuanceApprovalRequirement> issuanceApprovalRequirements,
            java.time.Clock clock, zeroecho.pki.spi.audit.AuditSink auditSink, Runnable reconciliationWake,
            Runnable openCheck) {
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
                authorization, approvals, breakGlass, disclosure, credentialPublication, auditorViews,
                repositoryAliases, descriptors, approvalPolicies);
        this.resourceScopes = Objects.requireNonNull(resourceScopes, "resourceScopes");
        this.approvalPolicies = Map.copyOf(Objects.requireNonNull(approvalPolicies, "approvalPolicies"));
        this.issuanceApprovalRequirements = Objects.requireNonNull(issuanceApprovalRequirements,
                "issuanceApprovalRequirements");
        this.audit = new SafeAudit(clock, auditSink);
        this.reconciliationWake = Objects.requireNonNull(reconciliationWake, "reconciliationWake");
        this.openCheck = Objects.requireNonNull(openCheck, "openCheck");
    }

    /**
     * Creates one gateway whose reconciliation is driven only by periodic polling.
     *
     * <p>The credential-publication gate must be realm-owned and use the same
     * disclosure service supplied to this constructor.</p>
     *
     * @param realmId exact realm identity
     * @param exposure authority exposure policy for the realm
     * @param control durable server-control store
     * @param roles role-template catalog
     * @param authorization authorization engine
     * @param approvals durable approval service
     * @param breakGlass emergency-access service
     * @param disclosure durable disclosure service
     * @param credentialPublication authoritative credential-publication gate
     * @param auditorViews audit-view service
     * @param repositoryAliases optional repository-alias capability
     * @param descriptors closed operation-security descriptor catalog
     * @param executor session-owned PKI operation executor
     * @param resourceScopes authoritative PKI resource-scope resolver
     * @param approvalPolicies approval policy by operation category
     * @param issuanceApprovalRequirements resolves the active certificate profile's issuance
     *            approval requirement by profile identifier
     * @param clock authoritative realm clock
     * @param auditSink safe audit sink
     * @param openCheck realm lifecycle guard
     */
    public ServerOperationGateway(RealmId realmId, AuthorityExposurePolicy exposure, ServerControlStore control,
            RoleTemplateCatalog roles, AuthorizationEngine authorization, ApprovalService approvals,
            BreakGlassService breakGlass, DisclosureService disclosure,
            CredentialPublicationGate credentialPublication, AuditorViews auditorViews,
            Optional<RepositoryAliasService> repositoryAliases,
            OperationSecurityDescriptors descriptors, PkiOperationExecutor executor,
            PkiResourceScopeResolver resourceScopes,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> approvalPolicies,
            Function<String, IssuanceApprovalRequirement> issuanceApprovalRequirements,
            java.time.Clock clock, zeroecho.pki.spi.audit.AuditSink auditSink, Runnable openCheck) {
        this(realmId, exposure, control, roles, authorization, approvals, breakGlass, disclosure,
                credentialPublication, auditorViews, repositoryAliases, descriptors, executor, resourceScopes,
                approvalPolicies, issuanceApprovalRequirements, clock, auditSink, () -> { }, openCheck);
    }

    /**
     * Installs the optional configured ACME control capability once before listener readiness.
     *
     * @param service realm-owned ACME service
     */
    public void installAcme(AcmeService service) { controlExecutor.installAcme(service); }
    /**
     * Installs the realm-owned OCSP administration capability before readiness.
     *
     * @param service realm-owned OCSP responder service
     */
    public void installOcsp(OcspResponderService service) { controlExecutor.installOcsp(service); }

    /**
     * Installs the queryable/verifiable audit capability when the configured sink supports it.
     *
     * @param search queryable audit service
     * @param integrity audit-integrity verification service
     */
    public void installAudit(zeroecho.pki.api.audit.AuditService search,
            zeroecho.pki.api.audit.AuditIntegrityService integrity) {
        controlExecutor.installAudit(search, integrity);
    }
    /**
     * Admits and synchronously executes one operation.
     *
     * @param request complete security request
     * @param cancellation cooperative cancellation signal passed unchanged to PKI
     * @return safe gateway outcome
     */
    // The ordered authentication, authorization, approval, and dispatch checks form one auditable security gate.
    @SuppressWarnings("PMD.CognitiveComplexity")
    public Outcome execute(Request request, CancellationSignal cancellation) {
        openCheck.run();
        Request exact = Objects.requireNonNull(request, "request");
        Objects.requireNonNull(cancellation, "cancellation");
        if (!realmId.equals(exact.realmId()) || !realmId.equals(exact.resource().scope().realmId())) {
            return denied(exact, AuthorizationEngine.Code.OUTSIDE_REALM);
        }
        try {
            exact = authoritativeRequest(exact);
        } catch (SecurityException | IllegalArgumentException | IllegalStateException invalid) {
            return denied(exact, AuthorizationEngine.Code.NO_MATCHING_GRANT);
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
        } catch (SecurityException | IllegalArgumentException | IllegalStateException invalid) {
            // IllegalStateException covers an authoritative-scope source that cannot yield a coordinate
            // (e.g. a publication whose CREDENTIAL source is not an end-entity credential); it fails closed
            // as a uniform denial rather than escaping as an unclassified error, matching authoritativeRequest.
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
        boolean grantApprovalRequired = decision.code() == AuthorizationEngine.Code.APPROVAL_REQUIRED;
        if (exact.approvalId().isPresent() && decision.allowed()) {
            Permission.Context withoutApproval = operationContext(exact.operation(), exact.context(), false);
            AuthorizationEngine.Decision withoutApprovalDecision = authorization.authorize(
                    new AuthorizationEngine.Request(realmId, exposure, principal, action, exact.resource(),
                            exact.relationship(), descriptor.dataView(), withoutApproval, grants,
                            emergency.grantIds()));
            grantApprovalRequired = withoutApprovalDecision.code() == AuthorizationEngine.Code.APPROVAL_REQUIRED;
        }
        OperationSecurityDescriptors.ApprovalCategory approvalCategory = descriptors.approvalPolicyCategory(
                exact.operation(), grantApprovalRequired);
        Optional<String> profileDriven = profileDrivenIssuanceProfileId(exact.operation());
        if (profileDriven.isPresent()) {
            approvalCategory = issuanceApprovalCategory(profileDriven.orElseThrow());
        }
        boolean filterableList = exact.operation() instanceof AdministrativeOperation.Pki pki
                && pki.operation() instanceof PkiOperation.ListAuthorities
                && decision.code() == AuthorizationEngine.Code.NO_MATCHING_GRANT;
        boolean conditionallyApprovable = decision.code() == AuthorizationEngine.Code.APPROVAL_REQUIRED
                && approvalCategory != OperationSecurityDescriptors.ApprovalCategory.NONE;
        if (!decision.allowed() && !filterableList && !conditionallyApprovable) {
            return denied(exact, decision.code());
        }
        Optional<OperationSecurityDescriptors.ApprovalCategory> approvedTargetCategory = Optional.empty();
        if (exact.operation() instanceof AdministrativeOperation.Control controlOperation
                && controlOperation.operation() instanceof ServerControlOperation.RequestApproval requestApproval) {
            approvedTargetCategory = approvedTargetCategory(exact, requestApproval, principal, grants,
                    emergency.grantIds());
            if (approvedTargetCategory.isEmpty()) {
                return denied(exact, AuthorizationEngine.Code.NO_MATCHING_GRANT);
            }
        }
        Optional<RevocationEvidenceExecutor> revocationExecutor = Optional.empty();
        if (exact.operation() instanceof AdministrativeOperation.Pki pki
                && (pki.operation() instanceof PkiOperation.RevokeCredential
                        || pki.operation() instanceof PkiOperation.RevokePendingCredentialConfirmation)) {
            revocationExecutor = Optional.of(RevocationEvidenceExecutor.require(executor));
        }
        if (decision.usedBreakGlass()) breakGlass.auditUse(principal.principalId());
        String commitment = descriptors.commitment(realmId, exact.operation(), exact.resource());
        Optional<String> claimedApproval = Optional.empty();
        if (approvalCategory != OperationSecurityDescriptors.ApprovalCategory.NONE) {
            ApprovalService.Policy expected = approvalPolicies.get(approvalCategory);
            if (expected == null) {
                throw new IllegalStateException("Approval policy is not configured for the operation category");
            }
            if (exact.approvalId().isEmpty()) return new Outcome.ApprovalRequired(commitment);
            ApprovalService.Request current = approvals.requireCurrent(exact.approvalId().orElseThrow());
            if (!current.policyCommitment().equals(expected.commitment())) {
                return denied(exact, AuthorizationEngine.Code.APPROVAL_REQUIRED);
            }
            approvals.claim(current.approvalId(), exact.operation().name(), commitment, exact.resource().scope());
            claimedApproval = Optional.of(current.approvalId());
        }
        if (exact.operation() instanceof AdministrativeOperation.Pki pki) {
            PkiOperationOutcome backend;
            if (pki.operation() instanceof PkiOperation.RevokeCredential revocation) {
                RevocationExecutionEvidence evidence = RevocationExecutionEvidence.administrative(
                        principal.principalId(), realmId.value(), exact.correlationId(),
                        authentication(exact.authenticationMode()), authorizationPath(decision, claimedApproval),
                        commitment, revocation.operatorJustification());
                backend = revocationExecutor.orElseThrow().executeRevocation(revocation, evidence, cancellation);
                wakeAfterCommittedRevocation(backend);
            } else if (pki.operation()
                    instanceof PkiOperation.RevokePendingCredentialConfirmation revocation) {
                RevocationExecutionEvidence evidence = RevocationExecutionEvidence.administrative(
                        principal.principalId(), realmId.value(), exact.correlationId(),
                        authentication(exact.authenticationMode()), authorizationPath(decision, claimedApproval),
                        commitment, revocation.operatorJustification());
                backend = revocationExecutor.orElseThrow().executePendingConfirmationRevocation(
                        revocation, evidence, cancellation);
                wakeAfterCommittedRevocation(backend);
            } else if (pki.operation() instanceof PkiOperation.IssueCredential issue) {
                IssuanceExecutionEvidence evidence = IssuanceExecutionEvidence.administrative(
                        principal.principalId(), realmId.value(), exact.correlationId(),
                        issuanceAuthentication(exact.authenticationMode()),
                        issuanceAuthorizationPath(decision, claimedApproval), commitment,
                        issue.issuerCaId().value(), issue.profileId());
                backend = executor.execute(pki.operation(), evidence.attributes(), cancellation);
            } else if (pki.operation() instanceof PkiOperation.RenewCredential renew) {
                backend = executeLifecycleIssuance(pki.operation(), renew.credentialId(), Optional.empty(),
                        principal, exact, decision, claimedApproval, commitment, cancellation);
            } else if (pki.operation() instanceof PkiOperation.ReissueCredential reissue) {
                backend = executeLifecycleIssuance(pki.operation(), reissue.credentialId(), Optional.empty(),
                        principal, exact, decision, claimedApproval, commitment, cancellation);
            } else if (pki.operation() instanceof PkiOperation.ReplaceCredential replace) {
                backend = executeLifecycleIssuance(pki.operation(), replace.existingCredentialId(),
                        Optional.of(replace.profileId()), principal, exact, decision, claimedApproval, commitment,
                        cancellation);
            } else {
                backend = executor.execute(pki.operation(), cancellation);
            }
            if (pki.operation() instanceof PkiOperation.ListAuthorities) {
                backend = filterAuthorities(backend, principal, grants, emergency.grantIds(), exact.context());
            }
            if (claimedApproval.isPresent()) approvals.complete(claimedApproval.orElseThrow(), classification(backend));
            audit.record("GATEWAY_RESULT", principal.principalId(), exact.resource().objectId(),
                    gatewayDetails(exact, "result", classification(backend)));
            return new Outcome.Executed(backend);
        }
        ServerControlOperation controlOperation = ((AdministrativeOperation.Control) exact.operation()).operation();
        ServerControlOperationOutcome controlResult = controlExecutor.executeAuthorized(controlOperation,
                principal.principalId(), exact.resource(), exact.approvalId(), approvedTargetCategory,
                cancellation);
        String result = classification(controlResult);
        if (claimedApproval.isPresent()) approvals.complete(claimedApproval.orElseThrow(), result);
        audit.record("GATEWAY_RESULT", principal.principalId(), exact.resource().objectId(),
                gatewayDetails(exact, "result", result));
        return new Outcome.ControlExecuted(controlResult);
    }

    private static RevocationExecutionEvidence.Authentication authentication(
            AdministrativeAuthenticationMode mode) {
        return switch (mode) {
            case DIRECT_MTLS -> RevocationExecutionEvidence.Authentication.DIRECT_MTLS;
            case TRUSTED_REVERSE_PROXY -> RevocationExecutionEvidence.Authentication.TRUSTED_REVERSE_PROXY;
        };
    }

    private void wakeAfterCommittedRevocation(PkiOperationOutcome outcome) {
        if (outcome instanceof PkiOperationOutcome.Completed) {
            signalReconciliation();
        }
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException") // A committed result must not depend on advisory wakeup.
    private void signalReconciliation() {
        try {
            reconciliationWake.run();
        } catch (RuntimeException ignored) {
            // Periodic reconciliation remains authoritative after a failed advisory wake.
        }
    }

    private static RevocationExecutionEvidence.AuthorizationPath authorizationPath(
            AuthorizationEngine.Decision decision, Optional<String> claimedApproval) {
        if (decision.usedBreakGlass()) return RevocationExecutionEvidence.AuthorizationPath.BREAK_GLASS;
        return claimedApproval.isPresent() ? RevocationExecutionEvidence.AuthorizationPath.APPROVAL
                : RevocationExecutionEvidence.AuthorizationPath.ORDINARY_GRANT;
    }

    private static IssuanceExecutionEvidence.Authentication issuanceAuthentication(
            AdministrativeAuthenticationMode mode) {
        return switch (mode) {
            case DIRECT_MTLS -> IssuanceExecutionEvidence.Authentication.DIRECT_MTLS;
            case TRUSTED_REVERSE_PROXY -> IssuanceExecutionEvidence.Authentication.TRUSTED_REVERSE_PROXY;
        };
    }

    private static IssuanceExecutionEvidence.AuthorizationPath issuanceAuthorizationPath(
            AuthorizationEngine.Decision decision, Optional<String> claimedApproval) {
        if (decision.usedBreakGlass()) return IssuanceExecutionEvidence.AuthorizationPath.BREAK_GLASS;
        return claimedApproval.isPresent() ? IssuanceExecutionEvidence.AuthorizationPath.APPROVAL
                : IssuanceExecutionEvidence.AuthorizationPath.ORDINARY_GRANT;
    }

    // Renew/replace/reissue produce a new credential just like IssueCredential, so they co-commit the same
    // issuance evidence. The issuing authority (and, for renew/reissue, the frozen profile) is the target
    // credential's AUTHORITATIVE coordinate resolved by the scope resolver, never a caller claim. If the
    // target credential cannot be resolved the operation will fail during execution, so evidence is omitted.
    private PkiOperationOutcome executeLifecycleIssuance(PkiOperation operation, PkiId existingCredentialId,
            Optional<String> overrideProfileId, SecurityPrincipal principal, Request exact,
            AuthorizationEngine.Decision decision, Optional<String> claimedApproval, String commitment,
            CancellationSignal cancellation) {
        Optional<PkiResourceScopeResolver.CredentialScope> scope =
                resourceScopes.credentialScope(existingCredentialId);
        if (scope.isEmpty()) {
            return executor.execute(operation, cancellation);
        }
        PkiResourceScopeResolver.CredentialScope coordinates = scope.orElseThrow();
        IssuanceExecutionEvidence evidence = IssuanceExecutionEvidence.administrative(
                principal.principalId(), realmId.value(), exact.correlationId(),
                issuanceAuthentication(exact.authenticationMode()),
                issuanceAuthorizationPath(decision, claimedApproval), commitment,
                coordinates.authorityId().value(), overrideProfileId.orElseGet(coordinates::profileId));
        return executor.execute(operation, evidence.attributes(), cancellation);
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

    /**
     * Resolves one descriptor by its immutable administrative operation family.
     *
     * @param operation decoded transport-neutral administrative operation
     * @return immutable descriptor from the sole gateway authority
     */
    public OperationSecurityDescriptors.Descriptor descriptor(AdministrativeOperation operation) {
        openCheck.run();
        return descriptors.require(operation);
    }

    /**
     * Resolves one descriptor by stable ID before closed typed decoding.
     *
     * @param operationId stable operation identifier
     * @return immutable descriptor from the sole gateway authority
     */
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
        if (!(outcome instanceof PkiOperationOutcome.Completed success)) return outcome;
        PkiOperationValue value = success.result().fields().get("authorities");
        if (!(value instanceof PkiOperationValue.ListValue list)) return outcome;
        List<PkiOperationValue> allowed = list.values().stream().filter(item -> authorityAllowed(item, principal,
                grants, breakGlassIds, context)).toList();
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>(success.result().fields());
        fields.put("count", new PkiOperationValue.IntegerValue(allowed.size()));
        fields.put("authorities", new PkiOperationValue.ListValue(allowed));
        return new PkiOperationOutcome.Completed(new PkiOperationResult(success.result().operationName(), fields));
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
        return operationContext(request.operation(), request.context(), request.approvalId().isPresent());
    }

    /**
     * Resolves the dynamic approval category mandated by the active certificate
     * profile for one end-entity issuance.
     *
     * <p>The profile's {@link IssuanceApprovalRequirement} is the authoritative
     * selector: {@code NONE} leaves issuance ungated, {@code SINGLE} maps to
     * {@link OperationSecurityDescriptors.ApprovalCategory#ISSUANCE_SINGLE}, and
     * {@code THRESHOLD} maps to
     * {@link OperationSecurityDescriptors.ApprovalCategory#ISSUANCE_THRESHOLD}. An
     * unresolvable profile fails closed to {@code NONE}; the core issuance service
     * then rejects the inactive or unknown profile, so an approval gate is never
     * silently skipped for a profile that could actually issue.</p>
     *
     * @param issue exact end-entity issuance operation
     * @return the mandated approval category
     */
    // Lifecycle operations whose approval is driven by the target profile's issuance approval
    // requirement (Task 7), so renewal, replacement, and reissue are governed by the same,
    // predictable policy as issuing a new certificate under that profile. Issue and replace carry
    // the profile id on the command; renew and reissue resolve the target credential's AUTHORITATIVE
    // profile through the resource-scope resolver (never a caller-supplied claim), so approval
    // strength cannot be weakened by lying about the profile.
    private Optional<String> profileDrivenIssuanceProfileId(AdministrativeOperation operation) {
        if (!(operation instanceof AdministrativeOperation.Pki pki)) {
            return Optional.empty();
        }
        return switch (pki.operation()) {
            case PkiOperation.IssueCredential issue -> Optional.of(issue.profileId());
            case PkiOperation.ReplaceCredential replace -> Optional.of(replace.profileId());
            case PkiOperation.RenewCredential renew -> resourceScopes.credentialScope(renew.credentialId())
                    .map(PkiResourceScopeResolver.CredentialScope::profileId);
            case PkiOperation.ReissueCredential reissue -> resourceScopes.credentialScope(reissue.credentialId())
                    .map(PkiResourceScopeResolver.CredentialScope::profileId);
            default -> Optional.empty();
        };
    }

    // An unavailable dynamic requirement resolver retains the established NONE fallback classification.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private OperationSecurityDescriptors.ApprovalCategory issuanceApprovalCategory(String profileId) {
        IssuanceApprovalRequirement requirement;
        try {
            requirement = issuanceApprovalRequirements.apply(profileId);
        } catch (RuntimeException unresolved) {
            return OperationSecurityDescriptors.ApprovalCategory.NONE;
        }
        if (requirement == null) {
            return OperationSecurityDescriptors.ApprovalCategory.NONE;
        }
        return switch (requirement) {
            case NONE -> OperationSecurityDescriptors.ApprovalCategory.NONE;
            case SINGLE -> OperationSecurityDescriptors.ApprovalCategory.ISSUANCE_SINGLE;
            case THRESHOLD -> OperationSecurityDescriptors.ApprovalCategory.ISSUANCE_THRESHOLD;
        };
    }

    private Optional<OperationSecurityDescriptors.ApprovalCategory> approvedTargetCategory(Request request,
            ServerControlOperation.RequestApproval approvalRequest, SecurityPrincipal principal,
            List<Permission.Grant> grants, java.util.Set<String> breakGlassIds) {
        OperationSecurityDescriptors.Descriptor target;
        try {
            target = descriptors.require(approvalRequest.targetOperation());
            if (target.resourceType() != approvalRequest.targetResource().type()) {
                return Optional.empty();
            }
            if (approvalRequest.targetOperation() instanceof AdministrativeOperation.Pki targetPki) {
                descriptors.validateResource(targetPki.operation(), approvalRequest.targetResource());
                validateAuthoritativeScope(targetPki.operation(), approvalRequest.targetResource());
            }
        } catch (SecurityException | IllegalArgumentException | IllegalStateException mismatch) {
            return Optional.empty();
        }
        Permission.Context withoutApproval = operationContext(approvalRequest.targetOperation(),
                request.context(), false);
        AuthorizationEngine.Decision withoutApprovalDecision = authorization.authorize(
                new AuthorizationEngine.Request(realmId, exposure, principal, target.action(),
                        approvalRequest.targetResource(), request.relationship(), target.dataView(), withoutApproval,
                        grants, breakGlassIds));
        Optional<String> profileDrivenProfileId = profileDrivenIssuanceProfileId(approvalRequest.targetOperation());
        if (profileDrivenProfileId.isPresent()) {
            OperationSecurityDescriptors.ApprovalCategory issuanceCategory =
                    issuanceApprovalCategory(profileDrivenProfileId.orElseThrow());
            if (issuanceCategory == OperationSecurityDescriptors.ApprovalCategory.NONE) {
                return Optional.empty();
            }
            return withoutApprovalDecision.allowed() ? Optional.of(issuanceCategory) : Optional.empty();
        }
        if (target.approvalCategory() != OperationSecurityDescriptors.ApprovalCategory.NONE) {
            return withoutApprovalDecision.allowed() ? Optional.of(target.approvalCategory()) : Optional.empty();
        }
        if (withoutApprovalDecision.code() != AuthorizationEngine.Code.APPROVAL_REQUIRED) {
            return Optional.empty();
        }
        Permission.Context withApproval = operationContext(approvalRequest.targetOperation(), request.context(),
                true);
        AuthorizationEngine.Decision withApprovalDecision = authorization.authorize(
                new AuthorizationEngine.Request(realmId, exposure, principal, target.action(),
                        approvalRequest.targetResource(), request.relationship(), target.dataView(), withApproval,
                        grants, breakGlassIds));
        if (!withApprovalDecision.allowed()) {
            return Optional.empty();
        }
        OperationSecurityDescriptors.ApprovalCategory category = descriptors.approvalPolicyCategory(
                approvalRequest.targetOperation(), true);
        return category == OperationSecurityDescriptors.ApprovalCategory.NONE
                ? Optional.empty() : Optional.of(category);
    }

    private static Permission.Context operationContext(AdministrativeOperation operation,
            Permission.Context supplied, boolean approvalPresent) {
        Optional<String> justification = supplied.operatorJustification();
        if (operation instanceof AdministrativeOperation.Pki pki) {
            justification = switch (pki.operation()) {
                case PkiOperation.RevokeCredential value -> value.operatorJustification();
                case PkiOperation.RevokePendingCredentialConfirmation value ->
                    value.operatorJustification();
                case PkiOperation.TransitionAuthority value -> Optional.of(value.reason());
                default -> justification;
            };
        }
        return new Permission.Context(justification, approvalPresent, supplied.authorityActive(),
                supplied.safeAttributes());
    }

    private void validateAuthoritativeScope(PkiOperation operation, Permission.Resource resource) {
        if (confirmationCredentialId(operation).isPresent()) {
            return;
        }
        Optional<PkiId> actual = switch (operation) {
            case PkiOperation.InspectCredential value -> credentialAuthority(value.credentialId());
            case PkiOperation.RevokeCredential value -> credentialAuthority(value.credentialId());
            case PkiOperation.RevokePendingCredentialConfirmation value ->
                credentialAuthority(value.credentialId());
            case PkiOperation.ReadRevocationHistory value -> credentialAuthority(value.credentialId());
            case PkiOperation.InspectPublication value -> resourceScopes.publicationAuthority(value.publicationId());
            case PkiOperation.ProcessPublication value -> resourceScopes.publicationAuthority(value.publicationId());
            case PkiOperation.RetryPublication value -> resourceScopes.publicationAuthority(value.publicationId());
            case PkiOperation.ReconcilePublication value -> resourceScopes.publicationAuthority(value.publicationId());
            case PkiOperation.RegisterPublication value -> sourceAuthority(value.sourceType(), value.sourceId());
            default -> resource.scope().authorityId();
        };
        if (requiresResolvedAuthority(operation)
                && (actual.isEmpty() || !actual.equals(resource.scope().authorityId()))) {
            throw new SecurityException("Authoritative object scope does not match the request");
        }
    }

    private Optional<PkiId> credentialAuthority(PkiId credentialId) {
        return resourceScopes.credentialScope(credentialId).map(PkiResourceScopeResolver.CredentialScope::authorityId);
    }

    // Resolves the owning authority of a not-yet-registered publication directly from its declared immutable
    // source, so RegisterPublication is bound to the real owner exactly as retry/reconcile are bound via the
    // committed record. A missing source resolves to empty and therefore fails closed.
    private Optional<PkiId> sourceAuthority(PublicationSourceType sourceType, PkiId sourceId) {
        return sourceType == PublicationSourceType.CREDENTIAL
                ? credentialAuthority(sourceId)
                : resourceScopes.statusObjectAuthority(sourceId);
    }

    private Request authoritativeRequest(Request request) {
        Request exact = authoritativeControlRequest(request);
        if (!(exact.operation() instanceof AdministrativeOperation.Pki pki)) {
            return exact;
        }
        Optional<PkiId> selectedCredential = confirmationCredentialId(pki.operation());
        if (selectedCredential.isEmpty()) return exact;
        PkiId credentialId = selectedCredential.orElseThrow();
        Permission.Resource authoritative = authoritativeConfirmationResource(
                credentialId, exact.resource(), exact.relationship());
        return new Request(exact.realmId(), exact.principalId(), exact.authenticationMode(),
                exact.transportPrincipalId(), exact.operation(), authoritative, Permission.Relationship.ANY,
                exact.context(), exact.approvalId(), exact.correlationId());
    }

    private static Optional<PkiId> confirmationCredentialId(PkiOperation operation) {
        return switch (operation) {
            case PkiOperation.IssueCredentialConfirmationChallenge value -> Optional.of(value.credentialId());
            case PkiOperation.CompleteCredentialConfirmationProof value ->
                Optional.of(value.submission().proofCas().credentialId());
            case PkiOperation.RevokePendingCredentialConfirmation value ->
                Optional.of(value.credentialId());
            default -> Optional.empty();
        };
    }

    private Request authoritativeControlRequest(Request request) {
        Request exact = request;
        if (request.operation() instanceof AdministrativeOperation.Control controlOperation) {
            ServerControlOperation operation = controlOperation.operation();
            if (operation instanceof ServerControlOperation.RegisterAcmeDirectory registration) {
                exact = withControlOperation(request,
                        controlExecutor.bindAcmeDirectoryRegistration(registration));
            } else if (operation instanceof ServerControlOperation.RequestApproval approval
                    && approval.targetOperation() instanceof AdministrativeOperation.Control target
                    && target.operation() instanceof ServerControlOperation.RegisterAcmeDirectory registration) {
                ServerControlOperation.RegisterAcmeDirectory bound =
                        controlExecutor.bindAcmeDirectoryRegistration(registration);
                exact = withControlOperation(request, new ServerControlOperation.RequestApproval(
                        approval.approvalId(), new AdministrativeOperation.Control(bound),
                        approval.targetResource()));
            } else if (operation instanceof ServerControlOperation.RequestApproval approval
                    && approval.targetOperation() instanceof AdministrativeOperation.Pki target
                    && target.operation()
                            instanceof PkiOperation.RevokePendingCredentialConfirmation revocation) {
                Permission.Resource targetResource = authoritativeConfirmationResource(
                        revocation.credentialId(), approval.targetResource(), request.relationship());
                ServerControlOperation.RequestApproval bound = new ServerControlOperation.RequestApproval(
                        approval.approvalId(), approval.targetOperation(), targetResource);
                Permission.Resource approvalResource = authoritativeApprovalResource(
                        request.resource(), targetResource.scope());
                exact = new Request(request.realmId(), request.principalId(), request.authenticationMode(),
                        request.transportPrincipalId(), new AdministrativeOperation.Control(bound),
                        approvalResource, Permission.Relationship.ANY, request.context(),
                        request.approvalId(), request.correlationId());
            }
        }
        if (!(exact.operation() instanceof AdministrativeOperation.Control controlOperation)
                || !(controlOperation.operation()
                        instanceof ServerControlOperation.EnrollCredentialPublication enrollment)) {
            return exact;
        }
        Permission.Resource supplied = exact.resource();
        Permission.Resource authoritative = controlExecutor.credentialPublicationResource(enrollment);
        if (supplied.type() != Permission.ResourceType.CERTIFICATE
                || !supplied.objectId().equals(Optional.of(enrollment.credentialId()))
                || supplied.ownerPrincipalId().isPresent()
                || exact.relationship() != Permission.Relationship.ANY
                || supplied.scope().issuerId().isPresent() || supplied.scope().responderId().isPresent()
                || supplied.scope().authorityId().isPresent()
                        && !supplied.scope().authorityId().equals(authoritative.scope().authorityId())
                || supplied.scope().profileId().isPresent()
                        && !supplied.scope().profileId().equals(authoritative.scope().profileId())) {
            throw new SecurityException("Credential publication resource differs");
        }
        return new Request(exact.realmId(), exact.principalId(), exact.authenticationMode(),
                exact.transportPrincipalId(), exact.operation(), authoritative, exact.relationship(),
                exact.context(), exact.approvalId(), exact.correlationId());
    }

    private Permission.Resource authoritativeConfirmationResource(PkiId credentialId,
            Permission.Resource supplied, Permission.Relationship relationship) {
        PkiResourceScopeResolver.CredentialScope coordinates = resourceScopes
                .credentialScope(credentialId)
                .orElseThrow(() -> new SecurityException("Credential authorization scope is unavailable"));
        if (supplied.type() != Permission.ResourceType.CERTIFICATE
                || !supplied.objectId().equals(Optional.of(credentialId))
                || supplied.ownerPrincipalId().isPresent()
                || relationship != Permission.Relationship.ANY
                || supplied.scope().issuerId().isPresent() || supplied.scope().responderId().isPresent()
                || !supplied.scope().authorityId().equals(Optional.of(coordinates.authorityId()))
                || supplied.scope().profileId().isPresent()
                        && !supplied.scope().profileId().equals(Optional.of(coordinates.profileId()))) {
            throw new SecurityException("Credential confirmation resource differs");
        }
        Permission.Scope scope = new Permission.Scope(realmId, Optional.of(coordinates.authorityId()),
                Optional.empty(), Optional.of(coordinates.profileId()));
        return new Permission.Resource(Permission.ResourceType.CERTIFICATE,
                scope, Optional.of(credentialId), Optional.empty());
    }

    private Permission.Resource authoritativeApprovalResource(Permission.Resource supplied,
            Permission.Scope targetScope) {
        if (supplied.type() != Permission.ResourceType.APPROVAL
                || supplied.objectId().isPresent() || supplied.ownerPrincipalId().isPresent()
                || supplied.scope().issuerId().isPresent() || supplied.scope().responderId().isPresent()
                || supplied.scope().authorityId().isPresent()
                        && !supplied.scope().authorityId().equals(targetScope.authorityId())
                || supplied.scope().profileId().isPresent()
                        && !supplied.scope().profileId().equals(targetScope.profileId())) {
            throw new SecurityException("Approval resource differs from its target");
        }
        return new Permission.Resource(Permission.ResourceType.APPROVAL,
                targetScope, Optional.empty(), Optional.empty());
    }

    private static Request withControlOperation(Request request, ServerControlOperation operation) {
        return new Request(request.realmId(), request.principalId(), request.authenticationMode(),
                request.transportPrincipalId(), new AdministrativeOperation.Control(operation), request.resource(),
                request.relationship(), request.context(), request.approvalId(), request.correlationId());
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
            case ServerControlOperation.EnrollCredentialPublication ignored -> resource.scope();
            case ServerControlOperation.RegisterAcmeDirectory value -> new Permission.Scope(realmId,
                    Optional.of(value.registration().authorityId()), Optional.empty(),
                    Optional.of(value.registration().profileId()));
            case ServerControlOperation.InspectAcmeDirectory value -> controlExecutor.acmeScope(value);
            case ServerControlOperation.SetAcmeDirectoryActive value -> controlExecutor.acmeScope(value);
            case ServerControlOperation.InspectAcmeAccount value -> controlExecutor.acmeScope(value);
            case ServerControlOperation.DeactivateAcmeAccount value -> controlExecutor.acmeScope(value);
            case ServerControlOperation.RegisterOcspResponder value -> new Permission.Scope(realmId,
                    Optional.of(value.registration().authorityId()), Optional.of(value.registration().issuerId()),
                    Optional.empty());
            case ServerControlOperation.InspectOcspResponder value -> {
                OcspResponderService.Responder responder = controlExecutor.ocspResponder(value.responderId());
                yield new Permission.Scope(realmId, Optional.of(responder.authorityId()),
                        Optional.of(responder.issuerId()), Optional.empty());
            }
            case ServerControlOperation.SetOcspResponderActive value -> {
                OcspResponderService.Responder responder = controlExecutor.ocspResponder(value.responderId());
                yield new Permission.Scope(realmId, Optional.of(responder.authorityId()),
                        Optional.of(responder.issuerId()), Optional.empty());
            }
            default -> resource.scope();
        };
        if (!actual.equals(resource.scope())) throw new SecurityException("Control scope differs");
    }

    private static boolean requiresResolvedAuthority(PkiOperation operation) {
        return operation instanceof PkiOperation.InspectCredential
                || operation instanceof PkiOperation.RevokeCredential
                || operation instanceof PkiOperation.RevokePendingCredentialConfirmation
                || operation instanceof PkiOperation.ReadRevocationHistory
                || operation instanceof PkiOperation.InspectPublication
                || operation instanceof PkiOperation.ProcessPublication
                || operation instanceof PkiOperation.RetryPublication
                || operation instanceof PkiOperation.ReconcilePublication
                || operation instanceof PkiOperation.RegisterPublication;
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
            case PkiOperationOutcome.Completed ignored -> "SUCCEEDED";
            case PkiOperationOutcome.Pending ignored -> "PENDING";
            case PkiOperationOutcome.Failed failure -> failure.classification().name();
        };
    }

    private static String classification(ServerControlOperationOutcome outcome) {
        if (outcome instanceof ServerControlOperationOutcome.OneTimeSensitive) return "SUCCEEDED";
        PkiOperationOutcome ordinary = ((ServerControlOperationOutcome.Ordinary) outcome).outcome();
        return classification(ordinary);
    }
}
