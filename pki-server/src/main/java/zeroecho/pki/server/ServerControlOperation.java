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

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.PkiId;

/** Closed transport-neutral server-control administration operation hierarchy. */
@SuppressWarnings("PMD.ControlStatementBraces")
public sealed interface ServerControlOperation permits ServerControlOperation.RegisterPrincipal,
        ServerControlOperation.InspectPrincipal, ServerControlOperation.ListPrincipals,
        ServerControlOperation.SetPrincipalEnabled, ServerControlOperation.ListRoleTemplates,
        ServerControlOperation.InspectRoleTemplate, ServerControlOperation.CreateRoleAssignment,
        ServerControlOperation.InspectRoleAssignment, ServerControlOperation.ListRoleAssignments,
        ServerControlOperation.RevokeRoleAssignment, ServerControlOperation.CreateGrant,
        ServerControlOperation.InspectGrant, ServerControlOperation.ListGrants,
        ServerControlOperation.RevokeGrant, ServerControlOperation.EvaluateAuthorization,
        ServerControlOperation.RequestApproval, ServerControlOperation.InspectApproval,
        ServerControlOperation.ListApprovals, ServerControlOperation.DecideApproval,
        ServerControlOperation.CancelApproval, ServerControlOperation.CreateBreakGlass,
        ServerControlOperation.ActivateBreakGlass,
        ServerControlOperation.InspectBreakGlass, ServerControlOperation.ListBreakGlass,
        ServerControlOperation.RevokeBreakGlass, ServerControlOperation.InspectDisclosure,
        ServerControlOperation.SetDisclosure, ServerControlOperation.IssueCapability,
        ServerControlOperation.RevokeCapability, ServerControlOperation.InspectAuditView {

    /** @return stable operation identity */
    String name();

    /** Principal registration. */
    record RegisterPrincipal(SecurityPrincipal principal) implements ServerControlOperation {
        public static final String NAME = "security.principal.register";
        public RegisterPrincipal { Objects.requireNonNull(principal, "principal"); }
        @Override public String name() { return NAME; }
    }
    /** Principal lookup. */
    record InspectPrincipal(String principalId) implements ServerControlOperation {
        public static final String NAME = "security.principal.inspect";
        public InspectPrincipal { Permission.requirePrincipal(principalId); }
        @Override public String name() { return NAME; }
    }
    /** Bounded principal page. */
    record ListPrincipals(int offset, int limit) implements ServerControlOperation {
        public static final String NAME = "security.principal.list";
        public ListPrincipals { page(offset, limit); }
        @Override public String name() { return NAME; }
    }
    /** Principal enablement transition. */
    record SetPrincipalEnabled(String principalId, boolean enabled) implements ServerControlOperation {
        public static final String ENABLE = "security.principal.enable";
        public static final String DISABLE = "security.principal.disable";
        public SetPrincipalEnabled { Permission.requirePrincipal(principalId); }
        @Override public String name() { return enabled ? ENABLE : DISABLE; }
    }
    /** Immutable role-template list. */
    record ListRoleTemplates() implements ServerControlOperation {
        public static final String NAME = "security.role-template.list";
        @Override public String name() { return NAME; }
    }
    /** Immutable role-template lookup. */
    record InspectRoleTemplate(String templateId, int version) implements ServerControlOperation {
        public static final String NAME = "security.role-template.inspect";
        public InspectRoleTemplate { Permission.requireId(templateId, "role template"); if (version <= 0) throw invalid(); }
        @Override public String name() { return NAME; }
    }
    /** Scoped assignment creation. */
    record CreateRoleAssignment(RoleTemplateCatalog.Assignment assignment) implements ServerControlOperation {
        public static final String NAME = "security.role-assignment.create";
        public CreateRoleAssignment { Objects.requireNonNull(assignment, "assignment"); }
        @Override public String name() { return NAME; }
    }
    /** Scoped assignment lookup. */
    record InspectRoleAssignment(String assignmentId) implements ServerControlOperation {
        public static final String NAME = "security.role-assignment.inspect";
        public InspectRoleAssignment { Permission.requireId(assignmentId, "assignment"); }
        @Override public String name() { return NAME; }
    }
    /** Bounded assignment page. */
    record ListRoleAssignments(int offset, int limit) implements ServerControlOperation {
        public static final String NAME = "security.role-assignment.list";
        public ListRoleAssignments { page(offset, limit); }
        @Override public String name() { return NAME; }
    }
    /** Durable assignment revocation. */
    record RevokeRoleAssignment(String assignmentId) implements ServerControlOperation {
        public static final String NAME = "security.role-assignment.revoke";
        public RevokeRoleAssignment { Permission.requireId(assignmentId, "assignment"); }
        @Override public String name() { return NAME; }
    }
    /** Direct grant creation. */
    record CreateGrant(Permission.Grant grant) implements ServerControlOperation {
        public static final String NAME = "security.grant.create";
        public CreateGrant { Objects.requireNonNull(grant, "grant"); }
        @Override public String name() { return NAME; }
    }
    /** Direct grant lookup. */
    record InspectGrant(String grantId) implements ServerControlOperation {
        public static final String NAME = "security.grant.inspect";
        public InspectGrant { Permission.requireId(grantId, "grant"); }
        @Override public String name() { return NAME; }
    }
    /** Bounded direct-grant page. */
    record ListGrants(int offset, int limit) implements ServerControlOperation {
        public static final String NAME = "security.grant.list";
        public ListGrants { page(offset, limit); }
        @Override public String name() { return NAME; }
    }
    /** Durable direct-grant revocation. */
    record RevokeGrant(String grantId) implements ServerControlOperation {
        public static final String NAME = "security.grant.revoke";
        public RevokeGrant { Permission.requireId(grantId, "grant"); }
        @Override public String name() { return NAME; }
    }
    /** Side-effect-free authorization simulation. */
    record EvaluateAuthorization(String principalId, Permission.Action action, Permission.Resource resource,
            Permission.Relationship relationship, Permission.DataView dataView,
            Permission.Context context) implements ServerControlOperation {
        public static final String NAME = "security.authorization.evaluate";
        public EvaluateAuthorization { Permission.requirePrincipal(principalId); Objects.requireNonNull(action);
            Objects.requireNonNull(resource); Objects.requireNonNull(relationship); Objects.requireNonNull(dataView);
            Objects.requireNonNull(context); }
        @Override public String name() { return NAME; }
    }
    /** Exact future-operation approval request. */
    record RequestApproval(String approvalId, AdministrativeOperation targetOperation,
            Permission.Resource targetResource) implements ServerControlOperation {
        public static final String NAME = "security.approval.request";
        public RequestApproval { Permission.requireId(approvalId, "approval");
            Objects.requireNonNull(targetOperation); Objects.requireNonNull(targetResource);
            if (targetOperation instanceof AdministrativeOperation.Control control
                    && control.operation() instanceof RequestApproval) throw invalid(); }
        @Override public String name() { return NAME; }
    }
    /** Approval lookup. */
    record InspectApproval(String approvalId) implements ServerControlOperation {
        public static final String NAME = "security.approval.inspect";
        public InspectApproval { Permission.requireId(approvalId, "approval"); }
        @Override public String name() { return NAME; }
    }
    /** Bounded approval page. */
    record ListApprovals(int offset, int limit, Optional<ApprovalService.State> state,
            Optional<String> requesterPrincipalId, Optional<String> targetOperationId)
            implements ServerControlOperation {
        public static final String NAME = "security.approval.list";
        public ListApprovals { page(offset, limit); state = Objects.requireNonNull(state);
            requesterPrincipalId = Objects.requireNonNull(requesterPrincipalId)
                    .map(Permission::requirePrincipal);
            targetOperationId = Objects.requireNonNull(targetOperationId)
                    .map(value -> Permission.requireBounded(value, 256, "target operation")); }
        /** Creates an unfiltered bounded approval page. */
        public ListApprovals(int offset, int limit) {
            this(offset, limit, Optional.empty(), Optional.empty(), Optional.empty());
        }
        @Override public String name() { return NAME; }
    }
    /** Approval or rejection decision. */
    record DecideApproval(String approvalId, ApprovalService.Choice choice,
            String justification) implements ServerControlOperation {
        public static final String APPROVE = "security.approval.approve";
        public static final String REJECT = "security.approval.reject";
        public DecideApproval { Permission.requireId(approvalId, "approval"); Objects.requireNonNull(choice);
            Permission.requireBounded(justification, 2048, "justification"); }
        @Override public String name() { return choice == ApprovalService.Choice.APPROVE ? APPROVE : REJECT; }
    }
    /** Approval cancellation. */
    record CancelApproval(String approvalId) implements ServerControlOperation {
        public static final String NAME = "security.approval.cancel";
        public CancelApproval { Permission.requireId(approvalId, "approval"); }
        @Override public String name() { return NAME; }
    }
    /** Independently approved emergency grant creation. */
    record CreateBreakGlass(String breakGlassId, String principalId, Permission.Grant grant,
            String reason, Instant expiresAt) implements ServerControlOperation {
        public static final String CREATE = "security.break-glass.create";
        public CreateBreakGlass { Permission.requireId(breakGlassId, "break-glass");
            Permission.requirePrincipal(principalId); Objects.requireNonNull(grant);
            Permission.requireBounded(reason, 2048, "reason"); Objects.requireNonNull(expiresAt); }
        @Override public String name() { return CREATE; }
    }
    /** Activation of one already-created approved emergency grant. */
    record ActivateBreakGlass(String breakGlassId) implements ServerControlOperation {
        public static final String ACTIVATE = "security.break-glass.activate";
        public ActivateBreakGlass { Permission.requireId(breakGlassId, "break-glass"); }
        @Override public String name() { return ACTIVATE; }
    }
    /** Break-glass lookup. */
    record InspectBreakGlass(String breakGlassId) implements ServerControlOperation {
        public static final String NAME = "security.break-glass.inspect";
        public InspectBreakGlass { Permission.requireId(breakGlassId, "break-glass"); }
        @Override public String name() { return NAME; }
    }
    /** Bounded break-glass page. */
    record ListBreakGlass(int offset, int limit) implements ServerControlOperation {
        public static final String NAME = "security.break-glass.list";
        public ListBreakGlass { page(offset, limit); }
        @Override public String name() { return NAME; }
    }
    /** Break-glass revocation. */
    record RevokeBreakGlass(String breakGlassId) implements ServerControlOperation {
        public static final String NAME = "security.break-glass.revoke";
        public RevokeBreakGlass { Permission.requireId(breakGlassId, "break-glass"); }
        @Override public String name() { return NAME; }
    }
    /** Disclosure metadata lookup. */
    record InspectDisclosure(PkiId objectId) implements ServerControlOperation {
        public static final String NAME = "security.disclosure.inspect";
        public InspectDisclosure { Objects.requireNonNull(objectId); }
        @Override public String name() { return NAME; }
    }
    /** Disclosure-only state transition. */
    record SetDisclosure(PkiId objectId, DisclosureService.Policy policy) implements ServerControlOperation {
        public static final String NAME = "security.disclosure.set";
        public SetDisclosure { Objects.requireNonNull(objectId); Objects.requireNonNull(policy); }
        @Override public String name() { return NAME; }
    }
    /** One-time unlisted retrieval capability issuance. */
    record IssueCapability(PkiId objectId, Instant expiresAt) implements ServerControlOperation {
        public static final String NAME = "security.disclosure.capability.issue";
        public IssueCapability { Objects.requireNonNull(objectId); Objects.requireNonNull(expiresAt); }
        @Override public String name() { return NAME; }
    }
    /** Capability revocation by non-bearer record identity. */
    record RevokeCapability(String capabilityId) implements ServerControlOperation {
        public static final String NAME = "security.disclosure.capability.revoke";
        public RevokeCapability { Permission.requireId(capabilityId, "capability"); }
        @Override public String name() { return NAME; }
    }
    /** Existing safe auditor projection over one server-control object. */
    record InspectAuditView(PkiId objectId, Permission.DataView view,
            Optional<String> reasonReference) implements ServerControlOperation {
        public static final String REDACTED = "security.audit-view.inspect-redacted";
        public static final String FULL = "security.audit-view.inspect-full";
        public static final String PII = "security.audit-view.inspect-pii";
        public InspectAuditView { Objects.requireNonNull(objectId); Objects.requireNonNull(view);
            reasonReference = Objects.requireNonNull(reasonReference); }
        @Override public String name() { return switch (view) { case METADATA_REDACTED -> REDACTED;
            case METADATA_FULL, CONTENT_FULL -> FULL; case PII_FULL -> PII; }; }
    }

    private static void page(int offset, int limit) {
        if (offset < 0 || limit <= 0 || limit > 256) throw invalid();
    }
    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Server-control operation input is invalid");
    }
}
