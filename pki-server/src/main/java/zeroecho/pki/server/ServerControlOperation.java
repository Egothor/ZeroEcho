/* *****************************************************************************
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
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.server.acme.AcmeService;
import zeroecho.pki.server.cmp.CmpEndpoint;
import zeroecho.pki.server.enrollment.EnrollmentProfile;
import zeroecho.pki.server.est.EstEndpoint;
import zeroecho.pki.server.scep.ScepEndpoint;

/** Closed transport-neutral server-control administration operation hierarchy. */
@SuppressWarnings({ "PMD.ControlStatementBraces", "PMD.ExcessivePublicCount" })
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
        ServerControlOperation.SetDisclosure, ServerControlOperation.EnrollCredentialPublication,
        ServerControlOperation.IssueCapability,
        ServerControlOperation.RevokeCapability, ServerControlOperation.InspectAuditView,
        ServerControlOperation.InspectRepositoryAlias, ServerControlOperation.ListRepositoryAliases,
        ServerControlOperation.SetRepositoryAlias, ServerControlOperation.RemoveRepositoryAlias,
        ServerControlOperation.RegisterAcmeDirectory, ServerControlOperation.InspectAcmeDirectory,
        ServerControlOperation.ListAcmeDirectories, ServerControlOperation.SetAcmeDirectoryActive,
        ServerControlOperation.InspectAcmeAccount, ServerControlOperation.ListAcmeAccounts,
        ServerControlOperation.DeactivateAcmeAccount, ServerControlOperation.RegisterOcspResponder,
        ServerControlOperation.InspectOcspResponder, ServerControlOperation.ListOcspResponders,
        ServerControlOperation.SetOcspResponderActive,
        ServerControlOperation.RegisterEstEndpoint, ServerControlOperation.DeregisterEstEndpoint,
        ServerControlOperation.InspectEstEndpoint, ServerControlOperation.ListEstEndpoints,
        ServerControlOperation.RegisterScepEndpoint, ServerControlOperation.DeregisterScepEndpoint,
        ServerControlOperation.InspectScepEndpoint, ServerControlOperation.ListScepEndpoints,
        ServerControlOperation.RegisterCmpEndpoint, ServerControlOperation.DeregisterCmpEndpoint,
        ServerControlOperation.InspectCmpEndpoint, ServerControlOperation.ListCmpEndpoints,
        ServerControlOperation.RegisterEnrollmentProfile, ServerControlOperation.UpdateEnrollmentProfile,
        ServerControlOperation.InspectEnrollmentProfile, ServerControlOperation.ListEnrollmentProfiles,
        ServerControlOperation.ActivateEnrollmentProfile, ServerControlOperation.SuspendEnrollmentProfile,
        ServerControlOperation.InspectEnrollmentRequest, ServerControlOperation.ListEnrollmentRequests,
        ServerControlOperation.DecideEnrollmentRequest,
        ServerControlOperation.SearchAudit,
        ServerControlOperation.VerifyAuditIntegrity, ServerControlOperation.ExportBackup,
        ServerControlOperation.VerifyBackup, ServerControlOperation.ExecuteRestore,
        ServerControlOperation.ReserveBackupUpload, ServerControlOperation.ExportBackupStream,
        ServerControlOperation.BackupArtifactCommand,
        ServerControlOperation.ConfigurationChoices,
        ServerControlOperation.ListCapabilities {

    /**
     * Lists safe configured metadata and one page of known key references.
     *
     * @param limit maximum number of returned entries, from 1 to 1000
     * @param after optional exclusive identifier cursor; empty starts the first page
     */
    record ConfigurationChoices(int limit, Optional<String> after) implements ServerControlOperation {
        /** Stable semantic name. */ public static final String NAME = "configuration.choices";
        /** Validates the bounded key page. */
        public ConfigurationChoices {
            requireSelectionLimit(limit);
            Objects.requireNonNull(after, "after").ifPresent(zeroecho.pki.api.KeyRef::new);
        }
        @Override public String name() { return NAME; }
    }

    /**
     * Lists non-bearer capabilities for one authoritative disclosure object.
     *
     * @param objectId exact stored object identifier
     * @param limit maximum number of returned entries, from 1 to 1000
     * @param after optional exclusive identifier cursor; empty starts the first page
     */
    record ListCapabilities(PkiId objectId, int limit, Optional<String> after) implements ServerControlOperation {
        /** Stable semantic name. */ public static final String NAME = "security.disclosure.capability.list";
        /** Validates the object and bounded lexical page. */
        public ListCapabilities {
            Objects.requireNonNull(objectId, "objectId");
            requireSelectionLimit(limit);
            Objects.requireNonNull(after, "after").ifPresent(value -> Permission.requireId(value, "capability cursor"));
        }
        @Override public String name() { return NAME; }
    }

    private static void requireSelectionLimit(int limit) {
        if (limit < 1 || limit > 1000) { throw new IllegalArgumentException("Selection limit must be 1 through 1000"); }
    }

    /**
     * Returns the stable operation identity used for authorization and dispatch.
     *
     * @return stable operation identity
     */
    String name();

    /**
     * Principal registration.
     *
     * @param principal principal to register
     */
    record RegisterPrincipal(SecurityPrincipal principal) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.principal.register";
        /** Validates the operation's immutable input. */
        public RegisterPrincipal { Objects.requireNonNull(principal, "principal"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Principal lookup.
     *
     * @param principalId stable principal identifier
     */
    record InspectPrincipal(String principalId) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.principal.inspect";
        /** Validates the operation's immutable input. */
        public InspectPrincipal { Permission.requirePrincipal(principalId); }
        @Override public String name() { return NAME; }
    }
    /**
     * Bounded principal page.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     */
    record ListPrincipals(int offset, int limit) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.principal.list";
        /** Validates the operation's immutable input. */
        public ListPrincipals { page(offset, limit); }
        @Override public String name() { return NAME; }
    }
    /**
     * Principal enablement transition.
     *
     * @param principalId stable principal identifier
     * @param enabled desired enabled state
     */
    record SetPrincipalEnabled(String principalId, boolean enabled) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String ENABLE = "security.principal.enable";
        /** Stable operation identity used for authorization and dispatch. */
        public static final String DISABLE = "security.principal.disable";
        /** Validates the operation's immutable input. */
        public SetPrincipalEnabled { Permission.requirePrincipal(principalId); }
        @Override public String name() { return enabled ? ENABLE : DISABLE; }
    }
    /** Immutable role-template list. */
    record ListRoleTemplates() implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.role-template.list";
        @Override public String name() { return NAME; }
    }
    /**
     * Immutable role-template lookup.
     *
     * @param templateId stable role-template identifier
     * @param version positive template version
     */
    record InspectRoleTemplate(String templateId, int version) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.role-template.inspect";
        /** Validates the operation's immutable input. */
        public InspectRoleTemplate { Permission.requireId(templateId, "role template"); if (version <= 0) throw invalid(); }
        @Override public String name() { return NAME; }
    }
    /**
     * Scoped assignment creation.
     *
     * @param assignment validated scoped role assignment
     */
    record CreateRoleAssignment(RoleTemplateCatalog.Assignment assignment) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.role-assignment.create";
        /** Validates the operation's immutable input. */
        public CreateRoleAssignment { Objects.requireNonNull(assignment, "assignment"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Scoped assignment lookup.
     *
     * @param assignmentId stable assignment identifier
     */
    record InspectRoleAssignment(String assignmentId) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.role-assignment.inspect";
        /** Validates the operation's immutable input. */
        public InspectRoleAssignment { Permission.requireId(assignmentId, "assignment"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Bounded assignment page.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     */
    record ListRoleAssignments(int offset, int limit) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.role-assignment.list";
        /** Validates the operation's immutable input. */
        public ListRoleAssignments { page(offset, limit); }
        @Override public String name() { return NAME; }
    }
    /**
     * Durable assignment revocation.
     *
     * @param assignmentId stable assignment identifier
     */
    record RevokeRoleAssignment(String assignmentId) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.role-assignment.revoke";
        /** Validates the operation's immutable input. */
        public RevokeRoleAssignment { Permission.requireId(assignmentId, "assignment"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Direct grant creation.
     *
     * @param grant validated permission grant
     */
    record CreateGrant(Permission.Grant grant) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.grant.create";
        /** Validates the operation's immutable input. */
        public CreateGrant { Objects.requireNonNull(grant, "grant"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Direct grant lookup.
     *
     * @param grantId stable grant identifier
     */
    record InspectGrant(String grantId) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.grant.inspect";
        /** Validates the operation's immutable input. */
        public InspectGrant { Permission.requireId(grantId, "grant"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Bounded direct-grant page.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     */
    record ListGrants(int offset, int limit) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.grant.list";
        /** Validates the operation's immutable input. */
        public ListGrants { page(offset, limit); }
        @Override public String name() { return NAME; }
    }
    /**
     * Durable direct-grant revocation.
     *
     * @param grantId stable grant identifier
     */
    record RevokeGrant(String grantId) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.grant.revoke";
        /** Validates the operation's immutable input. */
        public RevokeGrant { Permission.requireId(grantId, "grant"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Side-effect-free authorization simulation.
     *
     * @param principalId stable principal identifier
     * @param action permission action to evaluate
     * @param resource exact target resource
     * @param relationship requester-to-resource relationship
     * @param dataView requested data view
     * @param context closed authorization context
     */
    record EvaluateAuthorization(String principalId, Permission.Action action, Permission.Resource resource,
            Permission.Relationship relationship, Permission.DataView dataView,
            Permission.Context context) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.authorization.evaluate";
        /** Validates the operation's immutable input. */
        public EvaluateAuthorization { Permission.requirePrincipal(principalId); Objects.requireNonNull(action);
            Objects.requireNonNull(resource); Objects.requireNonNull(relationship); Objects.requireNonNull(dataView);
            Objects.requireNonNull(context); }
        @Override public String name() { return NAME; }
    }
    /**
     * Exact future-operation approval request.
     *
     * @param approvalId stable approval identifier
     * @param targetOperation exact future administrative operation
     * @param targetResource exact future target resource
     */
    record RequestApproval(String approvalId, AdministrativeOperation targetOperation,
            Permission.Resource targetResource) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.approval.request";
        /** Validates the operation's immutable input. */
        public RequestApproval { Permission.requireId(approvalId, "approval");
            Objects.requireNonNull(targetOperation); Objects.requireNonNull(targetResource);
            if (targetOperation instanceof AdministrativeOperation.Control control
                    && control.operation() instanceof RequestApproval) throw invalid(); }
        @Override public String name() { return NAME; }
    }
    /**
     * Approval lookup.
     *
     * @param approvalId stable approval identifier
     */
    record InspectApproval(String approvalId) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.approval.inspect";
        /** Validates the operation's immutable input. */
        public InspectApproval { Permission.requireId(approvalId, "approval"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Bounded approval page.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     * @param state optional approval-state filter
     * @param requesterPrincipalId optional requester-principal filter
     * @param targetOperationId optional target-operation filter
     */
    record ListApprovals(int offset, int limit, Optional<ApprovalService.State> state,
            Optional<String> requesterPrincipalId, Optional<String> targetOperationId)
            implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.approval.list";
        /** Validates the operation's immutable input. */
        public ListApprovals { page(offset, limit); state = Objects.requireNonNull(state);
            requesterPrincipalId = Objects.requireNonNull(requesterPrincipalId)
                    .map(Permission::requirePrincipal);
            targetOperationId = Objects.requireNonNull(targetOperationId)
                    .map(value -> Permission.requireBounded(value, 256, "target operation")); }
        /**
         * Creates an unfiltered bounded approval page.
         *
         * @param offset zero-based page offset
         * @param limit positive page-size limit
         */
        public ListApprovals(int offset, int limit) {
            this(offset, limit, Optional.empty(), Optional.empty(), Optional.empty());
        }
        @Override public String name() { return NAME; }
    }
    /**
     * Approval or rejection decision.
     *
     * @param approvalId stable approval identifier
     * @param choice approval or rejection decision
     * @param justification bounded operator justification
     */
    record DecideApproval(String approvalId, ApprovalService.Choice choice,
            String justification) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String APPROVE = "security.approval.approve";
        /** Stable operation identity used for authorization and dispatch. */
        public static final String REJECT = "security.approval.reject";
        /** Validates the operation's immutable input. */
        public DecideApproval { Permission.requireId(approvalId, "approval"); Objects.requireNonNull(choice);
            Permission.requireBounded(justification, 2048, "justification"); }
        @Override public String name() { return choice == ApprovalService.Choice.APPROVE ? APPROVE : REJECT; }
    }
    /**
     * Approval cancellation.
     *
     * @param approvalId stable approval identifier
     */
    record CancelApproval(String approvalId) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.approval.cancel";
        /** Validates the operation's immutable input. */
        public CancelApproval { Permission.requireId(approvalId, "approval"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Independently approved emergency grant creation.
     *
     * @param breakGlassId stable break-glass identifier
     * @param principalId stable principal identifier
     * @param grant validated permission grant
     * @param reason bounded operator reason
     * @param expiresAt mandatory capability or grant expiry
     */
    record CreateBreakGlass(String breakGlassId, String principalId, Permission.Grant grant,
            String reason, Instant expiresAt) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String CREATE = "security.break-glass.create";
        /** Validates the operation's immutable input. */
        public CreateBreakGlass { Permission.requireId(breakGlassId, "break-glass");
            Permission.requirePrincipal(principalId); Objects.requireNonNull(grant);
            Permission.requireBounded(reason, 2048, "reason"); Objects.requireNonNull(expiresAt); }
        @Override public String name() { return CREATE; }
    }
    /**
     * Activation of one already-created approved emergency grant.
     *
     * @param breakGlassId stable break-glass identifier
     */
    record ActivateBreakGlass(String breakGlassId) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String ACTIVATE = "security.break-glass.activate";
        /** Validates the operation's immutable input. */
        public ActivateBreakGlass { Permission.requireId(breakGlassId, "break-glass"); }
        @Override public String name() { return ACTIVATE; }
    }
    /**
     * Break-glass lookup.
     *
     * @param breakGlassId stable break-glass identifier
     */
    record InspectBreakGlass(String breakGlassId) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.break-glass.inspect";
        /** Validates the operation's immutable input. */
        public InspectBreakGlass { Permission.requireId(breakGlassId, "break-glass"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Bounded break-glass page.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     */
    record ListBreakGlass(int offset, int limit) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.break-glass.list";
        /** Validates the operation's immutable input. */
        public ListBreakGlass { page(offset, limit); }
        @Override public String name() { return NAME; }
    }
    /**
     * Break-glass revocation.
     *
     * @param breakGlassId stable break-glass identifier
     */
    record RevokeBreakGlass(String breakGlassId) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.break-glass.revoke";
        /** Validates the operation's immutable input. */
        public RevokeBreakGlass { Permission.requireId(breakGlassId, "break-glass"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Disclosure metadata lookup.
     *
     * @param objectId exact target object identifier
     */
    record InspectDisclosure(PkiId objectId) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.disclosure.inspect";
        /** Validates the operation's immutable input. */
        public InspectDisclosure { Objects.requireNonNull(objectId); }
        @Override public String name() { return NAME; }
    }
    /**
     * Disclosure-only state transition.
     *
     * @param objectId exact target object identifier
     * @param policy replacement disclosure policy
     */
    record SetDisclosure(PkiId objectId, DisclosureService.Policy policy) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.disclosure.set";
        /** Validates the operation's immutable input. */
        public SetDisclosure { Objects.requireNonNull(objectId); Objects.requireNonNull(policy); }
        @Override public String name() { return NAME; }
    }
    /**
     * Explicit post-issuance enrollment into confirmation and disclosure.
     *
     * @param credentialId exact credential identifier
     * @param ownerPrincipalId optional owning principal identifier
     */
    record EnrollCredentialPublication(PkiId credentialId, Optional<String> ownerPrincipalId)
            implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "certificate.publication.enroll";
        /** Validates the operation's immutable input. */
        public EnrollCredentialPublication {
            Objects.requireNonNull(credentialId, "credentialId");
            ownerPrincipalId = Objects.requireNonNull(ownerPrincipalId, "ownerPrincipalId")
                    .map(Permission::requirePrincipal);
        }
        @Override public String name() { return NAME; }
    }
    /**
     * One-time unlisted retrieval capability issuance.
     *
     * @param objectId exact target object identifier
     * @param expiresAt mandatory capability or grant expiry
     */
    record IssueCapability(PkiId objectId, Instant expiresAt) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.disclosure.capability.issue";
        /** Validates the operation's immutable input. */
        public IssueCapability { Objects.requireNonNull(objectId); Objects.requireNonNull(expiresAt); }
        @Override public String name() { return NAME; }
    }
    /**
     * Capability revocation by non-bearer record identity.
     *
     * @param capabilityId stable non-bearer capability identifier
     */
    record RevokeCapability(String capabilityId) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.disclosure.capability.revoke";
        /** Validates the operation's immutable input. */
        public RevokeCapability { Permission.requireId(capabilityId, "capability"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Existing safe auditor projection over one server-control object.
     *
     * @param objectId exact target object identifier
     * @param view requested audit data view
     * @param reasonReference optional audit reason reference
     */
    record InspectAuditView(PkiId objectId, Permission.DataView view,
            Optional<String> reasonReference) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String REDACTED = "security.audit-view.inspect-redacted";
        /** Stable operation identity used for authorization and dispatch. */
        public static final String FULL = "security.audit-view.inspect-full";
        /** Stable operation identity used for authorization and dispatch. */
        public static final String PII = "security.audit-view.inspect-pii";
        /** Validates the operation's immutable input. */
        public InspectAuditView { Objects.requireNonNull(objectId); Objects.requireNonNull(view);
            reasonReference = Objects.requireNonNull(reasonReference); }
        @Override public String name() { return switch (view) { case METADATA_REDACTED -> REDACTED;
            case METADATA_FULL, CONTENT_FULL -> FULL; case PII_FULL -> PII; }; }
    }

    /**
     * Bounded audit-log search over the packaged admin API; preserves tamper-evidence (read-only).
     *
     * @param query bounded audit query
     */
    record SearchAudit(zeroecho.pki.api.audit.AuditQuery query) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.audit.search";
        /** Validates the operation's immutable input. */
        public SearchAudit { Objects.requireNonNull(query, "query"); }
        @Override public String name() { return NAME; }
    }

    /**
     * Verifies the audit-log hash chain, optionally against a trusted head anchor.
     *
     * @param expectedHead optional trusted audit-chain head
     */
    record VerifyAuditIntegrity(Optional<zeroecho.pki.api.audit.AuditChainHead> expectedHead)
            implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "security.audit.verify-integrity";
        /** Validates the operation's immutable input. */
        public VerifyAuditIntegrity {
            expectedHead = Objects.requireNonNull(expectedHead, "expectedHead");
        }
        @Override public String name() { return NAME; }
    }

    /**
     * Exports a backup of PKI state, excluding private keys.
     *
     * @param label operator-provided human-readable label
     * @param attributes optional backup metadata
     */
    record ExportBackup(String label, zeroecho.pki.api.attr.AttributeSet attributes)
            implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "backup.export";
        /** Validates the operation's immutable input. */
        public ExportBackup {
            Permission.requireBounded(label, 256, "label");
            Objects.requireNonNull(attributes, "attributes");
        }
        @Override public String name() { return NAME; }
    }

    /**
     * Verifies structural integrity and completeness of a backup artifact.
     *
     * @param artifact backup artifact to verify
     */
    record VerifyBackup(zeroecho.pki.api.backup.BackupArtifact artifact)
            implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "backup.verify";
        /** Validates the operation's immutable input. */
        public VerifyBackup { Objects.requireNonNull(artifact, "artifact"); }
        @Override public String name() { return NAME; }
    }

    /**
     * Executes a restore from a backup artifact.
     *
     * @param request restore request including the artifact
     */
    record ExecuteRestore(zeroecho.pki.api.backup.RestoreRequest request)
            implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "backup.restore";
        /** Validates the operation's immutable input. */
        public ExecuteRestore { Objects.requireNonNull(request, "request"); }
        @Override public String name() { return NAME; }
    }

    /**
     * Reserves bounded storage for a streaming archive upload.
     * The supplied commitment is verified against bytes before domain validation.
     * @param backupId claimed manifest backup identifier
     * @param length exact compressed byte count
     * @param sha256 lowercase archive SHA-256
     */
    record ReserveBackupUpload(PkiId backupId, long length, String sha256) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "backup.stream.reserve";
        /** Validates the bounded declaration without allocating archive storage. */
        public ReserveBackupUpload {
            Objects.requireNonNull(backupId, "backupId");
            Permission.requireBounded(backupId.value(), 1024, "backupId");
            if (length < 1 || length > zeroecho.pki.api.backup.BackupLimits.defaults().compressedBytes()
                    || sha256 == null || !isCommitment(sha256)) {
                throw new IllegalArgumentException("Invalid backup upload declaration");
            }
        }
        @Override public String name() { return NAME; }
    }

    /**
     * Creates a file-backed export for a subsequent authorized download.
     * @param label bounded operator label
     */
    record ExportBackupStream(String label) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "backup.stream.export";
        /** Validates the export label. */
        public ExportBackupStream { Permission.requireBounded(label, 256, "label"); }
        @Override public String name() { return NAME; }
    }

    /**
     * Requests an action on an owned opaque archive or restore workflow.
     * The gateway replaces any supplied commitment with current authoritative
     * metadata before authorization and approval canonicalization.
     * @param action requested workflow phase
     * @param artifactHandle opaque owner-bound handle, never a filesystem path
     * @param commitment server-resolved metadata commitment; empty on the wire
     */
    record BackupArtifactCommand(Action action, String artifactHandle, Optional<String> commitment)
            implements ServerControlOperation {
        /** Upload backup archive operation identity. */
        public static final String UPLOAD = "backup.stream.upload";
        /** Download backup archive operation identity. */
        public static final String DOWNLOAD = "backup.stream.download";
        /** Verify uploaded archive operation identity. */
        public static final String VERIFY = "backup.stream.verify";
        /** Stage backup restoration operation identity. */
        public static final String RESTORE = "backup.stream.restore";
        /** Inspect restore workflow operation identity. */
        public static final String STATUS = "backup.stream.status";
        /** Acknowledge restore outcome operation identity. */
        public static final String ACKNOWLEDGE = "backup.stream.acknowledge";
        /** Closed workflow actions and their stable operation identities. */
        public enum Action {
            /** Receives an archive through the binary upload route. */
            UPLOAD(BackupArtifactCommand.UPLOAD),
            /** Consumes a single authorized archive download. */
            DOWNLOAD(BackupArtifactCommand.DOWNLOAD),
            /** Performs domain archive verification. */
            VERIFY(BackupArtifactCommand.VERIFY),
            /** Stages a verified archive with high-risk approval. */
            RESTORE(BackupArtifactCommand.RESTORE),
            /** Reads a retained restore outcome, including after archive expiry. */
            STATUS(BackupArtifactCommand.STATUS),
            /** Removes an acknowledged, authoritatively terminal workflow. */
            ACKNOWLEDGE(BackupArtifactCommand.ACKNOWLEDGE);
            private final String operationId;
            Action(String operationId) { this.operationId = operationId; }
            /** Returns the stable operation identity.
             * @return stable operation identity
             */
            public String operationId() { return operationId; }
        }
        /** Validates shape; ownership and phase are checked by the server. */
        public BackupArtifactCommand {
            Objects.requireNonNull(action, "action");
            Objects.requireNonNull(commitment, "commitment");
            if (artifactHandle == null || !isCommitment(artifactHandle)
                    || commitment.isPresent() && !isCommitment(commitment.orElseThrow())) {
                throw new IllegalArgumentException("Invalid backup artifact reference");
            }
        }
        @Override public String name() { return action.operationId(); }
        @Override public String toString() { return "BackupArtifactCommand[redacted]"; }
    }

    /**
     * Exact repository alias inspection.
     *
     * @param authorityId exact logical authority identifier
     * @param type repository alias type
     */
    record InspectRepositoryAlias(PkiId authorityId, RepositoryAliasService.Type type)
            implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "repository.alias.inspect";
        /** Validates the operation's immutable input. */
        public InspectRepositoryAlias { Objects.requireNonNull(authorityId); Objects.requireNonNull(type); }
        @Override public String name() { return NAME; }
    }

    /**
     * Bounded repository alias page.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     */
    record ListRepositoryAliases(int offset, int limit) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "repository.alias.list";
        /** Validates the operation's immutable input. */
        public ListRepositoryAliases { page(offset, limit); }
        @Override public String name() { return NAME; }
    }

    /**
     * Exact CRL or chain alias publication with expected-current protection.
     *
     * @param authorityId exact logical authority identifier
     * @param type repository alias type
     * @param targetObjectId exact alias target identifier
     * @param issuerId optional exact issuer generation
     * @param expectedCurrentCommitment expected current alias commitment
     */
    record SetRepositoryAlias(PkiId authorityId, RepositoryAliasService.Type type, PkiId targetObjectId,
            Optional<PkiId> issuerId, Optional<String> expectedCurrentCommitment) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "repository.alias.set";
        /** Validates the operation's immutable input. */
        public SetRepositoryAlias {
            Objects.requireNonNull(authorityId); Objects.requireNonNull(type); Objects.requireNonNull(targetObjectId);
            issuerId = Objects.requireNonNull(issuerId); expectedCurrentCommitment = Objects.requireNonNull(expectedCurrentCommitment);
        }
        @Override public String name() { return NAME; }
    }

    /**
     * Durable repository alias removal without target mutation.
     *
     * @param authorityId exact logical authority identifier
     * @param type repository alias type
     * @param expectedCurrentCommitment expected current alias commitment
     */
    record RemoveRepositoryAlias(PkiId authorityId, RepositoryAliasService.Type type,
            String expectedCurrentCommitment) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "repository.alias.remove";
        /** Validates the operation's immutable input. */
        public RemoveRepositoryAlias { Objects.requireNonNull(authorityId); Objects.requireNonNull(type);
            if (expectedCurrentCommitment == null || !isCommitment(expectedCurrentCommitment)) throw invalid(); }
        @Override public String name() { return NAME; }
    }

    /**
     * Server-resolved exact profile precondition bound into approval canonicalization.
     *
     * @param expectedProfile authoritative certificate-profile reference
     * @param expectedPolicyCommitment expected policy commitment
     */
    record AcmeDirectoryProfilePrecondition(CertificateProfileRef expectedProfile,
            String expectedPolicyCommitment) {
        /** Validates the authoritative exact profile and confirmation-policy identities. */
        /** Validates the operation's immutable input. */
        public AcmeDirectoryProfilePrecondition {
            Objects.requireNonNull(expectedProfile, "expectedProfile");
            if (expectedPolicyCommitment == null
                    || !isCommitment(expectedPolicyCommitment)) {
                throw invalid();
            }
        }
    }

    /**
     * Registers one immutable inactive ACME directory revision.
     *
     * @param registration validated protocol registration
     * @param profilePrecondition optional authoritative profile precondition
     */
    record RegisterAcmeDirectory(AcmeService.DirectoryRegistration registration,
            Optional<AcmeDirectoryProfilePrecondition> profilePrecondition) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "acme.directory.register";
        /** Validates the operation's immutable input. */
        public RegisterAcmeDirectory {
            Objects.requireNonNull(registration, "registration");
            profilePrecondition = Objects.requireNonNull(profilePrecondition, "profilePrecondition");
            profilePrecondition.ifPresent(value -> {
                if (!value.expectedProfile().profileId().equals(registration.profileId())) {
                    throw invalid();
                }
            });
        }
        /**
         * Creates an unbound transport input; the gateway supplies the authoritative precondition.
         *
         * @param registration validated directory registration
         */
        public RegisterAcmeDirectory(AcmeService.DirectoryRegistration registration) {
            this(registration, Optional.empty());
        }
        @Override public String name() { return NAME; }
    }
    /**
     * Inspects one exact ACME directory revision.
     *
     * @param directoryId stable ACME directory identifier
     */
    record InspectAcmeDirectory(String directoryId) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "acme.directory.inspect";
        /** Validates the operation's immutable input. */
        public InspectAcmeDirectory { Permission.requireId(directoryId, "ACME directory"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Lists a bounded page of ACME directory revisions.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     */
    record ListAcmeDirectories(int offset, int limit) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "acme.directory.list";
        /** Validates the operation's immutable input. */
        public ListAcmeDirectories { page(offset, limit); }
        @Override public String name() { return NAME; }
    }
    /**
     * Activates or deactivates one exact ACME directory revision.
     *
     * @param directoryId stable ACME directory identifier
     * @param active desired activation state
     */
    record SetAcmeDirectoryActive(String directoryId, boolean active) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String ACTIVATE = "acme.directory.activate";
        /** Stable operation identity used for authorization and dispatch. */
        public static final String DEACTIVATE = "acme.directory.deactivate";
        /** Validates the operation's immutable input. */
        public SetAcmeDirectoryActive { Permission.requireId(directoryId, "ACME directory"); }
        @Override public String name() { return active ? ACTIVATE : DEACTIVATE; }
    }
    /**
     * Inspects one protocol-scoped ACME account.
     *
     * @param accountId stable ACME account identifier
     */
    record InspectAcmeAccount(String accountId) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "acme.account.inspect";
        /** Validates the operation's immutable input. */
        public InspectAcmeAccount { Permission.requireId(accountId, "ACME account"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Lists a bounded account page without contact PII.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     */
    record ListAcmeAccounts(int offset, int limit) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "acme.account.list";
        /** Validates the operation's immutable input. */
        public ListAcmeAccounts { page(offset, limit); }
        @Override public String name() { return NAME; }
    }
    /**
     * Durably deactivates one ACME account without deleting history.
     *
     * @param accountId stable ACME account identifier
     */
    record DeactivateAcmeAccount(String accountId) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "acme.account.deactivate";
        /** Validates the operation's immutable input. */
        public DeactivateAcmeAccount { Permission.requireId(accountId, "ACME account"); }
        @Override public String name() { return NAME; }
    }

    /**
     * Registers one exact inactive OCSP responder binding.
     *
     * @param registration validated protocol registration
     */
    record RegisterOcspResponder(OcspResponderService.Registration registration) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "ocsp.responder.register";
        /** Validates the operation's immutable input. */
        public RegisterOcspResponder { Objects.requireNonNull(registration, "registration"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Inspects one exact OCSP responder binding.
     *
     * @param responderId stable OCSP responder identifier
     */
    record InspectOcspResponder(String responderId) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "ocsp.responder.inspect";
        /** Validates the operation's immutable input. */
        public InspectOcspResponder { Permission.requireId(responderId, "OCSP responder"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Lists a bounded OCSP responder page.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     */
    record ListOcspResponders(int offset, int limit) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String NAME = "ocsp.responder.list";
        /** Validates the operation's immutable input. */
        public ListOcspResponders { page(offset, limit); }
        @Override public String name() { return NAME; }
    }
    /**
     * Activates or deactivates one exact responder.
     *
     * @param responderId stable OCSP responder identifier
     * @param active desired activation state
     */
    record SetOcspResponderActive(String responderId, boolean active) implements ServerControlOperation {
        /** Stable operation identity used for authorization and dispatch. */
        public static final String ACTIVATE = "ocsp.responder.activate";
        /** Stable operation identity used for authorization and dispatch. */
        public static final String DEACTIVATE = "ocsp.responder.deactivate";
        /** Validates the operation's immutable input. */
        public SetOcspResponderActive { Permission.requireId(responderId, "OCSP responder"); }
        @Override public String name() { return active ? ACTIVATE : DEACTIVATE; }
    }

    /**
     * Registers an EST RFC 7030 endpoint.
     *
     * @param endpoint the endpoint to register
     */
    record RegisterEstEndpoint(EstEndpoint endpoint) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "est.endpoint.register";
        /** Validates the operation input. */
        public RegisterEstEndpoint { Objects.requireNonNull(endpoint, "endpoint"); }
        @Override public String name() { return NAME; }
    }
    /**
     * De-registers an EST endpoint by label.
     *
     * @param label the URL-safe endpoint label to remove
     */
    record DeregisterEstEndpoint(String label) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "est.endpoint.deregister";
        /** Validates the label. */
        public DeregisterEstEndpoint { Permission.requireId(label, "EST endpoint"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Inspects one registered EST endpoint.
     *
     * @param label the URL-safe endpoint label
     */
    record InspectEstEndpoint(String label) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "est.endpoint.inspect";
        /** Validates the label. */
        public InspectEstEndpoint { Permission.requireId(label, "EST endpoint"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Lists registered EST endpoints.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     */
    record ListEstEndpoints(int offset, int limit) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "est.endpoint.list";
        /** Validates bounds. */
        public ListEstEndpoints { page(offset, limit); }
        @Override public String name() { return NAME; }
    }

    /**
     * Registers a SCEP RFC 8894 endpoint.
     *
     * @param endpoint the endpoint to register
     */
    record RegisterScepEndpoint(ScepEndpoint endpoint) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "scep.endpoint.register";
        /** Validates the operation input. */
        public RegisterScepEndpoint { Objects.requireNonNull(endpoint, "endpoint"); }
        @Override public String name() { return NAME; }
    }
    /**
     * De-registers a SCEP endpoint by label.
     *
     * @param label the URL-safe endpoint label to remove
     */
    record DeregisterScepEndpoint(String label) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "scep.endpoint.deregister";
        /** Validates the label. */
        public DeregisterScepEndpoint { Permission.requireId(label, "SCEP endpoint"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Inspects one registered SCEP endpoint.
     *
     * @param label the URL-safe endpoint label
     */
    record InspectScepEndpoint(String label) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "scep.endpoint.inspect";
        /** Validates the label. */
        public InspectScepEndpoint { Permission.requireId(label, "SCEP endpoint"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Lists registered SCEP endpoints.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     */
    record ListScepEndpoints(int offset, int limit) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "scep.endpoint.list";
        /** Validates bounds. */
        public ListScepEndpoints { page(offset, limit); }
        @Override public String name() { return NAME; }
    }

    /**
     * Registers a CMP RFC 4210/9480 endpoint.
     *
     * @param endpoint the endpoint to register
     */
    record RegisterCmpEndpoint(CmpEndpoint endpoint) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "cmp.endpoint.register";
        /** Validates the operation input. */
        public RegisterCmpEndpoint { Objects.requireNonNull(endpoint, "endpoint"); }
        @Override public String name() { return NAME; }
    }
    /**
     * De-registers a CMP endpoint by label.
     *
     * @param label the URL-safe endpoint label to remove
     */
    record DeregisterCmpEndpoint(String label) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "cmp.endpoint.deregister";
        /** Validates the label. */
        public DeregisterCmpEndpoint { Permission.requireId(label, "CMP endpoint"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Inspects one registered CMP endpoint.
     *
     * @param label the URL-safe endpoint label
     */
    record InspectCmpEndpoint(String label) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "cmp.endpoint.inspect";
        /** Validates the label. */
        public InspectCmpEndpoint { Permission.requireId(label, "CMP endpoint"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Lists registered CMP endpoints.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     */
    record ListCmpEndpoints(int offset, int limit) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "cmp.endpoint.list";
        /** Validates bounds. */
        public ListCmpEndpoints { page(offset, limit); }
        @Override public String name() { return NAME; }
    }

    /**
     * Registers a new enrollment profile.
     *
     * @param profile the profile to register
     */
    record RegisterEnrollmentProfile(EnrollmentProfile profile) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "enrollment.profile.register";
        /** Validates the operation input. */
        public RegisterEnrollmentProfile { Objects.requireNonNull(profile, "profile"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Updates an existing enrollment profile (replaces all mutable fields).
     *
     * @param profile the updated profile
     */
    record UpdateEnrollmentProfile(EnrollmentProfile profile) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "enrollment.profile.update";
        /** Validates the operation input. */
        public UpdateEnrollmentProfile { Objects.requireNonNull(profile, "profile"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Inspects one enrollment profile.
     *
     * @param id the profile identity
     */
    record InspectEnrollmentProfile(String id) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "enrollment.profile.inspect";
        /** Validates the id. */
        public InspectEnrollmentProfile { Permission.requireId(id, "enrollment profile"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Inspects a durable protocol request using its authoritative persisted scope.
     * @param id enrollment request identity
     */
    record InspectEnrollmentRequest(String id) implements ServerControlOperation {
        /** Stable operation identity. */ public static final String NAME = "enrollment.request.inspect";
        /** Validates the stable reference. */
        public InspectEnrollmentRequest { Permission.requireId(id, "enrollment request"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Lists retained enrollment requests within the authorized scope.
     * @param offset zero-based page offset
     * @param limit page size, at most 256
     */
    record ListEnrollmentRequests(int offset, int limit) implements ServerControlOperation {
        /** Stable operation identity. */ public static final String NAME = "enrollment.request.list";
        /** Validates bounded pagination. */
        public ListEnrollmentRequests { page(offset, limit); }
        @Override public String name() { return NAME; }
    }
    /**
     * Independently approves or rejects the exact record reviewed by an administrator.
     * Trusted end-client evidence is supplied by authentication, never this DTO.
     * @param id durable request identity
     * @param expectedCommitment complete reviewed record commitment
     * @param choice explicit approval or rejection
     * @param justification bounded operator justification
     */
    record DecideEnrollmentRequest(String id, String expectedCommitment, ApprovalService.Choice choice,
            String justification) implements ServerControlOperation {
        /** Stable approval operation identity. */ public static final String APPROVE = "enrollment.request.approve";
        /** Stable rejection operation identity. */ public static final String REJECT = "enrollment.request.reject";
        /** Validates all caller-controlled decision fields. */
        public DecideEnrollmentRequest {
            Permission.requireId(id, "enrollment request"); Objects.requireNonNull(choice, "choice");
            if (expectedCommitment == null || !isCommitment(expectedCommitment)) throw new IllegalArgumentException("Enrollment record commitment is invalid");
            justification = Permission.requireBounded(justification, 2048, "justification");
        }
        @Override public String name() { return choice == ApprovalService.Choice.APPROVE ? APPROVE : REJECT; }
    }
    /**
     * Lists enrollment profiles.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     */
    record ListEnrollmentProfiles(int offset, int limit) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "enrollment.profile.list";
        /** Validates bounds. */
        public ListEnrollmentProfiles { page(offset, limit); }
        @Override public String name() { return NAME; }
    }
    /**
     * Activates a suspended enrollment profile.
     *
     * @param id the profile identity
     */
    record ActivateEnrollmentProfile(String id) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "enrollment.profile.activate";
        /** Validates the id. */
        public ActivateEnrollmentProfile { Permission.requireId(id, "enrollment profile"); }
        @Override public String name() { return NAME; }
    }
    /**
     * Suspends an active enrollment profile.
     *
     * @param id the profile identity
     */
    record SuspendEnrollmentProfile(String id) implements ServerControlOperation {
        /** Stable operation identity. */
        public static final String NAME = "enrollment.profile.suspend";
        /** Validates the id. */
        public SuspendEnrollmentProfile { Permission.requireId(id, "enrollment profile"); }
        @Override public String name() { return NAME; }
    }

    private static void page(int offset, int limit) {
        if (offset < 0 || limit <= 0 || limit > 256) throw invalid();
    }
    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Server-control operation input is invalid");
    }

    private static boolean isCommitment(String value) {
        return value.matches("[0-9a-f]{64}");
    }
}
