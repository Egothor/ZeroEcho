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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import zeroecho.pki.application.PkiOperation;

/** Immutable security descriptors keyed by existing typed-operation identities. */
@SuppressWarnings({ "PMD.ControlStatementBraces", "PMD.FieldDeclarationsShouldBeAtStartOfClass",
        "PMD.AvoidDuplicateLiterals" })
public final class OperationSecurityDescriptors {
    /** Internally fixed execution family; callers cannot select it. */
    public enum Family { PKI_OPERATION, SERVER_CONTROL_OPERATION }
    /** Approval treatment for one operation. */
    public enum ApprovalCategory { NONE, HIGH_RISK }

    /** Future transport eligibility without defining a transport protocol. */
    public enum Eligibility { ADMINISTRATIVE, PUBLIC_READ }

    /**
     * Immutable operation security descriptor.
     *
     * @param operationId stable typed-operation identity
     * @param action required permission
     * @param resourceType required resource type
     * @param mutating whether the operation may commit state
     * @param dataView required data view
     * @param approvalCategory approval treatment
     * @param eligibility future transport eligibility metadata
     */
    public record Descriptor(String operationId, Family family, Permission.Action action, Permission.ResourceType resourceType,
            boolean mutating, Permission.DataView dataView, ApprovalCategory approvalCategory,
            Eligibility eligibility) {
        /** Validates one finite descriptor. */
        public Descriptor {
            Permission.requireBounded(operationId, 256, "operation ID");
            Objects.requireNonNull(family, "family");
            Objects.requireNonNull(action, "action");
            Objects.requireNonNull(resourceType, "resourceType");
            Objects.requireNonNull(dataView, "dataView");
            Objects.requireNonNull(approvalCategory, "approvalCategory");
            Objects.requireNonNull(eligibility, "eligibility");
        }

        /** Creates an existing PKI-family descriptor for embedded callers. */
        public Descriptor(String operationId, Permission.Action action, Permission.ResourceType resourceType,
                boolean mutating, Permission.DataView dataView, ApprovalCategory approvalCategory,
                Eligibility eligibility) {
            this(operationId, Family.PKI_OPERATION, action, resourceType, mutating, dataView,
                    approvalCategory, eligibility);
        }
    }

    private final Map<String, Descriptor> descriptors;

    /** Creates the closed current gateway descriptor registry. */
    public OperationSecurityDescriptors() {
        this(List.of(
                read(PkiOperation.ListAuthorities.NAME, Permission.Action.AUTHORITY_LIST, Permission.ResourceType.AUTHORITY),
                read(PkiOperation.InspectAuthority.NAME, Permission.Action.AUTHORITY_READ, Permission.ResourceType.AUTHORITY),
                mutate(PkiOperation.CreateAuthority.NAME, Permission.Action.AUTHORITY_CREATE, Permission.ResourceType.AUTHORITY, true),
                mutate(PkiOperation.TransitionAuthority.NAME, Permission.Action.AUTHORITY_ACTIVATE, Permission.ResourceType.AUTHORITY, true),
                read(PkiOperation.ListProfileVersions.NAME, Permission.Action.PROFILE_READ, Permission.ResourceType.PROFILE),
                read(PkiOperation.InspectProfile.NAME, Permission.Action.PROFILE_READ, Permission.ResourceType.PROFILE),
                mutate(PkiOperation.ActivateProfile.NAME, Permission.Action.PROFILE_ACTIVATE, Permission.ResourceType.PROFILE, true),
                read(PkiOperation.InspectCredential.NAME, Permission.Action.CERTIFICATE_READ_METADATA, Permission.ResourceType.CERTIFICATE),
                mutate(PkiOperation.IssueCredential.NAME, Permission.Action.CERTIFICATE_ISSUE, Permission.ResourceType.CERTIFICATE, false),
                mutate(PkiOperation.RevokeCredential.NAME, Permission.Action.CERTIFICATE_REVOKE, Permission.ResourceType.REVOCATION, false),
                read(PkiOperation.ReadRevocationHistory.NAME, Permission.Action.REVOCATION_HISTORY_READ, Permission.ResourceType.REVOCATION),
                mutate(PkiOperation.GenerateStatus.NAME, Permission.Action.CRL_GENERATE, Permission.ResourceType.STATUS_OBJECT, false),
                read(PkiOperation.InspectPublication.NAME, Permission.Action.PUBLICATION_READ, Permission.ResourceType.PUBLICATION),
                mutate(PkiOperation.ProcessPublication.NAME, Permission.Action.PUBLICATION_PROCESS, Permission.ResourceType.PUBLICATION, false),
                read(PkiOperation.ListAlgorithmBindings.NAME, Permission.Action.X509_BINDING_READ, Permission.ResourceType.X509_BINDING),
                read(PkiOperation.InspectAlgorithmBinding.NAME, Permission.Action.X509_BINDING_READ, Permission.ResourceType.X509_BINDING),
                control(ServerControlOperation.RegisterPrincipal.NAME, Permission.Action.PRINCIPAL_MANAGE, Permission.ResourceType.PRINCIPAL, true, false),
                control(ServerControlOperation.InspectPrincipal.NAME, Permission.Action.PRINCIPAL_MANAGE, Permission.ResourceType.PRINCIPAL, false, false),
                control(ServerControlOperation.ListPrincipals.NAME, Permission.Action.PRINCIPAL_MANAGE, Permission.ResourceType.PRINCIPAL, false, false),
                control(ServerControlOperation.SetPrincipalEnabled.ENABLE, Permission.Action.PRINCIPAL_MANAGE, Permission.ResourceType.PRINCIPAL, true, false),
                control(ServerControlOperation.SetPrincipalEnabled.DISABLE, Permission.Action.PRINCIPAL_MANAGE, Permission.ResourceType.PRINCIPAL, true, true),
                control(ServerControlOperation.ListRoleTemplates.NAME, Permission.Action.ROLE_MANAGE, Permission.ResourceType.ROLE, false, false),
                control(ServerControlOperation.InspectRoleTemplate.NAME, Permission.Action.ROLE_MANAGE, Permission.ResourceType.ROLE, false, false),
                control(ServerControlOperation.CreateRoleAssignment.NAME, Permission.Action.ROLE_MANAGE, Permission.ResourceType.ROLE, true, true),
                control(ServerControlOperation.InspectRoleAssignment.NAME, Permission.Action.ROLE_MANAGE, Permission.ResourceType.ROLE, false, false),
                control(ServerControlOperation.ListRoleAssignments.NAME, Permission.Action.ROLE_MANAGE, Permission.ResourceType.ROLE, false, false),
                control(ServerControlOperation.RevokeRoleAssignment.NAME, Permission.Action.ROLE_MANAGE, Permission.ResourceType.ROLE, true, false),
                control(ServerControlOperation.CreateGrant.NAME, Permission.Action.PERMISSION_GRANT, Permission.ResourceType.GRANT, true, true),
                control(ServerControlOperation.InspectGrant.NAME, Permission.Action.PERMISSION_GRANT, Permission.ResourceType.GRANT, false, false),
                control(ServerControlOperation.ListGrants.NAME, Permission.Action.PERMISSION_GRANT, Permission.ResourceType.GRANT, false, false),
                control(ServerControlOperation.RevokeGrant.NAME, Permission.Action.PERMISSION_GRANT, Permission.ResourceType.GRANT, true, false),
                control(ServerControlOperation.EvaluateAuthorization.NAME, Permission.Action.PERMISSION_GRANT, Permission.ResourceType.GRANT, false, false),
                control(ServerControlOperation.RequestApproval.NAME, Permission.Action.REQUEST_SUBMIT, Permission.ResourceType.APPROVAL, true, false),
                control(ServerControlOperation.InspectApproval.NAME, Permission.Action.REQUEST_READ_ANY, Permission.ResourceType.APPROVAL, false, false),
                control(ServerControlOperation.ListApprovals.NAME, Permission.Action.REQUEST_READ_ANY, Permission.ResourceType.APPROVAL, false, false),
                control(ServerControlOperation.DecideApproval.APPROVE, Permission.Action.REQUEST_APPROVE, Permission.ResourceType.APPROVAL, true, false),
                control(ServerControlOperation.DecideApproval.REJECT, Permission.Action.REQUEST_REJECT, Permission.ResourceType.APPROVAL, true, false),
                control(ServerControlOperation.CancelApproval.NAME, Permission.Action.REQUEST_CANCEL, Permission.ResourceType.APPROVAL, true, false),
                control(ServerControlOperation.CreateBreakGlass.CREATE, Permission.Action.PERMISSION_GRANT, Permission.ResourceType.BREAK_GLASS, true, true),
                control(ServerControlOperation.ActivateBreakGlass.ACTIVATE, Permission.Action.PERMISSION_GRANT, Permission.ResourceType.BREAK_GLASS, true, true),
                control(ServerControlOperation.InspectBreakGlass.NAME, Permission.Action.PERMISSION_GRANT, Permission.ResourceType.BREAK_GLASS, false, false),
                control(ServerControlOperation.ListBreakGlass.NAME, Permission.Action.PERMISSION_GRANT, Permission.ResourceType.BREAK_GLASS, false, false),
                control(ServerControlOperation.RevokeBreakGlass.NAME, Permission.Action.PERMISSION_GRANT, Permission.ResourceType.BREAK_GLASS, true, false),
                control(ServerControlOperation.InspectDisclosure.NAME, Permission.Action.DISCLOSURE_READ, Permission.ResourceType.DISCLOSURE, false, false),
                control(ServerControlOperation.SetDisclosure.NAME, Permission.Action.DISCLOSURE_CHANGE, Permission.ResourceType.DISCLOSURE, true, true),
                control(ServerControlOperation.IssueCapability.NAME, Permission.Action.DISCLOSURE_CAPABILITY_ISSUE, Permission.ResourceType.CAPABILITY, true, false),
                control(ServerControlOperation.RevokeCapability.NAME, Permission.Action.DISCLOSURE_CAPABILITY_REVOKE, Permission.ResourceType.CAPABILITY, true, false),
                control(ServerControlOperation.InspectAuditView.REDACTED, Permission.Action.AUDIT_READ_REDACTED, Permission.ResourceType.AUDIT, false, false),
                control(ServerControlOperation.InspectAuditView.FULL, Permission.Action.AUDIT_READ_FULL, Permission.ResourceType.AUDIT, false, false),
                control(ServerControlOperation.InspectAuditView.PII, Permission.Action.AUDIT_READ_PII, Permission.ResourceType.AUDIT, false, false)));
    }

    /** Creates a registry and rejects duplicate operation identities. */
    public OperationSecurityDescriptors(List<Descriptor> values) {
        Map<String, Descriptor> copy = new LinkedHashMap<>();
        for (Descriptor descriptor : values) {
            if (copy.putIfAbsent(descriptor.operationId(), descriptor) != null) {
                throw new IllegalArgumentException("Duplicate operation security descriptor");
            }
        }
        descriptors = Map.copyOf(copy);
    }

    /** Resolves one descriptor or fails closed. */
    public Descriptor require(PkiOperation operation) {
        Objects.requireNonNull(operation, "operation");
        Descriptor descriptor = descriptors.get(operation.name());
        if (descriptor == null) throw new SecurityException("Operation is not exposed by the server gateway");
        validateOperationType(operation, descriptor);
        return descriptor;
    }

    /** Resolves either operation family through the sole descriptor authority. */
    public Descriptor require(AdministrativeOperation operation) {
        Objects.requireNonNull(operation, "operation");
        Descriptor descriptor = descriptors.get(operation.name());
        if (descriptor == null) throw new SecurityException("Operation is not exposed by the server gateway");
        Family expected = operation instanceof AdministrativeOperation.Pki ? Family.PKI_OPERATION
                : Family.SERVER_CONTROL_OPERATION;
        if (descriptor.family() != expected) throw new SecurityException("Operation family differs");
        return descriptor;
    }

    /** @return immutable descriptor map keyed by operation ID */
    public Map<String, Descriptor> descriptors() {
        return descriptors;
    }

    /** Resolves one descriptor by stable ID for strict transport decoding. */
    public Descriptor require(String operationId) {
        Permission.requireBounded(operationId, 256, "operation ID");
        Descriptor descriptor = descriptors.get(operationId);
        if (descriptor == null) throw new SecurityException("Operation is not exposed by the server gateway");
        return descriptor;
    }

    /** Computes an exact deterministic safe operation commitment. */
    public String commitment(RealmId realmId, PkiOperation operation, Permission.Resource resource) {
        Descriptor descriptor = require(operation);
        return ApprovalService.digest(realmId.value() + '|' + descriptor.operationId() + '|'
                + canonicalArguments(operation) + '|' + canonicalResource(resource));
    }

    /** Computes an exact deterministic commitment for either closed operation family. */
    public String commitment(RealmId realmId, AdministrativeOperation operation, Permission.Resource resource) {
        require(operation);
        String arguments = operation instanceof AdministrativeOperation.Pki pki
                ? canonicalArguments(pki.operation()) : canonicalControl(((AdministrativeOperation.Control) operation).operation());
        return ApprovalService.digest(realmId.value() + '|' + operation.name() + '|' + arguments + '|'
                + canonicalResource(resource));
    }

    /** Verifies that caller-supplied security scope matches operation identities. */
    public void validateResource(PkiOperation operation, Permission.Resource resource) {
        Descriptor descriptor = require(operation);
        if (descriptor.resourceType() != resource.type()) {
            throw new SecurityException("Operation resource type is invalid");
        }
        boolean valid = switch (operation) {
            case PkiOperation.InspectAuthority value -> matchesAuthorityAndObject(resource, value.caId());
            case PkiOperation.TransitionAuthority value -> matchesAuthorityAndObject(resource, value.caId());
            case PkiOperation.CreateAuthority ignored -> resource.scope().authorityId().isEmpty()
                    && resource.objectId().isEmpty();
            case PkiOperation.ListAuthorities ignored -> resource.scope().authorityId().isEmpty();
            case PkiOperation.InspectProfile value -> resource.scope().profileId().filter(value.profileId()::equals).isPresent();
            case PkiOperation.ListProfileVersions value -> resource.scope().profileId().filter(value.profileId()::equals).isPresent();
            case PkiOperation.ActivateProfile value -> resource.scope().profileId().filter(value.profileId()::equals).isPresent();
            case PkiOperation.InspectCredential value -> resource.objectId().filter(value.credentialId()::equals).isPresent()
                    && resource.scope().authorityId().isPresent();
            case PkiOperation.IssueCredential value -> resource.scope().authorityId().filter(value.issuerCaId()::equals).isPresent()
                    && resource.scope().profileId().filter(value.profileId()::equals).isPresent();
            case PkiOperation.RevokeCredential value -> resource.objectId().filter(value.credentialId()::equals).isPresent()
                    && resource.scope().authorityId().isPresent();
            case PkiOperation.ReadRevocationHistory value -> resource.objectId().filter(value.credentialId()::equals).isPresent()
                    && resource.scope().authorityId().isPresent();
            case PkiOperation.GenerateStatus value -> resource.scope().authorityId().filter(value.issuerCaId()::equals).isPresent();
            case PkiOperation.InspectPublication value -> resource.objectId().filter(value.publicationId()::equals).isPresent()
                    && resource.scope().authorityId().isPresent();
            case PkiOperation.ProcessPublication value -> resource.objectId().filter(value.publicationId()::equals).isPresent()
                    && resource.scope().authorityId().isPresent();
            case PkiOperation.ListAlgorithmBindings ignored -> resource.scope().authorityId().isEmpty();
            case PkiOperation.InspectAlgorithmBinding ignored -> resource.scope().authorityId().isEmpty();
            default -> false;
        };
        if (!valid) throw new SecurityException("Operation security scope does not match typed arguments");
    }

    private static boolean matchesAuthorityAndObject(Permission.Resource resource, zeroecho.pki.api.PkiId id) {
        return resource.scope().authorityId().filter(id::equals).isPresent()
                && resource.objectId().filter(id::equals).isPresent();
    }

    private static String canonicalArguments(PkiOperation operation) {
        return switch (operation) {
            case PkiOperation.ListAuthorities value -> "limit=" + value.limit();
            case PkiOperation.InspectAuthority value -> "ca=" + atom(value.caId().value());
            case PkiOperation.CreateAuthority value -> "format=" + atom(value.formatId().value()) + ";subject="
                    + atom(value.subjectRef().value()) + ";profile=" + atom(value.profileId())
                    + ";keyRef=" + atom(value.keyRef().value());
            case PkiOperation.TransitionAuthority value -> "ca=" + atom(value.caId().value()) + ";state="
                    + value.state().name() + ";reason=" + atom(value.reason());
            case PkiOperation.ListProfileVersions value -> "profile=" + atom(value.profileId());
            case PkiOperation.InspectProfile value -> "profile=" + atom(value.profileId()) + ";version=" + value.profileVersion();
            case PkiOperation.ActivateProfile value -> "profile=" + atom(value.profileId()) + ";version=" + value.profileVersion();
            case PkiOperation.InspectCredential value -> "credential=" + atom(value.credentialId().value());
            case PkiOperation.IssueCredential value -> "issuer=" + atom(value.issuerCaId().value()) + ";request="
                    + atom(value.requestId().value()) + ";profile=" + atom(value.profileId());
            case PkiOperation.RevokeCredential value -> "credential=" + atom(value.credentialId().value())
                    + ";reason=" + value.reason().name();
            case PkiOperation.ReadRevocationHistory value -> "credential=" + atom(value.credentialId().value())
                    + ";limit=" + value.limit();
            case PkiOperation.GenerateStatus value -> "issuer=" + atom(value.issuerCaId().value()) + ";type="
                    + value.type().name() + ";format=" + atom(value.formatId().value());
            case PkiOperation.InspectPublication value -> "publication=" + atom(value.publicationId().value());
            case PkiOperation.ProcessPublication value -> "publication=" + atom(value.publicationId().value());
            case PkiOperation.ListAlgorithmBindings value -> "origin=" + atom(value.origin().orElse("")) + ";role="
                    + atom(value.role().orElse("")) + ";limit=" + value.limit();
            case PkiOperation.InspectAlgorithmBinding value -> "binding=" + atom(value.bindingId());
            default -> throw new SecurityException("Operation has no canonical security encoding");
        };
    }

    private static String canonicalResource(Permission.Resource resource) {
        Permission.Scope scope = resource.scope();
        return resource.type().name() + '|' + atom(scope.realmId().value()) + '|'
                + atom(scope.authorityId().map(zeroecho.pki.api.PkiId::value).orElse("")) + '|'
                + atom(scope.issuerId().map(zeroecho.pki.api.PkiId::value).orElse("")) + '|'
                + atom(scope.profileId().orElse("")) + '|'
                + atom(resource.objectId().map(zeroecho.pki.api.PkiId::value).orElse("")) + '|'
                + atom(resource.ownerPrincipalId().orElse(""));
    }

    private static String atom(String value) {
        return ApprovalService.digest(value);
    }

    private static Descriptor read(String id, Permission.Action action, Permission.ResourceType type) {
        return new Descriptor(id, Family.PKI_OPERATION, action, type, false, Permission.DataView.METADATA_REDACTED,
                ApprovalCategory.NONE, Eligibility.ADMINISTRATIVE);
    }

    private static Descriptor mutate(String id, Permission.Action action, Permission.ResourceType type,
            boolean highRisk) {
        return new Descriptor(id, Family.PKI_OPERATION, action, type, true, Permission.DataView.METADATA_REDACTED,
                highRisk ? ApprovalCategory.HIGH_RISK : ApprovalCategory.NONE, Eligibility.ADMINISTRATIVE);
    }

    private static void validateOperationType(PkiOperation operation, Descriptor descriptor) {
        if (descriptor.family() != Family.PKI_OPERATION || !operation.name().equals(descriptor.operationId())) {
            throw new SecurityException("Operation identity and descriptor differ");
        }
    }

    private static Descriptor control(String id, Permission.Action action, Permission.ResourceType type,
            boolean mutating, boolean highRisk) {
        Permission.DataView view = action == Permission.Action.AUDIT_READ_PII
                ? Permission.DataView.PII_FULL : action == Permission.Action.AUDIT_READ_FULL
                        ? Permission.DataView.METADATA_FULL : Permission.DataView.METADATA_REDACTED;
        return new Descriptor(id, Family.SERVER_CONTROL_OPERATION, action, type, mutating,
                view, highRisk ? ApprovalCategory.HIGH_RISK
                        : ApprovalCategory.NONE, Eligibility.ADMINISTRATIVE);
    }

    private static String canonicalControl(ServerControlOperation operation) {
        return switch (operation) {
            case ServerControlOperation.RegisterPrincipal value -> "principal=" + atom(value.principal().principalId());
            case ServerControlOperation.InspectPrincipal value -> "principal=" + atom(value.principalId());
            case ServerControlOperation.ListPrincipals value -> "offset=" + value.offset() + ";limit=" + value.limit();
            case ServerControlOperation.SetPrincipalEnabled value -> "principal=" + atom(value.principalId())
                    + ";enabled=" + value.enabled();
            case ServerControlOperation.ListRoleTemplates ignored -> "all";
            case ServerControlOperation.InspectRoleTemplate value -> "template=" + atom(value.templateId())
                    + ";version=" + value.version();
            case ServerControlOperation.CreateRoleAssignment value -> "assignment="
                    + atom(value.assignment().assignmentId()) + ";principal=" + atom(value.assignment().principalId());
            case ServerControlOperation.InspectRoleAssignment value -> "assignment=" + atom(value.assignmentId());
            case ServerControlOperation.ListRoleAssignments value -> "offset=" + value.offset() + ";limit=" + value.limit();
            case ServerControlOperation.RevokeRoleAssignment value -> "assignment=" + atom(value.assignmentId());
            case ServerControlOperation.CreateGrant value -> "grant=" + atom(value.grant().grantId())
                    + ";principal=" + atom(value.grant().principalId()) + ";action=" + value.grant().action().name();
            case ServerControlOperation.InspectGrant value -> "grant=" + atom(value.grantId());
            case ServerControlOperation.ListGrants value -> "offset=" + value.offset() + ";limit=" + value.limit();
            case ServerControlOperation.RevokeGrant value -> "grant=" + atom(value.grantId());
            case ServerControlOperation.EvaluateAuthorization value -> "principal=" + atom(value.principalId())
                    + ";action=" + value.action().name();
            case ServerControlOperation.RequestApproval value -> "approval=" + atom(value.approvalId())
                    + ";target=" + atom(value.targetOperation().name());
            case ServerControlOperation.InspectApproval value -> "approval=" + atom(value.approvalId());
            case ServerControlOperation.ListApprovals value -> "offset=" + value.offset() + ";limit=" + value.limit()
                    + ";state=" + atom(value.state().map(Enum::name).orElse("")) + ";requester="
                    + atom(value.requesterPrincipalId().orElse("")) + ";target="
                    + atom(value.targetOperationId().orElse(""));
            case ServerControlOperation.DecideApproval value -> "approval=" + atom(value.approvalId())
                    + ";choice=" + value.choice().name();
            case ServerControlOperation.CancelApproval value -> "approval=" + atom(value.approvalId());
            case ServerControlOperation.CreateBreakGlass value -> "breakGlass=" + atom(value.breakGlassId())
                    + ";principal=" + atom(value.principalId()) + ";expiry=" + value.expiresAt();
            case ServerControlOperation.ActivateBreakGlass value -> "breakGlass=" + atom(value.breakGlassId());
            case ServerControlOperation.InspectBreakGlass value -> "breakGlass=" + atom(value.breakGlassId());
            case ServerControlOperation.ListBreakGlass value -> "offset=" + value.offset() + ";limit=" + value.limit();
            case ServerControlOperation.RevokeBreakGlass value -> "breakGlass=" + atom(value.breakGlassId());
            case ServerControlOperation.InspectDisclosure value -> "object=" + atom(value.objectId().value());
            case ServerControlOperation.SetDisclosure value -> "object=" + atom(value.objectId().value())
                    + ";policy=" + value.policy().name();
            case ServerControlOperation.IssueCapability value -> "object=" + atom(value.objectId().value())
                    + ";expiry=" + value.expiresAt();
            case ServerControlOperation.RevokeCapability value -> "capability=" + atom(value.capabilityId());
            case ServerControlOperation.InspectAuditView value -> "object=" + atom(value.objectId().value())
                    + ";view=" + value.view().name();
        };
    }
}
