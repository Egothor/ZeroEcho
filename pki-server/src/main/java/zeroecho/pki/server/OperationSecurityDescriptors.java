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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
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
    public enum Family {
        /** Operation belongs to the core PKI application family. */ PKI_OPERATION,
        /** Operation belongs to the server-control family. */ SERVER_CONTROL_OPERATION
    }
    /**
     * Approval treatment for one operation.
     *
     * <p>{@code HIGH_RISK} is the realm-wide dual-control category for
     * administratively high-risk operations (for example authority creation and
     * grant-conditioned revocation). {@code ISSUANCE_SINGLE} and
     * {@code ISSUANCE_THRESHOLD} are selected dynamically per end-entity issuance
     * from the resolved certificate profile's
     * {@link zeroecho.pki.api.profile.IssuanceApprovalRequirement}: they are never
     * attached statically to a descriptor, because whether issuance needs approval
     * depends on the profile, not the operation identity.</p>
     */
    public enum ApprovalCategory {
        /** No approval workflow is required. */ NONE,
        /** Realm-wide high-risk dual control applies. */ HIGH_RISK,
        /** Profile-selected single approval applies. */ ISSUANCE_SINGLE,
        /** Profile-selected threshold approval applies. */ ISSUANCE_THRESHOLD
    }

    /** Future transport eligibility without defining a transport protocol. */
    public enum Eligibility {
        /** Only the authenticated administrative transport may expose the operation. */ ADMINISTRATIVE,
        /** A read-only public transport may expose the operation. */ PUBLIC_READ
    }

    /**
     * Immutable operation security descriptor.
     *
     * @param operationId stable typed-operation identity
     * @param family internally fixed execution family
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

        /**
         * Creates an existing PKI-family descriptor for embedded callers.
         *
         * @param operationId stable typed-operation identity
         * @param action required permission
         * @param resourceType required resource type
         * @param mutating whether the operation may commit state
         * @param dataView required data view
         * @param approvalCategory approval treatment
         * @param eligibility transport eligibility
         */
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
                read(PkiOperation.ListPendingCredentialConfirmations.NAME,
                        Permission.Action.CERTIFICATE_SEARCH, Permission.ResourceType.CERTIFICATE),
                mutate(PkiOperation.IssueCredentialConfirmationChallenge.NAME,
                        Permission.Action.CERTIFICATE_PUBLICATION_CHANGE,
                        Permission.ResourceType.CERTIFICATE, false),
                mutate(PkiOperation.CompleteCredentialConfirmationProof.NAME,
                        Permission.Action.CERTIFICATE_CONFIRM,
                        Permission.ResourceType.CERTIFICATE, false),
                mutate(PkiOperation.RevokePendingCredentialConfirmation.NAME,
                        Permission.Action.CERTIFICATE_REVOKE,
                        Permission.ResourceType.CERTIFICATE, false),
                mutate(PkiOperation.IssueCredential.NAME, Permission.Action.CERTIFICATE_ISSUE, Permission.ResourceType.CERTIFICATE, false),
                mutate(PkiOperation.RenewCredential.NAME, Permission.Action.CERTIFICATE_RENEW, Permission.ResourceType.CERTIFICATE, false),
                mutate(PkiOperation.ReplaceCredential.NAME, Permission.Action.CERTIFICATE_REKEY, Permission.ResourceType.CERTIFICATE, false),
                mutate(PkiOperation.ReissueCredential.NAME, Permission.Action.CERTIFICATE_ISSUE, Permission.ResourceType.CERTIFICATE, true),
                mutate(PkiOperation.RolloverCaCertificate.NAME, Permission.Action.ISSUER_CREATE, Permission.ResourceType.AUTHORITY, true),
                mutate(PkiOperation.RotateCaKey.NAME, Permission.Action.ISSUER_ROTATE, Permission.ResourceType.AUTHORITY, true),
                read(PkiOperation.InspectRequest.NAME, Permission.Action.REQUEST_READ_ANY, Permission.ResourceType.REQUEST),
                mutate(PkiOperation.ImportRequest.NAME, Permission.Action.REQUEST_SUBMIT, Permission.ResourceType.REQUEST, false),
                read(PkiOperation.VerifyRequest.NAME, Permission.Action.REQUEST_READ_ANY, Permission.ResourceType.REQUEST),
                mutate(PkiOperation.RegisterProfile.NAME, Permission.Action.PROFILE_REGISTER, Permission.ResourceType.PROFILE, false),
                read(PkiOperation.ValidateConfiguration.NAME, Permission.Action.SERVER_CONFIGURATION_READ, Permission.ResourceType.SERVER_CONFIGURATION),
                read(PkiOperation.ValidateProfile.NAME, Permission.Action.PROFILE_VALIDATE, Permission.ResourceType.PROFILE),
                read(PkiOperation.ValidateAlgorithmBindings.NAME, Permission.Action.X509_BINDING_READ, Permission.ResourceType.X509_BINDING),
                read(PkiOperation.InspectRevocation.NAME, Permission.Action.REVOCATION_HISTORY_READ, Permission.ResourceType.REVOCATION),
                read(PkiOperation.SnapshotRevocations.NAME, Permission.Action.REVOCATION_HISTORY_READ, Permission.ResourceType.REVOCATION),
                read(PkiOperation.InspectStatus.NAME, Permission.Action.CRL_DOWNLOAD, Permission.ResourceType.STATUS_OBJECT),
                read(PkiOperation.ListStatus.NAME, Permission.Action.CRL_DOWNLOAD, Permission.ResourceType.STATUS_OBJECT),
                read(PkiOperation.ListPublications.NAME, Permission.Action.PUBLICATION_READ, Permission.ResourceType.PUBLICATION),
                mutate(PkiOperation.RegisterPublication.NAME, Permission.Action.PUBLICATION_REGISTER, Permission.ResourceType.PUBLICATION, false),
                mutate(PkiOperation.RetryPublication.NAME, Permission.Action.PUBLICATION_RETRY, Permission.ResourceType.PUBLICATION, false),
                mutate(PkiOperation.ReconcilePublication.NAME, Permission.Action.PUBLICATION_RECONCILE, Permission.ResourceType.PUBLICATION, false),
                mutate(PkiOperation.CreateIntermediate.NAME, Permission.Action.ISSUER_CREATE, Permission.ResourceType.AUTHORITY, true),
                mutate(PkiOperation.IssueIntermediateCertificate.NAME, Permission.Action.ISSUER_CREATE, Permission.ResourceType.AUTHORITY, true),
                read(PkiOperation.InspectIssuerGeneration.NAME, Permission.Action.AUTHORITY_READ, Permission.ResourceType.ISSUER),
                read(PkiOperation.InspectIssuerChainPath.NAME, Permission.Action.CA_CHAIN_DOWNLOAD, Permission.ResourceType.ISSUER),
                read(PkiOperation.ListIssuerChainPaths.NAME, Permission.Action.CA_CHAIN_DOWNLOAD, Permission.ResourceType.ISSUER),
                mutate(PkiOperation.SelectIssuancePath.NAME, Permission.Action.ISSUER_ROTATE, Permission.ResourceType.AUTHORITY, true),
                mutate(PkiOperation.RegisterIssuerChainPath.NAME, Permission.Action.ISSUER_ROTATE, Permission.ResourceType.AUTHORITY, false),
                mutate(PkiOperation.RevokeCredential.NAME, Permission.Action.CERTIFICATE_REVOKE, Permission.ResourceType.CERTIFICATE, false),
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
                control(ServerControlOperation.EnrollCredentialPublication.NAME,
                        Permission.Action.CERTIFICATE_PUBLICATION_CHANGE,
                        Permission.ResourceType.CERTIFICATE, true, false),
                control(ServerControlOperation.IssueCapability.NAME, Permission.Action.DISCLOSURE_CAPABILITY_ISSUE, Permission.ResourceType.CAPABILITY, true, false),
                control(ServerControlOperation.RevokeCapability.NAME, Permission.Action.DISCLOSURE_CAPABILITY_REVOKE, Permission.ResourceType.CAPABILITY, true, false),
                control(ServerControlOperation.InspectAuditView.REDACTED, Permission.Action.AUDIT_READ_REDACTED, Permission.ResourceType.AUDIT, false, false),
                control(ServerControlOperation.InspectAuditView.FULL, Permission.Action.AUDIT_READ_FULL, Permission.ResourceType.AUDIT, false, false),
                control(ServerControlOperation.InspectAuditView.PII, Permission.Action.AUDIT_READ_PII, Permission.ResourceType.AUDIT, false, false),
                control(ServerControlOperation.InspectRepositoryAlias.NAME, Permission.Action.REPOSITORY_ALIAS_READ,
                        Permission.ResourceType.REPOSITORY_ALIAS, false, false),
                control(ServerControlOperation.ListRepositoryAliases.NAME, Permission.Action.REPOSITORY_ALIAS_READ,
                        Permission.ResourceType.REPOSITORY_ALIAS, false, false),
                control(ServerControlOperation.SetRepositoryAlias.NAME, Permission.Action.REPOSITORY_ALIAS_MANAGE,
                        Permission.ResourceType.REPOSITORY_ALIAS, true, true),
                control(ServerControlOperation.RemoveRepositoryAlias.NAME, Permission.Action.REPOSITORY_ALIAS_MANAGE,
                        Permission.ResourceType.REPOSITORY_ALIAS, true, true),
                control(ServerControlOperation.RegisterAcmeDirectory.NAME, Permission.Action.ACME_DIRECTORY_MANAGE,
                        Permission.ResourceType.ACME_DIRECTORY, true, true),
                control(ServerControlOperation.InspectAcmeDirectory.NAME, Permission.Action.ACME_DIRECTORY_READ,
                        Permission.ResourceType.ACME_DIRECTORY, false, false),
                control(ServerControlOperation.ListAcmeDirectories.NAME, Permission.Action.ACME_DIRECTORY_READ,
                        Permission.ResourceType.ACME_DIRECTORY, false, false),
                control(ServerControlOperation.SetAcmeDirectoryActive.ACTIVATE,
                        Permission.Action.ACME_DIRECTORY_MANAGE, Permission.ResourceType.ACME_DIRECTORY, true, true),
                control(ServerControlOperation.SetAcmeDirectoryActive.DEACTIVATE,
                        Permission.Action.ACME_DIRECTORY_MANAGE, Permission.ResourceType.ACME_DIRECTORY, true, false),
                control(ServerControlOperation.InspectAcmeAccount.NAME, Permission.Action.ACME_ACCOUNT_READ,
                        Permission.ResourceType.ACME_ACCOUNT, false, false),
                control(ServerControlOperation.ListAcmeAccounts.NAME, Permission.Action.ACME_ACCOUNT_READ,
                        Permission.ResourceType.ACME_ACCOUNT, false, false),
                control(ServerControlOperation.DeactivateAcmeAccount.NAME, Permission.Action.ACME_ACCOUNT_MANAGE,
                        Permission.ResourceType.ACME_ACCOUNT, true, false),
                control(ServerControlOperation.RegisterOcspResponder.NAME, Permission.Action.OCSP_ADMINISTER,
                        Permission.ResourceType.OCSP_RESPONDER, true, true),
                control(ServerControlOperation.InspectOcspResponder.NAME, Permission.Action.OCSP_RESPONDER_READ,
                        Permission.ResourceType.OCSP_RESPONDER, false, false),
                control(ServerControlOperation.ListOcspResponders.NAME, Permission.Action.OCSP_RESPONDER_READ,
                        Permission.ResourceType.OCSP_RESPONDER, false, false),
                control(ServerControlOperation.SetOcspResponderActive.ACTIVATE, Permission.Action.OCSP_ADMINISTER,
                        Permission.ResourceType.OCSP_RESPONDER, true, true),
                control(ServerControlOperation.SetOcspResponderActive.DEACTIVATE, Permission.Action.OCSP_ADMINISTER,
                        Permission.ResourceType.OCSP_RESPONDER, true, false),
                control(ServerControlOperation.SearchAudit.NAME, Permission.Action.AUDIT_EXPORT,
                        Permission.ResourceType.AUDIT, false, false),
                control(ServerControlOperation.VerifyAuditIntegrity.NAME, Permission.Action.AUDIT_INTEGRITY_VERIFY,
                        Permission.ResourceType.AUDIT, false, false)));
    }

    /**
     * Creates a registry and rejects duplicate operation identities.
     *
     * @param values complete finite descriptor set
     */
    public OperationSecurityDescriptors(List<Descriptor> values) {
        Map<String, Descriptor> copy = new LinkedHashMap<>();
        for (Descriptor descriptor : values) {
            if (copy.putIfAbsent(descriptor.operationId(), descriptor) != null) {
                throw new IllegalArgumentException("Duplicate operation security descriptor");
            }
        }
        descriptors = Map.copyOf(copy);
    }

    /**
     * Resolves one PKI descriptor or fails closed.
     *
     * @param operation exact typed PKI operation
     * @return corresponding security descriptor
     */
    public Descriptor require(PkiOperation operation) {
        Objects.requireNonNull(operation, "operation");
        Descriptor descriptor = descriptors.get(operation.name());
        if (descriptor == null) throw new SecurityException("Operation is not exposed by the server gateway");
        validateOperationType(operation, descriptor);
        return descriptor;
    }

    /**
     * Resolves either operation family through the sole descriptor authority.
     *
     * @param operation exact typed administrative operation
     * @return corresponding security descriptor
     */
    public Descriptor require(AdministrativeOperation operation) {
        Objects.requireNonNull(operation, "operation");
        Descriptor descriptor = descriptors.get(operation.name());
        if (descriptor == null) throw new SecurityException("Operation is not exposed by the server gateway");
        Family expected = operation instanceof AdministrativeOperation.Pki ? Family.PKI_OPERATION
                : Family.SERVER_CONTROL_OPERATION;
        if (descriptor.family() != expected) throw new SecurityException("Operation family differs");
        return descriptor;
    }

    /**
     * Returns the complete descriptor registry.
     *
     * @return immutable descriptor map keyed by operation ID
     */
    public Map<String, Descriptor> descriptors() {
        return descriptors;
    }

    /**
     * Resolves one descriptor by stable ID for strict transport decoding.
     *
     * @param operationId stable typed-operation identifier
     * @return corresponding security descriptor
     */
    public Descriptor require(String operationId) {
        Permission.requireBounded(operationId, 256, "operation ID");
        Descriptor descriptor = descriptors.get(operationId);
        if (descriptor == null) throw new SecurityException("Operation is not exposed by the server gateway");
        return descriptor;
    }

    /**
     * Computes an exact deterministic safe PKI-operation commitment.
     *
     * @param realmId owning realm
     * @param operation exact typed PKI operation
     * @param resource exact authorized resource
     * @return lowercase SHA-256 operation commitment
     */
    public String commitment(RealmId realmId, PkiOperation operation, Permission.Resource resource) {
        Descriptor descriptor = require(operation);
        return ApprovalService.digest(realmId.value() + '|' + descriptor.operationId() + '|'
                + canonicalArguments(operation) + '|' + canonicalResource(resource));
    }

    /**
     * Computes an exact deterministic commitment for either closed operation family.
     *
     * @param realmId owning realm
     * @param operation exact typed administrative operation
     * @param resource exact authorized resource
     * @return lowercase SHA-256 operation commitment
     */
    public String commitment(RealmId realmId, AdministrativeOperation operation, Permission.Resource resource) {
        require(operation);
        String arguments = operation instanceof AdministrativeOperation.Pki pki
                ? canonicalArguments(pki.operation()) : canonicalControl(((AdministrativeOperation.Control) operation).operation());
        return ApprovalService.digest(realmId.value() + '|' + operation.name() + '|' + arguments + '|'
                + canonicalResource(resource));
    }

    /**
     * Resolves the configured policy category for an operation's actual approval requirement.
     *
     * <p>Credential revocation is ordinarily approval-free. A matching RBAC grant
     * may condition that permission on approval, in which case the existing
     * high-risk approval policy supplies the real approval workflow without
     * classifying every revocation as high risk.</p>
     *
     * @param operation exact typed operation
     * @param grantApprovalRequired whether the authorizing grant requires approval
     * @return policy category, or {@link ApprovalCategory#NONE} when approval is not required
     */
    public ApprovalCategory approvalPolicyCategory(AdministrativeOperation operation,
            boolean grantApprovalRequired) {
        Descriptor descriptor = require(operation);
        if (descriptor.approvalCategory() != ApprovalCategory.NONE) {
            return descriptor.approvalCategory();
        }
        return grantApprovalRequired && operation instanceof AdministrativeOperation.Pki pki
                && (pki.operation() instanceof PkiOperation.RevokeCredential
                        || pki.operation() instanceof PkiOperation.RevokePendingCredentialConfirmation)
                        ? ApprovalCategory.HIGH_RISK : ApprovalCategory.NONE;
    }

    /**
     * Verifies that caller-supplied security scope matches operation identities.
     *
     * @param operation exact typed PKI operation
     * @param resource caller-supplied resource and security scope
     */
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
            case PkiOperation.ListPendingCredentialConfirmations value ->
                resource.objectId().isEmpty()
                    && resource.scope().authorityId().filter(value.authorityId()::equals).isPresent()
                    && resource.scope().profileId().equals(value.profileId());
            case PkiOperation.IssueCredentialConfirmationChallenge value ->
                resource.objectId().filter(value.credentialId()::equals).isPresent()
                    && resource.scope().authorityId().isPresent()
                    && resource.scope().profileId().isPresent();
            case PkiOperation.CompleteCredentialConfirmationProof value ->
                resource.objectId().filter(value.submission().proofCas().credentialId()::equals).isPresent()
                    && resource.scope().authorityId().isPresent()
                    && resource.scope().profileId().isPresent();
            case PkiOperation.RevokePendingCredentialConfirmation value ->
                resource.objectId().filter(value.credentialId()::equals).isPresent()
                    && resource.scope().authorityId().isPresent()
                    && resource.scope().profileId().isPresent();
            case PkiOperation.IssueCredential value -> resource.scope().authorityId().filter(value.issuerCaId()::equals).isPresent()
                    && resource.scope().profileId().filter(value.profileId()::equals).isPresent();
            case PkiOperation.RenewCredential value -> resource.objectId().filter(value.credentialId()::equals).isPresent()
                    && resource.scope().authorityId().isPresent();
            case PkiOperation.ReplaceCredential value -> resource.objectId().filter(value.existingCredentialId()::equals).isPresent()
                    && resource.scope().authorityId().isPresent()
                    && resource.scope().profileId().filter(value.profileId()::equals).isPresent();
            case PkiOperation.ReissueCredential value -> resource.objectId().filter(value.credentialId()::equals).isPresent()
                    && resource.scope().authorityId().isPresent();
            case PkiOperation.RolloverCaCertificate value -> matchesAuthorityAndObject(resource, value.caId());
            case PkiOperation.RotateCaKey value -> matchesAuthorityAndObject(resource, value.caId());
            case PkiOperation.InspectRequest value -> resource.objectId().filter(value.requestId()::equals).isPresent()
                    && resource.scope().authorityId().isEmpty();
            case PkiOperation.ImportRequest ignored -> resource.objectId().isEmpty()
                    && resource.scope().authorityId().isEmpty();
            case PkiOperation.VerifyRequest value -> resource.objectId().filter(value.requestId()::equals).isPresent()
                    && resource.scope().authorityId().isEmpty();
            case PkiOperation.RegisterProfile ignored -> resource.scope().authorityId().isEmpty()
                    && resource.objectId().isEmpty();
            case PkiOperation.ValidateConfiguration ignored -> resource.scope().authorityId().isEmpty()
                    && resource.objectId().isEmpty();
            case PkiOperation.ValidateProfile ignored -> resource.scope().authorityId().isEmpty()
                    && resource.objectId().isEmpty();
            case PkiOperation.ValidateAlgorithmBindings ignored -> resource.scope().authorityId().isEmpty()
                    && resource.objectId().isEmpty();
            case PkiOperation.RevokeCredential value -> resource.objectId().filter(value.credentialId()::equals).isPresent()
                    && resource.scope().authorityId().isPresent();
            case PkiOperation.ReadRevocationHistory value -> resource.objectId().filter(value.credentialId()::equals).isPresent()
                    && resource.scope().authorityId().isPresent();
            case PkiOperation.InspectRevocation value -> resource.objectId().filter(value.credentialId()::equals).isPresent()
                    && resource.scope().authorityId().isPresent();
            case PkiOperation.SnapshotRevocations ignored -> resource.objectId().isEmpty()
                    && resource.scope().authorityId().isEmpty();
            case PkiOperation.InspectStatus value -> resource.objectId().filter(value.statusObjectId()::equals).isPresent()
                    && resource.scope().authorityId().isEmpty();
            case PkiOperation.ListStatus value -> resource.objectId().isEmpty()
                    && resource.scope().authorityId().filter(value.issuerCaId()::equals).isPresent();
            case PkiOperation.ListPublications ignored -> resource.objectId().isEmpty()
                    && resource.scope().authorityId().isEmpty();
            case PkiOperation.RegisterPublication value -> resource.objectId().filter(value.publicationId()::equals).isPresent()
                    && resource.scope().authorityId().isPresent();
            case PkiOperation.RetryPublication value -> resource.objectId().filter(value.publicationId()::equals).isPresent()
                    && resource.scope().authorityId().isPresent();
            case PkiOperation.ReconcilePublication value -> resource.objectId().filter(value.publicationId()::equals).isPresent()
                    && resource.scope().authorityId().isPresent();
            case PkiOperation.CreateIntermediate value -> resource.objectId().isEmpty()
                    && resource.scope().authorityId().filter(value.issuerCaId()::equals).isPresent()
                    && resource.scope().profileId().filter(value.profileId()::equals).isPresent();
            case PkiOperation.IssueIntermediateCertificate value ->
                resource.objectId().filter(value.subjectCaId()::equals).isPresent()
                    && resource.scope().authorityId().filter(value.issuerCaId()::equals).isPresent()
                    && resource.scope().profileId().filter(value.profileId()::equals).isPresent();
            case PkiOperation.InspectIssuerGeneration value -> resource.objectId().filter(value.issuerId()::equals).isPresent()
                    && resource.scope().authorityId().isEmpty();
            case PkiOperation.InspectIssuerChainPath value -> resource.objectId().filter(value.pathId()::equals).isPresent()
                    && resource.scope().authorityId().isEmpty();
            case PkiOperation.ListIssuerChainPaths value -> resource.objectId().filter(value.issuerId()::equals).isPresent()
                    && resource.scope().authorityId().isEmpty();
            case PkiOperation.SelectIssuancePath value -> matchesAuthorityAndObject(resource, value.caId());
            case PkiOperation.RegisterIssuerChainPath value -> matchesAuthorityAndObject(resource, value.caId());
            case PkiOperation.GenerateStatus value -> resource.scope().authorityId().filter(value.issuerCaId()::equals).isPresent();
            case PkiOperation.InspectPublication value -> resource.objectId().filter(value.publicationId()::equals).isPresent()
                    && resource.scope().authorityId().isPresent();
            case PkiOperation.ProcessPublication value -> resource.objectId().filter(value.publicationId()::equals).isPresent()
                    && resource.scope().authorityId().isPresent();
            case PkiOperation.ListAlgorithmBindings ignored -> resource.scope().authorityId().isEmpty();
            case PkiOperation.InspectAlgorithmBinding ignored -> resource.scope().authorityId().isEmpty();
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
            case PkiOperation.ListPendingCredentialConfirmations value -> "authority="
                    + atom(value.authorityId().value()) + ";profile="
                    + atom(value.profileId().orElse("")) + ";cutoff="
                    + atom(value.cutoffInclusive().toString()) + ";cursor="
                    + atom(value.afterExclusive().map(
                            zeroecho.pki.api.confirmation.CredentialConfirmationReviewCursor::value).orElse(""))
                    + ";limit=" + value.limit();
            case PkiOperation.IssueCredentialConfirmationChallenge value ->
                "credential=" + atom(value.credentialId().value());
            case PkiOperation.CompleteCredentialConfirmationProof value ->
                confirmationProofArguments(value);
            case PkiOperation.RevokePendingCredentialConfirmation value ->
                "credential=" + atom(value.credentialId().value())
                    + ";reason=UNSPECIFIED;justificationPresent="
                    + value.operatorJustification().isPresent() + ";justification="
                    + atom(value.operatorJustification().orElse(""));
            case PkiOperation.IssueCredential value -> "issuer=" + atom(value.issuerCaId().value()) + ";request="
                    + atom(value.requestId().value()) + ";profile=" + atom(value.profileId());
            case PkiOperation.RenewCredential value -> "credential=" + atom(value.credentialId().value());
            case PkiOperation.ReplaceCredential value -> "existing=" + atom(value.existingCredentialId().value())
                    + ";request=" + atom(value.requestId().value()) + ";profile=" + atom(value.profileId());
            case PkiOperation.ReissueCredential value -> "credential=" + atom(value.credentialId().value());
            case PkiOperation.RolloverCaCertificate value -> "ca=" + atom(value.caId().value()) + ";issuer="
                    + atom(value.issuerCaId().map(zeroecho.pki.api.PkiId::value).orElse(""));
            case PkiOperation.RotateCaKey value -> "ca=" + atom(value.caId().value()) + ";newKeyRef="
                    + atom(value.newKeyRef().map(zeroecho.pki.api.KeyRef::value).orElse("")) + ";issuer="
                    + atom(value.issuerCaId().map(zeroecho.pki.api.PkiId::value).orElse(""));
            case PkiOperation.InspectRequest value -> "request=" + atom(value.requestId().value());
            case PkiOperation.ImportRequest value -> "format=" + atom(value.formatId().value()) + ";encoded="
                    + digestOfBytes(value.encoded().bytes());
            case PkiOperation.VerifyRequest value -> "request=" + atom(value.requestId().value());
            case PkiOperation.RegisterProfile value -> "document=" + digestOfBytes(value.document());
            case PkiOperation.ValidateConfiguration ignored -> "validate=configuration";
            case PkiOperation.ValidateProfile value -> "document=" + digestOfBytes(value.document());
            case PkiOperation.ValidateAlgorithmBindings value -> "binding="
                    + atom(value.bindingId().orElse("")) + ";commitment="
                    + atom(value.expectedCommitment().orElse(""));
            case PkiOperation.RevokeCredential value -> "credential=" + atom(value.credentialId().value())
                    + ";reason=" + value.reason().name() + ";justificationPresent="
                    + value.operatorJustification().isPresent() + ";justification="
                    + atom(value.operatorJustification().orElse(""));
            case PkiOperation.ReadRevocationHistory value -> "credential=" + atom(value.credentialId().value())
                    + ";limit=" + value.limit();
            case PkiOperation.CreateIntermediate value -> "format=" + atom(value.formatId().value()) + ";issuer="
                    + atom(value.issuerCaId().value()) + ";subject=" + atom(value.subjectRef().value())
                    + ";profile=" + atom(value.profileId()) + ";keyRef="
                    + atom(value.keyRef().map(zeroecho.pki.api.KeyRef::value).orElse(""));
            case PkiOperation.IssueIntermediateCertificate value -> "format=" + atom(value.formatId().value())
                    + ";issuer=" + atom(value.issuerCaId().value()) + ";subject=" + atom(value.subjectCaId().value())
                    + ";profile=" + atom(value.profileId()) + ";validity="
                    + atom(value.requestedValidity().map(v -> v.notBefore() + "/" + v.notAfter()).orElse(""));
            case PkiOperation.InspectIssuerGeneration value -> "issuer=" + atom(value.issuerId().value());
            case PkiOperation.InspectIssuerChainPath value -> "path=" + atom(value.pathId().value());
            case PkiOperation.ListIssuerChainPaths value -> "issuer=" + atom(value.issuerId().value());
            case PkiOperation.SelectIssuancePath value -> "ca=" + atom(value.caId().value()) + ";issuer="
                    + atom(value.issuerId().value()) + ";path=" + atom(value.pathId().value()) + ";reason="
                    + atom(value.reason());
            case PkiOperation.RegisterIssuerChainPath value -> "ca=" + atom(value.caId().value()) + ";issuer="
                    + atom(value.issuerId().value()) + ";parentPath=" + atom(value.parentPathId().value());
            case PkiOperation.GenerateStatus value -> "issuer=" + atom(value.issuerCaId().value()) + ";type="
                    + value.type().name() + ";format=" + atom(value.formatId().value());
            case PkiOperation.InspectRevocation value -> "credential=" + atom(value.credentialId().value());
            case PkiOperation.SnapshotRevocations value -> "limit=" + value.limit();
            case PkiOperation.InspectStatus value -> "status=" + atom(value.statusObjectId().value());
            case PkiOperation.ListStatus value -> "issuer=" + atom(value.issuerCaId().value()) + ";limit=" + value.limit();
            case PkiOperation.ListPublications value -> "limit=" + value.limit();
            case PkiOperation.RegisterPublication value -> "publication=" + atom(value.publicationId().value())
                    + ";sourceType=" + value.sourceType().name() + ";source=" + atom(value.sourceId().value())
                    + ";targetType=" + value.target().type().name() + ";target=" + atom(value.target().targetId());
            case PkiOperation.RetryPublication value -> "publication=" + atom(value.publicationId().value());
            case PkiOperation.ReconcilePublication value -> "publication=" + atom(value.publicationId().value());
            case PkiOperation.InspectPublication value -> "publication=" + atom(value.publicationId().value());
            case PkiOperation.ProcessPublication value -> "publication=" + atom(value.publicationId().value());
            case PkiOperation.ListAlgorithmBindings value -> "origin=" + atom(value.origin().orElse("")) + ";role="
                    + atom(value.role().orElse("")) + ";limit=" + value.limit();
            case PkiOperation.InspectAlgorithmBinding value -> "binding=" + atom(value.bindingId());
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

    // Deterministic content digest for byte-valued operation arguments (e.g. an imported request or
    // profile document), so the approval commitment binds the exact submitted bytes.
    private static String digestOfBytes(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static String confirmationProofArguments(
            PkiOperation.CompleteCredentialConfirmationProof operation) {
        zeroecho.pki.api.confirmation.CredentialConfirmationProofSubmission submission = operation.submission();
        zeroecho.pki.api.confirmation.CredentialConfirmationProofCas proofCas = submission.proofCas();
        byte[] response = submission.response();
        String responseDigest;
        try {
            responseDigest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(response));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        } finally {
            Arrays.fill(response, (byte) 0);
        }
        return "credential=" + atom(proofCas.credentialId().value())
                + ";lifecycleRevision=" + proofCas.expectedLifecycleRevision()
                + ";lifecycleCommitment=" + atom(proofCas.expectedLifecycleRecordCommitment())
                + ";challengeCommitment=" + atom(proofCas.expectedChallengeRecordCommitment())
                + ";responseSha256=" + responseDigest;
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
                ? Permission.DataView.PII_FULL
                : action == Permission.Action.AUDIT_READ_FULL || action == Permission.Action.AUDIT_EXPORT
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
            case ServerControlOperation.EnrollCredentialPublication value -> "credential="
                    + atom(value.credentialId().value()) + ";owner="
                    + atom(value.ownerPrincipalId().orElse(""));
            case ServerControlOperation.IssueCapability value -> "object=" + atom(value.objectId().value())
                    + ";expiry=" + value.expiresAt();
            case ServerControlOperation.RevokeCapability value -> "capability=" + atom(value.capabilityId());
            case ServerControlOperation.InspectAuditView value -> "object=" + atom(value.objectId().value())
                    + ";view=" + value.view().name();
            case ServerControlOperation.InspectRepositoryAlias value -> "authority="
                    + atom(value.authorityId().value()) + ";type=" + value.type().name();
            case ServerControlOperation.ListRepositoryAliases value -> "offset=" + value.offset()
                    + ";limit=" + value.limit();
            case ServerControlOperation.SetRepositoryAlias value -> "authority="
                    + atom(value.authorityId().value()) + ";type=" + value.type().name() + ";target="
                    + atom(value.targetObjectId().value()) + ";issuer="
                    + atom(value.issuerId().map(zeroecho.pki.api.PkiId::value).orElse("")) + ";expected="
                    + atom(value.expectedCurrentCommitment().orElse(""));
            case ServerControlOperation.RemoveRepositoryAlias value -> "authority="
                    + atom(value.authorityId().value()) + ";type=" + value.type().name() + ";expected="
                    + atom(value.expectedCurrentCommitment());
            case ServerControlOperation.RegisterAcmeDirectory value -> "alias="
                    + atom(value.registration().alias()) + ";authority="
                    + atom(value.registration().authorityId().value()) + ";profile="
                    + atom(value.registration().profileId()) + ";namespaces="
                    + atom(value.registration().dnsNamespaces().stream().sorted().collect(java.util.stream.Collectors.joining(",")))
                    + ";validity=" + value.registration().maximumValidity().toMillis()
                    + ";keyAlgorithms=" + atom(value.registration().publicKeyAlgorithms().stream().sorted()
                            .collect(java.util.stream.Collectors.joining(",")))
                    + ";bindings=" + atom(value.registration().x509BindingPolicies().stream().sorted()
                            .collect(java.util.stream.Collectors.joining(",")))
                    + ";challenges=" + atom(value.registration().challengeTypes().stream().map(Enum::name)
                            .sorted().collect(java.util.stream.Collectors.joining(",")))
                    + ";providers=" + atom(value.registration().challengeProviderIds().stream().sorted()
                            .collect(java.util.stream.Collectors.joining(",")))
                    + ";eabProvider=" + atom(value.registration().eabProviderId().orElse("NONE"))
                    + ";eabRequired=" + value.registration().eabRequired()
                    + ";expectedProfile=" + profilePrecondition(value).expectedProfile().profileId()
                    + ':' + profilePrecondition(value).expectedProfile().profileVersion()
                    + ':' + HexFormat.of().formatHex(
                            profilePrecondition(value).expectedProfile().canonicalSha256())
                    + ";confirmationPolicy="
                    + profilePrecondition(value).expectedPolicyCommitment();
            case ServerControlOperation.InspectAcmeDirectory value -> "directory=" + atom(value.directoryId());
            case ServerControlOperation.ListAcmeDirectories value -> "offset=" + value.offset() + ";limit=" + value.limit();
            case ServerControlOperation.SetAcmeDirectoryActive value -> "directory="
                    + atom(value.directoryId()) + ";active=" + value.active();
            case ServerControlOperation.InspectAcmeAccount value -> "account=" + atom(value.accountId());
            case ServerControlOperation.ListAcmeAccounts value -> "offset=" + value.offset() + ";limit=" + value.limit();
            case ServerControlOperation.DeactivateAcmeAccount value -> "account=" + atom(value.accountId());
            case ServerControlOperation.RegisterOcspResponder value -> "responder="
                    + atom(value.registration().responderId()) + ";authority="
                    + atom(value.registration().authorityId().value()) + ";issuer="
                    + atom(value.registration().issuerId().value()) + ";binding="
                    + value.registration().signatureBindingCommitment() + ";requestPolicy="
                    + OcspResponderService.requestPolicyCommitment(value.registration());
            case ServerControlOperation.InspectOcspResponder value -> "responder=" + atom(value.responderId());
            case ServerControlOperation.ListOcspResponders value -> "offset=" + value.offset()
                    + ";limit=" + value.limit();
            case ServerControlOperation.SetOcspResponderActive value -> "responder="
                    + atom(value.responderId()) + ";active=" + value.active();
            case ServerControlOperation.SearchAudit value -> auditQueryCommitment(value.query());
            case ServerControlOperation.VerifyAuditIntegrity value -> "head=" + atom(value.expectedHead()
                    .map(head -> head.sequence() + ":" + head.recordHash()).orElse(""));
        };
    }

    private static String auditQueryCommitment(zeroecho.pki.api.audit.AuditQuery query) {
        String details = query.requiredDetails().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(entry -> atom(entry.getKey()) + '=' + atom(entry.getValue()))
                .collect(java.util.stream.Collectors.joining(","));
        return "category=" + atom(query.category().orElse("")) + ";action=" + atom(query.action().orElse(""))
                + ";after=" + atom(query.after().map(java.time.Instant::toString).orElse(""))
                + ";before=" + atom(query.before().map(java.time.Instant::toString).orElse(""))
                + ";object=" + atom(query.objectId().map(zeroecho.pki.api.PkiId::value).orElse(""))
                + ";principal=" + atom(query.principalName().orElse("")) + ";limit=" + query.limit()
                + ";details=" + atom(details);
    }

    private static ServerControlOperation.AcmeDirectoryProfilePrecondition profilePrecondition(
            ServerControlOperation.RegisterAcmeDirectory operation) {
        return operation.profilePrecondition()
                .orElseThrow(() -> new IllegalStateException("ACME directory profile precondition is unresolved"));
    }
}
