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
package zeroecho.pki.server.http;

import java.time.Instant;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofCas;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofSubmission;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.OperationSecurityDescriptors;
import zeroecho.pki.application.OcspResponseService;
import zeroecho.pki.server.AdministrativeOperation;
import zeroecho.pki.server.ApprovalService;
import zeroecho.pki.server.DisclosureService;
import zeroecho.pki.server.Permission;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.OcspResponderService;
import zeroecho.pki.server.RealmId;
import zeroecho.pki.server.RepositoryAliasService;
import zeroecho.pki.server.RoleTemplateCatalog;
import zeroecho.pki.server.SecurityPrincipal;
import zeroecho.pki.server.ServerControlOperation;
import zeroecho.pki.server.acme.AcmeService;
import zeroecho.pki.server.acme.AcmeState;

/** Closed strict HTTP decoding for operations exposed by the existing gateway. */
@SuppressWarnings("PMD")
final class HttpOperationCodec {
    /** Fully decoded gateway input excluding authenticated principal and request ID. */
    record Decoded(AdministrativeOperation operation, Permission.Resource resource, Permission.Context context,
            Optional<String> approvalId, Optional<Duration> requestedDeadline) { }

    private HttpOperationCodec() {
    }

    static Decoded decode(String operationId, byte[] document, int maximumBytes, RealmId realmId,
            java.util.function.Function<String, OperationSecurityDescriptors.Descriptor> descriptors) {
        Fields root = Fields.of(StrictJson.parse(document, maximumBytes));
        root.allowed(Set.of("version", "authorityId", "approvalId", "deadline", "arguments"));
        if (root.integer("version") != 1) throw new IllegalArgumentException("Request version is unsupported");
        Optional<PkiId> authority = root.optionalText("authorityId").map(PkiId::new);
        Optional<String> approval = root.optionalText("approvalId");
        approval.ifPresent(value -> requireId(value, "approval ID"));
        Optional<Duration> deadline = root.optionalText("deadline").map(HttpOperationCodec::duration);
        Fields arguments = root.object("arguments");
        OperationSecurityDescriptors.Descriptor descriptor = descriptors.apply(operationId);
        AdministrativeOperation operation;
        Permission.Scope scope;
        Optional<PkiId> objectId;
        if (descriptor.family() == OperationSecurityDescriptors.Family.PKI_OPERATION) {
            PkiOperation pki = operation(operationId, arguments, authority);
            operation = new AdministrativeOperation.Pki(pki);
            boolean realmWide = realmWide(pki);
            if (realmWide == authority.isPresent()) {
                throw new IllegalArgumentException(realmWide
                        ? "Realm-wide operation must not specify authorityId"
                        : "Authority-scoped operation requires authorityId");
            }
            validateAuthority(pki, authority);
            scope = new Permission.Scope(realmId, authority, Optional.empty(), profile(pki));
            objectId = objectId(pki);
        } else {
            ServerControlOperation control = control(operationId, arguments, realmId, authority, descriptors);
            operation = new AdministrativeOperation.Control(control);
            scope = controlScope(control, realmId, authority);
            objectId = controlObject(control);
        }
        arguments.complete();
        root.complete();
        Permission.Resource resource = new Permission.Resource(descriptor.resourceType(), scope, objectId,
                Optional.empty());
        Optional<String> justification = operation instanceof AdministrativeOperation.Pki pki
                ? operatorJustification(pki.operation()) : Optional.empty();
        Permission.Context context = new Permission.Context(justification, approval.isPresent(), false, Map.of());
        return new Decoded(operation, resource, context, approval, deadline);
    }

    private static PkiOperation operation(String id, Fields fields, Optional<PkiId> authority) {
        return switch (id) {
            case PkiOperation.ListAuthorities.NAME -> {
                fields.exact("limit"); yield new PkiOperation.ListAuthorities(fields.integer("limit"));
            }
            case PkiOperation.InspectAuthority.NAME -> {
                fields.exact("caId"); yield new PkiOperation.InspectAuthority(fields.pkiId("caId"));
            }
            case PkiOperation.CreateAuthority.NAME -> {
                fields.exact("formatId", "subjectRef", "profileId", "keyRef");
                yield new PkiOperation.CreateAuthority(new FormatId(fields.text("formatId")),
                        new SubjectRef(fields.text("subjectRef")), fields.text("profileId"),
                        new KeyRef(fields.text("keyRef")));
            }
            case PkiOperation.TransitionAuthority.NAME -> {
                fields.exact("caId", "state", "reason");
                yield new PkiOperation.TransitionAuthority(fields.pkiId("caId"),
                        CaState.valueOf(fields.text("state")), fields.text("reason"));
            }
            case PkiOperation.ListProfileVersions.NAME -> {
                fields.exact("profileId"); yield new PkiOperation.ListProfileVersions(fields.text("profileId"));
            }
            case PkiOperation.InspectProfile.NAME -> {
                fields.exact("profileId", "profileVersion");
                yield new PkiOperation.InspectProfile(fields.text("profileId"), fields.longValue("profileVersion"));
            }
            case PkiOperation.ActivateProfile.NAME -> {
                fields.exact("profileId", "profileVersion");
                yield new PkiOperation.ActivateProfile(fields.text("profileId"), fields.longValue("profileVersion"));
            }
            case PkiOperation.InspectCredential.NAME -> {
                fields.exact("credentialId"); yield new PkiOperation.InspectCredential(fields.pkiId("credentialId"));
            }
            case PkiOperation.ListPendingCredentialConfirmations.NAME -> {
                fields.allowed(Set.of("profileId", "cutoffInclusive", "afterExclusive", "limit"));
                yield new PkiOperation.ListPendingCredentialConfirmations(
                        authority.orElseThrow(() -> new IllegalArgumentException(
                                "Pending confirmation query requires authorityId")),
                        fields.optionalText("profileId"), instant(fields.text("cutoffInclusive")),
                        fields.optionalText("afterExclusive").map(
                                zeroecho.pki.api.confirmation.CredentialConfirmationReviewCursor::new),
                        fields.integer("limit"));
            }
            case PkiOperation.IssueCredentialConfirmationChallenge.NAME -> {
                fields.exact("credentialId");
                yield new PkiOperation.IssueCredentialConfirmationChallenge(fields.pkiId("credentialId"));
            }
            case PkiOperation.CompleteCredentialConfirmationProof.NAME -> {
                fields.exact("credentialId", "expectedLifecycleRevision",
                        "expectedLifecycleRecordCommitment", "expectedChallengeRecordCommitment", "response");
                CredentialConfirmationProofCas proofCas = new CredentialConfirmationProofCas(
                        fields.pkiId("credentialId"), fields.longValue("expectedLifecycleRevision"),
                        fields.text("expectedLifecycleRecordCommitment"),
                        fields.text("expectedChallengeRecordCommitment"));
                yield new PkiOperation.CompleteCredentialConfirmationProof(
                        proofSubmission(proofCas, fields.text("response")));
            }
            case PkiOperation.RevokePendingCredentialConfirmation.NAME -> {
                fields.allowed(Set.of("credentialId", "justification"));
                yield new PkiOperation.RevokePendingCredentialConfirmation(
                        fields.pkiId("credentialId"), fields.optionalText("justification"));
            }
            case PkiOperation.IssueCredential.NAME -> {
                fields.exact("issuerCaId", "requestId", "profileId");
                yield new PkiOperation.IssueCredential(fields.pkiId("issuerCaId"), fields.pkiId("requestId"),
                        fields.text("profileId"));
            }
            case PkiOperation.RevokeCredential.NAME -> {
                fields.allowed(Set.of("credentialId", "reason", "justification"));
                yield new PkiOperation.RevokeCredential(fields.pkiId("credentialId"),
                        RevocationReason.valueOf(fields.text("reason")), fields.optionalText("justification"));
            }
            case PkiOperation.RenewCredential.NAME -> {
                fields.exact("credentialId");
                yield new PkiOperation.RenewCredential(fields.pkiId("credentialId"));
            }
            case PkiOperation.ReplaceCredential.NAME -> {
                fields.exact("existingCredentialId", "requestId", "profileId");
                yield new PkiOperation.ReplaceCredential(fields.pkiId("existingCredentialId"),
                        fields.pkiId("requestId"), fields.text("profileId"));
            }
            case PkiOperation.ReissueCredential.NAME -> {
                fields.exact("credentialId");
                yield new PkiOperation.ReissueCredential(fields.pkiId("credentialId"));
            }
            case PkiOperation.RolloverCaCertificate.NAME -> {
                fields.allowed(Set.of("caId", "issuerCaId"));
                yield new PkiOperation.RolloverCaCertificate(fields.pkiId("caId"),
                        fields.optionalText("issuerCaId").map(PkiId::new));
            }
            case PkiOperation.RotateCaKey.NAME -> {
                fields.allowed(Set.of("caId", "newKeyRef", "issuerCaId"));
                yield new PkiOperation.RotateCaKey(fields.pkiId("caId"),
                        fields.optionalText("newKeyRef").map(KeyRef::new),
                        fields.optionalText("issuerCaId").map(PkiId::new));
            }
            case PkiOperation.ReadRevocationHistory.NAME -> {
                fields.exact("credentialId", "limit");
                yield new PkiOperation.ReadRevocationHistory(fields.pkiId("credentialId"), fields.integer("limit"));
            }
            case PkiOperation.GenerateStatus.NAME -> {
                fields.exact("issuerCaId", "type", "formatId");
                yield new PkiOperation.GenerateStatus(fields.pkiId("issuerCaId"),
                        StatusObjectType.valueOf(fields.text("type")), new FormatId(fields.text("formatId")));
            }
            case PkiOperation.InspectPublication.NAME -> {
                fields.exact("publicationId");
                yield new PkiOperation.InspectPublication(fields.pkiId("publicationId"));
            }
            case PkiOperation.ProcessPublication.NAME -> {
                fields.exact("publicationId");
                yield new PkiOperation.ProcessPublication(fields.pkiId("publicationId"));
            }
            case PkiOperation.InspectRevocation.NAME -> {
                fields.exact("credentialId");
                yield new PkiOperation.InspectRevocation(fields.pkiId("credentialId"));
            }
            case PkiOperation.SnapshotRevocations.NAME -> {
                fields.exact("limit");
                yield new PkiOperation.SnapshotRevocations(fields.integer("limit"));
            }
            case PkiOperation.InspectStatus.NAME -> {
                fields.exact("statusObjectId");
                yield new PkiOperation.InspectStatus(fields.pkiId("statusObjectId"));
            }
            case PkiOperation.ListStatus.NAME -> {
                fields.exact("issuerCaId", "limit");
                yield new PkiOperation.ListStatus(fields.pkiId("issuerCaId"), fields.integer("limit"));
            }
            case PkiOperation.ListPublications.NAME -> {
                fields.exact("limit");
                yield new PkiOperation.ListPublications(fields.integer("limit"));
            }
            case PkiOperation.RegisterPublication.NAME -> {
                fields.exact("publicationId", "sourceType", "sourceId", "targetType", "targetId");
                yield new PkiOperation.RegisterPublication(fields.pkiId("publicationId"),
                        zeroecho.pki.api.publication.PublicationSourceType.valueOf(fields.text("sourceType")),
                        fields.pkiId("sourceId"),
                        new zeroecho.pki.api.publication.PublicationTarget(
                                zeroecho.pki.api.publication.PublicationTargetType.valueOf(fields.text("targetType")),
                                fields.text("targetId")));
            }
            case PkiOperation.RetryPublication.NAME -> {
                fields.exact("publicationId");
                yield new PkiOperation.RetryPublication(fields.pkiId("publicationId"));
            }
            case PkiOperation.ReconcilePublication.NAME -> {
                fields.exact("publicationId");
                yield new PkiOperation.ReconcilePublication(fields.pkiId("publicationId"));
            }
            case PkiOperation.CreateIntermediate.NAME -> {
                fields.allowed(Set.of("formatId", "issuerCaId", "subjectRef", "profileId", "keyRef"));
                yield new PkiOperation.CreateIntermediate(new FormatId(fields.text("formatId")),
                        fields.pkiId("issuerCaId"), new SubjectRef(fields.text("subjectRef")),
                        fields.text("profileId"), fields.optionalText("keyRef").map(KeyRef::new));
            }
            case PkiOperation.IssueIntermediateCertificate.NAME -> {
                fields.allowed(Set.of("formatId", "issuerCaId", "subjectCaId", "profileId", "notBefore", "notAfter"));
                yield new PkiOperation.IssueIntermediateCertificate(new FormatId(fields.text("formatId")),
                        fields.pkiId("issuerCaId"), fields.pkiId("subjectCaId"), fields.text("profileId"),
                        requestedValidity(fields));
            }
            case PkiOperation.InspectIssuerGeneration.NAME -> {
                fields.exact("issuerId");
                yield new PkiOperation.InspectIssuerGeneration(fields.pkiId("issuerId"));
            }
            case PkiOperation.InspectIssuerChainPath.NAME -> {
                fields.exact("pathId");
                yield new PkiOperation.InspectIssuerChainPath(fields.pkiId("pathId"));
            }
            case PkiOperation.ListIssuerChainPaths.NAME -> {
                fields.exact("issuerId");
                yield new PkiOperation.ListIssuerChainPaths(fields.pkiId("issuerId"));
            }
            case PkiOperation.SelectIssuancePath.NAME -> {
                fields.exact("caId", "issuerId", "pathId", "reason");
                yield new PkiOperation.SelectIssuancePath(fields.pkiId("caId"), fields.pkiId("issuerId"),
                        fields.pkiId("pathId"), fields.text("reason"));
            }
            case PkiOperation.RegisterIssuerChainPath.NAME -> {
                fields.exact("caId", "issuerId", "parentPathId");
                yield new PkiOperation.RegisterIssuerChainPath(fields.pkiId("caId"), fields.pkiId("issuerId"),
                        fields.pkiId("parentPathId"));
            }
            case PkiOperation.ListAlgorithmBindings.NAME -> {
                fields.allowed(Set.of("origin", "role", "limit"));
                yield new PkiOperation.ListAlgorithmBindings(fields.optionalText("origin"),
                        fields.optionalText("role"), fields.integer("limit"));
            }
            case PkiOperation.InspectAlgorithmBinding.NAME -> {
                fields.exact("bindingId");
                yield new PkiOperation.InspectAlgorithmBinding(fields.text("bindingId"));
            }
            case PkiOperation.InspectRequest.NAME -> {
                fields.exact("requestId");
                yield new PkiOperation.InspectRequest(fields.pkiId("requestId"));
            }
            case PkiOperation.ImportRequest.NAME -> {
                fields.exact("formatId", "encoded");
                yield new PkiOperation.ImportRequest(new FormatId(fields.text("formatId")),
                        new EncodedObject(Encoding.DER, java.util.Base64.getDecoder().decode(fields.text("encoded"))));
            }
            case PkiOperation.VerifyRequest.NAME -> {
                fields.exact("requestId");
                yield new PkiOperation.VerifyRequest(fields.pkiId("requestId"));
            }
            case PkiOperation.RegisterProfile.NAME -> {
                fields.exact("document");
                yield new PkiOperation.RegisterProfile(java.util.Base64.getDecoder().decode(fields.text("document")));
            }
            case PkiOperation.ValidateConfiguration.NAME -> {
                fields.exact();
                yield new PkiOperation.ValidateConfiguration();
            }
            case PkiOperation.ValidateProfile.NAME -> {
                fields.exact("document");
                yield new PkiOperation.ValidateProfile(java.util.Base64.getDecoder().decode(fields.text("document")));
            }
            case PkiOperation.ValidateAlgorithmBindings.NAME -> {
                fields.allowed(Set.of("bindingId", "expectedCommitment"));
                yield new PkiOperation.ValidateAlgorithmBindings(fields.optionalText("bindingId"),
                        fields.optionalText("expectedCommitment"));
            }
            default -> throw new SecurityException("Operation is not exposed");
        };
    }

    private static ServerControlOperation control(String id, Fields fields, RealmId realmId,
            Optional<PkiId> authority,
            java.util.function.Function<String, OperationSecurityDescriptors.Descriptor> descriptors) {
        return switch (id) {
            case ServerControlOperation.RegisterPrincipal.NAME -> {
                fields.exact("principalId", "type", "displayName", "enabled");
                yield new ServerControlOperation.RegisterPrincipal(new SecurityPrincipal(fields.text("principalId"),
                        SecurityPrincipal.Type.valueOf(fields.text("type")), fields.text("displayName"),
                        Optional.empty(), Map.of(), fields.bool("enabled")));
            }
            case ServerControlOperation.InspectPrincipal.NAME -> {
                fields.exact("principalId"); yield new ServerControlOperation.InspectPrincipal(fields.text("principalId"));
            }
            case ServerControlOperation.ListPrincipals.NAME -> {
                fields.exact("offset", "limit"); yield new ServerControlOperation.ListPrincipals(
                        fields.integer("offset"), fields.integer("limit"));
            }
            case ServerControlOperation.SetPrincipalEnabled.ENABLE,
                    ServerControlOperation.SetPrincipalEnabled.DISABLE -> {
                fields.exact("principalId"); yield new ServerControlOperation.SetPrincipalEnabled(
                        fields.text("principalId"), id.equals(ServerControlOperation.SetPrincipalEnabled.ENABLE));
            }
            case ServerControlOperation.ListRoleTemplates.NAME -> {
                fields.exact(); yield new ServerControlOperation.ListRoleTemplates();
            }
            case ServerControlOperation.InspectRoleTemplate.NAME -> {
                fields.exact("templateId", "version"); yield new ServerControlOperation.InspectRoleTemplate(
                        fields.text("templateId"), fields.integer("version"));
            }
            case ServerControlOperation.CreateRoleAssignment.NAME -> {
                fields.allowed(Set.of("assignmentId", "principalId", "templateId", "templateVersion",
                        "profileId", "expiresAt"));
                Permission.Scope scope = new Permission.Scope(realmId, authority, Optional.empty(),
                        fields.optionalText("profileId"));
                yield new ServerControlOperation.CreateRoleAssignment(new RoleTemplateCatalog.Assignment(
                        fields.text("assignmentId"), fields.text("principalId"), fields.text("templateId"),
                        fields.integer("templateVersion"), scope, fields.optionalInstant("expiresAt"), true));
            }
            case ServerControlOperation.InspectRoleAssignment.NAME -> {
                fields.exact("assignmentId"); yield new ServerControlOperation.InspectRoleAssignment(
                        fields.text("assignmentId"));
            }
            case ServerControlOperation.ListRoleAssignments.NAME -> {
                fields.exact("offset", "limit"); yield new ServerControlOperation.ListRoleAssignments(
                        fields.integer("offset"), fields.integer("limit"));
            }
            case ServerControlOperation.RevokeRoleAssignment.NAME -> {
                fields.exact("assignmentId"); yield new ServerControlOperation.RevokeRoleAssignment(
                        fields.text("assignmentId"));
            }
            case ServerControlOperation.CreateGrant.NAME -> {
                fields.allowed(Set.of("grantId", "principalId", "effect", "action", "resourceType",
                        "issuerId", "profileId", "responderId", "relationship", "dataView", "conditions",
                        "expiresAt"));
                Permission.Scope scope = new Permission.Scope(realmId, authority,
                        fields.optionalText("issuerId").map(PkiId::new), fields.optionalText("profileId"),
                        fields.optionalText("responderId"));
                yield new ServerControlOperation.CreateGrant(new Permission.Grant(fields.text("grantId"),
                        fields.text("principalId"), Permission.Effect.valueOf(fields.text("effect")),
                        Permission.Action.valueOf(fields.text("action")),
                        Permission.ResourceType.valueOf(fields.text("resourceType")), scope,
                        Permission.Relationship.valueOf(fields.text("relationship")),
                        Permission.DataView.valueOf(fields.text("dataView")),
                        fields.enumSet("conditions", Permission.Condition.class), fields.optionalInstant("expiresAt"), true));
            }
            case ServerControlOperation.InspectGrant.NAME -> {
                fields.exact("grantId"); yield new ServerControlOperation.InspectGrant(fields.text("grantId"));
            }
            case ServerControlOperation.ListGrants.NAME -> {
                fields.exact("offset", "limit"); yield new ServerControlOperation.ListGrants(
                        fields.integer("offset"), fields.integer("limit"));
            }
            case ServerControlOperation.RevokeGrant.NAME -> {
                fields.exact("grantId"); yield new ServerControlOperation.RevokeGrant(fields.text("grantId"));
            }
            case ServerControlOperation.EvaluateAuthorization.NAME -> {
                fields.exact("principalId", "action", "resourceType", "relationship", "dataView");
                Permission.Resource resource = new Permission.Resource(
                        Permission.ResourceType.valueOf(fields.text("resourceType")),
                        new Permission.Scope(realmId, authority, Optional.empty(), Optional.empty()),
                        Optional.empty(), Optional.empty());
                yield new ServerControlOperation.EvaluateAuthorization(fields.text("principalId"),
                        Permission.Action.valueOf(fields.text("action")), resource,
                        Permission.Relationship.valueOf(fields.text("relationship")),
                        Permission.DataView.valueOf(fields.text("dataView")), Permission.Context.empty());
            }
            case ServerControlOperation.RequestApproval.NAME -> {
                fields.allowed(Set.of("approvalId", "targetOperation", "targetArguments", "targetAuthorityId"));
                String targetId = fields.text("targetOperation");
                Fields targetFields = fields.object("targetArguments");
                Optional<PkiId> targetAuthority = fields.optionalText("targetAuthorityId").map(PkiId::new);
                OperationSecurityDescriptors.Descriptor targetDescriptor = descriptors.apply(targetId);
                AdministrativeOperation targetOperation;
                Permission.Scope targetScope;
                Optional<PkiId> targetObject;
                if (targetDescriptor.family() == OperationSecurityDescriptors.Family.PKI_OPERATION) {
                    PkiOperation targetPki = operation(targetId, targetFields, targetAuthority);
                    targetOperation = new AdministrativeOperation.Pki(targetPki);
                    targetScope = new Permission.Scope(realmId, targetAuthority, Optional.empty(), profile(targetPki));
                    targetObject = objectId(targetPki);
                } else {
                    ServerControlOperation targetControl = control(targetId, targetFields, realmId,
                            targetAuthority, descriptors);
                    targetOperation = new AdministrativeOperation.Control(targetControl);
                    targetScope = controlScope(targetControl, realmId, targetAuthority);
                    targetObject = controlObject(targetControl);
                }
                targetFields.complete();
                Permission.Resource targetResource = new Permission.Resource(targetDescriptor.resourceType(),
                        targetScope, targetObject, Optional.empty());
                yield new ServerControlOperation.RequestApproval(fields.text("approvalId"),
                        targetOperation, targetResource);
            }
            case ServerControlOperation.InspectApproval.NAME -> {
                fields.exact("approvalId"); yield new ServerControlOperation.InspectApproval(fields.text("approvalId"));
            }
            case ServerControlOperation.ListApprovals.NAME -> {
                fields.allowed(Set.of("offset", "limit", "state", "requesterPrincipalId", "targetOperationId"));
                yield new ServerControlOperation.ListApprovals(fields.integer("offset"), fields.integer("limit"),
                        fields.optionalText("state").map(ApprovalService.State::valueOf),
                        fields.optionalText("requesterPrincipalId"), fields.optionalText("targetOperationId"));
            }
            case ServerControlOperation.DecideApproval.APPROVE,
                    ServerControlOperation.DecideApproval.REJECT -> {
                fields.exact("approvalId", "justification"); yield new ServerControlOperation.DecideApproval(
                        fields.text("approvalId"), id.equals(ServerControlOperation.DecideApproval.APPROVE)
                                ? ApprovalService.Choice.APPROVE : ApprovalService.Choice.REJECT,
                        fields.text("justification"));
            }
            case ServerControlOperation.CancelApproval.NAME -> {
                fields.exact("approvalId"); yield new ServerControlOperation.CancelApproval(fields.text("approvalId"));
            }
            case ServerControlOperation.CreateBreakGlass.CREATE -> {
                fields.exact("breakGlassId", "principalId", "grantId", "action", "resourceType", "reason", "expiresAt");
                Permission.Scope scope = new Permission.Scope(realmId, authority, Optional.empty(), Optional.empty());
                Permission.Grant grant = new Permission.Grant(fields.text("grantId"), fields.text("principalId"),
                        Permission.Effect.ALLOW, Permission.Action.valueOf(fields.text("action")),
                        Permission.ResourceType.valueOf(fields.text("resourceType")), scope,
                        Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED, Set.of(),
                        Optional.of(fields.instant("expiresAt")), true);
                yield new ServerControlOperation.CreateBreakGlass(fields.text("breakGlassId"),
                        fields.text("principalId"), grant, fields.text("reason"), fields.instant("expiresAt"));
            }
            case ServerControlOperation.ActivateBreakGlass.ACTIVATE -> {
                fields.exact("breakGlassId");
                yield new ServerControlOperation.ActivateBreakGlass(fields.text("breakGlassId"));
            }
            case ServerControlOperation.InspectBreakGlass.NAME -> {
                fields.exact("breakGlassId"); yield new ServerControlOperation.InspectBreakGlass(fields.text("breakGlassId"));
            }
            case ServerControlOperation.ListBreakGlass.NAME -> {
                fields.exact("offset", "limit"); yield new ServerControlOperation.ListBreakGlass(
                        fields.integer("offset"), fields.integer("limit"));
            }
            case ServerControlOperation.RevokeBreakGlass.NAME -> {
                fields.exact("breakGlassId"); yield new ServerControlOperation.RevokeBreakGlass(fields.text("breakGlassId"));
            }
            case ServerControlOperation.InspectDisclosure.NAME -> {
                fields.exact("objectId"); yield new ServerControlOperation.InspectDisclosure(fields.pkiId("objectId"));
            }
            case ServerControlOperation.SetDisclosure.NAME -> {
                fields.exact("objectId", "policy"); yield new ServerControlOperation.SetDisclosure(
                        fields.pkiId("objectId"), DisclosureService.Policy.valueOf(fields.text("policy")));
            }
            case ServerControlOperation.EnrollCredentialPublication.NAME -> {
                fields.allowed(Set.of("credentialId", "ownerPrincipalId"));
                yield new ServerControlOperation.EnrollCredentialPublication(fields.pkiId("credentialId"),
                        fields.optionalText("ownerPrincipalId"));
            }
            case ServerControlOperation.IssueCapability.NAME -> {
                fields.exact("objectId", "expiresAt"); yield new ServerControlOperation.IssueCapability(
                        fields.pkiId("objectId"), fields.instant("expiresAt"));
            }
            case ServerControlOperation.RevokeCapability.NAME -> {
                fields.exact("capabilityId"); yield new ServerControlOperation.RevokeCapability(fields.text("capabilityId"));
            }
            case ServerControlOperation.InspectAuditView.REDACTED,
                    ServerControlOperation.InspectAuditView.FULL,
                    ServerControlOperation.InspectAuditView.PII -> {
                fields.allowed(Set.of("objectId", "reasonReference"));
                Permission.DataView view = id.equals(ServerControlOperation.InspectAuditView.REDACTED)
                        ? Permission.DataView.METADATA_REDACTED
                        : id.equals(ServerControlOperation.InspectAuditView.FULL)
                                ? Permission.DataView.METADATA_FULL : Permission.DataView.PII_FULL;
                yield new ServerControlOperation.InspectAuditView(fields.pkiId("objectId"), view,
                        fields.optionalText("reasonReference"));
            }
            case ServerControlOperation.InspectRepositoryAlias.NAME -> {
                fields.exact("authorityId", "type");
                yield new ServerControlOperation.InspectRepositoryAlias(fields.pkiId("authorityId"),
                        RepositoryAliasService.Type.valueOf(fields.text("type")));
            }
            case ServerControlOperation.ListRepositoryAliases.NAME -> {
                fields.exact("offset", "limit");
                yield new ServerControlOperation.ListRepositoryAliases(fields.integer("offset"),
                        fields.integer("limit"));
            }
            case ServerControlOperation.SetRepositoryAlias.NAME -> {
                fields.allowed(Set.of("authorityId", "type", "targetObjectId", "issuerId",
                        "expectedCurrentCommitment"));
                yield new ServerControlOperation.SetRepositoryAlias(fields.pkiId("authorityId"),
                        RepositoryAliasService.Type.valueOf(fields.text("type")),
                        fields.pkiId("targetObjectId"), fields.optionalText("issuerId").map(PkiId::new),
                        fields.optionalText("expectedCurrentCommitment"));
            }
            case ServerControlOperation.RemoveRepositoryAlias.NAME -> {
                fields.exact("authorityId", "type", "expectedCurrentCommitment");
                yield new ServerControlOperation.RemoveRepositoryAlias(fields.pkiId("authorityId"),
                        RepositoryAliasService.Type.valueOf(fields.text("type")),
                        fields.text("expectedCurrentCommitment"));
            }
            case ServerControlOperation.RegisterAcmeDirectory.NAME -> {
                fields.allowed(Set.of("alias", "authorityId", "profileId", "dnsNamespaces",
                        "maximumValidityMillis", "publicKeyAlgorithms", "x509BindingPolicies",
                        "challengeTypes", "challengeProviderIds", "eabProviderId", "eabRequired"));
                yield new ServerControlOperation.RegisterAcmeDirectory(new AcmeService.DirectoryRegistration(
                        fields.text("alias"), fields.pkiId("authorityId"), fields.text("profileId"),
                        fields.stringSet("dnsNamespaces"), Duration.ofMillis(fields.longValue("maximumValidityMillis")),
                        fields.stringSet("publicKeyAlgorithms"), fields.stringSet("x509BindingPolicies"),
                        fields.enumSet("challengeTypes", AcmeState.ChallengeType.class),
                        fields.stringSet("challengeProviderIds"), fields.optionalText("eabProviderId"),
                        fields.bool("eabRequired")));
            }
            case ServerControlOperation.InspectAcmeDirectory.NAME -> {
                fields.exact("directoryId"); yield new ServerControlOperation.InspectAcmeDirectory(
                        fields.text("directoryId"));
            }
            case ServerControlOperation.ListAcmeDirectories.NAME -> {
                fields.exact("offset", "limit"); yield new ServerControlOperation.ListAcmeDirectories(
                        fields.integer("offset"), fields.integer("limit"));
            }
            case ServerControlOperation.SetAcmeDirectoryActive.ACTIVATE,
                    ServerControlOperation.SetAcmeDirectoryActive.DEACTIVATE -> {
                fields.exact("directoryId"); yield new ServerControlOperation.SetAcmeDirectoryActive(
                        fields.text("directoryId"), id.equals(ServerControlOperation.SetAcmeDirectoryActive.ACTIVATE));
            }
            case ServerControlOperation.InspectAcmeAccount.NAME -> {
                fields.exact("accountId"); yield new ServerControlOperation.InspectAcmeAccount(fields.text("accountId"));
            }
            case ServerControlOperation.ListAcmeAccounts.NAME -> {
                fields.exact("offset", "limit"); yield new ServerControlOperation.ListAcmeAccounts(
                        fields.integer("offset"), fields.integer("limit"));
            }
            case ServerControlOperation.DeactivateAcmeAccount.NAME -> {
                fields.exact("accountId"); yield new ServerControlOperation.DeactivateAcmeAccount(fields.text("accountId"));
            }
            case ServerControlOperation.RegisterOcspResponder.NAME -> {
                fields.allowed(Set.of("responderId", "alias", "authorityId", "issuerId", "signingMode",
                        "responderCredentialId", "signingKeyRef", "chainPathId", "signatureAlgorithm",
                        "signatureBindingId", "signatureBindingCommitment", "responderIdForm",
                        "responseValidityMillis", "noncePolicy", "maximumNonceBytes", "acceptedHashes",
                        "maximumRequestBytes", "maximumEntries", "cacheLifetimeMillis",
                        "requestAuthenticationMode", "requesterTrustPolicy"));
                OcspResponderService.RequestAuthenticationMode authenticationMode =
                        OcspResponderService.RequestAuthenticationMode.valueOf(
                                fields.text("requestAuthenticationMode"));
                Optional<OcspResponderService.RequesterTrustPolicy> trustPolicy = fields.contains(
                        "requesterTrustPolicy") ? Optional.of(requesterTrustPolicy(
                                fields.object("requesterTrustPolicy"))) : Optional.empty();
                yield new ServerControlOperation.RegisterOcspResponder(new OcspResponderService.Registration(
                        fields.text("responderId"), fields.text("alias"),
                        fields.pkiId("authorityId"), fields.pkiId("issuerId"),
                        OcspResponderService.SigningMode.valueOf(fields.text("signingMode")),
                        fields.pkiId("responderCredentialId"), new KeyRef(fields.text("signingKeyRef")),
                        fields.pkiId("chainPathId"), fields.text("signatureAlgorithm"),
                        fields.optionalText("signatureBindingId"), fields.text("signatureBindingCommitment"),
                        OcspResponseService.ResponderId.valueOf(fields.text("responderIdForm")),
                        Duration.ofMillis(fields.longValue("responseValidityMillis")),
                        OcspResponderService.NoncePolicy.valueOf(fields.text("noncePolicy")),
                        fields.integer("maximumNonceBytes"),
                        fields.enumSet("acceptedHashes", OcspResponseService.CertIdHash.class),
                        fields.integer("maximumRequestBytes"), fields.integer("maximumEntries"),
                        Duration.ofMillis(fields.longValue("cacheLifetimeMillis")), authenticationMode,
                        trustPolicy));
            }
            case ServerControlOperation.InspectOcspResponder.NAME -> {
                fields.exact("responderId"); yield new ServerControlOperation.InspectOcspResponder(fields.text("responderId"));
            }
            case ServerControlOperation.ListOcspResponders.NAME -> {
                fields.exact("offset", "limit"); yield new ServerControlOperation.ListOcspResponders(
                        fields.integer("offset"), fields.integer("limit"));
            }
            case ServerControlOperation.SetOcspResponderActive.ACTIVATE,
                    ServerControlOperation.SetOcspResponderActive.DEACTIVATE -> {
                fields.exact("responderId"); yield new ServerControlOperation.SetOcspResponderActive(
                        fields.text("responderId"), id.equals(ServerControlOperation.SetOcspResponderActive.ACTIVATE));
            }
            case ServerControlOperation.SearchAudit.NAME -> {
                fields.allowed(Set.of("category", "action", "after", "before", "objectId", "principalName", "limit"));
                yield new ServerControlOperation.SearchAudit(new zeroecho.pki.api.audit.AuditQuery(
                        fields.optionalText("category"), fields.optionalText("action"),
                        fields.optionalText("after").map(HttpOperationCodec::instant),
                        fields.optionalText("before").map(HttpOperationCodec::instant),
                        fields.optionalText("objectId").map(PkiId::new), fields.optionalText("principalName"),
                        java.util.Map.of(), fields.integer("limit")));
            }
            case ServerControlOperation.VerifyAuditIntegrity.NAME -> {
                fields.allowed(Set.of("sequence", "recordHash"));
                Optional<zeroecho.pki.api.audit.AuditChainHead> head =
                        fields.contains("sequence") || fields.contains("recordHash")
                                ? Optional.of(new zeroecho.pki.api.audit.AuditChainHead(
                                        fields.longValue("sequence"), fields.text("recordHash")))
                                : Optional.empty();
                yield new ServerControlOperation.VerifyAuditIntegrity(head);
            }
            default -> throw new SecurityException("Control operation is not exposed");
        };
    }

    private static Permission.Scope controlScope(ServerControlOperation operation, RealmId realmId,
            Optional<PkiId> authority) {
        return switch (operation) {
            case ServerControlOperation.CreateRoleAssignment value -> value.assignment().scope();
            case ServerControlOperation.CreateGrant value -> value.grant().scope();
            case ServerControlOperation.EvaluateAuthorization value -> value.resource().scope();
            case ServerControlOperation.RequestApproval value -> value.targetResource().scope();
            case ServerControlOperation.CreateBreakGlass value -> value.grant().scope();
            case ServerControlOperation.EnrollCredentialPublication ignored -> {
                if (authority.isPresent()) {
                    throw new IllegalArgumentException("Credential publication resolves authority from issuance");
                }
                yield new Permission.Scope(realmId, Optional.empty(), Optional.empty(), Optional.empty());
            }
            case ServerControlOperation.InspectRepositoryAlias value -> authorityScope(realmId, authority,
                    value.authorityId());
            case ServerControlOperation.SetRepositoryAlias value -> authorityScope(realmId, authority,
                    value.authorityId());
            case ServerControlOperation.RemoveRepositoryAlias value -> authorityScope(realmId, authority,
                    value.authorityId());
            case ServerControlOperation.RegisterAcmeDirectory value -> authorityScope(realmId, authority,
                    value.registration().authorityId());
            case ServerControlOperation.RegisterOcspResponder value -> new Permission.Scope(realmId,
                    Optional.of(value.registration().authorityId()), Optional.of(value.registration().issuerId()),
                    Optional.empty());
            default -> new Permission.Scope(realmId, authority, Optional.empty(), Optional.empty());
        };
    }

    private static Optional<PkiId> controlObject(ServerControlOperation operation) {
        return switch (operation) {
            case ServerControlOperation.InspectDisclosure value -> Optional.of(value.objectId());
            case ServerControlOperation.SetDisclosure value -> Optional.of(value.objectId());
            case ServerControlOperation.EnrollCredentialPublication value -> Optional.of(value.credentialId());
            case ServerControlOperation.IssueCapability value -> Optional.of(value.objectId());
            case ServerControlOperation.InspectAuditView value -> Optional.of(value.objectId());
            case ServerControlOperation.SetRepositoryAlias value -> Optional.of(value.targetObjectId());
            default -> Optional.empty();
        };
    }

    private static Permission.Scope authorityScope(RealmId realmId, Optional<PkiId> requested,
            PkiId embedded) {
        if (requested.isEmpty() || !requested.orElseThrow().equals(embedded)) {
            throw new IllegalArgumentException("Repository alias and authority scope differ");
        }
        return new Permission.Scope(realmId, requested, Optional.empty(), Optional.empty());
    }

    private static boolean realmWide(PkiOperation operation) {
        return operation instanceof PkiOperation.ListAuthorities
                || operation instanceof PkiOperation.CreateAuthority
                || operation instanceof PkiOperation.ListAlgorithmBindings
                || operation instanceof PkiOperation.InspectAlgorithmBinding
                || operation instanceof PkiOperation.InspectRequest
                || operation instanceof PkiOperation.ImportRequest
                || operation instanceof PkiOperation.VerifyRequest
                || operation instanceof PkiOperation.RegisterProfile
                || operation instanceof PkiOperation.ValidateConfiguration
                || operation instanceof PkiOperation.ValidateProfile
                || operation instanceof PkiOperation.ValidateAlgorithmBindings
                || operation instanceof PkiOperation.SnapshotRevocations
                || operation instanceof PkiOperation.InspectStatus
                || operation instanceof PkiOperation.ListPublications
                || operation instanceof PkiOperation.InspectIssuerGeneration
                || operation instanceof PkiOperation.InspectIssuerChainPath
                || operation instanceof PkiOperation.ListIssuerChainPaths;
    }

    private static void validateAuthority(PkiOperation operation, Optional<PkiId> authority) {
        Optional<PkiId> embedded = switch (operation) {
            case PkiOperation.InspectAuthority value -> Optional.of(value.caId());
            case PkiOperation.TransitionAuthority value -> Optional.of(value.caId());
            case PkiOperation.IssueCredential value -> Optional.of(value.issuerCaId());
            case PkiOperation.GenerateStatus value -> Optional.of(value.issuerCaId());
            case PkiOperation.ListStatus value -> Optional.of(value.issuerCaId());
            case PkiOperation.ListPendingCredentialConfirmations value -> Optional.of(value.authorityId());
            case PkiOperation.RolloverCaCertificate value -> Optional.of(value.caId());
            case PkiOperation.RotateCaKey value -> Optional.of(value.caId());
            case PkiOperation.CreateIntermediate value -> Optional.of(value.issuerCaId());
            case PkiOperation.IssueIntermediateCertificate value -> Optional.of(value.issuerCaId());
            case PkiOperation.SelectIssuancePath value -> Optional.of(value.caId());
            case PkiOperation.RegisterIssuerChainPath value -> Optional.of(value.caId());
            default -> Optional.empty();
        };
        if (embedded.isPresent() && !embedded.equals(authority)) {
            throw new IllegalArgumentException("Operation and authority scope differ");
        }
    }

    private static Optional<String> profile(PkiOperation operation) {
        return switch (operation) {
            case PkiOperation.ListProfileVersions value -> Optional.of(value.profileId());
            case PkiOperation.InspectProfile value -> Optional.of(value.profileId());
            case PkiOperation.ActivateProfile value -> Optional.of(value.profileId());
            case PkiOperation.IssueCredential value -> Optional.of(value.profileId());
            case PkiOperation.ReplaceCredential value -> Optional.of(value.profileId());
            case PkiOperation.CreateIntermediate value -> Optional.of(value.profileId());
            case PkiOperation.IssueIntermediateCertificate value -> Optional.of(value.profileId());
            case PkiOperation.ListPendingCredentialConfirmations value -> value.profileId();
            default -> Optional.empty();
        };
    }

    private static Optional<PkiId> objectId(PkiOperation operation) {
        return switch (operation) {
            case PkiOperation.InspectAuthority value -> Optional.of(value.caId());
            case PkiOperation.TransitionAuthority value -> Optional.of(value.caId());
            case PkiOperation.InspectCredential value -> Optional.of(value.credentialId());
            case PkiOperation.IssueCredentialConfirmationChallenge value -> Optional.of(value.credentialId());
            case PkiOperation.CompleteCredentialConfirmationProof value ->
                Optional.of(value.submission().proofCas().credentialId());
            case PkiOperation.RevokePendingCredentialConfirmation value ->
                Optional.of(value.credentialId());
            case PkiOperation.RevokeCredential value -> Optional.of(value.credentialId());
            case PkiOperation.RenewCredential value -> Optional.of(value.credentialId());
            case PkiOperation.ReplaceCredential value -> Optional.of(value.existingCredentialId());
            case PkiOperation.ReissueCredential value -> Optional.of(value.credentialId());
            case PkiOperation.RolloverCaCertificate value -> Optional.of(value.caId());
            case PkiOperation.RotateCaKey value -> Optional.of(value.caId());
            case PkiOperation.InspectRequest value -> Optional.of(value.requestId());
            case PkiOperation.VerifyRequest value -> Optional.of(value.requestId());
            case PkiOperation.ReadRevocationHistory value -> Optional.of(value.credentialId());
            case PkiOperation.InspectPublication value -> Optional.of(value.publicationId());
            case PkiOperation.ProcessPublication value -> Optional.of(value.publicationId());
            case PkiOperation.InspectRevocation value -> Optional.of(value.credentialId());
            case PkiOperation.InspectStatus value -> Optional.of(value.statusObjectId());
            case PkiOperation.RegisterPublication value -> Optional.of(value.publicationId());
            case PkiOperation.RetryPublication value -> Optional.of(value.publicationId());
            case PkiOperation.ReconcilePublication value -> Optional.of(value.publicationId());
            case PkiOperation.IssueIntermediateCertificate value -> Optional.of(value.subjectCaId());
            case PkiOperation.InspectIssuerGeneration value -> Optional.of(value.issuerId());
            case PkiOperation.InspectIssuerChainPath value -> Optional.of(value.pathId());
            case PkiOperation.ListIssuerChainPaths value -> Optional.of(value.issuerId());
            case PkiOperation.SelectIssuancePath value -> Optional.of(value.caId());
            case PkiOperation.RegisterIssuerChainPath value -> Optional.of(value.caId());
            default -> Optional.empty();
        };
    }

    private static Optional<String> operatorJustification(PkiOperation operation) {
        return switch (operation) {
            case PkiOperation.RevokeCredential value -> value.operatorJustification();
            case PkiOperation.RevokePendingCredentialConfirmation value ->
                value.operatorJustification();
            case PkiOperation.TransitionAuthority value -> Optional.of(value.reason());
            default -> Optional.empty();
        };
    }

    private static CredentialConfirmationProofSubmission proofSubmission(
            CredentialConfirmationProofCas proofCas, String encodedResponse) {
        Objects.requireNonNull(encodedResponse, "response");
        if (encodedResponse.isEmpty()
                || encodedResponse.length()
                        > PkiServerConfiguration.Listener.MAXIMUM_PROOF_RESPONSE_BASE64URL_CHARACTERS
                || !encodedResponse.matches("[A-Za-z0-9_-]+")) {
            throw new IllegalArgumentException("Proof response is not canonical unpadded Base64url");
        }
        byte[] decoded;
        try {
            decoded = Base64.getUrlDecoder().decode(encodedResponse);
        } catch (IllegalArgumentException malformed) {
            throw new IllegalArgumentException("Proof response is not canonical unpadded Base64url", malformed);
        }
        try {
            if (decoded.length > zeroecho.pki.spi.confirmation.KeyPossessionProofResponse.MAXIMUM_BYTES
                    || !encodedResponse.equals(Base64.getUrlEncoder().withoutPadding().encodeToString(decoded))) {
                throw new IllegalArgumentException("Proof response is not canonical unpadded Base64url");
            }
            return new CredentialConfirmationProofSubmission(proofCas, decoded);
        } finally {
            Arrays.fill(decoded, (byte) 0);
        }
    }

    private static Optional<zeroecho.pki.api.Validity> requestedValidity(Fields fields) {
        boolean hasBefore = fields.contains("notBefore");
        boolean hasAfter = fields.contains("notAfter");
        if (hasBefore != hasAfter) {
            throw new IllegalArgumentException("notBefore and notAfter must be supplied together");
        }
        if (!hasBefore) {
            return Optional.empty();
        }
        return Optional.of(new zeroecho.pki.api.Validity(instant(fields.text("notBefore")),
                instant(fields.text("notAfter"))));
    }

    private static java.time.Instant instant(String value) {
        java.time.Instant parsed = java.time.Instant.parse(value);
        if (!parsed.toString().equals(value) || parsed.getEpochSecond() < 0L
                || parsed.getEpochSecond() > 253_402_300_799L) {
            throw new IllegalArgumentException("Instant is not canonical or supported");
        }
        return parsed;
    }

    private static OcspResponderService.RequesterTrustPolicy requesterTrustPolicy(Fields fields) {
        fields.exact("trustSelectors", "principalMappings", "signatureBindings", "revocationPolicy",
                "maximumSignerCertificates", "maximumSignerChainBytes");
        List<OcspResponderService.TrustSelector> selectors = fields.objects("trustSelectors").stream()
                .map(value -> {
                    value.exact("type", "identities");
                    return new OcspResponderService.TrustSelector(
                            OcspResponderService.TrustSelectorType.valueOf(value.text("type")),
                            value.stringSet("identities"));
                }).toList();
        List<OcspResponderService.PrincipalMapping> mappings = fields.objects("principalMappings").stream()
                .map(value -> {
                    value.exact("mappingId", "principalId", "type", "commitment");
                    return new OcspResponderService.PrincipalMapping(value.text("mappingId"),
                            value.text("principalId"), OcspResponderService.PrincipalMappingType.valueOf(
                                    value.text("type")), value.text("commitment"));
                }).toList();
        List<OcspResponderService.RequestSignatureBinding> bindings = fields.objects("signatureBindings").stream()
                .map(value -> {
                    value.exact("bindingId", "commitment");
                    return new OcspResponderService.RequestSignatureBinding(value.text("bindingId"),
                            value.text("commitment"));
                }).toList();
        return new OcspResponderService.RequesterTrustPolicy(selectors, mappings, bindings,
                OcspResponderService.RequesterRevocationPolicy.valueOf(fields.text("revocationPolicy")),
                fields.integer("maximumSignerCertificates"), fields.integer("maximumSignerChainBytes"));
    }

    private static Duration duration(String value) {
        try {
            Duration result = Duration.parse(value);
            if (result.isZero() || result.isNegative()) throw new IllegalArgumentException("Deadline is invalid");
            return result;
        } catch (java.time.format.DateTimeParseException failure) {
            throw new IllegalArgumentException("Deadline is invalid");
        }
    }

    private static void requireId(String value, String name) {
        if (value == null || !value.matches("[a-zA-Z0-9][a-zA-Z0-9._:-]{0,255}")) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }

    private static final class Fields {
        private final Map<String, PkiOperationValue> fields;
        private final Set<String> consumed = new LinkedHashSet<>();
        private Fields(Map<String, PkiOperationValue> fields) { this.fields = fields; }
        static Fields of(PkiOperationValue value) {
            if (!(value instanceof PkiOperationValue.ObjectValue object)) {
                throw new IllegalArgumentException("Request value must be an object");
            }
            return new Fields(object.fields());
        }
        void exact(String... names) { allowed(Set.of(names)); if (fields.size() != names.length)
            throw new IllegalArgumentException("Request fields are incomplete"); }
        void allowed(Set<String> names) { if (!names.containsAll(fields.keySet()))
            throw new IllegalArgumentException("Unknown request field"); }
        String text(String name) { consumed.add(name); PkiOperationValue value = require(name);
            if (!(value instanceof PkiOperationValue.Text text)) throw type(); return text.value(); }
        Optional<String> optionalText(String name) { return fields.containsKey(name)
            ? Optional.of(text(name)) : Optional.empty(); }
        boolean contains(String name) { return fields.containsKey(name); }
        long longValue(String name) { consumed.add(name); PkiOperationValue value = require(name);
            if (!(value instanceof PkiOperationValue.IntegerValue integer)) throw type(); return integer.value(); }
        int integer(String name) { return Math.toIntExact(longValue(name)); }
        boolean bool(String name) { consumed.add(name); PkiOperationValue value = require(name);
            if (!(value instanceof PkiOperationValue.BooleanValue bool)) throw type(); return bool.value(); }
        PkiId pkiId(String name) { return new PkiId(text(name)); }
        Instant instant(String name) { try { return Instant.parse(text(name)); }
            catch (java.time.format.DateTimeParseException failure) { throw type(); } }
        Optional<Instant> optionalInstant(String name) { return fields.containsKey(name)
            ? Optional.of(instant(name)) : Optional.empty(); }
        <E extends Enum<E>> Set<E> enumSet(String name, Class<E> type) {
            consumed.add(name); PkiOperationValue value = require(name);
            if (!(value instanceof PkiOperationValue.ListValue list)) throw type();
            Set<E> result = new LinkedHashSet<>();
            for (PkiOperationValue item : list.values()) {
                if (!(item instanceof PkiOperationValue.Text text) || !result.add(Enum.valueOf(type, text.value()))) {
                    throw type();
                }
            }
            return Set.copyOf(result);
        }
        Set<String> stringSet(String name) {
            consumed.add(name); PkiOperationValue value = require(name);
            if (!(value instanceof PkiOperationValue.ListValue list)) throw type();
            Set<String> result = new LinkedHashSet<>();
            for (PkiOperationValue item : list.values()) {
                if (!(item instanceof PkiOperationValue.Text text) || !result.add(text.value())) throw type();
            }
            return Set.copyOf(result);
        }
        Fields object(String name) { consumed.add(name); return of(require(name)); }
        List<Fields> objects(String name) {
            consumed.add(name); PkiOperationValue value = require(name);
            if (!(value instanceof PkiOperationValue.ListValue list)) throw type();
            return list.values().stream().map(Fields::of).toList();
        }
        void complete() { if (!Objects.equals(consumed, fields.keySet()))
            throw new IllegalArgumentException("Request fields were not consumed"); }
        private PkiOperationValue require(String name) { PkiOperationValue value = fields.get(name);
            if (value == null) throw new IllegalArgumentException("Required request field is missing"); return value; }
        private static IllegalArgumentException type() {
            return new IllegalArgumentException("Request field type is invalid");
        }
    }
}
