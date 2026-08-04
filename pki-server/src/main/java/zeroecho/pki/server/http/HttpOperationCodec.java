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

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.OperationSecurityDescriptors;
import zeroecho.pki.server.AdministrativeOperation;
import zeroecho.pki.server.ApprovalService;
import zeroecho.pki.server.DisclosureService;
import zeroecho.pki.server.Permission;
import zeroecho.pki.server.RealmId;
import zeroecho.pki.server.RepositoryAliasService;
import zeroecho.pki.server.RoleTemplateCatalog;
import zeroecho.pki.server.SecurityPrincipal;
import zeroecho.pki.server.ServerControlOperation;

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
            PkiOperation pki = operation(operationId, arguments);
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
        Optional<String> reason = operation instanceof AdministrativeOperation.Pki pki
                && pki.operation() instanceof PkiOperation.TransitionAuthority transition
                ? Optional.of(transition.reason()) : Optional.empty();
        Permission.Context context = new Permission.Context(reason, approval.isPresent(), false, Map.of());
        return new Decoded(operation, resource, context, approval, deadline);
    }

    private static PkiOperation operation(String id, Fields fields) {
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
            case PkiOperation.IssueCredential.NAME -> {
                fields.exact("issuerCaId", "requestId", "profileId");
                yield new PkiOperation.IssueCredential(fields.pkiId("issuerCaId"), fields.pkiId("requestId"),
                        fields.text("profileId"));
            }
            case PkiOperation.RevokeCredential.NAME -> {
                fields.exact("credentialId", "reason");
                yield new PkiOperation.RevokeCredential(fields.pkiId("credentialId"),
                        RevocationReason.valueOf(fields.text("reason")));
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
            case PkiOperation.ListAlgorithmBindings.NAME -> {
                fields.allowed(Set.of("origin", "role", "limit"));
                yield new PkiOperation.ListAlgorithmBindings(fields.optionalText("origin"),
                        fields.optionalText("role"), fields.integer("limit"));
            }
            case PkiOperation.InspectAlgorithmBinding.NAME -> {
                fields.exact("bindingId");
                yield new PkiOperation.InspectAlgorithmBinding(fields.text("bindingId"));
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
                        "issuerId", "profileId", "relationship", "dataView", "conditions", "expiresAt"));
                Permission.Scope scope = new Permission.Scope(realmId, authority,
                        fields.optionalText("issuerId").map(PkiId::new), fields.optionalText("profileId"));
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
                    PkiOperation targetPki = operation(targetId, targetFields);
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
            case ServerControlOperation.InspectRepositoryAlias value -> authorityScope(realmId, authority,
                    value.authorityId());
            case ServerControlOperation.SetRepositoryAlias value -> authorityScope(realmId, authority,
                    value.authorityId());
            case ServerControlOperation.RemoveRepositoryAlias value -> authorityScope(realmId, authority,
                    value.authorityId());
            default -> new Permission.Scope(realmId, authority, Optional.empty(), Optional.empty());
        };
    }

    private static Optional<PkiId> controlObject(ServerControlOperation operation) {
        return switch (operation) {
            case ServerControlOperation.InspectDisclosure value -> Optional.of(value.objectId());
            case ServerControlOperation.SetDisclosure value -> Optional.of(value.objectId());
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
                || operation instanceof PkiOperation.InspectAlgorithmBinding;
    }

    private static void validateAuthority(PkiOperation operation, Optional<PkiId> authority) {
        Optional<PkiId> embedded = switch (operation) {
            case PkiOperation.InspectAuthority value -> Optional.of(value.caId());
            case PkiOperation.TransitionAuthority value -> Optional.of(value.caId());
            case PkiOperation.IssueCredential value -> Optional.of(value.issuerCaId());
            case PkiOperation.GenerateStatus value -> Optional.of(value.issuerCaId());
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
            default -> Optional.empty();
        };
    }

    private static Optional<PkiId> objectId(PkiOperation operation) {
        return switch (operation) {
            case PkiOperation.InspectAuthority value -> Optional.of(value.caId());
            case PkiOperation.TransitionAuthority value -> Optional.of(value.caId());
            case PkiOperation.InspectCredential value -> Optional.of(value.credentialId());
            case PkiOperation.RevokeCredential value -> Optional.of(value.credentialId());
            case PkiOperation.ReadRevocationHistory value -> Optional.of(value.credentialId());
            case PkiOperation.InspectPublication value -> Optional.of(value.publicationId());
            case PkiOperation.ProcessPublication value -> Optional.of(value.publicationId());
            default -> Optional.empty();
        };
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
        Fields object(String name) { consumed.add(name); return of(require(name)); }
        void complete() { if (!Objects.equals(consumed, fields.keySet()))
            throw new IllegalArgumentException("Request fields were not consumed"); }
        private PkiOperationValue require(String name) { PkiOperationValue value = fields.get(name);
            if (value == null) throw new IllegalArgumentException("Required request field is missing"); return value; }
        private static IllegalArgumentException type() {
            return new IllegalArgumentException("Request field type is invalid");
        }
    }
}
