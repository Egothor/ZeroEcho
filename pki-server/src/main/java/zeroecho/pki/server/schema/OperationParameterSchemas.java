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
package zeroecho.pki.server.schema;

import java.util.List;

import zeroecho.pki.server.schema.OperationParameterSchema.FieldSpec;
import zeroecho.pki.server.schema.OperationParameterSchema.OperationSpec;

/** Complete registry of machine-readable operation parameter schemas derived from the codec. */
@SuppressWarnings("PMD.AvoidDuplicateLiterals")
public final class OperationParameterSchemas {

    private static final List<String> CA_STATE = java.util.Arrays.stream(zeroecho.pki.api.ca.CaState.values()).map(Enum::name).toList();

    private static final List<String> CREDENTIAL_STATUS = java.util.Arrays.stream(zeroecho.pki.api.credential.CredentialStatus.values()).map(Enum::name).toList();

    private static final List<String> REVOCATION_REASON = java.util.Arrays.stream(zeroecho.pki.api.revocation.RevocationReason.values()).map(Enum::name).toList();

    private static final List<String> STATUS_OBJECT_TYPE = java.util.Arrays.stream(zeroecho.pki.api.status.StatusObjectType.values()).map(Enum::name).toList();

    private static final List<String> PUBLICATION_SOURCE_TYPE = java.util.Arrays.stream(zeroecho.pki.api.publication.PublicationSourceType.values()).map(Enum::name).toList();

    private static final List<String> PUBLICATION_TARGET_TYPE = java.util.Arrays.stream(zeroecho.pki.api.publication.PublicationTargetType.values()).map(Enum::name).toList();

    private static final List<String> PRINCIPAL_TYPE = java.util.Arrays.stream(zeroecho.pki.server.SecurityPrincipal.Type.values()).map(Enum::name).toList();

    private static final List<String> PERMISSION_EFFECT = java.util.Arrays.stream(
            zeroecho.pki.server.Permission.Effect.values()).map(Enum::name).toList();

    private static final List<String> PERMISSION_ACTION = java.util.Arrays.stream(
            zeroecho.pki.server.Permission.Action.values()).map(Enum::name).toList();

    private static final List<String> PERMISSION_RESOURCE_TYPE = java.util.Arrays.stream(
            zeroecho.pki.server.Permission.ResourceType.values()).map(Enum::name).toList();

    private static final List<String> PERMISSION_RELATIONSHIP = java.util.Arrays.stream(
            zeroecho.pki.server.Permission.Relationship.values()).map(Enum::name).toList();

    private static final List<String> PERMISSION_DATA_VIEW = java.util.Arrays.stream(
            zeroecho.pki.server.Permission.DataView.values()).map(Enum::name).toList();

    private static final List<String> PERMISSION_CONDITION = java.util.Arrays.stream(
            zeroecho.pki.server.Permission.Condition.values()).map(Enum::name).toList();

    private static final List<String> APPROVAL_STATE = List.of("PENDING", "APPROVED", "REJECTED", "EXPIRED");

    private static final List<String> DISCLOSURE_POLICY = List.of(
            "PUBLIC", "PUBLIC_UNLISTED", "AUTHENTICATED", "OWNER_ONLY");

    private static final List<String> REPOSITORY_ALIAS_TYPE = List.of(
            "CURRENT_CRL", "CURRENT_CHAIN", "CURRENT_DELTA_CRL");

    private static final List<String> ACME_CHALLENGE_TYPE = List.of("HTTP_01", "DNS_01");

    private static final List<String> OCSP_SIGNING_MODE = List.of("ISSUER_SIGNED", "DELEGATED_RESPONDER");

    private static final List<String> OCSP_RESPONDER_ID_FORM = List.of("BY_NAME", "BY_KEY");

    private static final List<String> OCSP_NONCE_POLICY = List.of("REJECT", "OPTIONAL_ECHO", "REQUIRED");

    private static final List<String> OCSP_CERT_ID_HASH = List.of("SHA1", "SHA256");

    private static final List<String> OCSP_REQUEST_AUTH_MODE = List.of(
            "UNSIGNED_ONLY", "UNSIGNED_OR_AUTHORIZED_SIGNED", "AUTHORIZED_SIGNED_REQUIRED");

    private static final List<String> CMP_PROTECTION_POLICY = List.of(
            "SIGNATURE_BASED", "SHARED_SECRET_MAC");

    private static final List<String> ENROLLMENT_PROFILE_STATE = List.of("ACTIVE", "SUSPENDED");

    /** Returns the complete catalog projection, including explicitly unavailable operations.
     * @return immutable schemas in canonical identity order
     */
    public static List<OperationSpec> all() {
        return OperationDescriptorCatalog.current().parameterSchemas();
    }

    /** Immutable parameter definition before permissions are joined from security metadata.
     * @param operationId stable operation identity
     * @param fields immutable argument definitions
     */
    public record Parameters(String operationId, List<FieldSpec> fields) {
        /** Copies the field list. */
        public Parameters { fields = List.copyOf(fields); }
    }

    /** Returns pure parameter definitions for catalog assembly.
     * @return ordered current parameter definitions
     */
    public static List<Parameters> definitions() {
        return List.of(
                // ─── PKI operations ───────────────────────────────────────────────────────
                op("ca.list",
                        FieldSpec.integer("limit", true), FieldSpec.text("after", false)),
                op("ca.inspect",
                        FieldSpec.text("caId", true)),
                op("ca.transition",
                        FieldSpec.text("caId", true),
                        FieldSpec.enum_("state", true, CA_STATE),
                        FieldSpec.text("reason", true)),
                op("profile.list-all",
                        FieldSpec.integer("limit", true), FieldSpec.text("after", false)),
                op("request.list",
                        FieldSpec.integer("limit", true), FieldSpec.text("after", false)),
                op("credential.search",
                        FieldSpec.integer("limit", true), FieldSpec.text("after", false),
                        FieldSpec.text("subjectFilter", false), FieldSpec.text("serialFilter", false),
                        FieldSpec.text("fingerprintFilter", false),
                        FieldSpec.enum_("statusFilter", false, CREDENTIAL_STATUS),
                        FieldSpec.text("profileIdFilter", false)),
                op("issuer.generation.list",
                        FieldSpec.integer("limit", true), FieldSpec.text("after", false)),
                op("profile.list",
                        FieldSpec.text("profileId", true)),
                op("profile.inspect",
                        FieldSpec.text("profileId", true), FieldSpec.integer("profileVersion", true)),
                op("profile.activate",
                        FieldSpec.text("profileId", true), FieldSpec.integer("profileVersion", true)),
                op("credential.inspect",
                        FieldSpec.text("credentialId", true)),
                op("credential.confirmation.pending.list",
                        FieldSpec.text("profileId", false),
                        FieldSpec.text("cutoffInclusive", true),
                        FieldSpec.text("afterExclusive", false),
                        FieldSpec.integer("limit", true)),
                op("credential.confirmation.challenge.issue",
                        FieldSpec.text("credentialId", true)),
                op("credential.confirmation.proof.complete",
                        FieldSpec.text("credentialId", true),
                        FieldSpec.integer("expectedLifecycleRevision", true),
                        FieldSpec.text("expectedLifecycleRecordCommitment", true),
                        FieldSpec.text("expectedChallengeRecordCommitment", true),
                        FieldSpec.text("response", true)),
                op("credential.confirmation.pending.revoke",
                        FieldSpec.text("credentialId", true), FieldSpec.text("justification", false)),
                op("credential.revoke",
                        FieldSpec.text("credentialId", true),
                        FieldSpec.enum_("reason", true, REVOCATION_REASON),
                        FieldSpec.text("justification", false)),
                op("revocation.history",
                        FieldSpec.text("credentialId", true), FieldSpec.integer("limit", true)),
                op("publication.inspect",
                        FieldSpec.text("publicationId", true)),
                op("publication.process",
                        FieldSpec.text("publicationId", true)),
                op("revocation.inspect",
                        FieldSpec.text("credentialId", true)),
                op("revocation.snapshot",
                        FieldSpec.integer("limit", true)),
                op("status.inspect",
                        FieldSpec.text("statusObjectId", true)),
                op("inventory.status",
                        FieldSpec.text("issuerCaId", true),
                        FieldSpec.integer("limit", true),
                        FieldSpec.text("after", false)),
                op("publication.list",
                        FieldSpec.integer("limit", true), FieldSpec.text("after", false)),
                op("publication.register",
                        FieldSpec.text("publicationId", true),
                        FieldSpec.enum_("sourceType", true, PUBLICATION_SOURCE_TYPE),
                        FieldSpec.text("sourceId", true),
                        FieldSpec.enum_("targetType", true, PUBLICATION_TARGET_TYPE),
                        FieldSpec.text("targetId", true)),
                op("publication.retry",
                        FieldSpec.text("publicationId", true)),
                op("publication.reconcile",
                        FieldSpec.text("publicationId", true)),
                op("issuer.generation.inspect",
                        FieldSpec.text("issuerId", true)),
                op("issuer.path.inspect",
                        FieldSpec.text("pathId", true)),
                op("issuer.path.list",
                        FieldSpec.text("issuerId", true)),
                op("issuer.path.select",
                        FieldSpec.text("caId", true),
                        FieldSpec.text("issuerId", true),
                        FieldSpec.text("pathId", true),
                        FieldSpec.text("reason", true)),
                op("issuer.path.register",
                        FieldSpec.text("caId", true),
                        FieldSpec.text("issuerId", true),
                        FieldSpec.text("parentPathId", true)),
                op("algorithm.binding.list",
                        FieldSpec.text("origin", false),
                        FieldSpec.text("role", false),
                        FieldSpec.integer("limit", true),
                        FieldSpec.text("after", false)),
                op("algorithm.binding.inspect",
                        FieldSpec.text("bindingId", true)),
                op("request.inspect",
                        FieldSpec.text("requestId", true)),
                op("request.import",
                        FieldSpec.text("formatId", true), FieldSpec.base64("encoded", true)),
                op("request.verify",
                        FieldSpec.text("requestId", true)),
                op("profile.register",
                        FieldSpec.base64("document", true)),
                op("configuration.validate"),
                op("profile.validate",
                        FieldSpec.base64("document", true)),
                op("algorithm.binding.validate",
                        FieldSpec.text("bindingId", false),
                        FieldSpec.text("expectedCommitment", false)),
                // ─── Signing operations ───────────────────────────────────────────────────
                op("ca.create",
                        FieldSpec.text("formatId", true),
                        FieldSpec.text("subjectRef", true),
                        FieldSpec.text("profileId", true),
                        FieldSpec.text("keyRef", true)),
                op("credential.issue",
                        FieldSpec.text("issuerCaId", true),
                        FieldSpec.text("requestId", true),
                        FieldSpec.text("profileId", true)),
                op("credential.renew",
                        FieldSpec.text("credentialId", true)),
                op("credential.replace",
                        FieldSpec.text("existingCredentialId", true),
                        FieldSpec.text("requestId", true),
                        FieldSpec.text("profileId", true)),
                op("credential.reissue",
                        FieldSpec.text("credentialId", true)),
                op("ca.rollover",
                        FieldSpec.text("caId", true), FieldSpec.text("issuerCaId", false)),
                op("ca.rotate",
                        FieldSpec.text("caId", true),
                        FieldSpec.text("newKeyRef", false),
                        FieldSpec.text("issuerCaId", false)),
                op("status.generate",
                        FieldSpec.text("issuerCaId", true),
                        FieldSpec.enum_("type", true, STATUS_OBJECT_TYPE),
                        FieldSpec.text("formatId", true)),
                op("status.schedule.set",
                        FieldSpec.text("caId", true),
                        FieldSpec.enum_("statusType", true, List.of("CRL", "DELTA_CRL")),
                        FieldSpec.enum_("formatId", true, List.of("x509")),
                        FieldSpec.text("interval", true),
                        FieldSpec.integer("graceSeconds", true),
                        FieldSpec.bool("enabled", true),
                        FieldSpec.enum_("targetType", false, PUBLICATION_TARGET_TYPE),
                        FieldSpec.text("targetId", false)),
                op("status.schedule.inspect",
                        FieldSpec.text("caId", true),
                        FieldSpec.enum_("statusType", true, STATUS_OBJECT_TYPE)),
                op("status.schedule.list",
                        FieldSpec.integer("limit", true),
                        FieldSpec.text("after", false)),
                op("dashboard.authority",
                        FieldSpec.text("caId", true)),
                op("dashboard.certificate",
                        FieldSpec.text("caId", true)),
                op("dashboard.revocation",
                        FieldSpec.text("caId", true)),
                op("dashboard.publication",
                        FieldSpec.text("caId", true)),
                op("dashboard.server"),
                op("ca.intermediate.create",
                        FieldSpec.text("formatId", true),
                        FieldSpec.text("issuerCaId", true),
                        FieldSpec.text("subjectRef", true),
                        FieldSpec.text("profileId", true),
                        FieldSpec.text("keyRef", false)),
                op("ca.intermediate.issue",
                        FieldSpec.text("formatId", true),
                        FieldSpec.text("issuerCaId", true),
                        FieldSpec.text("subjectCaId", true),
                        FieldSpec.text("profileId", true),
                        FieldSpec.text("notBefore", false),
                        FieldSpec.text("notAfter", false)),
                // ─── Server-control operations ────────────────────────────────────────────
                op("security.principal.register",
                        FieldSpec.text("principalId", true),
                        FieldSpec.enum_("type", true, PRINCIPAL_TYPE),
                        FieldSpec.text("displayName", true),
                        FieldSpec.bool("enabled", true)),
                op("security.principal.inspect",
                        FieldSpec.text("principalId", true)),
                op("security.principal.list",
                        FieldSpec.integer("offset", true), FieldSpec.integer("limit", true)),
                op("security.principal.enable",
                        FieldSpec.text("principalId", true)),
                op("security.principal.disable",
                        FieldSpec.text("principalId", true)),
                op("security.role-template.list"),
                op("security.role-template.inspect",
                        FieldSpec.text("templateId", true), FieldSpec.integer("version", true)),
                op("security.role-assignment.create",
                        FieldSpec.text("assignmentId", true),
                        FieldSpec.text("principalId", true),
                        FieldSpec.text("templateId", true),
                        FieldSpec.integer("templateVersion", true),
                        FieldSpec.text("profileId", false),
                        FieldSpec.text("expiresAt", false)),
                op("security.role-assignment.inspect",
                        FieldSpec.text("assignmentId", true)),
                op("security.role-assignment.list",
                        FieldSpec.integer("offset", true), FieldSpec.integer("limit", true)),
                op("security.role-assignment.revoke",
                        FieldSpec.text("assignmentId", true)),
                op("security.grant.create",
                        FieldSpec.text("grantId", true),
                        FieldSpec.text("principalId", true),
                        FieldSpec.enum_("effect", true, PERMISSION_EFFECT),
                        FieldSpec.enum_("action", true, PERMISSION_ACTION),
                        FieldSpec.enum_("resourceType", true, PERMISSION_RESOURCE_TYPE),
                        FieldSpec.text("issuerId", false),
                        FieldSpec.text("profileId", false),
                        FieldSpec.text("responderId", false),
                        FieldSpec.enum_("relationship", true, PERMISSION_RELATIONSHIP),
                        FieldSpec.enum_("dataView", true, PERMISSION_DATA_VIEW),
                        FieldSpec.enumSet("conditions", false, PERMISSION_CONDITION),
                        FieldSpec.text("expiresAt", false)),
                op("security.grant.inspect",
                        FieldSpec.text("grantId", true)),
                op("security.grant.list",
                        FieldSpec.integer("offset", true), FieldSpec.integer("limit", true)),
                op("security.grant.revoke",
                        FieldSpec.text("grantId", true)),
                op("security.authorization.evaluate",
                        FieldSpec.text("principalId", true),
                        FieldSpec.enum_("action", true, PERMISSION_ACTION),
                        FieldSpec.enum_("resourceType", true, PERMISSION_RESOURCE_TYPE),
                        FieldSpec.enum_("relationship", true, PERMISSION_RELATIONSHIP),
                        FieldSpec.enum_("dataView", true, PERMISSION_DATA_VIEW)),
                op("security.approval.request",
                        FieldSpec.text("approvalId", true),
                        FieldSpec.text("targetOperation", true),
                        FieldSpec.object("targetArguments", true),
                        FieldSpec.text("targetAuthorityId", false)),
                op("security.approval.inspect",
                        FieldSpec.text("approvalId", true)),
                op("security.approval.list",
                        FieldSpec.integer("offset", true),
                        FieldSpec.integer("limit", true),
                        FieldSpec.enum_("state", false, APPROVAL_STATE),
                        FieldSpec.text("requesterPrincipalId", false),
                        FieldSpec.text("targetOperationId", false)),
                op("security.approval.approve",
                        FieldSpec.text("approvalId", true), FieldSpec.text("justification", true)),
                op("security.approval.reject",
                        FieldSpec.text("approvalId", true), FieldSpec.text("justification", true)),
                op("security.approval.cancel",
                        FieldSpec.text("approvalId", true)),
                op("security.break-glass.create",
                        FieldSpec.text("breakGlassId", true),
                        FieldSpec.text("principalId", true),
                        FieldSpec.text("grantId", true),
                        FieldSpec.enum_("action", true, PERMISSION_ACTION),
                        FieldSpec.enum_("resourceType", true, PERMISSION_RESOURCE_TYPE),
                        FieldSpec.text("reason", true),
                        FieldSpec.text("expiresAt", true)),
                op("security.break-glass.activate",
                        FieldSpec.text("breakGlassId", true)),
                op("security.break-glass.inspect",
                        FieldSpec.text("breakGlassId", true)),
                op("security.break-glass.list",
                        FieldSpec.integer("offset", true), FieldSpec.integer("limit", true)),
                op("security.break-glass.revoke",
                        FieldSpec.text("breakGlassId", true)),
                op("configuration.choices",
                        FieldSpec.integer("limit", true), FieldSpec.text("after", false)),
                op("security.disclosure.capability.list",
                        FieldSpec.text("objectId", true),
                        FieldSpec.integer("limit", true),
                        FieldSpec.text("after", false)),
                op("security.disclosure.inspect",
                        FieldSpec.text("objectId", true)),
                op("security.disclosure.set",
                        FieldSpec.text("objectId", true),
                        FieldSpec.enum_("policy", true, DISCLOSURE_POLICY)),
                op("certificate.publication.enroll",
                        FieldSpec.text("credentialId", true),
                        FieldSpec.text("ownerPrincipalId", false)),
                op("security.disclosure.capability.issue",
                        FieldSpec.text("objectId", true), FieldSpec.text("expiresAt", true)),
                op("security.disclosure.capability.revoke",
                        FieldSpec.text("capabilityId", true)),
                op("security.audit-view.inspect-redacted",
                        FieldSpec.text("objectId", true), FieldSpec.text("reasonReference", false)),
                op("security.audit-view.inspect-full",
                        FieldSpec.text("objectId", true), FieldSpec.text("reasonReference", false)),
                op("security.audit-view.inspect-pii",
                        FieldSpec.text("objectId", true), FieldSpec.text("reasonReference", false)),
                op("repository.alias.inspect",
                        FieldSpec.text("authorityId", true),
                        FieldSpec.enum_("type", true, REPOSITORY_ALIAS_TYPE)),
                op("repository.alias.list",
                        FieldSpec.integer("offset", true), FieldSpec.integer("limit", true)),
                op("repository.alias.set",
                        FieldSpec.text("authorityId", true),
                        FieldSpec.enum_("type", true, REPOSITORY_ALIAS_TYPE),
                        FieldSpec.text("targetObjectId", true),
                        FieldSpec.text("issuerId", false),
                        FieldSpec.text("expectedCurrentCommitment", false)),
                op("repository.alias.remove",
                        FieldSpec.text("authorityId", true),
                        FieldSpec.enum_("type", true, REPOSITORY_ALIAS_TYPE),
                        FieldSpec.text("expectedCurrentCommitment", true)),
                op("acme.directory.register",
                        FieldSpec.text("alias", true),
                        FieldSpec.text("authorityId", true),
                        FieldSpec.text("profileId", true),
                        FieldSpec.textSet("dnsNamespaces", true),
                        FieldSpec.integer("maximumValidityMillis", true),
                        FieldSpec.textSet("publicKeyAlgorithms", true),
                        FieldSpec.textSet("x509BindingPolicies", true),
                        FieldSpec.enumSet("challengeTypes", true, ACME_CHALLENGE_TYPE),
                        FieldSpec.textSet("challengeProviderIds", true),
                        FieldSpec.text("eabProviderId", false),
                        FieldSpec.bool("eabRequired", true)),
                op("acme.directory.inspect",
                        FieldSpec.text("directoryId", true)),
                op("acme.directory.list",
                        FieldSpec.integer("offset", true), FieldSpec.integer("limit", true)),
                op("acme.directory.activate",
                        FieldSpec.text("directoryId", true)),
                op("acme.directory.deactivate",
                        FieldSpec.text("directoryId", true)),
                op("acme.account.inspect",
                        FieldSpec.text("accountId", true)),
                op("acme.account.list",
                        FieldSpec.integer("offset", true), FieldSpec.integer("limit", true)),
                op("acme.account.deactivate",
                        FieldSpec.text("accountId", true)),
                op("ocsp.responder.register",
                        FieldSpec.text("responderId", true),
                        FieldSpec.text("alias", true),
                        FieldSpec.text("authorityId", true),
                        FieldSpec.text("issuerId", true),
                        FieldSpec.enum_("signingMode", true, OCSP_SIGNING_MODE),
                        FieldSpec.text("responderCredentialId", true),
                        FieldSpec.text("signingKeyRef", true),
                        FieldSpec.text("chainPathId", true),
                        FieldSpec.text("signatureAlgorithm", true),
                        FieldSpec.text("signatureBindingId", false),
                        FieldSpec.text("signatureBindingCommitment", true),
                        FieldSpec.enum_("responderIdForm", true, OCSP_RESPONDER_ID_FORM),
                        FieldSpec.integer("responseValidityMillis", true),
                        FieldSpec.enum_("noncePolicy", true, OCSP_NONCE_POLICY),
                        FieldSpec.integer("maximumNonceBytes", true),
                        FieldSpec.enumSet("acceptedHashes", true, OCSP_CERT_ID_HASH),
                        FieldSpec.integer("maximumRequestBytes", true),
                        FieldSpec.integer("maximumEntries", true),
                        FieldSpec.integer("cacheLifetimeMillis", true),
                        FieldSpec.enum_("requestAuthenticationMode", true, OCSP_REQUEST_AUTH_MODE),
                        FieldSpec.object("requesterTrustPolicy", false)),
                op("ocsp.responder.inspect",
                        FieldSpec.text("responderId", true)),
                op("ocsp.responder.list",
                        FieldSpec.integer("offset", true), FieldSpec.integer("limit", true)),
                op("ocsp.responder.activate",
                        FieldSpec.text("responderId", true)),
                op("ocsp.responder.deactivate",
                        FieldSpec.text("responderId", true)),
                op("security.audit.search",
                        FieldSpec.text("category", false),
                        FieldSpec.text("action", false),
                        FieldSpec.text("after", false),
                        FieldSpec.text("before", false),
                        FieldSpec.text("objectId", false),
                        FieldSpec.text("principalName", false),
                        FieldSpec.integer("limit", true)),
                op("security.audit.verify-integrity",
                        FieldSpec.integer("sequence", false),
                        FieldSpec.text("recordHash", false)),
                op("est.endpoint.register",
                        FieldSpec.text("label", true),
                        FieldSpec.text("authorityId", true),
                        FieldSpec.text("profileId", true),
                        FieldSpec.object("keygen", false)),
                op("est.endpoint.deregister",
                        FieldSpec.text("label", true)),
                op("est.endpoint.inspect",
                        FieldSpec.text("label", true)),
                op("est.endpoint.list",
                        FieldSpec.integer("offset", true), FieldSpec.integer("limit", true)),
                op("scep.endpoint.register",
                        FieldSpec.text("label", true),
                        FieldSpec.text("authorityId", true),
                        FieldSpec.text("profileId", true),
                        FieldSpec.text("challengePasswordHash", true)),
                op("scep.endpoint.deregister",
                        FieldSpec.text("label", true)),
                op("scep.endpoint.inspect",
                        FieldSpec.text("label", true)),
                op("scep.endpoint.list",
                        FieldSpec.integer("offset", true), FieldSpec.integer("limit", true)),
                op("cmp.endpoint.register",
                        FieldSpec.text("label", true),
                        FieldSpec.text("authorityId", true),
                        FieldSpec.text("profileId", true),
                        FieldSpec.enum_("protectionPolicy", true, CMP_PROTECTION_POLICY)),
                op("cmp.endpoint.deregister",
                        FieldSpec.text("label", true)),
                op("cmp.endpoint.inspect",
                        FieldSpec.text("label", true)),
                op("cmp.endpoint.list",
                        FieldSpec.integer("offset", true), FieldSpec.integer("limit", true)),
                op("enrollment.profile.register",
                        FieldSpec.text("id", true),
                        FieldSpec.text("displayName", true),
                        FieldSpec.text("certificateProfileId", true),
                        FieldSpec.textSet("allowedAuthorityIds", false),
                        FieldSpec.text("subjectDnPattern", false),
                        FieldSpec.textSet("requiredSanDomains", false),
                        FieldSpec.bool("requireApproval", false)),
                op("enrollment.profile.update",
                        FieldSpec.text("id", true),
                        FieldSpec.text("displayName", true),
                        FieldSpec.text("certificateProfileId", true),
                        FieldSpec.textSet("allowedAuthorityIds", false),
                        FieldSpec.text("subjectDnPattern", false),
                        FieldSpec.textSet("requiredSanDomains", false),
                        FieldSpec.bool("requireApproval", false),
                        FieldSpec.enum_("state", false, ENROLLMENT_PROFILE_STATE)),
                op("enrollment.profile.inspect",
                        FieldSpec.text("id", true)),
                op("enrollment.profile.list",
                        FieldSpec.integer("offset", true), FieldSpec.integer("limit", true)),
                op("enrollment.profile.activate",
                        FieldSpec.text("id", true)),
                op("enrollment.profile.suspend",
                        FieldSpec.text("id", true)),
                op("backup.export",
                        FieldSpec.text("label", true)),
                op("backup.verify",
                        FieldSpec.text("backupId", true),
                        FieldSpec.base64("payload", true)),
                op("backup.restore",
                        FieldSpec.text("backupId", true),
                        FieldSpec.base64("payload", true)))
                ;
    }

    private static Parameters op(String id, FieldSpec... fields) {
        return new Parameters(id, List.of(fields));
    }

    private OperationParameterSchemas() {
    }
}
