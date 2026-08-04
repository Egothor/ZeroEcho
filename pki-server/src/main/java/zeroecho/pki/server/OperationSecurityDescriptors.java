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
@SuppressWarnings({ "PMD.ControlStatementBraces", "PMD.FieldDeclarationsShouldBeAtStartOfClass" })
public final class OperationSecurityDescriptors {
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
    public record Descriptor(String operationId, Permission.Action action, Permission.ResourceType resourceType,
            boolean mutating, Permission.DataView dataView, ApprovalCategory approvalCategory,
            Eligibility eligibility) {
        /** Validates one finite descriptor. */
        public Descriptor {
            Permission.requireBounded(operationId, 256, "operation ID");
            Objects.requireNonNull(action, "action");
            Objects.requireNonNull(resourceType, "resourceType");
            Objects.requireNonNull(dataView, "dataView");
            Objects.requireNonNull(approvalCategory, "approvalCategory");
            Objects.requireNonNull(eligibility, "eligibility");
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
                read(PkiOperation.InspectAlgorithmBinding.NAME, Permission.Action.X509_BINDING_READ, Permission.ResourceType.X509_BINDING)));
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

    /** @return immutable descriptor map keyed by operation ID */
    public Map<String, Descriptor> descriptors() {
        return descriptors;
    }

    /** Computes an exact deterministic safe operation commitment. */
    public String commitment(RealmId realmId, PkiOperation operation, Permission.Resource resource) {
        Descriptor descriptor = require(operation);
        return ApprovalService.digest(realmId.value() + '|' + descriptor.operationId() + '|'
                + canonicalArguments(operation) + '|' + canonicalResource(resource));
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
        return new Descriptor(id, action, type, false, Permission.DataView.METADATA_REDACTED,
                ApprovalCategory.NONE, Eligibility.ADMINISTRATIVE);
    }

    private static Descriptor mutate(String id, Permission.Action action, Permission.ResourceType type,
            boolean highRisk) {
        return new Descriptor(id, action, type, true, Permission.DataView.METADATA_REDACTED,
                highRisk ? ApprovalCategory.HIGH_RISK : ApprovalCategory.NONE, Eligibility.ADMINISTRATIVE);
    }

    private static void validateOperationType(PkiOperation operation, Descriptor descriptor) {
        if (!operation.name().equals(descriptor.operationId())) {
            throw new SecurityException("Operation identity and descriptor differ");
        }
    }
}
