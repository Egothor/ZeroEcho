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
package zeroecho.pki.server.http;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofCas;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofSubmission;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.application.OcspResponseService;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSigningOperation;
import zeroecho.pki.server.AdministrativeOperation;
import zeroecho.pki.server.ApprovalService;
import zeroecho.pki.server.DisclosureService;
import zeroecho.pki.server.OcspResponderService;
import zeroecho.pki.server.OperationSecurityDescriptors;
import zeroecho.pki.server.Permission;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.RealmId;
import zeroecho.pki.server.RepositoryAliasService;
import zeroecho.pki.server.RoleTemplateCatalog;
import zeroecho.pki.server.SecurityPrincipal;
import zeroecho.pki.server.ServerControlOperation;
import zeroecho.pki.server.acme.AcmeService;
import zeroecho.pki.server.acme.AcmeState;
import zeroecho.pki.server.cmp.CmpEndpoint;
import zeroecho.pki.server.cmp.CmpProtectionPolicy;
import zeroecho.pki.server.enrollment.EnrollmentProfile;
import zeroecho.pki.server.enrollment.EnrollmentProfileState;
import zeroecho.pki.server.est.EstEndpoint;
import zeroecho.pki.server.est.KeygenPolicy;
import zeroecho.pki.server.scep.ScepEndpoint;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Closed strict HTTP decoding for operations exposed by the existing gateway.
 */
public final class HttpOperationCodec {
    private static final String CONTROL_NOT_EXPOSED = "Control operation is not exposed";

    private static final String OPERATION_NOT_EXPOSED = "Operation is not exposed";

    private static final String TEXT_AUTHORITYID = "authorityId";
    private static final String TEXT_APPROVALID = "approvalId";
    private static final int BOUND_1 = 1;
    private static final String TEXT_FORMATID = "formatId";
    private static final String TEXT_PROFILEID = "profileId";
    private static final String TEXT_ISSUERCAID = "issuerCaId";
    private static final String TEXT_REQUESTID = "requestId";
    private static final String TEXT_CREDENTIALID = "credentialId";
    private static final String TEXT_CAID = "caId";
    private static final String TEXT_EXPECTEDHEAD = "expectedHead";
    private static final String TEXT_TYPE = "type";
    private static final String TEXT_LIMIT = "limit";
    private static final String TEXT_AFTER = "after";
    private static final String TEXT_STATE = "state";
    private static final String TEXT_REASON = "reason";
    private static final String TEXT_JUSTIFICATION = "justification";
    private static final String TEXT_PUBLICATIONID = "publicationId";
    private static final String TEXT_ISSUERID = "issuerId";
    private static final String TEXT_BINDINGID = "bindingId";
    private static final String TEXT_ENABLED = "enabled";
    private static final String TEXT_PRINCIPALID = "principalId";
    private static final String TEXT_DISPLAYNAME = "displayName";
    private static final String TEXT_OFFSET = "offset";
    private static final String TEXT_ASSIGNMENTID = "assignmentId";
    private static final String TEXT_EXPIRESAT = "expiresAt";
    private static final String TEXT_GRANTID = "grantId";
    private static final String TEXT_ACTION = "action";
    private static final String TEXT_RESOURCETYPE = "resourceType";
    private static final String TEXT_RESPONDERID = "responderId";
    private static final String TEXT_BREAKGLASSID = "breakGlassId";
    private static final String TEXT_OBJECTID = "objectId";
    private static final String TEXT_ENROLLMENTPROFILEID = "enrollmentProfileId";
    private static final String TEXT_LABEL = "label";
    private static final String TEXT_BACKUPID = "backupId";
    private static final String TEXT_ALLOWEDAUTHORITYIDS = "allowedAuthorityIds";
    private static final String TEXT_SUBJECTDNPATTERN = "subjectDnPattern";
    private static final String TEXT_REQUIREDSANDOMAINS = "requiredSanDomains";
    private static final String TEXT_REQUIREAPPROVAL = "requireApproval";
    private static final String TEXT_SDKPROFILE = "sdkProfile";

    /**
     * Signals that a legacy in-memory archive exceeds its bound and requires streaming transfer.
     */
    /* default */ static final class LegacyBackupLimitException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
        /**
         * Creates the safe failure carrying the stable streaming-required code.
         */
        /* default */ LegacyBackupLimitException() { super("BACKUP_LEGACY_LIMIT_USE_STREAMING"); }
    }

    private static byte[] legacyBackup(String encoded) {
        int maximum = zeroecho.pki.api.backup.BackupLimits.defaults().legacyBytes();
        int characters = Math.multiplyExact((maximum + 2) / 3, 4);
        if (encoded.length() > characters) {
            throw new LegacyBackupLimitException();
        }
        byte[] decoded = Base64.getDecoder().decode(encoded);
        if (decoded.length > maximum) {
            throw new LegacyBackupLimitException();
        }
        return decoded;
    }

    /**
     * Fully decoded gateway input excluding authenticated principal and request ID.
     * @param operation exact closed operation
     * @param resource requested resource, subsequently resolved by the gateway
     * @param context operation-specific authorization context
     * @param approvalId legacy explicit approval linkage, absent for new durable submissions
     * @param requestedDeadline execution duration, never an approval-wait expiry
     */
    public record Decoded(AdministrativeOperation operation, Permission.Resource resource, Permission.Context context,
            Optional<String> approvalId, Optional<Duration> requestedDeadline) { }

    private HttpOperationCodec() {
    }

    /**
     * Decodes the same strict operation envelope for HTTP and retained workflow recovery.
     * This method establishes no authentication or authorization.
     * @param operationId exact catalog identity
     * @param document bounded UTF-8 JSON envelope
     * @param maximumBytes maximum accepted document size
     * @param realmId trusted server realm
     * @param descriptors current closed catalog lookup
     * @return typed target requiring gateway authorization
     * @throws IllegalArgumentException for malformed or unsupported input
     */
    // Untrusted transport/parser failures retain the existing finite safe HTTP diagnostics.
    @SuppressWarnings({"PMD.PreserveStackTrace"})
    public static Decoded decode(
            String operationId,
            byte[] document,
            int maximumBytes,
            RealmId realmId,
            java.util.function.Function<String, OperationSecurityDescriptors.Descriptor>
                    descriptors) {
        Fields root;
        try {
            root = Fields.of(StrictJson.parse(document, maximumBytes));
        } catch (IllegalArgumentException invalid) {
            if ((ServerControlOperation.VerifyBackup.NAME.equals(operationId)
                            || ServerControlOperation.ExecuteRestore.NAME.equals(operationId))
                    && invalid.getCause()
                            instanceof tools.jackson.core.exc.StreamConstraintsException) {
                throw new LegacyBackupLimitException();
            }
            throw invalid;
        }
        root.allowed(Set.of("version", TEXT_AUTHORITYID, TEXT_APPROVALID, "deadline", "arguments"));
        if (root.integer("version") != BOUND_1) {
            throw new IllegalArgumentException("Request version is unsupported");
        }
        Optional<PkiId> authority = root.optionalText(TEXT_AUTHORITYID).map(PkiId::new);
        Optional<String> approval = root.optionalText(TEXT_APPROVALID);
        approval.ifPresent(value -> requireId(value, "approval ID"));
        Optional<Duration> deadline =
                root.optionalText("deadline").map(HttpOperationCodec::duration);
        Fields arguments = root.object("arguments");
        OperationSecurityDescriptors.Descriptor descriptor = descriptors.apply(operationId);
        AdministrativeOperation operation;
        Permission.Scope scope;
        Optional<PkiId> objectId;
        if (descriptor.family() == OperationSecurityDescriptors.Family.PKI_OPERATION) {
            PkiOperation pki = operation(operationId, arguments, authority);
            operation = new AdministrativeOperation.Pki(pki);
            boolean realmWide = DomainScope.realmWide(pki);
            requireAuthorityPresence(realmWide, authority);
            DomainScope.validateAuthority(pki, authority);
            scope =
                    new Permission.Scope(
                            realmId, authority, Optional.empty(), DomainScope.profile(pki));
            objectId = DomainScope.objectId(pki);
        } else if (descriptor.family() == OperationSecurityDescriptors.Family.SIGNING_OPERATION) {
            PkiSigningOperation signing = HttpSigningOperations.decode(operationId, arguments);
            operation = new AdministrativeOperation.Signing(signing);
            boolean realmWide = signing instanceof PkiSigningOperation.CreateAuthority;
            requireAuthorityPresence(realmWide, authority);
            SigningScope.validateAuthority(signing, authority);
            scope =
                    new Permission.Scope(
                            realmId,
                            authority,
                            signing
                                            instanceof
                                            PkiSigningOperation.IssueOcspResponderCertificate
                                                    provision
                                    ? Optional.of(provision.request().intent().expectedIssuerId())
                                    : Optional.empty(),
                            SigningScope.profile(signing));
            objectId = SigningScope.objectId(signing);
        } else {
            ServerControlOperation control =
                    control(operationId, arguments, realmId, authority, descriptors);
            operation = new AdministrativeOperation.Control(control);
            scope = ControlScope.controlScope(control, realmId, authority);
            objectId = ControlScope.controlObject(control);
        }
        arguments.complete();
        root.complete();
        Permission.Resource resource =
                new Permission.Resource(
                        descriptor.resourceType(), scope, objectId, Optional.empty());
        Optional<String> justification =
                operation instanceof AdministrativeOperation.Pki pki
                        ? DomainScope.operatorJustification(pki.operation())
                        : Optional.empty();
        Permission.Context context =
                new Permission.Context(justification, approval.isPresent(), false, Map.of());
        return new Decoded(operation, resource, context, approval, deadline);
    }

    private static PkiOperation operation(String id, Fields fields, Optional<PkiId> authority) {
        if (DomainAuthorities.NAMES.contains(id)) {
            return DomainAuthorities.decode(id, fields);
        }
        if (DomainProfiles.NAMES.contains(id)) {
            return DomainProfiles.decode(id, fields);
        }
        if (DomainRequests.NAMES.contains(id)) {
            return DomainRequests.decode(id, fields);
        }
        if (DomainCredentials.NAMES.contains(id)) {
            return DomainCredentials.decode(id, fields, authority);
        }
        if (DomainIssuers.NAMES.contains(id)) {
            return DomainIssuers.decode(id, fields, authority);
        }
        if (DomainConfirmation.NAMES.contains(id)) {
            return DomainConfirmation.decode(id, fields, authority);
        }
        if (DomainCredentialState.NAMES.contains(id)) {
            return DomainCredentialState.decode(id, fields);
        }
        if (DomainRevocations.NAMES.contains(id)) {
            return DomainRevocations.decode(id, fields);
        }
        if (DomainPublications.NAMES.contains(id)) {
            return DomainPublications.decode(id, fields);
        }
        if (DomainStatus.NAMES.contains(id)) {
            return DomainStatus.decode(id, fields);
        }
        if (DomainAlgorithmBindings.NAMES.contains(id)) {
            return DomainAlgorithmBindings.decode(id, fields);
        }
        if (DomainConfiguration.NAMES.contains(id)) {
            return DomainConfiguration.decode(id, fields);
        }
        if (DomainSchedules.NAMES.contains(id)) {
            return DomainSchedules.decode(id, fields);
        }
        if (DomainMetrics.NAMES.contains(id)) {
            return DomainMetrics.decode(id, fields);
        }
        throw new SecurityException(OPERATION_NOT_EXPOSED);
    }

    private static ServerControlOperation control(
            String id,
            Fields fields,
            RealmId realmId,
            Optional<PkiId> authority,
            java.util.function.Function<String, OperationSecurityDescriptors.Descriptor>
                    descriptors) {
        ServerControlOperation selected =
                SecurityControls.decode(id, fields, realmId, authority, descriptors);
        if (selected != null) {
            return selected;
        }
        return ProtocolControls.decode(id, fields);
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

    private static OcspResponderService.SdkConfiguration ocspSdk(Fields fields) {
        fields.allowed(
                Set.of(
                        "profile",
                        "alternativeKeyRef",
                        "alternativeSignatureAlgorithm",
                        "alternativeSignatureBindingId",
                        "alternativeSignatureBindingCommitment"));
        OcspResponderService.SdkConfiguration value =
                new OcspResponderService.SdkConfiguration(
                        fields.text("profile"),
                        new KeyRef(fields.text("alternativeKeyRef")),
                        fields.text("alternativeSignatureAlgorithm"),
                        fields.optionalText("alternativeSignatureBindingId"),
                        fields.text("alternativeSignatureBindingCommitment"));
        fields.complete();
        return value;
    }

    private static OcspResponderService.RequesterTrustPolicy requesterTrustPolicy(Fields fields) {
        fields.exact(
                "trustSelectors",
                "principalMappings",
                "signatureBindings",
                "revocationPolicy",
                "maximumSignerCertificates",
                "maximumSignerChainBytes");
        List<OcspResponderService.TrustSelector> selectors =
                fields.objects("trustSelectors").stream()
                        .map(
                                value -> {
                                    value.exact(TEXT_TYPE, "identities");
                                    return new OcspResponderService.TrustSelector(
                                            OcspResponderService.TrustSelectorType.valueOf(
                                                    value.text(TEXT_TYPE)),
                                            value.stringSet("identities"));
                                })
                        .toList();
        List<OcspResponderService.PrincipalMapping> mappings =
                fields.objects("principalMappings").stream()
                        .map(
                                value -> {
                                    value.exact(
                                            "mappingId", TEXT_PRINCIPALID, TEXT_TYPE, "commitment");
                                    return new OcspResponderService.PrincipalMapping(
                                            value.text("mappingId"),
                                            value.text(TEXT_PRINCIPALID),
                                            OcspResponderService.PrincipalMappingType.valueOf(
                                                    value.text(TEXT_TYPE)),
                                            value.text("commitment"));
                                })
                        .toList();
        List<OcspResponderService.RequestSignatureBinding> bindings =
                fields.objects("signatureBindings").stream()
                        .map(
                                value -> {
                                    value.exact(TEXT_BINDINGID, "commitment");
                                    return new OcspResponderService.RequestSignatureBinding(
                                            value.text(TEXT_BINDINGID), value.text("commitment"));
                                })
                        .toList();
        return new OcspResponderService.RequesterTrustPolicy(
                selectors,
                mappings,
                bindings,
                OcspResponderService.RequesterRevocationPolicy.valueOf(
                        fields.text("revocationPolicy")),
                fields.integer("maximumSignerCertificates"),
                fields.integer("maximumSignerChainBytes"));
    }

    // Untrusted transport/parser failures retain the existing finite safe HTTP diagnostics.
    @SuppressWarnings({"PMD.PreserveStackTrace"})
    private static Duration duration(String value) {
        try {
            Duration result = Duration.parse(value);
            if (result.isZero() || result.isNegative()) {
                throw new IllegalArgumentException("Deadline is invalid");
            }
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

    /** Tracks a closed object grammar and rejects every unconsumed field. */
    /* default */ static final class Fields {
        private final Map<String, PkiOperationValue> entries;
        private final Set<String> consumed = new LinkedHashSet<>();

        private Fields(Map<String, PkiOperationValue> entries) {
            this.entries = entries;
        }

        /* default */ Map<String, PkiOperationValue> values() {
            return entries;
        }

        /* default */ void consumeAll() {
            consumed.addAll(entries.keySet());
        }

        /* default */ static Fields of(PkiOperationValue value) {
            if (!(value instanceof PkiOperationValue.ObjectValue object)) {
                throw new IllegalArgumentException("Request value must be an object");
            }
            return new Fields(object.fields());
        }

        /* default */ void exact(String... names) {
            allowed(Set.of(names));
            if (entries.size() != names.length) {
                throw new IllegalArgumentException("Request fields are incomplete");
            }
        }

        /* default */ void allowed(Set<String> names) {
            if (!names.containsAll(entries.keySet())) {
                throw new IllegalArgumentException("Unknown request field");
            }
        }

        /* default */ String text(String name) {
            consumed.add(name);
            PkiOperationValue value = require(name);
            if (!(value instanceof PkiOperationValue.Text text)) {
                throw type();
            }
            return text.value();
        }

        /* default */ Optional<String> optionalText(String name) {
            return entries.containsKey(name) ? Optional.of(text(name)) : Optional.empty();
        }

        /* default */ boolean contains(String name) {
            return entries.containsKey(name);
        }

        /* default */ long longValue(String name) {
            consumed.add(name);
            PkiOperationValue value = require(name);
            if (!(value instanceof PkiOperationValue.IntegerValue integer)) {
                throw type();
            }
            return integer.value();
        }

        /* default */ int integer(String name) {
            return Math.toIntExact(longValue(name));
        }

        /* default */ boolean bool(String name) {
            consumed.add(name);
            PkiOperationValue value = require(name);
            if (!(value instanceof PkiOperationValue.BooleanValue bool)) {
                throw type();
            }
            return bool.value();
        }

        /* default */ PkiId pkiId(String name) { return new PkiId(text(name)); }

        // Untrusted transport/parser failures retain the existing finite safe HTTP diagnostics.
        /* default */
        @SuppressWarnings({"PMD.PreserveStackTrace"})
        Instant instant(String name) {
            try {
                return Instant.parse(text(name));
            } catch (java.time.format.DateTimeParseException failure) {
                throw type();
            }
        }

        /* default */ Optional<Instant> optionalInstant(String name) {
            return entries.containsKey(name) ? Optional.of(instant(name)) : Optional.empty();
        }

        /* default */ <E extends Enum<E>> Set<E> enumSet(String name, Class<E> type) {
            consumed.add(name);
            PkiOperationValue value = require(name);
            if (!(value instanceof PkiOperationValue.ListValue list)) {
                throw type();
            }
            Set<E> result = new LinkedHashSet<>();
            for (PkiOperationValue item : list.values()) {
                if (!(item instanceof PkiOperationValue.Text text)
                        || !result.add(Enum.valueOf(type, text.value()))) {
                    throw type();
                }
            }
            return Set.copyOf(result);
        }

        /* default */ Set<String> stringSet(String name) {
            consumed.add(name);
            PkiOperationValue value = require(name);
            if (!(value instanceof PkiOperationValue.ListValue list)) {
                throw type();
            }
            Set<String> result = new LinkedHashSet<>();
            for (PkiOperationValue item : list.values()) {
                if (!(item instanceof PkiOperationValue.Text text) || !result.add(text.value())) {
                    throw type();
                }
            }
            return Set.copyOf(result);
        }

        /* default */ Optional<zeroecho.pki.api.ca.CaHeadSnapshot> head() {
            if (entries.containsKey(TEXT_EXPECTEDHEAD)) {
                consumed.add(TEXT_EXPECTEDHEAD);
            }
            return zeroecho.pki.server.LifecycleProjection.head(entries);
        }

        /* default */ zeroecho.pki.api.ca.CaRotationSelection selection() {
            for (String name :
                    Set.of(
                            "newKeyRef",
                            "newAlternativeKeyRef",
                            "primarySignatureAlgorithmId",
                            "alternativeSignatureAlgorithmId")) {
                if (entries.containsKey(name)) {
                    consumed.add(name);
                }
            }
            return zeroecho.pki.server.LifecycleProjection.selection(entries);
        }

        /* default */ Fields object(String name) {
            consumed.add(name);
            return of(require(name));
        }

        /* default */ List<Fields> objects(String name) {
            consumed.add(name);
            PkiOperationValue value = require(name);
            if (!(value instanceof PkiOperationValue.ListValue list)) {
                throw type();
            }
            return list.values().stream().map(Fields::of).toList();
        }

        /* default */ void complete() {
            if (!Objects.equals(consumed, entries.keySet())) {
                throw new IllegalArgumentException("Request fields were not consumed");
            }
        }

        private PkiOperationValue require(String name) {
            PkiOperationValue value = entries.get(name);
            if (value == null) {
                throw new IllegalArgumentException("Required request field is missing");
            }
            return value;
        }

        private static IllegalArgumentException type() {
            return new IllegalArgumentException("Request field type is invalid");
        }
    }

    /** Strict field decoding for the authorities operation family. */
    private static final class DomainAuthorities {
        private static final Set<String> NAMES =
                Set.of(
                        PkiOperation.ListAuthorities.NAME,
                        PkiOperation.InspectAuthority.NAME,
                        PkiOperation.TransitionAuthority.NAME);

        private static PkiOperation decode(String id, Fields fields) {
            return switch (id) {
                case PkiOperation.ListAuthorities.NAME -> {
                    fields.allowed(Set.of(TEXT_LIMIT, TEXT_AFTER));
                    yield new PkiOperation.ListAuthorities(
                            fields.integer(TEXT_LIMIT), fields.optionalText(TEXT_AFTER));
                }
                case PkiOperation.InspectAuthority.NAME -> {
                    fields.exact(TEXT_CAID);
                    yield new PkiOperation.InspectAuthority(fields.pkiId(TEXT_CAID));
                }
                case PkiOperation.TransitionAuthority.NAME -> {
                    fields.exact(TEXT_CAID, TEXT_STATE, TEXT_REASON);
                    yield new PkiOperation.TransitionAuthority(
                            fields.pkiId(TEXT_CAID),
                            CaState.valueOf(fields.text(TEXT_STATE)),
                            fields.text(TEXT_REASON));
                }
                default -> throw new SecurityException(OPERATION_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the profiles operation family. */
    private static final class DomainProfiles {
        private static final Set<String> NAMES =
                Set.of(
                        PkiOperation.ListProfiles.NAME,
                        PkiOperation.ListProfileVersions.NAME,
                        PkiOperation.InspectProfile.NAME,
                        PkiOperation.ActivateProfile.NAME,
                        PkiOperation.RegisterProfile.NAME,
                        PkiOperation.ValidateProfile.NAME);

        private static PkiOperation decode(String id, Fields fields) {
            return switch (id) {
                case PkiOperation.ListProfiles.NAME -> {
                    fields.allowed(Set.of(TEXT_LIMIT, TEXT_AFTER));
                    yield new PkiOperation.ListProfiles(
                            fields.integer(TEXT_LIMIT), fields.optionalText(TEXT_AFTER));
                }
                case PkiOperation.ListProfileVersions.NAME -> {
                    fields.exact(TEXT_PROFILEID);
                    yield new PkiOperation.ListProfileVersions(fields.text(TEXT_PROFILEID));
                }
                case PkiOperation.InspectProfile.NAME -> {
                    fields.exact(TEXT_PROFILEID, "profileVersion");
                    yield new PkiOperation.InspectProfile(
                            fields.text(TEXT_PROFILEID), fields.longValue("profileVersion"));
                }
                case PkiOperation.ActivateProfile.NAME -> {
                    fields.exact(TEXT_PROFILEID, "profileVersion");
                    yield new PkiOperation.ActivateProfile(
                            fields.text(TEXT_PROFILEID), fields.longValue("profileVersion"));
                }
                case PkiOperation.RegisterProfile.NAME -> {
                    fields.exact("document");
                    yield new PkiOperation.RegisterProfile(
                            Base64.getDecoder().decode(fields.text("document")));
                }
                case PkiOperation.ValidateProfile.NAME -> {
                    fields.exact("document");
                    yield new PkiOperation.ValidateProfile(
                            Base64.getDecoder().decode(fields.text("document")));
                }
                default -> throw new SecurityException(OPERATION_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the requests operation family. */
    private static final class DomainRequests {
        private static final Set<String> NAMES =
                Set.of(
                        PkiOperation.ListRequests.NAME,
                        PkiOperation.InspectRequest.NAME,
                        PkiOperation.ImportRequest.NAME,
                        PkiOperation.VerifyRequest.NAME);

        private static PkiOperation decode(String id, Fields fields) {
            return switch (id) {
                case PkiOperation.ListRequests.NAME -> {
                    fields.allowed(Set.of(TEXT_LIMIT, TEXT_AFTER));
                    yield new PkiOperation.ListRequests(
                            fields.integer(TEXT_LIMIT), fields.optionalText(TEXT_AFTER));
                }
                case PkiOperation.InspectRequest.NAME -> {
                    fields.exact(TEXT_REQUESTID);
                    yield new PkiOperation.InspectRequest(fields.pkiId(TEXT_REQUESTID));
                }
                case PkiOperation.ImportRequest.NAME -> {
                    fields.exact(TEXT_FORMATID, "encoded");
                    yield new PkiOperation.ImportRequest(
                            new FormatId(fields.text(TEXT_FORMATID)),
                            new EncodedObject(
                                    Encoding.DER,
                                    Base64.getDecoder().decode(fields.text("encoded"))));
                }
                case PkiOperation.VerifyRequest.NAME -> {
                    fields.exact(TEXT_REQUESTID);
                    yield new PkiOperation.VerifyRequest(fields.pkiId(TEXT_REQUESTID));
                }
                default -> throw new SecurityException(OPERATION_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the credentials operation family. */
    private static final class DomainCredentials {
        private static final Set<String> NAMES =
                Set.of(
                        PkiOperation.ListCredentials.NAME,
                        PkiOperation.SearchCredentials.NAME,
                        PkiOperation.InspectCredential.NAME,
                        PkiOperation.UnholdCredential.NAME);

        private static PkiOperation decode(String id, Fields fields, Optional<PkiId> authority) {
            return switch (id) {
                case PkiOperation.ListCredentials.NAME -> {
                    fields.allowed(Set.of(TEXT_LIMIT, TEXT_AFTER));
                    yield new PkiOperation.ListCredentials(
                            authority.orElseThrow(),
                            fields.integer(TEXT_LIMIT),
                            fields.optionalText(TEXT_AFTER));
                }
                case PkiOperation.SearchCredentials.NAME -> {
                    fields.allowed(
                            Set.of(
                                    TEXT_LIMIT,
                                    TEXT_AFTER,
                                    "subjectFilter",
                                    "serialFilter",
                                    "fingerprintFilter",
                                    "statusFilter",
                                    "profileIdFilter",
                                    "sanFilter"));
                    yield new PkiOperation.SearchCredentials(
                            authority.orElseThrow(),
                            fields.integer(TEXT_LIMIT),
                            fields.optionalText(TEXT_AFTER),
                            fields.optionalText("subjectFilter"),
                            fields.optionalText("serialFilter"),
                            fields.optionalText("fingerprintFilter"),
                            fields.optionalText("statusFilter"),
                            fields.optionalText("profileIdFilter"),
                            fields.optionalText("sanFilter"));
                }
                case PkiOperation.InspectCredential.NAME -> {
                    fields.exact(TEXT_CREDENTIALID);
                    yield new PkiOperation.InspectCredential(fields.pkiId(TEXT_CREDENTIALID));
                }
                case PkiOperation.UnholdCredential.NAME -> {
                    fields.allowed(Set.of(TEXT_CREDENTIALID, TEXT_JUSTIFICATION));
                    yield new PkiOperation.UnholdCredential(
                            fields.pkiId(TEXT_CREDENTIALID),
                            fields.optionalText(TEXT_JUSTIFICATION));
                }
                default -> throw new SecurityException(OPERATION_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the issuers operation family. */
    private static final class DomainIssuers {
        private static final Set<String> NAMES =
                Set.of(
                        PkiOperation.ListIssuerGenerations.NAME,
                        PkiOperation.InspectIssuerGeneration.NAME,
                        PkiOperation.InspectIssuerChainPath.NAME,
                        PkiOperation.ListIssuerChainPaths.NAME,
                        PkiOperation.SelectIssuancePath.NAME,
                        PkiOperation.RegisterIssuerChainPath.NAME);

        private static PkiOperation decode(String id, Fields fields, Optional<PkiId> authority) {
            return switch (id) {
                case PkiOperation.ListIssuerGenerations.NAME -> {
                    fields.allowed(Set.of(TEXT_LIMIT, TEXT_AFTER));
                    yield new PkiOperation.ListIssuerGenerations(
                            authority.orElseThrow(),
                            fields.integer(TEXT_LIMIT),
                            fields.optionalText(TEXT_AFTER));
                }
                case PkiOperation.InspectIssuerGeneration.NAME -> {
                    fields.exact(TEXT_ISSUERID);
                    yield new PkiOperation.InspectIssuerGeneration(fields.pkiId(TEXT_ISSUERID));
                }
                case PkiOperation.InspectIssuerChainPath.NAME -> {
                    fields.exact("pathId");
                    yield new PkiOperation.InspectIssuerChainPath(fields.pkiId("pathId"));
                }
                case PkiOperation.ListIssuerChainPaths.NAME -> {
                    fields.exact(TEXT_ISSUERID);
                    yield new PkiOperation.ListIssuerChainPaths(fields.pkiId(TEXT_ISSUERID));
                }
                case PkiOperation.SelectIssuancePath.NAME -> {
                    fields.allowed(
                            Set.of(
                                    TEXT_CAID,
                                    TEXT_ISSUERID,
                                    "pathId",
                                    TEXT_REASON,
                                    TEXT_EXPECTEDHEAD,
                                    "transitionCommitment",
                                    "distributionAcknowledged"));
                    yield new PkiOperation.SelectIssuancePath(
                            fields.pkiId(TEXT_CAID),
                            fields.pkiId(TEXT_ISSUERID),
                            fields.pkiId("pathId"),
                            fields.text(TEXT_REASON),
                            fields.head(),
                            fields.optionalText("transitionCommitment"),
                            fields.values().containsKey("distributionAcknowledged")
                                    && fields.bool("distributionAcknowledged"));
                }
                case PkiOperation.RegisterIssuerChainPath.NAME -> {
                    fields.exact(TEXT_CAID, TEXT_ISSUERID, "parentPathId");
                    yield new PkiOperation.RegisterIssuerChainPath(
                            fields.pkiId(TEXT_CAID),
                            fields.pkiId(TEXT_ISSUERID),
                            fields.pkiId("parentPathId"));
                }
                default -> throw new SecurityException(OPERATION_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the confirmation operation family. */
    private static final class DomainConfirmation {
        private static final Set<String> NAMES =
                Set.of(
                        PkiOperation.ListPendingCredentialConfirmations.NAME,
                        PkiOperation.IssueCredentialConfirmationChallenge.NAME,
                        PkiOperation.CompleteCredentialConfirmationProof.NAME,
                        PkiOperation.RevokePendingCredentialConfirmation.NAME);

        private static PkiOperation decode(String id, Fields fields, Optional<PkiId> authority) {
            return switch (id) {
                case PkiOperation.ListPendingCredentialConfirmations.NAME -> {
                    fields.allowed(
                            Set.of(
                                    TEXT_PROFILEID,
                                    "cutoffInclusive",
                                    "afterExclusive",
                                    TEXT_LIMIT));
                    yield new PkiOperation.ListPendingCredentialConfirmations(
                            authority.orElseThrow(
                                    () ->
                                            new IllegalArgumentException(
                                                    "Pending confirmation query requires authorityId")),
                            fields.optionalText(TEXT_PROFILEID),
                            HttpSigningOperations.instant(fields.text("cutoffInclusive")),
                            fields.optionalText("afterExclusive")
                                    .map(
                                            zeroecho.pki.api.confirmation
                                                            .CredentialConfirmationReviewCursor
                                                    ::new),
                            fields.integer(TEXT_LIMIT));
                }
                case PkiOperation.IssueCredentialConfirmationChallenge.NAME -> {
                    fields.exact(TEXT_CREDENTIALID);
                    yield new PkiOperation.IssueCredentialConfirmationChallenge(
                            fields.pkiId(TEXT_CREDENTIALID));
                }
                case PkiOperation.CompleteCredentialConfirmationProof.NAME -> {
                    fields.exact(
                            TEXT_CREDENTIALID,
                            "expectedLifecycleRevision",
                            "expectedLifecycleRecordCommitment",
                            "expectedChallengeRecordCommitment",
                            "response");
                    CredentialConfirmationProofCas proofCas =
                            new CredentialConfirmationProofCas(
                                    fields.pkiId(TEXT_CREDENTIALID),
                                    fields.longValue("expectedLifecycleRevision"),
                                    fields.text("expectedLifecycleRecordCommitment"),
                                    fields.text("expectedChallengeRecordCommitment"));
                    yield new PkiOperation.CompleteCredentialConfirmationProof(
                            proofSubmission(proofCas, fields.text("response")));
                }
                case PkiOperation.RevokePendingCredentialConfirmation.NAME -> {
                    fields.allowed(Set.of(TEXT_CREDENTIALID, TEXT_JUSTIFICATION));
                    yield new PkiOperation.RevokePendingCredentialConfirmation(
                            fields.pkiId(TEXT_CREDENTIALID),
                            fields.optionalText(TEXT_JUSTIFICATION));
                }
                default -> throw new SecurityException(OPERATION_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the credentialstate operation family. */
    private static final class DomainCredentialState {
        private static final Set<String> NAMES =
                Set.of(PkiOperation.HoldCredential.NAME, PkiOperation.RevokeCredential.NAME);

        private static PkiOperation decode(String id, Fields fields) {
            return switch (id) {
                case PkiOperation.HoldCredential.NAME -> {
                    fields.allowed(Set.of(TEXT_CREDENTIALID, TEXT_JUSTIFICATION));
                    yield new PkiOperation.HoldCredential(
                            fields.pkiId(TEXT_CREDENTIALID),
                            fields.optionalText(TEXT_JUSTIFICATION));
                }
                case PkiOperation.RevokeCredential.NAME -> {
                    fields.allowed(Set.of(TEXT_CREDENTIALID, TEXT_REASON, TEXT_JUSTIFICATION));
                    yield new PkiOperation.RevokeCredential(
                            fields.pkiId(TEXT_CREDENTIALID),
                            RevocationReason.valueOf(fields.text(TEXT_REASON)),
                            fields.optionalText(TEXT_JUSTIFICATION));
                }
                default -> throw new SecurityException(OPERATION_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the revocations operation family. */
    private static final class DomainRevocations {
        private static final Set<String> NAMES =
                Set.of(
                        PkiOperation.ReadRevocationHistory.NAME,
                        PkiOperation.InspectRevocation.NAME,
                        PkiOperation.SnapshotRevocations.NAME);

        private static PkiOperation decode(String id, Fields fields) {
            return switch (id) {
                case PkiOperation.ReadRevocationHistory.NAME -> {
                    fields.exact(TEXT_CREDENTIALID, TEXT_LIMIT);
                    yield new PkiOperation.ReadRevocationHistory(
                            fields.pkiId(TEXT_CREDENTIALID), fields.integer(TEXT_LIMIT));
                }
                case PkiOperation.InspectRevocation.NAME -> {
                    fields.exact(TEXT_CREDENTIALID);
                    yield new PkiOperation.InspectRevocation(fields.pkiId(TEXT_CREDENTIALID));
                }
                case PkiOperation.SnapshotRevocations.NAME -> {
                    fields.exact(TEXT_LIMIT);
                    yield new PkiOperation.SnapshotRevocations(fields.integer(TEXT_LIMIT));
                }
                default -> throw new SecurityException(OPERATION_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the publications operation family. */
    private static final class DomainPublications {
        private static final Set<String> NAMES =
                Set.of(
                        PkiOperation.InspectPublication.NAME,
                        PkiOperation.ProcessPublication.NAME,
                        PkiOperation.ListPublications.NAME,
                        PkiOperation.RegisterPublication.NAME,
                        PkiOperation.RetryPublication.NAME,
                        PkiOperation.ReconcilePublication.NAME);

        private static PkiOperation decode(String id, Fields fields) {
            return switch (id) {
                case PkiOperation.InspectPublication.NAME -> {
                    fields.exact(TEXT_PUBLICATIONID);
                    yield new PkiOperation.InspectPublication(fields.pkiId(TEXT_PUBLICATIONID));
                }
                case PkiOperation.ProcessPublication.NAME -> {
                    fields.exact(TEXT_PUBLICATIONID);
                    yield new PkiOperation.ProcessPublication(fields.pkiId(TEXT_PUBLICATIONID));
                }
                case PkiOperation.ListPublications.NAME -> {
                    fields.allowed(Set.of(TEXT_LIMIT, TEXT_AFTER));
                    yield new PkiOperation.ListPublications(
                            fields.integer(TEXT_LIMIT), fields.optionalText(TEXT_AFTER));
                }
                case PkiOperation.RegisterPublication.NAME -> {
                    fields.exact(
                            TEXT_PUBLICATIONID, "sourceType", "sourceId", "targetType", "targetId");
                    yield new PkiOperation.RegisterPublication(
                            fields.pkiId(TEXT_PUBLICATIONID),
                            zeroecho.pki.api.publication.PublicationSourceType.valueOf(
                                    fields.text("sourceType")),
                            fields.pkiId("sourceId"),
                            new zeroecho.pki.api.publication.PublicationTarget(
                                    zeroecho.pki.api.publication.PublicationTargetType.valueOf(
                                            fields.text("targetType")),
                                    fields.text("targetId")));
                }
                case PkiOperation.RetryPublication.NAME -> {
                    fields.exact(TEXT_PUBLICATIONID);
                    yield new PkiOperation.RetryPublication(fields.pkiId(TEXT_PUBLICATIONID));
                }
                case PkiOperation.ReconcilePublication.NAME -> {
                    fields.exact(TEXT_PUBLICATIONID);
                    yield new PkiOperation.ReconcilePublication(fields.pkiId(TEXT_PUBLICATIONID));
                }
                default -> throw new SecurityException(OPERATION_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the status operation family. */
    private static final class DomainStatus {
        private static final Set<String> NAMES =
                Set.of(PkiOperation.InspectStatus.NAME, PkiOperation.ListStatus.NAME);

        private static PkiOperation decode(String id, Fields fields) {
            return switch (id) {
                case PkiOperation.InspectStatus.NAME -> {
                    fields.exact("statusObjectId");
                    yield new PkiOperation.InspectStatus(fields.pkiId("statusObjectId"));
                }
                case PkiOperation.ListStatus.NAME -> {
                    fields.allowed(Set.of(TEXT_ISSUERCAID, TEXT_LIMIT, TEXT_AFTER));
                    yield new PkiOperation.ListStatus(
                            fields.pkiId(TEXT_ISSUERCAID),
                            fields.integer(TEXT_LIMIT),
                            fields.optionalText(TEXT_AFTER));
                }
                default -> throw new SecurityException(OPERATION_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the algorithmbindings operation family. */
    private static final class DomainAlgorithmBindings {
        private static final Set<String> NAMES =
                Set.of(
                        PkiOperation.ListAlgorithmBindings.NAME,
                        PkiOperation.InspectAlgorithmBinding.NAME,
                        PkiOperation.ValidateAlgorithmBindings.NAME);

        private static PkiOperation decode(String id, Fields fields) {
            return switch (id) {
                case PkiOperation.ListAlgorithmBindings.NAME -> {
                    fields.allowed(Set.of("origin", "role", TEXT_LIMIT, TEXT_AFTER));
                    yield new PkiOperation.ListAlgorithmBindings(
                            fields.optionalText("origin"),
                            fields.optionalText("role"),
                            fields.integer(TEXT_LIMIT),
                            fields.optionalText(TEXT_AFTER));
                }
                case PkiOperation.InspectAlgorithmBinding.NAME -> {
                    fields.exact(TEXT_BINDINGID);
                    yield new PkiOperation.InspectAlgorithmBinding(fields.text(TEXT_BINDINGID));
                }
                case PkiOperation.ValidateAlgorithmBindings.NAME -> {
                    fields.allowed(Set.of(TEXT_BINDINGID, "expectedCommitment"));
                    yield new PkiOperation.ValidateAlgorithmBindings(
                            fields.optionalText(TEXT_BINDINGID),
                            fields.optionalText("expectedCommitment"));
                }
                default -> throw new SecurityException(OPERATION_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the configuration operation family. */
    private static final class DomainConfiguration {
        private static final Set<String> NAMES = Set.of(PkiOperation.ValidateConfiguration.NAME);

        private static PkiOperation decode(String id, Fields fields) {
            if (!NAMES.contains(id)) {
                throw new SecurityException(OPERATION_NOT_EXPOSED);
            }

            fields.exact();
            return new PkiOperation.ValidateConfiguration();
        }
    }

    /** Strict field decoding for the schedules operation family. */
    private static final class DomainSchedules {
        private static final Set<String> NAMES =
                Set.of(
                        PkiOperation.SetStatusSchedule.NAME,
                        PkiOperation.InspectStatusSchedule.NAME,
                        PkiOperation.ListStatusSchedules.NAME);

        private static PkiOperation decode(String id, Fields fields) {
            return switch (id) {
                case PkiOperation.SetStatusSchedule.NAME -> {
                    fields.allowed(
                            Set.of(
                                    TEXT_CAID,
                                    "statusType",
                                    TEXT_FORMATID,
                                    "interval",
                                    "graceSeconds",
                                    TEXT_ENABLED,
                                    "targetType",
                                    "targetId"));
                    Optional<zeroecho.pki.api.publication.PublicationTarget> publicationTarget =
                            fields.optionalText("targetType")
                                    .map(
                                            t ->
                                                    new zeroecho.pki.api.publication
                                                            .PublicationTarget(
                                                            zeroecho.pki.api.publication
                                                                    .PublicationTargetType.valueOf(
                                                                    t),
                                                            fields.text("targetId")));
                    yield new PkiOperation.SetStatusSchedule(
                            fields.pkiId(TEXT_CAID),
                            StatusObjectType.valueOf(fields.text("statusType")),
                            new FormatId(fields.text(TEXT_FORMATID)),
                            Duration.parse(fields.text("interval")),
                            (long) fields.integer("graceSeconds"),
                            fields.bool(TEXT_ENABLED),
                            publicationTarget);
                }
                case PkiOperation.InspectStatusSchedule.NAME -> {
                    fields.exact(TEXT_CAID, "statusType");
                    yield new PkiOperation.InspectStatusSchedule(
                            fields.pkiId(TEXT_CAID),
                            StatusObjectType.valueOf(fields.text("statusType")));
                }
                case PkiOperation.ListStatusSchedules.NAME -> {
                    fields.allowed(Set.of(TEXT_LIMIT, TEXT_AFTER));
                    yield new PkiOperation.ListStatusSchedules(
                            fields.integer(TEXT_LIMIT), fields.optionalText(TEXT_AFTER));
                }
                default -> throw new SecurityException(OPERATION_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the metrics operation family. */
    private static final class DomainMetrics {
        private static final Set<String> NAMES =
                Set.of(
                        PkiOperation.QueryAuthorityMetrics.NAME,
                        PkiOperation.QueryCertificateMetrics.NAME,
                        PkiOperation.QueryRevocationMetrics.NAME,
                        PkiOperation.QueryPublicationMetrics.NAME,
                        PkiOperation.QueryServerMetrics.NAME);

        private static PkiOperation decode(String id, Fields fields) {
            return switch (id) {
                case PkiOperation.QueryAuthorityMetrics.NAME -> {
                    fields.exact(TEXT_CAID);
                    yield new PkiOperation.QueryAuthorityMetrics(fields.pkiId(TEXT_CAID));
                }
                case PkiOperation.QueryCertificateMetrics.NAME -> {
                    fields.exact(TEXT_CAID);
                    yield new PkiOperation.QueryCertificateMetrics(fields.pkiId(TEXT_CAID));
                }
                case PkiOperation.QueryRevocationMetrics.NAME -> {
                    fields.exact(TEXT_CAID);
                    yield new PkiOperation.QueryRevocationMetrics(fields.pkiId(TEXT_CAID));
                }
                case PkiOperation.QueryPublicationMetrics.NAME -> {
                    fields.exact(TEXT_CAID);
                    yield new PkiOperation.QueryPublicationMetrics(fields.pkiId(TEXT_CAID));
                }
                case PkiOperation.QueryServerMetrics.NAME -> {
                    fields.allowed(Set.of());
                    yield new PkiOperation.QueryServerMetrics();
                }
                default -> throw new SecurityException(OPERATION_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the principals operation family. */
    private static final class ControlPrincipals {
        private static final Set<String> NAMES =
                Set.of(
                        ServerControlOperation.RegisterPrincipal.NAME,
                        ServerControlOperation.InspectPrincipal.NAME,
                        ServerControlOperation.ListPrincipals.NAME,
                        ServerControlOperation.SetPrincipalEnabled.ENABLE,
                        ServerControlOperation.SetPrincipalEnabled.DISABLE);

        private static ServerControlOperation decode(String id, Fields fields) {
            return switch (id) {
                case ServerControlOperation.RegisterPrincipal.NAME -> {
                    fields.exact(TEXT_PRINCIPALID, TEXT_TYPE, TEXT_DISPLAYNAME, TEXT_ENABLED);
                    yield new ServerControlOperation.RegisterPrincipal(
                            new SecurityPrincipal(
                                    fields.text(TEXT_PRINCIPALID),
                                    SecurityPrincipal.Type.valueOf(fields.text(TEXT_TYPE)),
                                    fields.text(TEXT_DISPLAYNAME),
                                    Optional.empty(),
                                    Map.of(),
                                    fields.bool(TEXT_ENABLED)));
                }
                case ServerControlOperation.InspectPrincipal.NAME -> {
                    fields.exact(TEXT_PRINCIPALID);
                    yield new ServerControlOperation.InspectPrincipal(
                            fields.text(TEXT_PRINCIPALID));
                }
                case ServerControlOperation.ListPrincipals.NAME -> {
                    fields.exact(TEXT_OFFSET, TEXT_LIMIT);
                    yield new ServerControlOperation.ListPrincipals(
                            fields.integer(TEXT_OFFSET), fields.integer(TEXT_LIMIT));
                }
                case ServerControlOperation.SetPrincipalEnabled.ENABLE,
                        ServerControlOperation.SetPrincipalEnabled.DISABLE -> {
                    fields.exact(TEXT_PRINCIPALID);
                    yield new ServerControlOperation.SetPrincipalEnabled(
                            fields.text(TEXT_PRINCIPALID),
                            ServerControlOperation.SetPrincipalEnabled.ENABLE.equals(id));
                }
                default -> throw new SecurityException(CONTROL_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the roles operation family. */
    private static final class ControlRoles {
        private static final Set<String> NAMES =
                Set.of(
                        ServerControlOperation.ListRoleTemplates.NAME,
                        ServerControlOperation.InspectRoleTemplate.NAME,
                        ServerControlOperation.CreateRoleAssignment.NAME,
                        ServerControlOperation.InspectRoleAssignment.NAME,
                        ServerControlOperation.ListRoleAssignments.NAME,
                        ServerControlOperation.RevokeRoleAssignment.NAME);

        private static ServerControlOperation decode(
                String id, Fields fields, RealmId realmId, Optional<PkiId> authority) {
            return switch (id) {
                case ServerControlOperation.ListRoleTemplates.NAME -> {
                    fields.exact();
                    yield new ServerControlOperation.ListRoleTemplates();
                }
                case ServerControlOperation.InspectRoleTemplate.NAME -> {
                    fields.exact("templateId", "version");
                    yield new ServerControlOperation.InspectRoleTemplate(
                            fields.text("templateId"), fields.integer("version"));
                }
                case ServerControlOperation.CreateRoleAssignment.NAME -> {
                    fields.allowed(
                            Set.of(
                                    TEXT_ASSIGNMENTID,
                                    TEXT_PRINCIPALID,
                                    "templateId",
                                    "templateVersion",
                                    TEXT_PROFILEID,
                                    TEXT_EXPIRESAT));
                    Permission.Scope scope =
                            new Permission.Scope(
                                    realmId,
                                    authority,
                                    Optional.empty(),
                                    fields.optionalText(TEXT_PROFILEID));
                    yield new ServerControlOperation.CreateRoleAssignment(
                            new RoleTemplateCatalog.Assignment(
                                    fields.text(TEXT_ASSIGNMENTID),
                                    fields.text(TEXT_PRINCIPALID),
                                    fields.text("templateId"),
                                    fields.integer("templateVersion"),
                                    scope,
                                    fields.optionalInstant(TEXT_EXPIRESAT),
                                    true));
                }
                case ServerControlOperation.InspectRoleAssignment.NAME -> {
                    fields.exact(TEXT_ASSIGNMENTID);
                    yield new ServerControlOperation.InspectRoleAssignment(
                            fields.text(TEXT_ASSIGNMENTID));
                }
                case ServerControlOperation.ListRoleAssignments.NAME -> {
                    fields.exact(TEXT_OFFSET, TEXT_LIMIT);
                    yield new ServerControlOperation.ListRoleAssignments(
                            fields.integer(TEXT_OFFSET), fields.integer(TEXT_LIMIT));
                }
                case ServerControlOperation.RevokeRoleAssignment.NAME -> {
                    fields.exact(TEXT_ASSIGNMENTID);
                    yield new ServerControlOperation.RevokeRoleAssignment(
                            fields.text(TEXT_ASSIGNMENTID));
                }
                default -> throw new SecurityException(CONTROL_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the grants operation family. */
    private static final class ControlGrants {
        private static final Set<String> NAMES =
                Set.of(
                        ServerControlOperation.CreateGrant.NAME,
                        ServerControlOperation.InspectGrant.NAME,
                        ServerControlOperation.ListGrants.NAME,
                        ServerControlOperation.RevokeGrant.NAME,
                        ServerControlOperation.EvaluateAuthorization.NAME);

        private static ServerControlOperation decode(
                String id, Fields fields, RealmId realmId, Optional<PkiId> authority) {
            return switch (id) {
                case ServerControlOperation.CreateGrant.NAME -> {
                    fields.allowed(
                            Set.of(
                                    TEXT_GRANTID,
                                    TEXT_PRINCIPALID,
                                    "effect",
                                    TEXT_ACTION,
                                    TEXT_RESOURCETYPE,
                                    TEXT_ISSUERID,
                                    TEXT_PROFILEID,
                                    TEXT_RESPONDERID,
                                    "relationship",
                                    "dataView",
                                    "conditions",
                                    TEXT_EXPIRESAT));
                    Permission.Scope scope =
                            new Permission.Scope(
                                    realmId,
                                    authority,
                                    fields.optionalText(TEXT_ISSUERID).map(PkiId::new),
                                    fields.optionalText(TEXT_PROFILEID),
                                    fields.optionalText(TEXT_RESPONDERID));
                    yield new ServerControlOperation.CreateGrant(
                            new Permission.Grant(
                                    fields.text(TEXT_GRANTID),
                                    fields.text(TEXT_PRINCIPALID),
                                    Permission.Effect.valueOf(fields.text("effect")),
                                    Permission.Action.valueOf(fields.text(TEXT_ACTION)),
                                    Permission.ResourceType.valueOf(fields.text(TEXT_RESOURCETYPE)),
                                    scope,
                                    Permission.Relationship.valueOf(fields.text("relationship")),
                                    Permission.DataView.valueOf(fields.text("dataView")),
                                    fields.contains("conditions")
                                            ? fields.enumSet(
                                                    "conditions", Permission.Condition.class)
                                            : Set.of(),
                                    fields.optionalInstant(TEXT_EXPIRESAT),
                                    true));
                }
                case ServerControlOperation.InspectGrant.NAME -> {
                    fields.exact(TEXT_GRANTID);
                    yield new ServerControlOperation.InspectGrant(fields.text(TEXT_GRANTID));
                }
                case ServerControlOperation.ListGrants.NAME -> {
                    fields.exact(TEXT_OFFSET, TEXT_LIMIT);
                    yield new ServerControlOperation.ListGrants(
                            fields.integer(TEXT_OFFSET), fields.integer(TEXT_LIMIT));
                }
                case ServerControlOperation.RevokeGrant.NAME -> {
                    fields.exact(TEXT_GRANTID);
                    yield new ServerControlOperation.RevokeGrant(fields.text(TEXT_GRANTID));
                }
                case ServerControlOperation.EvaluateAuthorization.NAME -> {
                    fields.exact(
                            TEXT_PRINCIPALID,
                            TEXT_ACTION,
                            TEXT_RESOURCETYPE,
                            "relationship",
                            "dataView");
                    Permission.Resource resource =
                            new Permission.Resource(
                                    Permission.ResourceType.valueOf(fields.text(TEXT_RESOURCETYPE)),
                                    new Permission.Scope(
                                            realmId, authority, Optional.empty(), Optional.empty()),
                                    Optional.empty(),
                                    Optional.empty());
                    yield new ServerControlOperation.EvaluateAuthorization(
                            fields.text(TEXT_PRINCIPALID),
                            Permission.Action.valueOf(fields.text(TEXT_ACTION)),
                            resource,
                            Permission.Relationship.valueOf(fields.text("relationship")),
                            Permission.DataView.valueOf(fields.text("dataView")),
                            Permission.Context.empty());
                }
                default -> throw new SecurityException(CONTROL_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the approvals operation family. */
    private static final class ControlApprovals {
        private static final Set<String> NAMES =
                Set.of(
                        ServerControlOperation.RequestApproval.NAME,
                        ServerControlOperation.InspectApproval.NAME,
                        ServerControlOperation.ListApprovals.NAME,
                        ServerControlOperation.DecideApproval.APPROVE,
                        ServerControlOperation.DecideApproval.REJECT,
                        ServerControlOperation.CancelApproval.NAME);

        private static ServerControlOperation decode(
                String id,
                Fields fields,
                RealmId realmId,
                java.util.function.Function<String, OperationSecurityDescriptors.Descriptor>
                        descriptors) {
            return switch (id) {
                case ServerControlOperation.RequestApproval.NAME -> {
                    fields.allowed(
                            Set.of(
                                    TEXT_APPROVALID,
                                    "targetOperation",
                                    "targetArguments",
                                    "targetAuthorityId"));
                    String targetId = fields.text("targetOperation");
                    Fields targetFields = fields.object("targetArguments");
                    Optional<PkiId> targetAuthority =
                            fields.optionalText("targetAuthorityId").map(PkiId::new);
                    OperationSecurityDescriptors.Descriptor targetDescriptor =
                            descriptors.apply(targetId);
                    AdministrativeOperation targetOperation;
                    Permission.Scope targetScope;
                    Optional<PkiId> targetObject;
                    if (targetDescriptor.family()
                            == OperationSecurityDescriptors.Family.PKI_OPERATION) {
                        PkiOperation targetPki = operation(targetId, targetFields, targetAuthority);
                        targetOperation = new AdministrativeOperation.Pki(targetPki);
                        targetScope =
                                new Permission.Scope(
                                        realmId,
                                        targetAuthority,
                                        Optional.empty(),
                                        DomainScope.profile(targetPki));
                        targetObject = DomainScope.objectId(targetPki);
                    } else if (targetDescriptor.family()
                            == OperationSecurityDescriptors.Family.SIGNING_OPERATION) {
                        PkiSigningOperation targetSigning =
                                HttpSigningOperations.decode(targetId, targetFields);
                        targetOperation = new AdministrativeOperation.Signing(targetSigning);
                        targetScope =
                                new Permission.Scope(
                                        realmId,
                                        targetAuthority,
                                        Optional.empty(),
                                        SigningScope.profile(targetSigning));
                        targetObject = SigningScope.objectId(targetSigning);
                    } else {
                        ServerControlOperation targetControl =
                                control(
                                        targetId,
                                        targetFields,
                                        realmId,
                                        targetAuthority,
                                        descriptors);
                        targetOperation = new AdministrativeOperation.Control(targetControl);
                        targetScope =
                                ControlScope.controlScope(targetControl, realmId, targetAuthority);
                        targetObject = ControlScope.controlObject(targetControl);
                    }
                    targetFields.complete();
                    Permission.Resource targetResource =
                            new Permission.Resource(
                                    targetDescriptor.resourceType(),
                                    targetScope,
                                    targetObject,
                                    Optional.empty());
                    yield new ServerControlOperation.RequestApproval(
                            fields.text(TEXT_APPROVALID), targetOperation, targetResource);
                }
                case ServerControlOperation.InspectApproval.NAME -> {
                    fields.exact(TEXT_APPROVALID);
                    yield new ServerControlOperation.InspectApproval(fields.text(TEXT_APPROVALID));
                }
                case ServerControlOperation.ListApprovals.NAME -> {
                    fields.allowed(
                            Set.of(
                                    TEXT_OFFSET,
                                    TEXT_LIMIT,
                                    TEXT_STATE,
                                    "requesterPrincipalId",
                                    "targetOperationId"));
                    yield new ServerControlOperation.ListApprovals(
                            fields.integer(TEXT_OFFSET),
                            fields.integer(TEXT_LIMIT),
                            fields.optionalText(TEXT_STATE).map(ApprovalService.State::valueOf),
                            fields.optionalText("requesterPrincipalId"),
                            fields.optionalText("targetOperationId"));
                }
                case ServerControlOperation.DecideApproval.APPROVE,
                        ServerControlOperation.DecideApproval.REJECT -> {
                    fields.exact(TEXT_APPROVALID, TEXT_JUSTIFICATION);
                    yield new ServerControlOperation.DecideApproval(
                            fields.text(TEXT_APPROVALID),
                            ServerControlOperation.DecideApproval.APPROVE.equals(id)
                                    ? ApprovalService.Choice.APPROVE
                                    : ApprovalService.Choice.REJECT,
                            fields.text(TEXT_JUSTIFICATION));
                }
                case ServerControlOperation.CancelApproval.NAME -> {
                    fields.exact(TEXT_APPROVALID);
                    yield new ServerControlOperation.CancelApproval(fields.text(TEXT_APPROVALID));
                }
                default -> throw new SecurityException(CONTROL_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the breakglass operation family. */
    private static final class ControlBreakGlass {
        private static final Set<String> NAMES =
                Set.of(
                        ServerControlOperation.CreateBreakGlass.CREATE,
                        ServerControlOperation.ActivateBreakGlass.ACTIVATE,
                        ServerControlOperation.InspectBreakGlass.NAME,
                        ServerControlOperation.ListBreakGlass.NAME,
                        ServerControlOperation.RevokeBreakGlass.NAME);

        private static ServerControlOperation decode(
                String id, Fields fields, RealmId realmId, Optional<PkiId> authority) {
            return switch (id) {
                case ServerControlOperation.CreateBreakGlass.CREATE -> {
                    fields.exact(
                            TEXT_BREAKGLASSID,
                            TEXT_PRINCIPALID,
                            TEXT_GRANTID,
                            TEXT_ACTION,
                            TEXT_RESOURCETYPE,
                            TEXT_REASON,
                            TEXT_EXPIRESAT);
                    Permission.Scope scope =
                            new Permission.Scope(
                                    realmId, authority, Optional.empty(), Optional.empty());
                    Permission.Grant grant =
                            new Permission.Grant(
                                    fields.text(TEXT_GRANTID),
                                    fields.text(TEXT_PRINCIPALID),
                                    Permission.Effect.ALLOW,
                                    Permission.Action.valueOf(fields.text(TEXT_ACTION)),
                                    Permission.ResourceType.valueOf(fields.text(TEXT_RESOURCETYPE)),
                                    scope,
                                    Permission.Relationship.ANY,
                                    Permission.DataView.METADATA_REDACTED,
                                    Set.of(),
                                    Optional.of(fields.instant(TEXT_EXPIRESAT)),
                                    true);
                    yield new ServerControlOperation.CreateBreakGlass(
                            fields.text(TEXT_BREAKGLASSID),
                            fields.text(TEXT_PRINCIPALID),
                            grant,
                            fields.text(TEXT_REASON),
                            fields.instant(TEXT_EXPIRESAT));
                }
                case ServerControlOperation.ActivateBreakGlass.ACTIVATE -> {
                    fields.exact(TEXT_BREAKGLASSID);
                    yield new ServerControlOperation.ActivateBreakGlass(
                            fields.text(TEXT_BREAKGLASSID));
                }
                case ServerControlOperation.InspectBreakGlass.NAME -> {
                    fields.exact(TEXT_BREAKGLASSID);
                    yield new ServerControlOperation.InspectBreakGlass(
                            fields.text(TEXT_BREAKGLASSID));
                }
                case ServerControlOperation.ListBreakGlass.NAME -> {
                    fields.exact(TEXT_OFFSET, TEXT_LIMIT);
                    yield new ServerControlOperation.ListBreakGlass(
                            fields.integer(TEXT_OFFSET), fields.integer(TEXT_LIMIT));
                }
                case ServerControlOperation.RevokeBreakGlass.NAME -> {
                    fields.exact(TEXT_BREAKGLASSID);
                    yield new ServerControlOperation.RevokeBreakGlass(
                            fields.text(TEXT_BREAKGLASSID));
                }
                default -> throw new SecurityException(CONTROL_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the configuration operation family. */
    private static final class ControlConfiguration {
        private static final Set<String> NAMES =
                Set.of(
                        ServerControlOperation.ConfigurationChoices.NAME,
                        ServerControlOperation.GenerateManagedKey.NAME);

        private static ServerControlOperation decode(String id, Fields fields) {
            return switch (id) {
                case ServerControlOperation.ConfigurationChoices.NAME -> {
                    fields.allowed(Set.of(TEXT_LIMIT, TEXT_AFTER));
                    yield new ServerControlOperation.ConfigurationChoices(
                            fields.integer(TEXT_LIMIT), fields.optionalText(TEXT_AFTER));
                }
                case ServerControlOperation.GenerateManagedKey.NAME -> {
                    fields.exact("generationId", "parameters");
                    yield new ServerControlOperation.GenerateManagedKey(
                            fields.text("generationId"),
                            zeroecho.pki.spi.crypto.ManagedKeyGeneration.Parameters.valueOf(
                                    fields.text("parameters")));
                }
                default -> throw new SecurityException(CONTROL_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the capabilities operation family. */
    private static final class ControlCapabilities {
        private static final Set<String> NAMES =
                Set.of(
                        ServerControlOperation.ListCapabilities.NAME,
                        ServerControlOperation.EnrollCredentialPublication.NAME,
                        ServerControlOperation.IssueCapability.NAME,
                        ServerControlOperation.RevokeCapability.NAME);

        private static ServerControlOperation decode(String id, Fields fields) {
            return switch (id) {
                case ServerControlOperation.ListCapabilities.NAME -> {
                    fields.allowed(Set.of(TEXT_OBJECTID, TEXT_LIMIT, TEXT_AFTER));
                    yield new ServerControlOperation.ListCapabilities(
                            fields.pkiId(TEXT_OBJECTID),
                            fields.integer(TEXT_LIMIT),
                            fields.optionalText(TEXT_AFTER));
                }
                case ServerControlOperation.EnrollCredentialPublication.NAME -> {
                    fields.allowed(Set.of(TEXT_CREDENTIALID, "ownerPrincipalId"));
                    yield new ServerControlOperation.EnrollCredentialPublication(
                            fields.pkiId(TEXT_CREDENTIALID),
                            fields.optionalText("ownerPrincipalId"));
                }
                case ServerControlOperation.IssueCapability.NAME -> {
                    fields.exact(TEXT_OBJECTID, TEXT_EXPIRESAT);
                    yield new ServerControlOperation.IssueCapability(
                            fields.pkiId(TEXT_OBJECTID), fields.instant(TEXT_EXPIRESAT));
                }
                case ServerControlOperation.RevokeCapability.NAME -> {
                    fields.exact("capabilityId");
                    yield new ServerControlOperation.RevokeCapability(fields.text("capabilityId"));
                }
                default -> throw new SecurityException(CONTROL_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the disclosure operation family. */
    private static final class ControlDisclosure {
        private static final Set<String> NAMES =
                Set.of(
                        ServerControlOperation.InspectDisclosure.NAME,
                        ServerControlOperation.SetDisclosure.NAME);

        private static ServerControlOperation decode(String id, Fields fields) {
            return switch (id) {
                case ServerControlOperation.InspectDisclosure.NAME -> {
                    fields.exact(TEXT_OBJECTID);
                    yield new ServerControlOperation.InspectDisclosure(fields.pkiId(TEXT_OBJECTID));
                }
                case ServerControlOperation.SetDisclosure.NAME -> {
                    fields.exact(TEXT_OBJECTID, "policy");
                    yield new ServerControlOperation.SetDisclosure(
                            fields.pkiId(TEXT_OBJECTID),
                            DisclosureService.Policy.valueOf(fields.text("policy")));
                }
                default -> throw new SecurityException(CONTROL_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the audit operation family. */
    private static final class ControlAudit {
        private static final Set<String> NAMES =
                Set.of(
                        ServerControlOperation.InspectAuditView.REDACTED,
                        ServerControlOperation.InspectAuditView.FULL,
                        ServerControlOperation.InspectAuditView.PII,
                        ServerControlOperation.SearchAudit.NAME,
                        ServerControlOperation.VerifyAuditIntegrity.NAME);

        private static ServerControlOperation decode(String id, Fields fields) {
            return switch (id) {
                case ServerControlOperation.InspectAuditView.REDACTED,
                        ServerControlOperation.InspectAuditView.FULL,
                        ServerControlOperation.InspectAuditView.PII -> {
                    fields.allowed(Set.of(TEXT_OBJECTID, "reasonReference"));
                    Permission.DataView view =
                            ServerControlOperation.InspectAuditView.REDACTED.equals(id)
                                    ? Permission.DataView.METADATA_REDACTED
                                    : ServerControlOperation.InspectAuditView.FULL.equals(id)
                                            ? Permission.DataView.METADATA_FULL
                                            : Permission.DataView.PII_FULL;
                    yield new ServerControlOperation.InspectAuditView(
                            fields.pkiId(TEXT_OBJECTID),
                            view,
                            fields.optionalText("reasonReference"));
                }
                case ServerControlOperation.SearchAudit.NAME -> {
                    fields.allowed(
                            Set.of(
                                    "category",
                                    TEXT_ACTION,
                                    TEXT_AFTER,
                                    "before",
                                    TEXT_OBJECTID,
                                    "principalName",
                                    TEXT_LIMIT));
                    yield new ServerControlOperation.SearchAudit(
                            new zeroecho.pki.api.audit.AuditQuery(
                                    fields.optionalText("category"),
                                    fields.optionalText(TEXT_ACTION),
                                    fields.optionalText(TEXT_AFTER)
                                            .map(HttpSigningOperations::instant),
                                    fields.optionalText("before")
                                            .map(HttpSigningOperations::instant),
                                    fields.optionalText(TEXT_OBJECTID).map(PkiId::new),
                                    fields.optionalText("principalName"),
                                    Map.of(),
                                    fields.integer(TEXT_LIMIT)));
                }
                case ServerControlOperation.VerifyAuditIntegrity.NAME -> {
                    fields.allowed(Set.of("sequence", "recordHash"));
                    Optional<zeroecho.pki.api.audit.AuditChainHead> head =
                            fields.contains("sequence") || fields.contains("recordHash")
                                    ? Optional.of(
                                            new zeroecho.pki.api.audit.AuditChainHead(
                                                    fields.longValue("sequence"),
                                                    fields.text("recordHash")))
                                    : Optional.empty();
                    yield new ServerControlOperation.VerifyAuditIntegrity(head);
                }
                default -> throw new SecurityException(CONTROL_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the repository operation family. */
    private static final class ControlRepository {
        private static final Set<String> NAMES =
                Set.of(
                        ServerControlOperation.InspectRepositoryAlias.NAME,
                        ServerControlOperation.ListRepositoryAliases.NAME,
                        ServerControlOperation.SetRepositoryAlias.NAME,
                        ServerControlOperation.RemoveRepositoryAlias.NAME);

        private static ServerControlOperation decode(String id, Fields fields) {
            return switch (id) {
                case ServerControlOperation.InspectRepositoryAlias.NAME -> {
                    fields.exact(TEXT_AUTHORITYID, TEXT_TYPE);
                    yield new ServerControlOperation.InspectRepositoryAlias(
                            fields.pkiId(TEXT_AUTHORITYID),
                            RepositoryAliasService.Type.valueOf(fields.text(TEXT_TYPE)));
                }
                case ServerControlOperation.ListRepositoryAliases.NAME -> {
                    fields.exact(TEXT_OFFSET, TEXT_LIMIT);
                    yield new ServerControlOperation.ListRepositoryAliases(
                            fields.integer(TEXT_OFFSET), fields.integer(TEXT_LIMIT));
                }
                case ServerControlOperation.SetRepositoryAlias.NAME -> {
                    fields.allowed(
                            Set.of(
                                    TEXT_AUTHORITYID,
                                    TEXT_TYPE,
                                    "targetObjectId",
                                    TEXT_ISSUERID,
                                    "expectedCurrentCommitment"));
                    yield new ServerControlOperation.SetRepositoryAlias(
                            fields.pkiId(TEXT_AUTHORITYID),
                            RepositoryAliasService.Type.valueOf(fields.text(TEXT_TYPE)),
                            fields.pkiId("targetObjectId"),
                            fields.optionalText(TEXT_ISSUERID).map(PkiId::new),
                            fields.optionalText("expectedCurrentCommitment"));
                }
                case ServerControlOperation.RemoveRepositoryAlias.NAME -> {
                    fields.exact(TEXT_AUTHORITYID, TEXT_TYPE, "expectedCurrentCommitment");
                    yield new ServerControlOperation.RemoveRepositoryAlias(
                            fields.pkiId(TEXT_AUTHORITYID),
                            RepositoryAliasService.Type.valueOf(fields.text(TEXT_TYPE)),
                            fields.text("expectedCurrentCommitment"));
                }
                default -> throw new SecurityException(CONTROL_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the acme operation family. */
    private static final class ControlAcme {
        private static final Set<String> NAMES =
                Set.of(
                        ServerControlOperation.RegisterAcmeDirectory.NAME,
                        ServerControlOperation.InspectAcmeDirectory.NAME,
                        ServerControlOperation.ListAcmeDirectories.NAME,
                        ServerControlOperation.SetAcmeDirectoryActive.ACTIVATE,
                        ServerControlOperation.SetAcmeDirectoryActive.DEACTIVATE,
                        ServerControlOperation.InspectAcmeAccount.NAME,
                        ServerControlOperation.ListAcmeAccounts.NAME,
                        ServerControlOperation.DeactivateAcmeAccount.NAME);

        private static ServerControlOperation decode(String id, Fields fields) {
            return switch (id) {
                case ServerControlOperation.RegisterAcmeDirectory.NAME -> {
                    fields.allowed(
                            Set.of(
                                    "alias",
                                    TEXT_AUTHORITYID,
                                    TEXT_PROFILEID,
                                    TEXT_ENROLLMENTPROFILEID,
                                    "dnsNamespaces",
                                    "maximumValidityMillis",
                                    "publicKeyAlgorithms",
                                    "x509BindingPolicies",
                                    "challengeTypes",
                                    "challengeProviderIds",
                                    "eabProviderId",
                                    "eabRequired"));
                    yield new ServerControlOperation.RegisterAcmeDirectory(
                            new AcmeService.DirectoryRegistration(
                                    fields.text("alias"),
                                    fields.pkiId(TEXT_AUTHORITYID),
                                    fields.text(TEXT_PROFILEID),
                                    fields.text(TEXT_ENROLLMENTPROFILEID),
                                    fields.stringSet("dnsNamespaces"),
                                    Duration.ofMillis(fields.longValue("maximumValidityMillis")),
                                    fields.stringSet("publicKeyAlgorithms"),
                                    fields.stringSet("x509BindingPolicies"),
                                    fields.enumSet("challengeTypes", AcmeState.ChallengeType.class),
                                    fields.stringSet("challengeProviderIds"),
                                    fields.optionalText("eabProviderId"),
                                    fields.bool("eabRequired")));
                }
                case ServerControlOperation.InspectAcmeDirectory.NAME -> {
                    fields.exact("directoryId");
                    yield new ServerControlOperation.InspectAcmeDirectory(
                            fields.text("directoryId"));
                }
                case ServerControlOperation.ListAcmeDirectories.NAME -> {
                    fields.exact(TEXT_OFFSET, TEXT_LIMIT);
                    yield new ServerControlOperation.ListAcmeDirectories(
                            fields.integer(TEXT_OFFSET), fields.integer(TEXT_LIMIT));
                }
                case ServerControlOperation.SetAcmeDirectoryActive.ACTIVATE,
                        ServerControlOperation.SetAcmeDirectoryActive.DEACTIVATE -> {
                    fields.exact("directoryId");
                    yield new ServerControlOperation.SetAcmeDirectoryActive(
                            fields.text("directoryId"),
                            ServerControlOperation.SetAcmeDirectoryActive.ACTIVATE.equals(id));
                }
                case ServerControlOperation.InspectAcmeAccount.NAME -> {
                    fields.exact("accountId");
                    yield new ServerControlOperation.InspectAcmeAccount(fields.text("accountId"));
                }
                case ServerControlOperation.ListAcmeAccounts.NAME -> {
                    fields.exact(TEXT_OFFSET, TEXT_LIMIT);
                    yield new ServerControlOperation.ListAcmeAccounts(
                            fields.integer(TEXT_OFFSET), fields.integer(TEXT_LIMIT));
                }
                case ServerControlOperation.DeactivateAcmeAccount.NAME -> {
                    fields.exact("accountId");
                    yield new ServerControlOperation.DeactivateAcmeAccount(
                            fields.text("accountId"));
                }
                default -> throw new SecurityException(CONTROL_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the ocsp operation family. */
    private static final class ControlOcsp {
        private static final Set<String> NAMES =
                Set.of(
                        ServerControlOperation.RegisterOcspResponder.NAME,
                        ServerControlOperation.InspectOcspResponder.NAME,
                        ServerControlOperation.ListOcspResponders.NAME,
                        ServerControlOperation.SetOcspResponderActive.ACTIVATE,
                        ServerControlOperation.SetOcspResponderActive.DEACTIVATE);

        private static ServerControlOperation decode(String id, Fields fields) {
            return switch (id) {
                case ServerControlOperation.RegisterOcspResponder.NAME -> {
                    fields.allowed(
                            Set.of(
                                    TEXT_RESPONDERID,
                                    "alias",
                                    TEXT_AUTHORITYID,
                                    TEXT_ISSUERID,
                                    "signingMode",
                                    "responderCredentialId",
                                    "signingKeyRef",
                                    "chainPathId",
                                    "signatureAlgorithm",
                                    "signatureBindingId",
                                    "signatureBindingCommitment",
                                    "responderIdForm",
                                    "responseValidityMillis",
                                    "noncePolicy",
                                    "maximumNonceBytes",
                                    "acceptedHashes",
                                    "maximumRequestBytes",
                                    "maximumEntries",
                                    "cacheLifetimeMillis",
                                    "requestAuthenticationMode",
                                    "requesterTrustPolicy",
                                    "hybridSdk"));
                    OcspResponderService.RequestAuthenticationMode authenticationMode =
                            OcspResponderService.RequestAuthenticationMode.valueOf(
                                    fields.text("requestAuthenticationMode"));
                    Optional<OcspResponderService.RequesterTrustPolicy> trustPolicy =
                            fields.contains("requesterTrustPolicy")
                                    ? Optional.of(
                                            requesterTrustPolicy(
                                                    fields.object("requesterTrustPolicy")))
                                    : Optional.empty();
                    Optional<OcspResponderService.SdkConfiguration> sdk =
                            fields.contains("hybridSdk")
                                    ? Optional.of(ocspSdk(fields.object("hybridSdk")))
                                    : Optional.empty();
                    yield new ServerControlOperation.RegisterOcspResponder(
                            new OcspResponderService.Registration(
                                    fields.text(TEXT_RESPONDERID),
                                    fields.text("alias"),
                                    fields.pkiId(TEXT_AUTHORITYID),
                                    fields.pkiId(TEXT_ISSUERID),
                                    OcspResponderService.SigningMode.valueOf(
                                            fields.text("signingMode")),
                                    fields.pkiId("responderCredentialId"),
                                    new KeyRef(fields.text("signingKeyRef")),
                                    fields.pkiId("chainPathId"),
                                    fields.text("signatureAlgorithm"),
                                    fields.optionalText("signatureBindingId"),
                                    fields.text("signatureBindingCommitment"),
                                    OcspResponseService.ResponderId.valueOf(
                                            fields.text("responderIdForm")),
                                    Duration.ofMillis(fields.longValue("responseValidityMillis")),
                                    OcspResponderService.NoncePolicy.valueOf(
                                            fields.text("noncePolicy")),
                                    fields.integer("maximumNonceBytes"),
                                    fields.enumSet(
                                            "acceptedHashes", OcspResponseService.CertIdHash.class),
                                    fields.integer("maximumRequestBytes"),
                                    fields.integer("maximumEntries"),
                                    Duration.ofMillis(fields.longValue("cacheLifetimeMillis")),
                                    authenticationMode,
                                    trustPolicy,
                                    sdk));
                }
                case ServerControlOperation.InspectOcspResponder.NAME -> {
                    fields.exact(TEXT_RESPONDERID);
                    yield new ServerControlOperation.InspectOcspResponder(
                            fields.text(TEXT_RESPONDERID));
                }
                case ServerControlOperation.ListOcspResponders.NAME -> {
                    fields.exact(TEXT_OFFSET, TEXT_LIMIT);
                    yield new ServerControlOperation.ListOcspResponders(
                            fields.integer(TEXT_OFFSET), fields.integer(TEXT_LIMIT));
                }
                case ServerControlOperation.SetOcspResponderActive.ACTIVATE,
                        ServerControlOperation.SetOcspResponderActive.DEACTIVATE -> {
                    fields.exact(TEXT_RESPONDERID);
                    yield new ServerControlOperation.SetOcspResponderActive(
                            fields.text(TEXT_RESPONDERID),
                            ServerControlOperation.SetOcspResponderActive.ACTIVATE.equals(id));
                }
                default -> throw new SecurityException(CONTROL_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the backups operation family. */
    private static final class ControlBackups {
        private static final Set<String> NAMES =
                Set.of(
                        ServerControlOperation.ExportBackup.NAME,
                        ServerControlOperation.ReserveBackupUpload.NAME,
                        ServerControlOperation.VerifyBackup.NAME,
                        ServerControlOperation.ExecuteRestore.NAME);

        private static ServerControlOperation decode(String id, Fields fields) {
            return switch (id) {
                case ServerControlOperation.ExportBackup.NAME -> {
                    fields.allowed(Set.of(TEXT_LABEL, "attributes"));
                    yield new ServerControlOperation.ExportBackup(
                            fields.text(TEXT_LABEL),
                            new zeroecho.pki.api.attr.AttributeSet() {
                                @Override
                                public Set<zeroecho.pki.api.attr.AttributeId> ids() {
                                    return Set.of();
                                }

                                @Override
                                public Optional<zeroecho.pki.api.attr.AttributeValue> get(
                                        zeroecho.pki.api.attr.AttributeId id) {
                                    return Optional.empty();
                                }

                                @Override
                                public List<zeroecho.pki.api.attr.AttributeValue> getAll(
                                        zeroecho.pki.api.attr.AttributeId id) {
                                    return List.of();
                                }
                            });
                }
                case ServerControlOperation.ReserveBackupUpload.NAME -> {
                    fields.exact(TEXT_BACKUPID, "length", "sha256");
                    yield new ServerControlOperation.ReserveBackupUpload(
                            new PkiId(fields.text(TEXT_BACKUPID)),
                            fields.longValue("length"),
                            fields.text("sha256"));
                }
                case ServerControlOperation.VerifyBackup.NAME -> {
                    fields.exact(TEXT_BACKUPID, "payload");
                    byte[] verifyBytes = legacyBackup(fields.text("payload"));
                    yield new ServerControlOperation.VerifyBackup(
                            new zeroecho.pki.api.backup.BackupArtifact(
                                    new PkiId(fields.text(TEXT_BACKUPID)),
                                    new EncodedObject(Encoding.BINARY, verifyBytes)));
                }
                case ServerControlOperation.ExecuteRestore.NAME -> {
                    fields.exact(TEXT_BACKUPID, "payload");
                    byte[] restoreBytes = legacyBackup(fields.text("payload"));
                    zeroecho.pki.api.backup.BackupArtifact artifact =
                            new zeroecho.pki.api.backup.BackupArtifact(
                                    new PkiId(fields.text(TEXT_BACKUPID)),
                                    new EncodedObject(Encoding.BINARY, restoreBytes));
                    yield new ServerControlOperation.ExecuteRestore(
                            new zeroecho.pki.api.backup.RestoreRequest(
                                    artifact,
                                    new zeroecho.pki.api.attr.AttributeSet() {
                                        @Override
                                        public Set<zeroecho.pki.api.attr.AttributeId> ids() {
                                            return Set.of();
                                        }

                                        @Override
                                        public Optional<zeroecho.pki.api.attr.AttributeValue> get(
                                                zeroecho.pki.api.attr.AttributeId id) {
                                            return Optional.empty();
                                        }

                                        @Override
                                        public List<zeroecho.pki.api.attr.AttributeValue> getAll(
                                                zeroecho.pki.api.attr.AttributeId id) {
                                            return List.of();
                                        }
                                    }));
                }
                default -> throw new SecurityException(CONTROL_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the backupstreams operation family. */
    private static final class ControlBackupStreams {
        private static final Set<String> NAMES =
                Set.of(
                        ServerControlOperation.ExportBackupStream.NAME,
                        "backup.stream.upload",
                        "backup.stream.download",
                        "backup.stream.verify",
                        "backup.stream.restore",
                        "backup.stream.status",
                        "backup.stream.acknowledge");

        private static ServerControlOperation decode(String id, Fields fields) {
            return switch (id) {
                case ServerControlOperation.ExportBackupStream.NAME -> {
                    fields.exact(TEXT_LABEL);
                    yield new ServerControlOperation.ExportBackupStream(fields.text(TEXT_LABEL));
                }
                case "backup.stream.upload",
                        "backup.stream.download",
                        "backup.stream.verify",
                        "backup.stream.restore",
                        "backup.stream.status",
                        "backup.stream.acknowledge" -> {
                    fields.exact("artifactHandle");
                    ServerControlOperation.BackupArtifactCommand.Action action =
                            Arrays.stream(
                                            ServerControlOperation.BackupArtifactCommand.Action
                                                    .values())
                                    .filter(value -> value.operationId().equals(id))
                                    .findFirst()
                                    .orElseThrow();
                    yield new ServerControlOperation.BackupArtifactCommand(
                            action, fields.text("artifactHandle"), Optional.empty());
                }
                default -> throw new SecurityException(CONTROL_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the est operation family. */
    private static final class ControlEst {
        private static final Set<String> NAMES =
                Set.of(
                        ServerControlOperation.RegisterEstEndpoint.NAME,
                        ServerControlOperation.DeregisterEstEndpoint.NAME,
                        ServerControlOperation.InspectEstEndpoint.NAME,
                        ServerControlOperation.ListEstEndpoints.NAME);

        private static ServerControlOperation decode(String id, Fields fields) {
            return switch (id) {
                case ServerControlOperation.RegisterEstEndpoint.NAME -> {
                    fields.allowed(
                            Set.of(
                                    TEXT_LABEL,
                                    TEXT_AUTHORITYID,
                                    TEXT_PROFILEID,
                                    TEXT_ENROLLMENTPROFILEID,
                                    "keygen"));
                    KeygenPolicy keygen;
                    if (fields.contains("keygen")) {
                        Fields kg = fields.object("keygen");
                        kg.exact(
                                TEXT_ENABLED,
                                "permittedAlgorithms",
                                "maximumKeySizeBits",
                                "storeGeneratedKeys");
                        keygen =
                                new KeygenPolicy(
                                        kg.bool(TEXT_ENABLED),
                                        List.copyOf(kg.stringSet("permittedAlgorithms")),
                                        kg.integer("maximumKeySizeBits"),
                                        kg.bool("storeGeneratedKeys"));
                        kg.complete();
                    } else {
                        keygen = KeygenPolicy.DISABLED;
                    }
                    yield new ServerControlOperation.RegisterEstEndpoint(
                            new EstEndpoint(
                                    fields.text(TEXT_LABEL),
                                    fields.text(TEXT_AUTHORITYID),
                                    fields.text(TEXT_PROFILEID),
                                    fields.text(TEXT_ENROLLMENTPROFILEID),
                                    keygen));
                }
                case ServerControlOperation.DeregisterEstEndpoint.NAME -> {
                    fields.exact(TEXT_LABEL);
                    yield new ServerControlOperation.DeregisterEstEndpoint(fields.text(TEXT_LABEL));
                }
                case ServerControlOperation.InspectEstEndpoint.NAME -> {
                    fields.exact(TEXT_LABEL);
                    yield new ServerControlOperation.InspectEstEndpoint(fields.text(TEXT_LABEL));
                }
                case ServerControlOperation.ListEstEndpoints.NAME -> {
                    fields.exact(TEXT_OFFSET, TEXT_LIMIT);
                    yield new ServerControlOperation.ListEstEndpoints(
                            fields.integer(TEXT_OFFSET), fields.integer(TEXT_LIMIT));
                }
                default -> throw new SecurityException(CONTROL_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the scep operation family. */
    private static final class ControlScep {
        private static final Set<String> NAMES =
                Set.of(
                        ServerControlOperation.RegisterScepEndpoint.NAME,
                        ServerControlOperation.DeregisterScepEndpoint.NAME,
                        ServerControlOperation.InspectScepEndpoint.NAME,
                        ServerControlOperation.ListScepEndpoints.NAME);

        private static ServerControlOperation decode(String id, Fields fields) {
            return switch (id) {
                case ServerControlOperation.RegisterScepEndpoint.NAME -> {
                    fields.allowed(
                            Set.of(
                                    TEXT_LABEL,
                                    TEXT_AUTHORITYID,
                                    TEXT_PROFILEID,
                                    TEXT_ENROLLMENTPROFILEID,
                                    "challengePasswordHash"));
                    yield new ServerControlOperation.RegisterScepEndpoint(
                            new ScepEndpoint(
                                    fields.text(TEXT_LABEL),
                                    fields.text(TEXT_AUTHORITYID),
                                    fields.text(TEXT_PROFILEID),
                                    fields.text(TEXT_ENROLLMENTPROFILEID),
                                    fields.text("challengePasswordHash")));
                }
                case ServerControlOperation.DeregisterScepEndpoint.NAME -> {
                    fields.exact(TEXT_LABEL);
                    yield new ServerControlOperation.DeregisterScepEndpoint(
                            fields.text(TEXT_LABEL));
                }
                case ServerControlOperation.InspectScepEndpoint.NAME -> {
                    fields.exact(TEXT_LABEL);
                    yield new ServerControlOperation.InspectScepEndpoint(fields.text(TEXT_LABEL));
                }
                case ServerControlOperation.ListScepEndpoints.NAME -> {
                    fields.exact(TEXT_OFFSET, TEXT_LIMIT);
                    yield new ServerControlOperation.ListScepEndpoints(
                            fields.integer(TEXT_OFFSET), fields.integer(TEXT_LIMIT));
                }
                default -> throw new SecurityException(CONTROL_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the cmp operation family. */
    private static final class ControlCmp {
        private static final Set<String> NAMES =
                Set.of(
                        ServerControlOperation.RegisterCmpEndpoint.NAME,
                        ServerControlOperation.DeregisterCmpEndpoint.NAME,
                        ServerControlOperation.InspectCmpEndpoint.NAME,
                        ServerControlOperation.ListCmpEndpoints.NAME);

        private static ServerControlOperation decode(String id, Fields fields) {
            return switch (id) {
                case ServerControlOperation.RegisterCmpEndpoint.NAME -> {
                    fields.allowed(
                            Set.of(
                                    TEXT_LABEL,
                                    TEXT_AUTHORITYID,
                                    TEXT_PROFILEID,
                                    TEXT_ENROLLMENTPROFILEID,
                                    "protectionPolicy"));
                    yield new ServerControlOperation.RegisterCmpEndpoint(
                            new CmpEndpoint(
                                    fields.text(TEXT_LABEL),
                                    fields.text(TEXT_AUTHORITYID),
                                    fields.text(TEXT_PROFILEID),
                                    fields.text(TEXT_ENROLLMENTPROFILEID),
                                    CmpProtectionPolicy.valueOf(fields.text("protectionPolicy"))));
                }
                case ServerControlOperation.DeregisterCmpEndpoint.NAME -> {
                    fields.exact(TEXT_LABEL);
                    yield new ServerControlOperation.DeregisterCmpEndpoint(fields.text(TEXT_LABEL));
                }
                case ServerControlOperation.InspectCmpEndpoint.NAME -> {
                    fields.exact(TEXT_LABEL);
                    yield new ServerControlOperation.InspectCmpEndpoint(fields.text(TEXT_LABEL));
                }
                case ServerControlOperation.ListCmpEndpoints.NAME -> {
                    fields.exact(TEXT_OFFSET, TEXT_LIMIT);
                    yield new ServerControlOperation.ListCmpEndpoints(
                            fields.integer(TEXT_OFFSET), fields.integer(TEXT_LIMIT));
                }
                default -> throw new SecurityException(CONTROL_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the enrollmentregistration operation family. */
    private static final class ControlEnrollmentRegistration {
        private static final Set<String> NAMES =
                Set.of(ServerControlOperation.RegisterEnrollmentProfile.NAME);

        private static ServerControlOperation decode(String id, Fields fields) {
            if (!NAMES.contains(id)) {
                throw new SecurityException(CONTROL_NOT_EXPOSED);
            }

            fields.allowed(
                    Set.of(
                            "id",
                            TEXT_DISPLAYNAME,
                            "certificateProfileId",
                            TEXT_ALLOWEDAUTHORITYIDS,
                            TEXT_SUBJECTDNPATTERN,
                            TEXT_REQUIREDSANDOMAINS,
                            TEXT_REQUIREAPPROVAL,
                            TEXT_SDKPROFILE));
            Set<String> allowedAuthorityIds =
                    fields.contains(TEXT_ALLOWEDAUTHORITYIDS)
                            ? fields.stringSet(TEXT_ALLOWEDAUTHORITYIDS)
                            : Set.of();
            Optional<String> subjectDnPattern =
                    fields.contains(TEXT_SUBJECTDNPATTERN)
                            ? Optional.of(fields.text(TEXT_SUBJECTDNPATTERN))
                            : Optional.empty();
            List<String> requiredSanDomains =
                    fields.contains(TEXT_REQUIREDSANDOMAINS)
                            ? List.copyOf(fields.stringSet(TEXT_REQUIREDSANDOMAINS))
                            : List.of();
            boolean requireApproval =
                    fields.contains(TEXT_REQUIREAPPROVAL) && fields.bool(TEXT_REQUIREAPPROVAL);
            return new ServerControlOperation.RegisterEnrollmentProfile(
                    new EnrollmentProfile(
                            fields.text("id"),
                            fields.text(TEXT_DISPLAYNAME),
                            EnrollmentProfileState.ACTIVE,
                            fields.text("certificateProfileId"),
                            allowedAuthorityIds,
                            subjectDnPattern,
                            requiredSanDomains,
                            requireApproval,
                            fields.contains(TEXT_SDKPROFILE)
                                    ? Optional.of(fields.text(TEXT_SDKPROFILE))
                                    : Optional.empty()));
        }
    }

    /** Strict field decoding for the enrollmentupdate operation family. */
    private static final class ControlEnrollmentUpdate {
        private static final Set<String> NAMES =
                Set.of(ServerControlOperation.UpdateEnrollmentProfile.NAME);

        private static ServerControlOperation decode(String id, Fields fields) {
            if (!NAMES.contains(id)) {
                throw new SecurityException(CONTROL_NOT_EXPOSED);
            }

            fields.allowed(
                    Set.of(
                            "id",
                            TEXT_DISPLAYNAME,
                            "certificateProfileId",
                            TEXT_ALLOWEDAUTHORITYIDS,
                            TEXT_SUBJECTDNPATTERN,
                            TEXT_REQUIREDSANDOMAINS,
                            TEXT_REQUIREAPPROVAL,
                            TEXT_SDKPROFILE,
                            TEXT_STATE));
            Set<String> allowedAuthorityIds =
                    fields.contains(TEXT_ALLOWEDAUTHORITYIDS)
                            ? fields.stringSet(TEXT_ALLOWEDAUTHORITYIDS)
                            : Set.of();
            Optional<String> subjectDnPattern =
                    fields.contains(TEXT_SUBJECTDNPATTERN)
                            ? Optional.of(fields.text(TEXT_SUBJECTDNPATTERN))
                            : Optional.empty();
            List<String> requiredSanDomains =
                    fields.contains(TEXT_REQUIREDSANDOMAINS)
                            ? List.copyOf(fields.stringSet(TEXT_REQUIREDSANDOMAINS))
                            : List.of();
            boolean requireApproval =
                    fields.contains(TEXT_REQUIREAPPROVAL) && fields.bool(TEXT_REQUIREAPPROVAL);
            EnrollmentProfileState state =
                    fields.contains(TEXT_STATE)
                            ? EnrollmentProfileState.valueOf(fields.text(TEXT_STATE))
                            : EnrollmentProfileState.ACTIVE;
            return new ServerControlOperation.UpdateEnrollmentProfile(
                    new EnrollmentProfile(
                            fields.text("id"),
                            fields.text(TEXT_DISPLAYNAME),
                            state,
                            fields.text("certificateProfileId"),
                            allowedAuthorityIds,
                            subjectDnPattern,
                            requiredSanDomains,
                            requireApproval,
                            fields.contains(TEXT_SDKPROFILE)
                                    ? Optional.of(fields.text(TEXT_SDKPROFILE))
                                    : Optional.empty()));
        }
    }

    /** Strict field decoding for the enrollmentprofiles operation family. */
    private static final class ControlEnrollmentProfiles {
        private static final Set<String> NAMES =
                Set.of(
                        ServerControlOperation.InspectEnrollmentProfile.NAME,
                        ServerControlOperation.ListEnrollmentProfiles.NAME,
                        ServerControlOperation.ActivateEnrollmentProfile.NAME,
                        ServerControlOperation.SuspendEnrollmentProfile.NAME);

        private static ServerControlOperation decode(String id, Fields fields) {
            return switch (id) {
                case ServerControlOperation.InspectEnrollmentProfile.NAME -> {
                    fields.exact("id");
                    yield new ServerControlOperation.InspectEnrollmentProfile(fields.text("id"));
                }
                case ServerControlOperation.ListEnrollmentProfiles.NAME -> {
                    fields.exact(TEXT_OFFSET, TEXT_LIMIT);
                    yield new ServerControlOperation.ListEnrollmentProfiles(
                            fields.integer(TEXT_OFFSET), fields.integer(TEXT_LIMIT));
                }
                case ServerControlOperation.ActivateEnrollmentProfile.NAME -> {
                    fields.exact("id");
                    yield new ServerControlOperation.ActivateEnrollmentProfile(fields.text("id"));
                }
                case ServerControlOperation.SuspendEnrollmentProfile.NAME -> {
                    fields.exact("id");
                    yield new ServerControlOperation.SuspendEnrollmentProfile(fields.text("id"));
                }
                default -> throw new SecurityException(CONTROL_NOT_EXPOSED);
            };
        }
    }

    /** Strict field decoding for the enrollmentrequests operation family. */
    private static final class ControlEnrollmentRequests {
        private static final Set<String> NAMES =
                Set.of(
                        ServerControlOperation.InspectEnrollmentRequest.NAME,
                        ServerControlOperation.ListEnrollmentRequests.NAME,
                        ServerControlOperation.DecideEnrollmentRequest.APPROVE,
                        ServerControlOperation.DecideEnrollmentRequest.REJECT);

        private static ServerControlOperation decode(String id, Fields fields) {
            return switch (id) {
                case ServerControlOperation.InspectEnrollmentRequest.NAME -> {
                    fields.exact("id");
                    yield new ServerControlOperation.InspectEnrollmentRequest(fields.text("id"));
                }
                case ServerControlOperation.ListEnrollmentRequests.NAME -> {
                    fields.exact(TEXT_OFFSET, TEXT_LIMIT);
                    yield new ServerControlOperation.ListEnrollmentRequests(
                            fields.integer(TEXT_OFFSET), fields.integer(TEXT_LIMIT));
                }
                case ServerControlOperation.DecideEnrollmentRequest.APPROVE,
                        ServerControlOperation.DecideEnrollmentRequest.REJECT -> {
                    fields.exact("id", "expectedCommitment", TEXT_JUSTIFICATION);
                    yield new ServerControlOperation.DecideEnrollmentRequest(
                            fields.text("id"),
                            fields.text("expectedCommitment"),
                            ServerControlOperation.DecideEnrollmentRequest.APPROVE.equals(id)
                                    ? ApprovalService.Choice.APPROVE
                                    : ApprovalService.Choice.REJECT,
                            fields.text(TEXT_JUSTIFICATION));
                }
                default -> throw new SecurityException(CONTROL_NOT_EXPOSED);
            };
        }
    }

    /** Projects the existing signingscope authorization coordinates. */
    private static final class SigningScope {
        private static void validateAuthority(
                PkiSigningOperation operation, Optional<PkiId> authority) {
            Optional<PkiId> embedded =
                    switch (operation) {
                        case PkiSigningOperation.IssueOcspResponderCertificate value ->
                                Optional.of(value.request().authorityId());
                        case PkiSigningOperation.IssueCredential value ->
                                Optional.of(value.issuerCaId());
                        case PkiSigningOperation.GenerateStatus value ->
                                Optional.of(value.issuerCaId());
                        case PkiSigningOperation.RolloverCaCertificate value ->
                                Optional.of(value.caId());
                        case PkiSigningOperation.RotateCaKey value -> Optional.of(value.caId());
                        case PkiSigningOperation.CreateIntermediate value ->
                                Optional.of(value.issuerCaId());
                        case PkiSigningOperation.IssueIntermediateCertificate value ->
                                Optional.of(value.issuerCaId());
                        default -> Optional.empty();
                    };
            if (embedded.isPresent() && !embedded.equals(authority)) {
                throw new IllegalArgumentException("Operation and authority scope differ");
            }
        }

        private static Optional<String> profile(PkiSigningOperation operation) {
            return switch (operation) {
                case PkiSigningOperation.IssueOcspResponderCertificate value ->
                        Optional.of(value.request().intent().expectedProfile().profileId());
                case PkiSigningOperation.IssueCredential value -> Optional.of(value.profileId());
                case PkiSigningOperation.ReplaceCredential value -> Optional.of(value.profileId());
                case PkiSigningOperation.CreateIntermediate value -> Optional.of(value.profileId());
                case PkiSigningOperation.IssueIntermediateCertificate value ->
                        Optional.of(value.profileId());
                default -> Optional.empty();
            };
        }

        private static Optional<PkiId> objectId(PkiSigningOperation operation) {
            return switch (operation) {
                case PkiSigningOperation.RenewCredential value -> Optional.of(value.credentialId());
                case PkiSigningOperation.ReplaceCredential value ->
                        Optional.of(value.existingCredentialId());
                case PkiSigningOperation.ReissueCredential value ->
                        Optional.of(value.credentialId());
                case PkiSigningOperation.RolloverCaCertificate value -> Optional.of(value.caId());
                case PkiSigningOperation.RotateCaKey value -> Optional.of(value.caId());
                case PkiSigningOperation.IssueIntermediateCertificate value ->
                        Optional.of(value.subjectCaId());
                default -> Optional.empty();
            };
        }
    }

    /** Projects the existing domainscope authorization coordinates. */
    private static final class DomainScope {
        private static void validateAuthority(PkiOperation operation, Optional<PkiId> authority) {
            Optional<PkiId> embedded =
                    switch (operation) {
                        case PkiOperation.InspectAuthority value -> Optional.of(value.caId());
                        case PkiOperation.TransitionAuthority value -> Optional.of(value.caId());
                        case PkiOperation.ListStatus value -> Optional.of(value.issuerCaId());
                        case PkiOperation.SearchCredentials value ->
                                Optional.of(value.authorityId());
                        case PkiOperation.ListCredentials value -> Optional.of(value.authorityId());
                        case PkiOperation.ListIssuerGenerations value ->
                                Optional.of(value.authorityId());
                        case PkiOperation.ListPendingCredentialConfirmations value ->
                                Optional.of(value.authorityId());
                        case PkiOperation.SelectIssuancePath value -> Optional.of(value.caId());
                        case PkiOperation.RegisterIssuerChainPath value ->
                                Optional.of(value.caId());
                        case PkiOperation.SetStatusSchedule value -> Optional.of(value.caId());
                        case PkiOperation.InspectStatusSchedule value -> Optional.of(value.caId());
                        case PkiOperation.QueryAuthorityMetrics value -> Optional.of(value.caId());
                        case PkiOperation.QueryCertificateMetrics value ->
                                Optional.of(value.caId());
                        case PkiOperation.QueryRevocationMetrics value -> Optional.of(value.caId());
                        case PkiOperation.QueryPublicationMetrics value ->
                                Optional.of(value.caId());
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
                case PkiOperation.ListPendingCredentialConfirmations value -> value.profileId();
                default -> Optional.empty();
            };
        }

        private static Optional<PkiId> objectId(PkiOperation operation) {
            return switch (operation) {
                case PkiOperation.InspectAuthority value -> Optional.of(value.caId());
                case PkiOperation.TransitionAuthority value -> Optional.of(value.caId());
                case PkiOperation.InspectCredential value -> Optional.of(value.credentialId());
                case PkiOperation.IssueCredentialConfirmationChallenge value ->
                        Optional.of(value.credentialId());
                case PkiOperation.CompleteCredentialConfirmationProof value ->
                        Optional.of(value.submission().proofCas().credentialId());
                case PkiOperation.RevokePendingCredentialConfirmation value ->
                        Optional.of(value.credentialId());
                case PkiOperation.RevokeCredential value -> Optional.of(value.credentialId());
                case PkiOperation.HoldCredential value -> Optional.of(value.credentialId());
                case PkiOperation.UnholdCredential value -> Optional.of(value.credentialId());
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
                case PkiOperation.InspectIssuerGeneration value -> Optional.of(value.issuerId());
                case PkiOperation.InspectIssuerChainPath value -> Optional.of(value.pathId());
                case PkiOperation.ListIssuerChainPaths value -> Optional.of(value.issuerId());
                case PkiOperation.SelectIssuancePath value -> Optional.of(value.caId());
                case PkiOperation.RegisterIssuerChainPath value -> Optional.of(value.caId());
                default -> Optional.empty();
            };
        }

        private static boolean realmWide(PkiOperation operation) {
            return operation instanceof PkiOperation.ListProfiles
                    || operation instanceof PkiOperation.QueryServerMetrics
                    || operation instanceof PkiOperation.ListStatusSchedules
                    || operation instanceof PkiOperation.ListRequests
                    || operation instanceof PkiOperation.ListAuthorities
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

        private static Optional<String> operatorJustification(PkiOperation operation) {
            return switch (operation) {
                case PkiOperation.RevokeCredential value -> value.operatorJustification();
                case PkiOperation.HoldCredential value -> value.operatorJustification();
                case PkiOperation.UnholdCredential value -> value.operatorJustification();
                case PkiOperation.RevokePendingCredentialConfirmation value ->
                        value.operatorJustification();
                case PkiOperation.TransitionAuthority value -> Optional.of(value.reason());
                default -> Optional.empty();
            };
        }
    }

    /** Projects the existing controlscope authorization coordinates. */
    private static final class ControlScope {
        private static Permission.Scope controlScope(
                ServerControlOperation operation, RealmId realmId, Optional<PkiId> authority) {
            if (operation.name().startsWith("backup.stream.") && authority.isPresent()) {
                throw new IllegalArgumentException("Backup transfers require realm scope");
            }
            return switch (operation) {
                case ServerControlOperation.ConfigurationChoices ignored -> {
                    if (authority.isPresent()) {
                        throw new IllegalArgumentException(
                                "Configuration choices require realm scope");
                    }
                    yield new Permission.Scope(
                            realmId, Optional.empty(), Optional.empty(), Optional.empty());
                }
                case ServerControlOperation.GenerateManagedKey ignored -> {
                    if (authority.isPresent()) {
                        throw new IllegalArgumentException("Managed keys require realm scope");
                    }
                    yield new Permission.Scope(
                            realmId, Optional.empty(), Optional.empty(), Optional.empty());
                }
                case ServerControlOperation.ListCapabilities ignored -> {
                    if (authority.isPresent()) {
                        throw new IllegalArgumentException(
                                "Capability selection resolves authoritative object scope");
                    }
                    yield new Permission.Scope(
                            realmId, Optional.empty(), Optional.empty(), Optional.empty());
                }
                case ServerControlOperation.CreateRoleAssignment value ->
                        value.assignment().scope();
                case ServerControlOperation.CreateGrant value -> value.grant().scope();
                case ServerControlOperation.EvaluateAuthorization value -> value.resource().scope();
                case ServerControlOperation.RequestApproval value -> value.targetResource().scope();
                case ServerControlOperation.CreateBreakGlass value -> value.grant().scope();
                case ServerControlOperation.EnrollCredentialPublication ignored -> {
                    if (authority.isPresent()) {
                        throw new IllegalArgumentException(
                                "Credential publication resolves authority from issuance");
                    }
                    yield new Permission.Scope(
                            realmId, Optional.empty(), Optional.empty(), Optional.empty());
                }
                case ServerControlOperation.InspectRepositoryAlias value ->
                        authorityScope(realmId, authority, value.authorityId());
                case ServerControlOperation.SetRepositoryAlias value ->
                        authorityScope(realmId, authority, value.authorityId());
                case ServerControlOperation.RemoveRepositoryAlias value ->
                        authorityScope(realmId, authority, value.authorityId());
                case ServerControlOperation.RegisterAcmeDirectory value -> {
                    Permission.Scope checked =
                            authorityScope(realmId, authority, value.registration().authorityId());
                    yield new Permission.Scope(
                            checked.realmId(),
                            checked.authorityId(),
                            Optional.empty(),
                            Optional.of(value.registration().profileId()));
                }
                case ServerControlOperation.RegisterOcspResponder value ->
                        new Permission.Scope(
                                realmId,
                                Optional.of(value.registration().authorityId()),
                                Optional.of(value.registration().issuerId()),
                                Optional.empty());
                default ->
                        new Permission.Scope(
                                realmId, authority, Optional.empty(), Optional.empty());
            };
        }

        private static Optional<PkiId> controlObject(ServerControlOperation operation) {
            return switch (operation) {
                case ServerControlOperation.ListCapabilities value -> Optional.of(value.objectId());
                case ServerControlOperation.InspectDisclosure value ->
                        Optional.of(value.objectId());
                case ServerControlOperation.SetDisclosure value -> Optional.of(value.objectId());
                case ServerControlOperation.EnrollCredentialPublication value ->
                        Optional.of(value.credentialId());
                case ServerControlOperation.IssueCapability value -> Optional.of(value.objectId());
                case ServerControlOperation.InspectAuditView value -> Optional.of(value.objectId());
                case ServerControlOperation.SetRepositoryAlias value ->
                        Optional.of(value.targetObjectId());
                default -> Optional.empty();
            };
        }

        private static Permission.Scope authorityScope(
                RealmId realmId, Optional<PkiId> requested, PkiId embedded) {
            if (requested.isEmpty() || !requested.orElseThrow().equals(embedded)) {
                throw new IllegalArgumentException("Repository alias and authority scope differ");
            }
            return new Permission.Scope(realmId, requested, Optional.empty(), Optional.empty());
        }
    }

    private static void requireAuthorityPresence(boolean realmWide, Optional<PkiId> authority) {
        if (realmWide == authority.isPresent()) {
            throw new IllegalArgumentException(
                    realmWide
                            ? "Realm-wide operation must not specify authorityId"
                            : "Authority-scoped operation requires authorityId");
        }
    }

    /** Selects one closed securitycontrols decoder without consuming fields during lookup. */
    private static final class SecurityControls {
        private static ServerControlOperation decode(
                String id,
                Fields fields,
                RealmId realmId,
                Optional<PkiId> authority,
                java.util.function.Function<String, OperationSecurityDescriptors.Descriptor>
                        descriptors) {
            if (ControlPrincipals.NAMES.contains(id)) {
                return ControlPrincipals.decode(id, fields);
            }
            if (ControlRoles.NAMES.contains(id)) {
                return ControlRoles.decode(id, fields, realmId, authority);
            }
            if (ControlGrants.NAMES.contains(id)) {
                return ControlGrants.decode(id, fields, realmId, authority);
            }
            if (ControlApprovals.NAMES.contains(id)) {
                return ControlApprovals.decode(id, fields, realmId, descriptors);
            }
            if (ControlBreakGlass.NAMES.contains(id)) {
                return ControlBreakGlass.decode(id, fields, realmId, authority);
            }
            if (ControlConfiguration.NAMES.contains(id)) {
                return ControlConfiguration.decode(id, fields);
            }
            if (ControlCapabilities.NAMES.contains(id)) {
                return ControlCapabilities.decode(id, fields);
            }
            if (ControlDisclosure.NAMES.contains(id)) {
                return ControlDisclosure.decode(id, fields);
            }
            if (ControlAudit.NAMES.contains(id)) {
                return ControlAudit.decode(id, fields);
            }
            if (ControlRepository.NAMES.contains(id)) {
                return ControlRepository.decode(id, fields);
            }
            return null;
        }
    }

    /** Selects one closed protocolcontrols decoder without consuming fields during lookup. */
    private static final class ProtocolControls {
        private static ServerControlOperation decode(String id, Fields fields) {
            if (ControlAcme.NAMES.contains(id)) {
                return ControlAcme.decode(id, fields);
            }
            if (ControlOcsp.NAMES.contains(id)) {
                return ControlOcsp.decode(id, fields);
            }
            if (ControlBackups.NAMES.contains(id)) {
                return ControlBackups.decode(id, fields);
            }
            if (ControlBackupStreams.NAMES.contains(id)) {
                return ControlBackupStreams.decode(id, fields);
            }
            if (ControlEst.NAMES.contains(id)) {
                return ControlEst.decode(id, fields);
            }
            if (ControlScep.NAMES.contains(id)) {
                return ControlScep.decode(id, fields);
            }
            if (ControlCmp.NAMES.contains(id)) {
                return ControlCmp.decode(id, fields);
            }
            if (ControlEnrollmentRegistration.NAMES.contains(id)) {
                return ControlEnrollmentRegistration.decode(id, fields);
            }
            if (ControlEnrollmentUpdate.NAMES.contains(id)) {
                return ControlEnrollmentUpdate.decode(id, fields);
            }
            if (ControlEnrollmentProfiles.NAMES.contains(id)) {
                return ControlEnrollmentProfiles.decode(id, fields);
            }
            if (ControlEnrollmentRequests.NAMES.contains(id)) {
                return ControlEnrollmentRequests.decode(id, fields);
            }
            throw new SecurityException(CONTROL_NOT_EXPOSED);
        }
    }
}
