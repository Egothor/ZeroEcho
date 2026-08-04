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
import zeroecho.pki.server.Permission;
import zeroecho.pki.server.RealmId;

/** Closed strict HTTP decoding for operations exposed by the existing gateway. */
@SuppressWarnings("PMD")
final class HttpOperationCodec {
    /** Fully decoded gateway input excluding authenticated principal and request ID. */
    record Decoded(PkiOperation operation, Permission.Resource resource, Permission.Context context,
            Optional<String> approvalId, Optional<Duration> requestedDeadline) { }

    private HttpOperationCodec() {
    }

    static Decoded decode(String operationId, byte[] document, int maximumBytes, RealmId realmId,
            java.util.function.Function<PkiOperation, OperationSecurityDescriptors.Descriptor> descriptors) {
        Fields root = Fields.of(StrictJson.parse(document, maximumBytes));
        root.allowed(Set.of("version", "authorityId", "approvalId", "deadline", "arguments"));
        if (root.integer("version") != 1) throw new IllegalArgumentException("Request version is unsupported");
        Optional<PkiId> authority = root.optionalText("authorityId").map(PkiId::new);
        Optional<String> approval = root.optionalText("approvalId");
        approval.ifPresent(value -> requireId(value, "approval ID"));
        Optional<Duration> deadline = root.optionalText("deadline").map(HttpOperationCodec::duration);
        Fields arguments = root.object("arguments");
        PkiOperation operation = operation(operationId, arguments);
        arguments.complete();
        root.complete();
        OperationSecurityDescriptors.Descriptor descriptor = descriptors.apply(operation);
        boolean realmWide = realmWide(operation);
        if (realmWide == authority.isPresent()) {
            throw new IllegalArgumentException(realmWide
                    ? "Realm-wide operation must not specify authorityId"
                    : "Authority-scoped operation requires authorityId");
        }
        validateAuthority(operation, authority);
        Permission.Scope scope = new Permission.Scope(realmId, authority, Optional.empty(), profile(operation));
        Optional<PkiId> objectId = objectId(operation);
        Permission.Resource resource = new Permission.Resource(descriptor.resourceType(), scope, objectId,
                Optional.empty());
        Optional<String> reason = operation instanceof PkiOperation.TransitionAuthority transition
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
        PkiId pkiId(String name) { return new PkiId(text(name)); }
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
