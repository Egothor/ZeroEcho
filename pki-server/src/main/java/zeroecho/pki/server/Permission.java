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
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.pki.api.PkiId;

/** Closed permission vocabulary and immutable scoped grant model. */
@SuppressWarnings({ "PMD.ExcessivePublicCount", "PMD.ControlStatementBraces",
        "PMD.AvoidLiteralsInIfCondition", "PMD.CommentDefaultAccessModifier" })
public final class Permission {
    private Permission() {
    }

    /** Stable permission actions; semantic separation is part of the public contract. */
    public enum Action {
        REALM_READ(1), SERVER_HEALTH_READ(2), SERVER_CONFIGURATION_READ(3),
        SERVER_CONFIGURATION_UPDATE(4), IDENTITY_PROVIDER_MANAGE(5), PRINCIPAL_MANAGE(6),
        ROLE_MANAGE(7), PERMISSION_GRANT(8), AUTHORITY_LIST(20), AUTHORITY_READ(21),
        AUTHORITY_CREATE(22), AUTHORITY_IMPORT(23), AUTHORITY_ACTIVATE(24), AUTHORITY_SUSPEND(25),
        AUTHORITY_RETIRE(26), ISSUER_CREATE(27), ISSUER_ROTATE(28), ISSUER_RETIRE(29),
        CA_CHAIN_DOWNLOAD(30), PROFILE_READ(40), PROFILE_REGISTER(41), PROFILE_VALIDATE(42),
        PROFILE_ACTIVATE(43), PROFILE_DEACTIVATE(44), POLICY_READ(45), POLICY_UPDATE(46),
        X509_BINDING_READ(47), X509_BINDING_PROVIDER_ENABLE(48), REQUEST_SUBMIT(60),
        REQUEST_READ_OWN(61), REQUEST_READ_ANY(62), REQUEST_APPROVE(63), REQUEST_REJECT(64),
        REQUEST_CANCEL(65), CERTIFICATE_ISSUE(70), CERTIFICATE_RENEW(71), CERTIFICATE_REKEY(72),
        CERTIFICATE_READ_METADATA(73), CERTIFICATE_READ_CONTENT(74), CERTIFICATE_SEARCH(75),
        CERTIFICATE_READ_PII(76), CERTIFICATE_DOWNLOAD(77), CERTIFICATE_PUBLICATION_CHANGE(78),
        CERTIFICATE_REVOKE(80), CERTIFICATE_HOLD(81), CERTIFICATE_RELEASE_HOLD(82),
        REVOCATION_HISTORY_READ(83), CRL_GENERATE(84), CRL_PUBLISH(85), CRL_DOWNLOAD(86),
        OCSP_ADMINISTER(87), PUBLICATION_REGISTER(100), PUBLICATION_READ(101),
        PUBLICATION_PROCESS(102), PUBLICATION_RETRY(103), PUBLICATION_RECONCILE(104),
        AUDIT_READ_REDACTED(120), AUDIT_READ_FULL(121), AUDIT_READ_PII(122), AUDIT_EXPORT(123),
        AUDIT_INTEGRITY_VERIFY(124), BACKUP_EXPORT(140), BACKUP_VERIFY(141), RESTORE_EXECUTE(142);

        private final int code;

        Action(int code) {
            this.code = code;
        }

        /** @return stable persistence code */
        public int code() {
            return code;
        }

        /** Resolves a stable persistence code. */
        public static Action fromCode(int code) {
            for (Action candidate : values()) {
                if (candidate.code == code) {
                    return candidate;
                }
            }
            throw new IllegalArgumentException("Unknown permission action code");
        }
    }

    /** Grant effect. */
    public enum Effect {
        ALLOW(1), DENY(2);
        private final int code;
        Effect(int code) { this.code = code; }
        /** @return stable code */ public int code() { return code; }
        /** Resolves a stable code. */
        public static Effect fromCode(int code) {
            return switch (code) { case 1 -> ALLOW; case 2 -> DENY;
                default -> throw new IllegalArgumentException("Unknown grant effect code"); };
        }
    }

    /** Security resource types, distinct from PKI authority ownership. */
    public enum ResourceType {
        REALM(1), SERVER_CONFIGURATION(2), PRINCIPAL(3), ROLE(4), GRANT(5), AUTHORITY(10),
        ISSUER(11), PROFILE(12), POLICY(13), X509_BINDING(14), REQUEST(20), CERTIFICATE(21),
        REVOCATION(22), STATUS_OBJECT(23), PUBLICATION(24), AUDIT(30), BACKUP(31), RESTORE(32),
        DISCLOSURE(33), CAPABILITY(34);
        private final int code;
        ResourceType(int code) { this.code = code; }
        /** @return stable code */ public int code() { return code; }
        /** Resolves a stable code. */
        public static ResourceType fromCode(int code) {
            for (ResourceType candidate : values()) if (candidate.code == code) return candidate;
            throw new IllegalArgumentException("Unknown resource type code");
        }
    }

    /** Relationship between the requesting principal and the target object. */
    public enum Relationship {
        OWN(1), ANY(2);
        private final int code;
        Relationship(int code) { this.code = code; }
        /** @return stable code */ public int code() { return code; }
        /** Resolves a stable code. */
        public static Relationship fromCode(int code) {
            return switch (code) { case 1 -> OWN; case 2 -> ANY;
                default -> throw new IllegalArgumentException("Unknown relationship code"); };
        }
    }

    /** Explicitly separated disclosure and audit data views. */
    public enum DataView {
        METADATA_REDACTED(1), METADATA_FULL(2), CONTENT_FULL(3), PII_FULL(4);
        private final int code;
        DataView(int code) { this.code = code; }
        /** @return stable code */ public int code() { return code; }
        /** Resolves a stable code. */
        public static DataView fromCode(int code) {
            return switch (code) { case 1 -> METADATA_REDACTED; case 2 -> METADATA_FULL;
                case 3 -> CONTENT_FULL; case 4 -> PII_FULL;
                default -> throw new IllegalArgumentException("Unknown data-view code"); };
        }

        /** Tests view sufficiency without merging content and PII authority. */
        public boolean permits(DataView requested) {
            Objects.requireNonNull(requested, "requested");
            return this == requested || this == METADATA_FULL && requested == METADATA_REDACTED;
        }
    }

    /** Closed non-programmable grant conditions. */
    public enum Condition {
        REASON_REQUIRED(1), APPROVAL_REQUIRED(2), REQUESTER_APPROVER_SEPARATION(3),
        AUTHORITY_ACTIVE(4), PROFILE_MATCH_REQUIRED(5);
        private final int code;
        Condition(int code) { this.code = code; }
        /** @return stable code */ public int code() { return code; }
        /** Resolves a stable code. */
        public static Condition fromCode(int code) {
            for (Condition candidate : values()) if (candidate.code == code) return candidate;
            throw new IllegalArgumentException("Unknown condition code");
        }
    }

    /**
     * Canonical resource scope supplied independently of object contents.
     *
     * @param realmId realm identity
     * @param authorityId explicit logical authority when applicable
     * @param issuerId explicit issuer generation when applicable
     * @param profileId explicit profile when applicable
     */
    public record Scope(RealmId realmId, Optional<PkiId> authorityId, Optional<PkiId> issuerId,
            Optional<String> profileId) {
        /** Validates the exact finite scope. */
        public Scope {
            Objects.requireNonNull(realmId, "realmId");
            authorityId = Objects.requireNonNull(authorityId, "authorityId");
            issuerId = Objects.requireNonNull(issuerId, "issuerId");
            profileId = Objects.requireNonNull(profileId, "profileId").map(Permission::requireProfile);
            if (issuerId.isPresent() && authorityId.isEmpty()) {
                throw new IllegalArgumentException("Issuer scope requires authority scope");
            }
        }
    }

    /**
     * Transport-neutral target reference. Possession is never authorization.
     *
     * @param type resource type
     * @param scope exact security scope
     * @param objectId optional canonical object identity
     * @param ownerPrincipalId optional owning principal identity
     */
    public record Resource(ResourceType type, Scope scope, Optional<PkiId> objectId,
            Optional<String> ownerPrincipalId) {
        /** Validates the finite resource reference. */
        public Resource {
            Objects.requireNonNull(type, "type");
            Objects.requireNonNull(scope, "scope");
            objectId = Objects.requireNonNull(objectId, "objectId");
            ownerPrincipalId = Objects.requireNonNull(ownerPrincipalId, "ownerPrincipalId")
                    .map(Permission::requirePrincipal);
        }

        /** @return whether the principal owns this object */
        public boolean ownedBy(SecurityPrincipal principal) {
            Objects.requireNonNull(principal, "principal");
            return ownerPrincipalId.filter(principal.principalId()::equals).isPresent();
        }
    }

    /**
     * Immutable persisted permission grant.
     *
     * @param grantId stable grant identity
     * @param principalId grantee identity
     * @param effect allow or deny
     * @param action exact action
     * @param resourceType exact resource type
     * @param scope exact non-wildcard realm and optional subscopes
     * @param relationship own or any
     * @param dataView maximum exact view
     * @param conditions closed conditions
     * @param expiresAt optional mandatory upper bound for temporary grants
     * @param enabled whether the grant participates in decisions
     */
    public record Grant(String grantId, String principalId, Effect effect, Action action,
            ResourceType resourceType, Scope scope, Relationship relationship, DataView dataView,
            Set<Condition> conditions, Optional<Instant> expiresAt, boolean enabled) {
        /** Validates and snapshots the finite grant. */
        public Grant {
            requireId(grantId, "grant");
            requirePrincipal(principalId);
            Objects.requireNonNull(effect, "effect");
            Objects.requireNonNull(action, "action");
            Objects.requireNonNull(resourceType, "resourceType");
            Objects.requireNonNull(scope, "scope");
            Objects.requireNonNull(relationship, "relationship");
            Objects.requireNonNull(dataView, "dataView");
            conditions = Set.copyOf(Objects.requireNonNull(conditions, "conditions"));
            expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
        }
    }

    /** Safe finite context used only by closed conditions. */
    public record Context(Optional<String> reason, boolean approvalPresent, boolean authorityActive,
            Map<String, String> safeAttributes) {
        /** Validates the finite condition context. */
        public Context {
            reason = Objects.requireNonNull(reason, "reason").map(value -> requireBounded(value, 1024, "reason"));
            safeAttributes = Map.copyOf(Objects.requireNonNull(safeAttributes, "safeAttributes"));
            if (safeAttributes.size() > 32) throw new IllegalArgumentException("Too many context attributes");
        }

        /** @return empty safe context */
        public static Context empty() {
            return new Context(Optional.empty(), false, false, Map.of());
        }
    }

    static void requireId(String value, String label) {
        if (value == null || !value.matches("[a-zA-Z0-9][a-zA-Z0-9._:-]{0,255}")) {
            throw new IllegalArgumentException(label + " identity is not canonical");
        }
    }

    static String requirePrincipal(String value) { requireId(value, "principal"); return value; }
    static String requireProfile(String value) { return requireBounded(value, 256, "profile"); }
    static String requireBounded(String value, int limit, String label) {
        if (value == null || value.isBlank() || value.length() > limit) {
            throw new IllegalArgumentException(label + " is invalid");
        }
        return value;
    }
}
