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
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.pki.api.PkiId;

/** Closed permission vocabulary and immutable scoped grant model. */
@SuppressWarnings({ "PMD.ExcessivePublicCount", "PMD.ControlStatementBraces",
        "PMD.AvoidLiteralsInIfCondition", "PMD.CommentDefaultAccessModifier", "PMD.LongVariable" })
public final class Permission {
    private Permission() {
    }

    /** Stable permission actions; semantic separation is part of the public contract. */
    public enum Action {
        /** Reads realm metadata. */ REALM_READ(1),
        /** Reads server health. */ SERVER_HEALTH_READ(2),
        /** Reads server configuration. */ SERVER_CONFIGURATION_READ(3),
        /** Updates server configuration. */ SERVER_CONFIGURATION_UPDATE(4),
        /** Manages identity-provider configuration. */ IDENTITY_PROVIDER_MANAGE(5),
        /** Manages security principals. */ PRINCIPAL_MANAGE(6),
        /** Manages role definitions. */ ROLE_MANAGE(7),
        /** Grants or revokes permissions. */ PERMISSION_GRANT(8),
        /** Forwards an authenticated client identity. */ FORWARD_AUTHENTICATED_CLIENT_IDENTITY(9),
        /** Lists authorities. */ AUTHORITY_LIST(20),
        /** Reads authority metadata. */ AUTHORITY_READ(21),
        /** Creates an authority. */ AUTHORITY_CREATE(22),
        /** Imports an authority. */ AUTHORITY_IMPORT(23),
        /** Activates an authority. */ AUTHORITY_ACTIVATE(24),
        /** Suspends an authority. */ AUTHORITY_SUSPEND(25),
        /** Retires an authority. */ AUTHORITY_RETIRE(26),
        /** Creates an issuer generation. */ ISSUER_CREATE(27),
        /** Rotates an issuer generation. */ ISSUER_ROTATE(28),
        /** Retires an issuer generation. */ ISSUER_RETIRE(29),
        /** Downloads a CA certificate chain. */ CA_CHAIN_DOWNLOAD(30),
        /** Reads certificate profiles. */ PROFILE_READ(40),
        /** Registers certificate profiles. */ PROFILE_REGISTER(41),
        /** Validates certificate profiles. */ PROFILE_VALIDATE(42),
        /** Activates certificate profiles. */ PROFILE_ACTIVATE(43),
        /** Deactivates certificate profiles. */ PROFILE_DEACTIVATE(44),
        /** Reads policy definitions. */ POLICY_READ(45),
        /** Updates policy definitions. */ POLICY_UPDATE(46),
        /** Reads X.509 bindings. */ X509_BINDING_READ(47),
        /** Enables an X.509 binding provider. */ X509_BINDING_PROVIDER_ENABLE(48),
        /** Submits a certificate request. */ REQUEST_SUBMIT(60),
        /** Reads requests owned by the principal. */ REQUEST_READ_OWN(61),
        /** Reads any request in scope. */ REQUEST_READ_ANY(62),
        /** Approves a certificate request. */ REQUEST_APPROVE(63),
        /** Rejects a certificate request. */ REQUEST_REJECT(64),
        /** Cancels a certificate request. */ REQUEST_CANCEL(65),
        /** Issues a certificate. */ CERTIFICATE_ISSUE(70),
        /** Renews a certificate. */ CERTIFICATE_RENEW(71),
        /** Replaces a certificate key. */ CERTIFICATE_REKEY(72),
        /** Reads certificate metadata. */ CERTIFICATE_READ_METADATA(73),
        /** Reads certificate content. */ CERTIFICATE_READ_CONTENT(74),
        /** Searches certificates. */ CERTIFICATE_SEARCH(75),
        /** Reads certificate personal data. */ CERTIFICATE_READ_PII(76),
        /** Downloads a certificate. */ CERTIFICATE_DOWNLOAD(77),
        /** Changes certificate publication. */ CERTIFICATE_PUBLICATION_CHANGE(78),
        /** Confirms certificate possession. */ CERTIFICATE_CONFIRM(79),
        /** Permanently revokes a certificate. */ CERTIFICATE_REVOKE(80),
        /** Places a certificate on hold. */ CERTIFICATE_HOLD(81),
        /** Releases a certificate hold. */ CERTIFICATE_RELEASE_HOLD(82),
        /** Reads revocation history. */ REVOCATION_HISTORY_READ(83),
        /** Generates a certificate revocation list. */ CRL_GENERATE(84),
        /** Publishes a certificate revocation list. */ CRL_PUBLISH(85),
        /** Downloads a certificate revocation list. */ CRL_DOWNLOAD(86),
        /** Administers OCSP configuration. */ OCSP_ADMINISTER(87),
        /** Reads OCSP responder configuration. */ OCSP_RESPONDER_READ(88),
        /** Queries certificate status through OCSP. */ OCSP_STATUS_QUERY(89),
        /** Registers a publication target. */ PUBLICATION_REGISTER(100),
        /** Reads publication state. */ PUBLICATION_READ(101),
        /** Processes pending publication. */ PUBLICATION_PROCESS(102),
        /** Retries failed publication. */ PUBLICATION_RETRY(103),
        /** Reconciles publication state. */ PUBLICATION_RECONCILE(104),
        /** Reads redacted audit data. */ AUDIT_READ_REDACTED(120),
        /** Reads complete audit metadata. */ AUDIT_READ_FULL(121),
        /** Reads personal data from audit records. */ AUDIT_READ_PII(122),
        /** Exports audit data. */ AUDIT_EXPORT(123),
        /** Verifies audit-log integrity. */ AUDIT_INTEGRITY_VERIFY(124),
        /** Exports a backup. */ BACKUP_EXPORT(140),
        /** Verifies a backup. */ BACKUP_VERIFY(141),
        /** Executes a restore. */ RESTORE_EXECUTE(142),
        /** Reads disclosure policy and state. */ DISCLOSURE_READ(160),
        /** Changes disclosure policy or state. */ DISCLOSURE_CHANGE(161),
        /** Issues a disclosure capability. */ DISCLOSURE_CAPABILITY_ISSUE(162),
        /** Revokes a disclosure capability. */ DISCLOSURE_CAPABILITY_REVOKE(163),
        /** Reads repository aliases. */ REPOSITORY_ALIAS_READ(164),
        /** Manages repository aliases. */ REPOSITORY_ALIAS_MANAGE(165),
        /** Reads an ACME directory. */ ACME_DIRECTORY_READ(180),
        /** Manages an ACME directory. */ ACME_DIRECTORY_MANAGE(181),
        /** Reads an ACME account. */ ACME_ACCOUNT_READ(182),
        /** Manages an ACME account. */ ACME_ACCOUNT_MANAGE(183),
        /** Administers an EST endpoint. */ EST_ENDPOINT_ADMINISTER(190),
        /** Reads an EST endpoint. */ EST_ENDPOINT_READ(191),
        /** Administers a SCEP endpoint. */ SCEP_ENDPOINT_ADMINISTER(192),
        /** Reads a SCEP endpoint. */ SCEP_ENDPOINT_READ(193),
        /** Administers a CMP endpoint. */ CMP_ENDPOINT_ADMINISTER(194),
        /** Reads a CMP endpoint. */ CMP_ENDPOINT_READ(195),
        /** Administers an enrollment profile. */ ENROLLMENT_PROFILE_ADMINISTER(196),
        /** Reads an enrollment profile. */ ENROLLMENT_PROFILE_READ(197),
        /** Manages automatic status-generation schedules. */ STATUS_SCHEDULE_MANAGE(198);

        private final int code;

        Action(int code) {
            this.code = code;
        }

        /**
         * Returns the stable persistence code.
         *
         * @return stable persistence code
         */
        public int code() {
            return code;
        }

        /**
         * Resolves a stable persistence code.
         *
         * @param code persisted action code
         * @return corresponding action
         */
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
        /** Allows the action when no stronger deny applies. */ ALLOW(1),
        /** Explicitly denies the action. */ DENY(2);
        private final int code;
        Effect(int code) { this.code = code; }
        /**
         * Returns the stable persistence code.
         *
         * @return stable code
         */
        public int code() { return code; }
        /**
         * Resolves a stable persistence code.
         *
         * @param code persisted effect code
         * @return corresponding effect
         */
        public static Effect fromCode(int code) {
            return switch (code) { case 1 -> ALLOW; case 2 -> DENY;
                default -> throw new IllegalArgumentException("Unknown grant effect code"); };
        }
    }

    /** Security resource types, distinct from PKI authority ownership. */
    public enum ResourceType {
        /** Security realm. */ REALM(1),
        /** Server configuration. */ SERVER_CONFIGURATION(2),
        /** Security principal. */ PRINCIPAL(3),
        /** Role definition. */ ROLE(4),
        /** Permission grant. */ GRANT(5),
        /** Logical certificate authority. */ AUTHORITY(10),
        /** Authority issuer generation. */ ISSUER(11),
        /** Certificate profile. */ PROFILE(12),
        /** Security or issuance policy. */ POLICY(13),
        /** X.509 representation binding. */ X509_BINDING(14),
        /** Certificate request. */ REQUEST(20),
        /** Issued certificate. */ CERTIFICATE(21),
        /** Revocation state. */ REVOCATION(22),
        /** Generated status object. */ STATUS_OBJECT(23),
        /** Publication operation or target. */ PUBLICATION(24),
        /** Audit data. */ AUDIT(30),
        /** Backup archive. */ BACKUP(31),
        /** Restore operation. */ RESTORE(32),
        /** Disclosure configuration or result. */ DISCLOSURE(33),
        /** Delegated disclosure capability. */ CAPABILITY(34),
        /** Approval request. */ APPROVAL(35),
        /** Break-glass authorization. */ BREAK_GLASS(36),
        /** Public repository alias. */ REPOSITORY_ALIAS(37),
        /** ACME directory configuration. */ ACME_DIRECTORY(38),
        /** ACME account. */ ACME_ACCOUNT(39),
        /** OCSP responder configuration. */ OCSP_RESPONDER(40),
        /** EST endpoint configuration. */ EST_ENDPOINT(41),
        /** SCEP endpoint configuration. */ SCEP_ENDPOINT(42),
        /** CMP endpoint configuration. */ CMP_ENDPOINT(43),
        /** Enrollment profile configuration. */ ENROLLMENT_PROFILE(44),
        /** Status-generation schedule configuration. */ STATUS_SCHEDULE(45),
        /** Durable protocol enrollment transaction and independent approval. */ ENROLLMENT_REQUEST(46);
        private final int code;
        ResourceType(int code) { this.code = code; }
        /**
         * Returns the stable persistence code.
         *
         * @return stable code
         */
        public int code() { return code; }
        /**
         * Resolves a stable persistence code.
         *
         * @param code persisted resource-type code
         * @return corresponding resource type
         */
        public static ResourceType fromCode(int code) {
            for (ResourceType candidate : values()) if (candidate.code == code) return candidate;
            throw new IllegalArgumentException("Unknown resource type code");
        }
    }

    /** Relationship between the requesting principal and the target object. */
    public enum Relationship {
        /** Restricts the grant to objects owned by the principal. */ OWN(1),
        /** Applies the grant to any object in its scope. */ ANY(2);
        private final int code;
        Relationship(int code) { this.code = code; }
        /**
         * Returns the stable persistence code.
         *
         * @return stable code
         */
        public int code() { return code; }
        /**
         * Resolves a stable persistence code.
         *
         * @param code persisted relationship code
         * @return corresponding relationship
         */
        public static Relationship fromCode(int code) {
            return switch (code) { case 1 -> OWN; case 2 -> ANY;
                default -> throw new IllegalArgumentException("Unknown relationship code"); };
        }
    }

    /** Explicitly separated disclosure and audit data views. */
    public enum DataView {
        /** Redacted non-sensitive metadata. */ METADATA_REDACTED(1),
        /** Complete metadata without content or personal data. */ METADATA_FULL(2),
        /** Complete object content. */ CONTENT_FULL(3),
        /** Personal data. */ PII_FULL(4);
        private final int code;
        DataView(int code) { this.code = code; }
        /**
         * Returns the stable persistence code.
         *
         * @return stable code
         */
        public int code() { return code; }
        /**
         * Resolves a stable persistence code.
         *
         * @param code persisted data-view code
         * @return corresponding data view
         */
        public static DataView fromCode(int code) {
            return switch (code) { case 1 -> METADATA_REDACTED; case 2 -> METADATA_FULL;
                case 3 -> CONTENT_FULL; case 4 -> PII_FULL;
                default -> throw new IllegalArgumentException("Unknown data-view code"); };
        }

        /**
         * Tests view sufficiency without merging content and PII authority.
         *
         * @param requested requested data view
         * @return {@code true} when this view permits the requested view
         */
        public boolean permits(DataView requested) {
            Objects.requireNonNull(requested, "requested");
            return this == requested || this == METADATA_FULL && requested == METADATA_REDACTED;
        }
    }

    /** Closed non-programmable grant conditions. */
    public enum Condition {
        /** Requires a nonblank operator reason. */ REASON_REQUIRED(1),
        /** Requires a valid approval. */ APPROVAL_REQUIRED(2),
        /** Requires distinct requester and approver principals. */ REQUESTER_APPROVER_SEPARATION(3),
        /** Requires an active authority. */ AUTHORITY_ACTIVE(4),
        /** Requires the configured profile to match. */ PROFILE_MATCH_REQUIRED(5);
        private final int code;
        Condition(int code) { this.code = code; }
        /**
         * Returns the stable persistence code.
         *
         * @return stable code
         */
        public int code() { return code; }
        /**
         * Resolves a stable persistence code.
         *
         * @param code persisted condition code
         * @return corresponding condition
         */
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
     * @param responderId explicit OCSP responder when applicable
     */
    public record Scope(RealmId realmId, Optional<PkiId> authorityId, Optional<PkiId> issuerId,
            Optional<String> profileId, Optional<String> responderId) {
        /** Validates the exact finite scope. */
        public Scope {
            Objects.requireNonNull(realmId, "realmId");
            authorityId = Objects.requireNonNull(authorityId, "authorityId");
            issuerId = Objects.requireNonNull(issuerId, "issuerId");
            profileId = Objects.requireNonNull(profileId, "profileId").map(Permission::requireProfile);
            responderId = Objects.requireNonNull(responderId, "responderId")
                    .map(value -> { requireId(value, "OCSP responder"); return value; });
            if (issuerId.isPresent() && authorityId.isEmpty()) {
                throw new IllegalArgumentException("Issuer scope requires authority scope");
            }
        }

        /**
         * Creates a scope without an OCSP responder dimension.
         *
         * @param realmId realm identity
         * @param authorityId explicit logical authority when applicable
         * @param issuerId explicit issuer generation when applicable
         * @param profileId explicit profile when applicable
         */
        public Scope(RealmId realmId, Optional<PkiId> authorityId, Optional<PkiId> issuerId,
                Optional<String> profileId) {
            this(realmId, authorityId, issuerId, profileId, Optional.empty());
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

        /**
         * Tests whether the principal owns this object.
         *
         * @param principal principal to test
         * @return {@code true} when the resource records that principal as owner
         */
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

    /**
     * Safe finite context used only by closed conditions.
     *
     * @param operatorJustification optional bounded operator reason or ticket
     * @param approvalPresent whether a valid approval is present
     * @param authorityActive whether the scoped authority is active
     * @param safeAttributes immutable non-sensitive condition attributes
     */
    public record Context(Optional<String> operatorJustification, boolean approvalPresent, boolean authorityActive,
            Map<String, String> safeAttributes) {
        /** Validates the finite condition context. */
        public Context {
            operatorJustification = Objects.requireNonNull(operatorJustification, "operatorJustification")
                    .map(value -> requireBounded(value, 1024, "operator justification"));
            safeAttributes = Map.copyOf(Objects.requireNonNull(safeAttributes, "safeAttributes"));
            if (safeAttributes.size() > 32) throw new IllegalArgumentException("Too many context attributes");
        }

        /**
         * Creates an empty safe context.
         *
         * @return empty safe context
         */
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
