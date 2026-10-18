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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.PkiId;

/** Durable disclosure authority and capability-based retrieval decision service. */
@SuppressWarnings({ "PMD.ControlStatementBraces", "PMD.AvoidLiteralsInIfCondition",
        "PMD.FieldDeclarationsShouldBeAtStartOfClass", "PMD.AvoidSynchronizedAtMethodLevel",
        "PMD.CyclomaticComplexity" })
public final class DisclosureService {
    /** Durable one-time delivery classification without retaining the raw token. */
    public enum DeliveryState {
        /** Token delivery has not yet been classified. */ PENDING(1),
        /** The raw token was delivered exactly once. */ DELIVERED(2),
        /** Delivery may have occurred but could not be confirmed. */ DELIVERY_UNKNOWN(3);
        private final int code;
        DeliveryState(int code) { this.code = code; }
        /**
         * Returns the stable persistence code.
         *
         * @return encoded value
         */
        public int code() { return code; }
        /**
         * Resolves one stable persistence code.
         *
         * @param code persisted delivery-state code
         * @return corresponding delivery state
         */
        public static DeliveryState fromCode(int code) {
            return switch (code) { case 1 -> PENDING; case 2 -> DELIVERED; case 3 -> DELIVERY_UNKNOWN;
                default -> throw new IllegalArgumentException("Unknown capability delivery code"); };
        }
    }
    /** Persisted disclosure states, independent of issuance and publication. */
    public enum Policy {
        /** Content is publicly retrievable and may be listed. */ PUBLIC(1),
        /** Content is public only through a point-addressable bearer. */ PUBLIC_UNLISTED(2),
        /** Any authenticated non-public principal may retrieve content. */ AUTHENTICATED(3),
        /** Only the owner or an administrator may retrieve content. */ OWNER_ONLY(4),
        /** Only explicitly authorized administrators may retrieve content. */ RESTRICTED(5),
        /** Content must not be served. */ NOT_PUBLISHED(6);
        private final int code;
        Policy(int code) { this.code = code; }
        /**
         * Returns the stable persistence code.
         *
         * @return encoded value
         */
        public int code() { return code; }
        /**
         * Resolves a stable persistence code.
         *
         * @param code persisted disclosure-policy code
         * @return corresponding disclosure policy
         */
        public static Policy fromCode(int code) {
            for (Policy candidate : values()) if (candidate.code == code) return candidate;
            throw new IllegalArgumentException("Unknown disclosure-policy code");
        }
    }

    /** Public-object classes with independent default policies. */
    public enum ObjectType {
        /** Certificate-authority certificate. */ CA_CERTIFICATE(1),
        /** Ordered certificate-authority chain. */ CA_CHAIN(2),
        /** End-entity certificate. */ LEAF_CERTIFICATE(3),
        /** Complete certificate revocation list. */ CRL(4),
        /** Other certificate status object. */ STATUS_OBJECT(5),
        /** Delta certificate revocation list. */ DELTA_CRL(6);
        private final int code;
        ObjectType(int code) { this.code = code; }
        /**
         * Returns the stable persistence code.
         *
         * @return encoded value
         */
        public int code() { return code; }
        /**
         * Resolves a stable persistence code.
         *
         * @param code persisted object-type code
         * @return corresponding object type
         */
        public static ObjectType fromCode(int code) {
            for (ObjectType candidate : values()) if (candidate.code == code) return candidate;
            throw new IllegalArgumentException("Unknown disclosure object-type code");
        }
    }

    /**
     * Typed disclosure owner, keeping ACME accounts outside administrative principals.
     *
     * @param type owner namespace
     * @param ownerId canonical identity within that namespace
     */
    public record Owner(OwnerType type, String ownerId) {
        /** Closed owner categories. */
        public enum OwnerType {
            /** Administrative security principal. */ SECURITY_PRINCIPAL,
            /** Protocol-scoped ACME account. */ ACME_ACCOUNT
        }
        /** Validates the canonical owner identity. */
        public Owner {
            Objects.requireNonNull(type, "type");
            if (ownerId == null || !ownerId.matches("[a-z0-9][a-z0-9._:-]{0,127}")) {
                throw new IllegalArgumentException("Disclosure owner identity is invalid");
            }
        }
        /**
         * Creates an administrative-principal owner.
         *
         * @param id canonical principal identifier
         * @return typed security-principal owner
         */
        public static Owner principal(String id) { Permission.requirePrincipal(id); return new Owner(OwnerType.SECURITY_PRINCIPAL, id); }
        /**
         * Creates a protocol-scoped ACME-account owner.
         *
         * @param id canonical ACME account identifier
         * @return typed ACME-account owner
         */
        public static Owner acmeAccount(String id) { return new Owner(OwnerType.ACME_ACCOUNT, id); }
    }

    /**
     * Configuration-driven safe defaults.
     *
     * @param rootCa root certificate default
     * @param intermediateCa intermediate certificate default
     * @param caChain chain default
     * @param crl CRL default
     * @param leaf leaf default
     * @param sensitiveLeaf sensitive leaf default
     */
    public record Defaults(Policy rootCa, Policy intermediateCa, Policy caChain, Policy crl,
            Policy leaf, Policy sensitiveLeaf) {
        /** Validates non-null defaults and prohibits public sensitive-leaf defaults. */
        public Defaults {
            Objects.requireNonNull(rootCa, "rootCa");
            Objects.requireNonNull(intermediateCa, "intermediateCa");
            Objects.requireNonNull(caChain, "caChain");
            Objects.requireNonNull(crl, "crl");
            Objects.requireNonNull(leaf, "leaf");
            Objects.requireNonNull(sensitiveLeaf, "sensitiveLeaf");
            if (leaf == Policy.PUBLIC || sensitiveLeaf == Policy.PUBLIC
                    || sensitiveLeaf == Policy.PUBLIC_UNLISTED) {
                throw new IllegalArgumentException("Leaf defaults must not silently expose certificate data");
            }
        }

        /**
         * Returns the normative recommended defaults.
         *
         * @return conservative recommended disclosure defaults
         */
        public static Defaults recommended() {
            return new Defaults(Policy.PUBLIC, Policy.PUBLIC, Policy.PUBLIC, Policy.PUBLIC,
                    Policy.OWNER_ONLY, Policy.RESTRICTED);
        }
    }

    /**
     * Durable policy bound to exact object and profile/policy commitment.
     *
     * @param objectId exact protected object identifier
     * @param objectType protected object classification
     * @param policy effective disclosure policy
     * @param ownerPrincipalId optional administrative owner
     * @param ownerAcmeAccountId optional protocol-scoped ACME owner
     * @param policyCommitment governing profile or policy commitment
     * @param updatedAt server-authoritative last-update time
     */
    public record Record(PkiId objectId, ObjectType objectType, Policy policy, Optional<String> ownerPrincipalId,
            Optional<String> ownerAcmeAccountId, String policyCommitment, Instant updatedAt) {
        /** Validates the durable disclosure record. */
        public Record {
            Objects.requireNonNull(objectId, "objectId");
            Objects.requireNonNull(objectType, "objectType");
            Objects.requireNonNull(policy, "policy");
            ownerPrincipalId = Objects.requireNonNull(ownerPrincipalId, "ownerPrincipalId")
                    .map(Permission::requirePrincipal);
            ownerAcmeAccountId = Objects.requireNonNull(ownerAcmeAccountId, "ownerAcmeAccountId");
            ownerAcmeAccountId.ifPresent(value -> new Owner(Owner.OwnerType.ACME_ACCOUNT, value));
            if (ownerPrincipalId.isPresent() && ownerAcmeAccountId.isPresent()) {
                throw new IllegalArgumentException("Disclosure owner categories are mutually exclusive");
            }
            if (policyCommitment == null || !policyCommitment.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Disclosure policy commitment is invalid");
            }
            Objects.requireNonNull(updatedAt, "updatedAt");
            if (objectType == ObjectType.LEAF_CERTIFICATE && policy == Policy.OWNER_ONLY
                    && ownerPrincipalId.isEmpty() && ownerAcmeAccountId.isEmpty()) {
                throw new IllegalArgumentException("Owner-only leaf disclosure requires an owner");
            }
        }

        /**
         * Creates a record with optional administrative-principal ownership.
         *
         * @param objectId exact protected object identifier
         * @param objectType protected object classification
         * @param policy effective disclosure policy
         * @param ownerPrincipalId optional administrative owner
         * @param policyCommitment governing profile or policy commitment
         * @param updatedAt server-authoritative last-update time
         */
        public Record(PkiId objectId, ObjectType objectType, Policy policy, Optional<String> ownerPrincipalId,
                String policyCommitment, Instant updatedAt) {
            this(objectId, objectType, policy, ownerPrincipalId, Optional.empty(), policyCommitment, updatedAt);
        }
    }

    /**
     * Persisted commitment-only capability authority.
     *
     * @param capabilityId stable non-bearer capability identifier
     * @param realmId owning security realm
     * @param objectId exact protected object identifier
     * @param action bounded capability action
     * @param issuerPrincipalId issuing administrative principal
     * @param tokenCommitment SHA-256 commitment to the raw bearer token
     * @param expiresAt mandatory capability expiry
     * @param deliveryState one-time token-delivery classification
     * @param revoked whether the capability is permanently revoked
     */
    public record Capability(String capabilityId, RealmId realmId, PkiId objectId, String action,
            String issuerPrincipalId, byte[] tokenCommitment, Instant expiresAt,
            DeliveryState deliveryState, boolean revoked) {
        /** Validates and snapshots capability metadata. */
        public Capability {
            Permission.requireId(capabilityId, "capability");
            Objects.requireNonNull(realmId, "realmId");
            Objects.requireNonNull(objectId, "objectId");
            Permission.requireBounded(action, 128, "capability action");
            Permission.requirePrincipal(issuerPrincipalId);
            tokenCommitment = Objects.requireNonNull(tokenCommitment, "tokenCommitment").clone();
            if (tokenCommitment.length != 32) throw new IllegalArgumentException("Capability commitment length");
            Objects.requireNonNull(expiresAt, "expiresAt");
            Objects.requireNonNull(deliveryState, "deliveryState");
        }

        /**
         * Returns a defensive commitment copy.
         *
         * @return exact 32-byte token commitment
         */
        @Override public byte[] tokenCommitment() { return tokenCommitment.clone(); }

        /**
         * Creates compatibility metadata with a non-secret system issuer.
         *
         * @param capabilityId stable non-bearer capability identifier
         * @param realmId owning security realm
         * @param objectId exact protected object identifier
         * @param action bounded capability action
         * @param tokenCommitment SHA-256 commitment to the raw bearer token
         * @param expiresAt mandatory capability expiry
         * @param revoked whether the capability is permanently revoked
         */
        public Capability(String capabilityId, RealmId realmId, PkiId objectId, String action,
                byte[] tokenCommitment, Instant expiresAt, boolean revoked) {
            this(capabilityId, realmId, objectId, action, "system", tokenCommitment, expiresAt, revoked);
        }

        /**
         * Creates capability metadata in the delivered state for embedded compatibility.
         *
         * @param capabilityId stable non-bearer capability identifier
         * @param realmId owning security realm
         * @param objectId exact protected object identifier
         * @param action bounded capability action
         * @param issuerPrincipalId issuing administrative principal
         * @param tokenCommitment SHA-256 commitment to the raw bearer token
         * @param expiresAt mandatory capability expiry
         * @param revoked whether the capability is permanently revoked
         */
        public Capability(String capabilityId, RealmId realmId, PkiId objectId, String action,
                String issuerPrincipalId, byte[] tokenCommitment, Instant expiresAt, boolean revoked) {
            this(capabilityId, realmId, objectId, action, issuerPrincipalId, tokenCommitment, expiresAt,
                    DeliveryState.DELIVERED, revoked);
        }
    }

    /** One-time raw-token issuance result. */
    public static final class IssuedCapability {
        private final Capability capability;
        private final byte[] token;
        private boolean consumed;
        /**
         * Validates and snapshots the one-time token.
         *
         * @param capability persisted commitment-only capability metadata
         * @param token exact 32-byte raw bearer token
         */
        public IssuedCapability(Capability capability, byte[] token) {
            this.capability = Objects.requireNonNull(capability, "capability");
            this.token = Objects.requireNonNull(token, "token").clone();
            if (token.length != 32) throw new IllegalArgumentException("Capability token length");
        }
        /**
         * Returns the persisted commitment-only metadata.
         *
         * @return persisted capability metadata
         */
        public Capability capability() { return capability; }
        /**
         * Returns and clears the raw token exactly once.
         *
         * @return defensive copy of the raw 32-byte token
         */
        public synchronized byte[] token() {
            if (consumed) throw new IllegalStateException("Capability token was already consumed");
            consumed = true;
            byte[] result = token.clone();
            java.util.Arrays.fill(token, (byte) 0);
            return result;
        }
    }

    /** Safe retrieval result that reveals no protected-object existence. */
    public enum Decision {
        /** Retrieval is authorized without revealing additional state. */ ALLOWED,
        /** Retrieval is denied without revealing object existence. */ DENIED
    }

    private final RealmId realmId;
    private final ServerControlStore store;
    private final Defaults defaults;
    private final Clock clock;
    private final SecureRandom random;
    private final SafeAudit audit;

    /**
     * Creates a durable disclosure service with an injected random source and clock.
     *
     * @param realmId owning security realm
     * @param store durable server-control store
     * @param defaults configuration-driven disclosure defaults
     * @param clock authoritative server clock
     * @param random cryptographically secure token source
     * @param auditSink required safe audit sink
     */
    public DisclosureService(RealmId realmId, ServerControlStore store, Defaults defaults, Clock clock,
            SecureRandom random, zeroecho.pki.spi.audit.AuditSink auditSink) {
        this.realmId = Objects.requireNonNull(realmId, "realmId");
        this.store = Objects.requireNonNull(store, "store");
        this.defaults = Objects.requireNonNull(defaults, "defaults");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.random = Objects.requireNonNull(random, "random");
        this.audit = new SafeAudit(clock, auditSink);
    }

    /**
     * Returns the default policy for one object classification.
     *
     * @param type protected object classification
     * @param rootCa whether a CA certificate is a root
     * @param sensitive whether a leaf contains sensitive data
     * @return configured default disclosure policy
     */
    public Policy defaultPolicy(ObjectType type, boolean rootCa, boolean sensitive) {
        Objects.requireNonNull(type, "type");
        return switch (type) {
            case CA_CERTIFICATE -> rootCa ? defaults.rootCa() : defaults.intermediateCa();
            case CA_CHAIN -> defaults.caChain();
            case CRL, DELTA_CRL -> defaults.crl();
            case LEAF_CERTIFICATE -> sensitive ? defaults.sensitiveLeaf() : defaults.leaf();
            case STATUS_OBJECT -> Policy.RESTRICTED;
        };
    }

    /**
     * Persists the first disclosure record without touching PKI content.
     *
     * @param objectId exact protected object identifier
     * @param type protected object classification
     * @param policy effective or requested disclosure policy
     * @param ownerPrincipalId optional administrative owner
     * @param profileOrPolicyCommitment governing profile or policy commitment
     * @param actorPrincipalId authenticated audit actor
     * @return newly persisted disclosure record
     */
    public synchronized Record register(PkiId objectId, ObjectType type, Policy policy,
            Optional<String> ownerPrincipalId,
            String profileOrPolicyCommitment, String actorPrincipalId) {
        ownerPrincipalId.ifPresent(store::requirePrincipal);
        Record record = new Record(objectId, type, policy, ownerPrincipalId,
                requireDigest(profileOrPolicyCommitment), clock.instant());
        store.createDisclosure(record);
        audit.record("DISCLOSURE_REGISTER", actorPrincipalId, Optional.of(objectId), Map.of("policy", policy.name()));
        return record;
    }

    /**
     * Persists or exactly replays one disclosure record with an optional typed owner.
     *
     * @param objectId exact disclosed object identity
     * @param type exact object classification
     * @param policy frozen disclosure policy
     * @param owner optional explicit protocol or administrative owner
     * @param profileOrPolicyCommitment exact governing policy commitment
     * @param actorPrincipalId audit actor; never inferred from {@code owner}
     * @return newly committed or exactly matching existing record
     * @throws IllegalStateException if an existing record differs
     */
    public synchronized Record registerExact(PkiId objectId, ObjectType type, Policy policy,
            Optional<Owner> owner, String profileOrPolicyCommitment, String actorPrincipalId) {
        return registerExactInternal(objectId, type, policy, owner, profileOrPolicyCommitment, actorPrincipalId);
    }

    /**
     * Changes only disclosure metadata; increased exposure may require approval.
     *
     * @param objectId exact protected object identifier
     * @param policy effective or requested disclosure policy
     * @param exposureApprovalRequired whether increased exposure requires approval
     * @param approvalPresented whether the required approval is present
     * @param actorPrincipalId authenticated audit actor
     * @return durably updated disclosure record
     */
    public synchronized Record change(PkiId objectId, Policy policy, boolean exposureApprovalRequired,
            boolean approvalPresented, String actorPrincipalId) {
        Record current = store.requireDisclosure(objectId);
        if (exposureApprovalRequired && exposure(policy) < exposure(current.policy())
                && !approvalPresented) {
            throw new IllegalStateException("Increased disclosure requires approval");
        }
        Record updated = new Record(current.objectId(), current.objectType(), policy, current.ownerPrincipalId(),
                current.ownerAcmeAccountId(), current.policyCommitment(), clock.instant());
        store.replaceDisclosure(current, updated);
        audit.record("DISCLOSURE_CHANGE", actorPrincipalId, Optional.of(objectId), Map.of("policy", policy.name()));
        return updated;
    }

    /* default */ synchronized void validateOwner(Optional<Owner> owner) {
        Optional<Owner> exactOwner = Objects.requireNonNull(owner, "owner");
        exactOwner.filter(value -> value.type() == Owner.OwnerType.SECURITY_PRINCIPAL)
                .ifPresent(value -> store.requirePrincipal(value.ownerId()));
    }

    private Record registerExactInternal(PkiId objectId, ObjectType type, Policy policy, Optional<Owner> owner,
            String profileOrPolicyCommitment, String actorPrincipalId) {
        Objects.requireNonNull(objectId, "objectId");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(policy, "policy");
        Optional<Owner> exactOwner = Objects.requireNonNull(owner, "owner");
        validateOwner(exactOwner);
        String commitment = requireDigest(profileOrPolicyCommitment);
        Optional<String> principal = exactOwner
                .filter(value -> value.type() == Owner.OwnerType.SECURITY_PRINCIPAL).map(Owner::ownerId);
        Optional<String> account = exactOwner
                .filter(value -> value.type() == Owner.OwnerType.ACME_ACCOUNT).map(Owner::ownerId);
        Optional<Record> existing = store.findDisclosure(objectId);
        if (existing.isPresent()) {
            Record exact = existing.orElseThrow();
            if (exact.objectType() != type || exact.policy() != policy
                    || !exact.ownerPrincipalId().equals(principal)
                    || !exact.ownerAcmeAccountId().equals(account)
                    || !exact.policyCommitment().equals(commitment)) {
                throw new IllegalStateException("Disclosure registration conflict");
            }
            return exact;
        }
        Record record = new Record(objectId, type, policy, principal, account, commitment, clock.instant());
        store.createDisclosure(record);
        audit.record("DISCLOSURE_REGISTER", actorPrincipalId, Optional.of(objectId), Map.of("policy", policy.name()));
        return record;
    }

    /**
     * Evaluates direct retrieval separately from search authorization.
     *
     * @param objectId exact protected object identifier
     * @param principal optional authenticated principal
     * @param ownerRelationship whether the principal owns the object
     * @param administrativePermission whether explicit administrative access is granted
     * @param capabilityToken optional raw capability token
     * @return non-revealing retrieval decision
     */
    public synchronized Decision decide(PkiId objectId, Optional<SecurityPrincipal> principal,
            boolean ownerRelationship,
            boolean administrativePermission, Optional<byte[]> capabilityToken) {
        Record record = store.requireDisclosure(objectId);
        return switch (record.policy()) {
            case PUBLIC -> Decision.ALLOWED;
            case PUBLIC_UNLISTED -> capabilityToken.filter(token -> validCapability(record.objectId(), token))
                    .isPresent() || principal.isPresent() && (ownerRelationship || administrativePermission)
                            ? Decision.ALLOWED : Decision.DENIED;
            case AUTHENTICATED -> principal.filter(SecurityPrincipal::enabled)
                    .filter(value -> value.type() != SecurityPrincipal.Type.PUBLIC)
                    .map(ignored -> Decision.ALLOWED).orElse(Decision.DENIED);
            case OWNER_ONLY -> ownerRelationship || administrativePermission
                    ? Decision.ALLOWED : Decision.DENIED;
            case RESTRICTED -> administrativePermission ? Decision.ALLOWED : Decision.DENIED;
            case NOT_PUBLISHED -> Decision.DENIED;
        };
    }

    /**
     * Evaluates public repository retrieval using a point-addressable bearer
     * credential. Capability and principal authority are not combined.
     *
     * @param objectId exact repository object identity
     * @param principal authenticated principal, or empty for a public request
     * @param ownerRelationship whether the principal owns the object
     * @param administrativePermission whether administrative disclosure is authorized
     * @param bearer point-addressable bearer credential, or empty
     * @return a non-disclosing allow or deny decision
     */
    public synchronized Decision decideRepository(PkiId objectId, Optional<SecurityPrincipal> principal,
            boolean ownerRelationship, boolean administrativePermission, Optional<String> bearer) {
        Record record = store.requireDisclosure(objectId);
        if (bearer.isPresent()) {
            return record.policy() == Policy.PUBLIC_UNLISTED
                    && validBearer(objectId, bearer.orElseThrow()) ? Decision.ALLOWED : Decision.DENIED;
        }
        return switch (record.policy()) {
            case PUBLIC -> Decision.ALLOWED;
            case PUBLIC_UNLISTED -> principal.isPresent() && (ownerRelationship || administrativePermission)
                    ? Decision.ALLOWED : Decision.DENIED;
            case AUTHENTICATED -> principal.filter(SecurityPrincipal::enabled)
                    .filter(value -> value.type() != SecurityPrincipal.Type.PUBLIC)
                    .map(ignored -> Decision.ALLOWED).orElse(Decision.DENIED);
            case OWNER_ONLY -> ownerRelationship || administrativePermission
                    ? Decision.ALLOWED : Decision.DENIED;
            case RESTRICTED -> administrativePermission ? Decision.ALLOWED : Decision.DENIED;
            case NOT_PUBLISHED -> Decision.DENIED;
        };
    }

    /**
     * Returns the strict one-time bearer credential for an issued capability.
     *
     * @param capability persisted capability metadata
     * @param token exact 32-byte raw capability token
     * @return strict point-addressable bearer credential
     */
    public static String bearerCredential(Capability capability, byte[] token) {
        Objects.requireNonNull(capability, "capability");
        return bearerCredential(capability.capabilityId(), token);
    }

    /**
     * Returns the strict bearer credential for one non-secret capability ID.
     *
     * @param capabilityId stable non-bearer capability identifier
     * @param token exact 32-byte raw capability token
     * @return strict point-addressable bearer credential
     */
    public static String bearerCredential(String capabilityId, byte[] token) {
        Permission.requireId(capabilityId, "capability");
        if (token == null || token.length != 32) throw new IllegalArgumentException("Capability token length");
        return capabilityId + '.' + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }

    /**
     * Issues 256 random capability bits and persists only their commitment.
     *
     * @param objectId exact protected object identifier
     * @param expiresAt mandatory capability expiry
     * @param actorPrincipalId authenticated audit actor
     * @return one-time raw token and persisted commitment-only metadata
     */
    public synchronized IssuedCapability issueCapability(PkiId objectId, Instant expiresAt,
            String actorPrincipalId) {
        store.requirePrincipal(actorPrincipalId);
        Record record = store.requireDisclosure(objectId);
        if (record.policy() != Policy.PUBLIC_UNLISTED || !expiresAt.isAfter(clock.instant())) {
            throw new IllegalStateException("Capability issuance is unavailable for this object");
        }
        byte[] token = new byte[32];
        byte[] identity = new byte[16];
        random.nextBytes(token);
        random.nextBytes(identity);
        String capabilityId = "cap-" + HexFormat.of().formatHex(identity);
        Capability capability = new Capability(capabilityId, realmId, objectId, "RETRIEVE", actorPrincipalId,
                capabilityCommitment(objectId, expiresAt, token), expiresAt, DeliveryState.PENDING, false);
        store.createCapability(capability);
        audit.record("CAPABILITY_ISSUE", actorPrincipalId, Optional.of(objectId), Map.of("issued", "true"));
        return new IssuedCapability(capability, token);
    }

    /**
     * Revokes a capability without revealing or recovering its raw token.
     *
     * @param capabilityId stable non-bearer capability identifier
     * @param actorPrincipalId authenticated audit actor
     * @return durably revoked capability
     */
    public synchronized Capability revokeCapability(String capabilityId, String actorPrincipalId) {
        Capability current = store.requireCapability(capabilityId);
        Capability revoked = new Capability(current.capabilityId(), current.realmId(), current.objectId(),
                current.action(), current.issuerPrincipalId(), current.tokenCommitment(), current.expiresAt(),
                current.deliveryState(), true);
        store.replaceCapability(current, revoked);
        audit.record("CAPABILITY_REVOKE", actorPrincipalId, Optional.of(current.objectId()), Map.of("revoked", "true"));
        return revoked;
    }

    /**
     * Persists the safe post-write delivery classification without changing token validity.
     *
     * @param capabilityId stable non-bearer capability identifier
     * @param delivered whether raw-token delivery completed
     * @return durably classified capability metadata
     */
    public synchronized Capability classifyDelivery(String capabilityId, boolean delivered) {
        Capability current = store.requireCapability(capabilityId);
        if (current.deliveryState() != DeliveryState.PENDING) return current;
        Capability updated = new Capability(current.capabilityId(), current.realmId(), current.objectId(),
                current.action(), current.issuerPrincipalId(), current.tokenCommitment(), current.expiresAt(),
                delivered ? DeliveryState.DELIVERED : DeliveryState.DELIVERY_UNKNOWN, current.revoked());
        store.replaceCapability(current, updated);
        audit.record(delivered ? "CAPABILITY_DELIVERED" : "CAPABILITY_DELIVERY_UNKNOWN",
                current.issuerPrincipalId(), Optional.of(current.objectId()), Map.of("delivered", Boolean.toString(delivered)));
        return updated;
    }

    private boolean validCapability(PkiId objectId, byte[] token) {
        if (token == null || token.length != 32) return false;
        for (Capability capability : store.capabilitiesFor(objectId)) {
            if (!capability.revoked() && capability.realmId().equals(realmId)
                    && "RETRIEVE".equals(capability.action())
                    && clock.instant().isBefore(capability.expiresAt())
                    && MessageDigest.isEqual(capability.tokenCommitment(),
                            capabilityCommitment(objectId, capability.expiresAt(), token))) return true;
        }
        return false;
    }

    private boolean validBearer(PkiId objectId, String bearer) {
        if (bearer == null || !bearer.matches("cap-[0-9a-f]{32}\\.[A-Za-z0-9_-]{43}")) return false;
        int separator = bearer.indexOf('.');
        DisclosureService.Capability capability;
        try {
            capability = store.requireCapability(bearer.substring(0, separator));
        } catch (IllegalArgumentException unavailable) {
            return false;
        }
        byte[] token;
        try {
            token = java.util.Base64.getUrlDecoder().decode(bearer.substring(separator + 1));
        } catch (IllegalArgumentException malformed) {
            return false;
        }
        try {
            return token.length == 32 && !capability.revoked() && capability.realmId().equals(realmId)
                    && capability.objectId().equals(objectId) && "RETRIEVE".equals(capability.action())
                    && clock.instant().isBefore(capability.expiresAt())
                    && MessageDigest.isEqual(capability.tokenCommitment(),
                            capabilityCommitment(objectId, capability.expiresAt(), token));
        } finally {
            java.util.Arrays.fill(token, (byte) 0);
        }
    }

    private byte[] capabilityCommitment(PkiId objectId, Instant expiry, byte[] token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(realmId.value().getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
            digest.update(objectId.value().getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
            digest.update(ByteBuffer.allocate(Long.BYTES).putLong(expiry.toEpochMilli()).array());
            digest.update(token);
            return digest.digest();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static int exposure(Policy policy) {
        return switch (policy) {
            case PUBLIC -> 0; case PUBLIC_UNLISTED -> 1; case AUTHENTICATED -> 2;
            case OWNER_ONLY -> 3; case RESTRICTED -> 4; case NOT_PUBLISHED -> 5;
        };
    }

    private static String requireDigest(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Policy commitment is invalid");
        }
        return value;
    }
}
