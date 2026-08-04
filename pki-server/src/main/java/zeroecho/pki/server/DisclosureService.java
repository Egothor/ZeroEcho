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
        "PMD.FieldDeclarationsShouldBeAtStartOfClass", "PMD.AvoidSynchronizedAtMethodLevel" })
public final class DisclosureService {
    /** Durable one-time delivery classification without retaining the raw token. */
    public enum DeliveryState {
        PENDING(1), DELIVERED(2), DELIVERY_UNKNOWN(3);
        private final int code;
        DeliveryState(int code) { this.code = code; }
        /** @return stable persistence code */ public int code() { return code; }
        /** Resolves one stable persistence code. */
        public static DeliveryState fromCode(int code) {
            return switch (code) { case 1 -> PENDING; case 2 -> DELIVERED; case 3 -> DELIVERY_UNKNOWN;
                default -> throw new IllegalArgumentException("Unknown capability delivery code"); };
        }
    }
    /** Persisted disclosure states, independent of issuance and publication. */
    public enum Policy {
        PUBLIC(1), PUBLIC_UNLISTED(2), AUTHENTICATED(3), OWNER_ONLY(4), RESTRICTED(5), NOT_PUBLISHED(6);
        private final int code;
        Policy(int code) { this.code = code; }
        /** @return stable persistence code */ public int code() { return code; }
        /** Resolves a stable persistence code. */
        public static Policy fromCode(int code) {
            for (Policy candidate : values()) if (candidate.code == code) return candidate;
            throw new IllegalArgumentException("Unknown disclosure-policy code");
        }
    }

    /** Public-object classes with independent default policies. */
    public enum ObjectType {
        CA_CERTIFICATE(1), CA_CHAIN(2), LEAF_CERTIFICATE(3), CRL(4), STATUS_OBJECT(5);
        private final int code;
        ObjectType(int code) { this.code = code; }
        /** @return stable persistence code */ public int code() { return code; }
        /** Resolves a stable persistence code. */
        public static ObjectType fromCode(int code) {
            for (ObjectType candidate : values()) if (candidate.code == code) return candidate;
            throw new IllegalArgumentException("Unknown disclosure object-type code");
        }
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

        /** @return normative recommended defaults */
        public static Defaults recommended() {
            return new Defaults(Policy.PUBLIC, Policy.PUBLIC, Policy.PUBLIC, Policy.PUBLIC,
                    Policy.OWNER_ONLY, Policy.RESTRICTED);
        }
    }

    /** Durable policy bound to exact object and profile/policy commitment. */
    public record Record(PkiId objectId, ObjectType objectType, Policy policy, Optional<String> ownerPrincipalId,
            String policyCommitment, Instant updatedAt) {
        /** Validates the durable disclosure record. */
        public Record {
            Objects.requireNonNull(objectId, "objectId");
            Objects.requireNonNull(objectType, "objectType");
            Objects.requireNonNull(policy, "policy");
            ownerPrincipalId = Objects.requireNonNull(ownerPrincipalId, "ownerPrincipalId")
                    .map(Permission::requirePrincipal);
            if (policyCommitment == null || !policyCommitment.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Disclosure policy commitment is invalid");
            }
            Objects.requireNonNull(updatedAt, "updatedAt");
            if (objectType == ObjectType.LEAF_CERTIFICATE && policy == Policy.OWNER_ONLY
                    && ownerPrincipalId.isEmpty()) {
                throw new IllegalArgumentException("Owner-only leaf disclosure requires an owner");
            }
        }
    }

    /** Persisted commitment-only capability authority. */
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

        /** Returns a defensive commitment copy. */
        @Override public byte[] tokenCommitment() { return tokenCommitment.clone(); }

        /** Creates legacy test metadata with an explicit non-secret system issuer. */
        public Capability(String capabilityId, RealmId realmId, PkiId objectId, String action,
                byte[] tokenCommitment, Instant expiresAt, boolean revoked) {
            this(capabilityId, realmId, objectId, action, "system", tokenCommitment, expiresAt, revoked);
        }

        /** Creates capability metadata in the delivered state for embedded compatibility. */
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
        /** Validates and snapshots the one-time token. */
        public IssuedCapability(Capability capability, byte[] token) {
            this.capability = Objects.requireNonNull(capability, "capability");
            this.token = Objects.requireNonNull(token, "token").clone();
            if (token.length != 32) throw new IllegalArgumentException("Capability token length");
        }
        /** @return persisted commitment-only metadata */ public Capability capability() { return capability; }
        /** Returns and clears the raw token exactly once. */
        public synchronized byte[] token() {
            if (consumed) throw new IllegalStateException("Capability token was already consumed");
            consumed = true;
            byte[] result = token.clone();
            java.util.Arrays.fill(token, (byte) 0);
            return result;
        }
    }

    /** Safe retrieval result that reveals no protected-object existence. */
    public enum Decision { ALLOWED, DENIED }

    private final RealmId realmId;
    private final ServerControlStore store;
    private final Defaults defaults;
    private final Clock clock;
    private final SecureRandom random;
    private final SafeAudit audit;

    /** Creates a durable disclosure service with an injected random source and clock. */
    public DisclosureService(RealmId realmId, ServerControlStore store, Defaults defaults, Clock clock,
            SecureRandom random, zeroecho.pki.spi.audit.AuditSink auditSink) {
        this.realmId = Objects.requireNonNull(realmId, "realmId");
        this.store = Objects.requireNonNull(store, "store");
        this.defaults = Objects.requireNonNull(defaults, "defaults");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.random = Objects.requireNonNull(random, "random");
        this.audit = new SafeAudit(clock, auditSink);
    }

    /** Returns the default policy for one object classification. */
    public Policy defaultPolicy(ObjectType type, boolean rootCa, boolean sensitive) {
        Objects.requireNonNull(type, "type");
        return switch (type) {
            case CA_CERTIFICATE -> rootCa ? defaults.rootCa() : defaults.intermediateCa();
            case CA_CHAIN -> defaults.caChain();
            case CRL -> defaults.crl();
            case LEAF_CERTIFICATE -> sensitive ? defaults.sensitiveLeaf() : defaults.leaf();
            case STATUS_OBJECT -> Policy.RESTRICTED;
        };
    }

    /** Persists the first disclosure record without touching PKI content. */
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

    /** Changes only disclosure metadata; increased exposure may require approval. */
    public synchronized Record change(PkiId objectId, Policy policy, boolean increasedExposureApprovalRequired,
            boolean approvalPresented, String actorPrincipalId) {
        Record current = store.requireDisclosure(objectId);
        if (increasedExposureApprovalRequired && exposure(policy) < exposure(current.policy())
                && !approvalPresented) {
            throw new IllegalStateException("Increased disclosure requires approval");
        }
        Record updated = new Record(current.objectId(), current.objectType(), policy, current.ownerPrincipalId(),
                current.policyCommitment(), clock.instant());
        store.replaceDisclosure(current, updated);
        audit.record("DISCLOSURE_CHANGE", actorPrincipalId, Optional.of(objectId), Map.of("policy", policy.name()));
        return updated;
    }

    /** Evaluates direct retrieval separately from search authorization. */
    public synchronized Decision decide(PkiId objectId, Optional<SecurityPrincipal> principal,
            boolean ownerRelationship,
            boolean explicitAdministrativePermission, Optional<byte[]> capabilityToken) {
        Record record = store.requireDisclosure(objectId);
        return switch (record.policy()) {
            case PUBLIC -> Decision.ALLOWED;
            case PUBLIC_UNLISTED -> capabilityToken.filter(token -> validCapability(record.objectId(), token))
                    .isPresent() ? Decision.ALLOWED : Decision.DENIED;
            case AUTHENTICATED -> principal.filter(SecurityPrincipal::enabled)
                    .filter(value -> value.type() != SecurityPrincipal.Type.PUBLIC)
                    .map(ignored -> Decision.ALLOWED).orElse(Decision.DENIED);
            case OWNER_ONLY -> ownerRelationship || explicitAdministrativePermission
                    ? Decision.ALLOWED : Decision.DENIED;
            case RESTRICTED -> explicitAdministrativePermission ? Decision.ALLOWED : Decision.DENIED;
            case NOT_PUBLISHED -> explicitAdministrativePermission || ownerRelationship
                    ? Decision.ALLOWED : Decision.DENIED;
        };
    }

    /** Issues 256 random capability bits and persists only their commitment. */
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

    /** Revokes a capability without revealing or recovering its raw token. */
    public synchronized Capability revokeCapability(String capabilityId, String actorPrincipalId) {
        Capability current = store.requireCapability(capabilityId);
        Capability revoked = new Capability(current.capabilityId(), current.realmId(), current.objectId(),
                current.action(), current.issuerPrincipalId(), current.tokenCommitment(), current.expiresAt(),
                current.deliveryState(), true);
        store.replaceCapability(current, revoked);
        audit.record("CAPABILITY_REVOKE", actorPrincipalId, Optional.of(current.objectId()), Map.of("revoked", "true"));
        return revoked;
    }

    /** Persists the safe post-write delivery classification without changing token validity. */
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
