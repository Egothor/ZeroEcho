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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.application.PkiRepository;

/** Durable non-authoritative repository alias administration. */
@SuppressWarnings({ "PMD.FieldDeclarationsShouldBeAtStartOfClass", "PMD.LinguisticNaming",
        "PMD.ExcessiveParameterList" })
public final class RepositoryAliasService {
    /** Closed stable repository alias types. */
    public enum Type {
        /** Stable route to one explicit immutable CRL. */
        CURRENT_CRL(1),
        /** Stable route to one explicit immutable issuer chain path. */
        CURRENT_CHAIN(2);
        private final int code;
        Type(int code) { this.code = code; }
        /** @return stable persistence code */ public int code() { return code; }
        /** Resolves a stable persistence code. */
        public static Type fromCode(int code) {
            return switch (code) { case 1 -> CURRENT_CRL; case 2 -> CURRENT_CHAIN;
                default -> throw new IllegalArgumentException("Unknown repository alias type"); };
        }
    }

    /** Durable alias state; removal never deletes its immutable target. */
    public enum State {
        /** Alias resolves its exact target. */ ACTIVE(1),
        /** Alias has been deliberately removed. */ REMOVED(2);
        private final int code;
        State(int code) { this.code = code; }
        /** @return stable persistence code */ public int code() { return code; }
        /** Resolves a stable persistence code. */
        public static State fromCode(int code) {
            return switch (code) { case 1 -> ACTIVE; case 2 -> REMOVED;
                default -> throw new IllegalArgumentException("Unknown repository alias state"); };
        }
    }

    /** Immutable finite alias metadata; no content bytes or filesystem paths. */
    public record Record(String aliasId, RealmId realmId, PkiId authorityId, Type type, PkiId targetObjectId,
            Optional<PkiId> issuerId, Optional<PkiId> pathId, String targetCommitment, Instant createdAt,
            Instant updatedAt, String actorPrincipalId, State state, String recordCommitment) {
        /** Validates exact alias identity and commitments. */
        public Record {
            Permission.requireId(aliasId, "repository alias");
            Objects.requireNonNull(realmId, "realmId");
            Objects.requireNonNull(authorityId, "authorityId");
            Objects.requireNonNull(type, "type");
            Objects.requireNonNull(targetObjectId, "targetObjectId");
            issuerId = Objects.requireNonNull(issuerId, "issuerId");
            pathId = Objects.requireNonNull(pathId, "pathId");
            requireDigest(targetCommitment);
            Objects.requireNonNull(createdAt, "createdAt");
            Objects.requireNonNull(updatedAt, "updatedAt");
            Permission.requirePrincipal(actorPrincipalId);
            Objects.requireNonNull(state, "state");
            requireDigest(recordCommitment);
            if (!aliasId.equals(idFor(realmId, authorityId, type))) {
                throw new IllegalArgumentException("Repository alias identity mismatch");
            }
            if (type == Type.CURRENT_CHAIN != issuerId.isPresent()
                    || type == Type.CURRENT_CHAIN != pathId.isPresent()) {
                throw new IllegalArgumentException("Repository alias target shape mismatch");
            }
            if (!recordCommitment.equals(commitmentFor(realmId, authorityId, type, targetObjectId,
                    issuerId, pathId, targetCommitment, state))) {
                throw new IllegalArgumentException("Repository alias record commitment mismatch");
            }
        }
    }

    private final RealmId realmId;
    private final ServerControlStore store;
    private final PkiRepository repository;
    private final DisclosureService disclosure;
    private final Clock clock;
    private final SafeAudit audit;

    /** Creates a repository alias authority over one realm control store. */
    public RepositoryAliasService(RealmId realmId, ServerControlStore store, PkiRepository repository,
            DisclosureService disclosure, Clock clock, zeroecho.pki.spi.audit.AuditSink auditSink) {
        this.realmId = Objects.requireNonNull(realmId, "realmId");
        this.store = Objects.requireNonNull(store, "store");
        this.repository = Objects.requireNonNull(repository, "repository");
        this.disclosure = Objects.requireNonNull(disclosure, "disclosure");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.audit = new SafeAudit(clock, auditSink);
    }

    /** Returns an exact alias, including a durable removed record. */
    public Record require(PkiId authorityId, Type type) {
        return store.requireRepositoryAlias(idFor(realmId, authorityId, type));
    }

    /** Returns a bounded alias page. */
    public ServerControlStore.Page<Record> list(int offset, int limit) {
        return store.repositoryAliases(offset, limit);
    }

    /** Atomically publishes a validated current-CRL alias. */
    public Record setCurrentCrl(PkiId authorityId, PkiId statusObjectId, Optional<String> expected,
            String actorPrincipalId) {
        StatusObject status = repository.statusObject(statusObjectId)
                .orElseThrow(() -> new IllegalArgumentException("Status object is unavailable"));
        if (!authorityId.equals(status.issuerCaId()) || status.type() != StatusObjectType.CRL) {
            throw new IllegalArgumentException("Current CRL target is invalid");
        }
        requirePublic(statusObjectId, DisclosureService.ObjectType.CRL, true);
        return set(authorityId, Type.CURRENT_CRL, statusObjectId, Optional.empty(), Optional.empty(),
                status.content().sha256(), expected, actorPrincipalId);
    }

    /** Atomically publishes one exact current public chain path. */
    public Record setCurrentChain(PkiId authorityId, PkiId issuerId, PkiId pathId, Optional<String> expected,
            String actorPrincipalId) {
        IssuerGeneration issuer = repository.issuer(issuerId)
                .orElseThrow(() -> new IllegalArgumentException("Issuer generation is unavailable"));
        IssuerChainPath path = repository.chainPath(pathId)
                .orElseThrow(() -> new IllegalArgumentException("Issuer chain path is unavailable"));
        if (!authorityId.equals(issuer.authorityId()) || !authorityId.equals(path.authorityId())
                || !issuerId.equals(path.issuerId())) {
            throw new IllegalArgumentException("Current chain target is outside the authority");
        }
        for (PkiId credentialId : path.orderedCredentialIds()) {
            requirePublic(credentialId, DisclosureService.ObjectType.CA_CERTIFICATE, false);
        }
        return set(authorityId, Type.CURRENT_CHAIN, pathId, Optional.of(issuerId), Optional.of(pathId),
                path.pathCommitment(), expected, actorPrincipalId);
    }

    /** Atomically removes an alias without deleting its target. */
    public Record remove(PkiId authorityId, Type type, String expectedCommitment, String actorPrincipalId) {
        Record current = require(authorityId, type);
        if (current.state() == State.REMOVED) {
            return current;
        }
        Instant now = clock.instant();
        Record removed = record(current.realmId(), current.authorityId(), current.type(), current.targetObjectId(),
                current.issuerId(), current.pathId(), current.targetCommitment(), current.createdAt(), now,
                actorPrincipalId, State.REMOVED);
        store.replaceRepositoryAlias(current, removed, Optional.of(expectedCommitment));
        audit.record("REPOSITORY_ALIAS_REMOVE", actorPrincipalId, Optional.of(current.targetObjectId()),
                Map.of("type", type.name()));
        return removed;
    }

    private Record set(PkiId authorityId, Type type, PkiId targetId, Optional<PkiId> issuerId,
            Optional<PkiId> pathId, String targetCommitment, Optional<String> expected, String actor) {
        Instant now = clock.instant();
        String aliasId = idFor(realmId, authorityId, type);
        Optional<Record> current = store.findRepositoryAlias(aliasId);
        if (current.isPresent() && expected.isEmpty()) {
            Record existing = current.orElseThrow();
            if (existing.state() == State.ACTIVE && existing.targetObjectId().equals(targetId)
                    && existing.issuerId().equals(issuerId) && existing.pathId().equals(pathId)
                    && existing.targetCommitment().equals(targetCommitment)) {
                return existing;
            }
            throw new IllegalStateException("Repository alias update requires expected-current commitment");
        }
        Record value = record(realmId, authorityId, type, targetId, issuerId, pathId, targetCommitment,
                current.map(Record::createdAt).orElse(now), now, actor, State.ACTIVE);
        if (current.isEmpty()) {
            if (expected.isPresent()) {
                throw new IllegalStateException("Repository alias expectation conflicts");
            }
            store.createRepositoryAlias(value);
        } else {
            store.replaceRepositoryAlias(current.orElseThrow(), value, expected);
        }
        audit.record("REPOSITORY_ALIAS_SET", actor, Optional.of(targetId), Map.of("type", type.name()));
        return value;
    }

    private void requirePublic(PkiId objectId, DisclosureService.ObjectType type, boolean crl) {
        DisclosureService.Policy effective = store.findDisclosure(objectId).map(DisclosureService.Record::policy)
                .orElseGet(() -> disclosure.defaultPolicy(type, false, false));
        if (effective != DisclosureService.Policy.PUBLIC) {
            throw new SecurityException(crl ? "CRL is not public" : "Chain credential is not public");
        }
    }

    private static Record record(RealmId realmId, PkiId authorityId, Type type, PkiId target,
            Optional<PkiId> issuer, Optional<PkiId> path, String targetCommitment, Instant createdAt,
            Instant updatedAt, String actor, State state) {
        String commitment = commitmentFor(realmId, authorityId, type, target, issuer, path, targetCommitment, state);
        return new Record(idFor(realmId, authorityId, type), realmId, authorityId, type, target, issuer, path,
                targetCommitment, createdAt, updatedAt, actor, state, commitment);
    }

    /** Returns the deterministic alias ID for one realm, authority, and type. */
    public static String idFor(RealmId realmId, PkiId authorityId, Type type) {
        return "repository-alias-" + digest(realmId.value() + "\n" + authorityId.value() + "\n" + type.name())
                .substring(0, 32);
    }

    private static String commitmentFor(RealmId realmId, PkiId authorityId, Type type, PkiId target,
            Optional<PkiId> issuer, Optional<PkiId> path, String targetCommitment, State state) {
        return digest(String.join("\n", realmId.value(), authorityId.value(), type.name(), target.value(),
                issuer.map(PkiId::value).orElse(""), path.map(PkiId::value).orElse(""), targetCommitment,
                state.name()));
    }

    private static String digest(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static void requireDigest(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Repository alias commitment is invalid");
        }
    }
}
