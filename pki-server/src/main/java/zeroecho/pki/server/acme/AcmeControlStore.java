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
package zeroecho.pki.server.acme;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.time.Clock;
import java.time.Instant;

import zeroecho.pki.server.ServerControlStore;

/** Typed ACME record facade over the realm's sole transactional control authority. */
@SuppressWarnings("PMD")
public final class AcmeControlStore {
    private final ServerControlStore control;
    private final AcmeStateCodec codec = new AcmeStateCodec();

    /**
     * Binds ACME state to the lifecycle-owned realm control store.
     *
     * @param control lifecycle-owned realm control store
     */
    public AcmeControlStore(ServerControlStore control) {
        this.control = Objects.requireNonNull(control, "control");
    }

    /**
     * Creates one record after canonical sealing.
     *
     * @param <T> ACME record type
     * @param unsealed validated unsealed domain record
     * @return canonically sealed and durably created record
     */
    public <T> T create(T unsealed) {
        T sealed = seal(unsealed);
        synchronized (control) {
            validateEnrollmentBinding(sealed, true);
            control.mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(record(sealed), Optional.empty())));
        }
        return sealed;
    }

    /**
     * Atomically creates an order and its complete authorization/challenge graph.
     *
     * @param order unsealed order record
     * @param authorizations complete unsealed authorization set
     * @param challenges complete unsealed challenge set
     * @return atomically committed sealed order graph
     */
    public Graph createOrderGraph(AcmeState.Order order, List<AcmeState.Authorization> authorizations,
            List<AcmeState.Challenge> challenges) {
        AcmeState.Order sealedOrder = seal(order);
        List<AcmeState.Authorization> sealedAuthorizations = authorizations.stream()
                .map(this::<AcmeState.Authorization>seal).toList();
        List<AcmeState.Challenge> sealedChallenges = challenges.stream()
                .map(this::<AcmeState.Challenge>seal).toList();
        List<ServerControlStore.ProtocolMutation> changes = new ArrayList<>();
        changes.add(new ServerControlStore.ProtocolMutation(record(sealedOrder), Optional.empty()));
        sealedAuthorizations.forEach(value -> changes.add(new ServerControlStore.ProtocolMutation(record(value), Optional.empty())));
        sealedChallenges.forEach(value -> changes.add(new ServerControlStore.ProtocolMutation(record(value), Optional.empty())));
        control.mutateProtocol(changes);
        return new Graph(sealedOrder, sealedAuthorizations, sealedChallenges);
    }

    /**
     * Atomically compare-and-replaces a finite related record set.
     *
     * @param replacements finite compare-and-set replacements
     * @return durably replaced records in request order
     */
    public List<Object> replace(List<Replacement> replacements) {
        return transition(replacements, List.of()).replaced();
    }

    /**
     * Atomically creates immutable records and replaces their related owners.
     *
     * @param replacements finite compare-and-set replacements
     * @param creations finite related records to create
     * @return atomically committed transition result
     */
    public Transition transition(List<Replacement> replacements, List<?> creations) {
        List<Object> sealed = replacements.stream().map(Replacement::next).map(this::sealObject).toList();
        List<Object> created = creations.stream().map(this::sealObject).toList();
        List<ServerControlStore.ProtocolMutation> changes = new ArrayList<>();
        for (int index = 0; index < replacements.size(); index++) {
            Object prior = replacements.get(index).prior(); Object next = sealed.get(index);
            changes.add(new ServerControlStore.ProtocolMutation(record(next), Optional.of(commitment(prior))));
        }
        created.forEach(value -> changes.add(new ServerControlStore.ProtocolMutation(record(value), Optional.empty())));
        synchronized (control) {
            for (Object value : created) validateEnrollmentBinding(value, true);
            for (Object value : sealed) {
                if (value instanceof AcmeState.Directory directory && directory.status() == AcmeState.DirectoryStatus.ACTIVE) {
                    validateEnrollmentBinding(directory, true);
                }
            }
            control.mutateProtocol(changes);
        }
        return new Transition(sealed, created);
    }

    private void validateEnrollmentBinding(Object record, boolean active) {
        if (record instanceof AcmeState.Directory directory) {
            zeroecho.pki.server.enrollment.EnrollmentProfileService.requireBinding(control, directory.enrollmentProfileId(),
                    directory.profile().profileId(), directory.authorityId().value(), active);
        }
    }

    /**
     * Rejects a policy replacement that would strand an active directory.
     * Callers retain the control monitor through the subsequent policy mutation.
     * Suspended policies remain compatible and can be administratively reactivated.
     * @param replacement candidate enrollment policy
     */
    public void requireCompatibleEnrollmentProfile(zeroecho.pki.server.enrollment.EnrollmentProfile replacement) {
        synchronized (control) {
            visit(AcmeState.Directory.class, directory -> {
                if (directory.status() == AcmeState.DirectoryStatus.ACTIVE
                        && directory.enrollmentProfileId().equals(replacement.id())
                        && (!directory.profile().profileId().equals(replacement.certificateProfileId())
                        || !replacement.allowedAuthorityIds().isEmpty()
                        && !replacement.allowedAuthorityIds().contains(directory.authorityId().value()))) {
                    throw new IllegalStateException("Deactivate incompatible ACME directories before updating the enrollment profile");
                }
            });
        }
    }

    /**
     * Results of one atomic ACME graph transition.
     *
     * @param replaced durably replaced records in request order
     * @param created durably created records in request order
     */
    public record Transition(List<Object> replaced, List<Object> created) {
        /** Defensively snapshots transition results. */
        public Transition { replaced = List.copyOf(replaced); created = List.copyOf(created); }
    }

    /**
     * One exact prior-to-next ACME compare-and-set transition.
     *
     * @param prior caller-observed current record
     * @param next replacement record with the same type and identity
     */
    public record Replacement(Object prior, Object next) {
        /** Validates stable type and identity before persistence. */
        public Replacement {
            Objects.requireNonNull(prior, "prior"); Objects.requireNonNull(next, "next");
            if (!prior.getClass().equals(next.getClass()) || !identity(prior).equals(identity(next))) {
                throw new IllegalArgumentException("ACME replacement identity is immutable");
            }
        }
    }

    /**
     * Reads one exact typed record and cross-checks its identity.
     *
     * @param <T> ACME record type
     * @param type exact ACME record class
     * @param recordId stable record identifier
     * @return validated record or empty when absent
     */
    public <T> Optional<T> get(Class<T> type, String recordId) {
        String namespace = namespace(type);
        return control.protocolRecord(namespace, recordId).map(value -> {
            Object decoded = codec.decode(value.payload());
            if (!type.isInstance(decoded) || !recordId.equals(identity(decoded))
                    || !value.commitment().equals(commitment(decoded))) {
                throw new IllegalStateException("ACME record identity or commitment mismatch");
            }
            return type.cast(decoded);
        });
    }

    /**
     * Validates an account from a stable startup snapshot without a second lookup.
     * @param record exact account namespace record
     * @return strictly decoded account
     */
    public AcmeState.Account decodeAccount(ServerControlStore.ProtocolRecord record) {
        Object decoded = codec.decode(record.payload());
        if (!ServerControlStore.ACME_ACCOUNT.equals(record.namespace()) || !(decoded instanceof AcmeState.Account account)
                || !record.recordId().equals(account.accountId()) || !record.commitment().equals(account.commitment())) {
            throw new IllegalStateException("ACME account snapshot differs");
        }
        return account;
    }

    /**
     * Measures exclusion-history retention, including its bounded account identity
     * and framing, and verifies that the complete account fits the control-record cap.
     * @param account validated account awaiting persistence
     * @return bytes charged to the shared enrollment retention budget
     */
    public long accountHistoryCharge(AcmeState.Account account) {
        record(seal(account)); // The existing ProtocolRecord boundary enforces its payload cap.
        return Math.addExact(16L + account.accountId().getBytes(java.nio.charset.StandardCharsets.UTF_8).length,
                AcmeStateCodec.accountKeyHistory(account.keyHistory()).length);
    }

    /**
     * Returns one bounded typed page without aggregating the namespace.
     *
     * @param <T> ACME record type
     * @param type exact ACME record class
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     * @return bounded validated record page
     */
    public <T> ServerControlStore.Page<T> page(Class<T> type, int offset, int limit) {
        ServerControlStore.Page<ServerControlStore.ProtocolRecord> page =
                control.protocolRecords(namespace(type), offset, limit);
        List<T> values = page.values().stream().map(value -> {
            Object decoded = codec.decode(value.payload());
            if (!type.isInstance(decoded) || !value.recordId().equals(identity(decoded))
                    || !value.commitment().equals(commitment(decoded))) {
                throw new IllegalStateException("ACME page record mismatch");
            }
            return type.cast(decoded);
        }).toList();
        return new ServerControlStore.Page<>(values, page.nextOffset(), page.hasMore());
    }

    /**
     * Strictly decodes, cross-checks, expires, and safely recovers every ACME
     * control record without re-running validation or issuance.
     *
     * @param clock authoritative recovery clock
     */
    public void validateAndRecover(Clock clock) {
        Instant now = Objects.requireNonNull(clock, "clock").instant();
        visit(AcmeState.Directory.class, directory -> {
            if (directory.status() == AcmeState.DirectoryStatus.ACTIVE) validateEnrollmentBinding(directory, false);
        });
        visit(AcmeState.Account.class, account -> {
            AcmeState.Directory directory = get(AcmeState.Directory.class, account.directoryId()).orElseThrow();
            if (account.directoryRevision() != directory.revision()
                    || !account.directoryPolicyCommitment().equals(directory.policyCommitment())) {
                throw new IllegalStateException("ACME account directory binding mismatch");
            }
        });
        visit(AcmeState.Order.class, order -> validateOrder(order, now));
        visit(AcmeState.Authorization.class, authorization -> validateAuthorization(authorization, now));
        visit(AcmeState.Challenge.class, challenge -> validateChallenge(challenge, now));
        visit(AcmeState.AuthorizationEvidence.class, evidence -> {
            AcmeState.Authorization authorization = get(AcmeState.Authorization.class,
                    evidence.authorizationId()).orElseThrow();
            if (!authorization.identifier().equals(evidence.identifier())) {
                throw new IllegalStateException("ACME evidence authorization binding mismatch");
            }
        });
    }

    private void validateOrder(AcmeState.Order order, Instant now) {
        AcmeState.Account account = get(AcmeState.Account.class, order.accountId()).orElseThrow();
        AcmeState.Directory directory = get(AcmeState.Directory.class, order.directoryId()).orElseThrow();
        if (!account.directoryId().equals(order.directoryId()) || order.directoryRevision() != directory.revision()
                || !order.directoryPolicyCommitment().equals(directory.policyCommitment())) {
            throw new IllegalStateException("ACME order authority binding mismatch");
        }
        for (String authorizationId : order.authorizationIds()) {
            AcmeState.Authorization authorization = get(AcmeState.Authorization.class, authorizationId).orElseThrow();
            if (!authorization.orderId().equals(order.orderId())
                    || !authorization.accountId().equals(order.accountId())) {
                throw new IllegalStateException("ACME order authorization binding mismatch");
            }
        }
        if (!order.expiresAt().isAfter(now) && order.status() != AcmeState.OrderStatus.VALID
                && order.status() != AcmeState.OrderStatus.INVALID) {
            replace(List.of(new Replacement(order, new AcmeState.Order(order.orderId(), order.accountId(),
                    order.directoryId(), order.directoryRevision(), order.directoryPolicyCommitment(), order.authorityId(),
                    order.profile(), order.issuerId(), order.issuancePathId(), order.issuancePathCommitment(),
                    order.identifiers(), order.notBefore(), order.notAfter(), AcmeState.OrderStatus.INVALID,
                    order.authorizationIds(), Optional.empty(), order.issuanceCommitment(),
                    order.signingOperationId(),
                    order.createdAt(), order.expiresAt(), ZERO))));
        }
    }

    private void validateAuthorization(AcmeState.Authorization authorization, Instant now) {
        AcmeState.Order order = get(AcmeState.Order.class, authorization.orderId()).orElseThrow();
        if (!order.accountId().equals(authorization.accountId())
                || !order.authorizationIds().contains(authorization.authorizationId())) {
            throw new IllegalStateException("ACME authorization order binding mismatch");
        }
        for (String challengeId : authorization.challengeIds()) {
            AcmeState.Challenge challenge = get(AcmeState.Challenge.class, challengeId).orElseThrow();
            if (!challenge.authorizationId().equals(authorization.authorizationId())) {
                throw new IllegalStateException("ACME authorization challenge binding mismatch");
            }
        }
        if (!authorization.expiresAt().isAfter(now)
                && authorization.status() == AcmeState.AuthorizationStatus.PENDING) {
            replace(List.of(new Replacement(authorization, new AcmeState.Authorization(
                    authorization.authorizationId(), authorization.orderId(), authorization.accountId(),
                    authorization.identifier(), AcmeState.AuthorizationStatus.EXPIRED,
                    authorization.challengeIds(), authorization.expiresAt(), Optional.empty(), ZERO))));
        }
    }

    private void validateChallenge(AcmeState.Challenge challenge, Instant now) {
        AcmeState.Authorization authorization = get(AcmeState.Authorization.class,
                challenge.authorizationId()).orElseThrow();
        if (!authorization.challengeIds().contains(challenge.challengeId())) {
            throw new IllegalStateException("ACME challenge authorization binding mismatch");
        }
        if (challenge.status() == AcmeState.ChallengeStatus.PROCESSING) {
            replace(List.of(new Replacement(challenge, new AcmeState.Challenge(challenge.challengeId(),
                    challenge.authorizationId(), challenge.type(), challenge.token(), AcmeState.ChallengeStatus.PENDING,
                    challenge.providerId(), challenge.attempt(), Optional.of("RECOVERY_REQUIRED"), Optional.empty(),
                    challenge.createdAt(), now, ZERO))));
        }
    }

    private <T> void visit(Class<T> type, java.util.function.Consumer<T> consumer) {
        int offset = 0;
        do {
            ServerControlStore.Page<T> current = page(type, offset, 256);
            current.values().forEach(consumer);
            if (!current.hasMore()) {
                return;
            }
            offset = current.nextOffset();
        } while (true);
    }

    private static final String ZERO = "0".repeat(64);

    /**
     * Immutable atomically committed order graph.
     *
     * @param order sealed order record
     * @param authorizations sealed order authorizations
     * @param challenges sealed authorization challenges
     */
    public record Graph(AcmeState.Order order, List<AcmeState.Authorization> authorizations,
            List<AcmeState.Challenge> challenges) {
        /** Defensively snapshots the graph. */
        public Graph {
            Objects.requireNonNull(order, "order"); authorizations = List.copyOf(authorizations);
            challenges = List.copyOf(challenges);
        }
    }

    @SuppressWarnings("unchecked")
    private <T> T seal(T value) { return (T) codec.seal(Objects.requireNonNull(value, "value")); }
    private Object sealObject(Object value) { return codec.seal(Objects.requireNonNull(value, "value")); }
    private ServerControlStore.ProtocolRecord record(Object value) {
        return new ServerControlStore.ProtocolRecord(namespace(value.getClass()), identity(value),
                commitment(value), codec.encode(value));
    }
    private static String commitment(Object value) {
        return switch (value) {
            case AcmeState.Directory item -> item.commitment(); case AcmeState.Account item -> item.commitment();
            case AcmeState.Order item -> item.commitment(); case AcmeState.Authorization item -> item.commitment();
            case AcmeState.Challenge item -> item.commitment(); case AcmeState.AuthorizationEvidence item -> item.commitment();
            default -> throw new IllegalArgumentException("Unsupported ACME record type");
        };
    }
    private static String identity(Object value) {
        return switch (value) {
            case AcmeState.Directory item -> item.directoryId(); case AcmeState.Account item -> item.accountId();
            case AcmeState.Order item -> item.orderId(); case AcmeState.Authorization item -> item.authorizationId();
            case AcmeState.Challenge item -> item.challengeId(); case AcmeState.AuthorizationEvidence item -> item.evidenceId();
            default -> throw new IllegalArgumentException("Unsupported ACME record type");
        };
    }
    private static String namespace(Class<?> type) {
        if (type == AcmeState.Directory.class) return ServerControlStore.ACME_DIRECTORY;
        if (type == AcmeState.Account.class) return ServerControlStore.ACME_ACCOUNT;
        if (type == AcmeState.Order.class) return ServerControlStore.ACME_ORDER;
        if (type == AcmeState.Authorization.class) return ServerControlStore.ACME_AUTHORIZATION;
        if (type == AcmeState.Challenge.class) return ServerControlStore.ACME_CHALLENGE;
        if (type == AcmeState.AuthorizationEvidence.class) return ServerControlStore.ACME_EVIDENCE;
        throw new IllegalArgumentException("Unsupported ACME record type");
    }
}
