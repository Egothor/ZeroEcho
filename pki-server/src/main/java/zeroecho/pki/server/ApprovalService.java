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
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Durable exact-operation multi-party approval service. */
@SuppressWarnings({ "PMD.ControlStatementBraces", "PMD.FieldDeclarationsShouldBeAtStartOfClass",
        "PMD.UseObjectForClearerAPI", "PMD.AvoidSynchronizedAtMethodLevel" })
public final class ApprovalService {
    /** Approval lifecycle states. */
    public enum State {
        /** Awaiting sufficient attributable decisions. */ PENDING(1),
        /** Approval threshold was satisfied. */ APPROVED(2),
        /** An eligible approver rejected the request. */ REJECTED(3),
        /** The request exceeded its approval lifetime. */ EXPIRED(4),
        /** The requester cancelled the request. */ CANCELLED(5),
        /** The approved operation is durably claimed for execution. */ EXECUTING(6),
        /** Execution completed and its safe classification is linked. */ EXECUTED(7);
        private final int code;
        State(int code) { this.code = code; }
        /**
         * Returns the stable persistence code.
         *
         * @return stable persistence code
         */
        public int code() { return code; }
        /**
         * Resolves a stable persistence code.
         *
         * @param code persisted approval-state code
         * @return corresponding approval state
         */
        public static State fromCode(int code) {
            for (State candidate : values()) if (candidate.code == code) return candidate;
            throw new IllegalArgumentException("Unknown approval-state code");
        }
    }

    /** Individual immutable approval choice. */
    public enum Choice {
        /** Supports execution of the exact requested operation. */ APPROVE(1),
        /** Rejects execution of the exact requested operation. */ REJECT(2);
        private final int code;
        Choice(int code) { this.code = code; }
        /**
         * Returns the stable persistence code.
         *
         * @return stable persistence code
         */
        public int code() { return code; }
        /**
         * Resolves a stable persistence code.
         *
         * @param code persisted approval-choice code
         * @return corresponding approval choice
         */
        public static Choice fromCode(int code) {
            return switch (code) { case 1 -> APPROVE; case 2 -> REJECT;
                default -> throw new IllegalArgumentException("Unknown approval-choice code"); };
        }
    }

    /**
     * Immutable approval policy.
     *
     * @param policyId stable policy identity
     * @param threshold required distinct approvals
     * @param eligibleApprovers finite M-set, empty only when a required role defines eligibility
     * @param requiredRoleTemplateIds eligible approver role-template IDs
     * @param requesterSeparation whether the requester is barred from approving
     * @param lifetime positive approval lifetime
     * @param justificationRequired whether a nonblank justification is mandatory
     */
    public record Policy(String policyId, int threshold, Set<String> eligibleApprovers,
            Set<String> requiredRoleTemplateIds, boolean requesterSeparation, Duration lifetime,
            boolean justificationRequired) {
        /** Validates the finite N-of-M policy. */
        public Policy {
            Permission.requireId(policyId, "approval policy");
            eligibleApprovers = Set.copyOf(Objects.requireNonNull(eligibleApprovers, "eligibleApprovers"));
            requiredRoleTemplateIds = Set.copyOf(
                    Objects.requireNonNull(requiredRoleTemplateIds, "requiredRoleTemplateIds"));
            eligibleApprovers.forEach(Permission::requirePrincipal);
            requiredRoleTemplateIds.forEach(value -> Permission.requireId(value, "role template"));
            if (threshold <= 0 || eligibleApprovers.isEmpty() && requiredRoleTemplateIds.isEmpty()
                    || !eligibleApprovers.isEmpty() && threshold > eligibleApprovers.size()) {
                throw new IllegalArgumentException("Approval threshold or eligibility set is invalid");
            }
            Objects.requireNonNull(lifetime, "lifetime");
            if (lifetime.isZero() || lifetime.isNegative() || lifetime.compareTo(Duration.ofDays(30)) > 0) {
                throw new IllegalArgumentException("Approval lifetime is invalid");
            }
        }

        /**
         * Returns a stable commitment for this policy.
         *
         * @return lowercase SHA-256 commitment to the complete policy
         */
        public String commitment() {
            List<String> approvers = eligibleApprovers.stream().sorted().toList();
            List<String> roles = requiredRoleTemplateIds.stream().sorted().toList();
            return digest(policyId + '|' + threshold + '|' + String.join(",", approvers) + '|'
                    + String.join(",", roles) + '|' + requesterSeparation + '|' + lifetime.toSeconds()
                    + '|' + justificationRequired);
        }
    }

    /**
     * One attributable immutable decision.
     *
     * @param principalId deciding principal identifier
     * @param choice approval or rejection
     * @param justification bounded operator justification
     * @param decidedAt server-authoritative decision time
     */
    public record Decision(String principalId, Choice choice, String justification, Instant decidedAt) {
        /** Validates the decision. */
        public Decision {
            Permission.requirePrincipal(principalId);
            Objects.requireNonNull(choice, "choice");
            Permission.requireBounded(justification, 2048, "justification");
            Objects.requireNonNull(decidedAt, "decidedAt");
        }
    }

    /**
     * Durable approval authority record.
     *
     * @param approvalId stable record identity
     * @param operationId stable typed operation name
     * @param operationCommitment exact safe operation commitment
     * @param scope exact realm/authority/issuer/profile scope
     * @param requesterPrincipalId requester identity
     * @param createdAt creation time
     * @param expiresAt expiry time
     * @param policy approval policy
     * @param policyCommitment exact policy commitment
     * @param state lifecycle state
     * @param decisions immutable attributable decisions
     * @param resultClassification safe linked execution classification
     */
    public record Request(String approvalId, String operationId, String operationCommitment,
            Permission.Scope scope, String requesterPrincipalId, Instant createdAt, Instant expiresAt,
            Policy policy, String policyCommitment, State state, List<Decision> decisions,
            Optional<String> resultClassification) {
        /** Validates and snapshots the durable record. */
        public Request {
            Permission.requireId(approvalId, "approval");
            Permission.requireBounded(operationId, 256, "operation ID");
            requireDigest(operationCommitment);
            Objects.requireNonNull(scope, "scope");
            Permission.requirePrincipal(requesterPrincipalId);
            Objects.requireNonNull(createdAt, "createdAt");
            Objects.requireNonNull(expiresAt, "expiresAt");
            if (!expiresAt.isAfter(createdAt)) throw new IllegalArgumentException("Approval expiry is invalid");
            Objects.requireNonNull(policy, "policy");
            requireDigest(policyCommitment);
            if (!policy.commitment().equals(policyCommitment)) {
                throw new IllegalArgumentException("Approval-policy commitment mismatch");
            }
            Objects.requireNonNull(state, "state");
            decisions = List.copyOf(Objects.requireNonNull(decisions, "decisions"));
            resultClassification = Objects.requireNonNull(resultClassification, "resultClassification")
                    .map(value -> Permission.requireBounded(value, 256, "result classification"));
            if (state == State.EXECUTED != resultClassification.isPresent()) {
                throw new IllegalArgumentException("Executed approval result linkage is invalid");
            }
        }
    }

    private final ServerControlStore store;
    private final Clock clock;
    private final SafeAudit audit;

    /**
     * Creates a durable approval service over one server-control authority.
     *
     * @param store durable server-control store
     * @param clock authoritative server clock
     * @param auditSink required safe audit sink
     */
    public ApprovalService(ServerControlStore store, Clock clock, zeroecho.pki.spi.audit.AuditSink auditSink) {
        this.store = Objects.requireNonNull(store, "store");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.audit = new SafeAudit(clock, auditSink);
    }

    /**
     * Creates a new pending exact-operation request.
     *
     * @param approvalId stable approval identifier
     * @param operationId stable typed operation identifier
     * @param operationCommitment exact safe operation commitment
     * @param scope exact security scope
     * @param requesterPrincipalId requesting principal identifier
     * @param policy frozen approval policy
     * @return new durable pending approval request
     */
    public synchronized Request request(String approvalId, String operationId, String operationCommitment,
            Permission.Scope scope, String requesterPrincipalId, Policy policy) {
        store.requirePrincipal(requesterPrincipalId);
        Instant now = clock.instant();
        Request request = new Request(approvalId, operationId, operationCommitment, scope, requesterPrincipalId,
                now, now.plus(policy.lifetime()), policy, policy.commitment(), State.PENDING, List.of(),
                Optional.empty());
        store.createApproval(request);
        audit.record("APPROVAL_REQUEST", requesterPrincipalId, Optional.empty(),
                Map.of("state", "PENDING", "approvalId", approvalId, "opCommitment", operationCommitment,
                        "policyCommitment", policy.commitment()));
        return request;
    }

    /**
     * Records one distinct qualified decision and advances the durable state.
     *
     * @param approvalId stable approval identifier
     * @param principalId deciding principal identifier
     * @param choice approval or rejection
     * @param justification bounded operator justification
     * @return durably updated approval request
     */
    public synchronized Request decide(String approvalId, String principalId,
            Choice choice, String justification) {
        SecurityPrincipal principal = store.requirePrincipal(principalId);
        Request current = requireCurrent(approvalId);
        requirePending(current);
        if (!principal.enabled() || current.policy().requesterSeparation()
                && current.requesterPrincipalId().equals(principal.principalId())) {
            throw new IllegalStateException("Principal is not eligible to decide this approval");
        }
        boolean direct = current.policy().eligibleApprovers().contains(principal.principalId());
        boolean role = store.assignmentsFor(principal.principalId()).stream()
                .filter(RoleTemplateCatalog.Assignment::enabled)
                .filter(assignment -> contains(assignment.scope(), current.scope()))
                .map(RoleTemplateCatalog.Assignment::templateId)
                .anyMatch(current.policy().requiredRoleTemplateIds()::contains);
        if (!direct && !role) throw new IllegalStateException("Principal is not an eligible approver");
        if (current.decisions().stream().anyMatch(item -> item.principalId().equals(principal.principalId()))) {
            throw new IllegalStateException("Principal has already decided this approval");
        }
        if (current.policy().justificationRequired() && (justification == null || justification.isBlank())) {
            throw new IllegalArgumentException("Approval justification is required");
        }
        List<Decision> decisions = new ArrayList<>(current.decisions());
        decisions.add(new Decision(principal.principalId(), choice,
                Permission.requireBounded(justification, 2048, "justification"), clock.instant()));
        decisions.sort(Comparator.comparing(Decision::decidedAt).thenComparing(Decision::principalId));
        State state = choice == Choice.REJECT ? State.REJECTED
                : decisions.stream().filter(item -> item.choice() == Choice.APPROVE).count()
                        >= current.policy().threshold() ? State.APPROVED : State.PENDING;
        Request updated = copy(current, state, decisions, Optional.empty());
        store.replaceApproval(current, updated);
        audit.record("APPROVAL_DECISION", principal.principalId(), Optional.empty(),
                Map.of("state", state.name(), "approvalId", approvalId, "choice", choice.name(),
                        "opCommitment", current.operationCommitment()));
        return updated;
    }

    /**
     * Cancels a pending request by its requester.
     *
     * @param approvalId stable approval identifier
     * @param requesterPrincipalId requesting principal identifier
     * @return durably cancelled request
     */
    public synchronized Request cancel(String approvalId, String requesterPrincipalId) {
        Request current = requireCurrent(approvalId);
        requirePending(current);
        if (!current.requesterPrincipalId().equals(requesterPrincipalId)) {
            throw new IllegalStateException("Only the requester may cancel a pending approval");
        }
        Request updated = copy(current, State.CANCELLED, current.decisions(), Optional.empty());
        store.replaceApproval(current, updated);
        audit.record("APPROVAL_CANCEL", requesterPrincipalId, Optional.empty(),
                Map.of("state", "CANCELLED", "approvalId", approvalId, "opCommitment", current.operationCommitment()));
        return updated;
    }

    /**
     * Validates and durably claims an approved operation before dispatch.
     *
     * @param approvalId stable approval identifier
     * @param operationId stable typed operation identifier
     * @param operationCommitment exact safe operation commitment
     * @param scope exact security scope
     * @return durably claimed executing request
     */
    public synchronized Request claim(String approvalId, String operationId, String operationCommitment,
            Permission.Scope scope) {
        Request current = requireCurrent(approvalId);
        if (!current.operationId().equals(operationId) || !current.operationCommitment().equals(operationCommitment)
                || !current.scope().equals(scope)) {
            throw new IllegalStateException("Approval does not bind the requested operation");
        }
        current = expireIfNecessary(current);
        if (current.state() != State.APPROVED) throw new IllegalStateException("Approval is not executable");
        Request executing = copy(current, State.EXECUTING, current.decisions(), Optional.empty());
        store.replaceApproval(current, executing);
        return executing;
    }

    /**
     * Durably links the safe result of one claimed execution.
     *
     * @param approvalId stable approval identifier
     * @param safeResultClassification safe linked execution result
     * @return durably executed request
     */
    public synchronized Request complete(String approvalId, String safeResultClassification) {
        Request current = requireCurrent(approvalId);
        if (current.state() != State.EXECUTING) throw new IllegalStateException("Approval is not executing");
        Request executed = copy(current, State.EXECUTED, current.decisions(),
                Optional.of(Permission.requireBounded(safeResultClassification, 256, "result classification")));
        store.replaceApproval(current, executed);
        audit.record("APPROVAL_EXECUTION", current.requesterPrincipalId(), Optional.empty(),
                Map.of("result", safeResultClassification, "approvalId", approvalId,
                        "opCommitment", current.operationCommitment()));
        return executed;
    }

    /**
     * Returns the current record, applying durable expiry when necessary.
     *
     * @param approvalId stable approval identifier
     * @return current request after applying expiry
     */
    public synchronized Request requireCurrent(String approvalId) {
        Request current = store.requireApproval(approvalId);
        return expireIfNecessary(current);
    }

    private Request expireIfNecessary(Request current) {
        if ((current.state() == State.PENDING || current.state() == State.APPROVED)
                && !clock.instant().isBefore(current.expiresAt())) {
            Request expired = copy(current, State.EXPIRED, current.decisions(), Optional.empty());
            store.replaceApproval(current, expired);
            audit.record("APPROVAL_EXPIRY", current.requesterPrincipalId(), Optional.empty(),
                    Map.of("state", "EXPIRED", "approvalId", current.approvalId(),
                            "opCommitment", current.operationCommitment()));
            return expired;
        }
        return current;
    }

    private static void requirePending(Request request) {
        if (request.state() != State.PENDING) throw new IllegalStateException("Approval is not pending");
    }

    private static boolean contains(Permission.Scope grant, Permission.Scope request) {
        return grant.realmId().equals(request.realmId())
                && grant.authorityId().map(value -> request.authorityId().filter(value::equals).isPresent())
                        .orElse(true)
                && grant.issuerId().map(value -> request.issuerId().filter(value::equals).isPresent()).orElse(true)
                && grant.profileId().map(value -> request.profileId().filter(value::equals).isPresent()).orElse(true);
    }

    private static Request copy(Request source, State state, List<Decision> decisions,
            Optional<String> result) {
        return new Request(source.approvalId(), source.operationId(), source.operationCommitment(), source.scope(),
                source.requesterPrincipalId(), source.createdAt(), source.expiresAt(), source.policy(),
                source.policyCommitment(), state, decisions, result);
    }

    /**
     * Computes a deterministic SHA-256 hexadecimal commitment.
     *
     * @param canonical canonical non-secret value to commit
     * @return lowercase SHA-256 commitment
     */
    public static String digest(String canonical) {
        Objects.requireNonNull(canonical, "canonical");
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(canonical.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static void requireDigest(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Commitment is not canonical SHA-256");
        }
    }
}
