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

import java.util.Set;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Coordinates durable, scoped emergency grants with mandatory expiry.
 *
 * <p>Stateful operations hold the supplied {@link ServerControlStore} monitor
 * throughout validation, record reads, updates and best-effort audit delivery.
 * This is the same authority held by administrative-request reconciliation and
 * gateway assessment. Calls made while already owning that authority are
 * reentrant, and separate service instances sharing a store remain serialized.
 *
 * <p>Audit delivery by stateful operations executes on the calling thread while
 * the authority is held. A collaborator must not synchronously wait for another
 * thread that needs the same control store; the service does not bound an
 * external callback's duration. {@link #auditUse(String)} emits telemetry
 * without acquiring the control authority or changing retained state.
 */
@SuppressWarnings({"PMD.FieldDeclarationsShouldBeAtStartOfClass", "PMD.UseObjectForClearerAPI", "PMD.AvoidSynchronizedStatement", "PMD.ExcessiveParameterList"})
public final class BreakGlassService {
    /**
     * Break-glass lifecycle states.
     */
    public enum State {
        /**
         * Emergency grant is active and not expired.
         */
        ACTIVE(1),
        /**
         * Emergency grant was explicitly revoked.
         */
        REVOKED(2),
        /**
         * Mandatory emergency lifetime elapsed.
         */
        EXPIRED(3),
        /**
         * Emergency grant awaits independent activation.
         */
        PENDING(4);
        private final int code;
        /* default */ State(int code) { this.code = code; }
        /**
         * Returns the stable persistence code.
         *
         * @return stable persistence code
         */
        public int code() { return code; }
        /**
         * Resolves one stable persistence code.
         *
         * @param code persisted break-glass state code
         * @return corresponding lifecycle state
         * @throws IllegalArgumentException if the code does not identify a supported break-glass state
         */
        public static State fromCode(int code) {
            return switch (code) { case 1 -> ACTIVE; case 2 -> REVOKED; case 3 -> EXPIRED; case 4 -> PENDING;
                default -> throw new IllegalArgumentException("Unknown break-glass state code"); };
        }
    }

    /**
     * Durable break-glass record.
     *
     * @param breakGlassId stable emergency grant identity
     * @param principalId grantee
     * @param grant exact scoped permission grant
     * @param reason mandatory reason
     * @param issuerPrincipalId independent issuer identity
     * @param approvalId optional independent approval authority
     * @param createdAt creation time
     * @param activatedAt activation time
     * @param expiresAt mandatory expiry
     * @param state lifecycle state
     * @param auditCommitment stable safe commitment
     */
    public record Record(String breakGlassId, String principalId, Permission.Grant grant, String reason,
            String issuerPrincipalId, Optional<String> approvalId, Instant createdAt, Optional<Instant> activatedAt,
            Instant expiresAt, State state, String auditCommitment) {
        /**
         * Validates the strict time-limited scoped record.
         * @param breakGlassId stable emergency grant identity
         * @param principalId grantee
         * @param grant exact scoped permission grant
         * @param reason mandatory reason
         * @param issuerPrincipalId independent issuer identity
         * @param approvalId optional independent approval authority
         * @param createdAt creation time
         * @param activatedAt activation time
         * @param expiresAt mandatory expiry
         * @param state lifecycle state
         * @param auditCommitment stable safe commitment
         * @throws NullPointerException if any of {@code grant}, {@code approvalId}, {@code createdAt}, {@code
         *         activatedAt}, {@code expiresAt}, {@code state} is null
         * @throws IllegalArgumentException if the grant is not an explicit scoped allow or issuer and grantee
         *         are the same principal or the expiry does not define a permitted lifetime or activation
         *         coordinates do not match lifecycle state or the audit commitment is noncanonical
         */
        public Record {
            Permission.requireId(breakGlassId, "break-glass");
            Permission.requirePrincipal(principalId);
            Objects.requireNonNull(grant, "grant");
            if (!grant.principalId().equals(principalId) || grant.effect() != Permission.Effect.ALLOW) {
                throw new IllegalArgumentException("Break-glass grant must be an explicit scoped allow");
            }
            Permission.requireBounded(reason, 2048, "break-glass reason");
            Permission.requirePrincipal(issuerPrincipalId);
            if (issuerPrincipalId.equals(principalId)) {
                throw new IllegalArgumentException("Break-glass issuer and grantee must differ");
            }
            approvalId = Objects.requireNonNull(approvalId, "approvalId");
            Objects.requireNonNull(createdAt, "createdAt");
            activatedAt = Objects.requireNonNull(activatedAt, "activatedAt");
            Objects.requireNonNull(expiresAt, "expiresAt");
            Instant lifetimeStart = activatedAt.orElse(createdAt);
            if (activatedAt.filter(value -> value.isBefore(createdAt)).isPresent() || !expiresAt.isAfter(lifetimeStart)
                    || Duration.between(lifetimeStart, expiresAt).compareTo(Duration.ofHours(24)) > 0) {
                throw new IllegalArgumentException("Break-glass lifetime is invalid");
            }
            Objects.requireNonNull(state, "state");
            if (state == State.PENDING && activatedAt.isPresent()
                    || state == State.ACTIVE && activatedAt.isEmpty()) {
                throw new IllegalArgumentException("Break-glass activation state is invalid");
            }
            if (auditCommitment == null || !auditCommitment.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Break-glass audit commitment is invalid");
            }
        }

        /**
         * Creates an activated record for existing embedded callers.
         *
         * @param breakGlassId stable emergency grant identifier
         * @param principalId grantee principal
         * @param grant exact scoped allow grant
         * @param reason mandatory bounded emergency reason
         * @param issuerPrincipalId independent issuer principal
         * @param approvalId optional independent approval authority
         * @param createdAt server-authoritative creation time
         * @param activatedAt server-authoritative activation time
         * @param expiresAt mandatory expiry no more than 24 hours after activation
         * @param state lifecycle state
         * @param auditCommitment safe immutable audit commitment
         */
        public Record(String breakGlassId, String principalId, Permission.Grant grant, String reason,
                String issuerPrincipalId, Optional<String> approvalId, Instant createdAt, Instant activatedAt,
                Instant expiresAt, State state, String auditCommitment) {
            this(breakGlassId, principalId, grant, reason, issuerPrincipalId, approvalId, createdAt,
                    Optional.of(activatedAt), expiresAt, state, auditCommitment);
        }
    }

    /**
     * Active grants plus their identities for authorization and use auditing.
     *
     * @param grants immutable active grants
     * @param grantIds immutable identifiers of the active grants
     */
    public record ActiveGrants(List<Permission.Grant> grants, Set<String> grantIds) {
        /**
         * Defensively snapshots active grants.
         * @param grants immutable active grants
         * @param grantIds immutable identifiers of the active grants
         * @throws NullPointerException if any of {@code grants}, {@code grantIds} is null
         */
        public ActiveGrants {
            grants = List.copyOf(Objects.requireNonNull(grants, "grants"));
            grantIds = Set.copyOf(Objects.requireNonNull(grantIds, "grantIds"));
        }
    }

    private final ServerControlStore store;
    private final Clock clock;
    private final SafeAudit audit;

    /**
     * Creates a durable break-glass service.
     *
     * @param store durable server-control store
     * @param clock authoritative server clock
     * @param auditSink required safe audit sink
     * @throws NullPointerException if any of {@code store}, {@code clock} is null
     */
    public BreakGlassService(ServerControlStore store, Clock clock, zeroecho.pki.spi.audit.AuditSink auditSink) {
        this.store = Objects.requireNonNull(store, "store");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.audit = new SafeAudit(clock, auditSink);
    }

    /**
     * Durably creates a scoped pending emergency grant linked to an executing approval.
     *
     * <p>Principal lookup, exact approval binding, record validation and creation
     * are serialized on the shared control authority. The new record remains
     * pending and grants no active emergency authorization until activation.
     *
     * @param breakGlassId stable emergency grant identifier
     * @param principalId grantee principal identifier
     * @param grant exact scoped allow grant
     * @param reason mandatory bounded emergency reason
     * @param issuerPrincipalId independent issuer principal
     * @param approvalId independent execution approval
     * @param expiresAt mandatory expiry no more than 24 hours after activation
     * @return durable pending emergency grant
     */
    public Record create(String breakGlassId, String principalId, Permission.Grant grant, String reason,
            String issuerPrincipalId, Optional<String> approvalId, Instant expiresAt) {
        synchronized (store) {
            store.requirePrincipal(principalId); store.requirePrincipal(issuerPrincipalId);
            requireExecutingApproval(approvalId, ServerControlOperation.CreateBreakGlass.CREATE, grant.scope());
            Instant now = clock.instant();
            String commitment = ApprovalService.digest(breakGlassId + '|' + principalId + '|' + grant.grantId()
                    + '|' + issuerPrincipalId + '|' + now + '|' + expiresAt);
            Record record = new Record(breakGlassId, principalId, grant, reason, issuerPrincipalId, approvalId,
                    now, Optional.empty(), expiresAt, State.PENDING, commitment);
            store.createBreakGlass(record);
            audit.record("BREAK_GLASS_CREATE", issuerPrincipalId, Optional.empty(), Map.of("state", "PENDING"));
            return record;
        }
    }

    /**
     * Durably activates a pending emergency grant bound to an executing activation approval.
     *
     * <p>Reading and expiring the record, checking the exact activation approval
     * and persisting the active state occur under one control-store monitor.
     * Activation records the authoritative clock instant without extending the
     * retained expiry.
     *
     * @param breakGlassId stable emergency grant identifier
     * @param actorPrincipalId authenticated administrative actor
     * @param approvalId independent execution approval
     * @return durably active emergency grant
     * @throws IllegalStateException if the retained grant is not approved for activation
     */
    public Record activatePending(String breakGlassId, String actorPrincipalId,
            Optional<String> approvalId) {
        synchronized (store) {
            Record current = requireCurrent(breakGlassId);
            if (current.state() != State.PENDING) {
                throw new IllegalStateException("Break-glass record is not approved for activation");
            }
            requireExecutingApproval(approvalId, ServerControlOperation.ActivateBreakGlass.ACTIVATE,
                    current.grant().scope());
            Record active = new Record(current.breakGlassId(), current.principalId(), current.grant(), current.reason(),
                    current.issuerPrincipalId(), approvalId, current.createdAt(), Optional.of(clock.instant()),
                    current.expiresAt(), State.ACTIVE, current.auditCommitment());
            store.replaceBreakGlass(current, active);
            audit.record("BREAK_GLASS_ACTIVATE", actorPrincipalId, Optional.empty(), Map.of("state", "ACTIVE"));
            return active;
        }
    }

    /**
     * Durably revokes a currently active emergency grant.
     *
     * <p>Any due expiry is applied before the active-state check. Validation,
     * revocation persistence and best-effort audit delivery share the control
     * authority, so a concurrent activation or expiry cannot overwrite this
     * transition using an earlier record snapshot.
     *
     * @param breakGlassId stable emergency grant identifier
     * @param actorPrincipalId authenticated administrative actor
     * @return durably revoked emergency grant
     * @throws IllegalStateException if the retained grant is not active
     */
    public Record revoke(String breakGlassId, String actorPrincipalId) {
        synchronized (store) {
            Record current = requireCurrent(breakGlassId);
            if (current.state() != State.ACTIVE) { throw new IllegalStateException("Break-glass grant is not active"); }
            Record revoked = copy(current, State.REVOKED);
            store.replaceBreakGlass(current, revoked);
            audit.record("BREAK_GLASS_REVOKE", actorPrincipalId, Optional.empty(), Map.of("state", "REVOKED"));
            return revoked;
        }
    }

    /**
     * Returns the retained emergency grant after applying any currently due expiry.
     *
     * <p>Pending and active grants expire when the authoritative clock reaches
     * their expiry instant. Other lifecycle states remain unchanged. The read,
     * any expiry write and best-effort audit delivery are serialized under the
     * shared control-store monitor.
     *
     * @param breakGlassId stable emergency grant identifier
     * @return immutable retained record after applying any due expiry
     * @throws IllegalArgumentException if the emergency grant is unavailable
     * @throws IllegalStateException if the control authority cannot read or persist its record
     */
    public Record requireCurrent(String breakGlassId) {
        synchronized (store) {
            Record current = store.requireBreakGlass(breakGlassId);
            if ((current.state() == State.ACTIVE || current.state() == State.PENDING)
                    && !clock.instant().isBefore(current.expiresAt())) {
                Record expired = copy(current, State.EXPIRED);
                store.replaceBreakGlass(current, expired);
                audit.record("BREAK_GLASS_EXPIRY", current.principalId(), Optional.empty(), Map.of("state", "EXPIRED"));
                return expired;
            }
            return current;
        }
    }

    /**
     * Returns the currently active, unexpired emergency grants for one principal.
     *
     * <p>The principal's record set, each due expiry transition and the resulting
     * immutable grant projection are evaluated under the shared control-store
     * monitor. Expiry is therefore applied consistently after reopening the store
     * as well as during ordinary authorization checks.
     *
     * @param principalId grantee principal identifier
     * @return current unexpired active grants
     */
    public ActiveGrants activeFor(String principalId) {
        synchronized (store) {
            Permission.requirePrincipal(principalId);
            List<Record> active = store.breakGlassFor(principalId).stream().map(item -> requireCurrent(item.breakGlassId()))
                    .filter(item -> item.state() == State.ACTIVE).toList();
            return new ActiveGrants(active.stream().map(Record::grant).toList(),
                    active.stream().map(item -> item.grant().grantId()).collect(java.util.stream.Collectors.toSet()));
        }
    }

    /**
     * Records use without exposing grant internals or reason.
     *
     * <p>This best-effort telemetry operation does not read or mutate retained
     * grant state and does not acquire the control-store monitor.
     *
     * @param principalId grantee principal identifier
     */
    public void auditUse(String principalId) {
        audit.record("BREAK_GLASS_USE", principalId, Optional.empty(), Map.of("used", "true"));
    }

    private static Record copy(Record source, State state) {
        return new Record(source.breakGlassId(), source.principalId(), source.grant(), source.reason(),
                source.issuerPrincipalId(), source.approvalId(), source.createdAt(), source.activatedAt(),
                source.expiresAt(), state, source.auditCommitment());
    }

    private void requireExecutingApproval(Optional<String> approvalId, String operationId,
            Permission.Scope scope) {
        ApprovalService.Request approval = store.requireApproval(approvalId
                .orElseThrow(() -> new IllegalStateException("Break-glass approval is required")));
        if (approval.state() != ApprovalService.State.EXECUTING || !approval.operationId().equals(operationId)
                || !approval.scope().equals(scope)) {
            throw new IllegalStateException("Break-glass approval is not executable");
        }
    }
}
