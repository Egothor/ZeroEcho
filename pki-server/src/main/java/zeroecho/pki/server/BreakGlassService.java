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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Durable, scoped, mandatory-expiry emergency authorization service. */
@SuppressWarnings({ "PMD.ControlStatementBraces", "PMD.FieldDeclarationsShouldBeAtStartOfClass",
        "PMD.UseObjectForClearerAPI", "PMD.AvoidSynchronizedAtMethodLevel" })
public final class BreakGlassService {
    /** Break-glass lifecycle states. */
    public enum State {
        ACTIVE(1), REVOKED(2), EXPIRED(3);
        private final int code;
        State(int code) { this.code = code; }
        /** @return stable persistence code */ public int code() { return code; }
        /** Resolves one stable persistence code. */
        public static State fromCode(int code) {
            return switch (code) { case 1 -> ACTIVE; case 2 -> REVOKED; case 3 -> EXPIRED;
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
            String issuerPrincipalId, Optional<String> approvalId, Instant createdAt, Instant activatedAt,
            Instant expiresAt, State state, String auditCommitment) {
        /** Validates the strict time-limited scoped record. */
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
            Objects.requireNonNull(activatedAt, "activatedAt");
            Objects.requireNonNull(expiresAt, "expiresAt");
            if (activatedAt.isBefore(createdAt) || !expiresAt.isAfter(activatedAt)
                    || Duration.between(activatedAt, expiresAt).compareTo(Duration.ofHours(24)) > 0) {
                throw new IllegalArgumentException("Break-glass lifetime is invalid");
            }
            Objects.requireNonNull(state, "state");
            if (auditCommitment == null || !auditCommitment.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Break-glass audit commitment is invalid");
            }
        }
    }

    /** Active grants plus their identities for authorization and use auditing. */
    public record ActiveGrants(List<Permission.Grant> grants, java.util.Set<String> grantIds) {
        /** Defensively snapshots active grants. */
        public ActiveGrants {
            grants = List.copyOf(Objects.requireNonNull(grants, "grants"));
            grantIds = java.util.Set.copyOf(Objects.requireNonNull(grantIds, "grantIds"));
        }
    }

    private final ServerControlStore store;
    private final Clock clock;
    private final SafeAudit audit;

    /** Creates a durable break-glass service. */
    public BreakGlassService(ServerControlStore store, Clock clock, zeroecho.pki.spi.audit.AuditSink auditSink) {
        this.store = Objects.requireNonNull(store, "store");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.audit = new SafeAudit(clock, auditSink);
    }

    /** Creates and immediately activates one independently issued emergency grant. */
    public synchronized Record activate(String breakGlassId, String principalId, Permission.Grant grant, String reason,
            String issuerPrincipalId, Optional<String> approvalId, Instant expiresAt) {
        store.requirePrincipal(principalId);
        store.requirePrincipal(issuerPrincipalId);
        Instant now = clock.instant();
        String commitment = ApprovalService.digest(breakGlassId + '|' + principalId + '|' + grant.grantId()
                + '|' + issuerPrincipalId + '|' + now + '|' + expiresAt);
        Record record = new Record(breakGlassId, principalId, grant, reason, issuerPrincipalId, approvalId,
                now, now, expiresAt, State.ACTIVE, commitment);
        store.createBreakGlass(record);
        audit.record("BREAK_GLASS_ACTIVATE", issuerPrincipalId, Optional.empty(), Map.of("state", "ACTIVE"));
        return record;
    }

    /** Revokes an active grant. */
    public synchronized Record revoke(String breakGlassId, String actorPrincipalId) {
        Record current = requireCurrent(breakGlassId);
        if (current.state() != State.ACTIVE) throw new IllegalStateException("Break-glass grant is not active");
        Record revoked = copy(current, State.REVOKED);
        store.replaceBreakGlass(current, revoked);
        audit.record("BREAK_GLASS_REVOKE", actorPrincipalId, Optional.empty(), Map.of("state", "REVOKED"));
        return revoked;
    }

    /** Returns a current record, durably applying expiry when observed. */
    public synchronized Record requireCurrent(String breakGlassId) {
        Record current = store.requireBreakGlass(breakGlassId);
        if (current.state() == State.ACTIVE && !clock.instant().isBefore(current.expiresAt())) {
            Record expired = copy(current, State.EXPIRED);
            store.replaceBreakGlass(current, expired);
            audit.record("BREAK_GLASS_EXPIRY", current.principalId(), Optional.empty(), Map.of("state", "EXPIRED"));
            return expired;
        }
        return current;
    }

    /** Returns current active grants for one principal and enforces expiry after reopen. */
    public synchronized ActiveGrants activeFor(String principalId) {
        Permission.requirePrincipal(principalId);
        List<Record> active = store.breakGlassFor(principalId).stream().map(item -> requireCurrent(item.breakGlassId()))
                .filter(item -> item.state() == State.ACTIVE).toList();
        return new ActiveGrants(active.stream().map(Record::grant).toList(),
                active.stream().map(item -> item.grant().grantId()).collect(java.util.stream.Collectors.toSet()));
    }

    /** Records use without exposing grant internals or reason. */
    public void auditUse(String principalId) {
        audit.record("BREAK_GLASS_USE", principalId, Optional.empty(), Map.of("used", "true"));
    }

    private static Record copy(Record source, State state) {
        return new Record(source.breakGlassId(), source.principalId(), source.grant(), source.reason(),
                source.issuerPrincipalId(), source.approvalId(), source.createdAt(), source.activatedAt(),
                source.expiresAt(), state, source.auditCommitment());
    }
}
