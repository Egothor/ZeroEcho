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
package zeroecho.pki.impl.core;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiFailureReason;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.api.revocation.RevocationQuery;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.RevocationHistory;
import zeroecho.pki.spi.store.RevocationSnapshot;
import zeroecho.pki.spi.store.RevocationTransitionFeed;

/**
 * Store-backed authoritative revocation transition service.
 */
public final class DefaultRevocationService implements RevocationService {
    private static final Instant UNKNOWN_AUDIT_TIME = Instant.EPOCH;
    private static final Principal SYSTEM_PKI = new Principal("SYSTEM", "pki");
    private static final Purpose REVOCATION_PURPOSE = new Purpose("REVOCATION");
    // Store failures are hostile boundaries: only these enumerated typed reasons are
    // preserved from a store exception; every other failure is reduced to the opaque
    // REVOCATION_STATE_UPDATE_FAILED reason.
    private static final Set<PkiFailureReason> SAFE_STORE_REASONS = EnumSet.of(
            PkiFailureReason.REVOCATION_CREDENTIAL_NOT_FOUND,
            PkiFailureReason.REVOCATION_TRANSITION_ILLEGAL,
            PkiFailureReason.REVOCATION_TERMINAL,
            PkiFailureReason.REVOCATION_TRANSITION_CONFLICT,
            PkiFailureReason.REVOCATION_STATE_CORRUPT,
            PkiFailureReason.REVOCATION_PERSIST_FAILED,
            PkiFailureReason.REVOCATION_RECOVERY_REQUIRED,
            PkiFailureReason.STORE_DURABILITY_UNCONFIRMED,
            PkiFailureReason.CONFIRMATION_REVOCATION_CONFLICT,
            PkiFailureReason.CONFIRMATION_REVOCATION_RECOVERY_REQUIRED);

    private final PkiStore store;
    private final Clock clock;
    private final AuditSink auditSink;

    /**
     * Creates the service with one authoritative clock.
     *
     * @param store     authoritative store
     * @param clock     authoritative clock
     * @param auditSink best-effort audit sink
     */
    public DefaultRevocationService(PkiStore store, Clock clock, AuditSink auditSink) {
        this.store = Objects.requireNonNull(store, "store");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink");
    }

    @Override
    public RevocationRecord hold(RevocationCommand.Hold command) {
        return transition(Objects.requireNonNull(command, "command"), "HOLD");
    }

    @Override
    public RevocationRecord unhold(RevocationCommand.Unhold command) {
        return transition(Objects.requireNonNull(command, "command"), "UNHOLD");
    }

    @Override
    public RevocationRecord revokePermanently(RevocationCommand.RevokePermanently command) {
        return transition(Objects.requireNonNull(command, "command"), "REVOKE_PERMANENTLY");
    }

    @Override
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public RevocationRecord revokeOverduePendingConfirmation(
            RevocationCommand.RevokePermanently command) {
        RevocationCommand.RevokePermanently exact = Objects.requireNonNull(command, "command");
        try {
            RevocationRecord record = store.revokeOverduePendingCredentialConfirmation(exact);
            auditSuccess(record.transition().time(), record,
                    "REVOKE_OVERDUE_PENDING_CONFIRMATION");
            return record;
        } catch (RuntimeException failure) {
            PkiException sanitized = sanitized(failure);
            auditRejected(safeAuditTime(), exact.credentialId(),
                    "REVOKE_OVERDUE_PENDING_CONFIRMATION", codeOf(sanitized), currentState(exact));
            throw sanitized;
        }
    }

    @Override
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public Optional<RevocationRecord> get(PkiId credentialId) {
        Objects.requireNonNull(credentialId, "credentialId");
        try {
            return store.getRevocation(credentialId);
        } catch (RuntimeException failure) {
            throw sanitized(failure);
        }
    }

    @Override
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public RevocationHistory history(PkiId credentialId) {
        Objects.requireNonNull(credentialId, "credentialId");
        try {
            return store.openRevocationHistory(credentialId);
        } catch (RuntimeException failure) {
            throw sanitized(failure);
        }
    }

    @Override
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public RevocationTransitionFeed feed(Optional<RevocationTransitionFeed.Position> afterExclusive) {
        Objects.requireNonNull(afterExclusive, "afterExclusive");
        try {
            return store.openRevocationTransitionFeed(afterExclusive);
        } catch (RuntimeException failure) {
            throw sanitized(failure);
        }
    }

    @Override
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public RevocationSnapshot search(RevocationQuery query) {
        Objects.requireNonNull(query, "query");
        try {
            return new FilteredSnapshot(store.openRevocationSnapshot(), query);
        } catch (RuntimeException failure) {
            throw sanitized(failure);
        }
    }

    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    private RevocationRecord transition(RevocationCommand command, String operation) {
        Instant time = null;
        try {
            time = Objects.requireNonNull(clock.instant(), "clock instant");
            RevocationRecord record = store.transitionRevocation(command, time);
            auditSuccess(time, record, operation);
            return record;
        } catch (RuntimeException failure) {
            PkiException sanitized = time == null
                    ? new PkiException("Revocation operation failed: code=REVOCATION_TIME_UNAVAILABLE",
                            PkiFailureReason.REVOCATION_TIME_UNAVAILABLE)
                    : sanitized(failure);
            auditRejected(time == null ? UNKNOWN_AUDIT_TIME : time, command.credentialId(), operation,
                    codeOf(sanitized), time == null ? Optional.empty() : currentState(command));
            throw sanitized;
        }
    }

    private boolean matches(RevocationRecord record, RevocationQuery query) {
        RevocationTransition latest = record.transition();
        if (query.reason().isPresent() && !latest.permanentReason().filter(query.reason().get()::equals).isPresent()) {
            return false;
        }
        if (query.revokedAfter().isPresent() && latest.time().isBefore(query.revokedAfter().get())) {
            return false;
        }
        if (query.revokedBefore().isPresent() && !latest.time().isBefore(query.revokedBefore().get())) {
            return false;
        }
        return query.issuerCaId().isEmpty() || store.getCredential(record.credentialId())
                .map(credential -> query.issuerCaId().get().equals(credential.issuerRef().caId())).orElse(false);
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private Optional<String> currentState(RevocationCommand command) {
        try {
            return store.getRevocation(command.credentialId()).map(RevocationRecord::transition)
                    .map(transition -> transition.state().name());
        } catch (RuntimeException ignored) {
            return Optional.empty();
        }
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private Instant safeAuditTime() {
        try {
            return Objects.requireNonNull(clock.instant(), "clock instant");
        } catch (RuntimeException unavailable) {
            return UNKNOWN_AUDIT_TIME;
        }
    }

    private void auditSuccess(Instant time, RevocationRecord record, String operation) {
        RevocationTransition latest = record.transition();
        audit(time, record.credentialId(), operation, Map.of("result", "COMMITTED", "state", latest.state().name(),
                "revision", Long.toString(latest.revision())));
    }

    private void auditRejected(Instant time, PkiId credentialId, String operation, String code,
            Optional<String> currentState) {
        Map<String, String> details = currentState
                .map(state -> Map.of("result", "REJECTED", "code", code, "state", state))
                .orElseGet(() -> Map.of("result", "REJECTED", "code", code));
        audit(time, credentialId, operation, details);
    }

    // Audit listeners are external and best-effort; their failures cannot alter
    // authoritative transition results.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private void audit(Instant time, PkiId credentialId, String operation, Map<String, String> details) {
        try {
            auditSink.record(new AuditEvent(time, "REVOCATION", operation, SYSTEM_PKI, REVOCATION_PURPOSE,
                    Optional.of(credentialId), Optional.empty(), details));
        } catch (RuntimeException ignored) {
            // Best-effort audit must not change revocation state.
        }
    }

    // Store failures are hostile boundaries. Preserve only the typed reason from the
    // enumerated safe set, never a raw message or cause; anything else collapses to
    // the opaque REVOCATION_STATE_UPDATE_FAILED reason.
    private static PkiException sanitized(RuntimeException failure) {
        PkiFailureReason reason = failure instanceof PkiException pkiFailure
                ? pkiFailure.failureReason().filter(SAFE_STORE_REASONS::contains).orElse(null)
                : null;
        if (reason != null) {
            return new PkiException("Revocation operation failed: code=" + reason.name(), reason);
        }
        return new PkiException("Revocation operation failed: code=REVOCATION_STATE_UPDATE_FAILED",
                PkiFailureReason.REVOCATION_STATE_UPDATE_FAILED);
    }

    private static String codeOf(PkiException failure) {
        return failure.failureReason().map(PkiFailureReason::name).orElse("REVOCATION_STATE_UPDATE_FAILED");
    }

    /** Query-filtered ownership wrapper over one stable store snapshot. */
    private final class FilteredSnapshot implements RevocationSnapshot {
        private final RevocationSnapshot source;
        private final RevocationQuery query;

        private FilteredSnapshot(RevocationSnapshot source, RevocationQuery query) {
            this.source = source;
            this.query = query;
        }

        @Override
        public String snapshotId() {
            return source.snapshotId();
        }

        @Override
        public zeroecho.pki.spi.store.MetadataStoreId sourceStoreId() {
            return source.sourceStoreId();
        }

        @Override
        public long revision() {
            return source.revision();
        }

        @Override
        public long boundary() {
            return source.boundary();
        }

        @Override
        public String commitment() {
            return source.commitment();
        }

        @Override
        public OptionalLong count() {
            return OptionalLong.empty();
        }

        @Override
        @SuppressWarnings("PMD.AvoidCatchingGenericException")
        public Cursor openCursor() throws IOException {
            try {
                return new FilteredCursor(source.openCursor(), query);
            } catch (RuntimeException failure) {
                throw sanitized(failure);
            }
        }

        @Override
        public void close() throws IOException {
            source.close();
        }
    }

    /** Lazy query filter retaining only one current state. */
    private final class FilteredCursor implements RevocationSnapshot.Cursor {
        private final RevocationSnapshot.Cursor source;
        private final RevocationQuery query;
        private RevocationRecord current;
        private long ordinal = -1L;

        private FilteredCursor(RevocationSnapshot.Cursor source, RevocationQuery query) {
            this.source = source;
            this.query = query;
        }

        @Override
        @SuppressWarnings({ "PMD.UnusedAssignment", "PMD.AvoidCatchingGenericException" })
        public boolean next(CancellationSignal cancellation) throws IOException {
            try {
                current = null;
                while (source.next(cancellation)) {
                    RevocationRecord candidate = source.current();
                    if (matches(candidate, query)) {
                        current = candidate;
                        ordinal = Math.addExact(ordinal, 1L);
                        return true;
                    }
                }
                return false;
            } catch (RuntimeException failure) {
                throw sanitized(failure);
            }
        }

        @Override
        public RevocationRecord current() {
            if (current == null) {
                throw new IllegalStateException("Revocation search cursor is not positioned");
            }
            return current;
        }

        @Override
        public long currentGlobalRevision() {
            if (current == null) {
                throw new IllegalStateException("Revocation search cursor is not positioned");
            }
            return source.currentGlobalRevision();
        }

        @Override
        public long ordinal() {
            if (current == null) {
                throw new IllegalStateException("Revocation search cursor is not positioned");
            }
            return ordinal;
        }

        @Override
        public void close() throws IOException {
            current = null;
            source.close();
        }
    }
}
