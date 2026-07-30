/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.impl.core;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationJournal;
import zeroecho.pki.api.revocation.RevocationQuery;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Store-backed authoritative revocation transition service.
 */
public final class DefaultRevocationService implements RevocationService {
    private static final Instant UNKNOWN_AUDIT_TIME = Instant.EPOCH;
    private static final Principal SYSTEM_PKI = new Principal("SYSTEM", "pki");
    private static final Purpose REVOCATION_PURPOSE = new Purpose("REVOCATION");
    private static final List<String> SAFE_STORE_CODES = List.of("REVOCATION_CREDENTIAL_NOT_FOUND",
            "REVOCATION_TRANSITION_ILLEGAL", "REVOCATION_TERMINAL", "REVOCATION_TRANSITION_CONFLICT",
            "REVOCATION_STATE_CORRUPT", "REVOCATION_PERSIST_FAILED", "REVOCATION_DURABILITY_UNCONFIRMED",
            "STORE_DURABILITY_UNCONFIRMED");

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
    public RevocationJournal hold(RevocationCommand.Hold command) {
        return transition(Objects.requireNonNull(command, "command"), "HOLD");
    }

    @Override
    public RevocationJournal unhold(RevocationCommand.Unhold command) {
        return transition(Objects.requireNonNull(command, "command"), "UNHOLD");
    }

    @Override
    public RevocationJournal revokePermanently(RevocationCommand.RevokePermanently command) {
        return transition(Objects.requireNonNull(command, "command"), "REVOKE_PERMANENTLY");
    }

    @Override
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public Optional<RevocationJournal> get(PkiId credentialId) {
        Objects.requireNonNull(credentialId, "credentialId");
        try {
            return store.getRevocationJournal(credentialId);
        } catch (RuntimeException failure) {
            throw sanitized(failure);
        }
    }

    @Override
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public List<RevocationJournal> search(RevocationQuery query) {
        Objects.requireNonNull(query, "query");
        try {
            return store.listRevocationJournals().stream().filter(journal -> matches(journal, query)).toList();
        } catch (RuntimeException failure) {
            throw sanitized(failure);
        }
    }

    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    private RevocationJournal transition(RevocationCommand command, String operation) {
        Instant time = null;
        try {
            time = Objects.requireNonNull(clock.instant(), "clock instant");
            RevocationJournal journal = store.transitionRevocation(command, time);
            auditSuccess(time, journal, operation);
            return journal;
        } catch (RuntimeException failure) {
            PkiException sanitized = time == null
                    ? new PkiException("Revocation operation failed: code=REVOCATION_TIME_UNAVAILABLE")
                    : sanitized(failure);
            auditRejected(time == null ? UNKNOWN_AUDIT_TIME : time, command.credentialId(), operation,
                    codeOf(sanitized), time == null ? Optional.empty() : currentState(command));
            throw sanitized;
        }
    }

    private boolean matches(RevocationJournal journal, RevocationQuery query) {
        RevocationTransition latest = journal.latest();
        if (query.reason().isPresent() && !latest.permanentReason().filter(query.reason().get()::equals).isPresent()) {
            return false;
        }
        if (query.revokedAfter().isPresent() && latest.time().isBefore(query.revokedAfter().get())) {
            return false;
        }
        if (query.revokedBefore().isPresent() && !latest.time().isBefore(query.revokedBefore().get())) {
            return false;
        }
        return query.issuerCaId().isEmpty() || store.getCredential(journal.credentialId())
                .map(credential -> query.issuerCaId().get().equals(credential.issuerRef().caId())).orElse(false);
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private Optional<String> currentState(RevocationCommand command) {
        try {
            return store.getRevocationJournal(command.credentialId()).map(RevocationJournal::latest)
                    .map(transition -> transition.state().name());
        } catch (RuntimeException ignored) {
            return Optional.empty();
        }
    }

    private void auditSuccess(Instant time, RevocationJournal journal, String operation) {
        RevocationTransition latest = journal.latest();
        audit(time, journal.credentialId(), operation, Map.of("result", "COMMITTED", "state", latest.state().name(),
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

    // Store failures are hostile boundaries. Preserve only enumerated stable codes,
    // never raw messages or causes.
    private static PkiException sanitized(RuntimeException failure) {
        String message = failure.getMessage();
        if (message != null) {
            for (String code : SAFE_STORE_CODES) {
                if (message.contains("code=" + code)) {
                    return new PkiException("Revocation operation failed: code=" + code);
                }
            }
        }
        return new PkiException("Revocation operation failed: code=REVOCATION_STATE_UPDATE_FAILED");
    }

    private static String codeOf(PkiException failure) {
        String message = failure.getMessage();
        int marker = message.indexOf("code=");
        return marker < 0 ? "REVOCATION_STATE_UPDATE_FAILED" : message.substring(marker + 5);
    }
}
