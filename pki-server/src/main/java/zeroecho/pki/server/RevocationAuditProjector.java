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

import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.application.RevocationExecutionEvidence;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.store.RevocationTransitionFeed;

/**
 * Synchronous thread-confined projection of authoritative revocation evidence to
 * one audit sink. A pass performs no scheduling and retains only one feed record.
 */
final class RevocationAuditProjector {
    private static final int MAXIMUM_PASS_COUNT = 4_096;
    private static final long MAXIMUM_BACKOFF_SECONDS = 3_600L;
    private static final byte[] EVENT_ID_DOMAIN =
            "ZEROECHO-REVOCATION-AUDIT-EVENT-V1\0".getBytes(StandardCharsets.US_ASCII);
    private static final Purpose PURPOSE = new Purpose("REVOCATION_AUDIT_PROJECTION");

    private final RealmId realmId;
    private final RevocationService revocations;
    private final ServerControlStore control;
    private final Clock clock;
    private final AuditSink sink;

    /* default */ RevocationAuditProjector(RealmId realmId, RevocationService revocations,
            ServerControlStore control, Clock clock, AuditSink sink) {
        this.realmId = Objects.requireNonNull(realmId, "realmId");
        this.revocations = Objects.requireNonNull(revocations, "revocations");
        this.control = Objects.requireNonNull(control, "control");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.sink = Objects.requireNonNull(sink, "sink");
    }

    /**
     * Runs one bounded pass over a captured authoritative feed head.
     *
     * @param maxExamined maximum feed entries decoded, from zero through 4096
     * @param maxSinkCalls maximum sink invocations, from zero through 4096
     * @param cancellation cooperative cancellation checked between bounded operations
     * @return immutable pass outcome
     * @throws IOException if the authoritative feed cannot be read safely
     * @implNote Cancellation is cooperative between bounded operations and does not interrupt an active
     *           {@link AuditSink#record(AuditEvent)} call. Cancellation observed after sink acknowledgement but
     *           before cursor persistence leaves the cursor unchanged, so a retry may emit the same event ID.
     */
    /* default */ PassResult project(int maxExamined, int maxSinkCalls, CancellationSignal cancellation)
            throws IOException {
        requireBound(maxExamined, "maxExamined");
        requireBound(maxSinkCalls, "maxSinkCalls");
        CancellationSignal exactCancellation = Objects.requireNonNull(cancellation, "cancellation");
        Optional<RevocationAuditProjectionState.Loaded> loaded = RevocationAuditProjectionState.load(control);
        Optional<RevocationTransitionFeed.Position> position = loaded
                .map(RevocationAuditProjectionState.Loaded::state)
                .flatMap(RevocationAuditProjectionState::lastPosition);
        try (RevocationTransitionFeed feed = revocations.feed(position)) {
            RevocationTransitionFeed.HighWatermark head = feed.highWatermark();
            RevocationAuditProjectionState state = loaded
                    .map(RevocationAuditProjectionState.Loaded::state)
                    .orElseGet(() -> RevocationAuditProjectionState.initial(head));
            validateState(state, head);
            if (exactCancellation.isCancelled()) {
                return result(0, 0, 0, false, false, state, head);
            }
            Instant now = clock.instant();
            if (state.nextEligible().filter(eligible -> eligible.isAfter(now)).isPresent()) {
                if (exactCancellation.isCancelled()) {
                    return result(0, 0, 0, false, true, state, head);
                }
                loaded = persistObservation(loaded, state, head);
                state = loaded.orElseThrow().state();
                return result(0, 0, 0, false, true, state, head);
            }
            return projectEligible(feed, head, loaded, state, maxExamined, maxSinkCalls, exactCancellation);
        }
    }

    /** Runs one bounded non-cancelling pass. */
    /* default */ PassResult project(int maxExamined, int maxSinkCalls) throws IOException {
        return project(maxExamined, maxSinkCalls, CancellationSignal.NONE);
    }

    private PassResult projectEligible(RevocationTransitionFeed feed, RevocationTransitionFeed.HighWatermark head,
            Optional<RevocationAuditProjectionState.Loaded> initialLoaded, RevocationAuditProjectionState initialState,
            int maxExamined, int maxSinkCalls, CancellationSignal cancellation) throws IOException {
        ProjectionProgress progress = new ProjectionProgress(initialLoaded, initialState);
        boolean endReached = false;
        while (progress.examined < maxExamined) {
            if (cancellation.isCancelled()) {
                break;
            }
            boolean available;
            try {
                available = feed.next(cancellation);
            } catch (InterruptedIOException cancelled) {
                if (!cancellation.isCancelled()) {
                    throw cancelled;
                }
                break;
            }
            if (cancellation.isCancelled()) {
                break;
            }
            if (!available) {
                endReached = true;
                break;
            }
            RevocationTransitionFeed.Entry entry = feed.current();
            progress.examined++;
            if (!processEntry(entry, progress, head, maxSinkCalls, cancellation)) {
                break;
            }
        }
        if (cancellation.isCancelled()) {
            return progress.result(endReached, head);
        }
        progress.loaded = persistObservation(progress.loaded, progress.state, head);
        progress.state = progress.loaded.orElseThrow().state();
        return progress.result(endReached, head);
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException") // AuditSink declares RuntimeException as its failure boundary.
    private boolean processEntry(RevocationTransitionFeed.Entry entry, ProjectionProgress progress,
            RevocationTransitionFeed.HighWatermark head, int maxSinkCalls, CancellationSignal cancellation) {
        Optional<RevocationExecutionEvidence> evidence;
        try {
            evidence = RevocationExecutionEvidence.decode(entry.record().transition().attributes());
            evidence.ifPresent(this::requireRealm);
        } catch (IllegalArgumentException invalidEvidence) {
            if (!cancellation.isCancelled()) {
                progress.fail(head);
            }
            return false;
        }
        if (evidence.isPresent() && progress.sinkCalls >= maxSinkCalls) {
            return false;
        }
        if (evidence.isPresent()) {
            if (cancellation.isCancelled()) {
                return false;
            }
            progress.sinkCalls++;
            try {
                sink.record(event(entry, evidence.orElseThrow()));
            } catch (RuntimeException sinkFailure) {
                if (!cancellation.isCancelled()) {
                    progress.fail(head);
                }
                return false;
            }
        }
        if (cancellation.isCancelled()) {
            return false;
        }
        progress.state = progress.state.advance(entry.nextPosition(), head);
        progress.loaded = Optional.of(RevocationAuditProjectionState.persist(control, progress.loaded,
                progress.state));
        progress.advanced++;
        return !cancellation.isCancelled();
    }

    private Optional<RevocationAuditProjectionState.Loaded> persistFailure(
            Optional<RevocationAuditProjectionState.Loaded> loaded, RevocationAuditProjectionState state,
            RevocationTransitionFeed.HighWatermark head) {
        int nextFailure = Math.min(RevocationAuditProjectionState.MAXIMUM_FAILURE_COUNT,
                state.failureCount() + 1);
        int exponent = Math.min(12, nextFailure - 1);
        long delaySeconds = Math.min(MAXIMUM_BACKOFF_SECONDS, 1L << exponent);
        RevocationAuditProjectionState failed = state.fail(clock.instant().plusSeconds(delaySeconds), head);
        return Optional.of(RevocationAuditProjectionState.persist(control, loaded, failed));
    }

    private Optional<RevocationAuditProjectionState.Loaded> persistObservation(
            Optional<RevocationAuditProjectionState.Loaded> loaded, RevocationAuditProjectionState state,
            RevocationTransitionFeed.HighWatermark head) {
        if (loaded.isPresent() && state.observedHighRevision() == head.globalRevision()
                && state.observedHighCommitment().equals(head.transitionCommitment())) {
            return loaded;
        }
        return Optional.of(RevocationAuditProjectionState.persist(control, loaded, state.observe(head)));
    }

    private AuditEvent event(RevocationTransitionFeed.Entry entry, RevocationExecutionEvidence evidence) {
        RevocationTransition transition = entry.record().transition();
        Map<String, String> details = new LinkedHashMap<>();
        details.put("eventId", eventId(realmId.value(), entry));
        details.put("realmId", evidence.realmId());
        details.put("sourceStoreId", entry.sourceStoreId().value());
        details.put("globalRevision", Long.toString(entry.globalRevision()));
        details.put("transitionCommitment", entry.transitionCommitment());
        details.put("credentialId", entry.record().credentialId().value());
        details.put("credentialRevision", Long.toString(transition.revision()));
        details.put("state", transition.state().name());
        details.put("reason", transition.permanentReason().map(Enum::name).orElse("NONE"));
        details.put("actorType", evidence.actorType().name());
        details.put("actorId", evidence.actorId());
        details.put("requestId", evidence.requestId());
        details.put("authentication", evidence.authentication().name());
        details.put("authorization", evidence.authorization().name());
        details.put("outcome", evidence.outcome().name());
        evidence.authorizationPath().ifPresent(value -> details.put("authorizationPath", value.name()));
        evidence.operationCommitment().ifPresent(value -> details.put("operationCommitment", value));
        evidence.justificationCommitment().ifPresent(value -> details.put("justificationCommitment", value));
        return new AuditEvent(transition.time(), "REVOCATION", "REVOCATION_TRANSITION",
                new Principal(evidence.actorType().name(), evidence.actorId()), PURPOSE,
                Optional.of(entry.record().credentialId()), Optional.empty(), Map.copyOf(details));
    }

    private void requireRealm(RevocationExecutionEvidence evidence) {
        if (!realmId.value().equals(evidence.realmId())) {
            throw new IllegalArgumentException("Revocation evidence realm is inconsistent");
        }
    }

    private static String eventId(String realm, RevocationTransitionFeed.Entry entry) {
        MessageDigest digest = sha256();
        digest.update(EVENT_ID_DOMAIN);
        updateField(digest, realm);
        updateField(digest, entry.sourceStoreId().value());
        updateField(digest, Long.toString(entry.globalRevision()));
        updateField(digest, entry.transitionCommitment());
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void updateField(MessageDigest digest, String value) {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(encoded.length).array());
        digest.update(encoded);
    }

    private static void validateState(RevocationAuditProjectionState state,
            RevocationTransitionFeed.HighWatermark head) {
        if (!state.sourceStoreId().equals(head.sourceStoreId())
                || state.observedHighRevision() > head.globalRevision()
                || (state.observedHighRevision() == head.globalRevision()
                    && !state.observedHighCommitment().equals(head.transitionCommitment()))) {
            throw new IllegalStateException("Revocation audit projection state does not match its source");
        }
    }

    private static PassResult result(int examined, int sinkCalls, int advanced, boolean endReached,
            boolean blocked, RevocationAuditProjectionState state, RevocationTransitionFeed.HighWatermark head) {
        return new PassResult(examined, sinkCalls, advanced, endReached, blocked, state.nextEligible(), head);
    }

    private static void requireBound(int value, String name) {
        if (value < 0 || value > MAXIMUM_PASS_COUNT) {
            throw new IllegalArgumentException(name + " is outside the supported bound");
        }
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("Required SHA-256 digest is unavailable", impossible);
        }
    }

    /** Mutable state confined to one synchronous projection pass. */
    private final class ProjectionProgress {
        private Optional<RevocationAuditProjectionState.Loaded> loaded;
        private RevocationAuditProjectionState state;
        private int examined;
        private int sinkCalls;
        private int advanced;
        private boolean blocked;

        private ProjectionProgress(Optional<RevocationAuditProjectionState.Loaded> loaded,
                RevocationAuditProjectionState state) {
            this.loaded = loaded;
            this.state = state;
        }

        private void fail(RevocationTransitionFeed.HighWatermark head) {
            loaded = persistFailure(loaded, state, head);
            state = loaded.orElseThrow().state();
            blocked = true;
        }

        private PassResult result(boolean endReached, RevocationTransitionFeed.HighWatermark head) {
            return RevocationAuditProjector.result(examined, sinkCalls, advanced, endReached, blocked, state, head);
        }
    }

    /** Immutable bounded-pass outcome for future scheduler integration. */
    /* default */
    record PassResult(int examined, int sinkCalls, int advanced, boolean endReached, boolean blocked,
            Optional<Instant> nextEligible, RevocationTransitionFeed.HighWatermark observedHead) {
        /** Validates immutable pass counters and snapshots. */
        PassResult {
            if (examined < 0 || sinkCalls < 0 || advanced < 0
                    || sinkCalls > examined || advanced > examined) {
                throw new IllegalArgumentException("Revocation audit projection result is invalid");
            }
            nextEligible = Objects.requireNonNull(nextEligible, "nextEligible");
            Objects.requireNonNull(observedHead, "observedHead");
        }
    }
}
