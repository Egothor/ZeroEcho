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

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.store.AuditEvidenceFeed;

/**
 * Generic, thread-confined bounded-pass projector of one family's success-evidence feed to an audit sink.
 *
 * <p>Reuses the crash-consistency shape of {@code RevocationAuditProjector} (which stays unchanged): it
 * advances a durable per-entry compare-and-replace cursor ({@link AuditEvidenceProjectionState}) after
 * each emission, so a crash between sink acknowledgement and cursor persistence re-emits the same entry.
 * Family adapters supply the feed opener and the entry-to-event mapping; the mapper must derive a
 * deterministic event identity so re-emission is idempotent at the sink.</p>
 */
final class AuditEvidenceProjector {
    private static final int MAXIMUM_PASS_COUNT = 4_096;
    private static final long MAXIMUM_BACKOFF_SECONDS = 3_600L;

    private final ServerControlStore control;
    private final String recordId;
    private final FeedOpener feedOpener;
    private final Function<AuditEvidenceFeed.Entry, Optional<AuditEvent>> mapper;
    private final AuditSink sink;
    private final Clock clock;

    /**
     * Opens the family feed strictly after a durable sequence.
     */
    @FunctionalInterface
    public interface FeedOpener {
        /**
         * Opens a snapshot feed positioned after the supplied durable sequence.
         *
         * @param afterSequenceExclusive last sequence already projected; entries start strictly after it
         * @return opened evidence feed owned by the caller
         * @throws IOException if the durable feed cannot be opened
         */
        AuditEvidenceFeed open(long afterSequenceExclusive) throws IOException;
    }

    /**
     * Composes one thread-confined evidence-family delivery cursor and audit-sink projection.
     *
     * @param control durable realm-owned cursor authority
     * @param recordId stable family projection identity
     * @param feedOpener opens authoritative evidence strictly after the retained sequence
     * @param mapper maps recognized evidence to deterministic safe audit events
     * @param sink destination audit sink, which may receive the same event after crash recovery
     * @param clock retry eligibility time source
     * @throws NullPointerException if a required collaborator is null
     */
    /* default */ AuditEvidenceProjector(ServerControlStore control, String recordId, FeedOpener feedOpener,
            Function<AuditEvidenceFeed.Entry, Optional<AuditEvent>> mapper, AuditSink sink, Clock clock) {
        this.control = Objects.requireNonNull(control, "control");
        this.recordId = Objects.requireNonNull(recordId, "recordId");
        this.feedOpener = Objects.requireNonNull(feedOpener, "feedOpener");
        this.mapper = Objects.requireNonNull(mapper, "mapper");
        this.sink = Objects.requireNonNull(sink, "sink");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Observes the retained consecutive delivery failure count for this family.
     *
     * @return current failure count, or zero before cursor creation
     */
    /* default */ long failureCount() {
        return AuditEvidenceProjectionState.load(control, recordId).map(value -> (long) value.state().failureCount()).orElse(0L);
    }

    /**
     * Runs one bounded evidence-delivery pass without an external cancellation request.
     *
     * @param maxExamined maximum entries examined, from zero through 4,096
     * @param maxSinkCalls maximum audit-sink calls, from zero through 4,096
     * @return delivery counts, feed-end classification and retry eligibility
     * @throws IllegalArgumentException if a pass bound is outside the supported range
     * @throws IOException if the source feed or durable cursor cannot be accessed
     */
    /* default */ PassResult project(int maxExamined, int maxSinkCalls) throws IOException {
        return project(maxExamined, maxSinkCalls, CancellationSignal.NONE);
    }

    /**
     * Runs one bounded pass over the captured feed head.
     *
     * @param maxExamined maximum entries decoded, from zero through 4096
     * @param maxSinkCalls maximum sink invocations, from zero through 4096
     * @param cancellation cooperative cancellation checked between bounded operations
     * @return immutable pass outcome
     * @throws IOException if the evidence feed cannot be read safely
     * @throws NullPointerException if {@code cancellation} is null
     */
    @SuppressWarnings("PMD.AvoidCatchingGenericException") // AuditSink and the mapper declare RuntimeException.
    /* default */ PassResult project(int maxExamined, int maxSinkCalls, CancellationSignal cancellation)
            throws IOException {
        requireBound(maxExamined, "maxExamined");
        requireBound(maxSinkCalls, "maxSinkCalls");
        CancellationSignal exact = Objects.requireNonNull(cancellation, "cancellation");
        Optional<AuditEvidenceProjectionState.Loaded> loaded =
                AuditEvidenceProjectionState.load(control, recordId);
        AuditEvidenceProjectionState state = loaded.map(AuditEvidenceProjectionState.Loaded::state)
                .orElseGet(AuditEvidenceProjectionState::initial);
        Instant now = clock.instant();
        if (state.nextEligible().filter(eligible -> eligible.isAfter(now)).isPresent()) {
            return new PassResult(0, 0, false, true, state.nextEligible());
        }
        int examined = 0;
        int emitted = 0;
        boolean endReached = false;
        try (AuditEvidenceFeed feed = feedOpener.open(state.lastSequence())) {
            while (examined < maxExamined) {
                if (exact.isCancelled()) {
                    break;
                }
                if (!feed.next(exact)) {
                    endReached = true;
                    break;
                }
                AuditEvidenceFeed.Entry entry = feed.current();
                examined++;
                Optional<AuditEvent> event;
                try {
                    event = mapper.apply(entry);
                } catch (RuntimeException failure) {
                    loaded = persistFailure(loaded, state, now);
                    return new PassResult(examined, emitted, false, true, loaded.orElseThrow().state().nextEligible());
                }
                if (event.isPresent()) {
                    if (emitted >= maxSinkCalls) {
                        break;
                    }
                    emitted++;
                    try {
                        sink.record(event.orElseThrow());
                    } catch (RuntimeException failure) {
                        loaded = persistFailure(loaded, state, now);
                        return new PassResult(examined, emitted, false, true,
                                loaded.orElseThrow().state().nextEligible());
                    }
                }
                if (exact.isCancelled()) {
                    break;
                }
                state = state.advance(entry.sequence());
                loaded = Optional.of(AuditEvidenceProjectionState.persist(control, recordId, loaded, state));
            }
        }
        return new PassResult(examined, emitted, endReached, false, state.nextEligible());
    }

    private Optional<AuditEvidenceProjectionState.Loaded> persistFailure(
            Optional<AuditEvidenceProjectionState.Loaded> loaded, AuditEvidenceProjectionState state, Instant now) {
        int nextFailure = Math.min(AuditEvidenceProjectionState.MAXIMUM_FAILURE_COUNT, state.failureCount() + 1);
        long delaySeconds = Math.min(MAXIMUM_BACKOFF_SECONDS, 1L << Math.min(12, nextFailure - 1));
        AuditEvidenceProjectionState failed = state.fail(now.plusSeconds(delaySeconds));
        return Optional.of(AuditEvidenceProjectionState.persist(control, recordId, loaded, failed));
    }

    private static void requireBound(int value, String name) {
        if (value < 0 || value > MAXIMUM_PASS_COUNT) {
            throw new IllegalArgumentException(name + " is outside the supported bound");
        }
    }

    /**
     * Immutable scheduling and delivery observations from one bounded evidence pass.
     *
     * @param examined number of evidence entries examined
     * @param emitted number of events delivered to the sink
     * @param endReached whether the captured feed head was reached
     * @param blocked whether a delivery failure/backoff blocked progress
     * @param nextEligible next retry instant, or empty when no retry is pending
     */
    /* default */ record PassResult(int examined, int emitted, boolean endReached, boolean blocked,
            Optional<Instant> nextEligible) {
        /**
         * Validates delivery counters and the explicit retry container.
         *
         * @param examined number of evidence entries examined
         * @param emitted number of events delivered to the sink
         * @param endReached whether the captured feed head was reached
         * @param blocked whether a delivery failure/backoff blocked progress
         * @param nextEligible next retry instant, or empty when no retry is pending
         * @throws IllegalArgumentException if counts are negative or emitted exceeds examined
         * @throws NullPointerException if the retry container is null
         */
        PassResult {
            if (examined < 0 || emitted < 0 || emitted > examined) {
                throw new IllegalArgumentException("Audit evidence projection result is invalid");
            }
            nextEligible = Objects.requireNonNull(nextEligible, "nextEligible");
        }
    }
}
