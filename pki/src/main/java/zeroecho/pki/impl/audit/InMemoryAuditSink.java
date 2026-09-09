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
package zeroecho.pki.impl.audit;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.AuditQuery;
import zeroecho.pki.spi.audit.AuditSink;

/**
 * In-memory {@link AuditSink} provider intended for deterministic tests and
 * local debugging.
 *
 * <h2>Memory bound</h2>
 * <p>
 * This sink is bounded by {@code maxEvents}. When the capacity is exceeded, the
 * oldest event is dropped (ring-buffer policy). This prevents unbounded memory
 * growth in long-running processes.
 * </p>
 *
 * <h3>Configuration</h3>
 * <ul>
 * <li>System property {@code zeroecho.pki.audit.inmemory.maxEvents} (positive
 * integer)</li>
 * <li>Default: 10_000</li>
 * </ul>
 *
 * <h2>Security properties</h2>
 * <ul>
 * <li>Does not log event payloads.</li>
 * <li>Stores events as received; callers must ensure
 * {@link AuditEvent#details()} contains no secrets.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This implementation is synchronized and safe for concurrent use.
 * </p>
 */
public final class InMemoryAuditSink implements AuditSink, SearchableAuditSink {

    private static final Logger LOG = Logger.getLogger(InMemoryAuditSink.class.getName());

    /* default */ static final int DEFAULT_MAX_EVENTS = 10_000;

    private final int maxEvents;
    private final Deque<AuditEvent> events;

    private boolean overflowLogged;

    /**
     * Public no-arg constructor required for {@link java.util.ServiceLoader}.
     *
     * <p>
     * Defaults to 10_000 events.
     * </p>
     */
    public InMemoryAuditSink() {
        this(DEFAULT_MAX_EVENTS);
    }

    /**
     * Creates a sink with an explicit maximum number of events.
     *
     * @param maxEvents maximum number of retained events (must be positive)
     * @throws IllegalArgumentException if {@code maxEvents <= 0}
     */
    public InMemoryAuditSink(int maxEvents) {
        if (maxEvents <= 0) {
            throw new IllegalArgumentException("maxEvents must be positive");
        }
        this.maxEvents = maxEvents;
        this.events = new ArrayDeque<>(Math.min(maxEvents, 1024));
        this.overflowLogged = false;

        LOG.log(Level.INFO, "InMemoryAuditSink initialized; maxEvents={0}", maxEvents);
    }

    @Override
    public synchronized void record(AuditEvent event) { // NOPMD
        if (event == null) {
            throw new IllegalArgumentException("event must not be null");
        }

        if (events.size() >= maxEvents) {
            events.removeFirst();
            if (!overflowLogged) {
                overflowLogged = true;
                LOG.log(Level.WARNING, "InMemoryAuditSink capacity exceeded; dropping oldest events (maxEvents={0})",
                        maxEvents);
            }
        }

        events.addLast(event);
    }

    /**
     * Returns an immutable snapshot of all currently retained events in insertion
     * order (oldest to newest).
     *
     * @return immutable snapshot
     */
    public synchronized List<AuditEvent> snapshot() { // NOPMD
        return List.copyOf(events);
    }

    @Override
    public synchronized List<AuditEvent> search(AuditQuery query) { // NOPMD
        if (query == null) {
            throw new IllegalArgumentException("query must not be null");
        }

        List<AuditEvent> out = new ArrayList<>();
        for (AuditEvent e : events) {
            if (e.matches(query)) {
                out.add(e);
            }
        }
        out.sort(AuditEvent.auditOrder());
        return List.copyOf(out.subList(0, Math.min(out.size(), query.limit())));
    }

    @Override
    public synchronized Optional<AuditEvent> getById(PkiId eventId) { // NOPMD
        if (eventId == null) {
            throw new IllegalArgumentException("eventId must not be null");
        }

        for (AuditEvent e : events) {
            if (AuditEventCodec.eventId(e).equals(eventId)) {
                return Optional.of(e);
            }
        }
        return Optional.empty();
    }

    /**
     * Returns the configured maximum number of retained events.
     *
     * @return maximum retained events
     */
    public int maxEvents() {
        return maxEvents;
    }

    @Override
    public synchronized String toString() { // NOPMD
        return "InMemoryAuditSink[size=" + events.size() + ", maxEvents=" + maxEvents + "]";
    }
}
