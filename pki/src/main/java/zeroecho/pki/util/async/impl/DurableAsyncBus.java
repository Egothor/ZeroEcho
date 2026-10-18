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
package zeroecho.pki.util.async.impl;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.pki.util.async.AsyncBus;
import zeroecho.pki.util.async.AsyncEndpoint;
import zeroecho.pki.util.async.AsyncEvent;
import zeroecho.pki.util.async.AsyncHandler;
import zeroecho.pki.util.async.AsyncOperationSnapshot;
import zeroecho.pki.util.async.AsyncRegistration;
import zeroecho.pki.util.async.AsyncState;
import zeroecho.pki.util.async.AsyncStatus;
import zeroecho.pki.util.async.codec.IdCodec;
import zeroecho.pki.util.async.codec.ResultCodec;

/**
 * Generic durable implementation of {@link AsyncBus}.
 *
 * <p>
 * This implementation combines:
 * </p>
 * <ul>
 * <li>an in-memory view of active operations, their last known statuses, and
 * optionally persisted results,</li>
 * <li>an append-only line store represented by
 * {@link AppendOnlyLineStore},</li>
 * <li>polling-based interaction with registered {@link AsyncEndpoint}
 * instances,</li>
 * <li>event dispatch to subscribed {@link AsyncHandler} observers.</li>
 * </ul>
 *
 * <p>
 * The append-only store is the durability boundary for operation snapshots,
 * status transitions, and optionally results. On construction, the bus
 * immediately replays the persisted log to reconstruct its in-memory state.
 * </p>
 *
 * <h2>Operational model</h2>
 * <ul>
 * <li>{@link #submit(Object, String, Object, Object, Instant, Duration)}
 * creates a new operation snapshot, persists it together with an initial
 * {@link AsyncState#SUBMITTED} status, and dispatches the corresponding
 * event.</li>
 * <li>{@link #sweep(Instant)} first expires overdue operations and then polls
 * registered endpoints for non-terminal active operations.</li>
 * <li>{@link #update(Object, AsyncStatus, Optional)} persists a status
 * transition, optionally persists a result, dispatches an event, and applies
 * terminal-state cleanup rules.</li>
 * <li>{@link #consumeResult(Object)} returns a successful result once and
 * durably tombstones the operation.</li>
 * </ul>
 *
 * <h2>Durability semantics</h2>
 * <ul>
 * <li>Operation snapshots are persisted as internal {@code S1} records.</li>
 * <li>Status transitions are persisted as internal {@code T1} records.</li>
 * <li>Results are persisted as internal {@code R1} records only when
 * {@link ResultCodec#persistsResults()} returns {@code true}.</li>
 * <li>Consumption and explicit retirement are persisted as internal {@code D1}
 * tombstones.</li>
 * <li>The log format is internal to this implementation and versioned by the
 * leading record token.</li>
 * <li>Corrupted lines encountered during replay are ignored with a warning, and
 * line contents themselves are not logged.</li>
 * </ul>
 *
 * <h2>Lifecycle semantics</h2>
 * <ul>
 * <li>Non-success terminal operations are removed from the active-operation map
 * as part of update or expiry processing, but their last terminal status is
 * retained for diagnostics until explicit deletion or result consumption
 * removes them.</li>
 * <li>Successful operations may retain their result until
 * {@link #consumeResult(Object)} is called.</li>
 * <li>Expired operations are marked with {@link AsyncState#EXPIRED}, persisted,
 * and removed from the active-operation map.</li>
 * </ul>
 *
 * <h2>Logging and sensitive data</h2>
 * <p>
 * This implementation logs only safe operational metadata such as encoded
 * operation ids, endpoint ids, and operation types. It never logs serialized
 * payloads, result bodies, or raw persisted line contents.
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * The main internal collections are wrapped in synchronized collection views.
 * This provides basic shared-state protection for ordinary concurrent use, but
 * callers should not treat this implementation as a lock-free or fully atomic
 * coordination primitive across all compound operations.
 * </p>
 *
 * @param <OpId>       operation identifier type
 * @param <Owner>      operation owner type
 * @param <EndpointId> endpoint identifier type
 * @param <Result>     result value type
 */
public final class DurableAsyncBus<OpId, Owner, EndpointId, Result> // NOPMD
        implements AsyncBus<OpId, Owner, EndpointId, Result> {

    private static final Logger LOG = Logger.getLogger(DurableAsyncBus.class.getName());

    private static final String REC_SNAPSHOT = "S1";
    private static final String REC_STATUS = "T1";
    private static final String REC_RESULT = "R1";
    private static final String REC_DELETE = "D1";
    private static final String ARG_OP_ID = "opId";

    private final IdCodec<OpId> opIdCodec;
    private final IdCodec<Owner> ownerCodec;
    private final IdCodec<EndpointId> endpointCodec;
    private final ResultCodec<Result> resultCodec;
    private final AppendOnlyLineStore store;

    private final Map<OpId, AsyncOperationSnapshot<OpId, Owner, EndpointId>> active;
    private final Map<OpId, AsyncStatus> lastStatus;
    private final Map<OpId, Result> results; // removed on consume
    private final Map<EndpointId, AsyncEndpoint<OpId, Result>> endpointsById;
    private final List<AsyncHandler<OpId, Owner, EndpointId, Result>> handlers;

    /**
     * Creates the durable async bus and immediately replays persisted state from
     * the append-only store.
     *
     * <p>
     * The supplied codecs define the stable serialization form used both for
     * persistence and for safe logging of identifiers. Construction reconstructs
     * in-memory operation snapshots, status history tail, and optionally persisted
     * results by calling {@link #replay()}.
     * </p>
     *
     * @param opIdCodec     codec for operation identifiers; must not be
     *                      {@code null}
     * @param ownerCodec    codec for owners; must not be {@code null}
     * @param endpointCodec codec for endpoint identifiers; must not be {@code null}
     * @param resultCodec   codec for result values; must not be {@code null}
     * @param store         append-only persistence store; must not be {@code null}
     * @throws NullPointerException if any argument is {@code null}
     */
    public DurableAsyncBus(IdCodec<OpId> opIdCodec, IdCodec<Owner> ownerCodec, IdCodec<EndpointId> endpointCodec,
            ResultCodec<Result> resultCodec, AppendOnlyLineStore store) {
        this.opIdCodec = Objects.requireNonNull(opIdCodec, "opIdCodec");
        this.ownerCodec = Objects.requireNonNull(ownerCodec, "ownerCodec");
        this.endpointCodec = Objects.requireNonNull(endpointCodec, "endpointCodec");
        this.resultCodec = Objects.requireNonNull(resultCodec, "resultCodec");
        this.store = Objects.requireNonNull(store, "store");

        this.active = Collections.synchronizedMap(new LinkedHashMap<>());
        this.lastStatus = Collections.synchronizedMap(new HashMap<>());
        this.results = Collections.synchronizedMap(new HashMap<>());
        this.endpointsById = Collections.synchronizedMap(new HashMap<>());
        this.handlers = Collections.synchronizedList(new ArrayList<>());

        replay();
    }

    /**
     * Registers an endpoint under the supplied endpoint identifier.
     *
     * <p>
     * Endpoint registration is purely in-memory and affects only future polling
     * performed by {@link #sweep(Instant)}. Registering a new endpoint under an
     * already existing identifier replaces the previous endpoint instance.
     * </p>
     *
     * @param endpointId endpoint identifier; must not be {@code null}
     * @param endpoint   endpoint implementation; must not be {@code null}
     * @throws NullPointerException if {@code endpointId} or {@code endpoint} is
     *                              {@code null}
     */
    @Override
    public void registerEndpoint(EndpointId endpointId, AsyncEndpoint<OpId, Result> endpoint) {
        Objects.requireNonNull(endpointId, "endpointId");
        Objects.requireNonNull(endpoint, "endpoint");
        endpointsById.put(endpointId, endpoint);

        if (LOG.isLoggable(Level.INFO)) {
            LOG.log(Level.INFO, "Registered async endpoint id={0}", new Object[] { safeEndpoint(endpointId) });
        }
    }

    /**
     * Subscribes an event handler to async bus events.
     *
     * <p>
     * The returned {@link AsyncRegistration} removes the handler when closed.
     * Closing the registration is idempotent.
     * </p>
     *
     * @param handler event handler to subscribe; must not be {@code null}
     * @return registration handle used to unsubscribe the handler
     * @throws NullPointerException if {@code handler} is {@code null}
     */
    @Override
    public AsyncRegistration subscribe(AsyncHandler<OpId, Owner, EndpointId, Result> handler) {
        Objects.requireNonNull(handler, "handler");
        handlers.add(handler);
        return new AsyncRegistration() {
            private volatile boolean closed; // NOPMD

            @Override
            public void close() {
                if (closed) {
                    return;
                }
                closed = true;
                handlers.remove(handler);
            }
        };
    }

    /**
     * Submits a new async operation.
     *
     * <p>
     * Submission records:
     * </p>
     * <ul>
     * <li>an {@link AsyncOperationSnapshot} in the active-operation map,</li>
     * <li>an initial {@link AsyncState#SUBMITTED} status in the status map,</li>
     * <li>a snapshot line and a status line in the append-only store,</li>
     * <li>an {@link AsyncEvent} dispatched to subscribed handlers.</li>
     * </ul>
     *
     * <p>
     * The method does not invoke the endpoint immediately. Actual endpoint polling
     * is performed later by {@link #sweep(Instant)}.
     * </p>
     *
     * @param opId       operation identifier; must not be {@code null}
     * @param type       non-blank operation type; must not be {@code null} or blank
     * @param owner      operation owner; must not be {@code null}
     * @param endpointId endpoint identifier to be used later for polling; must not
     *                   be {@code null}
     * @param createdAt  operation creation timestamp; must not be {@code null}
     * @param ttl        positive operation TTL; must not be {@code null}, zero, or
     *                   negative
     * @return submitted operation snapshot
     * @throws NullPointerException     if any mandatory argument is {@code null}
     * @throws IllegalArgumentException if {@code type} is blank or {@code ttl} is
     *                                  zero or negative
     */
    @Override
    public AsyncOperationSnapshot<OpId, Owner, EndpointId> submit(OpId opId, String type, Owner owner,
            EndpointId endpointId, Instant createdAt, Duration ttl) {

        Objects.requireNonNull(opId, ARG_OP_ID);
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(endpointId, "endpointId");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(ttl, "ttl");
        if (type.isBlank()) {
            throw new IllegalArgumentException("type must not be blank");
        }
        if (ttl.isZero() || ttl.isNegative()) {
            throw new IllegalArgumentException("ttl must be positive");
        }

        Instant expiresAt = createdAt.plus(ttl);
        AsyncOperationSnapshot<OpId, Owner, EndpointId> snap = new AsyncOperationSnapshot<>(opId, type, owner,
                endpointId, createdAt, expiresAt);

        active.put(opId, snap);

        AsyncStatus init = new AsyncStatus(AsyncState.SUBMITTED, createdAt, Optional.of("SUBMITTED"),
                Map.of("type", type));
        lastStatus.put(opId, init);

        store.appendLine(encodeSnapshotLine(snap));
        store.appendLine(encodeStatusLine(opId, init));

        dispatchEvent(opId, snap, init, Optional.empty());

        if (LOG.isLoggable(Level.INFO)) {
            LOG.log(Level.INFO, "Submitted async opId={0} type={1} endpoint={2}",
                    new Object[] { safeOpId(opId), type, safeEndpoint(endpointId) });
        }

        return snap;
    }

    /**
     * Applies a status update and an optional result to an existing operation.
     *
     * <p>
     * Unknown operation identifiers are ignored intentionally. This allows
     * idempotent or late updates to be safely dropped after cleanup.
     * </p>
     *
     * <p>
     * For known operations, the method:
     * </p>
     * <ul>
     * <li>updates the last known status,</li>
     * <li>persists the status line,</li>
     * <li>optionally persists and stores the result,</li>
     * <li>dispatches an event,</li>
     * <li>applies terminal-state cleanup rules.</li>
     * </ul>
     *
     * <p>
     * Non-success terminal states remove the operation from the active-operation
     * map immediately. Successful operations retain their result until
     * {@link #consumeResult(Object)} is called.
     * </p>
     *
     * @param opId   operation identifier; must not be {@code null}
     * @param status new status; must not be {@code null}
     * @param result optional result value associated with the status; must not be
     *               {@code null}
     * @throws NullPointerException if any argument is {@code null}
     */
    @Override
    public void update(OpId opId, AsyncStatus status, Optional<Result> result) {
        Objects.requireNonNull(opId, ARG_OP_ID);
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(result, "result");

        AsyncOperationSnapshot<OpId, Owner, EndpointId> snap = active.get(opId);
        if (snap == null) {
            // unknown op; ignore (or strict throw) - choose ignore to allow idempotent
            // updates after cleanup
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "Ignoring update for unknown async opId={0}", new Object[] { safeOpId(opId) });
            }
            return;
        }

        lastStatus.put(opId, status);
        store.appendLine(encodeStatusLine(opId, status));

        if (result.isPresent()) {
            if (resultCodec.persistsResults()) {
                store.appendLine(encodeResultLine(opId, result.get()));
            }
            results.put(opId, result.get());
        }

        dispatchEvent(opId, snap, status, result);

        if (status.isTerminal()) {
            // All terminal operations leave the active set. Only successful
            // operations retain their result for later consumption.
            active.remove(opId);
            if (status.state() != AsyncState.SUCCEEDED) {
                results.remove(opId);
            }
        }
    }

    /**
     * Returns the last known status for an operation.
     *
     * @param opId operation identifier; must not be {@code null}
     * @return optional last known status, or an empty optional when the operation
     *         is unknown
     * @throws NullPointerException if {@code opId} is {@code null}
     */
    @Override
    public Optional<AsyncStatus> status(OpId opId) {
        Objects.requireNonNull(opId, ARG_OP_ID);
        return Optional.ofNullable(lastStatus.get(opId));
    }

    /**
     * Returns the currently active snapshot for an operation.
     *
     * <p>
     * Terminal operations that have already been dropped from the active map are
     * therefore no longer visible through this method even if their terminal status
     * may still be retained in {@link #status(Object)}.
     * </p>
     *
     * @param opId operation identifier; must not be {@code null}
     * @return optional active snapshot, or an empty optional when no active
     *         snapshot is retained
     * @throws NullPointerException if {@code opId} is {@code null}
     */
    @Override
    public Optional<AsyncOperationSnapshot<OpId, Owner, EndpointId>> snapshot(OpId opId) {
        Objects.requireNonNull(opId, ARG_OP_ID);
        return Optional.ofNullable(active.get(opId));
    }

    /**
     * Returns and removes a previously stored successful result.
     *
     * <p>
     * Result consumption is destructive. Before returning the result, this method
     * appends a deletion tombstone and removes the complete in-memory operation
     * state. Consequently, replay cannot make a consumed result visible again.
     * </p>
     *
     * @param opId operation identifier; must not be {@code null}
     * @return optional result, or an empty optional when no result is available
     * @throws NullPointerException if {@code opId} is {@code null}
     */
    @Override
    public Optional<Result> consumeResult(OpId opId) {
        Objects.requireNonNull(opId, ARG_OP_ID);

        Result r = results.get(opId);
        if (r == null) {
            return Optional.empty();
        }

        store.appendLine(encodeDeleteLine(opId));
        deleteOperation(opId);

        if (LOG.isLoggable(Level.INFO)) {
            LOG.log(Level.INFO, "Consumed async result opId={0}", new Object[] { safeOpId(opId) });
        }

        return Optional.of(r);
    }

    /**
     * Durably retires all bus state for an operation.
     *
     * <p>
     * Retirement appends a tombstone before deleting in-memory state. Replay
     * applies records in order, so snapshots, statuses, and results preceding the
     * tombstone cannot resurrect after restart. A later explicit submission using
     * the same identifier remains visible because its records follow the tombstone.
     * </p>
     *
     * @param opId operation identifier; must not be {@code null}
     * @throws NullPointerException if {@code opId} is {@code null}
     */
    public void retire(OpId opId) {
        Objects.requireNonNull(opId, ARG_OP_ID);
        store.appendLine(encodeDeleteLine(opId));
        deleteOperation(opId);
    }

    /**
     * Performs one maintenance and polling sweep.
     *
     * <p>
     * The sweep has two phases:
     * </p>
     * <ol>
     * <li>expire operations whose deadline has passed,</li>
     * <li>poll non-terminal active operations through their registered
     * endpoints.</li>
     * </ol>
     *
     * <p>
     * Endpoint failures are isolated and logged as warnings. They do not abort the
     * sweep and do not fail other operations processed in the same pass.
     * </p>
     *
     * @param now current sweep time; must not be {@code null}
     * @throws NullPointerException if {@code now} is {@code null}
     */
    @Override
    public void sweep(Instant now) {
        Objects.requireNonNull(now, "now");

        // 1) expire
        sweepExpired(now);

        // 2) poll open ops (best-effort)
        List<AsyncOperationSnapshot<OpId, Owner, EndpointId>> open = List.copyOf(active.values());
        for (AsyncOperationSnapshot<OpId, Owner, EndpointId> snap : open) {
            OpId opId = snap.opId();
            AsyncStatus st = lastStatus.get(opId);
            if (st != null && st.isTerminal()) {
                continue;
            }

            AsyncEndpoint<OpId, Result> endpoint = endpointsById.get(snap.endpointId());
            if (endpoint == null) {
                continue;
            }

            Optional<AsyncStatus> statusOpt;
            try {
                statusOpt = endpoint.status(opId);
            } catch (RuntimeException ex) { // NOPMD
                // endpoint misbehaved; do not fail sweep
                if (LOG.isLoggable(Level.WARNING)) {
                    logSafeFailure("ENDPOINT_STATUS_FAILED", opId, ex);
                }
                continue;
            }

            if (statusOpt.isEmpty()) {
                continue;
            }

            AsyncStatus polled = statusOpt.get();
            AsyncStatus prev = lastStatus.get(opId);
            if (prev != null && prev.updatedAt().equals(polled.updatedAt()) && prev.state() == polled.state()) {
                continue;
            }

            Optional<Result> res = Optional.empty();
            if (polled.state() == AsyncState.SUCCEEDED) {
                try {
                    res = endpoint.result(opId);
                } catch (RuntimeException ex) { // NOPMD
                    if (LOG.isLoggable(Level.WARNING)) {
                        logSafeFailure("ENDPOINT_RESULT_FAILED", opId, ex);
                    }
                }
            }

            update(opId, polled, res);
        }
    }

    /**
     * Expires operations whose deadline has passed and emits the corresponding
     * terminal status.
     *
     * @param now current sweep time; must not be {@code null}
     */
    private void sweepExpired(Instant now) {
        List<Map.Entry<OpId, AsyncOperationSnapshot<OpId, Owner, EndpointId>>> entries = List.copyOf(active.entrySet());
        for (Map.Entry<OpId, AsyncOperationSnapshot<OpId, Owner, EndpointId>> e : entries) {
            OpId opId = e.getKey();
            AsyncOperationSnapshot<OpId, Owner, EndpointId> snap = e.getValue();

            if (!now.isAfter(snap.expiresAt())) {
                continue;
            }

            AsyncStatus expired = new AsyncStatus(AsyncState.EXPIRED, now, Optional.of("EXPIRED"), // NOPMD
                    Map.of("reason", "deadline-exceeded"));

            // prev is intentionally not used: we keep it to allow future diagnostics
            // (e.g., breakpoint inspection). If you prefer strictness, remove the
            // assignment.
            @SuppressWarnings("unused")
            AsyncStatus prev = lastStatus.put(opId, expired);

            store.appendLine(encodeStatusLine(opId, expired));

            if (LOG.isLoggable(Level.INFO)) {
                LOG.log(Level.INFO, "Expired async operation opId={0} type={1}",
                        new Object[] { safeOpId(opId), snap.type() }); // NOPMD
            }

            dispatchEvent(opId, snap, expired, Optional.empty());

            dropActiveOperation(opId);
        }
    }

    /**
     * Removes an operation from the active-operation and result maps but keeps any
     * retained status entry.
     *
     * @param opId operation identifier; must not be {@code null}
     */
    private void dropActiveOperation(OpId opId) {
        active.remove(opId);
        results.remove(opId);
    }

    /**
     * Removes all in-memory state associated with an operation.
     *
     * @param opId operation identifier; must not be {@code null}
     */
    private void deleteOperation(OpId opId) {
        dropActiveOperation(opId);
        lastStatus.remove(opId);
    }

    /**
     * Dispatches one async event to all currently subscribed handlers.
     *
     * <p>
     * Handler failures are isolated and logged as warnings. A misbehaving handler
     * must not prevent other handlers from receiving the event.
     * </p>
     *
     * @param opId   operation identifier used only for safe logging; must not be
     *               {@code null}
     * @param snap   operation snapshot; must not be {@code null}
     * @param status status being dispatched; must not be {@code null}
     * @param result optional result value; must not be {@code null}
     */
    private void dispatchEvent(OpId opId, AsyncOperationSnapshot<OpId, Owner, EndpointId> snap, AsyncStatus status,
            Optional<Result> result) {

        AsyncEvent<OpId, Owner, EndpointId, Result> event = new AsyncEvent<>(snap, status, result);

        List<AsyncHandler<OpId, Owner, EndpointId, Result>> copy = List.copyOf(handlers);
        for (AsyncHandler<OpId, Owner, EndpointId, Result> h : copy) {
            try {
                h.onEvent(event);
            } catch (RuntimeException ex) { // NOPMD
                if (LOG.isLoggable(Level.WARNING)) {
                    logSafeFailure("HANDLER_FAILED", opId, ex);
                }
            }
        }
    }

    /**
     * Replays all persisted lines from the append-only store and reconstructs the
     * in-memory state.
     *
     * <p>
     * Unknown or corrupted records are ignored safely. Record contents are not
     * logged.
     * </p>
     */
    private void replay() {
        List<String> lines = store.readAllLines();
        if (lines.isEmpty()) {
            return;
        }

        int applied = 0;
        for (String line : lines) {
            if (line == null || line.isBlank()) {
                continue;
            }
            try {
                if (line.startsWith(REC_SNAPSHOT + "|")) {
                    applySnapshotLine(line);
                    applied++;
                } else if (line.startsWith(REC_STATUS + "|")) {
                    applyStatusLine(line);
                    applied++;
                } else if (line.startsWith(REC_RESULT + "|")) {
                    applyResultLine(line);
                    applied++;
                } else if (line.startsWith(REC_DELETE + "|")) {
                    applyDeleteLine(line);
                    applied++;
                }
            } catch (RuntimeException ex) { // NOPMD
                // corrupted line: ignore safely without logging contents
                logRecordRejected(ex);
            }
        }

        if (LOG.isLoggable(Level.INFO)) {
            LOG.log(Level.INFO, "Replayed async store lines applied={0} activeOps={1}",
                    new Object[] { applied, active.size() });
        }
    }

    /**
     * Applies one persisted snapshot record.
     *
     * @param line snapshot record line in internal {@code S1} format; must not be
     *             {@code null}
     * @throws RuntimeException if the line cannot be decoded
     */
    private void applySnapshotLine(String line) {
        String[] parts = split(line, 7);
        // S1|opId|type|owner|endpoint|createdAt|expiresAt
        OpId opId = opIdCodec.decode(parts[1]);
        String type = parts[2];
        Owner owner = ownerCodec.decode(parts[3]);
        EndpointId endpointId = endpointCodec.decode(parts[4]);
        Instant createdAt = Instant.parse(parts[5]);
        Instant expiresAt = Instant.parse(parts[6]);

        AsyncOperationSnapshot<OpId, Owner, EndpointId> snap = new AsyncOperationSnapshot<>(opId, type, owner,
                endpointId, createdAt, expiresAt);
        active.put(opId, snap);
    }

    /**
     * Applies one persisted status record.
     *
     * @param line status record line in internal {@code T1} format; must not be
     *             {@code null}
     * @throws RuntimeException if the line cannot be decoded
     */
    private void applyStatusLine(String line) {
        String[] parts = split(line, 6);
        // T1|opId|state|updatedAt|detailCode|k=v&k=v
        OpId opId = opIdCodec.decode(parts[1]);
        AsyncState state = AsyncState.valueOf(parts[2]);
        Instant updatedAt = Instant.parse(parts[3]);
        Optional<String> dc = parts[4].isBlank() ? Optional.empty() : Optional.of(parts[4]);
        Map<String, String> details = decodeDetails(parts[5]);

        AsyncStatus st = new AsyncStatus(state, updatedAt, dc, details);
        lastStatus.put(opId, st);
        if (st.isTerminal()) {
            active.remove(opId);
            if (state != AsyncState.SUCCEEDED) {
                results.remove(opId);
            }
        }
    }

    /**
     * Applies one persisted result record when result persistence is enabled.
     *
     * @param line result record line in internal {@code R1} format; must not be
     *             {@code null}
     * @throws RuntimeException if the line cannot be decoded
     */
    private void applyResultLine(String line) {
        if (!resultCodec.persistsResults()) {
            return;
        }
        String[] parts = split(line, 3);
        // R1|opId|resultToken
        OpId opId = opIdCodec.decode(parts[1]);
        Result r = resultCodec.decode(parts[2]);
        AsyncStatus status = lastStatus.get(opId);
        if (active.containsKey(opId) || status != null && status.state() == AsyncState.SUCCEEDED) {
            results.put(opId, r);
        }
    }

    /**
     * Applies one persisted deletion tombstone.
     *
     * @param line deletion record line in internal {@code D1} format
     */
    private void applyDeleteLine(String line) {
        String[] parts = split(line, 2);
        deleteOperation(opIdCodec.decode(parts[1]));
    }

    /**
     * Encodes one snapshot record line for persistence.
     *
     * @param snap snapshot to encode; must not be {@code null}
     * @return encoded internal {@code S1} record line
     */
    private String encodeSnapshotLine(AsyncOperationSnapshot<OpId, Owner, EndpointId> snap) {
        return REC_SNAPSHOT + "|" + opIdCodec.encode(snap.opId()) + "|" + snap.type() + "|"
                + ownerCodec.encode(snap.owner()) + "|" + endpointCodec.encode(snap.endpointId()) + "|"
                + snap.createdAt().toString() + "|" + snap.expiresAt().toString();
    }

    /**
     * Encodes one status record line for persistence.
     *
     * @param opId operation identifier; must not be {@code null}
     * @param st   status to encode; must not be {@code null}
     * @return encoded internal {@code T1} record line
     */
    private String encodeStatusLine(OpId opId, AsyncStatus st) {
        String dc = st.detailCode().orElse("");
        String details = encodeDetails(st.details());
        return REC_STATUS + "|" + opIdCodec.encode(opId) + "|" + st.state().name() + "|" + st.updatedAt().toString()
                + "|" + dc + "|" + details;
    }

    /**
     * Encodes one result record line for persistence.
     *
     * @param opId operation identifier; must not be {@code null}
     * @param r    result value; must not be {@code null}
     * @return encoded internal {@code R1} record line
     */
    private String encodeResultLine(OpId opId, Result r) {
        return REC_RESULT + "|" + opIdCodec.encode(opId) + "|" + resultCodec.encode(r);
    }

    private String encodeDeleteLine(OpId opId) {
        return REC_DELETE + "|" + opIdCodec.encode(opId);
    }

    /**
     * Encodes a details map into the internal status-details token form.
     *
     * @param details details map; may be {@code null}
     * @return encoded details token, never {@code null}
     */
    private static String encodeDetails(Map<String, String> details) {
        if (details == null || details.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder(64);
        boolean first = true;
        for (Map.Entry<String, String> e : details.entrySet()) {
            if (!first) {
                sb.append('&');
            }
            first = false;
            sb.append(escape(e.getKey())).append('=').append(escape(e.getValue()));
        }
        return sb.toString();
    }

    /**
     * Decodes the internal status-details token form into an immutable map.
     *
     * @param token encoded details token; may be {@code null}
     * @return immutable decoded details map
     */
    private static Map<String, String> decodeDetails(String token) {
        if (token == null || token.isBlank()) {
            return Map.of();
        }
        Map<String, String> out = new LinkedHashMap<>();
        String[] pairs = token.split("&");
        for (String p : pairs) {
            int idx = p.indexOf('=');
            if (idx <= 0) {
                continue;
            }
            String k = unescape(p.substring(0, idx));
            String v = unescape(p.substring(idx + 1));
            out.put(k, v);
        }
        return Map.copyOf(out);
    }

    /**
     * Escapes special characters used by the internal details encoding.
     *
     * @param s source string; may be {@code null}
     * @return escaped string, never {@code null}
     */
    private static String escape(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("&", "\\&").replace("=", "\\=");
    }

    /**
     * Reverses escaping applied by {@link #escape(String)}.
     *
     * @param s escaped string; may be {@code null}
     * @return unescaped string, never {@code null}
     */
    private static String unescape(String s) {
        if (s == null || s.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length());
        boolean esc = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (esc) {
                sb.append(c);
                esc = false;
            } else if (c == '\\') { // NOPMD
                esc = true;
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Splits a persisted record line and validates the expected field count.
     *
     * @param line     persisted line; must not be {@code null}
     * @param expected expected number of fields after splitting
     * @return split parts
     * @throws IllegalArgumentException if the number of fields does not match
     */
    private static String[] split(String line, int expected) {
        String[] parts = line.split("\\|", -1);
        if (parts.length != expected) {
            throw new IllegalArgumentException("Invalid record arity.");
        }
        return parts;
    }

    /**
     * Encodes an operation identifier for safe logging and truncates long values.
     *
     * @param opId operation identifier; may be {@code null}
     * @return safe short log token
     */
    private String safeOpId(OpId opId) {
        try {
            String s = opIdCodec.encode(opId);
            if (s.length() > 30) { // NOPMD
                return s.substring(0, 30) + "...";
            }
            return s;
        } catch (RuntimeException ex) { // NOPMD
            return "<opId>";
        }
    }

    private void logSafeFailure(String code, OpId opId, Throwable failure) {
        if (LOG.isLoggable(Level.WARNING)) {
            LOG.log(Level.WARNING, "Async operation failed: code={0}, opId={1}, exception={2}",
                    new Object[] { code, safeOpId(opId), failure.getClass().getName() });
        }
    }

    private static void logRecordRejected(RuntimeException failure) {
        if (LOG.isLoggable(Level.WARNING)) {
            LOG.log(Level.WARNING, "Async store record rejected: code={0}, exception={1}",
                    new Object[] { "ASYNC_RECORD_INVALID", failure.getClass().getName() });
        }
    }

    /**
     * Encodes an endpoint identifier for safe logging and truncates long values.
     *
     * @param endpointId endpoint identifier; may be {@code null}
     * @return safe short log token
     */
    private String safeEndpoint(EndpointId endpointId) {
        try {
            String s = endpointCodec.encode(endpointId);
            if (s.length() > 30) { // NOPMD
                return s.substring(0, 30) + "...";
            }
            return s;
        } catch (RuntimeException ex) { // NOPMD
            return "<endpoint>";
        }
    }
}
