/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
 * Generic durable async bus implementation: in-memory state + append-only line
 * log for recovery.
 *
 * <p>
 * Log format is internal and versioned by a leading token. Corrupted lines are
 * ignored with a warning (without logging line content).
 * </p>
 *
 * <h2>No-secret logging</h2>
 * <p>
 * This implementation logs only operation ids (encoded) and types, never
 * payloads or serialized results.
 * </p>
 *
 * @param <OpId>       operation id type
 * @param <Owner>      owner type
 * @param <EndpointId> endpoint id type
 * @param <Result>     result type
 */
public final class DurableAsyncBus<OpId, Owner, EndpointId, Result> // NOPMD
        implements AsyncBus<OpId, Owner, EndpointId, Result> {

    private static final Logger LOG = Logger.getLogger(DurableAsyncBus.class.getName());

    private static final String REC_SNAPSHOT = "S1";
    private static final String REC_STATUS = "T1";
    private static final String REC_RESULT = "R1";

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
     * Creates the bus and immediately replays persisted state.
     *
     * @param opIdCodec     codec for operation ids (never {@code null})
     * @param ownerCodec    codec for owners (never {@code null})
     * @param endpointCodec codec for endpoints (never {@code null})
     * @param resultCodec   codec for results (never {@code null})
     * @param store         append-only store (never {@code null})
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

    @Override
    public void registerEndpoint(EndpointId endpointId, AsyncEndpoint<OpId, Result> endpoint) {
        Objects.requireNonNull(endpointId, "endpointId");
        Objects.requireNonNull(endpoint, "endpoint");
        endpointsById.put(endpointId, endpoint);

        if (LOG.isLoggable(Level.INFO)) {
            LOG.log(Level.INFO, "Registered async endpoint id={0}", new Object[] { safeEndpoint(endpointId) });
        }
    }

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

    @Override
    public AsyncOperationSnapshot<OpId, Owner, EndpointId> submit(OpId opId, String type, Owner owner,
            EndpointId endpointId, Instant createdAt, Duration ttl) {

        Objects.requireNonNull(opId, "opId");
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

    @Override
    public void update(OpId opId, AsyncStatus status, Optional<Result> result) {
        Objects.requireNonNull(opId, "opId");
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
            // keep snapshot+status until result consumed, but allow cleanup if no result
            // exists
            if (status.state() != AsyncState.SUCCEEDED) { // NOPMD
                deleteOperation(opId);
            }
        }
    }

    @Override
    public Optional<AsyncStatus> status(OpId opId) {
        Objects.requireNonNull(opId, "opId");
        return Optional.ofNullable(lastStatus.get(opId));
    }

    @Override
    public Optional<AsyncOperationSnapshot<OpId, Owner, EndpointId>> snapshot(OpId opId) {
        Objects.requireNonNull(opId, "opId");
        return Optional.ofNullable(active.get(opId));
    }

    @Override
    public Optional<Result> consumeResult(OpId opId) {
        Objects.requireNonNull(opId, "opId");

        Result r = results.remove(opId);
        if (r == null) {
            return Optional.empty();
        }

        // on successful consumption, forget operation entirely (bounded storage)
        deleteOperation(opId);

        if (LOG.isLoggable(Level.INFO)) {
            LOG.log(Level.INFO, "Consumed async result opId={0}", new Object[] { safeOpId(opId) });
        }

        return Optional.of(r);
    }

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
                    LOG.log(Level.WARNING, "Async endpoint status() failed; opId=" + safeOpId(opId), ex);
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
                        LOG.log(Level.WARNING, "Async endpoint result() failed; opId=" + safeOpId(opId), ex);
                    }
                }
            }

            update(opId, polled, res);
        }
    }

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

            deleteOperation(opId);
        }
    }

    private void deleteOperation(OpId opId) {
        active.remove(opId);
        lastStatus.remove(opId);
        results.remove(opId);
    }

    private void dispatchEvent(OpId opId, AsyncOperationSnapshot<OpId, Owner, EndpointId> snap, AsyncStatus status,
            Optional<Result> result) {

        AsyncEvent<OpId, Owner, EndpointId, Result> event = new AsyncEvent<>(snap, status, result);

        List<AsyncHandler<OpId, Owner, EndpointId, Result>> copy = List.copyOf(handlers);
        for (AsyncHandler<OpId, Owner, EndpointId, Result> h : copy) {
            try {
                h.onEvent(event);
            } catch (RuntimeException ex) { // NOPMD
                if (LOG.isLoggable(Level.WARNING)) {
                    LOG.log(Level.WARNING, "Async handler failed; opId=" + safeOpId(opId), ex);
                }
            }
        }
    }

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
                }
            } catch (RuntimeException ex) { // NOPMD
                // corrupted line: ignore safely without logging contents
                LOG.log(Level.WARNING, "Corrupted async store line encountered; skipping.", ex);
            }
        }

        if (LOG.isLoggable(Level.INFO)) {
            LOG.log(Level.INFO, "Replayed async store lines applied={0} activeOps={1}",
                    new Object[] { applied, active.size() });
        }
    }

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
    }

    private void applyResultLine(String line) {
        if (!resultCodec.persistsResults()) {
            return;
        }
        String[] parts = split(line, 3);
        // R1|opId|resultToken
        OpId opId = opIdCodec.decode(parts[1]);
        Result r = resultCodec.decode(parts[2]);
        results.put(opId, r);
    }

    private String encodeSnapshotLine(AsyncOperationSnapshot<OpId, Owner, EndpointId> snap) {
        return REC_SNAPSHOT + "|" + opIdCodec.encode(snap.opId()) + "|" + snap.type() + "|"
                + ownerCodec.encode(snap.owner()) + "|" + endpointCodec.encode(snap.endpointId()) + "|"
                + snap.createdAt().toString() + "|" + snap.expiresAt().toString();
    }

    private String encodeStatusLine(OpId opId, AsyncStatus st) {
        String dc = st.detailCode().orElse("");
        String details = encodeDetails(st.details());
        return REC_STATUS + "|" + opIdCodec.encode(opId) + "|" + st.state().name() + "|" + st.updatedAt().toString()
                + "|" + dc + "|" + details;
    }

    private String encodeResultLine(OpId opId, Result r) {
        return REC_RESULT + "|" + opIdCodec.encode(opId) + "|" + resultCodec.encode(r);
    }

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

    private static String escape(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("&", "\\&").replace("=", "\\=");
    }

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

    private static String[] split(String line, int expected) {
        String[] parts = line.split("\\|", -1);
        if (parts.length != expected) {
            throw new IllegalArgumentException("Invalid record arity.");
        }
        return parts;
    }

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
