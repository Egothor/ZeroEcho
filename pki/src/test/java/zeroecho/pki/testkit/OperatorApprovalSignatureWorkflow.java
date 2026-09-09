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
package zeroecho.pki.testkit;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.crypto.SignatureWorkflow;

/**
 * Test-only {@link SignatureWorkflow} implementation with operator approval.
 *
 * <p>
 * This workflow persists each operation to a filesystem directory so it can be
 * restarted deterministically within unit tests.
 * </p>
 *
 * <p>
 * The approval flow is intentionally explicit:
 * </p>
 * <ul>
 * <li>After {@link #submitSign(SignRequest, CallControl)} the operation enters
 * {@link State#WAITING_APPROVAL}.</li>
 * <li>Tests can call {@link #approve(PkiId)} or {@link #deny(PkiId)}.</li>
 * <li>If the operator does not act within {@link #approvalWindow}, the
 * operation becomes {@link State#EXPIRED} with detail code
 * {@code APPROVAL_EXPIRED}.</li>
 * </ul>
 */
public final class OperatorApprovalSignatureWorkflow implements SignatureWorkflow {

    private static final HexFormat HEX = HexFormat.of();

    private static final String FILE_META = "meta.properties";
    private static final String FILE_REQUEST = "request.bin";
    private static final String FILE_SIGNATURE = "signature.bin";

    private static final String K_CREATED_AT = "createdAt";
    private static final String K_UPDATED_AT = "updatedAt";
    private static final String K_STATE = "state";
    private static final String K_DETAIL = "detailCode";
    private static final String K_KEYREF = "keyRef";
    private static final String K_ALG = "algorithmId";
    private static final String K_DEADLINE = "deadline";
    private static final String K_APPROVED_AT = "approvedAt";
    private static final String K_DENIED_AT = "deniedAt";

    private final String id;
    private final Path root;
    private final TestSignIdentityRegistry identities;
    private final Map<String, PrivateKey> keysByKeyRef;
    private final Duration approvalWindow;
    private final Duration signDelay;
    private final AtomicLong seq;
    private final Map<PkiId, NotificationSink> sinks;

    /**
     * Creates a durable approval workflow.
     *
     * @param id             provider id
     * @param root           root directory for durable state
     * @param keysByKeyRef   key map (keyRef.value -&gt; private key)
     * @param approvalWindow approval window
     * @param signDelay      artificial signing delay (for async tests)
     */
    public OperatorApprovalSignatureWorkflow(String id, Path root, Map<String, PrivateKey> keysByKeyRef,
            Duration approvalWindow, Duration signDelay) {
        this.id = Objects.requireNonNull(id, "id");
        this.root = Objects.requireNonNull(root, "root");
        this.identities = new TestSignIdentityRegistry(root);
        this.keysByKeyRef = Objects.requireNonNull(keysByKeyRef, "keysByKeyRef");
        this.approvalWindow = Objects.requireNonNull(approvalWindow, "approvalWindow");
        this.signDelay = Objects.requireNonNull(signDelay, "signDelay");
        if (id.isBlank()) {
            throw new IllegalArgumentException("id must not be blank");
        }
        if (approvalWindow.isZero() || approvalWindow.isNegative()) {
            throw new IllegalArgumentException("approvalWindow must be positive");
        }
        if (signDelay.isNegative()) {
            throw new IllegalArgumentException("signDelay must not be negative");
        }
        this.seq = new AtomicLong(loadSeq(root));
        this.sinks = new ConcurrentHashMap<>();
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public ConfigurationCommitment configurationCommitment() {
        return new ConfigurationCommitment(new byte[ConfigurationCommitment.BYTE_LENGTH]);
    }

    @Override
    public PkiId submitSign(SignRequest request, CallControl control) {
        Objects.requireNonNull(request, "request");

        long n = seq.incrementAndGet();
        persistSeq(root, n);

        PkiId opId = request.submissionId();
        if (!identities.begin(request)) {
            return opId;
        }
        Path dir = opDir(opId);

        try {
            Files.createDirectories(dir);
            try (java.io.InputStream input = request.content().openStream();
                    java.io.OutputStream output = Files.newOutputStream(dir.resolve(FILE_REQUEST))) {
                input.transferTo(output);
            }

            java.util.Properties p = new java.util.Properties();
            Instant now = Instant.now();
            Instant deadline = now.plus(approvalWindow);
            if (request.deadline().isPresent() && request.deadline().get().isBefore(deadline)) {
                deadline = request.deadline().get();
            }
            p.setProperty(K_CREATED_AT, now.toString());
            p.setProperty(K_UPDATED_AT, now.toString());
            p.setProperty(K_DEADLINE, deadline.toString());
            p.setProperty(K_STATE, State.WAITING_APPROVAL.name());
            p.setProperty(K_DETAIL, "WAITING_APPROVAL");
            p.setProperty(K_KEYREF, request.keyRef().value());
            p.setProperty(K_ALG, request.algorithmId());
            writeProps(dir.resolve(FILE_META), p);
        } catch (IOException ex) {
            // Best-effort: return opId and surface as FAILED in status()
            failHard(opId, "IO_ERROR");
        }

        notifySink(opId);
        return opId;
    }

    @Override
    public PkiId submitVerify(VerifyRequest request, CallControl control) {
        Objects.requireNonNull(request, "request");
        // Not needed for these tests.
        long n = seq.incrementAndGet();
        persistSeq(root, n);
        PkiId opId = new PkiId("vwf:test:" + Long.toUnsignedString(n));
        failHard(opId, "NOT_SUPPORTED");
        return opId;
    }

    /**
     * Operator approves the request.
     */
    public void approve(PkiId operationId) {
        Objects.requireNonNull(operationId, "operationId");
        Path dir = opDir(operationId);
        java.util.Properties p = readPropsSafe(dir.resolve(FILE_META));
        if (p.isEmpty()) {
            return;
        }
        State s = parseState(p.getProperty(K_STATE));
        if (isTerminalState(s)) {
            return;
        }
        if (s != State.WAITING_APPROVAL && s != State.PENDING) {
            return;
        }
        Instant now = Instant.now();
        if (deadlineReached(p, now)) {
            p.setProperty(K_UPDATED_AT, now.toString());
            p.setProperty(K_STATE, State.EXPIRED.name());
            p.setProperty(K_DETAIL, "EXPIRED");
            writePropsSafe(dir.resolve(FILE_META), p);
            notifySink(operationId);
            return;
        }
        p.setProperty(K_APPROVED_AT, now.toString());
        p.setProperty(K_UPDATED_AT, now.toString());
        p.setProperty(K_STATE, State.RUNNING.name());
        p.setProperty(K_DETAIL, "APPROVED");
        writePropsSafe(dir.resolve(FILE_META), p);
        notifySink(operationId);
    }

    /**
     * Operator denies the request.
     */
    public void deny(PkiId operationId) {
        Objects.requireNonNull(operationId, "operationId");
        Path dir = opDir(operationId);
        java.util.Properties p = readPropsSafe(dir.resolve(FILE_META));
        if (p.isEmpty()) {
            return;
        }
        State s = parseState(p.getProperty(K_STATE));
        if (isTerminalState(s)) {
            return;
        }
        Instant now = Instant.now();
        p.setProperty(K_DENIED_AT, now.toString());
        p.setProperty(K_UPDATED_AT, now.toString());
        p.setProperty(K_STATE, State.FAILED.name());
        p.setProperty(K_DETAIL, "DENIED");
        writePropsSafe(dir.resolve(FILE_META), p);
        notifySink(operationId);
    }

    @Override
    public OperationStatus status(PkiId operationId, CallControl control) {
        Objects.requireNonNull(operationId, "operationId");
        Path dir = opDir(operationId);
        java.util.Properties p = readPropsSafe(dir.resolve(FILE_META));
        if (p.isEmpty()) {
            return new OperationStatus(State.FAILED, Instant.now(), Optional.of("UNKNOWN"), Optional.empty());
        }

        Instant updatedAt = Instant.parse(p.getProperty(K_UPDATED_AT));
        State state = parseState(p.getProperty(K_STATE));
        String detail = p.getProperty(K_DETAIL, "");

        // Expire while waiting for approval
        if (!isTerminalState(state) && (state == State.WAITING_APPROVAL || state == State.PENDING)
                && deadlineReached(p, Instant.now())) {
            state = State.EXPIRED;
            detail = "APPROVAL_EXPIRED";
            updatedAt = Instant.now();
            p.setProperty(K_STATE, state.name());
            p.setProperty(K_DETAIL, detail);
            p.setProperty(K_UPDATED_AT, updatedAt.toString());
            writePropsSafe(dir.resolve(FILE_META), p);
            notifySink(operationId);
        }

        // Complete after approval + delay
        if (!isTerminalState(state) && state == State.RUNNING) {
            String approvedAtRaw = p.getProperty(K_APPROVED_AT, "");
            if (!approvedAtRaw.isBlank()) {
                Instant approvedAt = Instant.parse(approvedAtRaw);
                if (Instant.now().isAfter(approvedAt.plus(signDelay))) {
                    Instant startedAt = Instant.now();
                    if (deadlineReached(p, startedAt)) {
                        p.setProperty(K_STATE, State.EXPIRED.name());
                        p.setProperty(K_DETAIL, "EXPIRED");
                        p.setProperty(K_UPDATED_AT, startedAt.toString());
                        writePropsSafe(dir.resolve(FILE_META), p);
                        notifySink(operationId);
                        return new OperationStatus(State.EXPIRED, startedAt, Optional.of("EXPIRED"), Optional.empty());
                    }
                    try {
                        byte[] payload = Files.readAllBytes(dir.resolve(FILE_REQUEST));
                        String keyRef = p.getProperty(K_KEYREF);
                        String alg = p.getProperty(K_ALG);
                        PrivateKey pk = keysByKeyRef.get(keyRef);
                        if (pk == null) {
                            return fail(operationId, dir, p, "UNKNOWN_KEY");
                        }
                        byte[] sigBytes = sign(alg, pk, payload);
                        updatedAt = Instant.now();
                        if (deadlineReached(p, updatedAt)) {
                            state = State.EXPIRED;
                            detail = "EXPIRED";
                        } else {
                            Files.write(dir.resolve(FILE_SIGNATURE), sigBytes);
                            state = State.SUCCEEDED;
                            detail = "SIGNED";
                        }
                        p.setProperty(K_STATE, state.name());
                        p.setProperty(K_DETAIL, detail);
                        p.setProperty(K_UPDATED_AT, updatedAt.toString());
                        writePropsSafe(dir.resolve(FILE_META), p);
                        notifySink(operationId);
                    } catch (IOException ex) {
                        return fail(operationId, dir, p, "IO_ERROR");
                    } catch (RuntimeException ex) {
                        return fail(operationId, dir, p, "RUNTIME");
                    }
                }
            }
        }

        Optional<OperationResult> result = Optional.empty();
        if (state == State.SUCCEEDED) {
            Optional<EncodedObject> signature = Optional.of(readSignatureSafe(dir));
            result = Optional.of(new OperationResult(signature, Optional.empty()));
        }
        return new OperationStatus(state, updatedAt, detail.isBlank() ? Optional.empty() : Optional.of(detail), result);
    }

    @Override
    public boolean cancel(PkiId operationId, long fencingToken, String reason, CallControl control) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(reason, "reason");
        if (fencingToken <= 0L) {
            throw new IllegalArgumentException("fencingToken must be positive");
        }
        if (reason.isBlank()) {
            throw new IllegalArgumentException("reason must not be blank");
        }
        Path dir = opDir(operationId);
        java.util.Properties p = readPropsSafe(dir.resolve(FILE_META));
        if (p.isEmpty()) {
            return false;
        }
        State s = parseState(p.getProperty(K_STATE));
        if (isTerminalState(s)) {
            return s == State.CANCELLED && identities.fence(operationId).orElse(-1L) == fencingToken;
        }
        if (!identities.acceptFence(operationId, fencingToken)) {
            return false;
        }
        Instant now = Instant.now();
        p.setProperty(K_STATE, State.CANCELLED.name());
        p.setProperty(K_DETAIL, "CANCELLED");
        p.setProperty(K_UPDATED_AT, now.toString());
        writePropsSafe(dir.resolve(FILE_META), p);
        notifySink(operationId);
        return true;
    }

    @Override
    public Registration register(NotificationSink sink) {
        Objects.requireNonNull(sink, "sink");
        PkiId k = new PkiId("sink:" + Integer.toUnsignedString(System.identityHashCode(sink)));
        sinks.put(k, sink);
        return () -> sinks.remove(k);
    }

    @Override
    public Set<String> supportedAlgorithms() {
        return Set.of("SHA256withRSA");
    }

    @Override
    public void close() {
        // no resources
    }

    private OperationStatus fail(PkiId opId, Path dir, java.util.Properties p, String detailCode) {
        Instant now = Instant.now();
        p.setProperty(K_STATE, State.FAILED.name());
        p.setProperty(K_DETAIL, detailCode);
        p.setProperty(K_UPDATED_AT, now.toString());
        writePropsSafe(dir.resolve(FILE_META), p);
        notifySink(opId);
        return new OperationStatus(State.FAILED, now, Optional.of(detailCode), Optional.empty());
    }

    private void failHard(PkiId opId, String detailCode) {
        try {
            Files.createDirectories(opDir(opId));
            java.util.Properties p = new java.util.Properties();
            Instant now = Instant.now();
            p.setProperty(K_CREATED_AT, now.toString());
            p.setProperty(K_UPDATED_AT, now.toString());
            p.setProperty(K_STATE, State.FAILED.name());
            p.setProperty(K_DETAIL, detailCode);
            writePropsSafe(opDir(opId).resolve(FILE_META), p);
        } catch (IOException ex) {
            // ignore
        }
    }

    private EncodedObject readSignatureSafe(Path dir) {
        try {
            byte[] b = Files.readAllBytes(dir.resolve(FILE_SIGNATURE));
            return new EncodedObject(Encoding.BINARY, b);
        } catch (IOException ex) {
            return new EncodedObject(Encoding.BINARY, new byte[0]);
        }
    }

    private byte[] sign(String algorithmId, PrivateKey pk, byte[] payload) {
        try {
            Signature s = Signature.getInstance(algorithmId);
            s.initSign(pk);
            s.update(payload);
            return s.sign();
        } catch (Exception ex) {
            throw new IllegalStateException("Signing failed", ex);
        }
    }

    private void notifySink(PkiId opId) {
        for (NotificationSink sink : sinks.values()) {
            try {
                sink.onStatusChanged(opId, status(opId,
                        new CallControl(Instant.MAX, zeroecho.core.io.CancellationSignal.NONE)));
            } catch (RuntimeException ex) {
                // ignore
            }
        }
    }

    private Path opDir(PkiId opId) {
        String safe = HEX.formatHex(opId.value().getBytes(StandardCharsets.UTF_8));
        return root.resolve(safe);
    }

    private static State parseState(String s) {
        if (s == null || s.isBlank()) {
            return State.FAILED;
        }
        try {
            return State.valueOf(s);
        } catch (IllegalArgumentException ex) {
            return State.FAILED;
        }
    }

    private static boolean isTerminalState(State s) {
        return s == State.SUCCEEDED || s == State.FAILED || s == State.CANCELLED || s == State.EXPIRED;
    }

    private static boolean deadlineReached(java.util.Properties properties, Instant observedAt) {
        String value = properties.getProperty(K_DEADLINE, "");
        return !value.isBlank() && !observedAt.isBefore(Instant.parse(value));
    }

    private static long loadSeq(Path root) {
        Path f = root.resolve("seq.txt");
        try {
            if (!Files.exists(f)) {
                return 0L;
            }
            String s = Files.readString(f, StandardCharsets.UTF_8).trim();
            if (s.isBlank()) {
                return 0L;
            }
            return Long.parseUnsignedLong(s);
        } catch (Exception ex) {
            return 0L;
        }
    }

    private static void persistSeq(Path root, long v) {
        Path f = root.resolve("seq.txt");
        try {
            Files.createDirectories(root);
            Files.writeString(f, Long.toUnsignedString(v), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            // ignore
        }
    }

    private static java.util.Properties readPropsSafe(Path file) {
        java.util.Properties p = new java.util.Properties();
        if (!Files.exists(file)) {
            return p;
        }
        try (InputStream in = Files.newInputStream(file)) {
            p.load(in);
        } catch (IOException ex) {
            // ignore
        }
        return p;
    }

    private static void writeProps(Path file, java.util.Properties p) throws IOException {
        try (OutputStream out = Files.newOutputStream(file)) {
            p.store(out, "");
        }
    }

    private static void writePropsSafe(Path file, java.util.Properties p) {
        try {
            writeProps(file, p);
        } catch (IOException ex) {
            // ignore
        }
    }
}
