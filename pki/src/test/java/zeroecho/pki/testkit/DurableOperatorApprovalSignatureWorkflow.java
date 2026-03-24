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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.crypto.SignatureWorkflow;

/**
 * Durable test implementation of {@link SignatureWorkflow} with operator
 * approval.
 *
 * <p>
 * This class is intended for deterministic testing of the PKI asynchronous
 * architecture. It persists workflow state under the provided directory so that
 * tests can simulate restarts by creating a new instance pointing to the same
 * directory.
 * </p>
 *
 * <p>
 * The workflow proceeds as:
 * </p>
 * <ol>
 * <li>{@code submitSign()} creates operation in {@code WAITING_APPROVAL}.</li>
 * <li>Operator calls {@link #approve(PkiId)} or {@link #deny(PkiId)}.</li>
 * <li>On next {@link #status(PkiId)} poll, the operation either expires, fails,
 * or signs and succeeds.</li>
 * </ol>
 */
public final class DurableOperatorApprovalSignatureWorkflow implements SignatureWorkflow, AutoCloseable {

    private static final String PROVIDER_ID = "testkit-operator-approval";

    private static final String FILE_STATUS = "status";
    private static final String FILE_DEADLINE = "deadline";
    private static final String FILE_REQUEST = "request";
    private static final String FILE_SIGNATURE = "signature";
    private static final String FILE_DECISION = "decision";

    private static final String DECISION_APPROVE = "APPROVE";
    private static final String DECISION_DENY = "DENY";

    private final Path root;
    private final Duration approvalWindow;
    private final Duration signingDelay;
    private final Map<String, PrivateKey> keysByRef;
    private final Map<PkiId, NotificationSink> sinks;

    /**
     * Creates the workflow.
     *
     * @param root           root directory for durable state
     * @param approvalWindow max duration to wait for operator approval
     * @param signingDelay   artificial delay (to prove async boundary)
     * @param keysByRef      mapping from {@code KeyRef.value()} to private key
     */
    public DurableOperatorApprovalSignatureWorkflow(Path root, Duration approvalWindow, Duration signingDelay,
            Map<String, PrivateKey> keysByRef) {
        this.root = Objects.requireNonNull(root, "root");
        this.approvalWindow = Objects.requireNonNull(approvalWindow, "approvalWindow");
        this.signingDelay = Objects.requireNonNull(signingDelay, "signingDelay");
        this.keysByRef = Objects.requireNonNull(keysByRef, "keysByRef");
        this.sinks = new ConcurrentHashMap<PkiId, NotificationSink>();

        if (approvalWindow.isZero() || approvalWindow.isNegative()) {
            throw new IllegalArgumentException("approvalWindow must be positive");
        }
        if (signingDelay.isNegative()) {
            throw new IllegalArgumentException("signingDelay must not be negative");
        }
        try {
            Files.createDirectories(root);
        } catch (IOException ex) {
            throw new IllegalArgumentException("Cannot create workflow root directory", ex);
        }
    }

    @Override
    public String id() {
        return PROVIDER_ID;
    }

    @Override
    public Set<String> supportedAlgorithms() {
        return Set.of("SHA256withRSA");
    }

    @Override
    public PkiId submitSign(SignRequest request) {
        Objects.requireNonNull(request, "request");

        PkiId opId = new PkiId("sig-" + UUID.randomUUID());
        Instant now = Instant.now();
        Instant deadline = now.plus(approvalWindow);

        persistRequest(opId, request);
        persistDeadline(opId, deadline);

        OperationStatus st = new OperationStatus(State.WAITING_APPROVAL, now, Optional.of("PENDING_APPROVAL"),
                Optional.empty());
        persistStatus(opId, st);
        notifySink(opId, st);
        return opId;
    }

    @Override
    public PkiId submitVerify(VerifyRequest request) {
        Objects.requireNonNull(request, "request");
        return new PkiId("verify-" + UUID.randomUUID());
    }

    /**
     * Operator approves the operation.
     *
     * @param operationId workflow operation id
     */
    public void approve(PkiId operationId) {
        Objects.requireNonNull(operationId, "operationId");
        persistDecision(operationId, DECISION_APPROVE);
        OperationStatus st = new OperationStatus(State.PENDING, Instant.now(), Optional.of("APPROVED"),
                Optional.empty());
        persistStatus(operationId, st);
        notifySink(operationId, st);
    }

    /**
     * Operator denies the operation.
     *
     * @param operationId workflow operation id
     */
    public void deny(PkiId operationId) {
        Objects.requireNonNull(operationId, "operationId");
        persistDecision(operationId, DECISION_DENY);
        OperationStatus st = new OperationStatus(State.FAILED, Instant.now(), Optional.of("DENIED"), Optional.empty());
        persistStatus(operationId, st);
        notifySink(operationId, st);
    }

    @Override
    public OperationStatus status(PkiId operationId) {
        Objects.requireNonNull(operationId, "operationId");

        OperationStatus st = loadStatus(operationId);
        if (st.isTerminal()) {
            return st;
        }

        if (st.state() == State.WAITING_APPROVAL) {
            // expire if past deadline
            Instant deadline = loadDeadline(operationId).orElse(Instant.EPOCH);
            if (Instant.now().isAfter(deadline)) {
                OperationStatus expired = new OperationStatus(State.EXPIRED, Instant.now(),
                        Optional.of("APPROVAL_EXPIRED"), Optional.empty());
                persistStatus(operationId, expired);
                notifySink(operationId, expired);
                return expired;
            }

            // decision file may already exist
            Optional<String> decision = loadDecision(operationId);
            if (decision.isPresent() && DECISION_DENY.equals(decision.get())) {
                OperationStatus denied = new OperationStatus(State.FAILED, Instant.now(), Optional.of("DENIED"),
                        Optional.empty());
                persistStatus(operationId, denied);
                notifySink(operationId, denied);
                return denied;
            }
            if (decision.isPresent() && DECISION_APPROVE.equals(decision.get())) {
                OperationStatus approved = new OperationStatus(State.PENDING, Instant.now(), Optional.of("APPROVED"),
                        Optional.empty());
                persistStatus(operationId, approved);
                notifySink(operationId, approved);
                st = approved;
            } else {
                return st;
            }
        }

        if (st.state() == State.PENDING) {
            OperationStatus running = new OperationStatus(State.RUNNING, Instant.now(), Optional.of("SIGNING"),
                    Optional.empty());
            persistStatus(operationId, running);
            notifySink(operationId, running);

            OperationStatus terminal = performSign(operationId);
            persistStatus(operationId, terminal);
            notifySink(operationId, terminal);
            return terminal;
        }

        return st;
    }

    @Override
    public boolean cancel(PkiId operationId, String reason) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(reason, "reason");
        if (reason.isBlank()) {
            throw new IllegalArgumentException("reason must not be blank");
        }

        OperationStatus st = loadStatus(operationId);
        if (st.isTerminal()) {
            return false;
        }

        OperationStatus cancelled = new OperationStatus(State.CANCELLED, Instant.now(), Optional.of("CANCELLED"),
                Optional.empty());
        persistStatus(operationId, cancelled);
        notifySink(operationId, cancelled);
        return true;
    }

    @Override
    public Registration register(NotificationSink sink) {
        Objects.requireNonNull(sink, "sink");
        PkiId id = new PkiId("sink-" + UUID.randomUUID());
        sinks.put(id, sink);
        return new Registration() {
            @Override
            public void close() {
                sinks.remove(id);
            }
        };
    }

    @Override
    public void close() {
        sinks.clear();
    }

    private OperationStatus performSign(PkiId opId) {
        PersistedSignRequest req = loadRequest(opId);

        PrivateKey key = keysByRef.get(req.keyRef);
        if (key == null) {
            return new OperationStatus(State.FAILED, Instant.now(), Optional.of("UNKNOWN_KEY"), Optional.empty());
        }
        if (!supportedAlgorithms().contains(req.algorithmId)) {
            return new OperationStatus(State.FAILED, Instant.now(), Optional.of("UNSUPPORTED_ALG"), Optional.empty());
        }

        if (!signingDelay.isZero()) {
            try {
                Thread.sleep(signingDelay.toMillis());
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return new OperationStatus(State.FAILED, Instant.now(), Optional.of("INTERRUPTED"), Optional.empty());
            }
        }

        try {
            Signature sig = Signature.getInstance(req.algorithmId);
            sig.initSign(key);
            sig.update(req.payload);
            byte[] signature = sig.sign();

            persistSignature(opId, signature);

            EncodedObject enc = new EncodedObject(Encoding.BINARY, signature);
            OperationResult res = new OperationResult(Optional.of(enc), Optional.empty());
            return new OperationStatus(State.SUCCEEDED, Instant.now(), Optional.of("SIGNED"), Optional.of(res));
        } catch (Exception ex) {
            return new OperationStatus(State.FAILED, Instant.now(), Optional.of("SIGN_ERROR"), Optional.empty());
        }
    }

    private void notifySink(PkiId opId, OperationStatus st) {
        for (NotificationSink s : sinks.values()) {
            try {
                s.onStatusChanged(opId, st);
            } catch (RuntimeException ex) {
                // ignore in testkit
            }
        }
    }

    private Path opDir(PkiId opId) {
        return root.resolve(opId.value());
    }

    private void persistRequest(PkiId opId, SignRequest req) {
        Path dir = opDir(opId);
        try {
            Files.createDirectories(dir);
            String line = req.keyRef().value() + "\n" + req.algorithmId() + "\n"
                    + Base64.getEncoder().encodeToString(req.payload().bytes());
            Files.writeString(dir.resolve(FILE_REQUEST), line, StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new IllegalStateException("Cannot persist request", ex);
        }
    }

    private PersistedSignRequest loadRequest(PkiId opId) {
        Path f = opDir(opId).resolve(FILE_REQUEST);
        try {
            String s = Files.readString(f, StandardCharsets.UTF_8);
            String[] parts = s.split("\n", 3);
            String keyRef = parts[0];
            String alg = parts[1];
            byte[] payload = Base64.getDecoder().decode(parts[2]);
            return new PersistedSignRequest(keyRef, alg, payload);
        } catch (IOException ex) {
            return new PersistedSignRequest("", "", new byte[0]);
        }
    }

    private void persistDeadline(PkiId opId, Instant deadline) {
        try {
            Files.writeString(opDir(opId).resolve(FILE_DEADLINE), Long.toString(deadline.toEpochMilli()),
                    StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new IllegalStateException("Cannot persist deadline", ex);
        }
    }

    private Optional<Instant> loadDeadline(PkiId opId) {
        Path f = opDir(opId).resolve(FILE_DEADLINE);
        if (!Files.exists(f)) {
            return Optional.empty();
        }
        try {
            String s = Files.readString(f, StandardCharsets.UTF_8);
            return Optional.of(Instant.ofEpochMilli(Long.parseLong(s.trim())));
        } catch (IOException ex) {
            return Optional.empty();
        }
    }

    private void persistDecision(PkiId opId, String decision) {
        try {
            Files.writeString(opDir(opId).resolve(FILE_DECISION), decision, StandardCharsets.UTF_8);
        } catch (IOException ex) {
            // best-effort
        }
    }

    private Optional<String> loadDecision(PkiId opId) {
        Path f = opDir(opId).resolve(FILE_DECISION);
        if (!Files.exists(f)) {
            return Optional.empty();
        }
        try {
            String s = Files.readString(f, StandardCharsets.UTF_8);
            String v = s.trim();
            if (v.isEmpty()) {
                return Optional.empty();
            }
            return Optional.of(v);
        } catch (IOException ex) {
            return Optional.empty();
        }
    }

    private void persistSignature(PkiId opId, byte[] signature) {
        try {
            Files.writeString(opDir(opId).resolve(FILE_SIGNATURE), Base64.getEncoder().encodeToString(signature),
                    StandardCharsets.UTF_8);
        } catch (IOException ex) {
            // best-effort
        }
    }

    private Optional<EncodedObject> loadSignature(PkiId opId) {
        Path f = opDir(opId).resolve(FILE_SIGNATURE);
        if (!Files.exists(f)) {
            return Optional.empty();
        }
        try {
            String s = Files.readString(f, StandardCharsets.UTF_8);
            byte[] bytes = Base64.getDecoder().decode(s.trim());
            return Optional.of(new EncodedObject(Encoding.BINARY, bytes));
        } catch (IOException ex) {
            return Optional.empty();
        }
    }

    private void persistStatus(PkiId opId, OperationStatus st) {
        Path f = opDir(opId).resolve(FILE_STATUS);
        String line = st.state().name() + "|" + Long.toString(st.updatedAt().toEpochMilli()) + "|"
                + st.detailCode().orElse("");
        try {
            Files.writeString(f, line, StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new IllegalStateException("Cannot persist status", ex);
        }
    }

    private OperationStatus loadStatus(PkiId opId) {
        Path f = opDir(opId).resolve(FILE_STATUS);
        if (!Files.exists(f)) {
            return new OperationStatus(State.WAITING_APPROVAL, Instant.now(), Optional.of("PENDING_APPROVAL"),
                    Optional.empty());
        }
        try {
            String s = Files.readString(f, StandardCharsets.UTF_8);
            String[] parts = s.split("\\|", 3);
            State st = State.valueOf(parts[0]);
            Instant at = Instant.ofEpochMilli(Long.parseLong(parts[1]));
            Optional<String> dc = parts.length >= 3 && !parts[2].isEmpty() ? Optional.of(parts[2]) : Optional.empty();

            Optional<OperationResult> res = Optional.empty();
            if (st == State.SUCCEEDED) {
                Optional<EncodedObject> sig = loadSignature(opId);
                if (sig.isPresent()) {
                    res = Optional.of(new OperationResult(Optional.of(sig.get()), Optional.empty()));
                }
            }
            return new OperationStatus(st, at, dc, res);
        } catch (Exception ex) {
            return new OperationStatus(State.WAITING_APPROVAL, Instant.now(), Optional.of("CORRUPT"), Optional.empty());
        }
    }

    private static final class PersistedSignRequest {
        private final String keyRef;
        private final String algorithmId;
        private final byte[] payload;

        private PersistedSignRequest(String keyRef, String algorithmId, byte[] payload) {
            this.keyRef = keyRef;
            this.algorithmId = algorithmId;
            this.payload = payload;
        }
    }
}
