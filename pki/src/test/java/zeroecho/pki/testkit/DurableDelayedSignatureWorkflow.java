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
 * Durable test signer that introduces an artificial delay before completing the
 * signature.
 *
 * <p>
 * This is a test harness implementation used to demonstrate asynchronous
 * orchestration. It persists state in a directory so tests can simulate
 * restarts.
 * </p>
 */
public final class DurableDelayedSignatureWorkflow implements SignatureWorkflow, AutoCloseable {

    private static final String PROVIDER_ID = "testkit-delayed";

    private static final String FILE_STATUS = "status";
    private static final String FILE_REQUEST = "request";
    private static final String FILE_SIGNATURE = "signature";

    private final Path root;
    private final TestSignIdentityRegistry identities;
    private final Duration signingDelay;
    private final Map<String, PrivateKey> keysByRef;
    private final Map<PkiId, NotificationSink> sinks;

    public DurableDelayedSignatureWorkflow(Path root, Duration signingDelay, Map<String, PrivateKey> keysByRef) {
        this.root = Objects.requireNonNull(root, "root");
        this.identities = new TestSignIdentityRegistry(root);
        this.signingDelay = Objects.requireNonNull(signingDelay, "signingDelay");
        this.keysByRef = Objects.requireNonNull(keysByRef, "keysByRef");
        this.sinks = new ConcurrentHashMap<PkiId, NotificationSink>();

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
    public ConfigurationCommitment configurationCommitment() {
        return new ConfigurationCommitment(new byte[ConfigurationCommitment.BYTE_LENGTH]);
    }

    @Override
    public PkiId submitSign(SignRequest request, CallControl control) {
        Objects.requireNonNull(request, "request");

        PkiId opId = request.submissionId();
        if (!identities.begin(request)) {
            return opId;
        }
        Instant now = Instant.now();

        persistRequest(opId, request);

        // There is no State.SUBMITTED in the SPI; use PENDING with detailCode.
        OperationStatus init = new OperationStatus(State.PENDING, now, Optional.of("SUBMITTED"), Optional.empty());
        persistStatus(opId, init);
        notifySink(opId, init);

        // Make progress immediately (still async vs bus submitter because orchestration
        // is driven via polling).
        // Actual "delay" is applied in status() -> performSign().
        return opId;
    }

    @Override
    public PkiId submitVerify(VerifyRequest request, CallControl control) {
        Objects.requireNonNull(request, "request");
        return new PkiId("verify-" + UUID.randomUUID());
    }

    @Override
    public OperationStatus status(PkiId operationId, CallControl control) {
        Objects.requireNonNull(operationId, "operationId");
        OperationStatus st = loadStatus(operationId);
        if (st.isTerminal()) {
            return st;
        }

        if (st.state() == State.PENDING) {
            PersistedSignRequest request = loadRequest(operationId);
            Instant startedAt = Instant.now();
            if (deadlineReached(request.deadline, startedAt)) {
                OperationStatus expired = expired(startedAt);
                persistStatus(operationId, expired);
                notifySink(operationId, expired);
                return expired;
            }
            OperationStatus running = new OperationStatus(State.RUNNING, startedAt, Optional.of("SIGNING"),
                    Optional.empty());
            persistStatus(operationId, running);
            notifySink(operationId, running);

            OperationStatus terminal = performSign(operationId);
            persistStatus(operationId, terminal);
            notifySink(operationId, terminal);
            return terminal;
        }

        if (st.state() == State.RUNNING) {
            // Best-effort: complete if signature file exists.
            Optional<EncodedObject> sig = loadSignature(operationId);
            if (sig.isPresent()) {
                OperationStatus expired = expired(Instant.now());
                persistStatus(operationId, expired);
                notifySink(operationId, expired);
                return expired;
            }
        }

        return st;
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
        OperationStatus st = status(operationId, control);
        if (st.isTerminal()) {
            return st.state() == State.CANCELLED
                    && identities.fence(operationId).orElse(-1L) == fencingToken;
        }
        if (!identities.acceptFence(operationId, fencingToken)) {
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
    public Set<String> supportedAlgorithms() {
        return Set.of("SHA256withRSA");
    }

    @Override
    public void close() {
        sinks.clear();
    }

    private OperationStatus performSign(PkiId opId) {
        PersistedSignRequest req = loadRequest(opId);
        Instant startedAt = Instant.now();
        if (deadlineReached(req.deadline, startedAt)) {
            return expired(startedAt);
        }
        PrivateKey key = keysByRef.get(req.keyRef);
        if (key == null) {
            return new OperationStatus(State.FAILED, Instant.now(), Optional.of("UNKNOWN_KEY"), Optional.empty());
        }
        String jcaAlgorithm = InMemorySignatureWorkflow.jcaName(req.algorithmId);
        if (!supportedAlgorithms().contains(jcaAlgorithm)) {
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
            Signature sig = Signature.getInstance(jcaAlgorithm);
            sig.initSign(key);
            sig.update(req.payload);
            byte[] signature = sig.sign();

            Instant completedAt = Instant.now();
            if (deadlineReached(req.deadline, completedAt)) {
                return expired(completedAt);
            }
            persistSignature(opId, signature);

            EncodedObject enc = new EncodedObject(Encoding.BINARY, signature);
            OperationResult res = new OperationResult(Optional.of(enc), Optional.empty());
            return new OperationStatus(State.SUCCEEDED, completedAt, Optional.of("SIGNED"), Optional.of(res));
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
                    + Base64.getEncoder().encodeToString(readContent(req.content())) + "\n"
                    + req.deadline().map(Instant::toString).orElse("");
            Files.writeString(dir.resolve(FILE_REQUEST), line, StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new IllegalStateException("Cannot persist request", ex);
        }
    }

    private static byte[] readContent(zeroecho.core.io.RepeatableContent content) throws IOException {
        try (java.io.InputStream input = content.openStream()) {
            return input.readAllBytes();
        }
    }

    private PersistedSignRequest loadRequest(PkiId opId) {
        Path f = opDir(opId).resolve(FILE_REQUEST);
        try {
            String s = Files.readString(f, StandardCharsets.UTF_8);
            String[] parts = s.split("\n", 4);
            String keyRef = parts[0];
            String alg = parts[1];
            byte[] payload = Base64.getDecoder().decode(parts[2]);
            Optional<Instant> deadline = parts.length == 4 && !parts[3].isBlank() ? Optional.of(Instant.parse(parts[3]))
                    : Optional.empty();
            return new PersistedSignRequest(keyRef, alg, payload, deadline);
        } catch (IOException ex) {
            return new PersistedSignRequest("", "", new byte[0], Optional.empty());
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
            return new OperationStatus(State.PENDING, Instant.now(), Optional.of("SUBMITTED"), Optional.empty());
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
            return new OperationStatus(State.PENDING, Instant.now(), Optional.of("CORRUPT"), Optional.empty());
        }
    }

    private static final class PersistedSignRequest {
        private final String keyRef;
        private final String algorithmId;
        private final byte[] payload;
        private final Optional<Instant> deadline;

        private PersistedSignRequest(String keyRef, String algorithmId, byte[] payload, Optional<Instant> deadline) {
            this.keyRef = keyRef;
            this.algorithmId = algorithmId;
            this.payload = payload;
            this.deadline = deadline;
        }
    }

    private static boolean deadlineReached(Optional<Instant> deadline, Instant observedAt) {
        return deadline.isPresent() && !observedAt.isBefore(deadline.get());
    }

    private static OperationStatus expired(Instant observedAt) {
        return new OperationStatus(State.EXPIRED, observedAt, Optional.of("EXPIRED"), Optional.empty());
    }
}
