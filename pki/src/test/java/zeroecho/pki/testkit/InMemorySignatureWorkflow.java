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

import java.security.KeyPair;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.pki.spi.crypto.SignatureWorkflow;

/**
 * Test-only in-memory signature workflow.
 */
public final class InMemorySignatureWorkflow implements SignatureWorkflow, PublicKeyInfoSource {

    private final Map<String, KeyPair> keys;
    private final Map<PkiId, OperationStatus> status;
    private final boolean completeImmediately;
    private final String id;
    private final ConcurrentMap<PkiId, String> fingerprints;
    private final ConcurrentMap<PkiId, Long> fences;
    private final ConcurrentMap<PkiId, Object> operationLocks;
    private long counter;
    private final AtomicInteger submittedSignCount;

    public InMemorySignatureWorkflow(Map<String, KeyPair> keys) {
        this(keys, true);
    }

    public InMemorySignatureWorkflow(Map<String, KeyPair> keys, boolean completeImmediately) {
        this("test-signer", keys, completeImmediately);
    }

    /**
     * Creates a workflow with an explicit stable identity, used where several
     * distinct in-memory services must coexist (per-CA routing tests).
     *
     * @param id stable service identity
     * @param keys signing key pairs indexed by key-reference value
     * @param completeImmediately whether submissions complete synchronously
     */
    public InMemorySignatureWorkflow(String id, Map<String, KeyPair> keys, boolean completeImmediately) {
        this.id = Objects.requireNonNull(id, "id");
        this.keys = new HashMap<>(Objects.requireNonNull(keys, "keys"));
        this.status = new HashMap<>();
        this.completeImmediately = completeImmediately;
        this.fingerprints = new ConcurrentHashMap<>();
        this.fences = new ConcurrentHashMap<>();
        this.operationLocks = new ConcurrentHashMap<>();
        this.submittedSignCount = new AtomicInteger();
        this.counter = 1L;
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
        PkiId opId = request.submissionId();
        Object lock = operationLocks.computeIfAbsent(opId, ignored -> new Object());
        synchronized (lock) { // test provider operation-local state only; no external call inside
            String fingerprint = fingerprints.get(opId);
            if (fingerprint != null) {
                if (!fingerprint.equals(request.semanticFingerprint())) {
                    throw new IllegalStateException("conflicting signing request");
                }
                if (request.fencingToken() < fences.get(opId)) {
                    throw new IllegalStateException("stale signing fence");
                }
                return opId;
            }
            fingerprints.put(opId, request.semanticFingerprint());
            fences.put(opId, request.fencingToken());
            status.put(opId,
                    new OperationStatus(State.RUNNING, Instant.now(), Optional.of("PENDING"), Optional.empty()));
            submittedSignCount.incrementAndGet();
        }
        if (!completeImmediately) {
            return opId;
        }

        try {
            if (deadlineReached(request, Instant.now())) {
                complete(request, expired(Instant.now()));
                return opId;
            }
            KeyPair kp = keys.get(request.keyRef().value());
            if (kp == null) {
                OperationStatus st = new OperationStatus(State.FAILED, Instant.now(), Optional.of("UNKNOWN_KEY"),
                        Optional.empty());
                complete(request, st);
                return opId;
            }

            java.security.Signature sig = java.security.Signature.getInstance(jcaName(request.algorithmId()));
            sig.initSign(kp.getPrivate());
            try (java.io.InputStream input = request.content().openStream()) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    if (read != 0) {
                        sig.update(buffer, 0, read);
                    }
                }
            }
            byte[] s = sig.sign();

            Instant completedAt = Instant.now();
            if (deadlineReached(request, completedAt)) {
                complete(request, expired(completedAt));
                return opId;
            }
            OperationResult res = new OperationResult(Optional.of(new EncodedObject(Encoding.BINARY, s)),
                    Optional.empty());
            OperationStatus st = new OperationStatus(State.SUCCEEDED, completedAt, Optional.of("SIGNED"),
                    Optional.of(res));
            complete(request, st);
            return opId;
        } catch (Exception ex) {
            OperationStatus st = new OperationStatus(State.FAILED, Instant.now(), Optional.of("SIGN_FAILED"),
                    Optional.empty());
            complete(request, st);
            return opId;
        }
    }

    static String jcaName(String identityOrAlias) {
        return zeroecho.core.alg.BootstrapAlgorithmIdentities.resolve(identityOrAlias)
                .map(identity -> {
                    if (identity.equals(zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256)) {
                        return "SHA256withRSA";
                    }
                    if (identity.equals(zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384)) {
                        return "SHA384withRSA";
                    }
                    if (identity.equals(zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA512)) {
                        return "SHA512withRSA";
                    }
                    throw new IllegalArgumentException("Unsupported test signature identity");
                }).orElse(identityOrAlias);
    }

    private void complete(SignRequest request, OperationStatus terminal) {
        Object lock = operationLocks.get(request.submissionId());
        synchronized (lock) {
            if (status.get(request.submissionId()).state() == State.RUNNING
                    && fences.get(request.submissionId()) == request.fencingToken()) {
                if (terminal.state() == State.SUCCEEDED && deadlineReached(request, terminal.updatedAt())) {
                    terminal = expired(terminal.updatedAt());
                }
                status.put(request.submissionId(), terminal);
            }
        }
    }

    private static boolean deadlineReached(SignRequest request, Instant observedAt) {
        return request.deadline().isPresent() && !observedAt.isBefore(request.deadline().get());
    }

    private static OperationStatus expired(Instant observedAt) {
        return new OperationStatus(State.EXPIRED, observedAt, Optional.of("EXPIRED"), Optional.empty());
    }

    @Override
    public PkiId submitVerify(VerifyRequest request, CallControl control) {
        Objects.requireNonNull(request, "request");
        PkiId opId = new PkiId("verify:" + (counter++));
        OperationStatus st = new OperationStatus(State.FAILED, Instant.now(), Optional.of("UNSUPPORTED"),
                Optional.empty());
        status.put(opId, st);
        return opId;
    }

    @Override
    public OperationStatus status(PkiId operationId, CallControl control) {
        Objects.requireNonNull(operationId, "operationId");
        OperationStatus st = status.get(operationId);
        if (st == null) {
            return new OperationStatus(State.FAILED, Instant.now(), Optional.of("UNKNOWN_OP"), Optional.empty());
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
        Object lock = operationLocks.computeIfAbsent(operationId, ignored -> new Object());
        synchronized (lock) {
            OperationStatus existing = status.get(operationId);
            if (existing == null) {
                return false;
            }
            long currentFence = fences.get(operationId);
            if (existing.isTerminal()) {
                return existing.state() == State.CANCELLED && fencingToken == currentFence;
            }
            if (fencingToken < currentFence) {
                return false;
            }
            fences.put(operationId, fencingToken);
            status.put(operationId,
                    new OperationStatus(State.CANCELLED, Instant.now(), Optional.of("CANCELLED"), Optional.empty()));
            return true;
        }
    }

    @Override
    public Registration register(NotificationSink sink) {
        Objects.requireNonNull(sink, "sink");
        return () -> {
            // no-op
        };
    }

    @Override
    public Set<String> supportedAlgorithms() {
        return Set.of("SHA256withRSA");
    }

    @Override
    public EncodedObject resolvePublicKeyInfo(KeyRef keyRef) {
        KeyPair keyPair = keys.get(Objects.requireNonNull(keyRef, "keyRef").value());
        if (keyPair == null) {
            throw new IllegalArgumentException("Managed test key is unavailable");
        }
        return new EncodedObject(Encoding.DER, keyPair.getPublic().getEncoded());
    }

    public int submittedSignCount() {
        return submittedSignCount.get();
    }

    public void putKeyPair(KeyRef keyRef, KeyPair keyPair) {
        keys.put(Objects.requireNonNull(keyRef, "keyRef").value(), Objects.requireNonNull(keyPair, "keyPair"));
    }

    public boolean hasRunningOperations() {
        return status.values().stream().anyMatch(operation -> !operation.isTerminal());
    }

    @Override
    public void close() {
        // no-op
    }
}
