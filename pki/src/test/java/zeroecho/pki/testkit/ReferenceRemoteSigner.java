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
import java.security.Signature;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport.RemoteSigningState;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport.RemoteSigningStatus;

/**
 * Test reference implementation of a remote signing service, exercised in process
 * as a {@link RemoteSigningTransport} and reusable behind an HTTP reference
 * server. It models an authoritative remote signer: per-instance idempotency
 * keyed by {@code submissionId}, optional external (human) approval before
 * signing, best-effort push callbacks, and fenced cancellation — while never
 * returning private key material. Deadline expiry is deliberately left to the
 * caller's orchestration, so this service reports only {@code QUEUED},
 * {@code SIGNED}, {@code DENIED}, and {@code CANCELLED}.
 */
public final class ReferenceRemoteSigner implements RemoteSigningTransport {

    private final Map<String, KeyPair> keys;
    private final boolean requireApproval;
    private final byte[] configurationCommitment;
    private final Map<String, RemoteSigningStatus> statuses = new HashMap<>();
    private final Map<String, String> fingerprints = new HashMap<>();
    private final Map<String, Long> fences = new HashMap<>();
    private final Map<String, RemoteSignRequest> pendingApproval = new HashMap<>();
    private final List<RemoteSigningCallback> callbacks = new CopyOnWriteArrayList<>();

    /**
     * Creates the reference signer.
     *
     * @param keys map of remote key handle to JCA key pair
     * @param requireApproval when {@code true}, submissions park in
     *                        {@link RemoteSigningState#QUEUED} until {@link #approve}
     */
    public ReferenceRemoteSigner(Map<String, KeyPair> keys, boolean requireApproval) {
        this.keys = new HashMap<>(Objects.requireNonNull(keys, "keys"));
        this.requireApproval = requireApproval;
        this.configurationCommitment = new byte[32];
        for (int index = 0; index < configurationCommitment.length; index++) {
            configurationCommitment[index] = (byte) (0x40 + index);
        }
    }

    @Override
    public synchronized RemoteSigningStatus submit(RemoteSignRequest request, RemoteCallControl control) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(control, "control");
        String operationId = request.submissionId();
        String existing = fingerprints.get(operationId);
        if (existing != null) {
            if (!existing.equals(request.semanticFingerprint())) {
                throw new IllegalStateException("Remote signing request conflicts with a prior submission");
            }
            if (request.fencingToken() < fences.get(operationId)) {
                throw new IllegalStateException("Stale remote signing fencing token");
            }
            return statuses.get(operationId);
        }
        fingerprints.put(operationId, request.semanticFingerprint());
        fences.put(operationId, request.fencingToken());
        if (requireApproval) {
            RemoteSigningStatus queued = new RemoteSigningStatus(operationId, RemoteSigningState.QUEUED,
                    Instant.now(), Optional.of("awaiting-operator-approval"), Optional.empty(), "");
            pendingApproval.put(operationId, request);
            return store(operationId, queued);
        }
        return sign(operationId, request);
    }

    @Override
    public synchronized RemoteSigningStatus status(String operationId, RemoteCallControl control) {
        Objects.requireNonNull(operationId, "operationId");
        RemoteSigningStatus current = statuses.get(operationId);
        if (current == null) {
            return new RemoteSigningStatus(operationId, RemoteSigningState.DENIED, Instant.now(),
                    Optional.of("unknown-operation"), Optional.empty(), "");
        }
        return current;
    }

    @Override
    public synchronized boolean cancel(String operationId, long fencingToken, String reason,
            RemoteCallControl control) {
        Objects.requireNonNull(operationId, "operationId");
        RemoteSigningStatus current = statuses.get(operationId);
        if (current == null) {
            return false;
        }
        long currentFence = fences.getOrDefault(operationId, 0L);
        if (current.state().isTerminal()) {
            return current.state() == RemoteSigningState.CANCELLED && fencingToken == currentFence;
        }
        if (fencingToken < currentFence) {
            return false;
        }
        fences.put(operationId, fencingToken);
        pendingApproval.remove(operationId);
        store(operationId, new RemoteSigningStatus(operationId, RemoteSigningState.CANCELLED, Instant.now(),
                Optional.of("cancelled-by-caller"), Optional.empty(), ""));
        return true;
    }

    @Override
    public synchronized byte[] publicKeyInfo(String keyHandle, RemoteCallControl control) {
        KeyPair keyPair = keys.get(Objects.requireNonNull(keyHandle, "keyHandle"));
        if (keyPair == null) {
            throw new IllegalArgumentException("Unknown remote key handle");
        }
        return keyPair.getPublic().getEncoded();
    }

    @Override
    public synchronized RemoteCapabilities capabilities() {
        return new RemoteCapabilities(Set.of("SHA256withRSA", "SHA384withRSA", "SHA512withRSA"),
                configurationCommitment.clone());
    }

    @Override
    public boolean supportsCallbacks() {
        return true;
    }

    @Override
    public AutoCloseable subscribe(RemoteSigningCallback callback) {
        Objects.requireNonNull(callback, "callback");
        callbacks.add(callback);
        return () -> callbacks.remove(callback);
    }

    /** Approves a pending operation, driving it to a terminal signature. */
    public synchronized RemoteSigningStatus approve(String operationId) {
        RemoteSignRequest request = pendingApproval.remove(operationId);
        if (request == null) {
            throw new IllegalStateException("No pending approval for operation");
        }
        return sign(operationId, request);
    }

    /** Denies a pending operation with a non-secret justification. */
    public synchronized RemoteSigningStatus deny(String operationId, String reason) {
        pendingApproval.remove(operationId);
        return store(operationId, new RemoteSigningStatus(operationId, RemoteSigningState.DENIED, Instant.now(),
                Optional.of(reason), Optional.empty(), ""));
    }

    @Override
    public void close() {
        callbacks.clear();
    }

    private RemoteSigningStatus sign(String operationId, RemoteSignRequest request) {
        KeyPair keyPair = keys.get(request.keyHandle());
        if (keyPair == null) {
            return store(operationId, new RemoteSigningStatus(operationId, RemoteSigningState.DENIED, Instant.now(),
                    Optional.of("unknown-key"), Optional.empty(), ""));
        }
        try {
            Signature signature = Signature.getInstance(InMemorySignatureWorkflow.jcaName(request.algorithmId()));
            signature.initSign(keyPair.getPrivate());
            signature.update(request.content());
            byte[] produced = signature.sign();
            return store(operationId, new RemoteSigningStatus(operationId, RemoteSigningState.SIGNED, Instant.now(),
                    Optional.of("signed"), Optional.of(produced), "BINARY"));
        } catch (Exception failure) {
            return store(operationId, new RemoteSigningStatus(operationId, RemoteSigningState.DENIED, Instant.now(),
                    Optional.of("signing-failed"), Optional.empty(), ""));
        }
    }

    private RemoteSigningStatus store(String operationId, RemoteSigningStatus status) {
        statuses.put(operationId, status);
        for (RemoteSigningCallback callback : callbacks) {
            try {
                callback.onStatus(status);
            } catch (RuntimeException ignored) {
                // Callbacks are best-effort.
            }
        }
        return status;
    }
}
