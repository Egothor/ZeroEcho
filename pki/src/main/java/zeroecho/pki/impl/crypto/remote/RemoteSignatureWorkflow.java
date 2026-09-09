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
package zeroecho.pki.impl.crypto.remote;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport;

/**
 * Signature workflow that delegates all cryptography to a remote signing service
 * over a {@link RemoteSigningTransport}, keeping private keys entirely on the
 * remote side.
 *
 * <p>
 * This provider is a thin, stateless client of an authoritative remote service:
 * the remote side owns durable idempotency (keyed by
 * {@code submissionId}/{@code semanticFingerprint}/{@code fencingToken}) and is
 * the sole source of truth for whether a signature has occurred. The client
 * therefore never re-submits after an uncertain call — it raises a runtime
 * failure so the orchestration bus reconciles by polling {@link #status}. The
 * remote service may park an operation in {@link State#WAITING_APPROVAL} while an
 * external (typically human) operator approves the signature; the client simply
 * surfaces that state and keeps polling.
 * </p>
 *
 * <h2>Confinement</h2>
 * <p>
 * The PKI orchestration passes only an opaque {@link KeyRef}; this client strips
 * the configured remote prefix to obtain the remote key handle and forwards it.
 * It never sees private key material and returns only signatures and canonical
 * {@code SubjectPublicKeyInfo}.
 * </p>
 */
public final class RemoteSignatureWorkflow implements SignatureWorkflow, PublicKeyInfoSource {

    /** Upper bound on the content one signing request may carry. */
    private static final int MAXIMUM_CONTENT_BYTES = 16 * 1024 * 1024;

    private final String id;
    private final RemoteSigningTransport transport;
    private final String keyRefPrefix;
    private final Duration operationHorizon;
    private final ConfigurationCommitment configurationCommitment;
    private final Set<String> supportedAlgorithms;
    private final ConcurrentMap<PkiId, OperationStatus> localStatuses = new ConcurrentHashMap<>();

    /**
     * Creates a remote signature workflow.
     *
     * @param id provider identity used for namespace binding and audit
     * @param transport open transport to the remote service; must not be {@code null}
     * @param keyRefPrefix required opaque {@link KeyRef} prefix identifying remote keys
     * @param operationHorizon signing operation horizon
     */
    public RemoteSignatureWorkflow(String id, RemoteSigningTransport transport, String keyRefPrefix,
            Duration operationHorizon) {
        this.id = requireText(id, "id");
        this.transport = Objects.requireNonNull(transport, "transport");
        this.keyRefPrefix = requireText(keyRefPrefix, "keyRefPrefix");
        this.operationHorizon = Objects.requireNonNull(operationHorizon, "operationHorizon");
        RemoteSigningTransport.RemoteCapabilities capabilities = transport.capabilities();
        this.configurationCommitment = new ConfigurationCommitment(capabilities.configurationCommitment());
        this.supportedAlgorithms = Set.copyOf(capabilities.supportedAlgorithms());
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public ConfigurationCommitment configurationCommitment() {
        return configurationCommitment;
    }

    @Override
    public Set<String> supportedAlgorithms() {
        return supportedAlgorithms;
    }

    @Override
    public PkiId submitSign(SignRequest request, CallControl control) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        Objects.requireNonNull(control, "control").requireActive(now());
        if (!request.configurationCommitment().matches(configurationCommitment)) {
            throw new IllegalStateException("Signing configuration commitment mismatch");
        }
        if (!request.namespace().endsWith("." + id)) {
            throw new IllegalArgumentException("Signing request namespace mismatch");
        }
        validateSigningDomain(request.namespace(), operationHorizon, Duration.ZERO);

        String keyHandle = remoteKeyHandle(request.keyRef());
        byte[] content = materialize(request);
        RemoteSigningTransport.RemoteSignRequest wire = new RemoteSigningTransport.RemoteSignRequest(
                request.submissionId().value(), request.namespace(), request.semanticFingerprint(),
                request.fencingToken(), keyHandle, request.algorithmId(),
                request.contentCommitment().sha256(), request.contentCommitment().length(), content,
                request.accessContext().principal().type(), request.accessContext().principal().name(),
                request.accessContext().purpose().value(), request.deadline());

        RemoteSigningTransport.RemoteSigningStatus remote = transport.submit(wire, callControl(control));
        String returnedId = remote.operationId();
        if (returnedId == null || !returnedId.equals(request.submissionId().value())) {
            throw new IllegalStateException("Remote signing operation id mismatch");
        }
        return request.submissionId();
    }

    @Override
    public PkiId submitVerify(VerifyRequest request, CallControl control) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        Objects.requireNonNull(control, "control").requireActive(now());
        // This provider is signing-only; verification is a public-key operation handled by a
        // local verifier. The outcome is exposed through status(), not thrown.
        PkiId operationId = new PkiId("remote-verify:" + java.util.UUID.randomUUID());
        localStatuses.put(operationId, new OperationStatus(State.FAILED, now(),
                Optional.of("VERIFY_UNSUPPORTED"), Optional.empty()));
        return operationId;
    }

    @Override
    public OperationStatus status(PkiId operationId, CallControl control) {
        if (operationId == null) {
            throw new IllegalArgumentException("operationId must not be null");
        }
        Objects.requireNonNull(control, "control").requireActive(now());
        OperationStatus local = localStatuses.get(operationId);
        if (local != null) {
            return local;
        }
        RemoteSigningTransport.RemoteSigningStatus remote = transport.status(operationId.value(),
                callControl(control));
        return fromRemote(remote);
    }

    @Override
    public boolean cancel(PkiId operationId, long fencingToken, String reason, CallControl control) {
        if (operationId == null) {
            throw new IllegalArgumentException("operationId must not be null");
        }
        Objects.requireNonNull(reason, "reason");
        if (!isPositive(fencingToken)) {
            throw new IllegalArgumentException("fencingToken must be positive");
        }
        Objects.requireNonNull(control, "control");
        return !localStatuses.containsKey(operationId)
                && transport.cancel(operationId.value(), fencingToken, reason, callControl(control));
    }

    private static boolean isPositive(long value) {
        return value > 0L;
    }

    // The returned registration assumes ownership of the transport callback handle until it is closed.
    @SuppressWarnings("PMD.CloseResource")
    @Override
    public Registration register(NotificationSink sink) {
        Objects.requireNonNull(sink, "sink");
        if (!transport.supportsCallbacks()) {
            // Status polling is authoritative; this remote service does not push notifications.
            return () -> {
                // no-op
            };
        }
        AutoCloseable subscription = transport.subscribe(remote -> {
            try {
                sink.onStatusChanged(new PkiId(remote.operationId()), fromRemote(remote));
            } catch (RuntimeException advisory) { // NOPMD - advisory failures cannot affect durable status.
                // Notifications are advisory; a failure never affects the authoritative status.
            }
        });
        return () -> {
            try {
                subscription.close();
            } catch (Exception ignored) {
                // Unsubscribe is best-effort.
            }
        };
    }

    @Override
    public EncodedObject resolvePublicKeyInfo(KeyRef keyRef) {
        String keyHandle = remoteKeyHandle(Objects.requireNonNull(keyRef, "keyRef"));
        byte[] spki = transport.publicKeyInfo(keyHandle,
                new RemoteSigningTransport.RemoteCallControl(now().plus(operationHorizon), CancellationSignal.NONE));
        return new EncodedObject(Encoding.DER, spki);
    }

    @Override
    public void close() {
        transport.close();
    }

    private OperationStatus fromRemote(RemoteSigningTransport.RemoteSigningStatus remote) {
        return switch (remote.state()) {
            case QUEUED -> new OperationStatus(State.WAITING_APPROVAL, remote.updatedAt(),
                    Optional.of(remote.reason().orElse("QUEUED")), Optional.empty());
            case DENIED -> new OperationStatus(State.FAILED, remote.updatedAt(),
                    Optional.of(remote.reason().orElse("DENIED")), Optional.empty());
            case CANCELLED -> new OperationStatus(State.CANCELLED, remote.updatedAt(),
                    Optional.of(remote.reason().orElse("CANCELLED")), Optional.empty());
            case SIGNED -> signedStatus(remote);
        };
    }

    private OperationStatus signedStatus(RemoteSigningTransport.RemoteSigningStatus remote) {
        Optional<byte[]> signature = remote.signature();
        if (signature.isEmpty() || signature.orElseThrow().length == 0) {
            return new OperationStatus(State.FAILED, remote.updatedAt(),
                    Optional.of("PROVIDER_RESULT_INVALID"), Optional.empty());
        }
        Encoding encoding = signatureEncoding(remote.signatureEncoding());
        OperationResult result = new OperationResult(
                Optional.of(new EncodedObject(encoding, signature.orElseThrow())), Optional.empty());
        return new OperationStatus(State.SUCCEEDED, remote.updatedAt(),
                Optional.of(remote.reason().orElse("SIGNED")), Optional.of(result));
    }

    private static Encoding signatureEncoding(String name) {
        if (name == null || name.isBlank()) {
            return Encoding.BINARY;
        }
        try {
            return Encoding.valueOf(name);
        } catch (IllegalArgumentException unknown) {
            return Encoding.BINARY;
        }
    }

    private String remoteKeyHandle(KeyRef keyRef) {
        String value = keyRef.value();
        if (!value.startsWith(keyRefPrefix)) {
            throw new IllegalArgumentException("Key reference is not a remote key");
        }
        String handle = value.substring(keyRefPrefix.length());
        if (handle.isBlank()) {
            throw new IllegalArgumentException("Remote key handle is empty");
        }
        return handle;
    }

    private static byte[] materialize(SignRequest request) {
        try (InputStream input = request.content().openStream()) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int read;
            long total = 0L;
            while ((read = input.read(chunk)) >= 0) {
                if (read > 0) {
                    total += read;
                    if (total > MAXIMUM_CONTENT_BYTES) {
                        throw new IllegalArgumentException("Signing content exceeds the remote transport limit");
                    }
                    buffer.write(chunk, 0, read);
                }
            }
            return buffer.toByteArray();
        } catch (IOException ex) {
            throw new RemoteSigningTransport.RemoteSigningException("Signing content could not be read", ex);
        }
    }

    private static RemoteSigningTransport.RemoteCallControl callControl(CallControl control) {
        return new RemoteSigningTransport.RemoteCallControl(control.deadline(), control.cancellation());
    }

    private static Instant now() {
        return Instant.now();
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be null/blank");
        }
        return value;
    }
}
