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
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningInputCapabilities;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport;

/** Stateless signing provider backed by an externally idempotent remote service. */
public final class RemoteSigningProvider implements SigningProvider, PublicKeyInfoSource {
    private static final long NO_FENCE = 0L;

    private final String id;
    private final RemoteSigningTransport transport;
    private final String keyRefPrefix;
    private final Duration operationHorizon;
    private final ConfigurationCommitment configurationCommitment;
    private final Set<String> supportedAlgorithms;
    private final SigningInputCapabilities inputCapabilities;
    private final ReentrantLock domainLock = new ReentrantLock();
    private String boundNamespace;

    /**
     * Creates one remote signing-provider client.
     *
     * @param id stable provider identifier
     * @param transport externally idempotent transport
     * @param keyRefPrefix required opaque-key prefix
     * @param operationHorizon authoritative operation identity horizon
     */
    public RemoteSigningProvider(String id, RemoteSigningTransport transport, String keyRefPrefix,
            Duration operationHorizon) {
        this.id = requireText(id, "id");
        this.transport = Objects.requireNonNull(transport, "transport");
        this.keyRefPrefix = requireText(keyRefPrefix, "keyRefPrefix");
        this.operationHorizon = Objects.requireNonNull(operationHorizon, "operationHorizon");
        RemoteSigningTransport.RemoteCapabilities capabilities = transport.capabilities();
        inputCapabilities = capabilities.effectiveInputs();
        configurationCommitment = capabilities.effectiveCommitment();
        supportedAlgorithms = Set.copyOf(capabilities.supportedAlgorithms());
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
    public SigningInputCapabilities inputCapabilities() {
        return inputCapabilities;
    }

    @Override
    public void validateSigningDomain(String namespace, Duration horizon, Duration permittedSkew) {
        if (namespace == null || !namespace.endsWith("." + id) || !operationHorizon.equals(horizon)
                || !Duration.ZERO.equals(permittedSkew)) {
            throw new IllegalArgumentException("Remote signing domain mismatch");
        }
        domainLock.lock();
        try {
            if (boundNamespace != null && !boundNamespace.equals(namespace)) {
                throw new IllegalArgumentException("Remote provider belongs to a different signing domain");
            }
            boundNamespace = namespace;
        } finally {
            domainLock.unlock();
        }
    }

    @Override
    public OperationObservation dispatch(SignRequest request, CallControl control) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(control, "control").requireActive(now());
        requireExactDomain(request.namespace());
        if (!configurationCommitment.matches(request.configurationCommitment())) {
            throw new IllegalArgumentException("Signing provider configuration commitment mismatch");
        }
        SigningInputCapabilities.Mode mode = inputCapabilities.select(request.algorithmId(),
                request.contentCommitment().length());
        AlgorithmIdentity digestIdentity = inputCapabilities.prehashedDigests().get(request.algorithmId());
        byte[] content = materializeAndVerify(request, control, digestIdentity);
        try {
            RemoteSigningTransport.RemoteSignRequest wire = new RemoteSigningTransport.RemoteSignRequest(
                    request.operationId().value(), request.namespace(), request.semanticFingerprint(),
                    request.fencingToken(), remoteKeyHandle(request.keyRef()), request.algorithmId(),
                    request.contentCommitment().sha256(), request.contentCommitment().length(), content,
                    request.accessContext().principal().type(), request.accessContext().principal().name(),
                    request.accessContext().purpose().value(), request.deadline(),
                    SigningInputCapabilities.PROTOCOL_VERSION, mode,
                    digestIdentity == null ? "" : digestIdentity.canonicalForm(), configurationCommitment);
            requireActive(request, control);
            RemoteSigningTransport.RemoteSigningStatus status;
            try {
                status = transport.submit(wire, callControl(control));
            } catch (RemoteSigningTransport.RemoteSigningException uncertainty) {
                return retryableUnknown(request.operationId());
            }
            return fromRemote(request.operationId(), status);
        } finally {
            Arrays.fill(content, (byte) 0);
        }
    }

    @Override
    public OperationObservation reconcile(PkiId operationId, CallControl control) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(control, "control").requireActive(now());
        try {
            return fromRemote(operationId, transport.status(operationId.value(), callControl(control)));
        } catch (RemoteSigningTransport.RemoteSigningException uncertainty) {
            return retryableUnknown(operationId);
        }
    }

    @Override
    public OperationObservation cancel(PkiId operationId, long fencingToken, CancellationReason reason,
            CallControl control) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(control, "control").requireActive(now());
        if (fencingToken <= NO_FENCE) {
            throw new IllegalArgumentException("fencingToken must be positive");
        }
        try {
            RemoteSigningTransport.RemoteSigningStatus status = transport.cancel(operationId.value(), fencingToken,
                    reason.name(), callControl(control));
            return fromRemote(operationId, status);
        } catch (RemoteSigningTransport.RemoteSigningException uncertainty) {
            return retryableUnknown(operationId);
        }
    }

    @Override
    public EncodedObject resolvePublicKeyInfo(KeyRef keyRef) {
        byte[] bytes = transport.publicKeyInfo(remoteKeyHandle(Objects.requireNonNull(keyRef, "keyRef")),
                new RemoteSigningTransport.RemoteCallControl(now().plus(operationHorizon), CancellationSignal.NONE));
        return new EncodedObject(Encoding.DER, bytes);
    }

    @Override
    public void close() {
        transport.close();
    }

    private OperationObservation fromRemote(PkiId requestedId,
            RemoteSigningTransport.RemoteSigningStatus remote) {
        Objects.requireNonNull(remote, "remote");
        if (!requestedId.value().equals(remote.operationId())) {
            throw new IllegalStateException("Remote signing operation id mismatch");
        }
        Objects.requireNonNull(remote.updatedAt(), "remote updatedAt");
        return switch (remote.state()) {
            case QUEUED -> observation(requestedId, ObservationState.PENDING, remote.updatedAt(),
                    DetailCode.PENDING);
            case UNKNOWN -> observation(requestedId, ObservationState.RETRYABLE_UNKNOWN, remote.updatedAt(),
                    DetailCode.RETRYABLE_UNKNOWN);
            case UNRECOVERABLE -> observation(requestedId, ObservationState.UNRECOVERABLE, remote.updatedAt(),
                    DetailCode.PROVIDER_RESULT_INVALID);
            case DENIED -> observation(requestedId, ObservationState.FAILED, remote.updatedAt(), DetailCode.DENIED);
            case CANCELLED -> observation(requestedId, ObservationState.CANCELLED, remote.updatedAt(),
                    DetailCode.CANCELLED);
            case SIGNED -> signed(requestedId, remote);
        };
    }

    private static OperationObservation observation(PkiId id, ObservationState state, Instant updatedAt,
            DetailCode code) {
        return new OperationObservation(id, state, updatedAt, code, Optional.empty());
    }

    private static OperationObservation retryableUnknown(PkiId operationId) {
        return observation(operationId, ObservationState.RETRYABLE_UNKNOWN, now(),
                DetailCode.RETRYABLE_UNKNOWN);
    }

    private static OperationObservation signed(PkiId id, RemoteSigningTransport.RemoteSigningStatus remote) {
        Optional<byte[]> signature = remote.signature();
        if (signature.isEmpty() || signature.orElseThrow().length == 0
                || signature.orElseThrow().length > OperationObservation.MAXIMUM_SIGNATURE_BYTES) {
            return observation(id, ObservationState.UNRECOVERABLE, remote.updatedAt(),
                    DetailCode.PROVIDER_RESULT_INVALID);
        }
        Encoding encoding;
        try {
            encoding = Encoding.valueOf(remote.signatureEncoding());
        } catch (IllegalArgumentException | NullPointerException invalid) {
            return observation(id, ObservationState.UNRECOVERABLE, remote.updatedAt(),
                    DetailCode.PROVIDER_RESULT_INVALID);
        }
        return new OperationObservation(id, ObservationState.SUCCEEDED, remote.updatedAt(), DetailCode.SIGNED,
                Optional.of(new EncodedObject(encoding, signature.orElseThrow())));
    }

    private void requireExactDomain(String namespace) {
        domainLock.lock();
        try {
            if (boundNamespace == null || !boundNamespace.equals(namespace)) {
                throw new IllegalArgumentException("Signing request namespace mismatch");
            }
        } finally {
            domainLock.unlock();
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

    private byte[] materializeAndVerify(SignRequest request, CallControl control, AlgorithmIdentity digestIdentity) {
        MessageDigest digest = SigningInputCapabilities.newDigest(BootstrapAlgorithmIdentities.SHA256);
        MessageDigest algorithmDigest = digestIdentity == null ? null
                : SigningInputCapabilities.newDigest(digestIdentity);
        requireActive(request, control);
        try (InputStream input = request.content().openStream();
                ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] chunk = new byte[8192];
            long total = 0L;
            int read;
            while ((read = input.read(chunk)) >= 0) {
                requireActive(request, control);
                if (read > 0) {
                    total = Math.addExact(total, read);
                    if ((algorithmDigest == null && total > inputCapabilities.rawMessageMaximum())
                            || total > request.contentCommitment().length()) {
                        throw new IllegalArgumentException("Signing content exceeds its finite bound");
                    }
                    digest.update(chunk, 0, read);
                    if (algorithmDigest == null) {
                        output.write(chunk, 0, read);
                    } else {
                        algorithmDigest.update(chunk, 0, read);
                    }
                }
            }
            byte[] actual = digest.digest();
            byte[] expected = HexFormat.of().parseHex(request.contentCommitment().sha256());
            try {
                if (total != request.contentCommitment().length() || !MessageDigest.isEqual(actual, expected)) {
                    throw new IllegalArgumentException("Signing content commitment mismatch");
                }
            } finally {
                Arrays.fill(actual, (byte) 0);
                Arrays.fill(expected, (byte) 0);
                Arrays.fill(chunk, (byte) 0);
            }
            requireActive(request, control);
            return algorithmDigest == null ? output.toByteArray() : algorithmDigest.digest();
        } catch (IOException failure) {
            throw new RemoteSigningTransport.RemoteSigningException("Signing content could not be read", failure);
        }
    }

    private static void requireActive(SignRequest request, CallControl control) {
        Instant current = now();
        control.requireActive(current);
        if (request.cancellation().isCancelled()
                || request.deadline().filter(value -> !current.isBefore(value)).isPresent()) {
            throw new IllegalStateException("Signing request is no longer active");
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
