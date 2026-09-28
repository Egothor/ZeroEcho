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
package zeroecho.pki.spi.crypto.remote;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.List;
import java.util.HexFormat;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.spi.crypto.SigningInputCapabilities;
import zeroecho.pki.spi.crypto.SigningProvider;

import zeroecho.core.io.CancellationSignal;

/**
 * Technology-neutral wire seam between the PKI's remote signing provider
 * provider and a remote signing service.
 *
 * <p>
 * The remote signing service is attached to this PKI by a unique identifier that
 * specifies where it is remotely reachable, and may be implemented by any
 * technology — including one that gates each signature behind an external,
 * typically human, operator approval. This interface is the only contract that
 * implementation must speak; a concrete transport (for example authenticated
 * HTTPS) maps these calls onto the wire, so the remote side stays fully
 * pluggable.
 * </p>
 *
 * <h2>Confinement</h2>
 * <p>
 * A transport carries only an opaque {@code keyHandle}, the algorithm identity,
 * the exact bytes to sign, and the resulting signature or a canonical
 * {@code SubjectPublicKeyInfo}. It never transports, and the remote service must
 * never return, private key material.
 * </p>
 *
 * <h2>Remote state model</h2>
 * <p>
 * The remote service reports a small, technology-neutral vocabulary
 * ({@link RemoteSigningState}): {@code QUEUED} while the request is accepted and
 * awaiting the service's decision (including an external, typically human,
 * operator approval), {@code SIGNED} once a signature is produced, {@code DENIED}
 * if the signature is refused, and {@code CANCELLED} if the caller's cancellation
 * was honoured. A wire response may carry an untrusted raw reason; the
 * transport must discard it and expose no such field in
 * {@link RemoteSigningStatus}. Deadline expiry is an orchestration-side overlay,
 * not a remote state.
 * </p>
 *
 * <h2>Outcome semantics</h2>
 * <ul>
 * <li>{@link #submit} and {@link #status} return the remote operation's current
 * {@link RemoteSigningStatus}; the remote service is the authority on whether a
 * signature has occurred and must be idempotent on
 * {@code (submissionId, semanticFingerprint, fencingToken)}.</li>
 * <li>Any delivery uncertainty (timeout, connection reset, ambiguous response)
 * must be raised as a {@link RemoteSigningException}. The caller never re-submits
 * blindly; it reconciles by polling {@link #status}.</li>
 * <li>A remote service may optionally push status changes: when
 * {@link #supportsCallbacks()} is {@code true}, {@link #subscribe} delivers them;
 * otherwise the provider relies solely on {@link #status} polling.</li>
 * </ul>
 */
public interface RemoteSigningTransport extends AutoCloseable {

    /**
     * Submits one signing request to the remote service.
     *
     * @param request signing request; must not be {@code null}
     * @param control per-call deadline and cancellation; must not be {@code null}
     * @return the remote operation's current status, echoing the submission id
     * @throws RemoteSigningException if the outcome is uncertain (never re-submitted)
     */
    RemoteSigningStatus submit(RemoteSignRequest request, RemoteCallControl control);

    /**
     * Reads the authoritative current status of one remote operation.
     *
     * @param operationId remote operation id (equal to the submission id)
     * @param control per-call deadline and cancellation
     * @return the remote operation's current status
     * @throws RemoteSigningException if the status is unavailable
     */
    RemoteSigningStatus status(String operationId, RemoteCallControl control);

    /**
     * Requests cancellation of one remote operation.
     *
     * @param operationId remote operation id
     * @param fencingToken monotonic fencing token
     * @param reason non-secret cancellation reason
     * @param control per-call deadline and cancellation
     * @return the remote operation's current status, echoing the operation id
     * @throws RemoteSigningException if the cancellation outcome is uncertain
     */
    RemoteSigningStatus cancel(String operationId, long fencingToken, String reason, RemoteCallControl control);

    /**
     * Resolves the canonical DER {@code SubjectPublicKeyInfo} for a key handle.
     *
     * @param keyHandle opaque remote key handle
     * @param control per-call deadline and cancellation
     * @return DER-encoded {@code SubjectPublicKeyInfo}
     * @throws RemoteSigningException if the public key info is unavailable
     */
    byte[] publicKeyInfo(String keyHandle, RemoteCallControl control);

    /**
     * Returns the remote service's advertised capabilities, captured when the
     * transport was opened.
     *
     * @return supported algorithm identities and the remote configuration commitment
     */
    RemoteCapabilities capabilities();

    /**
     * Indicates whether the remote service pushes status changes to subscribers.
     *
     * @return {@code true} if {@link #subscribe} is supported; {@code false} means
     *         the provider relies solely on {@link #status} polling
     */
    default boolean supportsCallbacks() {
        return false;
    }

    /**
     * Subscribes to best-effort remote status-change notifications.
     *
     * @param callback status-change callback; invoked best-effort and must not throw
     * @return a handle that unsubscribes when closed
     * @throws UnsupportedOperationException if {@link #supportsCallbacks()} is {@code false}
     */
    default AutoCloseable subscribe(RemoteSigningCallback callback) {
        throw new UnsupportedOperationException("Remote signing transport does not support callbacks");
    }

    @Override
    void close();

    /** Best-effort remote status-change callback. */
    @FunctionalInterface
    interface RemoteSigningCallback {
        /**
         * Receives one remote status change.
         *
         * @param status the changed remote status
         */
        void onStatus(RemoteSigningStatus status);
    }

    /**
     * Technology-neutral state a remote signing service reports.
     *
     * <p>{@code QUEUED} is non-terminal (accepted, awaiting the service's decision,
     * possibly an external operator approval); {@code SIGNED}, {@code DENIED}, and
     * {@code CANCELLED} are terminal. Deadline expiry is enforced by the caller's
     * orchestration, not reported here.</p>
     */
    enum RemoteSigningState {
        /** Accepted and awaiting signing or an external (typically human) decision. */
        QUEUED,
        /** A signature has been produced. */
        SIGNED,
        /** The signature was refused by policy or an operator. */
        DENIED,
        /** The caller's cancellation was honoured. */
        CANCELLED,
        /** Remote service cannot currently determine whether the operation exists. */
        UNKNOWN,
        /** Remote service guarantees the operation outcome cannot be recovered. */
        UNRECOVERABLE;

        /**
         * Indicates whether this state is terminal.
         *
         * @return {@code true} unless {@link #QUEUED}
         */
        public boolean isTerminal() {
            return this != QUEUED && this != UNKNOWN;
        }
    }

    /**
     * Per-call deadline and cooperative cancellation.
     *
     * @param deadline absolute deadline after which the caller abandons the call
     * @param cancellation cooperative cancellation signal
     */
    record RemoteCallControl(Instant deadline, CancellationSignal cancellation) {
        /** Validates the control. */
        public RemoteCallControl {
            Objects.requireNonNull(deadline, "deadline");
            Objects.requireNonNull(cancellation, "cancellation");
        }
    }

    /**
     * One signing request on the wire.
     *
     * @param submissionId caller-chosen idempotency key and operation id
     * @param namespace signing namespace bound to the provider
     * @param semanticFingerprint canonical request fingerprint the remote service pins
     * @param fencingToken monotonic fencing token
     * @param keyHandle opaque remote key handle
     * @param algorithmId canonical signature algorithm identity
     * @param contentSha256 lowercase 64-hex digest of the content
     * @param contentLength content length in bytes
     * @param content exact bytes to sign
     * @param principalType audit principal type
     * @param principalName audit principal name
     * @param purpose audit purpose
     * @param deadline optional request deadline
     * @param protocolVersion exact input protocol version
     * @param inputMode explicit original-message or prehashed-digest mode
     * @param digestId canonical digest identity only for prehashed input; empty otherwise
     * @param configurationCommitment expected client-effective configuration
     */
    record RemoteSignRequest(String submissionId, String namespace, String semanticFingerprint, long fencingToken,
            String keyHandle, String algorithmId, String contentSha256, long contentLength, byte[] content,
            String principalType, String principalName, String purpose, Optional<Instant> deadline,
            int protocolVersion, SigningInputCapabilities.Mode inputMode, String digestId,
            SigningProvider.ConfigurationCommitment configurationCommitment) {
        /** Validates bounded wire structure and takes ownership of a copy. */
        public RemoteSignRequest {
            for (String value : List.of(submissionId, namespace, semanticFingerprint, keyHandle, algorithmId,
                    contentSha256, principalType, principalName, purpose)) {
                if (value.isBlank() || value.length() > 8192) {
                    throw new IllegalArgumentException("Remote request field exceeds its finite bound");
                }
            }
            Objects.requireNonNull(deadline, "deadline");
            Objects.requireNonNull(inputMode, "inputMode");
            Objects.requireNonNull(digestId, "digestId");
            Objects.requireNonNull(configurationCommitment, "configurationCommitment");
            Objects.requireNonNull(content, "content");
            if (protocolVersion != SigningInputCapabilities.PROTOCOL_VERSION || fencingToken <= 0
                    || contentLength < 0 || contentSha256.length() != 64
                    || !HexFormat.of().formatHex(HexFormat.of().parseHex(contentSha256)).equals(contentSha256)
                    || content.length > SigningInputCapabilities.REMOTE_RAW_LIMIT || digestId.length() > 8192
                    || inputMode == SigningInputCapabilities.Mode.RAW_MESSAGE != digestId.isEmpty()) {
                throw new IllegalArgumentException("Invalid remote signing input contract");
            }
            content = content.clone();
        }

        /** {@return a defensive copy of the raw message or prehash bytes} */
        @Override public byte[] content() { return content.clone(); }

        /**
         * Validates against server-captured capabilities, never trusting the
         * client's mode or semantic fingerprint. In digest mode original length
         * and SHA-256 are assertions by the authenticated client, not proofs
         * recomputed by the server.
         * @param capabilities server's authoritative configuration snapshot
         * @throws IllegalArgumentException on a configuration or input mismatch
         */
        public void validate(RemoteCapabilities capabilities) {
            SigningInputCapabilities inputs = capabilities.effectiveInputs();
            if (!capabilities.supportedAlgorithms().contains(algorithmId)
                    || inputs.select(algorithmId, contentLength) != inputMode
                    || !capabilities.effectiveCommitment().matches(configurationCommitment)) {
                throw new IllegalArgumentException("Remote signing capability mismatch");
            }
            if (inputMode == SigningInputCapabilities.Mode.PREHASHED_DIGEST) {
                AlgorithmIdentity digest = inputs.prehashedDigests().get(algorithmId);
                if (!digest.canonicalForm().equals(digestId)
                        || content.length != SigningInputCapabilities.digestLength(digest)) {
                    throw new IllegalArgumentException("Remote prehashed input mismatch");
                }
            } else if (content.length != contentLength || !contentSha256.equals(HexFormat.of().formatHex(
                    SigningInputCapabilities.newDigest(BootstrapAlgorithmIdentities.SHA256).digest(content)))) {
                throw new IllegalArgumentException("Remote raw content commitment mismatch");
            }
        }

        /**
         * Computes a server-owned replay commitment over every wire coordinate
         * and payload. No client-supplied fingerprint substitutes for this check.
         * @return canonical lowercase SHA-256 wire fingerprint
         */
        public String wireFingerprint() {
            MessageDigest digest = SigningInputCapabilities.newDigest(BootstrapAlgorithmIdentities.SHA256);
            try (DataOutputStream output = new DataOutputStream(new DigestOutputStream(
                    OutputStream.nullOutputStream(), digest))) {
                output.writeUTF("zeroecho.remote-signing-wire");
                output.writeInt(protocolVersion);
                for (String value : List.of(submissionId, namespace, semanticFingerprint, keyHandle, algorithmId,
                        contentSha256, principalType, principalName, purpose, digestId, inputMode.name(),
                        deadline.map(Instant::toString).orElse(""))) {
                    output.writeUTF(value);
                }
                output.write(configurationCommitment.bytes());
                output.writeLong(fencingToken);
                output.writeLong(contentLength);
                output.writeInt(content.length);
                output.write(content);
            } catch (IOException impossible) {
                throw new IllegalStateException("In-memory wire fingerprint failed", impossible);
            }
            return HexFormat.of().formatHex(digest.digest());
        }
    }

    /**
     * The remote operation's current status.
     *
     * @param operationId remote operation id
     * @param state remote lifecycle state
     * @param updatedAt server-observed update instant
     * @param signature signature bytes, present only on {@link RemoteSigningState#SIGNED}
     * @param signatureEncoding encoding name of the signature (for example {@code BINARY})
     */
    record RemoteSigningStatus(String operationId, RemoteSigningState state, Instant updatedAt,
            Optional<byte[]> signature, String signatureEncoding) {
    }

    /**
     * Remote service capabilities.
     *
     * @param supportedAlgorithms advertised signature algorithm identities
     * @param configurationCommitment 32-byte remote configuration commitment
     * @param protocolVersion exact explicit-input protocol version
     * @param inputCapabilities finite server input capability snapshot
     */
    record RemoteCapabilities(Set<String> supportedAlgorithms, byte[] configurationCommitment,
            int protocolVersion, SigningInputCapabilities inputCapabilities) {
        /** Validates and snapshots the advertised configuration. */
        public RemoteCapabilities {
            supportedAlgorithms = Set.copyOf(supportedAlgorithms);
            configurationCommitment = new SigningProvider.ConfigurationCommitment(configurationCommitment).bytes();
            Objects.requireNonNull(inputCapabilities, "inputCapabilities");
            if (protocolVersion != SigningInputCapabilities.PROTOCOL_VERSION) {
                throw new IllegalArgumentException("Unsupported remote signing protocol version");
            }
            inputCapabilities.commitment(new SigningProvider.ConfigurationCommitment(configurationCommitment),
                    supportedAlgorithms);
        }

        /** {@return a defensive copy of the provider configuration commitment} */
        @Override public byte[] configurationCommitment() { return configurationCommitment.clone(); }

        /** {@return capabilities after applying the client's finite raw wire ceiling} */
        public SigningInputCapabilities effectiveInputs() {
            return new SigningInputCapabilities(Math.min(inputCapabilities.rawMessageMaximum(),
                    SigningInputCapabilities.REMOTE_RAW_LIMIT), inputCapabilities.prehashedDigests());
        }

        /** {@return deterministic client-effective configuration commitment} */
        public SigningProvider.ConfigurationCommitment effectiveCommitment() {
            return effectiveInputs().commitment(new SigningProvider.ConfigurationCommitment(configurationCommitment),
                    supportedAlgorithms);
        }
    }

    /**
     * Signals that a remote signing call did not complete with a definite,
     * trustworthy outcome. The message must never contain secrets, key material,
     * or payload bytes.
     */
    class RemoteSigningException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        /**
         * Creates the exception.
         *
         * @param message non-secret diagnostic
         */
        public RemoteSigningException(String message) {
            super(message);
        }

        /**
         * Creates the exception with a cause.
         *
         * @param message non-secret diagnostic
         * @param cause underlying transport cause
         */
        public RemoteSigningException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
