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
package zeroecho.pki.spi.crypto;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;

/**
 * Stateless execution boundary for one configured signing provider.
 *
 * <p>The authoritative workflow lifecycle, fencing, leases, retry metadata and
 * terminal result live in the signing store. A provider performs only the
 * bounded call represented by {@link #dispatch(SignRequest, CallControl)},
 * {@link #reconcile(PkiId, CallControl)}, or
 * {@link #cancel(PkiId, long, CancellationReason, CallControl)}. Implementations
 * must not retain orchestration state merely to emulate a workflow.</p>
 *
 * <p>A local provider may complete dispatch inline. If such a call is interrupted
 * after the durable dispatch claim, a later reconciliation must report
 * {@link ObservationState#UNRECOVERABLE}; it must never repeat cryptographic
 * execution. A remote provider may use external idempotency and can report
 * pending or retryably unknown observations.</p>
 *
 * <p>Implementations are thread-safe: a bounded reactor may invoke distinct
 * operation identifiers concurrently up to the aggregate configured lane count
 * across all routing pools. The reactor invokes at most one provider call for an operation at a time. The
 * owning session calls {@link #close()} only after all reactor lanes stop, and
 * no provider invocation may begin after close.</p>
 */
@SuppressWarnings("PMD.PreserveStackTrace")
public interface SigningProvider extends AutoCloseable {

    /** Immutable 256-bit commitment to effective provider configuration. */
    final class ConfigurationCommitment {
        /** Required commitment length in bytes. */
        public static final int BYTE_LENGTH = 32;
        private final byte[] bytes;

        /**
         * Creates a commitment from a borrowed exact 32-byte value.
         *
         * @param bytes exact commitment bytes, copied by the constructor
         */
        public ConfigurationCommitment(byte[] bytes) {
            Objects.requireNonNull(bytes, "bytes");
            if (bytes.length != BYTE_LENGTH) {
                throw new IllegalArgumentException("Configuration commitment must contain exactly 32 bytes");
            }
            this.bytes = bytes.clone();
        }

        /**
         * Returns an independent copy.
         *
         * @return exact commitment bytes
         */
        public byte[] bytes() {
            return bytes.clone();
        }

        /**
         * Compares the complete value in constant time.
         *
         * @param other candidate commitment
         * @return whether every commitment byte is equal
         */
        public boolean matches(ConfigurationCommitment other) {
            return other != null && MessageDigest.isEqual(bytes, other.bytes);
        }

        @Override
        public boolean equals(Object other) {
            return this == other || other instanceof ConfigurationCommitment commitment
                    && MessageDigest.isEqual(bytes, commitment.bytes);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(bytes);
        }

        @Override
        public String toString() {
            return "ConfigurationCommitment[redacted]";
        }
    }

    /**
     * Returns the stable provider identifier.
     *
     * @return non-blank provider identifier
     */
    String id();

    /**
     * Returns the stable non-secret effective-configuration commitment.
     *
     * @return provider configuration commitment
     */
    ConfigurationCommitment configurationCommitment();

    /**
     * Returns the immutable informational set of supported algorithm identities.
     *
     * @return finite immutable algorithm-identity set
     */
    Set<String> supportedAlgorithms();

    /**
     * Returns the immutable effective input contract pinned by configuration.
     * @return stable finite input capabilities
     */
    SigningInputCapabilities inputCapabilities();

    /**
     * Validates the authoritative store/provider signing domain.
     *
     * @param namespace exact {@code storeNamespace + "." + providerId}
     * @param horizon authoritative identity horizon
     * @param permittedSkew authoritative future skew
     */
    default void validateSigningDomain(String namespace, Duration horizon, Duration permittedSkew) {
        Objects.requireNonNull(namespace, "namespace");
        Objects.requireNonNull(horizon, "horizon");
        Objects.requireNonNull(permittedSkew, "permittedSkew");
        if (!namespace.endsWith("." + id()) || !Duration.ofDays(90).equals(horizon)
                || !Duration.ZERO.equals(permittedSkew)) {
            throw new IllegalArgumentException("Signing provider domain mismatch");
        }
    }

    /**
     * Executes or submits the exact already-claimed signing request once.
     *
     * @param request exact dispatch request
     * @param control finite call control
     * @return bounded current operation observation
     */
    OperationObservation dispatch(SignRequest request, CallControl control);

    /**
     * Observes an already-dispatched operation without re-dispatching it.
     *
     * @param operationId exact operation identifier
     * @param control finite call control
     * @return bounded current operation observation
     */
    OperationObservation reconcile(PkiId operationId, CallControl control);

    /**
     * Requests cancellation of an already-dispatched operation.
     *
     * @param operationId exact operation identifier
     * @param fencingToken authoritative positive fencing token
     * @param reason finite safe cancellation reason
     * @param control finite call control
     * @return bounded current operation observation
     */
    OperationObservation cancel(PkiId operationId, long fencingToken, CancellationReason reason,
            CallControl control);

    @Override
    void close();

    /** Finite, non-sensitive provider observation taxonomy. */
    enum ObservationState {
        /** Provider knows the operation and it remains pending. */
        PENDING(false),
        /** Provider cannot currently determine whether the operation exists. */
        RETRYABLE_UNKNOWN(false),
        /** Provider produced a signature. */
        SUCCEEDED(true),
        /** Provider reached a permanent failure. */
        FAILED(true),
        /** Provider confirmed cancellation. */
        CANCELLED(true),
        /** Outcome cannot be recovered and execution must not be repeated. */
        UNRECOVERABLE(true);

        private final boolean terminal;

        ObservationState(boolean terminal) {
            this.terminal = terminal;
        }

        /**
         * Returns whether the observation is terminal.
         *
         * @return {@code true} for terminal observations
         */
        public boolean isTerminal() {
            return terminal;
        }
    }

    /** Finite safe detail codes; raw provider reasons never cross this boundary. */
    enum DetailCode {
        /** Operation remains pending. */
        PENDING,
        /** Operation existence or outcome is temporarily unknown. */
        RETRYABLE_UNKNOWN,
        /** Signature was produced. */
        SIGNED,
        /** Provider policy denied the request. */
        DENIED,
        /** Cancellation was confirmed. */
        CANCELLED,
        /** Local process loss made an in-flight outcome unrecoverable. */
        LOCAL_RESTART_UNRECOVERABLE,
        /** Provider returned an invalid operation identity or result shape. */
        PROVIDER_RESULT_INVALID,
        /** Key reference is malformed for this provider. */
        INVALID_KEY_REFERENCE,
        /** Algorithm identity is invalid or unsupported. */
        INVALID_ALGORITHM,
        /** Requested algorithm does not match the selected key. */
        ALGORITHM_MISMATCH,
        /** Selected key is unavailable. */
        KEY_NOT_FOUND,
        /** Candidate content did not match its commitment. */
        CONTENT_INTEGRITY_FAILURE,
        /** Requested signature encoding is unsupported. */
        @SuppressWarnings("PMD.LongVariable")
        UNSUPPORTED_SIGNATURE_ENCODING,
        /** Keyring input/output failed. */
        KEYRING_IO_FAILURE,
        /** Cryptographic execution failed. */
        CRYPTO_FAILURE,
        /** The call or request deadline elapsed before completion. */
        DEADLINE_EXPIRED
    }

    /** Finite non-sensitive reasons accepted by provider cancellation. */
    enum CancellationReason {
        /** Explicit caller cancellation. */
        CALLER_REQUESTED,
        /** Runtime is closing. */
        RUNTIME_CLOSING,
        /** Authoritative signing deadline elapsed. */
        DEADLINE_EXPIRED
    }

    /**
     * Bounded observation returned directly by one provider call.
     *
     * @param operationId exact requested operation identifier
     * @param state finite lifecycle observation
     * @param updatedAt provider-observed transition time
     * @param detailCode finite safe classification
     * @param signature signature only for successful observations
     */
    record OperationObservation(PkiId operationId, ObservationState state, Instant updatedAt,
            DetailCode detailCode, Optional<EncodedObject> signature) {
        /** Maximum signature representation accepted across the SPI. */
        public static final int MAXIMUM_SIGNATURE_BYTES = 1_048_576;

        /** Validates and snapshots one bounded observation. */
        public OperationObservation {
            Objects.requireNonNull(operationId, "operationId");
            Objects.requireNonNull(state, "state");
            Objects.requireNonNull(updatedAt, "updatedAt");
            Objects.requireNonNull(detailCode, "detailCode");
            signature = Objects.requireNonNull(signature, "signature").map(value ->
                    new EncodedObject(value.encoding(), value.bytes()));
            if (state == ObservationState.SUCCEEDED != signature.isPresent()) {
                throw new IllegalArgumentException("Signature presence does not match provider observation");
            }
            if (signature.isPresent() && (signature.orElseThrow().bytes().length == 0
                    || signature.orElseThrow().bytes().length > MAXIMUM_SIGNATURE_BYTES)) {
                throw new IllegalArgumentException("Provider signature exceeds its finite bound");
            }
            if (!detailMatchesState(state, detailCode)) {
                throw new IllegalArgumentException("Provider detail code does not match observation state");
            }
        }

        private static boolean detailMatchesState(ObservationState state, DetailCode detailCode) {
            return switch (state) {
                case PENDING -> detailCode == DetailCode.PENDING;
                case RETRYABLE_UNKNOWN -> detailCode == DetailCode.RETRYABLE_UNKNOWN;
                case SUCCEEDED -> detailCode == DetailCode.SIGNED;
                case CANCELLED -> detailCode == DetailCode.CANCELLED;
                case UNRECOVERABLE -> detailCode == DetailCode.LOCAL_RESTART_UNRECOVERABLE
                        || detailCode == DetailCode.PROVIDER_RESULT_INVALID;
                case FAILED -> detailCode == DetailCode.DENIED
                        || detailCode == DetailCode.PROVIDER_RESULT_INVALID
                        || detailCode == DetailCode.INVALID_KEY_REFERENCE
                        || detailCode == DetailCode.INVALID_ALGORITHM
                        || detailCode == DetailCode.ALGORITHM_MISMATCH
                        || detailCode == DetailCode.KEY_NOT_FOUND
                        || detailCode == DetailCode.CONTENT_INTEGRITY_FAILURE
                        || detailCode == DetailCode.UNSUPPORTED_SIGNATURE_ENCODING
                        || detailCode == DetailCode.KEYRING_IO_FAILURE
                        || detailCode == DetailCode.CRYPTO_FAILURE
                        || detailCode == DetailCode.DEADLINE_EXPIRED;
            };
        }
    }

    /**
     * Per-invocation deadline and cooperative cancellation.
     *
     * @param deadline exclusive call deadline
     * @param cancellation cooperative cancellation signal
     */
    record CallControl(Instant deadline, CancellationSignal cancellation) {
        /** Validates one call control. */
        public CallControl {
            Objects.requireNonNull(deadline, "deadline");
            Objects.requireNonNull(cancellation, "cancellation");
        }

        /**
         * Rejects work at or after the deadline or after cancellation.
         *
         * @param now current clock instant
         */
        public void requireActive(Instant now) {
            Objects.requireNonNull(now, "now");
            if (cancellation.isCancelled() || !now.isBefore(deadline)) {
                throw new IllegalStateException("Signing provider call is no longer active");
            }
        }
    }

    /**
     * Exact immutable request for an already durably claimed dispatch.
     *
     * @param operationId exact operation identifier
     * @param namespace exact store/provider namespace
     * @param semanticFingerprint canonical request fingerprint
     * @param configurationCommitment exact provider-configuration commitment
     * @param fencingToken authoritative positive fencing token
     * @param accessContext trusted authorization and audit context
     * @param keyRef opaque provider key reference
     * @param algorithmId canonical signing algorithm identifier
     * @param contentCommitment exact candidate-content commitment
     * @param content repeatable candidate content
     * @param preferredSignatureEncoding requested signature encoding
     * @param deadline optional signing deadline
     * @param cancellation cooperative request cancellation signal
     */
    record SignRequest(PkiId operationId, String namespace, String semanticFingerprint,
            ConfigurationCommitment configurationCommitment, long fencingToken,
            AccessContext accessContext, KeyRef keyRef, String algorithmId,
            ContentCommitment contentCommitment, RepeatableContent content,
            Optional<Encoding> preferredSignatureEncoding, Optional<Instant> deadline,
            CancellationSignal cancellation) {
        /** Validates structure and the constant-time canonical fingerprint. */
        public SignRequest {
            Objects.requireNonNull(operationId, "operationId");
            Objects.requireNonNull(namespace, "namespace");
            Objects.requireNonNull(semanticFingerprint, "semanticFingerprint");
            Objects.requireNonNull(configurationCommitment, "configurationCommitment");
            Objects.requireNonNull(accessContext, "accessContext");
            Objects.requireNonNull(keyRef, "keyRef");
            Objects.requireNonNull(algorithmId, "algorithmId");
            Objects.requireNonNull(contentCommitment, "contentCommitment");
            Objects.requireNonNull(content, "content");
            Objects.requireNonNull(preferredSignatureEncoding, "preferredSignatureEncoding");
            Objects.requireNonNull(deadline, "deadline");
            Objects.requireNonNull(cancellation, "cancellation");
            if (namespace.isBlank() || algorithmId.isBlank() || fencingToken <= 0L) {
                throw new IllegalArgumentException("Signing request metadata is invalid");
            }
            String expected = fingerprint(configurationCommitment, namespace, accessContext, keyRef,
                    algorithmId, contentCommitment, preferredSignatureEncoding, deadline);
            if (!constantTimeEquals(expected, semanticFingerprint)) {
                throw new IllegalArgumentException("semanticFingerprint does not match signing request");
            }
        }

        /**
         * Creates a request with its canonical semantic fingerprint.
         *
         * @param operationId exact operation identifier
         * @param namespace exact store/provider namespace
         * @param configurationCommitment exact provider-configuration commitment
         * @param fencingToken authoritative positive fencing token
         * @param accessContext trusted authorization and audit context
         * @param keyRef opaque provider key reference
         * @param algorithmId canonical signing algorithm identifier
         * @param contentCommitment exact candidate-content commitment
         * @param content repeatable candidate content
         * @param preferredSignatureEncoding requested signature encoding
         * @param deadline optional signing deadline
         * @return validated immutable request
         */
        @SuppressWarnings("PMD.ExcessiveParameterList")
        public static SignRequest create(PkiId operationId, String namespace,
                ConfigurationCommitment configurationCommitment, long fencingToken,
                AccessContext accessContext, KeyRef keyRef, String algorithmId,
                ContentCommitment contentCommitment, RepeatableContent content,
                Optional<Encoding> preferredSignatureEncoding, Optional<Instant> deadline) {
            String fingerprint = fingerprint(configurationCommitment, namespace, accessContext, keyRef,
                    algorithmId, contentCommitment, preferredSignatureEncoding, deadline);
            return new SignRequest(operationId, namespace, fingerprint, configurationCommitment, fencingToken,
                    accessContext, keyRef, algorithmId, contentCommitment, content,
                    preferredSignatureEncoding, deadline, CancellationSignal.NONE);
        }

        /** Returns a deliberately redacted representation of the signing request. */
        @Override
        public String toString() {
            return "SignRequest[redacted]";
        }

        /**
         * Computes the canonical {@code signfp:v3} fingerprint.
         *
         * @param configurationCommitment exact provider-configuration commitment
         * @param namespace exact store/provider namespace
         * @param accessContext trusted authorization and audit context
         * @param keyRef opaque provider key reference
         * @param algorithmId canonical signing algorithm identifier
         * @param contentCommitment exact candidate-content commitment
         * @param preferredSignatureEncoding requested signature encoding
         * @param deadline optional signing deadline
         * @return canonical constant-size fingerprint
         */
        public static String fingerprint(ConfigurationCommitment configurationCommitment, String namespace,
                AccessContext accessContext, KeyRef keyRef, String algorithmId,
                ContentCommitment contentCommitment, Optional<Encoding> preferredSignatureEncoding,
                Optional<Instant> deadline) {
            try {
                return fingerprintWithDigest(configurationCommitment, namespace, accessContext, keyRef,
                        algorithmId, contentCommitment, preferredSignatureEncoding, deadline,
                        MessageDigest.getInstance("SHA-256"), ignored -> { });
            } catch (NoSuchAlgorithmException unavailable) {
                throw new IllegalStateException("Unable to compute signing request fingerprint");
            }
        }

        @SuppressWarnings("PMD.ExcessiveParameterList")
        /* default */ static String fingerprintWithDigest(ConfigurationCommitment configurationCommitment,
                String namespace,
                AccessContext accessContext, KeyRef keyRef, String algorithmId,
                ContentCommitment contentCommitment, Optional<Encoding> preferredSignatureEncoding,
                Optional<Instant> deadline, MessageDigest digest, Consumer<byte[]> cleanupObserver) {
            Objects.requireNonNull(configurationCommitment, "configurationCommitment");
            Objects.requireNonNull(namespace, "namespace");
            Objects.requireNonNull(accessContext, "accessContext");
            Objects.requireNonNull(keyRef, "keyRef");
            Objects.requireNonNull(algorithmId, "algorithmId");
            Objects.requireNonNull(contentCommitment, "contentCommitment");
            Objects.requireNonNull(preferredSignatureEncoding, "preferredSignatureEncoding");
            Objects.requireNonNull(deadline, "deadline");
            Objects.requireNonNull(digest, "digest");
            Objects.requireNonNull(cleanupObserver, "cleanupObserver");
            byte[] commitmentBytes = configurationCommitment.bytes();
            byte[] digestBytes = null;
            try {
                try (DataOutputStream output = new DataOutputStream(
                        new DigestOutputStream(OutputStream.nullOutputStream(), digest))) {
                    output.writeUTF("sign-request-v4");
                    output.write(commitmentBytes);
                    output.writeUTF(namespace);
                    output.writeUTF(accessContext.principal().type());
                    output.writeUTF(accessContext.principal().name());
                    output.writeUTF(accessContext.purpose().value());
                    output.writeUTF(accessContext.objectId().map(PkiId::value).orElse(""));
                    output.writeUTF(accessContext.formatId().map(zeroecho.pki.api.FormatId::value).orElse(""));
                    output.writeUTF(keyRef.value());
                    output.writeUTF(algorithmId);
                    output.writeUTF(contentCommitment.version());
                    output.writeLong(contentCommitment.length());
                    output.writeUTF(contentCommitment.sha256());
                    output.writeUTF(preferredSignatureEncoding.map(Enum::name).orElse(""));
                    output.writeUTF(deadline.map(Instant::toString).orElse(""));
                }
                digestBytes = digest.digest();
                return "signfp:v3:" + HexFormat.of().formatHex(digestBytes);
            } catch (IOException impossible) {
                throw new IllegalStateException("Unable to compute signing request fingerprint");
            } finally {
                clearOwned(commitmentBytes, cleanupObserver);
                clearOwned(digestBytes, cleanupObserver);
            }
        }

        private static boolean constantTimeEquals(String left, String right) {
            byte[] leftBytes = left.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            byte[] rightBytes = right.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            try {
                return MessageDigest.isEqual(leftBytes, rightBytes);
            } finally {
                Arrays.fill(leftBytes, (byte) 0);
                Arrays.fill(rightBytes, (byte) 0);
            }
        }

        private static void clearOwned(byte[] owned, Consumer<byte[]> observer) {
            if (owned != null) {
                Arrays.fill(owned, (byte) 0);
                observer.accept(owned);
            }
        }
    }

    /**
     * Exact commitment to candidate bytes consumed by the provider.
     *
     * @param version exact commitment schema identifier
     * @param length exact candidate length
     * @param sha256 lowercase hexadecimal SHA-256 digest
     */
    record ContentCommitment(String version, long length, String sha256) {
        /** Current commitment version. */
        public static final String SHA256_V1 = "content-sha256:v1";

        /** Validates a canonical content commitment. */
        public ContentCommitment {
            Objects.requireNonNull(version, "version");
            Objects.requireNonNull(sha256, "sha256");
            if (!SHA256_V1.equals(version) || length < 0L || !sha256.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Content commitment is not canonical");
            }
        }

        /**
         * Computes a SHA-256 commitment for materialized bytes.
         *
         * @param bytes borrowed bytes to commit
         * @return immutable SHA-256 content commitment
         */
        public static ContentCommitment sha256(byte[] bytes) {
            Objects.requireNonNull(bytes, "bytes");
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
                try {
                    return new ContentCommitment(SHA256_V1, bytes.length, HexFormat.of().formatHex(digest));
                } finally {
                    Arrays.fill(digest, (byte) 0);
                }
            } catch (NoSuchAlgorithmException unavailable) {
                throw new IllegalStateException("SHA-256 is unavailable");
            }
        }
    }
}
