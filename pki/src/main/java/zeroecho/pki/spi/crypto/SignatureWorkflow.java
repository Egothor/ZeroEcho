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

import java.io.Closeable;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
 * Asynchronous signature workflow boundary for PKI.
 *
 * <p>
 * This SPI is intentionally asynchronous to support ultra-secure deployments
 * where signing can be routed across multiple hops and may require human
 * approval. A local provider may complete operations immediately; a
 * remote/hop-based provider may keep them pending for extended periods.
 * </p>
 *
 * <h2>Trust boundary</h2>
 * <ul>
 * <li><strong>PKI (caller):</strong> works only with {@link KeyRef}, algorithm
     * id and repeatable content; it must never parse {@code KeyRef} nor access private
 * key bytes.</li>
 * <li><strong>Provider (callee):</strong> resolves {@code KeyRef} into an
 * internal runtime key handle, enforces policy (including multi-hop approvals),
 * and performs cryptographic operations.</li>
 * </ul>
 *
 * <h2>Failure model (normative - Variant 1)</h2>
 * <p>
 * This workflow is designed to be audit-friendly and transport-friendly (e.g.,
 * future HTTP APIs). Implementations must follow these rules:
 * </p>
 * <ul>
 * <li>Validation and policy failures must not be surfaced as uncaught
 * exceptions. Instead, the provider must return an operation id and expose the
 * failure via {@link #status(PkiId, CallControl)} using {@link OperationStatus#state()} ==
 * {@link State#FAILED} and a stable {@link OperationStatus#detailCode()}.</li>
 * <li>{@link IllegalArgumentException} may be thrown only for programmer errors
 * such as {@code request == null} or {@code operationId == null}. These are not
 * business/policy failures.</li>
 * <li>Providers must ensure {@link OperationStatus#detailCode()} does not
 * contain secrets, key material, or payload fragments; it must be safe for
 * audit logs and API responses.</li>
 * </ul>
 */
// PMD cannot infer that retaining digest/encoding causes would violate the redaction contract.
@SuppressWarnings("PMD.PreserveStackTrace")
public interface SignatureWorkflow extends Closeable {

    /**
     * Immutable commitment to one workflow's effective signing configuration.
     *
     * <p>The value is exactly 256 bits. Implementations must supply a stable,
     * non-secret commitment that changes whenever effective signing behavior or
     * effective key identity changes. The constructor and {@link #bytes()} use
     * defensive copies, so callers retain no mutable reference to internal state.
     * Instances are immutable and thread-safe.</p>
     *
     * <p>{@link #matches(ConfigurationCommitment)} and value equality compare the
     * complete value using {@link MessageDigest#isEqual(byte[], byte[])}. String
     * rendering is deliberately redacted.</p>
     *
     * <p>An unkeyed hash is suitable only when every committed input is a public,
     * high-entropy identity that is impractical to enumerate. Sensitive or
     * guessable inputs require a versioned, domain-separated pseudorandom
     * function under a stable, protected, high-entropy provider key. Raw secrets,
     * filesystem paths, credentials, bearer tokens, and analogous sensitive
     * values must never be embedded in or directly hashed into this value.</p>
     */
    final class ConfigurationCommitment {
        /** Required commitment length in bytes. */
        public static final int BYTE_LENGTH = 32;

        private final byte[] bytes;

        /**
         * Creates a commitment from one borrowed 32-byte value.
         *
         * @param bytes borrowed commitment bytes
         * @throws NullPointerException if {@code bytes} is {@code null}
         * @throws IllegalArgumentException if {@code bytes} is not exactly 32 bytes
         */
        public ConfigurationCommitment(byte[] bytes) {
            Objects.requireNonNull(bytes, "bytes");
            if (bytes.length != BYTE_LENGTH) {
                throw new IllegalArgumentException("Configuration commitment must contain exactly 32 bytes");
            }
            this.bytes = bytes.clone();
        }

        /**
         * Returns a newly owned copy of the commitment bytes.
         *
         * @return independent 32-byte value
         */
        public byte[] bytes() {
            return bytes.clone();
        }

        /**
         * Compares the complete commitment value in constant time for equal-length
         * inputs.
         *
         * @param other comparison value, or {@code null}
         * @return {@code true} only when all 32 bytes match
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
     * Provider identifier for diagnostics and audit correlation.
     *
     * @return stable provider id (never blank)
     */
    String id();

    /**
     * Returns the immutable commitment to this workflow's effective signing
     * configuration and effective key identities.
     *
     * <p>The value must remain stable for the lifetime of this workflow and across
     * restarts using the same effective configuration. It must change whenever a
     * configuration or key-identity change could alter signing behavior. The
     * commitment must not expose configuration values, paths, credentials, key
     * material, or other secrets.</p>
     *
     * <p>Providers may use an unkeyed hash only for public, high-entropy identities
     * that are impractical to guess or enumerate. If any effective input is
     * sensitive or guessable, the commitment must use a versioned,
     * domain-separated pseudorandom function keyed by a stable, protected,
     * high-entropy provider key. Providers must not embed or directly hash raw
     * secrets, paths, credentials, bearer tokens, or equivalent sensitive
     * values.</p>
     *
     * @return immutable non-secret 256-bit configuration commitment
     */
    ConfigurationCommitment configurationCommitment();

    /**
     * Validates the authoritative signing domain selected by orchestration.
     *
     * <p>
     * Providers must fail fast when their configured horizon or skew differs. The
     * default contract accepts the standard {@code P90D}/{@code PT0S} domain and a
     * namespace whose provider component is {@link #id()}.
     * </p>
     *
     * @param namespace     combined stable store and provider namespace
     * @param horizon       authoritative operation horizon
     * @param permittedSkew authoritative future timestamp skew
     */
    default void validateSigningDomain(String namespace, java.time.Duration horizon, java.time.Duration permittedSkew) {
        Objects.requireNonNull(namespace, "namespace");
        Objects.requireNonNull(horizon, "horizon");
        Objects.requireNonNull(permittedSkew, "permittedSkew");
        if (!namespace.endsWith("." + id()) || !java.time.Duration.ofDays(90).equals(horizon)
                || !java.time.Duration.ZERO.equals(permittedSkew)) {
            throw new IllegalArgumentException("Signature workflow signing domain mismatch");
        }
    }

    /**
     * Submits a signing request.
     *
     * <p>
     * Providers must never return private key material. The output is a signature
     * (encoded) on success.
     * </p>
     *
     * <p>
     * The provider must durably bind {@link SignRequest#submissionId()} to the
     * constant-time verified {@link SignRequest#semanticFingerprint()} before
     * invoking cryptography. The first accepted request may execute once. Any
     * concurrent or later request with the same non-expired identifier and
     * fingerprint attaches to the existing non-terminal or terminal outcome and
     * must not invoke cryptography again. A different fingerprint is a conflict.
     * The returned identifier must equal the submitted identifier.
     * </p>
     *
     * <p>
     * {@link SignRequest#fencingToken()} is monotonic. A stale token must not
     * mutate state; a completion may commit only while its fingerprint, token, and
     * running state remain current. Providers must check an optional request
     * deadline before starting cryptography or approval execution and again before
     * committing success. A completion at the deadline is late; it must become
     * {@link State#EXPIRED} without exposing a result. Terminal states are
     * immutable. At and after the configured horizon, submission is rejected and
     * {@link #status(PkiId, CallControl)} reports {@link State#EXPIRED}, including after
     * payload/result purge and restart. Provider callbacks must run after operation
     * state locks are released.
     * </p>
     *
     * <h4>Failure model (normative)</h4>
     * <ul>
     * <li>For validation and policy failures: do not throw; return operation id and
     * expose failure via {@link #status(PkiId, CallControl)} with {@code FAILED} and stable
     * {@code detailCode}.</li>
     * <li>Throws {@link IllegalStateException} for identifier/fingerprint conflicts
     * or stale fencing tokens.</li>
     * <li>May throw {@link IllegalArgumentException} for malformed, foreign, or
     * expired identifiers and programmer errors.</li>
     * </ul>
     *
     * @param request request (never {@code null})
     * @param control cooperative call deadline and cancellation
     * @return operation id (never {@code null})
     */
    PkiId submitSign(SignRequest request, CallControl control);

    /**
     * Submits a verification request.
     *
     * <p>
     * Verification typically uses public key material. For maximal portability
     * across PQC/hybrid algorithms, verification requests can either:
     * </p>
     * <ul>
     * <li>reference a public key via {@link KeyRef} (preferred), or</li>
     * <li>provide encoded public key bytes (provider-defined format; may be
     * unsupported by some providers).</li>
     * </ul>
     *
     * <h4>Failure model (normative)</h4>
     * <ul>
     * <li>For validation and policy failures: do not throw; return operation id and
     * expose failure via {@link #status(PkiId, CallControl)} with {@code FAILED} and stable
     * {@code detailCode}.</li>
     * <li>May throw {@link IllegalArgumentException} only for programmer errors
     * (e.g., {@code request == null}).</li>
     * </ul>
     *
     * @param request request (never {@code null})
     * @param control cooperative call deadline and cancellation
     * @return operation id (never {@code null})
     */
    PkiId submitVerify(VerifyRequest request, CallControl control);

    /**
     * Reads current status of an operation.
     *
     * @param operationId operation id (never {@code null})
     * @param control cooperative call deadline and cancellation
     * @return status (never {@code null})
     */
    OperationStatus status(PkiId operationId, CallControl control);

    /**
     * Best-effort cancellation.
     *
     * <p>
     * A {@code true} return value means only that the provider accepted the
     * cancellation request. It does not prove that the operation is terminal.
     * Callers must re-read {@link #status(PkiId, CallControl)} and may retire state only after
     * an immutable terminal status is observed.
     * </p>
     *
     * <p>The operation identifier and fencing-token pair is idempotent across
     * ambiguous acceptance and restart, regardless of the safe reason supplied on
     * a replay. A provider may retain the first accepted reason for audit, but a
     * replay with another reason must not cause another external effect. A lower
     * fencing token must not mutate provider state, and every terminal state is
     * immutable.</p>
     *
     * @param operationId operation id (never {@code null})
     * @param fencingToken monotonic fencing token
     * @param reason      non-sensitive reason (never blank)
     * @param control cooperative call deadline and cancellation
     * @return true if cancellation was accepted or the exact operation/fence pair
     *         replays an accepted cancellation; false if unknown, stale, superseded,
     *         or terminal for another outcome
     */
    boolean cancel(PkiId operationId, long fencingToken, String reason, CallControl control);

    /**
     * Registers a notification sink for status changes.
     *
     * <p>
     * Implementations may invoke the sink from provider-owned threads. The sink
     * must not throw.
     * </p>
     *
     * @param sink sink (never {@code null})
     * @return registration handle (never {@code null})
     */
    Registration register(NotificationSink sink);

    /**
     * Returns supported algorithm identifiers.
     *
     * @return supported algorithm ids (never {@code null})
     */
    Set<String> supportedAlgorithms();

    @Override
    void close();

    /**
     * Immutable cooperative deadline and cancellation control for one provider
     * invocation. Providers must not retain this value as workflow state.
     * Subsequent work reloads authoritative state using the operation {@link PkiId}
     * and receives a new control value for that invocation.
     *
     * @param deadline absolute exclusive call deadline
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
         * @param now authoritative current time
         * @throws IllegalStateException when the call may no longer continue
         */
        public void requireActive(Instant now) {
            Objects.requireNonNull(now, "now");
            if (cancellation.isCancelled() || !now.isBefore(deadline)) {
                throw new IllegalStateException("Signature workflow call is no longer active");
            }
        }
    }

    /**
     * Signing request.
     *
     * <p>
     * Note: this record performs basic structural validation and may throw
     * {@link IllegalArgumentException} at construction time. Callers building
     * requests for external transports are expected to catch such exceptions and
     * convert them to an appropriate error state before invoking
     * {@link #submitSign(SignRequest, CallControl)}.
     * </p>
     *
     * @param submissionId               stable caller-assigned submission
     *                                   identifier
     * @param namespace                  provider/store namespace
     * @param semanticFingerprint        versioned request fingerprint excluding
     *                                   fence
     * @param configurationCommitment    immutable commitment to the exact
     *                                   effective provider configuration
     * @param fencingToken               current positive fencing token
     * @param accessContext              audit/governance context (never
     *                                   {@code null})
     * @param keyRef                     opaque reference to the private key (never
     *                                   {@code null})
     * @param algorithmId                requested signature algorithm id (never
     *                                   blank)
     * @param contentCommitment          canonical commitment to the exact content
     *                                   bytes
     * @param content                    immutable repeatable content
     * @param preferredSignatureEncoding preferred signature encoding (optional)
     * @param deadline                   optional absolute deadline
     * @param cancellation               cooperative cancellation for this invocation
     */
    record SignRequest(PkiId submissionId, String namespace, String semanticFingerprint,
            ConfigurationCommitment configurationCommitment, long fencingToken,
            AccessContext accessContext, KeyRef keyRef, String algorithmId, ContentCommitment contentCommitment,
            RepeatableContent content,
            Optional<Encoding> preferredSignatureEncoding, Optional<Instant> deadline,
            CancellationSignal cancellation) {

        private static final long MIN_FENCING_TOKEN = 1L;

        /** Validates the request structure and its constant-time semantic fingerprint. */
        public SignRequest {
            Objects.requireNonNull(submissionId, "submissionId");
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
            if (algorithmId.isBlank()) {
                throw new IllegalArgumentException("algorithmId must not be blank");
            }
            if (fencingToken < MIN_FENCING_TOKEN) {
                throw new IllegalArgumentException("fencingToken must be positive");
            }
            String expected = fingerprint(configurationCommitment, namespace, accessContext, keyRef, algorithmId,
                    contentCommitment, preferredSignatureEncoding, deadline);
            if (!constantTimeFingerprintEquals(expected, semanticFingerprint)) {
                throw new IllegalArgumentException("semanticFingerprint does not match signing request");
            }
        }

        /**
         * Creates a request with its canonical versioned fingerprint.
         *
         * @param submissionId stable caller-assigned submission identifier
         * @param namespace provider/store namespace
         * @param configurationCommitment exact effective provider configuration commitment
         * @param fencingToken positive current fencing token
         * @param accessContext audit and governance context
         * @param keyRef opaque private-key reference
         * @param algorithmId nonblank signature algorithm identifier
         * @param contentCommitment commitment to the exact content bytes
         * @param content immutable repeatable content
         * @param preferredSignatureEncoding optional requested signature encoding
         * @param deadline optional absolute signing deadline
         * @return validated request with its canonical semantic fingerprint
         */
        @SuppressWarnings("PMD.ExcessiveParameterList")
        public static SignRequest create(PkiId submissionId, String namespace,
                ConfigurationCommitment configurationCommitment, long fencingToken,
                AccessContext accessContext, KeyRef keyRef, String algorithmId, ContentCommitment contentCommitment,
                RepeatableContent content,
                Optional<Encoding> preferredSignatureEncoding, Optional<Instant> deadline) {
            String fingerprint = fingerprint(configurationCommitment, namespace, accessContext, keyRef, algorithmId,
                    contentCommitment, preferredSignatureEncoding, deadline);
            return new SignRequest(submissionId, namespace, fingerprint, configurationCommitment, fencingToken,
                    accessContext, keyRef, algorithmId, contentCommitment, content, preferredSignatureEncoding, deadline,
                    CancellationSignal.NONE);
        }

        /**
         * Computes the canonical {@code signfp:v3} semantic fingerprint in O(1)
         * time and auxiliary memory. The fingerprint binds the exact canonical
         * configuration and content commitments and never relies on a
         * provider-defined content identifier.
         *
         * @param configurationCommitment exact effective provider configuration commitment
         * @param namespace provider/store namespace
         * @param accessContext audit and governance context
         * @param keyRef opaque private-key reference
         * @param algorithmId nonblank signature algorithm identifier
         * @param contentCommitment commitment to the exact content bytes
         * @param preferredSignatureEncoding optional requested signature encoding
         * @param deadline optional absolute signing deadline
         * @return canonical lowercase {@code signfp:v3} SHA-256 fingerprint
         */
        public static String fingerprint(ConfigurationCommitment configurationCommitment, String namespace,
                AccessContext accessContext, KeyRef keyRef,
                String algorithmId, ContentCommitment contentCommitment,
                Optional<Encoding> preferredSignatureEncoding,
                Optional<Instant> deadline) {
            Objects.requireNonNull(configurationCommitment, "configurationCommitment");
            Objects.requireNonNull(namespace, "namespace");
            Objects.requireNonNull(accessContext, "accessContext");
            Objects.requireNonNull(keyRef, "keyRef");
            Objects.requireNonNull(algorithmId, "algorithmId");
            Objects.requireNonNull(contentCommitment, "contentCommitment");
            Objects.requireNonNull(preferredSignatureEncoding, "preferredSignatureEncoding");
            Objects.requireNonNull(deadline, "deadline");
            try {
                return fingerprintWithDigest(configurationCommitment, namespace, accessContext, keyRef, algorithmId,
                        contentCommitment, preferredSignatureEncoding, deadline, MessageDigest.getInstance("SHA-256"), ignored -> {
                        });
            } catch (NoSuchAlgorithmException ex) {
                throw new IllegalStateException("Unable to compute signing request fingerprint");
            }
        }

        @SuppressWarnings("PMD.ExcessiveParameterList")
        /* default */ static String fingerprintWithDigest(ConfigurationCommitment configurationCommitment,
                String namespace, AccessContext accessContext, KeyRef keyRef,
                String algorithmId, ContentCommitment contentCommitment,
                Optional<Encoding> preferredSignatureEncoding,
                Optional<Instant> deadline, MessageDigest digest, Consumer<byte[]> cleanupObserver) {
            Objects.requireNonNull(digest, "digest");
            Objects.requireNonNull(cleanupObserver, "cleanupObserver");
            Objects.requireNonNull(configurationCommitment, "configurationCommitment");
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
            } catch (IOException ex) {
                throw new IllegalStateException("Unable to compute signing request fingerprint");
            } finally {
                clearOwned(commitmentBytes, cleanupObserver);
                clearOwned(digestBytes, cleanupObserver);
            }
        }

        private static boolean constantTimeFingerprintEquals(String left, String right) {
            byte[] leftBytes = left.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            byte[] rightBytes = right.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            try {
                return MessageDigest.isEqual(leftBytes, rightBytes);
            } finally {
                Arrays.fill(leftBytes, (byte) 0);
                Arrays.fill(rightBytes, (byte) 0);
            }
        }

        private static void clearOwned(byte[] owned, Consumer<byte[]> cleanupObserver) {
            if (owned != null) {
                Arrays.fill(owned, (byte) 0);
                cleanupObserver.accept(owned);
            }
        }
    }

    /**
     * Canonical commitment to the exact bytes consumed by a signing operation.
     *
     * <p>The current version commits an exact non-negative byte length and a
     * lowercase hexadecimal SHA-256 digest. It is independent of storage identity
     * and is therefore safe to carry across transport boundaries.</p>
     *
     * @param version commitment format version
     * @param length exact payload length in bytes
     * @param sha256 lowercase hexadecimal SHA-256 digest
     */
    record ContentCommitment(String version, long length, String sha256) {
        /** Current canonical commitment version. */
        public static final String SHA256_V1 = "content-sha256:v1";

        /** Validates a canonical content commitment. */
        public ContentCommitment {
            Objects.requireNonNull(version, "version");
            Objects.requireNonNull(sha256, "sha256");
            if (!SHA256_V1.equals(version) || length < 0L || sha256.length() != 64
                    || !isLowercaseHex(sha256)) {
                throw new IllegalArgumentException("Content commitment is not canonical");
            }
        }

        /**
         * Computes a canonical commitment for an already materialized payload.
         *
         * @param bytes payload bytes
         * @return exact SHA-256 commitment
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

        private static boolean isLowercaseHex(String value) {
            for (int index = 0; index < value.length(); index++) {
                char current = value.charAt(index);
                if (!(current >= '0' && current <= '9') && !(current >= 'a' && current <= 'f')) {
                    return false;
                }
            }
            return true;
        }
    }

    /**
     * Verification request.
     *
     * <p>
     * Note: this record performs basic structural validation and may throw
     * {@link IllegalArgumentException} at construction time. Callers building
     * requests for external transports are expected to catch such exceptions and
     * convert them to an appropriate error state before invoking
     * {@link #submitVerify(VerifyRequest, CallControl)}.
     * </p>
     *
     * @param accessContext    audit/governance context (never {@code null})
     * @param algorithmId      requested signature algorithm id (never blank)
     * @param content          immutable repeatable signed content
     * @param signature        signature bytes (never {@code null})
     * @param publicKeyRef     optional public key reference (preferred)
     * @param publicKeyEncoded optional encoded public key bytes (provider-specific;
     *                         may be unsupported)
     * @param deadline         optional absolute deadline
     * @param cancellation     cooperative cancellation for this invocation
     */
    record VerifyRequest(AccessContext accessContext, String algorithmId, RepeatableContent content,
            EncodedObject signature, Optional<KeyRef> publicKeyRef, Optional<EncodedObject> publicKeyEncoded,
            Optional<Instant> deadline, CancellationSignal cancellation) {

        /** Validates the request and requires at least one public-key representation. */
        public VerifyRequest {
            Objects.requireNonNull(accessContext, "accessContext");
            Objects.requireNonNull(algorithmId, "algorithmId");
            Objects.requireNonNull(content, "content");
            Objects.requireNonNull(signature, "signature");
            Objects.requireNonNull(publicKeyRef, "publicKeyRef");
            Objects.requireNonNull(publicKeyEncoded, "publicKeyEncoded");
            Objects.requireNonNull(deadline, "deadline");
            Objects.requireNonNull(cancellation, "cancellation");
            if (algorithmId.isBlank()) {
                throw new IllegalArgumentException("algorithmId must not be blank");
            }
            if (publicKeyRef.isEmpty() && publicKeyEncoded.isEmpty()) {
                throw new IllegalArgumentException("Either publicKeyRef or publicKeyEncoded must be provided");
            }
        }
    }

    /**
     * Status of a long-running or asynchronous signature workflow operation.
     *
     * <p>
     * An {@code OperationStatus} represents the authoritative, audit-relevant state
     * of an operation previously submitted via {@code submitSign} or
     * {@code submitVerify}. Providers must ensure that status transitions are
     * monotonic and observable through repeated calls to
     * {@link SignatureWorkflow#status(PkiId, CallControl)}.
     * </p>
     *
     * <h2>Failure and audit model</h2>
     * <ul>
     * <li>Operational, validation, or policy failures are reported via
     * {@link State#FAILED}, not via uncaught exceptions.</li>
     * <li>{@link #detailCode()} provides a stable, non-sensitive classification of
     * the outcome and is intended for audit logs, diagnostics, and transport-level
     * APIs.</li>
     * <li>{@link #detailCode()} must never contain secrets, key identifiers,
     * payload data, or provider-internal state.</li>
     * </ul>
     *
     * <h2>Terminal states</h2>
     * <p>
     * Once an operation reaches a terminal state (see {@link #isTerminal()}), its
     * {@code OperationStatus} must no longer change.
     * </p>
     *
     * <p>
     * For terminal states, {@link #updatedAt()} is the durable completion
     * timestamp, not the time at which a caller happened to poll. Providers must
     * preserve that value across restart. A successful status at or after its
     * request deadline is invalid and must instead be exposed as
     * {@link State#EXPIRED} without a result.
     * </p>
     *
     * @param state      current lifecycle state of the operation (never
     *                   {@code null})
     * @param updatedAt  timestamp of the last state transition (never
     *                   {@code null}); providers should use a deterministic value
     *                   where possible for non-operational states (e.g. unknown
     *                   operation)
     * @param detailCode optional stable, non-sensitive code describing the outcome
     *                   or reason for the current state
     * @param result     optional terminal result; present only for
     *                   {@link State#SUCCEEDED} and never for non-terminal states
     */
    record OperationStatus(State state, Instant updatedAt, Optional<String> detailCode,
            Optional<OperationResult> result) {

        /** Validates that terminal-result presence matches the lifecycle state. */
        public OperationStatus {
            Objects.requireNonNull(state, "state");
            Objects.requireNonNull(updatedAt, "updatedAt");
            Objects.requireNonNull(detailCode, "detailCode");
            Objects.requireNonNull(result, "result");
            if (state == State.SUCCEEDED && result.isEmpty() || state != State.SUCCEEDED && result.isPresent()) {
                throw new IllegalArgumentException("Operation result does not match status state");
            }
        }

        /**
         * Indicates whether this status represents a terminal lifecycle state.
         *
         * <p>
         * Terminal states are final and must not transition to any other state.
         * </p>
         *
         * @return {@code true} if the operation is terminal, {@code false} otherwise
         */
        public boolean isTerminal() {
            return state == State.SUCCEEDED || state == State.FAILED || state == State.CANCELLED
                    || state == State.EXPIRED;
        }
    }

    /**
     * Lifecycle states of a signature workflow operation.
     *
     * <p>
     * The state machine is intentionally minimal to accommodate both local
     * (in-process) and remote or multi-hop providers.
     * </p>
     *
     * <ul>
     * <li>{@link #PENDING} – operation accepted but not yet actively processed</li>
     * <li>{@link #RUNNING} – operation is currently being processed</li>
     * <li>{@link #WAITING_APPROVAL} – operation is suspended awaiting external
     * approval (e.g. human review, policy gate, HSM quorum)</li>
     * <li>{@link #SUCCEEDED} – operation completed successfully</li>
     * <li>{@link #FAILED} – operation permanently failed due to validation, policy,
     * or execution error</li>
     * <li>{@link #CANCELLED} – operation was explicitly cancelled by the
     * caller</li>
     * <li>{@link #EXPIRED} – operation expired before completion</li>
     * </ul>
     *
     * <p>
     * Providers must document which transitions they support and under which
     * conditions a given state may be observed.
     * </p>
     */
    enum State {
        /** Accepted but not yet actively processed. */
        PENDING,
        /** Provider processing is active. */
        RUNNING,
        /** Processing is suspended for an external approval. */
        WAITING_APPROVAL,
        /** Operation completed successfully. */
        SUCCEEDED,
        /** Operation permanently failed. */
        FAILED,
        /** Provider confirmed caller-requested cancellation. */
        CANCELLED,
        /** Deadline elapsed before successful completion. */
        EXPIRED
    }

    /**
     * Terminal result of a signature workflow operation.
     *
     * <p>
     * An {@code OperationResult} is present only when an operation reaches
     * {@link State#SUCCEEDED}. It represents the semantic outcome of the operation
     * without exposing any sensitive key material.
     * </p>
     *
     * <ul>
     * <li>For sign operations, {@link #signature()} contains the generated
     * signature.</li>
     * <li>For verify operations, {@link #verified()} indicates verification
     * outcome.</li>
     * </ul>
     *
     * <p>
     * Exactly one of {@code signature} or {@code verified} is typically present,
     * depending on the operation type.
     * </p>
     *
     * @param signature optional signature artifact for successful sign operations
     * @param verified  optional verification result for successful verify
     *                  operations
     */
    record OperationResult(Optional<EncodedObject> signature, Optional<Boolean> verified) {

        /** Validates optional terminal result values. */
        public OperationResult {
            Objects.requireNonNull(signature, "signature");
            Objects.requireNonNull(verified, "verified");
        }
    }

    /**
     * Callback interface for receiving asynchronous status updates.
     *
     * <p>
     * Providers may invoke this callback from provider-managed threads.
     * Implementations must therefore be thread-safe and must not throw exceptions.
     * Any exception thrown by a {@code NotificationSink} must be ignored by the
     * provider.
     * </p>
     *
     * <p>
     * The callback must be treated as a best-effort notification mechanism and must
     * not be relied upon as the sole source of truth; callers should always be able
     * to query the authoritative state via
     * {@link SignatureWorkflow#status(PkiId, CallControl)}.
     * Delivery may be coalesced or dropped under load. Providers must not require
     * callback processing to finish an operation, and sink implementations should
     * return promptly without waiting for operation-level coordination.
     * </p>
     */
    @FunctionalInterface
    interface NotificationSink {

        /**
         * Notifies about a change in operation status.
         *
         * @param operationId identifier of the affected operation (never {@code null})
         * @param status      new status of the operation (never {@code null})
         */
        void onStatusChanged(PkiId operationId, OperationStatus status);
    }

    /**
     * Handle representing a registered {@link NotificationSink}.
     *
     * <p>
     * Closing the registration unregisters the associated sink. The operation is
     * idempotent and must not throw.
     * </p>
     */
    @SuppressWarnings("PMD.ImplicitFunctionalInterface")
    interface Registration extends AutoCloseable {

        /**
         * Unregisters the associated {@link NotificationSink}.
         */
        @Override
        void close();
    }
}
