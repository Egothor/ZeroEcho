/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.spi.crypto;

import java.io.Closeable;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

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
 * id and payload bytes; it must never parse {@code KeyRef} nor access private
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
 * failure via {@link #status(PkiId)} using {@link OperationStatus#state()} ==
 * {@link State#FAILED} and a stable {@link OperationStatus#detailCode()}.</li>
 * <li>{@link IllegalArgumentException} may be thrown only for programmer errors
 * such as {@code request == null} or {@code operationId == null}. These are not
 * business/policy failures.</li>
 * <li>Providers must ensure {@link OperationStatus#detailCode()} does not
 * contain secrets, key material, or payload fragments; it must be safe for
 * audit logs and API responses.</li>
 * </ul>
 */
public interface SignatureWorkflow extends Closeable {

    /**
     * Provider identifier for diagnostics and audit correlation.
     *
     * @return stable provider id (never blank)
     */
    String id();

    /**
     * Submits a signing request.
     *
     * <p>
     * Providers must never return private key material. The output is a signature
     * (encoded) on success.
     * </p>
     *
     * <h4>Failure model (normative)</h4>
     * <ul>
     * <li>For validation and policy failures: do not throw; return operation id and
     * expose failure via {@link #status(PkiId)} with {@code FAILED} and stable
     * {@code detailCode}.</li>
     * <li>May throw {@link IllegalArgumentException} only for programmer errors
     * (e.g., {@code request == null}).</li>
     * </ul>
     *
     * @param request request (never {@code null})
     * @return operation id (never {@code null})
     */
    PkiId submitSign(SignRequest request);

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
     * expose failure via {@link #status(PkiId)} with {@code FAILED} and stable
     * {@code detailCode}.</li>
     * <li>May throw {@link IllegalArgumentException} only for programmer errors
     * (e.g., {@code request == null}).</li>
     * </ul>
     *
     * @param request request (never {@code null})
     * @return operation id (never {@code null})
     */
    PkiId submitVerify(VerifyRequest request);

    /**
     * Reads current status of an operation.
     *
     * @param operationId operation id (never {@code null})
     * @return status (never {@code null})
     */
    OperationStatus status(PkiId operationId);

    /**
     * Best-effort cancellation.
     *
     * @param operationId operation id (never {@code null})
     * @param reason      non-sensitive reason (never blank)
     * @return true if cancellation was accepted; false if already terminal/unknown
     */
    boolean cancel(PkiId operationId, String reason);

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
     * Signing request.
     *
     * <p>
     * Note: this record performs basic structural validation and may throw
     * {@link IllegalArgumentException} at construction time. Callers building
     * requests for external transports are expected to catch such exceptions and
     * convert them to an appropriate error state before invoking
     * {@link #submitSign(SignRequest)}.
     * </p>
     *
     * @param accessContext              audit/governance context (never
     *                                   {@code null})
     * @param keyRef                     opaque reference to the private key (never
     *                                   {@code null})
     * @param algorithmId                requested signature algorithm id (never
     *                                   blank)
     * @param payload                    payload bytes (never {@code null})
     * @param preferredSignatureEncoding preferred signature encoding (optional)
     * @param deadline                   optional absolute deadline
     */
    record SignRequest(AccessContext accessContext, KeyRef keyRef, String algorithmId, EncodedObject payload,
            Optional<Encoding> preferredSignatureEncoding, Optional<Instant> deadline) {

        public SignRequest {
            Objects.requireNonNull(accessContext, "accessContext");
            Objects.requireNonNull(keyRef, "keyRef");
            Objects.requireNonNull(algorithmId, "algorithmId");
            Objects.requireNonNull(payload, "payload");
            Objects.requireNonNull(preferredSignatureEncoding, "preferredSignatureEncoding");
            Objects.requireNonNull(deadline, "deadline");
            if (algorithmId.isBlank()) {
                throw new IllegalArgumentException("algorithmId must not be blank");
            }
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
     * {@link #submitVerify(VerifyRequest)}.
     * </p>
     *
     * @param accessContext    audit/governance context (never {@code null})
     * @param algorithmId      requested signature algorithm id (never blank)
     * @param payload          signed payload bytes (never {@code null})
     * @param signature        signature bytes (never {@code null})
     * @param publicKeyRef     optional public key reference (preferred)
     * @param publicKeyEncoded optional encoded public key bytes (provider-specific;
     *                         may be unsupported)
     * @param deadline         optional absolute deadline
     */
    record VerifyRequest(AccessContext accessContext, String algorithmId, EncodedObject payload,
            EncodedObject signature, Optional<KeyRef> publicKeyRef, Optional<EncodedObject> publicKeyEncoded,
            Optional<Instant> deadline) {

        public VerifyRequest {
            Objects.requireNonNull(accessContext, "accessContext");
            Objects.requireNonNull(algorithmId, "algorithmId");
            Objects.requireNonNull(payload, "payload");
            Objects.requireNonNull(signature, "signature");
            Objects.requireNonNull(publicKeyRef, "publicKeyRef");
            Objects.requireNonNull(publicKeyEncoded, "publicKeyEncoded");
            Objects.requireNonNull(deadline, "deadline");
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
     * {@link SignatureWorkflow#status(PkiId)}.
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

        public OperationStatus {
            Objects.requireNonNull(state, "state");
            Objects.requireNonNull(updatedAt, "updatedAt");
            Objects.requireNonNull(detailCode, "detailCode");
            Objects.requireNonNull(result, "result");
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
        PENDING, RUNNING, WAITING_APPROVAL, SUCCEEDED, FAILED, CANCELLED, EXPIRED
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
     * to query the authoritative state via {@link SignatureWorkflow#status(PkiId)}.
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
