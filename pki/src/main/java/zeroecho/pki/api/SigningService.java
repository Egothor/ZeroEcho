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

package zeroecho.pki.api;

import java.util.Optional;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.OneShotContent;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.signing.PreparedSigningRequest;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.api.signing.SigningAcceptanceResolution;
import zeroecho.pki.api.signing.SigningAcceptanceResult;
import zeroecho.pki.api.signing.SigningOperation;
import zeroecho.pki.api.signing.SigningRequest;

/**
 * Privileged, session-owned application boundary for durable signing.
 *
 * <p>Callers must already be authenticated and authorized. Identifiers and
 * receipts prove durable identity, not authority; a transport adapter must
 * derive or cross-check the access context, key reference, and fairness
 * authority before invoking this service. Implementations are thread-safe and
 * retain no per-operation handle.</p>
 */
public interface SigningService {
    /**
     * Returns a fresh identifier in this service's configured namespace.
     *
     * @return fresh submission identity
     */
    SigningSubmissionId newSubmissionId();

    /**
     * Streams a one-shot candidate into durable staging without accepting it.
     * The returned value must be passed exactly once to {@link #accept} or
     * {@link #discard}; successful preparation transfers staged-candidate
     * custody to the caller. The request's exact signature identity must satisfy
     * the PKI security floor and the selected provider's supported-algorithm set
     * before staging begins. This privileged opaque-content operation does not
     * export the key or perform certificate-specific algorithm/binding planning.
     *
     * @param request authorized signing metadata including the exact signature identity
     * @param candidate one-shot candidate bytes
     * @param cancellation cooperative staging cancellation
     * @return opaque prepared request and recovery receipt binding that identity
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if metadata, algorithm support or the security floor is invalid
     * @throws PkiException if candidate staging fails
     * @throws SigningExecutionException if the owning session no longer accepts preparation
     */
    PreparedSigningRequest prepare(SigningRequest request, OneShotContent candidate,
            CancellationSignal cancellation);

    /**
     * Prepares raw signing with one durable initial dispatch and at most one initial
     * provider observation. Preparation, custody, validation and staging have the
     * same contract as {@link #prepare}; the execution mode is bound into the receipt.
     * A pending observation completes this initial attempt without terminating the
     * durable operation. Subsequent cancellation and cleanup remain reactor-owned.
     *
     * @param request authorized signing metadata including the exact signature identity
     * @param candidate one-shot candidate bytes
     * @param cancellation cooperative staging cancellation
     * @return opaque prepared request and mode-bound recovery receipt
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if metadata, algorithm support or the security floor is invalid
     * @throws PkiException if candidate staging fails
     * @throws SigningExecutionException if the owning session no longer accepts preparation
     */
    PreparedSigningRequest prepareBoundedObservation(SigningRequest request, OneShotContent candidate,
            CancellationSignal cancellation);

    /**
     * Waits for the accepted bounded initial attempt and returns the current retained
     * operation snapshot. Completion may still be pending; later cleanup may already
     * have advanced the snapshot. A failed initial attempt always raises a safe
     * failure, even if subsequent cleanup observes successful signing. This method
     * never dispatches, observes or cancels a provider operation on the caller thread.
     *
     * <p>Cancelling or interrupting this wait affects only the wait, not the durable
     * operation; use {@link #cancel} for durable cancellation. Signal-only cancellation
     * is checked at most once per idle poll interval plus scheduling and store-I/O
     * latency. Interruption preserves the thread's interrupt status. Waiting retains
     * O(1) bookkeeping and no per-operation registration or workflow across sleeps.</p>
     *
     * @param operationId accepted operation identity
     * @param cancellation cooperative wait cancellation
     * @return current snapshot, or empty when unknown, outside this service's namespace or purged
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if the retained operation uses ordinary signing mode
     * @throws PkiException if the initial attempt failed, waiting was cancelled/interrupted or a store read fails
     * @throws SigningExecutionException if the owning session is shutting down
     */
    Optional<SigningOperation> awaitBoundedObservation(PkiId operationId, CancellationSignal cancellation);

    /**
     * Transfers prepared-candidate custody to durable workflow acceptance.
     * Provider input limits are selected for the exact request algorithm before
     * custody transfer. The immutable request identity is retained in the durable
     * envelope and receipt commitment, independently of the session's default.
     *
     * @param prepared service-issued prepared request
     * @return durable acceptance disposition and recovery receipt
     */
    SigningAcceptanceResult accept(PreparedSigningRequest prepared);

    /**
     * Resolves an acceptance whose committing call had an uncertain outcome.
     *
     * @param receipt recovery receipt returned by preparation or acceptance
     * @return authoritative acceptance resolution
     */
    SigningAcceptanceResolution resolve(SigningAcceptanceReceipt receipt);

    /**
     * Returns the authoritative retained operation, if known.
     *
     * @param operationId operation identity
     * @return current retained snapshot, or empty when unknown or purged
     */
    Optional<SigningOperation> find(PkiId operationId);

    /**
     * Requests durable cancellation and returns the authoritative result.
     *
     * @param operationId operation identity
     * @return current retained snapshot, or empty when unknown or purged
     */
    Optional<SigningOperation> cancel(PkiId operationId);

    /**
     * Releases a prepared candidate that will not be accepted.
     *
     * @param prepared service-issued prepared request
     */
    void discard(PreparedSigningRequest prepared);
}
