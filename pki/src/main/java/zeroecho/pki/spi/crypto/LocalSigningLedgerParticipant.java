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

import java.time.Duration;
import java.time.Instant;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;

/**
 * Borrowed process-local capability for a workflow participating in its owning
 * store's signing ledger.
 *
 * <p>The capability is supplied only to trusted in-process workflow providers.
 * The store owns its lifecycle; borrowers must not close, retain beyond the
 * allocated workflow lifetime, wrap, proxy, persist, serialize, or expose it.
 * Implementations are thread-safe. This port contains no filesystem or durable
 * record representation.</p>
 */
public interface LocalSigningLedgerParticipant {
    /** Result of accepting local cryptographic execution. */
    enum Acceptance {
        /** This invocation durably acquired the right to execute cryptography once. */
        EXECUTE,
        /** The identical request is already accepted or terminal. */
        ATTACHED
    }

    /**
     * Returns store-authoritative monotonic time.
     *
     * @return current store-authoritative time
     */
    Instant signingNow();

    /**
     * Returns the store/provider namespace accepted by this participant.
     *
     * @param providerId stable provider identifier
     * @return authoritative local signing namespace
     */
    String localSigningNamespace(String providerId);

    /**
     * Returns the configured signing-identity retention horizon.
     *
     * @return positive retention horizon
     */
    Duration signingHorizon();

    /**
     * Accepts local execution without orchestrator authority metadata.
     *
     * <p>Production stores may reject this narrow hook when atomic orchestrator
     * authority is required.</p>
     *
     * @param request exact provider request
     * @return local acceptance outcome
     * @throws IllegalStateException when atomic orchestrator authority is required
     */
    default Acceptance acceptLocalSign(SignatureWorkflow.SignRequest request) {
        throw new IllegalStateException("Local signing authority is required: code=LOCAL_SIGN_AUTHORITY_REQUIRED");
    }

    /**
     * Atomically publishes a local terminal provider and orchestrator outcome.
     *
     * @param request accepted provider request
     * @param terminal terminal provider status
     * @return {@code true} when the outcome was published or already identical
     */
    boolean completeLocalSign(SignatureWorkflow.SignRequest request, SignatureWorkflow.OperationStatus terminal);

    /**
     * Returns the store-owned cancellation signal for an executing operation.
     *
     * @param operationId durable operation identifier
     * @return borrowed cancellation signal
     */
    CancellationSignal localCancellation(PkiId operationId);

    /**
     * Reads the provider view derived from the canonical orchestrator record.
     *
     * @param operationId durable operation identifier
     * @return current provider-visible status
     */
    SignatureWorkflow.OperationStatus localSignStatus(PkiId operationId);

    /**
     * Applies a fenced local cancellation.
     *
     * @param operationId durable operation identifier
     * @param fencingToken current fencing token
     * @return {@code true} when cancellation was applied or already authoritative
     */
    boolean cancelLocalSign(PkiId operationId, long fencingToken);
}
