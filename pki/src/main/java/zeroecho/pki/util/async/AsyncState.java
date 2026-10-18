/* *****************************************************************************
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
package zeroecho.pki.util.async;

/**
 * Lifecycle state of an asynchronous operation.
 *
 * <p>
 * The state machine is intentionally simple and audit-friendly. Implementations
 * may attach additional non-sensitive detail through
 * {@link AsyncStatus#detailCode()} and {@link AsyncStatus#details()}.
 * </p>
 */
public enum AsyncState {

    /**
     * The operation has been created and is awaiting processing.
     *
     * <p>
     * Example: a certificate issuance request has been accepted, but is waiting for
     * an operator approval step.
     * </p>
     */
    SUBMITTED,

    /**
     * The operation is currently being processed.
     *
     * <p>
     * Example: an issuance request is being built, proof-of-possession verified, or
     * a signing workflow is executing.
     * </p>
     */
    RUNNING,

    /**
     * The operation completed successfully and the result is available for
     * retrieval.
     *
     * <p>
     * Example: a certificate (or bundle) has been issued and is ready to be
     * fetched.
     * </p>
     */
    SUCCEEDED,

    /**
     * The operation completed unsuccessfully (terminal failure).
     *
     * <p>
     * Example: proof-of-possession verification failed or a policy rule rejected
     * the request. The failure reason should be exposed via a stable, non-secret
     * {@link AsyncStatus#detailCode()} and optional {@link AsyncStatus#details()}.
     * </p>
     */
    FAILED,

    /**
     * The operation was cancelled by a caller or operator.
     *
     * <p>
     * Example: an administrator cancelled a long-running operation before it was
     * approved.
     * </p>
     */
    CANCELLED,

    /**
     * The operation exceeded its declared deadline and was expired by the bus.
     *
     * <p>
     * Example: a request had a 24h approval window; after that it is no longer
     * eligible for completion and is treated as expired.
     * </p>
     */
    EXPIRED
}
