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

package zeroecho.pki.application;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;

/**
 * Session-borrowed synchronous local signing. Calls execute sequentially on the
 * caller thread; concurrent calls or closing the session during a call are unsupported.
 * No reactor, retry scheduler, worker thread, or background completion is started.
 */
public interface LocalSigningExecutor {
    /**
     * Prepares, accepts once, and executes an explicitly approved local command.
     * @param operation command approved by the configured local root operator
     * @param cancellation cooperative cancellation; cancellation does not imply rollback
     * @return domain completion or explicit failure retaining any available receipt
     * @throws IllegalStateException if the owning session is closed
     * @throws NullPointerException if an argument is null
     */
    LocalSigningResult execute(PkiSigningOperation operation, CancellationSignal cancellation);

    /**
     * Reads the selected persisted operation without claiming work or completing it.
     * The access is audited under the configured local operator identity.
     * @param operationId exact previously accepted identity
     * @param cancellation cooperative cancellation
     * @return safe state and completion metadata, or a classified read failure
     * @throws IllegalStateException if the owning session is closed
     * @throws NullPointerException if an argument is null
     */
    PkiOperationOutcome inspect(PkiId operationId, CancellationSignal cancellation);

    /**
     * Advances only the selected persisted operation, preserving its original actor.
     * Live leases and future retries return immediately without sleeping or forcing claims.
     * @param operationId exact previously accepted identity
     * @param cancellation cooperative cancellation
     * @return existing completion or safe failure retaining any available receipt
     * @throws IllegalStateException if the owning session is closed
     * @throws NullPointerException if an argument is null
     */
    LocalSigningResult complete(PkiId operationId, CancellationSignal cancellation);
}
