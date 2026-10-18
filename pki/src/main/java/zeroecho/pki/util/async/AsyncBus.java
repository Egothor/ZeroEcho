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

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Generic asynchronous operation bus.
 *
 * <p>
 * The bus is responsible for:
 * </p>
 * <ul>
 * <li>tracking operation metadata and status transitions,</li>
 * <li>optional durability (implementation-defined),</li>
 * <li>dispatching events to registered handlers,</li>
 * <li>expiring operations that exceeded their deadline,</li>
 * <li>forgetting completed results once retrieved (to avoid unbounded
 * growth).</li>
 * </ul>
 *
 * <h2>Result retention</h2>
 * <p>
 * Results are retained until explicitly retrieved (or expired by retention
 * policy). Implementations must remove stored results once
 * {@link #consumeResult(Object)} returns a value. This ensures bounded memory
 * usage.
 * </p>
 *
 * @param <OpId>       operation id type
 * @param <Owner>      owner type
 * @param <EndpointId> endpoint id type
 * @param <Result>     result type
 */
public interface AsyncBus<OpId, Owner, EndpointId, Result> {

    /**
     * Registers an endpoint instance under an identifier.
     *
     * <p>
     * Registration must be performed by the endpoint itself during construction or
     * activation, not by bootstrap code, to avoid tight coupling.
     * </p>
     *
     * @param endpointId endpoint id (never {@code null})
     * @param endpoint   endpoint instance (never {@code null})
     */
    void registerEndpoint(EndpointId endpointId, AsyncEndpoint<OpId, Result> endpoint);

    /**
     * Subscribes a handler to status change events.
     *
     * @param handler handler (never {@code null})
     * @return registration handle (never {@code null})
     */
    AsyncRegistration subscribe(AsyncHandler<OpId, Owner, EndpointId, Result> handler);

    /**
     * Creates a new operation record and sets initial status to
     * {@link AsyncState#SUBMITTED}.
     *
     * @param opId       operation id (never {@code null})
     * @param type       operation type (never blank)
     * @param owner      owner (never {@code null})
     * @param endpointId endpoint id (never {@code null})
     * @param createdAt  creation time (never {@code null})
     * @param ttl        time-to-live (must be positive)
     * @return created snapshot (never {@code null})
     */
    AsyncOperationSnapshot<OpId, Owner, EndpointId> submit(OpId opId, String type, Owner owner, EndpointId endpointId,
            Instant createdAt, Duration ttl);

    /**
     * Updates status and optional result for an operation.
     *
     * <p>
     * Implementations must persist the transition before dispatching events.
     * </p>
     *
     * @param opId   operation id (never {@code null})
     * @param status new status (never {@code null})
     * @param result optional result (never {@code null})
     */
    void update(OpId opId, AsyncStatus status, Optional<Result> result);

    /**
     * Retrieves the latest known status for an operation.
     *
     * @param opId operation id (never {@code null})
     * @return status if known
     */
    Optional<AsyncStatus> status(OpId opId);

    /**
     * Returns immutable operation metadata if present.
     *
     * @param opId operation id (never {@code null})
     * @return snapshot if known
     */
    Optional<AsyncOperationSnapshot<OpId, Owner, EndpointId>> snapshot(OpId opId);

    /**
     * Consumes the stored result if present and removes it from the bus.
     *
     * @param opId operation id (never {@code null})
     * @return result if present (and then removed)
     */
    Optional<Result> consumeResult(OpId opId);

    /**
     * Performs periodic maintenance:
     *
     * <ul>
     * <li>expires operations past their deadline,</li>
     * <li>polls endpoints for open operations (restart recovery),</li>
     * <li>dispatches any discovered transitions.</li>
     * </ul>
     *
     * @param now current time (never {@code null})
     */
    void sweep(Instant now);
}
