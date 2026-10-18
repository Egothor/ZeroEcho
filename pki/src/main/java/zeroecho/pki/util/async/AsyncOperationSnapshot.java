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

import java.time.Instant;
import java.util.Objects;

/**
 * Immutable snapshot of an operation's identity and routing metadata.
 *
 * <p>
 * This object intentionally does not contain secrets. Payloads should be stored
 * outside the bus (or referenced indirectly).
 * </p>
 *
 * @param <OpId>       operation identifier type
 * @param <Owner>      operation owner type
 * @param <EndpointId> endpoint identifier type
 * @param opId         operation id (never {@code null})
 * @param type         operation type string (never blank)
 * @param owner        operation owner (never {@code null})
 * @param endpointId   endpoint id (never {@code null})
 * @param createdAt    creation time (never {@code null})
 * @param expiresAt    expiration deadline (never {@code null})
 */
public record AsyncOperationSnapshot<OpId, Owner, EndpointId>(OpId opId, String type, Owner owner,
        EndpointId endpointId, Instant createdAt, Instant expiresAt) {

    /**
     * Creates a snapshot and validates invariants.
     *
     * @throws IllegalArgumentException if required fields are null/blank or expiry
     *                                  is invalid
     */
    public AsyncOperationSnapshot {
        Objects.requireNonNull(opId, "opId");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(endpointId, "endpointId");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (type.isBlank()) {
            throw new IllegalArgumentException("type must not be blank");
        }
        if (!expiresAt.isAfter(createdAt)) {
            throw new IllegalArgumentException("expiresAt must be after createdAt");
        }
    }
}
