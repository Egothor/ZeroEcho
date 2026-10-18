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
package zeroecho.pki.api.orch;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.Principal;

/**
 * Persisted continuation state for an orchestrated workflow.
 *
 * <p>
 * This record is used by orchestrators to persist the minimum information
 * needed to resume long-running workflows after a process restart, according to
 * the selected {@link OrchestrationDurabilityPolicy}.
 * </p>
 *
 * <h2>Storage model</h2>
 * <p>
 * The async bus is the authoritative source for operation lifecycle and status,
 * but it does not persist sensitive payloads and may be configured not to
 * persist results. Orchestrators therefore persist workflow-specific
 * continuation state through {@code PkiStore}.
 * </p>
 *
 * <h2>Security</h2>
 * <ul>
 * <li>{@link #payload()} may contain sensitive information. It must not be
 * logged.</li>
 * <li>When {@link #durabilityPolicy()} is
 * {@link OrchestrationDurabilityPolicy#DURABLE_ENCRYPTED_STATE},
 * {@link #payloadEncoding()} must reflect an encrypted form and the payload
 * must be authenticated using AAD derived from operation identity.</li>
 * </ul>
 *
 * @param opId             async operation identifier (never {@code null})
 * @param type             operation type string (never {@code null})
 * @param owner            operation owner (never {@code null})
 * @param durabilityPolicy durability policy (never {@code null})
 * @param createdAt        creation time (never {@code null})
 * @param updatedAt        last update time (never {@code null})
 * @param expiresAt        expiration/deadline (never {@code null})
 * @param payloadEncoding  encoding of {@link #payload()} (never {@code null})
 * @param payload          optional persisted continuation payload
 */
public record WorkflowStateRecord(PkiId opId, String type, Principal owner,
        OrchestrationDurabilityPolicy durabilityPolicy, Instant createdAt, Instant updatedAt, Instant expiresAt,
        Encoding payloadEncoding, Optional<EncodedObject> payload) {

    /** Validates the complete persisted workflow snapshot. */
    public WorkflowStateRecord {
        Objects.requireNonNull(opId, "opId");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(durabilityPolicy, "durabilityPolicy");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(payloadEncoding, "payloadEncoding");
        Objects.requireNonNull(payload, "payload");

        if (type.isBlank()) {
            throw new IllegalArgumentException("type must not be blank.");
        }
        if (!expiresAt.isAfter(createdAt) && !expiresAt.equals(createdAt)) {
            // Allow expiresAt == createdAt for immediate-expire test scenarios, but reject
            // negative durations.
            if (expiresAt.isBefore(createdAt)) { // NOPMD
                throw new IllegalArgumentException("expiresAt must not be before createdAt.");
            }
        }
    }

    /**
     * Returns whether the record is expired at the provided time.
     *
     * @param now current time (never {@code null})
     * @return {@code true} if {@code now} is strictly after {@link #expiresAt()}
     */
    public boolean isExpiredAt(Instant now) {
        Objects.requireNonNull(now, "now");
        return now.isAfter(expiresAt);
    }
}
