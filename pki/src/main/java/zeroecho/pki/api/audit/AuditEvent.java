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
package zeroecho.pki.api.audit;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;

/**
 * Auditable event emitted by the PKI core.
 *
 * <p>
 * Audit events may represent high-level PKI operations (issuance, revocation,
 * publication, backup) and attribute access governance outcomes.
 * Implementations must ensure no secrets appear in {@code details}.
 * </p>
 *
 * @param time      event time (server time)
 * @param category  non-empty category (e.g., "ISSUANCE", "REVOCATION",
 *                  "ATTRIBUTE_ACCESS")
 * @param action    non-empty action string (e.g., "ISSUE_END_ENTITY", "REVOKE",
 *                  "READ")
 * @param principal actor responsible for the event
 * @param purpose   purpose of the operation/access
 * @param objectId  optional subject object id (credential id, request id, etc.)
 * @param formatId  optional format id related to the object
 * @param details   additional non-sensitive key/value details
 */
public record AuditEvent(Instant time, String category, String action, Principal principal, Purpose purpose,
        Optional<PkiId> objectId, Optional<FormatId> formatId, Map<String, String> details) {

    /**
     * Creates an audit event.
     *
     * @throws IllegalArgumentException if inputs are invalid or optional
     *                                  containers/maps are null
     */
    public AuditEvent {
        if (time == null) {
            throw new IllegalArgumentException("time must not be null");
        }
        if (category == null || category.isBlank()) {
            throw new IllegalArgumentException("category must not be null/blank");
        }
        if (action == null || action.isBlank()) {
            throw new IllegalArgumentException("action must not be null/blank");
        }
        if (principal == null) {
            throw new IllegalArgumentException("principal must not be null");
        }
        if (purpose == null) {
            throw new IllegalArgumentException("purpose must not be null");
        }
        if (objectId == null) {
            throw new IllegalArgumentException("objectId must not be null");
        }
        if (formatId == null) {
            throw new IllegalArgumentException("formatId must not be null");
        }
        if (details == null) {
            throw new IllegalArgumentException("details must not be null");
        }
    }
}
