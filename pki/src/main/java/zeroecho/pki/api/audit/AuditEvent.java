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
package zeroecho.pki.api.audit;

import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;

/**
 * Auditable event emitted by the PKI core and governance layer.
 *
 * <p>
 * An {@code AuditEvent} is an immutable, structured record describing a
 * security-relevant action or outcome. Typical event categories include
 * high-level PKI operations (issuance, revocation, publication, backup) and
 * attribute-level governance decisions (read/export attempts and outcomes).
 * </p>
 *
 * <h2>Security properties</h2>
 * <ul>
 * <li><strong>No secrets:</strong> {@link #details()} MUST NOT contain secrets
 * (keys, seeds, shared secrets, plaintext, private material, or other sensitive
 * cryptographic/internal state). It is intended for non-sensitive metadata only
 * (e.g., decision, policy id, reason codes, counters).</li>
 * <li><strong>Minimality:</strong> callers should prefer coarse,
 * non-identifying fields and avoid excessive detail. If an identifier is
 * needed, prefer {@link #objectId()} and a stable, non-secret reference.</li>
 * </ul>
 *
 * <h2>Determinism and ordering</h2>
 * <p>
 * The static comparator returned by {@link #auditOrder()} defines a
 * deterministic order for presentation and query results. It does not imply
 * causality; it is purely a stable sort key.
 * </p>
 *
 * <h2>Validation</h2>
 * <p>
 * This record enforces basic invariants: time is non-null, {@code category} and
 * {@code action} are non-blank, {@code principal} and {@code purpose} are
 * non-null, and optional containers/maps are non-null.
 * </p>
 *
 * @param time      event time (server time), never {@code null}
 * @param category  non-blank category (e.g., {@code "ISSUANCE"},
 *                  {@code "REVOCATION"}, {@code "ATTRIBUTE_ACCESS"})
 * @param action    non-blank action string (e.g., {@code "ISSUE_END_ENTITY"},
 *                  {@code "REVOKE"}, {@code "READ"})
 * @param principal actor responsible for the event, never {@code null}
 * @param purpose   declared purpose of the operation/access, never {@code null}
 * @param objectId  optional subject object id (credential id, request id,
 *                  attribute id, etc.), never {@code null}
 * @param formatId  optional format id related to the object (e.g., encoding),
 *                  never {@code null}
 * @param details   additional non-sensitive key/value details, never
 *                  {@code null}
 */
public record AuditEvent(Instant time, String category, String action, Principal principal, Purpose purpose,
        Optional<PkiId> objectId, Optional<FormatId> formatId, Map<String, String> details) {

    /**
     * Creates an audit event and validates record invariants.
     *
     * <p>
     * Note that this constructor does not (and cannot) automatically prove the
     * absence of secrets in {@link #details()}. The responsibility to redact and
     * constrain details is on the event producer.
     * </p>
     *
     * @throws IllegalArgumentException if {@code time} is {@code null},
     *                                  {@code category/action} are blank,
     *                                  {@code principal/purpose} are {@code null},
     *                                  or any of {@code objectId/formatId/details}
     *                                  are {@code null}
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

    /**
     * Returns a deterministic comparator for audit events.
     *
     * <p>
     * The comparator orders events by: {@code time}, {@code category},
     * {@code action}, {@code principal.type}, {@code principal.name}.
     * </p>
     *
     * <p>
     * This ordering is intended for consistent presentation and stable test
     * assertions. It is not a security primitive.
     * </p>
     *
     * @return deterministic comparator, never {@code null}
     */
    public static Comparator<AuditEvent> auditOrder() {
        return Comparator.comparing(AuditEvent::time).thenComparing(AuditEvent::category)
                .thenComparing(AuditEvent::action).thenComparing(e -> e.principal().type())
                .thenComparing(e -> e.principal().name());
    }

    /**
     * Evaluates whether this event matches a query constraint set.
     *
     * <p>
     * Matching semantics:
     * </p>
     * <ul>
     * <li>If {@code query.category} is present, it must equal
     * {@link #category()}.</li>
     * <li>If {@code query.action} is present, it must equal {@link #action()}.</li>
     * <li>If {@code query.after} is present, event time must be {@code >= after}
     * (implemented as {@code !time.isBefore(after)}).</li>
     * <li>If {@code query.before} is present, event time must be {@code <= before}
     * (implemented as {@code !time.isAfter(before)}).</li>
     * <li>If {@code query.objectId} is present, it must equal {@link #objectId()}
     * (empty optional does not match).</li>
     * <li>If {@code query.principalName} is present, it must equal
     * {@link #principal()}.{@code name()}.</li>
     * </ul>
     *
     * <p>
     * This method is side-effect free and deterministic.
     * </p>
     *
     * @param query query constraints, must not be {@code null}
     * @return {@code true} if this event matches all present constraints;
     *         {@code false} otherwise
     * @throws NullPointerException if {@code query} is {@code null}
     */
    public boolean matches(AuditQuery query) {
        Objects.requireNonNull(query, "query");

        if (query.category().isPresent() && !query.category().get().equals(category())) {
            return false;
        }
        if (query.action().isPresent() && !query.action().get().equals(action())) {
            return false;
        }
        if (query.after().isPresent() && time().isBefore(query.after().get())) {
            return false;
        }
        if (query.before().isPresent() && time().isAfter(query.before().get())) {
            return false;
        }
        if (query.objectId().isPresent() && !query.objectId().get().equals(objectId().orElse(null))) {
            return false;
        }
        if (query.principalName().isPresent() && !query.principalName().get().equals(principal().name())) { // NOPMD
            return false;
        }
        return true;
    }
}
