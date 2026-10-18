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
package zeroecho.pki.api.audit;

import java.util.List;
import java.util.Optional;

import zeroecho.pki.api.PkiId;

/**
 * Records and queries audit events for PKI operations and attribute governance.
 *
 * <p>
 * Implementations must ensure sensitive data is never stored or logged in clear
 * text.
 * </p>
 */
public interface AuditService {

    /**
     * Records an audit event.
     *
     * @param event audit event
     * @throws IllegalArgumentException if {@code event} is null
     * @throws RuntimeException         if recording fails (implementation-defined)
     */
    void record(AuditEvent event);

    /**
     * Searches audit events by query constraints.
     *
     * @param query query constraints
     * @return matching audit events
     * @throws IllegalArgumentException if {@code query} is null
     * @throws RuntimeException         if search fails
     */
    List<AuditEvent> search(AuditQuery query);

    /**
     * Retrieves an audit event by id if the implementation assigns stable ids.
     *
     * @param eventId event id
     * @return audit event if present
     * @throws IllegalArgumentException if {@code eventId} is null
     * @throws RuntimeException         if retrieval fails
     */
    Optional<AuditEvent> get(PkiId eventId);
}
