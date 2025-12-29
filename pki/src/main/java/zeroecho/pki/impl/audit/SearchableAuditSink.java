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
package zeroecho.pki.impl.audit;

import java.util.List;
import java.util.Optional;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.AuditQuery;

/**
 * Internal query extension for audit sinks.
 *
 * <p>
 * The public SPI {@code zeroecho.pki.spi.AuditSink} is record-only. Sinks may
 * also implement this internal interface to support
 * {@link zeroecho.pki.api.audit.AuditService#search(AuditQuery)} and
 * {@link zeroecho.pki.api.audit.AuditService#get(PkiId)}.
 * </p>
 */
interface SearchableAuditSink {

    /**
     * Searches persisted events by query constraints.
     *
     * @param query query constraints (must not be null)
     * @return immutable list of matching events (never null)
     * @throws IllegalArgumentException if {@code query} is null
     * @throws RuntimeException         on storage failure
     */
    List<AuditEvent> search(AuditQuery query);

    /**
     * Retrieves a persisted event by stable id.
     *
     * @param eventId stable event id (must not be null)
     * @return event if present
     * @throws IllegalArgumentException if {@code eventId} is null
     * @throws RuntimeException         on storage failure
     */
    Optional<AuditEvent> getById(PkiId eventId);
}
