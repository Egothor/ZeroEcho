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

package zeroecho.pki.application;

import java.time.Clock;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.spi.audit.AuditSink;

/** Best-effort local invocation attribution, separate from immutable accepted evidence. */
final class LocalInvocationAudit {
    private final AuditSink sink;
    private final Clock clock;
    private final Principal operator;

    /* default */ LocalInvocationAudit(AuditSink sink, Clock clock, Principal operator) {
        this.sink = Objects.requireNonNull(sink, "sink");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.operator = Objects.requireNonNull(operator, "operator");
    }

    /* default */ AccessContext access(String operation) {
        return new AccessContext(operator, new Purpose(operation), Optional.empty(), Optional.empty());
    }

    /* default */ // Local invocation auditing remains best effort under its existing sink-failure contract.
                  @SuppressWarnings({ "PMD.AvoidCatchingGenericException" })
                  void record(String operation, String action, Optional<PkiId> id, String result) {
        try {
            sink.record(new AuditEvent(clock.instant(), "LOCAL_PKI", action, operator,
                    new Purpose(operation), id, Optional.empty(), Map.of("result", result)));
        } catch (RuntimeException ignored) {
            // Existing audit callbacks are best effort and cannot change an authoritative outcome.
        }
    }
}
