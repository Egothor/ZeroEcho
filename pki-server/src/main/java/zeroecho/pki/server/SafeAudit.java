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
package zeroecho.pki.server;

import java.time.Clock;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.server.jfr.AuditWriteEvent;

/** Package-private safe server audit producer. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class SafeAudit {
    private final Clock clock;
    private final AuditSink sink;

    SafeAudit(Clock clock, AuditSink sink) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.sink = Objects.requireNonNull(sink, "sink");
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException") // AuditSink defines RuntimeException as its failure boundary.
    void record(String action, String principalId, Optional<PkiId> objectId, Map<String, String> details) {
        AuditWriteEvent jfrEvent = new AuditWriteEvent();
        jfrEvent.category = "SERVER_SECURITY";
        jfrEvent.recordCount = 1;
        jfrEvent.fsync = false;
        jfrEvent.begin();
        try {
            AuditEvent event = new AuditEvent(clock.instant(), "SERVER_SECURITY", action,
                    new Principal("SERVER_PRINCIPAL", principalId), new Purpose("SERVER_CONTROL"),
                    Objects.requireNonNull(objectId, "objectId"), Optional.empty(), Map.copyOf(details));
            sink.record(event);
        } catch (RuntimeException ignored) {
            // Immediate server telemetry is best effort; authoritative state remains the source of truth.
        } finally {
            if (jfrEvent.shouldCommit()) {
                jfrEvent.commit();
            }
        }
    }
}
