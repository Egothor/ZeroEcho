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
package zeroecho.pki.impl.core;

import java.time.Clock;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.spi.audit.AuditSink;

/** Emits minimal best-effort credential-confirmation proof outcomes. */
final class CredentialConfirmationAudit {
    private static final Principal SYSTEM_PKI = new Principal("SYSTEM", "pki");
    private static final Purpose CONFIRMATION_PURPOSE = new Purpose("CREDENTIAL_CONFIRMATION");
    private static final String CATEGORY = "CREDENTIAL_CONFIRMATION";

    private final Optional<AuditSink> sink;
    private final Clock clock;

    /* default */ CredentialConfirmationAudit(Optional<AuditSink> sink, Clock clock) {
        this.sink = Objects.requireNonNull(sink, "auditSink");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /* default */ void challengeAvailable(PkiId credentialId) {
        emit(credentialId, "PROOF_CHALLENGE", "AVAILABLE");
    }

    /* default */ void submission(PkiId credentialId, String result) {
        emit(credentialId, "PROOF_SUBMISSION", result);
    }

    private void emit(PkiId credentialId, String action, String result) {
        sink.ifPresent(value -> record(value, credentialId, action, result));
    }

    // Audit sinks are external best-effort callbacks. Runtime failures cannot
    // alter a successful persisted outcome or expose listener diagnostics.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private void record(AuditSink value, PkiId credentialId, String action, String result) {
        try {
            value.record(new AuditEvent(clock.instant(), CATEGORY, action,
                    SYSTEM_PKI, CONFIRMATION_PURPOSE, Optional.of(credentialId),
                    Optional.empty(), Map.of("result", result)));
        } catch (RuntimeException ignored) {
            // Best-effort auditing must not change confirmation state or results.
        }
    }
}
