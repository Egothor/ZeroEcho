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

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialUse;
import zeroecho.pki.api.credential.EffectiveCredentialStatus;
import zeroecho.pki.spi.audit.AuditSink;

/**
 * Emits one best-effort, redacted caller-level credential trust rejection.
 */
final class CredentialTrustAudit {
    private static final Principal SYSTEM_PKI = new Principal("SYSTEM", "pki");
    private static final Purpose TRUST_PURPOSE = new Purpose("CREDENTIAL_TRUST");

    private CredentialTrustAudit() {
        // Utility class.
    }

    // Best-effort audit callbacks are untrusted; broad catch and empty handling preserve
    // the authoritative trust rejection without exposing listener diagnostics.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.EmptyCatchBlock" })
    /* default */ static void rejected(AuditSink sink, Instant time, Credential credential, CredentialUse use,
            String code, EffectiveCredentialStatus status) {
        Map<String, String> details = status == null
                ? Map.of("code", code, "operation", use.name())
                : Map.of("code", code, "operation", use.name(), "effectiveStatus", status.name());
        try {
            sink.record(new AuditEvent(time, "CREDENTIAL_TRUST", "CREDENTIAL_REJECTED", SYSTEM_PKI, TRUST_PURPOSE,
                    Optional.of(credential.credentialId()), Optional.empty(), details));
        } catch (RuntimeException auditFailure) {
            // Best-effort auditing must not change the trust decision or expose sink data.
        }
    }
}
