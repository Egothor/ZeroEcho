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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.impl.core.async.DomainAttributeEncoding;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.AuditEvidenceFeed;

/** Maps issuance-evidence feed entries to payload-free audit events (Task 8a issuance adapter). */
class IssuanceAuditProjectionTest {
    private static final String COMMITMENT = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private static final Instant TIME = Instant.parse("2026-08-04T12:00:00Z");

    @Test
    void projectsAdministrativeIssuanceEvidence() {
        IssuanceExecutionEvidence evidence = IssuanceExecutionEvidence.administrative("operator-a", "production",
                "correlation-1", IssuanceExecutionEvidence.Authentication.DIRECT_MTLS,
                IssuanceExecutionEvidence.AuthorizationPath.APPROVAL, COMMITMENT, "ca-a", "leaf");
        AuditEvidenceFeed.Entry entry = new AuditEvidenceFeed.Entry(0L, new PkiId("x509:abc"), TIME,
                DomainAttributeEncoding.encode(evidence.attributes()).getBytes(StandardCharsets.UTF_8));

        AuditEvent event = IssuanceAuditProjection.toEvent(entry).orElseThrow();
        assertEquals("ISSUANCE", event.category());
        assertEquals("CREDENTIAL_ISSUED", event.action());
        assertEquals(TIME, event.time());
        assertEquals("operator-a", event.principal().name());
        assertEquals(Optional.of(new PkiId("x509:abc")), event.objectId());
        assertEquals("ca-a", event.details().get("issuerCaId"));
        assertEquals("leaf", event.details().get("profileId"));
        assertEquals("x509:abc", event.details().get("credentialId"));
        assertEquals("APPROVAL", event.details().get("authorizationPath"));
        assertEquals(COMMITMENT, event.details().get("operationCommitment"));
        assertTrue(event.details().containsKey("eventId"));
        // No certificate content, subject, SAN, or key material leaks into the projected event.
        assertFalse(event.details().containsKey("subject"));
        assertFalse(event.details().containsKey("csr"));
    }

    @Test
    void skipsCredentialsWithoutIssuanceEvidence() {
        byte[] payload = DomainAttributeEncoding.encode(SimpleAttributeSet.builder().build())
                .getBytes(StandardCharsets.UTF_8);
        AuditEvidenceFeed.Entry entry = new AuditEvidenceFeed.Entry(0L, new PkiId("x509:abc"), TIME, payload);
        assertTrue(IssuanceAuditProjection.toEvent(entry).isEmpty());
    }

    @Test
    void deterministicEventIdIsStableAcrossReprojection() {
        IssuanceExecutionEvidence evidence = IssuanceExecutionEvidence.acme("acct-1", "production", "corr-2",
                "ca-a", "leaf");
        byte[] payload = DomainAttributeEncoding.encode(evidence.attributes()).getBytes(StandardCharsets.UTF_8);
        AuditEvidenceFeed.Entry entry = new AuditEvidenceFeed.Entry(7L, new PkiId("x509:def"), TIME, payload);
        String first = IssuanceAuditProjection.toEvent(entry).orElseThrow().details().get("eventId");
        String second = IssuanceAuditProjection.toEvent(entry).orElseThrow().details().get("eventId");
        assertEquals(first, second);
    }
}
