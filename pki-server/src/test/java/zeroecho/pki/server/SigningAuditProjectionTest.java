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
import zeroecho.pki.application.SigningExecutionEvidence;
import zeroecho.pki.impl.core.continuation.DomainAttributeEncoding;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.AuditEvidenceFeed;

/** Maps signing-evidence feed entries to payload-free key-usage audit events through the signing adapter. */
class SigningAuditProjectionTest {
    private static final Instant TIME = Instant.parse("2026-08-04T12:00:00Z");
    private static final String FINGERPRINT = "ab".repeat(32);

    @Test
    void projectsSuccessfulSigning() {
        SigningExecutionEvidence evidence = SigningExecutionEvidence.terminal("realm.ca-a", FINGERPRINT,
                "COMPONENT", "issuance-bus", Optional.of("SIGNED"), SigningExecutionEvidence.Outcome.SIGNED);
        AuditEvidenceFeed.Entry entry = new AuditEvidenceFeed.Entry(0L, new PkiId("sign:1"), TIME,
                DomainAttributeEncoding.encode(evidence.attributes()).getBytes(StandardCharsets.UTF_8));

        AuditEvent event = SigningAuditProjection.toEvent(entry).orElseThrow();
        assertEquals("SIGNING", event.category());
        assertEquals("SIGNATURE_PRODUCED", event.action());
        assertEquals("COMPONENT", event.principal().type());
        assertEquals("issuance-bus", event.principal().name());
        assertEquals(Optional.of(new PkiId("sign:1")), event.objectId());
        assertEquals("realm.ca-a", event.details().get("namespace"));
        assertEquals(FINGERPRINT, event.details().get("fingerprint"));
        assertTrue(event.details().containsKey("eventId"));
        // No to-be-signed content, signature bytes, or key material leaks into the projected event.
        assertFalse(event.details().containsKey("signature"));
        assertFalse(event.details().containsKey("tbs"));
    }

    @Test
    void projectsFailedSigning() {
        SigningExecutionEvidence evidence = SigningExecutionEvidence.terminal("realm.ca-a", FINGERPRINT,
                "COMPONENT", "issuance-bus", Optional.of("PROVIDER_RESULT_INVALID"),
                SigningExecutionEvidence.Outcome.FAILED);
        AuditEvidenceFeed.Entry entry = new AuditEvidenceFeed.Entry(2L, new PkiId("sign:2"), TIME,
                DomainAttributeEncoding.encode(evidence.attributes()).getBytes(StandardCharsets.UTF_8));

        AuditEvent event = SigningAuditProjection.toEvent(entry).orElseThrow();
        assertEquals("SIGNATURE_NOT_PRODUCED", event.action());
        assertEquals("PROVIDER_RESULT_INVALID", event.details().get("detailCode"));
    }

    @Test
    void skipsEntriesWithoutSigningEvidence() {
        byte[] payload = DomainAttributeEncoding.encode(SimpleAttributeSet.builder().build())
                .getBytes(StandardCharsets.UTF_8);
        AuditEvidenceFeed.Entry entry = new AuditEvidenceFeed.Entry(0L, new PkiId("sign:x"), TIME, payload);
        assertTrue(SigningAuditProjection.toEvent(entry).isEmpty());
    }

    @Test
    void deterministicEventIdIsStableAcrossReprojection() {
        SigningExecutionEvidence evidence = SigningExecutionEvidence.terminal("realm.ca-a", FINGERPRINT,
                "COMPONENT", "status-bus", Optional.empty(), SigningExecutionEvidence.Outcome.EXPIRED);
        byte[] payload = DomainAttributeEncoding.encode(evidence.attributes()).getBytes(StandardCharsets.UTF_8);
        AuditEvidenceFeed.Entry entry = new AuditEvidenceFeed.Entry(13L, new PkiId("sign:3"), TIME, payload);
        String first = SigningAuditProjection.toEvent(entry).orElseThrow().details().get("eventId");
        String second = SigningAuditProjection.toEvent(entry).orElseThrow().details().get("eventId");
        assertEquals(first, second);
    }
}
