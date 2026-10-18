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
import zeroecho.pki.application.StatusGenerationEvidence;
import zeroecho.pki.impl.core.continuation.DomainAttributeEncoding;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.AuditEvidenceFeed;

/** Maps status-evidence feed entries to payload-free audit events through the status adapter. */
class StatusAuditProjectionTest {
    private static final Instant TIME = Instant.parse("2026-08-04T12:00:00Z");

    @Test
    void projectsStatusGenerationEvidence() {
        StatusGenerationEvidence evidence = StatusGenerationEvidence.system("CRL", "ca-a", "x509",
                TIME.toString(), Optional.of("2026-08-05T12:00:00Z"));
        AuditEvidenceFeed.Entry entry = new AuditEvidenceFeed.Entry(0L, new PkiId("status:crl:ca-a"), TIME,
                DomainAttributeEncoding.encode(evidence.attributes()).getBytes(StandardCharsets.UTF_8));

        AuditEvent event = StatusAuditProjection.toEvent(entry).orElseThrow();
        assertEquals("STATUS", event.category());
        assertEquals("STATUS_GENERATED", event.action());
        assertEquals(TIME, event.time());
        assertEquals(Optional.of(new PkiId("status:crl:ca-a")), event.objectId());
        assertEquals("CRL", event.details().get("statusType"));
        assertEquals("ca-a", event.details().get("issuerCaId"));
        assertEquals("x509", event.details().get("formatId"));
        assertEquals("2026-08-05T12:00:00Z", event.details().get("nextUpdate"));
        assertTrue(event.details().containsKey("eventId"));
        // No status object content, CRL entries, or signature material leaks into the projected event.
        assertFalse(event.details().containsKey("content"));
        assertFalse(event.details().containsKey("signature"));
    }

    @Test
    void skipsEntriesWithoutStatusEvidence() {
        byte[] payload = DomainAttributeEncoding.encode(SimpleAttributeSet.builder().build())
                .getBytes(StandardCharsets.UTF_8);
        AuditEvidenceFeed.Entry entry = new AuditEvidenceFeed.Entry(0L, new PkiId("status:x"), TIME, payload);
        assertTrue(StatusAuditProjection.toEvent(entry).isEmpty());
    }

    @Test
    void deterministicEventIdIsStableAcrossReprojection() {
        StatusGenerationEvidence evidence = StatusGenerationEvidence.system("OCSP", "ca-a", "x509",
                TIME.toString(), Optional.empty());
        byte[] payload = DomainAttributeEncoding.encode(evidence.attributes()).getBytes(StandardCharsets.UTF_8);
        AuditEvidenceFeed.Entry entry = new AuditEvidenceFeed.Entry(9L, new PkiId("status:ocsp"), TIME, payload);
        String first = StatusAuditProjection.toEvent(entry).orElseThrow().details().get("eventId");
        String second = StatusAuditProjection.toEvent(entry).orElseThrow().details().get("eventId");
        assertEquals(first, second);
    }
}
