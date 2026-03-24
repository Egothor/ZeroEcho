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
package zeroecho.pki.impl.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.AuditQuery;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;

public final class InMemoryAuditSinkTest {

    @Test
    public void recordAndSnapshot_preservesInsertionOrder() {
        System.out.println("recordAndSnapshot_preservesInsertionOrder");

        InMemoryAuditSink sink = new InMemoryAuditSink();

        AuditEvent e1 = new AuditEvent(Instant.parse("2025-01-01T00:00:01Z"), "CAT", "A",
                new Principal("USER", "alice"), new Purpose("LDAP"), Optional.empty(), Optional.empty(),
                Map.of("k", "v"));

        AuditEvent e2 = new AuditEvent(Instant.parse("2025-01-01T00:00:02Z"), "CAT", "B",
                new Principal("USER", "alice"), new Purpose("LDAP"), Optional.empty(), Optional.empty(),
                Map.of("k", "v"));

        sink.record(e1);
        sink.record(e2);

        List<AuditEvent> snap = sink.snapshot();

        System.out.println("...snapshotSize=" + snap.size());
        assertEquals(2, snap.size());
        assertEquals("A", snap.get(0).action());
        assertEquals("B", snap.get(1).action());

        System.out.println("...ok");
    }

    @Test
    public void search_returnsDeterministicallySortedResults() {
        System.out.println("search_returnsDeterministicallySortedResults");

        InMemoryAuditSink sink = new InMemoryAuditSink();

        Principal principal = new Principal("USER", "alice");
        Purpose purpose = new Purpose("LDAP");

        AuditEvent late = new AuditEvent(Instant.parse("2025-01-01T00:00:02Z"), "CAT", "WRITE", principal, purpose,
                Optional.empty(), Optional.empty(), Map.of("k", "v"));

        AuditEvent early = new AuditEvent(Instant.parse("2025-01-01T00:00:01Z"), "CAT", "READ", principal, purpose,
                Optional.empty(), Optional.empty(), Map.of("k", "v"));

        // Insert in reverse order to validate deterministic sort.
        sink.record(late);
        sink.record(early);

        AuditQuery query = new AuditQuery(Optional.of("CAT"), Optional.empty(), Optional.empty(), Optional.empty(),
                Optional.empty(), Optional.of("alice"));

        List<AuditEvent> found = sink.search(query);

        System.out.println("...foundSize=" + found.size());
        assertEquals(2, found.size());
        assertEquals("READ", found.get(0).action());
        assertEquals("WRITE", found.get(1).action());

        System.out.println("...ok");
    }

    @Test
    public void getById_findsEventByStableId() {
        System.out.println("getById_findsEventByStableId");

        InMemoryAuditSink sink = new InMemoryAuditSink();

        AuditEvent e = new AuditEvent(Instant.parse("2025-01-01T00:00:00Z"), "CAT", "READ",
                new Principal("USER", "alice"), new Purpose("LDAP"), Optional.empty(), Optional.empty(),
                Map.of("k", "v"));

        sink.record(e);

        PkiId id = AuditEventCodec.eventId(e);
        System.out.println("...eventId=" + summarize(id.value(), 16));

        Optional<AuditEvent> loaded = sink.getById(id);
        assertTrue(loaded.isPresent());
        assertEquals("READ", loaded.get().action());

        System.out.println("...ok");
    }

    @Test
    public void record_overCapacity_dropsOldestDeterministically() {
        System.out.println("record_overCapacity_dropsOldestDeterministically");

        InMemoryAuditSink sink = new InMemoryAuditSink(2);

        AuditEvent e1 = new AuditEvent(Instant.parse("2025-01-01T00:00:01Z"), "CAT", "A",
                new Principal("USER", "alice"), new Purpose("LDAP"), Optional.empty(), Optional.empty(),
                Map.of("k", "v"));

        AuditEvent e2 = new AuditEvent(Instant.parse("2025-01-01T00:00:02Z"), "CAT", "B",
                new Principal("USER", "alice"), new Purpose("LDAP"), Optional.empty(), Optional.empty(),
                Map.of("k", "v"));

        AuditEvent e3 = new AuditEvent(Instant.parse("2025-01-01T00:00:03Z"), "CAT", "C",
                new Principal("USER", "alice"), new Purpose("LDAP"), Optional.empty(), Optional.empty(),
                Map.of("k", "v"));

        sink.record(e1);
        sink.record(e2);
        sink.record(e3);

        List<AuditEvent> snap = sink.snapshot();
        System.out.println("...snapshotSize=" + snap.size());

        assertEquals(2, snap.size());
        assertEquals("B", snap.get(0).action());
        assertEquals("C", snap.get(1).action());

        System.out.println("...ok");
    }

    private static String summarize(String s, int prefixLen) {
        if (s == null) {
            return "";
        }
        if (s.length() <= prefixLen) {
            return s;
        }
        return s.substring(0, prefixLen) + "...";
    }
}
