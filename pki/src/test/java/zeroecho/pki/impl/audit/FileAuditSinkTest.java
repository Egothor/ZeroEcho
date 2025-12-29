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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.AuditQuery;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;

public final class FileAuditSinkTest {

    @TempDir
    public Path tempDir;

    @Test
    public void recordThenSearchAndGetById_roundTripsDeterministically() throws Exception {
        System.out.println("recordThenSearchAndGetById_roundTripsDeterministically");

        // Use JUnit-managed temp directory.
        Path dir = tempDir.resolve("audit");
        System.out.println("...dir=" + dir.toAbsolutePath());

        FileAuditSink sink = new FileAuditSink(dir);

        Principal principal = new Principal("USER", "alice");
        Purpose purpose = new Purpose("LDAP");

        AuditEvent e1 = new AuditEvent(Instant.parse("2025-01-01T00:00:00Z"), "CAT", "READ", principal, purpose,
                Optional.of(new PkiId("obj-1")), Optional.of(new FormatId("x509")), Map.of("decision", "ALLOW"));

        AuditEvent e2 = new AuditEvent(Instant.parse("2025-01-01T00:00:01Z"), "CAT", "WRITE", principal, purpose,
                Optional.of(new PkiId("obj-1")), Optional.of(new FormatId("x509")), Map.of("decision", "DENY"));

        // Insert in reverse order to validate deterministic query ordering.
        sink.record(e2);
        sink.record(e1);

        AuditQuery q = new AuditQuery(Optional.of("CAT"), Optional.empty(), Optional.empty(), Optional.empty(),
                Optional.of(new PkiId("obj-1")), Optional.of("alice"));

        List<AuditEvent> found = sink.search(q);
        System.out.println("...foundSize=" + found.size());

        assertEquals(2, found.size());
        assertEquals("READ", found.get(0).action());
        assertEquals("WRITE", found.get(1).action());

        PkiId id = AuditEventCodec.eventId(e2);
        System.out.println("...eventId=" + summarize(id.value(), 16));

        Optional<AuditEvent> loaded = sink.getById(id);
        assertTrue(loaded.isPresent());
        assertEquals("WRITE", loaded.get().action());

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
