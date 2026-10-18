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
package zeroecho.pki.impl.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;

public final class StdoutAuditSinkTest {

    @Test
    public void record_printsDeterministicSummaryWithoutDetails() {
        System.out.println("record_printsDeterministicSummaryWithoutDetails");

        PrintStream originalOut = System.out;

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        PrintStream capture = new PrintStream(buffer, true, StandardCharsets.UTF_8);

        try {
            System.setOut(capture);

            StdoutAuditSink sink = new StdoutAuditSink();

            AuditEvent event = new AuditEvent(Instant.parse("2025-01-01T00:00:00Z"), "CAT", "READ",
                    new Principal("USER", "alice"), new Purpose("LDAP"), Optional.empty(), Optional.empty(),
                    Map.of("secret", "SHOULD_NOT_APPEAR"));

            sink.record(event);

        } finally {
            System.setOut(originalOut);
        }

        String out = buffer.toString(StandardCharsets.UTF_8);

        System.out.println("...stdout=" + summarize(out, 120));

        assertTrue(out.contains("2025-01-01T00:00:00Z"));
        assertTrue(out.contains("category=CAT"));
        assertTrue(out.contains("action=READ"));
        assertTrue(out.contains("principalType=USER"));
        assertTrue(out.contains("principalName=alice"));
        assertTrue(out.contains("purpose=LDAP"));

        // Must not contain details payload.
        assertTrue(!out.contains("secret"));
        assertEquals(1, countLines(out));

        System.out.println("...ok");
    }

    private static int countLines(String s) {
        int lines = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '\n') {
                lines++;
            }
        }
        // If output doesn't end with newline, still treat it as one line if non-empty.
        if (!s.isEmpty() && s.charAt(s.length() - 1) != '\n') {
            lines++;
        }
        return lines;
    }

    private static String summarize(String s, int limit) {
        String trimmed = s.replace("\r", "");
        if (trimmed.length() <= limit) {
            return trimmed;
        }
        return trimmed.substring(0, limit) + "...";
    }
}
