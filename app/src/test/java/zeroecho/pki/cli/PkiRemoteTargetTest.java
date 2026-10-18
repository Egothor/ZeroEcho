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
package zeroecho.pki.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

import org.junit.jupiter.api.Test;

class PkiRemoteTargetTest {

    @Test
    void malformedUrlDoesNotExposeParserInput() {
        String sentinel = "SENTINEL_REMOTE_URL_SECRET";
        String malformedUrl = "https://user:" + sentinel + "@[invalid";

        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> PkiRemoteTarget.parse(malformedUrl, "client.p12", null, null, null, null, null));

        assertEquals("Remote base URL is invalid", failure.getMessage());
        assertNull(failure.getCause());
        assertThrowableGraphDoesNotContain(failure, sentinel);

        StringWriter diagnostic = new StringWriter();
        failure.printStackTrace(new PrintWriter(diagnostic));
        assertFalse(diagnostic.toString().contains(sentinel));
    }

    @Test
    void preservesExistingEnvironmentReferenceSpellingAndRejectsDanglingOptions() {
        PkiRemoteTarget target = PkiRemoteTarget.parse("https://pki.example", "client.p12", "lowercase_env",
                null, null, null, null);
        assertEquals("lowercase_env", target.clientKeystorePasswordEnv().orElseThrow());
        assertThrows(IllegalArgumentException.class, () -> PkiRemoteTarget.parse("https://pki.example", null,
                "orphan", "client.pem", "client.key", null, null));
        assertThrows(IllegalArgumentException.class, () -> PkiRemoteTarget.parse("https://pki.example", "client.p12",
                null, null, null, null, "orphan"));
    }

    private static void assertThrowableGraphDoesNotContain(Throwable failure, String sentinel) {
        Set<Throwable> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        ArrayDeque<Throwable> pending = new ArrayDeque<>();
        pending.add(failure);
        while (!pending.isEmpty()) {
            Throwable current = pending.removeFirst();
            if (!visited.add(current)) {
                continue;
            }
            assertFalse(current.toString().contains(sentinel));
            for (StackTraceElement frame : current.getStackTrace()) {
                assertFalse(frame.toString().contains(sentinel));
            }
            if (current.getCause() != null) {
                pending.addLast(current.getCause());
            }
            Collections.addAll(pending, current.getSuppressed());
        }
    }
}
