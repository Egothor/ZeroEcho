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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationValue;

/** Strict plan binding coverage for credential-revocation justification. */
class PkiRevocationRegistryTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void bindsOptionalJustificationWithoutConflatingTheStandardizedReason() throws Exception {
        PkiOperationRegistry registry = new PkiOperationRegistry();
        PkiOperation.RevokeCredential reasonOnly = (PkiOperation.RevokeCredential) ((PkiLocalCommand.Core) registry.bind(
                PkiOperation.RevokeCredential.NAME, arguments(Map.of(
                        "credentialId", text("credential-a"), "reason", text("KEY_COMPROMISE"))),
                temporaryDirectory)).operation();
        PkiOperation.RevokeCredential justified = (PkiOperation.RevokeCredential) ((PkiLocalCommand.Core) registry.bind(
                PkiOperation.RevokeCredential.NAME, arguments(Map.of(
                        "credentialId", text("credential-a"), "reason", text("KEY_COMPROMISE"),
                        "justification", text("ticket-100"))), temporaryDirectory)).operation();

        assertEquals(Optional.empty(), reasonOnly.operatorJustification());
        assertEquals(Optional.of("ticket-100"), justified.operatorJustification());
    }

    @Test
    void rejectsUnknownRevocationArgument() {
        PkiOperationRegistry registry = new PkiOperationRegistry();
        PkiOperationValue.ObjectValue arguments = arguments(Map.of(
                "credentialId", text("credential-a"), "reason", text("KEY_COMPROMISE"),
                "unexpected", text("value")));

        assertThrows(IllegalArgumentException.class, () -> registry.bind(
                PkiOperation.RevokeCredential.NAME, arguments, temporaryDirectory));
    }

    private static PkiOperationValue.ObjectValue arguments(Map<String, PkiOperationValue> values) {
        return new PkiOperationValue.ObjectValue(values);
    }

    @Test
    void bindsHoldAndReleaseWithoutCallerReasonOrTime() throws Exception {
        PkiOperationRegistry registry = new PkiOperationRegistry();
        for (String name : java.util.List.of("credential.hold", "credential.unhold")) {
            PkiOperation operation = ((PkiLocalCommand.Core) registry.bind(name, arguments(Map.of(
                    "credentialId", text("credential-a"), "justification", text("ticket-300"))), temporaryDirectory)).operation();
            PkiOperation expected = name.equals("credential.hold")
                    ? new PkiOperation.HoldCredential(new zeroecho.pki.api.PkiId("credential-a"), Optional.of("ticket-300"))
                    : new PkiOperation.UnholdCredential(new zeroecho.pki.api.PkiId("credential-a"), Optional.of("ticket-300"));
            assertEquals(expected, operation);
            for (String field : java.util.List.of("reason", "revocationDate", "evidence")) {
                assertThrows(IllegalArgumentException.class, () -> registry.bind(name, arguments(Map.of(
                        "credentialId", text("credential-a"), field, text("invalid"))), temporaryDirectory));
            }
        }
    }

    private static PkiOperationValue.Text text(String value) {
        return new PkiOperationValue.Text(value);
    }
}
