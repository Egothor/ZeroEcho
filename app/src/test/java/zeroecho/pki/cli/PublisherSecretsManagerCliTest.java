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

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Verifies locale-independent parsing and rejection diagnostics for publisher secret protection.
 */
class PublisherSecretsManagerCliTest {
    @ParameterizedTest
    @ValueSource(strings = {"classic", "hybrid"})
    @ResourceLock("java.util.Locale.default")
    void protectionNamesAreIndependentOfDefaultLocale(String protection) {
        Locale previous = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            assertEquals("Invalid arguments: Missing required argument: --password-env" + System.lineSeparator(),
                    writeStoreError(protection));
        } finally {
            Locale.setDefault(previous);
        }
    }

    @Test
    void invalidProtectionRetainsActionableDiagnostic() {
        assertEquals("Invalid arguments: Protection must be CLASSIC, PQC, or HYBRID; got: invalid"
                + System.lineSeparator(), writeStoreError("invalid"));
    }

    private static String writeStoreError(String protection) {
        ByteArrayOutputStream error = new ByteArrayOutputStream();
        try (PrintStream err = new PrintStream(error, true, StandardCharsets.UTF_8);
                PrintStream out = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8)) {
            assertEquals(2, PublisherSecretsManagerCli.run(new String[]{"write-store", "--store", "unused-store",
                    "--secrets", "unused-secrets", "--protection", protection}, out, err));
        }
        return error.toString(StandardCharsets.UTF_8);
    }
}
