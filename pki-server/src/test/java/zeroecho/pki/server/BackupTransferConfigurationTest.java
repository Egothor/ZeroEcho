/*
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
 */
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BackupTransferConfigurationTest {
    @TempDir Path directory;

    private String document() {
        return """
                {"version":1,"directory":"artifacts","maximumArchiveBytes":1048576,
                 "maximumRetainedBytes":2097152,"maximumArtifacts":2,"maximumConcurrentJobs":1,
                 "maximumWorkspaceBytes":8590983168,"lifetimeSeconds":3600,
                 "transferTimeoutSeconds":60,"browserOrigin":"https://admin.example"}
                """;
    }

    private BackupTransferConfiguration decode(String json) {
        return BackupTransferConfiguration.decode(json.getBytes(StandardCharsets.UTF_8));
    }

    @Test void explicitBudgetsRoundTripThroughBoundedFile() throws Exception {
        Path file = directory.resolve("transfer.json");
        Files.writeString(file, document());
        BackupTransferConfiguration configuration = BackupTransferConfiguration.read(file);
        assertEquals(1048576, configuration.maximumArchiveBytes());
        assertEquals(8590983168L, configuration.workspaceReservationBytes());
        assertEquals(decode(document()), configuration);
    }

    @Test void committedExampleUsesSupportedVersionAndExplicitBudgets() throws Exception {
        BackupTransferConfiguration example = BackupTransferConfiguration.read(
                Path.of("../docs/pki-backup-transfer-example.json"));
        assertEquals(64L * 1024 * 1024, example.maximumArchiveBytes());
        assertEquals(2 * example.workspaceReservationBytes(), example.maximumWorkspaceBytes());
    }

    @Test void rejectsUnknownMissingDuplicateAndFutureFields() {
        assertThrows(IllegalArgumentException.class, () -> decode(document().replace("1,", "2,")));
        assertThrows(IllegalArgumentException.class, () -> decode(document().replace("\"version\":1,", "")));
        assertThrows(IllegalArgumentException.class, () -> decode(document().replace("{", "{\"extra\":0,")));
        assertThrows(IllegalArgumentException.class, () -> decode(document().replace("{", "{\"version\":1,")));
    }

    @Test void rejectsOverflowAndInsufficientBudgets() {
        for (String invalid : new String[] {
                document().replace("1048576", "9223372036854775807"),
                document().replace("\"maximumArtifacts\":2", "\"maximumArtifacts\":9223372036854775807"),
                document().replace("8590983168", "8590983167"),
                document().replace("2097152", "1048575"),
                document().replace("\"maximumConcurrentJobs\":1", "\"maximumConcurrentJobs\":3"),
                document().replace("\"transferTimeoutSeconds\":60", "\"transferTimeoutSeconds\":3601")}) {
            assertThrows(IllegalArgumentException.class, () -> decode(invalid));
        }
    }

    @Test void acceptsOnlyExactSecureOrLoopbackOrigins() {
        for (String origin : new String[] {"http://admin.example", "http:/missing-host", "https://admin.example/",
                "https://user@admin.example", "https://admin.example?x=1", "https://admin.example#fragment"}) {
            assertThrows(IllegalArgumentException.class,
                    () -> decode(document().replace("https://admin.example", origin)));
        }
        decode(document().replace("https://admin.example", "http://localhost:8080"));
    }

    @Test void rejectsOversizedFileBeforeParsing() throws Exception {
        Path file = directory.resolve("oversized.json");
        Files.write(file, new byte[16385]);
        assertThrows(java.io.IOException.class, () -> BackupTransferConfiguration.read(file));
    }
}
