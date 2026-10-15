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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration;

class EnrollmentRuntimeConfigurationTest {
    @TempDir Path directory;

    @Test
    void rejectsUnknownMissingDuplicateFractionalOverflowAndUnsupportedVersions() {
        String valid = EnrollmentTestSupport.runtimeJson();
        assertEquals(1000, decode(valid).budgets().maximumTransactions());
        for (String malformed : List.of(
                valid.replace("\"version\":1", "\"version\":0"),
                valid.replace("\"version\":1", "\"version\":2"),
                valid.replace("\"version\":1", "\"version\":1,\"version\":1"),
                valid.replace("\"version\":1", "\"version\":1,\"unexpected\":true"),
                valid.replace("\"maximumTransactions\":1000", "\"maximumTransactions\":1.5"),
                valid.replace("\"maximumTransactions\":1000", "\"maximumTransactions\":2147483648"),
                valid.replace("\"maximumTransactions\":1000", "\"maximumTransactions\":0"),
                valid.replace("\"maximumPending\":100", "\"maximumPending\":1001"),
                valid.replace("\"retryAfterSeconds\":5", "\"retryAfterSeconds\":601"),
                valid.replace("\"retryAfterSeconds\":5", "\"retryAfterSeconds\":-1"),
                valid.replace("\"keyrings\":[]", "\"keyrings\":null"),
                valid.replace("\"credentialSets\":[],", ""),
                valid.replace("\"activeCredentials\":[]", "\"activeCredentials\":[],\"keygenArtifacts\":null"),
                valid.replace("\"maximumRetainedRequestBytes\":10485760", "\"maximumRetainedRequestBytes\":1"))) {
            assertThrows(IllegalArgumentException.class, () -> decode(malformed));
        }
        assertThrows(IllegalArgumentException.class, () -> EnrollmentRuntimeConfiguration.decode(new byte[1_048_577]));
    }

    @Test
    void validatesReferencesArraysAndExactWholeSecondDurations() {
        String valid = EnrollmentTestSupport.runtimeJson();
        for (String malformed : List.of(
                valid.replace("\"keyrings\":[]", "\"keyrings\":[{\"id\":\"ring\",\"path\":\"/a\"},{\"id\":\"ring\",\"path\":\"/b\"}]"),
                valid.replace("\"keyrings\":[]", "\"keyrings\":[{\"id\":\"ring\",\"path\":\"/a\",\"password\":\"forbidden\"}]"),
                valid.replace("\"activeCredentials\":[]", "\"activeCredentials\":[{\"protocol\":\"SCEP\",\"authorityId\":\"a\",\"credentialId\":\"missing\"}]"))) {
            assertThrows(IllegalArgumentException.class, () -> decode(malformed));
        }
        assertThrows(IllegalArgumentException.class, () -> new EnrollmentRuntimeConfiguration.Budgets(1, 1, 100, 100, 1,
                Duration.ofNanos(1), Duration.ofSeconds(1)));
        assertThrows(UnsupportedOperationException.class, () -> decode(valid).keyrings().clear());
        assertFalse(decode(valid).toString().contains("budgets"));
    }

    @Test
    void cliStrictlyValidatesCompanionWithoutOpeningStores() throws Exception {
        Path main = Path.of(System.getProperty("user.dir")).getParent().resolve("docs/pki-server-loopback-example.json");
        Path config = Files.writeString(directory.resolve("enrollment.json"), EnrollmentTestSupport.runtimeJson());
        assertEquals(0, PkiServerMain.run(new String[] { "--validate-config", "--config", main.toString(),
                "--enrollment-config", config.toString() }));
        assertEquals(2, PkiServerMain.run(new String[] { "--validate-config", "--config", main.toString(),
                "--enrollment-config", config.toString(), "--enrollment-config", config.toString() }));
        Files.writeString(config, EnrollmentTestSupport.runtimeJson().replace("\"version\":1", "\"version\":9"));
        assertEquals(2, PkiServerMain.run(new String[] { "--validate-config", "--config", main.toString(),
                "--enrollment-config", config.toString() }));
        try (java.util.stream.Stream<Path> files = Files.list(directory)) { assertEquals(1, files.count()); }
    }

    @Test
    void parsesMaintainedCompanionExample() throws Exception {
        Path root = Path.of(System.getProperty("user.dir")).getParent();
        EnrollmentRuntimeConfiguration example = EnrollmentRuntimeConfiguration.read(root.resolve("docs/pki-enrollment-example.json"));
        assertEquals(1, example.credentialSets().size());
        assertEquals("scep-example-v1", example.activeCredentials().getFirst().credentialId());
    }

    @Test void parsesExplicitEstGeneratorSelectionWithoutImplicitProtocolReuse() throws Exception {
        Path root = Path.of(System.getProperty("user.dir")).getParent();
        String json = Files.readString(root.resolve("docs/pki-enrollment-example.json")).replace("\"SCEP\"", "\"EST\"");
        EnrollmentRuntimeConfiguration configuration = decode(json);
        assertEquals(EnrollmentRuntimeConfiguration.Protocol.EST, configuration.credentialSets().getFirst().protocol());
        assertEquals(EnrollmentRuntimeConfiguration.Protocol.EST, configuration.activeCredentials().getFirst().protocol());
        assertThrows(IllegalArgumentException.class, () -> decode(json.replace("\"EST\"", "\"EST_IMPLICIT\"")));
    }

    private static EnrollmentRuntimeConfiguration decode(String json) {
        return EnrollmentRuntimeConfiguration.decode(json.getBytes(StandardCharsets.UTF_8));
    }
}
