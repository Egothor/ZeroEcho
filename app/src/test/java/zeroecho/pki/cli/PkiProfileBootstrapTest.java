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

package zeroecho.pki.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;

class PkiProfileBootstrapTest {
    @TempDir Path directory;

    @Test
    void importsArbitraryIdentityAndActualVersionThenSkipsKnownIdentity() throws Exception {
        Path configuration = configuration();
        Path profiles = Files.createDirectory(directory.resolve("profiles"));
        Files.write(profiles.resolve("root.json"), profile("team/α", 7));
        assertEquals(0, invoke(configuration, profiles).code());
        try (PkiSession session = open(configuration)) {
            PkiOperationResult listed = completed(session, new PkiOperation.ListProfileVersions("team/α"));
            assertEquals(new PkiOperationValue.IntegerValue(7), listed.fields().get("activeVersion"));
        }
        Files.write(profiles.resolve("root.json"), profile("team/α", 8));
        assertEquals(0, invoke(configuration, profiles).code());
        try (PkiSession session = open(configuration)) {
            PkiOperationResult listed = completed(session, new PkiOperation.ListProfileVersions("team/α"));
            assertEquals(new PkiOperationValue.IntegerValue(1), listed.fields().get("count"));
            assertEquals(new PkiOperationValue.IntegerValue(7), listed.fields().get("activeVersion"));
        }
    }

    @Test
    void existingInactiveProfileIsNeverAutomaticallyActivated() throws Exception {
        Path configuration = configuration();
        Path profiles = Files.createDirectory(directory.resolve("profiles"));
        byte[] document = profile("already-imported", 2);
        Files.write(profiles.resolve("profile.json"), document);
        try (PkiSession session = open(configuration)) {
            completed(session, new PkiOperation.RegisterProfile(document));
        }
        assertEquals(0, invoke(configuration, profiles).code());
        try (PkiSession session = open(configuration)) {
            assertFalse(completed(session, new PkiOperation.ListProfileVersions("already-imported"))
                    .fields().containsKey("activeVersion"));
        }
    }

    @Test
    void malformedInputStopsWithoutLeakingContentsAndClosesStore() throws Exception {
        Path configuration = configuration();
        Path profiles = Files.createDirectory(directory.resolve("profiles"));
        Files.write(profiles.resolve("a-valid.json"), profile("first", 3));
        Files.writeString(profiles.resolve("z-invalid.json"), "sensitive-invalid-profile");
        Result result = invoke(configuration, profiles);
        assertEquals(4, result.code());
        assertFalse(result.diagnostics().contains("sensitive-invalid-profile"));
        try (PkiSession session = open(configuration)) {
            assertEquals(new PkiOperationValue.IntegerValue(3), completed(session,
                    new PkiOperation.ListProfileVersions("first")).fields().get("activeVersion"));
        }
    }

    @Test
    void coreFailureStopsAndClosesStore() throws Exception {
        Path configuration = configuration();
        Path profiles = Files.createDirectory(directory.resolve("profiles"));
        String invalid = new String(profile("missing-binding", 1), StandardCharsets.UTF_8)
                .replace("\"mode\":\"STANDARD_ONLY\"", "\"mode\":\"EXPLICIT\",\"certificateSignature\":{"
                        + "\"bindingId\":\"unavailable-test-binding\",\"semanticCommitment\":\"test-commitment\"}");
        // The schema accepts the reference; registration must reject a binding
        // absent from the runtime authority, exercising the core failed outcome.
        assertEquals("missing-binding", CertificateProfileDocumentCodec.parse(
                invalid.getBytes(StandardCharsets.UTF_8)).profileId());
        Files.writeString(profiles.resolve("profile.json"), invalid);
        assertEquals(8, invoke(configuration, profiles).code());
        try (PkiSession session = open(configuration)) {
            assertEquals(new PkiOperationValue.IntegerValue(0), completed(session,
                    new PkiOperation.ListProfileVersions("missing-binding")).fields().get("count"));
        }
    }

    @Test
    void storeLockConflictFailsWithoutStartingAnotherWriter() throws Exception {
        Path configuration = configuration();
        Path profiles = Files.createDirectory(directory.resolve("profiles"));
        Files.write(profiles.resolve("profile.json"), profile("locked", 1));
        try (PkiSession session = open(configuration)) {
            assertEquals(8, invoke(configuration, profiles).code());
            assertEquals(new PkiOperationValue.IntegerValue(0), completed(session,
                    new PkiOperation.ListProfileVersions("locked")).fields().get("count"));
        }
        assertEquals(0, invoke(configuration, profiles).code());
    }

    @Test
    void resolvesKubernetesStyleProjectedProfileAndConfigurationLinks() throws Exception {
        Path configuration = configuration();
        Path profiles = Files.createDirectory(directory.resolve("profiles"));
        Path projection = Files.createDirectory(profiles.resolve("..projection"));
        Files.write(projection.resolve("profile.json"), profile("projected", 2));
        Files.createSymbolicLink(profiles.resolve("profile.json"), Path.of("..projection/profile.json"));
        Path link = Files.createSymbolicLink(directory.resolve("configuration-link.json"), configuration);
        assertEquals(0, invoke(link, profiles).code());
    }

    @Test
    void rejectsMissingConfigWrongStoreAndOversizedProfile() throws Exception {
        Path configuration = configuration();
        Path profiles = Files.createDirectory(directory.resolve("profiles"));
        assertEquals(3, invoke(directory.resolve("absent.json"), profiles).code());
        String original = Files.readString(configuration);
        Files.writeString(configuration, original.replace("/store\"", "/other-store\""));
        assertEquals(3, invoke(configuration, profiles).code());
        Files.writeString(configuration, original);
        Files.write(profiles.resolve("large.json"), new byte[262_145]);
        assertEquals(4, invoke(configuration, profiles).code());
        try (PkiSession session = open(configuration)) {
            assertTrue(completed(session, new PkiOperation.ListProfileVersions("absent")).fields().containsKey("count"));
        }
        assertEquals(2, PkiProfileBootstrap.execute(new String[] {"--config"}, System.err));
    }

    private Path configuration() throws Exception {
        Path path = directory.resolve("local.json");
        Files.writeString(path, """
                {"version":1,"mode":"local","operatorId":"bootstrap-test",
                "store":{"provider":"fs","properties":{"root":"%s"}},
                "audit":{"provider":"memory","properties":{"size":"128"}},
                "publishers":[],"bindingProviders":[]}
                """.formatted(directory.resolve("store")));
        return path;
    }

    private static byte[] profile(String identity, int version) throws Exception {
        try (InputStream input = PkiProfileBootstrapTest.class.getResourceAsStream("/zeroecho/pki/profiles/v1/root-ca.json")) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8)
                    .replace("\"profileId\":\"root-ca\"", "\"profileId\":\"" + identity + "\"")
                    .replace("\"profileVersion\":1", "\"profileVersion\":" + version)
                    .getBytes(StandardCharsets.UTF_8);
        }
    }

    private Result invoke(Path configuration, Path profiles) {
        ByteArrayOutputStream diagnostics = new ByteArrayOutputStream();
        int code = PkiProfileBootstrap.execute(new String[] {"--config", configuration.toString(),
                "--profiles-dir", profiles.toString(), "--store-dir", directory.resolve("store").toString()},
                new PrintStream(diagnostics, true, StandardCharsets.UTF_8));
        return new Result(code, diagnostics.toString(StandardCharsets.UTF_8));
    }

    private static PkiSession open(Path configuration) throws Exception {
        return PkiSession.openLocal(PkiCliConfiguration.read(configuration), PkiSessionRuntimeDependencies.none());
    }

    private static PkiOperationResult completed(PkiSession session, PkiOperation operation) {
        return assertInstanceOf(PkiOperationOutcome.Completed.class,
                session.operations().execute(operation, CancellationSignal.NONE)).result();
    }

    private record Result(int code, String diagnostics) { }
}
