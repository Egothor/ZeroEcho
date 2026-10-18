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

package zeroecho.pki.server.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.server.acme.AcmeProviders;
import zeroecho.pki.server.acme.AcmeState;
import zeroecho.pki.server.spi.AcmeChallengeProvider;
import zeroecho.pki.server.spi.AcmeExternalAccountBindingProvider;

class ServerSpiCompatibilityTest {
    @TempDir Path directory;

    @Test
    void externalNamedModuleImplementsAndRunsEverySupportedSpiWithoutExports() throws Exception {
        Path classes = compileFixture("module", true, null);
        Path log = directory.resolve("module.log");
        Process process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--module-path", classes + File.pathSeparator + distribution(),
                "-m", "external.spi/external.spi.Providers").redirectErrorStream(true)
                .redirectOutput(log.toFile()).start();
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "External SPI module timed out");
            assertEquals(0, process.exitValue(), Files.readString(log));
        } finally {
            if (process.isAlive()) process.destroyForcibly();
        }
    }

    @Test
    void actualSelectorsAdaptAllFieldsAndActivateOnlyConfiguredProviders() throws Exception {
        try (URLClassLoader loader = loader(compileFixture("selected", false, null))) {
            assertNotNull(TlsProviders.create(config("external-tls"), loader));
            assertThrows(IllegalStateException.class,
                    () -> TlsProviders.create(new ProviderConfig("external-tls", Map.of("fail", "true")), loader));
            assertNotNull(ClientTrustProviders.create(config("external-trust"), loader));
            assertTrue(AcmeProviders.challenges(List.of(), loader).isEmpty());
            assertTrue(AcmeProviders.eab(List.of(), loader).isEmpty());
            AcmeChallengeProvider challenge = AcmeProviders.challenges(List.of(config("external-challenge")), loader)
                    .get("external-challenge");
            assertEquals(Set.of(AcmeState.ChallengeType.DNS_01), challenge.challengeTypes());
            Instant now = Instant.parse("2026-10-05T12:00:00Z");
            AcmeChallengeProvider.Context context = new AcmeChallengeProvider.Context("directory", "authorization",
                    new AcmeState.Identifier(AcmeState.IdentifierType.DNS, "example.test", true),
                    AcmeState.ChallengeType.DNS_01, "t".repeat(43), "sensitive-key-authorization", 3,
                    now, now.plusSeconds(60));
            AcmeChallengeProvider.Result result = challenge.validate(context, config("external-challenge"),
                    CancellationSignal.NONE);
            assertTrue(result.valid());
            assertEquals("VERIFIED", result.classification());
            assertEquals(now, result.observedAt());
            assertEquals(now.plusSeconds(60), result.expiresAt());
            assertThrows(AssertionError.class,
                    () -> challenge.validate(context, config("external-challenge"), () -> true));
            AcmeExternalAccountBindingProvider eab = AcmeProviders.eab(List.of(config("external-eab")), loader)
                    .get("external-eab");
            AcmeExternalAccountBindingProvider.Binding binding = eab.verify(
                    new AcmeExternalAccountBindingProvider.Request("directory", new PkiId("authority"), "profile",
                            "a".repeat(64), new byte[] {1, 2}, now), config("external-eab"));
            assertTrue(binding.consumed());
            assertEquals("key", binding.keyId());
            assertEquals(now.plusSeconds(60), binding.expiresAt());
            assertEquals(Set.of("example.test"), binding.dnsNamespaces());
            assertEquals("b".repeat(64), binding.policyCommitment());
            assertThrows(IllegalArgumentException.class,
                    () -> AcmeProviders.challenges(List.of(config("missing")), loader));
            assertThrows(IllegalArgumentException.class,
                    () -> AcmeProviders.eab(List.of(config("missing")), loader));
            assertThrows(IllegalStateException.class, () -> TlsProviders.create(config("missing"), loader));
            assertThrows(IllegalArgumentException.class, () -> ClientTrustProviders.create(config("missing"), loader));
        }
    }

    @Test
    void crossGenerationDuplicateAndBlankIdentitiesFailBeforeSelection() throws Exception {
        try (URLClassLoader duplicate = loader(compileFixture("duplicate", false, "duplicate"))) {
            assertThrows(IllegalStateException.class, () -> TlsProviders.create(config("missing"), duplicate));
            assertThrows(IllegalStateException.class, () -> ClientTrustProviders.create(config("missing"), duplicate));
            assertThrows(IllegalStateException.class, () -> AcmeProviders.challenges(List.of(), duplicate));
            assertThrows(IllegalStateException.class, () -> AcmeProviders.eab(List.of(), duplicate));
        }
        try (URLClassLoader blank = loader(compileFixture("blank", false, "blank"))) {
            assertThrows(IllegalStateException.class, () -> TlsProviders.create(config("missing"), blank));
            assertThrows(IllegalStateException.class, () -> ClientTrustProviders.create(config("missing"), blank));
            assertThrows(IllegalStateException.class, () -> AcmeProviders.challenges(List.of(), blank));
            assertThrows(IllegalStateException.class, () -> AcmeProviders.eab(List.of(), blank));
        }
    }

    @Test
    void unchangedLegacyProviderBytecodeUsesOriginalContextConstructorsAndAccessors() throws Exception {
        Path root = Files.createDirectories(directory.resolve("legacy"));
        Path source = root.resolve("LegacyProvider.java");
        Files.writeString(source, resource("LegacyProvider.java"));
        Path classes = Files.createDirectories(root.resolve("classes"));
        String compilePath = classpath();
        String baseline = System.getProperty("serverSpi.legacyBaseline", "");
        if (!baseline.isEmpty()) {
            assertTrue(Files.isRegularFile(Path.of(baseline)), "Missing requested compatibility baseline");
            try (java.util.stream.Stream<Path> jars = Files.list(distribution())) {
                Path server = jars.filter(path -> path.getFileName().toString().startsWith("pki-server-"))
                        .findFirst().orElseThrow();
                compilePath = compilePath.replace(server.toString(), baseline);
            }
        }
        ByteArrayOutputStream diagnostics = new ByteArrayOutputStream();
        assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, diagnostics, diagnostics,
                "-classpath", compilePath, "-d", classes.toString(), source.toString()), diagnostics.toString());
        Path services = Files.createDirectories(classes.resolve("META-INF/services"));
        Files.writeString(services.resolve("zeroecho.pki.server.spi.AcmeChallengeProvider"), "legacy.spi.LegacyProvider");
        try (URLClassLoader loader = loader(classes)) {
            AcmeChallengeProvider provider = AcmeProviders.challenges(List.of(config("legacy-challenge")), loader)
                    .get("legacy-challenge");
            Instant now = Instant.parse("2026-10-05T12:00:00Z");
            AcmeChallengeProvider.Result result = provider.validate(new AcmeChallengeProvider.Context(
                    "directory", "authorization", new AcmeState.Identifier(AcmeState.IdentifierType.DNS,
                            "example.test", true), AcmeState.ChallengeType.DNS_01, "t".repeat(43), "key-auth", 3,
                    now, now.plusSeconds(60)), config("legacy-challenge"), CancellationSignal.NONE);
            assertTrue(result.valid());
            assertEquals("LEGACY_VERIFIED", result.classification());
            assertEquals(now, result.observedAt());
        }
    }

    private Path compileFixture(String name, boolean modular, String variant) throws Exception {
        Path root = Files.createDirectories(directory.resolve(name));
        Path source = root.resolve("Providers.java");
        String java = resource("Providers.java");
        if ("blank".equals(variant)) {
            java = java.replace("external-challenge", "").replace("external-eab", "")
                    .replace("external-tls", "").replace("external-trust", "");
        } else if ("duplicate".equals(variant)) {
            java = java.replace("external-challenge", zeroecho.pki.server.acme.Http01ChallengeProvider.ID)
                    .replace("external-eab", zeroecho.pki.server.acme.TestAcmeEabProvider.ID)
                    .replace("external-tls", new TestTlsProvider().id())
                    .replace("external-trust", TestClientTrustProvider.ID);
        }
        Files.writeString(source, java);
        Path classes = Files.createDirectories(root.resolve("classes"));
        List<String> arguments = new ArrayList<>(List.of(modular ? "--module-path" : "-classpath",
                modular ? distribution().toString() : classpath(), "-d", classes.toString(), source.toString()));
        if (modular) {
            Path descriptor = root.resolve("module-info.java");
            Files.writeString(descriptor, resource("module-info.java"));
            arguments.add(descriptor.toString());
        }
        ByteArrayOutputStream diagnostics = new ByteArrayOutputStream();
        assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, diagnostics, diagnostics,
                arguments.toArray(String[]::new)), diagnostics.toString());
        if (!modular) {
            Path services = Files.createDirectories(classes.resolve("META-INF/services"));
            Map<String, String> providers = Map.of("AcmeChallengeProvider", "Challenge",
                    "AcmeExternalAccountBindingProvider", "Eab", "PkiServerTlsProvider", "Tls",
                    "PkiServerClientTrustProvider", "Trust");
            for (Map.Entry<String, String> provider : providers.entrySet()) {
                Files.writeString(services.resolve("zeroecho.pki.server.spi.v2." + provider.getKey()),
                        "external.spi.Providers$" + provider.getValue());
            }
        }
        return classes;
    }

    private URLClassLoader loader(Path classes) throws Exception {
        return new URLClassLoader(new URL[] {classes.toUri().toURL()}, getClass().getClassLoader());
    }

    private static Path distribution() {
        return Path.of(System.getProperty("serverSpi.distributionLib"));
    }

    private static String classpath() throws Exception {
        try (java.util.stream.Stream<Path> jars = Files.list(distribution())) {
            return jars.filter(path -> path.toString().endsWith(".jar")).sorted()
                    .map(Path::toString).collect(Collectors.joining(File.pathSeparator));
        }
    }

    private String resource(String file) throws Exception {
        try (java.io.InputStream input = getClass().getResourceAsStream("/fixtures/server-spi/" + file)) {
            return new String(java.util.Objects.requireNonNull(input).readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static ProviderConfig config(String id) {
        return new ProviderConfig(id, Map.of("input", "exact"));
    }
}
