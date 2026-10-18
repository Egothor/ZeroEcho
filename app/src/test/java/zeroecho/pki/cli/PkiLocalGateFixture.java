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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SigningAcceptanceResult;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.application.PkiSigningOperation;

/** Test-owned filesystem, real keyring, and bounded process utilities for opt-in local gates. */
final class PkiLocalGateFixture {
    static final String PASSWORD = "local-validation-generated-test-keyring";
    static final String UNLOCK_ENVIRONMENT = "ZEROECHO_LOCAL_VALIDATION_UNLOCK";
    static final Duration CLAIM_LEASE = Duration.ofSeconds(10);
    static final Duration CALL_TIMEOUT = Duration.ofSeconds(5);

    private PkiLocalGateFixture() { }

    static Path privateDirectory(Path parent, String prefix) throws Exception {
        Files.createDirectories(parent);
        return Files.createTempDirectory(parent, prefix,
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    }

    static KeyPair rsaKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    static Path configuration(Path directory, KeyPair pair) throws Exception {
        Files.createDirectories(directory, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Path keyring = directory.resolve("keys.bin");
        try (KeyringPassword password = unlock(); KeyringStore keys = KeyringStore.create(keyring, password)) {
            keys.putPrivate("root.prv", "RSA", pair.getPrivate());
            keys.putPublic("root.pub", "RSA", pair.getPublic());
        }
        Path configuration = directory.resolve("local.json");
        Files.writeString(configuration, """
                {"version":1,"mode":"local","operatorId":"local-validation-operator",
                "store":{"provider":"fs","properties":{"root":%s}},
                "audit":{"provider":"memory","properties":{"size":"128"}},
                "publishers":[],"bindingProviders":[],
                "signing":{"provider":{"provider":"zeroecho-lib","properties":{"keyringPath":%s,
                "operationHorizon":"P90D","keyRefPrefix":"zeroecho-lib:","requireComponentSuffix":"true"}},
                "signatureAlgorithm":"%s","signingTtlSeconds":300,"claimLeaseMillis":10000,
                "providerCallTimeoutMillis":5000,"unlockEnvironmentVariable":"%s"}}
                """.formatted(jsonString(directory.resolve("store").toString()), jsonString(keyring.toString()),
                        BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(), UNLOCK_ENVIRONMENT));
        return configuration;
    }

    private static String jsonString(String value) {
        // Test directories are ordinary POSIX paths; preserve JSON quoting even under a workspace containing quotes.
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    static KeyringPassword unlock() { return new KeyringPassword(PASSWORD.toCharArray()); }

    static PkiSessionRuntimeDependencies dependencies() {
        return PkiSessionRuntimeDependencies.withKeyringUnlockProvider(PkiLocalGateFixture::unlock);
    }

    static void seedProfile(PkiSession session) throws Exception {
        try (InputStream input = PkiLocalGateFixture.class.getResourceAsStream("/zeroecho/pki/profiles/v1/root-ca.json")) {
            String profile = new String(input.readAllBytes(), StandardCharsets.UTF_8).replace("PT87600H", "PT2400H");
            session.profiles().importProfile(profile.getBytes(StandardCharsets.UTF_8));
            session.profiles().activateProfile("root-ca", 1);
        }
    }

    static PkiSigningOperation rootOperation(String subject) {
        return new PkiSigningOperation.CreateAuthority(new FormatId("x509"), new SubjectRef("CN=" + subject),
                "root-ca", new KeyRef("zeroecho-lib:root.prv"));
    }

    static AccessContext access() {
        return new AccessContext(new Principal("LOCAL_OPERATOR", "local-validation-operator"),
                new Purpose("ca.create"), Optional.empty(), Optional.empty());
    }

    static PkiId accept(PkiSession session, String subject) {
        PreparedSemanticSigningRequest prepared = session.signingCommands().orElseThrow().prepare(rootOperation(subject), access(),
                Optional.empty(), CancellationSignal.NONE);
        SigningAcceptanceResult accepted = session.semanticSigning().orElseThrow().accept(prepared);
        if (accepted.disposition() != zeroecho.pki.api.signing.SigningAcceptanceDisposition.ACCEPTED) {
            throw new IllegalStateException("Fixture root was not accepted");
        }
        return accepted.receipt().operationId();
    }

    static ProcessResult cli(Path executable, Path configuration, Path logs, String label, String... arguments) throws Exception {
        List<String> command = new ArrayList<>(List.of(executable.toString(), "pki", "--config", configuration.toString(),
                "--output", "json"));
        command.addAll(List.of(arguments));
        return process(command, logs, label, 90);
    }

    static ProcessResult child(Class<?> entrypoint, Path logs, String label, String... arguments) throws Exception {
        List<String> command = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Xms128m", "-Xmx512m", "-cp", childClasspath(), entrypoint.getName()));
        command.addAll(List.of(arguments));
        return process(command, logs, label, 600);
    }

    private static ProcessResult process(List<String> command, Path logs, String label, int timeoutSeconds) throws Exception {
        Path output = logs.resolve(label + ".out");
        Path errors = logs.resolve(label + ".err");
        ProcessBuilder builder = new ProcessBuilder(command).redirectOutput(output.toFile()).redirectError(errors.toFile());
        builder.environment().put(UNLOCK_ENVIRONMENT, PASSWORD);
        builder.environment().put("JAVA_HOME", System.getProperty("java.home"));
        long started = System.nanoTime();
        Process process = builder.start();
        try {
            process.getOutputStream().close();
            assertTrue(process.waitFor(timeoutSeconds, TimeUnit.SECONDS), "Owned fixture process timed out: " + label);
            long elapsed = System.nanoTime() - started;
            String stdout = Files.readString(output);
            String stderr = Files.readString(errors);
            assertFalse(stdout.contains(PASSWORD), "Fixture password exposed in stdout");
            assertFalse(stderr.contains(PASSWORD), "Fixture password exposed in stderr");
            return new ProcessResult(process.exitValue(), stdout, stderr, elapsed);
        } finally {
            // Force termination even if the initial timed wait was interrupted.
            if (process.isAlive()) {
                process.descendants().forEach(ProcessHandle::destroyForcibly);
                process.destroy();
                try {
                    process.waitFor(2, TimeUnit.SECONDS);
                } finally {
                    if (process.isAlive()) { process.destroyForcibly(); }
                    assertTrue(process.waitFor(10, TimeUnit.SECONDS), "Owned process did not terminate");
                }
            }
        }
    }

    private static String childClasspath() throws Exception {
        Set<String> entries = new LinkedHashSet<>(Arrays.asList(System.getProperty("java.class.path").split(File.pathSeparator)));
        for (ClassLoader loader = PkiLocalGateFixture.class.getClassLoader(); loader != null; loader = loader.getParent()) {
            if (loader instanceof URLClassLoader urls) {
                for (URL url : urls.getURLs()) {
                    if (url.getProtocol().equals("file")) { entries.add(Path.of(url.toURI()).toString()); }
                }
            }
        }
        return String.join(File.pathSeparator, entries);
    }

    static PkiOperationValue.ObjectValue firstStep(ProcessResult result) throws Exception {
        PkiOperationValue.ObjectValue document = PkiCliConfiguration.object(PkiCliJson.parse(result.output().getBytes(StandardCharsets.UTF_8)));
        return PkiCliConfiguration.object(((PkiOperationValue.ListValue) document.fields().get("steps")).values().getFirst());
    }

    record ProcessResult(int exit, String output, String errors, long elapsedNanos) { }
}
