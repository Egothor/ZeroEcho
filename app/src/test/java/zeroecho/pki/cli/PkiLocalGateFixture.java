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

/**
 * Test-owned filesystem, real keyring, and bounded process utilities for opt-in local gates.
 */
final class PkiLocalGateFixture {
    /**
     * Public test-only keyring password; never use it for a deployed store.
     */
    static final String PASSWORD = "local-validation-generated-test-keyring";
    /**
     * Environment variable populated only in owned child processes with the test password.
     */
    static final String UNLOCK_ENVIRONMENT = "ZEROECHO_LOCAL_VALIDATION_UNLOCK";
    /**
     * Ten-second local signing claim lease used by fixture sessions.
     */
    static final Duration CLAIM_LEASE = Duration.ofSeconds(10);
    /**
     * Five-second bound on one signing-provider call in fixture sessions.
     */
    static final Duration CALL_TIMEOUT = Duration.ofSeconds(5);

    private PkiLocalGateFixture() { }

    /**
     * Creates a new owner-only temporary directory below the supplied parent.
     *
     * @param parent parent directory, created if absent
     * @param prefix generated-directory name prefix
     * @return newly created directory with POSIX mode 0700
     * @throws Exception if directory creation or POSIX permission application fails
     */
    static Path privateDirectory(Path parent, String prefix) throws Exception {
        Files.createDirectories(parent);
        return Files.createTempDirectory(parent, prefix,
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    }

    /**
     * Generates a fresh RSA key pair for an isolated signing fixture.
     *
     * @return newly generated 2048-bit RSA key pair
     * @throws Exception if RSA generation is unavailable or fails
     */
    static KeyPair rsaKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    /**
     * Creates a real encrypted keyring and writes a bounded local signing configuration.
     *
     * @param directory fixture directory for keys, configuration, and persistent store
     * @param pair RSA key pair stored under the fixture root aliases
     * @return path to the generated local JSON configuration
     * @throws Exception if keyring creation, key storage, or configuration writing fails
     */
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

    /**
     * Creates an independently destroyable copy of the public fixture password.
     *
     * @return new password owned by the caller, which must close it
     */
    static KeyringPassword unlock() { return new KeyringPassword(PASSWORD.toCharArray()); }

    /**
     * Supplies the test password through the runtime unlock-provider boundary.
     *
     * @return runtime dependencies creating a fresh password for every unlock
     */
    static PkiSessionRuntimeDependencies dependencies() {
        return PkiSessionRuntimeDependencies.withKeyringUnlockProvider(PkiLocalGateFixture::unlock);
    }

    /**
     * Imports and activates the bundled root profile with a shortened test validity limit.
     *
     * @param session open fixture session; remains owned by the caller
     * @throws Exception if the resource cannot be read, imported, or activated
     */
    static void seedProfile(PkiSession session) throws Exception {
        try (InputStream input = PkiLocalGateFixture.class.getResourceAsStream("/zeroecho/pki/profiles/v1/root-ca.json")) {
            String profile = new String(input.readAllBytes(), StandardCharsets.UTF_8).replace("PT87600H", "PT2400H");
            session.profiles().importProfile(profile.getBytes(StandardCharsets.UTF_8));
            session.profiles().activateProfile("root-ca", 1);
        }
    }

    /**
     * Builds a root-authority operation using the fixture profile and private-key alias.
     *
     * @param subject common-name value appended to the test distinguished name
     * @return typed root creation operation; no work is submitted by this helper
     */
    static PkiSigningOperation rootOperation(String subject) {
        return new PkiSigningOperation.CreateAuthority(new FormatId("x509"), new SubjectRef("CN=" + subject),
                "root-ca", new KeyRef("zeroecho-lib:root.prv"));
    }

    /**
     * Creates the fixture local-operator context for root-authority creation.
     *
     * @return access context with the ca.create purpose and no approval selectors
     */
    static AccessContext access() {
        return new AccessContext(new Principal("LOCAL_OPERATOR", "local-validation-operator"),
                new Purpose("ca.create"), Optional.empty(), Optional.empty());
    }

    /**
     * Prepares and durably accepts a root signing operation without executing it.
     *
     * @param session fixture session with signing preparation and acceptance capabilities
     * @param subject common-name value for the root operation
     * @return accepted operation identity for later inspection or completion
     * @throws IllegalStateException if the backend does not accept the prepared request
     */
    static PkiId accept(PkiSession session, String subject) {
        PreparedSemanticSigningRequest prepared = session.signingCommands().orElseThrow().prepare(rootOperation(subject), access(),
                Optional.empty(), CancellationSignal.NONE);
        SigningAcceptanceResult accepted = session.semanticSigning().orElseThrow().accept(prepared);
        if (accepted.disposition() != zeroecho.pki.api.signing.SigningAcceptanceDisposition.ACCEPTED) {
            throw new IllegalStateException("Fixture root was not accepted");
        }
        return accepted.receipt().operationId();
    }

    /**
     * Runs the packaged PKI CLI with JSON output and a 90-second process deadline.
     *
     * @param executable packaged CLI executable
     * @param configuration fixture local JSON configuration
     * @param logs existing directory for captured output and errors
     * @param label basename for process output files
     * @param arguments PKI operation and its arguments
     * @return exit status, captured output, and elapsed monotonic time
     * @throws Exception if process startup, bounded waiting, or log reading fails
     */
    static ProcessResult cli(Path executable, Path configuration, Path logs, String label, String... arguments) throws Exception {
        List<String> command = new ArrayList<>(List.of(executable.toString(), "pki", "--config", configuration.toString(),
                "--output", "json"));
        command.addAll(List.of(arguments));
        return process(command, logs, label, 90);
    }

    /**
     * Runs a fixture entry point in an isolated JVM with a ten-minute deadline.
     *
     * @param entrypoint class with the child-process main method
     * @param logs existing directory for captured output and errors
     * @param label basename for process output files
     * @param arguments child entry-point arguments
     * @return exit status, captured output, and elapsed monotonic time
     * @throws Exception if classpath discovery, startup, waiting, or log reading fails
     */
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

    /**
     * Decodes the first step in a fixture process's JSON plan result.
     *
     * @param result completed process result containing a nonempty steps array
     * @return first step as a typed JSON object
     * @throws Exception if output decoding fails or the expected result shape is absent
     */
    static PkiOperationValue.ObjectValue firstStep(ProcessResult result) throws Exception {
        PkiOperationValue.ObjectValue document = PkiCliConfiguration.object(PkiCliJson.parse(result.output().getBytes(StandardCharsets.UTF_8)));
        return PkiCliConfiguration.object(((PkiOperationValue.ListValue) document.fields().get("steps")).values().getFirst());
    }

    /**
     * Captures one completed owned process without retaining process or stream handles.
     *
     * @param exit process exit status
     * @param output complete captured standard output
     * @param errors complete captured standard error
     * @param elapsedNanos process elapsed time in monotonic nanoseconds
     */
    record ProcessResult(int exit, String output, String errors, long elapsedNanos) { }
}
