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
package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.LogManager;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Verifies exclusive process-lifetime ownership of a filesystem PKI store.
 */
final class FilesystemPkiStoreOwnershipTest {

    private static final String OWNERSHIP_CODE = "STORE_ALREADY_OPEN";
    private static final long PROCESS_TIMEOUT_SECONDS = 10L;

    @Test
    void sameJvmOwnerExcludesSecondStoreAndReleasesOnClose(@TempDir Path tempDir) throws Exception {
        System.out.println("sameJvmOwnerExcludesSecondStoreAndReleasesOnClose");
        Path root = tempDir.resolve("shared");
        FsPkiStoreOptions options = FsPkiStoreOptions.defaults();

        FilesystemPkiStore first = new FilesystemPkiStore(root, options);
        try {
            FilesystemPkiStoreTest.importProfile(first,
                    FilesystemPkiStoreTest.TestObjects.minimalProfile("ownership-profile"),
                    java.time.Instant.now());
            first.activateProfile("ownership-profile", 1);
            assertOwnershipRejected(root);
            assertTrue(first.getActiveProfileRef("ownership-profile").isPresent());
        } finally {
            first.close();
        }
        first.close();

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, options)) {
            assertTrue(reopened.getActiveProfileRef("ownership-profile").isPresent());
        }
        System.out.println("sameJvmOwnerExcludesSecondStoreAndReleasesOnClose...ok");
    }

    @Test
    void separateStoreRootsRemainIndependent(@TempDir Path tempDir) throws Exception {
        System.out.println("separateStoreRootsRemainIndependent");
        try (FilesystemPkiStore first = new FilesystemPkiStore(tempDir.resolve("first"),
                FsPkiStoreOptions.defaults());
                FilesystemPkiStore second = new FilesystemPkiStore(tempDir.resolve("second"),
                        FsPkiStoreOptions.defaults())) {
            FilesystemPkiStoreTest.importProfile(first,
                    FilesystemPkiStoreTest.TestObjects.minimalProfile("first-profile"),
                    java.time.Instant.now());
            first.activateProfile("first-profile", 1);
            FilesystemPkiStoreTest.importProfile(second,
                    FilesystemPkiStoreTest.TestObjects.minimalProfile("second-profile"),
                    java.time.Instant.now());
            second.activateProfile("second-profile", 1);
            assertTrue(first.getActiveProfileRef("first-profile").isPresent());
            assertFalse(first.getActiveProfileRef("second-profile").isPresent());
            assertTrue(second.getActiveProfileRef("second-profile").isPresent());
            assertFalse(second.getActiveProfileRef("first-profile").isPresent());
        }
        System.out.println("separateStoreRootsRemainIndependent...ok");
    }

    @Test
    void constructorFailureAfterAcquisitionReleasesOwnership(@TempDir Path tempDir) throws Exception {
        System.out.println("constructorFailureAfterAcquisitionReleasesOwnership");
        Path root = tempDir.resolve("invalid-version");
        Files.createDirectories(root);
        Files.writeString(root.resolve(FsPaths.VERSION_FILE), "unsupported", StandardCharsets.US_ASCII);

        assertThrows(IllegalStateException.class,
                () -> new FilesystemPkiStore(root, FsPkiStoreOptions.defaults()));
        Files.writeString(root.resolve(FsPaths.VERSION_FILE), FilesystemPkiStore.CURRENT_STORE_VERSION,
                StandardCharsets.US_ASCII);

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            assertTrue(reopened.listCas().isEmpty());
        }
        System.out.println("constructorFailureAfterAcquisitionReleasesOwnership...ok");
    }

    @Test
    void forkedJvmOwnerExcludesParentAndReleasesNormally(@TempDir Path tempDir) throws Exception {
        System.out.println("forkedJvmOwnerExcludesParentAndReleasesNormally");
        Path root = tempDir.resolve("forked-graceful");
        try (ChildOwner child = ChildOwner.start(root)) {
            child.expect("LOCK_ACQUIRED");
            assertOwnershipRejected(root);
            child.send("PING");
            child.expect("STORE_USABLE");
            child.send("CLOSE");
            child.expect("STORE_CLOSED");
            child.awaitExit(0);
        }

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            assertTrue(reopened.listCas().isEmpty());
        }
        System.out.println("forkedJvmOwnerExcludesParentAndReleasesNormally...ok");
    }

    @Test
    void forkedJvmTerminationReleasesOperatingSystemLock(@TempDir Path tempDir) throws Exception {
        System.out.println("forkedJvmTerminationReleasesOperatingSystemLock");
        Path root = tempDir.resolve("forked-abrupt");
        try (ChildOwner child = ChildOwner.start(root)) {
            child.expect("LOCK_ACQUIRED");
            assertOwnershipRejected(root);
            child.destroyForcibly();
        }

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            assertTrue(reopened.listCas().isEmpty());
        }
        System.out.println("forkedJvmTerminationReleasesOperatingSystemLock...ok");
    }

    private static void assertOwnershipRejected(Path root) {
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> new FilesystemPkiStore(root, FsPkiStoreOptions.defaults()));
        assertTrue(failure.getMessage().contains(OWNERSHIP_CODE));
        assertNull(failure.getCause());
    }

    private static String childClasspath() throws Exception {
        Set<String> entries = new LinkedHashSet<>();
        String configured = System.getProperty("java.class.path", "");
        if (!configured.isBlank()) {
            for (String entry : configured.split(java.io.File.pathSeparator)) {
                entries.add(entry);
            }
        }
        ClassLoader loader = FilesystemPkiStoreOwnershipTest.class.getClassLoader();
        while (loader != null) {
            if (loader instanceof URLClassLoader urls) {
                for (URL url : urls.getURLs()) {
                    if ("file".equals(url.getProtocol())) {
                        entries.add(Path.of(url.toURI()).toString());
                    }
                }
            }
            loader = loader.getParent();
        }
        entries.add(codeSource(FilesystemPkiStoreOwnershipTest.class));
        entries.add(codeSource(FilesystemPkiStore.class));
        return String.join(java.io.File.pathSeparator, entries);
    }

    private static String codeSource(Class<?> type) throws Exception {
        return Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
    }

    private static final class ChildOwner implements AutoCloseable {
        private final Process process;
        private final BufferedReader output;
        private final BufferedWriter input;
        private final ExecutorService reader;

        private ChildOwner(Process process) {
            this.process = process;
            this.output = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
            this.input = new BufferedWriter(new OutputStreamWriter(process.getOutputStream(), StandardCharsets.UTF_8));
            this.reader = Executors.newSingleThreadExecutor();
        }

        private static ChildOwner start(Path root) throws Exception {
            String executable = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT)
                    .contains("win") ? "java.exe" : "java";
            Path java = Path.of(System.getProperty("java.home"), "bin", executable);
            Process process = new ProcessBuilder(java.toString(), "-cp", childClasspath(),
                    FilesystemPkiStoreLockProcess.class.getName(), root.toString()).redirectErrorStream(true).start();
            return new ChildOwner(process);
        }

        private void send(String command) throws IOException {
            input.write(command);
            input.newLine();
            input.flush();
        }

        private void expect(String expected) throws Exception {
            Future<String> line = reader.submit(output::readLine);
            try {
                assertEquals(expected, line.get(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS));
            } catch (ExecutionException ex) {
                throw new IOException("Child protocol read failed", ex.getCause());
            } catch (TimeoutException ex) {
                line.cancel(true);
                throw new IOException("Child protocol timed out");
            }
        }

        private void awaitExit(int expectedCode) throws Exception {
            assertTrue(process.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS));
            assertEquals(expectedCode, process.exitValue());
        }

        private void destroyForcibly() throws Exception {
            process.destroyForcibly();
            assertTrue(process.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS));
        }

        @Override
        public void close() throws Exception {
            if (process.isAlive()) {
                process.destroyForcibly();
                process.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            }
            input.close();
            output.close();
            reader.shutdownNow();
            assertTrue(reader.awaitTermination(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS));
        }
    }
}

/**
 * Test-process protocol endpoint for filesystem-store ownership checks.
 */
final class FilesystemPkiStoreLockProcess {

    private FilesystemPkiStoreLockProcess() {
    }

    /**
     * Opens one store and serves the fixed ownership-test control protocol.
     *
     * @param args one filesystem store root
     */
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("SETUP_FAILED");
            System.exit(2);
        }
        LogManager.getLogManager().reset();
        try (FilesystemPkiStore store = new FilesystemPkiStore(Path.of(args[0]),
                FsPkiStoreOptions.defaults());
                BufferedReader control = new BufferedReader(new InputStreamReader(System.in,
                        StandardCharsets.UTF_8))) {
            System.out.println("LOCK_ACQUIRED");
            System.out.flush();
            String command;
            while ((command = control.readLine()) != null) {
                if ("PING".equals(command)) {
                    store.listCas();
                    System.out.println("STORE_USABLE");
                    System.out.flush();
                } else if ("CLOSE".equals(command)) {
                    store.close();
                    System.out.println("STORE_CLOSED");
                    System.out.flush();
                    return;
                } else {
                    System.out.println("PROTOCOL_FAILED");
                    System.out.flush();
                    System.exit(3);
                }
            }
        } catch (Exception failure) {
            System.out.println("SETUP_FAILED:" + failure.getClass().getName());
            System.out.flush();
            System.exit(2);
        }
    }
}
