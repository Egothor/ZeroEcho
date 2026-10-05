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
package zeroecho.core.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.storage.KeyringFileOperations.Target;

class KeyringAtomicPersistenceTest {
    private static final char[] PASSWORD = { 'a', 't', 'o', 'm', 'i', 'c' };
    private static final byte[] ENTRY_A = material((byte) 0x31);
    private static final byte[] ENTRY_B = material((byte) 0x72);
    private static final Set<PosixFilePermission> FILE_PERMISSIONS = Set.of(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE);

    @TempDir
    Path temporaryDirectory;

    @Test
    void mainImagePreCommitFailuresPreserveAuthoritativeState() throws Exception {
        start("mainImagePreCommitFailuresPreserveAuthoritativeState");
        for (FailureStage stage : List.of(FailureStage.CREATE_TEMP, FailureStage.WRITE_TEMP, FailureStage.FORCE_TEMP,
                FailureStage.ATOMIC_MOVE)) {
            Path path = initialized("main-" + stage + ".zek");
            byte[] before = Files.readAllBytes(path);
            FailingFileOperations operations = new FailingFileOperations(Target.MAIN_IMAGE, stage, false);
            try (KeyringPassword password = password();
                    KeyringStore store = KeyringStore.open(path, password, KeyringProtection.standard(),
                            deterministicRandom(50), operations)) {
                long highWater = longField(store, "nonceHighWater");
                KeyringException failure = assertThrows(KeyringException.class, () -> put(store, "B", ENTRY_B));
                assertSafe(failure, KeyringException.Code.KEYRING_IO_FAILED);
                assertTrue(store.contains("A"));
                assertFalse(store.contains("B"));
                assertArrayEquals(before, Files.readAllBytes(path));
                assertEquals(highWater + 2, longField(store, "nonceHighWater"));
                assertAlreadyOpen(path);
                put(store, "B", ENTRY_B);
                assertTrue(store.contains("B"));
            } finally {
                wipe(before);
            }
            assertReopened(path, true);
            assertSentinelAbsent(path.getParent(), ENTRY_B);
        }
        ok();
    }

    @Test
    void mainImageDirectoryForceFailurePoisonsUntilReopen() throws Exception {
        start("mainImageDirectoryForceFailurePoisonsUntilReopen");
        Path path = initialized("main-directory.zek");
        FailingFileOperations operations = new FailingFileOperations(Target.MAIN_IMAGE, FailureStage.FORCE_DIRECTORY,
                false);
        KeyringStore store;
        try (KeyringPassword password = password()) {
            store = KeyringStore.open(path, password, KeyringProtection.standard(), deterministicRandom(70),
                    operations);
        }
        try {
            KeyringException failure = assertThrows(KeyringException.class, () -> put(store, "B", ENTRY_B));
            assertSafe(failure, KeyringException.Code.KEYRING_DURABILITY_UNCONFIRMED);
            assertTrue(store.isDestroyed());
            assertThrows(IllegalStateException.class, () -> store.contains("A"));
            assertThrows(KeyringException.class, () -> put(store, "C", ENTRY_B));
        } finally {
            store.close();
        }
        assertReopened(path, true);
        assertSentinelAbsent(path.getParent(), ENTRY_B);
        ok();
    }

    @Test
    void sidecarPreCommitFailuresIssueNoUncommittedNonce() throws Exception {
        start("sidecarPreCommitFailuresIssueNoUncommittedNonce");
        for (FailureStage stage : List.of(FailureStage.CREATE_TEMP, FailureStage.WRITE_TEMP, FailureStage.FORCE_TEMP,
                FailureStage.ATOMIC_MOVE)) {
            Path path = initialized("sidecar-" + stage + ".zek");
            byte[] mainBefore = Files.readAllBytes(path);
            byte[] sidecarBefore = Files.readAllBytes(sidecar(path));
            FailingFileOperations operations = new FailingFileOperations(Target.NONCE_RESERVATION, stage, false);
            try (KeyringPassword password = password();
                    KeyringStore store = KeyringStore.open(path, password, KeyringProtection.standard(),
                            deterministicRandom(90), operations)) {
                long highWater = longField(store, "nonceHighWater");
                KeyringException failure = assertThrows(KeyringException.class, () -> put(store, "B", ENTRY_B));
                assertSafe(failure, KeyringException.Code.KEYRING_IO_FAILED);
                assertEquals(highWater, longField(store, "nonceHighWater"));
                assertFalse(store.contains("B"));
                assertArrayEquals(mainBefore, Files.readAllBytes(path));
                assertArrayEquals(sidecarBefore, Files.readAllBytes(sidecar(path)));
                put(store, "B", ENTRY_B);
                assertEquals(highWater + 2, longField(store, "nonceHighWater"));
            } finally {
                wipe(mainBefore);
                wipe(sidecarBefore);
            }
            assertReopened(path, true);
            assertSentinelAbsent(path.getParent(), ENTRY_B);
        }
        ok();
    }

    @Test
    void sidecarDirectoryForceFailureIssuesNothingUntilReopen() throws Exception {
        start("sidecarDirectoryForceFailureIssuesNothingUntilReopen");
        Path path = initialized("sidecar-directory.zek");
        long initialHighWater;
        FailingFileOperations operations = new FailingFileOperations(Target.NONCE_RESERVATION,
                FailureStage.FORCE_DIRECTORY, false);
        KeyringStore store;
        try (KeyringPassword password = password()) {
            store = KeyringStore.open(path, password, KeyringProtection.standard(), deterministicRandom(110),
                    operations);
        }
        try {
            initialHighWater = longField(store, "nonceHighWater");
            KeyringException failure = assertThrows(KeyringException.class, () -> put(store, "B", ENTRY_B));
            assertSafe(failure, KeyringException.Code.KEYRING_DURABILITY_UNCONFIRMED);
            assertFalse(store.isDestroyed());
            assertThrows(IllegalStateException.class, () -> store.contains("A"));
            assertAlreadyOpen(path);
        } finally {
            store.close();
        }
        try (KeyringPassword password = password();
                KeyringStore reopened = KeyringStore.open(path, password, KeyringProtection.standard(),
                        deterministicRandom(130))) {
            assertTrue(reopened.contains("A"));
            assertFalse(reopened.contains("B"));
            assertEquals(initialHighWater + 1, longField(reopened, "nonceHighWater"));
            put(reopened, "B", ENTRY_B);
            assertEquals(initialHighWater + 3, longField(reopened, "nonceHighWater"));
        }
        assertReopened(path, true);
        ok();
    }

    @Test
    void windowsAtomicMoveTransientAccessDeniedIsRetriedSuccessfully() throws Exception {
        start("windowsAtomicMoveTransientAccessDeniedIsRetriedSuccessfully");
        // Fails 3 times (within the 5-attempt budget), then succeeds — put() must complete.
        Path path = initialized("retry-succeeds.zek");
        TransientAccessDeniedFileOperations operations = new TransientAccessDeniedFileOperations(
                Target.MAIN_IMAGE, 3);
        try (KeyringPassword password = password();
                KeyringStore store = KeyringStore.open(path, password, KeyringProtection.standard(),
                        deterministicRandom(50), operations)) {
            assertDoesNotThrow(() -> put(store, "B", ENTRY_B));
            assertTrue(store.contains("B"));
            assertEquals(3, operations.denialsIssued());
            assertEquals(List.of(10L, 10L, 10L), operations.pauses);
        }
        assertReopened(path, true);
        ok();
    }

    @Test
    void windowsAtomicMoveBudgetExhaustedThrowsKeyringIoFailed() throws Exception {
        start("windowsAtomicMoveBudgetExhaustedThrowsKeyringIoFailed");
        // Fails on every attempt (always AccessDeniedException) — put() must throw KEYRING_IO_FAILED.
        Path path = initialized("retry-exhausted.zek");
        TransientAccessDeniedFileOperations operations = new TransientAccessDeniedFileOperations(
                Target.MAIN_IMAGE, Integer.MAX_VALUE);
        try (KeyringPassword password = password();
                KeyringStore store = KeyringStore.open(path, password, KeyringProtection.standard(),
                        deterministicRandom(50), operations)) {
            KeyringException failure = assertThrows(KeyringException.class, () -> put(store, "B", ENTRY_B));
            assertSafe(failure, KeyringException.Code.KEYRING_IO_FAILED);
            assertFalse(store.contains("B"));
            assertEquals(5, operations.denialsIssued());
            assertEquals(List.of(10L, 10L, 10L, 10L), operations.pauses);
        }
        assertReopened(path, false);
        ok();
    }

    @Test
    void cleanupFailuresPreservePrimaryAndEncryptedResiduals() throws Exception {
        start("cleanupFailuresPreservePrimaryAndEncryptedResiduals");
        assertCleanupFailure(Target.MAIN_IMAGE, "cleanup-main.zek");
        assertCleanupFailure(Target.NONCE_RESERVATION, "cleanup-sidecar.zek");
        ok();
    }

    @Test
    void retryPolicyIsDeterministicForBothDestinationsAndAllFailureCategories() throws Exception {
        for (Target target : List.of(Target.MAIN_IMAGE, Target.NONCE_RESERVATION)) {
            for (String scenario : List.of("success", "exhausted", "non-windows", "other-io", "interrupted")) {
                Path path = initialized(target + "-" + scenario + ".zek");
                TransientAccessDeniedFileOperations operations = new TransientAccessDeniedFileOperations(
                        target, scenario.equals("success") ? 3 : Integer.MAX_VALUE);
                operations.windows = !scenario.equals("non-windows");
                operations.otherFailure = scenario.equals("other-io");
                operations.interrupted = scenario.equals("interrupted");
                try (KeyringPassword password = password();
                        KeyringStore store = KeyringStore.open(path, password, KeyringProtection.standard(),
                                deterministicRandom(50), operations)) {
                    if (scenario.equals("success")) {
                        put(store, "B", ENTRY_B);
                    } else {
                        KeyringException failure = assertThrows(KeyringException.class,
                                () -> put(store, "B", ENTRY_B));
                        assertSafe(failure, KeyringException.Code.KEYRING_IO_FAILED);
                        assertFalse(store.contains("B"));
                    }
                    int expectedDenials = scenario.equals("success") ? 3 : scenario.equals("exhausted") ? 5 : 1;
                    int expectedPauses = scenario.equals("success") ? 3 : scenario.equals("exhausted") ? 4
                            : scenario.equals("interrupted") ? 1 : 0;
                    assertEquals(expectedDenials, operations.denialsIssued());
                    assertEquals(java.util.Collections.nCopies(expectedPauses, 10L), operations.pauses);
                    assertEquals(scenario.equals("interrupted"), Thread.currentThread().isInterrupted());
                } finally {
                    Thread.interrupted();
                }
                assertReopened(path, scenario.equals("success"));
            }
        }
    }

    private void assertCleanupFailure(Target target, String file) throws Exception {
        Path path = initialized(file);
        FailingFileOperations operations = new FailingFileOperations(target, FailureStage.WRITE_TEMP, true);
        try (KeyringPassword password = password();
                KeyringStore store = KeyringStore.open(path, password, KeyringProtection.standard(),
                        deterministicRandom(150), operations)) {
            KeyringException failure = assertThrows(KeyringException.class, () -> put(store, "B", ENTRY_B));
            assertSafe(failure, KeyringException.Code.KEYRING_IO_FAILED);
            assertEquals(1, failure.getSuppressed().length);
            assertSafe((KeyringException) failure.getSuppressed()[0], KeyringException.Code.KEYRING_IO_FAILED);
            assertTrue(store.contains("A"));
            assertFalse(store.contains("B"));
            Path residual = operations.firstTemporary();
            assertTrue(Files.isRegularFile(residual));
            if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                // Owner-only enforcement is asserted via POSIX bits here; on Windows it
                // is carried by the parent directory's owner-only ACL inheritance.
                assertEquals(FILE_PERMISSIONS, Files.getPosixFilePermissions(residual));
            }
            assertSentinelAbsent(residual.getParent(), ENTRY_B);
            put(store, "B", ENTRY_B);
            assertNotEquals(residual, operations.lastTemporary());
            assertTrue(store.contains("B"));
        }
        assertReopened(path, true);
    }

    private Path initialized(String file) throws Exception {
        Path path = temporaryDirectory.resolve(file);
        try (KeyringPassword password = password();
                KeyringStore store = KeyringStore.create(path, password, KeyringProtection.standard(),
                        deterministicRandom(1))) {
            put(store, "A", ENTRY_A);
        }
        return path;
    }

    private static void put(KeyringStore store, String alias, byte[] material) throws Exception {
        store.putSecret(alias, "AES", new SecretKeySpec(material, "AES"));
    }

    private static void assertReopened(Path path, boolean hasB) throws Exception {
        try (KeyringPassword password = password(); KeyringStore store = KeyringStore.open(path, password)) {
            assertTrue(store.contains("A"));
            assertEquals(hasB, store.contains("B"));
            assertSecretEquals(ENTRY_A, store.getSecret("A"));
            if (hasB) {
                assertSecretEquals(ENTRY_B, store.getSecret("B"));
            }
        }
    }

    private static void assertSecretEquals(byte[] expected, SecretKey key) {
        byte[] encoded = key.getEncoded();
        try {
            assertArrayEquals(expected, encoded);
        } finally {
            wipe(encoded);
        }
    }

    private static void assertAlreadyOpen(Path path) throws Exception {
        try (KeyringPassword password = password()) {
            KeyringException failure = assertThrows(KeyringException.class, () -> KeyringStore.open(path, password));
            assertSafe(failure, KeyringException.Code.KEYRING_ALREADY_OPEN);
        }
    }

    private static void assertSafe(KeyringException failure, KeyringException.Code expected) {
        assertEquals(expected, failure.code());
        assertEquals(expected.name(), failure.getMessage());
        assertNull(failure.getCause());
    }

    private static void assertSentinelAbsent(Path directory, byte[] sentinel) throws IOException {
        try (java.util.stream.Stream<Path> paths = Files.list(directory)) {
            for (Path current : paths.toList()) {
                if (Files.isRegularFile(current)) {
                    byte[] image = Files.readAllBytes(current);
                    try {
                        assertEquals(-1, indexOf(image, sentinel));
                    } finally {
                        wipe(image);
                    }
                }
            }
        }
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer: for (int index = 0; index <= haystack.length - needle.length; index++) {
            for (int offset = 0; offset < needle.length; offset++) {
                if (haystack[index + offset] != needle[offset]) {
                    continue outer;
                }
            }
            return index;
        }
        return -1;
    }

    private static long longField(KeyringStore store, String name) throws Exception {
        Field field = KeyringStore.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.getLong(store);
    }

    private static Path sidecar(Path keyring) {
        return keyring.resolveSibling(keyring.getFileName() + ".nonce");
    }

    private static KeyringPassword password() {
        return new KeyringPassword(PASSWORD);
    }

    private static KeyringRandomBytes deterministicRandom(int initial) {
        AtomicInteger value = new AtomicInteger(initial);
        return destination -> {
            int base = value.getAndIncrement();
            for (int index = 0; index < destination.length; index++) {
                destination[index] = (byte) (base + index);
            }
        };
    }

    private static byte[] material(byte value) {
        byte[] material = new byte[32];
        Arrays.fill(material, value);
        return material;
    }

    private static void wipe(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private static void start(String method) {
        System.out.println(method);
    }

    private static void ok() {
        System.out.println("...ok");
    }

    /** Throws {@link AccessDeniedException} on {@code atomicReplace} for the first {@code maxDenials} calls,
     *  then delegates to the real NIO implementation. Models Windows Defender / indexer transient lock. */
    private static final class TransientAccessDeniedFileOperations implements KeyringFileOperations {
        private final Target target;
        private final int maxDenials;
        private int denials;
        private final List<Long> pauses = new ArrayList<>();
        private boolean windows = true;
        private boolean interrupted;
        private boolean otherFailure;

        private TransientAccessDeniedFileOperations(Target target, int maxDenials) {
            this.target = target;
            this.maxDenials = maxDenials;
        }

        @Override public KeyringAtomicMoveRetryPolicy atomicMoveRetryPolicy() {
            return KeyringAtomicMoveRetryPolicy.forPlatform(windows, delay -> {
                pauses.add(delay);
                if (interrupted) {
                    throw new InterruptedException("controlled pause interruption");
                }
            });
        }

        @Override public Path createTemporary(Target t, Path parent, String prefix, String suffix) throws IOException {
            return NIO.createTemporary(t, parent, prefix, suffix);
        }
        @Override public void writeTemporary(Target t, Path temporary, byte[] image) throws IOException {
            NIO.writeTemporary(t, temporary, image);
        }
        @Override public void forceTemporary(Target t, Path temporary) throws IOException {
            NIO.forceTemporary(t, temporary);
        }
        @Override public void atomicReplace(Target t, Path temporary, Path destination) throws IOException {
            if (t == target && denials < maxDenials) {
                denials++;
                if (otherFailure) {
                    throw new IOException("controlled unrelated I/O failure");
                }
                throw new AccessDeniedException(temporary.toString(), destination.toString(),
                        "transient AV lock (test stub)");
            }
            NIO.atomicReplace(t, temporary, destination);
        }
        @Override public void forceDirectory(Target t, Path parent) throws IOException {
            NIO.forceDirectory(t, parent);
        }
        @Override public void deleteTemporary(Target t, Path temporary) throws IOException {
            NIO.deleteTemporary(t, temporary);
        }

        int denialsIssued() { return denials; }
    }

    private enum FailureStage {
        CREATE_TEMP, WRITE_TEMP, FORCE_TEMP, ATOMIC_MOVE, FORCE_DIRECTORY, DELETE_TEMP
    }

    private static final class FailingFileOperations implements KeyringFileOperations {
        private final Target target;
        private final FailureStage primaryStage;
        private final boolean failCleanup;
        private final List<Path> temporaryPaths = new ArrayList<>();
        private boolean primaryFailed;
        private boolean cleanupFailed;

        private FailingFileOperations(Target target, FailureStage primaryStage, boolean failCleanup) {
            this.target = target;
            this.primaryStage = primaryStage;
            this.failCleanup = failCleanup;
        }

        @Override
        public Path createTemporary(Target actualTarget, Path parent, String prefix, String suffix)
                throws IOException {
            failBefore(actualTarget, FailureStage.CREATE_TEMP);
            Path temporary = NIO.createTemporary(actualTarget, parent, prefix, suffix);
            if (actualTarget == target) {
                temporaryPaths.add(temporary);
            }
            return temporary;
        }

        @Override
        public void writeTemporary(Target actualTarget, Path temporary, byte[] image) throws IOException {
            NIO.writeTemporary(actualTarget, temporary, image);
            failAfter(actualTarget, FailureStage.WRITE_TEMP);
        }

        @Override
        public void forceTemporary(Target actualTarget, Path temporary) throws IOException {
            NIO.forceTemporary(actualTarget, temporary);
            failAfter(actualTarget, FailureStage.FORCE_TEMP);
        }

        @Override
        public void atomicReplace(Target actualTarget, Path temporary, Path destination) throws IOException {
            failBefore(actualTarget, FailureStage.ATOMIC_MOVE);
            NIO.atomicReplace(actualTarget, temporary, destination);
        }

        @Override
        public void forceDirectory(Target actualTarget, Path parent) throws IOException {
            failBefore(actualTarget, FailureStage.FORCE_DIRECTORY);
            NIO.forceDirectory(actualTarget, parent);
        }

        @Override
        public void deleteTemporary(Target actualTarget, Path temporary) throws IOException {
            if (actualTarget == target && failCleanup && !cleanupFailed) {
                cleanupFailed = true;
                throw new IOException("DELETE_TEMP_SENTINEL");
            }
            NIO.deleteTemporary(actualTarget, temporary);
        }

        private void failBefore(Target actualTarget, FailureStage stage) throws IOException {
            if (actualTarget == target && primaryStage == stage && !primaryFailed) {
                primaryFailed = true;
                throw new IOException(stage.name() + "_SENTINEL");
            }
        }

        private void failAfter(Target actualTarget, FailureStage stage) throws IOException {
            failBefore(actualTarget, stage);
        }

        private Path firstTemporary() {
            return temporaryPaths.get(0);
        }

        private Path lastTemporary() {
            return temporaryPaths.get(temporaryPaths.size() - 1);
        }
    }
}
