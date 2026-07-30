package zeroecho.core.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Field;
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
    void cleanupFailuresPreservePrimaryAndEncryptedResiduals() throws Exception {
        start("cleanupFailuresPreservePrimaryAndEncryptedResiduals");
        assertCleanupFailure(Target.MAIN_IMAGE, "cleanup-main.zek");
        assertCleanupFailure(Target.NONCE_RESERVATION, "cleanup-sidecar.zek");
        ok();
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
            assertEquals(FILE_PERMISSIONS, Files.getPosixFilePermissions(residual));
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
        public Path createTemporary(Target actualTarget, Path parent, String prefix, String suffix,
                FileAttribute<Set<PosixFilePermission>> permissions) throws IOException {
            failBefore(actualTarget, FailureStage.CREATE_TEMP);
            Path temporary = NIO.createTemporary(actualTarget, parent, prefix, suffix, permissions);
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
