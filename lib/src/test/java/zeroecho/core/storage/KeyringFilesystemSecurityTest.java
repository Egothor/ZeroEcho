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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.LogManager;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KeyringFilesystemSecurityTest {
    private static final char[] PASSWORD = { 'f', 'i', 'l', 'e', 's', 'y', 's' };
    private static final byte[] CHILD_PASSWORD = { 'f', 'i', 'l', 'e', 's', 'y', 's' };
    private static final long TIMEOUT_SECONDS = 15L;
    private static final Set<PosixFilePermission> DIRECTORY_PERMISSIONS = Set.of(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);
    private static final Set<PosixFilePermission> FILE_PERMISSIONS = Set.of(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE);

    @TempDir
    Path temporaryDirectory;

    @Test
    void secureCreationAndUnsafePermissionsMatrix() throws Exception {
        start("secureCreationAndUnsafePermissionsMatrix");
        Path parent = temporaryDirectory.resolve("secure");
        Path path = parent.resolve("keys.zek");
        createPopulated(path, 1);
        assertEquals(DIRECTORY_PERMISSIONS, Files.getPosixFilePermissions(parent));
        assertEquals(FILE_PERMISSIONS, Files.getPosixFilePermissions(path));
        assertEquals(FILE_PERMISSIONS, Files.getPosixFilePermissions(lock(path)));
        assertEquals(FILE_PERMISSIONS, Files.getPosixFilePermissions(sidecar(path)));
        try (java.util.stream.Stream<Path> files = Files.list(parent)) {
            assertTrue(files.noneMatch(value -> value.getFileName().toString().endsWith(".tmp")));
        }
        assertOpenSucceeds(path);

        for (PosixFilePermission unsafe : List.of(PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE,
                PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE)) {
            Path unsafeParent = temporaryDirectory.resolve("parent-" + unsafe.name());
            Path unsafeStore = unsafeParent.resolve("keys.zek");
            createPopulated(unsafeStore, unsafe.ordinal() + 10);
            Set<PosixFilePermission> permissions = new java.util.HashSet<>(DIRECTORY_PERMISSIONS);
            permissions.add(unsafe);
            Files.setPosixFilePermissions(unsafeParent, permissions);
            assertRedactedFailure(unsafeStore, KeyringException.Code.KEYRING_FILESYSTEM_UNSUPPORTED);
            Files.setPosixFilePermissions(unsafeParent, DIRECTORY_PERMISSIONS);
        }

        assertUnsafeFilePermissions("main", Artifact.MAIN);
        assertUnsafeFilePermissions("lock", Artifact.LOCK);
        assertUnsafeFilePermissions("sidecar", Artifact.SIDECAR);
        ok();
    }

    @Test
    void nonPosixAndOwnershipMismatchFailClosed() throws Exception {
        start("nonPosixAndOwnershipMismatchFailClosed");
        Path archive = temporaryDirectory.resolve("non-posix.zip");
        URI uri = URI.create("jar:" + archive.toUri());
        try (FileSystem fileSystem = FileSystems.newFileSystem(uri, Map.of("create", "true"));
                KeyringPassword password = password()) {
            KeyringException failure = assertThrows(KeyringException.class,
                    () -> KeyringStore.create(fileSystem.getPath("/keys.zek"), password));
            assertEquals(KeyringException.Code.KEYRING_FILESYSTEM_UNSUPPORTED, failure.code());
            assertEquals(failure.code().name(), failure.getMessage());
            assertNull(failure.getCause());
        }

        Path path = temporaryDirectory.resolve("owner-mismatch.zek");
        createPopulated(path, 31);
        Method validator = KeyringStore.class.getDeclaredMethod("validateExistingFile", Path.class,
                UserPrincipal.class);
        validator.setAccessible(true);
        UserPrincipal other = () -> "controlled-other-owner";
        InvocationTargetException failure = assertThrows(InvocationTargetException.class,
                () -> validator.invoke(null, path, other));
        assertTrue(failure.getCause() instanceof KeyringException);
        assertEquals(KeyringException.Code.KEYRING_FILESYSTEM_UNSUPPORTED,
                ((KeyringException) failure.getCause()).code());
        ok();
    }

    @Test
    void symlinkAndHardLinkMatrixFailsClosed() throws Exception {
        start("symlinkAndHardLinkMatrixFailsClosed");
        assertKeyringSymlinkRejected();
        assertArtifactSymlinkRejected(Artifact.LOCK);
        assertArtifactSymlinkRejected(Artifact.SIDECAR);
        assertParentSymlinkRejected();
        assertArtifactHardLinkRejected(Artifact.MAIN);
        assertArtifactHardLinkRejected(Artifact.LOCK);
        assertArtifactHardLinkRejected(Artifact.SIDECAR);
        assertPrecreatedTemporarySymlinkIgnored();
        ok();
    }

    @Test
    void sameJvmOwnershipAndIndependentStores() throws Exception {
        start("sameJvmOwnershipAndIndependentStores");
        Path path = temporaryDirectory.resolve("shared.zek");
        byte[] material = material((byte) 0x41);
        try (KeyringPassword password = password();
                KeyringStore first = KeyringStore.create(path, password, KeyringProtection.standard(),
                        deterministicRandom(41));
                KeyringPassword secondPassword = password()) {
            first.putSecret("shared", "AES", new SecretKeySpec(material, "AES"));
            KeyringException contention = assertThrows(KeyringException.class,
                    () -> KeyringStore.open(path, secondPassword));
            assertEquals(KeyringException.Code.KEYRING_ALREADY_OPEN, contention.code());
            assertEquals(KeyringException.Code.KEYRING_ALREADY_OPEN.name(), contention.getMessage());
            assertNull(contention.getCause());
            assertArrayEquals(material, first.getSecret("shared").getEncoded());
        } finally {
            wipe(material);
        }
        assertOpenSucceeds(path);

        Path firstPath = temporaryDirectory.resolve("independent-one.zek");
        Path secondPath = temporaryDirectory.resolve("independent-two.zek");
        try (KeyringPassword firstPassword = password();
                KeyringPassword secondPassword = password();
                KeyringStore first = KeyringStore.create(firstPath, firstPassword);
                KeyringStore second = KeyringStore.create(secondPath, secondPassword)) {
            assertTrue(first.aliases().isEmpty());
            assertTrue(second.aliases().isEmpty());
        }
        ok();
    }

    @Test
    void forkedJvmOwnershipReleasesGracefullyAndAfterTermination() throws Exception {
        start("forkedJvmOwnershipReleasesGracefullyAndAfterTermination");
        Path graceful = temporaryDirectory.resolve("fork-graceful.zek");
        createPopulated(graceful, 51);
        try (ChildOwner child = ChildOwner.start(graceful)) {
            child.sendPassword(CHILD_PASSWORD);
            child.expect("KEYRING_OPEN");
            assertAlreadyOpen(graceful);
            child.send("PING");
            child.expect("KEYRING_USABLE");
            child.send("CLOSE");
            child.expect("KEYRING_CLOSED");
            child.awaitExit(0);
            assertFalse(child.outputContains("filesys"));
        }
        assertOpenSucceeds(graceful);

        Path abrupt = temporaryDirectory.resolve("fork-abrupt.zek");
        createPopulated(abrupt, 61);
        try (ChildOwner child = ChildOwner.start(abrupt)) {
            child.sendPassword(CHILD_PASSWORD);
            child.expect("KEYRING_OPEN");
            assertAlreadyOpen(abrupt);
            child.destroyForcibly();
        }
        assertOpenSucceeds(abrupt);
        ok();
    }

    @Test
    void concurrentReadsAndSerializedMutationsRemainConsistent() throws Exception {
        start("concurrentReadsAndSerializedMutationsRemainConsistent");
        Path path = temporaryDirectory.resolve("concurrent.zek");
        byte[] first = material((byte) 0x12);
        byte[] second = material((byte) 0x34);
        try (KeyringPassword password = password();
                KeyringStore store = KeyringStore.create(path, password, KeyringProtection.standard(),
                        deterministicRandom(71))) {
            store.putSecret("one", "AES", new SecretKeySpec(first, "AES"));
            store.putSecret("two", "AES", new SecretKeySpec(second, "AES"));
            runConcurrentReaders(store, first, second);
            runConcurrentPuts(store);
        } finally {
            wipe(first);
            wipe(second);
        }
        assertOpenSucceeds(path);
        ok();
    }

    @Test
    void closeWaitsForAdmittedOperationsAndClearsKeysOnce() throws Exception {
        start("closeWaitsForAdmittedOperationsAndClearsKeysOnce");
        Path path = temporaryDirectory.resolve("close-coordination.zek");
        KeyringStore store;
        try (KeyringPassword password = password()) {
            store = KeyringStore.create(path, password);
        }
        byte[] master = bytesField(store, "masterKey");
        byte[] macKey = bytesField(store, "nonceReservationMacKey");
        ReentrantReadWriteLock lock = lockField(store);
        lock.readLock().lock();
        CountDownLatch started = new CountDownLatch(2);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread first = closeThread(store, started, failure, "keyring-close-one");
        Thread second = closeThread(store, started, failure, "keyring-close-two");
        first.start();
        second.start();
        assertTrue(started.await(TIMEOUT_SECONDS, TimeUnit.SECONDS));
        awaitQueued(lock, 2);
        assertFalse(store.isDestroyed());
        lock.readLock().unlock();
        first.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
        second.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
        assertFalse(first.isAlive());
        assertFalse(second.isAlive());
        assertNull(failure.get());
        assertTrue(store.isDestroyed());
        assertTrue(allZero(master));
        assertTrue(allZero(macKey));
        assertThrows(IllegalStateException.class, store::aliases);
        store.close();
        assertOpenSucceeds(path);
        ok();
    }

    @Test
    void admittedMutationCompletesBeforeCloseAndLaterMutationFails() throws Exception {
        start("admittedMutationCompletesBeforeCloseAndLaterMutationFails");
        Path path = temporaryDirectory.resolve("mutation-close.zek");
        BlockingRandom random = new BlockingRandom(81);
        KeyringStore store;
        try (KeyringPassword password = password()) {
            store = KeyringStore.create(path, password, KeyringProtection.standard(), random);
        }
        byte[] material = material((byte) 0x5c);
        AtomicReference<Throwable> putFailure = new AtomicReference<>();
        AtomicReference<Throwable> closeFailure = new AtomicReference<>();
        random.arm();
        Thread mutation = new Thread(() -> {
            try {
                store.putSecret("admitted", "AES", new SecretKeySpec(material, "AES"));
            } catch (Throwable throwable) {
                putFailure.set(throwable);
            }
        }, "keyring-admitted-mutation");
        mutation.start();
        assertTrue(random.awaitEntered());
        Thread closer = new Thread(() -> {
            try {
                store.close();
            } catch (Throwable throwable) {
                closeFailure.set(throwable);
            }
        }, "keyring-close-after-mutation");
        closer.start();
        awaitQueued(lockField(store), 1);
        random.release();
        mutation.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
        closer.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
        assertNull(putFailure.get());
        assertNull(closeFailure.get());
        assertTrue(store.isDestroyed());
        assertThrows(KeyringException.class, () -> store.putSecret("late", "AES", new SecretKeySpec(material, "AES")));
        try (KeyringPassword password = password(); KeyringStore reopened = KeyringStore.open(path, password)) {
            assertArrayEquals(material, reopened.getSecret("admitted").getEncoded());
        } finally {
            wipe(material);
        }
        ok();
    }

    private void assertUnsafeFilePermissions(String name, Artifact artifact) throws Exception {
        Path path = temporaryDirectory.resolve("unsafe-" + name + ".zek");
        createPopulated(path, artifact.ordinal() + 20);
        Path target = artifact.path(path);
        Set<PosixFilePermission> permissions = new java.util.HashSet<>(FILE_PERMISSIONS);
        permissions.add(PosixFilePermission.GROUP_READ);
        Files.setPosixFilePermissions(target, permissions);
        assertRedactedFailure(path, KeyringException.Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        Files.setPosixFilePermissions(target, FILE_PERMISSIONS);
    }

    private void assertKeyringSymlinkRejected() throws Exception {
        Path target = temporaryDirectory.resolve("symlink-main-target.zek");
        createPopulated(target, 91);
        byte[] before = Files.readAllBytes(target);
        Path link = temporaryDirectory.resolve("symlink-main.zek");
        Files.createSymbolicLink(link, target.getFileName());
        try {
            assertRedactedFailure(link, KeyringException.Code.KEYRING_FILESYSTEM_UNSUPPORTED);
            assertArrayEquals(before, Files.readAllBytes(target));
        } finally {
            wipe(before);
        }
    }

    private void assertArtifactSymlinkRejected(Artifact artifact) throws Exception {
        Path path = temporaryDirectory.resolve("symlink-" + artifact.name() + ".zek");
        createPopulated(path, 101 + artifact.ordinal());
        Path original = artifact.path(path);
        Path saved = original.resolveSibling(original.getFileName() + ".saved");
        Files.move(original, saved);
        Path target = temporaryDirectory.resolve("symlink-target-" + artifact.name());
        Files.write(target, new byte[] { 7 });
        ownerOnly(target);
        byte[] before = Files.readAllBytes(target);
        Files.createSymbolicLink(original, target.getFileName());
        try {
            assertRedactedFailure(path, KeyringException.Code.KEYRING_FILESYSTEM_UNSUPPORTED);
            assertArrayEquals(before, Files.readAllBytes(target));
        } finally {
            wipe(before);
        }
    }

    private void assertParentSymlinkRejected() throws Exception {
        Path real = temporaryDirectory.resolve("real-parent");
        Path path = real.resolve("keys.zek");
        createPopulated(path, 111);
        Path link = temporaryDirectory.resolve("linked-parent");
        Files.createSymbolicLink(link, real.getFileName());
        assertRedactedFailure(link.resolve("keys.zek"), KeyringException.Code.KEYRING_FILESYSTEM_UNSUPPORTED);
    }

    private void assertArtifactHardLinkRejected(Artifact artifact) throws Exception {
        Path path = temporaryDirectory.resolve("hard-" + artifact.name() + ".zek");
        createPopulated(path, 121 + artifact.ordinal());
        Path target = artifact.path(path);
        Path extra = target.resolveSibling(target.getFileName() + ".hard");
        Files.createLink(extra, target);
        try {
            assertRedactedFailure(path, KeyringException.Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        } finally {
            Files.delete(extra);
        }
    }

    private void assertPrecreatedTemporarySymlinkIgnored() throws Exception {
        Path path = temporaryDirectory.resolve("temp-race.zek");
        createPopulated(path, 131);
        Path target = temporaryDirectory.resolve("temp-target");
        Files.write(target, new byte[] { 9, 8, 7 });
        ownerOnly(target);
        byte[] before = Files.readAllBytes(target);
        Path malicious = temporaryDirectory.resolve(".temp-race.zek.precreated.tmp");
        Files.createSymbolicLink(malicious, target.getFileName());
        byte[] material = material((byte) 0x63);
        try (KeyringPassword password = password(); KeyringStore store = KeyringStore.open(path, password)) {
            store.putSecret("safe", "AES", new SecretKeySpec(material, "AES"));
            assertArrayEquals(before, Files.readAllBytes(target));
        } finally {
            wipe(before);
            wipe(material);
        }
    }

    private void runConcurrentReaders(KeyringStore store, byte[] first, byte[] second) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> results = new ArrayList<>();
        try {
            for (int index = 0; index < 8; index++) {
                int selected = index;
                results.add(executor.submit(() -> {
                    start.await();
                    if (selected == 7) {
                        assertThrows(IllegalArgumentException.class, () -> store.getSecret("missing"));
                        return true;
                    }
                    String alias = selected % 2 == 0 ? "one" : "two";
                    byte[] expected = selected % 2 == 0 ? first : second;
                    SecretKey key = store.getSecret(alias);
                    byte[] encoded = key.getEncoded();
                    try {
                        return Arrays.equals(expected, encoded);
                    } finally {
                        wipe(encoded);
                    }
                }));
            }
            start.countDown();
            for (Future<Boolean> result : results) {
                assertTrue(result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS));
            }
        } finally {
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(TIMEOUT_SECONDS, TimeUnit.SECONDS));
        }
    }

    private void runConcurrentPuts(KeyringStore store) throws Exception {
        byte[] third = material((byte) 0x71);
        byte[] fourth = material((byte) 0x72);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch start = new CountDownLatch(1);
        try {
            Future<?> one = executor.submit(() -> {
                start.await();
                store.putSecret("three", "AES", new SecretKeySpec(third, "AES"));
                return null;
            });
            Future<?> two = executor.submit(() -> {
                start.await();
                store.putSecret("four", "AES", new SecretKeySpec(fourth, "AES"));
                return null;
            });
            start.countDown();
            one.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            two.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            assertArrayEquals(third, store.getSecret("three").getEncoded());
            assertArrayEquals(fourth, store.getSecret("four").getEncoded());
        } finally {
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(TIMEOUT_SECONDS, TimeUnit.SECONDS));
            wipe(third);
            wipe(fourth);
        }
    }

    private void createPopulated(Path path, int seed) throws Exception {
        byte[] material = material((byte) seed);
        try (KeyringPassword password = password();
                KeyringStore store = KeyringStore.create(path, password, KeyringProtection.standard(),
                        deterministicRandom(seed))) {
            store.putSecret("child", "AES", new SecretKeySpec(material, "AES"));
        } finally {
            wipe(material);
        }
    }

    private static void assertOpenSucceeds(Path path) throws Exception {
        try (KeyringPassword password = password(); KeyringStore store = KeyringStore.open(path, password)) {
            assertFalse(store.isDestroyed());
            store.aliases();
        }
    }

    private static void assertAlreadyOpen(Path path) throws Exception {
        try (KeyringPassword password = password()) {
            KeyringException failure = assertThrows(KeyringException.class, () -> KeyringStore.open(path, password));
            assertEquals(KeyringException.Code.KEYRING_ALREADY_OPEN, failure.code());
            assertEquals(failure.code().name(), failure.getMessage());
            assertNull(failure.getCause());
        }
    }

    private static void assertRedactedFailure(Path path, KeyringException.Code code) throws Exception {
        try (KeyringPassword password = password()) {
            KeyringException failure = assertThrows(KeyringException.class, () -> KeyringStore.open(path, password));
            assertEquals(code, failure.code());
            assertEquals(code.name(), failure.getMessage());
            assertNull(failure.getCause());
            assertEquals(0, failure.getSuppressed().length);
            assertFalse(failure.getMessage().contains(path.toString()));
        }
    }

    private static Thread closeThread(KeyringStore store, CountDownLatch started, AtomicReference<Throwable> failure,
            String name) {
        return new Thread(() -> {
            started.countDown();
            try {
                store.close();
            } catch (Throwable throwable) {
                failure.compareAndSet(null, throwable);
            }
        }, name);
    }

    private static void awaitQueued(ReentrantReadWriteLock lock, int minimum) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(TIMEOUT_SECONDS);
        while (lock.getQueueLength() < minimum && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        assertTrue(lock.getQueueLength() >= minimum);
    }

    private static ReentrantReadWriteLock lockField(KeyringStore store) throws Exception {
        Field field = KeyringStore.class.getDeclaredField("lifecycleLock");
        field.setAccessible(true);
        return (ReentrantReadWriteLock) field.get(store);
    }

    private static byte[] bytesField(KeyringStore store, String name) throws Exception {
        Field field = KeyringStore.class.getDeclaredField(name);
        field.setAccessible(true);
        return (byte[]) field.get(store);
    }

    private static boolean allZero(byte[] value) {
        for (byte current : value) {
            if (current != 0) {
                return false;
            }
        }
        return true;
    }

    private static byte[] material(byte value) {
        byte[] result = new byte[32];
        Arrays.fill(result, value);
        return result;
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

    private static void ownerOnly(Path path) throws Exception {
        Files.setPosixFilePermissions(path, FILE_PERMISSIONS);
    }

    private static Path lock(Path keyring) {
        return keyring.resolveSibling(keyring.getFileName() + ".lock");
    }

    private static Path sidecar(Path keyring) {
        return keyring.resolveSibling(keyring.getFileName() + ".nonce");
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

    private enum Artifact {
        MAIN {
            @Override
            Path path(Path keyring) {
                return keyring;
            }
        },
        LOCK {
            @Override
            Path path(Path keyring) {
                return lock(keyring);
            }
        },
        SIDECAR {
            @Override
            Path path(Path keyring) {
                return sidecar(keyring);
            }
        };

        abstract Path path(Path keyring);
    }

    private static final class BlockingRandom implements KeyringRandomBytes {
        private final AtomicInteger value;
        private final AtomicBoolean armed = new AtomicBoolean();
        private final AtomicBoolean blocked = new AtomicBoolean();
        private final CountDownLatch entered = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);

        private BlockingRandom(int initial) {
            value = new AtomicInteger(initial);
        }

        private void arm() {
            armed.set(true);
        }

        private boolean awaitEntered() throws InterruptedException {
            return entered.await(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        }

        private void release() {
            release.countDown();
        }

        @Override
        public void nextBytes(byte[] destination) {
            if (armed.get() && blocked.compareAndSet(false, true)) {
                entered.countDown();
                try {
                    if (!release.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("controlled random release timed out");
                    }
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("controlled random interrupted");
                }
            }
            int base = value.getAndIncrement();
            for (int index = 0; index < destination.length; index++) {
                destination[index] = (byte) (base + index);
            }
        }
    }

    private static final class ChildOwner implements AutoCloseable {
        private final Process process;
        private final BufferedReader output;
        private final OutputStream input;
        private final ExecutorService reader = Executors.newSingleThreadExecutor();
        private final StringBuilder transcript = new StringBuilder();

        private ChildOwner(Process process) {
            this.process = process;
            output = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
            input = process.getOutputStream();
        }

        private static ChildOwner start(Path path) throws Exception {
            String executable = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("win")
                    ? "java.exe"
                    : "java";
            Path java = Path.of(System.getProperty("java.home"), "bin", executable);
            Process process = new ProcessBuilder(java.toString(), "-cp", childClasspath(),
                    KeyringStoreLockProcess.class.getName(), path.toString()).redirectErrorStream(true).start();
            return new ChildOwner(process);
        }

        private void sendPassword(byte[] password) throws IOException {
            byte[] copy = password.clone();
            try {
                input.write(copy);
                input.write('\n');
                input.flush();
            } finally {
                wipe(copy);
            }
        }

        private void send(String command) throws IOException {
            byte[] encoded = command.getBytes(StandardCharsets.US_ASCII);
            try {
                input.write(encoded);
                input.write('\n');
                input.flush();
            } finally {
                wipe(encoded);
            }
        }

        private void expect(String expected) throws Exception {
            Future<String> future = reader.submit(output::readLine);
            String line;
            try {
                line = future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            } catch (ExecutionException exception) {
                throw new IOException("child protocol failed");
            } catch (TimeoutException exception) {
                future.cancel(true);
                throw new IOException("child protocol timed out");
            }
            transcript.append(line);
            assertEquals(expected, line);
        }

        private boolean outputContains(String value) {
            return transcript.toString().contains(value);
        }

        private void awaitExit(int expected) throws Exception {
            assertTrue(process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS));
            assertEquals(expected, process.exitValue());
        }

        private void destroyForcibly() throws Exception {
            process.destroyForcibly();
            assertTrue(process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS));
        }

        @Override
        public void close() throws Exception {
            if (process.isAlive()) {
                process.destroyForcibly();
                process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            }
            input.close();
            output.close();
            reader.shutdownNow();
            assertTrue(reader.awaitTermination(TIMEOUT_SECONDS, TimeUnit.SECONDS));
        }
    }

    private static String childClasspath() throws Exception {
        Set<String> entries = new LinkedHashSet<>();
        String configured = System.getProperty("java.class.path", "");
        if (!configured.isBlank()) {
            entries.addAll(Arrays.asList(configured.split(java.io.File.pathSeparator)));
        }
        ClassLoader loader = KeyringFilesystemSecurityTest.class.getClassLoader();
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
        entries.add(codeSource(KeyringFilesystemSecurityTest.class));
        entries.add(codeSource(KeyringStore.class));
        return String.join(java.io.File.pathSeparator, entries);
    }

    private static String codeSource(Class<?> type) throws Exception {
        return Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
    }
}

final class KeyringStoreLockProcess {
    private KeyringStoreLockProcess() {
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("SETUP_FAILED");
            System.exit(2);
        }
        LogManager.getLogManager().reset();
        byte[] passwordBytes = null;
        char[] passwordChars = null;
        try {
            passwordBytes = readSecret(System.in, 64);
            passwordChars = new char[passwordBytes.length];
            for (int index = 0; index < passwordBytes.length; index++) {
                passwordChars[index] = (char) Byte.toUnsignedInt(passwordBytes[index]);
            }
            try (KeyringPassword password = new KeyringPassword(passwordChars);
                    KeyringStore store = KeyringStore.open(Path.of(args[0]), password);
                    BufferedReader control = new BufferedReader(
                            new InputStreamReader(System.in, StandardCharsets.US_ASCII))) {
                Arrays.fill(passwordChars, '\0');
                Arrays.fill(passwordBytes, (byte) 0);
                System.out.println("KEYRING_OPEN");
                System.out.flush();
                String command;
                while ((command = control.readLine()) != null) {
                    if ("PING".equals(command)) {
                        store.aliases();
                        System.out.println("KEYRING_USABLE");
                        System.out.flush();
                    } else if ("CLOSE".equals(command)) {
                        store.close();
                        System.out.println("KEYRING_CLOSED");
                        System.out.flush();
                        return;
                    } else {
                        System.out.println("PROTOCOL_FAILED");
                        System.out.flush();
                        System.exit(3);
                    }
                }
            }
        } catch (Exception exception) {
            System.out.println("SETUP_FAILED");
            System.exit(4);
        } finally {
            if (passwordChars != null) {
                Arrays.fill(passwordChars, '\0');
            }
            wipe(passwordBytes);
        }
    }

    private static byte[] readSecret(InputStream input, int maximum) throws IOException {
        byte[] buffer = new byte[maximum];
        int count = 0;
        try {
            int current;
            while ((current = input.read()) >= 0 && current != '\n') {
                if (count >= maximum) {
                    throw new IOException("secret input exceeded test protocol limit");
                }
                buffer[count++] = (byte) current;
            }
            if (current < 0) {
                throw new IOException("secret input ended early");
            }
            return Arrays.copyOf(buffer, count);
        } finally {
            wipe(buffer);
        }
    }

    private static void wipe(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
