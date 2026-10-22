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
package zeroecho.core.storage;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import zeroecho.sdk.util.BouncyCastleActivator;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import zeroecho.core.storage.KeyringFileOperations.Target;

/** Real-filesystem integration coverage of logical alias transactions. */
class KeyringAliasMutationTest {
    @TempDir Path directory;
    @BeforeAll static void provider() { BouncyCastleActivator.init(); }

    @Test
    void pairAndSecretRemovalPreserveOtherAliasesAndReopen() throws Exception {
        Path path = directory.resolve("normal.zek");
        KeyPair pair = pair();
        try (KeyringPassword password = password(); KeyringStore store = KeyringStore.create(path, password)) {
            secret(store, "first");
            store.putKeyPairIfAbsent("token", "Ed25519", pair);
            secret(store, "last");
            assertPair(store, pair, true);
            assertThrows(IllegalArgumentException.class, () -> store.putKeyPairIfAbsent("token", "Ed25519", pair));
            assertTrue(store.removeAlias("first"));
            assertFalse(store.removeAlias("first"));
            assertPair(store, pair, true);
        }
        try (KeyringPassword password = password(); KeyringStore store = KeyringStore.open(path, password)) {
            assertPair(store, pair, true);
            assertTrue(store.removeAlias("token"));
            assertFalse(store.removeAlias("token"));
            assertNotNull(store.getSecret("last"));
        }
        try (KeyringPassword password = password(); KeyringStore store = KeyringStore.open(path, password)) {
            assertPair(store, pair, false);
            assertNotNull(store.getSecret("last"));
            assertFalse(store.contains("first"));
        }
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "token.pub", "token.priv", "token.pub.priv"})
    void rejectsInvalidLogicalAliasesWithoutWriting(String alias) throws Exception {
        Path path = directory.resolve("invalid.zek");
        KeyPair pair = pair();
        try (KeyringPassword password = password(); KeyringStore store = KeyringStore.create(path, password)) {
            byte[] before = Files.readAllBytes(path);
            assertThrows(IllegalArgumentException.class, () -> store.putKeyPairIfAbsent(alias, "Ed25519", pair));
            assertThrows(IllegalArgumentException.class, () -> store.removeAlias(alias));
            assertArrayEquals(before, Files.readAllBytes(path));
        }
    }

    @Test
    void validatesBothComponentsAndAlgorithmBeforeAnyPersistence() throws Exception {
        Path path = directory.resolve("validation.zek");
        Faults faults = new Faults();
        KeyPair pair = pair();
        try (KeyringPassword password = password(); KeyringStore store = KeyringStore.create(path, password)) { assertFalse(store.contains("token")); }
        try (KeyringPassword password = password(); KeyringStore store = KeyringStore.open(path, password,
                KeyringProtection.standard(), new java.security.SecureRandom()::nextBytes, faults)) {
            assertThrows(NullPointerException.class, () -> store.putKeyPairIfAbsent("token", "Ed25519", null));
            assertThrows(NullPointerException.class, () -> store.putKeyPairIfAbsent("token", "Ed25519", new KeyPair(pair.getPublic(), null)));
            assertThrows(NullPointerException.class, () -> store.putKeyPairIfAbsent("token", "Ed25519", new KeyPair(null, pair.getPrivate())));
            KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            assertThrows(IOException.class, () -> store.putKeyPairIfAbsent("token", "Ed25519", new KeyPair(pair.getPublic(), rsa.getPrivate())));
            assertThrows(IOException.class, () -> store.putKeyPairIfAbsent("token", "AES", pair));
            assertThrows(IOException.class, () -> store.putKeyPairIfAbsent("token", "unknown", pair));
            assertThrows(IOException.class, () -> store.putKeyPairIfAbsent("x".repeat(4096), "Ed25519", pair));
            for (String format : new String[] {null, "RAW", "PKCS#8"}) {
                java.security.PrivateKey invalid = new java.security.PrivateKey() {
                    private static final long serialVersionUID = 1L;
                    @Override public String getAlgorithm() { return "Ed25519"; }
                    @Override public String getFormat() { return format; }
                    @Override public byte[] getEncoded() { return null; }
                };
                assertThrows(KeyringException.class, () -> store.putKeyPairIfAbsent("token", "Ed25519", new KeyPair(pair.getPublic(), invalid)));
            }
            assertFalse(store.removeAlias("missing"));
            assertEquals(0, faults.creations);
            assertFalse(store.contains("token"));
        }
    }

    @Test
    void rejectsCollisionsAndPreservesLegacyStandaloneOperations() throws Exception {
        KeyPair pair = pair();
        Path path = directory.resolve("collisions.zek");
        try (KeyringPassword password = password(); KeyringStore store = KeyringStore.create(path, password)) {
            secret(store, "token.pub");
            store.putPrivate("token.pub", "Ed25519", pair.getPrivate());
            assertThrows(IllegalArgumentException.class, () -> store.putKeyPairIfAbsent("token", "Ed25519", pair));
            assertThrows(IllegalArgumentException.class, () -> store.removeAlias("token"));
            assertNotNull(store.getSecret("token.pub"));
            assertArrayEquals(pair.getPrivate().getEncoded(), store.getPrivate("token.pub").getEncoded());
            store.putPublic("partial", "Ed25519", pair.getPublic());
            assertThrows(IllegalArgumentException.class, () -> store.putKeyPairIfAbsent("partial", "Ed25519", pair));
            assertTrue(store.removeAlias("partial"));
            secret(store, "mixed");
            store.putPrivate("mixed", "Ed25519", pair.getPrivate());
            assertThrows(IllegalArgumentException.class, () -> store.removeAlias("mixed"));
            assertNotNull(store.getSecret("mixed"));
            assertNotNull(store.getPrivate("mixed"));
        }
    }

    @Test
    void acceptsMaximumUtf8AliasesAndRejectsOverLimitWithoutMutation() throws Exception {
        Path path = directory.resolve("boundary.zek");
        KeyPair pair = pair();
        try (KeyringPassword password = password(); KeyringStore store = KeyringStore.create(path, password)) {
            String longestSecret = "é".repeat(256);
            secret(store, longestSecret);
            assertTrue(store.removeAlias(longestSecret));
            String longestPair = "é".repeat(253) + "x";
            store.putKeyPairIfAbsent(longestPair, "Ed25519", pair);
            assertNotNull(store.getPublic(longestPair));
            assertTrue(store.removeAlias(longestPair));
            assertThrows(KeyringException.class, () -> store.putKeyPairIfAbsent(longestPair + "x", "Ed25519", pair));
            assertThrows(KeyringException.class, () -> store.removeAlias(longestSecret + "x"));
        }
    }

    @Test
    void statefulActiveAndPublicOnlyAliasesCannotBeRemoved() throws Exception {
        Path path = directory.resolve("keys/stateful.zek");
        try (KeyringPassword password = password(); KeyringStore store = KeyringStore.create(path, password);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.create(directory.resolve("authority"))) {
            store.generateStatefulKey("active", "LMS", authority);
            store.putPublic("exhausted", "LMS", store.getPublic("active"));
            secret(store, "other");
            byte[] before = Files.readAllBytes(path);
            for (String alias : List.of("active", "exhausted")) {
                assertEquals(KeyringException.Code.KEYRING_STATEFUL_RECOVERY_REQUIRED,
                        assertThrows(KeyringException.class, () -> store.removeAlias(alias)).code());
                assertNotNull(store.getPublic(alias));
            }
            assertArrayEquals(before, Files.readAllBytes(path));
            assertNotNull(store.getPrivate("active"));
            assertNotNull(store.getSecret("other"));
        }
    }

    @Test
    void closedStoreAndConcurrentInsertionHaveUnambiguousResults() throws Exception {
        KeyPair pair = pair();
        Path path = directory.resolve("concurrent.zek");
        KeyringStore store;
        try (KeyringPassword password = password()) { store = KeyringStore.create(path, password); }
        try (var executor = Executors.newFixedThreadPool(2)) {
            CountDownLatch start = new CountDownLatch(1);
            java.util.concurrent.Callable<Boolean> insert = () -> {
                if (!start.await(30, TimeUnit.SECONDS)) { throw new AssertionError("Start latch timed out"); }
                try { store.putKeyPairIfAbsent("token", "Ed25519", pair); return true; }
                catch (IllegalArgumentException occupied) { return false; }
            };
            Future<Boolean> first = executor.submit(insert);
            Future<Boolean> second = executor.submit(insert);
            start.countDown();
            assertNotEquals(first.get(30, TimeUnit.SECONDS), second.get(30, TimeUnit.SECONDS));
            assertPair(store, pair, true);
        } finally { store.close(); }
        assertEquals(KeyringException.Code.KEYRING_CLOSED,
                assertThrows(KeyringException.class, () -> store.putKeyPairIfAbsent("token", "Ed25519", pair)).code());
        assertEquals(KeyringException.Code.KEYRING_CLOSED,
                assertThrows(KeyringException.class, () -> store.removeAlias("token")).code());
    }

    @Test
    void concurrentRemovalIsIdempotent() throws Exception {
        Path path = directory.resolve("remove-concurrent.zek");
        try (KeyringPassword password = password(); KeyringStore store = KeyringStore.create(path, password);
                var executor = Executors.newFixedThreadPool(2)) {
            store.putKeyPairIfAbsent("token", "Ed25519", pair());
            secret(store, "other");
            CountDownLatch start = new CountDownLatch(1);
            java.util.concurrent.Callable<Boolean> remove = () -> { if (!start.await(30, TimeUnit.SECONDS)) { throw new AssertionError("Start latch timed out"); } return store.removeAlias("token"); };
            Future<Boolean> first = executor.submit(remove);
            Future<Boolean> second = executor.submit(remove);
            start.countDown();
            assertNotEquals(first.get(30, TimeUnit.SECONDS), second.get(30, TimeUnit.SECONDS));
            assertFalse(store.contains("token"));
            assertNotNull(store.getSecret("other"));
        }
    }

    @Test
    @SuppressWarnings("try") // Explicit close is the concurrent operation under test; the resource also guarantees cleanup.
    void closeWaitsForPairPublication() throws Exception {
        Path path = directory.resolve("close-concurrent.zek");
        try (KeyringPassword password = password(); KeyringStore initial = KeyringStore.create(path, password)) { assertFalse(initial.contains("token")); }
        Faults faults = new Faults();
        faults.writing = new CountDownLatch(1);
        faults.release = new CountDownLatch(1);
        try (KeyringPassword password = password(); KeyringStore store = KeyringStore.open(path, password,
                KeyringProtection.standard(), new java.security.SecureRandom()::nextBytes, faults);
                var executor = Executors.newFixedThreadPool(2)) {
            KeyPair pair = pair();
            Future<?> insertion = executor.submit(() -> { store.putKeyPairIfAbsent("token", "Ed25519", pair); return null; });
            try {
                assertTrue(faults.writing.await(30, TimeUnit.SECONDS));
                CountDownLatch closing = new CountDownLatch(1);
                Future<?> close = executor.submit(() -> { closing.countDown(); store.close(); });
                assertTrue(closing.await(30, TimeUnit.SECONDS));
                assertFalse(close.isDone());
                faults.release.countDown();
                insertion.get(30, TimeUnit.SECONDS);
                close.get(30, TimeUnit.SECONDS);
                assertThrows(KeyringException.class, () -> store.removeAlias("token"));
            } finally { faults.release.countDown(); }
        } finally { faults.release.countDown(); }
        try (KeyringPassword password = password(); KeyringStore store = KeyringStore.open(path, password)) {
            assertNotNull(store.getPublic("token"));
            assertNotNull(store.getPrivate("token"));
        }
    }

    @Test
    void everyPairPersistencePhaseNeverExposesIncompletePair() throws Exception {
        exerciseFailures(false);
    }

    @Test
    void everyRemovalPersistencePhasePreservesUnrelatedAliases() throws Exception {
        exerciseFailures(true);
    }

    private void exerciseFailures(boolean removal) throws Exception {
        KeyPair pair = pair();
        for (Target target : List.of(Target.MAIN_IMAGE, Target.NONCE_RESERVATION)) {
            for (Stage stage : Stage.values()) {
                int occurrences = target == Target.MAIN_IMAGE ? 1 : 3;
                for (int occurrence = 1; occurrence <= occurrences; occurrence++) {
                    Path path = directory.resolve(removal + "-" + target + "-" + stage + "-" + occurrence + ".zek");
                    try (KeyringPassword password = password(); KeyringStore store = KeyringStore.create(path, password)) {
                        if (removal) { store.putKeyPairIfAbsent("token", "Ed25519", pair); }
                        secret(store, "other");
                        secret(store, "last");
                    }
                    Faults faults = new Faults();
                    faults.arm(target, stage, occurrence);
                    boolean published = target == Target.MAIN_IMAGE && (stage == Stage.MOVE_AFTER || stage == Stage.MOVE_AFTER_UNSUPPORTED || stage == Stage.DIRECTORY);
                    boolean uncertain = stage == Stage.MOVE_AFTER || stage == Stage.MOVE_AFTER_UNSUPPORTED || stage == Stage.DIRECTORY;
                    try (KeyringPassword password = password(); KeyringStore store = KeyringStore.open(path, password,
                            KeyringProtection.standard(), new java.security.SecureRandom()::nextBytes, faults)) {
                        KeyringException failure = assertThrows(KeyringException.class, () -> {
                            if (removal) { store.removeAlias("token"); }
                            else { store.putKeyPairIfAbsent("token", "Ed25519", pair); }
                        });
                        assertEquals(uncertain ? KeyringException.Code.KEYRING_DURABILITY_UNCONFIRMED
                                : KeyringException.Code.KEYRING_IO_FAILED, failure.code());
                        assertEquals(failure.code().name(), failure.getMessage());
                        assertNull(failure.getCause());
                        if (uncertain) {
                            assertThrows(KeyringException.class, () -> store.removeAlias("other"));
                            assertThrows(KeyringException.class, () -> store.putKeyPairIfAbsent("retry", "Ed25519", pair));
                        } else {
                            assertPair(store, pair, removal);
                            assertNotNull(store.getSecret("other"));
                            assertNotNull(store.getSecret("last"));
                        }
                    }
                    try (KeyringPassword password = password(); KeyringStore store = KeyringStore.open(path, password)) {
                        assertPair(store, pair, removal != published);
                        assertNotNull(store.getSecret("other"));
                        assertNotNull(store.getSecret("last"));
                        if (!store.contains("token")) { store.putKeyPairIfAbsent("token", "Ed25519", pair); }
                        assertTrue(store.removeAlias("token"));
                        assertNotNull(store.getSecret("other"));
                    }
                }
            }
        }
    }

    private static void assertPair(KeyringStore store, KeyPair pair, boolean present) throws Exception {
        assertEquals(present, store.contains("token.pub"));
        assertEquals(present, store.contains("token.priv"));
        if (present) {
            assertArrayEquals(pair.getPublic().getEncoded(), store.getPublic("token").getEncoded());
            assertArrayEquals(pair.getPrivate().getEncoded(), store.getPrivate("token").getEncoded());
        }
    }

    private static KeyPair pair() throws Exception { return KeyPairGenerator.getInstance("Ed25519").generateKeyPair(); }
    private static KeyringPassword password() { return new KeyringPassword(new char[] {'t', 'e', 's', 't'}); }
    private static void secret(KeyringStore store, String alias) throws Exception {
        store.putSecret(alias, "AES", new SecretKeySpec(new byte[32], "AES"));
    }

    private enum Stage { CREATE, WRITE, FORCE, MOVE, MOVE_AFTER, MOVE_AFTER_UNSUPPORTED, DIRECTORY }

    private static final class Faults implements KeyringFileOperations {
        private Target selected;
        private Stage stage;
        private int remaining;
        private int creations;
        private CountDownLatch writing;
        private CountDownLatch release;
        void arm(Target target, Stage phase, int occurrence) { selected = target; stage = phase; remaining = occurrence; }
        private boolean fail(Target target, Stage phase) {
            return target == selected && stage == phase && --remaining == 0;
        }
        private void check(Target target, Stage phase) throws IOException {
            if (fail(target, phase)) { throw new IOException("redacted injected failure"); }
        }
        @Override public Path createTemporary(Target target, Path parent, String prefix, String suffix) throws IOException {
            creations++;
            check(target, Stage.CREATE);
            return NIO.createTemporary(target, parent, prefix, suffix);
        }
        @Override public void writeTemporary(Target target, Path temporary, byte[] image) throws IOException {
            if (target == Target.MAIN_IMAGE && writing != null) {
                writing.countDown();
                try { if (!release.await(30, TimeUnit.SECONDS)) { throw new IOException("Release latch timed out"); } } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Interrupted test persistence");
                }
            }
            check(target, Stage.WRITE); NIO.writeTemporary(target, temporary, image);
        }
        @Override public void forceTemporary(Target target, Path temporary) throws IOException {
            check(target, Stage.FORCE); NIO.forceTemporary(target, temporary);
        }
        @Override public void atomicReplace(Target target, Path temporary, Path destination) throws IOException {
            check(target, Stage.MOVE); NIO.atomicReplace(target, temporary, destination); check(target, Stage.MOVE_AFTER);
            if (fail(target, Stage.MOVE_AFTER_UNSUPPORTED)) { throw new UnsupportedOperationException("redacted injected failure"); }
        }
        @Override public void forceDirectory(Target target, Path parent) throws IOException {
            check(target, Stage.DIRECTORY); NIO.forceDirectory(target, parent);
        }
        @Override public void deleteTemporary(Target target, Path temporary) throws IOException { NIO.deleteTemporary(target, temporary); }
    }
}
