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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import zeroecho.sdk.util.BouncyCastleActivator;

class KeyringStatefulRecoveryTest {
    @TempDir Path root;
    @BeforeAll static void provider() { BouncyCastleActivator.init(); }

    record Fault(KeyringFileOperations.Target target, int occurrence, String step, boolean after) { }

    static Stream<Fault> faults() {
        return Stream.of(KeyringFileOperations.Target.values()).flatMap(target ->
                Stream.iterate(1, n -> n + 1).limit(target == KeyringFileOperations.Target.STATEFUL_AUTHORITY ? 2 : 1)
                .flatMap(occurrence -> List.of("create", "write", "force", "replace", "directory").stream()
                .flatMap(step -> Stream.of(false, true).map(after -> new Fault(target, occurrence, step, after)))));
    }

    @ParameterizedTest @MethodSource("faults")
    void everySigningPersistenceBoundaryFailsClosed(Fault fault) throws Exception {
        Path keys = root.resolve("keys/store");
        Path ledger = root.resolve("authority");
        Faults operations = new Faults();
        try (KeyringPassword password = KeyringStatefulSigningTest.password();
                KeyringStore store = KeyringStore.create(keys, password, KeyringProtection.standard(),
                        new SecureRandom()::nextBytes, operations);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.acquire(ledger, true, operations)) {
            store.generateStatefulKey("key", "LMS", authority);
            StatefulSigner signer = store.statefulSigner("key", authority);
            assertEquals(0, KeyringStatefulSigningTest.leaf("LMS", KeyringStatefulSigningTest.sign(signer)));
            operations.arm(fault);
            assertThrows(IOException.class, () -> KeyringStatefulSigningTest.sign(signer));
            assertTrue(operations.hit, "Fault was reached: " + fault);
        }
        try (KeyringPassword password = KeyringStatefulSigningTest.password();
                KeyringStore store = KeyringStore.open(keys, password);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.open(ledger)) {
            // A failed first reservation may leave the previous READY intact; a
            // failed acknowledgement may leave the advanced READY intact. Neither
            // path may reuse the already returned leaf zero. Pending stays blocked.
            try {
                int leaf = KeyringStatefulSigningTest.leaf("LMS",
                        KeyringStatefulSigningTest.sign(store.statefulSigner("key", authority)));
                assertTrue(leaf == 1 || leaf == 2);
            } catch (KeyringException blocked) {
                assertEquals(KeyringException.Code.KEYRING_STATEFUL_RECOVERY_REQUIRED, blocked.code());
            }
        }
    }

    @Test
    void staleWholeImageAndMovedAuthorityAreRejected() throws Exception {
        Path keys = root.resolve("keys/store");
        Path ledger = root.resolve("authority");
        byte[] snapshot;
        try (KeyringPassword password = KeyringStatefulSigningTest.password();
                KeyringStore store = KeyringStore.create(keys, password);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.create(ledger)) {
            store.generateStatefulKey("key", "LMS", authority);
            snapshot = Files.readAllBytes(keys);
            KeyringStatefulSigningTest.sign(store.statefulSigner("key", authority));
        }
        Files.write(keys, snapshot);
        try (KeyringPassword password = KeyringStatefulSigningTest.password();
                KeyringStore store = KeyringStore.open(keys, password);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.open(ledger)) {
            assertThrows(KeyringException.class, () -> store.statefulSigner("key", authority));
        }
        Path moved = root.resolve("moved");
        Files.move(ledger, moved);
        assertThrows(IOException.class, () -> LocalStatefulSigningAuthority.open(moved));
    }

    @ParameterizedTest @MethodSource("faults")
    void interruptedEnrollmentCannotReconstructAuthority(Fault fault) throws Exception {
        Path keys = root.resolve("keys/store");
        Path ledger = root.resolve("authority");
        Faults operations = new Faults();
        try (KeyringPassword password = KeyringStatefulSigningTest.password();
                KeyringStore store = KeyringStore.create(keys, password, KeyringProtection.standard(),
                        new SecureRandom()::nextBytes, operations);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.acquire(ledger, true, operations)) {
            operations.arm(fault);
            assertThrows(IOException.class, () -> store.generateStatefulKey("key", "LMS", authority));
            assertTrue(operations.hit);
        }
        try (KeyringPassword password = KeyringStatefulSigningTest.password();
                KeyringStore store = KeyringStore.open(keys, password);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.open(ledger)) {
            try {
                assertEquals(0, KeyringStatefulSigningTest.leaf("LMS",
                        KeyringStatefulSigningTest.sign(store.statefulSigner("key", authority))));
            } catch (IOException | IllegalArgumentException incomplete) {
                // No enrollment repair is attempted; missing entries or RESERVED
                // state cannot be converted into signing permission.
            }
        }
    }

    @Test
    void copiedKeyringAndMissingOpenAuthorityHeaderAreRejected() throws Exception {
        Path keys = root.resolve("keys/store");
        Path ledger = root.resolve("authority");
        try (KeyringPassword password = KeyringStatefulSigningTest.password();
                KeyringStore store = KeyringStore.create(keys, password);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.create(ledger)) {
            store.generateStatefulKey("key", "LMS", authority);
            Path clone = root.resolve("keys/clone");
            Files.copy(keys, clone, java.nio.file.StandardCopyOption.COPY_ATTRIBUTES);
            Files.copy(keys.resolveSibling("store.nonce"), clone.resolveSibling("clone.nonce"),
                    java.nio.file.StandardCopyOption.COPY_ATTRIBUTES);
            try (KeyringPassword copiedPassword = KeyringStatefulSigningTest.password();
                    KeyringStore copy = KeyringStore.open(clone, copiedPassword)) {
                assertThrows(IOException.class, () -> copy.statefulSigner("key", authority));
            }
            StatefulSigner signer = store.statefulSigner("key", authority);
            Files.delete(ledger.resolve("authority.bin"));
            assertThrows(IOException.class, () -> KeyringStatefulSigningTest.sign(signer));
        }
        assertThrows(IOException.class, () -> LocalStatefulSigningAuthority.open(ledger));
    }

    @ParameterizedTest @MethodSource("faults")
    void terminalRemovalNeverReleasesAnUncommittedFinalLeaf(Fault fault) throws Exception {
        Path keys = root.resolve("keys/store");
        Path ledger = root.resolve("authority");
        Faults operations = new Faults();
        try (KeyringPassword password = KeyringStatefulSigningTest.password();
                KeyringStore store = KeyringStore.create(keys, password, KeyringProtection.standard(),
                        new SecureRandom()::nextBytes, operations);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.acquire(ledger, true, operations)) {
            store.generateStatefulKey("key", "LMS", authority);
            store.putSecret("survivor", "AES", new javax.crypto.spec.SecretKeySpec(new byte[16], "AES"));
            StatefulSigner signer = store.statefulSigner("key", authority);
            for (int i = 0; i < 31; i++) {
                assertEquals(i, KeyringStatefulSigningTest.leaf("LMS", KeyringStatefulSigningTest.sign(signer)));
            }
            operations.arm(fault);
            assertThrows(IOException.class, () -> KeyringStatefulSigningTest.sign(signer));
            assertTrue(operations.hit);
        }
        try (KeyringPassword password = KeyringStatefulSigningTest.password();
                KeyringStore store = KeyringStore.open(keys, password);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.open(ledger)) {
            assertTrue(java.util.Arrays.equals(new byte[16], store.getSecret("survivor").getEncoded()));
            try {
                byte[] signature = KeyringStatefulSigningTest.sign(store.statefulSigner("key", authority));
                assertEquals(31, KeyringStatefulSigningTest.leaf("LMS", signature));
                KeyringStatefulSigningTest.verify("LMS", store.getPublic("key"), signature);
            } catch (KeyringException blocked) {
                assertTrue(blocked.code() == KeyringException.Code.KEYRING_STATEFUL_RECOVERY_REQUIRED
                        || blocked.code() == KeyringException.Code.KEYRING_STATEFUL_EXHAUSTED);
            }
        }
    }

    @Test
    void terminalAuthorityRejectsRestoredPrivateEntry() throws Exception {
        Path keys = root.resolve("keys/store");
        try (KeyringPassword password = KeyringStatefulSigningTest.password();
                KeyringStore store = KeyringStore.create(keys, password);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.create(root.resolve("authority"))) {
            store.generateStatefulKey("key", "LMS", authority);
            StatefulSigner signer = store.statefulSigner("key", authority);
            for (int i = 0; i < 31; i++) { KeyringStatefulSigningTest.sign(signer); }
            java.security.PrivateKey last = store.getPrivate("key");
            KeyringStatefulSigningTest.sign(signer);
            store.putPrivate("key", "LMS", last);
            assertEquals(KeyringException.Code.KEYRING_STATEFUL_RECOVERY_REQUIRED,
                    assertThrows(KeyringException.class, () -> KeyringStatefulSigningTest.sign(signer)).code());
        }
    }

    @Test
    void malformedMissingAndFutureAuthorityRecordsFailClosed() throws Exception {
        Path keys = root.resolve("keys/store");
        Path ledger = root.resolve("authority");
        try (KeyringPassword password = KeyringStatefulSigningTest.password();
                KeyringStore store = KeyringStore.create(keys, password);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.create(ledger)) {
            store.generateStatefulKey("key", "LMS", authority);
            StatefulSigner signer = store.statefulSigner("key", authority);
            Path record;
            try (Stream<Path> paths = Files.list(ledger)) {
                record = paths.filter(p -> p.toString().endsWith(".state")).findFirst().orElseThrow();
            }
            byte[] original = Files.readAllBytes(record);
            for (byte[] corrupt : List.of(new byte[0], new byte[40000], new byte[] { 1, 2, 3 })) {
                Files.write(record, corrupt);
                assertThrows(IOException.class, () -> KeyringStatefulSigningTest.sign(signer));
            }
            byte[] future = original.clone();
            future[7] = 2;
            Files.write(record, future);
            assertThrows(IOException.class, () -> KeyringStatefulSigningTest.sign(signer));
            Files.delete(record);
            assertThrows(IOException.class, () -> KeyringStatefulSigningTest.sign(signer));
        }
    }

    static final class Faults implements KeyringFileOperations {
        private Fault fault;
        private int occurrence;
        boolean hit;
        void arm(Fault value) { fault = value; occurrence = 0; hit = false; }
        private void check(Target target, String step, boolean after) throws IOException {
            if (fault != null && target == fault.target() && step.equals(fault.step()) && after == fault.after()
                    && ++occurrence == fault.occurrence()) {
                hit = true;
                throw new IOException("Injected persistence failure");
            }
        }
        @Override public Path createTemporary(Target target, Path parent, String prefix, String suffix) throws IOException {
            check(target, "create", false);
            Path value = NIO.createTemporary(target, parent, prefix, suffix);
            check(target, "create", true);
            return value;
        }
        @Override public void writeTemporary(Target target, Path temporary, byte[] image) throws IOException {
            check(target, "write", false); NIO.writeTemporary(target, temporary, image); check(target, "write", true);
        }
        @Override public void forceTemporary(Target target, Path temporary) throws IOException {
            check(target, "force", false); NIO.forceTemporary(target, temporary); check(target, "force", true);
        }
        @Override public void atomicReplace(Target target, Path temporary, Path destination) throws IOException {
            check(target, "replace", false); NIO.atomicReplace(target, temporary, destination); check(target, "replace", true);
        }
        @Override public void forceDirectory(Target target, Path parent) throws IOException {
            check(target, "directory", false); NIO.forceDirectory(target, parent); check(target, "directory", true);
        }
        @Override public void deleteTemporary(Target target, Path temporary) throws IOException { NIO.deleteTemporary(target, temporary); }
    }
}
