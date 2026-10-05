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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.Signature;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.err.UnsupportedRoleException;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.util.BouncyCastleActivator;

class KeyringStatefulSigningTest {
    @TempDir Path root;
    private static final byte[] MESSAGE = { 1, 2, 3, 4 };

    @BeforeAll static void provider() { BouncyCastleActivator.init(); }

    @Test
    void lmsAndXmssSignPersistAndReopenWithoutReusingLeaf() throws Exception {
        for (String algorithm : List.of("LMS", "XMSS")) {
            Path keyring = root.resolve(algorithm + "/keys/store");
            Path directory = Files.createDirectory(root.resolve(algorithm + "-authority-parent"));
            // Keyring parent creation must precede sibling authority initialization.
            try (KeyringPassword password = password();
                    KeyringStore store = KeyringStore.create(keyring, password);
                    LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.create(directory.resolve("authority"))) {
                PublicKey key = store.generateStatefulKey("key", algorithm, authority);
                StatefulSigner signer = store.statefulSigner("key", authority);
                byte[] before = store.getPrivate("key").getEncoded();
                int size = signer.signatureLength();
                assertTrue(java.util.Arrays.equals(before, store.getPrivate("key").getEncoded()));
                byte[] first = sign(signer);
                assertEquals(size, first.length);
                assertEquals(0, leaf(algorithm, first));
                verify(algorithm, key, first);
                assertThrows(UnsupportedRoleException.class, () -> new ZeroEchoSession()
                        .createContext(algorithm, KeyUsage.SIGN, store.getPrivate("key")));
                assertTrue(CryptoAlgorithms.require(algorithm).requiresStatefulSigning());
            }
            try (KeyringPassword password = password();
                    KeyringStore store = KeyringStore.open(keyring, password);
                    LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.open(directory.resolve("authority"))) {
                byte[] second = sign(store.statefulSigner("key", authority));
                assertEquals(1, leaf(algorithm, second));
                verify(algorithm, store.getPublic("key"), second);
            }
        }
    }

    @Test
    void stalePrivateStateMissingAuthorityAndAliasCopiesCannotSign() throws Exception {
        Path keyring = root.resolve("keys/store");
        try (KeyringPassword password = password();
                KeyringStore store = KeyringStore.create(keyring, password);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.create(root.resolve("authority"));
                LocalStatefulSigningAuthority empty = LocalStatefulSigningAuthority.create(root.resolve("empty"))) {
            PublicKey pub = store.generateStatefulKey("key", "LMS", authority);
            java.security.PrivateKey old = store.getPrivate("key");
            StatefulSigner signer = store.statefulSigner("key", authority);
            sign(signer);
            assertThrows(IOException.class, () -> store.statefulSigner("key", empty));
            store.putPrivate("copy", "LMS", old);
            store.putPublic("copy", "LMS", pub);
            assertThrows(IOException.class, () -> store.statefulSigner("copy", authority));
            assertThrows(IllegalArgumentException.class, () -> store.generateStatefulKey("copy", "LMS", empty));
            store.putPrivate("key", "LMS", old);
            assertThrows(KeyringException.class, () -> sign(signer));
        }
    }

    @Test
    void providerAdvancedLmsStateRetainsConsumptionOnImport() throws Exception {
        java.security.KeyPair pair = new ZeroEchoSession().keyBuilders().asymmetric()
                .generateKeyPair("LMS", zeroecho.core.alg.lms.LmsKeyGenSpec.DEFAULT);
        org.bouncycastle.pqc.jcajce.interfaces.LMSPrivateKey parent =
                (org.bouncycastle.pqc.jcajce.interfaces.LMSPrivateKey) pair.getPrivate();
        for (int i = 0; i < 31; i++) {
            parent.extractKeyShard(1);
            byte[] encoded = parent.getEncoded();
            org.bouncycastle.pqc.jcajce.interfaces.LMSPrivateKey imported =
                    (org.bouncycastle.pqc.jcajce.interfaces.LMSPrivateKey) java.security.KeyFactory.getInstance("LMS", "BCPQC")
                            .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(encoded));
            assertEquals(31 - i, imported.getUsagesRemaining());
            assertTrue(java.util.Arrays.equals(encoded, imported.getEncoded()), "Canonical encoding after reservation " + (i + 1));
        }
        parent.extractKeyShard(1);
        assertEquals(0, parent.getUsagesRemaining());
        // BC 1.86 cannot re-import the exhausted single-tree HSS container.
        // The durable protocol must retire this entry, not relax canonical validation.
        assertThrows(java.security.spec.InvalidKeySpecException.class, () -> java.security.KeyFactory.getInstance("LMS", "BCPQC")
                .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(parent.getEncoded())));
    }

    @Test
    void threadsSerializeAndExhaustionRemainsAfterReopen() throws Exception {
        Path keyring = root.resolve("keys/store");
        Path authorityPath = root.resolve("authority");
        try (KeyringPassword password = password();
                KeyringStore store = KeyringStore.create(keyring, password);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.create(authorityPath)) {
            store.generateStatefulKey("key", "LMS", authority);
            store.putSecret("survivor", "AES", new javax.crypto.spec.SecretKeySpec(new byte[16], "AES"));
            StatefulSigner signer = store.statefulSigner("key", authority);
            Set<Integer> leaves = new HashSet<>();
            CountDownLatch start = new CountDownLatch(1);
            try (java.util.concurrent.ExecutorService workers = Executors.newFixedThreadPool(4)) {
                java.util.ArrayList<Future<byte[]>> results = new java.util.ArrayList<>();
                for (int i = 0; i < 32; i++) {
                    results.add(workers.submit(() -> { start.await(); return sign(signer); }));
                }
                start.countDown();
                for (Future<byte[]> result : results) {
                    byte[] signature = result.get(30, java.util.concurrent.TimeUnit.SECONDS);
                    verify("LMS", store.getPublic("key"), signature);
                    assertTrue(leaves.add(leaf("LMS", signature)));
                }
            }
            assertEquals(32, leaves.size());
            assertEquals(KeyringException.Code.KEYRING_STATEFUL_EXHAUSTED,
                    assertThrows(KeyringException.class, () -> sign(signer)).code());
        }
        try (KeyringPassword password = password();
                KeyringStore store = KeyringStore.open(keyring, password);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.open(authorityPath)) {
            assertArrayEquals(new byte[16], store.getSecret("survivor").getEncoded());
            assertEquals(KeyringException.Code.KEYRING_STATEFUL_EXHAUSTED,
                    assertThrows(KeyringException.class, () -> sign(store.statefulSigner("key", authority))).code());
        }
    }

    static KeyringPassword password() { return new KeyringPassword("stateful-test".toCharArray()); }

    @Test
    void xmssFinalLeafVerifiesAndRetirementSurvivesRestart() throws Exception {
        Path keyring = root.resolve("keys/store");
        Path ledger = root.resolve("authority");
        try (KeyringPassword password = password();
                KeyringStore store = KeyringStore.create(keyring, password);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.create(ledger)) {
            PublicKey publicKey = store.generateStatefulKey("key", "XMSS", authority);
            StatefulSigner signer = store.statefulSigner("key", authority);
            for (int i = 0; i < 1024; i++) {
                byte[] signature = sign(signer);
                assertEquals(i, leaf("XMSS", signature));
                if (i == 1023) { verify("XMSS", publicKey, signature); }
            }
        }
        try (KeyringPassword password = password();
                KeyringStore store = KeyringStore.open(keyring, password);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.open(ledger)) {
            assertEquals(KeyringException.Code.KEYRING_STATEFUL_EXHAUSTED,
                    assertThrows(KeyringException.class, () -> sign(store.statefulSigner("key", authority))).code());
        }
    }

    static byte[] sign(StatefulSigner signer) throws Exception {
        return signer.sign(new ImmutableByteContent(MESSAGE), CancellationSignal.NONE, 4096);
    }
    static int leaf(String algorithm, byte[] signature) {
        return ByteBuffer.wrap(signature).getInt(algorithm.equals("LMS") ? 4 : 0);
    }
    static void verify(String algorithm, PublicKey publicKey, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance(algorithm, "BCPQC");
        verifier.initVerify(publicKey);
        verifier.update(MESSAGE);
        assertTrue(verifier.verify(signature));
    }
}
