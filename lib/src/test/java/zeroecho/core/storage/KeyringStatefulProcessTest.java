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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.sdk.util.BouncyCastleActivator;

class KeyringStatefulProcessTest {
    @TempDir Path root;
    @BeforeAll static void provider() { BouncyCastleActivator.init(); }

    @Test void authorityFenceExcludesAnotherJvmAndReleasesAfterExit() throws Exception {
        Path ledger = root.resolve("authority");
        LocalStatefulSigningAuthority.create(ledger).close();
        Process process = start("lock", ledger, root.resolve("unused"));
        try (java.util.concurrent.ExecutorService reader = Executors.newSingleThreadExecutor()) {
            try {
                String ready = reader.submit(() -> new BufferedReader(new InputStreamReader(process.getInputStream())).readLine())
                        .get(30, TimeUnit.SECONDS);
                assertEquals("READY", ready);
                assertEquals(KeyringException.Code.KEYRING_ALREADY_OPEN,
                        assertThrows(KeyringException.class, () -> LocalStatefulSigningAuthority.open(ledger)).code());
                process.getOutputStream().write(1);
                process.getOutputStream().flush();
                assertTrue(process.waitFor(30, TimeUnit.SECONDS));
                assertEquals(0, process.exitValue());
            } finally {
                // Terminate before ExecutorService.close can wait for a reader
                // blocked on a child that failed to publish its barrier.
                process.destroyForcibly();
            }
        }
        LocalStatefulSigningAuthority.open(ledger).close();
    }

    @ParameterizedTest @ValueSource(strings = { "reserved", "image", "ready" })
    void actualJvmCrashNeverReusesReturnedLeaf(String transition) throws Exception {
        Path keys = root.resolve("keys/store");
        Path ledger = root.resolve("authority");
        try (KeyringPassword password = KeyringStatefulSigningTest.password();
                KeyringStore store = KeyringStore.create(keys, password);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.create(ledger)) {
            store.generateStatefulKey("key", "LMS", authority);
            KeyringStatefulSigningTest.sign(store.statefulSigner("key", authority));
        }
        Process process = start(transition, ledger, keys);
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS));
            assertEquals(23, process.exitValue(), Files.readString(root.resolve("child.err")));
        } finally { process.destroyForcibly(); }
        try (KeyringPassword password = KeyringStatefulSigningTest.password();
                KeyringStore store = KeyringStore.open(keys, password);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.open(ledger)) {
            if (transition.equals("ready")) {
                assertEquals(2, KeyringStatefulSigningTest.leaf("LMS",
                        KeyringStatefulSigningTest.sign(store.statefulSigner("key", authority))));
            } else {
                assertEquals(KeyringException.Code.KEYRING_STATEFUL_RECOVERY_REQUIRED,
                        assertThrows(KeyringException.class, () -> store.statefulSigner("key", authority)).code());
            }
        }
    }

    private Process start(String mode, Path ledger, Path keys) throws Exception {
        ArrayList<String> paths = new ArrayList<>();
        for (Class<?> type : new Class<?>[] { KeyringStatefulProcess.class, CryptoAlgorithm.class,
                org.bouncycastle.jce.spec.ElGamalParameterSpec.class, org.bouncycastle.cert.X509CertificateHolder.class,
                org.bouncycastle.asn1.cms.ContentInfo.class, conflux.CtxInterface.class }) {
            paths.add(Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
        }
        paths.add(Path.of(CryptoAlgorithm.class.getResource("/META-INF/services/zeroecho.core.CryptoAlgorithm").toURI())
                .getParent().getParent().getParent().toString());
        return new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", String.join(File.pathSeparator, paths), KeyringStatefulProcess.class.getName(),
                mode, ledger.toString(), keys.toString()).redirectError(root.resolve("child.err").toFile()).start();
    }
}
