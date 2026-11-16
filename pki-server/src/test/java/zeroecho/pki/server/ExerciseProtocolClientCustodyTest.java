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
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.security.KeyPairGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;

/**
 * Client custody uses its own secret; server unlock authority does not open it.
 */
class ExerciseProtocolClientCustodyTest {
    /**
     * Checks canonical deployment publication identities pass stopped-seed guards while private-path and malformed identity attempts fail.
     *
     * @param root isolated JUnit-managed root for filesystem fixtures
     *
     * @throws Exception if test fixture setup or execution fails
     */
    @Test
    void deploymentPublicationIdsPassTheActualStoppedSeedIdentityGuard(@TempDir Path root) throws Exception {
        java.nio.file.Files.setPosixFilePermissions(root,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        Path repository=Path.of("").toAbsolutePath();
        if(!java.nio.file.Files.isDirectory(repository.resolve("deploy")))repository=repository.getParent();
        String nonce="a".repeat(32);
        for(String mode:java.util.List.of("retry","reconcile")) {
            Process process=new ProcessBuilder("python3","-c",
                    "import sys;sys.path.insert(0,sys.argv[1]);import exercise_environment;print(exercise_environment._publication_id(sys.argv[2],sys.argv[3]))",
                    repository.resolve("deploy").toString(),nonce,mode).start();
            String identity=new String(process.getInputStream().readAllBytes(),java.nio.charset.StandardCharsets.UTF_8).strip();
            org.junit.jupiter.api.Assertions.assertEquals(0,process.waitFor());
            // Missing owner metadata is deliberately later than the real helper's identity check.
            var boundary=assertThrows(IllegalArgumentException.class,()->ExerciseCatalogStateSeed.main(new String[] {
                    root.toString(),nonce,nonce,identity,"f".repeat(64),"RETRYABLE_FAILURE"}));
            org.junit.jupiter.api.Assertions.assertEquals("Private fixture path required",boundary.getMessage());
        }
        var rejected=assertThrows(IllegalArgumentException.class,()->ExerciseCatalogStateSeed.main(new String[] {
                root.toString(),nonce,nonce,"environment-"+nonce+"-retry","f".repeat(64),"RETRYABLE_FAILURE"}));
        org.junit.jupiter.api.Assertions.assertEquals("Invalid fixture identity or requested state",rejected.getMessage());
    }

    /**
     * Checks an authenticated copied client keyring preserves the actual signing key used by the independent client.
     *
     * @param root isolated JUnit-managed root for filesystem fixtures
     *
     * @throws Exception if test fixture setup or execution fails
     */
    @Test
    void copiedClientRingWithAuthenticatedNonceStillSignsWithOriginalKey(@TempDir Path root) throws Exception {
        var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);
        var key=generator.generateKeyPair();
        Path original=root.resolve("original.zek"), copy=root.resolve("client.zek");
        ExerciseProtocolSeed.storeClientKeyring(original,"sixsix".toCharArray(),key.getPrivate());
        for(String suffix:java.util.List.of("",".nonce")) {
            Path target=Path.of(copy+suffix);
            java.nio.file.Files.copy(Path.of(original+suffix),target);
            java.nio.file.Files.setPosixFilePermissions(target,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        }
        byte[] message="client-copy-proof".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        try(var password=new KeyringPassword("sixsix".toCharArray());var ring=KeyringStore.open(copy,password)) {
            var signature=java.security.Signature.getInstance("SHA256withRSA");
            signature.initSign(ring.getPrivate("client"));signature.update(message);byte[] proof=signature.sign();
            signature.initVerify(key.getPublic());signature.update(message);
            org.junit.jupiter.api.Assertions.assertTrue(signature.verify(proof));
        }
    }

    /**
     * Checks client custody opens under its own password and rejects the independent server unlock password.
     *
     * @param root isolated JUnit-managed root for filesystem fixtures
     *
     * @throws Exception if test fixture setup or execution fails
     */
    @Test
    void clientRingCannotBeOpenedWithServerPassword(@TempDir Path root) throws Exception {
        var generator=KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var client=generator.generateKeyPair();
        Path ring=root.resolve("client.zek");
        ExerciseProtocolSeed.storeClientKeyring(ring,"client-only-unlock".toCharArray(),client.getPrivate());
        try(var password=new KeyringPassword("client-only-unlock".toCharArray());
                var opened=KeyringStore.open(ring,password)) {
            assertArrayEquals(client.getPrivate().getEncoded(),opened.getPrivate("client").getEncoded());
        }
        assertThrows(Exception.class,()->{
            try(var password=new KeyringPassword("independent-server-unlock".toCharArray());
                    var opened=KeyringStore.open(ring,password)) {
                opened.getPrivate("client");
            }
        });
    }
}
