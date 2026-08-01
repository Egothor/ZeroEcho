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
package zeroecho.pki.impl.framework.x509.bc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static zeroecho.pki.testkit.PkiTestRuntime.signingAuthority;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.testkit.InMemorySignatureWorkflow;

final class PkiBusContentSignerCleanupTest {

    @Test
    void endEntityFailureRetiresEverySigningArtifact(@TempDir Path tempDir) throws Exception {
        assertCleanup(tempDir, false);
    }

    @Test
    void intermediateFailureRetiresEverySigningArtifact(@TempDir Path tempDir) throws Exception {
        assertCleanup(tempDir, true);
    }

    @Test
    void crlPostconditionRejectsEqualFingerprintForeignPlan(@TempDir Path tempDir) throws Exception {
        System.out.println("crlPostconditionRejectsEqualFingerprintForeignPlan");
        KeyRef issuerKeyRef = new KeyRef("kref:v1:keyring:test:issuer");
        InMemorySignatureWorkflow signer = new InMemorySignatureWorkflow(
                Map.of(issuerKeyRef.value(), generateRsa()));
        X509AuthoritySnapshot owning = signingAuthority(signer);
        X509AuthoritySnapshot foreign = signingAuthority(signer);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"), owning)) {
            PkiBusContentSigner contentSigner = new PkiBusContentSigner(bus, issuerKeyRef, "SHA256withRSA",
                    Duration.ofSeconds(5));
            X509ExecutionPlan<SignatureWorkflow> plan = contentSigner.executionPlan();

            BcX509StatusObjectGenerator.requireAuthorizedSigningPlan(owning, plan,
                    plan.selection().requested());
            assertEquals(owning.semanticFingerprint(), foreign.semanticFingerprint());
            assertThrows(IllegalArgumentException.class,
                    () -> BcX509StatusObjectGenerator.requireAuthorizedSigningPlan(foreign, plan,
                            plan.selection().requested()));
            assertThrows(PkiException.class,
                    () -> BcX509StatusObjectGenerator.requireAuthorizedSigningPlan(owning, plan,
                            BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384));
            contentSigner.getOutputStream().write(1);
            contentSigner.getSignature();
            System.out.println("...fingerprint=" + owning.semanticFingerprint().substring(0, 16));
            System.out.println("crlPostconditionRejectsEqualFingerprintForeignPlan...ok");
        } finally {
            signer.close();
        }
    }

    private static void assertCleanup(Path tempDir, boolean intermediate) throws Exception {
        KeyPair subjectKey = generateRsa();
        KeyRef issuerKeyRef = new KeyRef("kref:v1:keyring:test:issuer");
        InMemorySignatureWorkflow signer = new InMemorySignatureWorkflow(Map.of(), true);
        Path storeRoot = tempDir.resolve("store");
        Path busLog = tempDir.resolve("bus.log");

        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, signer, busLog, signingAuthority(signer))) {
            PkiBusContentSigner contentSigner = new PkiBusContentSigner(bus, issuerKeyRef, "SHA256withRSA",
                    Duration.ofSeconds(5));
            contentSigner.getOutputStream()
                    .write(intermediate ? subjectKey.getPublic().getEncoded() : new byte[] { 1, 2, 3 });
            assertThrows(PkiException.class, contentSigner::getSignature);

            assertEquals(1, signer.submittedSignCount());
            assertTrue(store.listWorkflowStates().isEmpty());
            assertFalse(signer.hasRunningOperations());
            assertTrue(store.listCas().isEmpty());
            assertFalse(Files.exists(storeRoot.resolve("credentials")));

            PkiId operationId = submittedOperation(busLog);
            try (PkiSigningBus replayed = new PkiSigningBus(store, signer, busLog, signingAuthority(signer))) {
                assertEquals(zeroecho.pki.util.async.AsyncState.CANCELLED,
                        replayed.status(operationId).orElseThrow().state());
            }
        } finally {
            signer.close();
        }
    }

    private static PkiId submittedOperation(Path busLog) throws Exception {
        List<String> lines = Files.readAllLines(busLog);
        for (String line : lines) {
            if (line.startsWith("S1|")) {
                return new PkiId(line.split("\\|", -1)[1]);
            }
        }
        throw new AssertionError("No durable signing operation snapshot found");
    }

    private static KeyPair generateRsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
