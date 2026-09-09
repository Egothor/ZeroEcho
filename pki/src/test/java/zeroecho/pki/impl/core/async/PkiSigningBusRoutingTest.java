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
package zeroecho.pki.impl.core.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static zeroecho.pki.testkit.PkiTestRuntime.stage;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.testkit.InMemorySignatureWorkflow;
import zeroecho.pki.testkit.PkiTestRuntime;
import zeroecho.pki.util.async.AsyncState;
import zeroecho.pki.util.async.AsyncStatus;

/**
 * Proves per-CA signing-service routing: one bus routes each signing key reference
 * to its configured service (each with its own key), signatures verify only under
 * the routed service's key, each service signs only its own request, and the
 * durable reconcile/status path resolves the owning service per record.
 */
public final class PkiSigningBusRoutingTest {

    @TempDir
    Path tempDir;

    private static final String ALGORITHM = "SHA256withRSA";

    @Test
    public void routesEachAuthorityKeyToItsConfiguredService() throws Exception {
        System.out.println("routesEachAuthorityKeyToItsConfiguredService");
        KeyPair keyPairA = rsa();
        KeyPair keyPairB = rsa();
        KeyRef keyA = new KeyRef("kref:ca-a");
        KeyRef keyB = new KeyRef("kref:ca-b");
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"), FsPkiStoreOptions.defaults());
                InMemorySignatureWorkflow serviceA = new InMemorySignatureWorkflow("svc-a",
                        Map.of(keyA.value(), keyPairA), true);
                InMemorySignatureWorkflow serviceB = new InMemorySignatureWorkflow("svc-b",
                        Map.of(keyB.value(), keyPairB), true)) {
            X509AuthoritySnapshot authority = PkiTestRuntime.multiSigningAuthority(List.of(serviceA, serviceB));
            PkiSigningBus.SigningRoutingPolicy routing = new PkiSigningBus.SigningRoutingPolicy(
                    Map.of(keyA.value(), "svc-a", keyB.value(), "svc-b"), "svc-a");
            try (PkiSigningBus bus = new PkiSigningBus(store, List.of(serviceA, serviceB), routing, authority)) {
                byte[] payloadA = "authority-a-payload".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                byte[] payloadB = "authority-b-payload".getBytes(java.nio.charset.StandardCharsets.UTF_8);

                byte[] signatureA = signRouted(bus, store, keyA, payloadA);
                byte[] signatureB = signRouted(bus, store, keyB, payloadB);

                // Each signature verifies under the routed service's key.
                assertTrue(verifies(signatureA, payloadA, keyPairA.getPublic()));
                assertTrue(verifies(signatureB, payloadB, keyPairB.getPublic()));
                // And NOT under the other service's key: the request was routed, not broadcast.
                assertFalse(verifies(signatureA, payloadA, keyPairB.getPublic()));
                assertFalse(verifies(signatureB, payloadB, keyPairA.getPublic()));

                // Each service signed exactly its own routed request.
                assertEquals(1, serviceA.submittedSignCount());
                assertEquals(1, serviceB.submittedSignCount());
            }
        }
    }

    @Test
    public void defaultServiceHandlesUnmappedAuthorityKeys() throws Exception {
        System.out.println("defaultServiceHandlesUnmappedAuthorityKeys");
        KeyPair keyPairDefault = rsa();
        KeyPair keyPairSpecial = rsa();
        KeyRef unmapped = new KeyRef("kref:ca-unmapped");
        KeyRef special = new KeyRef("kref:ca-special");
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"), FsPkiStoreOptions.defaults());
                InMemorySignatureWorkflow defaultService = new InMemorySignatureWorkflow("svc-default",
                        Map.of(unmapped.value(), keyPairDefault), true);
                InMemorySignatureWorkflow specialService = new InMemorySignatureWorkflow("svc-special",
                        Map.of(special.value(), keyPairSpecial), true)) {
            X509AuthoritySnapshot authority = PkiTestRuntime.multiSigningAuthority(
                    List.of(defaultService, specialService));
            PkiSigningBus.SigningRoutingPolicy routing = new PkiSigningBus.SigningRoutingPolicy(
                    Map.of(special.value(), "svc-special"), "svc-default");
            try (PkiSigningBus bus = new PkiSigningBus(store, List.of(defaultService, specialService), routing,
                    authority)) {
                byte[] payload = "unmapped-goes-default".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                byte[] signature = signRouted(bus, store, unmapped, payload);
                assertTrue(verifies(signature, payload, keyPairDefault.getPublic()));
                assertEquals(1, defaultService.submittedSignCount());
                assertEquals(0, specialService.submittedSignCount());
            }
        }
    }

    private static byte[] signRouted(PkiSigningBus bus, FilesystemPkiStore store, KeyRef keyRef, byte[] payload)
            throws Exception {
        Principal owner = new Principal("USER", "tester");
        PkiId opId = bus.canonicalizeOperationId(new PkiId("op:" + keyRef.value()), owner, keyRef);
        DurableContentReference content = stage(bus, new EncodedObject(Encoding.BINARY, payload));
        AccessContext access = new AccessContext(owner, new Purpose("ISSUANCE"), Optional.empty(), Optional.empty());
        PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(access, ALGORITHM, content,
                keyRef, Encoding.BINARY, Optional.empty());
        bus.submitSign(opId, owner, keyRef, ALGORITHM, content, Duration.ofSeconds(30),
                Optional.of(continuation.encode()));
        Optional<EncodedObject> signature = waitForSignature(bus, opId, Duration.ofSeconds(5));
        assertTrue(signature.isPresent(), "signature present for " + keyRef.value());
        return signature.orElseThrow().bytes();
    }

    private static boolean verifies(byte[] signature, byte[] payload, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance(ALGORITHM);
        verifier.initVerify(publicKey);
        verifier.update(payload);
        return verifier.verify(signature);
    }

    private static Optional<EncodedObject> waitForSignature(PkiSigningBus bus, PkiId opId, Duration timeout)
            throws InterruptedException {
        Instant deadline = Instant.now().plus(timeout);
        while (Instant.now().isBefore(deadline)) {
            bus.sweep(Instant.now());
            Optional<AsyncStatus> status = bus.status(opId);
            if (status.isPresent() && status.get().state() == AsyncState.SUCCEEDED) {
                return bus.consumeResult(opId);
            }
            if (status.isPresent() && status.get().state() == AsyncState.FAILED) {
                return Optional.empty();
            }
            Thread.sleep(10L);
        }
        return Optional.empty();
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
