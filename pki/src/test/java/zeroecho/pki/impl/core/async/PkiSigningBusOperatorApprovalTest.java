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

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
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
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.testkit.DurableOperatorApprovalSignatureWorkflow;
import zeroecho.pki.util.async.AsyncState;
import zeroecho.pki.util.async.AsyncStatus;

public final class PkiSigningBusOperatorApprovalTest {

    @TempDir
    Path tempDir;

    @Test
    public void operatorApprove_completesSignature() throws Exception {
        System.out.println("operatorApprove_completesSignature");

        Path storeRoot = tempDir.resolve("store");
        Path busFile = tempDir.resolve("bus.log");
        Path wfRoot = tempDir.resolve("workflow");

        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        KeyRef keyRef = new KeyRef("kref:test:rsa");

        FsPkiStoreOptions options = FsPkiStoreOptions.defaults();

        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, options);
                DurableOperatorApprovalSignatureWorkflow signer = new DurableOperatorApprovalSignatureWorkflow(wfRoot,
                        Duration.ofSeconds(10), Duration.ofMillis(100), Map.of(keyRef.value(), kp.getPrivate()));
                PkiSigningBus bus = new PkiSigningBus(store, signer, busFile)) {

            Principal owner = new Principal("USER", "alice");
            PkiId clientOpId = new PkiId("approve-1");
            PkiId opId = bus.canonicalizeOperationId(clientOpId, owner);
            System.out.println("...opId=" + opId.value());

            byte[] payload = "approval".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            EncodedObject payloadObj = new EncodedObject(Encoding.BINARY, payload);

            AccessContext ac = new AccessContext(owner, new Purpose("ISSUANCE"), Optional.empty(), Optional.empty());
            PkiSigningBus.SignContinuation cont = new PkiSigningBus.SignContinuation(ac, "SHA256withRSA", payloadObj,
                    keyRef, Encoding.BINARY, Optional.empty());

            Instant t0 = Instant.now();
            bus.submitSign(opId, owner, keyRef, "SHA256withRSA", payloadObj, Duration.ofSeconds(30),
                    Optional.of(cont.encode()));
            long submitMs = Duration.between(t0, Instant.now()).toMillis();
            System.out.println("...submitMs=" + submitMs);
            assertTrue(submitMs < 50L);

            // drive first poll -> execute() -> signerOpId stored
            PkiId signerOpId = waitSignerOpId(store, bus, opId);
            System.out.println("...signerOpId=" + signerOpId.value());

            signer.approve(signerOpId);

            Optional<EncodedObject> sigOpt = waitForSignature(bus, opId, Duration.ofSeconds(5));
            assertTrue(sigOpt.isPresent());
            System.out.println("...sigHexPrefix=" + hexPrefix(sigOpt.get().bytes()));

            Signature v = Signature.getInstance("SHA256withRSA");
            v.initVerify(kp.getPublic());
            v.update(payload);
            boolean ok = v.verify(sigOpt.get().bytes());
            System.out.println("...signatureVerified=" + ok);
            assertTrue(ok);

            Optional<AsyncStatus> st = bus.status(opId);
            System.out.println("...statusAfterConsumePresent=" + st.isPresent());
        }

        System.out.println("operatorApprove_completesSignature...ok");
    }

    @Test
    public void operatorDeny_failsSignature() throws Exception {
        System.out.println("operatorDeny_failsSignature");

        Path storeRoot = tempDir.resolve("store2");
        Path busFile = tempDir.resolve("bus2.log");
        Path wfRoot = tempDir.resolve("workflow2");

        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        KeyRef keyRef = new KeyRef("kref:test:rsa2");

        FsPkiStoreOptions options = FsPkiStoreOptions.defaults();

        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, options);
                DurableOperatorApprovalSignatureWorkflow signer = new DurableOperatorApprovalSignatureWorkflow(wfRoot,
                        Duration.ofSeconds(10), Duration.ofMillis(0), Map.of(keyRef.value(), kp.getPrivate()));
                PkiSigningBus bus = new PkiSigningBus(store, signer, busFile)) {

            Principal owner = new Principal("USER", "bob");
            PkiId clientOpId = new PkiId("deny-1");
            PkiId opId = bus.canonicalizeOperationId(clientOpId, owner);
            System.out.println("...opId=" + opId.value());

            byte[] payload = "deny".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            EncodedObject payloadObj = new EncodedObject(Encoding.BINARY, payload);

            AccessContext ac = new AccessContext(owner, new Purpose("ISSUANCE"), Optional.empty(), Optional.empty());
            PkiSigningBus.SignContinuation cont = new PkiSigningBus.SignContinuation(ac, "SHA256withRSA", payloadObj,
                    keyRef, Encoding.BINARY, Optional.empty());

            bus.submitSign(opId, owner, keyRef, "SHA256withRSA", payloadObj, Duration.ofSeconds(30),
                    Optional.of(cont.encode()));

            PkiId signerOpId = waitSignerOpId(store, bus, opId);
            signer.deny(signerOpId);

            Instant deadline = Instant.now().plusSeconds(5);
            boolean failed = false;
            AsyncState last = null;
            while (Instant.now().isBefore(deadline)) {
                bus.sweep(Instant.now());
                Optional<AsyncStatus> st = bus.status(opId);
                if (st.isPresent()) {
                    last = st.get().state();
                }
                if (st.isPresent() && st.get().state() == AsyncState.FAILED) {
                    failed = true;
                    break;
                }
                Thread.sleep(10L);
            }
            System.out.println("...lastState=" + (last == null ? "<none>" : last));
            System.out.println("...failed=" + failed);
            assertTrue(failed);
        }

        System.out.println("operatorDeny_failsSignature...ok");
    }

    private static Optional<EncodedObject> waitForSignature(PkiSigningBus bus, PkiId opId, Duration timeout)
            throws InterruptedException {
        Instant deadline = Instant.now().plus(timeout);
        while (Instant.now().isBefore(deadline)) {
            bus.sweep(Instant.now());
            Optional<AsyncStatus> st = bus.status(opId);
            if (st.isPresent() && st.get().state() == AsyncState.SUCCEEDED) {
                return bus.consumeResult(opId);
            }
            if (st.isPresent() && st.get().state() == AsyncState.FAILED) {
                return Optional.empty();
            }
            Thread.sleep(10L);
        }
        return Optional.empty();
    }

    private static PkiId waitSignerOpId(FilesystemPkiStore store, PkiSigningBus bus, PkiId opId)
            throws InterruptedException {
        Instant deadline = Instant.now().plusSeconds(2);
        while (Instant.now().isBefore(deadline)) {
            bus.sweep(Instant.now());

            String base = opId.value().split("#")[0];
            Optional<zeroecho.pki.api.orch.WorkflowStateRecord> wsOpt = store.getWorkflowState(new PkiId(base));
            if (wsOpt.isPresent() && wsOpt.get().payload().isPresent()) {
                PkiSigningBus.SignContinuation cont = PkiSigningBus.SignContinuation
                        .decode(wsOpt.get().payload().get());
                if (cont.signerOpId().isPresent()) {
                    return cont.signerOpId().get();
                }
            }

            Thread.sleep(10L);
        }
        throw new IllegalStateException("Signer operation id not available in continuation within timeout");
    }

    private static String hexPrefix(byte[] bytes) {
        int len = Math.min(bytes.length, 16);
        byte[] p = new byte[len];
        System.arraycopy(bytes, 0, p, 0, len);
        String s = HexFormat.of().formatHex(p);
        return bytes.length > len ? s + "..." : s;
    }
}
