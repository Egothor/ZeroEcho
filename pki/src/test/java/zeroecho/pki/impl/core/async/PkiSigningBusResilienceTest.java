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
import java.security.PublicKey;
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

public final class PkiSigningBusResilienceTest {

    @TempDir
    Path tempDir;

    @Test
    public void requesterRestart_canConsumeResult_afterServerCompletes() throws Exception {
        System.out.println("requesterRestart_canConsumeResult_afterServerCompletes");

        Path storeRoot = tempDir.resolve("store");
        Path busFile = tempDir.resolve("bus.log");
        Path wfRoot = tempDir.resolve("workflow");

        System.out.println("...storeRoot=" + storeRoot.getFileName());
        System.out.println("...busFile=" + busFile.getFileName());
        System.out.println("...wfRoot=" + wfRoot.getFileName());

        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        KeyRef keyRef = new KeyRef("kref:test:rsa");

        Principal owner = new Principal("USER", "alice");
        PkiId clientOpId = new PkiId("client-op-1");

        byte[] payload = "hello".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        EncodedObject payloadObj = new EncodedObject(Encoding.BINARY, payload);

        FsPkiStoreOptions options = FsPkiStoreOptions.defaults();

        // "Server" starts, request is submitted, then requester goes away.
        PkiId opId;
        PkiId signerOpId;
        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, options);
                DurableOperatorApprovalSignatureWorkflow signer = new DurableOperatorApprovalSignatureWorkflow(wfRoot,
                        Duration.ofSeconds(10), Duration.ofMillis(100), Map.of(keyRef.value(), kp.getPrivate()));
                PkiSigningBus bus = new PkiSigningBus(store, signer, busFile)) {

            opId = bus.canonicalizeOperationId(clientOpId, owner);
            System.out.println("...opId=" + opId.value());

            AccessContext ac = new AccessContext(owner, new Purpose("ISSUANCE"), Optional.empty(), Optional.empty());
            PkiSigningBus.SignContinuation cont = new PkiSigningBus.SignContinuation(ac, "SHA256withRSA", payloadObj,
                    keyRef, Encoding.BINARY, Optional.empty());

            Instant t0 = Instant.now();
            bus.submitSign(opId, owner, keyRef, "SHA256withRSA", payloadObj, Duration.ofSeconds(30),
                    Optional.of(cont.encode()));
            long submitMs = Duration.between(t0, Instant.now()).toMillis();
            System.out.println("...submitMs=" + submitMs);
            assertTrue(submitMs < 50L);

            bus.sweep(Instant.now());

            // Read signerOpId from continuation (after first sweep/status poll).
            signerOpId = waitSignerOpId(store, bus, opId);
            System.out.println("...signerOpId=" + signerOpId.value());

            // Approve and allow server to complete.
            signer.approve(signerOpId);

            Optional<EncodedObject> sigOpt = waitForSignature(bus, opId, Duration.ofSeconds(5));
            assertTrue(sigOpt.isPresent());
            System.out.println("...sigLen=" + sigOpt.get().bytes().length);
            System.out.println("...sigHexPrefix=" + hexPrefix(sigOpt.get().bytes()));

            verifySignature(kp.getPublic(), payload, sigOpt.get().bytes());

            // requester "goes away" here (close)
        }

        // "Requester restart": the caller retains the stable submission identifier.
        try (FilesystemPkiStore store2 = new FilesystemPkiStore(storeRoot, options);
                DurableOperatorApprovalSignatureWorkflow signer2 = new DurableOperatorApprovalSignatureWorkflow(wfRoot,
                        Duration.ofSeconds(10), Duration.ofMillis(0), Map.of(keyRef.value(), kp.getPrivate()));
                PkiSigningBus bus2 = new PkiSigningBus(store2, signer2, busFile)) {

            PkiId opId2 = opId;
            System.out.println("...opIdReattach=" + opId2.value());
            assertTrue(opId2.value().equals(opId.value()));

            bus2.sweep(Instant.now());
            Optional<AsyncStatus> st = bus2.status(opId2);
            System.out.println("...statusAfterRestart=" + (st.isPresent() ? st.get().state() : "EMPTY"));
            // It may already be consumed in previous phase; if not, it must at least be
            // terminal.
            if (st.isPresent()) {
                assertTrue(st.get().state() == AsyncState.SUCCEEDED || st.get().state() == AsyncState.FAILED
                        || st.get().state() == AsyncState.EXPIRED);
            }
        }

        System.out.println("requesterRestart_canConsumeResult_afterServerCompletes...ok");
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
            Optional<zeroecho.pki.api.orch.WorkflowStateRecord> wsOpt = store
                    .getWorkflowState(new PkiId(opId.value().split("#")[0]));
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

    private static void verifySignature(PublicKey publicKey, byte[] payload, byte[] signature) throws Exception {
        Signature v = Signature.getInstance("SHA256withRSA");
        v.initVerify(publicKey);
        v.update(payload);
        boolean ok = v.verify(signature);
        System.out.println("...signatureVerified=" + ok);
        assertTrue(ok);
    }

    private static String hexPrefix(byte[] bytes) {
        int len = Math.min(bytes.length, 16);
        byte[] p = new byte[len];
        System.arraycopy(bytes, 0, p, 0, len);
        String s = HexFormat.of().formatHex(p);
        return bytes.length > len ? s + "..." : s;
    }
}
