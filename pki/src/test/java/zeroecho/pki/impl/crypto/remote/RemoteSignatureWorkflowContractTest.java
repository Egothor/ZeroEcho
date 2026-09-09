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
package zeroecho.pki.impl.crypto.remote;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.crypto.SignatureWorkflow.CallControl;
import zeroecho.pki.spi.crypto.SignatureWorkflow.OperationStatus;
import zeroecho.pki.spi.crypto.SignatureWorkflow.SignRequest;
import zeroecho.pki.spi.crypto.SignatureWorkflow.State;
import zeroecho.pki.testkit.ReferenceRemoteSigner;

/**
 * Contract test proving the remote {@link SignatureWorkflow} provider satisfies
 * the same lifecycle, security, and failure contract as a local provider:
 * submit → status → signed result, idempotent re-submission (never double-signs),
 * conflicting-fingerprint and stale-fence rejection, external-approval and denial
 * hops, cancellation, unknown-operation, optional push callbacks, and key
 * confinement.
 */
public final class RemoteSignatureWorkflowContractTest {

    private static final String PROVIDER_ID = "zeroecho-remote";
    private static final String NAMESPACE = "test-store." + PROVIDER_ID;
    private static final String KEY_HANDLE = "rk-1";
    private static final KeyRef KEY_REF = new KeyRef("zeroecho-remote:" + KEY_HANDLE);
    private static final String ALGORITHM = "SHA256withRSA";

    @Test
    public void submitsThroughToASignedResultAndConfinesKeys() throws Exception {
        System.out.println("submitsThroughToASignedResultAndConfinesKeys");
        KeyPair keyPair = rsa();
        ReferenceRemoteSigner signer = new ReferenceRemoteSigner(Map.of(KEY_HANDLE, keyPair), false);
        try (RemoteSignatureWorkflow workflow = workflow(signer)) {
            byte[] content = "remote-signed-content".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            PkiId opId = new PkiId("remote-op-signed");
            PkiId returned = workflow.submitSign(request(workflow, opId, content, 1L), control());
            assertEquals(opId, returned);

            OperationStatus status = workflow.status(opId, control());
            assertEquals(State.SUCCEEDED, status.state());
            byte[] signature = status.result().orElseThrow().signature().orElseThrow().bytes();

            // The public key info crosses the boundary; the private key never does.
            PublicKey publicKey = publicKey(workflow.resolvePublicKeyInfo(KEY_REF).bytes());
            Signature verifier = Signature.getInstance(ALGORITHM);
            verifier.initVerify(publicKey);
            verifier.update(content);
            assertTrue(verifier.verify(signature), "remote signature must verify under the resolved public key");
        }
    }

    @Test
    public void reSubmissionIsIdempotentAndNeverSignsTwice() throws Exception {
        System.out.println("reSubmissionIsIdempotentAndNeverSignsTwice");
        ReferenceRemoteSigner signer = new ReferenceRemoteSigner(Map.of(KEY_HANDLE, rsa()), false);
        try (RemoteSignatureWorkflow workflow = workflow(signer)) {
            byte[] content = "idempotent".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            PkiId opId = new PkiId("remote-op-idem");
            workflow.submitSign(request(workflow, opId, content, 1L), control());
            byte[] first = workflow.status(opId, control()).result().orElseThrow().signature().orElseThrow().bytes();

            // Same submission id and fingerprint attaches to the existing outcome.
            workflow.submitSign(request(workflow, opId, content, 1L), control());
            byte[] second = workflow.status(opId, control()).result().orElseThrow().signature().orElseThrow().bytes();
            assertEquals(java.util.HexFormat.of().formatHex(first), java.util.HexFormat.of().formatHex(second));
        }
    }

    @Test
    public void rejectsConflictingFingerprintAndStaleFence() throws Exception {
        System.out.println("rejectsConflictingFingerprintAndStaleFence");
        ReferenceRemoteSigner signer = new ReferenceRemoteSigner(Map.of(KEY_HANDLE, rsa()), false);
        try (RemoteSignatureWorkflow workflow = workflow(signer)) {
            PkiId opId = new PkiId("remote-op-conflict");
            workflow.submitSign(request(workflow, opId, "first".getBytes(), 2L), control());

            // Same id, different content = different fingerprint.
            assertThrows(IllegalStateException.class,
                    () -> workflow.submitSign(request(workflow, opId, "second".getBytes(), 2L), control()));
            // Same id and fingerprint, lower fence = stale.
            assertThrows(IllegalStateException.class,
                    () -> workflow.submitSign(request(workflow, opId, "first".getBytes(), 1L), control()));
        }
    }

    @Test
    public void externalApprovalDrivesQueuedToSignedAndDenialToFailed() throws Exception {
        System.out.println("externalApprovalDrivesQueuedToSignedAndDenialToFailed");
        ReferenceRemoteSigner signer = new ReferenceRemoteSigner(Map.of(KEY_HANDLE, rsa()), true);
        try (RemoteSignatureWorkflow workflow = workflow(signer)) {
            PkiId approved = new PkiId("remote-op-approve");
            workflow.submitSign(request(workflow, approved, "approve-me".getBytes(), 1L), control());
            assertEquals(State.WAITING_APPROVAL, workflow.status(approved, control()).state());
            signer.approve(approved.value());
            assertEquals(State.SUCCEEDED, workflow.status(approved, control()).state());

            PkiId denied = new PkiId("remote-op-deny");
            workflow.submitSign(request(workflow, denied, "deny-me".getBytes(), 1L), control());
            assertEquals(State.WAITING_APPROVAL, workflow.status(denied, control()).state());
            signer.deny(denied.value(), "operator-rejected");
            OperationStatus deniedStatus = workflow.status(denied, control());
            assertEquals(State.FAILED, deniedStatus.state());
            assertEquals("operator-rejected", deniedStatus.detailCode().orElseThrow());
        }
    }

    @Test
    public void cancellationIsAcceptedAndTerminal() throws Exception {
        System.out.println("cancellationIsAcceptedAndTerminal");
        ReferenceRemoteSigner signer = new ReferenceRemoteSigner(Map.of(KEY_HANDLE, rsa()), true);
        try (RemoteSignatureWorkflow workflow = workflow(signer)) {
            PkiId opId = new PkiId("remote-op-cancel");
            workflow.submitSign(request(workflow, opId, "cancel-me".getBytes(), 1L), control());
            assertTrue(workflow.cancel(opId, 1L, "no-longer-needed", control()));
            assertEquals(State.CANCELLED, workflow.status(opId, control()).state());
        }
    }

    @Test
    public void unknownOperationIsFailedNotThrown() throws Exception {
        System.out.println("unknownOperationIsFailedNotThrown");
        ReferenceRemoteSigner signer = new ReferenceRemoteSigner(Map.of(KEY_HANDLE, rsa()), false);
        try (RemoteSignatureWorkflow workflow = workflow(signer)) {
            OperationStatus status = workflow.status(new PkiId("remote-op-unknown"), control());
            assertEquals(State.FAILED, status.state());
        }
    }

    @Test
    public void optionalPushCallbackDeliversTerminalStatus() throws Exception {
        System.out.println("optionalPushCallbackDeliversTerminalStatus");
        ReferenceRemoteSigner signer = new ReferenceRemoteSigner(Map.of(KEY_HANDLE, rsa()), true);
        try (RemoteSignatureWorkflow workflow = workflow(signer)) {
            List<State> observed = new ArrayList<>();
            try (SignatureWorkflow.Registration ignored = workflow.register((id, status) -> observed.add(status.state()))) {
                PkiId opId = new PkiId("remote-op-callback");
                workflow.submitSign(request(workflow, opId, "callback".getBytes(), 1L), control());
                signer.approve(opId.value());
            }
            assertTrue(observed.contains(State.SUCCEEDED), "a push callback must deliver the signed terminal status");
        }
    }

    private RemoteSignatureWorkflow workflow(ReferenceRemoteSigner signer) {
        return new RemoteSignatureWorkflow(PROVIDER_ID, signer, "zeroecho-remote:", Duration.ofDays(90));
    }

    private SignRequest request(RemoteSignatureWorkflow workflow, PkiId opId, byte[] content, long fence) {
        return SignRequest.create(opId, NAMESPACE, workflow.configurationCommitment(), fence,
                new AccessContext(new Principal("USER", "tester"), new Purpose("TEST"), Optional.empty(),
                        Optional.empty()),
                KEY_REF, ALGORITHM, SignatureWorkflow.ContentCommitment.sha256(content),
                new ImmutableByteContent(content), Optional.of(Encoding.BINARY), Optional.empty());
    }

    private static CallControl control() {
        return new CallControl(Instant.now().plusSeconds(60L), CancellationSignal.NONE);
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static PublicKey publicKey(byte[] spki) throws Exception {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(spki));
    }
}
