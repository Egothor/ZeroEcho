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
package zeroecho.pki.impl.crypto.remote.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.impl.crypto.remote.RemoteSignatureWorkflowProvider;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.crypto.SignatureWorkflow.CallControl;
import zeroecho.pki.spi.crypto.SignatureWorkflow.ContentCommitment;
import zeroecho.pki.spi.crypto.SignatureWorkflow.SignRequest;
import zeroecho.pki.spi.crypto.SignatureWorkflow.State;
import zeroecho.pki.spi.crypto.SignatureWorkflowRuntimeDependencies;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport.RemoteCallControl;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport.RemoteSignRequest;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport.RemoteSigningState;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport.RemoteSigningStatus;
import zeroecho.pki.testkit.ReferenceRemoteSigner;
import zeroecho.pki.testkit.TestMutualTls;

/** End-to-end proof of the packaged mutually-authenticated HTTPS/JSON remote signing transport. */
public final class HttpsRemoteSigningTransportTest {

    private static final String KEY_HANDLE = "rk-1";
    private static final String ALGORITHM = "SHA256withRSA";

    @Test
    public void signsEndToEndOverMutualTlsThroughTheTransport() throws Exception {
        System.out.println("signsEndToEndOverMutualTlsThroughTheTransport");
        KeyPair keyPair = rsa();
        TestMutualTls tls = TestMutualTls.create();
        try (ReferenceRemoteSigningServer server = ReferenceRemoteSigningServer.start(
                new ReferenceRemoteSigner(Map.of(KEY_HANDLE, keyPair), false), tls.serverContext());
                RemoteSigningTransport transport = HttpsRemoteSigningTransport.open(server.endpoint(),
                        tls.clientContext(), Duration.ofSeconds(5), Duration.ofSeconds(5))) {
            assertTrue(transport.capabilities().supportedAlgorithms().contains(ALGORITHM));
            assertEquals(32, transport.capabilities().configurationCommitment().length);

            byte[] content = "remote-signed-over-https".getBytes(StandardCharsets.UTF_8);
            RemoteSigningStatus status = transport.submit(request("op-1", "fp-1", content), control());
            assertEquals(RemoteSigningState.SIGNED, status.state());
            assertTrue(status.signature().isPresent());

            PublicKey publicKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(transport.publicKeyInfo(KEY_HANDLE, control())));
            Signature verifier = Signature.getInstance(ALGORITHM);
            verifier.initVerify(publicKey);
            verifier.update(content);
            assertTrue(verifier.verify(status.signature().orElseThrow()));
            assertEquals(RemoteSigningState.SIGNED, transport.status("op-1", control()).state());
        }
    }

    @Test
    public void externalApprovalDrivesQueuedToSignedOverTheTransport() throws Exception {
        System.out.println("externalApprovalDrivesQueuedToSignedOverTheTransport");
        ReferenceRemoteSigner signer = new ReferenceRemoteSigner(Map.of(KEY_HANDLE, rsa()), true);
        TestMutualTls tls = TestMutualTls.create();
        try (ReferenceRemoteSigningServer server = ReferenceRemoteSigningServer.start(signer, tls.serverContext());
                RemoteSigningTransport transport = HttpsRemoteSigningTransport.open(server.endpoint(),
                        tls.clientContext(), Duration.ofSeconds(5), Duration.ofSeconds(5))) {
            byte[] content = "awaiting-approval".getBytes(StandardCharsets.UTF_8);
            RemoteSigningStatus queued = transport.submit(request("op-2", "fp-2", content), control());
            assertEquals(RemoteSigningState.QUEUED, queued.state());

            signer.approve("op-2");
            RemoteSigningStatus signed = transport.status("op-2", control());
            assertEquals(RemoteSigningState.SIGNED, signed.state());
            assertTrue(signed.signature().isPresent());
        }
    }

    @Test
    public void conflictingResubmissionSurfacesAsIllegalState() throws Exception {
        System.out.println("conflictingResubmissionSurfacesAsIllegalState");
        TestMutualTls tls = TestMutualTls.create();
        try (ReferenceRemoteSigningServer server = ReferenceRemoteSigningServer.start(
                new ReferenceRemoteSigner(Map.of(KEY_HANDLE, rsa()), false), tls.serverContext());
                RemoteSigningTransport transport = HttpsRemoteSigningTransport.open(server.endpoint(),
                        tls.clientContext(), Duration.ofSeconds(5), Duration.ofSeconds(5))) {
            transport.submit(request("op-3", "fp-3", "first".getBytes(StandardCharsets.UTF_8)), control());
            assertThrows(IllegalStateException.class, () -> transport.submit(
                    request("op-3", "fp-3-different", "second".getBytes(StandardCharsets.UTF_8)), control()));
        }
    }

    @Test
    public void unknownOperationIsReportedDeniedNotThrown() throws Exception {
        System.out.println("unknownOperationIsReportedDeniedNotThrown");
        TestMutualTls tls = TestMutualTls.create();
        try (ReferenceRemoteSigningServer server = ReferenceRemoteSigningServer.start(
                new ReferenceRemoteSigner(Map.of(KEY_HANDLE, rsa()), false), tls.serverContext());
                RemoteSigningTransport transport = HttpsRemoteSigningTransport.open(server.endpoint(),
                        tls.clientContext(), Duration.ofSeconds(5), Duration.ofSeconds(5))) {
            assertEquals(RemoteSigningState.DENIED, transport.status("never-submitted", control()).state());
        }
    }

    @Test
    public void providerConfiguredWithPkcs12SignsOverHttps(@TempDir Path directory) throws Exception {
        System.out.println("providerConfiguredWithPkcs12SignsOverHttps");
        KeyPair keyPair = rsa();
        TestMutualTls tls = TestMutualTls.create();
        TestMutualTls.ClientMaterial material = tls.writeClientMaterial(directory);
        try (ReferenceRemoteSigningServer server = ReferenceRemoteSigningServer.start(
                new ReferenceRemoteSigner(Map.of(KEY_HANDLE, keyPair), false), tls.serverContext())) {
            String password = new String(TestMutualTls.PASSWORD);
            ProviderConfig config = new ProviderConfig("zeroecho-remote", Map.of(
                    "endpoint", server.endpoint().toString(),
                    "tlsKeystore", material.keystore().toString(),
                    "tlsKeystorePassword", password,
                    "tlsTruststore", material.truststore().toString(),
                    "tlsTruststorePassword", password));
            RemoteSignatureWorkflowProvider provider = new RemoteSignatureWorkflowProvider();
            try (SignatureWorkflow workflow = provider.allocate(config,
                    SignatureWorkflowRuntimeDependencies.none())) {
                byte[] content = "provider-over-https".getBytes(StandardCharsets.UTF_8);
                PkiId operationId = new PkiId("prov-https-1");
                CallControl control = new CallControl(Instant.now().plusSeconds(30L), CancellationSignal.NONE);
                SignRequest request = SignRequest.create(operationId, "store.zeroecho-remote",
                        workflow.configurationCommitment(), 1L,
                        new AccessContext(new Principal("USER", "tester"), new Purpose("TEST"), Optional.empty(),
                                Optional.empty()),
                        new KeyRef("zeroecho-remote:" + KEY_HANDLE), ALGORITHM, ContentCommitment.sha256(content),
                        new ImmutableByteContent(content), Optional.of(Encoding.BINARY), Optional.empty());
                workflow.submitSign(request, control);
                assertEquals(State.SUCCEEDED, workflow.status(operationId, control).state());
            }
        }
    }

    private static RemoteSignRequest request(String submissionId, String fingerprint, byte[] content) {
        return new RemoteSignRequest(submissionId, "store.zeroecho-remote", fingerprint, 1L, KEY_HANDLE, ALGORITHM,
                sha256Hex(content), content.length, content, "USER", "tester", "TEST", Optional.empty());
    }

    private static RemoteCallControl control() {
        return new RemoteCallControl(Instant.now().plusSeconds(30L), CancellationSignal.NONE);
    }

    private static String sha256Hex(byte[] content) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
        } catch (java.security.NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 unavailable", unavailable);
        }
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
