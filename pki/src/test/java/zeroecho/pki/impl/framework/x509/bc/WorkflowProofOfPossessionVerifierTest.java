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

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Map;
import java.util.Optional;

import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.issuance.VerificationPolicy;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.ProofOfPossessionResult;
import zeroecho.pki.api.request.ProofOfPossessionStatus;
import zeroecho.pki.impl.crypto.zeroecholib.ZeroEchoLibSignatureWorkflowProvider;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.crypto.SignatureWorkflow;

public final class WorkflowProofOfPossessionVerifierTest {

    @TempDir
    Path tempDir;

    @Test
    public void verifyRsaCsrViaWorkflow_ok() throws Exception {
        System.out.println("verifyRsaCsrViaWorkflow_ok");

        Path keyringPath = tempDir.resolve("keyring.zek");
        try (KeyringPassword password =
                zeroecho.pki.impl.crypto.zeroecholib.TestKeyringUnlocks.provider().acquire();
                KeyringStore ignored = KeyringStore.create(keyringPath, password)) {
            // Encoded-key verification needs no persisted key entry.
        }
        System.out.println("...keyringPath=" + keyringPath.getFileName());

        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        X500Name subject = new X500Name("CN=csr-test");
        PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate()));

        byte[] csrDer = csr.getEncoded();
        System.out.println("...csrDerLen=" + csrDer.length);

        CertificationRequest req = new CertificationRequest(BcX509CredentialFramework.FORMAT_ID,
                new EncodedObject(Encoding.DER, csrDer));

        ParsedCertificationRequest parsed = new BcX509CertificationRequestParser().parse(req);

        ZeroEchoLibSignatureWorkflowProvider provider =
                new ZeroEchoLibSignatureWorkflowProvider(
                        zeroecho.pki.impl.crypto.zeroecholib.TestKeyringUnlocks.provider());
        ProviderConfig cfg = new ProviderConfig(provider.id(), Map.of("keyringPath", keyringPath.toString(),
                "operationRoot", tempDir.resolve("signing-operations").toString()));
        SignatureWorkflow wf = provider.allocate(cfg);

        WorkflowProofOfPossessionVerifier verifier = new WorkflowProofOfPossessionVerifier(wf);
        VerificationPolicy policy = new VerificationPolicy(true, Optional.empty());

        ProofOfPossessionResult res = verifier.verify(parsed, policy);
        System.out.println("...status=" + res.status());
        assertEquals(ProofOfPossessionStatus.VERIFIED, res.status());

        System.out.println("verifyRsaCsrViaWorkflow_ok...ok");
    }
}
