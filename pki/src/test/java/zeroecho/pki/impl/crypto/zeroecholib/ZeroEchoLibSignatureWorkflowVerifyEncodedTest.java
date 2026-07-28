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
package zeroecho.pki.impl.crypto.zeroecholib;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.spi.crypto.SignatureWorkflow;

public final class ZeroEchoLibSignatureWorkflowVerifyEncodedTest {

    @TempDir
    Path tempDir;

    @Test
    public void verifyFromSpkiDerSucceeds() throws Exception {
        System.out.println("verifyFromSpkiDerSucceeds");

        Path keyring = tempDir.resolve("keyring.txt");
        KeyringStore ks = new KeyringStore(new zeroecho.sdk.ZeroEchoSession());
        ks.save(keyring);

        try (ZeroEchoLibSignatureWorkflow wf = new ZeroEchoLibSignatureWorkflow("wf", keyring, "zeroecho-lib:", true)) {

            KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            byte[] payload = "pqc-ready".getBytes(java.nio.charset.StandardCharsets.UTF_8);

            Signature s = Signature.getInstance("SHA256withRSA");
            s.initSign(kp.getPrivate());
            s.update(payload);
            byte[] sig = s.sign();

            EncodedObject payloadObj = new EncodedObject(Encoding.BINARY, payload);
            EncodedObject sigObj = new EncodedObject(Encoding.BINARY, sig);
            EncodedObject spkiObj = new EncodedObject(Encoding.DER, kp.getPublic().getEncoded());

            AccessContext ac = new AccessContext(new Principal("TEST", "verify"), new Purpose("UNIT"), Optional.empty(),
                    Optional.empty());

            SignatureWorkflow.VerifyRequest vr = new SignatureWorkflow.VerifyRequest(ac, "SHA256withRSA", payloadObj,
                    sigObj, Optional.empty(), Optional.of(spkiObj), Optional.of(Instant.now().plusSeconds(5)));

            PkiId opId = wf.submitVerify(vr);
            SignatureWorkflow.OperationStatus st = wf.status(opId);
            assertTrue(st.state() == SignatureWorkflow.State.SUCCEEDED);
            assertTrue(st.result().isPresent());
            assertTrue(st.result().get().verified().isPresent());
            boolean ok = st.result().get().verified().get().booleanValue();
            System.out.println("...verified=" + ok);
            assertTrue(ok);
        }
        System.out.println("verifyFromSpkiDerSucceeds...ok");
    }
}
