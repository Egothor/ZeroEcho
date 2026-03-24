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
package zeroecho.core.alg.ed25519;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.io.TailStrippingInputStream;

public class Ed25519LargeDataTest {

    @BeforeAll
    static void setup() {
        // Provider setup if needed
    }

    private static void logBegin(Object... params) {
        String thisClass = Ed25519LargeDataTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logBegin"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "(" + java.util.Arrays.deepToString(params) + ")");
    }

    private static void logEnd() {
        String thisClass = Ed25519LargeDataTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logEnd"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "...ok");
    }

    private static byte[] randomBytes(int len) {
        byte[] data = new byte[len];
        new SecureRandom().nextBytes(data);
        return data;
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private static byte[] jcaEd25519Sign(PrivateKey priv, byte[] msg) throws Exception {
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(priv);
        int off = 0;
        while (off < msg.length) {
            int len = Math.min(8192, msg.length - off);
            s.update(msg, off, len);
            off += len;
        }
        return s.sign();
    }

    private static boolean jcaEd25519Verify(PublicKey pub, byte[] msg, byte[] sig) throws Exception {
        Signature s = Signature.getInstance("Ed25519");
        s.initVerify(pub);
        int off = 0;
        while (off < msg.length) {
            int len = Math.min(8192, msg.length - off);
            s.update(msg, off, len);
            off += len;
        }
        return s.verify(sig);
    }

    @Test
    void ed25519_streaming_sign_verify_and_crosscheck_with_jca() throws Exception {
        final int SIZE = 48 * 1024 + 123;
        logBegin(Integer.valueOf(SIZE), "Ed25519 cross-check");

        byte[] msg = randomBytes(SIZE);

        if (!CryptoAlgorithms.available().contains("Ed25519")) {
            System.out.println("...*** SKIP *** Ed25519 not registered");
            return;
        }

        KeyPair kp = CryptoAlgorithms.keyPair("Ed25519", Ed25519KeyGenSpec.defaultSpec());

        // SIGN: context emits [body][signature] — capture trailer via
        // TailStrippingInputStream
        SignatureContext signer = CryptoAlgorithms.create("Ed25519", KeyUsage.SIGN, kp.getPrivate(), null);
        final byte[][] sigHolder = new byte[1][];
        final int sigLen = signer.tagLength();

        byte[] sink1;
        try (InputStream in = new TailStrippingInputStream(signer.wrap(new ByteArrayInputStream(msg)), sigLen, 8192) {
            @Override
            protected void processTail(byte[] tail) throws IOException {
                sigHolder[0] = (tail == null ? null : tail.clone());
            }
        }) {
            sink1 = readAll(in);
        } finally {
            try {
                signer.close();
            } catch (Exception ignore) {
            }
        }

        assertArrayEquals(msg, sink1, "sign passthrough mismatch");
        byte[] ourSig = sigHolder[0];
        assertNotNull(ourSig, "signature missing");
        System.out.println("...input size: " + msg.length);
        System.out.println("...signature size: " + ourSig.length);

        // Cross-check with JCA
        byte[] refSig = jcaEd25519Sign(kp.getPrivate(), msg);
        assertArrayEquals(refSig, ourSig, "signature mismatch vs JCA reference");

        // VERIFY: supply expected tag and drain (throws on mismatch)
        SignatureContext verifier = CryptoAlgorithms.create("Ed25519", KeyUsage.VERIFY, kp.getPublic(), null);
        verifier.setExpectedTag(ourSig);

        byte[] sink2;
        try (InputStream verIn = verifier.wrap(new ByteArrayInputStream(msg))) {
            sink2 = readAll(verIn);
        } finally {
            try {
                verifier.close();
            } catch (Exception ignore) {
            }
        }

        assertArrayEquals(msg, sink2, "verify passthrough mismatch");
        System.out.println("...verified: true");

        // JCA verify on produced signature
        assertTrue(jcaEd25519Verify(kp.getPublic(), msg, ourSig), "JCA verify failed on our signature");

        logEnd();
    }
}
