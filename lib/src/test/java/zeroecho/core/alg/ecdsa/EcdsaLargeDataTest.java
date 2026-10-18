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
package zeroecho.core.alg.ecdsa;

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

public class EcdsaLargeDataTest {

    @BeforeAll
    static void setup() {
        // No special provider needed for JDK 21+ SunEC.
    }

    private static void logBegin(Object... params) {
        String thisClass = EcdsaLargeDataTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logBegin"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "(" + java.util.Arrays.deepToString(params) + ")");
    }

    private static void logEnd() {
        String thisClass = EcdsaLargeDataTest.class.getName();
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

    private static byte[] jcaEcdsaSign(String jcaName, PrivateKey priv, byte[] msg) throws Exception {
        Signature s = Signature.getInstance(jcaName); // e.g. SHA256withECDSAinP1363Format
        s.initSign(priv); // randomized ECDSA (fresh k)
        int off = 0;
        while (off < msg.length) {
            int len = Math.min(8192, msg.length - off);
            s.update(msg, off, len);
            off += len;
        }
        return s.sign();
    }

    private static boolean jcaEcdsaVerify(String jcaName, PublicKey pub, byte[] msg, byte[] sig) throws Exception {
        Signature s = Signature.getInstance(jcaName);
        s.initVerify(pub);
        int off = 0;
        while (off < msg.length) {
            int len = Math.min(8192, msg.length - off);
            s.update(msg, off, len);
            off += len;
        }
        return s.verify(sig);
    }

    private static void runCase(EcdsaCurveSpec spec, int size) throws Exception {
        logBegin(spec.name(), Integer.valueOf(size), "ECDSA cross-check");

        if (!CryptoAlgorithms.available().contains("ECDSA")) {
            System.out.println("...*** SKIP *** ECDSA not registered");
            return;
        }

        byte[] msg = randomBytes(size);
        System.out.println("...msg=" + msg.length + " bytes");

        // Key pair via your unified ECDSA algorithm and enum spec
        KeyPair kp = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("ECDSA", spec);

        // SIGN (streaming): emits [body][signature]; capture trailer
        SignatureContext signer = new zeroecho.sdk.ZeroEchoSession().createContext("ECDSA", KeyUsage.SIGN,
                kp.getPrivate(), spec);
        final byte[][] sigHolder = new byte[1][];
        final int sigLen = signer.tagLength(); // should equal spec.signFixedLength()

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
        System.out.println("...signature size: " + ourSig.length + " (expected " + spec.signFixedLength() + ")");

        // VERIFY with our streaming verifier
        SignatureContext verifier = new zeroecho.sdk.ZeroEchoSession().createContext("ECDSA", KeyUsage.VERIFY,
                kp.getPublic(), spec);
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
        System.out.println("...verified (our verifier on our signature): true");

        // Cross-verify with JCA (P1363 format): JCA must accept our signature
        assertTrue(jcaEcdsaVerify(spec.jcaFactory(), kp.getPublic(), msg, ourSig),
                "JCA verify failed on our signature");

        // Extra symmetry check (optional): our verifier must accept a JCA signature
        // (different bytes)
        byte[] jcaSig = jcaEcdsaSign(spec.jcaFactory(), kp.getPrivate(), msg);
        SignatureContext verifier2 = new zeroecho.sdk.ZeroEchoSession().createContext("ECDSA", KeyUsage.VERIFY,
                kp.getPublic(), spec);
        verifier2.setExpectedTag(jcaSig);
        try (InputStream verIn2 = verifier2.wrap(new ByteArrayInputStream(msg))) {
            byte[] passthrough = readAll(verIn2);
            assertArrayEquals(msg, passthrough, "our verifier failed on JCA signature");
        } finally {
            try {
                verifier2.close();
            } catch (Exception ignore) {
            }
        }
        System.out.println("...verified (our verifier on JCA signature): true");

        logEnd();
    }

    @Test
    void ecdsa_p256_streaming_sign_verify_and_crosscheck_with_jca() throws Exception {
        runCase(EcdsaCurveSpec.P256, 48 * 1024 + 123);
    }

    @Test
    void ecdsa_p384_streaming_sign_verify_and_crosscheck_with_jca() throws Exception {
        runCase(EcdsaCurveSpec.P384, 48 * 1024 + 127);
    }

    @Test
    void ecdsa_p521_streaming_sign_verify_and_crosscheck_with_jca() throws Exception {
        runCase(EcdsaCurveSpec.P512, 48 * 1024 + 131);
    }
}
