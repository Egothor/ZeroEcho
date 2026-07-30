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
package zeroecho.core.alg.aes;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import conflux.Ctx;
import conflux.CtxInterface;
import zeroecho.core.ConfluxKeys;
import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.spi.ContextAware;

public class AesGcmCrossCheckTest {

    // ---- logging helpers (same pattern you use elsewhere) ----

    private static void logBegin(Object... params) {
        String thisClass = AesGcmCrossCheckTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logBegin"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "(" + Arrays.deepToString(params) + ")");
    }

    private static void logEnd() {
        String thisClass = AesGcmCrossCheckTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logEnd"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "...ok");
    }

    @BeforeAll
    static void setup() {
        // add providers if needed
    }

    private static byte[] rand(int n) {
        byte[] a = new byte[n];
        new SecureRandom().nextBytes(a);
        return a;
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

    private static byte[] jcaGcmEncrypt(SecretKey key, byte[] iv, int tagBits, byte[] aad, byte[] msg)
            throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NOPADDING");
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(tagBits, iv));
        if (aad != null && aad.length > 0) {
            c.updateAAD(aad);
        }
        return c.doFinal(msg);
    }

    private static byte[] jcaGcmDecrypt(SecretKey key, byte[] iv, int tagBits, byte[] aad, byte[] ct) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NOPADDING");
        c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(tagBits, iv));
        if (aad != null && aad.length > 0) {
            c.updateAAD(aad);
        }
        return c.doFinal(ct);
    }

    @Test
    void aesGcm_stream_vs_jca_ctxOnly_crosscheck() throws Exception {
        final int SIZE = 32 * 1024 + 777;
        final int TAG_BITS = 128;
        logBegin(SIZE, "AES/GCM ctx-only cross-check");

        // --- test vectors ---
        byte[] msg = rand(SIZE);
        byte[] aad = "test-aad-123".getBytes();

        // --- key (either via your builder or direct JCA; both fine) ---
        CryptoAlgorithm aesAlg = CryptoAlgorithms.require("AES");
        SecretKey key = aesAlg.symmetricKeyGenerator(AesKeyGenSpec.class).generateSecret(AesKeyGenSpec.aes256());
        // or:
        // KeyGenerator kg = KeyGenerator.getInstance("AES");
        // kg.init(256);
        // SecretKey key = kg.generateKey();

        // --- per-test context; encryption generates IV and stores it here ---
        CtxInterface session = Ctx.INSTANCE.getContext("aes-gcm-xchk-" + System.nanoTime());
        session.put(ConfluxKeys.aad("AES"), aad);

        AesSpec spec = AesSpec.gcm128(null);

        // === STREAM ENCRYPT ===
        EncryptionContext enc = new zeroecho.sdk.ZeroEchoSession().createContext("AES", KeyUsage.ENCRYPT, key, spec);
        ((ContextAware) enc).setContext(session);
        byte[] ct_stream = readAll(enc.attach(new ByteArrayInputStream(msg)));
        enc.close();
        byte[] iv = session.get(ConfluxKeys.iv("AES"));

        // === JCA ENCRYPT (reference) ===
        byte[] ct_jca = jcaGcmEncrypt(key, iv, TAG_BITS, aad, msg);

        System.out.printf("ct_stream: %d bytes, ct_jca: %d bytes%n", ct_stream.length, ct_jca.length);
        assertArrayEquals(ct_jca, ct_stream, "STREAM ciphertext != JCA ciphertext (IV/AAD/msg must match)");

        // === STREAM DECRYPT of JCA ciphertext ===
        EncryptionContext dec1 = new zeroecho.sdk.ZeroEchoSession().createContext("AES", KeyUsage.DECRYPT, key, spec);
        ((ContextAware) dec1).setContext(session); // same IV/AAD in ctx
        byte[] pt1 = readAll(dec1.attach(new ByteArrayInputStream(ct_jca)));
        dec1.close();
        assertArrayEquals(msg, pt1, "STREAM decrypt(JCA ct) mismatch");

        // === JCA DECRYPT of STREAM ciphertext ===
        byte[] pt2 = jcaGcmDecrypt(key, iv, TAG_BITS, aad, ct_stream);
        assertArrayEquals(msg, pt2, "JCA decrypt(STREAM ct) mismatch");

        logEnd();
    }
}
