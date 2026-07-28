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

import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import conflux.Ctx;
import conflux.CtxInterface;
import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.spi.ContextAware;

public class AesLargeDataTest {

    @BeforeAll
    static void setup() {
        // Providers if needed, e.g.:
        // Security.addProvider(new BouncyCastleProvider());
    }

    private static void logBegin(Object... params) {
        String thisClass = AesLargeDataTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logBegin"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "(" + Arrays.deepToString(params) + ")");
    }

    private static void logEnd() {
        String thisClass = AesLargeDataTest.class.getName();
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

    /**
     * AES-GCM round-trip using Ctx-only parameters (default; IV is shared in the
     * session Ctx).
     */
    @Test
    void aesGcmLargeData_ctxOnly() throws Exception {
        final int SIZE = 32 * 1024 + 777;
        logBegin(SIZE, "AES/GCM/NOPADDING (Ctx-only)");

        byte[] msg = randomBytes(SIZE);
        CryptoAlgorithm aes = CryptoAlgorithms.require("AES");

        SecretKey key = aes.symmetricKeyGenerator(AesKeyGenSpec.class).generateSecret(AesKeyGenSpec.aes256());

        CtxInterface session = Ctx.INSTANCE.getContext("aes-ctx-" + System.nanoTime());

        AesSpec spec = AesSpec.gcm128(null);

        EncryptionContext enc = new zeroecho.sdk.ZeroEchoSession().createContext("AES", KeyUsage.ENCRYPT, key, spec);
        ((ContextAware) enc).setContext(session);
        byte[] ct = readAll(enc.attach(new ByteArrayInputStream(msg)));
        enc.close();

        EncryptionContext dec = new zeroecho.sdk.ZeroEchoSession().createContext("AES", KeyUsage.DECRYPT, key, spec);
        ((ContextAware) dec).setContext(session);
        byte[] pt = readAll(dec.attach(new ByteArrayInputStream(ct)));
        dec.close();

        assertArrayEquals(msg, pt, "AES-GCM (Ctx-only) mismatch");
        logEnd();
    }

    /** AES-GCM round-trip using an in-band header (codec in Ctx). */
    @Test
    void aesGcmLargeData_headerCodec() throws Exception {
        final int SIZE = 32 * 1024 + 777;
        logBegin(SIZE, "AES/GCM/NOPADDING (HeaderCodec)");

        byte[] msg = randomBytes(SIZE);
        System.out.printf("...input: %d bytes%n", msg.length);
        CryptoAlgorithm aes = CryptoAlgorithms.require("AES");

        SecretKey key = aes.symmetricKeyGenerator(AesKeyGenSpec.class).generateSecret(AesKeyGenSpec.aes256());

        CtxInterface session = Ctx.INSTANCE.getContext("aes-hdr-" + System.nanoTime());
        AesSpec spec = AesSpec.gcm128(new AesHeaderCodec());

        EncryptionContext enc = new zeroecho.sdk.ZeroEchoSession().createContext("AES", KeyUsage.ENCRYPT, key, spec);
        ((ContextAware) enc).setContext(session);
        byte[] ct = readAll(enc.attach(new ByteArrayInputStream(msg)));
        enc.close();
        System.out.printf("...encrypted: %d bytes%n", ct.length);

        EncryptionContext dec = new zeroecho.sdk.ZeroEchoSession().createContext("AES", KeyUsage.DECRYPT, key, spec);
        ((ContextAware) dec).setContext(session);
        byte[] pt = readAll(dec.attach(new ByteArrayInputStream(ct)));
        dec.close();
        System.out.printf("...decrypted: %d bytes%n", pt.length);

        assertArrayEquals(msg, pt, "AES-GCM (HeaderCodec) mismatch");
        logEnd();
    }

    /** AES-CBC/PKCS7Padding round-trip (Ctx-only IV). */
    @Test
    void aesCbcPkcs5LargeData_ctxOnly() throws Exception {
        final int SIZE = 32 * 1024 + 777;
        logBegin(SIZE, "AES/CBC/PKCS7Padding (Ctx-only)");

        byte[] msg = randomBytes(SIZE);
        CryptoAlgorithm aes = CryptoAlgorithms.require("AES");

        SecretKey key = aes.symmetricKeyGenerator(AesKeyGenSpec.class).generateSecret(AesKeyGenSpec.aes256());

        CtxInterface session = Ctx.INSTANCE.getContext("aes-cbc-" + System.nanoTime());

        AesSpec spec = AesSpec.cbcPkcs7(null);

        EncryptionContext enc = new zeroecho.sdk.ZeroEchoSession().createContext("AES", KeyUsage.ENCRYPT, key, spec);
        ((ContextAware) enc).setContext(session);
        byte[] ct = readAll(enc.attach(new ByteArrayInputStream(msg)));
        enc.close();

        EncryptionContext dec = new zeroecho.sdk.ZeroEchoSession().createContext("AES", KeyUsage.DECRYPT, key, spec);
        ((ContextAware) dec).setContext(session);
        byte[] pt = readAll(dec.attach(new ByteArrayInputStream(ct)));
        dec.close();

        assertArrayEquals(msg, pt, "AES-CBC decrypt mismatch");
        logEnd();
    }
}
