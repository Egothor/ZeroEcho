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
package zeroecho.core.alg.rsa;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.context.EncryptionContext;

public class RsaLargeDataTest {

    @BeforeAll
    static void setup() {
        // If you register providers elsewhere, this can be empty.
        // e.g., Security.addProvider(new BouncyCastleProvider());
    }

    private static void logBegin(Object... params) {
        String thisClass = RsaLargeDataTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logBegin"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "(" + Arrays.deepToString(params) + ")");
    }

    private static void logEnd() {
        String thisClass = RsaLargeDataTest.class.getName();
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

    /** OAEP(SHA-256) round-trip on >16KB payload (non-multiple of block size). */
    @Test
    void rsaOaepLargeData() throws Exception {
        final int SIZE = 32 * 1024 + 777; // >16KB, odd length to cross block boundaries
        logBegin(SIZE, "OAEP(SHA-256)");

        byte[] msg = randomBytes(SIZE);
        System.out.printf("...input: %d bytes%n", msg.length);

        KeyPair kp = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("RSA", RsaKeyGenSpec.rsa2048());
        RsaEncSpec spec = RsaEncSpec.oaep(RsaEncSpec.Hash.SHA256);

        EncryptionContext enc = new zeroecho.sdk.ZeroEchoSession().createContext("RSA", KeyUsage.ENCRYPT, kp.getPublic(), spec);
        InputStream ctIn = enc.attach(new ByteArrayInputStream(msg));
        byte[] ct = ctIn.readAllBytes();
        enc.close();
        System.out.printf("...encrypted: %d bytes%n", ct.length);

        EncryptionContext dec = new zeroecho.sdk.ZeroEchoSession().createContext("RSA", KeyUsage.DECRYPT, kp.getPrivate(), spec);
        InputStream ptIn = dec.attach(new ByteArrayInputStream(ct));
        byte[] pt = ptIn.readAllBytes();
        dec.close();
        System.out.printf("...decrypted: %d bytes%n", pt.length);

        assertArrayEquals(msg, pt, "RSA OAEP decrypt mismatch");
        logEnd();
    }

    /** PKCS#1 v1.5 round-trip on >16KB payload (non-multiple of block size). */
    @Test
    void rsaPkcs1v15LargeData() throws Exception {
        final int SIZE = 32 * 1024 + 777; // >16KB, odd length
        logBegin(SIZE, "PKCS1v1.5");

        byte[] msg = randomBytes(SIZE);
        System.out.printf("...input: %d bytes%n", msg.length);

        KeyPair kp = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("RSA", RsaKeyGenSpec.rsa2048());
        RsaEncSpec spec = RsaEncSpec.pkcs1v15();

        EncryptionContext enc = new zeroecho.sdk.ZeroEchoSession().createContext("RSA", KeyUsage.ENCRYPT, kp.getPublic(), spec);
        InputStream ctIn = enc.attach(new ByteArrayInputStream(msg));
        byte[] ct = ctIn.readAllBytes();
        enc.close();
        System.out.printf("...encrypted: %d bytes%n", ct.length);

        EncryptionContext dec = new zeroecho.sdk.ZeroEchoSession().createContext("RSA", KeyUsage.DECRYPT, kp.getPrivate(), spec);
        InputStream ptIn = dec.attach(new ByteArrayInputStream(ct));
        byte[] pt = ptIn.readAllBytes();
        dec.close();
        System.out.printf("...decrypted: %d bytes%n", pt.length);

        assertArrayEquals(msg, pt, "RSA PKCS1v1.5 decrypt mismatch");
        logEnd();
    }
}
