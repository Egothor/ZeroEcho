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
package zeroecho.core.alg.aes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.BadPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import conflux.Ctx;
import conflux.CtxInterface;
import zeroecho.core.ConfluxKeys;
import zeroecho.core.KeyUsage;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.spi.ContextAware;

class AesDecryptionSecurityTest {
    private static final SecretKey KEY = new SecretKeySpec(repeated((byte) 0x11, 16), "AES");
    private static final SecretKey WRONG_KEY = new SecretKeySpec(repeated((byte) 0x22, 16), "AES");
    private static final AtomicInteger CONTEXT_IDS = new AtomicInteger();

    @Test
    void gcmTamperMatrix() throws Exception {
        System.out.println("gcmTamperMatrix");
        byte[] plaintext = repeated((byte) 0x5a, 96);
        Encrypted encrypted = encrypt(AesSpec.gcm128(null), plaintext);

        FailureResult modifiedBody = failedDecryption(encrypted.spec, KEY, encrypted.iv,
                changed(encrypted.ciphertext, 0));
        FailureResult modifiedTag = failedDecryption(encrypted.spec, KEY, encrypted.iv,
                changed(encrypted.ciphertext, encrypted.ciphertext.length - 1));
        FailureResult truncatedBody = failedDecryption(encrypted.spec, KEY, encrypted.iv,
                removed(encrypted.ciphertext, encrypted.ciphertext.length - 17));
        FailureResult truncatedTag = failedDecryption(encrypted.spec, KEY, encrypted.iv,
                Arrays.copyOf(encrypted.ciphertext, encrypted.ciphertext.length - 1));
        FailureResult trailing = failedDecryption(encrypted.spec, KEY, encrypted.iv,
                Arrays.copyOf(encrypted.ciphertext, encrypted.ciphertext.length + 1));
        FailureResult wrongKey = failedDecryption(encrypted.spec, WRONG_KEY, encrypted.iv, encrypted.ciphertext);
        FailureResult wrongIv = failedDecryption(encrypted.spec, KEY, changed(encrypted.iv, 0), encrypted.ciphertext);
        FailureResult empty = failedDecryption(encrypted.spec, KEY, encrypted.iv, new byte[0]);

        for (FailureResult result : List.of(modifiedBody, modifiedTag, truncatedBody, truncatedTag, trailing, wrongKey,
                wrongIv, empty)) {
            assertEquals(0, result.outputBytes());
            assertAuthenticationFailure(result.failure());
        }
        assertThrows(IOException.class, () -> decrypt(encrypted.spec, KEY,
                Arrays.copyOf(encrypted.iv, encrypted.iv.length - 1), encrypted.ciphertext));
        assertThrows(IOException.class, () -> decrypt(encrypted.spec, KEY, null, encrypted.ciphertext));
        System.out.println("...cases=10");
        System.out.println("gcmTamperMatrix...ok");
    }

    @Test
    void ctrTamperMatrix() throws Exception {
        System.out.println("ctrTamperMatrix");
        byte[] plaintext = repeated((byte) 0x33, 64);
        Encrypted encrypted = encrypt(AesSpec.ctr(null), plaintext);

        byte[] wrongIv = decrypt(encrypted.spec, KEY, changed(encrypted.iv, 0), encrypted.ciphertext);
        byte[] wrongKey = decrypt(encrypted.spec, WRONG_KEY, encrypted.iv, encrypted.ciphertext);
        byte[] modified = decrypt(encrypted.spec, KEY, encrypted.iv, changed(encrypted.ciphertext, 0));
        byte[] truncated = decrypt(encrypted.spec, KEY, encrypted.iv,
                Arrays.copyOf(encrypted.ciphertext, encrypted.ciphertext.length - 1));
        byte[] trailing = decrypt(encrypted.spec, KEY, encrypted.iv,
                Arrays.copyOf(encrypted.ciphertext, encrypted.ciphertext.length + 1));

        assertFalse(Arrays.equals(plaintext, wrongIv));
        assertFalse(Arrays.equals(plaintext, wrongKey));
        assertFalse(Arrays.equals(plaintext, modified));
        assertEquals(plaintext.length - 1, truncated.length);
        assertEquals(plaintext.length + 1, trailing.length);
        assertThrows(IOException.class, () -> decrypt(encrypted.spec, KEY,
                Arrays.copyOf(encrypted.iv, encrypted.iv.length - 1), encrypted.ciphertext));
        assertThrows(IOException.class, () -> decrypt(encrypted.spec, KEY, null, encrypted.ciphertext));
        System.out.println("...cases=7");
        System.out.println("ctrTamperMatrix...ok");
    }

    @Test
    void cbcNoPaddingMatrix() throws Exception {
        System.out.println("cbcNoPaddingMatrix");
        AesSpec spec = AesSpec.builder().mode(AesSpec.Mode.CBC).padding(AesSpec.Padding.NOPADDING).build();
        byte[] plaintext = repeated((byte) 0x44, 32);
        Encrypted encrypted = encrypt(spec, plaintext);

        assertFalse(Arrays.equals(plaintext, decrypt(spec, KEY, changed(encrypted.iv, 0), encrypted.ciphertext)));
        assertFalse(Arrays.equals(plaintext, decrypt(spec, WRONG_KEY, encrypted.iv, encrypted.ciphertext)));
        assertFalse(Arrays.equals(plaintext, decrypt(spec, KEY, encrypted.iv, changed(encrypted.ciphertext, 0))));
        assertThrows(IOException.class, () -> decrypt(spec, KEY, encrypted.iv,
                Arrays.copyOf(encrypted.ciphertext, encrypted.ciphertext.length - 1)));
        assertThrows(IOException.class, () -> decrypt(spec, KEY, encrypted.iv,
                Arrays.copyOf(encrypted.ciphertext, encrypted.ciphertext.length + 1)));
        assertThrows(IOException.class,
                () -> decrypt(spec, KEY, Arrays.copyOf(encrypted.iv, encrypted.iv.length - 1), encrypted.ciphertext));
        assertThrows(IOException.class, () -> decrypt(spec, KEY, null, encrypted.ciphertext));
        System.out.println("...cases=7");
        System.out.println("cbcNoPaddingMatrix...ok");
    }

    @Test
    void cbcPkcsPaddingMatrix() throws Exception {
        System.out.println("cbcPkcsPaddingMatrix");
        AesSpec spec = AesSpec.cbcPkcs7(null);
        Encrypted encrypted = encrypt(spec, repeated((byte) 0x66, 31));

        assertThrows(IOException.class, () -> decrypt(spec, KEY, encrypted.iv,
                Arrays.copyOf(encrypted.ciphertext, encrypted.ciphertext.length - 1)));
        // CBC is malleable: flipping this bit changes the final 0x01 padding byte to
        // 0x00 deterministically. The assertion covers padding rejection, not
        // authentication.
        assertThrows(IOException.class, () -> decrypt(spec, KEY, encrypted.iv,
                changed(encrypted.ciphertext, encrypted.ciphertext.length - 17)));
        assertThrows(IOException.class,
                () -> decrypt(spec, KEY, Arrays.copyOf(encrypted.iv, encrypted.iv.length - 1), encrypted.ciphertext));
        assertThrows(IOException.class, () -> decrypt(spec, KEY, null, encrypted.ciphertext));
        System.out.println("...cases=4");
        System.out.println("cbcPkcsPaddingMatrix...ok");
    }

    private static Encrypted encrypt(AesSpec spec, byte[] plaintext) throws Exception {
        CtxInterface context = newContext("aes-security-enc-");
        EncryptionContext encryption = new zeroecho.sdk.ZeroEchoSession().createContext("AES", KeyUsage.ENCRYPT, KEY,
                spec);
        ((ContextAware) encryption).setContext(context);
        byte[] ciphertext;
        try (InputStream stream = encryption.attach(new ByteArrayInputStream(plaintext))) {
            ciphertext = stream.readAllBytes();
        } finally {
            encryption.close();
        }
        return new Encrypted(spec, context.get(ConfluxKeys.iv("AES")).clone(), ciphertext);
    }

    private static byte[] decrypt(AesSpec spec, SecretKey key, byte[] iv, byte[] ciphertext) throws Exception {
        CtxInterface context = newContext("aes-security-dec-");
        if (iv != null) {
            context.put(ConfluxKeys.iv("AES"), iv);
        }
        EncryptionContext decryption = new zeroecho.sdk.ZeroEchoSession().createContext("AES", KeyUsage.DECRYPT, key,
                spec);
        ((ContextAware) decryption).setContext(context);
        try (InputStream stream = decryption.attach(new ByteArrayInputStream(ciphertext))) {
            return stream.readAllBytes();
        } finally {
            decryption.close();
        }
    }

    private static FailureResult failedDecryption(AesSpec spec, SecretKey key, byte[] iv, byte[] ciphertext)
            throws Exception {
        CtxInterface context = newContext("aes-security-fail-");
        context.put(ConfluxKeys.iv("AES"), iv);
        EncryptionContext decryption = new zeroecho.sdk.ZeroEchoSession().createContext("AES", KeyUsage.DECRYPT, key,
                spec);
        ((ContextAware) decryption).setContext(context);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (InputStream stream = decryption.attach(new ByteArrayInputStream(ciphertext))) {
            byte[] buffer = new byte[17];
            IOException failure = assertThrows(IOException.class, () -> {
                int count;
                while ((count = stream.read(buffer)) >= 0) {
                    if (count > 0) {
                        output.write(buffer, 0, count);
                    }
                }
            });
            return new FailureResult(output.size(), failure);
        } finally {
            decryption.close();
        }
    }

    private static void assertAuthenticationFailure(IOException failure) {
        assertTrue(hasCause(failure, BadPaddingException.class),
                "GCM failure must retain an authentication-related provider cause");
    }

    private static boolean hasCause(Throwable failure, Class<? extends Throwable> expectedType) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (expectedType.isInstance(cause)) {
                return true;
            }
        }
        return false;
    }

    private static CtxInterface newContext(String prefix) {
        return Ctx.INSTANCE.getContext(prefix + CONTEXT_IDS.incrementAndGet());
    }

    private static byte[] changed(byte[] input, int index) {
        byte[] result = input.clone();
        result[index] ^= 0x01;
        return result;
    }

    private static byte[] removed(byte[] input, int index) {
        byte[] result = new byte[input.length - 1];
        System.arraycopy(input, 0, result, 0, index);
        System.arraycopy(input, index + 1, result, index, input.length - index - 1);
        return result;
    }

    private static byte[] repeated(byte value, int length) {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
    }

    private record Encrypted(AesSpec spec, byte[] iv, byte[] ciphertext) {
    }

    private record FailureResult(int outputBytes, IOException failure) {
    }
}
