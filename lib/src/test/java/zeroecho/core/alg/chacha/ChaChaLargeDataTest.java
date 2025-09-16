/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.core.alg.chacha;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
import zeroecho.core.ConfluxKeys;
import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.spi.ContextAware;

/**
 * Large-data round-trip tests for ChaCha20 and ChaCha20-Poly1305, mirroring the
 * style of AesLargeDataTest.
 */
public class ChaChaLargeDataTest {

    @BeforeAll
    static void setup() {
        // If you need external providers, add them here, e.g.:
        // Security.addProvider(new BouncyCastleProvider());
    }

    private static void logBegin(Object... params) {
        String thisClass = ChaChaLargeDataTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logBegin"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "(" + Arrays.deepToString(params) + ")");
    }

    private static void logEnd() {
        String thisClass = ChaChaLargeDataTest.class.getName();
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

    // ------------------------------------------------------------------------
    // ChaCha20 (stream)
    // ------------------------------------------------------------------------

    /** ChaCha20 round-trip using Ctx-only parameters (nonce shared via Ctx). */
    @Test
    void chacha20LargeData_ctxOnly() throws Exception {
        final int SIZE = 32 * 1024 + 777;
        logBegin(SIZE, "ChaCha20 (Ctx-only)");

        byte[] msg = randomBytes(SIZE);
        CryptoAlgorithm chacha = CryptoAlgorithms.require("CHACHA20");
        SecretKey key = chacha.symmetricKeyBuilder(ChaChaKeyGenSpec.class).generateSecret(ChaChaKeyGenSpec.chacha256());

        CtxInterface session = Ctx.INSTANCE.getContext("chacha-ctx-" + System.nanoTime());
        ChaChaSpec spec = ChaChaSpec.builder().initialCounter(1).header(null).build();

        EncryptionContext enc = CryptoAlgorithms.create("CHACHA20", KeyUsage.ENCRYPT, key, spec);
        ((ContextAware) enc).setContext(session);
        byte[] ct = readAll(enc.attach(new ByteArrayInputStream(msg)));
        enc.close();

        EncryptionContext dec = CryptoAlgorithms.create("CHACHA20", KeyUsage.DECRYPT, key, spec);
        ((ContextAware) dec).setContext(session);
        byte[] pt = readAll(dec.attach(new ByteArrayInputStream(ct)));
        dec.close();

        assertArrayEquals(msg, pt, "ChaCha20 (Ctx-only) mismatch");
        logEnd();
    }

    /** ChaCha20 round-trip using an in-band header (nonce + counter in header). */
    @Test
    void chacha20LargeData_headerCodec() throws Exception {
        final int SIZE = 32 * 1024 + 777;
        logBegin(SIZE, "ChaCha20 (HeaderCodec)");

        byte[] msg = randomBytes(SIZE);
        CryptoAlgorithm chacha = CryptoAlgorithms.require("CHACHA20");
        SecretKey key = chacha.symmetricKeyBuilder(ChaChaKeyGenSpec.class).generateSecret(ChaChaKeyGenSpec.chacha256());

        CtxInterface session = Ctx.INSTANCE.getContext("chacha-hdr-" + System.nanoTime());
        ChaChaSpec spec = ChaChaSpec.builder().initialCounter(1).header(new ChaChaHeaderCodec()).build();

        EncryptionContext enc = CryptoAlgorithms.create("CHACHA20", KeyUsage.ENCRYPT, key, spec);
        ((ContextAware) enc).setContext(session);
        byte[] ct = readAll(enc.attach(new ByteArrayInputStream(msg)));
        enc.close();

        EncryptionContext dec = CryptoAlgorithms.create("CHACHA20", KeyUsage.DECRYPT, key, spec);
        ((ContextAware) dec).setContext(session);
        byte[] pt = readAll(dec.attach(new ByteArrayInputStream(ct)));
        dec.close();

        assertArrayEquals(msg, pt, "ChaCha20 (HeaderCodec) mismatch");
        logEnd();
    }

    /**
     * ChaCha20: counter affects the keystream. - Encrypt with counter=7. - Decrypt
     * with the same counter → success. - Decrypt with a different counter →
     * plaintext differs.
     */
    @Test
    void chacha20_counterMatters() throws Exception {
        final int SIZE = 16 * 1024 + 3;
        logBegin(SIZE, "ChaCha20 counter matters");

        byte[] msg = randomBytes(SIZE);
        CryptoAlgorithm chacha = CryptoAlgorithms.require("CHACHA20");
        SecretKey key = chacha.symmetricKeyBuilder(ChaChaKeyGenSpec.class).generateSecret(ChaChaKeyGenSpec.chacha256());

        // Encrypt with explicit counter=7 (in ctx), headerless (ctx-only).
        CtxInterface encCtx = Ctx.INSTANCE.getContext("chacha-ctr-enc-" + System.nanoTime());
        encCtx.put(ConfluxKeys.tagBits("CHACHA20"), 7);
        ChaChaSpec spec = ChaChaSpec.builder().initialCounter(1).header(null).build();

        EncryptionContext enc = CryptoAlgorithms.create("CHACHA20", KeyUsage.ENCRYPT, key, spec);
        ((ContextAware) enc).setContext(encCtx);
        byte[] ct = readAll(enc.attach(new ByteArrayInputStream(msg)));
        enc.close();

        // Grab the generated nonce from the enc ctx to feed decrypt ctxs
        byte[] nonce = encCtx.get(ConfluxKeys.iv("CHACHA20"));

        // Correct decryption (counter=7)
        CtxInterface decCtxOk = Ctx.INSTANCE.getContext("chacha-ctr-dec-ok-" + System.nanoTime());
        decCtxOk.put(ConfluxKeys.iv("CHACHA20"), nonce);
        decCtxOk.put(ConfluxKeys.tagBits("CHACHA20"), 7);

        EncryptionContext decOk = CryptoAlgorithms.create("CHACHA20", KeyUsage.DECRYPT, key, spec);
        ((ContextAware) decOk).setContext(decCtxOk);
        byte[] ptOk = readAll(decOk.attach(new ByteArrayInputStream(ct)));
        decOk.close();
        assertArrayEquals(msg, ptOk, "ChaCha20 decrypt with correct counter failed");

        // Wrong decryption (counter=8) → plaintext must differ
        CtxInterface decCtxBad = Ctx.INSTANCE.getContext("chacha-ctr-dec-bad-" + System.nanoTime());
        decCtxBad.put(ConfluxKeys.iv("CHACHA20"), nonce);
        decCtxBad.put(ConfluxKeys.tagBits("CHACHA20"), 8);

        EncryptionContext decBad = CryptoAlgorithms.create("CHACHA20", KeyUsage.DECRYPT, key, spec);
        ((ContextAware) decBad).setContext(decCtxBad);
        byte[] ptBad = readAll(decBad.attach(new ByteArrayInputStream(ct)));
        decBad.close();

        assertFalse(Arrays.equals(msg, ptBad), "ChaCha20 decrypt with wrong counter should not match");
        logEnd();
    }

    // ------------------------------------------------------------------------
    // ChaCha20-Poly1305 (AEAD)
    // ------------------------------------------------------------------------

    /** AEAD round-trip using Ctx-only parameters (nonce + AAD in Ctx). */
    @Test
    void chacha20Poly1305LargeData_ctxOnly_withAad() throws Exception {
        final int SIZE = 32 * 1024 + 777;
        logBegin(SIZE, "ChaCha20-Poly1305 (Ctx-only + AAD)");

        byte[] msg = randomBytes(SIZE);
        byte[] aad = "associated-data-ctx-only".getBytes();

        CryptoAlgorithm aead = CryptoAlgorithms.require("CHACHA20-POLY1305");
        SecretKey key = aead.symmetricKeyBuilder(ChaChaKeyGenSpec.class).generateSecret(ChaChaKeyGenSpec.chacha256());

        CtxInterface session = Ctx.INSTANCE.getContext("chacha-aead-ctx-" + System.nanoTime());
        session.put(ConfluxKeys.aad("CHACHA20-POLY1305"), aad);

        ChaCha20Poly1305Spec spec = ChaCha20Poly1305Spec.builder().header(null).build();

        EncryptionContext enc = CryptoAlgorithms.create("CHACHA20-POLY1305", KeyUsage.ENCRYPT, key, spec);
        ((ContextAware) enc).setContext(session);
        byte[] ct = readAll(enc.attach(new ByteArrayInputStream(msg)));
        enc.close();

        EncryptionContext dec = CryptoAlgorithms.create("CHACHA20-POLY1305", KeyUsage.DECRYPT, key, spec);
        ((ContextAware) dec).setContext(session);
        byte[] pt = readAll(dec.attach(new ByteArrayInputStream(ct)));
        dec.close();

        assertArrayEquals(msg, pt, "ChaCha20-Poly1305 (Ctx-only + AAD) mismatch");
        logEnd();
    }

    /** AEAD round-trip with in-band header; header validates AAD hash. */
    @Test
    void chacha20Poly1305LargeData_headerCodec_withAad() throws Exception {
        final int SIZE = 32 * 1024 + 777;
        logBegin(SIZE, "ChaCha20-Poly1305 (HeaderCodec + AAD)");

        byte[] msg = randomBytes(SIZE);
        byte[] aad = "associated-data-header".getBytes();

        CryptoAlgorithm aead = CryptoAlgorithms.require("CHACHA20-POLY1305");
        SecretKey key = aead.symmetricKeyBuilder(ChaChaKeyGenSpec.class).generateSecret(ChaChaKeyGenSpec.chacha256());

        CtxInterface session = Ctx.INSTANCE.getContext("chacha-aead-hdr-" + System.nanoTime());
        session.put(ConfluxKeys.aad("CHACHA20-POLY1305"), aad);

        ChaCha20Poly1305Spec spec = ChaCha20Poly1305Spec.builder().header(new ChaCha20Poly1305HeaderCodec()).build();

        EncryptionContext enc = CryptoAlgorithms.create("CHACHA20-POLY1305", KeyUsage.ENCRYPT, key, spec);
        ((ContextAware) enc).setContext(session);
        byte[] ct = readAll(enc.attach(new ByteArrayInputStream(msg)));
        enc.close();

        EncryptionContext dec = CryptoAlgorithms.create("CHACHA20-POLY1305", KeyUsage.DECRYPT, key, spec);
        ((ContextAware) dec).setContext(session);
        byte[] pt = readAll(dec.attach(new ByteArrayInputStream(ct)));
        dec.close();

        assertArrayEquals(msg, pt, "ChaCha20-Poly1305 (HeaderCodec + AAD) mismatch");
        logEnd();
    }

    /**
     * AEAD: AAD mismatch must fail verification (expect an IOException from
     * doFinal).
     */
    @Test
    void chacha20Poly1305_aadMismatchFails() throws Exception {
        final int SIZE = 8 * 1024 + 9;
        logBegin(SIZE, "ChaCha20-Poly1305 AAD mismatch");

        byte[] msg = randomBytes(SIZE);
        byte[] aadEnc = "aad-enc".getBytes();
        byte[] aadDec = "aad-dec-different".getBytes();

        CryptoAlgorithm aead = CryptoAlgorithms.require("CHACHA20-POLY1305");
        SecretKey key = aead.symmetricKeyBuilder(ChaChaKeyGenSpec.class).generateSecret(ChaChaKeyGenSpec.chacha256());

        // Encrypt with AAD = aadEnc (ctx-only, no header)
        CtxInterface encCtx = Ctx.INSTANCE.getContext("chacha-aead-enc-" + System.nanoTime());
        encCtx.put(ConfluxKeys.aad("CHACHA20-POLY1305"), aadEnc);

        ChaCha20Poly1305Spec spec = ChaCha20Poly1305Spec.builder().header(null).build();

        EncryptionContext enc = CryptoAlgorithms.create("CHACHA20-POLY1305", KeyUsage.ENCRYPT, key, spec);
        ((ContextAware) enc).setContext(encCtx);
        byte[] ct = readAll(enc.attach(new ByteArrayInputStream(msg)));
        enc.close();

        // Decrypt with different AAD → should fail during doFinal()
        CtxInterface decCtx = Ctx.INSTANCE.getContext("chacha-aead-dec-" + System.nanoTime());
        decCtx.put(ConfluxKeys.aad("CHACHA20-POLY1305"), aadDec);
        // copy the nonce from encCtx
        byte[] nonce = encCtx.get(ConfluxKeys.iv("CHACHA20-POLY1305"));
        decCtx.put(ConfluxKeys.iv("CHACHA20-POLY1305"), nonce);

        EncryptionContext dec = CryptoAlgorithms.create("CHACHA20-POLY1305", KeyUsage.DECRYPT, key, spec);
        ((ContextAware) dec).setContext(decCtx);

        assertThrows(IOException.class, () -> {
            @SuppressWarnings("unused")
            byte[] ignored = readAll(dec.attach(new ByteArrayInputStream(ct)));
            dec.close();
        }, "ChaCha20-Poly1305 should fail with AAD mismatch");

        logEnd();
    }
}
