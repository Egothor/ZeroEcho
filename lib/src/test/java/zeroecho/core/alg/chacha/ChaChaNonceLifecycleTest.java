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
package zeroecho.core.alg.chacha;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import conflux.Ctx;
import conflux.CtxInterface;
import zeroecho.core.ConfluxKeys;
import zeroecho.core.io.Util;
import zeroecho.core.spi.ContextAware;
import zeroecho.sdk.builders.alg.ChaChaDataContentBuilder;

class ChaChaNonceLifecycleTest {
    private static final String ALGORITHM_ID = "CHACHA20-POLY1305";
    private static final SecretKey KEY = new SecretKeySpec(new byte[32], "ChaCha20");
    private static final ChaCha20Poly1305Spec HEADER_SPEC = ChaCha20Poly1305Spec.builder()
            .header(new ChaCha20Poly1305HeaderCodec()).build();
    private static final ChaCha20Poly1305Spec CONTEXT_SPEC = ChaCha20Poly1305Spec.builder().header(null).build();

    @Test
    void encryptionIgnoresPreseededNonceAndContextIsSingleUse() throws Exception {
        System.out.print("ChaChaNonceLifecycle/encryptionIgnoresPreseededNonceAndContextIsSingleUse...");
        CountingSecureRandom random = new CountingSecureRandom();
        CtxInterface operation = Ctx.INSTANCE.getContext("chacha-preseeded");
        operation.put(ConfluxKeys.iv(ALGORITHM_ID), repeated((byte) 9, 12));
        ChaCha20Poly1305CipherContext context = encryptingContext(CONTEXT_SPEC, random, operation);

        try (InputStream stream = context.attach(new ByteArrayInputStream(new byte[0]))) {
            stream.readAllBytes();
        }
        IOException failure = assertThrows(IOException.class,
                () -> context.attach(new ByteArrayInputStream(new byte[0])));

        assertArrayEquals(repeated((byte) 1, 12), operation.get(ConfluxKeys.iv(ALGORITHM_ID)));
        assertEquals(1, random.calls());
        assertEquals("ChaCha20-Poly1305 encryption context is single-use", failure.getMessage());
        System.out.println("...randomCalls=" + random.calls());
        System.out.println("ok");
    }

    @Test
    void streamFailureConsumesEncryptionContext() throws Exception {
        System.out.print("ChaChaNonceLifecycle/streamFailureConsumesEncryptionContext...");
        CountingSecureRandom random = new CountingSecureRandom();
        ChaCha20Poly1305CipherContext context = encryptingContext(CONTEXT_SPEC, random,
                Ctx.INSTANCE.getContext("chacha-stream-failure"));
        InputStream failing = new InputStream() {
            @Override
            public int read() throws IOException {
                throw new IOException("controlled input failure");
            }
        };

        try (InputStream stream = context.attach(failing)) {
            assertThrows(IOException.class, stream::readAllBytes);
        }
        IOException reuse = assertThrows(IOException.class,
                () -> context.attach(new ByteArrayInputStream(new byte[0])));

        assertEquals("ChaCha20-Poly1305 encryption context is single-use", reuse.getMessage());
        assertEquals(1, random.calls());
        System.out.println("...terminalAfterFailure=true");
        System.out.println("ok");
    }

    @Test
    void concurrentClaimHasOneWinnerWhileSeparateContextsProceed() throws Exception {
        System.out.print("ChaChaNonceLifecycle/concurrentClaimHasOneWinnerWhileSeparateContextsProceed...");
        CountingSecureRandom sharedRandom = new CountingSecureRandom();
        ChaCha20Poly1305CipherContext shared = encryptingContext(CONTEXT_SPEC, sharedRandom,
                Ctx.INSTANCE.getContext("chacha-concurrent-shared"));
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(4);
        try {
            Callable<Boolean> attempt = () -> {
                ready.countDown();
                start.await();
                try (InputStream stream = shared.attach(new ByteArrayInputStream(new byte[0]))) {
                    stream.readAllBytes();
                    return true;
                } catch (IOException expected) {
                    return false;
                }
            };
            Future<Boolean> first = executor.submit(attempt);
            Future<Boolean> second = executor.submit(attempt);
            ready.await();
            start.countDown();
            assertTrue(first.get() ^ second.get());
            assertEquals(1, sharedRandom.calls());

            CountingSecureRandom independentRandom = new CountingSecureRandom();
            ChaCha20Poly1305CipherContext left = encryptingContext(CONTEXT_SPEC, independentRandom,
                    Ctx.INSTANCE.getContext("chacha-independent-left"));
            ChaCha20Poly1305CipherContext right = encryptingContext(CONTEXT_SPEC, independentRandom,
                    Ctx.INSTANCE.getContext("chacha-independent-right"));
            Future<byte[]> leftResult = executor.submit(() -> encryptEmpty(left));
            Future<byte[]> rightResult = executor.submit(() -> encryptEmpty(right));
            leftResult.get();
            rightResult.get();
            assertEquals(2, independentRandom.calls());
        } finally {
            executor.close();
        }
        System.out.println("...sharedWinners=1");
        System.out.println("...independentRandomCalls=2");
        System.out.println("ok");
    }

    @Test
    void encodedNonceDrivesDecryptionAndMalformedNonceFailsClosed() throws Exception {
        System.out.print("ChaChaNonceLifecycle/encodedNonceDrivesDecryptionAndMalformedNonceFailsClosed...");
        CountingSecureRandom random = new CountingSecureRandom();
        CtxInterface encryptionOperation = Ctx.INSTANCE.getContext("chacha-header-encrypt");
        byte[] plaintext = "nonce lifecycle".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] ciphertext;
        try (InputStream stream = encryptingContext(HEADER_SPEC, random, encryptionOperation)
                .attach(new ByteArrayInputStream(plaintext))) {
            ciphertext = stream.readAllBytes();
        }

        assertArrayEquals(repeated((byte) 1, 12), Util.read(new ByteArrayInputStream(ciphertext), 12));
        assertArrayEquals(plaintext, decryptHeader(ciphertext));

        byte[] modified = ciphertext.clone();
        modified[1] ^= 1;
        assertThrows(IOException.class, () -> decryptHeader(modified));
        assertThrows(IOException.class, () -> decryptHeader(Arrays.copyOf(ciphertext, 11)));
        assertEquals(1, random.calls());
        System.out.println("...roundTrip=true");
        System.out.println("...malformedRejected=true");
        System.out.println("ok");
    }

    @Test
    void publicBuilderExposesOnlyDecryptionNonceConfiguration() {
        System.out.print("ChaChaNonceLifecycle/publicBuilderExposesOnlyDecryptionNonceConfiguration...");
        List<String> methodNames = Arrays.stream(ChaChaDataContentBuilder.class.getMethods()).map(Method::getName)
                .toList();

        assertFalse(methodNames.contains("withNonce"));
        assertTrue(methodNames.contains("withDecryptionNonce"));
        ChaChaDataContentBuilder builder = ChaChaDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession())
                .withDecryptionNonce(repeated((byte) 1, 12));
        IllegalStateException failure = assertThrows(IllegalStateException.class, () -> builder.build(true));
        assertEquals("A caller-supplied nonce is valid only for ChaCha decryption", failure.getMessage());
        System.out.println("...encryptionNonceSetter=false");
        System.out.println("ok");
    }

    private static ChaCha20Poly1305CipherContext encryptingContext(ChaCha20Poly1305Spec spec, SecureRandom random,
            CtxInterface operation) {
        ChaCha20Poly1305CipherContext context = new ChaCha20Poly1305CipherContext(new ChaCha20Poly1305Algorithm(), KEY,
                true, spec, random);
        ((ContextAware) context).setContext(operation);
        return context;
    }

    private static byte[] encryptEmpty(ChaCha20Poly1305CipherContext context) throws IOException {
        try (InputStream stream = context.attach(new ByteArrayInputStream(new byte[0]))) {
            return stream.readAllBytes();
        }
    }

    private static byte[] decryptHeader(byte[] ciphertext) throws Exception {
        ChaCha20Poly1305CipherContext context = new ChaCha20Poly1305CipherContext(new ChaCha20Poly1305Algorithm(), KEY,
                false, HEADER_SPEC, null);
        ((ContextAware) context).setContext(Ctx.INSTANCE.getContext("chacha-header-decrypt-" + System.nanoTime()));
        try (InputStream stream = context.attach(new ByteArrayInputStream(ciphertext))) {
            return stream.readAllBytes();
        }
    }

    private static byte[] repeated(byte value, int length) {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
    }

    private static final class CountingSecureRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;
        private final AtomicInteger calls = new AtomicInteger();

        @Override
        public void nextBytes(byte[] bytes) {
            int current = calls.incrementAndGet();
            Arrays.fill(bytes, (byte) current);
        }

        private int calls() {
            return calls.get();
        }
    }
}
