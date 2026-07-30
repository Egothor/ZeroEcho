/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.alg.aes;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.ArrayList;
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
import zeroecho.core.KeyUsage;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.spec.VoidSpec;
import zeroecho.core.spi.ContextAware;
import zeroecho.core.util.RandomSupport;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;

class AesRandomSupportTest {
    private static final SecretKey KEY = new SecretKeySpec(new byte[16], "AES");

    @Test
    void allFactoriesUseSharedRandomSource() throws Exception {
        System.out.print("AesRandomSupport/allFactoriesUseSharedRandomSource...");
        AesAlgorithm algorithm = new AesAlgorithm();

        assertSharedRandom(algorithm.createContext(KeyUsage.ENCRYPT, KEY, AesSpec.gcm128(null)));
        assertSharedRandom(algorithm.createContext(KeyUsage.DECRYPT, KEY, AesSpec.gcm128(null)));
        assertSharedRandom(algorithm.createContext(KeyUsage.ENCRYPT, KEY, VoidSpec.INSTANCE));
        assertSharedRandom(algorithm.createContext(KeyUsage.DECRYPT, KEY, VoidSpec.INSTANCE));

        System.out.println("ok");
    }

    @Test
    void nullFallbackUsesSharedRandomSource() throws Exception {
        System.out.print("AesRandomSupport/nullFallbackUsesSharedRandomSource...");
        AesCipherContext context = new AesCipherContext(new AesAlgorithm(), KEY, true, AesSpec.gcm128(null), null);

        assertSharedRandom(context);

        System.out.println("ok");
    }

    @Test
    void keyGenerationUsesEstablishedRandomSourcePath() throws Exception {
        System.out.print("AesRandomSupport/keyGenerationUsesEstablishedRandomSourcePath...");
        AesAlgorithm algorithm = new AesAlgorithm();
        SecretKey generated = algorithm.symmetricKeyGenerator(AesKeyGenSpec.class)
                .generateSecret(AesKeyGenSpec.aes128());

        assertNotNull(generated);
        assertEquals("AES", generated.getAlgorithm());
        assertEquals(16, generated.getEncoded().length);
        System.out.println("...keyBytes=" + generated.getEncoded().length);
        System.out.println("ok");
    }

    @Test
    void controlledRandomProducesFreshIvForEachDirectContext() throws Exception {
        System.out.print("AesRandomSupport/controlledRandomProducesFreshIvForEachDirectContext...");
        CountingSecureRandom random = new CountingSecureRandom();
        AesAlgorithm algorithm = new AesAlgorithm();
        CtxInterface firstSession = Ctx.INSTANCE.getContext("aes-controlled-first");
        CtxInterface secondSession = Ctx.INSTANCE.getContext("aes-controlled-second");

        attachEmpty(new AesCipherContext(algorithm, KEY, true, AesSpec.gcm128(null), random), firstSession);
        attachEmpty(new AesCipherContext(algorithm, KEY, true, AesSpec.gcm128(null), random), secondSession);

        byte[] firstIv = firstSession.get(ConfluxKeys.iv("AES"));
        byte[] secondIv = secondSession.get(ConfluxKeys.iv("AES"));
        assertArrayEquals(repeated((byte) 1, 12), firstIv);
        assertArrayEquals(repeated((byte) 2, 12), secondIv);
        assertNotSame(firstIv, secondIv);
        System.out.println("...randomCalls=" + random.calls());
        System.out.println("ok");
    }

    @Test
    void encryptionIgnoresPreseededIvAndContextIsSingleUse() throws Exception {
        System.out.print("AesRandomSupport/encryptionIgnoresPreseededIvAndContextIsSingleUse...");
        CountingSecureRandom random = new CountingSecureRandom();
        CtxInterface session = Ctx.INSTANCE.getContext("aes-preseeded");
        session.put(ConfluxKeys.iv("AES"), repeated((byte) 9, 12));
        AesCipherContext context = new AesCipherContext(new AesAlgorithm(), KEY, true, AesSpec.gcm128(null), random);
        ((ContextAware) context).setContext(session);

        try (InputStream stream = context.attach(new ByteArrayInputStream(new byte[0]))) {
            stream.readAllBytes();
        }
        IOException failure = assertThrows(IOException.class,
                () -> context.attach(new ByteArrayInputStream(new byte[0])));

        assertArrayEquals(repeated((byte) 1, 12), session.get(ConfluxKeys.iv("AES")));
        assertEquals(1, random.calls());
        assertEquals("AES encryption context is single-use", failure.getMessage());
        System.out.println("...randomCalls=" + random.calls());
        System.out.println("ok");
    }

    @Test
    void streamFailureConsumesEncryptionContext() throws Exception {
        System.out.print("AesRandomSupport/streamFailureConsumesEncryptionContext...");
        CountingSecureRandom random = new CountingSecureRandom();
        AesCipherContext context = new AesCipherContext(new AesAlgorithm(), KEY, true, AesSpec.gcm128(null), random);
        ((ContextAware) context).setContext(Ctx.INSTANCE.getContext("aes-stream-failure"));

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

        assertEquals("AES encryption context is single-use", reuse.getMessage());
        assertEquals(1, random.calls());
        System.out.println("...terminalAfterFailure=true");
        System.out.println("ok");
    }

    @Test
    void concurrentEncryptionClaimHasExactlyOneWinner() throws Exception {
        System.out.print("AesRandomSupport/concurrentEncryptionClaimHasExactlyOneWinner...");
        CountingSecureRandom random = new CountingSecureRandom();
        AesCipherContext context = new AesCipherContext(new AesAlgorithm(), KEY, true, AesSpec.gcm128(null), random);
        ((ContextAware) context).setContext(Ctx.INSTANCE.getContext("aes-concurrent-claim"));
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Callable<Boolean> attempt = () -> {
                ready.countDown();
                start.await();
                try (InputStream stream = context.attach(new ByteArrayInputStream(new byte[0]))) {
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
            assertEquals(1, random.calls());

            CountingSecureRandom independentRandom = new CountingSecureRandom();
            AesCipherContext left = encryptingContext(independentRandom, "aes-independent-left");
            AesCipherContext right = encryptingContext(independentRandom, "aes-independent-right");
            Future<byte[]> leftResult = executor.submit(() -> encryptEmpty(left));
            Future<byte[]> rightResult = executor.submit(() -> encryptEmpty(right));
            leftResult.get();
            rightResult.get();
            assertEquals(2, independentRandom.calls());
        } finally {
            executor.close();
        }
        System.out.println("...winnerCount=1");
        System.out.println("...independentRandomCalls=2");
        System.out.println("ok");
    }

    @Test
    void publicBuilderExposesOnlyDecryptionIvConfiguration() throws Exception {
        System.out.print("AesRandomSupport/publicBuilderExposesOnlyDecryptionIvConfiguration...");
        List<String> methodNames = Arrays.stream(AesDataContentBuilder.class.getMethods()).map(Method::getName).toList();

        assertFalse(methodNames.contains("withIv"));
        assertTrue(methodNames.contains("withDecryptionIv"));
        AesDataContentBuilder builder = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession())
                .withDecryptionIv(repeated((byte) 1, 12));
        IllegalStateException failure = assertThrows(IllegalStateException.class, () -> builder.build(true));
        assertEquals("A caller-supplied IV is valid only for AES decryption", failure.getMessage());
        System.out.println("...encryptionIvSetter=false");
        System.out.println("ok");
    }

    @Test
    void concurrentFactoryConstructionUsesEstablishedSharedSource() throws Exception {
        System.out.print("AesRandomSupport/concurrentFactoryConstructionUsesEstablishedSharedSource...");
        AesAlgorithm algorithm = new AesAlgorithm();
        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Callable<SecureRandom>> tasks = new ArrayList<>();
            for (int index = 0; index < 64; index++) {
                tasks.add(() -> randomOf(algorithm.createContext(KeyUsage.ENCRYPT, KEY, AesSpec.gcm128(null))));
            }
            for (java.util.concurrent.Future<SecureRandom> result : executor.invokeAll(tasks)) {
                assertSame(RandomSupport.getRandom(), result.get());
            }
        } finally {
            executor.close();
        }

        System.out.println("ok");
    }

    private static void assertSharedRandom(EncryptionContext context) throws Exception {
        assertSame(RandomSupport.getRandom(), randomOf(context));
    }

    private static SecureRandom randomOf(Object context) throws Exception {
        Field field = AesCipherContext.class.getDeclaredField("rnd");
        field.setAccessible(true);
        return (SecureRandom) field.get(context);
    }

    private static void attachEmpty(AesCipherContext context, CtxInterface session) throws Exception {
        ((ContextAware) context).setContext(session);
        try (java.io.InputStream stream = context.attach(new ByteArrayInputStream(new byte[0]))) {
            stream.readAllBytes();
        }
    }

    private static AesCipherContext encryptingContext(SecureRandom random, String contextName) {
        AesCipherContext context = new AesCipherContext(new AesAlgorithm(), KEY, true, AesSpec.gcm128(null), random);
        ((ContextAware) context).setContext(Ctx.INSTANCE.getContext(contextName));
        return context;
    }

    private static byte[] encryptEmpty(AesCipherContext context) throws IOException {
        try (InputStream stream = context.attach(new ByteArrayInputStream(new byte[0]))) {
            return stream.readAllBytes();
        }
    }

    private static byte[] repeated(byte value, int length) {
        byte[] result = new byte[length];
        java.util.Arrays.fill(result, value);
        return result;
    }

    private static final class CountingSecureRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;
        private final AtomicInteger calls = new AtomicInteger();

        @Override
        public void nextBytes(byte[] bytes) {
            int current = calls.incrementAndGet();
            java.util.Arrays.fill(bytes, (byte) current);
        }

        private int calls() {
            return calls.get();
        }
    }
}
