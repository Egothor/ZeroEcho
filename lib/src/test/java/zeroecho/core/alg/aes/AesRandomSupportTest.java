/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.alg.aes;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Field;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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
import zeroecho.sdk.util.RandomSupport;

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
        System.out.println("...randomCalls=" + random.calls);
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

    private static byte[] repeated(byte value, int length) {
        byte[] result = new byte[length];
        java.util.Arrays.fill(result, value);
        return result;
    }

    private static final class CountingSecureRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;
        private int calls;

        @Override
        public void nextBytes(byte[] bytes) {
            calls++;
            java.util.Arrays.fill(bytes, (byte) calls);
        }
    }
}
