/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;

import org.junit.jupiter.api.Test;

import zeroecho.core.alg.aes.AesAlgorithm;
import zeroecho.core.alg.aes.AesKeyImportSpec;
import zeroecho.core.alg.chacha.ChaChaKeyImportSpec;
import zeroecho.core.alg.hmac.HmacKeyImportSpec;
import zeroecho.core.alg.mldsa.MldsaPrivateKeySpec;
import zeroecho.core.alg.rsa.RsaPrivateKeySpec;
import zeroecho.core.alg.slhdsa.SlhDsaPrivateKeySpec;
import zeroecho.core.alg.sphincsplus.SphincsPlusPrivateKeySpec;
import zeroecho.core.marshal.PairSeq;

class SecretSpecLifecycleTest {
    private static final List<SpecCase> SPECS = List.of(
            new SpecCase("zeroecho.core.alg.aes.AesKeyImportSpec", "key", 16, Factory.STATIC_RAW),
            new SpecCase("zeroecho.core.alg.bike.BikePrivateKeySpec", "pkcs8", 8, Factory.CONSTRUCTOR),
            new SpecCase("zeroecho.core.alg.chacha.ChaChaKeyImportSpec", "key", 32, Factory.STATIC_RAW),
            new SpecCase("zeroecho.core.alg.cmce.CmcePrivateKeySpec", "pkcs8", 8, Factory.CONSTRUCTOR),
            new SpecCase("zeroecho.core.alg.dh.DhPrivateKeySpec", "encoded", 8, Factory.CONSTRUCTOR),
            new SpecCase("zeroecho.core.alg.ecdsa.EcdsaPrivateKeySpec", "encoded", 8, Factory.CONSTRUCTOR),
            new SpecCase("zeroecho.core.alg.ed25519.Ed25519PrivateKeySpec", "encoded", 8, Factory.CONSTRUCTOR),
            new SpecCase("zeroecho.core.alg.ed448.Ed448PrivateKeySpec", "encoded", 8, Factory.CONSTRUCTOR),
            new SpecCase("zeroecho.core.alg.elgamal.ElgamalPrivateKeySpec", "encoded", 8, Factory.CONSTRUCTOR),
            new SpecCase("zeroecho.core.alg.frodo.FrodoPrivateKeySpec", "pkcs8", 8, Factory.CONSTRUCTOR),
            new SpecCase("zeroecho.core.alg.hmac.HmacKeyImportSpec", "key", 8, Factory.HMAC),
            new SpecCase("zeroecho.core.alg.hqc.HqcPrivateKeySpec", "pkcs8", 8, Factory.CONSTRUCTOR),
            new SpecCase("zeroecho.core.alg.kyber.KyberPrivateKeySpec", "pkcs8", 8, Factory.CONSTRUCTOR),
            new SpecCase("zeroecho.core.alg.mldsa.MldsaPrivateKeySpec", "encoded", 8, Factory.CONSTRUCTOR),
            new SpecCase("zeroecho.core.alg.ntru.NtruPrivateKeySpec", "pkcs8", 8, Factory.CONSTRUCTOR),
            new SpecCase("zeroecho.core.alg.ntruprime.NtrulPrimePrivateKeySpec", "pkcs8", 8, Factory.CONSTRUCTOR),
            new SpecCase("zeroecho.core.alg.ntruprime.SntruPrimePrivateKeySpec", "pkcs8", 8, Factory.CONSTRUCTOR),
            new SpecCase("zeroecho.core.alg.rsa.RsaPrivateKeySpec", "encoded", 8, Factory.CONSTRUCTOR),
            new SpecCase("zeroecho.core.alg.saber.SaberPrivateKeySpec", "pkcs8", 8, Factory.CONSTRUCTOR),
            new SpecCase("zeroecho.core.alg.slhdsa.SlhDsaPrivateKeySpec", "encoded", 8, Factory.CONSTRUCTOR),
            new SpecCase("zeroecho.core.alg.sphincsplus.SphincsPlusPrivateKeySpec", "encoded", 8, Factory.CONSTRUCTOR),
            new SpecCase("zeroecho.core.alg.xdh.XdhPrivateKeySpec", "encoded", 8, Factory.CONSTRUCTOR));

    @Test
    void allSecretSpecificationsOwnAndDestroyTheirByteArrays() throws Exception {
        System.out.print("SecretSpec/lifecycle...");
        for (SpecCase specCase : SPECS) {
            byte[] input = sequence(specCase.length());
            byte[] expected = input.clone();
            Object spec = specCase.create(input);
            Arrays.fill(input, (byte) 0);

            Method accessor = spec.getClass().getMethod(specCase.accessor());
            byte[] first = (byte[]) accessor.invoke(spec);
            assertArrayEquals(expected, first, specCase.className());
            first[0] ^= 0x7f;
            assertArrayEquals(expected, (byte[]) accessor.invoke(spec), specCase.className());

            Method marshal = spec.getClass().getMethod("marshal", spec.getClass());
            marshal.invoke(null, spec);
            Destroyable destroyable = assertInstanceOf(Destroyable.class, spec);
            assertFalse(destroyable.isDestroyed());
            destroyable.destroy();
            destroyable.destroy();
            assertTrue(destroyable.isDestroyed());
            assertAllSecretFieldsZero(spec);

            InvocationTargetException accessFailure = assertThrows(InvocationTargetException.class,
                    () -> accessor.invoke(spec), specCase.className());
            assertInstanceOf(IllegalStateException.class, accessFailure.getCause());
            InvocationTargetException marshalFailure = assertThrows(InvocationTargetException.class,
                    () -> marshal.invoke(null, spec), specCase.className());
            assertInstanceOf(IllegalStateException.class, marshalFailure.getCause());
        }
        System.out.println("ok");
    }

    @Test
    void validatesNullAndBoundaryKeyMaterial() {
        System.out.print("SecretSpec/boundaries...");
        assertThrows(NullPointerException.class, () -> AesKeyImportSpec.fromRaw(null));
        assertThrows(IllegalArgumentException.class, () -> AesKeyImportSpec.fromRaw(new byte[0]));
        assertThrows(NullPointerException.class, () -> new HmacKeyImportSpec("HmacSHA256", null));
        assertThrows(NullPointerException.class, () -> new RsaPrivateKeySpec(null));

        HmacKeyImportSpec emptyHmac = new HmacKeyImportSpec("HmacSHA256", new byte[0]);
        RsaPrivateKeySpec emptyRsa = new RsaPrivateKeySpec(new byte[0]);
        assertArrayEquals(new byte[0], emptyHmac.key());
        assertArrayEquals(new byte[0], emptyRsa.encoded());
        emptyHmac.destroy();
        emptyRsa.destroy();
        System.out.println("ok");
    }

    @Test
    void unmarshalCleansUpWhenMalformedDataFollowsValidSecretMaterial() {
        System.out.println("unmarshalCleansUpWhenMalformedDataFollowsValidSecretMaterial");
        String aesKey = Base64.getEncoder().encodeToString(sequence(16));
        String chachaKey = Base64.getEncoder().encodeToString(sequence(32));
        String encodedPrivateKey = Base64.getEncoder().encodeToString(sequence(8));

        assertThrows(IllegalArgumentException.class,
                () -> AesKeyImportSpec.unmarshal(PairSeq.of("k.b64", aesKey, "k.b64", "%")));
        assertThrows(IllegalArgumentException.class,
                () -> ChaChaKeyImportSpec.unmarshal(PairSeq.of("k.b64", chachaKey, "k.b64", "%")));
        assertThrows(IllegalArgumentException.class, () -> HmacKeyImportSpec
                .unmarshal(PairSeq.of("mac", "HmacSHA256", "k.b64", encodedPrivateKey, "k.b64", "%")));
        assertThrows(IllegalArgumentException.class,
                () -> MldsaPrivateKeySpec.unmarshal(PairSeq.of("pkcs8.b64", encodedPrivateKey, "pkcs8.b64", "%")));
        assertThrows(IllegalArgumentException.class,
                () -> SlhDsaPrivateKeySpec.unmarshal(PairSeq.of("pkcs8.b64", encodedPrivateKey, "pkcs8.b64", "%")));
        assertThrows(IllegalArgumentException.class, () -> SphincsPlusPrivateKeySpec
                .unmarshal(PairSeq.of("pkcs8.b64", encodedPrivateKey, "pkcs8.b64", "%")));
        System.out.println("...cases=6");
        System.out.println("unmarshalCleansUpWhenMalformedDataFollowsValidSecretMaterial...ok");
    }

    @Test
    void accessAndDestroyAreLinearizable() throws Exception {
        System.out.print("SecretSpec/concurrent...");
        byte[] expected = sequence(16);
        AesKeyImportSpec spec = AesKeyImportSpec.fromRaw(expected);
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < 32; i++) {
                futures.add(executor.submit(() -> {
                    start.await();
                    try {
                        assertArrayEquals(expected, spec.key());
                    } catch (IllegalStateException destroyed) {
                        assertTrue(spec.isDestroyed());
                    }
                    return null;
                }));
            }
            futures.add(executor.submit(() -> {
                start.await();
                spec.destroy();
                return null;
            }));
            start.countDown();
            for (Future<?> future : futures) {
                future.get();
            }
        } finally {
            executor.shutdownNow();
        }
        assertTrue(spec.isDestroyed());
        assertThrows(IllegalStateException.class, spec::key);
        System.out.println("ok");
    }

    @Test
    void importersDoNotDestroyCallerOwnedSpecifications() throws Exception {
        System.out.print("SecretSpec/import...");
        byte[] aesBytes = sequence(16);
        AesKeyImportSpec aesSpec = AesKeyImportSpec.fromRaw(aesBytes);
        AesAlgorithm aes = new AesAlgorithm();
        SecretKey secretKey = aes.symmetricKeyImporter(AesKeyImportSpec.class).importSecret(aesSpec);
        assertArrayEquals(aesBytes, secretKey.getEncoded());
        assertFalse(aesSpec.isDestroyed());
        assertArrayEquals(aesBytes, aesSpec.key());

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        RsaPrivateKeySpec rsaSpec = new RsaPrivateKeySpec(pair.getPrivate().getEncoded());
        PrivateKey imported = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().importPrivate("RSA",
                rsaSpec);
        assertArrayEquals(pair.getPrivate().getEncoded(), imported.getEncoded());
        assertFalse(rsaSpec.isDestroyed());
        assertArrayEquals(pair.getPrivate().getEncoded(), rsaSpec.encoded());
        System.out.println("ok");
    }

    private static byte[] sequence(int length) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) (i + 1);
        }
        return bytes;
    }

    private static void assertAllSecretFieldsZero(Object spec) throws IllegalAccessException {
        for (Field field : spec.getClass().getDeclaredFields()) {
            if (field.getType() == byte[].class) {
                field.setAccessible(true);
                byte[] bytes = (byte[]) field.get(spec);
                assertTrue(Arrays.equals(new byte[bytes.length], bytes), spec.getClass().getName());
            }
        }
    }

    private enum Factory {
        CONSTRUCTOR, STATIC_RAW, HMAC
    }

    private record SpecCase(String className, String accessor, int length, Factory factory) {
        private Object create(byte[] input) throws ReflectiveOperationException {
            Class<?> type = Class.forName(className);
            if (factory == Factory.STATIC_RAW) {
                Method method = type.getMethod("fromRaw", byte[].class);
                return method.invoke(null, (Object) input);
            }
            if (factory == Factory.HMAC) {
                Constructor<?> constructor = type.getConstructor(String.class, byte[].class);
                return constructor.newInstance("HmacSHA256", input);
            }
            Constructor<?> constructor = type.getConstructor(byte[].class);
            return constructor.newInstance((Object) input);
        }
    }
}
