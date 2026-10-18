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
package zeroecho.core.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Destroyable;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyOperation;
import zeroecho.core.KeyOperationInfo;
import zeroecho.core.KeyUsage;
import zeroecho.core.context.AgreementContext;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.context.KemContext;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.io.TailStrippingInputStream;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spi.AsymmetricKeyPairGenerator;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * Executes every approved persistent importer through the encrypted store and
 * then proves that the reconstructed key remains operational.
 */
class KeyringAlgorithmCoverageTest {
    private static final byte[] MESSAGE = "keyring-algorithm-matrix".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    @TempDir
    Path temporaryDirectory;

    @BeforeAll
    static void initializeProviders() {
        BouncyCastleActivator.init();
    }

    @Test
    void persistentImporterUniverseHasAcceptedCardinality() {
        List<KeyringImportRegistry.PersistentMapping> mappings = KeyringImportRegistry.mappings();
        assertEquals(22, count(mappings, KeyringStore.Kind.PUBLIC_KEY));
        assertEquals(22, count(mappings, KeyringStore.Kind.PRIVATE_KEY));
        assertEquals(6, count(mappings, KeyringStore.Kind.SECRET_KEY));
    }

    @Test
    void publicApiRequiresUnlockMaterialAndExposesNoPlaintextStorePath() {
        List<Method> publicMethods = Arrays.stream(KeyringStore.class.getDeclaredMethods())
                .filter(method -> Modifier.isPublic(method.getModifiers())).toList();
        publicMethods.stream().filter(method -> "create".equals(method.getName()) || "open".equals(method.getName()))
                .forEach(method -> {
                    assertTrue(Arrays.asList(method.getParameterTypes()).contains(KeyringPassword.class));
                    assertTrue(Arrays.stream(method.getParameterTypes()).noneMatch(String.class::equals));
                });
        assertTrue(publicMethods.stream().noneMatch(method -> switch (method.getName()) {
            case "exportText", "importText", "save", "load" -> true;
            default -> false;
        }));
        assertTrue(Arrays.stream(KeyringStore.class.getFields()).noneMatch(field -> field.getType() == byte[].class));
    }

    @TestFactory
    Stream<DynamicTest> asymmetricEncryptedStoreRoundTrips() {
        List<String> algorithms = KeyringImportRegistry.mappings().stream()
                .filter(mapping -> mapping.kind() == KeyringStore.Kind.PUBLIC_KEY)
                .map(KeyringImportRegistry.PersistentMapping::algorithmId).toList();
        return algorithms.stream().map(algorithmId -> DynamicTest
                .dynamicTest(algorithmId + " PUBLIC/X.509 + PRIVATE/PKCS#8", () -> roundTripAsymmetric(algorithmId)));
    }

    @TestFactory
    Stream<DynamicTest> secretEncryptedStoreRoundTrips() {
        return KeyringImportRegistry.mappings().stream()
                .filter(mapping -> mapping.kind() == KeyringStore.Kind.SECRET_KEY)
                .map(mapping -> DynamicTest.dynamicTest(secretDisplayName(mapping), () -> roundTripSecret(mapping)));
    }

    private void roundTripAsymmetric(String algorithmId) throws Exception {
        KeyPair original = generatePair(algorithmId);
        Path path = temporaryDirectory.resolve("asymmetric-" + safeName(algorithmId) + ".zek");
        try (KeyringPassword password = password(); KeyringStore store = KeyringStore.create(path, password)) {
            store.putPublic("matrix", algorithmId, original.getPublic());
            store.putPrivate("matrix", algorithmId, original.getPrivate());
        }

        PublicKey reconstructedPublic = null;
        PrivateKey reconstructedPrivate = null;
        byte[] originalPublic = null;
        byte[] reconstructedPublicBytes = null;
        try (KeyringPassword password = password(); KeyringStore store = KeyringStore.open(path, password)) {
            KeyringStore.PublicWithId publicWithId = store.getPublicWithId("matrix");
            KeyringStore.PrivateWithId privateWithId = store.getPrivateWithId("matrix");
            assertEquals(algorithmId, publicWithId.algorithm());
            assertEquals(algorithmId, privateWithId.algorithm());
            reconstructedPublic = publicWithId.key();
            reconstructedPrivate = privateWithId.key();
            originalPublic = original.getPublic().getEncoded();
            reconstructedPublicBytes = reconstructedPublic.getEncoded();
            assertArrayEquals(originalPublic, reconstructedPublicBytes);
            proveAsymmetricOperation(algorithmId, reconstructedPublic, reconstructedPrivate);
        } finally {
            wipe(originalPublic);
            wipe(reconstructedPublicBytes);
            destroy(reconstructedPublic);
            destroy(reconstructedPrivate);
            destroy(original.getPublic());
            destroy(original.getPrivate());
        }
    }

    private void roundTripSecret(KeyringImportRegistry.PersistentMapping mapping) throws Exception {
        byte[] material = new byte[32];
        Arrays.fill(material, secretFill(mapping));
        String jcaName = secretJcaName(mapping);
        SecretKey original = new SecretKeySpec(material, jcaName);
        Path path = temporaryDirectory.resolve("secret-" + safeName(secretDisplayName(mapping)) + ".zek");
        SecretKey reconstructed = null;
        byte[] reconstructedBytes = null;
        try {
            try (KeyringPassword password = password(); KeyringStore store = KeyringStore.create(path, password)) {
                store.putSecret("matrix", mapping.algorithmId(), original);
            }
            try (KeyringPassword password = password(); KeyringStore store = KeyringStore.open(path, password)) {
                KeyringStore.SecretWithId withId = store.getSecretWithId("matrix");
                assertEquals(mapping.algorithmId(), withId.algorithm());
                reconstructed = withId.key();
                reconstructedBytes = reconstructed.getEncoded();
                assertEquals(material.length, reconstructedBytes.length);
                assertArrayEquals(material, reconstructedBytes);
                proveSecretOperation(mapping, reconstructed);
            }
        } finally {
            wipe(material);
            wipe(reconstructedBytes);
            destroy(reconstructed);
            destroy(original);
        }
    }

    private static void proveAsymmetricOperation(String algorithmId, PublicKey publicKey, PrivateKey privateKey)
            throws Exception {
        CryptoAlgorithm algorithm = CryptoAlgorithms.require(algorithmId);
        if (algorithm.roles().contains(KeyUsage.SIGN) && algorithm.roles().contains(KeyUsage.VERIFY)) {
            proveSignature(algorithmId, publicKey, privateKey);
        } else if (algorithmId.equals("LMS") || algorithmId.equals("XMSS")) {
            ZeroEchoSession session = new ZeroEchoSession();
            byte[] before = privateKey.getEncoded();
            org.junit.jupiter.api.Assertions.assertThrows(zeroecho.core.err.UnsupportedRoleException.class,
                    () -> session.createContext(algorithmId, KeyUsage.SIGN, privateKey));
            assertArrayEquals(before, privateKey.getEncoded());
            java.security.Signature provider = java.security.Signature.getInstance(algorithmId, "BCPQC");
            provider.initSign(privateKey);
            provider.update(MESSAGE);
            byte[] signature = provider.sign();
            try (SignatureContext verifier = session.createContext(algorithmId, KeyUsage.VERIFY, publicKey)) {
                verifier.setExpectedTag(signature);
                try (InputStream stream = verifier.wrap(new ByteArrayInputStream(MESSAGE))) {
                    assertArrayEquals(MESSAGE, stream.readAllBytes());
                }
            }
        } else if (algorithm.roles().contains(KeyUsage.ENCAPSULATE)
                && algorithm.roles().contains(KeyUsage.DECAPSULATE)) {
            proveKem(algorithmId, publicKey, privateKey);
        } else if (algorithm.roles().contains(KeyUsage.AGREEMENT)) {
            proveAgreement(algorithmId, publicKey, privateKey);
        } else {
            assertTrue(algorithm.roles().contains(KeyUsage.ENCRYPT) && algorithm.roles().contains(KeyUsage.DECRYPT));
            proveEncryption(algorithmId, publicKey, privateKey);
        }
    }

    private static void proveSignature(String algorithmId, PublicKey publicKey, PrivateKey privateKey)
            throws Exception {
        ZeroEchoSession session = new ZeroEchoSession();
        AtomicReference<byte[]> signatureHolder = new AtomicReference<>();
        byte[] signature = null;
        try (SignatureContext signer = session.createContext(algorithmId, KeyUsage.SIGN, privateKey);
                InputStream signed = new TailStrippingInputStream(signer.wrap(new ByteArrayInputStream(MESSAGE)),
                        signer.tagLength(), 512) {
                    @Override
                    protected void processTail(byte[] tail) {
                        signatureHolder.set(tail == null ? null : tail.clone());
                    }
                }) {
            assertArrayEquals(MESSAGE, signed.readAllBytes());
            signature = signatureHolder.get();
        }
        try {
            assertTrue(signature != null && signature.length > 0);
            try (SignatureContext verifier = session.createContext(algorithmId, KeyUsage.VERIFY, publicKey);
                    InputStream verified = verificationStream(verifier, signature)) {
                assertArrayEquals(MESSAGE, verified.readAllBytes());
            }
        } finally {
            wipe(signature);
        }
    }

    private static InputStream verificationStream(SignatureContext verifier, byte[] signature) throws IOException {
        verifier.setVerificationApproach(verifier.getVerificationCore().getThrowOnMismatch());
        verifier.setExpectedTag(signature);
        return verifier.wrap(new ByteArrayInputStream(MESSAGE));
    }

    private static void proveKem(String algorithmId, PublicKey publicKey, PrivateKey privateKey) throws Exception {
        ZeroEchoSession session = new ZeroEchoSession();
        byte[] encapsulated = null;
        byte[] senderSecret = null;
        byte[] recipientSecret = null;
        try (KemContext sender = session.createContext(algorithmId, KeyUsage.ENCAPSULATE, publicKey);
                KemContext recipient = session.createContext(algorithmId, KeyUsage.DECAPSULATE, privateKey)) {
            KemContext.KemResult result = sender.encapsulate();
            encapsulated = result.ciphertext();
            senderSecret = result.sharedSecret();
            recipientSecret = recipient.decapsulate(encapsulated);
            assertArrayEquals(senderSecret, recipientSecret);
        } finally {
            wipe(encapsulated);
            wipe(senderSecret);
            wipe(recipientSecret);
        }
    }

    private static void proveAgreement(String algorithmId, PublicKey publicKey, PrivateKey privateKey)
            throws Exception {
        KeyPair peer = generatePair(algorithmId);
        ZeroEchoSession session = new ZeroEchoSession();
        byte[] firstSecret = null;
        byte[] secondSecret = null;
        try (AgreementContext first = session.createContext(algorithmId, KeyUsage.AGREEMENT, privateKey);
                AgreementContext second = session.createContext(algorithmId, KeyUsage.AGREEMENT, peer.getPrivate())) {
            first.setPeerPublic(peer.getPublic());
            second.setPeerPublic(publicKey);
            firstSecret = first.deriveSecret();
            secondSecret = second.deriveSecret();
            assertArrayEquals(firstSecret, secondSecret);
        } finally {
            wipe(firstSecret);
            wipe(secondSecret);
            destroy(peer.getPublic());
            destroy(peer.getPrivate());
        }
    }

    private static void proveEncryption(String algorithmId, Key encryptionKey, Key decryptionKey) throws Exception {
        ZeroEchoSession session = new ZeroEchoSession();
        conflux.CtxInterface operationContext = conflux.Ctx.INSTANCE.getContext("keyring-matrix-" + algorithmId);
        byte[] ciphertext = null;
        byte[] plaintext = null;
        try {
            try (EncryptionContext encryption = session.createContext(algorithmId, KeyUsage.ENCRYPT, encryptionKey)) {
                if (encryption instanceof zeroecho.core.spi.ContextAware contextAware) {
                    contextAware.setContext(operationContext);
                }
                try (InputStream encrypted = encryption.attach(new ByteArrayInputStream(MESSAGE))) {
                    ciphertext = encrypted.readAllBytes();
                }
            }
            try (EncryptionContext decryption = session.createContext(algorithmId, KeyUsage.DECRYPT, decryptionKey)) {
                if (decryption instanceof zeroecho.core.spi.ContextAware contextAware) {
                    contextAware.setContext(operationContext);
                }
                try (InputStream decrypted = decryption.attach(new ByteArrayInputStream(ciphertext))) {
                    plaintext = decrypted.readAllBytes();
                }
            }
            assertArrayEquals(MESSAGE, plaintext);
        } finally {
            wipe(ciphertext);
            wipe(plaintext);
        }
    }

    private static void proveSecretOperation(KeyringImportRegistry.PersistentMapping mapping, SecretKey key)
            throws Exception {
        if ("HMAC".equals(mapping.algorithmId())) {
            proveMac(key);
        } else {
            proveEncryption(mapping.algorithmId(), key, key);
        }
    }

    private static void proveMac(SecretKey key) throws Exception {
        byte[] first = null;
        byte[] second = null;
        try {
            Mac producer = Mac.getInstance(key.getAlgorithm());
            producer.init(key);
            first = producer.doFinal(MESSAGE);
            Mac verifier = Mac.getInstance(key.getAlgorithm());
            verifier.init(key);
            second = verifier.doFinal(MESSAGE);
            assertArrayEquals(first, second);
        } finally {
            wipe(first);
            wipe(second);
        }
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private static KeyPair generatePair(String algorithmId) throws Exception {
        CryptoAlgorithm algorithm = CryptoAlgorithms.require(algorithmId);
        KeyOperationInfo generation = algorithm.keyOperations().stream()
                .filter(info -> info.operation() == KeyOperation.ASYMMETRIC_KEY_PAIR_GENERATE)
                .filter(info -> info.defaultSpec() != null).findFirst()
                .orElseThrow(() -> new AssertionError("No default key-pair generation mapping for " + algorithmId));
        AsymmetricKeyPairGenerator generator = algorithm.asymmetricKeyPairGenerator(generation.specType());
        return generator.generateKeyPair(generation.defaultSpec());
    }

    private static long count(List<KeyringImportRegistry.PersistentMapping> mappings, KeyringStore.Kind kind) {
        return mappings.stream().filter(mapping -> mapping.kind() == kind).count();
    }

    private static String secretDisplayName(KeyringImportRegistry.PersistentMapping mapping) {
        return mapping.algorithmId() + "/" + mapping.hmacVariant().name() + " SECRET/RAW";
    }

    private static String secretJcaName(KeyringImportRegistry.PersistentMapping mapping) {
        return switch (mapping.algorithmId()) {
            case "AES" -> "AES";
            case "CHACHA20", "CHACHA20-POLY1305" -> "ChaCha20";
            case "HMAC" -> mapping.hmacVariant().jcaName();
            default -> throw new AssertionError("Unexpected secret mapping");
        };
    }

    private static byte secretFill(KeyringImportRegistry.PersistentMapping mapping) {
        return (byte) (mapping.hmacVariant().code() + mapping.algorithmId().length() + 1);
    }

    private static String safeName(String value) {
        return value.replaceAll("[^A-Za-z0-9]", "_");
    }

    private static KeyringPassword password() {
        char[] value = "keyring-matrix-password".toCharArray();
        try {
            return new KeyringPassword(value);
        } finally {
            Arrays.fill(value, '\0');
        }
    }

    private static void destroy(Key key) {
        if (key instanceof Destroyable destroyable) {
            try {
                destroyable.destroy();
            } catch (Exception exception) {
                // Provider keys may advertise but not implement destruction.
            }
        }
    }

    private static void wipe(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
