package zeroecho.core.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KeyringStoreTest {
    private static final char[] PASSWORD = new char[] { 'c', 'o', 'r', 'r', 'e', 'c', 't' };

    @TempDir
    Path temporaryDirectory;

    @Test
    void encryptedRoundTripAndPlaintextAbsence() throws Exception {
        start("encryptedRoundTripAndPlaintextAbsence");
        Path path = temporaryDirectory.resolve("keys.zek");
        byte[] aesBytes = new byte[32];
        Arrays.fill(aesBytes, (byte) 0x5a);
        SecretKey aes = new SecretKeySpec(aesBytes, "AES");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();

        try (KeyringPassword password = password();
                KeyringStore store = KeyringStore.create(path, password,
                        KeyringProtection.standard(), deterministicRandom())) {
            store.putPublic("rsa", "RSA", pair.getPublic());
            store.putPrivate("rsa", "RSA", pair.getPrivate());
            store.putSecret("aes", "AES", aes);
            assertArrayEquals(aesBytes, store.getSecret("aes").getEncoded());
            assertArrayEquals(pair.getPublic().getEncoded(), store.getPublic("rsa").getEncoded());
            assertArrayEquals(pair.getPrivate().getEncoded(), store.getPrivate("rsa").getEncoded());
        }
        byte[] persisted = Files.readAllBytes(path);
        try {
            assertFalse(indexOf(persisted, aesBytes) >= 0);
            assertFalse(new String(persisted, StandardCharsets.ISO_8859_1).contains("java."));
            System.out.println("...encrypted-bytes=" + persisted.length);
        } finally {
            Arrays.fill(persisted, (byte) 0);
            Arrays.fill(aesBytes, (byte) 0);
        }
        ok();
    }

    @Test
    void wrongPasswordAndCorruptionFailUniformly() throws Exception {
        start("wrongPasswordAndCorruptionFailUniformly");
        Path path = temporaryDirectory.resolve("wrong.zek");
        try (KeyringPassword password = password();
                KeyringStore ignored = KeyringStore.create(path, password)) {
            // empty current-format store
        }
        try (KeyringPassword wrong = new KeyringPassword(new char[] { 'w', 'r', 'o', 'n', 'g' })) {
            KeyringException exception = assertThrows(KeyringException.class,
                    () -> KeyringStore.open(path, wrong));
            assertEquals(KeyringException.Code.KEYRING_UNLOCK_FAILED, exception.code());
        }
        byte[] bytes = Files.readAllBytes(path);
        bytes[bytes.length - 1] ^= 1;
        Files.write(path, bytes);
        Arrays.fill(bytes, (byte) 0);
        try (KeyringPassword password = password()) {
            KeyringException exception = assertThrows(KeyringException.class,
                    () -> KeyringStore.open(path, password));
            assertEquals(KeyringException.Code.KEYRING_FORMAT_INVALID, exception.code());
        }
        ok();
    }

    @Test
    void plaintextV1AndDuplicateOwnerAreRejected() throws Exception {
        start("plaintextV1AndDuplicateOwnerAreRejected");
        Path old = temporaryDirectory.resolve("old.txt");
        Files.writeString(old, "# KeyringStore v1\n", StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(old, java.util.Set.of(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
        try (KeyringPassword password = password()) {
            assertEquals(KeyringException.Code.KEYRING_FORMAT_INVALID,
                    assertThrows(KeyringException.class,
                            () -> KeyringStore.open(old, password)).code());
        }

        Path path = temporaryDirectory.resolve("owned.zek");
        try (KeyringPassword password = password();
                KeyringStore first = KeyringStore.create(path, password);
                KeyringPassword secondPassword = password()) {
            assertEquals(KeyringException.Code.KEYRING_ALREADY_OPEN,
                    assertThrows(KeyringException.class,
                            () -> KeyringStore.open(path, secondPassword)).code());
            assertTrue(first.aliases().isEmpty());
        }
        try (KeyringPassword password = password();
                KeyringStore reopened = KeyringStore.open(path, password)) {
            assertTrue(reopened.aliases().isEmpty());
        }
        ok();
    }

    @Test
    void closeIsRepeatSafeAndRejectsUse() throws Exception {
        start("closeIsRepeatSafeAndRejectsUse");
        Path path = temporaryDirectory.resolve("closed.zek");
        KeyringStore store;
        try (KeyringPassword password = password()) {
            store = KeyringStore.create(path, password);
        }
        store.close();
        store.close();
        assertTrue(store.isDestroyed());
        assertThrows(IllegalStateException.class, store::aliases);
        ok();
    }

    @Test
    void trailingDataAndNonExportableKeysAreRejected() throws Exception {
        start("trailingDataAndNonExportableKeysAreRejected");
        Path path = temporaryDirectory.resolve("strict.zek");
        try (KeyringPassword password = password();
                KeyringStore store = KeyringStore.create(path, password)) {
            SecretKey nonExportable = new SecretKey() {
                private static final long serialVersionUID = 1L;

                @Override
                public String getAlgorithm() {
                    return "AES";
                }

                @Override
                public String getFormat() {
                    return "RAW";
                }

                @Override
                public byte[] getEncoded() {
                    return null;
                }
            };
            KeyringException exception = assertThrows(KeyringException.class,
                    () -> store.putSecret("opaque", "AES", nonExportable));
            assertEquals(KeyringException.Code.KEYRING_NON_EXPORTABLE_KEY, exception.code());
            assertTrue(store.aliases().isEmpty());
        }

        Files.write(path, new byte[] { 1 }, java.nio.file.StandardOpenOption.APPEND);
        try (KeyringPassword password = password()) {
            KeyringException exception = assertThrows(KeyringException.class,
                    () -> KeyringStore.open(path, password));
            assertEquals(KeyringException.Code.KEYRING_FORMAT_INVALID, exception.code());
        }
        ok();
    }

    @Test
    void hmacVariantsAreClosedAndRejectedBeforeMutation() throws Exception {
        start("hmacVariantsAreClosedAndRejectedBeforeMutation");
        Path path = temporaryDirectory.resolve("hmac.zek");
        List<String> accepted = List.of("HmacSHA256", "HmacSHA384", "HmacSHA512");
        try (KeyringPassword password = password();
                KeyringStore store = KeyringStore.create(path, password,
                        KeyringProtection.standard(), deterministicRandom())) {
            for (String variant : accepted) {
                byte[] material = new byte[64];
                Arrays.fill(material, (byte) variant.length());
                try {
                    String alias = variant + ".key";
                    store.putSecret(alias, "HMAC", new SecretKeySpec(material, variant));
                    assertArrayEquals(material, store.getSecret(alias).getEncoded());
                } finally {
                    Arrays.fill(material, (byte) 0);
                }
            }
            byte[] before = Files.readAllBytes(path);
            try {
                for (String rejected : List.of("HmacMD5", "HmacSHA1", "HmacSHA224",
                        "hmacsha256", "HmacSha384", " HmacSHA512", "HmacSHA512 ",
                        "BC:HmacSHA256", "", "X".repeat(4097))) {
                    SecretKey key = controlledSecret(rejected, new byte[32]);
                    KeyringException exception = assertThrows(KeyringException.class,
                            () -> store.putSecret("rejected", "HMAC", key));
                    assertEquals(KeyringException.Code.KEYRING_IMPORT_METADATA_INVALID,
                            exception.code());
                    assertEquals(KeyringException.Code.KEYRING_IMPORT_METADATA_INVALID.name(),
                            exception.getMessage());
                    assertArrayEquals(before, Files.readAllBytes(path));
                    assertFalse(store.contains("rejected"));
                }
                SecretKey mismatched = controlledSecret("HmacSHA256", new byte[32]);
                assertEquals(KeyringException.Code.KEYRING_KEY_NOT_CANONICALIZABLE,
                        assertThrows(KeyringException.class,
                                () -> store.putSecret("wrong", "AES", mismatched)).code());
                assertArrayEquals(before, Files.readAllBytes(path));
            } finally {
                Arrays.fill(before, (byte) 0);
            }
        }
        ok();
    }

    @Test
    void providerDraftAndUnknownHmacVariantAreRejectedStructurally() throws Exception {
        start("providerDraftAndUnknownHmacVariantAreRejectedStructurally");
        assertEquals(KeyringException.Code.KEYRING_IMPORT_METADATA_INVALID,
                assertThrows(KeyringException.class,
                        () -> KeyringImportRegistry.HmacVariant.fromCode(99)).code());
        byte[] staleDraft = staleProviderEntryPlaintext();
        try {
            java.lang.reflect.Method decoder = KeyringStore.class.getDeclaredMethod(
                    "decodeEntryPlaintext", byte[].class);
            decoder.setAccessible(true);
            java.lang.reflect.InvocationTargetException failure =
                    assertThrows(java.lang.reflect.InvocationTargetException.class,
                            () -> decoder.invoke(null, (Object) staleDraft));
            assertTrue(failure.getCause() instanceof KeyringException);
            assertEquals(KeyringException.Code.KEYRING_FORMAT_INVALID,
                    ((KeyringException) failure.getCause()).code());
        } finally {
            Arrays.fill(staleDraft, (byte) 0);
        }
        ok();
    }

    @Test
    void providerBoundOrNoncanonicalKeysFailBeforeMutation() throws Exception {
        start("providerBoundOrNoncanonicalKeysFailBeforeMutation");
        Path path = temporaryDirectory.resolve("provider-bound.zek");
        try (KeyringPassword password = password();
                KeyringStore store = KeyringStore.create(path, password)) {
            byte[] before = Files.readAllBytes(path);
            try {
                SecretKey unsupported = controlledSecret("ProviderAES", new byte[32]);
                KeyringException failure = assertThrows(KeyringException.class,
                        () -> store.putSecret("bad", "AES", unsupported));
                assertEquals(KeyringException.Code.KEYRING_KEY_NOT_CANONICALIZABLE,
                        failure.code());
                assertArrayEquals(before, Files.readAllBytes(path));
                assertFalse(store.contains("bad"));
            } finally {
                Arrays.fill(before, (byte) 0);
            }
        }
        ok();
    }

    private static KeyringPassword password() {
        return new KeyringPassword(PASSWORD);
    }

    private static KeyringRandomBytes deterministicRandom() {
        AtomicInteger value = new AtomicInteger(1);
        return destination -> {
            int base = value.getAndIncrement();
            for (int index = 0; index < destination.length; index++) {
                destination[index] = (byte) (base + index);
            }
        };
    }

    private static SecretKey controlledSecret(String algorithm, byte[] encoded) {
        return new SecretKey() {
            private static final long serialVersionUID = 1L;

            @Override
            public String getAlgorithm() {
                return algorithm;
            }

            @Override
            public String getFormat() {
                return "RAW";
            }

            @Override
            public byte[] getEncoded() {
                return encoded.clone();
            }
        };
    }

    private static byte[] staleProviderEntryPlaintext() throws Exception {
        java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
        try (java.io.DataOutputStream out = new java.io.DataOutputStream(bytes)) {
            out.writeInt(2);
            writeString(out, "legacy.pub");
            writeString(out, "ML-DSA");
            out.writeByte(KeyringStore.Kind.PUBLIC_KEY.ordinal() + 1);
            out.writeByte(KeyringStore.Encoding.X509.ordinal() + 1);
            writeString(out, "BC");
            out.writeInt(3);
            out.write(new byte[] { 1, 2, 3 });
        }
        return bytes.toByteArray();
    }

    private static void writeString(java.io.DataOutputStream out, String value)
            throws java.io.IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        try {
            out.writeInt(bytes.length);
            out.write(bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int index = 0; index <= haystack.length - needle.length; index++) {
            for (int offset = 0; offset < needle.length; offset++) {
                if (haystack[index + offset] != needle[offset]) {
                    continue outer;
                }
            }
            return index;
        }
        return -1;
    }

    private static void start(String method) {
        System.out.println(method);
    }

    private static void ok() {
        System.out.println("...ok");
    }
}
