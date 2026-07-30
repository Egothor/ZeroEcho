package zeroecho.core.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KeyringNonceReservationTest {
    private static final int MAGIC_BYTES = 8;
    private static final int VERSION_OFFSET = MAGIC_BYTES;
    private static final int HIGH_WATER_OFFSET = MAGIC_BYTES + Integer.BYTES + KeyringStore.UUID_BYTES + Integer.BYTES;
    private static final int TAG_BYTES = 32;
    private static final int CURRENT_SIDECAR_VERSION = 2;
    private static final char[] PASSWORD = { 'n', 'o', 'n', 'c', 'e' };

    @TempDir
    Path temporaryDirectory;

    @Test
    void hkdfUsesFixedRfc5869Contract() throws Exception {
        start("hkdfUsesFixedRfc5869Contract");
        byte[] masterKey = new byte[32];
        byte[] storeId = new byte[16];
        for (int index = 0; index < masterKey.length; index++) {
            masterKey[index] = (byte) index;
        }
        for (int index = 0; index < storeId.length; index++) {
            storeId[index] = (byte) (0xa0 + index);
        }
        byte[] expected = HexFormat.of().parseHex("54e0e054749745a3ef5e2cc5a5c16bafed6f39df9daa4ff412bac74d56bd27b9");
        byte[] first = null;
        byte[] second = null;
        byte[] changedMaster = null;
        byte[] changedStore = null;
        try {
            first = KeyringNonceReservationKdf.derive(masterKey, storeId);
            second = KeyringNonceReservationKdf.derive(masterKey, storeId);
            assertArrayEquals(expected, first);
            assertArrayEquals(first, second);
            assertEquals(32, first.length);
            assertFalse(MessageDigest.isEqual(masterKey, first));

            masterKey[0] ^= 1;
            changedMaster = KeyringNonceReservationKdf.derive(masterKey, storeId);
            assertFalse(MessageDigest.isEqual(first, changedMaster));
            masterKey[0] ^= 1;

            storeId[0] ^= 1;
            changedStore = KeyringNonceReservationKdf.derive(masterKey, storeId);
            assertFalse(MessageDigest.isEqual(first, changedStore));
        } finally {
            wipe(masterKey);
            wipe(storeId);
            wipe(expected);
            wipe(first);
            wipe(second);
            wipe(changedMaster);
            wipe(changedStore);
        }
        ok();
    }

    @Test
    void currentSidecarSurvivesRestartAndDerivedKeyIsCleared() throws Exception {
        start("currentSidecarSurvivesRestartAndDerivedKeyIsCleared");
        Path path = temporaryDirectory.resolve("current.zek");
        byte[] retainedMacKey;
        byte[] macKeyCopy;
        try (KeyringPassword password = password()) {
            KeyringStore store = KeyringStore.create(path, password, KeyringProtection.standard(),
                    deterministicRandom());
            retainedMacKey = field(store, "nonceReservationMacKey");
            macKeyCopy = retainedMacKey.clone();
            assertEquals(CURRENT_SIDECAR_VERSION,
                    ByteBuffer.wrap(Files.readAllBytes(sidecar(path)), VERSION_OFFSET, Integer.BYTES).getInt());
            store.close();
            store.close();
            assertTrue(allZero(retainedMacKey));
        }
        byte[] main = Files.readAllBytes(path);
        byte[] reservation = Files.readAllBytes(sidecar(path));
        try {
            assertFalse(indexOf(main, macKeyCopy) >= 0);
            assertFalse(indexOf(reservation, macKeyCopy) >= 0);
        } finally {
            wipe(main);
            wipe(reservation);
            wipe(macKeyCopy);
        }
        try (KeyringPassword password = password(); KeyringStore reopened = KeyringStore.open(path, password)) {
            assertTrue(reopened.aliases().isEmpty());
        }
        ok();
    }

    @Test
    void directMasterKeyMacAndSidecarTamperingFailClosed() throws Exception {
        start("directMasterKeyMacAndSidecarTamperingFailClosed");
        assertRejected(sidecarWithDirectMasterKeyMac("direct-master.zek"));
        assertRejected(sidecarWithBitFlippedTag("tag-bit.zek"));
        assertRejected(sidecarWithTamperedHighWater("high-water.zek"));
        assertRejected(sidecarWithVersion("old-version.zek", 1, true));
        assertRejected(sidecarWithVersion("future-version.zek", 3, false));
        assertRejected(sidecarTruncated("truncated.zek"));
        assertRejected(sidecarWithTrailingByte("trailing.zek"));
        ok();
    }

    @Test
    void sidecarCannotBeCopiedAcrossStores() throws Exception {
        start("sidecarCannotBeCopiedAcrossStores");
        Path first = createAndClose("first.zek", 1);
        Path second = createAndClose("second.zek", 101);
        byte[] copied = Files.readAllBytes(sidecar(first));
        try {
            Files.write(sidecar(second), copied);
        } finally {
            wipe(copied);
        }
        assertOpenRejectedWithoutMutation(second);
        ok();
    }

    @Test
    void restartAndAbandonedReservationAdvanceMonotonically() throws Exception {
        start("restartAndAbandonedReservationAdvanceMonotonically");
        Path path = temporaryDirectory.resolve("abandoned.zek");
        Path saved = temporaryDirectory.resolve("abandoned.saved");
        byte[] material = new byte[32];
        Arrays.fill(material, (byte) 0x4a);
        try {
            try (KeyringPassword password = password();
                    KeyringStore store = KeyringStore.create(path, password, KeyringProtection.standard(),
                            deterministicRandom())) {
                assertEquals(1L, longField(store, "nonceHighWater"));
                Files.move(path, saved);
                Files.createDirectory(path);
                assertThrows(IOException.class,
                        () -> store.putSecret("failed", "AES", new SecretKeySpec(material, "AES")));
                assertEquals(3L, sidecarHighWater(sidecar(path)));
                assertEquals(3L, longField(store, "nonceHighWater"));
                Files.delete(path);
                Files.move(saved, path);
            }

            try (KeyringPassword password = password();
                    KeyringStore reopened = KeyringStore.open(path, password, KeyringProtection.standard(),
                            deterministicRandom(51))) {
                assertEquals(3L, longField(reopened, "nonceHighWater"));
                assertTrue(reopened.aliases().isEmpty());
                reopened.putSecret("accepted", "AES", new SecretKeySpec(material, "AES"));
                assertEquals(5L, longField(reopened, "nonceHighWater"));
                assertEquals(5L, sidecarHighWater(sidecar(path)));
            }
            try (KeyringPassword password = password(); KeyringStore reopened = KeyringStore.open(path, password)) {
                assertEquals(5L, longField(reopened, "nonceHighWater"));
                assertArrayEquals(material, reopened.getSecret("accepted").getEncoded());
            }
        } finally {
            wipe(material);
        }
        ok();
    }

    @Test
    void failedSidecarReservationDoesNotAdvanceOrEncrypt() throws Exception {
        start("failedSidecarReservationDoesNotAdvanceOrEncrypt");
        Path path = temporaryDirectory.resolve("sidecar-write-failure.zek");
        Path reservation = sidecar(path);
        Path saved = temporaryDirectory.resolve("sidecar.saved");
        byte[] material = new byte[32];
        Arrays.fill(material, (byte) 0x35);
        RecordingRandom random = new RecordingRandom(1);
        try (KeyringPassword password = password();
                KeyringStore store = KeyringStore.create(path, password, KeyringProtection.standard(), random)) {
            byte[] mainBefore = Files.readAllBytes(path);
            try {
                assertEquals(List.of(32, 32, 16, 11, 3), random.requests());
                Files.move(reservation, saved);
                Files.createDirectory(reservation);
                assertThrows(IOException.class,
                        () -> store.putSecret("failed", "AES", new SecretKeySpec(material, "AES")));
                assertEquals(1L, longField(store, "nonceHighWater"));
                assertArrayEquals(mainBefore, Files.readAllBytes(path));
                assertEquals(List.of(32, 32, 16, 11, 3, 16), random.requests());

                Files.delete(reservation);
                Files.move(saved, reservation);
                store.putSecret("accepted", "AES", new SecretKeySpec(material, "AES"));
                assertEquals(3L, longField(store, "nonceHighWater"));
                assertEquals(List.of(32, 32, 16, 11, 3, 16, 16), random.requests());
            } finally {
                wipe(mainBefore);
            }
        } finally {
            wipe(material);
        }
        ok();
    }

    @Test
    void nonceAllocationUsesOneDurableCounterPerEncryption() throws Exception {
        start("nonceAllocationUsesOneDurableCounterPerEncryption");
        Path path = temporaryDirectory.resolve("allocation.zek");
        byte[] first = new byte[32];
        byte[] second = new byte[32];
        Arrays.fill(first, (byte) 0x11);
        Arrays.fill(second, (byte) 0x22);
        RecordingRandom random = new RecordingRandom(7);
        try (KeyringPassword password = password();
                KeyringStore store = KeyringStore.create(path, password, KeyringProtection.standard(), random)) {
            assertEquals(1L, longField(store, "nonceHighWater"));
            assertEquals(List.of(32, 32, 16, 11, 3), random.requests());
            store.putSecret("one", "AES", new SecretKeySpec(first, "AES"));
            assertEquals(3L, longField(store, "nonceHighWater"));
            store.putSecret("two", "AES", new SecretKeySpec(second, "AES"));
            assertEquals(5L, longField(store, "nonceHighWater"));
            store.putSecret("one", "AES", new SecretKeySpec(second, "AES"));
            assertEquals(7L, longField(store, "nonceHighWater"));
            assertEquals(List.of(32, 32, 16, 11, 3, 16, 16, 16), random.requests());
            assertEquals(7L, sidecarHighWater(sidecar(path)));
        } finally {
            wipe(first);
            wipe(second);
        }
        ok();
    }

    private Path sidecarWithDirectMasterKeyMac(String file) throws Exception {
        Path path = temporaryDirectory.resolve(file);
        byte[] image;
        byte[] master;
        try (KeyringPassword password = password()) {
            KeyringStore store = KeyringStore.create(path, password, KeyringProtection.standard(),
                    deterministicRandom());
            image = Files.readAllBytes(sidecar(path));
            master = field(store, "masterKey").clone();
            store.close();
        }
        byte[] tag = null;
        try {
            tag = hmac(master, authenticated(image));
            replaceTag(image, tag);
            Files.write(sidecar(path), image);
            return path;
        } finally {
            wipe(image);
            wipe(master);
            wipe(tag);
        }
    }

    private Path sidecarWithBitFlippedTag(String file) throws Exception {
        Path path = createAndClose(file);
        byte[] image = Files.readAllBytes(sidecar(path));
        try {
            image[image.length - 1] ^= 1;
            Files.write(sidecar(path), image);
            return path;
        } finally {
            wipe(image);
        }
    }

    private Path sidecarWithTamperedHighWater(String file) throws Exception {
        Path path = createAndClose(file);
        byte[] image = Files.readAllBytes(sidecar(path));
        try {
            image[HIGH_WATER_OFFSET + Long.BYTES - 1] ^= 1;
            Files.write(sidecar(path), image);
            return path;
        } finally {
            wipe(image);
        }
    }

    private Path sidecarWithVersion(String file, int version, boolean useMasterKey) throws Exception {
        Path path = temporaryDirectory.resolve(file);
        byte[] image;
        byte[] key;
        try (KeyringPassword password = password()) {
            KeyringStore store = KeyringStore.create(path, password, KeyringProtection.standard(),
                    deterministicRandom());
            image = Files.readAllBytes(sidecar(path));
            key = field(store, useMasterKey ? "masterKey" : "nonceReservationMacKey").clone();
            store.close();
        }
        byte[] tag = null;
        try {
            ByteBuffer.wrap(image, VERSION_OFFSET, Integer.BYTES).putInt(version);
            tag = hmac(key, authenticated(image));
            replaceTag(image, tag);
            Files.write(sidecar(path), image);
            return path;
        } finally {
            wipe(image);
            wipe(key);
            wipe(tag);
        }
    }

    private Path sidecarTruncated(String file) throws Exception {
        Path path = createAndClose(file);
        byte[] image = Files.readAllBytes(sidecar(path));
        try {
            Files.write(sidecar(path), Arrays.copyOf(image, image.length - 1));
            return path;
        } finally {
            wipe(image);
        }
    }

    private Path sidecarWithTrailingByte(String file) throws Exception {
        Path path = createAndClose(file);
        Files.write(sidecar(path), new byte[] { 0 }, java.nio.file.StandardOpenOption.APPEND);
        return path;
    }

    private void assertRejected(Path path) throws Exception {
        assertOpenRejectedWithoutMutation(path);
    }

    private void assertOpenRejectedWithoutMutation(Path path) throws Exception {
        byte[] mainBefore = Files.readAllBytes(path);
        byte[] sidecarBefore = Files.readAllBytes(sidecar(path));
        try (KeyringPassword password = password()) {
            KeyringException exception = assertThrows(KeyringException.class, () -> KeyringStore.open(path, password));
            assertEquals(KeyringException.Code.KEYRING_FORMAT_INVALID, exception.code());
            assertEquals(KeyringException.Code.KEYRING_FORMAT_INVALID.name(), exception.getMessage());
            assertArrayEquals(mainBefore, Files.readAllBytes(path));
            assertArrayEquals(sidecarBefore, Files.readAllBytes(sidecar(path)));
        } finally {
            wipe(mainBefore);
            wipe(sidecarBefore);
        }
    }

    private Path createAndClose(String file) throws Exception {
        return createAndClose(file, 1);
    }

    private Path createAndClose(String file, int randomSeed) throws Exception {
        Path path = temporaryDirectory.resolve(file);
        try (KeyringPassword password = password();
                KeyringStore ignored = KeyringStore.create(path, password, KeyringProtection.standard(),
                        deterministicRandom(randomSeed))) {
            // Creation writes the initial durable reservation.
        }
        return path;
    }

    private static byte[] authenticated(byte[] image) {
        return Arrays.copyOf(image, image.length - TAG_BYTES);
    }

    private static void replaceTag(byte[] image, byte[] tag) {
        System.arraycopy(tag, 0, image, image.length - TAG_BYTES, TAG_BYTES);
    }

    private static byte[] hmac(byte[] key, byte[] input) throws Exception {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(input);
        } finally {
            wipe(input);
        }
    }

    private static byte[] field(KeyringStore store, String name) throws Exception {
        Field field = KeyringStore.class.getDeclaredField(name);
        field.setAccessible(true);
        return (byte[]) field.get(store);
    }

    private static long longField(KeyringStore store, String name) throws Exception {
        Field field = KeyringStore.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.getLong(store);
    }

    private static long sidecarHighWater(Path path) throws Exception {
        byte[] image = Files.readAllBytes(path);
        try {
            return ByteBuffer.wrap(image, HIGH_WATER_OFFSET, Long.BYTES).getLong();
        } finally {
            wipe(image);
        }
    }

    private static Path sidecar(Path keyring) {
        return keyring.resolveSibling(keyring.getFileName() + ".nonce");
    }

    private static KeyringPassword password() {
        return new KeyringPassword(PASSWORD);
    }

    private static KeyringRandomBytes deterministicRandom() {
        return deterministicRandom(1);
    }

    private static KeyringRandomBytes deterministicRandom(int initialValue) {
        AtomicInteger value = new AtomicInteger(initialValue);
        return destination -> {
            int base = value.getAndIncrement();
            for (int index = 0; index < destination.length; index++) {
                destination[index] = (byte) (base + index);
            }
        };
    }

    private static boolean allZero(byte[] value) {
        for (byte current : value) {
            if (current != 0) {
                return false;
            }
        }
        return true;
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer: for (int index = 0; index <= haystack.length - needle.length; index++) {
            for (int offset = 0; offset < needle.length; offset++) {
                if (haystack[index + offset] != needle[offset]) {
                    continue outer;
                }
            }
            return index;
        }
        return -1;
    }

    private static void wipe(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private static void start(String method) {
        System.out.println(method);
    }

    private static void ok() {
        System.out.println("...ok");
    }

    private static final class RecordingRandom implements KeyringRandomBytes {
        private final AtomicInteger value;
        private final List<Integer> requests = new ArrayList<>();

        private RecordingRandom(int initialValue) {
            value = new AtomicInteger(initialValue);
        }

        @Override
        public void nextBytes(byte[] destination) {
            requests.add(destination.length);
            int base = value.getAndIncrement();
            for (int index = 0; index < destination.length; index++) {
                destination[index] = (byte) (base + index);
            }
        }

        private List<Integer> requests() {
            return List.copyOf(requests);
        }
    }
}
