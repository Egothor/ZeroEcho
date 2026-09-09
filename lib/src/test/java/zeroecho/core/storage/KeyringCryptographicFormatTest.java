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
package zeroecho.core.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KeyringCryptographicFormatTest {
    private static final char[] PASSWORD = { 'f', 'o', 'r', 'm', 'a', 't' };
    private static final int VERSION_OFFSET = 8;
    private static final int STORE_ID_OFFSET = 12;
    private static final int KDF_OFFSET = 28;
    private static final int ITERATIONS_OFFSET = 29;
    private static final int SALT_OFFSET = 33;
    private static final int KEK_LENGTH_OFFSET = 65;
    private static final int AEAD_OFFSET = 69;
    private static final int WRAP_NONCE_OFFSET = 70;
    private static final int WRAPPED_LENGTH_OFFSET = 82;
    private static final int WRAPPED_OFFSET = 86;
    private static final int ENTRY_COUNT_OFFSET = 134;

    @TempDir
    Path temporaryDirectory;

    @Test
    void masterWrapAuthenticationAndHeaderMatrixFailsClosed() throws Exception {
        start("masterWrapAuthenticationAndHeaderMatrixFailsClosed");
        Path source = createEmpty("master-source.zek", 1);
        byte[] image = Files.readAllBytes(source);
        try {
            assertUniformUnlockFailure(source, new char[] { 'w', 'r', 'o', 'n', 'g' });

            assertUniformUnlockFailure(
                    copyWithMutation(source, image, "wrapped-cipher", value -> value[WRAPPED_OFFSET] ^= 1), PASSWORD);
            assertUniformUnlockFailure(
                    copyWithMutation(source, image, "wrapped-tag", value -> value[WRAPPED_OFFSET + 47] ^= 1), PASSWORD);
            assertUniformUnlockFailure(copyWithMutation(source, image, "salt", value -> value[SALT_OFFSET] ^= 1),
                    PASSWORD);
            assertUniformUnlockFailure(copyWithMutation(source, image, "iterations-auth",
                    value -> putInt(value, ITERATIONS_OFFSET, 600_001)), PASSWORD);
            assertUniformUnlockFailure(
                    copyWithMutation(source, image, "wrap-nonce-auth", value -> value[WRAP_NONCE_OFFSET + 1] ^= 1),
                    PASSWORD);

            assertRejected(
                    copyWithMutation(source, image, "iterations-low",
                            value -> putInt(value, ITERATIONS_OFFSET, 599_999)),
                    KeyringException.Code.KEYRING_LIMIT_EXCEEDED);
            assertRejected(
                    copyWithMutation(source, image, "iterations-operational",
                            value -> putInt(value, ITERATIONS_OFFSET, 1_000_001)),
                    KeyringException.Code.KEYRING_LIMIT_EXCEEDED);
            assertRejected(
                    copyWithMutation(source, image, "iterations-absolute",
                            value -> putInt(value, ITERATIONS_OFFSET, 10_000_001)),
                    KeyringException.Code.KEYRING_LIMIT_EXCEEDED);
            assertRejected(copyWithMutation(source, image, "unknown-kdf", value -> value[KDF_OFFSET] = 99),
                    KeyringException.Code.KEYRING_FORMAT_INVALID);
            assertRejected(copyWithMutation(source, image, "unknown-aead", value -> value[AEAD_OFFSET] = 99),
                    KeyringException.Code.KEYRING_FORMAT_INVALID);
            assertRejected(copyWithMutation(source, image, "kek-length", value -> putInt(value, KEK_LENGTH_OFFSET, 31)),
                    KeyringException.Code.KEYRING_FORMAT_INVALID);
            assertRejected(copyWithMutation(source, image, "wrap-domain", value -> value[WRAP_NONCE_OFFSET] = 2),
                    KeyringException.Code.KEYRING_FORMAT_INVALID);
            for (int wrappedLength : new int[] { -1, 47, 49 }) {
                assertRejected(
                        copyWithMutation(source, image, "wrapped-length-" + wrappedLength,
                                value -> putInt(value, WRAPPED_LENGTH_OFFSET, wrappedLength)),
                        wrappedLength == 47 ? KeyringException.Code.KEYRING_FORMAT_INVALID
                                : KeyringException.Code.KEYRING_LIMIT_EXCEEDED);
            }

            int[] boundaries = { 1, VERSION_OFFSET, STORE_ID_OFFSET, KDF_OFFSET, ITERATIONS_OFFSET, SALT_OFFSET,
                    KEK_LENGTH_OFFSET, AEAD_OFFSET, WRAP_NONCE_OFFSET, WRAPPED_LENGTH_OFFSET, WRAPPED_OFFSET,
                    WRAPPED_OFFSET + 47, ENTRY_COUNT_OFFSET };
            for (int boundary : boundaries) {
                Path truncated = copyImage(source, Arrays.copyOf(image, boundary), "truncated-" + boundary);
                assertSafeRejected(truncated);
            }
            byte[] trailing = Arrays.copyOf(image, image.length + 1);
            assertRejected(copyImage(source, trailing, "trailing"), KeyringException.Code.KEYRING_FORMAT_INVALID);
        } finally {
            wipe(image);
        }
        ok();
    }

    @Test
    void entryAndManifestOuterTamperMatrixFailsBeforeExposure() throws Exception {
        start("entryAndManifestOuterTamperMatrixFailsBeforeExposure");
        Path source = createTwoEntries("outer-source.zek", 7);
        byte[] image = Files.readAllBytes(source);
        ImageLayout layout = layout(image);
        try {
            assertRejected(
                    copyWithMutation(source, image, "entry-cipher",
                            value -> value[layout.entries.get(0).ciphertextOffset] ^= 1),
                    KeyringException.Code.KEYRING_FORMAT_INVALID);
            assertRejected(
                    copyWithMutation(source, image, "entry-tag",
                            value -> value[layout.entries.get(0).endOffset - 1] ^= 1),
                    KeyringException.Code.KEYRING_FORMAT_INVALID);
            assertRejected(
                    copyWithMutation(source, image, "entry-nonce",
                            value -> value[layout.entries.get(0).nonceOffset] ^= 1),
                    KeyringException.Code.KEYRING_FORMAT_INVALID);
            assertRejected(
                    copyWithMutation(source, image, "entry-id",
                            value -> value[layout.entries.get(0).entryIdOffset] ^= 1),
                    KeyringException.Code.KEYRING_FORMAT_INVALID);
            assertRejected(
                    copyWithMutation(source, image, "manifest-nonce", value -> value[layout.manifestNonceOffset] ^= 1),
                    KeyringException.Code.KEYRING_FORMAT_INVALID);
            assertRejected(
                    copyWithMutation(source, image, "manifest-cipher",
                            value -> value[layout.manifestCipherOffset] ^= 1),
                    KeyringException.Code.KEYRING_FORMAT_INVALID);
            assertRejected(copyWithMutation(source, image, "manifest-tag", value -> value[image.length - 1] ^= 1),
                    KeyringException.Code.KEYRING_FORMAT_INVALID);

            assertRejected(copyImage(source, reorderEntries(image, layout), "entry-reorder"),
                    KeyringException.Code.KEYRING_FORMAT_INVALID);
            assertRejected(copyImage(source, duplicateFirstEntry(image, layout), "entry-duplicate"),
                    KeyringException.Code.KEYRING_FORMAT_INVALID);
            assertRejected(copyImage(source, deleteFirstEntry(image, layout), "entry-delete"),
                    KeyringException.Code.KEYRING_FORMAT_INVALID);
            assertRejected(copyImage(source, insertUnauthenticatedEntry(image, layout), "entry-insert"),
                    KeyringException.Code.KEYRING_FORMAT_INVALID);

            Path other = createTwoEntries("outer-other.zek", 107);
            byte[] otherImage = Files.readAllBytes(other);
            try {
                ImageLayout otherLayout = layout(otherImage);
                byte[] copied = replaceEntry(otherImage, otherLayout.entries.get(0),
                        slice(image, layout.entries.get(0).entryIdOffset, layout.entries.get(0).endOffset));
                assertRejected(copyImage(other, copied, "entry-cross-store"),
                        KeyringException.Code.KEYRING_FORMAT_INVALID);
                wipe(copied);
            } finally {
                wipe(otherImage);
            }

            assertFalse(openAliases(source).isEmpty());
        } finally {
            wipe(image);
        }
        ok();
    }

    @Test
    void authenticatedManifestAndEntryBindingTamperMatrixFailsClosed() throws Exception {
        start("authenticatedManifestAndEntryBindingTamperMatrixFailsClosed");
        StoreFixture fixture = createFixture("authenticated-source.zek", 17);
        byte[] image = Files.readAllBytes(fixture.path);
        byte[] masterKey = fixture.masterKey;
        try {
            assertManifestMutationRejected(fixture.path, image, masterKey, "position",
                    value -> putInt(value, descriptor(value, 0).positionOffset, 1));
            assertManifestMutationRejected(fixture.path, image, masterKey, "descriptor-id",
                    value -> value[descriptor(value, 0).entryIdOffset] ^= 1);
            assertManifestMutationRejected(fixture.path, image, masterKey, "descriptor-nonce",
                    value -> value[descriptor(value, 0).nonceOffset] ^= 1);
            assertManifestMutationRejected(fixture.path, image, masterKey, "cipher-length",
                    value -> putInt(value, descriptor(value, 0).ciphertextLengthOffset,
                            getInt(value, descriptor(value, 0).ciphertextLengthOffset) + 1));
            assertManifestMutationRejected(fixture.path, image, masterKey, "cipher-digest",
                    value -> value[descriptor(value, 0).digestOffset] ^= 1);
            assertManifestMutationRejected(fixture.path, image, masterKey, "duplicate-id", value -> copyField(value,
                    descriptor(value, 0).entryIdOffset, descriptor(value, 1).entryIdOffset, KeyringStore.UUID_BYTES));
            assertManifestMutationRejected(fixture.path, image, masterKey, "duplicate-nonce", value -> copyField(value,
                    descriptor(value, 0).nonceOffset, descriptor(value, 1).nonceOffset, KeyringStore.NONCE_BYTES));
            assertManifestMutationRejected(fixture.path, image, masterKey, "duplicate-alias",
                    value -> copyField(value, descriptor(value, 0).aliasOffset, descriptor(value, 1).aliasOffset,
                            descriptor(value, 0).aliasLength));
            assertManifestMutationRejected(fixture.path, image, masterKey, "unknown-algorithm",
                    value -> overwriteAscii(value, descriptor(value, 0).algorithmOffset, "BAD"),
                    KeyringException.Code.KEYRING_IMPORT_MAPPING_INVALID);
            assertManifestMutationRejected(fixture.path, image, masterKey, "unknown-kind",
                    value -> value[descriptor(value, 0).kindOffset] = 99);
            assertManifestMutationRejected(fixture.path, image, masterKey, "unknown-encoding",
                    value -> value[descriptor(value, 0).encodingOffset] = 99);
            assertManifestMutationRejected(fixture.path, image, masterKey, "unknown-hmac",
                    value -> value[descriptor(value, 0).hmacOffset] = 99,
                    KeyringException.Code.KEYRING_IMPORT_METADATA_INVALID);
            assertManifestMutationRejected(fixture.path, image, masterKey, "manifest-version",
                    value -> putInt(value, 0, 2));
            assertManifestMutationRejected(fixture.path, image, masterKey, "manifest-count",
                    value -> putInt(value, 16, 1));
            assertManifestMutationRejected(fixture.path, image, masterKey, "manifest-reorder",
                    KeyringCryptographicFormatTest::swapManifestDescriptors);
            assertManifestReplacementRejected(fixture.path, image, masterKey, "manifest-truncated",
                    value -> Arrays.copyOf(value, value.length - 1));
            assertManifestReplacementRejected(fixture.path, image, masterKey, "manifest-trailing",
                    value -> Arrays.copyOf(value, value.length + 1));

            assertEntryMutationRejected(fixture.path, image, masterKey, "entry-cipher-auth", value -> value[0] ^= 1,
                    false);
            assertEntryMutationRejected(fixture.path, image, masterKey, "entry-tag-auth",
                    value -> value[value.length - 1] ^= 1, false);
            assertEntryMutationRejected(fixture.path, image, masterKey, "entry-version", value -> putInt(value, 0, 2),
                    true);
            assertEntryMutationRejected(fixture.path, image, masterKey, "alias-substitution",
                    value -> overwriteAscii(value, Integer.BYTES * 2, "xxx"), true);
            assertEntryMutationRejected(fixture.path, image, masterKey, "algorithm-substitution",
                    value -> overwriteAscii(value, Integer.BYTES * 3 + 3, "BAD"), true);
            assertEntryMutationRejected(fixture.path, image, masterKey, "kind-substitution",
                    value -> value[Integer.BYTES * 4 + 2] = 1, true);
            assertEntryMutationRejected(fixture.path, image, masterKey, "encoding-substitution",
                    value -> value[Integer.BYTES * 4 + 3] = 1, true);
            assertEntryMutationRejected(fixture.path, image, masterKey, "hmac-substitution",
                    value -> value[Integer.BYTES * 4 + 4] = 1, true);
            assertCoherentIdentityMutationRejected(fixture.path, image, masterKey, "coherent-entry-id", true);
            assertCoherentIdentityMutationRejected(fixture.path, image, masterKey, "coherent-entry-nonce", false);
        } finally {
            wipe(image);
            wipe(masterKey);
        }
        ok();
    }

    @Test
    void decodedEntryAndManifestSchemasRejectTypeConfusionAndBounds() throws Exception {
        start("decodedEntryAndManifestSchemasRejectTypeConfusionAndBounds");
        byte[] validEntry = entryPlaintext(1, "a", "AES", 3, 3, 0, new byte[32], false);
        try {
            invokeDecodeEntry(validEntry);
            assertDecodeEntryRejected(entryPlaintext(2, "a", "AES", 3, 3, 0, new byte[32], false));
            assertDecodeEntryRejected(entryPlaintext(1, "a", "AES", 99, 3, 0, new byte[32], false));
            assertDecodeEntryRejected(entryPlaintext(1, "a", "AES", 3, 99, 0, new byte[32], false));
            assertDecodeEntryRejected(entryPlaintext(1, "a", "AES", 3, 3, 99, new byte[32], false));
            assertDecodeEntryRejected(entryPlaintext(1, "a", "AES", 3, 3, 0, new byte[32], true));
            assertDecodeEntryRejected(lengthOnlyEntry(-1, "AES"));
            assertDecodeEntryRejected(lengthOnlyEntry(KeyringStore.MAX_ALIAS_BYTES + 1, "AES"));
            assertDecodeEntryRejected(metadataLengthEntry(-1));
            assertDecodeEntryRejected(metadataLengthEntry(KeyringStore.MAX_METADATA_BYTES + 1));
            assertDecodeEntryRejected(encodedLengthEntry(-1));
            assertDecodeEntryRejected(encodedLengthEntry(KeyringStore.MAX_ENTRY_CIPHERTEXT_BYTES));

            byte[] maximumAlias = entryPlaintext(1, "a".repeat(KeyringStore.MAX_ALIAS_BYTES), "AES", 3, 3, 0,
                    new byte[1], false);
            byte[] maximumMetadata = entryPlaintext(1, "a", "A".repeat(KeyringStore.MAX_METADATA_BYTES), 3, 3, 0,
                    new byte[1], false);
            try {
                invokeDecodeEntry(maximumAlias);
                invokeDecodeEntry(maximumMetadata);
            } finally {
                wipe(maximumAlias);
                wipe(maximumMetadata);
            }
        } finally {
            wipe(validEntry);
        }

        byte[] manifest = emptyManifest(1, 1, 0, false);
        try {
            invokeDecodeManifest(manifest, 0);
            assertDecodeManifestRejected(emptyManifest(2, 1, 0, false), 0);
            assertDecodeManifestRejected(emptyManifest(1, 1, 0, true), 0);
            assertDecodeManifestRejected(Arrays.copyOf(manifest, manifest.length - 1), 0);
            assertDecodeManifestRejected(emptyManifest(1, 1, 1, false), 0);
            assertDecodeManifestRejected(emptyManifest(1, 0, 0, false), 0);
        } finally {
            wipe(manifest);
        }
        ok();
    }

    @Test
    void hardLimitsOldFormatsAndPlaintextSentinelsFailClosed() throws Exception {
        start("hardLimitsOldFormatsAndPlaintextSentinelsFailClosed");
        Path source = createEmpty("bounds-source.zek", 31);
        byte[] image = Files.readAllBytes(source);
        try {
            assertRejected(
                    copyWithMutation(source, image, "negative-count", value -> putInt(value, ENTRY_COUNT_OFFSET, -1)),
                    KeyringException.Code.KEYRING_LIMIT_EXCEEDED);
            assertRejected(
                    copyWithMutation(source, image, "oversized-count",
                            value -> putInt(value, ENTRY_COUNT_OFFSET, KeyringStore.MAX_ENTRY_COUNT + 1)),
                    KeyringException.Code.KEYRING_LIMIT_EXCEEDED);
            assertRejected(
                    copyWithMutation(source, image, "old-main-version", value -> putInt(value, VERSION_OFFSET, 1)),
                    KeyringException.Code.KEYRING_FORMAT_INVALID);
            assertRejected(
                    copyWithMutation(source, image, "draft-main-version", value -> putInt(value, VERSION_OFFSET, 3)),
                    KeyringException.Code.KEYRING_FORMAT_INVALID);
        } finally {
            wipe(image);
        }

        Path oversized = temporaryDirectory.resolve("oversized.zek");
        try (java.nio.channels.FileChannel channel = java.nio.channels.FileChannel.open(oversized,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            channel.position(KeyringStore.MAX_FILE_BYTES);
            channel.write(ByteBuffer.wrap(new byte[] { 0 }));
        }
        ownerOnly(oversized);
        try (KeyringPassword password = password()) {
            KeyringException failure = assertThrows(KeyringException.class,
                    () -> KeyringStore.open(oversized, password));
            assertEquals(KeyringException.Code.KEYRING_LIMIT_EXCEEDED, failure.code());
        }

        Path plaintext = temporaryDirectory.resolve("plaintext-v1.zek");
        Files.writeString(plaintext, "# KeyringStore v1\njava.io.File\nHmacSHA1\n", StandardCharsets.UTF_8);
        ownerOnly(plaintext);
        assertRejected(plaintext, KeyringException.Code.KEYRING_FORMAT_INVALID);

        byte[] sentinel = "CONTROLLED-SECRET-SENTINEL-00001".getBytes(StandardCharsets.US_ASCII);
        Path protectedStore = temporaryDirectory.resolve("sentinel.zek");
        CapturingHandler handler = new CapturingHandler();
        Logger root = Logger.getLogger("");
        root.addHandler(handler);
        try {
            try (KeyringPassword password = password();
                    KeyringStore store = KeyringStore.create(protectedStore, password, KeyringProtection.standard(),
                            deterministicRandom(61))) {
                store.putSecret("sentinel", "AES", new SecretKeySpec(Arrays.copyOf(sentinel, 32), "AES"));
            }
            assertAbsent(Files.readAllBytes(protectedStore), sentinel);
            assertAbsent(Files.readAllBytes(sidecar(protectedStore)), sentinel);
            try (Stream<Path> files = Files.list(temporaryDirectory)) {
                assertTrue(files.noneMatch(path -> path.getFileName().toString().endsWith(".tmp")));
            }
            byte[] corrupt = Files.readAllBytes(protectedStore);
            try {
                corrupt[corrupt.length - 1] ^= 1;
                Files.write(protectedStore, corrupt);
            } finally {
                wipe(corrupt);
            }
            try (KeyringPassword password = password()) {
                KeyringException failure = assertThrows(KeyringException.class,
                        () -> KeyringStore.open(protectedStore, password));
                assertFalse(failure.getMessage().contains("CONTROLLED"));
                assertNull(failure.getCause());
            }
            assertFalse(handler.output().contains("CONTROLLED"));
        } finally {
            root.removeHandler(handler);
            wipe(sentinel);
        }
        ok();
    }

    private Path createEmpty(String name, int seed) throws Exception {
        Path path = temporaryDirectory.resolve(name);
        try (KeyringPassword password = password();
                KeyringStore ignored = KeyringStore.create(path, password, KeyringProtection.standard(),
                        deterministicRandom(seed))) {
            // Current empty image and reservation sidecar are durable.
        }
        return path;
    }

    private Path createTwoEntries(String name, int seed) throws Exception {
        StoreFixture fixture = createFixture(name, seed);
        wipe(fixture.masterKey);
        return fixture.path;
    }

    private StoreFixture createFixture(String name, int seed) throws Exception {
        Path path = temporaryDirectory.resolve(name);
        byte[] first = new byte[32];
        byte[] second = new byte[32];
        byte[] masterKey;
        Arrays.fill(first, (byte) 0x31);
        Arrays.fill(second, (byte) 0x42);
        try (KeyringPassword password = password();
                KeyringStore store = KeyringStore.create(path, password, KeyringProtection.standard(),
                        deterministicRandom(seed))) {
            store.putSecret("one", "AES", new SecretKeySpec(first, "AES"));
            store.putSecret("two", "AES", new SecretKeySpec(second, "AES"));
            masterKey = bytesField(store, "masterKey").clone();
        } finally {
            wipe(first);
            wipe(second);
        }
        return new StoreFixture(path, masterKey);
    }

    private void assertManifestMutationRejected(Path source, byte[] image, byte[] masterKey, String name,
            Mutation mutation) throws Exception {
        assertManifestMutationRejected(source, image, masterKey, name, mutation,
                KeyringException.Code.KEYRING_FORMAT_INVALID);
    }

    private void assertManifestMutationRejected(Path source, byte[] image, byte[] masterKey, String name,
            Mutation mutation, KeyringException.Code code) throws Exception {
        assertManifestReplacementRejected(source, image, masterKey, name, value -> {
            mutation.apply(value);
            return value;
        }, code);
    }

    private void assertManifestReplacementRejected(Path source, byte[] image, byte[] masterKey, String name,
            Replacement mutation) throws Exception {
        assertManifestReplacementRejected(source, image, masterKey, name, mutation,
                KeyringException.Code.KEYRING_FORMAT_INVALID);
    }

    private void assertManifestReplacementRejected(Path source, byte[] image, byte[] masterKey, String name,
            Replacement mutation, KeyringException.Code code) throws Exception {
        byte[] plaintext = decryptManifest(image, masterKey);
        byte[] replacement = null;
        byte[] rewritten = null;
        try {
            replacement = mutation.apply(plaintext);
            rewritten = replaceManifest(image, masterKey, replacement);
            assertRejected(copyImage(source, rewritten, name), code);
        } finally {
            if (replacement != plaintext) {
                wipe(replacement);
            }
            wipe(plaintext);
            wipe(rewritten);
        }
    }

    private void assertEntryMutationRejected(Path source, byte[] image, byte[] masterKey, String name,
            Mutation mutation, boolean plaintextMutation) throws Exception {
        ImageLayout imageLayout = layout(image);
        WireEntry entry = imageLayout.entries.get(0);
        byte[] ciphertext = slice(image, entry.ciphertextOffset, entry.endOffset);
        byte[] changed = null;
        byte[] rewritten = null;
        try {
            if (plaintextMutation) {
                byte[] nonce = slice(image, entry.nonceOffset, entry.nonceOffset + KeyringStore.NONCE_BYTES);
                byte[] aad = entryAad(image, entry, 0);
                byte[] plaintext = null;
                try {
                    plaintext = crypt(Cipher.DECRYPT_MODE, masterKey, nonce, aad, ciphertext);
                    mutation.apply(plaintext);
                    changed = crypt(Cipher.ENCRYPT_MODE, masterKey, nonce, aad, plaintext);
                } finally {
                    wipe(nonce);
                    wipe(aad);
                    wipe(plaintext);
                }
            } else {
                changed = ciphertext.clone();
                mutation.apply(changed);
            }
            rewritten = installFirstCiphertext(image, masterKey, changed);
            Path path = copyImage(source, rewritten, name);
            try (KeyringPassword password = password(); KeyringStore store = KeyringStore.open(path, password)) {
                KeyringException failure = assertThrows(KeyringException.class, () -> store.getSecret("one"));
                assertEquals(KeyringException.Code.KEYRING_FORMAT_INVALID, failure.code());
                assertEquals(KeyringException.Code.KEYRING_FORMAT_INVALID.name(), failure.getMessage());
            }
        } finally {
            wipe(ciphertext);
            wipe(changed);
            wipe(rewritten);
        }
    }

    private void assertCoherentIdentityMutationRejected(Path source, byte[] image, byte[] masterKey, String name,
            boolean entryId) throws Exception {
        byte[] rewritten = image.clone();
        byte[] manifest = decryptManifest(image, masterKey);
        try {
            ImageLayout imageLayout = layout(rewritten);
            WireEntry wire = imageLayout.entries.get(0);
            ManifestDescriptor descriptor = descriptor(manifest, 0);
            if (entryId) {
                rewritten[wire.entryIdOffset] ^= 1;
                manifest[descriptor.entryIdOffset] ^= 1;
            } else {
                rewritten[wire.nonceOffset + KeyringStore.NONCE_BYTES - 1] = 1;
                manifest[descriptor.nonceOffset + KeyringStore.NONCE_BYTES - 1] = 1;
            }
            byte[] withManifest = replaceManifest(rewritten, masterKey, manifest);
            wipe(rewritten);
            rewritten = withManifest;
            Path path = copyImage(source, rewritten, name);
            try (KeyringPassword password = password(); KeyringStore store = KeyringStore.open(path, password)) {
                KeyringException failure = assertThrows(KeyringException.class, () -> store.getSecret("one"));
                assertEquals(KeyringException.Code.KEYRING_FORMAT_INVALID, failure.code());
            }
        } finally {
            wipe(rewritten);
            wipe(manifest);
        }
    }

    private static byte[] installFirstCiphertext(byte[] image, byte[] masterKey, byte[] ciphertext) throws Exception {
        byte[] result = image.clone();
        ImageLayout imageLayout = layout(result);
        WireEntry entry = imageLayout.entries.get(0);
        if (ciphertext.length != entry.endOffset - entry.ciphertextOffset) {
            throw new IllegalArgumentException("ciphertext length changed");
        }
        System.arraycopy(ciphertext, 0, result, entry.ciphertextOffset, ciphertext.length);
        byte[] manifest = decryptManifest(result, masterKey);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(ciphertext);
        try {
            ManifestDescriptor descriptor = descriptor(manifest, 0);
            System.arraycopy(digest, 0, manifest, descriptor.digestOffset, digest.length);
            byte[] rewritten = replaceManifest(result, masterKey, manifest);
            wipe(result);
            return rewritten;
        } finally {
            wipe(manifest);
            wipe(digest);
        }
    }

    private static byte[] decryptManifest(byte[] image, byte[] masterKey) throws Exception {
        ImageLayout imageLayout = layout(image);
        byte[] nonce = slice(image, imageLayout.manifestNonceOffset,
                imageLayout.manifestNonceOffset + KeyringStore.NONCE_BYTES);
        byte[] ciphertext = slice(image, imageLayout.manifestCipherOffset, image.length);
        byte[] aad = manifestAad(image);
        try {
            return crypt(Cipher.DECRYPT_MODE, masterKey, nonce, aad, ciphertext);
        } finally {
            wipe(nonce);
            wipe(ciphertext);
            wipe(aad);
        }
    }

    private static byte[] replaceManifest(byte[] image, byte[] masterKey, byte[] plaintext) throws Exception {
        ImageLayout imageLayout = layout(image);
        byte[] nonce = slice(image, imageLayout.manifestNonceOffset,
                imageLayout.manifestNonceOffset + KeyringStore.NONCE_BYTES);
        byte[] aad = manifestAad(image);
        byte[] ciphertext = null;
        try {
            ciphertext = crypt(Cipher.ENCRYPT_MODE, masterKey, nonce, aad, plaintext);
            int lengthOffset = imageLayout.manifestCipherOffset - Integer.BYTES;
            byte[] result = Arrays.copyOf(image, imageLayout.manifestCipherOffset + ciphertext.length);
            putInt(result, lengthOffset, ciphertext.length);
            System.arraycopy(ciphertext, 0, result, imageLayout.manifestCipherOffset, ciphertext.length);
            return result;
        } finally {
            wipe(nonce);
            wipe(aad);
            wipe(ciphertext);
        }
    }

    private static byte[] manifestAad(byte[] image) {
        ByteBuffer buffer = ByteBuffer.allocate(8 + Integer.BYTES + KeyringStore.UUID_BYTES + Integer.BYTES * 2);
        buffer.put(KeyringStore.MAGIC);
        buffer.putInt(KeyringStore.FORMAT_VERSION);
        buffer.put(image, STORE_ID_OFFSET, KeyringStore.UUID_BYTES);
        buffer.putInt(KeyringStore.MANIFEST_FORMAT_VERSION);
        buffer.putInt(getInt(image, ENTRY_COUNT_OFFSET));
        return buffer.array();
    }

    private static byte[] entryAad(byte[] image, WireEntry entry, int position) {
        ByteBuffer buffer = ByteBuffer.allocate(8 + Integer.BYTES + KeyringStore.UUID_BYTES * 2 + Integer.BYTES * 2);
        buffer.put(KeyringStore.MAGIC);
        buffer.putInt(KeyringStore.FORMAT_VERSION);
        buffer.put(image, STORE_ID_OFFSET, KeyringStore.UUID_BYTES);
        buffer.put(image, entry.entryIdOffset, KeyringStore.UUID_BYTES);
        buffer.putInt(position);
        buffer.putInt(KeyringStore.ENTRY_FORMAT_VERSION);
        return buffer.array();
    }

    private static byte[] crypt(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] input) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(KeyringStore.GCM_TAG_BITS, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(input);
    }

    private static ManifestDescriptor descriptor(byte[] manifest, int target) {
        ByteBuffer buffer = ByteBuffer.wrap(manifest);
        buffer.position(Integer.BYTES * 2 + Long.BYTES + Integer.BYTES);
        for (int index = 0; index <= target; index++) {
            int start = buffer.position();
            int entryId = start;
            buffer.position(entryId + KeyringStore.UUID_BYTES);
            int position = buffer.position();
            buffer.getInt();
            int aliasLength = buffer.getInt();
            int alias = buffer.position();
            buffer.position(alias + aliasLength);
            int algorithmLength = buffer.getInt();
            int algorithm = buffer.position();
            buffer.position(algorithm + algorithmLength);
            int kind = buffer.position();
            buffer.get();
            int encoding = buffer.position();
            buffer.get();
            int hmac = buffer.position();
            buffer.get();
            int nonce = buffer.position();
            buffer.position(nonce + KeyringStore.NONCE_BYTES);
            int ciphertextLength = buffer.position();
            buffer.getInt();
            int digest = buffer.position();
            buffer.position(digest + KeyringStore.SHA256_BYTES);
            if (index == target) {
                return new ManifestDescriptor(start, buffer.position(), entryId, position, alias, aliasLength,
                        algorithm, kind, encoding, hmac, nonce, ciphertextLength, digest);
            }
        }
        throw new IllegalArgumentException("descriptor index");
    }

    private static byte[] swapManifestDescriptors(byte[] manifest) {
        ManifestDescriptor first = descriptor(manifest, 0);
        ManifestDescriptor second = descriptor(manifest, 1);
        byte[] firstBytes = slice(manifest, first.startOffset, first.endOffset);
        byte[] secondBytes = slice(manifest, second.startOffset, second.endOffset);
        try {
            System.arraycopy(secondBytes, 0, manifest, first.startOffset, secondBytes.length);
            System.arraycopy(firstBytes, 0, manifest, second.startOffset, firstBytes.length);
            return manifest;
        } finally {
            wipe(firstBytes);
            wipe(secondBytes);
        }
    }

    private static void copyField(byte[] value, int source, int target, int length) {
        System.arraycopy(value, source, value, target, length);
    }

    private static void overwriteAscii(byte[] value, int offset, String replacement) {
        byte[] encoded = replacement.getBytes(StandardCharsets.US_ASCII);
        try {
            System.arraycopy(encoded, 0, value, offset, encoded.length);
        } finally {
            wipe(encoded);
        }
    }

    private static int getInt(byte[] value, int offset) {
        return ByteBuffer.wrap(value, offset, Integer.BYTES).getInt();
    }

    private static byte[] bytesField(KeyringStore store, String name) throws Exception {
        java.lang.reflect.Field field = KeyringStore.class.getDeclaredField(name);
        field.setAccessible(true);
        return (byte[]) field.get(store);
    }

    private void assertUniformUnlockFailure(Path source, char[] candidate) throws Exception {
        try (KeyringPassword password = new KeyringPassword(candidate)) {
            KeyringException failure = assertThrows(KeyringException.class, () -> KeyringStore.open(source, password));
            assertEquals(KeyringException.Code.KEYRING_UNLOCK_FAILED, failure.code());
            assertEquals(KeyringException.Code.KEYRING_UNLOCK_FAILED.name(), failure.getMessage());
            assertNull(failure.getCause());
            assertEquals(0, failure.getSuppressed().length);
        }
    }

    private void assertRejected(Path path, KeyringException.Code code) throws Exception {
        try (KeyringPassword password = password()) {
            KeyringException failure = assertThrows(KeyringException.class, () -> KeyringStore.open(path, password));
            assertEquals(code, failure.code());
            assertEquals(code.name(), failure.getMessage());
            assertNull(failure.getCause());
        }
    }

    private void assertSafeRejected(Path path) throws Exception {
        try (KeyringPassword password = password()) {
            KeyringException failure = assertThrows(KeyringException.class, () -> KeyringStore.open(path, password));
            assertTrue(
                    Set.of(KeyringException.Code.KEYRING_FORMAT_INVALID, KeyringException.Code.KEYRING_LIMIT_EXCEEDED,
                            KeyringException.Code.KEYRING_UNLOCK_FAILED).contains(failure.code()));
            assertEquals(failure.code().name(), failure.getMessage());
            assertNull(failure.getCause());
        }
    }

    private Path copyWithMutation(Path source, byte[] image, String name, Mutation mutation) throws Exception {
        byte[] copy = image.clone();
        try {
            mutation.apply(copy);
            return copyImage(source, copy, name);
        } finally {
            wipe(copy);
        }
    }

    private Path copyImage(Path source, byte[] image, String name) throws Exception {
        Path target = temporaryDirectory.resolve(name + ".zek");
        Files.write(target, image, StandardOpenOption.CREATE_NEW);
        ownerOnly(target);
        Files.copy(sidecar(source), sidecar(target));
        ownerOnly(sidecar(target));
        return target;
    }

    private static List<String> openAliases(Path path) throws Exception {
        try (KeyringPassword password = password(); KeyringStore store = KeyringStore.open(path, password)) {
            return store.aliases();
        }
    }

    private static ImageLayout layout(byte[] image) {
        ByteBuffer buffer = ByteBuffer.wrap(image);
        buffer.position(ENTRY_COUNT_OFFSET);
        int count = buffer.getInt();
        List<WireEntry> entries = new ArrayList<>();
        for (int index = 0; index < count; index++) {
            int entryId = buffer.position();
            buffer.position(entryId + KeyringStore.UUID_BYTES);
            int nonce = buffer.position();
            buffer.position(nonce + KeyringStore.NONCE_BYTES);
            int length = buffer.getInt();
            int ciphertext = buffer.position();
            buffer.position(ciphertext + length);
            entries.add(new WireEntry(entryId, nonce, ciphertext, buffer.position()));
        }
        int manifestNonce = buffer.position();
        buffer.position(manifestNonce + KeyringStore.NONCE_BYTES);
        buffer.getInt();
        return new ImageLayout(entries, manifestNonce, buffer.position());
    }

    private static byte[] reorderEntries(byte[] image, ImageLayout layout) {
        WireEntry first = layout.entries.get(0);
        WireEntry second = layout.entries.get(1);
        byte[] result = image.clone();
        byte[] firstBytes = slice(image, first.entryIdOffset, first.endOffset);
        byte[] secondBytes = slice(image, second.entryIdOffset, second.endOffset);
        try {
            System.arraycopy(secondBytes, 0, result, first.entryIdOffset, secondBytes.length);
            System.arraycopy(firstBytes, 0, result, second.entryIdOffset, firstBytes.length);
            return result;
        } finally {
            wipe(firstBytes);
            wipe(secondBytes);
        }
    }

    private static byte[] duplicateFirstEntry(byte[] image, ImageLayout layout) {
        WireEntry first = layout.entries.get(0);
        WireEntry second = layout.entries.get(1);
        return replaceEntry(image, second, slice(image, first.entryIdOffset, first.endOffset));
    }

    private static byte[] deleteFirstEntry(byte[] image, ImageLayout layout) {
        WireEntry first = layout.entries.get(0);
        byte[] result = new byte[image.length - (first.endOffset - first.entryIdOffset)];
        System.arraycopy(image, 0, result, 0, ENTRY_COUNT_OFFSET);
        putInt(result, ENTRY_COUNT_OFFSET, 1);
        System.arraycopy(image, first.endOffset, result, ENTRY_COUNT_OFFSET + Integer.BYTES,
                image.length - first.endOffset);
        return result;
    }

    private static byte[] insertUnauthenticatedEntry(byte[] image, ImageLayout layout) {
        WireEntry first = layout.entries.get(0);
        byte[] encoded = slice(image, first.entryIdOffset, first.endOffset);
        byte[] result = new byte[image.length + encoded.length];
        System.arraycopy(image, 0, result, 0, layout.manifestNonceOffset);
        putInt(result, ENTRY_COUNT_OFFSET, 3);
        System.arraycopy(encoded, 0, result, layout.manifestNonceOffset, encoded.length);
        System.arraycopy(image, layout.manifestNonceOffset, result, layout.manifestNonceOffset + encoded.length,
                image.length - layout.manifestNonceOffset);
        wipe(encoded);
        return result;
    }

    private static byte[] replaceEntry(byte[] image, WireEntry target, byte[] replacement) {
        int currentLength = target.endOffset - target.entryIdOffset;
        byte[] result = new byte[image.length - currentLength + replacement.length];
        System.arraycopy(image, 0, result, 0, target.entryIdOffset);
        System.arraycopy(replacement, 0, result, target.entryIdOffset, replacement.length);
        System.arraycopy(image, target.endOffset, result, target.entryIdOffset + replacement.length,
                image.length - target.endOffset);
        wipe(replacement);
        return result;
    }

    private static byte[] entryPlaintext(int version, String alias, String algorithm, int kind, int encoding, int hmac,
            byte[] key, boolean trailing) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.writeInt(version);
            writeString(out, alias);
            writeString(out, algorithm);
            out.writeByte(kind);
            out.writeByte(encoding);
            out.writeByte(hmac);
            out.writeInt(key.length);
            out.write(key);
            if (trailing) {
                out.writeByte(0);
            }
        }
        return bytes.toByteArray();
    }

    private static byte[] lengthOnlyEntry(int aliasLength, String algorithm) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.writeInt(1);
            out.writeInt(aliasLength);
            writeString(out, algorithm);
        }
        return bytes.toByteArray();
    }

    private static byte[] metadataLengthEntry(int length) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.writeInt(1);
            writeString(out, "a");
            out.writeInt(length);
        }
        return bytes.toByteArray();
    }

    private static byte[] encodedLengthEntry(int length) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.writeInt(1);
            writeString(out, "a");
            writeString(out, "AES");
            out.writeByte(3);
            out.writeByte(3);
            out.writeByte(0);
            out.writeInt(length);
        }
        return bytes.toByteArray();
    }

    private static byte[] emptyManifest(int version, long highWater, int count, boolean trailing) {
        ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES * 3 + Long.BYTES + (trailing ? 1 : 0));
        buffer.putInt(version).putInt(0x010203).putLong(highWater).putInt(count);
        if (trailing) {
            buffer.put((byte) 0);
        }
        return buffer.array();
    }

    private static Method persistenceMethod(String name, Class<?>... parameterTypes) throws Exception {
        Class<?> persistence = java.util.Arrays.stream(KeyringStore.class.getDeclaredClasses())
                .filter(type -> "Persistence".equals(type.getSimpleName()))
                .findFirst().orElseThrow();
        return persistence.getDeclaredMethod(name, parameterTypes);
    }

    private static void invokeDecodeEntry(byte[] input) throws Exception {
        Method method = persistenceMethod("decodeEntryPlaintext", byte[].class);
        method.setAccessible(true);
        method.invoke(null, (Object) input);
    }

    private static void assertDecodeEntryRejected(byte[] input) throws Exception {
        try {
            InvocationTargetException failure = assertThrows(InvocationTargetException.class,
                    () -> invokeDecodeEntry(input));
            assertTrue(failure.getCause() instanceof KeyringException);
        } finally {
            wipe(input);
        }
    }

    private static void invokeDecodeManifest(byte[] input, int expectedCount) throws Exception {
        Method method = persistenceMethod("decodeManifest", byte[].class, int.class);
        method.setAccessible(true);
        method.invoke(null, input, expectedCount);
    }

    private static void assertDecodeManifestRejected(byte[] input, int expectedCount) throws Exception {
        try {
            InvocationTargetException failure = assertThrows(InvocationTargetException.class,
                    () -> invokeDecodeManifest(input, expectedCount));
            assertTrue(failure.getCause() instanceof KeyringException);
        } finally {
            wipe(input);
        }
    }

    private static void writeString(DataOutputStream out, String value) throws Exception {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        try {
            out.writeInt(encoded.length);
            out.write(encoded);
        } finally {
            wipe(encoded);
        }
    }

    private static void assertAbsent(byte[] haystack, byte[] needle) {
        try {
            assertEquals(-1, indexOf(haystack, needle));
        } finally {
            wipe(haystack);
        }
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

    private static byte[] slice(byte[] input, int start, int end) {
        return Arrays.copyOfRange(input, start, end);
    }

    private static void putInt(byte[] value, int offset, int replacement) {
        ByteBuffer.wrap(value, offset, Integer.BYTES).putInt(replacement);
    }

    private static void ownerOnly(Path path) throws Exception {
        if (java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            Files.setPosixFilePermissions(path, Set.of(java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
            return;
        }
        // Windows: express owner-only as an NTFS ACL with a single owner-full-control
        // entry, mirroring the production Windows keyring policy so the crypto tamper
        // matrices (which are platform-neutral) can be exercised here too.
        java.nio.file.attribute.AclFileAttributeView view = Files.getFileAttributeView(path,
                java.nio.file.attribute.AclFileAttributeView.class, java.nio.file.LinkOption.NOFOLLOW_LINKS);
        java.nio.file.attribute.UserPrincipal owner = view.getOwner();
        java.nio.file.attribute.AclEntry entry = java.nio.file.attribute.AclEntry.newBuilder()
                .setType(java.nio.file.attribute.AclEntryType.ALLOW)
                .setPrincipal(owner)
                .setPermissions(java.util.EnumSet.allOf(java.nio.file.attribute.AclEntryPermission.class))
                .build();
        view.setAcl(java.util.List.of(entry));
    }

    private static Path sidecar(Path keyring) {
        return keyring.resolveSibling(keyring.getFileName() + ".nonce");
    }

    private static KeyringPassword password() {
        return new KeyringPassword(PASSWORD);
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

    @FunctionalInterface
    private interface Mutation {
        void apply(byte[] value);
    }

    @FunctionalInterface
    private interface Replacement {
        byte[] apply(byte[] value);
    }

    private record WireEntry(int entryIdOffset, int nonceOffset, int ciphertextOffset, int endOffset) {
    }

    private record ImageLayout(List<WireEntry> entries, int manifestNonceOffset, int manifestCipherOffset) {
    }

    private record ManifestDescriptor(int startOffset, int endOffset, int entryIdOffset, int positionOffset,
            int aliasOffset, int aliasLength, int algorithmOffset, int kindOffset, int encodingOffset, int hmacOffset,
            int nonceOffset, int ciphertextLengthOffset, int digestOffset) {
    }

    private record StoreFixture(Path path, byte[] masterKey) {
    }

    private static final class CapturingHandler extends Handler {
        private final StringBuilder output = new StringBuilder();

        @Override
        public void publish(LogRecord record) {
            if (record != null && record.getMessage() != null) {
                output.append(record.getMessage());
            }
        }

        @Override
        public void flush() {
            // No buffered external resource.
        }

        @Override
        public void close() {
            // No external resource.
        }

        private String output() {
            return output.toString();
        }
    }
}
