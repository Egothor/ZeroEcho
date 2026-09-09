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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;

import java.io.DataOutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class KeyringSigningConfigurationTagTest {
    private static final Duration HORIZON = Duration.ofDays(90);
    private static final String WORKFLOW_ID = "zeroecho-lib";
    private static final String KEY_REF_PREFIX = "zeroecho-lib:";
    private static final char[] PASSWORD = { 't', 'a', 'g', '-', 't', 'e', 's', 't' };
    private static final char[] REWRAPPED_PASSWORD = { 'r', 'e', 'w', 'r', 'a', 'p', 'p', 'e', 'd' };
    private static final int ITERATIONS_OFFSET = KeyringStore.MAGIC.length + Integer.BYTES
            + KeyringStore.UUID_BYTES + Byte.BYTES;
    private static final int SALT_OFFSET = ITERATIONS_OFFSET + Integer.BYTES;
    private static final int WRAP_NONCE_OFFSET = SALT_OFFSET + KeyringStore.SALT_BYTES
            + Integer.BYTES + Byte.BYTES;
    private static final int WRAPPED_MASTER_LENGTH_OFFSET = WRAP_NONCE_OFFSET + KeyringStore.NONCE_BYTES;
    private static final int WRAPPED_MASTER_OFFSET = WRAPPED_MASTER_LENGTH_OFFSET + Integer.BYTES;

    @TempDir
    Path temporaryDirectory;

    @Test
    void tagBindsResolvedConfigurationStoreAndEncryptedEntries() throws Exception {
        Path firstPath = temporaryDirectory.resolve("first.zek");
        byte[] firstKey = new byte[32];
        Arrays.fill(firstKey, (byte) 0x11);
        byte[] baseline;
        byte[] replaced;
        try (KeyringPassword password = password(); KeyringStore store = KeyringStore.create(firstPath, password)) {
            store.putSecret("signing", "AES", new SecretKeySpec(firstKey, "AES"));
            baseline = tag(store, HORIZON, KEY_REF_PREFIX, true);
            byte[] repeated = tag(store, HORIZON, KEY_REF_PREFIX, true);
            assertArrayEquals(baseline, repeated);
            assertNotSame(baseline, repeated);
            assertEquals(32, baseline.length);

            assertDifferent(baseline, tag(store, Duration.ofDays(91), KEY_REF_PREFIX, true));
            assertDifferent(baseline, tag(store, HORIZON, "alternate:", true));
            assertDifferent(baseline, tag(store, HORIZON, KEY_REF_PREFIX, false));
            assertDifferent(baseline, tag(store, "alternate-workflow", HORIZON, KEY_REF_PREFIX, true));

            byte[] replacementKey = new byte[32];
            Arrays.fill(replacementKey, (byte) 0x22);
            try {
                store.putSecret("signing", "AES", new SecretKeySpec(replacementKey, "AES"));
                replaced = tag(store, HORIZON, KEY_REF_PREFIX, true);
                assertDifferent(baseline, replaced);
            } finally {
                Arrays.fill(replacementKey, (byte) 0);
            }
        } finally {
            Arrays.fill(firstKey, (byte) 0);
        }

        try (KeyringPassword password = password(); KeyringStore reopened = KeyringStore.open(firstPath, password)) {
            assertArrayEquals(replaced, tag(reopened, HORIZON, KEY_REF_PREFIX, true));
        }

        Path copiedPath = temporaryDirectory.resolve("copied.zek");
        Files.copy(firstPath, copiedPath, StandardCopyOption.COPY_ATTRIBUTES);
        Files.copy(sidecar(firstPath), sidecar(copiedPath), StandardCopyOption.COPY_ATTRIBUTES);
        try (KeyringPassword password = password(); KeyringStore copied = KeyringStore.open(copiedPath, password)) {
            assertArrayEquals(replaced, tag(copied, HORIZON, KEY_REF_PREFIX, true));
        }
        rewrap(copiedPath, PASSWORD, REWRAPPED_PASSWORD);
        try (KeyringPassword password = password(REWRAPPED_PASSWORD);
                KeyringStore rewrapped = KeyringStore.open(copiedPath, password)) {
            assertArrayEquals(replaced, tag(rewrapped, HORIZON, KEY_REF_PREFIX, true));
        }

        Path secondPath = temporaryDirectory.resolve("second.zek");
        try (KeyringPassword password = password(); KeyringStore second = KeyringStore.create(secondPath, password)) {
            assertDifferent(tag(second, HORIZON, KEY_REF_PREFIX, true), replaced);
        } finally {
            Arrays.fill(baseline, (byte) 0);
            Arrays.fill(replaced, (byte) 0);
        }
    }

    @Test
    void transcriptBindsEveryEntryIdentityAndMetadataFieldIndependently() throws Exception {
        byte[] masterKey = new byte[KeyringStore.MASTER_KEY_BYTES];
        byte[] storeId = new byte[KeyringStore.UUID_BYTES];
        byte[] entryId = new byte[KeyringStore.UUID_BYTES];
        byte[] digest = new byte[KeyringStore.SHA256_BYTES];
        Arrays.fill(masterKey, (byte) 0x31);
        Arrays.fill(storeId, (byte) 0x42);
        Arrays.fill(entryId, (byte) 0x53);
        Arrays.fill(digest, (byte) 0x64);
        TranscriptEntry baselineEntry = new TranscriptEntry(entryId, 0, "signing", "AES", 3, 4, 5, 48, digest);
        byte[] baseline = transcriptTag(masterKey, storeId, baselineEntry);
        List<TranscriptEntry> isolatedChanges = List.of(
                baselineEntry.withEntryId(changed(entryId)),
                baselineEntry.withPosition(1),
                baselineEntry.withAlias("alternate"),
                baselineEntry.withAlgorithm("HmacSHA256"),
                baselineEntry.withKind(6),
                baselineEntry.withEncoding(7),
                baselineEntry.withHmacVariant(8),
                baselineEntry.withCiphertextLength(49),
                baselineEntry.withDigest(changed(digest)));
        try {
            for (TranscriptEntry changedEntry : isolatedChanges) {
                byte[] candidate = transcriptTag(masterKey, storeId, changedEntry);
                try {
                    assertDifferent(baseline, candidate);
                } finally {
                    Arrays.fill(candidate, (byte) 0);
                }
            }
        } finally {
            Arrays.fill(masterKey, (byte) 0);
            Arrays.fill(storeId, (byte) 0);
            Arrays.fill(entryId, (byte) 0);
            Arrays.fill(digest, (byte) 0);
            Arrays.fill(baseline, (byte) 0);
        }
    }

    private static byte[] tag(KeyringStore store, Duration horizon, String prefix, boolean requireSuffix)
            throws Exception {
        return tag(store, WORKFLOW_ID, horizon, prefix, requireSuffix);
    }

    private static byte[] tag(KeyringStore store, String workflowId, Duration horizon, String prefix,
            boolean requireSuffix) throws Exception {
        return store.zeroEchoSigningConfigurationTag(workflowId, horizon, prefix, requireSuffix);
    }

    private static void assertDifferent(byte[] first, byte[] second) {
        assertFalse(Arrays.equals(first, second));
    }

    private static KeyringPassword password() {
        return password(PASSWORD);
    }

    private static KeyringPassword password(char[] value) {
        return new KeyringPassword(value.clone());
    }

    private static Path sidecar(Path keyring) {
        return keyring.resolveSibling(keyring.getFileName() + ".nonce");
    }

    private static void rewrap(Path path, char[] oldPassword, char[] newPassword) throws Exception {
        byte[] image = Files.readAllBytes(path);
        byte[] oldSalt = Arrays.copyOfRange(image, SALT_OFFSET, SALT_OFFSET + KeyringStore.SALT_BYTES);
        byte[] oldNonce = Arrays.copyOfRange(image, WRAP_NONCE_OFFSET,
                WRAP_NONCE_OFFSET + KeyringStore.NONCE_BYTES);
        int wrappedLength = ByteBuffer.wrap(image, WRAPPED_MASTER_LENGTH_OFFSET, Integer.BYTES).getInt();
        assertEquals(KeyringStore.MASTER_KEY_BYTES + KeyringStore.GCM_TAG_BYTES, wrappedLength);
        byte[] oldWrapped = Arrays.copyOfRange(image, WRAPPED_MASTER_OFFSET,
                WRAPPED_MASTER_OFFSET + wrappedLength);
        byte[] oldAad = Arrays.copyOf(image, WRAP_NONCE_OFFSET);
        byte[] newSalt = new byte[KeyringStore.SALT_BYTES];
        byte[] newNonce = new byte[KeyringStore.NONCE_BYTES];
        Arrays.fill(newSalt, (byte) 0x6a);
        Arrays.fill(newNonce, (byte) 0x7b);
        newNonce[0] = 1;
        byte[] oldKek = null;
        byte[] masterKey = null;
        byte[] newKek = null;
        byte[] newWrapped = null;
        byte[] newAad = null;
        int iterations = ByteBuffer.wrap(image, ITERATIONS_OFFSET, Integer.BYTES).getInt();
        try (KeyringPassword oldValue = password(oldPassword);
                KeyringPassword newValue = password(newPassword)) {
            oldKek = KeyringSecuritySupport.deriveKek(oldValue, oldSalt, iterations);
            masterKey = KeyringSecuritySupport.crypt(Cipher.DECRYPT_MODE, oldKek, oldNonce, oldAad, oldWrapped);
            System.arraycopy(newSalt, 0, image, SALT_OFFSET, newSalt.length);
            System.arraycopy(newNonce, 0, image, WRAP_NONCE_OFFSET, newNonce.length);
            newAad = Arrays.copyOf(image, WRAP_NONCE_OFFSET);
            newKek = KeyringSecuritySupport.deriveKek(newValue, newSalt, iterations);
            newWrapped = KeyringSecuritySupport.crypt(Cipher.ENCRYPT_MODE, newKek, newNonce, newAad, masterKey);
            assertEquals(wrappedLength, newWrapped.length);
            System.arraycopy(newWrapped, 0, image, WRAPPED_MASTER_OFFSET, newWrapped.length);
            Files.write(path, image);
        } finally {
            wipe(image, oldSalt, oldNonce, oldWrapped, oldAad, newSalt, newNonce, oldKek, masterKey,
                    newKek, newWrapped, newAad);
        }
    }

    private static byte[] transcriptTag(byte[] masterKey, byte[] storeId, TranscriptEntry entry) throws Exception {
        return KeyringSigningConfigurationKdf.tag(masterKey, storeId, WORKFLOW_ID, HORIZON,
                KEY_REF_PREFIX, true, List.of(entry));
    }

    private static byte[] changed(byte[] value) {
        byte[] changed = value.clone();
        changed[0] ^= 1;
        return changed;
    }

    private static void wipe(byte[]... values) {
        for (byte[] value : values) {
            if (value != null) Arrays.fill(value, (byte) 0);
        }
    }

    private record TranscriptEntry(byte[] entryId, int position, String alias, String algorithm,
            int kind, int encoding, int hmacVariant, int ciphertextLength, byte[] digest)
            implements KeyringSigningConfigurationKdf.EntryView {
        @Override
        public void writeSigningConfigurationIdentity(DataOutputStream output) throws java.io.IOException {
            KeyringSigningConfigurationKdf.writeBytes(output, entryId);
            KeyringSigningConfigurationKdf.writeInt(output, position);
            KeyringSigningConfigurationKdf.writeString(output, alias);
            KeyringSigningConfigurationKdf.writeString(output, algorithm);
            KeyringSigningConfigurationKdf.writeInt(output, kind);
            KeyringSigningConfigurationKdf.writeInt(output, encoding);
            KeyringSigningConfigurationKdf.writeInt(output, hmacVariant);
            KeyringSigningConfigurationKdf.writeInt(output, ciphertextLength);
            KeyringSigningConfigurationKdf.writeBytes(output, digest);
        }

        private TranscriptEntry withEntryId(byte[] value) {
            return new TranscriptEntry(value, position, alias, algorithm, kind, encoding, hmacVariant,
                    ciphertextLength, digest);
        }
        private TranscriptEntry withPosition(int value) {
            return new TranscriptEntry(entryId, value, alias, algorithm, kind, encoding, hmacVariant,
                    ciphertextLength, digest);
        }
        private TranscriptEntry withAlias(String value) {
            return new TranscriptEntry(entryId, position, value, algorithm, kind, encoding, hmacVariant,
                    ciphertextLength, digest);
        }
        private TranscriptEntry withAlgorithm(String value) {
            return new TranscriptEntry(entryId, position, alias, value, kind, encoding, hmacVariant,
                    ciphertextLength, digest);
        }
        private TranscriptEntry withKind(int value) {
            return new TranscriptEntry(entryId, position, alias, algorithm, value, encoding, hmacVariant,
                    ciphertextLength, digest);
        }
        private TranscriptEntry withEncoding(int value) {
            return new TranscriptEntry(entryId, position, alias, algorithm, kind, value, hmacVariant,
                    ciphertextLength, digest);
        }
        private TranscriptEntry withHmacVariant(int value) {
            return new TranscriptEntry(entryId, position, alias, algorithm, kind, encoding, value,
                    ciphertextLength, digest);
        }
        private TranscriptEntry withCiphertextLength(int value) {
            return new TranscriptEntry(entryId, position, alias, algorithm, kind, encoding, hmacVariant,
                    value, digest);
        }
        private TranscriptEntry withDigest(byte[] value) {
            return new TranscriptEntry(entryId, position, alias, algorithm, kind, encoding, hmacVariant,
                    ciphertextLength, value);
        }
    }
}
