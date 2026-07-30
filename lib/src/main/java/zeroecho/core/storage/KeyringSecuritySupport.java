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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import zeroecho.core.storage.KeyringException.Code;

/** Cryptographic and filesystem validation for the encrypted keyring format. */
final class KeyringSecuritySupport {
    private KeyringSecuritySupport() {
    }

    /* default */ static byte[] deriveKek(KeyringPassword password, byte[] salt, int iterations)
            throws GeneralSecurityException {
        char[] chars = password.copy();
        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, KeyringStore.KEK_BYTES * Byte.SIZE);
        Arrays.fill(chars, '\0');
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }
    /* default */ static byte[] crypt(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] input)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(KeyringStore.GCM_TAG_BITS, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(input);
    }
    @SuppressWarnings("PMD.PreserveStackTrace")
    /* default */ static byte[] digest(byte[] value) throws KeyringException {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (GeneralSecurityException exception) {
            throw new KeyringException(Code.KEYRING_IO_FAILED);
        }
    }
    @SuppressWarnings("PMD.PreserveStackTrace")
    /* default */ static byte[] readStoreImage(Path source) throws IOException {
        try (FileChannel channel = FileChannel.open(source, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            long size = channel.size();
            if (size <= 0 || size > KeyringStore.MAX_FILE_BYTES) {
                throw new KeyringException(Code.KEYRING_LIMIT_EXCEEDED);
            }
            byte[] image = new byte[Math.toIntExact(size)];
            ByteBuffer target = ByteBuffer.wrap(image);
            while (target.hasRemaining()) {
                if (channel.read(target) < 0) {
                    KeyringStore.wipe(image);
                    throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
                }
            }
            ByteBuffer trailing = ByteBuffer.allocate(1);
            if (channel.read(trailing) >= 0) {
                KeyringStore.wipe(image);
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            return image;
        } catch (ArithmeticException exception) {
            throw new KeyringException(Code.KEYRING_LIMIT_EXCEEDED);
        }
    }
    /* default */ static byte[] readFixedImage(Path source, int expected) throws IOException {
        byte[] image = readStoreImage(source);
        if (image.length != expected) {
            KeyringStore.wipe(image);
            throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
        }
        return image;
    }
    @SuppressWarnings("PMD.PreserveStackTrace")
    /* default */ static Path securePath(Path requested, boolean createParent) throws IOException {
        Objects.requireNonNull(requested, "path must not be null");
        Path absolute = requested.toAbsolutePath().normalize();
        Path parent = absolute.getParent();
        if (parent == null) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        if (!Files.exists(parent, LinkOption.NOFOLLOW_LINKS)) {
            if (!createParent) {
                throw new KeyringException(Code.KEYRING_IO_FAILED);
            }
            try {
                Files.createDirectories(parent, KeyringStore.DIRECTORY_ATTRIBUTE);
            } catch (UnsupportedOperationException exception) {
                throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
            }
        }
        if (Files.isSymbolicLink(parent)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        FileStore store = Files.getFileStore(parent);
        if (!store.supportsFileAttributeView(PosixFileAttributeView.class)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        validateOwnerOnly(parent, true);
        if (Files.isSymbolicLink(absolute)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        return absolute;
    }
    @SuppressWarnings("PMD.PreserveStackTrace")
    /* default */ static void validateExistingFile(Path file, UserPrincipal expectedOwner) throws IOException {
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(file)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        validateOwnerOnly(file, false);
        PosixFileAttributes attributes = Files.readAttributes(file, PosixFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        if (!attributes.owner().equals(expectedOwner)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        try {
            Object links = Files.getAttribute(file, "unix:nlink", LinkOption.NOFOLLOW_LINKS);
            if (!(links instanceof Number number) || number.longValue() != 1L) {
                throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
            }
        } catch (UnsupportedOperationException exception) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
    }
    /* default */ static void validateOwnerOnly(Path path, boolean directory) throws IOException {
        PosixFileAttributes attributes = Files.readAttributes(path, PosixFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        Set<PosixFilePermission> expected = directory ? KeyringStore.DIRECTORY_PERMISSIONS : KeyringStore.FILE_PERMISSIONS;
        if (!attributes.permissions().equals(expected)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
    }
    /* default */ static long readNonceReservation(Path keyring, UserPrincipal owner, byte[] expectedStoreId,
            int expectedPrefix, byte[] nonceReservationMacKey) throws IOException, GeneralSecurityException {
        Path reservation = keyring.resolveSibling(keyring.getFileName() + ".nonce");
        validateExistingFile(reservation, owner);
        byte[] image = readFixedImage(reservation,
                KeyringStore.NONCE_RESERVATION_MAGIC.length + Integer.BYTES + KeyringStore.UUID_BYTES
                        + Integer.BYTES + Long.BYTES + KeyringStore.NONCE_RESERVATION_TAG_BYTES);
        byte[] authenticated = Arrays.copyOf(image, image.length - KeyringStore.NONCE_RESERVATION_TAG_BYTES);
        byte[] actualTag = Arrays.copyOfRange(image, authenticated.length, image.length);
        byte[] expectedTag = null;
        try {
            expectedTag = hmac(nonceReservationMacKey, authenticated);
            if (!MessageDigest.isEqual(actualTag, expectedTag)) {
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            ByteBuffer buffer = ByteBuffer.wrap(authenticated);
            byte[] magic = new byte[KeyringStore.NONCE_RESERVATION_MAGIC.length];
            buffer.get(magic);
            byte[] storeId = new byte[KeyringStore.UUID_BYTES];
            buffer.position(KeyringStore.NONCE_RESERVATION_MAGIC.length + Integer.BYTES);
            buffer.get(storeId);
            int prefix = buffer.getInt();
            long highWater = buffer.getLong();
            if (!MessageDigest.isEqual(magic, KeyringStore.NONCE_RESERVATION_MAGIC)
                    || ByteBuffer.wrap(authenticated, KeyringStore.NONCE_RESERVATION_MAGIC.length, Integer.BYTES)
                            .getInt() != KeyringStore.NONCE_RESERVATION_VERSION
                    || !MessageDigest.isEqual(storeId, expectedStoreId) || prefix != expectedPrefix
                    || highWater < KeyringStore.MIN_NONCE_HIGH_WATER) {
                throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
            }
            return highWater;
        } finally {
            KeyringStore.wipe(image);
            KeyringStore.wipe(authenticated);
            KeyringStore.wipe(actualTag);
            KeyringStore.wipe(expectedTag);
        }
    }

    /* default */ static byte[] encodeNonceReservation(byte[] storeId, int prefix, long highWater) {
        return ByteBuffer
                .allocate(KeyringStore.NONCE_RESERVATION_MAGIC.length + Integer.BYTES + KeyringStore.UUID_BYTES
                        + Integer.BYTES + Long.BYTES)
                .put(KeyringStore.NONCE_RESERVATION_MAGIC).putInt(KeyringStore.NONCE_RESERVATION_VERSION).put(storeId)
                .putInt(prefix).putLong(highWater).array();
    }

    /* default */ static byte[] hmac(byte[] key, byte[] input) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(input);
    }
}
