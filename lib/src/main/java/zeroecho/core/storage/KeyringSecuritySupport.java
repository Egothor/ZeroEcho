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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.UserPrincipal;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import zeroecho.core.storage.KeyringException.Code;

/**
 * Cryptographic and filesystem validation for the encrypted keyring format.
 */
final class KeyringSecuritySupport {
    private KeyringSecuritySupport() {
    }

    /**
     * Derives the AES key-encryption key using PBKDF2-HMAC-SHA-256.
     *
     * @param password borrowed password; its temporary character copies are cleared
     * @param salt nonempty KDF salt, retained by neither this method nor the caller-facing key
     * @param iterations positive PBKDF2 iteration count selected by validated policy
     * @return newly allocated key bytes; the caller must clear them after use
     * @throws GeneralSecurityException if the KDF cannot be obtained or the provider rejects the specification
     */
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
    /**
     * Encrypts or decrypts one authenticated AES-GCM payload.
     *
     * @param mode JCA encryption or decryption mode
     * @param key raw AES key bytes
     * @param nonce GCM nonce bytes
     * @param aad additional authenticated bytes, not encrypted
     * @param input plaintext for encryption or authenticated ciphertext for decryption
     * @return newly allocated ciphertext with tag, or verified plaintext
     * @throws GeneralSecurityException if cipher initialization, authentication, or finalization fails
     */
    /* default */ static byte[] crypt(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] input)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(KeyringStore.GCM_TAG_BITS, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(input);
    }
    /**
     * Computes the keyring SHA-256 digest without retaining input bytes.
     *
     * @param value bytes to hash; must not be null
     * @return newly allocated 32-byte digest
     * @throws KeyringException with KEYRING_IO_FAILED if SHA-256 is unavailable
     * @throws NullPointerException if the input is null
     */
    @SuppressWarnings("PMD.PreserveStackTrace")
    /* default */ static byte[] digest(byte[] value) throws KeyringException {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (GeneralSecurityException exception) {
            throw new KeyringException(Code.KEYRING_IO_FAILED);
        }
    }
    /**
     * Reads a bounded complete keyring image without following a symbolic link.
     *
     * @param source path of the image to read
     * @return newly allocated image bytes; the caller must clear them when no longer needed
     * @throws IOException if reading fails, the size exceeds the limit, or the file changes size during reading
     */
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
    /**
     * Reads an image and rejects any length other than the required framing length.
     *
     * @param source file to read without following symbolic links
     * @param expected required image length, in bytes
     * @return newly allocated image of exactly the requested length
     * @throws IOException if the file cannot be read or has an invalid length
     */
    /* default */ static byte[] readFixedImage(Path source, int expected) throws IOException {
        byte[] image = readStoreImage(source);
        if (image.length != expected) {
            KeyringStore.wipe(image);
            throw new KeyringException(Code.KEYRING_FORMAT_INVALID);
        }
        return image;
    }
    /**
     * Applies the platform path policy before keyring access.
     *
     * @param requested requested keyring path
     * @param createParent whether the policy may create the secured parent directory
     * @return normalized path satisfying the platform policy
     * @throws IOException if ownership, permissions, links, or filesystem checks fail
     */
    /* default */ static Path securePath(Path requested, boolean createParent) throws IOException {
        return KeyringPlatformPolicy.INSTANCE.securePath(requested, createParent);
    }
    /**
     * Checks that an existing keyring file has the required owner and protection.
     *
     * @param file file to validate
     * @param expectedOwner required filesystem owner
     * @throws IOException if the platform security checks fail
     */
    /* default */ static void validateExistingFile(Path file, UserPrincipal expectedOwner) throws IOException {
        KeyringPlatformPolicy.INSTANCE.validateExistingFile(file, expectedOwner);
    }
    /**
     * Checks platform permissions for owner-only access.
     *
     * @param path file or directory to validate
     * @param directory whether directory permissions are required
     * @throws IOException if permissions or filesystem attributes fail the policy
     */
    /* default */ static void validateOwnerOnly(Path path, boolean directory) throws IOException {
        KeyringPlatformPolicy.INSTANCE.validateOwnerOnly(path, directory);
    }
    /**
     * Authenticates the nonce sidecar and checks that it belongs to the expected store.
     *
     * @param keyring main keyring path whose sibling nonce sidecar is read
     * @param owner required sidecar owner
     * @param expectedStoreId expected encoded store UUID
     * @param expectedPrefix expected nonce prefix
     * @param nonceReservationMacKey borrowed sidecar HMAC key
     * @return authenticated high-water counter, at least the minimum reservation
     * @throws IOException if reading, security checks, framing, identity, or tag verification fails
     * @throws GeneralSecurityException if the MAC provider cannot execute
     */
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

    /**
     * Encodes the nonce-reservation framing before its authentication tag is appended.
     *
     * @param storeId encoded store UUID
     * @param prefix nonce prefix bound to this store
     * @param highWater reserved nonce counter
     * @return newly allocated unauthenticated reservation bytes
     */
    /* default */ static byte[] encodeNonceReservation(byte[] storeId, int prefix, long highWater) {
        return ByteBuffer
                .allocate(KeyringStore.NONCE_RESERVATION_MAGIC.length + Integer.BYTES + KeyringStore.UUID_BYTES
                        + Integer.BYTES + Long.BYTES)
                .put(KeyringStore.NONCE_RESERVATION_MAGIC).putInt(KeyringStore.NONCE_RESERVATION_VERSION).put(storeId)
                .putInt(prefix).putLong(highWater).array();
    }

    /**
     * Computes HMAC-SHA-256 for the supplied key and transcript.
     *
     * @param key borrowed MAC key bytes
     * @param input bytes to authenticate
     * @return newly allocated 32-byte authentication tag
     * @throws GeneralSecurityException if the MAC is unavailable or rejects the key
     */
    /* default */ static byte[] hmac(byte[] key, byte[] input) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(input);
    }
}
