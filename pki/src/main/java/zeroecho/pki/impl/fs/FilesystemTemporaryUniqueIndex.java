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
package zeroecho.pki.impl.fs;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.DirectoryStream;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

import zeroecho.pki.api.content.DurableContentOwner;
import zeroecho.pki.spi.store.TemporaryUniqueIndex;

/** File-backed exact set using fixed-length, self-verifying physical keys. */
final class FilesystemTemporaryUniqueIndex implements TemporaryUniqueIndex {

    private static final int MAX_VALUE_BYTES = 640;
    private static final int RECORD_VERSION = 1;
    private static final int MAX_RECORD_BYTES = 1 + Integer.BYTES + MAX_VALUE_BYTES;
    private static final int SHA256_KEY_HEX_CHARS = 64;
    private static final byte[] GENERAL_DOMAIN =
            "zeroecho:pki:temporary-unique-index:v2".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] OWNER_DOMAIN =
            "zeroecho:pki:durable-content-owner-index:v1".getBytes(StandardCharsets.US_ASCII);

    private final Path directory;
    private final byte[] domain;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final ReentrantLock lock = new ReentrantLock();

    private FilesystemTemporaryUniqueIndex(Path directory, byte[] domain) {
        this.directory = Objects.requireNonNull(directory, "directory");
        this.domain = domain.clone();
    }

    /* default */ static FilesystemTemporaryUniqueIndex general(Path directory) {
        return new FilesystemTemporaryUniqueIndex(directory, GENERAL_DOMAIN);
    }

    /* default */ static FilesystemTemporaryUniqueIndex owners(Path directory) {
        return new FilesystemTemporaryUniqueIndex(directory, OWNER_DOMAIN);
    }

    /* default */ static String ownerKey(DurableContentOwner owner) {
        Objects.requireNonNull(owner, "owner");
        return key(OWNER_DOMAIN, owner.canonicalForm().getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public boolean add(byte[] value) throws IOException {
        requireValue(value);
        Path entry = directory.resolve(key(domain, value));
        lock.lock();
        try {
            try {
                requireRecord(entry, value);
                return false;
            } catch (NoSuchFileException missing) {
                writeRecord(entry, value);
                return true;
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public boolean contains(byte[] value) throws IOException {
        requireValue(value);
        Path entry = directory.resolve(key(domain, value));
        lock.lock();
        try {
            try {
                requireRecord(entry, value);
                return true;
            } catch (NoSuchFileException missing) {
                return false;
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public boolean remove(byte[] value) throws IOException {
        requireValue(value);
        Path entry = directory.resolve(key(domain, value));
        lock.lock();
        try {
            try {
                requireRecord(entry, value);
            } catch (NoSuchFileException missing) {
                return false;
            }
            DurableMetadataFiles.delete(entry);
            return true;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void validateNamespace() throws IOException {
        requireOpen();
        lock.lock();
        try {
            if (!Files.exists(directory)) {
                return;
            }
            try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
                for (Path entry : entries) {
                    requireCommittedName(entry);
                    byte[] value = readRecord(entry);
                    try {
                        requireCanonicalOwner(value);
                        String actualKey = entry.getFileName().toString();
                        if (!actualKey.equals(key(domain, value))) {
                            throw integrityFailure();
                        }
                    } finally {
                        Arrays.fill(value, (byte) 0);
                    }
                }
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void close() throws IOException {
        lock.lock();
        try {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            if (Files.isDirectory(directory)) {
                try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
                    for (Path entry : entries) {
                        DurableMetadataFiles.delete(entry);
                    }
                }
            }
            Files.deleteIfExists(directory);
        } finally {
            lock.unlock();
        }
    }

    private void requireValue(byte[] value) throws IOException {
        Objects.requireNonNull(value, "value");
        requireOpen();
        if (value.length == 0 || value.length > MAX_VALUE_BYTES) {
            throw new IOException("Index element exceeds filesystem adapter capability");
        }
    }

    private void requireOpen() {
        if (closed.get()) {
            throw new IllegalStateException("Temporary uniqueness index is closed");
        }
    }

    private static void writeRecord(Path entry, byte[] value) throws IOException {
        DurableMetadataFiles.create(entry, MAX_RECORD_BYTES, output -> {
            output.writeByte(RECORD_VERSION);
            output.writeInt(value.length);
            output.write(value);
        });
    }

    private static void requireRecord(Path entry, byte[] expected) throws IOException {
        byte[] actual = readRecord(entry);
        try {
            if (!MessageDigest.isEqual(actual, expected)) {
                throw integrityFailure();
            }
        } finally {
            Arrays.fill(actual, (byte) 0);
        }
    }

    private static byte[] readRecord(Path entry) throws IOException {
        return DurableMetadataFiles.read(entry, MAX_RECORD_BYTES, input -> {
            if (input.readUnsignedByte() != RECORD_VERSION) {
                throw new IOException("Unsupported uniqueness index record");
            }
            int length = input.readInt();
            if (length <= 0 || length > MAX_VALUE_BYTES) {
                throw new IOException("Invalid uniqueness index record length");
            }
            byte[] actual = input.readNBytes(length);
            if (actual.length != length || input.read() >= 0) {
                Arrays.fill(actual, (byte) 0);
                throw integrityFailure();
            }
            return actual;
        });
    }

    private static void requireCommittedName(Path entry) throws IOException {
        String name = entry.getFileName().toString();
        if (name.length() != SHA256_KEY_HEX_CHARS) {
            throw integrityFailure();
        }
        for (int index = 0; index < name.length(); index++) {
            char current = name.charAt(index);
            if (!((current >= '0' && current <= '9') || (current >= 'a' && current <= 'f'))) {
                throw integrityFailure();
            }
        }
    }

    private void requireCanonicalOwner(byte[] value) throws IOException {
        if (!Arrays.equals(domain, OWNER_DOMAIN)) {
            return;
        }
        String encoded;
        try {
            encoded = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(value)).toString();
        } catch (CharacterCodingException exception) {
            throw integrityFailure(exception);
        }
        int separator = encoded.indexOf(':');
        try {
            if (separator <= 0 || separator == encoded.length() - 1) {
                throw integrityFailure();
            }
            DurableContentOwner.Category category = DurableContentOwner.Category.valueOf(
                    encoded.substring(0, separator));
            DurableContentOwner owner = new DurableContentOwner(category, encoded.substring(separator + 1));
            if (!MessageDigest.isEqual(value, owner.canonicalForm().getBytes(StandardCharsets.UTF_8))) {
                throw integrityFailure();
            }
        } catch (IllegalArgumentException exception) {
            throw integrityFailure(exception);
        }
    }

    private static IOException integrityFailure() {
        return new IOException("Uniqueness index collision or substitution: code=CONTENT_INTEGRITY_FAILED");
    }

    private static IOException integrityFailure(Throwable cause) {
        return new IOException("Uniqueness index collision or substitution: code=CONTENT_INTEGRITY_FAILED", cause);
    }

    private static String key(byte[] domain, byte[] value) {
        MessageDigest digest = sha256();
        updateLength(digest, domain.length);
        digest.update(domain);
        updateLength(digest, value.length);
        digest.update(value);
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void updateLength(MessageDigest digest, int length) {
        digest.update((byte) (length >>> 24));
        digest.update((byte) (length >>> 16));
        digest.update((byte) (length >>> 8));
        digest.update((byte) length);
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

}
