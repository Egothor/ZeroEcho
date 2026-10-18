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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;

import zeroecho.core.storage.KeyringException.Code;
import zeroecho.core.storage.KeyringFileOperations.Target;

/**
 * Default local monotonic authority for stateful signatures. Its directory must
 * be independently preserved outside keyring/PKI backup and restore domains.
 * Never roll back, clone, replace or reconstruct this authority. Losing it retires
 * its enrolled signing keys. All signing copies must consult the same authority.
 * A lifetime filesystem lock serializes all processes using this root. Closing
 * waits for admitted operations; callers own this resource separately from keyrings.
 * Records contain authenticated public commitments, never private-key material.
 */
public final class LocalStatefulSigningAuthority implements AutoCloseable { // NOPMD CyclomaticComplexity - Aggregate lifecycle/coordinator complexity; individual methods remain checked.
    private static final int HMAC_BYTES = 32;
    private static final int KEY_ID_HEX_LENGTH = 64;
    private static final int MAGIC = 0x5a455341;
    private static final int VERSION = 1;
    private static final int MAX_RECORD_BYTES = 32_768;
    private final Path root;
    private final UUID identity;
    private final FileChannel channel;
    private final FileLock lock;
    private final KeyringFileOperations operations;
    private boolean closed;
    private boolean poisoned;

    private LocalStatefulSigningAuthority(Path root, UUID identity, FileChannel channel,
            FileLock lock, KeyringFileOperations operations) {
        this.root = root;
        this.identity = identity;
        this.channel = channel;
        this.lock = lock;
        this.operations = operations;
    }

    /**
     * Creates an empty authority in a new owner-only directory. Creation never
     * replaces or repairs an existing directory and never enrolls existing keys.
     * @param directory new authority directory, outside all backup roots
     * @return exclusively owned authority
     * @throws IOException if secure durable initialization fails
     * @throws NullPointerException if directory is null
     */
    public static LocalStatefulSigningAuthority create(Path directory) throws IOException {
        return acquire(directory, true, KeyringFileOperations.NIO);
    }

    /**
     * Opens a previously initialized authority without creating missing state.
     * @param directory existing authority directory at its original location
     * @return exclusively owned authority
     * @throws IOException if missing, corrupt, moved, insecure or already owned
     * @throws NullPointerException if directory is null
     */
    public static LocalStatefulSigningAuthority open(Path directory) throws IOException {
        return acquire(directory, false, KeyringFileOperations.NIO);
    }

    /* default */ static LocalStatefulSigningAuthority acquire(Path directory, boolean create,
            KeyringFileOperations operations) throws IOException {
        Objects.requireNonNull(directory, "directory");
        Path requested = directory.toAbsolutePath().normalize();
        if (create) {
            Files.createDirectory(requested, KeyringPlatformPolicy.INSTANCE.directoryCreateAttributes());
            KeyringPlatformPolicy.INSTANCE.forceDirectory(requested.getParent());
        }
        KeyringSecuritySupport.validateOwnerOnly(requested, true);
        if (Files.isSymbolicLink(requested)) {
            throw recovery();
        }
        Path root = requested.toRealPath();
        Path fence = root.resolve("authority.lock");
        if (create) {
            Files.createFile(fence, KeyringPlatformPolicy.INSTANCE.fileCreateAttributes());
        }
        KeyringSecuritySupport.validateOwnerOnly(fence, false);
        FileChannel channel = FileChannel.open(fence, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
        FileLock lock = null; // NOPMD CloseResource - Exclusive authority fence ownership transfers on success; failure closes both lock and channel.
        boolean success = false;
        try { // NOPMD UseTryWithResources - Authority lifecycle owns both fence resources; close and failure cleanup release them in order.
            try {
                lock = channel.tryLock();
            } catch (OverlappingFileLockException busy) {
                throw new KeyringException(Code.KEYRING_ALREADY_OPEN); // NOPMD PreserveStackTrace - Expose stable redacted failure codes; provider and persisted-state details must not escape.
            }
            if (lock == null) {
                throw new KeyringException(Code.KEYRING_ALREADY_OPEN);
            }
            Path header = root.resolve("authority.bin");
            UUID identity = create ? UUID.randomUUID() : readIdentity(header, root);
            LocalStatefulSigningAuthority authority = new LocalStatefulSigningAuthority(root, identity, channel, lock, operations);
            if (create) {
                authority.writeIdentity(header);
            }
            success = true;
            return authority;
        } finally {
            if (!success) {
                try { // NOPMD UseTryWithResources - Authority lifecycle owns both fence resources; close and failure cleanup release them in order.
                    if (lock != null) {
                        lock.release();
                    }
                } finally {
                    channel.close();
                }
            }
        }
    }

    private static UUID readIdentity(Path header, Path root) throws IOException {
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(readBounded(header)))) {
            if (input.readInt() != MAGIC || input.readInt() != VERSION) { throw recovery(); }
            UUID identity = new UUID(input.readLong(), input.readLong());
            if (!root.toString().equals(input.readUTF()) || input.read() != -1) { throw recovery(); }
            return identity;
        }
    }

    private void writeIdentity(Path header) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(buffer)) {
            output.writeInt(MAGIC);
            output.writeInt(VERSION);
            output.writeLong(identity.getMostSignificantBits());
            output.writeLong(identity.getLeastSignificantBits());
            output.writeUTF(root.toString());
        }
        write(header, buffer.toByteArray());
    }

    /* default */ synchronized void ensureUsable(Path keyring) throws IOException { // NOPMD AvoidSynchronizedAtMethodLevel - Shares the authority monitor with keyring transactions; Java25 has no monitor pinning.
        if (closed || poisoned || !lock.isValid()) {
            throw recovery();
        }
        // Authority must not be a child of the directory normally copied with keys.
        if (root.startsWith(keyring.toRealPath().getParent())) {
            throw recovery();
        }
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(readBounded(root.resolve("authority.bin"))))) {
            if (input.readInt() != MAGIC || input.readInt() != VERSION
                    || input.readLong() != identity.getMostSignificantBits()
                    || input.readLong() != identity.getLeastSignificantBits()
                    || !root.toString().equals(input.readUTF()) || input.read() != -1) {
                throw recovery();
            }
        }
    }

    /* default */ record Binding(String keyId, String storeId, String keyring, String alias, String algorithm) { }
    /* default */ record State(Binding binding, long next, long capacity, boolean ready, byte[] digest) { }

    /* default */ synchronized State read(Binding binding, byte[] macKey) throws IOException, GeneralSecurityException { // NOPMD AvoidSynchronizedAtMethodLevel - Shares the authority monitor with keyring transactions; Java25 has no monitor pinning.
        ensureUsable(Path.of(binding.keyring()));
        byte[] image = readBounded(recordPath(binding));
        if (image.length < HMAC_BYTES) {
            throw recovery();
        }
        byte[] body = Arrays.copyOf(image, image.length - HMAC_BYTES);
        byte[] tag = Arrays.copyOfRange(image, image.length - HMAC_BYTES, image.length);
        if (!MessageDigest.isEqual(tag, KeyringSecuritySupport.hmac(macKey, body))) {
            throw recovery();
        }
        return decodeState(binding, body);
    }

    private State decodeState(Binding binding, byte[] body) throws IOException {
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
            if (input.readInt() != MAGIC || input.readInt() != VERSION
                    || !identity.toString().equals(input.readUTF()) || !root.toString().equals(input.readUTF())) {
                throw recovery();
            }
            Binding actual = new Binding(input.readUTF(), input.readUTF(), input.readUTF(), input.readUTF(), input.readUTF());
            long next = input.readLong();
            long capacity = input.readLong();
            int phase = input.readUnsignedByte();
            byte[] digest = input.readNBytes(32);
            if (!actual.equals(binding) || next < 0 || capacity <= 0 || next > capacity
                    || phase > 1 || digest.length != 32 || input.read() != -1) {
                throw recovery();
            }
            return new State(binding, next, capacity, phase == 1, digest);
        } catch (IllegalArgumentException invalid) {
            throw recovery(); // NOPMD PreserveStackTrace - Do not expose authenticated-state decoding details.
        }
    }

    /* default */ synchronized void enroll(State state, byte[] macKey) throws IOException, GeneralSecurityException { // NOPMD AvoidSynchronizedAtMethodLevel - Shares the authority monitor with keyring transactions; Java25 has no monitor pinning.
        ensureUsable(Path.of(state.binding().keyring()));
        if (Files.exists(recordPath(state.binding()), LinkOption.NOFOLLOW_LINKS)) {
            throw recovery();
        }
        save(state, macKey);
    }

    /* default */ synchronized void save(State state, byte[] macKey) throws IOException, GeneralSecurityException { // NOPMD AvoidSynchronizedAtMethodLevel - Shares the authority monitor with keyring transactions; Java25 has no monitor pinning.
        ensureUsable(Path.of(state.binding().keyring()));
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(buffer)) {
            output.writeInt(MAGIC);
            output.writeInt(VERSION);
            output.writeUTF(identity.toString());
            output.writeUTF(root.toString());
            output.writeUTF(state.binding().keyId());
            output.writeUTF(state.binding().storeId());
            output.writeUTF(state.binding().keyring());
            output.writeUTF(state.binding().alias());
            output.writeUTF(state.binding().algorithm());
            output.writeLong(state.next());
            output.writeLong(state.capacity());
            output.writeByte(state.ready() ? 1 : 0);
            output.write(state.digest());
        }
        byte[] body = buffer.toByteArray();
        byte[] tag = KeyringSecuritySupport.hmac(macKey, body);
        write(recordPath(state.binding()), ByteBuffer.allocate(body.length + tag.length).put(body).put(tag).array());
    }

    private Path recordPath(Binding binding) throws KeyringException {
        if (binding.keyId().length() != KEY_ID_HEX_LENGTH) {
            throw recovery();
        }
        try {
            HexFormat.of().parseHex(binding.keyId());
        } catch (IllegalArgumentException invalid) {
            throw recovery(); // NOPMD PreserveStackTrace - Do not expose persisted key identity details.
        }
        return root.resolve(binding.keyId() + ".state");
    }

    private static byte[] readBounded(Path path) throws IOException {
        KeyringSecuritySupport.validateOwnerOnly(path, false);
        try (FileChannel input = FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            long length = input.size();
            if (length < 1 || length > MAX_RECORD_BYTES) {
                throw recovery();
            }
            ByteBuffer bytes = ByteBuffer.allocate((int) length);
            while (bytes.hasRemaining()) {
                if (input.read(bytes) <= 0) {
                    throw recovery();
                }
            }
            if (input.read(ByteBuffer.allocate(1)) != -1) {
                throw recovery();
            }
            return bytes.array();
        }
    }

    private void write(Path target, byte[] image) throws IOException {
        if (image.length > MAX_RECORD_BYTES) {
            throw recovery();
        }
        Path temporary = null;
        boolean moved = false;
        try {
            temporary = operations.createTemporary(Target.STATEFUL_AUTHORITY, root, ".state-", ".tmp");
            operations.writeTemporary(Target.STATEFUL_AUTHORITY, temporary, image);
            operations.forceTemporary(Target.STATEFUL_AUTHORITY, temporary);
            operations.atomicReplace(Target.STATEFUL_AUTHORITY, temporary, target);
            moved = true;
            operations.forceDirectory(Target.STATEFUL_AUTHORITY, root);
        } catch (IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException - An unchecked failure after filesystem mutation poisons the authority and requires recovery.
            poisoned = true;
            throw recovery(); // NOPMD PreserveStackTrace - Emit only the stable recovery code after uncertain persistence.
        } finally {
            if (!moved && temporary != null) {
                try {
                    operations.deleteTemporary(Target.STATEFUL_AUTHORITY, temporary);
                } catch (IOException cleanup) {
                    poisoned = true;
                }
            }
        }
    }

    /* default */ static KeyringException recovery() {
        return new KeyringException(Code.KEYRING_STATEFUL_RECOVERY_REQUIRED);
    }

    /**
     * Releases exclusive authority ownership after admitted signing completes.
     * @throws IOException if releasing the filesystem fence fails
     */
    @Override
    public synchronized void close() throws IOException { // NOPMD AvoidSynchronizedAtMethodLevel - Shares the authority monitor with keyring transactions; Java25 has no monitor pinning.
        if (!closed) {
            closed = true;
            try { // NOPMD UseTryWithResources - Authority lifecycle owns both fence resources; close and failure cleanup release them in order.
                lock.release();
            } finally {
                channel.close();
            }
        }
    }
}
