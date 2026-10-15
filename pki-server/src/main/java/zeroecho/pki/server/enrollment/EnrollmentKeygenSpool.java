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

package zeroecho.pki.server.enrollment;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Exclusive ciphertext-only spool. Durable descriptors and all resource reservations
 * belong to the enrollment coordinator; this owner supplies bounded file publication
 * and delivery. No file is deleted without the coordinator's authoritative expiry.
 */
final class EnrollmentKeygenSpool implements AutoCloseable { // NOPMD CyclomaticComplexity - One ciphertext spool owns publication, integrity and delivery leases; individual methods remain checked.
    private static final String PROCESS_LOCK_FILE = "process.lock";
    private final EnrollmentRuntimeConfiguration.KeygenArtifacts configuration;
    private final int maximumLeases;
    private final Observer observer;
    private final FileChannel lockChannel;
    private final FileLock processLock;
    private final Set<String> writers = new HashSet<>();
    private final Set<Lease> leases = new HashSet<>();
    private boolean fenced;
    private boolean closing;
    private boolean closed;
    /** Reports exhausted ciphertext-delivery capacity without exposing artifact identity. */
    /* default */ static final class CapacityUnavailable extends IOException {
        private static final long serialVersionUID = 1L;
        /* default */ CapacityUnavailable() { super("Enrollment ciphertext delivery capacity is exhausted"); }
    }
    /** Ciphertext durability boundaries exposed to deterministic fault injection. */
    /* default */ enum Phase { CIPHERTEXT_FORCED, CIPHERTEXT_RENAMED, DIRECTORY_FORCED, BEFORE_DELETE }
    /** Observes ciphertext publication without changing persistence ordering. */
    /* default */ @FunctionalInterface interface Observer {
        /**
         * Observes one durability boundary.
         * @param phase completed or imminent persistence boundary
         * @throws IOException when fault injection interrupts publication
         */
        void at(Phase phase) throws IOException;
    }

    /* default */ EnrollmentKeygenSpool(EnrollmentRuntimeConfiguration.KeygenArtifacts configuration, int maximumLeases) throws IOException {
        this(configuration, maximumLeases, phase -> { });
    }

    /* default */ EnrollmentKeygenSpool(EnrollmentRuntimeConfiguration.KeygenArtifacts configuration, int maximumLeases, Observer observer) throws IOException {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.observer = Objects.requireNonNull(observer, "observer");
        if (maximumLeases <= 0) {
            throw new IllegalArgumentException("Invalid delivery lease bound");
        }
        this.maximumLeases = maximumLeases;
        requirePrivateDirectory(configuration.directory());
        lockChannel = FileChannel.open(configuration.directory().resolve(PROCESS_LOCK_FILE), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        FileLock acquired = null; // NOPMD CloseResource - Ownership transfers to processLock; constructor failure and spool close release it.
        try {
            acquired = lockChannel.tryLock();
            if (acquired == null) {
                throw unavailable();
            }
            processLock = acquired;
        } catch (IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl - Failure cleanup must retain the original ownership, release and fencing guarantees for unchecked failures too.
            try (lockChannel) {
                if (acquired != null) {
                    acquired.close();
                }
            }
            throw failure;
        }
    }

    /** Publishes one previously reserved, client-encrypted body; no replacement is permitted. */
    /* default */ void publish(String id, byte[] ciphertext, String digest) throws IOException {
        Objects.requireNonNull(ciphertext, "ciphertext");
        if (ciphertext.length < 1 || ciphertext.length > configuration.maximumArtifactBytes()
                || !hash(ciphertext).equals(digest)) {
            throw unavailable();
        }
        synchronized (this) { // NOPMD AvoidSynchronizedStatement - Serializes this lifecycle owner’s state and lease transitions.
            requireOpen();
            if (writers.size() >= configuration.maximumConcurrentGenerations() || !writers.add(id)) {
                throw unavailable();
            }
        }
        try {
            Path temporary = path(id, ".part");
            Path target = path(id, ".cms");
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                throw unavailable();
            }
            try (FileChannel output = FileChannel.open(temporary, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(ciphertext);
                while (buffer.hasRemaining()) {
                    output.write(buffer);
                }
                output.force(true);
            }
            observer.at(Phase.CIPHERTEXT_FORCED);
            Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
            observer.at(Phase.CIPHERTEXT_RENAMED);
            forceDirectory();
        } catch (IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl - Failure cleanup must retain the original ownership, release and fencing guarantees for unchecked failures too.
            synchronized (this) { fenced = true; } // NOPMD AvoidSynchronizedStatement - Serializes this lifecycle owner’s state and lease transitions.
            throw unavailable(); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        } finally {
            synchronized (this) { writers.remove(id); } // NOPMD AvoidSynchronizedStatement - Serializes this lifecycle owner’s state and lease transitions.
        }
    }

    /** Validates exact retained bytes with one fixed buffer, without opening a delivery lease. */
    /* default */ void verify(String id, long length, String digest) throws IOException {
        synchronized (this) { requireOpen(); } // NOPMD AvoidSynchronizedStatement - Serializes this lifecycle owner’s state and lease transitions.
        try (FileChannel input = FileChannel.open(path(id, ".cms"), StandardOpenOption.READ)) { verify(input, length, digest); }
    }

    /** Opens an integrity-checked bounded borrower; close fails until every borrower is released. */
    /* default */ Lease acquire(String id, long length, String digest) throws IOException {
        synchronized (this) { // NOPMD AvoidSynchronizedStatement - Serializes this lifecycle owner’s state and lease transitions.
            requireOpen();
            if (leases.size() >= maximumLeases || writers.contains(id)) {
                throw new CapacityUnavailable();
            }
            FileChannel channel = FileChannel.open(path(id, ".cms"), StandardOpenOption.READ); // NOPMD CloseResource - Returned Lease owns the channel; failure closes it before transfer.
            try {
                verify(channel, length, digest);
                channel.position(0);
                Lease lease = new Lease(id, channel, length);
                leases.add(lease);
                return lease;
            } catch (IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException - Failure cleanup must retain the original ownership, release and fencing guarantees for unchecked failures too.
                channel.close();
                throw failure;
            }
        }
    }

    /** Deletes only the files of a durably expired descriptor, preserving active delivery leases. */
    // Checks active writers and leases atomically with ciphertext deletion.
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    /* default */ synchronized boolean deleteExpired(String id) throws IOException {
        requireOpen();
        if (writers.contains(id) || leases.stream().anyMatch(value -> value.id.equals(id))) {
            return false;
        }
        try {
            observer.at(Phase.BEFORE_DELETE);
            Files.deleteIfExists(path(id, ".part"));
            Files.deleteIfExists(path(id, ".cms"));
            forceDirectory();
            return true;
        } catch (IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException - Failure cleanup must retain the original ownership, release and fencing guarantees for unchecked failures too.
            fenced = true;
            throw unavailable(); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
    }

    /** Enumerates owned names for startup descriptor validation; never guesses that an unknown file is disposable. */
    /* default */ void inspectFiles(Consumer<String> owner) throws IOException {
        synchronized (this) { requireOpen(); } // NOPMD AvoidSynchronizedStatement - Serializes this lifecycle owner’s state and lease transitions.
        long count = 0;
        try (DirectoryStream<Path> files = Files.newDirectoryStream(configuration.directory())) {
            for (Path file : files) {
                String name = file.getFileName().toString();
                if (PROCESS_LOCK_FILE.equals(name)) {
                    continue;
                }
                if (++count > Math.multiplyExact((long) configuration.maximumArtifacts(), 2)
                        || !(name.endsWith(".cms") && name.length() == 68 || name.endsWith(".part") && name.length() == 69)) {
                    throw unavailable();
                }
                String id = name.substring(0, 64);
                token(id);
                if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                    throw unavailable();
                }
                owner.accept(id);
            }
        }
    }

    // Serializes closing/closed state with writer and lease draining before process-lock release.
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    @Override public synchronized void close() throws IOException {
        closing = true;
        if (closed) {
            return;
        }
        if (!writers.isEmpty() || !leases.isEmpty()) {
            throw unavailable();
        }
        processLock.close();
        lockChannel.close();
        closed = true;
    }

    /** Keeps one ciphertext artifact alive while its owned delivery stream is open. */
    /* default */ final class Lease implements AutoCloseable {
        private final String id;
        private final FileChannel channel;
        private final long length;
        private boolean opened;
        private boolean released;
        private Lease(String id, FileChannel channel, long length) { this.id = id; this.channel = channel; this.length = length; }

        // Atomically checks the lease's released/opened state before handing off its stream.
        @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
        /* default */ synchronized InputStream openStream() throws IOException {
            if (released || opened) {
                throw unavailable();
            }
            opened = true;
            InputStream source = Channels.newInputStream(channel); // NOPMD CloseResource - The returned bounded stream borrows the channel owned and closed by this Lease.
            return new InputStream() {
                private long remaining = length;
                @Override public int read() throws IOException {
                    byte[] single = new byte[1];
                    return read(single, 0, 1) == -1 ? -1 : single[0] & 255;
                }
                @Override public int read(byte[] bytes, int offset, int count) throws IOException {
                    Objects.checkFromIndexSize(offset, count, bytes.length);
                    synchronized (Lease.this) { // NOPMD AvoidSynchronizedStatement - Serializes this lifecycle owner’s state and lease transitions.
                        if (released) {
                            throw unavailable();
                        }
                        if (count == 0) {
                            return 0;
                        }
                        if (remaining == 0) {
                            return -1;
                        }
                        int size = source.read(bytes, offset, (int) Math.min(remaining, count));
                        if (size < 0) {
                            throw unavailable();
                        }
                        remaining -= size;
                        return size;
                    }
                }
                @Override public void close() throws IOException { Lease.this.close(); }
            };
        }

        @Override public void close() throws IOException {
            synchronized (EnrollmentKeygenSpool.this) { // NOPMD AvoidSynchronizedStatement - Serializes this lifecycle owner’s state and lease transitions.
                synchronized (this) { // NOPMD AvoidSynchronizedStatement - Serializes this lifecycle owner’s state and lease transitions.
                    if (released) {
                        return;
                    }
                    channel.close();
                    released = true;
                }
                leases.remove(this);
            }
        }
    }

    private void verify(FileChannel input, long length, String digest) throws IOException {
        token(digest);
        if (length < 1 || length > configuration.maximumArtifactBytes() || input.size() != length) {
            throw unavailable();
        }
        MessageDigest hash = sha256();
        ByteBuffer buffer = ByteBuffer.allocate(65_536);
        long count = 0;
        while (input.read(buffer) != -1) {
            buffer.flip();
            count += buffer.remaining();
            if (count > length) {
                throw unavailable();
            }
            hash.update(buffer);
            buffer.clear();
        }
        if (count != length || !MessageDigest.isEqual(hash.digest(), HexFormat.of().parseHex(digest))) {
            throw unavailable();
        }
    }

    private Path path(String id, String suffix) { token(id); return configuration.directory().resolve(id + suffix); }
    private static void token(String value) {
        if (value == null || value.length() != 64) {
            throw new IllegalArgumentException("Invalid ciphertext reference");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!(c >= '0' && c <= '9' || c >= 'a' && c <= 'f')) {
                throw new IllegalArgumentException("Invalid ciphertext reference");
            }
        }
    }
    /* default */ static String hash(byte[] bytes) { return HexFormat.of().formatHex(sha256().digest(bytes)); }
    private static MessageDigest sha256() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
    private void forceDirectory() throws IOException {
        try (FileChannel directory = FileChannel.open(configuration.directory(), StandardOpenOption.READ)) { directory.force(true); }
        observer.at(Phase.DIRECTORY_FORCED);
    }
    private void requireOpen() throws IOException { if (closed || closing || fenced) {
        throw unavailable();
    } }
    private static IOException unavailable() { return new IOException("Enrollment ciphertext storage is unavailable"); }
    private static void requirePrivateDirectory(Path directory) throws IOException {
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            throw unavailable();
        }
        PosixFileAttributeView posix = Files.getFileAttributeView(directory, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (posix != null) {
            for (PosixFilePermission permission : posix.readAttributes().permissions())
                {
                    if (!permission.name().startsWith("OWNER_")) {
                        throw unavailable();
                    }
                }
            return;
        }
        AclFileAttributeView acl = Files.getFileAttributeView(directory, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (acl == null) {
            throw unavailable();
        }
        for (AclEntry entry : acl.getAcl())
            {
                if (entry.type() == AclEntryType.ALLOW && !entry.principal().equals(acl.getOwner())) {
                    throw unavailable();
                }
            }
    }
}
