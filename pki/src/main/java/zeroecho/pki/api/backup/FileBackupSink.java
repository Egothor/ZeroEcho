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
package zeroecho.pki.api.backup;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;
import zeroecho.pki.api.PkiId;

/** File-backed single-writer sink with durable publication and explicit source ownership. */
final class FileBackupSink implements BackupSink {

    private final Path directory;
    private final Path incomplete;
    private final Path published;
    private final PkiId id;
    private final long limit;
    private final Operations operations;
    private final MessageDigest digest = digest(); // NOPMD AvoidMessageDigestField - Thread-confined sink retains digest state across writes until single publication.
    private final OutputStream fileOutput;
    private final OutputStream output;
    private long length;
    private boolean outputClosed;
    private boolean failed;
    private boolean transferred;
    private boolean closed;
    /** Injectable filesystem boundaries for deterministic publication failure tests. */
    /* default */ interface Operations {
        /** Opens the incomplete file for writing.
         * @param file existing incomplete file
         * @return owned output stream
         * @throws IOException if opening fails
         */
        default OutputStream open(Path file) throws IOException {
            return Files.newOutputStream(file, StandardOpenOption.WRITE);
        }
        /** Flushes file content and metadata.
         * @param file file to force
         * @throws IOException if durability is unconfirmed
         */
        default void force(Path file) throws IOException {
            try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
                channel.force(true);
            }
        }
        /** Flushes directory metadata after publication.
         * @param directory parent directory
         * @throws IOException if durability is unconfirmed
         */
        default void forceDirectory(Path directory) throws IOException {
            try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
                channel.force(true);
            }
        }
        /** Atomically publishes the completed archive.
         * @param from incomplete archive
         * @param to published archive
         * @throws IOException if publication fails
         */
        default void publish(Path from, Path to) throws IOException {
            Files.move(from, to, StandardCopyOption.ATOMIC_MOVE);
        }
        /** Removes an owned file if present.
         * @param file owned file
         * @throws IOException if cleanup fails
         */
        default void delete(Path file) throws IOException { Files.deleteIfExists(file); }
    }

    /* default */ static BackupSink create(Path directory, PkiId id, BackupLimits limits) throws IOException {
        return new FileBackupSink(directory, id, limits, new Operations() { });
    }

    /* default */ FileBackupSink(Path directory, PkiId id, BackupLimits limits, Operations operations) throws IOException {
        this.directory = Objects.requireNonNull(directory, "directory");
        this.id = Objects.requireNonNull(id, "backupId");
        this.limit = Objects.requireNonNull(limits, "limits").compressedBytes();
        this.operations = Objects.requireNonNull(operations, "operations");
        this.incomplete = Files.createTempFile(directory, ".backup-", ".incomplete");
        this.published = incomplete.resolveSibling(incomplete.getFileName() + ".zip");
        try {
            this.fileOutput = operations.open(incomplete);
        } catch (IOException failure) {
            try { operations.delete(incomplete); } catch (IOException cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
        this.output = new OutputStream() {
            @Override public void write(int value) throws IOException {
                write(new byte[] { (byte) value }, 0, 1);
            }
            @Override public void write(byte[] bytes, int offset, int count) throws IOException {
                Objects.checkFromIndexSize(offset, count, bytes.length);
                requireWritable();
                if (count > limit - length) {
                    failed = true;
                    throw new IOException("BACKUP_COMPRESSED_LIMIT");
                }
                try {
                    fileOutput.write(bytes, offset, count);
                    digest.update(bytes, offset, count);
                    length += count;
                } catch (IOException failure) {
                    failed = true;
                    throw failure;
                }
            }
            @Override public void flush() throws IOException {
                requireWritable();
                try { fileOutput.flush(); } catch (IOException failure) { failed = true; throw failure; }
            }
            @Override public void close() throws IOException { closeOutput(); }
        };
    }

    private static MessageDigest digest() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    private void requireWritable() throws IOException {
        if (closed || transferred || failed || outputClosed) { throw new IOException("BACKUP_SINK_CLOSED"); }
    }

    @Override public OutputStream outputStream() throws IOException {
        requireWritable();
        return output;
    }

    private void closeOutput() throws IOException {
        if (!outputClosed) {
            try { fileOutput.close(); }
            catch (IOException failure) { failed = true; throw failure; }
            finally { outputClosed = true; }
        }
    }

    @Override public BackupSource complete() throws IOException {
        if (closed || transferred || failed) { throw new IOException("BACKUP_SINK_CLOSED"); }
        try {
            closeOutput();
            operations.force(incomplete);
            operations.publish(incomplete, published);
            operations.forceDirectory(directory);
            String commitment = HexFormat.of().formatHex(digest.digest());
            BackupSource source = new OwnedSource(id, published, length, commitment, operations);
            transferred = true;
            return source;
        } catch (IOException failure) {
            failed = true;
            throw new IOException("BACKUP_PUBLICATION_FAILED", failure);
        }
    }

    @Override public void close() throws IOException {
        if (closed || transferred) { return; }
        IOException failure = null;
        try { closeOutput(); } catch (IOException problem) { failure = problem; }
        for (Path path : new Path[] { incomplete, published }) {
            try { operations.delete(path); }
            catch (IOException problem) {
                if (failure == null) { failure = problem; } else { failure.addSuppressed(problem); }
            }
        }
        if (failure != null) { throw new IOException("BACKUP_CLEANUP_FAILED", failure); }
        closed = true;
    }

    /** Revocable source owning its archive and all open reader streams. */
    private static final class OwnedSource implements BackupSource {
        private final java.util.concurrent.locks.ReentrantLock lifecycle = new java.util.concurrent.locks.ReentrantLock();
        private final PkiId id;
        private final Path file;
        private final long length;
        private final String commitment;
        private final Operations operations;
        private final Set<InputStream> streams = new HashSet<>();
        private boolean closed;

        /* default */ OwnedSource(PkiId id, Path file, long length, String commitment, Operations operations) {
            this.id = id;
            this.file = file;
            this.length = length;
            this.commitment = commitment;
            this.operations = operations;
        }
        @Override public PkiId backupId() { return id; }
        @Override public long contentLength() { return length; }
        @Override public String sha256() { return commitment; }
        @Override public InputStream openStream() throws IOException {
            lifecycle.lock();
            try {
                return openStreamLocked();
            } finally {
                lifecycle.unlock();
            }
        }

        private InputStream openStreamLocked() throws IOException {
            if (closed) { throw new IOException("BACKUP_SOURCE_CLOSED"); }
            InputStream stream = new FilterInputStream(Files.newInputStream(file)) {
                @Override public void close() throws IOException {
                    try { super.close(); }
                    finally { removeStream(this); }
                }
            };
            streams.add(stream);
            return stream;
        }
        private void removeStream(InputStream stream) {
            lifecycle.lock();
            try {
                streams.remove(stream);
            } finally {
                lifecycle.unlock();
            }
        }

        @Override public void close() throws IOException {
            lifecycle.lock();
            try {
                closeLocked();
            } finally {
                lifecycle.unlock();
            }
        }

        private void closeLocked() throws IOException {
            IOException failure = null;
            for (InputStream stream : Set.copyOf(streams)) { // NOPMD CloseResource - Ownership is transferred to the enclosing lifecycle and its explicit close/stream completion; not a local resource.
                try { stream.close(); } catch (IOException problem) {
                    if (failure == null) { failure = problem; } else { failure.addSuppressed(problem); }
                }
            }
            try { operations.delete(file); } catch (IOException problem) {
                if (failure == null) { failure = problem; } else { failure.addSuppressed(problem); }
            }
            if (failure != null) { throw new IOException("BACKUP_CLEANUP_FAILED", failure); }
            closed = true;
        }
    }
}
