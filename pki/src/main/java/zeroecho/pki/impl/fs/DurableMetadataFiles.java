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

import java.nio.file.FileAlreadyExistsException;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Strict durable I/O for bounded filesystem metadata records.
 */
final class DurableMetadataFiles {

    private static final int FINAL_TEMP_CREATE_ATTEMPT = 15;
    private static final long ZERO_BYTES = 0L;
    private static final Set<PosixFilePermission> OWNER_ONLY =
            PosixFilePermissions.fromString("rw-------");
    private static final ThreadLocal<FaultInjector> FAULTS = new ThreadLocal<>();

    private DurableMetadataFiles() {
    }

    /**
     * Publishes a new bounded metadata record through an owned same-directory temporary file.
     *
     * <p>The caller serializes target creation or replacement. The temporary file is forced before
     * publication and the parent directory afterward.</p>
     *
     * @param target authoritative target path with a parent directory
     * @param maximumBytes positive inclusive encoded record length limit in bytes
     * @param encoder checked synchronous encoder writing one complete bounded record
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if the byte limit is not positive
     * @throws UncertainAfterMutationException if atomic move completed but its parent-directory force failed
     * @throws IOException if secure opening, bounded encoding, file forcing or atomic publication fails
     */
    /* default */ static void create(Path target, long maximumBytes, Encoder encoder) throws IOException {
        write(target, maximumBytes, encoder, false);
    }

    /**
     * Replaces an existing bounded metadata record through a forced same-directory temporary file.
     *
     * <p>The caller serializes target creation or replacement. The temporary file is forced before
     * publication and the parent directory afterward.</p>
     *
     * @param target authoritative target path with a parent directory
     * @param maximumBytes positive inclusive encoded record length limit in bytes
     * @param encoder checked synchronous encoder writing one complete bounded record
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if the byte limit is not positive
     * @throws UncertainAfterMutationException if atomic move completed but its parent-directory force failed
     * @throws IOException if secure opening, bounded encoding, file forcing or atomic publication fails
     */
    /* default */ static void replace(Path target, long maximumBytes, Encoder encoder) throws IOException {
        write(target, maximumBytes, encoder, true);
    }

    /**
     * Reads one complete bounded metadata record through a secure directory session.
     *
     * @param <T> decoded immutable metadata value type
     * @param target exact metadata file path with a parent directory
     * @param maximumBytes positive inclusive record byte limit
     * @param decoder checked decoder consuming one complete metadata record
     * @return decoder result after verifying that no trailing bytes remain
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if the byte limit is not positive
     * @throws IOException if secure opening, byte bounds, decoding, trailing-data validation or closure fails
     */
    /* default */ static <T> T read(Path target, long maximumBytes, Decoder<T> decoder) throws IOException {
        Objects.requireNonNull(decoder, "decoder");
        requireMaximum(maximumBytes);
        Path parent = requireParent(target);
        try (DurableDirectory directory = openDurableDirectory(parent);
                SeekableByteChannel channel = openRead(directory, target.getFileName());
                InputStream raw = Channels.newInputStream(channel);
                DataInputStream input = new DataInputStream(
                        new BufferedInputStream(new BoundedInputStream(raw, maximumBytes)))) {
            trip(FaultPoint.DECODE);
            T value = decoder.decode(input);
            if (input.read() >= 0) {
                throw new IOException("Trailing durable metadata data");
            }
            return value;
        }
    }

    /**
     * Lists immediate directory entries with an exact filename suffix in stable filename order.
     *
     * @param parent directory opened through the secure filesystem strategy
     * @param suffix literal filename suffix used to filter entries
     * @return immutable resolved paths sorted by filename
     * @throws NullPointerException if a required input is null
     * @throws IOException if the directory cannot be opened or enumerated
     */
    /* default */ static List<Path> list(Path parent, String suffix) throws IOException {
        Objects.requireNonNull(suffix, "suffix");
        List<Path> paths = new ArrayList<>();
        try (DurableDirectory directory = openDurableDirectory(parent)) {
            for (Path name : directory.listNames()) {
                if (name.toString().endsWith(suffix)) {
                    paths.add(parent.resolve(name));
                }
            }
        }
        paths.sort(Comparator.comparing(path -> path.getFileName().toString()));
        return List.copyOf(paths);
    }

    /**
     * Deletes one metadata entry and confirms durability of the parent namespace update.
     *
     * @param target exact metadata file path with a parent directory
     * @return true after deletion and confirmed directory force; false if the entry was absent
     * @throws NullPointerException if a required input is null
     * @throws UncertainAfterMutationException if deletion completed but directory durability could not be confirmed
     * @throws IOException if secure directory access or deletion fails
     */
    /* default */ static boolean delete(Path target) throws IOException {
        Path parent = requireParent(target);
        try (DurableDirectory directory = openDurableDirectory(parent)) {
            try {
                directory.deleteFile(target.getFileName());
            } catch (NoSuchFileException missing) {
                return false;
            }
        }
        try {
            trip(FaultPoint.DIRECTORY_FORCE_AFTER_DELETE);
            forceDirectory(parent);
            return true;
        } catch (IOException failure) {
            throw new UncertainAfterMutationException(Mutation.DELETE, failure);
        }
    }

    /**
     * Installs a deterministic persistence fault injector for the current thread.
     *
     * @param injector non-null fault callback replacing the thread's prior injector
     * @throws NullPointerException if a required input is null
     */
    /* default */ static void installFault(FaultInjector injector) {
        FAULTS.set(Objects.requireNonNull(injector, "injector"));
    }

    /**
     * Removes the current thread's deterministic persistence fault injector.
     *
     */
    /* default */ static void clearFault() {
        FAULTS.remove();
    }

    private static void write(Path target, long maximumBytes, Encoder encoder, boolean replace) throws IOException {
        Objects.requireNonNull(encoder, "encoder");
        requireMaximum(maximumBytes);
        Path parent = requireParent(target);
        Files.createDirectories(parent);
        Path temporary = createTemporary(parent);
        try {
            writeAndForce(temporary, maximumBytes, encoder);
        } catch (IOException failure) {
            cleanupAfterFailure(temporary, failure);
            throw failure;
        }
        try {
            trip(FaultPoint.MOVE);
            move(temporary, target, replace);
        } catch (IOException failure) {
            cleanupAfterFailure(temporary, failure);
            throw failure;
        }
        try {
            trip(FaultPoint.DIRECTORY_FORCE_AFTER_MOVE);
            forceDirectory(parent);
        } catch (IOException postMove) {
            throw new UncertainAfterMutationException(Mutation.MOVE, postMove);
        }
    }

    private static void move(Path source, Path target, boolean replace) throws IOException {
        if (replace) {
            AtomicPublish.replaceExisting(source, target);
        } else {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
        }
    }

    private static void cleanupAfterFailure(Path temporary, IOException failure) {
        try {
            trip(FaultPoint.CLEANUP);
            cleanupTemporary(temporary);
        } catch (IOException cleanupFailure) {
            failure.addSuppressed(cleanupFailure);
        }
    }

    private static Path createTemporary(Path parent) throws IOException {
        for (int attempt = 0; attempt < 16; attempt++) {
            trip(FaultPoint.TEMP_CREATE);
            Path candidate = parent.resolve(".metadata-" + UUID.randomUUID() + ".tmp");
            try (DurableDirectory directory = openDurableDirectory(parent)) {
                SeekableByteChannel ignored = directory.newByteChannel(candidate.getFileName(),
                        openOptions(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), fileAttributes(parent));
                try (ignored) {
                    return candidate;
                }
            } catch (FileAlreadyExistsException collision) {
                if (attempt == FINAL_TEMP_CREATE_ATTEMPT) {
                    throw new IOException("Unable to create durable metadata temporary file", collision);
                }
            }
        }
        throw new IOException("Unable to create durable metadata temporary file");
    }

    private static void writeAndForce(Path path, long maximumBytes, Encoder encoder) throws IOException {
        try (DurableDirectory directory = openDurableDirectory(path.getParent());
                SeekableByteChannel channel = directory.newByteChannel(path.getFileName(),
                        openOptions(StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING))) {
            if (!(channel instanceof FileChannel)) {
                throw new IOException("Durable metadata file forcing is unavailable");
            }
            try (DataOutputStream output = new DataOutputStream(
                    new BoundedOutputStream(Channels.newOutputStream(channel), maximumBytes))) {
                trip(FaultPoint.WRITE);
                encoder.encode(output);
                output.flush();
                trip(FaultPoint.FILE_FORCE);
                ((FileChannel) channel).force(true);
            }
        }
    }

    private static SeekableByteChannel openRead(DurableDirectory directory, Path name) throws IOException {
        return directory.newByteChannel(name, openOptions(StandardOpenOption.READ));
    }

    private static DurableDirectory openDurableDirectory(Path directory) throws IOException {
        trip(FaultPoint.SECURE_OPEN);
        return DurableDirectory.open(directory);
    }

    private static Set<OpenOption> openOptions(StandardOpenOption... options) {
        Set<OpenOption> selected = new HashSet<>();
        selected.addAll(EnumSet.copyOf(List.of(options)));
        selected.add(LinkOption.NOFOLLOW_LINKS);
        return Set.copyOf(selected);
    }

    private static FileAttribute<?>[] fileAttributes(Path parent) throws IOException {
        if (Files.getFileStore(parent).supportsFileAttributeView("posix")) {
            return new FileAttribute<?>[] { PosixFilePermissions.asFileAttribute(OWNER_ONLY) };
        }
        return new FileAttribute<?>[0];
    }

    private static void cleanupTemporary(Path temporary) throws IOException {
        try (DurableDirectory directory = openDurableDirectory(temporary.getParent())) {
            try {
                directory.deleteFile(temporary.getFileName());
            } catch (NoSuchFileException missing) {
                return;
            }
        }
        forceDirectory(temporary.getParent());
    }

    private static void forceDirectory(Path directory) throws IOException {
        SigningFormatSupport.forceDirectory(directory);
    }

    private static Path requireParent(Path target) throws IOException {
        Objects.requireNonNull(target, "target");
        Path parent = target.getParent();
        if (parent == null || target.getFileName() == null) {
            throw new IOException("Durable metadata target has no parent");
        }
        return parent;
    }

    private static void requireMaximum(long maximumBytes) {
        if (maximumBytes <= ZERO_BYTES) {
            throw new IllegalArgumentException("maximumBytes must be positive");
        }
    }

    private static void trip(FaultPoint point) throws IOException {
        FaultInjector injector = FAULTS.get();
        if (injector != null) {
            injector.fail(point);
        }
    }

    /**
     * Package-private streaming encoder used only by filesystem metadata persistence.
     */
    /* default */
    @FunctionalInterface
    interface Encoder {
        /**
         * Writes one complete bounded metadata record.
         * @param output borrowed destination stream for one complete bounded metadata record
         * @throws IOException if the bounded record cannot be written to the destination
         */
        void encode(DataOutputStream output) throws IOException;
    }

    /**
     * Package-private incremental decoder used only by filesystem metadata persistence.
     *
     * @param <T> decoded metadata value type
     */
    /* default */
    @FunctionalInterface
    interface Decoder<T> {
        /**
         * Decodes one complete bounded metadata record.
         * @param input borrowed source stream positioned at the start of one metadata record
         * @return decoded metadata value after bounded framing validation
         * @throws IOException if input is truncated, malformed or cannot be read
         */
        T decode(DataInputStream input) throws IOException;
    }

    /**
     * Package-private deterministic fault injection points.
     */
    /* default */ enum FaultPoint {
        /**
         * Fault injection point for temporary file creation.
         */
        TEMP_CREATE,
        /**
         * Fault injection point for file content writes.
         */
        WRITE,
        /**
         * Fault injection point for forcing file data and metadata.
         */
        FILE_FORCE,
        /**
         * Fault injection point for file publication by rename.
         */
        MOVE,
        /**
         * Fault injection point for forcing the parent directory after a rename.
         */
        DIRECTORY_FORCE_AFTER_MOVE,
        /**
         * Fault injection point for forcing the parent directory after deletion.
         */
        DIRECTORY_FORCE_AFTER_DELETE,
        /**
         * Fault injection point for opening a validated regular file.
         */
        SECURE_OPEN,
        /**
         * Fault injection point for decoding persisted content.
         */
        DECODE,
        /**
         * Fault injection point for cleanup of owned temporary artifacts.
         */
        CLEANUP
    }

    /**
     * Mutation whose namespace durability is uncertain.
     */
    /* default */ enum Mutation {
        /**
         * Publishes an owned temporary file by moving it into the authoritative namespace.
         */
        MOVE,
        /**
         * Deletes an existing metadata identity.
         */
        DELETE
    }

    /**
     * Path-free marker for a completed mutation with uncertain directory force.
     */
    /* default */ static final class UncertainAfterMutationException extends IOException {
        private static final long serialVersionUID = 6317105201345803018L;
        private final Mutation mutation;

        private UncertainAfterMutationException(Mutation mutation, IOException cause) {
            super("Durable metadata mutation completed but durability is uncertain: " + mutation.name(), cause);
            this.mutation = mutation;
        }

        /**
         * Returns the namespace mutation whose directory durability could not be confirmed.
         *
         * @return namespace mutation whose directory durability could not be confirmed
         */
        /* default */ Mutation mutation() {
            return mutation;
        }
    }

    /**
     * Package-private deterministic fault seam for focused filesystem tests;
     * it is not production API.
     */
    /* default */
    @FunctionalInterface
    interface FaultInjector {
        /**
         * Fails the selected operation point when requested by a focused test.
         * @param point exact deterministic failure boundary being observed
         * @throws IOException to inject a deterministic failure at the selected persistence boundary
         */
        void fail(FaultPoint point) throws IOException;
    }

    /**
     * Input wrapper rejecting records larger than their finite limit.
     */
    private static final class BoundedInputStream extends FilterInputStream {
        private long remaining;

        private BoundedInputStream(InputStream input, long maximumBytes) {
            super(input);
            this.remaining = maximumBytes;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public int read() throws IOException {
            if (remaining == ZERO_BYTES) {
                int extra = super.read();
                if (extra >= 0) {
                    throw new IOException("Durable metadata exceeds its size limit");
                }
                return -1;
            }
            int value = super.read();
            if (value >= 0) {
                remaining--;
            }
            return value;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            Objects.checkFromIndexSize(offset, length, bytes.length);
            if (length == 0) {
                return 0;
            }
            if (remaining == ZERO_BYTES) {
                return read();
            }
            int permitted = (int) Math.min(remaining, length);
            int read = super.read(bytes, offset, permitted);
            if (read > 0) {
                remaining -= read;
            }
            return read;
        }
    }

    /**
     * Output wrapper rejecting records larger than their finite limit.
     */
    private static final class BoundedOutputStream extends FilterOutputStream {
        private long remaining;

        private BoundedOutputStream(OutputStream output, long maximumBytes) {
            super(output);
            this.remaining = maximumBytes;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void write(int value) throws IOException {
            requireCapacity(1);
            out.write(value);
            remaining--;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void write(byte[] bytes, int offset, int length) throws IOException {
            Objects.checkFromIndexSize(offset, length, bytes.length);
            requireCapacity(length);
            out.write(bytes, offset, length);
            remaining -= length;
        }

        private void requireCapacity(int length) throws IOException {
            if (length > remaining) {
                throw new IOException("Durable metadata exceeds its size limit");
            }
        }
    }
}
