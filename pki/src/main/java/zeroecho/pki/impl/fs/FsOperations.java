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
package zeroecho.pki.impl.fs;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Filesystem I/O helpers for the PKI store implementation.
 *
 * <h2>Goals</h2>
 * <ul>
 * <li>Deterministic on-disk behavior.</li>
 * <li>Atomic updates via write-to-temp + move-into-place.</li>
 * <li>Best-effort durability (fsync) where the platform supports it.</li>
 * <li>Conservative file permissions (0700 for directories, 0600 for files) when
 * POSIX is available.</li>
 * <li>Targeted JUL diagnostics for unusual situations without logging any
 * sensitive material.</li>
 * </ul>
 *
 * <h2>Security</h2>
 * <p>
 * This class never logs file contents. Logged data is limited to paths and
 * operation outcomes.
 * </p>
 */
final class FsOperations {

    private static final Logger LOG = Logger.getLogger(FsOperations.class.getName());

    private static final Set<PosixFilePermission> DIR_0700 = EnumSet.of(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);

    private static final Set<PosixFilePermission> FILE_0600 = EnumSet.of(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE);

    private FsOperations() {
        // utility class
    }

    /**
     * Ensures the directory exists. If the filesystem supports POSIX attributes,
     * new directories are created with 0700.
     *
     * @param dir directory path
     * @throws IOException if directory cannot be created
     */
    /* default */ static void ensureDir(final Path dir) throws IOException {
        Objects.requireNonNull(dir, "dir");
        if (Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        Files.createDirectories(dir, dirAttributesIfSupported());
    }

    /**
     * Writes bytes to {@code target} atomically (best-effort).
     *
     * <p>
     * Implementation:
     * </p>
     * <ol>
     * <li>Create/overwrite a temp file next to {@code target} with safe permissions
     * (0600 when supported).</li>
     * <li>Write the content to temp.</li>
     * <li>fsync the temp file (best-effort).</li>
     * <li>Move temp into place. Prefer {@code ATOMIC_MOVE}, fallback to
     * replace.</li>
     * <li>fsync the parent directory (best-effort).</li>
     * </ol>
     *
     * @param target destination file
     * @param data   bytes to write
     * @throws IOException if writing fails
     */
    /* default */ static void writeAtomic(final Path target, final byte[] data) throws IOException {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(data, "data");

        final Path parent = requireParent(target);
        ensureDir(parent);

        final Path tmp = tempSibling(target);

        // If the tmp file exists, it indicates a previous crash or external
        // interference.
        // This is not fatal; we will overwrite it deterministically.
        if (Files.exists(tmp, LinkOption.NOFOLLOW_LINKS) && LOG.isLoggable(Level.FINE)) {
            LOG.log(Level.FINE, "Temporary file already exists; overwriting: {0}", tmp);
        }

        createOrTruncateTemp(tmp);

        // Write payload into tmp (do not log payload size/content here; size may be OK
        // but keep minimal).
        final OpenOption[] options = { StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE };

        try (OutputStream out = Files.newOutputStream(tmp, options)) {
            out.write(data);
            out.flush();
        }

        forceFileBestEffort(tmp);
        moveIntoPlace(tmp, target);
        forceDirectoryBestEffort(parent);
    }

    /**
     * Strictly persists one authoritative revocation journal image.
     *
     * <p>The namespace commit point is an {@link StandardCopyOption#ATOMIC_MOVE}
     * in the target directory. No non-atomic fallback is permitted. A directory
     * force failure after that move is reported distinctly because the durable
     * authoritative image is then uncertain.</p>
     *
     * @param target journal target
     * @param data complete encoded journal
     * @throws IOException on a pre-commit persistence failure
     * @throws DurabilityUncertainException after a committed move whose directory
     *                                     force failed
     */
    // The original directory-force cause is replaced by a marker that cannot expose
    // a filesystem path or operating-system diagnostic.
    @SuppressWarnings("PMD.PreserveStackTrace")
    /* default */ static void writeAtomicStrict(final Path target, final byte[] data) throws IOException {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(data, "data");
        Path parent = requireParent(target);
        ensureDir(parent);
        Path temporary = tempSibling(target);
        boolean moved = false;
        try {
            createOrTruncateTemp(temporary);
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer buffer = ByteBuffer.wrap(data);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            moved = true;
            try (FileChannel directory = FileChannel.open(parent, StandardOpenOption.READ)) {
                directory.force(true);
            } catch (IOException failure) {
                throw new DurabilityUncertainException();
            }
        } finally {
            if (!moved) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    /**
     * Atomically creates one immutable file and fails when the target exists.
     *
     * @param target immutable target
     * @param data complete encoded image
     * @throws IOException on persistence failure
     * @throws DurabilityUncertainException after an atomic move whose directory
     *                                     force failed
     */
    // The OS failure is deliberately replaced by the cause-free durability state.
    @SuppressWarnings("PMD.PreserveStackTrace")
    /* default */ static void writeNewAtomicStrict(final Path target, final byte[] data) throws IOException {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(data, "data");
        Path parent = requireParent(target);
        ensureDir(parent);
        Path temporary = tempSibling(target);
        boolean moved = false;
        try {
            Files.createFile(temporary, fileAttributesIfSupported());
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(data);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
            moved = true;
            try (FileChannel directory = FileChannel.open(parent, StandardOpenOption.READ)) {
                directory.force(true);
            } catch (IOException failure) {
                throw new DurabilityUncertainException();
            }
        } finally {
            if (!moved) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    /**
     * Signals a post-commit directory durability failure without exposing an
     * operating-system cause.
     */
    /* default */ static final class DurabilityUncertainException extends IOException {
        private static final long serialVersionUID = -2422560154076956224L;

        private DurabilityUncertainException() {
            super("filesystem durability unconfirmed");
        }
    }

    /**
     * Writes bytes to {@code target} as a write-once operation.
     *
     * <p>
     * If {@code target} exists, this method throws
     * {@link FileAlreadyExistsException}. New files are created with 0600
     * permissions when POSIX is available.
     * </p>
     *
     * @param target destination file
     * @param data   bytes to write
     * @throws IOException if writing fails
     */
    /* default */ static void writeNew(final Path target, final byte[] data) throws IOException {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(data, "data");

        final Path parent = requireParent(target);
        ensureDir(parent);

        Files.createFile(target, fileAttributesIfSupported());

        try (OutputStream out = Files.newOutputStream(target, StandardOpenOption.WRITE)) {
            out.write(data);
            out.flush();
        }

        forceFileBestEffort(target);
        forceDirectoryBestEffort(parent);
    }

    /**
     * Reads all bytes from {@code path}.
     *
     * @param path file path
     * @return file bytes
     * @throws IOException on read failure
     */
    /* default */ static byte[] readAll(final Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        return Files.readAllBytes(path);
    }

    /**
     * Opens an input stream for {@code path}.
     *
     * @param path file path
     * @return input stream
     * @throws IOException on failure
     */
    /* default */ static InputStream newInputStream(final Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        return Files.newInputStream(path, StandardOpenOption.READ);
    }

    /**
     * Opens an output stream for {@code path} (create/truncate).
     *
     * <p>
     * The caller is responsible for any atomicity requirements; use
     * {@link #writeAtomic(Path, byte[])} for atomic updates.
     * </p>
     *
     * @param path file path
     * @return output stream
     * @throws IOException on failure
     */
    /* default */ static OutputStream newOutputStream(final Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        final Path parent = requireParent(path);
        ensureDir(parent);
        return Files.newOutputStream(path, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);
    }

    private static void createOrTruncateTemp(final Path tmp) throws IOException {
        // We want deterministic permissions on tmp. If it doesn't exist, create with
        // attrs.
        // If it exists, truncate; permissions are best-effort (caller may have changed
        // them).
        if (!Files.exists(tmp, LinkOption.NOFOLLOW_LINKS)) {
            Files.createFile(tmp, fileAttributesIfSupported());
            return;
        }

        // Truncate by opening with TRUNCATE_EXISTING + WRITE and closing immediately.
        try (OutputStream ignored = Files.newOutputStream(tmp, StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE)) {
            // no-op
        }
    }

    private static void moveIntoPlace(final Path tmp, final Path target) throws IOException {
        try {
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "ATOMIC_MOVE not supported; falling back to REPLACE_EXISTING: {0} -> {1}",
                        new Object[] { tmp, target });
            }
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void forceFileBestEffort(final Path file) {
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
            ch.force(true);
        } catch (IOException e) {
            // Best-effort durability: never fail writes due to fsync limitations.
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "fsync file failed (best-effort): {0}", file);
            }
        }
    }

    private static void forceDirectoryBestEffort(final Path dir) {
        // Not all platforms allow opening directories for fsync; best-effort only.
        try (FileChannel ch = FileChannel.open(dir, StandardOpenOption.READ)) {
            ch.force(true);
        } catch (IOException e) {
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "fsync directory failed (best-effort): {0}", dir);
            }
        }
    }

    private static Path requireParent(final Path path) throws IOException {
        final Path parent = path.getParent();
        if (parent == null) {
            throw new IOException("Path has no parent directory: " + path);
        }
        return parent;
    }

    private static Path tempSibling(final Path target) {
        final String name = target.getFileName().toString();
        // Deterministic temp naming; safe because store is single-writer locked.
        return target.resolveSibling(name + ".tmp");
    }

    private static FileAttribute<?>[] dirAttributesIfSupported() {
        if (supportsPosix()) {
            return new FileAttribute<?>[] { PosixFilePermissions.asFileAttribute(DIR_0700) };
        }
        return new FileAttribute<?>[0];
    }

    private static FileAttribute<?>[] fileAttributesIfSupported() {
        if (supportsPosix()) {
            return new FileAttribute<?>[] { PosixFilePermissions.asFileAttribute(FILE_0600) };
        }
        return new FileAttribute<?>[0];
    }

    private static boolean supportsPosix() {
        final FileSystem fs = FileSystems.getDefault();
        return fs.supportedFileAttributeViews().contains("posix");
    }
}
