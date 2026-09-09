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

import java.io.Closeable;
import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Platform-neutral bounded-directory session for the durable PKI store.
 *
 * <p>
 * The store performs its metadata mutations relative to a single owner-only
 * parent directory: create a temporary sibling, force it, atomically publish it,
 * force the directory, delete stragglers. On POSIX these operations run against a
 * {@link SecureDirectoryStream}, which resolves each name relative to an open
 * directory descriptor and is therefore immune to a concurrent rename or symlink
 * swap of an ancestor component (a TOCTOU defence). Windows and other filesystems
 * that do not provide a {@code SecureDirectoryStream} cannot offer descriptor-
 * relative resolution; there the same operations are performed by resolving each
 * name against the directory {@link Path}.
 * </p>
 *
 * <p>
 * Both implementations enforce {@link LinkOption#NOFOLLOW_LINKS} at every open so
 * that a symlink planted in place of an expected regular file is rejected rather
 * than followed, and the store's parent directory is owner-only (POSIX
 * {@code 0700} bits or an inheritable owner-only NTFS ACL), so an unprivileged
 * third party cannot introduce such a component in the first place. The
 * descriptor-relative guarantee is therefore a defence-in-depth strengthening on
 * POSIX rather than the sole protection; dropping it on Windows narrows the
 * threat model to a race by a process already holding write access to the
 * owner-only store, which is outside the store's threat model.
 * </p>
 *
 * <p>
 * Instances are not thread-safe and are used within a single {@code try}-with-
 * resources scope. {@link #close()} releases the underlying descriptor on POSIX
 * and is a no-op on the path-resolved backend.
 * </p>
 */
interface DurableDirectory extends Closeable {

    /**
     * @return the directory this session operates within (never {@code null})
     */
    Path directory();

    /**
     * @return {@code true} when name resolution is bound to an open directory
     *         descriptor and therefore immune to concurrent ancestor renames
     *         (POSIX); {@code false} when names are resolved against the path
     */
    boolean descriptorRelative();

    /**
     * Opens a byte channel for a name directly within this directory.
     *
     * @param name       single-component file name within this directory
     * @param options    open options (must include {@link LinkOption#NOFOLLOW_LINKS})
     * @param attributes create-time attributes (owner-only bits on POSIX; empty
     *                   where owner-only access is carried by ACL inheritance)
     * @return the opened channel
     * @throws IOException if the channel cannot be opened
     */
    SeekableByteChannel newByteChannel(Path name, Set<? extends OpenOption> options,
            FileAttribute<?>... attributes) throws IOException;

    /**
     * Deletes a name directly within this directory.
     *
     * @param name single-component file name within this directory
     * @throws java.nio.file.NoSuchFileException if the name does not exist
     * @throws IOException                       if the delete fails for another reason
     */
    void deleteFile(Path name) throws IOException;

    /**
     * Reads an attribute view for a name directly within this directory.
     *
     * @param <V>     attribute-view type
     * @param name    single-component file name within this directory
     * @param type    attribute-view class
     * @param options link options (typically {@link LinkOption#NOFOLLOW_LINKS})
     * @return the view, or {@code null} if unsupported
     */
    <V extends FileAttributeView> V getFileAttributeView(Path name, Class<V> type, LinkOption... options);

    /**
     * Lists the single-component file names contained in this directory.
     *
     * @return the file-name components (unsorted)
     * @throws IOException if the directory cannot be enumerated
     */
    List<Path> listNames() throws IOException;

    /**
     * Opens a bounded-directory session over {@code directory}, selecting the
     * descriptor-relative backend when the platform provides one and the
     * path-resolved backend otherwise.
     *
     * @param directory an existing directory
     * @return an open session (caller closes it)
     * @throws IOException if the directory cannot be opened
     */
    // A secure stream is intentionally transferred into the returned closeable directory session.
    @SuppressWarnings("PMD.CloseResource")
    static DurableDirectory open(Path directory) throws IOException {
        Objects.requireNonNull(directory, "directory");
        DirectoryStream<Path> opened = Files.newDirectoryStream(directory);
        if (opened instanceof SecureDirectoryStream<?>) {
            @SuppressWarnings("unchecked")
            SecureDirectoryStream<Path> secure = (SecureDirectoryStream<Path>) opened;
            return new DescriptorRelative(directory, secure);
        }
        opened.close();
        return new PathResolved(directory);
    }

    /** POSIX descriptor-relative backend over a {@link SecureDirectoryStream}. */
    final class DescriptorRelative implements DurableDirectory {
        private final Path directory;
        private final SecureDirectoryStream<Path> stream;

        private DescriptorRelative(Path directory, SecureDirectoryStream<Path> stream) {
            this.directory = directory;
            this.stream = stream;
        }

        @Override
        public Path directory() {
            return directory;
        }

        @Override
        public boolean descriptorRelative() {
            return true;
        }

        @Override
        public SeekableByteChannel newByteChannel(Path name, Set<? extends OpenOption> options,
                FileAttribute<?>... attributes) throws IOException {
            return stream.newByteChannel(name, options, attributes);
        }

        @Override
        public void deleteFile(Path name) throws IOException {
            stream.deleteFile(name);
        }

        @Override
        public <V extends FileAttributeView> V getFileAttributeView(Path name, Class<V> type,
                LinkOption... options) {
            return stream.getFileAttributeView(name, type, options);
        }

        @Override
        public List<Path> listNames() throws IOException {
            List<Path> names = new ArrayList<>();
            for (Path entry : stream) {
                Path name = entry.getFileName();
                if (name != null) {
                    names.add(name);
                }
            }
            return names;
        }

        @Override
        public void close() throws IOException {
            stream.close();
        }
    }

    /** Path-resolved backend for filesystems without a {@link SecureDirectoryStream}. */
    final class PathResolved implements DurableDirectory {
        private final Path directory;

        private PathResolved(Path directory) {
            this.directory = directory;
        }

        @Override
        public Path directory() {
            return directory;
        }

        @Override
        public boolean descriptorRelative() {
            return false;
        }

        @Override
        public SeekableByteChannel newByteChannel(Path name, Set<? extends OpenOption> options,
                FileAttribute<?>... attributes) throws IOException {
            return Files.newByteChannel(directory.resolve(name), options, attributes);
        }

        @Override
        public void deleteFile(Path name) throws IOException {
            Files.delete(directory.resolve(name));
        }

        @Override
        public <V extends FileAttributeView> V getFileAttributeView(Path name, Class<V> type,
                LinkOption... options) {
            return Files.getFileAttributeView(directory.resolve(name), type, options);
        }

        @Override
        public List<Path> listNames() throws IOException {
            List<Path> names = new ArrayList<>();
            try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
                for (Path entry : entries) {
                    Path name = entry.getFileName();
                    if (name != null) {
                        names.add(name);
                    }
                }
            }
            return names;
        }

        @Override
        public void close() {
            // No descriptor is retained by the path-resolved backend.
        }
    }
}
