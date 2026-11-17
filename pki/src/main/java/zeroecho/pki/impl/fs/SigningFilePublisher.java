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
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import java.util.UUID;
import java.util.Objects;

/**
 * Strict same-directory atomic publication for signing format files.
 *
 * <p>Failed publications retain temporary directory entries: Java has no atomic
 * identity-check-and-delete operation, so deleting a checked pathname could remove
 * another writer's replacement. Channels are always closed; successful publication
 * consumes the temporary entry by atomic move. Retained entries require separately
 * coordinated maintenance, not an unguarded pathname sweep.</p>
 */
final class SigningFilePublisher {

    private static final PublicationOperations SYSTEM_OPERATIONS = new SystemPublicationOperations();

    private SigningFilePublisher() {
        // utility class
    }

    /**
     * Publishes one previously absent immutable signing artifact with strict file and directory durability.
     *
     * <p>Failed publications may leave owned temporary entries for coordinated maintenance; the
     * publisher closes their channels.</p>
     *
     * @param target file path in an existing secured nonsymlink parent directory
     * @param writer synchronous complete-image writer borrowing the temporary file channel
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if the parent or target file type is invalid
     * @throws PublicationException if writing, forcing or atomic namespace publication fails
     * @throws IOException if artifact publication cannot be durably completed
     */
    /* default */ static void publishImmutable(Path target, ContentWriter writer) throws IOException {
        publish(target, false, writer, SYSTEM_OPERATIONS);
    }

    /**
     * Atomically replaces the authoritative signing manifest after its complete image is forced.
     *
     * <p>Failed publications may leave owned temporary entries for coordinated maintenance; the
     * publisher closes their channels.</p>
     *
     * @param target file path in an existing secured nonsymlink parent directory
     * @param writer synchronous complete-image writer borrowing the temporary file channel
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if the parent or target file type is invalid
     * @throws PublicationException if writing, forcing or atomic namespace publication fails
     * @throws IOException if artifact publication cannot be durably completed
     */
    /* default */ static void publishManifest(Path target, ContentWriter writer) throws IOException {
        publish(target, true, writer, SYSTEM_OPERATIONS);
    }

    // Publication errors are deliberately translated to stable, path-free states.
    /**
     * Publishes a complete signing artifact through exact temporary-file identity checks and atomic move.
     *
     * @param target file path in an existing secured nonsymlink parent directory
     * @param replace whether the authoritative target is replaced rather than required absent
     * @param writer synchronous image writer that leaves channel closure to this publisher
     * @param operations borrowed filesystem and deterministic fault-injection seam
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if parent or target file type is invalid
     * @throws PublicationException if a persistence stage fails; its stage and uncertainty flag describe
     * the publication boundary
     * @throws IOException if artifact publication cannot be durably completed
     */
    @SuppressWarnings({ "PMD.PreserveStackTrace", "PMD.CyclomaticComplexity" })
    /* default */ static void publish(Path target, boolean replace, ContentWriter writer,
            PublicationOperations operations) throws IOException {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(writer, "writer");
        Objects.requireNonNull(operations, "operations");
        Path parent = target.getParent();
        Path fileName = target.getFileName();
        if (parent == null || fileName == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(parent)) {
            throw new IllegalArgumentException("signing publication target directory is invalid");
        }
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)
                && !Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("signing publication target is not a regular file");
        }
        if (!replace && Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new PublicationException(PublicationStage.ATOMIC_MOVE, false);
        }

        boolean moved = false;
        PublicationStage stage = PublicationStage.WRITE;
        try {
            TemporaryFile temporary = operations.createTemporary(parent, "." + fileName + "-");
            try (FileChannel channel = temporary.channel()) {
                operations.write(channel, writer);
                stage = PublicationStage.FILE_FORCE;
                operations.forceFile(channel);
            }
            stage = PublicationStage.ATOMIC_MOVE;
            operations.validateTemporary(temporary);
            try {
                operations.atomicMove(temporary.path(), target, replace);
                moved = true;
            } catch (AtomicMoveNotSupportedException | FileAlreadyExistsException precommit) {
                throw new PublicationException(stage, false);
            } catch (IOException ambiguous) {
                throw new PublicationException(stage, true);
            }
            stage = PublicationStage.DIRECTORY_FORCE;
            operations.forceDirectory(parent);
        } catch (PublicationException failure) {
            throw failure;
        } catch (IOException failure) {
            throw new PublicationException(stage, moved);
        }
    }

    /**
     * Writes one complete temporary file image; the publisher owns the channel.
     */
    @FunctionalInterface
    @SuppressWarnings("PMD.CommentDefaultAccessModifier")
    /* default */ interface ContentWriter {
        /**
         * Writes the image without closing the channel.
         *
         * @param channel temporary-file channel
         * @throws IOException on write failure
         */
        void write(FileChannel channel) throws IOException;
    }

    /**
     * Package-local fault seam; callers must not share mutable implementations.
     */
    @SuppressWarnings({ "PMD.CommentDefaultAccessModifier" })
    /* default */ interface PublicationOperations {
        /**
         * Creates a uniquely named owned temporary file with captured filesystem identity.
         *
         * @param parent existing secured publication directory
         * @param prefix filename prefix identifying this publication attempt
         * @return owned temporary file and open channel; caller closes or transfers ownership
         * @throws IOException if the filesystem operation or injected persistence boundary fails
         */
        TemporaryFile createTemporary(Path parent, String prefix) throws IOException;

        /**
         * Writes a complete candidate image without closing its owned publication channel.
         *
         * @param channel open candidate file channel
         * @param writer synchronous complete-image callback
         * @throws IOException if the filesystem operation or injected persistence boundary fails
         */
        void write(FileChannel channel, ContentWriter writer) throws IOException;

        /**
         * Confirms durability of candidate file data and metadata.
         *
         * @param channel open candidate channel whose complete image was written
         * @throws IOException if the filesystem operation or injected persistence boundary fails
         */
        void forceFile(FileChannel channel) throws IOException;

        /**
         * Requires that the temporary path still refers to the captured regular-file identity.
         *
         * @param temporary owned candidate file and captured filesystem identity
         * @throws IOException if the filesystem operation or injected persistence boundary fails
         */
        void validateTemporary(TemporaryFile temporary) throws IOException;

        /**
         * Atomically moves the candidate into the authoritative publication namespace.
         *
         * @param source exact validated temporary candidate path
         * @param target exact authoritative destination path
         * @param replace whether an existing target may be atomically replaced
         * @throws IOException if the filesystem operation or injected persistence boundary fails
         */
        void atomicMove(Path source, Path target, boolean replace) throws IOException;

        /**
         * Confirms durability of the completed publication namespace update.
         *
         * @param directory exact publication parent directory
         * @throws IOException if the filesystem operation or injected persistence boundary fails
         */
        void forceDirectory(Path directory) throws IOException;
    }

    /**
     * Open, uniquely created temporary file and its filesystem identity.
     *
     * <p>
     * {@code fileKey} is the stable filesystem identity (for example a POSIX
     * inode) used to detect a concurrent swap of the temporary path. Platforms
     * that do not expose a stable identity through the basic attribute view,
     * notably Windows, report {@code null}; the regular-file check then remains
     * the strongest available guard.
     * </p>
     * @param path exact local filesystem path
     * @param channel owned open temporary-file channel
     * @param fileKey captured filesystem identity used to detect replacement
     */
    /* default */ record TemporaryFile(Path path, FileChannel channel, Object fileKey) {
        /**
         * Creates the open, uniquely created temporary file and its filesystem identity.
         *
         * @param path exact local filesystem path
         * @param channel owned open temporary-file channel
         * @param fileKey captured filesystem identity used to detect replacement
         * @throws NullPointerException if {@code path} is null; or if {@code channel} is null
         */
        TemporaryFile {
            Objects.requireNonNull(path, "path");
            Objects.requireNonNull(channel, "channel");
        }
    }

    /**
     * Stable boundaries used by fault tests and redacted diagnostics.
     */
    /* default */ enum PublicationStage {
        /**
         * Writing complete candidate content before publication.
         */
        WRITE,
        /**
         * Forcing candidate file data and metadata before publication.
         */
        FILE_FORCE,
        /**
         * Atomically moving the candidate into its final namespace.
         */
        ATOMIC_MOVE,
        /**
         * Forcing the final parent directory after publication.
         */
        DIRECTORY_FORCE
    }

    /**
     * Stable redacted failure; directory-force failure means durability is uncertain.
     */
    /* default */ static final class PublicationException extends IOException {
        private static final long serialVersionUID = 1601142753017350472L;

        private final PublicationStage stage;
        private final boolean durabilityUncertain;

        private PublicationException(PublicationStage stage, boolean durabilityUncertain) {
            super(durabilityUncertain
                    ? "signing file publication durability is uncertain"
                    : "signing file publication failed before commit");
            this.stage = stage;
            this.durabilityUncertain = durabilityUncertain;
        }

        /**
         * Returns the publication stage at which the failure occurred.
         *
         * @return publication stage at which the failure occurred
         */
        /* default */ PublicationStage stage() {
            return stage;
        }

        /**
         * Reports whether publication may have changed the namespace without confirmed durability.
         *
         * @return true if the move outcome or the durability of a completed move is uncertain
         */
        /* default */ boolean durabilityUncertain() {
            return durabilityUncertain;
        }
    }

    /**
     * Closes a newly opened channel unless ownership transfers to a temporary file.
     */
    /* default */ static final class TemporaryChannel implements AutoCloseable {
        private final FileChannel channel;
        private boolean transferred;

        /**
         * Takes responsibility for closing a newly opened candidate channel until transfer succeeds.
         *
         * @param channel owned open candidate channel
         * @throws NullPointerException if a required input is null
         */
        /* default */ TemporaryChannel(FileChannel channel) {
            this.channel = Objects.requireNonNull(channel, "channel");
        }

        /**
         * Transfers channel closure responsibility to the returned temporary file.
         *
         * @param path exact owned temporary candidate path
         * @param fileKey captured filesystem identity, or null where unavailable
         * @return temporary file carrier now responsible for channel closure
         * @throws NullPointerException if the candidate path is null
         */
        /* default */ TemporaryFile transfer(Path path, Object fileKey) {
            TemporaryFile result = new TemporaryFile(path, channel, fileKey);
            transferred = true;
            return result;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void close() throws IOException {
            if (!transferred) {
                channel.close();
            }
        }
    }

    /**
     * JDK filesystem implementation of the publication seam.
     */
    /* default */ static final class SystemPublicationOperations implements PublicationOperations {
        /**
         * {@inheritDoc}
         */
        @Override
        @SuppressWarnings("PMD.EmptyCatchBlock")
        public TemporaryFile createTemporary(Path parent, String prefix) throws IOException {
            FileAttribute<?>[] attributes = Files.getFileStore(parent)
                    .supportsFileAttributeView("posix")
                            ? new FileAttribute<?>[] { PosixFilePermissions.asFileAttribute(
                                    PosixFilePermissions.fromString("rw-------")) }
                            : new FileAttribute<?>[0];
            for (int attempt = 0; attempt < 16; attempt++) {
                Path temporary = parent.resolve(prefix + UUID.randomUUID() + ".tmp");
                Set<OpenOption> options = Set.of(StandardOpenOption.CREATE_NEW,
                        StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
                try {
                    return openTemporary(temporary, options, attributes);
                } catch (FileAlreadyExistsException collision) {
                    // Try another unpredictable name without opening the existing path.
                }
            }
            throw new IOException("signing temporary-file creation is unavailable");
        }

        /**
         * Opens an owned channel until the temporary identity has been captured.
         */
        private static TemporaryFile openTemporary(Path path, Set<OpenOption> options,
                FileAttribute<?>... attributes) throws IOException {
            try (TemporaryChannel opened = new TemporaryChannel(FileChannel.open(path, options, attributes))) {
                BasicFileAttributes created = Files.readAttributes(path,
                        BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                if (!created.isRegularFile()) {
                    throw new IOException("signing temporary-file identity is unavailable");
                }
                // fileKey may be null on platforms without a stable identity (Windows).
                return opened.transfer(path, created.fileKey());
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void write(FileChannel channel, ContentWriter writer) throws IOException {
            writer.write(channel);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void forceFile(FileChannel channel) throws IOException {
            channel.force(true);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void validateTemporary(TemporaryFile temporary) throws IOException {
            BasicFileAttributes current = Files.readAttributes(temporary.path(),
                    BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!sameTemporaryIdentity(temporary, current)) {
                throw new FileAlreadyExistsException("signing temporary-file identity changed");
            }
        }

        /**
         * Confirms that {@code current} is still the temporary file that was
         * originally opened. When the platform exposes a stable file identity the
         * key must match; otherwise (for example on Windows) the regular-file
         * check is the strongest available guard.
         */
        private static boolean sameTemporaryIdentity(TemporaryFile temporary,
                BasicFileAttributes current) {
            if (!current.isRegularFile()) {
                return false;
            }
            return temporary.fileKey() == null
                    || temporary.fileKey().equals(current.fileKey());
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void atomicMove(Path source, Path target, boolean replace) throws IOException {
            if (replace) {
                AtomicPublish.replaceExisting(source, target);
            } else {
                Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void forceDirectory(Path directory) throws IOException {
            SigningFormatSupport.forceDirectory(directory);
        }
    }
}
