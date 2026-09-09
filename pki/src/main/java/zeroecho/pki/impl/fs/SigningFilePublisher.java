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

/** Strict same-directory atomic publication for signing format files. */
final class SigningFilePublisher {

    private static final PublicationOperations SYSTEM_OPERATIONS = new SystemPublicationOperations();

    private SigningFilePublisher() {
        // utility class
    }

    /* default */ static void publishImmutable(Path target, ContentWriter writer) throws IOException {
        publish(target, false, writer, SYSTEM_OPERATIONS);
    }

    /* default */ static void publishManifest(Path target, ContentWriter writer) throws IOException {
        publish(target, true, writer, SYSTEM_OPERATIONS);
    }

    // Publication errors are deliberately translated to stable, path-free states.
    @SuppressWarnings({ "PMD.PreserveStackTrace", "PMD.EmptyCatchBlock",
            "PMD.CyclomaticComplexity" })
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

        TemporaryFile temporary = null;
        boolean moved = false;
        boolean uncertain = false;
        PublicationStage stage = PublicationStage.WRITE;
        try {
            temporary = operations.createTemporary(parent, "." + fileName + "-");
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
                uncertain = true;
                throw new PublicationException(stage, true);
            }
            stage = PublicationStage.DIRECTORY_FORCE;
            operations.forceDirectory(parent);
        } catch (PublicationException failure) {
            throw failure;
        } catch (IOException failure) {
            throw new PublicationException(stage, moved);
        } finally {
            if (!moved && !uncertain && temporary != null) {
                try {
                    operations.deleteTemporary(temporary);
                } catch (IOException cleanupFailure) {
                    // The primary stable stage remains authoritative. A later startup
                    // sweep may remove an abandoned uniquely named temp file.
                }
            }
        }
    }

    /** Writes one complete temporary file image; the publisher owns the channel. */
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

    /** Package-local fault seam; callers must not share mutable implementations. */
    @SuppressWarnings({ "PMD.CommentRequired", "PMD.CommentDefaultAccessModifier" })
    /* default */ interface PublicationOperations {
        TemporaryFile createTemporary(Path parent, String prefix) throws IOException;

        void write(FileChannel channel, ContentWriter writer) throws IOException;

        void forceFile(FileChannel channel) throws IOException;

        void validateTemporary(TemporaryFile temporary) throws IOException;

        void atomicMove(Path source, Path target, boolean replace) throws IOException;

        void forceDirectory(Path directory) throws IOException;

        void deleteTemporary(TemporaryFile temporary) throws IOException;
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
     */
    /* default */ record TemporaryFile(Path path, FileChannel channel, Object fileKey) {
        TemporaryFile {
            Objects.requireNonNull(path, "path");
            Objects.requireNonNull(channel, "channel");
        }
    }

    /** Stable boundaries used by fault tests and redacted diagnostics. */
    /* default */ enum PublicationStage {
        WRITE,
        FILE_FORCE,
        ATOMIC_MOVE,
        DIRECTORY_FORCE
    }

    /** Stable redacted failure; directory-force failure means durability is uncertain. */
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

        /* default */ PublicationStage stage() {
            return stage;
        }

        /* default */ boolean durabilityUncertain() {
            return durabilityUncertain;
        }
    }

    /** JDK filesystem implementation of the publication seam. */
    private static final class SystemPublicationOperations implements PublicationOperations {
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
                    FileChannel channel = FileChannel.open(temporary, options, attributes);
                    BasicFileAttributes created = Files.readAttributes(temporary,
                            BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                    if (!created.isRegularFile()) {
                        channel.close();
                        Files.deleteIfExists(temporary);
                        throw new IOException("signing temporary-file identity is unavailable");
                    }
                    // fileKey may be null on platforms without a stable identity (Windows).
                    return new TemporaryFile(temporary, channel, created.fileKey());
                } catch (FileAlreadyExistsException collision) {
                    // Try another unpredictable name without opening the existing path.
                }
            }
            throw new IOException("signing temporary-file creation is unavailable");
        }

        @Override
        public void write(FileChannel channel, ContentWriter writer) throws IOException {
            writer.write(channel);
        }

        @Override
        public void forceFile(FileChannel channel) throws IOException {
            channel.force(true);
        }

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

        @Override
        public void atomicMove(Path source, Path target, boolean replace) throws IOException {
            if (replace) {
                AtomicPublish.replaceExisting(source, target);
            } else {
                Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
            }
        }

        @Override
        public void forceDirectory(Path directory) throws IOException {
            SigningFormatSupport.forceDirectory(directory);
        }

        @Override
        @SuppressWarnings("PMD.EmptyCatchBlock")
        public void deleteTemporary(TemporaryFile temporary) throws IOException {
            try {
                BasicFileAttributes current = Files.readAttributes(temporary.path(),
                        BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                if (sameTemporaryIdentity(temporary, current)) {
                    Files.delete(temporary.path());
                }
            } catch (java.nio.file.NoSuchFileException absent) {
                // Nothing remains from the originally opened temporary file.
            }
        }
    }
}
