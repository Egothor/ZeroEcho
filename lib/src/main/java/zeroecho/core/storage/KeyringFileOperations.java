/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.storage;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

/**
 * Narrow package-local boundary for atomic keyring persistence operations.
 */
interface KeyringFileOperations {
    KeyringFileOperations NIO = new NioKeyringFileOperations();

    /** Atomic persistence destination. */
    enum Target {
        MAIN_IMAGE, NONCE_RESERVATION
    }

    /** Creates one owner-only temporary file beside its destination. */
    Path createTemporary(Target target, Path parent, String prefix, String suffix,
            FileAttribute<Set<PosixFilePermission>> permissions) throws IOException;

    /** Writes the complete encrypted image to its temporary file. */
    void writeTemporary(Target target, Path temporary, byte[] image) throws IOException;

    /** Forces temporary-file contents to durable storage. */
    void forceTemporary(Target target, Path temporary) throws IOException;

    /** Atomically replaces the destination with the temporary file. */
    void atomicReplace(Target target, Path temporary, Path destination) throws IOException;

    /** Forces the destination directory after atomic replacement. */
    void forceDirectory(Target target, Path parent) throws IOException;

    /** Deletes a temporary file that did not become authoritative. */
    void deleteTemporary(Target target, Path temporary) throws IOException;
}

/** Production NIO implementation of the atomic persistence boundary. */
final class NioKeyringFileOperations implements KeyringFileOperations {
    @Override
    public Path createTemporary(Target target, Path parent, String prefix, String suffix,
            FileAttribute<Set<PosixFilePermission>> permissions) throws IOException {
        return Files.createTempFile(parent, prefix, suffix, permissions);
    }

    @Override
    public void writeTemporary(Target target, Path temporary, byte[] image) throws IOException {
        try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
            ByteBuffer buffer = ByteBuffer.wrap(image);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
        }
    }

    @Override
    public void forceTemporary(Target target, Path temporary) throws IOException {
        try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
            channel.force(true);
        }
    }

    @Override
    public void atomicReplace(Target target, Path temporary, Path destination) throws IOException {
        Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    @Override
    public void forceDirectory(Target target, Path parent) throws IOException {
        try (FileChannel directory = FileChannel.open(parent, StandardOpenOption.READ)) {
            directory.force(true);
        }
    }

    @Override
    public void deleteTemporary(Target target, Path temporary) throws IOException {
        Files.deleteIfExists(temporary);
    }
}
