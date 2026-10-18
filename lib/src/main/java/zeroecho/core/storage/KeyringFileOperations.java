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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;

/**
 * Narrow package-local boundary for atomic keyring persistence operations.
 */
interface KeyringFileOperations {
    KeyringFileOperations NIO = new NioKeyringFileOperations();

    /** Supplies the platform retry policy; tests may inject a deterministic pause. */
    default KeyringAtomicMoveRetryPolicy atomicMoveRetryPolicy() {
        return KeyringAtomicMoveRetryPolicy.PLATFORM;
    }

    /** Atomic persistence destination. */
    enum Target {
        MAIN_IMAGE, NONCE_RESERVATION, STATEFUL_AUTHORITY
    }

    /** Creates one owner-only temporary file beside its destination. */
    Path createTemporary(Target target, Path parent, String prefix, String suffix) throws IOException;

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
    public Path createTemporary(Target target, Path parent, String prefix, String suffix) throws IOException {
        // Owner-only protection comes from the create-time attributes on POSIX and
        // from inheritance of the secured parent directory's ACL on Windows.
        return Files.createTempFile(parent, prefix, suffix,
                KeyringPlatformPolicy.INSTANCE.fileCreateAttributes());
    }

    @Override
    public void writeTemporary(Target target, Path temporary, byte[] image) throws IOException {
        try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
            ByteBuffer buffer = ByteBuffer.wrap(image);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            // Force before closing so atomicReplace never races a re-open against
            // a transient OS file lock (e.g. AV scan triggered on close).
            channel.force(true);
        }
    }

    @Override
    public void forceTemporary(Target target, Path temporary) throws IOException {
        // Data was already forced at the end of writeTemporary; this is a no-op.
    }

    @Override
    public void atomicReplace(Target target, Path temporary, Path destination) throws IOException {
        Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    @Override
    public void forceDirectory(Target target, Path parent) throws IOException {
        KeyringPlatformPolicy.INSTANCE.forceDirectory(parent);
    }

    @Override
    public void deleteTemporary(Target target, Path temporary) throws IOException {
        Files.deleteIfExists(temporary);
    }
}
