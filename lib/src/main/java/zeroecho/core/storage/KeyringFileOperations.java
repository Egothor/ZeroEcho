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
    /**
     * Production implementation using NIO atomic moves and platform security attributes.
     */
    KeyringFileOperations NIO = new NioKeyringFileOperations();

    /**
     * Returns the retry policy used after transient access denial during atomic moves.
     *
     * @return platform policy, or the deterministic policy supplied by a test implementation
     */
    default KeyringAtomicMoveRetryPolicy atomicMoveRetryPolicy() {
        return KeyringAtomicMoveRetryPolicy.PLATFORM;
    }

    /**
     * Atomic persistence destination.
     */
    enum Target {
        /**
         * Encrypted primary keyring image.
         */
        MAIN_IMAGE,
        /**
         * Authenticated nonce high-water sidecar.
         */
        NONCE_RESERVATION,
        /**
         * Authenticated local stateful-signing authority image.
         */
        STATEFUL_AUTHORITY
    }

    /**
     * Creates one owner-only temporary file beside its destination.
     *
     * @param target logical persistence destination used for fault injection and routing
     * @param parent secured destination directory
     * @param prefix temporary file-name prefix
     * @param suffix temporary file-name suffix, or null for the platform default
     * @return path of the newly created empty file
     * @throws IOException if secure temporary-file creation fails
     */
    Path createTemporary(Target target, Path parent, String prefix, String suffix) throws IOException;

    /**
     * Writes the complete encrypted image and durably flushes it before returning.
     *
     * @param target logical persistence destination
     * @param temporary temporary file created for this transaction
     * @param image complete image bytes; borrowed without modification
     * @throws IOException if opening, writing, or flushing the file fails
     */
    void writeTemporary(Target target, Path temporary, byte[] image) throws IOException;

    /**
     * Completes the temporary-file durability barrier before atomic replacement.
     *
     * @param target logical persistence destination
     * @param temporary temporary image file
     * @throws IOException if the implementation cannot complete its durability barrier
     */
    void forceTemporary(Target target, Path temporary) throws IOException;

    /**
     * Atomically replaces the destination with the prepared temporary file.
     *
     * @param target logical persistence destination
     * @param temporary prepared source file; consumed by a successful move
     * @param destination authoritative destination path
     * @throws IOException if the atomic replacement cannot be completed
     */
    void atomicReplace(Target target, Path temporary, Path destination) throws IOException;

    /**
     * Forces the destination directory after publication where the platform supports it.
     *
     * @param target logical persistence destination
     * @param parent directory containing the published image
     * @throws IOException if the required directory durability operation fails
     */
    void forceDirectory(Target target, Path parent) throws IOException;

    /**
     * Deletes an uncommitted temporary file if it still exists.
     *
     * @param target logical persistence destination
     * @param temporary temporary image path
     * @throws IOException if cleanup cannot delete the temporary file
     */
    void deleteTemporary(Target target, Path temporary) throws IOException;
}

/**
 * Production NIO implementation of the atomic persistence boundary.
 */
final class NioKeyringFileOperations implements KeyringFileOperations {
    /**
     * {@inheritDoc}
     */
    @Override
    public Path createTemporary(Target target, Path parent, String prefix, String suffix) throws IOException {
        // Owner-only protection comes from the create-time attributes on POSIX and
        // from inheritance of the secured parent directory's ACL on Windows.
        return Files.createTempFile(parent, prefix, suffix,
                KeyringPlatformPolicy.INSTANCE.fileCreateAttributes());
    }

    /**
     * {@inheritDoc}
     */
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

    /**
     * {@inheritDoc}
     */
    @Override
    public void forceTemporary(Target target, Path temporary) throws IOException {
        // Data was already forced at the end of writeTemporary; this is a no-op.
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void atomicReplace(Target target, Path temporary, Path destination) throws IOException {
        Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void forceDirectory(Target target, Path parent) throws IOException {
        KeyringPlatformPolicy.INSTANCE.forceDirectory(parent);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void deleteTemporary(Target target, Path temporary) throws IOException {
        Files.deleteIfExists(temporary);
    }
}
