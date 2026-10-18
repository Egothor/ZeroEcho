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
import java.nio.file.AccessDeniedException;
import java.nio.file.CopyOption;
import java.nio.file.FileStore;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.util.Set;

/**
 * Resolves and holds the process-wide {@link PlatformFsOps} strategy.
 *
 * <p>
 * The strategy is a property of the operating system's default filesystem
 * (POSIX permission model versus NTFS/ACL model) and is therefore resolved once
 * from {@link FileSystems#getDefault()}. All store instances in a process run on
 * the same operating system, so a single resolved strategy is authoritative. The
 * per-store volume may still differ in capability from the default filesystem;
 * that is validated separately by {@link #requireOwnerOnlyCapable(Path)} at store
 * open, which fails closed when the store's volume cannot enforce owner-only
 * protection.
 * </p>
 */
final class PlatformFs {

    private static final PlatformFsOps OPS = resolve();
    // Windows Defender / indexer can transiently lock a just-written file during MoveFileEx.
    // The retry is Windows-only; on POSIX, rename(2) is unconditionally atomic and non-blocking.
    private static final boolean ON_WINDOWS = System.getProperty("os.name", "")
            .toLowerCase(java.util.Locale.ROOT).startsWith("windows");
    private static final int ATOMIC_MOVE_MAX_ATTEMPTS = 5;
    private static final long ATOMIC_MOVE_RETRY_DELAY_MS = 10L;

    private PlatformFs() {
    }

    /**
     * @return the resolved platform strategy (never {@code null})
     */
    /* default */ static PlatformFsOps ops() {
        return OPS;
    }

    /**
     * Forces one directory's entry updates durable, delegating to the resolved
     * platform strategy (a genuine {@code fsync} on POSIX; a no-op on platforms
     * that carry directory durability through the write-through atomic publish).
     *
     * @param directory existing directory whose entry updates must be durable
     * @throws IOException on a genuine directory durability failure
     */
    /* default */ static void forceDirectory(final Path directory) throws IOException {
        OPS.forceDirectory(directory);
    }

    /**
     * Validates that the given store path resides on a volume able to enforce
     * owner-only protection under the resolved platform model, failing closed
     * otherwise.
     *
     * @param path an existing path inside the store (typically the store root)
     * @throws IOException if owner-only protection cannot be enforced there
     */
    /* default */ static void requireOwnerOnlyCapable(final Path path) throws IOException {
        FileStore store = Files.getFileStore(path);
        boolean posix = store.supportsFileAttributeView(PosixFileAttributeView.class);
        boolean acl = store.supportsFileAttributeView(AclFileAttributeView.class);
        if (!posix && !acl) {
            throw new IOException("store volume cannot enforce owner-only protection (neither POSIX nor ACL): " + path);
        }
    }

    /**
     * Atomically moves {@code source} to {@code destination} with Windows-specific retry
     * on transient {@link AccessDeniedException} (AV / indexer file lock during MoveFileEx).
     * On POSIX, delegates directly to {@link Files#move} with no retry.
     *
     * @param source source path
     * @param destination destination path
     * @param options copy options (e.g. {@code ATOMIC_MOVE}, {@code REPLACE_EXISTING})
     * @throws IOException on non-transient failure or after exhausting the retry budget
     */

    /* default */ static Path atomicMove(final Path source, final Path destination,
            final CopyOption... options) throws IOException {
        if (!ON_WINDOWS) {
            return Files.move(source, destination, options);
        }
        AccessDeniedException lastDenied = null;
        for (int attempt = 0; attempt < ATOMIC_MOVE_MAX_ATTEMPTS; attempt++) {
            try {
                return Files.move(source, destination, options);
            } catch (AccessDeniedException denied) {
                lastDenied = denied;
                if (attempt < ATOMIC_MOVE_MAX_ATTEMPTS - 1) {
                    try {
                        Thread.sleep(ATOMIC_MOVE_RETRY_DELAY_MS); // NOPMD DoNotUseThreads - Standalone Java service uses bounded polling/retry or preserves cancellation; no J2EE container.
                    } catch (InterruptedException interrupted) {
                        denied.addSuppressed(interrupted);
                        Thread.currentThread().interrupt(); // NOPMD DoNotUseThreads - Standalone Java service uses bounded polling/retry or preserves cancellation; no J2EE container.
                        throw denied;
                    }
                }
            }
        }
        throw lastDenied;
    }

    private static PlatformFsOps resolve() {
        Set<String> views = FileSystems.getDefault().supportedFileAttributeViews();
        if (views.contains("posix")) {
            return new PosixPlatformFsOps();
        }
        if (views.contains("acl")) {
            return new WindowsPlatformFsOps();
        }
        throw new IllegalStateException(
                "unsupported platform: default filesystem provides neither POSIX nor ACL owner-only enforcement");
    }
}
