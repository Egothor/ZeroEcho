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
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Atomic publication commit point shared by the store's durable writers.
 *
 * <p>
 * The store publishes a durable record by writing a uniquely named temporary
 * sibling and then atomically moving it onto its final name. When the final name
 * already exists the move replaces it. On POSIX {@code rename(2)} replaces the
 * target even while a reader holds it open, so the publish never observes a
 * transient error. On Windows {@code MoveFileEx} implements the replace by
 * deleting the target, and it reports {@link java.nio.file.AccessDeniedException}
 * (or another {@link FileSystemException} sharing violation) when a reader holds
 * the target open at that instant — which the store legitimately does, for
 * example while another thread reads a manifest or a handoff intent it is about
 * to supersede.
 * </p>
 *
 * <p>
 * A failed atomic replace is a no-op: the source temporary and the existing
 * target are both left intact, so retrying is safe and idempotent. This helper
 * therefore rides out the reader's brief window with a bounded retry. The first
 * attempt succeeds on POSIX, so the retry path is Windows-only in practice. A
 * genuinely unsupported move ({@link AtomicMoveNotSupportedException}) or a
 * create-only collision ({@link FileAlreadyExistsException}) is not transient and
 * propagates immediately for the caller to classify.
 * </p>
 */
final class AtomicPublish {

    /**
     * Bounded retry budget for a replace defeated by a concurrent reader on
     * Windows. {@code 100} attempts at {@link #REPLACE_BACKOFF_MILLIS} bounds the
     * wait to ~1s, comfortably within callers' own timeouts.
     */
    private static final int REPLACE_ATTEMPTS = 100;

    /** Backoff between replace attempts, in milliseconds. */
    private static final long REPLACE_BACKOFF_MILLIS = 10L;

    private AtomicPublish() {
    }

    /**
     * Atomically replaces {@code target} with {@code source}, riding out a
     * transient Windows sharing violation with a bounded retry.
     *
     * @param source the fully written temporary source
     * @param target the final name to replace (may already exist)
     * @throws AtomicMoveNotSupportedException if the platform cannot move atomically
     * @throws IOException                     if the replace cannot be completed
     *                                         within the retry budget
     */
    // Bounded filesystem retry sleeps on the caller thread; the last sharing failure is rethrown unchanged.
    @SuppressWarnings({"PMD.DoNotUseThreads", "PMD.PreserveStackTrace"})
    /* default */ static void replaceExisting(Path source, Path target) throws IOException {
        for (int attempt = 0; attempt < REPLACE_ATTEMPTS; attempt++) {
            try {
                Files.move(source, target, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
                return;
            } catch (AtomicMoveNotSupportedException | FileAlreadyExistsException fatal) {
                throw fatal;
            } catch (FileSystemException transientSharing) {
                if (attempt == REPLACE_ATTEMPTS - 1) {
                    throw transientSharing;
                }
                try {
                    Thread.sleep(REPLACE_BACKOFF_MILLIS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new IOException("atomic replace interrupted", interrupted);
                }
            }
        }
        throw new AssertionError("positive replace-attempt count exhausted without a result");
    }
}
