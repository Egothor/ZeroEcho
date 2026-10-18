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
import java.nio.channels.FileLock;

/**
 * Single-writer exclusion lock taken on a fixed sentinel byte beyond any file
 * content rather than over the whole file.
 *
 * <p>
 * A durable log excludes concurrent writers by holding an exclusive
 * {@link FileLock} on its backing file for its whole lifetime. A whole-file
 * {@code tryLock()} is correct on POSIX, where region locks are advisory and
 * therefore never block a reader. On Windows region locks are <em>mandatory</em>:
 * a whole-file lock blocks every read of the same bytes issued through a second
 * handle, which the store legitimately does — for example the revocation
 * current-index recovery reads the transition log's preamble while the log's
 * writer authority is held open. Locking the log's content is unnecessary for
 * writer exclusion; a single agreed sentinel byte at a fixed high offset excludes
 * a second writer just as well (both contend for the same byte) while leaving the
 * content region unlocked and freely readable on every platform.
 * </p>
 *
 * <p>
 * The sentinel offset lies far beyond any attainable file size, so the lock never
 * overlaps content even as the log grows. All writers of a given file must take
 * the lock through this helper so they agree on the sentinel region.
 * </p>
 */
final class WriterExclusionLock {

    /**
     * Fixed sentinel offset, chosen beyond any attainable file size so the lock
     * never overlaps content. {@code Long.MAX_VALUE - 1} (not {@code MAX_VALUE})
     * keeps {@code offset + size} within {@code long} range as the file APIs
     * require.
     */
    private static final long SENTINEL_OFFSET = Long.MAX_VALUE - 1L;

    /** Sentinel region length: a single byte is sufficient for exclusion. */
    private static final long SENTINEL_LENGTH = 1L;

    private WriterExclusionLock() {
    }

    /**
     * Attempts to acquire the writer-exclusion lock on {@code channel}.
     *
     * @param channel the open channel whose file is being guarded
     * @return the acquired exclusive sentinel lock, or {@code null} if another
     *         writer already holds it
     * @throws IOException if the lock cannot be attempted
     * @throws java.nio.channels.OverlappingFileLockException if this JVM already
     *         holds an overlapping lock on the same channel's file
     */
    /* default */ static FileLock tryAcquire(FileChannel channel) throws IOException {
        return channel.tryLock(SENTINEL_OFFSET, SENTINEL_LENGTH, false);
    }
}
