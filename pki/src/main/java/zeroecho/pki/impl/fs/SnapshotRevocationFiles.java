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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;

/**
 * Publishes the exact captured revocation prefix and durable snapshot boundary.
 */
final class SnapshotRevocationFiles {
    private SnapshotRevocationFiles() { }
    /**
     * Writes and forces the snapshot's exact revocation transition boundary.
     *
     * @param targetRoot existing snapshot directory
     * @param boundary retained transition boundary
     * @throws IOException if marker creation or durability fails
     */
    /* default */ static void writeSnapshotBoundary(Path targetRoot, long boundary) throws IOException {
        Path marker = new FsPaths(targetRoot).revocationSnapshotBoundary();
        Files.writeString(marker, Long.toString(boundary), StandardCharsets.US_ASCII,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE);
        try (FileChannel channel = FileChannel.open(
                marker, StandardOpenOption.WRITE)) {
            channel.force(true);
        }
        PlatformFs.forceDirectory(targetRoot);
    }
    /**
     * Installs the captured revocation log by the required atomic move.
     *
     * @param targetRoot existing snapshot directory
     * @param stagedPrefix owned captured log to move into the snapshot
     * @throws IOException if cleanup, atomic publication or durability fails
     */
    /* default */ static void installRevocationAuthority(Path targetRoot, Path stagedPrefix) throws IOException {
        FsPaths paths = new FsPaths(targetRoot);
        Files.deleteIfExists(paths.revocationCurrentIndex());
        Files.createDirectories(paths.revocationTransitionLog().getParent());
        try {
            PlatformFs.atomicMove(stagedPrefix, paths.revocationTransitionLog(),
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException unsupported) {
            throw new IOException("Atomic revocation snapshot restoration is unsupported", unsupported);
        }
        PlatformFs.forceDirectory(paths.revocationTransitionLog().getParent());
    }
}
