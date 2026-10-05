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
package zeroecho.pki.impl.fs.ct;

import java.nio.file.Path;
import java.util.Objects;

import zeroecho.pki.spi.ct.CtJournalException;
import zeroecho.pki.spi.ct.CtJournalStore;

/**
 * Factory that opens or creates a {@link FsCtJournalStore} at a given filesystem path.
 *
 * <p>The factory is the single external creation point for CT Mode A journals. All
 * other code should use the {@link CtJournalStore} interface. The factory is exposed
 * from the {@code zeroecho.pki.impl.fs} package so that {@code FilesystemPkiStoreProvider}
 * and the administration API can construct journal instances from configuration.</p>
 *
 * @since 1.0
 */
public final class FsCtJournalStoreFactory {

    private FsCtJournalStoreFactory() {
        // utility
    }

    /**
     * Opens or creates a CT journal store rooted at {@code journalDir}.
     *
     * <p>If {@code journalDir} does not exist it is created along with any missing
     * ancestor directories. If {@code entries.bin} already exists, its contents are
     * scanned and the in-memory index is rebuilt before the store is returned.</p>
     *
     * @param journalDir directory that holds the journal data; must not be {@code null}
     * @return a ready-to-use journal store
     * @throws CtJournalException if the directory cannot be created, the file cannot
     *                            be opened, or existing records are unreadable
     * @throws NullPointerException if {@code journalDir} is {@code null}
     */
    public static CtJournalStore open(final Path journalDir) throws CtJournalException {
        Objects.requireNonNull(journalDir, "journalDir");
        return new FsCtJournalStore(journalDir);
    }
}
