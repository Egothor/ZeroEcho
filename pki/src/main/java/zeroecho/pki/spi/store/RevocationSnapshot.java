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
package zeroecho.pki.spi.store;

import java.io.IOException;
import java.util.OptionalLong;

import zeroecho.pki.api.revocation.RevocationJournal;

/**
 * Stable, restartable streaming view of authoritative revocation journals.
 *
 * <p>
 * A snapshot never exposes a complete collection. Each cursor yields one
 * immutable journal at a time and uses {@code long} ordinal accounting. ZeroEcho
 * core imposes no product-wide entry-count ceiling.
 * </p>
 */
public interface RevocationSnapshot extends AutoCloseable {

    /**
     * Returns stable non-secret snapshot provenance.
     *
     * @return non-blank snapshot identifier
     */
    String snapshotId();

    /**
     * Returns the journal count when the store can provide it without
     * materialization.
     *
     * @return count or empty
     */
    OptionalLong count();

    /**
     * Opens a new pass over the same logical snapshot.
     *
     * @return closeable cursor
     * @throws IOException if the cursor cannot be opened
     */
    Cursor openCursor() throws IOException;

    /**
     * Releases snapshot resources.
     *
     * @throws IOException if cleanup fails
     */
    @Override
    void close() throws IOException;

    /**
     * One-pass journal cursor.
     */
    interface Cursor extends AutoCloseable {

        /**
         * Advances to the next journal.
         *
         * @return {@code true} when {@link #current()} is available
         * @throws IOException if store reading fails
         */
        boolean next() throws IOException;

        /**
         * Returns the current journal.
         *
         * @return immutable current journal
         * @throws IllegalStateException if the cursor is not positioned on a value
         */
        RevocationJournal current();

        /**
         * Returns the zero-based current ordinal.
         *
         * @return non-negative ordinal
         * @throws IllegalStateException if the cursor is not positioned on a value
         */
        long ordinal();

        /**
         * Closes the cursor.
         *
         * @throws IOException if cleanup fails
         */
        @Override
        void close() throws IOException;
    }
}
