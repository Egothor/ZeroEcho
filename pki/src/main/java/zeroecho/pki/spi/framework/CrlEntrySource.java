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
package zeroecho.pki.spi.framework;

import java.io.IOException;
import java.util.OptionalLong;

/**
 * Stable restartable source of CRL entries.
 *
 * <p>
 * The source yields one immutable entry at a time and never exposes an aggregate
 * list. ZeroEcho core does not impose an arbitrary product-wide limit on
 * aggregate CRL size or revocation-entry cardinality.
 * </p>
 */
public interface CrlEntrySource extends AutoCloseable {

    /**
     * Opens a new cursor over the same logical snapshot.
     *
     * @return cursor
     * @throws IOException if the pass cannot be opened
     */
    Cursor openCursor() throws IOException;

    /**
     * Returns the entry count when cheaply known.
     *
     * @return count or empty
     */
    OptionalLong count();

    /**
     * Releases the stable snapshot.
     *
     * @throws IOException if cleanup fails
     */
    @Override
    void close() throws IOException;

    /**
     * One-pass entry cursor.
     */
    interface Cursor extends AutoCloseable {
        /**
         * Advances the cursor.
         *
         * @return {@code true} when an entry is available
         * @throws IOException if reading fails
         */
        boolean next() throws IOException;

        /**
         * Returns the current entry.
         *
         * @return current entry
         */
        CrlEntry current();

        /**
         * Returns the current zero-based ordinal.
         *
         * @return ordinal
         */
        long ordinal();

        @Override
        void close() throws IOException;
    }
}
