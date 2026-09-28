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

import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.core.io.CancellationSignal;

/**
 * Stable, restartable ordered current-state view at one authoritative revision.
 *
 * <p>
 * A snapshot never exposes a complete collection. Each cursor yields one
 * immutable current state at a time and uses {@code long} ordinal accounting. ZeroEcho
 * core imposes no product-wide entry-count ceiling.
 * </p>
 *
 * <p>An exact checkpoint opens without population materialization. Building a
 * missing checkpoint uses a bounded-memory external sort; cursor traversal is
 * linear in the current-state count and uses constant auxiliary heap per entry.</p>
 */
public interface RevocationSnapshot extends AutoCloseable {

    /**
     * Returns stable non-secret snapshot provenance.
     *
     * @return non-blank snapshot identifier
     */
    String snapshotId();

    /**
     * Returns the durable source-store identity captured with this snapshot.
     * Revisions are comparable only within the same source identity.
     * @return captured authoritative source-store identity
     */
    MetadataStoreId sourceStoreId();

    /**
     * Returns the captured authoritative revision.
     *
     * @return captured authoritative global revision
     */
    long revision();

    /**
     * Returns the captured log boundary.
     *
     * @return captured authoritative byte boundary
     */
    long boundary();

    /**
     * Returns the captured global commitment.
     *
     * @return captured authoritative global commitment in lowercase hexadecimal
     */
    String commitment();

    /**
     * Returns the current-state count when the store can provide it without
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
     * One-pass current-state cursor.
     */
    interface Cursor extends AutoCloseable {

        /**
         * Advances to the next current state.
         *
         * @return {@code true} when {@link #current()} is available
         * @throws IOException if store reading fails
         */
        default boolean next() throws IOException {
            return next(CancellationSignal.NONE);
        }

        /**
         * Advances with cancellation.
         *
         * @param cancellation cancellation signal
         * @return {@code true} when a current state is available
         * @throws IOException if store reading fails
         */
        boolean next(CancellationSignal cancellation) throws IOException;

        /**
         * Returns the current state.
         *
         * @return immutable current state
         * @throws IllegalStateException if the cursor is not positioned on a value
         */
        RevocationRecord current();

        /**
         * Returns the authoritative global transition revision of the current state.
         * This is the revision of its exact validated log frame, not the credential-local
         * revision or cursor ordinal. It is positive and at most the snapshot revision.
         * @return current state's global revision within the snapshot source store
         * @throws IllegalStateException if no current value exists, including after
         *         end of input, a failed advance or closure
         */
        long currentGlobalRevision();

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
