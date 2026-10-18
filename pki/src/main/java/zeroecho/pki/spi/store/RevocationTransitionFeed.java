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
package zeroecho.pki.spi.store;

import java.io.IOException;
import java.util.Objects;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.revocation.RevocationRecord;

/**
 * Closeable append-ordered feed over one immutable captured revocation-log head.
 * Opening or resuming is constant time. Each advance takes time linear in one
 * bounded record and retains only that record as auxiliary heap state.
 *
 * <p>Opening rejects a malformed, foreign, or structurally out-of-head position.
 * A same-store, structurally plausible position opens without decoding its next
 * record. The first {@link #next()} validates exact authoritative-log continuity
 * and commitment before yielding or advancing and reports an inconsistency as an
 * {@link IOException}.</p>
 *
 * <p>Instances are stateful and not thread-safe. A position is exclusive: a feed
 * resumed from an entry's {@link Entry#nextPosition()} begins with the following
 * append. Closing is idempotent; every other operation fails after close.</p>
 */
public interface RevocationTransitionFeed extends AutoCloseable {

    /** Maximum accepted opaque position length. */
    int MAXIMUM_POSITION_CHARACTERS = 192;

    /**
     * Provider-defined opaque exclusive resume position.
     *
     * <p>A position is a non-authoritative cursor usable only through an already
     * held {@link PkiStore} capability. It detects accidental local corruption;
     * its checksum is not a message authentication code. A position must never be
     * used for authentication or authorization and must be persisted only inside
     * an authenticated store.</p>
     *
     * @param value bounded URL-safe opaque value
     */
    record Position(String value) {
        /** Validates and snapshots the immutable position value. */
        public Position {
            if (value == null || value.isEmpty() || value.length() > MAXIMUM_POSITION_CHARACTERS
                    || !value.matches("[A-Za-z0-9_-]+")) {
                throw new IllegalArgumentException("Revocation feed position is invalid");
            }
        }

        /** Returns the opaque value. */
        @Override public String toString() { return value; }
    }

    /**
     * Immutable source head captured when the feed was opened.
     *
     * @param sourceStoreId durable source-store identity
     * @param globalRevision captured global append revision, zero for an empty log
     * @param transitionCommitment captured chain commitment, including the genesis commitment
     */
    record HighWatermark(MetadataStoreId sourceStoreId, long globalRevision, String transitionCommitment) {
        /** Validates the immutable captured head. */
        public HighWatermark {
            Objects.requireNonNull(sourceStoreId, "sourceStoreId");
            if (globalRevision < 0L || transitionCommitment == null
                    || !transitionCommitment.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Revocation feed high watermark is invalid");
            }
        }
    }

    /**
     * One authenticated append entry.
     *
     * @param sourceStoreId durable source-store identity
     * @param globalRevision contiguous global append revision
     * @param transitionCommitment exact authenticated transition commitment
     * @param nextPosition opaque exclusive position immediately after this entry
     * @param record existing immutable revocation record
     */
    record Entry(MetadataStoreId sourceStoreId, long globalRevision, String transitionCommitment,
            Position nextPosition, RevocationRecord record) {
        /** Validates and snapshots one entry. */
        public Entry {
            Objects.requireNonNull(sourceStoreId, "sourceStoreId");
            if (globalRevision <= 0L || transitionCommitment == null
                    || !transitionCommitment.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Revocation feed entry identity is invalid");
            }
            Objects.requireNonNull(nextPosition, "nextPosition");
            Objects.requireNonNull(record, "record");
        }
    }

    /**
     * Returns the immutable head captured at open time.
     *
     * @return captured source head
     * @throws IllegalStateException if this feed is closed
     */
    HighWatermark highWatermark();

    /**
     * Advances to the next append no later than the captured head.
     * The first advance after a resumed open validates the position's exact
     * authoritative-log continuity and commitment before yielding or advancing.
     * Cancellation is checked before and after bounded record decoding; a
     * cancellation, decoding, or continuity failure preserves both the logical
     * position and the entry returned by {@link #current()}.
     *
     * @param cancellation cooperative cancellation signal
     * @return {@code true} when {@link #current()} is available
     * @throws IOException if the captured log prefix is incomplete, corrupt, or noncontiguous
     * @throws IllegalStateException if this feed is closed
     */
    boolean next(CancellationSignal cancellation) throws IOException;

    /**
     * Advances with a non-cancelling signal.
     *
     * @return {@code true} when {@link #current()} is available
     * @throws IOException if the captured log prefix is incomplete, corrupt, or noncontiguous
     */
    default boolean next() throws IOException { return next(CancellationSignal.NONE); }

    /**
     * Returns the current append entry.
     *
     * @return current entry
     * @throws IllegalStateException if closed or not positioned on an entry
     */
    Entry current();

    /** Closes the feed and its file resource; repeated close is harmless. */
    @Override void close() throws IOException;
}
