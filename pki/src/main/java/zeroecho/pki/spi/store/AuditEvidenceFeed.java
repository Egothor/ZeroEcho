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
import java.time.Instant;
import java.util.Objects;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;

/**
 * Closeable append-ordered feed over one family's co-committed success-evidence log.
 *
 * <p>Entries are yielded in strictly increasing sequence, each carrying the produced object's identity,
 * the audit event time, and the family-serialized evidence payload (opaque to this feed). A resumed feed
 * begins strictly after a caller-held sequence, so a bounded audit projector can advance a durable cursor
 * exactly once per entry, matching the crash-consistency of the revocation transition feed. Instances are
 * stateful and not thread-safe; closing is idempotent.</p>
 */
public interface AuditEvidenceFeed extends AutoCloseable {

    /**
     * One append entry.
     *
     * @param sequence contiguous zero-based append sequence
     * @param objectId immutable produced-object identity
     * @param recordedAt audit event time captured at commit
     * @param evidence family-serialized evidence payload
     */
    record Entry(long sequence, PkiId objectId, Instant recordedAt, byte[] evidence) {
        /** Validates and defensively copies one entry. */
        public Entry {
            if (isNegative(sequence)) {
                throw new IllegalArgumentException("Evidence feed sequence must not be negative");
            }
            Objects.requireNonNull(objectId, "objectId");
            Objects.requireNonNull(recordedAt, "recordedAt");
            evidence = Objects.requireNonNull(evidence, "evidence").clone();
        }

        private static boolean isNegative(long value) {
            return value < 0L;
        }

        /**
         * Returns the encoded evidence payload.
         *
         * @return a defensive copy of the evidence payload
         */
        @Override public byte[] evidence() {
            return evidence.clone();
        }
    }

    /**
     * Returns the captured entry count (next sequence) at open time.
     *
     * @return non-negative high watermark
     */
    long highWatermark();

    /**
     * Advances to the next entry strictly after the resumed sequence.
     *
     * @param cancellation cooperative cancellation signal
     * @return {@code true} when {@link #current()} is available
     * @throws IOException if the evidence log cannot be read
     */
    boolean next(CancellationSignal cancellation) throws IOException;

    /**
     * Returns the current entry.
     *
     * @return current entry
     * @throws IllegalStateException if not positioned on an entry
     */
    Entry current();

    /** Closes the feed idempotently. */
    @Override void close();
}
