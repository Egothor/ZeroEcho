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
package zeroecho.pki.spi.ct;

/**
 * Append-only, Merkle-chained CT audit journal.
 *
 * <p>The journal records the SHA-256 fingerprint of every certificate issued by
 * the PKI instance. Each entry is chained to the previous entry via its
 * {@link CtJournalEntry#entryHash()} field, making the log tamper-evident.
 * Any post-hoc modification to an entry breaks the chain and is detectable
 * by {@link #verify(long, long)}.</p>
 *
 * <h2>Thread safety</h2>
 * <p>Implementations must be thread-safe. Concurrent calls to {@link #append}
 * must serialize correctly; concurrent calls to {@link #lookup} and
 * {@link #latestSequenceNumber} may execute concurrently with each other and
 * with {@link #append}.</p>
 *
 * @since 1.0
 */
public interface CtJournalStore extends AutoCloseable {

    /**
     * Appends one entry to the journal and fsyncs the backing store.
     *
     * <p>The entry's {@code sequenceNumber} must be exactly
     * {@code latestSequenceNumber() + 1} at the time of the call. The
     * {@code previousHash} must match the current head entry's {@code entryHash},
     * or be all-zeros if the journal is empty.</p>
     *
     * @param entry validated journal entry to append; must not be {@code null}
     * @throws CtJournalException   if the write or fsync fails, or if the entry
     *                              violates sequence or chain constraints
     * @throws NullPointerException if {@code entry} is {@code null}
     */
    void append(CtJournalEntry entry) throws CtJournalException;

    /**
     * Looks up a journal entry by certificate SHA-256 fingerprint.
     *
     * @param certSha256 32-byte SHA-256 fingerprint of the DER-encoded certificate;
     *                   must not be {@code null}
     * @return the matching entry
     * @throws CtJournalException   if the entry is not found or if a read failure occurs
     * @throws NullPointerException if {@code certSha256} is {@code null}
     */
    CtJournalEntry lookup(byte[] certSha256) throws CtJournalException;

    /**
     * Returns the sequence number of the most recently appended entry.
     *
     * @return current head sequence number, or {@code 0} if the journal is empty
     */
    long latestSequenceNumber();

    /**
     * Re-computes and validates the hash chain for the specified sequence range.
     *
     * <p>This is an O(n) scan over the checked range. For very large journals,
     * supply a narrow range to keep latency bounded.</p>
     *
     * @param fromSequence inclusive first sequence number to check; must be positive
     * @param toSequence   inclusive last sequence number to check; must be ≥ {@code fromSequence}
     * @return verification result indicating whether the chain is intact and listing
     *         any broken sequence numbers
     * @throws CtJournalException   if a read failure prevents verification from completing
     * @throws IllegalArgumentException if {@code fromSequence} or {@code toSequence} are invalid
     */
    CtJournalVerificationResult verify(long fromSequence, long toSequence) throws CtJournalException;

    /**
     * Releases all resources held by this journal store.
     *
     * <p>After {@code close()}, all other methods throw {@link IllegalStateException}.
     * Calling {@code close()} on an already-closed store is a no-op.</p>
     */
    @Override
    void close();
}
