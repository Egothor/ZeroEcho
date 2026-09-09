/*******************************************************************************
 * Copyright (c) 2025 ZeroEcho
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
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;

/**
 * A single-use, store-issued metadata transaction.
 *
 * <p>Implementations synchronously detach supplied content before a mutation
 * method returns. Transactions are thread-confined and reject operations
 * after commit, abort, or close. A revision conflict terminates the complete
 * transaction without exposing a subset of its mutations.
 */
public interface MetadataTransaction extends AutoCloseable {

    /**
     * Returns the store-issued transaction identity.
     *
     * @return transaction identity
     */
    MetadataTransactionId id();

    /**
     * Adds a create-if-absent mutation.
     *
     * @param key semantic record identity
     * @param content repeatable finite control metadata
     * @param cancellation cooperative cancellation signal
     * @throws IOException when content staging fails
     * @throws MetadataStoreException when the mutation is invalid or unsupported
     */
    void create(
            MetadataKey key,
            RepeatableContent content,
            CancellationSignal cancellation) throws IOException;

    /**
     * Adds a compare-and-replace mutation.
     *
     * @param key semantic record identity
     * @param expectedRevision required current non-negative record revision
     * @param content repeatable finite control metadata
     * @param cancellation cooperative cancellation signal
     * @throws IOException when content staging fails
     * @throws MetadataStoreException when the mutation is invalid or unsupported
     */
    void replace(
            MetadataKey key,
            long expectedRevision,
            RepeatableContent content,
            CancellationSignal cancellation) throws IOException;

    /**
     * Adds a compare-and-delete mutation.
     *
     * @param key semantic record identity
     * @param expectedRevision required current non-negative record revision
     */
    void delete(MetadataKey key, long expectedRevision);

    /**
     * Attempts one atomic durable commit.
     *
     * <p>A {@link MetadataCommitResult.Outcome#COMMITTED} outcome is the only
     * immediate result that authorizes a caller to report durable metadata
     * success. {@link MetadataCommitResult.Outcome#UNKNOWN} is uncertainty
     * about an already fixed attempt; it does not permit delayed execution.
     *
     * @return authoritative or immediately observable commit result
     * @throws IOException when the store cannot complete the operation
     * @throws MetadataStoreException when transaction authority or lifecycle is invalid
     */
    MetadataCommitResult commit() throws IOException;

    /**
     * Aborts the transaction and releases detached staging resources.
     *
     * @throws IOException when resource retirement fails
     */
    void abort() throws IOException;

    /**
     * Closes the transaction idempotently, aborting an uncommitted transaction.
     *
     * @throws IOException when resource retirement fails
     */
    @Override
    void close() throws IOException;
}
