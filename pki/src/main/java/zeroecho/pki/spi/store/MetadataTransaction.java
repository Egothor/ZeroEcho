/*
 * Copyright (c) 2025 ZeroEcho
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
