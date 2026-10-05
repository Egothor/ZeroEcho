/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
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

/**
 * Provider-neutral authority for finite transactional control metadata.
 *
 * <p>The store supports atomic mutations across namespaces, retained commit
 * outcomes, stable snapshots, and streaming iteration. It does not store
 * aggregate certificate, CRL, or staged-content payloads and exposes no
 * filesystem, database, or PKI-domain concepts.
 */
public interface TransactionalMetadataStore extends AutoCloseable {

    /**
     * Returns this durable store authority identity.
     *
     * @return store identity
     */
    MetadataStoreId id();

    /**
     * Returns immutable adapter capabilities.
     *
     * @return capability descriptor
     */
    MetadataStoreCapabilities capabilities();

    /**
     * Begins a single-use store-issued transaction.
     *
     * @return live transaction bound to this store instance
     * @throws IOException when durable transaction issuance fails
     * @throws MetadataStoreException when required capabilities or lifecycle are invalid
     */
    MetadataTransaction beginTransaction() throws IOException;

    /**
     * Resolves a transaction outcome retained by this store.
     *
     * <p>{@link MetadataCommitResult.Outcome#UNKNOWN} does not imply commit or
     * rollback and must be resolved through the owning store. A syntactically
     * valid but unissued identity fails closed rather than being treated as
     * authoritative {@code NOT_COMMITTED} evidence.
     *
     * @param transactionId store-issued transaction identity
     * @return retained authoritative result, or still-unknown observation
     * @throws IOException when resolution storage cannot be read
     * @throws MetadataStoreException for foreign, malformed, or unissued identities
     */
    MetadataCommitResult resolve(MetadataTransactionId transactionId) throws IOException;

    /**
     * Acknowledges a terminal retained outcome when supported.
     *
     * @param transactionId store-issued transaction identity
     * @throws IOException when outcome retention cannot be updated
     * @throws MetadataStoreException for foreign, unissued, or non-terminal identities
     */
    void acknowledge(MetadataTransactionId transactionId) throws IOException;

    /**
     * Opens a stable snapshot of the latest committed store revision.
     *
     * @return live snapshot bound to this store instance
     * @throws IOException when the snapshot cannot be established
     * @throws MetadataStoreException when the store is closed
     */
    MetadataSnapshot snapshot() throws IOException;

    /**
     * Closes the store idempotently.
     *
     * @throws IOException when store-owned resources cannot be retired
     */
    @Override
    void close() throws IOException;
}
