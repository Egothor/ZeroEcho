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
