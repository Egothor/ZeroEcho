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
package zeroecho.pki.impl.fs;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.Set;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataStoreCapabilities;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.MetadataTransactionId;
import zeroecho.pki.spi.store.TransactionalMetadataStore;

/**
 * POSIX exclusive-writer implementation of the transactional metadata-store SPI.
 *
 * <p>Content admission is synchronous and known-length only. Transactions stage
 * payloads with bounded heap, while snapshots copy finite metadata and read
 * repeatable bounded slices from the append-only log.</p>
 *
 * <p>Instances are thread-safe. Transactions are thread-confined and single-use.
 * Closing a snapshot invalidates all records and cursors it issued.</p>
 */
public final class PosixTransactionalMetadataStore implements TransactionalMetadataStore {
    private final PosixMetadataStoreEngine engine;
    private final MetadataStoreId storeId;
    private final MetadataStoreCapabilities capabilities;
    private final PosixMetadataAdapterLifecycle lifecycle;
    private final PosixMetadataTransactionSupport transactions;
    private final PosixMetadataSnapshotSupport snapshots;

    private PosixTransactionalMetadataStore(
            Path logPath,
            PosixMetadataStoreEngine engine,
            OptionalLong maximumRecordBytes,
            PosixMetadataTransactionSupport.StagingOperations stagingOperations) {
        this(logPath, engine, maximumRecordBytes, stagingOperations, engine::openValueSlice);
    }

    private PosixTransactionalMetadataStore(
            Path logPath,
            PosixMetadataStoreEngine engine,
            OptionalLong maximumRecordBytes,
            PosixMetadataTransactionSupport.StagingOperations stagingOperations,
            PosixMetadataSnapshotSupport.SliceOpener sliceOpener) {
        this.engine = Objects.requireNonNull(engine, "engine");
        this.storeId = engine.storeId();
        Path normalized = Objects.requireNonNull(logPath, "logPath")
                .toAbsolutePath().normalize();
        Path stagingDirectory = Objects.requireNonNull(normalized.getParent(), "log parent");
        this.capabilities = capabilities(maximumRecordBytes);
        this.lifecycle = new PosixMetadataAdapterLifecycle();
        this.transactions = new PosixMetadataTransactionSupport(
                engine, lifecycle, stagingDirectory, maximumRecordBytes, stagingOperations);
        this.snapshots = new PosixMetadataSnapshotSupport(
                engine, lifecycle, storeId, sliceOpener);
    }

    /**
     * Creates a new append-only store without an adapter-specific record limit.
     *
     * @param logPath new log path in a trusted POSIX directory
     * @param storeId durable store identity
     * @return opened metadata store
     * @throws IOException when exclusive initialization or durability fails
     */
    public static PosixTransactionalMetadataStore create(
            Path logPath, MetadataStoreId storeId) throws IOException {
        return create(logPath, storeId, OptionalLong.empty());
    }

    /**
     * Creates a new append-only store.
     *
     * @param logPath new log path in a trusted POSIX directory
     * @param storeId durable store identity
     * @param maximumRecordBytes optional positive adapter technical limit
     * @return opened metadata store
     * @throws IOException when exclusive initialization or durability fails
     */
    public static PosixTransactionalMetadataStore create(
            Path logPath,
            MetadataStoreId storeId,
            OptionalLong maximumRecordBytes) throws IOException {
        MetadataStoreCapabilities validated = capabilities(maximumRecordBytes);
        PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.create(logPath, storeId);
        return new PosixTransactionalMetadataStore(
                logPath,
                engine,
                validated.maximumIndividualRecordBytes(),
                PosixMetadataTransactionSupport.DefaultStagingOperations.INSTANCE);
    }

    /**
     * Opens an existing append-only store without an adapter-specific record limit.
     *
     * @param logPath existing log path in a trusted POSIX directory
     * @return opened metadata store
     * @throws IOException when locking, recovery, or durability fails
     */
    public static PosixTransactionalMetadataStore open(Path logPath) throws IOException {
        return open(logPath, OptionalLong.empty());
    }

    /**
     * Opens an existing append-only store.
     *
     * @param logPath existing log path in a trusted POSIX directory
     * @param maximumRecordBytes optional positive adapter technical limit
     * @return opened metadata store
     * @throws IOException when locking, recovery, or durability fails
     */
    public static PosixTransactionalMetadataStore open(
            Path logPath, OptionalLong maximumRecordBytes) throws IOException {
        MetadataStoreCapabilities validated = capabilities(maximumRecordBytes);
        PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.open(logPath);
        return new PosixTransactionalMetadataStore(
                logPath,
                engine,
                validated.maximumIndividualRecordBytes(),
                PosixMetadataTransactionSupport.DefaultStagingOperations.INSTANCE);
    }

    /* default */ static PosixTransactionalMetadataStore createForTest(
            Path logPath,
            MetadataStoreId storeId,
            OptionalLong maximumRecordBytes,
            PosixMetadataTransactionSupport.StagingOperations stagingOperations,
            PosixMetadataLog.FaultInjector logFaults,
            PosixMetadataStoreEngine.FaultInjector engineFaults) throws IOException {
        MetadataStoreCapabilities validated = capabilities(maximumRecordBytes);
        PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.create(
                logPath, storeId, logFaults, engineFaults);
        return new PosixTransactionalMetadataStore(
                logPath,
                engine,
                validated.maximumIndividualRecordBytes(),
                stagingOperations);
    }

    /* default */ static PosixTransactionalMetadataStore createForTest(
            Path logPath,
            MetadataStoreId storeId,
            OptionalLong maximumRecordBytes,
            PosixMetadataTransactionSupport.StagingOperations stagingOperations,
            PosixMetadataLog.FaultInjector logFaults,
            PosixMetadataStoreEngine.FaultInjector engineFaults,
            PosixMetadataSnapshotSupport.SliceOpener sliceOpener) throws IOException {
        MetadataStoreCapabilities validated = capabilities(maximumRecordBytes);
        PosixMetadataStoreEngine engine = PosixMetadataStoreEngine.create(
                logPath, storeId, logFaults, engineFaults);
        return new PosixTransactionalMetadataStore(
                logPath,
                engine,
                validated.maximumIndividualRecordBytes(),
                stagingOperations,
                sliceOpener);
    }

    /* default */ int activeOperationsForTest() {
        return lifecycle.activeOperationCount();
    }

    /* default */ void awaitClosingForTest() {
        lifecycle.awaitClosing();
    }

    /** {@inheritDoc} */
    @Override
    public MetadataStoreId id() {
        lifecycle.verifyOpen();
        return storeId;
    }

    /** {@inheritDoc} */
    @Override
    public MetadataStoreCapabilities capabilities() {
        lifecycle.verifyOpen();
        return capabilities;
    }

    /** {@inheritDoc} */
    @Override
    public MetadataTransaction beginTransaction() throws IOException {
        return transactions.begin();
    }

    /** {@inheritDoc} */
    @Override
    public MetadataCommitResult resolve(MetadataTransactionId transactionId) throws IOException {
        return transactions.resolve(transactionId);
    }

    /** {@inheritDoc} */
    @Override
    public void acknowledge(MetadataTransactionId transactionId) throws IOException {
        transactions.acknowledge(transactionId);
    }

    /** {@inheritDoc} */
    @Override
    public MetadataSnapshot snapshot() throws IOException {
        return snapshots.open();
    }

    /** {@inheritDoc} */
    @Override
    public void close() throws IOException {
        lifecycle.close(engine);
    }

    private static MetadataStoreCapabilities capabilities(OptionalLong maximumRecordBytes) {
        return new MetadataStoreCapabilities(
                MetadataStoreCapabilities.WriterModel.EXCLUSIVE_WRITER,
                MetadataStoreCapabilities.ContentLengthModel.KNOWN_LENGTH_ONLY,
                MetadataStoreCapabilities.OutcomeRetention.INDEFINITE,
                Set.of(MetadataStoreCapabilities.OptionalFeature.CROSS_PROCESS_COORDINATION),
                Objects.requireNonNull(maximumRecordBytes, "maximumRecordBytes"));
    }
}
