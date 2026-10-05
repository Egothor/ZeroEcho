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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataCursor;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataStoreCapabilities;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.MetadataTransactionId;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.StagedContentStore;
import zeroecho.pki.spi.store.TransactionalMetadataStore;

/** Package-private production adapter over the segmented signing ledger. */
// The adapter exposes one transaction boundary over the ledger's storage and recovery collaborators.
@SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops", "PMD.AvoidLiteralsInIfCondition",
        "PMD.AvoidSynchronizedAtMethodLevel", "PMD.AvoidSynchronizedStatement",
        "PMD.CloseResource", "PMD.CommentRequired", "PMD.CompareObjectsWithEquals",
        "PMD.ControlStatementBraces", "PMD.DataClass",
        "PMD.DoNotUseThreads",
        "PMD.UnusedNullCheckInEquals", "PMD.UseTryWithResources", "PMD.CouplingBetweenObjects" })
final class SegmentedTransactionalMetadataStore implements TransactionalMetadataStore { // NOPMD - CyclomaticComplexity totals independent dispatch/codec branches; method-level checks remain enabled.
    private static final int MAXIMUM_ACTIVE_TRANSACTIONS = 256;
    private static final int PAGE_SIZE = 4096;
    private static final long MAXIMUM_RECORD_BYTES = SigningWalFrameCodec.MAX_PAYLOAD_BYTES;
    private static final MetadataStoreCapabilities CAPABILITIES = new MetadataStoreCapabilities(
            MetadataStoreCapabilities.WriterModel.SERIALIZABLE_MULTI_WRITER,
            MetadataStoreCapabilities.ContentLengthModel.KNOWN_LENGTH_ONLY,
            MetadataStoreCapabilities.OutcomeRetention.UNTIL_ACKNOWLEDGED,
            Set.of(MetadataStoreCapabilities.OptionalFeature.CROSS_PROCESS_COORDINATION,
                    MetadataStoreCapabilities.OptionalFeature.CHECKPOINT,
                    MetadataStoreCapabilities.OptionalFeature.COMPACTION),
            OptionalLong.of(MAXIMUM_RECORD_BYTES));

    private final SigningLedgerStoreEngine engine;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicInteger activeTransactions = new AtomicInteger();
    private final Set<SnapshotImpl> snapshots =
            Collections.synchronizedSet(Collections.newSetFromMap(new IdentityHashMap<>()));

    private SegmentedTransactionalMetadataStore(SigningLedgerStoreEngine engine) {
        this.engine = engine;
    }

    /* default */ static SegmentedTransactionalMetadataStore create(Path root,
            MetadataStoreId storeId) throws IOException {
        return new SegmentedTransactionalMetadataStore(SigningLedgerStoreEngine.create(root, storeId));
    }

    /* default */ static SegmentedTransactionalMetadataStore create(Path root,
            MetadataStoreId storeId, SigningActiveWal.Operations walOperations) throws IOException {
        return new SegmentedTransactionalMetadataStore(
                SigningLedgerStoreEngine.create(root, storeId, walOperations));
    }

    /* default */ static SegmentedTransactionalMetadataStore create(Path root,
            MetadataStoreId storeId, SigningActiveWal.Operations walOperations,
            int maximumSigningWork) throws IOException {
        return create(root, storeId, walOperations, maximumSigningWork,
                SigningActiveWal.Configuration.defaults(),
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES,
                FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES);
    }

    /* default */ static SegmentedTransactionalMetadataStore create(Path root,
            MetadataStoreId storeId, SigningActiveWal.Operations walOperations,
            int maximumSigningWork, SigningActiveWal.Configuration activeWalConfiguration)
            throws IOException {
        return create(root, storeId, walOperations, maximumSigningWork,
                activeWalConfiguration,
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES,
                FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES);
    }

    /* default */ static SegmentedTransactionalMetadataStore create(Path root,
            MetadataStoreId storeId, SigningActiveWal.Operations walOperations,
            int maximumSigningWork, SigningActiveWal.Configuration activeWalConfiguration,
            long residentIndexBudgetBytes, long compactionBudgetBytes)
            throws IOException {
        return new SegmentedTransactionalMetadataStore(SigningLedgerStoreEngine.create(
                root, storeId, walOperations, maximumSigningWork, activeWalConfiguration,
                residentIndexBudgetBytes, compactionBudgetBytes));
    }

    /* default */ static SegmentedTransactionalMetadataStore create(Path root,
            MetadataStoreId storeId, SigningActiveWal.Operations walOperations,
            int maximumSigningWork, SigningActiveWal.Configuration activeWalConfiguration,
            long residentIndexBudgetBytes, long compactionBudgetBytes,
            StagedContentStore stagedContent) throws IOException {
        return new SegmentedTransactionalMetadataStore(SigningLedgerStoreEngine.create(
                root, storeId, walOperations, maximumSigningWork, activeWalConfiguration,
                residentIndexBudgetBytes, compactionBudgetBytes,
                Objects.requireNonNull(stagedContent, "stagedContent")));
    }

    /* default */ // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
                  @SuppressWarnings({ "PMD.PreserveStackTrace" })
                  static SegmentedTransactionalMetadataStore open(Path root,
            MetadataStoreId storeId) throws IOException {
        try {
            return new SegmentedTransactionalMetadataStore(
                    SigningLedgerStoreEngine.open(root, storeId));
        } catch (SigningLedgerStoreEngine.FormatUnsupportedException failure) {
            throw new OpenIntegrityException();
        }
    }

    /* default */ static SegmentedTransactionalMetadataStore open(Path root,
            MetadataStoreId storeId, int maximumSigningWork) throws IOException {
        return open(root, storeId, maximumSigningWork, SigningActiveWal.Configuration.defaults(),
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES,
                FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES);
    }

    /* default */ static SegmentedTransactionalMetadataStore open(Path root,
            MetadataStoreId storeId, int maximumSigningWork,
            SigningActiveWal.Configuration activeWalConfiguration) throws IOException {
        return open(root, storeId, maximumSigningWork, activeWalConfiguration,
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES,
                FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES);
    }

    /* default */ // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
                  @SuppressWarnings({ "PMD.PreserveStackTrace" })
                  static SegmentedTransactionalMetadataStore open(Path root,
            MetadataStoreId storeId, int maximumSigningWork,
            SigningActiveWal.Configuration activeWalConfiguration,
            long residentIndexBudgetBytes, long compactionBudgetBytes) throws IOException {
        try {
            return new SegmentedTransactionalMetadataStore(
                    SigningLedgerStoreEngine.open(root, storeId, maximumSigningWork,
                            activeWalConfiguration, residentIndexBudgetBytes,
                            compactionBudgetBytes));
        } catch (SigningLedgerStoreEngine.FormatUnsupportedException failure) {
            throw new OpenIntegrityException();
        }
    }

    /* default */ // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
                  @SuppressWarnings({ "PMD.PreserveStackTrace" })
                  static SegmentedTransactionalMetadataStore open(Path root,
            MetadataStoreId storeId, int maximumSigningWork,
            SigningActiveWal.Configuration activeWalConfiguration,
            long residentIndexBudgetBytes, long compactionBudgetBytes,
            StagedContentStore stagedContent) throws IOException {
        try {
            return new SegmentedTransactionalMetadataStore(
                    SigningLedgerStoreEngine.open(root, storeId, maximumSigningWork,
                            activeWalConfiguration, residentIndexBudgetBytes,
                            compactionBudgetBytes,
                            Objects.requireNonNull(stagedContent, "stagedContent")));
        } catch (SigningLedgerStoreEngine.FormatUnsupportedException failure) {
            throw new OpenIntegrityException();
        }
    }

    /* default */ static SegmentedTransactionalMetadataStore open(Path root) throws IOException {
        Path namespace = Objects.requireNonNull(root, "root").getParent().resolve("SIGNING_NAMESPACE");
        return open(root, new MetadataStoreId(Files.readString(namespace).trim()));
    }

    /** Cause-free marker preserving malformed persistence across store layers. */
    /* default */ static final class OpenIntegrityException extends IOException {
        private static final long serialVersionUID = 1L;

        private OpenIntegrityException() {
            super("Metadata ledger format unsupported: code=METADATA_FORMAT_UNSUPPORTED");
        }
    }

    @Override public MetadataStoreId id() { requireOpen(); return engine.storeId(); }
    @Override public MetadataStoreCapabilities capabilities() { requireOpen(); return CAPABILITIES; }

    @Override
    public MetadataTransaction beginTransaction() throws IOException {
        return beginTransactionInternal(null,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /* default */ MetadataTransaction beginSigningProgressTransaction() throws IOException {
        return beginTransactionInternal(null,
                SigningTransitionWorkspaceSizing.AdmissionClass
                        .PROTECTED_ACCEPTED_SIGNING);
    }

    /* default */ MetadataTransaction beginTransaction(
            SigningLedgerStoreEngine.SigningAdmission signingAdmission) throws IOException {
        Objects.requireNonNull(signingAdmission, "signingAdmission");
        return beginTransactionInternal(signingAdmission,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    private MetadataTransaction beginTransactionInternal(
            SigningLedgerStoreEngine.SigningAdmission signingAdmission,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) throws IOException {
        requireOpen();
        if (signingAdmission != null) engine.requireSigningAdmission(signingAdmission);
        int count = activeTransactions.incrementAndGet();
        if (count > MAXIMUM_ACTIVE_TRANSACTIONS) {
            activeTransactions.decrementAndGet();
            if (signingAdmission != null) signingAdmission.close();
            throw new MetadataStoreException(MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                    "Metadata transaction capacity is exhausted");
        }
        boolean issued = false;
        try {
            TransactionImpl transaction = new TransactionImpl(
                    engine.issue(admissionClass), signingAdmission, admissionClass);
            issued = true;
            return transaction;
        } finally {
            if (!issued) {
                activeTransactions.decrementAndGet();
                if (signingAdmission != null) signingAdmission.close();
            }
        }
    }

    @Override public MetadataCommitResult resolve(MetadataTransactionId transactionId)
            throws IOException { requireOpen(); return engine.resolve(transactionId); }
    @Override public void acknowledge(MetadataTransactionId transactionId)
            throws IOException { requireOpen(); engine.acknowledge(transactionId); }

    @Override
    public MetadataSnapshot snapshot() throws IOException {
        requireOpen();
        SnapshotImpl snapshot = new SnapshotImpl(engine.snapshot());
        snapshots.add(snapshot);
        return snapshot;
    }

    /* default */ long advanceWatermark(long epochMilli) throws IOException {
        requireOpen();
        return engine.advanceWatermark(epochMilli);
    }

    /* default */ void observeWatermark(long epochMilli) {
        requireOpen();
        engine.observeWatermark(epochMilli);
    }

    /* default */ MetadataCommitResult directCommit(
            List<SigningTransactionPayloadCodec.Mutation> mutations) throws IOException {
        requireOpen();
        return engine.directCommit(mutations);
    }

    /* default */ MetadataCommitResult directSigningProgressCommit(
            List<SigningTransactionPayloadCodec.Mutation> mutations) throws IOException {
        requireOpen();
        return engine.directProgressCommit(mutations);
    }

    /* default */ List<MetadataCommitResult> directCommitCohort(
            List<List<SigningTransactionPayloadCodec.Mutation>> mutationCohort) throws IOException {
        requireOpen();
        return engine.directCommitCohort(mutationCohort);
    }

    /* default */ MetadataCommitResult directCommit(
            List<SigningTransactionPayloadCodec.Mutation> mutations,
            SigningLedgerStoreEngine.SigningAdmission signingAdmission) throws IOException {
        requireOpen();
        return engine.directCommit(mutations, Objects.requireNonNull(
                signingAdmission, "signingAdmission"));
    }

    /* default */ SigningLedgerStoreEngine.ConditionalCommitResult directCommitAtAdmission(
            SigningLedgerStoreEngine.ConditionalDirectCommit decision) throws IOException {
        requireOpen();
        return engine.directCommitAtAdmission(Objects.requireNonNull(decision, "decision"));
    }

    /* default */ SigningLedgerStoreEngine.SigningAdmission reserveAcceptanceCapacity() {
        requireOpen();
        return engine.reserveAcceptanceCapacity();
    }

    /* default */ SigningActiveWal.Snapshot writerSnapshot() {
        requireOpen();
        return engine.writerSnapshot();
    }

    /* default */ SigningActiveWal.Snapshot cumulativeWriterSnapshot() {
        requireOpen();
        return engine.cumulativeWriterSnapshot();
    }

    /* default */ Throwable firstRecoveryFailure() {
        return engine.firstRecoveryFailure();
    }

    /* default */ SigningLedgerStoreEngine.CapacityObservation capacityObservation() {
        requireOpen();
        return engine.capacityObservation();
    }

    /* default */ SigningLedgerStoreEngine.CapacitySnapshot capacitySnapshot() {
        requireOpen();
        return engine.capacitySnapshot();
    }

    /* default */ SigningLedgerRecovery.Statistics recoveryStatistics() {
        requireOpen();
        return engine.recoveryStatistics();
    }

    /* default */ SigningLedgerStoreEngine.RecoveryProjectionStatistics
            recoveryProjectionStatistics() {
        requireOpen();
        return engine.recoveryProjectionStatistics();
    }

    /* default */ long recoveredWatermark() { requireOpen(); return engine.recoveredWatermark(); }

    /* default */ List<String> selectSigningDue(java.time.Instant cutoff, int maximumResults)
            throws IOException {
        requireOpen(); return engine.selectDue(cutoff, maximumResults);
    }

    /* default */ SigningDuePage pageSigningDue(java.time.Instant cutoff,
            Optional<String> exclusiveCursor, Optional<String> inclusiveHighWatermark,
            int maximumResults) throws IOException {
        requireOpen();
        SigningLedgerStoreEngine.DuePage due = engine.pageDue(cutoff, exclusiveCursor,
                inclusiveHighWatermark, maximumResults);
        List<SigningDueCandidate> candidates = due.candidates().stream()
                .map(record -> new SigningDueCandidate(record.operationId(),
                        record.scheduling(), record.malformed()))
                .toList();
        return new SigningDuePage(candidates, due.highWatermark(), due.endReached());
    }

    /* default */ SigningOwnerPage pageSigningOwners(Optional<String> exclusiveCursor,
            int maximumResults) throws IOException {
        requireOpen();
        SigningLedgerStoreEngine.DueSnapshot owners = engine.pageOwners(
                exclusiveCursor, maximumResults);
        boolean transferred = false;
        try {
            SnapshotImpl snapshot = new SnapshotImpl(owners.snapshot());
            snapshots.add(snapshot);
            List<SigningDueCandidate> candidates = owners.selection().records().stream()
                    .map(record -> new SigningDueCandidate(record.operationId(),
                            record.scheduling(), false)).toList();
            SigningOwnerPage page = new SigningOwnerPage(candidates,
                    owners.selection().highWatermark(), owners.selection().endReached(),
                    snapshot, owners);
            transferred = true;
            return page;
        } finally {
            if (!transferred) owners.close();
        }
    }

    /* default */ boolean containsSigningOwner(String operationId) {
        requireOpen();
        return engine.containsOwner(Objects.requireNonNull(operationId, "operationId"));
    }

    /* default */ CurrentSelection selectCurrentFirst(MetadataSnapshot.KeyRange range)
            throws IOException {
        requireOpen();
        return new CurrentSelection(engine.selectCurrentFirst(
                Objects.requireNonNull(range, "range")));
    }

    /* default */ CurrentSelection selectCurrentRange(MetadataSnapshot.KeyRange range)
            throws IOException {
        requireOpen();
        return new CurrentSelection(engine.selectCurrentRange(
                Objects.requireNonNull(range, "range")));
    }

    /* default */ List<String> selectSigningRetention(java.time.Instant createdAtCutoff,
            int maximumResults) {
        requireOpen(); return engine.selectRetention(createdAtCutoff, maximumResults);
    }

    /** Publishes one pinned revision directly as a fresh checkpoint ledger. */
    /* default */ void exportSnapshotTo(Path targetRoot, Set<String> excludedNamespaces)
            throws IOException {
        requireOpen();
        Objects.requireNonNull(targetRoot, "targetRoot");
        SigningLedgerSnapshotExporter.export(engine, targetRoot, excludedNamespaces);
    }

    /* default */ void exportSnapshotTo(MetadataSnapshot snapshot, Path targetRoot, Set<String> excludedNamespaces) throws IOException {
        requireOpen();
        if (!(snapshot instanceof SnapshotImpl exact) || !snapshots.contains(exact)) {
            throw new IllegalArgumentException("Metadata snapshot is closed or foreign");
        }
        exact.requireSnapshotOpen();
        SigningLedgerSnapshotExporter.export(engine, exact.snapshot, targetRoot, excludedNamespaces);
    }

    /** Copies every namespace and preserves authoritative revisions in a bounded backup checkpoint. */
    /* default */ void exportBackupSnapshotTo(MetadataSnapshot snapshot, Path targetRoot, long maximumCheckpointBytes)
            throws IOException {
        requireOpen();
        if (!(snapshot instanceof SnapshotImpl exact) || !snapshots.contains(exact)) {
            throw new IllegalArgumentException("Metadata snapshot is closed or foreign");
        }
        exact.requireSnapshotOpen();
        SigningLedgerSnapshotExporter.exportBackup(engine, exact.snapshot, targetRoot, maximumCheckpointBytes);
    }

    /** Copies one pinned logical revision into a fresh target, excluding rebuilt namespaces. */
    /* default */ void copySnapshotTo(SegmentedTransactionalMetadataStore target,
            Set<String> excludedNamespaces) throws IOException {
        requireOpen();
        Objects.requireNonNull(target, "target");
        Set<String> excluded = Set.copyOf(excludedNamespaces);
        try (SigningMvccIndex.Snapshot source = engine.snapshot()) {
            List<SigningLedgerStoreEngine.SnapshotOutcome> retainedOutcomes = new ArrayList<>();
            OptionalLong pinnedWatermark = OptionalLong.empty();
            MetadataKey lower = new MetadataKey("0", "!");
            MetadataKey previous = null;
            while (true) {
                List<SigningMvccIndex.SnapshotRecord> page = source.rangeFrom(lower, PAGE_SIZE + 1);
                int offset = previous != null && !page.isEmpty() && page.getFirst().key().equals(previous)
                        ? 1 : 0;
                if (offset >= page.size()) break;
                for (; offset < page.size(); offset++) {
                    SigningMvccIndex.SnapshotRecord record = page.get(offset);
                    previous = record.key();
                    lower = previous;
                    Optional<SigningLedgerStoreEngine.SnapshotOutcome> outcome =
                            engine.snapshotOutcome(record);
                    if (outcome.isPresent()) {
                        retainedOutcomes.add(outcome.orElseThrow());
                        continue;
                    }
                    OptionalLong recordWatermark = engine.snapshotWatermark(record);
                    if (recordWatermark.isPresent()) {
                        pinnedWatermark = recordWatermark;
                        continue;
                    }
                    if (excluded.contains(record.key().namespace())) continue;
                    byte[] value = engine.readValue(record);
                    try (MetadataTransaction transaction = target.beginTransaction();
                            RepeatableContent content = new ByteContent(value)) {
                        transaction.create(record.key(), content, CancellationSignal.NONE);
                        MetadataCommitResult committed = transaction.commit();
                        if (committed.outcome() != MetadataCommitResult.Outcome.COMMITTED) {
                            throw new IOException("Snapshot metadata reconstruction conflicted");
                        }
                        target.acknowledge(committed.transactionId());
                    }
                }
                if (page.size() <= PAGE_SIZE) break;
            }
            for (SigningLedgerStoreEngine.SnapshotOutcome outcome : retainedOutcomes) {
                target.engine.restoreOutcome(outcome);
            }
            if (pinnedWatermark.isPresent()) {
                target.advanceWatermark(pinnedWatermark.getAsLong());
            }
        }
    }

    /* default */ record SigningDueCandidate(String operationId,
            SignWorkflowStore.SchedulingCoordinates scheduling, boolean malformed) { }

    /** Store-local immutable lightweight due page. */
    /* default */ record SigningDuePage(List<SigningDueCandidate> candidates,
            Optional<String> highWatermark, boolean endReached) {
        SigningDuePage {
            candidates = List.copyOf(Objects.requireNonNull(candidates, "candidates"));
            highWatermark = Objects.requireNonNull(highWatermark, "highWatermark");
        }
    }

    /** Store-local owner page whose candidate reads share one pinned revision. */
    /* default */ final class SigningOwnerPage implements AutoCloseable {
        private final List<SigningDueCandidate> candidates;
        private final Optional<String> highWatermark;
        private final boolean endReached;
        private final SnapshotImpl snapshot;
        private final SigningLedgerStoreEngine.DueSnapshot owners;
        private final AtomicBoolean pageClosed = new AtomicBoolean();
        private SigningOwnerPage(List<SigningDueCandidate> candidates,
                Optional<String> highWatermark, boolean endReached, SnapshotImpl snapshot,
                SigningLedgerStoreEngine.DueSnapshot owners) {
            this.candidates = List.copyOf(candidates);
            this.highWatermark = highWatermark;
            this.endReached = endReached;
            this.snapshot = snapshot;
            this.owners = owners;
        }
        /* default */ List<SigningDueCandidate> candidates() {
            requirePageOpen();
            return candidates;
        }
        /* default */ Optional<String> highWatermark() {
            requirePageOpen();
            return highWatermark;
        }
        /* default */ boolean endReached() {
            requirePageOpen();
            return endReached;
        }
        /* default */ MetadataSnapshot snapshot() {
            requirePageOpen();
            return snapshot;
        }
        private void requirePageOpen() {
            if (pageClosed.get()) throw new IllegalStateException("signing owner page is closed");
        }
        @Override public void close() {
            if (pageClosed.compareAndSet(false, true)) {
                snapshot.close();
                owners.close();
            }
        }
    }

    @Override
    public void close() throws IOException {
        if (!closed.compareAndSet(false, true)) return;
        List<SnapshotImpl> open;
        synchronized (snapshots) { open = List.copyOf(snapshots); }
        for (SnapshotImpl snapshot : open) snapshot.close();
        engine.close();
    }

    private void requireOpen() {
        if (closed.get()) throw new IllegalStateException("Metadata store is closed");
    }

    private final class TransactionImpl implements MetadataTransaction {
        private final MetadataTransactionId id;
        private final SigningLedgerStoreEngine.SigningAdmission signingAdmission;
        private final SigningTransitionWorkspaceSizing.AdmissionClass admissionClass;
        private final Thread owner = Thread.currentThread();
        private final Map<MetadataKey, SigningTransactionPayloadCodec.Mutation> mutations =
                new LinkedHashMap<>();
        private State state = State.ACTIVE;
        private int stagedBytes;
        private TransactionImpl(MetadataTransactionId id,
                SigningLedgerStoreEngine.SigningAdmission signingAdmission,
                SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
            this.id = id;
            this.signingAdmission = signingAdmission;
            this.admissionClass = admissionClass;
        }
        @Override public MetadataTransactionId id() { requireActive(); return id; }
        @Override public void create(MetadataKey key, RepeatableContent content,
                CancellationSignal cancellation) throws IOException {
            stage(SigningTransactionPayloadCodec.MutationKind.CREATE, key, -1L, content, cancellation);
        }
        @Override public void replace(MetadataKey key, long expectedRevision,
                RepeatableContent content, CancellationSignal cancellation) throws IOException {
            if (expectedRevision < 0L) throw new IllegalArgumentException("expectedRevision");
            stage(SigningTransactionPayloadCodec.MutationKind.REPLACE, key, expectedRevision,
                    content, cancellation);
        }
        @Override public void delete(MetadataKey key, long expectedRevision) {
            requireActive();
            if (expectedRevision < 0L) throw new IllegalArgumentException("expectedRevision");
            admit(new SigningTransactionPayloadCodec.Mutation(
                    SigningTransactionPayloadCodec.MutationKind.DELETE,
                    Objects.requireNonNull(key, "key"), expectedRevision, null));
        }
        private void stage(SigningTransactionPayloadCodec.MutationKind kind, MetadataKey key,
                long expectedRevision, RepeatableContent content, CancellationSignal cancellation)
                throws IOException {
            requireActive();
            Objects.requireNonNull(content, "content");
            Objects.requireNonNull(cancellation, "cancellation");
            throwIfCancelled(cancellation);
            OptionalLong declared = Objects.requireNonNull(content.length(), "content length");
            if (declared.isEmpty()) {
                throw new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.UNSUPPORTED_CAPABILITY,
                        "Segmented metadata store requires known content length");
            }
            long length = declared.getAsLong();
            if (length < 0L || length > MAXIMUM_RECORD_BYTES
                    || length > Integer.MAX_VALUE || stagedBytes + length > MAXIMUM_RECORD_BYTES) {
                throw new MetadataStoreException(MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                        "Metadata transaction payload exceeds 2 MiB");
            }
            byte[] bytes = new byte[Math.toIntExact(length)];
            try (InputStream input = content.openStream()) {
                int offset = 0;
                while (offset < bytes.length) {
                    throwIfCancelled(cancellation);
                    int count = input.read(bytes, offset, bytes.length - offset);
                    if (count <= 0) throw integrity("Metadata content is shorter than declared");
                    offset += count;
                }
                if (input.read() >= 0) throw integrity("Metadata content is longer than declared");
            }
            admit(new SigningTransactionPayloadCodec.Mutation(kind,
                    Objects.requireNonNull(key, "key"), expectedRevision, bytes));
            stagedBytes = Math.addExact(stagedBytes, bytes.length);
        }
        private void admit(SigningTransactionPayloadCodec.Mutation mutation) {
            requireActive();
            if (mutations.size() == SigningTransactionPayloadCodec.MAXIMUM_MUTATIONS) {
                throw new IllegalStateException("Metadata transaction mutation limit is exhausted");
            }
            if (mutations.putIfAbsent(mutation.key(), mutation) != null) {
                throw new IllegalStateException("Metadata transaction key is duplicated");
            }
        }
        @Override public MetadataCommitResult commit() throws IOException {
            requireActive();
            if (mutations.isEmpty()) throw new IllegalStateException("Metadata transaction is empty");
            state = State.TERMINAL;
            try {
                return engine.commit(id, List.copyOf(mutations.values()),
                        signingAdmission, admissionClass);
            }
            finally { release(); }
        }
        @Override public void abort() throws IOException {
            requireOwner();
            if (state == State.ACTIVE) {
                state = State.TERMINAL;
                try {
                    if (signingAdmission != null) signingAdmission.close();
                    engine.reject(id, MetadataCommitResult.FailureCategory.CANCELLED);
                }
                finally { release(); }
            }
        }
        @Override public void close() throws IOException { if (state == State.ACTIVE) abort(); }
        private void release() {
            for (SigningTransactionPayloadCodec.Mutation mutation : mutations.values()) {
                byte[] value = mutation.content();
                if (value != null) Arrays.fill(value, (byte) 0);
            }
            mutations.clear();
            if (signingAdmission != null) signingAdmission.close();
            activeTransactions.decrementAndGet();
        }
        private void requireActive() {
            requireOwner(); requireOpen();
            if (state != State.ACTIVE) throw new IllegalStateException("Metadata transaction is terminal");
        }
        private void requireOwner() {
            if (Thread.currentThread() != owner)
                throw new IllegalStateException("Metadata transaction is thread-confined");
        }
    }

    private final class SnapshotImpl implements MetadataSnapshot {
        private final SigningMvccIndex.Snapshot snapshot;
        private final AtomicBoolean snapshotClosed = new AtomicBoolean();
        private SnapshotImpl(SigningMvccIndex.Snapshot snapshot) { this.snapshot = snapshot; }
        @Override public MetadataStoreId storeId() { requireSnapshotOpen(); return engine.storeId(); }
        @Override public long revision() { requireSnapshotOpen(); return snapshot.revision(); }
        @Override public Optional<Record> get(MetadataKey key) throws IOException {
            requireSnapshotOpen();
            Optional<SigningMvccIndex.SnapshotRecord> value = snapshot.lookup(Objects.requireNonNull(key, "key"));
            return value.isEmpty() ? Optional.empty() : Optional.of(record(value.orElseThrow()));
        }
        @Override public Optional<MetadataKey> greatestKey(String namespace) {
            requireSnapshotOpen(); return snapshot.greatest(namespace);
        }
        @Override public MetadataCursor scan(KeyRange range, CancellationSignal cancellation)
                throws IOException {
            requireSnapshotOpen();
            Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
            return new CursorImpl(Objects.requireNonNull(range, "range"));
        }
        private RecordImpl record(SigningMvccIndex.SnapshotRecord value) throws IOException {
            return new RecordImpl(value, engine.readValue(value));
        }
        @Override public void close() {
            if (snapshotClosed.compareAndSet(false, true)) {
                snapshot.close(); snapshots.remove(this);
            }
        }
        private void requireSnapshotOpen() {
            if (snapshotClosed.get()) throw new IllegalStateException("Metadata snapshot is closed");
        }

        private final class CursorImpl implements MetadataCursor {
            private final KeyRange range;
            private List<SigningMvccIndex.SnapshotRecord> page = List.of();
            private int offset;
            private MetadataKey nextLower;
            private MetadataKey lastReturned;
            private boolean cursorClosed;
            private CursorImpl(KeyRange range) {
                this.range = range;
                nextLower = new MetadataKey(range.namespace(), range.lowerInclusive().orElse("!"));
            }
            @Override public Optional<Record> next(CancellationSignal cancellation) throws IOException {
                requireCursorOpen();
                Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
                while (offset >= page.size()) {
                    page = snapshot.rangeFrom(nextLower, PAGE_SIZE + 1); offset = 0;
                    if (page.isEmpty()) return Optional.empty();
                    if (lastReturned != null && page.getFirst().key().equals(lastReturned)) offset++;
                    if (offset >= page.size()) return Optional.empty();
                }
                SigningMvccIndex.SnapshotRecord value = page.get(offset++);
                if (!range.contains(value.key())) return Optional.empty();
                lastReturned = value.key(); nextLower = lastReturned;
                return Optional.of(record(value));
            }
            @Override public void close() { cursorClosed = true; page = List.of(); }
            private void requireCursorOpen() {
                requireSnapshotOpen();
                if (cursorClosed) throw new IllegalStateException("Metadata cursor is closed");
            }
        }

        private final class RecordImpl implements MetadataSnapshot.Record {
            private final SigningMvccIndex.SnapshotRecord metadata;
            private final byte[] value;
            private final AtomicBoolean recordClosed = new AtomicBoolean();
            private RecordImpl(SigningMvccIndex.SnapshotRecord metadata, byte[] value) {
                this.metadata = metadata; this.value = value;
            }
            @Override public MetadataKey key() { requireRecordOpen(); return metadata.key(); }
            @Override public long recordRevision() { requireRecordOpen(); return metadata.revision(); }
            @Override public long commitRevision() { requireRecordOpen(); return metadata.revision(); }
            @Override public Optional<MetadataSnapshot.Integrity> integrity() {
                requireRecordOpen();
                return Optional.empty();
            }
            @Override public InputStream openStream() { requireRecordOpen(); return new OwnedStream(this, value); }
            @Override public OptionalLong length() { requireRecordOpen(); return OptionalLong.of(value.length); }
            @Override public String contentId() {
                requireRecordOpen();
                return "zeroecho-segmented-metadata-v1:" + engine.storeId().value() + ':'
                        + metadata.key().canonical() + ':' + metadata.revision();
            }
            @Override public void close() { recordClosed.set(true); }
            private void requireRecordOpen() {
                requireSnapshotOpen();
                if (recordClosed.get()) throw new IllegalStateException("Metadata record is closed");
            }
        }
    }

    /** Short-lived package-local current record selection. */
    /* default */ final class CurrentSelection implements AutoCloseable {
        private final SigningCurrentSelection selection;
        private final AtomicBoolean selectionClosed = new AtomicBoolean();
        private int offset;

        private CurrentSelection(SigningCurrentSelection selection) {
            this.selection = selection;
        }

        /* default */ Optional<MetadataSnapshot.Record> next() throws IOException {
            requireSelectionOpen();
            List<SigningMvccIndex.SnapshotRecord> records = selection.records();
            if (offset >= records.size()) {
                return Optional.empty();
            }
            SigningMvccIndex.SnapshotRecord metadata = records.get(offset);
            byte[] value = engine.readValue(metadata);
            offset++;
            return Optional.of(new RecordImpl(metadata, value));
        }

        @Override
        public void close() {
            if (selectionClosed.compareAndSet(false, true)) {
                selection.close();
            }
        }

        private void requireSelectionOpen() {
            if (selectionClosed.get()) {
                throw new IllegalStateException("Metadata current selection is closed");
            }
        }

        private final class RecordImpl implements MetadataSnapshot.Record {
            private final SigningMvccIndex.SnapshotRecord metadata;
            private final byte[] value;
            private final AtomicBoolean recordClosed = new AtomicBoolean();

            private RecordImpl(SigningMvccIndex.SnapshotRecord metadata, byte[] value) {
                this.metadata = metadata;
                this.value = value;
            }

            @Override public MetadataKey key() { requireRecordOpen(); return metadata.key(); }
            @Override public long recordRevision() { requireRecordOpen(); return metadata.revision(); }
            @Override public long commitRevision() { requireRecordOpen(); return metadata.revision(); }
            @Override public Optional<MetadataSnapshot.Integrity> integrity() {
                requireRecordOpen();
                return Optional.empty();
            }
            @Override public InputStream openStream() {
                requireRecordOpen();
                return new CurrentOwnedStream(this, value);
            }
            @Override public OptionalLong length() {
                requireRecordOpen();
                return OptionalLong.of(value.length);
            }
            @Override public String contentId() {
                requireRecordOpen();
                return "zeroecho-segmented-metadata-v1:" + engine.storeId().value() + ':'
                        + metadata.key().canonical() + ':' + metadata.revision();
            }
            @Override public void close() { recordClosed.set(true); }

            private void requireRecordOpen() {
                requireSelectionOpen();
                if (recordClosed.get()) {
                    throw new IllegalStateException("Metadata current record is closed");
                }
            }
        }
    }

    private static final class OwnedStream extends ByteArrayInputStream {
        private final SnapshotImpl.RecordImpl owner;
        private OwnedStream(SnapshotImpl.RecordImpl owner, byte[] value) { super(value); this.owner = owner; }
        @Override public synchronized int read() { owner.requireRecordOpen(); return super.read(); }
        @Override public synchronized int read(byte[] bytes, int offset, int length) {
            owner.requireRecordOpen(); return super.read(bytes, offset, length);
        }
    }

    private static final class CurrentOwnedStream extends ByteArrayInputStream {
        private final CurrentSelection.RecordImpl owner;
        private CurrentOwnedStream(CurrentSelection.RecordImpl owner, byte[] value) {
            super(value);
            this.owner = owner;
        }
        @Override public synchronized int read() { owner.requireRecordOpen(); return super.read(); }
        @Override public synchronized int read(byte[] bytes, int offset, int length) {
            owner.requireRecordOpen(); return super.read(bytes, offset, length);
        }
    }

    private static final class ByteContent implements RepeatableContent {
        private final byte[] value;
        private ByteContent(byte[] value) { this.value = value.clone(); }
        @Override public InputStream openStream() { return new ByteArrayInputStream(value); }
        @Override public OptionalLong length() { return OptionalLong.of(value.length); }
        @Override public String contentId() { return "snapshot-metadata"; }
        @Override public void close() { Arrays.fill(value, (byte) 0); }
    }

    private static void throwIfCancelled(CancellationSignal cancellation) throws MetadataStoreException {
        try { cancellation.throwIfCancelled(); }
        catch (InterruptedIOException failure) {
            throw new MetadataStoreException(MetadataCommitResult.FailureCategory.CANCELLED,
                    "Metadata content staging was cancelled", failure);
        }
    }
    private static MetadataStoreException integrity(String message) {
        return new MetadataStoreException(MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE, message);
    }
    private enum State { ACTIVE, TERMINAL }
}
