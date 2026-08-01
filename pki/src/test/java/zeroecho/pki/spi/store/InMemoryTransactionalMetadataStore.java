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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;

/**
 * Deterministic test-only contract oracle. Values are detached to files with a
 * bounded transfer buffer; this class is not production persistence.
 */
final class InMemoryTransactionalMetadataStore implements TransactionalMetadataStore {
    private static final int TRANSFER_BUFFER_SIZE = 8192;

    private final Object authority = new Object();
    private final MetadataStoreId storeId;
    private final MetadataStoreCapabilities capabilities;
    private final Path root;
    private final NavigableMap<MetadataKey, StoredRecord> current = new TreeMap<>();
    private final Map<MetadataTransactionId, MetadataCommitResult> outcomes = new HashMap<>();
    private final Map<MetadataTransactionId, Boolean> issued = new HashMap<>();
    private final List<Path> ownedFiles = new ArrayList<>();
    private final AtomicInteger openedSources = new AtomicInteger();
    private final CountDownLatch closingStarted = new CountDownLatch(1);
    private long storeRevision;
    private long transactionSequence;
    private int activeAdmissions;
    private boolean closing;
    private boolean closed;
    private boolean hideNextCommittedOutcome;

    InMemoryTransactionalMetadataStore(
            Path root,
            MetadataStoreCapabilities.ContentLengthModel lengthModel,
            OptionalLong maximumRecordSize) throws IOException {
        this(
                root,
                new MetadataStoreId(UUID.randomUUID().toString().replace("-", "")),
                lengthModel,
                maximumRecordSize);
    }

    InMemoryTransactionalMetadataStore(
            Path root,
            MetadataStoreId storeId,
            MetadataStoreCapabilities.ContentLengthModel lengthModel,
            OptionalLong maximumRecordSize) throws IOException {
        this.root = Files.createDirectories(root);
        this.storeId = storeId;
        this.capabilities = new MetadataStoreCapabilities(
                MetadataStoreCapabilities.WriterModel.SERIALIZABLE_MULTI_WRITER,
                lengthModel,
                MetadataStoreCapabilities.OutcomeRetention.INDEFINITE,
                Collections.unmodifiableSet(EnumSet.noneOf(
                        MetadataStoreCapabilities.OptionalFeature.class)),
                maximumRecordSize);
    }

    void hideNextCommittedOutcome() {
        hideNextCommittedOutcome = true;
    }

    int openedSourceCount() {
        return openedSources.get();
    }

    synchronized int activeAdmissionCount() {
        return activeAdmissions;
    }

    void awaitClosingStarted() throws InterruptedException {
        closingStarted.await();
    }

    @Override
    public synchronized MetadataStoreId id() {
        return storeId;
    }

    @Override
    public MetadataStoreCapabilities capabilities() {
        return capabilities;
    }

    @Override
    public synchronized MetadataTransaction beginTransaction() {
        requireOpen();
        transactionSequence = Math.addExact(transactionSequence, 1L);
        MetadataTransactionId transactionId =
                new MetadataTransactionId(storeId, String.format("%032x", transactionSequence));
        issued.put(transactionId, Boolean.TRUE);
        return new Transaction(transactionId);
    }

    @Override
    public synchronized MetadataCommitResult resolve(MetadataTransactionId transactionId)
            throws MetadataStoreException {
        requireOpen();
        validateTransactionIdentity(transactionId);
        MetadataCommitResult result = outcomes.get(transactionId);
        if (result == null) {
            throw failure(
                    MetadataCommitResult.FailureCategory.TRANSACTION_NOT_ISSUED,
                    "Transaction has no retained authoritative result");
        }
        return result;
    }

    @Override
    public synchronized void acknowledge(MetadataTransactionId transactionId)
            throws MetadataStoreException {
        requireOpen();
        validateTransactionIdentity(transactionId);
        if (!outcomes.containsKey(transactionId)) {
            throw failure(
                    MetadataCommitResult.FailureCategory.TRANSACTION_NOT_ISSUED,
                    "Transaction has no retained authoritative result");
        }
    }

    @Override
    public synchronized MetadataSnapshot snapshot() {
        requireOpen();
        NavigableMap<MetadataKey, StoredRecord> view =
                Collections.unmodifiableNavigableMap(new TreeMap<>(current));
        return new Snapshot(authority, storeRevision, view);
    }

    @Override
    public void close() throws IOException {
        List<Path> files;
        synchronized (this) {
            if (closed) {
                return;
            }
            closing = true;
            closingStarted.countDown();
            while (activeAdmissions != 0) {
                awaitLifecycleChange();
            }
            if (closed) {
                return;
            }
            closed = true;
            files = List.copyOf(ownedFiles);
            ownedFiles.clear();
            notifyAll();
        }
        IOException failure = null;
        for (Path path : files) {
            try {
                Files.deleteIfExists(path);
            } catch (IOException exception) {
                failure = exception;
            }
        }
        try {
            Files.deleteIfExists(root);
        } catch (IOException exception) {
            failure = exception;
        }
        if (failure != null) {
            throw failure;
        }
    }

    private void awaitLifecycleChange() throws IOException {
        try {
            wait();
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while closing metadata test store", exception);
        }
    }

    private StagedValue stageDetached(
            RepeatableContent source,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(cancellation, "cancellation");
        cancellation.throwIfCancelled();
        OptionalLong declaredLength = source.length();
        if (declaredLength.isEmpty()
                && capabilities.contentLengthModel()
                        == MetadataStoreCapabilities.ContentLengthModel.KNOWN_LENGTH_ONLY) {
            throw failure(
                    MetadataCommitResult.FailureCategory.UNSUPPORTED_CAPABILITY,
                    "Adapter requires known metadata length");
        }
        if (declaredLength.isPresent()) {
            checkTechnicalLimit(declaredLength.getAsLong());
        }
        Path spool = Files.createTempFile(root, "metadata-", ".spool");
        long count = 0L;
        boolean complete = false;
        try (InputStream input = source.openStream();
                java.io.OutputStream output = Files.newOutputStream(
                        spool, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            openedSources.incrementAndGet();
            byte[] buffer = new byte[TRANSFER_BUFFER_SIZE];
            while (true) {
                cancellation.throwIfCancelled();
                int read = input.read(buffer);
                if (read < 0) {
                    break;
                }
                if (read == 0) {
                    continue;
                }
                count = Math.addExact(count, read);
                checkTechnicalLimit(count);
                output.write(buffer, 0, read);
            }
            cancellation.throwIfCancelled();
            if (declaredLength.isPresent() && declaredLength.getAsLong() != count) {
                throw new IOException("Declared metadata length differs from streamed length");
            }
            complete = true;
            return new StagedValue(spool, count);
        } catch (ArithmeticException exception) {
            throw new IOException("Metadata length is not representable", exception);
        } finally {
            if (!complete) {
                Files.deleteIfExists(spool);
            }
        }
    }

    private void checkTechnicalLimit(long length) throws MetadataStoreException {
        OptionalLong maximum = capabilities.maximumIndividualRecordBytes();
        if (maximum.isPresent() && length > maximum.getAsLong()) {
            throw failure(
                    MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                    "Metadata exceeds adapter technical record limit");
        }
    }

    private synchronized MetadataCommitResult commit(Transaction transaction) {
        requireOpen();
        for (StagedMutation mutation : transaction.mutations.values()) {
            StoredRecord record = current.get(mutation.key);
            if (mutation.kind == MutationKind.CREATE && record != null
                    || mutation.kind != MutationKind.CREATE
                            && (record == null || record.recordRevision != mutation.expectedRevision)) {
                MetadataCommitResult conflict = new MetadataCommitResult(
                        transaction.id,
                        MetadataCommitResult.Outcome.NOT_COMMITTED,
                        OptionalLong.empty(),
                        Optional.of(MetadataCommitResult.FailureCategory.CONFLICT));
                outcomes.put(transaction.id, conflict);
                transaction.retireStagedValues();
                return conflict;
            }
        }
        storeRevision = Math.addExact(storeRevision, 1L);
        for (StagedMutation mutation : transaction.mutations.values()) {
            StoredRecord previous = current.get(mutation.key);
            if (mutation.kind == MutationKind.DELETE) {
                current.remove(mutation.key);
            } else {
                long recordRevision = previous == null
                        ? 0L
                        : Math.addExact(previous.recordRevision, 1L);
                current.put(
                        mutation.key,
                        new StoredRecord(
                                mutation.key,
                                recordRevision,
                                storeRevision,
                                mutation.value.orElseThrow()));
            }
        }
        MetadataCommitResult committed = new MetadataCommitResult(
                transaction.id,
                MetadataCommitResult.Outcome.COMMITTED,
                OptionalLong.of(storeRevision),
                Optional.empty());
        outcomes.put(transaction.id, committed);
        transaction.releaseTransferredValues();
        if (hideNextCommittedOutcome) {
            hideNextCommittedOutcome = false;
            return new MetadataCommitResult(
                    transaction.id,
                    MetadataCommitResult.Outcome.UNKNOWN,
                    OptionalLong.empty(),
                    Optional.empty());
        }
        return committed;
    }

    private void validateTransactionIdentity(MetadataTransactionId transactionId)
            throws MetadataStoreException {
        Objects.requireNonNull(transactionId, "transactionId");
        if (!storeId.equals(transactionId.storeId())) {
            throw failure(
                    MetadataCommitResult.FailureCategory.FOREIGN_TRANSACTION,
                    "Transaction belongs to another store");
        }
        if (!issued.containsKey(transactionId)) {
            throw failure(
                    MetadataCommitResult.FailureCategory.TRANSACTION_NOT_ISSUED,
                    "Transaction was not issued by this store instance");
        }
    }

    private void requireOpen() {
        if (closed || closing) {
            throw new IllegalStateException("Metadata store is closed");
        }
    }

    private synchronized void releaseAdmission() {
        if (activeAdmissions <= 0) {
            throw new IllegalStateException("Metadata admission reservation underflow");
        }
        activeAdmissions--;
        notifyAll();
    }

    private static MetadataStoreException failure(
            MetadataCommitResult.FailureCategory category,
            String message) {
        return new MetadataStoreException(category, message);
    }

    private enum MutationKind {
        CREATE,
        REPLACE,
        DELETE
    }

    private record StagedValue(Path path, long length) {
    }

    private record StoredRecord(
            MetadataKey key,
            long recordRevision,
            long commitRevision,
            StagedValue value) {
    }

    private record StagedMutation(
            MutationKind kind,
            MetadataKey key,
            long expectedRevision,
            Optional<StagedValue> value) {
    }

    private final class Transaction implements MetadataTransaction {
        private final MetadataTransactionId id;
        private final Thread owner = Thread.currentThread();
        private final Map<MetadataKey, StagedMutation> mutations = new LinkedHashMap<>();
        private boolean terminal;

        private Transaction(MetadataTransactionId id) {
            this.id = id;
        }

        @Override
        public MetadataTransactionId id() {
            return id;
        }

        @Override
        public void create(
                MetadataKey key,
                RepeatableContent content,
                CancellationSignal cancellation) throws IOException {
            admit(MutationKind.CREATE, key, 0L, content, cancellation);
        }

        @Override
        public void replace(
                MetadataKey key,
                long expectedRevision,
                RepeatableContent content,
                CancellationSignal cancellation) throws IOException {
            validateRevision(expectedRevision);
            admit(MutationKind.REPLACE, key, expectedRevision, content, cancellation);
        }

        @Override
        public void delete(MetadataKey key, long expectedRevision) {
            checkMutable();
            validateRevision(expectedRevision);
            addMutation(new StagedMutation(
                    MutationKind.DELETE,
                    Objects.requireNonNull(key, "key"),
                    expectedRevision,
                    Optional.empty()));
        }

        @Override
        public MetadataCommitResult commit() {
            checkMutable();
            terminal = true;
            return InMemoryTransactionalMetadataStore.this.commit(this);
        }

        @Override
        public void abort() throws IOException {
            checkThread();
            if (!terminal) {
                terminal = true;
                retireStagedValues();
            }
        }

        @Override
        public void close() throws IOException {
            if (!terminal) {
                abort();
            }
        }

        private void admit(
                MutationKind kind,
                MetadataKey key,
                long expectedRevision,
                RepeatableContent content,
                CancellationSignal cancellation) throws IOException {
            MetadataKey checkedKey = Objects.requireNonNull(key, "key");
            synchronized (InMemoryTransactionalMetadataStore.this) {
                checkMutable();
                rejectDuplicateKey(checkedKey);
                activeAdmissions = Math.addExact(activeAdmissions, 1);
            }
            StagedValue stagedValue = null;
            boolean installed = false;
            try {
                stagedValue = InMemoryTransactionalMetadataStore.this.stageDetached(
                        content, cancellation);
                synchronized (InMemoryTransactionalMetadataStore.this) {
                    checkMutable();
                    rejectDuplicateKey(checkedKey);
                    addMutation(new StagedMutation(
                            kind,
                            checkedKey,
                            expectedRevision,
                            Optional.of(stagedValue)));
                    ownedFiles.add(stagedValue.path);
                    installed = true;
                }
            } finally {
                try {
                    if (!installed && stagedValue != null) {
                        Files.deleteIfExists(stagedValue.path);
                    }
                } finally {
                    releaseAdmission();
                }
            }
        }

        private void rejectDuplicateKey(MetadataKey checkedKey) {
            if (mutations.containsKey(checkedKey)) {
                throw new IllegalArgumentException("A transaction may mutate a key only once");
            }
        }

        private void addMutation(StagedMutation mutation) {
            if (mutations.putIfAbsent(mutation.key, mutation) != null) {
                throw new IllegalArgumentException("A transaction may mutate a key only once");
            }
        }

        private void checkMutable() {
            checkThread();
            if (terminal) {
                throw new IllegalStateException("Metadata transaction is terminal");
            }
            requireOpen();
        }

        private void checkThread() {
            if (owner != Thread.currentThread()) {
                throw new IllegalStateException("Metadata transaction is thread-confined");
            }
        }

        private void retireStagedValues() {
            for (StagedMutation mutation : mutations.values()) {
                mutation.value.ifPresent(value -> {
                    try {
                        Files.deleteIfExists(value.path);
                        ownedFiles.remove(value.path);
                    } catch (IOException exception) {
                        throw new IllegalStateException("Test spool retirement failed", exception);
                    }
                });
            }
            mutations.clear();
        }

        private void releaseTransferredValues() {
            mutations.clear();
        }
    }

    private static void validateRevision(long revision) {
        if (revision < 0L) {
            throw new IllegalArgumentException("Expected revision must be non-negative");
        }
    }

    private final class Snapshot implements MetadataSnapshot {
        private final Object issuingAuthority;
        private final long revision;
        private final NavigableMap<MetadataKey, StoredRecord> view;
        private final List<Cursor> cursors = new ArrayList<>();
        private boolean snapshotClosed;

        private Snapshot(
                Object issuingAuthority,
                long revision,
                NavigableMap<MetadataKey, StoredRecord> view) {
            this.issuingAuthority = issuingAuthority;
            this.revision = revision;
            this.view = view;
        }

        @Override
        public MetadataStoreId storeId() {
            checkOpen();
            return storeId;
        }

        @Override
        public long revision() {
            checkOpen();
            return revision;
        }

        @Override
        public Optional<Record> get(MetadataKey key) {
            checkOpen();
            return Optional.ofNullable(view.get(Objects.requireNonNull(key, "key")))
                    .map(SnapshotRecord::new);
        }

        @Override
        public MetadataCursor scan(KeyRange range, CancellationSignal cancellation)
                throws IOException {
            checkOpen();
            Objects.requireNonNull(range, "range");
            Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
            Iterator<Map.Entry<MetadataKey, StoredRecord>> iterator =
                    view.entrySet().iterator();
            Cursor cursor = new Cursor(this, range, iterator);
            cursors.add(cursor);
            return cursor;
        }

        @Override
        public void close() {
            if (snapshotClosed) {
                return;
            }
            snapshotClosed = true;
            for (Cursor cursor : List.copyOf(cursors)) {
                cursor.close();
            }
            cursors.clear();
        }

        private void checkOpen() {
            if (snapshotClosed || issuingAuthority != authority) {
                throw new IllegalStateException("Metadata snapshot is closed or foreign");
            }
        }
    }

    private final class SnapshotRecord implements MetadataSnapshot.Record {
        private final StoredRecord record;
        private boolean recordClosed;

        private SnapshotRecord(StoredRecord record) {
            this.record = record;
        }

        @Override
        public MetadataKey key() {
            checkOpen();
            return record.key;
        }

        @Override
        public long recordRevision() {
            checkOpen();
            return record.recordRevision;
        }

        @Override
        public long commitRevision() {
            checkOpen();
            return record.commitRevision;
        }

        @Override
        public Optional<MetadataSnapshot.Integrity> integrity() {
            checkOpen();
            return Optional.empty();
        }

        @Override
        public InputStream openStream() throws IOException {
            checkOpen();
            InputStream delegate = Files.newInputStream(record.value.path);
            return new FilterInputStream(delegate) {
                private long remaining = record.value.length;

                @Override
                public int read() throws IOException {
                    if (remaining == 0L) {
                        return -1;
                    }
                    int value = super.read();
                    if (value >= 0) {
                        remaining--;
                    }
                    return value;
                }

                @Override
                public int read(byte[] data, int offset, int length) throws IOException {
                    if (remaining == 0L) {
                        return -1;
                    }
                    int boundedLength = (int) Math.min(length, remaining);
                    int count = super.read(data, offset, boundedLength);
                    if (count > 0) {
                        remaining -= count;
                    }
                    return count;
                }
            };
        }

        @Override
        public OptionalLong length() {
            checkOpen();
            return OptionalLong.of(record.value.length);
        }

        @Override
        public String contentId() {
            checkOpen();
            return "test-metadata:" + record.key.namespace() + ':' + record.key.key();
        }

        @Override
        public void close() {
            recordClosed = true;
        }

        private void checkOpen() {
            if (recordClosed) {
                throw new IllegalStateException("Metadata record is closed");
            }
        }
    }

    private final class Cursor implements MetadataCursor {
        private final Snapshot snapshot;
        private final MetadataSnapshot.KeyRange range;
        private Iterator<Map.Entry<MetadataKey, StoredRecord>> iterator;
        private boolean cursorClosed;

        private Cursor(
                Snapshot snapshot,
                MetadataSnapshot.KeyRange range,
                Iterator<Map.Entry<MetadataKey, StoredRecord>> iterator) {
            this.snapshot = snapshot;
            this.range = range;
            this.iterator = iterator;
        }

        @Override
        public Optional<MetadataSnapshot.Record> next(CancellationSignal cancellation)
                throws IOException {
            checkOpen();
            CancellationSignal checkedCancellation =
                    Objects.requireNonNull(cancellation, "cancellation");
            while (iterator.hasNext()) {
                checkedCancellation.throwIfCancelled();
                Map.Entry<MetadataKey, StoredRecord> entry = iterator.next();
                if (range.contains(entry.getKey())) {
                    return Optional.of(new SnapshotRecord(entry.getValue()));
                }
            }
            return Optional.empty();
        }

        @Override
        public void close() {
            if (cursorClosed) {
                return;
            }
            cursorClosed = true;
            iterator = Collections.emptyIterator();
            snapshot.cursors.remove(this);
        }

        private void checkOpen() {
            snapshot.checkOpen();
            if (cursorClosed) {
                throw new IllegalStateException("Metadata cursor is closed");
            }
        }
    }
}
