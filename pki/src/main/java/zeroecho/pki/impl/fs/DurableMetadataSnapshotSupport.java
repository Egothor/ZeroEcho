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
import java.io.InputStream;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.spi.store.MetadataCursor;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataStoreId;

/** Stable snapshot, lazy cursor, and bounded log-slice content lifecycles. */
@SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
final class DurableMetadataSnapshotSupport {
    private static final String MAXIMUM_KEY = "~".repeat(MetadataKey.MAXIMUM_KEY_UTF8_BYTES);
    private static final Logger LOGGER = Logger.getLogger(DurableMetadataSnapshotSupport.class.getName());
    private static final String CLEANUP_WARNING =
            "Durable metadata snapshot resources could not be fully retired";

    private final DurableMetadataStoreEngine engine;
    private final DurableMetadataAdapterLifecycle lifecycle;
    private final MetadataStoreId storeId;
    private final SliceOpener sliceOpener;

    /* default */ DurableMetadataSnapshotSupport(
            DurableMetadataStoreEngine engine,
            DurableMetadataAdapterLifecycle lifecycle,
            MetadataStoreId storeId) {
        this(engine, lifecycle, storeId, engine::openValueSlice);
    }

    /* default */ DurableMetadataSnapshotSupport(
            DurableMetadataStoreEngine engine,
            DurableMetadataAdapterLifecycle lifecycle,
            MetadataStoreId storeId,
            SliceOpener sliceOpener) {
        this.engine = Objects.requireNonNull(engine, "engine");
        this.lifecycle = Objects.requireNonNull(lifecycle, "lifecycle");
        this.storeId = Objects.requireNonNull(storeId, "storeId");
        this.sliceOpener = Objects.requireNonNull(sliceOpener, "sliceOpener");
    }

    /* default */ MetadataSnapshot open() throws IOException {
        return lifecycle.openManaged(() -> new SnapshotImpl(engine.snapshotState()));
    }

    /** Finite immutable snapshot metadata; no payload byte is copied. */
    private final class SnapshotImpl
            implements MetadataSnapshot, DurableMetadataAdapterLifecycle.ManagedResource {
        private final long revision;
        private final NavigableMap<MetadataKey, MetadataStateIndex.CurrentRecord> records;
        private final Runnable release;
        private final ReentrantLock lock = new ReentrantLock();
        private final Set<RecordImpl> recordChildren =
                Collections.newSetFromMap(new IdentityHashMap<>());
        private final Set<CursorImpl> cursorChildren =
                Collections.newSetFromMap(new IdentityHashMap<>());
        private boolean closed;

        private SnapshotImpl(DurableMetadataStoreEngine.SnapshotState captured) {
            super();
            revision = captured.revision();
            records = captured.records();
            release = captured.release();
        }

        @Override
        public MetadataStoreId storeId() {
            requireOpen();
            return storeId;
        }

        @Override
        public long revision() {
            requireOpen();
            return revision;
        }

        @Override
        public Optional<MetadataSnapshot.Record> get(MetadataKey key) {
            Objects.requireNonNull(key, "key");
            lock.lock();
            try {
                requireOpenLocked();
                MetadataStateIndex.CurrentRecord metadata = records.get(key);
                return metadata == null
                        ? Optional.empty()
                        : Optional.of(createRecordLocked(new RecordMetadata(metadata)));
            } finally {
                lock.unlock();
            }
        }

        @Override
        public Optional<MetadataKey> greatestKey(String namespace) {
            MetadataKey upper = new MetadataKey(namespace, MAXIMUM_KEY);
            lock.lock();
            try {
                requireOpenLocked();
                Map.Entry<MetadataKey, MetadataStateIndex.CurrentRecord> greatest = records.floorEntry(upper);
                if (greatest == null || !namespace.equals(greatest.getKey().namespace())) {
                    return Optional.empty();
                }
                return Optional.of(greatest.getKey());
            } finally {
                lock.unlock();
            }
        }

        @Override
        public MetadataCursor scan(KeyRange range, CancellationSignal cancellation)
                throws IOException {
            Objects.requireNonNull(range, "range");
            Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
            lock.lock();
            try {
                requireOpenLocked();
                String lower = range.lowerInclusive().orElse("!");
                MetadataKey first = new MetadataKey(range.namespace(), lower);
                CursorImpl cursor = new CursorImpl(range, records.tailMap(first, true).entrySet().iterator());
                cursorChildren.add(cursor);
                return cursor;
            } finally {
                lock.unlock();
            }
        }

        @Override
        public void close() {
            IOException failure = forceClose();
            lifecycle.unregister(this);
            if (failure != null) {
                warnCleanupFailure();
            }
        }

        @Override
        public IOException forceClose() {
            List<CursorImpl> cursors;
            List<RecordImpl> children;
            lock.lock();
            try {
                if (closed) {
                    return null;
                }
                closed = true;
                release.run();
                cursors = List.copyOf(cursorChildren);
                children = List.copyOf(recordChildren);
                cursorChildren.clear();
                recordChildren.clear();
            } finally {
                lock.unlock();
            }
            IOException failure = closeOwnedCursors(cursors);
            return DurableMetadataAdapterLifecycle.append(failure, closeOwnedRecords(children));
        }

        private IOException closeOwnedCursors(List<CursorImpl> owned) {
            IOException failure = null;
            Iterator<CursorImpl> iterator = owned.iterator();
            while (iterator.hasNext()) {
                failure = DurableMetadataAdapterLifecycle.append(
                        failure, iterator.next().forceClose());
            }
            return failure;
        }

        private IOException closeOwnedRecords(List<RecordImpl> owned) {
            IOException failure = null;
            Iterator<RecordImpl> iterator = owned.iterator();
            while (iterator.hasNext()) {
                failure = DurableMetadataAdapterLifecycle.append(
                        failure, iterator.next().forceClose());
            }
            return failure;
        }

        private RecordImpl createRecordLocked(RecordMetadata metadata) {
            RecordImpl record = new RecordImpl(metadata);
            recordChildren.add(record);
            return record;
        }

        private InputStream openStream(RecordImpl record) throws IOException {
            InputStream slice = lifecycle.read(() -> sliceOpener.open(
                    record.metadata.valueOffset(), record.metadata.valueLength()));
            lock.lock();
            try {
                requireOpenLocked();
                return record.register(slice);
            } catch (IllegalStateException failure) {
                try {
                    slice.close();
                } catch (IOException cleanup) {
                    failure.addSuppressed(cleanup);
                }
                throw failure;
            } finally {
                lock.unlock();
            }
        }

        private void requireOpen() {
            lock.lock();
            try {
                requireOpenLocked();
            } finally {
                lock.unlock();
            }
        }

        private void requireOpenLocked() {
            if (closed) {
                throw new IllegalStateException("Metadata snapshot is closed");
            }
        }

        /** Cursor retains only one map iterator and one current record. */
        private final class CursorImpl implements MetadataCursor {
            private final KeyRange range;
            private final Iterator<Map.Entry<MetadataKey, MetadataStateIndex.CurrentRecord>> iterator;
            private RecordImpl current;
            private boolean cursorClosed;

            private CursorImpl(
                    KeyRange range,
                    Iterator<Map.Entry<MetadataKey, MetadataStateIndex.CurrentRecord>> iterator) {
                super();
                this.range = range;
                this.iterator = iterator;
            }

            @Override
            public Optional<MetadataSnapshot.Record> next(CancellationSignal cancellation)
                    throws IOException {
                CancellationSignal checked = Objects.requireNonNull(cancellation, "cancellation");
                checked.throwIfCancelled();
                lock.lock();
                try {
                    requireOpenLocked();
                    requireCursorOpen();
                    closeCurrent();
                } finally {
                    lock.unlock();
                }
                while (true) {
                    checked.throwIfCancelled();
                    lock.lock();
                    try {
                        requireOpenLocked();
                        requireCursorOpen();
                        if (!iterator.hasNext()) {
                            return Optional.empty();
                        }
                        Map.Entry<MetadataKey, MetadataStateIndex.CurrentRecord> candidate = iterator.next();
                        if (range.contains(candidate.getKey())) {
                            current = createRecordLocked(new RecordMetadata(candidate.getValue()));
                            return Optional.of(current);
                        }
                        if (candidate.getKey().namespace().compareTo(range.namespace()) > 0
                                || candidate.getKey().namespace().equals(range.namespace())
                                && range.upperExclusive().isPresent()) {
                            return Optional.empty();
                        }
                    } finally {
                        lock.unlock();
                    }
                }
            }

            @Override
            public void close() {
                IOException failure = forceClose();
                lock.lock();
                try {
                    cursorChildren.remove(this);
                } finally {
                    lock.unlock();
                }
                if (failure != null) {
                    warnCleanupFailure();
                }
            }

            private IOException forceClose() {
                IOException failure = null;
                lock.lock();
                try {
                    if (!cursorClosed) {
                        cursorClosed = true;
                        failure = closeCurrentFailure();
                    }
                } finally {
                    lock.unlock();
                }
                return failure;
            }

            private void closeCurrent() throws IOException {
                if (current != null) {
                    current.close();
                    current = null;
                }
            }

            private IOException closeCurrentFailure() {
                try {
                    closeCurrent();
                    return null;
                } catch (IOException failure) {
                    return failure;
                }
            }

            private void requireCursorOpen() {
                if (cursorClosed) {
                    throw new IllegalStateException("Metadata cursor is closed");
                }
            }
        }

        /** Snapshot record whose streams are closed at the snapshot boundary. */
        private final class RecordImpl implements MetadataSnapshot.Record {
            private final RecordMetadata metadata;
            private final Set<OwnedInputStream> streams =
                    Collections.newSetFromMap(new IdentityHashMap<>());
            private boolean recordClosed;

            private RecordImpl(RecordMetadata metadata) {
                super();
                this.metadata = metadata;
            }

            @Override
            public MetadataKey key() {
                requireRecordOpen();
                return metadata.key();
            }

            @Override
            public long recordRevision() {
                requireRecordOpen();
                return metadata.revision();
            }

            @Override
            public long commitRevision() {
                requireRecordOpen();
                return metadata.revision();
            }

            @Override
            public Optional<Integrity> integrity() {
                requireRecordOpen();
                return Optional.empty();
            }

            @Override
            public InputStream openStream() throws IOException {
                requireRecordOpen();
                return SnapshotImpl.this.openStream(this);
            }

            @Override
            public OptionalLong length() {
                requireRecordOpen();
                return OptionalLong.of(metadata.valueLength());
            }

            @Override
            public String contentId() {
                requireRecordOpen();
                return "zeroecho-posix-metadata-record-v1:" + storeId.value()
                        + ':' + metadata.key().canonical() + ':' + metadata.revision();
            }

            @Override
            public void close() throws IOException {
                List<OwnedInputStream> detached;
                lock.lock();
                try {
                    if (recordClosed) {
                        return;
                    }
                    recordClosed = true;
                    detached = List.copyOf(streams);
                    streams.clear();
                    recordChildren.remove(this);
                } finally {
                    lock.unlock();
                }
                IOException failure = closeStreams(detached);
                if (failure != null) {
                    throw failure;
                }
            }

            private OwnedInputStream register(InputStream slice) {
                requireRecordOpen();
                OwnedInputStream result = new OwnedInputStream(this, slice);
                streams.add(result);
                return result;
            }

            private void unregister(OwnedInputStream stream) {
                lock.lock();
                try {
                    streams.remove(stream);
                } finally {
                    lock.unlock();
                }
            }

            private IOException forceClose() {
                try {
                    close();
                    return null;
                } catch (IOException failure) {
                    return failure;
                }
            }

            private void requireRecordOpen() {
                lock.lock();
                try {
                    requireOpenLocked();
                    if (recordClosed) {
                        throw new IllegalStateException("Metadata snapshot record is closed");
                    }
                } finally {
                    lock.unlock();
                }
            }
        }

        private static IOException closeStreams(List<OwnedInputStream> streams) {
            IOException failure = null;
            Iterator<OwnedInputStream> iterator = streams.iterator();
            while (iterator.hasNext()) {
                failure = DurableMetadataAdapterLifecycle.append(
                        failure, iterator.next().closeFailure());
            }
            return failure;
        }

        /** Bounded reader invalidated with its owning record. */
        private final class OwnedInputStream extends InputStream {
            private final RecordImpl owner;
            private final InputStream delegate;
            private boolean streamClosed;

            private OwnedInputStream(RecordImpl owner, InputStream delegate) {
                super();
                this.owner = owner;
                this.delegate = delegate;
            }

            @Override
            public int read() throws IOException {
                requireStreamOpen();
                return delegate.read();
            }

            @Override
            public int read(byte[] target, int offset, int length) throws IOException {
                requireStreamOpen();
                return delegate.read(target, offset, length);
            }

            @Override
            public void close() throws IOException {
                if (streamClosed) {
                    return;
                }
                streamClosed = true;
                try {
                    delegate.close();
                } finally {
                    owner.unregister(this);
                }
            }

            private void closeDelegate() throws IOException {
                if (!streamClosed) {
                    streamClosed = true;
                    delegate.close();
                }
            }

            private IOException closeFailure() {
                try {
                    closeDelegate();
                    return null;
                } catch (IOException failure) {
                    return failure;
                }
            }

            private void requireStreamOpen() {
                if (streamClosed) {
                    throw new IllegalStateException("Metadata record stream is closed");
                }
                owner.requireRecordOpen();
            }
        }
    }

    private static void warnCleanupFailure() {
        try {
            LOGGER.warning(CLEANUP_WARNING);
        } catch (IllegalStateException ignored) {
            // A non-fatal logging-handler failure cannot break logical close.
        }
    }

    /** Narrow record-slice seam used to verify child-resource cleanup. */
    /* default */
    @FunctionalInterface
    interface SliceOpener {
        /**
         * Opens one bounded durable-value region.
         *
         * @param offset absolute value offset
         * @param length exact value length
         * @return bounded stream
         * @throws IOException when the value region cannot be opened
         */
        InputStream open(long offset, long length) throws IOException;
    }

    /** Finite immutable durable value location. */
    private record RecordMetadata(
            MetadataKey key, long revision, long valueOffset, long valueLength) {
        private RecordMetadata(MetadataStateIndex.CurrentRecord record) {
            this(record.key(), record.revision(), record.valueOffset(), record.valueLength());
        }
    }
}
