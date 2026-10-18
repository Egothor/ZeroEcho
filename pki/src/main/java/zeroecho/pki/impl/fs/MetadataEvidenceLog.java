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
package zeroecho.pki.impl.fs;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataCursor;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.TransactionalMetadataStore;

/**
 * Reusable append-only, monotonically-sequenced evidence log backed by the transactional metadata store.
 *
 * <p>Each family (issuance, status, publication, signing) owns one instance under a distinct namespace.
 * An entry co-commits the operation's server-derived success evidence in append order so a bounded,
 * crash-consistent audit projector can advance a durable cursor exactly as the revocation slice does.
 * Appends are idempotent per {@code objectId} (a create-if-absent marker), so a producer that appends at
 * commit time and a startup reconciliation pass that appends for any committed record missing a marker
 * never double-record the same object. The sole {@code head} record holds the next sequence and is the
 * compare-and-replace concurrency point.</p>
 */
final class MetadataEvidenceLog {
    /** Bounded append retries under concurrent head advancement. */
    private static final int MAXIMUM_APPEND_ATTEMPTS = 64;
    private static final long MAXIMUM_VALUE_BYTES = 1L << 20;
    private static final String HEAD_KEY = "head";
    private static final String ENTRY_PREFIX = "e:";
    private static final String MARKER_PREFIX = "m:";

    private final TransactionalMetadataStore metadata;
    private final String namespace;

    /* default */ MetadataEvidenceLog(TransactionalMetadataStore metadata, String namespace) {
        this.metadata = Objects.requireNonNull(metadata, "metadata");
        this.namespace = Objects.requireNonNull(namespace, "namespace");
    }

    /**
     * Appends one evidence entry for {@code objectId} unless already recorded.
     *
     * @param objectId immutable produced-object identity (idempotency key)
     * @param payload opaque family-serialized evidence bytes
     * @return {@code true} when a new entry was committed, {@code false} when already present
     * @throws IOException on a durable read/write failure
     */
    // Every optimistic retry needs fresh keys, content wrappers, and transaction-owned immutable values.
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    /* default */ boolean append(PkiId objectId, java.time.Instant recordedAt, byte[] payload) throws IOException {
        Objects.requireNonNull(objectId, "objectId");
        Objects.requireNonNull(recordedAt, "recordedAt");
        byte[] exactPayload = Objects.requireNonNull(payload, "payload").clone();
        MetadataKey markerKey = new MetadataKey(namespace, MARKER_PREFIX + objectId.value());
        for (int attempt = 0; attempt < MAXIMUM_APPEND_ATTEMPTS; attempt++) {
            long sequence;
            Optional<Long> headRevision;
            try (MetadataSnapshot snapshot = metadata.snapshot()) {
                if (snapshot.get(markerKey).isPresent()) {
                    return false;
                }
                Optional<MetadataSnapshot.Record> head = snapshot.get(new MetadataKey(namespace, HEAD_KEY));
                if (head.isPresent()) {
                    try (MetadataSnapshot.Record record = head.orElseThrow()) {
                        sequence = decodeLong(readValue(record));
                        headRevision = Optional.of(record.recordRevision());
                    }
                } else {
                    sequence = 0L;
                    headRevision = Optional.empty();
                }
            }
            MetadataKey headKey = new MetadataKey(namespace, HEAD_KEY);
            MetadataKey entryKey = new MetadataKey(namespace, ENTRY_PREFIX + formatSequence(sequence));
            try (MetadataTransaction transaction = metadata.beginTransaction()) {
                if (headRevision.isPresent()) {
                    transaction.replace(headKey, headRevision.orElseThrow(),
                            new ImmutableByteContent(encodeLong(sequence + 1L)), CancellationSignal.NONE);
                } else {
                    transaction.create(headKey, new ImmutableByteContent(encodeLong(sequence + 1L)),
                            CancellationSignal.NONE);
                }
                transaction.create(entryKey,
                        new ImmutableByteContent(encodeEntry(objectId, recordedAt, exactPayload)),
                        CancellationSignal.NONE);
                transaction.create(markerKey, new ImmutableByteContent(new byte[0]), CancellationSignal.NONE);
                MetadataCommitResult result = transaction.commit();
                if (result.outcome() == MetadataCommitResult.Outcome.COMMITTED) {
                    return true;
                }
                if (result.outcome() == MetadataCommitResult.Outcome.UNKNOWN) {
                    throw new IOException("Evidence-log durability is unconfirmed");
                }
                // NOT_COMMITTED: a concurrent append advanced the head or already inserted the marker; retry.
            }
        }
        throw new IOException("Evidence-log append exceeded the concurrency retry bound");
    }

    /**
     * Opens an ordered reader over entries strictly after {@code afterSequenceExclusive}.
     *
     * @param afterSequenceExclusive last projected sequence, or {@code -1} to read from the start
     * @return closeable ordered reader whose high watermark is captured at open
     * @throws IOException on a durable read failure
     */
    // Any snapshot/scan runtime failure must close the snapshot before propagating the original failure.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    /* default */ Reader openReader(long afterSequenceExclusive) throws IOException {
        MetadataSnapshot snapshot = metadata.snapshot();
        try {
            long highWatermark;
            Optional<MetadataSnapshot.Record> head = snapshot.get(new MetadataKey(namespace, HEAD_KEY));
            if (head.isPresent()) {
                try (MetadataSnapshot.Record record = head.orElseThrow()) {
                    highWatermark = decodeLong(readValue(record));
                }
            } else {
                highWatermark = 0L;
            }
            // Resume the scan AT the first unprojected entry rather than at the namespace prefix start, so a
            // bounded pass over a large, ever-growing evidence log does not re-read (and discard) every
            // already-projected entry on each pass. The fixed-width zero-padded sequence key makes the
            // lower bound lexicographically exact; the Reader still skips defensively.
            MetadataSnapshot.KeyRange entries = MetadataSnapshot.KeyRange.prefix(namespace, ENTRY_PREFIX);
            long firstUnprojected = afterSequenceExclusive < 0L ? 0L : afterSequenceExclusive + 1L;
            MetadataSnapshot.KeyRange resumed = new MetadataSnapshot.KeyRange(namespace,
                    Optional.of(ENTRY_PREFIX + formatSequence(firstUnprojected)), entries.upperExclusive());
            MetadataCursor cursor = snapshot.scan(resumed, CancellationSignal.NONE);
            return new Reader(snapshot, cursor, afterSequenceExclusive, highWatermark);
        } catch (IOException | RuntimeException failure) {
            snapshot.close();
            throw failure;
        }
    }

    /** One decoded append entry. */
    /* default */ record Entry(long sequence, PkiId objectId, java.time.Instant recordedAt, byte[] payload) {
        Entry {
            Objects.requireNonNull(objectId, "objectId");
            Objects.requireNonNull(recordedAt, "recordedAt");
            payload = Objects.requireNonNull(payload, "payload").clone();
        }
        @Override public byte[] payload() { return payload.clone(); }
    }

    /** Closeable ordered reader over evidence entries after an exclusive sequence. */
    /* default */ static final class Reader implements AutoCloseable {
        private final MetadataSnapshot snapshot;
        private final MetadataCursor cursor;
        private final long afterSequenceExclusive;
        private final long highWatermark;
        private Entry current;

        private Reader(MetadataSnapshot snapshot, MetadataCursor cursor, long afterSequenceExclusive,
                long highWatermark) {
            this.snapshot = snapshot;
            this.cursor = cursor;
            this.afterSequenceExclusive = afterSequenceExclusive;
            this.highWatermark = highWatermark;
        }

        /** @return the captured entry count (next sequence) at open time */
        /* default */ long highWatermark() {
            return highWatermark;
        }

        /** Advances to the next entry strictly after the exclusive sequence. */
        /* default */ boolean next(CancellationSignal cancellation) throws IOException {
            Objects.requireNonNull(cancellation, "cancellation");
            Optional<MetadataSnapshot.Record> record;
            while ((record = cursor.next(cancellation)).isPresent()) {
                try (MetadataSnapshot.Record entry = record.orElseThrow()) {
                    long sequence = parseSequence(entry.key().key());
                    if (sequence <= afterSequenceExclusive) {
                        continue;
                    }
                    current = decodeEntry(sequence, readValue(entry));
                    return true;
                }
            }
            current = null;
            return false;
        }

        /** @return the entry positioned by the most recent {@link #next(CancellationSignal)} */
        /* default */ Entry current() {
            if (current == null) {
                throw new IllegalStateException("Evidence-log reader is not positioned on an entry");
            }
            return current;
        }

        // Explicit nesting guarantees cursor-before-snapshot closure without changing legacy exception precedence.
        @SuppressWarnings("PMD.UseTryWithResources")
        @Override public void close() {
            try {
                cursor.close();
            } finally {
                snapshot.close();
            }
        }
    }

    private static long parseSequence(String key) {
        if (!key.startsWith(ENTRY_PREFIX)) {
            throw new IllegalStateException("Evidence-log entry key is malformed");
        }
        return Long.parseLong(key.substring(ENTRY_PREFIX.length()));
    }

    private static String formatSequence(long sequence) {
        return String.format("%019d", sequence);
    }

    private static byte[] encodeEntry(PkiId objectId, java.time.Instant recordedAt, byte[] payload) {
        byte[] id = objectId.value().getBytes(StandardCharsets.UTF_8);
        return ByteBuffer.allocate(Long.BYTES + Integer.BYTES + id.length + payload.length)
                .putLong(recordedAt.toEpochMilli()).putInt(id.length).put(id).put(payload).array();
    }

    private static Entry decodeEntry(long sequence, byte[] value) {
        ByteBuffer buffer = ByteBuffer.wrap(value);
        java.time.Instant recordedAt = java.time.Instant.ofEpochMilli(buffer.getLong());
        int idLength = buffer.getInt();
        if (idLength < 0 || idLength > buffer.remaining()) {
            throw new IllegalStateException("Evidence-log entry payload is malformed");
        }
        byte[] id = new byte[idLength];
        buffer.get(id);
        byte[] payload = new byte[buffer.remaining()];
        buffer.get(payload);
        return new Entry(sequence, new PkiId(new String(id, StandardCharsets.UTF_8)), recordedAt, payload);
    }

    private static byte[] encodeLong(long value) {
        return ByteBuffer.allocate(Long.BYTES).putLong(value).array();
    }

    private static long decodeLong(byte[] value) {
        if (value.length != Long.BYTES) {
            throw new IllegalStateException("Evidence-log head value is malformed");
        }
        return ByteBuffer.wrap(value).getLong();
    }

    private static byte[] readValue(MetadataSnapshot.Record record) throws IOException {
        long length = record.length().orElseThrow();
        if (length < 0L || length > MAXIMUM_VALUE_BYTES) {
            throw new IOException("Evidence-log value length is invalid");
        }
        byte[] result = new byte[Math.toIntExact(length)];
        try (InputStream input = record.openStream()) {
            int offset = 0;
            while (offset < result.length) {
                int count = input.read(result, offset, result.length - offset);
                if (count <= 0) {
                    throw new IOException("Evidence-log value is truncated");
                }
                offset += count;
            }
            if (input.read() >= 0) {
                throw new IOException("Evidence-log value has trailing data");
            }
        }
        return result;
    }
}
