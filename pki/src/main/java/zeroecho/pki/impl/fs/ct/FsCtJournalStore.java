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
package zeroecho.pki.impl.fs.ct;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.pki.spi.ct.CtJournalEntry;
import zeroecho.pki.spi.ct.CtJournalException;
import zeroecho.pki.spi.ct.CtJournalStore;
import zeroecho.pki.spi.ct.CtJournalVerificationResult;

/**
 * Filesystem-backed implementation of {@link CtJournalStore}.
 *
 * <h2>Storage format</h2>
 * <p>Entries are stored as fixed-size 512-byte binary records in a flat sequential
 * file {@code entries.bin} inside the configured directory. Entry #N (1-based) is
 * located at file offset {@code (N - 1) * 512}. This layout allows O(1) random
 * access by sequence number.</p>
 *
 * <p>Each 512-byte record encodes:</p>
 * <pre>
 *   Offset  Size  Field
 *    0       8    sequenceNumber (big-endian long)
 *    8       8    timestamp epochSeconds (big-endian long)
 *   16       4    timestamp nanos (big-endian int)
 *   20      32    certFingerprint (SHA-256, 32 bytes)
 *   52      20    serialNumber (big-endian, zero-padded to 20 bytes)
 *   72       2    authorityId UTF-8 byte length (big-endian unsigned short)
 *   74     128    authorityId UTF-8 bytes (zero-padded)
 *  202      32    previousHash (32 bytes)
 *  234      32    leafHash (32 bytes)
 *  266      32    entryHash (32 bytes)
 *  298     214    reserved (zero)
 * Total     512
 * </pre>
 *
 * <h2>Thread safety</h2>
 * <p>Read operations acquire the shared read lock; {@link #append} acquires the
 * exclusive write lock. The in-memory fingerprint index is protected by the same
 * lock.</p>
 *
 * @since 1.0
 */
public final class FsCtJournalStore implements CtJournalStore {

    private static final Logger LOG = Logger.getLogger(FsCtJournalStore.class.getName());

    /** Byte size of one serialized journal entry. */
    /* default */ static final int RECORD_BYTES = 512;

    private static final int OFFSET_SEQ = 0;
    private static final int OFFSET_EPOCH_S = 8;
    private static final int OFFSET_NANOS = 16;
    private static final int OFFSET_FINGERPRINT = 20;
    private static final int OFFSET_SERIAL = 52;
    private static final int SERIAL_BYTES = 20;
    private static final int OFFSET_AUTHORITY_LEN = 72;
    private static final int OFFSET_AUTHORITY_DATA = 74;
    private static final int AUTHORITY_DATA_BYTES = 128;
    private static final int OFFSET_PREV_HASH = 202;
    private static final int OFFSET_LEAF_HASH = 234;
    private static final int OFFSET_ENTRY_HASH = 266;

    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    /** Maps hex-encoded certificate fingerprint → sequence number. */
    private final Map<String, Long> fingerprintIndex;
    private final AtomicLong headSequence;
    private final FileChannel channel;
    private boolean closed;

    /**
     * Opens or creates the CT journal store at {@code journalDir/entries.bin}.
     * Rebuilds the in-memory fingerprint index by scanning existing records.
     *
     * @param journalDir path to the journal directory; created if absent
     * @throws CtJournalException if the directory or file cannot be opened or
     *                            if existing records are unreadable
     */
    /* default */ FsCtJournalStore(final Path journalDir) throws CtJournalException {
        Objects.requireNonNull(journalDir, "journalDir");
        try {
            java.nio.file.Files.createDirectories(journalDir);
            Path entriesFile = journalDir.resolve("entries.bin");
            this.channel = FileChannel.open(entriesFile,
                    StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
        } catch (IOException failure) {
            throw new CtJournalException("Failed to open CT journal at " + journalDir, failure);
        }

        this.fingerprintIndex = new HashMap<>();
        long count;
        try {
            count = rebuildIndex();
        } catch (Exception failure) {
            try { channel.close(); } catch (IOException ignored) { /* best-effort */ }
            throw new CtJournalException("Failed to rebuild CT journal index", failure);
        }
        this.headSequence = new AtomicLong(count);
        this.closed = false;
    }

    @Override
    public void append(final CtJournalEntry entry) throws CtJournalException {
        Objects.requireNonNull(entry, "entry");
        lock.writeLock().lock();
        try {
            requireOpen();
            long expectedSeq = headSequence.get() + 1L;
            if (entry.sequenceNumber() != expectedSeq) {
                throw new CtJournalException("Expected sequence " + expectedSeq
                        + " but entry has " + entry.sequenceNumber());
            }
            byte[] record = serialize(entry);
            long offset = (entry.sequenceNumber() - 1L) * RECORD_BYTES;
            ByteBuffer buf = ByteBuffer.wrap(record);
            while (buf.hasRemaining()) {
                try {
                    channel.write(buf, offset + RECORD_BYTES - buf.remaining());
                } catch (IOException failure) {
                    throw new CtJournalException("Failed to write CT journal entry " + entry.sequenceNumber(), failure);
                }
            }
            try {
                channel.force(false);
            } catch (IOException failure) {
                throw new CtJournalException("Failed to fsync CT journal after entry " + entry.sequenceNumber(), failure);
            }
            String fpHex = HexFormat.of().formatHex(entry.certFingerprint());
            fingerprintIndex.put(fpHex, entry.sequenceNumber());
            headSequence.set(entry.sequenceNumber());
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public CtJournalEntry lookup(final byte[] certSha256) throws CtJournalException {
        Objects.requireNonNull(certSha256, "certSha256");
        String fpHex = HexFormat.of().formatHex(certSha256);
        lock.readLock().lock();
        try {
            requireOpen();
            Long seq = fingerprintIndex.get(fpHex);
            if (seq == null) {
                throw new CtJournalException("No journal entry for fingerprint: " + fpHex);
            }
            return readEntry(seq);
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public long latestSequenceNumber() {
        lock.readLock().lock();
        try {
            requireOpen();
            return headSequence.get();
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public CtJournalVerificationResult verify(final long fromSequence, final long toSequence)
            throws CtJournalException {
        if (fromSequence <= 0) {
            throw new IllegalArgumentException("fromSequence must be positive");
        }
        if (toSequence < fromSequence) {
            throw new IllegalArgumentException("toSequence must not be less than fromSequence");
        }
        List<Long> broken = new ArrayList<>();
        lock.readLock().lock();
        try {
            requireOpen();
            byte[] expectedPreviousHash = null;
            for (long seq = fromSequence; seq <= toSequence; seq++) {
                CtJournalEntry entry = readEntry(seq);
                // Verify entryHash matches re-computed value.
                CtJournalEntry recomputed = CtJournalEntry.create(
                        entry.sequenceNumber(), entry.timestamp(), entry.certFingerprint(),
                        entry.serialNumber(), entry.authorityId(), entry.previousHash());
                if (!Arrays.equals(entry.entryHash(), recomputed.entryHash())) {
                    broken.add(seq);
                    expectedPreviousHash = null;
                    continue;
                }
                // Verify chain: previousHash must match prior entry's entryHash.
                if (expectedPreviousHash != null
                        && !Arrays.equals(entry.previousHash(), expectedPreviousHash)) {
                    broken.add(seq);
                }
                expectedPreviousHash = entry.entryHashCopy();
            }
        } finally {
            lock.readLock().unlock();
        }
        return new CtJournalVerificationResult(fromSequence, toSequence, broken.isEmpty(), broken);
    }

    /**
     * Returns the {@code entryHash} of the most-recently-appended entry, or all-zeros
     * if the journal is empty. Used by {@code FilesystemPkiStore} to chain new entries.
     *
     * @return 32-byte copy of the head entry hash; all-zeros when the journal is empty
     * @throws CtJournalException if a read failure prevents retrieval
     */
    public byte[] headEntryHash() throws CtJournalException {
        lock.readLock().lock();
        try {
            requireOpen();
            long head = headSequence.get();
            if (head == 0) {
                return new byte[CtJournalEntry.HASH_BYTES];
            }
            return readEntry(head).entryHashCopy();
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public void close() {
        lock.writeLock().lock();
        try {
            if (!closed) {
                closed = true;
                try {
                    channel.close();
                } catch (IOException failure) {
                    LOG.log(Level.WARNING, "Failed to close CT journal channel", failure);
                }
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    // Reads one entry from the file by sequence number (1-based).
    private CtJournalEntry readEntry(final long sequenceNumber) throws CtJournalException {
        long offset = (sequenceNumber - 1L) * RECORD_BYTES;
        ByteBuffer buf = ByteBuffer.allocate(RECORD_BYTES);
        try {
            int read = 0;
            while (buf.hasRemaining()) {
                int n = channel.read(buf, offset + read);
                if (n < 0) {
                    throw new CtJournalException("Unexpected EOF reading entry " + sequenceNumber);
                }
                read += n;
            }
        } catch (IOException failure) {
            throw new CtJournalException("Failed to read CT journal entry " + sequenceNumber, failure);
        }
        return deserialize(buf.array(), sequenceNumber);
    }

    // Scans entries.bin from the beginning and rebuilds the in-memory index.

    private long rebuildIndex() throws CtJournalException {
        long count = 0L;
        try {
            long fileSize = channel.size();
            long entryCount = fileSize / RECORD_BYTES;
            for (long i = 0L; i < entryCount; i++) {
                CtJournalEntry entry = readEntry(i + 1L);
                String fpHex = HexFormat.of().formatHex(entry.certFingerprint());
                fingerprintIndex.put(fpHex, entry.sequenceNumber());
                count = entry.sequenceNumber();
            }
        } catch (IOException failure) {
            throw new CtJournalException("Failed to read CT journal file size", failure);
        }
        return count;
    }

    private static byte[] serialize(final CtJournalEntry entry) {
        byte[] record = new byte[RECORD_BYTES];
        ByteBuffer buf = ByteBuffer.wrap(record);

        // sequenceNumber
        buf.position(OFFSET_SEQ);
        buf.putLong(entry.sequenceNumber());

        // timestamp
        buf.position(OFFSET_EPOCH_S);
        buf.putLong(entry.timestamp().getEpochSecond());
        buf.position(OFFSET_NANOS);
        buf.putInt(entry.timestamp().getNano());

        // certFingerprint (32 bytes)
        buf.position(OFFSET_FINGERPRINT);
        buf.put(entry.certFingerprint(), 0, CtJournalEntry.HASH_BYTES);

        // serialNumber (20 bytes big-endian, zero-padded from left)
        byte[] serialBytes = entry.serialNumber().toByteArray();
        buf.position(OFFSET_SERIAL);
        if (serialBytes.length >= SERIAL_BYTES) {
            buf.put(serialBytes, serialBytes.length - SERIAL_BYTES, SERIAL_BYTES);
        } else {
            buf.position(OFFSET_SERIAL + SERIAL_BYTES - serialBytes.length);
            buf.put(serialBytes);
        }

        // authorityId (2-byte length + up to 128 bytes data)
        byte[] authorityBytes = entry.authorityId().getBytes(StandardCharsets.UTF_8);
        int authorityLen = Math.min(authorityBytes.length, AUTHORITY_DATA_BYTES);
        buf.position(OFFSET_AUTHORITY_LEN);
        buf.putShort((short) authorityLen);
        buf.position(OFFSET_AUTHORITY_DATA);
        buf.put(authorityBytes, 0, authorityLen);

        // previousHash, leafHash, entryHash
        buf.position(OFFSET_PREV_HASH);
        buf.put(entry.previousHash(), 0, CtJournalEntry.HASH_BYTES);
        buf.position(OFFSET_LEAF_HASH);
        buf.put(entry.leafHash(), 0, CtJournalEntry.HASH_BYTES);
        buf.position(OFFSET_ENTRY_HASH);
        buf.put(entry.entryHash(), 0, CtJournalEntry.HASH_BYTES);

        return record;
    }

    private static CtJournalEntry deserialize(final byte[] record, final long expectedSeq)
            throws CtJournalException {
        if (record.length < RECORD_BYTES) {
            throw new CtJournalException("Record too short for entry " + expectedSeq);
        }
        ByteBuffer buf = ByteBuffer.wrap(record);

        long sequenceNumber = buf.getLong(OFFSET_SEQ);
        long epochSeconds = buf.getLong(OFFSET_EPOCH_S);
        int nanos = buf.getInt(OFFSET_NANOS);
        Instant timestamp = Instant.ofEpochSecond(epochSeconds, nanos);

        byte[] certFingerprint = new byte[CtJournalEntry.HASH_BYTES];
        buf.position(OFFSET_FINGERPRINT);
        buf.get(certFingerprint);

        byte[] serialBytes = new byte[SERIAL_BYTES];
        buf.position(OFFSET_SERIAL);
        buf.get(serialBytes);
        BigInteger serialNumber = new BigInteger(1, serialBytes);

        int authorityLen = Short.toUnsignedInt(buf.getShort(OFFSET_AUTHORITY_LEN));
        byte[] authorityData = new byte[Math.min(authorityLen, AUTHORITY_DATA_BYTES)];
        buf.position(OFFSET_AUTHORITY_DATA);
        buf.get(authorityData);
        String authorityId = new String(authorityData, 0, authorityData.length, StandardCharsets.UTF_8);

        byte[] previousHash = new byte[CtJournalEntry.HASH_BYTES];
        buf.position(OFFSET_PREV_HASH);
        buf.get(previousHash);

        byte[] leafHash = new byte[CtJournalEntry.HASH_BYTES];
        buf.position(OFFSET_LEAF_HASH);
        buf.get(leafHash);

        byte[] entryHash = new byte[CtJournalEntry.HASH_BYTES];
        buf.position(OFFSET_ENTRY_HASH);
        buf.get(entryHash);

        if (sequenceNumber != expectedSeq) {
            throw new CtJournalException("Record at position " + expectedSeq
                    + " has unexpected sequenceNumber " + sequenceNumber);
        }

        return new CtJournalEntry(sequenceNumber, timestamp, certFingerprint,
                serialNumber, authorityId, previousHash, leafHash, entryHash);
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("CT journal store is closed");
        }
    }
}
