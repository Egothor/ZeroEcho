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
package zeroecho.pki.impl.fs.ct;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.spi.ct.CtJournalEntry;
import zeroecho.pki.spi.ct.CtJournalException;
import zeroecho.pki.spi.ct.CtJournalStore;
import zeroecho.pki.spi.ct.CtJournalVerificationResult;

/** Unit tests for {@link FsCtJournalStore}. */
class FsCtJournalStoreTest {

    private static final Instant T0 = Instant.parse("2026-09-01T00:00:00Z");
    private static final String AUTHORITY = "cn=Test CA";

    @TempDir Path dir;

    @Test
    @Timeout(10)
    void queuedAppendRechecksClosedStateAfterAcquiringLock() throws Exception {
        {
            FsCtJournalStore store = new FsCtJournalStore(dir.resolve("queued"));
            try (store) {
                ReentrantReadWriteLock lock = storeLock(store);
                FutureTask<Void> append = new FutureTask<>(() -> {
                    store.append(firstEntry(fingerprint(1)));
                    return null;
                });
                lock.writeLock().lock();
                try {
                    Thread thread = Thread.ofPlatform().start(append);
                    awaitQueued(lock, thread, append);
                    store.close();
                } finally {
                    lock.writeLock().unlock();
                }
                ExecutionException failure = assertThrows(ExecutionException.class,
                        () -> append.get(5, TimeUnit.SECONDS));
                assertInstanceOf(IllegalStateException.class, failure.getCause());
            }
        }
    }

    @Test
    @Timeout(10)
    void closeWaitsForActiveReadOperation() throws Exception {
        {
            FsCtJournalStore store = new FsCtJournalStore(dir.resolve("closing"));
            try (store) {
                ReentrantReadWriteLock lock = storeLock(store);
                FutureTask<Void> close = new FutureTask<>(() -> { store.close(); return null; });
                lock.readLock().lock();
                try {
                    Thread thread = Thread.ofPlatform().start(close);
                    awaitQueued(lock, thread, close);
                    assertFalse(close.isDone(), "close must not close the channel during an active reader");
                } finally {
                    lock.readLock().unlock();
                }
                close.get(5, TimeUnit.SECONDS);
                assertThrows(IllegalStateException.class, store::latestSequenceNumber);
            }
        }
    }

    private static ReentrantReadWriteLock storeLock(FsCtJournalStore store) throws Exception {
        Field field = FsCtJournalStore.class.getDeclaredField("lock");
        field.setAccessible(true);
        return (ReentrantReadWriteLock) field.get(store);
    }

    private static void awaitQueued(ReentrantReadWriteLock lock, Thread thread, FutureTask<?> task) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!lock.hasQueuedThread(thread) && !task.isDone() && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        assertTrue(lock.hasQueuedThread(thread) || task.isDone(), "operation did not reach the lock");
    }

    private static byte[] fingerprint(int seed) {
        byte[] fp = new byte[CtJournalEntry.HASH_BYTES];
        Arrays.fill(fp, (byte) seed);
        return fp;
    }

    private static CtJournalEntry firstEntry(byte[] fp) {
        return CtJournalEntry.create(1L, T0, fp, BigInteger.ONE, AUTHORITY,
                new byte[CtJournalEntry.HASH_BYTES]);
    }

    /** Empty journal reports sequence number 0 and index is rebuilt correctly on reopen. */
    @Test
    void emptyJournal_sequenceIsZero() throws CtJournalException {
        try (CtJournalStore store = FsCtJournalStoreFactory.open(dir.resolve("ct"))) {
            assertEquals(0L, store.latestSequenceNumber());
        }
    }

    /** Appended entry is durable: survives store close and reopen. */
    @Test
    void appendAndReopen_entryIsDurable() throws CtJournalException {
        Path journalDir = dir.resolve("ct");
        byte[] fp = fingerprint(0xAB);
        CtJournalEntry appended = firstEntry(fp);

        try (CtJournalStore store = FsCtJournalStoreFactory.open(journalDir)) {
            store.append(appended);
            assertEquals(1L, store.latestSequenceNumber());
        }

        try (CtJournalStore store = FsCtJournalStoreFactory.open(journalDir)) {
            assertEquals(1L, store.latestSequenceNumber());
            CtJournalEntry retrieved = store.lookup(fp);
            assertNotNull(retrieved);
            assertEquals(1L, retrieved.sequenceNumber());
            assertEquals(AUTHORITY, retrieved.authorityId());
            assertArrayEquals(appended.entryHash(), retrieved.entryHash());
        }
    }

    /** Chain of three entries verifies intact end-to-end. */
    @Test
    void chainOfThree_verifyIntact() throws CtJournalException {
        Path journalDir = dir.resolve("ct");
        try (FsCtJournalStore store = (FsCtJournalStore) FsCtJournalStoreFactory.open(journalDir)) {
            byte[] prevHash = new byte[CtJournalEntry.HASH_BYTES];
            for (int i = 1; i <= 3; i++) {
                byte[] fp = fingerprint(i);
                CtJournalEntry entry = CtJournalEntry.create((long) i, T0.plusSeconds(i), fp,
                        BigInteger.valueOf(i), AUTHORITY, prevHash);
                store.append(entry);
                prevHash = store.headEntryHash();
            }
            CtJournalVerificationResult result = store.verify(1L, 3L);
            assertTrue(result.intact());
            assertTrue(result.brokenAtSequences().isEmpty());
        }
    }

    /** Appending with wrong sequence number throws CtJournalException. */
    @Test
    void appendWrongSequence_throwsException() throws CtJournalException {
        try (CtJournalStore store = FsCtJournalStoreFactory.open(dir.resolve("ct"))) {
            byte[] fp = fingerprint(0x01);
            CtJournalEntry wrongSeq = CtJournalEntry.create(2L, T0, fp, BigInteger.ONE, AUTHORITY,
                    new byte[CtJournalEntry.HASH_BYTES]);
            assertThrows(CtJournalException.class, () -> store.append(wrongSeq));
        }
    }

    /** Tampered record is detected by verify(). */
    @Test
    void tamperedEntry_verifyReportsBreak() throws Exception {
        Path journalDir = dir.resolve("ct");
        byte[] fp1 = fingerprint(0x11);
        byte[] fp2 = fingerprint(0x22);
        byte[] headHash;
        try (FsCtJournalStore store = (FsCtJournalStore) FsCtJournalStoreFactory.open(journalDir)) {
            store.append(firstEntry(fp1));
            headHash = store.headEntryHash();
            CtJournalEntry entry2 = CtJournalEntry.create(2L, T0.plusSeconds(1), fp2,
                    BigInteger.TWO, AUTHORITY, headHash);
            store.append(entry2);
        }

        // Corrupt one byte inside entry 1's entryHash region (offset 266 into record 0).
        Path entriesFile = journalDir.resolve("entries.bin");
        byte[] raw = Files.readAllBytes(entriesFile);
        raw[266] = (byte) (raw[266] ^ 0xFF);
        Files.write(entriesFile, raw);

        try (CtJournalStore store = FsCtJournalStoreFactory.open(journalDir)) {
            CtJournalVerificationResult result = store.verify(1L, 2L);
            assertFalse(result.intact());
            assertFalse(result.brokenAtSequences().isEmpty());
        }
    }
}
