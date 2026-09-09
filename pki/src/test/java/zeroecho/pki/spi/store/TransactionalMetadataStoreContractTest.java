/*******************************************************************************
 * Copyright (c) 2025 ZeroEcho
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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;

final class TransactionalMetadataStoreContractTest {
    private static final MetadataKey FIRST = new MetadataKey("example.records", "first");
    private static final MetadataKey SECOND = new MetadataKey("example.other", "second");

    @TempDir
    private Path temporaryDirectory;

    @Test
    void createReplaceAndDeleteAreAtomicAcrossNamespaces() throws Exception {
        System.out.print("createReplaceAndDeleteAreAtomicAcrossNamespaces ");
        try (InMemoryTransactionalMetadataStore store = store()) {
            try (MetadataTransaction transaction = store.beginTransaction()) {
                transaction.create(FIRST, content("one"), CancellationSignal.NONE);
                transaction.create(SECOND, content("two"), CancellationSignal.NONE);
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
            }
            try (MetadataSnapshot snapshot = store.snapshot()) {
                assertEquals("one", read(snapshot, FIRST));
                assertEquals("two", read(snapshot, SECOND));
            }
            try (MetadataTransaction transaction = store.beginTransaction()) {
                transaction.replace(FIRST, 0L, content("updated"), CancellationSignal.NONE);
                transaction.delete(SECOND, 0L);
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
            }
            try (MetadataSnapshot snapshot = store.snapshot()) {
                assertEquals("updated", read(snapshot, FIRST));
                assertTrue(snapshot.get(SECOND).isEmpty());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void conflictIsTerminalResolvableAndHasNoPartialVisibility() throws Exception {
        System.out.print("conflictIsTerminalResolvableAndHasNoPartialVisibility ");
        try (InMemoryTransactionalMetadataStore store = store()) {
            create(store, FIRST, "original");
            MetadataTransaction transaction = store.beginTransaction();
            transaction.create(FIRST, content("conflict"), CancellationSignal.NONE);
            transaction.create(SECOND, content("hidden"), CancellationSignal.NONE);
            MetadataCommitResult result = transaction.commit();
            assertEquals(MetadataCommitResult.Outcome.NOT_COMMITTED, result.outcome());
            assertEquals(result, store.resolve(transaction.id()));
            assertThrows(IllegalStateException.class, transaction::commit);
            try (MetadataSnapshot snapshot = store.snapshot()) {
                assertEquals("original", read(snapshot, FIRST));
                assertTrue(snapshot.get(SECOND).isEmpty());
            }
            transaction.close();
        }
        System.out.println("...ok");
    }

    @Test
    void unknownOnlyHidesAnAlreadyFixedOutcome() throws Exception {
        System.out.print("unknownOnlyHidesAnAlreadyFixedOutcome ");
        try (InMemoryTransactionalMetadataStore store = store()) {
            store.hideNextCommittedOutcome();
            MetadataTransaction transaction = store.beginTransaction();
            transaction.create(FIRST, content("fixed"), CancellationSignal.NONE);
            MetadataCommitResult immediate = transaction.commit();
            assertEquals(MetadataCommitResult.Outcome.UNKNOWN, immediate.outcome());
            try (MetadataSnapshot snapshot = store.snapshot()) {
                assertEquals("fixed", read(snapshot, FIRST));
            }
            assertEquals(
                    MetadataCommitResult.Outcome.COMMITTED,
                    store.resolve(transaction.id()).outcome());
            assertEquals(store.resolve(transaction.id()), store.resolve(transaction.id()));
            transaction.close();
        }
        System.out.println("...ok");
    }

    @Test
    void foreignAndUnissuedTransactionIdentitiesFailClosed() throws Exception {
        System.out.print("foreignAndUnissuedTransactionIdentitiesFailClosed ");
        MetadataStoreId shared = new MetadataStoreId("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        try (InMemoryTransactionalMetadataStore first = new InMemoryTransactionalMetadataStore(
                        temporaryDirectory.resolve("first"),
                        shared,
                        MetadataStoreCapabilities.ContentLengthModel.KNOWN_OR_UNKNOWN_LENGTH,
                        OptionalLong.empty());
                InMemoryTransactionalMetadataStore second = new InMemoryTransactionalMetadataStore(
                        temporaryDirectory.resolve("second"),
                        shared,
                        MetadataStoreCapabilities.ContentLengthModel.KNOWN_OR_UNKNOWN_LENGTH,
                        OptionalLong.empty())) {
            MetadataTransaction issued = first.beginTransaction();
            assertThrows(MetadataStoreException.class, () -> second.resolve(issued.id()));
            MetadataTransactionId unissued =
                    new MetadataTransactionId(shared, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
            assertThrows(MetadataStoreException.class, () -> first.resolve(unissued));
            issued.abort();
        }
        System.out.println("...ok");
    }

    @Test
    void knownAndUnknownContentDetachSynchronously() throws Exception {
        System.out.print("knownAndUnknownContentDetachSynchronously ");
        try (InMemoryTransactionalMetadataStore store = store()) {
            ProbeContent known = new ProbeContent("known", true);
            ProbeContent unknown = new ProbeContent("unknown", false);
            try (MetadataTransaction transaction = store.beginTransaction()) {
                transaction.create(FIRST, known, CancellationSignal.NONE);
                transaction.create(SECOND, unknown, CancellationSignal.NONE);
                known.invalidate();
                unknown.invalidate();
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
            }
            assertEquals(1, known.openCount());
            assertEquals(1, unknown.openCount());
            try (MetadataSnapshot snapshot = store.snapshot()) {
                assertEquals("known", read(snapshot, FIRST));
                assertEquals("unknown", read(snapshot, SECOND));
            }
        }
        System.out.println("...ok");
    }

    @Test
    void callerContentStagingDoesNotHoldStoreMonitor() throws Exception {
        System.out.print("callerContentStagingDoesNotHoldStoreMonitor ");
        try (InMemoryTransactionalMetadataStore store = store();
                ExecutorService executor = Executors.newSingleThreadExecutor()) {
            BlockingContent content = new BlockingContent(store);
            Future<Void> staging = executor.submit(() -> {
                try (MetadataTransaction transaction = store.beginTransaction()) {
                    transaction.create(FIRST, content, CancellationSignal.NONE);
                    transaction.abort();
                }
                return null;
            });
            content.awaitReadStarted();
            assertEquals(1, store.activeAdmissionCount());
            try (MetadataSnapshot snapshot = store.snapshot()) {
                assertEquals(0L, snapshot.revision());
            }
            assertFalse(content.monitorObserved());
            content.releaseRead();
            staging.get();
            assertEquals(0, store.activeAdmissionCount());
        }
        System.out.println("...ok");
    }

    @Test
    void interruptedClosePreservesClosingAdmissionBarrier() throws Exception {
        System.out.print("interruptedClosePreservesClosingAdmissionBarrier ");
        InMemoryTransactionalMetadataStore store = store();
        try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
            BlockingContent content = new BlockingContent(store);
            Future<Void> staging = executor.submit(() -> {
                try (MetadataTransaction transaction = store.beginTransaction()) {
                    transaction.create(FIRST, content, CancellationSignal.NONE);
                }
                return null;
            });
            content.awaitReadStarted();
            AtomicReference<Throwable> closeFailure = new AtomicReference<>();
            Thread closingThread = Thread.ofPlatform().unstarted(() -> {
                try {
                    store.close();
                } catch (Throwable failure) {
                    closeFailure.set(failure);
                }
            });
            closingThread.start();
            store.awaitClosingStarted();
            closingThread.interrupt();
            closingThread.join();
            assertTrue(closeFailure.get() instanceof IOException);
            content.releaseRead();
            assertThrows(java.util.concurrent.ExecutionException.class, staging::get);
            assertEquals(0, store.activeAdmissionCount());
            store.close();
        } finally {
            store.close();
        }
        System.out.println("...ok");
    }

    @Test
    void contentLengthCapabilityAndTechnicalLimitAreEnforced() throws Exception {
        System.out.print("contentLengthCapabilityAndTechnicalLimitAreEnforced ");
        try (InMemoryTransactionalMetadataStore knownOnly =
                        new InMemoryTransactionalMetadataStore(
                                temporaryDirectory.resolve("known-only"),
                                MetadataStoreCapabilities.ContentLengthModel.KNOWN_LENGTH_ONLY,
                                OptionalLong.of(4L));
                MetadataTransaction transaction = knownOnly.beginTransaction()) {
            transaction.create(FIRST, content("four"), CancellationSignal.NONE);
            assertThrows(
                    MetadataStoreException.class,
                    () -> transaction.create(
                            SECOND, new ProbeContent("x", false), CancellationSignal.NONE));
        }
        try (InMemoryTransactionalMetadataStore limited =
                        new InMemoryTransactionalMetadataStore(
                                temporaryDirectory.resolve("limited"),
                                MetadataStoreCapabilities.ContentLengthModel.KNOWN_OR_UNKNOWN_LENGTH,
                                OptionalLong.of(4L));
                MetadataTransaction transaction = limited.beginTransaction()) {
            assertThrows(
                    MetadataStoreException.class,
                    () -> transaction.create(FIRST, content("five!"), CancellationSignal.NONE));
        }
        System.out.println("...ok");
    }

    @Test
    void snapshotsAreStableAndScansAreLazyAndOrdered() throws Exception {
        System.out.print("snapshotsAreStableAndScansAreLazyAndOrdered ");
        try (InMemoryTransactionalMetadataStore store = store()) {
            create(store, new MetadataKey("example.records", "a"), "a");
            create(store, new MetadataKey("example.records", "b"), "b");
            try (MetadataSnapshot old = store.snapshot()) {
                replace(store, new MetadataKey("example.records", "a"), 0L, "new-a");
                assertEquals("a", read(old, new MetadataKey("example.records", "a")));
                List<String> keys = new ArrayList<>();
                try (MetadataCursor cursor = old.scan(
                        MetadataSnapshot.KeyRange.prefix("example.records", ""),
                        CancellationSignal.NONE)) {
                    Optional<MetadataSnapshot.Record> next;
                    while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                        try (MetadataSnapshot.Record record = next.orElseThrow()) {
                            keys.add(record.key().key());
                        }
                    }
                }
                assertEquals(List.of("a", "b"), keys);
            }
            try (MetadataSnapshot current = store.snapshot()) {
                assertEquals("new-a", read(current, new MetadataKey("example.records", "a")));
            }
        }
        System.out.println("...ok");
    }

    @Test
    void cancellationStopsAdmissionAndLeavesTransactionReusable() throws Exception {
        System.out.print("cancellationStopsAdmissionAndLeavesTransactionReusable ");
        try (InMemoryTransactionalMetadataStore store = store();
                MetadataTransaction transaction = store.beginTransaction()) {
            AtomicInteger checks = new AtomicInteger();
            CancellationSignal cancellation = () -> checks.incrementAndGet() > 3;
            assertThrows(
                    IOException.class,
                    () -> transaction.create(
                            FIRST, new GeneratedContent(32768L, false), cancellation));
            transaction.create(FIRST, content("retry"), CancellationSignal.NONE);
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
        }
        System.out.println("...ok");
    }

    @Test
    void largeUnknownContentUsesBoundedStreamingAndRemainsRepeatable() throws Exception {
        System.out.print("largeUnknownContentUsesBoundedStreamingAndRemainsRepeatable ");
        try (InMemoryTransactionalMetadataStore store = store()) {
            GeneratedContent generated = new GeneratedContent(131_072L, false);
            try (MetadataTransaction transaction = store.beginTransaction()) {
                transaction.create(FIRST, generated, CancellationSignal.NONE);
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
            }
            assertEquals(1, generated.openCount());
            try (MetadataSnapshot snapshot = store.snapshot();
                    MetadataSnapshot.Record record = snapshot.get(FIRST).orElseThrow();
                    InputStream first = record.openStream();
                    InputStream second = record.openStream()) {
                assertArrayEquals(first.readNBytes(1024), second.readNBytes(1024));
                assertEquals(131_072L, record.length().orElseThrow());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void lifecycleRejectsUseAfterClose() throws Exception {
        System.out.print("lifecycleRejectsUseAfterClose ");
        InMemoryTransactionalMetadataStore store = store();
        MetadataTransaction transaction = store.beginTransaction();
        transaction.abort();
            assertThrows(IllegalStateException.class, transaction::commit);
        MetadataSnapshot snapshot = store.snapshot();
        MetadataCursor cursor = snapshot.scan(
                MetadataSnapshot.KeyRange.all("example.records"),
                CancellationSignal.NONE);
        cursor.close();
        assertThrows(
                IllegalStateException.class,
                () -> cursor.next(CancellationSignal.NONE));
        snapshot.close();
        assertThrows(IllegalStateException.class, () -> snapshot.get(FIRST));
        store.close();
        store.close();
        assertThrows(IllegalStateException.class, store::beginTransaction);
        System.out.println("...ok");
    }

    private InMemoryTransactionalMetadataStore store() throws IOException {
        return new InMemoryTransactionalMetadataStore(
                temporaryDirectory.resolve("store-" + System.nanoTime()),
                MetadataStoreCapabilities.ContentLengthModel.KNOWN_OR_UNKNOWN_LENGTH,
                OptionalLong.empty());
    }

    private static void create(
            TransactionalMetadataStore store, MetadataKey key, String value) throws Exception {
        try (MetadataTransaction transaction = store.beginTransaction()) {
            transaction.create(key, content(value), CancellationSignal.NONE);
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
        }
    }

    private static void replace(
            TransactionalMetadataStore store,
            MetadataKey key,
            long expectedRevision,
            String value) throws Exception {
        try (MetadataTransaction transaction = store.beginTransaction()) {
            transaction.replace(key, expectedRevision, content(value), CancellationSignal.NONE);
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
        }
    }

    private static String read(MetadataSnapshot snapshot, MetadataKey key) throws Exception {
        try (MetadataSnapshot.Record record = snapshot.get(key).orElseThrow();
                InputStream input = record.openStream()) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static RepeatableContent content(String value) {
        return new ProbeContent(value, true);
    }

    private static final class ProbeContent implements RepeatableContent {
        private final byte[] value;
        private final boolean knownLength;
        private final AtomicBoolean valid = new AtomicBoolean(true);
        private final AtomicInteger opens = new AtomicInteger();

        private ProbeContent(String value, boolean knownLength) {
            this.value = value.getBytes(StandardCharsets.UTF_8);
            this.knownLength = knownLength;
        }

        @Override
        public InputStream openStream() throws IOException {
            if (!valid.get()) {
                throw new IOException("Probe source invalidated");
            }
            opens.incrementAndGet();
            return new ByteArrayInputStream(value);
        }

        @Override
        public OptionalLong length() {
            return knownLength ? OptionalLong.of(value.length) : OptionalLong.empty();
        }

        @Override
        public String contentId() {
            return "probe";
        }

        @Override
        public void close() {
            valid.set(false);
        }

        private void invalidate() {
            valid.set(false);
        }

        private int openCount() {
            return opens.get();
        }
    }

    private static final class GeneratedContent implements RepeatableContent {
        private final long length;
        private final boolean knownLength;
        private final AtomicInteger opens = new AtomicInteger();

        private GeneratedContent(long length, boolean knownLength) {
            this.length = length;
            this.knownLength = knownLength;
        }

        @Override
        public InputStream openStream() {
            opens.incrementAndGet();
            return new InputStream() {
                private long remaining = length;

                @Override
                public int read() {
                    if (remaining == 0L) {
                        return -1;
                    }
                    remaining--;
                    return 0x5a;
                }

                @Override
                public int read(byte[] buffer, int offset, int requested) {
                    if (remaining == 0L) {
                        return -1;
                    }
                    int count = (int) Math.min(requested, remaining);
                    java.util.Arrays.fill(buffer, offset, offset + count, (byte) 0x5a);
                    remaining -= count;
                    return count;
                }
            };
        }

        @Override
        public OptionalLong length() {
            return knownLength ? OptionalLong.of(length) : OptionalLong.empty();
        }

        @Override
        public String contentId() {
            return "generated";
        }

        @Override
        public void close() {
        }

        private int openCount() {
            return opens.get();
        }
    }

    private static final class BlockingContent implements RepeatableContent {
        private final InMemoryTransactionalMetadataStore store;
        private final CountDownLatch readStarted = new CountDownLatch(1);
        private final CountDownLatch readReleased = new CountDownLatch(1);
        private final AtomicBoolean monitorObserved = new AtomicBoolean();

        private BlockingContent(InMemoryTransactionalMetadataStore store) {
            this.store = store;
        }

        @Override
        public InputStream openStream() {
            recordMonitorState();
            return new InputStream() {
                private boolean delivered;

                @Override
                public int read() throws IOException {
                    byte[] single = new byte[1];
                    int count = read(single, 0, single.length);
                    return count < 0 ? -1 : Byte.toUnsignedInt(single[0]);
                }

                @Override
                public int read(byte[] buffer, int offset, int length) throws IOException {
                    recordMonitorState();
                    if (delivered) {
                        return -1;
                    }
                    readStarted.countDown();
                    awaitReadRelease();
                    buffer[offset] = 0x41;
                    delivered = true;
                    return 1;
                }
            };
        }

        @Override
        public OptionalLong length() {
            recordMonitorState();
            return OptionalLong.of(1L);
        }

        @Override
        public String contentId() {
            return "blocking-probe";
        }

        @Override
        public void close() {
        }

        private void awaitReadStarted() throws InterruptedException {
            readStarted.await();
        }

        private void releaseRead() {
            readReleased.countDown();
        }

        private boolean monitorObserved() {
            return monitorObserved.get();
        }

        private void recordMonitorState() {
            if (Thread.holdsLock(store)) {
                monitorObserved.set(true);
            }
        }

        private void awaitReadRelease() throws IOException {
            try {
                readReleased.await();
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new IOException("Blocking content read interrupted", exception);
            }
        }
    }
}
