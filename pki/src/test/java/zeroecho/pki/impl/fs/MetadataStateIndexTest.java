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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.OptionalLong;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataStoreException;

final class MetadataStateIndexTest {

    @Test
    void committedRevisionIsTheRecordRevisionAndEmptyCommitAdvancesOnce() throws MetadataStoreException {
        System.out.print("committedRevisionIsTheRecordRevisionAndEmptyCommitAdvancesOnce ");
        MetadataStateIndex index = new MetadataStateIndex();
        MetadataKey key = key("b");
        index.applyCommitted(1L, List.of(create(key, 100L, 4L)));
        assertEquals(1L, index.storeRevision());
        assertEquals(1L, index.lookup(key).orElseThrow().revision());
        index.applyCommitted(2L, List.of());
        assertEquals(2L, index.storeRevision());
        assertEquals(1L, index.lookup(key).orElseThrow().revision());
        index.applyCommitted(3L, List.of(replace(key, 1L, 200L, 5L)));
        assertEquals(3L, index.lookup(key).orElseThrow().revision());
        assertEquals(200L, index.lookup(key).orElseThrow().valueOffset());
        index.applyCommitted(4L, List.of(delete(key, 3L)));
        assertEquals(4L, index.storeRevision());
        assertTrue(index.lookup(key).isEmpty());
        System.out.println("...ok");
    }

    @Test
    void conflictsAndDuplicateKeysPublishNoPartialDelta() throws MetadataStoreException {
        System.out.print("conflictsAndDuplicateKeysPublishNoPartialDelta ");
        MetadataStateIndex index = new MetadataStateIndex();
        MetadataKey existing = key("existing");
        MetadataKey added = key("added");
        index.applyCommitted(1L, List.of(create(existing, 10L, 2L)));

        assertConflict(() -> index.applyCommitted(2L, List.of(
                create(added, 20L, 2L), replace(existing, 0L, 30L, 3L))));
        assertEquals(1L, index.storeRevision());
        assertTrue(index.lookup(added).isEmpty());
        assertEquals(10L, index.lookup(existing).orElseThrow().valueOffset());

        assertConflict(() -> index.applyCommitted(2L, List.of(create(existing, 40L, 4L))));
        assertConflict(() -> index.applyCommitted(2L, List.of(delete(existing, 0L))));
        assertConflict(() -> index.applyCommitted(2L, List.of(
                replace(existing, 1L, 50L, 5L), delete(existing, 1L))));
        assertEquals(1L, index.storeRevision());
        System.out.println("...ok");
    }

    @Test
    void multiKeyPublicationAndIterationAreDeterministicAndImmutable() throws MetadataStoreException {
        System.out.print("multiKeyPublicationAndIterationAreDeterministicAndImmutable ");
        MetadataStateIndex index = new MetadataStateIndex();
        MetadataKey first = key("a");
        MetadataKey second = key("b");
        index.applyCommitted(1L, List.of(create(second, 20L, 2L), create(first, 10L, 1L)));
        List<MetadataStateIndex.CurrentRecord> records = index.records();
        assertEquals(List.of(first, second), records.stream().map(MetadataStateIndex.CurrentRecord::key).toList());
        assertThrows(UnsupportedOperationException.class,
                () -> records.add(new MetadataStateIndex.CurrentRecord(key("c"), 1L, 30L, 3L)));
        assertEquals(records, index.records());
        System.out.println("...ok");
    }

    @Test
    void invalidRevisionAndDescriptorShapesFailWithStableSafeCategories() throws MetadataStoreException {
        System.out.print("invalidRevisionAndDescriptorShapesFailWithStableSafeCategories ");
        MetadataStateIndex index = new MetadataStateIndex();
        MetadataStoreException skipped = assertThrows(
                MetadataStoreException.class, () -> index.applyCommitted(2L, List.of()));
        assertEquals(MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE, skipped.category());
        MetadataStoreException malformed = assertThrows(
                MetadataStoreException.class,
                () -> index.applyCommitted(1L, List.of(new MetadataMutationPayloadCodec.Descriptor(
                        MetadataMutationPayloadCodec.MutationKind.CREATE,
                        key("bad"),
                        OptionalLong.empty(),
                        OptionalLong.empty(),
                        OptionalLong.empty()))));
        assertEquals(MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE, malformed.category());
        assertEquals(0L, index.storeRevision());
        assertTrue(index.records().isEmpty());
        System.out.println("...ok");
    }

    @Test
    void malformedValueRegionsFailCheckedAndPublishNoState() throws MetadataStoreException {
        System.out.print("malformedValueRegionsFailCheckedAndPublishNoState ");
        MetadataStateIndex index = new MetadataStateIndex();
        MetadataKey existing = key("existing-region");
        index.applyCommitted(1L, List.of(create(existing, 10L, 2L)));
        List<MetadataStateIndex.CurrentRecord> before = index.records();

        assertIntegrity(() -> index.applyCommitted(2L, List.of(create(key("negative-offset"), -1L, 1L))));
        assertIntegrity(() -> index.applyCommitted(2L, List.of(create(key("negative-length"), 1L, -1L))));
        assertIntegrity(() -> index.applyCommitted(
                2L, List.of(create(key("overflow"), Long.MAX_VALUE, 1L))));
        assertIntegrity(() -> index.applyCommitted(2L, List.of(new MetadataMutationPayloadCodec.Descriptor(
                MetadataMutationPayloadCodec.MutationKind.DELETE,
                existing,
                OptionalLong.of(1L),
                OptionalLong.of(20L),
                OptionalLong.of(1L)))));
        assertIntegrity(() -> index.applyCommitted(2L, List.of(new MetadataMutationPayloadCodec.Descriptor(
                MetadataMutationPayloadCodec.MutationKind.CREATE,
                key("unexpected-revision"),
                OptionalLong.of(1L),
                OptionalLong.of(20L),
                OptionalLong.of(1L)))));
        assertIntegrity(() -> index.applyCommitted(2L, java.util.Collections.singletonList(null)));

        assertEquals(1L, index.storeRevision());
        assertEquals(before, index.records());
        System.out.println("...ok");
    }

    @Test
    void concurrentReadersObserveOnlyAtomicImmutableStates() throws Exception {
        System.out.print("concurrentReadersObserveOnlyAtomicImmutableStates ");
        MetadataStateIndex index = new MetadataStateIndex();
        index.applyCommitted(1L, List.of(create(key("initial"), 1L, 1L)));
        CountDownLatch start = new CountDownLatch(1);
        AtomicBoolean writeComplete = new AtomicBoolean();
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<List<Integer>> observations = executor.submit(() -> {
                java.util.ArrayList<Integer> sizes = new java.util.ArrayList<>();
                start.await();
                do {
                    sizes.add(index.records().size());
                } while (!writeComplete.get());
                sizes.add(index.records().size());
                return List.copyOf(sizes);
            });
            Future<Void> writer = executor.submit(() -> {
                start.await();
                index.applyCommitted(2L, List.of(
                        create(key("second"), 2L, 1L),
                        create(key("third"), 3L, 1L)));
                writeComplete.set(true);
                return null;
            });
            start.countDown();
            writer.get();
            List<Integer> sizes = observations.get();
            assertTrue(sizes.stream().allMatch(size -> size == 1 || size == 3));
            assertEquals(3, sizes.get(sizes.size() - 1));
            List<MetadataStateIndex.CurrentRecord> records = index.records();
            assertThrows(UnsupportedOperationException.class, records::clear);
        } finally {
            executor.shutdownNow();
        }
        System.out.println("...ok");
    }

    @Test
    void updatesAvoidFullIndexCopiesWithoutPinnedSnapshotAndPreservePinnedView() throws Exception {
        MetadataStateIndex index = new MetadataStateIndex();
        for (int revision = 1; revision <= 100; revision++) {
            index.applyCommitted(revision, List.of(create(key("key-" + revision), revision, 1L)));
        }
        assertEquals(0L, index.snapshotCopyCount());

        MetadataStateIndex.SnapshotView pinned = index.snapshot();
        assertEquals(100, pinned.records().size());
        index.applyCommitted(101L, List.of(create(key("key-101"), 101L, 1L)));
        assertEquals(1L, index.snapshotCopyCount());
        assertEquals(100, pinned.records().size());
        index.applyCommitted(102L, List.of(create(key("key-102"), 102L, 1L)));
        assertEquals(1L, index.snapshotCopyCount());
        assertEquals(100, pinned.records().size());
        pinned.release().run();

        index.applyCommitted(103L, List.of(create(key("key-103"), 103L, 1L)));
        assertEquals(1L, index.snapshotCopyCount());
        assertEquals(103, index.records().size());
    }

    private static MetadataMutationPayloadCodec.Descriptor create(
            MetadataKey key, long offset, long length) {
        return new MetadataMutationPayloadCodec.Descriptor(
                MetadataMutationPayloadCodec.MutationKind.CREATE,
                key,
                OptionalLong.empty(),
                OptionalLong.of(offset),
                OptionalLong.of(length));
    }

    private static MetadataMutationPayloadCodec.Descriptor replace(
            MetadataKey key, long expectedRevision, long offset, long length) {
        return new MetadataMutationPayloadCodec.Descriptor(
                MetadataMutationPayloadCodec.MutationKind.REPLACE,
                key,
                OptionalLong.of(expectedRevision),
                OptionalLong.of(offset),
                OptionalLong.of(length));
    }

    private static MetadataMutationPayloadCodec.Descriptor delete(MetadataKey key, long expectedRevision) {
        return new MetadataMutationPayloadCodec.Descriptor(
                MetadataMutationPayloadCodec.MutationKind.DELETE,
                key,
                OptionalLong.of(expectedRevision),
                OptionalLong.empty(),
                OptionalLong.empty());
    }

    private static MetadataKey key(String key) {
        return new MetadataKey("example.index", key);
    }

    private static void assertConflict(CheckedOperation operation) {
        MetadataStoreException conflict = assertThrows(MetadataStoreException.class, operation::run);
        assertEquals(MetadataCommitResult.FailureCategory.CONFLICT, conflict.category());
    }

    private static void assertIntegrity(CheckedOperation operation) {
        MetadataStoreException failure = assertThrows(MetadataStoreException.class, operation::run);
        assertEquals(MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE, failure.category());
    }

    @FunctionalInterface
    private interface CheckedOperation {
        void run() throws MetadataStoreException;
    }
}
