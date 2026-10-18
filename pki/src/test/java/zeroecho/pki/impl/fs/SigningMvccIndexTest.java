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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;

final class SigningMvccIndexTest {

    @Test
    void snapshotDeferralSignalsExactlyOnceAfterLastSnapshotCloses() {
        SigningGenerationRegistry generations = publishedGenerations(1L);
        try (SigningMvccIndex index = index(generations, 10, 4, 20L, 20L)) {
            index.apply(1L, List.of(upsert(key("wake", "record"), pointer(1L, 1L))));
            SigningMvccIndex.Snapshot first = index.snapshot();
            SigningMvccIndex.Snapshot second = index.snapshot();
            AtomicInteger signals = new AtomicInteger();
            index.signalWhenSnapshotsClose(signals::incrementAndGet);

            first.close();
            assertEquals(0, signals.get());
            second.close();
            second.close();
            assertEquals(1, signals.get());

            index.signalWhenSnapshotsClose(signals::incrementAndGet);
            assertEquals(2, signals.get());
        }
    }

    @Test
    void pointAndRangeReadsUseCanonicalOrderWithoutFullMapCopies() {
        SigningGenerationRegistry generations = publishedGenerations(1L);
        try (SigningMvccIndex index = index(generations, 1_000, 8, 100L, 100L)) {
            index.apply(1L, List.of(
                    upsert(key("ns.b", "z"), pointer(1L, 1L)),
                    upsert(key("ns.a", "b"), pointer(1L, 2L)),
                    upsert(key("ns.a", "a"), pointer(1L, 3L))));
            assertEquals(1L, index.lookup(key("ns.a", "a")).orElseThrow().revision());
            assertTrue(index.lookup(key("ns.a", "missing")).isEmpty());
            try (SigningMvccIndex.Snapshot snapshot = index.snapshot()) {
                List<MetadataKey> ordered = snapshot.range(
                        key("ns.a", "!"), key("ns.c", "!"), 10).stream()
                        .map(SigningMvccIndex.SnapshotRecord::key)
                        .toList();
                assertEquals(List.of(key("ns.a", "a"), key("ns.a", "b"), key("ns.b", "z")),
                        ordered);
                assertEquals(List.of(key("ns.a", "a")), snapshot.prefix("ns.a", "a", 10).stream()
                        .map(SigningMvccIndex.SnapshotRecord::key).toList());
                assertThrows(UnsupportedOperationException.class,
                        () -> snapshot.prefix("ns.a", "", 10).clear());
            }
            assertEquals(0L, index.statistics().fullMapCopies());
            assertTrue(index.statistics().canonicalKeyBytes() > 0L);
            assertTrue(index.statistics().estimatedResidentBytes() > 0L);
        }
    }

    @Test
    void overlappingSnapshotsObserveUpdateDeleteAndReinsert() {
        SigningGenerationRegistry generations = publishedGenerations(1L, 2L);
        try (SigningMvccIndex index = index(generations, 10, 4, 20L, 20L)) {
            MetadataKey key = key("example", "record");
            index.apply(1L, List.of(upsert(key, pointer(1L, 1L))));
            SigningMvccIndex.Snapshot first = index.snapshot();
            index.apply(2L, List.of(upsert(key, pointer(2L, 2L))));
            SigningMvccIndex.Snapshot second = index.snapshot();
            index.apply(3L, List.of(SigningMvccIndex.Mutation.delete(key, 3L)));
            SigningMvccIndex.Snapshot deleted = index.snapshot();
            index.apply(4L, List.of(upsert(key, pointer(2L, 4L))));

            assertEquals(1L, first.lookup(key).orElseThrow().pointer().sequence());
            assertEquals(2L, second.lookup(key).orElseThrow().pointer().sequence());
            assertTrue(deleted.lookup(key).isEmpty());
            assertEquals(4L, index.lookup(key).orElseThrow().pointer().sequence());
            assertEquals(0L, index.statistics().retainedObsoleteVersions());
            assertTrue(index.statistics().retainedOrderedNodeUpperBound() > 0L);

            second.close();
            first.close();
            deleted.close();
            deleted.close();
            assertEquals(0L, index.statistics().retainedObsoleteVersions());
            assertEquals(1, index.statistics().retainedKeys());
        }
    }

    @Test
    void allocationWatermarksReleaseAsOldestSnapshotAdvances() {
        SigningGenerationRegistry generations = publishedGenerations(1L);
        SigningIndexCapacityBudget budget = maximumBudget();
        try (SigningMvccIndex index = index(generations, budget, 10, 4, 20L)) {
            MetadataKey key = key("watermark", "record");
            index.apply(1L, List.of(upsert(key, pointer(1L, 1L))));
            SigningMvccIndex.Snapshot oldest = index.snapshot();
            index.apply(2L, List.of(upsert(key, pointer(1L, 2L))));
            SigningMvccIndex.Snapshot sameWatermarkFirst = index.snapshot();
            SigningMvccIndex.Snapshot sameWatermarkSecond = index.snapshot();
            index.apply(3L, List.of(upsert(key, pointer(1L, 3L))));
            assertEquals(2L, index.statistics().retainedOrderedNodeUpperBound());

            sameWatermarkSecond.close();
            assertEquals(2L, index.statistics().retainedOrderedNodeUpperBound());
            long beforeOldestClose = budget.snapshot().reservedBytes();
            oldest.close();
            assertEquals(1L, index.statistics().retainedOrderedNodeUpperBound());
            assertTrue(budget.snapshot().reservedBytes() < beforeOldestClose);

            sameWatermarkFirst.close();
            assertEquals(0L, index.statistics().retainedOrderedNodeUpperBound());
        }
        assertEquals(0L, budget.snapshot().reservedBytes());
    }

    @Test
    void sustainedOverlappingSnapshotsReclaimAtEveryOldestAdvance() {
        SigningGenerationRegistry generations = publishedGenerations(1L);
        SigningIndexCapacityBudget budget = maximumBudget();
        try (SigningMvccIndex index = index(generations, budget, 10, 2, 2L)) {
            MetadataKey key = key("watermark", "sustained");
            index.apply(1L, List.of(upsert(key, pointer(1L, 1L))));
            SigningMvccIndex.Snapshot oldest = index.snapshot();
            long capacityCeiling = 0L;
            for (long revision = 2L; revision <= 256L; revision++) {
                index.apply(revision, List.of(upsert(key, pointer(1L, revision))));
                SigningMvccIndex.Snapshot newer = index.snapshot();
                assertEquals(1L, index.statistics().retainedOrderedNodeUpperBound());
                long reserved = budget.snapshot().reservedBytes();
                if (capacityCeiling == 0L) {
                    capacityCeiling = reserved;
                } else {
                    assertTrue(reserved <= capacityCeiling);
                }
                oldest.close();
                assertEquals(0L, index.statistics().retainedOrderedNodeUpperBound());
                oldest = newer;
            }
            oldest.close();
            assertEquals(0L, index.statistics().retainedOrderedNodeUpperBound());
        }
        assertEquals(0L, budget.snapshot().reservedBytes());
    }

    @Test
    void currentSelectionsSeekOnceAndRespectExactPrefixBoundaries() {
        SigningGenerationRegistry generations = publishedGenerations(1L, 2L);
        try (SigningMvccIndex index = index(generations, 20, 2, 20L, 20L)) {
            MetadataKey first = key("owner", "content-a:operation-1");
            MetadataKey second = key("owner", "content-a:operation-2");
            index.apply(1L, List.of(
                    upsert(key("other", "content-a:foreign"), pointer(1L, 1L)),
                    upsert(key("owner", "content-9:before"), pointer(1L, 2L)),
                    upsert(first, pointer(1L, 3L)),
                    upsert(second, pointer(2L, 4L)),
                    upsert(key("owner", "content-aa:after"), pointer(2L, 5L))));
            MetadataSnapshot.KeyRange range = MetadataSnapshot.KeyRange.prefix(
                    "owner", "content-a:");

            try (SigningCurrentSelection selection = selectCurrentFirst(index, range)) {
                assertEquals(List.of(first), selection.records().stream()
                        .map(SigningMvccIndex.SnapshotRecord::key).toList());
                assertEquals(1L, generations.statistics().snapshotPins());
            }
            try (SigningCurrentSelection selection = selectCurrentRange(index, range)) {
                assertEquals(List.of(first, second), selection.records().stream()
                        .map(SigningMvccIndex.SnapshotRecord::key).toList());
                assertEquals(2L, generations.statistics().snapshotPins());
            }
            try (SigningCurrentSelection selection = selectCurrentRange(index,
                    MetadataSnapshot.KeyRange.prefix("owner", "missing:"))) {
                assertTrue(selection.records().isEmpty());
                assertEquals(0L, generations.statistics().snapshotPins());
            }
            assertEquals(0L, generations.statistics().snapshotPins());
        }
    }

    @Test
    void currentSelectionPinsOldGenerationThroughReplacementAndReclamation() {
        SigningGenerationRegistry generations = publishedGenerations(1L, 2L);
        try (SigningMvccIndex index = index(generations, 10, 2, 10L, 10L)) {
            MetadataKey key = key("owner", "content:operation");
            index.apply(1L, List.of(upsert(key, pointer(1L, 1L))));
            SigningCurrentSelection selection = selectCurrentFirst(index,
                    MetadataSnapshot.KeyRange.prefix("owner", "content:"));
            assertEquals(1L, selection.records().getFirst().pointer().generationId());

            index.apply(2L, List.of(upsert(key, pointer(2L, 2L))));
            generations.supersede(1L);
            assertTrue(generations.claimReclaimable(1).isEmpty());
            selection.close();
            selection.close();
            assertEquals(List.of(1L), generations.claimReclaimable(1).stream()
                    .map(SigningGenerationRegistry.ReclaimAction::generationId).toList());
            assertThrows(IllegalStateException.class, selection::records);
        }
    }

    @Test
    void failedCurrentRangeCaptureReleasesCapacityAndPins() {
        MetadataKey key = key("owner", "abc:1");
        long entryBytes = 320L + 2L * (key.namespace().length() + key.key().length());
        SigningGenerationRegistry generations = publishedGenerations(1L);
        SigningIndexCapacityBudget budget = new SigningIndexCapacityBudget(entryBytes + 128L);
        try (SigningMvccIndex index = index(generations, budget, 10, 2, 10L)) {
            index.apply(1L, List.of(upsert(key, pointer(1L, 1L))));
            long baseline = budget.snapshot().reservedBytes();
            assertThrows(IllegalStateException.class, () -> selectCurrentRange(index,
                    MetadataSnapshot.KeyRange.prefix("owner", "abc:")));
            assertEquals(baseline, budget.snapshot().reservedBytes());
            assertEquals(0L, generations.statistics().snapshotPins());
        }
        assertEquals(0L, budget.snapshot().reservedBytes());
    }

    @Test
    void versionsNeededByIntermediateSnapshotRemainVisible() {
        SigningGenerationRegistry generations = publishedGenerations(1L);
        try (SigningMvccIndex index = index(generations, 10, 4, 20L, 20L)) {
            MetadataKey key = key("example", "record");
            index.apply(1L, List.of(upsert(key, pointer(1L, 1L))));
            index.apply(2L, List.of(upsert(key, pointer(1L, 2L))));
            SigningMvccIndex.Snapshot atSecond = index.snapshot();
            index.apply(3L, List.of(upsert(key, pointer(1L, 3L))));
            index.apply(4L, List.of(upsert(key, pointer(1L, 4L))));

            assertEquals(2L, atSecond.lookup(key).orElseThrow().pointer().sequence());
            assertEquals(4L, index.lookup(key).orElseThrow().pointer().sequence());
            atSecond.close();
            assertEquals(0L, index.statistics().retainedObsoleteVersions());
        }
    }

    @Test
    void snapshotBoundsAndRevisionSpanRejectBeforeMutation() {
        SigningGenerationRegistry generations = publishedGenerations(1L);
        try (SigningMvccIndex index = index(generations, 10, 1, 2L, 10L)) {
            index.apply(1L, List.of(upsert(key("example", "a"), pointer(1L, 1L))));
            try (SigningMvccIndex.Snapshot snapshot = index.snapshot()) {
                assertThrows(IllegalStateException.class, index::snapshot);
                index.apply(2L, List.of());
                index.apply(3L, List.of());
                IllegalStateException exhausted = assertThrows(IllegalStateException.class,
                        () -> index.apply(4L, List.of()));
                assertEquals("signing index snapshot revision span is exhausted", exhausted.getMessage());
                assertEquals(3L, index.currentRevision());
            }
            index.apply(4L, List.of());
        }
    }

    @Test
    void keyCapacityIsStableAndAtomic() {
        SigningGenerationRegistry generations = publishedGenerations(1L);
        try (SigningMvccIndex index = index(generations, 2, 2, 20L, 1L)) {
            MetadataKey first = key("example", "a");
            MetadataKey second = key("example", "b");
            index.apply(1L, List.of(upsert(first, pointer(1L, 1L)),
                    upsert(second, pointer(1L, 2L))));
            assertThrows(IllegalStateException.class,
                    () -> index.apply(2L, List.of(upsert(key("example", "c"), pointer(1L, 3L)))));
            assertEquals(1L, index.currentRevision());
            try (SigningMvccIndex.Snapshot snapshot = index.snapshot()) {
                index.apply(2L, List.of(upsert(first, pointer(1L, 4L))));
                index.apply(3L, List.of(upsert(first, pointer(1L, 5L)),
                        upsert(second, pointer(1L, 6L))));
                assertEquals(3L, index.currentRevision());
                assertEquals(5L, index.lookup(first).orElseThrow().pointer().sequence());
            }
        }
    }

    @Test
    void malformedRecoveryBoundaryInputsDoNotPublish() {
        SigningGenerationRegistry generations = publishedGenerations(1L);
        try (SigningMvccIndex index = index(generations, 10, 2, 10L, 10L)) {
            MetadataKey key = key("example", "a");
            assertThrows(IllegalArgumentException.class, () -> index.apply(2L, List.of()));
            assertThrows(IllegalArgumentException.class, () -> index.apply(1L, List.of(
                    upsert(key, pointer(1L, 1L)), upsert(key, pointer(1L, 2L)))));
            assertThrows(IllegalStateException.class, () -> index.apply(1L,
                    List.of(upsert(key, pointer(9L, 1L)))));
            assertThrows(IllegalArgumentException.class, () -> index.apply(1L,
                    List.of(SigningMvccIndex.Mutation.delete(key, 1L))));
            assertEquals(0L, index.currentRevision());
            index.apply(1L, List.of(upsert(key, pointer(1L, 1L))));
            assertThrows(IllegalArgumentException.class, () -> index.apply(1L, List.of()));
            assertThrows(IllegalArgumentException.class, () -> index.apply(2L, List.of(
                    upsert(key("example", "b"), pointer(1L, 3L)),
                    upsert(key("example", "c"), pointer(1L, 2L)))));
            assertEquals(1L, index.currentRevision());
        }
    }

    @Test
    void preparedApplyPublishesResolvedSlotAndCloseRollsBackReservations() {
        SigningGenerationRegistry generations = publishedGenerations(1L);
        SigningIndexCapacityBudget budget = maximumBudget();
        try (SigningMvccIndex index = index(generations, budget, 10, 2, 10L)) {
            MetadataKey first = key("example", "first");
            SigningRecordPointerSlot slot = new SigningRecordPointerSlot();
            SigningMvccIndex.RecordPointer unresolved = new SigningMvccIndex.RecordPointer(
                    1L, 0L, 1L, SigningWalFrameCodec.RecordType.MUTATION, slot);
            long baseline = budget.snapshot().reservedBytes();
            SigningMvccIndex.PreparedApply prepared = index.prepare(1L, 0L,
                    List.of(upsert(first, unresolved)));
            assertTrue(index.lookup(first).isEmpty());
            assertTrue(budget.snapshot().reservedBytes() > baseline);
            assertThrows(IllegalStateException.class, unresolved::frameOffset);
            slot.resolve(SigningWalContainerCodec.HEADER_BYTES, 64);
            prepared.publish();
            assertEquals(SigningWalContainerCodec.HEADER_BYTES,
                    index.lookup(first).orElseThrow().pointer().frameOffset());
            prepared.close();

            MetadataKey second = key("example", "second");
            SigningRecordPointerSlot rolledBackSlot = SigningRecordPointerSlot.resolved(
                    SigningWalContainerCodec.HEADER_BYTES + 64L, 64);
            SigningMvccIndex.PreparedApply rolledBack = index.prepare(2L, 1L,
                    List.of(upsert(second, new SigningMvccIndex.RecordPointer(
                            1L, 1L, 2L, SigningWalFrameCodec.RecordType.MUTATION,
                            rolledBackSlot))));
            long reserved = budget.snapshot().reservedBytes();
            rolledBack.close();
            rolledBack.close();
            assertTrue(index.lookup(second).isEmpty());
            assertTrue(budget.snapshot().reservedBytes() < reserved);
            assertEquals(1L, index.currentRevision());
        }
        assertEquals(0L, budget.snapshot().reservedBytes());
    }

    @Test
    void queuedPreparedAppliesValidateAgainstCandidateRootAndPublishInOrder() {
        SigningGenerationRegistry generations = publishedGenerations(1L);
        try (SigningMvccIndex index = index(generations, 10, 2, 10L, 10L)) {
            MetadataKey key = key("example", "record");
            SigningMvccIndex.PreparedApply first = index.prepare(1L, 0L,
                    List.of(upsert(key, new SigningMvccIndex.RecordPointer(1L,
                            SigningWalContainerCodec.HEADER_BYTES, 64, 0L, 1L,
                            SigningWalFrameCodec.RecordType.MUTATION))));
            SigningMvccIndex.PreparedApply second = index.prepare(2L, 1L,
                    List.of(SigningMvccIndex.Mutation.delete(key, 1L)));
            assertThrows(IllegalStateException.class, second::publish);
            first.publish();
            assertTrue(index.lookup(key).isPresent());
            second.publish();
            assertTrue(index.lookup(key).isEmpty());
            assertEquals(2L, index.currentRevision());
        }
    }

    @Test
    void orderedRecoveryBaselineInstallsWithoutPerKeyRevisionReplay() {
        SigningGenerationRegistry generations = publishedGenerations(1L);
        try (SigningMvccIndex index = index(generations, 10, 2, 10L, 10L)) {
            MetadataKey first = key("example", "a");
            MetadataKey second = key("example", "b");
            index.recover(20L, 100L, List.of(
                    new SigningMvccIndex.RecoveredRecord(first, pointer(1L, 100L), 15L),
                    new SigningMvccIndex.RecoveredRecord(second, pointer(1L, 90L), 20L)));
            assertEquals(20L, index.currentRevision());
            assertEquals(100L, index.lastSequence());
            assertEquals(15L, index.lookup(first).orElseThrow().revision());
            assertEquals(2L, index.statistics().orderedNodeAllocations());
            try (SigningMvccIndex.Snapshot snapshot = index.snapshot()) {
                assertEquals(List.of(first, second), snapshot.range(
                        key("example", "!"), key("example", "z"), 10).stream()
                        .map(SigningMvccIndex.SnapshotRecord::key).toList());
            }
            assertThrows(IllegalStateException.class,
                    () -> index.recover(20L, 100L, List.of()));
        }

        try (SigningMvccIndex index = index(generations, 10, 2, 10L, 10L)) {
            assertThrows(IllegalArgumentException.class, () -> index.recover(20L, 100L, List.of(
                    new SigningMvccIndex.RecoveredRecord(
                            key("example", "b"), pointer(1L, 90L), 15L),
                    new SigningMvccIndex.RecoveredRecord(
                            key("example", "a"), pointer(1L, 100L), 20L))));
            assertEquals(0L, index.currentRevision());
            assertTrue(index.lookup(key("example", "a")).isEmpty());
        }
    }

    @Test
    void currentPointersOwnSupersededGenerationUntilReplacementOrDelete() {
        SigningGenerationRegistry generations = publishedGenerations(1L, 2L);
        SigningIndexCapacityBudget budget = maximumBudget();
        try (SigningMvccIndex index = index(generations, budget, 10, 4, 20L)) {
            MetadataKey first = key("example", "a");
            MetadataKey second = key("example", "b");
            index.apply(1L, List.of(upsert(first, pointer(1L, 1L)),
                    upsert(second, pointer(1L, 2L))));
            assertEquals(2L, generations.statistics().currentReferences());
            generations.supersede(1L);
            assertTrue(generations.claimReclaimable(10).isEmpty());
            SigningMvccIndex.Snapshot snapshot = index.snapshot();
            assertEquals(1L, generations.statistics().snapshotPins());

            index.apply(2L, List.of(upsert(first, pointer(2L, 3L))));
            assertEquals(2L, generations.statistics().currentReferences());
            index.apply(3L, List.of(SigningMvccIndex.Mutation.delete(second, 4L)));
            assertEquals(1L, generations.statistics().currentReferences());
            assertTrue(generations.claimReclaimable(10).isEmpty());
            snapshot.close();
            assertEquals(List.of(1L), generations.claimReclaimable(10).stream()
                    .map(SigningGenerationRegistry.ReclaimAction::generationId).toList());
        }
    }

    @Test
    void sharedByteBudgetRejectsBeforeEitherIndexMutates() {
        SigningGenerationRegistry generations = publishedGenerations(1L);
        SigningIndexCapacityBudget budget = new SigningIndexCapacityBudget(420L);
        try (SigningMvccIndex index = index(generations, budget, 10, 2, 10L);
                SigningDueWorkIndex due = new SigningDueWorkIndex(10, budget, generations,
                        SigningGenerationRegistry.Owner.DUE)) {
            index.apply(1L, List.of(upsert(key("example", "a"), pointer(1L, 1L))));
            long afterMetadata = budget.snapshot().reservedBytes();
            SigningDueWorkIndex.CanonicalOperationId operation = due.admit("operation-too-large");
            assertThrows(IllegalStateException.class, () -> due.update(
                    operation, java.time.Instant.EPOCH, zeroecho.pki.spi.store.SignWorkflowStore.State.INTENT,
                    pointer(1L, 2L)));
            assertEquals(0, due.statistics().workCount());
            assertEquals(afterMetadata, budget.snapshot().reservedBytes());
        }
        assertEquals(0L, budget.snapshot().reservedBytes());
    }

    @Test
    void concurrentReadersObserveOnlyWholeRevisions() throws Exception {
        SigningGenerationRegistry generations = publishedGenerations(1L);
        try (SigningMvccIndex index = index(generations, 1_000, 8, 1_000L, 1_000L)) {
            index.apply(1L, List.of(upsert(key("example", "base"), pointer(1L, 1L))));
            CountDownLatch start = new CountDownLatch(1);
            AtomicBoolean complete = new AtomicBoolean();
            ExecutorService executor = Executors.newFixedThreadPool(2);
            try {
                Future<List<Integer>> reader = executor.submit(() -> {
                    List<Integer> sizes = new ArrayList<>();
                    start.await();
                    do {
                        try (SigningMvccIndex.Snapshot snapshot = index.snapshot()) {
                            sizes.add(snapshot.prefix("example", "", 1_000).size());
                        }
                    } while (!complete.get());
                    return List.copyOf(sizes);
                });
                Future<?> writer = executor.submit(() -> {
                    start.await();
                    List<SigningMvccIndex.Mutation> mutations = new ArrayList<>();
                    for (int value = 0; value < 32; value++) {
                        mutations.add(upsert(key("example", "k-" + value), pointer(1L, value + 2L)));
                    }
                    index.apply(2L, mutations);
                    complete.set(true);
                    return null;
                });
                start.countDown();
                writer.get();
                List<Integer> observed = reader.get();
                assertFalse(observed.isEmpty());
                assertTrue(observed.stream().allMatch(size -> size == 1 || size == 33));
            } finally {
                executor.shutdownNow();
            }
        }
    }

    @Test
    void boundedScalingRetainsNoMapCopies() {
        SigningGenerationRegistry generations = publishedGenerations(1L);
        try (SigningMvccIndex index = index(generations, 20_000, 4, 20_000L, 20_000L)) {
            for (int revision = 1; revision <= 10_000; revision++) {
                index.apply(revision, List.of(upsert(
                        key("scale", String.format("k-%05d", revision)), pointer(1L, revision))));
            }
            SigningMvccIndex.Statistics statistics = index.statistics();
            assertEquals(10_000, statistics.currentKeys());
            assertEquals(0L, statistics.fullMapCopies());
            assertTrue(statistics.orderedNodeAllocations() < 1_000_000L);
            try (SigningMvccIndex.Snapshot snapshot = index.snapshot()) {
                assertEquals(10_000, snapshot.prefix("scale", "k-", 20_000).size());
            }
        }
    }

    @Test
    void relocationWatermarksReleaseAsBoundarySnapshotAdvances() {
        int count = 1_000;
        SigningGenerationRegistry generations = publishedGenerations(1L, 2L);
        SigningIndexCapacityBudget budget = new SigningIndexCapacityBudget(512L * 1024L);
        try (SigningMvccIndex index = index(generations, budget, count, 2, count + 1L)) {
            for (int revision = 1; revision <= count; revision++) {
                index.apply(revision, List.of(upsert(
                        key("capacity", String.format("k-%04d", revision)),
                        pointer(1L, revision))));
            }
            SigningMvccIndex.Snapshot boundary = index.snapshot();
            long before = budget.snapshot().reservedBytes();
            index.relocateSnapshot(boundary, 2L, boundary.checkpointDataOffset());
            assertEquals(before + count * 64L, budget.snapshot().reservedBytes());
            assertEquals(count, index.statistics().retainedOrderedNodeUpperBound());
            assertEquals(0L, index.statistics().fullMapCopies());
            SigningMvccIndex.Snapshot newer = index.snapshot();
            SigningMvccIndex.SnapshotRecord expected = newer.lookup(key("capacity", "k-0001"))
                    .orElseThrow();
            SigningMvccIndex.RecordPointer previous = expected.pointer();
            SigningMvccIndex.RecordPointer replacement = new SigningMvccIndex.RecordPointer(
                    1L, previous.frameOffset() + 4_096L, previous.frameLength(),
                    previous.sequence(), previous.revision(), previous.recordType());
            assertTrue(index.relocateIfCurrent(expected, replacement));
            long retainedAfterRelocations = index.statistics().retainedOrderedNodeUpperBound();
            assertTrue(retainedAfterRelocations > count);
            long beforeBoundaryClose = budget.snapshot().reservedBytes();
            boundary.close();
            assertEquals(retainedAfterRelocations - count,
                    index.statistics().retainedOrderedNodeUpperBound());
            assertTrue(budget.snapshot().reservedBytes() < beforeBoundaryClose);
            newer.close();
            assertEquals(0L, index.statistics().retainedOrderedNodeUpperBound());
        }
        assertEquals(0L, budget.snapshot().reservedBytes());
    }

    @Test
    void stalePreparedApplyIsAttributedBeforeItCanSpendAnotherIndexOwner() {
        String diagnosticId = "diagnostic-stale-apply-001";
        SigningGenerationRegistry generations = publishedGenerations(1L, 2L, 3L);
        SigningIndexCapacityBudget budget = maximumBudget();
        SigningMvccIndex index = index(generations, budget, 10, 2, 10L);
        SigningDueWorkIndex due = new SigningDueWorkIndex(10, budget, generations,
                SigningGenerationRegistry.Owner.DUE);
        SigningDueWorkIndex owners = new SigningDueWorkIndex(10, budget, generations,
                SigningGenerationRegistry.Owner.OWNER);
        SigningMvccIndex.Snapshot boundary = null;
        try {
            MetadataKey metadataKey = key("diagnostic", diagnosticId);
            SigningDueWorkIndex.CanonicalOperationId operation = due.admit(diagnosticId);
            SigningDueWorkIndex.CanonicalOperationId ownerOperation = owners.admit(diagnosticId);
            SigningMvccIndex.RecordPointer original = pointer(1L, 1L);
            index.apply(1L, List.of(upsert(metadataKey, original)));
            due.update(operation, java.time.Instant.EPOCH,
                    zeroecho.pki.spi.store.SignWorkflowStore.State.INTENT, original);
            owners.update(ownerOperation, java.time.Instant.EPOCH,
                    zeroecho.pki.spi.store.SignWorkflowStore.State.INTENT, original);
            boundary = index.snapshot();
            SigningMvccIndex.PreparedApply stale = index.prepare(2L, 2L,
                    List.of(upsert(metadataKey, pointer(3L, 2L))));

            index.relocateSnapshot(boundary, 2L, boundary.checkpointDataOffset());
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    stale::publish, diagnosticId);
            assertTrue(failure.getMessage().contains("generationId=1"), diagnosticId);
            assertTrue(failure.getMessage().contains("owner=MVCC"), diagnosticId);
            assertTrue(failure.getMessage().contains("ownerAvailable=0"), diagnosticId);
            SigningGenerationRegistry.Snapshot snapshot = generations.statistics();
            assertEquals(1L, snapshot.dueReferences(), diagnosticId);
            assertEquals(1L, snapshot.ownerReferences(), diagnosticId);
            assertEquals(2L, snapshot.mvccReferences(), diagnosticId);
        } finally {
            if (boundary != null) {
                boundary.close();
            }
            index.close();
            due.close();
            owners.close();
            if (generations.statistics().mvccReferences() != 0L) {
                generations.releaseCurrent(SigningGenerationRegistry.Owner.MVCC, List.of(2L));
            }
            generations.close();
        }
    }

    @Test
    void closeIsIdempotentAndInvalidatesSnapshots() {
        SigningGenerationRegistry generations = publishedGenerations(1L);
        SigningMvccIndex index = index(generations, 10, 2, 10L, 10L);
        index.apply(1L, List.of(upsert(key("example", "a"), pointer(1L, 1L))));
        SigningMvccIndex.Snapshot first = index.snapshot();
        index.apply(2L, List.of(upsert(key("example", "a"), pointer(1L, 2L))));
        SigningMvccIndex.Snapshot second = index.snapshot();
        index.close();
        index.close();
        first.close();
        second.close();
        assertThrows(IllegalStateException.class, first::revision);
        assertThrows(IllegalStateException.class, second::revision);
        assertThrows(IllegalStateException.class, () -> index.lookup(key("example", "a")));
        assertEquals(0L, generations.statistics().snapshotPins());
        assertEquals(0L, generations.statistics().currentReferences());
    }

    private static SigningMvccIndex index(SigningGenerationRegistry generations, int keys,
            int snapshots, long span, long versions) {
        return index(generations, maximumBudget(), keys, snapshots, span);
    }

    private static SigningMvccIndex index(SigningGenerationRegistry generations,
            SigningIndexCapacityBudget budget, int keys, int snapshots, long span) {
        return new SigningMvccIndex(new SigningMvccIndex.Configuration(
                keys, snapshots, span, 0L), generations, budget, maximumBudget());
    }

    private static SigningIndexCapacityBudget maximumBudget() {
        return new SigningIndexCapacityBudget(
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES);
    }

    private static SigningGenerationRegistry publishedGenerations(long... identities) {
        SigningGenerationRegistry result = new SigningGenerationRegistry();
        for (long identity : identities) {
            result.create(identity);
            result.publish(identity);
        }
        return result;
    }

    private static MetadataKey key(String namespace, String value) {
        return new MetadataKey(namespace, value);
    }

    private static SigningMvccIndex.Mutation upsert(MetadataKey key,
            SigningMvccIndex.RecordPointer pointer) {
        return SigningMvccIndex.Mutation.upsert(key, pointer);
    }

    private static SigningCurrentSelection selectCurrentFirst(
            SigningMvccIndex index, MetadataSnapshot.KeyRange range) {
        return index.selectCurrentFirst(range.namespace(),
                range.lowerInclusive().orElse("!"), range.upperExclusive());
    }

    private static SigningCurrentSelection selectCurrentRange(
            SigningMvccIndex index, MetadataSnapshot.KeyRange range) {
        return index.selectCurrentRange(range.namespace(),
                range.lowerInclusive().orElse("!"), range.upperExclusive());
    }

    private static SigningMvccIndex.RecordPointer pointer(long generation, long sequence) {
        return new SigningMvccIndex.RecordPointer(generation,
                SigningWalContainerCodec.HEADER_BYTES + sequence * 64L, 64, sequence,
                SigningWalFrameCodec.RecordType.MUTATION);
    }
}
