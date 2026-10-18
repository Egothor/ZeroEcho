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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.SignWorkflowStore;

final class SigningMvccRelocationCandidateTest {
    private static final long SOURCE_GENERATION = 1L;
    private static final long CHECKPOINT_GENERATION = 2L;
    private static final long ACTIVE_GENERATION = 3L;

    @TempDir
    private Path temporaryDirectory;

    @Test
    void detachedBuildAndPreparedSwapChangeOnlyMvccRootOwnership() {
        SigningGenerationRegistry generations = publishedGenerations(
                SOURCE_GENERATION, CHECKPOINT_GENERATION, ACTIVE_GENERATION);
        SigningIndexCapacityBudget budget = maximumBudget();
        SigningIndexCapacityBudget transientBudget = maximumBudget();
        SigningMvccIndex index = index(generations, budget, transientBudget);
        SigningDueWorkIndex due = new SigningDueWorkIndex(10, budget, generations,
                SigningGenerationRegistry.Owner.DUE);
        SigningDueWorkIndex owners = new SigningDueWorkIndex(10, budget, generations,
                SigningGenerationRegistry.Owner.OWNER);
        SigningMvccIndex.Snapshot boundary = null;
        try {
            MetadataKey key = key("candidate", "baseline");
            SigningMvccIndex.RecordPointer original = pointer(SOURCE_GENERATION, 0L);
            index.apply(1L, 0L, List.of(SigningMvccIndex.Mutation.upsert(key, original)));
            SigningDueWorkIndex.CanonicalOperationId dueId = due.admit("candidate-due");
            SigningDueWorkIndex.CanonicalOperationId ownerId = owners.admit("candidate-owner");
            due.update(dueId, Instant.EPOCH, SignWorkflowStore.State.INTENT, original);
            owners.update(ownerId, Instant.EPOCH, SignWorkflowStore.State.INTENT, original);
            boundary = index.snapshot();
            byte[] commitment = commitment(7);

            SigningMvccRelocationCandidate candidate =
                    index.buildRelocationCandidate(boundary, CHECKPOINT_GENERATION,
                            SigningCheckpointCodec.HEADER_BYTES,
                            emptyBoundary(1L, 0L, commitment),
                            index.prepareRelocationCapacity(boundary));
            assertTrue(transientBudget.snapshot().reservedBytes() > 0L);
            assertEquals(SOURCE_GENERATION,
                    index.lookup(key).orElseThrow().pointer().generationId());
            assertEquals(CHECKPOINT_GENERATION,
                    candidate.lookup(key).orElseThrow().pointer().generationId());
            assertEquals(SigningCheckpointCodec.HEADER_BYTES + original.frameLength(),
                    candidate.checkpointEndOffset());
            SigningGenerationRegistry.Snapshot detached = generations.statistics();
            assertEquals(2L, detached.mvccReferences());
            assertEquals(1L, detached.dueReferences());
            assertEquals(1L, detached.ownerReferences());
            boundary.close();
            boundary = null;

            try (SigningMvccRelocationCandidate.PreparedRootSwap swap =
                    index.prepareRelocationSwap(
                            candidate, 1L, 0L, commitment)) {
                swap.publish();
                assertEquals(CHECKPOINT_GENERATION,
                        index.lookup(key).orElseThrow().pointer().generationId());
                assertEquals(1L, generations.statistics().dueReferences());
                assertEquals(1L, generations.statistics().ownerReferences());
            }
            assertEquals(1L, generations.statistics().mvccReferences());
            assertEquals(0L, transientBudget.snapshot().reservedBytes());
            candidate.close();
        } finally {
            if (boundary != null) {
                boundary.close();
            }
            index.close();
            due.close();
            owners.close();
            generations.close();
        }
        assertEquals(0L, budget.snapshot().reservedBytes());
        assertEquals(0L, transientBudget.snapshot().reservedBytes());
    }

    @Test
    void catchUpUsesCommittedPrefixExactlyOnceBeforeSwap() throws Exception {
        SigningGenerationRegistry generations = publishedGenerations(
                SOURCE_GENERATION, CHECKPOINT_GENERATION, ACTIVE_GENERATION);
        SigningIndexCapacityBudget budget = maximumBudget();
        SigningMvccIndex index = index(generations, budget);
        SigningMvccIndex.Snapshot boundary = null;
        try {
            MetadataKey baselineKey = key("candidate", "baseline");
            index.apply(1L, 0L, List.of(SigningMvccIndex.Mutation.upsert(
                    baselineKey, pointer(SOURCE_GENERATION, 0L))));
            boundary = index.snapshot();
            WalFixture fixture = new WalFixture();
            SigningMvccRelocationCandidate candidate =
                    index.buildRelocationCandidate(boundary, CHECKPOINT_GENERATION,
                            SigningCheckpointCodec.HEADER_BYTES,
                            fixture.descriptor(fixture.baseline, fixture.baseline),
                            index.prepareRelocationCapacity(boundary));
            WalEndpoint end = fixture.append(List.of(
                    frame(1L, 11L), frame(2L, 12L)), 3L);
            Path path = temporaryDirectory.resolve("candidate-catch-up.zew");
            Files.write(path, fixture.bytes());

            index.apply(2L, 1L, List.of(SigningMvccIndex.Mutation.upsert(
                    key("catchup", "k-1"), pointer(ACTIVE_GENERATION, 1L))));
            index.apply(3L, 2L, List.of(SigningMvccIndex.Mutation.upsert(
                    key("catchup", "k-2"), pointer(ACTIVE_GENERATION, 2L))));
            CommittedPrefixDescriptor descriptor = fixture.descriptor(
                    fixture.baseline, end);
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
                SigningCommittedPrefixReader.Result result = candidate.catchUp(
                        channel, descriptor, index.currentRevision(),
                        (frame, pointer) -> List.of(SigningMvccIndex.Mutation.upsert(
                                key("catchup", "k-" + pointer.sequence()), pointer)));
                assertEquals(2L, result.appliedFrames());
                assertTrue(result.forcedAndProjectedEndpointsEqual());
            }
            assertEquals(3L, candidate.revision());
            assertEquals(2L, candidate.lastSequence());
            assertEquals(ACTIVE_GENERATION, candidate.lookup(
                    key("catchup", "k-2")).orElseThrow().pointer().generationId());
            assertEquals(1L, candidate.appliedGroups());
            assertEquals(1L, candidate.generationReferenceCopies());
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
                assertEquals(0L, candidate.catchUp(channel,
                        fixture.descriptor(end, end),
                        index.currentRevision(), (frame, pointer) -> List.of(
                                SigningMvccIndex.Mutation.upsert(
                                        key("catchup", "duplicate"), pointer)))
                        .appliedFrames());
            }
            boundary.close();
            boundary = null;

            try (SigningMvccRelocationCandidate.PreparedRootSwap swap =
                    index.prepareRelocationSwap(
                            candidate, 3L, 2L, end.commitment())) {
                swap.publish();
            }
            assertTrue(index.lookup(key("catchup", "duplicate")).isEmpty());
            assertEquals(CHECKPOINT_GENERATION,
                    index.lookup(baselineKey).orElseThrow().pointer().generationId());
        } finally {
            if (boundary != null) {
                boundary.close();
            }
            index.close();
            generations.close();
        }
        assertEquals(0L, budget.snapshot().reservedBytes());
    }

    @Test
    void partialProjectionRetryStartsAtAcceptedCursorAndBatchesEachGroupOnce()
            throws Exception {
        SigningGenerationRegistry generations = publishedGenerations(
                SOURCE_GENERATION, CHECKPOINT_GENERATION, ACTIVE_GENERATION);
        SigningIndexCapacityBudget budget = maximumBudget();
        SigningMvccIndex index = index(generations, budget);
        SigningMvccIndex.Snapshot boundary = null;
        try {
            index.apply(1L, 0L, List.of(SigningMvccIndex.Mutation.upsert(
                    key("retry", "baseline"), pointer(SOURCE_GENERATION, 0L))));
            boundary = index.snapshot();
            WalFixture fixture = new WalFixture();
            SigningMvccRelocationCandidate candidate = index.buildRelocationCandidate(
                    boundary, CHECKPOINT_GENERATION, SigningCheckpointCodec.HEADER_BYTES,
                    fixture.descriptor(fixture.baseline, fixture.baseline),
                    index.prepareRelocationCapacity(boundary));
            WalEndpoint first = fixture.append(List.of(frame(1L, 21L)), 2L);
            WalEndpoint second = fixture.append(List.of(frame(2L, 22L)), 3L);
            Path path = temporaryDirectory.resolve("candidate-partial-retry.zew");
            Files.write(path, fixture.bytes());
            index.apply(2L, 1L, List.of(SigningMvccIndex.Mutation.upsert(
                    key("retry", "k-1"), pointer(ACTIVE_GENERATION, 1L))));
            index.apply(3L, 2L, List.of(SigningMvccIndex.Mutation.upsert(
                    key("retry", "k-2"), pointer(ACTIVE_GENERATION, 2L))));
            List<Long> applied = new ArrayList<>();
            CommittedPrefixDescriptor full = fixture.descriptor(fixture.baseline, second);
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
                SigningCommittedPrefixReader.Result partial = candidate.catchUp(
                        channel, full, 2L, (frame, pointer) -> {
                            applied.add(pointer.sequence());
                            return List.of(SigningMvccIndex.Mutation.upsert(
                                    key("retry", "k-" + pointer.sequence()), pointer));
                        });
                assertEquals(first.offset(),
                        partial.acceptedPrefix().inclusiveForcedEndOffset());
                assertFalse(partial.forcedAndProjectedEndpointsEqual());
            }
            assertThrows(IllegalArgumentException.class, () -> {
                try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
                    candidate.catchUp(channel, full, 3L, (frame, pointer) -> List.of());
                }
            });
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
                candidate.catchUp(channel, fixture.descriptor(first, second), 3L,
                        (frame, pointer) -> {
                            applied.add(pointer.sequence());
                            return List.of(SigningMvccIndex.Mutation.upsert(
                                    key("retry", "k-" + pointer.sequence()), pointer));
                        });
            }
            assertEquals(List.of(1L, 2L), applied);
            assertEquals(2L, candidate.appliedGroups());
            assertEquals(2L, candidate.generationReferenceCopies());
            candidate.close();
        } finally {
            if (boundary != null) {
                boundary.close();
            }
            index.close();
            generations.close();
        }
        assertEquals(0L, budget.snapshot().reservedBytes());
    }

    @Test
    void capacityFailurePrecedesCandidateMaterializationAndCleansOwnership() {
        SigningGenerationRegistry generations = publishedGenerations(
                SOURCE_GENERATION, CHECKPOINT_GENERATION, ACTIVE_GENERATION);
        SigningIndexCapacityBudget budget = new SigningIndexCapacityBudget(700L);
        SigningIndexCapacityBudget transientBudget = new SigningIndexCapacityBudget(319L);
        SigningMvccIndex index = index(generations, budget, transientBudget);
        SigningMvccIndex.Snapshot boundary = null;
        try {
            index.apply(1L, 0L, List.of(SigningMvccIndex.Mutation.upsert(
                    key("capacity", "baseline"), pointer(SOURCE_GENERATION, 0L))));
            boundary = index.snapshot();
            long reserved = budget.snapshot().reservedBytes();
            long highWater = budget.snapshot().highWaterReservedBytes();
            long mvcc = generations.statistics().mvccReferences();
            SigningMvccIndex.Snapshot finalBoundary = boundary;
            assertThrows(IllegalStateException.class, () -> index.buildRelocationCandidate(
                    finalBoundary, CHECKPOINT_GENERATION,
                    SigningCheckpointCodec.HEADER_BYTES,
                    emptyBoundary(1L, 0L, commitment(5)),
                    index.prepareRelocationCapacity(finalBoundary)));
            assertEquals(reserved, budget.snapshot().reservedBytes());
            assertEquals(highWater, budget.snapshot().highWaterReservedBytes());
            assertEquals(mvcc, generations.statistics().mvccReferences());
        } finally {
            if (boundary != null) {
                boundary.close();
            }
            index.close();
            generations.close();
        }
        assertEquals(0L, budget.snapshot().reservedBytes());
    }

    @Test
    void cutoverPermitReliesOnTheEngineToDrainNewPreparedApply() {
        String diagnosticId = "diagnostic-stale-apply-001";
        SigningGenerationRegistry generations = publishedGenerations(
                SOURCE_GENERATION, CHECKPOINT_GENERATION, ACTIVE_GENERATION);
        SigningIndexCapacityBudget budget = maximumBudget();
        SigningMvccIndex index = index(generations, budget);
        SigningMvccIndex.Snapshot boundary = null;
        try {
            MetadataKey key = key("diagnostic", diagnosticId);
            index.apply(1L, 0L, List.of(SigningMvccIndex.Mutation.upsert(
                    key, pointer(SOURCE_GENERATION, 0L))));
            boundary = index.snapshot();
            byte[] commitment = commitment(9);
            SigningMvccRelocationCandidate candidate =
                    index.buildRelocationCandidate(boundary, CHECKPOINT_GENERATION,
                            SigningCheckpointCodec.HEADER_BYTES,
                            emptyBoundary(1L, 0L, commitment),
                            index.prepareRelocationCapacity(boundary));
            boundary.close();
            boundary = null;
            try (SigningMvccRelocationCandidate.PreparedRootSwap swap =
                    index.prepareRelocationSwap(candidate, 1L, 0L, commitment);
                    SigningMvccIndex.PreparedApply prepared = index.prepare(2L, 1L,
                            List.of(SigningMvccIndex.Mutation.upsert(key,
                                    pointer(ACTIVE_GENERATION, 1L))))) {
                assertEquals(SOURCE_GENERATION,
                        index.lookup(key).orElseThrow().pointer().generationId(), diagnosticId);
                assertEquals(3L, generations.statistics().mvccReferences(), diagnosticId);
                assertEquals(0L, generations.statistics().dueReferences(), diagnosticId);
                assertEquals(0L, generations.statistics().ownerReferences(), diagnosticId);
            }
            assertEquals(1L, generations.statistics().mvccReferences(), diagnosticId);
            try (SigningMvccIndex.PreparedApply allowed = index.prepare(2L, 1L,
                    List.of(SigningMvccIndex.Mutation.upsert(key,
                            pointer(ACTIVE_GENERATION, 1L))))) {
                assertEquals(1L, index.currentRevision(), diagnosticId);
            }
        } finally {
            if (boundary != null) {
                boundary.close();
            }
            index.close();
            generations.close();
        }
        assertEquals(0L, budget.snapshot().reservedBytes());
    }

    @Test
    void firstSnapshotAfterRelocationAcceptsResetAllocationEpoch() {
        SigningGenerationRegistry generations = publishedGenerations(
                SOURCE_GENERATION, CHECKPOINT_GENERATION, ACTIVE_GENERATION);
        SigningIndexCapacityBudget budget = maximumBudget();
        SigningMvccIndex index = index(generations, budget);
        try {
            MetadataKey key = key("snapshot", "allocation-epoch");
            index.apply(1L, 0L, List.of(SigningMvccIndex.Mutation.upsert(
                    key, pointer(SOURCE_GENERATION, 0L))));
            try (SigningMvccIndex.Snapshot oldest = index.snapshot()) {
                index.apply(2L, 1L, List.of(SigningMvccIndex.Mutation.upsert(
                        key, pointer(ACTIVE_GENERATION, 1L))));
                try (SigningMvccIndex.Snapshot nonzeroEpoch = index.snapshot()) {
                    assertEquals(2L, nonzeroEpoch.revision());
                }
            }

            byte[] commitment = commitment(10);
            SigningMvccRelocationCandidate candidate;
            try (SigningMvccIndex.Snapshot boundary = index.snapshot()) {
                candidate = index.buildRelocationCandidate(boundary, CHECKPOINT_GENERATION,
                        SigningCheckpointCodec.HEADER_BYTES,
                        emptyBoundary(2L, 1L, commitment),
                        index.prepareRelocationCapacity(boundary));
            }
            try (SigningMvccRelocationCandidate.PreparedRootSwap swap =
                    index.prepareRelocationSwap(candidate, 2L, 1L, commitment)) {
                swap.publish();
            }

            try (SigningMvccIndex.Snapshot afterRelocation = index.snapshot()) {
                assertEquals(2L, afterRelocation.revision());
            }
        } finally {
            index.close();
            generations.close();
        }
        assertEquals(0L, budget.snapshot().reservedBytes());
    }

    @Test
    void endpointMismatchAndPreparedRollbackLeaveLiveStateUntouched() {
        SigningGenerationRegistry generations = publishedGenerations(
                SOURCE_GENERATION, CHECKPOINT_GENERATION);
        SigningIndexCapacityBudget budget = maximumBudget();
        SigningMvccIndex index = index(generations, budget);
        SigningMvccIndex.Snapshot boundary = null;
        try {
            MetadataKey key = key("candidate", "mismatch");
            index.apply(1L, 0L, List.of(SigningMvccIndex.Mutation.upsert(
                    key, pointer(SOURCE_GENERATION, 0L))));
            boundary = index.snapshot();
            byte[] commitment = commitment(3);
            SigningMvccRelocationCandidate mismatched =
                    index.buildRelocationCandidate(boundary, CHECKPOINT_GENERATION,
                            SigningCheckpointCodec.HEADER_BYTES,
                            emptyBoundary(1L, 0L, commitment),
                            index.prepareRelocationCapacity(boundary));
            assertThrows(IllegalStateException.class, () -> index.prepareRelocationSwap(
                    mismatched, 1L, 0L, commitment(4)));
            assertEquals(SOURCE_GENERATION,
                    index.lookup(key).orElseThrow().pointer().generationId());
            mismatched.close();
            assertEquals(1L, generations.statistics().mvccReferences());

            SigningMvccRelocationCandidate rolledBack =
                    index.buildRelocationCandidate(boundary, CHECKPOINT_GENERATION,
                            SigningCheckpointCodec.HEADER_BYTES,
                            emptyBoundary(1L, 0L, commitment),
                            index.prepareRelocationCapacity(boundary));
            boundary.close();
            boundary = null;
            try (SigningMvccRelocationCandidate.PreparedRootSwap ignored =
                    index.prepareRelocationSwap(
                            rolledBack, 1L, 0L, commitment)) {
                assertEquals(2L, generations.statistics().mvccReferences());
            }
            assertEquals(1L, generations.statistics().mvccReferences());
            assertThrows(IllegalStateException.class, () -> rolledBack.lookup(key));
            assertEquals(SOURCE_GENERATION,
                    index.lookup(key).orElseThrow().pointer().generationId());
        } finally {
            if (boundary != null) {
                boundary.close();
            }
            index.close();
            generations.close();
        }
        assertEquals(0L, budget.snapshot().reservedBytes());
    }

    private static SigningMvccIndex index(SigningGenerationRegistry generations,
            SigningIndexCapacityBudget budget) {
        return index(generations, budget, maximumBudget());
    }

    private static SigningMvccIndex index(SigningGenerationRegistry generations,
            SigningIndexCapacityBudget budget, SigningIndexCapacityBudget transientBudget) {
        return new SigningMvccIndex(new SigningMvccIndex.Configuration(
                32, 4, 32L, 0L), generations, budget, transientBudget);
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

    private static SigningMvccIndex.RecordPointer pointer(long generation, long sequence) {
        return new SigningMvccIndex.RecordPointer(generation,
                SigningWalContainerCodec.HEADER_BYTES + sequence * 64L,
                64, sequence, SigningWalFrameCodec.RecordType.MUTATION);
    }

    private static MetadataKey key(String namespace, String value) {
        return new MetadataKey(namespace, value);
    }

    private static byte[] commitment(int value) {
        byte[] result = new byte[SigningFormatSupport.SHA_256_BYTES];
        result[0] = (byte) value;
        return result;
    }

    private static CommittedPrefixDescriptor emptyBoundary(long revision,
            long sequence, byte[] commitment) {
        return new CommittedPrefixDescriptor(ACTIVE_GENERATION,
                SigningWalContainerCodec.HEADER_BYTES, sequence, revision, commitment,
                SigningWalContainerCodec.HEADER_BYTES, sequence, revision, commitment);
    }

    private static SigningWalFrameCodec.Frame frame(long sequence, long transaction) {
        return new SigningWalFrameCodec.Frame(SigningWalFrameCodec.RecordType.MUTATION,
                new UUID(0L, transaction), sequence, new byte[0]);
    }

    private static final class WalFixture {
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();
        private final WalEndpoint baseline;
        private WalEndpoint current;

        private WalFixture() throws IOException {
            byte[] header = SigningWalContainerCodec.encode(
                    new SigningWalContainerCodec.Header(ACTIVE_GENERATION, 1L, 1L));
            output.write(header);
            baseline = new WalEndpoint(SigningWalContainerCodec.HEADER_BYTES,
                    0L, 1L, SigningFormatSupport.sha256().digest(header));
            current = baseline;
        }

        private WalEndpoint append(List<SigningWalFrameCodec.Frame> frames,
                long committedRevision) throws IOException {
            SigningWalFrameCodec.BatchCommit commit = SigningWalFrameCodec.writeCommittedBatch(
                    Channels.newChannel(output), frames, current.revision(),
                    committedRevision, current.commitment());
            current = new WalEndpoint(output.size(), commit.endSequence(),
                    commit.committedRevision(), commit.resultingCommitment());
            return current;
        }

        private CommittedPrefixDescriptor descriptor(WalEndpoint start, WalEndpoint end) {
            return new CommittedPrefixDescriptor(ACTIVE_GENERATION,
                    start.offset(), start.sequence(), start.revision(), start.commitment(),
                    end.offset(), end.sequence(), end.revision(), end.commitment());
        }

        private byte[] bytes() {
            return output.toByteArray();
        }
    }

    private record WalEndpoint(long offset, long sequence, long revision, byte[] commitment) {
        private WalEndpoint {
            commitment = commitment.clone();
        }

        @Override
        public byte[] commitment() {
            return commitment.clone();
        }
    }
}
