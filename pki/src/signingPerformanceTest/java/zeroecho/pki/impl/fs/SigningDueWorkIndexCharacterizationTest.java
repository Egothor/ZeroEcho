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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import zeroecho.pki.spi.store.SignWorkflowStore;

/** Explicitly opt-in identity-ordered due-page traversal characterization. */
@EnabledIfEnvironmentVariable(
        named = "ZEROECHO_SIGNING_DUE_INDEX_CHARACTERIZATION", matches = "100000")
final class SigningDueWorkIndexCharacterizationTest {
    private static final int WORK_RECORDS = 100_000;
    private static final int MAXIMUM_DUE_RECORDS = 4_096;
    private static final int DUE_RANK_BITS = Integer.numberOfTrailingZeros(MAXIMUM_DUE_RECORDS);
    private static final int[] PAGE_SIZES = { 1, 64, 1_024, MAXIMUM_DUE_RECORDS };
    private static final Instant BASE = Instant.parse("2026-01-01T00:00:00Z");
    private static final Instant NOT_DUE = BASE.plusSeconds(WORK_RECORDS);

    @Test
    void characterizesClusteredAndEvenlyScatteredDueIdentitiesWithoutLinearScan() {
        characterize("clustered", clusteredRanks());
        characterize("evenly-scattered", evenlyScatteredRanks());
    }

    private static void characterize(String distribution, int[] dueRankByIdentity) {
        SigningGenerationRegistry generations = published();
        SigningIndexCapacityBudget capacity = new SigningIndexCapacityBudget(
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES);
        try (SigningDueWorkIndex index = new SigningDueWorkIndex(
                WORK_RECORDS, capacity, generations, SigningGenerationRegistry.Owner.DUE)) {
            populate(index, dueRankByIdentity);
            for (int pageSize : PAGE_SIZES) {
                try (SigningDueWorkIndex.IdentitySelection selection = index.pageThrough(
                        BASE.plusSeconds(pageSize - 1L), Optional.empty(), Optional.empty(),
                        pageSize)) {
                    assertEquals(pageSize, selection.records().size());
                    assertTrue(selection.endReached());
                }
                long visits = index.lastIdentityPageNodesVisited();
                long visitLimit = visitLimit(pageSize);
                System.out.printf("due-index distribution=%s W=%d D=%d visits=%d limit=%d%n",
                        distribution, WORK_RECORDS, pageSize, visits, visitLimit);
                assertTrue(visits <= visitLimit,
                        () -> "identity due paging visited " + visits + " nodes for "
                                + distribution + " W=" + WORK_RECORDS + " D=" + pageSize
                                + "; characterization limit=" + visitLimit);
            }
        }
        assertEquals(0L, capacity.snapshot().reservedBytes());
    }

    private static void populate(SigningDueWorkIndex index, int[] dueRankByIdentity) {
        for (int identity = 0; identity < WORK_RECORDS; identity++) {
            SigningDueWorkIndex.CanonicalOperationId operation = index.admit(
                    "operation-%06d".formatted(identity));
            int rank = dueRankByIdentity[identity];
            Instant eligibleAt = rank < 0 ? NOT_DUE : BASE.plusSeconds(rank);
            index.update(operation, eligibleAt, SignWorkflowStore.State.INTENT,
                    pointer(identity + 1L));
        }
    }

    private static int[] clusteredRanks() {
        int[] ranks = new int[WORK_RECORDS];
        Arrays.fill(ranks, -1);
        for (int rank = 0; rank < MAXIMUM_DUE_RECORDS; rank++) {
            ranks[rank] = rank;
        }
        return ranks;
    }

    private static int[] evenlyScatteredRanks() {
        int[] ranks = new int[WORK_RECORDS];
        Arrays.fill(ranks, -1);
        for (int rank = 0; rank < MAXIMUM_DUE_RECORDS; rank++) {
            // Bit reversal keeps every tested power-of-two prefix evenly distributed.
            int reversed = Integer.reverse(rank) >>> (Integer.SIZE - DUE_RANK_BITS);
            int identity = reversed * WORK_RECORDS / MAXIMUM_DUE_RECORDS;
            ranks[identity] = rank;
        }
        return ranks;
    }

    private static long visitLimit(int dueRecords) {
        int averageGap = (WORK_RECORDS + dueRecords - 1) / dueRecords;
        return 2L * (ceilLog2(WORK_RECORDS) + dueRecords
                + (long) dueRecords * ceilLog2(averageGap));
    }

    private static int ceilLog2(int positiveValue) {
        if (positiveValue <= 1) {
            return 0;
        }
        return Integer.SIZE - Integer.numberOfLeadingZeros(positiveValue - 1);
    }

    private static SigningGenerationRegistry published() {
        SigningGenerationRegistry generations = new SigningGenerationRegistry();
        generations.create(1L);
        generations.publish(1L);
        return generations;
    }

    private static SigningMvccIndex.RecordPointer pointer(long sequence) {
        return new SigningMvccIndex.RecordPointer(1L,
                SigningWalContainerCodec.HEADER_BYTES + sequence * 64L, 64, sequence,
                SigningWalFrameCodec.RecordType.MUTATION);
    }
}
