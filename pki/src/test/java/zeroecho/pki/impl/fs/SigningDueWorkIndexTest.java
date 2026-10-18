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

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import zeroecho.pki.spi.store.SignWorkflowStore;

final class SigningDueWorkIndexTest {
    private static final Instant BASE = Instant.parse("2026-08-12T12:00:00Z");

    @Test
    void selectionOrdersByTimeThenCanonicalOperationIdAndHonorsCutoff() {
        try (SigningDueWorkIndex index = index(10)) {
            SigningDueWorkIndex.CanonicalOperationId second = index.admit("op-b");
            SigningDueWorkIndex.CanonicalOperationId third = index.admit("op-c");
            SigningDueWorkIndex.CanonicalOperationId first = index.admit("op-a");
            index.update(second, BASE, SignWorkflowStore.State.INTENT, pointer(2L));
            index.update(third, BASE.plusSeconds(1L), SignWorkflowStore.State.DISPATCHED, pointer(3L));
            index.update(first, BASE, SignWorkflowStore.State.CANCELLING, pointer(1L));

            try (SigningDueWorkIndex.Selection due = index.selectThrough(BASE, 10);
                    SigningDueWorkIndex.Selection one =
                            index.selectThrough(BASE.plusSeconds(5L), 1)) {
                assertEquals(List.of("op-a", "op-b"), due.records().stream()
                        .map(SigningDueWorkIndex.WorkDescriptor::operationId).toList());
                assertEquals(List.of("op-a"), one.records().stream()
                        .map(SigningDueWorkIndex.WorkDescriptor::operationId).toList());
                assertThrows(UnsupportedOperationException.class, () -> due.records().clear());
            }
        }
    }

    @Test
    void bulkRecoveryBuildsDueAndIdentityOrderWithoutIncrementalInsertion() {
        try (SigningDueWorkIndex index = index(8)) {
            List<SigningDueWorkIndex.RecoveryEntry> identityOrdered = List.of(
                    recovery(index, "op-a", BASE.plusNanos(1L), 1L),
                    recovery(index, "op-b", Instant.MIN, 2L),
                    recovery(index, "op-c", BASE, 3L),
                    recovery(index, "op-d", BASE, 4L));

            index.recoverAll(identityOrdered);

            try (SigningDueWorkIndex.Selection selection =
                    index.selectThrough(Instant.MAX, 8);
                    SigningDueWorkIndex.IdentitySelection identity = index.pageThrough(
                            Instant.MAX, Optional.empty(), Optional.empty(), 8)) {
                assertEquals(List.of("op-b", "op-c", "op-d", "op-a"),
                        selection.records().stream()
                                .map(SigningDueWorkIndex.WorkDescriptor::operationId).toList());
                assertEquals(List.of("op-a", "op-b", "op-c", "op-d"),
                        identity.records().stream()
                                .map(SigningDueWorkIndex.WorkDescriptor::operationId).toList());
            }
            assertEquals(4, index.statistics().workCount());
            assertEquals(4L, index.statistics().admittedIdentities());
        }
    }

    @Test
    void oneAdmittedIdentityIsReusedForUpdateRemoveAndRetire() {
        try (SigningDueWorkIndex index = index(10)) {
            SigningDueWorkIndex.CanonicalOperationId operation = index.admit("operation");
            index.update(operation, BASE, SignWorkflowStore.State.INTENT, pointer(1L));
            index.update(operation, BASE.plusSeconds(10L), SignWorkflowStore.State.SUCCEEDED, pointer(2L));
            assertEquals(1L, index.statistics().admittedIdentities());
            try (SigningDueWorkIndex.Selection selection =
                    index.selectThrough(BASE.plusSeconds(10L), 10)) {
                assertEquals(2L, selection.records().get(0).pointer().sequence());
            }
            SigningDueWorkIndex.CanonicalOperationId missing = index.admit("missing");
            assertFalse(index.remove(missing));
            assertTrue(index.remove(operation));
            index.update(operation, BASE, SignWorkflowStore.State.FAILED, pointer(3L));
            index.retire(operation);
            assertEquals(0, index.statistics().workCount());
        }
    }

    @Test
    void equivalentButReadmittedObjectCannotReplaceCurrentIdentity() {
        try (SigningDueWorkIndex index = index(10)) {
            SigningDueWorkIndex.CanonicalOperationId admitted = index.admit("operation");
            index.update(admitted, BASE, SignWorkflowStore.State.INTENT, pointer(1L));
            SigningDueWorkIndex.CanonicalOperationId duplicate = index.admit("operation");
            assertThrows(IllegalArgumentException.class, () -> index.update(
                    duplicate, BASE, SignWorkflowStore.State.DISPATCHED, pointer(2L)));
            assertThrows(IllegalArgumentException.class, () -> index.remove(duplicate));
            assertEquals(1, index.statistics().workCount());
        }
    }

    @Test
    void capacityRejectsNewWorkButAllowsReplacementAndRetirement() {
        try (SigningDueWorkIndex index = index(2)) {
            SigningDueWorkIndex.CanonicalOperationId first = index.admit("a");
            SigningDueWorkIndex.CanonicalOperationId second = index.admit("b");
            SigningDueWorkIndex.CanonicalOperationId third = index.admit("c");
            index.update(first, BASE, SignWorkflowStore.State.INTENT, pointer(1L));
            index.update(second, BASE, SignWorkflowStore.State.INTENT, pointer(2L));
            assertThrows(IllegalStateException.class, () -> index.update(
                    third, BASE, SignWorkflowStore.State.INTENT, pointer(3L)));
            assertFalse(index.contains(third),
                    "resident due-index rejection must publish no durable-work projection");
            index.update(first, BASE.plusSeconds(1L), SignWorkflowStore.State.DISPATCHED, pointer(4L));
            index.retire(second);
            index.update(third, BASE, SignWorkflowStore.State.INTENT, pointer(6L));
            assertEquals(2, index.statistics().workCount());
            assertTrue(index.statistics().estimatedResidentBytes() > 0L);
        }
    }

    @Test
    void admissionExhaustionCloseAndReuseAreExact() {
        try (SigningDueWorkIndex index = index(1);
                SigningDueWorkIndex.Admission first = index.reserveAdmission()) {
            assertThrows(IllegalStateException.class, index::reserveAdmission);
            first.close();
            first.close();
            try (SigningDueWorkIndex.Admission reused = index.reserveAdmission()) {
                assertThrows(IllegalStateException.class, index::reserveAdmission);
            }
        }
    }

    @Test
    void publishedAdmissionTransfersCapacityUntilRetirement() {
        try (SigningDueWorkIndex index = index(1);
                SigningDueWorkIndex.Admission admission = index.reserveAdmission()) {
            SigningDueWorkIndex.CanonicalOperationId operation = index.admit("operation");
            admission.bind(operation);
            try (SigningDueWorkIndex.PreparedChange prepared = index.prepareUpdate(
                    admission, operation, BASE, SignWorkflowStore.State.INTENT, pointer(1L))) {
                prepared.publish();
            }
            admission.close();
            assertTrue(index.contains(operation));
            assertThrows(IllegalStateException.class, index::reserveAdmission);

            index.retire(operation);
            try (SigningDueWorkIndex.Admission replacement = index.reserveAdmission()) {
                assertThrows(IllegalStateException.class, index::reserveAdmission);
            }
        }
    }

    @Test
    void preparedAdmissionRollbackReleasesItsOneShotCapacity() {
        try (SigningDueWorkIndex index = index(1)) {
            SigningDueWorkIndex.CanonicalOperationId operation = index.admit("operation");
            SigningDueWorkIndex.Admission admission = index.reserveAdmission();
            admission.bind(operation);
            try (SigningDueWorkIndex.PreparedChange ignored = index.prepareUpdate(
                    admission, operation, BASE, SignWorkflowStore.State.INTENT, pointer(1L))) {
                assertThrows(IllegalStateException.class, index::reserveAdmission);
            }
            assertFalse(index.contains(operation));
            assertThrows(IllegalStateException.class, () -> index.prepareUpdate(
                    admission, operation, BASE, SignWorkflowStore.State.INTENT, pointer(2L)));
            admission.close();
            try (SigningDueWorkIndex.Admission replacement = index.reserveAdmission()) {
                assertThrows(IllegalStateException.class, index::reserveAdmission);
            }
        }
    }

    @Test
    void unreservedPreparationCannotStealOutstandingAdmission() {
        try (SigningDueWorkIndex index = index(1);
                SigningDueWorkIndex.Admission admission = index.reserveAdmission()) {
            SigningDueWorkIndex.CanonicalOperationId reserved = index.admit("reserved");
            SigningDueWorkIndex.CanonicalOperationId unreserved = index.admit("unreserved");
            assertThrows(IllegalStateException.class, () -> index.prepareUpdate(
                    unreserved, BASE, SignWorkflowStore.State.INTENT, pointer(1L)));

            admission.bind(reserved);
            try (SigningDueWorkIndex.PreparedChange prepared = index.prepareUpdate(
                    admission, reserved, BASE, SignWorkflowStore.State.INTENT, pointer(2L))) {
                prepared.publish();
            }
            assertTrue(index.contains(reserved));
            assertFalse(index.contains(unreserved));
        }
    }

    @Test
    void admissionRejectsForeignMismatchedReboundAndConsumedUse() {
        try (SigningDueWorkIndex owner = index(2);
                SigningDueWorkIndex foreign = index(2);
                SigningDueWorkIndex.Admission admission = owner.reserveAdmission()) {
            SigningDueWorkIndex.CanonicalOperationId operation = owner.admit("operation");
            admission.bind(operation);
            assertThrows(IllegalStateException.class, () -> admission.bind(operation));
            assertThrows(IllegalArgumentException.class, () -> owner.prepareUpdate(
                    admission, owner.admit("operation"), BASE,
                    SignWorkflowStore.State.INTENT, pointer(1L)));
            assertThrows(IllegalArgumentException.class, () -> foreign.prepareUpdate(
                    admission, foreign.admit("operation"), BASE,
                    SignWorkflowStore.State.INTENT, pointer(1L)));

            try (SigningDueWorkIndex.PreparedChange prepared = owner.prepareUpdate(
                    admission, operation, BASE, SignWorkflowStore.State.INTENT, pointer(1L))) {
                prepared.close();
            }
            assertThrows(IllegalStateException.class, () -> owner.prepareUpdate(
                    admission, operation, BASE, SignWorkflowStore.State.INTENT, pointer(2L)));
        }
    }

    @Test
    void concurrentAdmissionsHaveExactlyMaximumWorkWinners() throws Exception {
        int maximum = 8;
        int contenders = 32;
        try (SigningDueWorkIndex index = index(maximum);
                ExecutorService executor = Executors.newFixedThreadPool(contenders)) {
            CountDownLatch ready = new CountDownLatch(contenders);
            CountDownLatch start = new CountDownLatch(1);
            List<Future<SigningDueWorkIndex.Admission>> futures = new ArrayList<>(contenders);
            for (int count = 0; count < contenders; count++) {
                futures.add(executor.submit(() -> {
                    ready.countDown();
                    start.await();
                    try {
                        return index.reserveAdmission();
                    } catch (IllegalStateException exhausted) {
                        return null;
                    }
                }));
            }
            ready.await();
            start.countDown();
            List<SigningDueWorkIndex.Admission> winners = new ArrayList<>();
            for (Future<SigningDueWorkIndex.Admission> future : futures) {
                SigningDueWorkIndex.Admission admission = future.get();
                if (admission != null) winners.add(admission);
            }
            assertEquals(maximum, winners.size());
            assertThrows(IllegalStateException.class, index::reserveAdmission);
            winners.forEach(SigningDueWorkIndex.Admission::close);
            try (SigningDueWorkIndex.Admission reused = index.reserveAdmission()) {
                List<SigningDueWorkIndex.Admission> remaining = new ArrayList<>();
                try {
                    for (int count = 1; count < maximum; count++) {
                        remaining.add(index.reserveAdmission());
                    }
                    assertThrows(IllegalStateException.class, index::reserveAdmission);
                } finally {
                    remaining.forEach(SigningDueWorkIndex.Admission::close);
                }
            }
        }
    }

    @Test
    void invalidBoundsCanonicalIdentifiersAndByteBudgetAreRejectedAtomically() {
        SigningIndexCapacityBudget small = new SigningIndexCapacityBudget(300L);
        assertThrows(IllegalArgumentException.class,
                () -> new SigningDueWorkIndex(0, small, published(),
                        SigningGenerationRegistry.Owner.DUE));
        try (SigningDueWorkIndex index = new SigningDueWorkIndex(10, small, published(),
                SigningGenerationRegistry.Owner.DUE)) {
            assertThrows(IllegalArgumentException.class, () -> index.admit("bad\nidentifier"));
            SigningDueWorkIndex.CanonicalOperationId first = index.admit("short");
            index.update(first, BASE, SignWorkflowStore.State.INTENT, pointer(1L));
            long before = index.statistics().estimatedResidentBytes();
            SigningDueWorkIndex.CanonicalOperationId second = index.admit("another-long-id");
            assertThrows(IllegalStateException.class, () -> index.update(
                    second, BASE, SignWorkflowStore.State.INTENT, pointer(2L)));
            assertEquals(before, index.statistics().estimatedResidentBytes());
            assertEquals(1, index.statistics().workCount());
            assertThrows(IllegalArgumentException.class, () -> index.selectThrough(BASE, 0));
        }
        assertEquals(0L, small.snapshot().reservedBytes());
    }

    @Test
    void substantialBoundedPopulationSelectsOnlyDuePrefix() {
        try (SigningDueWorkIndex index = index(20_000)) {
            for (int value = 0; value < 10_000; value++) {
                SigningDueWorkIndex.CanonicalOperationId operation =
                        index.admit("operation-" + value);
                index.update(operation, BASE.plusSeconds(value),
                        SignWorkflowStore.State.INTENT, pointer(value + 1L));
            }
            try (SigningDueWorkIndex.Selection selection =
                    index.selectThrough(BASE.plusSeconds(4_999L), 6_000)) {
                List<SigningDueWorkIndex.WorkDescriptor> due = selection.records();
                assertEquals(5_000, due.size());
                assertEquals(BASE, due.get(0).nextEligibleAt());
                assertEquals(BASE.plusSeconds(4_999L), due.get(due.size() - 1).nextEligibleAt());
            }
        }
    }

    @Test
    void identityPagePrunesNonDueSubtreesAndPreservesExclusiveContinuation() {
        try (SigningDueWorkIndex index = index(20_000)) {
            for (int value = 0; value < 10_000; value++) {
                String identity = "operation-%05d".formatted(value);
                SigningDueWorkIndex.CanonicalOperationId operation = index.admit(identity);
                Instant eligibility = value == 123 || value == 9_876
                        ? BASE : BASE.plusSeconds(3_600L);
                index.update(operation, eligibility, SignWorkflowStore.State.INTENT,
                        pointer(value + 1L));
            }
            try (SigningDueWorkIndex.IdentitySelection first = index.pageThrough(
                    BASE, Optional.empty(), Optional.empty(), 1)) {
                assertEquals(List.of("operation-00123"), first.records().stream()
                        .map(SigningDueWorkIndex.WorkDescriptor::operationId).toList());
                assertFalse(first.endReached());
                assertEquals(Optional.of("operation-09876"), first.highWatermark());
            }
            try (SigningDueWorkIndex.IdentitySelection second = index.pageThrough(
                    BASE, Optional.of("operation-00123"), Optional.of("operation-09876"), 1)) {
                assertEquals(List.of("operation-09876"), second.records().stream()
                        .map(SigningDueWorkIndex.WorkDescriptor::operationId).toList());
                assertTrue(second.endReached());
            }
            assertTrue(index.lastIdentityPageNodesVisited() < 100,
                    "augmented selection must not scan all non-due records");
        }
    }

    private static SigningDueWorkIndex index(int maximum) {
        return new SigningDueWorkIndex(maximum,
                new SigningIndexCapacityBudget(
                        FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES),
                published(), SigningGenerationRegistry.Owner.DUE);
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

    private static SigningDueWorkIndex.RecoveryEntry recovery(SigningDueWorkIndex index,
            String operationId, Instant nextEligibleAt, long sequence) {
        return new SigningDueWorkIndex.RecoveryEntry(index.admit(operationId), nextEligibleAt,
                SignWorkflowStore.State.INTENT, pointer(sequence), false);
    }
}
