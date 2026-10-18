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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;

final class SigningGenerationRegistryTest {

    @Test
    void currentReferencesAndSnapshotPinsBothDelayReclaim() {
        SigningGenerationRegistry registry = published(1L);
        SigningGenerationRegistry.CurrentReferences current =
                registry.acquireCurrent(SigningGenerationRegistry.Owner.MVCC,
                        List.of(1L, 1L));
        current.transfer();
        registry.supersede(1L);
        assertTrue(registry.claimReclaimable(10).isEmpty());

        SigningGenerationRegistry.SnapshotPins pins = registry.pinSnapshot(List.of(1L));
        registry.releaseCurrent(SigningGenerationRegistry.Owner.MVCC, List.of(1L, 1L));
        assertTrue(registry.claimReclaimable(10).isEmpty());
        pins.close();

        SigningGenerationRegistry.ReclaimAction action = registry.claimReclaimable(10).get(0);
        registry.reclaimCompleted(action);
        assertEquals(0, registry.statistics().registered());
        assertThrows(IllegalStateException.class, () -> registry.pinSnapshot(List.of(1L)));
    }

    @Test
    void failedClaimRequeuesAndCompletionRemovesLifetimeState() {
        SigningGenerationRegistry registry = published(2L, 1L);
        registry.supersede(2L);
        registry.supersede(1L);
        List<SigningGenerationRegistry.ReclaimAction> first = registry.claimReclaimable(1);
        assertEquals(List.of(1L), first.stream()
                .map(SigningGenerationRegistry.ReclaimAction::generationId).toList());
        registry.reclaimFailed(first.get(0));
        List<SigningGenerationRegistry.ReclaimAction> retried = registry.claimReclaimable(2);
        assertEquals(List.of(1L, 2L), retried.stream()
                .map(SigningGenerationRegistry.ReclaimAction::generationId).toList());
        registry.reclaimCompleted(retried.get(0));
        registry.reclaimCompleted(retried.get(1));
        assertEquals(0, registry.statistics().registered());
        assertEquals(0, registry.statistics().reclaimable());
    }

    @Test
    void invalidTransitionsAndAccountingFailWithoutPartialAcquisition() {
        SigningGenerationRegistry registry = published(1L);
        assertThrows(IllegalArgumentException.class,
                () -> registry.acquireCurrent(SigningGenerationRegistry.Owner.MVCC,
                        List.of(1L, -1L)));
        assertEquals(0L, registry.statistics().currentReferences());
        assertThrows(IllegalArgumentException.class,
                () -> registry.pinSnapshot(List.of(1L, 1L)));
        assertEquals(0L, registry.statistics().snapshotPins());
        assertThrows(IllegalStateException.class, () -> registry.releaseCurrent(
                SigningGenerationRegistry.Owner.MVCC, List.of(1L)));
        registry.supersede(1L);
        SigningGenerationRegistry.ReclaimAction action = registry.claimReclaimable(1).get(0);
        assertThrows(IllegalStateException.class, () -> registry.acquireCurrent(
                SigningGenerationRegistry.Owner.MVCC, List.of(1L)));
        assertThrows(IllegalStateException.class, () -> registry.pinSnapshot(List.of(1L)));
        registry.reclaimCompleted(action);
    }

    @Test
    void supersedeVersusSnapshotPinIsSerializedWithoutReclaimWhilePinned() throws Exception {
        SigningGenerationRegistry registry = published(1L);
        SigningGenerationRegistry.CurrentReferences current = registry.acquireCurrent(
                SigningGenerationRegistry.Owner.MVCC, List.of(1L));
        current.transfer();
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch pinned = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<SigningGenerationRegistry.SnapshotPins> pinFuture = executor.submit(() -> {
                start.await();
                SigningGenerationRegistry.SnapshotPins pins = registry.pinSnapshot(List.of(1L));
                pinned.countDown();
                return pins;
            });
            Future<?> supersede = executor.submit(() -> {
                start.await();
                pinned.await();
                registry.supersede(1L);
                registry.releaseCurrent(SigningGenerationRegistry.Owner.MVCC, List.of(1L));
                return null;
            });
            start.countDown();
            SigningGenerationRegistry.SnapshotPins pins = pinFuture.get();
            supersede.get();
            assertTrue(registry.claimReclaimable(1).isEmpty());
            pins.close();
            assertEquals(1, registry.claimReclaimable(1).size());
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void rollbackTokenAndCloseAreIdempotent() {
        SigningGenerationRegistry registry = published(1L);
        SigningGenerationRegistry.CurrentReferences rollback = registry.acquireCurrent(
                SigningGenerationRegistry.Owner.MVCC, List.of(1L));
        rollback.close();
        rollback.close();
        assertEquals(0L, registry.statistics().currentReferences());
        SigningGenerationRegistry.SnapshotPins pins = registry.pinSnapshot(List.of(1L));
        IllegalStateException pinned = assertThrows(IllegalStateException.class, registry::close);
        assertTrue(pinned.getMessage().contains("owner=SNAPSHOT"));
        pins.close();
        pins.close();
        registry.close();
        registry.close();
        assertEquals(0L, registry.statistics().snapshotPins());
        assertThrows(IllegalStateException.class, () -> registry.create(2L));
    }

    @Test
    void ownerBucketsRejectCrossOwnerReleaseWithoutChangingAnyBucket() {
        SigningGenerationRegistry registry = published(1L);
        SigningGenerationRegistry.CurrentReferences mvcc = registry.acquireCurrent(
                SigningGenerationRegistry.Owner.MVCC, List.of(1L, 1L));
        SigningGenerationRegistry.CurrentReferences due = registry.acquireCurrent(
                SigningGenerationRegistry.Owner.DUE, List.of(1L));
        SigningGenerationRegistry.CurrentReferences owner = registry.acquireCurrent(
                SigningGenerationRegistry.Owner.OWNER, List.of(1L));
        mvcc.transfer();
        due.transfer();
        owner.transfer();

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> registry.releaseCurrent(SigningGenerationRegistry.Owner.MVCC,
                        List.of(1L, 1L, 1L)));
        assertTrue(failure.getMessage().contains("generationId=1"));
        assertTrue(failure.getMessage().contains("owner=MVCC"));
        assertTrue(failure.getMessage().contains("requested=3"));
        assertTrue(failure.getMessage().contains("ownerAvailable=2"));
        assertTrue(failure.getMessage().contains("totalAvailable=4"));
        SigningGenerationRegistry.Snapshot snapshot = registry.statistics();
        assertEquals(2L, snapshot.mvccReferences());
        assertEquals(1L, snapshot.dueReferences());
        assertEquals(1L, snapshot.ownerReferences());
        assertEquals(4L, snapshot.currentReferences());

        registry.releaseCurrent(SigningGenerationRegistry.Owner.MVCC, List.of(1L, 1L));
        registry.releaseCurrent(SigningGenerationRegistry.Owner.DUE, List.of(1L));
        registry.releaseCurrent(SigningGenerationRegistry.Owner.OWNER, List.of(1L));
        registry.close();
    }

    @Test
    void ownerBatchReleasePrevalidatesEveryGenerationBeforeMutation() {
        SigningGenerationRegistry registry = published(1L, 2L);
        SigningGenerationRegistry.CurrentReferences references = registry.acquireCurrent(
                SigningGenerationRegistry.Owner.MVCC, List.of(1L, 2L));
        references.transfer();

        assertThrows(IllegalStateException.class, () -> registry.releaseCurrent(
                SigningGenerationRegistry.Owner.MVCC, List.of(1L, 2L, 2L)));
        assertEquals(2L, registry.statistics().mvccReferences());

        registry.releaseCurrent(SigningGenerationRegistry.Owner.MVCC, List.of(1L, 2L));
        registry.close();
    }

    @Test
    void closeRejectsTemporaryRecoveryOwnershipUntilRollbackCompletes() {
        SigningGenerationRegistry registry = published(1L);
        SigningGenerationRegistry.CurrentReferences temporary = registry.acquireCurrent(
                SigningGenerationRegistry.Owner.RECOVERY_TEMPORARY, List.of(1L));

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                registry::close);
        assertTrue(failure.getMessage().contains("owner=RECOVERY_TEMPORARY"));
        assertTrue(failure.getMessage().contains("state=PUBLISHED"));
        assertEquals(1L, registry.statistics().recoveryTemporaryReferences());

        temporary.close();
        assertEquals(0L, registry.statistics().recoveryTemporaryReferences());
        registry.close();
    }

    @Test
    void reclaimRequiresEveryOwnerBucketAndPinsToBeEmpty() {
        SigningGenerationRegistry registry = published(1L);
        SigningGenerationRegistry.CurrentReferences due = registry.acquireCurrent(
                SigningGenerationRegistry.Owner.DUE, List.of(1L));
        SigningGenerationRegistry.CurrentReferences owner = registry.acquireCurrent(
                SigningGenerationRegistry.Owner.OWNER, List.of(1L));
        due.transfer();
        owner.transfer();
        registry.supersede(1L);

        registry.releaseCurrent(SigningGenerationRegistry.Owner.DUE, List.of(1L));
        assertTrue(registry.claimReclaimable(1).isEmpty());
        registry.releaseCurrent(SigningGenerationRegistry.Owner.OWNER, List.of(1L));
        SigningGenerationRegistry.ReclaimAction action =
                registry.claimReclaimable(1).getFirst();
        registry.reclaimCompleted(action);
        registry.close();
    }

    private static SigningGenerationRegistry published(long... identities) {
        SigningGenerationRegistry registry = new SigningGenerationRegistry();
        for (long identity : identities) {
            registry.create(identity);
            registry.publish(identity);
        }
        return registry;
    }
}
