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
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.SignWorkflowStore;

/** Explicitly opt-in approved-tier production projection characterization. */
@EnabledIfEnvironmentVariable(named = "ZEROECHO_SIGNING_INDEX_CAPACITY", matches = "1000000")
final class SigningIndexCapacityCharacterizationTest {
    private static final int RETAINED_RECORDS = 100_000;
    private static final int DUE_RECORDS = 50_000;
    private static final int OWNER_RECORDS = 50_000;
    private static final int GENERIC_RECORDS = SigningMvccIndex.FOUR_GIB_MAXIMUM_KEYS
            - RETAINED_RECORDS - DUE_RECORDS - OWNER_RECORDS;
    private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");
    private static final Principal OWNER = new Principal("capacity", "owner");
    private static final String OWNER_CONTENT_ID = "123e4567-e89b-42d3-a456-426614174000";

    @Test
    void characterizesApprovedTierWithProductionWorkProjection() throws Exception {
        SigningGenerationRegistry generations = new SigningGenerationRegistry();
        generations.create(1L);
        generations.publish(1L);
        SigningIndexCapacityBudget capacity = new SigningIndexCapacityBudget(
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES);
        SigningIndexCapacityBudget transientCapacity = new SigningIndexCapacityBudget(
                FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES);
        SigningMvccIndex.Configuration configuration = new SigningMvccIndex.Configuration(
                SigningMvccIndex.FOUR_GIB_MAXIMUM_KEYS, 8, 1_000_000L, 0L);
        long baselineUsedBytes = usedHeapAfterControlledGc();
        try (SigningMvccIndex index = new SigningMvccIndex(
                    configuration, generations, capacity, transientCapacity);
                SigningDueWorkIndex due = new SigningDueWorkIndex(
                        SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK, capacity, generations,
                        SigningGenerationRegistry.Owner.DUE);
                SigningRetentionIndex retention = new SigningRetentionIndex(
                        SigningDueWorkIndex.FOUR_GIB_ORDERED_LIMIT, capacity);
                SigningDueWorkIndex owners = new SigningDueWorkIndex(
                        SigningDueWorkIndex.FOUR_GIB_ORDERED_LIMIT,
                        capacity, generations, SigningGenerationRegistry.Owner.OWNER);
                SigningWorkProjection projection = new SigningWorkProjection(
                        due, retention, owners, capacity)) {
            List<SigningMvccIndex.RecoveredRecord> records = new ArrayList<>(
                    SigningMvccIndex.FOUR_GIB_MAXIMUM_KEYS);
            long sequence = addGenericRecords(records);
            sequence = addSigningRecords(records, projection, sequence,
                    RETAINED_RECORDS, "retained", SignWorkflowStore.State.RETIRED);
            sequence = addSigningRecords(records, projection, sequence,
                    DUE_RECORDS, "due", SignWorkflowStore.State.INTENT);
            sequence = addOwners(records, projection, sequence);
            assertEquals(SigningMvccIndex.FOUR_GIB_MAXIMUM_KEYS, sequence);

            index.recover(sequence, sequence, records);
            records.clear();
            long actualUsedBytes = usedHeapAfterControlledGc();
            long actualRetainedBytes = Math.max(0L, actualUsedBytes - baselineUsedBytes);
            long estimatedBytes = capacity.snapshot().reservedBytes();
            System.out.printf("production signing projection: combinedEstimated=%d "
                            + "actualRetainedHeap=%d retained=%d due=%d owners=%d%n",
                    estimatedBytes, actualRetainedBytes, retention.size(),
                    due.statistics().workCount(), owners.statistics().workCount());
            assertEquals(SigningMvccIndex.FOUR_GIB_MAXIMUM_KEYS,
                    index.statistics().currentKeys());
            assertEquals(RETAINED_RECORDS, retention.size());
            assertEquals(DUE_RECORDS, due.statistics().workCount());
            assertEquals(OWNER_RECORDS, owners.statistics().workCount());
            assertTrue(estimatedBytes <= FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES);
            assertTrue(actualRetainedBytes > 0L);
        }
        assertEquals(0L, capacity.snapshot().reservedBytes());
    }

    private static long addGenericRecords(List<SigningMvccIndex.RecoveredRecord> records) {
        long sequence = 0L;
        for (int value = 0; value < GENERIC_RECORDS; value++) {
            sequence++;
            records.add(new SigningMvccIndex.RecoveredRecord(
                    new MetadataKey("capacity", String.format("key-%07d", value)),
                    pointer(sequence), sequence));
        }
        return sequence;
    }

    private static long addSigningRecords(List<SigningMvccIndex.RecoveredRecord> records,
            SigningWorkProjection projection, long initialSequence, int count, String prefix,
            SignWorkflowStore.State state) throws Exception {
        long sequence = initialSequence;
        for (int value = 0; value < count; value++) {
            sequence++;
            String operationId = String.format("%s-%06d", prefix, value);
            MetadataKey key = new MetadataKey(SigningWorkProjection.RECORD_NAMESPACE, operationId);
            SigningMvccIndex.RecordPointer pointer = pointer(sequence);
            records.add(new SigningMvccIndex.RecoveredRecord(key, pointer, sequence));
            projection.recover(key, workflow(operationId, state), pointer);
        }
        return sequence;
    }

    private static long addOwners(List<SigningMvccIndex.RecoveredRecord> records,
            SigningWorkProjection projection, long initialSequence) throws Exception {
        long sequence = initialSequence;
        for (int value = 0; value < OWNER_RECORDS; value++) {
            sequence++;
            String operationId = String.format(java.util.Locale.ROOT,
                    "zsign:v1:capacity:1767225600000:%032x", value);
            MetadataKey key = new MetadataKey(SigningWorkProjection.OWNER_NAMESPACE,
                    OWNER_CONTENT_ID + ':' + operationId);
            SigningMvccIndex.RecordPointer pointer = pointer(sequence);
            records.add(new SigningMvccIndex.RecoveredRecord(key, pointer, sequence));
            projection.recover(key, new byte[0], pointer);
        }
        return sequence;
    }

    private static byte[] workflow(String operationId, SignWorkflowStore.State state) {
        SignWorkflowStore.Record record = new SignWorkflowStore.Record(new PkiId(operationId),
                "capacity", "fingerprint", new SignatureWorkflow.ConfigurationCommitment(
                        new byte[SignatureWorkflow.ConfigurationCommitment.BYTE_LENGTH]),
                OWNER, CREATED_AT, CREATED_AT.plusSeconds(60L),
                new EncodedObject(Encoding.BINARY, new byte[] { 1 }), state, 0L, 0L,
                Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 0,
                Optional.empty(), Optional.empty());
        return FsCodec.encode(FsCodec.SIGN_WORKFLOW_RECORD, record);
    }

    private static SigningMvccIndex.RecordPointer pointer(long sequence) {
        return new SigningMvccIndex.RecordPointer(1L,
                SigningWalContainerCodec.HEADER_BYTES + sequence * 64L, 64, sequence,
                SigningWalFrameCodec.RecordType.MUTATION);
    }

    @SuppressWarnings("PMD.DoNotCallGarbageCollectionExplicitly")
    private static long usedHeapAfterControlledGc() {
        System.gc();
        System.gc();
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }
}
