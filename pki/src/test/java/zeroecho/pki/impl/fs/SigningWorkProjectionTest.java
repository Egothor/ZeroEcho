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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.crypto.SignatureWorkflow;

final class SigningWorkProjectionTest {
    private static final String CONTENT_ID = "123e4567-e89b-42d3-a456-426614174000";

    @Test
    void admissionSkipsOwnerProjectionAndTransfersOnlyToInitialRecordDueWork() throws Exception {
        SigningGenerationRegistry generations = publishedGenerations();
        SigningIndexCapacityBudget capacity = new SigningIndexCapacityBudget(32_768L);
        SigningDueWorkIndex due = new SigningDueWorkIndex(1, capacity, generations,
                SigningGenerationRegistry.Owner.DUE);
        SigningRetentionIndex retention = new SigningRetentionIndex(8, capacity);
        SigningDueWorkIndex owners = new SigningDueWorkIndex(8, capacity, generations,
                SigningGenerationRegistry.Owner.OWNER);
        SigningWorkProjection projection = new SigningWorkProjection(
                due, retention, owners, capacity);
        String operationId = operationId(1);
        try {
            SigningDueWorkIndex.Admission admission = due.reserveAdmission();
            SigningTransactionPayloadCodec.Payload ownerOnly = SigningTransactionPayloadCodec
                    .commitPayload(List.of(ownerMutation(operationId)));
            try (SigningWorkProjection.Prepared prepared = projection.prepare(
                    ownerOnly, pointer(1L), admission)) {
                prepared.publish();
            }
            assertThrows(IllegalStateException.class, due::reserveAdmission,
                    "owner projection must not consume the due admission");
            admission.close();

            try (SigningDueWorkIndex.Admission recordAdmission = due.reserveAdmission()) {
                SigningTransactionPayloadCodec.Payload record = SigningTransactionPayloadCodec
                        .commitPayload(List.of(recordMutation(operationId,
                                SignWorkflowStore.State.INTENT)));
                try (SigningWorkProjection.Prepared prepared = projection.prepare(
                        record, pointer(2L), recordAdmission)) {
                    prepared.publish();
                }
                recordAdmission.close();
                assertEquals(1, due.statistics().workCount());
                assertThrows(IllegalStateException.class, due::reserveAdmission);
            }
        } finally {
            projection.close();
            due.close();
            retention.close();
            owners.close();
            generations.close();
        }
        assertEquals(0L, capacity.snapshot().reservedBytes());
    }

    @Test
    void preparedProjectionRollbackReleasesConsumedAdmissionExactlyOnce() throws Exception {
        SigningGenerationRegistry generations = publishedGenerations();
        SigningIndexCapacityBudget capacity = new SigningIndexCapacityBudget(32_768L);
        SigningDueWorkIndex due = new SigningDueWorkIndex(1, capacity, generations,
                SigningGenerationRegistry.Owner.DUE);
        SigningRetentionIndex retention = new SigningRetentionIndex(8, capacity);
        SigningDueWorkIndex owners = new SigningDueWorkIndex(8, capacity, generations,
                SigningGenerationRegistry.Owner.OWNER);
        SigningWorkProjection projection = new SigningWorkProjection(
                due, retention, owners, capacity);
        try {
            SigningDueWorkIndex.Admission admission = due.reserveAdmission();
            SigningTransactionPayloadCodec.Payload record = SigningTransactionPayloadCodec
                    .commitPayload(List.of(recordMutation(operationId(2),
                            SignWorkflowStore.State.INTENT)));
            SigningWorkProjection.Prepared prepared = projection.prepare(
                    record, pointer(1L), admission);
            assertThrows(IllegalStateException.class, due::reserveAdmission);
            prepared.close();
            prepared.close();
            admission.close();
            try (SigningDueWorkIndex.Admission reused = due.reserveAdmission()) {
                assertThrows(IllegalStateException.class, due::reserveAdmission);
            }
        } finally {
            projection.close();
            due.close();
            retention.close();
            owners.close();
            generations.close();
        }
        assertEquals(0L, capacity.snapshot().reservedBytes());
    }

    @Test
    void oneCanonicalIdentityIsSharedAndEveryReservationIsReleased() throws Exception {
        SigningGenerationRegistry generations = new SigningGenerationRegistry();
        generations.create(1L);
        generations.publish(1L);
        SigningIndexCapacityBudget capacity = new SigningIndexCapacityBudget(32_768L);
        SigningDueWorkIndex due = new SigningDueWorkIndex(8, capacity, generations,
                SigningGenerationRegistry.Owner.DUE);
        SigningRetentionIndex retention = new SigningRetentionIndex(8, capacity);
        SigningDueWorkIndex owners = new SigningDueWorkIndex(8, capacity, generations,
                SigningGenerationRegistry.Owner.OWNER);
        SigningWorkProjection projection = new SigningWorkProjection(
                due, retention, owners, capacity);
        String operationId = operationId(3);
        try {
            SigningMvccIndex.RecordPointer first = pointer(1L);
            SigningTransactionPayloadCodec.Payload active = SigningTransactionPayloadCodec
                    .commitPayload(List.of(recordMutation(operationId,
                            SignWorkflowStore.State.INTENT), ownerMutation(operationId)));
            try (SigningWorkProjection.Prepared prepared = projection.prepare(active, first)) {
                prepared.publish();
            }
            assertEquals(1, due.statistics().workCount());
            assertEquals(0, retention.size());
            assertEquals(1, owners.statistics().workCount());
            long sharedBytes = 160L + operationId.length() * 2L;
            assertEquals(sharedBytes + 448L, capacity.snapshot().reservedBytes());

            SigningMvccIndex.RecordPointer second = pointer(2L);
            SigningTransactionPayloadCodec.Payload expired = SigningTransactionPayloadCodec
                    .commitPayload(List.of(recordMutation(operationId,
                            SignWorkflowStore.State.EXPIRED)));
            try (SigningWorkProjection.Prepared prepared = projection.prepare(expired, second)) {
                prepared.publish();
            }
            assertEquals(0, due.statistics().workCount());
            assertEquals(1, retention.size());
            assertEquals(1, owners.statistics().workCount());
            assertEquals(sharedBytes + 384L, capacity.snapshot().reservedBytes());

            SigningMvccIndex.RecordPointer third = pointer(3L);
            SigningTransactionPayloadCodec.Payload retired = SigningTransactionPayloadCodec
                    .commitPayload(List.of(recordMutation(operationId,
                            SignWorkflowStore.State.RETIRED)));
            try (SigningWorkProjection.Prepared prepared = projection.prepare(retired, third)) {
                prepared.publish();
            }
            assertEquals(0, due.statistics().workCount());
            assertEquals(1, retention.size());

            SigningMvccIndex.RecordPointer fourth = pointer(4L);
            SigningTransactionPayloadCodec.Payload deleted = SigningTransactionPayloadCodec
                    .commitPayload(List.of(delete(SigningWorkProjection.RECORD_NAMESPACE,
                            operationId), delete(ownerKey(operationId))));
            try (SigningWorkProjection.Prepared prepared = projection.prepare(deleted, fourth)) {
                prepared.publish();
            }
            assertEquals(0L, capacity.snapshot().reservedBytes());
        } finally {
            projection.close();
            due.close();
            retention.close();
            owners.close();
            generations.close();
        }
        assertEquals(0L, capacity.snapshot().reservedBytes());
    }

    @Test
    void recoveryRejectsLegacyOwnerKeyBeforePublishingMembership() throws Exception {
        SigningGenerationRegistry generations = publishedGenerations();
        SigningIndexCapacityBudget capacity = new SigningIndexCapacityBudget(32_768L);
        SigningDueWorkIndex due = new SigningDueWorkIndex(8, capacity, generations,
                SigningGenerationRegistry.Owner.DUE);
        SigningRetentionIndex retention = new SigningRetentionIndex(8, capacity);
        SigningDueWorkIndex owners = new SigningDueWorkIndex(8, capacity, generations,
                SigningGenerationRegistry.Owner.OWNER);
        SigningWorkProjection projection = new SigningWorkProjection(
                due, retention, owners, capacity);
        String operationId = operationId(4);
        try {
            MetadataKey legacy = new MetadataKey(
                    SigningWorkProjection.OWNER_NAMESPACE, operationId);

            assertThrows(java.io.IOException.class,
                    () -> projection.recover(legacy, new byte[] { 1 }, pointer(1L)));
            assertFalse(projection.containsOwner(operationId));
            assertEquals(0, owners.statistics().workCount());
        } finally {
            projection.close();
            due.close();
            retention.close();
            owners.close();
            generations.close();
        }
        assertEquals(0L, capacity.snapshot().reservedBytes());
    }

    private static SigningTransactionPayloadCodec.Mutation recordMutation(String operationId,
            SignWorkflowStore.State state) {
        Instant createdAt = Instant.parse("2026-01-01T00:00:00Z");
        SignWorkflowStore.Record record = new SignWorkflowStore.Record(new PkiId(operationId),
                "test", "fingerprint", new SignatureWorkflow.ConfigurationCommitment(new byte[32]),
                new Principal("test", "owner"), createdAt,
                createdAt.plusSeconds(60L), new EncodedObject(Encoding.BINARY, new byte[] { 1 }),
                state, 0L, 0L, Optional.empty(), Optional.empty(), Optional.empty(),
                Optional.empty(), 0, Optional.empty(), Optional.empty());
        return new SigningTransactionPayloadCodec.Mutation(
                SigningTransactionPayloadCodec.MutationKind.CREATE,
                new MetadataKey(SigningWorkProjection.RECORD_NAMESPACE, operationId), -1L,
                FsCodec.encode(FsCodec.SIGN_WORKFLOW_RECORD, record));
    }

    private static SigningTransactionPayloadCodec.Mutation ownerMutation(String operationId) {
        return new SigningTransactionPayloadCodec.Mutation(
                SigningTransactionPayloadCodec.MutationKind.CREATE,
                ownerKey(operationId), -1L,
                new byte[] { 1 });
    }

    private static MetadataKey ownerKey(String operationId) {
        return new MetadataKey(SigningWorkProjection.OWNER_NAMESPACE,
                CONTENT_ID + ':' + operationId);
    }

    private static SigningTransactionPayloadCodec.Mutation delete(String namespace,
            String operationId) {
        return delete(new MetadataKey(namespace, operationId));
    }

    private static SigningTransactionPayloadCodec.Mutation delete(MetadataKey key) {
        return new SigningTransactionPayloadCodec.Mutation(
                SigningTransactionPayloadCodec.MutationKind.DELETE,
                key, 1L, null);
    }

    private static String operationId(int marker) {
        return "zsign:v1:test:1767225600000:"
                + String.format(java.util.Locale.ROOT, "%032x", marker);
    }

    private static SigningMvccIndex.RecordPointer pointer(long revision) {
        return new SigningMvccIndex.RecordPointer(1L,
                SigningWalContainerCodec.HEADER_BYTES + revision * 64L, 64, revision,
                SigningWalFrameCodec.RecordType.MUTATION);
    }

    private static SigningGenerationRegistry publishedGenerations() {
        SigningGenerationRegistry generations = new SigningGenerationRegistry();
        generations.create(1L);
        generations.publish(1L);
        return generations;
    }
}
