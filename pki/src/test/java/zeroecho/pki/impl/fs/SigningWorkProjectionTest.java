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

import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.StagedContentStore;

final class SigningWorkProjectionTest {
    @Test
    void admissionTransfersOnlyToInitialStateDueWork() throws Exception {
        SigningGenerationRegistry generations = publishedGenerations();
        SigningIndexCapacityBudget capacity = new SigningIndexCapacityBudget(32_768L);
        SigningDueWorkIndex due = new SigningDueWorkIndex(1, capacity, generations,
                SigningGenerationRegistry.Owner.DUE);
        SigningRetentionIndex retention = new SigningRetentionIndex(8, capacity);
        SigningDueWorkIndex owners = new SigningDueWorkIndex(8, capacity, generations,
                SigningGenerationRegistry.Owner.OWNER);
        SigningWorkProjection projection = new SigningWorkProjection(
                due, retention, owners, capacity, stagedContent());
        String operationId = operationId(1);
        try {
            try (SigningDueWorkIndex.Admission recordAdmission = due.reserveAdmission()) {
                SigningTransactionPayloadCodec.Payload record = acceptancePayload(
                        operationId, SignWorkflowStore.State.INTENT);
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
                due, retention, owners, capacity, stagedContent());
        try {
            SigningDueWorkIndex.Admission admission = due.reserveAdmission();
            SigningTransactionPayloadCodec.Payload record = acceptancePayload(
                    operationId(2), SignWorkflowStore.State.INTENT);
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
                due, retention, owners, capacity, stagedContent());
        String operationId = operationId(3);
        try {
            SigningMvccIndex.RecordPointer first = pointer(1L);
            SigningTransactionPayloadCodec.Payload active = acceptancePayload(
                    operationId, SignWorkflowStore.State.INTENT);
            try (SigningWorkProjection.Prepared prepared = projection.prepare(active, first)) {
                prepared.publish();
            }
            assertEquals(1, due.statistics().workCount());
            assertEquals(0, retention.size());
            assertEquals(0, owners.statistics().workCount());
            assertEquals(1, projection.statistics().identities());

            SigningMvccIndex.RecordPointer second = pointer(2L);
            SigningTransactionPayloadCodec.Payload expired = SigningTransactionPayloadCodec
                    .commitPayload(List.of(recordMutation(operationId,
                            SignWorkflowStore.State.EXPIRED)));
            try (SigningWorkProjection.Prepared prepared = projection.prepare(expired, second)) {
                prepared.publish();
            }
            assertEquals(0, due.statistics().workCount());
            assertEquals(0, retention.size());
            assertEquals(0, owners.statistics().workCount());
            assertEquals(0, projection.statistics().identities());

            SigningMvccIndex.RecordPointer third = pointer(3L);
            SigningTransactionPayloadCodec.Payload retired = SigningTransactionPayloadCodec
                    .commitPayload(List.of(recordMutation(operationId,
                            SignWorkflowStore.State.RETIRED)));
            assertThrows(IllegalArgumentException.class,
                    () -> projection.prepare(retired, third));
            assertEquals(0, due.statistics().workCount());
            assertEquals(0, retention.size());

            SigningMvccIndex.RecordPointer fourth = pointer(4L);
            SigningTransactionPayloadCodec.Payload deleted = SigningTransactionPayloadCodec
                    .commitPayload(List.of(delete(SigningWorkProjection.STATE_NAMESPACE,
                            operationId)));
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
    void bulkRecoveryRejectsForeignNamespaceBeforePublishingMembership() throws Exception {
        SigningGenerationRegistry generations = publishedGenerations();
        SigningIndexCapacityBudget capacity = new SigningIndexCapacityBudget(32_768L);
        SigningDueWorkIndex due = new SigningDueWorkIndex(8, capacity, generations,
                SigningGenerationRegistry.Owner.DUE);
        SigningRetentionIndex retention = new SigningRetentionIndex(8, capacity);
        SigningDueWorkIndex owners = new SigningDueWorkIndex(8, capacity, generations,
                SigningGenerationRegistry.Owner.OWNER);
        SigningWorkProjection projection = new SigningWorkProjection(
                due, retention, owners, capacity, stagedContent());
        String operationId = operationId(4);
        try {
            MetadataKey foreign = new MetadataKey("io.zeroecho.pki.legacy-owner", operationId);
            assertThrows(IllegalArgumentException.class,
                    () -> projection.recoverAll(List.of(
                            new SigningWorkProjection.RecoveredState(
                                    foreign, new byte[] { 1 }, pointer(1L))), Map.of()));
            assertFalse(projection.containsOperation(operationId));
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

    @Test
    void recoveryRetainsOnlyValidatedSchedulingCoordinates() throws Exception {
        String operationId = operationId(5);
        try (ProjectionFixture fixture = new ProjectionFixture()) {
            SigningWorkProjection.RecoveryStatistics statistics = fixture.projection.recoverAll(
                    List.of(recoveredState(operationId, SignWorkflowStore.State.INTENT)),
                    Map.of(operationId, new SignWorkflowStore.SchedulingPlan(schedulingCoordinates(), Optional.empty())));

            assertEquals(new SigningWorkProjection.RecoveryStatistics(1L, 1L, 1L),
                    statistics);
            try (SigningDueWorkIndex.IdentitySelection page = fixture.due.pageThrough(
                    java.time.Instant.EPOCH, Optional.empty(), Optional.empty(), 1)) {
                SigningDueWorkIndex.WorkDescriptor due = page.records().getFirst();
                assertEquals(operationId, due.operationId());
                assertEquals(new SignWorkflowStore.SchedulingCoordinates(
                        new KeyRef("projection-key"), new PkiId("projection-authority")),
                        due.scheduling());
                assertFalse(due.malformed());
            }
        }
    }

    @Test
    void recoveryRejectsMissingCoordinatesAndMismatchedStateIdentity() throws Exception {
        String operationId = operationId(7);
        String otherOperationId = operationId(8);

        try (ProjectionFixture fixture = new ProjectionFixture()) {
            assertThrows(IllegalArgumentException.class, () -> fixture.projection.recoverAll(
                    List.of(recoveredState(operationId, SignWorkflowStore.State.INTENT)),
                    Map.of()));
        }
        try (ProjectionFixture fixture = new ProjectionFixture()) {
            assertThrows(IllegalArgumentException.class, () -> fixture.projection.recoverAll(
                    List.of(new SigningWorkProjection.RecoveredState(
                            new MetadataKey(SigningWorkProjection.STATE_NAMESPACE, operationId),
                            recordMutation(otherOperationId, SignWorkflowStore.State.INTENT)
                                    .contentInternal(), pointer(1L))),
                    Map.of(operationId, new SignWorkflowStore.SchedulingPlan(schedulingCoordinates(), Optional.empty()))));
        }
    }

    @Test
    void malformedRecoveredStateStillUsesValidatedEnvelopeCoordinates() throws Exception {
        String operationId = operationId(9);
        try (ProjectionFixture fixture = new ProjectionFixture()) {
            fixture.projection.recoverAll(List.of(new SigningWorkProjection.RecoveredState(
                    new MetadataKey(SigningWorkProjection.STATE_NAMESPACE, operationId),
                    new byte[] { 1 }, pointer(1L))),
                    Map.of(operationId, new SignWorkflowStore.SchedulingPlan(schedulingCoordinates(), Optional.empty())));

            try (SigningDueWorkIndex.IdentitySelection page = fixture.due.pageThrough(
                    java.time.Instant.EPOCH, Optional.empty(), Optional.empty(), 1)) {
                SigningDueWorkIndex.WorkDescriptor due = page.records().getFirst();
                assertEquals(new SignWorkflowStore.SchedulingCoordinates(
                        new KeyRef("projection-key"), new PkiId("projection-authority")),
                        due.scheduling());
                assertEquals(true, due.malformed());
            }
        }
    }

    @Test
    void acceptanceEnvelopeCodecBytesAndVersionRemainStable() throws Exception {
        byte[] encoded = envelopeBytes(operationId(10));
        assertEquals(11, Byte.toUnsignedInt(encoded[Integer.BYTES]));
        byte[] oldVersion = encoded.clone();
        oldVersion[Integer.BYTES] = 10;
        assertThrows(IllegalStateException.class, () -> FsCodec.decode(
                FsCodec.SIGN_ACCEPTANCE_ENVELOPE, oldVersion, stagedContent()));
        assertEquals("8bcffca9b5efafccada02119530ea9a61c61b821000e573fd60a80a7f9da3164",
                HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(encoded)));
    }

    private static SigningTransactionPayloadCodec.Mutation recordMutation(String operationId,
            SignWorkflowStore.State state) {
        SignWorkflowStore.MutableState record = new SignWorkflowStore.MutableState(
                new PkiId(operationId), state, 0L, 0L, Optional.empty(), Optional.empty(),
                Optional.of(state.name()), Optional.empty(), Optional.empty(), 0,
                Optional.empty(), Optional.empty(), SignWorkflowStore.InitialAttemptPhase.NOT_APPLICABLE, zeroecho.pki.spi.store.SignWorkflowStore.Stage.SINGLE, java.util.Optional.empty());
        return new SigningTransactionPayloadCodec.Mutation(
                SigningTransactionPayloadCodec.MutationKind.CREATE,
                new MetadataKey(SigningWorkProjection.STATE_NAMESPACE, operationId), -1L,
                FsCodec.encode(FsCodec.SIGN_MUTABLE_STATE, record));
    }

    private static SigningWorkProjection.RecoveredState recoveredState(String operationId,
            SignWorkflowStore.State state) {
        return new SigningWorkProjection.RecoveredState(
                new MetadataKey(SigningWorkProjection.STATE_NAMESPACE, operationId),
                recordMutation(operationId, state).contentInternal(), pointer(1L));
    }

    private static SignWorkflowStore.SchedulingCoordinates schedulingCoordinates() {
        return new SignWorkflowStore.SchedulingCoordinates(
                new KeyRef("projection-key"), new PkiId("projection-authority"));
    }

    private static SigningTransactionPayloadCodec.Payload acceptancePayload(String operationId,
            SignWorkflowStore.State state) {
        SigningTransactionPayloadCodec.Mutation envelopeMutation =
                new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.CREATE,
                        new MetadataKey(SigningWorkProjection.ENVELOPE_NAMESPACE, operationId),
                        -1L, envelopeBytes(operationId));
        return SigningTransactionPayloadCodec.commitPayload(List.of(
                envelopeMutation, recordMutation(operationId, state)));
    }

    private static byte[] envelopeBytes(String operationId) {
        return FsCodec.encode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE,
                acceptanceEnvelope(operationId));
    }

    private static SignWorkflowStore.AcceptanceEnvelope acceptanceEnvelope(String operationId) {
        SignWorkflowStore.AcceptanceCommand command = new SignWorkflowStore.AcceptanceCommand(
                new PkiId(operationId), "test", new SigningProvider.ConfigurationCommitment(
                        new byte[SigningProvider.ConfigurationCommitment.BYTE_LENGTH]),
                new AccessContext(new Principal("SERVICE", "test"), new Purpose("TEST"),
                        Optional.empty(), Optional.empty()),
                new KeyRef("projection-key"), new PkiId("projection-authority"),
                "test", Encoding.BINARY, java.time.Instant.EPOCH,
                java.time.Instant.EPOCH.plusSeconds(60L), REFERENCE, Optional.empty(), SignWorkflowStore.Mode.NORMAL, java.util.Optional.empty());
        return SignWorkflowStore.AcceptanceEnvelope.from(command);
    }

    private static StagedContentStore stagedContent() {
        return (StagedContentStore) java.lang.reflect.Proxy.newProxyInstance(
                StagedContentStore.class.getClassLoader(),
                new Class<?>[] { StagedContentStore.class }, (proxy, method, arguments) -> {
                    if ("restoreReference".equals(method.getName())) {
                        if (!REFERENCE.storeId().equals(arguments[0])
                                || !REFERENCE.contentId().equals(arguments[1])
                                || REFERENCE.encoding() != arguments[2]
                                || REFERENCE.length() != (Long) arguments[3]
                                || !REFERENCE.sha256().equals(arguments[4])
                                || REFERENCE.lifecycle() != arguments[5]) {
                            throw new IllegalArgumentException(
                                    "Persisted content reference is inconsistent");
                        }
                        return REFERENCE;
                    }
                    if ("contentStoreId".equals(method.getName())) {
                        return REFERENCE.storeId();
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    private static final class ProjectionFixture implements AutoCloseable {
        private final SigningGenerationRegistry generations = publishedGenerations();
        private final SigningIndexCapacityBudget capacity =
                new SigningIndexCapacityBudget(32_768L);
        private final SigningDueWorkIndex due = new SigningDueWorkIndex(8, capacity,
                generations, SigningGenerationRegistry.Owner.DUE);
        private final SigningRetentionIndex retention = new SigningRetentionIndex(8, capacity);
        private final SigningDueWorkIndex owners = new SigningDueWorkIndex(8, capacity,
                generations, SigningGenerationRegistry.Owner.OWNER);
        private final SigningWorkProjection projection = new SigningWorkProjection(
                due, retention, owners, capacity, stagedContent());

        @Override public void close() {
            projection.close();
            due.close();
            retention.close();
            owners.close();
            generations.close();
            assertEquals(0L, capacity.snapshot().reservedBytes());
        }
    }

    private static final DurableContentReference REFERENCE = new DurableContentReference() {
        @Override public String storeId() { return "test-store"; }
        @Override public String contentId() { return "test-content"; }
        @Override public Encoding encoding() { return Encoding.BINARY; }
        @Override public long length() { return 0L; }
        @Override public String sha256() { return "0".repeat(64); }
        @Override public Lifecycle lifecycle() { return Lifecycle.OPERATION; }
    };

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
