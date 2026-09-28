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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.StagedContentStore;

/** Atomic signing-work projections sharing one canonical identity per operation. */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.AvoidDeeplyNestedIfStmts",
        "PMD.AvoidLiteralsInIfCondition", "PMD.CloseResource", "PMD.CommentRequired",
        "PMD.CompareObjectsWithEquals", "PMD.ControlStatementBraces",
        "PMD.UseTryWithResources" })
final class SigningWorkProjection implements AutoCloseable {
    /* default */ static final String STATE_NAMESPACE = "io.zeroecho.pki.signing-state";
    /* default */ static final String ENVELOPE_NAMESPACE = "io.zeroecho.pki.signing-envelope";
    private static final long COORDINATE_FIXED_BYTES = 128L;

    private final SigningDueWorkIndex due;
    private final SigningRetentionIndex retention;
    private final SigningIndexCapacityBudget capacity;
    private final StagedContentStore stagedContent;
    private final Map<String, IdentitySlot> identities = new HashMap<>();
    private long reservedIdentityBytes;

    /* default */ SigningWorkProjection(SigningDueWorkIndex due,
            SigningRetentionIndex retention, SigningDueWorkIndex owners,
            SigningIndexCapacityBudget capacity) {
        this(due, retention, owners, capacity, null);
    }

    /* default */ SigningWorkProjection(SigningDueWorkIndex due,
            SigningRetentionIndex retention, SigningDueWorkIndex owners,
            SigningIndexCapacityBudget capacity, StagedContentStore stagedContent) {
        this.due = Objects.requireNonNull(due, "due");
        this.retention = Objects.requireNonNull(retention, "retention");
        Objects.requireNonNull(owners, "owners");
        this.capacity = Objects.requireNonNull(capacity, "capacity");
        this.stagedContent = stagedContent;
    }

    /** Reserves every identity and derived structural change before WAL admission. */
    /* default */ Prepared prepare(SigningTransactionPayloadCodec.Payload payload,
            SigningMvccIndex.RecordPointer pointer) throws IOException {
        return prepare(payload, pointer, null,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /** Reserves changes while transferring one ephemeral initial due-work admission. */
    /* default */ Prepared prepare(SigningTransactionPayloadCodec.Payload payload,
            SigningMvccIndex.RecordPointer pointer,
            SigningDueWorkIndex.Admission dueAdmission) throws IOException {
        return prepare(payload, pointer, dueAdmission,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /* default */ Prepared prepare(SigningTransactionPayloadCodec.Payload payload,
            SigningMvccIndex.RecordPointer pointer,
            SigningDueWorkIndex.Admission dueAdmission,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) throws IOException {
        Objects.requireNonNull(admissionClass, "admissionClass");
        if (payload.kind() != SigningTransactionPayloadCodec.Kind.COMMIT
                && payload.kind() != SigningTransactionPayloadCodec.Kind.DIRECT_COMMIT) return new Prepared();
        List<SigningDueWorkIndex.PreparedChange> orderedChanges = new ArrayList<>();
        List<SigningRetentionIndex.PreparedChange> retentionChanges = new ArrayList<>();
        List<AdmittedIdentity> admitted = new ArrayList<>();
        List<IdentitySlot> touched = new ArrayList<>();
        Map<String, SignWorkflowStore.SchedulingPlan> scheduling =
                schedulingCoordinates(payload);
        boolean transferred = false;
        try {
            for (SigningTransactionPayloadCodec.Mutation mutation : payload.mutations()) {
                MetadataKey key = mutation.key();
                if (STATE_NAMESPACE.equals(key.namespace())) {
                    prepareRecordMutation(mutation, pointer, orderedChanges, retentionChanges,
                            admitted, touched, dueAdmission, admissionClass,
                            scheduling.get(key.key()));
                }
            }
            Prepared result = new Prepared(List.copyOf(orderedChanges),
                    List.copyOf(retentionChanges), List.copyOf(admitted), List.copyOf(touched));
            transferred = true;
            return result;
        } finally {
            if (!transferred) rollback(orderedChanges, retentionChanges, admitted);
        }
    }

    private void prepareRecordMutation(SigningTransactionPayloadCodec.Mutation mutation,
            SigningMvccIndex.RecordPointer pointer,
            List<SigningDueWorkIndex.PreparedChange> orderedChanges,
            List<SigningRetentionIndex.PreparedChange> retentionChanges,
            List<AdmittedIdentity> admitted, List<IdentitySlot> touched,
            SigningDueWorkIndex.Admission dueAdmission,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass,
            SignWorkflowStore.SchedulingPlan scheduling) {
        String operationId = mutation.key().key();
        IdentitySlot slot = identities.get(operationId);
        if (mutation.kind() == SigningTransactionPayloadCodec.MutationKind.DELETE) {
            if (slot != null) {
                if (due.contains(slot.identity)) {
                    orderedChanges.add(due.prepareRemove(slot.identity));
                }
                if (retention.contains(slot.identity)) {
                    retentionChanges.add(retention.prepareRemove(slot.identity));
                }
                touch(touched, slot);
            }
            return;
        }
        slot = admit(operationId, scheduling, admitted, admissionClass);
        touch(touched, slot);
        SignWorkflowStore.MutableState state;
        try {
            state = FsCodec.decode(FsCodec.SIGN_MUTABLE_STATE,
                    Objects.requireNonNull(mutation.contentInternal(), "content"));
        } catch (RuntimeException malformed) {
            if (retention.contains(slot.identity)) {
                retentionChanges.add(retention.prepareRemove(slot.identity));
            }
            boolean initialDue = !due.contains(slot.identity);
            if (initialDue && dueAdmission != null) {
                dueAdmission.bind(slot.identity);
                orderedChanges.add(due.prepareMalformed(dueAdmission, slot.identity, pointer,
                        slot.scheduling.certificate()));
            } else {
                orderedChanges.add(due.prepareMalformed(slot.identity, pointer, slot.scheduling.certificate()));
            }
            return;
        }
        if (!operationId.equals(state.operationId().value())) return;
        if (RecoveryBuilder.isRetained(state.state())) {
            if (due.contains(slot.identity)) orderedChanges.add(due.prepareRemove(slot.identity));
        } else {
            if (retention.contains(slot.identity)) {
                retentionChanges.add(retention.prepareRemove(slot.identity));
            }
            Instant nextEligibleAt = effectiveEligibility(state);
            boolean initialDue = !due.contains(slot.identity);
            if (initialDue && dueAdmission != null) {
                dueAdmission.bind(slot.identity);
                orderedChanges.add(due.prepareUpdate(dueAdmission, slot.identity,
                        nextEligibleAt, state.state(), pointer, slot.scheduling.forStage(state.stage())));
            } else {
                orderedChanges.add(due.prepareUpdate(slot.identity,
                        nextEligibleAt, state.state(), pointer, admissionClass,
                        slot.scheduling.forStage(state.stage())));
            }
        }
    }

    private Map<String, SignWorkflowStore.SchedulingPlan> schedulingCoordinates(
            SigningTransactionPayloadCodec.Payload payload) {
        Map<String, SignWorkflowStore.SchedulingPlan> result = new HashMap<>();
        for (SigningTransactionPayloadCodec.Mutation mutation : payload.mutations()) {
            if (!ENVELOPE_NAMESPACE.equals(mutation.key().namespace())
                    || mutation.kind() == SigningTransactionPayloadCodec.MutationKind.DELETE) {
                continue;
            }
            SignWorkflowStore.AcceptanceEnvelope envelope = decodeEnvelope(
                    Objects.requireNonNull(mutation.contentInternal(), "content"));
            requireEnvelopeIdentity(mutation.key(), envelope);
            if (result.put(mutation.key().key(), schedulingCoordinates(envelope)) != null) {
                throw new IllegalArgumentException(
                        "Signing acceptance-envelope identity is duplicated");
            }
        }
        return result;
    }

    private SignWorkflowStore.AcceptanceEnvelope decodeEnvelope(byte[] content) {
        if (stagedContent == null) {
            throw new IllegalStateException(
                    "Signing acceptance envelope requires a staged-content resolver");
        }
        return FsCodec.decode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE, content, stagedContent);
    }

    private static void requireEnvelopeIdentity(MetadataKey key,
            SignWorkflowStore.AcceptanceEnvelope envelope) {
        if (!key.key().equals(envelope.operationId().value())) {
            throw new IllegalArgumentException(
                    "Signing acceptance-envelope identity is inconsistent");
        }
    }

    private static SignWorkflowStore.SchedulingPlan schedulingCoordinates(
            SignWorkflowStore.AcceptanceEnvelope envelope) {
        return SignWorkflowStore.SchedulingPlan.from(envelope);
    }

    /** Bulk-rebuilds active state pointers from canonical metadata-key order. */
    /* default */ RecoveryStatistics recoverAll(List<RecoveredState> recoveredStates,
            Map<String, SignWorkflowStore.SchedulingPlan> schedulingByOperation) {
        Objects.requireNonNull(recoveredStates, "recoveredStates");
        if (!identities.isEmpty() || reservedIdentityBytes != 0L) {
            throw new IllegalStateException("Signing work projection recovery target is invalid");
        }
        RecoveredProjection recovered = new RecoveryBuilder(due)
                .build(recoveredStates, schedulingByOperation);
        SigningIndexCapacityBudget.Reservation reservation = capacity.reserve(recovered.identityBytes);
        try {
            due.recoverAll(recovered.dueEntries);
            identities.putAll(recovered.identities);
            reservedIdentityBytes = recovered.identityBytes;
            reservation.transfer();
        } finally {
            reservation.close();
        }
        return new RecoveryStatistics(recoveredStates.size(), recovered.dueEntries.size(),
                recovered.dueEntries.size());
    }

    /**
     * Returns the first instant at which a live state may be claimed again.
     * Active leases are authoritative even when their records sort before ready
     * work, so a leased prefix cannot consume a bounded ready page.
     */
    private static Instant effectiveEligibility(SignWorkflowStore.MutableState state) {
        Instant eligible = state.nextEligibleAt().orElse(Instant.EPOCH);
        if (state.state() == SignWorkflowStore.State.INTENT
                || state.state() == SignWorkflowStore.State.DISPATCHED
                || state.state() == SignWorkflowStore.State.CANCELLING) {
            Optional<Instant> leaseUntil = state.leaseUntil();
            if (leaseUntil.isPresent() && leaseUntil.orElseThrow().isAfter(eligible)) {
                eligible = leaseUntil.orElseThrow();
            }
        }
        return eligible;
    }


    private IdentitySlot admit(String operationId,
            SignWorkflowStore.SchedulingPlan scheduling,
            List<AdmittedIdentity> admitted,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
        IdentitySlot existing = identities.get(operationId);
        if (existing != null) {
            if (scheduling != null && !existing.scheduling.equals(scheduling)) {
                throw new IllegalArgumentException(
                        "Signing scheduling coordinates are inconsistent");
            }
            return existing;
        }
        if (scheduling == null) {
            throw new IllegalArgumentException(
                    "Accepted signing state has no scheduling coordinates");
        }
        SigningDueWorkIndex.CanonicalOperationId identity = due.admit(operationId);
        long bytes = identityResidentBytes(identity, scheduling);
        SigningIndexCapacityBudget.Reservation reservation =
                capacity.reserve(bytes, admissionClass);
        IdentitySlot slot = new IdentitySlot(identity, scheduling, bytes);
        identities.put(identity.value(), slot);
        admitted.add(new AdmittedIdentity(slot, reservation));
        return slot;
    }

    private static long identityResidentBytes(SigningDueWorkIndex.CanonicalOperationId identity,
            SignWorkflowStore.SchedulingPlan scheduling) {
        long bytes = Math.addExact(identity.sharedResidentBytes(), 64L);
        bytes = Math.addExact(bytes, coordinateBytes(scheduling.certificate()));
        if (scheduling.proof().isPresent()) { bytes = Math.addExact(bytes, coordinateBytes(scheduling.proof().orElseThrow())); }
        return bytes;
    }

    private static long coordinateBytes(SignWorkflowStore.SchedulingCoordinates coordinate) {
        return Math.addExact(COORDINATE_FIXED_BYTES, Math.addExact(coordinate.keyRef().utf8Length(),
                coordinate.fairnessAuthorityId().value().getBytes(StandardCharsets.UTF_8).length));
    }

    private static void touch(List<IdentitySlot> touched, IdentitySlot slot) {
        for (IdentitySlot value : touched) if (value == slot) return;
        touched.add(slot);
    }

    private void rollback(List<SigningDueWorkIndex.PreparedChange> orderedChanges,
            List<SigningRetentionIndex.PreparedChange> retentionChanges,
            List<AdmittedIdentity> admitted) {
        for (int index = retentionChanges.size() - 1; index >= 0; index--) {
            retentionChanges.get(index).close();
        }
        for (int index = orderedChanges.size() - 1; index >= 0; index--) {
            orderedChanges.get(index).close();
        }
        rollbackAdmissions(admitted);
    }

    private void rollbackAdmissions(List<AdmittedIdentity> admitted) {
        for (AdmittedIdentity value : admitted) {
            identities.remove(value.slot.identity.value(), value.slot);
            value.reservation.close();
        }
    }

    private void commitAdmissions(List<AdmittedIdentity> admitted) {
        for (AdmittedIdentity value : admitted) {
            value.reservation.transfer();
            value.reservation.close();
            reservedIdentityBytes = Math.addExact(reservedIdentityBytes, value.slot.bytes);
        }
    }

    private void discardUnreferenced(List<IdentitySlot> touched) {
        for (IdentitySlot slot : touched) {
            if (!due.contains(slot.identity)
                    && identities.remove(slot.identity.value(), slot)) {
                reservedIdentityBytes -= slot.bytes;
                capacity.releaseCommitted(slot.bytes);
            }
        }
    }

    /* default */ Statistics statistics() {
        return new Statistics(identities.size(), reservedIdentityBytes);
    }

    /* default */ boolean containsOperation(String operationId) {
        return identities.containsKey(Objects.requireNonNull(operationId, "operationId"));
    }

    @Override public void close() {
        if (reservedIdentityBytes > 0L) capacity.releaseCommitted(reservedIdentityBytes);
        reservedIdentityBytes = 0L;
        identities.clear();
    }

    private static final class IdentitySlot {
        private final SigningDueWorkIndex.CanonicalOperationId identity;
        private final SignWorkflowStore.SchedulingPlan scheduling;
        private final long bytes;
        private IdentitySlot(SigningDueWorkIndex.CanonicalOperationId identity,
                SignWorkflowStore.SchedulingPlan scheduling, long bytes) {
            this.identity = identity;
            this.scheduling = scheduling;
            this.bytes = bytes;
        }
    }

    private record AdmittedIdentity(IdentitySlot slot,
            SigningIndexCapacityBudget.Reservation reservation) { }

    private static final class RecoveryBuilder {
        private final SigningDueWorkIndex due;
        private final List<SigningDueWorkIndex.RecoveryEntry> dueEntries;
        private final Map<String, IdentitySlot> identities;
        private Map<String, SignWorkflowStore.SchedulingPlan> scheduling;
        private String previousOperationId;
        private long identityBytes;

        private RecoveryBuilder(SigningDueWorkIndex due) {
            this.due = due;
            this.dueEntries = new ArrayList<>();
            this.identities = new HashMap<>();
        }

        private RecoveredProjection build(List<RecoveredState> recoveredStates,
                Map<String, SignWorkflowStore.SchedulingPlan> schedulingByOperation) {
            scheduling = Objects.requireNonNull(schedulingByOperation,
                    "schedulingByOperation");
            for (RecoveredState recovered : recoveredStates) {
                add(recovered);
            }
            return new RecoveredProjection(dueEntries, identities, identityBytes);
        }

        private void add(RecoveredState recovered) {
            MetadataKey key = recovered.key();
            requireStateNamespace(key);
            String operationId = key.key();
            requireStateOrder(operationId);
            SigningDueWorkIndex.CanonicalOperationId identity = due.admit(operationId);
            SignWorkflowStore.MutableState state = decodeState(recovered.content());
            boolean malformed = state == null;
            requireStateIdentity(operationId, state);
            SignWorkflowStore.SchedulingPlan coordinates = scheduling.get(operationId);
            if (coordinates == null) {
                throw new IllegalArgumentException(
                        "Signing recovered state has no acceptance envelope");
            }
            if (!malformed && isRetained(state.state())) {
                return;
            }
            long bytes = identityResidentBytes(identity, coordinates);
            identities.put(operationId, new IdentitySlot(identity, coordinates, bytes));
            identityBytes = Math.addExact(identityBytes, bytes);
            dueEntries.add(new SigningDueWorkIndex.RecoveryEntry(identity,
                    malformed ? Instant.MIN : effectiveEligibility(state),
                    malformed ? SignWorkflowStore.State.INTENT : state.state(),
                    recovered.pointer(), malformed ? coordinates.certificate() : coordinates.forStage(state.stage()), malformed));
        }

        private void requireStateNamespace(MetadataKey key) {
            if (!STATE_NAMESPACE.equals(key.namespace())) {
                throw new IllegalArgumentException("Signing recovery state namespace is invalid");
            }
        }

        private void requireStateOrder(String operationId) {
            if (previousOperationId != null
                    && previousOperationId.compareTo(operationId) >= 0) {
                throw new IllegalArgumentException("Signing recovery state order is invalid");
            }
            previousOperationId = operationId;
        }

        private static SignWorkflowStore.MutableState decodeState(byte[] content) {
            try {
                return FsCodec.decode(FsCodec.SIGN_MUTABLE_STATE, content);
            } catch (RuntimeException malformed) {
                return null;
            }
        }

        private static void requireStateIdentity(String operationId,
                SignWorkflowStore.MutableState state) {
            if (state != null && !operationId.equals(state.operationId().value())) {
                throw new IllegalArgumentException(
                        "Signing recovered mutable-state identity is inconsistent");
            }
        }

        private static boolean isRetained(SignWorkflowStore.State state) {
            return state == SignWorkflowStore.State.RETIRED
                    || state == SignWorkflowStore.State.EXPIRED;
        }
    }

    private record RecoveredProjection(List<SigningDueWorkIndex.RecoveryEntry> dueEntries,
            Map<String, IdentitySlot> identities, long identityBytes) {
    }

    /** Prepared derived changes with idempotent rollback. */
    /* default */ final class Prepared implements AutoCloseable {
        private final List<SigningDueWorkIndex.PreparedChange> orderedChanges;
        private final List<SigningRetentionIndex.PreparedChange> retentionChanges;
        private final List<AdmittedIdentity> admitted;
        private final List<IdentitySlot> touched;
        private boolean active = true;

        private Prepared() {
            this(List.of(), List.of(), List.of(), List.of());
        }

        private Prepared(List<SigningDueWorkIndex.PreparedChange> orderedChanges,
                List<SigningRetentionIndex.PreparedChange> retentionChanges,
                List<AdmittedIdentity> admitted, List<IdentitySlot> touched) {
            this.orderedChanges = orderedChanges;
            this.retentionChanges = retentionChanges;
            this.admitted = admitted;
            this.touched = touched;
        }

        /* default */ void publish() {
            if (!active) throw new IllegalStateException("Signing work projection is closed");
            for (SigningDueWorkIndex.PreparedChange change : orderedChanges) change.publish();
            for (SigningRetentionIndex.PreparedChange change : retentionChanges) change.publish();
            commitAdmissions(admitted);
            discardUnreferenced(touched);
            active = false;
        }

        @Override public void close() {
            if (!active) return;
            active = false;
            rollback(orderedChanges, retentionChanges, admitted);
        }
    }

    /* default */ record Statistics(int identities, long reservedBytes) {
    }

    /** One state record read through the recovered MVCC pointer. */
    /* default */ record RecoveredState(MetadataKey key, byte[] content,
            SigningMvccIndex.RecordPointer pointer) {
        RecoveredState {
            Objects.requireNonNull(key, "key");
            Objects.requireNonNull(content, "content");
            Objects.requireNonNull(pointer, "pointer");
        }
    }

    /** Scalar evidence emitted by the production bulk reconstruction path. */
    /* default */ record RecoveryStatistics(long statesVisited, long activeEntriesBuilt,
            long statePointersRetained) {
    }
}
