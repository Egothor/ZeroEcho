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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.HashSet;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.StagedContentStore;

/**
 * Atomic signing-work projections sharing one canonical identity per operation.
 */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.AvoidDeeplyNestedIfStmts",
        "PMD.AvoidLiteralsInIfCondition", "PMD.CloseResource", "PMD.CommentRequired",
        "PMD.CompareObjectsWithEquals", "PMD.ControlStatementBraces",
        "PMD.UseTryWithResources" })
final class SigningWorkProjection implements AutoCloseable {
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.signing-state}; persisted identities depend on this value.
     */
    /* default */ static final String STATE_NAMESPACE = "io.zeroecho.pki.signing-state";
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.signing-envelope}; persisted identities depend on this value.
     */
    /* default */ static final String ENVELOPE_NAMESPACE = "io.zeroecho.pki.signing-envelope";
    private static final long COORDINATE_FIXED_BYTES = 128L;

    private final SigningDueWorkIndex due;
    private final SigningRetentionIndex retention;
    private final SigningIndexCapacityBudget capacity;
    private final StagedContentStore stagedContent;
    private final Map<String, IdentitySlot> identities = new HashMap<>();
    private long reservedIdentityBytes;
    private final Set<String> residentOnly = new HashSet<>();

    /**
     * Creates a derived signing-work projection borrowing the due, retention, ownership, and capacity collaborators.
     *
     * @param due borrowed due-work index; must not be null
     * @param retention borrowed terminal-retention index; must not be null
     * @param owners borrowed owner-work index validated for composition; must not be null
     * @param capacity borrowed resident index workspace budget; must not be null
     * @throws NullPointerException if a required index or capacity collaborator is null
     */
    /* default */ SigningWorkProjection(SigningDueWorkIndex due,
            SigningRetentionIndex retention, SigningDueWorkIndex owners,
            SigningIndexCapacityBudget capacity) {
        this(due, retention, owners, capacity, null);
    }

    /**
     * Creates a derived signing-work projection borrowing the due, retention, ownership, and capacity collaborators.
     *
     * @param due borrowed due-work index; must not be null
     * @param retention borrowed terminal-retention index; must not be null
     * @param owners borrowed owner-work index validated for composition; must not be null
     * @param capacity borrowed resident index workspace budget; must not be null
     * @param stagedContent optional borrowed content store for exact content-ownership validation, or null
     * @throws NullPointerException if a required index or capacity collaborator is null
     */
    /* default */ SigningWorkProjection(SigningDueWorkIndex due,
            SigningRetentionIndex retention, SigningDueWorkIndex owners,
            SigningIndexCapacityBudget capacity, StagedContentStore stagedContent) {
        this.due = Objects.requireNonNull(due, "due");
        this.retention = Objects.requireNonNull(retention, "retention");
        Objects.requireNonNull(owners, "owners");
        this.capacity = Objects.requireNonNull(capacity, "capacity");
        this.stagedContent = stagedContent;
    }

    /**
     * Reserves every identity and derived structural change before WAL admission.
     * @param payload validated committed or direct-committed transaction payload
     * @param pointer exact physical pointer assigned to that mutation frame
     * @return owned prepared projection; publish or close it to roll back reservations
     * @throws IOException if stored workflow/dependency semantics cannot be decoded or validated
     * @throws NullPointerException if a required payload or admission-class input is null
     * @throws IllegalArgumentException if workflow identity, scheduling, or dependency handoff differs
     * @throws SigningIndexCapacityBudget.CapacityExceededException if projection workspace is unavailable
     */
    /* default */ Prepared prepare(SigningTransactionPayloadCodec.Payload payload,
            SigningMvccIndex.RecordPointer pointer) throws IOException {
        return prepare(payload, pointer, null,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /**
     * Reserves changes while transferring one ephemeral initial due-work admission.
     * @param payload validated committed or direct-committed transaction payload
     * @param pointer exact physical pointer assigned to that mutation frame
     * @param dueAdmission optional active admission reserved for an initial due entry, or null
     * @return owned prepared projection; publish or close it to roll back reservations
     * @throws IOException if stored workflow/dependency semantics cannot be decoded or validated
     * @throws NullPointerException if a required payload or admission-class input is null
     * @throws IllegalArgumentException if workflow identity, scheduling, or dependency handoff differs
     * @throws SigningIndexCapacityBudget.CapacityExceededException if projection workspace is unavailable
     */
    /* default */ Prepared prepare(SigningTransactionPayloadCodec.Payload payload,
            SigningMvccIndex.RecordPointer pointer,
            SigningDueWorkIndex.Admission dueAdmission) throws IOException {
        return prepare(payload, pointer, dueAdmission,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /**
     * Reserves all identity, due, retention, and dependency changes before WAL admission.
     *
     * @param payload validated committed or direct-committed transaction payload
     * @param pointer exact physical pointer assigned to that mutation frame
     * @param dueAdmission optional active admission reserved for an initial due entry, or null
     * @param admissionClass workspace admission class; must not be null
     * @return owned prepared projection; publish or close it to roll back reservations
     * @throws IOException if stored workflow/dependency semantics cannot be decoded or validated
     * @throws NullPointerException if a required payload or admission-class input is null
     * @throws IllegalArgumentException if workflow identity, scheduling, or dependency handoff differs
     * @throws SigningIndexCapacityBudget.CapacityExceededException if projection workspace is unavailable
     */
    /* default */ Prepared prepare(SigningTransactionPayloadCodec.Payload payload,
            SigningMvccIndex.RecordPointer pointer,
            SigningDueWorkIndex.Admission dueAdmission,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) throws IOException {
        return prepare(payload, pointer, dueAdmission, admissionClass,
                SigningHybridCrlDependencies.View.empty());
    }

    /**
     * Reserves all identity, due, retention, and dependency changes before WAL admission.
     *
     * @param payload validated committed or direct-committed transaction payload
     * @param pointer exact physical pointer assigned to that mutation frame
     * @param dueAdmission optional active admission reserved for an initial due entry, or null
     * @param admissionClass workspace admission class; must not be null
     * @param dependencies validated hybrid parent/child dependency view; must not be null
     * @return owned prepared projection; publish or close it to roll back reservations
     * @throws IOException if stored workflow/dependency semantics cannot be decoded or validated
     * @throws NullPointerException if a required payload or admission-class input is null
     * @throws IllegalArgumentException if workflow identity, scheduling, or dependency handoff differs
     * @throws SigningIndexCapacityBudget.CapacityExceededException if projection workspace is unavailable
     */
    /* default */ Prepared prepare(SigningTransactionPayloadCodec.Payload payload,
            SigningMvccIndex.RecordPointer pointer,
            SigningDueWorkIndex.Admission dueAdmission,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass,
            SigningHybridCrlDependencies.View dependencies) throws IOException {
        Objects.requireNonNull(admissionClass, "admissionClass");
        if (payload.kind() != SigningTransactionPayloadCodec.Kind.COMMIT
                && payload.kind() != SigningTransactionPayloadCodec.Kind.DIRECT_COMMIT) { return new Prepared(); }
        List<SigningDueWorkIndex.PreparedChange> orderedChanges = new ArrayList<>();
        List<SigningRetentionIndex.PreparedChange> retentionChanges = new ArrayList<>();
        List<AdmittedIdentity> admitted = new ArrayList<>();
        List<IdentitySlot> touched = new ArrayList<>();
        Map<String, SignWorkflowStore.SchedulingPlan> scheduling =
                schedulingCoordinates(payload);
        boolean transferred = false;
        Set<String> handoffIds = new HashSet<>();
        Map<String, Boolean> residentChanges = new HashMap<>();
        MutationPreparation preparation = new MutationPreparation(pointer, orderedChanges, retentionChanges,
                admitted, touched, dueAdmission, admissionClass, dependencies, handoffIds, residentChanges);
        try {
            for (Map.Entry<String,String> handoff : dependencies.handoffs().entrySet()) {
                String receiverId = handoff.getKey();
                String donorId = handoff.getValue();
                SigningTransactionPayloadCodec.Mutation receiverMutation = receiverMutation(payload, receiverId);
                SignWorkflowStore.MutableState state = FsCodec.decode(FsCodec.SIGN_MUTABLE_STATE, receiverMutation.contentInternal());
                IdentitySlot receiver = admit(receiverId, scheduling.get(receiverId), admitted, admissionClass);
                IdentitySlot donor = identities.get(donorId);
                if (donor == null) { throw new IllegalArgumentException("Hybrid CRL handoff has no resident donor"); }
                orderedChanges.add(due.prepareHandoff(donor.identity, receiver.identity,
                        effectiveEligibility(state), state.state(), pointer,
                        receiver.scheduling.forStage(state.stage()), admissionClass));
                touch(touched, donor); touch(touched, receiver);
                handoffIds.add(receiverId); handoffIds.add(donorId);
            }
            for (SigningTransactionPayloadCodec.Mutation mutation : payload.mutations()) {
                MetadataKey key = mutation.key();
                if (STATE_NAMESPACE.equals(key.namespace())) {
                    preparation.process(mutation, scheduling.get(key.key()));
                }
            }
            Prepared result = new Prepared(List.copyOf(orderedChanges),
                    List.copyOf(retentionChanges), List.copyOf(admitted), List.copyOf(touched), residentChanges);
            transferred = true;
            return result;
        } finally {
            if (!transferred) { rollback(orderedChanges, retentionChanges, admitted); }
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

    /**
     * Bulk-rebuilds active state pointers from canonical metadata-key order.
     * @param recoveredStates validated retained workflow states in canonical identity order
     * @param schedulingByOperation exact frozen scheduling plans indexed by operation identity
     * @return immutable state-visit and projection-entry reconstruction statistics
     * @throws NullPointerException if required recovery inputs are null
     * @throws IllegalStateException if the target projection already owns identities
     * @throws IllegalArgumentException if recovery identity, scheduling, or dependency evidence is inconsistent
     * @throws SigningIndexCapacityBudget.CapacityExceededException if recovery workspace is unavailable
     */
    /* default */ RecoveryStatistics recoverAll(List<RecoveredState> recoveredStates,
            Map<String, SignWorkflowStore.SchedulingPlan> schedulingByOperation) {
        return recoverAll(recoveredStates, schedulingByOperation, SigningHybridCrlDependencies.View.empty());
    }

    /**
     * Bulk-rebuilds derived work projections from validated canonical state and scheduling evidence.
     *
     * @param recoveredStates validated retained workflow states in canonical identity order
     * @param schedulingByOperation exact frozen scheduling plans indexed by operation identity
     * @param dependencies validated recovered hybrid dependency view
     * @return immutable state-visit and projection-entry reconstruction statistics
     * @throws NullPointerException if required recovery inputs are null
     * @throws IllegalStateException if the target projection already owns identities
     * @throws IllegalArgumentException if recovery identity, scheduling, or dependency evidence is inconsistent
     * @throws SigningIndexCapacityBudget.CapacityExceededException if recovery workspace is unavailable
     */
    /* default */ RecoveryStatistics recoverAll(List<RecoveredState> recoveredStates,
            Map<String, SignWorkflowStore.SchedulingPlan> schedulingByOperation,
            SigningHybridCrlDependencies.View dependencies) {
        Objects.requireNonNull(recoveredStates, "recoveredStates");
        if (!identities.isEmpty() || reservedIdentityBytes != 0L) {
            throw new IllegalStateException("Signing work projection recovery target is invalid");
        }
        RecoveredProjection recovered = new RecoveryBuilder(due)
                .build(recoveredStates, schedulingByOperation, dependencies);
        SigningIndexCapacityBudget.Reservation reservation = capacity.reserve(recovered.identityBytes);
        try {
            due.recoverAll(recovered.dueEntries);
            identities.putAll(recovered.identities);
            reservedIdentityBytes = recovered.identityBytes;
            for (String id : dependencies.suppressed()) if (identities.containsKey(id)) { residentOnly.add(id); }
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

    /**
     * Measures shared canonical identity and all primary/alternative proof scheduling coordinates.
     *
     * @param identity reused canonical operation identity
     * @param scheduling exact immutable operation scheduling plan
     * @return tracked resident identity and scheduling reservation in bytes
     * @throws NullPointerException if identity or scheduling is null
     * @throws ArithmeticException if tracked byte arithmetic overflows
     */
    /* default */ static long identityResidentBytes(SigningDueWorkIndex.CanonicalOperationId identity,
            SignWorkflowStore.SchedulingPlan scheduling) {
        long bytes = Math.addExact(identity.sharedResidentBytes(), 64L);
        bytes = Math.addExact(bytes, coordinateBytes(scheduling.certificate()));
        if (scheduling.proof().isPresent()) { bytes = Math.addExact(bytes, coordinateBytes(scheduling.proof().orElseThrow())); }
        if (scheduling.alternativeProof().isPresent()) { bytes = Math.addExact(bytes, coordinateBytes(scheduling.alternativeProof().orElseThrow())); }
        return bytes;
    }

    private static long coordinateBytes(SignWorkflowStore.SchedulingCoordinates coordinate) {
        return Math.addExact(COORDINATE_FIXED_BYTES, Math.addExact(coordinate.keyRef().utf8Length(),
                coordinate.fairnessAuthorityId().value().getBytes(StandardCharsets.UTF_8).length));
    }

    private static void touch(List<IdentitySlot> touched, IdentitySlot slot) {
        for (IdentitySlot value : touched) if (value == slot) { return; }
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
            if (!due.contains(slot.identity) && !residentOnly.contains(slot.identity.value())
                    && identities.remove(slot.identity.value(), slot)) {
                reservedIdentityBytes -= slot.bytes;
                capacity.releaseCommitted(slot.bytes);
            }
        }
    }

    /**
     * Returns current identity counts and tracked shared reservation bytes.
     *
     * @return immutable projection identity cardinality and byte reservation statistics
     */
    /* default */ Statistics statistics() {
        return new Statistics(identities.size(), reservedIdentityBytes);
    }

    /**
     * Tests whether the projection retains the exact operation identity.
     *
     * @param operationId logical operation identity; must not be null
     * @return true when its shared identity slot remains retained
     * @throws NullPointerException if operationId is null
     */
    /* default */ boolean containsOperation(String operationId) {
        return identities.containsKey(Objects.requireNonNull(operationId, "operationId"));
    }

    /**
     * Releases committed shared-identity workspace and clears this projection's retained identity maps.
     *
     * <p>The due and retention indexes, staged-content store, and capacity budget are
     * borrowed and remain open. Repeated cleanup of the emptied projection is a no-op;
     * separately owned prepared changes retain their own rollback obligations.</p>
     */
    @Override public void close() {
        if (reservedIdentityBytes > 0L) { capacity.releaseCommitted(reservedIdentityBytes); }
        reservedIdentityBytes = 0L;
        identities.clear();
        residentOnly.clear();
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
        private SigningHybridCrlDependencies.View dependencies;
        private long identityBytes;

        private RecoveryBuilder(SigningDueWorkIndex due) {
            this.due = due;
            this.dueEntries = new ArrayList<>();
            this.identities = new HashMap<>();
        }

        private RecoveredProjection build(List<RecoveredState> recoveredStates,
                Map<String, SignWorkflowStore.SchedulingPlan> schedulingByOperation,
                SigningHybridCrlDependencies.View dependencies) {
            this.dependencies = dependencies;
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
            if (dependencies.suppressed().contains(operationId)) { return; }
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

    /**
     * Prepared derived changes with idempotent rollback.
     */
    /* default */ final class Prepared implements AutoCloseable {
        private final List<SigningDueWorkIndex.PreparedChange> orderedChanges;
        private final List<SigningRetentionIndex.PreparedChange> retentionChanges;
        private final List<AdmittedIdentity> admitted;
        private final List<IdentitySlot> touched;
        private final Map<String, Boolean> residentChanges;
        private SigningHybridCrlDependencies.Prepared dependencies;
        private boolean active = true;

        private Prepared() {
            this(List.of(), List.of(), List.of(), List.of(), Map.of());
        }

        private Prepared(List<SigningDueWorkIndex.PreparedChange> orderedChanges,
                List<SigningRetentionIndex.PreparedChange> retentionChanges,
                List<AdmittedIdentity> admitted, List<IdentitySlot> touched,
                Map<String, Boolean> residentChanges) {
            this.orderedChanges = orderedChanges;
            this.retentionChanges = retentionChanges;
            this.admitted = admitted;
            this.touched = touched;
            this.residentChanges = Map.copyOf(residentChanges);
        }

        /**
         * Attaches prepared hybrid dependencies for publication; rollback also requires closeDependencies.
         *
         * @param prepared owned prepared dependency changes to publish with this projection
         */
        /* default */ void attach(SigningHybridCrlDependencies.Prepared prepared) { dependencies = prepared; }
        /**
         * Closes attached prepared dependency changes when present; leaves unrelated collaborators open.
         */
        /* default */ void closeDependencies() { if (dependencies != null) { dependencies.close(); } }

        /**
         * Publishes all ordered changes, commits identity reservations, and publishes attached dependencies.
         *
         * @throws IllegalStateException if this preparation is inactive or child publication ownership differs
         */
        /* default */ void publish() {
            if (!active) { throw new IllegalStateException("Signing work projection is closed"); }
            for (SigningDueWorkIndex.PreparedChange change : orderedChanges) { change.publish(); }
            for (SigningRetentionIndex.PreparedChange change : retentionChanges) { change.publish(); }
            commitAdmissions(admitted);
            for (Map.Entry<String,Boolean> change : residentChanges.entrySet()) {
                if (change.getValue()) { residentOnly.add(change.getKey()); }
                else { residentOnly.remove(change.getKey()); }
            }
            discardUnreferenced(touched);
            if (dependencies != null) { dependencies.publish(); }
            active = false;
        }

        /**
         * Rolls back this unpublished projection's due, retention, and identity reservations once.
         *
         * <p>Published or already closed preparations are no-ops. Attached hybrid dependency
         * preparations are not closed here; their owner must also call closeDependencies.
         * Borrowed indexes, budgets, and content stores remain open.</p>
         */
        @Override public void close() {
            if (!active) { return; }
            active = false;
            rollback(orderedChanges, retentionChanges, admitted);
        }
    }

    /**
     * Projected operation identity count and its accounted memory reservation.
     *
     * @param identities number of retained projected operation identities
     * @param reservedBytes current accounted reservation in bytes
     */
    /* default */ record Statistics(int identities, long reservedBytes) {
    }

    /**
     * One state record read through the recovered MVCC pointer.
     * @param key exact logical metadata identity
     * @param content exact encoded metadata content bytes
     * @param pointer exact retained physical record pointer
     */
    /* default */ record RecoveredState(MetadataKey key, byte[] content,
            SigningMvccIndex.RecordPointer pointer) {
        /**
         * Creates one state record read through the recovered MVCC pointer.
         *
         * @param key exact logical metadata identity
         * @param content exact encoded metadata content bytes
         * @param pointer exact retained physical record pointer
         * @throws NullPointerException if {@code key} is null; or if {@code content} is null; or if
         * {@code pointer} is null
         */
        RecoveredState {
            Objects.requireNonNull(key, "key");
            Objects.requireNonNull(content, "content");
            Objects.requireNonNull(pointer, "pointer");
        }
    }

    /**
     * Scalar evidence emitted by the production bulk reconstruction path.
     * @param statesVisited number of mutable-state records visited during reconstruction
     * @param activeEntriesBuilt number of active work descriptors built during reconstruction
     * @param statePointersRetained number of physical state pointers retained by the reconstructed projection
     */
    /* default */ record RecoveryStatistics(long statesVisited, long activeEntriesBuilt,
            long statePointersRetained) {
    }

    /** Owns the borrowed projection lists for one prepared transaction. */
    private final class MutationPreparation {
        private final SigningMvccIndex.RecordPointer pointer;
        private final List<SigningDueWorkIndex.PreparedChange> orderedChanges;
        private final List<SigningRetentionIndex.PreparedChange> retentionChanges;
        private final List<AdmittedIdentity> admitted;
        private final List<IdentitySlot> touched;
        private final SigningDueWorkIndex.Admission dueAdmission;
        private final SigningTransitionWorkspaceSizing.AdmissionClass admissionClass;
        private final SigningHybridCrlDependencies.View dependencies;
        private final Set<String> handoffIds;
        private final Map<String, Boolean> residentChanges;
        private MutationPreparation(SigningMvccIndex.RecordPointer pointer,
                List<SigningDueWorkIndex.PreparedChange> orderedChanges,
                List<SigningRetentionIndex.PreparedChange> retentionChanges,
                List<AdmittedIdentity> admitted,
                List<IdentitySlot> touched,
                SigningDueWorkIndex.Admission dueAdmission,
                SigningTransitionWorkspaceSizing.AdmissionClass admissionClass,
                SigningHybridCrlDependencies.View dependencies,
                Set<String> handoffIds,
                Map<String, Boolean> residentChanges) {
            this.pointer = pointer;
            this.orderedChanges = orderedChanges;
            this.retentionChanges = retentionChanges;
            this.admitted = admitted;
            this.touched = touched;
            this.dueAdmission = dueAdmission;
            this.admissionClass = admissionClass;
            this.dependencies = dependencies;
            this.handoffIds = handoffIds;
            this.residentChanges = residentChanges;
        }
        private void process(SigningTransactionPayloadCodec.Mutation mutation, SignWorkflowStore.SchedulingPlan scheduling) {

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
        if (!operationId.equals(state.operationId().value())) { return; }
        residentChanges.put(operationId, dependencies.suppressed().contains(operationId)
                && !RecoveryBuilder.isRetained(state.state()));
        if (handoffIds.contains(operationId)) { return; }
        if (RecoveryBuilder.isRetained(state.state()) || dependencies.suppressed().contains(operationId)) {
            if (due.contains(slot.identity)) { orderedChanges.add(due.prepareRemove(slot.identity)); }
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
    }


    private static SigningTransactionPayloadCodec.Mutation receiverMutation(SigningTransactionPayloadCodec.Payload payload,
            String receiverId) {
        MetadataKey expected = new MetadataKey(STATE_NAMESPACE, receiverId);
        return payload.mutations().stream().filter(value -> value.key().equals(expected)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Hybrid CRL handoff has no receiver state"));
    }

}
