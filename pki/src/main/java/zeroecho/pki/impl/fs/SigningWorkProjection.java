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
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.SignWorkflowStore;

/** Atomic signing-work projections sharing one canonical identity per operation. */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.AvoidDeeplyNestedIfStmts",
        "PMD.AvoidLiteralsInIfCondition", "PMD.CloseResource", "PMD.CommentRequired",
        "PMD.CompareObjectsWithEquals", "PMD.ControlStatementBraces" })
final class SigningWorkProjection implements AutoCloseable {
    /* default */ static final String RECORD_NAMESPACE = "io.zeroecho.pki.signing-record";
    /* default */ static final String OWNER_NAMESPACE = SigningOwnerKey.NAMESPACE;

    private final SigningDueWorkIndex due;
    private final SigningRetentionIndex retention;
    private final SigningDueWorkIndex owners;
    private final SigningIndexCapacityBudget capacity;
    private final Map<String, IdentitySlot> identities = new HashMap<>();
    private long reservedIdentityBytes;

    /* default */ SigningWorkProjection(SigningDueWorkIndex due,
            SigningRetentionIndex retention, SigningDueWorkIndex owners,
            SigningIndexCapacityBudget capacity) {
        this.due = Objects.requireNonNull(due, "due");
        this.retention = Objects.requireNonNull(retention, "retention");
        this.owners = Objects.requireNonNull(owners, "owners");
        this.capacity = Objects.requireNonNull(capacity, "capacity");
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
        Set<String> ownerChanges = new HashSet<>();
        boolean transferred = false;
        try {
            for (SigningTransactionPayloadCodec.Mutation mutation : payload.mutations()) {
                MetadataKey key = mutation.key();
                if (OWNER_NAMESPACE.equals(key.namespace())) {
                    prepareOwnerMutation(mutation, pointer, orderedChanges, admitted,
                            touched, ownerChanges, admissionClass);
                } else if (RECORD_NAMESPACE.equals(key.namespace())) {
                    prepareRecordMutation(mutation, pointer, orderedChanges, retentionChanges,
                            admitted, touched, dueAdmission, admissionClass);
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
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
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
        slot = admit(operationId, admitted, admissionClass);
        touch(touched, slot);
        SignWorkflowStore.Record record;
        try {
            record = FsCodec.decode(FsCodec.SIGN_WORKFLOW_RECORD,
                    Objects.requireNonNull(mutation.contentInternal(), "content"));
        } catch (RuntimeException malformed) {
            if (retention.contains(slot.identity)) {
                retentionChanges.add(retention.prepareRemove(slot.identity));
            }
            boolean initialDue = !due.contains(slot.identity);
            if (initialDue && dueAdmission != null) {
                dueAdmission.bind(slot.identity);
                orderedChanges.add(due.prepareMalformed(dueAdmission, slot.identity, pointer));
            } else {
                orderedChanges.add(due.prepareMalformed(slot.identity, pointer));
            }
            return;
        }
        if (!operationId.equals(record.submissionId().value())) return;
        if (isRetained(record.state())) {
            if (due.contains(slot.identity)) orderedChanges.add(due.prepareRemove(slot.identity));
            retentionChanges.add(retention.prepareRetained(
                    slot.identity, record.createdAt(), admissionClass));
        } else {
            if (retention.contains(slot.identity)) {
                retentionChanges.add(retention.prepareRemove(slot.identity));
            }
            Instant nextEligibleAt = record.nextEligibleAt().orElse(Instant.EPOCH);
            boolean initialDue = !due.contains(slot.identity);
            if (initialDue && dueAdmission != null) {
                dueAdmission.bind(slot.identity);
                orderedChanges.add(due.prepareUpdate(dueAdmission, slot.identity,
                        nextEligibleAt, record.state(), pointer));
            } else {
                orderedChanges.add(due.prepareUpdate(slot.identity,
                        nextEligibleAt, record.state(), pointer, admissionClass));
            }
        }
    }

    private void prepareOwnerMutation(SigningTransactionPayloadCodec.Mutation mutation,
            SigningMvccIndex.RecordPointer pointer,
            List<SigningDueWorkIndex.PreparedChange> orderedChanges,
            List<AdmittedIdentity> admitted, List<IdentitySlot> touched,
            Set<String> ownerChanges,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) throws IOException {
        String operationId = ownerOperationId(mutation.key());
        if (!ownerChanges.add(operationId)) {
            throw new IOException("Signing owner operation is duplicated");
        }
        IdentitySlot slot = identities.get(operationId);
        if (mutation.kind() == SigningTransactionPayloadCodec.MutationKind.DELETE) {
            if (slot != null && owners.contains(slot.identity)) {
                orderedChanges.add(owners.prepareRemove(slot.identity));
                touch(touched, slot);
            }
            return;
        }
        slot = admit(operationId, admitted, admissionClass);
        touch(touched, slot);
        if (owners.contains(slot.identity)) {
            throw new IOException("Signing owner operation is duplicated");
        }
        orderedChanges.add(owners.prepareUpdate(slot.identity, Instant.EPOCH,
                SignWorkflowStore.State.INTENT, pointer, admissionClass));
    }

    /* default */ void recover(MetadataKey key, byte[] content,
            SigningMvccIndex.RecordPointer pointer) throws IOException {
        if (!OWNER_NAMESPACE.equals(key.namespace()) && !RECORD_NAMESPACE.equals(key.namespace())) {
            return;
        }
        String operationId = OWNER_NAMESPACE.equals(key.namespace())
                ? ownerOperationId(key) : key.key();
        List<AdmittedIdentity> admitted = new ArrayList<>(1);
        IdentitySlot slot = admit(operationId, admitted,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
        boolean published = false;
        try {
            if (OWNER_NAMESPACE.equals(key.namespace())) {
                if (owners.contains(slot.identity)) {
                    throw new IOException("Signing owner operation is duplicated");
                }
                owners.update(slot.identity, Instant.EPOCH, SignWorkflowStore.State.INTENT, pointer);
            } else {
                recoverRecord(key, content, pointer, slot);
            }
            commitAdmissions(admitted);
            discardUnreferenced(List.of(slot));
            published = true;
        } finally {
            if (!published) rollbackAdmissions(admitted);
        }
    }

    private void recoverRecord(MetadataKey key, byte[] content,
            SigningMvccIndex.RecordPointer pointer, IdentitySlot slot) throws IOException {
        SignWorkflowStore.Record record;
        try {
            record = FsCodec.decode(FsCodec.SIGN_WORKFLOW_RECORD, content);
        } catch (RuntimeException malformed) {
            try (SigningDueWorkIndex.PreparedChange prepared =
                    due.prepareMalformed(slot.identity, pointer)) {
                prepared.publish();
            }
            return;
        }
        if (!key.key().equals(record.submissionId().value())) return;
        if (isRetained(record.state())) {
            try (SigningRetentionIndex.PreparedChange prepared =
                    retention.prepareRetained(slot.identity, record.createdAt())) {
                prepared.publish();
            }
        } else {
            due.update(slot.identity, record.nextEligibleAt().orElse(Instant.EPOCH),
                    record.state(), pointer);
        }
    }

    private static boolean isRetained(SignWorkflowStore.State state) {
        return state == SignWorkflowStore.State.RETIRED
                || state == SignWorkflowStore.State.EXPIRED;
    }

    /* default */ boolean containsOwner(String operationId) {
        IdentitySlot slot = identities.get(Objects.requireNonNull(operationId, "operationId"));
        return slot != null && owners.contains(slot.identity);
    }

    private static String ownerOperationId(MetadataKey key) throws IOException {
        try {
            return SigningOwnerKey.parse(key).submissionId().value();
        } catch (IllegalArgumentException malformed) {
            throw new IOException("Signing owner key is invalid", malformed);
        }
    }

    private IdentitySlot admit(String operationId, List<AdmittedIdentity> admitted,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
        IdentitySlot existing = identities.get(operationId);
        if (existing != null) return existing;
        SigningDueWorkIndex.CanonicalOperationId identity = due.admit(operationId);
        long bytes = identity.sharedResidentBytes();
        SigningIndexCapacityBudget.Reservation reservation =
                capacity.reserve(bytes, admissionClass);
        IdentitySlot slot = new IdentitySlot(identity, bytes);
        identities.put(identity.value(), slot);
        admitted.add(new AdmittedIdentity(slot, reservation));
        return slot;
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
            if (!due.contains(slot.identity) && !retention.contains(slot.identity)
                    && !owners.contains(slot.identity)
                    && identities.remove(slot.identity.value(), slot)) {
                reservedIdentityBytes -= slot.bytes;
                capacity.releaseCommitted(slot.bytes);
            }
        }
    }

    /* default */ Statistics statistics() {
        return new Statistics(identities.size(), reservedIdentityBytes);
    }

    @Override public void close() {
        if (reservedIdentityBytes > 0L) capacity.releaseCommitted(reservedIdentityBytes);
        reservedIdentityBytes = 0L;
        identities.clear();
    }

    private static final class IdentitySlot {
        private final SigningDueWorkIndex.CanonicalOperationId identity;
        private final long bytes;
        private IdentitySlot(SigningDueWorkIndex.CanonicalOperationId identity, long bytes) {
            this.identity = identity;
            this.bytes = bytes;
        }
    }

    private record AdmittedIdentity(IdentitySlot slot,
            SigningIndexCapacityBudget.Reservation reservation) { }

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
}
