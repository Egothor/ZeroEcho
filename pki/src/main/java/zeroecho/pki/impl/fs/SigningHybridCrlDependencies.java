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

import java.util.concurrent.locks.ReentrantLock;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Optional;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataStoreException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import zeroecho.pki.spi.store.CrlHybridExecution;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.StagedContentStore;

/**
 * Transaction-local hybrid CRL graph from prepared MVCC pointers and their
 * pending mutation overlay. The child reservation exists before adoption;
 * linked terminal children remain suppressed until grouped retirement.
 */
final class SigningHybridCrlDependencies {
    private static final String DOMAIN = "io.zeroecho.pki.domain-continuation";
    private static final AttributeId CRL_COMMAND =
            new AttributeId("zeroecho.pki.full-crl.command-sha256");
    /**
     * Exact status-object metadata namespace used to resolve hybrid CRL publication dependencies.
     */
    /* default */ static final String STATUS = FilesystemPkiStore.statusRecordKey(
            new PkiId("crl:" + "f".repeat(64))).namespace();
    private final ReentrantLock graphLock = new ReentrantLock();
    private final Map<String, CrlHybridExecution> parents = new HashMap<>();
    private final Map<String, String> children = new HashMap<>();
    private final GraphValidation graphValidation = new GraphValidation();
    private final Accounting accounting = new Accounting();
    private final StagedContentStore content;
    private final SigningIndexCapacityBudget capacity;
    private final SigningDueWorkIndex due;
    private final int maximumIndexKeys;
    private final Map<String, Long> escrowByParent = new HashMap<>();
    private final Map<String, CapacityPlan> capacityPlans = new HashMap<>();
    private final Map<String, Long> graphBytesByParent = new HashMap<>();
    private final Map<String, Integer> futureKeysByParent = new HashMap<>();
    private final Map<String, String> parentsByCommand = new HashMap<>();
    private final Map<String, String> publishedStatusByParent = new HashMap<>();
    private long reservedFutureKeys;
    private long pendingFutureKeys;
    private final Map<String, String> pendingChildren = new HashMap<>();
    private final Set<String> pendingParents = new HashSet<>();
    private final Set<Prepared> pendingChanges = new HashSet<>();

    /**
     * Creates a dependency graph without capacity accounting.
     *
     * @param content durable resolver used to validate accepted content
     */
    /* default */ SigningHybridCrlDependencies(StagedContentStore content) {
        this(content, null, null, 1);
    }

    /**
     * Creates the hybrid dependency graph with optional resident and future capacity accounting.
     *
     * @param content durable resolver used for accepted content
     * @param capacity shared signing index budget, or null to disable accounting
     * @param due live due-work index used by capacity accounting
     * @param maximumIndexKeys maximum actual and reserved future index keys
     */
    /* default */ SigningHybridCrlDependencies(StagedContentStore content, SigningIndexCapacityBudget capacity,
            SigningDueWorkIndex due, int maximumIndexKeys) {
        this.content = content; this.capacity = capacity; this.due = due;
        this.maximumIndexKeys = maximumIndexKeys;
    }

    /**
     * Reads one prepared MVCC value without entering the metadata-store façade.
     */
    /* default */
    @FunctionalInterface
    interface RowReader {
        /**
         * Reads a prepared MVCC value without entering the metadata-store facade.
         *
         * @param key exact namespaced record key
         * @return canonical bytes, or null if absent
         * @throws IOException if the pinned value cannot be read
         */
        byte[] read(MetadataKey key) throws IOException;
        /**
         * Tests record presence without requiring callers to read an uncommitted WAL frame.
         *
         * @param key exact namespaced record key
         * @return true if the record exists
         * @throws IOException if existence cannot be determined
         */
        default boolean exists(MetadataKey key) throws IOException { return read(key) != null; }
    }

    /**
     * Builds a bounded transaction overlay, validates affected reserved identities and reserves future graph capacity.
     * The returned change must be published only after authoritative commit, or closed to roll back reservations.
     *
     * @param payload exact transaction mutations
     * @param current reader of the current pinned metadata view
     * @param projectedActualKeys actual key count projected after this transaction
     * @return transaction-local dependency change and due-ownership view
     * @throws NullPointerException if payload or current is null
     * @throws IOException if graph invariants, authority, reserved identities or capacity validation fail
     * @throws IllegalStateException if resident or future capacity cannot be reserved
     * @throws ArithmeticException if capacity arithmetic overflows
     */
    /* default */ Prepared prepare(SigningTransactionPayloadCodec.Payload payload, RowReader current,
            int projectedActualKeys) throws IOException {
        graphLock.lock();
        try { return new Preparation(payload, current, projectedActualKeys).prepare(); }
        finally { graphLock.unlock(); }
    }


    /**
     * Reconstructs immutable parent-child reservations, future capacity and effective due ownership
     * before live work begins.
     * This graph must be empty before recovery.
     *
     * @param executions recovered executions keyed by parent identifier
     * @param rows reader of recovered authoritative metadata
     * @return recovered suppressed and resident operation identities
     * @throws NullPointerException if a required argument is null
     * @throws IOException if the graph is nonempty, authority is inconsistent or reserved key capacity cannot fit
     * @throws IllegalStateException if recovered resident or future byte capacity cannot be reserved
     * @throws ArithmeticException if recovered capacity arithmetic overflows
     */
    /* default */ View recover(Map<String, CrlHybridExecution> executions, RowReader rows) throws IOException {
        graphLock.lock();
        try {

        return recover(executions, rows, Map.of(), 0);

        } finally { graphLock.unlock(); }
    }

    /**
     * Reconstructs immutable parent-child reservations, future capacity and effective due ownership
     * before live work begins.
     * This graph must be empty before recovery.
     *
     * @param executions recovered executions keyed by parent identifier
     * @param rows reader of recovered authoritative metadata
     * @param publications published status identity by parent operation
     * @param actualKeys recovered actual metadata key count
     * @return recovered suppressed and resident operation identities
     * @throws NullPointerException if a required argument is null
     * @throws IOException if the graph is nonempty, authority is inconsistent or reserved key capacity cannot fit
     * @throws IllegalStateException if recovered resident or future byte capacity cannot be reserved
     * @throws ArithmeticException if recovered capacity arithmetic overflows
     */
    /* default */ View recover(Map<String, CrlHybridExecution> executions, RowReader rows,
            Map<String, String> publications, int actualKeys) throws IOException {
        graphLock.lock();
        try {

        if (!parents.isEmpty() || !children.isEmpty()) { throw invalid(); }
        Set<String> suppressed = new HashSet<>();
        Set<String> resident = new HashSet<>();
        publishedStatusByParent.putAll(publications);
        for (Map.Entry<String,CrlHybridExecution> entry : executions.entrySet()) {
            CrlHybridExecution execution = entry.getValue();
            String parent = execution.parentId().value();
            String child = execution.nativeChildId().value();
            if (!entry.getKey().equals(parent) || children.put(child, parent) != null
                    || executions.containsKey(child)) { throw invalid(); }
            graphValidation.validateGraph(execution, rows);
            CapacityPlan plan = capacity == null ? null : accounting.buildCapacityPlan(execution, rows);
            long escrow = accounting.futureBytes(execution, rows, publications.containsKey(parent), plan);
            long graphBytes = plan == null ? 0L : plan.graphBytes();
            if (capacity != null) {
                try (SigningIndexCapacityBudget.Reservation reservation = capacity.reserve(Math.addExact(escrow, graphBytes))) { reservation.transfer(); }
            }
            escrowByParent.put(parent, escrow);
            graphBytesByParent.put(parent, graphBytes);
            int futureKeys = accounting.futureKeys(execution, rows, publications.containsKey(parent), plan);
            if (plan != null) { capacityPlans.put(parent, plan); }
            futureKeysByParent.put(parent, futureKeys);
            reservedFutureKeys = Math.addExact(reservedFutureKeys, futureKeys);
            parentsByCommand.put(execution.parentCommandCommitment(), parent);
            parents.put(parent, execution);
            resident.add(parent);
            recoverDue(execution, rows, suppressed, resident, parent, child);

        }
        if (capacity != null && actualKeys > maximumIndexKeys - reservedFutureKeys) { throw invalid(); }
        return new View(suppressed, Map.of(), resident);

        } finally { graphLock.unlock(); }
    }



    /**
     * Extracts the single string command commitment that binds a published CRL to its hybrid parent.
     *
     * @param status published status object
     * @return command commitment, or an empty string if the attribute is absent, repeated or not a string
     * @throws NullPointerException if status is null
     */
    /* default */ static String publicationCommitment(StatusObject status) {
        List<AttributeValue> values = status.attributes().getAll(CRL_COMMAND);
        return values.size() == 1 && values.getFirst() instanceof AttributeValue.StringValue value
                ? value.value() : "";
    }





    /**
     * Resident plan strings and phase maxima are owned by exactly one parent.
     */
    private record CapacityPlan(long peakBytes, long childResidentBytes, long graphBytes,
            Set<MetadataKey> childKeys, Set<MetadataKey> statusKeys, Set<MetadataKey> otherKeys) {
        CapacityPlan { childKeys = Set.copyOf(childKeys); statusKeys = Set.copyOf(statusKeys); otherKeys = Set.copyOf(otherKeys); }
    }



    /**
     * Releases only this graph's committed reservations when the engine closes.
     */
    /* default */ void close() {
        graphLock.lock();
        try {

        List.copyOf(pendingChanges).forEach(this::closePending);
        if (capacity != null) {
            for (long bytes : escrowByParent.values()) { capacity.releaseCommitted(bytes); }
            for (long bytes : graphBytesByParent.values()) { capacity.releaseCommitted(bytes); }
        }
        escrowByParent.clear(); graphBytesByParent.clear(); futureKeysByParent.clear(); capacityPlans.clear();
        parentsByCommand.clear(); publishedStatusByParent.clear(); reservedFutureKeys = 0L;
        parents.clear(); children.clear();

        } finally { graphLock.unlock(); }
    }



    private static void requireWake(String parent, RowReader current, RowReader overlay,
            Map<MetadataKey, SigningTransactionPayloadCodec.Mutation> mutations) throws IOException {
        if (!mutations.containsKey(stateKey(parent))) { throw invalid(); }
        SignWorkflowStore.MutableState before = state(current, parent);
        SignWorkflowStore.MutableState after = state(overlay, parent);
        if (before.state() != SignWorkflowStore.State.SUCCEEDED || after.state() != before.state()
                || after.revision() != before.revision() + 1L || after.fence() != before.fence()
                || !sameResult(after.result(), before.result()) || after.nextEligibleAt().isPresent()
                || after.leaseUntil().isPresent()) { throw invalid(); }
    }

    /**
     * EncodedObject defensively owns arrays, so record equality is not content equality.
     */
    private static boolean sameResult(Optional<EncodedObject> left,
            Optional<EncodedObject> right) {
        if (left.isEmpty() || right.isEmpty()) { return left.isEmpty() && right.isEmpty(); }
        EncodedObject actual = left.orElseThrow();
        EncodedObject expected = right.orElseThrow();
        return actual.encoding() == expected.encoding()
                && MessageDigest.isEqual(actual.bytes(), expected.bytes());
    }

    private static boolean terminalBefore(RowReader rows, String id) throws IOException {
        byte[] encoded = rows.read(stateKey(id));
        return encoded != null && terminal(FsCodec.decode(FsCodec.SIGN_MUTABLE_STATE, encoded).state());
    }

    private CrlHybridExecution decodeExecution(byte[] bytes) throws IOException {
        return FsCodec.decodeRecovery(FsCodec.CRL_HYBRID_EXECUTION, bytes, content);
    }

    private static SignWorkflowStore.MutableState state(RowReader rows, String id) throws IOException {
        byte[] encoded = rows.read(stateKey(id));
        if (encoded == null) { throw invalid(); }
        SignWorkflowStore.MutableState state = FsCodec.decode(FsCodec.SIGN_MUTABLE_STATE, encoded);
        if (!state.operationId().value().equals(id)) { throw invalid(); }
        return state;
    }

    /**
     * Returns the signing mutable-state metadata key for an exact operation identifier.
     *
     * @param id operation identifier text
     * @return namespaced metadata key
     * @throws NullPointerException if id is null
     * @throws IllegalArgumentException if id violates metadata key bounds
     */
    /* default */ static MetadataKey stateKey(String id) { return new MetadataKey(SigningWorkProjection.STATE_NAMESPACE, id); }
    /**
     * Returns the signing acceptance-envelope metadata key for an exact operation identifier.
     *
     * @param id operation identifier text
     * @return namespaced metadata key
     * @throws NullPointerException if id is null
     * @throws IllegalArgumentException if id violates metadata key bounds
     */
    /* default */ static MetadataKey envelopeKey(String id) { return new MetadataKey(SigningWorkProjection.ENVELOPE_NAMESPACE, id); }
    private static boolean retained(SignWorkflowStore.State state) {
        return state == SignWorkflowStore.State.RETIRED || state == SignWorkflowStore.State.EXPIRED;
    }
    private static boolean terminal(SignWorkflowStore.State state) {
        return switch (state) {
            case SUCCEEDED, FAILED, CANCELLED, RETIRED, EXPIRED -> true;
            default -> false;
        };
    }
    private static IOException invalid() { return new IOException("Hybrid CRL dependency graph is inconsistent"); }

    /**
     * Effective due ownership for the exact transaction, never arbitrary caller credits.
     * @param suppressed operation identities suppressed by exact dependency ownership
     * @param handoffs parent-to-child ownership handoffs retained by the transaction
     * @param resident operation identities already resident in due-work ownership
     */
    /* default */ record View(Set<String> suppressed, Map<String, String> handoffs, Set<String> resident) {
        /**
         * Creates the effective due ownership for the exact transaction, never arbitrary caller credits.
         *
         * @param suppressed operation identities suppressed by exact dependency ownership
         * @param handoffs parent-to-child ownership handoffs retained by the transaction
         * @param resident operation identities already resident in due-work ownership
         * @throws NullPointerException if a set or map, or any of its elements, keys or values, is null
         */
        View { suppressed = Set.copyOf(suppressed); handoffs = Map.copyOf(handoffs); resident = Set.copyOf(resident); }
        /**
         * Creates an empty dependency ownership view.
         *
         * @return immutable view with no suppressions, handoffs or resident operations
         */
        /* default */ static View empty() { return new View(Set.of(), Map.of(), Set.of()); }
    }

    /**
     * Publishes graph coordinates only after the authoritative transaction commits.
     */
    /* default */ final class Prepared implements AutoCloseable {
        private final Map<String, CrlHybridExecution> replacements;
        private final Set<String> deleted;
        private final View view;
        private final Set<String> affected;
        private final Map<String, Long> nextEscrow;
        private final Map<String, Long> nextGraphBytes;
        private final List<SigningIndexCapacityBudget.Reservation> reservations;
        private final long borrowed;
        private final long residual;
        private final Map<String, Integer> nextKeys;
        private final long keyDelta;
        private final Map<String, String> publications;
        private final Map<String, CapacityPlan> newPlans;
        private SigningIndexCapacityBudget.PreparationLoan loan;
        private Runnable rollbackBeforeClose;
        private boolean active = true;
        private Prepared(Map<String, CrlHybridExecution> replacements, Set<String> deleted,
                Set<String> affected, View view, Map<String, Long> nextEscrow,
                Map<String, Long> nextGraphBytes, List<SigningIndexCapacityBudget.Reservation> reservations,
                long borrowed, long residual, Map<String, Integer> nextKeys,
                long keyDelta, Map<String, String> publications, Map<String, CapacityPlan> newPlans) {
            this.newPlans = newPlans;
            this.nextKeys = nextKeys; this.keyDelta = keyDelta; this.publications = publications;
            this.replacements = replacements; this.deleted = deleted; this.view = view;
            this.affected = Set.copyOf(affected); this.nextEscrow = nextEscrow;
            this.nextGraphBytes = nextGraphBytes; this.reservations = reservations;
            this.borrowed = borrowed; this.residual = residual;
        }
        /**
         * Attaches transaction rollback to run before abandoning this prepared change.
         *
         * @param rollback caller-owned rollback action
         * @throws NullPointerException if rollback is null
         */
        /* default */ void attachRollback(Runnable rollback) { rollbackBeforeClose = Objects.requireNonNull(rollback); }
        /**
         * Borrows committed capacity for this prepared transaction when accounting and a positive
         * borrowed amount are present.
         *
         * @throws IllegalStateException if the shared budget cannot honor the committed-capacity loan
         */
        /* default */ void enterLoan() { if (capacity != null && borrowed > 0L) { loan = capacity.borrowCommitted(borrowed); } }
        /**
         * Detaches the active transaction capacity loan and requires the computed residual reservation before commit.
         *
         * @throws IllegalStateException if detachment occurs from a different preparation thread or loan scope
         * @throws SigningIndexCapacityBudget.CapacityExceededException if the residual capacity
         * requirement cannot be met
         */
        /* default */ void detachLoan() { if (loan != null) { loan.detach(); loan.requireResidual(residual); } }
        /**
         * Returns the exact prepared transaction-local hybrid CRL dependency view.
         *
         * @return exact prepared transaction-local hybrid CRL dependency view
         */
        /* default */ View view() { return view; }
        /**
         * Publishes graph replacements, due ownership and capacity changes after the authoritative transaction commits.
         * Transfers reservations, releases deleted graph capacity and removes this change from the pending set.
         *
         * @throws IllegalStateException if this change has already been closed or published
         * @throws ArithmeticException if committed future-key accounting overflows
         */
        /* default */ void publish() {
            graphLock.lock();
            try {
            if (!active) { throw new IllegalStateException("Hybrid CRL dependency change is closed"); }
            if (loan != null) { loan.publish(residual); }
            reservations.forEach(Prepared::transferReservation);
            for (Map.Entry<String,Long> entry : nextEscrow.entrySet()) {
                if (deleted.contains(entry.getKey())) { escrowByParent.remove(entry.getKey()); }
                else { escrowByParent.put(entry.getKey(), entry.getValue()); }
            }
            graphBytesByParent.putAll(nextGraphBytes);
            capacityPlans.putAll(newPlans);
            reservedFutureKeys = Math.addExact(reservedFutureKeys, keyDelta);
            futureKeysByParent.putAll(nextKeys);
            publishedStatusByParent.putAll(publications);
            for (String parent : deleted) {
                Long graphBytes = graphBytesByParent.remove(parent);
                if (capacity != null && graphBytes != null) { capacity.releaseCommitted(graphBytes); }
                CrlHybridExecution old = parents.remove(parent);
                futureKeysByParent.remove(parent); publishedStatusByParent.remove(parent); capacityPlans.remove(parent);
                if (old != null) {
                    children.remove(old.nativeChildId().value(), parent);
                    parentsByCommand.remove(old.parentCommandCommitment(), parent);
                }
            }
            for (Map.Entry<String,CrlHybridExecution> entry : replacements.entrySet()) {
                parents.put(entry.getKey(), entry.getValue());
                parentsByCommand.put(entry.getValue().parentCommandCommitment(), entry.getKey());
                children.put(entry.getValue().nativeChildId().value(), entry.getKey());
            }
            releasePending();
            active = false;

            } finally { graphLock.unlock(); }
        }
        private static void transferReservation(SigningIndexCapacityBudget.Reservation reservation) {
            reservation.transfer(); reservation.close();
        }
        private void releasePending() {
            pendingChanges.remove(this);
            pendingFutureKeys = Math.subtractExact(pendingFutureKeys, keyDelta);
            pendingParents.removeAll(affected);
            for (Map.Entry<String,CrlHybridExecution> entry : replacements.entrySet()) {
                pendingChildren.remove(entry.getValue().nativeChildId().value(), entry.getKey());
            }
        }
        /**
         * {@inheritDoc}
         */
        @Override public void close() {
            graphLock.lock();
            try {
            if (active) {
                if (loan != null) { loan.close(); }
                reservations.forEach(SigningIndexCapacityBudget.Reservation::close);
                releasePending(); active = false;
            }

            } finally { graphLock.unlock(); }
        }
    }

    /** Owns one ordered transaction overlay and all rollback reservations until publication. */
    private final class Preparation {
        private final SigningTransactionPayloadCodec.Payload payload;
        private final RowReader current;
        private final int projectedActualKeys;
        private RowReader overlay;
        private final Map<MetadataKey, SigningTransactionPayloadCodec.Mutation> mutations = new HashMap<>();
        private final Set<String> affected = new HashSet<>();
        private final Map<String, CrlHybridExecution> replacements = new HashMap<>();
        private final Map<String, String> publications = new HashMap<>();
        private final Set<String> deleted = new HashSet<>();
        private final Map<String, CrlHybridExecution> selected = new HashMap<>();
        private final Set<String> suppressed = new HashSet<>();
        private final Map<String, String> handoffs = new HashMap<>();
        private final Set<String> resident = new HashSet<>();
        private final Map<String, Long> nextEscrow = new HashMap<>();
        private final Map<String, CapacityPlan> newPlans = new HashMap<>();
        private final Map<String, Long> nextGraphBytes = new HashMap<>();
        private final List<SigningIndexCapacityBudget.Reservation> reservations = new ArrayList<>();
        private final Map<String, Integer> nextKeys = new HashMap<>();
        private long borrowed;
        private long residual;
        private long keyDelta;
        private Preparation(SigningTransactionPayloadCodec.Payload payload, RowReader current, int projectedActualKeys) {
            this.payload = payload; this.current = current; this.projectedActualKeys = projectedActualKeys;
        }
        private Prepared prepare() throws IOException {
            new MutationSelection().collect();
        overlay = key -> {
            SigningTransactionPayloadCodec.Mutation mutation = mutations.get(key);
            return mutation == null ? current.read(key)
                    : mutation.kind() == SigningTransactionPayloadCodec.MutationKind.DELETE
                            ? null : mutation.contentInternal();
        };
        for (String id : affected) { select(id); }
            new MutationSelection().validateEnvelopes();
            reserve();
        pendingFutureKeys = Math.addExact(pendingFutureKeys, keyDelta);
        for (String parent : affected) { pendingParents.add(parent); }
        for (Map.Entry<String,CrlHybridExecution> entry : replacements.entrySet()) {
            pendingChildren.put(entry.getValue().nativeChildId().value(), entry.getKey());
        }
        Prepared prepared = new Prepared(replacements, deleted, affected,
                new View(suppressed, handoffs, resident), nextEscrow, nextGraphBytes,
                reservations, borrowed, residual, nextKeys, keyDelta, publications, newPlans);
        pendingChanges.add(prepared);
        return prepared;

        }
        private void select(String id) throws IOException {

            if (pendingParents.contains(id)) { throw invalid(); }
            CrlHybridExecution before = parents.get(id);
            CrlHybridExecution after = deleted.contains(id) ? null : replacements.getOrDefault(id, before);
            if (after == null) {
                if (before != null && (overlay.read(stateKey(id)) != null
                        || overlay.read(stateKey(before.nativeChildId().value())) != null)) { throw invalid(); }
                return;
            }
            selected.put(id, after);
            String child = after.nativeChildId().value();
            requireOwnership(id, child, before);
            graphValidation.validateGraph(after, overlay);
            if (publications.containsKey(id)) {
                PkiId statusId = publicationId(id);
                StatusObject status = FsCodec.decodeRecovery(FsCodec.STATUS_OBJECT,
                        overlay.read(FilesystemPkiStore.statusRecordKey(statusId)), content);
                CrlHybridMetadata.requireOwnedPublication(status, after, overlay, content);
            }
            requireTransition(id, before, after);
            resident.add(id);
            selectDue(id, child, before, after);


        }
        private void requireOwnership(String id, String child, CrlHybridExecution before) throws IOException {
            String owner = children.get(child);
            if (pendingChildren.containsKey(child) || pendingParents.contains(child)) { throw invalid(); }
            if (owner != null && !owner.equals(id) || parents.containsKey(child)) { throw invalid(); }
            if (before == null && (current.exists(stateKey(child)) || current.exists(envelopeKey(child)))) { throw invalid(); }
        }
        private void requireTransition(String id, CrlHybridExecution before, CrlHybridExecution after) throws IOException {
            if (before != null && before.phase() == SignWorkflowStore.CrlHybridPhase.AWAITING_ALT
                    && after.phase() == SignWorkflowStore.CrlHybridPhase.NATIVE_LINKED) {
                MetadataKey domainKey = domainKey(id);
                if (!mutations.containsKey(stateKey(id)) || !mutations.containsKey(domainKey)
                        || state(current, id).state() != SignWorkflowStore.State.SUCCEEDED
                        || !Arrays.equals(current.read(stateKey(id)), overlay.read(stateKey(id)))
                        || !Arrays.equals(current.read(domainKey), overlay.read(domainKey))) { throw invalid(); }
            }
        }
        private void selectDue(String id, String child, CrlHybridExecution before, CrlHybridExecution after) throws IOException {
            if (after.phase() != SignWorkflowStore.CrlHybridPhase.NATIVE_LINKED) { return; }

                resident.add(child);
                SignWorkflowStore.MutableState parentState = state(overlay, id);
                SignWorkflowStore.MutableState childState = state(overlay, child);
                if (terminal(childState.state())) {
                    suppressed.add(child);
                    if (!retained(parentState.state()) && !terminalBefore(current, child)) {
                        requireWake(id, current, overlay, mutations);
                        handoffs.put(id, child);
                    }
                } else {
                    suppressed.add(id);
                    if (before == null || before.phase() != SignWorkflowStore.CrlHybridPhase.NATIVE_LINKED) {
                        handoffs.put(child, id);
                    }
                }
                    }

        private PkiId publicationId(String id) { return new PkiId(publications.get(id)); }
        // Every runtime failure must release all reservations accumulated by this preparation.
        @SuppressWarnings("PMD.AvoidCatchingGenericException")
        private void reserve() throws IOException {
        try {
            reserveAffected();

            validateFutureCapacity();
        } catch (IOException | RuntimeException failure) {
            reservations.forEach(SigningIndexCapacityBudget.Reservation::close);
            throw failure;
        }

        }
        private void validateFutureCapacity() throws IOException {
            if (borrowed > 0L && !nextGraphBytes.isEmpty()) { throw invalid(); }
            long future = Math.addExact(Math.addExact(reservedFutureKeys, pendingFutureKeys), keyDelta);
            if (capacity != null && (future < 0L || projectedActualKeys > maximumIndexKeys - future)) {
                throw new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                        "Hybrid CRL future metadata-key capacity is exhausted");
            }
        }
        private void reserveAffected() throws IOException {
            for (String parent : affected) { reserveParent(parent); }
        }
        private void reserveParent(String parent) throws IOException {

                CrlHybridExecution execution = selected.get(parent);
                CapacityPlan plan = capacityPlans.get(parent);
                if (capacity != null && execution != null && plan == null) {
                    plan = accounting.buildCapacityPlan(execution, overlay);
                    newPlans.put(parent, plan);
                }
                long next = futureBytes(parent, execution, plan);
                long previous = escrowByParent.getOrDefault(parent, 0L);
                int keys = futureKeys(parent, execution, plan);
                nextKeys.put(parent, keys);
                keyDelta = Math.addExact(keyDelta, (long) keys - futureKeysByParent.getOrDefault(parent, 0));
                nextEscrow.put(parent, next);
                if (!parents.containsKey(parent) && execution != null) {
                    long graphBytes = plan == null ? 0L : plan.graphBytes();
                    nextGraphBytes.put(parent, graphBytes);
                    if (capacity != null) { reservations.add(capacity.reserve(Math.addExact(next, graphBytes))); }
                } else if (next < previous) {
                    borrowed = Math.addExact(borrowed, previous);
                    residual = Math.addExact(residual, next);
                } else if (next > previous) {
                    throw invalid();
                }

        }
        private long futureBytes(String parent, CrlHybridExecution execution, CapacityPlan plan) throws IOException {
            return execution == null ? 0L : accounting.futureBytes(execution, overlay,
                    publications.containsKey(parent) || publishedStatusByParent.containsKey(parent), plan);
        }
        private int futureKeys(String parent, CrlHybridExecution execution, CapacityPlan plan) throws IOException {
            return execution == null ? 0 : accounting.futureKeys(execution, overlay,
                    publications.containsKey(parent) || publishedStatusByParent.containsKey(parent), plan);
        }

        /** Selects affected identities before graph validation and reservation. */
        private final class MutationSelection {
            private void collect() throws IOException {
                collectMutations(); collectPublications();
            }
            private void collectMutations() throws IOException {

        for (SigningTransactionPayloadCodec.Mutation mutation : payload.mutations()) {
            mutations.put(mutation.key(), mutation);
            String namespace = mutation.key().namespace();
            String id = mutation.key().key();
            if (CrlHybridMetadata.EXECUTION_NAMESPACE.equals(namespace)) {
                affected.add(id);
                if (mutation.kind() == SigningTransactionPayloadCodec.MutationKind.DELETE) { deleted.add(id); }
                else {
                    CrlHybridExecution execution = decodeExecution(mutation.contentInternal());
                    if (!execution.parentId().value().equals(id)) { throw invalid(); }
                    replacements.put(id, execution);
                }
            }
            if (SigningWorkProjection.STATE_NAMESPACE.equals(namespace)
                    || SigningWorkProjection.ENVELOPE_NAMESPACE.equals(namespace) || DOMAIN.equals(namespace)) {
                if (parents.containsKey(id)) { affected.add(id); }
                if (pendingChildren.containsKey(id)) { throw invalid(); }
                String parent = children.get(id);
                if (parent != null) { affected.add(parent); }
            }
        }
            }
            private void collectPublications() throws IOException {
        for (SigningTransactionPayloadCodec.Mutation mutation : payload.mutations()) {
            if (parentsByCommand.isEmpty() || !STATUS.equals(mutation.key().namespace())
                    || mutation.kind() == SigningTransactionPayloadCodec.MutationKind.DELETE) { continue; }
            StatusObject status = FsCodec.decodeRecovery(FsCodec.STATUS_OBJECT, mutation.contentInternal(), content);
            String commitment = publicationCommitment(status);
            String parent = parentsByCommand.get(commitment);
            if (parent != null) {
                if (!mutation.key().equals(FilesystemPkiStore.statusRecordKey(status.statusObjectId()))) { throw invalid(); }
                publications.put(parent, status.statusObjectId().value());
                affected.add(parent);
            }
        }

                        }

            private void validateEnvelopes() throws IOException {
        for (SigningTransactionPayloadCodec.Mutation mutation : payload.mutations()) {
            if (!SigningWorkProjection.ENVELOPE_NAMESPACE.equals(mutation.key().namespace())
                    || mutation.kind() == SigningTransactionPayloadCodec.MutationKind.DELETE) { continue; }
            String owner = children.get(mutation.key().key());
            if (owner != null && !selected.containsKey(owner)) { throw invalid(); }
            if (owner != null && selected.get(owner).phase() != SignWorkflowStore.CrlHybridPhase.NATIVE_LINKED) { throw invalid(); }
        }

            }
        }
    }
    private static MetadataKey domainKey(String id) { return new MetadataKey(DOMAIN, id); }


    private void closePending(Prepared pending) {
        if (pending.rollbackBeforeClose != null) { pending.rollbackBeforeClose.run(); }
        pending.close();
    }


    /** Computes immutable graph capacity and phase reservations. */
    private final class Accounting {
        private int futureKeys(CrlHybridExecution execution, RowReader rows, boolean published,
                CapacityPlan plan) throws IOException {
            if (capacity == null) { return 0; }
            SignWorkflowStore.MutableState parentState = state(rows, execution.parentId().value());
            if (retained(parentState.state()) || parentState.state() == SignWorkflowStore.State.FAILED
                    || parentState.state() == SignWorkflowStore.State.CANCELLED) { return 0; }
            boolean childPending = execution.phase() == SignWorkflowStore.CrlHybridPhase.AWAITING_ALT;
            boolean statusPending = !published;
            DomainContinuationStore.Record domain = FsCodec.decode(FsCodec.DOMAIN_CONTINUATION,
                    rows.read(new MetadataKey(DOMAIN, execution.parentId().value())), content);
            if (domain.state() == DomainContinuationStore.State.FAILED || domain.state() == DomainContinuationStore.State.EXPIRED) {
                statusPending = false; childPending = false;
            }
            if (execution.phase() == SignWorkflowStore.CrlHybridPhase.NATIVE_LINKED) {
                SignWorkflowStore.MutableState childState = state(rows, execution.nativeChildId().value());
                if (terminal(childState.state()) && childState.state() != SignWorkflowStore.State.SUCCEEDED) { statusPending = false; }
            }
            int keys = childPending ? plan.childKeys().size() : 0;
            if (statusPending) { keys = Math.addExact(keys, plan.statusKeys().size()); }
            for (MetadataKey key : plan.otherKeys()) { if (!rows.exists(key)) { keys = Math.incrementExact(keys); } }
            return keys;
        }

        private long futureBytes(CrlHybridExecution execution, RowReader rows, boolean published,
                CapacityPlan plan) throws IOException {
            if (capacity == null) { return 0L; }
            SignWorkflowStore.MutableState parentState = state(rows, execution.parentId().value());
            if (retained(parentState.state())) { return 0L; }
            long peak = plan.peakBytes();
            DomainContinuationStore.Record domain = FsCodec.decode(FsCodec.DOMAIN_CONTINUATION,
                    rows.read(new MetadataKey(DOMAIN, execution.parentId().value())), content);
            if (domain.state() == DomainContinuationStore.State.COMPLETED && !published) { throw invalid(); }
            if (domain.state() == DomainContinuationStore.State.FAILED
                    || domain.state() == DomainContinuationStore.State.EXPIRED || published) { return peak; }
            if (execution.phase() == SignWorkflowStore.CrlHybridPhase.NATIVE_LINKED) {
                SignWorkflowStore.MutableState childState = state(rows, execution.nativeChildId().value());
                return Math.multiplyExact(peak, terminal(childState.state()) ? 2L : 3L);
            }
            if (terminal(parentState.state()) && parentState.state() != SignWorkflowStore.State.SUCCEEDED) { return peak; }
            return Math.addExact(plan.childResidentBytes(), Math.multiplyExact(peak, 4L));
        }

        private CapacityPlan buildCapacityPlan(CrlHybridExecution execution, RowReader rows) throws IOException {
            long graphBytes = graphBytes(execution, rows);
            if (retained(state(rows, execution.parentId().value()).state())) {
                return new CapacityPlan(0L, 0L, graphBytes, Set.of(), Set.of(), Set.of());
            }
            SignWorkflowStore.AcceptanceEnvelope parent = FsCodec.decodeRecovery(FsCodec.SIGN_ACCEPTANCE_ENVELOPE,
                    rows.read(envelopeKey(execution.parentId().value())), content);
            SignWorkflowStore.AcceptanceEnvelope future = CrlHybridMetadata.futureChildEnvelope(parent, execution, rows);
            Set<MetadataKey> expectedChild = Set.of(envelopeKey(execution.nativeChildId().value()),
                    stateKey(execution.nativeChildId().value()),
                    FilesystemPkiStore.signingCandidateBindingKey(future.candidate().contentId()),
                    CrlHybridMetadata.reverseKey(execution.nativeChildId()));
            Set<MetadataKey> candidates = new HashSet<>();
            long[] maximumEncoded = { 0L };
            CrlHybridTransactionBudget.visitPhases(parent, execution, rows, phase -> {
                maximumEncoded[0] = Math.max(maximumEncoded[0], SigningTransactionPayloadCodec.encodedCommitSize(phase));
                for (SigningTransactionPayloadCodec.Mutation mutation : phase) {
                    if (mutation.kind() != SigningTransactionPayloadCodec.MutationKind.DELETE) { candidates.add(mutation.key()); }
                }
            });
            String statusOwner = FilesystemPkiStore.statusOwnerKey(new PkiId("crl:" + "f".repeat(64))).namespace();
            Set<MetadataKey> childKeys = new HashSet<>();
            Set<MetadataKey> statusKeys = new HashSet<>();
            Set<MetadataKey> otherKeys = new HashSet<>();
            for (MetadataKey key : candidates) {
                if (expectedChild.contains(key)) { childKeys.add(key); }
                else if (STATUS.equals(key.namespace()) || statusOwner.equals(key.namespace())) { statusKeys.add(key); }
                else if (!rows.exists(key)) { otherKeys.add(key); }
            }
            long childResident = SigningWorkProjection.identityResidentBytes(due.admit(execution.nativeChildId().value()),
                    SignWorkflowStore.SchedulingPlan.from(future));
            childResident = Math.addExact(childResident, SigningDueWorkIndex.entryResidentBytes());
            for (MetadataKey key : childKeys) { childResident = Math.addExact(childResident,
                    SigningMvccIndex.residentEntryBytes(key)); }
            int height = SigningTransitionWorkspaceSizing.maximumAvlHeight(maximumIndexKeys);
            long pathNodes = Math.multiplyExact((long) SigningTransactionPayloadCodec.MAXIMUM_MUTATIONS,
                    Math.multiplyExact(6L, height));
            // Source serializer buffers and the immutable mutation copy can coexist.
            long peak = Math.addExact(Math.multiplyExact(maximumEncoded[0], 2L),
                    Math.multiplyExact(pathNodes, SigningMvccIndex.ORDERED_NODE_BYTES));
            Set<MetadataKey> retainedKeys = new HashSet<>(childKeys);
            retainedKeys.addAll(statusKeys); retainedKeys.addAll(otherKeys);
            for (MetadataKey key : retainedKeys) { graphBytes = Math.addExact(graphBytes,
                    SigningMvccIndex.residentEntryBytes(key)); }
            return new CapacityPlan(peak, childResident, graphBytes, childKeys, statusKeys, otherKeys);
        }

        private long graphBytes(CrlHybridExecution execution, RowReader rows) throws IOException {
            if (capacity == null) { return 0L; }
            CrlHybridExecution awaiting = new CrlHybridExecution(execution.version(), execution.parentId(),
                    execution.parentCommandCommitment(), execution.issuerBindingCommitment(),
                    execution.roleTupleCommitment(), execution.nativeChildId(),
                    SignWorkflowStore.CrlHybridPhase.AWAITING_ALT, 0L,
                    Optional.empty(), Optional.empty(), Optional.empty());
            SignWorkflowStore.AcceptanceEnvelope envelope = FsCodec.decodeRecovery(FsCodec.SIGN_ACCEPTANCE_ENVELOPE,
                    rows.read(envelopeKey(execution.parentId().value())), content);
            SignWorkflowStore.AcceptanceEnvelope future = CrlHybridMetadata.futureChildEnvelope(envelope, execution, rows);
            long stringsAndReferences = Math.addExact(CrlHybridMetadata.encode(awaiting).length,
                    FsCodec.encode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE, future).length);
            return Math.addExact(256L, Math.multiplyExact(2L, stringsAndReferences));
        }
    }


    /** Verifies exact retained parent and child graph coordinates. */
    private final class GraphValidation {
        private void validateGraph(CrlHybridExecution execution, RowReader rows) throws IOException {
            String parent = execution.parentId().value();
            String child = execution.nativeChildId().value();
            SignWorkflowStore.MutableState parentState = state(rows, parent);
            byte[] envelopeBytes = rows.read(envelopeKey(parent));
            if (envelopeBytes == null) { throw invalid(); }
            SignWorkflowStore.AcceptanceEnvelope envelope = FsCodec.decodeRecovery(FsCodec.SIGN_ACCEPTANCE_ENVELOPE, envelopeBytes, content);
            requireParent(execution, envelope);
            byte[] domainBytes = rows.read(new MetadataKey(DOMAIN, parent));
            if (domainBytes == null) { throw invalid(); }
            DomainContinuationStore.Record domain = FsCodec.decode(FsCodec.DOMAIN_CONTINUATION, domainBytes, content);
            if (execution.phase() == SignWorkflowStore.CrlHybridPhase.AWAITING_ALT) {
                requireAwaiting(execution, rows, domain, child);
                return;
            }
            byte[] reverse = rows.read(CrlHybridMetadata.reverseKey(execution.nativeChildId()));
            if (reverse == null || !execution.equals(decodeExecution(reverse))) { throw invalid(); }
            SignWorkflowStore.MutableState childState = state(rows, child);
            byte[] childEnvelopeBytes = rows.read(envelopeKey(child));
            if (childEnvelopeBytes == null) { throw invalid(); }
            SignWorkflowStore.AcceptanceEnvelope childEnvelope = FsCodec.decodeRecovery(FsCodec.SIGN_ACCEPTANCE_ENVELOPE, childEnvelopeBytes, content);
            SignWorkflowStore.AcceptanceEnvelope expected = CrlHybridMetadata.futureChildEnvelope(envelope, execution, rows);
            requireChild1(execution, childState, childEnvelope);
        requireChild2(envelope, childEnvelope, expected);
        requireChild3(execution, envelope, parentState, childEnvelope);
            requireTerminal(domain, parentState, childState);
        }

        private static void requireParent(CrlHybridExecution execution, SignWorkflowStore.AcceptanceEnvelope envelope) throws IOException {
            if (!execution.parentId().equals(envelope.operationId())
                    || envelope.outer().isEmpty()
                    || !execution.parentCommandCommitment().equals(envelope.outer().orElseThrow().commandCommitment())) { throw invalid(); }
            DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(
                    envelope.outer().orElseThrow().command());
            CrlHybridSigningCommand.Descriptor descriptor = CrlHybridSigningCommand.descriptor(command);
            if (!descriptor.issuerBindingCommitment().equals(execution.issuerBindingCommitment())
                    || !descriptor.roleTupleCommitment().equals(execution.roleTupleCommitment())
                    || !descriptor.nativeChildId().equals(execution.nativeChildId())
                    || !CrlHybridSigningCommand.nativeChildId(
                            execution.parentId()).equals(execution.nativeChildId())) { throw invalid(); }
        }
        private static void requireAwaiting(CrlHybridExecution execution, RowReader rows, DomainContinuationStore.Record domain,
                String child) throws IOException {
                if (domain.state() == DomainContinuationStore.State.COMPLETED || rows.read(stateKey(child)) != null
                        || rows.read(envelopeKey(child)) != null || rows.read(CrlHybridMetadata.reverseKey(execution.nativeChildId())) != null) { throw invalid(); }
        }
        private static void requireTerminal(DomainContinuationStore.Record domain, SignWorkflowStore.MutableState parentState,
                SignWorkflowStore.MutableState childState) throws IOException {
        if (domain.state() != DomainContinuationStore.State.SIGNING
                    && domain.state() != DomainContinuationStore.State.PUBLISHING
                    && !terminal(childState.state())) { throw invalid(); }
            if (retained(parentState.state()) && !retained(childState.state())) { throw invalid(); }        }
        private void requireChild1(CrlHybridExecution execution, SignWorkflowStore.MutableState childState,
                SignWorkflowStore.AcceptanceEnvelope childEnvelope) throws IOException {
            if (!execution.nativeChildId().equals(childEnvelope.operationId()) || childEnvelope.outer().isPresent()
                    || !execution.nativeAcceptanceCommitment().orElseThrow().equals(childEnvelope.acceptanceCommitment())
                    || !execution.nativeTbs().orElseThrow().equals(childEnvelope.candidate())
                    || childEnvelope.mode() != SignWorkflowStore.Mode.NORMAL
                    || childEnvelope.proofStep().isPresent() || childEnvelope.alternativeProofStep().isPresent()
                    || childState.stage() != SignWorkflowStore.Stage.SINGLE
                    ) { throw invalid(); }
        }
        private void requireChild2(SignWorkflowStore.AcceptanceEnvelope envelope,
                SignWorkflowStore.AcceptanceEnvelope childEnvelope, SignWorkflowStore.AcceptanceEnvelope expected) throws IOException {
            if (!expected.providerNamespace().equals(childEnvelope.providerNamespace())
                    || !expected.providerConfigurationCommitment().equals(childEnvelope.providerConfigurationCommitment())
                    || !expected.accessContext().equals(childEnvelope.accessContext())
                    || !expected.keyRef().equals(childEnvelope.keyRef())
                    || !expected.fairnessAuthorityId().equals(childEnvelope.fairnessAuthorityId())
                    || !expected.algorithmId().equals(childEnvelope.algorithmId())
                    || expected.signatureEncoding() != childEnvelope.signatureEncoding()
                    || !envelope.createdAt().equals(childEnvelope.createdAt())
                    ) { throw invalid(); }
        }
        private void requireChild3(CrlHybridExecution execution, SignWorkflowStore.AcceptanceEnvelope envelope,
                SignWorkflowStore.MutableState parentState, SignWorkflowStore.AcceptanceEnvelope childEnvelope) throws IOException {
            if (!envelope.deadline().equals(childEnvelope.deadline()) || parentState.result().isEmpty()
                    || !HexFormat.of().formatHex(SigningFormatSupport.sha256().digest(
                            parentState.result().orElseThrow().bytes())).equals(execution.alternativeSignatureSha256().orElseThrow())) { throw invalid(); }
        }
    }


    private static void recoverDue(CrlHybridExecution execution, RowReader rows, Set<String> suppressed,
            Set<String> resident, String parent, String child) throws IOException {
            if (execution.phase() == SignWorkflowStore.CrlHybridPhase.NATIVE_LINKED) {
                resident.add(child);
                if (terminal(state(rows, child).state())) { suppressed.add(child); }
                else { suppressed.add(parent); }
            }    }

}
