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

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.TreeMap;

/** Compact retention ordering over canonical identities owned by the work projection. */
@SuppressWarnings({ "PMD.AvoidLiteralsInIfCondition", "PMD.CloseResource",
        "PMD.CommentRequired", "PMD.CompareObjectsWithEquals", "PMD.ConfusingTernary",
        "PMD.ControlStatementBraces", "PMD.CyclomaticComplexity", "PMD.NPathComplexity",
        "PMD.PrematureDeclaration", "PMD.UseTryWithResources" })
final class SigningRetentionIndex implements AutoCloseable {
    /* Hash node, tree node, key/slot objects, timestamp and alignment. */
    private static final long DESCRIPTOR_BYTES = 160L;

    private final int maximumRecords;
    private final SigningIndexCapacityBudget capacity;
    private final NavigableMap<RetentionKey, DescriptorSlot> ordered = new TreeMap<>();
    private final Map<SigningDueWorkIndex.CanonicalOperationId, OperationSlot> byOperation =
            new HashMap<>();
    private long reservedBytes;
    private boolean closed;

    /* default */ SigningRetentionIndex(int maximumRecords,
            SigningIndexCapacityBudget capacity) {
        if (maximumRecords <= 0
                || maximumRecords > SigningDueWorkIndex.FOUR_GIB_ORDERED_LIMIT) {
            throw new IllegalArgumentException("signing retention capacity is invalid");
        }
        this.maximumRecords = maximumRecords;
        this.capacity = Objects.requireNonNull(capacity, "capacity");
    }

    /* default */ PreparedChange prepareRetained(
            SigningDueWorkIndex.CanonicalOperationId operationId, Instant createdAt) {
        return prepareRetained(operationId, createdAt,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /* default */ PreparedChange prepareRetained(
            SigningDueWorkIndex.CanonicalOperationId operationId, Instant createdAt,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(admissionClass, "admissionClass");
        requireOpen();
        OperationSlot operationSlot = byOperation.get(operationId);
        requireReusedIdentity(operationId, operationSlot);
        RetentionKey previous = operationSlot == null ? null : operationSlot.published;
        if (operationSlot != null && operationSlot.pending) {
            throw new IllegalStateException("signing retention operation already has a prepared change");
        }
        if (previous == null && byOperation.size() >= maximumRecords) {
            throw new IllegalStateException("signing retention capacity is exhausted");
        }
        long delta = previous == null ? DESCRIPTOR_BYTES : 0L;
        SigningIndexCapacityBudget.Reservation reservation =
                capacity.reserve(delta, admissionClass);
        boolean transferred = false;
        try {
            RetentionKey replacement = new RetentionKey(createdAt, operationId);
            DescriptorSlot previousSlot = previous == null ? null : ordered.get(previous);
            if (previous != null && (previousSlot == null || !previousSlot.published)) {
                throw new IllegalStateException("signing retention index is inconsistent");
            }
            DescriptorSlot replacementSlot = ordered.get(replacement);
            boolean inserted = false;
            if (replacementSlot == null) {
                replacementSlot = new DescriptorSlot();
                ordered.put(replacement, replacementSlot);
                inserted = true;
            } else if (replacementSlot != previousSlot || replacementSlot.pending) {
                throw new IllegalStateException("signing retention ordering identity is duplicated");
            }
            if (operationSlot == null) {
                operationSlot = new OperationSlot(operationId);
                byOperation.put(operationId, operationSlot);
            }
            operationSlot.pending = true;
            replacementSlot.pending = true;
            PreparedChange result = new PreparedChange(operationSlot, previous, previousSlot,
                    replacement, replacementSlot, inserted, delta, reservation);
            transferred = true;
            return result;
        } finally {
            if (!transferred) reservation.close();
        }
    }

    /* default */ PreparedChange prepareRemove(
            SigningDueWorkIndex.CanonicalOperationId operationId) {
        Objects.requireNonNull(operationId, "operationId");
        requireOpen();
        OperationSlot slot = byOperation.get(operationId);
        requireReusedIdentity(operationId, slot);
        if (slot == null || slot.published == null) return new PreparedChange();
        if (slot.pending) {
            throw new IllegalStateException("signing retention operation already has a prepared change");
        }
        DescriptorSlot previous = ordered.get(slot.published);
        if (previous == null || !previous.published) {
            throw new IllegalStateException("signing retention index is inconsistent");
        }
        slot.pending = true;
        return new PreparedChange(slot, slot.published, previous, null, null,
                false, -DESCRIPTOR_BYTES, null);
    }

    /* default */ boolean contains(SigningDueWorkIndex.CanonicalOperationId operationId) {
        OperationSlot slot = byOperation.get(Objects.requireNonNull(operationId, "operationId"));
        requireReusedIdentity(operationId, slot);
        return slot != null && slot.published != null;
    }

    /* default */ List<String> selectThrough(Instant cutoffInclusive, int maximumResults) {
        Objects.requireNonNull(cutoffInclusive, "cutoffInclusive");
        if (maximumResults <= 0) {
            throw new IllegalArgumentException("signing retention selection bound is invalid");
        }
        requireOpen();
        List<String> result = new ArrayList<>(Math.min(maximumResults, ordered.size()));
        for (Map.Entry<RetentionKey, DescriptorSlot> entry : ordered.entrySet()) {
            if (entry.getKey().createdAt.isAfter(cutoffInclusive)
                    || result.size() == maximumResults) break;
            if (entry.getValue().published) {
                result.add(entry.getKey().operationId.value());
            }
        }
        return List.copyOf(result);
    }

    /* default */ int size() { return byOperation.size(); }

    /* default */ Statistics statistics() {
        requireOpen();
        return new Statistics(byOperation.size(), reservedBytes);
    }

    @Override public void close() {
        if (closed) return;
        closed = true;
        if (reservedBytes > 0L) capacity.releaseCommitted(reservedBytes);
        reservedBytes = 0L;
        ordered.clear();
        byOperation.clear();
    }

    private void requireOpen() {
        if (closed) throw new IllegalStateException("signing retention index is closed");
    }

    private static void requireReusedIdentity(SigningDueWorkIndex.CanonicalOperationId supplied,
            OperationSlot existing) {
        if (existing != null && existing.operationId != supplied) {
            throw new IllegalArgumentException("signing operation identity object was not reused");
        }
    }

    /* default */ record Statistics(int records, long reservedBytes) {
    }

    private record RetentionKey(Instant createdAt,
            SigningDueWorkIndex.CanonicalOperationId operationId)
            implements Comparable<RetentionKey> {
        @Override public int compareTo(RetentionKey other) {
            int time = createdAt.compareTo(other.createdAt);
            return time != 0 ? time : operationId.compareTo(other.operationId);
        }
    }

    private static final class OperationSlot {
        private final SigningDueWorkIndex.CanonicalOperationId operationId;
        private RetentionKey published;
        private boolean pending;
        private OperationSlot(SigningDueWorkIndex.CanonicalOperationId operationId) {
            this.operationId = operationId;
        }
    }

    private static final class DescriptorSlot {
        private boolean published;
        private boolean pending;
    }

    /** Rollback-capable retention replacement prepared before WAL admission. */
    /* default */ final class PreparedChange implements AutoCloseable {
        private final OperationSlot operationSlot;
        private final RetentionKey previousKey;
        private final DescriptorSlot previousSlot;
        private final RetentionKey replacementKey;
        private final DescriptorSlot replacementSlot;
        private final boolean insertedReplacement;
        private final long byteDelta;
        private final SigningIndexCapacityBudget.Reservation reservation;
        private boolean active;

        private PreparedChange(OperationSlot operationSlot, RetentionKey previousKey,
                DescriptorSlot previousSlot, RetentionKey replacementKey,
                DescriptorSlot replacementSlot, boolean insertedReplacement, long byteDelta,
                SigningIndexCapacityBudget.Reservation reservation) {
            this.operationSlot = operationSlot;
            this.previousKey = previousKey;
            this.previousSlot = previousSlot;
            this.replacementKey = replacementKey;
            this.replacementSlot = replacementSlot;
            this.insertedReplacement = insertedReplacement;
            this.byteDelta = byteDelta;
            this.reservation = reservation;
            active = operationSlot != null;
        }

        private PreparedChange() {
            this(null, null, null, null, null, false, 0L, null);
        }

        /* default */ void publish() {
            if (!active) return;
            requireOpen();
            if (!operationSlot.pending) {
                throw new IllegalStateException("signing retention prepared ownership is inconsistent");
            }
            if (replacementKey == null) {
                previousSlot.published = false;
                ordered.remove(previousKey, previousSlot);
                operationSlot.published = null;
                byOperation.remove(operationSlot.operationId, operationSlot);
                reservedBytes += byteDelta;
                capacity.releaseCommitted(-byteDelta);
            } else {
                replacementSlot.pending = false;
                replacementSlot.published = true;
                if (previousSlot != null && previousSlot != replacementSlot) {
                    previousSlot.published = false;
                    ordered.remove(previousKey, previousSlot);
                }
                operationSlot.published = replacementKey;
                if (previousKey == null) {
                    reservedBytes = Math.addExact(reservedBytes, byteDelta);
                    reservation.transfer();
                }
            }
            operationSlot.pending = false;
            active = false;
            if (reservation != null) reservation.close();
        }

        @Override public void close() {
            if (!active) return;
            active = false;
            operationSlot.pending = false;
            if (replacementSlot != null) replacementSlot.pending = false;
            if (insertedReplacement) ordered.remove(replacementKey, replacementSlot);
            if (operationSlot.published == null) {
                byOperation.remove(operationSlot.operationId, operationSlot);
            }
            if (reservation != null) reservation.close();
        }
    }
}
