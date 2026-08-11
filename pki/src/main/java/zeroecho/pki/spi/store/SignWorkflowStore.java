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
package zeroecho.pki.spi.store;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.Principal;

/**
 * Authoritative durable state machine for signing submissions.
 *
 * <p>
 * Implementations must provide atomic per-operation compare-and-set behavior.
 * External signer, callback, and audit code must never run while an
 * implementation holds its coordination lock. Different submission identifiers
 * must not share a permanent global mutation lock.
 * </p>
 *
 * <p>
 * Retained records are the source of truth through {@link #signingHorizon()}.
 * Purging a record does not make its stable identifier reusable because
 * creation validates the identifier timestamp against the same horizon.
 * </p>
 */
public interface SignWorkflowStore {

    /** Durable classification for one deferred reconciliation retry. */
    enum ReconciliationFailureClass {
        /** Submission may have been accepted. */
        SUBMISSION_UNCERTAIN,
        /** Provider status could not be obtained. */
        STATUS_UNAVAILABLE,
        /** Provider cancellation outcome is uncertain. */
        CANCELLATION_UNCERTAIN,
        /** Local durable reconciliation failed. */
        LOCAL_FAILURE
    }

    /**
     * Signing orchestration states.
     *
     * <p>
     * {@link #CANCELLING} is authoritative and non-terminal: it records that
     * cancellation was requested before the provider is called. A provider result
     * observed while cancelling must still be reconciled before retirement.
     * Persistent codes are stable and independent of declaration order.
     * </p>
     */
    enum State {
        INTENT(10), DISPATCHED(20), SUCCEEDED(40), FAILED(50), CANCELLED(60), RETIRED(70), EXPIRED(80), CANCELLING(30);

        private final int persistentCode;

        State(int persistentCode) {
            this.persistentCode = persistentCode;
        }

        /**
         * Returns the stable filesystem persistence code.
         *
         * @return stable positive code
         */
        public int persistentCode() {
            return persistentCode;
        }

        /**
         * Resolves a current stable persistence code.
         *
         * @param code persisted code
         * @return matching state
         * @throws IllegalArgumentException if the code is unknown
         */
        public static State fromPersistentCode(int code) {
            return switch (code) {
                case 10 -> INTENT;
                case 20 -> DISPATCHED;
                case 30 -> CANCELLING;
                case 40 -> SUCCEEDED;
                case 50 -> FAILED;
                case 60 -> CANCELLED;
                case 70 -> RETIRED;
                case 80 -> EXPIRED;
                default -> throw new IllegalArgumentException("Unknown signing workflow state code: " + code);
            };
        }
    }

    /**
     * Complete durable signing state.
     *
     * @param submissionId      stable submission identifier
     * @param namespace         provider/store namespace
     * @param fingerprint       versioned semantic request fingerprint
     * @param owner             request owner
     * @param createdAt         store-validated creation time
     * @param deadline          request deadline
     * @param request           versioned request continuation
     * @param state             lifecycle state
     * @param revision          monotonic record revision
     * @param fence             monotonic claim fencing token
     * @param leaseUntil        optional active claim lease
     * @param detailCode        optional non-sensitive detail code
     * @param result            optional terminal signature result
     * @param providerUpdatedAt optional durable provider terminal-transition time;
     *                          the provider clock may be independent of the store
     *                          clock, but successful completion must be strictly
     *                          before {@code deadline}
     */
    record Record(PkiId submissionId, String namespace, String fingerprint, Principal owner, Instant createdAt,
            Instant deadline, EncodedObject request, State state, long revision, long fence,
            Optional<Instant> leaseUntil, Optional<String> detailCode, Optional<EncodedObject> result,
            Optional<Instant> providerUpdatedAt, int failureCount, Optional<Instant> nextEligibleAt,
            Optional<ReconciliationFailureClass> reconciliationFailureClass) {
        public Record {
            Objects.requireNonNull(submissionId, "submissionId");
            Objects.requireNonNull(namespace, "namespace");
            Objects.requireNonNull(fingerprint, "fingerprint");
            Objects.requireNonNull(owner, "owner");
            Objects.requireNonNull(createdAt, "createdAt");
            Objects.requireNonNull(deadline, "deadline");
            Objects.requireNonNull(request, "request");
            Objects.requireNonNull(state, "state");
            Objects.requireNonNull(leaseUntil, "leaseUntil");
            Objects.requireNonNull(detailCode, "detailCode");
            Objects.requireNonNull(result, "result");
            Objects.requireNonNull(providerUpdatedAt, "providerUpdatedAt");
            Objects.requireNonNull(nextEligibleAt, "nextEligibleAt");
            Objects.requireNonNull(reconciliationFailureClass, "reconciliationFailureClass");
            if (namespace.isBlank() || fingerprint.isBlank()) {
                throw new IllegalArgumentException("namespace and fingerprint must not be blank");
            }
            if (deadline.isBefore(createdAt)) {
                throw new IllegalArgumentException("deadline must not be before createdAt");
            }
            if (revision < 0L || fence < 0L) {
                throw new IllegalArgumentException("revision and fence must not be negative");
            }
            boolean retryMetadataPresent = nextEligibleAt.isPresent() && reconciliationFailureClass.isPresent();
            if (failureCount < 0 || failureCount == 0 != !retryMetadataPresent) {
                throw new IllegalArgumentException("Reconciliation retry metadata is inconsistent");
            }
            if ((state == State.SUCCEEDED || state == State.FAILED || state == State.CANCELLED
                    || state == State.EXPIRED || state == State.RETIRED) && failureCount != 0) {
                throw new IllegalArgumentException("Terminal signing records cannot retain retry metadata");
            }
        }
    }

    /**
     * One bounded snapshot page ordered by canonical submission identifier.
     *
     * @param records immutable page records
     * @param nextCursor exclusive cursor after the last returned record
     * @param endReached whether the snapshot namespace was exhausted
     */
    record Page(List<Record> records, Optional<String> nextCursor, int examined, int failures,
            boolean endReached) {
        /** Validates one immutable page. */
        public Page {
            records = List.copyOf(Objects.requireNonNull(records, "records"));
            nextCursor = Objects.requireNonNull(nextCursor, "nextCursor");
            if (examined < records.size() || failures < 0 || failures > examined
                    || records.size() + failures != examined) {
                throw new IllegalArgumentException("Signing page counts are inconsistent");
            }
        }
    }

    /** Result of idempotent intent creation. */
    enum CreateResult {
        CREATED, ATTACHED, CONFLICT
    }

    /**
     * Returns store-authoritative time.
     *
     * @return current store time
     */
    Instant signingNow();

    /**
     * Returns the stable trusted namespace owned by this store.
     *
     * @return namespace persisted for the lifetime of the store
     */
    String signingNamespace();

    /**
     * Returns configured retention/identity horizon.
     *
     * @return positive horizon
     */
    Duration signingHorizon();

    /**
     * Returns the accepted future clock skew for signing identifiers.
     *
     * @return non-negative permitted skew
     */
    Duration signingPermittedSkew();

    /**
     * Creates an INTENT or attaches to an identical existing record.
     *
     * @param intent revision-zero INTENT
     * @return creation result
     */
    CreateResult createSignIntent(Record intent);

    /**
     * Returns authoritative state for an identifier.
     *
     * @param submissionId stable submission identifier
     * @return retained state, or empty when unknown or purged
     */
    Optional<Record> getSignRecord(PkiId submissionId);

    /**
     * Returns a stable snapshot of retained signing records.
     *
     * @return retained records
     */
    List<Record> listSignRecords();

    /**
     * Returns at most {@code maximumRecords} records after an advisory exclusive
     * cursor, ordered by canonical submission identifier.
     *
     * @param exclusiveCursor opaque cursor from an earlier page
     * @param maximumRecords page bound from 1 through 4096
     * @param cancellation cooperative scan cancellation
     * @return bounded snapshot page
     */
    Page pageSignRecords(Optional<String> exclusiveCursor, int maximumRecords,
            zeroecho.core.io.CancellationSignal cancellation);

    /**
     * Defers reconciliation with store-authoritative exponential backoff.
     *
     * @return updated record, or empty when the revision/fence CAS loses
     */
    Optional<Record> deferSignReconciliation(PkiId submissionId, long expectedRevision, long fence,
            ReconciliationFailureClass failureClass);

    /**
     * Clears durable retry metadata against the current revision and fence.
     *
     * @return updated record, or empty when the revision/fence CAS loses
     */
    Optional<Record> clearSignReconciliation(PkiId submissionId, long expectedRevision, long fence);

    /**
     * Atomically claims an intent and increments its revision and fencing token.
     *
     * @param submissionId     stable submission identifier
     * @param expectedRevision caller-observed revision
     * @param lease            positive claim duration
     * @return claimed record, or empty when compare-and-set loses
     */
    Optional<Record> tryClaimSign(PkiId submissionId, long expectedRevision, Duration lease);

    /**
     * Atomically renews an owned lease.
     *
     * @param submissionId     stable submission identifier
     * @param expectedRevision caller-observed revision
     * @param fence            current fencing token
     * @param lease            positive renewal duration
     * @return renewed record, or empty when compare-and-set loses
     */
    Optional<Record> renewSignClaim(PkiId submissionId, long expectedRevision, long fence, Duration lease);

    /**
     * Atomically transitions state when revision and fence are current.
     *
     * <p>
     * Cancellation follows {@code INTENT|DISPATCHED -> CANCELLING ->
     * CANCELLED|SUCCEEDED|FAILED|EXPIRED}. The intermediate state must be durable
     * before a provider cancellation call. A {@code CANCELLING -> CANCELLING}
     * transition records that the external cancellation submission returned,
     * without treating provider acceptance as terminal.
     * </p>
     *
     * @param submissionId      stable submission identifier
     * @param expectedRevision  caller-observed revision
     * @param fence             current fencing token
     * @param target            allowed target state
     * @param detailCode        optional non-sensitive detail
     * @param result            signature result, required only for success
     * @param providerUpdatedAt durable provider terminal-transition time from the
     *                          provider clock domain; required for success and
     *                          required to be strictly before the request deadline
     * @return transitioned record, or empty when compare-and-set loses
     */
    Optional<Record> transitionSign(PkiId submissionId, long expectedRevision, long fence, State target,
            Optional<String> detailCode, Optional<EncodedObject> result, Optional<Instant> providerUpdatedAt);

    /**
     * Atomically retires a terminal current record while retaining its identity and
     * any successful result. Non-terminal records, including
     * {@link State#CANCELLING}, are not retirable.
     *
     * @param submissionId     stable submission identifier
     * @param expectedRevision caller-observed revision
     * @param fence            current fencing token
     * @return retired record, or empty when compare-and-set loses
     */
    Optional<Record> retireSign(PkiId submissionId, long expectedRevision, long fence);

    /**
     * Purges retired payload-bearing records after the configured horizon.
     * Non-retired records, including active and cancellation-pending provider
     * operations, must be retained for reconciliation.
     *
     * @return number of purged records
     */
    int purgeExpiredSignRecords();
}
