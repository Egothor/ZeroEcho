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
import zeroecho.pki.spi.crypto.SignatureWorkflow.ConfigurationCommitment;

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
        /** Durable intent exists but has not been submitted to the provider. */
        INTENT(10),
        /** Provider submission has a stable downstream operation identifier. */
        DISPATCHED(20),
        /** Provider completed successfully with a trustworthy result. */
        SUCCEEDED(40),
        /** Provider or local processing reached a terminal failure. */
        FAILED(50),
        /** Provider confirmed cancellation. */
        CANCELLED(60),
        /** Terminal evidence is retained without live content ownership. */
        RETIRED(70),
        /** The store-authoritative signing deadline elapsed. */
        EXPIRED(80),
        /** Cancellation is durably requested but provider outcome is not final. */
        CANCELLING(30);

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
     * @param configurationCommitment exact immutable provider configuration
     *                                commitment
     * @param owner             request owner
     * @param createdAt         store-validated creation time
     * @param deadline          request deadline
     * @param request           versioned request continuation; {@link State#EXPIRED}
     *                          and {@link State#RETIRED} retain only immutable
     *                          commitment metadata and no live staged-content owner
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
     * @param failureCount consecutive reconciliation failures, zero when no retry is scheduled
     * @param nextEligibleAt next retry time, present exactly when {@code failureCount} is positive
     * @param reconciliationFailureClass retry classification, paired with {@code nextEligibleAt}
     */
    record Record(PkiId submissionId, String namespace, String fingerprint,
            ConfigurationCommitment configurationCommitment, Principal owner, Instant createdAt,
            Instant deadline, EncodedObject request, State state, long revision, long fence,
            Optional<Instant> leaseUntil, Optional<String> detailCode, Optional<EncodedObject> result,
            Optional<Instant> providerUpdatedAt, int failureCount, Optional<Instant> nextEligibleAt,
            Optional<ReconciliationFailureClass> reconciliationFailureClass) {
        /** Validates immutable state, timing, fencing, and retry-metadata invariants. */
        public Record {
            Objects.requireNonNull(submissionId, "submissionId");
            Objects.requireNonNull(namespace, "namespace");
            Objects.requireNonNull(fingerprint, "fingerprint");
            Objects.requireNonNull(configurationCommitment, "configurationCommitment");
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
            if ((state == State.FAILED || state == State.CANCELLED
                    || state == State.EXPIRED || state == State.RETIRED) && failureCount != 0) {
                throw new IllegalArgumentException("Terminal signing records cannot retain retry metadata");
            }
        }
    }

    /**
     * One ordered signing-record scan result.
     *
     * @param cursor exclusive cursor after this examined metadata candidate
     * @param record decoded signing record, or empty when the candidate was malformed
     */
    record PageCandidate(String cursor, Optional<Record> record) {
        /** Validates one immutable scan result. */
        public PageCandidate {
            Objects.requireNonNull(cursor, "cursor");
            record = Objects.requireNonNull(record, "record");
            if (cursor.isBlank()) {
                throw new IllegalArgumentException("Signing page candidate cursor must not be blank");
            }
            record.ifPresent(value -> {
                if (!cursor.equals(value.submissionId().value())) {
                    throw new IllegalArgumentException("Signing page candidate cursor does not match its record");
                }
            });
        }
    }

    /**
     * One bounded snapshot page ordered by canonical submission identifier.
     *
     * @param records immutable page records
     * @param nextCursor exclusive cursor after the last examined metadata candidate
     * @param examined number of metadata candidates examined for this page
     * @param failures number of malformed candidates among {@code examined}
     * @param endReached whether the snapshot namespace was exhausted
     * @param candidates ordered examined candidates, including malformed entries
     * @param highWatermark greatest record key in the page's stable snapshot
     */
    record Page(List<Record> records, Optional<String> nextCursor, int examined, int failures,
            boolean endReached, List<PageCandidate> candidates, Optional<String> highWatermark) {
        /**
         * Creates a page with explicit candidate detail and no cycle watermark.
         *
         * @param records immutable successfully decoded records
         * @param nextCursor exclusive cursor after the last examined candidate
         * @param examined number of candidates examined
         * @param failures number of malformed candidates
         * @param endReached whether the snapshot namespace was exhausted
         * @param candidates ordered decoded and malformed candidates
         */
        public Page(List<Record> records, Optional<String> nextCursor, int examined, int failures,
                boolean endReached, List<PageCandidate> candidates) {
            this(records, nextCursor, examined, failures, endReached, candidates, Optional.empty());
        }

        /**
         * Creates a page without malformed candidates.
         *
         * @param records immutable successfully decoded records
         * @param nextCursor exclusive cursor after the last examined candidate
         * @param examined number of candidates examined
         * @param failures number of malformed candidates; must be zero for this compatibility constructor
         * @param endReached whether the snapshot namespace was exhausted
         * @deprecated implementations should provide explicit ordered candidate
         *             details so reconciliation can resume precisely after failures
         */
        @Deprecated
        public Page(List<Record> records, Optional<String> nextCursor, int examined, int failures,
                boolean endReached) {
            this(records, nextCursor, examined, failures, endReached,
                    successfulCandidates(records, examined, failures), Optional.empty());
        }

        /** Validates one immutable page. */
        public Page {
            records = List.copyOf(Objects.requireNonNull(records, "records"));
            nextCursor = Objects.requireNonNull(nextCursor, "nextCursor");
            candidates = List.copyOf(Objects.requireNonNull(candidates, "candidates"));
            highWatermark = Objects.requireNonNull(highWatermark, "highWatermark");
            if (examined < records.size() || failures < 0 || failures > examined
                    || records.size() + failures != examined || candidates.size() != examined) {
                throw new IllegalArgumentException("Signing page counts are inconsistent");
            }
            int recordIndex = 0;
            int candidateFailures = 0;
            for (PageCandidate candidate : candidates) {
                if (candidate.record().isEmpty()) {
                    candidateFailures++;
                } else if (recordIndex >= records.size()
                        || !candidate.record().orElseThrow().equals(records.get(recordIndex++))) {
                    throw new IllegalArgumentException("Signing page candidate order is inconsistent");
                }
            }
            if (recordIndex != records.size() || candidateFailures != failures) {
                throw new IllegalArgumentException("Signing page candidate order is inconsistent");
            }
            if (!candidates.isEmpty()
                    && !nextCursor.equals(Optional.of(candidates.getLast().cursor()))) {
                throw new IllegalArgumentException("Signing page cursor is inconsistent");
            }
        }

        private static List<PageCandidate> successfulCandidates(List<Record> records, int examined, int failures) {
            Objects.requireNonNull(records, "records");
            if (failures != 0 || examined != records.size()) {
                throw new IllegalArgumentException("Signing page candidate details are required for failures");
            }
            return records.stream()
                    .map(record -> new PageCandidate(record.submissionId().value(), Optional.of(record)))
                    .toList();
        }
    }

    /** Result of idempotent intent creation. */
    enum CreateResult {
        /** A new durable intent was created. */
        CREATED,
        /** An identical durable intent already existed and was attached. */
        ATTACHED,
        /** The identifier already names a semantically different intent. */
        CONFLICT
    }

    /** Opaque one-shot reservation for one new durable signing workflow. */
    @FunctionalInterface
    interface SignAdmission extends AutoCloseable {
        /**
         * Binds this reservation to the normalized identifier it will create.
         *
         * @param submissionId exact normalized identifier reserved for intent creation
         */
        default void bind(PkiId submissionId) {
            Objects.requireNonNull(submissionId, "submissionId");
            throw new UnsupportedOperationException("Deferred signing admission binding is unsupported");
        }

        /** Releases an unused reservation; repeated calls have no effect. */
        @Override void close();
    }

    /** Stable reason that a store could not reserve a new durable workflow. */
    enum SignAdmissionFailure {
        /** The configured durable workflow bound has been reached. */
        CAPACITY_EXHAUSTED
    }

    /** Typed nonblocking durable-workflow admission rejection. */
    final class SignAdmissionException extends IllegalStateException {
        @java.io.Serial private static final long serialVersionUID = 1L;
        /** Stable capacity-rejection classification. */
        private final SignAdmissionFailure failure;

        /**
         * Creates a stable admission rejection without exposing store diagnostics.
         *
         * @param failure stable capacity-rejection classification
         */
        public SignAdmissionException(SignAdmissionFailure failure) {
            super("Signing workflow capacity is exhausted");
            this.failure = Objects.requireNonNull(failure, "failure");
        }

        /**
         * Returns the stable admission failure classification.
         *
         * @return capacity-rejection classification
         */
        public SignAdmissionFailure failure() {
            return failure;
        }
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
     * Nonblockingly reserves capacity before a submission identifier is created.
     *
     * @return one-shot store-owned admission
     * @throws SignAdmissionException if durable workflow capacity is exhausted
     */
    default SignAdmission reserveSignAdmission() {
        throw new UnsupportedOperationException("Signing admission is unsupported");
    }

    /**
     * Reserves and immediately binds capacity for compatibility callers that
     * already own a normalized identifier.
     *
     * @param submissionId identifier that the later intent must use
     * @return one-shot store-owned admission
     */
    @SuppressWarnings("PMD.UseTryWithResources") // A successfully bound admission is returned to its caller.
    default SignAdmission reserveSignAdmission(PkiId submissionId) {
        SignAdmission admission = reserveSignAdmission();
        boolean bound = false;
        try {
            admission.bind(Objects.requireNonNull(submissionId, "submissionId"));
            bound = true;
            return admission;
        } finally {
            if (!bound) {
                admission.close();
            }
        }
    }

    /**
     * Creates an INTENT using a previously reserved store-owned admission.
     *
     * @param admission one-shot admission bound to the intent identifier
     * @param intent revision-zero INTENT
     * @return creation result
     */
    default CreateResult createSignIntent(SignAdmission admission, Record intent) {
        Objects.requireNonNull(admission, "admission");
        try (admission) {
            return createSignIntent(intent);
        }
    }

    /**
     * Atomically creates a signing intent, staged-content owner, and its
     * domain-owned outer continuation in one metadata-ledger transaction.
     *
     * @param admission one-shot admission bound to the shared identifier
     * @param intent revision-zero signing intent
     * @param continuation revision-zero outer continuation with the same id
     * @return idempotent creation result
     */
    default CreateResult createSignIntent(SignAdmission admission, Record intent,
            DomainContinuationStore.Record continuation) {
        Objects.requireNonNull(continuation, "continuation");
        if (!intent.submissionId().equals(continuation.operationId())) {
            throw new IllegalArgumentException("Signing and domain continuation identifiers differ");
        }
        throw new UnsupportedOperationException("Atomic domain continuation creation is unsupported");
    }

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
     * Selects bounded reconciliation work ordered by its durable eligibility time.
     * Implementations without an ordered projection retain compatibility through
     * this bounded-result fallback; production stores should override it.
     *
     * @param cutoffInclusive latest eligible retry time
     * @param maximumRecords result bound from 1 through 4096
     * @return due records in deterministic reconciliation order
     */
    default List<Record> selectDueSignRecords(Instant cutoffInclusive, int maximumRecords) {
        Objects.requireNonNull(cutoffInclusive, "cutoffInclusive");
        if (maximumRecords < 1 || maximumRecords > 4096) {
            throw new IllegalArgumentException("maximumRecords must be between 1 and 4096");
        }
        return listSignRecords().stream()
                .filter(record -> record.state() != State.RETIRED)
                .filter(record -> record.nextEligibleAt()
                        .map(eligible -> !eligible.isAfter(cutoffInclusive)).orElse(true))
                .limit(maximumRecords).toList();
    }

    /**
     * Returns at most {@code maximumRecords} records after an advisory exclusive
     * cursor, ordered by canonical submission identifier.
     *
     * @param exclusiveCursor opaque cursor from an earlier page
     * @param maximumRecords page bound from 1 through 4096
     * @param cancellation cooperative scan cancellation
     * @return bounded snapshot page whose ordered candidates retain a cursor for
     *         every successfully decoded or malformed metadata entry
     */
    Page pageSignRecords(Optional<String> exclusiveCursor, int maximumRecords,
            zeroecho.core.io.CancellationSignal cancellation);

    /**
     * Returns a page capped at an inclusive stable cycle high-watermark.
     *
     * @param exclusiveCursor opaque cursor from an earlier page
     * @param inclusiveHighWatermark greatest key eligible for this cycle
     * @param maximumRecords page bound from 1 through 4096
     * @param cancellation cooperative scan cancellation
     * @return bounded snapshot page
     */
    default Page pageSignRecords(Optional<String> exclusiveCursor, Optional<String> inclusiveHighWatermark,
            int maximumRecords, zeroecho.core.io.CancellationSignal cancellation) {
        return pageSignRecords(exclusiveCursor, maximumRecords, cancellation);
    }

    /**
     * Returns an identity-ordered page of records eligible for reconciliation at
     * {@code cutoffInclusive}. The default preserves compatibility with stores
     * that have no eligibility projection; production stores should override it.
     * For nonempty indexed work {@code W} and {@code R} returned records, define
     * {@code D = max(1, R)}, so {@code 1 <= D <= W}; the page-bound worst case uses
     * {@code D = min(maximumRecords, W)}. A production identity-ordered
     * implementation then has worst-case
     * {@code Theta(log W + D + D log(W / D))} selection time, returns
     * {@code O(D)} immutable page memory, and uses {@code O(D + log W)} total
     * auxiliary memory. An empty index returns an empty page in constant time and
     * memory. The cursor and high-watermark do not change these bounds or the
     * stable cycle semantics.
     *
     * @param cutoffInclusive latest eligible retry time
     * @param exclusiveCursor advisory exclusive identity cursor
     * @param inclusiveHighWatermark optional stable cycle upper bound
     * @param maximumRecords page bound from 1 through 4096
     * @param cancellation cooperative cancellation
     * @return bounded eligible page with ordered malformed diagnostics
     */
    default Page pageDueSignRecords(Instant cutoffInclusive, Optional<String> exclusiveCursor,
            Optional<String> inclusiveHighWatermark, int maximumRecords,
            zeroecho.core.io.CancellationSignal cancellation) {
        Objects.requireNonNull(cutoffInclusive, "cutoffInclusive");
        return pageSignRecords(exclusiveCursor, inclusiveHighWatermark,
                maximumRecords, cancellation);
    }

    /**
     * Defers reconciliation with store-authoritative exponential backoff.
     *
     * @param submissionId stable submission identifier
     * @param expectedRevision caller-observed record revision
     * @param fence current fencing token
     * @param failureClass stable retry classification used to calculate backoff
     * @return updated record, or empty when the revision/fence CAS loses
     */
    Optional<Record> deferSignReconciliation(PkiId submissionId, long expectedRevision, long fence,
            ReconciliationFailureClass failureClass);

    /**
     * Clears durable retry metadata against the current revision and fence.
     *
     * @param submissionId stable submission identifier
     * @param expectedRevision caller-observed record revision
     * @param fence current fencing token
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
     * A transition to {@link State#EXPIRED} atomically removes live continuation
     * content and its owner edge while preserving the terminal state as
     * {@code EXPIRED}. Implementations decide a concurrent terminal transition at
     * its durable WAL-admission linearization point: admission strictly before the
     * deadline wins even when durability acknowledgement finishes later, while
     * admission at or after the deadline atomically selects {@code EXPIRED}.
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
     *                          cancellation, and required to be strictly before the
     *                          request deadline
     * @return transitioned record, or empty when compare-and-set loses
     */
    Optional<Record> transitionSign(PkiId submissionId, long expectedRevision, long fence, State target,
            Optional<String> detailCode, Optional<EncodedObject> result, Optional<Instant> providerUpdatedAt);

    /**
     * Atomically retires a terminal current record while retaining its identity and
     * any successful result. An already content-free {@link State#EXPIRED} record
     * remains {@code EXPIRED}; cleanup does not rewrite its terminal outcome.
     * Non-terminal records, including {@link State#CANCELLING}, are not retirable.
     *
     * @param submissionId     stable submission identifier
     * @param expectedRevision caller-observed revision
     * @param fence            current fencing token
     * @return retired record, or empty when compare-and-set loses
     */
    Optional<Record> retireSign(PkiId submissionId, long expectedRevision, long fence);

    /**
     * Performs one bounded purge pass for content-free expired or retired records
     * after the configured horizon. Active and cancellation-pending provider
     * operations must be retained for reconciliation. Callers repeat this method on
     * later maintenance passes to converge when more eligible records remain.
     *
     * @return number of records purged by this pass
     */
    int purgeExpiredSignRecords();
}
