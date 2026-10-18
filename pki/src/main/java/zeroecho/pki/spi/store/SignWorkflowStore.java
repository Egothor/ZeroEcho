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
package zeroecho.pki.spi.store;

import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.spi.crypto.SigningProvider.ConfigurationCommitment;
import zeroecho.pki.spi.crypto.SigningProvider.DetailCode;
import zeroecho.pki.spi.crypto.SigningProvider.ObservationState;

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
@SuppressWarnings("PMD.AvoidLiteralsInIfCondition")
public interface SignWorkflowStore { // NOPMD - ExcessivePublicCount: nested values form one atomic workflow persistence contract.

    /**
     * Immutable scheduling identity used to route one signing workflow.
     * Diagnostic rendering deliberately redacts both routing coordinates.
     *
     * @param keyRef opaque signing-key route
     * @param fairnessAuthorityId opaque authority used by the scheduling policy
     */
    record SchedulingCoordinates(KeyRef keyRef, PkiId fairnessAuthorityId) {
        /** Validates the required scheduling coordinates. */
        public SchedulingCoordinates {
            Objects.requireNonNull(keyRef, "keyRef");
            Objects.requireNonNull(fairnessAuthorityId, "fairnessAuthorityId");
        }

        @Override
        public String toString() {
            return "SchedulingCoordinates[keyRef=<redacted>, fairnessAuthorityId=<redacted>]";
        }
    }

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

    /** Atomic durable acceptance disposition. */
    enum AcceptanceResult {
        /** A new envelope and initial state were committed. */
        ACCEPTED,
        /** The exact immutable acceptance was already committed. */
        ATTACHED_EXISTING,
        /** The operation or candidate is committed to different immutable input. */
        CONFLICT,
        /** No durable acceptance occurred because the active-work bound was full. */
        CAPACITY_REJECTED
    }

    /** Authoritative resolution of a potentially uncertain acceptance commit. */
    enum AcceptanceResolution {
        /** The exact acceptance commitment is durably present. */
        MATCHED,
        /** The operation identifier names different immutable input. */
        CONFLICT,
        /** No acceptance exists for the identifier. */
        NOT_ACCEPTED
    }

    /**
     * Canonical, non-secret commitment to one complete acceptance command.
     * Instances compare their digest bytes in constant time and never expose the
     * digest through diagnostics.
     */
    final class AcceptanceCommitment {
        private static final String PREFIX = "accept-sign:v3:";
        private final byte[] digest;

        private AcceptanceCommitment(byte[] digest) {
            this.digest = Objects.requireNonNull(digest, "digest").clone();
            if (this.digest.length != 32) {
                throw new IllegalArgumentException("Acceptance commitment must be SHA-256");
            }
        }

        /**
         * Restores a canonical current-version commitment.
         * @param encoded exact {@code accept-sign:v3:} representation with a lowercase SHA-256 digest
         * @return immutable parsed commitment
         * @throws IllegalArgumentException if the representation is not canonical
         */
        public static AcceptanceCommitment parse(String encoded) {
            String exact = Objects.requireNonNull(encoded, "encoded");
            if (!exact.matches("accept-sign:v3:[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Acceptance commitment is not canonical");
            }
            return new AcceptanceCommitment(HexFormat.of().parseHex(exact.substring(PREFIX.length())));
        }

        /** {@return the versioned persistence representation} */
        public String encoded() {
            return PREFIX + HexFormat.of().formatHex(digest);
        }

        /**
         * Compares digest bytes in constant time.
         * @param other another commitment, or null
         * @return true if the non-null commitment has identical digest bytes
         */
        public boolean matches(AcceptanceCommitment other) {
            return other != null && MessageDigest.isEqual(digest, other.digest);
        }

        @Override public boolean equals(Object other) {
            return other instanceof AcceptanceCommitment commitment && matches(commitment);
        }

        @Override public int hashCode() {
            return Arrays.hashCode(digest);
        }

        @Override public String toString() {
            return "AcceptanceCommitment[redacted]";
        }
    }

    /**
     * Immutable outer-operation input paired atomically with signing acceptance.
     *
     * @param kind outer domain kind
     * @param correlationId mandatory bounded idempotency identity
     * @param command exact bounded command
     * @param commandCommitment canonical command commitment
     */
    record OuterCommand(DomainContinuationStore.Kind kind, String correlationId,
            EncodedObject command, String commandCommitment) {
        /** Validates and snapshots the bounded outer command. */
        public OuterCommand {
            Objects.requireNonNull(kind, "kind");
            if (correlationId == null || !correlationId.matches("[a-z0-9][a-z0-9._:-]{0,127}")) {
                throw new IllegalArgumentException("Outer correlation identity is invalid");
            }
            EncodedObject exact = Objects.requireNonNull(command, "command");
            command = new EncodedObject(exact.encoding(), exact.bytes());
            if (command.bytes().length == 0 || command.bytes().length > 1_048_576
                    || commandCommitment == null
                    || !commandCommitment.matches("domain:v1:[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Outer command is invalid");
            }
        }
    }

    /**
     * Durable stage of a parent-owned CA subject proof or ordinary signing.
     * Stable codes are part of the current strict codec.
     * Provider success in {@link #CA_PROOF} cannot mean parent signing success.
     */
    enum Stage {
        /** One ordinary signing step, including root self-signatures. */
        SINGLE(10),
        /** The distinct subject-key proof provider step is current. */
        CA_PROOF(20),
        /** A retained proof signature awaits local cryptographic verification. */
        CA_PROOF_VERIFYING(30),
        /** Proof verification succeeded; certificate dispatch has not started. */
        CA_CERTIFICATE_READY(40),
        /** The parent's final certificate provider step is current. */
        CA_CERTIFICATE(50);

        private final int persistentCode;
        Stage(int persistentCode) { this.persistentCode = persistentCode; }
        /** {@return the stable current-format stage code} */
        public int persistentCode() { return persistentCode; }
        /**
         * Restores a stage.
         * @param code stable current-format discriminator
         * @return decoded enum value
         * @throws IllegalArgumentException if the discriminator is unknown
         */
        public static Stage fromPersistentCode(int code) {
            return switch (code) {
                case 10 -> SINGLE;
                case 20 -> CA_PROOF;
                case 30 -> CA_PROOF_VERIFYING;
                case 40 -> CA_CERTIFICATE_READY;
                case 50 -> CA_CERTIFICATE;
                default -> throw new IllegalArgumentException("Unknown signing stage");
            };
        }
        /** {@return whether scheduling still uses the proof key} */
        public boolean usesProofKey() { return this == CA_PROOF || this == CA_PROOF_VERIFYING; }
    }

    /**
     * Immutable structural descriptor of a parent-owned internal CA proof step.
     * It owns no resource and grants no admission, provider or content authority.
     * The owning store must subsequently validate the staged reference and bind
     * the challenge to the parent intent, deadline, nonce and final TBS/SPKI.
     * Algorithm text is preserved exactly without installed-codec resolution.
     * Preparation/runtime authority must require SIGNATURE kind and exact canonical
     * identity before execution. The descriptor is bound to the one parent
     * acceptance commitment and does not create another workflow.
     *
     * @param operationId distinct canonical provider-step identifier
     * @param subjectKeyRef exact subject key, at most 1 MiB of strict UTF-8
     * @param algorithmId exact nonblank algorithm text, at most 8,192 strict UTF-8 bytes
     * @param challenge staged binary operation challenge, validated by its store later
     */
    record CaSubjectProofStep(PkiId operationId, KeyRef subjectKeyRef,
            String algorithmId, DurableContentReference challenge) {
        /** Existing managed-proof challenge bound: command + SPKI + framing. */
        public static final int MAXIMUM_CHALLENGE_BYTES = 2 * 1_048_576 + 8192;

        /**
         * Validates structural bounds without reading content or resolving keys.
         * @throws NullPointerException if a coordinate is null
         * @throws IllegalArgumentException if identity, algorithm or challenge shape is invalid
         */
        public CaSubjectProofStep {
            requireCanonicalOperation(Objects.requireNonNull(operationId, "operationId"));
            Objects.requireNonNull(subjectKeyRef, "subjectKeyRef");
            Objects.requireNonNull(algorithmId, "algorithmId");
            Objects.requireNonNull(challenge, "challenge");
            if (subjectKeyRef.value().length() > 1_048_576 || subjectKeyRef.utf8Length() > 1_048_576) {
                throw new IllegalArgumentException("CA subject proof key exceeds its bound");
            }
            byte[] keyBytes = subjectKeyRef.value().getBytes(StandardCharsets.UTF_8);
            if (!new String(keyBytes, StandardCharsets.UTF_8).equals(subjectKeyRef.value())) {
                throw new IllegalArgumentException("CA subject proof key is not strict UTF-8");
            }
            if (algorithmId.isBlank() || algorithmId.length() > 8192) {
                throw new IllegalArgumentException("CA subject proof algorithm text is invalid");
            }
            byte[] algorithmBytes = algorithmId.getBytes(StandardCharsets.UTF_8);
            if (algorithmBytes.length > 8192
                    || !new String(algorithmBytes, StandardCharsets.UTF_8).equals(algorithmId)
                    || challenge.encoding() != Encoding.BINARY
                    || challenge.lifecycle() != DurableContentReference.Lifecycle.OPERATION
                    || challenge.length() <= 0 || challenge.length() > MAXIMUM_CHALLENGE_BYTES
                    || challenge.sha256() == null || !challenge.sha256().matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("CA subject proof step is invalid");
            }
        }

        /**
         * Requires a distinct parent identifier in the same provider namespace.
         * Timestamp admission and accepted-deadline validation belong to the store.
         * @param parentId canonical parent signing identifier
         * @throws NullPointerException if the parent is null
         * @throws IllegalArgumentException if it equals this step or has another namespace
         */
        public void requireParent(PkiId parentId) {
            SigningSubmissionId parent = requireCanonicalOperation(Objects.requireNonNull(parentId, "parentId"));
            if (operationId.equals(parentId)
                    || !SigningSubmissionId.parse(operationId).namespace().equals(parent.namespace())) {
                throw new IllegalArgumentException("CA subject proof parent identity is invalid");
            }
        }

        private static SigningSubmissionId requireCanonicalOperation(PkiId id) {
            SigningSubmissionId parsed = SigningSubmissionId.parse(id);
            String random = id.value().substring(id.value().lastIndexOf(':') + 1);
            String canonical = "zsign:v1:" + parsed.namespace() + ':' + parsed.createdAt().toEpochMilli() + ':'
                    + random.toLowerCase(java.util.Locale.ROOT);
            if (!canonical.equals(id.value())) {
                throw new IllegalArgumentException("CA subject proof identity is not canonical");
            }
            return parsed;
        }

        @Override public String toString() { return "CaSubjectProofStep[redacted]"; }
    }

    /**
     * Small immutable terminal provider evidence for an internal proof.
     * This is neither a proof signature nor the parent's lifecycle outcome.
     * It can survive clearing the proof signature before certificate dispatch.
     * The mutable parent record retains this evidence across retirement.
     *
     * @param disposition terminal provider observation disposition
     * @param detailCode matching finite safe provider detail
     * @param providerUpdatedAt required provider timestamp for success or cancellation;
     *        may be absent for a local failure or unrecoverable classification
     */
    record CaSubjectProofOutcome(ObservationState disposition, DetailCode detailCode,
            Optional<Instant> providerUpdatedAt) {
        /**
         * Requires terminal evidence and an existing provider-compatible detail.
         * @throws NullPointerException if a component is null
         * @throws IllegalArgumentException if the disposition is nonterminal, detail mismatches,
         *         or success/cancellation lacks its provider timestamp
         */
        public CaSubjectProofOutcome {
            Objects.requireNonNull(disposition, "disposition");
            Objects.requireNonNull(detailCode, "detailCode");
            Objects.requireNonNull(providerUpdatedAt, "providerUpdatedAt");
            boolean valid = switch (disposition) {
                case SUCCEEDED -> detailCode == DetailCode.SIGNED;
                case CANCELLED -> detailCode == DetailCode.CANCELLED;
                case UNRECOVERABLE -> detailCode == DetailCode.LOCAL_RESTART_UNRECOVERABLE
                        || detailCode == DetailCode.PROVIDER_RESULT_INVALID;
                case FAILED -> switch (detailCode) {
                    case DENIED, PROVIDER_RESULT_INVALID, INVALID_KEY_REFERENCE, INVALID_ALGORITHM,
                            ALGORITHM_MISMATCH, KEY_NOT_FOUND, CONTENT_INTEGRITY_FAILURE,
                            UNSUPPORTED_SIGNATURE_ENCODING, KEYRING_IO_FAILURE, CRYPTO_FAILURE, DEADLINE_EXPIRED -> true;
                    default -> false;
                };
                case PENDING, RETRYABLE_UNKNOWN -> false;
            };
            if (!valid || (disposition == ObservationState.SUCCEEDED || disposition == ObservationState.CANCELLED)
                    && providerUpdatedAt.isEmpty()) {
                throw new IllegalArgumentException("CA subject proof outcome is invalid");
            }
        }
    }

    /**
     * Both immutable scheduling coordinates reserved at acceptance. Only the
     * selected coordinate is placed in the due index; switching stage introduces
     * no new identity reservation.
     * @param certificate final certificate/ordinary coordinate
     * @param proof optional subject-proof coordinate
     */
    record SchedulingPlan(SchedulingCoordinates certificate, Optional<SchedulingCoordinates> proof) {
        /** Validates both immutable coordinates. */
        public SchedulingPlan {
            Objects.requireNonNull(certificate, "certificate");
            Objects.requireNonNull(proof, "proof");
        }
        /**
         * Constructs an immutable plan from accepted input.
         * @param envelope immutable accepted input
         * @return certificate and optional proof scheduling coordinates
         */
        public static SchedulingPlan from(AcceptanceEnvelope envelope) {
            return new SchedulingPlan(new SchedulingCoordinates(envelope.keyRef(), envelope.fairnessAuthorityId()),
                    envelope.proofStep().map(step -> new SchedulingCoordinates(step.subjectKeyRef(), envelope.fairnessAuthorityId())));
        }
        /**
         * Selects a pre-reserved coordinate.
         * @param stage current durable signing stage
         * @return scheduling coordinate for the selected provider step
         * @throws IllegalArgumentException if a proof stage lacks its reserved coordinate
         */
        public SchedulingCoordinates forStage(Stage stage) {
            return stage.usesProofKey() ? proof.orElseThrow(() -> new IllegalArgumentException("Proof scheduling is missing")) : certificate;
        }
    }

    /** Immutable execution policy selected at acceptance. */
    enum Mode {
        /** Ordinary durable signing with the existing reconciliation lifecycle. */
        NORMAL(10),
        /** Raw signing with one durable initial dispatch and observation budget. */
        BOUNDED_OBSERVATION(20);

        private final int persistentCode;

        Mode(int persistentCode) { this.persistentCode = persistentCode; }

        /** {@return the stable format code, independent of enum order} */
        public int persistentCode() { return persistentCode; }

        /**
         * Decodes a current-format mode.
         * @param code stable persistent discriminator
         * @return decoded enum value
         * @throws IllegalArgumentException if the discriminator is unknown
         */
        public static Mode fromPersistentCode(int code) {
            return switch (code) {
                case 10 -> NORMAL;
                case 20 -> BOUNDED_OBSERVATION;
                default -> throw new IllegalArgumentException("Unknown signing mode");
            };
        }
    }

    /** Persisted budget of the bounded initial attempt, separate from cleanup retries. */
    enum InitialAttemptPhase {
        /** Ordinary signing has no bounded initial attempt. */
        NOT_APPLICABLE(10),
        /** The initial dispatch has not yet returned a durable pending checkpoint. */
        DISPATCH_OWED(20),
        /** Dispatch returned pending and the sole observation is ready to claim. */
        OBSERVATION_OWED(30),
        /** The observation budget was consumed before invoking the provider. */
        OBSERVATION_CONSUMED(40),
        /** A provider observation returned, including a pending result, or signing terminated. */
        COMPLETED(50),
        /** The initial attempt failed; ordinary durable cleanup remains eligible. */
        FAILED(60);

        private final int persistentCode;

        InitialAttemptPhase(int persistentCode) { this.persistentCode = persistentCode; }

        /** {@return the stable format code, independent of enum order} */
        public int persistentCode() { return persistentCode; }

        /**
         * Decodes a current-format phase.
         * @param code stable persistent discriminator
         * @return decoded enum value
         * @throws IllegalArgumentException if the discriminator is unknown
         */
        public static InitialAttemptPhase fromPersistentCode(int code) {
            return switch (code) {
                case 10 -> NOT_APPLICABLE;
                case 20 -> DISPATCH_OWED;
                case 30 -> OBSERVATION_OWED;
                case 40 -> OBSERVATION_CONSUMED;
                case 50 -> COMPLETED;
                case 60 -> FAILED;
                default -> throw new IllegalArgumentException("Unknown initial signing attempt phase");
            };
        }

        /** {@return whether a bounded initial attempt has a retained outcome} */
        public boolean finished() { return this == COMPLETED || this == FAILED; }
    }

    /**
     * Transport-neutral immutable input consumed by one atomic acceptance.
     * Custody of {@code candidate} transfers to the store when
     * {@link #acceptSign(AcceptanceCommand)} is invoked.
     *
     * @param operationId stable operation identifier
     * @param providerNamespace exact provider namespace
     * @param providerConfigurationCommitment exact provider configuration
     * @param accessContext exact trusted access context
     * @param keyRef exact trusted signing key reference
     * @param fairnessAuthorityId server-derived fairness authority
     * @param algorithmId canonical signature algorithm
     * @param signatureEncoding requested signature encoding
     * @param createdAt identifier creation time
     * @param deadline absolute signing deadline
     * @param candidate sealed candidate content
     * @param outer optional paired outer command
     * @param mode immutable execution policy; bounded observation requires no outer command
     * @param proofStep optional internal CA proof descriptor, ordinary/domain producers otherwise empty
     */
    record AcceptanceCommand(PkiId operationId, String providerNamespace,
            ConfigurationCommitment providerConfigurationCommitment, // NOPMD - LongVariable: public component names distinguish provider configuration from acceptance commitments.
            AccessContext accessContext, KeyRef keyRef, PkiId fairnessAuthorityId,
            String algorithmId, Encoding signatureEncoding, Instant createdAt,
            Instant deadline, DurableContentReference candidate, Optional<OuterCommand> outer, Mode mode, Optional<CaSubjectProofStep> proofStep) {
        /** Validates immutable command structure and current component bounds. */
        public AcceptanceCommand {
            Objects.requireNonNull(operationId, "operationId");
            Objects.requireNonNull(providerNamespace, "providerNamespace");
            Objects.requireNonNull(providerConfigurationCommitment,
                    "providerConfigurationCommitment");
            Objects.requireNonNull(accessContext, "accessContext");
            Objects.requireNonNull(keyRef, "keyRef");
            Objects.requireNonNull(fairnessAuthorityId, "fairnessAuthorityId");
            Objects.requireNonNull(algorithmId, "algorithmId");
            Objects.requireNonNull(signatureEncoding, "signatureEncoding");
            Objects.requireNonNull(createdAt, "createdAt");
            Objects.requireNonNull(deadline, "deadline");
            Objects.requireNonNull(candidate, "candidate");
            outer = Objects.requireNonNull(outer, "outer");
            Objects.requireNonNull(mode, "mode");
            proofStep = Objects.requireNonNull(proofStep, "proofStep");
            if (proofStep.isPresent()) {
                CaSubjectProofStep proof = proofStep.orElseThrow();
                proof.requireParent(operationId);
                if (mode != Mode.NORMAL || outer.filter(value -> value.kind() == DomainContinuationStore.Kind.CA).isEmpty()
                        || !proof.algorithmId().equals(algorithmId)
                        || !proof.challenge().storeId().equals(candidate.storeId())
                        || proof.challenge().contentId().equals(candidate.contentId())
                        || candidate.encoding() != Encoding.DER || signatureEncoding != Encoding.BINARY) {
                    throw new IllegalArgumentException("Composite CA acceptance is inconsistent");
                }
            }
            if (mode == Mode.BOUNDED_OBSERVATION && outer.isPresent()) {
                throw new IllegalArgumentException("Bounded observation requires raw signing");
            }
            if (providerNamespace.isBlank() || algorithmId.isBlank()
                    || deadline.isBefore(createdAt)) {
                throw new IllegalArgumentException("Signing acceptance metadata is invalid");
            }
        }

        /** {@return the canonical streaming {@code accept-sign:v3} commitment} */
        public AcceptanceCommitment commitment() {
            return AcceptanceCommitments.compute(this);
        }
    }

    /**
     * Once-written immutable signing envelope. It contains no mutable lifecycle
     * fields and is not retained in the active projection. The immutable mode
     * participates in the commitment; bounded observation cannot have an outer command.
     *
     * @param operationId canonical accepted signing operation identity
     * @param acceptanceCommitment verified commitment to the complete immutable acceptance command
     * @param providerNamespace exact provider namespace
     * @param providerConfigurationCommitment exact accepted provider configuration commitment
     * @param accessContext trusted access context retained at acceptance
     * @param keyRef accepted signing key reference
     * @param fairnessAuthorityId server-derived authority used for fair scheduling
     * @param algorithmId canonical signature algorithm identity
     * @param signatureEncoding requested signature encoding
     * @param createdAt operation identifier creation time
     * @param deadline absolute accepted signing deadline
     * @param candidate sealed staged content retained by this workflow
     * @param outer optional paired domain continuation command
     * @param mode immutable execution policy selected at acceptance
     * @param proofStep optional descriptor of the parent-owned CA proof step
     */
    record AcceptanceEnvelope(PkiId operationId, AcceptanceCommitment acceptanceCommitment,
            String providerNamespace, ConfigurationCommitment providerConfigurationCommitment, // NOPMD - LongVariable: public component names distinguish provider configuration from acceptance commitments.
            AccessContext accessContext, KeyRef keyRef, PkiId fairnessAuthorityId,
            String algorithmId, Encoding signatureEncoding, Instant createdAt,
            Instant deadline, DurableContentReference candidate, Optional<OuterCommand> outer, Mode mode, Optional<CaSubjectProofStep> proofStep) {
        /** Validates one exact immutable envelope. */
        public AcceptanceEnvelope {
            Objects.requireNonNull(acceptanceCommitment, "acceptanceCommitment");
            AcceptanceCommand command = new AcceptanceCommand(operationId, providerNamespace,
                    providerConfigurationCommitment, accessContext, keyRef, fairnessAuthorityId,
                    algorithmId, signatureEncoding, createdAt, deadline, candidate, outer, mode, proofStep);
            if (!acceptanceCommitment.matches(command.commitment())) {
                throw new IllegalArgumentException("Acceptance envelope commitment mismatch");
            }
        }

        /**
         * Creates the immutable envelope for a validated acceptance command.
         * @param command non-null accepted input
         * @return immutable envelope with its computed commitment
         */
        public static AcceptanceEnvelope from(AcceptanceCommand command) {
            AcceptanceCommand exact = Objects.requireNonNull(command, "command");
            return new AcceptanceEnvelope(exact.operationId(), exact.commitment(),
                    exact.providerNamespace(), exact.providerConfigurationCommitment(),
                    exact.accessContext(), exact.keyRef(), exact.fairnessAuthorityId(),
                    exact.algorithmId(), exact.signatureEncoding(), exact.createdAt(),
                    exact.deadline(), exact.candidate(), exact.outer(), exact.mode(), exact.proofStep());
        }
    }

    /**
     * Unique immutable candidate identity retained through the signing identity
     * horizon.
     *
     * @param candidateId sealed content identity
     * @param operationId accepted operation identity
     * @param length exact candidate length
     * @param sha256 canonical candidate digest
     */
    record CandidateBinding(String candidateId, PkiId operationId, long length,
            String sha256) {
        /** Validates one canonical binding. */
        public CandidateBinding {
            Objects.requireNonNull(candidateId, "candidateId");
            Objects.requireNonNull(operationId, "operationId");
            Objects.requireNonNull(sha256, "sha256");
            if (candidateId.isBlank() || length < 0L
                    || !sha256.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Candidate binding is invalid");
            }
        }
    }

    /**
     * Separately replaced mutable signing state. The initial-attempt phase retains
     * its outcome independently of retry metadata and is checked against the
     * accepted mode when assembling a workflow.
     *
     * @param operationId canonical accepted signing operation identity
     * @param state durable signing lifecycle state
     * @param revision nonnegative compare-and-set revision
     * @param fence nonnegative fencing token
     * @param leaseUntil optional expiration of the current provider claim
     * @param downstreamOperationId optional current provider-side operation identity
     * @param detailCode optional finite safe status detail
     * @param result optional retained signature, defensively copied
     * @param providerUpdatedAt optional timestamp of the last provider observation
     * @param failureCount nonnegative reconciliation failure count
     * @param nextEligibleAt optional earliest reconciliation retry time
     * @param reconciliationFailureClass optional classification accompanying the retry time
     * @param initialAttemptPhase retained bounded-observation attempt phase
     * @param stage current provider or proof-verification stage
     * @param proofOutcome optional retained terminal CA proof evidence
     */
    record MutableState(PkiId operationId, State state, long revision, long fence,
            Optional<Instant> leaseUntil, Optional<PkiId> downstreamOperationId,
            Optional<String> detailCode, Optional<EncodedObject> result,
            Optional<Instant> providerUpdatedAt, int failureCount,
            Optional<Instant> nextEligibleAt,
            Optional<ReconciliationFailureClass> reconciliationFailureClass,
            InitialAttemptPhase initialAttemptPhase, Stage stage, Optional<CaSubjectProofOutcome> proofOutcome) {
        /** Validates lifecycle, fencing and retry metadata. */
        public MutableState {
            Objects.requireNonNull(operationId, "operationId");
            Objects.requireNonNull(state, "state");
            Objects.requireNonNull(initialAttemptPhase, "initialAttemptPhase");
            Objects.requireNonNull(stage, "stage");
            proofOutcome = Objects.requireNonNull(proofOutcome, "proofOutcome");
            leaseUntil = Objects.requireNonNull(leaseUntil, "leaseUntil");
            downstreamOperationId = Objects.requireNonNull(downstreamOperationId,
                    "downstreamOperationId");
            detailCode = Objects.requireNonNull(detailCode, "detailCode");
            result = Objects.requireNonNull(result, "result").map(value ->
                    new EncodedObject(value.encoding(), value.bytes()));
            providerUpdatedAt = Objects.requireNonNull(providerUpdatedAt, "providerUpdatedAt");
            nextEligibleAt = Objects.requireNonNull(nextEligibleAt, "nextEligibleAt");
            reconciliationFailureClass = Objects.requireNonNull(
                    reconciliationFailureClass, "reconciliationFailureClass");
            if (revision < 0L || fence < 0L) {
                throw new IllegalArgumentException("revision and fence must not be negative");
            }
            boolean retryPresent = nextEligibleAt.isPresent()
                    && reconciliationFailureClass.isPresent();
            if (failureCount < 0 || failureCount == 0 == retryPresent) {
                throw new IllegalArgumentException("Reconciliation retry metadata is inconsistent");
            }
            if ((state == State.FAILED || state == State.CANCELLED
                    || state == State.EXPIRED || state == State.RETIRED)
                    && failureCount != 0) {
                throw new IllegalArgumentException("Terminal state cannot retain retry metadata");
            }
            if (state == State.SUCCEEDED && failureCount != 0
                    && reconciliationFailureClass
                            .filter(ReconciliationFailureClass.LOCAL_FAILURE::equals).isEmpty()) {
                throw new IllegalArgumentException(
                        "Successful signing may retain only local outer-continuation retry metadata");
            }
        }

        /**
         * Returns a revision-zero intent with the initial phase for the accepted mode.
         *
         * @param operationId accepted operation identity
         * @param mode immutable accepted execution policy
         * @param stage SINGLE or CA_PROOF according to the accepted descriptor
         * @return initial immutable mutable-state value
         */
        public static MutableState intent(PkiId operationId, Mode mode, Stage stage) {
            Objects.requireNonNull(mode, "mode");
            return new MutableState(operationId, State.INTENT, 0L, 0L,
                    Optional.empty(), Optional.empty(), Optional.of("INTENT"),
                    Optional.empty(), Optional.empty(), 0, Optional.empty(), Optional.empty(),
                    mode == Mode.NORMAL ? InitialAttemptPhase.NOT_APPLICABLE
                            : InitialAttemptPhase.DISPATCH_OWED, stage, Optional.empty());
        }
    }

    /**
     * Read-only aggregate assembled from one immutable envelope and mutable state.
     *
     * @param envelope immutable accepted signing envelope
     * @param mutableState current mutable state with the same operation identity
     */
    record Workflow(AcceptanceEnvelope envelope, MutableState mutableState) { // NOPMD - CyclomaticComplexity totals independent dispatch/codec branches; method-level checks remain enabled.
        /** Validates shared operation identity and accepted-mode/phase invariants. */
        public Workflow {
            Objects.requireNonNull(envelope, "envelope");
            Objects.requireNonNull(mutableState, "mutableState");
            if (!envelope.operationId().equals(mutableState.operationId())) {
                throw new IllegalArgumentException("Signing workflow identity mismatch");
            }
            validateInitialAttempt(envelope.mode(), mutableState);
            validateStage(envelope, mutableState);
        }

        private static void validateStage(AcceptanceEnvelope envelope, MutableState mutable) {
            Stage stage = mutable.stage();
            if (envelope.proofStep().isEmpty()) {
                if (stage != Stage.SINGLE || mutable.proofOutcome().isPresent()) {
                    throw new IllegalArgumentException("Single signing cannot retain a CA proof stage");
                }
                return;
            }
            if (stage == Stage.SINGLE || mutable.state() == State.INTENT && stage != Stage.CA_PROOF) {
                throw new IllegalArgumentException("Composite signing stage is inconsistent");
            }
            validateUnfinishedProof(stage, mutable);
            validateProofCompletion(stage, mutable);
        }

        private static void validateUnfinishedProof(Stage stage, MutableState mutable) {
            if (stage == Stage.CA_PROOF && (mutable.state() == State.INTENT || mutable.state() == State.DISPATCHED
                    || mutable.state() == State.CANCELLING) && (mutable.result().isPresent() || mutable.proofOutcome().isPresent())) {
                throw new IllegalArgumentException("Unfinished proof cannot retain terminal evidence");
            }
            if (stage == Stage.CA_CERTIFICATE_READY && mutable.state() == State.DISPATCHED
                    && (mutable.leaseUntil().isPresent() || mutable.downstreamOperationId().isPresent())) {
                throw new IllegalArgumentException("Certificate readiness must release the proof claim");
            }
        }

        private static void validateProofCompletion(Stage stage, MutableState mutable) {
            boolean proofSucceeded = mutable.proofOutcome()
                    .filter(value -> value.disposition() == ObservationState.SUCCEEDED).isPresent();
            if ((stage == Stage.CA_PROOF_VERIFYING || stage == Stage.CA_CERTIFICATE_READY || stage == Stage.CA_CERTIFICATE)
                    && !proofSucceeded) {
                throw new IllegalArgumentException("Certificate stage requires successful proof evidence");
            }
            if (stage == Stage.CA_PROOF_VERIFYING && mutable.state() == State.DISPATCHED
                    && mutable.result().isEmpty()) {
                throw new IllegalArgumentException("Proof verification requires its retained signature");
            }
            validateFinalResult(stage, mutable);
        }

        private static void validateFinalResult(Stage stage, MutableState mutable) {
            if (stage != Stage.CA_CERTIFICATE && (mutable.state() == State.SUCCEEDED
                    || mutable.state() == State.RETIRED && mutable.result().isPresent())
                    || stage == Stage.CA_CERTIFICATE_READY && mutable.result().isPresent()) {
                throw new IllegalArgumentException("Proof signature is not a final signing result");
            }
        }

        private static void validateInitialAttempt(Mode mode, MutableState mutable) {
            InitialAttemptPhase phase = mutable.initialAttemptPhase();
            if (mode == Mode.NORMAL) {
                if (phase != InitialAttemptPhase.NOT_APPLICABLE) {
                    throw new IllegalArgumentException("Ordinary signing cannot retain an initial attempt");
                }
                return;
            }
            if (phase == InitialAttemptPhase.NOT_APPLICABLE
                    || mutable.state() == State.INTENT && phase != InitialAttemptPhase.DISPATCH_OWED
                    || mutable.state() != State.INTENT && mutable.state() != State.DISPATCHED
                            && mutable.state() != State.CANCELLING && !phase.finished()) {
                throw new IllegalArgumentException("Bounded signing phase does not match lifecycle");
            }
            validateInitialClaim(phase, mutable);
        }

        private static void validateInitialClaim(InitialAttemptPhase phase, MutableState mutable) {
            if (mutable.state() == State.DISPATCHED) {
                boolean valid = switch (phase) {
                    case DISPATCH_OWED, OBSERVATION_CONSUMED -> mutable.leaseUntil().isPresent()
                            && mutable.failureCount() == 0;
                    case OBSERVATION_OWED -> mutable.leaseUntil().isEmpty()
                            && mutable.failureCount() == 0;
                    case COMPLETED, FAILED -> true;
                    case NOT_APPLICABLE -> false;
                };
                if (!valid) {
                    throw new IllegalArgumentException("Bounded signing phase does not match claim");
                }
            }
        }

        /** {@return the immutable accepted execution policy} */
        public Mode mode() { return envelope.mode(); }
        /** {@return the durable provider/local-verification stage} */
        public Stage stage() { return mutableState.stage(); }
        /** {@return small retained proof evidence, never its signature} */
        public Optional<CaSubjectProofOutcome> proofOutcome() { return mutableState.proofOutcome(); }
        /** {@return the exact immutable references owned by this one parent} */
        public List<DurableContentReference> candidates() {
            return envelope.proofStep().map(proof -> List.of(envelope.candidate(), proof.challenge()))
                    .orElseGet(() -> List.of(envelope.candidate()));
        }
        /** {@return the current stage's exact provider identity} */
        public PkiId providerOperationId() {
            return stage().usesProofKey() ? envelope.proofStep().orElseThrow().operationId() : operationId();
        }
        /** {@return the retained bounded initial-attempt phase} */
        public InitialAttemptPhase initialAttemptPhase() { return mutableState.initialAttemptPhase(); }
        /** {@return the canonical accepted operation identity} */
        public PkiId operationId() { return envelope.operationId(); }
        /** {@return the accepted operation identity, also used as its submission identity} */
        public PkiId submissionId() { return envelope.operationId(); }
        /** {@return the accepted provider namespace} */
        public String namespace() { return envelope.providerNamespace(); }
        /** {@return the encoded acceptance commitment} */
        public String fingerprint() { return envelope.acceptanceCommitment().encoded(); }
        /** {@return the accepted provider configuration commitment} */
        public ConfigurationCommitment configurationCommitment() {
            return envelope.providerConfigurationCommitment();
        }
        /** {@return the trusted principal retained at acceptance} */
        public Principal owner() { return envelope.accessContext().principal(); }
        /** {@return the accepted identifier creation time} */
        public Instant createdAt() { return envelope.createdAt(); }
        /** {@return the absolute accepted signing deadline} */
        public Instant deadline() { return envelope.deadline(); }
        /** {@return the durable lifecycle state} */
        public State state() { return mutableState.state(); }
        /** {@return the current compare-and-set revision} */
        public long revision() { return mutableState.revision(); }
        /** {@return the current fencing token} */
        public long fence() { return mutableState.fence(); }
        /** {@return the optional provider claim expiration} */
        public Optional<Instant> leaseUntil() { return mutableState.leaseUntil(); }
        /** {@return the optional current provider-side operation identity} */
        public Optional<PkiId> downstreamOperationId() { return mutableState.downstreamOperationId(); }
        /** {@return the optional finite safe status detail} */
        public Optional<String> detailCode() { return mutableState.detailCode(); }
        /** {@return the optional immutable retained signature} */
        public Optional<EncodedObject> result() { return mutableState.result(); }
        /** {@return the optional last provider observation timestamp} */
        public Optional<Instant> providerUpdatedAt() { return mutableState.providerUpdatedAt(); }
        /** {@return the nonnegative reconciliation failure count} */
        public int failureCount() { return mutableState.failureCount(); }
        /** {@return the optional earliest reconciliation retry time} */
        public Optional<Instant> nextEligibleAt() { return mutableState.nextEligibleAt(); }
        /** {@return the optional retained reconciliation failure classification} */
        public Optional<ReconciliationFailureClass> reconciliationFailureClass() {
            return mutableState.reconciliationFailureClass();
        }
    }

    /**
     * One ordered signing-record scan result.
     *
     * @param cursor exclusive cursor after this examined metadata candidate
     * @param record decoded signing record, or empty when the candidate was malformed
     */
    record PageCandidate(String cursor, Optional<Workflow> record) {
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
    record Page(List<Workflow> records, Optional<String> nextCursor, int examined, int failures,
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
        public Page(List<Workflow> records, Optional<String> nextCursor, int examined, int failures,
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
        public Page(List<Workflow> records, Optional<String> nextCursor, int examined, int failures,
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

        private static List<PageCandidate> successfulCandidates(List<Workflow> records, int examined, int failures) {
            Objects.requireNonNull(records, "records");
            if (failures != 0 || examined != records.size()) {
                throw new IllegalArgumentException("Signing page candidate details are required for failures");
            }
            return records.stream()
                    .map(record -> new PageCandidate(record.submissionId().value(), Optional.of(record)))
                    .toList();
        }
    }

    /**
     * One lightweight reconciliation candidate. The candidate deliberately
     * carries no workflow, acceptance envelope, payload, provider object, or
     * revision; consumers must point-load authoritative state before claiming it.
     *
     * @param operationId canonical signing submission identifier
     * @param scheduling immutable coordinates derived from the authoritative envelope
     * @param malformed whether the indexed mutable-state record was malformed
     */
    record DueCandidate(PkiId operationId, SchedulingCoordinates scheduling,
            boolean malformed) {
        /** Validates one immutable due candidate. */
        public DueCandidate {
            requireCanonicalSigningId(operationId, "due candidate operation id");
            Objects.requireNonNull(scheduling, "scheduling");
        }
    }

    /**
     * One bounded identity-ordered page of lightweight reconciliation candidates.
     *
     * @param candidates immutable candidates in strict canonical identifier order
     * @param nextCursor exclusive cursor equal to the final candidate identifier,
     *                   or empty when the page has no candidates
     * @param failures number of malformed candidates
     * @param endReached whether the stable due cycle was exhausted
     * @param highWatermark stable inclusive upper bound for the due cycle
     */
    record DuePage(List<DueCandidate> candidates, Optional<String> nextCursor,
            int failures, boolean endReached, Optional<String> highWatermark) {
        /** Validates and snapshots one lightweight due page. */
        public DuePage {
            candidates = List.copyOf(Objects.requireNonNull(candidates, "candidates"));
            nextCursor = Objects.requireNonNull(nextCursor, "nextCursor");
            highWatermark = Objects.requireNonNull(highWatermark, "highWatermark");
            PkiId previous = null;
            int malformed = 0;
            for (DueCandidate candidate : candidates) {
                Objects.requireNonNull(candidate, "candidate");
                PkiId current = candidate.operationId();
                if (previous != null
                        && previous.value().compareTo(current.value()) >= 0) {
                    throw new IllegalArgumentException(
                            "Signing due candidates must be strictly ordered");
                }
                if (candidate.malformed()) {
                    malformed++;
                }
                previous = current;
            }
            if (failures < 0 || failures != malformed) {
                throw new IllegalArgumentException("Signing due page failure count is inconsistent");
            }
            if (candidates.isEmpty()) {
                if (nextCursor.isPresent()) {
                    throw new IllegalArgumentException("Empty signing due page must not have a cursor");
                }
            } else if (!nextCursor.equals(Optional.of(previous.value()))) {
                throw new IllegalArgumentException("Signing due page cursor is inconsistent");
            }
            if (highWatermark.isPresent()) {
                PkiId watermark = requireCanonicalSigningId(
                        new PkiId(highWatermark.orElseThrow()), "due page high-watermark");
                if (previous != null && watermark.value().compareTo(previous.value()) < 0) {
                    throw new IllegalArgumentException(
                            "Signing due page high-watermark precedes its final candidate");
                }
            }
        }
    }

    private static PkiId requireCanonicalSigningId(PkiId operationId, String name) {
        PkiId exact = Objects.requireNonNull(operationId, name);
        SigningSubmissionId parsed = SigningSubmissionId.parse(exact);
        String value = exact.value();
        int nonceSeparator = value.lastIndexOf(':');
        String canonical = "zsign:v1:" + parsed.namespace() + ':'
                + parsed.createdAt().toEpochMilli() + value.substring(nonceSeparator);
        if (!canonical.equals(value)) {
            throw new IllegalArgumentException("Signing submission id is not canonical");
        }
        return exact;
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
     * Atomically accepts one sealed candidate and publishes its immutable
     * envelope, initial {@link State#INTENT}, unique candidate binding and optional
     * outer operation. The implementation rechecks existing identity and candidate
     * bindings inside the committing transaction before applying capacity.
     *
     * @param command complete immutable acceptance command; candidate custody
     *                transfers on entry
     * @return exact durable disposition
     */
    AcceptanceResult acceptSign(AcceptanceCommand command);

    /**
     * Resolves a previously uncertain acceptance without modifying workflow state.
     *
     * @param operationId stable operation identifier
     * @param commitment exact command commitment
     * @return authoritative resolution
     */
    AcceptanceResolution resolveAcceptance(PkiId operationId,
            AcceptanceCommitment commitment);

    /**
     * Returns authoritative state for an identifier.
     *
     * @param submissionId stable submission identifier
     * @return retained state, or empty when unknown or purged
     */
    Optional<Workflow> getSignWorkflow(PkiId submissionId);

    /**
     * Returns a stable snapshot of retained signing records.
     *
     * @return retained records
     */
    List<Workflow> listSignWorkflows();

    /**
     * Selects bounded reconciliation work ordered by its durable eligibility time.
     * Implementations without an ordered projection retain compatibility through
     * this bounded-result fallback; production stores should override it.
     *
     * @param cutoffInclusive latest eligible retry time
     * @param maximumRecords result bound from 1 through 4096
     * @return due records in deterministic reconciliation order
     */
    default List<Workflow> selectDueSignWorkflows(Instant cutoffInclusive, int maximumRecords) {
        Objects.requireNonNull(cutoffInclusive, "cutoffInclusive");
        if (maximumRecords < 1 || maximumRecords > 4096) {
            throw new IllegalArgumentException("maximumRecords must be between 1 and 4096");
        }
        return listSignWorkflows().stream()
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
    Page pageSignWorkflows(Optional<String> exclusiveCursor, int maximumRecords,
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
    default Page pageSignWorkflows(Optional<String> exclusiveCursor, Optional<String> inclusiveHighWatermark,
            int maximumRecords, zeroecho.core.io.CancellationSignal cancellation) {
        return pageSignWorkflows(exclusiveCursor, maximumRecords, cancellation);
    }

    /**
     * Returns an identity-ordered page of lightweight identifiers eligible for
     * reconciliation at {@code cutoffInclusive}. The result deliberately omits
     * workflows and acceptance envelopes; a consumer point-loads authoritative
     * state only after a processing lane is available.
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
    DuePage pageDueSignWorkflows(Instant cutoffInclusive, Optional<String> exclusiveCursor,
            Optional<String> inclusiveHighWatermark, int maximumRecords,
            zeroecho.core.io.CancellationSignal cancellation);

    /**
     * Defers reconciliation with store-authoritative exponential backoff.
     * Provider reconciliation may be deferred from {@code DISPATCHED} or
     * {@code CANCELLING}; the durable retry tuple replaces the active lease. A
     * {@code SUCCEEDED} workflow may be deferred only with {@link
     * ReconciliationFailureClass#LOCAL_FAILURE} while its accepted outer
     * continuation remains in {@code SIGNING} or {@code PUBLISHING}. In that case
     * terminal signing evidence and the fence are preserved and no lease exists.
     * For an unfinished bounded initial attempt, the same commit records
     * {@link InitialAttemptPhase#FAILED}. A retained completed or failed attempt
     * outcome is never replaced by retry metadata.
     *
     * @param submissionId stable submission identifier
     * @param expectedRevision caller-observed record revision
     * @param fence current fencing token
     * @param failureClass stable retry classification used to calculate backoff
     * @return updated record, or empty when the revision/fence CAS loses
     */
    Optional<Workflow> deferSignReconciliation(PkiId submissionId, long expectedRevision, long fence,
            ReconciliationFailureClass failureClass);

    /**
     * Atomically claims the next provider step.
     *
     * <p>An {@link State#INTENT} claim durably changes state to
     * {@link State#DISPATCHED}, increments revision and fence, assigns the exact
     * downstream operation identity, and publishes the lease in one commit before
     * any provider or cryptographic call. An expired or absent lease on
     * {@code DISPATCHED} or {@code CANCELLING} is reclaimed the same way without a
     * lifecycle change. Live leases are never claimable. The lease is clamped to
     * the workflow deadline, and a workflow at or after its deadline is not
     * claimable. A durable retry cannot be claimed before its next eligibility
     * time. For bounded signing, a reclaimed dispatch or ready observation reserves
     * the sole observation before returning. Reclaiming an already consumed
     * observation records a failed initial attempt and retains a cleanup lease.</p>
     *
     * @param submissionId     stable submission identifier
     * @param expectedRevision caller-observed revision
     * @param lease            positive claim duration
     * @return claimed record, or empty when compare-and-set loses
     */
    Optional<Workflow> claimSignStep(PkiId submissionId, long expectedRevision, Duration lease);

    /**
     * Checkpoints a pending initial dispatch and releases its lease, making the sole
     * bounded observation immediately claimable. Only bounded, dispatched workflows
     * in {@link InitialAttemptPhase#DISPATCH_OWED} with a present claim lease qualify.
     * Lease expiry alone does not invalidate the observed revision and fence.
     * Deadline admission and durability confirmation precede publication of readiness.
     *
     * @param submissionId stable operation identifier
     * @param expectedRevision observed revision
     * @param fence observed claim fence
     * @return committed ready workflow, or empty on stale ownership or ineligible state
     */
    Optional<Workflow> checkpointPendingSignDispatch(PkiId submissionId, long expectedRevision, long fence);

    /**
     * Checkpoints a returned bounded observation, including a pending result, after
     * its budget was consumed by a claim. The current lease is retained so ordinary
     * reconciliation can eventually clean up when the caller disappears. Revision,
     * fence, a present lease, deadline admission and confirmed durability are required;
     * lease expiry alone does not invalidate the checkpoint.
     *
     * @param submissionId stable operation identifier
     * @param expectedRevision observed revision
     * @param fence observed claim fence
     * @return committed completed-attempt workflow, or empty on stale ownership or ineligible state
     */
    Optional<Workflow> completeSignObservation(PkiId submissionId, long expectedRevision, long fence);

    /**
     * Atomically renews an owned lease.
     *
     * <p>Only a still-live lease may be renewed. The replacement lease is clamped
     * to the workflow deadline; an expired lease must instead be reclaimed with a
     * new fence through {@link #claimSignStep(PkiId, long, Duration)}.</p>
     *
     * @param submissionId     stable submission identifier
     * @param expectedRevision caller-observed revision
     * @param fence            current fencing token
     * @param lease            positive renewal duration
     * @return renewed record, or empty when compare-and-set loses
     */
    Optional<Workflow> renewSignStep(PkiId submissionId, long expectedRevision, long fence, Duration lease);

    /**
     * Atomically applies authoritative cancellation intent.
     *
     * <p>An unclaimed {@code INTENT} becomes terminal {@code CANCELLED} without a
     * provider call because no external effect can exist. A {@code DISPATCHED}
     * operation first becomes durable {@code CANCELLING}; only that state may be
     * passed to a provider cancellation call. Reconciliation terminalizes a
     * retained {@code CANCELLING} operation.</p>
     *
     * @param submissionId stable operation identifier
     * @param expectedRevision caller-observed revision
     * @param fence caller-observed fence
     * @return cancelled or cancelling state, or empty when the CAS loses
     */
    Optional<Workflow> requestSignCancellation(PkiId submissionId, long expectedRevision, long fence);

    /**
     * Atomically transitions state when revision and fence are current.
     *
     * <p>
     * Provider observations terminalize {@code DISPATCHED} or
     * {@code CANCELLING}. Dispatch and cancellation intent use
     * {@link #claimSignStep(PkiId, long, Duration)} and
     * {@link #requestSignCancellation(PkiId, long, long)} respectively rather
     * than this transition method.
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
    Optional<Workflow> transitionSign(PkiId submissionId, long expectedRevision, long fence, State target,
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
    Optional<Workflow> retireSign(PkiId submissionId, long expectedRevision, long fence);

    /**
     * Atomically records one terminal internal-proof observation. Successful
     * proof enters local verification, never parent success. Cancellation already
     * requested on the parent prevents verification/certificate advancement.
     * @param submissionId parent identity
     * @param expectedRevision exact current revision
     * @param fence exact current claimed fence
     * @param outcome terminal safe proof evidence
     * @param signature present exactly for successful proof observations
     * @return committed parent state, or empty for stale/ineligible work
     */
    Optional<Workflow> checkpointCaProof(PkiId submissionId, long expectedRevision, long fence,
            CaSubjectProofOutcome outcome, Optional<EncodedObject> signature);

    /**
     * Records successful local verification and releases the claim for final-key
     * scheduling. The trusted caller must verify the retained signature first.
     * @param submissionId parent identity
     * @param expectedRevision exact verifying revision
     * @param fence exact claimed fence
     * @return ready parent state, or empty for stale/cancelled/expired work
     */
    Optional<Workflow> completeCaProofVerification(PkiId submissionId, long expectedRevision, long fence);



    /**
     * Performs one bounded purge pass for content-free expired or retired records
     * after the configured horizon. Active and cancellation-pending provider
     * operations must be retained for reconciliation. Callers repeat this method on
     * later maintenance passes to converge when more eligible records remain.
     *
     * @return number of records purged by this pass
     */
    int purgeExpiredSignRecords();

    /** Canonical streaming encoder for the immutable acceptance commitment. */
    final class AcceptanceCommitments {
        private static final byte[] DOMAIN = "accept-sign:v3"
                .getBytes(StandardCharsets.US_ASCII);
        private static final int MAXIMUM_COMPONENT_BYTES = 1_048_576;

        private AcceptanceCommitments() {
        }

        private static AcceptanceCommitment compute(AcceptanceCommand command) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                try (DataOutputStream output = new DataOutputStream(new DigestOutputStream(
                        java.io.OutputStream.nullOutputStream(), digest))) {
                    field(output, DOMAIN);
                    field(output, command.operationId().value());
                    field(output, command.providerNamespace());
                    byte[] configuration = command.providerConfigurationCommitment().bytes();
                    try {
                        field(output, configuration);
                    } finally {
                        Arrays.fill(configuration, (byte) 0);
                    }
                    accessContext(output, command.accessContext());
                    field(output, command.keyRef().value());
                    field(output, command.fairnessAuthorityId().value());
                    field(output, command.algorithmId());
                    output.writeInt(encodingCode(command.signatureEncoding()));
                    instant(output, command.createdAt());
                    instant(output, command.deadline());
                    content(output, command.candidate());
                    output.writeInt(command.mode().persistentCode());
                    output.writeBoolean(command.proofStep().isPresent());
                    if (command.proofStep().isPresent()) {
                        CaSubjectProofStep proof = command.proofStep().orElseThrow();
                        field(output, proof.operationId().value());
                        field(output, proof.subjectKeyRef().value());
                        field(output, proof.algorithmId());
                        content(output, proof.challenge());
                    }
                    output.writeBoolean(command.outer().isPresent());
                    if (command.outer().isPresent()) {
                        outer(output, command.outer().orElseThrow());
                    }
                }
                return new AcceptanceCommitment(digest.digest());
            } catch (NoSuchAlgorithmException impossible) {
                throw new IllegalStateException("SHA-256 unavailable", impossible);
            } catch (IOException impossible) {
                throw new IllegalStateException("Acceptance commitment encoding failed", impossible);
            }
        }

        private static void accessContext(DataOutputStream output, AccessContext context)
                throws IOException {
            Principal principal = context.principal();
            field(output, principal.type());
            field(output, principal.name());
            Purpose purpose = context.purpose();
            field(output, purpose.value());
            optional(output, context.objectId().map(PkiId::value));
            optional(output, context.formatId().map(FormatId::value));
        }

        private static void content(DataOutputStream output, DurableContentReference reference)
                throws IOException {
            field(output, reference.storeId());
            field(output, reference.contentId());
            output.writeInt(encodingCode(reference.encoding()));
            output.writeLong(reference.length());
            field(output, reference.sha256());
            output.writeInt(lifecycleCode(reference.lifecycle()));
        }

        private static void outer(DataOutputStream output, OuterCommand outer) throws IOException {
            output.writeInt(kindCode(outer.kind()));
            field(output, outer.correlationId());
            output.writeInt(encodingCode(outer.command().encoding()));
            byte[] command = outer.command().bytes();
            try {
                field(output, command);
            } finally {
                Arrays.fill(command, (byte) 0);
            }
            field(output, outer.commandCommitment());
        }

        private static void optional(DataOutputStream output, Optional<String> value)
                throws IOException {
            output.writeBoolean(value.isPresent());
            if (value.isPresent()) {
                field(output, value.orElseThrow());
            }
        }

        private static void instant(DataOutputStream output, Instant value) throws IOException {
            output.writeLong(value.getEpochSecond());
            output.writeInt(value.getNano());
        }

        private static void field(DataOutputStream output, String value) throws IOException {
            byte[] encoded = Objects.requireNonNull(value, "value").getBytes(StandardCharsets.UTF_8);
            try {
                field(output, encoded);
            } finally {
                Arrays.fill(encoded, (byte) 0);
            }
        }

        private static void field(DataOutputStream output, byte[] value) throws IOException {
            if (value.length > MAXIMUM_COMPONENT_BYTES) {
                throw new IllegalArgumentException("Acceptance component exceeds the current bound");
            }
            output.writeInt(value.length);
            output.write(value);
        }

        private static int encodingCode(Encoding value) {
            return switch (value) {
                case DER -> 1;
                case PEM -> 2;
                case BINARY -> 3;
            };
        }

        private static int lifecycleCode(DurableContentReference.Lifecycle value) {
            return switch (value) {
                case OPERATION -> 1;
                case PERSISTED -> 2;
                case TEMPORARY -> 3;
            };
        }

        private static int kindCode(DomainContinuationStore.Kind value) {
            return switch (value) {
                case CA -> 1;
                case ISSUANCE -> 2;
                case STATUS -> 3;
                case KEY_PROOF -> 4;
            };
        }
    }
}
