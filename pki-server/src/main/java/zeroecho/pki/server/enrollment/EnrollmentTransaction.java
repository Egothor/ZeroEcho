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
package zeroecho.pki.server.enrollment;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.server.ApprovalService;
import zeroecho.pki.server.CertificateIdentityEvidence;
import zeroecho.pki.server.OperationSecurityDescriptors.ApprovalCategory;
import zeroecho.pki.server.RealmId;

/**
 * Immutable durable enrollment state. Original request and private material remain
 * in their domain stores; this record contains only bounded references and policy
 * commitments. Diagnostic rendering deliberately excludes identity information.
 *
 * <p>Construction checks consistency of supplied immutable evidence. It does not
 * authenticate requesters/administrators, verify SDK signatures, reserve capacity
 * or commit a signing receipt. The owning coordinator establishes those facts
 * and retains their exact replay/recovery links.</p>
 *
 * @param id stable replay identity, independent of endpoint revision
 * @param revision monotonic positive mutation revision
 * @param intent immutable admitted request and policy snapshot
 * @param state durable workflow state
 * @param decisions verified administrative decisions
 * @param receipt prepared signing receipt persisted before acceptance
 * @param credentialId completed credential, present only for ISSUED
 */
public record EnrollmentTransaction(String id, long revision, Intent intent, State state,
        List<Decision> decisions, Optional<SigningAcceptanceReceipt> receipt, Optional<PkiId> credentialId) {
    /**
     * Immutable retained SDK acceptance reference; construction grants no enrollment authority.
     *
     * @param intentId canonical server intent identity
     * @param proofCommitment complete F3 SHA-512 commitment
     * @param authenticationContextSha512 exact F6 SHA-512 commitment
     * @param targetSha512 exact F7 SHA-512 commitment
     * @param acceptedAt trusted acceptance time, independent of later approval delay
     */
    public record SdkProofReference(String intentId, String proofCommitment, String authenticationContextSha512,
            String targetSha512, Instant acceptedAt) {
        /**
         * Checks canonical digest coordinates without verifying proofs, current freshness or a retained
         * receipt.
         *
         * @param intentId canonical server intent identity
         * @param proofCommitment complete F3 SHA-512 commitment
         * @param authenticationContextSha512 exact F6 SHA-512 commitment
         * @param targetSha512 exact F7 SHA-512 commitment
         * @param acceptedAt trusted acceptance time, independent of later approval delay
         * @throws NullPointerException if acceptedAt is null
         * @throws IllegalArgumentException if the intent identity or a prefixed SHA-512 commitment is malformed
         */
        public SdkProofReference {
            if (intentId == null || !intentId.matches("[0-9a-f]{64}")) throw invalid();
            for (String value : new String[] {proofCommitment, authenticationContextSha512, targetSha512}) {
                if (value == null || !value.matches("sha512:[0-9a-f]{128}")) throw invalid();
            }
            Objects.requireNonNull(acceptedAt, "acceptedAt");
        }
        /**
         * Returns redacted immutable reference description.
         *
         * @return redacted immutable reference description
         */
        @Override public String toString() { return "EnrollmentTransaction.SdkProofReference[redacted]"; }
    }

    private static final int MAX_LEGACY_KEY_COMMITMENTS = 3;
    /**
     * Protocol family determines admission and recovery binding semantics.
     */
    public enum Protocol {
        /**
         * Authenticated HTTPS enrollment.
         */
        EST,
        /**
         * CMS-protected certificate enrollment.
         */
        SCEP,
        /**
         * Protected PKI messages.
         */
        CMP,
        /**
         * Account-authorized automated certificate enrollment.
         */
        ACME
    }
    /**
     * Existing enrollment operation kinds with separate replay domains.
     */
    public enum Operation {
        /**
         * Issue a credential for a proved request.
         */
        ISSUE,
        /**
         * Renew the exact authoritative predecessor identity.
         */
        RENEW,
        /**
         * Replace a CMP predecessor using the original signed CRMF request.
         */
        REPLACE,
        /**
         * Issue for an attached server-generated encrypted delivery artifact.
         */
        SERVER_KEYGEN
    }
    /**
     * Durable states; uncertain or accepted work never silently expires.
     */
    public enum State {
        /**
         * Awaiting independent administrative votes.
         */
        PENDING,
        /**
         * Policy permits a fresh dispatch claim.
         */
        APPROVED,
        /**
         * An administrator rejected the request.
         */
        REJECTED,
        /**
         * Unaccepted request passed its admission deadline.
         */
        EXPIRED,
        /**
         * Durable admission owns the exact prepared receipt.
         */
        DISPATCHING,
        /**
         * Signing authority accepted this exact operation.
         */
        ACCEPTED,
        /**
         * Credential was persisted and its binding verified.
         */
        ISSUED,
        /**
         * Acceptance or reconciliation requires authoritative recovery.
         */
        UNCERTAIN,
        /**
         * Accepted operation terminated without a credential.
         */
        FAILED
    }

    /**
     * Frozen endpoint identity. The replay namespace uses label; recordId and
     * revision are immutable admission preconditions, never replay-key inputs.
     *
     * @param protocol wire protocol
     * @param label stable configured endpoint label or ACME directory alias
     * @param recordId exact persisted endpoint/directory identity
     * @param revision positive revision
     * @param commitment complete endpoint record commitment
     * @param enrollmentProfileId explicit enrollment policy identity
     * @param enrollmentCommitment complete enrollment policy commitment
     * @param credentialId selected immutable protocol credential set, where required
     */
    public record Source(Protocol protocol, String label, String recordId, long revision, String commitment,
            String enrollmentProfileId, String enrollmentCommitment, Optional<String> credentialId) {
        /**
         * Checks bounded source identities, commitments and protocol-specific credential-reference presence.
         *
         * @param protocol wire protocol
         * @param label stable configured endpoint label or ACME directory alias
         * @param recordId exact persisted endpoint/directory identity
         * @param revision positive revision
         * @param commitment complete endpoint record commitment
         * @param enrollmentProfileId explicit enrollment policy identity
         * @param enrollmentCommitment complete enrollment policy commitment
         * @param credentialId selected immutable protocol credential set, where required
         * @throws NullPointerException if protocol or the credential-reference container is null
         * @throws IllegalArgumentException if identifiers/digests/revision or protocol credential selection
         *     shape is invalid
         */
        public Source {
            Objects.requireNonNull(protocol, "protocol"); id(label); id(recordId); id(enrollmentProfileId);
            digest(commitment); digest(enrollmentCommitment);
            if (revision <= 0) {
                throw invalid();
            }
            Objects.requireNonNull(credentialId, "credentialId").ifPresent(EnrollmentTransaction::id);
            if ((protocol == Protocol.SCEP || protocol == Protocol.CMP) && credentialId.isEmpty()
                    || protocol == Protocol.ACME && credentialId.isPresent()) {
                throw invalid();
            }
        }
        /**
         * Returns redacted snapshot description.
         *
         * @return redacted snapshot description
         */
        @Override public String toString() { return "EnrollmentTransaction.Source[redacted]"; }
    }

    /**
     * Authenticated protocol actor, distinct from an administrative principal.
     * Construction asserts no authentication; protocol adapters supply verified
     * evidence. PBM identities supply explicit configured owner aliases.
     *
     * @param type protocol actor classification
     * @param actorId stable protocol identity, account ID or configured PBM identity
     * @param authentication exact verified mechanism
     * @param certificate verified certificate evidence for certificate-authenticated protocols
     * @param canonicalKeySha256 verified mathematical requester key; absent for PBM
     * @param legacySpkiSha256 supported equivalent SPKI hashes for alias exclusion
     * @param aliases frozen realm-scoped administrative exclusions
     */
    public record Requester(IssuanceExecutionEvidence.ActorType type, String actorId,
            IssuanceExecutionEvidence.Authentication authentication, Optional<CertificateIdentityEvidence> certificate,
            Optional<String> canonicalKeySha256, Set<String> legacySpkiSha256, EnrollmentIdentityAliases.Snapshot aliases) {
        /**
         * Copies legacy-key aliases and checks actor/mechanism/evidence correspondence without authenticating
         * an actor.
         *
         * @param type protocol actor classification
         * @param actorId stable protocol identity, account ID or configured PBM identity
         * @param authentication exact verified mechanism
         * @param certificate verified certificate evidence for certificate-authenticated protocols
         * @param canonicalKeySha256 verified mathematical requester key; absent for PBM
         * @param legacySpkiSha256 supported equivalent SPKI hashes for alias exclusion
         * @param aliases frozen realm-scoped administrative exclusions
         * @throws NullPointerException if a required enum, container, alias snapshot or set element is null
         * @throws IllegalArgumentException if actor mechanism, digest syntax, legacy alias count or
         *     certificate/realm/key correspondence is invalid
         */
        public Requester {
            Objects.requireNonNull(type, "type"); id(actorId); Objects.requireNonNull(authentication, "authentication");
            Objects.requireNonNull(certificate, "certificate"); Objects.requireNonNull(canonicalKeySha256, "canonicalKeySha256");
            canonicalKeySha256.ifPresent(EnrollmentTransaction::digest);
            legacySpkiSha256 = Set.copyOf(Objects.requireNonNull(legacySpkiSha256, "legacySpkiSha256"));
            legacySpkiSha256.forEach(EnrollmentTransaction::digest);
            if (legacySpkiSha256.size() > MAX_LEGACY_KEY_COMMITMENTS) {
                throw invalid();
            }
            Objects.requireNonNull(aliases, "aliases");
            boolean valid = switch (type) {
                case EST_CLIENT -> authentication == IssuanceExecutionEvidence.Authentication.EST_MTLS && certificate.isPresent();
                case SCEP_SIGNER -> authentication == IssuanceExecutionEvidence.Authentication.SCEP_CMS && certificate.isPresent();
                case CMP_SIGNER -> authentication == IssuanceExecutionEvidence.Authentication.CMP_SIGNATURE && certificate.isPresent();
                case ACME_ACCOUNT -> authentication == IssuanceExecutionEvidence.Authentication.ACME_ACCOUNT_JWS && certificate.isEmpty();
                case CMP_PBM -> authentication == IssuanceExecutionEvidence.Authentication.CMP_PBM && certificate.isEmpty();
                case ADMIN_PRINCIPAL -> false;
            };
            if (!valid || type == IssuanceExecutionEvidence.ActorType.CMP_PBM == canonicalKeySha256.isPresent()
                    || canonicalKeySha256.isPresent() == legacySpkiSha256.isEmpty()) {
                throw invalid();
            }
            if (certificate.isPresent()) {
                CertificateIdentityEvidence evidence = certificate.orElseThrow();
                if (!evidence.realmId().equals(aliases.realmId()) || !canonicalKeySha256.orElseThrow().equals(evidence.canonicalKeySha256())
                        || !legacySpkiSha256.equals(evidence.legacySpkiSha256())) {
                    throw invalid();
                }
            }
        }
        /**
         * Returns redacted requester description.
         *
         * @return redacted requester description
         */
        @Override public String toString() { return "EnrollmentTransaction.Requester[redacted]"; }
    }

    /**
     * Frozen verified original request reference and complete issuance selection.
     *
     * @param realmId exact realm
     * @param source endpoint and credential selection
     * @param requester original authenticated actor
     * @param transactionId protocol transaction commitment, never secret/raw nonce data
     * @param operation requested operation kind
     * @param requestId exact immutable domain request reference
     * @param requestKind original syntax
     * @param requestSha256 exact original DER SHA-256
     * @param requestBytes original request size charged to retained capacity
     * @param authorityId logical issuing authority
     * @param profile frozen exact certificate profile
     * @param issuerId selected issuer generation
     * @param pathId selected chain path
     * @param pathCommitment exact selected chain commitment
     * @param validity requested validity override
     * @param predecessorId renewal or replacement predecessor, absent for issuance
     * @param predecessorSha256 exact predecessor digest, present for lifecycle operations
     * @param approvalCategory effective issuance approval category
     * @param approvalPolicy complete frozen approval policy when required
     * @param artifact immutable encrypted delivery binding for attached server-keygen work
     * @param createdAt admission time
     * @param expiresAt deadline for a fresh dispatch claim
     * @param sdkProof retained fresh dual-client proof reference, absent for ordinary enrollment
     */
    public record Intent(RealmId realmId, Source source, Requester requester, String transactionId, Operation operation,
            PkiId requestId, X509EnrollmentPayload.Kind requestKind, String requestSha256, int requestBytes,
            PkiId authorityId, CertificateProfileRef profile, PkiId issuerId, PkiId pathId, String pathCommitment,
            Optional<Validity> validity, Optional<PkiId> predecessorId, Optional<String> predecessorSha256,
            ApprovalCategory approvalCategory, Optional<ApprovalService.Policy> approvalPolicy, Optional<ArtifactBinding> artifact,
            Instant createdAt, Instant expiresAt, Optional<SdkProofReference> sdkProof) {
        /**
         * Creates an ordinary intent retaining the version-two representation.
         *
         * @param realmId owning realm
         * @param source frozen endpoint
         * @param requester genuine native actor
         * @param transactionId replay coordinate
         * @param operation native operation
         * @param requestId stored request
         * @param requestKind typed syntax
         * @param requestSha256 original digest
         * @param requestBytes original size
         * @param authorityId selected authority
         * @param profile certificate profile
         * @param issuerId selected generation
         * @param pathId selected path
         * @param pathCommitment exact path digest
         * @param validity optional validity
         * @param predecessorId lifecycle predecessor
         * @param predecessorSha256 exact predecessor digest
         * @param approvalCategory required approval
         * @param approvalPolicy frozen policy
         * @param artifact keygen binding
         * @param createdAt admission time
         * @param expiresAt dispatch deadline
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if delegated correspondence or operation constraints fail
         */
        public Intent(RealmId realmId, Source source, Requester requester, String transactionId, Operation operation,
                PkiId requestId, X509EnrollmentPayload.Kind requestKind, String requestSha256, int requestBytes,
                PkiId authorityId, CertificateProfileRef profile, PkiId issuerId, PkiId pathId, String pathCommitment,
                Optional<Validity> validity, Optional<PkiId> predecessorId, Optional<String> predecessorSha256,
                ApprovalCategory approvalCategory, Optional<ApprovalService.Policy> approvalPolicy, Optional<ArtifactBinding> artifact,
                Instant createdAt, Instant expiresAt) {
            this(realmId, source, requester, transactionId, operation, requestId, requestKind, requestSha256, requestBytes,
                    authorityId, profile, issuerId, pathId, pathCommitment, validity, predecessorId, predecessorSha256,
                    approvalCategory, approvalPolicy, artifact, createdAt, expiresAt, Optional.empty());
        }
        /**
         * Copies this immutable policy with an explicit retained SDK proof reference.
         *
         * @param proof exact optional SDK reference
         * @return new immutable intent with the supplied SDK proof reference
         * @throws NullPointerException if the proof container is null
         * @throws IllegalArgumentException if SDK proof is incompatible with artifact/server-keygen work
         */
        public Intent withSdkProof(Optional<SdkProofReference> proof) {
            return new Intent(realmId, source, requester, transactionId, operation, requestId, requestKind, requestSha256, requestBytes,
                    authorityId, profile, issuerId, pathId, pathCommitment, validity, predecessorId, predecessorSha256,
                    approvalCategory, approvalPolicy, artifact, createdAt, expiresAt, proof);
        }
        /**
         * Checks internally consistent frozen request/policy references without reading or admitting stored
         * objects.
         *
         * @param realmId exact realm
         * @param source endpoint and credential selection
         * @param requester original authenticated actor
         * @param transactionId protocol transaction commitment, never secret/raw nonce data
         * @param operation requested operation kind
         * @param requestId exact immutable domain request reference
         * @param requestKind original syntax
         * @param requestSha256 exact original DER SHA-256
         * @param requestBytes original request size charged to retained capacity
         * @param authorityId logical issuing authority
         * @param profile frozen exact certificate profile
         * @param issuerId selected issuer generation
         * @param pathId selected chain path
         * @param pathCommitment exact selected chain commitment
         * @param validity requested validity override
         * @param predecessorId renewal or replacement predecessor, absent for issuance
         * @param predecessorSha256 exact predecessor digest, present for lifecycle operations
         * @param approvalCategory effective issuance approval category
         * @param approvalPolicy complete frozen approval policy when required
         * @param artifact immutable encrypted delivery binding for attached server-keygen work
         * @param createdAt admission time
         * @param expiresAt deadline for a fresh dispatch claim
         * @param sdkProof retained fresh dual-client proof reference, absent for ordinary enrollment
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if identifiers/digests, request size, time order, actor/protocol,
         *     predecessor, approval or artifact/SDK operation shape is invalid
         */
        public Intent {
            Objects.requireNonNull(sdkProof, "sdkProof");
            if (sdkProof.isPresent() && (artifact.isPresent() || operation == Operation.SERVER_KEYGEN)) throw invalid();
            Objects.requireNonNull(realmId, "realmId"); Objects.requireNonNull(source, "source");
            Objects.requireNonNull(requester, "requester"); digest(transactionId); Objects.requireNonNull(operation, "operation");
            Objects.requireNonNull(requestId, "requestId"); Objects.requireNonNull(requestKind, "requestKind"); digest(requestSha256);
            Objects.requireNonNull(authorityId, "authorityId"); Objects.requireNonNull(profile, "profile");
            Objects.requireNonNull(issuerId, "issuerId"); Objects.requireNonNull(pathId, "pathId"); digest(pathCommitment);
            id(requestId.value()); id(authorityId.value()); id(profile.profileId()); id(issuerId.value()); id(pathId.value());
            Objects.requireNonNull(validity, "validity"); Objects.requireNonNull(predecessorId, "predecessorId");
            Objects.requireNonNull(predecessorSha256, "predecessorSha256").ifPresent(EnrollmentTransaction::digest);
            Objects.requireNonNull(approvalCategory, "approvalCategory"); Objects.requireNonNull(approvalPolicy, "approvalPolicy");
            Objects.requireNonNull(artifact, "artifact");
            if (source.protocol() == Protocol.EST && operation == Operation.SERVER_KEYGEN != source.credentialId().isPresent()) {
                throw invalid();
            }
            if (artifact.isPresent() && operation != Operation.SERVER_KEYGEN
                    || operation == Operation.SERVER_KEYGEN && (source.protocol() != Protocol.EST || requestKind != X509EnrollmentPayload.Kind.PKCS10)) {
                throw invalid();
            }
            Objects.requireNonNull(createdAt, "createdAt"); Objects.requireNonNull(expiresAt, "expiresAt");
            if (!realmId.equals(requester.aliases().realmId()) || requestBytes < 1 || requestBytes > X509EnrollmentPayload.MAXIMUM_DER_BYTES
                    || !expiresAt.isAfter(createdAt) || (operation == Operation.RENEW || operation == Operation.REPLACE) != predecessorId.isPresent()
                    || predecessorId.isPresent() != predecessorSha256.isPresent()
                    || approvalCategory != ApprovalCategory.NONE != approvalPolicy.isPresent()
                    || approvalCategory != ApprovalCategory.NONE && approvalCategory != ApprovalCategory.ISSUANCE_SINGLE
                    && approvalCategory != ApprovalCategory.ISSUANCE_THRESHOLD) {
                throw invalid();
            }
            boolean actorMatches = switch (source.protocol()) {
                case EST -> requester.type() == IssuanceExecutionEvidence.ActorType.EST_CLIENT;
                case SCEP -> requester.type() == IssuanceExecutionEvidence.ActorType.SCEP_SIGNER;
                case CMP -> requester.type() == IssuanceExecutionEvidence.ActorType.CMP_SIGNER || requester.type() == IssuanceExecutionEvidence.ActorType.CMP_PBM;
                case ACME -> requester.type() == IssuanceExecutionEvidence.ActorType.ACME_ACCOUNT;
            };
            if (!actorMatches) {
                throw invalid();
            }
            if (operation == Operation.REPLACE && (source.protocol() != Protocol.CMP
                    || requester.type() != IssuanceExecutionEvidence.ActorType.CMP_SIGNER
                    || requestKind != X509EnrollmentPayload.Kind.CRMF || (sdkProof.isEmpty() ? validity.isPresent() : validity.isEmpty()))) {
                throw invalid();
            }
            if (approvalCategory == ApprovalCategory.ISSUANCE_SINGLE && approvalPolicy.orElseThrow().threshold() != 1
                    || approvalCategory == ApprovalCategory.ISSUANCE_THRESHOLD && approvalPolicy.orElseThrow().threshold() < 2) {
                throw invalid();
            }
        }
        /**
         * Returns redacted intent description.
         *
         * @return redacted intent description
         */
        @Override public String toString() { return "EnrollmentTransaction.Intent[redacted]"; }
    }

    /**
     * Frozen client-encrypted key delivery, included in issuance and approval commitments.
     *
     * @param artifactId stable generation descriptor identity
     * @param generationCommitment complete original template and generation-policy commitment
     * @param ciphertextSha256 exact encrypted body commitment
     * @param ciphertextBytes bounded encrypted body length
     */
    public record ArtifactBinding(String artifactId, String generationCommitment, String ciphertextSha256, long ciphertextBytes) {
        /**
         * Checks encrypted-delivery reference digests and byte bounds without reading or granting delivery.
         *
         * @param artifactId stable generation descriptor identity
         * @param generationCommitment complete original template and generation-policy commitment
         * @param ciphertextSha256 exact encrypted body commitment
         * @param ciphertextBytes bounded encrypted body length
         * @throws IllegalArgumentException if a digest is malformed or ciphertext length is outside 1 through
         *     16777216 bytes
         */
        public ArtifactBinding {
            digest(artifactId); digest(generationCommitment); digest(ciphertextSha256);
            if (ciphertextBytes < 1 || ciphertextBytes > 16_777_216) {
                throw invalid();
            }
        }
        /**
         * Returns redacted artifact description.
         *
         * @return redacted artifact description
         */
        @Override public String toString() { return "EnrollmentTransaction.ArtifactBinding[redacted]"; }
    }

    /**
     * One verified independent administrative decision.
     *
     * @param principalId registered administrator
     * @param evidence trusted actual end-client credential evidence
     * @param choice approval or terminal rejection
     * @param justification bounded operator justification
     * @param decidedAt authoritative decision time
     */
    public record Decision(String principalId, CertificateIdentityEvidence evidence, ApprovalService.Choice choice,
            String justification, Instant decidedAt) {
        /**
         * Checks administrative decision coordinates without verifying a live principal or credential.
         *
         * @param principalId registered administrator
         * @param evidence trusted actual end-client credential evidence
         * @param choice approval or terminal rejection
         * @param justification bounded operator justification
         * @param decidedAt authoritative decision time
         * @throws NullPointerException if evidence, choice or decidedAt is null
         * @throws IllegalArgumentException if principal identity is invalid or justification is null or longer
         *     than 2048 characters
         */
        public Decision {
            id(principalId); Objects.requireNonNull(evidence, "evidence"); Objects.requireNonNull(choice, "choice");
            Objects.requireNonNull(decidedAt, "decidedAt");
            if (justification == null || justification.length() > 2048) {
                throw invalid();
            }
        }
        /**
         * Returns redacted decision description.
         *
         * @return redacted decision description
         */
        @Override public String toString() { return "EnrollmentTransaction.Decision[redacted]"; }
    }

    /**
     * Copies decisions and checks state-dependent receipts, independent votes and threshold consistency.
     *
     * @param id stable replay identity, independent of endpoint revision
     * @param revision monotonic positive mutation revision
     * @param intent immutable admitted request and policy snapshot
     * @param state durable workflow state
     * @param decisions verified administrative decisions
     * @param receipt prepared signing receipt persisted before acceptance
     * @param credentialId completed credential, present only for ISSUED
     * @throws NullPointerException if intent, state, a container/list or a decision element is null
     * @throws IllegalArgumentException if identities/revision/counts, receipt/credential state, artifact
     *     binding or independent decision/threshold constraints fail
     */
    public EnrollmentTransaction {
        if (intent != null && intent.operation() == Operation.SERVER_KEYGEN != intent.artifact().isPresent()) {
            throw invalid();
        }
        id(id); Objects.requireNonNull(intent, "intent"); Objects.requireNonNull(state, "state");
        decisions = List.copyOf(Objects.requireNonNull(decisions, "decisions"));
        Objects.requireNonNull(receipt, "receipt"); Objects.requireNonNull(credentialId, "credentialId");
        if (revision <= 0 || decisions.size() > 4096 || state == State.ISSUED != credentialId.isPresent()
                || (state == State.DISPATCHING || state == State.ACCEPTED || state == State.ISSUED || state == State.FAILED)
                && receipt.isEmpty()) {
            throw invalid();
        }
        if ((state == State.PENDING || state == State.APPROVED || state == State.REJECTED || state == State.EXPIRED) && receipt.isPresent()
                || state == State.UNCERTAIN && receipt.isEmpty()) {
            throw invalid();
        }
        Set<String> principals = new TreeSet<>(); Set<String> keys = new TreeSet<>();
        int approvals = 0;
        boolean rejected = false;
        for (Decision decision : decisions) {
            Requester requester = intent.requester();
            if (!principals.add(decision.principalId()) || !keys.add(decision.evidence().canonicalKeySha256())
                    || !intent.realmId().equals(decision.evidence().realmId()) || decision.decidedAt().isBefore(intent.createdAt())
                    || !decision.decidedAt().isBefore(intent.expiresAt()) || rejected
                    || requester.aliases().principalIds().contains(decision.principalId())
                    || requester.certificate().filter(decision.evidence()::sameCredential).isPresent()
                    || requester.canonicalKeySha256().filter(decision.evidence().canonicalKeySha256()::equals).isPresent()
                    || intent.approvalPolicy().filter(ApprovalService.Policy::justificationRequired).isPresent()
                            && decision.justification().isBlank()) {
                throw invalid();
            }
            if (decision.choice() == ApprovalService.Choice.APPROVE) {
                approvals++;
            } else {
                rejected = true;
            }
        }
        int threshold = intent.approvalPolicy().map(ApprovalService.Policy::threshold).orElse(0);
        if (approvals > threshold || threshold == 0 && !decisions.isEmpty() || rejected != (state == State.REJECTED)
                || state == State.PENDING && (threshold == 0 || approvals >= threshold)
                || state != State.PENDING && state != State.REJECTED && state != State.EXPIRED && approvals != threshold) {
            throw invalid();
        }
    }

    /**
     * Returns the complete immutable intent commitment used by issuance and approval.
     *
     * @return SHA-256 intent commitment
     */
    public String intentCommitment() { return EnrollmentTransactionCodec.intentCommitment(intent); }
    /**
     * Returns the complete versioned persisted record commitment.
     *
     * @return SHA-256 record commitment
     */
    public String commitment() { return EnrollmentTransactionCodec.record(this).commitment(); }
    /**
     * Returns redacted workflow description.
     *
     * @return redacted workflow description
     */
    @Override public String toString() { return "EnrollmentTransaction[state=" + state + ", redacted]"; }

    /**
     * Requires a canonical bounded enrollment transaction coordinate.
     *
     * @param value identity text to validate without normalization
     * @throws IllegalArgumentException if identity is null, empty, oversized or noncanonical
     */
    /* default */ static void id(String value) { EnrollmentEndpoint.requireProfileId(value); }
    /**
     * Requires a lowercase hexadecimal SHA-256 commitment.
     *
     * @param value exact 64-character digest text
     * @throws IllegalArgumentException if the value is null or has another syntax
     */
    /* default */ static void digest(String value) { if (value == null || !value.matches("[0-9a-f]{64}")) {
        throw invalid();
    } }
    /**
     * Creates the safe fixed-classification exception for invalid enrollment state.
     *
     * @return fresh exception without private payload or provider diagnostics
     */
    /* default */ static IllegalArgumentException invalid() { return new IllegalArgumentException("Enrollment transaction is invalid"); }
}
