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
package zeroecho.pki.server;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;

/**
 * Private, durable administrative execution intent; target arguments never belong in list projections.
 *
 * <p>Construction retains immutable argument/result references and checks local
 * shape only. It does not authenticate an actor, recompute operation/target
 * commitments, establish receipt ownership or enforce every state-dependent
 * result/receipt rule. The execution coordinator owns those durable boundaries.
 * A redacted toString does not sanitize retained argument or result contents.</p>
 *
 * @param requestId client-selected durable idempotency identity
 * @param revision monotonic request revision
 * @param operation closed operation catalog identity
 * @param envelope strict canonical operation envelope, without caller-supplied identity or approval
 * @param actor originally authenticated requester and trusted credential commitments
 * @param scope authoritative target scope at admission
 * @param operationCommitment exact gateway operation commitment
 * @param profileCommitment optional exact active profile version/hash binding
 * @param targetCommitment operation plus execution-budget idempotency commitment
 * @param state durable lifecycle state
 * @param createdAt admission time
 * @param updatedAt last durable transition time
 * @param executionTimeoutMillis bounded execution budget starting only after approval
 * @param approvalId deterministic linked approval, absent for approval-free operations
 * @param policyCommitment frozen required policy commitment
 * @param receipt exact prepared signing receipt persisted before acceptance
 * @param result terminal ordinary typed result, never a reusable secret
 * @param failureCode bounded safe machine code
 * @param sdkProof optional immutable dual-subject proof reference; absent for ordinary requests
 */
public record AdministrativeRequest(String requestId, long revision, String operation,
        PkiOperationValue.ObjectValue envelope, Actor actor, Permission.Scope scope, String operationCommitment,
        Optional<String> profileCommitment, String targetCommitment, State state, Instant createdAt, Instant updatedAt, long executionTimeoutMillis,
        Optional<String> approvalId, Optional<String> policyCommitment, Optional<SigningAcceptanceReceipt> receipt,
        Optional<PkiOperationValue.ObjectValue> result, Optional<String> failureCode, Optional<SdkProof> sdkProof) {
    /**
     * Creates an ordinary version-one request without an SDK proof reference.
     *
     * @param requestId durable identity
     * @param revision revision
     * @param operation operation
     * @param envelope exact envelope
     * @param actor trusted actor
     * @param scope target scope
     * @param operationCommitment operation commitment
     * @param profileCommitment profile commitment
     * @param targetCommitment target commitment
     * @param state state
     * @param createdAt creation time
     * @param updatedAt transition time
     * @param executionTimeoutMillis budget
     * @param approvalId approval
     * @param policyCommitment policy
     * @param receipt signing receipt
     * @param result result
     * @param failureCode safe failure
     * @throws NullPointerException if a required delegated value or optional container is null
     * @throws IllegalArgumentException if delegated identity, timing, commitment or linkage checks fail
     */
    // Retain the established public compatibility constructor.
    @SuppressWarnings({"PMD.ExcessiveParameterList"})
    public AdministrativeRequest(String requestId, long revision, String operation,
            PkiOperationValue.ObjectValue envelope, Actor actor, Permission.Scope scope, String operationCommitment,
            Optional<String> profileCommitment, String targetCommitment, State state, Instant createdAt, Instant updatedAt, long executionTimeoutMillis,
            Optional<String> approvalId, Optional<String> policyCommitment, Optional<SigningAcceptanceReceipt> receipt,
            Optional<PkiOperationValue.ObjectValue> result, Optional<String> failureCode) {
        this(requestId, revision, operation, envelope, actor, scope, operationCommitment, profileCommitment,
                targetCommitment, state, createdAt, updatedAt, executionTimeoutMillis, approvalId, policyCommitment, receipt, result, failureCode, Optional.empty());
    }

    /**
     * Reference to the consumed private SDK intent; it is not a bearer credential.
     *
     * @param intentId server-generated lowercase 32-byte hexadecimal identity
     * @param proofCommitment complete domain-separated F3 SHA-512 commitment
     */
    public record SdkProof(String intentId, String proofCommitment) {
        /**
         * Checks the server intent identity and F3 commitment syntax without verifying or consuming proofs.
         *
         * @param intentId server-generated lowercase 32-byte hexadecimal identity
         * @param proofCommitment complete domain-separated F3 SHA-512 commitment
         * @throws IllegalArgumentException either coordinate is null or noncanonical
         */
        public SdkProof {
            if (intentId == null || !intentId.matches("[0-9a-f]{64}") || proofCommitment == null
                    || !proofCommitment.matches("sha512:[0-9a-f]{128}")) { throw new IllegalArgumentException("SDK proof reference is invalid"); }
        }
    }
    /**
     * Durable states; admitted signing is always reconciled from its exact receipt.
     */
    public enum State {
        /**
         * Waiting for an explicit human decision.
         */
        WAITING_APPROVAL,
        /**
         * Eligible for a new authorized dispatch.
         */
        READY,
        /**
         * Durable claim precedes acceptance or a synchronous mutation.
         */
        DISPATCHING,
        /**
         * Exact signing acceptance is observed.
         */
        RUNNING,
        /**
         * Domain operation completed.
         */
        SUCCEEDED,
        /**
         * Definitive safe failure.
         */
        FAILED,
        /**
         * Human rejected the request.
         */
        REJECTED,
        /**
         * Approval or a pre-admission execution budget expired.
         */
        EXPIRED,
        /**
         * Outcome cannot be safely replayed.
         */
        RECONCILIATION_REQUIRED
    }

    /**
     * Original trusted actor snapshot; none of these commitments grants authority on its own.
     *
     * @param principalId original requesting USER/SERVICE identity
     * @param mode original authenticated transport mode
     * @param transportPrincipalId dedicated proxy identity in reverse-proxy mode
     * @param evidence validated certificate/key commitments, never credentials or keys
     */
    public record Actor(String principalId, AdministrativeAuthenticationMode mode,
            Optional<String> transportPrincipalId, Optional<CertificateIdentityEvidence> evidence) {
        /**
         * Checks principal and transport-mode correspondence without authenticating a principal.
         *
         * @param principalId original requesting USER/SERVICE identity
         * @param mode original authenticated transport mode
         * @param transportPrincipalId dedicated proxy identity in reverse-proxy mode
         * @param evidence validated certificate/key commitments, never credentials or keys
         * @throws NullPointerException if a required value or optional container is null
         * @throws IllegalArgumentException principal grammar or reverse-proxy transport-principal presence is
         *     invalid
         */
        public Actor {
            Permission.requirePrincipal(principalId);
            Objects.requireNonNull(mode, "mode");
            transportPrincipalId = Objects.requireNonNull(transportPrincipalId, "transportPrincipalId");
            evidence = Objects.requireNonNull(evidence, "evidence");
            transportPrincipalId.ifPresent(Permission::requirePrincipal);
            if (mode==AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY !=transportPrincipalId.isPresent()) {
                throw new IllegalArgumentException("Actor transport identity differs from authentication mode");
            }
        }
    }

    /**
     * Checks finite identity, timing, commitment syntax and linkage shape without executing a transition.
     *
     * @param requestId client-selected durable idempotency identity
     * @param revision monotonic request revision
     * @param operation closed operation catalog identity
     * @param envelope strict canonical operation envelope, without caller-supplied identity or approval
     * @param actor originally authenticated requester and trusted credential commitments
     * @param scope authoritative target scope at admission
     * @param operationCommitment exact gateway operation commitment
     * @param profileCommitment optional exact active profile version/hash binding
     * @param targetCommitment operation plus execution-budget idempotency commitment
     * @param state durable lifecycle state
     * @param createdAt admission time
     * @param updatedAt last durable transition time
     * @param executionTimeoutMillis bounded execution budget starting only after approval
     * @param approvalId deterministic linked approval, absent for approval-free operations
     * @param policyCommitment frozen required policy commitment
     * @param receipt exact prepared signing receipt persisted before acceptance
     * @param result terminal ordinary typed result, never a reusable secret
     * @param failureCode bounded safe machine code
     * @param sdkProof optional immutable dual-subject proof reference; absent for ordinary requests
     * @throws NullPointerException if a required value or optional container is null
     * @throws IllegalArgumentException identity, revision, operation syntax, digest syntax, time order,
     *     1-through-120000 millisecond budget or linkage is invalid
     */
    public AdministrativeRequest {
        Permission.requireId(requestId, "administrative request");
        if (revision < 0 || operation == null || !operation.matches("[a-z][a-z0-9.-]{2,127}")) { throw new IllegalArgumentException("Request identity is invalid"); }
        Objects.requireNonNull(envelope, "envelope"); Objects.requireNonNull(actor, "actor"); Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(state, "state"); Objects.requireNonNull(createdAt, "createdAt"); Objects.requireNonNull(updatedAt, "updatedAt");
        if (!operationCommitment.matches("[0-9a-f]{64}") || !targetCommitment.matches("[0-9a-f]{64}")
                || updatedAt.isBefore(createdAt) || executionTimeoutMillis < 1 || executionTimeoutMillis > 120_000) {
            throw new IllegalArgumentException("Request commitments or execution budget are invalid");
        }
        profileCommitment = Objects.requireNonNull(profileCommitment, "profileCommitment");
        sdkProof = Objects.requireNonNull(sdkProof, "sdkProof");
        approvalId = Objects.requireNonNull(approvalId, "approvalId"); policyCommitment = Objects.requireNonNull(policyCommitment, "policyCommitment");
        receipt = Objects.requireNonNull(receipt, "receipt"); result = Objects.requireNonNull(result, "result"); failureCode = Objects.requireNonNull(failureCode, "failureCode");
        profileCommitment.ifPresent(value -> {if(!value.matches("[0-9a-f]{64}")){ throw new IllegalArgumentException("Profile commitment is invalid"); }});
        approvalId.ifPresent(value -> Permission.requireId(value,"approval"));
        actor.evidence().ifPresent(value -> {if(!value.realmId().equals(scope.realmId())){ throw new IllegalArgumentException("Actor evidence realm differs"); }});
        if (approvalId.isPresent() != policyCommitment.isPresent() || policyCommitment.filter(value -> !value.matches("[0-9a-f]{64}")).isPresent()
                || failureCode.filter(value -> !value.matches("[A-Z0-9_]{3,128}")).isPresent()) { throw new IllegalArgumentException("Request linkage is invalid"); }
    }

    /**
     * Returns whether no automated dispatch or observation remains.
     *
     * @return whether no automated dispatch or observation remains
     */
    public boolean terminal() { return switch (state) { case SUCCEEDED, FAILED, REJECTED, EXPIRED, RECONCILIATION_REQUIRED -> true; default -> false; }; }
    /**
     * Returns diagnostic representation without arguments, result content or credential hashes.
     *
     * @return diagnostic representation without arguments, result content or credential hashes
     */
    @Override public String toString() { return "AdministrativeRequest[redacted," + state + "]"; }
}
