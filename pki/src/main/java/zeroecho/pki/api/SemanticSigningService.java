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

package zeroecho.pki.api;

import zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest;
import zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest;
import java.util.Optional;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.issuance.EndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.CorrelatedEndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.CorrelatedIssuancePreparation;
import zeroecho.pki.api.issuance.RetainedIssuanceBinding;
import zeroecho.pki.api.issuance.EndEntityRenewalRequest;
import zeroecho.pki.api.issuance.EndEntityReplacementRequest;
import zeroecho.pki.api.issuance.EndEntityReissueRequest;

import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.ManagedKeyProofRequest;
import zeroecho.pki.api.signing.SemanticSigningKind;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.api.signing.SigningAcceptanceResolution;
import zeroecho.pki.api.signing.SigningAcceptanceResult;
import zeroecho.pki.api.status.FullCrlRequest;
import zeroecho.pki.api.status.DeltaCrlRequest;
import zeroecho.pki.application.IssuanceExecutionEvidence;

/**
 * Privileged, thread-safe lifecycle boundary for durably signed domain operations.
 *
 * <p>The owning session shares its existing signing acceptance gate, provider and
 * reactor. Callers must authenticate and authorize each action, including lookup
 * and result disclosure. Identifiers, receipts, correlations and returned scope
 * are metadata, never authorization capabilities. A successful signature alone
 * does not complete a domain operation.</p>
 *
 * <p>Leaf preparation accepts optional trusted issuance evidence supplied by the
 * authenticated orchestration layer, never by an untrusted request body. Present
 * evidence must match the access principal's name and actor type and the frozen
 * issuing authority and profile. An empty optional preserves embedded issuance
 * without server execution evidence. Evidence is bound before content staging.</p>
 *
 * <p>Prepared values originate from module-owned domain preparation. This interface
 * intentionally exposes no generic candidate or encoded-command preparation.
 * Implementations retain no per-operation runtime handle.</p>
 */
public interface SemanticSigningService {
    /**
     * Returns the configured canonical signature default used for CA creation.
     *
     * <p>This value does not select or replace the immutable outgoing algorithm of
     * an existing issuer generation. The default implementation does not support
     * creation and throws rather than inventing a fallback algorithm.
     *
     * @return the configured canonical creation signature identity
     * @throws UnsupportedOperationException if creation is unavailable
     */
    default String creationSignatureAlgorithm() {
        throw new UnsupportedOperationException("Creation unavailable");
    }

    /**
     * Freezes omitted rotation members and the expected original selected head.
     * This pure operation never generates keys, signs, stages or authorizes use.
     * @param command explicit role selection and optional caller-supplied head fence
     * @return complete selector and authoritative expected head
     * @throws UnsupportedOperationException if normalization is unavailable
     * @throws PkiException if the supplied expected head is stale or evidence is absent
     */
    default zeroecho.pki.api.ca.CaKeyRotationCommand normalizeCaKeyRotation(
            zeroecho.pki.api.ca.CaKeyRotationCommand command) {
        throw new UnsupportedOperationException("CA rotation normalization unavailable");
    }

    /**
     * Captures or checks one expected CA head before approval without staging/signing.
     * @param caId logical subject authority
     * @param expected supplied fence, or an empty optional before initial normalization
     * @return exact authoritative generation/path/binding/epoch fence
     * @throws PkiException if a supplied fence is stale or current evidence is absent
     * @throws UnsupportedOperationException if this pure domain seam is unavailable
     */
    default zeroecho.pki.api.ca.CaHeadSnapshot freezeCaHead(PkiId caId,
            Optional<zeroecho.pki.api.ca.CaHeadSnapshot> expected) {
        throw new UnsupportedOperationException("CA head normalization unavailable");
    }

    /**
     * Validates issuance of another credential for an existing intermediate authority.
     *
     * <p>Authoritative subject-key, profile and issuer/path policy is evaluated
     * without reserving a serial, signing, staging content or accepting work.
     * This pre-approval check does not replace execution-time revalidation or
     * authorize use of the parent and subject authorities.
     *
     * @param access authenticated and authorized invocation context
     * @param command exact intermediate authority, expected key, profile and proof coordinates
     * @param cancellation cooperative cancellation
     * @throws UnsupportedOperationException if pure validation is unavailable
     * @throws RuntimeException if input or authoritative state is invalid
     */
    default void validateIntermediateIssuance(AccessContext access, zeroecho.pki.api.ca.IntermediateCertIssueCommand command,
            CancellationSignal cancellation) {
        throw new UnsupportedOperationException("Pure input validation unavailable");
    }

    /**
     * Validates a same-key root or intermediate rollover against current authority policy.
     *
     * <p>The selected authority, key, profile and expected head are checked without
     * serial reservation, signing, staging or acceptance. A successful check is not
     * a possession proof and does not freeze mutable state for later execution.
     *
     * @param access authenticated and authorized invocation context
     * @param command closed root or intermediate rollover request
     * @param cancellation cooperative cancellation
     * @throws UnsupportedOperationException if pure validation is unavailable
     * @throws RuntimeException if input or authoritative state is invalid
     */
    default void validateCaRollover(AccessContext access, zeroecho.pki.api.ca.CaRolloverCommand command,
            CancellationSignal cancellation) {
        throw new UnsupportedOperationException("Pure input validation unavailable");
    }

    /**
     * Validates explicit outgoing role changes against the selected CA's retained binding.
     *
     * <p>Omitted members and the expected head are normalized from authoritative state.
     * Validation does not generate keys, reserve a serial, sign, stage content or accept
     * work. Execution must still revalidate the selection and required fresh proofs.
     *
     * @param access authenticated and authorized invocation context
     * @param command explicit root or intermediate key/algorithm role selection
     * @param cancellation cooperative cancellation
     * @throws UnsupportedOperationException if pure validation is unavailable
     * @throws RuntimeException if input or authoritative state is invalid
     */
    default void validateCaKeyRotation(AccessContext access, zeroecho.pki.api.ca.CaKeyRotationCommand command,
            CancellationSignal cancellation) {
        throw new UnsupportedOperationException("Pure input validation unavailable");
    }

    /**
     * Validates a new end-entity request and its prospective signing input before approval.
     *
     * <p>CSR, subject, profile, issuer and algorithm/input-size policy are evaluated
     * without serial allocation, signing, durable staging or acceptance. Supplied
     * execution evidence must come from the authenticated orchestration layer;
     * it is not applicant-controlled authorization.
     *
     * @param access authenticated and authorized invocation context
     * @param command exact bounded request payload and issuer/profile selection
     * @param evidence trusted execution evidence, or an empty optional for embedded use
     * @param cancellation cooperative cancellation
     * @throws UnsupportedOperationException if pure validation is unavailable
     * @throws RuntimeException if input or authoritative state is invalid
     */
    default void validateEndEntity(AccessContext access, zeroecho.pki.api.issuance.EndEntityIssuanceRequest command,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("Pure input validation unavailable");
    }

    /**
     * Validates renewal of the retained predecessor under current lifecycle policy.
     *
     * <p>The prospective unchanged-subject/key certificate and signing-input bounds
     * are checked without reserving a serial, signing, staging or accepting work.
     * The predecessor is not mutated, and a successful check does not bypass later
     * status or policy revalidation.
     *
     * @param access authenticated and authorized invocation context
     * @param command exact predecessor identity and requested renewal validity
     * @param evidence trusted execution evidence, or an empty optional for embedded use
     * @param cancellation cooperative cancellation
     * @throws UnsupportedOperationException if pure validation is unavailable
     * @throws RuntimeException if input or authoritative state is invalid
     */
    default void validateRenewal(AccessContext access, zeroecho.pki.api.issuance.EndEntityRenewalRequest command,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("Pure input validation unavailable");
    }

    /**
     * Validates a replacement request and predecessor-key reuse eligibility before approval.
     *
     * <p>The original proof, selected profile, predecessor and prospective signing
     * input are evaluated without serial allocation, signing, staging or acceptance.
     * This check neither changes predecessor status nor substitutes for the exact
     * request and lifecycle checks repeated during preparation.
     *
     * @param access authenticated and authorized invocation context
     * @param command exact predecessor, bounded replacement request and selected profile
     * @param evidence trusted execution evidence, or an empty optional for embedded use
     * @param cancellation cooperative cancellation
     * @throws UnsupportedOperationException if pure validation is unavailable
     * @throws RuntimeException if input or authoritative state is invalid
     */
    default void validateReplacement(AccessContext access, zeroecho.pki.api.issuance.EndEntityReplacementRequest command,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("Pure input validation unavailable");
    }

    /**
     * Validates reissue of a predecessor's subject, SANs and keys under current policy.
     *
     * <p>Authoritative predecessor, profile, issuer and signing-input bounds are
     * evaluated without serial allocation, signing, staging or acceptance. No
     * predecessor mutation occurs; the validation result does not reserve future
     * issuer selection or exempt execution from rechecking current eligibility.
     *
     * @param access authenticated and authorized invocation context
     * @param command exact authoritative predecessor selected for reissue
     * @param evidence trusted execution evidence, or an empty optional for embedded use
     * @param cancellation cooperative cancellation
     * @throws UnsupportedOperationException if pure validation is unavailable
     * @throws RuntimeException if input or authoritative state is invalid
     */
    default void validateReissue(AccessContext access, zeroecho.pki.api.issuance.EndEntityReissueRequest command,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("Pure input validation unavailable");
    }

    /**
     * Validates root creation using current profile, public-key and algorithm
     * metadata without signing, allocating a serial, staging content or accepting
     * an operation. Execution repeats validation against its current inputs.
     *
     * @param access separately authenticated and authorized invocation context
     * @param command existing managed key, profile and subject coordinates
     * @param cancellation cooperative validation cancellation
     * @throws UnsupportedOperationException if this provider has no pure validator
     * @throws PkiException if known profile, subject or key policy rejects input
     * @throws NullPointerException if an argument is null
     */
    default void validateRootCreation(AccessContext access, zeroecho.pki.api.ca.CaCreateCommand command,
            CancellationSignal cancellation) {
        throw new UnsupportedOperationException("Pure root creation validation unavailable");
    }

    /**
     * Validates intermediate creation using current issuer/path, profile and
     * public-key metadata without signing, serial allocation, staging or acceptance.
     * Execution repeats validation, including its fresh proof and signing boundary.
     *
     * @param access separately authenticated and authorized invocation context
     * @param command existing issuer, managed key, profile and subject coordinates
     * @param cancellation cooperative validation cancellation
     * @throws UnsupportedOperationException if this provider has no pure validator
     * @throws PkiException if known issuer, profile, subject or key policy rejects input
     * @throws NullPointerException if an argument is null
     */
    default void validateIntermediateCreation(AccessContext access, zeroecho.pki.api.ca.IntermediateCreateCommand command,
            CancellationSignal cancellation) {
        throw new UnsupportedOperationException("Pure intermediate creation validation unavailable");
    }

    /**
     * Prepares a self-issued root certificate using an existing managed key and
     * the exact active root profile. The caller must separately authenticate and
     * authorize root creation. The selected provider exports its canonical DER
     * public key once; profile-approved subject, key, extensions and inward-rounded
     * whole-second validity are frozen before staging. A fresh eventual root
     * self-signature must verify against that key; retained proofs do not replace it.
     *
     * <p>Preparation performs no provider signing dispatch, durable acceptance,
     * serial reservation or CA mutation. Each invocation allocates a fresh operation
     * identity. The returned single-use value owns one staged TBS until acceptance
     * or discard. Its derived authority is a scheduling coordinate, not permission;
     * root creation retains realm-scoped semantic metadata. Local work and memory
     * are linear in bounded key, subject, TBS and command sizes, plus existing
     * provider/planning/store costs.</p>
     *
     * @param access separately authenticated and authorized invocation context
     * @param command root profile, subject and mandatory existing managed key
     * @param cancellation cooperative pre-acceptance cancellation
     * @return unused preparation owned by this session
     * @throws NullPointerException if an argument or exported public key is null
     * @throws IllegalArgumentException if an algorithm binding or input bound is invalid
     * @throws PkiException if profile, subject, key, staging or cancellation validation fails
     * @throws SigningExecutionException if the session no longer accepts preparation
     */
    PreparedSemanticSigningRequest prepareRootCreation(AccessContext access,
            zeroecho.pki.api.ca.CaCreateCommand command, CancellationSignal cancellation);

    /**
     * Prepares creation of an intermediate CA from an exact retained completed
     * managed-key proof, active issuer selection and active intermediate profile.
     * The caller must separately authenticate and authorize the invocation.
     * No signing dispatch, acceptance, serial reservation or CA mutation occurs.
     * The returned single-use preparation owns one staged TBS until acceptance
     * or discard. Acceptance freezes the proof provenance, so later proof purge
     * does not require another lookup. Work is bounded by the selected parent
     * chain (at most 31 certificates), command and certificate sizes.
     *
     * @param access trusted authorized invocation context
     * @param command exact intermediate creation coordinates and proof identifier
     * @param cancellation cooperative pre-acceptance cancellation
     * @return unused preparation owned by this session
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if proof coordinates or bindings differ
     * @throws PkiException if issuer/profile/path validation, content access or cancellation fails
     * @throws SigningExecutionException if the session no longer accepts preparation
     */
    PreparedSemanticSigningRequest prepareIntermediateCreation(AccessContext access,
            zeroecho.pki.api.ca.IntermediateCreateCommand command, CancellationSignal cancellation);

    /**
     * Prepares an additional certificate for an active existing intermediate CA.
     * Uses the explicit requested active profile, the authoritative current subject
     * key and an exact completed parent/subject/profile/key proof. The existing
     * subject principal, including fixed RDNs, is preserved. Nonempty generic
     * attributes are rejected; the requested validity is policy-checked and narrowed
     * to whole seconds. Successful publication appends an issuer generation while
     * preserving the authority's current key and issuance selection.
     *
     * <p>The caller authenticates and authorizes the invocation separately. No
     * signing dispatch, acceptance, serial reservation or CA mutation occurs during
     * preparation. The returned single-use value owns one staged TBS until acceptance
     * or discard. Work is bounded by the parent chain, command and certificate sizes;
     * no subject credential status or expiry policy is added by this operation.</p>
     *
     * @param access separately authenticated and authorized invocation context
     * @param command exact existing authority, expected key, profile and proof coordinates
     * @param cancellation cooperative pre-acceptance cancellation
     * @return unused preparation owned by this session
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if proof coordinates, bindings or input bounds differ
     * @throws PkiException if authority/profile/path validation, content access or cancellation fails
     * @throws SigningExecutionException if the session no longer accepts preparation
     */
    PreparedSemanticSigningRequest prepareIntermediateIssuance(AccessContext access,
            zeroecho.pki.api.ca.IntermediateCertIssueCommand command, CancellationSignal cancellation);

    /**
     * Renews a root or intermediate credential using its authoritative current key.
     * Resolves an active authority and the active version of the selected
     * credential's CA profile, preserving its authoritative subject principal.
     * Root publication requires a fresh self-signature; intermediate preparation
     * requires an exact completed parent/subject/profile/target-key proof and a
     * usable parent path. Old subject credential expiry/revocation does not veto
     * renewal. Nonempty generic attributes are rejected; validity is policy-checked
     * and narrowed inward to whole seconds. Reusing the current key is permitted.
     * Successful publication retains historical generations and selects the new
     * generation, path and key.
     *
     * <p>The caller authenticates and authorizes separately. Preparation performs
     * no signing dispatch, acceptance or CA mutation. The returned single-use
     * value owns one staged TBS until acceptance or discard. Payload work/memory
     * are linear in bounded subject, SPKI, TBS and command bytes, plus bounded
     * parent-path work for intermediate operations and existing store costs.</p>
     *
     * @param access separately authenticated and authorized invocation context
     * @param command closed root/intermediate lifecycle coordinates
     * @param cancellation cooperative pre-acceptance cancellation
     * @return unused preparation owned by this session
     * @throws NullPointerException if an argument or exported public key is null
     * @throws IllegalArgumentException if proof coordinates, algorithm bindings or bounds differ
     * @throws PkiException if authority/profile/path validation, content access or cancellation fails
     * @throws SigningExecutionException if the session no longer accepts preparation
     */
    PreparedSemanticSigningRequest prepareCaRollover(AccessContext access,
            zeroecho.pki.api.ca.CaRolloverCommand command, CancellationSignal cancellation);

    /**
     * Prepares a root or intermediate credential for explicit outgoing role changes.
     * Resolves an active authority and the active version of the selected
     * credential's CA profile, preserving its authoritative subject principal.
     * Root publication requires a fresh self-signature; intermediate preparation
     * requires an exact completed parent/subject/profile/target-key proof and a
     * usable parent path. Old subject credential expiry/revocation does not veto
     * renewal. Nonempty generic attributes are rejected; validity is policy-checked
     * and narrowed inward to whole seconds. Unspecified selector members retain the
     * current binding, so an algorithm-only change can keep the same managed key.
     * Successful publication retains historical generations and selects the new
     * generation, path and key.
     *
     * <p>The caller authenticates and authorizes separately. Preparation performs
     * no signing dispatch, acceptance or CA mutation. The returned single-use
     * value owns one staged TBS until acceptance or discard. Payload work/memory
     * are linear in bounded subject, SPKI, TBS and command bytes, plus bounded
     * parent-path work for intermediate operations and existing store costs.</p>
     *
     * @param access separately authenticated and authorized invocation context
     * @param command closed root/intermediate lifecycle coordinates
     * @param cancellation cooperative pre-acceptance cancellation
     * @return unused preparation owned by this session
     * @throws NullPointerException if an argument or exported public key is null
     * @throws IllegalArgumentException if proof coordinates, algorithm bindings or bounds differ
     * @throws PkiException if authority/profile/path validation, content access or cancellation fails
     * @throws SigningExecutionException if the session no longer accepts preparation
     */
    PreparedSemanticSigningRequest prepareCaKeyRotation(AccessContext access,
            zeroecho.pki.api.ca.CaKeyRotationCommand command, CancellationSignal cancellation);

    /**
     * Prepares a fresh managed-private-key possession challenge using this session's
     * exact provider public-key source and configured signature algorithm. Callers
     * must authorize the supplied purpose and authority/profile coordinates; this
     * primitive does not grant authority or publish a certificate/status artifact.
     * No signing dispatch or durable acceptance occurs during preparation. The
     * returned single-use carrier owns staged bytes until acceptance or discard.
     * Each invocation gets a fresh submission ID and cryptographically random nonce.
     * Work and memory are linear in the bounded command and public-key encoding.
     * Successful completion exposes only binary ASCII {@code proof:<64-hex-command-digest>},
     * never the raw signature through this semantic API. The raw signing API is unchanged.
     *
     * @param access authenticated and authorized invocation context
     * @param request exact purpose-specific managed key coordinates
     * @param cancellation cooperative pre-acceptance cancellation
     * @return unused preparation owned by this session
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if provider capability, binding or bounds are invalid
     * @throws PkiException if content lookup, staging or cancellation fails
     * @throws SigningExecutionException if the session no longer accepts preparation
     */
    PreparedSemanticSigningRequest prepareManagedKeyProof(AccessContext access, ManagedKeyProofRequest request,
            CancellationSignal cancellation);

    /**
     * Prepares a full CRL for the exact active or retired issuer generation.
     * Validates issuer policy and the session's selected signing capability before
     * reserving a monotonically increasing CRL number and streaming the TBS.
     * No provider dispatch or durable signing acceptance occurs during preparation.
     * The returned single-use carrier owns the staged content until accepted or
     * discarded. Reserved numbers are never reused, including after cancellation,
     * discard or failure. Callers authenticate and authorize this privileged operation.
     *
     * <p>The validity interval is evaluated at one captured time and narrowed to
     * whole X.509 seconds. Preparation makes two streaming entry passes; application
     * auxiliary memory is bounded independently of CRL byte length. Snapshot and
     * store costs retain their documented contracts. Pure EdDSA admission uses the
     * session's configured raw-message bound before acceptance.</p>
     *
     * <p>After acceptance, successful completion returns only a binary-encoded
     * ASCII {@code crl:<sha256>} status identifier, never the aggregate CRL bytes.
     * The identifier resolves published status metadata through the session repository.</p>
     *
     * @param access authenticated and authorized caller's audit context
     * @param request exact issuer generation and requested positive validity
     * @param cancellation cooperative pre-acceptance cancellation signal
     * @return unused preparation owned by this session
     * @throws NullPointerException if an argument is null
     * @throws PkiException if validation, staging or cancellation fails
     * @throws IllegalArgumentException if the staged TBS exceeds the configured pure-EdDSA bound
     * @throws SigningExecutionException if the owning session no longer accepts preparation
     */
    PreparedSemanticSigningRequest prepareFullCrl(AccessContext access, FullCrlRequest request,
            CancellationSignal cancellation);

    /**
     * Prepares a delta CRL against the latest full CRL of the selected issuer's
     * authority. The base's signature, scope and authoritative snapshot prefix
     * are verified before a number is reserved. Exactly one new revocation
     * snapshot bounds the changes; releases are encoded as removeFromCRL.
     * The selected base is frozen for acceptance, publication and recovery.
     *
     * <p>No signature or durable acceptance occurs here. The returned preparation
     * owns its staged TBS until acceptance or discard; a reserved number remains
     * consumed on subsequent failure. Existing status inventory materialization
     * and bounded streaming verification costs apply, followed by the same two
     * entry passes as full CRL preparation.</p>
     *
     * @param access authenticated and authorized caller's audit context
     * @param request exact signing generation and requested validity
     * @param cancellation cooperative pre-acceptance cancellation
     * @return session-owned single-use preparation
     * @throws PkiException if base, issuer, prefix, staging or cancellation validation fails
     * @throws IllegalArgumentException if a pure-EdDSA TBS exceeds the configured bound
     * @throws SigningExecutionException if the session no longer accepts preparation
     */
    PreparedSemanticSigningRequest prepareDeltaCrl(AccessContext access, DeltaCrlRequest request,
            CancellationSignal cancellation);

    /**
     * Evaluates the exact SDK issuance target without consuming proof or staging a candidate.
     *
     * <p>The preview binds subject keys, issuer generation and path, profile and
     * absolute validity. A retained validity optional prevents revalidation from
     * extending the originally approved target. The preview itself grants neither
     * authentication nor permission to issue; the caller supplies an authorized context.
     * The default implementation reports that SDK preview is unsupported.
     *
     * @param access authorized invocation context
     * @param request selected issuer/profile and exact request payload
     * @param parsed parsed dual-subject request
     * @param frozenValidity exact absolute bounds for revalidation, or empty initially
     * @param cancellation cooperative cancellation
     * @return immutable public preview
     * @throws UnsupportedOperationException if SDK issuance is unavailable
     * @throws PkiException if the request, selected issuer, profile or frozen target is invalid
     */
    default zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdk(AccessContext access,
            EndEntityIssuanceRequest request, zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed,
            Optional<zeroecho.pki.api.Validity> frozenValidity, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("SDK preview unavailable");
    }

    /**
     * Prepares SDK issuance using retained proof and frozen absolute policy bounds.
     *
     * <p>The implementation revalidates the proof at its retained acceptance time and
     * compares the actual target with the approved preview before alternative signing.
     * The returned preparation owns staged content until accepted or discarded; this
     * call does not durably accept the signing operation. The default implementation
     * does not support SDK preparation.
     *
     * @param access authorized invocation context
     * @param request selected issuer/profile and exact original payload
     * @param parsed parsed dual-subject request
     * @param approval retained independently reverified proof and preview
     * @param evidence optional trusted publication evidence
     * @param cancellation cooperative cancellation
     * @return exclusively caller-owned prepared signing request
     * @throws UnsupportedOperationException if SDK issuance is unavailable
     * @throws PkiException if proof, target, policy, staging or cancellation validation fails
     */
    default PreparedSemanticSigningRequest prepareSdk(AccessContext access, EndEntityIssuanceRequest request,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed,
            zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval approval,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("SDK preparation unavailable");
    }

    /**
     * Evaluates an SDK renewal target with exact predecessor and both subject keys.
     *
     * <p>The preview includes the lifecycle binding without consuming the proof,
     * signing or staging content. Supplied absolute validity is retained during
     * revalidation rather than rebased on the current time. The caller must separately
     * authorize the predecessor and issuer selection.
     *
     * @param access authenticated and authorized caller context
     * @param request exact renewal predecessor and lifecycle selection
     * @param parsed exact dual-subject client request bound to the proof
     * @param frozenValidity absolute retained bounds, or an empty optional initially
     * @param cancellation cooperative cancellation signal
     * @return immutable public preview including the exact renewal lifecycle target
     * @throws UnsupportedOperationException if SDK lifecycle is unavailable
     * @throws PkiException if predecessor, subject keys, policy or frozen selection is invalid
     */
    default zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdk(AccessContext access, zeroecho.pki.api.issuance.EndEntityRenewalRequest request,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed, Optional<zeroecho.pki.api.Validity> frozenValidity,
            CancellationSignal cancellation) {
        throw new UnsupportedOperationException("SDK lifecycle preview unavailable");
    }

    /**
     * Revalidates fresh dual proof and the exact approved renewal snapshot before alternative signing.
     *
     * <p>Proof lifetime is evaluated at its retained acceptance time. Current permitted
     * use and predecessor eligibility remain subject to revalidation against the
     * same approved target. The preparation owns staged content until accept or discard;
     * no durable signing acceptance occurs here.
     *
     * @param access authenticated and authorized caller context
     * @param request exact renewal predecessor and lifecycle selection
     * @param parsed exact proof-bound dual-subject client request
     * @param approval retained accepted proof and its frozen approved preview
     * @param evidence trusted execution evidence, or an empty optional for embedded use
     * @param cancellation cooperative pre-acceptance cancellation
     * @return caller-owned staged lifecycle request
     * @throws UnsupportedOperationException if SDK lifecycle is unavailable
     * @throws PkiException if proof, predecessor, target, policy, staging or cancellation validation fails
     */
    default PreparedSemanticSigningRequest prepareSdk(AccessContext access, zeroecho.pki.api.issuance.EndEntityRenewalRequest request,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed, zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval approval,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("SDK lifecycle preparation unavailable");
    }

    /**
     * Evaluates an SDK reissue target with exact predecessor and both subject keys.
     *
     * <p>The preview preserves the exact reissue lifecycle context without proof
     * consumption, signing or staging. A retained validity optional fixes the approved
     * absolute interval. It does not grant permission to reuse the predecessor keys.
     *
     * @param access authenticated and authorized caller context
     * @param request authoritative predecessor selected for reissue
     * @param parsed exact proof-bound dual-subject client request
     * @param frozenValidity absolute retained bounds, or an empty optional initially
     * @param cancellation cooperative cancellation signal
     * @return immutable public preview including the exact reissue lifecycle target
     * @throws UnsupportedOperationException if SDK lifecycle is unavailable
     * @throws PkiException if predecessor, subject keys, policy or frozen selection is invalid
     */
    default zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdk(AccessContext access, zeroecho.pki.api.issuance.EndEntityReissueRequest request,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed, Optional<zeroecho.pki.api.Validity> frozenValidity,
            CancellationSignal cancellation) {
        throw new UnsupportedOperationException("SDK lifecycle preview unavailable");
    }

    /**
     * Revalidates fresh dual proof and the exact approved reissue snapshot before alternative signing.
     *
     * <p>The retained proof is evaluated at acceptance time, while current permitted
     * use and the actual reissue target are checked again before staging the final
     * candidate. The caller must accept or discard the returned single-use preparation.
     *
     * @param access authenticated and authorized caller context
     * @param request authoritative predecessor selected for reissue
     * @param parsed exact proof-bound dual-subject client request
     * @param approval retained accepted proof and its frozen approved preview
     * @param evidence trusted execution evidence, or an empty optional for embedded use
     * @param cancellation cooperative pre-acceptance cancellation
     * @return caller-owned staged lifecycle request
     * @throws UnsupportedOperationException if SDK lifecycle is unavailable
     * @throws PkiException if proof, predecessor, target, policy, staging or cancellation validation fails
     */
    default PreparedSemanticSigningRequest prepareSdk(AccessContext access, zeroecho.pki.api.issuance.EndEntityReissueRequest request,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed, zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval approval,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("SDK lifecycle preparation unavailable");
    }

    /**
     * Evaluates an SDK replacement target with exact predecessor and both subject keys.
     *
     * <p>The replacement preview binds the predecessor and requested replacement
     * keys to the selected profile, issuer and absolute validity. It evaluates policy
     * without consuming proof, signing or staging, and does not itself authorize replacement.
     *
     * @param access authenticated and authorized caller context
     * @param request exact predecessor, replacement request and profile selection
     * @param parsed exact proof-bound dual-subject replacement request
     * @param frozenValidity absolute retained bounds, or an empty optional initially
     * @param cancellation cooperative cancellation signal
     * @return immutable public preview including the exact replacement lifecycle target
     * @throws UnsupportedOperationException if SDK lifecycle is unavailable
     * @throws PkiException if predecessor, subject keys, policy or frozen selection is invalid
     */
    default zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdk(AccessContext access, zeroecho.pki.api.issuance.EndEntityReplacementRequest request,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed, Optional<zeroecho.pki.api.Validity> frozenValidity,
            CancellationSignal cancellation) {
        throw new UnsupportedOperationException("SDK lifecycle preview unavailable");
    }

    /**
     * Revalidates fresh dual proof and the exact approved replacement snapshot before alternative signing.
     *
     * <p>The actual replacement target and current reuse eligibility must still agree
     * with the accepted dual proof. The retained proof's lifetime is evaluated at its
     * acceptance time. Returned staged content remains under preparation custody until
     * accepted or discarded; preparation is not durable acceptance.
     *
     * @param access authenticated and authorized caller context
     * @param request exact predecessor, replacement request and profile selection
     * @param parsed exact proof-bound dual-subject replacement request
     * @param approval retained accepted proof and its frozen approved preview
     * @param evidence trusted execution evidence, or an empty optional for embedded use
     * @param cancellation cooperative pre-acceptance cancellation
     * @return caller-owned staged lifecycle request
     * @throws UnsupportedOperationException if SDK lifecycle is unavailable
     * @throws PkiException if proof, predecessor, target, policy, staging or cancellation validation fails
     */
    default PreparedSemanticSigningRequest prepareSdk(AccessContext access, zeroecho.pki.api.issuance.EndEntityReplacementRequest request,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed, zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval approval,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("SDK lifecycle preparation unavailable");
    }

    /**
     * Verifies and prepares one end-entity certificate using the current
     * authoritative issuer generation and active profile. No signature or durable
     * acceptance occurs. The returned value exclusively owns staged TBS content
     * until this service accepts or discards it. Each call allocates a new operation
     * identity; correlation does not deduplicate caller retries.
     *
     * <p>The validity interval is policy-checked at one captured evaluation time,
     * then narrowed to whole X.509 seconds without extending either endpoint.
     * An interval with no positive representable duration is rejected before staging.
     * Local payload time and memory are O(C + I + T), plus cryptographic verification
     * and bounded authoritative lookups, for CSR, issuer and TBS byte sizes.</p>
     *
     * @param access authenticated and authorized caller's audit context
     * @param request exact bounded DER CSR and policy selection
     * @param evidence trusted execution evidence, or empty for embedded issuance; never null
     * @param cancellation cooperative pre-acceptance cancellation signal
     * @return unused preparation owned by this session
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if execution evidence conflicts with actor or frozen scope
     * @throws PkiException if validation, staging or cancellation fails
     * @throws IllegalStateException if the owning session is closed
     */
    PreparedSemanticSigningRequest prepareEndEntity(AccessContext access, EndEntityIssuanceRequest request,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation);

    /**
     * Looks up exact retained issuance before preparing any new work. A matching
     * operation, including a failed, cancelled or expired operation, returns
     * {@link CorrelatedIssuancePreparation.Existing} without CSR verification,
     * serial allocation, profile/issuer admission or content staging. Callers
     * must authorize both preparation and disclosure; a prior lookup is optional.
     * Supplied evidence is checked against this invocation's access and expected
     * frozen scope even on replay. It neither replaces nor must equal the retained
     * winner's evidence and does not participate in correlation identity.
     *
     * <p>When absent, verifies the CSR and policy against the exact imported
     * profile version/digest in the intent, independently of the active profile
     * pointer. The expected issuer generation and chain path must still match
     * the current active issuance selection. A new candidate follows
     * {@link #prepareEndEntity}'s validity, custody and cleanup rules and returns
     * {@link CorrelatedIssuancePreparation.Prepared}. No signature, durable
     * acceptance or correlation reservation occurs. Concurrent preparations can
     * independently observe absence; acceptance remains authoritative.</p>
     *
     * <p>Replay has the local hashing and point-read costs of {@link #findIssuance(CorrelatedEndEntityIssuanceRequest)}.
     * New preparation additionally has the bounded payload, verification and
     * authoritative lookup costs of {@link #prepareEndEntity}, plus decoding and
     * validation of the bounded imported profile document.</p>
     *
     * @param access authenticated and authorized caller's audit context
     * @param request bounded exact issuance input and frozen orchestration intent
     * @param evidence trusted invocation evidence, or empty for embedded issuance; never null
     * @param cancellation cooperative pre-acceptance cancellation signal
     * @return matching retained snapshot or exclusively owned unused preparation
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if execution evidence conflicts with actor or frozen scope
     * @throws PkiException if correlation conflicts, frozen selection is unavailable
     *         or stale, or validation, staging or cancellation fails
     * @throws IllegalStateException if the session is closed or persisted bindings are inconsistent
     */
    CorrelatedIssuancePreparation prepareCorrelatedEndEntity(AccessContext access,
            CorrelatedEndEntityIssuanceRequest request, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation);

    /**
     * Prepares renewal from the authoritative predecessor under the currently
     * active logical profile and issuer generation. Subject, SAN and SPKI remain
     * unchanged. Held or permanently revoked predecessors are rejected; expired
     * and not-yet-valid certificates are permitted. No new proof is supplied.
     *
     * <p>The actor and purpose are preserved; audit object and format coordinates
     * are bound to the predecessor and X.509. Supplied conflicting coordinates
     * are rejected. Preparation performs no signing, durable acceptance or
     * predecessor mutation. Each invocation has a fresh operation and serial;
     * retries are not deduplicated. Content custody and validity normalization
     * match {@link #prepareEndEntity}. Local time and payload memory are
     * O(P + I + T), plus verification, policy validation and bounded store lookups.</p>
     *
     * @param access authenticated and authorized caller's audit context
     * @param request predecessor identity and optional validity duration
     * @param evidence trusted execution evidence, or empty for embedded issuance; never null
     * @param cancellation cooperative pre-acceptance cancellation
     * @return unused preparation exclusively owned by this session
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if supplied audit coordinates or execution evidence conflict
     * @throws PkiException if validation, staging or cancellation fails
     * @throws IllegalStateException if the owning session is closed
     */
    PreparedSemanticSigningRequest prepareRenewal(AccessContext access, EndEntityRenewalRequest request,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation);

    /**
     * Prepares one durable correlated renewal or returns its already accepted
     * operation. Fresh work verifies the authoritative predecessor and current
     * status against the exact frozen issuer, path and profile selection. Replay
     * performs point reads and exact commitment checks without signing again or
     * reinterpreting the accepted operation after later status changes.
     * The caller must accept or discard a returned prepared candidate.
     * @param access trusted requester audit context
     * @param request immutable predecessor binding and frozen intent
     * @param evidence trusted execution evidence, or empty; never null
     * @param cancellation cooperative pre-acceptance cancellation
     * @return existing operation or exclusively owned unaccepted candidate
     * @throws PkiException if validation, correlation or preparation fails
     */
    CorrelatedIssuancePreparation prepareCorrelatedRenewal(AccessContext access,
            CorrelatedEndEntityRenewalRequest request,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation);

    /**
     * Finds a retained renewal using exact frozen input and predecessor binding.
     * No parsing, status evaluation, signing or credential inventory scan occurs.
     * Local work is linear in bounded input text plus durable point reads.
     * @param request immutable exact renewal input
     * @return retained operation, or empty after absence or retention purge
     * @throws PkiException if the external identity belongs to different work
     */
    Optional<SemanticSigningOperation> findRenewal(
            CorrelatedEndEntityRenewalRequest request);

    /**
     * Prepares replacement from a verified exact CSR using the selected active
     * profile and the predecessor's current logical issuing authority. Reuse of
     * the predecessor SPKI is permitted only while it is neither held nor
     * permanently revoked; a different verified SPKI may replace either status.
     *
     * <p>Audit binding, fresh operation/serial allocation and exclusive content
     * custody match {@link #prepareRenewal}. Preparation performs no signing,
     * durable acceptance or predecessor mutation. Local time and payload memory
     * are O(P + C + I + T), plus verification, policy validation and bounded lookups.</p>
     *
     * @param access authenticated and authorized caller's audit context
     * @param request predecessor, bounded exact CSR and selected active profile
     * @param evidence trusted execution evidence, or empty for embedded issuance; never null
     * @param cancellation cooperative pre-acceptance cancellation
     * @return unused preparation exclusively owned by this session
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if supplied audit coordinates or execution evidence conflict
     * @throws PkiException if validation, staging or cancellation fails
     * @throws IllegalStateException if the owning session is closed
     */
    PreparedSemanticSigningRequest prepareReplacement(AccessContext access, EndEntityReplacementRequest request,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation);

    /**
     * Prepares a correlated replacement or returns its already accepted operation.
     * Fresh preparation verifies exact original proof, authoritative predecessor,
     * current reuse eligibility and the frozen profile, issuer and path. Accepted
     * replay validates its exact binding without signing or re-evaluating status.
     * A prepared result is exclusively owned and must be accepted or discarded.
     * @param access trusted requester audit context
     * @param request exact predecessor, typed request and frozen selection
     * @param evidence trusted execution evidence, or empty; never null
     * @param cancellation cooperative pre-acceptance cancellation
     * @return existing operation or exclusively owned unaccepted candidate
     * @throws PkiException if validation, correlation or preparation fails
     */
    CorrelatedIssuancePreparation prepareCorrelatedReplacement(AccessContext access,
            CorrelatedEndEntityReplacementRequest request,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation);

    /**
     * Finds an accepted replacement using exact frozen input and predecessor binding.
     * No parsing, status evaluation or signing occurs. Hashing is linear in bounded
     * request bytes; persistent recovery uses point reads.
     * @param request exact immutable replacement input
     * @return retained operation, or empty after absence or retention purge
     * @throws PkiException if the correlation belongs to different work
     */
    Optional<SemanticSigningOperation> findReplacement(CorrelatedEndEntityReplacementRequest request);

    /**
     * Prepares reissue of the predecessor's subject, SAN and SPKI using the
     * current logical profile and issuer generation, with policy-derived validity.
     * Predecessor eligibility, audit binding, fresh operation/serial allocation
     * and exclusive content custody match {@link #prepareRenewal}. Preparation
     * performs no signing, durable acceptance or predecessor mutation.
     * Local time and payload memory are O(P + I + T), plus verification,
     * policy validation and bounded authoritative lookups.
     *
     * @param access authenticated and authorized caller's audit context
     * @param request authoritative predecessor identifier
     * @param evidence trusted execution evidence, or empty for embedded issuance; never null
     * @param cancellation cooperative pre-acceptance cancellation
     * @return unused preparation exclusively owned by this session
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if supplied audit coordinates or execution evidence conflict
     * @throws PkiException if validation, staging or cancellation fails
     * @throws IllegalStateException if the owning session is closed
     */
    PreparedSemanticSigningRequest prepareReissue(AccessContext access, EndEntityReissueRequest request,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation);

    /**
     * Transfers exclusive prepared-candidate custody to durable acceptance.
     * For correlated issuance, an exact retained winner is attached before
     * admission, or after a definite store rejection reveals a concurrent winner.
     * Attachment returns the authoritative winner's receipt, which can differ
     * from the prepared candidate's receipt. Different retained intent returns
     * {@code CONFLICT}; definite rejection retires only unaccepted content.
     *
     * <p>An acceptance exception preserves the original prepared receipt and
     * existing custody semantics. Resolve that original receipt before interpreting
     * a later correlation lookup; no exception path infers non-acceptance or
     * reclaims a possibly accepted candidate. A definite capacity rejection still
     * requires fresh preparation for a later retry. Correlated resolution performs
     * at most two bounded correlation/workflow lookup pairs, with local work linear
     * in bounded command/envelope/result sizes and no registry or scan.</p>
     *
     * @param prepared unused value prepared by this session's service
     * @return durable disposition and the accepted/attached operation's receipt,
     *         or the original receipt for conflict/capacity rejection
     * @throws IllegalArgumentException if the value belongs to another service
     * @throws IllegalStateException if custody has already transferred
     */
    SigningAcceptanceResult accept(PreparedSemanticSigningRequest prepared);

    /**
     * Releases an unused prepared candidate without accepting the operation.
     * A failed cleanup retains the existing retryable discard contract.
     *
     * @param prepared unused value prepared by this session's service
     * @throws IllegalArgumentException if the value belongs to another service
     * @throws IllegalStateException if custody has already transferred
     */
    void discard(PreparedSemanticSigningRequest prepared);

    /**
     * Reads retained authoritative semantic state by operation identity.
     *
     * @param operationId canonical signing operation identity
     * @return snapshot, or empty for unknown, purged, foreign or sign-only work
     */
    Optional<SemanticSigningOperation> find(PkiId operationId);

    /**
     * Projects the canonical status identity from a completed full-CRL observation.
     * This pure operation performs no lookup, parsing or authorization and creates
     * no persistent state. Other kinds, states or operation discriminators return
     * empty; a matching observation with a malformed result fails closed.
     * @param operation immutable semantic observation
     * @return canonical status object identity for a completed full CRL
     * @throws NullPointerException if {@code operation} is null
     * @throws IllegalStateException if a matching completion result is malformed
     */
    Optional<PkiId> completedStatusObjectId(SemanticSigningOperation operation);

    /**
     * Projects public candidate/activation and selected-head coordinates from retained completion evidence.
     * This read-only projection does not activate the root or install external trust.
     * @param operation completed semantic observation
     * @return immutable named public coordinates, empty for noncandidate operations
     * @throws RuntimeException if matching retained lifecycle evidence is inconsistent
     */
    default java.util.Map<String, String> completedCaLifecycleMetadata(SemanticSigningOperation operation) {
        return java.util.Map.of();
    }


    /**
     * Derives a CSR-free binding to the exact bounded request and its frozen selection.
     * This is pure identity derivation: no CSR parsing, provider call, store lookup,
     * staging or admission occurs. The returned value grants no authorization.
     * Time and transient memory are O(C + F) for existing defensive CSR and field
     * snapshots; hash state is constant.
     * @param request immutable correlated issuance input
     * @return exact retained-lookup coordinates and effective commitment
     * @throws NullPointerException if the request is null
     * @throws IllegalStateException if the owning session is closed
     */
    RetainedIssuanceBinding issuanceBinding(CorrelatedEndEntityIssuanceRequest request);

    /**
     * Finds retained issuance using a previously derived CSR-free binding. Exact
     * issuer, path, profile and effective commitment are checked before disclosure,
     * followed by immutable outer/envelope consistency checks. Current profile
     * selection does not replace the frozen values. Callers must authenticate and
     * authorize the returned persisted scope; the binding itself grants no permission.
     * Performs bounded point reads without CSR parsing, inventory scans or admission.
     * @param binding immutable exact retained issuance coordinates
     * @return verified snapshot, or empty for unknown or purged correlation
     * @throws NullPointerException if binding is null
     * @throws PkiException if occupied correlation has different issuance semantics
     * @throws IllegalStateException if persisted bindings are inconsistent or the session is closed
     */
    Optional<SemanticSigningOperation> findIssuance(RetainedIssuanceBinding binding);

    /**
     * Finds a retained issuance by the request's authority and external issuance ID,
     * and verifies its exact effective commitment and frozen selection before
     * disclosure. Callers must authenticate and authorize this privileged read;
     * neither the intent nor a matching commitment grants permission. This method
     * performs bounded hashing and authoritative point reads, without CSR proof
     * verification, profile validation, inventory scans or new acceptance.
     * A changed CSR, including malformed bounded DER, conflicts with retained work.
     *
     * <p>Local hashing takes O(C + F) time and constant hash state over defensive
     * bounded input snapshots. Snapshot memory is O(C + F); retained command and
     * result decoding and store point-read costs remain those of {@link #find}.</p>
     *
     * @param request exact bounded issuance input and frozen orchestration intent
     * @return verified semantic snapshot, or empty when no correlation remains,
     *         including after retention purge
     * @throws NullPointerException if the request is null
     * @throws PkiException if occupied correlation has different issuance semantics
     * @throws IllegalStateException if persisted bindings are inconsistent or the session is closed
     */
    Optional<SemanticSigningOperation> findIssuance(CorrelatedEndEntityIssuanceRequest request);

    /**
     * Requests durable signing cancellation for a semantic operation.
     * Outer completion remains asynchronous and can win a cancellation race.
     *
     * @param operationId canonical signing operation identity
     * @return latest snapshot, or empty for unknown, purged, foreign or sign-only work
     */
    Optional<SemanticSigningOperation> cancel(PkiId operationId);

    /**
     * Resolves an uncertain acceptance against the authoritative store.
     *
     * @param receipt receipt from semantic preparation or acceptance
     * @return authoritative acceptance resolution
     * @throws IllegalArgumentException if the identity names retained sign-only work
     */
    SigningAcceptanceResolution resolve(SigningAcceptanceReceipt receipt);

    /**
     * Looks up retained work through its existing durable domain correlation.
     * This privileged lookup neither authorizes disclosure nor proves that a new
     * request matches the stored domain intent.
     *
     * @param kind finite semantic domain
     * @param correlationId canonical identifier matching {@code [a-z0-9][a-z0-9._:-]{0,127}}
     * @return authoritative snapshot, or empty when unknown or purged
     * @throws IllegalArgumentException if the correlation identifier is malformed
     */
    Optional<SemanticSigningOperation> findByCorrelation(SemanticSigningKind kind, String correlationId);

    /**
     * Evaluates SDK issuance with an optional trusted native enrollment target.
     *
     * <p>A present target must match the native request kind and issuance operation;
     * it is public commitment data, not authentication supplied by the applicant.
     * The default implementation rejects a present target and delegates administrative
     * use to the overload without an enrollment target. Evaluation does not consume
     * proof, allocate a serial, sign or stage content.
     *
     * @param access authenticated and authorized invocation context
     * @param request exact typed issuance request and issuer/profile selection
     * @param parsed exact proof-bound dual-subject request
     * @param frozenValidity retained absolute validity, or an empty optional initially
     * @param enrollmentTarget trusted native coordinates, or an empty optional for
     *        administrative use; the optional must not be null
     * @param cancellation cooperative cancellation signal
     * @return immutable public preview including any supported native target
     * @throws NullPointerException if the enrollment-target optional is null
     * @throws UnsupportedOperationException if enrollment-target evaluation is unavailable
     * @throws PkiException if the native target, issuer, profile or request does not match
     */
    default zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdk(AccessContext access,
            zeroecho.pki.api.issuance.EndEntityIssuanceRequest request,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed,
            Optional<zeroecho.pki.api.Validity> frozenValidity,
            Optional<zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget> enrollmentTarget,
            CancellationSignal cancellation) {
        java.util.Objects.requireNonNull(enrollmentTarget, "enrollmentTarget");
        if (enrollmentTarget.isPresent()) {
            throw new UnsupportedOperationException("SDK enrollment preview unavailable");
        }
        return previewSdk(access, request, parsed, frozenValidity, cancellation);
    }

    /**
     * Evaluates an SDK renewal preview with optional native enrollment coordinates.
     *
     * <p>The lifecycle and native target must describe the same renewal request and
     * frozen absolute validity. Native coordinates do not replace authentication or
     * predecessor policy. The default implementation supports only an empty target
     * by delegating to the administrative renewal overload.
     *
     * @param access authenticated and authorized invocation context
     * @param request exact typed renewal predecessor and lifecycle selection
     * @param parsed exact proof-bound dual-subject renewal request
     * @param frozenValidity retained absolute validity, or an empty optional initially
     * @param enrollmentTarget trusted native coordinates, or an empty optional for
     *        administrative use; the optional must not be null
     * @param cancellation cooperative cancellation signal
     * @return immutable renewal preview including any supported native target
     * @throws NullPointerException if the enrollment-target optional is null
     * @throws UnsupportedOperationException if enrollment-target evaluation is unavailable
     * @throws PkiException if lifecycle policy, keys or native target do not match
     */
    default zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdk(AccessContext access,
            zeroecho.pki.api.issuance.EndEntityRenewalRequest request,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed,
            Optional<zeroecho.pki.api.Validity> frozenValidity,
            Optional<zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget> enrollmentTarget,
            CancellationSignal cancellation) {
        java.util.Objects.requireNonNull(enrollmentTarget, "enrollmentTarget");
        if (enrollmentTarget.isPresent()) {
            throw new UnsupportedOperationException("SDK enrollment preview unavailable");
        }
        return previewSdk(access, request, parsed, frozenValidity, cancellation);
    }

    /**
     * Evaluates an SDK reissue preview when the selected native target is supported.
     *
     * <p>The presence of this overload does not make reissue available through every
     * enrollment carrier or SDK profile. Unsupported native operation mappings fail
     * closed. The default implementation rejects any present native target and delegates
     * an empty target to the administrative reissue overload.
     *
     * @param access authenticated and authorized invocation context
     * @param request exact predecessor selected for reissue
     * @param parsed exact proof-bound dual-subject request
     * @param frozenValidity retained absolute validity, or an empty optional initially
     * @param enrollmentTarget trusted native coordinates, or an empty optional for
     *        administrative use; the optional must not be null
     * @param cancellation cooperative cancellation signal
     * @return immutable reissue preview when the selected operation mapping is supported
     * @throws NullPointerException if the enrollment-target optional is null
     * @throws UnsupportedOperationException if enrollment-target evaluation is unavailable
     * @throws PkiException if the native operation mapping, target or lifecycle policy is invalid
     */
    default zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdk(AccessContext access,
            zeroecho.pki.api.issuance.EndEntityReissueRequest request,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed,
            Optional<zeroecho.pki.api.Validity> frozenValidity,
            Optional<zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget> enrollmentTarget,
            CancellationSignal cancellation) {
        java.util.Objects.requireNonNull(enrollmentTarget, "enrollmentTarget");
        if (enrollmentTarget.isPresent()) {
            throw new UnsupportedOperationException("SDK enrollment preview unavailable");
        }
        return previewSdk(access, request, parsed, frozenValidity, cancellation);
    }

    /**
     * Evaluates an SDK replacement preview with optional native enrollment coordinates.
     *
     * <p>The native target must agree with the replacement lifecycle and original
     * request kind. It does not bypass predecessor reuse or subject-key policy.
     * The default implementation rejects present native targets and delegates an
     * empty target to the administrative replacement overload.
     *
     * @param access authenticated and authorized invocation context
     * @param request exact predecessor and typed replacement request
     * @param parsed exact proof-bound dual-subject replacement request
     * @param frozenValidity retained absolute validity, or an empty optional initially
     * @param enrollmentTarget trusted native coordinates, or an empty optional for
     *        administrative use; the optional must not be null
     * @param cancellation cooperative cancellation signal
     * @return immutable replacement preview including any supported native target
     * @throws NullPointerException if the enrollment-target optional is null
     * @throws UnsupportedOperationException if enrollment-target evaluation is unavailable
     * @throws PkiException if lifecycle policy, keys or native target do not match
     */
    default zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdk(AccessContext access,
            zeroecho.pki.api.issuance.EndEntityReplacementRequest request,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed,
            Optional<zeroecho.pki.api.Validity> frozenValidity,
            Optional<zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget> enrollmentTarget,
            CancellationSignal cancellation) {
        java.util.Objects.requireNonNull(enrollmentTarget, "enrollmentTarget");
        if (enrollmentTarget.isPresent()) {
            throw new UnsupportedOperationException("SDK enrollment preview unavailable");
        }
        return previewSdk(access, request, parsed, frozenValidity, cancellation);
    }

    /**
     * Prepares SDK issuance or attaches its retained operation under the native correlation identity.
     *
     * <p>Retained proof and exact request/target bindings are validated before lookup.
     * An exact accepted winner returns existing work without issuing another certificate;
     * absent work is prepared against the frozen selection. The caller owns a new
     * candidate until accept or discard. Lookup does not grant disclosure authority.
     *
     * @param access genuine authenticated and authorized native caller context
     * @param request exact correlated issuance and frozen issuer/profile/path intent
     * @param parsed exact original dual-subject request
     * @param approval retained accepted dual proof and frozen target
     * @param evidence trusted native execution evidence, or an empty optional
     * @param cancellation cooperative pre-acceptance cancellation
     * @return retained existing operation or exclusively owned prepared candidate
     * @throws UnsupportedOperationException if correlated SDK preparation is unavailable
     * @throws PkiException if proof, correlation, target, policy, staging or cancellation validation fails
     */
    default CorrelatedIssuancePreparation prepareSdk(AccessContext access, CorrelatedEndEntityIssuanceRequest request,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed,
            zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval approval,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("Correlated SDK preparation unavailable");
    }

    /**
     * Prepares a correlated SDK renewal or returns its exact retained operation.
     *
     * <p>Proof and request bindings are checked before retained lookup. Accepted replay
     * does not prepare or sign another renewal; new work must still satisfy current
     * predecessor and policy checks against the frozen approved target. A prepared
     * result remains caller-owned until accepted or discarded.
     *
     * @param access genuine authenticated and authorized native caller context
     * @param request exact correlated renewal predecessor and frozen intent
     * @param parsed exact original dual-subject renewal request
     * @param approval retained accepted dual proof and lifecycle target
     * @param evidence trusted native execution evidence, or an empty optional
     * @param cancellation cooperative pre-acceptance cancellation
     * @return retained existing operation or exclusively owned prepared candidate
     * @throws UnsupportedOperationException if correlated SDK preparation is unavailable
     * @throws PkiException if proof, correlation, predecessor, policy, staging or cancellation validation fails
     */
    default CorrelatedIssuancePreparation prepareSdk(AccessContext access, CorrelatedEndEntityRenewalRequest request,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed,
            zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval approval,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("Correlated SDK preparation unavailable");
    }

    /**
     * Prepares a correlated SDK replacement or returns its exact retained operation.
     *
     * <p>The exact original request, retained proof and frozen target are checked
     * before correlation lookup. A retained winner is observed without another
     * replacement; fresh preparation additionally checks current predecessor reuse
     * eligibility. The caller must accept or discard any newly prepared candidate.
     *
     * @param access genuine authenticated and authorized native caller context
     * @param request exact correlated replacement and frozen issuer/profile/path intent
     * @param parsed exact original dual-subject replacement request
     * @param approval retained accepted dual proof and lifecycle target
     * @param evidence trusted native execution evidence, or an empty optional
     * @param cancellation cooperative pre-acceptance cancellation
     * @return retained existing operation or exclusively owned prepared candidate
     * @throws UnsupportedOperationException if correlated SDK preparation is unavailable
     * @throws PkiException if proof, correlation, predecessor, policy, staging or cancellation validation fails
     */
    default CorrelatedIssuancePreparation prepareSdk(AccessContext access, CorrelatedEndEntityReplacementRequest request,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed,
            zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval approval,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("Correlated SDK preparation unavailable");
    }

    /**
     * Prepares dedicated managed responder issuance or returns its canonical retained operation.
     *
     * <p>Provisioning identity derives from the actual selected managed public keys
     * and exact issuer/profile/path target, not an arbitrary caller retry identifier.
     * Existing accepted work is observed rather than issued again. New preparation
     * owns the final candidate and both purpose-specific key-proof challenges until
     * acceptance or discard. It does not generate/export keys, register a responder
     * or activate a listener. The default implementation is unsupported.
     *
     * @param access authenticated caller already authorized for issuer and profile use
     * @param request exact managed subject-key pair and frozen certificate selection
     * @param evidence trusted execution evidence, or an empty optional for embedded use
     * @param cancellation cooperative pre-acceptance cancellation signal
     * @return retained existing operation or exclusively owned candidate
     * @throws UnsupportedOperationException if managed responder issuance is unavailable
     * @throws PkiException if key, issuer, profile, correlation, staging or cancellation validation fails
     */
    default CorrelatedIssuancePreparation prepareManagedOcspResponder(AccessContext access,
            zeroecho.pki.api.issuance.ManagedOcspResponderIssuanceRequest request,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("Managed OCSP responder issuance unavailable");
    }

    /**
     * Validates a managed responder target before approval without signing, allocating a serial or staging content.
     *
     * <p>The implementation resolves actual public-key evidence and evaluates the
     * unsigned certificate target. It grants no permission: the caller must already
     * have issuer and profile authorization. Validation neither provisions a certificate
     * nor registers or activates a responder. The default implementation is unsupported.
     *
     * @param access authenticated caller already authorized for issuer and profile use
     * @param request exact selected managed responder target
     * @param evidence trusted execution evidence, or an empty optional for embedded use
     * @param cancellation cooperative validation cancellation signal
     * @throws UnsupportedOperationException if managed responder validation is unavailable
     * @throws RuntimeException if policy, actual public keys, execution evidence or frozen selection differs
     */
    default void validateManagedOcspResponder(AccessContext access,
            zeroecho.pki.api.issuance.ManagedOcspResponderIssuanceRequest request,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("Managed OCSP responder validation unavailable");
    }
    /**
     * Observes canonical managed responder issuance without signing.
     *
     * <p>Actual managed public keys determine the canonical provisioning binding.
     * The exact target must match retained work; observation neither repeats issuance
     * nor authorizes disclosure. An empty result means no matching retained operation
     * was found, not that an uncertain earlier acceptance can safely be replayed.
     *
     * @param request exact managed responder target and optional same-slot predecessor
     * @return matching retained canonical operation, or an empty optional when absent
     * @throws UnsupportedOperationException if unavailable
     * @throws PkiException if public-key evidence is unavailable, the target conflicts
     *         with retained work or retained provisioning requires reconciliation
     */
    default Optional<SemanticSigningOperation> findManagedOcspResponder(
            zeroecho.pki.api.issuance.ManagedOcspResponderIssuanceRequest request) {
        throw new UnsupportedOperationException("Managed OCSP responder lookup unavailable");
    }
    /**
     * Observes the authoritative acceptance receipt after exact canonical target validation.
     *
     * <p>The receipt belongs to the retained operation's actual acceptance commitment.
     * A found operation with missing signing-workflow evidence requires reconciliation;
     * it must not be interpreted as permission to issue a replacement operation.
     *
     * @param request exact managed responder target
     * @return receipt of matching retained accepted work, or an empty optional when absent
     * @throws UnsupportedOperationException if managed responder provisioning is unavailable
     * @throws PkiException if target validation fails or retained workflow evidence is inconsistent
     */
    default Optional<zeroecho.pki.api.signing.SigningAcceptanceReceipt> findManagedOcspResponderReceipt(
            zeroecho.pki.api.issuance.ManagedOcspResponderIssuanceRequest request) {
        throw new UnsupportedOperationException("Managed OCSP responder receipt lookup unavailable");
    }
    /**
     * Resolves the canonical provisioning binding and actual public key digests without signing.
     *
     * <p>The binding identifies the exact frozen issuer/profile/path selection and
     * actual managed subject-key tuple. It neither reserves a provisioning slot nor
     * grants authority to use its keys. No private key material is returned.
     *
     * @param request exact managed responder target
     * @return canonical retained selection and both actual public SPKI digests
     * @throws UnsupportedOperationException if managed responder provisioning is unavailable
     * @throws PkiException if managed public-key or selected issuer/profile evidence is unavailable or invalid
     */
    default zeroecho.pki.api.issuance.ManagedOcspResponderProvisioningBinding managedOcspResponderProvisioningBinding(
            zeroecho.pki.api.issuance.ManagedOcspResponderIssuanceRequest request) {
        throw new UnsupportedOperationException("Managed OCSP responder binding unavailable");
    }
    /**
     * Derives the retained immutable binding using actual managed public keys.
     *
     * <p>This is the retained-issuance coordinate projection of
     * {@link #managedOcspResponderProvisioningBinding}. It performs no signing or
     * acceptance and does not replace target validation or caller authorization.
     *
     * @param request exact managed responder target
     * @return stable immutable core issuance binding for canonical retained lookup
     * @throws UnsupportedOperationException if unavailable
     * @throws PkiException if managed public-key or selected issuer/profile evidence is unavailable or invalid
     */
    default RetainedIssuanceBinding managedOcspResponderBinding(
            zeroecho.pki.api.issuance.ManagedOcspResponderIssuanceRequest request) {
        throw new UnsupportedOperationException("Managed OCSP responder binding unavailable");
    }
}
