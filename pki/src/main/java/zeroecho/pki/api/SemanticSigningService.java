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

package zeroecho.pki.api;

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
     * Prepares a root or intermediate credential for an explicitly provisioned key.
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
}
