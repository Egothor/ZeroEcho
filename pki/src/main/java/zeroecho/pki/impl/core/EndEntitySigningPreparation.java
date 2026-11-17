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

package zeroecho.pki.impl.core;

import java.util.Comparator;
import zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest;
import zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget;
import zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval;
import zeroecho.pki.api.hybrid.sdk.SdkLifecycleTarget;
import zeroecho.pki.api.issuance.ManagedOcspResponderIssuanceRequest;
import zeroecho.pki.api.issuance.ManagedOcspResponderProvisioningBinding;
import zeroecho.pki.api.issuance.RetainedIssuanceBinding;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview;
import zeroecho.pki.api.issuance.CorrelatedEndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest;
import zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest;
import zeroecho.pki.api.issuance.EndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.EndEntityReissueRequest;
import zeroecho.pki.api.issuance.EndEntityRenewalRequest;
import zeroecho.pki.api.issuance.EndEntityReplacementRequest;
import zeroecho.pki.api.issuance.IssuanceIntent;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.profile.ExtendedKeyUsageId;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.impl.core.continuation.DomainAttributeEncoding;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Session-owned leaf TBS construction and staging boundary. Only validated
 * issuance or lifecycle inputs reach the shared builder. Local time and payload
 * memory are O(P + C + I + T), for bounded predecessor, CSR, issuer certificate
 * and TBS bytes, plus verification, policy validation and store I/O.
 * No signing provider, acceptance gate, thread or per-operation registry is owned.
 * Instances are thread-safe when their store is thread-safe.
 */
public final class EndEntitySigningPreparation {
    private static final String SUBMISSION_PARAMETER = "submission";
    private static final String TTL_PARAMETER = "ttl";

    private static final String EVIDENCE_ARGUMENT = "evidence";

    private final PkiStore store;
    private final EndEntityIssuancePreparation validation;
    private final EndEntityLifecyclePreparation lifecycle;

    /**
     * Creates preparation using the session's exact verification and binding graph.
     *
     * @param store authoritative session store
     * @param clock authoritative evaluation clock
     * @param authority immutable X.509 authority shared by the session
     * @param verifier cryptographic verifier bound into the authority
     * @param bindings exact configured binding registry
     * @param signatureAlgorithm canonical session signing algorithm identity
     * @throws NullPointerException if a required dependency is null
     * @throws IllegalArgumentException if an algorithm or binding configuration is invalid
     */
    public EndEntitySigningPreparation(PkiStore store, Clock clock, X509AuthoritySnapshot authority,
            BcX509VerificationExecutor verifier, X509AlgorithmBindingRegistry bindings, String signatureAlgorithm) {
        this(store, new EndEntityIssuancePreparation(store, clock, authority, verifier, bindings, signatureAlgorithm));
    }

    /**
     * Binds leaf verification and signing to separate exact authority snapshots.
     *
     * <p>The provider is already open and remains session-owned. Ordinary signing-only
     * providers retain their established behavior; SDK issuance separately requires a
     * provider that exposes managed public-key evidence. Construction does not open,
     * close or use a provider to sign a candidate.
     *
     * @param store authoritative session store
     * @param clock authoritative policy clock
     * @param authority verification authority for client proof
     * @param verifier exact verification executor
     * @param bindings installed representation registry
     * @param signatureAlgorithm configured legacy creation default
     * @param signingAuthority signing authority bound to the selected provider
     * @param provider already-open managed public-key source and signer
     * @throws NullPointerException if a required dependency is null
     * @throws IllegalArgumentException if an algorithm or binding configuration is invalid
     */
    public EndEntitySigningPreparation(PkiStore store, Clock clock, X509AuthoritySnapshot authority,
            BcX509VerificationExecutor verifier, X509AlgorithmBindingRegistry bindings, String signatureAlgorithm,
            X509AuthoritySnapshot signingAuthority, SigningProvider provider) {
        this(store, new EndEntityIssuancePreparation(store, clock, authority, verifier, bindings, signatureAlgorithm,
                signingAuthority, publicKeys(provider)));
    }
    private static Optional<PublicKeyInfoSource> publicKeys(SigningProvider provider) {
        Objects.requireNonNull(provider, "provider");
        return provider instanceof PublicKeyInfoSource keys ? Optional.of(keys) : Optional.empty();
    }

    /**
     * Creates a preparer borrowing authoritative store and validation collaborators.
     *
     * <p>The caller retains collaborator lifecycle ownership; construction does not submit
     * a signing request or publish a credential.</p>
     *
     * @param store borrowed PKI store; must not be null
     * @param validation borrowed issuance validation preparer; must not be null
     * @throws NullPointerException if a required collaborator is null
     */
    /* default */ EndEntitySigningPreparation(PkiStore store, EndEntityIssuancePreparation validation) {
        this.store = Objects.requireNonNull(store, "store");
        this.validation = Objects.requireNonNull(validation, "validation");
        this.lifecycle = validation.lifecyclePreparation();
    }

    /**
     * Validates one request, freezes its command and stages its TBS exactly once.
     * On success the caller owns the returned unaccepted candidate and must either
     * hand it to semantic preparation or retire it if that handoff fails. Every
     * failure before return aborts or retires content owned by this invocation.
     *
     * @param access trusted requester audit context, not an authorization decision
     * @param request bounded caller input
     * @param submission internally generated session operation identity
     * @param ttl exact session signing lifetime
     * @param evidence trusted execution evidence, or empty; never null
     * @param cancellation cooperative cancellation signal
     * @return typed domain preparation with exclusive unaccepted-content custody
     * @throws IOException if staging or cancellation fails
     * @throws PkiException if request, issuer, profile or binding validation fails
     * @throws IllegalArgumentException if evidence conflicts with actor or frozen scope
     * @throws NullPointerException if an argument is null
     */
    public DomainSigningRequest prepare(AccessContext access, EndEntityIssuanceRequest request,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(evidence, EVIDENCE_ARGUMENT);
        Objects.requireNonNull(submission, SUBMISSION_PARAMETER);
        Objects.requireNonNull(ttl, TTL_PARAMETER);
        EndEntityIssuancePreparation.Prepared approved = validation.prepare(access, request, cancellation);
        return stage(approved, submission, ttl, evidence, cancellation, LeafOperation.ISSUE_END_ENTITY, Optional.empty());
    }

    /**
     * Validates a new correlated issuance against its exact imported profile and
     * current issuer/path selection, then stages one TBS with PKI-derived intent.
     * The semantic facade must perform authoritative replay lookup first. This
     * method does not reserve a correlation or accept work; custody and cleanup
     * match {@link #prepare}.
     *
     * @param access trusted requester audit context
     * @param request exact bounded request and frozen selection
     * @param submission fresh session operation identity
     * @param ttl exact session signing lifetime
     * @param evidence trusted execution evidence, or empty; never null
     * @param cancellation cooperative pre-acceptance cancellation
     * @return exclusively owned staged domain preparation
     * @throws IOException if staging or cancellation fails
     * @throws PkiException if proof, policy or frozen-selection validation fails
     * @throws IllegalArgumentException if evidence conflicts with actor or frozen scope
     * @throws NullPointerException if an argument is null
     */
    public DomainSigningRequest prepareCorrelated(AccessContext access, CorrelatedEndEntityIssuanceRequest request,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(evidence, EVIDENCE_ARGUMENT);
        Objects.requireNonNull(submission, SUBMISSION_PARAMETER);
        Objects.requireNonNull(ttl, TTL_PARAMETER);
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        CorrelatedIssuanceIdentity identity = CorrelatedIssuanceIdentity.derive(request);
        IssuanceIntent caller = request.intent();
        IssuanceIntent effective = new IssuanceIntent(caller.issuanceId(), identity.effectiveCommitment(),
                caller.expectedProfile(), caller.expectedIssuerId(), caller.expectedChainPathId(),
                caller.expectedChainPathCommitment());
        EndEntityIssuancePreparation.Prepared approved = validation.prepare(access, request.request(),
                Optional.of(effective), cancellation);
        return stage(approved, submission, ttl, evidence, cancellation, LeafOperation.ISSUE_END_ENTITY,
                Optional.empty(), identity.correlationId());
    }

    /**
     * Prepares a correlated renewal after the semantic facade has excluded an
     * accepted replay. Authoritative predecessor status and frozen selection are
     * checked before staging; content ownership matches {@link #prepare}.
     * @param access trusted requester audit context
     * @param request immutable predecessor binding and frozen selection
     * @param submission fresh session operation identity
     * @param ttl exact signing lifetime
     * @param evidence trusted issuance evidence, never null
     * @param cancellation cooperative pre-acceptance cancellation
     * @return exclusively owned staged renewal candidate
     * @throws IOException if staging or cancellation fails
     * @throws PkiException if predecessor, policy or frozen selection is invalid
     * @throws NullPointerException if evidence, submission, ttl is null
     */
    public DomainSigningRequest prepareCorrelatedRenewal(AccessContext access,
            CorrelatedEndEntityRenewalRequest request,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(evidence, EVIDENCE_ARGUMENT);
        Objects.requireNonNull(submission, SUBMISSION_PARAMETER);
        Objects.requireNonNull(ttl, TTL_PARAMETER);
        CorrelatedIssuanceIdentity identity = CorrelatedIssuanceIdentity.derive(request);
        IssuanceIntent caller = request.intent();
        IssuanceIntent effective = new IssuanceIntent(caller.issuanceId(), identity.effectiveCommitment(),
                caller.expectedProfile(), caller.expectedIssuerId(), caller.expectedChainPathId(),
                caller.expectedChainPathCommitment());
        EndEntityLifecyclePreparation.Prepared approved = lifecycle.prepareCorrelatedRenewal(
                EndEntitySdkBindings.lifecycleAccess(access, request.request().existingCredentialId()), request, effective, cancellation);
        return stage(approved.issuance(), submission, ttl, evidence, cancellation, LeafOperation.RENEW_END_ENTITY,
                Optional.of(approved.predecessor().credentialId()), identity.correlationId());
    }

    /**
     * Stages a correlated replacement through the existing replacement continuation.
     * The caller exclusively owns the resulting candidate; no acceptance occurs.
     * @param access trusted requester audit context
     * @param request exact replacement and frozen predecessor binding
     * @param submission fresh internal signing identity
     * @param ttl signing lifetime
     * @param evidence trusted execution evidence, never null
     * @param cancellation cooperative pre-acceptance cancellation
     * @return exclusively owned staged candidate
     * @throws IOException if staging or cancellation fails
     * @throws PkiException if proof, predecessor or frozen policy is invalid
     * @throws NullPointerException if evidence, submission, ttl is null
     */
    public DomainSigningRequest prepareCorrelatedReplacement(AccessContext access,
            CorrelatedEndEntityReplacementRequest request, SigningSubmissionId submission, Duration ttl,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(evidence, EVIDENCE_ARGUMENT);
        Objects.requireNonNull(submission, SUBMISSION_PARAMETER);
        Objects.requireNonNull(ttl, TTL_PARAMETER);
        CorrelatedIssuanceIdentity identity = CorrelatedIssuanceIdentity.derive(request);
        IssuanceIntent caller = request.intent();
        IssuanceIntent effective = new IssuanceIntent(caller.issuanceId(), identity.effectiveCommitment(),
                caller.expectedProfile(), caller.expectedIssuerId(), caller.expectedChainPathId(),
                caller.expectedChainPathCommitment());
        EndEntityLifecyclePreparation.Prepared approved = lifecycle.prepareCorrelatedReplacement(
                EndEntitySdkBindings.lifecycleAccess(access, request.request().existingCredentialId()), request, effective, cancellation);
        return stage(approved.issuance(), submission, ttl, evidence, cancellation, LeafOperation.REPLACE_END_ENTITY,
                Optional.of(approved.predecessor().credentialId()), identity.correlationId());
    }

    /**
     * Prepares renewal through the shared leaf builder and single staging path.
     * The predecessor supplies immutable source identity and current policy selection.
     * Ownership and cleanup match {@link #prepare}.
     * @param access trusted actor/purpose, with absent or matching source coordinates
     * @param request immutable renewal input
     * @param submission internally generated fresh operation identity
     * @param ttl exact session lifetime
     * @param evidence trusted execution evidence, or empty; never null
     * @param cancellation cooperative pre-acceptance cancellation
     * @return staged domain request exclusively owned by its caller
     * @throws IOException if staging or cancellation fails
     * @throws PkiException if predecessor or policy validation fails
     * @throws IllegalArgumentException if supplied access coordinates or evidence conflict
     * @throws NullPointerException if an argument is null
     */
    public DomainSigningRequest prepareRenewal(AccessContext access, EndEntityRenewalRequest request,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(evidence, EVIDENCE_ARGUMENT);
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(submission, SUBMISSION_PARAMETER);
        Objects.requireNonNull(ttl, TTL_PARAMETER);
        EndEntityLifecyclePreparation.Prepared approved = lifecycle.prepareRenewal(
                EndEntitySdkBindings.lifecycleAccess(access, request.existingCredentialId()), request, cancellation);
        return stage(approved.issuance(), submission, ttl, evidence, cancellation, LeafOperation.RENEW_END_ENTITY,
                Optional.of(approved.predecessor().credentialId()));
    }

    /**
     * Prepares verified replacement through the shared leaf builder and staging path.
     * Ownership and cleanup match {@link #prepare}.
     * @param access trusted actor/purpose, with absent or matching source coordinates
     * @param request immutable predecessor, exact CSR and selected profile
     * @param submission internally generated fresh operation identity
     * @param ttl exact session lifetime
     * @param evidence trusted execution evidence, or empty; never null
     * @param cancellation cooperative pre-acceptance cancellation
     * @return staged domain request exclusively owned by its caller
     * @throws IOException if staging or cancellation fails
     * @throws PkiException if predecessor, proof or policy validation fails
     * @throws IllegalArgumentException if supplied access coordinates or evidence conflict
     * @throws NullPointerException if an argument is null
     */
    public DomainSigningRequest prepareReplacement(AccessContext access, EndEntityReplacementRequest request,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(evidence, EVIDENCE_ARGUMENT);
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(submission, SUBMISSION_PARAMETER);
        Objects.requireNonNull(ttl, TTL_PARAMETER);
        EndEntityLifecyclePreparation.Prepared approved = lifecycle.prepareReplacement(
                EndEntitySdkBindings.lifecycleAccess(access, request.existingCredentialId()), request, cancellation);
        return stage(approved.issuance(), submission, ttl, evidence, cancellation, LeafOperation.REPLACE_END_ENTITY,
                Optional.of(approved.predecessor().credentialId()));
    }

    /**
     * Prepares reissue through the shared leaf builder and single staging path.
     * Ownership and cleanup match {@link #prepare}.
     * @param access trusted actor/purpose, with absent or matching source coordinates
     * @param request immutable reissue input
     * @param submission internally generated fresh operation identity
     * @param ttl exact session lifetime
     * @param evidence trusted execution evidence, or empty; never null
     * @param cancellation cooperative pre-acceptance cancellation
     * @return staged domain request exclusively owned by its caller
     * @throws IOException if staging or cancellation fails
     * @throws PkiException if predecessor or policy validation fails
     * @throws IllegalArgumentException if supplied access coordinates or evidence conflict
     * @throws NullPointerException if an argument is null
     */
    public DomainSigningRequest prepareReissue(AccessContext access, EndEntityReissueRequest request,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(evidence, EVIDENCE_ARGUMENT);
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(submission, SUBMISSION_PARAMETER);
        Objects.requireNonNull(ttl, TTL_PARAMETER);
        EndEntityLifecyclePreparation.Prepared approved = lifecycle.prepareReissue(
                EndEntitySdkBindings.lifecycleAccess(access, request.existingCredentialId()), request, cancellation);
        return stage(approved.issuance(), submission, ttl, evidence, cancellation, LeafOperation.REISSUE_END_ENTITY,
                Optional.of(approved.predecessor().credentialId()));
    }

    /**
     * Evaluates a new issuance request and prospective TBS size without durable preparation.
     *
     * <p>Policy validation uses a local serial coordinate rather than consuming an
     * issuer serial. The TBS is built only to measure its bounded length; it is not
     * retained, signed, staged or accepted. Trusted execution evidence is checked
     * against the validated actor, issuer and profile.
     *
     * @param access trusted invocation context
     * @param request typed issuance input
     * @param evidence trusted execution evidence when available
     * @param cancellation cooperative cancellation
     * @return bounded non-secret signing input admission coordinates
     * @throws IOException if authoritative metadata cannot be read
     * @throws RuntimeException if input, predecessor, profile or evidence is invalid
     */
    public Validation validate(AccessContext access, EndEntityIssuanceRequest request, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        return validateInput(access, request, evidence, cancellation);
    }

    /**
     * Evaluates a renewal predecessor and prospective TBS size without consuming a serial.
     *
     * <p>Authoritative lifecycle policy and access coordinates are checked through the
     * serial-free validation path. The temporary TBS supplies only an input-size
     * coordinate; no content is staged, no signature is requested and no work is accepted.
     *
     * @param access trusted invocation context
     * @param request exact renewal predecessor and requested validity
     * @param evidence trusted execution evidence when available
     * @param cancellation cooperative cancellation
     * @return bounded non-secret signing input admission coordinates
     * @throws IOException if authoritative metadata cannot be read
     * @throws RuntimeException if input, predecessor, profile or evidence is invalid
     */
    public Validation validate(AccessContext access, EndEntityRenewalRequest request, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        return validateInput(access, request, evidence, cancellation);
    }

    /**
     * Evaluates a replacement proof, predecessor policy and prospective signing-input size.
     *
     * <p>The serial-free validation path builds a temporary TBS only for its bounded
     * size. It neither changes predecessor status nor allocates a serial, signs,
     * stages content or admits an operation.
     *
     * @param access trusted invocation context
     * @param request exact predecessor, replacement request and selected profile
     * @param evidence trusted execution evidence when available
     * @param cancellation cooperative cancellation
     * @return bounded non-secret signing input admission coordinates
     * @throws IOException if authoritative metadata cannot be read
     * @throws RuntimeException if input, predecessor, profile or evidence is invalid
     */
    public Validation validate(AccessContext access, EndEntityReplacementRequest request, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        return validateInput(access, request, evidence, cancellation);
    }

    /**
     * Evaluates reissue of a retained predecessor and the prospective TBS size.
     *
     * <p>Current lifecycle and issuer policy is evaluated with a local serial
     * coordinate. No issuer serial is consumed and no content, signature or accepted
     * operation is retained by this validation-only path.
     *
     * @param access trusted invocation context
     * @param request exact authoritative predecessor selected for reissue
     * @param evidence trusted execution evidence when available
     * @param cancellation cooperative cancellation
     * @return bounded non-secret signing input admission coordinates
     * @throws IOException if authoritative metadata cannot be read
     * @throws RuntimeException if input, predecessor, profile or evidence is invalid
     */
    public Validation validate(AccessContext access, EndEntityReissueRequest request, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        return validateInput(access, request, evidence, cancellation);
    }

    private Validation validateInput(AccessContext access, Object request, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(evidence, EVIDENCE_ARGUMENT);
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        EndEntityIssuancePreparation pure = validation.withoutSerialAllocation();
        EndEntityLifecyclePreparation lifecycleValidation = pure.lifecyclePreparation();
        EndEntityIssuancePreparation.Prepared approved;
        if (request instanceof EndEntityIssuanceRequest input) {
            approved = pure.prepare(access, input, cancellation);
        } else if (request instanceof EndEntityRenewalRequest input) {
            approved = lifecycleValidation.prepareRenewal(EndEntitySdkBindings.lifecycleAccess(access, input.existingCredentialId()), input, cancellation).issuance();
        } else if (request instanceof EndEntityReplacementRequest input) {
            approved = lifecycleValidation.prepareReplacement(EndEntitySdkBindings.lifecycleAccess(access, input.existingCredentialId()), input, cancellation).issuance();
        } else if (request instanceof EndEntityReissueRequest input) {
            approved = lifecycleValidation.prepareReissue(EndEntitySdkBindings.lifecycleAccess(access, input.existingCredentialId()), input, cancellation).issuance();
        } else {
            throw new UnsupportedOperationException("Unsupported issuance input");
        }
        validateEvidence(evidence, approved.access(), approved.request().issuerCaId().value(), approved.request().profileId());
        int length = EndEntityCertificateEncoding.tbs(approved).length;
        if (length > CredentialContent.MAXIMUM_CERTIFICATE_BYTES) {
            throw new PkiException("Certificate body exceeds artifact limit: code=CERTIFICATE_TOO_LARGE");
        }
        cancellation.throwIfCancelled();
        return new Validation(approved.signature().canonicalForm(), length);
    }

    /**
     * Carries the selected signature identity and measured prospective TBS length.
     *
     * <p>Validation methods return these public coordinates without retaining a
     * generated artifact. The record itself is a passive carrier: its implicit
     * constructor does not repeat policy checks or enforce input-size bounds.
     *
     * @param signatureAlgorithm exact selected signature identity
     * @param tbsBytes measured TBS length in bytes
     */
    public record Validation(String signatureAlgorithm, int tbsBytes) {
    }

    /**
     * Evaluates SDK policy without allocating serials, staging or signing.
     *
     * <p>The returned preview binds the exact subject keys, issuer/profile/path and
     * effective policy. A supplied absolute validity is preserved during revalidation,
     * not extended from the current clock. No client proof is consumed and the
     * preview does not authorize issuance.
     *
     * @param access authorized invocation context
     * @param request exact selected issuer/profile/request
     * @param parsed parsed dual-subject request
     * @param frozenValidity exact absolute bounds, or empty for initial evaluation
     * @param cancellation cooperative cancellation
     * @return complete public policy preview
     * @throws IOException if public issuer metadata cannot be read
     * @throws RuntimeException if the request, selected policy, keys or frozen bounds are invalid
     */
    public SdkIssuancePreview previewSdk(AccessContext access,
            EndEntityIssuanceRequest request, ParsedHybridSdkRequest parsed,
            Optional<Validity> frozenValidity, CancellationSignal cancellation) throws IOException {
        EndEntityIssuancePreparation.Prepared approved = validation.prepareSdk(access, request, parsed, frozenValidity,
                true, cancellation);
        return sdkPreview(approved, parsed);
    }

    /**
     * Evaluates exact native enrollment coordinates using the ordinary pure policy snapshot.
     *
     * <p>A present native target must select issuance and the same original request
     * kind as the parsed payload. These public commitments do not replace carrier
     * authentication. No serial, signing result or staged candidate is created.
     *
     * @param access authenticated and authorized caller context
     * @param request exact typed issuance and selected issuer/profile
     * @param parsed exact original dual-subject request
     * @param frozenValidity retained absolute bounds, or an empty optional initially
     * @param enrollmentTarget trusted native target, or an empty optional for administrative use
     * @param cancellation cooperative validation cancellation signal
     * @return immutable preview including the validated native target when present
     * @throws IOException if retained public evidence is unavailable
     * @throws RuntimeException if the native operation, request kind, keys or selected policy is invalid
     */
    public SdkIssuancePreview previewSdk(AccessContext access,
            EndEntityIssuanceRequest request, ParsedHybridSdkRequest parsed,
            Optional<Validity> frozenValidity,
            Optional<SdkEnrollmentTarget> enrollmentTarget,
            CancellationSignal cancellation) throws IOException {
        return EndEntitySdkBindings.enrollmentPreview(previewSdk(access, request, parsed, frozenValidity, cancellation), parsed, enrollmentTarget);
    }

    private SdkIssuancePreview sdkPreview(EndEntityIssuancePreparation.Prepared approved,
            ParsedHybridSdkRequest parsed) throws IOException {
        return sdkPreview(approved, parsed, Optional.empty());
    }

    private SdkIssuancePreview sdkPreview(EndEntityIssuancePreparation.Prepared approved,
            ParsedHybridSdkRequest parsed,
            Optional<SdkLifecycleTarget> lifecycleTarget) throws IOException {
        return EndEntitySdkBindings.sdkPreview(approved, parsed, lifecycleTarget, validation);
    }

    /**
     * Verifies accepted client proofs and revalidates the exact frozen SDK target before staging.
     *
     * <p>Proof lifetime is evaluated at the retained acceptance time. Both the pure
     * preview and actual prepared policy snapshot must match the approved target.
     * Preparation then produces and verifies the issuer's alternative signature
     * before staging the final TBS; primary durable signing acceptance remains the
     * caller's responsibility. Returned content follows {@link #prepare}'s custody
     * and cleanup contract.
     *
     * @param access authorized invocation context
     * @param request selected issuer/profile/request
     * @param parsed exact parsed client request
     * @param approval trusted retained proof plus signed target
     * @param submission fresh submission identifier
     * @param ttl signing lifetime
     * @param evidence trusted publication evidence
     * @param cancellation cooperative cancellation
     * @return exclusively caller-owned staged request
     * @throws IOException if public metadata or staging fails
     * @throws PkiException if proof, target or policy differs
     */
    public DomainSigningRequest prepareSdk(AccessContext access, EndEntityIssuanceRequest request,
            ParsedHybridSdkRequest parsed,
            SdkIssuanceApproval approval, SigningSubmissionId submission,
            Duration ttl, Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) throws IOException {
        EndEntitySdkBindings.verifySdkProof(parsed, approval);
        SdkIssuancePreview preview = previewSdk(access, request, parsed, Optional.of(approval.preview().validity()),
                approval.preview().enrollmentTarget(), cancellation);
        EndEntitySdkBindings.requireSdkTarget(preview, approval, parsed);
        EndEntityIssuancePreparation.Prepared approved = validation.prepareSdk(access, request, parsed,
                Optional.of(preview.validity()), false, cancellation);
        // Revalidation may observe a new head or profile. Bind the actual signing
        // snapshot, including its frozen profile policy, before any signer or stage.
        preview = EndEntitySdkBindings.enrollmentPreview(sdkPreview(approved, parsed), parsed, approval.preview().enrollmentTarget());
        EndEntitySdkBindings.requireSdkTarget(preview, approval, parsed);
        return signSdk(approved, parsed, preview, submission, ttl, evidence, cancellation, LeafOperation.ISSUE_END_ENTITY, Optional.empty());
    }

    /**
     * Resolves the canonical core slot binding from actual managed public keys without signing.
     *
     * <p>This projects the retained-issuance coordinates from
     * {@link #managedOcspResponderProvisioningBinding}. It does not reserve a slot,
     * generate a key, stage content or admit an issuance operation.
     *
     * @param request exact proposed managed responder target
     * @param cancellation cooperative public-evidence resolution cancellation
     * @return canonical immutable retained-issuance binding
     * @throws IOException if managed public evidence is unavailable or cancellation is requested
     * @throws RuntimeException if the managed tuple or frozen issuer/profile selection is invalid
     */
    public RetainedIssuanceBinding managedOcspResponderBinding(
            ManagedOcspResponderIssuanceRequest request, CancellationSignal cancellation) throws IOException {
        return new ManagedResponderSigningPreparation(store, validation).managedOcspResponderBinding(request, cancellation);
    }

    /**
     * Resolves one actual managed subject tuple and its canonical issuance binding without signing.
     *
     * <p>The actual selected public keys determine their SPKI digests and canonical
     * provisioning identity. The result contains public coordinates only, not managed
     * private keys or authorization to use them. No slot, certificate or signing
     * workflow is created by this lookup.
     *
     * @param request immutable proposed managed responder target
     * @param cancellation cooperative public-evidence resolution cancellation
     * @return exact retained binding and both actual managed subject-SPKI digests
     * @throws IOException if public-key evidence is unavailable or cancellation is requested
     * @throws RuntimeException if the managed tuple or frozen issuer/profile selection is invalid
     */
    public ManagedOcspResponderProvisioningBinding managedOcspResponderProvisioningBinding(
            ManagedOcspResponderIssuanceRequest request, CancellationSignal cancellation) throws IOException {
        return new ManagedResponderSigningPreparation(store, validation).managedOcspResponderProvisioningBinding(request, cancellation);
    }

    /**
     * Performs all unsigned managed responder policy checks before an approval is requested.
     *
     * <p>Actual managed-key selection is resolved before the serial-free policy
     * evaluation. No serial is consumed, no issuer signature or subject-key proof
     * is produced, and no content is staged. The caller must supply its separately
     * authenticated and authorized invocation context.
     *
     * @param access authenticated and authorized caller context
     * @param request exact managed subject-key pair and issuer/profile/path target
     * @param cancellation cooperative validation cancellation signal
     * @throws IOException if immutable public key or issuer evidence is unavailable
     * @throws RuntimeException if key, issuer, profile, subject or validity policy rejects the target
     */
    public void validateManagedOcsp(AccessContext access,
            ManagedOcspResponderIssuanceRequest request, CancellationSignal cancellation) throws IOException {
        new ManagedResponderSigningPreparation(store, validation).validateManagedOcsp(access, request, cancellation);
    }

    /**
     * Freezes a dedicated managed responder leaf and both purpose-specific subject proofs.
     *
     * <p>Preparation resolves the canonical managed tuple, validates the certificate
     * target, and creates and verifies the issuer's alternative signature. Both
     * fresh subject-key challenges bind the final TBS, exact parent intent and their
     * distinct roles. The final TBS and two challenges are staged, but no durable
     * primary signing acceptance or certificate publication occurs here.
     *
     * <p>On success the caller owns all three candidates until semantic adoption.
     * A failed staging sequence retires candidates completed by this invocation,
     * retaining cleanup failures as suppressed exceptions. Already-produced issuer
     * alternative signatures are not undone. This operation neither generates or
     * exports managed private keys nor registers or activates a responder.
     *
     * @param access authenticated and authorized caller context
     * @param request immutable managed responder target
     * @param proofs session-owned managed subject-proof preparer
     * @param submission fresh parent signing identity
     * @param ttl finite positive signing lifetime, also used for child-proof deadlines
     * @param evidence trusted publication evidence, or an empty optional for embedded use
     * @param cancellation cooperative pre-adoption cancellation signal
     * @return exclusively owned final TBS and two proof-challenge candidates
     * @throws IOException if managed public evidence or staging is unavailable
     * @throws RuntimeException if keys, policy, alternative signing, proof planning,
     *         target bindings or trusted execution evidence are invalid
     */
    public DomainSigningRequest prepareManagedOcsp(AccessContext access,
            ManagedOcspResponderIssuanceRequest request, ManagedKeyProofPreparation proofs,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        return new ManagedResponderSigningPreparation(store, validation).prepareManagedOcsp(access, request, proofs, submission, ttl, evidence, cancellation);
    }

    /**
     * Checks retained proof/target consistency without current-policy reads or signing.
     *
     * <p>The dual client proofs are cryptographically verified at the retained proof
     * acceptance time and compared with their stored F3 commitment. The retained
     * public preview must also match the approved target frame. This check does not
     * re-admit an expired open intent, authorize a caller or evaluate current key-use policy.
     *
     * @param parsed exact original parsed dual-subject client request
     * @param approval retained accepted proof and immutable public target
     * @throws PkiException if either proof or the immutable target differs
     */
    public static void validateSdkApproval(ParsedHybridSdkRequest parsed,
            SdkIssuanceApproval approval) {
        EndEntitySdkBindings.verifySdkProof(parsed, approval);
        EndEntitySdkBindings.requireSdkTarget(approval.preview(), approval, parsed);
    }

    /**
     * Checks a correlated operation against the retained public SDK target before lookup.
     *
     * <p>The selected issuer, profile and path must agree with the preview; an issuance
     * request must additionally carry the exact original payload kind and bytes. This
     * method does not itself verify the dual signatures: the caller must separately
     * invoke {@link #validateSdkApproval}. No live policy admission or signing occurs.
     *
     * @param correlated existing correlated issuance, renewal or replacement request
     * @param parsed exact original parsed request
     * @param approval retained accepted target and preview
     * @throws PkiException if immutable request or frozen-selection coordinates differ
     * @throws UnsupportedOperationException if the correlated request type is unsupported
     */
    public static void validateCorrelatedSdkBinding(Object correlated,
            ParsedHybridSdkRequest parsed,
            SdkIssuanceApproval approval) {
        EndEntitySdkBindings.validateCorrelatedSdkBinding(correlated, parsed, approval);
    }

    /**
     * Prepares one exact correlated SDK leaf operation using its native durable identity.
     *
     * <p>The semantic facade must exclude an already accepted replay before calling
     * this fresh-preparation path. Retained dual proof and frozen selection are
     * revalidated, then the actual target must match before alternative issuer signing.
     * The native correlation is retained in the resulting continuation; this method
     * does not reserve it or durably accept work. Content custody follows {@link #prepare}.
     *
     * @param access genuine authenticated and authorized native caller context
     * @param correlated exact correlated issuance, renewal or replacement request
     * @param parsed exact original proof-bound dual-subject request
     * @param approval retained accepted proof and frozen target
     * @param submission fresh parent signing identity
     * @param ttl finite positive signing lifetime
     * @param evidence trusted native execution evidence, or an empty optional
     * @param cancellation cooperative pre-adoption cancellation signal
     * @return exclusively caller-owned staged signing request
     * @throws IOException if retained public data or staging fails
     * @throws PkiException if the correlated selection, predecessor or proof differs
     * @throws UnsupportedOperationException if the correlated request type is unsupported
     */
    public DomainSigningRequest prepareCorrelatedSdk(AccessContext access, Object correlated,
            ParsedHybridSdkRequest parsed,
            SdkIssuanceApproval approval, SigningSubmissionId submission,
            Duration ttl, Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) throws IOException {
        validateSdkApproval(parsed, approval);
        CorrelatedIssuanceIdentity identity;
        IssuanceIntent caller;
        Object command;
        if (correlated instanceof CorrelatedEndEntityIssuanceRequest issue) {
            identity = CorrelatedIssuanceIdentity.derive(issue);
            caller = issue.intent();
            command = issue.request();
        } else if (correlated instanceof CorrelatedEndEntityRenewalRequest renew) {
            identity = CorrelatedIssuanceIdentity.derive(renew);
            caller = renew.intent();
            command = renew.request();
        } else if (correlated instanceof CorrelatedEndEntityReplacementRequest replace) {
            identity = CorrelatedIssuanceIdentity.derive(replace);
            caller = replace.intent();
            command = replace.request();
        } else {
            throw new UnsupportedOperationException("SDK correlated operation unavailable");
        }
        IssuanceIntent effective = new IssuanceIntent(caller.issuanceId(), identity.effectiveCommitment(), caller.expectedProfile(),
                caller.expectedIssuerId(), caller.expectedChainPathId(), caller.expectedChainPathCommitment());
        Optional<Validity> validity = Optional.of(approval.preview().validity());
        EndEntityIssuancePreparation.Prepared approved;
        Optional<SdkLifecycleTarget> lifecycleTarget;
        LeafOperation operation;
        Optional<PkiId> predecessor;
        if (command instanceof EndEntityIssuanceRequest issue) {
            approved = validation.prepareSdk(access, issue, parsed, validity, false, validation.beginSdkEvaluation(),
                    Optional.of(effective), cancellation);
            lifecycleTarget = Optional.empty();
            operation = LeafOperation.ISSUE_END_ENTITY;
            predecessor = Optional.empty();
        } else {
            EndEntityLifecyclePreparation.SdkPrepared snapshot = lifecycle.prepareSdk(EndEntitySdkBindings.sdkLifecycleAccess(access, command),
                    command, parsed, validity, false,
                    Optional.of(effective), Optional.of(correlated), cancellation);
            approved = snapshot.prepared().issuance();
            lifecycleTarget = Optional.of(snapshot.target());
            operation = command instanceof EndEntityRenewalRequest ? LeafOperation.RENEW_END_ENTITY : LeafOperation.REPLACE_END_ENTITY;
            predecessor = Optional.of(snapshot.prepared().predecessor().credentialId());
        }
        SdkIssuancePreview preview = EndEntitySdkBindings.enrollmentPreview(sdkPreview(approved, parsed, lifecycleTarget), parsed,
                approval.preview().enrollmentTarget());
        EndEntitySdkBindings.requireSdkTarget(preview, approval, parsed);
        return signSdk(approved, parsed, preview, submission, ttl, evidence, cancellation, new LeafTarget(operation, predecessor), identity.correlationId());
    }

    /**
     * Evaluates one existing leaf lifecycle target without proof consumption, signing or staging.
     *
     * <p>The serial-free lifecycle preparation validates the predecessor and selected
     * policy, then constructs the public SDK preview. Supplied absolute validity is
     * preserved during revalidation. The returned lifecycle commitment is evidence
     * of the evaluated target, not authorization to reuse a key or issue a certificate.
     *
     * @param access authenticated and authorized caller context
     * @param request exact renewal, reissue or replacement request
     * @param parsed exact original dual-subject client request
     * @param frozenValidity retained absolute bounds, or an empty optional initially
     * @param cancellation cooperative validation cancellation signal
     * @return immutable preview including the exact predecessor and lifecycle target
     * @throws IOException if retained public content cannot be read
     * @throws RuntimeException if operation, predecessor, subject keys or policy is invalid
     */
    public SdkIssuancePreview previewSdkLifecycle(AccessContext access, Object request,
            ParsedHybridSdkRequest parsed, Optional<Validity> frozenValidity,
            CancellationSignal cancellation) throws IOException {
        EndEntityLifecyclePreparation.SdkPrepared snapshot = validation.withoutSerialAllocation().lifecyclePreparation().prepareSdk(
                EndEntitySdkBindings.sdkLifecycleAccess(access, request), request, parsed, frozenValidity, true, cancellation);
        return sdkPreview(snapshot.prepared().issuance(), parsed, Optional.of(snapshot.target()));
    }

    /**
     * Evaluates a lifecycle and native enrollment target in one public preview.
     *
     * <p>A present enrollment target must select the lifecycle action supported by
     * its native mapping and the same original request kind. The current mapping
     * permits renewal and replacement; native reissue is rejected rather than
     * silently relabeled. Empty enrollment context preserves administrative lifecycle use.
     *
     * @param access authenticated and authorized caller context
     * @param request exact renewal, reissue or replacement request
     * @param parsed exact original dual-subject client request
     * @param frozenValidity retained absolute bounds, or an empty optional initially
     * @param enrollmentTarget trusted native policy context, or an empty optional
     * @param cancellation cooperative validation cancellation signal
     * @return immutable combined lifecycle and supported native-enrollment target
     * @throws IOException if retained public evidence is unavailable
     * @throws RuntimeException if lifecycle policy, native operation or request kind is invalid
     */
    public SdkIssuancePreview previewSdkLifecycle(AccessContext access, Object request,
            ParsedHybridSdkRequest parsed, Optional<Validity> frozenValidity,
            Optional<SdkEnrollmentTarget> enrollmentTarget,
            CancellationSignal cancellation) throws IOException {
        return EndEntitySdkBindings.enrollmentPreview(previewSdkLifecycle(access, request, parsed, frozenValidity, cancellation), parsed, enrollmentTarget);
    }

    /**
     * Verifies fresh accepted dual proof and actual frozen lifecycle target before any alternative signing.
     *
     * <p>Dual proof is evaluated at its original acceptance time. Current lifecycle
     * validation must still produce the exact approved target; a changed predecessor,
     * issuer, path, profile or subject key fails before alternative issuer signing.
     * The alternative signature is produced and verified before final TBS staging.
     * No durable primary signing acceptance occurs, and returned content remains
     * caller-owned until semantic adoption or retirement.
     *
     * @param access authenticated and authorized caller context
     * @param request exact renewal, reissue or replacement request
     * @param parsed exact original dual-subject client request
     * @param approval retained accepted proof and frozen target
     * @param submission fresh parent signing-submission identity
     * @param ttl configured positive signing lifetime
     * @param evidence trusted publication evidence, or an empty optional for embedded use
     * @param cancellation cooperative pre-adoption cancellation signal
     * @return caller-owned final staged lifecycle signing request
     * @throws IOException if public content or staging fails
     * @throws RuntimeException if proof, predecessor, target, status or policy differs
     */
    public DomainSigningRequest prepareSdkLifecycle(AccessContext access, Object request,
            ParsedHybridSdkRequest parsed, SdkIssuanceApproval approval,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        EndEntitySdkBindings.verifySdkProof(parsed, approval);
        SdkIssuancePreview preview = previewSdkLifecycle(access, request, parsed, Optional.of(approval.preview().validity()),
                approval.preview().enrollmentTarget(), cancellation);
        EndEntitySdkBindings.requireSdkTarget(preview, approval, parsed);
        EndEntityLifecyclePreparation.SdkPrepared actual = lifecycle.prepareSdk(EndEntitySdkBindings.sdkLifecycleAccess(access, request), request, parsed,
                Optional.of(preview.validity()), false, cancellation);
        preview = EndEntitySdkBindings.enrollmentPreview(sdkPreview(actual.prepared().issuance(), parsed, Optional.of(actual.target())), parsed,
                approval.preview().enrollmentTarget());
        EndEntitySdkBindings.requireSdkTarget(preview, approval, parsed);
        LeafOperation operation = switch (actual.target().operation()) {
            case "credential.renew" -> LeafOperation.RENEW_END_ENTITY;
            case "credential.reissue" -> LeafOperation.REISSUE_END_ENTITY;
            case "credential.replace" -> LeafOperation.REPLACE_END_ENTITY;
            default -> throw new UnsupportedOperationException("Unsupported SDK lifecycle operation");
        };
        return signSdk(actual.prepared().issuance(), parsed, preview, submission, ttl, evidence, cancellation,
                operation, Optional.of(actual.prepared().predecessor().credentialId()));
    }

    private DomainSigningRequest signSdk(EndEntityIssuancePreparation.Prepared approved,
            ParsedHybridSdkRequest parsed, SdkIssuancePreview preview,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation, LeafOperation operation, Optional<PkiId> predecessor) throws IOException {
        return signSdk(approved, parsed, preview, submission, ttl, evidence, cancellation, new LeafTarget(operation, predecessor),
                "issue." + EndEntityCertificateEncoding.sha256(submission.id().value().getBytes(StandardCharsets.UTF_8)));
    }

    private DomainSigningRequest signSdk(EndEntityIssuancePreparation.Prepared approved,
            ParsedHybridSdkRequest parsed, SdkIssuancePreview preview,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation, LeafTarget target, String correlation) throws IOException {
        byte[] completeTbs = EndEntityCertificateEncoding.buildHybridTbs(approved, parsed, preview, validation);
        return stageSdk(approved, submission, ttl, evidence, cancellation, completeTbs, target.operation(), target.predecessor(), correlation);
    }

    private DomainSigningRequest stage(EndEntityIssuancePreparation.Prepared approved, SigningSubmissionId submission,
            Duration ttl, Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation,
            LeafOperation operation, Optional<PkiId> predecessor)
            throws IOException {
        String correlation = "issue." + EndEntityCertificateEncoding.sha256(submission.id().value().getBytes(StandardCharsets.UTF_8));
        return stage(approved, submission, ttl, evidence, cancellation, operation, predecessor, correlation);
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    private DomainSigningRequest stage(EndEntityIssuancePreparation.Prepared approved, SigningSubmissionId submission,
            Duration ttl, Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation,
            LeafOperation operation, Optional<PkiId> predecessor,
            String correlation) throws IOException {
        validateEvidence(evidence, approved.access(), approved.request().issuerCaId().value(),
                approved.request().profileId());
        return stageSdk(approved, submission, ttl, evidence, cancellation, EndEntityCertificateEncoding.tbs(approved), operation, predecessor, correlation);
    }

    // Retain the primary failure and original cleanup-failure suppression precedence.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private DomainSigningRequest stageSdk(EndEntityIssuancePreparation.Prepared approved, SigningSubmissionId submission,
            Duration ttl, Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation, byte[] tbs,
            LeafOperation operation, Optional<PkiId> predecessor, String correlation) throws IOException {
        validateEvidence(evidence, approved.access(), approved.request().issuerCaId().value(), approved.request().profileId());
        if (tbs.length > CredentialContent.MAXIMUM_CERTIFICATE_BYTES) {
            throw new PkiException("Certificate body exceeds artifact limit: code=CERTIFICATE_TOO_LARGE");
        }
        DomainContinuationTemplate template = continuation(approved, correlation, operation, predecessor, evidence);
        DurableContentReference content = null;
        try {
            cancellation.throwIfCancelled();
            try (ContentSink sink = store.stagedContent().beginContent(Encoding.DER,
                    DurableContentReference.Lifecycle.OPERATION); OutputStream output = sink.outputStream()) {
                int offset = 0;
                while (offset < tbs.length) {
                    cancellation.throwIfCancelled();
                    int length = Math.min(16 * 1024, tbs.length - offset);
                    output.write(tbs, offset, length);
                    offset += length;
                }
                cancellation.throwIfCancelled();
                content = sink.complete();
            }
            cancellation.throwIfCancelled();
            return new DomainSigningRequest(submission.id(), approved.access(), approved.keyRef(),
                    approved.signature().canonicalForm(), Encoding.BINARY, content, ttl, template, Optional.empty());
        } catch (IOException | RuntimeException | Error primary) {
            if (content != null) {
                try {
                    store.stagedContent().retireUnownedContent(content);
                } catch (IOException | RuntimeException cleanup) {
                    primary.addSuppressed(cleanup);
                }
            }
            throw primary;
        }
    }

    private static DomainContinuationTemplate continuation(EndEntityIssuancePreparation.Prepared approved,
            String correlation, LeafOperation operation, Optional<PkiId> predecessor,
            Optional<IssuanceExecutionEvidence> evidence) {
        ValidatedCertificateRequest request = evidence.isPresent()
                ? approved.request().withExecutionEvidence(evidence.orElseThrow().attributes()) : approved.request();
        ValidatedCertificateRequest.FrozenIssuance frozen = request.frozenIssuance().orElseThrow();
        List<String> fields = new ArrayList<>(List.of(request.issuerCaId().value(), frozen.issuerId().value(), frozen.chainPathId().value(),
                frozen.chainPathCommitment(), request.profileId(), Long.toString(request.profileReference().profileVersion()),
                HexFormat.of().formatHex(request.profileReference().canonicalSha256()), request.subjectRef().value(),
                request.validity().notBefore().toString(), request.validity().notAfter().toString(), approved.serial().toString(),
                approved.keyRef().value(), approved.issuerContent().contentId(), approved.issuerContent().sha256(),
                EndEntityCertificateEncoding.sha256(request.exactPublicKey().bytes()), frozen.intent().map(IssuanceIntent::issuanceId).orElse(""),
                frozen.intent().map(IssuanceIntent::commandCommitment).orElse(""), request.subjectRdns().toString(),
                request.subjectAlternativeNames().toString(), request.keyUsages().stream().sorted().toList().toString(),
                request.extendedKeyUsages().stream().sorted(Comparator.comparing(ExtendedKeyUsageId::oid))
                        .toList().toString(),
                request.algorithmBindingPolicy().toString(), DomainAttributeEncoding.encode(request.executionEvidence())));
        predecessor.ifPresent(value -> fields.add(value.value()));
        fields.add(approved.issuerBinding().commitment());
        return DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.ISSUANCE, correlation,
                operation.name(), fields.toArray(String[]::new));
    }

    /**
     * Leaf publication target retained with its predecessor coordinates.
     */
    private record LeafTarget(LeafOperation operation, Optional<PkiId> predecessor) { }

    /** Leaf workflow discriminator retained in the accepted signing metadata. */
    private enum LeafOperation {
        ISSUE_END_ENTITY,
        RENEW_END_ENTITY,
        REPLACE_END_ENTITY,
        REISSUE_END_ENTITY
    }

    /**
     * Checks trusted evidence against the actor and already frozen issuance scope.
     * Performs no store lookup, policy admission, allocation of content or mutation.
     *
     * @param evidence trusted or decoded evidence, possibly empty but never null
     * @param access invocation or retained acceptance audit context
     * @param issuerCaId authoritative logical issuing authority identifier
     * @param profileId authoritative frozen profile identifier
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if present evidence conflicts with the supplied binding
     */
    public static void validateEvidence(Optional<IssuanceExecutionEvidence> evidence, AccessContext access,
            String issuerCaId, String profileId) {
        Objects.requireNonNull(evidence, EVIDENCE_ARGUMENT);
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(issuerCaId, "issuerCaId");
        Objects.requireNonNull(profileId, "profileId");
        if (evidence.isPresent()) {
            IssuanceExecutionEvidence value = evidence.orElseThrow();
            if (!value.actorId().equals(access.principal().name())
                    || !value.actorType().name().equals(access.principal().type())
                    || !value.issuerCaId().equals(issuerCaId) || !value.profileId().equals(profileId)) {
                throw new IllegalArgumentException("Issuance execution evidence binding differs");
            }
        }
    }

}
