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

import zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest;
import zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.EnumSet;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.issuance.EndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.CorrelatedEndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.IssuanceIntent;
import zeroecho.pki.api.issuance.EndEntityRenewalRequest;
import zeroecho.pki.api.issuance.EndEntityReplacementRequest;
import zeroecho.pki.api.issuance.EndEntityReissueRequest;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.profile.ExtendedKeyUsageId;
import zeroecho.pki.api.profile.LeafKeyUsage;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.impl.core.continuation.DomainAttributeEncoding;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pkix.BasicConstraints;
import zeroecho.pkix.ExtendedKeyUsage;
import zeroecho.pkix.GeneralName;
import zeroecho.pkix.KeyUsage;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.cert.CertificateBuilder;

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
     */
    public EndEntitySigningPreparation(PkiStore store, Clock clock, X509AuthoritySnapshot authority,
            BcX509VerificationExecutor verifier, X509AlgorithmBindingRegistry bindings, String signatureAlgorithm) {
        this(store, new EndEntityIssuancePreparation(store, clock, authority, verifier, bindings, signatureAlgorithm));
    }

    /**
     * Binds leaf verification and signing to separate exact authority snapshots.
     * @param store authoritative session store
     * @param clock authoritative policy clock
     * @param authority verification authority for client proof
     * @param verifier exact verification executor
     * @param bindings installed representation registry
     * @param signatureAlgorithm configured legacy creation default
     * @param signingAuthority signing authority bound to the selected provider
     * @param provider already-open managed public-key source and signer
     * Ordinary signing-only providers retain their established behavior; SDK
     * issuance independently requires managed public-key evidence.
     */
    public EndEntitySigningPreparation(PkiStore store, Clock clock, X509AuthoritySnapshot authority,
            BcX509VerificationExecutor verifier, X509AlgorithmBindingRegistry bindings, String signatureAlgorithm,
            X509AuthoritySnapshot signingAuthority, zeroecho.pki.spi.crypto.SigningProvider provider) {
        this(store, new EndEntityIssuancePreparation(store, clock, authority, verifier, bindings, signatureAlgorithm,
                signingAuthority, publicKeys(provider)));
    }
    private static Optional<zeroecho.pki.spi.crypto.PublicKeyInfoSource> publicKeys(zeroecho.pki.spi.crypto.SigningProvider provider) {
        Objects.requireNonNull(provider, "provider");
        return provider instanceof zeroecho.pki.spi.crypto.PublicKeyInfoSource keys ? Optional.of(keys) : Optional.empty();
    }

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
                lifecycleAccess(access, request.request().existingCredentialId()), request, effective, cancellation);
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
                lifecycleAccess(access, request.request().existingCredentialId()), request, effective, cancellation);
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
                lifecycleAccess(access, request.existingCredentialId()), request, cancellation);
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
                lifecycleAccess(access, request.existingCredentialId()), request, cancellation);
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
                lifecycleAccess(access, request.existingCredentialId()), request, cancellation);
        return stage(approved.issuance(), submission, ttl, evidence, cancellation, LeafOperation.REISSUE_END_ENTITY,
                Optional.of(approved.predecessor().credentialId()));
    }

    /**
     * Validates typed issuance input using public metadata and a local serial coordinate.
     * No serial allocation, signing, content staging or acceptance is reachable.
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
     * Validates typed issuance input using public metadata and a local serial coordinate.
     * No serial allocation, signing, content staging or acceptance is reachable.
     * @param access trusted invocation context
     * @param request typed issuance input
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
     * Validates typed issuance input using public metadata and a local serial coordinate.
     * No serial allocation, signing, content staging or acceptance is reachable.
     * @param access trusted invocation context
     * @param request typed issuance input
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
     * Validates typed issuance input using public metadata and a local serial coordinate.
     * No serial allocation, signing, content staging or acceptance is reachable.
     * @param access trusted invocation context
     * @param request typed issuance input
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
            approved = lifecycleValidation.prepareRenewal(lifecycleAccess(access, input.existingCredentialId()), input, cancellation).issuance();
        } else if (request instanceof EndEntityReplacementRequest input) {
            approved = lifecycleValidation.prepareReplacement(lifecycleAccess(access, input.existingCredentialId()), input, cancellation).issuance();
        } else if (request instanceof EndEntityReissueRequest input) {
            approved = lifecycleValidation.prepareReissue(lifecycleAccess(access, input.existingCredentialId()), input, cancellation).issuance();
        } else { throw new UnsupportedOperationException("Unsupported issuance input"); }
        validateEvidence(evidence, approved.access(), approved.request().issuerCaId().value(), approved.request().profileId());
        int length = tbs(approved).length;
        if (length > CredentialContent.MAXIMUM_CERTIFICATE_BYTES) {
            throw new PkiException("Certificate body exceeds artifact limit: code=CERTIFICATE_TOO_LARGE");
        }
        cancellation.throwIfCancelled();
        return new Validation(approved.signature().canonicalForm(), length);
    }

    /**
     * Public non-secret input admission coordinates; no generated artifact is retained.
     * @param signatureAlgorithm exact selected signature identity
     * @param tbsBytes bounded local TBS length
     */
    public record Validation(String signatureAlgorithm, int tbsBytes) { }

    /**
     * Evaluates SDK policy without allocating serials, staging or signing.
     * @param access authorized invocation context
     * @param request exact selected issuer/profile/request
     * @param parsed parsed dual-subject request
     * @param frozenValidity exact absolute bounds, or empty for initial evaluation
     * @param cancellation cooperative cancellation
     * @return complete public policy preview
     * @throws IOException if public issuer metadata cannot be read
     */
    public zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdk(AccessContext access,
            EndEntityIssuanceRequest request, zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed,
            Optional<zeroecho.pki.api.Validity> frozenValidity, CancellationSignal cancellation) throws IOException {
        var approved = validation.prepareSdk(access, request, parsed, frozenValidity, true, cancellation);
        return sdkPreview(approved, parsed);
    }

    /**
     * Evaluates exact native enrollment coordinates using the ordinary pure policy snapshot.
     * @param access authorized caller @param request typed issuance @param parsed original request
     * @param frozenValidity retained bounds @param enrollmentTarget native frozen target
     * @param cancellation cancellation @return public combined preview
     * @throws IOException if retained public evidence is unavailable
     */
    public zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdk(AccessContext access,
            EndEntityIssuanceRequest request, zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed,
            Optional<zeroecho.pki.api.Validity> frozenValidity,
            Optional<zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget> enrollmentTarget,
            CancellationSignal cancellation) throws IOException {
        return enrollmentPreview(previewSdk(access, request, parsed, frozenValidity, cancellation), parsed, enrollmentTarget);
    }

    private static zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview enrollmentPreview(
            zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview preview,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed,
            Optional<zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget> target) {
        target.ifPresent(value -> {
            String operation = preview.lifecycleTarget().map(lifecycle -> switch (lifecycle.operation()) {
                case "credential.renew" -> "RENEW";
                case "credential.replace" -> "REPLACE";
                default -> throw new PkiException("SDK_ENROLLMENT_OPERATION_UNSUPPORTED");
            }).orElse("ISSUE");
            if (!value.operation().equals(operation) || value.requestKind() != parsed.originalPayload().kind()) {
                throw new PkiException("SDK_ENROLLMENT_TARGET_MISMATCH");
            }
        });
        return new zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview(preview.issuerCaId(), preview.issuerId(),
                preview.chainPathId(), preview.chainPathCommitment(), preview.profile(), preview.subjectRef(),
                preview.subject(), preview.subjectAlternativeNames(), preview.validity(), preview.primarySubjectSpki(),
                preview.alternativeSubjectSpki(), preview.issuerBinding(), preview.issuerPrimarySpki(), preview.issuerAlternativeSpki(),
                preview.issuerCertificateSha512(), preview.providerEvidence(), preview.disclosurePolicy(), preview.lifecycleTarget(), target);
    }

    private zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview sdkPreview(EndEntityIssuancePreparation.Prepared approved,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed) throws IOException {
        return sdkPreview(approved, parsed, Optional.empty());
    }

    private zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview sdkPreview(EndEntityIssuancePreparation.Prepared approved,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed,
            Optional<zeroecho.pki.api.hybrid.sdk.SdkLifecycleTarget> lifecycleTarget) throws IOException {
        var frozen = approved.request().frozenIssuance().orElseThrow();
        var certificate = Pkix.parseCertificate(approved.issuerDer());
        var profile = approved.profile();
        var policy = zeroecho.pki.api.hybrid.sdk.HybridSdkValue.object(java.util.Map.of(
                "profile", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.bytes(profile.reference().canonicalSha256()),
                "confirmation", profile.definition().confirmationPolicy().map(EndEntitySigningPreparation::confirmationPolicyValue)
                        .orElseGet(() -> zeroecho.pki.api.hybrid.sdk.HybridSdkValue.object(java.util.Map.of()))));
        return new zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview(approved.request().issuerCaId(), frozen.issuerId(),
                frozen.chainPathId(), frozen.chainPathCommitment(), approved.request().profileReference(),
                approved.request().subjectRef(), approved.request().subjectRdns(), approved.request().subjectAlternativeNames(),
                approved.request().validity(), approved.request().exactPublicKey(), parsed.alternativeSubjectPublicKeyInfo(),
                approved.issuerBinding(), new zeroecho.pki.api.EncodedObject(Encoding.DER, Pkix.subjectPublicKeyInfo(certificate)),
                Optional.of(new zeroecho.pki.api.EncodedObject(Encoding.DER,
                        zeroecho.pki.impl.hybrid.AltSignatureExtensions.requiredValue(certificate, "2.5.29.72"))),
                java.util.HexFormat.of().formatHex(zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.hash(approved.issuerDer())),
                validation.authority().semanticFingerprint(), policy, lifecycleTarget);
    }

    private static zeroecho.pki.api.hybrid.sdk.HybridSdkValue confirmationPolicyValue(
            zeroecho.pki.api.confirmation.CredentialConfirmationPolicy policy) {
        return zeroecho.pki.api.hybrid.sdk.HybridSdkValue.object(java.util.Map.of(
                "disclosure", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(policy.disclosurePolicy().name()),
                "window", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(policy.confirmationWindow().toString()),
                "suite", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(policy.proofSuite().suiteId()),
                "suiteCommitment", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(policy.proofSuite().configurationCommitment()),
                "commitment", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text("sha256:" + policy.configurationCommitment())));
    }

    /**
     * Verifies accepted client proofs and revalidates the exact frozen SDK target before staging.
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
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed,
            zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval approval, SigningSubmissionId submission,
            Duration ttl, Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) throws IOException {
        verifySdkProof(parsed, approval);
        var preview = previewSdk(access, request, parsed, Optional.of(approval.preview().validity()), approval.preview().enrollmentTarget(), cancellation);
        requireSdkTarget(preview, approval, parsed);
        var approved = validation.prepareSdk(access, request, parsed, Optional.of(preview.validity()), false, cancellation);
        // Revalidation may observe a new head or profile. Bind the actual signing
        // snapshot, including its frozen profile policy, before any signer or stage.
        preview = enrollmentPreview(sdkPreview(approved, parsed), parsed, approval.preview().enrollmentTarget());
        requireSdkTarget(preview, approval, parsed);
        return signSdk(approved, parsed, preview, submission, ttl, evidence, cancellation, LeafOperation.ISSUE_END_ENTITY, Optional.empty());
    }

    /**
     * Checks retained proof/target consistency without current-policy reads or signing.
     * @param parsed exact original client request @param approval retained proof and public target
     * @throws PkiException if either proof or the immutable target differs
     */
    public static void validateSdkApproval(zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed,
            zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval approval) {
        verifySdkProof(parsed, approval);
        requireSdkTarget(approval.preview(), approval, parsed);
    }

    /**
     * Checks a correlated operation against the retained public SDK target before lookup.
     * @param correlated existing native correlated request @param parsed exact original request
     * @param approval retained accepted target @throws PkiException if immutable coordinates differ
     */
    public static void validateCorrelatedSdkBinding(Object correlated,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed,
            zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval approval) {
        IssuanceIntent intent; PkiId ca;
        if (correlated instanceof CorrelatedEndEntityIssuanceRequest issue) {
            intent = issue.intent(); ca = issue.request().issuerCaId();
            if (issue.request().payload().kind() != parsed.originalPayload().kind()
                    || !java.util.Arrays.equals(issue.request().payload().der(), parsed.originalPayload().der())) {
                throw new PkiException("SDK_REQUEST_MISMATCH");
            }
        } else if (correlated instanceof CorrelatedEndEntityRenewalRequest renew) {
            intent = renew.intent(); ca = renew.issuerCaId();
        } else if (correlated instanceof CorrelatedEndEntityReplacementRequest replace) {
            intent = replace.intent(); ca = replace.issuerCaId();
        } else throw new UnsupportedOperationException("SDK correlated operation unavailable");
        var preview = approval.preview();
        if (!ca.equals(preview.issuerCaId()) || !intent.expectedProfile().equals(preview.profile())
                || !intent.expectedIssuerId().equals(preview.issuerId())
                || !intent.expectedChainPathId().equals(preview.chainPathId())
                || !intent.expectedChainPathCommitment().equals(preview.chainPathCommitment())) {
            throw new PkiException("SDK_FROZEN_TARGET_MISMATCH");
        }
    }

    /**
     * Prepares one exact correlated SDK leaf operation using its native durable identity.
     * @param access genuine authorized caller @param correlated restricted existing correlated request
     * @param parsed exact proof-bound request @param approval retained SDK acceptance
     * @param submission fresh signing identity @param ttl signing lifetime @param evidence trusted native evidence
     * @param cancellation cooperative cancellation @return exclusively owned staged request
     * @throws IOException if retained public data or staging fails
     * @throws PkiException if the correlated selection, predecessor or proof differs
     */
    public DomainSigningRequest prepareCorrelatedSdk(AccessContext access, Object correlated,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed,
            zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval approval, SigningSubmissionId submission,
            Duration ttl, Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) throws IOException {
        validateSdkApproval(parsed, approval);
        CorrelatedIssuanceIdentity identity; IssuanceIntent caller; Object command;
        if (correlated instanceof CorrelatedEndEntityIssuanceRequest issue) {
            identity = CorrelatedIssuanceIdentity.derive(issue); caller = issue.intent(); command = issue.request();
        } else if (correlated instanceof CorrelatedEndEntityRenewalRequest renew) {
            identity = CorrelatedIssuanceIdentity.derive(renew); caller = renew.intent(); command = renew.request();
        } else if (correlated instanceof CorrelatedEndEntityReplacementRequest replace) {
            identity = CorrelatedIssuanceIdentity.derive(replace); caller = replace.intent(); command = replace.request();
        } else throw new UnsupportedOperationException("SDK correlated operation unavailable");
        var effective = new IssuanceIntent(caller.issuanceId(), identity.effectiveCommitment(), caller.expectedProfile(),
                caller.expectedIssuerId(), caller.expectedChainPathId(), caller.expectedChainPathCommitment());
        var validity = Optional.of(approval.preview().validity());
        EndEntityIssuancePreparation.Prepared approved;
        Optional<zeroecho.pki.api.hybrid.sdk.SdkLifecycleTarget> lifecycleTarget;
        LeafOperation operation; Optional<PkiId> predecessor;
        if (command instanceof EndEntityIssuanceRequest issue) {
            approved = validation.prepareSdk(access, issue, parsed, validity, false, validation.beginSdkEvaluation(), Optional.of(effective), cancellation);
            lifecycleTarget = Optional.empty(); operation = LeafOperation.ISSUE_END_ENTITY; predecessor = Optional.empty();
        } else {
            var snapshot = lifecycle.prepareSdk(sdkLifecycleAccess(access, command), command, parsed, validity, false,
                    Optional.of(effective), Optional.of(correlated), cancellation);
            approved = snapshot.prepared().issuance(); lifecycleTarget = Optional.of(snapshot.target());
            operation = command instanceof EndEntityRenewalRequest ? LeafOperation.RENEW_END_ENTITY : LeafOperation.REPLACE_END_ENTITY;
            predecessor = Optional.of(snapshot.prepared().predecessor().credentialId());
        }
        var preview = enrollmentPreview(sdkPreview(approved, parsed, lifecycleTarget), parsed, approval.preview().enrollmentTarget());
        requireSdkTarget(preview, approval, parsed);
        return signSdk(approved, parsed, preview, submission, ttl, evidence, cancellation, operation, predecessor, identity.correlationId());
    }

    private static void verifySdkProof(zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed,
            zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval approval) {
        String proof = new zeroecho.pki.impl.framework.x509.bc.BcHybridSdkProofVerifier().verify(parsed,
                approval.primaryFrame(), approval.primaryProof(), approval.alternativeProof(), approval.proofAcceptedAt());
        if (!java.security.MessageDigest.isEqual(proof.getBytes(StandardCharsets.US_ASCII),
                approval.expectedF3().getBytes(StandardCharsets.US_ASCII))) throw new PkiException("SDK_PROOF_COMMITMENT_MISMATCH");
    }

    /**
     * Evaluates one existing leaf lifecycle target without proof consumption, signing or staging.
     * @param access authorized caller @param request existing renewal/reissue/replacement input
     * @param parsed exact dual-subject client request @param frozenValidity optional absolute retained bounds
     * @param cancellation cooperative cancellation @return exact immutable lifecycle preview
     * @throws IOException if retained public content cannot be read
     * @throws RuntimeException if operation, predecessor, subject keys or policy is invalid
     */
    public zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdkLifecycle(AccessContext access, Object request,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed, Optional<zeroecho.pki.api.Validity> frozenValidity,
            CancellationSignal cancellation) throws IOException {
        var snapshot = validation.withoutSerialAllocation().lifecyclePreparation().prepareSdk(
                sdkLifecycleAccess(access, request), request, parsed, frozenValidity, true, cancellation);
        return sdkPreview(snapshot.prepared().issuance(), parsed, Optional.of(snapshot.target()));
    }

    /**
     * Evaluates a lifecycle and native enrollment target in one public preview.
     * @param access authorized caller @param request typed lifecycle request @param parsed original request
     * @param frozenValidity absolute bounds @param enrollmentTarget native policy context
     * @param cancellation cancellation @return combined exact target
     * @throws IOException if retained public evidence is unavailable
     */
    public zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdkLifecycle(AccessContext access, Object request,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed, Optional<zeroecho.pki.api.Validity> frozenValidity,
            Optional<zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget> enrollmentTarget,
            CancellationSignal cancellation) throws IOException {
        return enrollmentPreview(previewSdkLifecycle(access, request, parsed, frozenValidity, cancellation), parsed, enrollmentTarget);
    }

    /**
     * Verifies fresh accepted dual proof and actual frozen lifecycle target before any alternative signing.
     * @param access authorized caller @param request restricted existing lifecycle input
     * @param parsed exact client request @param approval retained accepted proof and signed target
     * @param submission fresh signing submission @param ttl configured signing lifetime
     * @param evidence trusted publication evidence @param cancellation cooperative cancellation
     * @return caller-owned final staged lifecycle signing request
     * @throws IOException if public content or staging fails
     * @throws RuntimeException if proof, predecessor, target, status or policy differs
     */
    public DomainSigningRequest prepareSdkLifecycle(AccessContext access, Object request,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed, zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval approval,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        verifySdkProof(parsed, approval);
        var preview = previewSdkLifecycle(access, request, parsed, Optional.of(approval.preview().validity()), approval.preview().enrollmentTarget(), cancellation);
        requireSdkTarget(preview, approval, parsed);
        var actual = lifecycle.prepareSdk(sdkLifecycleAccess(access, request), request, parsed,
                Optional.of(preview.validity()), false, cancellation);
        preview = enrollmentPreview(sdkPreview(actual.prepared().issuance(), parsed, Optional.of(actual.target())), parsed, approval.preview().enrollmentTarget());
        requireSdkTarget(preview, approval, parsed);
        LeafOperation operation = switch (actual.target().operation()) {
            case "credential.renew" -> LeafOperation.RENEW_END_ENTITY;
            case "credential.reissue" -> LeafOperation.REISSUE_END_ENTITY;
            case "credential.replace" -> LeafOperation.REPLACE_END_ENTITY;
            default -> throw new UnsupportedOperationException("Unsupported SDK lifecycle operation");
        };
        return signSdk(actual.prepared().issuance(), parsed, preview, submission, ttl, evidence, cancellation,
                operation, Optional.of(actual.prepared().predecessor().credentialId()));
    }

    private static AccessContext sdkLifecycleAccess(AccessContext access, Object request) {
        PkiId predecessor;
        if (request instanceof EndEntityRenewalRequest value) predecessor = value.existingCredentialId();
        else if (request instanceof EndEntityReissueRequest value) predecessor = value.existingCredentialId();
        else if (request instanceof EndEntityReplacementRequest value) predecessor = value.existingCredentialId();
        else throw new UnsupportedOperationException("Unsupported SDK lifecycle operation");
        return lifecycleAccess(access, predecessor);
    }

    private DomainSigningRequest signSdk(EndEntityIssuancePreparation.Prepared approved,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed, zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview preview,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation, LeafOperation operation, Optional<PkiId> predecessor) throws IOException {
        return signSdk(approved, parsed, preview, submission, ttl, evidence, cancellation, operation, predecessor,
                "issue." + sha256(submission.id().value().getBytes(StandardCharsets.UTF_8)));
    }

    private DomainSigningRequest signSdk(EndEntityIssuancePreparation.Prepared approved,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed, zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview preview,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation, LeafOperation operation, Optional<PkiId> predecessor, String correlation) throws IOException {
        var builder = leafBuilder(approved);
        var issuerAlternative = approved.issuerBinding().alternative().orElseThrow(() -> new PkiException("SDK_ISSUER_NOT_HYBRID"));
        var altAlgorithm = Pkix.parseAlgorithmIdentifier(issuerAlternative.signatureAlgorithmIdentifier().bytes());
        builder.addExtension(zeroecho.pki.impl.hybrid.AltSignatureExtensions.subjectAltPublicKeyInfo(parsed.alternativeSubjectPublicKeyInfo().bytes()))
                .addExtension(zeroecho.pki.impl.hybrid.AltSignatureExtensions.altSignatureAlgorithm(altAlgorithm));
        byte[] transcript = builder.buildAlternativeSignatureTbs(approved.signatureBinding());
        var authority = validation.authority();
        var plan = authority.plan(issuerAlternative.signatureAlgorithm(), issuerAlternative.publicKeyAlgorithm(),
                zeroecho.core.spi.AlgorithmExecutionCapability.Direction.SIGN, Optional.empty(), "explicit",
                zeroecho.pki.spi.crypto.SigningProvider.class);
        authority.authorize(plan, plan.executor(), zeroecho.core.spi.AlgorithmExecutionCapability.Direction.SIGN);
        if (!(plan.executor() instanceof zeroecho.pki.spi.crypto.AltSigningCapability signer)) throw new PkiException("ALT_SIGNING_CAPABILITY_UNAVAILABLE");
        byte[] signature;
        try { signature = signer.sign(issuerAlternative.keyRef(), issuerAlternative.signatureAlgorithm().canonicalForm(), transcript); }
        catch (java.security.GeneralSecurityException failure) { throw new PkiException("ALT_SIGNING_FAILED", failure); }
        var verifier = Pkix.verifier(preview.issuerAlternativeSpki().orElseThrow().bytes(), altAlgorithm);
        try (var output = verifier.contentStream()) { output.write(transcript); }
        if (!verifier.verify(signature)) throw new PkiException("ALT_SIGNATURE_INVALID");
        byte[] completeTbs = builder.addExtension(zeroecho.pki.impl.hybrid.AltSignatureExtensions.altSignatureValue(signature))
                .buildTbs(approved.signatureBinding());
        return stageSdk(approved, submission, ttl, evidence, cancellation, completeTbs, operation, predecessor, correlation);
    }

    private static void requireSdkTarget(zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview preview,
            zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval approval,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed) {
        var target = approval.targetFrame();
        if (target.kind() != 7 || !java.security.MessageDigest.isEqual(
                zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.hash(target.encode()), approval.primaryFrame().field(17))) {
            throw new PkiException("SDK_FROZEN_TARGET_MISMATCH");
        }
        var fields = java.util.Map.ofEntries(
                java.util.Map.entry(1, utf8(preview.lifecycleTarget().map(zeroecho.pki.api.hybrid.sdk.SdkLifecycleTarget::operation).orElse("credential.issue"))),
                java.util.Map.entry(4, utf8(preview.issuerCaId().value())),
                java.util.Map.entry(5, utf8(preview.issuerId().value())),
                java.util.Map.entry(6, utf8(preview.chainPathId().value())),
                java.util.Map.entry(7, utf8("sha512:" + preview.issuerCertificateSha512())),
                java.util.Map.entry(8, preview.primaryIssuerBindingFrame().encode()),
                java.util.Map.entry(9, preview.alternativeIssuerBindingFrame().map(zeroecho.pki.api.hybrid.sdk.HybridSdkFrame::encode)
                        .orElseGet(() -> new byte[0])),
                java.util.Map.entry(10, utf8(preview.profile().profileId())),
                java.util.Map.entry(11, java.nio.ByteBuffer.allocate(Long.BYTES).putLong(preview.profile().profileVersion()).array()),
                java.util.Map.entry(12, utf8("sha256:" + HexFormat.of().formatHex(preview.profile().canonicalSha256()))),
                java.util.Map.entry(13, utf8(preview.bindingSetCommitment())),
                java.util.Map.entry(15, preview.effectiveSubjectValue().encode()),
                java.util.Map.entry(16, preview.disclosurePolicy().encode()),
                java.util.Map.entry(17, preview.targetExtensionValue().encode()));
        preview.lifecycleTarget().ifPresent(lifecycle -> {
            var arguments = zeroecho.pki.api.hybrid.sdk.HybridSdkValue.decode(target.field(2)).objectFields();
            boolean replacement = lifecycle.operation().equals("credential.replace");
            var names = replacement ? java.util.Set.of("existingCredentialId", "requestId", "profileId") : java.util.Set.of("credentialId");
            if (!arguments.keySet().equals(names) || !arguments.get(replacement ? "existingCredentialId" : "credentialId").textValue()
                    .equals(lifecycle.predecessorId().value()) || replacement && (!arguments.get("profileId").textValue().equals(preview.profile().profileId())
                            || !arguments.get("requestId").textValue().equals(parsed.primary().requestId().value()))) {
                throw new PkiException("SDK_FROZEN_TARGET_MISMATCH");
            }
        });
        for (var field : fields.entrySet()) {
            if (!java.security.MessageDigest.isEqual(field.getValue(), target.field(field.getKey()))) {
                throw new PkiException("SDK_FROZEN_TARGET_MISMATCH");
            }
        }
    }
    private static byte[] utf8(String text) { return text.getBytes(StandardCharsets.UTF_8); }

    private static AccessContext lifecycleAccess(AccessContext access, PkiId predecessor) {
        Objects.requireNonNull(access, "access");
        if (access.objectId().filter(value -> !value.equals(predecessor)).isPresent()
                || access.formatId().filter(value -> !value.equals(BcX509CredentialFramework.FORMAT_ID)).isPresent()) {
            throw new IllegalArgumentException("Lifecycle access coordinates conflict with predecessor");
        }
        return new AccessContext(access.principal(), access.purpose(), Optional.of(predecessor),
                Optional.of(BcX509CredentialFramework.FORMAT_ID));
    }

    private DomainSigningRequest stage(EndEntityIssuancePreparation.Prepared approved, SigningSubmissionId submission,
            Duration ttl, Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation,
            LeafOperation operation, Optional<PkiId> predecessor)
            throws IOException {
        String correlation = "issue." + sha256(submission.id().value().getBytes(StandardCharsets.UTF_8));
        return stage(approved, submission, ttl, evidence, cancellation, operation, predecessor, correlation);
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException" })
    private DomainSigningRequest stage(EndEntityIssuancePreparation.Prepared approved, SigningSubmissionId submission,
            Duration ttl, Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation,
            LeafOperation operation, Optional<PkiId> predecessor,
            String correlation) throws IOException {
        validateEvidence(evidence, approved.access(), approved.request().issuerCaId().value(),
                approved.request().profileId());
        return stageSdk(approved, submission, ttl, evidence, cancellation, tbs(approved), operation, predecessor, correlation);
    }

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

    private static byte[] tbs(EndEntityIssuancePreparation.Prepared approved) {
        return leafBuilder(approved).buildTbs(approved.signatureBinding());
    }

    private static CertificateBuilder leafBuilder(EndEntityIssuancePreparation.Prepared approved) {
        ValidatedCertificateRequest request = approved.request();
        CertificateBuilder builder = Pkix.certificateBuilder().serialNumber(approved.serial())
                .issuer(Pkix.parseCertificate(approved.issuerDer()).getSubjectX500Principal())
                .subject(BcX509ProfileSupport.subject(request.subjectRdns()))
                .validity(request.validity().notBefore(), request.validity().notAfter())
                .publicKeyInfo(request.exactPublicKey().bytes())
                .basicConstraints(BasicConstraints.endEntity(), request.basicConstraintsCritical());
        if (!request.keyUsages().isEmpty()) {
            builder.keyUsage(keyUsages(request.keyUsages()), request.keyUsageCritical());
        }
        if (!request.extendedKeyUsages().isEmpty()) {
            builder.extendedKeyUsage(new ExtendedKeyUsage(request.extendedKeyUsages().stream()
                    .map(ExtendedKeyUsageId::oid).sorted().toList()), request.extendedKeyUsageCritical());
        }
        if (!request.subjectAlternativeNames().isEmpty()) {
            builder.subjectAlternativeNames(request.subjectAlternativeNames().stream()
                    .map(EndEntitySigningPreparation::generalName).toList(), request.subjectAlternativeNameCritical());
        }
        return builder;
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
                sha256(request.exactPublicKey().bytes()), frozen.intent().map(IssuanceIntent::issuanceId).orElse(""),
                frozen.intent().map(IssuanceIntent::commandCommitment).orElse(""), request.subjectRdns().toString(),
                request.subjectAlternativeNames().toString(), request.keyUsages().stream().sorted().toList().toString(),
                request.extendedKeyUsages().stream().sorted(java.util.Comparator.comparing(ExtendedKeyUsageId::oid))
                        .toList().toString(),
                request.algorithmBindingPolicy().toString(), DomainAttributeEncoding.encode(request.executionEvidence())));
        predecessor.ifPresent(value -> fields.add(value.value()));
        fields.add(approved.issuerBinding().commitment());
        return DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.ISSUANCE, correlation,
                operation.name(), fields.toArray(String[]::new));
    }

    /** Leaf workflow discriminator retained in the accepted signing metadata. */
    private enum LeafOperation { ISSUE_END_ENTITY, RENEW_END_ENTITY, REPLACE_END_ENTITY, REISSUE_END_ENTITY }

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

    private static Set<KeyUsage> keyUsages(Set<LeafKeyUsage> source) {
        Set<KeyUsage> result = EnumSet.noneOf(KeyUsage.class);
        for (LeafKeyUsage usage : source) {
            result.add(switch (usage) {
                case DIGITAL_SIGNATURE -> KeyUsage.DIGITAL_SIGNATURE;
                case CONTENT_COMMITMENT -> KeyUsage.NON_REPUDIATION;
                case KEY_ENCIPHERMENT -> KeyUsage.KEY_ENCIPHERMENT;
                case DATA_ENCIPHERMENT -> KeyUsage.DATA_ENCIPHERMENT;
                case KEY_AGREEMENT -> KeyUsage.KEY_AGREEMENT;
                case ENCIPHER_ONLY -> KeyUsage.ENCIPHER_ONLY;
                case DECIPHER_ONLY -> KeyUsage.DECIPHER_ONLY;
            });
        }
        return result;
    }

    private static GeneralName generalName(SubjectAlternativeName name) {
        return switch (name) {
            case SubjectAlternativeName.DnsName dns -> new GeneralName.DnsName(dns.value());
            case SubjectAlternativeName.Rfc822Name email -> new GeneralName.Rfc822Name(email.value());
            case SubjectAlternativeName.UriName uri -> new GeneralName.UniformResourceIdentifier(uri.value());
            case SubjectAlternativeName.IpAddress ip -> new GeneralName.IpAddress(ipLiteral(ip.bytes()));
        };
    }

    private static String ipLiteral(byte[] octets) {
        try {
            return InetAddress.getByAddress(octets).getHostAddress();
        } catch (UnknownHostException impossible) {
            throw new IllegalArgumentException("Invalid validated IP address length", impossible);
        }
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }
}
