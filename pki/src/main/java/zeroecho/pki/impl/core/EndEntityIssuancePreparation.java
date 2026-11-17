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

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.ca.IssuerCryptographicBinding;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.hybrid.HybridCertificateMode;
import zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest;
import zeroecho.pki.api.issuance.ManagedOcspProvisioningIdentity;
import zeroecho.pki.api.issuance.ManagedOcspResponderIssuanceRequest;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.DomainContinuationValidation;
import zeroecho.pki.impl.core.continuation.OcspResponderCertificateCommand;
import zeroecho.pki.impl.hybrid.AltSignatureExtensions;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore;

import zeroecho.pki.api.EncodedObject;

import zeroecho.pki.api.request.X509EnrollmentPayload;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiFailureReason;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialUse;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.issuance.EndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;
import zeroecho.pki.api.issuance.IssuanceIntent;
import zeroecho.pki.api.issuance.VerificationPolicy;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.ProofOfPossessionResult;
import zeroecho.pki.api.request.ProofOfPossessionStatus;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509SecurityFloor;
import zeroecho.pki.impl.framework.x509.bc.BcX509CertificationRequestParser;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.impl.framework.x509.bc.BcX509ProofOfPossessionVerifier;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.Pkix;

/**
 * Read-only end-entity preparation gate. Each invocation captures one evaluation
 * time and returns frozen construction inputs after mandatory cryptographic PoP
 * and deny-by-default policy checks. No signing or content staging is reachable.
 * Local work and payload memory are O(C + I), for bounded CSR and issuer DER,
 * plus cryptographic verification and a bounded number of authoritative lookups.
 */
final class EndEntityIssuancePreparation {
    private static final String OCSP_PREDECESSOR_INVALID = "OCSP_PREDECESSOR_PROVENANCE_INVALID";
    private final PkiStore store;
    private final EffectiveCredentialStatusResolver status;
    private final X509AuthoritySnapshot authority;
    private final Optional<PublicKeyInfoSource> managedKeys;
    private final X509AuthoritySnapshot signingAuthority;
    private final BcX509ProofOfPossessionVerifier proofVerifier;
    private final X509ProfileBindingMatcher bindingMatcher;
    private final AlgorithmIdentity signature;
    private final Supplier<BigInteger> serialSource;

    /**
     * Creates a preparer borrowing authoritative store and validation collaborators.
     *
     * <p>The caller retains collaborator lifecycle ownership; construction does not submit
     * a signing request or publish a credential.</p>
     *
     * @param store borrowed PKI store; must not be null
     * @param clock authoritative session clock; must not be null
     * @param authority frozen X.509 authority snapshot; must not be null
     * @param verifier borrowed X.509 signature verification executor; must not be null
     * @param bindings immutable X.509 algorithm binding registry; must not be null
     * @param signatureAlgorithm canonical permitted signature algorithm identity
     * @throws NullPointerException if a required collaborator is null
     * @throws IllegalArgumentException if configured algorithm or binding selection is invalid
     */
    /* default */ EndEntityIssuancePreparation(PkiStore store, Clock clock, X509AuthoritySnapshot authority,
            BcX509VerificationExecutor verifier, X509AlgorithmBindingRegistry bindings, String signatureAlgorithm) {
        this(store, clock, authority, verifier, bindings, signatureAlgorithm, authority, Optional.empty());
    }

    /**
     * Creates a preparer borrowing authoritative store and validation collaborators.
     *
     * <p>The caller retains collaborator lifecycle ownership; construction does not submit
     * a signing request or publish a credential.</p>
     *
     * @param store borrowed PKI store; must not be null
     * @param clock authoritative session clock; must not be null
     * @param authority frozen X.509 authority snapshot; must not be null
     * @param verifier borrowed X.509 signature verification executor; must not be null
     * @param bindings immutable X.509 algorithm binding registry; must not be null
     * @param signatureAlgorithm canonical permitted signature algorithm identity
     * @param signingAuthority frozen signing authority snapshot; must not be null
     * @param managedKeys optional borrowed managed public-key source; container must not be null
     * @throws NullPointerException if a required collaborator is null
     * @throws IllegalArgumentException if configured algorithm or binding selection is invalid
     */
    /* default */ EndEntityIssuancePreparation(PkiStore store, Clock clock, X509AuthoritySnapshot authority,
            BcX509VerificationExecutor verifier, X509AlgorithmBindingRegistry bindings, String signatureAlgorithm,
            X509AuthoritySnapshot signingAuthority, Optional<PublicKeyInfoSource> managedKeys) {
        this.signingAuthority = Objects.requireNonNull(signingAuthority, "signingAuthority");
        this.managedKeys = Objects.requireNonNull(managedKeys, "managedKeys");
        this.serialSource = CertificateSerialAllocator::allocate;
        this.store = Objects.requireNonNull(store, "store");
        this.status = new StoreBackedEffectiveCredentialStatusResolver(store, clock);
        this.authority = Objects.requireNonNull(authority, "authority");
        this.proofVerifier = new BcX509ProofOfPossessionVerifier(authority, verifier);
        this.bindingMatcher = new X509ProfileBindingMatcher(authority, bindings);
        this.signature = authority.resolveIdentity(signatureAlgorithm);
        if (!signature.canonicalForm().equals(signatureAlgorithm)
                || signature.kind() != AlgorithmIdentity.Kind.SIGNATURE) {
            throw new IllegalArgumentException("Configured signing algorithm must be a canonical signature identity");
        }
        X509SecurityFloor.requirePermitted(signature);
    }

    private EndEntityIssuancePreparation(EndEntityIssuancePreparation source) {
        store = source.store; status = source.status; authority = source.authority;
        managedKeys = source.managedKeys; signingAuthority = source.signingAuthority;
        proofVerifier = source.proofVerifier; bindingMatcher = source.bindingMatcher; signature = source.signature;
        serialSource = () -> BigInteger.ONE;
    }

    /**
     * Creates a preview preparer using serial one instead of allocating a production serial.
     *
     * @return preparer sharing authoritative validation collaborators with serial allocation disabled
     */
    /* default */ EndEntityIssuancePreparation withoutSerialAllocation() {
        return new EndEntityIssuancePreparation(this);
    }

    /**
     * Creates a lifecycle preparer sharing this issuance validation and status resolver.
     *
     * @return new lifecycle preparer borrowing the same authoritative collaborators
     */
    /* default */ EndEntityLifecyclePreparation lifecyclePreparation() {
        return new EndEntityLifecyclePreparation(store, status, authority, this);
    }

    /**
     * Verifies enrollment proof and freezes an issuance candidate against current authority policy.
     *
     * @param access authenticated operation access context; must not be null
     * @param input bounded end-entity enrollment input; must not be null
     * @param cancellation cooperative cancellation signal; must not be null
     * @return validated bounded issuance inputs with a selected serial and issuer binding
     * @throws IOException if enrollment processing, issuer content access, or cancellation fails
     * @throws PkiException if proof, profile, issuer, or issuance-intent checks fail
     */
    /* default */ Prepared prepare(AccessContext access, EndEntityIssuanceRequest input, CancellationSignal cancellation)
            throws IOException {
        return prepare(access, input, Optional.empty(), cancellation);
    }

    /**
     * Verifies enrollment proof and freezes an issuance candidate against current authority policy.
     *
     * @param access authenticated operation access context; must not be null
     * @param input bounded end-entity enrollment input; must not be null
     * @param intent optional frozen caller idempotency intent; container must not be null
     * @param cancellation cooperative cancellation signal; must not be null
     * @return validated bounded issuance inputs with a selected serial and issuer binding
     * @throws IOException if enrollment processing, issuer content access, or cancellation fails
     * @throws PkiException if proof, profile, issuer, or issuance-intent checks fail
     * @throws NullPointerException if access, input, cancellation is null
     */
    /* default */ Prepared prepare(AccessContext access, EndEntityIssuanceRequest input, Optional<IssuanceIntent> intent,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        EffectiveCredentialStatusResolver.Evaluation evaluation = status.beginEvaluation();
        X509EnrollmentPayload payload = input.payload();
        VerifiedIssuanceCandidate candidate = verifyRequest(input.issuerCaId(), payload, input.profileId(),
                input.validityOverride(), cancellation);
        return prepareCandidate(access, candidate, evaluation, Optional.of(payload), intent, cancellation);
    }

    /**
     * Parses and verifies a PKCS#10 request before it may enter profile validation.
     *
     * @param issuerCaId logical issuing authority identity; must not be null
     * @param csrDer bounded DER PKCS#10 request bytes; must not be null
     * @param profileId requested certificate profile identity
     * @param validityOverride optional requested validity interval; container must not be null
     * @param cancellation cooperative cancellation signal; must not be null
     * @return defensive verified candidate bound to the requested issuer, profile, and validity
     * @throws IOException if parsing, proof verification, or cancellation fails
     * @throws PkiException if proof of possession is not verified
     */
    /* default */ VerifiedIssuanceCandidate verifyCsr(PkiId issuerCaId, byte[] csrDer, String profileId,
            Optional<Validity> validityOverride, CancellationSignal cancellation) throws IOException {
        return verifyRequest(issuerCaId, new X509EnrollmentPayload(
                X509EnrollmentPayload.Kind.PKCS10, csrDer), profileId, validityOverride, cancellation);
    }

    /**
     * Parses and verifies the supplied enrollment payload before profile validation.
     *
     * @param issuerCaId logical issuing authority identity; must not be null
     * @param payload bounded PKCS#10 or CRMF enrollment payload; must not be null
     * @param profileId requested certificate profile identity
     * @param validityOverride optional requested validity interval; container must not be null
     * @param cancellation cooperative cancellation signal; must not be null
     * @return defensive verified candidate bound to the requested issuer, profile, and validity
     * @throws IOException if parsing, proof verification, or cancellation fails
     * @throws PkiException if proof of possession is not verified
     */
    /* default */ VerifiedIssuanceCandidate verifyRequest(PkiId issuerCaId,
            X509EnrollmentPayload payload, String profileId,
            Optional<Validity> validityOverride, CancellationSignal cancellation) throws IOException {
        ParsedCertificationRequest parsed = new BcX509CertificationRequestParser().parseX509(payload);
        ProofOfPossessionResult proof = proofVerifier.verify(parsed, new VerificationPolicy(true, Optional.empty()));
        if (proof.status() != ProofOfPossessionStatus.VERIFIED) {
            throw new PkiException("End-entity preparation rejected: code=CSR_PROOF_INVALID");
        }
        cancellation.throwIfCancelled();
        return new VerifiedIssuanceCandidate(parsed, parsed.requestId(),
                parsed.publicKeyInfo(), proof.status(), new IssueEndEntityCommand(issuerCaId, parsed,
                        profileId, validityOverride));
    }

    /**
     * Validates a proven subject against current issuer state, exact profile, and optional frozen intent.
     *
     * @param access authenticated operation access context; must not be null
     * @param candidate cryptographically verified issuance candidate; must not be null
     * @param evaluation frozen authoritative status evaluation shared by this preparation
     * @param csrDer original enrollment payload when present; container must not be null
     * @param cancellation cooperative cancellation signal; must not be null
     * @return frozen bounded inputs for TBS construction; no signature is emitted here
     * @throws IOException if authoritative content access or cancellation fails
     * @throws PkiException if issuer, profile, key, validity, or intent selection is invalid
     */
    /* default */ Prepared prepareCandidate(AccessContext access, VerifiedIssuanceCandidate candidate,
            EffectiveCredentialStatusResolver.Evaluation evaluation, Optional<X509EnrollmentPayload> csrDer,
            CancellationSignal cancellation) throws IOException {
        return prepareCandidate(access, candidate, evaluation, csrDer, Optional.empty(), cancellation);
    }

    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    /**
     * Validates a proven subject against current issuer state, exact profile, and optional frozen intent.
     *
     * @param access authenticated operation access context; must not be null
     * @param candidate cryptographically verified issuance candidate; must not be null
     * @param evaluation frozen authoritative status evaluation shared by this preparation
     * @param csrDer original enrollment payload when present; container must not be null
     * @param intent optional frozen caller idempotency intent; container must not be null
     * @param cancellation cooperative cancellation signal; must not be null
     * @return frozen bounded inputs for TBS construction; no signature is emitted here
     * @throws IOException if authoritative content access or cancellation fails
     * @throws PkiException if issuer, profile, key, validity, or intent selection is invalid
     */
    /* default */ Prepared prepareCandidate(AccessContext access, VerifiedIssuanceCandidate candidate,
            EffectiveCredentialStatusResolver.Evaluation evaluation, Optional<X509EnrollmentPayload> csrDer,
            Optional<IssuanceIntent> intent, CancellationSignal cancellation) throws IOException {
        return prepareCandidate(access, candidate, evaluation, csrDer, intent, Optional.empty(), false, cancellation);
    }

    /**
     * Validates a proven subject against current issuer state, exact profile, and optional frozen intent.
     *
     * @param access authenticated operation access context; must not be null
     * @param candidate cryptographically verified issuance candidate; must not be null
     * @param evaluation frozen authoritative status evaluation shared by this preparation
     * @param csrDer original enrollment payload when present; container must not be null
     * @param intent optional frozen caller idempotency intent; container must not be null
     * @param frozenValidity optional previously frozen validity; container must not be null
     * @param sdk whether validation uses the hybrid SDK issuance path
     * @param cancellation cooperative cancellation signal; must not be null
     * @return frozen bounded inputs for TBS construction; no signature is emitted here
     * @throws IOException if authoritative content access or cancellation fails
     * @throws PkiException if issuer, profile, key, validity, or intent selection is invalid
     */
    /* default */ Prepared prepareCandidate(AccessContext access, VerifiedIssuanceCandidate candidate,
            EffectiveCredentialStatusResolver.Evaluation evaluation, Optional<X509EnrollmentPayload> csrDer,
            Optional<IssuanceIntent> intent, Optional<Validity> frozenValidity, boolean sdk,
            CancellationSignal cancellation) throws IOException {
        CaRecord ca = store.getCa(candidate.issuerCaId()).orElseThrow(
                () -> new PkiException("Issuer CA not found", PkiFailureReason.ISSUER_CA_NOT_FOUND));
        if (!ca.caId().equals(candidate.issuerCaId()) || ca.state() != CaState.ACTIVE) {
            throw new PkiException("Issuer CA is not active", PkiFailureReason.ISSUER_CA_NOT_ACTIVE);
        }
        IssuerGeneration generation = IssuerAuthorities.current(store, ca);
        IssuerCryptographicBinding issuerBinding = store.getIssuerCryptographicBinding(generation.issuerId())
                .orElseThrow(() -> new PkiException("Issuer binding unavailable: code=ISSUER_BINDING_MISSING"));
        AlgorithmIdentity signature = issuerBinding.primary().signatureAlgorithm();
        X509SecurityFloor.requirePermitted(signature);
        IssuerChainPath path = IssuerAuthorities.issuancePath(store, ca);
        if (intent.isPresent()) {
            EndEntityIssuerBinding.requireSelectedIssuance(intent.orElseThrow(), generation, path);
        }
        Credential issuer = store.getCredential(generation.credentialId()).orElseThrow(
                () -> new PkiException("Issuer credential not found", PkiFailureReason.ISSUER_CREDENTIAL_NOT_FOUND));
        EndEntityIssuerBinding.requireConsistentIssuer(ca, generation, path, issuer);
        evaluation.requireUsable(issuer, CredentialUse.END_ENTITY_ISSUER);
        ActiveCertificateProfile profile = selectProfile(candidate.profileId(), intent);
        if (!profile.reference().profileId().equals(candidate.profileId())
                || profile.definition().certificateType() != CertificateProfileKind.END_ENTITY
                || !BcX509CredentialFramework.FORMAT_ID.equals(profile.definition().formatId())) {
            throw new PkiException("End-entity preparation rejected: code=PROFILE_KIND_MISMATCH");
        }
        boolean requestAlternative = profile.definition().hybridMode() instanceof HybridCertificateMode.AltSignature;
        if (requestAlternative != sdk) { throw new PkiException("SDK dual proof required: code=SDK_PROFILE_REQUIRED"); }
        if (sdk) {
            HybridCertificateMode.AltSignature mode = (HybridCertificateMode.AltSignature) profile.definition().hybridMode();
            if (mode.subjectKeySource() != HybridCertificateMode.AlternativeSubjectKeySource.REQUEST) {
                throw new PkiException("SDK_REQUEST_OWNED_PROFILE_REQUIRED");
            }
            IssuerKeyBinding alternative = issuerBinding.alternative().orElseThrow(() -> new PkiException("SDK_ISSUER_NOT_HYBRID"));
            if (!alternative.signatureAlgorithm().equals(authority.resolveIdentity(mode.altSignatureAlgorithmId()))) {
                throw new PkiException("SDK_ALTERNATIVE_ISSUER_ALGORITHM_DIFFERS");
            }
        }
        ValidatedCertificateRequest validated = csrDer.isPresent()
                ? CertificateProfileValidator.validateFrozen(candidate, profile.profile(), profile.reference(), issuer,
                        evaluation.evaluationTime(), authority, frozenValidity)
                : CertificateProfileValidator.validateReconstructed(candidate, profile.profile(), profile.reference(), issuer,
                        evaluation.evaluationTime(), authority);
        ValidatedCertificateRequest approved = validated.withFrozenIssuance(
                generation.issuerId(), path.pathId(), path.pathCommitment(), intent);
        byte[] issuerDer = CredentialContent.materializeForBc(store, issuer.content());
        AlgorithmIdentifier signingBinding = new EndEntityIssuerBinding(store, managedKeys, authority, bindingMatcher)
                .select(issuerDer, issuer, evaluation.evaluationTime(), signature, generation, issuerBinding, approved, csrDer, candidate);
        cancellation.throwIfCancelled();
        return new Prepared(access, approved, generation.signingKeyRef(), signature, signingBinding,
                serialSource.get(), evaluation.evaluationTime(), issuerDer, issuer.content(), issuerBinding, profile);
    }

    /**
     * Reparses hybrid enrollment evidence and freezes matching SDK issuance inputs.
     *
     * <p>Preview mode selects the serial-free preparer. Supplied primary and alternative
     * keys must match the keys parsed from the original payload.</p>
     *
     * @param access authenticated operation access context; must not be null
     * @param input bounded end-entity enrollment input; must not be null
     * @param supplied previously parsed hybrid SDK request, checked against the original payload
     * @param frozenValidity optional previously frozen validity; container must not be null
     * @param preview whether to avoid serial allocation for a preview
     * @param cancellation cooperative cancellation signal; must not be null
     * @return validated frozen hybrid SDK issuance inputs
     * @throws IOException if request processing, public-key export, issuer access, or cancellation fails
     * @throws PkiException if managed keys are unavailable or the request, profile, or policy differs
     */
    /* default */ Prepared prepareSdk(AccessContext access, EndEntityIssuanceRequest input,
            ParsedHybridSdkRequest supplied,
            Optional<Validity> frozenValidity, boolean preview,
            CancellationSignal cancellation) throws IOException {
        return prepareSdk(access, input, supplied, frozenValidity, preview, status.beginEvaluation(), cancellation);
    }

    /**
     * Reparses hybrid enrollment evidence and freezes matching SDK issuance inputs.
     *
     * <p>Preview mode selects the serial-free preparer. Supplied primary and alternative
     * keys must match the keys parsed from the original payload.</p>
     *
     * @param access authenticated operation access context; must not be null
     * @param input bounded end-entity enrollment input; must not be null
     * @param supplied previously parsed hybrid SDK request, checked against the original payload
     * @param frozenValidity optional previously frozen validity; container must not be null
     * @param preview whether to avoid serial allocation for a preview
     * @param evaluation frozen authoritative status evaluation shared by this preparation
     * @param cancellation cooperative cancellation signal; must not be null
     * @return validated frozen hybrid SDK issuance inputs
     * @throws IOException if request processing, public-key export, issuer access, or cancellation fails
     * @throws PkiException if managed keys are unavailable or the request, profile, or policy differs
     */
    /* default */ Prepared prepareSdk(AccessContext access, EndEntityIssuanceRequest input,
            ParsedHybridSdkRequest supplied,
            Optional<Validity> frozenValidity, boolean preview,
            EffectiveCredentialStatusResolver.Evaluation evaluation, CancellationSignal cancellation) throws IOException {
        return prepareSdk(access, input, supplied, frozenValidity, preview, evaluation, Optional.empty(), cancellation);
    }

    /**
     * Reparses hybrid enrollment evidence and freezes matching SDK issuance inputs.
     *
     * <p>Preview mode selects the serial-free preparer. Supplied primary and alternative
     * keys must match the keys parsed from the original payload.</p>
     *
     * @param access authenticated operation access context; must not be null
     * @param input bounded end-entity enrollment input; must not be null
     * @param supplied previously parsed hybrid SDK request, checked against the original payload
     * @param frozenValidity optional previously frozen validity; container must not be null
     * @param preview whether to avoid serial allocation for a preview
     * @param evaluation frozen authoritative status evaluation shared by this preparation
     * @param intent optional frozen caller idempotency intent; container must not be null
     * @param cancellation cooperative cancellation signal; must not be null
     * @return validated frozen hybrid SDK issuance inputs
     * @throws IOException if request processing, public-key export, issuer access, or cancellation fails
     * @throws PkiException if managed keys are unavailable or the request, profile, or policy differs
     */
    /* default */ Prepared prepareSdk(AccessContext access, EndEntityIssuanceRequest input,
            ParsedHybridSdkRequest supplied,
            Optional<Validity> frozenValidity, boolean preview,
            EffectiveCredentialStatusResolver.Evaluation evaluation, Optional<IssuanceIntent> intent,
            CancellationSignal cancellation) throws IOException {
        if (managedKeys.isEmpty()) { throw new PkiException("SDK_MANAGED_PUBLIC_KEY_SOURCE_REQUIRED"); }
        if (input.payload().kind() != supplied.originalPayload().kind()
                || !Arrays.equals(input.payload().der(), supplied.originalPayload().der())) {
            throw new PkiException("SDK_REQUEST_MISMATCH");
        }
        ParsedHybridSdkRequest parsed = new BcX509CertificationRequestParser().parseHybridSdk(input.payload());
        if (!Arrays.equals(parsed.primary().publicKeyInfo().bytes(), supplied.primary().publicKeyInfo().bytes())
                || !Arrays.equals(parsed.alternativeSubjectPublicKeyInfo().bytes(), supplied.alternativeSubjectPublicKeyInfo().bytes())) {
            throw new PkiException("SDK_REQUEST_MISMATCH");
        }
        VerifiedIssuanceCandidate candidate = new VerifiedIssuanceCandidate(parsed.primary(), parsed.primary().requestId(),
                parsed.primary().publicKeyInfo(), ProofOfPossessionStatus.VERIFIED,
                new IssueEndEntityCommand(input.issuerCaId(), parsed.primary(), input.profileId(), input.validityOverride()));
        EndEntityIssuancePreparation selected = preview ? withoutSerialAllocation() : this;
        return selected.prepareCandidate(access, candidate, evaluation, Optional.of(input.payload()),
                intent, frozenValidity, true, cancellation);
    }

    /**
     * Resolves and validates the managed responder key pair and frozen issuance intent.
     *
     * @param request managed OCSP responder issuance request with its exact frozen target
     * @param cancellation cooperative cancellation signal; must not be null
     * @return validated primary/alternative keys, core slot, revision, and intent
     * @throws IOException if managed public-key export or cancellation fails
     * @throws PkiException if the key suite, profile, or frozen target does not match
     */
    /* default */ ManagedOcspSelection managedOcspSelection(ManagedOcspResponderIssuanceRequest request,
            CancellationSignal cancellation) throws IOException {
        return new ManagedOcspPreparation().managedOcspSelection(request, cancellation);
    }

    /**
     * Validates managed responder issuance and freezes its issuer and subject-key bindings.
     *
     * @param access authenticated operation access context; must not be null
     * @param request managed responder issuance request
     * @param selected previously validated managed responder key and intent selection
     * @param cancellation cooperative cancellation signal; must not be null
     * @return bounded managed responder issuance inputs for TBS construction
     * @throws IOException if authoritative content access or cancellation fails
     * @throws PkiException if the frozen selection or responder policy is invalid
     */
    /* default */ Prepared prepareManagedOcsp(AccessContext access,
            ManagedOcspResponderIssuanceRequest request, ManagedOcspSelection selected,
            CancellationSignal cancellation) throws IOException {
        return new ManagedOcspPreparation().prepareManagedOcsp(access, request, selected, cancellation);
    }

    // Mutable inventory attributes alone cannot authorize another issuance revision.

    /**
     * Frozen managed responder keys and exact authoritative issuance selection.
     *
     * @param primarySpki resolved primary subject public-key information
     * @param alternativeSpki resolved alternative subject public-key information
     * @param primary validated primary subject key binding
     * @param alternative validated alternative subject key binding
     * @param coreSlotId selected core key slot identity
     * @param revision frozen authoritative target revision
     * @param intent frozen effective issuance intent
     */
    /* default */ record ManagedOcspSelection(EncodedObject primarySpki, EncodedObject alternativeSpki,
            IssuerKeyBinding primary, IssuerKeyBinding alternative,
            String coreSlotId, long revision, IssuanceIntent intent) { }

    /**
     * Begins one authoritative status evaluation for a hybrid SDK operation.
     *
     * @return evaluation capturing the authoritative time for subsequent policy checks
     */
    /* default */ EffectiveCredentialStatusResolver.Evaluation beginSdkEvaluation() { return status.beginEvaluation(); }

    /**
     * Returns the signing authority used to resolve SDK signature bindings.
     *
     * @return borrowed immutable signing authority snapshot
     */
    /* default */ X509AuthoritySnapshot authority() { return signingAuthority; }

    private ActiveCertificateProfile selectProfile(String profileId, Optional<IssuanceIntent> intent) {
        if (intent.isEmpty()) {
            return store.requireActiveProfile(profileId);
        }
        CertificateProfileRef expected = intent.orElseThrow().expectedProfile();
        ImportedCertificateProfileVersion imported = store.getProfileVersion(profileId, expected.profileVersion())
                .orElseThrow(() -> new PkiException("Correlated issuance rejected: code=FROZEN_PROFILE_UNAVAILABLE"));
        if (!expected.profileId().equals(profileId) || !expected.equals(imported.reference())) {
            throw new PkiException("Correlated issuance rejected: code=FROZEN_PROFILE_MISMATCH");
        }
        // Reuse the validated definition projection, without consulting the active pointer.
        try {
            return new ActiveCertificateProfile(imported.reference(), imported.definition());
        } catch (IllegalArgumentException invalid) {
            throw new PkiException("Correlated issuance rejected: code=FROZEN_PROFILE_MISMATCH", invalid);
        }
    }

    private AlgorithmIdentifier selectBinding(AlgorithmIdentity algorithm, X509AlgorithmBinding.Role role,
            Optional<X509AlgorithmBindingPolicy.BindingReference> reference) {
        return bindingMatcher.select(algorithm, role, reference);
    }

    private void requireRequestBinding(AlgorithmIdentifier actual, X509AlgorithmBinding.Role role,
            Optional<X509AlgorithmBindingPolicy.BindingReference> reference) {
        bindingMatcher.require(actual, role, reference);
    }

    /**
     * Frozen, bounded inputs for the subsequent TBS construction step.
     * @param access authenticated operation access context; must not be null
     * @param request gate-approved end-entity request
     * @param keyRef selected issuer signing key reference
     * @param signature canonical selected signature identity
     * @param signatureBinding selected native signature AlgorithmIdentifier
     * @param serial selected positive certificate serial number
     * @param evaluationTime frozen authoritative evaluation instant
     * @param issuerDer issuer certificate DER, cloned on construction and access
     * @param issuerContent durable issuer certificate reference
     * @param issuerBinding frozen issuer cryptographic binding
     * @param profile selected active certificate profile
     */
    /* default */ record Prepared(AccessContext access, ValidatedCertificateRequest request, KeyRef keyRef,
            AlgorithmIdentity signature, AlgorithmIdentifier signatureBinding, BigInteger serial,
            Instant evaluationTime, byte[] issuerDer, DurableContentReference issuerContent,
            IssuerCryptographicBinding issuerBinding, ActiveCertificateProfile profile) {
        /**
         * Retains frozen issuance inputs and takes a defensive copy of issuer certificate DER.
         *
         * @param access authenticated operation access context; must not be null
         * @param request gate-approved end-entity request
         * @param keyRef selected issuer signing key reference
         * @param signature canonical selected signature identity
         * @param signatureBinding selected native signature AlgorithmIdentifier
         * @param serial selected positive certificate serial number
         * @param evaluationTime frozen authoritative evaluation instant
         * @param issuerDer issuer certificate DER, cloned on construction and access
         * @param issuerContent durable issuer certificate reference
         * @param issuerBinding frozen issuer cryptographic binding
         * @param profile selected active certificate profile
         * @throws NullPointerException if issuerDer is null
         */
        Prepared { issuerDer = issuerDer.clone(); }
        /**
         * Returns an independent copy of the frozen issuer certificate DER.
         *
         * @return issuer certificate bytes owned by the caller
         */
        @Override public byte[] issuerDer() { return issuerDer.clone(); }
        /**
         * {@inheritDoc}
         */
        @Override public String toString() { return "PreparedEndEntityIssuance[redacted]"; }
    }

    /** Validates the frozen managed-responder selection and predecessor evidence. */
    private final class ManagedOcspPreparation {
        private ManagedOcspSelection managedOcspSelection(ManagedOcspResponderIssuanceRequest request,
                CancellationSignal cancellation) throws IOException {
            cancellation.throwIfCancelled();
            PublicKeyInfoSource keys = managedKeys.orElseThrow(() -> new PkiException("MANAGED_PUBLIC_KEY_SOURCE_REQUIRED"));
            EncodedObject primarySpki = keys.resolvePublicKeyInfo(request.primaryKeyRef());
            EncodedObject alternativeSpki = keys.resolvePublicKeyInfo(request.alternativeKeyRef());
            IssuerKeyBinding primary = IssuerBindingResolver.createKey(request.primaryKeyRef(), BootstrapAlgorithmIdentities.ECDSA_SHA384,
                    primarySpki.bytes(), keys, signingAuthority);
            IssuerKeyBinding alternative = IssuerBindingResolver.createKey(request.alternativeKeyRef(), BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE,
                    alternativeSpki.bytes(), keys, signingAuthority);
            AlgorithmIdentifier primaryAlgorithm = Pkix.subjectPublicKeyAlgorithm(primarySpki.bytes());
            if (!"1.2.840.10045.2.1".equals(primaryAlgorithm.oid())
                    || !Arrays.equals(primaryAlgorithm.parameters(), HexFormat.of().parseHex("06052b81040022"))
                    || !BootstrapAlgorithmIdentities.ML_DSA_87_PUBLIC_KEY.equals(alternative.publicKeyAlgorithm())) {
                throw new PkiException("OCSP_RESPONDER_SUBJECT_SUITE_INVALID");
            }
            if (primary.subjectSpkiSha256().equals(alternative.subjectSpkiSha256())) { throw new PkiException("OCSP_RESPONDER_KEYS_DIFFER"); }
            ImportedCertificateProfileVersion imported = store.getProfileVersion(request.intent().expectedProfile().profileId(), request.intent().expectedProfile().profileVersion())
                    .orElseThrow(() -> new PkiException("FROZEN_PROFILE_UNAVAILABLE"));
            if (!imported.reference().equals(request.intent().expectedProfile()) || !imported.definition().isManagedOcspResponderProfile()) {
                throw new PkiException("MANAGED_OCSP_PROFILE_REQUIRED");
            }
            HybridCertificateMode.AltSignature mode = (HybridCertificateMode.AltSignature) imported.definition().hybridMode();
            EncodedObject profileAlternative = keys.resolvePublicKeyInfo(new KeyRef(mode.altKeyRef()));
            if (!Arrays.equals(profileAlternative.bytes(), alternativeSpki.bytes())
                    || !signingAuthority.resolveIdentity(mode.altSignatureAlgorithmId()).equals(alternative.signatureAlgorithm())) {
                throw new PkiException("OCSP_PROFILE_SUBJECT_BINDING_DIFFERS");
            }
            IssuerGeneration generation = store.getIssuerGeneration(request.intent().expectedIssuerId()).orElseThrow();
            IssuerChainPath path = store.getIssuerChainPath(request.intent().expectedChainPathId()).orElseThrow();
            requireSelectedIssuer(request, generation, path);
            requireUnusedCaKeys(request, primary, alternative);
        String slot = ManagedOcspProvisioningIdentity.coreSlotId(request.authorityId(), generation.issuerId(), primarySpki, alternativeSpki);
            long revision = 1;
            if (request.expectedPredecessorCredentialId().isPresent()) {
                Credential predecessor = store.getCredential(request.expectedPredecessorCredentialId().orElseThrow()).orElseThrow();
                String priorSlot = EndEntityIssuerBinding.managedAttribute(predecessor, "urn:zeroecho:pki:ocsp-provision-core-slot:v1");
                String priorRevision = EndEntityIssuerBinding.managedAttribute(predecessor, "urn:zeroecho:pki:ocsp-provision-revision:v1");
                if (!slot.equals(priorSlot) || !priorRevision.matches("[1-9][0-9]{0,18}")) { throw new PkiException("OCSP_PREDECESSOR_SLOT_DIFFERS"); }
                long previous = Long.parseLong(priorRevision);
                requireManagedOcspPredecessor(predecessor, request.authorityId(), generation, slot, previous,
                        primary.subjectSpkiSha256(), alternative.subjectSpkiSha256());
                revision = Math.addExact(previous, 1);
            }
            List<String> fields = new ArrayList<>(List.of(request.authorityId().value(), generation.issuerId().value(), path.pathId().value(),
                    path.pathCommitment(), imported.reference().profileId(), Long.toString(imported.reference().profileVersion()),
                    HexFormat.of().formatHex(imported.reference().canonicalSha256()),
                    OcspResponderCertificateCommand.encodeSubject(request.subject()),
                    request.validity().notBefore().toString(), request.validity().notAfter().toString(),
                    primary.publicKeyAlgorithm().canonicalForm(), primary.signatureAlgorithm().canonicalForm(), primary.subjectSpkiSha256(),
                    HexFormat.of().formatHex(primary.signatureAlgorithmIdentifier().bytes()),
                    alternative.publicKeyAlgorithm().canonicalForm(), alternative.signatureAlgorithm().canonicalForm(), alternative.subjectSpkiSha256(),
                    HexFormat.of().formatHex(alternative.signatureAlgorithmIdentifier().bytes()),
                    request.expectedPredecessorCredentialId().map(PkiId::value).orElse("")));
            String target = SigningProvider.ContentCommitment.sha256(
                    DomainCommandEncoding.template(DomainContinuationStore.Kind.ISSUANCE,
                            "MANAGED_OCSP_PROVISION_TARGET_V1", fields.toArray(String[]::new)).command().bytes()).sha256();
            String issuance = ManagedOcspProvisioningIdentity.coreIssuanceId(slot, revision);
            IssuanceIntent intent = new IssuanceIntent(issuance, target, imported.reference(), generation.issuerId(), path.pathId(), path.pathCommitment());
            return new ManagedOcspSelection(primarySpki, alternativeSpki, primary, alternative, slot, revision, intent);
        }

        private Prepared prepareManagedOcsp(AccessContext access,
                ManagedOcspResponderIssuanceRequest request, ManagedOcspSelection selected,
                CancellationSignal cancellation) throws IOException {
            cancellation.throwIfCancelled();
            EffectiveCredentialStatusResolver.Evaluation evaluation = status.beginEvaluation();
            CaRecord ca = store.getCa(request.authorityId()).orElseThrow();
            if (ca.state() != CaState.ACTIVE) { throw new PkiException("ISSUER_CA_NOT_ACTIVE"); }
            IssuerGeneration generation = IssuerAuthorities.current(store, ca);
            IssuerChainPath path = IssuerAuthorities.issuancePath(store, ca);
            EndEntityIssuerBinding.requireSelectedIssuance(selected.intent(), generation, path);
            IssuerCryptographicBinding binding = IssuerBindingResolver.resolve(store, generation, managedKeys.orElseThrow(), signingAuthority);
            if (binding.alternative().isEmpty()) { throw new PkiException("OCSP_HYBRID_ISSUER_REQUIRED"); }
            Credential issuer = store.getCredential(generation.credentialId()).orElseThrow();
            EndEntityIssuerBinding.requireConsistentIssuer(ca, generation, path, issuer);
            evaluation.requireUsable(issuer, CredentialUse.END_ENTITY_ISSUER);
            ActiveCertificateProfile profile = selectProfile(selected.intent().expectedProfile().profileId(), Optional.of(selected.intent()));
            if (!profile.definition().isManagedOcspResponderProfile()) { throw new PkiException("MANAGED_OCSP_PROFILE_REQUIRED"); }
            ValidatedCertificateRequest approved = CertificateProfileValidator.validateManagedOcsp(request, selected.primarySpki(), profile.profile(),
                    profile.reference(), issuer, evaluation.evaluationTime(), authority)
                    .withFrozenIssuance(generation.issuerId(), path.pathId(), path.pathCommitment(), Optional.of(selected.intent()));
            HybridCertificateMode.AltSignature mode = (HybridCertificateMode.AltSignature) profile.definition().hybridMode();
            if (!binding.alternative().orElseThrow().signatureAlgorithm().equals(authority.resolveIdentity(mode.altSignatureAlgorithmId()))) {
                throw new PkiException("OCSP_ALTERNATIVE_ISSUER_ALGORITHM_DIFFERS");
            }
            byte[] issuerDer = CredentialContent.materializeForBc(store, issuer.content());
            X509Certificate certificate = Pkix.parseCertificate(issuerDer);
            EndEntityIssuerBinding.requireIssuerCertificate(certificate, issuer, evaluation.evaluationTime());
            AlgorithmIdentity signature = binding.primary().signatureAlgorithm();
            X509SecurityFloor.requirePermitted(signature);
            AlgorithmIdentifier algorithm = selectBinding(signature, X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE,
                    approved.algorithmBindingPolicy().certificateSignature());
            if (!Arrays.equals(Pkix.encodeAlgorithmIdentifier(algorithm), binding.primary().signatureAlgorithmIdentifier().bytes())) {
                throw new PkiException("OCSP_ISSUER_BINDING_DIFFERS");
            }
            requireRequestBinding(Pkix.subjectPublicKeyAlgorithm(selected.primarySpki().bytes()), X509AlgorithmBinding.Role.SUBJECT_PUBLIC_KEY,
                    approved.algorithmBindingPolicy().subjectPublicKey());
            cancellation.throwIfCancelled();
            return new Prepared(access, approved, generation.signingKeyRef(), signature, algorithm, serialSource.get(),
                    evaluation.evaluationTime(), issuerDer, issuer.content(), binding, profile);
        }

        private void requireManagedOcspPredecessor(Credential predecessor,
                PkiId authorityId, IssuerGeneration issuer, String slot, long revision,
                String primarySpki, String alternativeSpki) throws IOException {
            String issuance = ManagedOcspProvisioningIdentity.coreIssuanceId(slot, revision);
            String correlation = CorrelatedIssuanceIdentity.correlationId(authorityId, issuance);
            DomainContinuationStore.Record retained = store.getDomainContinuation(DomainContinuationStore.Kind.ISSUANCE, correlation)
                    .orElseThrow(() -> new PkiException(OCSP_PREDECESSOR_INVALID));
            DomainCommandEncoding.Decoded decoded = DomainContinuationValidation.validate(
                    new DomainContinuationTemplate(retained.kind(), retained.correlationId(),
                            retained.command(), retained.commandCommitment()));
            OcspResponderCertificateCommand command = OcspResponderCertificateCommand.decode(retained.command());
            byte[] der = CredentialContent.materializeForBc(store, predecessor.content());
            X509Certificate certificate = Pkix.parseCertificate(der);
            IssuerChainPath path = store.getIssuerChainPath(new PkiId(command.fields().get(4)))
                    .orElseThrow(() -> new PkiException(OCSP_PREDECESSOR_INVALID));
            requirePredecessorCommand(retained, correlation, decoded, command, authorityId, issuer, issuance, path, predecessor);
        requirePredecessorCertificate(predecessor, command, primarySpki, alternativeSpki, der, retained, certificate);
            Credential issuerCredential = store.getCredential(issuer.credentialId()).orElseThrow();
            X509Certificate issuerCertificate = Pkix.parseCertificate(CredentialContent.materializeForBc(store, issuerCredential.content()));
            try {
                certificate.verify(issuerCertificate.getPublicKey());
                if (!Pkix.verifyAlternativeSignatureCor3(certificate, Pkix.publicKeyFromSubjectPublicKeyInfo(
                        AltSignatureExtensions.requiredValue(issuerCertificate, X509ExtensionOids.subjectAltPublicKeyInfo())))) {
                    throw new PkiException(OCSP_PREDECESSOR_INVALID);
                }
            } catch (GeneralSecurityException invalid) {
                throw new PkiException(OCSP_PREDECESSOR_INVALID, invalid);
            }
        }


        private void requireUnusedCaKeys(ManagedOcspResponderIssuanceRequest request,
                IssuerKeyBinding primary, IssuerKeyBinding alternative) {
            for (CaRecord ca : store.listCas()) {
                for (IssuerGeneration issuer : store.listIssuerGenerations(ca.caId())) {
                    IssuerCryptographicBinding binding = store.getIssuerCryptographicBinding(issuer.issuerId()).orElseThrow();
                    requireDistinctRole(request, primary, alternative, binding.primary());
                    binding.alternative().ifPresent(role -> requireDistinctRole(request, primary, alternative, role));
                }
            }
        }

        private static void requireDistinctRole(ManagedOcspResponderIssuanceRequest request,
                IssuerKeyBinding primary, IssuerKeyBinding alternative, IssuerKeyBinding role) {
            if (Set.of(primary.subjectSpkiSha256(), alternative.subjectSpkiSha256()).contains(role.subjectSpkiSha256())
                    || role.keyRef().equals(request.primaryKeyRef()) || role.keyRef().equals(request.alternativeKeyRef())) {
                throw new PkiException("OCSP_CA_KEY_REUSE_FORBIDDEN");
            }
        }

        private static void requireSelectedIssuer(ManagedOcspResponderIssuanceRequest request,
                IssuerGeneration generation, IssuerChainPath path) {
        if (!generation.authorityId().equals(request.authorityId()) || !path.authorityId().equals(request.authorityId())
                    || !path.issuerId().equals(generation.issuerId()) || !path.pathCommitment().equals(request.intent().expectedChainPathCommitment())) {
                throw new PkiException("OCSP_ISSUER_SELECTION_DIFFERS");
            }
        }

        private static void requirePredecessorCommand(DomainContinuationStore.Record retained, String correlation,
                DomainCommandEncoding.Decoded decoded, OcspResponderCertificateCommand command, PkiId authorityId,
                IssuerGeneration issuer, String issuance, IssuerChainPath path, Credential predecessor) {
            if (retained.state() != DomainContinuationStore.State.COMPLETED
                    || retained.correlationId().filter(correlation::equals).isEmpty()
                    || !OcspResponderCertificateCommand.OPERATION.equals(decoded.operation())
                    || !command.fields().get(1).equals(authorityId.value()) || !command.fields().get(2).equals(issuer.issuerId().value())
                    || !command.fields().get(3).equals(issuer.credentialId().value()) || !command.fields().get(17).equals(issuance)
                    || !path.authorityId().equals(authorityId) || !path.issuerId().equals(issuer.issuerId())
                    || !path.pathCommitment().equals(command.fields().get(5))
                    || !predecessor.issuerRef().equals(new IssuerRef(authorityId, issuer.issuerId(), path.pathId()))) {
                throw new PkiException(OCSP_PREDECESSOR_INVALID);
            }
        }

        private static void requirePredecessorCertificate(Credential predecessor, OcspResponderCertificateCommand command,
                String primarySpki, String alternativeSpki, byte[] der, DomainContinuationStore.Record retained,
                X509Certificate certificate) throws IOException {
            if (!(predecessor.profileBinding() instanceof EndEntityProfileBinding profile)
                    || !profile.reference().equals(command.profile())
                    || !command.subjectBinding(SignWorkflowStore.SubjectKeyRole.PRIMARY).subjectSpkiSha256().equals(primarySpki)
                    || !command.subjectBinding(SignWorkflowStore.SubjectKeyRole.ALTERNATIVE).subjectSpkiSha256().equals(alternativeSpki)
                    || !predecessor.credentialId().value().equals("x509:" + SigningProvider.ContentCommitment.sha256(der).sha256())
                    || !Arrays.equals(retained.result().orElseThrow().bytes(), der)
                    || !SigningProvider.ContentCommitment.sha256(Pkix.subjectPublicKeyInfo(certificate)).sha256().equals(primarySpki)
                    || !SigningProvider.ContentCommitment.sha256(
                            AltSignatureExtensions.requiredValue(certificate, X509ExtensionOids.subjectAltPublicKeyInfo())).sha256().equals(alternativeSpki)) {
                throw new PkiException(OCSP_PREDECESSOR_INVALID);
            }
        }

    }
}
