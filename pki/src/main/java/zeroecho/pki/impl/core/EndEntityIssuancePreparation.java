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

package zeroecho.pki.impl.core;

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
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.credential.CaProfileBinding;
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
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509SecurityFloor;
import zeroecho.pki.impl.framework.x509.X509SuiteCompatibility;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
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
    private final PkiStore store;
    private final EffectiveCredentialStatusResolver status;
    private final X509AuthoritySnapshot authority;
    private final BcX509ProofOfPossessionVerifier proofVerifier;
    private final X509ProfileBindingMatcher bindingMatcher;
    private final AlgorithmIdentity signature;

    /* default */ EndEntityIssuancePreparation(PkiStore store, Clock clock, X509AuthoritySnapshot authority,
            BcX509VerificationExecutor verifier, X509AlgorithmBindingRegistry bindings, String signatureAlgorithm) {
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

    /* default */ EndEntityLifecyclePreparation lifecyclePreparation() {
        return new EndEntityLifecyclePreparation(store, status, authority, this);
    }

    /* default */ Prepared prepare(AccessContext access, EndEntityIssuanceRequest input, CancellationSignal cancellation)
            throws IOException {
        return prepare(access, input, Optional.empty(), cancellation);
    }

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

    /* default */ VerifiedIssuanceCandidate verifyCsr(zeroecho.pki.api.PkiId issuerCaId, byte[] csrDer, String profileId,
            Optional<zeroecho.pki.api.Validity> validityOverride, CancellationSignal cancellation) throws IOException {
        return verifyRequest(issuerCaId, new X509EnrollmentPayload(
                X509EnrollmentPayload.Kind.PKCS10, csrDer), profileId, validityOverride, cancellation);
    }

    /* default */ VerifiedIssuanceCandidate verifyRequest(zeroecho.pki.api.PkiId issuerCaId,
            X509EnrollmentPayload payload, String profileId,
            Optional<zeroecho.pki.api.Validity> validityOverride, CancellationSignal cancellation) throws IOException {
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

    /* default */ Prepared prepareCandidate(AccessContext access, VerifiedIssuanceCandidate candidate,
            EffectiveCredentialStatusResolver.Evaluation evaluation, Optional<X509EnrollmentPayload> csrDer,
            CancellationSignal cancellation) throws IOException {
        return prepareCandidate(access, candidate, evaluation, csrDer, Optional.empty(), cancellation);
    }

    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    /* default */ Prepared prepareCandidate(AccessContext access, VerifiedIssuanceCandidate candidate,
            EffectiveCredentialStatusResolver.Evaluation evaluation, Optional<X509EnrollmentPayload> csrDer,
            Optional<IssuanceIntent> intent, CancellationSignal cancellation) throws IOException {
        CaRecord ca = store.getCa(candidate.issuerCaId()).orElseThrow(
                () -> new PkiException("Issuer CA not found", PkiFailureReason.ISSUER_CA_NOT_FOUND));
        if (!ca.caId().equals(candidate.issuerCaId()) || ca.state() != CaState.ACTIVE) {
            throw new PkiException("Issuer CA is not active", PkiFailureReason.ISSUER_CA_NOT_ACTIVE);
        }
        IssuerGeneration generation = IssuerAuthorities.current(store, ca);
        IssuerChainPath path = IssuerAuthorities.issuancePath(store, ca);
        if (intent.isPresent()) {
            requireSelectedIssuance(intent.orElseThrow(), generation, path);
        }
        Credential issuer = store.getCredential(generation.credentialId()).orElseThrow(
                () -> new PkiException("Issuer credential not found", PkiFailureReason.ISSUER_CREDENTIAL_NOT_FOUND));
        requireConsistentIssuer(ca, generation, path, issuer);
        evaluation.requireUsable(issuer, CredentialUse.END_ENTITY_ISSUER);
        ActiveCertificateProfile profile = selectProfile(candidate.profileId(), intent);
        if (!profile.reference().profileId().equals(candidate.profileId())
                || profile.definition().certificateType() != CertificateProfileKind.END_ENTITY
                || !profile.definition().formatId().equals(BcX509CredentialFramework.FORMAT_ID)) {
            throw new PkiException("End-entity preparation rejected: code=PROFILE_KIND_MISMATCH");
        }
        ValidatedCertificateRequest validated = csrDer.isPresent()
                ? CertificateProfileValidator.validate(candidate, profile.profile(), profile.reference(), issuer,
                        evaluation.evaluationTime(), authority)
                : CertificateProfileValidator.validateReconstructed(candidate, profile.profile(), profile.reference(), issuer,
                        evaluation.evaluationTime(), authority);
        ValidatedCertificateRequest approved = validated.withFrozenIssuance(
                generation.issuerId(), path.pathId(), path.pathCommitment(), intent);
        byte[] issuerDer = CredentialContent.materializeForBc(store, issuer.content());
        AlgorithmIdentifier signingBinding;
        try {
            new StreamingDerReader().validate(issuerDer, CredentialContent.MAXIMUM_CERTIFICATE_BYTES);
            X509Certificate certificate = Pkix.parseCertificate(issuerDer);
            requireIssuerCertificate(certificate, issuer, evaluation.evaluationTime());
            BcX509AlgorithmAdapter adapter = new BcX509AlgorithmAdapter(authority.bindings());
            AlgorithmIdentity issuerKey = adapter.decode(Pkix.subjectPublicKeyAlgorithm(
                    Pkix.subjectPublicKeyInfo(certificate)), X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
            X509SuiteCompatibility.requireCompatible(signature, issuerKey);
            X509AlgorithmBindingPolicy policy = approved.algorithmBindingPolicy();
            signingBinding = selectBinding(signature, X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE,
                    policy.certificateSignature());
            if (csrDer.isPresent()) {
                X509EnrollmentPayload payload = csrDer.orElseThrow();
                AlgorithmIdentifier proofAlgorithm = payload.kind() == X509EnrollmentPayload.Kind.PKCS10
                        ? Pkix.parseCertificationRequest(payload.der()).signatureAlgorithm()
                        : zeroecho.pkix.cmp.CrmfRequest.parse(payload.der()).signatureAlgorithm();
                requireRequestBinding(proofAlgorithm, X509AlgorithmBinding.Role.CSR_SIGNATURE,
                        policy.csrSignature());
            }
            requireRequestBinding(Pkix.subjectPublicKeyAlgorithm(candidate.exactPublicKey().bytes()),
                    X509AlgorithmBinding.Role.SUBJECT_PUBLIC_KEY, policy.subjectPublicKey());
        } catch (IllegalArgumentException | IOException invalid) {
            throw new PkiException("End-entity preparation rejected: code=ISSUANCE_BINDING_INVALID");
        }
        cancellation.throwIfCancelled();
        return new Prepared(access, approved, generation.signingKeyRef(), signature, signingBinding,
                CertificateSerialAllocator.allocate(), evaluation.evaluationTime(), issuerDer, issuer.content());
    }

    private static void requireSelectedIssuance(IssuanceIntent expected, IssuerGeneration generation, IssuerChainPath path) {
        if (!expected.expectedIssuerId().equals(generation.issuerId())
                || !expected.expectedChainPathId().equals(path.pathId())
                || !expected.expectedChainPathCommitment().equals(path.pathCommitment())) {
            throw new PkiException("Correlated issuance rejected: code=ISSUANCE_SELECTION_STALE");
        }
    }

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

    private static void requireConsistentIssuer(CaRecord ca, IssuerGeneration generation, IssuerChainPath path,
            Credential credential) {
        if (!generation.issuerId().equals(ca.currentIssuanceIssuerId())
                || !path.pathId().equals(ca.issuanceChainPathId())
                || !credential.credentialId().equals(generation.credentialId())
                || !path.orderedCredentialIds().getFirst().equals(credential.credentialId())
                || !ca.issuerKeyRef().equals(generation.signingKeyRef())
                || !credential.subjectRef().equals(ca.subjectRef())
                || !credential.formatId().equals(BcX509CredentialFramework.FORMAT_ID)
                || !(credential.profileBinding() instanceof CaProfileBinding profile)
                || !generation.profilePolicyCommitment().equals(java.util.HexFormat.of().formatHex(
                        profile.reference().canonicalSha256()))) {
            throw new PkiException("End-entity preparation rejected: code=ISSUER_BINDING_INCONSISTENT");
        }
    }

    private static void requireIssuerCertificate(X509Certificate certificate, Credential issuer, Instant now) {
        boolean[] usages = certificate.getKeyUsage();
        if (certificate.getBasicConstraints() < 0 || usages == null || usages.length <= 5 || !usages[5]
                || !certificate.getNotBefore().toInstant().equals(issuer.validity().notBefore())
                || !certificate.getNotAfter().toInstant().equals(issuer.validity().notAfter())
                || now.isBefore(certificate.getNotBefore().toInstant()) || !now.isBefore(certificate.getNotAfter().toInstant())) {
            throw new PkiException("End-entity preparation rejected: code=ISSUER_CERTIFICATE_UNUSABLE");
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

    /** Frozen, bounded inputs for the subsequent TBS construction step. */
    /* default */ record Prepared(AccessContext access, ValidatedCertificateRequest request, KeyRef keyRef,
            AlgorithmIdentity signature, AlgorithmIdentifier signatureBinding, BigInteger serial,
            Instant evaluationTime, byte[] issuerDer, DurableContentReference issuerContent) {
        Prepared { issuerDer = issuerDer.clone(); }
        @Override public byte[] issuerDer() { return issuerDer.clone(); }
        @Override public String toString() { return "PreparedEndEntityIssuance[redacted]"; }
    }
}
