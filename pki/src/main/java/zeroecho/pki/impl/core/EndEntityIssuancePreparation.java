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
    private final Optional<zeroecho.pki.spi.crypto.PublicKeyInfoSource> managedKeys;
    private final X509AuthoritySnapshot signingAuthority;
    private final BcX509ProofOfPossessionVerifier proofVerifier;
    private final X509ProfileBindingMatcher bindingMatcher;
    private final AlgorithmIdentity signature;
    private final java.util.function.Supplier<BigInteger> serialSource;

    /* default */ EndEntityIssuancePreparation(PkiStore store, Clock clock, X509AuthoritySnapshot authority,
            BcX509VerificationExecutor verifier, X509AlgorithmBindingRegistry bindings, String signatureAlgorithm) {
        this(store, clock, authority, verifier, bindings, signatureAlgorithm, authority, Optional.empty());
    }

    /* default */ EndEntityIssuancePreparation(PkiStore store, Clock clock, X509AuthoritySnapshot authority,
            BcX509VerificationExecutor verifier, X509AlgorithmBindingRegistry bindings, String signatureAlgorithm,
            X509AuthoritySnapshot signingAuthority, Optional<zeroecho.pki.spi.crypto.PublicKeyInfoSource> managedKeys) {
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

    /* default */ EndEntityIssuancePreparation withoutSerialAllocation() {
        return new EndEntityIssuancePreparation(this);
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
        return prepareCandidate(access, candidate, evaluation, csrDer, intent, Optional.empty(), false, cancellation);
    }

    /* default */ Prepared prepareCandidate(AccessContext access, VerifiedIssuanceCandidate candidate,
            EffectiveCredentialStatusResolver.Evaluation evaluation, Optional<X509EnrollmentPayload> csrDer,
            Optional<IssuanceIntent> intent, Optional<zeroecho.pki.api.Validity> frozenValidity, boolean sdk,
            CancellationSignal cancellation) throws IOException {
        CaRecord ca = store.getCa(candidate.issuerCaId()).orElseThrow(
                () -> new PkiException("Issuer CA not found", PkiFailureReason.ISSUER_CA_NOT_FOUND));
        if (!ca.caId().equals(candidate.issuerCaId()) || ca.state() != CaState.ACTIVE) {
            throw new PkiException("Issuer CA is not active", PkiFailureReason.ISSUER_CA_NOT_ACTIVE);
        }
        IssuerGeneration generation = IssuerAuthorities.current(store, ca);
        zeroecho.pki.api.ca.IssuerCryptographicBinding issuerBinding = store.getIssuerCryptographicBinding(generation.issuerId())
                .orElseThrow(() -> new PkiException("Issuer binding unavailable: code=ISSUER_BINDING_MISSING"));
        AlgorithmIdentity signature = issuerBinding.primary().signatureAlgorithm();
        X509SecurityFloor.requirePermitted(signature);
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
        boolean requestAlternative = profile.definition().hybridMode() instanceof zeroecho.pki.api.hybrid.HybridCertificateMode.AltSignature;
        if (requestAlternative != sdk) throw new PkiException("SDK dual proof required: code=SDK_PROFILE_REQUIRED");
        if (sdk) {
            var mode = (zeroecho.pki.api.hybrid.HybridCertificateMode.AltSignature) profile.definition().hybridMode();
            if (mode.subjectKeySource() != zeroecho.pki.api.hybrid.HybridCertificateMode.AlternativeSubjectKeySource.REQUEST) {
                throw new PkiException("SDK_REQUEST_OWNED_PROFILE_REQUIRED");
            }
            var alternative = issuerBinding.alternative().orElseThrow(() -> new PkiException("SDK_ISSUER_NOT_HYBRID"));
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
        AlgorithmIdentifier signingBinding;
        try {
            new StreamingDerReader().validate(issuerDer, CredentialContent.MAXIMUM_CERTIFICATE_BYTES);
            X509Certificate certificate = Pkix.parseCertificate(issuerDer);
            requireIssuerCertificate(certificate, issuer, evaluation.evaluationTime());
            BcX509AlgorithmAdapter adapter = new BcX509AlgorithmAdapter(authority.bindings());
            AlgorithmIdentity issuerKey = adapter.decode(Pkix.subjectPublicKeyAlgorithm(
                    Pkix.subjectPublicKeyInfo(certificate)), X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
            X509SuiteCompatibility.requireCompatible(signature, issuerKey);
            if (managedKeys.isPresent()) IssuerBindingResolver.resolve(store, generation, managedKeys.orElseThrow(), authority);
            X509AlgorithmBindingPolicy policy = approved.algorithmBindingPolicy();
            signingBinding = selectBinding(signature, X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE,
                    policy.certificateSignature());
            if (!signingBinding.equals(Pkix.parseAlgorithmIdentifier(issuerBinding.primary().signatureAlgorithmIdentifier().bytes()))) {
                throw new IllegalArgumentException("Frozen issuer signature binding differs");
            }
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
                serialSource.get(), evaluation.evaluationTime(), issuerDer, issuer.content(), issuerBinding, profile);
    }

    /* default */ Prepared prepareSdk(AccessContext access, EndEntityIssuanceRequest input,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest supplied,
            Optional<zeroecho.pki.api.Validity> frozenValidity, boolean preview,
            CancellationSignal cancellation) throws IOException {
        return prepareSdk(access, input, supplied, frozenValidity, preview, status.beginEvaluation(), cancellation);
    }

    /* default */ Prepared prepareSdk(AccessContext access, EndEntityIssuanceRequest input,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest supplied,
            Optional<zeroecho.pki.api.Validity> frozenValidity, boolean preview,
            EffectiveCredentialStatusResolver.Evaluation evaluation, CancellationSignal cancellation) throws IOException {
        return prepareSdk(access, input, supplied, frozenValidity, preview, evaluation, Optional.empty(), cancellation);
    }

    /* default */ Prepared prepareSdk(AccessContext access, EndEntityIssuanceRequest input,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest supplied,
            Optional<zeroecho.pki.api.Validity> frozenValidity, boolean preview,
            EffectiveCredentialStatusResolver.Evaluation evaluation, Optional<IssuanceIntent> intent,
            CancellationSignal cancellation) throws IOException {
        if (managedKeys.isEmpty()) throw new PkiException("SDK_MANAGED_PUBLIC_KEY_SOURCE_REQUIRED");
        if (input.payload().kind() != supplied.originalPayload().kind()
                || !java.util.Arrays.equals(input.payload().der(), supplied.originalPayload().der())) {
            throw new PkiException("SDK_REQUEST_MISMATCH");
        }
        var parsed = new BcX509CertificationRequestParser().parseHybridSdk(input.payload());
        if (!java.util.Arrays.equals(parsed.primary().publicKeyInfo().bytes(), supplied.primary().publicKeyInfo().bytes())
                || !java.util.Arrays.equals(parsed.alternativeSubjectPublicKeyInfo().bytes(), supplied.alternativeSubjectPublicKeyInfo().bytes())) {
            throw new PkiException("SDK_REQUEST_MISMATCH");
        }
        var candidate = new VerifiedIssuanceCandidate(parsed.primary(), parsed.primary().requestId(),
                parsed.primary().publicKeyInfo(), ProofOfPossessionStatus.VERIFIED,
                new IssueEndEntityCommand(input.issuerCaId(), parsed.primary(), input.profileId(), input.validityOverride()));
        EndEntityIssuancePreparation selected = preview ? withoutSerialAllocation() : this;
        return selected.prepareCandidate(access, candidate, evaluation, Optional.of(input.payload()),
                intent, frozenValidity, true, cancellation);
    }

    /* default */ ManagedOcspSelection managedOcspSelection(zeroecho.pki.api.issuance.ManagedOcspResponderIssuanceRequest request,
            CancellationSignal cancellation) throws IOException {
        cancellation.throwIfCancelled();
        var keys = managedKeys.orElseThrow(() -> new PkiException("MANAGED_PUBLIC_KEY_SOURCE_REQUIRED"));
        var primarySpki = keys.resolvePublicKeyInfo(request.primaryKeyRef());
        var alternativeSpki = keys.resolvePublicKeyInfo(request.alternativeKeyRef());
        var primary = IssuerBindingResolver.createKey(request.primaryKeyRef(), zeroecho.core.alg.BootstrapAlgorithmIdentities.ECDSA_SHA384,
                primarySpki.bytes(), keys, signingAuthority);
        var alternative = IssuerBindingResolver.createKey(request.alternativeKeyRef(), zeroecho.core.alg.BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE,
                alternativeSpki.bytes(), keys, signingAuthority);
        var primaryAlgorithm = zeroecho.pkix.Pkix.subjectPublicKeyAlgorithm(primarySpki.bytes());
        if (!primaryAlgorithm.oid().equals("1.2.840.10045.2.1")
                || !java.util.Arrays.equals(primaryAlgorithm.parameters(), java.util.HexFormat.of().parseHex("06052b81040022"))
                || !alternative.publicKeyAlgorithm().equals(zeroecho.core.alg.BootstrapAlgorithmIdentities.ML_DSA_87_PUBLIC_KEY)) {
            throw new PkiException("OCSP_RESPONDER_SUBJECT_SUITE_INVALID");
        }
        if (primary.subjectSpkiSha256().equals(alternative.subjectSpkiSha256())) throw new PkiException("OCSP_RESPONDER_KEYS_DIFFER");
        var imported = store.getProfileVersion(request.intent().expectedProfile().profileId(), request.intent().expectedProfile().profileVersion())
                .orElseThrow(() -> new PkiException("FROZEN_PROFILE_UNAVAILABLE"));
        if (!imported.reference().equals(request.intent().expectedProfile()) || !imported.definition().isManagedOcspResponderProfile()) {
            throw new PkiException("MANAGED_OCSP_PROFILE_REQUIRED");
        }
        var mode = (zeroecho.pki.api.hybrid.HybridCertificateMode.AltSignature) imported.definition().hybridMode();
        var profileAlternative = keys.resolvePublicKeyInfo(new zeroecho.pki.api.KeyRef(mode.altKeyRef()));
        if (!java.util.Arrays.equals(profileAlternative.bytes(), alternativeSpki.bytes())
                || !signingAuthority.resolveIdentity(mode.altSignatureAlgorithmId()).equals(alternative.signatureAlgorithm())) {
            throw new PkiException("OCSP_PROFILE_SUBJECT_BINDING_DIFFERS");
        }
        var generation = store.getIssuerGeneration(request.intent().expectedIssuerId()).orElseThrow();
        var path = store.getIssuerChainPath(request.intent().expectedChainPathId()).orElseThrow();
        if (!generation.authorityId().equals(request.authorityId()) || !path.authorityId().equals(request.authorityId())
                || !path.issuerId().equals(generation.issuerId()) || !path.pathCommitment().equals(request.intent().expectedChainPathCommitment())) {
            throw new PkiException("OCSP_ISSUER_SELECTION_DIFFERS");
        }
        for (var ca : store.listCas()) for (var issuer : store.listIssuerGenerations(ca.caId())) {
            var binding = store.getIssuerCryptographicBinding(issuer.issuerId()).orElseThrow();
            var roles = new java.util.ArrayList<zeroecho.pki.api.ca.IssuerKeyBinding>(); roles.add(binding.primary()); binding.alternative().ifPresent(roles::add);
            for (var role : roles) if (java.util.Set.of(primary.subjectSpkiSha256(), alternative.subjectSpkiSha256()).contains(role.subjectSpkiSha256())
                    || role.keyRef().equals(request.primaryKeyRef()) || role.keyRef().equals(request.alternativeKeyRef())) {
                throw new PkiException("OCSP_CA_KEY_REUSE_FORBIDDEN");
            }
        }
        String slot = zeroecho.pki.api.issuance.ManagedOcspProvisioningIdentity.coreSlotId(request.authorityId(), generation.issuerId(), primarySpki, alternativeSpki);
        long revision = 1;
        if (request.expectedPredecessorCredentialId().isPresent()) {
            var predecessor = store.getCredential(request.expectedPredecessorCredentialId().orElseThrow()).orElseThrow();
            String priorSlot = managedAttribute(predecessor, "urn:zeroecho:pki:ocsp-provision-core-slot:v1");
            String priorRevision = managedAttribute(predecessor, "urn:zeroecho:pki:ocsp-provision-revision:v1");
            if (!slot.equals(priorSlot) || !priorRevision.matches("[1-9][0-9]{0,18}")) throw new PkiException("OCSP_PREDECESSOR_SLOT_DIFFERS");
            long previous = Long.parseLong(priorRevision);
            requireManagedOcspPredecessor(predecessor, request.authorityId(), generation, slot, previous,
                    primary.subjectSpkiSha256(), alternative.subjectSpkiSha256());
            revision = Math.addExact(previous, 1);
        }
        var fields = new java.util.ArrayList<String>(java.util.List.of(request.authorityId().value(), generation.issuerId().value(), path.pathId().value(),
                path.pathCommitment(), imported.reference().profileId(), Long.toString(imported.reference().profileVersion()),
                java.util.HexFormat.of().formatHex(imported.reference().canonicalSha256()),
                zeroecho.pki.impl.core.continuation.OcspResponderCertificateCommand.encodeSubject(request.subject()),
                request.validity().notBefore().toString(), request.validity().notAfter().toString(),
                primary.publicKeyAlgorithm().canonicalForm(), primary.signatureAlgorithm().canonicalForm(), primary.subjectSpkiSha256(),
                java.util.HexFormat.of().formatHex(primary.signatureAlgorithmIdentifier().bytes()),
                alternative.publicKeyAlgorithm().canonicalForm(), alternative.signatureAlgorithm().canonicalForm(), alternative.subjectSpkiSha256(),
                java.util.HexFormat.of().formatHex(alternative.signatureAlgorithmIdentifier().bytes()),
                request.expectedPredecessorCredentialId().map(zeroecho.pki.api.PkiId::value).orElse("")));
        String target = zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment.sha256(
                zeroecho.pki.impl.core.continuation.DomainCommandEncoding.template(zeroecho.pki.spi.store.DomainContinuationStore.Kind.ISSUANCE,
                        "MANAGED_OCSP_PROVISION_TARGET_V1", fields.toArray(String[]::new)).command().bytes()).sha256();
        String issuance = zeroecho.pki.api.issuance.ManagedOcspProvisioningIdentity.coreIssuanceId(slot, revision);
        var intent = new IssuanceIntent(issuance, target, imported.reference(), generation.issuerId(), path.pathId(), path.pathCommitment());
        return new ManagedOcspSelection(primarySpki, alternativeSpki, primary, alternative, slot, revision, intent);
    }

    /* default */ Prepared prepareManagedOcsp(AccessContext access,
            zeroecho.pki.api.issuance.ManagedOcspResponderIssuanceRequest request, ManagedOcspSelection selected,
            CancellationSignal cancellation) throws IOException {
        cancellation.throwIfCancelled();
        var evaluation = status.beginEvaluation();
        var ca = store.getCa(request.authorityId()).orElseThrow();
        if (ca.state() != CaState.ACTIVE) throw new PkiException("ISSUER_CA_NOT_ACTIVE");
        var generation = IssuerAuthorities.current(store, ca);
        var path = IssuerAuthorities.issuancePath(store, ca);
        requireSelectedIssuance(selected.intent(), generation, path);
        var binding = IssuerBindingResolver.resolve(store, generation, managedKeys.orElseThrow(), signingAuthority);
        if (binding.alternative().isEmpty()) throw new PkiException("OCSP_HYBRID_ISSUER_REQUIRED");
        var issuer = store.getCredential(generation.credentialId()).orElseThrow();
        requireConsistentIssuer(ca, generation, path, issuer);
        evaluation.requireUsable(issuer, CredentialUse.END_ENTITY_ISSUER);
        var profile = selectProfile(selected.intent().expectedProfile().profileId(), Optional.of(selected.intent()));
        if (!profile.definition().isManagedOcspResponderProfile()) throw new PkiException("MANAGED_OCSP_PROFILE_REQUIRED");
        var approved = CertificateProfileValidator.validateManagedOcsp(request, selected.primarySpki(), profile.profile(),
                profile.reference(), issuer, evaluation.evaluationTime(), authority)
                .withFrozenIssuance(generation.issuerId(), path.pathId(), path.pathCommitment(), Optional.of(selected.intent()));
        var mode = (zeroecho.pki.api.hybrid.HybridCertificateMode.AltSignature) profile.definition().hybridMode();
        if (!binding.alternative().orElseThrow().signatureAlgorithm().equals(authority.resolveIdentity(mode.altSignatureAlgorithmId()))) {
            throw new PkiException("OCSP_ALTERNATIVE_ISSUER_ALGORITHM_DIFFERS");
        }
        byte[] issuerDer = CredentialContent.materializeForBc(store, issuer.content());
        var certificate = Pkix.parseCertificate(issuerDer);
        requireIssuerCertificate(certificate, issuer, evaluation.evaluationTime());
        var signature = binding.primary().signatureAlgorithm();
        X509SecurityFloor.requirePermitted(signature);
        var algorithm = selectBinding(signature, X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE,
                approved.algorithmBindingPolicy().certificateSignature());
        if (!java.util.Arrays.equals(Pkix.encodeAlgorithmIdentifier(algorithm), binding.primary().signatureAlgorithmIdentifier().bytes())) {
            throw new PkiException("OCSP_ISSUER_BINDING_DIFFERS");
        }
        requireRequestBinding(Pkix.subjectPublicKeyAlgorithm(selected.primarySpki().bytes()), X509AlgorithmBinding.Role.SUBJECT_PUBLIC_KEY,
                approved.algorithmBindingPolicy().subjectPublicKey());
        cancellation.throwIfCancelled();
        return new Prepared(access, approved, generation.signingKeyRef(), signature, algorithm, serialSource.get(),
                evaluation.evaluationTime(), issuerDer, issuer.content(), binding, profile);
    }

    // Mutable inventory attributes alone cannot authorize another issuance revision.
    private void requireManagedOcspPredecessor(zeroecho.pki.api.credential.Credential predecessor,
            PkiId authorityId, IssuerGeneration issuer, String slot, long revision,
            String primarySpki, String alternativeSpki) throws IOException {
        String issuance = zeroecho.pki.api.issuance.ManagedOcspProvisioningIdentity.coreIssuanceId(slot, revision);
        String correlation = CorrelatedIssuanceIdentity.correlationId(authorityId, issuance);
        var retained = store.getDomainContinuation(zeroecho.pki.spi.store.DomainContinuationStore.Kind.ISSUANCE, correlation)
                .orElseThrow(() -> new PkiException("OCSP_PREDECESSOR_PROVENANCE_INVALID"));
        var decoded = zeroecho.pki.impl.core.continuation.DomainContinuationValidation.validate(
                new zeroecho.pki.impl.core.continuation.DomainContinuationTemplate(retained.kind(), retained.correlationId(),
                        retained.command(), retained.commandCommitment()));
        var command = zeroecho.pki.impl.core.continuation.OcspResponderCertificateCommand.decode(retained.command());
        byte[] der = CredentialContent.materializeForBc(store, predecessor.content());
        var certificate = Pkix.parseCertificate(der);
        var path = store.getIssuerChainPath(new PkiId(command.fields().get(4)))
                .orElseThrow(() -> new PkiException("OCSP_PREDECESSOR_PROVENANCE_INVALID"));
        if (retained.state() != zeroecho.pki.spi.store.DomainContinuationStore.State.COMPLETED
                || retained.correlationId().filter(correlation::equals).isEmpty()
                || !decoded.operation().equals(zeroecho.pki.impl.core.continuation.OcspResponderCertificateCommand.OPERATION)
                || !command.fields().get(1).equals(authorityId.value()) || !command.fields().get(2).equals(issuer.issuerId().value())
                || !command.fields().get(3).equals(issuer.credentialId().value()) || !command.fields().get(17).equals(issuance)
                || !path.authorityId().equals(authorityId) || !path.issuerId().equals(issuer.issuerId())
                || !path.pathCommitment().equals(command.fields().get(5))
                || !predecessor.issuerRef().equals(new zeroecho.pki.api.IssuerRef(authorityId, issuer.issuerId(), path.pathId()))
                || !(predecessor.profileBinding() instanceof zeroecho.pki.api.credential.EndEntityProfileBinding profile)
                || !profile.reference().equals(command.profile())
                || !command.subjectBinding(zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole.PRIMARY).subjectSpkiSha256().equals(primarySpki)
                || !command.subjectBinding(zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole.ALTERNATIVE).subjectSpkiSha256().equals(alternativeSpki)
                || !predecessor.credentialId().value().equals("x509:" + zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment.sha256(der).sha256())
                || !java.util.Arrays.equals(retained.result().orElseThrow().bytes(), der)
                || !zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment.sha256(Pkix.subjectPublicKeyInfo(certificate)).sha256().equals(primarySpki)
                || !zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment.sha256(
                        zeroecho.pki.impl.hybrid.AltSignatureExtensions.requiredValue(certificate, "2.5.29.72")).sha256().equals(alternativeSpki)) {
            throw new PkiException("OCSP_PREDECESSOR_PROVENANCE_INVALID");
        }
        var issuerCredential = store.getCredential(issuer.credentialId()).orElseThrow();
        var issuerCertificate = Pkix.parseCertificate(CredentialContent.materializeForBc(store, issuerCredential.content()));
        try {
            certificate.verify(issuerCertificate.getPublicKey());
            if (!Pkix.verifyAlternativeSignatureCor3(certificate, Pkix.publicKeyFromSubjectPublicKeyInfo(
                    zeroecho.pki.impl.hybrid.AltSignatureExtensions.requiredValue(issuerCertificate, "2.5.29.72")))) {
                throw new PkiException("OCSP_PREDECESSOR_PROVENANCE_INVALID");
            }
        } catch (java.security.GeneralSecurityException invalid) {
            throw new PkiException("OCSP_PREDECESSOR_PROVENANCE_INVALID", invalid);
        }
    }
    private static String managedAttribute(zeroecho.pki.api.credential.Credential credential, String name) {
        var values = credential.attributes().getAll(new zeroecho.pki.api.attr.AttributeId(name));
        if (values.size() != 1 || !(values.getFirst() instanceof zeroecho.pki.api.attr.AttributeValue.StringValue value)) {
            throw new PkiException("OCSP_PREDECESSOR_PROVENANCE_INVALID");
        }
        return value.value();
    }
    /* default */ record ManagedOcspSelection(EncodedObject primarySpki, EncodedObject alternativeSpki,
            zeroecho.pki.api.ca.IssuerKeyBinding primary, zeroecho.pki.api.ca.IssuerKeyBinding alternative,
            String coreSlotId, long revision, IssuanceIntent intent) { }

    /* default */ EffectiveCredentialStatusResolver.Evaluation beginSdkEvaluation() { return status.beginEvaluation(); }

    /* default */ X509AuthoritySnapshot authority() { return signingAuthority; }

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
            Instant evaluationTime, byte[] issuerDer, DurableContentReference issuerContent,
            zeroecho.pki.api.ca.IssuerCryptographicBinding issuerBinding, ActiveCertificateProfile profile) {
        Prepared { issuerDer = issuerDer.clone(); }
        @Override public byte[] issuerDer() { return issuerDer.clone(); }
        @Override public String toString() { return "PreparedEndEntityIssuance[redacted]"; }
    }
}
