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

import zeroecho.pki.api.issuance.IssuanceIntent;
import zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest;
import zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ContentSlice;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.EffectiveCredentialStatus;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.issuance.EndEntityReissueRequest;
import zeroecho.pki.api.issuance.EndEntityRenewalRequest;
import zeroecho.pki.api.issuance.EndEntityReplacementRequest;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.X509SecurityFloor;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.impl.framework.x509.bc.BcX509CertificationRequestParser;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.Pkix;

/**
 * Read-only predecessor and policy preparation for leaf lifecycle operations.
 * No content staging, signing provider or continuation is reachable. Each call
 * captures one evaluation time and uses only bounded authoritative point reads.
 * Local work and auxiliary memory are O(P + C + I) in predecessor, optional CSR
 * and issuer DER, plus cryptographic verification and profile validation.
 */
final class EndEntityLifecyclePreparation { // NOPMD CyclomaticComplexity - One issuer lifecycle prepares renewal, replacement and reissue; individual methods remain checked.
    private final PkiStore store;
    private final EffectiveCredentialStatusResolver status;
    private final EndEntityIssuancePreparation issuance;
    private final X509AuthoritySnapshot authority;

    /* default */ EndEntityLifecyclePreparation(PkiStore store, Clock clock, X509AuthoritySnapshot authority,
            BcX509VerificationExecutor verifier, X509AlgorithmBindingRegistry bindings, String signatureAlgorithm) {
        this(store, new StoreBackedEffectiveCredentialStatusResolver(store, clock), authority,
                new EndEntityIssuancePreparation(store, clock, authority, verifier, bindings, signatureAlgorithm));
    }

    /* default */ EndEntityLifecyclePreparation(PkiStore store, EffectiveCredentialStatusResolver status,
            X509AuthoritySnapshot authority, EndEntityIssuancePreparation issuance) {
        this.store = Objects.requireNonNull(store, "store");
        this.authority = Objects.requireNonNull(authority, "authority");
        this.status = Objects.requireNonNull(status, "status");
        this.issuance = Objects.requireNonNull(issuance, "issuance");
    }

    /* default */ Prepared prepareRenewal(AccessContext access, EndEntityRenewalRequest request, CancellationSignal cancellation)
            throws IOException {
        Objects.requireNonNull(request, "request");
        return reconstruct(access, request.existingCredentialId(), request.validityOverride(), cancellation);
    }

    /* default */ Prepared prepareReissue(AccessContext access, EndEntityReissueRequest request, CancellationSignal cancellation)
            throws IOException {
        Objects.requireNonNull(request, "request");
        return reconstruct(access, request.existingCredentialId(), Optional.empty(), cancellation);
    }

    /* default */ Prepared prepareReplacement(AccessContext access, EndEntityReplacementRequest request, CancellationSignal cancellation)
            throws IOException {
        return replace(access, request, Optional.empty(), Optional.empty(), cancellation);
    }

    /* default */ Prepared prepareCorrelatedReplacement(AccessContext access,
            CorrelatedEndEntityReplacementRequest request, IssuanceIntent effective,
            CancellationSignal cancellation) throws IOException {
        return replace(access, request.request(), Optional.of(request), Optional.of(effective), cancellation);
    }

    private Prepared replace(AccessContext access, EndEntityReplacementRequest request,
            Optional<CorrelatedEndEntityReplacementRequest> binding, Optional<IssuanceIntent> intent,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        EffectiveCredentialStatusResolver.Evaluation evaluation = status.beginEvaluation();
        Predecessor predecessor = predecessor(request.existingCredentialId(), cancellation);
        if (binding.isPresent()) {
            CorrelatedEndEntityReplacementRequest expected = binding.orElseThrow();
            if (!expected.issuerCaId().equals(predecessor.credential().issuerRef().caId())
                    || !expected.predecessorSha256().equals(predecessor.credential().content().sha256())) {
                throw reject("PREDECESSOR_BINDING_MISMATCH");
            }
        }
        VerifiedIssuanceCandidate candidate = issuance.verifyRequest(predecessor.credential().issuerRef().caId(), request.payload(),
                request.profileId(), Optional.empty(), cancellation);
        if (request.payload().kind() == zeroecho.pki.api.request.X509EnrollmentPayload.Kind.CRMF) {
            zeroecho.pkix.cmp.CrmfRequest.CertificateReference original = zeroecho.pkix.cmp.CrmfRequest.parse(request.payload().der())
                    .oldCertificate().orElseThrow(() -> reject("PREDECESSOR_REFERENCE_REQUIRED"));
            if (!original.issuer().equals(predecessor.certificate().getIssuerX500Principal())
                    || !original.serialNumber().equals(predecessor.certificate().getSerialNumber())) {
                throw reject("PREDECESSOR_REFERENCE_MISMATCH");
            }
        }
        EffectiveCredentialStatus effective = evaluation.resolve(predecessor.credential());
        if (Arrays.equals(candidate.exactPublicKey().bytes(), predecessor.request().publicKeyInfo().bytes())) {
            requireReusable(effective);
        }
        return new Prepared(predecessor.credential(), issuance.prepareCandidate(access, candidate, evaluation,
                Optional.of(request.payload()), intent, cancellation));
    }

    private Prepared reconstruct(AccessContext access, PkiId id, Optional<Validity> validity,
            CancellationSignal cancellation) throws IOException {
        return reconstruct(access, id, validity, Optional.empty(), Optional.empty(), cancellation);
    }

    /* default */ Prepared prepareCorrelatedRenewal(AccessContext access,
            CorrelatedEndEntityRenewalRequest request,
            IssuanceIntent effective, CancellationSignal cancellation) throws IOException {
        return reconstruct(access, request.request().existingCredentialId(), request.request().validityOverride(),
                Optional.of(request), Optional.of(effective), cancellation);
    }

    private Prepared reconstruct(AccessContext access, PkiId id, Optional<Validity> validity,
            Optional<CorrelatedEndEntityRenewalRequest> binding,
            Optional<IssuanceIntent> intent, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        EffectiveCredentialStatusResolver.Evaluation evaluation = status.beginEvaluation();
        Predecessor predecessor = predecessor(id, cancellation);
        if (binding.isPresent()) {
            CorrelatedEndEntityRenewalRequest expected = binding.orElseThrow();
            if (!expected.issuerCaId().equals(predecessor.credential().issuerRef().caId())
                    || !expected.predecessorSha256().equals(predecessor.credential().content().sha256())) {
                throw reject("PREDECESSOR_BINDING_MISMATCH");
            }
        }
        requireReusable(evaluation.resolve(predecessor.credential()));
        ParsedCertificationRequest request = predecessor.request();
        CertificateProfileRef profile = ((EndEntityProfileBinding) predecessor.credential().profileBinding()).reference();
        VerifiedIssuanceCandidate candidate = VerifiedIssuanceCandidate.reconstructed(request, request.requestId(),
                request.publicKeyInfo(), new IssueEndEntityCommand(predecessor.credential().issuerRef().caId(), request,
                        profile.profileId(), validity));
        Optional<zeroecho.pki.api.request.X509EnrollmentPayload> original = binding.flatMap(CorrelatedEndEntityRenewalRequest::originalRequest);
        if (original.isPresent()) {
            candidate = issuance.verifyRequest(predecessor.credential().issuerRef().caId(), original.orElseThrow(), profile.profileId(), validity, cancellation);
            ParsedCertificationRequest verified = candidate.request();
            if (!request.subjectRef().equals(verified.subjectRef()) || !request.subjectRdns().equals(verified.subjectRdns())
                    || !request.subjectAlternativeNames().equals(verified.subjectAlternativeNames())
                    || request.subjectAlternativeNamePresent() != verified.subjectAlternativeNamePresent()
                    || !Arrays.equals(request.publicKeyInfo().bytes(), verified.publicKeyInfo().bytes())) {
                throw reject("PREDECESSOR_IDENTITY_CHANGED");
            }
        }
        EndEntityIssuancePreparation.Prepared prepared = issuance.prepareCandidate(access, candidate, evaluation,
                original, intent, cancellation);
        if (!request.subjectRdns().equals(prepared.request().subjectRdns())
                || !request.subjectAlternativeNames().equals(prepared.request().subjectAlternativeNames())
                || !Arrays.equals(predecessor.subjectDer(), BcX509ProfileSupport.subject(
                        prepared.request().subjectRdns()).getEncoded())) {
            throw reject("PREDECESSOR_SUBJECT_CHANGED");
        }
        return new Prepared(predecessor.credential(), prepared);
    }

    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    private Predecessor predecessor(PkiId id, CancellationSignal cancellation) throws IOException {
        Credential credential = store.getCredential(id).orElseThrow(() -> reject("PREDECESSOR_NOT_FOUND"));
        if (!id.equals(credential.credentialId())
                || !BcX509CredentialFramework.FORMAT_ID.equals(credential.formatId())
                || !(credential.profileBinding() instanceof EndEntityProfileBinding binding)) {
            throw reject("PREDECESSOR_NOT_LEAF");
        }
        Credential originalIssuer = requireOriginalBindings(credential, binding.reference());
        byte[] der = CredentialContent.materializeForBc(store, credential.content());
        try {
            new StreamingDerReader().validate(der, CredentialContent.MAXIMUM_CERTIFICATE_BYTES);
            X509Certificate certificate = Pkix.parseCertificate(der);
            requireOriginalSignature(certificate, der, originalIssuer, cancellation);
            ParsedCertificationRequest request = BcX509CertificationRequestParser.reconstructForRenewal(certificate,
                    credential.formatId());
            String digest = sha256(der);
            if (certificate.getBasicConstraints() >= 0
                    || !id.value().equals("x509:" + digest)
                    || !credential.content().sha256().equals(digest)
                    || !credential.publicKeyId().value().equals("spki:" + sha256(request.publicKeyInfo().bytes()))
                    || !credential.subjectRef().equals(request.subjectRef())
                    || !credential.serialOrUniqueId().equals(certificate.getSerialNumber().toString())
                    || !credential.validity().notBefore().equals(certificate.getNotBefore().toInstant())
                    || !credential.validity().notAfter().equals(certificate.getNotAfter().toInstant())) {
                throw reject("PREDECESSOR_METADATA_MISMATCH");
            }
            return new Predecessor(credential, request, certificate.getSubjectX500Principal().getEncoded(), certificate);
        } catch (IllegalArgumentException invalid) {
            throw reject("PREDECESSOR_CERTIFICATE_INVALID");
        }
    }

    private Credential requireOriginalBindings(Credential credential, CertificateProfileRef reference) {
        ImportedCertificateProfileVersion version = store.getProfileVersion(reference.profileId(), reference.profileVersion())
                .orElseThrow(() -> reject("PREDECESSOR_PROFILE_UNAVAILABLE"));
        if (!reference.equals(version.reference()) || version.definition().certificateType() != CertificateProfileKind.END_ENTITY
                || !credential.formatId().equals(version.definition().formatId())) {
            throw reject("PREDECESSOR_PROFILE_MISMATCH");
        }
        IssuerGeneration generation = store.getIssuerGeneration(credential.issuerRef().issuerId())
                .orElseThrow(() -> reject("PREDECESSOR_ISSUER_UNAVAILABLE"));
        IssuerChainPath path = store.getIssuerChainPath(credential.issuerRef().chainPathId())
                .orElseThrow(() -> reject("PREDECESSOR_PATH_UNAVAILABLE"));
        if (!generation.issuerId().equals(credential.issuerRef().issuerId())
                || !generation.authorityId().equals(credential.issuerRef().caId())
                || !path.pathId().equals(credential.issuerRef().chainPathId())
                || !path.authorityId().equals(generation.authorityId()) || !path.issuerId().equals(generation.issuerId())
                || !path.orderedCredentialIds().getFirst().equals(generation.credentialId())) {
            throw reject("PREDECESSOR_ISSUER_MISMATCH");
        }
        Credential issuer = store.getCredential(generation.credentialId())
                .orElseThrow(() -> reject("PREDECESSOR_ISSUER_UNAVAILABLE"));
        if (!issuer.credentialId().equals(generation.credentialId()) || !issuer.formatId().equals(credential.formatId())
                || !(issuer.profileBinding() instanceof CaProfileBinding binding)
                || !generation.profilePolicyCommitment().equals(HexFormat.of().formatHex(
                        binding.reference().canonicalSha256()))) {
            throw reject("PREDECESSOR_ISSUER_MISMATCH");
        }
        return issuer;
    }

    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    private void requireOriginalSignature(X509Certificate certificate, byte[] certificateDer, Credential issuer,
            CancellationSignal cancellation) throws IOException {
        byte[] der = CredentialContent.materializeForBc(store, issuer.content());
        new StreamingDerReader().validate(der, CredentialContent.MAXIMUM_CERTIFICATE_BYTES);
        X509Certificate issuerCertificate = Pkix.parseCertificate(der);
        if (issuerCertificate.getBasicConstraints() < 0
                || !sha256(der).equals(issuer.content().sha256())
                || !certificate.getIssuerX500Principal().equals(issuerCertificate.getSubjectX500Principal())) {
            throw reject("PREDECESSOR_ISSUER_MISMATCH");
        }
        try (RepeatableContent content = new ImmutableByteContent(certificateDer)) {
            StreamingDerReader.SignedObjectLayout layout = new StreamingDerReader().inspectSignedObject(content,
                    StreamingDerReader.SignedObjectKind.CERTIFICATE, cancellation);
            byte[] algorithmDer = element(certificateDer, layout.outerAlgorithmOffset(), layout.outerAlgorithmLength());
            if (!Arrays.equals(algorithmDer, element(certificateDer, layout.tbsAlgorithmOffset(), layout.tbsAlgorithmLength()))) {
                throw reject("PREDECESSOR_ALGORITHM_MISMATCH");
            }
            AlgorithmIdentifier identifier = Pkix.parseAlgorithmIdentifier(algorithmDer);
            BcX509AlgorithmAdapter adapter = new BcX509AlgorithmAdapter(authority.bindings());
            AlgorithmIdentity signature = adapter.decode(identifier, X509AlgorithmRole.SIGNATURE_ALGORITHM);
            X509SecurityFloor.requirePermitted(signature);
            byte[] issuerPublicKey = Pkix.subjectPublicKeyInfo(issuerCertificate);
            AlgorithmIdentity issuerKey = adapter.decode(Pkix.subjectPublicKeyAlgorithm(issuerPublicKey),
                    X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
            X509ExecutionPlan<BcX509VerificationExecutor> verification = authority.plan(signature, issuerKey,
                    AlgorithmExecutionCapability.Direction.VERIFY, Optional.of(BcX509VerificationExecutor.IMPLEMENTATION_ID),
                    "lifecycle-predecessor", authority.bindings().bindingId(BcX509AlgorithmAdapter.fromLib(identifier),
                            X509AlgorithmRole.SIGNATURE_ALGORITHM), BcX509VerificationExecutor.class);
            try (RepeatableContent tbs = new ContentSlice(content, layout.tbsOffset(), layout.tbsLength())) {
                if (!verification.executor().verify(authority, verification, issuerPublicKey, identifier, tbs,
                        element(certificateDer, layout.signatureOffset(), layout.signatureLength()))) {
                    throw reject("PREDECESSOR_SIGNATURE_INVALID");
                }
            }
        } catch (GeneralSecurityException invalid) {
            throw reject("PREDECESSOR_SIGNATURE_INVALID");
        }
    }

    private static byte[] element(byte[] encoded, long offset, long length) {
        return Arrays.copyOfRange(encoded, Math.toIntExact(offset), Math.toIntExact(Math.addExact(offset, length)));
    }

    private static void requireReusable(EffectiveCredentialStatus status) {
        if (status == EffectiveCredentialStatus.HELD || status == EffectiveCredentialStatus.PERMANENTLY_REVOKED) {
            throw reject("PREDECESSOR_KEY_NOT_REUSABLE");
        }
    }

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static PkiException reject(String code) {
        return new PkiException("End-entity lifecycle preparation rejected: code=" + code);
    }

    /* default */ record Prepared(Credential predecessor, EndEntityIssuancePreparation.Prepared issuance) {
        @Override public String toString() { return "PreparedEndEntityLifecycle[redacted]"; }
    }

    private record Predecessor(Credential credential, ParsedCertificationRequest request, byte[] subjectDer,
            X509Certificate certificate) {
        private Predecessor { subjectDer = subjectDer.clone(); }
        @Override public byte[] subjectDer() { return subjectDer.clone(); }
    }
}
