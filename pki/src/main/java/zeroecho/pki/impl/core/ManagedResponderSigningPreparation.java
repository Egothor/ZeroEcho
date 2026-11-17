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
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.pki.api.issuance.ManagedOcspResponderIssuanceRequest;
import zeroecho.pki.api.issuance.ManagedOcspResponderProvisioningBinding;
import zeroecho.pki.api.issuance.RetainedIssuanceBinding;
import zeroecho.pki.api.signing.ManagedKeyProofRequest;
import zeroecho.pki.api.signing.ManagedOcspResponderProofTarget;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.hybrid.AltSignatureExtensions;
import zeroecho.pki.spi.crypto.AltSigningCapability;
import zeroecho.pki.spi.store.SignWorkflowStore;
import java.io.IOException;
import java.io.OutputStream;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.issuance.IssuanceIntent;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.impl.core.continuation.DomainAttributeEncoding;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.impl.core.continuation.OcspResponderCertificateCommand;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.cert.CertificateBuilder;
import zeroecho.pkix.sign.ContentVerifier;

/**
 * Prepares managed-responder signing proofs and cleans up candidates that are not adopted.
 */
final class ManagedResponderSigningPreparation {
    private final PkiStore store;
    private final EndEntityIssuancePreparation validation;

    /* default */ ManagedResponderSigningPreparation(PkiStore store, EndEntityIssuancePreparation validation) {
        this.store = store;
        this.validation = validation;
    }

    /* default */ RetainedIssuanceBinding managedOcspResponderBinding(
            ManagedOcspResponderIssuanceRequest request, CancellationSignal cancellation) throws IOException {
        return managedOcspResponderProvisioningBinding(request, cancellation).retainedBinding();
    }

    /* default */ ManagedOcspResponderProvisioningBinding managedOcspResponderProvisioningBinding(
            ManagedOcspResponderIssuanceRequest request, CancellationSignal cancellation) throws IOException {
        EndEntityIssuancePreparation.ManagedOcspSelection selected = validation.managedOcspSelection(request, cancellation);
        IssuanceIntent intent = selected.intent();
        return new ManagedOcspResponderProvisioningBinding(
                new RetainedIssuanceBinding(request.authorityId(), intent.issuanceId(), intent.expectedProfile(),
                        intent.expectedIssuerId(), intent.expectedChainPathId(), intent.expectedChainPathCommitment(), intent.commandCommitment()),
                selected.primary().subjectSpkiSha256(), selected.alternative().subjectSpkiSha256());
    }

    /* default */ void validateManagedOcsp(AccessContext access,
            ManagedOcspResponderIssuanceRequest request, CancellationSignal cancellation) throws IOException {
        EndEntityIssuancePreparation.ManagedOcspSelection selected = validation.managedOcspSelection(request, cancellation);
        validation.withoutSerialAllocation().prepareManagedOcsp(access, request, selected, cancellation);
    }

    // Every unadopted candidate must be retired for IO, runtime and Error failures.
    /* default */
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    DomainSigningRequest prepareManagedOcsp(AccessContext access,
            ManagedOcspResponderIssuanceRequest request, ManagedKeyProofPreparation proofs,
            SigningSubmissionId submission, Duration ttl, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) throws IOException {
        EndEntityIssuancePreparation.ManagedOcspSelection selected = validation.managedOcspSelection(request, cancellation);
        EndEntityIssuancePreparation.Prepared approved = validation.prepareManagedOcsp(access, request, selected, cancellation);
        EndEntitySigningPreparation.validateEvidence(evidence, access, request.authorityId().value(), approved.request().profileId());
        ManagedTbs captured = managedTbs(approved, selected);
    byte[] tbs = captured.bytes();
    X509AuthoritySnapshot authority = captured.authority();
    IssuanceIntent intent = selected.intent();
        List<String> fields = new ArrayList<>(List.of("1", request.authorityId().value(), intent.expectedIssuerId().value(),
                approved.issuerBinding().credentialId().value(), intent.expectedChainPathId().value(), intent.expectedChainPathCommitment(),
                intent.expectedProfile().profileId(), Long.toString(intent.expectedProfile().profileVersion()),
                HexFormat.of().formatHex(intent.expectedProfile().canonicalSha256()),
                OcspResponderCertificateCommand.encodeSubject(approved.request().subjectRdns()),
                approved.request().validity().notBefore().toString(), approved.request().validity().notAfter().toString(),
                OcspResponderCertificateCommand.encodeKey(selected.primary()),
                OcspResponderCertificateCommand.encodeKey(selected.alternative()),
                approved.issuerBinding().commitment(), authority.semanticFingerprint(), EndEntityCertificateEncoding.sha256(tbs), intent.issuanceId(),
                intent.commandCommitment(), DomainAttributeEncoding.encode(evidence.map(IssuanceExecutionEvidence::attributes)
                        .orElseGet(() -> new SimpleAttributeSet(List.of())))));
        String operation = OcspResponderCertificateCommand.OPERATION;
        List<String> parentFields = new ArrayList<>(fields);
        parentFields.add(approved.serial().toString());
        String parentIntent = "ocsp-intent:v1:" + EndEntityCertificateEncoding.sha256(DomainCommandEncoding.template(DomainContinuationStore.Kind.ISSUANCE,
                operation, parentFields.toArray(String[]::new)).command().bytes());
        String target = EndEntityCertificateEncoding.sha256(DomainCommandEncoding.template(DomainContinuationStore.Kind.ISSUANCE,
                "OCSP_RESPONDER_FROZEN_TARGET_V1", parentFields.toArray(String[]::new)).command().bytes());
        SigningSubmissionId primaryStep = proofs.newStep(submission);
        SigningSubmissionId alternativeStep = proofs.newStep(submission);
        while (alternativeStep.id().equals(primaryStep.id())) {
            alternativeStep = proofs.newStep(submission);
        }
        ManagedKeyProofPreparation.FrozenChallenge primaryProof = responderProof(proofs, selected.primary(), request,
                new ResponderProofContext(submission, primaryStep, ttl, parentIntent, target,
                        SignWorkflowStore.SubjectKeyRole.PRIMARY), cancellation);
        ManagedKeyProofPreparation.FrozenChallenge alternativeProof = responderProof(proofs, selected.alternative(), request,
                new ResponderProofContext(submission, alternativeStep, ttl, parentIntent, target,
                        SignWorkflowStore.SubjectKeyRole.ALTERNATIVE), cancellation);
        fields.add(primaryStep.id().value());
        fields.add(OcspResponderCertificateCommand.encodeProof(primaryProof.command()));
        fields.add(alternativeStep.id().value());
        fields.add(OcspResponderCertificateCommand.encodeProof(alternativeProof.command()));
        fields.add(approved.serial().toString());
        OcspResponderCertificateCommand command = new OcspResponderCertificateCommand(fields);
        DomainContinuationTemplate template = DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.ISSUANCE,
                CorrelatedIssuanceIdentity.correlationId(request.authorityId(), intent.issuanceId()), operation,
                command.fields().toArray(String[]::new));
        List<DurableContentReference> candidates = new ArrayList<>();
        try {
            DurableContentReference content = stageManagedBytes(tbs, Encoding.DER, cancellation);
            candidates.add(content);
            DurableContentReference primaryContent = stageManagedBytes(primaryProof.content().bytes(), Encoding.BINARY, cancellation);
            candidates.add(primaryContent);
            DurableContentReference alternativeContent = stageManagedBytes(alternativeProof.content().bytes(), Encoding.BINARY, cancellation);
            candidates.add(alternativeContent);
            return new DomainSigningRequest(submission.id(), access, approved.keyRef(), approved.signature().canonicalForm(), Encoding.BINARY,
                    content, ttl, template, Optional.of(new SignWorkflowStore.CaSubjectProofStep(primaryStep.id(),
                            selected.primary().keyRef(), selected.primary().signatureAlgorithm().canonicalForm(), primaryContent)),
                    Optional.of(new SignWorkflowStore.CaSubjectProofStep(alternativeStep.id(), selected.alternative().keyRef(),
                            selected.alternative().signatureAlgorithm().canonicalForm(), alternativeContent,
                            SignWorkflowStore.SubjectKeyRole.ALTERNATIVE)));
        } catch (IOException | RuntimeException | Error failure) {
            for (DurableContentReference content : candidates) {
                try {
                    store.stagedContent().retireUnownedContent(content);
                } catch (IOException | RuntimeException cleanup) {
                    failure.addSuppressed(cleanup);
                }
            }
            throw failure;
        }
    }

    private static ManagedKeyProofPreparation.FrozenChallenge responderProof(ManagedKeyProofPreparation proofs,
            IssuerKeyBinding binding, ManagedOcspResponderIssuanceRequest request,
            ResponderProofContext context, CancellationSignal cancellation) throws IOException {
        ManagedKeyProofPreparation.ProofPlan plan = proofs.withSignature(binding.signatureAlgorithm().canonicalForm()).plan(
                new ManagedKeyProofRequest.OcspResponderCandidate(request.authorityId(),
                        request.intent().expectedProfile(), binding.keyRef(),
                        new ManagedOcspResponderProofTarget(context.parent().id(), context.intent(), context.target(), context.role())), cancellation);
        return proofs.challenge(plan, context.step(), context.parent().createdAt().plus(context.ttl()), Optional.empty(), cancellation);
    }

    private DurableContentReference stageManagedBytes(byte[] bytes, Encoding encoding, CancellationSignal cancellation) throws IOException {
        cancellation.throwIfCancelled();
        try (ContentSink sink = store.stagedContent().beginContent(encoding, DurableContentReference.Lifecycle.OPERATION);
                OutputStream output = sink.outputStream()) {
            output.write(bytes);
            cancellation.throwIfCancelled();
            return sink.complete();
        }
    }
    private ManagedTbs managedTbs(EndEntityIssuancePreparation.Prepared approved,
            EndEntityIssuancePreparation.ManagedOcspSelection selected) throws IOException {
        IssuerKeyBinding issuerAlternative = approved.issuerBinding().alternative().orElseThrow();
        AlgorithmIdentifier altAlgorithm = Pkix.parseAlgorithmIdentifier(issuerAlternative.signatureAlgorithmIdentifier().bytes());
        CertificateBuilder builder = EndEntityCertificateEncoding.leafBuilder(approved)
                .addExtension(AltSignatureExtensions.subjectAltPublicKeyInfo(selected.alternativeSpki().bytes()))
                .addExtension(AltSignatureExtensions.altSignatureAlgorithm(altAlgorithm));
        byte[] transcript = builder.buildAlternativeSignatureTbs(approved.signatureBinding());
        X509AuthoritySnapshot authority = validation.authority();
        X509ExecutionPlan<SigningProvider> plan = authority.plan(issuerAlternative.signatureAlgorithm(), issuerAlternative.publicKeyAlgorithm(),
                AlgorithmExecutionCapability.Direction.SIGN, Optional.empty(), "explicit",
                SigningProvider.class);
        authority.authorize(plan, plan.executor(), AlgorithmExecutionCapability.Direction.SIGN);
        if (!(plan.executor() instanceof AltSigningCapability signer)) {
            throw new PkiException("ALT_SIGNING_CAPABILITY_UNAVAILABLE");
        }
        byte[] signature;
        try {
            signature = signer.sign(issuerAlternative.keyRef(), issuerAlternative.signatureAlgorithm().canonicalForm(), transcript);
        } catch (GeneralSecurityException invalid) {
            throw new PkiException("ALT_SIGNING_FAILED", invalid);
        }
        byte[] issuerAltSpki = AltSignatureExtensions.requiredValue(
                Pkix.parseCertificate(approved.issuerDer()), X509ExtensionOids.subjectAltPublicKeyInfo());
        ContentVerifier verifier = Pkix.verifier(issuerAltSpki, altAlgorithm);
        try (OutputStream output = verifier.contentStream()) {
            output.write(transcript);
        }
        if (!verifier.verify(signature)) {
            throw new PkiException("ALT_SIGNATURE_INVALID");
        }
        byte[] tbs = builder.addExtension(AltSignatureExtensions.altSignatureValue(signature))
                .buildTbs(approved.signatureBinding());
        if (tbs.length > CredentialContent.MAXIMUM_CERTIFICATE_BYTES) {
            throw new PkiException("CERTIFICATE_TOO_LARGE");
        }

        return new ManagedTbs(tbs, authority);
    }

    private record ManagedTbs(byte[] bytes, X509AuthoritySnapshot authority) { }

    private record ResponderProofContext(SigningSubmissionId parent, SigningSubmissionId step,
            Duration ttl, String intent, String target, SignWorkflowStore.SubjectKeyRole role) { }

}
