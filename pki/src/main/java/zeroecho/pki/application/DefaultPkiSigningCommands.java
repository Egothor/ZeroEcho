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

package zeroecho.pki.application;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.ca.CaKeyRotationCommand;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaRolloverCommand;
import zeroecho.pki.api.ca.IntermediateCertIssueCommand;
import zeroecho.pki.api.ca.IntermediateCreateCommand;
import zeroecho.pki.api.issuance.EndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.EndEntityReissueRequest;
import zeroecho.pki.api.issuance.EndEntityRenewalRequest;
import zeroecho.pki.api.issuance.EndEntityReplacementRequest;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.api.status.DeltaCrlRequest;
import zeroecho.pki.api.status.FullCrlRequest;

/** Session-borrowed command preparation and completed-result projection. */
final class DefaultPkiSigningCommands implements PkiSigningCommands {
    private static final AttributeSet EMPTY_ATTRIBUTES = new AttributeSet() {
        @Override public java.util.Set<AttributeId> ids() { return java.util.Set.of(); }
        @Override public Optional<AttributeValue> get(AttributeId id) {
            Objects.requireNonNull(id, "id");
            return Optional.empty();
        }
        @Override public java.util.List<AttributeValue> getAll(AttributeId id) {
            Objects.requireNonNull(id, "id");
            return java.util.List.of();
        }
    };
    private final SemanticSigningService service;
    private final PkiRepository repository;
    private final Optional<CertificationRequestService> requests;
    private final Runnable requireOpen;

    /* default */ DefaultPkiSigningCommands(SemanticSigningService service, PkiRepository repository,
            Optional<CertificationRequestService> requests, Runnable requireOpen) {
        this.service = Objects.requireNonNull(service, "service");
        this.repository = Objects.requireNonNull(repository, "repository");
        this.requests = Objects.requireNonNull(requests, "requests");
        this.requireOpen = Objects.requireNonNull(requireOpen, "requireOpen");
    }

    @Override public PkiSigningOperation normalizeCreation(PkiSigningOperation operation) {
        requireOpen.run(); Objects.requireNonNull(operation, "operation");
        if (operation instanceof PkiSigningOperation.IssueOcspResponderCertificate value) {
            var selected = value.request(); var binding = service.managedOcspResponderBinding(selected);
            var intent = new zeroecho.pki.api.issuance.IssuanceIntent(binding.issuanceId(), binding.effectiveCommitment(),
                    binding.expectedProfile(), binding.expectedIssuerId(), binding.expectedChainPathId(), binding.expectedChainPathCommitment());
            return new PkiSigningOperation.IssueOcspResponderCertificate(new zeroecho.pki.api.issuance.ManagedOcspResponderIssuanceRequest(
                    selected.authorityId(), selected.primaryKeyRef(), selected.alternativeKeyRef(), selected.subject(), selected.validity(),
                    intent, selected.expectedPredecessorCredentialId()));
        }
        if (operation instanceof PkiSigningOperation.CreateAuthority value && value.signatureAlgorithmId().isEmpty()) {
            return new PkiSigningOperation.CreateAuthority(value.formatId(), value.subjectRef(), value.profileId(),
                    value.keyRef(), Optional.of(service.creationSignatureAlgorithm()));
        }
        if (operation instanceof PkiSigningOperation.CreateIntermediate value && value.signatureAlgorithmId().isEmpty()) {
            return new PkiSigningOperation.CreateIntermediate(value.formatId(), value.issuerCaId(), value.subjectRef(), value.profileId(),
                    value.keyRef(), Optional.of(service.creationSignatureAlgorithm()));
        }
        return operation;
    }

    @Override public PkiSigningOperation normalizeLifecycle(PkiSigningOperation operation) {
        requireOpen.run(); Objects.requireNonNull(operation, "operation");
        if (operation instanceof PkiSigningOperation.RolloverCaCertificate value) {
            return new PkiSigningOperation.RolloverCaCertificate(value.caId(), value.issuerCaId(),
                    Optional.of(service.freezeCaHead(value.caId(), value.expectedHead())));
        }
        if (operation instanceof PkiSigningOperation.IssueIntermediateCertificate value) {
            return new PkiSigningOperation.IssueIntermediateCertificate(value.formatId(), value.issuerCaId(), value.subjectCaId(),
                    value.profileId(), value.requestedValidity(), Optional.of(service.freezeCaHead(value.subjectCaId(), value.expectedHead())));
        }
        if (operation instanceof PkiSigningOperation.RotateCaKey value) {
            CaRecord current = authority(value.caId());
            requireIssuer(current, value.issuerCaId());
            CaKeyRotationCommand input = current.kind() == CaKind.ROOT
                    ? new CaKeyRotationCommand.Root(value.caId(), value.selection(), value.expectedHead(), EMPTY_ATTRIBUTES)
                    : new CaKeyRotationCommand.Intermediate(value.caId(), value.selection(), value.issuerCaId().orElseThrow(),
                            value.expectedHead(), EMPTY_ATTRIBUTES);
            var normalized = service.normalizeCaKeyRotation(input);
            return new PkiSigningOperation.RotateCaKey(value.caId(), normalized.selection(), value.issuerCaId(), normalized.expectedHead());
        }
        return operation;
    }

    @Override public zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdk(PkiSigningOperation.IssueCredential operation,
            AccessContext access, zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest request,
            Optional<zeroecho.pki.api.Validity> frozenValidity, CancellationSignal cancellation) {
        return previewSdk((PkiSigningOperation) operation, access, request, frozenValidity, cancellation);
    }

    @Override public zeroecho.pki.api.signing.PreparedSemanticSigningRequest prepareSdk(PkiSigningOperation.IssueCredential operation,
            AccessContext access, zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest request,
            zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval approval,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        return prepareSdk((PkiSigningOperation) operation, access, request, approval, evidence, cancellation);
    }

    @Override public zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdk(PkiSigningOperation operation,
            AccessContext access, zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest request,
            Optional<zeroecho.pki.api.Validity> frozenValidity, CancellationSignal cancellation) {
        requireOpen.run();
        return switch (operation) {
            case PkiSigningOperation.IssueCredential value -> service.previewSdk(access, sdkRequest(value, request), request, frozenValidity, cancellation);
            case PkiSigningOperation.RenewCredential value -> service.previewSdk(access,
                    new EndEntityRenewalRequest(value.credentialId(), Optional.empty()), request, frozenValidity, cancellation);
            case PkiSigningOperation.ReissueCredential value -> service.previewSdk(access,
                    new EndEntityReissueRequest(value.credentialId()), request, frozenValidity, cancellation);
            case PkiSigningOperation.ReplaceCredential value -> service.previewSdk(access, sdkReplacement(value, request), request, frozenValidity, cancellation);
            default -> throw new UnsupportedOperationException("SDK operation is not a supported leaf operation");
        };
    }

    @Override public zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdk(PkiSigningOperation operation,
            AccessContext access, zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest request,
            Optional<zeroecho.pki.api.Validity> frozenValidity,
            Optional<zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget> enrollmentTarget, CancellationSignal cancellation) {
        requireOpen.run();
        return switch (operation) {
            case PkiSigningOperation.IssueCredential value -> service.previewSdk(access, sdkRequest(value, request), request, frozenValidity, enrollmentTarget, cancellation);
            case PkiSigningOperation.RenewCredential value -> service.previewSdk(access,
                    new EndEntityRenewalRequest(value.credentialId(), Optional.empty()), request, frozenValidity, enrollmentTarget, cancellation);
            case PkiSigningOperation.ReissueCredential value -> service.previewSdk(access,
                    new EndEntityReissueRequest(value.credentialId()), request, frozenValidity, enrollmentTarget, cancellation);
            case PkiSigningOperation.ReplaceCredential value -> service.previewSdk(access, sdkReplacement(value, request), request, frozenValidity, enrollmentTarget, cancellation);
            default -> throw new UnsupportedOperationException("SDK operation is not a supported leaf operation");
        };
    }

    @Override public zeroecho.pki.api.signing.PreparedSemanticSigningRequest prepareSdk(PkiSigningOperation operation,
            AccessContext access, zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest request,
            zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval approval,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        requireOpen.run();
        return switch (operation) {
            case PkiSigningOperation.IssueCredential value -> service.prepareSdk(access, sdkRequest(value, request), request, approval, evidence, cancellation);
            case PkiSigningOperation.RenewCredential value -> service.prepareSdk(access,
                    new EndEntityRenewalRequest(value.credentialId(), Optional.empty()), request, approval, evidence, cancellation);
            case PkiSigningOperation.ReissueCredential value -> service.prepareSdk(access,
                    new EndEntityReissueRequest(value.credentialId()), request, approval, evidence, cancellation);
            case PkiSigningOperation.ReplaceCredential value -> service.prepareSdk(access, sdkReplacement(value, request), request, approval, evidence, cancellation);
            default -> throw new UnsupportedOperationException("SDK operation is not a supported leaf operation");
        };
    }

    private static EndEntityReplacementRequest sdkReplacement(PkiSigningOperation.ReplaceCredential operation,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest request) {
        if (!operation.requestId().equals(request.primary().requestId())) throw new IllegalArgumentException("SDK request selection differs");
        return new EndEntityReplacementRequest(operation.existingCredentialId(),
                zeroecho.pki.impl.framework.x509.bc.BcX509RequestPayloads.extract(request.primary()), operation.profileId());
    }

    private static EndEntityIssuanceRequest sdkRequest(PkiSigningOperation.IssueCredential operation,
            zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest request) {
        if (!operation.requestId().equals(request.primary().requestId())) {
            throw new IllegalArgumentException("SDK request selection differs from its original signed request");
        }
        return new EndEntityIssuanceRequest(operation.issuerCaId(),
                zeroecho.pki.impl.framework.x509.bc.BcX509RequestPayloads.extract(request.primary()),
                operation.profileId(), Optional.empty());
    }

    @Override
    public void validate(PkiSigningOperation operation, AccessContext access,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        requireOpen.run();
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(evidence, "evidence");
        Objects.requireNonNull(cancellation, "cancellation");
        switch (operation) {
            case PkiSigningOperation.CreateAuthority value -> service.validateRootCreation(access,
                    new CaCreateCommand(value.formatId(), value.subjectRef(), value.profileId(), value.keyRef(),
                            Optional.empty(), EMPTY_ATTRIBUTES, value.signatureAlgorithmId()), cancellation);
            case PkiSigningOperation.CreateIntermediate value -> service.validateIntermediateCreation(access,
                    new IntermediateCreateCommand(value.formatId(), value.issuerCaId(), value.subjectRef(),
                            value.profileId(), value.keyRef().orElseThrow(), EMPTY_ATTRIBUTES, value.signatureAlgorithmId()), cancellation);
            case PkiSigningOperation.IssueIntermediateCertificate value -> service.validateIntermediateIssuance(access,
                    new IntermediateCertIssueCommand(value.formatId(), value.issuerCaId(), value.subjectCaId(),
                            value.profileId(), authority(value.subjectCaId()).issuerKeyRef(),
                            value.requestedValidity(), EMPTY_ATTRIBUTES, value.expectedHead()), cancellation);
            case PkiSigningOperation.RolloverCaCertificate value -> {
                CaRecord current = authority(value.caId());
                requireIssuer(current, value.issuerCaId());
                CaRolloverCommand command = current.kind() == CaKind.ROOT
                        ? new CaRolloverCommand.Root(value.caId(), Optional.empty(), EMPTY_ATTRIBUTES, value.expectedHead())
                        : new CaRolloverCommand.Intermediate(value.caId(), value.issuerCaId().orElseThrow(),
                                current.issuerKeyRef(), Optional.empty(), EMPTY_ATTRIBUTES, value.expectedHead());
                service.validateCaRollover(access, command, cancellation);
            }
            case PkiSigningOperation.RotateCaKey value -> {
                CaRecord current = authority(value.caId());
                requireIssuer(current, value.issuerCaId());
                CaKeyRotationCommand command = current.kind() == CaKind.ROOT
                        ? new CaKeyRotationCommand.Root(value.caId(), value.selection(), value.expectedHead(), EMPTY_ATTRIBUTES)
                        : new CaKeyRotationCommand.Intermediate(value.caId(), value.selection(),
                                value.issuerCaId().orElseThrow(), value.expectedHead(), EMPTY_ATTRIBUTES);
                service.validateCaKeyRotation(access, command, cancellation);
            }
            case PkiSigningOperation.IssueOcspResponderCertificate value -> service.validateManagedOcspResponder(access,
                    value.request(), evidence, cancellation);
            case PkiSigningOperation.IssueCredential value -> service.validateEndEntity(access,
                    new EndEntityIssuanceRequest(value.issuerCaId(), csr(value.requestId()), value.profileId(),
                            Optional.empty()), evidence, cancellation);
            case PkiSigningOperation.RenewCredential value -> service.validateRenewal(access,
                    new EndEntityRenewalRequest(value.credentialId(), Optional.empty()), evidence, cancellation);
            case PkiSigningOperation.ReplaceCredential value -> service.validateReplacement(access,
                    new EndEntityReplacementRequest(value.existingCredentialId(), csr(value.requestId()),
                            value.profileId()), evidence, cancellation);
            case PkiSigningOperation.ReissueCredential value -> service.validateReissue(access,
                    new EndEntityReissueRequest(value.credentialId()), evidence, cancellation);
            default -> throw new UnsupportedOperationException("Pure signing input validation unavailable");
        }
    }

    @Override
    public PreparedSemanticSigningRequest prepare(PkiSigningOperation operation, AccessContext access,
            Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) {
        requireOpen.run();
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(evidence, "evidence");
        Objects.requireNonNull(cancellation, "cancellation");
        if (operation instanceof PkiSigningOperation.GenerateStatus status
                && status.type() == zeroecho.pki.api.status.StatusObjectType.OCSP) {
            throw new PkiException("OCSP_TARGET_REQUIRED");
        }
        return switch (operation) {
            case PkiSigningOperation.CreateAuthority value -> service.prepareRootCreation(access,
                    new CaCreateCommand(value.formatId(), value.subjectRef(), value.profileId(), value.keyRef(),
                            Optional.empty(), EMPTY_ATTRIBUTES, value.signatureAlgorithmId()), cancellation);
            case PkiSigningOperation.CreateIntermediate value -> service.prepareIntermediateCreation(access,
                    new IntermediateCreateCommand(value.formatId(), value.issuerCaId(), value.subjectRef(),
                            value.profileId(), value.keyRef().orElseThrow(), EMPTY_ATTRIBUTES, value.signatureAlgorithmId()), cancellation);
            case PkiSigningOperation.IssueIntermediateCertificate value -> service.prepareIntermediateIssuance(access,
                    new IntermediateCertIssueCommand(value.formatId(), value.issuerCaId(), value.subjectCaId(),
                            value.profileId(), authority(value.subjectCaId()).issuerKeyRef(),
                            value.requestedValidity(), EMPTY_ATTRIBUTES, value.expectedHead()), cancellation);
            case PkiSigningOperation.RolloverCaCertificate value -> {
                CaRecord current = authority(value.caId());
                requireIssuer(current, value.issuerCaId());
                CaRolloverCommand command = current.kind() == CaKind.ROOT
                        ? new CaRolloverCommand.Root(value.caId(), Optional.empty(), EMPTY_ATTRIBUTES, value.expectedHead())
                        : new CaRolloverCommand.Intermediate(value.caId(), value.issuerCaId().orElseThrow(),
                                current.issuerKeyRef(), Optional.empty(), EMPTY_ATTRIBUTES, value.expectedHead());
                yield service.prepareCaRollover(access, command, cancellation);
            }
            case PkiSigningOperation.RotateCaKey value -> {
                CaRecord current = authority(value.caId());
                requireIssuer(current, value.issuerCaId());
                CaKeyRotationCommand command = current.kind() == CaKind.ROOT
                        ? new CaKeyRotationCommand.Root(value.caId(), value.selection(), value.expectedHead(), EMPTY_ATTRIBUTES)
                        : new CaKeyRotationCommand.Intermediate(value.caId(), value.selection(),
                                value.issuerCaId().orElseThrow(), value.expectedHead(), EMPTY_ATTRIBUTES);
                yield service.prepareCaKeyRotation(access, command, cancellation);
            }
            case PkiSigningOperation.IssueOcspResponderCertificate ignored -> throw new UnsupportedOperationException(
                    "Managed OCSP provisioning requires canonical correlated dispatch");
            case PkiSigningOperation.IssueCredential value -> service.prepareEndEntity(access,
                    new EndEntityIssuanceRequest(value.issuerCaId(), csr(value.requestId()), value.profileId(),
                            Optional.empty()), evidence, cancellation);
            case PkiSigningOperation.RenewCredential value -> service.prepareRenewal(access,
                    new EndEntityRenewalRequest(value.credentialId(), Optional.empty()), evidence, cancellation);
            case PkiSigningOperation.ReplaceCredential value -> service.prepareReplacement(access,
                    new EndEntityReplacementRequest(value.existingCredentialId(), csr(value.requestId()),
                            value.profileId()), evidence, cancellation);
            case PkiSigningOperation.ReissueCredential value -> service.prepareReissue(access,
                    new EndEntityReissueRequest(value.credentialId()), evidence, cancellation);
            case PkiSigningOperation.GenerateStatus value -> {
                if (!"x509".equals(value.formatId().value())) {
                    throw new IllegalArgumentException("Status format is unsupported");
                }
                PkiId issuer = authority(value.issuerCaId()).currentIssuanceIssuerId();
                yield switch (value.type()) {
                    case CRL -> service.prepareFullCrl(access, new FullCrlRequest(issuer, Duration.ofDays(7)),
                            cancellation);
                    case DELTA_CRL -> service.prepareDeltaCrl(access,
                            new DeltaCrlRequest(issuer, Duration.ofDays(7)), cancellation);
                    case OCSP -> throw new PkiException("OCSP_TARGET_REQUIRED");
                };
            }
        };
    }

    private CaRecord authority(PkiId id) {
        return repository.authority(id).orElseThrow();
    }

    private static void requireIssuer(CaRecord authority, Optional<PkiId> issuer) {
        if (authority.kind() == CaKind.ROOT && issuer.isPresent()) {
            throw new PkiException("Root authority must not specify an issuer");
        }
        if (authority.kind() == CaKind.INTERMEDIATE && issuer.isEmpty()) {
            throw new PkiException("Intermediate authority requires an issuer");
        }
    }

    private byte[] csr(PkiId id) {
        CertificationRequestService configuredRequests = requests.orElseThrow(UnsupportedOperationException::new);
        return configuredRequests.encodedRequest(configuredRequests.get(id).orElseThrow()).encoded().bytes();
    }

    @Override
    public PkiOperationResult completedResult(SemanticSigningOperation operation) {
        requireOpen.run();
        Objects.requireNonNull(operation, "operation");
        if (operation.state() != SemanticSigningState.COMPLETED) {
            throw new IllegalArgumentException("Signing operation has not completed");
        }
        EncodedObject result = operation.result().orElseThrow();
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        fields.put("operationId", new PkiOperationValue.Text(operation.submissionId().id().value()));
        fields.put("kind", new PkiOperationValue.Text(operation.scope().kind().name()));
        fields.put("encoding", new PkiOperationValue.Text(result.encoding().name()));
        try {
            fields.put("resultSha256", new PkiOperationValue.Text(HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(result.bytes()))));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
        operation.completedCredentialId().ifPresent(id ->
                fields.put("credentialId", new PkiOperationValue.Text(id.value())));
        service.completedStatusObjectId(operation).ifPresent(id ->
                fields.put("statusObjectId", new PkiOperationValue.Text(id.value())));
        service.completedCaLifecycleMetadata(operation).forEach((key, value) -> fields.put(key, new PkiOperationValue.Text(value)));
        return new PkiOperationResult("signing.operation", fields);
    }

}
