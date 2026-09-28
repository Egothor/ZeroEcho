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
                            EMPTY_ATTRIBUTES), cancellation);
            case PkiSigningOperation.CreateIntermediate value -> service.prepareIntermediateCreation(access,
                    new IntermediateCreateCommand(value.formatId(), value.issuerCaId(), value.subjectRef(),
                            value.profileId(), value.keyRef().orElseThrow(), EMPTY_ATTRIBUTES), cancellation);
            case PkiSigningOperation.IssueIntermediateCertificate value -> service.prepareIntermediateIssuance(access,
                    new IntermediateCertIssueCommand(value.formatId(), value.issuerCaId(), value.subjectCaId(),
                            value.profileId(), authority(value.subjectCaId()).issuerKeyRef(),
                            value.requestedValidity(), EMPTY_ATTRIBUTES), cancellation);
            case PkiSigningOperation.RolloverCaCertificate value -> {
                CaRecord current = authority(value.caId());
                requireIssuer(current, value.issuerCaId());
                CaRolloverCommand command = current.kind() == CaKind.ROOT
                        ? new CaRolloverCommand.Root(value.caId(), Optional.empty(), EMPTY_ATTRIBUTES)
                        : new CaRolloverCommand.Intermediate(value.caId(), value.issuerCaId().orElseThrow(),
                                current.issuerKeyRef(), Optional.empty(), EMPTY_ATTRIBUTES);
                yield service.prepareCaRollover(access, command, cancellation);
            }
            case PkiSigningOperation.RotateCaKey value -> {
                CaRecord current = authority(value.caId());
                requireIssuer(current, value.issuerCaId());
                CaKeyRotationCommand command = current.kind() == CaKind.ROOT
                        ? new CaKeyRotationCommand.Root(value.caId(), value.newKeyRef().orElseThrow(),
                                EMPTY_ATTRIBUTES)
                        : new CaKeyRotationCommand.Intermediate(value.caId(), value.newKeyRef().orElseThrow(),
                                value.issuerCaId().orElseThrow(), EMPTY_ATTRIBUTES);
                yield service.prepareCaKeyRotation(access, command, cancellation);
            }
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
        return new PkiOperationResult("signing.operation", fields);
    }

}
