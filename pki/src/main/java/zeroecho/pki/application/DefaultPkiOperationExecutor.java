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

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiFailureClassification;
import zeroecho.pki.api.PkiFailureReason;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.ca.IntermediateCertIssueCommand;
import zeroecho.pki.api.ca.IntermediateCreateCommand;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.CaService;
import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.IssuanceService;
import zeroecho.pki.api.PublicationService;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.StatusObjectService;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.confirmation.CredentialConfirmationReview;
import zeroecho.pki.api.confirmation.CredentialConfirmationReviewPage;
import zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofChallenge;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofChallengeRequest;
import zeroecho.pki.api.confirmation.CredentialConfirmationService;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialBundle;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;
import zeroecho.pki.api.issuance.VerificationPolicy;
import zeroecho.pki.api.publication.PublicationRequest;
import zeroecho.pki.api.publication.PublicationResult;
import zeroecho.pki.api.publication.PublicationStatus;
import zeroecho.pki.api.publication.PublicationCursor;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.ProofOfPossessionResult;
import zeroecho.pki.api.request.RequestStorePolicy;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.api.revocation.RevocationQuery;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectGenerateCommand;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.RevocationHistory;
import zeroecho.pki.spi.store.RevocationSnapshot;
import zeroecho.pki.impl.core.async.PendingSigningOperation;

/** Explicit non-reflective executor used by one backend session. */
@SuppressWarnings({ "PMD.CouplingBetweenObjects", "PMD.CyclomaticComplexity", "PMD.ExcessiveParameterList",
        "PMD.TooManyMethods" })
final class DefaultPkiOperationExecutor implements PkiOperationExecutor, RevocationEvidenceExecutor {

    private static final String COUNT = "count";
    private static final String CREDENTIAL_ID = "credentialId";
    private static final String AUTHORITY = "authority";
    private static final String AUTHORITY_ID = "caId";
    private static final zeroecho.pki.api.attr.AttributeSet EMPTY_EVIDENCE = new SimpleAttributeSet();
    private static final String FORMAT_ID = "formatId";
    private static final String ISSUER_ID = "issuerId";
    private static final String OPERATION_CANCELLED = "OPERATION_CANCELLED";
    private static final String STATUS = "status";

    private final PkiSessionConfiguration configuration;
    private final PkiStore store;
    private final ProfileService profiles;
    private final RevocationService revocations;
    private final Optional<CaService> authorities;
    private final Optional<CertificationRequestService> requests;
    private final Optional<IssuanceService> issuance;
    private final Optional<StatusObjectService> statusObjects;
    private final Optional<PublicationService> publications;
    private final Optional<CredentialConfirmationService> confirmations;
    private final X509AlgorithmBindingRegistry algorithmBindings;
    private final Runnable openCheck;

    /* default */ DefaultPkiOperationExecutor(PkiSessionConfiguration configuration, PkiStore store,
            ProfileService profiles, RevocationService revocations, Runnable openCheck) {
        this(configuration, store, profiles, revocations, Optional.empty(), Optional.empty(), Optional.empty(),
                Optional.empty(), Optional.empty(), Optional.empty(), defaultBindings(), openCheck);
    }

    /* default */ DefaultPkiOperationExecutor(PkiSessionConfiguration configuration, PkiStore store,
            ProfileService profiles, RevocationService revocations, Optional<CaService> authorities,
            Optional<CertificationRequestService> requests, Optional<IssuanceService> issuance,
            Optional<StatusObjectService> statusObjects, Optional<PublicationService> publications,
            Runnable openCheck) {
        this(configuration, store, profiles, revocations, authorities, requests, issuance, statusObjects,
                publications, Optional.empty(), defaultBindings(), openCheck);
    }

    /* default */ DefaultPkiOperationExecutor(PkiSessionConfiguration configuration, PkiStore store,
            ProfileService profiles, RevocationService revocations, Optional<CaService> authorities,
            Optional<CertificationRequestService> requests, Optional<IssuanceService> issuance,
            Optional<StatusObjectService> statusObjects, Optional<PublicationService> publications,
            Optional<CredentialConfirmationService> confirmations, Runnable openCheck) {
        this(configuration, store, profiles, revocations, authorities, requests, issuance, statusObjects,
                publications, confirmations, defaultBindings(), openCheck);
    }

    /* default */ DefaultPkiOperationExecutor(PkiSessionConfiguration configuration, PkiStore store,
            ProfileService profiles, RevocationService revocations, Optional<CaService> authorities,
            Optional<CertificationRequestService> requests, Optional<IssuanceService> issuance,
            Optional<StatusObjectService> statusObjects, Optional<PublicationService> publications,
            X509AlgorithmBindingRegistry algorithmBindings,
            Runnable openCheck) {
        this(configuration, store, profiles, revocations, authorities, requests, issuance, statusObjects,
                publications, Optional.empty(), algorithmBindings, openCheck);
    }

    /* default */ DefaultPkiOperationExecutor(PkiSessionConfiguration configuration, PkiStore store,
            ProfileService profiles, RevocationService revocations, Optional<CaService> authorities,
            Optional<CertificationRequestService> requests, Optional<IssuanceService> issuance,
            Optional<StatusObjectService> statusObjects, Optional<PublicationService> publications,
            Optional<CredentialConfirmationService> confirmations,
            X509AlgorithmBindingRegistry algorithmBindings, Runnable openCheck) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.store = Objects.requireNonNull(store, "store");
        this.profiles = Objects.requireNonNull(profiles, "profiles");
        this.revocations = Objects.requireNonNull(revocations, "revocations");
        this.authorities = Objects.requireNonNull(authorities, "authorities");
        this.requests = Objects.requireNonNull(requests, "requests");
        this.issuance = Objects.requireNonNull(issuance, "issuance");
        this.statusObjects = Objects.requireNonNull(statusObjects, "statusObjects");
        this.publications = Objects.requireNonNull(publications, "publications");
        this.confirmations = Objects.requireNonNull(confirmations, "confirmations");
        this.algorithmBindings = Objects.requireNonNull(algorithmBindings, "algorithmBindings");
        this.openCheck = Objects.requireNonNull(openCheck, "openCheck");
    }

    @Override
    public PkiOperationOutcome execute(PkiOperation operation, CancellationSignal cancellation) {
        return execute(operation, EMPTY_EVIDENCE, cancellation);
    }

    // The exhaustive typed dispatcher is kept as one method so adding an operation remains compile-time visible.
    @SuppressWarnings("PMD.NcssCount")
    @Override
    public PkiOperationOutcome execute(PkiOperation operation,
            zeroecho.pki.api.attr.AttributeSet issuanceEvidence, CancellationSignal cancellation) {
        openCheck.run();
        PkiOperation exact = Objects.requireNonNull(operation, "operation");
        zeroecho.pki.api.attr.AttributeSet evidence = Objects.requireNonNull(issuanceEvidence, "issuanceEvidence");
        CancellationSignal signal = Objects.requireNonNull(cancellation, "cancellation");
        try {
            signal.throwIfCancelled();
            PkiOperationResult result = switch (exact) {
                case PkiOperation.ListAlgorithmBindings request -> listAlgorithmBindings(request);
                case PkiOperation.InspectAlgorithmBinding request -> inspectAlgorithmBinding(request);
                case PkiOperation.ValidateAlgorithmBindings request -> validateAlgorithmBindings(request);
                case PkiOperation.ValidateConfiguration ignored -> validateConfiguration();
                case PkiOperation.ValidateProfile request -> validateProfile(request);
                case PkiOperation.RegisterProfile request -> registerProfile(request);
                case PkiOperation.InspectProfile request -> inspectProfile(request);
                case PkiOperation.ListProfileVersions request -> listProfileVersions(request);
                case PkiOperation.ActivateProfile request -> activateProfile(request);
                case PkiOperation.InspectAuthority request -> inspectAuthority(request);
                case PkiOperation.ListAuthorities request -> listAuthorities(request);
                case PkiOperation.CreateAuthority request -> createAuthority(request, signal);
                case PkiOperation.TransitionAuthority request -> transitionAuthority(request);
                case PkiOperation.InspectRequest request -> inspectRequest(request);
                case PkiOperation.ImportRequest request -> importRequest(request);
                case PkiOperation.VerifyRequest request -> verifyRequest(request);
                case PkiOperation.InspectCredential request -> inspectCredential(request);
                case PkiOperation.ListPendingCredentialConfirmations request ->
                    listPendingCredentialConfirmations(request);
                case PkiOperation.IssueCredentialConfirmationChallenge request ->
                    issueCredentialConfirmationChallenge(request);
                case PkiOperation.CompleteCredentialConfirmationProof request ->
                    completeCredentialConfirmationProof(request);
                case PkiOperation.RevokePendingCredentialConfirmation request ->
                    revokePendingCredentialConfirmation(request, new SimpleAttributeSet());
                case PkiOperation.IssueCredential request -> issueCredential(request, evidence, signal);
                case PkiOperation.RenewCredential request -> renewCredential(request, evidence, signal);
                case PkiOperation.ReplaceCredential request -> replaceCredential(request, evidence, signal);
                case PkiOperation.ReissueCredential request -> reissueCredential(request, evidence, signal);
                case PkiOperation.RolloverCaCertificate request -> rolloverCaCertificate(request, signal);
                case PkiOperation.RotateCaKey request -> rotateCaKey(request, signal);
                case PkiOperation.RevokeCredential request -> revokeCredential(request);
                case PkiOperation.InspectRevocation request -> inspectRevocation(request);
                case PkiOperation.ReadRevocationHistory request -> readHistory(request, signal);
                case PkiOperation.SnapshotRevocations request -> snapshotRevocations(request, signal);
                case PkiOperation.InspectStatus request -> inspectStatus(request);
                case PkiOperation.ListStatus request -> listStatus(request);
                case PkiOperation.GenerateStatus request -> generateStatus(request, signal);
                case PkiOperation.InspectPublication request -> inspectPublication(request);
                case PkiOperation.ListPublications request -> listPublications(request, signal);
                case PkiOperation.RegisterPublication request -> registerPublication(request);
                case PkiOperation.ProcessPublication request -> processPublication(request);
                case PkiOperation.RetryPublication request -> retryPublication(request);
                case PkiOperation.ReconcilePublication request -> reconcilePublication(request);
                case PkiOperation.CreateIntermediate request -> createIntermediate(request, signal);
                case PkiOperation.IssueIntermediateCertificate request ->
                    issueIntermediateCertificate(request, signal);
                case PkiOperation.InspectIssuerGeneration request -> inspectIssuerGeneration(request);
                case PkiOperation.InspectIssuerChainPath request -> inspectIssuerChainPath(request);
                case PkiOperation.ListIssuerChainPaths request -> listIssuerChainPaths(request);
                case PkiOperation.SelectIssuancePath request -> selectIssuancePath(request);
                case PkiOperation.RegisterIssuerChainPath request -> registerIssuerChainPath(request);
        };
            return new PkiOperationOutcome.Completed(result);
        } catch (PendingSigningOperation pending) {
            return new PkiOperationOutcome.Pending(exact.name(), pending.operationId());
        } catch (InterruptedIOException failure) {
            return failure(exact.name(), PkiOperationFailure.CANCELLED, OPERATION_CANCELLED);
        } catch (IOException failure) {
            return failure(exact.name(), PkiOperationFailure.RESOURCE_FAILURE, "OPERATION_RESOURCE_FAILED");
        } catch (RuntimeException failure) { // NOPMD - normalize provider failures at the application boundary.
            if (signal.isCancelled()) {
                return failure(exact.name(), PkiOperationFailure.CANCELLED, OPERATION_CANCELLED);
            }
            return classify(exact.name(), failure);
        }
    }

    @Override
    public PkiOperationOutcome executeRevocation(PkiOperation.RevokeCredential operation,
            RevocationExecutionEvidence evidence, CancellationSignal cancellation) {
        openCheck.run();
        PkiOperation.RevokeCredential exact = Objects.requireNonNull(operation, "operation");
        RevocationExecutionEvidence exactEvidence = Objects.requireNonNull(evidence, "evidence");
        CancellationSignal signal = Objects.requireNonNull(cancellation, "cancellation");
        try {
            signal.throwIfCancelled();
            return new PkiOperationOutcome.Completed(revokeCredential(exact, exactEvidence.attributes()));
        } catch (InterruptedIOException failure) {
            return failure(exact.name(), PkiOperationFailure.CANCELLED, OPERATION_CANCELLED);
        } catch (RuntimeException failure) { // NOPMD - normalize provider failures at the application boundary.
            if (signal.isCancelled()) {
                return failure(exact.name(), PkiOperationFailure.CANCELLED, OPERATION_CANCELLED);
            }
            return classify(exact.name(), failure);
        }
    }

    @Override
    public PkiOperationOutcome executePendingConfirmationRevocation(
            PkiOperation.RevokePendingCredentialConfirmation operation,
            RevocationExecutionEvidence evidence, CancellationSignal cancellation) {
        openCheck.run();
        PkiOperation.RevokePendingCredentialConfirmation exact = Objects.requireNonNull(
                operation, "operation");
        RevocationExecutionEvidence exactEvidence = Objects.requireNonNull(evidence, "evidence");
        CancellationSignal signal = Objects.requireNonNull(cancellation, "cancellation");
        try {
            signal.throwIfCancelled();
            return new PkiOperationOutcome.Completed(
                    revokePendingCredentialConfirmation(exact, exactEvidence.attributes()));
        } catch (InterruptedIOException failure) {
            return failure(exact.name(), PkiOperationFailure.CANCELLED, OPERATION_CANCELLED);
        } catch (RuntimeException failure) { // NOPMD - normalize store failures at the application boundary.
            if (signal.isCancelled()) {
                return failure(exact.name(), PkiOperationFailure.CANCELLED, OPERATION_CANCELLED);
            }
            return classify(exact.name(), failure);
        }
    }

    private PkiOperationResult listAlgorithmBindings(PkiOperation.ListAlgorithmBindings request) {
        List<PkiOperationValue> values = algorithmBindings.bindings().stream()
                .filter(binding -> request.origin().isEmpty() || binding.origin().name().equals(request.origin().get()))
                .filter(binding -> request.role().isEmpty() || binding.role().name().equals(request.role().get()))
                .limit(request.limit()).map(binding -> (PkiOperationValue) bindingValue(binding)).toList();
        Map<String, PkiOperationValue> fields = fields();
        fields.put(COUNT, integer(values.size()));
        fields.put("registryCommitment", text(algorithmBindings.commitment()));
        fields.put("bindings", new PkiOperationValue.ListValue(values));
        return result(request.name(), fields);
    }

    private PkiOperationResult inspectAlgorithmBinding(PkiOperation.InspectAlgorithmBinding request) {
        X509AlgorithmBinding binding = algorithmBindings.find(request.bindingId())
                .orElseThrow(MissingObjectException::new);
        Map<String, PkiOperationValue> fields = fields();
        fields.putAll(bindingValue(binding).fields());
        fields.put("registryCommitment", text(algorithmBindings.commitment()));
        return result(request.name(), fields);
    }

    private PkiOperationResult validateAlgorithmBindings(PkiOperation.ValidateAlgorithmBindings request) {
        request.bindingId().ifPresent(bindingId -> algorithmBindings.require(bindingId,
                request.expectedCommitment().orElseThrow()));
        Map<String, PkiOperationValue> fields = fields();
        fields.put("valid", bool(true));
        fields.put(COUNT, integer(algorithmBindings.bindings().size()));
        fields.put("registryCommitment", text(algorithmBindings.commitment()));
        return result(request.name(), fields);
    }

    private static PkiOperationValue.ObjectValue bindingValue(X509AlgorithmBinding binding) {
        Map<String, PkiOperationValue> fields = fields();
        fields.put("bindingId", text(binding.bindingId()));
        fields.put("algorithmId", text(binding.algorithmIdentity().canonicalForm()));
        fields.put("role", text(binding.role().name()));
        fields.put("oid", text(binding.oid()));
        fields.put("origin", text(binding.origin().name()));
        fields.put("encodingVersion", integer(binding.encodingVersion()));
        fields.put("parameterRule", text(binding.parameterRule().name()));
        fields.put("publicKeyEncoding", text(binding.publicKeyEncoding().name()));
        fields.put("signatureEncoding", text(binding.signatureEncoding().name()));
        fields.put("interoperability", text(binding.interoperability().name()));
        fields.put("bindingCommitment", text(binding.semanticCommitment()));
        binding.providerId().ifPresent(value -> fields.put("providerId", text(value)));
        return new PkiOperationValue.ObjectValue(fields);
    }

    private static X509AlgorithmBindingRegistry defaultBindings() {
        List<X509AlgorithmBinding> descriptors = new ArrayList<>(
                zeroecho.pki.impl.framework.x509.StandardX509Bindings.descriptors());
        descriptors.addAll(zeroecho.pki.impl.framework.x509.ZeroEchoPrivateX509Bindings.descriptors());
        return zeroecho.pki.impl.framework.x509.ImmutableX509AlgorithmBindingRegistry.create(descriptors);
    }

    private PkiOperationResult validateConfiguration() {
        Map<String, PkiOperationValue> fields = fields();
        fields.put("version", integer(configuration.version()));
        fields.put("storeProvider", text(configuration.store().backendId()));
        fields.put("auditProvider", text(configuration.audit().backendId()));
        return result(PkiOperation.ValidateConfiguration.NAME, fields);
    }

    private PkiOperationResult validateProfile(PkiOperation.ValidateProfile request) {
        CertificateProfileDefinition definition = CertificateProfileDocumentCodec.parse(request.document());
        validateProfileBindings(definition.algorithmBindingPolicy());
        Map<String, PkiOperationValue> fields = fields();
        fields.put("profileId", text(definition.profileId()));
        fields.put("profileVersion", integer(definition.profileVersion()));
        fields.put("certificateType", text(definition.certificateType().name()));
        fields.put(FORMAT_ID, text(definition.formatId().value()));
        return result(request.name(), fields);
    }

    private void validateProfileBindings(X509AlgorithmBindingPolicy policy) {
        if (policy.mode() == X509AlgorithmBindingPolicy.Mode.STANDARD_ONLY) {
            return;
        }
        validateProfileBinding(policy.subjectPublicKey(), X509AlgorithmBinding.Role.SUBJECT_PUBLIC_KEY);
        validateProfileBinding(policy.csrSignature(), X509AlgorithmBinding.Role.CSR_SIGNATURE);
        validateProfileBinding(policy.certificateSignature(), X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE);
        validateProfileBinding(policy.crlSignature(), X509AlgorithmBinding.Role.CRL_SIGNATURE);
    }

    private void validateProfileBinding(Optional<X509AlgorithmBindingPolicy.BindingReference> reference,
            X509AlgorithmBinding.Role role) {
        reference.ifPresent(value -> {
            X509AlgorithmBinding binding = algorithmBindings.require(value.bindingId(), value.semanticCommitment());
            if (binding.role() != role || binding.origin() == X509AlgorithmBinding.Origin.STANDARD) {
                throw new IllegalArgumentException("Explicit profile binding is invalid for its role");
            }
        });
    }

    private PkiOperationResult registerProfile(PkiOperation.RegisterProfile request) {
        CertificateProfileRef reference = profiles.importProfile(request.document());
        return profileReferenceResult(request.name(), reference);
    }

    private PkiOperationResult inspectProfile(PkiOperation.InspectProfile request) {
        ImportedCertificateProfileVersion version = profiles
                .getImportedVersion(request.profileId(), request.profileVersion())
                .orElseThrow(MissingObjectException::new);
        return profileVersionResult(request.name(), version);
    }

    private PkiOperationResult listProfileVersions(PkiOperation.ListProfileVersions request) {
        List<PkiOperationValue> versions = profiles.listImportedVersions(request.profileId()).stream()
                .map(DefaultPkiOperationExecutor::profileVersionValue).toList();
        Map<String, PkiOperationValue> fields = fields();
        fields.put("profileId", text(request.profileId()));
        fields.put(COUNT, integer(versions.size()));
        profiles.getActiveReference(request.profileId())
                .ifPresent(reference -> fields.put("activeVersion", integer(reference.profileVersion())));
        fields.put("versions", new PkiOperationValue.ListValue(versions));
        return result(request.name(), fields);
    }

    private PkiOperationResult activateProfile(PkiOperation.ActivateProfile request) {
        CertificateProfileRef reference = profiles.activateProfile(request.profileId(), request.profileVersion());
        return profileReferenceResult(request.name(), reference);
    }

    private PkiOperationResult inspectAuthority(PkiOperation.InspectAuthority request) {
        return authorityResult(request.name(), store.getCa(request.caId()).orElseThrow(MissingObjectException::new));
    }

    private PkiOperationResult listAuthorities(PkiOperation.ListAuthorities request) {
        List<CaRecord> records = store.listCas();
        int count = Math.min(records.size(), request.limit());
        List<PkiOperationValue> values = records.subList(0, count).stream()
                .map(DefaultPkiOperationExecutor::authorityValue).toList();
        Map<String, PkiOperationValue> fields = fields();
        fields.put(COUNT, integer(count));
        fields.put("truncated", bool(records.size() > count));
        fields.put("authorities", new PkiOperationValue.ListValue(values));
        return result(request.name(), fields);
    }

    private PkiOperationResult createAuthority(PkiOperation.CreateAuthority request,
            CancellationSignal cancellation) {
        CaCreateCommand command = new CaCreateCommand(request.formatId(), request.subjectRef(), request.profileId(),
                Optional.of(request.keyRef()), new SimpleAttributeSet());
        PkiId caId = requireCapability(authorities, AUTHORITY).createRoot(command, cancellation);
        Map<String, PkiOperationValue> fields = fields();
        fields.put(AUTHORITY_ID, text(caId.value()));
        fields.put("state", text(store.getCa(caId).orElseThrow(MissingObjectException::new).state().name()));
        return result(request.name(), fields);
    }

    private PkiOperationResult transitionAuthority(PkiOperation.TransitionAuthority request) {
        requireCapability(authorities, AUTHORITY).setCaState(request.caId(), request.state(), request.reason());
        return authorityResult(request.name(), store.getCa(request.caId()).orElseThrow(MissingObjectException::new));
    }

    private PkiOperationResult inspectRequest(PkiOperation.InspectRequest request) {
        ParsedCertificationRequest parsed = store.getRequest(request.requestId())
                .orElseThrow(MissingObjectException::new);
        Map<String, PkiOperationValue> fields = fields();
        fields.put("requestId", text(parsed.requestId().value()));
        fields.put(FORMAT_ID, text(parsed.formatId().value()));
        fields.put("publicKeyBytes", integer(parsed.publicKeyInfo().bytes().length));
        parsed.requestedProfileId().ifPresent(value -> fields.put("requestedProfileId", text(value)));
        fields.put("subjectAlternativeNameCount", integer(parsed.subjectAlternativeNames().size()));
        return result(request.name(), fields);
    }

    private PkiOperationResult importRequest(PkiOperation.ImportRequest request) {
        CertificationRequest encoded = new CertificationRequest(request.formatId(), request.encoded());
        CertificationRequestService service = requireCapability(requests, "certification-request");
        ParsedCertificationRequest parsed = service.parse(encoded);
        PkiId requestId = service.store(parsed, RequestStorePolicy.STORE_ALWAYS);
        Map<String, PkiOperationValue> fields = fields();
        fields.put("requestId", text(requestId.value()));
        fields.put(FORMAT_ID, text(parsed.formatId().value()));
        return result(request.name(), fields);
    }

    private PkiOperationResult verifyRequest(PkiOperation.VerifyRequest request) {
        CertificationRequestService service = requireCapability(requests, "certification-request");
        ParsedCertificationRequest parsed = service.get(request.requestId()).orElseThrow(MissingObjectException::new);
        ProofOfPossessionResult proof = service.verifyProofOfPossession(parsed,
                new VerificationPolicy(true, Optional.empty()));
        Map<String, PkiOperationValue> fields = fields();
        fields.put("requestId", text(request.requestId().value()));
        fields.put("proofStatus", text(proof.status().name()));
        return result(request.name(), fields);
    }

    private PkiOperationResult inspectCredential(PkiOperation.InspectCredential request) {
        Credential credential = store.getCredential(request.credentialId())
                .orElseThrow(() -> new MissingObjectException());
        CertificateProfileRef profile = profileReference(credential);
        Map<String, PkiOperationValue> fields = fields();
        fields.put(CREDENTIAL_ID, text(credential.credentialId().value()));
        fields.put(FORMAT_ID, text(credential.formatId().value()));
        fields.put("authorityId", text(credential.issuerRef().caId().value()));
        fields.put(ISSUER_ID, text(credential.issuerRef().issuerId().value()));
        fields.put("publicKeyId", text(credential.publicKeyId().value()));
        fields.put("profileId", text(profile.profileId()));
        fields.put("profileVersion", integer(profile.profileVersion()));
        fields.put(STATUS, text(credential.status().name()));
        fields.put("notBefore", text(credential.validity().notBefore().toString()));
        fields.put("notAfter", text(credential.validity().notAfter().toString()));
        return result(request.name(), fields);
    }

    private PkiOperationResult listPendingCredentialConfirmations(
            PkiOperation.ListPendingCredentialConfirmations request) {
        CredentialConfirmationReviewPage page = requireCapability(confirmations, "credential-confirmation")
                .pagePendingReviews(request.authorityId(), request.profileId(), request.cutoffInclusive(),
                        request.afterExclusive(), request.limit());
        List<PkiOperationValue> values = page.reviews().stream()
                .map(DefaultPkiOperationExecutor::confirmationReviewValue)
                .map(PkiOperationValue.class::cast).toList();
        Map<String, PkiOperationValue> fields = fields();
        fields.put(COUNT, integer(values.size()));
        fields.put("reviews", new PkiOperationValue.ListValue(values));
        page.nextCursor().ifPresent(cursor -> fields.put("nextCursor", text(cursor.value())));
        fields.put("cutoffInclusive", text(request.cutoffInclusive().toString()));
        return result(request.name(), fields);
    }

    private static PkiOperationValue.ObjectValue confirmationReviewValue(
            CredentialConfirmationReview review) {
        Map<String, PkiOperationValue> fields = fields();
        fields.put(CREDENTIAL_ID, text(review.credentialId().value()));
        fields.put("authorityId", text(review.authorityId().value()));
        fields.put("profileId", text(review.profileId()));
        fields.put("confirmationReviewAt", text(review.confirmationReviewAt().toString()));
        fields.put("initialDisclosurePolicy", text(review.initialDisclosurePolicy().name()));
        return new PkiOperationValue.ObjectValue(fields);
    }

    private PkiOperationResult issueCredentialConfirmationChallenge(
            PkiOperation.IssueCredentialConfirmationChallenge request) {
        CredentialConfirmationService service = requireCapability(confirmations, "credential-confirmation");
        CredentialConfirmationLifecycle lifecycle = service.get(request.credentialId())
                .orElseThrow(MissingObjectException::new);
        if (lifecycle.state() != CredentialConfirmationLifecycle.State.PENDING) {
            throw new OperationConflictException();
        }
        CredentialConfirmationProofChallenge challenge;
        try {
            challenge = service.issueProofChallenge(new CredentialConfirmationProofChallengeRequest(
                    request.credentialId(), lifecycle.revision(), lifecycle.recordCommitment()));
        } catch (IllegalArgumentException | IllegalStateException failure) {
            CredentialConfirmationLifecycle current = service.get(request.credentialId())
                    .orElseThrow(MissingObjectException::new);
            if (current.state() != CredentialConfirmationLifecycle.State.PENDING
                    || current.revision() != lifecycle.revision()
                    || !current.recordCommitment().equals(lifecycle.recordCommitment())) {
                throw new OperationConflictException(failure);
            }
            throw failure;
        }
        Map<String, PkiOperationValue> fields = fields();
        fields.put(CREDENTIAL_ID, text(challenge.proofCas().credentialId().value()));
        fields.put("expectedLifecycleRevision", integer(challenge.proofCas().expectedLifecycleRevision()));
        fields.put("expectedLifecycleRecordCommitment",
                text(challenge.proofCas().expectedLifecycleRecordCommitment()));
        fields.put("expectedChallengeRecordCommitment",
                text(challenge.proofCas().expectedChallengeRecordCommitment()));
        fields.put("proofSuiteId", text(challenge.proofSuiteBinding().proofSuiteRef().suiteId()));
        fields.put("proofSuiteConfigurationCommitment",
                text(challenge.proofSuiteBinding().proofSuiteRef().configurationCommitment()));
        fields.put("rsaMaximumModulusBits",
                integer(challenge.proofSuiteBinding().rsaMaximumModulusBits()));
        fields.put("expiresAt", text(challenge.expiresAt().toString()));
        fields.put("maximumResponseBytes", integer(challenge.maximumResponseBytes()));
        fields.put("presentation", text(Base64.getUrlEncoder().withoutPadding()
                .encodeToString(challenge.presentation())));
        return result(request.name(), fields);
    }

    private PkiOperationResult completeCredentialConfirmationProof(
            PkiOperation.CompleteCredentialConfirmationProof request) {
        zeroecho.pki.api.confirmation.CredentialConfirmationProofResult confirmationResult =
                requireCapability(confirmations, "credential-confirmation")
                        .verifyAndComplete(request.submission());
        Map<String, PkiOperationValue> fields = fields();
        fields.put("confirmationResult", text(confirmationResult.name()));
        return result(request.name(), fields);
    }

    private PkiOperationResult issueCredential(PkiOperation.IssueCredential request,
            zeroecho.pki.api.attr.AttributeSet evidence, CancellationSignal cancellation) {
        ParsedCertificationRequest parsed = requireCapability(requests, "certification-request")
                .get(request.requestId()).orElseThrow(MissingObjectException::new);
        IssueEndEntityCommand command = new IssueEndEntityCommand(request.issuerCaId(), parsed, request.profileId(),
                Optional.empty());
        CredentialBundle bundle = requireCapability(issuance, "issuance")
                .issueEndEntity(command, evidence, cancellation);
        return credentialResult(request.name(), bundle);
    }

    private PkiOperationResult renewCredential(PkiOperation.RenewCredential request,
            zeroecho.pki.api.attr.AttributeSet evidence, CancellationSignal cancellation) {
        CredentialBundle bundle = requireCapability(issuance, "issuance").renew(
                new zeroecho.pki.api.issuance.RenewCommand(request.credentialId(), Optional.empty(), evidence),
                cancellation);
        return credentialResult(request.name(), bundle);
    }

    private PkiOperationResult replaceCredential(PkiOperation.ReplaceCredential request,
            zeroecho.pki.api.attr.AttributeSet evidence, CancellationSignal cancellation) {
        ParsedCertificationRequest parsed = requireCapability(requests, "certification-request")
                .get(request.requestId()).orElseThrow(MissingObjectException::new);
        CredentialBundle bundle = requireCapability(issuance, "issuance").replace(
                new zeroecho.pki.api.issuance.ReplaceCommand(request.existingCredentialId(), parsed,
                        request.profileId(), evidence),
                cancellation);
        return credentialResult(request.name(), bundle);
    }

    private PkiOperationResult reissueCredential(PkiOperation.ReissueCredential request,
            zeroecho.pki.api.attr.AttributeSet evidence, CancellationSignal cancellation) {
        CredentialBundle bundle = requireCapability(issuance, "issuance").reissue(
                new zeroecho.pki.api.issuance.ReissueCommand(request.credentialId(), evidence),
                cancellation);
        return credentialResult(request.name(), bundle);
    }

    private PkiOperationResult rolloverCaCertificate(PkiOperation.RolloverCaCertificate request,
            CancellationSignal cancellation) {
        PkiId caId = requireCapability(authorities, AUTHORITY).rolloverCaCertificate(
                new zeroecho.pki.api.ca.CaRolloverCommand(request.caId(), request.issuerCaId(), Optional.empty(),
                        new SimpleAttributeSet()),
                cancellation);
        Map<String, PkiOperationValue> fields = fields();
        fields.put(AUTHORITY_ID, text(caId.value()));
        return result(request.name(), fields);
    }

    private PkiOperationResult rotateCaKey(PkiOperation.RotateCaKey request, CancellationSignal cancellation) {
        PkiId caId = requireCapability(authorities, AUTHORITY).rotateCaKey(
                new zeroecho.pki.api.ca.CaKeyRotationCommand(request.caId(), request.newKeyRef(), request.issuerCaId(),
                        new SimpleAttributeSet()),
                cancellation);
        Map<String, PkiOperationValue> fields = fields();
        fields.put(AUTHORITY_ID, text(caId.value()));
        return result(request.name(), fields);
    }

    private PkiOperationResult createIntermediate(PkiOperation.CreateIntermediate request,
            CancellationSignal cancellation) {
        IntermediateCreateCommand command = new IntermediateCreateCommand(request.formatId(), request.issuerCaId(),
                request.subjectRef(), request.profileId(), request.keyRef(), new SimpleAttributeSet());
        PkiId caId = requireCapability(authorities, AUTHORITY).createIntermediate(command, cancellation);
        Map<String, PkiOperationValue> fields = fields();
        fields.put(AUTHORITY_ID, text(caId.value()));
        fields.put("issuerCaId", text(request.issuerCaId().value()));
        fields.put("state", text(store.getCa(caId).orElseThrow(MissingObjectException::new).state().name()));
        return result(request.name(), fields);
    }

    private PkiOperationResult issueIntermediateCertificate(PkiOperation.IssueIntermediateCertificate request,
            CancellationSignal cancellation) {
        IntermediateCertIssueCommand command = new IntermediateCertIssueCommand(request.formatId(),
                request.issuerCaId(), request.subjectCaId(), request.profileId(), request.requestedValidity(),
                new SimpleAttributeSet());
        Credential credential = requireCapability(authorities, AUTHORITY)
                .issueIntermediateCertificate(command, cancellation);
        Map<String, PkiOperationValue> fields = fields();
        fields.put(CREDENTIAL_ID, text(credential.credentialId().value()));
        fields.put("issuerCaId", text(credential.issuerRef().caId().value()));
        fields.put(ISSUER_ID, text(credential.issuerRef().issuerId().value()));
        fields.put("subjectCaId", text(request.subjectCaId().value()));
        fields.put(STATUS, text(credential.status().name()));
        return result(request.name(), fields);
    }

    private PkiOperationResult inspectIssuerGeneration(PkiOperation.InspectIssuerGeneration request) {
        IssuerGeneration generation = requireCapability(authorities, AUTHORITY)
                .getIssuerGeneration(request.issuerId());
        Map<String, PkiOperationValue> fields = fields();
        fields.put(ISSUER_ID, text(generation.issuerId().value()));
        fields.put("authorityId", text(generation.authorityId().value()));
        fields.put(CREDENTIAL_ID, text(generation.credentialId().value()));
        fields.put("state", text(generation.state().name()));
        fields.put("profilePolicyCommitment", text(generation.profilePolicyCommitment()));
        fields.put("x509BindingCommitment", text(generation.x509BindingCommitment()));
        return result(request.name(), fields);
    }

    private PkiOperationResult inspectIssuerChainPath(PkiOperation.InspectIssuerChainPath request) {
        IssuerChainPath path = requireCapability(authorities, AUTHORITY).getIssuerChainPath(request.pathId());
        return result(request.name(), chainPathFields(path));
    }

    private PkiOperationResult listIssuerChainPaths(PkiOperation.ListIssuerChainPaths request) {
        List<IssuerChainPath> paths = requireCapability(authorities, AUTHORITY)
                .listIssuerChainPaths(request.issuerId());
        List<PkiOperationValue> values = paths.stream()
                .map(path -> (PkiOperationValue) new PkiOperationValue.ObjectValue(chainPathFields(path))).toList();
        Map<String, PkiOperationValue> fields = fields();
        fields.put(ISSUER_ID, text(request.issuerId().value()));
        fields.put(COUNT, integer(values.size()));
        fields.put("paths", new PkiOperationValue.ListValue(values));
        return result(request.name(), fields);
    }

    private PkiOperationResult selectIssuancePath(PkiOperation.SelectIssuancePath request) {
        requireCapability(authorities, AUTHORITY).selectIssuancePath(request.caId(), request.issuerId(),
                request.pathId(), request.reason());
        Map<String, PkiOperationValue> fields = fields();
        fields.put(AUTHORITY_ID, text(request.caId().value()));
        fields.put(ISSUER_ID, text(request.issuerId().value()));
        fields.put("pathId", text(request.pathId().value()));
        return result(request.name(), fields);
    }

    private PkiOperationResult registerIssuerChainPath(PkiOperation.RegisterIssuerChainPath request) {
        IssuerChainPath path = requireCapability(authorities, AUTHORITY)
                .registerIssuerChainPath(request.caId(), request.issuerId(), request.parentPathId());
        return result(request.name(), chainPathFields(path));
    }

    private static Map<String, PkiOperationValue> chainPathFields(IssuerChainPath path) {
        Map<String, PkiOperationValue> fields = fields();
        fields.put("pathId", text(path.pathId().value()));
        fields.put("authorityId", text(path.authorityId().value()));
        fields.put(ISSUER_ID, text(path.issuerId().value()));
        fields.put("pathCommitment", text(path.pathCommitment()));
        List<PkiOperationValue> ordered = path.orderedCredentialIds().stream()
                .<PkiOperationValue>map(id -> text(id.value())).toList();
        fields.put("orderedCredentialIds", new PkiOperationValue.ListValue(ordered));
        fields.put(COUNT, integer(ordered.size()));
        return fields;
    }

    private PkiOperationResult credentialResult(String name, CredentialBundle bundle) {
        Map<String, PkiOperationValue> fields = fields();
        fields.put(CREDENTIAL_ID, text(bundle.credential().credentialId().value()));
        fields.put("issuerCaId", text(bundle.credential().issuerRef().caId().value()));
        fields.put("supportingObjectCount", integer(bundle.supportingObjects().size()));
        return result(name, fields);
    }

    private PkiOperationResult revokeCredential(PkiOperation.RevokeCredential request) {
        return revokeCredential(request, new SimpleAttributeSet());
    }

    private PkiOperationResult revokeCredential(PkiOperation.RevokeCredential request,
            zeroecho.pki.api.attr.AttributeSet attributes) {
        RevocationCommand.RevokePermanently command = new RevocationCommand.RevokePermanently(request.credentialId(),
                request.reason(), attributes);
        RevocationRecord record = revocations.revokePermanently(command);
        return revocationResult(request.name(), record);
    }

    private PkiOperationResult revokePendingCredentialConfirmation(
            PkiOperation.RevokePendingCredentialConfirmation request,
            zeroecho.pki.api.attr.AttributeSet attributes) {
        RevocationCommand.RevokePermanently command = new RevocationCommand.RevokePermanently(
                request.credentialId(), zeroecho.pki.api.revocation.RevocationReason.UNSPECIFIED,
                attributes);
        RevocationRecord record = revocations.revokeOverduePendingConfirmation(command);
        return revocationResult(request.name(), record);
    }

    private PkiOperationResult inspectRevocation(PkiOperation.InspectRevocation request) {
        RevocationRecord record = revocations.get(request.credentialId()).orElseThrow(MissingObjectException::new);
        return revocationResult(request.name(), record);
    }

    private PkiOperationResult readHistory(PkiOperation.ReadRevocationHistory request, CancellationSignal signal)
            throws IOException {
        List<PkiOperationValue> transitions = new ArrayList<>();
        boolean truncated;
        try (RevocationHistory history = revocations.history(request.credentialId())) {
            while (transitions.size() < request.limit() && history.next(signal)) {
                transitions.add(transitionValue(history.current()));
            }
            truncated = transitions.size() == request.limit() && history.next(signal);
        }
        Map<String, PkiOperationValue> fields = fields();
        fields.put(CREDENTIAL_ID, text(request.credentialId().value()));
        fields.put(COUNT, integer(transitions.size()));
        fields.put("truncated", bool(truncated));
        fields.put("transitions", new PkiOperationValue.ListValue(transitions));
        return result(request.name(), fields);
    }

    private PkiOperationResult inspectPublication(PkiOperation.InspectPublication request) {
        PublicationRecord record = store.getPublicationRecord(request.publicationId())
                .orElseThrow(() -> new MissingObjectException());
        Map<String, PkiOperationValue> fields = fields();
        fields.put("publicationId", text(record.publicationId().value()));
        fields.put("sourceType", text(record.sourceType().name()));
        fields.put("sourceId", text(record.sourceId().value()));
        fields.put(STATUS, text(record.status().name()));
        fields.put("attemptNumber", integer(record.attemptNumber()));
        fields.put("createdAt", text(record.createdAt().toString()));
        fields.put("updatedAt", text(record.updatedAt().toString()));
        record.failure().ifPresent(value -> fields.put("failure", text(value.name())));
        record.evidence().ifPresent(value -> fields.put("evidence", text(value.name())));
        return result(request.name(), fields);
    }

    private PkiOperationResult snapshotRevocations(PkiOperation.SnapshotRevocations request,
            CancellationSignal signal) throws IOException {
        List<PkiOperationValue> records = new ArrayList<>();
        boolean truncated;
        Map<String, PkiOperationValue> fields = fields();
        RevocationQuery query = new RevocationQuery(Optional.empty(), Optional.empty(), Optional.empty(),
                Optional.empty());
        try (RevocationSnapshot snapshot = revocations.search(query);
                RevocationSnapshot.Cursor cursor = snapshot.openCursor()) {
            while (records.size() < request.limit() && cursor.next(signal)) {
                records.add(revocationValue(cursor.current()));
            }
            truncated = records.size() == request.limit() && cursor.next(signal);
            fields.put("snapshotId", text(snapshot.snapshotId()));
            fields.put("revision", integer(snapshot.revision()));
            fields.put("boundary", integer(snapshot.boundary()));
            fields.put("commitment", text(snapshot.commitment()));
        }
        fields.put(COUNT, integer(records.size()));
        fields.put("truncated", bool(truncated));
        fields.put("records", new PkiOperationValue.ListValue(records));
        return result(request.name(), fields);
    }

    private PkiOperationResult inspectStatus(PkiOperation.InspectStatus request) {
        StatusObject object = store.getStatusObject(request.statusObjectId())
                .orElseThrow(MissingObjectException::new);
        return statusResult(request.name(), object);
    }

    private PkiOperationResult generateStatus(PkiOperation.GenerateStatus request,
            CancellationSignal cancellation) {
        StatusObjectGenerateCommand command = new StatusObjectGenerateCommand(request.issuerCaId(), request.type(),
                request.formatId(), new SimpleAttributeSet());
        StatusObject object = requireCapability(statusObjects, "status-object").generate(command, cancellation);
        return statusResult(request.name(), object);
    }

    private PkiOperationResult listStatus(PkiOperation.ListStatus request) {
        List<StatusObject> records = store.listStatusObjects(request.issuerCaId());
        int count = Math.min(records.size(), request.limit());
        List<PkiOperationValue> values = records.subList(0, count).stream()
                .map(DefaultPkiOperationExecutor::statusValue).toList();
        Map<String, PkiOperationValue> fields = fields();
        fields.put("issuerCaId", text(request.issuerCaId().value()));
        fields.put(COUNT, integer(count));
        fields.put("truncated", bool(records.size() > count));
        fields.put("statusObjects", new PkiOperationValue.ListValue(values));
        return result(request.name(), fields);
    }

    private PkiOperationResult listPublications(PkiOperation.ListPublications request, CancellationSignal signal)
            throws IOException {
        List<PkiOperationValue> records = new ArrayList<>();
        boolean truncated;
        try (PublicationCursor cursor = store.openPublicationRecords()) {
            Optional<PublicationRecord> next = cursor.next(signal);
            while (records.size() < request.limit() && next.isPresent()) {
                records.add(publicationValue(next.orElseThrow()));
                next = cursor.next(signal);
            }
            truncated = next.isPresent();
        }
        Map<String, PkiOperationValue> fields = fields();
        fields.put(COUNT, integer(records.size()));
        fields.put("truncated", bool(truncated));
        fields.put("publications", new PkiOperationValue.ListValue(records));
        return result(request.name(), fields);
    }

    private PkiOperationResult registerPublication(PkiOperation.RegisterPublication request) {
        PublicationRequest registration = new PublicationRequest(request.publicationId(), request.sourceType(),
                request.sourceId(), request.target());
        PublicationRecord record = requireCapability(publications, "publication").register(registration);
        return publicationRecordResult(request.name(), record);
    }

    private PkiOperationResult processPublication(PkiOperation.ProcessPublication request) {
        return publicationResult(request.name(),
                requireCapability(publications, "publication").process(request.publicationId()));
    }

    private PkiOperationResult retryPublication(PkiOperation.RetryPublication request) {
        return publicationResult(request.name(),
                requireCapability(publications, "publication").retry(request.publicationId()));
    }

    private PkiOperationResult reconcilePublication(PkiOperation.ReconcilePublication request) {
        return publicationResult(request.name(),
                requireCapability(publications, "publication").reconcile(request.publicationId()));
    }

    private static PkiOperationResult publicationResult(String operation, PublicationResult publication) {
        if (publication.status() == PublicationStatus.OUTCOME_UNKNOWN) {
            throw new ExternalOutcomeUnknownException();
        }
        Map<String, PkiOperationValue> fields = fields();
        fields.put("publicationId", text(publication.publicationId().value()));
        fields.put(STATUS, text(publication.status().name()));
        fields.put("attemptNumber", integer(publication.attemptNumber()));
        return result(operation, fields);
    }

    private static PkiOperationResult publicationRecordResult(String operation, PublicationRecord publication) {
        Map<String, PkiOperationValue> fields = fields();
        fields.put("publicationId", text(publication.publicationId().value()));
        fields.put(STATUS, text(publication.status().name()));
        fields.put("attemptNumber", integer(publication.attemptNumber()));
        return result(operation, fields);
    }

    private static <T> T requireCapability(Optional<T> service, String capability) {
        return service.orElseThrow(() -> new CapabilityUnavailableException(capability));
    }

    private static PkiOperationResult revocationResult(String operation, RevocationRecord record) {
        Map<String, PkiOperationValue> fields = fields();
        fields.put(CREDENTIAL_ID, text(record.credentialId().value()));
        appendTransition(fields, record.transition());
        return result(operation, fields);
    }

    private static PkiOperationResult profileReferenceResult(String operation, CertificateProfileRef reference) {
        Map<String, PkiOperationValue> fields = fields();
        appendProfileReference(fields, reference);
        return result(operation, fields);
    }

    private static PkiOperationResult profileVersionResult(String operation,
            ImportedCertificateProfileVersion version) {
        Map<String, PkiOperationValue> fields = fields();
        appendProfileVersion(fields, version);
        return result(operation, fields);
    }

    private static PkiOperationValue profileVersionValue(ImportedCertificateProfileVersion version) {
        Map<String, PkiOperationValue> fields = fields();
        appendProfileVersion(fields, version);
        return new PkiOperationValue.ObjectValue(fields);
    }

    private static void appendProfileVersion(Map<String, PkiOperationValue> fields,
            ImportedCertificateProfileVersion version) {
        appendProfileReference(fields, version.reference());
        fields.put("certificateType", text(version.definition().certificateType().name()));
        fields.put(FORMAT_ID, text(version.definition().formatId().value()));
        fields.put("importedAt", text(version.importedAt().toString()));
    }

    private static void appendProfileReference(Map<String, PkiOperationValue> fields,
            CertificateProfileRef reference) {
        fields.put("profileId", text(reference.profileId()));
        fields.put("profileVersion", integer(reference.profileVersion()));
        fields.put("fingerprint", text(reference.shortFingerprint()));
    }

    private static PkiOperationResult authorityResult(String operation, CaRecord record) {
        return result(operation, authorityFields(record));
    }

    private static PkiOperationValue authorityValue(CaRecord record) {
        return new PkiOperationValue.ObjectValue(authorityFields(record));
    }

    private static Map<String, PkiOperationValue> authorityFields(CaRecord record) {
        Map<String, PkiOperationValue> fields = fields();
        fields.put(AUTHORITY_ID, text(record.caId().value()));
        fields.put("kind", text(record.kind().name()));
        fields.put("state", text(record.state().name()));
        fields.put("issuerGenerationCount", integer(record.issuerIds().size()));
        fields.put("currentIssuanceIssuerId", text(record.currentIssuanceIssuerId().value()));
        return fields;
    }

    private static PkiOperationValue revocationValue(RevocationRecord record) {
        Map<String, PkiOperationValue> fields = fields();
        fields.put(CREDENTIAL_ID, text(record.credentialId().value()));
        appendTransition(fields, record.transition());
        return new PkiOperationValue.ObjectValue(fields);
    }

    private static PkiOperationResult statusResult(String operation, StatusObject object) {
        return result(operation, statusFields(object));
    }

    private static PkiOperationValue statusValue(StatusObject object) {
        return new PkiOperationValue.ObjectValue(statusFields(object));
    }

    private static Map<String, PkiOperationValue> statusFields(StatusObject object) {
        Map<String, PkiOperationValue> fields = fields();
        fields.put("statusObjectId", text(object.statusObjectId().value()));
        fields.put("issuerCaId", text(object.issuerCaId().value()));
        fields.put("type", text(object.type().name()));
        fields.put(FORMAT_ID, text(object.formatId().value()));
        fields.put("thisUpdate", text(object.thisUpdate().toString()));
        object.nextUpdate().ifPresent(value -> fields.put("nextUpdate", text(value.toString())));
        fields.put("contentLength", integer(object.content().length()));
        fields.put("contentSha256", text(object.content().sha256()));
        return fields;
    }

    private static PkiOperationValue publicationValue(PublicationRecord record) {
        Map<String, PkiOperationValue> fields = fields();
        fields.put("publicationId", text(record.publicationId().value()));
        fields.put("sourceType", text(record.sourceType().name()));
        fields.put("sourceId", text(record.sourceId().value()));
        fields.put(STATUS, text(record.status().name()));
        fields.put("attemptNumber", integer(record.attemptNumber()));
        return new PkiOperationValue.ObjectValue(fields);
    }

    private static PkiOperationValue transitionValue(RevocationTransition transition) {
        Map<String, PkiOperationValue> fields = fields();
        appendTransition(fields, transition);
        return new PkiOperationValue.ObjectValue(fields);
    }

    private static void appendTransition(Map<String, PkiOperationValue> fields, RevocationTransition transition) {
        fields.put("revision", integer(transition.revision()));
        fields.put("state", text(transition.state().name()));
        fields.put("time", text(transition.time().toString()));
        transition.permanentReason().ifPresent(reason -> fields.put("reason", text(reason.name())));
    }

    private static CertificateProfileRef profileReference(Credential credential) {
        if (credential.profileBinding() instanceof EndEntityProfileBinding binding) {
            return binding.reference();
        }
        if (credential.profileBinding() instanceof CaProfileBinding binding) {
            return binding.reference();
        }
        throw new IllegalStateException("Credential profile binding is unsupported");
    }

    private static PkiOperationOutcome classify(String operation, RuntimeException failure) {
        if (failure instanceof zeroecho.pki.api.SigningExecutionException signingFailure
                && signingFailure.classification()
                        == zeroecho.pki.api.SigningExecutionException.Classification.OVERLOADED) {
            return failure(operation, PkiOperationFailure.OVERLOADED, "SIGNING_OVERLOADED");
        }
        if (failure instanceof CapabilityUnavailableException) {
            return failure(operation, PkiOperationFailure.VALIDATION_FAILURE, "CAPABILITY_NOT_CONFIGURED");
        }
        if (failure instanceof ExternalOutcomeUnknownException) {
            return failure(operation, PkiOperationFailure.EXTERNAL_OUTCOME_UNKNOWN, "EXTERNAL_OUTCOME_UNKNOWN");
        }
        if (failure instanceof MissingObjectException) {
            return failure(operation, PkiOperationFailure.NOT_FOUND, "OBJECT_NOT_FOUND");
        }
        if (failure instanceof OperationConflictException) {
            return failure(operation, PkiOperationFailure.CONFLICT, "OPERATION_CONFLICT");
        }
        if (failure instanceof PkiException pkiFailure && pkiFailure.failureReason().isPresent()) {
            return classifyReason(operation, pkiFailure.failureReason().orElseThrow());
        }
        // Every domain producer whose outcome is caller-meaningful now carries a typed
        // PkiFailureReason (classified above) or a typed internal marker (handled above); no code
        // path parses exception prose. The remaining checks are a bounded structural fallback over
        // the exception TYPE alone for a genuinely untyped programming/runtime failure: an untyped
        // IllegalArgumentException is a validation defect, a bare PkiException a policy rejection, an
        // IllegalStateException a resource failure, and anything else an internal failure.
        if (failure instanceof IllegalArgumentException) {
            return failure(operation, PkiOperationFailure.VALIDATION_FAILURE, "OPERATION_INPUT_INVALID");
        }
        if (failure instanceof PkiException) {
            return failure(operation, PkiOperationFailure.POLICY_REJECTION, "PKI_POLICY_REJECTED");
        }
        if (failure instanceof IllegalStateException) {
            return failure(operation, PkiOperationFailure.RESOURCE_FAILURE, "PKI_RESOURCE_FAILED");
        }
        return failure(operation, PkiOperationFailure.INTERNAL_FAILURE, "INTERNAL_FAILURE");
    }

    // Maps a typed failure reason to the synchronous operation outcome by its
    // classification alone, so no code path depends on exception message text. The
    // switch is exhaustive over every classification, guaranteeing a stable result.
    private static PkiOperationOutcome classifyReason(String operation, PkiFailureReason reason) {
        PkiFailureClassification classification = reason.classification();
        return switch (classification) {
            case RECOVERY_REQUIRED ->
                    failure(operation, PkiOperationFailure.RECOVERY_REQUIRED, "RECOVERY_REQUIRED");
            case EXTERNAL_OUTCOME_UNKNOWN ->
                    failure(operation, PkiOperationFailure.EXTERNAL_OUTCOME_UNKNOWN, "EXTERNAL_OUTCOME_UNKNOWN");
            case NOT_FOUND -> failure(operation, PkiOperationFailure.NOT_FOUND, "OBJECT_NOT_FOUND");
            case CONFLICT -> failure(operation, PkiOperationFailure.CONFLICT, "OPERATION_CONFLICT");
            case POLICY_REJECTION ->
                    failure(operation, PkiOperationFailure.POLICY_REJECTION, "PKI_POLICY_REJECTED");
            case VALIDATION_FAILURE ->
                    failure(operation, PkiOperationFailure.VALIDATION_FAILURE, "OPERATION_INPUT_INVALID");
            case RESOURCE_FAILURE ->
                    failure(operation, PkiOperationFailure.RESOURCE_FAILURE, "PKI_RESOURCE_FAILED");
            case OVERLOADED -> failure(operation, PkiOperationFailure.OVERLOADED, "SIGNING_OVERLOADED");
            case CANCELLED -> failure(operation, PkiOperationFailure.CANCELLED, "OPERATION_CANCELLED");
            case AUTHENTICATION_FAILURE, AUTHORIZATION_DENIED, DEADLINE_EXCEEDED, INTERNAL_FAILURE ->
                    failure(operation, PkiOperationFailure.INTERNAL_FAILURE, "INTERNAL_FAILURE");
        };
    }

    private static PkiOperationOutcome failure(String operation, PkiOperationFailure classification, String code) {
        return new PkiOperationOutcome.Failed(operation, classification, code);
    }

    private static PkiOperationResult result(String operation, Map<String, PkiOperationValue> fields) {
        return new PkiOperationResult(operation, fields);
    }

    private static Map<String, PkiOperationValue> fields() {
        return new LinkedHashMap<>();
    }

    private static PkiOperationValue text(String value) {
        return new PkiOperationValue.Text(value);
    }

    private static PkiOperationValue integer(long value) {
        return new PkiOperationValue.IntegerValue(value);
    }

    private static PkiOperationValue bool(boolean value) {
        return new PkiOperationValue.BooleanValue(value);
    }

    /** Internal marker normalized to the public NOT_FOUND classification. */
    private static final class MissingObjectException extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    /** Internal marker normalized to the public conflict classification. */
    private static final class OperationConflictException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        private OperationConflictException() {
            super();
        }

        private OperationConflictException(Throwable cause) {
            super(cause);
        }
    }

    /** Internal marker for an operation whose explicitly configured service is unavailable. */
    private static final class CapabilityUnavailableException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        private CapabilityUnavailableException(String capability) {
            super(capability);
        }
    }

    /** Internal marker preserving an unresolved external publication outcome. */
    private static final class ExternalOutcomeUnknownException extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }
}
