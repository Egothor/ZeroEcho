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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaCreateCommand;
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

/** Explicit non-reflective executor used by one backend session. */
@SuppressWarnings({ "PMD.CouplingBetweenObjects", "PMD.CyclomaticComplexity", "PMD.ExcessiveParameterList",
        "PMD.TooManyMethods" })
final class DefaultPkiOperationExecutor implements PkiOperationExecutor {

    private static final String COUNT = "count";
    private static final String FORMAT_ID = "formatId";

    private final PkiSessionConfiguration configuration;
    private final PkiStore store;
    private final ProfileService profiles;
    private final RevocationService revocations;
    private final Optional<CaService> authorities;
    private final Optional<CertificationRequestService> requests;
    private final Optional<IssuanceService> issuance;
    private final Optional<StatusObjectService> statusObjects;
    private final Optional<PublicationService> publications;
    private final X509AlgorithmBindingRegistry algorithmBindings;
    private final Runnable openCheck;

    /* default */ DefaultPkiOperationExecutor(PkiSessionConfiguration configuration, PkiStore store,
            ProfileService profiles, RevocationService revocations, Runnable openCheck) {
        this(configuration, store, profiles, revocations, Optional.empty(), Optional.empty(), Optional.empty(),
                Optional.empty(), Optional.empty(), defaultBindings(), openCheck);
    }

    /* default */ DefaultPkiOperationExecutor(PkiSessionConfiguration configuration, PkiStore store,
            ProfileService profiles, RevocationService revocations, Optional<CaService> authorities,
            Optional<CertificationRequestService> requests, Optional<IssuanceService> issuance,
            Optional<StatusObjectService> statusObjects, Optional<PublicationService> publications,
            Runnable openCheck) {
        this(configuration, store, profiles, revocations, authorities, requests, issuance, statusObjects,
                publications, defaultBindings(), openCheck);
    }

    /* default */ DefaultPkiOperationExecutor(PkiSessionConfiguration configuration, PkiStore store,
            ProfileService profiles, RevocationService revocations, Optional<CaService> authorities,
            Optional<CertificationRequestService> requests, Optional<IssuanceService> issuance,
            Optional<StatusObjectService> statusObjects, Optional<PublicationService> publications,
            X509AlgorithmBindingRegistry algorithmBindings,
            Runnable openCheck) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.store = Objects.requireNonNull(store, "store");
        this.profiles = Objects.requireNonNull(profiles, "profiles");
        this.revocations = Objects.requireNonNull(revocations, "revocations");
        this.authorities = Objects.requireNonNull(authorities, "authorities");
        this.requests = Objects.requireNonNull(requests, "requests");
        this.issuance = Objects.requireNonNull(issuance, "issuance");
        this.statusObjects = Objects.requireNonNull(statusObjects, "statusObjects");
        this.publications = Objects.requireNonNull(publications, "publications");
        this.algorithmBindings = Objects.requireNonNull(algorithmBindings, "algorithmBindings");
        this.openCheck = Objects.requireNonNull(openCheck, "openCheck");
    }

    @Override
    public PkiOperationOutcome execute(PkiOperation operation, CancellationSignal cancellation) {
        openCheck.run();
        PkiOperation exact = Objects.requireNonNull(operation, "operation");
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
                case PkiOperation.CreateAuthority request -> createAuthority(request);
                case PkiOperation.TransitionAuthority request -> transitionAuthority(request);
                case PkiOperation.InspectRequest request -> inspectRequest(request);
                case PkiOperation.ImportRequest request -> importRequest(request);
                case PkiOperation.VerifyRequest request -> verifyRequest(request);
                case PkiOperation.InspectCredential request -> inspectCredential(request);
                case PkiOperation.IssueCredential request -> issueCredential(request);
                case PkiOperation.RevokeCredential request -> revokeCredential(request);
                case PkiOperation.InspectRevocation request -> inspectRevocation(request);
                case PkiOperation.ReadRevocationHistory request -> readHistory(request, signal);
                case PkiOperation.SnapshotRevocations request -> snapshotRevocations(request, signal);
                case PkiOperation.InspectStatus request -> inspectStatus(request);
                case PkiOperation.ListStatus request -> listStatus(request);
                case PkiOperation.GenerateStatus request -> generateStatus(request);
                case PkiOperation.InspectPublication request -> inspectPublication(request);
                case PkiOperation.ListPublications request -> listPublications(request, signal);
                case PkiOperation.RegisterPublication request -> registerPublication(request);
                case PkiOperation.ProcessPublication request -> processPublication(request);
                case PkiOperation.RetryPublication request -> retryPublication(request);
                case PkiOperation.ReconcilePublication request -> reconcilePublication(request);
        };
            return new PkiOperationOutcome.Success(result);
        } catch (InterruptedIOException failure) {
            return failure(exact.name(), PkiOperationFailure.CANCELLED, "OPERATION_CANCELLED");
        } catch (IOException failure) {
            return failure(exact.name(), PkiOperationFailure.RESOURCE_FAILURE, "OPERATION_RESOURCE_FAILED");
        } catch (RuntimeException failure) { // NOPMD - normalize provider failures at the application boundary.
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

    private PkiOperationResult createAuthority(PkiOperation.CreateAuthority request) {
        CaCreateCommand command = new CaCreateCommand(request.formatId(), request.subjectRef(), request.profileId(),
                Optional.of(request.keyRef()), new SimpleAttributeSet());
        PkiId caId = requireCapability(authorities, "authority").createRoot(command);
        Map<String, PkiOperationValue> fields = fields();
        fields.put("caId", text(caId.value()));
        fields.put("state", text(store.getCa(caId).orElseThrow(MissingObjectException::new).state().name()));
        return result(request.name(), fields);
    }

    private PkiOperationResult transitionAuthority(PkiOperation.TransitionAuthority request) {
        requireCapability(authorities, "authority").setCaState(request.caId(), request.state(), request.reason());
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
        fields.put("credentialId", text(credential.credentialId().value()));
        fields.put(FORMAT_ID, text(credential.formatId().value()));
        fields.put("authorityId", text(credential.issuerRef().caId().value()));
        fields.put("issuerId", text(credential.issuerRef().issuerId().value()));
        fields.put("publicKeyId", text(credential.publicKeyId().value()));
        fields.put("profileId", text(profile.profileId()));
        fields.put("profileVersion", integer(profile.profileVersion()));
        fields.put("status", text(credential.status().name()));
        fields.put("notBefore", text(credential.validity().notBefore().toString()));
        fields.put("notAfter", text(credential.validity().notAfter().toString()));
        return result(request.name(), fields);
    }

    private PkiOperationResult issueCredential(PkiOperation.IssueCredential request) {
        ParsedCertificationRequest parsed = requireCapability(requests, "certification-request")
                .get(request.requestId()).orElseThrow(MissingObjectException::new);
        IssueEndEntityCommand command = new IssueEndEntityCommand(request.issuerCaId(), parsed, request.profileId(),
                Optional.empty());
        CredentialBundle bundle = requireCapability(issuance, "issuance").issueEndEntity(command);
        Map<String, PkiOperationValue> fields = fields();
        fields.put("credentialId", text(bundle.credential().credentialId().value()));
        fields.put("issuerCaId", text(bundle.credential().issuerRef().caId().value()));
        fields.put("supportingObjectCount", integer(bundle.supportingObjects().size()));
        return result(request.name(), fields);
    }

    private PkiOperationResult revokeCredential(PkiOperation.RevokeCredential request) {
        RevocationCommand.RevokePermanently command = new RevocationCommand.RevokePermanently(request.credentialId(),
                request.reason(), new SimpleAttributeSet());
        RevocationRecord record = revocations.revokePermanently(command);
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
        fields.put("credentialId", text(request.credentialId().value()));
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
        fields.put("status", text(record.status().name()));
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

    private PkiOperationResult generateStatus(PkiOperation.GenerateStatus request) {
        StatusObjectGenerateCommand command = new StatusObjectGenerateCommand(request.issuerCaId(), request.type(),
                request.formatId(), new SimpleAttributeSet());
        StatusObject object = requireCapability(statusObjects, "status-object").generate(command);
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
        fields.put("status", text(publication.status().name()));
        fields.put("attemptNumber", integer(publication.attemptNumber()));
        return result(operation, fields);
    }

    private static PkiOperationResult publicationRecordResult(String operation, PublicationRecord publication) {
        Map<String, PkiOperationValue> fields = fields();
        fields.put("publicationId", text(publication.publicationId().value()));
        fields.put("status", text(publication.status().name()));
        fields.put("attemptNumber", integer(publication.attemptNumber()));
        return result(operation, fields);
    }

    private static <T> T requireCapability(Optional<T> service, String capability) {
        return service.orElseThrow(() -> new CapabilityUnavailableException(capability));
    }

    private static PkiOperationResult revocationResult(String operation, RevocationRecord record) {
        Map<String, PkiOperationValue> fields = fields();
        fields.put("credentialId", text(record.credentialId().value()));
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
        fields.put("caId", text(record.caId().value()));
        fields.put("kind", text(record.kind().name()));
        fields.put("state", text(record.state().name()));
        fields.put("issuerGenerationCount", integer(record.issuerIds().size()));
        fields.put("currentIssuanceIssuerId", text(record.currentIssuanceIssuerId().value()));
        return fields;
    }

    private static PkiOperationValue revocationValue(RevocationRecord record) {
        Map<String, PkiOperationValue> fields = fields();
        fields.put("credentialId", text(record.credentialId().value()));
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
        fields.put("status", text(record.status().name()));
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
        if (failure instanceof CapabilityUnavailableException) {
            return failure(operation, PkiOperationFailure.VALIDATION_FAILURE, "CAPABILITY_NOT_CONFIGURED");
        }
        if (failure instanceof ExternalOutcomeUnknownException) {
            return failure(operation, PkiOperationFailure.EXTERNAL_OUTCOME_UNKNOWN, "EXTERNAL_OUTCOME_UNKNOWN");
        }
        if (failure instanceof MissingObjectException) {
            return failure(operation, PkiOperationFailure.NOT_FOUND, "OBJECT_NOT_FOUND");
        }
        String message = Optional.ofNullable(failure.getMessage()).orElse("");
        if (message.contains("RECOVERY_REQUIRED") || message.contains("DURABILITY_UNCONFIRMED")) {
            return failure(operation, PkiOperationFailure.RECOVERY_REQUIRED, "RECOVERY_REQUIRED");
        }
        if (message.contains("OUTCOME_UNKNOWN") || message.contains("RESULT_UNCONFIRMED")) {
            return failure(operation, PkiOperationFailure.EXTERNAL_OUTCOME_UNKNOWN, "EXTERNAL_OUTCOME_UNKNOWN");
        }
        if (message.contains("CREDENTIAL_NOT_FOUND")) {
            return failure(operation, PkiOperationFailure.NOT_FOUND, "OBJECT_NOT_FOUND");
        }
        String lowerMessage = message.toLowerCase(java.util.Locale.ROOT);
        if (lowerMessage.contains("not found") || lowerMessage.contains("does not exist")) {
            return failure(operation, PkiOperationFailure.NOT_FOUND, "OBJECT_NOT_FOUND");
        }
        if (message.contains("CONFLICT") || message.contains("changed concurrently")) {
            return failure(operation, PkiOperationFailure.CONFLICT, "OPERATION_CONFLICT");
        }
        if (message.contains("TRANSITION_ILLEGAL") || message.contains("REVOCATION_TERMINAL")) {
            return failure(operation, PkiOperationFailure.POLICY_REJECTION, "PKI_POLICY_REJECTED");
        }
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

    private static PkiOperationOutcome failure(String operation, PkiOperationFailure classification, String code) {
        return new PkiOperationOutcome.Failure(operation, classification, code);
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
