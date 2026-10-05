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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.PublicationService;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.schedule.StatusSchedule;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.PkiFailureReason;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofChallenge;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofChallengeRequest;
import zeroecho.pki.api.confirmation.CredentialConfirmationReview;
import zeroecho.pki.api.confirmation.CredentialConfirmationReviewPage;
import zeroecho.pki.api.confirmation.CredentialConfirmationService;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.publication.PublicationRequest;
import zeroecho.pki.api.publication.PublicationResult;
import zeroecho.pki.api.publication.PublicationStatus;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.ProofOfPossessionResult;
import zeroecho.pki.api.request.RequestStorePolicy;
import zeroecho.pki.api.issuance.VerificationPolicy;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationQuery;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.RevocationHistory;
import zeroecho.pki.spi.store.RevocationSnapshot;

/** Explicit non-reflective executor for synchronous non-signing operations. */
@SuppressWarnings({ "PMD.CouplingBetweenObjects", "PMD.TooManyMethods" })
final class DefaultPkiOperationExecutor implements PkiOperationExecutor, RevocationEvidenceExecutor, PkiSelectionExecutor, PkiConfigurationChoicesSource { // NOPMD CyclomaticComplexity - Aggregate lifecycle/coordinator complexity; individual methods remain checked.
    private static final String TEXT_CA_ID = "caId";
    private static final String PROFILE_ID = "profileId";
    private static final String ISSUER_ID = "issuerId";
    private static final String AUTHORITY_ID = "authorityId";
    private static final String COUNT = "count";
    private static final String CREDENTIAL_ID = "credentialId";
    private static final String FORMAT_ID = "formatId";
    private static final String STATUS = "status";
    private static final String OPERATION_CANCELLED = "OPERATION_CANCELLED";

    private final ConfigurationSummary configuration;
    private final PkiStore store;
    private final ProfileService profiles;
    private final RevocationService revocations;
    private final Optional<CertificationRequestService> requests;
    private final Optional<PublicationService> publications;
    private final CredentialConfirmationService confirmations;
    private final X509AlgorithmBindingRegistry algorithmBindings;
    private final Runnable openCheck;
    private final PkiConfigurationChoicesSource configurationChoices;
    private final Clock clock;
    private final DashboardLiveSource liveSource;

    // Cap credential scan at 100K to bound heap; countCapped=true signals the caller that the result was truncated.
    private static final int CREDENTIAL_SCAN_CAP = 100_000;
    private static final int DASHBOARD_PAGE_SIZE = 100;

    /** Only the diagnostic configuration facts used by the core operation catalog. */
    /* default */ record ConfigurationSummary(int version, String storeProvider, String auditProvider) {
        ConfigurationSummary {
            Objects.requireNonNull(storeProvider, "storeProvider");
            Objects.requireNonNull(auditProvider, "auditProvider");
        }
    }

    // Explicit collaborators or atomic persisted coordinates remain visible at this boundary.
    @SuppressWarnings("PMD.ExcessiveParameterList")
    /* default */ DefaultPkiOperationExecutor(ConfigurationSummary configuration, PkiStore store,
            ProfileService profiles, RevocationService revocations,
            Optional<CertificationRequestService> requests, Optional<PublicationService> publications,
            CredentialConfirmationService confirmations, X509AlgorithmBindingRegistry algorithmBindings,
            Runnable openCheck, PkiConfigurationChoicesSource configurationChoices, Clock clock,
            DashboardLiveSource liveSource) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.store = Objects.requireNonNull(store, "store");
        this.profiles = Objects.requireNonNull(profiles, "profiles");
        this.revocations = Objects.requireNonNull(revocations, "revocations");
        this.requests = Objects.requireNonNull(requests, "requests");
        this.publications = Objects.requireNonNull(publications, "publications");
        this.confirmations = Objects.requireNonNull(confirmations, "confirmations");
        this.algorithmBindings = Objects.requireNonNull(algorithmBindings, "algorithmBindings");
        this.openCheck = Objects.requireNonNull(openCheck, "openCheck");
        this.configurationChoices = Objects.requireNonNull(configurationChoices, "configurationChoices");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.liveSource = Objects.requireNonNull(liveSource, "liveSource");
    }

    @Override
    public PkiConfigurationChoicesSource.Choices configurationChoices(int limit, Optional<String> after,
            CancellationSignal cancellation) {
        return configurationChoices.configurationChoices(limit, after, cancellation);
    }

    @Override
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public PkiOperationOutcome execute(PkiOperation operation, CancellationSignal cancellation) {
        openCheck.run();
        PkiOperation exact = Objects.requireNonNull(operation, "operation");
        CancellationSignal signal = Objects.requireNonNull(cancellation, "cancellation");
        try {
            signal.throwIfCancelled();
            PkiOperationResult result = dispatch(exact, signal);
            return new PkiOperationOutcome.Completed(result);
        } catch (InterruptedIOException failure) {
            return failure(exact.name(), PkiOperationFailure.CANCELLED, OPERATION_CANCELLED);
        } catch (IOException failure) {
            return failure(exact.name(), PkiOperationFailure.RESOURCE_FAILURE, "OPERATION_RESOURCE_FAILED");
        } catch (RuntimeException failure) {
            if (signal.isCancelled()) {
                return failure(exact.name(), PkiOperationFailure.CANCELLED, OPERATION_CANCELLED);
            }
            return classify(exact.name(), failure);
        }
    }

    @Override
    public PkiOperationOutcome executeRevocation(PkiOperation.RevokeCredential operation,
            RevocationExecutionEvidence evidence, CancellationSignal cancellation) {
        return executeEvidence(operation.name(), cancellation,
                () -> revoke(operation, Objects.requireNonNull(evidence, "evidence").attributes()));
    }

    @Override
    public PkiOperationOutcome executePendingConfirmationRevocation(
            PkiOperation.RevokePendingCredentialConfirmation operation,
            RevocationExecutionEvidence evidence, CancellationSignal cancellation) {
        return executeEvidence(operation.name(), cancellation,
                () -> revokePending(operation, Objects.requireNonNull(evidence, "evidence").attributes()));
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private PkiOperationOutcome executeEvidence(String name, CancellationSignal cancellation,
            java.util.function.Supplier<PkiOperationResult> action) {
        openCheck.run();
        CancellationSignal signal = Objects.requireNonNull(cancellation, "cancellation");
        try {
            signal.throwIfCancelled();
            return new PkiOperationOutcome.Completed(action.get());
        } catch (InterruptedIOException failure) {
            return failure(name, PkiOperationFailure.CANCELLED, OPERATION_CANCELLED);
        } catch (RuntimeException failure) {
            return classify(name, failure);
        }
    }

    // The selection callback must abort traversal on cancellation; returning false would continue scanning.
    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.ExceptionAsFlowControl" })
    @Override
    public PkiOperationOutcome executeSelection(PkiOperation operation,
            java.util.function.Predicate<PkiOperationValue.ObjectValue> include, CancellationSignal cancellation) {
        openCheck.run();
        Objects.requireNonNull(include, "include");
        Objects.requireNonNull(cancellation, "cancellation");
        try {
            cancellation.throwIfCancelled();
            return new PkiOperationOutcome.Completed(selection(operation, row -> {
                if (cancellation.isCancelled()) { throw new SelectionCancelled(); }
                return include.test(row);
            }, cancellation));
        } catch (InterruptedIOException | SelectionCancelled failure) {
            return failure(operation.name(), PkiOperationFailure.CANCELLED, OPERATION_CANCELLED);
        } catch (RuntimeException failure) { return classify(operation.name(), failure); }
    }

    private PkiOperationResult selection(PkiOperation operation,
            java.util.function.Predicate<PkiOperationValue.ObjectValue> include, CancellationSignal cancellation) {
        return switch (operation) {
            case PkiOperation.ListAuthorities query -> page(query.name(), "authorities", TEXT_CA_ID, query.limit(),
                    store.selectAuthoritiesPage(query.after(), query.limit() + 1,
                            value -> include.test(object(authorityFields(value))), cancellation).stream()
                            .map(value -> object(authorityFields(value))).toList());
            case PkiOperation.ListProfiles query -> page(query.name(), "profiles", PROFILE_ID, query.limit(),
                    store.listProfileIdsPage(query.after(), query.limit() + 1,
                            value -> include.test(object(Map.of(PROFILE_ID, text(value)))), cancellation).stream()
                            .map(this::profileSelection).toList());
            case PkiOperation.ListRequests query -> page(query.name(), "requests", "requestId", query.limit(),
                    store.listRequestsPage(query.after(), query.limit() + 1,
                            value -> include.test(requestSelection(value)), cancellation).stream()
                            .map(DefaultPkiOperationExecutor::requestSelection).toList());
            case PkiOperation.SearchCredentials query -> page(query.name(), "credentials", "credentialId", query.limit(),
                    store.listCredentialsPage(query.authorityId(), query.after(), query.limit() + 1,
                            value -> include.test(object(credentialFields(value))), cancellation).stream()
                            .map(value -> object(credentialFields(value))).toList());
            case PkiOperation.ListIssuerGenerations query -> page(query.name(), "generations", ISSUER_ID, query.limit(),
                    store.listIssuerGenerationsPage(query.authorityId(), query.after(), query.limit() + 1,
                            value -> include.test(object(generationFields(value))), cancellation).stream()
                            .map(value -> object(generationFields(value))).toList());
            case PkiOperation.ListStatus query -> {
                PkiOperationResult selected = page(query.name(), "statusObjects", "statusObjectId", query.limit(),
                        store.listStatusObjectsPage(query.issuerCaId(), query.after(), query.limit() + 1,
                                value -> include.test(object(statusFields(value))), cancellation).stream()
                                .map(value -> object(statusFields(value))).toList());
                Map<String, PkiOperationValue> fields = new LinkedHashMap<>(selected.fields());
                fields.put("issuerCaId", text(query.issuerCaId().value()));
                yield result(query.name(), fields);
            }
            case PkiOperation.ListPublications query -> page(query.name(), "publications", "publicationId", query.limit(),
                    store.listPublicationsPage(query.after(), query.limit() + 1,
                            value -> include.test(publicationSelection(value)), cancellation).stream()
                            .map(this::publicationSelection).toList());
            case PkiOperation.ListAlgorithmBindings query -> {
                List<PkiOperationValue.ObjectValue> rows = algorithmBindings.bindings().stream()
                        .filter(value -> query.origin().isEmpty() || query.origin().orElseThrow().equals(value.origin().name()))
                        .filter(value -> query.role().isEmpty() || query.role().orElseThrow().equals(value.role().name()))
                        .filter(value -> query.after().isEmpty() || value.bindingId().compareTo(query.after().orElseThrow()) > 0)
                        .sorted(java.util.Comparator.comparing(X509AlgorithmBinding::bindingId))
                        .map(DefaultPkiOperationExecutor::bindingValue).filter(include).limit(query.limit() + 1L).toList();
                PkiOperationResult page = page(query.name(), "bindings", "bindingId", query.limit(), rows);
                Map<String, PkiOperationValue> fields = new LinkedHashMap<>(page.fields());
                fields.put("registryCommitment", text(algorithmBindings.commitment()));
                yield result(query.name(), fields);
            }
            default -> throw new IllegalArgumentException("Operation is not a pageable selection");
        };
    }

    private PkiOperationValue.ObjectValue profileSelection(String id) {
        Map<String, PkiOperationValue> fields = fields();
        fields.put(PROFILE_ID, text(id));
        profiles.getActiveReference(id).ifPresent(reference -> {
            ImportedCertificateProfileVersion version = profiles.getImportedVersion(id, reference.profileVersion()).orElseThrow(Missing::new);
            fields.put("activeVersion", integer(reference.profileVersion()));
            fields.put("displayName", text(version.definition().displayName()));
            fields.put("certificateType", text(version.definition().certificateType().name()));
            fields.put("formatId", text(version.definition().formatId().value()));
        });
        return object(fields);
    }

    private static PkiOperationValue.ObjectValue requestSelection(PkiStore.RequestSelection value) {
        Map<String, PkiOperationValue> fields = fields();
        fields.put("requestId", text(value.requestId().value()));
        fields.put("formatId", text(value.formatId().value()));
        value.profileId().ifPresent(profile -> fields.put(PROFILE_ID, text(profile)));
        return object(fields);
    }

    private static PkiOperationValue.ObjectValue object(Map<String, PkiOperationValue> fields) {
        return new PkiOperationValue.ObjectValue(fields);
    }

    private static PkiOperationResult page(String operation, String collection, String identity, int limit,
            List<PkiOperationValue.ObjectValue> candidates) {
        boolean more = candidates.size() > limit;
        List<PkiOperationValue> rows = new ArrayList<>(candidates.subList(0, Math.min(limit, candidates.size())));
        Map<String, PkiOperationValue> fields = fields();
        fields.put("count", integer(rows.size()));
        fields.put("truncated", bool(more));
        fields.put(collection, new PkiOperationValue.ListValue(rows));
        if (more) { fields.put("nextCursor", ((PkiOperationValue.ObjectValue) rows.getLast()).fields().get(identity)); }
        return result(operation, fields);
    }

    /** Internal cancellation marker for bounded selection traversal. */
    private static final class SelectionCancelled extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    private PkiOperationResult inspectAlgorithmBinding(PkiOperation.InspectAlgorithmBinding request) {
        X509AlgorithmBinding binding = algorithmBindings.find(request.bindingId()).orElseThrow(Missing::new);
        Map<String, PkiOperationValue> result = fields();
        result.putAll(bindingValue(binding).fields());
        result.put("registryCommitment", text(algorithmBindings.commitment()));
        return result(request.name(), result);
    }

    private PkiOperationResult validateAlgorithmBindings(PkiOperation.ValidateAlgorithmBindings request) {
        request.bindingId().ifPresent(id -> algorithmBindings.require(id,
                request.expectedCommitment().orElseThrow()));
        Map<String, PkiOperationValue> result = fields();
        result.put("valid", bool(true));
        result.put(COUNT, integer(algorithmBindings.bindings().size()));
        result.put("registryCommitment", text(algorithmBindings.commitment()));
        return result(request.name(), result);
    }

    private static PkiOperationValue.ObjectValue bindingValue(X509AlgorithmBinding binding) {
        Map<String, PkiOperationValue> result = fields();
        result.put("bindingId", text(binding.bindingId()));
        result.put("algorithmId", text(binding.algorithmIdentity().canonicalForm()));
        result.put("role", text(binding.role().name()));
        result.put("oid", text(binding.oid()));
        result.put("origin", text(binding.origin().name()));
        result.put("bindingCommitment", text(binding.semanticCommitment()));
        binding.providerId().ifPresent(value -> result.put("providerId", text(value)));
        return new PkiOperationValue.ObjectValue(result);
    }

    private PkiOperationResult validateConfiguration() {
        Map<String, PkiOperationValue> result = fields();
        result.put("version", integer(configuration.version()));
        result.put("storeProvider", text(configuration.storeProvider()));
        result.put("auditProvider", text(configuration.auditProvider()));
        return result(PkiOperation.ValidateConfiguration.NAME, result);
    }

    private PkiOperationResult validateProfile(PkiOperation.ValidateProfile request) {
        CertificateProfileDefinition definition = CertificateProfileDocumentCodec.parse(request.document());
        validateProfileBindings(definition.algorithmBindingPolicy());
        Map<String, PkiOperationValue> result = fields();
        result.put("valid", bool(true));
        result.put(FORMAT_ID, text(definition.formatId().value()));
        result.put("certificateType", text(definition.certificateType().name()));
        return result(request.name(), result);
    }

    private void validateProfileBindings(X509AlgorithmBindingPolicy policy) {
        validateProfileBinding(policy.certificateSignature(), X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE);
        validateProfileBinding(policy.subjectPublicKey(), X509AlgorithmBinding.Role.SUBJECT_PUBLIC_KEY);
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
        CertificateProfileDefinition definition = CertificateProfileDocumentCodec.parse(request.document());
        byte[] canonical = CertificateProfileDocumentCodec.writeCanonical(definition);
        byte[] incomingHash = sha256(canonical);
        Optional<CertificateProfileRef> activeRef = profiles.getActiveReference(definition.profileId());
        if (activeRef.isPresent() && MessageDigest.isEqual(activeRef.get().canonicalSha256(), incomingHash)) {
            return profileReferenceResult(request.name(), activeRef.get());
        }
        CertificateProfileRef imported = profiles.importProfile(request.document());
        if (!definition.approvalRequirement().requiresApproval()) {
            return profileReferenceResult(request.name(),
                    profiles.activateProfile(definition.profileId(), definition.profileVersion()));
        }
        return profileReferenceResult(request.name(), imported);
    }

    private PkiOperationResult inspectProfile(PkiOperation.InspectProfile request) {
        ImportedCertificateProfileVersion version = profiles
                .getImportedVersion(request.profileId(), request.profileVersion()).orElseThrow(Missing::new);
        Map<String, PkiOperationValue> result = fields();
        appendProfileVersion(result, version);
        return result(request.name(), result);
    }

    private PkiOperationResult listProfileVersions(PkiOperation.ListProfileVersions request) {
        List<PkiOperationValue> versions = profiles.listImportedVersions(request.profileId()).stream()
                .<PkiOperationValue>map(DefaultPkiOperationExecutor::profileVersionValue).toList();
        Map<String, PkiOperationValue> result = fields();
        result.put(PROFILE_ID, text(request.profileId()));
        result.put(COUNT, integer(versions.size()));
        result.put("versions", new PkiOperationValue.ListValue(versions));
        profiles.getActiveReference(request.profileId())
                .ifPresent(reference -> result.put("activeVersion", integer(reference.profileVersion())));
        return result(request.name(), result);
    }

    private PkiOperationResult activateProfile(PkiOperation.ActivateProfile request) {
        return profileReferenceResult(request.name(),
                profiles.activateProfile(request.profileId(), request.profileVersion()));
    }

    private PkiOperationResult inspectAuthority(PkiOperation.InspectAuthority request) {
        return result(request.name(), authorityFields(store.getCa(request.caId()).orElseThrow(Missing::new)));
    }

    private static Map<String, PkiOperationValue> authorityFields(CaRecord authority) {
        Map<String, PkiOperationValue> result = fields();
        result.put(TEXT_CA_ID, text(authority.caId().value()));
        result.put("kind", text(authority.kind().name()));
        result.put("state", text(authority.state().name()));
        result.put("issuerGenerationCount", integer(authority.issuerIds().size()));
        result.put("currentIssuanceIssuerId", text(authority.currentIssuanceIssuerId().value()));
        return result;
    }

    private PkiOperationResult inspectCredential(PkiOperation.InspectCredential request) {
        Credential credential = store.getCredential(request.credentialId()).orElseThrow(Missing::new);
        return result(request.name(), credentialFields(credential));
    }

    private static Map<String, PkiOperationValue> credentialFields(Credential credential) {
        CertificateProfileRef profile = switch (credential.profileBinding()) {
            case EndEntityProfileBinding binding -> binding.reference();
            case CaProfileBinding binding -> binding.reference();
        };
        Map<String, PkiOperationValue> result = fields();
        result.put(CREDENTIAL_ID, text(credential.credentialId().value()));
        result.put(FORMAT_ID, text(credential.formatId().value()));
        result.put(AUTHORITY_ID, text(credential.issuerRef().caId().value()));
        result.put(ISSUER_ID, text(credential.issuerRef().issuerId().value()));
        result.put("publicKeyId", text(credential.publicKeyId().value()));
        result.put("subjectRef", text(credential.subjectRef().value()));
        result.put("serialOrUniqueId", text(credential.serialOrUniqueId()));
        result.put(PROFILE_ID, text(profile.profileId()));
        result.put("profileVersion", integer(profile.profileVersion()));
        result.put(STATUS, text(credential.status().name()));
        result.put("notBefore", text(credential.validity().notBefore().toString()));
        result.put("notAfter", text(credential.validity().notAfter().toString()));
        return result;
    }

    private static java.util.function.Predicate<PkiOperationValue.ObjectValue> credentialSearchFilter(
            PkiOperation.SearchCredentials q) {
        java.util.function.Predicate<PkiOperationValue.ObjectValue> p = row -> true;
        if (q.subjectFilter().isPresent()) {
            String sub = q.subjectFilter().get().toLowerCase(java.util.Locale.ROOT);
            p = p.and(row -> textField(row, "subjectRef").toLowerCase(java.util.Locale.ROOT).contains(sub));
        }
        if (q.serialFilter().isPresent()) {
            String ser = q.serialFilter().get().toLowerCase(java.util.Locale.ROOT);
            p = p.and(row -> textField(row, "serialOrUniqueId").toLowerCase(java.util.Locale.ROOT).contains(ser));
        }
        if (q.fingerprintFilter().isPresent()) {
            String fp = q.fingerprintFilter().get().toLowerCase(java.util.Locale.ROOT);
            p = p.and(row -> textField(row, CREDENTIAL_ID).toLowerCase(java.util.Locale.ROOT).startsWith(fp));
        }
        if (q.statusFilter().isPresent()) {
            String status = q.statusFilter().get();
            p = p.and(row -> textField(row, STATUS).equals(status));
        }
        if (q.profileIdFilter().isPresent()) {
            String profile = q.profileIdFilter().get();
            p = p.and(row -> textField(row, PROFILE_ID).equals(profile));
        }
        return p;
    }

    private static String textField(PkiOperationValue.ObjectValue row, String key) {
        PkiOperationValue val = row.fields().get(key);
        return val instanceof PkiOperationValue.Text t ? t.value() : "";
    }

    private PkiOperationResult inspectIssuerGeneration(PkiOperation.InspectIssuerGeneration request) {
        IssuerGeneration generation = store.getIssuerGeneration(request.issuerId()).orElseThrow(Missing::new);
        return result(request.name(), generationFields(generation));
    }

    private Map<String, PkiOperationValue> generationFields(IssuerGeneration generation) {
        Map<String, PkiOperationValue> result = fields();
        result.put(ISSUER_ID, text(generation.issuerId().value()));
        result.put(AUTHORITY_ID, text(generation.authorityId().value()));
        result.put(CREDENTIAL_ID, text(generation.credentialId().value()));
        result.put("state", text(generation.state().name()));
        Credential credential = store.getCredential(generation.credentialId()).orElseThrow(Missing::new);
        result.put(PROFILE_ID, credentialFields(credential).get(PROFILE_ID));
        result.put("profilePolicyCommitment", text(generation.profilePolicyCommitment()));
        result.put("x509BindingCommitment", text(generation.x509BindingCommitment()));
        return result;
    }

    private PkiOperationResult inspectIssuerChainPath(PkiOperation.InspectIssuerChainPath request) {
        return result(request.name(), chainPathFields(store.getIssuerChainPath(request.pathId()).orElseThrow(Missing::new)));
    }

    private static Map<String, PkiOperationValue> chainPathFields(IssuerChainPath path) {
        Map<String, PkiOperationValue> result = fields();
        result.put("pathId", text(path.pathId().value()));
        result.put(AUTHORITY_ID, text(path.authorityId().value()));
        result.put(ISSUER_ID, text(path.issuerId().value()));
        result.put("pathCommitment", text(path.pathCommitment()));
        List<PkiOperationValue> ordered = path.orderedCredentialIds().stream()
                .<PkiOperationValue>map(id -> text(id.value())).toList();
        result.put("orderedCredentialIds", new PkiOperationValue.ListValue(ordered));
        result.put(COUNT, integer(ordered.size()));
        return result;
    }

    private PkiOperationResult inspectStatus(PkiOperation.InspectStatus request) {
        return result(request.name(), statusFields(store.getStatusObject(request.statusObjectId()).orElseThrow(Missing::new)));
    }

    private static Map<String, PkiOperationValue> statusFields(StatusObject status) {
        Map<String, PkiOperationValue> result = fields();
        result.put("statusObjectId", text(status.statusObjectId().value()));
        result.put("issuerCaId", text(status.issuerCaId().value()));
        result.put("type", text(status.type().name()));
        result.put(FORMAT_ID, text(status.formatId().value()));
        result.put("thisUpdate", text(status.thisUpdate().toString()));
        status.nextUpdate().ifPresent(value -> result.put("nextUpdate", text(value.toString())));
        result.put("contentLength", integer(status.content().length()));
        result.put("contentSha256", text(status.content().sha256()));
        return result;
    }

    private PkiOperationResult listIssuerChainPaths(PkiOperation.ListIssuerChainPaths request) {
        List<IssuerChainPath> paths = store.listIssuerChainPaths(request.issuerId());
        List<PkiOperationValue> values = paths.stream()
                .<PkiOperationValue>map(path -> new PkiOperationValue.ObjectValue(chainPathFields(path))).toList();
        Map<String, PkiOperationValue> result = fields();
        result.put(ISSUER_ID, text(request.issuerId().value()));
        result.put(COUNT, integer(values.size()));
        result.put("paths", new PkiOperationValue.ListValue(values));
        return result(request.name(), result);
    }

    private PkiOperationResult transitionAuthority(PkiOperation.TransitionAuthority request) {
        CaRecord current = store.getCa(request.caId()).orElseThrow(Missing::new);
        if (current.state() != request.state()) {
            CaRecord replacement = new CaRecord(current.caId(), current.kind(), request.state(), current.issuerKeyRef(),
                    current.subjectRef(), current.issuerIds(), current.currentIssuanceIssuerId(), current.issuanceChainPathId());
            if (!store.replaceCa(current, replacement)) { throw new Conflict(); }
        }
        return result(request.name(), authorityFields(store.getCa(request.caId()).orElseThrow(Missing::new)));
    }

    private PkiOperationResult selectIssuancePath(PkiOperation.SelectIssuancePath request) {
        CaRecord current = store.getCa(request.caId()).orElseThrow(Missing::new);
        IssuerGeneration generation = store.getIssuerGeneration(request.issuerId()).orElseThrow(Missing::new);
        IssuerChainPath path = store.getIssuerChainPath(request.pathId()).orElseThrow(Missing::new);
        if (!current.issuerIds().contains(request.issuerId()) || !current.caId().equals(generation.authorityId())
                || generation.state() != IssuerGenerationState.ACTIVE || !current.caId().equals(path.authorityId())
                || !generation.issuerId().equals(path.issuerId())) {
            throw new PkiException("Issuance selection is outside the authority");
        }
        CaRecord replacement = new CaRecord(current.caId(), current.kind(), current.state(), generation.signingKeyRef(),
                current.subjectRef(), current.issuerIds(), generation.issuerId(), path.pathId());
        if (!store.replaceCa(current, replacement)) { throw new Conflict(); }
        Map<String, PkiOperationValue> result = fields();
        result.put(TEXT_CA_ID, text(request.caId().value()));
        result.put(ISSUER_ID, text(request.issuerId().value()));
        result.put("pathId", text(request.pathId().value()));
        return result(request.name(), result);
    }

    private PkiOperationResult registerIssuerChainPath(PkiOperation.RegisterIssuerChainPath request) {
        CaRecord current = store.getCa(request.caId()).orElseThrow(Missing::new);
        IssuerGeneration generation = store.getIssuerGeneration(request.issuerId()).orElseThrow(Missing::new);
        IssuerChainPath parent = store.getIssuerChainPath(request.parentPathId()).orElseThrow(Missing::new);
        if (!current.issuerIds().contains(request.issuerId()) || !current.caId().equals(generation.authorityId())) {
            throw new PkiException("Issuer generation is outside the authority");
        }
        List<PkiId> credentials = new ArrayList<>(parent.orderedCredentialIds().size() + 1);
        credentials.add(generation.credentialId());
        credentials.addAll(parent.orderedCredentialIds());
        IssuerChainPath path = IssuerChainPath.create(current.caId(), generation.issuerId(), credentials);
        store.putIssuerChainPath(path);
        return result(request.name(), chainPathFields(path));
    }

    private PkiOperationResult inspectRequest(PkiOperation.InspectRequest request) {
        ParsedCertificationRequest parsed = store.getRequest(request.requestId()).orElseThrow(Missing::new);
        Map<String, PkiOperationValue> result = fields();
        result.put("requestId", text(parsed.requestId().value()));
        result.put(FORMAT_ID, text(parsed.formatId().value()));
        result.put("publicKeyBytes", integer(parsed.publicKeyInfo().bytes().length));
        parsed.requestedProfileId().ifPresent(value -> result.put("requestedProfileId", text(value)));
        result.put("subjectAlternativeNameCount", integer(parsed.subjectAlternativeNames().size()));
        return result(request.name(), result);
    }

    private PkiOperationResult importRequest(PkiOperation.ImportRequest request) {
        CertificationRequestService service = requireRequests();
        ParsedCertificationRequest parsed = service.parse(new CertificationRequest(request.formatId(),
                request.encoded()));
        PkiId id = service.store(parsed, RequestStorePolicy.STORE_ALWAYS);
        Map<String, PkiOperationValue> result = fields();
        result.put("requestId", text(id.value()));
        result.put(FORMAT_ID, text(parsed.formatId().value()));
        return result(request.name(), result);
    }

    private PkiOperationResult verifyRequest(PkiOperation.VerifyRequest request) {
        CertificationRequestService service = requireRequests();
        ParsedCertificationRequest parsed = service.get(request.requestId()).orElseThrow(Missing::new);
        ProofOfPossessionResult proof = service.verifyProofOfPossession(parsed,
                new VerificationPolicy(true, Optional.empty()));
        Map<String, PkiOperationValue> result = fields();
        result.put("requestId", text(request.requestId().value()));
        result.put("proofStatus", text(proof.status().name()));
        return result(request.name(), result);
    }

    private PkiOperationResult listPendingConfirmations(PkiOperation.ListPendingCredentialConfirmations request) {
        CredentialConfirmationReviewPage page = confirmations.pagePendingReviews(request.authorityId(),
                request.profileId(), request.cutoffInclusive(), request.afterExclusive(), request.limit());
        List<PkiOperationValue> values = page.reviews().stream()
                .map(review -> (PkiOperationValue) confirmationReviewValue(review)).toList();
        Map<String, PkiOperationValue> result = fields();
        result.put(COUNT, integer(values.size()));
        result.put("reviews", new PkiOperationValue.ListValue(values));
        page.nextCursor().ifPresent(cursor -> result.put("nextCursor", text(cursor.value())));
        result.put("cutoffInclusive", text(request.cutoffInclusive().toString()));
        return result(request.name(), result);
    }

    private static PkiOperationValue.ObjectValue confirmationReviewValue(CredentialConfirmationReview review) {
        Map<String, PkiOperationValue> result = fields();
        result.put(CREDENTIAL_ID, text(review.credentialId().value()));
        result.put(AUTHORITY_ID, text(review.authorityId().value()));
        result.put(PROFILE_ID, text(review.profileId()));
        result.put("confirmationReviewAt", text(review.confirmationReviewAt().toString()));
        result.put("initialDisclosurePolicy", text(review.initialDisclosurePolicy().name()));
        return new PkiOperationValue.ObjectValue(result);
    }

    private PkiOperationResult issueChallenge(PkiOperation.IssueCredentialConfirmationChallenge request) {
        CredentialConfirmationLifecycle lifecycle = confirmations.get(request.credentialId())
                .orElseThrow(Missing::new);
        if (lifecycle.state() != CredentialConfirmationLifecycle.State.PENDING) {
            throw new Conflict();
        }
        CredentialConfirmationProofChallenge challenge = confirmations.issueProofChallenge(
                new CredentialConfirmationProofChallengeRequest(request.credentialId(), lifecycle.revision(),
                        lifecycle.recordCommitment()));
        Map<String, PkiOperationValue> result = fields();
        result.put(CREDENTIAL_ID, text(challenge.proofCas().credentialId().value()));
        result.put("expectedLifecycleRevision", integer(challenge.proofCas().expectedLifecycleRevision()));
        result.put("expectedLifecycleRecordCommitment", text(challenge.proofCas().expectedLifecycleRecordCommitment()));
        result.put("expectedChallengeRecordCommitment", text(challenge.proofCas().expectedChallengeRecordCommitment()));
        result.put("proofSuiteId", text(challenge.proofSuiteBinding().proofSuiteRef().suiteId()));
        result.put("expiresAt", text(challenge.expiresAt().toString()));
        result.put("maximumResponseBytes", integer(challenge.maximumResponseBytes()));
        result.put("presentation", text(Base64.getUrlEncoder().withoutPadding()
                .encodeToString(challenge.presentation())));
        return result(request.name(), result);
    }

    private PkiOperationResult completeProof(PkiOperation.CompleteCredentialConfirmationProof request) {
        Map<String, PkiOperationValue> result = fields();
        result.put("confirmationResult", text(confirmations.verifyAndComplete(request.submission()).name()));
        return result(request.name(), result);
    }

    private PkiOperationResult revoke(PkiOperation.RevokeCredential request,
            zeroecho.pki.api.attr.AttributeSet evidence) {
        RevocationRecord record = revocations.revokePermanently(new RevocationCommand.RevokePermanently(
                request.credentialId(), request.reason(), evidence));
        return revocationResult(request.name(), record);
    }

    private PkiOperationResult revokePending(PkiOperation.RevokePendingCredentialConfirmation request,
            zeroecho.pki.api.attr.AttributeSet evidence) {
        RevocationRecord record = revocations.revokeOverduePendingConfirmation(
                new RevocationCommand.RevokePermanently(request.credentialId(),
                        zeroecho.pki.api.revocation.RevocationReason.UNSPECIFIED, evidence));
        return revocationResult(request.name(), record);
    }

    private PkiOperationResult inspectRevocation(PkiOperation.InspectRevocation request) {
        return revocationResult(request.name(),
                revocations.get(request.credentialId()).orElseThrow(Missing::new));
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
        Map<String, PkiOperationValue> result = fields();
        result.put(CREDENTIAL_ID, text(request.credentialId().value()));
        result.put(COUNT, integer(transitions.size()));
        result.put("truncated", bool(truncated));
        result.put("transitions", new PkiOperationValue.ListValue(transitions));
        return result(request.name(), result);
    }

    private PkiOperationResult snapshotRevocations(PkiOperation.SnapshotRevocations request,
            CancellationSignal signal) throws IOException {
        List<PkiOperationValue> records = new ArrayList<>();
        boolean truncated;
        Map<String, PkiOperationValue> result = fields();
        try (RevocationSnapshot snapshot = revocations.search(new RevocationQuery(Optional.empty(),
                Optional.empty(), Optional.empty(), Optional.empty()));
                RevocationSnapshot.Cursor cursor = snapshot.openCursor()) {
            while (records.size() < request.limit() && cursor.next(signal)) {
                records.add(revocationValue(cursor.current()));
            }
            truncated = records.size() == request.limit() && cursor.next(signal);
            result.put("snapshotId", text(snapshot.snapshotId()));
            result.put("revision", integer(snapshot.revision()));
            result.put("boundary", integer(snapshot.boundary()));
            result.put("commitment", text(snapshot.commitment()));
        }
        result.put(COUNT, integer(records.size()));
        result.put("truncated", bool(truncated));
        result.put("records", new PkiOperationValue.ListValue(records));
        return result(request.name(), result);
    }

    private PkiOperationResult inspectPublication(PkiOperation.InspectPublication request) {
        PublicationRecord record = store.getPublicationRecord(request.publicationId()).orElseThrow(Missing::new);
        return publicationRecordResult(request.name(), record);
    }

    private PkiOperationResult registerPublication(PkiOperation.RegisterPublication request) {
        PublicationRecord record = requirePublication().register(new PublicationRequest(request.publicationId(),
                request.sourceType(), request.sourceId(), request.target()));
        return publicationRecordResult(request.name(), record);
    }

    private PkiOperationResult publicationResult(String operation, PublicationResult publication) {
        if (publication.status() == PublicationStatus.OUTCOME_UNKNOWN) {
            throw new ExternalUnknown();
        }
        Map<String, PkiOperationValue> result = fields();
        result.put("publicationId", text(publication.publicationId().value()));
        result.put(STATUS, text(publication.status().name()));
        result.put("attemptNumber", integer(publication.attemptNumber()));
        return result(operation, result);
    }

    private static PkiOperationResult publicationRecordResult(String operation, PublicationRecord publication) {
        Map<String, PkiOperationValue> result = fields();
        result.put("publicationId", text(publication.publicationId().value()));
        result.put("sourceType", text(publication.sourceType().name()));
        result.put("sourceId", text(publication.sourceId().value()));
        result.put(STATUS, text(publication.status().name()));
        result.put("attemptNumber", integer(publication.attemptNumber()));
        return result(operation, result);
    }

    private PkiOperationResult updateStatusSchedule(PkiOperation.SetStatusSchedule request) {
        if (!store.supportsStatusScheduling()) { throw new CapabilityMissing(); }
        java.time.Instant now = clock.instant();
        StatusSchedule schedule = new StatusSchedule(request.caId(), request.statusType(), request.formatId(),
                request.interval(), request.graceSeconds(), request.enabled(), request.publicationTarget(),
                now, now, 0L);
        StatusSchedule stored = store.putStatusSchedule(schedule);
        return result(request.name(), scheduleFields(stored));
    }

    private PkiOperationResult inspectStatusSchedule(PkiOperation.InspectStatusSchedule request) {
        StatusSchedule schedule = store.getStatusSchedule(request.caId(), request.statusType())
                .orElseThrow(Missing::new);
        Map<String, PkiOperationValue> result = scheduleFields(schedule);
        if (store.supportsStatusScheduling()) {
            zeroecho.pki.api.schedule.StatusScheduleState state = store.getStatusScheduleState(request.caId(), request.statusType()).orElseThrow(Missing::new);
            result = scheduleFields(state.configuration());
            result.put("nextDue", text(state.nextDue().toString()));
            result.put("workerRevision", integer(state.workerRevision()));
            result.put("executionState", text(state.execution().map(value -> value.phase().name()).orElse("IDLE")));
            if (state.execution().isPresent()) {
                zeroecho.pki.api.schedule.StatusScheduleState.Execution execution = state.execution().orElseThrow();
                addScheduleExecution(result, execution);
            }
        }
        return result(request.name(), result);
    }

    private static void addScheduleExecution(Map<String, PkiOperationValue> result,
            zeroecho.pki.api.schedule.StatusScheduleState.Execution execution) {
        result.put("executionId", text(execution.executionId()));
        if (!execution.detailCode().isEmpty()) { result.put("failureCode", text(execution.detailCode())); }
        execution.signingOperationId().ifPresent(id -> result.put("signingOperationId", text(id.value())));
    }

    private PkiOperationResult listStatusSchedules(PkiOperation.ListStatusSchedules request,
            CancellationSignal signal) {
        return page(request.name(), "schedules", "cursor", request.limit(),
                store.listActiveStatusSchedulesPage(request.after(), request.limit() + 1, signal).stream()
                        .map(s -> object(scheduleFields(s))).toList());
    }

    private static Map<String, PkiOperationValue> scheduleFields(StatusSchedule schedule) {
        Map<String, PkiOperationValue> result = fields();
        result.put("cursor", text(PkiStore.statusScheduleCursor(schedule)));
        result.put(TEXT_CA_ID, text(schedule.caId().value()));
        result.put("statusType", text(schedule.statusType().name()));
        result.put("formatId", text(schedule.formatId().value()));
        result.put("interval", text(schedule.interval().toString()));
        result.put("graceSeconds", integer(schedule.graceSeconds()));
        result.put("enabled", bool(schedule.enabled()));
        schedule.publicationTarget().ifPresent(target -> {
            result.put("publicationTargetType", text(target.type().name()));
            result.put("publicationTargetId", text(target.targetId()));
        });
        result.put("createdAt", text(schedule.createdAt().toString()));
        result.put("updatedAt", text(schedule.updatedAt().toString()));
        result.put("revision", integer(schedule.revision()));
        return result;
    }

    private CertificationRequestService requireRequests() {
        return requests.orElseThrow(CapabilityMissing::new);
    }

    private PublicationService requirePublication() {
        return publications.orElseThrow(CapabilityMissing::new);
    }

    private static PkiOperationResult revocationResult(String operation, RevocationRecord record) {
        Map<String, PkiOperationValue> result = fields();
        result.put(CREDENTIAL_ID, text(record.credentialId().value()));
        appendTransition(result, record.transition());
        return result(operation, result);
    }

    private static PkiOperationValue revocationValue(RevocationRecord record) {
        Map<String, PkiOperationValue> result = fields();
        result.put(CREDENTIAL_ID, text(record.credentialId().value()));
        appendTransition(result, record.transition());
        return new PkiOperationValue.ObjectValue(result);
    }

    private static PkiOperationValue transitionValue(RevocationTransition transition) {
        Map<String, PkiOperationValue> result = fields();
        appendTransition(result, transition);
        return new PkiOperationValue.ObjectValue(result);
    }

    private static void appendTransition(Map<String, PkiOperationValue> result, RevocationTransition transition) {
        result.put("revision", integer(transition.revision()));
        result.put("state", text(transition.state().name()));
        result.put("time", text(transition.time().toString()));
        transition.permanentReason().ifPresent(reason -> result.put("reason", text(reason.name())));
    }

    private static PkiOperationResult profileReferenceResult(String operation, CertificateProfileRef reference) {
        Map<String, PkiOperationValue> result = fields();
        appendProfileReference(result, reference);
        return result(operation, result);
    }

    private static PkiOperationValue profileVersionValue(ImportedCertificateProfileVersion version) {
        Map<String, PkiOperationValue> result = fields();
        appendProfileVersion(result, version);
        return new PkiOperationValue.ObjectValue(result);
    }

    private static void appendProfileVersion(Map<String, PkiOperationValue> result,
            ImportedCertificateProfileVersion version) {
        appendProfileReference(result, version.reference());
        result.put("certificateType", text(version.definition().certificateType().name()));
        result.put(FORMAT_ID, text(version.definition().formatId().value()));
        result.put("importedAt", text(version.importedAt().toString()));
        result.put("displayName", text(version.definition().displayName()));
        result.put("maximumValidity", text(version.definition().maximumValidity().toString()));
        if (version.definition().certificateType() == zeroecho.pki.api.profile.CertificateProfileKind.END_ENTITY) {
            result.put("publicKeyAlgorithms", new PkiOperationValue.ListValue(version.definition().leafPolicy()
                    .allowedSubjectKeyAlgorithmIds().stream().sorted().<PkiOperationValue>map(DefaultPkiOperationExecutor::text).toList()));
        }
        X509AlgorithmBindingPolicy policy = version.definition().algorithmBindingPolicy();
        List<PkiOperationValue> policies = policy.mode() == X509AlgorithmBindingPolicy.Mode.STANDARD_ONLY
                ? List.of(text("STANDARD_ONLY"))
                : java.util.stream.Stream.of(policy.subjectPublicKey(), policy.csrSignature(), policy.certificateSignature(), policy.crlSignature())
                        .flatMap(Optional::stream).map(X509AlgorithmBindingPolicy.BindingReference::bindingId)
                        .distinct().sorted().<PkiOperationValue>map(DefaultPkiOperationExecutor::text).toList();
        result.put("x509BindingPolicies", new PkiOperationValue.ListValue(policies));
    }

    private static void appendProfileReference(Map<String, PkiOperationValue> result,
            CertificateProfileRef reference) {
        result.put(PROFILE_ID, text(reference.profileId()));
        result.put("profileVersion", integer(reference.profileVersion()));
        result.put("canonicalSha256", text(java.util.HexFormat.of().formatHex(reference.canonicalSha256())));
    }

    private PkiOperationValue.ObjectValue publicationSelection(PublicationRecord record) {
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>(publicationRecordResult("ignored", record).fields());
        if (record.sourceType() == zeroecho.pki.api.publication.PublicationSourceType.CREDENTIAL) {
            Map<String, PkiOperationValue> source = credentialFields(store.getCredential(record.sourceId()).orElseThrow(Missing::new));
            for (String key : List.of(AUTHORITY_ID, ISSUER_ID, PROFILE_ID)) { fields.put(key, source.get(key)); }
        } else {
            fields.put(AUTHORITY_ID, text(store.getStatusObject(record.sourceId()).orElseThrow(Missing::new).issuerCaId().value()));
        }
        return object(fields);
    }

    private PkiOperationResult dispatch(PkiOperation exact, CancellationSignal signal) throws IOException {
        return switch (exact) {
            case PkiOperation.ListAlgorithmBindings request -> selection(request, row -> true, signal);
            case PkiOperation.ListProfiles request -> selection(request, row -> true, signal);
            case PkiOperation.ListRequests request -> selection(request, row -> true, signal);
            case PkiOperation.SearchCredentials request -> selection(request, credentialSearchFilter(request), signal);
            case PkiOperation.ListIssuerGenerations request -> selection(request, row -> true, signal);
            case PkiOperation.InspectAlgorithmBinding request -> inspectAlgorithmBinding(request);
            case PkiOperation.ValidateAlgorithmBindings request -> validateAlgorithmBindings(request);
            case PkiOperation.ValidateConfiguration ignored -> validateConfiguration();
            case PkiOperation.ValidateProfile request -> validateProfile(request);
            case PkiOperation.RegisterProfile request -> registerProfile(request);
            case PkiOperation.InspectProfile request -> inspectProfile(request);
            case PkiOperation.ListProfileVersions request -> listProfileVersions(request);
            case PkiOperation.ActivateProfile request -> activateProfile(request);
            case PkiOperation.InspectAuthority request -> inspectAuthority(request);
            case PkiOperation.InspectCredential request -> inspectCredential(request);
            case PkiOperation.InspectIssuerGeneration request -> inspectIssuerGeneration(request);
            case PkiOperation.InspectIssuerChainPath request -> inspectIssuerChainPath(request);
            case PkiOperation.InspectStatus request -> inspectStatus(request);
            case PkiOperation.ListAuthorities request -> selection(request, row -> true, signal);
            case PkiOperation.ListStatus request -> selection(request, row -> true, signal);
            case PkiOperation.ListIssuerChainPaths request -> listIssuerChainPaths(request);
            case PkiOperation.TransitionAuthority request -> transitionAuthority(request);
            case PkiOperation.SelectIssuancePath request -> selectIssuancePath(request);
            case PkiOperation.RegisterIssuerChainPath request -> registerIssuerChainPath(request);
            case PkiOperation.InspectRequest request -> inspectRequest(request);
            case PkiOperation.ImportRequest request -> importRequest(request);
            case PkiOperation.VerifyRequest request -> verifyRequest(request);
            case PkiOperation.ListPendingCredentialConfirmations request -> listPendingConfirmations(request);
            case PkiOperation.IssueCredentialConfirmationChallenge request -> issueChallenge(request);
            case PkiOperation.CompleteCredentialConfirmationProof request -> completeProof(request);
            case PkiOperation.RevokePendingCredentialConfirmation request -> revokePending(request,
                    zeroecho.pki.impl.core.attr.SimpleAttributeSet.builder().build());
            case PkiOperation.RevokeCredential request -> revoke(request,
                    zeroecho.pki.impl.core.attr.SimpleAttributeSet.builder().build());
            case PkiOperation.InspectRevocation request -> inspectRevocation(request);
            case PkiOperation.ReadRevocationHistory request -> readHistory(request, signal);
            case PkiOperation.SnapshotRevocations request -> snapshotRevocations(request, signal);
            case PkiOperation.InspectPublication request -> inspectPublication(request);
            case PkiOperation.ListPublications request -> selection(request, row -> true, signal);
            case PkiOperation.RegisterPublication request -> registerPublication(request);
            case PkiOperation.ProcessPublication request -> publicationResult(request.name(),
                    requirePublication().process(request.publicationId()));
            case PkiOperation.RetryPublication request -> publicationResult(request.name(),
                    requirePublication().retry(request.publicationId()));
            case PkiOperation.ReconcilePublication request -> publicationResult(request.name(),
                    requirePublication().reconcile(request.publicationId()));
            case PkiOperation.SetStatusSchedule request -> updateStatusSchedule(request);
            case PkiOperation.InspectStatusSchedule request -> inspectStatusSchedule(request);
            case PkiOperation.ListStatusSchedules request -> listStatusSchedules(request, signal);
            case PkiOperation.QueryAuthorityMetrics request -> queryAuthorityMetrics(request, signal);
            case PkiOperation.QueryCertificateMetrics request -> queryCertificateMetrics(request, signal);
            case PkiOperation.QueryRevocationMetrics request -> queryRevocationMetrics(request, signal);
            case PkiOperation.QueryPublicationMetrics request -> queryPublicationMetrics(request, signal);
            case PkiOperation.QueryServerMetrics request -> queryServerMetrics(request);
        };
    }


    private static PkiOperationOutcome classify(String operation, RuntimeException exception) {
        if (exception instanceof java.util.concurrent.CancellationException) {
            return failure(operation, PkiOperationFailure.CANCELLED, OPERATION_CANCELLED);
        }
        if (exception instanceof CapabilityMissing) {
            return failure(operation, PkiOperationFailure.VALIDATION_FAILURE, "CAPABILITY_NOT_CONFIGURED");
        }
        if (exception instanceof ExternalUnknown) {
            return failure(operation, PkiOperationFailure.EXTERNAL_OUTCOME_UNKNOWN, "EXTERNAL_OUTCOME_UNKNOWN");
        }
        if (exception instanceof Missing) {
            return failure(operation, PkiOperationFailure.NOT_FOUND, "OBJECT_NOT_FOUND");
        }
        if (exception instanceof Conflict) {
            return failure(operation, PkiOperationFailure.CONFLICT, "OPERATION_CONFLICT");
        }
        if (exception instanceof IllegalArgumentException) {
            return failure(operation, PkiOperationFailure.VALIDATION_FAILURE, "OPERATION_INPUT_INVALID");
        }
        if (exception instanceof PkiException pkiFailure) {
            return classifyPki(operation, pkiFailure);
        }
        if (exception instanceof IllegalStateException) {
            return failure(operation, PkiOperationFailure.RESOURCE_FAILURE, "PKI_RESOURCE_FAILED");
        }
        return failure(operation, PkiOperationFailure.INTERNAL_FAILURE, "INTERNAL_FAILURE");
    }

    private static PkiOperationOutcome classifyPki(String operation, PkiException pkiFailure) {
        Optional<PkiFailureReason> reason = pkiFailure.failureReason();
        if (reason.isPresent()) {
            return switch (reason.get().classification()) {
                case RECOVERY_REQUIRED -> failure(operation, PkiOperationFailure.RECOVERY_REQUIRED, "RECOVERY_REQUIRED");
                case NOT_FOUND -> failure(operation, PkiOperationFailure.NOT_FOUND, "OBJECT_NOT_FOUND");
                case CONFLICT -> failure(operation, PkiOperationFailure.CONFLICT, "OPERATION_CONFLICT");
                case RESOURCE_FAILURE -> failure(operation, PkiOperationFailure.RESOURCE_FAILURE, "PKI_RESOURCE_FAILED");
                case EXTERNAL_OUTCOME_UNKNOWN -> failure(operation, PkiOperationFailure.EXTERNAL_OUTCOME_UNKNOWN, "EXTERNAL_OUTCOME_UNKNOWN");
                case VALIDATION_FAILURE -> failure(operation, PkiOperationFailure.VALIDATION_FAILURE, "OPERATION_INPUT_INVALID");
                case CANCELLED -> failure(operation, PkiOperationFailure.CANCELLED, OPERATION_CANCELLED);
                case OVERLOADED -> failure(operation, PkiOperationFailure.OVERLOADED, "PKI_OVERLOADED");
                case INTERNAL_FAILURE -> failure(operation, PkiOperationFailure.INTERNAL_FAILURE, "INTERNAL_FAILURE");
                default -> failure(operation, PkiOperationFailure.POLICY_REJECTION, "PKI_POLICY_REJECTED");
            };
        }
        return failure(operation, PkiOperationFailure.POLICY_REJECTION, "PKI_POLICY_REJECTED");
    }


    private static PkiOperationOutcome failure(String operation, PkiOperationFailure classification, String code) {
        return new PkiOperationOutcome.Failed(operation, classification, code);
    }

    private static PkiOperationResult result(String operation, Map<String, PkiOperationValue> values) {
        return new PkiOperationResult(operation, values);
    }

    private static Map<String, PkiOperationValue> fields() { return new LinkedHashMap<>(); }
    private static PkiOperationValue text(String value) { return new PkiOperationValue.Text(value); }
    private static PkiOperationValue integer(long value) { return new PkiOperationValue.IntegerValue(value); }
    private static PkiOperationValue bool(boolean value) { return new PkiOperationValue.BooleanValue(value); }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private PkiOperationResult queryAuthorityMetrics(PkiOperation.QueryAuthorityMetrics request,
            CancellationSignal signal) throws IOException {
        CaRecord ca = store.getCa(request.caId()).orElseThrow(Missing::new);
        long totalGenerations = 0L;
        long activeGenerations = 0L;
        Optional<String> after = Optional.empty();
        while (true) {
            signal.throwIfCancelled();
            List<IssuerGeneration> page = store.listIssuerGenerationsPage(
                    request.caId(), after, DASHBOARD_PAGE_SIZE + 1, g -> true, signal);
            boolean hasMore = page.size() > DASHBOARD_PAGE_SIZE;
            List<IssuerGeneration> batch = hasMore ? page.subList(0, DASHBOARD_PAGE_SIZE) : page;
            totalGenerations += batch.size();
            activeGenerations += batch.stream().filter(g -> g.state() == IssuerGenerationState.ACTIVE).count();
            if (!hasMore) { break; }
            after = Optional.of(batch.get(batch.size() - 1).issuerId().value());
        }
        int chainDepth = store.getIssuerChainPath(ca.issuanceChainPathId())
                .map(path -> path.orderedCredentialIds().size()).orElse(0);
        Map<String, PkiOperationValue> result = fields();
        result.put(TEXT_CA_ID, text(ca.caId().value()));
        result.put("caState", text(ca.state().name()));
        result.put("issuerGenerationsTotal", integer(totalGenerations));
        result.put("issuerGenerationsActive", integer(activeGenerations));
        result.put("issuanceChainDepth", integer(chainDepth));
        result.put("computedAt", text(clock.instant().toString()));
        return result(request.name(), result);
    }

    private PkiOperationResult queryCertificateMetrics(PkiOperation.QueryCertificateMetrics request,
            CancellationSignal signal) throws IOException {
        java.time.Instant now = clock.instant();
        java.time.Instant in7d = now.plus(java.time.Duration.ofDays(7));
        java.time.Instant in30d = now.plus(java.time.Duration.ofDays(30));
        java.time.Instant in90d = now.plus(java.time.Duration.ofDays(90));
        long total = 0L;
        long activeTotal = 0L;
        long expiring7d = 0L;
        long expiring30d = 0L;
        long expiring90d = 0L;
        long revokedTotal = 0L;
        long expiredTotal = 0L;
        boolean countCapped = false;
        Optional<String> after = Optional.empty();
        while (total < CREDENTIAL_SCAN_CAP) {
            signal.throwIfCancelled();
            List<Credential> page = store.listCredentialsPage(
                    request.caId(), after, DASHBOARD_PAGE_SIZE + 1, c -> true, signal);
            boolean hasMore = page.size() > DASHBOARD_PAGE_SIZE;
            List<Credential> batch = hasMore ? page.subList(0, DASHBOARD_PAGE_SIZE) : page;
            for (Credential c : batch) {
                zeroecho.pki.api.credential.CredentialStatus status = c.status();
                java.time.Instant notAfter = c.validity().notAfter();
                if (status == zeroecho.pki.api.credential.CredentialStatus.ISSUED && notAfter.isAfter(now)) {
                    activeTotal++;
                    if (notAfter.isBefore(in7d)) { expiring7d++; }
                    if (notAfter.isBefore(in30d)) { expiring30d++; }
                    if (notAfter.isBefore(in90d)) { expiring90d++; }
                } else if (status == zeroecho.pki.api.credential.CredentialStatus.REVOKED) {
                    revokedTotal++;
                } else if (status == zeroecho.pki.api.credential.CredentialStatus.EXPIRED
                        || status == zeroecho.pki.api.credential.CredentialStatus.ISSUED && !notAfter.isAfter(now)) {
                    expiredTotal++;
                }
            }
            total += batch.size();
            if (!hasMore) { break; }
            if (total >= CREDENTIAL_SCAN_CAP) { countCapped = true; break; }
            after = Optional.of(batch.get(batch.size() - 1).credentialId().value());
        }
        Map<String, PkiOperationValue> result = fields();
        result.put(TEXT_CA_ID, text(request.caId().value()));
        result.put("certificatesTotal", integer(total));
        result.put("countCapped", bool(countCapped));
        result.put("activeTotal", integer(activeTotal));
        result.put("expiring7dTotal", integer(expiring7d));
        result.put("expiring30dTotal", integer(expiring30d));
        result.put("expiring90dTotal", integer(expiring90d));
        result.put("revokedTotal", integer(revokedTotal));
        result.put("expiredTotal", integer(expiredTotal));
        result.put("metricStates", object(Map.of("pendingRequestsTotal", metricState(
                DashboardLiveSource.Metric.unavailable("CA_REQUEST_LIFECYCLE_UNAVAILABLE")))));
        result.put("computedAt", text(now.toString()));
        return result(request.name(), result);
    }

    private PkiOperationResult queryRevocationMetrics(PkiOperation.QueryRevocationMetrics request,
            CancellationSignal signal) throws IOException {
        long revokedTotal = 0L;
        Optional<String> after = Optional.empty();
        while (true) {
            signal.throwIfCancelled();
            List<Credential> page = store.listCredentialsPage(request.caId(), after, DASHBOARD_PAGE_SIZE + 1,
                    c -> c.status() == zeroecho.pki.api.credential.CredentialStatus.REVOKED, signal);
            boolean hasMore = page.size() > DASHBOARD_PAGE_SIZE;
            List<Credential> batch = hasMore ? page.subList(0, DASHBOARD_PAGE_SIZE) : page;
            revokedTotal += batch.size();
            if (!hasMore) { break; }
            after = Optional.of(batch.get(batch.size() - 1).credentialId().value());
        }
        Optional<StatusObject> latestCrl = Optional.empty();
        after = Optional.empty();
        while (true) {
            signal.throwIfCancelled();
            List<StatusObject> page = store.listStatusObjectsPage(request.caId(), after, DASHBOARD_PAGE_SIZE + 1,
                    s -> s.type() == zeroecho.pki.api.status.StatusObjectType.CRL, signal);
            boolean hasMore = page.size() > DASHBOARD_PAGE_SIZE;
            List<StatusObject> batch = hasMore ? page.subList(0, DASHBOARD_PAGE_SIZE) : page;
            for (StatusObject s : batch) {
                if (latestCrl.isEmpty() || s.thisUpdate().isAfter(latestCrl.get().thisUpdate())) {
                    latestCrl = Optional.of(s);
                }
            }
            if (!hasMore) { break; }
            after = Optional.of(batch.get(batch.size() - 1).statusObjectId().value());
        }
        java.time.Instant now = clock.instant();
        Map<String, PkiOperationValue> result = fields();
        result.put(TEXT_CA_ID, text(request.caId().value()));
        result.put("revokedTotal", integer(revokedTotal));
        if (latestCrl.isPresent()) {
            StatusObject crl = latestCrl.get();
            result.put("crlLastGeneratedEpoch", integer(crl.thisUpdate().getEpochSecond()));
            result.put("crlFreshnessSeconds", integer(now.getEpochSecond() - crl.thisUpdate().getEpochSecond()));
            crl.nextUpdate().ifPresent(next -> result.put("crlNextUpdateEpoch", integer(next.getEpochSecond())));
            result.put("crlSizeBytes", integer(crl.content().length()));
        }
        result.put("computedAt", text(now.toString()));
        return result(request.name(), result);
    }

    private PkiOperationResult queryPublicationMetrics(PkiOperation.QueryPublicationMetrics request,
            CancellationSignal signal) throws IOException {
        Optional<StatusObject> latestCrl = latestCrl(request.caId(), signal);
        long pendingPublications = 0L;
        long terminalFailures = 0L;
        Optional<String> after = Optional.empty();
        while (true) {
            signal.throwIfCancelled();
            List<PublicationRecord> page = store.listPublicationsPage(after, DASHBOARD_PAGE_SIZE + 1,
                    publication -> publicationAuthority(publication).filter(request.caId()::equals).isPresent(), signal);
            boolean hasMore = page.size() > DASHBOARD_PAGE_SIZE;
            List<PublicationRecord> batch = hasMore ? page.subList(0, DASHBOARD_PAGE_SIZE) : page;
            for (PublicationRecord p : batch) {
                if (p.status() == PublicationStatus.PENDING) { pendingPublications++; }
                if (p.status() == PublicationStatus.TERMINAL_FAILURE) { terminalFailures++; }
            }
            if (!hasMore) { break; }
            after = Optional.of(batch.get(batch.size() - 1).publicationId().value());
        }
        java.time.Instant now = clock.instant();
        Map<String, PkiOperationValue> result = fields();
        result.put(TEXT_CA_ID, text(request.caId().value()));
        result.put("publicationsPendingTotal", integer(pendingPublications));
        result.put("publicationsTerminalFailureTotal", integer(terminalFailures));
        if (latestCrl.isPresent()) {
            StatusObject crl = latestCrl.get();
            result.put("crlLastGeneratedEpoch", integer(crl.thisUpdate().getEpochSecond()));
            crl.nextUpdate().ifPresent(next -> result.put("crlNextUpdateEpoch", integer(next.getEpochSecond())));
        }
        result.put("computedAt", text(now.toString()));
        return result(request.name(), result);
    }

    private Optional<StatusObject> latestCrl(PkiId authorityId, CancellationSignal signal) throws IOException {
        Optional<StatusObject> latestCrl = Optional.empty();
        Optional<String> after = Optional.empty();
        while (true) {
            signal.throwIfCancelled();
            List<StatusObject> page = store.listStatusObjectsPage(authorityId, after, DASHBOARD_PAGE_SIZE + 1,
                    s -> s.type() == zeroecho.pki.api.status.StatusObjectType.CRL, signal);
            boolean hasMore = page.size() > DASHBOARD_PAGE_SIZE;
            List<StatusObject> batch = hasMore ? page.subList(0, DASHBOARD_PAGE_SIZE) : page;
            for (StatusObject s : batch) {
                if (latestCrl.isEmpty() || s.thisUpdate().isAfter(latestCrl.get().thisUpdate())) {
                    latestCrl = Optional.of(s);
                }
            }
            if (!hasMore) { break; }
            after = Optional.of(batch.get(batch.size() - 1).statusObjectId().value());
        }
        return latestCrl;
    }


    private PkiOperationResult queryServerMetrics(PkiOperation.QueryServerMetrics request) {
        Map<String, PkiOperationValue> result = fields();
        Map<String, PkiOperationValue> states = fields();
        liveSource.snapshot().forEach((name, metric) -> {
            metric.value().ifPresent(value -> result.put(name, integer(value)));
            states.put(name, metricState(metric));
        });
        result.put("metricStates", object(states));
        result.put("computedAt", text(clock.instant().toString()));
        return result(request.name(), result);
    }

    private Optional<PkiId> publicationAuthority(PublicationRecord publication) {
        return switch (publication.sourceType()) {
            case STATUS_OBJECT -> store.getStatusObject(publication.sourceId()).map(StatusObject::issuerCaId);
            case CREDENTIAL -> store.getCredential(publication.sourceId()).map(value -> value.issuerRef().caId());
        };
    }

    private static PkiOperationValue metricState(DashboardLiveSource.Metric metric) {
        Map<String, PkiOperationValue> fields = fields();
        fields.put("state", text(metric.state().name()));
        if (!metric.reason().isEmpty()) { fields.put("reason", text(metric.reason())); }
        return object(fields);
    }

    /** Internal control signal for a missing authoritative object. */
    private static final class Missing extends RuntimeException { private static final long serialVersionUID = 1L; }
    /** Internal control signal for an authoritative conflict. */
    private static final class Conflict extends RuntimeException { private static final long serialVersionUID = 1L; }
    /** Internal control signal for an unavailable optional capability. */
    private static final class CapabilityMissing extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }
    /** Internal control signal for an uncertain external outcome. */
    private static final class ExternalUnknown extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }
}
