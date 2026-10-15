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
package zeroecho.pki.cli;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.publication.PublicationSourceType;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.publication.PublicationTargetType;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiSigningOperation;
import java.time.Instant;
import java.util.Base64;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofCas;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofSubmission;
import zeroecho.pki.api.confirmation.CredentialConfirmationReviewCursor;
import zeroecho.pki.application.PkiOperationValue;

/** Explicit stable operation-name to typed-request binding registry. */
// A single closed registry keeps every stable external operation name visibly bound to its typed parser.
@SuppressWarnings({"PMD.CyclomaticComplexity", "PMD.TooManyMethods", "PMD.UnusedFormalParameter"})
final class PkiOperationRegistry {
    private static final String PARAM_JUSTIFICATION = "justification";
    private static final String TEXT_CA_ID = "caId";

    private static final String AFTER = "after";
    private static final String SCOPE_AUTHORITY_ID = "authorityId";


    private static final String CREDENTIAL_ID = "credentialId";
    private static final String FORMAT_ID = "formatId";
    private static final String ISSUER_CA_ID = "issuerCaId";
    private static final String LIMIT = "limit";
    private static final String PUBLICATION_ID = "publicationId";
    private static final String PROFILE_FILE = "profileFile";
    private static final String PROFILE_ID = "profileId";
    private static final String PROFILE_VERSION = "profileVersion";
    private static final String REQUEST_ID = "requestId";
    private static final String BINDING_ID = "bindingId";
    private static final String AUTHORITY_ID = TEXT_CA_ID;
    private static final String FAILURE_REASON = "reason";
    private static final String ISSUER_ID = "issuerId";
    private static final String INVALID_ARGUMENTS = "PKI operation arguments are invalid";
    private static final int MAXIMUM_REQUEST_BYTES = 1024 * 1024;

    private final Map<String, Binding> bindings;

    /* default */ PkiOperationRegistry() {
        Map<String, Binding> configured = new LinkedHashMap<>();
        registerAuthorityBindings(configured);
        registerCredentialBindings(configured);
        registerStatusBindings(configured);
        registerPublicationBindings(configured);
        registerInventoryBindings(configured);
        registerMonitoringBindings(configured);
        configured.put(PkiLocalCommand.INSPECT, (arguments, base) -> new PkiLocalCommand.Inspect(operationId(arguments)));
        configured.put(PkiLocalCommand.COMPLETE, (arguments, base) -> new PkiLocalCommand.Complete(operationId(arguments)));
        bindings = Map.copyOf(configured);
    }

    private void registerAuthorityBindings(Map<String, Binding> configured) {
        add(configured, PkiOperation.ListAlgorithmBindings.NAME, this::listAlgorithmBindings);
        add(configured, PkiOperation.InspectAlgorithmBinding.NAME, this::inspectAlgorithmBinding);
        add(configured, PkiOperation.ValidateAlgorithmBindings.NAME, this::validateAlgorithmBindings);
        add(configured, PkiOperation.ValidateConfiguration.NAME, this::configuration);
        add(configured, PkiOperation.ValidateProfile.NAME, this::profile);
        add(configured, PkiOperation.RegisterProfile.NAME, this::registerProfile);
        add(configured, PkiOperation.InspectProfile.NAME, this::inspectProfile);
        add(configured, PkiOperation.ListProfileVersions.NAME, this::listProfiles);
        add(configured, PkiOperation.ActivateProfile.NAME, this::activateProfile);
        add(configured, PkiOperation.InspectAuthority.NAME, this::inspectAuthority);
        add(configured, PkiOperation.ListAuthorities.NAME, this::listAuthorities);
        addSigning(configured, PkiSigningOperation.CreateAuthority.NAME, this::createAuthority);
        add(configured, PkiOperation.TransitionAuthority.NAME, this::transitionAuthority);
    }

    private void registerCredentialBindings(Map<String, Binding> configured) {
        add(configured, PkiOperation.InspectRequest.NAME, this::inspectRequest);
        add(configured, PkiOperation.ImportRequest.NAME, this::importRequest);
        add(configured, PkiOperation.VerifyRequest.NAME, this::verifyRequest);
        add(configured, PkiOperation.InspectCredential.NAME, this::credential);
        addSigning(configured, PkiSigningOperation.IssueCredential.NAME, this::issueCredential);
        addSigning(configured, PkiSigningOperation.RenewCredential.NAME, this::renewCredential);
        addSigning(configured, PkiSigningOperation.ReplaceCredential.NAME, this::replaceCredential);
        addSigning(configured, PkiSigningOperation.ReissueCredential.NAME, this::reissueCredential);
        addSigning(configured, PkiSigningOperation.CreateIntermediate.NAME, this::createIntermediate);
        addSigning(configured, PkiSigningOperation.IssueIntermediateCertificate.NAME, this::issueIntermediate);
        addSigning(configured, PkiSigningOperation.RolloverCaCertificate.NAME, this::rolloverCa);
        addSigning(configured, PkiSigningOperation.RotateCaKey.NAME, this::rotateCaKey);
        add(configured, PkiOperation.InspectIssuerGeneration.NAME, this::inspectIssuerGeneration);
        add(configured, PkiOperation.InspectIssuerChainPath.NAME, this::inspectIssuerChainPath);
        add(configured, PkiOperation.ListIssuerChainPaths.NAME, this::listIssuerChainPaths);
        add(configured, PkiOperation.RegisterIssuerChainPath.NAME, this::registerIssuerChainPath);
        add(configured, PkiOperation.SelectIssuancePath.NAME, this::selectIssuancePath);
    }

    private void registerStatusBindings(Map<String, Binding> configured) {
        add(configured, PkiOperation.RevokeCredential.NAME, this::revoke);
        add(configured, PkiOperation.HoldCredential.NAME, this::hold);
        add(configured, PkiOperation.UnholdCredential.NAME, this::unhold);
        add(configured, PkiOperation.InspectRevocation.NAME, this::inspectRevocation);
        add(configured, PkiOperation.ReadRevocationHistory.NAME, this::history);
        add(configured, PkiOperation.SnapshotRevocations.NAME, this::snapshotRevocations);
        add(configured, PkiOperation.InspectStatus.NAME, this::inspectStatus);
        add(configured, PkiOperation.ListStatus.NAME, this::listStatus);
        addSigning(configured, PkiSigningOperation.GenerateStatus.NAME, this::generateStatus);
    }

    private void registerPublicationBindings(Map<String, Binding> configured) {
        add(configured, PkiOperation.InspectPublication.NAME, this::publication);
        add(configured, PkiOperation.ListPublications.NAME, this::listPublications);
        add(configured, PkiOperation.RegisterPublication.NAME, this::registerPublication);
        add(configured, PkiOperation.ProcessPublication.NAME, this::processPublication);
        add(configured, PkiOperation.RetryPublication.NAME, this::retryPublication);
        add(configured, PkiOperation.ReconcilePublication.NAME, this::reconcilePublication);
    }

    private void registerInventoryBindings(Map<String, Binding> configured) {
        add(configured, PkiOperation.ListProfiles.NAME, this::allProfiles);
        add(configured, PkiOperation.ListRequests.NAME, this::listRequests);
        add(configured, PkiOperation.SearchCredentials.NAME, this::searchCredentials);
        add(configured, PkiOperation.ListIssuerGenerations.NAME, this::listGenerations);
        add(configured, PkiOperation.ListPendingCredentialConfirmations.NAME, this::pendingConfirmations);
        add(configured, PkiOperation.IssueCredentialConfirmationChallenge.NAME, this::confirmationChallenge);
        add(configured, PkiOperation.CompleteCredentialConfirmationProof.NAME, this::confirmationProof);
        add(configured, PkiOperation.RevokePendingCredentialConfirmation.NAME, this::revokePending);
    }

    private void registerMonitoringBindings(Map<String, Binding> configured) {
        add(configured, PkiOperation.SetStatusSchedule.NAME, this::statusScheduleRequest);
        add(configured, PkiOperation.InspectStatusSchedule.NAME, this::inspectStatusSchedule);
        add(configured, PkiOperation.ListStatusSchedules.NAME, this::listStatusSchedules);
        add(configured, PkiOperation.QueryAuthorityMetrics.NAME, this::queryAuthorityMetrics);
        add(configured, PkiOperation.QueryCertificateMetrics.NAME, this::queryCertificateMetrics);
        add(configured, PkiOperation.QueryRevocationMetrics.NAME, this::queryRevocationMetrics);
        add(configured, PkiOperation.QueryPublicationMetrics.NAME, this::queryPublicationMetrics);
        add(configured, PkiOperation.QueryServerMetrics.NAME, this::queryServerMetrics);
    }

    /* default */ Set<String> names() {
        return bindings.keySet();
    }

    /* default */ PkiLocalCommand bind(String name, PkiOperationValue.ObjectValue arguments, Path baseDirectory)
            throws IOException {
        Binding binding = bindings.get(name);
        if (binding == null) {
            throw new IllegalArgumentException("Unknown PKI operation");
        }
        return binding.bind(arguments, baseDirectory);
    }

    private PkiOperation configuration(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of());
        return new PkiOperation.ValidateConfiguration();
    }

    private PkiOperation listAlgorithmBindings(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        Set<String> supplied = arguments.fields().keySet();
        if (!supplied.contains(LIMIT) || !Set.of(LIMIT, "origin", "role", AFTER).containsAll(supplied)) {
            throw new IllegalArgumentException(INVALID_ARGUMENTS);
        }
        return new PkiOperation.ListAlgorithmBindings(optionalText(arguments, "origin"),
                optionalText(arguments, "role"), limit(arguments), optionalText(arguments, AFTER));
    }

    private PkiOperation inspectAlgorithmBinding(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(BINDING_ID));
        return new PkiOperation.InspectAlgorithmBinding(text(arguments, BINDING_ID));
    }

    private PkiOperation validateAlgorithmBindings(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        Set<String> supplied = arguments.fields().keySet();
        if (!(supplied.isEmpty() || supplied.equals(Set.of(BINDING_ID, "bindingCommitment")))) {
            throw new IllegalArgumentException(INVALID_ARGUMENTS);
        }
        return new PkiOperation.ValidateAlgorithmBindings(optionalText(arguments, BINDING_ID),
                optionalText(arguments, "bindingCommitment"));
    }

    private PkiOperation profile(PkiOperationValue.ObjectValue arguments, Path baseDirectory) throws IOException {
        requireFields(arguments, Set.of(PROFILE_FILE));
        Path path = resolve(baseDirectory, text(arguments, PROFILE_FILE));
        byte[] document = PkiCliFiles.readRegularFile(path, CertificateProfileDocumentCodec.MAXIMUM_DOCUMENT_BYTES);
        return new PkiOperation.ValidateProfile(document);
    }

    private PkiOperation registerProfile(PkiOperationValue.ObjectValue arguments, Path baseDirectory)
            throws IOException {
        requireFields(arguments, Set.of(PROFILE_FILE));
        Path path = resolve(baseDirectory, text(arguments, PROFILE_FILE));
        byte[] document = PkiCliFiles.readRegularFile(path, CertificateProfileDocumentCodec.MAXIMUM_DOCUMENT_BYTES);
        return new PkiOperation.RegisterProfile(document);
    }

    private PkiOperation inspectProfile(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(PROFILE_ID, PROFILE_VERSION));
        return new PkiOperation.InspectProfile(text(arguments, PROFILE_ID), integer(arguments, PROFILE_VERSION));
    }

    private PkiOperation listProfiles(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(PROFILE_ID));
        return new PkiOperation.ListProfileVersions(text(arguments, PROFILE_ID));
    }

    private PkiOperation activateProfile(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(PROFILE_ID, PROFILE_VERSION));
        return new PkiOperation.ActivateProfile(text(arguments, PROFILE_ID), integer(arguments, PROFILE_VERSION));
    }

    private PkiOperation inspectAuthority(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(AUTHORITY_ID));
        return new PkiOperation.InspectAuthority(new PkiId(text(arguments, AUTHORITY_ID)));
    }

    private PkiOperation listAuthorities(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        pageFields(arguments, Set.of());
        return new PkiOperation.ListAuthorities(limit(arguments), optionalText(arguments, AFTER));
    }

    private PkiSigningOperation createAuthority(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(FORMAT_ID, "subjectRef", PROFILE_ID, "keyRef"));
        return new PkiSigningOperation.CreateAuthority(new FormatId(text(arguments, FORMAT_ID)),
                new SubjectRef(text(arguments, "subjectRef")), text(arguments, PROFILE_ID),
                new KeyRef(text(arguments, "keyRef")));
    }

    private PkiOperation transitionAuthority(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(AUTHORITY_ID, "state", FAILURE_REASON));
        return new PkiOperation.TransitionAuthority(new PkiId(text(arguments, AUTHORITY_ID)),
                CaState.valueOf(text(arguments, "state")), text(arguments, FAILURE_REASON));
    }

    private PkiOperation inspectRequest(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(REQUEST_ID));
        return new PkiOperation.InspectRequest(new PkiId(text(arguments, REQUEST_ID)));
    }

    private PkiOperation importRequest(PkiOperationValue.ObjectValue arguments, Path baseDirectory)
            throws IOException {
        requireFields(arguments, Set.of(FORMAT_ID, "encoding", "requestFile"));
        Path path = resolve(baseDirectory, text(arguments, "requestFile"));
        byte[] document = PkiCliFiles.readRegularFile(path, MAXIMUM_REQUEST_BYTES);
        return new PkiOperation.ImportRequest(new FormatId(text(arguments, FORMAT_ID)),
                new EncodedObject(Encoding.valueOf(text(arguments, "encoding")), document));
    }

    private PkiOperation verifyRequest(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(REQUEST_ID));
        return new PkiOperation.VerifyRequest(new PkiId(text(arguments, REQUEST_ID)));
    }

    private PkiOperation credential(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(CREDENTIAL_ID));
        return new PkiOperation.InspectCredential(new PkiId(text(arguments, CREDENTIAL_ID)));
    }

    private PkiSigningOperation issueCredential(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(ISSUER_CA_ID, REQUEST_ID, PROFILE_ID));
        return new PkiSigningOperation.IssueCredential(new PkiId(text(arguments, ISSUER_CA_ID)),
                new PkiId(text(arguments, REQUEST_ID)), text(arguments, PROFILE_ID));
    }

    private PkiSigningOperation renewCredential(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(CREDENTIAL_ID));
        return new PkiSigningOperation.RenewCredential(new PkiId(text(arguments, CREDENTIAL_ID)));
    }

    private PkiSigningOperation replaceCredential(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of("existingCredentialId", REQUEST_ID, PROFILE_ID));
        return new PkiSigningOperation.ReplaceCredential(new PkiId(text(arguments, "existingCredentialId")),
                new PkiId(text(arguments, REQUEST_ID)), text(arguments, PROFILE_ID));
    }

    private PkiSigningOperation reissueCredential(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(CREDENTIAL_ID));
        return new PkiSigningOperation.ReissueCredential(new PkiId(text(arguments, CREDENTIAL_ID)));
    }

    private PkiSigningOperation createIntermediate(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        Set<String> supplied = arguments.fields().keySet();
        if (!supplied.containsAll(Set.of(FORMAT_ID, ISSUER_CA_ID, "subjectRef", PROFILE_ID))
                || !Set.of(FORMAT_ID, ISSUER_CA_ID, "subjectRef", PROFILE_ID, "keyRef").containsAll(supplied)) {
            throw new IllegalArgumentException(INVALID_ARGUMENTS);
        }
        return new PkiSigningOperation.CreateIntermediate(new FormatId(text(arguments, FORMAT_ID)),
                new PkiId(text(arguments, ISSUER_CA_ID)), new SubjectRef(text(arguments, "subjectRef")),
                text(arguments, PROFILE_ID), optionalText(arguments, "keyRef").map(KeyRef::new));
    }

    private PkiSigningOperation issueIntermediate(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(FORMAT_ID, ISSUER_CA_ID, "subjectCaId", PROFILE_ID));
        return new PkiSigningOperation.IssueIntermediateCertificate(new FormatId(text(arguments, FORMAT_ID)),
                new PkiId(text(arguments, ISSUER_CA_ID)), new PkiId(text(arguments, "subjectCaId")),
                text(arguments, PROFILE_ID), java.util.Optional.empty());
    }

    private PkiSigningOperation rolloverCa(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        Set<String> supplied = arguments.fields().keySet();
        if (!supplied.contains(AUTHORITY_ID) || !Set.of(AUTHORITY_ID, ISSUER_CA_ID).containsAll(supplied)) {
            throw new IllegalArgumentException(INVALID_ARGUMENTS);
        }
        return new PkiSigningOperation.RolloverCaCertificate(new PkiId(text(arguments, AUTHORITY_ID)),
                optionalText(arguments, ISSUER_CA_ID).map(PkiId::new));
    }

    private PkiSigningOperation rotateCaKey(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        Set<String> supplied = arguments.fields().keySet();
        if (!supplied.contains(AUTHORITY_ID) || !Set.of(AUTHORITY_ID, "newKeyRef", ISSUER_CA_ID).containsAll(supplied)) {
            throw new IllegalArgumentException(INVALID_ARGUMENTS);
        }
        return new PkiSigningOperation.RotateCaKey(new PkiId(text(arguments, AUTHORITY_ID)),
                optionalText(arguments, "newKeyRef").map(KeyRef::new),
                optionalText(arguments, ISSUER_CA_ID).map(PkiId::new));
    }

    private PkiOperation inspectIssuerGeneration(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(ISSUER_ID));
        return new PkiOperation.InspectIssuerGeneration(new PkiId(text(arguments, ISSUER_ID)));
    }

    private PkiOperation inspectIssuerChainPath(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of("pathId"));
        return new PkiOperation.InspectIssuerChainPath(new PkiId(text(arguments, "pathId")));
    }

    private PkiOperation listIssuerChainPaths(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(ISSUER_ID));
        return new PkiOperation.ListIssuerChainPaths(new PkiId(text(arguments, ISSUER_ID)));
    }

    private PkiOperation registerIssuerChainPath(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(AUTHORITY_ID, ISSUER_ID, "parentPathId"));
        return new PkiOperation.RegisterIssuerChainPath(new PkiId(text(arguments, AUTHORITY_ID)),
                new PkiId(text(arguments, ISSUER_ID)), new PkiId(text(arguments, "parentPathId")));
    }

    private PkiOperation selectIssuancePath(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(AUTHORITY_ID, ISSUER_ID, "pathId", FAILURE_REASON));
        return new PkiOperation.SelectIssuancePath(new PkiId(text(arguments, AUTHORITY_ID)),
                new PkiId(text(arguments, ISSUER_ID)), new PkiId(text(arguments, "pathId")),
                text(arguments, FAILURE_REASON));
    }

    private PkiOperation revoke(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        Set<String> supplied = arguments.fields().keySet();
        if (!supplied.containsAll(Set.of(CREDENTIAL_ID, FAILURE_REASON))
                || !Set.of(CREDENTIAL_ID, FAILURE_REASON, PARAM_JUSTIFICATION).containsAll(supplied)) {
            throw new IllegalArgumentException(INVALID_ARGUMENTS);
        }
        RevocationReason reason = RevocationReason.valueOf(text(arguments, FAILURE_REASON));
        return new PkiOperation.RevokeCredential(new PkiId(text(arguments, CREDENTIAL_ID)), reason,
                optionalText(arguments, PARAM_JUSTIFICATION));
    }

    private PkiOperation history(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(CREDENTIAL_ID, LIMIT));
        return new PkiOperation.ReadRevocationHistory(new PkiId(text(arguments, CREDENTIAL_ID)), limit(arguments));
    }

    private PkiOperation hold(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireHoldFields(arguments);
        return new PkiOperation.HoldCredential(new PkiId(text(arguments, CREDENTIAL_ID)), optionalText(arguments, PARAM_JUSTIFICATION));
    }

    private PkiOperation unhold(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireHoldFields(arguments);
        return new PkiOperation.UnholdCredential(new PkiId(text(arguments, CREDENTIAL_ID)), optionalText(arguments, PARAM_JUSTIFICATION));
    }

    private static void requireHoldFields(PkiOperationValue.ObjectValue arguments) {
        Set<String> supplied = arguments.fields().keySet();
        if (!supplied.contains(CREDENTIAL_ID) || !Set.of(CREDENTIAL_ID, PARAM_JUSTIFICATION).containsAll(supplied)) {
            throw new IllegalArgumentException(INVALID_ARGUMENTS);
        }
    }

    private PkiOperation inspectRevocation(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(CREDENTIAL_ID));
        return new PkiOperation.InspectRevocation(new PkiId(text(arguments, CREDENTIAL_ID)));
    }

    private PkiOperation snapshotRevocations(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(LIMIT));
        return new PkiOperation.SnapshotRevocations(limit(arguments));
    }

    private PkiOperation inspectStatus(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of("statusObjectId"));
        return new PkiOperation.InspectStatus(new PkiId(text(arguments, "statusObjectId")));
    }

    private PkiOperation listStatus(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        pageFields(arguments, Set.of(ISSUER_CA_ID));
        return new PkiOperation.ListStatus(new PkiId(text(arguments, ISSUER_CA_ID)), limit(arguments), optionalText(arguments, AFTER));
    }

    private PkiSigningOperation generateStatus(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(ISSUER_CA_ID, "type", FORMAT_ID));
        return new PkiSigningOperation.GenerateStatus(new PkiId(text(arguments, ISSUER_CA_ID)),
                StatusObjectType.valueOf(text(arguments, "type")), new FormatId(text(arguments, FORMAT_ID)));
    }

    private PkiOperation publication(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(PUBLICATION_ID));
        return new PkiOperation.InspectPublication(new PkiId(text(arguments, PUBLICATION_ID)));
    }

    private PkiOperation listPublications(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        pageFields(arguments, Set.of());
        return new PkiOperation.ListPublications(limit(arguments), optionalText(arguments, AFTER));
    }

    private PkiOperation registerPublication(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments,
                Set.of(PUBLICATION_ID, "sourceType", "sourceId", "targetType", "targetId"));
        PublicationTarget target = new PublicationTarget(PublicationTargetType.valueOf(text(arguments, "targetType")),
                text(arguments, "targetId"));
        return new PkiOperation.RegisterPublication(new PkiId(text(arguments, PUBLICATION_ID)),
                PublicationSourceType.valueOf(text(arguments, "sourceType")),
                new PkiId(text(arguments, "sourceId")), target);
    }

    private PkiOperation processPublication(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        return new PkiOperation.ProcessPublication(publicationId(arguments));
    }

    private PkiOperation retryPublication(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        return new PkiOperation.RetryPublication(publicationId(arguments));
    }

    private PkiOperation reconcilePublication(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        return new PkiOperation.ReconcilePublication(publicationId(arguments));
    }

    private PkiOperation statusScheduleRequest(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        Set<String> required = Set.of(TEXT_CA_ID, "statusType", FORMAT_ID, "interval", "graceSeconds", "enabled");
        Set<String> allowed = new java.util.HashSet<>(required);
        allowed.add("targetType");
        allowed.add("targetId");
        allowedFields(arguments, required, allowed);
        java.util.Optional<PublicationTarget> target =
                optionalText(arguments, "targetType").map(t ->
                        new PublicationTarget(
                                PublicationTargetType.valueOf(t),
                                text(arguments, "targetId")));
        return new PkiOperation.SetStatusSchedule(
                new PkiId(text(arguments, TEXT_CA_ID)),
                StatusObjectType.valueOf(text(arguments, "statusType")),
                new FormatId(text(arguments, FORMAT_ID)),
                Duration.parse(text(arguments, "interval")),
                integer(arguments, "graceSeconds"),
                bool(arguments, "enabled"),
                target);
    }

    private PkiOperation inspectStatusSchedule(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(TEXT_CA_ID, "statusType"));
        return new PkiOperation.InspectStatusSchedule(new PkiId(text(arguments, TEXT_CA_ID)),
                StatusObjectType.valueOf(text(arguments, "statusType")));
    }

    private PkiOperation listStatusSchedules(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        pageFields(arguments, Set.of());
        return new PkiOperation.ListStatusSchedules(limit(arguments), optionalText(arguments, AFTER));
    }

    private PkiOperation queryAuthorityMetrics(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(TEXT_CA_ID));
        return new PkiOperation.QueryAuthorityMetrics(new PkiId(text(arguments, TEXT_CA_ID)));
    }

    private PkiOperation queryCertificateMetrics(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(TEXT_CA_ID));
        return new PkiOperation.QueryCertificateMetrics(new PkiId(text(arguments, TEXT_CA_ID)));
    }

    private PkiOperation queryRevocationMetrics(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(TEXT_CA_ID));
        return new PkiOperation.QueryRevocationMetrics(new PkiId(text(arguments, TEXT_CA_ID)));
    }

    private PkiOperation queryPublicationMetrics(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(TEXT_CA_ID));
        return new PkiOperation.QueryPublicationMetrics(new PkiId(text(arguments, TEXT_CA_ID)));
    }

    private PkiOperation queryServerMetrics(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of());
        return new PkiOperation.QueryServerMetrics();
    }

    private static PkiId publicationId(PkiOperationValue.ObjectValue arguments) {
        requireFields(arguments, Set.of(PUBLICATION_ID));
        return new PkiId(text(arguments, PUBLICATION_ID));
    }

    private static void add(Map<String, Binding> target, String name, CoreBinding binding) {
        if (target.putIfAbsent(name, (arguments, base) -> new PkiLocalCommand.Core(binding.bind(arguments, base))) != null) {
            throw new IllegalStateException("Duplicate PKI operation identity");
        }
    }

    private static void addSigning(Map<String, Binding> target, String name, SigningBinding binding) {
        if (target.putIfAbsent(name, (arguments, base) ->
                new PkiLocalCommand.Signing(binding.bind(arguments, base))) != null) {
            throw new IllegalStateException("Duplicate PKI operation identity");
        }
    }

    /* default */ boolean executable(String name) {
        return bindings.containsKey(name);
    }

    private static PkiId operationId(PkiOperationValue.ObjectValue arguments) {
        requireFields(arguments, Set.of("operationId"));
        return new PkiId(text(arguments, "operationId"));
    }

    private PkiOperation allProfiles(PkiOperationValue.ObjectValue arguments, Path base) {
        pageFields(arguments, Set.of());
        return new PkiOperation.ListProfiles(limit(arguments), optionalText(arguments, AFTER));
    }

    private PkiOperation listRequests(PkiOperationValue.ObjectValue arguments, Path base) {
        pageFields(arguments, Set.of());
        return new PkiOperation.ListRequests(limit(arguments), optionalText(arguments, AFTER));
    }

    private PkiOperation searchCredentials(PkiOperationValue.ObjectValue arguments, Path base) {
        allowedFields(arguments, Set.of(SCOPE_AUTHORITY_ID, LIMIT),
                Set.of(SCOPE_AUTHORITY_ID, LIMIT, AFTER, "subjectFilter", "serialFilter",
                        "fingerprintFilter", "statusFilter", "profileIdFilter", "sanFilter"));
        return new PkiOperation.SearchCredentials(new PkiId(text(arguments, SCOPE_AUTHORITY_ID)),
                limit(arguments), optionalText(arguments, AFTER),
                optionalText(arguments, "subjectFilter"), optionalText(arguments, "serialFilter"),
                optionalText(arguments, "fingerprintFilter"), optionalText(arguments, "statusFilter"),
                optionalText(arguments, "profileIdFilter"), optionalText(arguments, "sanFilter"));
    }

    private PkiOperation listGenerations(PkiOperationValue.ObjectValue arguments, Path base) {
        pageFields(arguments, Set.of(SCOPE_AUTHORITY_ID));
        return new PkiOperation.ListIssuerGenerations(new PkiId(text(arguments, SCOPE_AUTHORITY_ID)),
                limit(arguments), optionalText(arguments, AFTER));
    }

    private PkiOperation pendingConfirmations(PkiOperationValue.ObjectValue arguments, Path base) {
        allowedFields(arguments, Set.of(SCOPE_AUTHORITY_ID, "cutoffInclusive", LIMIT),
                Set.of(SCOPE_AUTHORITY_ID, "cutoffInclusive", LIMIT, PROFILE_ID, "afterExclusive"));
        return new PkiOperation.ListPendingCredentialConfirmations(new PkiId(text(arguments, SCOPE_AUTHORITY_ID)),
                optionalText(arguments, PROFILE_ID), instant(text(arguments, "cutoffInclusive")),
                optionalText(arguments, "afterExclusive").map(CredentialConfirmationReviewCursor::new), limit(arguments));
    }

    private PkiOperation confirmationChallenge(PkiOperationValue.ObjectValue arguments, Path base) {
        requireFields(arguments, Set.of(CREDENTIAL_ID));
        return new PkiOperation.IssueCredentialConfirmationChallenge(new PkiId(text(arguments, CREDENTIAL_ID)));
    }

    private PkiOperation confirmationProof(PkiOperationValue.ObjectValue arguments, Path base) {
        requireFields(arguments, Set.of(CREDENTIAL_ID, "expectedLifecycleRevision",
                "expectedLifecycleRecordCommitment", "expectedChallengeRecordCommitment", "response"));
        String encoded = text(arguments, "response");
        if (encoded.isEmpty() || encoded.length() > 21_846) { throw new IllegalArgumentException(INVALID_ARGUMENTS); }
        CredentialConfirmationProofCas cas = new CredentialConfirmationProofCas(
                new PkiId(text(arguments, CREDENTIAL_ID)), integer(arguments, "expectedLifecycleRevision"),
                text(arguments, "expectedLifecycleRecordCommitment"), text(arguments, "expectedChallengeRecordCommitment"));
        byte[] response = Base64.getUrlDecoder().decode(encoded);
        try {
            if (!encoded.equals(Base64.getUrlEncoder().withoutPadding().encodeToString(response))) {
                throw new IllegalArgumentException("Proof response must be canonical unpadded Base64url");
            }
            return new PkiOperation.CompleteCredentialConfirmationProof(
                    new CredentialConfirmationProofSubmission(cas, response));
        } finally {
            java.util.Arrays.fill(response, (byte) 0);
        }
    }

    private PkiOperation revokePending(PkiOperationValue.ObjectValue arguments, Path base) {
        allowedFields(arguments, Set.of(CREDENTIAL_ID), Set.of(CREDENTIAL_ID, PARAM_JUSTIFICATION));
        return new PkiOperation.RevokePendingCredentialConfirmation(new PkiId(text(arguments, CREDENTIAL_ID)),
                optionalText(arguments, PARAM_JUSTIFICATION));
    }

    private static Instant instant(String value) {
        try {
            return Instant.parse(value);
        } catch (java.time.format.DateTimeParseException invalid) {
            throw new IllegalArgumentException("Invalid confirmation cutoff", invalid);
        }
    }

    private static void pageFields(PkiOperationValue.ObjectValue arguments, Set<String> scope) {
        Set<String> required = new java.util.HashSet<>(scope);
        required.add(LIMIT);
        Set<String> allowed = new java.util.HashSet<>(required);
        allowed.add(AFTER);
        allowedFields(arguments, required, allowed);
    }

    private static void allowedFields(PkiOperationValue.ObjectValue arguments, Set<String> required,
            Set<String> allowed) {
        if (!arguments.fields().keySet().containsAll(required) || !allowed.containsAll(arguments.fields().keySet())) {
            throw new IllegalArgumentException(INVALID_ARGUMENTS);
        }
    }

    /** Binds validated CLI arguments to a synchronous core operation. */
    @FunctionalInterface
    private interface CoreBinding {
        /** Resolves arguments and bounded file inputs relative to the plan directory. */
        PkiOperation bind(PkiOperationValue.ObjectValue arguments, Path baseDirectory) throws IOException;
    }

    /** Binds validated CLI arguments to a signing operation. */
    @FunctionalInterface
    private interface SigningBinding {
        /** Resolves arguments and bounded file inputs relative to the plan directory. */
        PkiSigningOperation bind(PkiOperationValue.ObjectValue arguments, Path baseDirectory) throws IOException;
    }

    private static void requireFields(PkiOperationValue.ObjectValue arguments, Set<String> expected) {
        if (!arguments.fields().keySet().equals(expected)) {
            throw new IllegalArgumentException(INVALID_ARGUMENTS);
        }
    }

    private static String text(PkiOperationValue.ObjectValue arguments, String name) {
        return PkiCliConfiguration.text(PkiCliConfiguration.required(arguments, name));
    }

    private static java.util.Optional<String> optionalText(PkiOperationValue.ObjectValue arguments, String name) {
        PkiOperationValue value = arguments.fields().get(name);
        return value == null ? java.util.Optional.empty() : java.util.Optional.of(PkiCliConfiguration.text(value));
    }

    private static long integer(PkiOperationValue.ObjectValue arguments, String name) {
        return PkiCliConfiguration.integer(PkiCliConfiguration.required(arguments, name));
    }

    private static int limit(PkiOperationValue.ObjectValue arguments) {
        return Math.toIntExact(integer(arguments, LIMIT));
    }

    private static boolean bool(PkiOperationValue.ObjectValue arguments, String name) {
        PkiOperationValue value = PkiCliConfiguration.required(arguments, name);
        if (value instanceof PkiOperationValue.BooleanValue b) {
            return b.value();
        }
        throw new IllegalArgumentException(INVALID_ARGUMENTS);
    }

    private static Path resolve(Path baseDirectory, String value) {
        Path supplied = Path.of(value);
        return (supplied.isAbsolute() ? supplied : baseDirectory.resolve(supplied)).toAbsolutePath().normalize();
    }

    /** One explicit typed binding. */
    @FunctionalInterface
    private interface Binding {
        /** Binds validated structured arguments to one typed operation. */
        PkiLocalCommand bind(PkiOperationValue.ObjectValue arguments, Path baseDirectory) throws IOException;
    }
}
