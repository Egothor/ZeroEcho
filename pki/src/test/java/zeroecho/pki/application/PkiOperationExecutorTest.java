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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.CaService;
import zeroecho.pki.api.ca.CaKeyRotationCommand;
import zeroecho.pki.api.ca.CaRolloverCommand;
import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuanceService;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiFailureReason;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.PublicationService;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.StatusObjectService;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteBinding;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef;
import zeroecho.pki.api.confirmation.CredentialConfirmationInitialization;
import zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofCas;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofChallenge;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofChallengeRequest;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofResult;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofSubmission;
import zeroecho.pki.api.confirmation.CredentialConfirmationReview;
import zeroecho.pki.api.confirmation.CredentialConfirmationReviewCursor;
import zeroecho.pki.api.confirmation.CredentialConfirmationReviewPage;
import zeroecho.pki.api.confirmation.CredentialConfirmationService;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.ca.IntermediateCertIssueCommand;
import zeroecho.pki.api.ca.IntermediateCreateCommand;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.api.publication.PublicationCursor;
import zeroecho.pki.api.publication.PublicationQuery;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.publication.PublicationRequest;
import zeroecho.pki.api.publication.PublicationResult;
import zeroecho.pki.api.publication.PublicationStatus;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationQuery;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.RevocationHistory;
import zeroecho.pki.spi.store.RevocationSnapshot;

class PkiOperationExecutorTest {

    private static final PkiId CREDENTIAL_ID = new PkiId("credential:test");

    @Test
    void validatesConfigurationAndProfilesWithSafeTypedResults() {
        System.out.println("validatesConfigurationAndProfilesWithSafeTypedResults");
        DefaultPkiOperationExecutor executor = executor(new AtomicInteger());
        PkiOperationOutcome configuration = executor.execute(new PkiOperation.ValidateConfiguration(),
                CancellationSignal.NONE);
        byte[] profile = BuiltInCertificateProfileCatalog.load(getClass().getClassLoader()).get(0).canonicalJson();
        PkiOperationOutcome validated = executor.execute(new PkiOperation.ValidateProfile(profile),
                CancellationSignal.NONE);
        PkiOperationOutcome malformed = executor.execute(new PkiOperation.ValidateProfile(new byte[] { 1 }),
                CancellationSignal.NONE);
        System.out.println("...profileBytes=" + profile.length);
        assertInstanceOf(PkiOperationOutcome.Completed.class, configuration);
        PkiOperationResult profileResult = ((PkiOperationOutcome.Completed) validated).result();
        assertTrue(profileResult.field("profileId").isPresent());
        assertEquals(PkiOperationFailure.POLICY_REJECTION,
                ((PkiOperationOutcome.Failed) malformed).classification());
        System.out.println("...ok");
    }

    @Test
    void delegatesMutationAndStreamsBoundedHistory() {
        System.out.println("delegatesMutationAndStreamsBoundedHistory");
        AtomicInteger revocations = new AtomicInteger();
        DefaultPkiOperationExecutor executor = executor(revocations);
        PkiOperationOutcome mutation = executor.execute(
                new PkiOperation.RevokeCredential(CREDENTIAL_ID, RevocationReason.KEY_COMPROMISE),
                CancellationSignal.NONE);
        PkiOperationOutcome history = executor.execute(new PkiOperation.ReadRevocationHistory(CREDENTIAL_ID, 1),
                CancellationSignal.NONE);
        System.out.println("...mutations=" + revocations.get());
        assertInstanceOf(PkiOperationOutcome.Completed.class, mutation);
        PkiOperationResult historyResult = ((PkiOperationOutcome.Completed) history).result();
        assertEquals(new PkiOperationValue.BooleanValue(true), historyResult.field("truncated").orElseThrow());
        assertEquals(1, revocations.get());
        System.out.println("...ok");
    }

    @Test
    void coCommitsEvidenceButDoesNotExposeAttributesInOrdinaryHistory() {
        AtomicReference<RevocationCommand.RevokePermanently> captured = new AtomicReference<>();
        DefaultPkiOperationExecutor executor = executor(new AtomicInteger(), captured);
        RevocationExecutionEvidence evidence = RevocationExecutionEvidence.administrative("operator-a", "realm-a",
                "request-a", RevocationExecutionEvidence.Authentication.DIRECT_MTLS,
                RevocationExecutionEvidence.AuthorizationPath.ORDINARY_GRANT, "a".repeat(64),
                Optional.of("ticket-100"));

        assertInstanceOf(PkiOperationOutcome.Completed.class, executor.executeRevocation(
                new PkiOperation.RevokeCredential(CREDENTIAL_ID, RevocationReason.KEY_COMPROMISE,
                        Optional.of("ticket-100")), evidence, CancellationSignal.NONE));
        assertEquals(evidence.attributes().ids(), captured.get().attributes().ids());
        PkiOperationResult history = assertInstanceOf(PkiOperationOutcome.Completed.class, executor.execute(
                new PkiOperation.ReadRevocationHistory(CREDENTIAL_ID, 2), CancellationSignal.NONE)).result();
        PkiOperationValue.ListValue transitions = (PkiOperationValue.ListValue) history.field("transitions")
                .orElseThrow();
        assertFalse(((PkiOperationValue.ObjectValue) transitions.values().get(1)).fields().containsKey("attributes"));
    }

    @Test
    void executesPendingConfirmationRevocationWithFixedReasonAndEvidence() {
        AtomicReference<RevocationCommand.RevokePermanently> captured = new AtomicReference<>();
        DefaultPkiOperationExecutor executor = executor(new AtomicInteger(), captured);
        RevocationExecutionEvidence evidence = RevocationExecutionEvidence.administrative(
                "operator-a", "realm-a", "request-a",
                RevocationExecutionEvidence.Authentication.DIRECT_MTLS,
                RevocationExecutionEvidence.AuthorizationPath.ORDINARY_GRANT,
                "a".repeat(64), Optional.of("ticket-200"));
        PkiOperation.RevokePendingCredentialConfirmation operation =
                new PkiOperation.RevokePendingCredentialConfirmation(
                        CREDENTIAL_ID, Optional.of("ticket-200"));

        PkiOperationResult result = assertInstanceOf(PkiOperationOutcome.Completed.class,
                executor.executePendingConfirmationRevocation(
                        operation, evidence, CancellationSignal.NONE)).result();

        assertEquals(RevocationReason.UNSPECIFIED, captured.get().reason());
        assertEquals(evidence.attributes().ids(), captured.get().attributes().ids());
        assertEquals(new PkiOperationValue.Text(RevocationReason.UNSPECIFIED.name()),
                result.field("reason").orElseThrow());
        assertEquals(operation.name(), result.operationName());
    }

    @Test
    void classifiesMissingObjectsAndCancellationWithoutThrowableDetails() {
        System.out.println("classifiesMissingObjectsAndCancellationWithoutThrowableDetails");
        DefaultPkiOperationExecutor executor = executor(new AtomicInteger());
        PkiOperationOutcome missing = executor.execute(new PkiOperation.InspectPublication(new PkiId("missing")),
                CancellationSignal.NONE);
        PkiOperationOutcome cancelled = executor.execute(new PkiOperation.InspectCredential(CREDENTIAL_ID),
                () -> true);
        assertEquals(PkiOperationFailure.NOT_FOUND, ((PkiOperationOutcome.Failed) missing).classification());
        PkiOperationOutcome.Failed cancelledFailure = (PkiOperationOutcome.Failed) cancelled;
        assertEquals(PkiOperationFailure.CANCELLED, cancelledFailure.classification());
        assertEquals("OPERATION_CANCELLED", cancelledFailure.code());
        System.out.println("...ok");
    }

    @Test
    void rejectsSigningDependentOperationWhenCapabilityIsNotConfigured() {
        System.out.println("rejectsSigningDependentOperationWhenCapabilityIsNotConfigured");
        DefaultPkiOperationExecutor executor = executor(new AtomicInteger());
        PkiOperation operation = new PkiOperation.CreateAuthority(new FormatId("x509"),
                new SubjectRef("CN=Unavailable"), "root-ca", new KeyRef("managed:root.prv"));
        PkiOperationOutcome.Failed failure = (PkiOperationOutcome.Failed) executor.execute(operation,
                CancellationSignal.NONE);
        System.out.println("...classification=" + failure.classification());
        assertEquals(PkiOperationFailure.VALIDATION_FAILURE, failure.classification());
        assertEquals("CAPABILITY_NOT_CONFIGURED", failure.code());
        System.out.println("...ok");
    }

    @Test
    void returnsOnlyReducedPendingConfirmationReviewFields() {
        PkiId authorityId = new PkiId("ca:confirmation");
        Instant cutoff = Instant.parse("2026-08-30T12:00:00Z");
        CredentialConfirmationReview review = new CredentialConfirmationReview(
                CREDENTIAL_ID, authorityId, "server-tls", cutoff,
                ConfirmationDisclosurePolicy.OWNER_ONLY);
        CredentialConfirmationReviewPage page = new CredentialConfirmationReviewPage(List.of(review),
                Optional.of(new CredentialConfirmationReviewCursor("YWJj")));
        CredentialConfirmationService confirmations = (CredentialConfirmationService) Proxy.newProxyInstance(
                CredentialConfirmationService.class.getClassLoader(),
                new Class<?>[] { CredentialConfirmationService.class },
                (proxy, method, arguments) -> "pagePendingReviews".equals(method.getName())
                        ? page : throwUnsupported(method.getName()));
        DefaultPkiOperationExecutor executor = confirmationExecutor(confirmations);

        PkiOperationOutcome.Completed completed = assertInstanceOf(PkiOperationOutcome.Completed.class,
                executor.execute(new PkiOperation.ListPendingCredentialConfirmations(authorityId,
                        Optional.of("server-tls"), cutoff, Optional.empty(), 100), CancellationSignal.NONE));
        PkiOperationValue.ListValue reviews = (PkiOperationValue.ListValue) completed.result()
                .field("reviews").orElseThrow();
        PkiOperationValue.ObjectValue value = (PkiOperationValue.ObjectValue) reviews.values().getFirst();
        assertEquals(java.util.Set.of("credentialId", "authorityId", "profileId",
                "confirmationReviewAt", "initialDisclosurePolicy"), value.fields().keySet());
        assertEquals(new PkiOperationValue.Text("YWJj"),
                completed.result().field("nextCursor").orElseThrow());
    }

    @Test
    void issuesChallengeFromAuthoritativeLifecycleAndReturnsOnlySafePresentationFields() {
        ConfirmationProofSuiteRef suite = new ConfirmationProofSuiteRef(
                "signature-key-possession.v1", "b".repeat(64));
        CredentialConfirmationLifecycle lifecycle = CredentialConfirmationLifecycle.initialize(
                new CredentialConfirmationInitialization(CREDENTIAL_ID,
                        ConfirmationDisclosurePolicy.OWNER_ONLY, "a".repeat(64), true,
                        Instant.parse("2026-08-31T12:00:00Z"), suite));
        CredentialConfirmationProofChallenge challenge = new CredentialConfirmationProofChallenge(
                new CredentialConfirmationProofCas(CREDENTIAL_ID, lifecycle.revision(),
                        lifecycle.recordCommitment(), "c".repeat(64)),
                new ConfirmationProofSuiteBinding(suite, 4096),
                Instant.parse("2026-08-30T12:05:00Z"), 4096,
                new byte[] { (byte) 0xfb, (byte) 0xff });
        AtomicReference<CredentialConfirmationProofChallengeRequest> captured = new AtomicReference<>();
        CredentialConfirmationService confirmations = (CredentialConfirmationService) Proxy.newProxyInstance(
                CredentialConfirmationService.class.getClassLoader(),
                new Class<?>[] { CredentialConfirmationService.class }, (proxy, method, arguments) -> {
                    if ("get".equals(method.getName())) return Optional.of(lifecycle);
                    if ("issueProofChallenge".equals(method.getName())) {
                        captured.set((CredentialConfirmationProofChallengeRequest) arguments[0]);
                        return challenge;
                    }
                    return throwUnsupported(method.getName());
                });
        DefaultPkiOperationExecutor executor = confirmationExecutor(confirmations);
        PkiOperation operation = new PkiOperation.IssueCredentialConfirmationChallenge(CREDENTIAL_ID);

        PkiOperationResult first = assertInstanceOf(PkiOperationOutcome.Completed.class,
                executor.execute(operation, CancellationSignal.NONE)).result();
        PkiOperationResult replay = assertInstanceOf(PkiOperationOutcome.Completed.class,
                executor.execute(operation, CancellationSignal.NONE)).result();

        assertEquals(first, replay);
        assertEquals(new CredentialConfirmationProofChallengeRequest(CREDENTIAL_ID,
                lifecycle.revision(), lifecycle.recordCommitment()), captured.get());
        assertEquals(java.util.Set.of("credentialId", "expectedLifecycleRevision",
                "expectedLifecycleRecordCommitment", "expectedChallengeRecordCommitment",
                "proofSuiteId", "proofSuiteConfigurationCommitment", "rsaMaximumModulusBits",
                "expiresAt", "maximumResponseBytes", "presentation"), first.fields().keySet());
        assertEquals(new PkiOperationValue.Text("-_8"), first.field("presentation").orElseThrow());
    }

    @Test
    void doesNotIssueChallengeForMissingOrTerminalLifecycle() {
        AtomicInteger issued = new AtomicInteger();
        CredentialConfirmationLifecycle confirmed = CredentialConfirmationLifecycle.initialize(
                new CredentialConfirmationInitialization(CREDENTIAL_ID,
                        ConfirmationDisclosurePolicy.OWNER_ONLY, "a".repeat(64), true,
                        Instant.parse("2026-08-31T12:00:00Z"),
                        new ConfirmationProofSuiteRef("signature-key-possession.v1", "b".repeat(64))))
                .deriveConfirmed(new CredentialConfirmationProofCas(CREDENTIAL_ID, 1L,
                        CredentialConfirmationLifecycle.initialize(new CredentialConfirmationInitialization(
                                CREDENTIAL_ID, ConfirmationDisclosurePolicy.OWNER_ONLY, "a".repeat(64), true,
                                Instant.parse("2026-08-31T12:00:00Z"), new ConfirmationProofSuiteRef(
                                        "signature-key-possession.v1", "b".repeat(64)))).recordCommitment(),
                        "c".repeat(64)), Instant.parse("2026-08-30T12:00:00Z"));
        AtomicReference<Optional<CredentialConfirmationLifecycle>> current =
                new AtomicReference<>(Optional.empty());
        CredentialConfirmationService confirmations = (CredentialConfirmationService) Proxy.newProxyInstance(
                CredentialConfirmationService.class.getClassLoader(),
                new Class<?>[] { CredentialConfirmationService.class }, (proxy, method, arguments) -> {
                    if ("get".equals(method.getName())) return current.get();
                    if ("issueProofChallenge".equals(method.getName())) {
                        issued.incrementAndGet();
                        throw new AssertionError("terminal lifecycle reached challenge service");
                    }
                    return throwUnsupported(method.getName());
                });
        DefaultPkiOperationExecutor executor = confirmationExecutor(confirmations);
        PkiOperation operation = new PkiOperation.IssueCredentialConfirmationChallenge(CREDENTIAL_ID);

        assertEquals(PkiOperationFailure.NOT_FOUND, assertInstanceOf(PkiOperationOutcome.Failed.class,
                executor.execute(operation, CancellationSignal.NONE)).classification());
        current.set(Optional.of(confirmed));
        assertEquals(PkiOperationFailure.CONFLICT, assertInstanceOf(PkiOperationOutcome.Failed.class,
                executor.execute(operation, CancellationSignal.NONE)).classification());
        current.set(Optional.of(CredentialConfirmationLifecycle.initialize(
                new CredentialConfirmationInitialization(CREDENTIAL_ID,
                        ConfirmationDisclosurePolicy.PUBLIC, "d".repeat(64), false,
                        Instant.parse("2026-08-31T12:00:00Z"),
                        new ConfirmationProofSuiteRef("signature-key-possession.v1", "b".repeat(64))))));
        assertEquals(PkiOperationFailure.CONFLICT, assertInstanceOf(PkiOperationOutcome.Failed.class,
                executor.execute(operation, CancellationSignal.NONE)).classification());
        assertEquals(0, issued.get());
    }

    @Test
    void delegatesProofCompletionExactlyOnceAndReturnsOnlyConfirmationResult() {
        AtomicInteger calls = new AtomicInteger();
        AtomicReference<CredentialConfirmationProofResult> serviceResult =
                new AtomicReference<>(CredentialConfirmationProofResult.REJECTED);
        CredentialConfirmationService confirmations = (CredentialConfirmationService) Proxy.newProxyInstance(
                CredentialConfirmationService.class.getClassLoader(),
                new Class<?>[] { CredentialConfirmationService.class }, (proxy, method, arguments) -> {
                    if ("verifyAndComplete".equals(method.getName())) {
                        calls.incrementAndGet();
                        return serviceResult.get();
                    }
                    return throwUnsupported(method.getName());
                });
        byte[] raw = new byte[] { 1, 2, 3, 4 };
        CredentialConfirmationProofSubmission submission = new CredentialConfirmationProofSubmission(
                new CredentialConfirmationProofCas(CREDENTIAL_ID, 1L, "a".repeat(64), "b".repeat(64)), raw);
        PkiOperation operation = new PkiOperation.CompleteCredentialConfirmationProof(submission);
        DefaultPkiOperationExecutor executor = confirmationExecutor(confirmations);

        PkiOperationResult rejected = assertInstanceOf(PkiOperationOutcome.Completed.class,
                executor.execute(operation, CancellationSignal.NONE)).result();
        assertEquals(Map.of("confirmationResult", new PkiOperationValue.Text("REJECTED")),
                rejected.fields());
        assertEquals(1, calls.get());

        serviceResult.set(CredentialConfirmationProofResult.CONFIRMED);
        PkiOperationResult replay = assertInstanceOf(PkiOperationOutcome.Completed.class,
                executor.execute(operation, CancellationSignal.NONE)).result();
        assertEquals(Map.of("confirmationResult", new PkiOperationValue.Text("CONFIRMED")), replay.fields());
        assertEquals(2, calls.get());
        assertFalse(operation.toString().contains(java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(raw)));
    }

    @Test
    void preservesExplicitPublicationResultsAndUnknownOutcome() {
        System.out.println("preservesExplicitPublicationResultsAndUnknownOutcome");
        PkiId publicationId = new PkiId("publication:test");
        DefaultPkiOperationExecutor executor = publicationExecutor();
        PkiOperationOutcome processed = executor.execute(new PkiOperation.ProcessPublication(publicationId),
                CancellationSignal.NONE);
        PkiOperationOutcome reconciled = executor.execute(new PkiOperation.ReconcilePublication(publicationId),
                CancellationSignal.NONE);
        System.out.println("...process=" + processed.getClass().getSimpleName());
        assertInstanceOf(PkiOperationOutcome.Completed.class, processed);
        assertEquals(PkiOperationFailure.EXTERNAL_OUTCOME_UNKNOWN,
                ((PkiOperationOutcome.Failed) reconciled).classification());
        System.out.println("...ok");
    }

    @Test
    void carriesExactCancellationThroughSigningOperationEntrypoints() {
        AtomicReference<CancellationSignal> root = new AtomicReference<>();
        AtomicReference<CancellationSignal> intermediate = new AtomicReference<>();
        AtomicReference<CancellationSignal> leaf = new AtomicReference<>();
        AtomicReference<CancellationSignal> status = new AtomicReference<>();
        CancellationSignal signal = () -> false;
        CaService authorities = (CaService) Proxy.newProxyInstance(CaService.class.getClassLoader(),
                new Class<?>[] { CaService.class }, (proxy, method, arguments) -> {
                    if ("createRoot".equals(method.getName()) && arguments.length == 2) {
                        root.set((CancellationSignal) arguments[1]);
                        throw new CaptureCompleteException();
                    }
                    if ("createIntermediate".equals(method.getName()) && arguments.length == 2) {
                        intermediate.set((CancellationSignal) arguments[1]);
                        throw new CaptureCompleteException();
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
        IssuanceService issuance = captureService(IssuanceService.class, "issueEndEntity", leaf);
        StatusObjectService statuses = captureService(StatusObjectService.class, "generate", status);
        PkiId requestId = new PkiId("request:cancellation");
        ParsedCertificationRequest parsed = new ParsedCertificationRequest(requestId, new FormatId("x509"),
                new SubjectRef("CN=Cancellation"), new EncodedObject(Encoding.DER, new byte[] { 1 }),
                Optional.empty(), Optional.empty(), new SimpleAttributeSet());
        CertificationRequestService requests = (CertificationRequestService) Proxy.newProxyInstance(
                CertificationRequestService.class.getClassLoader(), new Class<?>[] { CertificationRequestService.class },
                (proxy, method, arguments) -> "get".equals(method.getName()) ? Optional.of(parsed)
                        : throwUnsupported(method.getName()));
        DefaultPkiOperationExecutor executor = signingExecutor(authorities, requests, issuance, statuses);

        executor.execute(new PkiOperation.CreateAuthority(new FormatId("x509"), new SubjectRef("CN=Root"),
                "root-ca", new KeyRef("managed:root")), signal);
        executor.execute(new PkiOperation.IssueCredential(new PkiId("ca:issuer"), requestId, "leaf"), signal);
        executor.execute(new PkiOperation.GenerateStatus(new PkiId("ca:issuer"), StatusObjectType.CRL,
                new FormatId("x509")), signal);
        try {
            authorities.createIntermediate(new IntermediateCreateCommand(new FormatId("x509"),
                    new PkiId("ca:issuer"), new SubjectRef("CN=Intermediate"), "intermediate-ca",
                    Optional.of(new KeyRef("managed:intermediate")), new SimpleAttributeSet()), signal);
        } catch (CaptureCompleteException expected) {
            // Captured at the service boundary.
        }

        assertEquals(signal, root.get());
        assertEquals(signal, intermediate.get());
        assertEquals(signal, leaf.get());
        assertEquals(signal, status.get());
    }

    @Test
    void classifiesMidFlightCallerCancellationBeforeRuntimeFailure() {
        AtomicBoolean cancelled = new AtomicBoolean();
        CancellationSignal signal = cancelled::get;
        CaService authorities = (CaService) Proxy.newProxyInstance(CaService.class.getClassLoader(),
                new Class<?>[] { CaService.class }, (proxy, method, arguments) -> {
                    if ("createRoot".equals(method.getName()) && arguments.length == 2) {
                        cancelled.set(true);
                        throw new PkiException("Signing failed after caller cancellation");
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
        DefaultPkiOperationExecutor executor = signingExecutor(authorities,
                unsupportedService(CertificationRequestService.class), unsupportedService(IssuanceService.class),
                unsupportedService(StatusObjectService.class));

        PkiOperationOutcome outcome = executor.execute(new PkiOperation.CreateAuthority(new FormatId("x509"),
                new SubjectRef("CN=Cancelled Root"), "root-ca", new KeyRef("managed:root")), signal);

        PkiOperationOutcome.Failed failure = assertInstanceOf(PkiOperationOutcome.Failed.class, outcome);
        assertEquals(PkiOperationFailure.CANCELLED, failure.classification());
        assertEquals("OPERATION_CANCELLED", failure.code());
    }

    @Test
    void classifiesOnlyTypedSigningAdmissionFailureAsOverloaded() {
        CaService overloaded = failingAuthorities(new SigningExecutionException(
                SigningExecutionException.Classification.OVERLOADED, "unrelated diagnostic"));
        CaService misleading = failingAuthorities(new PkiException("SIGNING_OVERLOADED"));

        PkiOperationOutcome typed = signingExecutor(overloaded,
                unsupportedService(CertificationRequestService.class), unsupportedService(IssuanceService.class),
                unsupportedService(StatusObjectService.class)).execute(createAuthority(), CancellationSignal.NONE);
        PkiOperationOutcome generic = signingExecutor(misleading,
                unsupportedService(CertificationRequestService.class), unsupportedService(IssuanceService.class),
                unsupportedService(StatusObjectService.class)).execute(createAuthority(), CancellationSignal.NONE);

        assertEquals(PkiOperationFailure.OVERLOADED,
                assertInstanceOf(PkiOperationOutcome.Failed.class, typed).classification());
        assertEquals(PkiOperationFailure.POLICY_REJECTION,
                assertInstanceOf(PkiOperationOutcome.Failed.class, generic).classification());
    }

    @Test
    void classifiesStructuralDurabilityReasonAsRecoveryRequired() {
        DefaultPkiOperationExecutor executor = signingExecutor(
                failingAuthorities(new PkiException(
                        "Store durability unconfirmed: code=STORE_DURABILITY_UNCONFIRMED",
                        PkiFailureReason.STORE_DURABILITY_UNCONFIRMED)),
                unsupportedService(CertificationRequestService.class),
                unsupportedService(IssuanceService.class),
                unsupportedService(StatusObjectService.class));

        PkiOperationOutcome.Failed failure = assertInstanceOf(
                PkiOperationOutcome.Failed.class,
                executor.execute(createAuthority(), CancellationSignal.NONE));

        assertEquals(PkiOperationFailure.RECOVERY_REQUIRED, failure.classification());
        assertEquals("RECOVERY_REQUIRED", failure.code());
        assertFalse(failure.code().contains("UNCONFIRMED"));
    }

    @Test
    void doesNotClassifyDurabilityFromMessageTextAlone() {
        // The same diagnostic text carried without the typed reason must not be
        // reclassified by message parsing; classification now depends on the
        // structural reason only.
        DefaultPkiOperationExecutor executor = signingExecutor(
                failingAuthorities(new PkiException(
                        "Store durability unconfirmed: code=STORE_DURABILITY_UNCONFIRMED")),
                unsupportedService(CertificationRequestService.class),
                unsupportedService(IssuanceService.class),
                unsupportedService(StatusObjectService.class));

        PkiOperationOutcome.Failed failure = assertInstanceOf(
                PkiOperationOutcome.Failed.class,
                executor.execute(createAuthority(), CancellationSignal.NONE));

        assertNotEquals(PkiOperationFailure.RECOVERY_REQUIRED, failure.classification());
    }

    @Test
    void classifiesTypedNotFoundReasonStructurally() {
        // A domain "not found" now carries a typed reason and classifies as NOT_FOUND from that reason.
        DefaultPkiOperationExecutor executor = signingExecutor(
                failingAuthorities(new PkiException("CA not found", PkiFailureReason.ISSUER_CA_NOT_FOUND)),
                unsupportedService(CertificationRequestService.class),
                unsupportedService(IssuanceService.class), unsupportedService(StatusObjectService.class));

        PkiOperationOutcome.Failed failure = assertInstanceOf(PkiOperationOutcome.Failed.class,
                executor.execute(createAuthority(), CancellationSignal.NONE));
        assertEquals(PkiOperationFailure.NOT_FOUND, failure.classification());
        assertEquals("OBJECT_NOT_FOUND", failure.code());
    }

    @Test
    void doesNotClassifyNotFoundOrConflictFromMessageTextAlone() {
        // The retired prose-parsing fallback must no longer infer NOT_FOUND/CONFLICT from message text:
        // an untyped PkiException carrying only "not found" prose is a bare policy rejection, and an
        // untyped IllegalStateException carrying "changed concurrently" prose is a resource failure.
        DefaultPkiOperationExecutor proseNotFound = signingExecutor(
                failingAuthorities(new PkiException("Issuer CA not found")),
                unsupportedService(CertificationRequestService.class),
                unsupportedService(IssuanceService.class), unsupportedService(StatusObjectService.class));
        PkiOperationOutcome.Failed notFound = assertInstanceOf(PkiOperationOutcome.Failed.class,
                proseNotFound.execute(createAuthority(), CancellationSignal.NONE));
        assertNotEquals(PkiOperationFailure.NOT_FOUND, notFound.classification());
        assertEquals(PkiOperationFailure.POLICY_REJECTION, notFound.classification());

        DefaultPkiOperationExecutor proseConflict = signingExecutor(
                failingAuthorities(new IllegalStateException("record changed concurrently")),
                unsupportedService(CertificationRequestService.class),
                unsupportedService(IssuanceService.class), unsupportedService(StatusObjectService.class));
        PkiOperationOutcome.Failed conflict = assertInstanceOf(PkiOperationOutcome.Failed.class,
                proseConflict.execute(createAuthority(), CancellationSignal.NONE));
        assertNotEquals(PkiOperationFailure.CONFLICT, conflict.classification());
        assertEquals(PkiOperationFailure.RESOURCE_FAILURE, conflict.classification());
    }

    @Test
    void classifiesPublicationUncertaintyReasonStructurally() {
        DefaultPkiOperationExecutor executor = signingExecutor(
                failingAuthorities(new PkiException(
                        "Publication result unconfirmed: code=PUBLICATION_RESULT_UNCONFIRMED",
                        PkiFailureReason.PUBLICATION_RESULT_UNCONFIRMED)),
                unsupportedService(CertificationRequestService.class),
                unsupportedService(IssuanceService.class),
                unsupportedService(StatusObjectService.class));

        PkiOperationOutcome.Failed failure = assertInstanceOf(
                PkiOperationOutcome.Failed.class,
                executor.execute(createAuthority(), CancellationSignal.NONE));

        assertEquals(PkiOperationFailure.EXTERNAL_OUTCOME_UNKNOWN, failure.classification());
        assertEquals("EXTERNAL_OUTCOME_UNKNOWN", failure.code());
        assertFalse(failure.code().contains("UNCONFIRMED"));
    }

    @Test
    void classifiesRevocationReasonsStructurallyWithoutMessageText() {
        // Revocation reasons carried structurally classify without the removed
        // REVOCATION text branches, producing the same stable outcomes.
        assertRevocationReasonClassifies(PkiFailureReason.REVOCATION_TERMINAL,
                PkiOperationFailure.POLICY_REJECTION, "PKI_POLICY_REJECTED");
        assertRevocationReasonClassifies(PkiFailureReason.REVOCATION_CREDENTIAL_NOT_FOUND,
                PkiOperationFailure.NOT_FOUND, "OBJECT_NOT_FOUND");
        assertRevocationReasonClassifies(PkiFailureReason.REVOCATION_TRANSITION_CONFLICT,
                PkiOperationFailure.CONFLICT, "OPERATION_CONFLICT");
        assertRevocationReasonClassifies(PkiFailureReason.REVOCATION_RECOVERY_REQUIRED,
                PkiOperationFailure.RECOVERY_REQUIRED, "RECOVERY_REQUIRED");
    }

    private void assertRevocationReasonClassifies(PkiFailureReason reason,
            PkiOperationFailure expectedClassification, String expectedCode) {
        DefaultPkiOperationExecutor executor = signingExecutor(
                failingAuthorities(new PkiException("Revocation operation failed", reason)),
                unsupportedService(CertificationRequestService.class),
                unsupportedService(IssuanceService.class),
                unsupportedService(StatusObjectService.class));

        PkiOperationOutcome.Failed failure = assertInstanceOf(
                PkiOperationOutcome.Failed.class,
                executor.execute(createAuthority(), CancellationSignal.NONE));

        assertEquals(expectedClassification, failure.classification());
        assertEquals(expectedCode, failure.code());
    }

    private static PkiOperation createAuthority() {
        return new PkiOperation.CreateAuthority(new FormatId("x509"), new SubjectRef("CN=Overload"),
                "root-ca", new KeyRef("managed:root"));
    }

    private static CaService failingAuthorities(RuntimeException failure) {
        return (CaService) Proxy.newProxyInstance(CaService.class.getClassLoader(), new Class<?>[] { CaService.class },
                (proxy, method, arguments) -> {
                    if ("createRoot".equals(method.getName()) && arguments.length == 2) {
                        throw failure;
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    private static DefaultPkiOperationExecutor signingExecutor(CaService authorities,
            CertificationRequestService requests, IssuanceService issuance, StatusObjectService statuses) {
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(1,
                new ProviderConfig("fs", Map.of("root", "unused")), new ProviderConfig("memory", Map.of()));
        PkiStore store = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class }, (proxy, method, arguments) -> throwUnsupported(method.getName()));
        ProfileService profiles = (ProfileService) Proxy.newProxyInstance(ProfileService.class.getClassLoader(),
                new Class<?>[] { ProfileService.class },
                (proxy, method, arguments) -> throwUnsupported(method.getName()));
        return new DefaultPkiOperationExecutor(configuration, store, profiles, revocations(new AtomicInteger()),
                Optional.of(authorities), Optional.of(requests), Optional.of(issuance), Optional.of(statuses),
                Optional.empty(), () -> { });
    }

    @SuppressWarnings("unchecked")
    private static <T> T captureService(Class<T> type, String methodName,
            AtomicReference<CancellationSignal> capture) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type },
                (proxy, method, arguments) -> {
                    // The cancellation signal is always the final argument, whether the issuance entrypoint
                    // is invoked with or without the co-committed evidence attribute set.
                    if (methodName.equals(method.getName()) && arguments.length >= 2
                            && arguments[arguments.length - 1] instanceof CancellationSignal cancellation) {
                        capture.set(cancellation);
                        throw new CaptureCompleteException();
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    @SuppressWarnings("unchecked")
    private static <T> T unsupportedService(Class<T> type) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type },
                (proxy, method, arguments) -> throwUnsupported(method.getName()));
    }

    private static Object throwUnsupported(String method) {
        throw new UnsupportedOperationException(method);
    }

    private static final class CaptureCompleteException extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    @Test
    void dispatchesCaLifecycleOperationsToAuthorityServiceWithExactCommands() {
        System.out.println("dispatchesCaLifecycleOperationsToAuthorityServiceWithExactCommands");
        AtomicReference<Object> captured = new AtomicReference<>();
        CaService authorities = (CaService) Proxy.newProxyInstance(CaService.class.getClassLoader(),
                new Class<?>[] { CaService.class }, (proxy, method, arguments) -> switch (method.getName()) {
                    case "rolloverCaCertificate", "rotateCaKey" -> {
                        captured.set(arguments[0]);
                        yield new PkiId("ca:dispatched");
                    }
                    default -> throwUnsupported(method.getName());
                });
        DefaultPkiOperationExecutor executor = authorityExecutor(authorities);

        PkiOperationResult rollover = assertInstanceOf(PkiOperationOutcome.Completed.class,
                executor.execute(new PkiOperation.RolloverCaCertificate(new PkiId("ca:x"), Optional.empty()),
                        CancellationSignal.NONE)).result();
        assertInstanceOf(CaRolloverCommand.class, captured.get());
        assertEquals(new PkiId("ca:x"), ((CaRolloverCommand) captured.get()).caId());
        assertEquals(new PkiOperationValue.Text("ca:dispatched"), rollover.field("caId").orElseThrow());

        KeyRef rotated = new KeyRef("kref:v1:keyring:test:rotated");
        PkiOperationResult rotate = assertInstanceOf(PkiOperationOutcome.Completed.class,
                executor.execute(new PkiOperation.RotateCaKey(new PkiId("ca:y"), Optional.of(rotated),
                        Optional.empty()), CancellationSignal.NONE)).result();
        assertInstanceOf(CaKeyRotationCommand.class, captured.get());
        assertEquals(new PkiId("ca:y"), ((CaKeyRotationCommand) captured.get()).caId());
        assertEquals(Optional.of(rotated), ((CaKeyRotationCommand) captured.get()).newKeyRef());
        assertEquals(new PkiOperationValue.Text("ca:dispatched"), rotate.field("caId").orElseThrow());
        System.out.println("...ok");
    }

    @Test
    void dispatchesIntermediateAndIssuerPathOperationsToAuthorityService() {
        System.out.println("dispatchesIntermediateAndIssuerPathOperationsToAuthorityService");
        AtomicReference<Object> captured = new AtomicReference<>();
        PkiId authorityId = new PkiId("ca:x");
        PkiId credentialId = new PkiId("cred:x");
        PkiId issuerId = IssuerGeneration.idFor(authorityId, credentialId);
        IssuerChainPath path = IssuerChainPath.create(authorityId, issuerId, List.of(credentialId));
        IssuerGeneration generation = new IssuerGeneration(issuerId, authorityId, credentialId,
                new KeyRef("kref:v1:keyring:test:im"), IssuerGenerationState.ACTIVE,
                "a".repeat(64), "b".repeat(64));
        CaService authorities = (CaService) Proxy.newProxyInstance(CaService.class.getClassLoader(),
                new Class<?>[] { CaService.class }, (proxy, method, arguments) -> switch (method.getName()) {
                    case "createIntermediate" -> {
                        captured.set(arguments[0]);
                        throw new PkiException("STOP_AFTER_CAPTURE");
                    }
                    case "issueIntermediateCertificate" -> {
                        captured.set(arguments[0]);
                        throw new PkiException("STOP_AFTER_CAPTURE");
                    }
                    case "getIssuerGeneration" -> generation;
                    case "getIssuerChainPath" -> path;
                    case "listIssuerChainPaths" -> List.of(path);
                    case "selectIssuancePath" -> {
                        captured.set(arguments);
                        yield null;
                    }
                    case "registerIssuerChainPath" -> {
                        captured.set(arguments);
                        yield path;
                    }
                    default -> throwUnsupported(method.getName());
                });
        DefaultPkiOperationExecutor executor = authorityExecutor(authorities);

        assertInstanceOf(PkiOperationOutcome.Failed.class,
                executor.execute(new PkiOperation.CreateIntermediate(new FormatId("x509"), authorityId,
                        new SubjectRef("CN=Intermediate"), "intermediate", Optional.empty()), CancellationSignal.NONE));
        assertInstanceOf(IntermediateCreateCommand.class, captured.get());
        assertEquals(authorityId, ((IntermediateCreateCommand) captured.get()).issuerCaId());
        assertEquals("intermediate", ((IntermediateCreateCommand) captured.get()).profileId());

        assertInstanceOf(PkiOperationOutcome.Failed.class,
                executor.execute(new PkiOperation.IssueIntermediateCertificate(new FormatId("x509"), authorityId,
                        new PkiId("ca:sub"), "intermediate", Optional.of(new Validity(
                                Instant.parse("2026-01-01T00:00:00Z"), Instant.parse("2031-01-01T00:00:00Z")))),
                        CancellationSignal.NONE));
        assertInstanceOf(IntermediateCertIssueCommand.class, captured.get());
        assertEquals(new PkiId("ca:sub"), ((IntermediateCertIssueCommand) captured.get()).subjectCaId());

        PkiOperationResult inspectGeneration = assertInstanceOf(PkiOperationOutcome.Completed.class,
                executor.execute(new PkiOperation.InspectIssuerGeneration(issuerId), CancellationSignal.NONE)).result();
        assertEquals(new PkiOperationValue.Text(issuerId.value()),
                inspectGeneration.field("issuerId").orElseThrow());
        assertEquals(new PkiOperationValue.Text("ACTIVE"), inspectGeneration.field("state").orElseThrow());

        PkiOperationResult inspectPath = assertInstanceOf(PkiOperationOutcome.Completed.class,
                executor.execute(new PkiOperation.InspectIssuerChainPath(path.pathId()), CancellationSignal.NONE))
                .result();
        assertEquals(new PkiOperationValue.Text(path.pathId().value()), inspectPath.field("pathId").orElseThrow());

        PkiOperationResult listPaths = assertInstanceOf(PkiOperationOutcome.Completed.class,
                executor.execute(new PkiOperation.ListIssuerChainPaths(issuerId), CancellationSignal.NONE)).result();
        assertEquals(new PkiOperationValue.IntegerValue(1L), listPaths.field("count").orElseThrow());

        assertInstanceOf(PkiOperationOutcome.Completed.class,
                executor.execute(new PkiOperation.SelectIssuancePath(authorityId, issuerId, path.pathId(),
                        "rotation"), CancellationSignal.NONE));
        Object[] selectArguments = (Object[]) captured.get();
        assertEquals(authorityId, selectArguments[0]);
        assertEquals("rotation", selectArguments[3]);

        PkiOperationResult register = assertInstanceOf(PkiOperationOutcome.Completed.class,
                executor.execute(new PkiOperation.RegisterIssuerChainPath(authorityId, issuerId, path.pathId()),
                        CancellationSignal.NONE)).result();
        assertEquals(new PkiOperationValue.Text(path.pathId().value()), register.field("pathId").orElseThrow());
        System.out.println("...ok");
    }

    private static DefaultPkiOperationExecutor authorityExecutor(CaService authorities) {
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(1,
                new ProviderConfig("fs", Map.of("root", "unused")), new ProviderConfig("memory", Map.of()));
        PkiStore store = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class },
                (proxy, method, arguments) -> throwUnsupported(method.getName()));
        ProfileService profiles = (ProfileService) Proxy.newProxyInstance(ProfileService.class.getClassLoader(),
                new Class<?>[] { ProfileService.class },
                (proxy, method, arguments) -> throwUnsupported(method.getName()));
        return new DefaultPkiOperationExecutor(configuration, store, profiles, revocations(new AtomicInteger()),
                Optional.of(authorities), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                Optional.empty(), () -> { });
    }

    private static DefaultPkiOperationExecutor executor(AtomicInteger mutations) {
        return executor(mutations, new AtomicReference<>());
    }

    private static DefaultPkiOperationExecutor executor(AtomicInteger mutations,
            AtomicReference<RevocationCommand.RevokePermanently> captured) {
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(1,
                new ProviderConfig("fs", Map.of("root", "unused")), new ProviderConfig("memory", Map.of()));
        PkiStore store = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class }, (proxy, method, arguments) -> switch (method.getName()) {
                    case "getCredential", "getPublicationRecord" -> Optional.empty();
                    case "close" -> null;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
        ProfileService profiles = (ProfileService) Proxy.newProxyInstance(ProfileService.class.getClassLoader(),
                new Class<?>[] { ProfileService.class }, (proxy, method, arguments) -> {
                    throw new UnsupportedOperationException(method.getName());
                });
        return new DefaultPkiOperationExecutor(configuration, store, profiles, revocations(mutations, captured), () -> {
        });
    }

    private static DefaultPkiOperationExecutor confirmationExecutor(
            CredentialConfirmationService confirmations) {
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(1,
                new ProviderConfig("fs", Map.of("root", "unused")),
                new ProviderConfig("memory", Map.of()));
        PkiStore store = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class },
                (proxy, method, arguments) -> throwUnsupported(method.getName()));
        ProfileService profiles = (ProfileService) Proxy.newProxyInstance(
                ProfileService.class.getClassLoader(), new Class<?>[] { ProfileService.class },
                (proxy, method, arguments) -> throwUnsupported(method.getName()));
        return new DefaultPkiOperationExecutor(configuration, store, profiles,
                revocations(new AtomicInteger()), Optional.empty(), Optional.empty(), Optional.empty(),
                Optional.empty(), Optional.empty(), Optional.of(confirmations), () -> { });
    }

    private static DefaultPkiOperationExecutor publicationExecutor() {
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(1,
                new ProviderConfig("fs", Map.of("root", "unused")), new ProviderConfig("memory", Map.of()));
        PkiStore store = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class }, (proxy, method, arguments) -> {
                    throw new UnsupportedOperationException(method.getName());
                });
        ProfileService profiles = (ProfileService) Proxy.newProxyInstance(ProfileService.class.getClassLoader(),
                new Class<?>[] { ProfileService.class }, (proxy, method, arguments) -> {
                    throw new UnsupportedOperationException(method.getName());
                });
        PublicationService publications = new PublicationService() {
            @Override
            public PublicationRecord register(PublicationRequest request) {
                throw new UnsupportedOperationException();
            }

            @Override
            public PublicationResult process(PkiId selected) {
                return new PublicationResult(selected, PublicationStatus.SUCCEEDED, 1L);
            }

            @Override
            public PublicationResult retry(PkiId selected) {
                return new PublicationResult(selected, PublicationStatus.SUCCEEDED, 2L);
            }

            @Override
            public PublicationResult reconcile(PkiId selected) {
                return new PublicationResult(selected, PublicationStatus.OUTCOME_UNKNOWN, 1L);
            }

            @Override
            public Optional<PublicationRecord> find(PkiId selected) {
                return Optional.empty();
            }

            @Override
            public PublicationCursor openPublications(PublicationQuery query) {
                throw new UnsupportedOperationException();
            }

            @Override
            public void close() {
                // no-op
            }
        };
        return new DefaultPkiOperationExecutor(configuration, store, profiles, revocations(new AtomicInteger()),
                Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(publications),
                () -> {
                });
    }

    private static RevocationService revocations(AtomicInteger mutations) {
        return revocations(mutations, new AtomicReference<>());
    }

    private static RevocationService revocations(AtomicInteger mutations,
            AtomicReference<RevocationCommand.RevokePermanently> captured) {
        return new RevocationService() {
            @Override
            public RevocationRecord hold(RevocationCommand.Hold command) {
                throw new UnsupportedOperationException();
            }

            @Override
            public RevocationRecord unhold(RevocationCommand.Unhold command) {
                throw new UnsupportedOperationException();
            }

            @Override
            public RevocationRecord revokePermanently(RevocationCommand.RevokePermanently command) {
                captured.set(command);
                mutations.incrementAndGet();
                return new RevocationRecord(command.credentialId(), transitions().get(1));
            }

            @Override
            public RevocationRecord revokeOverduePendingConfirmation(
                    RevocationCommand.RevokePermanently command) {
                captured.set(command);
                mutations.incrementAndGet();
                RevocationTransition baseline = transitions().get(1);
                return new RevocationRecord(command.credentialId(), new RevocationTransition(
                        baseline.revision(), baseline.state(), baseline.time(),
                        Optional.of(command.reason()), command.attributes()));
            }

            @Override
            public Optional<RevocationRecord> get(PkiId credentialId) {
                return Optional.empty();
            }

            @Override
            public RevocationHistory history(PkiId credentialId) {
                return historyCursor(credentialId);
            }

            @Override
            public RevocationSnapshot search(RevocationQuery query) {
                throw new UnsupportedOperationException();
            }

            @Override
            public zeroecho.pki.spi.store.RevocationTransitionFeed feed(
                    Optional<zeroecho.pki.spi.store.RevocationTransitionFeed.Position> afterExclusive) {
                throw new UnsupportedOperationException();
            }
        };
    }

    private static RevocationHistory historyCursor(PkiId credentialId) {
        return new RevocationHistory() {
            private int index = -1;

            @Override
            public PkiId credentialId() {
                return credentialId;
            }

            @Override
            public boolean next(CancellationSignal cancellation) throws IOException {
                cancellation.throwIfCancelled();
                index++;
                return index < transitions().size();
            }

            @Override
            public RevocationTransition current() {
                return transitions().get(index);
            }

            @Override
            public void close() {
                // no-op
            }
        };
    }

    private static List<RevocationTransition> transitions() {
        return List.of(new RevocationTransition(1L, RevocationState.HELD, Instant.parse("2026-08-04T00:00:00Z"),
                Optional.empty(), new SimpleAttributeSet()),
                new RevocationTransition(2L, RevocationState.PERMANENTLY_REVOKED,
                        Instant.parse("2026-08-04T00:01:00Z"), Optional.of(RevocationReason.KEY_COMPROMISE),
                        new SimpleAttributeSet()));
    }
}
