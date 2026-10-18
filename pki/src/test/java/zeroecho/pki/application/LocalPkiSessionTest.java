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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiFailureReason;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.RequestStorePolicy;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.crypto.zeroecholib.TestKeyringUnlocks;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProviderRuntimeDependencies;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.PkiStoreRuntimeDependencies;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.H7ProfileDocuments;
import zeroecho.pki.testkit.RootCreationFixture;
import zeroecho.pkix.Pkix;

final class LocalPkiSessionTest {
    private static final FormatId X509 = new FormatId("x509");
    private static final KeyRef ROOT_KEY = new KeyRef("zeroecho-lib:root.prv");
    private static final KeyRef CHILD_KEY = new KeyRef("zeroecho-lib:child.prv");
    private static final KeyRef ROTATED_KEY = new KeyRef("zeroecho-lib:rotated.prv");

    @Test
    void realKeyringCompletesRootIntermediateLifecycleAndCrlOnCallerWithoutSigningThreads(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(root);
        Set<Thread> before = signingThreads();
        LocalSigningExecutor borrowed;
        try (PkiSession session = fixture.open("first-operator")) {
            assertTrue(session.ocsp().isEmpty());
            borrowed = session.localSigning().orElseThrow();
            LocalSigningResult.Completed created = completed(borrowed.execute(rootCommand(), CancellationSignal.NONE));
            assertEquals(1, fixture.dispatches.get());
            CaRecord rootCa = fixture.store.listCas().getFirst();
            completed(borrowed.execute(new PkiSigningOperation.RolloverCaCertificate(rootCa.caId(), Optional.empty()), CancellationSignal.NONE));
            completed(borrowed.execute(new PkiSigningOperation.RotateCaKey(rootCa.caId(), Optional.of(ROTATED_KEY), Optional.empty()), CancellationSignal.NONE));
            PkiSigningOperation childCommand = new PkiSigningOperation.CreateIntermediate(
                    X509, rootCa.caId(), new SubjectRef("CN=Local Child"), "intermediate-test", Optional.of(CHILD_KEY));
            LocalSigningResult.Completed child = completed(borrowed.execute(childCommand, CancellationSignal.NONE));
            assertEquals(5, fixture.dispatches.get(), "Intermediate creation performs proof and certificate signing");
            PkiId childId = fixture.store.listCas().stream().filter(value -> !value.caId().equals(rootCa.caId())).findFirst().orElseThrow().caId();
            PkiSigningOperation issueChild = new PkiSigningOperation.IssueIntermediateCertificate(X509, rootCa.caId(), childId,
                    "intermediate-test", Optional.empty());
            completed(borrowed.execute(issueChild, CancellationSignal.NONE));
            completed(borrowed.execute(new PkiSigningOperation.GenerateStatus(rootCa.caId(), StatusObjectType.CRL, X509), CancellationSignal.NONE));
            completed(borrowed.execute(new PkiSigningOperation.GenerateStatus(rootCa.caId(), StatusObjectType.DELTA_CRL, X509), CancellationSignal.NONE));
            assertEquals(created.receipt(), completed(borrowed.complete(created.receipt().operationId(), CancellationSignal.NONE)).receipt());
            assertEquals(SemanticSigningState.COMPLETED, session.semanticSigning().orElseThrow().find(child.receipt().operationId()).orElseThrow().state());
            assertEquals(before, signingThreads());
            assertThrows(RuntimeException.class, () -> fixture.open("competing-operator"));
            assertEquals("first-operator", fixture.store.getSignWorkflow(created.receipt().operationId()).orElseThrow().owner().name());
        }
        assertThrows(IllegalStateException.class, () -> borrowed.execute(rootCommand(), CancellationSignal.NONE));
        assertEquals(before, signingThreads());
    }

    @Test
    void localRootApprovesAllProfileRequirementsWithoutServerEvidence(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(root);
        KeyPair leaf = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        byte[] csr = Pkix.certificationRequestBuilder().subject(new X500Principal("CN=Local Applicant"))
                .publicKey(leaf.getPublic()).build(Pkix.signer(leaf.getPrivate(),
                        zeroecho.pkix.AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11"))).encoded();
        try (PkiSession session = fixture.open("root-operator")) {
            LocalSigningExecutor executor = session.localSigning().orElseThrow();
            completed(executor.execute(rootCommand(), CancellationSignal.NONE));
            PkiId authority = fixture.store.listCas().getFirst().caId();
            PkiId request = session.requests().orElseThrow().store(session.requests().orElseThrow().parse(
                    new CertificationRequest(X509, new EncodedObject(Encoding.DER, csr))), RequestStorePolicy.STORE_ALWAYS);
            for (String requirement : List.of("NONE", "SINGLE", "THRESHOLD")) {
                String profile = "local-" + requirement.toLowerCase(java.util.Locale.ROOT);
                byte[] document = new String(H7ProfileDocuments.noSanOrEkuProfile(), StandardCharsets.UTF_8)
                        .replace("h7-no-san-eku", profile).replace("PT8760H", "PT24H")
                        .replace("\"approvalRequirement\":\"NONE\"", "\"approvalRequirement\":\"" + requirement + "\"")
                        .getBytes(StandardCharsets.UTF_8);
                session.profiles().importProfile(document);
                session.profiles().activateProfile(profile, 1);
                PkiSigningOperation issuance = new PkiSigningOperation.IssueCredential(authority, request, profile);
                LocalSigningResult.Completed issued = completed(executor.execute(issuance, CancellationSignal.NONE));
                PkiId credential = new PkiId(((PkiOperationValue.Text) issued.result().fields().get("credentialId")).value());
                assertEquals("root-operator", fixture.store.getSignWorkflow(issued.receipt().operationId()).orElseThrow().owner().name());
                assertTrue(IssuanceExecutionEvidence.decode(fixture.store.getCredential(credential).orElseThrow().attributes()).isEmpty());
                completed(executor.execute(new PkiSigningOperation.RenewCredential(credential), CancellationSignal.NONE));
                LocalSigningResult.Completed reissued = completed(executor.execute(new PkiSigningOperation.ReissueCredential(credential), CancellationSignal.NONE));
                PkiId latest = new PkiId(((PkiOperationValue.Text) reissued.result().fields().get("credentialId")).value());
                completed(executor.execute(new PkiSigningOperation.ReplaceCredential(latest, request, profile), CancellationSignal.NONE));
            }
        }
    }

    @Test
    void reopenAndReadsDoNotAdvanceAcceptedWorkExplicitCompletePreservesOriginalActor(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(root);
        SigningAcceptanceReceipt receipt;
        SigningAcceptanceReceipt unrelated;
        try (PkiSession session = fixture.open("original")) {
            receipt = acceptRoot(session);
            unrelated = accept(session, new PkiSigningOperation.CreateAuthority(X509,
                    new SubjectRef("CN=Unrelated Root,C=CZ"), "root-test", CHILD_KEY));
            assertEquals(0, fixture.dispatches.get());
        }
        try (PkiSession session = fixture.open("recovery-operator")) {
            assertEquals(SemanticSigningState.SIGNING, session.semanticSigning().orElseThrow().find(receipt.operationId()).orElseThrow().state());
            session.operations().execute(new PkiOperation.ValidateConfiguration(), CancellationSignal.NONE);
            assertEquals(0, fixture.dispatches.get());
            completed(session.localSigning().orElseThrow().complete(receipt.operationId(), CancellationSignal.NONE));
            assertEquals(SignWorkflowStore.State.INTENT, fixture.store.getSignWorkflow(unrelated.operationId()).orElseThrow().state());
            assertEquals("original", fixture.store.getSignWorkflow(receipt.operationId()).orElseThrow().owner().name());
            assertTrue(fixture.events.stream().anyMatch(event -> event.principal().name().equals("recovery-operator")
                    && event.purpose().value().equals("signing.operation.complete")));
            assertTrue(fixture.events.stream().anyMatch(event -> event.principal().name().equals("recovery-operator")
                    && event.purpose().value().equals(PkiOperation.ValidateConfiguration.NAME)));
        }
    }

    @Test
    void uncertainAcceptanceRetainsReceiptAndNeverSignsUntilExplicitCompletion(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(root);
        SigningAcceptanceReceipt receipt;
        try (PkiSession session = fixture.open("root")) {
            fixture.loseAcceptance = true;
            LocalSigningResult.Failed uncertain = assertInstanceOf(LocalSigningResult.Failed.class,
                    session.localSigning().orElseThrow().execute(rootCommand(), CancellationSignal.NONE));
            assertEquals(PkiOperationFailure.RECOVERY_REQUIRED, uncertain.failure().classification());
            receipt = uncertain.receipt().orElseThrow();
            assertEquals(SignWorkflowStore.State.INTENT, fixture.store.getSignWorkflow(receipt.operationId()).orElseThrow().state());
            assertEquals(0, fixture.dispatches.get());
        }
        try (PkiSession session = fixture.open("recovery")) {
            assertEquals(0, fixture.dispatches.get());
            completed(session.localSigning().orElseThrow().complete(receipt.operationId(), CancellationSignal.NONE));
            assertEquals(1, fixture.dispatches.get());
        }
    }

    @Test
    void durableSignatureResumesPublicationOnlyAfterExplicitEligibleCompletion(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(root);
        SigningAcceptanceReceipt receipt;
        try (PkiSession session = fixture.open("root")) {
            fixture.failPublication = true;
            LocalSigningResult.Failed failed = assertInstanceOf(LocalSigningResult.Failed.class,
                    session.localSigning().orElseThrow().execute(rootCommand(), CancellationSignal.NONE));
            assertEquals(PkiOperationFailure.RECOVERY_REQUIRED, failed.failure().classification());
            receipt = failed.receipt().orElseThrow();
            SignWorkflowStore.Workflow workflow = fixture.store.getSignWorkflow(receipt.operationId()).orElseThrow();
            assertEquals(SignWorkflowStore.State.SUCCEEDED, workflow.state());
            assertTrue(workflow.nextEligibleAt().orElseThrow().isAfter(fixture.clock.instant()));
            fixture.failPublication = false;
            LocalSigningResult.Failed notReady = assertInstanceOf(LocalSigningResult.Failed.class,
                    session.localSigning().orElseThrow().complete(receipt.operationId(), CancellationSignal.NONE));
            assertEquals("SIGNING_NOT_READY", notReady.failure().code());
            assertTrue(fixture.store.listCas().isEmpty());
            fixture.clock.now = workflow.nextEligibleAt().orElseThrow().plusSeconds(1);
        }
        try (PkiSession session = fixture.open("recovery")) {
            assertTrue(fixture.store.listCas().isEmpty());
            assertEquals(1, fixture.dispatches.get());
            assertEquals(SemanticSigningState.PUBLISHING, session.semanticSigning().orElseThrow().find(receipt.operationId()).orElseThrow().state());
            completed(session.localSigning().orElseThrow().complete(receipt.operationId(), CancellationSignal.NONE));
            assertEquals(1, fixture.dispatches.get(), "Persisted signature must not be recreated");
        }
    }

    @Test
    void liveClaimReturnsImmediatelyAndExpiredClaimReconcilesWithoutRedispatch(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(root);
        SigningAcceptanceReceipt receipt;
        try (PkiSession session = fixture.open("root")) {
            receipt = acceptRoot(session);
            SignWorkflowStore.Workflow intent = fixture.store.getSignWorkflow(receipt.operationId()).orElseThrow();
            SignWorkflowStore.Workflow claimed = fixture.store.claimSignStep(receipt.operationId(), intent.revision(), Duration.ofSeconds(10)).orElseThrow();
            LocalSigningResult.Failed notReady = assertInstanceOf(LocalSigningResult.Failed.class,
                    session.localSigning().orElseThrow().complete(receipt.operationId(), CancellationSignal.NONE));
            assertEquals("SIGNING_NOT_READY", notReady.failure().code());
            assertEquals(claimed.revision(), fixture.store.getSignWorkflow(receipt.operationId()).orElseThrow().revision());
            fixture.clock.now = claimed.leaseUntil().orElseThrow().plusSeconds(1);
        }
        try (PkiSession session = fixture.open("recovery")) {
            LocalSigningResult.Failed failed = assertInstanceOf(LocalSigningResult.Failed.class,
                    session.localSigning().orElseThrow().complete(receipt.operationId(), CancellationSignal.NONE));
            assertEquals("LOCAL_RESTART_UNRECOVERABLE", failed.failure().code());
            assertEquals(0, fixture.dispatches.get());
            assertTrue(fixture.store.listCas().isEmpty());
        }
    }

    @Test
    void retiredProviderCancellationRemainsCancelledAfterReopen(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(root);
        SigningAcceptanceReceipt receipt;
        try (PkiSession session = fixture.open("root")) {
            fixture.providerCancelled = true;
            LocalSigningResult.Failed cancelled = assertInstanceOf(LocalSigningResult.Failed.class,
                    session.localSigning().orElseThrow().execute(rootCommand(), CancellationSignal.NONE));
            receipt = cancelled.receipt().orElseThrow();
            assertEquals(PkiOperationFailure.CANCELLED, cancelled.failure().classification());
            assertEquals("CANCELLED", cancelled.failure().code());
            assertEquals(SignWorkflowStore.State.RETIRED, fixture.store.getSignWorkflow(receipt.operationId()).orElseThrow().state());
        }
        try (PkiSession session = fixture.open("recovery")) {
            LocalSigningResult.Failed cancelled = assertInstanceOf(LocalSigningResult.Failed.class,
                    session.localSigning().orElseThrow().complete(receipt.operationId(), CancellationSignal.NONE));
            assertEquals(PkiOperationFailure.CANCELLED, cancelled.failure().classification());
            assertEquals("CANCELLED", cancelled.failure().code());
        }
    }

    @Test
    void independentReadFailureIsNotCancellationAndPostClaimUncertaintyIsRecovery(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(root);
        try (PkiSession session = fixture.open("root")) {
            SigningAcceptanceReceipt receipt = acceptRoot(session);
            fixture.failRead = true;
            Thread.currentThread().interrupt();
            try {
                LocalSigningResult.Failed failed = assertInstanceOf(LocalSigningResult.Failed.class,
                        session.localSigning().orElseThrow().complete(receipt.operationId(), () -> true));
                assertEquals(PkiOperationFailure.RESOURCE_FAILURE, failed.failure().classification());
                assertTrue(Thread.currentThread().isInterrupted());
            } finally { Thread.interrupted(); }
            fixture.failRead = false;
            fixture.failReadAfterClaim = true;
            LocalSigningResult.Failed failed = assertInstanceOf(LocalSigningResult.Failed.class,
                    session.localSigning().orElseThrow().complete(receipt.operationId(), CancellationSignal.NONE));
            assertEquals(PkiOperationFailure.RECOVERY_REQUIRED, failed.failure().classification());
            assertEquals(receipt, failed.receipt().orElseThrow());
            fixture.failRead = false;
            fixture.failReadAfterClaim = false;
        }
    }

    @Test
    void completedPublicationWinsOverLateCancellation(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(root);
        try (PkiSession session = fixture.open("root")) {
            fixture.cancelAfterDispatch = true;
            completed(session.localSigning().orElseThrow().execute(rootCommand(), fixture.cancellation::get));
            assertTrue(fixture.cancellation.get());
        }
    }

    @Test
    void cancellationAfterPreparationDiscardsUnboundContentAndRetainsReceipt(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(root);
        try (PkiSession session = fixture.open("root")) {
            long before;
            try (java.util.stream.Stream<Path> files = java.nio.file.Files.walk(root)) {
                before = files.filter(path -> path.getFileName().toString().endsWith(".content")).count();
            }
            PkiSigningCommands commands = new PkiSigningCommands() {
                @Override public PreparedSemanticSigningRequest prepare(PkiSigningOperation operation, AccessContext access,
                        Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
                    PreparedSemanticSigningRequest prepared = session.signingCommands().orElseThrow().prepare(operation, access, evidence, cancellation);
                    fixture.cancellation.set(true);
                    return prepared;
                }
                @Override public PkiOperationResult completedResult(zeroecho.pki.api.signing.SemanticSigningOperation operation) {
                    throw new AssertionError("Cancelled candidate must not execute");
                }
            };
            LocalSigningExecutor executor = new DefaultLocalSigningExecutor(fixture.store, fixture.provider,
                    session.semanticSigning().orElseThrow(), commands, fixture.signingConfiguration(),
                    ignored -> { throw new AssertionError("Cancelled candidate must not publish"); },
                    new LocalInvocationAudit(fixture.events::add, fixture.clock, new Principal("LOCAL_OPERATOR", "root")), () -> { });
            LocalSigningResult.Failed cancelled = assertInstanceOf(LocalSigningResult.Failed.class,
                    executor.execute(rootCommand(), fixture.cancellation::get));
            assertEquals(PkiOperationFailure.CANCELLED, cancelled.failure().classification());
            assertTrue(fixture.store.getSignWorkflow(cancelled.receipt().orElseThrow().operationId()).isEmpty());
            assertEquals(0, fixture.dispatches.get());
            try (java.util.stream.Stream<Path> files = java.nio.file.Files.walk(root)) {
                assertEquals(before, files.filter(path -> path.getFileName().toString().endsWith(".content")).count());
            }
        }
    }

    @Test
    void explicitCompletionRejectsUnknownAndRawSignOnlyIdentitiesWithoutAdvancing(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(root);
        try (PkiSession session = fixture.open("root")) {
            zeroecho.pki.api.SigningService raw = session.signing().orElseThrow();
            PkiId absent = raw.newSubmissionId().id();
            LocalSigningResult.Failed missing = assertInstanceOf(LocalSigningResult.Failed.class,
                    session.localSigning().orElseThrow().complete(absent, CancellationSignal.NONE));
            assertEquals(PkiOperationFailure.NOT_FOUND, missing.failure().classification());
            assertTrue(missing.receipt().isEmpty());
            zeroecho.pki.api.signing.SigningRequest input = new zeroecho.pki.api.signing.SigningRequest(
                    raw.newSubmissionId(), new AccessContext(new Principal("LOCAL_OPERATOR", "root"), new Purpose("TEST"),
                            Optional.empty(), Optional.empty()), ROOT_KEY, new PkiId("raw-authority"),
                    zeroecho.core.alg.BootstrapAlgorithmIdentities.ED25519_SIGNATURE, Encoding.BINARY, Encoding.BINARY);
            zeroecho.core.io.OneShotContent content = new zeroecho.core.io.OneShotContent() {
                @Override public java.io.InputStream openStream() { return new java.io.ByteArrayInputStream(new byte[] { 1, 2 }); }
                @Override public OptionalLong length() { return OptionalLong.of(2); }
                @Override public void close() { }
            };
            SigningAcceptanceReceipt receipt = raw.accept(raw.prepare(input, content, CancellationSignal.NONE)).receipt();
            LocalSigningResult.Failed unsupported = assertInstanceOf(LocalSigningResult.Failed.class,
                    session.localSigning().orElseThrow().complete(receipt.operationId(), CancellationSignal.NONE));
            assertEquals(PkiOperationFailure.NOT_FOUND, unsupported.failure().classification());
            assertEquals(SignWorkflowStore.State.INTENT, fixture.store.getSignWorkflow(receipt.operationId()).orElseThrow().state());
            assertEquals(0, fixture.dispatches.get());
        }
    }

    @Test
    void auditedInspectionNeverAdvancesPendingWorkAndProjectsOnlyCompletedMetadata(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(root);
        SigningAcceptanceReceipt receipt;
        try (PkiSession session = fixture.open("creator")) {
            receipt = acceptRoot(session);
        }
        LocalSigningExecutor borrowed;
        try (PkiSession session = fixture.open("observer")) {
            borrowed = session.localSigning().orElseThrow();
            PkiOperationOutcome.Completed pending = assertInstanceOf(PkiOperationOutcome.Completed.class,
                    borrowed.inspect(receipt.operationId(), CancellationSignal.NONE));
            assertEquals(new PkiOperationValue.Text("SIGNING"), pending.result().fields().get("state"));
            assertFalse(pending.result().fields().containsKey("credentialId"));
            assertFalse(pending.result().fields().containsKey("resultSha256"));
            assertEquals(0, fixture.dispatches.get());
            assertEquals(SignWorkflowStore.State.INTENT, fixture.store.getSignWorkflow(receipt.operationId()).orElseThrow().state());
            PkiOperationOutcome.Failed missing = assertInstanceOf(PkiOperationOutcome.Failed.class,
                    borrowed.inspect(session.signing().orElseThrow().newSubmissionId().id(), CancellationSignal.NONE));
            assertEquals(PkiOperationFailure.NOT_FOUND, missing.classification());
            PkiOperationOutcome.Failed cancelled = assertInstanceOf(PkiOperationOutcome.Failed.class,
                    borrowed.inspect(receipt.operationId(), () -> true));
            assertEquals(PkiOperationFailure.CANCELLED, cancelled.classification());
            completed(borrowed.complete(receipt.operationId(), CancellationSignal.NONE));
            PkiOperationOutcome.Completed completed = assertInstanceOf(PkiOperationOutcome.Completed.class,
                    borrowed.inspect(receipt.operationId(), CancellationSignal.NONE));
            assertEquals(new PkiOperationValue.Text("COMPLETED"), completed.result().fields().get("state"));
            assertTrue(completed.result().fields().containsKey("credentialId"));
            assertTrue(completed.result().fields().containsKey("resultSha256"));
            assertEquals(Set.of("operationId", "kind", "state", "signingState", "revision", "signingRevision",
                    "createdAt", "deadline", "encoding", "resultSha256", "credentialId"),
                    completed.result().fields().keySet().stream().filter(key -> !key.equals("detailCode"))
                            .collect(java.util.stream.Collectors.toSet()));
            assertEquals(1, fixture.dispatches.get());
            assertEquals("original", fixture.store.getSignWorkflow(receipt.operationId()).orElseThrow().owner().name());
            assertEquals(8, fixture.events.stream().filter(event -> event.purpose().value().equals("signing.operation.inspect")
                    && event.principal().name().equals("observer")).count());
        }
        assertThrows(IllegalStateException.class, () -> borrowed.inspect(receipt.operationId(), CancellationSignal.NONE));
    }

    private static SigningAcceptanceReceipt acceptRoot(PkiSession session) {
        return accept(session, rootCommand());
    }

    private static SigningAcceptanceReceipt accept(PkiSession session, PkiSigningOperation operation) {
        AccessContext original = new AccessContext(new Principal("LOCAL_OPERATOR", "original"),
                new Purpose("ca.create"), Optional.empty(), Optional.empty());
        PreparedSemanticSigningRequest request = session.signingCommands().orElseThrow().prepare(operation, original,
                Optional.empty(), CancellationSignal.NONE);
        zeroecho.pki.api.signing.SigningAcceptanceResult accepted = session.semanticSigning().orElseThrow().accept(request);
        assertEquals(zeroecho.pki.api.signing.SigningAcceptanceDisposition.ACCEPTED, accepted.disposition());
        return accepted.receipt();
    }

    static PkiSigningOperation rootCommand() {
        return new PkiSigningOperation.CreateAuthority(X509, new SubjectRef("CN=Local Root,C=CZ"), "root-test", ROOT_KEY);
    }

    private static LocalSigningResult.Completed completed(LocalSigningResult result) {
        return assertInstanceOf(LocalSigningResult.Completed.class, result, result.toString());
    }

    private static Set<Thread> signingThreads() {
        return Thread.getAllStackTraces().keySet().stream().filter(thread ->
                        thread.getName().equals("zeroecho-signing-topology-scanner") || thread.getName().startsWith("zeroecho-signing-pool-"))
                .collect(java.util.stream.Collectors.toSet());
    }

    private static final class MutableClock extends Clock {
        private Instant now = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }

    static final class Fixture implements DefaultPkiSession.Bootstrap {
        private final Path root;
        private final Path keyring;
        private final MutableClock clock = new MutableClock();
        final AtomicInteger dispatches = new AtomicInteger();
        private final List<AuditEvent> events = new ArrayList<>();
        private final AtomicBoolean cancellation = new AtomicBoolean();
        PkiStore store;
        private SigningProvider provider;
        private boolean loseAcceptance;
        private boolean failPublication;
        private boolean failRead;
        private boolean failReadAfterClaim;
        private boolean providerCancelled;
        private boolean cancelAfterDispatch;
        private boolean controlledProviderClock;

        Fixture(Path root) throws Exception {
            this.root = root;
            keyring = root.resolve("keys.bin");
            try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                    KeyringStore keys = KeyringStore.create(keyring, password)) {
                for (String name : List.of("root", "child", "rotated")) {
                    KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
                    keys.putPrivate(name + ".prv", "Ed25519", pair.getPrivate());
                    keys.putPublic(name + ".pub", "Ed25519", pair.getPublic());
                }
            }
        }

        void time(Instant instant) { clock.now = instant; controlledProviderClock = true; }

        PkiSession open(String operator) {
            return DefaultPkiSession.openLocal(new LocalPkiSessionConfiguration(new ProviderConfig("fs", Map.of("root", root.resolve("store").toString())),
                    new ProviderConfig("memory", Map.of()), operator, Optional.of(signingConfiguration()), List.of(), List.of()),
                    PkiSessionRuntimeDependencies.withKeyringUnlockProvider(TestKeyringUnlocks.provider()), clock, this);
        }

        LocalSigningConfiguration signingConfiguration() {
            return new LocalSigningConfiguration(new ProviderConfig("zeroecho-lib", Map.of(
                    "keyringPath", keyring.toString(), "operationHorizon", "P90D", "keyRefPrefix", "zeroecho-lib:",
                    "requireComponentSuffix", "true")), RootCreationFixture.ALGORITHM, Duration.ofMinutes(5),
                    Optional.empty(), Duration.ofSeconds(30), Duration.ofSeconds(20), OptionalLong.empty());
        }

        @Override public void validateStore(ProviderConfig configuration) { PkiBootstrap.validateStoreConfiguration(configuration); }
        @Override public void validateAudit(ProviderConfig configuration) { PkiBootstrap.validateAuditConfiguration(configuration); }
        @Override public PkiStore openStore(ProviderConfig configuration) { return openStore(configuration, new PkiStoreRuntimeDependencies(clock)); }
        @Override public PkiStore openStore(ProviderConfig configuration, PkiStoreRuntimeDependencies dependencies) {
            store = PkiBootstrap.openStore(configuration, dependencies);
            if (store.getActiveProfileRef("root-test").isEmpty()) {
                try {
                    RootCreationFixture.install(store, RootCreationFixture.definition("root-test", CertificateProfileKind.ROOT_CA,
                            Duration.ofDays(100), X509AlgorithmBindingPolicy.standardOnly()));
                    RootCreationFixture.install(store, new zeroecho.pki.api.profile.CertificateProfileDefinition(
                            CertificateProfileKind.INTERMEDIATE_CA, "intermediate-test", 1, X509, "Local intermediate",
                            Duration.ofDays(30), new zeroecho.pki.api.profile.SubjectPolicy(false, List.of(
                                    new zeroecho.pki.api.profile.SubjectRdnRule(zeroecho.pki.api.profile.SubjectRdnType.COMMON_NAME,
                                            1, 1, 128, Optional.empty(), true))),
                            new zeroecho.pki.api.profile.CaCertificatePolicy(true, 1, true,
                                    Set.of(zeroecho.pki.api.profile.CaKeyUsage.KEY_CERT_SIGN, zeroecho.pki.api.profile.CaKeyUsage.CRL_SIGN),
                                    Set.of("Ed25519")), X509AlgorithmBindingPolicy.standardOnly()));
                } catch (Exception failure) { throw new AssertionError(failure); }
            }
            PkiStore actual = store;
            store = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                    (proxy, method, arguments) -> {
                        String name = method.getName();
                        if (failRead && name.equals("getSignWorkflow") || failPublication && name.equals("putCredentialFromSigning")) {
                            throw new IllegalStateException("Injected independent metadata failure");
                        }
                        try {
                            Object result = method.invoke(actual, arguments);
                            if (name.equals("acceptSign") && loseAcceptance) {
                                loseAcceptance = false;
                                throw new PkiException("Injected lost durable acknowledgement", PkiFailureReason.STORE_DURABILITY_UNCONFIRMED);
                            }
                            if (name.equals("claimSignStep") && failReadAfterClaim) failRead = true;
                            return result;
                        } catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
            return store;
        }
        @Override public AuditSink openAudit(ProviderConfig configuration) { return events::add; }
        @Override public PkiBootstrap.SigningComposition openSigningComposition(ProviderConfig configuration,
                SigningProviderRuntimeDependencies dependencies) {
            PkiBootstrap.SigningComposition allocation = PkiBootstrap.openConfiguredSigningComposition(configuration, dependencies);
            SigningProvider effective = allocation.provider();
            if (controlledProviderClock) {
                SigningProvider.ConfigurationCommitment commitment = effective.configurationCommitment();
                effective.close();
                effective = TestKeyringUnlocks.withClock(keyring, clock, commitment);
            }
            SigningProvider selected = effective;
            Thread caller = Thread.currentThread();
            SigningProvider counted = (SigningProvider) Proxy.newProxyInstance(SigningProvider.class.getClassLoader(),
                    new Class<?>[] { SigningProvider.class, PublicKeyInfoSource.class }, (proxy, method, arguments) -> {
                        if (method.getName().equals("dispatch")) {
                            assertEquals(caller, Thread.currentThread());
                            dispatches.incrementAndGet();
                            if (providerCancelled) return new SigningProvider.OperationObservation(
                                    ((SigningProvider.SignRequest) arguments[0]).operationId(), SigningProvider.ObservationState.CANCELLED,
                                    clock.instant(), SigningProvider.DetailCode.CANCELLED, Optional.empty());
                        }
                        try {
                            Object result = method.invoke(selected, arguments);
                            if (method.getName().equals("dispatch") && cancelAfterDispatch) cancellation.set(true);
                            return result;
                        }
                        catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
            provider = counted;
            return new PkiBootstrap.SigningComposition(counted, allocation.capabilities());
        }
    }
}
