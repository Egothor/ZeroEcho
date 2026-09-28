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

package zeroecho.pki.impl.core.signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.List;
import java.util.Set;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.issuance.CorrelatedEndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.CorrelatedIssuancePreparation;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.issuance.EndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.RetainedIssuanceBinding;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.impl.core.CorrelatedIssuanceIdentity;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningKind;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.api.signing.SigningAcceptanceDisposition;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.api.signing.SigningAcceptanceResolution;
import zeroecho.pki.api.signing.SigningOperationState;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainAttributeEncoding;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.DomainContinuationValidation;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FilesystemPkiStoreTestAccess;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.PkiTestRuntime;

final class DefaultSemanticSigningServiceTest {
    static final Instant NOW = Instant.parse("2026-01-02T03:04:05Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final Duration TTL = Duration.ofMinutes(1);
    private static final KeyRef KEY = new KeyRef("test-key");
    static final PkiId FAIRNESS = new PkiId("authority");
    static final AccessContext ACCESS = new AccessContext(
            new Principal("TEST", "signer"), new Purpose("CA_CREATE"),
            Optional.empty(), Optional.empty());

    @Test
    void rejectsInconsistentEvidenceDuringAdoptionAndRetainedObservation(@TempDir Path root) throws Exception {
        AccessContext access = new AccessContext(new Principal("ACME_ACCOUNT", "account"), ACCESS.purpose(),
                Optional.empty(), Optional.empty());
        List<IssuanceExecutionEvidence> inconsistent = List.of(
                IssuanceExecutionEvidence.acme("wrong-account", "realm", "invocation", "authority", "profile"),
                IssuanceExecutionEvidence.administrative("account", "realm", "invocation",
                        IssuanceExecutionEvidence.Authentication.DIRECT_MTLS,
                        IssuanceExecutionEvidence.AuthorizationPath.APPROVAL, "1".repeat(64), "authority", "profile"),
                IssuanceExecutionEvidence.acme("account", "realm", "invocation", "wrong-authority", "profile"),
                IssuanceExecutionEvidence.acme("account", "realm", "invocation", "authority", "wrong-profile"));
        for (int index = 0; index < inconsistent.size(); index++) {
            try (FilesystemPkiStore store = open(root.resolve(Integer.toString(index)));
                    TestProvider provider = new TestProvider()) {
                DefaultSigningService signing = signing(store, provider);
                DefaultSemanticSigningService service = semantic(store, signing);
                CorrelatedEndEntityIssuanceRequest input = correlatedInput();
                DomainSigningRequest original = issuance(store, signing, input, 22,
                        DomainAttributeEncoding.encode(inconsistent.get(index).attributes()));
                DomainSigningRequest request = new DomainSigningRequest(original.operationId(), access, original.keyRef(),
                        original.algorithmId(), original.signatureEncoding(), original.content(), original.ttl(),
                        original.domainTemplate(), original.proofStep());
                IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                        () -> service.prepare(request, FAIRNESS));
                assertEquals("Issuance execution evidence binding differs", failure.getMessage());
                assertTrue(PkiTestRuntime.readContent(store, request.content()).length > 0);
                assertTrue(store.getSignWorkflow(request.operationId()).isEmpty());

                DomainContinuationTemplate template = request.domainTemplate();
                SignWorkflowStore.OuterCommand outer = new SignWorkflowStore.OuterCommand(template.kind(),
                        template.correlationId().orElseThrow(), template.command(), template.commandCommitment());
                // Model an inconsistent retained envelope without passing through semantic adoption.
                SignWorkflowStore.AcceptanceCommand acceptance = new SignWorkflowStore.AcceptanceCommand(
                        request.operationId(), signing.newSubmissionId().namespace(), provider.configurationCommitment(),
                        access, request.keyRef(), FAIRNESS, request.algorithmId(), request.signatureEncoding(),
                        NOW, NOW.plus(TTL), request.content(), Optional.of(outer), SignWorkflowStore.Mode.NORMAL, java.util.Optional.empty());
                assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(acceptance));
                assertThrows(IllegalArgumentException.class, () -> service.find(request.operationId()));
                assertThrows(IllegalArgumentException.class, () -> service.findIssuance(input));
                assertThrows(IllegalArgumentException.class,
                        () -> service.findByCorrelation(SemanticSigningKind.ISSUANCE, outer.correlationId()));
                assertEquals(0, provider.calls.get());
            }
        }
    }

    @Test
    void providerLimitRejectsSemanticAcceptanceBeforeCustodyOrOuterContinuation(@TempDir Path root)
            throws Exception {
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider()) {
            AtomicInteger accepts = new AtomicInteger();
            DefaultSigningService signing = signing(store, provider, (command, custody) -> {
                accepts.incrementAndGet();
                custody.run();
                return store.acceptSign(command);
            });
            DefaultSemanticSigningService service = semantic(store, signing);
            DomainSigningRequest request = request(store, signing, "root-over-provider-limit");
            PreparedSemanticSigningRequest prepared = service.prepare(request, FAIRNESS);
            provider.inputs = new zeroecho.pki.spi.crypto.SigningInputCapabilities(1, java.util.Map.of());
            assertThrows(IllegalArgumentException.class, () -> service.accept(prepared));
            assertEquals(0, accepts.get());
            assertEquals(0, provider.calls.get());
            assertTrue(store.getSignWorkflow(request.operationId()).isEmpty());
            assertTrue(store.getDomainContinuation(DomainContinuationStore.Kind.CA,
                    "root-over-provider-limit").isEmpty());
            service.discard(prepared);
            assertThrows(java.io.IOException.class, () -> PkiTestRuntime.readContent(store, request.content()));
        }
    }

    @Test
    void preparationAdoptsStagedContentAndUsesOneAtomicAcceptance(@TempDir Path root)
            throws Exception {
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider()) {
            AtomicInteger accepts = new AtomicInteger();
            DefaultSigningService signing = signing(store, provider, (command, custody) -> {
                accepts.incrementAndGet();
                custody.run();
                return store.acceptSign(command);
            });
            DefaultSemanticSigningService service = semantic(store, signing);
            DomainSigningRequest request = request(store, signing, "root-one");
            PreparedSemanticSigningRequest prepared = service.prepare(request, FAIRNESS);
            assertTrue(store.getSignWorkflow(request.operationId()).isEmpty());
            assertEquals(0, accepts.get());
            assertEquals(0, provider.calls.get());
            assertEquals("PreparedSemanticSigningRequest[redacted]", prepared.toString());
            assertEquals(SigningAcceptanceDisposition.ACCEPTED, service.accept(prepared).disposition());
            assertEquals(1, accepts.get());
            SignWorkflowStore.Workflow workflow = store.getSignWorkflow(request.operationId()).orElseThrow();
            assertEquals(request.content(), workflow.envelope().candidate());
            assertEquals(prepared.receipt().encodedCommitment(), workflow.fingerprint());
            assertEquals(request.operationId(), store.getDomainContinuation(
                    DomainContinuationStore.Kind.CA, "root-one").orElseThrow().operationId());
            assertEquals(SigningAcceptanceResolution.MATCHED, service.resolve(prepared.receipt()));
            assertEquals(service.find(request.operationId()),
                    service.findByCorrelation(SemanticSigningKind.CA, "root-one"));
            assertThrows(IllegalStateException.class, () -> service.accept(prepared));
            assertThrows(IllegalStateException.class, () -> service.discard(prepared));
        }
    }

    @Test
    void scopeSurvivesReopenAndNeverUsesSchedulingAuthority(@TempDir Path root) throws Exception {
        PkiId id;
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider()) {
            DefaultSigningService signing = signing(store, provider);
            DefaultSemanticSigningService service = semantic(store, signing);
            DomainSigningRequest request = request(store, signing, "root-reopen");
            id = request.operationId();
            service.accept(service.prepare(request, FAIRNESS));
        }
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider()) {
            DefaultSemanticSigningService service = semantic(
                    store, signing(store, provider));
            SemanticSigningOperation operation = service.find(id).orElseThrow();
            assertEquals(ACCESS, operation.scope().accessContext());
            assertEquals(KEY, operation.scope().keyRef());
            assertEquals("CREATE_ROOT", operation.scope().operation());
            assertEquals(Optional.of("profile"), operation.scope().profileId());
            assertTrue(operation.scope().authorityId().isEmpty());
            assertEquals(SemanticSigningState.SIGNING, operation.state());
        }
    }

    @Test
    void signingSuccessIsNotSemanticCompletion(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider()) {
            DefaultSigningService signing = signing(store, provider);
            DefaultSemanticSigningService service = semantic(store, signing);
            DomainSigningRequest request = request(store, signing, "root-terminal");
            service.accept(service.prepare(request, FAIRNESS));
            SignWorkflowStore.Workflow claimed = store.claimSignStep(request.operationId(), 0L,
                    Duration.ofSeconds(10)).orElseThrow();
            store.transitionSign(request.operationId(), claimed.revision(), claimed.fence(),
                    SignWorkflowStore.State.SUCCEEDED, Optional.of("SIGNED"),
                    Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 7 })), Optional.of(NOW))
                    .orElseThrow();
            SemanticSigningOperation signed = service.find(request.operationId()).orElseThrow();
            assertEquals(SigningOperationState.SUCCEEDED, signed.signingState());
            assertEquals(SemanticSigningState.SIGNING, signed.state());
            assertTrue(signed.result().isEmpty());
            assertTrue(signed.completedCredentialId().isEmpty());
            DomainContinuationStore.Record publishing = store.transitionDomainContinuation(
                    request.operationId(), 0L, DomainContinuationStore.State.PUBLISHING,
                    Optional.empty(), Optional.empty()).orElseThrow();
            assertEquals(SemanticSigningState.PUBLISHING, service.find(request.operationId()).orElseThrow().state());
            EncodedObject domainResult = new EncodedObject(Encoding.DER, new byte[] { 1, 2 });
            store.transitionDomainContinuation(request.operationId(), publishing.revision(),
                    DomainContinuationStore.State.COMPLETED, Optional.of(domainResult),
                    Optional.of("COMPLETED")).orElseThrow();
            SemanticSigningOperation completed = service.find(request.operationId()).orElseThrow();
            assertEquals(SemanticSigningState.COMPLETED, completed.state());
            assertEquals(domainResult.encoding(), completed.result().orElseThrow().encoding());
            assertArrayEquals(domainResult.bytes(), completed.result().orElseThrow().bytes());
            assertEquals(Optional.of(new PkiId("x509:" + zeroecho.pki.testkit.SemanticIssuanceFixture.digest(
                    domainResult.bytes()))), completed.completedCredentialId());
        }
    }

    @Test
    void foreignCarrierAndInvalidBindingCannotTransferCustody(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider()) {
            DefaultSigningService signing = signing(store, provider);
            DefaultSemanticSigningService service = semantic(store, signing);
            DefaultSemanticSigningService foreign = semantic(
                    store, signing(store, provider));
            DomainSigningRequest request = request(store, signing, "root-discard");
            PreparedSemanticSigningRequest prepared = service.prepare(request, FAIRNESS);
            assertThrows(IllegalArgumentException.class, () -> foreign.accept(prepared));
            service.discard(prepared);
            assertThrows(IllegalStateException.class, () -> service.discard(prepared));
            assertThrows(RuntimeException.class, () -> service.prepare(request, FAIRNESS));
            DomainSigningRequest valid = request(store, signing, "root-invalid");
            DomainSigningRequest wrongKey = new DomainSigningRequest(valid.operationId(), ACCESS,
                    new KeyRef("other-key"), valid.algorithmId(), valid.signatureEncoding(),
                    valid.content(), TTL, valid.domainTemplate(), valid.proofStep());
            assertThrows(IllegalArgumentException.class, () -> service.prepare(wrongKey, FAIRNESS));
            assertTrue(store.getSignWorkflow(valid.operationId()).isEmpty());
            service.discard(service.prepare(valid, FAIRNESS));
        }
    }

    @Test
    void capacityRejectionCleansUpWithoutRetainingCustody(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 1, CLOCK);
                TestProvider provider = new TestProvider()) {
            DefaultSigningService signing = signing(store, provider);
            DefaultSemanticSigningService service = semantic(store, signing);
            service.accept(service.prepare(request(store, signing, "root-filled"), FAIRNESS));
            DomainSigningRequest rejected = request(store, signing, "root-rejected");
            PreparedSemanticSigningRequest prepared = service.prepare(rejected, FAIRNESS);
            assertEquals(SigningAcceptanceDisposition.CAPACITY_REJECTED, service.accept(prepared).disposition());
            assertThrows(RuntimeException.class, () -> service.prepare(rejected, FAIRNESS));
            assertThrows(IllegalStateException.class, () -> service.discard(prepared));
        }
    }

    @Test
    void uncertainCommitPreservesSingleUseAndAuthoritativeResolution(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider()) {
            DefaultSigningService signing = signing(store, provider, (command, custody) -> {
                custody.run();
                store.acceptSign(command);
                throw new IllegalStateException("controlled uncertain acknowledgement");
            });
            DefaultSemanticSigningService service = semantic(store, signing);
            PreparedSemanticSigningRequest prepared = service.prepare(
                    request(store, signing, "root-uncertain"), FAIRNESS);
            assertThrows(IllegalStateException.class, () -> service.accept(prepared));
            assertEquals(SigningAcceptanceResolution.MATCHED, service.resolve(prepared.receipt()));
            assertTrue(service.find(prepared.receipt().operationId()).isPresent());
            assertThrows(IllegalStateException.class, () -> service.discard(prepared));
        }
    }

    @Test
    void rawSigningIdentifiersAndCorruptedOuterScopesAreNotExposed(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider()) {
            DefaultSigningService signing = signing(store, provider);
            DomainSigningRequest request = request(store, signing, "root-corrupt");
            SignWorkflowStore.AcceptanceCommand raw = new SignWorkflowStore.AcceptanceCommand(
                    request.operationId(), signing.newSubmissionId().namespace(), provider.configurationCommitment(),
                    ACCESS, KEY, FAIRNESS, zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(), Encoding.BINARY, NOW, NOW.plus(TTL),
                    request.content(), Optional.empty(), SignWorkflowStore.Mode.NORMAL, java.util.Optional.empty());
            store.acceptSign(raw);
            DefaultSemanticSigningService service = semantic(store, signing);
            assertTrue(service.find(request.operationId()).isEmpty());
            assertTrue(service.cancel(request.operationId()).isEmpty());
            assertEquals(SignWorkflowStore.State.INTENT,
                    store.getSignWorkflow(request.operationId()).orElseThrow().state());
            assertThrows(IllegalArgumentException.class, () -> service.resolve(
                    SigningAcceptanceReceipt.parse(request.operationId(), raw.commitment().encoded())));

            DomainSigningRequest semantic = request(store, signing, "root-semantic");
            service.accept(service.prepare(semantic, FAIRNESS));
            PkiStore corrupt = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                    new Class<?>[] { PkiStore.class }, (proxy, method, args) -> {
                        try {
                            Object result = method.invoke(store, args);
                            if (method.getName().equals("getDomainContinuation") && args[0] instanceof PkiId) {
                                DomainContinuationStore.Record record = (DomainContinuationStore.Record)
                                        ((Optional<?>) result).orElseThrow();
                                return Optional.of(new DomainContinuationStore.Record(record.operationId(), record.version(),
                                        record.kind(), Optional.of("wrong-correlation"), record.state(), record.revision(),
                                        record.createdAt(), record.deadline(), record.command(), record.commandCommitment(),
                                        record.signingContent(), record.result(), record.detailCode()));
                            }
                            return result;
                        } catch (InvocationTargetException failure) {
                            throw failure.getCause();
                        }
                    });
            DefaultSemanticSigningService corruptService = semantic(
                    corrupt, signing(corrupt, provider));
            assertThrows(IllegalStateException.class, () -> corruptService.find(semantic.operationId()));
        }
    }

    @Test
    void scopeComesFromEachCanonicalDomainAndCancellationDoesNotCompleteOuter(@TempDir Path root)
            throws Exception {
        String digest = "1".repeat(64);
        String attributes = DomainAttributeEncoding.encode(new SimpleAttributeSet(List.of()));
        List<DomainContinuationTemplate> templates = List.of(
                DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.ISSUANCE,
                        "issuance-scope", "ISSUE_END_ENTITY", "authority", "issuer", "path", digest,
                        "profile", "1", digest, "CN=Subject", NOW.toString(), NOW.plusSeconds(30).toString(),
                        "1", KEY.value(), "request", digest, digest, "", "", "", "", "", "", "", attributes),
                DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.STATUS,
                        "status-scope", "GENERATE_STATUS", "authority", "CRL", "format:test", NOW.toString(),
                        NOW.plusSeconds(30).toString(), KEY.value(), "entries", digest, attributes));
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider()) {
            DefaultSigningService signing = signing(store, provider);
            DefaultSemanticSigningService service = semantic(store, signing);
            for (DomainContinuationTemplate template : templates) {
                DomainSigningRequest request;
                if (template.kind() == DomainContinuationStore.Kind.ISSUANCE) {
                    request = issuance(store, signing, correlatedInput(), -1, "");
                } else {
                    DurableContentReference content = PkiTestRuntime.operationReference(store.stagedContent(),
                            Encoding.BINARY,
                            new byte[] { 1, 2, 3 });
                    request = new DomainSigningRequest(signing.newSubmissionId().id(),
                            ACCESS, KEY, zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(),
                            Encoding.BINARY, content, TTL, template, java.util.Optional.empty());
                }
                service.accept(service.prepare(request, FAIRNESS));
                SemanticSigningOperation operation = service.find(request.operationId()).orElseThrow();
                assertEquals(Optional.of(new PkiId("authority")), operation.scope().authorityId());
                assertEquals(KEY, operation.scope().keyRef());
                assertEquals(Optional.empty(), operation.scope().subjectAuthorityId());
                assertEquals(template.kind() == DomainContinuationStore.Kind.STATUS
                        ? Optional.empty() : Optional.of("profile"), operation.scope().profileId());
                SemanticSigningOperation cancelled = service.cancel(request.operationId()).orElseThrow();
                assertEquals(SigningOperationState.CANCELLED, cancelled.signingState());
                assertEquals(SemanticSigningState.SIGNING, cancelled.state());
                assertTrue(cancelled.result().isEmpty());
            }
            assertThrows(IllegalArgumentException.class,
                    () -> service.findByCorrelation(SemanticSigningKind.CA, "x".repeat(129)));
        }
        zeroecho.pki.testkit.IntermediateCreationFixture fixture = new zeroecho.pki.testkit.IntermediateCreationFixture();
        try (FilesystemPkiStore store = new FilesystemPkiStore(root.resolve("intermediate"),
                zeroecho.pki.impl.fs.FsPkiStoreOptions.defaults(), zeroecho.pki.testkit.IntermediateCreationFixture.CLOCK)) {
            fixture.initialize(store, 1);
            DefaultSigningService signing = new DefaultSigningService(store, fixture.provider,
                    fixture.signing.resolveIdentity(zeroecho.pki.testkit.IntermediateCreationFixture.ALGORITHM),
                    zeroecho.pki.testkit.IntermediateCreationFixture.TTL, new SecureRandom(), () -> { },
                    (command, custody) -> { custody.run(); return store.acceptSign(command); }, () -> { },
                    (id, cancellation) -> { throw new UnsupportedOperationException("No fixture wait"); });
            DefaultSemanticSigningService service = semantic(store, signing);
            DomainSigningRequest request = fixture.preparer(store).prepare(zeroecho.pki.testkit.IntermediateCreationFixture.ACCESS,
                    fixture.command("CN=Scope Child"), fixture.submission(store), zeroecho.pki.testkit.IntermediateCreationFixture.TTL,
                    CancellationSignal.NONE);
            PkiId subject = new PkiId(DomainCommandEncoding.decode(request.domainTemplate().command()).field(2));
            service.accept(service.prepare(request, zeroecho.pki.testkit.IntermediateCreationFixture.CA));
            SemanticSigningOperation operation = service.find(request.operationId()).orElseThrow();
            assertEquals("CREATE_INTERMEDIATE", operation.scope().operation());
            assertEquals(Optional.of(zeroecho.pki.testkit.IntermediateCreationFixture.CA), operation.scope().authorityId());
            assertEquals(zeroecho.pki.testkit.IntermediateCreationFixture.PARENT_KEY, operation.scope().keyRef());
            assertEquals(Optional.of(subject), operation.scope().subjectAuthorityId());
            assertEquals(Optional.of("intermediate-ca"), operation.scope().profileId());
            assertEquals(zeroecho.pki.testkit.IntermediateCreationFixture.ACCESS, operation.scope().accessContext());
            assertTrue(store.getSignWorkflow(request.proofStep().orElseThrow().operationId()).isEmpty());
            SemanticSigningOperation cancelled = service.cancel(request.operationId()).orElseThrow();
            assertEquals(SigningOperationState.CANCELLED, cancelled.signingState());
            assertEquals(SemanticSigningState.SIGNING, cancelled.state());
            assertTrue(cancelled.result().isEmpty());
            assertEquals(DomainContinuationStore.State.SIGNING,
                    store.getDomainContinuation(request.operationId()).orElseThrow().state());
            assertEquals(0, fixture.provider.dispatches);
        }
    }

    static DefaultSemanticSigningService semantic(PkiStore store, DefaultSigningService signing) {
        return new DefaultSemanticSigningService(store, signing, PkiTestRuntime.endEntityPreparation(store, CLOCK));
    }

    @Test
    void exactIssuanceReplayUsesOnlyPointReadsAndSurvivesReopenThenPurge(@TempDir Path root) throws Exception {
        CorrelatedEndEntityIssuanceRequest input = correlatedInput();
        PkiId operationId;
        RetainedIssuanceBinding binding;
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider()) {
            DefaultSigningService signing = signing(store, provider);
            DefaultSemanticSigningService service = semantic(store, signing);
            binding = service.issuanceBinding(input);
            DomainSigningRequest prepared = issuance(store, signing, input, -1, "");
            operationId = prepared.operationId();
            service.accept(service.prepare(prepared, FAIRNESS));
            PkiStore points = pointReadsOnly(store);
            assertEquals(service.find(operationId), semantic(points, signing(points, provider)).findIssuance(input));
            assertEquals(service.findIssuance(input), semantic(points, signing(points, provider)).findIssuance(binding));
            CorrelatedIssuancePreparation replay = semantic(points, signing(points, provider))
                    .prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), CancellationSignal.NONE);
            assertEquals(service.find(operationId).orElseThrow(), ((CorrelatedIssuancePreparation.Existing) replay).operation());
            assertEquals(0, provider.calls.get());
        }
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider()) {
            DefaultSemanticSigningService service = semantic(store, signing(store, provider));
            assertEquals(service.find(operationId), service.findIssuance(input));
            assertEquals(service.find(operationId), service.findIssuance(binding));
            service.cancel(operationId);
            CorrelatedIssuancePreparation cancelledReplay = service.prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), CancellationSignal.NONE);
            assertEquals(SigningOperationState.CANCELLED,
                    ((CorrelatedIssuancePreparation.Existing) cancelledReplay).operation().signingState());
            store.transitionDomainContinuation(operationId, 0L, DomainContinuationStore.State.FAILED,
                    Optional.empty(), Optional.of("CANCELLED")).orElseThrow();
            SignWorkflowStore.Workflow cancelled = store.getSignWorkflow(operationId).orElseThrow();
            store.retireSign(operationId, cancelled.revision(), cancelled.fence()).orElseThrow();
            assertTrue(service.findIssuance(input).isPresent());
            assertTrue(service.findIssuance(binding).isPresent());
            PkiStore points = pointReadsOnly(store);
            CorrelatedIssuancePreparation replay = semantic(points, signing(points, provider))
                    .prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), CancellationSignal.NONE);
            assertEquals(SemanticSigningState.FAILED, ((CorrelatedIssuancePreparation.Existing) replay).operation().state());
        }
        Clock afterRetention = Clock.fixed(NOW.plus(Duration.ofDays(91)), ZoneOffset.UTC);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, afterRetention);
                TestProvider provider = new TestProvider()) {
            assertEquals(1, store.purgeExpiredSignRecords());
            PkiStore points = pointReadsOnly(store);
            assertTrue(semantic(points, signing(points, provider)).findIssuance(input).isEmpty());
            assertTrue(semantic(points, signing(points, provider)).findIssuance(binding).isEmpty());
        }
    }

    @Test
    void changedOrMalformedCsrConflictsWithoutParsingOrProofVerification(@TempDir Path root) throws Exception {
        CorrelatedEndEntityIssuanceRequest input = correlatedInput();
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider()) {
            DefaultSigningService signing = signing(store, provider);
            DefaultSemanticSigningService service = semantic(store, signing);
            service.accept(service.prepare(issuance(store, signing, input, -1, ""), FAIRNESS));
            for (byte[] changed : List.of(new byte[] { 9 }, new byte[] { 0x30, (byte) 0xff },
                    new byte[] { 1, 2, 3, 0 })) {
                CorrelatedEndEntityIssuanceRequest replay = new CorrelatedEndEntityIssuanceRequest(
                        new EndEntityIssuanceRequest(input.request().issuerCaId(), changed,
                                input.request().profileId(), Optional.empty()), input.intent());
                PkiException conflict = assertThrows(PkiException.class, () -> service.findIssuance(replay));
                assertThrows(PkiException.class, () -> service.findIssuance(service.issuanceBinding(replay)));
                assertTrue(conflict.getMessage().contains("ISSUANCE_CONFLICT"));
                assertThrows(PkiException.class,
                        () -> service.prepareCorrelatedEndEntity(ACCESS, replay, Optional.empty(), CancellationSignal.NONE));
            }
            assertEquals(0, provider.calls.get());
        }
    }

    @Test
    void correlatedPreparationReplaysFailedAndExpiredWorkWithoutNewPreparation(@TempDir Path root) throws Exception {
        CorrelatedEndEntityIssuanceRequest input = correlatedInput();
        PkiId expires;
        try (FilesystemPkiStore store = open(root.resolve("failed")); TestProvider provider = new TestProvider()) {
            DefaultSigningService signing = signing(store, provider);
            DefaultSemanticSigningService service = semantic(store, signing);
            DomainSigningRequest prepared = issuance(store, signing, input, -1, "");
            service.accept(service.prepare(prepared, FAIRNESS));
            SignWorkflowStore.Workflow claimed = store.claimSignStep(prepared.operationId(), 0L,
                    Duration.ofSeconds(10)).orElseThrow();
            store.transitionSign(prepared.operationId(), claimed.revision(), claimed.fence(),
                    SignWorkflowStore.State.FAILED, Optional.of("DENIED"), Optional.empty(), Optional.of(NOW)).orElseThrow();
            store.transitionDomainContinuation(prepared.operationId(), 0L, DomainContinuationStore.State.FAILED,
                    Optional.empty(), Optional.of("DENIED")).orElseThrow();
            PkiStore points = pointReadsOnly(store);
            CorrelatedIssuancePreparation replay = semantic(points, signing(points, provider))
                    .prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), CancellationSignal.NONE);
            assertEquals(SigningOperationState.FAILED,
                    ((CorrelatedIssuancePreparation.Existing) replay).operation().signingState());
        }
        try (FilesystemPkiStore store = open(root.resolve("expired")); TestProvider provider = new TestProvider()) {
            DefaultSigningService signing = signing(store, provider);
            DefaultSemanticSigningService service = semantic(store, signing);
            DomainSigningRequest prepared = issuance(store, signing, input, -1, "");
            expires = prepared.operationId();
            service.accept(service.prepare(prepared, FAIRNESS));
        }
        Clock afterDeadline = Clock.fixed(NOW.plus(TTL).plusSeconds(1), ZoneOffset.UTC);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root.resolve("expired"), 4, afterDeadline);
                TestProvider provider = new TestProvider()) {
            assertEquals(SignWorkflowStore.State.EXPIRED, store.getSignWorkflow(expires).orElseThrow().state());
            PkiStore points = pointReadsOnly(store);
            CorrelatedIssuancePreparation replay = semantic(points, signing(points, provider))
                    .prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), CancellationSignal.NONE);
            assertEquals(SemanticSigningState.EXPIRED, ((CorrelatedIssuancePreparation.Existing) replay).operation().state());
            assertEquals(expires, ((CorrelatedIssuancePreparation.Existing) replay).operation().submissionId().id());
        }
    }

    @Test
    void occupiedCorrelationVerifiesEveryFrozenCoordinateAndExcludesNoIntent(@TempDir Path root) throws Exception {
        CorrelatedEndEntityIssuanceRequest input = correlatedInput();
        int[] fields = { 0, 1, 2, 3, 4, 5, 6, 15, 16 };
        for (int field : fields) {
            try (FilesystemPkiStore store = open(root.resolve("field-" + field));
                    TestProvider provider = new TestProvider()) {
                DefaultSigningService signing = signing(store, provider);
                DefaultSemanticSigningService service = semantic(store, signing);
                String different = field == 3 || field == 6 || field == 16 ? "2".repeat(64)
                        : field == 5 ? "2" : "different";
                DomainSigningRequest changed = issuance(store, signing, input, field, different);
                if (field <= 3) {
                    assertThrows(IllegalArgumentException.class,
                            () -> service.accept(service.prepare(changed, FAIRNESS)), "field " + field);
                    assertTrue(service.findIssuance(input).isEmpty());
                } else {
                    service.accept(service.prepare(changed, FAIRNESS));
                    assertThrows(PkiException.class, () -> service.findIssuance(input), "field " + field);
                }
            }
        }
        try (FilesystemPkiStore store = open(root.resolve("no-intent")); TestProvider provider = new TestProvider()) {
            DefaultSigningService signing = signing(store, provider);
            DefaultSemanticSigningService service = semantic(store, signing);
            service.accept(service.prepare(issuance(store, signing, input, 15, ""), FAIRNESS));
            assertThrows(PkiException.class, () -> service.findIssuance(input));
        }
    }

    @Test
    void wrongKindAndRawWorkAreNotReturnedAsIssuance(@TempDir Path root) throws Exception {
        CorrelatedEndEntityIssuanceRequest input = correlatedInput();
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider()) {
            DefaultSigningService signing = signing(store, provider);
            DefaultSemanticSigningService service = semantic(store, signing);
            DomainSigningRequest rootRequest = request(store, signing, CorrelatedIssuanceIdentity.derive(input).correlationId());
            service.accept(service.prepare(rootRequest, FAIRNESS));
            assertTrue(service.findIssuance(input).isEmpty());
            PkiStore wrongKind = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                    new Class<?>[] { PkiStore.class }, (proxy, method, args) -> {
                        if (method.getName().equals("getDomainContinuation") && args.length == 2) {
                            return store.getDomainContinuation(rootRequest.operationId());
                        }
                        try {
                            return method.invoke(store, args);
                        } catch (InvocationTargetException failure) {
                            throw failure.getCause();
                        }
                    });
            assertThrows(PkiException.class,
                    () -> semantic(wrongKind, signing(wrongKind, provider)).findIssuance(input));
            DomainSigningRequest raw = issuance(store, signing, input, -1, "");
            store.acceptSign(new SignWorkflowStore.AcceptanceCommand(raw.operationId(),
                    signing.newSubmissionId().namespace(), provider.configurationCommitment(), ACCESS, KEY, FAIRNESS,
                    raw.algorithmId(), Encoding.BINARY, NOW, NOW.plus(TTL), raw.content(), Optional.empty(),
                    SignWorkflowStore.Mode.NORMAL, java.util.Optional.empty()));
            assertTrue(service.findIssuance(input).isEmpty());
        }
    }

    @Test
    void malformedPersistedIssuanceIdentityIsRejected(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider()) {
            DefaultSigningService signing = signing(store, provider);
            DomainSigningRequest valid = issuance(store, signing, correlatedInput(), -1, "");
            DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(valid.domainTemplate().command());
            for (String invalid : List.of("UPPERCASE", "x".repeat(129), "", "white space")) {
                List<String> fields = new ArrayList<>(command.fields());
                fields.set(15, invalid);
                DomainContinuationTemplate malformed = DomainCommandEncoding.correlatedTemplate(
                        DomainContinuationStore.Kind.ISSUANCE, valid.domainTemplate().correlationId().orElseThrow(),
                        command.operation(), fields.toArray(String[]::new));
                assertThrows(IllegalStateException.class, () -> DomainContinuationValidation.validate(malformed));
            }
            List<String> fields = new ArrayList<>(command.fields());
            fields.set(16, "");
            DomainContinuationTemplate incomplete = DomainCommandEncoding.template(DomainContinuationStore.Kind.ISSUANCE,
                    command.operation(), fields.toArray(String[]::new));
            assertThrows(IllegalStateException.class, () -> DomainContinuationValidation.validate(incomplete));
            store.stagedContent().retireUnownedContent(valid.content());
        }
    }

    @Test
    void bindingDerivationIsPureAndLookupChecksEveryFrozenCoordinate(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider()) {
            AtomicInteger storeReads = new AtomicInteger();
            PkiStore observed = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                    new Class<?>[] { PkiStore.class }, (proxy, method, args) -> {
                        storeReads.incrementAndGet();
                        try { return method.invoke(store, args); }
                        catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
            DefaultSigningService signing = signing(observed, provider, (command, custody) -> {
                throw new AssertionError("Lookup must not admit signing");
            });
            DefaultSemanticSigningService service = semantic(observed, signing);
            int initialReads = storeReads.get();
            CorrelatedEndEntityIssuanceRequest input = correlatedInput(); // Deliberately not a parseable CSR.
            RetainedIssuanceBinding binding = service.issuanceBinding(input);
            assertEquals(initialReads, storeReads.get());
            assertEquals(input.request().issuerCaId(), binding.authorityId());
            assertEquals(input.intent().issuanceId(), binding.issuanceId());
            assertEquals(input.intent().expectedProfile(), binding.expectedProfile());
            assertEquals(input.intent().expectedIssuerId(), binding.expectedIssuerId());
            assertEquals(input.intent().expectedChainPathId(), binding.expectedChainPathId());
            assertEquals(input.intent().expectedChainPathCommitment(), binding.expectedChainPathCommitment());
            assertEquals(CorrelatedIssuanceIdentity.derive(input).effectiveCommitment(), binding.effectiveCommitment());
            DefaultSigningService accepting = signing(store, provider);
            DefaultSemanticSigningService acceptingService = semantic(store, accepting);
            assertEquals(SigningAcceptanceDisposition.ACCEPTED, acceptingService.accept(acceptingService.prepare(
                    issuance(store, accepting, input, -1, ""), FAIRNESS)).disposition());
            assertEquals(service.findIssuance(input), service.findIssuance(binding));
            assertTrue(service.findIssuance(binding).orElseThrow().completedCredentialId().isEmpty());
            // Changing the current profile cannot change this accepted, frozen binding.
            zeroecho.pki.api.profile.CertificateProfileDefinition profile =
                    zeroecho.pki.testkit.RootCreationFixture.definition("profile",
                            zeroecho.pki.api.profile.CertificateProfileKind.ROOT_CA, Duration.ofDays(30),
                            zeroecho.pki.api.profile.X509AlgorithmBindingPolicy.standardOnly());
            zeroecho.pki.testkit.RootCreationFixture.install(store, profile);
            zeroecho.pki.testkit.RootCreationFixture.install(store,
                    new zeroecho.pki.api.profile.CertificateProfileDefinition(profile.certificateType(),
                            profile.profileId(), 2, profile.formatId(), profile.displayName(), Duration.ofDays(60),
                            profile.subjectPolicy(), profile.certificatePolicy(), profile.algorithmBindingPolicy()));
            assertEquals(service.findIssuance(input), service.findIssuance(binding));
            for (int field = 0; field < 9; field++) {
                RetainedIssuanceBinding changed = new RetainedIssuanceBinding(
                        field == 0 ? new PkiId("other-authority") : binding.authorityId(),
                        field == 1 ? "other-order" : binding.issuanceId(),
                        new CertificateProfileRef(field == 2 ? "other-profile" : binding.expectedProfile().profileId(),
                                field == 3 ? 2 : binding.expectedProfile().profileVersion(),
                                field == 4 ? new byte[32] : binding.expectedProfile().canonicalSha256()),
                        field == 5 ? new PkiId("other-issuer") : binding.expectedIssuerId(),
                        field == 6 ? new PkiId("other-path") : binding.expectedChainPathId(),
                        field == 7 ? "2".repeat(64) : binding.expectedChainPathCommitment(),
                        field == 8 ? "2".repeat(64) : binding.effectiveCommitment());
                if (field < 2) {
                    // A different stable key is absent, never a fallback to another correlation.
                    assertTrue(service.findIssuance(changed).isEmpty());
                } else {
                    PkiException failure = assertThrows(PkiException.class, () -> service.findIssuance(changed));
                    assertEquals("Issuance correlation conflict: code=ISSUANCE_CONFLICT", failure.getMessage());
                }
            }
            assertEquals(0, provider.calls.get());
            assertEquals(1, store.listSignWorkflows().size());
        }
    }

    @Test
    void bindingLookupRejectsInconsistentOuterSnapshot(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider()) {
            DefaultSigningService signing = signing(store, provider);
            DefaultSemanticSigningService service = semantic(store, signing);
            CorrelatedEndEntityIssuanceRequest input = correlatedInput();
            DomainSigningRequest request = issuance(store, signing, input, -1, "");
            service.accept(service.prepare(request, FAIRNESS));
            RetainedIssuanceBinding binding = service.issuanceBinding(input);
            DomainContinuationStore.Record original = store.getDomainContinuation(request.operationId()).orElseThrow();
            DomainContinuationStore.Record inconsistent = new DomainContinuationStore.Record(original.operationId(),
                    original.version(), original.kind(), original.correlationId(), original.state(), original.revision(),
                    original.createdAt().plusSeconds(1), original.deadline(), original.command(),
                    original.commandCommitment(), original.signingContent(), original.result(), original.detailCode());
            PkiStore substituted = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                    new Class<?>[] { PkiStore.class }, (proxy, method, args) -> {
                        if (method.getName().equals("getDomainContinuation")) return Optional.of(inconsistent);
                        try { return method.invoke(store, args); }
                        catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
            DefaultSemanticSigningService checking = semantic(substituted, signing(substituted, provider));
            assertThrows(IllegalStateException.class, () -> checking.findIssuance(binding));
            assertThrows(IllegalStateException.class, () -> checking.findIssuance(input));
            assertEquals(0, provider.calls.get());
        }
    }

    static CorrelatedEndEntityIssuanceRequest correlatedInput() {
        return CorrelatedIssuanceIdentityTest.request("authority", "order", "1".repeat(64), "profile", 1,
                "1".repeat(64), zeroecho.pki.testkit.SemanticIssuanceFixture.issuerId(1).value(),
                zeroecho.pki.testkit.SemanticIssuanceFixture.path(1).pathId().value(),
                zeroecho.pki.testkit.SemanticIssuanceFixture.path(1).pathCommitment(), new byte[] { 1, 2, 3 }, Optional.empty());
    }

    static DomainSigningRequest issuance(PkiStore store, DefaultSigningService signing,
            CorrelatedEndEntityIssuanceRequest input, int changedField, String changedValue) throws Exception {
        CorrelatedIssuanceIdentity identity = CorrelatedIssuanceIdentity.derive(input);
        String digest = "1".repeat(64);
        zeroecho.pki.api.credential.Credential issuer = zeroecho.pki.testkit.SemanticIssuanceFixture.issuer(store, 1);
        PkiId operation = signing.newSubmissionId().id();
        java.math.BigInteger serial = new java.math.BigInteger(
                zeroecho.pki.testkit.SemanticIssuanceFixture.digest(operation.value().getBytes(java.nio.charset.StandardCharsets.UTF_8))
                        .substring(0, 38), 16).add(java.math.BigInteger.valueOf(100));
        String[] fields = { "authority", zeroecho.pki.testkit.SemanticIssuanceFixture.issuerId(1).value(),
                zeroecho.pki.testkit.SemanticIssuanceFixture.path(1).pathId().value(),
                zeroecho.pki.testkit.SemanticIssuanceFixture.path(1).pathCommitment(), "profile", "1", digest,
                "CN=Subject", NOW.toString(), NOW.plusSeconds(30).toString(), serial.toString(), KEY.value(), issuer.content().contentId(),
                issuer.content().sha256(), zeroecho.pki.testkit.SemanticIssuanceFixture.publicKeyDigest(),
                input.intent().issuanceId(), identity.effectiveCommitment(), "", "", "", "", "",
                DomainAttributeEncoding.encode(new SimpleAttributeSet(List.of())) };
        if (changedField >= 0) {
            fields[changedField] = changedValue;
            if (changedField == 15 && changedValue.isEmpty()) fields[16] = "";
        }
        DomainContinuationTemplate template = DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.ISSUANCE,
                identity.correlationId(), "ISSUE_END_ENTITY", fields);
        DurableContentReference content = PkiTestRuntime.operationReference(store.stagedContent(),
                Encoding.DER, zeroecho.pki.testkit.SemanticIssuanceFixture.certificate("CN=Subject", serial,
                        NOW, NOW.plusSeconds(30)).toASN1Structure().getTBSCertificate().getEncoded());
        return new DomainSigningRequest(operation, ACCESS, KEY,
                zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(), Encoding.BINARY,
                content, TTL, template, java.util.Optional.empty());
    }

    private static PkiStore pointReadsOnly(PkiStore store) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, args) -> {
                    assertTrue(Set.of("getDomainContinuation", "getSignWorkflow", "signingNamespace", "signingNow",
                            "signingHorizon", "signingPermittedSkew")
                            .contains(method.getName()), "Unexpected store access: " + method.getName());
                    try {
                        return method.invoke(store, args);
                    } catch (InvocationTargetException failure) {
                        throw failure.getCause();
                    }
                });
    }

    static FilesystemPkiStore open(Path root) {
        return FilesystemPkiStoreTestAccess.open(root, 4, CLOCK);
    }

    static DefaultSigningService signing(PkiStore store, SigningProvider provider) {
        return signing(store, provider, (command, custody) -> {
            custody.run();
            return store.acceptSign(command);
        });
    }

    static DefaultSigningService signing(PkiStore store, SigningProvider provider,
            DefaultSigningService.AcceptanceOperation acceptance) {
        return new DefaultSigningService(store, provider, zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, TTL, new SecureRandom(),
                () -> { }, acceptance, () -> { },
                (boundedWaitId, boundedWaitCancellation) -> { throw new UnsupportedOperationException("Fixture has no reactor wait"); });
    }

    static DomainSigningRequest request(PkiStore store, DefaultSigningService signing,
            String correlation) throws Exception {
        DomainContinuationTemplate template = DomainCommandEncoding.correlatedTemplate(
                DomainContinuationStore.Kind.CA, correlation, "CREATE_ROOT", "format:test", "CN=Test", "root",
                KEY.value(), "profile", "1", "1".repeat(64), NOW.toString(), NOW.plusSeconds(30).toString(),
                "1", "", "", "", "authority");
        DurableContentReference content = PkiTestRuntime.operationReference(store.stagedContent(),
                Encoding.BINARY, new byte[] { 1, 2, 3 });
        return new DomainSigningRequest(signing.newSubmissionId().id(), ACCESS, KEY, zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(),
                Encoding.BINARY, content, TTL, template, java.util.Optional.empty());
    }

    static final class TestProvider implements SigningProvider {
        private zeroecho.pki.spi.crypto.SigningInputCapabilities inputs =
                new zeroecho.pki.spi.crypto.SigningInputCapabilities(Long.MAX_VALUE, java.util.Map.of());
        @Override public zeroecho.pki.spi.crypto.SigningInputCapabilities inputCapabilities() {
            return inputs;
        }
        final AtomicInteger calls = new AtomicInteger();
        @Override public String id() { return "test-signer"; }
        @Override public ConfigurationCommitment configurationCommitment() {
            return new ConfigurationCommitment(new byte[ConfigurationCommitment.BYTE_LENGTH]);
        }
        @Override public Set<String> supportedAlgorithms() { return Set.of(zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm()); }
        @Override public OperationObservation dispatch(SignRequest request, CallControl control) {
            calls.incrementAndGet();
            throw new UnsupportedOperationException();
        }
        @Override public OperationObservation reconcile(PkiId id, CallControl control) {
            throw new UnsupportedOperationException();
        }
        @Override public OperationObservation cancel(PkiId id, long fence, CancellationReason reason,
                CallControl control) { throw new UnsupportedOperationException(); }
        @Override public void close() { }
    }
}
