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

package zeroecho.pki.impl.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.bouncycastle.asn1.x509.TBSCertificate;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.issuance.EndEntityReissueRequest;
import zeroecho.pki.api.issuance.EndEntityRenewalRequest;
import zeroecho.pki.api.issuance.EndEntityReplacementRequest;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SigningAcceptanceDisposition;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.impl.audit.InMemoryAuditSink;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainAttributeEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.DomainContinuationValidation;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.impl.core.signing.DefaultSemanticSigningService;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.H7ProfileDocuments;
import zeroecho.pki.testkit.PkiTestRuntime;

final class EndEntityLifecycleSigningPreparationTest {
    private static final Instant NOW = Instant.parse("2026-09-20T12:00:00Z");
    private static final AccessContext ACCESS = new AccessContext(new Principal("TEST", "lifecycle-actor"),
            new Purpose("LIFECYCLE"), Optional.empty(), Optional.empty());
    private static byte[] csr;

    @BeforeAll static void keys() throws Exception {
        EndEntityLifecyclePreparationTest.keys();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        csr = EndEntityLifecyclePreparationTest.csr(generator.generateKeyPair());
    }

    @Test void allLifecyclePreparationsFreezeBindingsAndShareSingleStaging(@TempDir Path root) throws Exception {
        for (String operation : List.of("RENEW_END_ENTITY", "REPLACE_END_ENTITY", "REISSUE_END_ENTITY")) {
            try (FilesystemPkiStore store = EndEntityLifecyclePreparationTest.fixture(root.resolve(operation))) {
                Credential leaf = leaf(store);
                AtomicInteger stages = new AtomicInteger();
                AtomicReference<DurableContentReference> candidate = new AtomicReference<>();
                EndEntityIssuancePreparationTest.CountingProvider provider = new EndEntityIssuancePreparationTest.CountingProvider();
                SemanticSigningService service = EndEntityIssuancePreparationTest.semantic(
                        EndEntityIssuancePreparationTest.observePreparation(store, stages, candidate, new AtomicBoolean(), false),
                        provider, () -> { });
                PreparedSemanticSigningRequest first = prepare(service, operation, ACCESS, leaf, CancellationSignal.NONE);
                DurableContentReference firstContent = candidate.get();
                TBSCertificate firstTbs = TBSCertificate.getInstance(PkiTestRuntime.readContent(store, firstContent));
                assertEquals(1, stages.get());
                assertEquals(DurableContentReference.Lifecycle.OPERATION, firstContent.lifecycle());
                assertTrue(store.getSignWorkflow(first.receipt().operationId()).isEmpty());
                assertTrue(store.getDomainContinuation(first.receipt().operationId()).isEmpty());
                assertEquals(0, provider.calls.get());
                PreparedSemanticSigningRequest second = prepare(service, operation, ACCESS, leaf, CancellationSignal.NONE);
                assertEquals(2, stages.get());
                assertNotEquals(first.receipt().operationId(), second.receipt().operationId());
                TBSCertificate secondTbs = TBSCertificate.getInstance(PkiTestRuntime.readContent(store, candidate.get()));
                assertNotEquals(firstTbs.getSerialNumber(), secondTbs.getSerialNumber());

                DefaultProfileService profiles = new DefaultProfileService(store, Clock.fixed(NOW, ZoneOffset.UTC),
                        new InMemoryAuditSink());
                profiles.importProfile(new String(H7ProfileDocuments.noSanOrEkuProfile(), StandardCharsets.UTF_8)
                        .replace("\"profileVersion\":1", "\"profileVersion\":2").getBytes(StandardCharsets.UTF_8));
                profiles.activateProfile("h7-no-san-eku", 2);
                assertEquals(SigningAcceptanceDisposition.ACCEPTED, service.accept(first).disposition());
                SignWorkflowStore.Workflow workflow = store.getSignWorkflow(first.receipt().operationId()).orElseThrow();
                SignWorkflowStore.OuterCommand outer = workflow.envelope().outer().orElseThrow();
                DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(outer.command());
                assertEquals(operation, command.operation());
                command.requireFields(24);
                assertEquals(leaf.credentialId().value(), command.field(23));
                assertEquals(leaf.issuerRef().caId().value(), command.field(0));
                assertEquals(leaf.issuerRef().issuerId().value(), command.field(1));
                assertEquals(leaf.issuerRef().chainPathId().value(), command.field(2));
                assertEquals("h7-no-san-eku", command.field(4));
                assertEquals("1", command.field(5));
                assertEquals("", command.field(15));
                assertEquals("", command.field(16));
                assertEquals(firstTbs.getSerialNumber().getValue().toString(), command.field(10));
                assertEquals("issue." + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                        .digest(first.receipt().operationId().value().getBytes(StandardCharsets.UTF_8))), outer.correlationId());
                AccessContext bound = new AccessContext(ACCESS.principal(), ACCESS.purpose(), Optional.of(leaf.credentialId()),
                        Optional.of(new FormatId("x509")));
                assertEquals(bound, workflow.envelope().accessContext());
                assertEquals(leaf.issuerRef().caId(), workflow.envelope().fairnessAuthorityId());
                assertEquals(bound, service.find(first.receipt().operationId()).orElseThrow().scope().accessContext());
                assertEquals(0, provider.calls.get());
                service.discard(second);
                assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, candidate.get()));
                assertThrows(IllegalStateException.class, () -> service.discard(first));
                assertInvalidSchemas(outer, command);
                assertScopeMismatch(service, workflow, leaf);
            }
        }
    }

    @Test void conflictingSuppliedAccessCoordinatesRejectBeforeStaging(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = EndEntityLifecyclePreparationTest.fixture(root)) {
            Credential leaf = leaf(store);
            AtomicInteger stages = new AtomicInteger();
            EndEntityIssuancePreparationTest.CountingProvider provider = new EndEntityIssuancePreparationTest.CountingProvider();
            SemanticSigningService service = EndEntityIssuancePreparationTest.semantic(
                    EndEntityIssuancePreparationTest.observePreparation(store, stages, new AtomicReference<>(), new AtomicBoolean(), false),
                    provider, () -> { });
            for (String operation : List.of("RENEW_END_ENTITY", "REPLACE_END_ENTITY", "REISSUE_END_ENTITY")) {
                for (AccessContext conflict : List.of(
                        new AccessContext(ACCESS.principal(), ACCESS.purpose(), Optional.of(new PkiId("other")), Optional.empty()),
                        new AccessContext(ACCESS.principal(), ACCESS.purpose(), Optional.empty(), Optional.of(new FormatId("other"))))) {
                    assertThrows(IllegalArgumentException.class, () -> prepare(service, operation, conflict, leaf, CancellationSignal.NONE));
                }
            }
            assertEquals(0, stages.get());
            assertEquals(0, provider.calls.get());
        }
    }

    @Test void lifecycleEvidenceBindsBeforeStagingAndSurvivesAcceptance(@TempDir Path root) throws Exception {
        for (String operation : List.of("RENEW_END_ENTITY", "REPLACE_END_ENTITY", "REISSUE_END_ENTITY")) {
            try (FilesystemPkiStore store = EndEntityLifecyclePreparationTest.fixture(root.resolve(operation))) {
                Credential leaf = leaf(store);
                AtomicInteger stages = new AtomicInteger();
                AtomicReference<DurableContentReference> candidate = new AtomicReference<>();
                SemanticSigningService service = EndEntityIssuancePreparationTest.semantic(
                        EndEntityIssuancePreparationTest.observePreparation(store, stages, candidate, new AtomicBoolean(), false),
                        new EndEntityIssuancePreparationTest.CountingProvider(), () -> { });
                AccessContext access = new AccessContext(new Principal("ACME_ACCOUNT", "lifecycle-account"),
                        ACCESS.purpose(), Optional.empty(), Optional.empty());
                String issuer = leaf.issuerRef().caId().value();
                String profile = "h7-no-san-eku";
                assertThrows(NullPointerException.class,
                        () -> prepare(service, operation, access, leaf, null, CancellationSignal.NONE));
                for (IssuanceExecutionEvidence mismatch : List.of(
                        IssuanceExecutionEvidence.acme("other-actor", "realm", "invoke", issuer, profile),
                        IssuanceExecutionEvidence.administrative("lifecycle-account", "realm", "invoke",
                                IssuanceExecutionEvidence.Authentication.DIRECT_MTLS,
                                IssuanceExecutionEvidence.AuthorizationPath.APPROVAL, "0".repeat(64), issuer, profile),
                        IssuanceExecutionEvidence.acme("lifecycle-account", "realm", "invoke", "other-issuer", profile),
                        IssuanceExecutionEvidence.acme("lifecycle-account", "realm", "invoke", issuer, "other-profile"))) {
                    assertThrows(IllegalArgumentException.class,
                            () -> prepare(service, operation, access, leaf, Optional.of(mismatch), CancellationSignal.NONE));
                }
                assertEquals(0, stages.get());
                IssuanceExecutionEvidence evidence = IssuanceExecutionEvidence.acme(
                        "lifecycle-account", "realm", "invoke", issuer, profile);
                PreparedSemanticSigningRequest prepared = prepare(service, operation, access, leaf,
                        Optional.of(evidence), CancellationSignal.NONE);
                assertEquals(SigningAcceptanceDisposition.ACCEPTED, service.accept(prepared).disposition());
                SignWorkflowStore.Workflow retained = store.getSignWorkflow(prepared.receipt().operationId()).orElseThrow();
                DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(retained.envelope().outer().orElseThrow().command());
                assertEquals(evidence, IssuanceExecutionEvidence.decode(DomainAttributeEncoding.decode(command.field(22))).orElseThrow());
                assertEquals(access.principal(), service.find(prepared.receipt().operationId()).orElseThrow()
                        .scope().accessContext().principal());
                PreparedSemanticSigningRequest discarded = prepare(service, operation, access, leaf,
                        Optional.of(evidence), CancellationSignal.NONE);
                service.discard(discarded);
                assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, candidate.get()));
                assertEquals(2, stages.get());
            }
        }
    }

    @Test void cancellationAndAdoptionFailureCleanEveryLifecycleCandidate(@TempDir Path root) throws Exception {
        for (String operation : List.of("RENEW_END_ENTITY", "REPLACE_END_ENTITY", "REISSUE_END_ENTITY")) {
            try (FilesystemPkiStore store = EndEntityLifecyclePreparationTest.fixture(root.resolve(operation))) {
                Credential leaf = leaf(store);
                AtomicInteger stages = new AtomicInteger();
                AtomicReference<DurableContentReference> candidate = new AtomicReference<>();
                AtomicBoolean cancelled = new AtomicBoolean();
                EndEntityIssuancePreparationTest.CountingProvider provider = new EndEntityIssuancePreparationTest.CountingProvider();
                PkiStore observed = EndEntityIssuancePreparationTest.observePreparation(store, stages, candidate, cancelled, true);
                SemanticSigningService service = EndEntityIssuancePreparationTest.semantic(observed, provider, () -> { });
                assertThrows(PkiException.class, () -> prepare(service, operation, ACCESS, leaf, cancelled::get));
                assertEquals(1, stages.get());
                assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, candidate.get()));
                AtomicInteger checks = new AtomicInteger();
                SemanticSigningService closing = EndEntityIssuancePreparationTest.semantic(
                        EndEntityIssuancePreparationTest.observePreparation(store, stages, candidate, cancelled, false), provider,
                        () -> { if (checks.incrementAndGet() == 3) { throw new IllegalStateException("closed"); } });
                assertThrows(IllegalStateException.class, () -> prepare(closing, operation, ACCESS, leaf, CancellationSignal.NONE));
                assertEquals(2, stages.get());
                assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, candidate.get()));
                assertEquals(0, provider.calls.get());
            }
        }
    }

    private static void assertInvalidSchemas(SignWorkflowStore.OuterCommand outer, DomainCommandEncoding.Decoded command) {
        for (String operation : List.of("ISSUE_END_ENTITY", "UNKNOWN_END_ENTITY")) {
            DomainContinuationTemplate invalid = DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.ISSUANCE,
                    outer.correlationId(), operation, command.fields().toArray(String[]::new));
            assertThrows(RuntimeException.class, () -> DomainContinuationValidation.validate(invalid));
        }
        for (int field : List.of(15, 16)) {
            List<String> fields = new ArrayList<>(command.fields());
            fields.set(field, "aa".repeat(32));
            DomainContinuationTemplate invalid = DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.ISSUANCE,
                    outer.correlationId(), command.operation(), fields.toArray(String[]::new));
            assertThrows(RuntimeException.class, () -> DomainContinuationValidation.validate(invalid));
        }
    }

    private static void assertScopeMismatch(SemanticSigningService service, SignWorkflowStore.Workflow workflow, Credential leaf) {
        SignWorkflowStore.AcceptanceEnvelope envelope = workflow.envelope();
        SignWorkflowStore.OuterCommand outer = envelope.outer().orElseThrow();
        DomainContinuationTemplate template = new DomainContinuationTemplate(outer.kind(), Optional.of(outer.correlationId()),
                outer.command(), outer.commandCommitment());
        DomainSigningRequest invalid = new DomainSigningRequest(envelope.operationId(), ACCESS, envelope.keyRef(),
                envelope.algorithmId(), envelope.signatureEncoding(), envelope.candidate(), java.time.Duration.ofMinutes(1), template, java.util.Optional.empty());
        assertThrows(IllegalArgumentException.class, () -> ((DefaultSemanticSigningService) service).prepare(invalid, leaf.issuerRef().caId()));
    }

    private static Credential leaf(FilesystemPkiStore store) throws Exception {
        return EndEntityLifecyclePreparationTest.leaf(store, "CN=Applicant", new Validity(NOW.minusSeconds(10), NOW.plusSeconds(100)));
    }

    private static PreparedSemanticSigningRequest prepare(SemanticSigningService service, String operation,
            AccessContext access, Credential leaf, CancellationSignal cancellation) {
        return prepare(service, operation, access, leaf, Optional.empty(), cancellation);
    }

    private static PreparedSemanticSigningRequest prepare(SemanticSigningService service, String operation,
            AccessContext access, Credential leaf, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation) {
        return switch (operation) {
            case "RENEW_END_ENTITY" -> service.prepareRenewal(access, new EndEntityRenewalRequest(leaf.credentialId(), Optional.empty()), evidence, cancellation);
            case "REPLACE_END_ENTITY" -> service.prepareReplacement(access, new EndEntityReplacementRequest(leaf.credentialId(), csr, "h7-no-san-eku"), evidence, cancellation);
            case "REISSUE_END_ENTITY" -> service.prepareReissue(access, new EndEntityReissueRequest(leaf.credentialId()), evidence, cancellation);
            default -> throw new AssertionError(operation);
        };
    }
}
