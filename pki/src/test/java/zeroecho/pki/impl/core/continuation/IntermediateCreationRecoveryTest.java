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

package zeroecho.pki.impl.core.continuation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Path;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.core.signing.DefaultSemanticSigningService;
import zeroecho.pki.impl.core.signing.DefaultSigningService;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.impl.core.IntermediateSigningPreparation;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.IntermediateCreationFixture;
import zeroecho.pki.testkit.PkiTestRuntime;

final class IntermediateCreationRecoveryTest {
    @Test void resumesEveryPublicationPrefixAfterReopenWithRetainedInternalProof(@TempDir Path temporary) throws Exception {
        for (DomainContinuationPublisher.PublicationFaultPoint point : new DomainContinuationPublisher.PublicationFaultPoint[] {
                DomainContinuationPublisher.PublicationFaultPoint.AFTER_CREDENTIAL,
                DomainContinuationPublisher.PublicationFaultPoint.AFTER_ISSUER_GENERATION,
                DomainContinuationPublisher.PublicationFaultPoint.AFTER_CHAIN_PATH,
                DomainContinuationPublisher.PublicationFaultPoint.AFTER_CA }) {
            Path root = temporary.resolve(point.name());
            MutableClock clock = new MutableClock();
            IntermediateCreationFixture fixture = new IntermediateCreationFixture();
            PkiId operation;
            PkiId child;
            CaRecord laterAdministration = null;
            try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
                fixture.initialize(store, 1);
                clock.now = IntermediateCreationFixture.NOW.plus(store.signingHorizon()).minusSeconds(10);
                SigningSubmissionId submission = SigningSubmissionId.create(store.signingNamespace() + "." + fixture.provider.id(),
                        clock.instant(), new SecureRandom());
                DomainSigningRequest request = new IntermediateSigningPreparation(store, clock, fixture.provider, fixture.signing,
                        fixture.bindings, IntermediateCreationFixture.ALGORITHM, ManagedKeyProofCommand.MAX_CHALLENGE_BYTES, fixture.proofPreparation(store))
                        .prepare(IntermediateCreationFixture.ACCESS, fixture.command("CN=Child"), submission,
                                IntermediateCreationFixture.TTL, CancellationSignal.NONE);
                DomainContinuationTemplate template = request.domainTemplate();
                store.acceptSign(new SignWorkflowStore.AcceptanceCommand(request.operationId(),
                        store.signingNamespace() + "." + fixture.provider.id(), fixture.provider.configurationCommitment(),
                        request.accessContext(), request.keyRef(), IntermediateCreationFixture.CA, IntermediateCreationFixture.ALGORITHM,
                        Encoding.BINARY, clock.instant(), clock.instant().plus(IntermediateCreationFixture.TTL), request.content(),
                        Optional.of(new SignWorkflowStore.OuterCommand(template.kind(), template.correlationId().orElseThrow(),
                                template.command(), template.commandCommitment())), SignWorkflowStore.Mode.NORMAL, request.proofStep()));
                operation = request.operationId();
                child = new PkiId(DomainCommandEncoding.decode(template.command()).field(2));
                fixture.signCertificate(store, operation);
                SignWorkflowStore.Workflow signed = store.getSignWorkflow(operation).orElseThrow();
                assertEquals(SignWorkflowStore.Stage.CA_CERTIFICATE, signed.stage());
                assertTrue(signed.proofOutcome().isPresent());
                assertTrue(store.getSignWorkflow(request.proofStep().orElseThrow().operationId()).isEmpty());
                DomainContinuationPublisher.installPublicationFault(observed -> {
                    if (observed == point) { throw new SimulatedCrash(); }
                });
                try {
                    assertThrows(SimulatedCrash.class, () -> new SigningOuterTerminalDriver(store, fixture.verification,
                            fixture.verifier, ManagedKeyProofCommand.MAX_CHALLENGE_BYTES)
                            .advance(store.getSignWorkflow(operation).orElseThrow()));
                } finally {
                    DomainContinuationPublisher.clearPublicationFault();
                }
                if (point == DomainContinuationPublisher.PublicationFaultPoint.AFTER_CA) {
                    CaRecord published = store.getCa(child).orElseThrow();
                    laterAdministration = new CaRecord(published.caId(), published.kind(), CaState.DISABLED,
                            published.issuerKeyRef(), published.subjectRef(), published.issuerIds(),
                            published.currentIssuanceIssuerId(), published.issuanceChainPathId());
                    assertTrue(store.replaceCa(published, laterAdministration));
                }
            }
            try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
                SigningOuterTerminalDriver driver = new SigningOuterTerminalDriver(store, fixture.verification, fixture.verifier,
                        ManagedKeyProofCommand.MAX_CHALLENGE_BYTES);
                driver.advance(store.getSignWorkflow(operation).orElseThrow());
                driver.advance(store.getSignWorkflow(operation).orElseThrow());
                assertEquals(DomainContinuationStore.State.COMPLETED, store.getDomainContinuation(operation).orElseThrow().state());
                assertEquals(1, store.listIssuerGenerations(child).size());
                assertEquals(2, store.getIssuerChainPath(store.getCa(child).orElseThrow().issuanceChainPathId())
                        .orElseThrow().orderedCredentialIds().size());
                assertEquals(0, fixture.provider.dispatches);
                if (laterAdministration != null) assertEquals(laterAdministration, store.getCa(child).orElseThrow());
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"ISSUE_INTERMEDIATE", "ROLLOVER_INTERMEDIATE"})
    void existingAuthorityOperationsRecoverAfterInternalProofAndPublicationCrash(String operation,
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock();
        IntermediateCreationFixture fixture = new IntermediateCreationFixture();
        PkiId operationId;
        PkiId child;
        PkiId originalSelection;
        PkiId proofId;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            fixture.initialize(store, 1);
            DomainSigningRequest creation = fixture.preparer(store).prepare(IntermediateCreationFixture.ACCESS,
                    fixture.command("CN=Child"), fixture.submission(store), IntermediateCreationFixture.TTL, CancellationSignal.NONE);
            fixture.accept(store, creation);
            fixture.finish(store, creation.operationId());
            child = new PkiId(DomainCommandEncoding.decode(creation.domainTemplate().command()).field(2));
            originalSelection = store.getCa(child).orElseThrow().currentIssuanceIssuerId();
            DomainSigningRequest request = existingRequest(store, fixture, operation, child, clock);
            proofId = request.proofStep().orElseThrow().operationId();
            DefaultSemanticSigningService semantic = semantic(store, fixture);
            rejectSubstitutedCandidate(store, fixture, semantic, request, clock);
            operationId = semantic.accept(semantic.prepare(request, IntermediateCreationFixture.CA)).receipt().operationId();
            assertEquals(SemanticSigningState.SIGNING, semantic.find(operationId).orElseThrow().state());
            fixture.signCertificate(store, operationId);
            assertTrue(store.getSignWorkflow(proofId).isEmpty());
            assertTrue(store.getDomainContinuation(proofId).isEmpty());
            assertTrue(store.getSignWorkflow(operationId).orElseThrow().proofOutcome().isPresent());
            DomainContinuationPublisher.installPublicationFault(point -> {
                if (point == DomainContinuationPublisher.PublicationFaultPoint.AFTER_CREDENTIAL) throw new SimulatedCrash();
            });
            try {
                assertThrows(SimulatedCrash.class, () -> new SigningOuterTerminalDriver(store, fixture.verification,
                        fixture.verifier, ManagedKeyProofCommand.MAX_CHALLENGE_BYTES)
                        .advance(store.getSignWorkflow(operationId).orElseThrow()));
            } finally { DomainContinuationPublisher.clearPublicationFault(); }
        }
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            SigningOuterTerminalDriver driver = new SigningOuterTerminalDriver(store, fixture.verification,
                    fixture.verifier, ManagedKeyProofCommand.MAX_CHALLENGE_BYTES);
            driver.advance(store.getSignWorkflow(operationId).orElseThrow());
            driver.advance(store.getSignWorkflow(operationId).orElseThrow());
            assertEquals(SemanticSigningState.COMPLETED, semantic(store, fixture).find(operationId).orElseThrow().state());
            assertTrue(store.getDomainContinuation(proofId).isEmpty());
            CaRecord current = store.getCa(child).orElseThrow();
            assertEquals(2, current.issuerIds().size());
            assertEquals(originalSelection, current.issuerIds().getFirst());
            assertEquals(IntermediateSigningCommand.ISSUE.equals(operation) ? originalSelection : current.issuerIds().getLast(),
                    current.currentIssuanceIssuerId());
            assertEquals(0, fixture.provider.dispatches);
        }
    }

    private static void rejectSubstitutedCandidate(FilesystemPkiStore store, IntermediateCreationFixture fixture,
            DefaultSemanticSigningService semantic, DomainSigningRequest request, Clock clock) throws Exception {
        byte[] changed = PkiTestRuntime.readContent(store, request.content());
        changed[changed.length - 1] ^= 1;
        zeroecho.pki.api.content.DurableContentReference candidate = PkiTestRuntime.operationReference(store.stagedContent(), Encoding.DER, changed);
        DomainSigningRequest substituted = new DomainSigningRequest(request.operationId(), request.accessContext(), request.keyRef(),
                request.algorithmId(), request.signatureEncoding(), candidate, request.ttl(), request.domainTemplate(), request.proofStep());
        assertThrows(RuntimeException.class, () -> semantic.prepare(substituted, IntermediateCreationFixture.CA));
        assertEquals(changed.length, PkiTestRuntime.readContent(store, candidate).length);
        assertTrue(store.getSignWorkflow(request.operationId()).isEmpty());
        store.stagedContent().retireUnownedContent(candidate);
        assertThrows(IOException.class, () -> PkiTestRuntime.readContent(store, candidate));
    }

    private static DomainSigningRequest existingRequest(FilesystemPkiStore store, IntermediateCreationFixture fixture,
            String operation, PkiId child, Clock clock) throws Exception {
        CaRecord subject = store.getCa(child).orElseThrow();
        IntermediateSigningPreparation preparation = new IntermediateSigningPreparation(store, clock, fixture.provider,
                fixture.signing, fixture.bindings, IntermediateCreationFixture.ALGORITHM,
                ManagedKeyProofCommand.MAX_CHALLENGE_BYTES, fixture.proofPreparation(store));
        SigningSubmissionId submission = SigningSubmissionId.create(store.signingNamespace() + "." + fixture.provider.id(),
                clock.instant(), new SecureRandom());
        if (IntermediateSigningCommand.ISSUE.equals(operation)) {
            return preparation.prepare(IntermediateCreationFixture.ACCESS,
                    new zeroecho.pki.api.ca.IntermediateCertIssueCommand(new zeroecho.pki.api.FormatId("x509"),
                            IntermediateCreationFixture.CA, child, "intermediate-ca", subject.issuerKeyRef(),
                            Optional.empty(), new SimpleAttributeSet()), submission, IntermediateCreationFixture.TTL, CancellationSignal.NONE);
        }
        return preparation.prepare(IntermediateCreationFixture.ACCESS,
                new zeroecho.pki.api.ca.CaRolloverCommand.Intermediate(child, IntermediateCreationFixture.CA,
                        subject.issuerKeyRef(), Optional.empty(), new SimpleAttributeSet()), submission,
                IntermediateCreationFixture.TTL, CancellationSignal.NONE);
    }

    private static DefaultSemanticSigningService semantic(FilesystemPkiStore store, IntermediateCreationFixture fixture) {
        DefaultSigningService signing = new DefaultSigningService(store, fixture.provider, fixture.signing.resolveIdentity(IntermediateCreationFixture.ALGORITHM),
                IntermediateCreationFixture.TTL, new SecureRandom(), () -> { },
                (command, custody) -> { custody.run(); return store.acceptSign(command); }, () -> { },
                (boundedWaitId, boundedWaitCancellation) -> { throw new UnsupportedOperationException("Fixture has no reactor wait"); });
        return new DefaultSemanticSigningService(store, signing, PkiTestRuntime.endEntityPreparation(store, IntermediateCreationFixture.CLOCK));
    }

    private static final class SimulatedCrash extends Error { }
    private static final class MutableClock extends Clock {
        private Instant now = IntermediateCreationFixture.NOW;
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return Clock.fixed(now, zone); }
        @Override public Instant instant() { return now; }
    }
}
