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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialLineage;
import zeroecho.pki.api.issuance.EndEntityReissueRequest;
import zeroecho.pki.api.issuance.EndEntityRenewalRequest;
import zeroecho.pki.api.issuance.EndEntityReplacementRequest;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.core.continuation.DomainAttributeEncoding;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.DomainContinuationValidation;
import zeroecho.pki.impl.core.continuation.SigningOuterTerminalDriver;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.PkiTestRuntime;

final class EndEntitySupersessionPublicationTest {
    private static final Instant NOW = Instant.parse("2026-09-20T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final AccessContext ACCESS = new AccessContext(new Principal("TEST", "operator"),
            new Purpose("LIFECYCLE"), Optional.empty(), Optional.empty());

    @BeforeAll static void keys() throws Exception { EndEntityLifecyclePreparationTest.keys(); }

    @Test void renewKeepsPredecessorWhileReplaceAndReissueSupersede(@TempDir Path root) throws Exception {
        for (String operation : List.of("RENEW_END_ENTITY", "REPLACE_END_ENTITY", "REISSUE_END_ENTITY")) {
            try (FilesystemPkiStore store = EndEntityLifecyclePreparationTest.fixture(root.resolve(operation))) {
                Credential predecessor = predecessor(store);
                SignWorkflowStore.Workflow signed = signed(store, operation, predecessor);
                new SigningOuterTerminalDriver(store).advance(signed);
                assertEquals(DomainContinuationStore.State.COMPLETED, store.getDomainContinuation(signed.operationId()).orElseThrow().state());
                Credential successor = successor(store, signed).orElseThrow();
                if (operation.equals("RENEW_END_ENTITY")) {
                    assertTrue(store.getRevocation(predecessor.credentialId()).isEmpty());
                    assertTrue(CredentialLineage.supersededCredentialId(successor.attributes()).isEmpty());
                } else {
                    assertEquals(Optional.of(predecessor.credentialId()), CredentialLineage.supersededCredentialId(successor.attributes()));
                    assertEquals(Optional.of(new AttributeValue.StringValue(operation)), successor.attributes().get(CredentialLineage.SUPERSESSION_REASON));
                    assertEquals(Optional.of(RevocationReason.SUPERSEDED), store.getRevocation(predecessor.credentialId()).orElseThrow().transition().permanentReason());
                }
            }
        }
    }

    @Test void permanentReasonIsPreservedAndHeldStateCanBecomeSuperseded(@TempDir Path root) throws Exception {
        for (boolean permanent : List.of(true, false)) {
            try (FilesystemPkiStore store = EndEntityLifecyclePreparationTest.fixture(root.resolve(Boolean.toString(permanent)))) {
                Credential predecessor = predecessor(store);
                SignWorkflowStore.Workflow signed = signed(store, "REPLACE_END_ENTITY", predecessor);
                store.transitionRevocation(permanent
                        ? new RevocationCommand.RevokePermanently(predecessor.credentialId(), RevocationReason.KEY_COMPROMISE, new SimpleAttributeSet())
                        : new RevocationCommand.Hold(predecessor.credentialId(), new SimpleAttributeSet()), NOW);
                new SigningOuterTerminalDriver(store).advance(signed);
                assertEquals(DomainContinuationStore.State.COMPLETED, store.getDomainContinuation(signed.operationId()).orElseThrow().state());
                assertEquals(Optional.of(permanent ? RevocationReason.KEY_COMPROMISE : RevocationReason.SUPERSEDED),
                        store.getRevocation(predecessor.credentialId()).orElseThrow().transition().permanentReason());
                assertEquals(permanent ? 1L : 2L, store.getRevocation(predecessor.credentialId()).orElseThrow().transition().revision());
            }
        }
    }

    @Test void eachDurableCrashPrefixResumesWithoutDuplicateWrites(@TempDir Path root) throws Exception {
        for (String cut : List.of("putCredentialFromSigning", "transitionRevocation", "transitionDomainContinuation")) {
            for (String operation : List.of("REPLACE_END_ENTITY", "REISSUE_END_ENTITY")) {
                Path directory = root.resolve(cut + operation);
                AtomicInteger credentialWrites = new AtomicInteger();
                AtomicInteger revocationWrites = new AtomicInteger();
                PkiId operationId;
                PkiId predecessorId;
                PkiId successorId;
                try (FilesystemPkiStore store = EndEntityLifecyclePreparationTest.fixture(directory)) {
                    Credential predecessor = predecessor(store);
                    predecessorId = predecessor.credentialId();
                    SignWorkflowStore.Workflow signed = signed(store, operation, predecessor);
                    operationId = signed.operationId();
                    AtomicBoolean injected = new AtomicBoolean();
                    PkiStore crashing = observe(store, credentialWrites, revocationWrites, cut, injected, false, false);
                    assertThrows(Throwable.class, () -> new SigningOuterTerminalDriver(crashing).advance(signed));
                    assertTrue(injected.get());
                    assertEquals(DomainContinuationStore.State.PUBLISHING, store.getDomainContinuation(operationId).orElseThrow().state());
                    successorId = successor(store, signed).orElseThrow().credentialId();
                    assertEquals(1, credentialWrites.get());
                }
                try (FilesystemPkiStore store = new FilesystemPkiStore(directory, FsPkiStoreOptions.defaults(), CLOCK)) {
                    PkiStore observed = observe(store, credentialWrites, revocationWrites, "", new AtomicBoolean(), false, false);
                    SigningOuterTerminalDriver driver = new SigningOuterTerminalDriver(observed);
                    driver.advance(store.getSignWorkflow(operationId).orElseThrow());
                    driver.advance(store.getSignWorkflow(operationId).orElseThrow());
                    DomainContinuationStore.Record recovered = store.getDomainContinuation(operationId).orElseThrow();
                    assertEquals(DomainContinuationStore.State.COMPLETED, recovered.state(),
                            cut + ": " + recovered.detailCode().orElse("none"));
                    assertEquals(successorId, store.getCredential(successorId).orElseThrow().credentialId());
                    assertEquals(1, credentialWrites.get());
                    assertEquals(1, revocationWrites.get());
                    assertEquals(1L, store.getRevocation(predecessorId).orElseThrow().transition().revision());
                }
            }
        }
    }

    @Test void concurrentPermanentRevocationAndUnknownAcknowledgementResolveByPointRead(@TempDir Path root) throws Exception {
        for (boolean race : List.of(true, false)) {
            try (FilesystemPkiStore store = EndEntityLifecyclePreparationTest.fixture(root.resolve(Boolean.toString(race)))) {
                Credential predecessor = predecessor(store);
                SignWorkflowStore.Workflow signed = signed(store, "REISSUE_END_ENTITY", predecessor);
                PkiStore observed = observe(store, new AtomicInteger(), new AtomicInteger(), "", new AtomicBoolean(), race, !race);
                new SigningOuterTerminalDriver(observed).advance(signed);
                assertEquals(DomainContinuationStore.State.COMPLETED, store.getDomainContinuation(signed.operationId()).orElseThrow().state());
                assertEquals(RevocationState.PERMANENTLY_REVOKED, store.getRevocation(predecessor.credentialId()).orElseThrow().transition().state());
                assertEquals(Optional.of(race ? RevocationReason.KEY_COMPROMISE : RevocationReason.SUPERSEDED),
                        store.getRevocation(predecessor.credentialId()).orElseThrow().transition().permanentReason());
                assertEquals(1L, store.getRevocation(predecessor.credentialId()).orElseThrow().transition().revision());
            }
        }
    }

    @Test void cancellationOrSigningFailureNeverPublishesOrRevokes(@TempDir Path root) throws Exception {
        for (boolean cancel : List.of(true, false)) {
            try (FilesystemPkiStore store = EndEntityLifecyclePreparationTest.fixture(root.resolve(Boolean.toString(cancel)))) {
                Credential predecessor = predecessor(store);
                PkiId id = accept(store, "REISSUE_END_ENTITY", predecessor);
                SignWorkflowStore.Workflow terminal;
                if (cancel) {
                    terminal = store.requestSignCancellation(id, 0, 0).orElseThrow();
                } else {
                    SignWorkflowStore.Workflow claim = store.claimSignStep(id, 0, Duration.ofSeconds(10)).orElseThrow();
                    terminal = store.transitionSign(id, claim.revision(), claim.fence(), SignWorkflowStore.State.FAILED,
                            Optional.of("DENIED"), Optional.empty(), Optional.of(NOW)).orElseThrow();
                }
                new SigningOuterTerminalDriver(store).advance(terminal);
                assertEquals(DomainContinuationStore.State.FAILED, store.getDomainContinuation(id).orElseThrow().state());
                assertTrue(successor(store, terminal).isEmpty());
                assertTrue(store.getRevocation(predecessor.credentialId()).isEmpty());
            }
        }
    }

    @Test void reservedLineageAttributesAndMalformedSourceCannotEnterCanonicalCommand(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = EndEntityLifecyclePreparationTest.fixture(root)) {
            SignWorkflowStore.Workflow signed = signed(store, "REISSUE_END_ENTITY", predecessor(store));
            DomainCommandEncoding.Decoded command = command(signed);
            for (zeroecho.pki.api.attr.AttributeId attribute : List.of(CredentialLineage.SUPERSEDES_CREDENTIAL_ID, CredentialLineage.SUPERSESSION_REASON)) {
                List<String> fields = new ArrayList<>(command.fields());
                fields.set(22, DomainAttributeEncoding.encode(SimpleAttributeSet.builder()
                        .put(attribute, new AttributeValue.StringValue("forged")).build()));
                assertThrows(IllegalStateException.class, () -> DomainContinuationValidation.validate(template(command.operation(), fields)));
            }
            List<String> fields = new ArrayList<>(command.fields());
            fields.set(23, "forged");
            assertThrows(IllegalStateException.class, () -> DomainContinuationValidation.validate(template(command.operation(), fields)));
        }
    }

    private static PkiStore observe(PkiStore store, AtomicInteger credentials, AtomicInteger revocations,
            String cut, AtomicBoolean injected, boolean explicitRevocationRace, boolean loseRevocationAcknowledgement) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, args) -> {
                    String name = method.getName();
                    boolean publication = name.equals("putCredentialFromSigning")
                            && store.getCredential(((Credential) args[0]).credentialId()).isEmpty();
                    if (name.equals("transitionDomainContinuation") && args[2] == DomainContinuationStore.State.COMPLETED
                            && cut.equals(name) && injected.compareAndSet(false, true)) { throw new SimulatedCrash(); }
                    if (name.equals("transitionRevocation") && explicitRevocationRace) {
                        PkiId target = ((RevocationCommand) args[0]).credentialId();
                        store.transitionRevocation(new RevocationCommand.RevokePermanently(target, RevocationReason.KEY_COMPROMISE,
                                new SimpleAttributeSet()), NOW);
                    }
                    try {
                        Object result = method.invoke(store, args);
                        if (name.equals("getCredential") && result instanceof Optional<?> found
                                && found.orElse(null) instanceof Credential credential
                                && credential.attributes().ids().contains(CredentialLineage.SUPERSEDES_CREDENTIAL_ID)) {
                            // Force the alternate legal store enumeration order on every recovery read,
                            // independent of the JVM's randomized immutable-set iteration seed.
                            SimpleAttributeSet reordered = new SimpleAttributeSet(List.of(
                                    new SimpleAttributeSet.Entry(CredentialLineage.SUPERSESSION_REASON,
                                            credential.attributes().getAll(CredentialLineage.SUPERSESSION_REASON)),
                                    new SimpleAttributeSet.Entry(CredentialLineage.SUPERSEDES_CREDENTIAL_ID,
                                            credential.attributes().getAll(CredentialLineage.SUPERSEDES_CREDENTIAL_ID))));
                            result = Optional.of(new Credential(credential.credentialId(), credential.formatId(), credential.issuerRef(),
                                    credential.subjectRef(), credential.validity(), credential.serialOrUniqueId(), credential.publicKeyId(),
                                    credential.profileBinding(), credential.status(), credential.content(), reordered));
                        }
                        if (publication) { credentials.incrementAndGet(); }
                        if (name.equals("transitionRevocation")) { revocations.incrementAndGet(); }
                        if (!name.equals("transitionDomainContinuation") && cut.equals(name)
                                && injected.compareAndSet(false, true)) { throw new SimulatedCrash(); }
                        if (name.equals("transitionRevocation") && loseRevocationAcknowledgement) {
                            throw new IllegalStateException("Simulated lost revocation acknowledgement");
                        }
                        return result;
                    } catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
    }

    private static PkiId accept(FilesystemPkiStore store, String operation, Credential predecessor) throws Exception {
        SemanticSigningService service = EndEntityIssuancePreparationTest.semantic(store,
                new EndEntityIssuancePreparationTest.CountingProvider(), () -> { });
        PreparedSemanticSigningRequest prepared = switch (operation) {
            case "RENEW_END_ENTITY" -> service.prepareRenewal(ACCESS,
                    new EndEntityRenewalRequest(predecessor.credentialId(), Optional.empty()), Optional.empty(), CancellationSignal.NONE);
            case "REPLACE_END_ENTITY" -> service.prepareReplacement(ACCESS, new EndEntityReplacementRequest(predecessor.credentialId(),
                    EndEntityLifecyclePreparationTest.csr(EndEntityLifecyclePreparationTest.key), "h7-no-san-eku"), Optional.empty(), CancellationSignal.NONE);
            case "REISSUE_END_ENTITY" -> service.prepareReissue(ACCESS, new EndEntityReissueRequest(predecessor.credentialId()), Optional.empty(), CancellationSignal.NONE);
            default -> throw new AssertionError(operation);
        };
        service.accept(prepared);
        return prepared.receipt().operationId();
    }

    private static SignWorkflowStore.Workflow signed(FilesystemPkiStore store, String operation, Credential predecessor) throws Exception {
        PkiId id = accept(store, operation, predecessor);
        SignWorkflowStore.Workflow claim = store.claimSignStep(id, 0, Duration.ofSeconds(10)).orElseThrow();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(EndEntityLifecyclePreparationTest.key.getPrivate());
        signature.update(PkiTestRuntime.readContent(store, claim.envelope().candidate()));
        return store.transitionSign(id, claim.revision(), claim.fence(), SignWorkflowStore.State.SUCCEEDED, Optional.of("SIGNED"),
                Optional.of(new EncodedObject(Encoding.BINARY, signature.sign())), Optional.of(NOW)).orElseThrow();
    }

    private static Credential predecessor(FilesystemPkiStore store) throws Exception {
        return EndEntityLifecyclePreparationTest.leaf(store, "CN=Applicant", new Validity(NOW.minusSeconds(10), NOW.plusSeconds(100)));
    }

    private static DomainCommandEncoding.Decoded command(SignWorkflowStore.Workflow workflow) {
        return DomainCommandEncoding.decode(workflow.envelope().outer().orElseThrow().command());
    }

    private static Optional<Credential> successor(PkiStore store, SignWorkflowStore.Workflow workflow) {
        DomainCommandEncoding.Decoded command = command(workflow);
        return store.getCredentialByIssuerAndSerial(new PkiId(command.field(1)), new BigInteger(command.field(10)));
    }

    private static DomainContinuationTemplate template(String operation, List<String> fields) {
        return DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.ISSUANCE, "test", operation, fields.toArray(String[]::new));
    }

    private static final class SimulatedCrash extends Error {
        private static final long serialVersionUID = 1L;
    }
}
