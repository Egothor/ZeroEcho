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

package zeroecho.pki.impl.core.continuation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spi.AlgorithmExecutionCapability.Direction;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.signing.ManagedKeyProofRequest;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningKind;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.api.signing.SigningAcceptanceDisposition;
import zeroecho.pki.api.signing.SigningAcceptanceResolution;
import zeroecho.pki.impl.core.ManagedKeyProofPreparation;
import zeroecho.pki.impl.core.signing.DefaultSemanticSigningService;
import zeroecho.pki.impl.core.signing.DefaultSigningService;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FilesystemPkiStoreTestAccess;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.pki.spi.crypto.SigningInputCapabilities;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.StagedContentStore;
import zeroecho.pki.testkit.PkiTestRuntime;

final class ManagedKeyProofLifecycleTest {
    private static final Instant NOW = Instant.parse("2026-09-21T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final Duration TTL = Duration.ofMinutes(1);
    private static final KeyRef KEY = new KeyRef("proof-key");
    private static final PkiId AUTHORITY = new PkiId("proof-authority");
    private static final AccessContext ACCESS = new AccessContext(new Principal("TEST", "actor"), new Purpose("PROVE"),
            Optional.empty(), Optional.empty());

    @Test void rsaPssAndEd25519CompleteWithoutPublishingAndReopenAfterRetirement(@TempDir Path root) throws Exception {
        for (boolean rsa : new boolean[] {true, false}) {
            Path directory = root.resolve(Boolean.toString(rsa));
            Provider provider = new Provider(rsa);
            PkiId operation;
            EncodedObject signature;
            byte[] marker;
            try (FilesystemPkiStore store = open(directory)) {
                Fixture fixture = new Fixture(store, provider);
                PreparedSemanticSigningRequest unused = fixture.prepare();
                assertEquals(0, provider.dispatches.get());
                fixture.semantic.discard(unused);
                assertThrows(IllegalStateException.class, () -> fixture.semantic.accept(unused));
                PreparedSemanticSigningRequest prepared = fixture.prepare();
                assertNotEquals(unused.receipt().operationId(), prepared.receipt().operationId());
                assertEquals(0, provider.dispatches.get());
                operation = fixture.semantic.accept(prepared).receipt().operationId();
                DomainContinuationStore.Record domain = store.getDomainContinuation(operation).orElseThrow();
                DurableContentReference content = domain.signingContent().orElseThrow();
                signature = provider.sign(PkiTestRuntime.readContent(store, content));
                sign(store, operation, signature);
                fixture.driver.advance(store.getSignWorkflow(operation).orElseThrow());
                SemanticSigningOperation completed = fixture.semantic.find(operation).orElseThrow();
                assertEquals(SemanticSigningState.COMPLETED, completed.state());
                assertEquals(SemanticSigningKind.KEY_PROOF, completed.scope().kind());
                marker = completed.result().orElseThrow().bytes();
                assertEquals(70, marker.length);
                assertEquals("proof:" + domain.commandCommitment().substring(10), new String(marker, StandardCharsets.US_ASCII));
                assertFalse(java.util.Arrays.equals(signature.bytes(), marker));
                assertArrayEquals(signature.bytes(), fixture.signing.find(operation).orElseThrow().signature().orElseThrow().bytes());
                assertEquals(SignWorkflowStore.State.RETIRED, store.getSignWorkflow(operation).orElseThrow().state());
                assertThrows(Exception.class, () -> store.stagedContent().openContent(content));
                assertTrue(store.listStatusObjects(AUTHORITY).isEmpty());
                assertTrue(store.getCa(AUTHORITY).isEmpty());
            }
            try (FilesystemPkiStore store = open(directory)) {
                Fixture fixture = new Fixture(store, provider);
                assertArrayEquals(marker, fixture.semantic.find(operation).orElseThrow().result().orElseThrow().bytes());
                assertArrayEquals(signature.bytes(), fixture.signing.find(operation).orElseThrow().signature().orElseThrow().bytes());
                fixture.driver.advance(store.getSignWorkflow(operation).orElseThrow());
                assertEquals(0, provider.dispatches.get());
            }
        }
    }

    @Test void definiteMismatchFailsButContentIoRemainsPublishingAndCanRetry(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            Provider provider = new Provider(false);
            Fixture fixture = new Fixture(store, provider);
            PkiId invalid = fixture.semantic.accept(fixture.prepare()).receipt().operationId();
            byte[] challenge = PkiTestRuntime.readContent(store, store.getSignWorkflow(invalid).orElseThrow().envelope().candidate());
            byte[] otherMessage = challenge.clone();
            otherMessage[0] ^= 1;
            byte[] bytes = provider.sign(otherMessage).bytes();
            sign(store, invalid, new EncodedObject(Encoding.BINARY, bytes));
            fixture.driver.advance(store.getSignWorkflow(invalid).orElseThrow());
            SemanticSigningOperation failed = fixture.semantic.find(invalid).orElseThrow();
            assertEquals(SemanticSigningState.FAILED, failed.state());
            assertEquals(Optional.of("MANAGED_KEY_PROOF_SIGNATURE_INVALID"), failed.detailCode());
            assertTrue(failed.result().isEmpty());

            PkiId retry = fixture.semantic.accept(fixture.prepare()).receipt().operationId();
            DurableContentReference content = store.getSignWorkflow(retry).orElseThrow().envelope().candidate();
            sign(store, retry, provider.sign(PkiTestRuntime.readContent(store, content)));
            StagedContentStore unreadable = proxy(StagedContentStore.class, store.stagedContent(), (method, args) -> {
                if (method.equals("openContent")) { throw new IOException("controlled content read failure"); }
                return PROCEED;
            });
            PkiStore fault = proxy(PkiStore.class, store, (method, args) -> method.equals("stagedContent") ? unreadable : PROCEED);
            SigningOuterTerminalDriver blocked = new SigningOuterTerminalDriver(fault, fixture.authority, fixture.verifier,
                    ManagedKeyProofCommand.MAX_CHALLENGE_BYTES);
            assertThrows(PkiException.class, () -> blocked.advance(store.getSignWorkflow(retry).orElseThrow()));
            assertEquals(DomainContinuationStore.State.PUBLISHING, store.getDomainContinuation(retry).orElseThrow().state());
            assertEquals(SignWorkflowStore.State.SUCCEEDED, store.getSignWorkflow(retry).orElseThrow().state());
            assertEquals(content.length(), PkiTestRuntime.readContent(store, content).length);
            fixture.driver.advance(store.getSignWorkflow(retry).orElseThrow());
            assertEquals(SemanticSigningState.COMPLETED, fixture.semantic.find(retry).orElseThrow().state());
        }
    }

    @Test void truncatedEd25519AndMalformedRsaSignaturesFailWithoutRetainingDiagnostics(@TempDir Path root) throws Exception {
        for (boolean rsa : new boolean[] {false, true}) {
            try (FilesystemPkiStore store = open(root.resolve(Boolean.toString(rsa)))) {
                Provider provider = new Provider(rsa);
                Fixture fixture = new Fixture(store, provider);
                PkiId operation = fixture.semantic.accept(fixture.prepare()).receipt().operationId();
                DurableContentReference content = store.getSignWorkflow(operation).orElseThrow().envelope().candidate();
                byte[] valid = provider.sign(PkiTestRuntime.readContent(store, content)).bytes();
                byte[] malformed = java.util.Arrays.copyOf(valid, valid.length - 1);
                assertEquals(rsa ? 255 : 63, malformed.length);
                sign(store, operation, new EncodedObject(Encoding.BINARY, malformed));
                ManagedKeyProofVerifier verifier = new ManagedKeyProofVerifier(store, fixture.authority,
                        fixture.verifier, ManagedKeyProofCommand.MAX_CHALLENGE_BYTES);
                DomainContinuationPublisher.PostconditionFailure failure = assertThrows(
                        DomainContinuationPublisher.PostconditionFailure.class,
                        () -> verifier.verify(store.getDomainContinuation(operation).orElseThrow(),
                                store.getSignWorkflow(operation).orElseThrow()));
                assertNull(failure.getCause());
                assertEquals(0, failure.getSuppressed().length);
                assertEquals("MANAGED_KEY_PROOF_SIGNATURE_INVALID", failure.getMessage());
                fixture.driver.advance(store.getSignWorkflow(operation).orElseThrow());
                SemanticSigningOperation failed = fixture.semantic.find(operation).orElseThrow();
                assertEquals(SemanticSigningState.FAILED, failed.state());
                assertEquals(Optional.of("MANAGED_KEY_PROOF_SIGNATURE_INVALID"), failed.detailCode());
                assertTrue(failed.result().isEmpty());
            }
        }
    }

    @Test void liveAndCompletedSnapshotsRestoreWithoutRequiringRetiredChallenge(@TempDir Path root) throws Exception {
        for (DomainContinuationStore.State cut : List.of(DomainContinuationStore.State.SIGNING,
                DomainContinuationStore.State.PUBLISHING, DomainContinuationStore.State.COMPLETED)) {
            Provider provider = new Provider(false);
            Path source = root.resolve(cut.name());
            Path snapshot = root.resolve(cut.name() + "-snapshot");
            PkiId operation;
            EncodedObject signature;
            try (FilesystemPkiStore store = open(source)) {
                Fixture fixture = new Fixture(store, provider);
                operation = fixture.semantic.accept(fixture.prepare()).receipt().operationId();
                signature = provider.sign(PkiTestRuntime.readContent(store,
                        store.getSignWorkflow(operation).orElseThrow().envelope().candidate()));
                if (cut != DomainContinuationStore.State.SIGNING) {
                    sign(store, operation, signature);
                    store.transitionDomainContinuation(operation, 0, DomainContinuationStore.State.PUBLISHING,
                            Optional.empty(), Optional.empty()).orElseThrow();
                }
                if (cut == DomainContinuationStore.State.COMPLETED) { fixture.driver.advance(store.getSignWorkflow(operation).orElseThrow()); }
                store.exportSnapshot(snapshot, Instant.MAX);
            }
            try (FilesystemPkiStore store = open(snapshot)) {
                Fixture fixture = new Fixture(store, provider);
                assertEquals(cut.name(), fixture.semantic.find(operation).orElseThrow().state().name());
                if (cut == DomainContinuationStore.State.SIGNING) { sign(store, operation, signature); }
                fixture.driver.advance(store.getSignWorkflow(operation).orElseThrow());
                assertEquals(SemanticSigningState.COMPLETED, fixture.semantic.find(operation).orElseThrow().state());
            }
            try (FilesystemPkiStore store = open(snapshot)) {
                assertEquals(SemanticSigningState.COMPLETED, new Fixture(store, provider).semantic.find(operation).orElseThrow().state());
            }
        }
    }

    @Test void capacityUnknownAcceptanceAndConcurrentTerminalAdvancementPreserveCustody(@TempDir Path root) throws Exception {
        Provider provider = new Provider(false);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root.resolve("capacity"), 1, CLOCK)) {
            Fixture fixture = new Fixture(store, provider);
            fixture.semantic.accept(fixture.prepare());
            PreparedSemanticSigningRequest second = fixture.prepare();
            assertEquals(SigningAcceptanceDisposition.CAPACITY_REJECTED, fixture.semantic.accept(second).disposition());
            assertThrows(IllegalStateException.class, () -> fixture.semantic.discard(second));
            assertTrue(store.getSignWorkflow(second.receipt().operationId()).isEmpty());
        }
        try (FilesystemPkiStore store = open(root.resolve("unknown"))) {
            Fixture fixture = new Fixture(store, provider, store, (command, custody) -> {
                custody.run();
                store.acceptSign(command);
                throw new IllegalStateException("controlled acknowledgement loss");
            });
            PreparedSemanticSigningRequest prepared = fixture.prepare();
            assertThrows(IllegalStateException.class, () -> fixture.semantic.accept(prepared));
            assertEquals(SigningAcceptanceResolution.MATCHED, fixture.semantic.resolve(prepared.receipt()));
            assertThrows(IllegalStateException.class, () -> fixture.semantic.discard(prepared));
            PkiId operation = prepared.receipt().operationId();
            sign(store, operation, provider.sign(PkiTestRuntime.readContent(store,
                    store.getSignWorkflow(operation).orElseThrow().envelope().candidate())));
            SignWorkflowStore.Workflow workflow = store.getSignWorkflow(operation).orElseThrow();
            CyclicBarrier barrier = new CyclicBarrier(2);
            try (java.util.concurrent.ExecutorService workers = Executors.newFixedThreadPool(2)) {
                List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
                for (int index = 0; index < 2; index++) {
                    futures.add(workers.submit(() -> {
                        barrier.await(5, TimeUnit.SECONDS);
                        fixture.driver.advance(workflow);
                        return null;
                    }));
                }
                for (java.util.concurrent.Future<?> future : futures) { future.get(10, TimeUnit.SECONDS); }
            }
            assertEquals(SemanticSigningState.COMPLETED, fixture.semantic.find(operation).orElseThrow().state());
        }
    }

    @Test void adoptionFailureRetiresOnlyUnownedCandidate(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            Provider provider = new Provider(false);
            AtomicInteger retired = new AtomicInteger();
            StagedContentStore staging = proxy(StagedContentStore.class, store.stagedContent(), (method, args) -> {
                if (method.equals("restoreReference")) { throw new IOException("controlled adoption failure"); }
                if (method.equals("retireUnownedContent")) { retired.incrementAndGet(); }
                return PROCEED;
            });
            PkiStore fault = proxy(PkiStore.class, store, (method, args) -> method.equals("stagedContent") ? staging : PROCEED);
            Fixture fixture = new Fixture(store, provider, fault, (command, custody) -> { throw new AssertionError("No acceptance"); });
            assertThrows(PkiException.class, fixture::prepare);
            assertEquals(1, retired.get());
            assertEquals(0, provider.dispatches.get());
        }
    }

    @Test void completedMarkerCorruptionFailsObservationAndReopen(@TempDir Path root) throws Exception {
        Provider provider = new Provider(false);
        try (FilesystemPkiStore store = open(root)) {
            Fixture fixture = new Fixture(store, provider);
            PkiId operation = fixture.semantic.accept(fixture.prepare()).receipt().operationId();
            sign(store, operation, provider.sign(PkiTestRuntime.readContent(store,
                    store.getSignWorkflow(operation).orElseThrow().envelope().candidate())));
            fixture.driver.advance(store.getSignWorkflow(operation).orElseThrow());
            DomainContinuationStore.Record domain = store.getDomainContinuation(operation).orElseThrow();
            store.transitionDomainContinuation(operation, domain.revision(), DomainContinuationStore.State.COMPLETED,
                    Optional.of(new EncodedObject(Encoding.BINARY, ("proof:" + "0".repeat(64)).getBytes(StandardCharsets.US_ASCII))),
                    Optional.of("COMPLETED")).orElseThrow();
            assertThrows(RuntimeException.class, () -> fixture.semantic.find(operation));
        }
        assertThrows(RuntimeException.class, () -> open(root));
    }

    @Test void pendingObservationDoesNotOpenChallengeAfterConcurrentCompletionAndRetirement(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            Provider provider = new Provider(false);
            Fixture fixture = new Fixture(store, provider);
            PkiId operation = fixture.semantic.accept(fixture.prepare()).receipt().operationId();
            DurableContentReference candidate = store.getSignWorkflow(operation).orElseThrow().envelope().candidate();
            sign(store, operation, provider.sign(PkiTestRuntime.readContent(store, candidate)));
            AtomicInteger contentOpens = new AtomicInteger();
            StagedContentStore metadataOnly = proxy(StagedContentStore.class, store.stagedContent(), (method, args) -> {
                if (method.equals("openContent")) {
                    contentOpens.incrementAndGet();
                    throw new AssertionError("Semantic observation must not reopen challenge bytes");
                }
                return PROCEED;
            });
            java.util.concurrent.atomic.AtomicBoolean completeOnce = new java.util.concurrent.atomic.AtomicBoolean(true);
            PkiStore observedStore = proxy(PkiStore.class, store, (method, args) -> {
                if (method.equals("stagedContent")) { return metadataOnly; }
                if (method.equals("getDomainContinuation") && args.length == 1 && operation.equals(args[0])
                        && completeOnce.compareAndSet(true, false)) {
                    DomainContinuationStore.Record pending = store.getDomainContinuation(operation).orElseThrow();
                    assertEquals(DomainContinuationStore.State.SIGNING, pending.state());
                    fixture.driver.advance(store.getSignWorkflow(operation).orElseThrow());
                    assertEquals(DomainContinuationStore.State.COMPLETED, store.getDomainContinuation(operation).orElseThrow().state());
                    assertEquals(SignWorkflowStore.State.RETIRED, store.getSignWorkflow(operation).orElseThrow().state());
                    assertThrows(Exception.class, () -> store.stagedContent().openContent(candidate));
                    return Optional.of(pending);
                }
                return PROCEED;
            });
            Fixture observer = new Fixture(store, provider, observedStore,
                    (command, custody) -> { throw new AssertionError("Observation cannot accept signing"); });
            SemanticSigningOperation pending = observer.semantic.find(operation).orElseThrow();
            assertEquals(SemanticSigningState.SIGNING, pending.state());
            assertEquals(zeroecho.pki.api.signing.SigningOperationState.SUCCEEDED, pending.signingState());
            assertTrue(pending.result().isEmpty());
            assertEquals(Optional.of(AUTHORITY), pending.scope().authorityId());
            assertEquals(SemanticSigningState.COMPLETED, observer.semantic.find(operation).orElseThrow().state());
            assertEquals(0, contentOpens.get());
        }
    }

    @Test void acceptanceRejectsFrozenEnvelopeAndChallengeMismatchesBeforeCreatingWorkflow(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            Provider provider = new Provider(false);
            Fixture fixture = new Fixture(store, provider);
            for (int index = 0; index < 9; index++) {
                DomainSigningRequest domain = fixture.preparation.prepare(ACCESS, new ManagedKeyProofRequest.OcspResponder(
                        AUTHORITY, new PkiId("responder"), KEY), fixture.signing.newSubmissionId(), TTL, CancellationSignal.NONE);
                List<String> fields = new ArrayList<>(DomainCommandEncoding.decode(domain.domainTemplate().command()).fields());
                // Last two cases preserve envelope scalars but contradict the exact challenge.
                if (index == 7) { fields.set(11, "0".repeat(64)); }
                if (index == 8) { fields.set(4, "different-responder"); }
                DomainContinuationTemplate template = DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.KEY_PROOF,
                        index == 6 ? "wrong-correlation" : domain.domainTemplate().correlationId().orElseThrow(),
                        ManagedKeyProofCommand.OPERATION, fields.toArray(String[]::new));
                SignWorkflowStore.AcceptanceCommand accepted = new SignWorkflowStore.AcceptanceCommand(domain.operationId(),
                        fields.get(6), index == 0 ? new SigningProvider.ConfigurationCommitment(
                                java.util.HexFormat.of().parseHex("01" + "00".repeat(31)))
                                : provider.configurationCommitment(), ACCESS,
                        index == 1 ? new KeyRef("different-key") : KEY,
                        index == 2 ? new PkiId("different-authority") : AUTHORITY,
                        index == 3 ? BootstrapAlgorithmIdentities.ED448_SIGNATURE.canonicalForm() : domain.algorithmId(),
                        index == 4 ? Encoding.DER : Encoding.BINARY,
                        index == 5 ? NOW.minusSeconds(1) : NOW, NOW.plus(TTL), domain.content(),
                        Optional.of(new SignWorkflowStore.OuterCommand(template.kind(), template.correlationId().orElseThrow(),
                                template.command(), template.commandCommitment())), SignWorkflowStore.Mode.NORMAL, java.util.Optional.empty());
                assertThrows(RuntimeException.class, () -> store.acceptSign(accepted));
                assertTrue(store.getSignWorkflow(domain.operationId()).isEmpty());
                assertTrue(store.getDomainContinuation(domain.operationId()).isEmpty());
                assertThrows(Exception.class, () -> store.stagedContent().openContent(domain.content()));
            }
        }
    }

    private static FilesystemPkiStore open(Path root) { return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK); }
    private static void sign(FilesystemPkiStore store, PkiId operation, EncodedObject signature) {
        SignWorkflowStore.Workflow claimed = store.claimSignStep(operation, 0, Duration.ofSeconds(10)).orElseThrow();
        store.transitionSign(operation, claimed.revision(), claimed.fence(), SignWorkflowStore.State.SUCCEEDED,
                Optional.of("SIGNED"), Optional.of(signature), Optional.of(NOW)).orElseThrow();
    }

    private static final Object PROCEED = new Object();
    @FunctionalInterface private interface Intercept { Object call(String method, Object[] args) throws Exception; }
    private static <T> T proxy(Class<T> type, T delegate, Intercept intercept) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, (proxy, method, args) -> {
            Object result = intercept.call(method.getName(), args);
            if (result != PROCEED) { return result; }
            try { return method.invoke(delegate, args); }
            catch (InvocationTargetException failure) { throw failure.getCause(); }
        }));
    }

    private static final class Fixture {
        private final BcX509VerificationExecutor verifier = new BcX509VerificationExecutor();
        private final X509AuthoritySnapshot authority = X509AuthoritySnapshot.compose(List.of(), List.of(verifier),
                List.of(X509AuthoritySnapshot.bindExecutor(BcX509VerificationExecutor.IMPLEMENTATION_ID,
                        Direction.VERIFY, verifier)), (suite, direction) -> direction == Direction.VERIFY);
        private final DefaultSigningService signing;
        private final DefaultSemanticSigningService semantic;
        private final SigningOuterTerminalDriver driver;
        private final ManagedKeyProofPreparation preparation;
        Fixture(FilesystemPkiStore store, Provider provider) {
            this(store, provider, store, (command, custody) -> { custody.run(); return store.acceptSign(command); });
        }
        Fixture(FilesystemPkiStore actual, Provider provider, PkiStore store, DefaultSigningService.AcceptanceOperation acceptance) {
            signing = new DefaultSigningService(store, provider, provider.algorithm, TTL, new SecureRandom(),
                    () -> { }, acceptance, () -> { },
                (boundedWaitId, boundedWaitCancellation) -> { throw new UnsupportedOperationException("Fixture has no reactor wait"); });
            preparation = new ManagedKeyProofPreparation(store, provider, PkiTestRuntime.signingAuthority(provider), authority,
                    verifier, provider.algorithm.canonicalForm(), new SecureRandom(), ManagedKeyProofCommand.MAX_CHALLENGE_BYTES);
            semantic = new DefaultSemanticSigningService(store, signing, PkiTestRuntime.endEntityPreparation(store, CLOCK),
                    ManagedKeyProofCommand.MAX_CHALLENGE_BYTES, Optional.empty(), Optional.of(preparation));
            driver = new SigningOuterTerminalDriver(actual, authority, verifier, ManagedKeyProofCommand.MAX_CHALLENGE_BYTES);
        }
        PreparedSemanticSigningRequest prepare() {
            return semantic.prepareManagedKeyProof(ACCESS, new ManagedKeyProofRequest.CaSubject(AUTHORITY, Optional.empty(),
                    "root-profile", KEY), CancellationSignal.NONE);
        }
    }

    private static final class Provider implements SigningProvider, PublicKeyInfoSource {
        private final AlgorithmIdentity algorithm;
        private final boolean rsa;
        private final KeyPair key;
        private final AtomicInteger dispatches = new AtomicInteger();
        Provider(boolean rsa) throws Exception {
            this.rsa = rsa;
            algorithm = rsa ? BootstrapAlgorithmIdentities.RSA_PSS_SHA256 : BootstrapAlgorithmIdentities.ED25519_SIGNATURE;
            KeyPairGenerator generator = KeyPairGenerator.getInstance(rsa ? "RSA" : "Ed25519");
            if (rsa) { generator.initialize(2048); }
            key = generator.generateKeyPair();
        }
        EncodedObject sign(byte[] bytes) throws Exception {
            Signature signature = Signature.getInstance(rsa ? "RSASSA-PSS" : "Ed25519");
            if (rsa) { signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)); }
            signature.initSign(key.getPrivate());
            signature.update(bytes);
            return new EncodedObject(Encoding.BINARY, signature.sign());
        }
        @Override public String id() { return "proof-test"; }
        @Override public ConfigurationCommitment configurationCommitment() { return new ConfigurationCommitment(new byte[32]); }
        @Override public Set<String> supportedAlgorithms() { return Set.of(algorithm.canonicalForm()); }
        @Override public SigningInputCapabilities inputCapabilities() { return new SigningInputCapabilities(4_000_000, Map.of()); }
        @Override public EncodedObject resolvePublicKeyInfo(KeyRef keyRef) {
            assertEquals(KEY, keyRef);
            return new EncodedObject(Encoding.DER, key.getPublic().getEncoded());
        }
        @Override public OperationObservation dispatch(SignRequest request, CallControl control) {
            dispatches.incrementAndGet();
            throw new AssertionError("Preparation and local terminal verification do not dispatch");
        }
        @Override public OperationObservation reconcile(PkiId id, CallControl control) { throw new AssertionError("No reconcile"); }
        @Override public OperationObservation cancel(PkiId id, long fence, CancellationReason reason, CallControl control) {
            throw new AssertionError("No provider cancellation");
        }
        @Override public void close() { }
    }
}
