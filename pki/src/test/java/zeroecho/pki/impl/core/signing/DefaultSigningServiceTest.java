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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.OneShotContent;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.signing.PreparedSigningRequest;
import zeroecho.pki.api.signing.SigningAcceptanceDisposition;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.api.signing.SigningAcceptanceResolution;
import zeroecho.pki.api.signing.SigningRequest;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FilesystemPkiStoreTestAccess;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.StagedContentStore;

@SuppressWarnings({ "PMD.UnitTestAssertionsShouldIncludeMessage",
        "PMD.UnitTestContainsTooManyAsserts" })
final class DefaultSigningServiceTest {
    private static final Instant NOW = Instant.parse("2026-01-02T03:04:05Z");
    private static final AccessContext ACCESS = new AccessContext(
            new Principal("TEST", "signer"), new Purpose("SIGN"),
            Optional.empty(), Optional.empty());

    @Test
    void rawLimitRejectsBeforeCustodyAndAnyDurableAcceptance(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, new MutableClock(NOW));
                TestProvider provider = new TestProvider()) {
            provider.inputs = new zeroecho.pki.spi.crypto.SigningInputCapabilities(10, java.util.Map.of());
            AtomicInteger wakes = new AtomicInteger();
            DefaultSigningService service = service(store, provider, wakes::incrementAndGet);
            PreparedSigningRequest oversized = service.prepare(request(service), oneShot(new byte[11]),
                    CancellationSignal.NONE);
            assertThrows(IllegalArgumentException.class, () -> service.accept(oversized));
            assertFalse(store.listSignWorkflows().iterator().hasNext());
            assertEquals(SigningAcceptanceResolution.NOT_ACCEPTED, service.resolve(oversized.receipt()));
            assertEquals(0, wakes.get());
            service.discard(oversized);
            for (int length : new int[] { 9, 10 }) {
                PreparedSigningRequest prepared = service.prepare(request(service), oneShot(new byte[length]),
                        CancellationSignal.NONE);
                assertEquals(SigningAcceptanceDisposition.ACCEPTED, service.accept(prepared).disposition());
            }
        }
    }

    @Test
    void requestSpecificInputLimitAcceptsRsaDigestButRejectsNondefaultPureEd(@TempDir Path root) throws Exception {
        String rsa = zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm();
        AlgorithmIdentity ed = BootstrapAlgorithmIdentities.ED25519_SIGNATURE;
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, new MutableClock(NOW));
                TestProvider provider = new TestProvider()) {
            provider.inputs = new zeroecho.pki.spi.crypto.SigningInputCapabilities(10,
                    java.util.Map.of(rsa, zeroecho.core.alg.BootstrapAlgorithmIdentities.SHA256));
            DefaultSigningService rsaService = service(store, provider, () -> { });
            PreparedSigningRequest rsaRequest = rsaService.prepare(request(rsaService), oneShot(new byte[11]),
                    CancellationSignal.NONE);
            assertEquals(SigningAcceptanceDisposition.ACCEPTED, rsaService.accept(rsaRequest).disposition());
            PreparedSigningRequest edRequest = rsaService.prepare(request(rsaService, ed), oneShot(new byte[11]),
                    CancellationSignal.NONE);
            assertThrows(IllegalArgumentException.class, () -> rsaService.accept(edRequest));
            assertTrue(store.getSignWorkflow(edRequest.receipt().operationId()).isEmpty());
            rsaService.discard(edRequest);
        }
    }

    @Test
    void nondefaultAlgorithmIsFrozenInPreparationEnvelopeAndReceipt(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, new MutableClock(NOW));
                TestProvider provider = new TestProvider()) {
            DefaultSigningService service = service(store, provider, () -> { });
            SigningRequest request = request(service, BootstrapAlgorithmIdentities.ED25519_SIGNATURE);
            PreparedSigningRequest prepared = service.prepare(request, oneShot(new byte[] {1, 2}), CancellationSignal.NONE);
            assertEquals(BootstrapAlgorithmIdentities.ED25519_SIGNATURE, prepared.request().signatureAlgorithm());
            SignWorkflowStore.AcceptanceCommand exact = new SignWorkflowStore.AcceptanceCommand(request.submissionId().id(),
                    request.submissionId().namespace(), provider.configurationCommitment(), ACCESS, request.keyRef(),
                    request.fairnessAuthorityId(), request.signatureAlgorithm().canonicalForm(), Encoding.BINARY,
                    request.submissionId().createdAt(), request.submissionId().createdAt().plus(Duration.ofMinutes(1)),
                    prepared.candidate(), Optional.empty(), SignWorkflowStore.Mode.NORMAL, java.util.Optional.empty());
            assertEquals(exact.commitment().encoded(), prepared.receipt().encodedCommitment());
            assertEquals(SigningAcceptanceDisposition.ACCEPTED, service.accept(prepared).disposition());
            assertEquals(exact.algorithmId(), store.getSignWorkflow(request.submissionId().id()).orElseThrow().envelope().algorithmId());
            assertEquals(SigningAcceptanceResolution.MATCHED, service.resolve(prepared.receipt()));
        }
    }

    @Test
    void unsupportedWrongKindAndSecurityFloorFailBeforeCandidateStaging(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore actual = FilesystemPkiStoreTestAccess.open(root, 4, new MutableClock(NOW));
                TestProvider provider = new TestProvider()) {
            AtomicInteger stages = new AtomicInteger();
            StagedContentStore staging = stagedProxy((proxy, method, args) -> {
                if (method.getName().equals("stage")) stages.incrementAndGet();
                return invoke(actual.stagedContent(), method, args);
            });
            DefaultSigningService service = service(storeProxy(actual, staging), provider, () -> { });
            AtomicBoolean opened = new AtomicBoolean();
            assertThrows(IllegalArgumentException.class, () -> service.prepare(
                    request(service, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384), observedContent(opened, new byte[] {1}), CancellationSignal.NONE));
            assertThrows(IllegalArgumentException.class, () -> request(service, BootstrapAlgorithmIdentities.SHA256));
            AlgorithmIdentity sha1 = new AlgorithmIdentity(AlgorithmIdentity.Kind.SIGNATURE,
                    new AlgorithmIdentity.Family("test", "sha1-signature"), AlgorithmIdentity.NoParameters.INSTANCE);
            IllegalArgumentException floor = assertThrows(IllegalArgumentException.class, () -> service.prepare(
                    request(service, sha1), observedContent(opened, new byte[] {1}), CancellationSignal.NONE));
            assertTrue(floor.getMessage().contains("SHA-1"));
            assertThrows(IllegalArgumentException.class, () -> service(actual, provider, () -> { }, sha1));
            assertEquals(0, stages.get());
            assertFalse(opened.get());
            assertFalse(actual.listSignWorkflows().iterator().hasNext());
        }
    }

    @Test
    void domainAdoptionStillRequiresConfiguredDefaultAndLifetime(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, new MutableClock(NOW));
                TestProvider provider = new TestProvider()) {
            DefaultSigningService service = service(store, provider, () -> { });
            PreparedSigningRequest raw = service.prepare(request(service), oneShot(new byte[] {1}), CancellationSignal.NONE);
            DomainContinuationTemplate template = DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.CA,
                    "algorithm-boundary", "CREATE_ROOT", "x509");
            SignWorkflowStore.OuterCommand outer = new SignWorkflowStore.OuterCommand(template.kind(),
                    template.correlationId().orElseThrow(), template.command(), template.commandCommitment());
            DomainSigningRequest otherAlgorithm = new DomainSigningRequest(raw.receipt().operationId(), ACCESS, raw.request().keyRef(),
                    BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm(), Encoding.BINARY, raw.candidate(), Duration.ofMinutes(1), template, java.util.Optional.empty());
            assertThrows(IllegalArgumentException.class, () -> service.prepareDomain(otherAlgorithm, raw.request().fairnessAuthorityId(), outer));
            DomainSigningRequest otherLifetime = new DomainSigningRequest(raw.receipt().operationId(), ACCESS, raw.request().keyRef(),
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(), Encoding.BINARY, raw.candidate(), Duration.ofMinutes(2), template, java.util.Optional.empty());
            assertThrows(IllegalArgumentException.class, () -> service.prepareDomain(otherLifetime, raw.request().fairnessAuthorityId(), outer));
            assertFalse(store.listSignWorkflows().iterator().hasNext());
            service.discard(raw);
        }
    }

    @Test
    void twoPhaseCustodyAcceptResolveAndDiscardAreExact(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock);
                TestProvider provider = new TestProvider()) {
            AtomicInteger wakes = new AtomicInteger();
            DefaultSigningService service = service(store, provider, wakes::incrementAndGet);
            SigningRequest request = request(service);
            PreparedSigningRequest prepared = service.prepare(request,
                    oneShot(new byte[] { 1, 2, 3 }), CancellationSignal.NONE);

            assertTrue(store.getSignWorkflow(request.submissionId().id()).isEmpty());
            assertEquals("PreparedSigningRequest[redacted]", prepared.toString());
            assertEquals("SigningAcceptanceReceipt[redacted]", prepared.receipt().toString());
            assertEquals(SigningAcceptanceDisposition.ACCEPTED,
                    service.accept(prepared).disposition());
            assertEquals(1, wakes.get());
            assertEquals(SigningAcceptanceResolution.MATCHED,
                    service.resolve(prepared.receipt()));
            SigningAcceptanceReceipt restoredReceipt = SigningAcceptanceReceipt.parse(
                    prepared.receipt().operationId(), prepared.receipt().encodedCommitment());
            assertEquals(prepared.receipt(), restoredReceipt);
            assertEquals(prepared.receipt().hashCode(), restoredReceipt.hashCode());
            assertFalse(prepared.receipt().equals(SigningAcceptanceReceipt.parse(
                    service.newSubmissionId().id(), prepared.receipt().encodedCommitment())));
            assertThrows(IllegalStateException.class, () -> service.accept(prepared));

            PkiId foreign = SigningSubmissionId.create("foreign.test-signer", NOW,
                    new SecureRandom()).id();
            assertTrue(service.cancel(foreign).isEmpty());

            PreparedSigningRequest discarded = service.prepare(request(service),
                    oneShot(new byte[] { 4 }), CancellationSignal.NONE);
            service.discard(discarded);
            assertThrows(IllegalStateException.class, () -> service.discard(discarded));
        }
    }

    @Test
    void uncertainAcceptanceRemainsRecoverableByReceipt(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock);
                TestProvider provider = new TestProvider()) {
            AtomicBoolean failAfterAccept = new AtomicBoolean(true);
            PkiStore uncertainStore = (PkiStore) Proxy.newProxyInstance(
                    PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                    (proxy, method, arguments) -> {
                        try {
                            Object result = method.invoke(store, arguments);
                            if ("acceptSign".equals(method.getName())
                                    && failAfterAccept.getAndSet(false)) {
                                throw new IllegalStateException("controlled uncertain outcome");
                            }
                            return result;
                        } catch (InvocationTargetException wrapped) {
                            throw wrapped.getCause();
                        }
                    });
            DefaultSigningService service = service(uncertainStore, provider, () -> { });
            PreparedSigningRequest prepared = service.prepare(request(service),
                    oneShot(new byte[] { 9 }), CancellationSignal.NONE);

            assertThrows(IllegalStateException.class, () -> service.accept(prepared));
            assertEquals(SigningAcceptanceResolution.MATCHED,
                    service.resolve(prepared.receipt()));
            assertTrue(service.find(prepared.receipt().operationId()).isPresent());
            assertThrows(IllegalStateException.class, () -> service.discard(prepared));
        }
    }

    @Test
    void serviceRejectsNonBinarySignatureContractBeforeStaging(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock);
                TestProvider provider = new TestProvider()) {
            DefaultSigningService service = service(store, provider, () -> { });
            assertThrows(IllegalArgumentException.class, () -> new SigningRequest(
                    service.newSubmissionId(), ACCESS, new KeyRef("test-key"),
                    new PkiId("authority"), BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, Encoding.BINARY, Encoding.DER));
            assertFalse(store.listSignWorkflows().iterator().hasNext());
        }
    }

    @Test
    void oversizedAcceptanceMetadataIsRejectedBeforeCandidateOpen(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock);
                TestProvider provider = new TestProvider()) {
            DefaultSigningService service = service(store, provider, () -> { });
            AtomicBoolean opened = new AtomicBoolean();
            OneShotContent candidate = observedContent(opened, new byte[] { 1 });
            SigningRequest request = new SigningRequest(service.newSubmissionId(), ACCESS,
                    new KeyRef("k".repeat(1_048_577)), new PkiId("authority"), BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                    Encoding.BINARY, Encoding.BINARY);

            assertThrows(IllegalArgumentException.class,
                    () -> service.prepare(request, candidate, CancellationSignal.NONE));
            assertFalse(opened.get());
        }
    }

    @Test
    void transientDiscardFailureLeavesPreparedRequestRetryable(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock);
                TestProvider provider = new TestProvider()) {
            AtomicBoolean failOnce = new AtomicBoolean(true);
            StagedContentStore flakyStaging = stagedProxy((proxy, method, arguments) -> {
                if ("retireUnownedContent".equals(method.getName())
                        && failOnce.getAndSet(false)) {
                    throw new IOException("controlled cleanup failure");
                }
                return invoke(store.stagedContent(), method, arguments);
            });
            DefaultSigningService service = service(
                    storeProxy(store, flakyStaging), provider, () -> { });
            PreparedSigningRequest prepared = service.prepare(request(service),
                    oneShot(new byte[] { 2 }), CancellationSignal.NONE);

            assertThrows(PkiException.class, () -> service.discard(prepared));
            service.discard(prepared);
            assertThrows(IllegalStateException.class, () -> service.discard(prepared));
        }
    }

    @Test
    void discardExcludesConcurrentAcceptanceUntilCleanupCompletes(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock);
                TestProvider provider = new TestProvider()) {
            CountDownLatch discardRestoreEntered = new CountDownLatch(1);
            CountDownLatch releaseDiscard = new CountDownLatch(1);
            AtomicBoolean blockNextRestore = new AtomicBoolean();
            StagedContentStore blockedStaging = stagedProxy((proxy, method, arguments) -> {
                if ("restoreReference".equals(method.getName())
                        && blockNextRestore.compareAndSet(true, false)) {
                    discardRestoreEntered.countDown();
                    assertTrue(releaseDiscard.await(5L, TimeUnit.SECONDS));
                }
                return invoke(store.stagedContent(), method, arguments);
            });
            AtomicInteger acceptCalls = new AtomicInteger();
            PkiStore exactStore = storeProxy(store, blockedStaging);
            DefaultSigningService service = new DefaultSigningService(exactStore, provider,
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, Duration.ofMinutes(1L), new SecureRandom(), () -> { },
                    (command, transferCustody) -> {
                        transferCustody.run();
                        acceptCalls.incrementAndGet();
                        return exactStore.acceptSign(command);
                    }, () -> { },
                (boundedWaitId, boundedWaitCancellation) -> { throw new UnsupportedOperationException("Fixture has no reactor wait"); });
            PreparedSigningRequest prepared = service.prepare(request(service),
                    oneShot(new byte[] { 3 }), CancellationSignal.NONE);
            blockNextRestore.set(true);
            AtomicReference<Throwable> discardFailure = new AtomicReference<>();
            Thread discard = new Thread(() -> {
                try {
                    service.discard(prepared);
                } catch (Throwable failure) {
                    discardFailure.set(failure);
                }
            }, "signing-discard-race");
            discard.start();
            assertTrue(discardRestoreEntered.await(5L, TimeUnit.SECONDS));

            assertThrows(IllegalStateException.class, () -> service.accept(prepared));
            assertEquals(0, acceptCalls.get());
            releaseDiscard.countDown();
            discard.join(TimeUnit.SECONDS.toMillis(5L));
            assertFalse(discard.isAlive());
            assertTrue(discardFailure.get() == null);
        }
    }

    @Test
    void boundedDispatchRechecksDeadlineAfterOpeningCandidate(@TempDir Path root) throws Exception {
        AtomicReference<Instant> now = new AtomicReference<>(NOW);
        Clock clock = new Clock() {
            @Override public ZoneId getZone() { return java.time.ZoneOffset.UTC; }
            @Override public Clock withZone(ZoneId zone) { return this; }
            @Override public Instant instant() { return now.get(); }
        };
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock);
                TestProvider provider = new TestProvider()) {
            AtomicBoolean opened = new AtomicBoolean();
            StagedContentStore staging = stagedProxy((proxy, method, arguments) -> {
                Object result = invoke(store.stagedContent(), method, arguments);
                if ("openContent".equals(method.getName()) && opened.compareAndSet(false, true)) {
                    now.set(NOW.plusSeconds(60));
                }
                return result;
            });
            PkiStore observed = storeProxy(store, staging);
            zeroecho.pki.application.PkiSessionConfiguration.SigningTopology topology =
                    new zeroecho.pki.application.PkiSessionConfiguration.SigningTopology(
                            new zeroecho.pki.application.PkiSessionConfiguration.SigningCoordinatorLimits(4,
                                    Duration.ofSeconds(10), Duration.ofSeconds(5), Duration.ofMillis(5), Duration.ofSeconds(2)),
                            java.util.List.of(), new zeroecho.pki.application.PkiSessionConfiguration.SigningLanePool(1, 4));
            try (SigningReactor reactor = new SigningReactor(observed, provider, topology, ignored -> { })) {
                DefaultSigningService service = new DefaultSigningService(observed, provider,
                        BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, Duration.ofSeconds(60), new SecureRandom(),
                        reactor::requireAccepting, reactor::acceptSign, reactor::wake, reactor::awaitBoundedObservation);
                PreparedSigningRequest prepared = service.prepareBoundedObservation(request(service), oneShot(new byte[] { 1 }),
                        CancellationSignal.NONE);
                service.accept(prepared);
                reactor.start();
                assertEquals(zeroecho.pki.api.signing.SigningOperationState.EXPIRED,
                        service.awaitBoundedObservation(prepared.receipt().operationId(), CancellationSignal.NONE)
                                .orElseThrow().state());
                assertTrue(opened.get());
                assertEquals(0, provider.dispatches.get());
                assertEquals(SignWorkflowStore.InitialAttemptPhase.COMPLETED,
                        store.getSignWorkflow(prepared.receipt().operationId()).orElseThrow().initialAttemptPhase());
            }
        }
    }

    private static DefaultSigningService service(PkiStore store,
            SigningProvider provider, Runnable wake) {
        return service(store, provider, wake, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256);
    }

    private static DefaultSigningService service(PkiStore store,
            SigningProvider provider, Runnable wake, AlgorithmIdentity algorithm) {
        return new DefaultSigningService(store, provider, algorithm,
                Duration.ofMinutes(1L), new SecureRandom(), () -> { },
                (command, transferCustody) -> {
                    transferCustody.run();
                    return store.acceptSign(command);
                }, wake,
                (boundedWaitId, boundedWaitCancellation) -> { throw new UnsupportedOperationException("Fixture has no reactor wait"); });
    }

    private static SigningRequest request(DefaultSigningService service) {
        return request(service, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256);
    }

    private static SigningRequest request(DefaultSigningService service, AlgorithmIdentity algorithm) {
        return new SigningRequest(service.newSubmissionId(), ACCESS,
                new KeyRef("test-key"), new PkiId("authority"), algorithm,
                Encoding.BINARY, Encoding.BINARY);
    }

    private static OneShotContent oneShot(byte[] value) {
        byte[] snapshot = value.clone();
        return new OneShotContent() {
            private boolean opened;
            @Override public InputStream openStream() {
                if (opened) throw new IllegalStateException("already opened");
                opened = true;
                return new ByteArrayInputStream(snapshot);
            }
            @Override public OptionalLong length() { return OptionalLong.of(snapshot.length); }
            @Override public void close() { }
        };
    }

    private static OneShotContent observedContent(AtomicBoolean opened, byte[] value) {
        byte[] snapshot = value.clone();
        return new OneShotContent() {
            @Override public InputStream openStream() {
                opened.set(true);
                return new ByteArrayInputStream(snapshot);
            }
            @Override public OptionalLong length() { return OptionalLong.of(snapshot.length); }
            @Override public void close() { }
        };
    }

    private static PkiStore storeProxy(PkiStore store, StagedContentStore stagedContent) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class }, (proxy, method, arguments) -> {
                    if ("stagedContent".equals(method.getName())) {
                        return stagedContent;
                    }
                    return invoke(store, method, arguments);
                });
    }

    private static StagedContentStore stagedProxy(
            java.lang.reflect.InvocationHandler handler) {
        return (StagedContentStore) Proxy.newProxyInstance(
                StagedContentStore.class.getClassLoader(),
                new Class<?>[] { StagedContentStore.class }, handler);
    }

    private static Object invoke(Object target, java.lang.reflect.Method method,
            Object[] arguments) throws Throwable {
        try {
            return method.invoke(target, arguments);
        } catch (InvocationTargetException wrapped) {
            throw wrapped.getCause();
        }
    }

    private static final class TestProvider implements SigningProvider {
        private final AtomicInteger dispatches = new AtomicInteger();
        private zeroecho.pki.spi.crypto.SigningInputCapabilities inputs =
                new zeroecho.pki.spi.crypto.SigningInputCapabilities(Long.MAX_VALUE, java.util.Map.of());
        @Override public zeroecho.pki.spi.crypto.SigningInputCapabilities inputCapabilities() {
            return inputs;
        }
        private final ConfigurationCommitment commitment;

        private TestProvider() {
            byte[] value = new byte[ConfigurationCommitment.BYTE_LENGTH];
            Arrays.fill(value, (byte) 17);
            commitment = new ConfigurationCommitment(value);
        }

        @Override public String id() { return "test-signer"; }
        @Override public ConfigurationCommitment configurationCommitment() { return commitment; }
        @Override public Set<String> supportedAlgorithms() {
            return Set.of(zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(),
                    zeroecho.core.alg.BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm());
        }
        @Override public OperationObservation dispatch(SigningProvider.SignRequest request,
                CallControl control) {
            dispatches.incrementAndGet();
            throw new UnsupportedOperationException();
        }
        @Override public OperationObservation reconcile(PkiId operationId, CallControl control) {
            throw new UnsupportedOperationException();
        }
        @Override public OperationObservation cancel(PkiId operationId, long fencingToken,
                CancellationReason reason, CallControl control) {
            throw new UnsupportedOperationException();
        }
        @Override public void close() { }
    }

    private static final class MutableClock extends Clock {
        private final Instant value;
        private MutableClock(Instant value) { this.value = value; }
        @Override public ZoneId getZone() { return java.time.ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return value; }
    }
}
