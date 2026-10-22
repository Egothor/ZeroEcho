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

package zeroecho.pki.impl.core.signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.RepeatedTest;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.OneShotContent;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.signing.PreparedSigningRequest;
import zeroecho.pki.api.signing.SigningOperation;
import zeroecho.pki.api.signing.SigningOperationState;
import zeroecho.pki.api.signing.SigningRequest;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.application.PkiSessionConfiguration.SigningCoordinatorLimits;
import zeroecho.pki.application.PkiSessionConfiguration.SigningKeyGroup;
import zeroecho.pki.application.PkiSessionConfiguration.SigningLanePool;
import zeroecho.pki.application.PkiSessionConfiguration.SigningTopology;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.SigningOuterTerminalDriver;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FilesystemPkiStoreTestAccess;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.PkiTestRuntime;

@SuppressWarnings({ "PMD.DoNotUseThreads", "PMD.UnitTestAssertionsShouldIncludeMessage",
        "PMD.UnitTestContainsTooManyAsserts" })
final class SigningReactorTest {
    private static final Instant NOW = Instant.parse("2026-01-02T03:04:05Z");
    private static final KeyRef EXACT_KEY = new KeyRef("exact-secret-key");
    private static final KeyRef OTHER_KEY = new KeyRef("other-secret-key");
    private static final AccessContext ACCESS = new AccessContext(
            new Principal("TEST", "topology-reactor"), new Purpose("SIGN"),
            Optional.empty(), Optional.empty());

    @Test
    void stepExecutorDispatchesAndAdvancesOuterOnCallingThreadWithoutReactor(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        Thread caller = Thread.currentThread();
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 8, clock)) {
            SigningSubmissionId identity = SigningSubmissionId.create(
                    store.signingNamespace() + ".test-signer", NOW, new SecureRandom());
            AcceptanceFixture fixture = accept(store, identity, EXACT_KEY,
                    new PkiId("authority-a"), Optional.of(outer()));
            RecordingProvider provider = new RecordingProvider(store, 1) {
                @Override void onDispatch(SignRequest request) {
                    assertSame(caller, Thread.currentThread());
                }
            };
            AtomicInteger outerCalls = new AtomicInteger();
            AtomicInteger progressCalls = new AtomicInteger();
            SigningStepExecutor executor = new SigningStepExecutor(store, provider,
                    Duration.ofSeconds(5), terminal -> {
                        assertSame(caller, Thread.currentThread());
                        assertEquals(SignWorkflowStore.State.FAILED, terminal.state());
                        outerCalls.incrementAndGet();
                    });
            SignWorkflowStore.Workflow observed = store.getSignWorkflow(identity.id()).orElseThrow();

            assertFalse(executor.advance(observed, workflow -> {
                assertSame(caller, Thread.currentThread());
                return store.claimSignStep(workflow.operationId(), workflow.revision(), Duration.ofSeconds(10));
            }, CancellationSignal.NONE, () -> {
                assertSame(caller, Thread.currentThread());
                progressCalls.incrementAndGet();
            }));

            assertEquals(1, provider.dispatches.get());
            assertEquals(1, outerCalls.get());
            assertEquals(1, progressCalls.get());
            assertEquals(SignWorkflowStore.State.FAILED,
                    store.getSignWorkflow(fixture.command().operationId()).orElseThrow().state());
        }
    }

    @Test
    void stepExecutorReconcilesRecoveredDispatchWithoutSigningAgain(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        Thread caller = Thread.currentThread();
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 8, clock)) {
            PkiId operationId = accept(store, EXACT_KEY, new PkiId("authority-a")).command().operationId();
            SignWorkflowStore.Workflow intent = store.getSignWorkflow(operationId).orElseThrow();
            store.claimSignStep(operationId, intent.revision(), Duration.ofSeconds(10)).orElseThrow();
            clock.now = NOW.plusSeconds(11);
            AtomicInteger reconciliations = new AtomicInteger();
            RecordingProvider provider = new RecordingProvider(store, 0) {
                @Override public OperationObservation reconcile(PkiId id, CallControl control) {
                    assertSame(caller, Thread.currentThread());
                    reconciliations.incrementAndGet();
                    return failure(id);
                }
            };
            SigningStepExecutor executor = new SigningStepExecutor(store, provider,
                    Duration.ofSeconds(5), ignored -> { throw new AssertionError("No outer continuation"); });

            assertFalse(executor.advance(store.getSignWorkflow(operationId).orElseThrow(),
                    workflow -> store.claimSignStep(workflow.operationId(), workflow.revision(), Duration.ofSeconds(10)),
                    CancellationSignal.NONE, () -> assertSame(caller, Thread.currentThread())));

            assertEquals(0, provider.dispatches.get());
            assertEquals(1, reconciliations.get());
            assertEquals(SignWorkflowStore.State.RETIRED, store.getSignWorkflow(operationId).orElseThrow().state());
        }
    }

    @Test
    void stepExecutorDoesNothingWhenClaimIsNotEligible(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 8, clock)) {
            PkiId operationId = accept(store, EXACT_KEY, new PkiId("authority-a")).command().operationId();
            SignWorkflowStore.Workflow stale = store.getSignWorkflow(operationId).orElseThrow();
            store.claimSignStep(operationId, stale.revision(), Duration.ofSeconds(10)).orElseThrow();
            RecordingProvider provider = new RecordingProvider(store, 0);
            SigningStepExecutor executor = new SigningStepExecutor(store, provider,
                    Duration.ofSeconds(5), ignored -> { throw new AssertionError("No outer continuation"); });

            assertFalse(executor.advance(stale,
                    workflow -> store.claimSignStep(workflow.operationId(), workflow.revision(), Duration.ofSeconds(10)),
                    CancellationSignal.NONE, () -> { throw new AssertionError("No durable progress"); }));

            assertEquals(0, provider.dispatches.get());
            assertEquals(SignWorkflowStore.State.DISPATCHED, store.getSignWorkflow(operationId).orElseThrow().state());
        }
    }

    @Test
    void routesExactAndCatchAllWithFixedDaemonThreadsAndRedactedNames(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 8, clock)) {
            AcceptanceFixture exact = accept(store, EXACT_KEY, new PkiId("authority-a"));
            AcceptanceFixture catchAll = accept(store, OTHER_KEY, new PkiId("authority-b"));
            RecordingProvider provider = new RecordingProvider(store, 2);
            SigningReactor reactor = new SigningReactor(store, provider,
                    topology(4, Duration.ofSeconds(2L),
                            List.of(new SigningKeyGroup(List.of(EXACT_KEY),
                                    new SigningLanePool(1, 2))),
                            new SigningLanePool(1, 2)), ignored -> { });

            reactor.start();
            await(provider.expectedCalls);
            awaitState(store, exact.command().operationId(), SignWorkflowStore.State.RETIRED);
            awaitState(store, catchAll.command().operationId(), SignWorkflowStore.State.RETIRED);

            assertTrue(provider.threadFor(exact.command().operationId()).contains("pool-0"));
            assertTrue(provider.threadFor(catchAll.command().operationId()).contains("pool-1"));
            assertEquals(3, reactor.ownedThreads().size());
            assertTrue(reactor.ownedThreads().stream().allMatch(Thread::isDaemon));
            assertTrue(reactor.ownedThreads().stream()
                    .map(Thread::getName).noneMatch(name -> name.contains(EXACT_KEY.value())
                            || name.contains(OTHER_KEY.value())));
            reactor.close();
        }
    }

    @Test
    void rechecksScheduledCoordinatesAndRouteBeforeClaim(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            AcceptanceFixture fixture = accept(store, EXACT_KEY, new PkiId("authority-a"));
            CountDownLatch authoritativeLoad = new CountDownLatch(1);
            CountDownLatch repeatedScan = new CountDownLatch(1);
            AtomicInteger scanCalls = new AtomicInteger();
            PkiStore mismatched = proxy(store, (method, result) -> {
                if ("pageDueSignWorkflows".equals(method)) {
                    if (scanCalls.incrementAndGet() > 1) {
                        repeatedScan.countDown();
                    }
                    SignWorkflowStore.DuePage page = (SignWorkflowStore.DuePage) result;
                    List<SignWorkflowStore.DueCandidate> candidates = page.candidates().stream()
                            .map(candidate -> new SignWorkflowStore.DueCandidate(
                                    candidate.operationId(),
                                    new SignWorkflowStore.SchedulingCoordinates(OTHER_KEY,
                                            candidate.scheduling().fairnessAuthorityId()),
                                    candidate.malformed()))
                            .toList();
                    return new SignWorkflowStore.DuePage(candidates, page.nextCursor(),
                            page.failures(), page.endReached(), page.highWatermark());
                }
                if ("getSignWorkflow".equals(method)) {
                    authoritativeLoad.countDown();
                }
                return result;
            });
            RecordingProvider provider = new RecordingProvider(store, 0);
            SigningReactor reactor = new SigningReactor(mismatched, provider,
                    topology(1, Duration.ofSeconds(2L),
                            List.of(new SigningKeyGroup(List.of(EXACT_KEY),
                                    new SigningLanePool(1, 1))),
                            new SigningLanePool(1, 1)), ignored -> { });

            reactor.start();
            try {
                await(authoritativeLoad);
                awaitRetainedCount(reactor, 0);
                assertFalse(repeatedScan.await(100L, TimeUnit.MILLISECONDS));
                assertEquals(1, scanCalls.get());
                assertEquals(SignWorkflowStore.State.INTENT,
                        store.getSignWorkflow(fixture.command().operationId()).orElseThrow().state());
                assertEquals(0, provider.dispatches.get());
                reactor.wake();
                await(repeatedScan);
            } finally {
                reactor.close();
            }
        }
    }

    @Test
    void capacityBlockedScannerResumesItsStableCycleWhenLaneFreesSlot(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 8, clock)) {
            List<SigningSubmissionId> identities = sortedIdentities(store, 5);
            for (int index = 0; index < identities.size(); index++) {
                accept(store, identities.get(index), OTHER_KEY,
                        new PkiId("authority-capacity-" + index));
            }
            AtomicInteger scanCalls = new AtomicInteger();
            CountDownLatch thirdScan = new CountDownLatch(1);
            List<Optional<String>> suppliedHighWatermarks = Collections.synchronizedList(
                    new ArrayList<>());
            PkiStore observed = proxy(store, (method, result) -> {
                if ("pageDueSignWorkflows".equals(method)) {
                    if (scanCalls.incrementAndGet() >= 3) {
                        thirdScan.countDown();
                    }
                }
                return result;
            }, suppliedHighWatermarks);
            FirstCallBlockingProvider provider = new FirstCallBlockingProvider(store, 4);
            SigningReactor reactor = new SigningReactor(observed, provider,
                    topology(2, Duration.ofSeconds(2L), List.of(),
                            new SigningLanePool(1, 2)), ignored -> { });

            reactor.start();
            try {
                await(provider.firstEntered);
                awaitScanCalls(scanCalls, 2);
                assertFalse(thirdScan.await(100L, TimeUnit.MILLISECONDS));
                provider.releaseFirst.countDown();
                await(thirdScan);
                await(provider.expectedCalls);
                assertEquals(3, scanCalls.get());
                assertEquals(Optional.empty(), suppliedHighWatermarks.getFirst());
                assertTrue(suppliedHighWatermarks.get(1).isPresent());
                assertEquals(suppliedHighWatermarks.get(1), suppliedHighWatermarks.get(2));
            } finally {
                provider.releaseFirst.countDown();
                reactor.close();
            }
        }
    }

    @Test
    void authorityRoundRobinPreservesPerAuthorityFifo(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 8, clock)) {
            List<SigningSubmissionId> identities = sortedIdentities(store, 5);
            List<AcceptanceFixture> fixtures = List.of(
                    accept(store, identities.get(0), EXACT_KEY, new PkiId("authority-a")),
                    accept(store, identities.get(1), EXACT_KEY, new PkiId("authority-b")),
                    accept(store, identities.get(2), EXACT_KEY, new PkiId("authority-c")),
                    accept(store, identities.get(3), EXACT_KEY, new PkiId("authority-a")),
                    accept(store, identities.get(4), EXACT_KEY, new PkiId("authority-b")));
            FirstCallBlockingProvider provider = new FirstCallBlockingProvider(store, 5);
            SigningReactor reactor = new SigningReactor(store, provider,
                    topology(5, Duration.ofSeconds(2L),
                            List.of(new SigningKeyGroup(List.of(EXACT_KEY),
                                    new SigningLanePool(1, 5))),
                            new SigningLanePool(1, 1)), ignored -> { });

            reactor.start();
            await(provider.firstEntered);
            provider.releaseFirst.countDown();
            await(provider.expectedCalls);

            assertEquals(fixtures.stream().map(value -> value.command().operationId()).toList(),
                    provider.callOrder());
            reactor.close();
        }
    }

    @Test
    void saturatedExactPoolDoesNotBorrowOrBlockCatchAll(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 8, clock)) {
            List<SigningSubmissionId> identities = sortedIdentities(store, 4);
            List<AcceptanceFixture> exact = List.of(
                    accept(store, identities.get(0), EXACT_KEY, new PkiId("authority-a")),
                    accept(store, identities.get(1), EXACT_KEY, new PkiId("authority-b")),
                    accept(store, identities.get(2), EXACT_KEY, new PkiId("authority-c")));
            AcceptanceFixture catchAll = accept(store, identities.get(3), OTHER_KEY,
                    new PkiId("authority-z"));
            ExactBlockingProvider provider = new ExactBlockingProvider(store, EXACT_KEY);
            SigningReactor reactor = new SigningReactor(store, provider,
                    topology(2, Duration.ofSeconds(2L),
                            List.of(new SigningKeyGroup(List.of(EXACT_KEY),
                                    new SigningLanePool(1, 1))),
                            new SigningLanePool(1, 1)), ignored -> { });

            reactor.start();
            await(provider.exactEntered);
            await(provider.otherEntered);
            assertEquals(1, provider.maximumExactActive.get());
            assertEquals(1, provider.exactDispatches.get());
            assertTrue(reactor.retainedIdentifierCount() <= 4);
            provider.releaseExact.countDown();
            reactor.wake();

            awaitState(store, catchAll.command().operationId(), SignWorkflowStore.State.RETIRED);
            awaitCounter(provider.exactDispatches, 2);
            reactor.wake();
            for (AcceptanceFixture fixture : exact) {
                awaitState(store, fixture.command().operationId(), SignWorkflowStore.State.RETIRED);
            }
            assertEquals(3, provider.exactDispatches.get());
            reactor.close();
        }
    }

    @Test
    void saturatedRouteScansWithFixedPageQuantumUntilUnrelatedCapacityIsFilled(
            @TempDir Path root) throws Exception {
        int work = 65;
        int quantum = 8;
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, work, clock)) {
            List<SigningSubmissionId> identities = sortedIdentities(store, work);
            for (int index = 0; index < work - 1; index++) {
                accept(store, identities.get(index), EXACT_KEY,
                        new PkiId("authority-exact-" + index));
            }
            AcceptanceFixture unrelated = accept(store, identities.getLast(), OTHER_KEY,
                    new PkiId("authority-unrelated"));
            List<ScanCall> calls = Collections.synchronizedList(new ArrayList<>());
            PkiStore observed = (PkiStore) Proxy.newProxyInstance(
                    PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                    (proxy, method, arguments) -> {
                        if ("pageDueSignWorkflows".equals(method.getName())) {
                            calls.add(new ScanCall(((Optional<?>) arguments[1]).map(String.class::cast),
                                    ((Optional<?>) arguments[2]).map(String.class::cast), (Integer) arguments[3]));
                        }
                        try {
                            return method.invoke(store, arguments);
                        } catch (InvocationTargetException wrapped) {
                            throw wrapped.getCause();
                        }
                    });
            ScanBlockingProvider provider = new ScanBlockingProvider(store, EXACT_KEY);
            SigningReactor reactor = new SigningReactor(observed, provider,
                    topology(quantum, Duration.ofSeconds(2L),
                            List.of(new SigningKeyGroup(List.of(EXACT_KEY),
                                    new SigningLanePool(1, quantum - 1))),
                            new SigningLanePool(1, 1)), ignored -> { });

            reactor.start();
            try {
                await(provider.exactEntered);
                await(provider.unrelatedEntered);
                List<ScanCall> stableCalls;
                synchronized (calls) {
                    stableCalls = List.copyOf(calls);
                }
                assertTrue(stableCalls.size() <= (work + quantum - 1) / quantum + 1);
                assertTrue(stableCalls.stream()
                        .allMatch(call -> call.maximumRecords() == quantum));
                assertEquals(Optional.empty(), stableCalls.getFirst().cursor());
                assertEquals(Optional.empty(), stableCalls.getFirst().highWatermark());
                String stableHighWatermark = stableCalls.get(1).highWatermark().orElseThrow();
                assertTrue(stableCalls.stream().skip(1)
                        .allMatch(call -> call.highWatermark().equals(
                                Optional.of(stableHighWatermark))));
                String previous = stableCalls.getFirst().cursor().orElse("");
                for (ScanCall call : stableCalls.subList(1, stableCalls.size())) {
                    String current = call.cursor().orElseThrow();
                    assertTrue(previous.compareTo(current) < 0);
                    previous = current;
                }
                assertEquals(1, provider.exactDispatches.get());
                assertEquals(1, provider.unrelatedDispatches.get());

                provider.release.countDown();
                awaitState(store, unrelated.command().operationId(),
                        SignWorkflowStore.State.RETIRED);
            } finally {
                provider.release.countDown();
                reactor.close();
            }
        }
    }

    @Test
    void stableCycleSkipsMalformedDrainsBacklogAndRestartFindsSkippedWork(
            @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 8, clock)) {
            List<AcceptanceFixture> fixtures = new ArrayList<>();
            for (int index = 0; index < 4; index++) {
                fixtures.add(accept(store, OTHER_KEY, new PkiId("authority-" + index)));
            }
            PkiId malformed = fixtures.stream().map(value -> value.command().operationId())
                    .min((left, right) -> left.value().compareTo(right.value())).orElseThrow();
            List<Optional<String>> suppliedHighWatermarks = Collections.synchronizedList(
                    new ArrayList<>());
            PkiStore projected = proxy(store, (method, result) -> {
                if (!"pageDueSignWorkflows".equals(method)) {
                    return result;
                }
                SignWorkflowStore.DuePage page = (SignWorkflowStore.DuePage) result;
                List<SignWorkflowStore.DueCandidate> candidates = page.candidates().stream()
                        .map(candidate -> candidate.operationId().equals(malformed)
                                ? new SignWorkflowStore.DueCandidate(candidate.operationId(),
                                        candidate.scheduling(), true) : candidate)
                        .toList();
                int failures = (int) candidates.stream()
                        .filter(SignWorkflowStore.DueCandidate::malformed).count();
                return new SignWorkflowStore.DuePage(candidates, page.nextCursor(), failures,
                        page.endReached(), page.highWatermark());
            }, suppliedHighWatermarks);
            RecordingProvider provider = new RecordingProvider(store, 3);
            SigningReactor reactor = new SigningReactor(projected, provider,
                    topology(1, Duration.ofDays(1L), List.of(), new SigningLanePool(1, 1)),
                    ignored -> { });

            reactor.start();
            await(provider.expectedCalls);
            for (AcceptanceFixture fixture : fixtures) {
                if (!fixture.command().operationId().equals(malformed)) {
                    awaitState(store, fixture.command().operationId(),
                            SignWorkflowStore.State.RETIRED);
                }
            }
            assertEquals(SignWorkflowStore.State.INTENT,
                    store.getSignWorkflow(malformed).orElseThrow().state());
            assertTrue(suppliedHighWatermarks.stream().skip(1).anyMatch(Optional::isPresent));
            assertEquals(3, provider.dispatches.get());
            reactor.close();

            RecordingProvider restartedProvider = new RecordingProvider(store, 1);
            SigningReactor restarted = new SigningReactor(store, restartedProvider,
                    topology(1, Duration.ofSeconds(2L), List.of(),
                            new SigningLanePool(1, 1)), ignored -> { });
            restarted.start();
            awaitState(store, malformed, SignWorkflowStore.State.RETIRED);
            assertEquals(1, restartedProvider.dispatches.get());
            restarted.close();
        }
    }

    @RepeatedTest(20)
    void acceptanceGateRejectsNewWorkWhileAnAcceptedCallDrains(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            AcceptanceFixture fixture = staged(store, EXACT_KEY, new PkiId("authority-a"));
            CountDownLatch acceptanceEntered = new CountDownLatch(1);
            CountDownLatch releaseAcceptance = new CountDownLatch(1);
            AtomicInteger storeAcceptances = new AtomicInteger();
            PkiStore gated = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                    new Class<?>[] { PkiStore.class }, (proxy, method, arguments) -> {
                        if ("acceptSign".equals(method.getName())) {
                            storeAcceptances.incrementAndGet();
                            acceptanceEntered.countDown();
                            awaitIgnoringInterrupt(releaseAcceptance);
                        }
                        try {
                            return method.invoke(store, arguments);
                        } catch (InvocationTargetException wrapped) {
                            throw wrapped.getCause();
                        }
                    });
            RecordingProvider provider = new RecordingProvider(store, 0);
            SigningReactor reactor = new SigningReactor(gated, provider,
                    topology(1, Duration.ofSeconds(2L), List.of(),
                            new SigningLanePool(1, 1)), ignored -> { });
            AtomicReference<Object> accepted = new AtomicReference<>();
            Thread accepter = new Thread(() -> accepted.set(reactor.acceptSign(
                    fixture.command(), () -> { })), "topology-accept-permitted");
            AtomicReference<Throwable> closeFailure = new AtomicReference<>();
            Thread closer = new Thread(() -> {
                try {
                    reactor.close();
                } catch (Throwable failure) {
                    closeFailure.set(failure);
                }
            }, "topology-close-gate");
            accepter.start();
            try {
                await(acceptanceEntered);
                closer.start();
                awaitQuiescing(reactor);
                assertTrue(closer.isAlive());
                AtomicBoolean custodyTransferred = new AtomicBoolean();
                SigningExecutionException rejected = assertThrows(
                        SigningExecutionException.class,
                        () -> reactor.acceptSign(fixture.command(),
                                () -> custodyTransferred.set(true)));
                assertEquals(SigningExecutionException.Classification.SHUTTING_DOWN,
                        rejected.classification());
                assertFalse(custodyTransferred.get());
                assertEquals(1, storeAcceptances.get());
            } finally {
                releaseAcceptance.countDown();
                accepter.join(TimeUnit.SECONDS.toMillis(5L));
                closer.join(TimeUnit.SECONDS.toMillis(5L));
                reactor.close();
            }
            assertFalse(accepter.isAlive());
            assertFalse(closer.isAlive());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, accepted.get());
            assertTrue(closeFailure.get() == null);
        }
    }

    @RepeatedTest(20)
    void commonCloseDeadlineCanBeRetriedAfterBlockedProviderReturns(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 2, clock)) {
            AcceptanceFixture blocked = accept(store, OTHER_KEY, new PkiId("authority-b"));
            BlockingProvider provider = new BlockingProvider(store);
            SigningReactor reactor = new SigningReactor(store, provider,
                    topology(1, Duration.ofMillis(40L), List.of(),
                            new SigningLanePool(1, 1)), ignored -> { });
            reactor.start();
            boolean shutdownRequested = false;
            try {
                await(provider.entered);
                shutdownRequested = true;
                SigningExecutionException failure = assertThrows(
                        SigningExecutionException.class, reactor::close);
                assertEquals(SigningExecutionException.Classification.SHUTDOWN_TIMEOUT,
                        failure.classification());
                assertEquals(SignWorkflowStore.State.DISPATCHED,
                        store.getSignWorkflow(blocked.command().operationId())
                                .orElseThrow().state());
                provider.release.countDown();
                await(provider.returnEntered);
                assertTrue(provider.active.get());
                SigningExecutionException stillReturning = assertThrows(
                        SigningExecutionException.class, reactor::close);
                assertEquals(SigningExecutionException.Classification.SHUTDOWN_TIMEOUT,
                        stillReturning.classification());
            } finally {
                provider.release.countDown();
                provider.allowReturn.countDown();
                try {
                    if (!shutdownRequested) {
                        reactor.close();
                    }
                } finally {
                    // Releasing the provider is not a lane-termination barrier.
                    for (Thread thread : reactor.ownedThreads()) {
                        thread.join(TimeUnit.SECONDS.toMillis(5L));
                    }
                }
            }
            assertTrue(reactor.ownedThreads().stream().noneMatch(Thread::isAlive));
            reactor.close();
            assertFalse(provider.active.get());
        }
    }

    @Test
    void terminalOuterContinuationAdvancesBeforeRetirement(@TempDir Path root)
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 4, clock)) {
            AcceptanceFixture fixture = accept(store, SigningSubmissionId.create(
                    store.signingNamespace() + ".test-signer", NOW, new SecureRandom()),
                    EXACT_KEY, new PkiId("authority-a"), Optional.of(outer()));
            RecordingProvider provider = new RecordingProvider(store, 1);
            SigningOuterTerminalDriver driver = new SigningOuterTerminalDriver(store);
            SigningReactor reactor = new SigningReactor(store, provider,
                    topology(2, Duration.ofSeconds(2L),
                            List.of(new SigningKeyGroup(List.of(EXACT_KEY),
                                    new SigningLanePool(1, 1))),
                            new SigningLanePool(1, 1)), driver::advance);

            reactor.start();
            awaitState(store, fixture.command().operationId(), SignWorkflowStore.State.RETIRED);
            assertEquals(DomainContinuationStore.State.FAILED,
                    store.getDomainContinuation(fixture.command().operationId())
                            .orElseThrow().state());
            reactor.close();
        }
    }

    @Test
    void boundedPreparationBindsModeAndImmediateTerminalCanCompleteBeforeWait(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 8, clock)) {
            BoundedProvider provider = new BoundedProvider(store);
            provider.immediate = true;
            try (SigningReactor reactor = boundedReactor(store, provider, Duration.ofDays(1))) {
                DefaultSigningService service = boundedService(store, provider, reactor);
                SigningRequest request = boundedRequest(service);
                PreparedSigningRequest ordinary = service.prepare(request, bytes(), CancellationSignal.NONE);
                PreparedSigningRequest bounded = service.prepareBoundedObservation(request, bytes(), CancellationSignal.NONE);
                assertFalse(ordinary.receipt().equals(bounded.receipt()));
                assertEquals(0, provider.dispatches.get());
                assertTrue(store.getSignWorkflow(request.submissionId().id()).isEmpty());
                service.discard(ordinary);
                service.accept(bounded);
                assertThrows(IllegalStateException.class, () -> service.accept(bounded));
                assertEquals(SignWorkflowStore.Mode.BOUNDED_OBSERVATION,
                        store.getSignWorkflow(request.submissionId().id()).orElseThrow().mode());
                reactor.start();
                awaitState(store, request.submissionId().id(), SignWorkflowStore.State.RETIRED);
                SigningOperation result = service.awaitBoundedObservation(request.submissionId().id(), CancellationSignal.NONE)
                        .orElseThrow();
                assertEquals(SigningOperationState.SUCCEEDED, result.state());
                assertEquals(1, provider.dispatches.get());
                assertEquals(0, provider.observations.get());
                PreparedSigningRequest discarded = service.prepareBoundedObservation(boundedRequest(service), bytes(), CancellationSignal.NONE);
                service.discard(discarded);
                assertTrue(store.getSignWorkflow(discarded.receipt().operationId()).isEmpty());
                assertThrows(PkiException.class, () -> service.prepareBoundedObservation(boundedRequest(service), bytes(), () -> true));
            }
        }
    }

    @Test
    void boundedPendingReturnsAfterOneObservationAndLaterCleansUpWithoutCaller(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 8, clock)) {
            BoundedProvider provider = new BoundedProvider(store);
            try (SigningReactor reactor = boundedReactor(store, provider, Duration.ofMillis(5))) {
                DefaultSigningService service = boundedService(store, provider, reactor);
                PkiId operation = acceptBounded(service);
                reactor.start();
                SigningOperation initial = service.awaitBoundedObservation(operation, CancellationSignal.NONE).orElseThrow();
                assertEquals(SigningOperationState.PENDING, initial.state());
                assertEquals(1, provider.dispatches.get());
                assertEquals(1, provider.initialObservations.get());
                clock.now = NOW.plusSeconds(10);
                reactor.wake();
                awaitState(store, operation, SignWorkflowStore.State.RETIRED);
                assertEquals(1, provider.dispatches.get());
                assertEquals(2, provider.observations.get());
                assertEquals(1, provider.cancellations.get());
                assertEquals(SigningOperationState.CANCELLED,
                        service.awaitBoundedObservation(operation, CancellationSignal.NONE).orElseThrow().state());
            }
        }
    }

    @Test
    void initialFailureRemainsFailureAfterCleanupFindsSuccess(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 8, clock)) {
            BoundedProvider provider = new BoundedProvider(store);
            provider.failInitial = true;
            provider.cleanupSuccess = true;
            try (SigningReactor reactor = boundedReactor(store, provider, Duration.ofMillis(5))) {
                DefaultSigningService service = boundedService(store, provider, reactor);
                PkiId operation = acceptBounded(service);
                reactor.start();
                PkiException first = assertThrows(PkiException.class,
                        () -> service.awaitBoundedObservation(operation, CancellationSignal.NONE));
                assertEquals("Bounded signing initial attempt failed", first.getMessage());
                assertEquals(null, first.getCause());
                clock.now = NOW.plusSeconds(3);
                reactor.wake();
                awaitState(store, operation, SignWorkflowStore.State.RETIRED);
                assertEquals(SigningOperationState.SUCCEEDED, service.find(operation).orElseThrow().state());
                assertEquals("Bounded signing initial attempt failed", assertThrows(PkiException.class,
                        () -> service.awaitBoundedObservation(operation, CancellationSignal.NONE)).getMessage());
                assertEquals(1, provider.initialObservations.get());
                assertEquals(1, provider.dispatches.get());
            }
        }
    }

    @Test
    void shutdownDispatchExceptionRemainsFailedAfterRestartCleanupSuccess(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        PkiId operation;
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 8, clock)) {
            BoundedProvider provider = new BoundedProvider(store);
            provider.failDuringClose = true;
            {
                SigningReactor reactor = boundedReactor(store, provider, Duration.ofMillis(5));
                try (reactor) {
                    operation = acceptBounded(boundedService(store, provider, reactor));
                    reactor.start();
                    await(provider.dispatchEntered);
                    reactor.close();
                    SignWorkflowStore.Workflow failed = store.getSignWorkflow(operation).orElseThrow();
                    assertEquals(SignWorkflowStore.InitialAttemptPhase.FAILED, failed.initialAttemptPhase());
                    assertEquals(SignWorkflowStore.State.DISPATCHED, failed.state());
                    assertEquals(1, failed.failureCount());
                    assertTrue(failed.leaseUntil().isEmpty());
                    assertEquals(1, provider.dispatches.get());
                    assertEquals(0, provider.observations.get());
                }
            }
        }
        clock.now = NOW.plusSeconds(3);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 8, clock)) {
            BoundedProvider provider = new BoundedProvider(store);
            provider.cleanupSuccess = true;
            try (SigningReactor reactor = boundedReactor(store, provider, Duration.ofMillis(5))) {
                DefaultSigningService service = boundedService(store, provider, reactor);
                assertEquals(SignWorkflowStore.InitialAttemptPhase.FAILED,
                        store.getSignWorkflow(operation).orElseThrow().initialAttemptPhase());
                reactor.start();
                awaitState(store, operation, SignWorkflowStore.State.RETIRED);
                assertEquals(SigningOperationState.SUCCEEDED, service.find(operation).orElseThrow().state());
                PkiException failure = assertThrows(PkiException.class,
                        () -> service.awaitBoundedObservation(operation, CancellationSignal.NONE));
                assertEquals("Bounded signing initial attempt failed", failure.getMessage());
                assertEquals(null, failure.getCause());
                assertEquals(SignWorkflowStore.InitialAttemptPhase.FAILED,
                        store.getSignWorkflow(operation).orElseThrow().initialAttemptPhase());
                assertEquals(0, provider.dispatches.get());
                assertEquals(0, provider.initialObservations.get());
                assertEquals(1, provider.observations.get());
                assertEquals(0, provider.cancellations.get());
            }
        }
    }

    @Test
    void recoveryNeverRedispatchesAndNeverRepeatsConsumedInitialObservation(@TempDir Path root) throws Exception {
        for (boolean consumed : List.of(false, true)) {
            MutableClock clock = new MutableClock(NOW);
            Path directory = root.resolve(Boolean.toString(consumed));
            PkiId operation;
            try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(directory, 8, clock)) {
                BoundedProvider provider = new BoundedProvider(store);
                try (SigningReactor reactor = boundedReactor(store, provider, Duration.ofMillis(5))) {
                    operation = acceptBounded(boundedService(store, provider, reactor));
                    SignWorkflowStore.Workflow dispatch = store.claimSignStep(operation, 0, Duration.ofSeconds(10)).orElseThrow();
                    if (consumed) {
                        SignWorkflowStore.Workflow ready = store.checkpointPendingSignDispatch(operation, dispatch.revision(), dispatch.fence())
                                .orElseThrow();
                        store.claimSignStep(operation, ready.revision(), Duration.ofSeconds(10)).orElseThrow();
                    }
                }
            }
            clock.now = NOW.plusSeconds(10);
            try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(directory, 8, clock)) {
                BoundedProvider provider = new BoundedProvider(store);
                try (SigningReactor reactor = boundedReactor(store, provider, Duration.ofMillis(5))) {
                    DefaultSigningService service = boundedService(store, provider, reactor);
                    reactor.start();
                    if (consumed) {
                        assertThrows(PkiException.class, () -> service.awaitBoundedObservation(operation, CancellationSignal.NONE));
                        awaitState(store, operation, SignWorkflowStore.State.RETIRED);
                        assertEquals(0, provider.initialObservations.get());
                        assertEquals(1, provider.cancellations.get());
                    } else {
                        assertEquals(SigningOperationState.PENDING,
                                service.awaitBoundedObservation(operation, CancellationSignal.NONE).orElseThrow().state());
                        assertEquals(1, provider.initialObservations.get());
                    }
                    assertEquals(0, provider.dispatches.get());
                }
            }
        }
    }

    @Test
    void completionBetweenAuthoritativeReadAndWaitCannotLoseWake(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 8, clock)) {
            CountDownLatch staleRead = new CountDownLatch(1);
            CountDownLatch releaseRead = new CountDownLatch(1);
            AtomicBoolean first = new AtomicBoolean(true);
            PkiStore observed = proxy(store, (method, result) -> {
                if ("getSignWorkflow".equals(method) && Thread.currentThread().getName().equals("bounded-lost-wake")
                        && first.compareAndSet(true, false)) {
                    staleRead.countDown();
                    awaitIgnoringInterrupt(releaseRead);
                }
                return result;
            });
            BoundedProvider provider = new BoundedProvider(store);
            provider.immediate = true;
            try (SigningReactor reactor = boundedReactor(observed, provider, Duration.ofDays(1))) {
                DefaultSigningService service = boundedService(observed, provider, reactor);
                PkiId operation = acceptBounded(service);
                CompletableFuture<Optional<SigningOperation>> result = new CompletableFuture<>();
                Thread waiter = new Thread(() -> {
                    try { result.complete(service.awaitBoundedObservation(operation, CancellationSignal.NONE)); }
                    catch (Throwable failure) { result.completeExceptionally(failure); }
                }, "bounded-lost-wake");
                waiter.start();
                try {
                    await(staleRead);
                    reactor.start();
                    awaitState(store, operation, SignWorkflowStore.State.RETIRED);
                } finally {
                    releaseRead.countDown();
                }
                assertEquals(SigningOperationState.SUCCEEDED, result.get(5, TimeUnit.SECONDS).orElseThrow().state());
                waiter.join(5_000L);
                assertFalse(waiter.isAlive());
            }
        }
    }

    @Test
    void waitCancellationInterruptionAndShutdownDoNotCancelDurableIntent(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        for (String outcome : List.of("signal", "interrupt", "shutdown")) {
            Path iterRoot = Files.createTempDirectory(root, outcome + "-");
            try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(iterRoot, 8, clock)) {
                BoundedProvider provider = new BoundedProvider(store);
                {
                    SigningReactor reactor = boundedReactor(store, provider, Duration.ofMillis(5));
                    try (reactor) {
                        DefaultSigningService service = boundedService(store, provider, reactor);
                        PkiId operation = acceptBounded(service);
                        CountDownLatch checked = new CountDownLatch(1);
                        AtomicBoolean cancelled = new AtomicBoolean();
                        AtomicBoolean interruptPreserved = new AtomicBoolean();
                        CompletableFuture<Throwable> result = new CompletableFuture<>();
                        Thread waiter = new Thread(() -> {
                            try {
                                service.awaitBoundedObservation(operation, () -> {
                                    checked.countDown();
                                    return cancelled.get();
                                });
                                result.complete(new AssertionError("Wait unexpectedly completed"));
                            } catch (Throwable failure) {
                                interruptPreserved.set(Thread.currentThread().isInterrupted());
                                result.complete(failure);
                            }
                        }, "bounded-wait-cancellation");
                        waiter.start();
                        await(checked);
                        switch (outcome) {
                            case "signal" -> cancelled.set(true);
                            case "interrupt" -> waiter.interrupt();
                            case "shutdown" -> reactor.close();
                            default -> throw new AssertionError(outcome);
                        }
                        Throwable failure = result.get(5, TimeUnit.SECONDS);
                        assertTrue(failure instanceof PkiException,
                                () -> "Wait scenario=" + outcome + "; actual=" + failure.getClass().getName()
                                        + "; cause=" + (failure.getCause() == null ? "none"
                                                : failure.getCause().getClass().getName())
                                        + "; origin=" + (failure.getStackTrace().length == 0 ? "none"
                                                : failure.getStackTrace()[0]));
                        if ("shutdown".equals(outcome)) {
                            assertEquals(SigningExecutionException.Classification.SHUTTING_DOWN,
                                    ((SigningExecutionException) failure).classification());
                        }
                        assertEquals("interrupt".equals(outcome), interruptPreserved.get());
                        waiter.join(5_000L);
                        assertFalse(waiter.isAlive());
                        assertEquals(SignWorkflowStore.State.INTENT, store.getSignWorkflow(operation).orElseThrow().state());
                        assertEquals(0, provider.dispatches.get());
                    }
                }
            }
        }
    }

    @Test
    void interruptedAuthoritativeLookupReturnsSafeFailureAndPreservesInterrupt(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 8, clock)) {
            CountDownLatch lookupEntered = new CountDownLatch(1);
            PkiStore observed = proxy(store, (method, result) -> {
                if ("getSignWorkflow".equals(method)) {
                    lookupEntered.countDown();
                    try {
                        new CountDownLatch(1).await();
                        throw new AssertionError("Interrupted lookup must not complete normally");
                    } catch (InterruptedException interrupted) {
                        throw new IllegalStateException("Controlled lookup wrapper",
                                new MetadataStoreException(MetadataCommitResult.FailureCategory.CANCELLED,
                                        "Controlled metadata interruption", interrupted));
                    }
                }
                return result;
            });
            BoundedProvider provider = new BoundedProvider(store);
            try (SigningReactor reactor = boundedReactor(observed, provider, Duration.ofMillis(5))) {
                DefaultSigningService service = boundedService(observed, provider, reactor);
                PkiId operation = acceptBounded(service);
                AtomicBoolean interruptPreserved = new AtomicBoolean();
                CompletableFuture<Throwable> result = new CompletableFuture<>();
                Thread waiter = new Thread(() -> {
                    try {
                        service.awaitBoundedObservation(operation, CancellationSignal.NONE);
                        result.complete(new AssertionError("Wait unexpectedly completed"));
                    } catch (Throwable failure) {
                        interruptPreserved.set(Thread.currentThread().isInterrupted());
                        result.complete(failure);
                    }
                }, "bounded-interrupted-lookup");
                waiter.start();
                await(lookupEntered);
                waiter.interrupt();
                Throwable failure = result.get(5, TimeUnit.SECONDS);
                assertEquals(PkiException.class, failure.getClass());
                assertEquals("Bounded signing observation wait interrupted", failure.getMessage());
                assertEquals(null, failure.getCause());
                assertTrue(interruptPreserved.get());
                waiter.join(5_000L);
                assertFalse(waiter.isAlive());
                SignWorkflowStore.Workflow unchanged = store.getSignWorkflow(operation).orElseThrow();
                assertEquals(SignWorkflowStore.State.INTENT, unchanged.state());
                assertEquals(0L, unchanged.revision());
                assertEquals(0, provider.dispatches.get());
                assertEquals(0, provider.observations.get());
            }
        }
    }

    @Test
    void noncancelMetadataFailureIsNotReclassifiedByInterruptFlagOrCause(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 8, clock)) {
            IllegalStateException original = new IllegalStateException("Controlled lookup wrapper",
                    new MetadataStoreException(MetadataCommitResult.FailureCategory.STORAGE_FAILURE,
                            "Controlled storage failure", new InterruptedException("Nested interruption")));
            PkiStore observed = proxy(store, (method, result) -> {
                if ("getSignWorkflow".equals(method)) {
                    Thread.currentThread().interrupt();
                    throw original;
                }
                return result;
            });
            BoundedProvider provider = new BoundedProvider(store);
            try (SigningReactor reactor = boundedReactor(observed, provider, Duration.ofMillis(5))) {
                DefaultSigningService service = boundedService(observed, provider, reactor);
                PkiId operation = acceptBounded(service);
                try {
                    assertSame(original, assertThrows(IllegalStateException.class,
                            () -> service.awaitBoundedObservation(operation, CancellationSignal.NONE)));
                    assertTrue(Thread.currentThread().isInterrupted());
                } finally {
                    Thread.interrupted();
                }
                assertEquals(SignWorkflowStore.State.INTENT, store.getSignWorkflow(operation).orElseThrow().state());
                assertEquals(0, provider.dispatches.get());
                assertEquals(0, provider.observations.get());
            }
        }
    }

    @Test
    void ordinaryModeIsRejectedAndUnknownBoundedIdentityReturnsEmpty(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 8, clock)) {
            BoundedProvider provider = new BoundedProvider(store);
            try (SigningReactor reactor = boundedReactor(store, provider, Duration.ofMillis(5))) {
                DefaultSigningService service = boundedService(store, provider, reactor);
                PreparedSigningRequest ordinary = service.prepare(boundedRequest(service), bytes(), CancellationSignal.NONE);
                service.accept(ordinary);
                assertThrows(IllegalArgumentException.class,
                        () -> service.awaitBoundedObservation(ordinary.receipt().operationId(), CancellationSignal.NONE));
                assertTrue(service.awaitBoundedObservation(service.newSubmissionId().id(), CancellationSignal.NONE).isEmpty());
            }
        }
    }

    private static SigningReactor boundedReactor(PkiStore store, SigningProvider provider, Duration poll) {
        return new SigningReactor(store, provider,
                new SigningTopology(new SigningCoordinatorLimits(8, Duration.ofSeconds(10), Duration.ofSeconds(5),
                        poll, Duration.ofSeconds(2)), List.of(), new SigningLanePool(1, 8)), ignored -> { });
    }

    private static DefaultSigningService boundedService(PkiStore store, SigningProvider provider, SigningReactor reactor) {
        return new DefaultSigningService(store, provider, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                Duration.ofSeconds(60), new SecureRandom(), reactor::requireAccepting, reactor::acceptSign, reactor::wake,
                reactor::awaitBoundedObservation);
    }

    private static SigningRequest boundedRequest(DefaultSigningService service) {
        return new SigningRequest(service.newSubmissionId(), ACCESS, EXACT_KEY, new PkiId("bounded-authority"),
                BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, Encoding.BINARY, Encoding.BINARY);
    }

    private static PkiId acceptBounded(DefaultSigningService service) {
        PreparedSigningRequest prepared = service.prepareBoundedObservation(boundedRequest(service), bytes(), CancellationSignal.NONE);
        service.accept(prepared);
        return prepared.receipt().operationId();
    }

    private static OneShotContent bytes() {
        return new OneShotContent() {
            @Override public InputStream openStream() { return new ByteArrayInputStream(new byte[] { 1, 2, 3 }); }
            @Override public OptionalLong length() { return OptionalLong.of(3); }
            @Override public void close() { }
        };
    }

    private static final class BoundedProvider implements SigningProvider {
        private final FilesystemPkiStore store;
        private final AtomicInteger dispatches = new AtomicInteger();
        private final AtomicInteger observations = new AtomicInteger();
        private final AtomicInteger initialObservations = new AtomicInteger();
        private final AtomicInteger cancellations = new AtomicInteger();
        private boolean immediate;
        private boolean failInitial;
        private boolean cleanupSuccess;
        private boolean failDuringClose;
        private final CountDownLatch dispatchEntered = new CountDownLatch(1);

        private BoundedProvider(FilesystemPkiStore store) { this.store = store; }
        @Override public String id() { return "test-signer"; }
        @Override public ConfigurationCommitment configurationCommitment() {
            byte[] value = new byte[ConfigurationCommitment.BYTE_LENGTH];
            Arrays.fill(value, (byte) 17);
            return new ConfigurationCommitment(value);
        }
        @Override public Set<String> supportedAlgorithms() {
            return Set.of(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm());
        }
        @Override public zeroecho.pki.spi.crypto.SigningInputCapabilities inputCapabilities() {
            return new zeroecho.pki.spi.crypto.SigningInputCapabilities(Long.MAX_VALUE, Map.of());
        }
        @Override public OperationObservation dispatch(SignRequest request, CallControl control) {
            requireLane();
            dispatches.incrementAndGet();
            assertEquals(SignWorkflowStore.InitialAttemptPhase.DISPATCH_OWED,
                    store.getSignWorkflow(request.operationId()).orElseThrow().initialAttemptPhase());
            if (failDuringClose) {
                dispatchEntered.countDown();
                try {
                    new CountDownLatch(1).await();
                    throw new AssertionError("Shutdown test latch cannot complete normally");
                } catch (InterruptedException shutdown) {
                    throw new IllegalStateException("Provider-private dispatch failure during shutdown");
                }
            }
            return observation(request.operationId(), immediate ? ObservationState.SUCCEEDED : ObservationState.PENDING);
        }
        @Override public OperationObservation reconcile(PkiId operationId, CallControl control) {
            requireLane();
            observations.incrementAndGet();
            SignWorkflowStore.Workflow workflow = store.getSignWorkflow(operationId).orElseThrow();
            if (workflow.state() == SignWorkflowStore.State.DISPATCHED) {
                assertEquals(SignWorkflowStore.InitialAttemptPhase.OBSERVATION_CONSUMED, workflow.initialAttemptPhase());
                initialObservations.incrementAndGet();
                if (failInitial) { throw new IllegalStateException("Provider-private failure must not escape"); }
                return observation(operationId, ObservationState.PENDING);
            }
            assertEquals(SignWorkflowStore.State.CANCELLING, workflow.state());
            return observation(operationId, cleanupSuccess ? ObservationState.SUCCEEDED : ObservationState.PENDING);
        }
        @Override public OperationObservation cancel(PkiId operationId, long fence, CancellationReason reason, CallControl control) {
            requireLane();
            cancellations.incrementAndGet();
            return observation(operationId, ObservationState.CANCELLED);
        }
        private static OperationObservation observation(PkiId operationId, ObservationState state) {
            return new OperationObservation(operationId, state, NOW, switch (state) {
                case SUCCEEDED -> DetailCode.SIGNED;
                case CANCELLED -> DetailCode.CANCELLED;
                default -> DetailCode.PENDING;
            }, state == ObservationState.SUCCEEDED
                    ? Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 7 })) : Optional.empty());
        }
        private static void requireLane() {
            assertTrue(Thread.currentThread().getName().startsWith("zeroecho-signing-pool-"));
        }
        @Override public void close() { }
    }

    private static SigningTopology topology(int pageSize, Duration closeTimeout,
            List<SigningKeyGroup> groups, SigningLanePool catchAll) {
        return new SigningTopology(new SigningCoordinatorLimits(pageSize,
                Duration.ofSeconds(10L), Duration.ofSeconds(5L),
                Duration.ofDays(1L), closeTimeout), groups, catchAll);
    }

    private static AcceptanceFixture accept(FilesystemPkiStore store, KeyRef keyRef,
            PkiId authority) throws Exception {
        AcceptanceFixture fixture = staged(store, keyRef, authority);
        assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED,
                store.acceptSign(fixture.command()));
        return fixture;
    }

    private static AcceptanceFixture accept(FilesystemPkiStore store,
            SigningSubmissionId identity, KeyRef keyRef, PkiId authority) throws Exception {
        return accept(store, identity, keyRef, authority, Optional.empty());
    }

    private static AcceptanceFixture accept(FilesystemPkiStore store,
            SigningSubmissionId identity, KeyRef keyRef, PkiId authority,
            Optional<SignWorkflowStore.OuterCommand> outer) throws Exception {
        AcceptanceFixture fixture = staged(store, identity, keyRef, authority, outer);
        assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED,
                store.acceptSign(fixture.command()));
        return fixture;
    }

    private static AcceptanceFixture staged(FilesystemPkiStore store, KeyRef keyRef,
            PkiId authority) throws Exception {
        SigningSubmissionId identity = SigningSubmissionId.create(
                store.signingNamespace() + ".test-signer", NOW, new SecureRandom());
        return staged(store, identity, keyRef, authority, Optional.empty());
    }

    private static AcceptanceFixture staged(FilesystemPkiStore store,
            SigningSubmissionId identity, KeyRef keyRef, PkiId authority,
            Optional<SignWorkflowStore.OuterCommand> outer) throws Exception {
        DurableContentReference candidate = PkiTestRuntime.operationReference(
                store.stagedContent(), Encoding.BINARY, new byte[] { 1, 2, 3 });
        byte[] commitment = new byte[SigningProvider.ConfigurationCommitment.BYTE_LENGTH];
        Arrays.fill(commitment, (byte) 17);
        SignWorkflowStore.AcceptanceCommand command = new SignWorkflowStore.AcceptanceCommand(
                identity.id(), identity.namespace(),
                new SigningProvider.ConfigurationCommitment(commitment), ACCESS, keyRef,
                authority, "SHA256withRSA", Encoding.BINARY, identity.createdAt(),
                identity.createdAt().plusSeconds(30L), candidate, outer, SignWorkflowStore.Mode.NORMAL, java.util.Optional.empty());
        return new AcceptanceFixture(command);
    }

    private static List<SigningSubmissionId> sortedIdentities(FilesystemPkiStore store,
            int count) {
        List<SigningSubmissionId> identities = new ArrayList<>(count);
        for (int index = 0; index < count; index++) {
            identities.add(SigningSubmissionId.create(
                    store.signingNamespace() + ".test-signer", NOW, new SecureRandom()));
        }
        identities.sort((left, right) -> left.id().value().compareTo(right.id().value()));
        return List.copyOf(identities);
    }

    private static SignWorkflowStore.OuterCommand outer() {
        DomainContinuationTemplate template = DomainCommandEncoding.correlatedTemplate(
                DomainContinuationStore.Kind.CA, "topology-outer", "CREATE_ROOT",
                "format:test", "CN=Test", "root", "test-key", "profile", "1",
                "1".repeat(64), NOW.toString(), NOW.plusSeconds(30L).toString(),
                "1", "", "", "", "authority");
        return new SignWorkflowStore.OuterCommand(template.kind(),
                template.correlationId().orElseThrow(), template.command(),
                template.commandCommitment());
    }

    private static PkiStore proxy(FilesystemPkiStore store, ResultInterceptor interceptor) {
        return proxy(store, interceptor, null);
    }

    private static PkiStore proxy(FilesystemPkiStore store, ResultInterceptor interceptor,
            List<Optional<String>> suppliedHighWatermarks) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class }, (proxy, method, arguments) -> {
                    if (suppliedHighWatermarks != null
                            && "pageDueSignWorkflows".equals(method.getName())) {
                        suppliedHighWatermarks.add(((Optional<?>) arguments[2]).map(String.class::cast));
                    }
                    try {
                        Object result = method.invoke(store, arguments);
                        return interceptor.intercept(method.getName(), result);
                    } catch (InvocationTargetException wrapped) {
                        throw wrapped.getCause();
                    }
                });
    }

    private static SignWorkflowStore.Workflow awaitState(FilesystemPkiStore store, PkiId id,
            SignWorkflowStore.State state) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5L);
        while (System.nanoTime() < deadline) {
            SignWorkflowStore.Workflow workflow = store.getSignWorkflow(id).orElseThrow();
            if (workflow.state() == state) {
                return workflow;
            }
            Thread.sleep(5L);
        }
        throw new AssertionError("Signing workflow did not reach the expected state");
    }

    private static void await(CountDownLatch latch) throws InterruptedException {
        assertTrue(latch.await(5L, TimeUnit.SECONDS));
    }

    private static void awaitQuiescing(SigningReactor reactor) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5L);
        while (System.nanoTime() < deadline) {
            try {
                reactor.requireAccepting();
            } catch (SigningExecutionException expected) {
                return;
            }
            Thread.sleep(1L);
        }
        throw new AssertionError("Signing reactor did not begin quiescing");
    }

    private static void awaitRetainedCount(SigningReactor reactor, int expected)
            throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5L);
        while (System.nanoTime() < deadline) {
            if (reactor.retainedIdentifierCount() == expected) {
                return;
            }
            Thread.sleep(1L);
        }
        throw new AssertionError("Signing reactor did not reach retained count " + expected);
    }

    private static void awaitScanCalls(AtomicInteger calls, int expected)
            throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5L);
        while (System.nanoTime() < deadline) {
            if (calls.get() >= expected) {
                return;
            }
            Thread.sleep(1L);
        }
        throw new AssertionError("Signing reactor did not reach scan count " + expected);
    }

    private static void awaitCounter(AtomicInteger counter, int expected)
            throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5L);
        while (System.nanoTime() < deadline) {
            if (counter.get() >= expected) {
                return;
            }
            Thread.sleep(1L);
        }
        throw new AssertionError("Signing reactor did not reach counter " + expected);
    }

    private static SigningProvider.OperationObservation failure(PkiId operationId) {
        return new SigningProvider.OperationObservation(operationId,
                SigningProvider.ObservationState.FAILED, NOW.plusSeconds(1L),
                SigningProvider.DetailCode.DENIED, Optional.empty());
    }

    private static void awaitIgnoringInterrupt(CountDownLatch latch) {
        while (true) {
            try {
                latch.await();
                return;
            } catch (InterruptedException ignored) {
                // The controlled provider deliberately models a non-cooperative call.
            }
        }
    }

    private record AcceptanceFixture(SignWorkflowStore.AcceptanceCommand command) { }

    private record ScanCall(Optional<String> cursor, Optional<String> highWatermark,
            int maximumRecords) { }

    @FunctionalInterface
    private interface ResultInterceptor {
        Object intercept(String method, Object result);
    }

    private static class RecordingProvider implements SigningProvider {
        @Override public zeroecho.pki.spi.crypto.SigningInputCapabilities inputCapabilities() {
            return new zeroecho.pki.spi.crypto.SigningInputCapabilities(Long.MAX_VALUE, java.util.Map.of());
        }
        private final FilesystemPkiStore store;
        private final ConfigurationCommitment commitment;
        private final List<PkiId> order = Collections.synchronizedList(new ArrayList<>());
        private final Map<PkiId, String> threads = Collections.synchronizedMap(new HashMap<>());
        final AtomicInteger dispatches = new AtomicInteger();
        final CountDownLatch expectedCalls;

        RecordingProvider(FilesystemPkiStore store, int expectedCalls) {
            this.store = store;
            this.expectedCalls = new CountDownLatch(expectedCalls);
            byte[] value = new byte[ConfigurationCommitment.BYTE_LENGTH];
            Arrays.fill(value, (byte) 17);
            commitment = new ConfigurationCommitment(value);
        }

        @Override public String id() { return "test-signer"; }
        @Override public ConfigurationCommitment configurationCommitment() { return commitment; }
        @Override public Set<String> supportedAlgorithms() { return Set.of("SHA256withRSA"); }

        @Override
        public OperationObservation dispatch(SignRequest request, CallControl control) {
            SignWorkflowStore.Workflow claimed = store.getSignWorkflow(request.operationId())
                    .orElseThrow();
            if (claimed.state() != SignWorkflowStore.State.DISPATCHED
                    || claimed.leaseUntil().isEmpty()) {
                throw new AssertionError("Provider was called before durable claim");
            }
            dispatches.incrementAndGet();
            order.add(request.operationId());
            threads.put(request.operationId(), Thread.currentThread().getName());
            onDispatch(request);
            expectedCalls.countDown();
            return failure(request.operationId());
        }

        void onDispatch(SignRequest request) { }

        List<PkiId> callOrder() {
            synchronized (order) {
                return List.copyOf(order);
            }
        }

        String threadFor(PkiId operationId) {
            return threads.get(operationId);
        }

        @Override public OperationObservation reconcile(PkiId operationId, CallControl control) {
            return failure(operationId);
        }
        @Override public OperationObservation cancel(PkiId operationId, long fencingToken,
                CancellationReason reason, CallControl control) { return failure(operationId); }
        @Override public void close() { }
    }

    private static final class FirstCallBlockingProvider extends RecordingProvider {
        private final AtomicBoolean first = new AtomicBoolean(true);
        final CountDownLatch firstEntered = new CountDownLatch(1);
        final CountDownLatch releaseFirst = new CountDownLatch(1);

        FirstCallBlockingProvider(FilesystemPkiStore store, int expectedCalls) {
            super(store, expectedCalls);
        }

        @Override void onDispatch(SignRequest request) {
            if (first.compareAndSet(true, false)) {
                firstEntered.countDown();
                awaitIgnoringInterrupt(releaseFirst);
            }
        }
    }

    private static final class ExactBlockingProvider extends RecordingProvider {
        private final KeyRef blockedKey;
        private final AtomicInteger exactActive = new AtomicInteger();
        final AtomicInteger exactDispatches = new AtomicInteger();
        final AtomicInteger maximumExactActive = new AtomicInteger();
        final CountDownLatch exactEntered = new CountDownLatch(1);
        final CountDownLatch otherEntered = new CountDownLatch(1);
        final CountDownLatch releaseExact = new CountDownLatch(1);

        ExactBlockingProvider(FilesystemPkiStore store, KeyRef blockedKey) {
            super(store, 0);
            this.blockedKey = blockedKey;
        }

        @Override void onDispatch(SignRequest request) {
            if (blockedKey.equals(request.keyRef())) {
                exactDispatches.incrementAndGet();
                int active = exactActive.incrementAndGet();
                maximumExactActive.accumulateAndGet(active, Math::max);
                exactEntered.countDown();
                awaitIgnoringInterrupt(releaseExact);
                exactActive.decrementAndGet();
            } else {
                otherEntered.countDown();
            }
        }
    }

    private static final class ScanBlockingProvider extends RecordingProvider {
        private final KeyRef saturatedKey;
        final AtomicInteger exactDispatches = new AtomicInteger();
        final AtomicInteger unrelatedDispatches = new AtomicInteger();
        final CountDownLatch exactEntered = new CountDownLatch(1);
        final CountDownLatch unrelatedEntered = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);

        ScanBlockingProvider(FilesystemPkiStore store, KeyRef saturatedKey) {
            super(store, 0);
            this.saturatedKey = saturatedKey;
        }

        @Override void onDispatch(SignRequest request) {
            if (saturatedKey.equals(request.keyRef())) {
                exactDispatches.incrementAndGet();
                exactEntered.countDown();
            } else {
                unrelatedDispatches.incrementAndGet();
                unrelatedEntered.countDown();
            }
            awaitIgnoringInterrupt(release);
        }
    }

    private static final class BlockingProvider extends RecordingProvider {
        final CountDownLatch entered = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);
        final CountDownLatch returnEntered = new CountDownLatch(1);
        final CountDownLatch allowReturn = new CountDownLatch(1);
        final AtomicBoolean active = new AtomicBoolean();

        BlockingProvider(FilesystemPkiStore store) {
            super(store, 0);
        }

        @Override void onDispatch(SignRequest request) {
            active.set(true);
            entered.countDown();
            awaitIgnoringInterrupt(release);
            returnEntered.countDown();
            awaitIgnoringInterrupt(allowReturn);
            active.set(false);
        }
    }

    private static final class MutableClock extends Clock {
        private volatile Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        @Override public ZoneId getZone() { return java.time.ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
