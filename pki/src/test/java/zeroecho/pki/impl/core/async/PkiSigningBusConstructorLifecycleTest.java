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
package zeroecho.pki.impl.core.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static zeroecho.pki.testkit.PkiTestRuntime.signingAuthority;
import static zeroecho.pki.testkit.PkiTestRuntime.stage;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.application.SigningReconciliationContinuation;
import zeroecho.pki.application.SigningReconciliationRequest;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.InMemorySignatureWorkflow;
import zeroecho.pki.util.async.AsyncState;

/** Constructor failure and runtime-ownership coverage for the signing bus. */
@SuppressWarnings({ "PMD.UnitTestContainsTooManyAsserts", "PMD.UnitTestAssertionsShouldIncludeMessage" })
final class PkiSigningBusConstructorLifecycleTest {
    private static final Principal OWNER = new Principal("TEST", "startup-owner");
    private static final AccessContext ACCESS = new AccessContext(OWNER, new Purpose("SIGN"),
            Optional.empty(), Optional.empty());

    @Test
    void remoteConstructionDoesNotPageRetainedHistoryAndPointLookupRemainsAvailable(
            @TempDir Path root) throws Exception {
        LifecycleWorkflow workflow = new LifecycleWorkflow("no-startup-scan", FailurePoint.NONE);
        AtomicInteger pageCalls = new AtomicInteger();
        AtomicInteger pointReads = new AtomicInteger();
        try (FilesystemPkiStore delegate = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults());
                SigningExecutionRuntime runtime = runtime()) {
            PkiStore store = trackingStore(delegate, pageCalls, pointReads);
            try (PkiSigningBus bus = PkiSigningBus.attach(
                    store, workflow, signingAuthority(workflow), runtime)) {
                assertEquals(0, pageCalls.get());

                assertTrue(bus.status(bus.newSubmissionId()).isEmpty());
                assertTrue(pointReads.get() > 0);
                assertEquals(0, pageCalls.get());
            }
        } finally {
            workflow.close();
        }
    }

    @ParameterizedTest
    @CsvSource({
            "INITIAL_INTENT, true", "FENCED_INTENT, true", "DISPATCHED, true", "CANCELLING, true",
            "INITIAL_INTENT, false", "FENCED_INTENT, false", "DISPATCHED, false", "CANCELLING, false"
    })
    void configurationDriftIsIsolatedWithoutCallingReplacementProviderAndExpiresAtOriginalDeadline(
            StartupState startupState, boolean sameProviderIdentity, @TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-14T12:00:00Z"));
        LifecycleWorkflow workflowA = new LifecycleWorkflow("restart-provider", FailurePoint.NONE,
                commitment((byte) 1));
        LifecycleWorkflow workflowB = new LifecycleWorkflow(
                sameProviderIdentity ? "restart-provider" : "replacement-provider", FailurePoint.NONE,
                sameProviderIdentity ? commitment((byte) 2) : commitment((byte) 1));
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            PkiId submissionId;
            Instant deadline;
            try (PkiSigningBus bus = new PkiSigningBus(store, workflowA, signingAuthority(workflowA))) {
                submissionId = bus.newSubmissionId();
                DurableContentReference content = stage(bus,
                        new EncodedObject(Encoding.BINARY, new byte[] { 1, 2, 3 }));
                PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(
                        ACCESS, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(),
                        content, new KeyRef("remote:test"),
                        Encoding.BINARY, Optional.of(submissionId));
                Instant createdAt = SigningSubmissionId.parse(submissionId).createdAt();
                deadline = createdAt.plus(Duration.ofMinutes(1));
                SignWorkflowStore.Record intent = new SignWorkflowStore.Record(submissionId,
                        store.signingNamespace() + "." + workflowA.id(),
                        continuation.semanticFingerprint(workflowA.configurationCommitment(),
                                store.signingNamespace() + "." + workflowA.id(), deadline),
                        workflowA.configurationCommitment(), OWNER, createdAt, deadline, continuation.encode(),
                        SignWorkflowStore.State.INTENT, 0L, 0L, Optional.empty(), Optional.of("INTENT"),
                        Optional.empty(), Optional.empty(), 0, Optional.empty(), Optional.empty());
                assertEquals(SignWorkflowStore.CreateResult.CREATED, store.createSignIntent(intent));
            }
            advanceToStartupState(store, submissionId, startupState);
            SignWorkflowStore.Record before = store.getSignRecord(submissionId).orElseThrow();
            Map<String, String> filesBefore = fileInventory(root);
            workflowB.resetProviderCalls();
            try (SigningExecutionRuntime runtime = runtime();
                    PkiSigningBus bus = PkiSigningBus.attach(
                            store, workflowB, signingAuthority(workflowB), runtime)) {
                assertEquals(0, workflowB.providerOperationCalls.get());
                assertEquals(0, runtime.metrics().pendingAdvisories());
                assertEquals(0L, runtime.metrics().callbackWake());
                assertRecordUnchanged(before, store.getSignRecord(submissionId).orElseThrow());
                assertEquals(filesBefore, fileInventory(root));

                assertEquals(AsyncState.RUNNING, bus.status(submissionId).orElseThrow().state());
                assertEquals(0, workflowB.providerOperationCalls.get());
                assertRecordUnchanged(before, store.getSignRecord(submissionId).orElseThrow());

                bus.reconcile(new SigningReconciliationRequest(
                        SigningReconciliationContinuation.start(), 8, 8,
                        clock.instant().plusSeconds(10), Duration.ofSeconds(1), CancellationSignal.NONE));
                assertEquals(0, workflowB.providerOperationCalls.get());
                assertRecordUnchanged(before, store.getSignRecord(submissionId).orElseThrow());

                bus.retireSignOperation(submissionId, "configuration-mismatch-test");
                assertEquals(0, workflowB.providerOperationCalls.get());
                assertRecordUnchanged(before, store.getSignRecord(submissionId).orElseThrow());
                assertEquals(filesBefore, fileInventory(root));

                clock.set(deadline);
                bus.retireSignOperation(submissionId, "configuration-mismatch-test");
                assertEquals(0, workflowB.providerOperationCalls.get());
                SignWorkflowStore.Record expired = store.getSignRecord(submissionId).orElseThrow();
                assertEquals(SignWorkflowStore.State.EXPIRED, expired.state());
                assertEquals(before.configurationCommitment(), expired.configurationCommitment());
                assertEquals(AsyncState.EXPIRED, bus.status(submissionId).orElseThrow().state());
                bus.retireSignOperation(submissionId, "configuration-mismatch-test");
                assertEquals(SignWorkflowStore.State.EXPIRED,
                        store.getSignRecord(submissionId).orElseThrow().state());
            }
        } finally {
            workflowA.close();
            workflowB.close();
        }
    }

    @Test
    void ownedInvalidAuthorityClosesEveryRuntimeThreadAndPreservesBorrowedResources(@TempDir Path root)
            throws Exception {
        Set<Thread> before = signingRuntimeThreads();
        LifecycleWorkflow workflow = new LifecycleWorkflow("authority-target", FailurePoint.NONE);
        InMemorySignatureWorkflow foreign = new InMemorySignatureWorkflow(Map.of(), false);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root.resolve("store"), FsPkiStoreOptions.defaults())) {
            assertThrows(IllegalArgumentException.class,
                    () -> new PkiSigningBus(store, workflow, signingAuthority(foreign)));

            assertEquals(before, signingRuntimeThreads());
            assertFalse(workflow.closed.get());
            assertEquals(0, store.listSignRecords().size());
        } finally {
            workflow.close();
            foreign.close();
        }
    }

    @Test
    void ownedDomainAndRegistrationFailuresCloseEveryRuntimeThread(@TempDir Path root) throws Exception {
        Set<Thread> before = signingRuntimeThreads();
        assertOwnedFailure(root.resolve("domain"), new LifecycleWorkflow("domain-failure", FailurePoint.DOMAIN));
        assertEquals(before, signingRuntimeThreads());
        assertOwnedFailure(root.resolve("registration"),
                new LifecycleWorkflow("registration-failure", FailurePoint.REGISTRATION));
        assertEquals(before, signingRuntimeThreads());
    }

    @Test
    void attachedFailureLeavesBorrowedRuntimeOpenAndSchedulable(@TempDir Path root) throws Exception {
        for (FailurePoint point : new FailurePoint[] { FailurePoint.DOMAIN, FailurePoint.REGISTRATION }) {
            LifecycleWorkflow workflow = new LifecycleWorkflow("borrowed-" + point.name().toLowerCase(), point);
            try (FilesystemPkiStore store = new FilesystemPkiStore(root.resolve(point.name()),
                    FsPkiStoreOptions.defaults());
                    SigningExecutionRuntime runtime = runtime()) {
                RuntimeException failure = assertThrows(RuntimeException.class,
                        () -> PkiSigningBus.attach(store, workflow, signingAuthority(workflow), runtime));

                assertSame(workflow.failure, failure);
                assertEquals(SigningExecutionRuntime.State.OPEN, runtime.state());
                try (SigningExecutionRuntime.InitialStepReservation ignored = runtime.reserveInitialStep()) {
                    assertEquals(1, runtime.metrics().schedulerReserved());
                }
                assertEquals(0, runtime.metrics().schedulerReserved());
                assertFalse(workflow.closed.get());
                assertEquals(0, store.listSignRecords().size());
            } finally {
                workflow.close();
            }
        }
    }

    @Test
    void successfulBusCloseHonorsOwnedAndAttachedRuntimeOwnership(@TempDir Path root) throws Exception {
        LifecycleWorkflow ownedWorkflow = new LifecycleWorkflow("owned-success", FailurePoint.NONE);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root.resolve("owned"), FsPkiStoreOptions.defaults())) {
            PkiSigningBus owned = new PkiSigningBus(store, ownedWorkflow, signingAuthority(ownedWorkflow));
            SigningExecutionRuntime ownedRuntime = owned.executionRuntime();

            owned.close();

            assertEquals(SigningExecutionRuntime.State.CLOSED, ownedRuntime.state());
            assertFalse(ownedWorkflow.closed.get());
            assertEquals(0, store.listSignRecords().size());
        } finally {
            ownedWorkflow.close();
        }

        LifecycleWorkflow attachedWorkflow = new LifecycleWorkflow("attached-success", FailurePoint.NONE);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root.resolve("attached"),
                FsPkiStoreOptions.defaults());
                SigningExecutionRuntime runtime = runtime()) {
            PkiSigningBus attached = PkiSigningBus.attach(store, attachedWorkflow,
                    signingAuthority(attachedWorkflow), runtime);

            attached.close();

            assertEquals(SigningExecutionRuntime.State.OPEN, runtime.state());
            try (SigningExecutionRuntime.InitialStepReservation ignored = runtime.reserveInitialStep()) {
                assertEquals(1, runtime.metrics().schedulerReserved());
            }
            assertFalse(attachedWorkflow.closed.get());
            assertEquals(0, store.listSignRecords().size());
        } finally {
            attachedWorkflow.close();
        }
    }

    @Test
    void attachedBusCloseDoesNotWaitForOrCancelUnrelatedBorrowedRuntimeTasks(@TempDir Path root)
            throws Exception {
        LifecycleWorkflow workflow = new LifecycleWorkflow("unrelated-runtime", FailurePoint.NONE);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root.resolve("store"), FsPkiStoreOptions.defaults());
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 1,
                        Duration.ofMillis(100), Duration.ofMillis(100))) {
            PkiSigningBus bus = PkiSigningBus.attach(store, workflow, signingAuthority(workflow), runtime);
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            SigningExecutionRuntime.StepSubmission<String> running = runtime.scheduleStep(new PkiId("unrelated-1"),
                    () -> {
                        entered.countDown();
                        release.await();
                        return "running";
                    }, CancellationSignal.NONE);
            assertEquals(SigningExecutionRuntime.StepDisposition.ACCEPTED, running.disposition());
            assertTrue(entered.await(1, TimeUnit.SECONDS));
            SigningExecutionRuntime.StepSubmission<String> queued = runtime.scheduleStep(new PkiId("unrelated-2"),
                    () -> "queued", CancellationSignal.NONE);
            assertEquals(SigningExecutionRuntime.StepDisposition.ACCEPTED, queued.disposition());

            bus.close();

            assertEquals(SigningExecutionRuntime.State.OPEN, runtime.state());
            assertEquals(2, runtime.metrics().schedulerReserved());
            release.countDown();
            assertEquals("running", running.future().orElseThrow().get(1, TimeUnit.SECONDS));
            assertEquals("queued", queued.future().orElseThrow().get(1, TimeUnit.SECONDS));
        } finally {
            workflow.close();
        }
    }

    private static void assertOwnedFailure(Path root, LifecycleWorkflow workflow) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            RuntimeException failure = assertThrows(RuntimeException.class,
                    () -> new PkiSigningBus(store, workflow, signingAuthority(workflow)));
            assertSame(workflow.failure, failure);
            assertFalse(workflow.closed.get());
            assertEquals(0, store.listSignRecords().size());
        } finally {
            workflow.close();
        }
    }

    private static SigningExecutionRuntime runtime() {
        return new SigningExecutionRuntime(1, 0, Duration.ofMillis(100), Duration.ofMillis(100));
    }

    private static PkiStore trackingStore(FilesystemPkiStore delegate, AtomicInteger pageCalls,
            AtomicInteger pointReads) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class }, (proxy, method, arguments) -> {
                    if ("pageSignRecords".equals(method.getName())) {
                        pageCalls.incrementAndGet();
                    } else if ("getSignRecord".equals(method.getName())) {
                        pointReads.incrementAndGet();
                    }
                    try {
                        return method.invoke(delegate, arguments);
                    } catch (InvocationTargetException failure) {
                        throw failure.getCause();
                    }
                });
    }

    private static Set<Thread> signingRuntimeThreads() {
        return Thread.getAllStackTraces().keySet().stream().filter(Thread::isAlive)
                .filter(thread -> thread.getName().startsWith("zeroecho-signing-lane-")
                        || thread.getName().equals("zeroecho-signing-advisory-notifier"))
                .collect(Collectors.toUnmodifiableSet());
    }

    private static SignatureWorkflow.ConfigurationCommitment commitment(byte value) {
        byte[] bytes = new byte[SignatureWorkflow.ConfigurationCommitment.BYTE_LENGTH];
        java.util.Arrays.fill(bytes, value);
        return new SignatureWorkflow.ConfigurationCommitment(bytes);
    }

    private static void advanceToStartupState(FilesystemPkiStore store, PkiId submissionId,
            StartupState startupState) {
        if (startupState == StartupState.INITIAL_INTENT) return;
        SignWorkflowStore.Record current = store.getSignRecord(submissionId).orElseThrow();
        current = store.tryClaimSign(submissionId, current.revision(), Duration.ofSeconds(10)).orElseThrow();
        if (startupState == StartupState.FENCED_INTENT) return;
        current = store.transitionSign(submissionId, current.revision(), current.fence(),
                SignWorkflowStore.State.DISPATCHED, Optional.of("DISPATCHED"), Optional.empty(), Optional.empty())
                .orElseThrow();
        if (startupState == StartupState.DISPATCHED) return;
        store.transitionSign(submissionId, current.revision(), current.fence(),
                SignWorkflowStore.State.CANCELLING, Optional.of("CANCEL_REQUESTED"), Optional.empty(),
                Optional.empty()).orElseThrow();
    }

    private static Map<String, String> fileInventory(Path root) throws Exception {
        Map<String, String> inventory = new HashMap<>();
        try (var paths = Files.walk(root)) {
            for (Path path : paths.filter(Files::isRegularFile).toList()) {
                inventory.put(root.relativize(path).toString(),
                        Base64.getEncoder().encodeToString(Files.readAllBytes(path)));
            }
        }
        return Map.copyOf(inventory);
    }

    private static void assertRecordUnchanged(SignWorkflowStore.Record expected,
            SignWorkflowStore.Record actual) {
        assertEquals(expected.submissionId(), actual.submissionId());
        assertEquals(expected.namespace(), actual.namespace());
        assertEquals(expected.fingerprint(), actual.fingerprint());
        assertEquals(expected.configurationCommitment(), actual.configurationCommitment());
        assertEquals(expected.owner(), actual.owner());
        assertEquals(expected.createdAt(), actual.createdAt());
        assertEquals(expected.deadline(), actual.deadline());
        assertEquals(expected.state(), actual.state());
        assertEquals(expected.revision(), actual.revision());
        assertEquals(expected.fence(), actual.fence());
        assertEquals(expected.leaseUntil(), actual.leaseUntil());
        assertEquals(expected.detailCode(), actual.detailCode());
        assertEquals(expected.providerUpdatedAt(), actual.providerUpdatedAt());
        assertEquals(expected.failureCount(), actual.failureCount());
        assertEquals(expected.nextEligibleAt(), actual.nextEligibleAt());
        assertEquals(expected.reconciliationFailureClass(), actual.reconciliationFailureClass());
        assertEquals(expected.request().encoding(), actual.request().encoding());
        assertArrayEquals(expected.request().bytes(), actual.request().bytes());
        assertEquals(expected.result().isPresent(), actual.result().isPresent());
        if (expected.result().isPresent()) {
            assertEquals(expected.result().orElseThrow().encoding(), actual.result().orElseThrow().encoding());
            assertArrayEquals(expected.result().orElseThrow().bytes(), actual.result().orElseThrow().bytes());
        }
    }

    private static final class MutableClock extends Clock {
        private final AtomicReference<Instant> value;

        private MutableClock(Instant value) {
            this.value = new AtomicReference<>(value);
        }

        private void set(Instant instant) {
            value.set(instant);
        }

        @Override public ZoneId getZone() {
            return java.time.ZoneOffset.UTC;
        }

        @Override public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override public Instant instant() {
            return value.get();
        }
    }

    private enum FailurePoint {
        NONE,
        DOMAIN,
        REGISTRATION
    }

    private enum StartupState {
        INITIAL_INTENT,
        FENCED_INTENT,
        DISPATCHED,
        CANCELLING
    }

    private static final class LifecycleWorkflow implements SignatureWorkflow {
        private final String id;
        private final FailurePoint failurePoint;
        private final RuntimeException failure = new IllegalStateException("deliberate constructor failure");
        private final AtomicBoolean closed = new AtomicBoolean();
        private final ConfigurationCommitment configurationCommitment;
        private final AtomicInteger providerCalls = new AtomicInteger();
        private final AtomicInteger providerOperationCalls = new AtomicInteger();
        private final AtomicReference<NotificationSink> notificationSink = new AtomicReference<>();
        private final boolean notifyDuringRegistration;
        private final boolean notifyDuringRegistrationClose;

        private LifecycleWorkflow(String id, FailurePoint failurePoint) {
            this(id, failurePoint, commitment((byte) 0));
        }

        private LifecycleWorkflow(String id, FailurePoint failurePoint,
                ConfigurationCommitment configurationCommitment) {
            this(id, failurePoint, configurationCommitment, false, false);
        }

        private LifecycleWorkflow(String id, FailurePoint failurePoint,
                ConfigurationCommitment configurationCommitment, boolean notifyDuringRegistration,
                boolean notifyDuringRegistrationClose) {
            this.id = id;
            this.failurePoint = failurePoint;
            this.configurationCommitment = configurationCommitment;
            this.notifyDuringRegistration = notifyDuringRegistration;
            this.notifyDuringRegistrationClose = notifyDuringRegistrationClose;
        }

        @Override public String id() {
            return id;
        }

        @Override public ConfigurationCommitment configurationCommitment() {
            return configurationCommitment;
        }

        @Override public void validateSigningDomain(String namespace, Duration horizon, Duration permittedSkew) {
            providerCalls.incrementAndGet();
            if (failurePoint == FailurePoint.DOMAIN) {
                throw failure;
            }
            SignatureWorkflow.super.validateSigningDomain(namespace, horizon, permittedSkew);
        }

        @Override public PkiId submitSign(SignRequest request, CallControl control) {
            providerCalls.incrementAndGet();
            providerOperationCalls.incrementAndGet();
            throw new UnsupportedOperationException();
        }

        @Override public PkiId submitVerify(VerifyRequest request, CallControl control) {
            throw new UnsupportedOperationException();
        }

        @Override public OperationStatus status(PkiId operationId, CallControl control) {
            providerCalls.incrementAndGet();
            providerOperationCalls.incrementAndGet();
            throw new UnsupportedOperationException();
        }

        @Override public boolean cancel(PkiId operationId, long fencingToken, String reason, CallControl control) {
            providerCalls.incrementAndGet();
            providerOperationCalls.incrementAndGet();
            return false;
        }

        @Override public Registration register(NotificationSink sink) {
            providerCalls.incrementAndGet();
            if (failurePoint == FailurePoint.REGISTRATION) {
                throw failure;
            }
            notificationSink.set(sink);
            if (notifyDuringRegistration) {
                sink.onStatusChanged(new PkiId("synchronous-registration"), runningStatus());
            }
            return () -> {
                if (notifyDuringRegistrationClose) {
                    sink.onStatusChanged(new PkiId("registration-close"), runningStatus());
                }
                notificationSink.compareAndSet(sink, null);
            };
        }

        @Override public Set<String> supportedAlgorithms() {
            providerCalls.incrementAndGet();
            return Set.of("SHA256withRSA");
        }

        private void resetProviderCalls() {
            providerCalls.set(0);
            providerOperationCalls.set(0);
        }

        private static OperationStatus runningStatus() {
            return new OperationStatus(State.RUNNING, Instant.EPOCH, Optional.of("RUNNING"), Optional.empty());
        }

        @Override public void close() {
            closed.set(true);
        }
    }
}
