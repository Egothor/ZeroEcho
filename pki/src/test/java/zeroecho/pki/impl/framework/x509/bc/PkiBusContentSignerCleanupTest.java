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
package zeroecho.pki.impl.framework.x509.bc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static zeroecho.pki.testkit.PkiTestRuntime.signingAuthority;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.impl.core.async.SigningExecutionRuntime;
import zeroecho.pki.impl.core.async.DomainCommandEncoding;
import zeroecho.pki.impl.core.async.DomainContinuationTemplate;
import zeroecho.pki.impl.core.async.PendingSigningOperation;
import zeroecho.pki.impl.crypto.zeroecholib.TestKeyringUnlocks;
import zeroecho.pki.impl.crypto.zeroecholib.ZeroEchoLibSignatureWorkflowProvider;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.fs.AtomicLocalSigningLedgerParticipant;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FilesystemPkiStoreTestAccess;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.crypto.SignatureWorkflowRuntimeDependencies;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.testkit.DurableOperatorApprovalSignatureWorkflow;
import zeroecho.pki.testkit.InMemorySignatureWorkflow;

final class PkiBusContentSignerCleanupTest {

    @Test
    void approvalPendingReturnsWithAtomicOuterContinuationAndNoRuntimeReservation(@TempDir Path tempDir)
            throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        DurableOperatorApprovalSignatureWorkflow workflow = new DurableOperatorApprovalSignatureWorkflow(
                tempDir.resolve("provider"), Duration.ofMinutes(5), Duration.ZERO,
                Map.of("test", keyPair.getPrivate()));
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                    FsPkiStoreOptions.defaults());
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                        Duration.ofMillis(100), Duration.ofMillis(100));
                PkiSigningBus bus = PkiSigningBus.attach(store, workflow, signingAuthority(workflow), runtime)) {
            DomainContinuationTemplate domain = DomainCommandEncoding.template(
                    DomainContinuationStore.Kind.ISSUANCE, "ISSUE_END_ENTITY", domainFields("", ""));
            PkiBusContentSigner signer = new PkiBusContentSigner(bus, new KeyRef("test"),
                    bus.authority().resolveIdentity("SHA256withRSA"), Duration.ofMinutes(5),
                    zeroecho.core.io.CancellationSignal.NONE, domain);
            signer.getOutputStream().write(new byte[] { 1, 2, 3 });

            PendingSigningOperation pending = assertThrows(PendingSigningOperation.class,
                    signer::getSignature);

            assertEquals(0, runtime.metrics().schedulerReserved());
            assertEquals(SignWorkflowStore.State.DISPATCHED,
                    store.getSignRecord(pending.operationId()).orElseThrow().state());
            DomainContinuationStore.Record continuation = store.getDomainContinuation(
                    pending.operationId()).orElseThrow();
            assertEquals(pending.operationId(), continuation.operationId());
            assertEquals(DomainContinuationStore.State.SIGNING, continuation.state());
            assertEquals(domain.commandCommitment(), continuation.commandCommitment());
            assertTrue(store.getSignRecord(pending.operationId()).isPresent());
        } finally {
            workflow.close();
        }
    }

    @Test
    void restartResolvesSamePendingOperationThroughDurableCorrelation(@TempDir Path tempDir)
            throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        Path storeRoot = tempDir.resolve("store");
        DurableOperatorApprovalSignatureWorkflow workflow = new DurableOperatorApprovalSignatureWorkflow(
                tempDir.resolve("provider"), Duration.ofMinutes(5), Duration.ZERO,
                Map.of("test", keyPair.getPrivate()));
        PkiId operationId;
        try {
            try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults());
                    SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                            Duration.ofMillis(100), Duration.ofMillis(100));
                    PkiSigningBus bus = PkiSigningBus.attach(store, workflow, signingAuthority(workflow), runtime)) {
                DomainContinuationTemplate domain = DomainCommandEncoding.correlatedTemplate(
                        DomainContinuationStore.Kind.ISSUANCE, "order:restart-fixture",
                        "ISSUE_END_ENTITY", domainFields("order:restart-fixture", "1".repeat(64)));
                PkiBusContentSigner signer = new PkiBusContentSigner(bus, new KeyRef("test"),
                        bus.authority().resolveIdentity("SHA256withRSA"), Duration.ofMinutes(5),
                        zeroecho.core.io.CancellationSignal.NONE, domain);
                signer.getOutputStream().write(new byte[] { 4, 5, 6 });
                operationId = assertThrows(PendingSigningOperation.class, signer::getSignature).operationId();
            }

            try (FilesystemPkiStore reopened = new FilesystemPkiStore(storeRoot,
                    FsPkiStoreOptions.defaults())) {
                DomainContinuationStore.Record recovered = reopened.getDomainContinuation(
                        DomainContinuationStore.Kind.ISSUANCE, "order:restart-fixture").orElseThrow();
                assertEquals(operationId, recovered.operationId());
                assertEquals(Optional.of("order:restart-fixture"), recovered.correlationId());
                assertEquals(DomainContinuationStore.State.SIGNING, recovered.state());
                assertTrue(reopened.getSignRecord(operationId).isPresent());
            }
        } finally {
            workflow.close();
        }
    }

    private static String[] domainFields(String issuanceId, String issuanceCommitment) {
        String digest = "1".repeat(64);
        return new String[] { "ca:test", "issuer:test", "path:test", digest, "leaf", "1", digest,
                "subject:test", "2026-08-20T10:00:00Z", "2026-08-20T11:00:00Z", "1", "key:test",
                "content:test", digest, digest, issuanceId, issuanceCommitment,
                "CN=test", "[]", "[]", "[]", "binding:test",
                zeroecho.pki.impl.core.async.DomainAttributeEncoding.encode(
                        zeroecho.pki.impl.core.attr.SimpleAttributeSet.builder().build()) };
    }

    @Test
    void realSignerOverloadRejectsBeforeStagingOrDurableIdentity(@TempDir Path tempDir) throws Exception {
        InMemorySignatureWorkflow workflow = new InMemorySignatureWorkflow(Map.of(), false);
        Path storeRoot = tempDir.resolve("store");
        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults());
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                        Duration.ofMillis(100), Duration.ofMillis(100));
                PkiSigningBus bus = PkiSigningBus.attach(store, workflow, signingAuthority(workflow), runtime);
                SigningExecutionRuntime.InitialStepReservation occupied = runtime.reserveInitialStep()) {
            SigningExecutionException overloaded = assertThrows(SigningExecutionException.class,
                    () -> new PkiBusContentSigner(bus, new KeyRef("test"), "SHA256withRSA",
                            Duration.ofSeconds(1)));

            assertEquals(SigningExecutionException.Classification.OVERLOADED, overloaded.classification());
            assertEquals(0L, stagedFileCount(storeRoot));
            assertTrue(store.listSignRecords().isEmpty());
            assertEquals(0, workflow.submittedSignCount());
        } finally {
            workflow.close();
        }
    }

    @Test
    void durableWorkflowOverloadRollsBackSchedulerBeforeStagingOrIdentity(@TempDir Path tempDir)
            throws Exception {
        InMemorySignatureWorkflow workflow = new InMemorySignatureWorkflow(Map.of(), false);
        Path storeRoot = tempDir.resolve("store");
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(storeRoot, 1);
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                        Duration.ofMillis(100), Duration.ofMillis(100));
                PkiSigningBus bus = PkiSigningBus.attach(store, workflow, signingAuthority(workflow), runtime);
                SignWorkflowStore.SignAdmission occupied = store.reserveSignAdmission()) {
            SigningExecutionException overloaded = assertThrows(SigningExecutionException.class,
                    () -> new PkiBusContentSigner(bus, new KeyRef("test"), "SHA256withRSA",
                            Duration.ofSeconds(1)));

            assertEquals(SigningExecutionException.Classification.OVERLOADED, overloaded.classification());
            assertEquals(0, runtime.metrics().schedulerReserved());
            assertEquals(0L, stagedFileCount(storeRoot));
            assertTrue(store.listSignRecords().isEmpty());
            assertEquals(0, workflow.submittedSignCount());
        } finally {
            workflow.close();
        }
    }

    @Test
    void shutdownBeforeIntentReleasesStagingAndAdmissions(@TempDir Path tempDir) throws Exception {
        InMemorySignatureWorkflow workflow = new InMemorySignatureWorkflow(Map.of(), false);
        Path storeRoot = tempDir.resolve("store");
        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults());
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                        Duration.ofMillis(100), Duration.ofMillis(100));
                PkiSigningBus bus = PkiSigningBus.attach(store, workflow, signingAuthority(workflow), runtime,
                        Duration.ofMillis(1), Duration.ofMillis(1));
                PkiBusContentSigner signer = new PkiBusContentSigner(bus, new KeyRef("test"),
                        "SHA256withRSA", Duration.ofSeconds(5))) {
            signer.getOutputStream().write(1);

            bus.close();
            SigningExecutionException cancelled = assertThrows(SigningExecutionException.class,
                    signer::getSignature);

            assertEquals(SigningExecutionException.Classification.SHUTTING_DOWN, cancelled.classification());
            assertEquals(0L, stagedFileCount(storeRoot));
            assertTrue(store.listSignRecords().isEmpty());
            assertEquals(0, workflow.submittedSignCount());
            assertEquals(0, runtime.metrics().schedulerReserved());
            bus.close();
        } finally {
            workflow.close();
        }
    }

    @Test
    void forcedCancellationBeforeCommitGateLeavesNoDurableOrStagedState(@TempDir Path tempDir)
            throws Exception {
        InMemorySignatureWorkflow workflow = new InMemorySignatureWorkflow(Map.of(), false);
        Path storeRoot = tempDir.resolve("store");
        CountDownLatch preparationEntered = new CountDownLatch(1);
        CountDownLatch releasePreparation = new CountDownLatch(1);
        AtomicBoolean blockNextStagedContentLookup = new AtomicBoolean();
        try (FilesystemPkiStore delegate = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults());
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                        Duration.ofMillis(100), Duration.ofMillis(100))) {
            PkiStore store = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                    new Class<?>[] { PkiStore.class }, (proxy, method, arguments) -> {
                        if ("stagedContent".equals(method.getName())
                                && blockNextStagedContentLookup.compareAndSet(true, false)) {
                            preparationEntered.countDown();
                            if (!releasePreparation.await(2, TimeUnit.SECONDS)) {
                                throw new AssertionError("Signing preparation was not released");
                            }
                        }
                        try {
                            return method.invoke(delegate, arguments);
                        } catch (InvocationTargetException failure) {
                            throw failure.getCause();
                        }
                    });
            try (PkiSigningBus bus = PkiSigningBus.attach(store, workflow, signingAuthority(workflow), runtime,
                    Duration.ofMillis(1), Duration.ofMillis(1));
                    PkiBusContentSigner signer = new PkiBusContentSigner(bus, new KeyRef("test"),
                            "SHA256withRSA", Duration.ofSeconds(5))) {
                signer.getOutputStream().write(1);
                blockNextStagedContentLookup.set(true);
                CompletableFuture<byte[]> signing = CompletableFuture.supplyAsync(signer::getSignature);
                assertTrue(preparationEntered.await(1, TimeUnit.SECONDS));

                SigningExecutionException timeout = assertThrows(SigningExecutionException.class, bus::close);
                assertEquals(SigningExecutionException.Classification.SHUTDOWN_TIMEOUT,
                        timeout.classification());
                releasePreparation.countDown();
                ExecutionException cancelled = assertThrows(ExecutionException.class,
                        () -> signing.get(2, TimeUnit.SECONDS));

                assertTrue(cancelled.getCause() instanceof SigningExecutionException);
                assertTrue(delegate.listSignRecords().isEmpty());
                assertEquals(0L, stagedFileCount(storeRoot));
                assertEquals(0, workflow.submittedSignCount());
                try (SigningExecutionRuntime.InitialStepReservation ignored = runtime.reserveInitialStep();
                        SignWorkflowStore.SignAdmission ignoredAdmission = delegate.reserveSignAdmission()) {
                    assertEquals(1, runtime.metrics().schedulerReserved());
                }
                assertEquals(0, runtime.metrics().schedulerReserved());
                bus.close();
            }
        } finally {
            releasePreparation.countDown();
            workflow.close();
        }
    }

    @Test
    void forcedCancellationProgressesWhileRemoteIntentCreationIsBlocked(@TempDir Path tempDir)
            throws Exception {
        InMemorySignatureWorkflow workflow = new InMemorySignatureWorkflow(Map.of(), false);
        Path storeRoot = tempDir.resolve("store");
        CountDownLatch createEntered = new CountDownLatch(1);
        CountDownLatch releaseCreate = new CountDownLatch(1);
        AtomicBoolean blockCreate = new AtomicBoolean(true);
        try (FilesystemPkiStore delegate = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults());
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                        Duration.ofMillis(100), Duration.ofMillis(100))) {
            PkiStore store = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                    new Class<?>[] { PkiStore.class }, (proxy, method, arguments) -> {
                        if ("createSignIntent".equals(method.getName()) && arguments.length == 2
                                && blockCreate.compareAndSet(true, false)) {
                            createEntered.countDown();
                            if (!releaseCreate.await(2, TimeUnit.SECONDS)) {
                                throw new AssertionError("Remote intent creation was not released");
                            }
                        }
                        try {
                            return method.invoke(delegate, arguments);
                        } catch (InvocationTargetException failure) {
                            throw failure.getCause();
                        }
                    });
            try (PkiSigningBus bus = PkiSigningBus.attach(store, workflow, signingAuthority(workflow), runtime,
                    Duration.ofMillis(1), Duration.ofMillis(1));
                    PkiBusContentSigner signer = new PkiBusContentSigner(bus, new KeyRef("test"),
                            "SHA256withRSA", Duration.ofSeconds(5))) {
                signer.getOutputStream().write(1);
                CompletableFuture<byte[]> signing = CompletableFuture.supplyAsync(signer::getSignature);
                assertTrue(createEntered.await(1, TimeUnit.SECONDS));

                SigningExecutionException timeout = assertThrows(SigningExecutionException.class, bus::close);

                assertEquals(SigningExecutionException.Classification.SHUTDOWN_TIMEOUT,
                        timeout.classification());
                assertEquals("OPEN", runtime.metrics().state().name());
                delegate.signingNow();
                releaseCreate.countDown();
                ExecutionException cancelled = assertThrows(ExecutionException.class,
                        () -> signing.get(2, TimeUnit.SECONDS));
                assertTrue(cancelled.getCause() instanceof SigningExecutionException);
                assertEquals(0, workflow.submittedSignCount());
                SignWorkflowStore.Record retained = delegate.listSignRecords().getFirst();
                assertEquals(SignWorkflowStore.State.RETIRED, retained.state());
                assertTrue(retained.result().isEmpty());
                bus.close();
            }
        } finally {
            releaseCreate.countDown();
            workflow.close();
        }
    }

    @Test
    void forcedCancellationProgressesWhileLocalAcceptanceIsBlocked(@TempDir Path tempDir)
            throws Exception {
        Path keyring = tempDir.resolve("keyring.zek");
        KeyPair pair = generateRsa();
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keys = KeyringStore.create(keyring, password)) {
            keys.putPrivate("sign.prv", "RSA", pair.getPrivate());
        }
        CountDownLatch acceptEntered = new CountDownLatch(1);
        CountDownLatch releaseAccept = new CountDownLatch(1);
        AtomicBoolean blockAccept = new AtomicBoolean(true);
        AtomicInteger localCompletions = new AtomicInteger();
        try (FilesystemPkiStore delegate = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults());
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                        Duration.ofMillis(100), Duration.ofMillis(100))) {
            PkiStore store = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                    new Class<?>[] { PkiStore.class, AtomicLocalSigningLedgerParticipant.class },
                    (proxy, method, arguments) -> {
                        if ("acceptLocalSign".equals(method.getName()) && arguments.length == 5
                                && blockAccept.compareAndSet(true, false)) {
                            acceptEntered.countDown();
                            if (!releaseAccept.await(2, TimeUnit.SECONDS)) {
                                throw new AssertionError("Local signing acceptance was not released");
                            }
                        }
                        if ("completeLocalSign".equals(method.getName())) {
                            localCompletions.incrementAndGet();
                        }
                        try {
                            return method.invoke(delegate, arguments);
                        } catch (InvocationTargetException failure) {
                            throw failure.getCause();
                        }
                    });
            AtomicLocalSigningLedgerParticipant participant = (AtomicLocalSigningLedgerParticipant) store;
            try (SignatureWorkflow workflow = new ZeroEchoLibSignatureWorkflowProvider(
                    TestKeyringUnlocks.provider()).allocate(
                            new ProviderConfig("zeroecho-lib", Map.of("keyringPath", keyring.toString())),
                            SignatureWorkflowRuntimeDependencies.local(TestKeyringUnlocks.provider(), participant));
                    PkiSigningBus bus = PkiSigningBus.attach(store, workflow, signingAuthority(workflow), runtime,
                            Duration.ofMillis(1), Duration.ofMillis(1));
                    PkiBusContentSigner signer = new PkiBusContentSigner(bus,
                            new KeyRef("zeroecho-lib:sign.prv"), "SHA256withRSA", Duration.ofSeconds(5))) {
                signer.getOutputStream().write(1);
                CompletableFuture<byte[]> signing = CompletableFuture.supplyAsync(signer::getSignature);
                assertTrue(acceptEntered.await(1, TimeUnit.SECONDS));

                SigningExecutionException timeout = assertThrows(SigningExecutionException.class, bus::close);

                assertEquals(SigningExecutionException.Classification.SHUTDOWN_TIMEOUT,
                        timeout.classification());
                assertEquals("OPEN", runtime.metrics().state().name());
                delegate.signingNow();
                releaseAccept.countDown();
                ExecutionException cancelled = assertThrows(ExecutionException.class,
                        () -> signing.get(2, TimeUnit.SECONDS));
                assertTrue(cancelled.getCause() instanceof SigningExecutionException);
                assertEquals(0, localCompletions.get());
                SignWorkflowStore.Record retained = delegate.listSignRecords().getFirst();
                assertEquals(SignWorkflowStore.State.CANCELLING, retained.state());
                assertTrue(retained.result().isEmpty());
                bus.close();
            }
        } finally {
            releaseAccept.countDown();
        }
    }

    @Test
    void callerCancellationReachesProviderControlAndRetainsDurableEvidence(@TempDir Path tempDir)
            throws Exception {
        AtomicBoolean callerCancelled = new AtomicBoolean();
        try (SignalOnlyWorkflow workflow = new SignalOnlyWorkflow();
                FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                        FsPkiStoreOptions.defaults());
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                        Duration.ofMillis(100), Duration.ofMillis(100));
                PkiSigningBus bus = PkiSigningBus.attach(store, workflow, signingAuthority(workflow), runtime);
                PkiBusContentSigner signer = new PkiBusContentSigner(bus, new KeyRef("test"),
                        "SHA256withRSA", Duration.ofSeconds(5), callerCancelled::get)) {
            signer.getOutputStream().write(1);
            CompletableFuture<byte[]> signing = CompletableFuture.supplyAsync(signer::getSignature);
            assertTrue(workflow.submitEntered.await(1, TimeUnit.SECONDS));
            assertTrue(workflow.rawInterruptIgnored.get());

            callerCancelled.set(true);
            ExecutionException cancelled = assertThrows(ExecutionException.class,
                    () -> signing.get(2, TimeUnit.SECONDS));

            assertInstanceOf(PkiException.class, cancelled.getCause());
            assertTrue(workflow.controlCancellationObserved.get());
            assertEquals(0, workflow.cryptoCompletions.get());
            SignWorkflowStore.Record retained = store.listSignRecords().getFirst();
            assertEquals(SignWorkflowStore.State.RETIRED, retained.state());
            assertTrue(retained.result().isEmpty());
        }
    }

    @Test
    void foregroundShutdownCancellationReachesProviderControl(@TempDir Path tempDir) throws Exception {
        try (SignalOnlyWorkflow workflow = new SignalOnlyWorkflow();
                FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                        FsPkiStoreOptions.defaults());
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                        Duration.ofMillis(100), Duration.ofMillis(100));
                PkiSigningBus bus = PkiSigningBus.attach(store, workflow, signingAuthority(workflow), runtime,
                        Duration.ofMillis(1), Duration.ofSeconds(1));
                PkiBusContentSigner signer = new PkiBusContentSigner(bus, new KeyRef("test"),
                        "SHA256withRSA", Duration.ofSeconds(5))) {
            signer.getOutputStream().write(1);
            CompletableFuture<byte[]> signing = CompletableFuture.supplyAsync(signer::getSignature);
            assertTrue(workflow.submitEntered.await(1, TimeUnit.SECONDS));

            bus.close();
            ExecutionException cancelled = assertThrows(ExecutionException.class,
                    () -> signing.get(2, TimeUnit.SECONDS));

            assertInstanceOf(PkiException.class, cancelled.getCause());
            assertTrue(workflow.controlCancellationObserved.get());
            assertEquals(0, workflow.cryptoCompletions.get());
            assertEquals(SignWorkflowStore.State.RETIRED, store.listSignRecords().getFirst().state());
        }
    }

    @Test
    void unsubmittedOpenSignerDoesNotBlockBusShutdown(@TempDir Path tempDir) throws Exception {
        try (SignalOnlyWorkflow workflow = new SignalOnlyWorkflow();
                FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                        FsPkiStoreOptions.defaults());
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                        Duration.ofMillis(100), Duration.ofMillis(100));
                PkiSigningBus bus = PkiSigningBus.attach(store, workflow, signingAuthority(workflow), runtime,
                        Duration.ofMillis(1), Duration.ofMillis(1));
                PkiBusContentSigner signer = new PkiBusContentSigner(bus, new KeyRef("test"),
                        "SHA256withRSA", Duration.ofSeconds(5))) {
            signer.getOutputStream().write(1);

            bus.close();
        }
    }

    @Test
    void localInitialSubmissionConsumesTheCompositeStoreAdmission(@TempDir Path tempDir) throws Exception {
        Path keyring = tempDir.resolve("keyring.zek");
        KeyPair pair = generateRsa();
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keys = KeyringStore.create(keyring, password)) {
            keys.putPrivate("sign.prv", "RSA", pair.getPrivate());
        }
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(tempDir.resolve("store"), 1);
                SignatureWorkflow workflow = new ZeroEchoLibSignatureWorkflowProvider(TestKeyringUnlocks.provider())
                        .allocate(new ProviderConfig("zeroecho-lib", Map.of("keyringPath", keyring.toString())),
                                SignatureWorkflowRuntimeDependencies.local(TestKeyringUnlocks.provider(), store));
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                        Duration.ofMillis(100), Duration.ofMillis(100));
                PkiSigningBus bus = PkiSigningBus.attach(store, workflow, signingAuthority(workflow), runtime);
                PkiBusContentSigner signer = new PkiBusContentSigner(bus,
                        new KeyRef("zeroecho-lib:sign.prv"), "SHA256withRSA", Duration.ofSeconds(5))) {
            signer.getOutputStream().write(new byte[] { 1, 2, 3 });

            assertTrue(signer.getSignature().length > 0);
            assertEquals(0, runtime.metrics().schedulerReserved());
        }
    }

    @Test
    void endEntityFailureRetiresEverySigningArtifact(@TempDir Path tempDir) throws Exception {
        assertCleanup(tempDir, false);
    }

    @Test
    void intermediateFailureRetiresEverySigningArtifact(@TempDir Path tempDir) throws Exception {
        assertCleanup(tempDir, true);
    }

    @Test
    void closeBeforeCompletionAbortsStagingAndConsumesSigner(@TempDir Path tempDir) throws Exception {
        KeyRef issuerKeyRef = new KeyRef("kref:v1:keyring:test:issuer");
        InMemorySignatureWorkflow workflow = new InMemorySignatureWorkflow(Map.of(), false);
        Path storeRoot = tempDir.resolve("store");
        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, workflow, tempDir.resolve("bus.log"),
                        signingAuthority(workflow))) {
            PkiBusContentSigner signer = new PkiBusContentSigner(bus, issuerKeyRef, "SHA256withRSA",
                    Duration.ofSeconds(5));
            signer.getOutputStream().write(new byte[] { 1, 2, 3 });
            signer.close();
            signer.close();

            assertThrows(IllegalStateException.class, signer::getOutputStream);
            assertThrows(IllegalStateException.class, signer::getSignature);
            assertEquals(0L, stagedFileCount(storeRoot));
            assertEquals(0, workflow.submittedSignCount());
            assertEquals(0, bus.executionRuntime().metrics().schedulerReserved());
            store.reserveSignAdmission().close();
        } finally {
            workflow.close();
        }
    }

    @Test
    void continuationEncodingFailureReleasesCompletedContentAndConsumesSigner(@TempDir Path tempDir) throws Exception {
        KeyRef oversizedKeyRef = new KeyRef("k".repeat(65_536));
        InMemorySignatureWorkflow workflow = new InMemorySignatureWorkflow(Map.of(), false);
        Path storeRoot = tempDir.resolve("store");
        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, workflow, tempDir.resolve("bus.log"),
                        signingAuthority(workflow));
                PkiBusContentSigner signer = new PkiBusContentSigner(bus, oversizedKeyRef, "SHA256withRSA",
                        Duration.ofSeconds(5))) {
            signer.getOutputStream().write(new byte[] { 1, 2, 3 });

            PkiException failure = assertThrows(PkiException.class, signer::getSignature);

            assertEquals("Signing workflow failed: code=SIGNING_WORKFLOW_FAILED", failure.getMessage());
            assertNull(failure.getCause());
            assertEquals(0, failure.getSuppressed().length);
            assertThrows(IllegalStateException.class, signer::getOutputStream);
            assertThrows(IllegalStateException.class, signer::getSignature);
            assertEquals(0, workflow.submittedSignCount());
            assertTrue(store.listSignRecords().isEmpty());
            assertTrue(store.listWorkflowStates().isEmpty());
            assertEquals(0L, stagedFileCount(storeRoot));
            assertEquals(0, bus.executionRuntime().metrics().schedulerReserved());
            store.reserveSignAdmission().close();
        } finally {
            workflow.close();
        }
    }

    @Test
    void interruptionPreservesFlagAndRetiresOperation(@TempDir Path tempDir) throws Exception {
        KeyRef issuerKeyRef = new KeyRef("kref:v1:keyring:test:issuer");
        InMemorySignatureWorkflow workflow = new InMemorySignatureWorkflow(Map.of(), false);
        Path storeRoot = tempDir.resolve("store");
        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, workflow, tempDir.resolve("bus.log"),
                        signingAuthority(workflow));
                PkiBusContentSigner signer = new PkiBusContentSigner(bus, issuerKeyRef, "SHA256withRSA",
                        Duration.ofSeconds(5))) {
            signer.getOutputStream().write(new byte[] { 1, 2, 3 });
            Thread.currentThread().interrupt();
            try {
                SigningExecutionException failure = assertThrows(SigningExecutionException.class,
                        signer::getSignature);
                assertEquals(SigningExecutionException.Classification.SHUTTING_DOWN, failure.classification());
                assertEquals("Signing foreground call is cancelled: code=SIGNING_SHUTTING_DOWN",
                        failure.getMessage());
                assertNull(failure.getCause());
                assertEquals(0, failure.getSuppressed().length);
                assertTrue(Thread.currentThread().isInterrupted());
            } finally {
                Thread.interrupted();
            }
            assertTrue(store.listSignRecords().isEmpty());
            assertFalse(workflow.hasRunningOperations());
            assertEquals(0L, stagedFileCount(storeRoot));
            assertEquals(0, bus.executionRuntime().metrics().schedulerReserved());
        } finally {
            workflow.close();
        }
    }

    @Test
    void timeoutRetiresOperationAndStagedContent(@TempDir Path tempDir) throws Exception {
        KeyRef issuerKeyRef = new KeyRef("kref:v1:keyring:test:issuer");
        InMemorySignatureWorkflow workflow = new InMemorySignatureWorkflow(Map.of(), false);
        Path storeRoot = tempDir.resolve("store");
        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, workflow, tempDir.resolve("bus.log"),
                        signingAuthority(workflow));
                PkiBusContentSigner signer = new PkiBusContentSigner(bus, issuerKeyRef, "SHA256withRSA",
                        Duration.ofMillis(1))) {
            signer.getOutputStream().write(new byte[] { 1, 2, 3 });

            PkiException failure = assertThrows(PkiException.class, signer::getSignature);

            assertEquals("Signing workflow failed: code=SIGNING_WORKFLOW_FAILED", failure.getMessage());
            assertNull(failure.getCause());
            assertEquals(0, failure.getSuppressed().length);
            assertFalse(workflow.hasRunningOperations());
            assertEquals(0L, stagedFileCount(storeRoot));
        } finally {
            workflow.close();
        }
    }

    @Test
    void crlPostconditionRejectsEqualFingerprintForeignPlan(@TempDir Path tempDir) throws Exception {
        System.out.println("crlPostconditionRejectsEqualFingerprintForeignPlan");
        KeyRef issuerKeyRef = new KeyRef("kref:v1:keyring:test:issuer");
        InMemorySignatureWorkflow signer = new InMemorySignatureWorkflow(
                Map.of(issuerKeyRef.value(), generateRsa()));
        X509AuthoritySnapshot owning = signingAuthority(signer);
        X509AuthoritySnapshot foreign = signingAuthority(signer);
        try (FilesystemPkiStore store = new FilesystemPkiStore(tempDir.resolve("store"),
                FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, signer, tempDir.resolve("bus.log"), owning)) {
            try (PkiBusContentSigner contentSigner = new PkiBusContentSigner(bus, issuerKeyRef, "SHA256withRSA",
                    Duration.ofSeconds(5))) {
                X509ExecutionPlan<SignatureWorkflow> plan = contentSigner.executionPlan();

                BcX509StatusObjectGenerator.requireAuthorizedSigningPlan(owning, plan,
                        plan.selection().requested());
                assertEquals(owning.semanticFingerprint(), foreign.semanticFingerprint());
                assertThrows(IllegalArgumentException.class,
                        () -> BcX509StatusObjectGenerator.requireAuthorizedSigningPlan(foreign, plan,
                                plan.selection().requested()));
                assertThrows(PkiException.class,
                        () -> BcX509StatusObjectGenerator.requireAuthorizedSigningPlan(owning, plan,
                                BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384));
                contentSigner.getOutputStream().write(1);
                contentSigner.getSignature();
                assertThrows(IllegalStateException.class, contentSigner::getSignature);
                System.out.println("...fingerprint=" + owning.semanticFingerprint().substring(0, 16));
                System.out.println("crlPostconditionRejectsEqualFingerprintForeignPlan...ok");
            }
        } finally {
            signer.close();
        }
    }

    private static void assertCleanup(Path tempDir, boolean intermediate) throws Exception {
        KeyPair subjectKey = generateRsa();
        KeyRef issuerKeyRef = new KeyRef("kref:v1:keyring:test:issuer");
        InMemorySignatureWorkflow signer = new InMemorySignatureWorkflow(Map.of(), true);
        Path storeRoot = tempDir.resolve("store");

        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, FsPkiStoreOptions.defaults());
                PkiSigningBus bus = new PkiSigningBus(store, signer, signingAuthority(signer))) {
            try (PkiBusContentSigner contentSigner = new PkiBusContentSigner(bus, issuerKeyRef, "SHA256withRSA",
                    Duration.ofSeconds(5))) {
                contentSigner.getOutputStream()
                        .write(intermediate ? subjectKey.getPublic().getEncoded() : new byte[] { 1, 2, 3 });
                PkiException failure = assertThrows(PkiException.class, contentSigner::getSignature);
                assertEquals("Signing workflow failed: code=SIGNING_WORKFLOW_FAILED", failure.getMessage());
                assertNull(failure.getCause());
                assertEquals(0, failure.getSuppressed().length);
            }

            assertEquals(1, signer.submittedSignCount());
            assertTrue(store.listWorkflowStates().isEmpty());
            assertFalse(signer.hasRunningOperations());
            assertTrue(store.listCas().isEmpty());
            assertFalse(Files.exists(storeRoot.resolve("credentials")));

            PkiId operationId = store.listSignRecords().get(0).submissionId();
            try (PkiSigningBus replayed = new PkiSigningBus(store, signer, signingAuthority(signer))) {
                assertEquals(zeroecho.pki.util.async.AsyncState.CANCELLED,
                        replayed.status(operationId).orElseThrow().state());
            }
        } finally {
            signer.close();
        }
    }

    private static long stagedFileCount(Path storeRoot) throws Exception {
        try (java.util.stream.Stream<Path> paths = Files.walk(storeRoot.resolve("staged-content"))) {
            return paths.filter(Files::isRegularFile).count();
        }
    }

    private static KeyPair generateRsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static final class SignalOnlyWorkflow implements SignatureWorkflow {
        private final CountDownLatch submitEntered = new CountDownLatch(1);
        private final AtomicBoolean rawInterruptIgnored = new AtomicBoolean();
        private final AtomicBoolean controlCancellationObserved = new AtomicBoolean();
        private final AtomicBoolean accepted = new AtomicBoolean();
        private final AtomicBoolean cancelled = new AtomicBoolean();
        private final AtomicInteger cryptoCompletions = new AtomicInteger();

        @Override public String id() { return "signal-only"; }

        @Override public ConfigurationCommitment configurationCommitment() {
            return new ConfigurationCommitment(new byte[ConfigurationCommitment.BYTE_LENGTH]);
        }

        @Override public PkiId submitSign(SignRequest request, CallControl control) {
            Thread.currentThread().interrupt();
            rawInterruptIgnored.set(Thread.interrupted());
            submitEntered.countDown();
            while (!control.cancellation().isCancelled()) {
                Thread.interrupted();
                LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1));
            }
            controlCancellationObserved.set(true);
            accepted.set(true);
            return request.submissionId();
        }

        @Override public PkiId submitVerify(VerifyRequest request, CallControl control) {
            throw new UnsupportedOperationException();
        }

        @Override public OperationStatus status(PkiId operationId, CallControl control) {
            State state = cancelled.get() ? State.CANCELLED : accepted.get() ? State.RUNNING : State.PENDING;
            return new OperationStatus(state, Instant.now(), Optional.of(state.name()), Optional.empty());
        }

        @Override public boolean cancel(PkiId operationId, long fencingToken, String reason, CallControl control) {
            cancelled.set(true);
            return true;
        }

        @Override public Registration register(NotificationSink sink) { return () -> { }; }

        @Override public Set<String> supportedAlgorithms() { return Set.of("SHA256withRSA"); }

        @Override public void close() { }
    }
}
