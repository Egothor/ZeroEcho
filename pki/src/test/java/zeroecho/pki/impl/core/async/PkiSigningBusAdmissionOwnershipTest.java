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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static zeroecho.pki.testkit.PkiTestRuntime.readContent;
import static zeroecho.pki.testkit.PkiTestRuntime.signingAuthority;
import static zeroecho.pki.testkit.PkiTestRuntime.stage;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.impl.crypto.zeroecholib.TestKeyringUnlocks;
import zeroecho.pki.impl.crypto.zeroecholib.ZeroEchoLibSignatureWorkflowProvider;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FilesystemPkiStoreTestAccess;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.crypto.SignatureWorkflowRuntimeDependencies;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.InMemorySignatureWorkflow;

/** Exact bus ownership and deferred admission-binding regression coverage. */
@SuppressWarnings({ "PMD.CloseResource", "PMD.UnitTestContainsTooManyAsserts",
        "PMD.UnitTestAssertionsShouldIncludeMessage" })
final class PkiSigningBusAdmissionOwnershipTest {

    private static final Principal OWNER = new Principal("TEST", "owner");
    private static final AccessContext ACCESS = new AccessContext(OWNER, new Purpose("SIGN"),
            Optional.empty(), Optional.empty());
    private static final String ALGORITHM = "SHA256withRSA";
    private static final KeyRef REMOTE_KEY = new KeyRef("test-key");
    private static final byte[] PAYLOAD = new byte[] { 1, 2, 3, 4 };

    @Test
    void nonForegroundAdmissionsBindForRemoteAndLocalCreation(@TempDir Path root) throws Exception {
        InMemorySignatureWorkflow remoteWorkflow = new InMemorySignatureWorkflow(Map.of(), false);
        try (FilesystemPkiStore remoteStore = new FilesystemPkiStore(root.resolve("remote-store"),
                FsPkiStoreOptions.defaults());
                SigningExecutionRuntime remoteRuntime = runtime();
                PkiSigningBus remoteBus = PkiSigningBus.attach(remoteStore, remoteWorkflow,
                        signingAuthority(remoteWorkflow), remoteRuntime)) {
            Submission remote = stageSubmission(remoteBus, REMOTE_KEY);
            try (PkiSigningBus.NewSignAdmission admission = remoteBus.reserveNewSignAdmission()) {
                submit(remoteBus, admission, remote);
            }

            assertEquals(1, remoteWorkflow.submittedSignCount());
            assertTrue(remoteStore.getSignRecord(remote.id()).isPresent());
            assertEquals(0, remoteRuntime.metrics().schedulerReserved());
        } finally {
            remoteWorkflow.close();
        }

        Path keyring = root.resolve("local-keyring.zek");
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keys = KeyringStore.create(keyring, password)) {
            keys.putPrivate("sign.prv", "RSA", pair.getPrivate());
        }
        try (FilesystemPkiStore localStore = new FilesystemPkiStore(root.resolve("local-store"),
                FsPkiStoreOptions.defaults());
                SignatureWorkflow localWorkflow = new ZeroEchoLibSignatureWorkflowProvider(
                        TestKeyringUnlocks.provider()).allocate(
                                new ProviderConfig("zeroecho-lib", Map.of("keyringPath", keyring.toString())),
                                SignatureWorkflowRuntimeDependencies.local(
                                        TestKeyringUnlocks.provider(), localStore));
                SigningExecutionRuntime localRuntime = runtime();
                PkiSigningBus localBus = PkiSigningBus.attach(localStore, localWorkflow,
                        signingAuthority(localWorkflow), localRuntime)) {
            Submission local = stageSubmission(localBus, new KeyRef("zeroecho-lib:sign.prv"));
            try (PkiSigningBus.NewSignAdmission admission = localBus.reserveNewSignAdmission()) {
                submit(localBus, admission, local);
            }

            assertTrue(localBus.consumeResult(local.id()).isPresent());
            assertEquals(0, localRuntime.metrics().schedulerReserved());
        }
    }

    @Test
    void attachedBusCloseWaitsForPhysicalTerminalRetryAndLeavesSharedRuntimeUsable(@TempDir Path root)
            throws Exception {
        Path keyring = root.resolve("close-keyring.zek");
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keys = KeyringStore.create(keyring, password)) {
            keys.putPrivate("sign.prv", "RSA", pair.getPrivate());
        }
        try (FilesystemPkiStore store = new FilesystemPkiStore(root.resolve("close-store"),
                FsPkiStoreOptions.defaults());
                SignatureWorkflow workflow = new ZeroEchoLibSignatureWorkflowProvider(
                        TestKeyringUnlocks.provider()).allocate(
                                new ProviderConfig("zeroecho-lib", Map.of("keyringPath", keyring.toString())),
                                SignatureWorkflowRuntimeDependencies.local(
                                        TestKeyringUnlocks.provider(), store));
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(
                        2, 2, Duration.ofSeconds(1), Duration.ofSeconds(1));
                SigningExecutionRuntime.InitialStepReservation closingInitial = runtime.reserveInitialStep()) {
            PkiSigningBus bus = PkiSigningBus.attach(store, workflow, signingAuthority(workflow), runtime,
                    Duration.ofSeconds(1), Duration.ofSeconds(1));
            CloseBlockingTerminal closingCompletion = new CloseBlockingTerminal("closing");
            CompletableFuture<Void> close = null;
            try {
                SigningExecutionRuntime.TerminalOwner closingOwner = terminalOwner(bus);
                SigningExecutionRuntime.StepSubmission<String> closing = runtime.scheduleInitialTerminalStep(
                        closingOwner, closingInitial, new PkiId("close-owner"), () -> closingCompletion,
                        CancellationSignal.NONE);
                assertEquals("closing", closing.future().orElseThrow().get(1, TimeUnit.SECONDS));
                closingCompletion.allowCommit.set(true);
                runtime.headroomRestored(closingOwner, 1L);
                assertTrue(closingCompletion.commitEntered.await(1, TimeUnit.SECONDS));
                assertEquals(1, runtime.metrics().running());

                close = CompletableFuture.runAsync(bus::close);
                assertTrue(closingCompletion.cancellationObserved.await(1, TimeUnit.SECONDS));
                runtime.headroomRestored(closingOwner, 2L);
                assertFalse(close.isDone());

                SigningExecutionRuntime.TerminalOwner otherOwner = runtime.attachTerminalOwner();
                try (SigningExecutionRuntime.InitialStepReservation otherInitial = runtime.reserveInitialStep()) {
                    ImmediateTerminal otherCompletion = new ImmediateTerminal("other");
                    SigningExecutionRuntime.StepSubmission<String> other = runtime.scheduleInitialTerminalStep(
                            otherOwner, otherInitial, new PkiId("other-owner"), () -> otherCompletion,
                            CancellationSignal.NONE);
                    assertEquals("other", other.future().orElseThrow().get(1, TimeUnit.SECONDS));
                    assertTrue(otherCompletion.closed.get());
                }

                closingCompletion.releaseCommit.countDown();
                close.get(1, TimeUnit.SECONDS);
                assertTrue(closingCompletion.closed.get());
                assertEquals(2, closingCompletion.commitAttempts.get());
                assertEquals(0, runtime.suspendedTerminalCount());
                assertEquals(0, runtime.terminalSlotsInUse());
            } finally {
                closingCompletion.releaseCommit.countDown();
                if (close != null) {
                    close.get(2, TimeUnit.SECONDS);
                }
                bus.close();
            }
        }
    }

    @Test
    void attachedBusCloseClearsSuspendedTerminalAndIgnoresLateRestoration(@TempDir Path root)
            throws Exception {
        Path keyring = root.resolve("suspended-close-keyring.zek");
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keys = KeyringStore.create(keyring, password)) {
            keys.putPrivate("sign.prv", "RSA", pair.getPrivate());
        }
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                    root.resolve("suspended-close-store"), FsPkiStoreOptions.defaults());
                SignatureWorkflow workflow = new ZeroEchoLibSignatureWorkflowProvider(
                        TestKeyringUnlocks.provider()).allocate(
                                new ProviderConfig("zeroecho-lib",
                                        Map.of("keyringPath", keyring.toString())),
                                SignatureWorkflowRuntimeDependencies.local(
                                        TestKeyringUnlocks.provider(), store));
                SigningExecutionRuntime runtime = runtime();
                SigningExecutionRuntime.InitialStepReservation initial =
                        runtime.reserveInitialStep()) {
            PkiSigningBus bus = PkiSigningBus.attach(
                    store, workflow, signingAuthority(workflow), runtime,
                    Duration.ofSeconds(1), Duration.ofSeconds(1));
            CloseBlockingTerminal completion = new CloseBlockingTerminal("accepted");
            try {
                SigningExecutionRuntime.TerminalOwner owner = terminalOwner(bus);
                SigningExecutionRuntime.StepSubmission<String> terminal =
                        runtime.scheduleInitialTerminalStep(
                                owner, initial, new PkiId("suspended-close"),
                                () -> completion, CancellationSignal.NONE);
                assertEquals("accepted",
                        terminal.future().orElseThrow().get(1, TimeUnit.SECONDS));

                SigningExecutionRuntime.StepSubmission<Boolean> barrier = runtime.scheduleStep(
                        new PkiId("suspended-close-barrier"), () -> Boolean.TRUE,
                        CancellationSignal.NONE);
                assertEquals(SigningExecutionRuntime.StepDisposition.ACCEPTED,
                        barrier.disposition());
                assertTrue(barrier.future().orElseThrow().get(1, TimeUnit.SECONDS));
                assertEquals(1, runtime.suspendedTerminalCount());
                assertEquals(1, runtime.terminalSlotsInUse());
                assertEquals(1, completion.commitAttempts.get());

                bus.close();

                assertTrue(completion.closed.get());
                assertEquals(0, runtime.suspendedTerminalCount());
                assertEquals(0, runtime.terminalSlotsInUse());
                assertEquals(0, runtime.metrics().schedulerReserved());

                runtime.headroomRestored(owner, 1L);
                SigningExecutionRuntime.StepSubmission<Boolean> afterClose = runtime.scheduleStep(
                        new PkiId("suspended-close-after"), () -> Boolean.TRUE,
                        CancellationSignal.NONE);
                assertEquals(SigningExecutionRuntime.StepDisposition.ACCEPTED,
                        afterClose.disposition());
                assertTrue(afterClose.future().orElseThrow().get(1, TimeUnit.SECONDS));
                assertEquals(1, completion.commitAttempts.get());
            } finally {
                bus.close();
            }
        }
    }

    @Test
    void foreignAdmissionIsRejectedAcrossBusesSharingOneRuntimeAndRemainsUsable(@TempDir Path root)
            throws Exception {
        InMemorySignatureWorkflow workflowA = new InMemorySignatureWorkflow(Map.of(), false);
        InMemorySignatureWorkflow workflowB = new InMemorySignatureWorkflow(Map.of(), false);
        try (FilesystemPkiStore storeA = new FilesystemPkiStore(root.resolve("store-a"),
                FsPkiStoreOptions.defaults());
                FilesystemPkiStore storeB = new FilesystemPkiStore(root.resolve("store-b"),
                        FsPkiStoreOptions.defaults());
                SigningExecutionRuntime sharedRuntime = runtime();
                PkiSigningBus busA = PkiSigningBus.attach(storeA, workflowA, signingAuthority(workflowA),
                        sharedRuntime);
                PkiSigningBus busB = PkiSigningBus.attach(storeB, workflowB, signingAuthority(workflowB),
                        sharedRuntime);
                PkiSigningBus.NewSignAdmission admissionA = busA.reserveNewSignAdmission()) {
            Submission foreign = stageSubmission(busB, REMOTE_KEY);

            assertThrows(IllegalArgumentException.class, () -> submit(busB, admissionA, foreign));

            assertArrayEquals(PAYLOAD, readContent(busB, foreign.content()));
            assertTrue(storeA.listSignRecords().isEmpty());
            assertTrue(storeB.listSignRecords().isEmpty());
            assertEquals(0, workflowA.submittedSignCount());
            assertEquals(0, workflowB.submittedSignCount());
            assertEquals(1, sharedRuntime.metrics().schedulerReserved());
            busB.releaseContent(foreign.content());

            Submission owned = stageSubmission(busA, REMOTE_KEY);
            submit(busA, admissionA, owned);
            admissionA.close();
            assertEquals(1, workflowA.submittedSignCount());
            assertEquals(0, sharedRuntime.metrics().schedulerReserved());
        } finally {
            workflowB.close();
            workflowA.close();
        }
    }

    @Test
    void mixedAdmissionAndForegroundOwnersAreRejectedBeforeOwnershipTransfer(@TempDir Path root)
            throws Exception {
        InMemorySignatureWorkflow workflowA = new InMemorySignatureWorkflow(Map.of(), false);
        InMemorySignatureWorkflow workflowB = new InMemorySignatureWorkflow(Map.of(), false);
        try (FilesystemPkiStore storeA = new FilesystemPkiStore(root.resolve("store-a"),
                FsPkiStoreOptions.defaults());
                FilesystemPkiStore storeB = new FilesystemPkiStore(root.resolve("store-b"),
                        FsPkiStoreOptions.defaults());
                SigningExecutionRuntime runtimeA = runtime();
                SigningExecutionRuntime runtimeB = runtime();
                PkiSigningBus busA = PkiSigningBus.attach(storeA, workflowA, signingAuthority(workflowA), runtimeA);
                PkiSigningBus busB = PkiSigningBus.attach(storeB, workflowB, signingAuthority(workflowB), runtimeB);
                PkiSigningBus.ForegroundCall foregroundA = busA.registerForegroundCall(CancellationSignal.NONE);
                PkiSigningBus.NewSignAdmission admissionB = busB.reserveNewSignAdmission()) {
            Submission submissionA = stageSubmission(busA, REMOTE_KEY);
            Submission submissionB = stageSubmission(busB, REMOTE_KEY);

            assertThrows(IllegalArgumentException.class,
                    () -> submit(busA, admissionB, submissionA, foregroundA));
            assertThrows(IllegalArgumentException.class,
                    () -> submit(busB, admissionB, submissionB, foregroundA));

            assertArrayEquals(PAYLOAD, readContent(busA, submissionA.content()));
            assertArrayEquals(PAYLOAD, readContent(busB, submissionB.content()));
            assertTrue(storeA.listSignRecords().isEmpty());
            assertTrue(storeB.listSignRecords().isEmpty());
            assertEquals(0, workflowA.submittedSignCount());
            assertEquals(0, workflowB.submittedSignCount());

            try (PkiSigningBus.NewSignAdmission admissionA = busA.reserveNewSignAdmission()) {
                submit(busA, admissionA, submissionA, foregroundA);
            }
            submit(busB, admissionB, submissionB);
            admissionB.close();

            assertEquals(1, workflowA.submittedSignCount());
            assertEquals(1, workflowB.submittedSignCount());
            assertEquals(0, runtimeA.metrics().schedulerReserved());
            assertEquals(0, runtimeB.metrics().schedulerReserved());
        } finally {
            workflowB.close();
            workflowA.close();
        }
    }

    @Test
    void bindFailureRollsBackCompositeAdmissionExactlyOnce(@TempDir Path root) throws Exception {
        RuntimeException bindFailure = new IllegalStateException("deliberate bind failure");
        AtomicInteger admissionCloses = new AtomicInteger();
        InMemorySignatureWorkflow workflow = new InMemorySignatureWorkflow(Map.of(), false);
        try (FilesystemPkiStore delegate = FilesystemPkiStoreTestAccess.open(root.resolve("store"), 1);
                SigningExecutionRuntime runtime = runtime()) {
            PkiStore failingStore = bindFailingStore(delegate, bindFailure, admissionCloses);
            try (PkiSigningBus bus = PkiSigningBus.attach(failingStore, workflow,
                    signingAuthority(workflow), runtime)) {
                Submission submission = stageSubmission(bus, REMOTE_KEY);
                RuntimeException observed;
                try (PkiSigningBus.NewSignAdmission admission = bus.reserveNewSignAdmission()) {
                    observed = assertThrows(RuntimeException.class, () -> submit(bus, admission, submission));
                }

                assertSame(bindFailure, observed);
                assertEquals(1, admissionCloses.get());
                assertTrue(delegate.listSignRecords().isEmpty());
                assertEquals(0, workflow.submittedSignCount());
                assertEquals(0, runtime.metrics().schedulerReserved());
                assertThrows(PkiException.class, () -> bus.openContent(submission.content()));
                try (SignWorkflowStore.SignAdmission ignored = delegate.reserveSignAdmission()) {
                    assertTrue(delegate.listSignRecords().isEmpty());
                }
            }
        } finally {
            workflow.close();
        }
    }

    private static PkiStore bindFailingStore(FilesystemPkiStore delegate, RuntimeException bindFailure,
            AtomicInteger admissionCloses) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class }, (proxy, method, arguments) -> {
                    if ("reserveSignAdmission".equals(method.getName()) && method.getParameterCount() == 0) {
                        SignWorkflowStore.SignAdmission reserved = delegate.reserveSignAdmission();
                        return new SignWorkflowStore.SignAdmission() {
                            @Override public void bind(PkiId submissionId) {
                                throw bindFailure;
                            }

                            @Override public void close() {
                                admissionCloses.incrementAndGet();
                                reserved.close();
                            }
                        };
                    }
                    try {
                        return method.invoke(delegate, arguments);
                    } catch (InvocationTargetException failure) {
                        throw failure.getCause();
                    }
                });
    }

    private static SigningExecutionRuntime.TerminalOwner terminalOwner(PkiSigningBus bus)
            throws ReflectiveOperationException {
        Field field = PkiSigningBus.class.getDeclaredField("terminalOwner");
        field.setAccessible(true);
        return (SigningExecutionRuntime.TerminalOwner) field.get(bus);
    }

    private static final class CloseBlockingTerminal
            implements SigningExecutionRuntime.TerminalCompletion<String> {
        private final String accepted;
        private final AtomicBoolean allowCommit = new AtomicBoolean();
        private final AtomicBoolean closed = new AtomicBoolean();
        private final AtomicInteger commitAttempts = new AtomicInteger();
        private final CountDownLatch commitEntered = new CountDownLatch(1);
        private final CountDownLatch cancellationObserved = new CountDownLatch(1);
        private final CountDownLatch releaseCommit = new CountDownLatch(1);

        private CloseBlockingTerminal(String accepted) {
            this.accepted = accepted;
        }

        @Override
        public String commit() {
            if (commitAttempts.incrementAndGet() == 1 && !allowCommit.get()) {
                throw limitExceeded();
            }
            commitEntered.countDown();
            boolean interrupted = false;
            while (true) {
                try {
                    releaseCommit.await();
                    break;
                } catch (InterruptedException ignored) {
                    interrupted = true;
                    cancellationObserved.countDown();
                }
            }
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
            throw limitExceeded();
        }

        private static IllegalStateException limitExceeded() {
            MetadataStoreException limit = new MetadataStoreException(
                    MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                    "injected metadata headroom exhaustion");
            return new IllegalStateException("injected terminal persistence limit", limit);
        }

        @Override public String acceptedResult() { return accepted; }
        @Override public void close() { closed.set(true); }
    }

    private static final class ImmediateTerminal
            implements SigningExecutionRuntime.TerminalCompletion<String> {
        private final String accepted;
        private final AtomicBoolean closed = new AtomicBoolean();

        private ImmediateTerminal(String accepted) {
            this.accepted = accepted;
        }

        @Override public String commit() { return accepted; }
        @Override public String acceptedResult() { return accepted; }
        @Override public void close() { closed.set(true); }
    }

    private static SigningExecutionRuntime runtime() {
        return new SigningExecutionRuntime(1, 1, Duration.ofMillis(100), Duration.ofMillis(100));
    }

    private static Submission stageSubmission(PkiSigningBus bus, KeyRef keyRef) throws Exception {
        PkiId id = bus.newSubmissionId();
        DurableContentReference content = stage(bus, new EncodedObject(Encoding.BINARY, PAYLOAD));
        PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(
                ACCESS, ALGORITHM, content, keyRef, Encoding.BINARY, Optional.empty());
        return new Submission(id, keyRef, content, continuation.encode());
    }

    private static void submit(PkiSigningBus bus, PkiSigningBus.NewSignAdmission admission,
            Submission submission) {
        bus.submitInitialSign(admission, submission.id(), OWNER, submission.keyRef(), ALGORITHM,
                submission.content(), Duration.ofSeconds(5), Optional.of(submission.continuation()));
    }

    private static void submit(PkiSigningBus bus, PkiSigningBus.NewSignAdmission admission,
            Submission submission, PkiSigningBus.ForegroundCall foregroundCall) {
        bus.submitInitialSign(admission, submission.id(), OWNER, submission.keyRef(), ALGORITHM,
                submission.content(), Duration.ofSeconds(5), Optional.of(submission.continuation()),
                foregroundCall);
    }

    private record Submission(PkiId id, KeyRef keyRef, DurableContentReference content,
            EncodedObject continuation) { }
}
