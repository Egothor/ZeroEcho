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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.ACCESS;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.CA;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.NOW;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.fixture;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.open;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.semantic;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.sign;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.schedule.StatusSchedule;
import zeroecho.pki.api.schedule.StatusScheduleState;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.signing.DefaultSemanticSigningService;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore;

class StatusScheduleSigningTest {
    @TempDir Path root;

    @Test void backupStillRejectsMissingPayloadOfAcceptedLiveSigningWork() throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            FullCrlStreamingPublicationTest.Fixture fixture = fixture(store, "RSA", "SHA256withRSA",
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 0);
            StatusScheduleState.Execution claim = claim(store, CA, StatusObjectType.CRL, Duration.ofHours(1));
            DefaultSemanticSigningService service = semantic(store, fixture.algorithm(), 1);
            PkiId operation = service.acceptScheduled(service.prepareFullCrl(ACCESS, fixture.prepared(), CancellationSignal.NONE), claim).receipt().operationId();
            String contentId = store.getSignWorkflow(operation).orElseThrow().envelope().candidate().contentId();
            java.nio.file.Files.delete(root.resolve("staged-content").resolve(contentId + ".content"));
            assertThrows(java.io.IOException.class, () -> store.createBackupSource(new zeroecho.pki.api.backup.BackupRequest(
                    "missing-live", new zeroecho.pki.impl.core.attr.SimpleAttributeSet())));
        }
    }

    @ParameterizedTest @ValueSource(strings = {"future", "trailing", "missing-head", "missing-receipt", "wrong-operation"})
    void corruptAcceptedReceiptLinkageRejectsReopen(String corruption) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            FullCrlStreamingPublicationTest.Fixture fixture = fixture(store, "RSA", "SHA256withRSA",
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 0);
            StatusScheduleState.Execution claim = claim(store, CA, StatusObjectType.CRL, Duration.ofHours(1));
            DefaultSemanticSigningService service = semantic(store, fixture.algorithm(), 1);
            service.acceptScheduled(service.prepareFullCrl(ACCESS, fixture.prepared(), CancellationSignal.NONE), claim);
            zeroecho.pki.impl.fs.StatusScheduleFaults.corrupt(store, state(store, StatusObjectType.CRL), corruption);
        }
        assertThrows(IllegalStateException.class, () -> open(root));
    }

    @Test void concurrentAcceptanceAttachesOnlyToTheSameClaim() throws Exception {
        try (FilesystemPkiStore store = open(root);
                java.util.concurrent.ExecutorService callers = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            FullCrlStreamingPublicationTest.Fixture fixture = fixture(store, "RSA", "SHA256withRSA",
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 0);
            StatusScheduleState.Execution claim = claim(store, CA, StatusObjectType.CRL, Duration.ofHours(1));
            DefaultSemanticSigningService first = semantic(store, fixture.algorithm(), 1);
            DefaultSemanticSigningService second = semantic(store, fixture.algorithm(), 1);
            PreparedSemanticSigningRequest a = first.prepareFullCrl(ACCESS, fixture.prepared(), CancellationSignal.NONE);
            PreparedSemanticSigningRequest b = second.prepareFullCrl(ACCESS, fixture.prepared(), CancellationSignal.NONE);
            java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
            java.util.concurrent.Future<zeroecho.pki.api.signing.SigningAcceptanceResult> one = callers.submit(() -> {
                start.await(); return first.acceptScheduled(a, claim);
            });
            java.util.concurrent.Future<zeroecho.pki.api.signing.SigningAcceptanceResult> two = callers.submit(() -> {
                start.await(); return second.acceptScheduled(b, claim);
            });
            start.countDown();
            zeroecho.pki.api.signing.SigningAcceptanceResult firstResult = one.get(10, java.util.concurrent.TimeUnit.SECONDS);
            zeroecho.pki.api.signing.SigningAcceptanceResult secondResult = two.get(10, java.util.concurrent.TimeUnit.SECONDS);
            assertEquals(java.util.Set.of(zeroecho.pki.api.signing.SigningAcceptanceDisposition.ACCEPTED,
                    zeroecho.pki.api.signing.SigningAcceptanceDisposition.CONFLICT),
                    java.util.Set.of(firstResult.disposition(), secondResult.disposition()));
            PkiId id = state(store, StatusObjectType.CRL).execution().orElseThrow().signingOperationId().orElseThrow();
            assertEquals(SignWorkflowStore.AcceptanceResult.ATTACHED_EXISTING,
                    store.acceptScheduledSign(command(store.getSignWorkflow(id).orElseThrow().envelope()), claim));
            assertEquals(Optional.of(id), state(store, StatusObjectType.CRL).execution().orElseThrow().signingOperationId());
            sign(store, id, fixture.signature());
            new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(id).orElseThrow());
            assertEquals(1, store.listStatusObjects(CA).size());
        }
    }

    @Test void ordinaryAcceptanceCannotBeAttachedAsScheduledWork() throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            FullCrlStreamingPublicationTest.Fixture fixture = fixture(store, "RSA", "SHA256withRSA",
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 0);
            DefaultSemanticSigningService service = semantic(store, fixture.algorithm(), 1);
            PkiId operation = service.accept(service.prepareFullCrl(ACCESS, fixture.prepared(), CancellationSignal.NONE)).receipt().operationId();
            StatusScheduleState.Execution claim = claim(store, CA, StatusObjectType.CRL, Duration.ofHours(1));
            assertEquals(SignWorkflowStore.AcceptanceResult.CONFLICT, store.acceptScheduledSign(
                    command(store.getSignWorkflow(operation).orElseThrow().envelope()), claim));
            PreparedSemanticSigningRequest prepared = service.prepareFullCrl(ACCESS, fixture.prepared(), CancellationSignal.NONE);
            assertEquals(zeroecho.pki.api.signing.SigningAcceptanceDisposition.CONFLICT, service.acceptScheduled(prepared, claim).disposition());
            assertTrue(state(store, StatusObjectType.CRL).execution().orElseThrow().signingOperationId().isEmpty());
        }
    }

    @Test void customStoreDefaultPublicationHookPreservesCrashReplayWithoutDuplicateInsertion() throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            FullCrlStreamingPublicationTest.Fixture fixture = fixture(store, "RSA", "SHA256withRSA",
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 0);
            DefaultSemanticSigningService service = semantic(store, fixture.algorithm(), 1);
            PkiId operation = service.accept(service.prepareFullCrl(ACCESS, fixture.prepared(), CancellationSignal.NONE)).receipt().operationId();
            sign(store, operation, fixture.signature());
            java.util.concurrent.atomic.AtomicInteger writes = new java.util.concurrent.atomic.AtomicInteger();
            zeroecho.pki.spi.store.PkiStore custom = (zeroecho.pki.spi.store.PkiStore) java.lang.reflect.Proxy.newProxyInstance(
                    zeroecho.pki.spi.store.PkiStore.class.getClassLoader(), new Class<?>[]{zeroecho.pki.spi.store.PkiStore.class},
                    (proxy, method, args) -> {
                        if (method.getName().equals("supportsStatusScheduling")) return false;
                        if (method.getName().equals("putStatusObjectFromSigning")) return java.lang.reflect.InvocationHandler.invokeDefault(proxy, method, args);
                        if (method.getName().equals("putStatusObject")) writes.incrementAndGet();
                        try { return method.invoke(store, args); }
                        catch (java.lang.reflect.InvocationTargetException failure) { throw failure.getCause(); }
                    });
            DomainContinuationPublisher.installPublicationFault(point -> { throw new SimulatedCrash(); });
            try {
                assertThrows(SimulatedCrash.class, () -> new SigningOuterTerminalDriver(custom).advance(store.getSignWorkflow(operation).orElseThrow()));
            } finally { DomainContinuationPublisher.clearPublicationFault(); }
            new SigningOuterTerminalDriver(custom).advance(store.getSignWorkflow(operation).orElseThrow());
            assertEquals(DomainContinuationStore.State.COMPLETED, store.getDomainContinuation(operation).orElseThrow().state());
            assertEquals(1, writes.get());
            assertThrows(IllegalStateException.class, () -> store.putStatusObject(store.listStatusObjects(CA).getFirst()));
        }
    }

    @ParameterizedTest @ValueSource(strings = {"BEFORE_COMMIT_AS_UNKNOWN", "AFTER_COMMIT_AS_UNKNOWN"})
    void unknownAcceptanceRecoversOneCoherentClaim(String cut) throws Exception {
        FullCrlStreamingPublicationTest.Fixture fixture;
        try (FilesystemPkiStore store = open(root)) {
            fixture = fixture(store, "RSA", "SHA256withRSA", BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 0);
            StatusScheduleState.Execution claim = claim(store, CA, StatusObjectType.CRL, Duration.ofHours(1));
            DefaultSemanticSigningService service = semantic(store, fixture.algorithm(), 1);
            PreparedSemanticSigningRequest prepared = service.prepareFullCrl(ACCESS, fixture.prepared(), CancellationSignal.NONE);
            zeroecho.pki.impl.fs.StatusScheduleFaults.acceptance(cut,
                    () -> assertThrows(RuntimeException.class, () -> service.acceptScheduled(prepared, claim)));
            assertThrows(zeroecho.pki.api.PkiException.class, () -> state(store, StatusObjectType.CRL));
        }
        try (FilesystemPkiStore store = open(root)) {
            StatusScheduleState.Execution execution = state(store, StatusObjectType.CRL).execution().orElseThrow();
            if (cut.startsWith("BEFORE")) {
                assertTrue(execution.signingOperationId().isEmpty());
                assertTrue(store.getDomainContinuation(DomainContinuationStore.Kind.STATUS,
                        FullCrlSigningCommand.template(fixture.prepared()).correlationId().orElseThrow()).isEmpty());
            } else {
                PkiId operation = execution.signingOperationId().orElseThrow();
                assertTrue(store.getSignWorkflow(operation).isPresent());
                assertEquals(DomainContinuationStore.State.SIGNING, store.getDomainContinuation(operation).orElseThrow().state());
                sign(store, operation, fixture.signature());
                new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(operation).orElseThrow());
                assertTrue(store.advanceStatusSchedule(state(store, StatusObjectType.CRL).execution().orElseThrow()));
                assertEquals(1, store.listStatusObjects(CA).size());
            }
        }
    }

    @Test void unknownEffectRecoversTheAtomicStatusAndReceipt() throws Exception {
        PkiId operation;
        try (FilesystemPkiStore store = open(root)) {
            FullCrlStreamingPublicationTest.Fixture fixture = fixture(store, "RSA", "SHA256withRSA",
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 0);
            StatusScheduleState.Execution claim = claim(store, CA, StatusObjectType.CRL, Duration.ofHours(1));
            DefaultSemanticSigningService service = semantic(store, fixture.algorithm(), 1);
            operation = service.acceptScheduled(service.prepareFullCrl(ACCESS, fixture.prepared(), CancellationSignal.NONE), claim).receipt().operationId();
            sign(store, operation, fixture.signature());
            zeroecho.pki.impl.fs.StatusScheduleFaults.effect("AFTER_COMMIT_AS_UNKNOWN",
                    () -> assertThrows(RuntimeException.class, () -> new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(operation).orElseThrow())));
        }
        try (FilesystemPkiStore store = open(root)) {
            assertEquals(StatusScheduleState.Phase.EFFECT_COMMITTED, state(store, StatusObjectType.CRL).execution().orElseThrow().phase());
            new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(operation).orElseThrow());
            assertTrue(store.advanceStatusSchedule(state(store, StatusObjectType.CRL).execution().orElseThrow()));
            assertEquals(1, store.listStatusObjects(CA).size());
        }
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void snapshotPreservesAcceptedAndCommittedSchedulingSafetyState(boolean effect) throws Exception {
        Path source = root.resolve("source");
        Path snapshot = root.resolve("snapshot");
        PkiId operation;
        EncodedObject signature;
        StatusScheduleState expected;
        try (FilesystemPkiStore store = open(source)) {
            FullCrlStreamingPublicationTest.Fixture fixture = fixture(store, "RSA", "SHA256withRSA",
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 0);
            StatusScheduleState.Execution claim = claim(store, CA, StatusObjectType.CRL, Duration.ofHours(1));
            DefaultSemanticSigningService service = semantic(store, fixture.algorithm(), 1);
            operation = service.acceptScheduled(service.prepareFullCrl(ACCESS, fixture.prepared(), CancellationSignal.NONE), claim).receipt().operationId();
            signature = fixture.signature();
            if (effect) {
                sign(store, operation, signature);
                new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(operation).orElseThrow());
            }
            expected = state(store, StatusObjectType.CRL);
            try (zeroecho.pki.api.backup.BackupSource backup = store.createBackupSource(
                    new zeroecho.pki.api.backup.BackupRequest("schedule-cut", new zeroecho.pki.impl.core.attr.SimpleAttributeSet()));
                    zeroecho.pki.api.backup.BackupPreparation prepared = store.prepareBackup(backup);
                    FilesystemPkiStore recovered = open(prepared.directory())) {
                assertEquals(expected, state(recovered, StatusObjectType.CRL));
                assertTrue(recovered.getSignWorkflow(operation).isPresent());
                if (effect) assertEquals(1, recovered.listStatusObjects(CA).size());
            }
            store.exportSnapshot(snapshot, NOW.minusSeconds(1));
        }
        try (FilesystemPkiStore store = open(snapshot)) {
            assertEquals(expected, state(store, StatusObjectType.CRL));
            if (!effect) {
                sign(store, operation, signature);
                new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(operation).orElseThrow());
            }
            assertTrue(store.advanceStatusSchedule(state(store, StatusObjectType.CRL).execution().orElseThrow()));
            assertEquals(1, store.listStatusObjects(CA).size());
        }
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void acceptedClaimAndCommittedEffectSurviveCrashesWithoutRegeneration(boolean delta) throws Exception {
        PkiId operation;
        EncodedObject signature;
        StatusObjectType type = delta ? StatusObjectType.DELTA_CRL : StatusObjectType.CRL;
        int count = delta ? 2 : 1;
        try (FilesystemPkiStore store = open(root)) {
            FullCrlStreamingPublicationTest.Fixture fixture = fixture(store, "RSA", "SHA256withRSA",
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 1, delta);
            StatusScheduleState.Execution claim = claim(store, CA, type, Duration.ofHours(1));
            DefaultSemanticSigningService service = semantic(store, fixture.algorithm(), 1);
            operation = service.acceptScheduled(service.prepareFullCrl(ACCESS, fixture.prepared(), CancellationSignal.NONE), claim).receipt().operationId();
            signature = fixture.signature();
            assertEquals(Optional.of(operation), state(store, type).execution().orElseThrow().signingOperationId());
            StatusSchedule config = state(store, type).configuration();
            store.putStatusSchedule(new StatusSchedule(CA, type, config.formatId(), Duration.ofHours(2), 30, false,
                    Optional.empty(), NOW, NOW, config.revision()));
            assertEquals(claim.configuration(), state(store, type).execution().orElseThrow().configuration());
        }
        try (FilesystemPkiStore store = open(root)) {
            sign(store, operation, signature);
            DomainContinuationPublisher.installPublicationFault(point -> { throw new SimulatedCrash(); });
            try {
                assertThrows(SimulatedCrash.class, () -> new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(operation).orElseThrow()));
            } finally { DomainContinuationPublisher.clearPublicationFault(); }
            assertEquals(StatusScheduleState.Phase.EFFECT_COMMITTED, state(store, type).execution().orElseThrow().phase());
            assertEquals(count, store.listStatusObjects(CA).size());
        }
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(),
                Clock.fixed(NOW.plus(Duration.ofDays(100)), ZoneOffset.UTC))) {
            assertEquals(0, store.purgeExpiredSignRecords());
            new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(operation).orElseThrow());
            assertEquals(DomainContinuationStore.State.COMPLETED, store.getDomainContinuation(operation).orElseThrow().state());
            assertEquals(0, store.purgeExpiredSignRecords());
            StatusScheduleState.Execution effect = state(store, type).execution().orElseThrow();
            assertTrue(store.advanceStatusSchedule(effect));
            assertFalse(store.advanceStatusSchedule(effect));
            assertEquals(NOW.plusSeconds(3570), state(store, type).nextDue());
            assertEquals(2, state(store, type).configuration().revision());
            assertFalse(state(store, type).configuration().enabled());
            assertEquals(count, store.listStatusObjects(CA).size());
            assertEquals(1, store.purgeExpiredSignRecords());
        }
        try (FilesystemPkiStore store = open(root)) {
            assertEquals(StatusScheduleState.Phase.SCHEDULE_ADVANCED, state(store, type).execution().orElseThrow().phase());
            assertEquals(count, store.listStatusObjects(CA).size());
        }
    }

    @ParameterizedTest @ValueSource(strings = {"ca", "type", "interval", "stale", "old"})
    void mismatchedOrStaleClaimRejectsBeforeSigningAcceptance(String mismatch) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(),
                Clock.fixed(mismatch.equals("old") ? NOW.plusSeconds(3570) : NOW, ZoneOffset.UTC))) {
            FullCrlStreamingPublicationTest.Fixture fixture = fixture(store, "RSA", "SHA256withRSA",
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 0);
            PkiId ca = mismatch.equals("ca") ? new PkiId("other") : CA;
            StatusObjectType type = mismatch.equals("type") ? StatusObjectType.DELTA_CRL : StatusObjectType.CRL;
            StatusScheduleState.Execution claim = claim(store, ca, type, mismatch.equals("interval") ? Duration.ofHours(2) : Duration.ofHours(1));
            if (mismatch.equals("stale")) store.putStatusSchedule(claim.configuration());
            StatusScheduleState before = store.getStatusScheduleState(ca, type).orElseThrow();
            DefaultSemanticSigningService service = semantic(store, fixture.algorithm(), 1);
            PreparedSemanticSigningRequest prepared = service.prepareFullCrl(ACCESS, fixture.prepared(), CancellationSignal.NONE);
            assertThrows(IllegalStateException.class, () -> service.acceptScheduled(prepared, claim));
            assertEquals(before, store.getStatusScheduleState(ca, type).orElseThrow());
            assertTrue(store.listStatusObjects(CA).isEmpty());
            assertTrue(store.getDomainContinuation(DomainContinuationStore.Kind.STATUS,
                    FullCrlSigningCommand.template(fixture.prepared()).correlationId().orElseThrow()).isEmpty());
        }
    }

    @Test void explicitNoOpEditResolvesProvenTerminalFailureAndFencesOldEffect() throws Exception {
        PkiId operation;
        try (FilesystemPkiStore store = open(root)) {
            FullCrlStreamingPublicationTest.Fixture fixture = fixture(store, "RSA", "SHA256withRSA",
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 0);
            StatusScheduleState.Execution claim = claim(store, CA, StatusObjectType.CRL, Duration.ofHours(1));
            DefaultSemanticSigningService service = semantic(store, fixture.algorithm(), 1);
            operation = service.acceptScheduled(service.prepareFullCrl(ACCESS, fixture.prepared(), CancellationSignal.NONE), claim).receipt().operationId();
            StatusScheduleState.Execution accepted = state(store, StatusObjectType.CRL).execution().orElseThrow();
            assertThrows(IllegalStateException.class, () -> store.failStatusSchedule(accepted, "FAILED"));
            SignWorkflowStore.Workflow step = store.claimSignStep(operation, 0, Duration.ofSeconds(10)).orElseThrow();
            store.transitionSign(operation, step.revision(), step.fence(), SignWorkflowStore.State.FAILED,
                    Optional.of("TEST_FAILURE"), Optional.empty(), Optional.of(NOW)).orElseThrow();
            new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(operation).orElseThrow());
            assertTrue(store.failStatusSchedule(accepted, "SIGNING_FAILED"));
            StatusSchedule config = state(store, StatusObjectType.CRL).configuration();
            store.putStatusSchedule(config);
            assertTrue(state(store, StatusObjectType.CRL).execution().isEmpty());
            assertEquals(2, state(store, StatusObjectType.CRL).configuration().revision());
        }
        try (FilesystemPkiStore store = open(root)) {
            assertTrue(store.claimStatusSchedule(state(store, StatusObjectType.CRL)).isPresent());
            assertEquals(0, store.purgeExpiredSignRecords());
        }
    }

    private static StatusScheduleState state(FilesystemPkiStore store, StatusObjectType type) {
        return store.getStatusScheduleState(CA, type).orElseThrow();
    }

    private static SignWorkflowStore.AcceptanceCommand command(SignWorkflowStore.AcceptanceEnvelope value) {
        return new SignWorkflowStore.AcceptanceCommand(value.operationId(), value.providerNamespace(),
                value.providerConfigurationCommitment(), value.accessContext(), value.keyRef(), value.fairnessAuthorityId(),
                value.algorithmId(), value.signatureEncoding(), value.createdAt(), value.deadline(), value.candidate(),
                value.outer(), value.mode(), value.proofStep());
    }

    private static StatusScheduleState.Execution claim(FilesystemPkiStore store, PkiId ca, StatusObjectType type, Duration interval) {
        store.putStatusSchedule(new StatusSchedule(ca, type, new FormatId("x509"), interval, 30, true,
                Optional.empty(), NOW, NOW, 0));
        return store.claimStatusSchedule(store.getStatusScheduleState(ca, type).orElseThrow()).orElseThrow();
    }

    private static final class SimulatedCrash extends RuntimeException { private static final long serialVersionUID = 1L; }
}
