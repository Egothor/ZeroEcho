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
package zeroecho.pki.application;

import static org.junit.jupiter.api.Assertions.*;
import static zeroecho.core.io.CancellationSignal.NONE;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.hybrid.HybridCertificateMode;
import zeroecho.pki.api.status.FullCrlRequest;
import zeroecho.pki.impl.fs.FilesystemPkiStoreTestAccess;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;

/**
 * Real FS/WAL/local-provider restart tests; injected process stops are not HTTP or Podman tests.
 */
final class HybridCrlDurabilityTest {
    private static final AccessContext ACCESS = new AccessContext(new Principal("TEST", "crl-durability"),
            new Purpose("STATUS_GENERATE"), Optional.empty(), Optional.empty());

    /**
     * One work slot supports both handoffs and completed replay.
     *
     * @param root isolated temporary store root supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void oneWorkSlotSupportsBothHandoffsAndCompletedReplay(@TempDir Path root) throws Exception {
        var rig = new Rig(root, null);
        PkiId parent;
        PkiId status;
        try (var session = rig.fixture.open()) {
            var ca = rig.fixture.create(session);
            rig.dispatches.clear();
            parent = rig.accept(session, ca);
            status = rig.complete(session, parent);
            assertEquals(2, rig.dispatches.size());
            assertNotEquals(rig.dispatches.getFirst().operation(), rig.dispatches.getLast().operation());
            assertEquals(parent, rig.dispatches.getFirst().operation());
            assertEquals(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(), rig.dispatches.getFirst().algorithm());
            assertEquals(BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm(), rig.dispatches.getLast().algorithm());
            assertNotEquals(rig.dispatches.getFirst().contentHash(), rig.dispatches.getLast().contentHash());
            assertEquals(SignWorkflowStore.CrlHybridPhase.NATIVE_LINKED,
                    rig.fixture.store.getCrlHybridExecution(parent).orElseThrow().phase());
            rig.verify(session, status);
        }
        try (var session = rig.fixture.open()) {
            assertEquals(status, rig.complete(session, parent));
            rig.verify(session, status);
            assertEquals(2, rig.dispatches.size(), "Terminal replay must not sign either transcript again");
        }
    }

    /**
     * Restart before adoption after link and after status never resigns.
     *
     * @param root isolated temporary store root supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void restartBeforeAdoptionAfterLinkAndAfterStatusNeverResigns(@TempDir Path root) throws Exception {
        for (var stop : Stop.values()) {
            var rig = new Rig(root.resolve(stop.name()), null);
            var armed = new AtomicBoolean();
            rig.fixture.storeDecorator = store -> (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                    new Class<?>[] {PkiStore.class}, (proxy, method, arguments) -> {
                        boolean selected = armed.get() && (stop == Stop.BEFORE_ADOPTION || stop == Stop.AFTER_ADOPTION
                                ? method.getName().equals("adoptCrlNativeChild")
                                : method.getName().equals("putStatusObjectFromSigning"));
                        if (selected && stop == Stop.BEFORE_ADOPTION && armed.compareAndSet(true, false)) throw new ProcessStop();
                        try {
                            var result = method.invoke(store, arguments);
                            if (selected && armed.compareAndSet(true, false)) throw new ProcessStop();
                            return result;
                        } catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
            PkiId parent;
            BigInteger reservedNumber;
            try (var session = rig.fixture.open()) {
                var ca = rig.fixture.create(session);
                rig.dispatches.clear();
                parent = rig.accept(session, ca);
                reservedNumber = rig.numberFromParent(parent);
                armed.set(true);
                try {
                    assertInstanceOf(LocalSigningResult.Failed.class,
                            session.localSigning().orElseThrow().complete(parent, NONE), stop.name());
                } catch (ProcessStop expected) {
                    // Some local-driver boundaries propagate the simulated process stop directly.
                }
                assertFalse(armed.get(), "The selected real store boundary must be reached: " + stop);
                int expected = stop == Stop.AFTER_STATUS ? 2 : 1;
                assertEquals(expected, rig.dispatches.size());
                var execution = rig.fixture.store.getCrlHybridExecution(parent).orElseThrow();
                assertEquals(stop == Stop.BEFORE_ADOPTION ? SignWorkflowStore.CrlHybridPhase.AWAITING_ALT
                        : SignWorkflowStore.CrlHybridPhase.NATIVE_LINKED, execution.phase());
            }
            rig.clock.advance();
            try (var session = rig.fixture.open()) {
                var status = rig.complete(session, parent);
                assertEquals(reservedNumber, rig.verify(session, status));
                assertEquals(2, rig.dispatches.size(), "Recovery must use the retained real ALT/native results");
                assertEquals(2, rig.dispatches.stream().map(Dispatch::operation).distinct().count());
            }
        }
    }

    /**
     * Lost acknowledgement of forced adoption recovers without duplicate signing.
     *
     * @param root isolated temporary store root supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void lostAcknowledgementOfForcedAdoptionRecoversWithoutDuplicateSigning(@TempDir Path root) throws Exception {
        var fault = new FilesystemPkiStoreTestAccess.AdoptionForceFault();
        var rig = new Rig(root, fault);
        PkiId parent;
        BigInteger reservedNumber;
        var initial = rig.fixture.open();
        try {
            var ca = rig.fixture.create(initial);
            rig.dispatches.clear();
            parent = rig.accept(initial, ca);
            reservedNumber = rig.numberFromParent(parent);
            fault.arm();
            try {
                var result = initial.localSigning().orElseThrow().complete(parent, NONE);
                assertFalse(result instanceof LocalSigningResult.Completed);
            } catch (Exception uncertain) {
                assertTrue(injectedAdoptionFailure(uncertain), () -> "Unexpected failure: " + uncertain);
            }
            assertTrue(fault.fired(), "The actual native-link metadata group must have reached force");
            assertEquals(1, rig.dispatches.size());
        } finally {
            try { initial.close(); }
            catch (Exception uncertainClose) {
                assertTrue(fault.fired() && injectedAdoptionFailure(uncertainClose),
                        () -> "Unexpected close failure: " + uncertainClose);
            }
        }
        rig.clock.advance();
        try (var session = rig.fixture.open()) {
            var status = rig.complete(session, parent);
            assertEquals(reservedNumber, rig.verify(session, status));
            assertEquals(2, rig.dispatches.size());
            assertEquals(2, rig.dispatches.stream().map(Dispatch::operation).distinct().count());
        }
    }

    /**
     * Saturated resident budget cannot steal accepted parents future capacity.
     *
     * @param root isolated temporary store root supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void saturatedResidentBudgetCannotStealAcceptedParentsFutureCapacity(@TempDir Path root) throws Exception {
        var rig = new Rig(root, null);
        rig.maximumWork = 16;
        rig.residentBytes = 32L * 1024 * 1024;
        var accepted = new ArrayList<PkiId>();
        PkiId completed;
        PkiId status;
        try (var session = rig.fixture.open()) {
            var ca = rig.fixture.create(session);
            rig.dispatches.clear();
            boolean saturated = false;
            for (int attempt = 0; attempt < 16; attempt++) {
                var result = rig.tryAccept(session, ca);
                if (result.disposition() == zeroecho.pki.api.signing.SigningAcceptanceDisposition.CAPACITY_REJECTED) {
                    saturated = true;
                    break;
                }
                assertEquals(zeroecho.pki.api.signing.SigningAcceptanceDisposition.ACCEPTED, result.disposition());
                accepted.add(result.receipt().operationId());
            }
            assertTrue(saturated, "The configured resident budget must reject another parent before any ALT dispatch");
            assertTrue(accepted.size() >= 2, "At least two parents must retain competing future-capacity ownership");
            assertTrue(rig.dispatches.isEmpty());
            completed = accepted.removeFirst();
            status = rig.complete(session, completed);
            rig.verify(session, status);
            var budget = FilesystemPkiStoreTestAccess.residentBudget((zeroecho.pki.impl.fs.FilesystemPkiStore) rig.fixture.store);
            assertTrue(budget.reserved() <= budget.maximum());
            assertTrue(budget.highWater() <= budget.maximum());
        }
        try (var session = rig.fixture.open()) {
            assertEquals(status, rig.complete(session, completed));
            for (var parent : accepted) rig.verify(session, rig.complete(session, parent));
            var budget = FilesystemPkiStoreTestAccess.residentBudget((zeroecho.pki.impl.fs.FilesystemPkiStore) rig.fixture.store);
            assertTrue(budget.highWater() <= budget.maximum());
            assertEquals(2L * (accepted.size() + 1), rig.dispatches.size());
        }
    }

    /**
     * Existing native child identity rejects parent before alternative dispatch.
     *
     * @param root isolated temporary store root supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void existingNativeChildIdentityRejectsParentBeforeAlternativeDispatch(@TempDir Path root) throws Exception {
        var rig = new Rig(root, null);
        rig.maximumWork = 4;
        var seeded = new AtomicBoolean();
        rig.fixture.storeDecorator = store -> (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] {PkiStore.class}, (proxy, method, arguments) -> {
                    if (method.getName().equals("acceptSign") && arguments[0] instanceof SignWorkflowStore.AcceptanceCommand parent
                            && parent.outer().filter(outer -> outer.kind() == zeroecho.pki.spi.store.DomainContinuationStore.Kind.STATUS).isPresent()
                            && seeded.compareAndSet(false, true)) {
                        zeroecho.pki.api.content.DurableContentReference candidate;
                        try (var sink = store.stagedContent().beginContent(zeroecho.pki.api.Encoding.DER,
                                zeroecho.pki.api.content.DurableContentReference.Lifecycle.OPERATION)) {
                            sink.outputStream().write(new byte[] {0x30, 0});
                            candidate = sink.complete();
                        }
                        var collision = new SignWorkflowStore.AcceptanceCommand(
                                zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.nativeChildId(parent.operationId()),
                                parent.providerNamespace(), parent.providerConfigurationCommitment(), parent.accessContext(),
                                HybridIssuanceFixture.key("root"), parent.fairnessAuthorityId(),
                                BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm(), parent.signatureEncoding(),
                                parent.createdAt(), parent.deadline(), candidate, Optional.empty(), SignWorkflowStore.Mode.NORMAL,
                                Optional.empty());
                        assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(collision));
                    }
                    try { return method.invoke(store, arguments); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
        try (var session = rig.fixture.open()) {
            var ca = rig.fixture.create(session);
            rig.dispatches.clear();
            assertEquals(zeroecho.pki.api.signing.SigningAcceptanceDisposition.CONFLICT, rig.tryAccept(session, ca).disposition());
            assertTrue(seeded.get());
            assertTrue(rig.dispatches.isEmpty(), "A conflicting reserved child must be detected before ALT signing");
        }
    }

    /**
     * Alternative result above captured algorithm bound cannot become successful.
     *
     * @param root isolated temporary store root supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void alternativeResultAboveCapturedAlgorithmBoundCannotBecomeSuccessful(@TempDir Path root) throws Exception {
        var rig = new Rig(root, null);
        var armed = new AtomicBoolean();
        var tracking = rig.fixture.signingDecorator;
        rig.fixture.signingDecorator = provider -> {
            var counted = tracking.apply(provider);
            return (SigningProvider) Proxy.newProxyInstance(SigningProvider.class.getClassLoader(),
                    new Class<?>[] {SigningProvider.class, zeroecho.pki.spi.crypto.PublicKeyInfoSource.class,
                            zeroecho.pki.spi.crypto.AltSigningCapability.class}, (proxy, method, arguments) -> {
                        try {
                            var result = method.invoke(counted, arguments);
                            if (armed.get() && method.getName().equals("dispatch")
                                    && arguments[0] instanceof SigningProvider.SignRequest request
                                    && request.algorithmId().equals(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm())) {
                                var observation = (SigningProvider.OperationObservation) result;
                                return new SigningProvider.OperationObservation(request.operationId(), SigningProvider.ObservationState.SUCCEEDED,
                                        observation.updatedAt(), SigningProvider.DetailCode.SIGNED,
                                        Optional.of(new zeroecho.pki.api.EncodedObject(zeroecho.pki.api.Encoding.BINARY, new byte[4628])));
                            }
                            return result;
                        } catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
        };
        try (var session = rig.fixture.open()) {
            var ca = rig.fixture.create(session);
            rig.dispatches.clear();
            var parent = rig.accept(session, ca);
            armed.set(true);
            assertInstanceOf(LocalSigningResult.Failed.class, session.localSigning().orElseThrow().complete(parent, NONE));
            assertEquals(1, rig.dispatches.size());
            assertNotEquals(SignWorkflowStore.State.SUCCEEDED, rig.fixture.store.getSignWorkflow(parent).orElseThrow().state());
            assertTrue(rig.fixture.store.getSignWorkflow(
                    zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.nativeChildId(parent)).isEmpty());
            assertTrue(rig.fixture.store.listStatusObjects(ca).isEmpty());
        }
    }

    /**
     * Current backup retains historical full base after joint workflow purge.
     *
     * @param root isolated temporary store root supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void currentBackupRetainsHistoricalFullBaseAfterJointWorkflowPurge(@TempDir Path root) throws Exception {
        var rig = new Rig(root.resolve("source"), null);
        var unsupportedHistorical = root.resolve("historical-snapshot");
        PkiId baseParent;
        PkiId baseStatus;
        PkiId oldIssuer;
        BigInteger baseNumber;
        try (var session = rig.fixture.open()) {
            var ca = rig.fixture.create(session);
            oldIssuer = rig.fixture.store.getCa(ca).orElseThrow().currentIssuanceIssuerId();
            baseParent = rig.accept(session, ca);
            baseStatus = rig.complete(session, baseParent);
            baseNumber = rig.verify(session, baseStatus);
            rig.fixture.execute(session, new PkiSigningOperation.RolloverCaCertificate(ca, Optional.empty()));
            assertNotEquals(oldIssuer, rig.fixture.store.getCa(ca).orElseThrow().currentIssuanceIssuerId());
        }
        rig.clock.now = rig.clock.now.plus(Duration.ofDays(91));
        try (var session = rig.fixture.open()) {
            rig.fixture.store.purgeExpiredSignRecords();
            assertTrue(rig.fixture.store.getSignWorkflow(baseParent).isEmpty());
            assertTrue(rig.fixture.store.getSignWorkflow(
                    zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.nativeChildId(baseParent)).isEmpty());
            assertTrue(rig.fixture.store.getCrlHybridExecution(baseParent).isEmpty());
            assertEquals(baseNumber, rig.verify(session, baseStatus));
            var unsupported = assertThrows(IllegalStateException.class,
                    () -> ((zeroecho.pki.impl.fs.FilesystemPkiStore) rig.fixture.store)
                            .exportSnapshot(unsupportedHistorical, rig.clock.instant()));
            assertTrue(unsupported.getMessage().contains("PROFILE_ACTIVATION_HISTORY_UNAVAILABLE"));
            var attributes = new zeroecho.pki.impl.core.attr.SimpleAttributeSet();
            var backup = rig.fixture.store.createBackup(new zeroecho.pki.api.backup.BackupRequest("hybrid-crl-current", attributes));
            assertTrue(rig.fixture.store.verifyBackup(backup).valid());
            var staged = rig.fixture.store.restoreBackup(new zeroecho.pki.api.backup.RestoreRequest(backup, attributes));
            assertFalse(staged.success(), "Restore must wait for cold activation");
            assertTrue(staged.errors().isEmpty(), staged.errors()::toString);
        }
        // Reopen activates the staged current backup; issuer private keys remain in the caller-owned keyring.
        try (var restored = rig.fixture.open()) {
            assertEquals(zeroecho.pki.api.backup.RestoreStatus.State.ACTIVATED,
                    rig.fixture.store.latestRestoreStatus().orElseThrow().state());
            assertTrue(rig.fixture.store.getSignWorkflow(baseParent).isEmpty());
            assertEquals(baseNumber, rig.verify(restored, baseStatus));
            var semantic = restored.semanticSigning().orElseThrow();
            var accepted = semantic.accept(semantic.prepareDeltaCrl(ACCESS,
                    new zeroecho.pki.api.status.DeltaCrlRequest(oldIssuer, Duration.ofHours(1)), NONE));
            var deltaStatus = rig.complete(restored, accepted.receipt().operationId());
            rig.verify(restored, deltaStatus);
            try (var lease = restored.repository().openStatusObject(deltaStatus, "original", NONE); var input = lease.openStream()) {
                var delta = new X509CRLHolder(input.readAllBytes());
                assertEquals(baseNumber, ASN1Integer.getInstance(delta.getExtension(Extension.deltaCRLIndicator).getParsedValue()).getValue());
            }
            var attributes = restored.repository().statusObject(deltaStatus).orElseThrow().attributes();
            assertEquals(baseStatus.value(), assertInstanceOf(zeroecho.pki.api.attr.AttributeValue.StringValue.class,
                    attributes.getAll(zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.BASE_STATUS_ID).getFirst()).value());
            assertEquals(oldIssuer.value(), assertInstanceOf(zeroecho.pki.api.attr.AttributeValue.StringValue.class,
                    attributes.getAll(zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.ISSUER_GENERATION).getFirst()).value());
        }
    }

    /**
     * Cancellation of linked pending native child never publishes status.
     *
     * @param root isolated temporary store root supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void cancellationOfLinkedPendingNativeChildNeverPublishesStatus(@TempDir Path root) throws Exception {
        var rig = new Rig(root, null);
        var armed = new AtomicBoolean();
        rig.fixture.storeDecorator = store -> (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] {PkiStore.class}, (proxy, method, arguments) -> {
                    try {
                        var result = method.invoke(store, arguments);
                        if (method.getName().equals("adoptCrlNativeChild") && armed.compareAndSet(true, false)) throw new ProcessStop();
                        return result;
                    } catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
        PkiId parent;
        PkiId ca;
        try (var session = rig.fixture.open()) {
            ca = rig.fixture.create(session);
            rig.dispatches.clear();
            parent = rig.accept(session, ca);
            armed.set(true);
            try { session.localSigning().orElseThrow().complete(parent, NONE); }
            catch (ProcessStop expected) { /* Simulated stop after the real atomic link. */ }
            assertFalse(armed.get());
            var child = rig.fixture.store.getCrlHybridExecution(parent).orElseThrow().nativeChildId();
            assertEquals(SignWorkflowStore.State.INTENT, rig.fixture.store.getSignWorkflow(child).orElseThrow().state());
            assertEquals(1, rig.dispatches.size());
        }
        rig.clock.advance();
        try (var session = rig.fixture.open()) {
            assertTrue(session.semanticSigning().orElseThrow().cancel(parent).isPresent());
            assertInstanceOf(LocalSigningResult.Failed.class, session.localSigning().orElseThrow().complete(parent, NONE));
            assertTrue(rig.fixture.store.listStatusObjects(ca).isEmpty());
            assertEquals(1, rig.dispatches.size(), "Cancelled pending native child must never reach the provider");
            assertEquals(zeroecho.pki.spi.store.DomainContinuationStore.State.FAILED,
                    rig.fixture.store.getDomainContinuation(parent).orElseThrow().state());
        }
    }

    /**
     * Scheduled committed hybrid effect replays without regeneration.
     *
     * @param root isolated temporary store root supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void scheduledCommittedHybridEffectReplaysWithoutRegeneration(@TempDir Path root) throws Exception {
        var rig = new Rig(root, null);
        var armed = new AtomicBoolean();
        var effectCut = new AtomicBoolean();
        rig.fixture.storeDecorator = store -> (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] {PkiStore.class}, (proxy, method, arguments) -> {
                    // Prevent the coordinator from advancing a receipt after its local executor classified the stop.
                    if (method.getName().equals("advanceStatusSchedule") && effectCut.get()) throw new ProcessStop();
                    try {
                        var result = method.invoke(store, arguments);
                        if (method.getName().equals("putStatusObjectFromSigning") && armed.compareAndSet(true, false)) {
                            effectCut.set(true);
                            throw new ProcessStop();
                        }
                        return result;
                    } catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
        PkiId ca;
        PkiId status;
        PkiId parent;
        try (var session = rig.fixture.open()) {
            ca = rig.fixture.create(session);
            rig.dispatches.clear();
            rig.fixture.store.putStatusSchedule(new zeroecho.pki.api.schedule.StatusSchedule(ca,
                    zeroecho.pki.api.status.StatusObjectType.CRL, HybridIssuanceFixture.X509,
                    Duration.ofMinutes(10), 30, true, Optional.empty(), rig.clock.instant(), rig.clock.instant(), 0));
            armed.set(true);
            assertThrows(ProcessStop.class, () -> session.statusSchedules().orElseThrow().reconcile(
                    rig.fixture.store.getStatusScheduleState(ca, zeroecho.pki.api.status.StatusObjectType.CRL).orElseThrow(), NONE));
            assertFalse(armed.get());
            var effect = rig.fixture.store.getStatusScheduleState(ca, zeroecho.pki.api.status.StatusObjectType.CRL)
                    .orElseThrow().execution().orElseThrow();
            assertEquals(zeroecho.pki.api.schedule.StatusScheduleState.Phase.EFFECT_COMMITTED, effect.phase());
            status = effect.statusObjectId().orElseThrow();
            parent = effect.signingOperationId().orElseThrow();
            rig.verify(session, status);
            assertEquals(2, rig.dispatches.size());
            assertEquals(zeroecho.pki.spi.store.DomainContinuationStore.State.PUBLISHING,
                    rig.fixture.store.getDomainContinuation(parent).orElseThrow().state());
        }
        rig.clock.advance();
        effectCut.set(false);
        try (var session = rig.fixture.open()) {
            assertEquals(status, rig.complete(session, parent));
            var coordinator = session.statusSchedules().orElseThrow();
            var resumed = coordinator.reconcile(rig.fixture.store.getStatusScheduleState(ca,
                    zeroecho.pki.api.status.StatusObjectType.CRL).orElseThrow(), NONE);
            var completed = resumed.execution().orElseThrow();
            assertEquals(zeroecho.pki.api.schedule.StatusScheduleState.Phase.SCHEDULE_ADVANCED, completed.phase());
            assertEquals(status, completed.statusObjectId().orElseThrow());
            assertEquals(parent, completed.signingOperationId().orElseThrow());
            assertEquals(1, rig.fixture.store.listStatusObjects(ca).size());
            assertEquals(2, rig.dispatches.size());
            rig.verify(session, status);
        }
    }

    /**
     * Encoded future metadata limit rejects real parent before alternative signing.
     *
     * @param root isolated temporary store root supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void encodedFutureMetadataLimitRejectsRealParentBeforeAlternativeSigning(@TempDir Path root) throws Exception {
        var rig = new Rig(root, null);
        try (var session = rig.fixture.open()) {
            var ca = rig.fixture.create(session);
            rig.dispatches.clear();
            // Each valid individual field is below the codec's one-MiB string bound;
            // their real combined future transaction exceeds the two-MiB frame bound.
            var largeAccess = new AccessContext(new Principal("T".repeat(768 * 1024), "N".repeat(768 * 1024)),
                    new Purpose("P".repeat(768 * 1024)), Optional.empty(), Optional.empty());
            var semantic = session.semanticSigning().orElseThrow();
            var prepared = semantic.prepareFullCrl(largeAccess, new FullCrlRequest(
                    rig.fixture.store.getCa(ca).orElseThrow().currentIssuanceIssuerId(), Duration.ofHours(1)), NONE);
            var parent = prepared.receipt().operationId();
            var rejected = assertThrows(zeroecho.pki.api.PkiException.class, () -> semantic.accept(prepared));
            assertEquals("CRL_HYBRID_METADATA_LIMIT", rejected.getMessage());
            assertTrue(rig.dispatches.isEmpty());
            assertTrue(rig.fixture.store.getSignWorkflow(parent).isEmpty());
            assertTrue(rig.fixture.store.getDomainContinuation(parent).isEmpty());
            assertTrue(rig.fixture.store.getCrlHybridExecution(parent).isEmpty());
            assertTrue(rig.fixture.store.listStatusObjects(ca).isEmpty());
        }
    }

    private static boolean injectedAdoptionFailure(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof java.io.IOException && "Injected lost acknowledgement after durable hybrid CRL adoption".equals(cause.getMessage())) return true;
        }
        return false;
    }

    private enum Stop { BEFORE_ADOPTION, AFTER_ADOPTION, AFTER_STATUS }
    private static final class ProcessStop extends Error { private static final long serialVersionUID = 1L; }
    private record Dispatch(PkiId operation, String algorithm, String contentHash) { }
    private static final class TestClock extends Clock {
        private Instant now = HybridIssuanceFixture.CLOCK.instant();
        void advance() { now = now.plusSeconds(30); }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { if (!zone.equals(ZoneOffset.UTC)) throw new IllegalArgumentException("UTC required"); return this; }
        @Override public Instant instant() { return now; }
    }

    private static final class Rig {
        private final HybridIssuanceFixture fixture;
        private final TestClock clock = new TestClock();
        private final List<Dispatch> dispatches = new ArrayList<>();
        private int maximumWork = 1;
        private long residentBytes = 512L * 1024 * 1024;
        private Rig(Path root, FilesystemPkiStoreTestAccess.AdoptionForceFault fault) throws Exception {
            fixture = new HybridIssuanceFixture(root, "EC384", "ECDSA",
                    BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm(),
                    new HybridCertificateMode.AltSignature(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(),
                            HybridIssuanceFixture.key("alt").value()), "EC384", "ML-DSA-87");
            fixture.clock = clock;
            fixture.storeFactory = (configuration, dependencies) -> FilesystemPkiStoreTestAccess.open(
                    root.resolve("store"), maximumWork, dependencies, fault, residentBytes);
            fixture.signingDecorator = provider -> (SigningProvider) Proxy.newProxyInstance(SigningProvider.class.getClassLoader(),
                    new Class<?>[] {SigningProvider.class, zeroecho.pki.spi.crypto.PublicKeyInfoSource.class,
                            zeroecho.pki.spi.crypto.AltSigningCapability.class}, (proxy, method, arguments) -> {
                        if (method.getName().equals("dispatch")) {
                            var request = (SigningProvider.SignRequest) arguments[0];
                            dispatches.add(new Dispatch(request.operationId(), request.algorithmId(), request.contentCommitment().sha256()));
                        }
                        try { return method.invoke(provider, arguments); }
                        catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
        }
        private PkiId accept(PkiSession session, PkiId ca) {
            return tryAccept(session, ca).receipt().operationId();
        }
        private zeroecho.pki.api.signing.SigningAcceptanceResult tryAccept(PkiSession session, PkiId ca) {
            var semantic = session.semanticSigning().orElseThrow();
            return semantic.accept(semantic.prepareFullCrl(ACCESS, new FullCrlRequest(
                    fixture.store.getCa(ca).orElseThrow().currentIssuanceIssuerId(), Duration.ofHours(1)), NONE));
        }
        private PkiId complete(PkiSession session, PkiId parent) {
            var observation = session.localSigning().orElseThrow().complete(parent, NONE);
            var result = assertInstanceOf(LocalSigningResult.Completed.class, observation,
                    () -> fixture.failureDescription(observation));
            return new PkiId(assertInstanceOf(PkiOperationValue.Text.class, result.result().fields().get("statusObjectId")).value());
        }
        private BigInteger numberFromParent(PkiId parent) throws Exception {
            var workflow = fixture.store.getSignWorkflow(parent).orElseThrow();
            try (var content = fixture.store.stagedContent().openContent(workflow.envelope().candidate())) {
                return new zeroecho.pki.impl.framework.x509.StreamingDerReader()
                        .inspectAlternativeCrlTbs(content, NONE).crlNumber();
            }
        }
        private BigInteger verify(PkiSession session, PkiId status) throws Exception {
            byte[] der;
            try (var lease = session.repository().openStatusObject(status, "original", NONE); var input = lease.openStream()) { der = input.readAllBytes(); }
            var crl = new X509CRLHolder(der);
            assertTrue(crl.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(fixture.rootKey.getPublic())));
            assertTrue(crl.isAlternativeSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(fixture.altKey.getPublic())));
            return ASN1Integer.getInstance(crl.getExtension(Extension.cRLNumber).getParsedValue()).getValue();
        }
    }
}
