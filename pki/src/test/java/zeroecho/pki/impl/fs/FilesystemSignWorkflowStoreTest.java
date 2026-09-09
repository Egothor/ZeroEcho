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
package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static zeroecho.pki.testkit.PkiTestRuntime.signingAuthority;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.MethodSource;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.application.SigningReconciliationContinuation;
import zeroecho.pki.application.SigningReconciliationRequest;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.impl.core.async.SigningExecutionRuntime;
import zeroecho.pki.impl.core.async.DomainCommandEncoding;
import zeroecho.pki.impl.core.async.DomainContinuationTemplate;
import zeroecho.pki.impl.crypto.zeroecholib.TestKeyringUnlocks;
import zeroecho.pki.impl.crypto.zeroecholib.ZeroEchoLibSignatureWorkflow;
import zeroecho.pki.impl.crypto.zeroecholib.ZeroEchoLibSignatureWorkflowProvider;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.crypto.SignatureWorkflowRuntimeDependencies;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.testkit.InMemorySignatureWorkflow;
import zeroecho.pki.spi.store.StagedContentStore;
import zeroecho.pki.util.async.AsyncState;

final class FilesystemSignWorkflowStoreTest {

    private static final Principal TEST_OWNER = new Principal("TEST", "owner");
    private static final AccessContext TEST_ACCESS = new AccessContext(TEST_OWNER, new Purpose("SIGN"),
            Optional.empty(), Optional.empty());
    private static final KeyRef TEST_KEY = new KeyRef("test-key");
    private static final String TEST_ALGORITHM = "SHA256withRSA";

    @TempDir
    private Path localMatrixDirectory;

    @Test
    void localSuccessUsesExactlyTwoForcedCompositeRounds(@TempDir Path root) throws Exception {
        Instant now = Instant.parse("2026-01-02T03:04:05.123Z");
        Path keyring = root.resolve("keyring.zek");
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keys = KeyringStore.create(keyring, password)) {
            keys.putPrivate("sign.prv", "RSA", pair.getPrivate());
        }
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                    root.resolve("store"), FsPkiStoreOptions.defaults(), Clock.fixed(now, java.time.ZoneOffset.UTC));
                SignatureWorkflow workflow = new ZeroEchoLibSignatureWorkflowProvider(TestKeyringUnlocks.provider())
                        .allocate(new ProviderConfig("zeroecho-lib", Map.of("keyringPath", keyring.toString())),
                                SignatureWorkflowRuntimeDependencies.local(TestKeyringUnlocks.provider(), store));
                PkiSigningBus bus = new PkiSigningBus(store, workflow, signingAuthority(workflow))) {
            byte[] payload = new byte[] { 1, 2, 3, 4 };
            DurableContentReference reference = operationReference(store, payload);
            PkiId id = bus.newSubmissionId();
            PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(TEST_ACCESS,
                    TEST_ALGORITHM, reference, new KeyRef("zeroecho-lib:sign.prv"), Encoding.BINARY,
                    Optional.of(id));
            long before = store.localSigningWriterSnapshot().forces();
            bus.submitSign(id, TEST_OWNER, new KeyRef("zeroecho-lib:sign.prv"), TEST_ALGORITHM, reference,
                    Duration.ofSeconds(30), Optional.of(continuation.encode()));
            long after = store.localSigningWriterSnapshot().forces();
            assertEquals(2L, after - before);
            assertTrue(bus.consumeResult(id).isPresent());
        }
    }

    @Test
    void signingEvidenceDisabledByDefaultLeavesFeedUnsupportedAndForcesUnchanged(@TempDir Path root)
            throws Exception {
        Instant now = Instant.parse("2026-01-02T03:04:05.123Z");
        Path keyring = root.resolve("keyring.zek");
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keys = KeyringStore.create(keyring, password)) {
            keys.putPrivate("sign.prv", "RSA", pair.getPrivate());
        }
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                    root.resolve("store"), FsPkiStoreOptions.defaults(), Clock.fixed(now, java.time.ZoneOffset.UTC));
                SignatureWorkflow workflow = new ZeroEchoLibSignatureWorkflowProvider(TestKeyringUnlocks.provider())
                        .allocate(new ProviderConfig("zeroecho-lib", Map.of("keyringPath", keyring.toString())),
                                SignatureWorkflowRuntimeDependencies.local(TestKeyringUnlocks.provider(), store));
                PkiSigningBus bus = new PkiSigningBus(store, workflow, signingAuthority(workflow))) {
            assertFalse(store.supportsSigningEvidenceFeed());
            DurableContentReference reference = operationReference(store, new byte[] { 5, 6, 7, 8 });
            PkiId id = bus.newSubmissionId();
            PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(TEST_ACCESS,
                    TEST_ALGORITHM, reference, new KeyRef("zeroecho-lib:sign.prv"), Encoding.BINARY, Optional.of(id));
            long before = store.localSigningWriterSnapshot().forces();
            bus.submitSign(id, TEST_OWNER, new KeyRef("zeroecho-lib:sign.prv"), TEST_ALGORITHM, reference,
                    Duration.ofSeconds(30), Optional.of(continuation.encode()));
            // Default deployment: no evidence write, so the signing hot path is force-for-force unchanged.
            assertEquals(2L, store.localSigningWriterSnapshot().forces() - before);
            assertThrows(UnsupportedOperationException.class, () -> store.openSigningEvidenceFeed(-1L));
        }
    }

    @Test
    void signingEvidenceRecordedAndFedWhenOperatorEnablesIt(@TempDir Path root) throws Exception {
        Instant now = Instant.parse("2026-01-02T03:04:05.123Z");
        Path keyring = root.resolve("keyring.zek");
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keys = KeyringStore.create(keyring, password)) {
            keys.putPrivate("sign.prv", "RSA", pair.getPrivate());
        }
        try (FilesystemPkiStore store = new FilesystemPkiStore(root.resolve("store"),
                    FsPkiStoreOptions.defaults().withSigningEvidenceAudit(true),
                    Clock.fixed(now, java.time.ZoneOffset.UTC));
                SignatureWorkflow workflow = new ZeroEchoLibSignatureWorkflowProvider(TestKeyringUnlocks.provider())
                        .allocate(new ProviderConfig("zeroecho-lib", Map.of("keyringPath", keyring.toString())),
                                SignatureWorkflowRuntimeDependencies.local(TestKeyringUnlocks.provider(), store));
                PkiSigningBus bus = new PkiSigningBus(store, workflow, signingAuthority(workflow))) {
            assertTrue(store.supportsSigningEvidenceFeed());
            DurableContentReference reference = operationReference(store, new byte[] { 1, 2, 3, 4 });
            PkiId id = bus.newSubmissionId();
            PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(TEST_ACCESS,
                    TEST_ALGORITHM, reference, new KeyRef("zeroecho-lib:sign.prv"), Encoding.BINARY, Optional.of(id));
            long before = store.localSigningWriterSnapshot().forces();
            bus.submitSign(id, TEST_OWNER, new KeyRef("zeroecho-lib:sign.prv"), TEST_ALGORITHM, reference,
                    Duration.ofSeconds(30), Optional.of(continuation.encode()));
            // Opt-in cost: the evidence-log append is a separate metadata commit, so the terminal path does
            // strictly more forced rounds than the default two (a durable-audit-for-throughput trade the
            // operator accepts by enabling the feature).
            assertTrue(store.localSigningWriterSnapshot().forces() - before > 2L);
            assertTrue(bus.consumeResult(id).isPresent());

            List<PkiId> objectIds = new java.util.ArrayList<>();
            zeroecho.pki.application.SigningExecutionEvidence evidence = null;
            try (zeroecho.pki.spi.store.AuditEvidenceFeed feed = store.openSigningEvidenceFeed(-1L)) {
                while (feed.next(CancellationSignal.NONE)) {
                    objectIds.add(feed.current().objectId());
                    evidence = zeroecho.pki.application.SigningExecutionEvidence.decode(
                            zeroecho.pki.impl.core.async.DomainAttributeEncoding.decode(new String(
                                    feed.current().evidence(), java.nio.charset.StandardCharsets.UTF_8)))
                            .orElseThrow();
                }
            }
            assertEquals(List.of(id), objectIds);
            assertEquals(zeroecho.pki.application.SigningExecutionEvidence.Outcome.SIGNED, evidence.outcome());
            assertEquals(TEST_OWNER.name(), evidence.ownerId());
        }
    }

    @Test
    void localTerminalResultResumesAfterRealWalHeadroomRestoration(@TempDir Path root)
            throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        Path keyring = root.resolve("headroom-keyring.zek");
        createSigningKeyring(keyring);
        byte[] payload = { 1, 2, 3, 4 };

        WalCalibration calibration = calibrateLocalWal(
                root.resolve("calibration"), keyring, clock, now, payload,
                singletonWalConfiguration(8L * 1024L * 1024L));
        long maximumSegmentBytes = SigningWalContainerCodec.HEADER_BYTES
                + calibration.acceptanceBytes() + calibration.terminalBytes() - 1L;
        SigningActiveWal.Configuration constrained =
                singletonWalConfiguration(maximumSegmentBytes);

        Path storeRoot = root.resolve("constrained");
        AtomicInteger contentReads = new AtomicInteger();
        AtomicInteger restorations = new AtomicInteger();
        CountDownLatch firstRestoration = new CountDownLatch(1);
        CountDownLatch secondRestoration = new CountDownLatch(1);
        EncodedObject durableResult;
        PkiId operationId;

        try (FilesystemPkiStore store = new FilesystemPkiStore(
                    storeRoot, FsPkiStoreOptions.defaults(), clock, 8, null, constrained);
                SignatureWorkflow workflow = localWorkflow(keyring, store);
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(
                        1, 1, Duration.ofSeconds(5), Duration.ofSeconds(5));
                PkiSigningBus bus = PkiSigningBus.attach(
                        observingStore(store, contentReads, restorations,
                                firstRestoration, secondRestoration),
                        workflow, signingAuthority(workflow), runtime,
                        Duration.ofSeconds(5), Duration.ofSeconds(5))) {
            DurableContentReference reference = operationReference(store, payload);
            operationId = bus.newSubmissionId();
            assertEquals(calibration.identifierLength(), operationId.value().length());

            PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(
                    TEST_ACCESS, TEST_ALGORITHM, reference,
                    new KeyRef("zeroecho-lib:sign.prv"), Encoding.BINARY,
                    Optional.of(operationId));
            bus.submitSign(operationId, TEST_OWNER,
                    new KeyRef("zeroecho-lib:sign.prv"), TEST_ALGORITHM,
                    reference, Duration.ofSeconds(30), Optional.of(continuation.encode()));

            assertEquals(1, contentReads.get());
            assertTrue(firstRestoration.await(5, TimeUnit.SECONDS));
            awaitRuntimeBarrier(runtime, bus.newSubmissionId());

            durableResult = bus.consumeResult(operationId).orElseThrow();
            assertArrayEquals(calibration.result().bytes(), durableResult.bytes());
            assertEquals(1, contentReads.get());
            assertRuntimeReleased(runtime);

            SigningManifestCodec.Manifest firstRotation = readSigningManifest(storeRoot);
            assertEquals(1, firstRotation.sealedSegments().size());
            SigningManifestCodec.Segment acceptedSegment = firstRotation.sealedSegments().get(0);
            long actualAcceptanceBytes = acceptedSegment.length()
                    - SigningWalContainerCodec.HEADER_BYTES;

            assertEquals(calibration.acceptanceBytes(), actualAcceptanceBytes);
            assertEquals(calibration.terminalBytes() - 1L,
                    maximumSegmentBytes - acceptedSegment.length());
            assertEquals(SigningWalContainerCodec.HEADER_BYTES + calibration.terminalBytes(),
                    Files.size(signingMetadataRoot(storeRoot)
                            .resolve(firstRotation.activeWal().name())));

            SigningActiveWal.Snapshot terminalSnapshot = store.localSigningWriterSnapshot();
            assertEquals(1L, terminalSnapshot.groupsCommitted());
            assertEquals(1L, terminalSnapshot.requestsCommitted());
            assertEquals(1L, terminalSnapshot.maximumBatchSize());
            assertEquals(calibration.terminalBytes(), terminalSnapshot.bytesAppended());

            DurableContentReference rejectedReference = operationReference(store, payload.clone());
            PkiId rejectedId = bus.newSubmissionId();
            PkiSigningBus.SignContinuation rejectedContinuation = new PkiSigningBus.SignContinuation(
                    TEST_ACCESS, TEST_ALGORITHM, rejectedReference,
                    new KeyRef("zeroecho-lib:sign.prv"), Encoding.BINARY,
                    Optional.of(rejectedId));

            SigningExecutionException overloaded = assertThrows(SigningExecutionException.class,
                    () -> bus.submitSign(rejectedId, TEST_OWNER,
                            new KeyRef("zeroecho-lib:sign.prv"), TEST_ALGORITHM,
                            rejectedReference, Duration.ofSeconds(30),
                            Optional.of(rejectedContinuation.encode())));
            assertEquals(SigningExecutionException.Classification.OVERLOADED,
                    overloaded.classification());
            assertTrue(store.getSignRecord(rejectedId).isEmpty());
            assertEquals(1, contentReads.get());
            assertTrue(secondRestoration.await(5, TimeUnit.SECONDS));

            bus.retireSignOperation(operationId, "test-complete");
            assertEquals(SignWorkflowStore.State.RETIRED,
                    store.getSignRecord(operationId).orElseThrow().state());
            assertArrayEquals(durableResult.bytes(),
                    bus.consumeResult(operationId).orElseThrow().bytes());
            assertRuntimeReleased(runtime);
        }

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(
                storeRoot, FsPkiStoreOptions.defaults(), clock, 8, null, constrained)) {
            SignWorkflowStore.Record authoritative = reopened.getSignRecord(operationId).orElseThrow();
            assertEquals(SignWorkflowStore.State.RETIRED, authoritative.state());
            assertArrayEquals(durableResult.bytes(), authoritative.result().orElseThrow().bytes());
        }
    }

    @Test
    void localSuspendedTerminalRestartBecomesRecoveryIncompleteWithoutRepeatingCrypto(
            @TempDir Path root) throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        Path keyring = root.resolve("suspended-restart-keyring.zek");
        createSigningKeyring(keyring);
        byte[] payload = { 5, 6, 7, 8 };
        WalCalibration calibration = calibrateLocalWal(
                root.resolve("restart-calibration"), keyring, clock, now, payload,
                singletonWalConfiguration(8L * 1024L * 1024L));
        SigningActiveWal.Configuration constrained = singletonWalConfiguration(
                SigningWalContainerCodec.HEADER_BYTES
                        + calibration.acceptanceBytes() + calibration.terminalBytes() - 1L);

        Path storeRoot = root.resolve("suspended-restart-store");
        AtomicInteger contentReads = new AtomicInteger();
        CountDownLatch restorationWithheld = new CountDownLatch(1);
        PkiId operationId;
        DurableContentReference reference;
        String namespace;
        SignatureWorkflow.ConfigurationCommitment configurationCommitment;

        try (FilesystemPkiStore store = new FilesystemPkiStore(
                    storeRoot, FsPkiStoreOptions.defaults(), clock, 8, null, constrained);
                SignatureWorkflow workflow = localWorkflow(keyring, store);
                SigningExecutionRuntime runtime = new SigningExecutionRuntime(
                        1, 1, Duration.ofSeconds(5), Duration.ofSeconds(5));
                PkiSigningBus bus = PkiSigningBus.attach(
                        withholdingHeadroomStore(store, contentReads, restorationWithheld),
                        workflow, signingAuthority(workflow), runtime,
                        Duration.ofSeconds(5), Duration.ofSeconds(5))) {
            reference = operationReference(store, payload);
            operationId = bus.newSubmissionId();
            namespace = store.localSigningNamespace("zeroecho-lib");
            configurationCommitment = workflow.configurationCommitment();
            PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(
                    TEST_ACCESS, TEST_ALGORITHM, reference,
                    new KeyRef("zeroecho-lib:sign.prv"), Encoding.BINARY,
                    Optional.of(operationId));

            bus.submitSign(operationId, TEST_OWNER,
                    new KeyRef("zeroecho-lib:sign.prv"), TEST_ALGORITHM,
                    reference, Duration.ofSeconds(30), Optional.of(continuation.encode()));
            assertTrue(restorationWithheld.await(5, TimeUnit.SECONDS));
            awaitRuntimeBarrier(runtime, bus.newSubmissionId());

            assertEquals(1, contentReads.get());
            assertEquals(1, runtimeCount(runtime, "suspendedTerminalCount"));
            assertEquals(1, runtimeCount(runtime, "terminalSlotsInUse"));
            SignWorkflowStore.Record active = store.getSignRecord(operationId).orElseThrow();
            assertEquals(SignWorkflowStore.State.DISPATCHED, active.state());
            assertTrue(active.result().isEmpty());

            bus.close();
            assertRuntimeReleased(runtime);
            assertEquals(1, contentReads.get());
        }

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(
                storeRoot, FsPkiStoreOptions.defaults(), clock, 8, null, constrained)) {
            reopened.recoverMatchedLocalSigning(namespace, configurationCommitment);
            SignWorkflowStore.Record failed = reopened.getSignRecord(operationId).orElseThrow();
            assertEquals(SignWorkflowStore.State.FAILED, failed.state());
            assertEquals(Optional.of("RECOVERY_INCOMPLETE"), failed.detailCode());
            assertTrue(failed.result().isEmpty());
            assertEquals(1, contentReads.get());
            try (RepeatableContent retained = reopened.stagedContent().openContent(reference)) {
                assertEquals(reference.length(), retained.length().orElseThrow());
            }

            SignWorkflowStore.Record retired = reopened.retireSign(
                    operationId, failed.revision(), failed.fence()).orElseThrow();
            assertEquals(SignWorkflowStore.State.RETIRED, retired.state());
            assertThrows(java.io.IOException.class,
                    () -> reopened.stagedContent().openContent(reference));
            assertEquals(1, contentReads.get());
        }
    }

    @ParameterizedTest
    @MethodSource("permitReuseModes")
    void localExecutionPermitIsBoundAndOneShotWithoutAdditionalForce(boolean concurrent) throws Exception {
        Instant now = Instant.parse("2026-01-02T03:04:05.123Z");
        Path root = localMatrixDirectory.resolve("permit-reuse-store-" + concurrent);
        Path keyring = localMatrixDirectory.resolve("permit-reuse-" + concurrent + ".zek");
        createSigningKeyring(keyring);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root.resolve("store"),
                    FsPkiStoreOptions.defaults(), Clock.fixed(now, java.time.ZoneOffset.UTC));
                SignatureWorkflow allocated = new ZeroEchoLibSignatureWorkflowProvider(TestKeyringUnlocks.provider())
                        .allocate(new ProviderConfig("zeroecho-lib", Map.of("keyringPath", keyring.toString())),
                                SignatureWorkflowRuntimeDependencies.local(TestKeyringUnlocks.provider(), store));
                ExecutorService executor = Executors.newFixedThreadPool(2)) {
            ZeroEchoLibSignatureWorkflow workflow = (ZeroEchoLibSignatureWorkflow) allocated;
            byte[] payload = new byte[] { 1, 2, 3, 4 };
            AtomicInteger cryptoReads = new AtomicInteger();
            DurableContentReference reference = operationReference(store, payload);
            PkiId id = SigningSubmissionId.create(store.localSigningNamespace("zeroecho-lib"), now,
                    new SecureRandom()).id();
            SignatureWorkflow.SignRequest request = SignatureWorkflow.SignRequest.create(id,
                    store.localSigningNamespace("zeroecho-lib"), workflow.configurationCommitment(), 1L, TEST_ACCESS,
                    new KeyRef("zeroecho-lib:sign.prv"), TEST_ALGORITHM,
                    SignatureWorkflow.ContentCommitment.sha256(payload),
                    new CountingContent(payload, cryptoReads), Optional.of(Encoding.BINARY),
                    Optional.of(now.plusSeconds(30)));
            SignWorkflowStore.Record intent = localIntent(request, reference, now);
            long before = store.localSigningWriterSnapshot().forces();
            byte[] differentConfiguration = workflow.configurationCommitment().bytes();
            differentConfiguration[0] ^= 1;
            SignatureWorkflow.ConfigurationCommitment mismatch =
                    new SignatureWorkflow.ConfigurationCommitment(differentConfiguration);
            SignWorkflowStore.Record recordMismatch = new SignWorkflowStore.Record(intent.submissionId(),
                    intent.namespace(), intent.fingerprint(), mismatch, intent.owner(), intent.createdAt(),
                    intent.deadline(), intent.request(), intent.state(), intent.revision(), intent.fence(),
                    intent.leaseUntil(), intent.detailCode(), intent.result(), intent.providerUpdatedAt(),
                    intent.failureCount(), intent.nextEligibleAt(), intent.reconciliationFailureClass());
            try (SignWorkflowStore.SignAdmission admission = store.reserveSignAdmission(id)) {
                assertThrows(IllegalArgumentException.class, () -> store.acceptLocalSign(admission, request,
                        workflow.configurationCommitment(), recordMismatch, reference));
            }
            try (SignWorkflowStore.SignAdmission admission = store.reserveSignAdmission(id)) {
                assertThrows(IllegalArgumentException.class, () -> store.acceptLocalSign(admission, request,
                        mismatch, intent, reference));
            }
            assertTrue(store.getSignRecord(id).isEmpty());
            AtomicLocalSigningLedgerParticipant.AtomicAcceptance acceptance;
            try (SignWorkflowStore.SignAdmission admission = store.reserveSignAdmission(id)) {
                acceptance = store.acceptLocalSign(admission, request, workflow.configurationCommitment(),
                        intent, reference);
            }
            assertEquals(AtomicLocalSigningLedgerParticipant.AtomicAcceptance.Outcome.EXECUTE,
                    acceptance.outcome());
            LocalExecutionPermit permit = acceptance.executionPermit().orElseThrow();

            try (SignWorkflowStore.SignAdmission admission = store.reserveSignAdmission(id)) {
                assertThrows(IllegalStateException.class, () -> store.acceptLocalSign(
                        admission, request, mismatch, intent, reference));
            }

            try (SignWorkflowStore.SignAdmission admission = store.reserveSignAdmission(id)) {
                AtomicLocalSigningLedgerParticipant.AtomicAcceptance attached = store.acceptLocalSign(
                        admission, request, workflow.configurationCommitment(), intent, reference);
                assertEquals(AtomicLocalSigningLedgerParticipant.AtomicAcceptance.Outcome.ATTACHED,
                        attached.outcome());
                assertTrue(attached.executionPermit().isEmpty());
            }

            zeroecho.pki.spi.crypto.LocalSigningLedgerParticipant foreignParticipant =
                    (zeroecho.pki.spi.crypto.LocalSigningLedgerParticipant) java.lang.reflect.Proxy.newProxyInstance(
                            zeroecho.pki.spi.crypto.LocalSigningLedgerParticipant.class.getClassLoader(),
                            new Class<?>[] { zeroecho.pki.spi.crypto.LocalSigningLedgerParticipant.class },
                            (proxy, method, arguments) -> null);
            assertThrows(IllegalStateException.class, () -> permit.consume(foreignParticipant, request,
                    workflow.configurationCommitment()));

            PkiId differentId = SigningSubmissionId.create(request.namespace(), now, new SecureRandom()).id();
            SignatureWorkflow.SignRequest submissionMismatch = new SignatureWorkflow.SignRequest(
                    differentId, request.namespace(), request.semanticFingerprint(),
                    request.configurationCommitment(), request.fencingToken(),
                    request.accessContext(), request.keyRef(), request.algorithmId(), request.contentCommitment(),
                    request.content(), request.preferredSignatureEncoding(), request.deadline(),
                    request.cancellation());
            assertThrows(IllegalStateException.class, () -> permit.consume(store, submissionMismatch,
                    workflow.configurationCommitment()));

            SignatureWorkflow.SignRequest fingerprintMismatch = SignatureWorkflow.SignRequest.create(
                    request.submissionId(), request.namespace(), request.configurationCommitment(),
                    request.fencingToken(), request.accessContext(),
                    new KeyRef("zeroecho-lib:other.prv"), request.algorithmId(), request.contentCommitment(),
                    request.content(), request.preferredSignatureEncoding(), request.deadline());
            assertThrows(IllegalStateException.class, () -> permit.consume(store, fingerprintMismatch,
                    workflow.configurationCommitment()));

            SignatureWorkflow.SignRequest fenceMismatch = new SignatureWorkflow.SignRequest(
                    request.submissionId(), request.namespace(), request.semanticFingerprint(),
                    request.configurationCommitment(), request.fencingToken() + 1L, request.accessContext(),
                    request.keyRef(), request.algorithmId(),
                    request.contentCommitment(), request.content(), request.preferredSignatureEncoding(),
                    request.deadline(), request.cancellation());
            assertThrows(IllegalStateException.class, () -> permit.consume(store, fenceMismatch,
                    workflow.configurationCommitment()));

            assertThrows(IllegalStateException.class,
                    () -> permit.consume(store, request, mismatch));
            assertEquals("LocalExecutionPermit[redacted]", permit.toString());

            SignatureWorkflow.CallControl control = new SignatureWorkflow.CallControl(
                    now.plusSeconds(30), CancellationSignal.NONE);
            List<PkiId> results;
            if (concurrent) {
                CountDownLatch ready = new CountDownLatch(2);
                CountDownLatch start = new CountDownLatch(1);
                Callable<PkiId> invocation = () -> {
                    ready.countDown();
                    assertTrue(start.await(5, TimeUnit.SECONDS));
                    return workflow.submitAcceptedLocalSign(request, permit, control);
                };
                Future<PkiId> first = executor.submit(invocation);
                Future<PkiId> second = executor.submit(invocation);
                assertTrue(ready.await(5, TimeUnit.SECONDS));
                start.countDown();
                results = List.of(first.get(5, TimeUnit.SECONDS), second.get(5, TimeUnit.SECONDS));
            } else {
                results = List.of(workflow.submitAcceptedLocalSign(request, permit, control),
                        workflow.submitAcceptedLocalSign(request, permit, control));
            }

            assertEquals(List.of(id, id), results);
            assertEquals(1, cryptoReads.get());
            assertEquals(SignWorkflowStore.State.SUCCEEDED, store.getSignRecord(id).orElseThrow().state());
            assertEquals(2L, store.localSigningWriterSnapshot().forces() - before);
        }
    }

    @Test
    void cancellationBeforePermitConsumptionPublishesTerminalWithoutCryptography(@TempDir Path root)
            throws Exception {
        Instant now = Instant.parse("2026-01-02T03:04:05.123Z");
        Path keyring = root.resolve("keyring.zek");
        createSigningKeyring(keyring);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root.resolve("store"),
                    FsPkiStoreOptions.defaults(), Clock.fixed(now, java.time.ZoneOffset.UTC));
                SignatureWorkflow allocated = new ZeroEchoLibSignatureWorkflowProvider(TestKeyringUnlocks.provider())
                        .allocate(new ProviderConfig("zeroecho-lib", Map.of("keyringPath", keyring.toString())),
                                SignatureWorkflowRuntimeDependencies.local(TestKeyringUnlocks.provider(), store))) {
            ZeroEchoLibSignatureWorkflow workflow = (ZeroEchoLibSignatureWorkflow) allocated;
            byte[] payload = new byte[] { 5, 6, 7, 8 };
            AtomicInteger cryptoReads = new AtomicInteger();
            DurableContentReference reference = operationReference(store, payload);
            PkiId id = SigningSubmissionId.create(store.localSigningNamespace("zeroecho-lib"), now,
                    new SecureRandom()).id();
            SignatureWorkflow.SignRequest request = SignatureWorkflow.SignRequest.create(id,
                    store.localSigningNamespace("zeroecho-lib"), workflow.configurationCommitment(), 1L, TEST_ACCESS,
                    new KeyRef("zeroecho-lib:sign.prv"), TEST_ALGORITHM,
                    SignatureWorkflow.ContentCommitment.sha256(payload),
                    new CountingContent(payload, cryptoReads), Optional.of(Encoding.BINARY),
                    Optional.of(now.plusSeconds(30)));
            SignWorkflowStore.Record intent = localIntent(request, reference, now);
            AtomicLocalSigningLedgerParticipant.AtomicAcceptance acceptance;
            try (SignWorkflowStore.SignAdmission admission = store.reserveSignAdmission(id)) {
                acceptance = store.acceptLocalSign(admission, request, workflow.configurationCommitment(),
                        intent, reference);
            }
            assertTrue(store.cancelLocalSign(id, request.fencingToken()));

            assertEquals(id, workflow.submitAcceptedLocalSign(request,
                    acceptance.executionPermit().orElseThrow(), new SignatureWorkflow.CallControl(
                            now.plusSeconds(30), CancellationSignal.NONE)));
            assertEquals(0, cryptoReads.get());
            assertEquals(SignWorkflowStore.State.CANCELLED, store.getSignRecord(id).orElseThrow().state());
        }
    }

    @Test
    void acceptedLocalExecutionEntryRequiresPermitAndHasNoLegacyOverload() {
        java.lang.reflect.Method[] methods = Arrays.stream(ZeroEchoLibSignatureWorkflow.class.getDeclaredMethods())
                .filter(method -> "submitAcceptedLocalSign".equals(method.getName()))
                .toArray(java.lang.reflect.Method[]::new);
        assertEquals(1, methods.length);
        assertEquals(List.of(SignatureWorkflow.SignRequest.class, LocalExecutionPermit.class,
                SignatureWorkflow.CallControl.class), List.of(methods[0].getParameterTypes()));
        assertFalse(Serializable.class.isAssignableFrom(LocalExecutionPermit.class));
        assertFalse(Arrays.stream(LocalExecutionPermit.class.getDeclaredConstructors())
                .anyMatch(constructor -> Modifier.isPublic(constructor.getModifiers())));
    }

    @Test
    void localFilesystemPayloadMismatchIsDurableFailureWithoutSignature(@TempDir Path root) throws Exception {
        Instant now = Instant.parse("2026-01-02T03:04:05.123Z");
        Path keyring = root.resolve("mismatch-keyring.zek");
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keys = KeyringStore.create(keyring, password)) {
            keys.putPrivate("sign.prv", "RSA", pair.getPrivate());
        }
        Path storeRoot = root.resolve("store");
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                    storeRoot, FsPkiStoreOptions.defaults(), Clock.fixed(now, java.time.ZoneOffset.UTC));
                SignatureWorkflow workflow = new ZeroEchoLibSignatureWorkflowProvider(TestKeyringUnlocks.provider())
                        .allocate(new ProviderConfig("zeroecho-lib", Map.of("keyringPath", keyring.toString())),
                                SignatureWorkflowRuntimeDependencies.local(TestKeyringUnlocks.provider(), store));
                PkiSigningBus bus = new PkiSigningBus(store, workflow, signingAuthority(workflow))) {
            byte[] payload = new byte[] { 1, 2, 3, 4 };
            DurableContentReference reference = operationReference(store, payload);
            byte[] substituted = payload.clone();
            substituted[0] ^= 1;
            Files.write(new FsPaths(storeRoot).stagedContentRoot().resolve(reference.contentId() + ".content"),
                    substituted);
            PkiId id = bus.newSubmissionId();
            PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(TEST_ACCESS,
                    TEST_ALGORITHM, reference, new KeyRef("zeroecho-lib:sign.prv"), Encoding.BINARY,
                    Optional.of(id));

            bus.submitSign(id, TEST_OWNER, new KeyRef("zeroecho-lib:sign.prv"), TEST_ALGORITHM, reference,
                    Duration.ofSeconds(30), Optional.of(continuation.encode()));

            SignWorkflowStore.Record failed = store.getSignRecord(id).orElseThrow();
            assertEquals(SignWorkflowStore.State.FAILED, failed.state());
            assertEquals(Optional.of("CONTENT_INTEGRITY_FAILURE"), failed.detailCode());
            assertTrue(failed.result().isEmpty());
            assertTrue(bus.consumeResult(id).isEmpty());
        }
    }

    @Test
    void localCancellationWaitsForCryptoAcknowledgementBeforeRetirement(@TempDir Path root) throws Exception {
        Instant now = Instant.parse("2026-01-02T03:04:05.123Z");
        Path keyring = root.resolve("cancel-keyring.zek");
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keys = KeyringStore.create(keyring, password)) {
            keys.putPrivate("sign.prv", "RSA", pair.getPrivate());
        }
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                    root.resolve("store"), FsPkiStoreOptions.defaults(), Clock.fixed(now, java.time.ZoneOffset.UTC));
                SignatureWorkflow allocated = new ZeroEchoLibSignatureWorkflowProvider(TestKeyringUnlocks.provider())
                        .allocate(new ProviderConfig("zeroecho-lib", Map.of("keyringPath", keyring.toString())),
                                SignatureWorkflowRuntimeDependencies.local(TestKeyringUnlocks.provider(), store));
                ExecutorService executor = Executors.newSingleThreadExecutor()) {
            ZeroEchoLibSignatureWorkflow workflow = (ZeroEchoLibSignatureWorkflow) allocated;
            byte[] payload = new byte[64 * 1024];
            Arrays.fill(payload, (byte) 7);
            DurableContentReference reference = operationReference(store, payload);
            PkiId id = SigningSubmissionId.create(store.localSigningNamespace("zeroecho-lib"), now,
                    new SecureRandom()).id();
            CountDownLatch reading = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            RepeatableContent blocked = blockingContent(payload, reading, release);
            SignatureWorkflow.SignRequest request = SignatureWorkflow.SignRequest.create(id,
                    store.localSigningNamespace("zeroecho-lib"), workflow.configurationCommitment(), 1L,
                    TEST_ACCESS,
                    new KeyRef("zeroecho-lib:sign.prv"), TEST_ALGORITHM,
                    SignatureWorkflow.ContentCommitment.sha256(payload), blocked,
                    Optional.of(Encoding.BINARY), Optional.of(now.plusSeconds(30)));
            PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(TEST_ACCESS,
                    TEST_ALGORITHM, reference, new KeyRef("zeroecho-lib:sign.prv"), Encoding.BINARY,
                    Optional.of(id));
            SignWorkflowStore.Record intent = new SignWorkflowStore.Record(id,
                    store.localSigningNamespace("zeroecho-lib"), request.semanticFingerprint(),
                    request.configurationCommitment(), TEST_OWNER, now, now.plusSeconds(30), continuation.encode(),
                    SignWorkflowStore.State.INTENT, 0L, 0L,
                    Optional.empty(), Optional.of("INTENT"), Optional.empty(), Optional.empty(), 0,
                    Optional.empty(), Optional.empty());
            LocalExecutionPermit permit;
            try (SignWorkflowStore.SignAdmission admission = store.reserveSignAdmission(id)) {
                AtomicLocalSigningLedgerParticipant.AtomicAcceptance acceptance = store.acceptLocalSign(
                        admission, request, workflow.configurationCommitment(), intent, reference);
                assertEquals(AtomicLocalSigningLedgerParticipant.AtomicAcceptance.Outcome.EXECUTE,
                        acceptance.outcome());
                permit = acceptance.executionPermit().orElseThrow();
            }
            Future<PkiId> execution = executor.submit(() -> workflow.submitAcceptedLocalSign(request, permit,
                    new SignatureWorkflow.CallControl(now.plusSeconds(30), CancellationSignal.NONE)));
            assertTrue(reading.await(5, TimeUnit.SECONDS));
            assertTrue(workflow.cancel(id, 1L, "test cancellation",
                    new SignatureWorkflow.CallControl(now.plusSeconds(30), CancellationSignal.NONE)));
            assertEquals(SignWorkflowStore.State.CANCELLING, store.getSignRecord(id).orElseThrow().state());
            try (RepeatableContent stillOwned = store.stagedContent().openContent(reference)) {
                assertEquals(reference.length(), stillOwned.length().orElseThrow());
            }
            release.countDown();
            assertEquals(id, execution.get(5, TimeUnit.SECONDS));
            SignWorkflowStore.Record cancelled = store.getSignRecord(id).orElseThrow();
            assertEquals(SignWorkflowStore.State.CANCELLED, cancelled.state());
            SignWorkflowStore.Record retired = store.retireSign(id, cancelled.revision(), cancelled.fence())
                    .orElseThrow();
            assertEquals(SignWorkflowStore.State.RETIRED, retired.state());
            assertThrows(java.io.IOException.class, () -> store.stagedContent().openContent(reference));
        }
    }

    @Test
    void localCancellingRestartBecomesRecoveryIncompleteWithoutCrypto(@TempDir Path root) throws Exception {
        Instant now = Instant.parse("2026-01-02T03:04:05.123Z");
        PkiId id;
        String namespace;
        SignatureWorkflow.ConfigurationCommitment configurationCommitment = testConfigurationCommitment();
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), Clock.fixed(now, java.time.ZoneOffset.UTC))) {
            byte[] payload = new byte[] { 9, 8, 7 };
            DurableContentReference reference = operationReference(store, payload);
            namespace = store.localSigningNamespace("zeroecho-lib");
            id = SigningSubmissionId.create(namespace, now, new SecureRandom()).id();
            SignatureWorkflow.SignRequest request = SignatureWorkflow.SignRequest.create(id, namespace,
                    configurationCommitment, 1L, TEST_ACCESS, new KeyRef("zeroecho-lib:unused"), TEST_ALGORITHM,
                    SignatureWorkflow.ContentCommitment.sha256(payload), new ImmutableByteContent(payload),
                    Optional.of(Encoding.BINARY), Optional.of(now.plusSeconds(30)));
            EncodedObject continuation = new PkiSigningBus.SignContinuation(TEST_ACCESS, TEST_ALGORITHM,
                    reference, new KeyRef("zeroecho-lib:unused"), Encoding.BINARY, Optional.of(id)).encode();
            SignWorkflowStore.Record intent = new SignWorkflowStore.Record(id, namespace,
                    request.semanticFingerprint(), request.configurationCommitment(), TEST_OWNER, now,
                    now.plusSeconds(30), continuation,
                    SignWorkflowStore.State.INTENT, 0L, 0L, Optional.empty(), Optional.of("INTENT"),
                    Optional.empty(), Optional.empty(), 0, Optional.empty(), Optional.empty());
            try (SignWorkflowStore.SignAdmission admission = store.reserveSignAdmission(id)) {
                assertEquals(AtomicLocalSigningLedgerParticipant.AtomicAcceptance.Outcome.EXECUTE,
                        store.acceptLocalSign(admission, request, configurationCommitment, intent, reference)
                                .outcome());
            }
            assertTrue(store.cancelLocalSign(id, 1L));
            assertEquals(SignWorkflowStore.State.CANCELLING, store.getSignRecord(id).orElseThrow().state());
        }
        try (FilesystemPkiStore recovered = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), Clock.fixed(now.plusSeconds(1), java.time.ZoneOffset.UTC))) {
            assertEquals(SignWorkflowStore.State.CANCELLING,
                    recovered.getSignRecord(id).orElseThrow().state());
            byte[] mismatchBytes = configurationCommitment.bytes();
            mismatchBytes[0] ^= 1;
            recovered.recoverMatchedLocalSigning(namespace,
                    new SignatureWorkflow.ConfigurationCommitment(mismatchBytes));
            assertEquals(SignWorkflowStore.State.CANCELLING,
                    recovered.getSignRecord(id).orElseThrow().state());
            recovered.recoverMatchedLocalSigning(namespace, configurationCommitment);
            SignWorkflowStore.Record failed = recovered.getSignRecord(id).orElseThrow();
            assertEquals(SignWorkflowStore.State.FAILED, failed.state());
            assertEquals(Optional.of("RECOVERY_INCOMPLETE"), failed.detailCode());
        }
    }

    @ParameterizedTest
    @MethodSource("localDirectCommitBoundaries")
    void localSharedLedgerRestartMatrixNeverSplitsAuthorityOrRepeatsCryptography(
            LocalCommitBoundary boundary, int expectedCryptoInvocations) throws Exception {
        Instant now = Instant.parse("2026-01-02T03:04:05.123Z");
        Path root = localMatrixDirectory.resolve("local-" + boundary);
        AtomicInteger cryptoInvocations = new AtomicInteger();
        SigningActiveWal.Operations operations = boundary.operations();
        SignatureWorkflow.ConfigurationCommitment configurationCommitment = testConfigurationCommitment();
        LocalAttempt attempt;
        FilesystemPkiStore faulted = new FilesystemPkiStore(root,
                FsPkiStoreOptions.defaults(), Clock.fixed(now, java.time.ZoneOffset.UTC),
                8, operations);
        try {
            attempt = localAttempt(faulted, now);
            if (boundary == LocalCommitBoundary.ACCEPT_BEFORE_DURABILITY) {
                try (SignWorkflowStore.SignAdmission admission =
                        faulted.reserveSignAdmission(attempt.id())) {
                    assertThrows(PkiException.class, () -> faulted.acceptLocalSign(
                            admission, attempt.request(), configurationCommitment,
                            attempt.intent(), attempt.reference()));
                }
            } else {
                AtomicLocalSigningLedgerParticipant.AtomicAcceptance acceptance;
                try (SignWorkflowStore.SignAdmission admission =
                        faulted.reserveSignAdmission(attempt.id())) {
                    acceptance = faulted.acceptLocalSign(admission, attempt.request(), configurationCommitment,
                            attempt.intent(), attempt.reference());
                }
                assertEquals(AtomicLocalSigningLedgerParticipant.AtomicAcceptance.Outcome.EXECUTE,
                        acceptance.outcome());
                if (boundary.isTerminalBoundary()) {
                    assertTrue(acceptance.executionPermit().orElseThrow()
                            .consume(faulted, attempt.request(), configurationCommitment).isPresent());
                    SignatureWorkflow.OperationStatus terminal = invokeDeterministicCrypto(
                            cryptoInvocations, now.plusSeconds(1));
                    assertThrows(PkiException.class,
                            () -> faulted.completeLocalSign(attempt.request(), terminal));
                }
            }
        } finally {
            try {
                faulted.close();
            } catch (java.io.IOException expectedRecoveryRequired) {
                // The injected direct-commit boundary requires validated restart.
            }
        }

        try (FilesystemPkiStore restarted = new FilesystemPkiStore(root,
                FsPkiStoreOptions.defaults(), Clock.fixed(now.plusSeconds(2),
                        java.time.ZoneOffset.UTC))) {
            assertEquals(expectedCryptoInvocations, cryptoInvocations.get());
            restarted.recoverMatchedLocalSigning(attempt.request().namespace(), configurationCommitment);
            if (boundary == LocalCommitBoundary.ACCEPT_BEFORE_DURABILITY) {
                assertTrue(restarted.getSignRecord(attempt.id()).isEmpty());
                assertThrows(java.io.IOException.class, () -> restarted.stagedContent()
                        .openContent(attempt.reference()));
                return;
            }

            SignWorkflowStore.Record recovered = restarted.getSignRecord(attempt.id())
                    .orElseThrow();
            SignatureWorkflow.OperationStatus providerView =
                    restarted.localSignStatus(attempt.id());
            if (boundary == LocalCommitBoundary.TERMINAL_DELEGATE_THEN_FAIL) {
                assertEquals(SignWorkflowStore.State.SUCCEEDED, recovered.state());
                assertEquals(SignatureWorkflow.State.SUCCEEDED, providerView.state());
                assertArrayEquals(new byte[] { 91, 92 },
                        recovered.result().orElseThrow().bytes());
                assertArrayEquals(new byte[] { 91, 92 }, providerView.result().orElseThrow()
                        .signature().orElseThrow().bytes());
            } else {
                assertEquals(SignWorkflowStore.State.FAILED, recovered.state());
                assertEquals(Optional.of("RECOVERY_INCOMPLETE"), recovered.detailCode());
                assertEquals(SignatureWorkflow.State.FAILED, providerView.state());
                assertEquals(Optional.of("RECOVERY_INCOMPLETE"), providerView.detailCode());
                assertTrue(recovered.result().isEmpty());
            }
            try (RepeatableContent retained = restarted.stagedContent()
                    .openContent(attempt.reference())) {
                assertEquals(attempt.reference().length(), retained.length().orElseThrow());
            }
            SignWorkflowStore.Record retired = restarted.retireSign(attempt.id(),
                    recovered.revision(), recovered.fence()).orElseThrow();
            assertEquals(SignWorkflowStore.State.RETIRED, retired.state());
            if (boundary == LocalCommitBoundary.TERMINAL_DELEGATE_THEN_FAIL) {
                assertArrayEquals(new byte[] { 91, 92 },
                        retired.result().orElseThrow().bytes());
            }
            assertThrows(java.io.IOException.class, () -> restarted.stagedContent()
                    .openContent(attempt.reference()));
            assertEquals(expectedCryptoInvocations, cryptoInvocations.get());
        }
    }

    @ParameterizedTest(name = "shared remote ledger terminal force/restart: {0}")
    @EnumSource(SharedRemoteTerminalBoundary.class)
    void sharedRemoteLedgerTerminalFaultIsolatesAuthoritiesAndNeverRepeatsProviderWork(
            SharedRemoteTerminalBoundary boundary) throws Exception {
        Instant now = Instant.parse("2026-01-02T03:04:05.123Z");
        Clock clock = Clock.fixed(now, java.time.ZoneOffset.UTC);
        Path root = localMatrixDirectory.resolve("remote-shared-" + boundary.name()
                .toLowerCase(java.util.Locale.ROOT));
        LocalFaultWalOperations operations = new LocalFaultWalOperations(boundary.image());
        SignatureWorkflow.ConfigurationCommitment sharedCommitment =
                configurationCommitment((byte) 17);
        MatrixRemoteWorkflow controlWorkflow = new MatrixRemoteWorkflow(
                "control-authority", sharedCommitment, now.plusSeconds(1), null);
        MatrixRemoteWorkflow targetWorkflow = new MatrixRemoteWorkflow(
                "target-authority", sharedCommitment, now.plusSeconds(1), operations);
        assertFalse(Arrays.equals(controlWorkflow.signature(), targetWorkflow.signature()));
        RemoteAttempt control;
        RemoteAttempt target;
        RemoteAttempt controlProbe;
        RemoteAttempt targetProbe;
        RemoteAttempt controlDispatchedProbe;
        RemoteAttempt targetDispatchedProbe;

        FilesystemPkiStore faulted = new FilesystemPkiStore(root,
                FsPkiStoreOptions.defaults(), clock, 8, operations);
        try {
            try (PkiSigningBus controlBus = new PkiSigningBus(
                        faulted, controlWorkflow, signingAuthority(controlWorkflow));
                    PkiSigningBus targetBus = new PkiSigningBus(
                            faulted, targetWorkflow, signingAuthority(targetWorkflow))) {
                controlProbe = submitRemote(
                        faulted, controlBus, controlWorkflow, (byte) 37);
                targetProbe = submitRemote(
                        faulted, targetBus, targetWorkflow, (byte) 38);
                controlDispatchedProbe = submitRemoteDispatched(
                        faulted, controlBus, controlWorkflow, (byte) 39);
                targetDispatchedProbe = submitRemoteDispatched(
                        faulted, targetBus, targetWorkflow, (byte) 40);
                assertBidirectionalForeignIsolation(faulted,
                        controlBus, controlWorkflow, controlProbe,
                        targetBus, targetWorkflow, targetProbe);
                assertBidirectionalDispatchedForeignIsolation(faulted,
                        controlBus, controlWorkflow, controlDispatchedProbe,
                        targetBus, targetWorkflow, targetDispatchedProbe);

                control = submitRemote(faulted, controlBus, controlWorkflow, (byte) 41);
                assertEquals(AsyncState.SUCCEEDED,
                        controlBus.status(control.id()).orElseThrow().state());
                assertArrayEquals(controlWorkflow.signature(),
                        controlBus.consumeResult(control.id()).orElseThrow().bytes());
                assertEquals(SignWorkflowStore.State.SUCCEEDED,
                        faulted.getSignRecord(control.id()).orElseThrow().state());

                target = submitRemote(faulted, targetBus, targetWorkflow, (byte) 42);
                targetWorkflow.armTerminalPublication();
                assertThrows(PkiException.class, () -> targetBus.status(target.id()));
            }
        } finally {
            try {
                faulted.close();
            } catch (java.io.IOException expectedRecoveryRequired) {
                // The injected terminal-force boundary requires validated restart.
            }
        }

        assertProviderExactlyOnce(controlWorkflow, control, controlDispatchedProbe);
        assertProviderExactlyOnce(targetWorkflow, target, targetDispatchedProbe);
        try (FilesystemPkiStore restarted = new FilesystemPkiStore(
                    root, FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus controlBus = new PkiSigningBus(
                        restarted, controlWorkflow, signingAuthority(controlWorkflow));
                PkiSigningBus targetBus = new PkiSigningBus(
                        restarted, targetWorkflow, signingAuthority(targetWorkflow))) {
            assertRecoveredProviderOwnership(restarted, control, controlWorkflow);
            assertRecoveredProviderOwnership(restarted, target, targetWorkflow);
            assertRecoveredProviderOwnership(restarted, controlProbe, controlWorkflow);
            assertRecoveredProviderOwnership(restarted, targetProbe, targetWorkflow);
            assertRecoveredProviderOwnership(
                    restarted, controlDispatchedProbe, controlWorkflow);
            assertRecoveredProviderOwnership(
                    restarted, targetDispatchedProbe, targetWorkflow);
            assertEquals(SignWorkflowStore.State.SUCCEEDED,
                    restarted.getSignRecord(control.id()).orElseThrow().state());
            assertEquals(boundary.terminalRecovered()
                            ? SignWorkflowStore.State.SUCCEEDED : SignWorkflowStore.State.DISPATCHED,
                    restarted.getSignRecord(target.id()).orElseThrow().state());

            assertBidirectionalForeignIsolation(restarted,
                    controlBus, controlWorkflow, controlProbe,
                    targetBus, targetWorkflow, targetProbe);
            assertBidirectionalDispatchedForeignIsolation(restarted,
                    controlBus, controlWorkflow, controlDispatchedProbe,
                    targetBus, targetWorkflow, targetDispatchedProbe);

            int controlStatusCalls = controlWorkflow.statusCalls();
            int targetStatusCalls = targetWorkflow.statusCalls();
            controlBus.status(target.id());
            targetBus.status(control.id());
            assertEquals(controlStatusCalls, controlWorkflow.statusCalls());
            assertEquals(targetStatusCalls, targetWorkflow.statusCalls());

            assertArrayEquals(controlWorkflow.signature(),
                    controlBus.consumeResult(control.id()).orElseThrow().bytes());
            assertEquals(AsyncState.SUCCEEDED,
                    targetBus.status(target.id()).orElseThrow().state());
            assertArrayEquals(targetWorkflow.signature(),
                    targetBus.consumeResult(target.id()).orElseThrow().bytes());
            assertRecoveredProviderOwnership(restarted, control, controlWorkflow);
            assertRecoveredProviderOwnership(restarted, target, targetWorkflow);
            assertEquals(SignWorkflowStore.State.SUCCEEDED,
                    restarted.getSignRecord(target.id()).orElseThrow().state());
            assertProviderExactlyOnce(controlWorkflow, control, controlDispatchedProbe);
            assertProviderExactlyOnce(targetWorkflow, target, targetDispatchedProbe);
        } finally {
            targetWorkflow.close();
            controlWorkflow.close();
        }
    }

    @Test
    void currentRecordCodecRequiresExactShapeAndRedactsStructuralFailures(@TempDir Path root) throws Exception {
        System.out.println("currentRecordCodecRequiresExactShapeAndRedactsStructuralFailures");
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        PkiId id = SigningSubmissionId
                .create("0123456789abcdef0123456789abcdef.test-signer", createdAt, new SecureRandom()).id();
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
        SignWorkflowStore.Record current = intent(store, id, createdAt,
                new EncodedObject(Encoding.BINARY, new byte[] { 7 }), TEST_ALGORITHM);
        String fingerprint = current.fingerprint();
        byte[] encoded = FsCodec.encode(FsCodec.SIGN_WORKFLOW_RECORD, current);

        SignWorkflowStore.Record decoded = FsCodec.decode(FsCodec.SIGN_WORKFLOW_RECORD, encoded,
                store.stagedContent());
        assertEquals(current.submissionId(), decoded.submissionId());
        assertEquals(current.providerUpdatedAt(), decoded.providerUpdatedAt());
        assertTrue(current.configurationCommitment().matches(decoded.configurationCommitment()));

        byte[] commitmentBytes = current.configurationCommitment().bytes();
        int commitmentOffset = indexOf(encoded, commitmentBytes);
        assertTrue(commitmentOffset > 0);
        byte[] malformedCommitment = encoded.clone();
        malformedCommitment[commitmentOffset - 1] = 31;
        assertRedactedStructuralFailure(malformedCommitment, fingerprint);

        byte[] missingComponent = Arrays.copyOf(encoded, encoded.length - 1);
        assertRedactedStructuralFailure(missingComponent, fingerprint);

        byte[] extraComponent = Arrays.copyOf(encoded, encoded.length + 1);
        extraComponent[extraComponent.length - 1] = 1;
        assertRedactedStructuralFailure(extraComponent, fingerprint);

        byte[] missingProviderUpdatedAt = Arrays.copyOf(encoded, encoded.length - 3);
        assertRedactedStructuralFailure(missingProviderUpdatedAt, fingerprint);
        }
        System.out.println("...ok");
    }

    @Test
    void malformedObsoleteSigningRecordIsIgnoredAndCannotExposeResult(@TempDir Path root) throws Exception {
        System.out.println("malformedObsoleteSigningRecordIsIgnoredAndCannotExposeResult");
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        MutableClock clock = new MutableClock(createdAt);
        SignWorkflowStore.Record intent;
        PkiId id;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            String namespace = store.signingNamespace() + ".test-signer";
            id = SigningSubmissionId.create(namespace, createdAt, new SecureRandom()).id();
            intent = intent(store, id, createdAt, new EncodedObject(Encoding.BINARY, new byte[] { 9 }), TEST_ALGORITHM);
            store.createSignIntent(intent);
        }
        String fingerprint = intent.fingerprint();

        Path recordPath = root.resolve("sign-workflows/by-id/legacy/current.bin");
        Files.createDirectories(recordPath.getParent());
        Files.write(recordPath, new byte[] { 1, 2, 3 });

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock);
                InMemorySignatureWorkflow signer = new InMemorySignatureWorkflow(Map.of(), false);
                PkiSigningBus bus = new PkiSigningBus(reopened, signer, signingAuthority(signer))) {
            assertEquals(intent.fingerprint(), reopened.getSignRecord(id).orElseThrow().fingerprint());
            assertTrue(bus.consumeResult(id).isEmpty());
            assertEquals(0, signer.submittedSignCount());
        }
        System.out.println("...ok");
    }

    @Test
    void unsupportedObsoleteSigningRecordVersionIsNotAnAuthoritativeInput(@TempDir Path root) throws Exception {
        System.out.println("unsupportedObsoleteSigningRecordVersionIsNotAnAuthoritativeInput");
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        MutableClock clock = new MutableClock(createdAt);
        PkiId id;
        String fingerprint;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            String namespace = store.signingNamespace() + ".test-signer";
            id = SigningSubmissionId.create(namespace, createdAt, new SecureRandom()).id();
            SignWorkflowStore.Record current = intent(store, id, createdAt,
                    new EncodedObject(Encoding.BINARY, new byte[] { 10 }), TEST_ALGORITHM);
            fingerprint = current.fingerprint();
            store.createSignIntent(current);
        }

        Path recordPath = root.resolve("sign-workflows/by-id/legacy/current.bin");
        Files.createDirectories(recordPath.getParent());
        Files.write(recordPath, ByteBuffer.allocate(8).putInt(0x5A455352).putInt(99).array());

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock);
                InMemorySignatureWorkflow signer = new InMemorySignatureWorkflow(Map.of(), false);
                PkiSigningBus bus = new PkiSigningBus(reopened, signer, signingAuthority(signer))) {
            assertEquals(id, reopened.getSignRecord(id).orElseThrow().submissionId());
            assertTrue(bus.consumeResult(id).isEmpty());
            assertEquals(0, signer.submittedSignCount());
        }
        System.out.println("...ok");
    }

    @Test
    void stableIdentityCasRestartConflictAndExpiry(@TempDir java.nio.file.Path root) throws Exception {
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        MutableClock clock = new MutableClock(createdAt);
        FsPkiStoreOptions defaults = FsPkiStoreOptions.defaults();
        FsPkiStoreOptions options = new FsPkiStoreOptions(defaults.caHistoryPolicy(), defaults.profileHistoryPolicy(),
                defaults.revocationHistoryPolicy(), defaults.workflowHistoryPolicy(), true, Duration.ofDays(90),
                Duration.ZERO, defaults.signingMaximumGroupSize(),
                defaults.signingResidentIndexBudgetBytes(), defaults.signingCompactionTransientBudgetBytes(),
                defaults.signingEvidenceAudit());
        EncodedObject request = new EncodedObject(Encoding.BINARY, new byte[] { 1, 2, 3 });
        PkiId id;
        SignWorkflowStore.Record intent;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options, clock)) {
            String namespace = store.signingNamespace() + ".test-signer";
            id = SigningSubmissionId.create(namespace, createdAt, new SecureRandom()).id();
            intent = intent(store, id, createdAt, request, TEST_ALGORITHM);
            assertEquals(SignWorkflowStore.CreateResult.CREATED, store.createSignIntent(intent));
            assertEquals(SignWorkflowStore.CreateResult.ATTACHED, store.createSignIntent(intent));
            SignWorkflowStore.Record fingerprintConflict = copy(intent, intent.request(),
                    flipFingerprint(intent.fingerprint()), intent.state(), intent.revision(), intent.fence(),
                    intent.leaseUntil(), intent.detailCode(), intent.result(), intent.providerUpdatedAt());
            assertEquals(SignWorkflowStore.CreateResult.CONFLICT, store.createSignIntent(fingerprintConflict));
            assertEquals(SignWorkflowStore.CreateResult.CONFLICT,
                    store.createSignIntent(intent(store, id, createdAt, request, "SHA512withRSA")));

            SignWorkflowStore.Record claimed = store.tryClaimSign(id, 0L, Duration.ofSeconds(30)).orElseThrow();
            assertEquals(1L, claimed.revision());
            assertEquals(1L, claimed.fence());
            assertTrue(store.tryClaimSign(id, 0L, Duration.ofSeconds(30)).isEmpty());
            assertTrue(store.transitionSign(id, claimed.revision(), claimed.fence(), SignWorkflowStore.State.DISPATCHED,
                    Optional.of("DISPATCHED"), Optional.empty(), Optional.empty()).isPresent());
        }

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, options, clock)) {
            assertEquals(SignWorkflowStore.State.DISPATCHED, reopened.getSignRecord(id).orElseThrow().state());
            clock.set(createdAt.plus(Duration.ofDays(90)));
            assertEquals(0, reopened.purgeExpiredSignRecords());
            SignWorkflowStore.Record expired = reopened.getSignRecord(id).orElseThrow();
            assertEquals(SignWorkflowStore.State.EXPIRED, expired.state());
            assertTrue(reopened.transitionSign(id, expired.revision(), expired.fence(),
                    SignWorkflowStore.State.FAILED, Optional.of("PROVIDER_FAILED"), Optional.empty(),
                    Optional.of(clock.instant())).isEmpty());
            assertEquals(1, reopened.purgeExpiredSignRecords());
            assertFalse(reopened.getSignRecord(id).isPresent());
            assertThrows(IllegalArgumentException.class, () -> reopened.createSignIntent(intent));
        }
        try (FilesystemPkiStore foreign = new FilesystemPkiStore(root.resolve("foreign"), options, clock)) {
            assertThrows(IllegalArgumentException.class, () -> foreign.createSignIntent(intent));
        }
    }

    @Test
    void periodicReconciliationPurgesOneForcedBoundedBatchPerPass(@TempDir Path root) throws Exception {
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        MutableClock clock = new MutableClock(createdAt);
        InMemorySignatureWorkflow signer = new InMemorySignatureWorkflow(Map.of());
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock);
                PkiSigningBus bus = new PkiSigningBus(store, signer, signingAuthority(signer))) {
            List<PkiId> retained = new java.util.ArrayList<>();
            for (int marker = 0; marker < 40; marker++) {
                PkiId id = persistClaimed(store, createdAt, marker);
                SignWorkflowStore.Record intent = store.getSignRecord(id).orElseThrow();
                SignWorkflowStore.Record failed = store.transitionSign(id, intent.revision(), intent.fence(),
                        SignWorkflowStore.State.FAILED, Optional.of("PROVIDER_FAILED"), Optional.empty(),
                        Optional.of(createdAt)).orElseThrow();
                store.retireSign(id, failed.revision(), failed.fence()).orElseThrow();
                retained.add(id);
            }
            clock.set(createdAt.plus(Duration.ofDays(90)));

            long rejectedForces = store.localSigningWriterSnapshot().forces();
            bus.reconcile(new SigningReconciliationRequest(SigningReconciliationContinuation.start(), 1, 1,
                    clock.instant().plusSeconds(5), Duration.ofSeconds(1), () -> true));
            bus.reconcile(new SigningReconciliationRequest(SigningReconciliationContinuation.start(), 1, 1,
                    clock.instant(), Duration.ofSeconds(1), CancellationSignal.NONE));
            assertEquals(rejectedForces, store.localSigningWriterSnapshot().forces());
            assertEquals(40L, retained.stream().filter(id -> store.getSignRecord(id).isPresent()).count());

            long firstForces = store.localSigningWriterSnapshot().forces();
            assertTimeout(Duration.ofSeconds(5), () -> bus.reconcile(reconciliationPass(clock)));
            assertEquals(1L, store.localSigningWriterSnapshot().forces() - firstForces);
            assertEquals(30L, retained.stream().filter(id -> store.getSignRecord(id).isPresent()).count());

            long secondForces = store.localSigningWriterSnapshot().forces();
            assertTimeout(Duration.ofSeconds(5), () -> bus.reconcile(reconciliationPass(clock)));
            assertEquals(1L, store.localSigningWriterSnapshot().forces() - secondForces);
            assertEquals(20L, retained.stream().filter(id -> store.getSignRecord(id).isPresent()).count());

            long thirdForces = store.localSigningWriterSnapshot().forces();
            assertTimeout(Duration.ofSeconds(5), () -> bus.reconcile(reconciliationPass(clock)));
            assertEquals(1L, store.localSigningWriterSnapshot().forces() - thirdForces);
            assertEquals(10L, retained.stream().filter(id -> store.getSignRecord(id).isPresent()).count());

            long fourthForces = store.localSigningWriterSnapshot().forces();
            assertTimeout(Duration.ofSeconds(5), () -> bus.reconcile(reconciliationPass(clock)));
            assertEquals(1L, store.localSigningWriterSnapshot().forces() - fourthForces);
            assertTrue(retained.stream().noneMatch(id -> store.getSignRecord(id).isPresent()));

            long completedForces = store.localSigningWriterSnapshot().forces();
            bus.reconcile(reconciliationPass(clock));
            assertEquals(completedForces, store.localSigningWriterSnapshot().forces());
        }
    }

    private static SigningReconciliationRequest reconciliationPass(Clock clock) {
        return new SigningReconciliationRequest(SigningReconciliationContinuation.start(), 1, 1,
                clock.instant().plusSeconds(5), Duration.ofSeconds(1), CancellationSignal.NONE);
    }

    @Test
    void postRetirementContentFailureStillDeletesWorkflowAndRecoversOnRestart(@TempDir Path root) throws Exception {
        Path busLog = root.resolveSibling(root.getFileName() + "-bus.log");
        AtomicBoolean failRetirement = new AtomicBoolean(true);
        InMemorySignatureWorkflow signer = new InMemorySignatureWorkflow(Map.of());
        PkiId operationId;
        DurableContentReference content;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), Clock.systemUTC(),
                FilesystemRevocationAuthority.IndexUpdateFaultInjector.NONE, reference -> {
                    if (failRetirement.compareAndSet(true, false)) {
                        throw new java.io.IOException("injected physical cleanup detail");
                    }
                }); PkiSigningBus bus = new PkiSigningBus(store, signer, signingAuthority(signer))) {
            operationId = bus.newSubmissionId();
            try (zeroecho.pki.spi.store.ContentSink sink = store.stagedContent().beginContent(Encoding.BINARY,
                    DurableContentReference.Lifecycle.OPERATION);
                    java.io.OutputStream output = sink.outputStream()) {
                output.write(new byte[] { 1, 2, 3 });
                content = sink.complete();
            }
            AccessContext access = new AccessContext(TEST_OWNER, new Purpose("SIGN"), Optional.empty(),
                    Optional.empty());
            PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(access,
                    TEST_ALGORITHM, content, TEST_KEY, Encoding.BINARY, Optional.empty());
            bus.submitSign(operationId, TEST_OWNER, TEST_KEY, TEST_ALGORITHM, content, Duration.ofSeconds(30),
                    Optional.of(continuation.encode()));
            assertTrue(bus.status(operationId).isPresent());
            assertTrue(store.listWorkflowStates().isEmpty());
            assertFalse(Files.exists(busLog));

            PkiException failure = assertThrows(PkiException.class,
                    () -> bus.retireSignOperation(operationId, "test-retirement"));

            assertEquals("Signing content cleanup failed: code=SIGNING_CONTENT_CLEANUP_FAILED",
                    failure.getMessage());
            assertFalse(failure.toString().contains("injected physical cleanup detail"));
            assertEquals(0, failure.getSuppressed().length);
            SignWorkflowStore.Record retired = store.getSignRecord(operationId).orElseThrow();
            assertEquals(SignWorkflowStore.State.RETIRED, retired.state());
            assertFalse(PkiSigningBus.SignContinuation.decode(retired.request(), store.stagedContent())
                    .hasLiveContent());
            assertTrue(store.listWorkflowStates().isEmpty());
            try (RepeatableContent orphan = bus.openContent(content)) {
                assertEquals(3L, orphan.length().orElseThrow());
            }
        }

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults());
                PkiSigningBus replayed = new PkiSigningBus(reopened, signer, signingAuthority(signer))) {
            SignWorkflowStore.Record retained = reopened.getSignRecord(operationId).orElseThrow();
            assertEquals(SignWorkflowStore.State.RETIRED, retained.state());
            assertFalse(PkiSigningBus.SignContinuation.decode(retained.request(), reopened.stagedContent())
                    .hasLiveContent());
            assertTrue(reopened.listWorkflowStates().isEmpty());
            assertThrows(PkiException.class, () -> replayed.openContent(content));
        } finally {
            signer.close();
        }
    }

    @Test
    void snapshotRetainsNamespaceResultRevisionFenceAndRollbackWatermark(@TempDir java.nio.file.Path root)
            throws Exception {
        Instant createdAt = Instant.parse("2026-04-05T06:07:08.900Z");
        MutableClock clock = new MutableClock(createdAt);
        Path snapshot = root.resolveSibling(root.getFileName() + "-snapshot");
        String namespace;
        PkiId id;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            namespace = store.signingNamespace() + ".test-signer";
            id = SigningSubmissionId.create(namespace, createdAt, new SecureRandom()).id();
            SignWorkflowStore.Record created = intent(store, id, createdAt,
                    new EncodedObject(Encoding.BINARY, new byte[] { 4 }), TEST_ALGORITHM);
            store.createSignIntent(created);
            SignWorkflowStore.Record claimed = store.tryClaimSign(id, 0L, Duration.ofSeconds(10)).orElseThrow();
            SignWorkflowStore.Record dispatched = store.transitionSign(id, claimed.revision(), claimed.fence(),
                    SignWorkflowStore.State.DISPATCHED, Optional.of("DISPATCHED"), Optional.empty(), Optional.empty())
                    .orElseThrow();
            clock.set(createdAt.plusSeconds(1));
            store.transitionSign(id, dispatched.revision(), dispatched.fence(), SignWorkflowStore.State.SUCCEEDED,
                    Optional.of("SIGNED"), Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 9 })),
                    Optional.of(createdAt.plusSeconds(1))).orElseThrow();
            clock.set(createdAt.plusSeconds(30));
            assertEquals(createdAt.plusSeconds(30), store.signingNow());
            clock.set(createdAt.minusSeconds(30));
            assertEquals(createdAt.plusSeconds(30), store.signingNow());
            // Signing safety metadata deliberately reflects export time, even when the
            // requested historical instant predates the operation.
            store.exportSnapshot(snapshot, createdAt.minusSeconds(60));
        }
        try (FilesystemPkiStore restored = new FilesystemPkiStore(snapshot, FsPkiStoreOptions.defaults(), clock)) {
            assertEquals(namespace.substring(0, 32), restored.signingNamespace());
            SignWorkflowStore.Record restoredRecord = restored.getSignRecord(id).orElseThrow();
            assertEquals(SignWorkflowStore.State.SUCCEEDED, restoredRecord.state());
            assertEquals(Encoding.BINARY, restoredRecord.result().orElseThrow().encoding());
            assertArrayEquals(new byte[] { 9 }, restoredRecord.result().orElseThrow().bytes());
            assertEquals(3L, restoredRecord.revision());
            assertEquals(1L, restoredRecord.fence());
            assertTrue(restored.listWorkflowStates().isEmpty());
            assertEquals(createdAt.plusSeconds(30), restored.signingNow());
        }
    }

    @Test
    void concurrentClaimsHaveOneWinnerAndDifferentIdsRemainIndependent(@TempDir java.nio.file.Path root)
            throws Exception {
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        MutableClock clock = new MutableClock(createdAt);
        EncodedObject request = new EncodedObject(Encoding.BINARY, new byte[] { 1 });
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock);
                ExecutorService executor = Executors.newFixedThreadPool(8)) {
            String namespace = store.signingNamespace() + ".test-signer";
            PkiId first = SigningSubmissionId.create(namespace, createdAt, new SecureRandom()).id();
            PkiId second = SigningSubmissionId.create(namespace, createdAt, new SecureRandom()).id();
            store.createSignIntent(intent(store, first, createdAt, request, TEST_ALGORITHM));
            store.createSignIntent(intent(store, second, createdAt, request, TEST_ALGORITHM));
            Callable<Boolean> claim = () -> store.tryClaimSign(first, 0L, Duration.ofSeconds(30)).isPresent();
            long winners = executor.invokeAll(java.util.Collections.nCopies(32, claim)).stream().filter(future -> {
                try {
                    return future.get();
                } catch (Exception ex) {
                    throw new IllegalStateException(ex);
                }
            }).count();
            assertEquals(1L, winners);
            assertTrue(store.tryClaimSign(second, 0L, Duration.ofSeconds(30)).isPresent());
        }
    }

    @Test
    void concurrentWatermarkWritesNeverRegressAcrossRestart(@TempDir Path root) throws Exception {
        Instant base = Instant.parse("2026-01-02T03:04:05.123Z");
        Instant high = base.plusSeconds(60);
        MutableClock clock = new MutableClock(base);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock);
                ExecutorService executor = Executors.newFixedThreadPool(2)) {
            clock.arm(high);
            Future<Instant> highRead = executor.submit(store::signingNow);
            assertTrue(clock.observed.await(5, TimeUnit.SECONDS));
            clock.set(base.minusSeconds(60));
            Future<Instant> rollbackRead = executor.submit(store::signingNow);
            clock.release.countDown();
            assertEquals(high, highRead.get(5, TimeUnit.SECONDS));
            assertEquals(high, rollbackRead.get(5, TimeUnit.SECONDS));
            persistIntent(store, base, 77);
        }
        clock.set(base.minusSeconds(120));
        try (FilesystemPkiStore restarted = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            assertEquals(high, restarted.signingNow());
        }
    }

    @Test
    void repeatedSigningReadsAppendAndForceNothing(@TempDir Path root) throws Exception {
        Instant now = Instant.parse("2026-01-02T03:04:05.123Z");
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), Clock.fixed(now, java.time.ZoneOffset.UTC))) {
            SigningActiveWal.Snapshot before = store.localSigningWriterSnapshot();
            for (int index = 0; index < 100; index++) {
                assertEquals(now, store.signingNow());
                PkiId unknown = SigningSubmissionId.create(
                        store.localSigningNamespace("zeroecho-lib"), now, new SecureRandom()).id();
                store.localSignStatus(unknown);
            }
            SigningActiveWal.Snapshot after = store.localSigningWriterSnapshot();
            assertEquals(before.bytesAppended(), after.bytesAppended());
            assertEquals(before.forces(), after.forces());
        }
    }

    @Test
    void cancellingStateUsesStableCodeAndSurvivesRestart(@TempDir Path root) throws Exception {
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        MutableClock clock = new MutableClock(createdAt);
        PkiId id;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            String namespace = store.signingNamespace() + ".test-signer";
            id = SigningSubmissionId.create(namespace, createdAt, new SecureRandom()).id();
            store.createSignIntent(
                    intent(store, id, createdAt, new EncodedObject(Encoding.BINARY, new byte[] { 8 }), TEST_ALGORITHM));
            SignWorkflowStore.Record claimed = store.tryClaimSign(id, 0L, Duration.ofSeconds(30)).orElseThrow();
            SignWorkflowStore.Record dispatched = store.transitionSign(id, claimed.revision(), claimed.fence(),
                    SignWorkflowStore.State.DISPATCHED, Optional.of("DISPATCHED"), Optional.empty(), Optional.empty())
                    .orElseThrow();
            store.transitionSign(id, dispatched.revision(), dispatched.fence(), SignWorkflowStore.State.CANCELLING,
                    Optional.of("CANCEL_REQUESTED"), Optional.empty(), Optional.empty()).orElseThrow();
            assertEquals(30, SignWorkflowStore.State.CANCELLING.persistentCode());
            assertThrows(IllegalArgumentException.class, () -> SignWorkflowStore.State.fromPersistentCode(999));
        }
        try (FilesystemPkiStore restarted = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            assertEquals(SignWorkflowStore.State.CANCELLING, restarted.getSignRecord(id).orElseThrow().state());
        }
    }

    @Test
    void everyCurrentSigningStateSurvivesSemanticValidationOnRestart(@TempDir Path root) throws Exception {
        System.out.println("everyCurrentSigningStateSurvivesSemanticValidationOnRestart");
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        MutableClock clock = new MutableClock(createdAt);
        java.util.LinkedHashMap<PkiId, SignWorkflowStore.State> expected = new java.util.LinkedHashMap<>();
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            expected.put(persistIntent(store, createdAt, 1), SignWorkflowStore.State.INTENT);

            PkiId claimedId = persistIntent(store, createdAt, 2);
            store.tryClaimSign(claimedId, 0L, Duration.ofSeconds(30)).orElseThrow();
            expected.put(claimedId, SignWorkflowStore.State.INTENT);

            PkiId dispatchedId = persistDispatched(store, createdAt, 3);
            expected.put(dispatchedId, SignWorkflowStore.State.DISPATCHED);

            PkiId cancellingId = persistDispatched(store, createdAt, 4);
            SignWorkflowStore.Record cancellingSource = store.getSignRecord(cancellingId).orElseThrow();
            store.transitionSign(cancellingId, cancellingSource.revision(), cancellingSource.fence(),
                    SignWorkflowStore.State.CANCELLING, Optional.of("CANCEL_REQUESTED"), Optional.empty(),
                    Optional.empty()).orElseThrow();
            expected.put(cancellingId, SignWorkflowStore.State.CANCELLING);

            PkiId succeededId = persistDispatched(store, createdAt, 5);
            SignWorkflowStore.Record successSource = store.getSignRecord(succeededId).orElseThrow();
            store.transitionSign(succeededId, successSource.revision(), successSource.fence(),
                    SignWorkflowStore.State.SUCCEEDED, Optional.of("SIGNED"),
                    Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 5 })),
                    Optional.of(createdAt.plusSeconds(1))).orElseThrow();
            expected.put(succeededId, SignWorkflowStore.State.SUCCEEDED);

            PkiId failedId = persistClaimed(store, createdAt, 6);
            SignWorkflowStore.Record failureSource = store.getSignRecord(failedId).orElseThrow();
            store.transitionSign(failedId, failureSource.revision(), failureSource.fence(),
                    SignWorkflowStore.State.FAILED, Optional.of("PROVIDER_SUBMISSION_FAILED"), Optional.empty(),
                    Optional.empty()).orElseThrow();
            expected.put(failedId, SignWorkflowStore.State.FAILED);

            PkiId cancelledId = persistIntent(store, createdAt, 7);
            SignWorkflowStore.Record cancelSource = store.getSignRecord(cancelledId).orElseThrow();
            SignWorkflowStore.Record cancelling = store.transitionSign(cancelledId, cancelSource.revision(),
                    cancelSource.fence(), SignWorkflowStore.State.CANCELLING, Optional.of("CANCEL_REQUESTED"),
                    Optional.empty(), Optional.empty()).orElseThrow();
            store.transitionSign(cancelledId, cancelling.revision(), cancelling.fence(),
                    SignWorkflowStore.State.CANCELLED, Optional.of("CANCELLED"), Optional.empty(),
                    Optional.of(createdAt.plusSeconds(1)))
                    .orElseThrow();
            expected.put(cancelledId, SignWorkflowStore.State.CANCELLED);

            PkiId expiredId = persistIntent(store, createdAt, 8);
            SignWorkflowStore.Record expirySource = store.getSignRecord(expiredId).orElseThrow();
            store.transitionSign(expiredId, expirySource.revision(), expirySource.fence(),
                    SignWorkflowStore.State.EXPIRED, Optional.of("EXPIRED"), Optional.empty(), Optional.empty())
                    .orElseThrow();
            expected.put(expiredId, SignWorkflowStore.State.EXPIRED);

            PkiId retiredId = persistDispatched(store, createdAt, 9);
            SignWorkflowStore.Record retiredSuccessSource = store.getSignRecord(retiredId).orElseThrow();
            SignWorkflowStore.Record retiredSuccess = store.transitionSign(retiredId, retiredSuccessSource.revision(),
                    retiredSuccessSource.fence(), SignWorkflowStore.State.SUCCEEDED, Optional.of("SIGNED"),
                    Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 9 })),
                    Optional.of(createdAt.plusSeconds(1))).orElseThrow();
            store.retireSign(retiredId, retiredSuccess.revision(), retiredSuccess.fence()).orElseThrow();
            expected.put(retiredId, SignWorkflowStore.State.RETIRED);
        }

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            for (Map.Entry<PkiId, SignWorkflowStore.State> entry : expected.entrySet()) {
                SignWorkflowStore.Record restored = reopened.getSignRecord(entry.getKey()).orElseThrow();
                System.out.println("...state=" + restored.state());
                assertEquals(entry.getValue(), restored.state());
                if (restored.state() == SignWorkflowStore.State.SUCCEEDED
                        || restored.state() == SignWorkflowStore.State.RETIRED) {
                    assertTrue(restored.result().isPresent());
                }
            }
        }
        System.out.println("...ok");
    }

    @Test
    void sharedSigningContentSurvivesRestartUntilLastCompositeOwnerExpires(
            @TempDir Path root) throws Exception {
        Instant createdAt = Instant.parse("2026-08-30T12:00:00.123Z");
        MutableClock clock = new MutableClock(createdAt);
        DurableContentReference reference;
        PkiId first;
        PkiId second;
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), clock)) {
            reference = operationReference(store, new byte[] { 3, 1, 4, 1, 5 });
            first = createIntentForReference(store, createdAt, reference);
            second = createIntentForReference(store, createdAt, reference);
        }

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), clock)) {
            assertEquals(SignWorkflowStore.State.INTENT,
                    reopened.getSignRecord(first).orElseThrow().state());
            assertEquals(SignWorkflowStore.State.INTENT,
                    reopened.getSignRecord(second).orElseThrow().state());
            clock.set(createdAt.plusSeconds(60L));

            assertEquals(SignWorkflowStore.State.EXPIRED,
                    reopened.getSignRecord(first).orElseThrow().state());
            try (RepeatableContent stillOwned = reopened.stagedContent().openContent(reference)) {
                assertEquals(reference.length(), stillOwned.length().orElseThrow());
            }
            assertEquals(SignWorkflowStore.State.EXPIRED,
                    reopened.getSignRecord(second).orElseThrow().state());
            assertThrows(java.io.IOException.class,
                    () -> reopened.stagedContent().openContent(reference));
        }
    }

    @Test
    void exactSigningReadIgnoresUnrelatedMalformedOwnerAndDetectsItsStaleMembership(
            @TempDir Path root) throws Exception {
        Instant createdAt = Instant.parse("2026-08-30T12:00:00.123Z");
        MutableClock clock = new MutableClock(createdAt);
        PkiId validId;
        PkiId staleId;
        MetadataKey staleOwner;
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), clock)) {
            DurableContentReference valid = operationReference(store, new byte[] { 1, 2, 3 });
            validId = createIntentForReference(store, createdAt, valid);
            DurableContentReference unrelated = operationReference(store, new byte[] { 9, 8, 7 });
            staleId = SigningSubmissionId.create(
                    store.signingNamespace() + ".test-signer", createdAt,
                    new SecureRandom()).id();
            staleOwner = SigningOwnerKey.exact(unrelated, staleId);
        }
        createRawMetadata(root, staleOwner, new byte[] { 1 });

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), clock)) {
            assertEquals(SignWorkflowStore.State.INTENT,
                    reopened.getSignRecord(validId).orElseThrow().state());
            assertThrows(IllegalStateException.class,
                    () -> reopened.getSignRecord(staleId));
        }
    }

    @Test
    void matchingMalformedCompositeOwnerFailsClosedAfterRestart(@TempDir Path root)
            throws Exception {
        Instant createdAt = Instant.parse("2026-08-30T12:00:00.123Z");
        MutableClock clock = new MutableClock(createdAt);
        PkiId id;
        MetadataKey ownerKey;
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), clock)) {
            DurableContentReference reference = operationReference(store, new byte[] { 2, 7, 1, 8 });
            id = createIntentForReference(store, createdAt, reference);
            ownerKey = SigningOwnerKey.exact(reference, id);
        }
        recreateRawMetadata(root, ownerKey, new byte[] { 1 });

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), clock)) {
            assertThrows(IllegalStateException.class, () -> reopened.getSignRecord(id));
        }
    }

    private static PkiId createIntentForReference(FilesystemPkiStore store,
            Instant createdAt, DurableContentReference reference) {
        String namespace = store.signingNamespace() + ".test-signer";
        PkiId id = SigningSubmissionId.create(namespace, createdAt, new SecureRandom()).id();
        PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(
                TEST_ACCESS, TEST_ALGORITHM, reference, TEST_KEY, Encoding.BINARY,
                Optional.of(id));
        Instant deadline = createdAt.plusSeconds(60L);
        SignatureWorkflow.ConfigurationCommitment commitment = testConfigurationCommitment();
        SignWorkflowStore.Record record = new SignWorkflowStore.Record(id, namespace,
                continuation.semanticFingerprint(commitment, namespace, deadline), commitment,
                TEST_OWNER, createdAt, deadline, continuation.encode(),
                SignWorkflowStore.State.INTENT, 0L, 0L, Optional.empty(),
                Optional.of("INTENT"), Optional.empty(), Optional.empty(), 0,
                Optional.empty(), Optional.empty());
        assertEquals(SignWorkflowStore.CreateResult.CREATED, store.createSignIntent(record));
        return id;
    }

    private static void createRawMetadata(Path root, MetadataKey key, byte[] value)
            throws Exception {
        try (SegmentedTransactionalMetadataStore metadata =
                SegmentedTransactionalMetadataStore.open(
                        new FsPaths(root).transactionalMetadataRoot())) {
            SigningTransactionPayloadCodec.Mutation mutation =
                    new SigningTransactionPayloadCodec.Mutation(
                            SigningTransactionPayloadCodec.MutationKind.CREATE,
                            key, -1L, value);
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    metadata.directCommit(List.of(mutation)).outcome());
        }
    }

    private static void recreateRawMetadata(Path root, MetadataKey key, byte[] value)
            throws Exception {
        try (SegmentedTransactionalMetadataStore metadata =
                SegmentedTransactionalMetadataStore.open(
                        new FsPaths(root).transactionalMetadataRoot());
                MetadataSnapshot snapshot = metadata.snapshot()) {
            long revision;
            try (MetadataSnapshot.Record current = snapshot.get(key).orElseThrow()) {
                revision = current.recordRevision();
            }
            SigningTransactionPayloadCodec.Mutation delete =
                    new SigningTransactionPayloadCodec.Mutation(
                            SigningTransactionPayloadCodec.MutationKind.DELETE,
                            key, revision, null);
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    metadata.directCommit(List.of(delete)).outcome());
            SigningTransactionPayloadCodec.Mutation create =
                    new SigningTransactionPayloadCodec.Mutation(
                            SigningTransactionPayloadCodec.MutationKind.CREATE,
                            key, -1L, value);
            assertEquals(MetadataCommitResult.Outcome.COMMITTED,
                    metadata.directCommit(List.of(create)).outcome());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = { "INITIAL_INTENT", "FENCED_INTENT", "DISPATCHED", "CANCELLING" })
    void exactDeadlineAtomicallyExpiresEveryActiveStateAndReclaimsContent(String sourceState,
            @TempDir Path root) throws Exception {
        Instant createdAt = Instant.parse("2026-08-14T12:00:00.123Z");
        MutableClock clock = new MutableClock(createdAt);
        PkiId id;
        DurableContentReference reference;
        long expectedRevision;
        long expectedFence;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            String namespace = store.signingNamespace() + ".test-signer";
            id = SigningSubmissionId.create(namespace, createdAt, new SecureRandom()).id();
            reference = operationReference(store, new byte[] { (byte) sourceState.hashCode() });
            PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(TEST_ACCESS,
                    TEST_ALGORITHM, reference, TEST_KEY, Encoding.BINARY, Optional.of(id));
            SignatureWorkflow.ConfigurationCommitment commitment = testConfigurationCommitment();
            Instant deadline = createdAt.plusSeconds(60L);
            SignWorkflowStore.Record initial = new SignWorkflowStore.Record(id, namespace,
                    continuation.semanticFingerprint(commitment, namespace, deadline), commitment, TEST_OWNER,
                    createdAt, deadline, continuation.encode(), SignWorkflowStore.State.INTENT, 0L, 0L,
                    Optional.empty(), Optional.of("INTENT"), Optional.empty(), Optional.empty(), 0,
                    Optional.empty(), Optional.empty());
            assertEquals(SignWorkflowStore.CreateResult.CREATED, store.createSignIntent(initial));
            if (!"INITIAL_INTENT".equals(sourceState)) {
                SignWorkflowStore.Record intent = store.getSignRecord(id).orElseThrow();
                store.tryClaimSign(id, intent.revision(), Duration.ofSeconds(30)).orElseThrow();
            }
            if ("DISPATCHED".equals(sourceState) || "CANCELLING".equals(sourceState)) {
                SignWorkflowStore.Record claimed = store.getSignRecord(id).orElseThrow();
                store.transitionSign(id, claimed.revision(), claimed.fence(), SignWorkflowStore.State.DISPATCHED,
                        Optional.of("DISPATCHED"), Optional.empty(), Optional.empty()).orElseThrow();
            }
            if ("CANCELLING".equals(sourceState)) {
                SignWorkflowStore.Record dispatched = store.getSignRecord(id).orElseThrow();
                store.transitionSign(id, dispatched.revision(), dispatched.fence(),
                        SignWorkflowStore.State.CANCELLING, Optional.of("CANCEL_REQUESTED"), Optional.empty(),
                        Optional.empty()).orElseThrow();
            }
            SignWorkflowStore.Record before = store.getSignRecord(id).orElseThrow();
            expectedRevision = before.revision() + 1L;
            expectedFence = before.fence();

            clock.set(before.deadline().minusMillis(1L));
            assertEquals(before.state(), store.getSignRecord(id).orElseThrow().state());
            try (RepeatableContent content = store.stagedContent().openContent(reference)) {
                assertEquals(reference.length(), content.length().orElseThrow());
            }

            clock.set(before.deadline());
            SignWorkflowStore.Record expired = store.getSignRecord(id).orElseThrow();
            assertEquals(SignWorkflowStore.State.EXPIRED, expired.state());
            assertEquals(expectedRevision, expired.revision());
            assertEquals(expectedFence, expired.fence());
            assertEquals(Optional.of("EXPIRED"), expired.detailCode());
            assertTrue(expired.leaseUntil().isEmpty());
            assertTrue(expired.result().isEmpty());
            assertTrue(expired.providerUpdatedAt().isEmpty());
            assertEquals(0, expired.failureCount());
            assertTrue(expired.nextEligibleAt().isEmpty());
            assertTrue(expired.reconciliationFailureClass().isEmpty());
            assertFalse(PkiSigningBus.SignContinuation.decode(
                    expired.request(), store.stagedContent()).hasLiveContent());
            assertThrows(java.io.IOException.class, () -> store.stagedContent().openContent(reference));
            assertTrue(store.selectDueSignRecords(clock.instant(), 16).isEmpty());
            assertEquals(SignWorkflowStore.State.EXPIRED,
                    store.retireSign(id, expired.revision(), expired.fence()).orElseThrow().state());
        }

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            assertEquals(SignWorkflowStore.State.EXPIRED, reopened.getSignRecord(id).orElseThrow().state());
            assertThrows(java.io.IOException.class, () -> reopened.stagedContent().openContent(reference));
        }
    }

    @Test
    void cancellationAcknowledgedBeforeDeadlineRemainsCancelled(@TempDir Path root) {
        Instant createdAt = Instant.parse("2026-08-14T12:00:00.123Z");
        MutableClock clock = new MutableClock(createdAt);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            PkiId id = persistIntent(store, createdAt, 77);
            SignWorkflowStore.Record intent = store.getSignRecord(id).orElseThrow();
            SignWorkflowStore.Record cancelling = store.transitionSign(id, intent.revision(), intent.fence(),
                    SignWorkflowStore.State.CANCELLING, Optional.of("CANCEL_REQUESTED"), Optional.empty(),
                    Optional.empty()).orElseThrow();
            SignWorkflowStore.Record cancelled = store.transitionSign(id, cancelling.revision(), cancelling.fence(),
                    SignWorkflowStore.State.CANCELLED, Optional.of("CANCELLED"), Optional.empty(),
                    Optional.of(createdAt.plusSeconds(1)))
                    .orElseThrow();

            clock.set(cancelled.deadline());
            SignWorkflowStore.Record retained = store.getSignRecord(id).orElseThrow();
            assertEquals(SignWorkflowStore.State.CANCELLED, retained.state());
            assertEquals(cancelled.revision(), retained.revision());
        } catch (java.io.IOException failure) {
            throw new AssertionError(failure);
        }
    }

    @ParameterizedTest
    @MethodSource("terminalAdmissionTargets")
    void terminalTransitionCrossingDeadlineAtWalAdmissionBecomesExpired(
            SignWorkflowStore.State target, @TempDir Path root) throws Exception {
        Instant createdAt = Instant.parse("2026-08-14T12:00:00.123Z");
        MutableClock clock = new MutableClock(createdAt);
        CountDownLatch admissionEntered = new CountDownLatch(1);
        CountDownLatch admit = new CountDownLatch(1);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock);
                ExecutorService executor = Executors.newSingleThreadExecutor()) {
            PkiId id = persistDispatched(store, createdAt, 78 + target.ordinal());
            SignWorkflowStore.Record source = store.getSignRecord(id).orElseThrow();
            if (target == SignWorkflowStore.State.CANCELLED) {
                source = store.transitionSign(id, source.revision(), source.fence(),
                        SignWorkflowStore.State.CANCELLING, Optional.of("CANCEL_REQUESTED"), Optional.empty(),
                        Optional.empty()).orElseThrow();
            }
            SignWorkflowStore.Record transitionSource = source;
            Optional<EncodedObject> result = target == SignWorkflowStore.State.SUCCEEDED
                    ? Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 9 })) : Optional.empty();
            Future<Optional<SignWorkflowStore.Record>> transition = executor.submit(() -> {
                FilesystemPkiStore.installSignTransitionAdmissionObserver(() -> {
                    admissionEntered.countDown();
                    try {
                        if (!admit.await(5L, TimeUnit.SECONDS)) {
                            throw new IllegalStateException("Timed out awaiting WAL admission release");
                        }
                    } catch (InterruptedException failure) {
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException("WAL admission wait was interrupted", failure);
                    }
                });
                try {
                    return store.transitionSign(id, transitionSource.revision(), transitionSource.fence(), target,
                            Optional.of(target.name()), result,
                            Optional.of(transitionSource.deadline().minusMillis(1L)));
                } finally {
                    FilesystemPkiStore.clearSignTransitionAdmissionObserver();
                }
            });
            assertTrue(admissionEntered.await(5L, TimeUnit.SECONDS));

            clock.set(transitionSource.deadline());
            admit.countDown();

            SignWorkflowStore.Record expired = transition.get(5L, TimeUnit.SECONDS).orElseThrow();
            assertEquals(SignWorkflowStore.State.EXPIRED, expired.state());
            assertEquals(transitionSource.revision() + 1L, expired.revision());
            assertEquals(transitionSource.fence(), expired.fence());
            assertTrue(expired.result().isEmpty());
            assertTrue(expired.providerUpdatedAt().isEmpty());
            assertFalse(PkiSigningBus.SignContinuation.decode(
                    expired.request(), store.stagedContent()).hasLiveContent());
        } finally {
            admit.countDown();
        }
    }

    @Test
    void cancelledTransitionRequiresStrictlyOnTimeAcknowledgement(@TempDir Path root) throws Exception {
        Instant createdAt = Instant.parse("2026-08-14T12:00:00.123Z");
        MutableClock clock = new MutableClock(createdAt);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            PkiId id = persistDispatched(store, createdAt, 91);
            SignWorkflowStore.Record dispatched = store.getSignRecord(id).orElseThrow();
            SignWorkflowStore.Record cancelling = store.transitionSign(id, dispatched.revision(), dispatched.fence(),
                    SignWorkflowStore.State.CANCELLING, Optional.of("CANCEL_REQUESTED"), Optional.empty(),
                    Optional.empty()).orElseThrow();

            assertThrows(IllegalArgumentException.class, () -> store.transitionSign(id, cancelling.revision(),
                    cancelling.fence(), SignWorkflowStore.State.CANCELLED, Optional.of("CANCELLED"),
                    Optional.empty(), Optional.empty()));
            assertThrows(IllegalArgumentException.class, () -> store.transitionSign(id, cancelling.revision(),
                    cancelling.fence(), SignWorkflowStore.State.CANCELLED, Optional.of("CANCELLED"),
                    Optional.empty(), Optional.of(cancelling.deadline())));
        }
    }

    @Test
    void deadlineCommitSignalsAdmittedLocalExecutionAfterDurability(@TempDir Path root) throws Exception {
        Instant createdAt = Instant.parse("2026-08-14T12:00:00.123Z");
        MutableClock clock = new MutableClock(createdAt);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            LocalAttempt attempt = localAttempt(store, createdAt);
            AtomicLocalSigningLedgerParticipant.AtomicAcceptance acceptance;
            try (SignWorkflowStore.SignAdmission admission = store.reserveSignAdmission(attempt.id())) {
                acceptance = store.acceptLocalSign(admission, attempt.request(),
                        attempt.request().configurationCommitment(), attempt.intent(), attempt.reference());
            }
            zeroecho.core.io.CancellationSignal cancellation = acceptance.executionPermit().orElseThrow()
                    .consume(store, attempt.request(), attempt.request().configurationCommitment()).orElseThrow();
            assertFalse(cancellation.isCancelled());

            clock.set(attempt.intent().deadline());
            assertEquals(SignWorkflowStore.State.EXPIRED,
                    store.getSignRecord(attempt.id()).orElseThrow().state());
            assertTrue(cancellation.isCancelled());
            assertThrows(java.io.IOException.class,
                    () -> store.stagedContent().openContent(attempt.reference()));
        }
    }

    @Test
    void semanticCorruptionCannotActivateRecoverOrExposeInjectedResult(@TempDir Path root) throws Exception {
        System.out.println("semanticCorruptionCannotActivateRecoverOrExposeInjectedResult");
        List<CorruptionCase> cases = List.of(
                new CorruptionCase("request-changed",
                        (record, store) -> copy(record,
                                request(store, record.submissionId(), new byte[] { 99 }, TEST_ALGORITHM),
                                record.fingerprint(), record.state(), record.revision(), record.fence(),
                                record.leaseUntil(), record.detailCode(), record.result(), record.providerUpdatedAt()),
                        "FINGERPRINT_MISMATCH"),
                new CorruptionCase("fingerprint-changed",
                        (record, store) -> copy(record, record.request(), flipFingerprint(record.fingerprint()), record.state(),
                                record.revision(), record.fence(), record.leaseUntil(), record.detailCode(),
                                record.result(), record.providerUpdatedAt()),
                        "FINGERPRINT_MISMATCH"),
                new CorruptionCase("configuration-commitment-changed",
                        (record, store) -> withConfigurationCommitment(record,
                                changedConfigurationCommitment(record.configurationCommitment())),
                        "FINGERPRINT_MISMATCH"),
                new CorruptionCase("fingerprint-length",
                        (record, store) -> copy(record, record.request(), "signfp:v2:00", record.state(), record.revision(),
                                record.fence(), record.leaseUntil(), record.detailCode(), record.result(),
                                record.providerUpdatedAt()),
                        "FINGERPRINT_FORMAT_INVALID"),
                new CorruptionCase("success-no-result",
                        (record, store) -> copy(record, record.request(), record.fingerprint(), record.state(),
                                record.revision(), record.fence(), record.leaseUntil(), record.detailCode(),
                                Optional.empty(), record.providerUpdatedAt()),
                        "SUCCESS_EVIDENCE_MISSING"),
                new CorruptionCase("success-no-provider-time",
                        (record, store) -> copy(record, record.request(), record.fingerprint(), record.state(),
                                record.revision(), record.fence(), record.leaseUntil(), record.detailCode(),
                                record.result(), Optional.empty()),
                        "SUCCESS_EVIDENCE_MISSING"),
                new CorruptionCase("success-at-deadline",
                        (record, store) -> copy(record, record.request(), record.fingerprint(), record.state(),
                                record.revision(), record.fence(), record.leaseUntil(), record.detailCode(),
                                record.result(), Optional.of(record.deadline())),
                        "PROVIDER_TIME_INVALID"),
                new CorruptionCase("success-after-deadline",
                        (record, store) -> copy(record, record.request(), record.fingerprint(), record.state(),
                                record.revision(), record.fence(), record.leaseUntil(), record.detailCode(),
                                record.result(), Optional.of(record.deadline().plusNanos(1))),
                        "PROVIDER_TIME_INVALID"),
                new CorruptionCase("success-active-lease",
                        (record, store) -> copy(record, record.request(), record.fingerprint(), record.state(),
                                record.revision(), record.fence(), Optional.of(record.createdAt().plusSeconds(30)),
                                record.detailCode(), record.result(), record.providerUpdatedAt()),
                        "SUCCESS_EVIDENCE_MISSING"),
                new CorruptionCase("success-expiry-code",
                        (record, store) -> copy(record, record.request(), record.fingerprint(), record.state(),
                                record.revision(), record.fence(), record.leaseUntil(), Optional.of("EXPIRED"),
                                record.result(), record.providerUpdatedAt()),
                        "SUCCESS_DETAIL_CONTRADICTORY"),
                new CorruptionCase("success-stale-fence",
                        (record, store) -> copy(record, record.request(), record.fingerprint(), record.state(),
                                record.revision(), record.revision(), record.leaseUntil(), record.detailCode(),
                                record.result(), record.providerUpdatedAt()),
                        "SUCCESS_REVISION_INVALID"),
                new CorruptionCase("injected-result-fingerprint-mismatch",
                        (record, store) -> copy(record, record.request(), flipFingerprint(record.fingerprint()), record.state(),
                                record.revision(), record.fence(), record.leaseUntil(), record.detailCode(),
                                Optional.of(new EncodedObject(Encoding.BINARY,
                                        "injected-signature".getBytes(java.nio.charset.StandardCharsets.UTF_8))),
                                record.providerUpdatedAt()),
                        "FINGERPRINT_MISMATCH"),
                new CorruptionCase("failed-with-result",
                        (record, store) -> copy(record, record.request(), record.fingerprint(), SignWorkflowStore.State.FAILED,
                                record.revision(), record.fence(), record.leaseUntil(), Optional.of("FAILED"),
                                record.result(), record.providerUpdatedAt()),
                        "FAILURE_RESULT_OR_LEASE_PRESENT"),
                new CorruptionCase("claim-without-lease",
                        (record, store) -> copy(record, record.request(), record.fingerprint(), SignWorkflowStore.State.INTENT,
                                1L, 1L, Optional.empty(), Optional.of("INTENT"), Optional.empty(), Optional.empty()),
                        "INTENT_CLAIM_INVALID"),
                new CorruptionCase("terminal-with-lease",
                        (record, store) -> copy(record, record.request(), record.fingerprint(), record.state(),
                                record.revision(), record.fence(), Optional.of(record.createdAt().plusSeconds(30)),
                                record.detailCode(), record.result(), record.providerUpdatedAt()),
                        "SUCCESS_EVIDENCE_MISSING"),
                new CorruptionCase("lease-before-creation",
                        (record, store) -> copy(record, record.request(), record.fingerprint(), SignWorkflowStore.State.INTENT,
                                1L, 1L, Optional.of(record.createdAt().minusNanos(1)), Optional.of("INTENT"),
                                Optional.empty(), Optional.empty()),
                        "LEASE_TIME_INVALID"),
                new CorruptionCase("dispatched-zero-fence",
                        (record, store) -> copy(record, record.request(), record.fingerprint(),
                                SignWorkflowStore.State.DISPATCHED, 1L, 0L, Optional.empty(), Optional.of("DISPATCHED"),
                                Optional.empty(), Optional.empty()),
                        "DISPATCH_REVISION_INVALID"));

        int index = 0;
        for (CorruptionCase corruption : cases) {
            Path caseRoot = root.resolve("case-" + index++);
            assertSemanticCorruptionRejected(caseRoot, corruption);
            System.out.println("...case=" + corruption.name());
        }
        System.out.println("...ok");
    }

    @Test
    void signingPagesAndRetryBackoffAreBoundedAndRestartSafe(@TempDir Path root) throws Exception {
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        MutableClock clock = new MutableClock(createdAt);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            PkiId first = persistIntent(store, createdAt, 1);
            PkiId second = persistIntent(store, createdAt, 2);
            PkiId third = persistIntent(store, createdAt, 3);
            List<String> expected = java.util.stream.Stream.of(first, second, third).map(PkiId::value).sorted().toList();

            SignWorkflowStore.Page pageOne = store.pageSignRecords(Optional.empty(), 2, CancellationSignal.NONE);
            assertEquals(expected.subList(0, 2), pageOne.records().stream()
                    .map(record -> record.submissionId().value()).toList());
            assertFalse(pageOne.endReached());
            SignWorkflowStore.Page pageTwo = store.pageSignRecords(pageOne.nextCursor(), 2, CancellationSignal.NONE);
            assertEquals(List.of(expected.get(2)), pageTwo.records().stream()
                    .map(record -> record.submissionId().value()).toList());
            assertTrue(pageTwo.endReached());
            SignWorkflowStore.Page maximumCursor = store.pageSignRecords(Optional.of("~".repeat(4096)), 1,
                    CancellationSignal.NONE);
            assertEquals(0, maximumCursor.examined());
            assertTrue(maximumCursor.endReached());

            SignWorkflowStore.Record retry = store.tryClaimSign(first, 0L, Duration.ofSeconds(30)).orElseThrow();
            long[] delays = { 2L, 4L, 8L, 16L, 30L, 30L };
            for (int index = 0; index < delays.length; index++) {
                Instant deferredAt = clock.instant();
                retry = store.deferSignReconciliation(first, retry.revision(), retry.fence(),
                        SignWorkflowStore.ReconciliationFailureClass.SUBMISSION_UNCERTAIN).orElseThrow();
                assertEquals(index + 1, retry.failureCount());
                assertEquals(deferredAt.plusSeconds(delays[index]), retry.nextEligibleAt().orElseThrow());
                clock.set(deferredAt.plusSeconds(1));
            }
            retry = store.clearSignReconciliation(first, retry.revision(), retry.fence()).orElseThrow();
            assertEquals(0, retry.failureCount());
            assertEquals(Optional.empty(), retry.nextEligibleAt());
        }
    }

    @Test
    void signedDomainPublicationRetryRemainsFutureDatedBeyondRetentionHorizon(@TempDir Path root)
            throws Exception {
        Instant createdAt = Instant.parse("2026-08-20T10:00:00Z");
        MutableClock clock = new MutableClock(createdAt);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            PkiId operationId = persistPublishingSuccess(store, createdAt);
            Instant beyondHorizon = createdAt.plus(store.signingHorizon()).plusSeconds(5L);
            clock.set(beyondHorizon);
            SignWorkflowStore.Record succeeded = store.getSignRecord(operationId).orElseThrow();

            SignWorkflowStore.Record deferred = store.deferSignReconciliation(operationId,
                    succeeded.revision(), succeeded.fence(),
                    SignWorkflowStore.ReconciliationFailureClass.LOCAL_FAILURE).orElseThrow();

            assertEquals(beyondHorizon.plusSeconds(2L), deferred.nextEligibleAt().orElseThrow());
            assertTrue(store.pageDueSignRecords(beyondHorizon, Optional.empty(), Optional.empty(), 1,
                    CancellationSignal.NONE).records().isEmpty());
            clock.set(beyondHorizon.plusSeconds(2L));
            assertEquals(List.of(operationId), store.pageDueSignRecords(clock.instant(), Optional.empty(),
                    Optional.empty(), 1, CancellationSignal.NONE).records().stream()
                    .map(SignWorkflowStore.Record::submissionId).toList());
            assertEquals(DomainContinuationStore.State.PUBLISHING,
                    store.getDomainContinuation(operationId).orElseThrow().state());
        }
    }

    @Test
    void dueSelectionIsEligibilityOrderedBoundedAndRestartSafe(@TempDir Path root)
            throws Exception {
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        MutableClock clock = new MutableClock(createdAt);
        PkiId deferred;
        PkiId immediate;
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), clock)) {
            deferred = persistIntent(store, createdAt, 41);
            immediate = persistIntent(store, createdAt, 42);
            SignWorkflowStore.Record claimed = store.tryClaimSign(
                    deferred, 0L, Duration.ofSeconds(30)).orElseThrow();
            store.deferSignReconciliation(deferred, claimed.revision(), claimed.fence(),
                    SignWorkflowStore.ReconciliationFailureClass.STATUS_UNAVAILABLE).orElseThrow();
            assertEquals(List.of(immediate), store.selectDueSignRecords(clock.instant(), 1)
                    .stream().map(SignWorkflowStore.Record::submissionId).toList());
            SignWorkflowStore.Page due = store.pageDueSignRecords(clock.instant(),
                    Optional.empty(), Optional.empty(), 1, CancellationSignal.NONE);
            assertEquals(List.of(immediate), due.records().stream()
                    .map(SignWorkflowStore.Record::submissionId).toList());
            assertTrue(due.endReached());
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), clock)) {
            assertEquals(List.of(immediate), reopened.selectDueSignRecords(clock.instant(), 1)
                    .stream().map(SignWorkflowStore.Record::submissionId).toList());
            clock.set(clock.instant().plusSeconds(2));
            assertEquals(2, reopened.selectDueSignRecords(clock.instant(), 2).size());
        }
    }

    @Test
    void malformedCandidateIsRejectedOnAccessWithoutMutatingTheRoot(@TempDir Path root) throws Exception {
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        List<String> ordered;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(),
                Clock.fixed(createdAt, java.time.ZoneOffset.UTC))) {
            ordered = java.util.stream.Stream.of(
                    persistIntent(store, createdAt, 1),
                    persistIntent(store, createdAt, 2),
                    persistIntent(store, createdAt, 3))
                    .map(PkiId::value).sorted().toList();
        }

        Path metadataLog = root.resolve("metadata");
        MetadataKey malformed = new MetadataKey("io.zeroecho.pki.signing-record", ordered.get(0));
        try (SegmentedTransactionalMetadataStore metadata = SegmentedTransactionalMetadataStore.open(metadataLog);
                MetadataSnapshot snapshot = metadata.snapshot()) {
            long revision;
            try (MetadataSnapshot.Record record = snapshot.get(malformed).orElseThrow()) {
                revision = record.recordRevision();
            }
            try (MetadataTransaction transaction = metadata.beginTransaction()) {
                transaction.replace(malformed, revision, new ImmutableByteContent(new byte[] { 1, 2, 3 }),
                        CancellationSignal.NONE);
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
            }
        }
        List<String> beforeRecovery = rootFileState(root);

        IllegalStateException failure;
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(),
                Clock.fixed(createdAt, java.time.ZoneOffset.UTC))) {
            failure = assertThrows(IllegalStateException.class,
                    () -> reopened.getSignRecord(new PkiId(ordered.get(0))));
        }
        assertTrue(failure.getMessage().contains("code=INVALID_CURRENT_PAYLOAD"));
        assertFalse(failure.toString().contains(ordered.get(0)));
        assertEquals(beforeRecovery, rootFileState(root));
    }

    @Test
    void farFutureRetryEligibilityIsRejectedAsCorruptOnAccess(@TempDir Path root) throws Exception {
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        MutableClock clock = new MutableClock(createdAt);
        PkiId id;
        SignWorkflowStore.Record corrupted;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            id = persistClaimed(store, createdAt, 4);
            SignWorkflowStore.Record claimed = store.getSignRecord(id).orElseThrow();
            corrupted = new SignWorkflowStore.Record(claimed.submissionId(), claimed.namespace(),
                    claimed.fingerprint(), claimed.configurationCommitment(), claimed.owner(), claimed.createdAt(),
                    claimed.deadline(), claimed.request(),
                    claimed.state(), claimed.revision(), claimed.fence(), claimed.leaseUntil(), claimed.detailCode(),
                    claimed.result(), claimed.providerUpdatedAt(), 1, Optional.of(createdAt.plusSeconds(31)),
                    Optional.of(SignWorkflowStore.ReconciliationFailureClass.STATUS_UNAVAILABLE));
        }
        writeRawCurrentRecord(root, id, corrupted);
        List<String> beforeRecovery = rootFileState(root);

        IllegalStateException failure;
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), clock)) {
            failure = assertThrows(IllegalStateException.class, () -> reopened.getSignRecord(id));
        }
        assertTrue(failure.getMessage().contains("code=RECONCILIATION_ELIGIBILITY_INVALID"));
        assertFalse(failure.toString().contains(id.value()));
        assertEquals(beforeRecovery, rootFileState(root));
    }

    @Test
    void previousSigningRecordCodecIsRejectedWithoutSynthesis(@TempDir Path root) throws Exception {
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            PkiId id = SigningSubmissionId
                    .create(store.signingNamespace() + ".test-signer", createdAt, new SecureRandom()).id();
            SignWorkflowStore.Record record = intent(store, id, createdAt,
                    new EncodedObject(Encoding.BINARY, new byte[] { 7 }), TEST_ALGORITHM);
            byte[] current = FsCodec.encode(FsCodec.SIGN_WORKFLOW_RECORD, record);
            byte[] previous = current.clone();
            previous[Integer.BYTES] = (byte) (FsCodec.CURRENT_CODEC_VERSION - 1);
            assertThrows(IllegalStateException.class,
                    () -> FsCodec.decode(FsCodec.SIGN_WORKFLOW_RECORD, previous, store.stagedContent()));
        }
    }

    @Test
    void signingAdmissionCreatesAndRollsBackAttachConflictAndIdentityFailures(@TempDir Path root)
            throws Exception {
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        Clock clock = Clock.fixed(createdAt, java.time.ZoneOffset.UTC);
        Path ownerRoot = root.resolve("owner");
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                    ownerRoot, FsPkiStoreOptions.defaults(), clock, 2, null);
                FilesystemPkiStore foreign = new FilesystemPkiStore(
                        root.resolve("foreign"), FsPkiStoreOptions.defaults(), clock, 2, null)) {
            String namespace = store.signingNamespace() + ".test-signer";
            PkiId first = SigningSubmissionId.create(namespace, createdAt, new SecureRandom()).id();
            PkiId second = SigningSubmissionId.create(namespace, createdAt, new SecureRandom()).id();
            SignWorkflowStore.Record intent = intent(store, first, createdAt,
                    new EncodedObject(Encoding.BINARY, new byte[] { 1 }), TEST_ALGORITHM);
            SignWorkflowStore.SignAdmission created = store.reserveSignAdmission(first);
            assertEquals(SignWorkflowStore.CreateResult.CREATED,
                    store.createSignIntent(created, intent));
            assertThrows(IllegalStateException.class,
                    () -> store.createSignIntent(created, intent));
            created.close();

            try (SignWorkflowStore.SignAdmission attached = store.reserveSignAdmission(first)) {
                assertEquals(SignWorkflowStore.CreateResult.ATTACHED,
                        store.createSignIntent(attached, intent));
            }
            SignWorkflowStore.Record conflict = copy(intent, intent.request(),
                    flipFingerprint(intent.fingerprint()), SignWorkflowStore.State.INTENT,
                    0L, 0L, Optional.empty(), Optional.of("INTENT"), Optional.empty(), Optional.empty());
            try (SignWorkflowStore.SignAdmission rejected = store.reserveSignAdmission(first)) {
                assertEquals(SignWorkflowStore.CreateResult.CONFLICT,
                        store.createSignIntent(rejected, conflict));
            }

            try (SignWorkflowStore.SignAdmission mismatched = store.reserveSignAdmission(second)) {
                assertThrows(IllegalArgumentException.class,
                        () -> store.createSignIntent(mismatched, intent));
            }
            try (SignWorkflowStore.SignAdmission foreignAdmission = store.reserveSignAdmission(second)) {
                assertThrows(IllegalArgumentException.class,
                        () -> foreign.createSignIntent(foreignAdmission, intent));
            }
            try (SignWorkflowStore.SignAdmission reusableCapacity = store.reserveSignAdmission(second)) {
                assertThrows(IllegalStateException.class, () -> store.reserveSignAdmission(second));
            }
        }
    }

    @Test
    void signingAdmissionRollsBackValidationAndStagedContentFailure(@TempDir Path root)
            throws Exception {
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        Clock clock = Clock.fixed(createdAt, java.time.ZoneOffset.UTC);
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), clock, 1, null)) {
            String namespace = store.signingNamespace() + ".test-signer";
            PkiId id = SigningSubmissionId.create(namespace, createdAt, new SecureRandom()).id();
            SignWorkflowStore.Record valid = intent(store, id, createdAt,
                    new EncodedObject(Encoding.BINARY, new byte[] { 2 }), TEST_ALGORITHM);
            SignWorkflowStore.Record invalid = copy(valid, valid.request(), valid.fingerprint(),
                    SignWorkflowStore.State.DISPATCHED, 0L, 0L, Optional.empty(),
                    Optional.of("DISPATCHED"), Optional.empty(), Optional.empty());
            try (SignWorkflowStore.SignAdmission admission = store.reserveSignAdmission(id)) {
                assertThrows(IllegalArgumentException.class,
                        () -> store.createSignIntent(admission, invalid));
            }
            DurableContentReference reference = PkiSigningBus.SignContinuation.decode(
                    valid.request(), store.stagedContent()).content();
            Files.write(new FsPaths(root).stagedContentRoot().resolve(
                    reference.contentId() + ".content"), new byte[0]);
            try (SignWorkflowStore.SignAdmission admission = store.reserveSignAdmission(id)) {
                assertThrows(PkiException.class, () -> store.createSignIntent(admission, valid));
            }
            try (SignWorkflowStore.SignAdmission released = store.reserveSignAdmission(id)) {
                assertThrows(IllegalStateException.class, () -> store.reserveSignAdmission(id));
            }
        }
    }

    @Test
    void fullReopenRejectsUntilRetirementThenAdmits(@TempDir Path root) throws Exception {
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        MutableClock clock = new MutableClock(createdAt);
        PkiId first;
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), clock, 1, null)) {
            first = persistIntent(store, createdAt, 1);
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), clock, 1, null)) {
            String namespace = reopened.signingNamespace() + ".test-signer";
            PkiId second = SigningSubmissionId.create(namespace, createdAt, new SecureRandom()).id();
            assertThrows(IllegalStateException.class, () -> reopened.reserveSignAdmission(second));
            SignWorkflowStore.Record malformed = new SignWorkflowStore.Record(second, namespace,
                    "signfp:v3:" + "0".repeat(64), testConfigurationCommitment(), TEST_OWNER, createdAt,
                    createdAt.plusSeconds(60L), new EncodedObject(Encoding.BINARY, new byte[] { 1 }),
                    SignWorkflowStore.State.INTENT, 0L, 0L, Optional.empty(), Optional.of("INTENT"),
                    Optional.empty(), Optional.empty(), 0, Optional.empty(), Optional.empty());
            assertThrows(IllegalStateException.class, () -> reopened.createSignIntent(malformed),
                    "capacity must reject before malformed staged-content continuation access");

            SignWorkflowStore.Record claimed = reopened.tryClaimSign(
                    first, 0L, Duration.ofSeconds(30)).orElseThrow();
            SignWorkflowStore.Record dispatched = reopened.transitionSign(first, claimed.revision(),
                    claimed.fence(), SignWorkflowStore.State.DISPATCHED, Optional.of("DISPATCHED"),
                    Optional.empty(), Optional.empty()).orElseThrow();
            SignWorkflowStore.Record failed = reopened.transitionSign(first, dispatched.revision(),
                    dispatched.fence(), SignWorkflowStore.State.FAILED, Optional.of("PROVIDER_FAILED"),
                    Optional.empty(), Optional.of(createdAt)).orElseThrow();
            reopened.retireSign(first, failed.revision(), failed.fence()).orElseThrow();

            SignWorkflowStore.Record secondIntent = intent(reopened, second, createdAt,
                    new EncodedObject(Encoding.BINARY, new byte[] { 2 }), TEST_ALGORITHM);
            try (SignWorkflowStore.SignAdmission admission = reopened.reserveSignAdmission(second)) {
                assertEquals(SignWorkflowStore.CreateResult.CREATED,
                        reopened.createSignIntent(admission, secondIntent));
            }
        }
    }

    @Test
    void acceptedWorkflowProgressesAndRetiresWithOrdinaryCapacityExhausted(
            @TempDir Path root) throws Exception {
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        Clock clock = Clock.fixed(createdAt, ZoneOffset.UTC);
        FsPkiStoreOptions defaults = FsPkiStoreOptions.defaults();
        long ordinaryCapacityBytes = 64L * 1024L;
        int maximumFillers = 1024;
        long protectedFloor = SigningTransitionWorkspaceSizing.derive(
                SigningMvccIndex.FOUR_GIB_MAXIMUM_KEYS,
                SigningActiveWal.Configuration.defaults().queueCapacity()).workspaceFloorBytes();
        FsPkiStoreOptions constrained = new FsPkiStoreOptions(
                defaults.caHistoryPolicy(), defaults.profileHistoryPolicy(),
                defaults.revocationHistoryPolicy(), defaults.workflowHistoryPolicy(),
                defaults.strictSnapshotExport(), defaults.signingOperationHorizon(),
                defaults.signingIdPermittedSkew(), defaults.signingMaximumGroupSize(),
                Math.addExact(protectedFloor, ordinaryCapacityBytes),
                defaults.signingCompactionTransientBudgetBytes(), defaults.signingEvidenceAudit());

        try (FilesystemPkiStore store = new FilesystemPkiStore(
                root.resolve("subject"), constrained, clock)) {
            String namespace = store.signingNamespace() + ".test-signer";
            PkiId id = new PkiId("zsign:v1:" + namespace + ':'
                    + createdAt.toEpochMilli() + ':' + "01".repeat(16));
            assertEquals(SignWorkflowStore.CreateResult.CREATED,
                    store.createSignIntent(intent(store, id, createdAt,
                            new EncodedObject(Encoding.BINARY, new byte[] { 10 }),
                            TEST_ALGORITHM)));

            PkiException capacityRejection = null;
            for (int sequence = 2; sequence <= maximumFillers + 1; sequence++) {
                String suffix = "%032x".formatted(sequence);
                PkiId filler = new PkiId("zsign:v1:" + namespace + ':'
                        + createdAt.toEpochMilli() + ':' + suffix);
                SignWorkflowStore.Record fillerIntent = intent(store, filler, createdAt,
                        new EncodedObject(Encoding.BINARY, new byte[] { 11 }), TEST_ALGORITHM);
                try {
                    assertEquals(SignWorkflowStore.CreateResult.CREATED,
                            store.createSignIntent(fillerIntent));
                } catch (PkiException failure) {
                    assertTrue(failure.getCause() instanceof MetadataStoreException,
                            "ordinary capacity rejection must preserve metadata classification");
                    MetadataStoreException metadataFailure =
                            (MetadataStoreException) failure.getCause();
                    assertEquals(MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                            metadataFailure.category());
                    capacityRejection = failure;
                    break;
                }
            }
            assertTrue(capacityRejection != null,
                    "ordinary capacity was not reached within the bounded filler sequence");
            Throwable cause = capacityRejection;
            boolean capacityCauseFound = false;
            while (cause != null) {
                if (cause instanceof SigningIndexCapacityBudget.CapacityExceededException) {
                    capacityCauseFound = true;
                    break;
                }
                cause = cause.getCause();
            }
            assertTrue(capacityCauseFound,
                    "ordinary capacity rejection must preserve the capacity-exceeded cause");
            FilesystemPkiStore.LocalSigningIndexCapacityMetrics saturated =
                    store.localSigningIndexCapacityMetrics();
            assertEquals(Math.addExact(protectedFloor, ordinaryCapacityBytes),
                    saturated.steadyMaximumBytes());
            String storeNamespace = store.signingNamespace();
            assertEquals(storeNamespace, store.signingNamespace());
            SignWorkflowStore.Record claimed = store.tryClaimSign(
                    id, 0L, Duration.ofSeconds(30L)).orElseThrow();
            SignWorkflowStore.Record dispatched = store.transitionSign(
                    id, claimed.revision(), claimed.fence(),
                    SignWorkflowStore.State.DISPATCHED, Optional.of("DISPATCHED"),
                    Optional.empty(), Optional.empty()).orElseThrow();
            SignWorkflowStore.Record failed = store.transitionSign(
                    id, dispatched.revision(), dispatched.fence(),
                    SignWorkflowStore.State.FAILED, Optional.of("PROVIDER_FAILED"),
                    Optional.empty(), Optional.of(createdAt)).orElseThrow();
            SignWorkflowStore.Record retired = store.retireSign(
                    id, failed.revision(), failed.fence()).orElseThrow();
            assertEquals(SignWorkflowStore.State.RETIRED, retired.state());
        }
    }

    @Test
    void localInitialAcceptanceReportsOrdinaryIndexCapacityWithoutInvokingCrypto(
            @TempDir Path root) throws Exception {
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        Clock clock = Clock.fixed(createdAt, ZoneOffset.UTC);
        FsPkiStoreOptions defaults = FsPkiStoreOptions.defaults();
        long ordinaryCapacityBytes = 64L * 1024L;
        int maximumFillers = 1024;
        long protectedFloor = SigningTransitionWorkspaceSizing.derive(
                SigningMvccIndex.FOUR_GIB_MAXIMUM_KEYS,
                SigningActiveWal.Configuration.defaults().queueCapacity()).workspaceFloorBytes();
        FsPkiStoreOptions constrained = new FsPkiStoreOptions(
                defaults.caHistoryPolicy(), defaults.profileHistoryPolicy(),
                defaults.revocationHistoryPolicy(), defaults.workflowHistoryPolicy(),
                defaults.strictSnapshotExport(), defaults.signingOperationHorizon(),
                defaults.signingIdPermittedSkew(), defaults.signingMaximumGroupSize(),
                Math.addExact(protectedFloor, ordinaryCapacityBytes),
                defaults.signingCompactionTransientBudgetBytes(), defaults.signingEvidenceAudit());

        try (FilesystemPkiStore store = new FilesystemPkiStore(root, constrained, clock)) {
            byte[] payload = { 21, 22, 23, 24 };
            AtomicInteger cryptoReads = new AtomicInteger();
            DurableContentReference reference = operationReference(store, payload);
            String localNamespace = store.localSigningNamespace("test-provider");
            SignatureWorkflow.ConfigurationCommitment configuration =
                    testConfigurationCommitment();
            PkiException saturation = null;
            SignatureWorkflow.SignRequest rejectedRequest = null;
            SignWorkflowStore.Record rejectedIntent = null;
            for (int sequence = 2; sequence <= maximumFillers + 1; sequence++) {
                PkiId filler = new PkiId("zsign:v1:" + localNamespace + ':'
                        + createdAt.toEpochMilli() + ':' + "%032x".formatted(sequence));
                SignatureWorkflow.SignRequest fillerRequest = SignatureWorkflow.SignRequest.create(
                        filler, localNamespace, configuration, 1L, TEST_ACCESS,
                        new KeyRef("test-provider:test-key"), TEST_ALGORITHM,
                        SignatureWorkflow.ContentCommitment.sha256(payload),
                        new CountingContent(payload, cryptoReads), Optional.of(Encoding.BINARY),
                        Optional.of(createdAt.plusSeconds(30L)));
                SignWorkflowStore.Record fillerIntent =
                        localIntent(fillerRequest, reference, createdAt);
                try {
                    assertEquals(SignWorkflowStore.CreateResult.CREATED,
                            store.createSignIntent(fillerIntent));
                } catch (PkiException failure) {
                    saturation = failure;
                    rejectedRequest = fillerRequest;
                    rejectedIntent = fillerIntent;
                    break;
                }
            }
            assertTrue(saturation != null,
                    "ordinary capacity was not reached within the bounded filler sequence");
            assertTrue(rejectedRequest != null && rejectedIntent != null,
                    "ordinary capacity rejection did not preserve its exact local request");

            String storeNamespace = store.signingNamespace();
            SignatureWorkflow.SignRequest request = rejectedRequest;
            SignWorkflowStore.Record targetIntent = rejectedIntent;
            PkiException rejected;
            try (SignWorkflowStore.SignAdmission admission =
                    store.reserveSignAdmission(request.submissionId())) {
                rejected = assertThrows(PkiException.class,
                        () -> store.acceptLocalSign(admission, request, configuration,
                                targetIntent, reference));
            }
            assertTrue(rejected.getMessage().contains("SIGNING_METADATA_CAPACITY_UNAVAILABLE"));
            assertTrue(rejected.getCause() instanceof MetadataStoreException,
                    "local acceptance must preserve metadata capacity classification");
            MetadataStoreException metadataFailure = (MetadataStoreException) rejected.getCause();
            assertEquals(MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                    metadataFailure.category());
            assertTrue(metadataFailure.getCause()
                            instanceof SigningIndexCapacityBudget.CapacityExceededException,
                    "local acceptance must preserve the capacity-exceeded cause");
            assertEquals(0, cryptoReads.get());
            assertEquals(storeNamespace, store.signingNamespace());
        }
    }

    @Test
    void durabilityUncertainReleasesEphemeralAdmissionAndReopenReconstructsCapacity(
            @TempDir Path root) throws Exception {
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        Clock clock = Clock.fixed(createdAt, java.time.ZoneOffset.UTC);
        PkiId id;
        FilesystemPkiStore uncertain = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), clock, 1, new FailThirdWalForce());
        try {
            String namespace = uncertain.signingNamespace() + ".test-signer";
            id = SigningSubmissionId.create(namespace, createdAt, new SecureRandom()).id();
            SignWorkflowStore.Record intent = intent(uncertain, id, createdAt,
                    new EncodedObject(Encoding.BINARY, new byte[] { 3 }), TEST_ALGORITHM);
            try (SignWorkflowStore.SignAdmission admission = uncertain.reserveSignAdmission(id)) {
                assertThrows(PkiException.class,
                        () -> uncertain.createSignIntent(admission, intent));
            }
            assertThrows(PkiException.class, () -> uncertain.reserveSignAdmission(id));
        } finally {
            try {
                uncertain.close();
            } catch (java.io.IOException expectedRecoveryRequired) {
                // The failed force permanently closes this writer generation.
            }
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), clock, 1, null)) {
            assertTrue(reopened.getSignRecord(id).isPresent());
            PkiId next = SigningSubmissionId.create(
                    reopened.signingNamespace() + ".test-signer", createdAt, new SecureRandom()).id();
            assertThrows(IllegalStateException.class, () -> reopened.reserveSignAdmission(next));
        }
    }

    @Test
    void categorizedMetadataRejectionPreservesStoreUntilDurabilityBecomesUncertain(
            @TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), Clock.systemUTC())) {
            String namespace = store.signingNamespace();
            MetadataStoreException limit = new MetadataStoreException(
                    MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                    "test metadata capacity rejection");
            PkiException limited = store.translateSigningMetadataFailure(limit);
            assertSame(limit, limited.getCause());
            assertEquals(namespace, store.signingNamespace());

            MetadataStoreException cancelled = new MetadataStoreException(
                    MetadataCommitResult.FailureCategory.CANCELLED,
                    "test metadata cancellation");
            PkiException cancelledCommit = store.translateSigningMetadataFailure(cancelled);
            assertSame(cancelled, cancelledCommit.getCause());
            assertEquals(namespace, store.signingNamespace());

            MetadataStoreException storage = new MetadataStoreException(
                    MetadataCommitResult.FailureCategory.STORAGE_FAILURE,
                    "test uncertain metadata durability");
            PkiException uncertain = store.translateSigningMetadataFailure(storage);
            assertSame(storage, uncertain.getCause());
            assertThrows(PkiException.class, store::signingNamespace);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = { 1, 8 })
    void historicalGroup32RecoversAndNewStoreWritesHonorSmallerMaximum(
            int runtimeMaximum) throws Exception {
        Path root = localMatrixDirectory.resolve("historical-group-" + runtimeMaximum);
        FsPkiStoreOptions initialOptions = FsPkiStoreOptions.defaults()
                .withSigningMaximumGroupSize(32);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, initialOptions)) {
            // Establish a complete store image before injecting the historical group.
        }
        List<ExpectedMetadata> historical = appendHistoricalGroup32(root);
        Instant createdAt = Instant.ofEpochMilli(System.currentTimeMillis());
        FsPkiStoreOptions runtimeOptions = FsPkiStoreOptions.defaults()
                .withSigningMaximumGroupSize(runtimeMaximum);
        List<PkiId> newRecords = new ArrayList<>();

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, runtimeOptions)) {
            for (int marker = 0; marker < 8; marker++) {
                PkiId id = persistIntent(reopened, createdAt, marker);
                newRecords.add(id);
                assertEquals(SignWorkflowStore.State.INTENT,
                        reopened.getSignRecord(id).orElseThrow().state());
            }
            assertWriterMaximum(reopened, runtimeMaximum);
        }
        assertHistoricalMetadata(root, historical);

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, runtimeOptions)) {
            for (PkiId id : newRecords) {
                assertEquals(SignWorkflowStore.State.INTENT,
                        reopened.getSignRecord(id).orElseThrow().state());
            }
            PkiId appended = persistIntent(reopened, createdAt, 99);
            assertEquals(SignWorkflowStore.State.INTENT,
                    reopened.getSignRecord(appended).orElseThrow().state());
            assertWriterMaximum(reopened, runtimeMaximum);
        }
    }

    private static WalCalibration calibrateLocalWal(
            Path storeRoot, Path keyring, Clock clock, Instant now,
            byte[] payload, SigningActiveWal.Configuration configuration)
            throws Exception {
        AtomicInteger contentReads = new AtomicInteger();

        try (FilesystemPkiStore store = new FilesystemPkiStore(
                    storeRoot, FsPkiStoreOptions.defaults(), clock,
                    8, null, configuration);
                SignatureWorkflow allocated = localWorkflow(keyring, store)) {
            ZeroEchoLibSignatureWorkflow workflow =
                    (ZeroEchoLibSignatureWorkflow) allocated;
            String canonicalAlgorithm = signingAuthority(workflow)
                    .planSigning(TEST_ALGORITHM, SignatureWorkflow.class)
                    .selection().requested().canonicalForm();

            DurableContentReference reference = operationReference(store, payload);
            String namespace = store.localSigningNamespace("zeroecho-lib");
            PkiId id = SigningSubmissionId.create(
                    namespace, now, new SecureRandom()).id();
            SignatureWorkflow.SignRequest request = SignatureWorkflow.SignRequest.create(
                    id, namespace, workflow.configurationCommitment(), 1L, TEST_ACCESS,
                    new KeyRef("zeroecho-lib:sign.prv"), canonicalAlgorithm,
                    SignatureWorkflow.ContentCommitment.sha256(payload),
                    new CountingContent(payload, contentReads),
                    Optional.of(Encoding.BINARY), Optional.of(now.plusSeconds(30)));
            EncodedObject persistedContinuation = new PkiSigningBus.SignContinuation(
                    TEST_ACCESS, canonicalAlgorithm, reference, request.keyRef(),
                    Encoding.BINARY, Optional.empty()).withSignerOpId(id).encode();
            SignWorkflowStore.Record intent = new SignWorkflowStore.Record(
                    id, namespace, request.semanticFingerprint(),
                    request.configurationCommitment(), TEST_OWNER,
                    now, now.plusSeconds(30), persistedContinuation,
                    SignWorkflowStore.State.INTENT, 0L, 0L, Optional.empty(),
                    Optional.of("INTENT"), Optional.empty(), Optional.empty(), 0,
                    Optional.empty(), Optional.empty());

            SigningActiveWal.Snapshot before = store.localSigningWriterSnapshot();
            AtomicLocalSigningLedgerParticipant.AtomicAcceptance acceptance;
            try (SignWorkflowStore.SignAdmission admission = store.reserveSignAdmission(id)) {
                acceptance = store.acceptLocalSign(admission, request,
                        workflow.configurationCommitment(), intent, reference);
            }
            SigningActiveWal.Snapshot afterAcceptance = store.localSigningWriterSnapshot();
            long acceptanceBytes = afterAcceptance.bytesAppended() - before.bytesAppended();
            assertEquals(1L, afterAcceptance.groupsCommitted() - before.groupsCommitted());
            assertEquals(1L, afterAcceptance.requestsCommitted() - before.requestsCommitted());

            assertEquals(id, workflow.submitAcceptedLocalSign(
                    request, acceptance.executionPermit().orElseThrow(),
                    new SignatureWorkflow.CallControl(
                            now.plusSeconds(30), CancellationSignal.NONE)));
            SigningActiveWal.Snapshot afterTerminal = store.localSigningWriterSnapshot();
            long terminalBytes = afterTerminal.bytesAppended()
                    - afterAcceptance.bytesAppended();

            assertTrue(acceptanceBytes > 0L);
            assertTrue(terminalBytes > 0L);
            assertEquals(1L, afterTerminal.groupsCommitted()
                    - afterAcceptance.groupsCommitted());
            assertEquals(1L, afterTerminal.requestsCommitted()
                    - afterAcceptance.requestsCommitted());
            assertEquals(1L, afterTerminal.maximumBatchSize());
            assertEquals(1, contentReads.get());

            SigningManifestCodec.Manifest manifest = readSigningManifest(storeRoot);
            assertTrue(manifest.sealedSegments().isEmpty());
            assertEquals(SigningWalContainerCodec.HEADER_BYTES
                            + acceptanceBytes + terminalBytes,
                    Files.size(signingMetadataRoot(storeRoot)
                            .resolve(manifest.activeWal().name())));

            EncodedObject result = store.getSignRecord(id)
                    .orElseThrow().result().orElseThrow();
            return new WalCalibration(acceptanceBytes, terminalBytes,
                    new EncodedObject(result.encoding(), result.bytes()),
                    id.value().length());
        }
    }

    private static SignatureWorkflow localWorkflow(
            Path keyring, FilesystemPkiStore store) {
        return new ZeroEchoLibSignatureWorkflowProvider(
                TestKeyringUnlocks.provider()).allocate(
                new ProviderConfig("zeroecho-lib",
                        Map.of("keyringPath", keyring.toString())),
                SignatureWorkflowRuntimeDependencies.local(
                        TestKeyringUnlocks.provider(), store));
    }

    private static SigningActiveWal.Configuration singletonWalConfiguration(
            long maximumSegmentBytes) {
        return new SigningActiveWal.Configuration(
                1, 1, 0L, SigningWalFrameCodec.MAX_PAYLOAD_BYTES,
                SigningWalFrameCodec.BATCH_MARKER_BYTES
                        + SigningWalFrameCodec.MAX_FRAME_BYTES,
                maximumSegmentBytes);
    }

    private static Path signingMetadataRoot(Path storeRoot) {
        return new FsPaths(storeRoot).transactionalMetadataRoot();
    }

    private static SigningManifestCodec.Manifest readSigningManifest(
            Path storeRoot) throws Exception {
        return SigningManifestCodec.decode(Files.readAllBytes(
                signingMetadataRoot(storeRoot)
                        .resolve(SigningLedgerRecovery.MANIFEST_FILE)));
    }

    private static PkiStore observingStore(
            FilesystemPkiStore store, AtomicInteger contentReads,
            AtomicInteger restorations, CountDownLatch firstRestoration,
            CountDownLatch secondRestoration) {
        StagedContentStore stagedContent =
                observingContentStore(store.stagedContent(), contentReads);
        return (PkiStore) Proxy.newProxyInstance(
                PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class, AtomicLocalSigningLedgerParticipant.class },
                (proxy, method, arguments) -> {
                    if ("stagedContent".equals(method.getName())) {
                        return stagedContent;
                    }
                    if ("registerSigningHeadroomRestored".equals(method.getName())) {
                        AtomicLocalSigningLedgerParticipant.HeadroomListener listener =
                                (AtomicLocalSigningLedgerParticipant.HeadroomListener) arguments[0];
                        return store.registerSigningHeadroomRestored(
                                new AtomicLocalSigningLedgerParticipant.HeadroomListener() {
                                    @Override public void restored(long epoch) {
                                        listener.restored(epoch);
                                        int observed = restorations.incrementAndGet();
                                        if (observed == 1) {
                                            firstRestoration.countDown();
                                        }
                                        if (observed == 2) {
                                            secondRestoration.countDown();
                                        }
                                    }

                                    @Override public void recoveryRequired() {
                                        listener.recoveryRequired();
                                    }
                                });
                    }
                    return invokeDelegate(store, method, arguments);
                });
    }

    private static PkiStore withholdingHeadroomStore(
            FilesystemPkiStore store, AtomicInteger contentReads,
            CountDownLatch restorationWithheld) {
        StagedContentStore stagedContent =
                observingContentStore(store.stagedContent(), contentReads);
        return (PkiStore) Proxy.newProxyInstance(
                PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class, AtomicLocalSigningLedgerParticipant.class },
                (proxy, method, arguments) -> {
                    if ("stagedContent".equals(method.getName())) {
                        return stagedContent;
                    }
                    if ("registerSigningHeadroomRestored".equals(method.getName())) {
                        AtomicLocalSigningLedgerParticipant.HeadroomListener listener =
                                (AtomicLocalSigningLedgerParticipant.HeadroomListener) arguments[0];
                        return store.registerSigningHeadroomRestored(
                                new AtomicLocalSigningLedgerParticipant.HeadroomListener() {
                                    @Override public void restored(long epoch) {
                                        restorationWithheld.countDown();
                                    }

                                    @Override public void recoveryRequired() {
                                        listener.recoveryRequired();
                                    }
                                });
                    }
                    return invokeDelegate(store, method, arguments);
                });
    }

    private static StagedContentStore observingContentStore(
            StagedContentStore store, AtomicInteger contentReads) {
        return (StagedContentStore) Proxy.newProxyInstance(
                StagedContentStore.class.getClassLoader(),
                new Class<?>[] { StagedContentStore.class },
                (proxy, method, arguments) -> {
                    Object result = invokeDelegate(store, method, arguments);
                    if (!"openContent".equals(method.getName())) {
                        return result;
                    }
                    RepeatableContent content = (RepeatableContent) result;
                    return new RepeatableContent() {
                        @Override public InputStream openStream() throws java.io.IOException {
                            contentReads.incrementAndGet();
                            return content.openStream();
                        }

                        @Override public OptionalLong length() {
                            return content.length();
                        }

                        @Override public String contentId() {
                            return content.contentId();
                        }

                        @Override public void close() throws java.io.IOException {
                            content.close();
                        }
                    };
                });
    }

    private static Object invokeDelegate(
            Object target, java.lang.reflect.Method method, Object[] arguments)
            throws Throwable {
        try {
            return method.invoke(target, arguments);
        } catch (InvocationTargetException failure) {
            throw failure.getCause();
        }
    }

    private static void awaitRuntimeBarrier(
            SigningExecutionRuntime runtime, PkiId barrierId) throws Exception {
        SigningExecutionRuntime.StepSubmission<Boolean> barrier = runtime.scheduleStep(
                barrierId, () -> Boolean.TRUE, CancellationSignal.NONE);
        assertEquals(SigningExecutionRuntime.StepDisposition.ACCEPTED,
                barrier.disposition());
        assertTrue(barrier.future().orElseThrow().get(5, TimeUnit.SECONDS));
    }

    private static void assertRuntimeReleased(
            SigningExecutionRuntime runtime) throws Exception {
        assertEquals(0, runtimeCount(runtime, "suspendedTerminalCount"));
        assertEquals(0, runtimeCount(runtime, "terminalSlotsInUse"));
        assertEquals(0, runtime.metrics().schedulerReserved());
    }

    private static int runtimeCount(
            SigningExecutionRuntime runtime, String methodName) throws Exception {
        java.lang.reflect.Method method =
                SigningExecutionRuntime.class.getDeclaredMethod(methodName);
        method.setAccessible(true);
        return (Integer) method.invoke(runtime);
    }

    private static List<ExpectedMetadata> appendHistoricalGroup32(Path storeRoot)
            throws Exception {
        Path metadataRoot = new FsPaths(storeRoot).transactionalMetadataRoot();
        SigningManifestCodec.ActiveWal active = SigningManifestCodec.decode(Files.readAllBytes(
                metadataRoot.resolve(SigningLedgerRecovery.MANIFEST_FILE))).activeWal();
        Path activePath = metadataRoot.resolve(active.name());
        SigningWalFrameCodec.ScanResult before;
        try (FileChannel input = FileChannel.open(activePath, StandardOpenOption.READ)) {
            before = SigningWalFrameCodec.scanGroups(input, active.firstSequence(), true,
                    (frames, commit) -> { });
        }
        long nextSequence = before.frameCount() == 0L
                ? active.firstSequence() : Math.incrementExact(before.lastSequence());
        List<ExpectedMetadata> expected = new ArrayList<>(32);
        List<SigningWalFrameCodec.Frame> frames = new ArrayList<>(32);
        for (int index = 0; index < 32; index++) {
            MetadataKey key = new MetadataKey(
                    "io.zeroecho.test.signing-group", "historical-" + index);
            byte[] value = ByteBuffer.allocate(Integer.BYTES).putInt(index).array();
            expected.add(new ExpectedMetadata(key, value));
            SigningTransactionPayloadCodec.Mutation mutation =
                    new SigningTransactionPayloadCodec.Mutation(
                            SigningTransactionPayloadCodec.MutationKind.CREATE,
                            key, -1L, value);
            frames.add(new SigningWalFrameCodec.Frame(
                    SigningWalFrameCodec.RecordType.COMMIT,
                    new UUID(13L, index + 1L), nextSequence + index,
                    SigningTransactionPayloadCodec.directCommit(List.of(mutation), 0L)));
        }
        try (FileChannel output = FileChannel.open(activePath, StandardOpenOption.APPEND)) {
            SigningWalFrameCodec.writeCommittedBatch(output, frames,
                    before.committedRevision(),
                    Math.addExact(before.committedRevision(), frames.size()),
                    before.rollingCommitment());
            output.force(true);
        }
        List<Integer> groupSizes = new ArrayList<>();
        try (FileChannel input = FileChannel.open(activePath, StandardOpenOption.READ)) {
            SigningWalFrameCodec.scanGroups(input, active.firstSequence(), true,
                    (committed, marker) -> groupSizes.add(committed.size()));
        }
        assertTrue(groupSizes.contains(32), "fixture must contain one historical 32-frame group");
        return List.copyOf(expected);
    }

    private static void assertHistoricalMetadata(Path storeRoot,
            List<ExpectedMetadata> expected) throws Exception {
        Path metadataRoot = new FsPaths(storeRoot).transactionalMetadataRoot();
        try (SegmentedTransactionalMetadataStore metadata =
                SegmentedTransactionalMetadataStore.open(metadataRoot);
                MetadataSnapshot snapshot = metadata.snapshot()) {
            for (ExpectedMetadata entry : expected) {
                try (MetadataSnapshot.Record record = snapshot.get(entry.key()).orElseThrow()) {
                    assertArrayEquals(entry.value(), record.openStream().readAllBytes());
                }
            }
        }
    }

    private static void assertWriterMaximum(FilesystemPkiStore store, int configuredMaximum) {
        FilesystemPkiStore.LocalSigningWriterMetrics metrics =
                store.localSigningWriterMetrics();
        assertTrue(metrics.maximumBatchSize() > 0L);
        assertTrue(metrics.maximumBatchSize() <= configuredMaximum);
    }

    private record ExpectedMetadata(MetadataKey key, byte[] value) {
        private ExpectedMetadata {
            value = value.clone();
        }

        @Override public byte[] value() {
            return value.clone();
        }
    }

    private record WalCalibration(long acceptanceBytes, long terminalBytes,
            EncodedObject result, int identifierLength) {
    }

    private static SignWorkflowStore.Record intent(FilesystemPkiStore store, PkiId id, Instant createdAt,
            EncodedObject request,
            String algorithmId) {
        Instant deadline = createdAt.plusSeconds(60);
        PkiSigningBus.SignContinuation continuation = continuation(store, id, request, algorithmId);
        String namespace = SigningSubmissionId.parse(id).namespace();
        SignatureWorkflow.ConfigurationCommitment configurationCommitment = testConfigurationCommitment();
        String fingerprint = continuation.semanticFingerprint(configurationCommitment, namespace, deadline);
        return new SignWorkflowStore.Record(id, namespace, fingerprint, configurationCommitment, TEST_OWNER,
                createdAt, deadline,
                continuation.encode(), SignWorkflowStore.State.INTENT, 0L, 0L, Optional.empty(), Optional.of("INTENT"),
                Optional.empty(), Optional.empty(), 0, Optional.empty(), Optional.empty());
    }

    private static PkiId persistIntent(FilesystemPkiStore store, Instant createdAt, int marker) {
        String namespace = store.signingNamespace() + ".test-signer";
        PkiId id = SigningSubmissionId.create(namespace, createdAt, new SecureRandom()).id();
        store.createSignIntent(intent(store, id, createdAt,
                new EncodedObject(Encoding.BINARY, new byte[] { (byte) marker }), TEST_ALGORITHM));
        return id;
    }

    private static PkiId persistPublishingSuccess(FilesystemPkiStore store, Instant createdAt) {
        String namespace = store.signingNamespace() + ".test-signer";
        PkiId id = SigningSubmissionId.create(namespace, createdAt, new SecureRandom()).id();
        PkiSigningBus.SignContinuation signing = continuation(store, id,
                new EncodedObject(Encoding.BINARY, new byte[] { 91 }), TEST_ALGORITHM);
        Instant deadline = createdAt.plusSeconds(60L);
        SignatureWorkflow.ConfigurationCommitment configuration = testConfigurationCommitment();
        SignWorkflowStore.Record intent = new SignWorkflowStore.Record(id, namespace,
                signing.semanticFingerprint(configuration, namespace, deadline), configuration, TEST_OWNER,
                createdAt, deadline, signing.encode(), SignWorkflowStore.State.INTENT, 0L, 0L,
                Optional.empty(), Optional.of("INTENT"), Optional.empty(), Optional.empty(), 0,
                Optional.empty(), Optional.empty());
        String digest = "1".repeat(64);
        DomainContinuationTemplate template = DomainCommandEncoding.template(DomainContinuationStore.Kind.ISSUANCE,
                "ISSUE_END_ENTITY", "ca:test", "issuer:test", "path:test", digest, "leaf", "1", digest,
                "subject:test", createdAt.toString(), deadline.toString(), "1", "key:test", "content:test",
                digest, digest, "", "", "CN=Test", "[]", "[]", "[]", "binding:test",
                zeroecho.pki.impl.core.async.DomainAttributeEncoding.encode(
                        zeroecho.pki.impl.core.attr.SimpleAttributeSet.builder().build()));
        DomainContinuationStore.Record domain = new DomainContinuationStore.Record(id, 2, template.kind(),
                template.correlationId(), DomainContinuationStore.State.SIGNING, 0L, createdAt, deadline,
                template.command(), template.commandCommitment(), Optional.of(signing.content()), Optional.empty(),
                Optional.empty());
        try (SignWorkflowStore.SignAdmission admission = store.reserveSignAdmission(id)) {
            store.createSignIntent(admission, intent, domain);
        }
        SignWorkflowStore.Record claimed = store.tryClaimSign(id, 0L, Duration.ofSeconds(30L)).orElseThrow();
        SignWorkflowStore.Record dispatched = store.transitionSign(id, claimed.revision(), claimed.fence(),
                SignWorkflowStore.State.DISPATCHED, Optional.of("DISPATCHED"), Optional.empty(),
                Optional.empty()).orElseThrow();
        store.transitionSign(id, dispatched.revision(), dispatched.fence(), SignWorkflowStore.State.SUCCEEDED,
                Optional.of("SIGNED"), Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 1 })),
                Optional.of(createdAt.plusSeconds(10L))).orElseThrow();
        store.transitionDomainContinuation(id, 0L, DomainContinuationStore.State.PUBLISHING,
                Optional.empty(), Optional.empty()).orElseThrow();
        return id;
    }

    private static PkiId persistClaimed(FilesystemPkiStore store, Instant createdAt, int marker) {
        PkiId id = persistIntent(store, createdAt, marker);
        store.tryClaimSign(id, 0L, Duration.ofSeconds(30)).orElseThrow();
        return id;
    }

    private static PkiId persistDispatched(FilesystemPkiStore store, Instant createdAt, int marker) {
        PkiId id = persistClaimed(store, createdAt, marker);
        SignWorkflowStore.Record claimed = store.getSignRecord(id).orElseThrow();
        store.transitionSign(id, claimed.revision(), claimed.fence(), SignWorkflowStore.State.DISPATCHED,
                Optional.of("DISPATCHED"), Optional.empty(), Optional.empty()).orElseThrow();
        return id;
    }

    private static PkiSigningBus.SignContinuation continuation(FilesystemPkiStore store, PkiId id,
            EncodedObject payload, String algorithmId) {
        DurableContentReference content;
        try {
            content = zeroecho.pki.testkit.PkiTestRuntime.fixtureReference(store.stagedContent(), payload.encoding(),
                    payload.bytes());
        } catch (java.io.IOException exception) {
            throw new AssertionError("Unable to stage signing fixture", exception);
        }
        return new PkiSigningBus.SignContinuation(TEST_ACCESS, algorithmId, content, TEST_KEY, Encoding.BINARY,
                Optional.of(id));
    }

    private static String sha256(byte[] bytes) {
        try {
            return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }

    private static EncodedObject request(FilesystemPkiStore store, PkiId id, byte[] payload, String algorithmId) {
        return continuation(store, id, new EncodedObject(Encoding.BINARY, payload), algorithmId).encode();
    }

    private static RepeatableContent blockingContent(byte[] payload, CountDownLatch reading,
            CountDownLatch release) {
        return new RepeatableContent() {
            @Override
            public InputStream openStream() {
                return new ByteArrayInputStream(payload) {
                    private boolean blocked;

                    @Override
                    public int read(byte[] bytes, int offset, int length) {
                        if (!blocked) {
                            blocked = true;
                            reading.countDown();
                            try {
                                if (!release.await(5, TimeUnit.SECONDS)) {
                                    throw new IllegalStateException("Timed out awaiting cancellation");
                                }
                            } catch (InterruptedException failure) {
                                Thread.currentThread().interrupt();
                                throw new IllegalStateException(failure);
                            }
                        }
                        return super.read(bytes, offset, Math.min(length, 1024));
                    }
                };
            }

            @Override public OptionalLong length() { return OptionalLong.of(payload.length); }
            @Override public String contentId() { return "blocking-content"; }
            @Override public void close() { }
        };
    }

    private static DurableContentReference operationReference(FilesystemPkiStore store, byte[] payload)
            throws Exception {
        try (zeroecho.pki.spi.store.ContentSink sink = store.stagedContent().beginContent(
                    Encoding.BINARY, DurableContentReference.Lifecycle.OPERATION);
                java.io.OutputStream output = sink.outputStream()) {
            output.write(payload);
            return sink.complete();
        }
    }

    private static Stream<Arguments> permitReuseModes() {
        return Stream.of(Arguments.of(false), Arguments.of(true));
    }

    private static Stream<Arguments> terminalAdmissionTargets() {
        return Stream.of(
                Arguments.of(SignWorkflowStore.State.SUCCEEDED),
                Arguments.of(SignWorkflowStore.State.FAILED),
                Arguments.of(SignWorkflowStore.State.CANCELLED));
    }

    private static void createSigningKeyring(Path path) throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore keys = KeyringStore.create(path, password)) {
            keys.putPrivate("sign.prv", "RSA", pair.getPrivate());
        }
    }

    private static SignWorkflowStore.Record localIntent(SignatureWorkflow.SignRequest request,
            DurableContentReference reference, Instant now) {
        EncodedObject continuation = new PkiSigningBus.SignContinuation(TEST_ACCESS, TEST_ALGORITHM,
                reference, request.keyRef(), Encoding.BINARY, Optional.of(request.submissionId())).encode();
        return new SignWorkflowStore.Record(request.submissionId(), request.namespace(),
                request.semanticFingerprint(), request.configurationCommitment(), TEST_OWNER, now,
                now.plusSeconds(30), continuation,
                SignWorkflowStore.State.INTENT, 0L, 0L, Optional.empty(), Optional.of("INTENT"),
                Optional.empty(), Optional.empty(), 0, Optional.empty(), Optional.empty());
    }

    private static Stream<Arguments> localDirectCommitBoundaries() {
        return Stream.of(
                Arguments.of(LocalCommitBoundary.ACCEPT_BEFORE_DURABILITY, 0),
                Arguments.of(LocalCommitBoundary.DISPATCHED_RESTART, 0),
                Arguments.of(LocalCommitBoundary.TERMINAL_BEFORE_PERSISTENCE, 1),
                Arguments.of(LocalCommitBoundary.TERMINAL_DELEGATE_THEN_FAIL, 1));
    }

    private static RemoteAttempt submitRemote(FilesystemPkiStore store, PkiSigningBus bus,
            MatrixRemoteWorkflow workflow, byte payloadMarker) throws Exception {
        byte[] payload = { payloadMarker, (byte) (payloadMarker + 1) };
        DurableContentReference reference = operationReference(store, payload);
        PkiId id = bus.newSubmissionId();
        KeyRef key = new KeyRef(workflow.id() + ":test-key");
        PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(
                TEST_ACCESS, TEST_ALGORITHM, reference, key, Encoding.BINARY, Optional.of(id));
        bus.submitSign(id, TEST_OWNER, key, TEST_ALGORITHM, reference,
                Duration.ofSeconds(30), Optional.of(continuation.encode()));
        return new RemoteAttempt(id, store.signingNamespace() + "." + workflow.id(),
                workflow.configurationCommitment());
    }

    private static RemoteAttempt submitRemoteDispatched(FilesystemPkiStore store,
            PkiSigningBus bus, MatrixRemoteWorkflow workflow, byte payloadMarker) throws Exception {
        RemoteAttempt attempt = submitRemote(store, bus, workflow, payloadMarker);
        workflow.holdRunning(attempt.id());
        assertEquals(AsyncState.RUNNING, bus.status(attempt.id()).orElseThrow().state());
        SignWorkflowStore.Record dispatched = store.getSignRecord(attempt.id()).orElseThrow();
        assertEquals(SignWorkflowStore.State.DISPATCHED, dispatched.state());
        assertTrue(dispatched.fence() > 0L);
        return attempt;
    }

    private static void assertRecoveredProviderOwnership(FilesystemPkiStore store,
            RemoteAttempt attempt, MatrixRemoteWorkflow workflow) {
        SignWorkflowStore.Record record = store.getSignRecord(attempt.id()).orElseThrow();
        assertEquals(attempt.namespace(), record.namespace());
        assertEquals(attempt.namespace(), SigningSubmissionId.parse(attempt.id()).namespace());
        assertTrue(record.configurationCommitment().matches(attempt.configurationCommitment()));
        assertTrue(record.configurationCommitment().matches(workflow.configurationCommitment()));
        assertEquals(0, workflow.foreignCalls());
    }

    private static void assertProviderExactlyOnce(MatrixRemoteWorkflow workflow,
            RemoteAttempt terminal, RemoteAttempt dispatched) {
        assertEquals(2, workflow.submitCalls());
        assertEquals(1, workflow.cryptoInvocations());
        assertEquals(1, workflow.submitCalls(terminal.id()));
        assertEquals(1, workflow.cryptoInvocations(terminal.id()));
        assertEquals(1, workflow.submitCalls(dispatched.id()));
        assertEquals(0, workflow.cryptoInvocations(dispatched.id()));
        assertEquals(0, workflow.foreignCalls());
    }

    private static void assertBidirectionalForeignIsolation(FilesystemPkiStore store,
            PkiSigningBus controlBus, MatrixRemoteWorkflow controlWorkflow,
            RemoteAttempt controlProbe, PkiSigningBus targetBus,
            MatrixRemoteWorkflow targetWorkflow, RemoteAttempt targetProbe) throws Exception {
        assertTrue(controlWorkflow.configurationCommitment().matches(
                targetWorkflow.configurationCommitment()));
        assertForeignIsolation(store, controlBus, controlWorkflow, targetProbe);
        assertForeignIsolation(store, targetBus, targetWorkflow, controlProbe);
    }

    private static void assertForeignIsolation(FilesystemPkiStore store,
            PkiSigningBus foreignBus, MatrixRemoteWorkflow foreignWorkflow,
            RemoteAttempt ownedByOtherProvider) throws Exception {
        SignWorkflowStore.Record active = store.getSignRecord(
                ownedByOtherProvider.id()).orElseThrow();
        assertEquals(SignWorkflowStore.State.INTENT, active.state());
        AuthoritativeRecordSnapshot expected = AuthoritativeRecordSnapshot.capture(active);
        int submitCalls = foreignWorkflow.submitCalls();
        int statusCalls = foreignWorkflow.statusCalls();
        int cancellationCalls = foreignWorkflow.cancellationCalls();

        DurableContentReference foreignContent = operationReference(store, new byte[] { 61, 62 });
        KeyRef foreignKey = new KeyRef(foreignWorkflow.id() + ":foreign-probe");
        PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(
                TEST_ACCESS, TEST_ALGORITHM, foreignContent, foreignKey, Encoding.BINARY,
                Optional.of(ownedByOtherProvider.id()));
        assertThrows(IllegalArgumentException.class, () -> foreignBus.submitSign(
                ownedByOtherProvider.id(), TEST_OWNER, foreignKey, TEST_ALGORITHM,
                foreignContent, Duration.ofSeconds(30), Optional.of(continuation.encode())));
        expected.assertUnchanged(store.getSignRecord(ownedByOtherProvider.id()).orElseThrow());

        assertEquals(AsyncState.RUNNING,
                foreignBus.status(ownedByOtherProvider.id()).orElseThrow().state());
        expected.assertUnchanged(store.getSignRecord(ownedByOtherProvider.id()).orElseThrow());

        foreignWorkflow.offerForeignTerminal(ownedByOtherProvider.id());
        assertTrue(foreignBus.consumeResult(ownedByOtherProvider.id()).isEmpty());
        expected.assertUnchanged(store.getSignRecord(ownedByOtherProvider.id()).orElseThrow());

        foreignBus.retireSignOperation(ownedByOtherProvider.id(), "foreign ownership probe");
        expected.assertUnchanged(store.getSignRecord(ownedByOtherProvider.id()).orElseThrow());
        assertEquals(submitCalls, foreignWorkflow.submitCalls());
        assertEquals(statusCalls, foreignWorkflow.statusCalls());
        assertEquals(cancellationCalls, foreignWorkflow.cancellationCalls());
        assertEquals(0, foreignWorkflow.foreignCalls());
    }

    private static void assertBidirectionalDispatchedForeignIsolation(
            FilesystemPkiStore store,
            PkiSigningBus controlBus, MatrixRemoteWorkflow controlWorkflow,
            RemoteAttempt controlDispatchedProbe, PkiSigningBus targetBus,
            MatrixRemoteWorkflow targetWorkflow,
            RemoteAttempt targetDispatchedProbe) {
        assertDispatchedForeignIsolation(
                store, controlBus, controlWorkflow, targetDispatchedProbe);
        assertDispatchedForeignIsolation(
                store, targetBus, targetWorkflow, controlDispatchedProbe);
    }

    private static void assertDispatchedForeignIsolation(FilesystemPkiStore store,
            PkiSigningBus foreignBus, MatrixRemoteWorkflow foreignWorkflow,
            RemoteAttempt ownedByOtherProvider) {
        SignWorkflowStore.Record active = store.getSignRecord(
                ownedByOtherProvider.id()).orElseThrow();
        assertEquals(SignWorkflowStore.State.DISPATCHED, active.state());
        assertTrue(active.fence() > 0L);
        AuthoritativeRecordSnapshot expected = AuthoritativeRecordSnapshot.capture(active);
        int submitCalls = foreignWorkflow.submitCalls();
        int statusCalls = foreignWorkflow.statusCalls();
        int cancellationCalls = foreignWorkflow.cancellationCalls();

        foreignWorkflow.offerForeignTerminal(ownedByOtherProvider.id());
        assertEquals(AsyncState.RUNNING,
                foreignBus.status(ownedByOtherProvider.id()).orElseThrow().state());
        expected.assertUnchanged(store.getSignRecord(ownedByOtherProvider.id()).orElseThrow());
        assertTrue(foreignBus.consumeResult(ownedByOtherProvider.id()).isEmpty());
        expected.assertUnchanged(store.getSignRecord(ownedByOtherProvider.id()).orElseThrow());

        assertEquals(submitCalls, foreignWorkflow.submitCalls());
        assertEquals(statusCalls, foreignWorkflow.statusCalls());
        assertEquals(cancellationCalls, foreignWorkflow.cancellationCalls());
        assertEquals(0, foreignWorkflow.foreignCalls());
    }

    private static LocalAttempt localAttempt(FilesystemPkiStore store, Instant now)
            throws Exception {
        byte[] payload = new byte[] { 1, 2, 3, 4 };
        DurableContentReference reference = operationReference(store, payload);
        String namespace = store.localSigningNamespace("zeroecho-lib");
        PkiId id = SigningSubmissionId.create(namespace, now, new SecureRandom()).id();
        SignatureWorkflow.SignRequest request = SignatureWorkflow.SignRequest.create(id,
                namespace, testConfigurationCommitment(), 1L, TEST_ACCESS,
                new KeyRef("zeroecho-lib:test.prv"),
                TEST_ALGORITHM, SignatureWorkflow.ContentCommitment.sha256(payload),
                new ImmutableByteContent(payload), Optional.of(Encoding.BINARY),
                Optional.of(now.plusSeconds(30)));
        EncodedObject continuation = new PkiSigningBus.SignContinuation(TEST_ACCESS,
                TEST_ALGORITHM, reference, new KeyRef("zeroecho-lib:test.prv"),
                Encoding.BINARY, Optional.of(id)).encode();
        SignWorkflowStore.Record intent = new SignWorkflowStore.Record(id, namespace,
                request.semanticFingerprint(), request.configurationCommitment(), TEST_OWNER, now,
                now.plusSeconds(30), continuation,
                SignWorkflowStore.State.INTENT, 0L, 0L, Optional.empty(),
                Optional.of("INTENT"), Optional.empty(), Optional.empty(), 0,
                Optional.empty(), Optional.empty());
        return new LocalAttempt(id, request, intent, reference);
    }

    private static SignatureWorkflow.OperationStatus invokeDeterministicCrypto(
            AtomicInteger invocations, Instant completedAt) {
        invocations.incrementAndGet();
        SignatureWorkflow.OperationResult result = new SignatureWorkflow.OperationResult(
                Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 91, 92 })),
                Optional.empty());
        return new SignatureWorkflow.OperationStatus(SignatureWorkflow.State.SUCCEEDED,
                completedAt, Optional.of("SIGNED"), Optional.of(result));
    }

    private static SignatureWorkflow.ConfigurationCommitment testConfigurationCommitment() {
        byte[] bytes = new byte[SignatureWorkflow.ConfigurationCommitment.BYTE_LENGTH];
        for (int index = 0; index < bytes.length; index++) {
            bytes[index] = (byte) index;
        }
        return new SignatureWorkflow.ConfigurationCommitment(bytes);
    }

    private static SignatureWorkflow.ConfigurationCommitment configurationCommitment(byte marker) {
        byte[] bytes = new byte[SignatureWorkflow.ConfigurationCommitment.BYTE_LENGTH];
        Arrays.fill(bytes, marker);
        return new SignatureWorkflow.ConfigurationCommitment(bytes);
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer: for (int offset = 0; offset <= haystack.length - needle.length; offset++) {
            for (int index = 0; index < needle.length; index++) {
                if (haystack[offset + index] != needle[index]) {
                    continue outer;
                }
            }
            return offset;
        }
        return -1;
    }

    private static SignWorkflowStore.Record copy(SignWorkflowStore.Record source, EncodedObject request,
            String fingerprint, SignWorkflowStore.State state, long revision, long fence, Optional<Instant> leaseUntil,
            Optional<String> detailCode, Optional<EncodedObject> result, Optional<Instant> providerUpdatedAt) {
        return new SignWorkflowStore.Record(source.submissionId(), source.namespace(), fingerprint,
                source.configurationCommitment(), source.owner(), source.createdAt(), source.deadline(), request,
                state, revision, fence, leaseUntil, detailCode, result,
                providerUpdatedAt, state == SignWorkflowStore.State.INTENT
                        || state == SignWorkflowStore.State.DISPATCHED
                        || state == SignWorkflowStore.State.CANCELLING ? source.failureCount() : 0,
                state == SignWorkflowStore.State.INTENT || state == SignWorkflowStore.State.DISPATCHED
                        || state == SignWorkflowStore.State.CANCELLING ? source.nextEligibleAt() : Optional.empty(),
                state == SignWorkflowStore.State.INTENT || state == SignWorkflowStore.State.DISPATCHED
                        || state == SignWorkflowStore.State.CANCELLING
                                ? source.reconciliationFailureClass() : Optional.empty());
    }

    private static SignWorkflowStore.Record withConfigurationCommitment(SignWorkflowStore.Record source,
            SignatureWorkflow.ConfigurationCommitment configurationCommitment) {
        return new SignWorkflowStore.Record(source.submissionId(), source.namespace(), source.fingerprint(),
                configurationCommitment, source.owner(), source.createdAt(), source.deadline(), source.request(),
                source.state(), source.revision(), source.fence(), source.leaseUntil(), source.detailCode(),
                source.result(), source.providerUpdatedAt(), source.failureCount(), source.nextEligibleAt(),
                source.reconciliationFailureClass());
    }

    private static SignatureWorkflow.ConfigurationCommitment changedConfigurationCommitment(
            SignatureWorkflow.ConfigurationCommitment source) {
        byte[] bytes = source.bytes();
        bytes[0] ^= 1;
        return new SignatureWorkflow.ConfigurationCommitment(bytes);
    }

    private static String flipFingerprint(String fingerprint) {
        int index = "signfp:v3:".length();
        char replacement = fingerprint.charAt(index) == '0' ? '1' : '0';
        return fingerprint.substring(0, index) + replacement + fingerprint.substring(index + 1);
    }

    private static void assertSemanticCorruptionRejected(Path root, CorruptionCase corruption) throws Exception {
        Instant createdAt = Instant.parse("2026-01-02T03:04:05.123Z");
        MutableClock clock = new MutableClock(createdAt);
        PkiId id;
        SignWorkflowStore.Record corrupted;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            id = persistDispatched(store, createdAt, 42);
            SignWorkflowStore.Record dispatched = store.getSignRecord(id).orElseThrow();
            clock.set(createdAt.plusSeconds(1));
            SignWorkflowStore.Record succeeded = store.transitionSign(id, dispatched.revision(), dispatched.fence(),
                    SignWorkflowStore.State.SUCCEEDED, Optional.of("SIGNED"),
                    Optional.of(new EncodedObject(Encoding.BINARY,
                            "valid-signature".getBytes(java.nio.charset.StandardCharsets.UTF_8))),
                    Optional.of(createdAt.plusSeconds(1))).orElseThrow();
            corrupted = corruption.mutation().apply(succeeded, store);
        }
        writeRawCurrentRecord(root, id, corrupted);
        String sensitiveRequest = "injected-signature";
        String sensitiveFingerprint = corrupted.fingerprint();
        List<String> beforeRecovery = rootFileState(root);
        try (InMemorySignatureWorkflow signer = new InMemorySignatureWorkflow(Map.of(), false)) {
            IllegalStateException activationFailure;
            try (FilesystemPkiStore reopened = new FilesystemPkiStore(
                    root, FsPkiStoreOptions.defaults(), clock)) {
                activationFailure = assertThrows(IllegalStateException.class,
                        () -> reopened.getSignRecord(id));
            }
            assertTrue(activationFailure.getMessage().contains("code=" + corruption.expectedCode()));
            assertFalse(activationFailure.toString().contains(sensitiveRequest));
            assertFalse(activationFailure.toString().contains(sensitiveFingerprint));
            assertFalse(activationFailure.toString().contains(id.value()));
            assertEquals(0, signer.submittedSignCount());
        }
        assertEquals(beforeRecovery, rootFileState(root));
    }

    private static void writeRawCurrentRecord(Path root, PkiId id, SignWorkflowStore.Record record) throws Exception {
        byte[] payload = FsCodec.encode(FsCodec.SIGN_WORKFLOW_RECORD, record);
        MetadataKey key = new MetadataKey("io.zeroecho.pki.signing-record", id.value());
        try (SegmentedTransactionalMetadataStore metadata = SegmentedTransactionalMetadataStore.open(
                new FsPaths(root).transactionalMetadataRoot());
                MetadataSnapshot snapshot = metadata.snapshot();
                MetadataTransaction transaction = metadata.beginTransaction()) {
            long revision = snapshot.get(key).orElseThrow().recordRevision();
            transaction.replace(key, revision, new TestContent(payload), CancellationSignal.NONE);
            assertEquals(zeroecho.pki.spi.store.MetadataCommitResult.Outcome.COMMITTED,
                    transaction.commit().outcome());
        }
    }

    private static List<String> rootFileState(Path root) throws Exception {
        List<Path> files;
        try (java.util.stream.Stream<Path> paths = Files.walk(root)) {
            files = paths.filter(Files::isRegularFile).sorted().toList();
        }
        List<String> state = new java.util.ArrayList<>(files.size());
        for (Path file : files) {
            byte[] bytes = Files.readAllBytes(file);
            state.add(root.relativize(file) + ":" + bytes.length + ":" + sha256(bytes));
        }
        return List.copyOf(state);
    }

    private static final class TestContent implements RepeatableContent {
        private final byte[] value;

        private TestContent(byte[] value) {
            this.value = value.clone();
        }

        @Override
        public InputStream openStream() {
            return new ByteArrayInputStream(value);
        }

        @Override
        public OptionalLong length() {
            return OptionalLong.of(value.length);
        }

        @Override
        public String contentId() {
            return "test-sign-record";
        }

        @Override
        public void close() {
            Arrays.fill(value, (byte) 0);
        }
    }

    private static final class CountingContent implements RepeatableContent {
        private final byte[] value;
        private final AtomicInteger reads;

        private CountingContent(byte[] value, AtomicInteger reads) {
            this.value = value.clone();
            this.reads = reads;
        }

        @Override
        public InputStream openStream() {
            reads.incrementAndGet();
            return new ByteArrayInputStream(value);
        }

        @Override public OptionalLong length() { return OptionalLong.of(value.length); }
        @Override public String contentId() { return "counting-sign-content"; }
        @Override public void close() { }
    }

    private static void assertRedactedStructuralFailure(byte[] encoded, String sensitiveFingerprint) {
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> FsCodec.decode(FsCodec.SIGN_WORKFLOW_RECORD, encoded));
        assertFalse(failure.toString().contains(sensitiveFingerprint));
    }

    private record CorruptionCase(String name,
            java.util.function.BiFunction<SignWorkflowStore.Record, FilesystemPkiStore, SignWorkflowStore.Record> mutation,
            String expectedCode) {
    }

    private record LocalAttempt(PkiId id, SignatureWorkflow.SignRequest request,
            SignWorkflowStore.Record intent, DurableContentReference reference) {
    }

    private record RemoteAttempt(PkiId id, String namespace,
            SignatureWorkflow.ConfigurationCommitment configurationCommitment) {
    }

    private record AuthoritativeRecordSnapshot(long revision, long fence,
            SignWorkflowStore.State state, Optional<EncodedObject> result,
            Optional<Instant> providerUpdatedAt, String namespace,
            byte[] configurationCommitment) {
        private AuthoritativeRecordSnapshot {
            configurationCommitment = configurationCommitment.clone();
        }

        private static AuthoritativeRecordSnapshot capture(SignWorkflowStore.Record record) {
            Optional<EncodedObject> copiedResult = record.result().map(value ->
                    new EncodedObject(value.encoding(), value.bytes()));
            return new AuthoritativeRecordSnapshot(record.revision(), record.fence(),
                    record.state(), copiedResult, record.providerUpdatedAt(), record.namespace(),
                    record.configurationCommitment().bytes());
        }

        private void assertUnchanged(SignWorkflowStore.Record current) {
            assertEquals(revision, current.revision());
            assertEquals(fence, current.fence());
            assertEquals(state, current.state());
            assertEquals(providerUpdatedAt, current.providerUpdatedAt());
            assertEquals(namespace, current.namespace());
            assertArrayEquals(configurationCommitment,
                    current.configurationCommitment().bytes());
            assertEquals(result.isPresent(), current.result().isPresent());
            if (result.isPresent()) {
                assertEquals(result.orElseThrow().encoding(),
                        current.result().orElseThrow().encoding());
                assertArrayEquals(result.orElseThrow().bytes(),
                        current.result().orElseThrow().bytes());
            }
        }

        @Override
        public byte[] configurationCommitment() {
            return configurationCommitment.clone();
        }
    }

    private enum SharedRemoteTerminalBoundary {
        PREVIOUS_DURABLE_IMAGE(LocalForceImage.PREVIOUS_DURABLE, false),
        COMPLETE_VISIBLE_IMAGE_BEFORE_FORCE(LocalForceImage.VISIBLE_BEFORE_FORCE, true),
        FORCE_COMPLETED_THEN_REPORTED_FAILURE(LocalForceImage.DELEGATE_THEN_FAIL, true);

        private final LocalForceImage image;
        private final boolean terminalRecovered;

        SharedRemoteTerminalBoundary(LocalForceImage image, boolean terminalRecovered) {
            this.image = image;
            this.terminalRecovered = terminalRecovered;
        }

        private LocalForceImage image() {
            return image;
        }

        private boolean terminalRecovered() {
            return terminalRecovered;
        }
    }

    private static final class MatrixRemoteWorkflow implements SignatureWorkflow {
        private final String workflowId;
        private final ConfigurationCommitment commitment;
        private final Instant completedAt;
        private final LocalFaultWalOperations terminalFault;
        private final byte[] signature;
        private final Map<PkiId, OperationStatus> statuses = new ConcurrentHashMap<>();
        private final Map<PkiId, AtomicInteger> submissionsByOperation =
                new ConcurrentHashMap<>();
        private final Map<PkiId, AtomicInteger> cryptographyByOperation =
                new ConcurrentHashMap<>();
        private final Set<PkiId> heldRunning = ConcurrentHashMap.newKeySet();
        private final AtomicInteger submitCalls = new AtomicInteger();
        private final AtomicInteger cryptoInvocations = new AtomicInteger();
        private final AtomicInteger statusCalls = new AtomicInteger();
        private final AtomicInteger cancellationCalls = new AtomicInteger();
        private final AtomicInteger foreignCalls = new AtomicInteger();
        private final AtomicBoolean armTerminalPublication = new AtomicBoolean();

        private MatrixRemoteWorkflow(String workflowId, ConfigurationCommitment commitment,
                Instant completedAt, LocalFaultWalOperations terminalFault) {
            this.workflowId = workflowId;
            this.commitment = commitment;
            this.completedAt = completedAt;
            this.terminalFault = terminalFault;
            this.signature = new byte[] { (byte) workflowId.hashCode(), 73 };
        }

        @Override
        public String id() {
            return workflowId;
        }

        @Override
        public ConfigurationCommitment configurationCommitment() {
            return commitment;
        }

        @Override
        public PkiId submitSign(SignRequest request, CallControl control) {
            submitCalls.incrementAndGet();
            submissionsByOperation.computeIfAbsent(
                    request.submissionId(), ignored -> new AtomicInteger()).incrementAndGet();
            requireOwned(request.submissionId(), request.namespace(),
                    request.configurationCommitment());
            statuses.computeIfAbsent(request.submissionId(), operationId -> {
                if (heldRunning.contains(operationId)) {
                    return new OperationStatus(State.RUNNING, completedAt,
                            Optional.of("RUNNING"), Optional.empty());
                }
                cryptoInvocations.incrementAndGet();
                cryptographyByOperation.computeIfAbsent(
                        operationId, ignored -> new AtomicInteger()).incrementAndGet();
                OperationResult result = new OperationResult(Optional.of(
                        new EncodedObject(Encoding.BINARY, signature)), Optional.empty());
                return new OperationStatus(State.SUCCEEDED, completedAt,
                        Optional.of("SIGNED"), Optional.of(result));
            });
            return request.submissionId();
        }

        @Override
        public PkiId submitVerify(VerifyRequest request, CallControl control) {
            throw new UnsupportedOperationException();
        }

        @Override
        public OperationStatus status(PkiId operationId, CallControl control) {
            statusCalls.incrementAndGet();
            requireOwned(operationId, SigningSubmissionId.parse(operationId).namespace(), commitment);
            if (armTerminalPublication.compareAndSet(true, false)) {
                terminalFault.armNextForce();
            }
            return statuses.getOrDefault(operationId, new OperationStatus(State.FAILED,
                    completedAt, Optional.of("UNKNOWN_OP"), Optional.empty()));
        }

        @Override
        public boolean cancel(PkiId operationId, long fencingToken, String reason,
                CallControl control) {
            requireOwned(operationId, SigningSubmissionId.parse(operationId).namespace(), commitment);
            cancellationCalls.incrementAndGet();
            return false;
        }

        @Override
        public Registration register(NotificationSink sink) {
            return () -> { };
        }

        @Override
        public Set<String> supportedAlgorithms() {
            return Set.of(TEST_ALGORITHM);
        }

        @Override
        public void close() {
            // Test provider state deliberately survives bus restart.
        }

        private void armTerminalPublication() {
            if (terminalFault == null || !armTerminalPublication.compareAndSet(false, true)) {
                throw new IllegalStateException("test terminal publication is already armed");
            }
        }

        private void holdRunning(PkiId operationId) {
            if (!heldRunning.add(operationId)) {
                throw new IllegalStateException("test signing operation is already held running");
            }
        }

        private void offerForeignTerminal(PkiId operationId) {
            OperationResult result = new OperationResult(Optional.of(
                    new EncodedObject(Encoding.BINARY, new byte[] { 99, 100 })), Optional.empty());
            statuses.put(operationId, new OperationStatus(State.SUCCEEDED, completedAt,
                    Optional.of("SIGNED"), Optional.of(result)));
        }

        private void requireOwned(PkiId operationId, String namespace,
                ConfigurationCommitment requestCommitment) {
            String expectedNamespace = SigningSubmissionId.parse(operationId).namespace();
            boolean owned = expectedNamespace.equals(namespace)
                    && expectedNamespace.endsWith("." + workflowId)
                    && commitment.matches(requestCommitment);
            if (!owned) {
                foreignCalls.incrementAndGet();
                throw new IllegalArgumentException("foreign test signing operation");
            }
        }

        private byte[] signature() {
            return signature.clone();
        }

        private int submitCalls() {
            return submitCalls.get();
        }

        private int cryptoInvocations() {
            return cryptoInvocations.get();
        }

        private int submitCalls(PkiId operationId) {
            AtomicInteger calls = submissionsByOperation.get(operationId);
            return calls == null ? 0 : calls.get();
        }

        private int cryptoInvocations(PkiId operationId) {
            AtomicInteger calls = cryptographyByOperation.get(operationId);
            return calls == null ? 0 : calls.get();
        }

        private int statusCalls() {
            return statusCalls.get();
        }

        private int cancellationCalls() {
            return cancellationCalls.get();
        }

        private int foreignCalls() {
            return foreignCalls.get();
        }
    }

    private enum LocalCommitBoundary {
        ACCEPT_BEFORE_DURABILITY,
        DISPATCHED_RESTART,
        TERMINAL_BEFORE_PERSISTENCE,
        TERMINAL_DELEGATE_THEN_FAIL;

        private SigningActiveWal.Operations operations() {
            return switch (this) {
                case ACCEPT_BEFORE_DURABILITY -> new LocalFaultWalOperations(
                        2, LocalForceImage.PREVIOUS_DURABLE);
                case DISPATCHED_RESTART -> null;
                case TERMINAL_BEFORE_PERSISTENCE -> new LocalFaultWalOperations(
                        3, LocalForceImage.PREVIOUS_DURABLE);
                case TERMINAL_DELEGATE_THEN_FAIL -> new LocalFaultWalOperations(
                        3, LocalForceImage.DELEGATE_THEN_FAIL);
            };
        }

        private boolean isTerminalBoundary() {
            return this == TERMINAL_BEFORE_PERSISTENCE
                    || this == TERMINAL_DELEGATE_THEN_FAIL;
        }
    }

    private enum LocalForceImage {
        PREVIOUS_DURABLE,
        VISIBLE_BEFORE_FORCE,
        DELEGATE_THEN_FAIL
    }

    private static final class FailThirdWalForce extends LocalFaultWalOperations {
        private FailThirdWalForce() {
            super(3, LocalForceImage.VISIBLE_BEFORE_FORCE);
        }
    }

    private static class LocalFaultWalOperations implements SigningActiveWal.Operations {
        private final AtomicInteger forces = new AtomicInteger();
        private final int faultOrdinal;
        private final LocalForceImage image;
        private final AtomicInteger armedFaultOrdinal = new AtomicInteger(-1);
        private long durableLength;
        private volatile boolean injected;

        private LocalFaultWalOperations(int faultOrdinal, LocalForceImage image) {
            this.faultOrdinal = faultOrdinal;
            this.image = image;
        }

        private LocalFaultWalOperations(LocalForceImage image) {
            this(-1, image);
        }

        private void armNextForce() {
            int next = forces.get() + 1;
            if (faultOrdinal > 0 || injected
                    || !armedFaultOrdinal.compareAndSet(-1, next)) {
                throw new IllegalStateException("test WAL force fault cannot be armed");
            }
        }

        @Override public boolean exists(Path path) {
            return Files.exists(path, LinkOption.NOFOLLOW_LINKS);
        }
        @Override public boolean isRegularFile(Path path) {
            return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS);
        }
        @Override public SigningActiveWal.WalChannel createNew(Path path) throws java.io.IOException {
            return wrap(FileChannel.open(path, Set.of(StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.READ, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)));
        }
        @Override public SigningActiveWal.WalChannel openExisting(Path path) throws java.io.IOException {
            return wrap(FileChannel.open(path, Set.of(StandardOpenOption.READ,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)));
        }
        @Override public void forceDirectory(Path directory) throws java.io.IOException {
            // Route through the platform seam: a directory fsync on POSIX, a
            // correct no-op on Windows (a directory cannot be opened as a channel).
            SigningFormatSupport.forceDirectory(directory);
        }
        private SigningActiveWal.WalChannel wrap(FileChannel channel) {
            return new SigningActiveWal.WalChannel() {
                @Override public int read(ByteBuffer target) throws java.io.IOException {
                    return channel.read(target);
                }
                @Override public int write(ByteBuffer source) throws java.io.IOException {
                    return channel.write(source);
                }
                @Override public long position() throws java.io.IOException { return channel.position(); }
                @Override public SigningActiveWal.WalChannel position(long value)
                        throws java.io.IOException {
                    channel.position(value);
                    return this;
                }
                @Override public long size() throws java.io.IOException { return channel.size(); }
                @Override public SigningActiveWal.WalChannel truncate(long size)
                        throws java.io.IOException {
                    channel.truncate(size);
                    return this;
                }
                @Override public boolean isOpen() { return channel.isOpen(); }
                @Override public void close() throws java.io.IOException { channel.close(); }
                @Override public void force(boolean metadata) throws java.io.IOException {
                    int ordinal = forces.incrementAndGet();
                    int selectedOrdinal = faultOrdinal > 0
                            ? faultOrdinal : armedFaultOrdinal.get();
                    if (!injected && ordinal == selectedOrdinal) {
                        injected = true;
                        switch (image) {
                            case PREVIOUS_DURABLE -> {
                                channel.truncate(durableLength);
                                channel.force(metadata);
                            }
                            case VISIBLE_BEFORE_FORCE -> {
                                // The complete group reached the page cache before force.
                            }
                            case DELEGATE_THEN_FAIL -> {
                                channel.force(metadata);
                                durableLength = channel.size();
                            }
                        }
                        throw new java.io.IOException("injected force boundary failure");
                    }
                    channel.force(metadata);
                    durableLength = channel.size();
                }
            };
        }
    }

    private static final class MutableClock extends Clock {
        private final AtomicBoolean block = new AtomicBoolean();
        private final CountDownLatch observed = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);
        private volatile Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        private void set(Instant value) {
            this.instant = value;
        }

        private void arm(Instant value) {
            this.instant = value;
            block.set(true);
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            Instant observedValue = instant;
            if (block.compareAndSet(true, false)) {
                observed.countDown();
                try {
                    release.await();
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(ex);
                }
            }
            return observedValue;
        }
    }
}
