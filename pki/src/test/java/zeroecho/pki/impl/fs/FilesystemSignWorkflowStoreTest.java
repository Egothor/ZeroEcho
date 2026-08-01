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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static zeroecho.pki.testkit.PkiTestRuntime.signingAuthority;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.testkit.InMemorySignatureWorkflow;

final class FilesystemSignWorkflowStoreTest {

    private static final Principal TEST_OWNER = new Principal("TEST", "owner");
    private static final AccessContext TEST_ACCESS = new AccessContext(TEST_OWNER, new Purpose("SIGN"),
            Optional.empty(), Optional.empty());
    private static final KeyRef TEST_KEY = new KeyRef("test-key");
    private static final String TEST_ALGORITHM = "SHA256withRSA";

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
    void malformedCurrentRecordCannotActivateAttachOrExposeResult(@TempDir Path root) throws Exception {
        System.out.println("malformedCurrentRecordCannotActivateAttachOrExposeResult");
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
                InMemorySignatureWorkflow signer = new InMemorySignatureWorkflow(Map.of(), false)) {
            assertEquals(intent.fingerprint(), reopened.getSignRecord(id).orElseThrow().fingerprint());
            try (PkiSigningBus ignored = new PkiSigningBus(reopened, signer, root.resolve("bus.log"),
                    signingAuthority(signer))) {
                assertEquals(intent.fingerprint(), reopened.getSignRecord(id).orElseThrow().fingerprint());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void unsupportedFilesystemSigningRecordVersionCannotActivate(@TempDir Path root) throws Exception {
        System.out.println("unsupportedFilesystemSigningRecordVersionCannotActivate");
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
                InMemorySignatureWorkflow signer = new InMemorySignatureWorkflow(Map.of(), false)) {
            assertEquals(id, reopened.getSignRecord(id).orElseThrow().submissionId());
            try (PkiSigningBus ignored = new PkiSigningBus(reopened, signer,
                    root.resolve("unsupported-version-bus.log"), signingAuthority(signer))) {
                assertEquals(id, reopened.getSignRecord(id).orElseThrow().submissionId());
            }
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
                Duration.ZERO);
        EncodedObject request = new EncodedObject(Encoding.BINARY, new byte[] { 1, 2, 3 });
        PkiId id;
        SignWorkflowStore.Record intent;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options, clock)) {
            String namespace = store.signingNamespace() + ".test-signer";
            id = SigningSubmissionId.create(namespace, createdAt, new SecureRandom()).id();
            intent = intent(store, id, createdAt, request, TEST_ALGORITHM);
            assertEquals(SignWorkflowStore.CreateResult.CREATED, store.createSignIntent(intent));
            assertEquals(SignWorkflowStore.CreateResult.ATTACHED, store.createSignIntent(intent));
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
            SignWorkflowStore.Record active = reopened.getSignRecord(id).orElseThrow();
            SignWorkflowStore.Record failed = reopened
                    .transitionSign(id, active.revision(), active.fence(), SignWorkflowStore.State.FAILED,
                            Optional.of("PROVIDER_FAILED"), Optional.empty(), Optional.of(clock.instant()))
                    .orElseThrow();
            reopened.retireSign(id, failed.revision(), failed.fence()).orElseThrow();
            assertEquals(1, reopened.purgeExpiredSignRecords());
            assertFalse(reopened.getSignRecord(id).isPresent());
            assertThrows(IllegalArgumentException.class, () -> reopened.createSignIntent(intent));
        }
        try (FilesystemPkiStore foreign = new FilesystemPkiStore(root.resolve("foreign"), options, clock)) {
            assertThrows(IllegalArgumentException.class, () -> foreign.createSignIntent(intent));
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
            assertTrue(restored.getSignRecord(id).isEmpty());
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
        }
        clock.set(base.minusSeconds(120));
        try (FilesystemPkiStore restarted = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            assertEquals(high, restarted.signingNow());
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
                    SignWorkflowStore.State.CANCELLED, Optional.of("CANCELLED"), Optional.empty(), Optional.empty())
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
                new CorruptionCase("fingerprint-length",
                        (record, store) -> copy(record, record.request(), "signfp:v1:00", record.state(), record.revision(),
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

    private static SignWorkflowStore.Record intent(FilesystemPkiStore store, PkiId id, Instant createdAt,
            EncodedObject request,
            String algorithmId) {
        Instant deadline = createdAt.plusSeconds(60);
        PkiSigningBus.SignContinuation continuation = continuation(store, id, request, algorithmId);
        String namespace = SigningSubmissionId.parse(id).namespace();
        String fingerprint = continuation.semanticFingerprint(namespace, deadline);
        return new SignWorkflowStore.Record(id, namespace, fingerprint, TEST_OWNER, createdAt, deadline,
                continuation.encode(), SignWorkflowStore.State.INTENT, 0L, 0L, Optional.empty(), Optional.of("INTENT"),
                Optional.empty(), Optional.empty());
    }

    private static PkiId persistIntent(FilesystemPkiStore store, Instant createdAt, int marker) {
        String namespace = store.signingNamespace() + ".test-signer";
        PkiId id = SigningSubmissionId.create(namespace, createdAt, new SecureRandom()).id();
        store.createSignIntent(intent(store, id, createdAt,
                new EncodedObject(Encoding.BINARY, new byte[] { (byte) marker }), TEST_ALGORITHM));
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

    private static SignWorkflowStore.Record copy(SignWorkflowStore.Record source, EncodedObject request,
            String fingerprint, SignWorkflowStore.State state, long revision, long fence, Optional<Instant> leaseUntil,
            Optional<String> detailCode, Optional<EncodedObject> result, Optional<Instant> providerUpdatedAt) {
        return new SignWorkflowStore.Record(source.submissionId(), source.namespace(), fingerprint, source.owner(),
                source.createdAt(), source.deadline(), request, state, revision, fence, leaseUntil, detailCode, result,
                providerUpdatedAt);
    }

    private static String flipFingerprint(String fingerprint) {
        int index = "signfp:v1:".length();
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
        Path busLog = root.resolve("corrupt-bus.log");
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock);
                InMemorySignatureWorkflow signer = new InMemorySignatureWorkflow(Map.of(), false)) {
            IllegalStateException readFailure = assertThrows(IllegalStateException.class,
                    () -> reopened.getSignRecord(id));
            assertTrue(readFailure.getMessage().contains("code=" + corruption.expectedCode()));
            assertFalse(readFailure.toString().contains(sensitiveRequest));
            assertFalse(readFailure.toString().contains(sensitiveFingerprint));

            IllegalStateException activationFailure = assertThrows(IllegalStateException.class,
                    () -> new PkiSigningBus(reopened, signer, busLog, signingAuthority(signer)));
            assertTrue(activationFailure.getMessage().contains("code=" + corruption.expectedCode()));
            assertEquals(0, signer.submittedSignCount());
            assertThrows(IllegalStateException.class, () -> reopened.listSignRecords());
        }
        assertFalse(Files.exists(busLog) && Files.size(busLog) > 0L);
    }

    private static void writeRawCurrentRecord(Path root, PkiId id, SignWorkflowStore.Record record) throws Exception {
        byte[] payload = FsCodec.encode(FsCodec.SIGN_WORKFLOW_RECORD, record);
        MetadataKey key = new MetadataKey("io.zeroecho.pki.signing-record", id.value());
        try (PosixTransactionalMetadataStore metadata = PosixTransactionalMetadataStore.open(
                new FsPaths(root).transactionalMetadataLog());
                MetadataSnapshot snapshot = metadata.snapshot();
                MetadataTransaction transaction = metadata.beginTransaction()) {
            long revision = snapshot.get(key).orElseThrow().recordRevision();
            transaction.replace(key, revision, new TestContent(payload), CancellationSignal.NONE);
            assertEquals(zeroecho.pki.spi.store.MetadataCommitResult.Outcome.COMMITTED,
                    transaction.commit().outcome());
        }
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

    private static void assertRedactedStructuralFailure(byte[] encoded, String sensitiveFingerprint) {
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> FsCodec.decode(FsCodec.SIGN_WORKFLOW_RECORD, encoded));
        assertFalse(failure.toString().contains(sensitiveFingerprint));
    }

    private record CorruptionCase(String name,
            java.util.function.BiFunction<SignWorkflowStore.Record, FilesystemPkiStore, SignWorkflowStore.Record> mutation,
            String expectedCode) {
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
