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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.publication.PublicationTargetType;
import zeroecho.pki.api.schedule.StatusSchedule;
import zeroecho.pki.api.schedule.StatusScheduleState;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.TransactionalMetadataStore;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.PkiSessionConfiguration;

class FilesystemStatusScheduleTest {
    private static final Instant NOW = Instant.parse("2026-10-05T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    @TempDir Path temporary;

    @Test void oldVersion18WithoutScheduleNamespaceIsEmptyAndReopens() throws Exception {
        try (FilesystemPkiStore store = open(temporary)) {
            assertTrue(store.getStatusSchedule(new PkiId("absent"), StatusObjectType.CRL).isEmpty());
            assertTrue(store.listActiveStatusSchedulesPage(Optional.empty(), 10, CancellationSignal.NONE).isEmpty());
        }
        assertEquals("v18", Files.readString(temporary.resolve("VERSION")));
        try (FilesystemPkiStore store = open(temporary)) {
            assertTrue(store.listStatusScheduleWork(Optional.empty(), 10, CancellationSignal.NONE).isEmpty());
        }
    }

    @Test void persistsEveryConfigurationFieldAndPreservesCreationTime() throws Exception {
        StatusSchedule first;
        StatusSchedule replacement;
        try (FilesystemPkiStore store = open(temporary)) {
            first = store.putStatusSchedule(schedule("ca:日本/žluťoučký", StatusObjectType.CRL, true, 99));
            assertEquals(1, first.revision());
            assertEquals(NOW, store.getStatusScheduleState(first.caId(), first.statusType()).orElseThrow().nextDue());
            StatusSchedule supplied = new StatusSchedule(first.caId(), first.statusType(), new FormatId("other-format"),
                    Duration.ofMinutes(17), 42, false, Optional.empty(), NOW.plusSeconds(1), NOW.plusSeconds(2), 500);
            replacement = store.putStatusSchedule(supplied);
            assertEquals(first.createdAt(), replacement.createdAt());
            assertEquals(supplied.updatedAt(), replacement.updatedAt());
            assertEquals(2, replacement.revision());
            assertEquals(Duration.ofMinutes(17), replacement.interval());
            assertTrue(store.listActiveStatusSchedulesPage(Optional.empty(), 10, CancellationSignal.NONE).isEmpty());
        }
        try (FilesystemPkiStore store = open(temporary)) {
            assertEquals(replacement, store.getStatusSchedule(first.caId(), first.statusType()).orElseThrow());
            assertEquals(0, store.getStatusScheduleState(first.caId(), first.statusType()).orElseThrow().workerRevision());
        }
    }

    @Test void compareAndReplaceHasOneConcurrentWinnerAndMonotonicRevision() throws Exception {
        try (FilesystemPkiStore store = open(temporary); java.util.concurrent.ExecutorService pool = Executors.newFixedThreadPool(2)) {
            StatusSchedule original = store.putStatusSchedule(schedule("ca", StatusObjectType.CRL, true, 0));
            StatusSchedule disabled = schedule("ca", StatusObjectType.CRL, false, 0);
            CountDownLatch ready = new CountDownLatch(2);
            CountDownLatch start = new CountDownLatch(1);
            List<Future<Boolean>> attempts = new ArrayList<>();
            for (int index = 0; index < 2; index++) attempts.add(pool.submit(() -> {
                ready.countDown(); start.await(); return store.replaceStatusSchedule(original, disabled);
            }));
            ready.await(); start.countDown();
            int winners = 0;
            for (Future<Boolean> attempt : attempts) if (attempt.get()) winners++;
            assertEquals(1, winners);
            StatusSchedule current = store.getStatusSchedule(original.caId(), original.statusType()).orElseThrow();
            assertEquals(2, current.revision());
            assertFalse(store.replaceStatusSchedule(original, disabled));
            assertEquals(3, store.putStatusSchedule(original).revision());
            assertThrows(IllegalArgumentException.class, () -> store.replaceStatusSchedule(current,
                    schedule("other", StatusObjectType.CRL, true, 0)));
        }
    }

    @Test void compositePagesIncludeEveryEnabledFamilyWithoutRepeatsOrDisabledGaps() throws Exception {
        try (FilesystemPkiStore store = open(temporary)) {
            for (String ca : List.of("a", "a:CRL", "a/DELTA_CRL", "ž", "日本")) {
                store.putStatusSchedule(schedule(ca, StatusObjectType.CRL, true, 0));
                store.putStatusSchedule(schedule(ca, StatusObjectType.DELTA_CRL, true, 0));
                store.putStatusSchedule(schedule(ca, StatusObjectType.OCSP, false, 0));
            }
            List<String> collected = new ArrayList<>();
            Optional<String> cursor = Optional.empty();
            for (;;) {
                List<StatusSchedule> page = store.listActiveStatusSchedulesPage(cursor, 1, CancellationSignal.NONE);
                if (page.isEmpty()) break;
                StatusSchedule value = page.getFirst();
                collected.add(value.caId().value() + "|" + value.statusType());
                cursor = Optional.of(PkiStore.statusScheduleCursor(value));
            }
            assertEquals(List.of("a|CRL", "a|DELTA_CRL", "a/DELTA_CRL|CRL", "a/DELTA_CRL|DELTA_CRL",
                    "a:CRL|CRL", "a:CRL|DELTA_CRL", "ž|CRL", "ž|DELTA_CRL", "日本|CRL", "日本|DELTA_CRL"), collected);
            assertThrows(UnsupportedOperationException.class, () ->
                    store.listActiveStatusSchedulesPage(Optional.empty(), 2, CancellationSignal.NONE).clear());
        }
    }

    @Test void invalidUnicodeCannotAliasAnExistingAuthority() throws Exception {
        try (FilesystemPkiStore store = open(temporary)) {
            StatusSchedule ordinary = store.putStatusSchedule(schedule("?", StatusObjectType.CRL, true, 0));
            for (String malformed : List.of("\uD800", "\uDC00", "x\uD800y")) {
                assertThrows(IllegalArgumentException.class, () -> schedule(malformed, StatusObjectType.CRL, true, 0));
                assertThrows(IllegalArgumentException.class, () -> store.getStatusSchedule(new PkiId(malformed), StatusObjectType.CRL));
            }
            assertEquals(ordinary, store.getStatusSchedule(new PkiId("?"), StatusObjectType.CRL).orElseThrow());
            assertNotEquals(FsStatusSchedules.key(new PkiId("a:CRL"), StatusObjectType.DELTA_CRL),
                    FsStatusSchedules.key(new PkiId("a"), StatusObjectType.CRL));
        }
    }

    @Test void malformedCursorsAndInvalidBoundsAreRejected() throws Exception {
        try (FilesystemPkiStore store = open(temporary)) {
            for (String cursor : List.of("", "ca:CRL", ".CRL", "YQ==.CRL", "_w.CRL", "YQ.UNKNOWN", "IA.CRL")) {
                assertThrows(IllegalArgumentException.class, () ->
                        store.listActiveStatusSchedulesPage(Optional.of(cursor), 1, CancellationSignal.NONE), cursor);
            }
            for (int limit : List.of(-1, 0, 1002)) assertThrows(IllegalArgumentException.class, () ->
                    store.listActiveStatusSchedulesPage(Optional.empty(), limit, CancellationSignal.NONE));
            store.putStatusSchedule(schedule("ca", StatusObjectType.CRL, true, 0));
            assertThrows(RuntimeException.class, () -> store.listActiveStatusSchedulesPage(Optional.empty(), 1, () -> true));
        }
    }

    @Test void deterministicClaimSurvivesRestartAndExplicitEditFencesUnacceptedWork() throws Exception {
        StatusScheduleState.Execution claimed;
        try (FilesystemPkiStore store = open(temporary)) {
            StatusSchedule config = store.putStatusSchedule(schedule("ca", StatusObjectType.CRL, true, 0));
            StatusScheduleState head = store.getStatusScheduleState(config.caId(), config.statusType()).orElseThrow();
            claimed = store.claimStatusSchedule(head).orElseThrow();
            assertTrue(store.claimStatusSchedule(head).isEmpty());
            String canonical = "status-schedule-execution:v1:2:ca:1:CRL:" + NOW;
            assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(canonical.getBytes(java.nio.charset.StandardCharsets.UTF_8))), claimed.executionId());
            assertEquals(claimed, store.listStatusScheduleWork(Optional.empty(), 1, CancellationSignal.NONE)
                    .getFirst().execution().orElseThrow());
        }
        try (FilesystemPkiStore store = open(temporary)) {
            StatusScheduleState recovered = store.getStatusScheduleState(new PkiId("ca"), StatusObjectType.CRL).orElseThrow();
            assertEquals(claimed, recovered.execution().orElseThrow());
            assertEquals(1, recovered.configuration().revision());
            assertEquals(1, recovered.workerRevision());
            store.putStatusSchedule(schedule("ca", StatusObjectType.CRL, false, 0));
            StatusScheduleState edited = store.getStatusScheduleState(new PkiId("ca"), StatusObjectType.CRL).orElseThrow();
            assertTrue(edited.execution().isEmpty());
            assertEquals(2, edited.workerRevision());
            assertTrue(store.claimStatusSchedule(recovered).isEmpty());
            assertTrue(store.listStatusScheduleWork(Optional.empty(), 1, CancellationSignal.NONE).isEmpty());
        }
    }

    @ParameterizedTest @ValueSource(strings = {"future", "negative-revision", "negative-worker", "truncated", "trailing", "wrong-key", "duplicate"})
    void invalidPersistedHeadsRejectOpen(String corruption) throws Exception {
        Path root = temporary.resolve(corruption);
        try (FilesystemPkiStore store = open(root)) {
            StatusSchedule stored = store.putStatusSchedule(schedule("ca", StatusObjectType.CRL, true, 0));
            MetadataKey key = FsStatusSchedules.key(stored.caId(), stored.statusType());
            byte[] bytes = rawHead(stored, corruption.equals("future") ? 2 : 1,
                    corruption.equals("negative-revision") ? -1 : 1,
                    corruption.equals("negative-worker") ? -1 : 0);
            if (corruption.equals("truncated")) bytes = java.util.Arrays.copyOf(bytes, bytes.length - 1);
            if (corruption.equals("trailing")) bytes = java.util.Arrays.copyOf(bytes, bytes.length + 1);
            try (MetadataSnapshot snapshot = store.metadataStore().snapshot();
                    MetadataTransaction transaction = store.metadataStore().beginTransaction();
                    MetadataSnapshot.Record old = snapshot.get(key).orElseThrow();
                    ImmutableByteContent content = new ImmutableByteContent(bytes)) {
                if (corruption.equals("wrong-key") || corruption.equals("duplicate")) {
                    transaction.create(FsStatusSchedules.key(new PkiId("different"), StatusObjectType.CRL), content, CancellationSignal.NONE);
                    if (corruption.equals("wrong-key")) transaction.delete(key, old.recordRevision());
                } else transaction.replace(key, old.recordRevision(), content, CancellationSignal.NONE);
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
            }
        }
        assertThrows(IllegalStateException.class, () -> open(root));
        assertEquals("v18", Files.readString(root.resolve("VERSION")));
    }

    @Test void invalidCadenceAndGraceAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new StatusSchedule(new PkiId("ca"), StatusObjectType.CRL,
                new FormatId("x509"), Duration.ofSeconds(60).plusNanos(1), 60, true, Optional.empty(), NOW, NOW, 0));
        assertThrows(IllegalArgumentException.class, () -> new StatusSchedule(new PkiId("ca"), StatusObjectType.CRL,
                new FormatId("x509"), Duration.ofSeconds(59), 0, true, Optional.empty(), NOW, NOW, 0));
        for (long grace : List.of(-1L, 60L, Long.MAX_VALUE)) assertThrows(IllegalArgumentException.class, () ->
                new StatusSchedule(new PkiId("ca"), StatusObjectType.CRL, new FormatId("x509"),
                        Duration.ofMinutes(1), grace, true, Optional.empty(), NOW, NOW, 0));
    }

    @Test void longIdentityRoundTripsThroughApplicationPagination() throws Exception {
        String first = "a".repeat(800);
        String second = "b".repeat(800);
        try (FilesystemPkiStore store = open(temporary)) {
            store.putStatusSchedule(schedule(first, StatusObjectType.CRL, true, 0));
            store.putStatusSchedule(schedule(second, StatusObjectType.CRL, true, 0));
        }
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("fs", Map.of("root", temporary.toString())),
                new ProviderConfig("memory", Map.of("size", "16")), Optional.empty(), List.of(), List.of());
        try (PkiSession session = PkiSession.open(configuration)) {
            PkiOperationResult page = assertInstanceOf(PkiOperationOutcome.Completed.class,
                    session.operations().execute(new PkiOperation.ListStatusSchedules(1), CancellationSignal.NONE)).result();
            String cursor = assertInstanceOf(PkiOperationValue.Text.class, page.field("nextCursor").orElseThrow()).value();
            assertTrue(cursor.length() <= 1024);
            PkiOperationResult next = assertInstanceOf(PkiOperationOutcome.Completed.class,
                    session.operations().execute(new PkiOperation.ListStatusSchedules(1, Optional.of(cursor)), CancellationSignal.NONE)).result();
            PkiOperationValue.ListValue rows = assertInstanceOf(PkiOperationValue.ListValue.class, next.field("schedules").orElseThrow());
            assertEquals(new PkiOperationValue.Text(second), assertInstanceOf(PkiOperationValue.ObjectValue.class,
                    rows.values().getFirst()).fields().get("caId"));
            assertTrue(next.field("nextCursor").isEmpty());
        }
    }

    @Test void capacityFailureDoesNotRetryOrMasqueradeAsCasConflict() throws Exception {
        try (FilesystemPkiStore store = open(temporary)) {
            AtomicInteger attempts = new AtomicInteger();
            FsStatusSchedules schedules = new FsStatusSchedules(faulting(store.metadataStore(), attempts,
                    MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED, Integer.MAX_VALUE), ignored -> { });
            StatusSchedule requested = schedule("ca", StatusObjectType.CRL, true, 0);
            assertThrows(IOException.class, () -> schedules.put(requested, Optional.empty(), NOW));
            assertEquals(1, attempts.get());
            assertTrue(store.getStatusSchedule(requested.caId(), requested.statusType()).isEmpty());
            StatusSchedule prior = store.putStatusSchedule(requested);
            assertThrows(IOException.class, () -> schedules.put(requested, Optional.of(prior), NOW));
            assertEquals(2, attempts.get());
            assertEquals(prior, store.getStatusSchedule(prior.caId(), prior.statusType()).orElseThrow());
        }
    }

    @Test void onlyConflictsRetryAndPersistentConflictsAreBounded() throws Exception {
        try (FilesystemPkiStore store = open(temporary)) {
            AtomicInteger attempts = new AtomicInteger();
            FsStatusSchedules transientConflict = new FsStatusSchedules(faulting(store.metadataStore(), attempts,
                    MetadataCommitResult.FailureCategory.CONFLICT, 1), ignored -> { });
            assertEquals(1, transientConflict.put(schedule("ca", StatusObjectType.CRL, true, 0), Optional.empty(), NOW).revision());
            assertEquals(2, attempts.get());
            attempts.set(0);
            FsStatusSchedules persistentConflict = new FsStatusSchedules(faulting(store.metadataStore(), attempts,
                    MetadataCommitResult.FailureCategory.CONFLICT, Integer.MAX_VALUE), ignored -> { });
            assertThrows(IOException.class, () -> persistentConflict.put(schedule("other", StatusObjectType.CRL, true, 0), Optional.empty(), NOW));
            assertEquals(16, attempts.get());
            assertTrue(store.getStatusSchedule(new PkiId("other"), StatusObjectType.CRL).isEmpty());
        }
    }

    private static TransactionalMetadataStore faulting(TransactionalMetadataStore delegate, AtomicInteger attempts,
            MetadataCommitResult.FailureCategory category, int failures) {
        return (TransactionalMetadataStore) Proxy.newProxyInstance(TransactionalMetadataStore.class.getClassLoader(),
                new Class<?>[]{TransactionalMetadataStore.class}, (proxy, method, arguments) -> {
                    try {
                        Object result = method.invoke(delegate, arguments);
                        if (!method.getName().equals("beginTransaction")) return result;
                        MetadataTransaction transaction = (MetadataTransaction) result;
                        return Proxy.newProxyInstance(MetadataTransaction.class.getClassLoader(), new Class<?>[]{MetadataTransaction.class},
                                (ignored, action, parameters) -> {
                                    if (action.getName().equals("commit") && attempts.incrementAndGet() <= failures) {
                                        return new MetadataCommitResult(transaction.id(), MetadataCommitResult.Outcome.NOT_COMMITTED,
                                                OptionalLong.empty(), Optional.of(category));
                                    }
                                    try { return action.invoke(transaction, parameters); }
                                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                                });
                    } catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
    }

    private static byte[] rawHead(StatusSchedule value, int version, long revision, long workerRevision) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.writeInt(version); out.writeUTF(value.caId().value()); out.writeUTF(value.statusType().name());
            out.writeUTF(value.formatId().value()); out.writeUTF(value.interval().toString());
            out.writeLong(value.graceSeconds()); out.writeBoolean(value.enabled()); out.writeBoolean(value.publicationTarget().isPresent());
            if (value.publicationTarget().isPresent()) {
                out.writeUTF(value.publicationTarget().orElseThrow().type().name());
                out.writeUTF(value.publicationTarget().orElseThrow().targetId());
            }
            out.writeUTF(value.createdAt().toString()); out.writeUTF(value.updatedAt().toString()); out.writeLong(revision);
            out.writeUTF(NOW.toString()); out.writeLong(workerRevision); out.writeBoolean(false);
        }
        return bytes.toByteArray();
    }

    private static StatusSchedule schedule(String ca, StatusObjectType type, boolean enabled, long revision) {
        return new StatusSchedule(new PkiId(ca), type, new FormatId("x509"), Duration.ofMinutes(10), 30,
                enabled, Optional.of(new PublicationTarget(PublicationTargetType.CUSTOM, "publisher-1")), NOW, NOW, revision);
    }

    private static FilesystemPkiStore open(Path root) { return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK); }
}
