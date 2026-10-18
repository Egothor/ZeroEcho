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
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.application.RevocationExecutionEvidence;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.fs.DurableTransactionalMetadataStore;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.RevocationTransitionFeed;

final class RevocationAuditProjectorTest {
    private static final MetadataStoreId SOURCE =
            new MetadataStoreId("abcdefabcdefabcdefabcdefabcdefab");
    private static final MetadataStoreId FOREIGN =
            new MetadataStoreId("abcdefabcdefabcdefabcdefabcdefac");
    private static final Instant NOW = Instant.parse("2026-08-21T12:00:00Z");
    private static final String PLAINTEXT = "ticket-secret-42";

    @TempDir Path temporaryDirectory;

    @Test
    void mapsAdministrativeAndAcmeEvidenceExactlyAndSkipsLegacy() throws Exception {
        FeedSource source = new FeedSource(SOURCE);
        source.add("credential:ordinary", administrative(RevocationExecutionEvidence.AuthorizationPath.ORDINARY_GRANT,
                "operator-ordinary", "request-ordinary"));
        source.add("credential:approval", administrative(RevocationExecutionEvidence.AuthorizationPath.APPROVAL,
                "operator-approval", "request-approval"));
        source.add("credential:break-glass", administrative(RevocationExecutionEvidence.AuthorizationPath.BREAK_GLASS,
                "operator-break-glass", "request-break-glass"));
        source.add("credential:acme", RevocationExecutionEvidence.acme("account-7",
                ServerTestSupport.REALM.value(), "request-acme").attributes());
        source.addLegacy("credential:legacy");
        List<AuditEvent> events = new ArrayList<>();

        try (ServerTestSupport.OpenedStore opened = openStore("mapping")) {
            RevocationAuditProjector projector = projector(source, opened.store(), new MutableClock(NOW), events::add);
            RevocationAuditProjector.PassResult result = projector.project(10, 10);
            assertEquals(5, result.examined());
            assertEquals(4, result.sinkCalls());
            assertEquals(5, result.advanced());
            assertTrue(result.endReached());
            assertFalse(result.blocked());
            assertEquals(4, events.size());
            assertAdministrative(events.get(0), "operator-ordinary", "ORDINARY_GRANT");
            assertAdministrative(events.get(1), "operator-approval", "APPROVAL");
            assertAdministrative(events.get(2), "operator-break-glass", "BREAK_GLASS");
            AuditEvent acme = events.get(3);
            assertEquals("ACME_ACCOUNT", acme.principal().type());
            assertEquals("account-7", acme.principal().name());
            assertEquals("ACME_ACCOUNT_JWS", acme.details().get("authentication"));
            assertEquals("ACME_OWNERSHIP", acme.details().get("authorization"));
            assertFalse(acme.details().containsKey("authorizationPath"));
            assertFalse(acme.details().containsKey("operationCommitment"));
            assertFalse(acme.details().containsKey("justificationCommitment"));
            assertEquals("credential:acme", acme.objectId().orElseThrow().value());
            assertEquals(NOW.plusSeconds(4), acme.time());
            assertEquals("KEY_COMPROMISE", acme.details().get("reason"));
            assertTrue(events.stream().map(AuditEvent::details).flatMap(details -> details.values().stream())
                    .noneMatch(PLAINTEXT::equals));
            assertTrue(events.stream().allMatch(event -> event.details().get("eventId").matches("[0-9a-f]{64}")));
            assertEquals(4, events.stream().map(event -> event.details().get("eventId")).distinct().count());
            String acmeEventId = events.get(3).details().get("eventId");
            RevocationAuditProjector.PassResult repeated = projector.project(10, 10);
            assertEquals(0, repeated.sinkCalls());
            assertEquals(4, events.size());
            assertEquals(acmeEventId, events.get(3).details().get("eventId"));

            ServerControlStore.Page<ServerControlStore.ProtocolRecord> records = opened.store().protocolRecords(
                    ServerControlStore.REVOCATION_AUDIT_PROJECTION, 0, 10);
            assertEquals(1, records.values().size());
            assertEquals(RevocationAuditProjectionState.RECORD_ID, records.values().getFirst().recordId());
            RevocationAuditProjectionState state = RevocationAuditProjectionState.load(opened.store())
                    .orElseThrow().state();
            assertEquals(source.entries().getLast().nextPosition(), state.lastPosition().orElseThrow());
            assertEquals(source.head().globalRevision(), state.observedHighRevision());
        }
    }

    @Test
    void poisonRetainsCursorAppliesBackoffAndBlocksLaterEntries() throws Exception {
        FeedSource source = new FeedSource(SOURCE);
        AttributeSet unknownVersion = SimpleAttributeSet.builder().put(
                new zeroecho.pki.api.attr.AttributeId(
                        "urn:zeroecho:pki:revocation-evidence:actor-type:v2"),
                new AttributeValue.StringValue("ADMIN_PRINCIPAL")).build();
        source.add("credential:poison", unknownVersion);
        source.add("credential:later", administrative(RevocationExecutionEvidence.AuthorizationPath.APPROVAL,
                "operator-later", "request-later"));
        MutableClock clock = new MutableClock(NOW);
        List<AuditEvent> events = new ArrayList<>();
        try (ServerTestSupport.OpenedStore opened = openStore("poison")) {
            RevocationAuditProjector projector = projector(source, opened.store(), clock, events::add);
            RevocationAuditProjector.PassResult first = projector.project(10, 10);
            assertEquals(1, first.examined());
            assertEquals(0, first.advanced());
            assertTrue(first.blocked());
            assertEquals(Optional.of(NOW.plusSeconds(1)), first.nextEligible());
            assertTrue(RevocationAuditProjectionState.load(opened.store()).orElseThrow().state()
                    .lastPosition().isEmpty());

            RevocationAuditProjector.PassResult backedOff = projector.project(10, 10);
            assertEquals(0, backedOff.examined());
            assertTrue(backedOff.blocked());
            clock.advanceSeconds(1);
            RevocationAuditProjector.PassResult second = projector.project(10, 10);
            assertEquals(1, second.examined());
            assertEquals(Optional.of(NOW.plusSeconds(3)), second.nextEligible());
            assertTrue(events.isEmpty());
        }
    }

    @Test
    void sinkFailureRetainsCursorAndCursorMovesOnlyAfterAcknowledgement() throws Exception {
        FeedSource source = new FeedSource(SOURCE);
        source.add("credential:first", administrative(RevocationExecutionEvidence.AuthorizationPath.ORDINARY_GRANT,
                "operator-a", "request-a"));
        source.add("credential:second", administrative(RevocationExecutionEvidence.AuthorizationPath.APPROVAL,
                "operator-b", "request-b"));
        MutableClock clock = new MutableClock(NOW);
        try (ServerTestSupport.OpenedStore opened = openStore("sink")) {
            projector(source, opened.store(), clock, event -> { }).project(0, 0);
            RevocationAuditProjector failing = projector(source, opened.store(), clock, event -> {
                assertTrue(RevocationAuditProjectionState.load(opened.store()).orElseThrow().state()
                        .lastPosition().isEmpty());
                clock.advanceSeconds(10);
                throw new IllegalStateException("sink unavailable");
            });
            RevocationAuditProjector.PassResult failed = failing.project(10, 10);
            assertEquals(1, failed.sinkCalls());
            assertEquals(0, failed.advanced());
            assertTrue(failed.blocked());
            assertEquals(Optional.of(NOW.plusSeconds(11)), failed.nextEligible());
            assertTrue(RevocationAuditProjectionState.load(opened.store()).orElseThrow().state()
                    .lastPosition().isEmpty());

            RevocationAuditProjector.PassResult immediate = failing.project(10, 10);
            assertEquals(0, immediate.examined());
            assertTrue(immediate.blocked());
            clock.advanceSeconds(1);
            List<AuditEvent> recovered = new ArrayList<>();
            RevocationAuditProjector.PassResult bounded = projector(source, opened.store(), clock, recovered::add)
                    .project(10, 1);
            assertEquals(2, bounded.examined());
            assertEquals(1, bounded.sinkCalls());
            assertEquals(1, bounded.advanced());
            assertEquals(source.entries().getFirst().nextPosition(), RevocationAuditProjectionState
                    .load(opened.store()).orElseThrow().state().lastPosition().orElseThrow());
            assertEquals("credential:first", recovered.getFirst().objectId().orElseThrow().value());
        }
    }

    @Test
    void cancellationAfterSinkAcknowledgementRetainsCursorAndRetryResumesWithoutLoss() throws Exception {
        FeedSource source = new FeedSource(SOURCE);
        source.add("credential:first", administrative(
                RevocationExecutionEvidence.AuthorizationPath.ORDINARY_GRANT, "operator-a", "request-a"));
        source.add("credential:second", administrative(
                RevocationExecutionEvidence.AuthorizationPath.APPROVAL, "operator-b", "request-b"));
        source.add("credential:third", administrative(
                RevocationExecutionEvidence.AuthorizationPath.BREAK_GLASS, "operator-c", "request-c"));
        AtomicBoolean cancelled = new AtomicBoolean();
        List<AuditEvent> attempts = new ArrayList<>();
        try (ServerTestSupport.OpenedStore opened = openStore("cancelled")) {
            RevocationAuditProjector interrupted = projector(source, opened.store(), new MutableClock(NOW), event -> {
                attempts.add(event);
                cancelled.set(true);
            });

            RevocationAuditProjector.PassResult partial = interrupted.project(10, 10, cancelled::get);

            assertEquals(1, partial.examined());
            assertEquals(1, partial.sinkCalls());
            assertEquals(0, partial.advanced());
            assertTrue(RevocationAuditProjectionState.load(opened.store()).isEmpty());
            cancelled.set(false);
            List<AuditEvent> resumed = new ArrayList<>();
            RevocationAuditProjector.PassResult completed = projector(source, opened.store(),
                    new MutableClock(NOW), resumed::add).project(10, 10, cancelled::get);
            assertEquals(3, completed.advanced());
            assertTrue(completed.endReached());
            assertEquals(3, resumed.size());
            assertEquals(attempts.getFirst().details().get("eventId"),
                    resumed.getFirst().details().get("eventId"));
            assertEquals(source.entries().getLast().nextPosition(), RevocationAuditProjectionState
                    .load(opened.store()).orElseThrow().state().lastPosition().orElseThrow());
        }
    }

    @Test
    void resumesAfterRestartAndReplaysStableIdAfterUncertainStateCommit() throws Exception {
        FeedSource restartSource = new FeedSource(SOURCE);
        restartSource.add("credential:first", administrative(
                RevocationExecutionEvidence.AuthorizationPath.ORDINARY_GRANT, "operator-a", "request-a"));
        restartSource.add("credential:second", administrative(
                RevocationExecutionEvidence.AuthorizationPath.APPROVAL, "operator-b", "request-b"));
        Path restartRoot = temporaryDirectory.resolve("restart");
        Path log;
        Files.createDirectories(restartRoot);
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(restartRoot)) {
            log = opened.log();
            List<AuditEvent> first = new ArrayList<>();
            projector(restartSource, opened.store(), new MutableClock(NOW), first::add).project(1, 1);
            assertEquals("credential:first", first.getFirst().objectId().orElseThrow().value());
        }
        try (ServerControlStore reopened = new ServerControlStore(DurableTransactionalMetadataStore.open(log,
                OptionalLong.of(1_048_576)))) {
            List<AuditEvent> resumed = new ArrayList<>();
            projector(restartSource, reopened, new MutableClock(NOW), resumed::add).project(10, 10);
            assertEquals(1, resumed.size());
            assertEquals("credential:second", resumed.getFirst().objectId().orElseThrow().value());
        }

        FeedSource uncertainSource = new FeedSource(SOURCE);
        uncertainSource.add("credential:uncertain", administrative(
                RevocationExecutionEvidence.AuthorizationPath.BREAK_GLASS, "operator-c", "request-c"));
        MutableClock clock = new MutableClock(NOW);
        List<AuditEvent> attempts = new ArrayList<>();
        try (ServerTestSupport.OpenedStore opened = openStore("uncertain")) {
            projector(uncertainSource, opened.store(), clock, event -> { }).project(0, 0);
            RevocationAuditProjector uncertain = projector(uncertainSource, opened.store(), clock, event -> {
                attempts.add(event);
                RevocationAuditProjectionState.Loaded current = RevocationAuditProjectionState.load(opened.store())
                        .orElseThrow();
                RevocationAuditProjectionState competing = current.state().fail(NOW.plusSeconds(1),
                        uncertainSource.head());
                RevocationAuditProjectionState.persist(opened.store(), Optional.of(current), competing);
            });
            assertThrows(IllegalStateException.class, () -> uncertain.project(10, 10));
            assertTrue(RevocationAuditProjectionState.load(opened.store()).orElseThrow().state()
                    .lastPosition().isEmpty());
            clock.advanceSeconds(1);
            projector(uncertainSource, opened.store(), clock, attempts::add).project(10, 10);
            assertEquals(2, attempts.size());
            assertEquals(attempts.get(0).details().get("eventId"), attempts.get(1).details().get("eventId"));
        }
    }

    @Test
    void foreignAndMalformedStateFailClosedBeforeSink() throws Exception {
        FeedSource source = new FeedSource(SOURCE);
        source.add("credential:first", administrative(RevocationExecutionEvidence.AuthorizationPath.ORDINARY_GRANT,
                "operator-a", "request-a"));
        List<AuditEvent> events = new ArrayList<>();
        try (ServerTestSupport.OpenedStore opened = openStore("foreign")) {
            RevocationAuditProjectionState foreign = new RevocationAuditProjectionState(FOREIGN, Optional.empty(),
                    0, Optional.empty(), source.head().globalRevision(), source.head().transitionCommitment());
            RevocationAuditProjectionState.persist(opened.store(), Optional.empty(), foreign);
            assertThrows(IllegalStateException.class,
                    () -> projector(source, opened.store(), new MutableClock(NOW), events::add).project(10, 10));
            assertTrue(events.isEmpty());
        }

        try (ServerTestSupport.OpenedStore opened = openStore("malformed")) {
            byte[] malformed = new byte[] { 1, 2, 3 };
            ServerControlStore.ProtocolRecord record = new ServerControlStore.ProtocolRecord(
                    ServerControlStore.REVOCATION_AUDIT_PROJECTION, RevocationAuditProjectionState.RECORD_ID,
                    digest(malformed), malformed);
            opened.store().mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(record, Optional.empty())));
            assertThrows(IllegalStateException.class,
                    () -> projector(source, opened.store(), new MutableClock(NOW), events::add).project(10, 10));
            assertTrue(events.isEmpty());
        }
    }

    private static AttributeSet administrative(RevocationExecutionEvidence.AuthorizationPath path,
            String actor, String request) {
        return RevocationExecutionEvidence.administrative(actor, ServerTestSupport.REALM.value(), request,
                RevocationExecutionEvidence.Authentication.DIRECT_MTLS, path, "a".repeat(64),
                Optional.of(PLAINTEXT)).attributes();
    }

    private ServerTestSupport.OpenedStore openStore(String name) throws IOException {
        Path directory = temporaryDirectory.resolve(name);
        Files.createDirectories(directory);
        return ServerTestSupport.open(directory);
    }

    private static RevocationAuditProjector projector(FeedSource source, ServerControlStore control,
            Clock clock, zeroecho.pki.spi.audit.AuditSink sink) {
        return new RevocationAuditProjector(ServerTestSupport.REALM, source.service(), control, clock, sink);
    }

    private static void assertAdministrative(AuditEvent event, String actor, String path) {
        assertEquals("ADMIN_PRINCIPAL", event.principal().type());
        assertEquals(actor, event.principal().name());
        assertEquals("ALLOWED", event.details().get("authorization"));
        assertEquals(path, event.details().get("authorizationPath"));
        assertEquals("a".repeat(64), event.details().get("operationCommitment"));
        assertNotEquals(PLAINTEXT, event.details().get("justificationCommitment"));
        assertEquals("COMMITTED", event.details().get("outcome"));
    }

    private static String digest(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static final class FeedSource {
        private final MetadataStoreId storeId;
        private final List<RevocationTransitionFeed.Entry> entries = new ArrayList<>();

        private FeedSource(MetadataStoreId storeId) {
            this.storeId = storeId;
        }

        private void add(String credentialId, AttributeSet attributes) {
            long revision = entries.size() + 1L;
            String commitment = "%064x".formatted(revision);
            RevocationTransition transition = new RevocationTransition(1L, RevocationState.PERMANENTLY_REVOKED,
                    NOW.plusSeconds(revision), Optional.of(RevocationReason.KEY_COMPROMISE), attributes);
            entries.add(new RevocationTransitionFeed.Entry(storeId, revision, commitment,
                    new RevocationTransitionFeed.Position("p-" + revision),
                    new RevocationRecord(new PkiId(credentialId), transition)));
        }

        private void addLegacy(String credentialId) {
            add(credentialId, SimpleAttributeSet.builder().put(new zeroecho.pki.api.attr.AttributeId("legacy.note"),
                    new AttributeValue.StringValue("legacy")).build());
        }

        private List<RevocationTransitionFeed.Entry> entries() {
            return List.copyOf(entries);
        }

        private RevocationTransitionFeed.HighWatermark head() {
            if (entries.isEmpty()) {
                return new RevocationTransitionFeed.HighWatermark(storeId, 0L, "0".repeat(64));
            }
            RevocationTransitionFeed.Entry last = entries.getLast();
            return new RevocationTransitionFeed.HighWatermark(storeId, last.globalRevision(),
                    last.transitionCommitment());
        }

        private RevocationService service() {
            RevocationService service = mock(RevocationService.class);
            when(service.feed(any())).thenAnswer(invocation -> open(invocation.getArgument(0)));
            return service;
        }

        private RevocationTransitionFeed open(Optional<RevocationTransitionFeed.Position> position) {
            int start = 0;
            if (position.isPresent()) {
                start = -1;
                for (int index = 0; index < entries.size(); index++) {
                    if (entries.get(index).nextPosition().equals(position.orElseThrow())) {
                        start = index + 1;
                        break;
                    }
                }
                if (start < 0) {
                    throw new IllegalArgumentException("Foreign test feed position");
                }
            }
            return new TestFeed(entries(), start, head());
        }
    }

    private static final class TestFeed implements RevocationTransitionFeed {
        private final List<Entry> entries;
        private final HighWatermark head;
        private int index;
        private Entry current;
        private boolean closed;

        private TestFeed(List<Entry> entries, int start, HighWatermark head) {
            this.entries = entries;
            this.index = start;
            this.head = head;
        }

        @Override public HighWatermark highWatermark() { requireOpen(); return head; }
        @Override public boolean next(CancellationSignal cancellation) throws IOException {
            requireOpen();
            cancellation.throwIfCancelled();
            if (index >= entries.size()) return false;
            current = entries.get(index++);
            return true;
        }
        @Override public Entry current() {
            requireOpen();
            if (current == null) throw new IllegalStateException("Test feed is not positioned");
            return current;
        }
        @Override public void close() { closed = true; current = null; }
        private void requireOpen() {
            if (closed) throw new IllegalStateException("Test feed is closed");
        }
    }

    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        private void advanceSeconds(long seconds) {
            instant = instant.plusSeconds(seconds);
        }

        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) {
            if (!ZoneOffset.UTC.equals(zone)) throw new IllegalArgumentException("Only UTC is supported");
            return this;
        }
        @Override public Instant instant() { return instant; }
    }
}
