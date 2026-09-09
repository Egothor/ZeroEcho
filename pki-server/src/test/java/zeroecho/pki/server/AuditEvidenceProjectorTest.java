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
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.store.AuditEvidenceFeed;

/** Bounded, resumable, idempotent behaviour of the generic evidence projector (Task 8a framework). */
class AuditEvidenceProjectorTest {
    private static final Instant TIME = Instant.parse("2026-08-04T12:00:00Z");

    @TempDir Path directory;

    @Test
    void projectsEmitsAdvancesCursorAndResumes() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            List<AuditEvidenceFeed.Entry> entries = List.of(entry(0, "obj-a"), entry(1, "obj-b"), entry(2, "obj-c"));
            RecordingSink sink = new RecordingSink();
            AuditEvidenceProjector projector = new AuditEvidenceProjector(opened.store(), "test-v1",
                    after -> new StubFeed(entries, after), AuditEvidenceProjectorTest::toEvent, sink,
                    ServerTestSupport.CLOCK);

            AuditEvidenceProjector.PassResult first = projector.project(4_096, 4_096);
            assertEquals(3, first.examined());
            assertEquals(3, first.emitted());
            assertTrue(first.endReached());
            assertEquals(3, sink.events.size());
            assertEquals("obj-a", sink.events.get(0).objectId().orElseThrow().value());

            // Durable cursor: a fresh projector reopened on the same store re-emits nothing.
            AuditEvidenceProjector resumed = new AuditEvidenceProjector(opened.store(), "test-v1",
                    after -> new StubFeed(entries, after), AuditEvidenceProjectorTest::toEvent, sink,
                    ServerTestSupport.CLOCK);
            AuditEvidenceProjector.PassResult second = resumed.project(4_096, 4_096);
            assertEquals(0, second.examined());
            assertEquals(3, sink.events.size());
        }
    }

    @Test
    void skippedEntriesStillAdvanceTheCursor() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            // "skip" objects map to no event but must still advance the cursor so they are not revisited.
            List<AuditEvidenceFeed.Entry> entries = List.of(entry(0, "skip"), entry(1, "obj-b"), entry(2, "skip"));
            RecordingSink sink = new RecordingSink();
            AuditEvidenceProjector projector = new AuditEvidenceProjector(opened.store(), "test-v1",
                    after -> new StubFeed(entries, after), AuditEvidenceProjectorTest::toEvent, sink,
                    ServerTestSupport.CLOCK);

            AuditEvidenceProjector.PassResult result = projector.project(4_096, 4_096);
            assertEquals(3, result.examined());
            assertEquals(1, result.emitted());
            assertEquals(1, sink.events.size());
            assertEquals("obj-b", sink.events.get(0).objectId().orElseThrow().value());
            assertEquals(0, projector.project(4_096, 4_096).examined());
        }
    }

    private static Optional<AuditEvent> toEvent(AuditEvidenceFeed.Entry entry) {
        if ("skip".equals(entry.objectId().value())) {
            return Optional.empty();
        }
        return Optional.of(new AuditEvent(entry.recordedAt(), "TEST", "PROJECTED",
                new Principal("USER", "actor"), new Purpose("TEST_PROJECTION"),
                Optional.of(entry.objectId()), Optional.empty(),
                Map.of("sequence", Long.toString(entry.sequence()))));
    }

    private static AuditEvidenceFeed.Entry entry(long sequence, String objectId) {
        return new AuditEvidenceFeed.Entry(sequence, new PkiId(objectId), TIME,
                objectId.getBytes(StandardCharsets.UTF_8));
    }

    private static final class RecordingSink implements AuditSink {
        private final List<AuditEvent> events = new ArrayList<>();
        @Override public void record(AuditEvent event) { events.add(event); }
    }

    private static final class StubFeed implements AuditEvidenceFeed {
        private final List<Entry> remaining = new ArrayList<>();
        private final long highWatermark;
        private Entry current;

        private StubFeed(List<Entry> entries, long afterSequenceExclusive) {
            long maximum = -1L;
            for (Entry entry : entries) {
                maximum = Math.max(maximum, entry.sequence());
                if (entry.sequence() > afterSequenceExclusive) {
                    remaining.add(entry);
                }
            }
            this.highWatermark = maximum + 1L;
        }

        @Override public long highWatermark() { return highWatermark; }

        @Override public boolean next(CancellationSignal cancellation) {
            if (remaining.isEmpty()) {
                current = null;
                return false;
            }
            current = remaining.remove(0);
            return true;
        }

        @Override public Entry current() {
            if (current == null) {
                throw new IllegalStateException("not positioned");
            }
            return current;
        }

        @Override public void close() { }
    }
}
