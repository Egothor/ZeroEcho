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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.OptionalLong;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.store.MetadataStoreId;

/** Ordered, idempotent, resumable behaviour of the reusable append-only evidence log. */
class MetadataEvidenceLogTest {
    private static final MetadataStoreId STORE_ID = new MetadataStoreId("0123456789abcdef0123456789abcdef");
    private static final String NAMESPACE = "io.zeroecho.pki.test-evidence";
    private static final Instant TIME = Instant.parse("2026-08-04T12:00:00Z");

    @TempDir Path directory;

    @Test
    void appendsAreMonotonicIdempotentAndResumable() throws Exception {
        try (DurableTransactionalMetadataStore store = DurableTransactionalMetadataStore.create(
                directory.resolve("meta.log"), STORE_ID, OptionalLong.of(1L << 20))) {
            MetadataEvidenceLog log = new MetadataEvidenceLog(store, NAMESPACE);

            assertTrue(log.append(new PkiId("obj-a"), TIME, "A".getBytes(StandardCharsets.UTF_8)));
            assertTrue(log.append(new PkiId("obj-b"), TIME, "B".getBytes(StandardCharsets.UTF_8)));
            // Idempotent: a second append for the same object is a no-op and does not consume a sequence.
            assertFalse(log.append(new PkiId("obj-a"), TIME, "IGNORED".getBytes(StandardCharsets.UTF_8)));
            assertTrue(log.append(new PkiId("obj-c"), TIME, "C".getBytes(StandardCharsets.UTF_8)));

            try (MetadataEvidenceLog.Reader reader = log.openReader(-1L)) {
                assertEquals(3L, reader.highWatermark());
                assertTrue(reader.next(CancellationSignal.NONE));
                assertEquals(0L, reader.current().sequence());
                assertEquals(new PkiId("obj-a"), reader.current().objectId());
                assertArrayEquals("A".getBytes(StandardCharsets.UTF_8), reader.current().payload());
                assertTrue(reader.next(CancellationSignal.NONE));
                assertEquals(1L, reader.current().sequence());
                assertEquals(new PkiId("obj-b"), reader.current().objectId());
                assertTrue(reader.next(CancellationSignal.NONE));
                assertEquals(2L, reader.current().sequence());
                assertEquals(new PkiId("obj-c"), reader.current().objectId());
                assertFalse(reader.next(CancellationSignal.NONE));
            }

            // Resume strictly after sequence 0.
            try (MetadataEvidenceLog.Reader reader = log.openReader(0L)) {
                assertTrue(reader.next(CancellationSignal.NONE));
                assertEquals(1L, reader.current().sequence());
                assertTrue(reader.next(CancellationSignal.NONE));
                assertEquals(2L, reader.current().sequence());
                assertFalse(reader.next(CancellationSignal.NONE));
            }
        }
    }

    @Test
    void reopenedLogContinuesTheSameSequence() throws Exception {
        Path log = directory.resolve("reopen.log");
        try (DurableTransactionalMetadataStore store = DurableTransactionalMetadataStore.create(
                log, STORE_ID, OptionalLong.of(1L << 20))) {
            MetadataEvidenceLog evidence = new MetadataEvidenceLog(store, NAMESPACE);
            assertTrue(evidence.append(new PkiId("obj-a"), TIME, "A".getBytes(StandardCharsets.UTF_8)));
        }
        try (DurableTransactionalMetadataStore store = DurableTransactionalMetadataStore.open(
                log, OptionalLong.of(1L << 20))) {
            MetadataEvidenceLog evidence = new MetadataEvidenceLog(store, NAMESPACE);
            // The reopened log must not restart the sequence and must remain idempotent for a prior object.
            assertFalse(evidence.append(new PkiId("obj-a"), TIME, "A".getBytes(StandardCharsets.UTF_8)));
            assertTrue(evidence.append(new PkiId("obj-b"), TIME, "B".getBytes(StandardCharsets.UTF_8)));
            try (MetadataEvidenceLog.Reader reader = evidence.openReader(-1L)) {
                assertEquals(2L, reader.highWatermark());
                assertTrue(reader.next(CancellationSignal.NONE));
                assertEquals(0L, reader.current().sequence());
                assertTrue(reader.next(CancellationSignal.NONE));
                assertEquals(1L, reader.current().sequence());
                assertEquals(new PkiId("obj-b"), reader.current().objectId());
                assertFalse(reader.next(CancellationSignal.NONE));
            }
        }
    }
}
