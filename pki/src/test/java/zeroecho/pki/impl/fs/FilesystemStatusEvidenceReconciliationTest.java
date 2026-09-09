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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.application.StatusGenerationEvidence;
import zeroecho.pki.impl.core.async.DomainAttributeEncoding;
import zeroecho.pki.spi.store.AuditEvidenceFeed;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataCursor;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.TransactionalMetadataStore;

/** Co-commit and startup reconciliation of the status-generation evidence log (Task 8a status slice). */
final class FilesystemStatusEvidenceReconciliationTest {

    private static final String STORE_DIRECTORY = "store";
    private static final Instant TIME = Instant.parse("2026-08-04T12:00:00Z");

    @Test
    void statusGenerationCoCommitsEvidenceAndReconcilesTheCrashWindow(@TempDir Path tempDir) throws Exception {
        Path root = tempDir.resolve(STORE_DIRECTORY);
        StatusObject status;
        try (FilesystemPkiStore store = open(root)) {
            status = crl(store, "crl:ca-a");
            store.putStatusObject(status);
            assertEquals(List.of(status.statusObjectId()), evidenceObjectIds(store),
                    "putStatusObject must co-record status-generation evidence");
            // Model the crash window: the status object committed but its evidence append never ran.
            clearStatusEvidence(store.metadataStore());
            assertTrue(evidenceObjectIds(store).isEmpty(), "evidence must be cleared to model the crash window");
        }

        try (FilesystemPkiStore reopened = open(root)) {
            assertTrue(reopened.getStatusObject(status.statusObjectId()).isPresent(),
                    "the committed status object must remain readable");
            assertEquals(List.of(status.statusObjectId()), evidenceObjectIds(reopened),
                    "startup recovery must re-append the missing status evidence");
            AuditEvidenceFeed.Entry entry = firstEntry(reopened);
            StatusGenerationEvidence evidence = StatusGenerationEvidence.decode(
                    DomainAttributeEncoding.decode(new String(entry.evidence(),
                            java.nio.charset.StandardCharsets.UTF_8))).orElseThrow();
            assertEquals("CRL", evidence.statusObjectType());
            assertEquals("ca-a", evidence.issuerCaId());
        }

        // Idempotent: a further restart re-runs reconciliation without duplicating the entry.
        try (FilesystemPkiStore reopenedAgain = open(root)) {
            assertEquals(List.of(status.statusObjectId()), evidenceObjectIds(reopenedAgain),
                    "recovery must not duplicate an already-reconciled entry");
        }
    }

    private static FilesystemPkiStore open(Path root) {
        return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults());
    }

    private static StatusObject crl(FilesystemPkiStore store, String id) throws IOException {
        DurableContentReference content = zeroecho.pki.testkit.PkiTestRuntime.fixtureReference(
                store.stagedContent(), Encoding.DER, new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 });
        return new StatusObject(new PkiId(id), new FormatId("x509"), new PkiId("ca-a"), StatusObjectType.CRL,
                TIME, Optional.of(TIME.plusSeconds(86_400L)), content,
                FilesystemPkiStoreTest.TestObjects.emptyAttributes());
    }

    private static AuditEvidenceFeed.Entry firstEntry(FilesystemPkiStore store) throws IOException {
        try (AuditEvidenceFeed feed = store.openStatusEvidenceFeed(-1L)) {
            if (!feed.next(CancellationSignal.NONE)) {
                throw new IllegalStateException("no status evidence entry");
            }
            return feed.current();
        }
    }

    private static List<PkiId> evidenceObjectIds(FilesystemPkiStore store) throws IOException {
        List<PkiId> ids = new ArrayList<>();
        try (AuditEvidenceFeed feed = store.openStatusEvidenceFeed(-1L)) {
            while (feed.next(CancellationSignal.NONE)) {
                ids.add(feed.current().objectId());
            }
        }
        return ids;
    }

    // Deletes every status-evidence record (head, entry, marker) to model an interrupted commit.
    private static void clearStatusEvidence(TransactionalMetadataStore metadata) throws IOException {
        List<MetadataKey> keys = new ArrayList<>();
        Map<MetadataKey, Long> revisions = new HashMap<>();
        try (MetadataSnapshot snapshot = metadata.snapshot();
                MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(
                        FilesystemPkiStore.STATUS_EVIDENCE_NAMESPACE), CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> record;
            while ((record = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (MetadataSnapshot.Record entry = record.orElseThrow()) {
                    keys.add(entry.key());
                    revisions.put(entry.key(), entry.recordRevision());
                }
            }
        }
        try (MetadataTransaction transaction = metadata.beginTransaction()) {
            for (MetadataKey key : keys) {
                transaction.delete(key, revisions.get(key));
            }
            MetadataCommitResult result = transaction.commit();
            if (result.outcome() != MetadataCommitResult.Outcome.COMMITTED) {
                throw new IOException("Failed to clear status evidence: " + result.outcome());
            }
        }
    }
}
