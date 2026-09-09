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
import java.nio.charset.StandardCharsets;
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
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.publication.PublicationEvidence;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.publication.PublicationSourceType;
import zeroecho.pki.api.publication.PublicationStatus;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.publication.PublicationTargetType;
import zeroecho.pki.application.PublicationExecutionEvidence;
import zeroecho.pki.impl.core.async.DomainAttributeEncoding;
import zeroecho.pki.spi.store.AuditEvidenceFeed;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataCursor;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.TransactionalMetadataStore;

/** Terminal co-commit and startup reconciliation of the publication-evidence log (Task 8a). */
final class FilesystemPublicationEvidenceReconciliationTest {

    private static final String STORE_DIRECTORY = "store";
    private static final Instant TIME = Instant.parse("2026-08-04T12:00:00Z");
    private static final PkiId PUBLICATION_ID = new PkiId("publication:crash");

    @Test
    void terminalPublicationCoCommitsEvidenceAndReconcilesTheCrashWindow(@TempDir Path tempDir) throws Exception {
        Path root = tempDir.resolve(STORE_DIRECTORY);
        try (FilesystemPkiStore store = open(root)) {
            driveToSucceeded(store);
            assertEquals(List.of(PUBLICATION_ID), evidenceObjectIds(store),
                    "the terminal publication transition must co-record evidence");
            clearPublicationEvidence(store.metadataStore());
            assertTrue(evidenceObjectIds(store).isEmpty(), "evidence must be cleared to model the crash window");
        }

        try (FilesystemPkiStore reopened = open(root)) {
            assertEquals(List.of(PUBLICATION_ID), evidenceObjectIds(reopened),
                    "startup recovery must re-append the missing publication evidence");
            PublicationExecutionEvidence evidence = PublicationExecutionEvidence.decode(
                    DomainAttributeEncoding.decode(new String(firstEntry(reopened).evidence(),
                            StandardCharsets.UTF_8))).orElseThrow();
            assertEquals(PublicationExecutionEvidence.Outcome.SUCCEEDED, evidence.outcome());
            assertEquals("DIRECT_RESPONSE", evidence.responseEvidence().orElseThrow());
        }

        // Non-terminal publications never record evidence, and terminal ones are not duplicated.
        try (FilesystemPkiStore reopenedAgain = open(root)) {
            assertEquals(List.of(PUBLICATION_ID), evidenceObjectIds(reopenedAgain),
                    "recovery must not duplicate an already-reconciled entry");
        }
    }

    private static void driveToSucceeded(FilesystemPkiStore store) throws IOException {
        Credential source = FilesystemPkiStoreTest.TestObjects.minimalCredential(store, "SERIAL-PUB", "profile-pub");
        store.putCredential(source);
        PublicationRecord pending = new PublicationRecord(PUBLICATION_ID, PublicationSourceType.CREDENTIAL,
                source.credentialId(), source.content(),
                new PublicationTarget(PublicationTargetType.FILESYSTEM, "target-a"), PublicationStatus.PENDING,
                0L, Optional.empty(), TIME, TIME, Optional.empty(), Optional.empty());
        store.createPublicationRecord(pending);
        PublicationRecord prepared = new PublicationRecord(PUBLICATION_ID, PublicationSourceType.CREDENTIAL,
                source.credentialId(), source.content(),
                new PublicationTarget(PublicationTargetType.FILESYSTEM, "target-a"),
                PublicationStatus.DISPATCH_PREPARED, 1L, Optional.of("a".repeat(64)), TIME, TIME.plusSeconds(1L),
                Optional.empty(), Optional.empty());
        assertTrue(store.replacePublicationRecord(pending, prepared), "prepare transition must commit");
        PublicationRecord succeeded = new PublicationRecord(PUBLICATION_ID, PublicationSourceType.CREDENTIAL,
                source.credentialId(), source.content(),
                new PublicationTarget(PublicationTargetType.FILESYSTEM, "target-a"), PublicationStatus.SUCCEEDED,
                1L, Optional.of("a".repeat(64)), TIME, TIME.plusSeconds(2L), Optional.empty(),
                Optional.of(PublicationEvidence.DIRECT_RESPONSE));
        assertTrue(store.replacePublicationRecord(prepared, succeeded), "terminal transition must commit");
    }

    private static FilesystemPkiStore open(Path root) {
        return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults());
    }

    private static AuditEvidenceFeed.Entry firstEntry(FilesystemPkiStore store) throws IOException {
        try (AuditEvidenceFeed feed = store.openPublicationEvidenceFeed(-1L)) {
            if (!feed.next(CancellationSignal.NONE)) {
                throw new IllegalStateException("no publication evidence entry");
            }
            return feed.current();
        }
    }

    private static List<PkiId> evidenceObjectIds(FilesystemPkiStore store) throws IOException {
        List<PkiId> ids = new ArrayList<>();
        try (AuditEvidenceFeed feed = store.openPublicationEvidenceFeed(-1L)) {
            while (feed.next(CancellationSignal.NONE)) {
                ids.add(feed.current().objectId());
            }
        }
        return ids;
    }

    private static void clearPublicationEvidence(TransactionalMetadataStore metadata) throws IOException {
        List<MetadataKey> keys = new ArrayList<>();
        Map<MetadataKey, Long> revisions = new HashMap<>();
        try (MetadataSnapshot snapshot = metadata.snapshot();
                MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(
                        FilesystemPkiStore.PUBLICATION_EVIDENCE_NS), CancellationSignal.NONE)) {
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
                throw new IOException("Failed to clear publication evidence: " + result.outcome());
            }
        }
    }
}
