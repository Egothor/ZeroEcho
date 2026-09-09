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
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.spi.store.AuditEvidenceFeed;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataCursor;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.TransactionalMetadataStore;

/** Startup reconciliation of the issuance-evidence log across the credential-commit crash window (Task 8a). */
final class FilesystemIssuanceEvidenceReconciliationTest {

    private static final String STORE_DIRECTORY = "store";

    @Test
    void crashWindowIssuanceEvidenceIsReconciledOnRestart(@TempDir Path tempDir) throws Exception {
        Path root = tempDir.resolve(STORE_DIRECTORY);
        Credential credential;
        try (FilesystemPkiStore store = open(root)) {
            credential = endEntityCredential(store, "SERIAL-CRASH", "profile-leaf");
            store.putCredential(credential);
            assertEquals(List.of(credential.credentialId()), evidenceObjectIds(store),
                    "putCredential must co-record issuance evidence for an end-entity credential");
            // Model the crash window: the credential file committed but its evidence append never ran.
            clearIssuanceEvidence(store.metadataStore());
            assertTrue(evidenceObjectIds(store).isEmpty(), "evidence must be cleared to model the crash window");
        }

        try (FilesystemPkiStore reopened = open(root)) {
            assertTrue(reopened.getCredential(credential.credentialId()).isPresent(),
                    "the committed credential must remain readable");
            assertEquals(List.of(credential.credentialId()), evidenceObjectIds(reopened),
                    "startup recovery must re-append the missing issuance evidence");
        }

        // Idempotent: a further restart re-runs the visitor but the per-credential marker prevents duplication.
        try (FilesystemPkiStore reopenedAgain = open(root)) {
            assertEquals(List.of(credential.credentialId()), evidenceObjectIds(reopenedAgain),
                    "recovery must not duplicate an already-reconciled entry");
        }
    }

    @Test
    void caCredentialsAreNotReconciledIntoTheIssuanceFeed(@TempDir Path tempDir) throws Exception {
        Path root = tempDir.resolve(STORE_DIRECTORY);
        Credential ca;
        try (FilesystemPkiStore store = open(root)) {
            ca = caCredential(store, "SERIAL-CA", "profile-ca");
            store.putCredential(ca);
            assertTrue(evidenceObjectIds(store).isEmpty(), "CA credentials must not record issuance evidence");
        }
        try (FilesystemPkiStore reopened = open(root)) {
            assertTrue(evidenceObjectIds(reopened).isEmpty(),
                    "startup recovery must not synthesize issuance evidence for a CA credential");
        }
    }

    private static FilesystemPkiStore open(Path root) {
        return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults());
    }

    private static Credential endEntityCredential(FilesystemPkiStore store, String serial, String profileId)
            throws IOException {
        return credential(store, serial, new EndEntityProfileBinding(profileRef(profileId)));
    }

    private static Credential caCredential(FilesystemPkiStore store, String serial, String profileId)
            throws IOException {
        return credential(store, serial, new CaProfileBinding(profileRef(profileId)));
    }

    private static CertificateProfileRef profileRef(String profileId) {
        return new CertificateProfileRef(profileId, 1, new byte[32]);
    }

    private static Credential credential(FilesystemPkiStore store, String serial,
            zeroecho.pki.api.credential.CredentialProfileBinding binding) throws IOException {
        PkiId credentialId = new PkiId("cred-" + serial);
        DurableContentReference encoded = zeroecho.pki.testkit.PkiTestRuntime.fixtureReference(
                store.stagedContent(), Encoding.DER, new byte[] { 0x01, 0x02, 0x03 });
        return new Credential(credentialId, new FormatId("fmt-x509"), new IssuerRef(new PkiId("issuer-" + serial)),
                new SubjectRef("CN=subj-" + serial), new Validity(Instant.EPOCH, Instant.EPOCH.plusSeconds(60L)),
                serial, new PkiId("pk-" + serial), binding, CredentialStatus.ISSUED, encoded,
                FilesystemPkiStoreTest.TestObjects.emptyAttributes());
    }

    private static List<PkiId> evidenceObjectIds(FilesystemPkiStore store) throws IOException {
        List<PkiId> ids = new ArrayList<>();
        try (AuditEvidenceFeed feed = store.openIssuanceEvidenceFeed(-1L)) {
            while (feed.next(CancellationSignal.NONE)) {
                ids.add(feed.current().objectId());
            }
        }
        return ids;
    }

    // Deletes every issuance-evidence record (head, entry, marker) to model an interrupted commit.
    private static void clearIssuanceEvidence(TransactionalMetadataStore metadata) throws IOException {
        List<MetadataKey> keys = new ArrayList<>();
        Map<MetadataKey, Long> revisions = new HashMap<>();
        try (MetadataSnapshot snapshot = metadata.snapshot();
                MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(
                        FilesystemPkiStore.ISSUANCE_EVIDENCE_NAMESPACE), CancellationSignal.NONE)) {
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
                throw new IOException("Failed to clear issuance evidence: " + result.outcome());
            }
        }
    }
}
