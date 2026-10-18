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
package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.content.DurableContentOwner;
import zeroecho.pki.api.credential.Credential;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransaction;

/** Tests transactional credential ownership and restart reconciliation. */
@SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
final class FilesystemCredentialContentTransactionTest {

    private static final String STORE_DIRECTORY = "store";

    @Test
    void nonX509ExactDuplicateStillRejects(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            Credential credential = credential(store, "SERIAL-DUPLICATE");
            store.putCredential(credential);
            assertThrows(IllegalStateException.class, () -> store.putCredential(credential));
        }
    }

    @Test
    void metadataKeysDoNotCollapseSanitizedCredentialIds() {
        zeroecho.pki.spi.store.MetadataKey punctuation = AuthorityMetadataCodec.credentialKey(new zeroecho.pki.api.PkiId("credential:a"));
        zeroecho.pki.spi.store.MetadataKey underscore = AuthorityMetadataCodec.credentialKey(new zeroecho.pki.api.PkiId("credential_a"));
        assertFalse(punctuation.equals(underscore), "full credential identifiers must produce distinct keys");
    }

    @Test
    void credentialOwnerPersistsAcrossRestart(@TempDir Path tempDir) throws Exception {
        System.out.println("credentialOwnerPersistsAcrossRestart");
        Path root = tempDir.resolve(STORE_DIRECTORY);
        Credential credential;
        DurableContentOwner owner;
        try (FilesystemPkiStore store = open(root)) {
            credential = credential(store, "SERIAL-OWNER");
            owner = DurableContentOwner.credentialRecord(credential.credentialId());
            assertFalse(store.stagedContent().contentOwners(credential.content()).contains(owner),
                    "owner must be absent before publication");
            store.putCredential(credential);
            assertTrue(store.stagedContent().contentOwners(credential.content()).contains(owner),
                    "publication must retain the exact owner");
        }

        try (FilesystemPkiStore reopened = open(root)) {
            assertTrue(reopened.getCredential(credential.credentialId()).isPresent(),
                    "credential must remain readable after restart");
            assertTrue(reopened.stagedContent().contentOwners(credential.content()).contains(owner),
                    "credential owner must survive recovery");
        }
        System.out.println("credentialOwnerPersistsAcrossRestart...ok");
    }

    @Test
    void exactCredentialOwnerIsRequiredWithoutMutation(@TempDir Path tempDir) throws Exception {
        System.out.println("exactCredentialOwnerIsRequiredWithoutMutation");
        Path root = tempDir.resolve(STORE_DIRECTORY);
        Credential credential;
        DurableContentOwner wrong = DurableContentOwner.credentialRecord(
                new zeroecho.pki.api.PkiId("wrong-credential"));
        try (FilesystemPkiStore store = open(root)) {
            credential = credential(store, "SERIAL-MISSING-OWNER");
            store.putCredential(credential);
            byte[] wrongPayload = CredentialMetadataAuthority.encodeOwners(credential.content().contentId(), Set.of(wrong));
            try (MetadataSnapshot snapshot = store.metadataStore().snapshot();
                    MetadataSnapshot.Record record = snapshot.get(AuthorityMetadataCodec.ownerSetKey(credential.content().contentId())).orElseThrow();
                    MetadataTransaction transaction = store.metadataStore().beginTransaction();
                    RepeatableContent bytes = new ImmutableByteContent(wrongPayload)) {
                transaction.replace(record.key(), record.recordRevision(), bytes, CancellationSignal.NONE);
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
            }
            assertThrows(IllegalStateException.class, () -> store.getCredential(credential.credentialId()));
            try (MetadataSnapshot snapshot = store.metadataStore().snapshot();
                    MetadataSnapshot.Record record = snapshot.get(AuthorityMetadataCodec.ownerSetKey(credential.content().contentId())).orElseThrow()) {
                assertArrayEquals(wrongPayload, CredentialMetadataAuthority.read(record, 1024),
                        "read validation must not repair committed owner evidence");
            }
        }

        assertThrows(IllegalStateException.class, () -> open(root));
        System.out.println("exactCredentialOwnerIsRequiredWithoutMutation...ok");
    }

    @Test
    void uncommittedRecordAndOwnerAreAbsentOnRestart(@TempDir Path tempDir) throws Exception {
        Path root = tempDir.resolve(STORE_DIRECTORY);
        Credential credential;
        try (FilesystemPkiStore store = open(root)) {
            credential = credential(store, "SERIAL-PREPARED");
            {
                FilesystemStagedContentStore.TransactionalReservation reservation = ((FilesystemStagedContentStore) store.stagedContent())
                    .reserveTransactionalPublication(credential.content());
                try (reservation) {
                    try (MetadataSnapshot snapshot = store.metadataStore().snapshot()) {
                        try (MetadataTransaction transaction = store.metadataStore().beginTransaction()) {
                            new CredentialMetadataAuthority(store.metadataStore(), store.stagedContent()).stageCreate(snapshot, transaction, credential);
                            assertTrue(store.getCredential(credential.credentialId()).isEmpty());
                            assertTrue(store.stagedContent().contentOwners(credential.content()).isEmpty());
                            assertThrows(IOException.class, () -> store.stagedContent().retireUnownedContent(credential.content()));
                        }
                    }
                }
            }
        }

        try (FilesystemPkiStore reopened = open(root)) {
            assertFalse(reopened.getCredential(credential.credentialId()).isPresent(),
                    "recovery must not publish a record");
            try (MetadataSnapshot snapshot = reopened.metadataStore().snapshot()) {
                assertTrue(snapshot.get(AuthorityMetadataCodec.ownerSetKey(credential.content().contentId())).isEmpty());
            }
            assertThrows(IOException.class, () -> reopened.stagedContent().openContent(credential.content()));
        }
    }

    @Test
    void legacyIntentWithoutPublishedRecordRejectsWithoutReclamation(@TempDir Path tempDir) throws Exception {
        Path root = tempDir.resolve(STORE_DIRECTORY);
        Credential credential;
        Path intentPath;
        try (FilesystemPkiStore store = open(root)) {
            credential = credential(store, "SERIAL-INTENT-ONLY");
            intentPath = writePreparedIntent(root, credential);
        }

        assertThrows(IllegalStateException.class, () -> open(root));
        assertTrue(Files.exists(intentPath), "unsupported legacy intent must not be removed");
        assertTrue(Files.exists(root.resolve("staged-content").resolve(credential.content().contentId() + ".content")));
    }

    @Test
    void legacyIntentAlongsideCommittedMetadataRejectsWithoutRepair(@TempDir Path tempDir) throws Exception {
        Path root = tempDir.resolve(STORE_DIRECTORY);
        Credential credential;
        Path intentPath;
        try (FilesystemPkiStore store = open(root)) {
            credential = credential(store, "SERIAL-PUBLISHED");
            store.putCredential(credential);
            intentPath = writePreparedIntent(root, credential);
        }

        assertThrows(IllegalStateException.class, () -> open(root));
        assertTrue(Files.exists(intentPath), "unsupported mixed layout must not be repaired");
        assertTrue(Files.exists(root.resolve("staged-content").resolve(credential.content().contentId() + ".content")));
    }

    @Test
    void handoffIntentRejectsTrailingData(@TempDir Path tempDir) throws Exception {
        System.out.println("handoffIntentRejectsTrailingData");
        Path root = tempDir.resolve(STORE_DIRECTORY);
        Path intentPath;
        try (FilesystemPkiStore store = open(root)) {
            Credential credential = credential(store, "SERIAL-STRICT");
            intentPath = writePreparedIntent(root, credential);
            byte[] exact = Files.readAllBytes(intentPath);
            Files.write(intentPath, Arrays.copyOf(exact, exact.length + 1), StandardOpenOption.TRUNCATE_EXISTING);
        }

        assertThrows(IllegalStateException.class, () -> open(root));
        assertTrue(Files.exists(intentPath), "invalid intent must not be silently discarded");
        System.out.println("handoffIntentRejectsTrailingData...ok");
    }

    @Test
    void corruptedContentIsRejectedBeforeOwnershipHandoff(@TempDir Path tempDir) throws Exception {
        System.out.println("corruptedContentIsRejectedBeforeOwnershipHandoff");
        Path root = tempDir.resolve(STORE_DIRECTORY);
        try (FilesystemPkiStore store = open(root)) {
            Credential credential = credential(store, "SERIAL-CORRUPT");
            Path contentPath = root.resolve("staged-content").resolve(credential.content().contentId() + ".content");
            byte[] original = Files.readAllBytes(contentPath);
            byte[] corrupted = original.clone();
            corrupted[0] ^= 0x7f;
            Files.write(contentPath, corrupted, StandardOpenOption.TRUNCATE_EXISTING);

            assertThrows(IllegalStateException.class, () -> store.putCredential(credential));
            assertTrue(store.getCredential(credential.credentialId()).isEmpty(),
                    "corrupt content must not make the record visible");
            assertTrue(store.stagedContent().contentOwners(credential.content()).isEmpty(),
                    "corrupt content must not gain an owner");
            assertArrayEquals(corrupted, Files.readAllBytes(contentPath),
                    "failed validation must not rewrite the supplied content");
            store.stagedContent().retireUnownedContent(credential.content());
            assertFalse(Files.exists(contentPath), "precommit rejection must release its reservation");
            Credential valid = credential(store, "SERIAL-AFTER-REJECTION");
            store.putCredential(valid);
            assertTrue(store.getCredential(valid.credentialId()).isPresent(), "known rejection must not fence the store");
        }
        System.out.println("corruptedContentIsRejectedBeforeOwnershipHandoff...ok");
    }

    private static FilesystemPkiStore open(Path root) {
        return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults());
    }

    private static Credential credential(FilesystemPkiStore store, String serial) throws IOException {
        return FilesystemPkiStoreTest.TestObjects.minimalCredential(store, serial, "credential-profile");
    }

    private static Path writePreparedIntent(Path root, Credential credential) throws IOException {
        CredentialContentTransaction.Intent intent = CredentialContentTransaction.Intent.from(credential,
                CredentialContentTransaction.State.PREPARED);
        Path path = root.resolve("credential-handoffs")
                .resolve(CredentialContentTransaction.intentFileName(credential.credentialId()));
        DurableMetadataFiles.create(path, 64 * 1024,
                output -> output.write(CredentialContentTransaction.encode(intent)));
        return path;
    }
}
