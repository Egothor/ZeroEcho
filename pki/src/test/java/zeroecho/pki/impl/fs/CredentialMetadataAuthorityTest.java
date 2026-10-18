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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentOwner;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransaction;

final class CredentialMetadataAuthorityTest {
    @Test void atomicRecordAndOwnerSurviveReopenAndPreventReclaim(@TempDir Path root) throws Exception {
        Credential credential;
        try (FilesystemPkiStore store = open(root)) {
            credential = FilesystemPkiStoreTest.TestObjects.minimalCredential(store, "metadata-owner", "profile");
            CredentialMetadataAuthority authority = new CredentialMetadataAuthority(store.metadataStore(), store.stagedContent());
            {
                FilesystemStagedContentStore.TransactionalReservation reservation = ((FilesystemStagedContentStore) store.stagedContent())
                    .reserveTransactionalPublication(credential.content());
                try (reservation) {
                    try (MetadataSnapshot snapshot = store.metadataStore().snapshot()) {
                        try (MetadataTransaction transaction = store.metadataStore().beginTransaction()) {
                            authority.stageCreate(snapshot, transaction, credential);
                            assertTrue(authority.find(credential.credentialId()).isEmpty());
                            assertThrows(IOException.class, () -> store.stagedContent().retireUnownedContent(credential.content()));
                            assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
                        }
                    }
                }
            }
            assertEquals(Set.of(DurableContentOwner.credentialRecord(credential.credentialId())),
                    store.stagedContent().contentOwners(credential.content()));
            assertThrows(IOException.class, () -> store.stagedContent().retireUnownedContent(credential.content()));
            assertArrayEquals(FsCodec.encode(FsCodec.CREDENTIAL, credential),
                    FsCodec.encode(FsCodec.CREDENTIAL, authority.find(credential.credentialId()).orElseThrow()));
        }
        try (FilesystemPkiStore store = open(root)) {
            assertArrayEquals(FsCodec.encode(FsCodec.CREDENTIAL, credential), FsCodec.encode(FsCodec.CREDENTIAL,
                    new CredentialMetadataAuthority(store.metadataStore(), store.stagedContent())
                            .find(credential.credentialId()).orElseThrow()));
            assertEquals(Set.of(DurableContentOwner.credentialRecord(credential.credentialId())),
                    store.stagedContent().contentOwners(credential.content()));
        }
    }

    @Test void incompleteCommittedEdgeRejectsStartupBeforeContentReclamation(@TempDir Path root) throws Exception {
        Path contentPath;
        try (FilesystemPkiStore store = open(root)) {
            Credential credential = FilesystemPkiStoreTest.TestObjects.minimalCredential(store, "missing-edge", "profile");
            contentPath = root.resolve("staged-content").resolve(credential.content().contentId() + ".content");
            try (MetadataTransaction transaction = store.metadataStore().beginTransaction();
                    RepeatableContent bytes = new ImmutableByteContent(FsCodec.encode(FsCodec.CREDENTIAL, credential))) {
                transaction.create(AuthorityMetadataCodec.credentialKey(credential.credentialId()), bytes, CancellationSignal.NONE);
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
            }
            assertThrows(IOException.class, () -> new CredentialMetadataAuthority(store.metadataStore(), store.stagedContent())
                    .validateAll(value -> { }));
        }
        assertThrows(RuntimeException.class, () -> open(root));
        assertTrue(Files.exists(contentPath));
    }

    @Test void ownerPayloadPreservesExistingVersionAndRejectsWrongIdentityOrCategory() throws Exception {
        String content = "12345678-1234-4234-9234-123456789abc";
        Set<DurableContentOwner> owners = Set.of(DurableContentOwner.credentialRecord(new PkiId("credential")));
        byte[] encoded = CredentialMetadataAuthority.encodeOwners(content, owners);
        assertEquals(2, encoded[0]);
        assertEquals(owners, CredentialMetadataAuthority.decodeOwners(AuthorityMetadataCodec.ownerSetKey(content), encoded));
        assertThrows(IOException.class, () -> CredentialMetadataAuthority.decodeOwners(
                AuthorityMetadataCodec.ownerSetKey("12345678-1234-4234-9234-123456789abd"), encoded));
        assertThrows(IllegalArgumentException.class, () -> CredentialMetadataAuthority.encodeOwners(content,
                Set.of(new DurableContentOwner(DurableContentOwner.Category.STATUS_OBJECT_RECORD, "status"))));
    }

    private static FilesystemPkiStore open(Path root) { return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults()); }
}
