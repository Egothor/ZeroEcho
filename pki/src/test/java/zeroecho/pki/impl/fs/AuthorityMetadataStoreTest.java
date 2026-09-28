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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.Duration;
import java.util.List;
import java.util.ArrayList;
import java.util.Optional;
import java.util.OptionalLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.MetadataTransactionId;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataStoreCapabilities;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.TransactionalMetadataStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.IntermediateCreationFixture;
import zeroecho.pki.testkit.SemanticIssuanceFixture;

final class AuthorityMetadataStoreTest {
    @Test void conflictingPruneDefersCleanupAfterSuccessfulCurrentCommit(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            CaRecord active = FilesystemPkiStoreTest.TestObjects.minimalCaRecord(store, "prune-conflict", CaState.ACTIVE);
            store.putCa(active);
            stage(store, active, Instant.EPOCH, true);
            CaRecord disabled = new CaRecord(active.caId(), active.kind(), CaState.DISABLED, active.issuerKeyRef(), active.subjectRef(),
                    active.issuerIds(), active.currentIssuanceIssuerId(), active.issuanceChainPathId());
            PruneInterleaving metadata = new PruneInterleaving(store.metadataStore(), PruneInterleaving.Mode.CONFLICT);
            List<MetadataCommitResult.Outcome> outcomes = new ArrayList<>();
            AuthorityMetadataStore authority = new AuthorityMetadataStore(metadata, result -> outcomes.add(result.outcome()));
            authority.putCa(disabled, FsHistoryPolicy.onWrite(Optional.of(Duration.ofDays(1))));
            assertEquals(List.of(MetadataCommitResult.Outcome.COMMITTED, MetadataCommitResult.Outcome.NOT_COMMITTED), outcomes);
            assertEquals(disabled, store.getCa(active.caId()).orElseThrow());
            try (MetadataSnapshot snapshot = store.metadataStore().snapshot()) {
                assertEquals(active, AuthorityMetadataStore.caAt(snapshot, active.caId(), Instant.EPOCH,
                        FsHistoryPolicy.onWrite(Optional.empty()), true).orElseThrow());
            }
            assertTrue(metadata.injected);
            authority.prune(active.caId(), Instant.EPOCH.plusSeconds(1));
            try (MetadataSnapshot snapshot = store.metadataStore().snapshot()) {
                assertThrows(IOException.class, () -> AuthorityMetadataStore.caAt(snapshot, active.caId(), Instant.EPOCH,
                        FsHistoryPolicy.onWrite(Optional.empty()), true));
            }
            assertEquals(disabled, store.getCa(active.caId()).orElseThrow());
        }
    }

    @Test void pruneUncertaintyAndStorageFailureAreNotBestEffortSuccess(@TempDir Path root) throws Exception {
        for (PruneInterleaving.Mode mode : List.of(PruneInterleaving.Mode.UNKNOWN, PruneInterleaving.Mode.STORAGE_FAILURE)) {
            try (FilesystemPkiStore store = new FilesystemPkiStore(root.resolve(mode.name()), FsPkiStoreOptions.defaults())) {
                CaRecord active = FilesystemPkiStoreTest.TestObjects.minimalCaRecord(store, "prune-uncertain", CaState.ACTIVE);
                store.putCa(active);
                stage(store, active, Instant.EPOCH, true);
                AuthorityMetadataStore authority = new AuthorityMetadataStore(new PruneInterleaving(store.metadataStore(), mode), result -> { });
                assertThrows(IOException.class, () -> authority.prune(active.caId(), Instant.EPOCH.plusSeconds(1)));
                assertEquals(active, store.getCa(active.caId()).orElseThrow());
            }
        }
    }

    @Test void historicalSnapshotRetainsUnpublishedSigningGenerationButNotUnrelatedAuthority(@TempDir Path root) throws Exception {
        Path sourceRoot = root.resolve("source");
        Path targetRoot = root.resolve("target");
        PkiId operation;
        try (FilesystemPkiStore source = new FilesystemPkiStore(sourceRoot, FsPkiStoreOptions.defaults(), IntermediateCreationFixture.CLOCK)) {
            SemanticIssuanceFixture.issuer(source, 1);
            CaRecord first = new CaRecord(SemanticIssuanceFixture.AUTHORITY, CaKind.ROOT, CaState.ACTIVE, SemanticIssuanceFixture.KEY,
                    new SubjectRef("CN=Acceptance Issuer"), List.of(SemanticIssuanceFixture.issuerId(1)),
                    SemanticIssuanceFixture.issuerId(1), SemanticIssuanceFixture.path(1).pathId());
            stage(source, first, Instant.EPOCH, true);
            SemanticIssuanceFixture.issuer(source, 2);
            CaRecord second = new CaRecord(first.caId(), first.kind(), first.state(), first.issuerKeyRef(), first.subjectRef(),
                    List.of(SemanticIssuanceFixture.issuerId(1), SemanticIssuanceFixture.issuerId(2)),
                    SemanticIssuanceFixture.issuerId(2), SemanticIssuanceFixture.path(2).pathId());
            stage(source, second, Instant.EPOCH.plusSeconds(1), true);
            SemanticIssuanceFixture.issuer(source, 3); // No selected CA or signing command references this generation.
            SignWorkflowStore.AcceptanceCommand accepted = FilesystemSignScopeAcceptanceTest.command(source, 2, 42, -1, "", null);
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, source.acceptSign(accepted));
            operation = accepted.operationId();
            assertTrue(source.getCredentialByIssuerAndSerial(SemanticIssuanceFixture.issuerId(2), java.math.BigInteger.valueOf(42)).isEmpty());
            source.exportSnapshot(targetRoot, Instant.EPOCH);
        }
        try (FilesystemPkiStore target = new FilesystemPkiStore(targetRoot, FsPkiStoreOptions.defaults(), IntermediateCreationFixture.CLOCK)) {
            assertEquals(List.of(SemanticIssuanceFixture.issuerId(1)),
                    target.getCa(SemanticIssuanceFixture.AUTHORITY).orElseThrow().issuerIds());
            assertTrue(target.getIssuerGeneration(SemanticIssuanceFixture.issuerId(2)).isPresent());
            assertEquals(SemanticIssuanceFixture.path(2), target.getIssuerChainPath(SemanticIssuanceFixture.path(2).pathId()).orElseThrow());
            assertEquals(SignWorkflowStore.State.INTENT, target.getSignWorkflow(operation).orElseThrow().state());
            assertTrue(target.getCredentialByIssuerAndSerial(SemanticIssuanceFixture.issuerId(2), java.math.BigInteger.valueOf(42)).isEmpty());
            assertTrue(target.getIssuerGeneration(SemanticIssuanceFixture.issuerId(3)).isEmpty());
            assertTrue(target.getIssuerChainPath(SemanticIssuanceFixture.path(3).pathId()).isEmpty());
        }
    }

    @Test void historicalSnapshotRemintsContentAndKeepsOnlySelectedCaState(@TempDir Path root) throws Exception {
        Path sourceRoot = root.resolve("source");
        Path targetRoot = root.resolve("target");
        String content;
        try (FilesystemPkiStore source = new FilesystemPkiStore(sourceRoot, FsPkiStoreOptions.defaults(), IntermediateCreationFixture.CLOCK)) {
            CaRecord active = FilesystemPkiStoreTest.TestObjects.minimalCaRecord(source, "snapshot-history", CaState.ACTIVE);
            source.putCa(active);
            content = source.getCredential(source.getIssuerGeneration(active.currentIssuanceIssuerId()).orElseThrow().credentialId())
                    .orElseThrow().content().contentId();
            stage(source, active, Instant.EPOCH, true);
            stage(source, new CaRecord(active.caId(), active.kind(), CaState.DISABLED, active.issuerKeyRef(), active.subjectRef(),
                    active.issuerIds(), active.currentIssuanceIssuerId(), active.issuanceChainPathId()), Instant.EPOCH.plusSeconds(1), true);
            source.exportSnapshot(targetRoot, Instant.EPOCH);
        }
        try (FilesystemPkiStore target = new FilesystemPkiStore(targetRoot, FsPkiStoreOptions.defaults(), IntermediateCreationFixture.CLOCK);
                MetadataSnapshot snapshot = target.metadataStore().snapshot()) {
            CaRecord restored = target.getCa(new zeroecho.pki.api.PkiId("snapshot-history")).orElseThrow();
            assertEquals(CaState.ACTIVE, restored.state());
            assertNotEquals(content, target.getCredential(target.getIssuerGeneration(restored.currentIssuanceIssuerId()).orElseThrow().credentialId())
                    .orElseThrow().content().contentId());
            assertThrows(IOException.class, () -> AuthorityMetadataStore.caAt(snapshot, restored.caId(), Instant.EPOCH,
                    FsHistoryPolicy.onWrite(java.util.Optional.empty()), true));
        }
    }

    @Test void currentAndHistoryCommitTogetherWithTimestampCollisionOrdering(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), IntermediateCreationFixture.CLOCK)) {
            new IntermediateCreationFixture().initialize(store, 1);
            CaRecord active = store.getCa(IntermediateCreationFixture.CA).orElseThrow();
            CaRecord disabled = new CaRecord(active.caId(), active.kind(), CaState.DISABLED, active.issuerKeyRef(), active.subjectRef(),
                    active.issuerIds(), active.currentIssuanceIssuerId(), active.issuanceChainPathId());
            Instant timestamp = Instant.parse("2026-01-01T00:00:00Z");
            stage(store, active, timestamp, true);
            try (MetadataSnapshot pinned = store.metadataStore().snapshot()) {
                stage(store, disabled, timestamp, true);
                assertEquals(CaState.ACTIVE, AuthorityMetadataStore.caAt(pinned, active.caId(), timestamp,
                        FsHistoryPolicy.onWrite(java.util.Optional.empty()), true).orElseThrow().state());
            }
            try (MetadataSnapshot latest = store.metadataStore().snapshot()) {
                assertEquals(CaState.DISABLED, AuthorityMetadataStore.caAt(latest, active.caId(), timestamp,
                        FsHistoryPolicy.onWrite(java.util.Optional.empty()), true).orElseThrow().state());
                assertThrows(IOException.class, () -> AuthorityMetadataStore.caAt(latest, active.caId(), timestamp.minusNanos(1),
                        FsHistoryPolicy.onWrite(java.util.Optional.empty()), true));
                assertEquals(CaState.DISABLED, AuthorityMetadataStore.caAt(latest, active.caId(), timestamp,
                        FsHistoryPolicy.disabled(), false).orElseThrow().state());
                assertEquals(CaState.DISABLED, AuthorityMetadataStore.caAt(latest, active.caId(), timestamp,
                        FsHistoryPolicy.disabled(), true).orElseThrow().state());
            }
            AuthorityMetadataStore authority = new AuthorityMetadataStore(store.metadataStore(), result ->
                    assertEquals(MetadataCommitResult.Outcome.COMMITTED, result.outcome()));
            authority.prune(active.caId(), timestamp);
            try (MetadataSnapshot retained = store.metadataStore().snapshot()) {
                assertEquals(CaState.DISABLED, AuthorityMetadataStore.caAt(retained, active.caId(), timestamp,
                        FsHistoryPolicy.onWrite(java.util.Optional.empty()), true).orElseThrow().state());
            }
            authority.prune(active.caId(), timestamp.plusNanos(1));
            try (MetadataSnapshot pruned = store.metadataStore().snapshot()) {
                assertThrows(IOException.class, () -> AuthorityMetadataStore.caAt(pruned, active.caId(), timestamp,
                        FsHistoryPolicy.onWrite(java.util.Optional.empty()), true));
            }
            assertFalse(Files.exists(root.resolve("cas")));
            assertFalse(Files.exists(root.resolve("credentials")));
            assertFalse(Files.exists(root.resolve("issuer-generations")));
            assertFalse(Files.exists(root.resolve("issuer-chain-paths")));
        }
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), IntermediateCreationFixture.CLOCK)) {
            assertEquals(CaState.DISABLED, store.getCa(IntermediateCreationFixture.CA).orElseThrow().state());
        }
    }

    private static void stage(FilesystemPkiStore store, CaRecord ca, Instant timestamp, boolean history) throws IOException {
        try (MetadataSnapshot snapshot = store.metadataStore().snapshot(); MetadataTransaction transaction = store.metadataStore().beginTransaction()) {
            AuthorityMetadataStore.stageCa(snapshot, transaction, ca, history, timestamp);
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
        }
    }

    /** Interleaves one real revision change immediately before the cleanup commit. */
    private static final class PruneInterleaving implements TransactionalMetadataStore {
        private enum Mode { CONFLICT, UNKNOWN, STORAGE_FAILURE }
        private final TransactionalMetadataStore delegate;
        private final Mode mode;
        private boolean injected;

        private PruneInterleaving(TransactionalMetadataStore delegate, Mode mode) { this.delegate = delegate; this.mode = mode; }
        @Override public MetadataStoreId id() { return delegate.id(); }
        @Override public MetadataStoreCapabilities capabilities() { return delegate.capabilities(); }
        @Override public MetadataSnapshot snapshot() throws IOException { return delegate.snapshot(); }
        @Override public MetadataCommitResult resolve(MetadataTransactionId id) throws IOException { return delegate.resolve(id); }
        @Override public void acknowledge(MetadataTransactionId id) throws IOException { delegate.acknowledge(id); }
        @Override public void close() { }
        @Override public MetadataTransaction beginTransaction() throws IOException {
            MetadataTransaction transaction = delegate.beginTransaction();
            return new MetadataTransaction() {
                private MetadataKey deleted;
                @Override public MetadataTransactionId id() { return transaction.id(); }
                @Override public void create(MetadataKey key, RepeatableContent content, CancellationSignal cancellation) throws IOException {
                    transaction.create(key, content, cancellation);
                }
                @Override public void replace(MetadataKey key, long revision, RepeatableContent content, CancellationSignal cancellation) throws IOException {
                    transaction.replace(key, revision, content, cancellation);
                }
                @Override public void delete(MetadataKey key, long revision) { deleted = key; transaction.delete(key, revision); }
                @Override public MetadataCommitResult commit() throws IOException {
                    if (deleted != null && !injected) {
                        injected = true;
                        if (mode == Mode.STORAGE_FAILURE) { throw new IOException("Injected cleanup storage failure"); }
                        if (mode == Mode.UNKNOWN) {
                            MetadataTransactionId id = transaction.id();
                            assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
                            return new MetadataCommitResult(id, MetadataCommitResult.Outcome.UNKNOWN,
                                    OptionalLong.empty(), Optional.empty());
                        }
                        try (MetadataSnapshot snapshot = delegate.snapshot(); MetadataSnapshot.Record record = snapshot.get(deleted).orElseThrow();
                                MetadataTransaction concurrent = delegate.beginTransaction();
                                RepeatableContent bytes = new ImmutableByteContent(CredentialMetadataAuthority.read(record, AuthorityMetadataCodec.MAX_VALUE_BYTES))) {
                            concurrent.replace(record.key(), record.recordRevision(), bytes, CancellationSignal.NONE);
                            assertEquals(MetadataCommitResult.Outcome.COMMITTED, concurrent.commit().outcome());
                        }
                    }
                    return transaction.commit();
                }
                @Override public void abort() throws IOException { transaction.abort(); }
                @Override public void close() throws IOException { transaction.close(); }
            };
        }
    }
}
