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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Files;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataCursor;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.MetadataTransactionId;

final class NormalizedCaMetadataTest {
    private static final MetadataStoreId STORE = new MetadataStoreId("1".repeat(32));
    private static final PkiId CA = new PkiId("ca:normalized");

    @Test void ledgerExportBorrowsExactPinnedRevisionAndRejectsForeignSnapshot(@TempDir Path root) throws Exception {
        Path target = Files.createDirectory(root.resolve("target"));
        MetadataKey key = new MetadataKey("test.pinned", "record");
        try (SegmentedTransactionalMetadataStore source = SegmentedTransactionalMetadataStore.create(Files.createDirectory(root.resolve("source")), STORE)) {
            new AuthorityMetadataStore(source, NormalizedCaMetadataTest::committed).create(key, new byte[] {1});
            try (MetadataSnapshot snapshot = source.snapshot(); MetadataSnapshot.Record previous = snapshot.get(key).orElseThrow()) {
                try (MetadataTransaction transaction = source.beginTransaction(); RepeatableContent bytes = new ImmutableByteContent(new byte[] {2})) {
                    transaction.replace(key, previous.recordRevision(), bytes, CancellationSignal.NONE);
                    committed(transaction.commit());
                }
                source.exportSnapshotTo(snapshot, target, Set.of());
                try (SegmentedTransactionalMetadataStore restored = SegmentedTransactionalMetadataStore.open(target, STORE);
                        MetadataSnapshot targetSnapshot = restored.snapshot(); MetadataSnapshot.Record record = targetSnapshot.get(key).orElseThrow()) {
                    assertEquals(1, CredentialMetadataAuthority.read(record, 1)[0]);
                    assertThrows(IllegalArgumentException.class, () -> source.exportSnapshotTo(targetSnapshot, root.resolve("foreign"), Set.of()));
                }
                try (MetadataSnapshot.Record stillPinned = snapshot.get(key).orElseThrow()) {
                    assertEquals(1, CredentialMetadataAuthority.read(stillPinned, 1)[0]); // Borrowed, not closed by export.
                }
            }
        }
    }

    @ParameterizedTest @ValueSource(ints = {32, 10_000})
    void boundedRestoreOrderHistoryAndConstantMutationFootprint(int count, @TempDir Path root) throws Exception {
        CaRecord ca;
        try (SegmentedTransactionalMetadataStore metadata = SegmentedTransactionalMetadataStore.create(root, STORE)) {
            AuthorityMetadataStore authority = new AuthorityMetadataStore(metadata, NormalizedCaMetadataTest::committed);
            List<PkiId> ids = new ArrayList<>();
            for (int first = 0; first <= count; first += AuthorityMetadataStore.MAX_BATCH_MUTATIONS) {
                try (MetadataTransaction transaction = metadata.beginTransaction()) {
                    for (int index = first; index <= count && index < first + AuthorityMetadataStore.MAX_BATCH_MUTATIONS; index++) {
                        IssuerGeneration generation = generation(index);
                        AuthorityMetadataStore.create(transaction, AuthorityMetadataCodec.generationKey(generation.issuerId()),
                                FsCodec.encode(FsCodec.ISSUER_GENERATION, generation));
                        if (index < count) { ids.add(generation.issuerId()); }
                    }
                    committed(transaction.commit());
                }
            }
            IssuerChainPath path = IssuerChainPath.create(CA, ids.getFirst(), List.of(generation(0).credentialId()));
            authority.create(AuthorityMetadataCodec.pathKey(path.pathId()), FsCodec.encode(FsCodec.ISSUER_CHAIN_PATH, path));
            ca = new CaRecord(CA, CaKind.ROOT, CaState.ACTIVE, generation(0).signingKeyRef(), new SubjectRef("CN=Normalized"),
                    ids, ids.getFirst(), path.pathId());
            authority.restoreCa(ca, FsHistoryPolicy.onWrite(Optional.empty()));
            try (MetadataSnapshot snapshot = metadata.snapshot()) {
                assertEquals(ca, AuthorityMetadataStore.ca(snapshot, CA).orElseThrow());
                assertEquals(ids, AuthorityMetadataStore.generations(snapshot, CA).stream().map(IssuerGeneration::issuerId).toList());
                AuthorityMetadataStore.validateAll(snapshot);
                try (RecordingTransaction transaction = new RecordingTransaction(metadata.beginTransaction())) {
                    AuthorityMetadataStore.stageCa(snapshot, transaction, ca, true, Instant.EPOCH);
                    assertEquals(2, transaction.mutations.size());
                    int expected = SigningTransactionPayloadCodec.emptyCommitBytes();
                    for (SigningTransactionPayloadCodec.Mutation mutation : transaction.mutations) {
                        expected += SigningTransactionPayloadCodec.encodedCreateBytes(mutation.key(), mutation.content().length);
                    }
                    assertEquals(expected, SigningTransactionPayloadCodec.encodedCommitSize(transaction.mutations));
                    assertTrue(expected < 1024); // Independent of the full membership count.
                    committed(transaction.commit());
                }
                CountingSnapshot counted = new CountingSnapshot(snapshot);
                try (RecordingTransaction transaction = new RecordingTransaction(metadata.beginTransaction())) {
                    AuthorityMetadataStore.stageMembership(counted, transaction,
                            new AuthorityMetadataCodec.Membership(CA, generation(count).issuerId(), count));
                    assertEquals(2, counted.reads);
                    assertEquals(2, transaction.mutations.size());
                    assertTrue(SigningTransactionPayloadCodec.encodedCommitSize(transaction.mutations) < 1024);
                    // No head advance: abort the isolated suffix-stage instrumentation.
                }
                List<PkiId> reordered = new ArrayList<>(ids);
                java.util.Collections.swap(reordered, 0, 1);
                CaRecord bad = new CaRecord(CA, ca.kind(), ca.state(), ca.issuerKeyRef(), ca.subjectRef(), reordered,
                        ca.currentIssuanceIssuerId(), ca.issuanceChainPathId());
                try (MetadataTransaction transaction = metadata.beginTransaction()) {
                    assertThrows(IOException.class, () -> AuthorityMetadataStore.stageCa(snapshot, transaction, bad, true, Instant.EPOCH));
                }
            }
        }
        try (SegmentedTransactionalMetadataStore metadata = SegmentedTransactionalMetadataStore.open(root, STORE);
                MetadataSnapshot snapshot = metadata.snapshot()) {
            AuthorityMetadataStore.validateAll(snapshot);
            assertEquals(ca, AuthorityMetadataStore.ca(snapshot, CA).orElseThrow());
            assertEquals(ca, AuthorityMetadataStore.caAt(snapshot, CA, Instant.EPOCH, FsHistoryPolicy.onWrite(Optional.empty()), true).orElseThrow());
        }
    }

    private static IssuerGeneration generation(int ordinal) {
        PkiId credential = new PkiId("credential:" + ordinal);
        return new IssuerGeneration(IssuerGeneration.idFor(CA, credential), CA, credential,
                new KeyRef(ordinal == 0 ? "k".repeat(1_048_576) : "key"),
                IssuerGenerationState.ACTIVE, "0".repeat(64), "1".repeat(64));
    }

    private static void committed(MetadataCommitResult result) { assertEquals(MetadataCommitResult.Outcome.COMMITTED, result.outcome()); }

    private static final class RecordingTransaction implements MetadataTransaction {
        private final MetadataTransaction delegate;
        private final List<SigningTransactionPayloadCodec.Mutation> mutations = new ArrayList<>();
        private RecordingTransaction(MetadataTransaction delegate) { this.delegate = delegate; }
        public MetadataTransactionId id() { return delegate.id(); }
        public void create(MetadataKey key, RepeatableContent content, CancellationSignal cancellation) throws IOException {
            record(SigningTransactionPayloadCodec.MutationKind.CREATE, key, -1, content);
            delegate.create(key, content, cancellation);
        }
        public void replace(MetadataKey key, long revision, RepeatableContent content, CancellationSignal cancellation) throws IOException {
            record(SigningTransactionPayloadCodec.MutationKind.REPLACE, key, revision, content);
            delegate.replace(key, revision, content, cancellation);
        }
        private void record(SigningTransactionPayloadCodec.MutationKind kind, MetadataKey key, long revision, RepeatableContent content) throws IOException {
            try (java.io.InputStream input = content.openStream()) {
                mutations.add(new SigningTransactionPayloadCodec.Mutation(kind, key, revision, input.readAllBytes()));
            }
        }
        public void delete(MetadataKey key, long revision) { delegate.delete(key, revision); }
        public MetadataCommitResult commit() throws IOException { return delegate.commit(); }
        public void abort() throws IOException { delegate.abort(); }
        public void close() throws IOException { delegate.close(); }
    }

    private static final class CountingSnapshot implements MetadataSnapshot {
        private final MetadataSnapshot delegate;
        private int reads;
        private CountingSnapshot(MetadataSnapshot delegate) { this.delegate = delegate; }
        public MetadataStoreId storeId() { return delegate.storeId(); }
        public long revision() { return delegate.revision(); }
        public Optional<Record> get(MetadataKey key) throws IOException { reads++; return delegate.get(key); }
        public Optional<MetadataKey> greatestKey(String namespace) { return delegate.greatestKey(namespace); }
        public MetadataCursor scan(KeyRange range, CancellationSignal cancellation) { throw new AssertionError("Unexpected membership scan"); }
        public void close() { }
    }
}
