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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiFailureReason;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataCursor;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataStoreCapabilities;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.MetadataTransactionId;
import zeroecho.pki.spi.store.TransactionalMetadataStore;
import zeroecho.pki.testkit.SemanticIssuanceFixture;

final class AuthorityMetadataCompareAndSetTest {
    @Test
    void exactReplacementChangesOnlyCurrentStateAndAddsAtomicHistory(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options())) {
            CaRecord original = initial(store);
            CaRecord disabled = state(original, CaState.DISABLED);
            Map<MetadataKey, String> membership = rows(store, AuthorityMetadataCodec.CA_GENERATION_ORDER,
                    AuthorityMetadataCodec.CA_GENERATION_MEMBER, AuthorityMetadataCodec.CA_BASE);
            try (MetadataSnapshot pinned = store.metadataStore().snapshot()) {
                assertTrue(store.replaceCa(original, disabled));
                assertEquals(original, AuthorityMetadataStore.ca(pinned, original.caId()).orElseThrow());
            }
            assertEquals(disabled, store.getCa(original.caId()).orElseThrow());
            assertEquals(membership, rows(store, AuthorityMetadataCodec.CA_GENERATION_ORDER,
                    AuthorityMetadataCodec.CA_GENERATION_MEMBER, AuthorityMetadataCodec.CA_BASE));
            assertEquals(List.of(CaState.ACTIVE, CaState.DISABLED), historyStates(store));
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, options())) {
            assertEquals(CaState.DISABLED, reopened.getCa(SemanticIssuanceFixture.AUTHORITY).orElseThrow().state());
            assertEquals(List.of(CaState.ACTIVE, CaState.DISABLED), historyStates(reopened));
        }
    }

    @Test
    void absentAndStaleExpectedValuesPublishNoAuthorityRows(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options())) {
            SemanticIssuanceFixture.issuer(store, 1);
            CaRecord original = authority(1, CaState.ACTIVE);
            Map<MetadataKey, String> empty = authorityRows(store);
            assertFalse(store.replaceCa(original, state(original, CaState.DISABLED)));
            assertEquals(empty, authorityRows(store));
            store.putCa(original);
            Map<MetadataKey, String> before = authorityRows(store);
            assertFalse(store.replaceCa(state(original, CaState.DISABLED), original));
            assertEquals(before, authorityRows(store));
        }
    }

    @Test
    void historyCleanupRunsOnlyAfterSuccessfulReplacement(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            CaRecord original = initial(store);
            try (MetadataSnapshot snapshot = store.metadataStore().snapshot();
                    MetadataTransaction transaction = store.metadataStore().beginTransaction()) {
                AuthorityMetadataStore.stageCa(snapshot, transaction, original, true, Instant.EPOCH);
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
            }
            assertEquals(2, historyStates(store).size());
            assertFalse(store.replaceCa(state(original, CaState.DISABLED), original));
            assertEquals(2, historyStates(store).size());
            assertTrue(store.replaceCa(original, state(original, CaState.DISABLED)));
            assertEquals(List.of(CaState.ACTIVE, CaState.DISABLED), historyStates(store));
        }
    }

    @Test
    void rejectsInvalidInputsAndPrecommitValidationWithoutFencing(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options())) {
            CaRecord original = initial(store);
            CaRecord otherId = new CaRecord(new PkiId("other-authority"), original.kind(), original.state(),
                    original.issuerKeyRef(), original.subjectRef(), original.issuerIds(),
                    original.currentIssuanceIssuerId(), original.issuanceChainPathId());
            assertThrows(NullPointerException.class, () -> store.replaceCa(null, original));
            assertThrows(NullPointerException.class, () -> store.replaceCa(original, null));
            assertThrows(IllegalArgumentException.class, () -> store.replaceCa(original, otherId));
            Map<MetadataKey, String> before = authorityRows(store);
            CaRecord changedBase = new CaRecord(original.caId(), original.kind(), original.state(),
                    original.issuerKeyRef(), new SubjectRef("CN=Different"), original.issuerIds(),
                    original.currentIssuanceIssuerId(), original.issuanceChainPathId());
            assertThrows(IllegalStateException.class, () -> store.replaceCa(original, changedBase));
            CaRecord absentPath = new CaRecord(original.caId(), original.kind(), original.state(),
                    original.issuerKeyRef(), original.subjectRef(), original.issuerIds(),
                    original.currentIssuanceIssuerId(), new PkiId("absent-path"));
            assertThrows(IllegalStateException.class, () -> store.replaceCa(original, absentPath));
            assertEquals(original, store.getCa(original.caId()).orElseThrow());
            assertEquals(before, authorityRows(store));
        }
    }

    @Test
    void concurrentWinnerAfterSnapshotRejectsLoserWithoutMembershipOrHistoryLeak(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options())) {
            CaRecord original = initial(store);
            SemanticIssuanceFixture.issuer(store, 2);
            CaRecord winner = state(original, CaState.DISABLED);
            CaRecord loser = new CaRecord(original.caId(), original.kind(), CaState.ACTIVE, original.issuerKeyRef(),
                    original.subjectRef(), List.of(SemanticIssuanceFixture.issuerId(1), SemanticIssuanceFixture.issuerId(2)),
                    SemanticIssuanceFixture.issuerId(2), SemanticIssuanceFixture.path(2).pathId());
            AtomicReference<Map<MetadataKey, String>> winnerRows = new AtomicReference<>();
            InterleavingMetadata metadata = new InterleavingMetadata(store.metadataStore());
            metadata.beforeCommit = () -> {
                assertTrue(store.replaceCa(original, winner));
                winnerRows.set(authorityRows(store));
            };
            List<MetadataCommitResult> outcomes = new ArrayList<>();
            AuthorityMetadataStore authority = new AuthorityMetadataStore(metadata, outcomes::add);
            assertFalse(authority.replaceCa(original, loser, options().caHistoryPolicy()));
            assertEquals(1, outcomes.size());
            assertEquals(MetadataCommitResult.Outcome.NOT_COMMITTED, outcomes.getFirst().outcome());
            assertEquals(Optional.of(MetadataCommitResult.FailureCategory.CONFLICT), outcomes.getFirst().failureCategory());
            assertEquals(winner, store.getCa(original.caId()).orElseThrow());
            assertEquals(winnerRows.get(), authorityRows(store));
            assertEquals(List.of(CaState.ACTIVE, CaState.DISABLED), historyStates(store));
        }
    }

    @Test
    void helperAcknowledgesEveryAttemptOnceAndOnlyConflictReturnsFalse(@TempDir Path root) throws Exception {
        List<Optional<MetadataCommitResult.FailureCategory>> categories = List.of(
                Optional.of(MetadataCommitResult.FailureCategory.CONFLICT),
                Optional.of(MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED), Optional.empty());
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options())) {
            CaRecord original = initial(store);
            CaRecord replacement = state(original, CaState.DISABLED);
            Map<MetadataKey, String> before = authorityRows(store);
            for (Optional<MetadataCommitResult.FailureCategory> category : categories) {
                InterleavingMetadata metadata = new InterleavingMetadata(store.metadataStore());
                metadata.outcome = MetadataCommitResult.Outcome.NOT_COMMITTED;
                metadata.category = category;
                AtomicInteger callbacks = new AtomicInteger();
                AuthorityMetadataStore authority = new AuthorityMetadataStore(metadata, ignored -> callbacks.incrementAndGet());
                if (category.equals(Optional.of(MetadataCommitResult.FailureCategory.CONFLICT))) {
                    assertFalse(authority.replaceCa(original, replacement, options().caHistoryPolicy()));
                } else {
                    assertThrows(IllegalStateException.class,
                            () -> authority.replaceCa(original, replacement, options().caHistoryPolicy()));
                }
                assertEquals(1, callbacks.get());
                assertEquals(before, authorityRows(store));
            }
            AtomicInteger callbacks = new AtomicInteger();
            AuthorityMetadataStore authority = new AuthorityMetadataStore(store.metadataStore(), result -> {
                callbacks.incrementAndGet();
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, result.outcome());
            });
            assertTrue(authority.replaceCa(original, replacement, options().caHistoryPolicy()));
            assertEquals(1, callbacks.get());
        }
    }

    @Test
    void helperUnknownAndAcknowledgementFailurePropagateWithoutFalseResult(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options())) {
            CaRecord original = initial(store);
            CaRecord replacement = state(original, CaState.DISABLED);
            InterleavingMetadata metadata = new InterleavingMetadata(store.metadataStore());
            metadata.outcome = MetadataCommitResult.Outcome.UNKNOWN;
            AtomicInteger callbacks = new AtomicInteger();
            AuthorityMetadataStore authority = new AuthorityMetadataStore(metadata, ignored -> callbacks.incrementAndGet());
            assertThrows(IOException.class, () -> authority.replaceCa(original, replacement, options().caHistoryPolicy()));
            assertEquals(1, callbacks.get());
            PkiException acknowledgement = new PkiException("Injected acknowledgement failure",
                    PkiFailureReason.STORE_DURABILITY_UNCONFIRMED);
            callbacks.set(0);
            AuthorityMetadataStore failingAcknowledgement = new AuthorityMetadataStore(store.metadataStore(), result -> {
                callbacks.incrementAndGet();
                throw acknowledgement;
            });
            assertSame(acknowledgement, assertThrows(PkiException.class,
                    () -> failingAcknowledgement.replaceCa(original, replacement, options().caHistoryPolicy())));
            assertEquals(1, callbacks.get());
            assertEquals(replacement, store.getCa(original.caId()).orElseThrow());
        }
    }

    @Test
    void unknownCommitFencesFacadeAndReopenResolvesDurableWinner(@TempDir Path root) throws Exception {
        for (boolean durable : List.of(false, true)) {
            assertFacadeFailureRecovery(root.resolve("commit-" + durable), 2, durable, durable);
        }
    }

    @Test
    void acknowledgementFailureFencesFacadeWithoutMisreportingConflict(@TempDir Path root) throws Exception {
        assertFacadeFailureRecovery(root.resolve("acknowledgement"), 3, false, true);
    }

    private static void assertFacadeFailureRecovery(Path root, int forceOrdinal, boolean durable, boolean committed)
            throws Exception {
        ArmedWalFailure operations = new ArmedWalFailure();
        CaRecord original;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options(), Clock.systemUTC(),
                SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK, operations)) {
            original = initial(store);
            operations.arm(forceOrdinal, durable);
            PkiException failure = assertThrows(PkiException.class,
                    () -> store.replaceCa(original, state(original, CaState.DISABLED)));
            assertEquals(Optional.of(PkiFailureReason.STORE_DURABILITY_UNCONFIRMED), failure.failureReason());
            assertTrue(operations.injected);
            assertThrows(PkiException.class, () -> store.getCa(original.caId()));
            assertThrows(PkiException.class, () -> store.replaceCa(original, original));
            assertThrows(SigningActiveWal.RecoveryRequiredException.class, store::close);
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, options())) {
            assertEquals(committed ? state(original, CaState.DISABLED) : original,
                    reopened.getCa(original.caId()).orElseThrow());
            assertEquals(committed ? List.of(CaState.ACTIVE, CaState.DISABLED) : List.of(CaState.ACTIVE),
                    historyStates(reopened));
        }
    }

    private static CaRecord initial(FilesystemPkiStore store) throws Exception {
        SemanticIssuanceFixture.issuer(store, 1);
        CaRecord authority = authority(1, CaState.ACTIVE);
        store.putCa(authority);
        return authority;
    }

    private static CaRecord authority(int generation, CaState state) {
        return new CaRecord(SemanticIssuanceFixture.AUTHORITY, CaKind.ROOT, state, SemanticIssuanceFixture.KEY,
                new SubjectRef("CN=Acceptance Issuer"), List.of(SemanticIssuanceFixture.issuerId(generation)),
                SemanticIssuanceFixture.issuerId(generation), SemanticIssuanceFixture.path(generation).pathId());
    }

    private static CaRecord state(CaRecord record, CaState state) {
        return new CaRecord(record.caId(), record.kind(), state, record.issuerKeyRef(), record.subjectRef(),
                record.issuerIds(), record.currentIssuanceIssuerId(), record.issuanceChainPathId());
    }

    private static FsPkiStoreOptions options() {
        FsPkiStoreOptions defaults = FsPkiStoreOptions.defaults();
        return new FsPkiStoreOptions(FsHistoryPolicy.onWrite(Optional.empty()), defaults.profileHistoryPolicy(),
                defaults.revocationHistoryPolicy(), defaults.workflowHistoryPolicy(), defaults.strictSnapshotExport(),
                defaults.signingOperationHorizon(), defaults.signingIdPermittedSkew(), defaults.signingMaximumGroupSize(),
                defaults.signingResidentIndexBudgetBytes(), defaults.signingCompactionTransientBudgetBytes(), defaults.initialCrlNumber(), false);
    }

    private static Map<MetadataKey, String> authorityRows(FilesystemPkiStore store) throws IOException {
        return rows(store, AuthorityMetadataCodec.CA_BASE, AuthorityMetadataCodec.CA_CURRENT,
                AuthorityMetadataCodec.CA_HISTORY, AuthorityMetadataCodec.CA_GENERATION_ORDER,
                AuthorityMetadataCodec.CA_GENERATION_MEMBER);
    }

    private static Map<MetadataKey, String> rows(FilesystemPkiStore store, String... namespaces) throws IOException {
        Map<MetadataKey, String> result = new LinkedHashMap<>();
        try (MetadataSnapshot snapshot = store.metadataStore().snapshot()) {
            for (String namespace : namespaces) {
                try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(namespace), CancellationSignal.NONE)) {
                    Optional<MetadataSnapshot.Record> next;
                    while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                        try (MetadataSnapshot.Record record = next.orElseThrow()) {
                            result.put(record.key(), record.recordRevision() + ":" + HexFormat.of().formatHex(
                                    CredentialMetadataAuthority.read(record, AuthorityMetadataCodec.MAX_VALUE_BYTES)));
                        }
                    }
                }
            }
        }
        return result;
    }

    private static List<CaState> historyStates(FilesystemPkiStore store) throws IOException {
        List<AuthorityMetadataCodec.HistoryEntry> result = new ArrayList<>();
        try (MetadataSnapshot snapshot = store.metadataStore().snapshot();
                MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(AuthorityMetadataCodec.CA_HISTORY),
                        CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (MetadataSnapshot.Record record = next.orElseThrow()) {
                    result.add(AuthorityMetadataCodec.history(record.key(),
                            CredentialMetadataAuthority.read(record, AuthorityMetadataCodec.MAX_VALUE_BYTES), record.recordRevision()));
                }
            }
        }
        return result.stream().sorted(java.util.Comparator.comparingLong(AuthorityMetadataCodec.HistoryEntry::commitRevision))
                .map(entry -> entry.value().state()).toList();
    }

    @FunctionalInterface
    private interface BeforeCommit { void run() throws IOException; }

    /** Inserts a real competing commit, or supplies one exact result category to the helper. */
    private static final class InterleavingMetadata implements TransactionalMetadataStore {
        private final TransactionalMetadataStore delegate;
        private BeforeCommit beforeCommit;
        private MetadataCommitResult.Outcome outcome;
        private Optional<MetadataCommitResult.FailureCategory> category = Optional.empty();

        private InterleavingMetadata(TransactionalMetadataStore delegate) { this.delegate = delegate; }
        @Override public MetadataStoreId id() { return delegate.id(); }
        @Override public MetadataStoreCapabilities capabilities() { return delegate.capabilities(); }
        @Override public MetadataSnapshot snapshot() throws IOException { return delegate.snapshot(); }
        @Override public MetadataCommitResult resolve(MetadataTransactionId id) throws IOException { return delegate.resolve(id); }
        @Override public void acknowledge(MetadataTransactionId id) throws IOException { delegate.acknowledge(id); }
        @Override public void close() { }
        @Override public MetadataTransaction beginTransaction() throws IOException {
            MetadataTransaction transaction = delegate.beginTransaction();
            return new MetadataTransaction() {
                @Override public MetadataTransactionId id() { return transaction.id(); }
                @Override public void create(MetadataKey key, RepeatableContent content, CancellationSignal cancellation) throws IOException {
                    transaction.create(key, content, cancellation);
                }
                @Override public void replace(MetadataKey key, long revision, RepeatableContent content, CancellationSignal cancellation) throws IOException {
                    transaction.replace(key, revision, content, cancellation);
                }
                @Override public void delete(MetadataKey key, long revision) { transaction.delete(key, revision); }
                @Override public MetadataCommitResult commit() throws IOException {
                    if (beforeCommit != null) {
                        BeforeCommit action = beforeCommit;
                        beforeCommit = null;
                        action.run();
                    }
                    return outcome == null ? transaction.commit()
                            : new MetadataCommitResult(id(), outcome, OptionalLong.empty(), category);
                }
                @Override public void abort() throws IOException { transaction.abort(); }
                @Override public void close() throws IOException { transaction.close(); }
            };
        }
    }

    /** Existing WAL seam; arm after fixture publication, before issue/commit/acknowledgement. */
    private static final class ArmedWalFailure implements SigningActiveWal.Operations {
        private final AtomicInteger remaining = new AtomicInteger();
        private boolean durableBeforeFailure;
        private boolean injected;

        private void arm(int forceOrdinal, boolean durable) {
            durableBeforeFailure = durable;
            remaining.set(forceOrdinal);
        }
        @Override public boolean exists(Path path) { return Files.exists(path, LinkOption.NOFOLLOW_LINKS); }
        @Override public boolean isRegularFile(Path path) { return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS); }
        @Override public SigningActiveWal.WalChannel createNew(Path path) throws IOException {
            return wrap(FileChannel.open(path, Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.READ,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)));
        }
        @Override public SigningActiveWal.WalChannel openExisting(Path path) throws IOException {
            return wrap(FileChannel.open(path, Set.of(StandardOpenOption.READ, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)));
        }
        @Override public void forceDirectory(Path directory) throws IOException { SigningFormatSupport.forceDirectory(directory); }
        private SigningActiveWal.WalChannel wrap(FileChannel channel) throws IOException {
            long initialLength = channel.size();
            return new SigningActiveWal.WalChannel() {
                private long durableLength = initialLength;
                @Override public int read(ByteBuffer target) throws IOException { return channel.read(target); }
                @Override public int write(ByteBuffer source) throws IOException { return channel.write(source); }
                @Override public long position() throws IOException { return channel.position(); }
                @Override public SigningActiveWal.WalChannel position(long value) throws IOException { channel.position(value); return this; }
                @Override public long size() throws IOException { return channel.size(); }
                @Override public SigningActiveWal.WalChannel truncate(long size) throws IOException { channel.truncate(size); return this; }
                @Override public boolean isOpen() { return channel.isOpen(); }
                @Override public void close() throws IOException { channel.close(); }
                @Override public void force(boolean metadata) throws IOException {
                    if (remaining.get() > 0 && remaining.decrementAndGet() == 0) {
                        injected = true;
                        if (!durableBeforeFailure) channel.truncate(durableLength);
                        channel.force(metadata);
                        throw new IOException("Injected CA compare-and-set force failure");
                    }
                    channel.force(metadata);
                    durableLength = channel.size();
                }
            };
        }
    }
}
