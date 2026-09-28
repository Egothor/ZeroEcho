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

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataCursor;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.TransactionalMetadataStore;

/**
 * Stateless borrowed metadata CRUD; no aggregate publication. Public CA
 * ingestion (including lifecycle changes) and reconstruction visit O(G)
 * memberships end-to-end. Lifecycle updates stage two small heads; append
 * stages only the suffix, not the existing prefix. A single suffix helper call
 * performs constant membership work, but does not replace public ingestion.
 * Startup validates O(G + H) rows without expanding historical memberships.
 */
final class AuthorityMetadataStore { // NOPMD - CyclomaticComplexity totals cohesive independent operations; method-level checks remain enabled.
    private static final Logger LOG = Logger.getLogger(AuthorityMetadataStore.class.getName());
    private static final int MAX_BYTES = AuthorityMetadataCodec.MAX_VALUE_BYTES;
    // Ordinary transactions also publish an outcome and a watermark index row.
    /* default */ static final int MAX_BATCH_MUTATIONS = Math.min(SigningTransactionPayloadCodec.MAXIMUM_MUTATIONS,
            SigningWalFrameCodec.MAX_BATCH_FRAMES - 2);
    private final TransactionalMetadataStore metadata;
    private final Consumer<MetadataCommitResult> outcome;

    /* default */ AuthorityMetadataStore(TransactionalMetadataStore metadata, Consumer<MetadataCommitResult> outcome) {
        this.metadata = metadata;
        this.outcome = outcome;
    }

    /* default */ <T> Optional<T> find(MetadataKey key, BiFunction<MetadataKey, byte[], T> decoder) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot()) { return find(snapshot, key, decoder); }
    }

    /* default */ static <T> Optional<T> find(MetadataSnapshot snapshot, MetadataKey key, BiFunction<MetadataKey, byte[], T> decoder) throws IOException {
        try (MetadataSnapshot.Record record = snapshot.get(key).orElse(null)) {
            return record == null ? Optional.empty() : Optional.of(decoder.apply(record.key(), CredentialMetadataAuthority.read(record, MAX_BYTES)));
        }
    }

    /* default */ <T> List<T> list(String namespace, BiFunction<MetadataKey, byte[], T> decoder) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot()) { return list(snapshot, namespace, decoder); }
    }

    /* default */ static <T> List<T> list(MetadataSnapshot snapshot, String namespace, BiFunction<MetadataKey, byte[], T> decoder) throws IOException {
        List<T> values = new ArrayList<>();
        visit(snapshot, namespace, decoder, values::add);
        return List.copyOf(values);
    }

    /** Visits one detached decoded payload at a time; retention belongs to the visitor. */
    /* default */ static <T> void visit(MetadataSnapshot snapshot, String namespace, BiFunction<MetadataKey, byte[], T> decoder,
            Visitor<T> visitor) throws IOException {
        try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(namespace), CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (MetadataSnapshot.Record record = next.orElseThrow()) {
                    visitor.accept(decoder.apply(record.key(), CredentialMetadataAuthority.read(record, MAX_BYTES)));
                }
            }
        }
    }

    /** Checked visitor over decoded authority metadata. */
    /* default */
    @FunctionalInterface
    interface Visitor<T> {
        /** Consumes one decoded value, propagating storage failures. */
        void accept(T value) throws IOException;
    }

    /* default */ void create(MetadataKey key, byte[] payload) throws IOException {
        try (MetadataTransaction transaction = metadata.beginTransaction()) {
            create(transaction, key, payload);
            committed(transaction.commit());
        }
    }

    /* default */ void putCa(CaRecord ca, FsHistoryPolicy policy) throws IOException {
        // Each definite retry, if requested by the caller, gets a fresh issued
        // transaction and wall-clock sample. An UNKNOWN attempt is never replayed here.
        try (MetadataTransaction transaction = metadata.beginTransaction(); MetadataSnapshot snapshot = metadata.snapshot()) {
            Instant timestamp = Instant.now().truncatedTo(ChronoUnit.MICROS);
            try {
                stageCa(snapshot, transaction, ca, policy.enabled(), timestamp);
            } catch (IOException failure) {
                // No commit has been attempted: validation cannot make durability uncertain.
                throw new IllegalStateException("CA metadata validation failed", failure);
            }
            committed(transaction.commit());
        }
        if (policy.enabled() && policy.cleanupStrategy() == FsHistoryPolicy.CleanupStrategy.ON_WRITE
                && policy.retentionWindow().isPresent()) {
            prune(ca.caId(), Instant.now().minus(policy.retentionWindow().orElseThrow()));
        }
    }

    /** Compares and stages against one snapshot; only definite conflicts are a false result. */
    /* default */ boolean replaceCa(CaRecord expected, CaRecord replacement, FsHistoryPolicy policy) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot()) {
            Optional<CaRecord> current;
            try { current = ca(snapshot, expected.caId()); }
            catch (IOException failure) { throw new IllegalStateException("CA metadata validation failed", failure); }
            if (current.isEmpty() || !current.orElseThrow().equals(expected)) { return false; }
            try (MetadataTransaction transaction = metadata.beginTransaction()) {
                try {
                    stageCa(snapshot, transaction, replacement, policy.enabled(), Instant.now().truncatedTo(ChronoUnit.MICROS));
                } catch (IOException failure) {
                    // Comparison and staging are pre-commit validation, never uncertain publication.
                    throw new IllegalStateException("CA metadata validation failed", failure);
                }
                MetadataCommitResult result = transaction.commit();
                outcome.accept(result);
                if (result.outcome() == MetadataCommitResult.Outcome.NOT_COMMITTED) {
                    if (result.failureCategory().orElse(null) == MetadataCommitResult.FailureCategory.CONFLICT) { return false; }
                    throw new IllegalStateException("Authority metadata transaction was not committed");
                }
                if (result.outcome() != MetadataCommitResult.Outcome.COMMITTED) {
                    throw new IOException("Authority metadata transaction outcome is unknown");
                }
            }
        }
        if (policy.enabled() && policy.cleanupStrategy() == FsHistoryPolicy.CleanupStrategy.ON_WRITE
                && policy.retentionWindow().isPresent()) {
            prune(replacement.caId(), Instant.now().minus(policy.retentionWindow().orElseThrow()));
        }
        return true;
    }

    /** Only for a fresh, unexposed snapshot target; head publication is last. */
    /* default */ // Each iteration requires its own immutable value or failure object; sharing would conflate distinct records or attempts.
                  @SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops" })
                  void restoreCa(CaRecord ca, FsHistoryPolicy policy) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot()) {
            if (find(snapshot, AuthorityMetadataCodec.baseKey(ca.caId()), AuthorityMetadataCodec::base).isPresent()
                    || find(snapshot, AuthorityMetadataCodec.caKey(ca.caId()), AuthorityMetadataCodec::head).isPresent()) { throw invalid(); }
            requireSelection(snapshot, AuthorityMetadataCodec.Head.of(ca), false);
            IssuerGeneration selected = requireGeneration(snapshot, ca.caId(), ca.currentIssuanceIssuerId());
            if (!selected.signingKeyRef().equals(ca.issuerKeyRef())) { throw invalid(); }
            try (RestoreBatch batch = new RestoreBatch()) {
                batch.add(AuthorityMetadataCodec.baseKey(ca.caId()), FsCodec.encode(FsCodec.CA_BASE, AuthorityMetadataCodec.Base.of(ca)));
                for (int ordinal = 0; ordinal < ca.issuerIds().size(); ordinal++) {
                    PkiId generation = ca.issuerIds().get(ordinal);
                    requireGeneration(snapshot, ca.caId(), generation);
                    AuthorityMetadataCodec.Membership member = new AuthorityMetadataCodec.Membership(ca.caId(), generation, ordinal);
                    byte[] payload = FsCodec.encode(FsCodec.CA_MEMBERSHIP, member);
                    batch.addPair(AuthorityMetadataCodec.orderKey(ca.caId(), ordinal), AuthorityMetadataCodec.memberKey(ca.caId(), generation), payload);
                }
                batch.flush();
            }
        }
        try (MetadataSnapshot snapshot = metadata.snapshot(); MetadataTransaction transaction = metadata.beginTransaction()) {
            AuthorityMetadataCodec.Head head = AuthorityMetadataCodec.Head.of(ca);
            requireSelection(snapshot, head, true);
            byte[] payload = FsCodec.encode(FsCodec.CA_HEAD, head);
            create(transaction, AuthorityMetadataCodec.caKey(ca.caId()), payload);
            if (policy.enabled()) {
                Instant timestamp = Instant.now().truncatedTo(ChronoUnit.MICROS);
                create(transaction, AuthorityMetadataCodec.historyKey(ca.caId(), timestamp, transaction.id()), payload);
            }
            committed(transaction.commit());
        }
    }

    /** At most 30 caller mutations and 2 MiB including exact transaction framing. */
    private final class RestoreBatch implements AutoCloseable {
        private MetadataTransaction transaction;
        private int mutations;
        private long bytes = SigningTransactionPayloadCodec.emptyCommitBytes();

        /* default */ void add(MetadataKey key, byte[] payload) throws IOException {
            reserve(1, SigningTransactionPayloadCodec.encodedCreateBytes(key, payload.length));
            create(transaction, key, payload);
        }

        /* default */ void addPair(MetadataKey first, MetadataKey second, byte[] payload) throws IOException {
            long size = (long) SigningTransactionPayloadCodec.encodedCreateBytes(first, payload.length)
                    + SigningTransactionPayloadCodec.encodedCreateBytes(second, payload.length);
            reserve(2, size);
            create(transaction, first, payload);
            create(transaction, second, payload);
        }

        private void reserve(int count, long size) throws IOException {
            if (size + SigningTransactionPayloadCodec.emptyCommitBytes() > SigningWalFrameCodec.MAX_PAYLOAD_BYTES) { throw invalid(); }
            if (mutations + count > MAX_BATCH_MUTATIONS
                    || bytes + size > SigningWalFrameCodec.MAX_PAYLOAD_BYTES) { flush(); }
            if (transaction == null) { transaction = metadata.beginTransaction(); }
            mutations += count;
            bytes += size;
        }

        /* default */ void flush() throws IOException {
            if (transaction != null) {
                try (MetadataTransaction active = transaction) { committed(active.commit()); }
                finally { transaction = null; mutations = 0; bytes = SigningTransactionPayloadCodec.emptyCommitBytes(); }
            }
        }

        @Override public void close() throws IOException { if (transaction != null) { transaction.close(); } }
    }

    /* default */ static void stageCa(MetadataSnapshot snapshot, MetadataTransaction transaction, CaRecord ca,
            boolean history, Instant timestamp) throws IOException {
        AuthorityMetadataCodec.Base base = AuthorityMetadataCodec.Base.of(ca);
        Optional<AuthorityMetadataCodec.Base> previousBase = find(snapshot, AuthorityMetadataCodec.baseKey(ca.caId()), AuthorityMetadataCodec::base);
        if (previousBase.isPresent() && !previousBase.orElseThrow().equals(base)) { throw invalid(); }
        AuthorityMetadataCodec.Head head = AuthorityMetadataCodec.Head.of(ca);
        byte[] payload = FsCodec.encode(FsCodec.CA_HEAD, head);
        AuthorityMetadataCodec.requireValueSize(payload);
        MetadataKey key = AuthorityMetadataCodec.caKey(ca.caId());
        try (MetadataSnapshot.Record current = snapshot.get(key).orElse(null);
                RepeatableContent bytes = new ImmutableByteContent(payload)) {
            AuthorityMetadataCodec.Head previous = current == null ? null
                    : AuthorityMetadataCodec.head(current.key(), CredentialMetadataAuthority.read(current, MAX_BYTES));
            if (previous == null != previousBase.isEmpty() || previous != null
                    && (!previous.caId().equals(ca.caId()) || previous.membershipCount() > head.membershipCount())) { throw invalid(); }
            stageCaMemberships(snapshot, transaction, ca, head, previous);
            requireSelection(snapshot, head, false);
            if (previousBase.isEmpty()) { create(transaction, AuthorityMetadataCodec.baseKey(ca.caId()), FsCodec.encode(FsCodec.CA_BASE, base)); }
            if (current == null) { transaction.create(key, bytes, CancellationSignal.NONE); }
            else { transaction.replace(key, current.recordRevision(), bytes, CancellationSignal.NONE); }
        }
        if (history) { create(transaction, AuthorityMetadataCodec.historyKey(ca.caId(), timestamp, transaction.id()), payload); }
    }

    /* default */ static void stageMembership(MetadataSnapshot snapshot, MetadataTransaction transaction,
            AuthorityMetadataCodec.Membership member) throws IOException {
        MetadataKey orderKey = AuthorityMetadataCodec.orderKey(member.caId(), member.ordinal());
        MetadataKey memberKey = AuthorityMetadataCodec.memberKey(member.caId(), member.generationId());
        if (find(snapshot, orderKey, AuthorityMetadataCodec::membership).isPresent()
                || find(snapshot, memberKey, AuthorityMetadataCodec::membership).isPresent()) { throw invalid(); }
        byte[] payload = FsCodec.encode(FsCodec.CA_MEMBERSHIP, member);
        create(transaction, orderKey, payload);
        create(transaction, memberKey, payload);
    }

    /* default */ static Optional<CaRecord> ca(MetadataSnapshot snapshot, PkiId id) throws IOException {
        Optional<AuthorityMetadataCodec.Head> head = find(snapshot, AuthorityMetadataCodec.caKey(id), AuthorityMetadataCodec::head);
        if (head.isEmpty()) { return Optional.empty(); }
        if (!head.orElseThrow().caId().equals(id)) { throw invalid(); }
        return Optional.of(reconstruct(snapshot, head.orElseThrow()));
    }

    /* default */ static CaRecord reconstruct(MetadataSnapshot snapshot, AuthorityMetadataCodec.Head head) throws IOException {
        AuthorityMetadataCodec.Base base = find(snapshot, AuthorityMetadataCodec.baseKey(head.caId()), AuthorityMetadataCodec::base)
                .orElseThrow(AuthorityMetadataStore::invalid);
        if (!base.caId().equals(head.caId())) { throw invalid(); }
        // Do not preallocate from an untrusted persisted count before checking rows.
        List<PkiId> members = new ArrayList<>();
        for (int ordinal = 0; ordinal < head.membershipCount(); ordinal++) {
            AuthorityMetadataCodec.Membership member = requireMembership(snapshot, head.caId(), ordinal);
            requireGeneration(snapshot, head.caId(), member.generationId());
            members.add(member.generationId());
        }
        IssuerGeneration selected = requireSelection(snapshot, head, true);
        return new CaRecord(head.caId(), base.kind(), head.state(), selected.signingKeyRef(), base.subjectRef(),
                members, head.generationId(), head.pathId());
    }

    /* default */ static List<IssuerGeneration> generations(MetadataSnapshot snapshot, PkiId authority) throws IOException {
        Optional<AuthorityMetadataCodec.Head> current = find(snapshot, AuthorityMetadataCodec.caKey(authority), AuthorityMetadataCodec::head);
        if (current.isEmpty()) { return List.of(); }
        List<IssuerGeneration> generations = new ArrayList<>();
        for (int ordinal = 0; ordinal < current.orElseThrow().membershipCount(); ordinal++) {
            generations.add(requireGeneration(snapshot, authority, requireMembership(snapshot, authority, ordinal).generationId()));
        }
        return List.copyOf(generations);
    }

    private static AuthorityMetadataCodec.Membership requireMembership(MetadataSnapshot snapshot, PkiId authority, int ordinal) throws IOException {
        AuthorityMetadataCodec.Membership order = find(snapshot, AuthorityMetadataCodec.orderKey(authority, ordinal), AuthorityMetadataCodec::membership)
                .orElseThrow(AuthorityMetadataStore::invalid);
        AuthorityMetadataCodec.Membership reverse = find(snapshot, AuthorityMetadataCodec.memberKey(authority, order.generationId()), AuthorityMetadataCodec::membership)
                .orElseThrow(AuthorityMetadataStore::invalid);
        if (!order.caId().equals(authority) || order.ordinal() != ordinal || !order.equals(reverse)) { throw invalid(); }
        return order;
    }

    private static IssuerGeneration requireGeneration(MetadataSnapshot snapshot, PkiId authority, PkiId generationId) throws IOException {
        IssuerGeneration generation = find(snapshot, AuthorityMetadataCodec.generationKey(generationId), AuthorityMetadataCodec::generation)
                .orElseThrow(AuthorityMetadataStore::invalid);
        if (!generation.authorityId().equals(authority) || !generation.issuerId().equals(generationId)) { throw invalid(); }
        return generation;
    }

    private static IssuerGeneration requireSelection(MetadataSnapshot snapshot, AuthorityMetadataCodec.Head head, boolean retainedMembership) throws IOException {
        if (retainedMembership) {
            AuthorityMetadataCodec.Membership selected = find(snapshot, AuthorityMetadataCodec.memberKey(head.caId(), head.generationId()), AuthorityMetadataCodec::membership)
                    .orElseThrow(AuthorityMetadataStore::invalid);
            if (!selected.caId().equals(head.caId()) || !selected.generationId().equals(head.generationId())
                    || selected.ordinal() >= head.membershipCount()
                    || !requireMembership(snapshot, head.caId(), selected.ordinal()).equals(selected)) { throw invalid(); }
        }
        IssuerGeneration generation = requireGeneration(snapshot, head.caId(), head.generationId());
        IssuerChainPath path = find(snapshot, AuthorityMetadataCodec.pathKey(head.pathId()), AuthorityMetadataCodec::path)
                .orElseThrow(AuthorityMetadataStore::invalid);
        if (!path.pathId().equals(head.pathId()) || !path.authorityId().equals(head.caId())
                || !path.issuerId().equals(head.generationId()) || !path.orderedCredentialIds().getFirst().equals(generation.credentialId())) { throw invalid(); }
        return generation;
    }

    /* default */ static void validateAll(MetadataSnapshot snapshot) throws IOException {
        // Validate each current prefix once. History only checks count and exact selection.
        for (AuthorityMetadataCodec.Head head : list(snapshot, AuthorityMetadataCodec.CA_CURRENT, AuthorityMetadataCodec::head)) {
            reconstruct(snapshot, head);
        }
        for (AuthorityMetadataCodec.Base base : list(snapshot, AuthorityMetadataCodec.CA_BASE, AuthorityMetadataCodec::base)) {
            if (find(snapshot, AuthorityMetadataCodec.caKey(base.caId()), AuthorityMetadataCodec::head).isEmpty()) { throw invalid(); }
        }
        for (String namespace : List.of(AuthorityMetadataCodec.CA_GENERATION_ORDER, AuthorityMetadataCodec.CA_GENERATION_MEMBER)) {
            try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(namespace), CancellationSignal.NONE)) {
                Optional<MetadataSnapshot.Record> next;
                while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                    try (MetadataSnapshot.Record record = next.orElseThrow()) {
                        AuthorityMetadataCodec.Membership member = AuthorityMetadataCodec.membership(record.key(), CredentialMetadataAuthority.read(record, MAX_BYTES));
                        AuthorityMetadataCodec.Head head = find(snapshot, AuthorityMetadataCodec.caKey(member.caId()), AuthorityMetadataCodec::head)
                                .orElseThrow(AuthorityMetadataStore::invalid);
                        if (member.ordinal() >= head.membershipCount() || !member.equals(requireMembership(snapshot, member.caId(), member.ordinal()))) { throw invalid(); }
                    }
                }
            }
        }
        try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(AuthorityMetadataCodec.CA_HISTORY), CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (MetadataSnapshot.Record record = next.orElseThrow()) {
                    AuthorityMetadataCodec.Head head = AuthorityMetadataCodec.history(record.key(), CredentialMetadataAuthority.read(record, MAX_BYTES), record.commitRevision()).value();
                    AuthorityMetadataCodec.Head current = find(snapshot, AuthorityMetadataCodec.caKey(head.caId()), AuthorityMetadataCodec::head)
                            .orElseThrow(AuthorityMetadataStore::invalid);
                    if (head.membershipCount() > current.membershipCount()) { throw invalid(); }
                    requireSelection(snapshot, head, true);
                }
            }
        }
    }

    /* default */ static Optional<CaRecord> caAt(MetadataSnapshot snapshot, PkiId id, Instant at, FsHistoryPolicy policy,
            boolean strict) throws IOException {
        AuthorityMetadataCodec.HistoryEntry latest = null;
        if (policy.enabled()) {
            try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.prefix(AuthorityMetadataCodec.CA_HISTORY,
                    AuthorityMetadataCodec.historyPrefix(id)), CancellationSignal.NONE)) {
                Optional<MetadataSnapshot.Record> next;
                while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                    try (MetadataSnapshot.Record record = next.orElseThrow()) {
                        AuthorityMetadataCodec.HistoryEntry entry = AuthorityMetadataCodec.history(record.key(),
                                CredentialMetadataAuthority.read(record, MAX_BYTES), record.commitRevision());
                        if (!entry.value().caId().equals(id)) { throw new IOException("CA history authority differs"); }
                        if (!entry.timestamp().isAfter(at) && (latest == null || AuthorityMetadataCodec.HISTORY_ORDER.compare(entry, latest) > 0)) {
                            latest = entry;
                        }
                    }
                }
            }
        }
        if (latest != null) { return Optional.of(reconstruct(snapshot, latest.value())); }
        if (strict && policy.enabled()) { throw new IOException("No CA history entry is available for snapshot time"); }
        return ca(snapshot, id);
    }

    /* default */ void prune(PkiId id, Instant cutoff) throws IOException {
        // Separate, bounded best-effort cleanup; never changes the committed current row.
        try (MetadataSnapshot snapshot = metadata.snapshot(); MetadataTransaction transaction = metadata.beginTransaction();
                MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.prefix(AuthorityMetadataCodec.CA_HISTORY,
                        AuthorityMetadataCodec.historyPrefix(id)), CancellationSignal.NONE)) {
            int deletes = 0;
            int examined = 0;
            Optional<MetadataSnapshot.Record> next;
            while (examined < MAX_BATCH_MUTATIONS
                    && (next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (MetadataSnapshot.Record record = next.orElseThrow()) {
                    examined++;
                    AuthorityMetadataCodec.HistoryEntry entry = AuthorityMetadataCodec.history(record.key(),
                            CredentialMetadataAuthority.read(record, MAX_BYTES), record.commitRevision());
                    if (entry.timestamp().isBefore(cutoff)) { transaction.delete(record.key(), record.recordRevision()); deletes++; }
                }
            }
            if (deletes > 0) {
                MetadataCommitResult result = transaction.commit();
                if (result.outcome() == MetadataCommitResult.Outcome.NOT_COMMITTED) {
                    outcome.accept(result);
                    LOG.log(Level.FINE, "CA history cleanup deferred: code=CA_HISTORY_CLEANUP_CONFLICT");
                    return;
                }
                // Unlike a known cleanup conflict, uncertainty still fences the caller.
                committed(result);
            }
        }
    }

    /* default */ static void create(MetadataTransaction transaction, MetadataKey key, byte[] payload) throws IOException {
        AuthorityMetadataCodec.requireValueSize(payload);
        try (RepeatableContent bytes = new ImmutableByteContent(payload)) { transaction.create(key, bytes, CancellationSignal.NONE); }
    }

    private void committed(MetadataCommitResult result) throws IOException {
        outcome.accept(result);
        if (result.outcome() == MetadataCommitResult.Outcome.NOT_COMMITTED) {
            throw new IllegalStateException("Authority metadata transaction was not committed");
        }
        if (result.outcome() != MetadataCommitResult.Outcome.COMMITTED) {
            throw new IOException("Authority metadata transaction outcome is unknown");
        }
    }

    private static IOException invalid() { return new IOException("CA metadata binding is inconsistent"); }

    // Each append retains its own immutable generation membership.
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    private static void stageCaMemberships(MetadataSnapshot snapshot, MetadataTransaction transaction, CaRecord ca,
            AuthorityMetadataCodec.Head head, AuthorityMetadataCodec.Head previous) throws IOException {
        int existing = previous == null ? 0 : previous.membershipCount();
        for (int ordinal = 0; ordinal < ca.issuerIds().size(); ordinal++) {
            PkiId generationId = ca.issuerIds().get(ordinal);
            IssuerGeneration generation = requireGeneration(snapshot, ca.caId(), generationId);
            if (generationId.equals(head.generationId()) && !generation.signingKeyRef().equals(ca.issuerKeyRef())) { throw invalid(); }
            if (ordinal < existing) {
                if (!requireMembership(snapshot, ca.caId(), ordinal).generationId().equals(generationId)) { throw invalid(); }
            } else { stageMembership(snapshot, transaction, new AuthorityMetadataCodec.Membership(ca.caId(), generationId, ordinal)); }
        }
    }
}
