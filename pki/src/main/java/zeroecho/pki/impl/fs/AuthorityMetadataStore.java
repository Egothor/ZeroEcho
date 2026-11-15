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

    /* default */ void createGeneration(IssuerGeneration generation,
            zeroecho.pki.api.ca.IssuerCryptographicBinding binding) throws IOException {
        requireBinding(generation, binding);
        byte[] encoded = IssuerBindingStorageCodec.encode(binding, generation);
        try (MetadataTransaction transaction = metadata.beginTransaction()) {
            create(transaction, AuthorityMetadataCodec.generationKey(generation.issuerId()), FsCodec.encode(FsCodec.ISSUER_GENERATION, generation));
            create(transaction, AuthorityMetadataCodec.bindingKey(generation.issuerId()), encoded);
            committed(transaction.commit());
        }
    }

    /* default */ static Optional<zeroecho.pki.api.ca.IssuerCryptographicBinding> findBinding(MetadataSnapshot snapshot, PkiId issuerId) throws IOException {
        try (var record = snapshot.get(AuthorityMetadataCodec.bindingKey(issuerId)).orElse(null)) {
            return record == null ? Optional.empty() : Optional.of(decodeBinding(snapshot, record.key(), CredentialMetadataAuthority.read(record, MAX_BYTES)));
        }
    }

    private static void visitBindings(MetadataSnapshot snapshot, Visitor<zeroecho.pki.api.ca.IssuerCryptographicBinding> visitor) throws IOException {
        try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(AuthorityMetadataCodec.ISSUER_CRYPTO_BINDING), CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (var record = next.orElseThrow()) {
                    visitor.accept(decodeBinding(snapshot, record.key(), CredentialMetadataAuthority.read(record, MAX_BYTES)));
                }
            }
        }
    }

    private static zeroecho.pki.api.ca.IssuerCryptographicBinding decodeBinding(MetadataSnapshot snapshot, MetadataKey key, byte[] bytes) throws IOException {
        PkiId issuer = IssuerBindingStorageCodec.issuerId(bytes);
        IssuerGeneration generation = find(snapshot, AuthorityMetadataCodec.generationKey(issuer), AuthorityMetadataCodec::generation)
                .orElseThrow(AuthorityMetadataStore::invalid);
        var binding = AuthorityMetadataCodec.binding(key, bytes, generation);
        return binding;
    }

    private static void requireBinding(IssuerGeneration generation, zeroecho.pki.api.ca.IssuerCryptographicBinding binding) throws IOException {
        if (!generation.issuerId().equals(binding.issuerId()) || !generation.authorityId().equals(binding.authorityId())
                || !generation.credentialId().equals(binding.credentialId()) || !generation.signingKeyRef().equals(binding.primary().keyRef())
                || !generation.profilePolicyCommitment().equals(java.util.HexFormat.of().formatHex(binding.profile().canonicalSha256()))
                || !generation.x509BindingCommitment().equals(binding.bindingSetCommitment())) {
            throw invalid();
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
            requireHead(snapshot, ca);
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
                MetadataKey historyKey = AuthorityMetadataCodec.historyKey(ca.caId(), timestamp, transaction.id());
                create(transaction, historyKey, payload);
                create(transaction, CaLifecycleMetadataCodec.historyKey(historyKey),
                        CaLifecycleMetadataCodec.encode(requireHead(snapshot, ca)));
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
        stageCa(snapshot, transaction, ca, history, timestamp, Optional.empty(), Optional.empty());
    }

    /* default */ static void stageCaFenced(MetadataSnapshot snapshot, MetadataTransaction transaction, CaRecord ca,
            boolean history, Instant timestamp, zeroecho.pki.api.ca.CaHeadSnapshot expected) throws IOException {
        stageCa(snapshot, transaction, ca, history, timestamp, Optional.of(expected), Optional.empty());
    }

    private static void stageCa(MetadataSnapshot snapshot, MetadataTransaction transaction, CaRecord ca,
            boolean history, Instant timestamp, Optional<zeroecho.pki.api.ca.CaHeadSnapshot> expected,
            Optional<zeroecho.pki.api.ca.RootTrustAnchorActivation> activation) throws IOException {
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
            var selected = requireGeneration(snapshot, ca.caId(), head.generationId());
            var binding = findBinding(snapshot, selected.issuerId()).orElseThrow(AuthorityMetadataStore::invalid);
            Optional<zeroecho.pki.api.ca.CaHeadSnapshot> original = CaLifecycleMetadataCodec.head(snapshot, ca.caId());
            boolean changesHead = previous != null && (!previous.generationId().equals(head.generationId()) || !previous.pathId().equals(head.pathId()));
            if (previous == null && original.isPresent() || previous != null && original.isEmpty()) { throw invalid(); }
            if (expected.isPresent() && !original.filter(expected.orElseThrow()::equals).isPresent()) { throw invalid(); }
            if (changesHead && expected.isEmpty()) { throw new IllegalArgumentException("Selected CA head changes require an admitted epoch fence"); }
            if (changesHead && ca.kind() == zeroecho.pki.api.ca.CaKind.ROOT) {
                var old = findBinding(snapshot, original.orElseThrow().issuerId()).orElseThrow(AuthorityMetadataStore::invalid);
                if (!sameAnchor(old, binding) && activation.isEmpty()) { throw new IllegalArgumentException("Root anchor changes require an acknowledged candidate activation"); }
            }
            long epoch = previous == null ? 1 : changesHead ? Math.incrementExact(original.orElseThrow().epoch()) : original.orElseThrow().epoch();
            var updated = new zeroecho.pki.api.ca.CaHeadSnapshot(1, ca.caId(), epoch, selected.issuerId(), head.pathId(), binding.commitment());
            stageHead(snapshot, transaction, updated);
            stageCaMemberships(snapshot, transaction, ca, head, previous);
            requireSelection(snapshot, head, false);
            if (previousBase.isEmpty()) { create(transaction, AuthorityMetadataCodec.baseKey(ca.caId()), FsCodec.encode(FsCodec.CA_BASE, base)); }
            if (current == null) { transaction.create(key, bytes, CancellationSignal.NONE); }
            else { transaction.replace(key, current.recordRevision(), bytes, CancellationSignal.NONE); }
        }
        if (history) {
            MetadataKey historyKey = AuthorityMetadataCodec.historyKey(ca.caId(), timestamp, transaction.id());
            create(transaction, historyKey, payload);
            var original = CaLifecycleMetadataCodec.head(snapshot, ca.caId());
            boolean changes = original.isPresent() && (!original.orElseThrow().issuerId().equals(head.generationId()) || !original.orElseThrow().pathId().equals(head.pathId()));
            long epoch = original.isEmpty() ? 1 : changes ? Math.incrementExact(original.orElseThrow().epoch()) : original.orElseThrow().epoch();
            var binding = findBinding(snapshot, head.generationId()).orElseThrow(AuthorityMetadataStore::invalid);
            create(transaction, CaLifecycleMetadataCodec.historyKey(historyKey), CaLifecycleMetadataCodec.encode(
                    new zeroecho.pki.api.ca.CaHeadSnapshot(1, ca.caId(), epoch, head.generationId(), head.pathId(), binding.commitment())));
        }
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
        CaRecord value = reconstruct(snapshot, head.orElseThrow());
        requireHead(snapshot, value);
        return Optional.of(value);
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
        requireBinding(generation, findBinding(snapshot, generationId).orElseThrow(() -> new IOException(
                "Required issuer cryptographic binding is missing; initialize a fresh empty PKI store")));
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
        visit(snapshot, AuthorityMetadataCodec.ISSUER_GENERATION, AuthorityMetadataCodec::generation,
                generation -> requireGeneration(snapshot, generation.authorityId(), generation.issuerId()));
        visitBindings(snapshot, binding -> requireGeneration(snapshot, binding.authorityId(), binding.issuerId()));
        for (var head : list(snapshot, CaLifecycleMetadataCodec.HEAD, CaLifecycleMetadataCodec::headRow)) {
            CaRecord ca = ca(snapshot, head.caId()).orElseThrow(AuthorityMetadataStore::invalid);
            if (!head.equals(requireHead(snapshot, ca))) { throw invalid(); }
        }
        for (var transition : list(snapshot, CaLifecycleMetadataCodec.TRANSITION, CaLifecycleMetadataCodec::transitionRow)) {
            validateTransition(snapshot, transition);
            CaRecord ca = ca(snapshot, transition.caId()).orElseThrow(AuthorityMetadataStore::invalid);
            if (ca.kind() != zeroecho.pki.api.ca.CaKind.ROOT || !ca.issuerIds().contains(transition.candidateIssuerId())
                    || requireHead(snapshot, ca).epoch() < transition.expectedHead().epoch()
                    || !find(snapshot, CaLifecycleMetadataCodec.candidateKey(transition.candidateIssuerId()), CaLifecycleMetadataCodec::transitionRow)
                        .filter(transition::equals).isPresent()) { throw invalid(); }
        }
        for (var transition : list(snapshot, CaLifecycleMetadataCodec.CANDIDATE_INDEX, CaLifecycleMetadataCodec::transitionRow)) {
            if (!CaLifecycleMetadataCodec.transition(snapshot, transition.transitionId()).filter(transition::equals).isPresent()) { throw invalid(); }
        }
        for (var activation : list(snapshot, CaLifecycleMetadataCodec.ACTIVATION, CaLifecycleMetadataCodec::activationRow)) {
            var transition = CaLifecycleMetadataCodec.transition(snapshot, activation.transitionId()).orElseThrow(AuthorityMetadataStore::invalid);
            CaRecord ca = ca(snapshot, transition.caId()).orElseThrow(AuthorityMetadataStore::invalid);
            if (!activation.transitionCommitment().equals(transition.commitment()) || !activation.expectedHead().equals(transition.expectedHead())
                    || !activation.candidateIssuerId().equals(transition.candidateIssuerId())
                    || !activation.candidatePathId().equals(transition.candidatePathId())
                    || activation.newEpoch() > requireHead(snapshot, ca).epoch()) { throw invalid(); }
        }
        // Validate each current prefix once. History only checks count and exact selection.
        for (AuthorityMetadataCodec.Head head : list(snapshot, AuthorityMetadataCodec.CA_CURRENT, AuthorityMetadataCodec::head)) {
            requireHead(snapshot, reconstruct(snapshot, head));
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
        try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(CaLifecycleMetadataCodec.HEAD_HISTORY), CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (var row = next.orElseThrow(); var original = snapshot.get(new MetadataKey(AuthorityMetadataCodec.CA_HISTORY, row.key().key())).orElse(null)) {
                    if (original == null) { throw invalid(); }
                    CaLifecycleMetadataCodec.decodeHead(CredentialMetadataAuthority.read(row, MAX_BYTES));
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
                    var historical = find(snapshot, CaLifecycleMetadataCodec.historyKey(record.key()), (key, bytes) -> {
                        try { return CaLifecycleMetadataCodec.decodeHead(bytes); } catch (IOException failure) { throw new IllegalStateException(failure); }
                    }).orElseThrow(AuthorityMetadataStore::invalid);
                    var binding = findBinding(snapshot, head.generationId()).orElseThrow(AuthorityMetadataStore::invalid);
                    if (!historical.caId().equals(head.caId()) || !historical.issuerId().equals(head.generationId())
                            || !historical.pathId().equals(head.pathId()) || !historical.bindingCommitment().equals(binding.commitment())
                            || historical.epoch() > CaLifecycleMetadataCodec.head(snapshot, head.caId()).orElseThrow().epoch()) { throw invalid(); }

                }
            }
        }
    }

    /* default */ static zeroecho.pki.api.ca.CaHeadSnapshot requireHead(MetadataSnapshot snapshot, CaRecord ca) throws IOException {
        var value = CaLifecycleMetadataCodec.head(snapshot, ca.caId()).orElseThrow(() -> new IOException("Required CA head epoch is missing"));
        var binding = findBinding(snapshot, ca.currentIssuanceIssuerId()).orElseThrow(AuthorityMetadataStore::invalid);
        if (!value.issuerId().equals(ca.currentIssuanceIssuerId()) || !value.pathId().equals(ca.issuanceChainPathId())
                || !value.bindingCommitment().equals(binding.commitment())) { throw invalid(); }
        if (ca.kind() == zeroecho.pki.api.ca.CaKind.ROOT) {
            var candidate = find(snapshot, CaLifecycleMetadataCodec.candidateKey(value.issuerId()), CaLifecycleMetadataCodec::transitionRow);
            if (candidate.isPresent()) {
                var transition = candidate.orElseThrow();
                var receipt = CaLifecycleMetadataCodec.activation(snapshot, transition.transitionId())
                        .orElseThrow(() -> new IOException("Selected root candidate is missing its activation receipt"));
                if (!transition.caId().equals(ca.caId()) || !transition.candidatePathId().equals(value.pathId())
                        || !receipt.transitionCommitment().equals(transition.commitment())
                        || !receipt.expectedHead().equals(transition.expectedHead())
                        || !receipt.candidateIssuerId().equals(value.issuerId()) || !receipt.candidatePathId().equals(value.pathId())
                        || receipt.newEpoch() > value.epoch()) { throw invalid(); }
            }
        }
        return value;
    }

    private static void stageHead(MetadataSnapshot snapshot, MetadataTransaction transaction,
            zeroecho.pki.api.ca.CaHeadSnapshot head) throws IOException {
        MetadataKey key = CaLifecycleMetadataCodec.headKey(head.caId());
        try (var previous = snapshot.get(key).orElse(null); var bytes = new ImmutableByteContent(CaLifecycleMetadataCodec.encode(head))) {
            if (previous == null) { transaction.create(key, bytes, CancellationSignal.NONE); }
            else { transaction.replace(key, previous.recordRevision(), bytes, CancellationSignal.NONE); }
        }
    }

    private static boolean sameAnchor(zeroecho.pki.api.ca.IssuerCryptographicBinding left, zeroecho.pki.api.ca.IssuerCryptographicBinding right) {
        return sameKey(left.primary(), right.primary()) && left.alternative().isPresent() == right.alternative().isPresent()
                && (left.alternative().isEmpty() || sameKey(left.alternative().orElseThrow(), right.alternative().orElseThrow()));
    }
    private static boolean sameKey(zeroecho.pki.api.ca.IssuerKeyBinding left, zeroecho.pki.api.ca.IssuerKeyBinding right) {
        return left.subjectSpkiSha256().equals(right.subjectSpkiSha256()) && left.publicKeyAlgorithm().equals(right.publicKeyAlgorithm())
                && left.signatureAlgorithm().equals(right.signatureAlgorithm())
                && java.util.Arrays.equals(left.signatureAlgorithmIdentifier().bytes(), right.signatureAlgorithmIdentifier().bytes());
    }

    /* default */ boolean compareAndSetHead(zeroecho.pki.api.ca.CaHeadSnapshot expected, CaRecord replacement, FsHistoryPolicy history) throws IOException {
        try (var snapshot = metadata.snapshot()) {
            if (!CaLifecycleMetadataCodec.head(snapshot, expected.caId()).filter(expected::equals).isPresent()) { return false; }
            if (ca(snapshot, expected.caId()).orElseThrow(AuthorityMetadataStore::invalid).state() != replacement.state()) { return false; }
            if (!replacement.caId().equals(expected.caId())) { throw new IllegalArgumentException("Replacement CA differs from expected head authority"); }
            try (var transaction = metadata.beginTransaction()) {
                stageCa(snapshot, transaction, replacement, history.enabled(), Instant.now().truncatedTo(ChronoUnit.MICROS), Optional.of(expected), Optional.empty());
                MetadataCommitResult result = transaction.commit();
                outcome.accept(result);
                if (result.outcome() == MetadataCommitResult.Outcome.NOT_COMMITTED) {
                    if (result.failureCategory().orElse(null) == MetadataCommitResult.FailureCategory.CONFLICT) { return false; }
                    throw new IllegalStateException("Authority metadata transaction was not committed");
                }
                if (result.outcome() != MetadataCommitResult.Outcome.COMMITTED) {
                    throw new IOException("Authority metadata transaction outcome is unknown");
                }
                return true;
            }
        }
    }

    /* default */ zeroecho.pki.api.ca.RootTrustAnchorTransition registerCandidate(zeroecho.pki.api.ca.RootTrustAnchorTransition transition,
            FsHistoryPolicy history) throws IOException {
        try (var snapshot = metadata.snapshot()) {
            var existing = CaLifecycleMetadataCodec.transition(snapshot, transition.transitionId());
            if (existing.isPresent()) {
                if (!existing.orElseThrow().equals(transition)) { throw new IllegalArgumentException("Root candidate transition ID already has different immutable content"); } return existing.orElseThrow();
            }
            CaRecord ca = ca(snapshot, transition.caId()).orElseThrow(AuthorityMetadataStore::invalid);
            var head = requireHead(snapshot, ca);
            if (ca.kind() != zeroecho.pki.api.ca.CaKind.ROOT || ca.state() != zeroecho.pki.api.ca.CaState.ACTIVE
                    || !head.equals(transition.expectedHead())) { throw new IllegalArgumentException("Root candidate expected head is stale or authority is inactive"); }
            validateTransition(snapshot, transition);
            var current = findBinding(snapshot, head.issuerId()).orElseThrow(AuthorityMetadataStore::invalid);
            var candidate = findBinding(snapshot, transition.candidateIssuerId()).orElseThrow(AuthorityMetadataStore::invalid);
            if (sameAnchor(current, candidate)) { throw new IllegalArgumentException("Same-anchor renewal must use guarded head publication"); }
            var members = new ArrayList<>(ca.issuerIds());
            if (!members.contains(transition.candidateIssuerId())) { members.add(transition.candidateIssuerId()); }
            CaRecord replacement = new CaRecord(ca.caId(), ca.kind(), ca.state(), ca.issuerKeyRef(), ca.subjectRef(), members, ca.currentIssuanceIssuerId(), ca.issuanceChainPathId());
            try (var transaction = metadata.beginTransaction()) {
                stageCa(snapshot, transaction, replacement, history.enabled(), Instant.now().truncatedTo(ChronoUnit.MICROS), Optional.of(head), Optional.empty());
                create(transaction, CaLifecycleMetadataCodec.transitionKey(transition.transitionId()), CaLifecycleMetadataCodec.encode(transition));
                create(transaction, CaLifecycleMetadataCodec.candidateKey(transition.candidateIssuerId()), CaLifecycleMetadataCodec.encode(transition));
                MetadataCommitResult result = transaction.commit();
                if (definiteConflict(result)) {
                    try (var committedSnapshot = metadata.snapshot()) {
                        var retained = CaLifecycleMetadataCodec.transition(committedSnapshot, transition.transitionId()).orElseThrow(() -> new IllegalArgumentException("Root candidate registration lost its expected head conflict"));
                        if (!retained.equals(transition)) { throw new IllegalArgumentException("Concurrent root candidate has different immutable content"); } return retained;
                    }
                }
                committed(result); return transition;
            }
        }
    }

    /* default */ zeroecho.pki.api.ca.RootTrustAnchorActivation activateCandidate(PkiId transitionId,
            zeroecho.pki.api.ca.CaHeadSnapshot expected, zeroecho.pki.api.ca.RootTrustAnchorActivation activation, FsHistoryPolicy history) throws IOException {
        try (var snapshot = metadata.snapshot()) {
            var existing = CaLifecycleMetadataCodec.activation(snapshot, transitionId);
            if (existing.isPresent()) {
                if (!existing.orElseThrow().equals(activation)) { throw new IllegalArgumentException("Root activation already has a different immutable receipt"); } return existing.orElseThrow();
            }
            var transition = CaLifecycleMetadataCodec.transition(snapshot, transitionId).orElseThrow(AuthorityMetadataStore::invalid);
            CaRecord ca = ca(snapshot, transition.caId()).orElseThrow(AuthorityMetadataStore::invalid);
            if (!requireHead(snapshot, ca).equals(expected) || !expected.equals(transition.expectedHead())
                    || !activation.expectedHead().equals(expected) || !activation.transitionId().equals(transitionId)
                    || !activation.transitionCommitment().equals(transition.commitment())
                    || !activation.candidateIssuerId().equals(transition.candidateIssuerId())
                    || !activation.candidatePathId().equals(transition.candidatePathId())
                    || !ca.issuerIds().contains(transition.candidateIssuerId()) || ca.state() != zeroecho.pki.api.ca.CaState.ACTIVE) {
                throw new IllegalArgumentException("Root activation expected head or approved receipt differs from its candidate");
            }
            validateTransition(snapshot, transition);
            var generation = requireGeneration(snapshot, ca.caId(), transition.candidateIssuerId());
            CaRecord replacement = new CaRecord(ca.caId(), ca.kind(), ca.state(), generation.signingKeyRef(), ca.subjectRef(), ca.issuerIds(), generation.issuerId(), transition.candidatePathId());
            try (var transaction = metadata.beginTransaction()) {
                stageCa(snapshot, transaction, replacement, history.enabled(), activation.acceptedAt(), Optional.of(expected), Optional.of(activation));
                create(transaction, CaLifecycleMetadataCodec.activationKey(transitionId), CaLifecycleMetadataCodec.encode(activation));
                MetadataCommitResult result = transaction.commit();
                if (definiteConflict(result)) {
                    try (var current = metadata.snapshot()) {
                        var retained = CaLifecycleMetadataCodec.activation(current, transitionId).orElseThrow(() -> new IllegalArgumentException("Root activation lost its expected head conflict"));
                        if (!retained.equals(activation)) { throw new IllegalArgumentException("Concurrent root activation has a different immutable receipt"); } return retained;
                    }
                }
                committed(result); return activation;
            }
        }
    }

    private static boolean definiteConflict(MetadataCommitResult result) {
        return result.outcome() == MetadataCommitResult.Outcome.NOT_COMMITTED
                && result.failureCategory().filter(MetadataCommitResult.FailureCategory.CONFLICT::equals).isPresent();
    }

    private static void validateTransition(MetadataSnapshot snapshot, zeroecho.pki.api.ca.RootTrustAnchorTransition value) throws IOException {
        var old = requireGeneration(snapshot, value.caId(), value.expectedHead().issuerId());
        var candidate = requireGeneration(snapshot, value.caId(), value.candidateIssuerId());
        var oldBinding = findBinding(snapshot, old.issuerId()).orElseThrow(AuthorityMetadataStore::invalid);
        var candidateBinding = findBinding(snapshot, candidate.issuerId()).orElseThrow(AuthorityMetadataStore::invalid);
        var path = find(snapshot, AuthorityMetadataCodec.pathKey(value.candidatePathId()), AuthorityMetadataCodec::path).orElseThrow(AuthorityMetadataStore::invalid);
        if (candidate.state() != zeroecho.pki.api.ca.IssuerGenerationState.ACTIVE
                || !old.credentialId().equals(value.oldCredentialId()) || !oldBinding.certificateSha256().equals(value.oldCertificateSha256())
                || !oldBinding.commitment().equals(value.oldBindingCommitment()) || !candidate.credentialId().equals(value.candidateCredentialId())
                || !candidateBinding.certificateSha256().equals(value.candidateCertificateSha256()) || !candidateBinding.commitment().equals(value.candidateBindingCommitment())
                || !path.issuerId().equals(candidate.issuerId()) || !path.authorityId().equals(value.caId())
                || !path.orderedCredentialIds().getFirst().equals(candidate.credentialId())) { throw invalid(); }
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

    /* default */ static zeroecho.pki.api.ca.CaHeadSnapshot headAt(MetadataSnapshot snapshot, CaRecord selected,
            Instant at, FsHistoryPolicy policy) throws IOException {
        AuthorityMetadataCodec.HistoryEntry latest = null;
        if (policy.enabled()) {
            try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.prefix(AuthorityMetadataCodec.CA_HISTORY,
                    AuthorityMetadataCodec.historyPrefix(selected.caId())), CancellationSignal.NONE)) {
                Optional<MetadataSnapshot.Record> next;
                while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                    try (var record = next.orElseThrow()) {
                        var entry = AuthorityMetadataCodec.history(record.key(), CredentialMetadataAuthority.read(record, MAX_BYTES), record.commitRevision());
                        if (!entry.timestamp().isAfter(at) && (latest == null || AuthorityMetadataCodec.HISTORY_ORDER.compare(entry, latest) > 0)) { latest = entry; }
                    }
                }
            }
        }
        if (latest == null) { return requireHead(snapshot, selected); }
        var head = find(snapshot, CaLifecycleMetadataCodec.historyKey(latest.key()), (key, bytes) -> {
            try { return CaLifecycleMetadataCodec.decodeHead(bytes); } catch (IOException failure) { throw new IllegalStateException(failure); }
        }).orElseThrow(() -> new IOException("Snapshot historical CA epoch is missing"));
        if (!head.caId().equals(selected.caId()) || !head.issuerId().equals(selected.currentIssuanceIssuerId())
                || !head.pathId().equals(selected.issuanceChainPathId())) { throw invalid(); }
        return head;
    }

    /* default */ void prune(PkiId id, Instant cutoff) throws IOException {
        // Separate, bounded best-effort cleanup; never changes the committed current row.
        try (MetadataSnapshot snapshot = metadata.snapshot(); MetadataTransaction transaction = metadata.beginTransaction();
                MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.prefix(AuthorityMetadataCodec.CA_HISTORY,
                        AuthorityMetadataCodec.historyPrefix(id)), CancellationSignal.NONE)) {
            int deletes = 0;
            int examined = 0;
            Optional<MetadataSnapshot.Record> next;
            while (examined < MAX_BATCH_MUTATIONS / 2
                    && (next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (MetadataSnapshot.Record record = next.orElseThrow()) {
                    examined++;
                    AuthorityMetadataCodec.HistoryEntry entry = AuthorityMetadataCodec.history(record.key(),
                            CredentialMetadataAuthority.read(record, MAX_BYTES), record.commitRevision());
                    if (entry.timestamp().isBefore(cutoff)) {
                        transaction.delete(record.key(), record.recordRevision()); deletes++;
                        try (var head = snapshot.get(CaLifecycleMetadataCodec.historyKey(record.key())).orElseThrow(AuthorityMetadataStore::invalid)) {
                            transaction.delete(head.key(), head.recordRevision()); deletes++;
                        }
                    }
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
