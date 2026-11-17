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

import java.util.Arrays;
import java.util.HexFormat;
import zeroecho.pki.api.ca.CaHeadSnapshot;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerCryptographicBinding;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.api.ca.RootTrustAnchorActivation;
import zeroecho.pki.api.ca.RootTrustAnchorTransition;

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
    /**
     * Maximum mutations fitting both transaction payload and WAL batch limits.
     */
    /* default */ static final int MAX_BATCH_MUTATIONS = Math.min(SigningTransactionPayloadCodec.MAXIMUM_MUTATIONS,
            SigningWalFrameCodec.MAX_BATCH_FRAMES - 2);
    private final TransactionalMetadataStore metadata;
    private final Consumer<MetadataCommitResult> outcome;
    private final Optional<LineageAuthority> lineageAuthority;

    /**
     * Resolves exact hybrid signer-tuple authority against one stable metadata snapshot.
     */
    /* default */
    @FunctionalInterface
    interface LineageAuthority {
        /**
         * Resolves exact hybrid signer-tuple evidence against stable authoritative metadata.
         *
         * @param snapshot borrowed stable metadata snapshot; this method does not close it
         * @param generation exact issuer generation being qualified
         * @param binding validated immutable binding for that generation
         * @return canonical hybrid signer-tuple commitment
         * @throws IOException if metadata cannot be read or its authority, generation, path or
         * binding coordinates are inconsistent
         */
        String tuple(MetadataSnapshot snapshot, IssuerGeneration generation,
                IssuerCryptographicBinding binding) throws IOException;
    }

    /**
     * Binds authority metadata operations to the caller-owned transaction store and outcome observer.
     *
     * <p>Collaborators are retained without local validation or lifecycle transfer.</p>
     *
     * @param metadata borrowed transactional authority store
     * @param outcome callback observing transaction outcomes without granting commit authority
     */
    /* default */ AuthorityMetadataStore(TransactionalMetadataStore metadata, Consumer<MetadataCommitResult> outcome) {
        this(metadata, outcome, Optional.empty());
    }

    /**
     * Binds authority metadata operations to the caller-owned transaction store and outcome observer.
     *
     * <p>Collaborators are retained without local validation or lifecycle transfer.</p>
     *
     * @param metadata borrowed transactional authority store
     * @param outcome callback observing transaction outcomes without granting commit authority
     * @param lineageAuthority optional exact public hybrid-lineage qualification callback
     */
    /* default */ AuthorityMetadataStore(TransactionalMetadataStore metadata, Consumer<MetadataCommitResult> outcome, Optional<LineageAuthority> lineageAuthority) {
        this.metadata = metadata;
        this.outcome = outcome;
        this.lineageAuthority = lineageAuthority;
    }

    /**
     * Reads and decodes one authority metadata value using a newly opened snapshot.
     *
     * @param <T> decoded immutable metadata value type
     * @param key exact authority metadata identity
     * @param decoder bounded key-aware decoder; must return a non-null value
     * @return matching decoded value, or an empty optional if absent
     * @throws IOException if metadata cannot be read or its authority, generation, path or binding
     * coordinates are inconsistent
     * @throws NullPointerException if a required input is null
     * @throws RuntimeException if the supplied decoder rejects a stored row
     */
    /* default */ <T> Optional<T> find(MetadataKey key, BiFunction<MetadataKey, byte[], T> decoder) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot()) { return find(snapshot, key, decoder); }
    }

    /**
     * Reads and decodes one authority metadata value from the supplied stable snapshot.
     *
     * @param <T> decoded immutable metadata value type
     * @param snapshot borrowed stable metadata snapshot; this method does not close it
     * @param key exact authority metadata identity
     * @param decoder bounded key-aware decoder; must return a non-null value
     * @return matching decoded value, or an empty optional if absent
     * @throws IOException if metadata cannot be read or its authority, generation, path or binding
     * coordinates are inconsistent
     * @throws NullPointerException if a required input is null
     * @throws RuntimeException if the supplied decoder rejects a stored row
     */
    /* default */ static <T> Optional<T> find(MetadataSnapshot snapshot, MetadataKey key, BiFunction<MetadataKey, byte[], T> decoder) throws IOException {
        try (MetadataSnapshot.Record record = snapshot.get(key).orElse(null)) {
            return record == null ? Optional.empty() : Optional.of(decoder.apply(record.key(), CredentialMetadataAuthority.read(record, MAX_BYTES)));
        }
    }

    /**
     * Collects a complete authority namespace using a newly opened snapshot.
     *
     * @param <T> decoded immutable metadata value type
     * @param namespace exact metadata namespace to scan
     * @param decoder bounded key-aware decoder for each stored row
     * @return immutable decoded values in metadata traversal order
     * @throws IOException if metadata cannot be read or its authority, generation, path or binding
     * coordinates are inconsistent
     * @throws NullPointerException if a required input is null
     * @throws RuntimeException if the supplied decoder rejects a stored row
     */
    /* default */ <T> List<T> list(String namespace, BiFunction<MetadataKey, byte[], T> decoder) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot()) { return list(snapshot, namespace, decoder); }
    }

    /**
     * Collects a complete authority namespace from the supplied stable snapshot.
     *
     * @param <T> decoded immutable metadata value type
     * @param snapshot borrowed stable metadata snapshot; this method does not close it
     * @param namespace exact metadata namespace to scan
     * @param decoder bounded key-aware decoder for each stored row
     * @return immutable decoded values in metadata traversal order
     * @throws IOException if metadata cannot be read or its authority, generation, path or binding
     * coordinates are inconsistent
     * @throws NullPointerException if a required input is null
     * @throws RuntimeException if the supplied decoder rejects a stored row
     */
    /* default */ static <T> List<T> list(MetadataSnapshot snapshot, String namespace, BiFunction<MetadataKey, byte[], T> decoder) throws IOException {
        List<T> values = new ArrayList<>();
        visit(snapshot, namespace, decoder, values::add);
        return List.copyOf(values);
    }

    /**
     * Visits one detached decoded payload at a time; retention belongs to the visitor.
     *
     * @param <T> decoded immutable metadata type
     * @param snapshot borrowed stable metadata snapshot; remains caller-owned
     * @param namespace exact authority metadata namespace to traverse
     * @param decoder key-aware bounded decoder producing each detached value
     * @param visitor checked consumer deciding whether to retain each decoded value
     * @throws NullPointerException if a required collaborator is null
     * @throws IOException if metadata reading or the checked visitor fails
     * @throws RuntimeException if the decoder rejects a stored value
     */
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

    /**
     * Checked visitor over decoded authority metadata.
     *
     * @param <T> decoded immutable authority metadata type
     */
    /* default */
    @FunctionalInterface
    interface Visitor<T> {
        /**
         * Consumes one decoded value, propagating storage failures.
         *
         * @param value detached decoded authority metadata value
         * @throws IOException if checked processing of the value fails
         */
        void accept(T value) throws IOException;
    }

    /**
     * Creates one bounded authority row in a dedicated transaction and requires a definite commit.
     *
     * @param key previously absent exact authority metadata identity
     * @param payload bounded complete encoded metadata value
     * @throws NullPointerException if a required input is null
     * @throws IOException if staging or commit fails or its durable outcome is unknown
     * @throws IllegalStateException if the transaction is definitely not committed
     */
    /* default */ void create(MetadataKey key, byte[] payload) throws IOException {
        try (MetadataTransaction transaction = metadata.beginTransaction()) {
            create(transaction, key, payload);
            committed(transaction.commit());
        }
    }

    /**
     * Atomically creates issuer generation metadata together with its exact context-bound public binding.
     *
     * @param generation new immutable issuer generation
     * @param binding validated public binding whose generation coordinates must match
     * @throws NullPointerException if a required input is null
     * @throws IOException if coordinate validation, encoding or atomic persistence fails
     * @throws IllegalStateException if the transaction is definitely not committed
     */
    /* default */ void createGeneration(IssuerGeneration generation,
            IssuerCryptographicBinding binding) throws IOException {
        requireBinding(generation, binding);
        byte[] encoded = IssuerBindingStorageCodec.encode(binding, generation);
        try (MetadataTransaction transaction = metadata.beginTransaction()) {
            create(transaction, AuthorityMetadataCodec.generationKey(generation.issuerId()), FsCodec.encode(FsCodec.ISSUER_GENERATION, generation));
            create(transaction, AuthorityMetadataCodec.bindingKey(generation.issuerId()), encoded);
            committed(transaction.commit());
        }
    }

    /**
     * Reads an exact issuer binding and validates it against its retained issuer generation.
     *
     * @param snapshot borrowed stable metadata snapshot; this method does not close it
     * @param issuerId exact immutable issuer generation identity
     * @return validated public binding, or an empty optional if absent
     * @throws IOException if metadata cannot be read or its authority, generation, path or binding
     * coordinates are inconsistent
     */
    /* default */ static Optional<IssuerCryptographicBinding> findBinding(MetadataSnapshot snapshot, PkiId issuerId) throws IOException {
        try (MetadataSnapshot.Record record = snapshot.get(AuthorityMetadataCodec.bindingKey(issuerId)).orElse(null)) {
            return record == null ? Optional.empty() : Optional.of(decodeBinding(snapshot, record.key(), CredentialMetadataAuthority.read(record, MAX_BYTES)));
        }
    }

    private static void visitBindings(MetadataSnapshot snapshot, Visitor<IssuerCryptographicBinding> visitor) throws IOException {
        try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(AuthorityMetadataCodec.ISSUER_CRYPTO_BINDING), CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (MetadataSnapshot.Record record = next.orElseThrow()) {
                    visitor.accept(decodeBinding(snapshot, record.key(), CredentialMetadataAuthority.read(record, MAX_BYTES)));
                }
            }
        }
    }

    private static IssuerCryptographicBinding decodeBinding(MetadataSnapshot snapshot, MetadataKey key, byte[] bytes) throws IOException {
        PkiId issuer = IssuerBindingStorageCodec.issuerId(bytes);
        IssuerGeneration generation = find(snapshot, AuthorityMetadataCodec.generationKey(issuer), AuthorityMetadataCodec::generation)
                .orElseThrow(AuthorityMetadataStore::invalid);
        IssuerCryptographicBinding binding = AuthorityMetadataCodec.binding(key, bytes, generation);
        return binding;
    }

    private static void requireBinding(IssuerGeneration generation, IssuerCryptographicBinding binding) throws IOException {
        if (!generation.issuerId().equals(binding.issuerId()) || !generation.authorityId().equals(binding.authorityId())
                || !generation.credentialId().equals(binding.credentialId()) || !generation.signingKeyRef().equals(binding.primary().keyRef())
                || !generation.profilePolicyCommitment().equals(HexFormat.of().formatHex(binding.profile().canonicalSha256()))
                || !generation.x509BindingCommitment().equals(binding.bindingSetCommitment())) {
            throw invalid();
        }
    }

    /**
     * Persists a CA head, immutable membership and optional history in one transaction.
     *
     * @param ca complete validated authority state to persist
     * @param policy history retention and optional bounded on-write cleanup policy
     * @throws NullPointerException if a required input is null
     * @throws IOException if transactional storage fails or the outcome is unknown
     * @throws IllegalStateException if authority validation fails or persistence is definitely rejected
     */
    /* default */ void putCa(CaRecord ca, FsHistoryPolicy policy) throws IOException {
        // Each definite retry, if requested by the caller, gets a fresh issued
        // transaction and wall-clock sample. An UNKNOWN attempt is never replayed here.
        try (MetadataTransaction transaction = metadata.beginTransaction(); MetadataSnapshot snapshot = metadata.snapshot()) {
            Instant timestamp = Instant.now().truncatedTo(ChronoUnit.MICROS);
            try {
                stageCa(snapshot, transaction, ca, policy.enabled(), timestamp, Optional.empty(), Optional.empty(), lineageAuthority);
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

    /**
     * Compares and stages against one snapshot; only definite conflicts are a false result.
     *
     * @param expected exact current CA record required before replacement
     * @param replacement coherent replacement authority state and immutable membership
     * @param policy history retention and optional bounded cleanup policy
     * @return true after a definite commit; false when the expected record differs or persistence
     * reports a definite conflict
     * @throws NullPointerException if a required argument is null
     * @throws IOException if storage access fails or the transaction outcome is unknown
     * @throws IllegalStateException if pre-commit authority validation fails or persistence rejects for
     * a nonconflict reason
     */
    /* default */ boolean replaceCa(CaRecord expected, CaRecord replacement, FsHistoryPolicy policy) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot()) {
            Optional<CaRecord> current;
            try { current = ca(snapshot, expected.caId()); }
            catch (IOException failure) { throw new IllegalStateException("CA metadata validation failed", failure); }
            if (current.isEmpty() || !current.orElseThrow().equals(expected)) { return false; }
            try (MetadataTransaction transaction = metadata.beginTransaction()) {
                try {
                    stageCa(snapshot, transaction, replacement, policy.enabled(), Instant.now().truncatedTo(ChronoUnit.MICROS), Optional.empty(), Optional.empty(), lineageAuthority);
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

    /**
     * Only for a fresh, unexposed snapshot target; head publication is last.
     *
     * @param ca complete authoritative CA snapshot whose generations and bindings were already restored
     * @param policy whether matching immutable history rows are created
     * @throws NullPointerException if a required argument is null
     * @throws IOException if authority coordinates differ, base or head already exists, or a staged
     * batch cannot be committed
     * @throws IllegalStateException if a restore transaction is definitely rejected
     */
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

    /**
     * At most 30 caller mutations and 2 MiB including exact transaction framing.
     */
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

        /**
         * {@inheritDoc}
         */
        @Override public void close() throws IOException { if (transaction != null) { transaction.close(); } }
    }

    /**
     * Stages coherent CA selection and optional history against one stable original state.
     *
     * @param snapshot borrowed stable metadata snapshot; this method does not close it
     * @param transaction borrowed transaction receiving staged mutations; the caller commits or aborts it
     * @param ca replacement authority metadata with exact immutable membership
     * @param history whether paired authority and lifecycle-head history rows are staged
     * @param timestamp authoritative history timestamp
     * @throws NullPointerException if a required input is null
     * @throws IOException if authority bindings, membership, expected head or staged storage are inconsistent
     */
    /* default */ static void stageCa(MetadataSnapshot snapshot, MetadataTransaction transaction, CaRecord ca,
            boolean history, Instant timestamp) throws IOException {
        stageCa(snapshot, transaction, ca, history, timestamp, Optional.empty(), Optional.empty(), Optional.empty());
    }

    /**
     * Stages coherent CA selection and optional history against one stable original state.
     *
     * @param snapshot borrowed stable metadata snapshot; this method does not close it
     * @param transaction borrowed transaction receiving staged mutations; the caller commits or aborts it
     * @param ca replacement authority metadata with exact immutable membership
     * @param history whether paired authority and lifecycle-head history rows are staged
     * @param timestamp authoritative history timestamp
     * @param expected exact original lifecycle head required before staging its replacement
     * @throws NullPointerException if a required input is null
     * @throws IOException if authority bindings, membership, expected head or staged storage are inconsistent
     */
    /* default */ static void stageCaFenced(MetadataSnapshot snapshot, MetadataTransaction transaction, CaRecord ca,
            boolean history, Instant timestamp, CaHeadSnapshot expected) throws IOException {
        stageCa(snapshot, transaction, ca, history, timestamp, Optional.of(expected), Optional.empty(), Optional.empty());
    }

    private static void stageCa(MetadataSnapshot snapshot, MetadataTransaction transaction, CaRecord ca,
            boolean history, Instant timestamp, Optional<CaHeadSnapshot> expected,
            Optional<RootTrustAnchorActivation> activation, Optional<LineageAuthority> lineageAuthority) throws IOException {
        AuthorityMetadataCodec.Base base = AuthorityMetadataCodec.Base.of(ca);
        AuthorityMetadataCodec.Base previousBase = find(snapshot, AuthorityMetadataCodec.baseKey(ca.caId()), AuthorityMetadataCodec::base).orElse(null);
        if (previousBase != null && !previousBase.equals(base)) { throw invalid(); }
        AuthorityMetadataCodec.Head head = AuthorityMetadataCodec.Head.of(ca);
        byte[] payload = FsCodec.encode(FsCodec.CA_HEAD, head);
        AuthorityMetadataCodec.requireValueSize(payload);
        MetadataKey key = AuthorityMetadataCodec.caKey(ca.caId());
        try (MetadataSnapshot.Record current = snapshot.get(key).orElse(null);
                RepeatableContent bytes = new ImmutableByteContent(payload)) {
            AuthorityMetadataCodec.Head previous = current == null ? null
                    : AuthorityMetadataCodec.head(current.key(), CredentialMetadataAuthority.read(current, MAX_BYTES));
            if ((previous == null) != (previousBase == null) || previous != null
                    && (!previous.caId().equals(ca.caId()) || previous.membershipCount() > head.membershipCount())) { throw invalid(); }
            CaHeadSnapshot updated = selectedHead(snapshot, ca, head, previous, expected, activation);
            stageHead(snapshot, transaction, updated);
            stageCrlLineages(snapshot, transaction, ca, previous, lineageAuthority);
            stageCaMemberships(snapshot, transaction, ca, head, previous);
            requireSelection(snapshot, head, false);
            if (previousBase == null) { create(transaction, AuthorityMetadataCodec.baseKey(ca.caId()), FsCodec.encode(FsCodec.CA_BASE, base)); }
            if (current == null) { transaction.create(key, bytes, CancellationSignal.NONE); }
            else { transaction.replace(key, current.recordRevision(), bytes, CancellationSignal.NONE); }
        }
        if (history) { stageCaHistory(snapshot, transaction, ca, head, timestamp, payload); }
    }

    /**
     * Stages both ordered and direct lookup rows for one previously absent issuer membership.
     *
     * @param snapshot borrowed stable metadata snapshot; this method does not close it
     * @param transaction borrowed transaction receiving staged mutations; the caller commits or aborts it
     * @param member exact authority, issuer generation and ordinal membership coordinates
     * @throws NullPointerException if a required input is null
     * @throws IOException if either membership key already exists or staging fails
     */
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

    /**
     * Reconstructs current CA metadata and verifies its exact lifecycle-head authority.
     *
     * @param snapshot borrowed stable metadata snapshot; this method does not close it
     * @param id exact logical CA identity
     * @return validated current CA record, or an empty optional if no head exists
     * @throws IOException if metadata cannot be read or its authority, generation, path or binding
     * coordinates are inconsistent
     */
    /* default */ static Optional<CaRecord> ca(MetadataSnapshot snapshot, PkiId id) throws IOException {
        Optional<AuthorityMetadataCodec.Head> head = find(snapshot, AuthorityMetadataCodec.caKey(id), AuthorityMetadataCodec::head);
        if (head.isEmpty()) { return Optional.empty(); }
        if (!head.orElseThrow().caId().equals(id)) { throw invalid(); }
        CaRecord value = reconstruct(snapshot, head.orElseThrow());
        requireHead(snapshot, value);
        return Optional.of(value);
    }

    /**
     * Reconstructs a CA record from its immutable base, ordered membership and exact selected generation.
     *
     * @param snapshot borrowed stable metadata snapshot; this method does not close it
     * @param head validated current or historical authority head
     * @return complete CA record whose membership and selected path match retained authority
     * @throws IOException if metadata cannot be read or its authority, generation, path or binding
     * coordinates are inconsistent
     */
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

    /**
     * Loads validated issuer generations in the authority's exact retained membership order.
     *
     * @param snapshot borrowed stable metadata snapshot; this method does not close it
     * @param authority exact logical CA identity
     * @return immutable ordered generations, or an empty list when no authority head exists
     * @throws IOException if metadata cannot be read or its authority, generation, path or binding
     * coordinates are inconsistent
     */
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

    /**
     * Validates all current and historical CA selections, bindings, memberships and root transition receipts.
     *
     * @param snapshot borrowed stable metadata snapshot; this method does not close it
     * @throws IOException if metadata cannot be read or its authority, generation, path or binding
     * coordinates are inconsistent
     * @throws IllegalStateException if a historical lifecycle head cannot be decoded
     */
    /* default */ static void validateAll(MetadataSnapshot snapshot) throws IOException {
        visit(snapshot, AuthorityMetadataCodec.ISSUER_GENERATION, AuthorityMetadataCodec::generation,
                generation -> requireGeneration(snapshot, generation.authorityId(), generation.issuerId()));
        visitBindings(snapshot, binding -> requireGeneration(snapshot, binding.authorityId(), binding.issuerId()));
        Integrity.currentHeads(snapshot);
        Integrity.transitions(snapshot);
        Integrity.candidates(snapshot);
        Integrity.activations(snapshot);
        Integrity.currentSelections(snapshot);
        Integrity.bases(snapshot);
        Integrity.memberships(snapshot);
        Integrity.historyHeads(snapshot);
        Integrity.historySelections(snapshot);
    }

    /**
     * Requires the exact lifecycle head matching the CA's selected generation, path and binding.
     *
     * @param snapshot borrowed stable metadata snapshot; this method does not close it
     * @param ca reconstructed authority whose current selection is being checked
     * @return validated exact lifecycle head including root activation evidence where applicable
     * @throws IOException if metadata cannot be read or its authority, generation, path or binding
     * coordinates are inconsistent
     */
    /* default */ static CaHeadSnapshot requireHead(MetadataSnapshot snapshot, CaRecord ca) throws IOException {
        CaHeadSnapshot value = CaLifecycleMetadataCodec.head(snapshot, ca.caId()).orElseThrow(() -> new IOException("Required CA head epoch is missing"));
        IssuerCryptographicBinding binding = findBinding(snapshot, ca.currentIssuanceIssuerId()).orElseThrow(AuthorityMetadataStore::invalid);
        if (!value.issuerId().equals(ca.currentIssuanceIssuerId()) || !value.pathId().equals(ca.issuanceChainPathId())
                || !value.bindingCommitment().equals(binding.commitment())) { throw invalid(); }
        if (ca.kind() != CaKind.ROOT) { return value; }
        {
            Optional<RootTrustAnchorTransition> candidate = find(snapshot, CaLifecycleMetadataCodec.candidateKey(value.issuerId()), CaLifecycleMetadataCodec::transitionRow);
            if (candidate.isEmpty()) { return value; }
            {
                RootTrustAnchorTransition transition = candidate.orElseThrow();
                RootTrustAnchorActivation receipt = CaLifecycleMetadataCodec.activation(snapshot, transition.transitionId())
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
            CaHeadSnapshot head) throws IOException {
        MetadataKey key = CaLifecycleMetadataCodec.headKey(head.caId());
        try (MetadataSnapshot.Record previous = snapshot.get(key).orElse(null); RepeatableContent bytes = new ImmutableByteContent(CaLifecycleMetadataCodec.encode(head))) {
            if (previous == null) { transaction.create(key, bytes, CancellationSignal.NONE); }
            else { transaction.replace(key, previous.recordRevision(), bytes, CancellationSignal.NONE); }
        }
    }

    /**
     * Looks up retained hybrid CRL signer lineage for one exact issuer generation.
     *
     * @param snapshot borrowed stable metadata snapshot; this method does not close it
     * @param issuer exact issuer generation identity
     * @return decoded lineage evidence, or an empty optional if absent
     * @throws IOException if metadata cannot be read or its authority, generation, path or binding
     * coordinates are inconsistent
     */
    /* default */ static Optional<CrlSignerLineage> lineage(MetadataSnapshot snapshot, PkiId issuer) throws IOException {
        return find(snapshot, CrlSignerLineageCodec.key(issuer), CrlSignerLineageCodec::decode);
    }

    private static void stageCrlLineages(MetadataSnapshot snapshot, MetadataTransaction transaction, CaRecord ca,
            AuthorityMetadataCodec.Head previous, Optional<LineageAuthority> authority) throws IOException {
        int first = previous == null ? 0 : previous.membershipCount();
        for (int ordinal = first; ordinal < ca.issuerIds().size(); ordinal++) {
            stageCrlLineage(snapshot, transaction, ca, previous, authority, ordinal);
        }
    }

    /**
     * Requires hybrid lineage consistent with exact current and predecessor public signer bindings.
     *
     * @param snapshot borrowed stable metadata snapshot; this method does not close it
     * @param issuer exact hybrid issuer generation identity
     * @return validated retained lineage evidence
     * @throws IOException if required lineage or binding evidence is absent or inconsistent
     * @throws IllegalArgumentException if the issuer is native-only and has no qualified hybrid lineage
     */
    /* default */ static CrlSignerLineage requireLineage(MetadataSnapshot snapshot, PkiId issuer) throws IOException {
        IssuerCryptographicBinding binding = findBinding(snapshot, issuer).orElseThrow(AuthorityMetadataStore::invalid);
        if (binding.alternative().isEmpty()) { throw new IllegalArgumentException("Native-only issuer has no qualified hybrid CRL lineage"); }
        CrlSignerLineage value = lineage(snapshot, issuer).orElseThrow(() -> new IOException("Required hybrid CRL signer lineage is missing"));
        if (!value.issuerBindingCommitment().equals(binding.commitment())) { throw invalid(); }
        if (value.predecessorSelectedIssuerId().isEmpty()) {
            if (!value.lineageId().equals(issuer)) { throw invalid(); }
        } else {
            IssuerCryptographicBinding predecessor = findBinding(snapshot, value.predecessorSelectedIssuerId().orElseThrow()).orElseThrow(AuthorityMetadataStore::invalid);
            if (predecessor.alternative().isEmpty()) {
                if (!value.lineageId().equals(issuer)) { throw invalid(); }
            } else {
                CrlSignerLineage prior = lineage(snapshot, predecessor.issuerId()).orElseThrow(AuthorityMetadataStore::invalid);
                PkiId expected = prior.signerTupleCommitment().equals(value.signerTupleCommitment()) ? prior.lineageId() : issuer;
                if (!value.lineageId().equals(expected) || !prior.issuerBindingCommitment().equals(predecessor.commitment())) { throw invalid(); }
            }
        }
        return value;
    }

    private static boolean sameAnchor(IssuerCryptographicBinding left, IssuerCryptographicBinding right) {
        return sameKey(left.primary(), right.primary()) && left.alternative().isPresent() == right.alternative().isPresent()
                && (left.alternative().isEmpty() || sameKey(left.alternative().orElseThrow(), right.alternative().orElseThrow()));
    }
    private static boolean sameKey(IssuerKeyBinding left, IssuerKeyBinding right) {
        return left.subjectSpkiSha256().equals(right.subjectSpkiSha256()) && left.publicKeyAlgorithm().equals(right.publicKeyAlgorithm())
                && left.signatureAlgorithm().equals(right.signatureAlgorithm())
                && Arrays.equals(left.signatureAlgorithmIdentifier().bytes(), right.signatureAlgorithmIdentifier().bytes());
    }

    /**
     * Atomically replaces a matching authority lifecycle head while retaining coherent membership and history.
     *
     * @param expected exact original lifecycle head expected by the caller
     * @param replacement new CA selection preserving the authority identity and lifecycle state
     * @param history history policy applied while staging the replacement
     * @return true on a definite commit; false when the expected head or current lifecycle state changed
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if the replacement selects a different authority
     * @throws IOException if validation or storage fails or the transaction outcome is unknown
     * @throws IllegalStateException if persistence is definitely rejected for a nonconflict reason
     */
    /* default */ boolean compareAndSetHead(CaHeadSnapshot expected, CaRecord replacement, FsHistoryPolicy history) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot()) {
            if (!CaLifecycleMetadataCodec.head(snapshot, expected.caId()).filter(expected::equals).isPresent()) { return false; }
            if (ca(snapshot, expected.caId()).orElseThrow(AuthorityMetadataStore::invalid).state() != replacement.state()) { return false; }
            if (!replacement.caId().equals(expected.caId())) { throw new IllegalArgumentException("Replacement CA differs from expected head authority"); }
            try (MetadataTransaction transaction = metadata.beginTransaction()) {
                stageCa(snapshot, transaction, replacement, history.enabled(), Instant.now().truncatedTo(ChronoUnit.MICROS), Optional.of(expected), Optional.empty(), lineageAuthority);
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

    /**
     * Atomically registers immutable root transition evidence and candidate membership without activating it.
     *
     * @param transition exact approved candidate transition bound to the original lifecycle head
     * @param history history policy applied to the membership update
     * @return retained identical transition after successful registration or idempotent reuse
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if an existing or concurrent candidate differs or expected
     * authority state changed
     * @throws IOException if retained authority evidence is inconsistent or persistence fails
     * @throws IllegalStateException if persistence is definitely rejected
     */
    /* default */ RootTrustAnchorTransition registerCandidate(RootTrustAnchorTransition transition,
            FsHistoryPolicy history) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot()) {
            Optional<RootTrustAnchorTransition> existing = CaLifecycleMetadataCodec.transition(snapshot, transition.transitionId());
            if (existing.isPresent()) {
                if (!existing.orElseThrow().equals(transition)) { throw new IllegalArgumentException("Root candidate transition ID already has different immutable content"); } return existing.orElseThrow();
            }
            CaRecord ca = ca(snapshot, transition.caId()).orElseThrow(AuthorityMetadataStore::invalid);
            CaHeadSnapshot head = requireHead(snapshot, ca);
            if (ca.kind() != CaKind.ROOT || ca.state() != CaState.ACTIVE
                    || !head.equals(transition.expectedHead())) { throw new IllegalArgumentException("Root candidate expected head is stale or authority is inactive"); }
            validateTransition(snapshot, transition);
            IssuerCryptographicBinding current = findBinding(snapshot, head.issuerId()).orElseThrow(AuthorityMetadataStore::invalid);
            IssuerCryptographicBinding candidate = findBinding(snapshot, transition.candidateIssuerId()).orElseThrow(AuthorityMetadataStore::invalid);
            if (sameAnchor(current, candidate)) { throw new IllegalArgumentException("Same-anchor renewal must use guarded head publication"); }
            List<PkiId> members = new ArrayList<>(ca.issuerIds());
            if (!members.contains(transition.candidateIssuerId())) { members.add(transition.candidateIssuerId()); }
            CaRecord replacement = new CaRecord(ca.caId(), ca.kind(), ca.state(), ca.issuerKeyRef(), ca.subjectRef(), members, ca.currentIssuanceIssuerId(), ca.issuanceChainPathId());
            try (MetadataTransaction transaction = metadata.beginTransaction()) {
                stageCa(snapshot, transaction, replacement, history.enabled(), Instant.now().truncatedTo(ChronoUnit.MICROS), Optional.of(head), Optional.empty(), lineageAuthority);
                create(transaction, CaLifecycleMetadataCodec.transitionKey(transition.transitionId()), CaLifecycleMetadataCodec.encode(transition));
                create(transaction, CaLifecycleMetadataCodec.candidateKey(transition.candidateIssuerId()), CaLifecycleMetadataCodec.encode(transition));
                MetadataCommitResult result = transaction.commit();
                if (definiteConflict(result)) {
                    try (MetadataSnapshot committedSnapshot = metadata.snapshot()) {
                        RootTrustAnchorTransition retained = CaLifecycleMetadataCodec.transition(committedSnapshot, transition.transitionId()).orElseThrow(() -> new IllegalArgumentException("Root candidate registration lost its expected head conflict"));
                        if (!retained.equals(transition)) { throw new IllegalArgumentException("Concurrent root candidate has different immutable content"); } return retained;
                    }
                }
                committed(result); return transition;
            }
        }
    }

    /**
     * Atomically selects a registered root candidate and persists its immutable activation receipt.
     *
     * @param transitionId exact registered root transition identity
     * @param expected exact original lifecycle head approved for activation
     * @param activation immutable receipt binding the approved transition, candidate and new epoch
     * @param history history policy applied to the selection update
     * @return retained identical activation receipt after a definite commit or idempotent reuse
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if expected state, approved receipt or a concurrent activation differs
     * @throws IOException if retained authority evidence is inconsistent or persistence fails
     * @throws IllegalStateException if persistence is definitely rejected
     */
    /* default */ RootTrustAnchorActivation activateCandidate(PkiId transitionId,
            CaHeadSnapshot expected, RootTrustAnchorActivation activation, FsHistoryPolicy history) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot()) {
            Optional<RootTrustAnchorActivation> existing = CaLifecycleMetadataCodec.activation(snapshot, transitionId);
            if (existing.isPresent()) {
                if (!existing.orElseThrow().equals(activation)) { throw new IllegalArgumentException("Root activation already has a different immutable receipt"); } return existing.orElseThrow();
            }
            RootTrustAnchorTransition transition = CaLifecycleMetadataCodec.transition(snapshot, transitionId).orElseThrow(AuthorityMetadataStore::invalid);
            CaRecord ca = ca(snapshot, transition.caId()).orElseThrow(AuthorityMetadataStore::invalid);
            if (!requireHead(snapshot, ca).equals(expected) || !expected.equals(transition.expectedHead())
                    || !activation.expectedHead().equals(expected) || !activation.transitionId().equals(transitionId)
                    || !activation.transitionCommitment().equals(transition.commitment())
                    || !activation.candidateIssuerId().equals(transition.candidateIssuerId())
                    || !activation.candidatePathId().equals(transition.candidatePathId())
                    || !ca.issuerIds().contains(transition.candidateIssuerId()) || ca.state() != CaState.ACTIVE) {
                throw new IllegalArgumentException("Root activation expected head or approved receipt differs from its candidate");
            }
            validateTransition(snapshot, transition);
            IssuerGeneration generation = requireGeneration(snapshot, ca.caId(), transition.candidateIssuerId());
            CaRecord replacement = new CaRecord(ca.caId(), ca.kind(), ca.state(), generation.signingKeyRef(), ca.subjectRef(), ca.issuerIds(), generation.issuerId(), transition.candidatePathId());
            try (MetadataTransaction transaction = metadata.beginTransaction()) {
                stageCa(snapshot, transaction, replacement, history.enabled(), activation.acceptedAt(), Optional.of(expected), Optional.of(activation), lineageAuthority);
                create(transaction, CaLifecycleMetadataCodec.activationKey(transitionId), CaLifecycleMetadataCodec.encode(activation));
                MetadataCommitResult result = transaction.commit();
                if (definiteConflict(result)) {
                    try (MetadataSnapshot current = metadata.snapshot()) {
                        RootTrustAnchorActivation retained = CaLifecycleMetadataCodec.activation(current, transitionId).orElseThrow(() -> new IllegalArgumentException("Root activation lost its expected head conflict"));
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

    private static void validateTransition(MetadataSnapshot snapshot, RootTrustAnchorTransition value) throws IOException {
        IssuerGeneration old = requireGeneration(snapshot, value.caId(), value.expectedHead().issuerId());
        IssuerGeneration candidate = requireGeneration(snapshot, value.caId(), value.candidateIssuerId());
        IssuerCryptographicBinding oldBinding = findBinding(snapshot, old.issuerId()).orElseThrow(AuthorityMetadataStore::invalid);
        IssuerCryptographicBinding candidateBinding = findBinding(snapshot, candidate.issuerId()).orElseThrow(AuthorityMetadataStore::invalid);
        IssuerChainPath path = find(snapshot, AuthorityMetadataCodec.pathKey(value.candidatePathId()), AuthorityMetadataCodec::path).orElseThrow(AuthorityMetadataStore::invalid);
        if (candidate.state() != IssuerGenerationState.ACTIVE
                || !old.credentialId().equals(value.oldCredentialId()) || !oldBinding.certificateSha256().equals(value.oldCertificateSha256())
                || !oldBinding.commitment().equals(value.oldBindingCommitment()) || !candidate.credentialId().equals(value.candidateCredentialId())
                || !candidateBinding.certificateSha256().equals(value.candidateCertificateSha256()) || !candidateBinding.commitment().equals(value.candidateBindingCommitment())
                || !path.issuerId().equals(candidate.issuerId()) || !path.authorityId().equals(value.caId())
                || !path.orderedCredentialIds().getFirst().equals(candidate.credentialId())) { throw invalid(); }
    }

    /**
     * Reconstructs the latest retained CA history at or before a requested snapshot time.
     *
     * @param snapshot borrowed stable metadata snapshot; this method does not close it
     * @param id exact logical CA identity
     * @param at inclusive upper history timestamp
     * @param policy whether authority history is enabled
     * @param strict whether enabled history must contain an entry at or before the requested time
     * @return historical authority if found, otherwise current authority when fallback is permitted
     * @throws IOException if history is required but unavailable, metadata is inconsistent or storage fails
     */
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

    /**
     * Loads the exact historical lifecycle head matching an already selected CA snapshot.
     *
     * @param snapshot borrowed stable metadata snapshot; this method does not close it
     * @param selected reconstructed CA selection whose epoch authority is requested
     * @param at inclusive upper history timestamp
     * @param policy whether authority history is enabled
     * @return historical matching epoch, or the validated current head when no historical entry is selected
     * @throws IOException if metadata cannot be read or its authority, generation, path or binding
     * coordinates are inconsistent
     * @throws IllegalStateException if a historical lifecycle head cannot be decoded
     */
    /* default */ static CaHeadSnapshot headAt(MetadataSnapshot snapshot, CaRecord selected,
            Instant at, FsHistoryPolicy policy) throws IOException {
        AuthorityMetadataCodec.HistoryEntry latest = null;
        if (policy.enabled()) {
            try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.prefix(AuthorityMetadataCodec.CA_HISTORY,
                    AuthorityMetadataCodec.historyPrefix(selected.caId())), CancellationSignal.NONE)) {
                Optional<MetadataSnapshot.Record> next;
                while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                    try (MetadataSnapshot.Record record = next.orElseThrow()) {
                        AuthorityMetadataCodec.HistoryEntry entry = AuthorityMetadataCodec.history(record.key(), CredentialMetadataAuthority.read(record, MAX_BYTES), record.commitRevision());
                        if (!entry.timestamp().isAfter(at) && (latest == null || AuthorityMetadataCodec.HISTORY_ORDER.compare(entry, latest) > 0)) { latest = entry; }
                    }
                }
            }
        }
        if (latest == null) { return requireHead(snapshot, selected); }
        CaHeadSnapshot head = find(snapshot, CaLifecycleMetadataCodec.historyKey(latest.key()), (key, bytes) -> {
            try { return CaLifecycleMetadataCodec.decodeHead(bytes); } catch (IOException failure) { throw new IllegalStateException(failure); }
        }).orElseThrow(() -> new IOException("Snapshot historical CA epoch is missing"));
        if (!head.caId().equals(selected.caId()) || !head.issuerId().equals(selected.currentIssuanceIssuerId())
                || !head.pathId().equals(selected.issuanceChainPathId())) { throw invalid(); }
        return head;
    }

    /**
     * Deletes one bounded batch of paired history rows strictly older than the cutoff.
     *
     * <p>Known cleanup conflicts are tolerated; current authority rows are retained.</p>
     *
     * @param id exact logical authority identity
     * @param cutoff exclusive retention timestamp cutoff
     * @throws IOException if history cannot be read, staged deletion fails or commit durability is unknown
     * @throws IllegalStateException if a nonconflict cleanup transaction is definitely rejected
     */
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
                        try (MetadataSnapshot.Record head = snapshot.get(CaLifecycleMetadataCodec.historyKey(record.key())).orElseThrow(AuthorityMetadataStore::invalid)) {
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

    /**
     * Stages creation of one bounded authority row in the caller's transaction.
     *
     * @param transaction borrowed transaction receiving staged mutations; the caller commits or aborts it
     * @param key previously absent exact metadata identity
     * @param payload bounded complete encoded metadata value
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if the encoded value exceeds the transaction payload bound
     * @throws IOException if the staged mutation cannot be written
     */
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

    /** Validates retained authority projections in separate ordered passes. */
    private static final class Integrity {
        private static void currentHeads(MetadataSnapshot snapshot) throws IOException {
        for (CaHeadSnapshot head : list(snapshot, CaLifecycleMetadataCodec.HEAD, CaLifecycleMetadataCodec::headRow)) {
            CaRecord ca = ca(snapshot, head.caId()).orElseThrow(AuthorityMetadataStore::invalid);
            if (!head.equals(requireHead(snapshot, ca))) { throw invalid(); }
        }
        }
        private static void transitions(MetadataSnapshot snapshot) throws IOException {
        for (RootTrustAnchorTransition transition : list(snapshot, CaLifecycleMetadataCodec.TRANSITION, CaLifecycleMetadataCodec::transitionRow)) {
            validateTransition(snapshot, transition);
            CaRecord ca = ca(snapshot, transition.caId()).orElseThrow(AuthorityMetadataStore::invalid);
            if (ca.kind() != CaKind.ROOT || !ca.issuerIds().contains(transition.candidateIssuerId())
                    || requireHead(snapshot, ca).epoch() < transition.expectedHead().epoch()
                    || !find(snapshot, CaLifecycleMetadataCodec.candidateKey(transition.candidateIssuerId()), CaLifecycleMetadataCodec::transitionRow)
                        .filter(transition::equals).isPresent()) { throw invalid(); }
        }
        }
        private static void candidates(MetadataSnapshot snapshot) throws IOException {
        for (RootTrustAnchorTransition transition : list(snapshot, CaLifecycleMetadataCodec.CANDIDATE_INDEX, CaLifecycleMetadataCodec::transitionRow)) {
            if (!CaLifecycleMetadataCodec.transition(snapshot, transition.transitionId()).filter(transition::equals).isPresent()) { throw invalid(); }
        }
        }
        private static void activations(MetadataSnapshot snapshot) throws IOException {
        for (RootTrustAnchorActivation activation : list(snapshot, CaLifecycleMetadataCodec.ACTIVATION, CaLifecycleMetadataCodec::activationRow)) {
            RootTrustAnchorTransition transition = CaLifecycleMetadataCodec.transition(snapshot, activation.transitionId()).orElseThrow(AuthorityMetadataStore::invalid);
            CaRecord ca = ca(snapshot, transition.caId()).orElseThrow(AuthorityMetadataStore::invalid);
            if (!activation.transitionCommitment().equals(transition.commitment()) || !activation.expectedHead().equals(transition.expectedHead())
                    || !activation.candidateIssuerId().equals(transition.candidateIssuerId())
                    || !activation.candidatePathId().equals(transition.candidatePathId())
                    || activation.newEpoch() > requireHead(snapshot, ca).epoch()) { throw invalid(); }
        }
        }
        private static void currentSelections(MetadataSnapshot snapshot) throws IOException {
        // Validate each current prefix once. History only checks count and exact selection.
        for (AuthorityMetadataCodec.Head head : list(snapshot, AuthorityMetadataCodec.CA_CURRENT, AuthorityMetadataCodec::head)) {
            requireHead(snapshot, reconstruct(snapshot, head));
        }
        }
        private static void bases(MetadataSnapshot snapshot) throws IOException {
        for (AuthorityMetadataCodec.Base base : list(snapshot, AuthorityMetadataCodec.CA_BASE, AuthorityMetadataCodec::base)) {
            if (find(snapshot, AuthorityMetadataCodec.caKey(base.caId()), AuthorityMetadataCodec::head).isEmpty()) { throw invalid(); }
        }
        }
        private static void memberships(MetadataSnapshot snapshot) throws IOException {
        for (String namespace : List.of(AuthorityMetadataCodec.CA_GENERATION_ORDER, AuthorityMetadataCodec.CA_GENERATION_MEMBER)) {
            try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(namespace), CancellationSignal.NONE)) {
                Optional<MetadataSnapshot.Record> next;
                while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                    try (MetadataSnapshot.Record record = next.orElseThrow()) {
                        AuthorityMetadataCodec.Membership member = AuthorityMetadataCodec.membership(record.key(), CredentialMetadataAuthority.read(record, MAX_BYTES));
                        AuthorityMetadataCodec.Head head = find(snapshot, AuthorityMetadataCodec.caKey(member.caId()), AuthorityMetadataCodec::head)
                                .orElseThrow(AuthorityMetadataStore::invalid);
                        IssuerCryptographicBinding memberBinding = findBinding(snapshot, member.generationId()).orElseThrow(AuthorityMetadataStore::invalid);
                        if (memberBinding.alternative().isPresent()) { requireLineage(snapshot, member.generationId()); }
                        if (member.ordinal() >= head.membershipCount() || !member.equals(requireMembership(snapshot, member.caId(), member.ordinal()))) { throw invalid(); }
                    }
                }
            }
        }
        }
        private static void historyHeads(MetadataSnapshot snapshot) throws IOException {
        try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(CaLifecycleMetadataCodec.HEAD_HISTORY), CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (MetadataSnapshot.Record row = next.orElseThrow(); MetadataSnapshot.Record original = snapshot.get(historyAuthorityKey(row.key())).orElse(null)) {
                    if (original == null) { throw invalid(); }
                    CaLifecycleMetadataCodec.decodeHead(CredentialMetadataAuthority.read(row, MAX_BYTES));
                }
            }
        }
        }
        private static void historySelections(MetadataSnapshot snapshot) throws IOException {
        try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(AuthorityMetadataCodec.CA_HISTORY), CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (MetadataSnapshot.Record record = next.orElseThrow()) {
                    AuthorityMetadataCodec.Head head = AuthorityMetadataCodec.history(record.key(), CredentialMetadataAuthority.read(record, MAX_BYTES), record.commitRevision()).value();
                    AuthorityMetadataCodec.Head current = find(snapshot, AuthorityMetadataCodec.caKey(head.caId()), AuthorityMetadataCodec::head)
                            .orElseThrow(AuthorityMetadataStore::invalid);
                    if (head.membershipCount() > current.membershipCount()) { throw invalid(); }
                    requireSelection(snapshot, head, true);
                    CaHeadSnapshot historical = find(snapshot, CaLifecycleMetadataCodec.historyKey(record.key()), (key, bytes) -> {
                        try { return CaLifecycleMetadataCodec.decodeHead(bytes); } catch (IOException failure) { throw new IllegalStateException(failure); }
                    }).orElseThrow(AuthorityMetadataStore::invalid);
                    IssuerCryptographicBinding binding = findBinding(snapshot, head.generationId()).orElseThrow(AuthorityMetadataStore::invalid);
                    if (!historical.caId().equals(head.caId()) || !historical.issuerId().equals(head.generationId())
                            || !historical.pathId().equals(head.pathId()) || !historical.bindingCommitment().equals(binding.commitment())
                            || historical.epoch() > CaLifecycleMetadataCodec.head(snapshot, head.caId()).orElseThrow().epoch()) { throw invalid(); }

                }
            }
        }
            }
    }


    private static MetadataKey historyAuthorityKey(MetadataKey row) { return new MetadataKey(AuthorityMetadataCodec.CA_HISTORY, row.key()); }


    private static void stageCrlLineage(MetadataSnapshot snapshot, MetadataTransaction transaction, CaRecord ca,
            AuthorityMetadataCodec.Head previous, Optional<LineageAuthority> authority, int ordinal) throws IOException {

            IssuerGeneration generation = requireGeneration(snapshot, ca.caId(), ca.issuerIds().get(ordinal));
            IssuerCryptographicBinding binding = findBinding(snapshot, generation.issuerId()).orElseThrow(AuthorityMetadataStore::invalid);
            if (binding.alternative().isEmpty()) { return; }
            if (lineage(snapshot, generation.issuerId()).isPresent()) { throw invalid(); }
            String tuple = authority.orElseThrow(() -> new UnsupportedOperationException("Configured hybrid CRL lineage authority unavailable"))
                    .tuple(snapshot, generation, binding);
            PkiId root = generation.issuerId();
            PkiId predecessor = previous == null ? null : previous.generationId();
            root = lineageRoot(snapshot, predecessor, tuple, root);
            CrlSignerLineage value = new CrlSignerLineage(1, generation.issuerId(), Optional.ofNullable(predecessor), root, tuple, binding.commitment());
            create(transaction, CrlSignerLineageCodec.key(generation.issuerId()), CrlSignerLineageCodec.encode(value));

    }


    private static PkiId lineageRoot(MetadataSnapshot snapshot, PkiId predecessor, String tuple, PkiId root) throws IOException {
        if (predecessor == null) { return root; }
        IssuerCryptographicBinding priorBinding = findBinding(snapshot, predecessor).orElseThrow(AuthorityMetadataStore::invalid);
        if (priorBinding.alternative().isEmpty()) { return root; }
        CrlSignerLineage prior = requireLineage(snapshot, predecessor);
        return prior.signerTupleCommitment().equals(tuple) ? prior.lineageId() : root;
    }


    private static CaHeadSnapshot selectedHead(MetadataSnapshot snapshot, CaRecord ca, AuthorityMetadataCodec.Head head,
            AuthorityMetadataCodec.Head previous, Optional<CaHeadSnapshot> expected,
            Optional<RootTrustAnchorActivation> activation) throws IOException {
            IssuerGeneration selected = requireGeneration(snapshot, ca.caId(), head.generationId());
            IssuerCryptographicBinding binding = findBinding(snapshot, selected.issuerId()).orElseThrow(AuthorityMetadataStore::invalid);
            Optional<CaHeadSnapshot> original = CaLifecycleMetadataCodec.head(snapshot, ca.caId());
            boolean changesHead = previous != null && (!previous.generationId().equals(head.generationId()) || !previous.pathId().equals(head.pathId()));
            if (previous == null && original.isPresent() || previous != null && original.isEmpty()) { throw invalid(); }
            if (expected.isPresent() && !original.filter(expected.orElseThrow()::equals).isPresent()) { throw invalid(); }
            if (changesHead && expected.isEmpty()) { throw new IllegalArgumentException("Selected CA head changes require an admitted epoch fence"); }
            requireRootActivation(snapshot, ca, changesHead, original, binding, activation);

            long epoch = previous == null ? 1 : changesHead ? Math.incrementExact(original.orElseThrow().epoch()) : original.orElseThrow().epoch();
            CaHeadSnapshot updated = new CaHeadSnapshot(1, ca.caId(), epoch, selected.issuerId(), head.pathId(), binding.commitment());
        return updated;
    }
    private static void stageCaHistory(MetadataSnapshot snapshot, MetadataTransaction transaction, CaRecord ca,
            AuthorityMetadataCodec.Head head, Instant timestamp, byte[] payload) throws IOException {

            MetadataKey historyKey = AuthorityMetadataCodec.historyKey(ca.caId(), timestamp, transaction.id());
            create(transaction, historyKey, payload);
            Optional<CaHeadSnapshot> original = CaLifecycleMetadataCodec.head(snapshot, ca.caId());
            boolean changes = original.isPresent() && (!original.orElseThrow().issuerId().equals(head.generationId()) || !original.orElseThrow().pathId().equals(head.pathId()));
            long epoch = original.isEmpty() ? 1 : changes ? Math.incrementExact(original.orElseThrow().epoch()) : original.orElseThrow().epoch();
            IssuerCryptographicBinding binding = findBinding(snapshot, head.generationId()).orElseThrow(AuthorityMetadataStore::invalid);
            create(transaction, CaLifecycleMetadataCodec.historyKey(historyKey), CaLifecycleMetadataCodec.encode(
                    new CaHeadSnapshot(1, ca.caId(), epoch, head.generationId(), head.pathId(), binding.commitment())));

    }


    private static void requireRootActivation(MetadataSnapshot snapshot, CaRecord ca, boolean changesHead,
            Optional<CaHeadSnapshot> original, IssuerCryptographicBinding binding, Optional<RootTrustAnchorActivation> activation) throws IOException {
            if (changesHead && ca.kind() == CaKind.ROOT) {
                IssuerCryptographicBinding old = findBinding(snapshot, original.orElseThrow().issuerId()).orElseThrow(AuthorityMetadataStore::invalid);
                if (!sameAnchor(old, binding) && activation.isEmpty()) { throw new IllegalArgumentException("Root anchor changes require an acknowledged candidate activation"); }
            }    }

}
