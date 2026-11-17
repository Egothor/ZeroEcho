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
import zeroecho.pki.api.ca.IssuerCryptographicBinding;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Comparator;
import java.util.Objects;
import java.util.UUID;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataTransactionId;
import zeroecho.pki.spi.store.StagedContentStore;

/**
 * Normalized authority metadata. CA heads never repeat keys or membership lists.
 * Opaque identities use bounded digest keys, never filesystem-safe aliases.
 * Every decoded payload must reproduce its exact namespace/key binding.
 * History ordering is semantic timestamp then committed metadata revision, not
 * lexical key order. This helper neither samples time nor writes metadata.
 */
final class AuthorityMetadataCodec {
    private static final int UTF8_TWO_BYTE_START = 0x80;
    private static final int UTF8_THREE_BYTE_START = 0x800;
    // Record reads use the existing transaction/WAL ceiling, not a new product
    // limit. Transaction framing and paired writes still share that same budget.
    /**
     * Inclusive maximum metadata value length in bytes.
     */
    /* default */ static final int MAX_VALUE_BYTES = SigningWalFrameCodec.MAX_PAYLOAD_BYTES;
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.ca-base}; persisted identities depend on this value.
     */
    /* default */ static final String CA_BASE = "io.zeroecho.pki.ca-base";
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.ca-current}; persisted identities depend on this value.
     */
    /* default */ static final String CA_CURRENT = "io.zeroecho.pki.ca-current";
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.ca-generation-order}; persisted identities depend on this value.
     */
    /* default */ static final String CA_GENERATION_ORDER = "io.zeroecho.pki.ca-generation-order";
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.ca-generation-member}; persisted identities depend on this value.
     */
    /* default */ static final String CA_GENERATION_MEMBER = "io.zeroecho.pki.ca-generation-member";
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.ca-history}; persisted identities depend on this value.
     */
    /* default */ static final String CA_HISTORY = "io.zeroecho.pki.ca-history";
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.issuer-generation}; persisted identities depend on this value.
     */
    /* default */ static final String ISSUER_GENERATION = "io.zeroecho.pki.issuer-generation";
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.issuer-crypto-binding}; persisted identities
     * depend on this value.
     */
    /* default */ static final String ISSUER_CRYPTO_BINDING = "io.zeroecho.pki.issuer-crypto-binding";
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.issuer-chain-path}; persisted identities depend on this value.
     */
    /* default */ static final String ISSUER_PATH = "io.zeroecho.pki.issuer-chain-path";
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.credential-record}; persisted identities depend on this value.
     */
    /* default */ static final String CREDENTIAL_RECORD = "io.zeroecho.pki.credential-record";
    /**
     * Exact metadata namespace {@code io.zeroecho.pki.credential-owner-set}; persisted identities depend on this value.
     */
    /* default */ static final String CREDENTIAL_OWNER_SET = "io.zeroecho.pki.credential-owner-set";
    /**
     * Stable history ordering by timestamp and then commit revision.
     */
    /* default */ static final Comparator<HistoryEntry> HISTORY_ORDER = Comparator.comparing(HistoryEntry::timestamp)
            .thenComparingLong(HistoryEntry::commitRevision);

    private AuthorityMetadataCodec() { }

    /**
     * Checks the inclusive transaction payload bound for one authority metadata value.
     *
     * @param payload complete encoded authority metadata bytes
     * @throws NullPointerException if the array is null
     * @throws IllegalArgumentException if the value exceeds the maximum transaction payload length
     */
    /* default */ static void requireValueSize(byte[] payload) {
        if (payload.length > MAX_VALUE_BYTES) { throw new IllegalArgumentException("Authority metadata exceeds the transaction payload bound"); }
    }

    /**
     * Derives the exact current CA head metadata identity.
     *
     * @param id exact logical CA identity
     * @return canonical digest-framed key in the current CA head namespace
     * @throws NullPointerException if a required input is null
     */
    /* default */ static MetadataKey caKey(PkiId id) { return identityKey(CA_CURRENT, id); }
    /**
     * Derives the exact immutable CA base metadata identity.
     *
     * @param id exact logical CA identity
     * @return canonical digest-framed key in the immutable CA base namespace
     * @throws NullPointerException if a required input is null
     */
    /* default */ static MetadataKey baseKey(PkiId id) { return identityKey(CA_BASE, id); }
    /**
     * Derives a lexically ordered authority generation-membership key.
     *
     * @param id owning logical authority identity
     * @param ordinal nonnegative generation ordinal, encoded as a ten-digit decimal suffix
     * @return canonical membership-order key
     * @throws NullPointerException if the authority identity is null
     * @throws IllegalArgumentException if the ordinal is negative
     */
    /* default */ static MetadataKey orderKey(PkiId id, int ordinal) {
        if (ordinal < 0) { throw invalid(); }
        String number = Integer.toString(ordinal);
        return new MetadataKey(CA_GENERATION_ORDER, historyPrefix(id) + "0".repeat(10 - number.length()) + number);
    }
    /**
     * Derives the exact authority-to-generation membership lookup key.
     *
     * @param id owning logical authority identity
     * @param generation exact issuer generation identity
     * @return digest-framed authority membership key
     * @throws NullPointerException if a required input is null
     */
    /* default */ static MetadataKey memberKey(PkiId id, PkiId generation) {
        return new MetadataKey(CA_GENERATION_MEMBER, historyPrefix(id) + digest(generation));
    }
    /**
     * Derives the exact issuer generation metadata identity.
     *
     * @param id exact issuer generation identity
     * @return canonical digest-framed key in the issuer generation namespace
     * @throws NullPointerException if a required input is null
     */
    /* default */ static MetadataKey generationKey(PkiId id) { return identityKey(ISSUER_GENERATION, id); }
    /**
     * Derives the exact context-bound issuer cryptographic binding metadata identity.
     *
     * @param id exact issuer generation identity
     * @return canonical digest-framed key in the context-bound issuer cryptographic binding namespace
     * @throws NullPointerException if a required input is null
     */
    /* default */ static MetadataKey bindingKey(PkiId id) { return identityKey(ISSUER_CRYPTO_BINDING, id); }
    /**
     * Decodes context-bound issuer public binding evidence and checks the persisted key.
     *
     * @param key exact issuer binding metadata identity
     * @param payload complete context-bound binary binding evidence
     * @param generation authoritative issuer generation against which context is verified
     * @return validated immutable issuer cryptographic binding
     * @throws java.io.IOException if encoding, generation context or binding commitment is invalid
     * @throws IllegalArgumentException if the persisted metadata key differs from the decoded issuer identity
     */
    /* default */ static IssuerCryptographicBinding binding(MetadataKey key, byte[] payload, IssuerGeneration generation) throws IOException {
        IssuerCryptographicBinding value = IssuerBindingStorageCodec.decode(payload, generation);
        requireKey(key, bindingKey(value.issuerId()));
        return value;
    }
    /**
     * Derives the exact issuer chain path metadata identity.
     *
     * @param id exact issuer chain path identity
     * @return canonical digest-framed key in the issuer chain path namespace
     * @throws NullPointerException if a required input is null
     */
    /* default */ static MetadataKey pathKey(PkiId id) { return identityKey(ISSUER_PATH, id); }
    /**
     * Derives the exact immutable credential metadata identity.
     *
     * @param id exact credential identity
     * @return canonical digest-framed key in the immutable credential namespace
     * @throws NullPointerException if a required input is null
     */
    /* default */ static MetadataKey credentialKey(PkiId id) { return identityKey(CREDENTIAL_RECORD, id); }

    /**
     * Derives the content owner-set metadata key from a canonical content UUID.
     *
     * @param contentId canonical content UUID text
     * @return exact content ownership projection key
     * @throws NullPointerException if the identity is null
     * @throws IllegalArgumentException if its UUID representation is not canonical
     */
    /* default */ static MetadataKey ownerSetKey(String contentId) {
        requireUuid(contentId);
        return new MetadataKey(CREDENTIAL_OWNER_SET, contentId);
    }

    /**
     * Derives an immutable authority history key ordered by timestamp and transaction token.
     *
     * @param authority owning logical CA identity
     * @param timestamp history timestamp, encoded in epoch microseconds
     * @param transaction exact transaction identity supplying the disambiguating token
     * @return canonical authority history metadata key
     * @throws NullPointerException if a required input is null
     * @throws ArithmeticException if the timestamp cannot fit the epoch-microsecond representation
     */
    /* default */ static MetadataKey historyKey(PkiId authority, Instant timestamp, MetadataTransactionId transaction) {
        Objects.requireNonNull(timestamp, "timestamp");
        Objects.requireNonNull(transaction, "transaction");
        return historyKey(authority, epochMicros(timestamp), transaction.token());
    }

    /**
     * Derives the canonical key prefix selecting one authority's complete history.
     *
     * @param authority exact logical authority identity
     * @return authority digest followed by the history separator
     * @throws NullPointerException if a required input is null
     */
    /* default */ static String historyPrefix(PkiId authority) { return digest(authority) + "."; }

    /**
     * Decodes current mutable authority head and requires its derived key to match persisted identity.
     *
     * @param key exact persisted metadata key
     * @param payload complete versioned binary metadata value
     * @return validated current mutable authority head
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if framing, semantic coordinates or the persisted identity differ
     */
    /* default */ static Head head(MetadataKey key, byte[] payload) {
        Head value = FsCodec.decode(FsCodec.CA_HEAD, payload);
        requireKey(key, caKey(value.caId()));
        return value;
    }

    /**
     * Decodes immutable authority base and requires its derived key to match persisted identity.
     *
     * @param key exact persisted metadata key
     * @param payload complete versioned binary metadata value
     * @return validated immutable authority base
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if framing, semantic coordinates or the persisted identity differ
     */
    /* default */ static Base base(MetadataKey key, byte[] payload) {
        Base value = FsCodec.decode(FsCodec.CA_BASE, payload);
        requireKey(key, baseKey(value.caId()));
        return value;
    }

    /**
     * Decodes ordered or direct authority generation membership and requires its derived key to match
     * persisted identity.
     *
     * @param key exact persisted metadata key
     * @param payload complete versioned binary metadata value
     * @return validated ordered or direct authority generation membership
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if framing, semantic coordinates or the persisted identity differ
     */
    /* default */ static Membership membership(MetadataKey key, byte[] payload) {
        Membership value = FsCodec.decode(FsCodec.CA_MEMBERSHIP, payload);
        requireKey(key, CA_GENERATION_ORDER.equals(key.namespace())
                ? orderKey(value.caId(), value.ordinal()) : memberKey(value.caId(), value.generationId()));
        return value;
    }

    /**
     * Decodes immutable issuer generation and requires its derived key to match persisted identity.
     *
     * @param key exact persisted metadata key
     * @param payload complete versioned binary metadata value
     * @return validated immutable issuer generation
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if framing, semantic coordinates or the persisted identity differ
     */
    /* default */ static IssuerGeneration generation(MetadataKey key, byte[] payload) {
        IssuerGeneration value = FsCodec.decode(FsCodec.ISSUER_GENERATION, payload);
        requireKey(key, generationKey(value.issuerId()));
        return value;
    }

    /**
     * Decodes immutable issuer chain path and requires its derived key to match persisted identity.
     *
     * @param key exact persisted metadata key
     * @param payload complete versioned binary metadata value
     * @return validated immutable issuer chain path
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if framing, semantic coordinates or the persisted identity differ
     */
    /* default */ static IssuerChainPath path(MetadataKey key, byte[] payload) {
        IssuerChainPath value = FsCodec.decode(FsCodec.ISSUER_CHAIN_PATH, payload);
        requireKey(key, pathKey(value.pathId()));
        return value;
    }

    /**
     * Decodes credential metadata and restores its exact store-bound content reference.
     *
     * @param key exact credential metadata identity
     * @param payload complete versioned binary credential metadata
     * @param content store used to restore durable content provenance
     * @return validated immutable credential with matching persisted identity
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if framing, credential coordinates or persisted identity are invalid
     */
    /* default */ static Credential credential(MetadataKey key, byte[] payload, StagedContentStore content) {
        Credential value = FsCodec.decode(FsCodec.CREDENTIAL, payload, content);
        requireKey(key, credentialKey(value.credentialId()));
        return value;
    }

    /* default */ // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
                  /**
                   * Decodes an immutable authority head history row with its timestamp and committed revision.
                   *
                   * @param key exact authority history key containing timestamp and transaction discriminator
                   * @param payload complete encoded authority head
                   * @param commitRevision nonnegative revision that committed this history row
                   * @return validated head history entry with timestamp recovered from its key
                   * @throws NullPointerException if a required input is null
                   * @throws IllegalArgumentException if framing, key namespace, timestamp,
                   * identity or committed revision is invalid
                   */
                  @SuppressWarnings({ "PMD.PreserveStackTrace" })
                  static HistoryEntry history(MetadataKey key, byte[] payload, long commitRevision) {
        Head value = FsCodec.decode(FsCodec.CA_HEAD, payload);
        String prefix = historyPrefix(value.caId());
        String component = key.key();
        if (!CA_HISTORY.equals(key.namespace()) || !component.startsWith(prefix) || commitRevision < 0) { throw invalid(); }
        int separator = component.indexOf('.', prefix.length());
        if (separator < 0) { throw invalid(); }
        try {
            long micros = Long.parseLong(component.substring(prefix.length(), separator));
            Instant timestamp = Instant.ofEpochSecond(Math.floorDiv(micros, 1_000_000L), Math.floorMod(micros, 1_000_000L) * 1000);
            String discriminator = component.substring(separator + 1);
            requireKey(key, historyKey(value.caId(), epochMicros(timestamp), discriminator));
            return new HistoryEntry(key, value, timestamp, commitRevision);
        } catch (IllegalArgumentException malformed) {
            throw invalid();
        }
    }

    private static MetadataKey historyKey(PkiId authority, long micros, String token) {
        if (!token.matches("[0-9a-f]{32}")) { throw invalid(); }
        return new MetadataKey(CA_HISTORY, historyPrefix(authority) + micros + "." + token);
    }

    private static long epochMicros(Instant timestamp) {
        long seconds = timestamp.getEpochSecond();
        long micros = timestamp.getNano() / 1000;
        // Avoid intermediate underflow at the representable negative boundary.
        if (seconds < 0 && micros > 0) {
            return Math.addExact(Math.multiplyExact(seconds + 1, 1_000_000L), micros - 1_000_000L);
        }
        return Math.addExact(Math.multiplyExact(seconds, 1_000_000L), micros);
    }

    private static MetadataKey identityKey(String namespace, PkiId id) {
        return new MetadataKey(namespace, digest(id));
    }

    private static String digest(PkiId id) {
        // Retain the existing FsCodec component limit; the metadata key itself
        // is always 64 ASCII bytes regardless of the original opaque ID.
        requireBoundedIdentity(id.value());
        return SigningProvider.ContentCommitment.sha256(id.value().getBytes(StandardCharsets.UTF_8)).sha256();
    }

    private static void requireBoundedIdentity(String value) {
        int bytes = 0;
        int index = 0;
        while (index < value.length()) {
            char unit = value.charAt(index);
            if (unit < UTF8_TWO_BYTE_START) { bytes++; }
            else if (unit < UTF8_THREE_BYTE_START) { bytes += 2; }
            else if (Character.isHighSurrogate(unit) && index + 1 < value.length()
                    && Character.isLowSurrogate(value.charAt(index + 1))) { bytes += 4; index++; }
            else if (Character.isSurrogate(unit)) { throw invalid(); }
            else { bytes += 3; }
            if (bytes > FsCodec.MAX_COMPONENT_BYTES) { throw invalid(); }
            index++;
        }
    }

    private static void requireUuid(String value) {
        if (value == null || value.length() != 36 || !UUID.fromString(value).toString().equals(value)) { throw invalid(); }
    }

    private static void requireKey(MetadataKey actual, MetadataKey expected) {
        if (!expected.equals(actual)) { throw invalid(); }
    }

    private static IllegalStateException invalid() {
        return new IllegalStateException("Authority metadata identity is inconsistent");
    }

    /**
     * Immutable authority identity, certificate category and subject coordinates.
     *
     * @param caId owning logical certificate authority identity
     * @param kind closed CaKind discriminator
     * @param subjectRef immutable authority subject reference
     */
    /* default */ record Base(PkiId caId, CaKind kind, SubjectRef subjectRef) {
        /**
         * Creates an immutable authority identity, certificate category and subject coordinates.
         *
         * @param caId owning logical certificate authority identity
         * @param kind closed CaKind discriminator
         * @param subjectRef immutable authority subject reference
         * @throws NullPointerException if {@code caId} is null; or if {@code kind} is null; or if
         * {@code subjectRef} is null
         */
        Base { Objects.requireNonNull(caId); Objects.requireNonNull(kind); Objects.requireNonNull(subjectRef); }
        /**
         * Projects the immutable base identity, category and subject coordinates from an existing CA record.
         *
         * @param ca authoritative CA metadata to project
         * @return new finite projection without storage access
         * @throws NullPointerException if a required input is null
         */
        /* default */ static Base of(CaRecord ca) { return new Base(ca.caId(), ca.kind(), ca.subjectRef()); }
    }

    /**
     * Mutable authority head pointing to its selected issuer generation and chain path.
     *
     * @param caId owning logical certificate authority identity
     * @param state closed lifecycle state
     * @param generationId exact generation identity
     * @param pathId selected immutable issuer chain path identity
     * @param membershipCount number of issuer-generation members retained by the authority
     */
    /* default */ record Head(PkiId caId, CaState state, PkiId generationId, PkiId pathId, int membershipCount) {
        /**
         * Creates the mutable authority head pointing to its selected issuer generation and chain path.
         *
         * @param caId owning logical certificate authority identity
         * @param state closed lifecycle state
         * @param generationId exact generation identity
         * @param pathId selected immutable issuer chain path identity
         * @param membershipCount number of issuer-generation members retained by the authority
         * @throws NullPointerException if {@code caId} is null; or if {@code state} is null; or if
         * {@code generationId} is null; or if {@code pathId} is null
         */
        Head {
            Objects.requireNonNull(caId); Objects.requireNonNull(state);
            Objects.requireNonNull(generationId); Objects.requireNonNull(pathId);
            if (membershipCount <= 0) { throw invalid(); }
        }
        /**
         * Projects the mutable state, selected issuer, chain path and membership count from an existing CA record.
         *
         * @param ca authoritative CA metadata to project
         * @return new finite projection without storage access
         * @throws NullPointerException if a required input is null
         */
        /* default */ static Head of(CaRecord ca) {
            return new Head(ca.caId(), ca.state(), ca.currentIssuanceIssuerId(), ca.issuanceChainPathId(), ca.issuerIds().size());
        }
    }

    /**
     * One ordered authority-to-issuer-generation membership entry.
     *
     * @param caId owning logical certificate authority identity
     * @param generationId exact generation identity
     * @param ordinal generation ordinal within the authority membership order
     */
    /* default */ record Membership(PkiId caId, PkiId generationId, int ordinal) {
        /**
         * Creates one ordered authority-to-issuer-generation membership entry.
         *
         * @param caId owning logical certificate authority identity
         * @param generationId exact generation identity
         * @param ordinal generation ordinal within the authority membership order
         * @throws NullPointerException if {@code caId} is null; or if {@code generationId} is null
         */
        Membership {
            Objects.requireNonNull(caId); Objects.requireNonNull(generationId);
            if (ordinal < 0) { throw invalid(); }
        }
    }

    /**
     * Retained authority head together with its metadata key and committed history coordinates.
     *
     * @param key exact logical metadata identity
     * @param value immutable authority head retained by this history entry
     * @param timestamp authoritative history entry timestamp
     * @param commitRevision revision that committed the retained history entry
     */
    /* default */ record HistoryEntry(MetadataKey key, Head value, Instant timestamp, long commitRevision) { }
}
