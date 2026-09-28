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
    /* default */ static final int MAX_VALUE_BYTES = SigningWalFrameCodec.MAX_PAYLOAD_BYTES;
    /* default */ static final String CA_BASE = "io.zeroecho.pki.ca-base";
    /* default */ static final String CA_CURRENT = "io.zeroecho.pki.ca-current";
    /* default */ static final String CA_GENERATION_ORDER = "io.zeroecho.pki.ca-generation-order";
    /* default */ static final String CA_GENERATION_MEMBER = "io.zeroecho.pki.ca-generation-member";
    /* default */ static final String CA_HISTORY = "io.zeroecho.pki.ca-history";
    /* default */ static final String ISSUER_GENERATION = "io.zeroecho.pki.issuer-generation";
    /* default */ static final String ISSUER_PATH = "io.zeroecho.pki.issuer-chain-path";
    /* default */ static final String CREDENTIAL_RECORD = "io.zeroecho.pki.credential-record";
    /* default */ static final String CREDENTIAL_OWNER_SET = "io.zeroecho.pki.credential-owner-set";
    /* default */ static final Comparator<HistoryEntry> HISTORY_ORDER = Comparator.comparing(HistoryEntry::timestamp)
            .thenComparingLong(HistoryEntry::commitRevision);

    private AuthorityMetadataCodec() { }

    /* default */ static void requireValueSize(byte[] payload) {
        if (payload.length > MAX_VALUE_BYTES) { throw new IllegalArgumentException("Authority metadata exceeds the transaction payload bound"); }
    }

    /* default */ static MetadataKey caKey(PkiId id) { return identityKey(CA_CURRENT, id); }
    /* default */ static MetadataKey baseKey(PkiId id) { return identityKey(CA_BASE, id); }
    /* default */ static MetadataKey orderKey(PkiId id, int ordinal) {
        if (ordinal < 0) { throw invalid(); }
        String number = Integer.toString(ordinal);
        return new MetadataKey(CA_GENERATION_ORDER, historyPrefix(id) + "0".repeat(10 - number.length()) + number);
    }
    /* default */ static MetadataKey memberKey(PkiId id, PkiId generation) {
        return new MetadataKey(CA_GENERATION_MEMBER, historyPrefix(id) + digest(generation));
    }
    /* default */ static MetadataKey generationKey(PkiId id) { return identityKey(ISSUER_GENERATION, id); }
    /* default */ static MetadataKey pathKey(PkiId id) { return identityKey(ISSUER_PATH, id); }
    /* default */ static MetadataKey credentialKey(PkiId id) { return identityKey(CREDENTIAL_RECORD, id); }

    /* default */ static MetadataKey ownerSetKey(String contentId) {
        requireUuid(contentId);
        return new MetadataKey(CREDENTIAL_OWNER_SET, contentId);
    }

    /* default */ static MetadataKey historyKey(PkiId authority, Instant timestamp, MetadataTransactionId transaction) {
        Objects.requireNonNull(timestamp, "timestamp");
        Objects.requireNonNull(transaction, "transaction");
        return historyKey(authority, epochMicros(timestamp), transaction.token());
    }

    /* default */ static String historyPrefix(PkiId authority) { return digest(authority) + "."; }

    /* default */ static Head head(MetadataKey key, byte[] payload) {
        Head value = FsCodec.decode(FsCodec.CA_HEAD, payload);
        requireKey(key, caKey(value.caId()));
        return value;
    }

    /* default */ static Base base(MetadataKey key, byte[] payload) {
        Base value = FsCodec.decode(FsCodec.CA_BASE, payload);
        requireKey(key, baseKey(value.caId()));
        return value;
    }

    /* default */ static Membership membership(MetadataKey key, byte[] payload) {
        Membership value = FsCodec.decode(FsCodec.CA_MEMBERSHIP, payload);
        requireKey(key, CA_GENERATION_ORDER.equals(key.namespace())
                ? orderKey(value.caId(), value.ordinal()) : memberKey(value.caId(), value.generationId()));
        return value;
    }

    /* default */ static IssuerGeneration generation(MetadataKey key, byte[] payload) {
        IssuerGeneration value = FsCodec.decode(FsCodec.ISSUER_GENERATION, payload);
        requireKey(key, generationKey(value.issuerId()));
        return value;
    }

    /* default */ static IssuerChainPath path(MetadataKey key, byte[] payload) {
        IssuerChainPath value = FsCodec.decode(FsCodec.ISSUER_CHAIN_PATH, payload);
        requireKey(key, pathKey(value.pathId()));
        return value;
    }

    /* default */ static Credential credential(MetadataKey key, byte[] payload, StagedContentStore content) {
        Credential value = FsCodec.decode(FsCodec.CREDENTIAL, payload, content);
        requireKey(key, credentialKey(value.credentialId()));
        return value;
    }

    /* default */ // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
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

    /* default */ record Base(PkiId caId, CaKind kind, SubjectRef subjectRef) {
        Base { Objects.requireNonNull(caId); Objects.requireNonNull(kind); Objects.requireNonNull(subjectRef); }
        /* default */ static Base of(CaRecord ca) { return new Base(ca.caId(), ca.kind(), ca.subjectRef()); }
    }

    /* default */ record Head(PkiId caId, CaState state, PkiId generationId, PkiId pathId, int membershipCount) {
        Head {
            Objects.requireNonNull(caId); Objects.requireNonNull(state);
            Objects.requireNonNull(generationId); Objects.requireNonNull(pathId);
            if (membershipCount <= 0) { throw invalid(); }
        }
        /* default */ static Head of(CaRecord ca) {
            return new Head(ca.caId(), ca.state(), ca.currentIssuanceIssuerId(), ca.issuanceChainPathId(), ca.issuerIds().size());
        }
    }

    /* default */ record Membership(PkiId caId, PkiId generationId, int ordinal) {
        Membership {
            Objects.requireNonNull(caId); Objects.requireNonNull(generationId);
            if (ordinal < 0) { throw invalid(); }
        }
    }

    /* default */ record HistoryEntry(MetadataKey key, Head value, Instant timestamp, long commitRevision) { }
}
