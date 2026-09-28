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
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;

/** Strict version-one payload for one atomic metadata-ledger transaction frame. */
@SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops", "PMD.AvoidLiteralsInIfCondition",
        "PMD.CommentRequired", "PMD.ControlStatementBraces",
        "PMD.CyclomaticComplexity", "PMD.MethodReturnsInternalArray", "PMD.PreserveStackTrace",
        "PMD.ReturnEmptyCollectionRatherThanNull" })
final class SigningTransactionPayloadCodec {
    /* default */ static final int MAXIMUM_MUTATIONS = 31;
    private static final int MAGIC = 0x5A455458;
    private static final short VERSION = 1;
    private static final short FLAGS = 0;
    private static final int HEADER_BYTES = 12;
    private static final AtomicLong CONTENT_COPIES = new AtomicLong();

    private SigningTransactionPayloadCodec() {
        // utility class
    }

    /* default */ static byte[] issue() {
        return header(Kind.ISSUE, 0).array();
    }

    /* default */ static byte[] commit(List<Mutation> mutations) {
        return commit(mutations, -1L);
    }

    /* default */ static byte[] commit(List<Mutation> mutations, long watermark) {
        List<Mutation> values = List.copyOf(Objects.requireNonNull(mutations, "mutations"));
        requireCommitWatermark(watermark);
        int size = encodedCommitSize(values);
        ByteBuffer output = grow(header(Kind.COMMIT, values.size()), size);
        for (Mutation mutation : values) {
            byte[] key = mutation.key().canonical().getBytes(StandardCharsets.US_ASCII);
            byte[] content = mutation.contentInternal();
            output.put(mutation.kind().code).putLong(mutation.expectedRevision())
                    .putInt(key.length).put(key).putInt(content == null ? -1 : content.length);
            if (content != null) {
                output.put(content);
            }
        }
        output.putLong(watermark);
        return output.array();
    }

    /* default */ static byte[] directCommit(List<Mutation> mutations, long watermark) {
        List<Mutation> values = List.copyOf(Objects.requireNonNull(mutations, "mutations"));
        if (values.isEmpty()) {
            throw new IllegalArgumentException("direct metadata commit must contain a mutation");
        }
        requireCommitWatermark(watermark);
        int size = encodedCommitSize(values);
        ByteBuffer output = grow(header(Kind.DIRECT_COMMIT, values.size()), size);
        for (Mutation mutation : values) {
            byte[] key = mutation.key().canonical().getBytes(StandardCharsets.US_ASCII);
            byte[] content = mutation.contentInternal();
            output.put(mutation.kind().code).putLong(mutation.expectedRevision())
                    .putInt(key.length).put(key).putInt(content == null ? -1 : content.length);
            if (content != null) output.put(content);
        }
        output.putLong(watermark);
        return output.array();
    }

    /* default */ static int encodedCommitSize(List<Mutation> mutations) {
        List<Mutation> values = Objects.requireNonNull(mutations, "mutations");
        if (values.isEmpty() || values.size() > MAXIMUM_MUTATIONS) {
            throw new IllegalArgumentException("metadata transaction mutation count is invalid");
        }
        int size = HEADER_BYTES + Long.BYTES;
        Set<MetadataKey> distinct = new HashSet<>();
        for (Mutation mutation : values) {
            Objects.requireNonNull(mutation, "mutation");
            if (!distinct.add(mutation.key())) {
                throw new IllegalArgumentException("metadata transaction keys must be distinct");
            }
            byte[] key = mutation.key().canonical().getBytes(StandardCharsets.US_ASCII);
            int contentLength = mutation.content == null ? -1 : mutation.content.length;
            size = Math.addExact(size, Math.addExact(1 + Long.BYTES + Integer.BYTES + key.length,
                    Math.addExact(Integer.BYTES, Math.max(0, contentLength))));
        }
        requirePayloadSize(size);
        return size;
    }

    /** Exact framing budget for callers assembling bounded restore batches. */
    /* default */ static int emptyCommitBytes() { return HEADER_BYTES + Long.BYTES; }

    /* default */ static int encodedCreateBytes(MetadataKey key, int contentBytes) {
        if (contentBytes < 0) { throw new IllegalArgumentException("Negative metadata payload length"); }
        return Math.addExact(1 + Long.BYTES + 2 * Integer.BYTES,
                Math.addExact(key.canonical().length(), contentBytes));
    }

    /* default */ static long retainedMutationBytes(List<Mutation> mutations) {
        long result = 0L;
        for (Mutation mutation : Objects.requireNonNull(mutations, "mutations")) {
            Objects.requireNonNull(mutation, "mutation");
            result = Math.addExact(result, mutation.contentLength());
        }
        return result;
    }

    /* default */ static Payload commitPayload(List<Mutation> mutations) {
        return commitPayload(mutations, -1L);
    }

    /* default */ static Payload commitPayload(List<Mutation> mutations, long watermark) {
        requireCommitWatermark(watermark);
        return new Payload(Kind.COMMIT, mutations, null, watermark);
    }

    /* default */ static Payload directCommitPayload(List<Mutation> mutations, long watermark) {
        requireCommitWatermark(watermark);
        return new Payload(Kind.DIRECT_COMMIT, mutations, null, watermark);
    }

    /* default */ static Payload issuePayload() {
        return new Payload(Kind.ISSUE, List.of(), null, -1L);
    }

    /* default */ static Payload rejectPayload(MetadataCommitResult.FailureCategory category) {
        return new Payload(Kind.REJECT, List.of(), Objects.requireNonNull(category, "category"), -1L);
    }

    /* default */ static Payload acknowledgePayload() {
        return new Payload(Kind.ACK, List.of(), null, -1L);
    }

    /* default */ static Payload watermarkPayload(long epochMilli) {
        if (epochMilli < 0L) {
            throw new IllegalArgumentException("metadata watermark is invalid");
        }
        return new Payload(Kind.WATERMARK, List.of(), null, epochMilli);
    }

    /** Encodes a committed retained outcome without replaying caller mutations. */
    /* default */ static byte[] committedOutcome() {
        ByteBuffer output = grow(header(Kind.COMMIT, 0), HEADER_BYTES + Long.BYTES);
        output.putLong(-1L);
        return output.array();
    }

    /* default */ static byte[] reject(MetadataCommitResult.FailureCategory category) {
        Objects.requireNonNull(category, "category");
        ByteBuffer output = grow(header(Kind.REJECT, 0), HEADER_BYTES + Integer.BYTES);
        output.putInt(category.ordinal());
        return output.array();
    }

    /* default */ static byte[] acknowledge() {
        return header(Kind.ACK, 0).array();
    }

    /* default */ static byte[] watermark(long epochMilli) {
        if (epochMilli < 0L) {
            throw new IllegalArgumentException("metadata watermark is invalid");
        }
        ByteBuffer output = grow(header(Kind.WATERMARK, 0), HEADER_BYTES + Long.BYTES);
        output.putLong(epochMilli);
        return output.array();
    }

    /* default */ static Payload decode(byte[] encoded) throws IOException {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length < HEADER_BYTES || encoded.length > SigningWalFrameCodec.MAX_PAYLOAD_BYTES) {
            throw invalid();
        }
        ByteBuffer input = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
        if (input.getInt() != MAGIC || input.getShort() != VERSION || input.getShort() != FLAGS) {
            throw invalid();
        }
        Kind kind = Kind.fromCode(input.get());
        int count = Byte.toUnsignedInt(input.get());
        if (input.getShort() != 0 || kind == null || count > MAXIMUM_MUTATIONS
                || kind == Kind.DIRECT_COMMIT && count == 0
                || kind != Kind.COMMIT && kind != Kind.DIRECT_COMMIT && count != 0) {
            throw invalid();
        }
        try {
            List<Mutation> mutations = new ArrayList<>(count);
            MetadataCommitResult.FailureCategory failure = null;
            long watermark = -1L;
            if (kind == Kind.COMMIT || kind == Kind.DIRECT_COMMIT) {
                Set<MetadataKey> distinct = new HashSet<>();
                for (int index = 0; index < count; index++) {
                    MutationKind mutationKind = MutationKind.fromCode(input.get());
                    long expected = input.getLong();
                    String key = readAscii(input);
                    byte[] content = readMutationContent(input, mutationKind);
                    MetadataKey metadataKey = MetadataKey.parse(key);
                    if (!distinct.add(metadataKey)) {
                        throw invalid();
                    }
                    Mutation mutation = new Mutation(mutationKind, metadataKey, expected, content);
                    mutations.add(mutation);
                }
                watermark = input.getLong();
                if (watermark < -1L) {
                    throw invalid();
                }
            } else if (kind == Kind.REJECT) {
                int ordinal = input.getInt();
                MetadataCommitResult.FailureCategory[] categories =
                        MetadataCommitResult.FailureCategory.values();
                if (ordinal < 0 || ordinal >= categories.length) {
                    throw invalid();
                }
                failure = categories[ordinal];
            } else if (kind == Kind.WATERMARK) {
                watermark = input.getLong();
                if (watermark < 0L) {
                    throw invalid();
                }
            }
            if (input.hasRemaining()) {
                throw invalid();
            }
            return new Payload(kind, mutations, failure, watermark);
        } catch (IllegalArgumentException | java.nio.BufferUnderflowException failure) {
            throw invalid();
        }
    }

    private static String readAscii(ByteBuffer input) throws IOException {
        int length = input.getInt();
        if (length <= 0 || length > 8192 || length > input.remaining()) {
            throw invalid();
        }
        byte[] bytes = new byte[length];
        input.get(bytes);
        String value = new String(bytes, StandardCharsets.US_ASCII);
        if (!java.util.Arrays.equals(bytes, value.getBytes(StandardCharsets.US_ASCII))) {
            throw invalid();
        }
        return value;
    }

    private static byte[] readMutationContent(ByteBuffer input, MutationKind kind) throws IOException {
        int length = input.getInt();
        if (kind == MutationKind.DELETE ? length != -1 : length < 0) {
            throw invalid();
        }
        if (length < 0) return null;
        if (length > input.remaining()) throw invalid();
        byte[] content = new byte[length];
        input.get(content);
        CONTENT_COPIES.incrementAndGet();
        return content;
    }

    private static ByteBuffer header(Kind kind, int count) {
        ByteBuffer output = ByteBuffer.allocate(HEADER_BYTES).order(ByteOrder.BIG_ENDIAN);
        output.putInt(MAGIC).putShort(VERSION).putShort(FLAGS).put(kind.code)
                .put((byte) count).putShort((short) 0);
        return output;
    }

    private static ByteBuffer grow(ByteBuffer prefix, int length) {
        ByteBuffer output = ByteBuffer.allocate(length).order(ByteOrder.BIG_ENDIAN);
        output.put(prefix.array());
        return output;
    }

    private static void requirePayloadSize(int size) {
        if (size > SigningWalFrameCodec.MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("metadata transaction payload exceeds 2 MiB");
        }
    }

    /** A commit carries either no observation ({@code -1}) or a non-negative epoch millisecond. */
    private static void requireCommitWatermark(long watermark) {
        if (watermark < -1L) {
            throw new IllegalArgumentException("metadata commit watermark is invalid");
        }
    }

    private static IOException invalid() {
        return SigningFormatSupport.invalid("metadata transaction payload is invalid");
    }

    /* default */ static void resetContentCopyCount() { CONTENT_COPIES.set(0L); }

    /* default */ static long contentCopyCount() { return CONTENT_COPIES.get(); }

    /* default */ enum Kind {
        ISSUE(1), COMMIT(2), REJECT(3), ACK(4), WATERMARK(5), DIRECT_COMMIT(6);
        private final byte code;
        Kind(int code) { this.code = (byte) code; }
        private static Kind fromCode(byte code) {
            for (Kind value : values()) {
                if (value.code == code) return value;
            }
            return null;
        }
    }

    /* default */ enum MutationKind {
        CREATE(1), REPLACE(2), DELETE(3);
        private final byte code;
        MutationKind(int code) { this.code = (byte) code; }
        private static MutationKind fromCode(byte code) throws IOException {
            for (MutationKind value : values()) {
                if (value.code == code) return value;
            }
            throw invalid();
        }
    }

    /* default */ record Mutation(MutationKind kind, MetadataKey key,
            long expectedRevision, byte[] content) {
        Mutation {
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(key, "key");
            if (kind == MutationKind.CREATE && expectedRevision != -1L
                    || kind != MutationKind.CREATE && expectedRevision < 0L
                    || kind == MutationKind.DELETE && content != null
                    || kind != MutationKind.DELETE && content == null) {
                throw new IllegalArgumentException("metadata transaction mutation is invalid");
            }
            content = content == null ? null : content.clone();
        }
        @Override public byte[] content() {
            if (content == null) return null;
            CONTENT_COPIES.incrementAndGet();
            return content.clone();
        }
        private int contentLength() { return content == null ? 0 : content.length; }
        /* default */ byte[] contentInternal() { return content; }
    }

    /* default */ record Payload(Kind kind, List<Mutation> mutations,
            MetadataCommitResult.FailureCategory failure, long watermark) {
        Payload {
            Objects.requireNonNull(kind, "kind");
            mutations = List.copyOf(mutations);
            if (kind == Kind.DIRECT_COMMIT && mutations.isEmpty()) {
                throw new IllegalArgumentException("direct metadata commit must contain a mutation");
            }
            if (kind == Kind.COMMIT || kind == Kind.DIRECT_COMMIT) {
                requireCommitWatermark(watermark);
                Set<MetadataKey> distinct = new HashSet<>();
                for (Mutation mutation : mutations) {
                    if (!distinct.add(mutation.key())) {
                        throw new IllegalArgumentException("metadata transaction keys must be distinct");
                    }
                }
            }
        }
    }
}
