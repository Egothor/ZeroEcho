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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.OptionalLong;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataStoreException;

/** Strict current-version codec for opaque metadata mutation frame payloads. */
final class MetadataMutationPayloadCodec {
    private static final short SCHEMA_VERSION = 1;
    private static final byte RESERVED_FLAGS = 0;
    private static final int COMMON_BYTES = Short.BYTES + Byte.BYTES + Byte.BYTES
            + Short.BYTES + Short.BYTES;
    private static final int VALUE_SCALAR_BYTES = Long.BYTES;
    private static final int EXPECTED_VALUE_SCALAR_BYTES = Long.BYTES + Long.BYTES;
    private static final int MAXIMUM_IDENTITY_BYTES = MetadataKey.MAXIMUM_NAMESPACE_UTF8_BYTES
            + MetadataKey.MAXIMUM_KEY_UTF8_BYTES;
    private static final int TRANSFER_BUFFER_BYTES = 8192;
    private static final long NO_REMAINING_VALUE_BYTES = 0L;
    private static final long MINIMUM_REVISION = 0L;
    private static final long MINIMUM_LENGTH = 0L;

    private MetadataMutationPayloadCodec() {
    }

    /* default */ static RepeatableContent create(
            MetadataKey key, RepeatableContent value, CancellationSignal cancellation)
            throws MetadataStoreException {
        return PayloadEncoder.create(key, value, cancellation);
    }

    /* default */ static RepeatableContent replace(
            MetadataKey key,
            long expectedRevision,
            RepeatableContent value,
            CancellationSignal cancellation) throws MetadataStoreException {
        return PayloadEncoder.replace(key, expectedRevision, value, cancellation);
    }

    /* default */ static RepeatableContent delete(MetadataKey key, long expectedRevision) {
        return PayloadEncoder.delete(key, expectedRevision);
    }

    /*
     * Decoding reads only the bounded descriptor prefix. Value bytes remain in
     * the already validated frame region and no channel authority escapes.
     */
    /* default */ static Descriptor decode(
            SeekableByteChannel channel, MetadataFrameCodec.FrameMetadata frame) throws IOException {
        return PayloadDecoder.decode(channel, frame);
    }

    /** Builds bounded mutation prefixes without consuming caller content. */
    private static final class PayloadEncoder {
        private static RepeatableContent create(
                MetadataKey key, RepeatableContent value, CancellationSignal cancellation)
                throws MetadataStoreException {
            return valuePayload(MutationKind.CREATE, key, OptionalLong.empty(), value, cancellation);
        }

        private static RepeatableContent replace(
                MetadataKey key,
                long expectedRevision,
                RepeatableContent value,
                CancellationSignal cancellation) throws MetadataStoreException {
            requireRevision(expectedRevision);
            return valuePayload(
                    MutationKind.REPLACE, key, OptionalLong.of(expectedRevision), value, cancellation);
        }

        private static RepeatableContent delete(MetadataKey key, long expectedRevision) {
            Objects.requireNonNull(key, "key");
            requireRevision(expectedRevision);
            byte[] prefix = prefix(
                    MutationKind.DELETE, key, OptionalLong.of(expectedRevision), OptionalLong.empty());
            return new CompositePayload(prefix, null, 0L, CancellationSignal.NONE);
        }

        private static RepeatableContent valuePayload(
                MutationKind kind,
                MetadataKey key,
                OptionalLong expectedRevision,
                RepeatableContent value,
                CancellationSignal cancellation) throws MetadataStoreException {
            Objects.requireNonNull(key, "key");
            Objects.requireNonNull(value, "value");
            Objects.requireNonNull(cancellation, "cancellation");
            OptionalLong knownLength = value.length();
            if (knownLength.isEmpty()) {
                throw new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.UNSUPPORTED_CAPABILITY,
                        "Metadata mutation value requires a known length");
            }
            long valueLength = knownLength.getAsLong();
            if (valueLength < MINIMUM_LENGTH) {
                throw new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE,
                        "Metadata mutation value length is negative");
            }
            byte[] prefix = prefix(kind, key, expectedRevision, OptionalLong.of(valueLength));
            try {
                Math.addExact((long) prefix.length, valueLength);
            } catch (ArithmeticException failure) {
                throw new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                        "Metadata mutation payload length is not representable",
                        failure);
            }
            return new CompositePayload(prefix, value, valueLength, cancellation);
        }

        private static byte[] prefix(
                MutationKind kind,
                MetadataKey key,
                OptionalLong expectedRevision,
                OptionalLong valueLength) {
            byte[] namespace = key.namespace().getBytes(StandardCharsets.UTF_8);
            byte[] logicalKey = key.key().getBytes(StandardCharsets.UTF_8);
            SchemaRules.requireIdentityLengths(namespace.length, logicalKey.length);
            int scalarLength = SchemaRules.scalarLength(kind);
            int prefixLength = Math.addExact(
                    Math.addExact(COMMON_BYTES, scalarLength),
                    Math.addExact(namespace.length, logicalKey.length));
            ByteBuffer prefix = ByteBuffer.allocate(prefixLength).order(ByteOrder.BIG_ENDIAN);
            prefix.putShort(SCHEMA_VERSION).put(kind.code).put(RESERVED_FLAGS);
            prefix.putShort((short) namespace.length).putShort((short) logicalKey.length);
            if (expectedRevision.isPresent()) {
                prefix.putLong(expectedRevision.getAsLong());
            }
            if (valueLength.isPresent()) {
                prefix.putLong(valueLength.getAsLong());
            }
            prefix.put(namespace).put(logicalKey);
            return prefix.array();
        }

        private static void requireRevision(long revision) {
            if (revision < MINIMUM_REVISION) {
                throw new IllegalArgumentException(
                        "Metadata mutation expected revision must be non-negative");
            }
        }
    }

    /** Validates bounded mutation descriptors without reading value bytes. */
    private static final class PayloadDecoder {
        private static Descriptor decode(
                SeekableByteChannel channel, MetadataFrameCodec.FrameMetadata frame) throws IOException {
            Objects.requireNonNull(channel, "channel");
            Objects.requireNonNull(frame, "frame");
            requireMutationFrame(frame.frameType());
            requirePayloadRegion(frame);
            ByteBuffer common = readExact(channel, frame.payloadOffset(), COMMON_BYTES, frame);
            short version = common.getShort();
            MutationKind kind = MutationKind.fromCode(common.get());
            byte flags = common.get();
            int namespaceLength = Short.toUnsignedInt(common.getShort());
            int keyLength = Short.toUnsignedInt(common.getShort());
            validateCommonFields(version, flags, namespaceLength, keyLength);
            requireFrameKind(frame.frameType(), kind);
            int scalarLength = SchemaRules.scalarLength(kind);
            long scalarOffset = checkedAdd(frame.payloadOffset(), COMMON_BYTES);
            ByteBuffer scalars = readExact(channel, scalarOffset, scalarLength, frame);
            OptionalLong expectedRevision = expectedRevision(kind, scalars);
            OptionalLong valueLength = valueLength(kind, scalars);
            long identityOffset = checkedAdd(scalarOffset, scalarLength);
            int identityLength = Math.addExact(namespaceLength, keyLength);
            MetadataKey metadataKey = decodeIdentity(
                    channel, frame, identityOffset, identityLength, namespaceLength, keyLength);
            long valueOffset = checkedAdd(identityOffset, identityLength);
            validatePayloadBoundary(frame, valueOffset, valueLength);
            return new Descriptor(
                    kind,
                    metadataKey,
                    expectedRevision,
                    valueLength.isPresent() ? OptionalLong.of(valueOffset) : OptionalLong.empty(),
                    valueLength);
        }

        private static void validateCommonFields(
                short version, byte flags, int namespaceLength, int keyLength)
                throws MetadataStoreException {
            if (version != SCHEMA_VERSION || flags != RESERVED_FLAGS) {
                throw integrity("Metadata mutation payload schema is unsupported");
            }
            try {
                SchemaRules.requireIdentityLengths(namespaceLength, keyLength);
            } catch (IllegalArgumentException failure) {
                throw integrity("Metadata mutation identity length exceeds its canonical limit", failure);
            }
        }

        private static MetadataKey decodeIdentity(
                SeekableByteChannel channel,
                MetadataFrameCodec.FrameMetadata frame,
                long identityOffset,
                int identityLength,
                int namespaceLength,
                int keyLength) throws IOException {
            ByteBuffer identity = readExact(channel, identityOffset, identityLength, frame);
            String namespace = decodeUtf8(identity, namespaceLength);
            String logicalKey = decodeUtf8(identity, keyLength);
            try {
                return new MetadataKey(namespace, logicalKey);
            } catch (IllegalArgumentException failure) {
                throw integrity("Metadata mutation identity is not canonical", failure);
            }
        }

        private static OptionalLong expectedRevision(MutationKind kind, ByteBuffer scalars)
                throws MetadataStoreException {
            if (kind == MutationKind.CREATE) {
                return OptionalLong.empty();
            }
            long revision = scalars.getLong();
            if (revision < MINIMUM_REVISION) {
                throw integrity("Metadata mutation expected revision is negative");
            }
            return OptionalLong.of(revision);
        }

        private static OptionalLong valueLength(MutationKind kind, ByteBuffer scalars)
                throws MetadataStoreException {
            if (kind == MutationKind.DELETE) {
                return OptionalLong.empty();
            }
            long length = scalars.getLong();
            if (length < MINIMUM_LENGTH) {
                throw integrity("Metadata mutation value length is negative");
            }
            return OptionalLong.of(length);
        }

        private static void validatePayloadBoundary(
                MetadataFrameCodec.FrameMetadata frame,
                long valueOffset,
                OptionalLong valueLength) throws MetadataStoreException {
            if (valueOffset < frame.payloadOffset()) {
                throw integrity("Metadata mutation value begins before its validated payload region");
            }
            long expectedEnd = valueOffset;
            if (valueLength.isPresent()) {
                long length = valueLength.getAsLong();
                if (length < MINIMUM_LENGTH) {
                    throw integrity("Metadata mutation value length is negative");
                }
                expectedEnd = checkedAdd(expectedEnd, length);
            }
            if (expectedEnd != frame.payloadDigestOffset()) {
                throw integrity("Metadata mutation payload has trailing or missing data");
            }
        }

        private static void requirePayloadRegion(MetadataFrameCodec.FrameMetadata frame)
                throws MetadataStoreException {
            if (frame.payloadOffset() < MINIMUM_LENGTH || frame.payloadLength() < MINIMUM_LENGTH) {
                throw integrity("Metadata mutation frame payload region is negative");
            }
            long expectedEnd = checkedAdd(frame.payloadOffset(), frame.payloadLength());
            if (expectedEnd != frame.payloadDigestOffset()) {
                throw integrity("Metadata mutation frame payload region is inconsistent");
            }
        }

        private static ByteBuffer readExact(
                SeekableByteChannel channel,
                long offset,
                int length,
                MetadataFrameCodec.FrameMetadata frame) throws IOException {
            long end = checkedAdd(offset, length);
            if (offset < frame.payloadOffset() || end > frame.payloadDigestOffset()) {
                throw integrity("Metadata mutation descriptor exceeds its validated payload region");
            }
            ByteBuffer result = ByteBuffer.allocate(length).order(ByteOrder.BIG_ENDIAN);
            channel.position(offset);
            while (result.hasRemaining()) {
                int count = channel.read(result);
                if (count < 0) {
                    throw integrity("Metadata mutation descriptor is truncated");
                }
                if (count == 0) {
                    throw integrity("Metadata mutation descriptor channel made no read progress");
                }
            }
            result.flip();
            return result;
        }

        private static String decodeUtf8(ByteBuffer source, int length)
                throws MetadataStoreException {
            ByteBuffer bytes = source.slice();
            bytes.limit(length);
            source.position(source.position() + length);
            try {
                return StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(bytes)
                        .toString();
            } catch (CharacterCodingException failure) {
                throw integrity("Metadata mutation identity is not valid UTF-8", failure);
            }
        }

        private static void requireMutationFrame(MetadataFrameCodec.FrameType type) {
            if (type != MetadataFrameCodec.FrameType.MUTATION_CREATE
                    && type != MetadataFrameCodec.FrameType.MUTATION_REPLACE
                    && type != MetadataFrameCodec.FrameType.MUTATION_DELETE) {
                throw new IllegalArgumentException("Frame does not contain a metadata mutation");
            }
        }

        private static void requireFrameKind(
                MetadataFrameCodec.FrameType frameType, MutationKind kind)
                throws MetadataStoreException {
            if (kind.frameType != frameType) {
                throw integrity("Metadata mutation kind does not match its frame type");
            }
        }

        private static long checkedAdd(long first, long second) throws MetadataStoreException {
            try {
                return Math.addExact(first, second);
            } catch (ArithmeticException failure) {
                throw integrity("Metadata mutation payload boundary overflows", failure);
            }
        }
    }

    /** Centralizes the schema limits shared by encoding and decoding. */
    private static final class SchemaRules {
        private static void requireIdentityLengths(int namespaceLength, int keyLength) {
            if (namespaceLength > MetadataKey.MAXIMUM_NAMESPACE_UTF8_BYTES
                    || keyLength > MetadataKey.MAXIMUM_KEY_UTF8_BYTES
                    || Math.addExact(namespaceLength, keyLength) > MAXIMUM_IDENTITY_BYTES) {
                throw new IllegalArgumentException(
                        "Metadata mutation identity length exceeds its canonical limit");
            }
        }

        private static int scalarLength(MutationKind kind) {
            return kind == MutationKind.REPLACE
                    ? EXPECTED_VALUE_SCALAR_BYTES
                    : VALUE_SCALAR_BYTES;
        }
    }

    private static MetadataStoreException integrity(String message) {
        return new MetadataStoreException(MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE, message);
    }

    private static MetadataStoreException integrity(String message, Throwable cause) {
        return new MetadataStoreException(
                MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE, message, cause);
    }

    /** Stable mutation kinds; codes never depend on Java enum ordinals. */
    /* default */ enum MutationKind {
        CREATE((byte) 1, MetadataFrameCodec.FrameType.MUTATION_CREATE),
        REPLACE((byte) 2, MetadataFrameCodec.FrameType.MUTATION_REPLACE),
        DELETE((byte) 3, MetadataFrameCodec.FrameType.MUTATION_DELETE);

        private final byte code;
        private final MetadataFrameCodec.FrameType frameType;

        MutationKind(byte code, MetadataFrameCodec.FrameType frameType) {
            this.code = code;
            this.frameType = frameType;
        }

        private static MutationKind fromCode(byte code) throws MetadataStoreException {
            for (MutationKind candidate : values()) {
                if (candidate.code == code) {
                    return candidate;
                }
            }
            throw integrity("Metadata mutation kind is unsupported");
        }
    }

    /** Bounded descriptor of a decoded mutation; it carries no channel or value bytes. */
    /* default */ record Descriptor(
            MutationKind kind,
            MetadataKey key,
            OptionalLong expectedRevision,
            OptionalLong valueOffset,
            OptionalLong valueLength) {
        Descriptor {
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(key, "key");
            Objects.requireNonNull(expectedRevision, "expectedRevision");
            Objects.requireNonNull(valueOffset, "valueOffset");
            Objects.requireNonNull(valueLength, "valueLength");
        }
    }

    /** Composite control prefix plus an exactly bounded caller-owned value stream. */
    private static final class CompositePayload implements RepeatableContent {
        private final byte[] prefix;
        private final RepeatableContent value;
        private final long valueLength;
        private final CancellationSignal cancellation;

        private CompositePayload(
                byte[] prefix,
                RepeatableContent value,
                long valueLength,
                CancellationSignal cancellation) {
            this.prefix = prefix.clone();
            this.value = value;
            this.valueLength = valueLength;
            this.cancellation = cancellation;
        }

        @Override
        public InputStream openStream() throws IOException {
            cancellation.throwIfCancelled();
            InputStream valueStream = value == null ? null : value.openStream();
            return new ExactCompositeInputStream(prefix, valueStream, valueLength, cancellation);
        }

        @Override
        public OptionalLong length() {
            return OptionalLong.of(Math.addExact((long) prefix.length, valueLength));
        }

        @Override
        public String contentId() {
            return "zeroecho-metadata-mutation-payload-v1";
        }

        @Override
        public void close() {
            // The composite owns opened streams, never the caller's content object.
        }
    }

    /** Bounded stream that validates declared value length without buffering it. */
    private static final class ExactCompositeInputStream extends InputStream {
        private final ByteArrayInputStream prefix;
        private final InputStream value;
        private final CancellationSignal cancellation;
        private long remaining;
        private boolean exactLengthVerified;
        private boolean closed;

        private ExactCompositeInputStream(
                byte[] prefix,
                InputStream value,
                long valueLength,
                CancellationSignal cancellation) {
            super();
            this.prefix = new ByteArrayInputStream(prefix);
            this.value = value;
            this.remaining = valueLength;
            this.cancellation = cancellation;
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int count = read(one, 0, one.length);
            return count < 0 ? -1 : Byte.toUnsignedInt(one[0]);
        }

        @Override
        public int read(byte[] target, int offset, int length) throws IOException {
            Objects.checkFromIndexSize(offset, length, target.length);
            requireOpen();
            cancellation.throwIfCancelled();
            if (length == 0) {
                return 0;
            }
            int prefixCount = prefix.read(target, offset, length);
            if (prefixCount >= 0) {
                return prefixCount;
            }
            return readValue(target, offset, length);
        }

        private int readValue(byte[] target, int offset, int length) throws IOException {
            if (value == null) {
                return -1;
            }
            if (remaining == NO_REMAINING_VALUE_BYTES) {
                verifyNoExcess();
                return -1;
            }
            int requested = (int) Math.min((long) Math.min(length, TRANSFER_BUFFER_BYTES), remaining);
            int count = value.read(target, offset, requested);
            if (count < 0) {
                throw new IOException("Metadata mutation value is shorter than declared");
            }
            if (count == 0) {
                throw closeAfterNoProgress();
            }
            remaining -= count;
            return count;
        }

        private MetadataStoreException closeAfterNoProgress() {
            MetadataStoreException failure = new MetadataStoreException(
                    MetadataCommitResult.FailureCategory.STORAGE_FAILURE,
                    "Metadata mutation value stream made no read progress");
            closed = true;
            try {
                prefix.close();
            } catch (IOException closeFailure) {
                failure.addSuppressed(closeFailure);
            }
            try {
                value.close();
            } catch (IOException closeFailure) {
                failure.addSuppressed(closeFailure);
            }
            return failure;
        }

        private void verifyNoExcess() throws IOException {
            if (!exactLengthVerified) {
                cancellation.throwIfCancelled();
                if (value.read() >= 0) {
                    throw new IOException("Metadata mutation value is longer than declared");
                }
                exactLengthVerified = true;
            }
        }

        private void requireOpen() {
            if (closed) {
                throw new IllegalStateException("Metadata mutation payload stream is closed");
            }
        }

        @Override
        public void close() throws IOException {
            if (!closed) {
                closed = true;
                prefix.close();
                if (value != null) {
                    value.close();
                }
            }
        }
    }
}
