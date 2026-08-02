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
import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.CharBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.MetadataStoreId;

/** Strict streaming codec for one immutable current-state checkpoint. */
final class RevocationCheckpointCodec {

    /* default */ static final int HEADER_BYTES = 128;
    /* default */ static final int TRAILER_BYTES = 48;
    /* default */ static final int DIGEST_BYTES = 32;
    /* default */ static final int MAX_COMPONENT_BYTES =
            RevocationTransitionFrameCodec.MAX_COMPONENT_BYTES;

    private static final int HEADER_MAGIC = 0x5A455243;
    private static final int RECORD_MAGIC = 0x5A455245;
    private static final int TRAILER_MAGIC = 0x5A455246;
    private static final short FORMAT_VERSION = 1;
    private static final short RESERVED_FLAGS = 0;
    private static final int STORE_ID_BYTES = 16;
    private static final int COMMITMENT_BYTES = 32;
    private static final int HEADER_FIELDS_BYTES = HEADER_BYTES - DIGEST_BYTES;
    private static final int TRAILER_FIELDS_BYTES = TRAILER_BYTES - DIGEST_BYTES;
    private static final int PRESENT = 1;
    private static final int ABSENT = 0;
    private static final long ZERO_REVISION = 0L;
    private static final int TRANSFER_BYTES = 16 * 1024;
    private static final byte[] RECORD_DOMAIN =
            "ZeroEcho revocation checkpoint record v1".getBytes(StandardCharsets.US_ASCII);
    private static final HexFormat HEX = HexFormat.of();

    /* default */ Encoder encoder(FileChannel channel, HeaderData header) throws IOException {
        return new Encoder(channel, header);
    }

    /* default */ ValidatedFile validate(FileChannel channel) throws IOException {
        return DecoderOperations.validate(channel);
    }

    /* default */ DecodedRecord readRecord(
            FileChannel channel, long recordOffset, long trailerOffset) throws IOException {
        return new SequentialDecoder().read(channel, recordOffset, trailerOffset);
    }

    /* default */ SequentialDecoder sequentialDecoder() {
        return new SequentialDecoder();
    }

    /** Structural validation is isolated to keep the codec facade cohesive. */
    private static final class DecoderOperations {
        private static ValidatedFile validate(FileChannel channel) throws IOException {
            Objects.requireNonNull(channel, "channel");
            try {
                long size = channel.size();
                if (size < HEADER_BYTES + TRAILER_BYTES) {
                    throw corrupt("Revocation checkpoint is truncated");
                }
                HeaderData header = decodeHeader(readAt(channel, 0L, HEADER_BYTES));
                long offset = HEADER_BYTES;
                byte[] previousIdentity = null;
                SequentialDecoder decoder = new SequentialDecoder();
                for (long index = 0L; index < header.entryCount(); index++) {
                    DecodedRecord decoded = decoder.read(channel, offset, size - TRAILER_BYTES);
                    byte[] identity = strictUtf8(decoded.entry().credentialId().value());
                    if (previousIdentity != null
                            && compareUnsigned(previousIdentity, identity) >= 0) {
                        throw corrupt("Revocation checkpoint identities are not canonical");
                    }
                    previousIdentity = identity;
                    offset = decoded.nextOffset();
                }
                Trailer trailer = decodeTrailer(readAt(channel, offset, TRAILER_BYTES));
                long expectedEnd = addExact(
                        offset, TRAILER_BYTES, "Revocation checkpoint boundary overflow");
                if (expectedEnd != size || trailer.entryCount() != header.entryCount()) {
                    throw corrupt("Revocation checkpoint framing is inconsistent");
                }
                byte[] calculated = digestPrefix(channel, size - DIGEST_BYTES);
                if (!MessageDigest.isEqual(calculated, trailer.commitment())) {
                    throw corrupt("Revocation checkpoint commitment is invalid");
                }
                return new ValidatedFile(header, HEX.formatHex(calculated), offset);
            } catch (IllegalArgumentException | DateTimeException malformed) {
                throw corrupt("Revocation checkpoint contains malformed semantic data", malformed);
            }
        }

        private static HeaderData decodeHeader(byte[] bytes) throws IOException {
            ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
            if (buffer.getInt() != HEADER_MAGIC) {
                throw corrupt("Revocation checkpoint header magic is invalid");
            }
            byte[] suppliedDigest = java.util.Arrays.copyOfRange(
                    bytes, HEADER_FIELDS_BYTES, HEADER_BYTES);
            MessageDigest digest = sha256();
            digest.update(bytes, 0, HEADER_FIELDS_BYTES);
            if (!MessageDigest.isEqual(digest.digest(), suppliedDigest)) {
                throw corrupt("Revocation checkpoint header authentication failed");
            }
            short version = buffer.getShort();
            short flags = buffer.getShort();
            byte[] store = new byte[STORE_ID_BYTES];
            buffer.get(store);
            long revision = buffer.getLong();
            int startPresent = Byte.toUnsignedInt(buffer.get());
            byte[] reserved = new byte[7];
            buffer.get(reserved);
            long start = buffer.getLong();
            long boundary = buffer.getLong();
            byte[] commitment = new byte[COMMITMENT_BYTES];
            buffer.get(commitment);
            long count = buffer.getLong();
            if (version != FORMAT_VERSION || flags != RESERVED_FLAGS || !allZero(reserved)
                    || count < 0L || revision < 0L) {
                throw corrupt("Revocation checkpoint header fields are unsupported");
            }
            OptionalLong finalStart = decodeStart(revision, startPresent, start);
            MetadataStoreId storeId = new MetadataStoreId(HEX.formatHex(store));
            RevocationTransitionFrameCodec.Commitment chain =
                    new RevocationTransitionFrameCodec.Commitment(HEX.formatHex(commitment));
            HeaderData header = new HeaderData(
                    storeId, revision, finalStart, boundary, chain, count);
            requireHeader(header);
            return header;
        }

        private static OptionalLong decodeStart(long revision, int present, long value)
                throws IOException {
            if (present == ABSENT && revision == ZERO_REVISION && value == ZERO_REVISION) {
                return OptionalLong.empty();
            }
            if (present == PRESENT && revision > ZERO_REVISION) {
                return OptionalLong.of(value);
            }
            throw corrupt("Revocation checkpoint final-record presence is invalid");
        }

        private static DecodedRecord decodeRecord(
                FileChannel channel,
                long offset,
                long trailerOffset,
                ByteBuffer input) throws IOException {
            if (offset < HEADER_BYTES || trailerOffset < offset) {
                throw corrupt("Revocation checkpoint record boundary is invalid");
            }
            byte[] prefix = readAt(channel, offset, Integer.BYTES + Long.BYTES);
            ByteBuffer framing = ByteBuffer.wrap(prefix).order(ByteOrder.BIG_ENDIAN);
            if (framing.getInt() != RECORD_MAGIC) {
                throw corrupt("Revocation checkpoint record magic is invalid");
            }
            long payloadLength = framing.getLong();
            if (payloadLength < ZERO_REVISION) {
                throw corrupt("Revocation checkpoint record length is invalid");
            }
            long payloadStart = addExact(
                    offset, prefix.length, "Revocation checkpoint record boundary overflow");
            long digestOffset = addExact(
                    payloadStart, payloadLength, "Revocation checkpoint record boundary overflow");
            long nextOffset = addExact(
                    digestOffset, DIGEST_BYTES, "Revocation checkpoint record boundary overflow");
            if (nextOffset > trailerOffset) {
                throw corrupt("Revocation checkpoint record exceeds its bounded region");
            }
            MessageDigest digest = sha256();
            digest.update(RECORD_DOMAIN);
            digest.update(prefix);
            RecordReader reader = new RecordReader(
                    channel, payloadStart, payloadLength, digest, input);
            CurrentStateEntry entry;
            try {
                entry = reader.readEntry();
            } catch (IllegalArgumentException | DateTimeException malformed) {
                throw corrupt("Revocation checkpoint record is malformed", malformed);
            }
            if (reader.remaining() != ZERO_REVISION) {
                throw corrupt("Revocation checkpoint record contains trailing data");
            }
            byte[] supplied = readAt(channel, digestOffset, DIGEST_BYTES);
            if (!MessageDigest.isEqual(digest.digest(), supplied)) {
                throw corrupt("Revocation checkpoint record commitment is invalid");
            }
            return new DecodedRecord(entry, nextOffset);
        }

        private static Trailer decodeTrailer(byte[] bytes) throws IOException {
            ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
            long count = buffer.getLong();
            int magic = buffer.getInt();
            short version = buffer.getShort();
            short flags = buffer.getShort();
            byte[] commitment = new byte[DIGEST_BYTES];
            buffer.get(commitment);
            if (count < 0L || magic != TRAILER_MAGIC || version != FORMAT_VERSION
                    || flags != RESERVED_FLAGS) {
                throw corrupt("Revocation checkpoint trailer is invalid");
            }
            return new Trailer(count, commitment);
        }
    }

    /** Reuses one bounded transfer buffer across a sequential record pass. */
    /* default */ static final class SequentialDecoder {
        private final ByteBuffer input = ByteBuffer.allocate(TRANSFER_BYTES);

        /* default */ DecodedRecord read(
                FileChannel channel, long recordOffset, long trailerOffset) throws IOException {
            return DecoderOperations.decodeRecord(channel, recordOffset, trailerOffset, input);
        }
    }

    private static byte[] encodeHeader(HeaderData header) throws IOException {
        requireHeader(header);
        ByteBuffer buffer = ByteBuffer.allocate(HEADER_BYTES).order(ByteOrder.BIG_ENDIAN);
        buffer.putInt(HEADER_MAGIC);
        buffer.putShort(FORMAT_VERSION);
        buffer.putShort(RESERVED_FLAGS);
        buffer.put(HEX.parseHex(header.storeId().value()));
        buffer.putLong(header.coveredRevision());
        if (header.finalRecordStart().isPresent()) {
            buffer.put((byte) PRESENT);
            buffer.put(new byte[7]);
            buffer.putLong(header.finalRecordStart().getAsLong());
        } else {
            buffer.put((byte) ABSENT);
            buffer.put(new byte[7]);
            buffer.putLong(0L);
        }
        buffer.putLong(header.coveredBoundary());
        buffer.put(HEX.parseHex(header.globalCommitment().value()));
        buffer.putLong(header.entryCount());
        MessageDigest digest = sha256();
        digest.update(buffer.array(), 0, HEADER_FIELDS_BYTES);
        buffer.put(digest.digest());
        return buffer.array();
    }

    private static void requireHeader(HeaderData header) {
        Objects.requireNonNull(header, "header");
        if (header.coveredRevision() < 0L || header.entryCount() < 0L
                || header.coveredBoundary() < RevocationTransitionFrameCodec.PREAMBLE_BYTES) {
            throw new IllegalArgumentException("Invalid revocation checkpoint header values");
        }
        if (header.coveredRevision() == 0L != header.finalRecordStart().isEmpty()) {
            throw new IllegalArgumentException("Checkpoint revision and final record disagree");
        }
        if (header.coveredRevision() == ZERO_REVISION
                && (header.entryCount() != ZERO_REVISION
                || header.coveredBoundary() != RevocationTransitionFrameCodec.PREAMBLE_BYTES
                || !header.globalCommitment().equals(
                        RevocationTransitionFrameCodec.initialCommitment(header.storeId())))) {
            throw new IllegalArgumentException("Checkpoint genesis framing is invalid");
        }
        if (header.finalRecordStart().isPresent()
                && (header.finalRecordStart().getAsLong() < RevocationTransitionFrameCodec.PREAMBLE_BYTES
                || header.finalRecordStart().getAsLong() >= header.coveredBoundary())) {
            throw new IllegalArgumentException("Invalid covered revocation frame start");
        }
    }

    private static byte[] digestPrefix(FileChannel channel, long length) throws IOException {
        MessageDigest digest = sha256();
        byte[] bytes = new byte[TRANSFER_BYTES];
        long offset = 0L;
        while (offset < length) {
            int request = (int) Math.min(bytes.length, length - offset);
            ByteBuffer target = ByteBuffer.wrap(bytes, 0, request);
            readFullyAt(channel, target, offset);
            digest.update(bytes, 0, request);
            offset += request;
        }
        return digest.digest();
    }

    private static byte[] readAt(FileChannel channel, long offset, int length) throws IOException {
        if (offset < 0L || length < 0) {
            throw corrupt("Revocation checkpoint read boundary is invalid");
        }
        byte[] bytes = new byte[length];
        readFullyAt(channel, ByteBuffer.wrap(bytes), offset);
        return bytes;
    }

    private static void readFullyAt(FileChannel channel, ByteBuffer target, long offset) throws IOException {
        long position = offset;
        while (target.hasRemaining()) {
            int read = channel.read(target, position);
            if (read < 0) {
                throw corrupt("Revocation checkpoint is truncated");
            }
            if (read == 0) {
                throw new IOException("Revocation checkpoint channel made no read progress");
            }
            position += read;
        }
    }

    private static void writeFully(FileChannel channel, ByteBuffer source) throws IOException {
        while (source.hasRemaining()) {
            if (channel.write(source) == 0) {
                throw new IOException("Revocation checkpoint channel made no write progress");
            }
        }
    }

    private static long addExact(long first, long second, String message) throws IOException {
        try {
            return Math.addExact(first, second);
        } catch (ArithmeticException overflow) {
            throw new IOException(message, overflow);
        }
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 is unavailable", unavailable);
        }
    }

    private static boolean allZero(byte[] bytes) {
        for (byte value : bytes) {
            if (value != 0) {
                return false;
            }
        }
        return true;
    }

    /* default */ static byte[] strictUtf8(String value) {
        Objects.requireNonNull(value, "value");
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(value));
            if (encoded.remaining() > MAX_COMPONENT_BYTES) {
                throw new IllegalArgumentException("Checkpoint component exceeds its technical limit");
            }
            byte[] bytes = new byte[encoded.remaining()];
            encoded.get(bytes);
            return bytes;
        } catch (CharacterCodingException malformed) {
            throw new IllegalArgumentException("Checkpoint text is not valid Unicode", malformed);
        }
    }

    private static String decodeUtf8(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException malformed) {
            throw new IllegalArgumentException("Checkpoint contains malformed UTF-8", malformed);
        }
    }

    /* default */ static int compareUnsigned(byte[] first, byte[] second) {
        int common = Math.min(first.length, second.length);
        for (int index = 0; index < common; index++) {
            int difference = Byte.toUnsignedInt(first[index]) - Byte.toUnsignedInt(second[index]);
            if (difference != 0) {
                return difference;
            }
        }
        return first.length - second.length;
    }

    private static IOException corrupt(String message) {
        return new IOException(message);
    }

    private static IOException corrupt(String message, Throwable cause) {
        return new IOException(message, cause);
    }

    /** Streaming encoder retaining only one current-state entry. */
    /* default */ static final class Encoder {
        private final FileChannel channel;
        private final HeaderData header;
        private final DigestOutputStream wholeDigest = digestStream();
        private long count;
        private boolean finished;

        private Encoder(FileChannel channel, HeaderData header) throws IOException {
            this.channel = Objects.requireNonNull(channel, "channel");
            this.header = Objects.requireNonNull(header, "header");
            channel.position(0L);
            channel.truncate(0L);
            writeCommitted(encodeHeader(header));
        }

        /* default */ void write(CurrentStateEntry entry) throws IOException {
            if (finished) {
                throw new IllegalStateException("Checkpoint encoder is finished");
            }
            EntryPlan plan = EntryPlan.create(entry);
            ByteBuffer framing = ByteBuffer.allocate(Integer.BYTES + Long.BYTES)
                    .order(ByteOrder.BIG_ENDIAN);
            framing.putInt(RECORD_MAGIC).putLong(plan.length()).flip();
            byte[] prefix = new byte[framing.remaining()];
            framing.get(prefix);
            try (DigestOutputStream recordDigest = digestStream()) {
                recordDigest.write(RECORD_DOMAIN);
                recordDigest.write(prefix);
                writeCommitted(prefix);
                FieldWriter writer = new FieldWriter(channel, wholeDigest, recordDigest);
                plan.write(writer, entry);
                writeCommitted(recordDigest.getMessageDigest().digest());
            }
            try {
                count = Math.addExact(count, 1L);
            } catch (ArithmeticException overflow) {
                throw new IOException("Checkpoint entry count is exhausted", overflow);
            }
        }

        /* default */ String finish() throws IOException {
            if (finished) {
                throw new IllegalStateException("Checkpoint encoder is finished");
            }
            if (count != header.entryCount()) {
                throw new IOException("Checkpoint source count does not match its declaration");
            }
            ByteBuffer fields = ByteBuffer.allocate(TRAILER_FIELDS_BYTES).order(ByteOrder.BIG_ENDIAN);
            fields.putLong(count).putInt(TRAILER_MAGIC)
                    .putShort(FORMAT_VERSION).putShort(RESERVED_FLAGS);
            writeCommitted(fields.array());
            byte[] generation = wholeDigest.getMessageDigest().digest();
            writeFully(channel, ByteBuffer.wrap(generation));
            finished = true;
            return HEX.formatHex(generation);
        }

        private void writeCommitted(byte[] bytes) throws IOException {
            wholeDigest.write(bytes);
            writeFully(channel, ByteBuffer.wrap(bytes));
        }
    }

    /** Authenticated checkpoint identity and covered authoritative log position. */
    /* default */ record HeaderData(
            MetadataStoreId storeId,
            long coveredRevision,
            OptionalLong finalRecordStart,
            long coveredBoundary,
            RevocationTransitionFrameCodec.Commitment globalCommitment,
            long entryCount) {
        HeaderData {
            Objects.requireNonNull(storeId, "storeId");
            Objects.requireNonNull(finalRecordStart, "finalRecordStart");
            Objects.requireNonNull(globalCommitment, "globalCommitment");
        }
    }

    /** One finite latest state and its authoritative frame locator. */
    /* default */ record CurrentStateEntry(
            PkiId credentialId,
            long globalRevision,
            long credentialRevision,
            RevocationTransitionFrameCodec.Commitment transitionCommitment,
            RevocationTransition transition,
            long frameStart,
            long frameEnd) {
        CurrentStateEntry {
            Objects.requireNonNull(credentialId, "credentialId");
            Objects.requireNonNull(transitionCommitment, "transitionCommitment");
            Objects.requireNonNull(transition, "transition");
            if (globalRevision <= 0L || credentialRevision <= 0L
                    || transition.revision() != credentialRevision
                    || frameStart < RevocationTransitionFrameCodec.PREAMBLE_BYTES
                    || frameEnd <= frameStart) {
                throw new IllegalArgumentException("Invalid revocation checkpoint entry");
            }
        }
    }

    /** Fully validated checkpoint framing used by immutable readers. */
    /* default */ record ValidatedFile(HeaderData header, String generationId, long trailerOffset) {
        ValidatedFile {
            Objects.requireNonNull(header, "header");
            Objects.requireNonNull(generationId, "generationId");
        }
    }

    /** One decoded record plus the next sequential offset. */
    /* default */ record DecodedRecord(CurrentStateEntry entry, long nextOffset) {
        DecodedRecord {
            Objects.requireNonNull(entry, "entry");
        }
    }

    private record Trailer(long entryCount, byte[] commitment) {
        private Trailer {
            commitment = commitment.clone();
        }
    }

    /** Canonical per-entry plan, bounded by one current state. */
    private record EntryPlan(long length, List<PlannedAttribute> attributes) {
        private static EntryPlan create(CurrentStateEntry entry) throws IOException {
            Objects.requireNonNull(entry, "entry");
            List<PlannedAttribute> attributes = capture(entry.transition().attributes());
            attributes.sort((first, second) -> compareUnsigned(first.id(), second.id()));
            long length = Short.BYTES * 2L;
            length = addComponent(length, strictUtf8(entry.credentialId().value()).length);
            length = add(length, Long.BYTES * 2L + COMMITMENT_BYTES);
            length = add(length, 1L + 1L + Short.BYTES + Long.BYTES + Integer.BYTES);
            length = add(length, Integer.BYTES);
            for (PlannedAttribute attribute : attributes) {
                length = addComponent(length, attribute.id().length);
                length = add(length, Integer.BYTES);
                for (AttributeValue value : attribute.values()) {
                    length = add(length, valueLength(value));
                }
            }
            length = add(length, Long.BYTES * 2L);
            return new EntryPlan(length, List.copyOf(attributes));
        }

        private static List<PlannedAttribute> capture(AttributeSet set) {
            List<PlannedAttribute> result = new ArrayList<>();
            for (AttributeId id : set.ids()) {
                result.add(new PlannedAttribute(strictUtf8(id.value()), List.copyOf(set.getAll(id))));
            }
            return result;
        }

        private void write(FieldWriter writer, CurrentStateEntry entry) throws IOException {
            writer.writeShort(FORMAT_VERSION);
            writer.writeShort(RESERVED_FLAGS);
            writer.writeComponent(strictUtf8(entry.credentialId().value()));
            writer.writeLong(entry.globalRevision());
            writer.writeLong(entry.credentialRevision());
            writer.writeBytes(HEX.parseHex(entry.transitionCommitment().value()));
            writer.writeByte(encodeState(entry.transition().state()));
            writer.writeByte(encodeReason(entry.transition().permanentReason()));
            writer.writeShort(RESERVED_FLAGS);
            writer.writeLong(entry.transition().time().getEpochSecond());
            writer.writeInt(entry.transition().time().getNano());
            writer.writeInt(attributes.size());
            for (PlannedAttribute attribute : attributes) {
                writer.writeComponent(attribute.id());
                writer.writeInt(attribute.values().size());
                for (AttributeValue value : attribute.values()) {
                    writeValue(writer, value);
                }
            }
            writer.writeLong(entry.frameStart());
            writer.writeLong(entry.frameEnd());
        }

        private static long valueLength(AttributeValue value) throws IOException {
            Objects.requireNonNull(value, "attribute value");
            return switch (value) {
                case AttributeValue.StringValue string ->
                    addComponent(1L, strictUtf8(string.value()).length);
                case AttributeValue.BooleanValue ignored -> 2L;
                case AttributeValue.IntegerValue ignored -> 1L + Long.BYTES;
                case AttributeValue.InstantValue ignored -> 1L + Long.BYTES + Integer.BYTES;
                case AttributeValue.BytesValue bytes -> addComponent(1L, bytes.value().length);
            };
        }

        private static void writeValue(FieldWriter writer, AttributeValue value) throws IOException {
            switch (value) {
                case AttributeValue.StringValue string -> {
                    writer.writeByte(1);
                    writer.writeComponent(strictUtf8(string.value()));
                }
                case AttributeValue.BooleanValue bool -> {
                    writer.writeByte(2);
                    writer.writeByte(bool.value() ? 1 : 0);
                }
                case AttributeValue.IntegerValue integer -> {
                    writer.writeByte(3);
                    writer.writeLong(integer.value());
                }
                case AttributeValue.InstantValue instant -> {
                    writer.writeByte(4);
                    writer.writeLong(instant.value().getEpochSecond());
                    writer.writeInt(instant.value().getNano());
                }
                case AttributeValue.BytesValue bytes -> {
                    writer.writeByte(5);
                    writer.writeComponent(bytes.value());
                }
            }
        }

        private static long addComponent(long current, int length) throws IOException {
            requireComponent(length);
            return add(current, Integer.BYTES + (long) length);
        }

        private static long add(long first, long second) throws IOException {
            return addExact(first, second, "Revocation checkpoint record is too large");
        }
    }

    private record PlannedAttribute(byte[] id, List<AttributeValue> values) {
        private PlannedAttribute {
            id = id.clone();
            values = List.copyOf(values);
        }
    }

    /** Writes primitive fields to the channel and both incremental commitments. */
    private static final class FieldWriter {
        private final FileChannel channel;
        private final DigestOutputStream whole;
        private final DigestOutputStream record;
        private final ByteBuffer primitive = ByteBuffer.allocate(Long.BYTES).order(ByteOrder.BIG_ENDIAN);

        private FieldWriter(
                FileChannel channel, DigestOutputStream whole, DigestOutputStream record) {
            this.channel = channel;
            this.whole = whole;
            this.record = record;
        }

        private void writeByte(int value) throws IOException {
            primitive(1, buffer -> buffer.put((byte) value));
        }

        private void writeShort(int value) throws IOException {
            primitive(Short.BYTES, buffer -> buffer.putShort((short) value));
        }

        private void writeInt(int value) throws IOException {
            primitive(Integer.BYTES, buffer -> buffer.putInt(value));
        }

        private void writeLong(long value) throws IOException {
            primitive(Long.BYTES, buffer -> buffer.putLong(value));
        }

        private void writeComponent(byte[] bytes) throws IOException {
            requireComponent(bytes.length);
            writeInt(bytes.length);
            writeBytes(bytes);
        }

        private void primitive(int length, PrimitiveEncoder encoder) throws IOException {
            primitive.clear();
            encoder.encode(primitive);
            primitive.flip();
            primitive.limit(length);
            byte[] bytes = new byte[length];
            primitive.get(bytes);
            writeBytes(bytes);
        }

        private void writeBytes(byte[] bytes) throws IOException {
            whole.write(bytes);
            record.write(bytes);
            writeFully(channel, ByteBuffer.wrap(bytes));
        }
    }

    /** Bounded positional reader for one authenticated record payload. */
    private static final class RecordReader {
        private final FileChannel channel;
        private final DigestOutputStream digest;
        private final ByteBuffer input;
        private long sourcePosition;
        private long remaining;

        private RecordReader(
                FileChannel channel,
                long position,
                long remaining,
                MessageDigest digest,
                ByteBuffer input) {
            this.channel = channel;
            sourcePosition = position;
            this.remaining = remaining;
            this.digest = new DigestOutputStream(OutputStream.nullOutputStream(), digest);
            this.input = input;
            this.input.clear();
            this.input.limit(0);
        }

        private long remaining() {
            return remaining;
        }

        private CurrentStateEntry readEntry() throws IOException {
            if (readShort() != FORMAT_VERSION || readShort() != RESERVED_FLAGS) {
                throw new IllegalArgumentException("Unsupported checkpoint record version");
            }
            PkiId credential = new PkiId(readString());
            long globalRevision = readLong();
            long localRevision = readLong();
            RevocationTransitionFrameCodec.Commitment commitment =
                    new RevocationTransitionFrameCodec.Commitment(HEX.formatHex(readBytes(COMMITMENT_BYTES)));
            RevocationState state = decodeState(readUnsignedByte());
            Optional<RevocationReason> reason = decodeReason(readUnsignedByte());
            if (readShort() != RESERVED_FLAGS) {
                throw new IllegalArgumentException("Invalid checkpoint record reserved field");
            }
            Instant time = Instant.ofEpochSecond(readLong(), readInt());
            AttributeSet attributes = readAttributes();
            long start = readLong();
            long end = readLong();
            RevocationTransition transition =
                    new RevocationTransition(localRevision, state, time, reason, attributes);
            return new CurrentStateEntry(
                    credential, globalRevision, localRevision, commitment, transition, start, end);
        }

        private AttributeSet readAttributes() throws IOException {
            int count = readCount();
            List<SimpleAttributeSet.Entry> entries = new ArrayList<>(count);
            byte[] previous = null;
            for (int index = 0; index < count; index++) {
                byte[] encodedId = readComponent();
                if (previous != null && compareUnsigned(previous, encodedId) >= 0) {
                    throw new IllegalArgumentException("Checkpoint attributes are not canonical");
                }
                entries.add(readAttributeEntry(encodedId));
                previous = encodedId;
            }
            return new SimpleAttributeSet(entries);
        }

        private SimpleAttributeSet.Entry readAttributeEntry(byte[] encodedId) throws IOException {
            AttributeId id = new AttributeId(decodeUtf8(encodedId));
            int valueCount = readCount();
            return new SimpleAttributeSet.Entry(id, readAttributeValues(valueCount));
        }

        private List<AttributeValue> readAttributeValues(int valueCount) throws IOException {
            List<AttributeValue> values = new ArrayList<>(valueCount);
            for (int valueIndex = 0; valueIndex < valueCount; valueIndex++) {
                values.add(readValue());
            }
            return values;
        }

        private AttributeValue readValue() throws IOException {
            return switch (readUnsignedByte()) {
                case 1 -> new AttributeValue.StringValue(readString());
                case 2 -> new AttributeValue.BooleanValue(readBoolean());
                case 3 -> new AttributeValue.IntegerValue(readLong());
                case 4 -> new AttributeValue.InstantValue(Instant.ofEpochSecond(readLong(), readInt()));
                case 5 -> new AttributeValue.BytesValue(readComponent());
                default -> throw new IllegalArgumentException("Unknown checkpoint attribute value code");
            };
        }

        private String readString() throws IOException {
            return decodeUtf8(readComponent());
        }

        private byte[] readComponent() throws IOException {
            int length = readInt();
            requireComponent(length);
            return readBytes(length);
        }

        private int readCount() throws IOException {
            int count = readInt();
            requireComponent(count);
            return count;
        }

        private boolean readBoolean() throws IOException {
            int code = readUnsignedByte();
            if (code != 0 && code != 1) {
                throw new IllegalArgumentException("Invalid checkpoint boolean code");
            }
            return code == 1;
        }

        private int readUnsignedByte() throws IOException {
            return Byte.toUnsignedInt(readByte());
        }

        private short readShort() throws IOException {
            return (short) (readUnsignedByte() << Byte.SIZE | readUnsignedByte());
        }

        private int readInt() throws IOException {
            return readUnsignedByte() << 24
                    | readUnsignedByte() << 16
                    | readUnsignedByte() << 8
                    | readUnsignedByte();
        }

        private long readLong() throws IOException {
            return (long) readUnsignedByte() << 56
                    | (long) readUnsignedByte() << 48
                    | (long) readUnsignedByte() << 40
                    | (long) readUnsignedByte() << 32
                    | (long) readUnsignedByte() << 24
                    | (long) readUnsignedByte() << 16
                    | (long) readUnsignedByte() << 8
                    | readUnsignedByte();
        }

        private byte[] readBytes(int length) throws IOException {
            if (length < 0 || length > remaining) {
                throw new IllegalArgumentException("Checkpoint field exceeds its bounded record");
            }
            byte[] bytes = new byte[length];
            int offset = 0;
            while (offset < length) {
                requireInput();
                int count = Math.min(length - offset, input.remaining());
                input.get(bytes, offset, count);
                digest.write(bytes, offset, count);
                offset += count;
                remaining -= count;
            }
            return bytes;
        }

        private byte readByte() throws IOException {
            if (remaining == ZERO_REVISION) {
                throw new IllegalArgumentException("Checkpoint field exceeds its bounded record");
            }
            requireInput();
            byte value = input.get();
            digest.write(value);
            remaining--;
            return value;
        }

        private void requireInput() throws IOException {
            if (input.hasRemaining()) {
                return;
            }
            input.clear();
            input.limit((int) Math.min(input.capacity(), remaining));
            int read = channel.read(input, sourcePosition);
            if (read < 0) {
                throw corrupt("Revocation checkpoint is truncated");
            }
            if (read == 0) {
                throw new IOException("Revocation checkpoint channel made no read progress");
            }
            sourcePosition += read;
            input.flip();
        }
    }

    private static void requireComponent(int value) {
        if (value < 0 || value > MAX_COMPONENT_BYTES) {
            throw new IllegalArgumentException("Checkpoint component exceeds its technical limit");
        }
    }

    private static DigestOutputStream digestStream() {
        return new DigestOutputStream(OutputStream.nullOutputStream(), sha256());
    }

    private static int encodeState(RevocationState state) {
        return ValueCodes.encodeState(state);
    }

    private static RevocationState decodeState(int code) {
        return ValueCodes.decodeState(code);
    }

    private static int encodeReason(Optional<RevocationReason> reason) {
        return ValueCodes.encodeReason(reason);
    }

    private static Optional<RevocationReason> decodeReason(int code) {
        return ValueCodes.decodeReason(code);
    }

    /** Stable numeric codes are isolated from the surrounding framing logic. */
    private static final class ValueCodes {
        private static int encodeState(RevocationState state) {
            return switch (state) {
                case CLEAR -> 1;
                case HELD -> 2;
                case PERMANENTLY_REVOKED -> 3;
            };
        }

        private static RevocationState decodeState(int code) {
            return switch (code) {
                case 1 -> RevocationState.CLEAR;
                case 2 -> RevocationState.HELD;
                case 3 -> RevocationState.PERMANENTLY_REVOKED;
                default -> throw new IllegalArgumentException(
                        "Unknown checkpoint revocation state code");
            };
        }

        private static int encodeReason(Optional<RevocationReason> reason) {
            if (reason.isEmpty()) {
                return 0;
            }
            return switch (reason.orElseThrow()) {
                case UNSPECIFIED -> 1;
                case KEY_COMPROMISE -> 2;
                case CA_COMPROMISE -> 3;
                case AFFILIATION_CHANGED -> 4;
                case SUPERSEDED -> 5;
                case CESSATION_OF_OPERATION -> 6;
                case CERTIFICATE_HOLD -> 7;
                case REMOVE_FROM_CRL -> 8;
                case PRIVILEGE_WITHDRAWN -> 9;
                case AA_COMPROMISE -> 10;
            };
        }

        private static Optional<RevocationReason> decodeReason(int code) {
            return switch (code) {
                case 0 -> Optional.empty();
                case 1 -> Optional.of(RevocationReason.UNSPECIFIED);
                case 2 -> Optional.of(RevocationReason.KEY_COMPROMISE);
                case 3 -> Optional.of(RevocationReason.CA_COMPROMISE);
                case 4 -> Optional.of(RevocationReason.AFFILIATION_CHANGED);
                case 5 -> Optional.of(RevocationReason.SUPERSEDED);
                case 6 -> Optional.of(RevocationReason.CESSATION_OF_OPERATION);
                case 7 -> Optional.of(RevocationReason.CERTIFICATE_HOLD);
                case 8 -> Optional.of(RevocationReason.REMOVE_FROM_CRL);
                case 9 -> Optional.of(RevocationReason.PRIVILEGE_WITHDRAWN);
                case 10 -> Optional.of(RevocationReason.AA_COMPROMISE);
                default -> throw new IllegalArgumentException(
                        "Unknown checkpoint revocation reason code");
            };
        }
    }

    /** Encodes one fixed-width primitive into a reusable buffer. */
    @FunctionalInterface
    private interface PrimitiveEncoder {
        /** Writes one primitive value. */
        void encode(ByteBuffer buffer);
    }
}
