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
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.CharBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.DigestOutputStream;
import java.security.NoSuchAlgorithmException;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.spi.store.MetadataStoreId;

/** Strict bounded-memory codec for one authenticated revocation transition. */
final class RevocationTransitionFrameCodec {

    /* default */ static final int PREAMBLE_BYTES = 56;
    /* default */ static final int HEADER_BYTES = 88;
    /* default */ static final int COMMITMENT_BYTES = 32;
    /* default */ static final int MAX_COMPONENT_BYTES = 256 * 1024;
    /* default */ static final int READ_SCRATCH_BYTES = 16 * 1024;

    private static final int PREAMBLE_MAGIC = 0x5A455250;
    private static final int RECORD_MAGIC = 0x5A455254;
    private static final short STRUCTURAL_VERSION = 1;
    private static final short SEMANTIC_VERSION = 1;
    private static final short RESERVED_FLAGS = 0;
    private static final int PREAMBLE_FIELDS_BYTES = PREAMBLE_BYTES - COMMITMENT_BYTES;
    private static final int HEADER_FIELDS_BYTES = HEADER_BYTES - COMMITMENT_BYTES;
    private static final int STORE_ID_BYTES = 16;
    private static final long MINIMUM_GLOBAL_REVISION = 1L;
    private static final long NO_REMAINING_PAYLOAD = 0L;
    private static final int LINK_PRESENT = 1;
    private static final long FIRST_CREDENTIAL_REVISION = 1L;
    private static final int BOOLEAN_FALSE = 0;
    private static final int BOOLEAN_TRUE = 1;
    private static final byte[] RECORD_DOMAIN = "ZeroEcho revocation transition record v1"
            .getBytes(StandardCharsets.US_ASCII);
    private static final HexFormat LOWERCASE_HEX = HexFormat.of();
    private static final byte[] INITIAL_CHAIN_DOMAIN = "ZeroEcho revocation log initial chain v1"
            .getBytes(StandardCharsets.US_ASCII);

    /* default */ void writePreamble(SeekableByteChannel channel, MetadataStoreId storeId) throws IOException {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(storeId, "storeId");
        writeFully(channel, ByteBuffer.wrap(encodePreamble(storeId)));
    }

    private static byte[] encodePreamble(MetadataStoreId storeId) {
        byte[] rawStoreId = decodeStoreId(storeId);
        ByteBuffer preamble = ByteBuffer.allocate(PREAMBLE_BYTES).order(ByteOrder.BIG_ENDIAN);
        preamble.putInt(PREAMBLE_MAGIC);
        preamble.putShort(STRUCTURAL_VERSION);
        preamble.putShort(RESERVED_FLAGS);
        preamble.put(rawStoreId);
        MessageDigest digest = newSha256();
        digest.update(preamble.array(), 0, PREAMBLE_FIELDS_BYTES);
        preamble.put(digest.digest());
        return preamble.array();
    }

    /* default */ MetadataStoreId readPreamble(SeekableByteChannel channel) throws IOException {
        Objects.requireNonNull(channel, "channel");
        channel.position(0L);
        ByteBuffer preamble = ByteBuffer.allocate(PREAMBLE_BYTES).order(ByteOrder.BIG_ENDIAN);
        if (readAvailable(channel, preamble) != PREAMBLE_BYTES) {
            throw new IOException("Revocation log preamble is incomplete");
        }
        byte[] encoded = preamble.array();
        ByteBuffer fields = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
        if (fields.getInt() != PREAMBLE_MAGIC) {
            throw new IOException("Revocation log preamble is corrupt");
        }
        byte[] suppliedDigest = new byte[COMMITMENT_BYTES];
        System.arraycopy(encoded, PREAMBLE_FIELDS_BYTES, suppliedDigest, 0, COMMITMENT_BYTES);
        MessageDigest digest = newSha256();
        digest.update(encoded, 0, PREAMBLE_FIELDS_BYTES);
        if (!MessageDigest.isEqual(digest.digest(), suppliedDigest)) {
            throw new IOException("Revocation log preamble is corrupt");
        }
        short version = fields.getShort();
        short flags = fields.getShort();
        byte[] rawStoreId = new byte[STORE_ID_BYTES];
        fields.get(rawStoreId);
        if (version != STRUCTURAL_VERSION || flags != RESERVED_FLAGS) {
            throw new IOException("Revocation log preamble is unsupported");
        }
        return new MetadataStoreId(LOWERCASE_HEX.formatHex(rawStoreId));
    }

    /* default */ CompleteRecord write(SeekableByteChannel channel, TransitionData data) throws IOException {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(data, "data");
        requireTransitionData(data);
        PayloadPlan plan = PayloadPlan.create(data);
        long recordOffset = channel.position();
        long recordEnd = checkedRecordEnd(recordOffset, plan.length());
        byte[] header = encodeHeader(data, plan.length());
        MessageDigest recordDigest = newSha256();
        recordDigest.update(RECORD_DOMAIN);
        recordDigest.update(header);
        writeFully(channel, ByteBuffer.wrap(header));
        DigestingWriter writer = new DigestingWriter(channel, recordDigest);
        plan.write(writer, data);
        Commitment commitment = new Commitment(LOWERCASE_HEX.formatHex(recordDigest.digest()));
        writeFully(channel, ByteBuffer.wrap(commitment.bytes()));
        return new CompleteRecord(data, recordOffset, recordEnd, commitment);
    }

    /* default */ ReadResult read(SeekableByteChannel channel, long recordOffset) throws IOException {
        try (DecodeScratch scratch = new DecodeScratch()) {
            return read(channel, recordOffset, scratch);
        }
    }

    /** Reads one frame with caller-owned, exclusively used decode scratch. */
    /* default */ ReadResult read(SeekableByteChannel channel, long recordOffset, DecodeScratch scratch)
            throws IOException {
        Objects.requireNonNull(scratch, "scratch");
        byte[] transfer = scratch.acquire();
        try {
            return WireOperations.read(channel, recordOffset, transfer);
        } finally {
            scratch.release();
        }
    }

    private static TransitionData decodePayload(Header header, BoundedReader reader) throws IOException {
        return SemanticOperations.decodePayload(header, reader);
    }

    private static byte[] encodeHeader(TransitionData data, long payloadLength) {
        ByteBuffer header = ByteBuffer.allocate(HEADER_BYTES).order(ByteOrder.BIG_ENDIAN);
        header.putInt(RECORD_MAGIC);
        header.putShort(STRUCTURAL_VERSION);
        header.putShort(RESERVED_FLAGS);
        header.putLong(data.globalRevision());
        header.put(data.previousGlobalCommitment().bytes());
        header.putLong(payloadLength);
        MessageDigest digest = newSha256();
        digest.update(header.array(), 0, HEADER_FIELDS_BYTES);
        header.put(digest.digest());
        return header.array();
    }

    private static long checkedRecordEnd(long offset, long payloadLength) throws IOException {
        try {
            return Math.addExact(Math.addExact(offset, HEADER_BYTES),
                    Math.addExact(payloadLength, COMMITMENT_BYTES));
        } catch (ArithmeticException overflow) {
            throw new IOException("Revocation record boundaries exceed the supported range", overflow);
        }
    }

    private static void requireTransitionData(TransitionData data) {
        SemanticOperations.requireTransitionData(data);
    }

    private static byte[] decodeStoreId(MetadataStoreId storeId) {
        return LOWERCASE_HEX.parseHex(storeId.value());
    }

    private static byte[] encodeUtf8(String value) {
        return SemanticOperations.encodeUtf8(value);
    }

    private static String decodeStrictUtf8(byte[] encoded) {
        return SemanticOperations.decodeStrictUtf8(encoded);
    }

    private static int compareUnsigned(byte[] first, byte[] second) {
        return SemanticOperations.compareUnsigned(first, second);
    }

    private static MessageDigest newSha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 is unavailable", unavailable);
        }
    }

    /* default */ static Commitment initialCommitment(MetadataStoreId storeId) {
        Objects.requireNonNull(storeId, "storeId");
        MessageDigest digest = newSha256();
        digest.update(INITIAL_CHAIN_DOMAIN);
        digest.update(encodePreamble(storeId));
        return new Commitment(LOWERCASE_HEX.formatHex(digest.digest()));
    }

    private static int readAvailable(SeekableByteChannel channel, ByteBuffer destination) throws IOException {
        int total = 0;
        while (destination.hasRemaining()) {
            int read = channel.read(destination);
            if (read < 0) {
                return total;
            }
            if (read == 0) {
                throw new IOException("Revocation log channel made no read progress");
            }
            total += read;
        }
        return total;
    }

    private static void readFully(SeekableByteChannel channel, ByteBuffer destination) throws IOException {
        if (readAvailable(channel, destination) != destination.capacity()) {
            throw new IOException("Revocation record changed during bounded decoding");
        }
    }

    private static void writeFully(SeekableByteChannel channel, ByteBuffer source) throws IOException {
        while (source.hasRemaining()) {
            if (channel.write(source) == 0) {
                throw new IOException("Revocation log channel made no write progress");
            }
        }
    }

    /** Immutable lowercase hexadecimal SHA-256 commitment. */
    /* default */ record Commitment(String value) {
        Commitment {
            Objects.requireNonNull(value, "value");
            if (!value.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Revocation commitment must be canonical SHA-256 hexadecimal");
            }
        }

        private byte[] bytes() {
            return LOWERCASE_HEX.parseHex(value);
        }

    }

    /** Finite semantic input for one transition record. */
    /* default */ @SuppressWarnings("PMD.LongVariable")
    record TransitionData(
            long globalRevision,
            Commitment previousGlobalCommitment,
            PkiId credentialId,
            OptionalLong previousCredentialGlobalRevision,
            Optional<Commitment> previousCredentialCommitment,
            RevocationTransition transition) {
        TransitionData {
            Objects.requireNonNull(previousGlobalCommitment, "previousGlobalCommitment");
            Objects.requireNonNull(credentialId, "credentialId");
            Objects.requireNonNull(previousCredentialGlobalRevision, "previousCredentialGlobalRevision");
            Objects.requireNonNull(previousCredentialCommitment, "previousCredentialCommitment");
            Objects.requireNonNull(transition, "transition");
        }

        @Override
        public boolean equals(Object candidate) {
            if (this == candidate) {
                return true;
            }
            if (!(candidate instanceof TransitionData other)) {
                return false;
            }
            return globalRevision == other.globalRevision
                    && previousGlobalCommitment.equals(other.previousGlobalCommitment)
                    && credentialId.equals(other.credentialId)
                    && previousCredentialGlobalRevision.equals(other.previousCredentialGlobalRevision)
                    && previousCredentialCommitment.equals(other.previousCredentialCommitment)
                    && transitionsEqual(transition, other.transition);
        }

        @Override
        public int hashCode() {
            return Objects.hash(globalRevision, previousGlobalCommitment, credentialId,
                    previousCredentialGlobalRevision, previousCredentialCommitment,
                    transitionHash(transition));
        }
    }

    /** One fully authenticated record and its durable byte boundaries. */
    /* default */ record CompleteRecord(
            TransitionData data, long recordOffset, long recordEnd, Commitment commitment) {
        CompleteRecord {
            Objects.requireNonNull(data, "data");
            Objects.requireNonNull(commitment, "commitment");
            if (recordOffset < PREAMBLE_BYTES || recordEnd <= recordOffset) {
                throw new IllegalArgumentException("Invalid revocation record boundaries");
            }
        }
    }

    /** Structural scanner classifications independent of semantic log ordering. */
    /* default */ enum Classification {
        END_OF_INPUT,
        INCOMPLETE_TAIL,
        COMPLETE_RECORD,
        CORRUPT_RECORD
    }

    /** Strict structural result containing a record only for complete input. */
    /* default */ record ReadResult(Classification classification, Optional<CompleteRecord> record) {
        ReadResult {
            Objects.requireNonNull(classification, "classification");
            Objects.requireNonNull(record, "record");
            if (classification == Classification.COMPLETE_RECORD != record.isPresent()) {
                throw new IllegalArgumentException("Revocation frame result and record presence disagree");
            }
        }

        private static ReadResult endOfInput() {
            return new ReadResult(Classification.END_OF_INPUT, Optional.empty());
        }

        private static ReadResult incompleteTail() {
            return new ReadResult(Classification.INCOMPLETE_TAIL, Optional.empty());
        }

        private static ReadResult corruptRecord() {
            return new ReadResult(Classification.CORRUPT_RECORD, Optional.empty());
        }

        private static ReadResult completeRecord(CompleteRecord record) {
            return new ReadResult(Classification.COMPLETE_RECORD, Optional.of(record));
        }
    }

    /** Authenticated fixed-header fields trusted before any payload positioning. */
    private record Header(long globalRevision, Commitment previousGlobalCommitment, long payloadLength) {
    }

    /** One canonical attribute captured once before any record byte is written. */
    private record PlannedAttribute(byte[] encodedId, List<AttributeValue> values) {
        private PlannedAttribute {
            Objects.requireNonNull(encodedId, "encodedId");
            Objects.requireNonNull(values, "values");
            values = List.copyOf(values);
        }
    }

    /** Bounded canonical payload plan; it retains finite values, never encoded record chunks. */
    private record PayloadPlan(long length, List<PlannedAttribute> attributes) {
        private static PayloadPlan create(TransitionData data) throws IOException {
            List<PlannedAttribute> attributes = captureAttributes(data.transition().attributes());
            attributes.sort((first, second) -> compareUnsigned(first.encodedId(), second.encodedId()));
            requireCount(attributes.size());
            long length = 2L + 2L;
            length = addComponent(length, encodeUtf8(data.credentialId().value()).length);
            length = add(length, Long.BYTES + 1L);
            if (data.previousCredentialGlobalRevision().isPresent()) {
                length = add(length, Long.BYTES + COMMITMENT_BYTES);
            }
            length = add(length, Long.BYTES + Integer.BYTES + 1L + 1L + Short.BYTES + Integer.BYTES);
            for (PlannedAttribute attribute : attributes) {
                length = addComponent(length, attribute.encodedId().length);
                List<AttributeValue> values = attribute.values();
                length = add(length, Integer.BYTES);
                for (AttributeValue value : values) {
                    length = add(length, attributeLength(value));
                }
            }
            return new PayloadPlan(length, List.copyOf(attributes));
        }

        private static List<PlannedAttribute> captureAttributes(AttributeSet source) {
            List<PlannedAttribute> captured = new ArrayList<>();
            for (AttributeId id : source.ids()) {
                List<AttributeValue> values = List.copyOf(source.getAll(id));
                requireCount(values.size());
                captured.add(new PlannedAttribute(encodeUtf8(id.value()), values));
            }
            return captured;
        }

        private void write(DigestingWriter writer, TransitionData data) throws IOException {
            writer.writeShort(SEMANTIC_VERSION);
            writer.writeShort(RESERVED_FLAGS);
            writer.writeComponent(encodeUtf8(data.credentialId().value()));
            writer.writeLong(data.transition().revision());
            if (data.previousCredentialGlobalRevision().isPresent()) {
                writer.writeByte(1);
                writer.writeLong(data.previousCredentialGlobalRevision().getAsLong());
                writer.writeBytes(data.previousCredentialCommitment().orElseThrow().bytes());
            } else {
                writer.writeByte(0);
            }
            writer.writeLong(data.transition().time().getEpochSecond());
            writer.writeInt(data.transition().time().getNano());
            writer.writeByte(encodeState(data.transition().state()));
            writer.writeByte(encodeReason(data.transition().permanentReason()));
            writer.writeShort(RESERVED_FLAGS);
            writer.writeInt(attributes.size());
            for (PlannedAttribute attribute : attributes) {
                writer.writeComponent(attribute.encodedId());
                List<AttributeValue> values = attribute.values();
                writer.writeInt(values.size());
                for (AttributeValue value : values) {
                    writeAttributeValue(writer, value);
                }
            }
        }

        private static long attributeLength(AttributeValue value) throws IOException {
            Objects.requireNonNull(value, "attribute value");
            return switch (value) {
                case AttributeValue.StringValue stringValue ->
                    addComponent(1L, encodeUtf8(stringValue.value()).length);
                case AttributeValue.BooleanValue ignored -> 2L;
                case AttributeValue.IntegerValue ignored -> 1L + Long.BYTES;
                case AttributeValue.InstantValue ignored -> 1L + Long.BYTES + Integer.BYTES;
                case AttributeValue.BytesValue bytesValue -> {
                    requireComponentLength(bytesValue.value().length);
                    yield 1L + Integer.BYTES + bytesValue.value().length;
                }
            };
        }

        private static void writeAttributeValue(DigestingWriter writer, AttributeValue value) throws IOException {
            switch (value) {
                case AttributeValue.StringValue stringValue -> {
                    writer.writeByte(1);
                    writer.writeComponent(encodeUtf8(stringValue.value()));
                }
                case AttributeValue.BooleanValue booleanValue -> {
                    writer.writeByte(2);
                    writer.writeByte(booleanValue.value() ? 1 : 0);
                }
                case AttributeValue.IntegerValue integerValue -> {
                    writer.writeByte(3);
                    writer.writeLong(integerValue.value());
                }
                case AttributeValue.InstantValue instantValue -> {
                    writer.writeByte(4);
                    writer.writeLong(instantValue.value().getEpochSecond());
                    writer.writeInt(instantValue.value().getNano());
                }
                case AttributeValue.BytesValue bytesValue -> {
                    writer.writeByte(5);
                    writer.writeComponent(bytesValue.value());
                }
            }
        }

        private static long addComponent(long current, int componentLength) throws IOException {
            requireComponentLength(componentLength);
            return add(current, Integer.BYTES + (long) componentLength);
        }

        private static long add(long first, long second) throws IOException {
            try {
                return Math.addExact(first, second);
            } catch (ArithmeticException overflow) {
                throw new IOException("Revocation transition payload is too large", overflow);
            }
        }

        private static void requireComponentLength(int length) {
            if (length < 0 || length > MAX_COMPONENT_BYTES) {
                throw new IllegalArgumentException("Revocation transition component exceeds its technical limit");
            }
        }

        private static void requireCount(int count) {
            if (count < 0 || count > MAX_COMPONENT_BYTES) {
                throw new IllegalArgumentException("Revocation transition collection exceeds its technical limit");
            }
        }
    }

    /** Writes canonical fields while incrementally committing every payload byte. */
    private static final class DigestingWriter {
        private final SeekableByteChannel channel;
        private final DigestOutputStream digest;
        private final ByteBuffer primitive = ByteBuffer.allocate(Long.BYTES).order(ByteOrder.BIG_ENDIAN);

        private DigestingWriter(SeekableByteChannel channel, MessageDigest digest) {
            this.channel = channel;
            this.digest = new DigestOutputStream(OutputStream.nullOutputStream(), digest);
        }

        private void writeByte(int value) throws IOException {
            writePrimitive(1, buffer -> buffer.put((byte) value));
        }

        private void writeShort(int value) throws IOException {
            writePrimitive(Short.BYTES, buffer -> buffer.putShort((short) value));
        }

        private void writeInt(int value) throws IOException {
            writePrimitive(Integer.BYTES, buffer -> buffer.putInt(value));
        }

        private void writeLong(long value) throws IOException {
            writePrimitive(Long.BYTES, buffer -> buffer.putLong(value));
        }

        private void writeComponent(byte[] value) throws IOException {
            PayloadPlan.requireComponentLength(value.length);
            writeInt(value.length);
            writeBytes(value);
        }

        private void writeBytes(byte[] value) throws IOException {
            digest.write(value);
            writeFully(channel, ByteBuffer.wrap(value));
        }

        private void writePrimitive(int bytes, PrimitiveEncoder encoder) throws IOException {
            primitive.clear();
            encoder.encode(primitive);
            primitive.flip();
            primitive.limit(bytes);
            byte[] encoded = new byte[bytes];
            primitive.get(encoded);
            writeBytes(encoded);
        }
    }

    /** Reads only the authenticated payload region and commits bytes incrementally. */
    private static final class BoundedReader {
        private final SeekableByteChannel channel;
        private final DigestOutputStream digest;
        private final byte[] transfer;
        private long remaining;

        private BoundedReader(SeekableByteChannel channel, long remaining, MessageDigest digest, byte[] transfer) {
            this.channel = channel;
            this.remaining = remaining;
            this.digest = new DigestOutputStream(OutputStream.nullOutputStream(), digest);
            if (transfer.length != READ_SCRATCH_BYTES) {
                throw new IllegalArgumentException("Revocation decode scratch has an invalid size");
            }
            this.transfer = transfer;
        }

        private long remaining() {
            return remaining;
        }

        private int readUnsignedByte() throws IOException {
            return Byte.toUnsignedInt(readBytes(1)[0]);
        }

        private short readShort() throws IOException {
            return ByteBuffer.wrap(readBytes(Short.BYTES)).order(ByteOrder.BIG_ENDIAN).getShort();
        }

        private int readInt() throws IOException {
            return ByteBuffer.wrap(readBytes(Integer.BYTES)).order(ByteOrder.BIG_ENDIAN).getInt();
        }

        private long readLong() throws IOException {
            return ByteBuffer.wrap(readBytes(Long.BYTES)).order(ByteOrder.BIG_ENDIAN).getLong();
        }

        private boolean readStrictBoolean() throws IOException {
            int value = readUnsignedByte();
            if (value != BOOLEAN_FALSE && value != BOOLEAN_TRUE) {
                throw new IllegalArgumentException("Invalid revocation boolean value");
            }
            return value == BOOLEAN_TRUE;
        }

        private int readBoundedCount() throws IOException {
            int count = readInt();
            PayloadPlan.requireCount(count);
            return count;
        }

        private String readStrictString() throws IOException {
            return decodeStrictUtf8(readComponent());
        }

        private byte[] readComponent() throws IOException {
            int length = readInt();
            PayloadPlan.requireComponentLength(length);
            return readBytes(length);
        }

        private byte[] readBytes(int length) throws IOException {
            if (length < 0 || length > remaining) {
                throw new IllegalArgumentException("Revocation payload field exceeds its bounded region");
            }
            byte[] result = new byte[length];
            int copied = 0;
            while (copied < length) {
                int requested = Math.min(transfer.length, length - copied);
                ByteBuffer target = ByteBuffer.wrap(transfer, 0, requested);
                if (readAvailable(channel, target) != requested) {
                    throw new IOException("Revocation payload changed during bounded decoding");
                }
                digest.write(transfer, 0, requested);
                System.arraycopy(transfer, 0, result, copied, requested);
                copied += requested;
                remaining -= requested;
            }
            return result;
        }
    }

    /**
     * Caller-owned fixed decode scratch for one sequential reader. Instances are
     * not thread-safe and must be confined to one feed and one calling thread;
     * they expose no mutable buffer reference.
     */
    /* default */ static final class DecodeScratch implements AutoCloseable {
        private byte[] transfer = new byte[READ_SCRATCH_BYTES];
        private boolean acquired;

        /** Returns the exact fixed capacity without exposing mutable storage. */
        /* default */ int capacity() {
            requireOpen();
            return transfer.length;
        }

        private byte[] acquire() {
            requireOpen();
            if (acquired) {
                throw new IllegalStateException("Revocation decode scratch is already in use");
            }
            acquired = true;
            return transfer;
        }

        private void release() {
            acquired = false;
        }

        /** Drops the reusable storage; repeated close is harmless. */
        @Override public void close() {
            if (acquired) {
                throw new IllegalStateException("Revocation decode scratch is in use");
            }
            transfer = null;
        }

        private void requireOpen() {
            if (transfer == null) {
                throw new IllegalStateException("Revocation decode scratch is closed");
            }
        }
    }

    /** Encodes one primitive into the reusable fixed-width scratch buffer. */
    @FunctionalInterface
    private interface PrimitiveEncoder {
        /** Encodes one fixed-width primitive into the reusable buffer. */
        void encode(ByteBuffer buffer);
    }

    /** One canonical decoded attribute and the bytes used for order validation. */
    private record DecodedAttribute(byte[] encodedId, AttributeId id, List<AttributeValue> values) {
        /** Retains one bounded component and one immutable semantic entry. */
        private DecodedAttribute {
            Objects.requireNonNull(encodedId, "encodedId");
            Objects.requireNonNull(id, "id");
            values = List.copyOf(values);
        }
    }

    /** Map-backed decode input keeps transition snapshot construction linear in attribute count. */
    private static final class DecodedAttributeSet implements AttributeSet {
        private final Map<AttributeId, List<AttributeValue>> attributes;

        private DecodedAttributeSet(Map<AttributeId, List<AttributeValue>> attributes) {
            this.attributes = Map.copyOf(attributes);
        }

        @Override
        public Set<AttributeId> ids() {
            return attributes.keySet();
        }

        @Override
        public Optional<AttributeValue> get(AttributeId id) {
            List<AttributeValue> values = getAll(id);
            return values.isEmpty() ? Optional.empty() : Optional.of(values.get(0));
        }

        @Override
        public List<AttributeValue> getAll(AttributeId id) {
            Objects.requireNonNull(id, "id");
            return attributes.getOrDefault(id, List.of());
        }
    }

    /** Structural record reader that authenticates boundaries before semantic decoding. */
    private static final class WireOperations {
        private static ReadResult read(SeekableByteChannel channel, long recordOffset, byte[] transfer)
                throws IOException {
            Objects.requireNonNull(channel, "channel");
            if (recordOffset < PREAMBLE_BYTES) {
                throw new IllegalArgumentException("Revocation record offset precedes the log preamble");
            }
            channel.position(recordOffset);
            ByteBuffer headerBuffer = ByteBuffer.allocate(HEADER_BYTES).order(ByteOrder.BIG_ENDIAN);
            int headerRead = readAvailable(channel, headerBuffer);
            if (headerRead == 0) {
                return ReadResult.endOfInput();
            }
            if (headerRead != HEADER_BYTES) {
                return ReadResult.incompleteTail();
            }
            byte[] header = headerBuffer.array();
            Header decoded = decodeHeader(header);
            if (decoded == null) {
                return ReadResult.corruptRecord();
            }
            Long recordEnd = recordEnd(recordOffset, decoded.payloadLength());
            if (recordEnd == null) {
                return ReadResult.corruptRecord();
            }
            if (recordEnd > channel.size()) {
                return ReadResult.incompleteTail();
            }
            return decodeComplete(channel, recordOffset, recordEnd, header, decoded, transfer);
        }

        private static ReadResult decodeComplete(
                SeekableByteChannel channel,
                long recordOffset,
                long recordEnd,
                byte[] header,
                Header decoded,
                byte[] transfer) throws IOException {
            MessageDigest recordDigest = newSha256();
            recordDigest.update(RECORD_DOMAIN);
            recordDigest.update(header);
            BoundedReader reader = new BoundedReader(channel, decoded.payloadLength(), recordDigest, transfer);
            try {
                TransitionData data = decodePayload(decoded, reader);
                if (reader.remaining() != NO_REMAINING_PAYLOAD) {
                    return ReadResult.corruptRecord();
                }
                byte[] suppliedCommitment = new byte[COMMITMENT_BYTES];
                readFully(channel, ByteBuffer.wrap(suppliedCommitment));
                byte[] calculated = recordDigest.digest();
                if (!MessageDigest.isEqual(calculated, suppliedCommitment)) {
                    return ReadResult.corruptRecord();
                }
                Commitment commitment = new Commitment(LOWERCASE_HEX.formatHex(suppliedCommitment));
                return ReadResult.completeRecord(
                        new CompleteRecord(data, recordOffset, recordEnd, commitment));
            } catch (IllegalArgumentException | DateTimeException malformed) {
                return ReadResult.corruptRecord();
            }
        }

        private static Header decodeHeader(byte[] encoded) {
            ByteBuffer fields = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
            if (fields.getInt() != RECORD_MAGIC) {
                return null;
            }
            byte[] suppliedDigest = new byte[COMMITMENT_BYTES];
            System.arraycopy(encoded, HEADER_FIELDS_BYTES, suppliedDigest, 0, COMMITMENT_BYTES);
            MessageDigest digest = newSha256();
            digest.update(encoded, 0, HEADER_FIELDS_BYTES);
            if (!MessageDigest.isEqual(digest.digest(), suppliedDigest)) {
                return null;
            }
            short version = fields.getShort();
            short flags = fields.getShort();
            long globalRevision = fields.getLong();
            byte[] previous = new byte[COMMITMENT_BYTES];
            fields.get(previous);
            long payloadLength = fields.getLong();
            if (version != STRUCTURAL_VERSION || flags != RESERVED_FLAGS
                    || globalRevision < MINIMUM_GLOBAL_REVISION || payloadLength < 0L) {
                return null;
            }
            return new Header(globalRevision,
                    new Commitment(LOWERCASE_HEX.formatHex(previous)), payloadLength);
        }

        private static Long recordEnd(long recordOffset, long payloadLength) {
            try {
                return checkedRecordEnd(recordOffset, payloadLength);
            } catch (IOException invalidBoundary) {
                return null;
            }
        }
    }

    /** Strict semantic payload handling isolated from structural frame authentication. */
    private static final class SemanticOperations {
        private static TransitionData decodePayload(Header header, BoundedReader reader) throws IOException {
            if (reader.readShort() != SEMANTIC_VERSION || reader.readShort() != RESERVED_FLAGS) {
                throw new IllegalArgumentException("Unsupported revocation transition payload");
            }
            PkiId credentialId = new PkiId(reader.readStrictString());
            long localRevision = reader.readLong();
            CredentialLink link = readCredentialLink(reader);
            Instant time = Instant.ofEpochSecond(reader.readLong(), reader.readInt());
            RevocationState state = decodeState(reader.readUnsignedByte());
            Optional<RevocationReason> reason = decodeReason(reader.readUnsignedByte());
            if (reader.readShort() != RESERVED_FLAGS) {
                throw new IllegalArgumentException("Invalid revocation transition reserved field");
            }
            AttributeSet attributes = readAttributes(reader);
            RevocationTransition transition = new RevocationTransition(
                    localRevision, state, time, reason, attributes);
            TransitionData data = new TransitionData(
                    header.globalRevision(), header.previousGlobalCommitment(), credentialId,
                    link.globalRevision(), link.commitment(), transition);
            requireTransitionData(data);
            return data;
        }

        private static CredentialLink readCredentialLink(BoundedReader reader) throws IOException {
            int linked = reader.readUnsignedByte();
            if (linked == 0) {
                return new CredentialLink(OptionalLong.empty(), Optional.empty());
            }
            if (linked != LINK_PRESENT) {
                throw new IllegalArgumentException("Invalid revocation credential link marker");
            }
            long previousRevision = reader.readLong();
            byte[] previousCommitment = reader.readBytes(COMMITMENT_BYTES);
            return new CredentialLink(OptionalLong.of(previousRevision), Optional.of(
                    new Commitment(LOWERCASE_HEX.formatHex(previousCommitment))));
        }

        private static AttributeSet readAttributes(BoundedReader reader) throws IOException {
            int count = reader.readBoundedCount();
            Map<AttributeId, List<AttributeValue>> entries = new LinkedHashMap<>(count);
            byte[] previousId = null;
            for (int index = 0; index < count; index++) {
                DecodedAttribute decoded = readAttribute(reader, previousId);
                entries.put(decoded.id(), decoded.values());
                previousId = decoded.encodedId();
            }
            return new DecodedAttributeSet(entries);
        }

        private static DecodedAttribute readAttribute(
                BoundedReader reader, byte[] previousId) throws IOException {
            byte[] encodedId = reader.readComponent();
            if (previousId != null && compareUnsigned(previousId, encodedId) >= 0) {
                throw new IllegalArgumentException("Revocation attributes are not canonical");
            }
            AttributeId id = new AttributeId(decodeStrictUtf8(encodedId));
            int valueCount = reader.readBoundedCount();
            List<AttributeValue> values = readAttributeValues(reader, valueCount);
            return new DecodedAttribute(encodedId, id, values);
        }

        private static List<AttributeValue> readAttributeValues(
                BoundedReader reader, int valueCount) throws IOException {
            List<AttributeValue> values = new ArrayList<>(valueCount);
            for (int valueIndex = 0; valueIndex < valueCount; valueIndex++) {
                values.add(readAttributeValue(reader));
            }
            return values;
        }

        private static AttributeValue readAttributeValue(BoundedReader reader) throws IOException {
            return switch (reader.readUnsignedByte()) {
                case 1 -> new AttributeValue.StringValue(reader.readStrictString());
                case 2 -> new AttributeValue.BooleanValue(reader.readStrictBoolean());
                case 3 -> new AttributeValue.IntegerValue(reader.readLong());
                case 4 -> new AttributeValue.InstantValue(
                        Instant.ofEpochSecond(reader.readLong(), reader.readInt()));
                case 5 -> new AttributeValue.BytesValue(reader.readComponent());
                default -> throw new IllegalArgumentException("Unknown revocation attribute value code");
            };
        }

        private static RevocationState decodeState(int code) {
            return ValueCodes.decodeState(code);
        }

        private static Optional<RevocationReason> decodeReason(int code) {
            return ValueCodes.decodeReason(code);
        }

        private static void requireTransitionData(TransitionData data) {
            if (data.globalRevision() < MINIMUM_GLOBAL_REVISION) {
                throw new IllegalArgumentException("Global revocation revision must be positive");
            }
            requireIntrinsicTransition(data.transition());
            boolean previousRevision = data.previousCredentialGlobalRevision().isPresent();
            boolean previousCommitment = data.previousCredentialCommitment().isPresent();
            if (previousRevision != previousCommitment
                    || previousRevision && data.previousCredentialGlobalRevision().getAsLong() <= 0L) {
                throw new IllegalArgumentException("Revocation credential history link is invalid");
            }
            if (data.transition().revision() == FIRST_CREDENTIAL_REVISION && previousRevision
                    || data.transition().revision() > FIRST_CREDENTIAL_REVISION && !previousRevision) {
                throw new IllegalArgumentException(
                        "Revocation credential revision and history link disagree");
            }
        }

        private static void requireIntrinsicTransition(RevocationTransition transition) {
            if (transition.state() == RevocationState.PERMANENTLY_REVOKED) {
                RevocationReason reason = transition.permanentReason().orElseThrow(
                        () -> new IllegalArgumentException(
                                "Permanent revocation requires a permanent reason"));
                if (reason == RevocationReason.CERTIFICATE_HOLD
                        || reason == RevocationReason.REMOVE_FROM_CRL) {
                    throw new IllegalArgumentException(
                            "Permanent revocation requires a permanent reason");
                }
            } else if (transition.permanentReason().isPresent()) {
                throw new IllegalArgumentException(
                        "Non-permanent revocation state cannot carry a permanent reason");
            }
        }

        private static byte[] encodeUtf8(String value) {
            final byte[] encoded;
            try {
                ByteBuffer buffer = StandardCharsets.UTF_8.newEncoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .encode(CharBuffer.wrap(value));
                encoded = new byte[buffer.remaining()];
                buffer.get(encoded);
            } catch (CharacterCodingException malformed) {
                throw new IllegalArgumentException(
                        "Revocation transition text is not valid Unicode", malformed);
            }
            if (encoded.length > MAX_COMPONENT_BYTES) {
                throw new IllegalArgumentException(
                        "Revocation transition component exceeds its technical limit");
            }
            return encoded;
        }

        private static String decodeStrictUtf8(byte[] encoded) {
            try {
                CharBuffer decoded = StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(encoded));
                return decoded.toString();
            } catch (CharacterCodingException malformed) {
                throw new IllegalArgumentException(
                        "Revocation transition contains malformed UTF-8", malformed);
            }
        }

        private static int compareUnsigned(byte[] first, byte[] second) {
            int common = Math.min(first.length, second.length);
            for (int index = 0; index < common; index++) {
                int difference = Byte.toUnsignedInt(first[index]) - Byte.toUnsignedInt(second[index]);
                if (difference != 0) {
                    return difference;
                }
            }
            return first.length - second.length;
        }

        private static int encodeState(RevocationState state) {
            return ValueCodes.encodeState(state);
        }

        private static int encodeReason(Optional<RevocationReason> reason) {
            return ValueCodes.encodeReason(reason);
        }

    }

    /** Semantic equality for immutable decoded transition metadata. */
    private static final class SemanticEquality {
        private static boolean transitionsEqual(
                RevocationTransition first, RevocationTransition second) {
            return first.revision() == second.revision()
                    && first.state() == second.state()
                    && first.time().equals(second.time())
                    && first.permanentReason().equals(second.permanentReason())
                    && attributesEqual(first.attributes(), second.attributes());
        }

        private static int transitionHash(RevocationTransition transition) {
            return Objects.hash(transition.revision(), transition.state(), transition.time(),
                    transition.permanentReason(), attributeHash(transition.attributes()));
        }

        private static boolean attributesEqual(AttributeSet first, AttributeSet second) {
            Set<AttributeId> firstIds = first.ids();
            Set<AttributeId> secondIds = second.ids();
            if (!firstIds.equals(secondIds)) {
                return false;
            }
            for (AttributeId id : firstIds) {
                if (!attributeListsEqual(first.getAll(id), second.getAll(id))) {
                    return false;
                }
            }
            return true;
        }

        private static boolean attributeListsEqual(
                List<AttributeValue> first, List<AttributeValue> second) {
            if (first.size() != second.size()) {
                return false;
            }
            for (int index = 0; index < first.size(); index++) {
                if (!attributeValuesEqual(first.get(index), second.get(index))) {
                    return false;
                }
            }
            return true;
        }

        private static boolean attributeValuesEqual(AttributeValue first, AttributeValue second) {
            if (first instanceof AttributeValue.BytesValue firstBytes
                    && second instanceof AttributeValue.BytesValue secondBytes) {
                return java.util.Arrays.equals(firstBytes.value(), secondBytes.value());
            }
            return first.equals(second);
        }

        private static int attributeHash(AttributeSet attributes) {
            List<AttributeId> ids = new ArrayList<>(attributes.ids());
            ids.sort(Comparator.comparing(AttributeId::value));
            int hash = 1;
            for (AttributeId id : ids) {
                hash = 31 * hash + id.hashCode();
                hash = attributeValuesHash(hash, attributes.getAll(id));
            }
            return hash;
        }

        private static int attributeValuesHash(int initial, List<AttributeValue> values) {
            int hash = initial;
            for (AttributeValue value : values) {
                hash = 31 * hash + attributeValueHash(value);
            }
            return hash;
        }

        private static int attributeValueHash(AttributeValue value) {
            if (value instanceof AttributeValue.BytesValue bytesValue) {
                return java.util.Arrays.hashCode(bytesValue.value());
            }
            return value.hashCode();
        }
    }

    /** Closed stable numeric codes for revocation state and reason values. */
    private static final class ValueCodes {
        private static RevocationState decodeState(int code) {
            return switch (code) {
                case 1 -> RevocationState.CLEAR;
                case 2 -> RevocationState.HELD;
                case 3 -> RevocationState.PERMANENTLY_REVOKED;
                default -> throw new IllegalArgumentException("Unknown revocation state code");
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
                default -> throw new IllegalArgumentException("Unknown revocation reason code");
            };
        }

        private static int encodeState(RevocationState state) {
            return switch (state) {
                case CLEAR -> 1;
                case HELD -> 2;
                case PERMANENTLY_REVOKED -> 3;
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
    }

    /** Optional same-credential history link decoded from one payload. */
    private record CredentialLink(
            OptionalLong globalRevision, Optional<Commitment> commitment) {
    }

    private static int encodeState(RevocationState state) {
        return SemanticOperations.encodeState(state);
    }

    private static int encodeReason(Optional<RevocationReason> reason) {
        return SemanticOperations.encodeReason(reason);
    }

    /* default */ static boolean transitionsEqual(RevocationTransition first, RevocationTransition second) {
        return SemanticEquality.transitionsEqual(first, second);
    }

    /* default */ static int transitionHash(RevocationTransition transition) {
        return SemanticEquality.transitionHash(transition);
    }
}
