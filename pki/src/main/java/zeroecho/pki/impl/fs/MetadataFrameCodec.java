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
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.OptionalLong;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;

/**
 * Strict streaming codec for one structural metadata-log frame.
 */
final class MetadataFrameCodec {

    private static final int FRAME_MAGIC = 0x5A454D46;
    private static final short SCHEMA_VERSION = 1;
    private static final byte RESERVED_FLAGS = 0;
    private static final int TRANSACTION_TOKEN_BYTES = 16;
    private static final int HEADER_FIELDS_BYTES = 40;
    private static final int SHA_256_BYTES = 32;
    private static final int FIXED_HEADER_BYTES = HEADER_FIELDS_BYTES + SHA_256_BYTES;
    private static final int TRANSFER_BUFFER_BYTES = 16 * 1024;
    private static final long MINIMUM_FRAME_OFFSET = 0L;
    private static final long MINIMUM_PAYLOAD_LENGTH = 0L;
    private static final long MINIMUM_SEQUENCE_NUMBER = 0L;
    private static final HexFormat LOWERCASE_HEX = HexFormat.of();

    private final OptionalLong maximumPayloadLength;

    /**
     * Creates a frame codec with the supplied optional payload bound. A present bound must be nonnegative.
     *
     * @param maximumPayloadLength optional inclusive payload-byte limit; empty selects no configured limit
     * @throws NullPointerException if maximumPayloadLength is null
     * @throws IllegalArgumentException if the configured limit is negative
     */
    /* default */ MetadataFrameCodec(OptionalLong maximumPayloadLength) {
        this.maximumPayloadLength = Objects.requireNonNull(maximumPayloadLength, "maximumPayloadLength");
        if (maximumPayloadLength.isPresent() && maximumPayloadLength.getAsLong() < 0L) {
            throw new IllegalArgumentException("Maximum metadata-frame payload length must be non-negative");
        }
    }

    /**
     * Creates a frame codec without a configured payload-length limit.
     *
     */
    /* default */ MetadataFrameCodec() {
        this(OptionalLong.empty());
    }

    /*
     * The authenticated header is validated before payloadLength is used for
     * positioning or allocation. A tampered length is therefore corruption, not
     * an apparently incomplete tail selected by unauthenticated input.
     */
    /**
     * Reads and authenticates the frame at the specified offset using bounded transfer storage. End of input, an incomplete tail and corrupt framing are represented by the returned result; the borrowed channel remains open.
     *
     * @param channel borrowed channel, which remains open
     * @param frameOffset nonnegative byte offset of the frame header
     * @return classification and authenticated record metadata
     * @throws IOException if the channel cannot be read or positioned
     * @throws NullPointerException if channel is null
     * @throws IllegalArgumentException if frameOffset is negative
     */
    /* default */ ReadResult read(SeekableByteChannel channel, long frameOffset) throws IOException {
        Objects.requireNonNull(channel, "channel");
        if (frameOffset < MINIMUM_FRAME_OFFSET) {
            throw new IllegalArgumentException("Metadata-frame offset must be non-negative");
        }

        ByteBuffer header = ByteBuffer.allocate(FIXED_HEADER_BYTES).order(ByteOrder.BIG_ENDIAN);
        channel.position(frameOffset);
        int headerBytes = readAvailable(channel, header);
        if (headerBytes == 0) {
            return ReadResult.endOfInput();
        }
        if (headerBytes < FIXED_HEADER_BYTES) {
            return ReadResult.incompleteTail();
        }
        return decodeCompleteHeader(channel, frameOffset, header.array());
    }

    private ReadResult decodeCompleteHeader(
            SeekableByteChannel channel, long frameOffset, byte[] encodedHeader) throws IOException {
        ByteBuffer fields = ByteBuffer.wrap(encodedHeader).order(ByteOrder.BIG_ENDIAN);
        if (fields.getInt() != FRAME_MAGIC) {
            return ReadResult.corruptFrame();
        }

        byte[] suppliedHeaderDigest = Arrays.copyOfRange(
                encodedHeader, HEADER_FIELDS_BYTES, FIXED_HEADER_BYTES);
        MessageDigest headerDigest = newSha256();
        headerDigest.update(encodedHeader, 0, HEADER_FIELDS_BYTES);
        if (!MessageDigest.isEqual(headerDigest.digest(), suppliedHeaderDigest)) {
            return ReadResult.corruptFrame();
        }

        short version = fields.getShort();
        byte typeCode = fields.get();
        byte flags = fields.get();
        byte[] transactionTokenBytes = new byte[TRANSACTION_TOKEN_BYTES];
        fields.get(transactionTokenBytes);
        long sequence = fields.getLong();
        long payloadLength = fields.getLong();
        FrameType frameType = FrameType.fromWireCode(typeCode);
        if (headerFieldsAreInvalid(version, frameType, flags, sequence, payloadLength)) {
            return ReadResult.corruptFrame();
        }

        final long payloadOffset;
        final long payloadDigestOffset;
        final long frameEndOffset;
        try {
            // Checked arithmetic prevents a validly authenticated hostile length
            // from wrapping frame boundaries into an earlier part of the log.
            payloadOffset = Math.addExact(frameOffset, FIXED_HEADER_BYTES);
            payloadDigestOffset = Math.addExact(payloadOffset, payloadLength);
            frameEndOffset = Math.addExact(payloadDigestOffset, SHA_256_BYTES);
        } catch (ArithmeticException overflow) {
            return ReadResult.corruptFrame();
        }

        ReadClassification payloadClassification = classifyPayloadAndDigest(channel, payloadLength);
        if (payloadClassification != ReadClassification.COMPLETE_FRAME) {
            return ReadResult.forClassification(payloadClassification);
        }

        FrameMetadata metadata = new FrameMetadata(
                frameType,
                LOWERCASE_HEX.formatHex(transactionTokenBytes),
                sequence,
                frameOffset,
                payloadOffset,
                payloadLength,
                payloadDigestOffset,
                frameEndOffset);
        return ReadResult.completeFrame(metadata);
    }

    private boolean headerFieldsAreInvalid(
            short version, FrameType frameType, byte flags, long sequence, long payloadLength) {
        return version != SCHEMA_VERSION || frameType == null || flags != RESERVED_FLAGS
                || sequence < MINIMUM_SEQUENCE_NUMBER || payloadLength < MINIMUM_PAYLOAD_LENGTH
                || exceedsTechnicalLimit(payloadLength);
    }

    private static ReadClassification classifyPayloadAndDigest(
            SeekableByteChannel channel, long payloadLength) throws IOException {
        MessageDigest payloadDigest = newSha256();
        byte[] transferBuffer = new byte[TRANSFER_BUFFER_BYTES];
        long remaining = payloadLength;
        try {
            while (remaining > 0L) {
                int requested = (int) Math.min((long) transferBuffer.length, remaining);
                ByteBuffer destination = ByteBuffer.wrap(transferBuffer, 0, requested);
                int read = readAvailable(channel, destination);
                if (read < requested) {
                    return ReadClassification.INCOMPLETE_TAIL;
                }
                payloadDigest.update(transferBuffer, 0, read);
                remaining -= read;
            }

            ByteBuffer footer = ByteBuffer.allocate(SHA_256_BYTES);
            int footerBytes = readAvailable(channel, footer);
            if (footerBytes < SHA_256_BYTES) {
                return ReadClassification.INCOMPLETE_TAIL;
            }
            if (!MessageDigest.isEqual(payloadDigest.digest(), footer.array())) {
                return ReadClassification.CORRUPT_FRAME;
            }
        } finally {
            Arrays.fill(transferBuffer, (byte) 0);
        }
        return ReadClassification.COMPLETE_FRAME;
    }

    /*
     * Failed writes may leave a partial frame at the channel's current position.
     * Truncation and rollback belong to the later log writer, not this codec.
     * Payload processing uses one fixed buffer, so auxiliary memory is O(1).
     */
    /**
     * Writes one authenticated frame at the current channel position, streaming and closing the opened content stream. The channel remains open; a failed write can leave a partial suffix for the owning log writer to roll back.
     *
     * @param channel borrowed channel, which remains open
     * @param frameType encoded frame discriminator
     * @param transactionToken canonical transaction token to encode
     * @param sequence nonnegative frame sequence
     * @param declaredPayloadLength exact payload length in bytes
     * @param content repeatable payload source
     * @param cancellation cooperative cancellation signal
     * @return coordinates and commitment of the written frame
     * @throws IOException if payload length differs, cancellation fails, or content/channel I/O cannot complete
     * @throws NullPointerException if channel, frameType, transactionToken, content or cancellation is null
     * @throws IllegalArgumentException if the token is not 32 lowercase hexadecimal characters, the sequence is negative or the declared payload violates its configured bound
     */
    /* default */ FrameMetadata write(
            SeekableByteChannel channel,
            FrameType frameType,
            String transactionToken,
            long sequence,
            long declaredPayloadLength,
            RepeatableContent content,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(frameType, "frameType");
        Objects.requireNonNull(content, "content");
        Objects.requireNonNull(cancellation, "cancellation");
        byte[] transactionTokenBytes = decodeTransactionToken(transactionToken);
        requirePayloadLength(declaredPayloadLength);
        OptionalLong knownLength = content.length();
        if (knownLength.isPresent() && knownLength.getAsLong() != declaredPayloadLength) {
            throw new IOException("Declared metadata-frame payload length does not match content length");
        }

        long frameOffset = channel.position();
        final long payloadOffset;
        final long payloadDigestOffset;
        final long frameEndOffset;
        try {
            payloadOffset = Math.addExact(frameOffset, FIXED_HEADER_BYTES);
            payloadDigestOffset = Math.addExact(payloadOffset, declaredPayloadLength);
            frameEndOffset = Math.addExact(payloadDigestOffset, SHA_256_BYTES);
        } catch (ArithmeticException overflow) {
            throw new IOException("Metadata-frame boundaries exceed the supported long range", overflow);
        }

        ByteBuffer header = encodeHeader(frameType, transactionTokenBytes, sequence, declaredPayloadLength);
        cancellation.throwIfCancelled();
        writeFully(channel, header);

        MessageDigest payloadDigest = newSha256();
        byte[] transferBuffer = new byte[TRANSFER_BUFFER_BYTES];
        long remaining = declaredPayloadLength;
        cancellation.throwIfCancelled();
        try (InputStream input = content.openStream()) {
            while (remaining > 0L) {
                cancellation.throwIfCancelled();
                int requested = (int) Math.min((long) transferBuffer.length, remaining);
                int read = input.read(transferBuffer, 0, requested);
                if (read < 0) {
                    throw new IOException("Metadata-frame payload is shorter than its declared length");
                }
                if (read == 0) {
                    continue;
                }
                payloadDigest.update(transferBuffer, 0, read);
                writeFully(channel, ByteBuffer.wrap(transferBuffer, 0, read));
                remaining -= read;
            }
            cancellation.throwIfCancelled();
            if (input.read() >= 0) {
                throw new IOException("Metadata-frame payload is longer than its declared length");
            }
            writeFully(channel, ByteBuffer.wrap(payloadDigest.digest()));
        } finally {
            Arrays.fill(transferBuffer, (byte) 0);
        }

        return new FrameMetadata(
                frameType,
                LOWERCASE_HEX.formatHex(transactionTokenBytes),
                sequence,
                frameOffset,
                payloadOffset,
                declaredPayloadLength,
                payloadDigestOffset,
                frameEndOffset);
    }

    private boolean exceedsTechnicalLimit(long payloadLength) {
        return maximumPayloadLength.isPresent() && payloadLength > maximumPayloadLength.getAsLong();
    }

    private void requirePayloadLength(long payloadLength) {
        if (payloadLength < MINIMUM_PAYLOAD_LENGTH) {
            throw new IllegalArgumentException("Metadata-frame payload length must be non-negative");
        }
        if (exceedsTechnicalLimit(payloadLength)) {
            throw new IllegalArgumentException("Metadata-frame payload exceeds the adapter technical limit");
        }
    }

    private static ByteBuffer encodeHeader(
            FrameType frameType, byte[] transactionToken, long sequence, long payloadLength) {
        if (sequence < MINIMUM_SEQUENCE_NUMBER) {
            throw new IllegalArgumentException("Metadata-frame sequence must be non-negative");
        }
        ByteBuffer header = ByteBuffer.allocate(FIXED_HEADER_BYTES).order(ByteOrder.BIG_ENDIAN);
        header.putInt(FRAME_MAGIC);
        header.putShort(SCHEMA_VERSION);
        header.put(frameType.wireCode());
        header.put(RESERVED_FLAGS);
        header.put(transactionToken);
        header.putLong(sequence);
        header.putLong(payloadLength);
        MessageDigest digest = newSha256();
        digest.update(header.array(), 0, HEADER_FIELDS_BYTES);
        header.put(digest.digest());
        header.flip();
        return header;
    }

    private static byte[] decodeTransactionToken(String transactionToken) {
        Objects.requireNonNull(transactionToken, "transactionToken");
        if (transactionToken.length() != TRANSACTION_TOKEN_BYTES * 2) {
            throw new IllegalArgumentException("Metadata transaction token must be 32 lowercase hexadecimal characters");
        }
        for (int index = 0; index < transactionToken.length(); index++) {
            char current = transactionToken.charAt(index);
            if (!((current >= '0' && current <= '9') || (current >= 'a' && current <= 'f'))) {
                throw new IllegalArgumentException(
                        "Metadata transaction token must be 32 lowercase hexadecimal characters");
            }
        }
        return LOWERCASE_HEX.parseHex(transactionToken);
    }

    private static int readAvailable(SeekableByteChannel channel, ByteBuffer destination) throws IOException {
        int total = 0;
        while (destination.hasRemaining()) {
            int read = channel.read(destination);
            if (read < 0) {
                break;
            }
            if (read == 0) {
                throw new IOException("Metadata-frame channel made no read progress");
            }
            total += read;
        }
        return total;
    }

    private static void writeFully(SeekableByteChannel channel, ByteBuffer source) throws IOException {
        while (source.hasRemaining()) {
            if (channel.write(source) == 0) {
                throw new IOException("Metadata-frame channel made no write progress");
            }
        }
    }

    private static MessageDigest newSha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 is unavailable", failure);
        }
    }

    /**
     * Package-local wire kinds keep structural frame codes outside the public SPI
     * while preserving the closed current-version type set.
     */
    /* default */ enum FrameType {
        /**
         * Store identity and format header frame.
         */
        STORE_HEADER(1),
        /**
         * Transaction issuance frame.
         */
        TRANSACTION_ISSUED(2),
        /**
         * Create-mutation frame.
         */
        MUTATION_CREATE(3),
        /**
         * Replacement-mutation frame.
         */
        MUTATION_REPLACE(4),
        /**
         * Delete-mutation frame.
         */
        MUTATION_DELETE(5),
        /**
         * Committed transaction terminal frame.
         */
        TERMINAL_COMMITTED(6),
        /**
         * Noncommitted transaction terminal frame.
         */
        TERMINAL_NOT_COMMITTED(7),
        /**
         * Recovery restart and continuity frame.
         */
        RECOVERY_RESTART(8);

        private final byte wireCode;

        FrameType(int wireCode) {
            this.wireCode = (byte) wireCode;
        }

        private byte wireCode() {
            return wireCode;
        }

        private static FrameType fromWireCode(byte wireCode) {
            for (FrameType candidate : values()) {
                if (candidate.wireCode == wireCode) {
                    return candidate;
                }
            }
            return null;
        }
    }

    /**
     * Package-local classifications keep recovery-facing wire state outside the
     * public SPI while preserving the exhaustive structural outcomes.
     */
    /* default */ enum ReadClassification {
        /**
         * No bytes remain for another frame or record.
         */
        END_OF_INPUT,
        /**
         * The input ends with a partial frame or record.
         */
        INCOMPLETE_TAIL,
        /**
         * A complete frame with valid framing and checksum was decoded.
         */
        COMPLETE_FRAME,
        /**
         * A complete candidate frame fails structural or integrity validation.
         */
        CORRUPT_FRAME
    }

    /**
     * Bounded framing coordinates for one decoded metadata-log frame; payload bytes remain in the source file.
     *
     * @param frameType closed metadata frame discriminator
     * @param transactionToken exact transaction token encoded by the frame
     * @param sequence exact persisted record sequence
     * @param frameOffset zero-based byte offset of the encoded frame
     * @param payloadOffset zero-based byte offset of the frame payload
     * @param payloadLength exact encoded mutation payload length in bytes
     * @param payloadDigestOffset zero-based byte offset of the payload integrity digest
     * @param frameEndOffset exclusive byte offset immediately after the frame
     */
    /* default */ record FrameMetadata(
            FrameType frameType,
            String transactionToken,
            long sequence,
            long frameOffset,
            long payloadOffset,
            long payloadLength,
            long payloadDigestOffset,
            long frameEndOffset) {

        /**
         * Creates the bounded framing coordinates for one decoded metadata-log frame; payload bytes remain in the source file.
         *
         * @param frameType closed metadata frame discriminator
         * @param transactionToken exact transaction token encoded by the frame
         * @param sequence exact persisted record sequence
         * @param frameOffset zero-based byte offset of the encoded frame
         * @param payloadOffset zero-based byte offset of the frame payload
         * @param payloadLength exact encoded mutation payload length in bytes
         * @param payloadDigestOffset zero-based byte offset of the payload integrity digest
         * @param frameEndOffset exclusive byte offset immediately after the frame
         * @throws NullPointerException if {@code frameType} is null; or if {@code transactionToken} is null
         */
        FrameMetadata {
            Objects.requireNonNull(frameType, "frameType");
            Objects.requireNonNull(transactionToken, "transactionToken");
        }
    }

    /**
     * Classification and optional framing metadata from one metadata-log read attempt.
     *
     * @param classification closed structural classification of the read attempt
     * @param metadata decoded framing metadata when a complete frame was available
     */
    /* default */ record ReadResult(ReadClassification classification, FrameMetadata metadata) {

        /**
         * Creates the classification and optional framing metadata from one metadata-log read attempt.
         *
         * @param classification closed structural classification of the read attempt
         * @param metadata decoded framing metadata when a complete frame was available
         * @throws NullPointerException if {@code classification} is null
         * @throws IllegalArgumentException if {@code ((classification == ReadClassification.COMPLETE_FRAME) != (metadata != null))}
         */
        ReadResult {
            Objects.requireNonNull(classification, "classification");
            if ((classification == ReadClassification.COMPLETE_FRAME) != (metadata != null)) {
                throw new IllegalArgumentException("Complete metadata-frame classification requires metadata only");
            }
        }

        private static ReadResult endOfInput() {
            return new ReadResult(ReadClassification.END_OF_INPUT, null);
        }

        private static ReadResult incompleteTail() {
            return new ReadResult(ReadClassification.INCOMPLETE_TAIL, null);
        }

        private static ReadResult corruptFrame() {
            return new ReadResult(ReadClassification.CORRUPT_FRAME, null);
        }

        private static ReadResult forClassification(ReadClassification classification) {
            return new ReadResult(classification, null);
        }

        private static ReadResult completeFrame(FrameMetadata metadata) {
            return new ReadResult(ReadClassification.COMPLETE_FRAME, metadata);
        }
    }
}
