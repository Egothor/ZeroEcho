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
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.MessageDigest;
import java.util.Objects;
import java.util.Optional;
import zeroecho.pki.spi.store.MetadataKey;

/** Streaming version-one self-contained immutable signing checkpoint codec. */
final class SigningCheckpointCodec {

    /* default */ static final int MAGIC = 0x5A454350;
    /* default */ static final short VERSION = 1;
    /* default */ static final int HEADER_BYTES = 44;
    /* default */ static final int FOOTER_BYTES = SigningFormatSupport.SHA_256_BYTES;
    /* default */ static final int MAX_KEY_BYTES = 8192;
    /* default */ static final int MAX_ENTRIES = 1_000_000;
    /* default */ static final long MAX_CHECKPOINT_BYTES = 1L << 40;

    private static final short FLAGS = 0;
    private static final int ENTRY_FIXED_BYTES = 32;

    private SigningCheckpointCodec() {
        // utility class
    }

    /* default */ static Writer writer(WritableByteChannel channel, Header header) throws IOException {
        return new Writer(channel, header);
    }

    /* default */ static Reader reader(SeekableByteChannel channel) throws IOException {
        return new Reader(channel);
    }

    /* default */ static int encodedIndexBytes(String key) {
        return Math.addExact(Integer.BYTES + ENTRY_FIXED_BYTES, canonicalKey(key).length);
    }

    /** Thread-confined two-phase writer; the caller owns and closes the channel. */
    @SuppressWarnings("PMD.AvoidMessageDigestField")
    /* default */ static final class Writer {
        private final WritableByteChannel channel;
        private final Header header;
        private final MessageDigest digest = SigningFormatSupport.sha256();
        private final ByteBuffer output = ByteBuffer.allocate(
                Integer.BYTES + MAX_KEY_BYTES + ENTRY_FIXED_BYTES).order(ByteOrder.BIG_ENDIAN);
        private MetadataKey previousKey;
        private int indexed;
        private int dataFrames;
        private long position;
        private long expectedFrameOffset;
        private boolean dataStarted;
        private boolean finished;

        private Writer(WritableByteChannel channel, Header header) throws IOException {
            this.channel = Objects.requireNonNull(channel, "channel");
            this.header = requireHeader(header);
            expectedFrameOffset = header.dataOffset();
            writeAuthenticated(encodeHeader(header));
        }

        /* default */ void writeIndex(EntryDescriptor entry) throws IOException {
            Objects.requireNonNull(entry, "entry");
            if (finished || dataStarted || indexed >= header.entryCount()) {
                throw new IllegalStateException("signing checkpoint index is not accepting entries");
            }
            MetadataKey semanticKey = semanticKey(entry.key());
            byte[] key = canonicalKey(entry.key());
            if (previousKey != null && previousKey.compareTo(semanticKey) >= 0) {
                throw new IOException("signing checkpoint keys are not strictly ordered");
            }
            requireEntry(entry, header);
            if (entry.frameOffset() != expectedFrameOffset) {
                throw new IOException("signing checkpoint frame data is not contiguous");
            }
            output.clear();
            output.putInt(key.length).put(key);
            output.putShort(entry.recordType().wireCode()).putShort(FLAGS);
            output.putLong(entry.frameOffset()).putInt(entry.frameLength());
            output.putLong(entry.revision()).putLong(entry.sequence()).flip();
            writeAuthenticated(output);
            expectedFrameOffset = Math.addExact(expectedFrameOffset, entry.frameLength());
            previousKey = semanticKey;
            indexed++;
        }

        /* default */ void beginData() throws IOException {
            if (finished || dataStarted || indexed != header.entryCount()
                    || position != header.dataOffset()) {
                throw new IOException("signing checkpoint index boundary is inconsistent");
            }
            dataStarted = true;
        }

        /* default */ void writeFrame(EntryDescriptor entry, byte[] encodedFrame) throws IOException {
            writeFrame(entry, encodedFrame, true);
        }

        /* default */ void writeValidatedFrame(EntryDescriptor entry, byte[] encodedFrame)
                throws IOException {
            writeFrame(entry, encodedFrame, false);
        }

        private void writeFrame(EntryDescriptor entry, byte[] encodedFrame, boolean validate)
                throws IOException {
            Objects.requireNonNull(entry, "entry");
            Objects.requireNonNull(encodedFrame, "encodedFrame");
            if (finished || !dataStarted || dataFrames >= header.entryCount()
                    || position != entry.frameOffset() || encodedFrame.length != entry.frameLength()) {
                throw new IOException("signing checkpoint frame boundary is inconsistent");
            }
            if (validate) {
                validateFrame(entry, encodedFrame);
            }
            writeAuthenticated(ByteBuffer.wrap(encodedFrame));
            dataFrames++;
        }

        /* default */ byte[] finish() throws IOException {
            if (finished) {
                throw new IllegalStateException("signing checkpoint writer is already finished");
            }
            if (!dataStarted || dataFrames != header.entryCount()) {
                throw new IOException("signing checkpoint data is incomplete");
            }
            finished = true;
            byte[] commitment = digest.digest();
            SigningFormatSupport.writeFully(channel, ByteBuffer.wrap(commitment));
            return commitment.clone();
        }

        private void writeAuthenticated(ByteBuffer source) throws IOException {
            int count = source.remaining();
            digest.update(source.asReadOnlyBuffer());
            SigningFormatSupport.writeFully(channel, source);
            position = Math.addExact(position, count);
        }
    }

    /** Thread-confined reader retaining only one bounded key and encoded frame. */
    @SuppressWarnings("PMD.AvoidMessageDigestField")
    /* default */ static final class Reader {
        private final SeekableByteChannel channel;
        private final Header header;
        private final long footerOffset;
        private final long commitmentIndexReadCalls;
        private final Cursor indexInput;
        private final Cursor dataInput;
        private final MessageDigest authenticated = SigningFormatSupport.sha256();
        private final byte[] fixed = new byte[ENTRY_FIXED_BYTES];
        private final ByteBuffer fixedView = ByteBuffer.wrap(fixed).order(ByteOrder.BIG_ENDIAN);
        private long expectedFrameOffset;
        private MetadataKey previousKey;
        private int read;
        private boolean verified;
        private byte[] fileCommitment;

        private Reader(SeekableByteChannel channel) throws IOException {
            this.channel = Objects.requireNonNull(channel, "channel");
            long size = channel.size();
            if (size < HEADER_BYTES + FOOTER_BYTES || size > MAX_CHECKPOINT_BYTES) {
                throw invalid("signing checkpoint length is invalid");
            }
            footerOffset = size - FOOTER_BYTES;
            Cursor headerInput = new Cursor(channel, 0L, size);
            byte[] encodedHeader = headerInput.readExact(HEADER_BYTES,
                    "signing checkpoint is truncated");
            header = decodeHeader(ByteBuffer.wrap(encodedHeader));
            if (header.dataOffset() < HEADER_BYTES || header.dataOffset() > footerOffset) {
                throw invalid("signing checkpoint data offset is invalid");
            }
            Cursor commitmentInput = new Cursor(channel, 0L, header.dataOffset());
            byte[] transfer = new byte[SigningFormatSupport.TRANSFER_BYTES];
            while (commitmentInput.position() < header.dataOffset()) {
                int count = (int) Math.min(transfer.length,
                        header.dataOffset() - commitmentInput.position());
                commitmentInput.readFully(transfer, 0, count,
                        "signing checkpoint index is truncated");
                authenticated.update(transfer, 0, count);
            }
            commitmentIndexReadCalls = commitmentInput.readCalls();
            indexInput = new Cursor(channel, HEADER_BYTES, header.dataOffset());
            dataInput = new Cursor(channel, header.dataOffset(), footerOffset);
            expectedFrameOffset = header.dataOffset();
        }

        /* default */ Header header() {
            return header;
        }

        // Sequential boundary, ordering, checksum, and EOF checks authenticate one cursor transition.
        @SuppressWarnings({ "PMD.PreserveStackTrace", "PMD.CyclomaticComplexity" })
        /* default */ Optional<EntryDescriptor> next() throws IOException {
            if (verified || read == header.entryCount()) {
                return Optional.empty();
            }
            int keyLength = indexInput.readInt("signing checkpoint entry is truncated");
            if (keyLength <= 0 || keyLength > MAX_KEY_BYTES) {
                throw invalid("signing checkpoint key length is invalid");
            }
            long entryLength = Math.addExact(keyLength, ENTRY_FIXED_BYTES);
            long end = Math.addExact(indexInput.position(), entryLength);
            if (end > header.dataOffset()) {
                throw invalid("signing checkpoint index is truncated");
            }
            byte[] key = indexInput.readExact(keyLength,
                    "signing checkpoint entry is truncated");
            indexInput.readFully(fixed, 0, fixed.length,
                    "signing checkpoint entry is truncated");
            fixedView.clear();
            String decodedKey = SigningFormatSupport.decodeCanonicalUtf8(key, MAX_KEY_BYTES);
            MetadataKey semanticKey;
            try {
                semanticKey = semanticKey(decodedKey);
            } catch (IllegalArgumentException failure) {
                throw invalid("signing checkpoint key is not a metadata identity");
            }
            if (previousKey != null && previousKey.compareTo(semanticKey) >= 0) {
                throw invalid("signing checkpoint keys are not canonical");
            }
            short typeCode = fixedView.getShort();
            short flags = fixedView.getShort();
            EntryDescriptor entry = new EntryDescriptor(decodedKey, recordType(typeCode),
                    fixedView.getLong(), fixedView.getInt(), fixedView.getLong(), fixedView.getLong());
            if (flags != FLAGS || entry.frameOffset() != expectedFrameOffset) {
                throw invalid("signing checkpoint entry framing is invalid");
            }
            try {
                requireEntry(entry, header);
            } catch (IllegalArgumentException failure) {
                throw invalid("signing checkpoint entry fields are invalid");
            }
            expectedFrameOffset = Math.addExact(expectedFrameOffset, entry.frameLength());
            previousKey = semanticKey;
            read++;
            return Optional.of(entry);
        }

        /* default */ SigningWalFrameCodec.Frame readFrame(EntryDescriptor entry) throws IOException {
            Objects.requireNonNull(entry, "entry");
            if (dataInput.position() != entry.frameOffset()) {
                throw invalid("signing checkpoint frame order is inconsistent");
            }
            byte[] encoded = dataInput.readExact(entry.frameLength(),
                    "signing checkpoint frame is truncated");
            authenticated.update(encoded);
            return validateFrame(entry, encoded);
        }

        /* default */ void verifyComplete() throws IOException {
            if (verified) {
                return;
            }
            if (read != header.entryCount() || indexInput.position() != header.dataOffset()
                    || expectedFrameOffset != footerOffset || dataInput.position() != footerOffset) {
                throw invalid("signing checkpoint framing is inconsistent");
            }
            Cursor footerInput = new Cursor(channel, footerOffset, channel.size());
            byte[] supplied = footerInput.readExact(FOOTER_BYTES,
                    "signing checkpoint commitment is truncated");
            MessageDigest wholeFile;
            try {
                wholeFile = (MessageDigest) authenticated.clone();
            } catch (CloneNotSupportedException failure) {
                throw new IOException("signing checkpoint digest state is unavailable", failure);
            }
            if (!MessageDigest.isEqual(authenticated.digest(), supplied)) {
                throw invalid("signing checkpoint commitment is invalid");
            }
            wholeFile.update(supplied);
            verified = true;
            fileCommitment = wholeFile.digest();
        }

        /* default */ byte[] fileCommitment() {
            if (!verified) {
                throw new IllegalStateException("signing checkpoint is not verified");
            }
            return fileCommitment.clone();
        }

        /* default */ ReadStatistics statistics() {
            return new ReadStatistics(Math.addExact(commitmentIndexReadCalls,
                    indexInput.readCalls()), dataInput.readCalls());
        }

    }

    private static Header requireHeader(Header header) {
        Objects.requireNonNull(header, "header");
        if (header.generationIdentity() < 0L || header.revision() < 0L
                || header.committedSequence() < 0L || header.entryCount() < 0
                || header.entryCount() > MAX_ENTRIES || header.dataOffset() < HEADER_BYTES
                || header.dataOffset() > MAX_CHECKPOINT_BYTES - FOOTER_BYTES) {
            throw new IllegalArgumentException("signing checkpoint header fields are invalid");
        }
        return header;
    }

    private static void requireEntry(EntryDescriptor entry, Header header) {
        Objects.requireNonNull(entry.recordType(), "recordType");
        if (entry.recordType() == SigningWalFrameCodec.RecordType.BATCH_COMMIT
                || entry.frameOffset() < header.dataOffset() || entry.frameLength() <= 0
                || entry.frameLength() > SigningWalFrameCodec.MAX_FRAME_BYTES
                || entry.revision() <= 0L || entry.revision() > header.revision()
                || entry.sequence() < 0L || entry.sequence() > header.committedSequence()) {
            throw new IllegalArgumentException("signing checkpoint entry fields are invalid");
        }
        try {
            Math.addExact(entry.frameOffset(), entry.frameLength());
        } catch (ArithmeticException failure) {
            throw new IllegalArgumentException("signing checkpoint frame pointer overflows", failure);
        }
    }

    private static SigningWalFrameCodec.Frame validateFrame(EntryDescriptor entry, byte[] encoded)
            throws IOException {
        SigningWalFrameCodec.Frame frame = SigningWalFrameCodec.decode(encoded);
        if (frame.recordType() != entry.recordType() || frame.sequence() != entry.sequence()) {
            throw invalid("signing checkpoint frame does not match its index entry");
        }
        return frame;
    }

    private static byte[] canonicalKey(String key) {
        return SigningFormatSupport.strictUtf8(key, MAX_KEY_BYTES);
    }

    private static MetadataKey semanticKey(String key) {
        MetadataKey parsed = MetadataKey.parse(key);
        if (!parsed.canonical().equals(key)) {
            throw new IllegalArgumentException("signing checkpoint key is not canonical");
        }
        return parsed;
    }

    private static ByteBuffer encodeHeader(Header header) {
        ByteBuffer output = ByteBuffer.allocate(HEADER_BYTES).order(ByteOrder.BIG_ENDIAN);
        output.putInt(MAGIC).putShort(VERSION).putShort(FLAGS)
                .putLong(header.generationIdentity()).putLong(header.revision())
                .putLong(header.committedSequence()).putInt(header.entryCount())
                .putLong(header.dataOffset()).flip();
        return output;
    }

    @SuppressWarnings("PMD.PreserveStackTrace")
    private static Header decodeHeader(ByteBuffer input) throws IOException {
        input.order(ByteOrder.BIG_ENDIAN);
        int magic = input.getInt();
        short version = input.getShort();
        short flags = input.getShort();
        Header header = new Header(input.getLong(), input.getLong(), input.getLong(),
                input.getInt(), input.getLong());
        if (magic != MAGIC || version != VERSION || flags != FLAGS) {
            throw invalid("signing checkpoint header is unsupported");
        }
        try {
            return requireHeader(header);
        } catch (IllegalArgumentException failure) {
            throw invalid("signing checkpoint header fields are invalid");
        }
    }

    private static SigningWalFrameCodec.RecordType recordType(short code) throws IOException {
        for (SigningWalFrameCodec.RecordType value : SigningWalFrameCodec.RecordType.values()) {
            if (value.wireCode() == code) {
                return value;
            }
        }
        throw invalid("signing checkpoint record type is unsupported");
    }

    private static IOException invalid(String diagnostic) {
        return SigningFormatSupport.invalid(diagnostic);
    }

    /* default */ record Header(long generationIdentity, long revision,
            long committedSequence, int entryCount, long dataOffset) {
    }

    /* default */ record EntryDescriptor(String key, SigningWalFrameCodec.RecordType recordType,
            long frameOffset, int frameLength, long revision, long sequence) {
        EntryDescriptor {
            Objects.requireNonNull(key, "key");
            Objects.requireNonNull(recordType, "recordType");
        }
    }

    /* default */ record ReadStatistics(long indexChannelReads, long dataChannelReads) {
    }

    /** Absolute-position buffered cursor; channel seeks are proportional to buffer refills. */
    private static final class Cursor {
        private final SeekableByteChannel channel;
        private final long limit;
        private final ByteBuffer buffer = ByteBuffer.allocate(SigningFormatSupport.TRANSFER_BYTES);
        private final byte[] integerBytes = new byte[Integer.BYTES];
        private long position;
        private long readCalls;

        private Cursor(SeekableByteChannel channel, long position, long limit) {
            this.channel = channel;
            this.position = position;
            this.limit = limit;
            buffer.limit(0);
        }

        private long position() {
            return position;
        }

        private long readCalls() { return readCalls; }

        private int readInt(String diagnostic) throws IOException {
            readFully(integerBytes, 0, integerBytes.length, diagnostic);
            return Byte.toUnsignedInt(integerBytes[0]) << 24
                    | Byte.toUnsignedInt(integerBytes[1]) << 16
                    | Byte.toUnsignedInt(integerBytes[2]) << 8
                    | Byte.toUnsignedInt(integerBytes[3]);
        }

        private byte[] readExact(int length, String diagnostic) throws IOException {
            byte[] result = new byte[length];
            readFully(result, 0, length, diagnostic);
            return result;
        }

        private void readFully(byte[] target, int offset, int length, String diagnostic)
                throws IOException {
            if (length < 0 || Math.addExact(position, length) > limit) {
                throw invalid(diagnostic);
            }
            int copied = 0;
            while (copied < length) {
                if (!buffer.hasRemaining()) {
                    refill(diagnostic);
                }
                int count = Math.min(length - copied, buffer.remaining());
                buffer.get(target, offset + copied, count);
                copied += count;
                position += count;
            }
        }

        private void refill(String diagnostic) throws IOException {
            channel.position(position);
            buffer.clear();
            buffer.limit((int) Math.min(buffer.capacity(), limit - position));
            int count = channel.read(buffer);
            readCalls++;
            if (count <= 0) {
                throw invalid(diagnostic);
            }
            buffer.flip();
        }
    }
}
