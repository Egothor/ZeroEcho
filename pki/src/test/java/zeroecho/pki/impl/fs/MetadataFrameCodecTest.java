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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;

final class MetadataFrameCodecTest {

    private static final String TOKEN = "00112233445566778899aabbccddeeff";
    private static final int HEADER_BYTES = 72;
    private static final int HEADER_FIELDS_BYTES = 40;
    private static final int PAYLOAD_DIGEST_BYTES = 32;
    private static final int VERSION_OFFSET = 4;
    private static final int TYPE_OFFSET = 6;
    private static final int FLAGS_OFFSET = 7;
    private static final int SEQUENCE_OFFSET = 24;
    private static final int PAYLOAD_LENGTH_OFFSET = 32;
    private static final int HEADER_DIGEST_OFFSET = 40;

    @TempDir
    Path temporaryDirectory;

    @Test
    void allFrameTypesUseOneCanonicalRoundTrip() throws IOException {
        System.out.print("allFrameTypesUseOneCanonicalRoundTrip ");
        MetadataFrameCodec codec = new MetadataFrameCodec();
        Path path = temporaryDirectory.resolve("all-types.frames");
        long offset = 0L;
        try (FileChannel channel = open(path)) {
            for (MetadataFrameCodec.FrameType frameType : MetadataFrameCodec.FrameType.values()) {
                long sequence = frameType.ordinal();
                GeneratedContent content = GeneratedContent.known(3L, frameType.ordinal());
                MetadataFrameCodec.FrameMetadata written = codec.write(
                        channel, frameType, TOKEN, sequence, 3L, content, CancellationSignal.NONE);
                assertEquals(offset, written.frameOffset());
                MetadataFrameCodec.ReadResult result = codec.read(channel, offset);
                assertEquals(MetadataFrameCodec.ReadClassification.COMPLETE_FRAME, result.classification());
                assertEquals(frameType, result.metadata().frameType());
                assertEquals(TOKEN, result.metadata().transactionToken());
                assertEquals(sequence, result.metadata().sequence());
                assertEquals(3L, result.metadata().payloadLength());
                offset = result.metadata().frameEndOffset();
                channel.position(offset);
            }
            assertEquals(offset, channel.size());
        }
        System.out.println("...ok");
    }

    @Test
    void zeroAndMultiBufferPayloadsRemainStreaming() throws IOException {
        System.out.print("zeroAndMultiBufferPayloadsRemainStreaming ");
        MetadataFrameCodec codec = new MetadataFrameCodec();
        Path path = temporaryDirectory.resolve("streaming.frames");
        try (FileChannel channel = open(path)) {
            MetadataFrameCodec.FrameMetadata zero = codec.write(
                    channel,
                    MetadataFrameCodec.FrameType.STORE_HEADER,
                    TOKEN,
                    0L,
                    0L,
                    GeneratedContent.known(0L, 0),
                    CancellationSignal.NONE);
            assertEquals(HEADER_BYTES, zero.payloadOffset());
            channel.position(zero.frameEndOffset());
            long largeLength = 3L * 16L * 1024L + 37L;
            MetadataFrameCodec.FrameMetadata large = codec.write(
                    channel,
                    MetadataFrameCodec.FrameType.MUTATION_CREATE,
                    TOKEN,
                    1L,
                    largeLength,
                    GeneratedContent.unknown(largeLength, 91),
                    CancellationSignal.NONE);
            assertEquals(
                    MetadataFrameCodec.ReadClassification.COMPLETE_FRAME,
                    codec.read(channel, large.frameOffset()).classification());
            assertTrue(largeLength > 16L * 1024L);
        }
        System.out.println("...ok");
    }

    @Test
    void partialHeaderAtEveryBoundaryIsIncompleteTail() throws IOException {
        System.out.print("partialHeaderAtEveryBoundaryIsIncompleteTail ");
        byte[] complete = encodedFrame(GeneratedContent.known(1L, 7), 1L);
        Path path = temporaryDirectory.resolve("partial-header.frame");
        MetadataFrameCodec codec = new MetadataFrameCodec();
        writeBytes(path, new byte[0]);
        assertClassification(codec, path, MetadataFrameCodec.ReadClassification.END_OF_INPUT);
        for (int length = 1; length < HEADER_BYTES; length++) {
            writeBytes(path, Arrays.copyOf(complete, length));
            assertClassification(codec, path, MetadataFrameCodec.ReadClassification.INCOMPLETE_TAIL);
        }
        System.out.println("...ok");
    }

    @Test
    void hostileAuthenticatedHeaderFieldsFailClosed() throws IOException {
        System.out.print("hostileAuthenticatedHeaderFieldsFailClosed ");
        byte[] canonical = encodedFrame(GeneratedContent.known(2L, 5), 2L);
        assertCorruptAfterMutation(canonical, bytes -> bytes[0] ^= 1, false, "magic");
        assertCorruptAfterMutation(canonical, bytes -> bytes[HEADER_DIGEST_OFFSET] ^= 1, false, "digest");
        assertCorruptAfterMutation(canonical, bytes -> putShort(bytes, VERSION_OFFSET, (short) 2), true, "version");
        assertCorruptAfterMutation(canonical, bytes -> bytes[TYPE_OFFSET] = 99, true, "type");
        assertCorruptAfterMutation(canonical, bytes -> bytes[FLAGS_OFFSET] = 1, true, "flags");
        assertCorruptAfterMutation(canonical, bytes -> putLong(bytes, SEQUENCE_OFFSET, -1L), true, "sequence");
        assertCorruptAfterMutation(canonical, bytes -> putLong(bytes, PAYLOAD_LENGTH_OFFSET, -1L), true, "length");
        assertCorruptAfterMutation(
                canonical, bytes -> putLong(bytes, PAYLOAD_LENGTH_OFFSET, Long.MAX_VALUE), true, "overflow");
        System.out.println("...ok");
    }

    @Test
    void unauthenticatedLengthCorruptionIsNeverIncompleteTail() throws IOException {
        System.out.print("unauthenticatedLengthCorruptionIsNeverIncompleteTail ");
        byte[] encoded = encodedFrame(GeneratedContent.known(4L, 3), 4L);
        putLong(encoded, PAYLOAD_LENGTH_OFFSET, Long.MAX_VALUE);
        Path path = temporaryDirectory.resolve("tampered-length.frame");
        writeBytes(path, encoded);
        MetadataFrameCodec.ReadResult result = read(new MetadataFrameCodec(), path, 0L);
        assertEquals(MetadataFrameCodec.ReadClassification.CORRUPT_FRAME, result.classification());
        assertFalse(result.classification() == MetadataFrameCodec.ReadClassification.INCOMPLETE_TAIL);
        System.out.println("...ok");
    }

    @Test
    void payloadTruncationAndDigestMismatchAreDistinguished() throws IOException {
        System.out.print("payloadTruncationAndDigestMismatchAreDistinguished ");
        byte[] encoded = encodedFrame(GeneratedContent.known(5L, 29), 5L);
        Path path = temporaryDirectory.resolve("payload-integrity.frame");
        writeBytes(path, Arrays.copyOf(encoded, HEADER_BYTES + 4));
        assertClassification(new MetadataFrameCodec(), path, MetadataFrameCodec.ReadClassification.INCOMPLETE_TAIL);
        writeBytes(path, Arrays.copyOf(encoded, encoded.length - 1));
        assertClassification(new MetadataFrameCodec(), path, MetadataFrameCodec.ReadClassification.INCOMPLETE_TAIL);
        byte[] corrupt = encoded.clone();
        corrupt[HEADER_BYTES + 2] ^= 1;
        writeBytes(path, corrupt);
        assertClassification(new MetadataFrameCodec(), path, MetadataFrameCodec.ReadClassification.CORRUPT_FRAME);
        System.out.println("...ok");
    }

    @Test
    void technicalLimitIsAdapterControlled() throws IOException {
        System.out.print("technicalLimitIsAdapterControlled ");
        MetadataFrameCodec limited = new MetadataFrameCodec(OptionalLong.of(4L));
        Path boundary = temporaryDirectory.resolve("limit-boundary.frame");
        try (FileChannel channel = open(boundary)) {
            limited.write(
                    channel,
                    MetadataFrameCodec.FrameType.MUTATION_REPLACE,
                    TOKEN,
                    2L,
                    4L,
                    GeneratedContent.unknown(4L, 1),
                    CancellationSignal.NONE);
        }
        Path over = temporaryDirectory.resolve("limit-over.frame");
        try (FileChannel channel = open(over)) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> limited.write(
                            channel,
                            MetadataFrameCodec.FrameType.MUTATION_REPLACE,
                            TOKEN,
                            3L,
                            5L,
                            GeneratedContent.unknown(5L, 1),
                            CancellationSignal.NONE));
        }
        byte[] encodedOver = encodedFrame(GeneratedContent.known(5L, 1), 5L);
        writeBytes(over, encodedOver);
        assertClassification(limited, over, MetadataFrameCodec.ReadClassification.CORRUPT_FRAME);
        System.out.println("...ok");
    }

    @Test
    void writerRejectsLengthMismatchAndObservesCancellation() throws IOException {
        System.out.print("writerRejectsLengthMismatchAndObservesCancellation ");
        MetadataFrameCodec codec = new MetadataFrameCodec();
        Path path = temporaryDirectory.resolve("writer-validation.frame");
        try (FileChannel channel = open(path)) {
            assertThrows(
                    IOException.class,
                    () -> codec.write(
                            channel,
                            MetadataFrameCodec.FrameType.MUTATION_CREATE,
                            TOKEN,
                            0L,
                            2L,
                            GeneratedContent.unknown(3L, 4),
                            CancellationSignal.NONE));
        }
        try (FileChannel channel = open(path)) {
            assertThrows(
                    IOException.class,
                    () -> codec.write(
                            channel,
                            MetadataFrameCodec.FrameType.MUTATION_CREATE,
                            TOKEN,
                            0L,
                            4L,
                            GeneratedContent.unknown(3L, 4),
                            CancellationSignal.NONE));
        }
        GeneratedContent unopened = GeneratedContent.unknown(1L, 2);
        try (FileChannel channel = open(path)) {
            assertThrows(
                    InterruptedIOException.class,
                    () -> codec.write(
                            channel,
                            MetadataFrameCodec.FrameType.MUTATION_CREATE,
                            TOKEN,
                            0L,
                            1L,
                            unopened,
                            () -> true));
        }
        assertEquals(0, unopened.openCount());

        GeneratedContent cancellable = GeneratedContent.unknown(40_000L, 8);
        AtomicInteger checks = new AtomicInteger();
        try (FileChannel channel = open(path)) {
            assertThrows(
                    InterruptedIOException.class,
                    () -> codec.write(
                            channel,
                            MetadataFrameCodec.FrameType.MUTATION_CREATE,
                            TOKEN,
                            0L,
                            40_000L,
                            cancellable,
                            () -> checks.incrementAndGet() > 2));
        }
        assertTrue(cancellable.closedStream());
        System.out.println("...ok");
    }

    @Test
    void decoderLeavesNextFrameUnreadAndIsDeterministic() throws IOException {
        System.out.print("decoderLeavesNextFrameUnreadAndIsDeterministic ");
        MetadataFrameCodec codec = new MetadataFrameCodec();
        Path path = temporaryDirectory.resolve("two.frames");
        MetadataFrameCodec.FrameMetadata first;
        MetadataFrameCodec.FrameMetadata second;
        try (FileChannel channel = open(path)) {
            first = codec.write(
                    channel,
                    MetadataFrameCodec.FrameType.TRANSACTION_ISSUED,
                    TOKEN,
                    0L,
                    2L,
                    GeneratedContent.known(2L, 11),
                    CancellationSignal.NONE);
            second = codec.write(
                    channel,
                    MetadataFrameCodec.FrameType.TERMINAL_COMMITTED,
                    TOKEN,
                    1L,
                    1L,
                    GeneratedContent.known(1L, 12),
                    CancellationSignal.NONE);

            MetadataFrameCodec.ReadResult firstRead = codec.read(channel, first.frameOffset());
            assertEquals(first.frameEndOffset(), channel.position());
            assertEquals(second.frameOffset(), channel.position());
            MetadataFrameCodec.ReadResult repeated = codec.read(channel, first.frameOffset());
            assertEquals(firstRead, repeated);
            MetadataFrameCodec.ReadResult secondRead = codec.read(channel, second.frameOffset());
            assertEquals(MetadataFrameCodec.ReadClassification.COMPLETE_FRAME, secondRead.classification());
            assertEquals(second.frameEndOffset(), channel.position());
            assertEquals(
                    MetadataFrameCodec.ReadClassification.END_OF_INPUT,
                    codec.read(channel, second.frameEndOffset()).classification());
        }
        System.out.println("...ok");
    }

    @Test
    void partialProgressWorksAndZeroProgressFails() throws IOException {
        System.out.print("partialProgressWorksAndZeroProgressFails ");
        MetadataFrameCodec codec = new MetadataFrameCodec();
        Path shortProgress = temporaryDirectory.resolve("short-progress.frame");
        try (FileChannel file = open(shortProgress);
                ControlledChannel channel = new ControlledChannel(file, 3, 2, 0, 0, null)) {
            codec.write(
                    channel,
                    MetadataFrameCodec.FrameType.MUTATION_CREATE,
                    TOKEN,
                    0L,
                    19L,
                    GeneratedContent.known(19L, 31),
                    CancellationSignal.NONE);
            assertEquals(
                    MetadataFrameCodec.ReadClassification.COMPLETE_FRAME,
                    codec.read(channel, 0L).classification());
        }

        Path zeroWrite = temporaryDirectory.resolve("zero-write.frame");
        try (FileChannel file = open(zeroWrite);
                ControlledChannel channel = new ControlledChannel(file, 8, 8, 0, 1, null)) {
            assertThrows(
                    IOException.class,
                    () -> codec.write(
                            channel,
                            MetadataFrameCodec.FrameType.MUTATION_CREATE,
                            TOKEN,
                            0L,
                            1L,
                            GeneratedContent.known(1L, 1),
                            CancellationSignal.NONE));
        }

        Path zeroRead = temporaryDirectory.resolve("zero-read.frame");
        writeBytes(zeroRead, encodedFrame(GeneratedContent.known(1L, 2), 1L));
        try (FileChannel file = FileChannel.open(zeroRead, StandardOpenOption.READ);
                ControlledChannel channel = new ControlledChannel(file, 8, 8, 1, 0, null)) {
            assertThrows(IOException.class, () -> codec.read(channel, 0L));
        }
        System.out.println("...ok");
    }

    @Test
    void cancellationDuringHeaderWritePreventsContentOpen() throws IOException {
        System.out.print("cancellationDuringHeaderWritePreventsContentOpen ");
        MetadataFrameCodec codec = new MetadataFrameCodec();
        GeneratedContent content = GeneratedContent.known(1L, 1);
        AtomicInteger cancellationState = new AtomicInteger();
        Path path = temporaryDirectory.resolve("cancel-before-open.frame");
        try (FileChannel file = open(path);
                ControlledChannel channel = new ControlledChannel(
                        file, HEADER_BYTES, HEADER_BYTES, 0, 0, () -> cancellationState.set(1))) {
            assertThrows(
                    InterruptedIOException.class,
                    () -> codec.write(
                            channel,
                            MetadataFrameCodec.FrameType.MUTATION_CREATE,
                            TOKEN,
                            0L,
                            1L,
                            content,
                            () -> cancellationState.get() != 0));
        }
        assertEquals(0, content.openCount());
        System.out.println("...ok");
    }

    private byte[] encodedFrame(GeneratedContent content, long declaredLength) throws IOException {
        Path path = temporaryDirectory.resolve("source-" + System.nanoTime() + ".frame");
        MetadataFrameCodec codec = new MetadataFrameCodec();
        try (FileChannel channel = open(path)) {
            codec.write(
                    channel,
                    MetadataFrameCodec.FrameType.MUTATION_CREATE,
                    TOKEN,
                    0L,
                    declaredLength,
                    content,
                    CancellationSignal.NONE);
        }
        long size = Files.size(path);
        byte[] result = new byte[Math.toIntExact(size)];
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            ByteBuffer target = ByteBuffer.wrap(result);
            while (target.hasRemaining()) {
                channel.read(target);
            }
        }
        return result;
    }

    private void assertCorruptAfterMutation(
            byte[] canonical, ByteMutation mutation, boolean refreshDigest, String name) throws IOException {
        byte[] changed = canonical.clone();
        mutation.apply(changed);
        if (refreshDigest) {
            refreshHeaderDigest(changed);
        }
        Path path = temporaryDirectory.resolve("hostile-" + name + ".frame");
        writeBytes(path, changed);
        assertClassification(new MetadataFrameCodec(), path, MetadataFrameCodec.ReadClassification.CORRUPT_FRAME);
    }

    private static MetadataFrameCodec.ReadResult read(MetadataFrameCodec codec, Path path, long offset)
            throws IOException {
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            return codec.read(channel, offset);
        }
    }

    private static void assertClassification(
            MetadataFrameCodec codec, Path path, MetadataFrameCodec.ReadClassification expected) throws IOException {
        assertEquals(expected, read(codec, path, 0L).classification());
    }

    private static FileChannel open(Path path) throws IOException {
        return FileChannel.open(
                path,
                StandardOpenOption.CREATE,
                StandardOpenOption.READ,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING);
    }

    private static void writeBytes(Path path, byte[] bytes) throws IOException {
        try (FileChannel channel = open(path)) {
            ByteBuffer source = ByteBuffer.wrap(bytes);
            while (source.hasRemaining()) {
                channel.write(source);
            }
        }
    }

    private static void refreshHeaderDigest(byte[] frame) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 is unavailable", failure);
        }
        byte[] authenticated = digest.digest(Arrays.copyOf(frame, HEADER_FIELDS_BYTES));
        System.arraycopy(authenticated, 0, frame, HEADER_DIGEST_OFFSET, PAYLOAD_DIGEST_BYTES);
    }

    private static void putShort(byte[] bytes, int offset, short value) {
        ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN).putShort(offset, value);
    }

    private static void putLong(byte[] bytes, int offset, long value) {
        ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN).putLong(offset, value);
    }

    @FunctionalInterface
    private interface ByteMutation {
        void apply(byte[] bytes);
    }

    private static final class ControlledChannel implements SeekableByteChannel {
        private final SeekableByteChannel delegate;
        private final int maximumWrite;
        private final int maximumRead;
        private final int zeroReadCall;
        private final int zeroWriteCall;
        private final Runnable afterFirstWrite;
        private int readCalls;
        private int writeCalls;

        private ControlledChannel(
                SeekableByteChannel delegate,
                int maximumWrite,
                int maximumRead,
                int zeroReadCall,
                int zeroWriteCall,
                Runnable afterFirstWrite) {
            this.delegate = delegate;
            this.maximumWrite = maximumWrite;
            this.maximumRead = maximumRead;
            this.zeroReadCall = zeroReadCall;
            this.zeroWriteCall = zeroWriteCall;
            this.afterFirstWrite = afterFirstWrite;
        }

        @Override
        public int read(ByteBuffer destination) throws IOException {
            readCalls++;
            if (readCalls == zeroReadCall) {
                return 0;
            }
            int originalLimit = destination.limit();
            destination.limit(destination.position() + Math.min(destination.remaining(), maximumRead));
            try {
                return delegate.read(destination);
            } finally {
                destination.limit(originalLimit);
            }
        }

        @Override
        public int write(ByteBuffer source) throws IOException {
            writeCalls++;
            if (writeCalls == zeroWriteCall) {
                return 0;
            }
            int originalLimit = source.limit();
            source.limit(source.position() + Math.min(source.remaining(), maximumWrite));
            int written;
            try {
                written = delegate.write(source);
            } finally {
                source.limit(originalLimit);
            }
            if (writeCalls == 1 && afterFirstWrite != null) {
                afterFirstWrite.run();
            }
            return written;
        }

        @Override
        public long position() throws IOException {
            return delegate.position();
        }

        @Override
        public SeekableByteChannel position(long newPosition) throws IOException {
            delegate.position(newPosition);
            return this;
        }

        @Override
        public long size() throws IOException {
            return delegate.size();
        }

        @Override
        public SeekableByteChannel truncate(long size) throws IOException {
            delegate.truncate(size);
            return this;
        }

        @Override
        public boolean isOpen() {
            return delegate.isOpen();
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }

    private static final class GeneratedContent implements RepeatableContent {
        private final long length;
        private final int seed;
        private final boolean knownLength;
        private final AtomicInteger openCount = new AtomicInteger();
        private volatile boolean closedStream;

        private GeneratedContent(long length, int seed, boolean knownLength) {
            this.length = length;
            this.seed = seed;
            this.knownLength = knownLength;
        }

        private static GeneratedContent known(long length, int seed) {
            return new GeneratedContent(length, seed, true);
        }

        private static GeneratedContent unknown(long length, int seed) {
            return new GeneratedContent(length, seed, false);
        }

        @Override
        public InputStream openStream() {
            openCount.incrementAndGet();
            return new InputStream() {
                private long position;
                private boolean closed;

                @Override
                public int read() {
                    if (position >= length) {
                        return -1;
                    }
                    int value = (int) ((position + seed) & 0xFFL);
                    position++;
                    return value;
                }

                @Override
                public int read(byte[] bytes, int offset, int requested) {
                    if (position >= length) {
                        return -1;
                    }
                    int actual = (int) Math.min((long) requested, length - position);
                    for (int index = 0; index < actual; index++) {
                        bytes[offset + index] = (byte) ((position + index + seed) & 0xFFL);
                    }
                    position += actual;
                    return actual;
                }

                @Override
                public void close() {
                    if (!closed) {
                        closed = true;
                        closedStream = true;
                    }
                }
            };
        }

        @Override
        public OptionalLong length() {
            return knownLength ? OptionalLong.of(length) : OptionalLong.empty();
        }

        @Override
        public String contentId() {
            return "generated-test-content";
        }

        @Override
        public void close() {
            // The caller retains the repeatable-content wrapper.
        }

        private int openCount() {
            return openCount.get();
        }

        private boolean closedStream() {
            return closedStream;
        }
    }
}
