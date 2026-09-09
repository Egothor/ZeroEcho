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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class SigningWalFrameCodecTest {

    @TempDir
    private Path temporaryDirectory;

    @Test
    void canonicalGoldenRoundTripAndBoundaries() throws Exception {
        SigningWalFrameCodec.Frame frame = frame(7L, new byte[] { 1, 2, 3 });
        byte[] encoded = SigningWalFrameCodec.encode(frame);
        assertEquals("5a4557460001002c000000330001000000000000000000070123456789abcdef"
                + "fedcba9876543210000000030102036883a58c", hex(encoded));
        SigningWalFrameCodec.Frame decoded = SigningWalFrameCodec.decode(encoded);
        assertEquals(frame.recordType(), decoded.recordType());
        assertEquals(frame.transactionId(), decoded.transactionId());
        assertEquals(frame.sequence(), decoded.sequence());
        assertArrayEquals(frame.payload(), decoded.payload());
        assertThrows(IllegalArgumentException.class, () -> frame(-1L, new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> frame(0L,
                new byte[SigningWalFrameCodec.MAX_PAYLOAD_BYTES + 1]));
    }

    @Test
    void malformedFrameAndContainerFailClosed() throws Exception {
        byte[] valid = SigningWalFrameCodec.encode(frame(0L, new byte[] { 4 }));
        for (int offset : List.of(0, 4, 12, 14, 40, valid.length - 1)) {
            byte[] malformed = valid.clone();
            malformed[offset] ^= 1;
            assertThrows(IOException.class, () -> SigningWalFrameCodec.decode(malformed));
        }
        assertThrows(IOException.class, () -> SigningWalFrameCodec.decode(Arrays.copyOf(valid, valid.length - 1)));
        SigningWalContainerCodec.Header header = new SigningWalContainerCodec.Header(4L, 9L, 7L);
        byte[] container = SigningWalContainerCodec.encode(header);
        assertEquals(header, SigningWalContainerCodec.decode(container));
        container[container.length - 1] ^= 1;
        assertThrows(IOException.class, () -> SigningWalContainerCodec.decode(container));
    }

    @Test
    void committedGroupsAreDeliveredAndUnmarkedSuffixIsNot() throws Exception {
        WalFixture fixture = new WalFixture(10L);
        fixture.appendCommitted(List.of(frame(10L, new byte[] { 1 }), frame(11L, new byte[] { 2 })), 3L);
        fixture.appendCommitted(List.of(frame(12L, new byte[] { 3 })), 4L);
        long unmarkedOffset = fixture.size();
        fixture.appendRaw(SigningWalFrameCodec.encode(frame(13L, new byte[] { 4 })));
        List<SigningWalFrameCodec.Frame> delivered = new ArrayList<>();
        SigningWalFrameCodec.ScanResult result = fixture.scan(true, delivered);
        assertEquals(List.of(10L, 11L, 12L), delivered.stream().map(
                SigningWalFrameCodec.Frame::sequence).toList());
        assertEquals(3L, result.frameCount());
        assertEquals(12L, result.lastSequence());
        assertEquals(unmarkedOffset, result.incompleteTailOffset());
        assertTrue(result.hasIncompleteTail());
        assertThrows(IOException.class, () -> fixture.scan(false, new ArrayList<>()));
    }

    @Test
    void recoveryPayloadViewIsCallbackScopedAndReadOnly() throws Exception {
        WalFixture fixture = new WalFixture(0L);
        fixture.appendCommitted(List.of(frame(0L, new byte[] { 7, 8 })), 1L);
        try (SeekableByteChannel channel = Files.newByteChannel(fixture.path,
                StandardOpenOption.READ)) {
            SigningWalFrameCodec.scanGroups(channel, 0L, false, (frames, marker) -> {
                ByteBuffer payload = frames.get(0).payloadView();
                assertEquals(7, payload.get(0));
                assertThrows(ReadOnlyBufferException.class, () -> payload.put(0, (byte) 9));
                assertArrayEquals(new byte[] { 7, 8 }, frames.get(0).frame().payload());
            });
        }
    }

    @Test
    void tornCorruptAndReorderedGroupsNeverDeliverUncommittedFrames() throws Exception {
        WalFixture torn = new WalFixture(0L);
        torn.appendRaw(Arrays.copyOf(SigningWalFrameCodec.encode(frame(0L, new byte[] { 1 })), 45));
        List<SigningWalFrameCodec.Frame> tornDelivered = new ArrayList<>();
        assertTrue(torn.scan(true, tornDelivered).hasIncompleteTail());
        assertTrue(tornDelivered.isEmpty());

        WalFixture corrupt = new WalFixture(0L);
        corrupt.appendCommitted(List.of(frame(0L, new byte[] { 1 })), 1L);
        byte[] bytes = corrupt.bytes();
        bytes[SigningWalContainerCodec.HEADER_BYTES + SigningWalFrameCodec.HEADER_BYTES] ^= 1;
        corrupt.replace(bytes);
        List<SigningWalFrameCodec.Frame> corruptDelivered = new ArrayList<>();
        assertThrows(IOException.class, () -> corrupt.scan(true, corruptDelivered));
        assertTrue(corruptDelivered.isEmpty());

        WalFixture reordered = new WalFixture(0L);
        reordered.appendCommitted(List.of(frame(0L, new byte[] { 1 }),
                frame(1L, new byte[] { 2 })), 1L);
        byte[] reorderedBytes = reordered.bytes();
        int start = SigningWalContainerCodec.HEADER_BYTES;
        int frameLength = SigningWalFrameCodec.HEADER_BYTES + 1 + SigningWalFrameCodec.CHECKSUM_BYTES;
        byte[] first = Arrays.copyOfRange(reorderedBytes, start, start + frameLength);
        byte[] second = Arrays.copyOfRange(reorderedBytes, start + frameLength,
                start + 2 * frameLength);
        System.arraycopy(second, 0, reorderedBytes, start, frameLength);
        System.arraycopy(first, 0, reorderedBytes, start + frameLength, frameLength);
        reordered.replace(reorderedBytes);
        List<SigningWalFrameCodec.Frame> reorderedDelivered = new ArrayList<>();
        assertThrows(IOException.class, () -> reordered.scan(true, reorderedDelivered));
        assertTrue(reorderedDelivered.isEmpty());
    }

    @Test
    void corruptedOrMissingMarkerDoesNotPartiallyApplyGroup() throws Exception {
        WalFixture fixture = new WalFixture(0L);
        fixture.appendCommitted(List.of(frame(0L, new byte[] { 1 }), frame(1L, new byte[] { 2 })), 1L);
        byte[] bytes = fixture.bytes();
        bytes[bytes.length - 1] ^= 1;
        fixture.replace(bytes);
        List<SigningWalFrameCodec.Frame> delivered = new ArrayList<>();
        assertThrows(IOException.class, () -> fixture.scan(true, delivered));
        assertTrue(delivered.isEmpty());

        WalFixture missing = new WalFixture(0L);
        missing.appendRaw(SigningWalFrameCodec.encode(frame(0L, new byte[] { 1 })));
        delivered.clear();
        SigningWalFrameCodec.ScanResult result = missing.scan(true, delivered);
        assertTrue(result.hasIncompleteTail());
        assertTrue(delivered.isEmpty());

        WalFixture torn = new WalFixture(0L);
        torn.appendCommitted(List.of(frame(0L, new byte[] { 1 })), 1L);
        byte[] tornBytes = torn.bytes();
        torn.replace(Arrays.copyOf(tornBytes, tornBytes.length - 10));
        delivered.clear();
        assertTrue(torn.scan(true, delivered).hasIncompleteTail());
        assertTrue(delivered.isEmpty());
    }

    @Test
    void committedRevisionMustIncreaseAcrossGroups() throws Exception {
        WalFixture equalBaseline = new WalFixture(0L, 1L);
        assertThrows(IllegalArgumentException.class,
                () -> equalBaseline.appendCommitted(List.of(frame(0L, new byte[] { 0 })), 1L));
        equalBaseline.appendWithDeclaredPrevious(List.of(frame(0L, new byte[] { 0 })), 0L, 1L);
        assertThrows(IOException.class, () -> equalBaseline.scan(true, new ArrayList<>()));

        WalFixture accepted = new WalFixture(0L, 1L);
        accepted.appendCommitted(List.of(frame(0L, new byte[] { 1 })), 2L);
        SigningWalFrameCodec.ScanResult acceptedResult = accepted.scan(true, new ArrayList<>());
        assertEquals(2L, acceptedResult.committedRevision());

        WalFixture fixture = new WalFixture(0L);
        fixture.appendCommitted(List.of(frame(0L, new byte[] { 1 })), 2L);
        fixture.appendWithDeclaredPrevious(List.of(frame(1L, new byte[] { 2 })), 0L, 1L);
        List<SigningWalFrameCodec.Frame> delivered = new ArrayList<>();
        assertThrows(IOException.class, () -> fixture.scan(true, delivered));
        assertEquals(1, delivered.size());
        assertEquals(0L, delivered.get(0).sequence());
    }

    @Test
    void batchCountIsBoundedBeforeWriting() throws Exception {
        WalFixture fixture = new WalFixture(0L);
        ArrayList<SigningWalFrameCodec.Frame> frames = new ArrayList<>();
        for (int index = 0; index <= SigningWalFrameCodec.MAX_BATCH_FRAMES; index++) {
            frames.add(frame(index, new byte[0]));
        }
        assertThrows(IllegalArgumentException.class, () -> fixture.appendCommitted(frames, 1L));
    }

    @Test
    void aggregateEncodingIsByteEquivalentToCommittedChannelEncoding() throws Exception {
        List<SigningWalFrameCodec.Frame> frames = List.of(
                frame(0L, new byte[] { 1, 2, 3 }), frame(1L, new byte[] { 4, 5 }));
        byte[] previous = SigningFormatSupport.sha256().digest(new byte[] { 9 });
        ByteArrayOutputStream channelBytes = new ByteArrayOutputStream();
        SigningWalFrameCodec.writeCommittedBatch(Channels.newChannel(channelBytes),
                frames, 4L, 6L, previous);

        ByteBuffer aggregate = ByteBuffer.allocate(4096);
        aggregate.position(11);
        int start = aggregate.position();
        SigningWalFrameCodec.encodeCommittedBatch(aggregate, frames, 4L, 6L, previous);
        assertArrayEquals(channelBytes.toByteArray(),
                Arrays.copyOfRange(aggregate.array(), start, aggregate.position()));
    }

    @Test
    void largeScanUsesSequentialTransferBuffersRatherThanPerFrameReads() throws Exception {
        Path path = Files.createTempFile(temporaryDirectory, "buffered-wal-", ".zew");
        byte[] container = SigningWalContainerCodec.encode(
                new SigningWalContainerCodec.Header(1L, 0L, 0L));
        Files.write(path, container, StandardOpenOption.TRUNCATE_EXISTING);
        byte[] rolling = SigningFormatSupport.sha256().digest(container);
        long revision = 0L;
        int frameCount = 10_000;
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.APPEND)) {
            for (int start = 0; start < frameCount; start += SigningWalFrameCodec.MAX_BATCH_FRAMES) {
                int count = Math.min(SigningWalFrameCodec.MAX_BATCH_FRAMES, frameCount - start);
                List<SigningWalFrameCodec.Frame> group = new ArrayList<>(count);
                for (int index = 0; index < count; index++) {
                    group.add(frame(start + index, new byte[] { 1 }));
                }
                revision += count;
                SigningWalFrameCodec.BatchCommit commit = SigningWalFrameCodec.writeCommittedBatch(
                        channel, group, revision - count, revision, rolling);
                rolling = commit.resultingCommitment();
            }
        }
        try (FileChannel file = FileChannel.open(path, StandardOpenOption.READ);
                CountingChannel channel = new CountingChannel(file)) {
            SigningWalFrameCodec.ScanResult result = SigningWalFrameCodec.scanGroups(channel,
                    0L, false, (frames, marker) -> { }, false);
            assertEquals(frameCount, result.frameCount());
            assertTrue(channel.readCalls < 100L);
            assertEquals(1L, channel.positionSetCalls);
        }
    }

    private static SigningWalFrameCodec.Frame frame(long sequence, byte[] payload) {
        return new SigningWalFrameCodec.Frame(SigningWalFrameCodec.RecordType.INTENT,
                UUID.fromString("01234567-89ab-cdef-fedc-ba9876543210"), sequence, payload);
    }

    private static String hex(byte[] bytes) {
        return java.util.HexFormat.of().formatHex(bytes);
    }

    private final class WalFixture {
        private final Path path = Files.createTempFile(temporaryDirectory, "wal-", ".zew");
        private final long firstSequence;
        private byte[] rollingCommitment;
        private long committedRevision;

        private WalFixture(long firstSequence) throws IOException {
            this(firstSequence, 0L);
        }

        private WalFixture(long firstSequence, long baselineRevision) throws IOException {
            this.firstSequence = firstSequence;
            committedRevision = baselineRevision;
            byte[] container = SigningWalContainerCodec.encode(
                    new SigningWalContainerCodec.Header(1L, firstSequence, baselineRevision));
            Files.write(path, container, StandardOpenOption.TRUNCATE_EXISTING);
            rollingCommitment = SigningFormatSupport.sha256().digest(container);
        }

        private void appendCommitted(List<SigningWalFrameCodec.Frame> frames, long revision) throws IOException {
            appendWithDeclaredPrevious(frames, committedRevision, revision);
        }

        private void appendWithDeclaredPrevious(List<SigningWalFrameCodec.Frame> frames,
                long declaredPreviousRevision, long revision) throws IOException {
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.APPEND)) {
                SigningWalFrameCodec.BatchCommit commit = SigningWalFrameCodec.writeCommittedBatch(
                        channel, frames, declaredPreviousRevision, revision, rollingCommitment);
                rollingCommitment = commit.resultingCommitment();
                committedRevision = revision;
            }
        }

        private void appendRaw(byte[] bytes) throws IOException {
            Files.write(path, bytes, StandardOpenOption.APPEND);
        }

        private SigningWalFrameCodec.ScanResult scan(boolean active,
                List<SigningWalFrameCodec.Frame> delivered) throws IOException {
            try (SeekableByteChannel channel = Files.newByteChannel(path, StandardOpenOption.READ)) {
                return SigningWalFrameCodec.scan(channel, firstSequence, active, delivered::add);
            }
        }

        private long size() throws IOException {
            return Files.size(path);
        }

        private byte[] bytes() throws IOException {
            return Files.readAllBytes(path);
        }

        private void replace(byte[] bytes) throws IOException {
            Files.write(path, bytes, StandardOpenOption.TRUNCATE_EXISTING);
        }
    }

    private static final class CountingChannel implements SeekableByteChannel {
        private final SeekableByteChannel delegate;
        private long readCalls;
        private long positionSetCalls;
        private CountingChannel(SeekableByteChannel delegate) { this.delegate = delegate; }
        @Override public int read(ByteBuffer target) throws IOException {
            readCalls++;
            return delegate.read(target);
        }
        @Override public int write(ByteBuffer source) throws IOException { return delegate.write(source); }
        @Override public long position() throws IOException { return delegate.position(); }
        @Override public SeekableByteChannel position(long value) throws IOException {
            positionSetCalls++;
            delegate.position(value);
            return this;
        }
        @Override public long size() throws IOException { return delegate.size(); }
        @Override public SeekableByteChannel truncate(long size) throws IOException {
            delegate.truncate(size);
            return this;
        }
        @Override public boolean isOpen() { return delegate.isOpen(); }
        @Override public void close() throws IOException { delegate.close(); }
    }
}
