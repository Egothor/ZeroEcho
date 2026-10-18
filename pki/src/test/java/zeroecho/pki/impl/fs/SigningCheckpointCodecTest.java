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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.spi.store.MetadataKey;

final class SigningCheckpointCodecTest {
    @TempDir
    private Path temporaryDirectory;

    @Test
    void selfContainedRoundTripValidatesIndexAndExactFrames() throws Exception {
        byte[] first = frame(12L, 1);
        byte[] second = frame(20L, 2);
        String firstKey = "mk1:1:1:ab";
        String secondKey = "mk1:1:1:ac";
        long dataOffset = SigningCheckpointCodec.HEADER_BYTES
                + SigningCheckpointCodec.encodedIndexBytes(firstKey)
                + SigningCheckpointCodec.encodedIndexBytes(secondKey);
        SigningCheckpointCodec.EntryDescriptor firstEntry = entry(firstKey, dataOffset,
                first.length, 8L, 12L);
        SigningCheckpointCodec.EntryDescriptor secondEntry = entry(secondKey,
                dataOffset + first.length, second.length, 9L, 20L);
        Path path = temporaryDirectory.resolve("checkpoint.zec");
        write(path, new SigningCheckpointCodec.Header(3L, 9L, 20L, 2, dataOffset),
                new SigningCheckpointCodec.EntryDescriptor[] { firstEntry, secondEntry },
                new byte[][] { first, second });

        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            SigningCheckpointCodec.Reader reader = SigningCheckpointCodec.reader(channel);
            SigningCheckpointCodec.EntryDescriptor decodedFirst = reader.next().orElseThrow();
            assertArrayEquals(first, SigningWalFrameCodec.encode(reader.readFrame(decodedFirst)));
            SigningCheckpointCodec.EntryDescriptor decodedSecond = reader.next().orElseThrow();
            assertArrayEquals(second, SigningWalFrameCodec.encode(reader.readFrame(decodedSecond)));
            assertEquals(Optional.empty(), reader.next());
            reader.verifyComplete();
            assertEquals(32, reader.fileCommitment().length);
        }
    }

    @Test
    void writerRejectsUnsortedNoncontiguousAndMismatchedFrames() throws Exception {
        byte[] encoded = frame(1L, 1);
        String key = new zeroecho.pki.spi.store.MetadataKey("example", "key").canonical();
        long dataOffset = SigningCheckpointCodec.HEADER_BYTES
                + 2L * SigningCheckpointCodec.encodedIndexBytes(key);
        Path path = temporaryDirectory.resolve("invalid.zec");
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE)) {
            SigningCheckpointCodec.Writer writer = SigningCheckpointCodec.writer(channel,
                    new SigningCheckpointCodec.Header(3L, 2L, 2L, 2, dataOffset));
            writer.writeIndex(entry(key, dataOffset, encoded.length, 1L, 1L));
            assertThrows(IOException.class, () -> writer.writeIndex(
                    entry(key, dataOffset + encoded.length, encoded.length, 2L, 2L)));
        }

        Path mismatch = temporaryDirectory.resolve("mismatch.zec");
        long oneOffset = SigningCheckpointCodec.HEADER_BYTES
                + SigningCheckpointCodec.encodedIndexBytes(key);
        try (FileChannel channel = FileChannel.open(mismatch, StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE)) {
            SigningCheckpointCodec.Writer writer = SigningCheckpointCodec.writer(channel,
                    new SigningCheckpointCodec.Header(3L, 2L, 2L, 1, oneOffset));
            SigningCheckpointCodec.EntryDescriptor descriptor = entry(key, oneOffset,
                    encoded.length, 2L, 2L);
            writer.writeIndex(descriptor);
            writer.beginData();
            assertThrows(IOException.class, () -> writer.writeFrame(descriptor, encoded));
        }
    }

    @Test
    void corruptionAndTruncationFailClosed() throws Exception {
        byte[] encoded = frame(1L, 1);
        String key = new zeroecho.pki.spi.store.MetadataKey("example", "key").canonical();
        long offset = SigningCheckpointCodec.HEADER_BYTES
                + SigningCheckpointCodec.encodedIndexBytes(key);
        SigningCheckpointCodec.EntryDescriptor descriptor = entry(key, offset,
                encoded.length, 1L, 1L);
        Path path = temporaryDirectory.resolve("corrupt.zec");
        write(path, new SigningCheckpointCodec.Header(3L, 1L, 1L, 1, offset),
                new SigningCheckpointCodec.EntryDescriptor[] { descriptor },
                new byte[][] { encoded });
        byte[] corrupt = Files.readAllBytes(path);
        corrupt[(int) offset + SigningWalFrameCodec.HEADER_BYTES] ^= 1;
        Files.write(path, corrupt, StandardOpenOption.TRUNCATE_EXISTING);
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            SigningCheckpointCodec.Reader reader = SigningCheckpointCodec.reader(channel);
            SigningCheckpointCodec.EntryDescriptor decoded = reader.next().orElseThrow();
            assertThrows(IOException.class, () -> reader.readFrame(decoded));
        }

        Files.write(path, new byte[SigningCheckpointCodec.HEADER_BYTES - 1],
                StandardOpenOption.TRUNCATE_EXISTING);
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            assertThrows(IOException.class, () -> SigningCheckpointCodec.reader(channel));
        }
    }

    @Test
    void semanticMetadataOrderIgnoresCanonicalLengthPrefixes() throws Exception {
        byte[] first = frame(0L, 1);
        byte[] second = frame(1L, 2);
        String firstKey = new MetadataKey("a", "aa").canonical();
        String secondKey = new MetadataKey("a", "z").canonical();
        long dataOffset = SigningCheckpointCodec.HEADER_BYTES
                + SigningCheckpointCodec.encodedIndexBytes(firstKey)
                + SigningCheckpointCodec.encodedIndexBytes(secondKey);
        SigningCheckpointCodec.EntryDescriptor firstEntry = entry(firstKey, dataOffset,
                first.length, 1L, 0L);
        SigningCheckpointCodec.EntryDescriptor secondEntry = entry(secondKey,
                dataOffset + first.length, second.length, 2L, 1L);
        Path path = temporaryDirectory.resolve("semantic-order.zec");
        write(path, new SigningCheckpointCodec.Header(3L, 2L, 1L, 2, dataOffset),
                new SigningCheckpointCodec.EntryDescriptor[] { firstEntry, secondEntry },
                new byte[][] { first, second });

        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            SigningCheckpointCodec.Reader reader = SigningCheckpointCodec.reader(channel);
            assertEquals(firstKey, reader.next().orElseThrow().key());
            assertEquals(secondKey, reader.next().orElseThrow().key());
        }
    }

    @Test
    void bufferedReaderChannelCallsScaleWithBytesRatherThanEntries() throws Exception {
        int count = 1_000;
        SigningCheckpointCodec.EntryDescriptor[] entries =
                new SigningCheckpointCodec.EntryDescriptor[count];
        byte[][] frames = new byte[count][];
        long dataOffset = SigningCheckpointCodec.HEADER_BYTES;
        for (int value = 0; value < count; value++) {
            String key = new MetadataKey("example", String.format("%04d", value)).canonical();
            dataOffset += SigningCheckpointCodec.encodedIndexBytes(key);
        }
        long offset = dataOffset;
        for (int value = 0; value < count; value++) {
            String key = new MetadataKey("example", String.format("%04d", value)).canonical();
            frames[value] = frame(value, value);
            entries[value] = entry(key, offset, frames[value].length, value + 1L, value);
            offset += frames[value].length;
        }
        Path path = temporaryDirectory.resolve("buffered.zec");
        write(path, new SigningCheckpointCodec.Header(3L, count, count - 1L, count,
                dataOffset), entries, frames);

        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            SigningCheckpointCodec.Reader reader = SigningCheckpointCodec.reader(channel);
            for (int value = 0; value < count; value++) {
                SigningCheckpointCodec.EntryDescriptor entry = reader.next().orElseThrow();
                reader.readFrame(entry);
            }
            reader.verifyComplete();
            SigningCheckpointCodec.ReadStatistics statistics = reader.statistics();
            assertTrue(statistics.indexChannelReads() < 32L);
            assertTrue(statistics.dataChannelReads() < 16L);
        }
    }

    private static void write(Path path, SigningCheckpointCodec.Header header,
            SigningCheckpointCodec.EntryDescriptor[] entries, byte[][] frames) throws IOException {
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE)) {
            SigningCheckpointCodec.Writer writer = SigningCheckpointCodec.writer(channel, header);
            for (SigningCheckpointCodec.EntryDescriptor entry : entries) {
                writer.writeIndex(entry);
            }
            writer.beginData();
            for (int index = 0; index < entries.length; index++) {
                writer.writeFrame(entries[index], frames[index]);
            }
            assertEquals(32, writer.finish().length);
        }
    }

    private static SigningCheckpointCodec.EntryDescriptor entry(String key, long offset,
            int length, long revision, long sequence) {
        return new SigningCheckpointCodec.EntryDescriptor(key,
                SigningWalFrameCodec.RecordType.MUTATION, offset, length, revision, sequence);
    }

    private static byte[] frame(long sequence, int value) {
        return SigningWalFrameCodec.encode(new SigningWalFrameCodec.Frame(
                SigningWalFrameCodec.RecordType.MUTATION, new UUID(1L, sequence + 1L),
                sequence, new byte[] { (byte) value }));
    }
}
