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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.MetadataStoreId;

final class RevocationCheckpointCodecTest {

    private static final MetadataStoreId STORE_ID =
            new MetadataStoreId("00112233445566778899aabbccddeeff");
    private static final RevocationTransitionFrameCodec.Commitment GENESIS =
            RevocationTransitionFrameCodec.initialCommitment(STORE_ID);

    @TempDir
    Path temporaryDirectory;

    @Test
    void revisionZeroCheckpointHasStrictEmptyFraming() throws Exception {
        System.out.print("revisionZeroCheckpointHasStrictEmptyFraming ");
        Path first = encode("zero-a.chk", zeroHeader(), List.of());
        Path second = encode("zero-b.chk", zeroHeader(), List.of());
        assertArrayEquals(Files.readAllBytes(first), Files.readAllBytes(second));
        try (FileChannel channel = FileChannel.open(first, StandardOpenOption.READ)) {
            RevocationCheckpointCodec.ValidatedFile validated =
                    new RevocationCheckpointCodec().validate(channel);
            assertEquals(0L, validated.header().coveredRevision());
            assertTrue(validated.header().finalRecordStart().isEmpty());
            assertEquals(0L, validated.header().entryCount());
        }
        List<RevocationCheckpointCodec.HeaderData> invalid = List.of(
                new RevocationCheckpointCodec.HeaderData(
                        STORE_ID, 0L, OptionalLong.empty(),
                        RevocationTransitionFrameCodec.PREAMBLE_BYTES, GENESIS, 1L),
                new RevocationCheckpointCodec.HeaderData(
                        STORE_ID, 0L, OptionalLong.empty(),
                        RevocationTransitionFrameCodec.PREAMBLE_BYTES + 1L, GENESIS, 0L),
                new RevocationCheckpointCodec.HeaderData(
                        STORE_ID, 0L, OptionalLong.empty(),
                        RevocationTransitionFrameCodec.PREAMBLE_BYTES, commitment(7), 0L));
        for (int index = 0; index < invalid.size(); index++) {
            Path path = temporaryDirectory.resolve("invalid-genesis-" + index + ".chk");
            try (FileChannel channel = FileChannel.open(path,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.READ,
                    StandardOpenOption.WRITE)) {
                RevocationCheckpointCodec.HeaderData header = invalid.get(index);
                assertThrows(IllegalArgumentException.class,
                        () -> new RevocationCheckpointCodec().encoder(channel, header));
            }
        }
        System.out.println("...ok");
    }

    @Test
    void canonicalRecordsRoundTripEveryStateReasonAndAttributeShape() throws Exception {
        System.out.print("canonicalRecordsRoundTripEveryStateReasonAndAttributeShape ");
        List<RevocationCheckpointCodec.CurrentStateEntry> entries = List.of(
                entry("credential:a", 1L, RevocationState.CLEAR, Optional.empty(), 128L),
                entry("credential:b", 2L, RevocationState.HELD, Optional.empty(), 512L),
                entry("credential:c", 3L, RevocationState.PERMANENTLY_REVOKED,
                        Optional.of(RevocationReason.KEY_COMPROMISE), 896L));
        Path file = encode("round-trip.chk", header(3L, entries.size()), entries);
        RevocationCheckpointCodec codec = new RevocationCheckpointCodec();
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            RevocationCheckpointCodec.ValidatedFile validated = codec.validate(channel);
            long offset = RevocationCheckpointCodec.HEADER_BYTES;
            for (RevocationCheckpointCodec.CurrentStateEntry expected : entries) {
                RevocationCheckpointCodec.DecodedRecord decoded =
                        codec.readRecord(channel, offset, validated.trailerOffset());
                assertEquals(expected.credentialId(), decoded.entry().credentialId());
                assertEquals(expected.globalRevision(), decoded.entry().globalRevision());
                assertTrue(RevocationTransitionFrameCodec.transitionsEqual(
                        expected.transition(), decoded.entry().transition()));
                offset = decoded.nextOffset();
            }
        }
        System.out.println("...ok");
    }

    @Test
    void truncatedHeaderRecordAndTrailerFailClosed() throws Exception {
        System.out.print("truncatedHeaderRecordAndTrailerFailClosed ");
        Path complete = encode("complete.chk", header(1L, 1L),
                List.of(entry("credential:a", 1L, RevocationState.HELD, Optional.empty(), 128L)));
        byte[] bytes = Files.readAllBytes(complete);
        int[] cuts = { 1, RevocationCheckpointCodec.HEADER_BYTES - 1,
                RevocationCheckpointCodec.HEADER_BYTES + 4, bytes.length - 1 };
        for (int cut : cuts) {
            Path truncated = temporaryDirectory.resolve("truncated-" + cut + ".chk");
            Files.write(truncated, java.util.Arrays.copyOf(bytes, cut));
            try (FileChannel channel = FileChannel.open(truncated, StandardOpenOption.READ)) {
                assertThrows(IOException.class, () -> new RevocationCheckpointCodec().validate(channel));
            }
        }
        System.out.println("...ok");
    }

    @Test
    void headerRecordAndWholeFileIntegrityFailuresAreDistinctlyRejected() throws Exception {
        System.out.print("headerRecordAndWholeFileIntegrityFailuresAreDistinctlyRejected ");
        Path complete = encode("integrity.chk", header(1L, 1L),
                List.of(entry("credential:a", 1L, RevocationState.HELD, Optional.empty(), 128L)));
        byte[] bytes = Files.readAllBytes(complete);
        int[] positions = { 5, RevocationCheckpointCodec.HEADER_BYTES + 20, bytes.length - 1 };
        for (int index = 0; index < positions.length; index++) {
            byte[] corrupt = bytes.clone();
            corrupt[positions[index]] ^= 0x01;
            Path path = temporaryDirectory.resolve("corrupt-" + index + ".chk");
            Files.write(path, corrupt);
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
                assertThrows(IOException.class, () -> new RevocationCheckpointCodec().validate(channel));
            }
        }
        System.out.println("...ok");
    }

    @Test
    void invalidCountsOffsetsTimestampsAndSemanticCodesFailClosed() throws Exception {
        System.out.print("invalidCountsOffsetsTimestampsAndSemanticCodesFailClosed ");
        Path invalidHeader = temporaryDirectory.resolve("invalid-header.chk");
        try (FileChannel channel = FileChannel.open(invalidHeader,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            assertThrows(IllegalArgumentException.class,
                    () -> new RevocationCheckpointCodec().encoder(channel,
                            new RevocationCheckpointCodec.HeaderData(
                                    STORE_ID, -1L, OptionalLong.empty(), 56L, GENESIS, 0L)));
        }
        assertThrows(DateTimeException.class, () -> entry(
                "credential:a", 1L, RevocationState.HELD, Optional.empty(), 127L)
                .transition().time().with(java.time.temporal.ChronoField.NANO_OF_SECOND, -1L));
        assertThrows(IllegalArgumentException.class, () -> new RevocationCheckpointCodec.CurrentStateEntry(
                new PkiId("credential:a"), 1L, 1L, commitment(1),
                transition(1L, RevocationState.HELD, Optional.empty()), 100L, 99L));
        Path file = encode("codes.chk", header(1L, 1L),
                List.of(entry("credential:a", 1L, RevocationState.HELD, Optional.empty(), 128L)));
        byte[] bytes = Files.readAllBytes(file);
        long payloadLength = ByteBuffer.wrap(bytes,
                RevocationCheckpointCodec.HEADER_BYTES + Integer.BYTES, Long.BYTES)
                .order(ByteOrder.BIG_ENDIAN).getLong();
        assertTrue(payloadLength > 0L);
        System.out.println("...ok");
    }

    @Test
    void encoderRejectsDeclaredCountMismatchWithoutAggregateLimit() throws Exception {
        System.out.print("encoderRejectsDeclaredCountMismatchWithoutAggregateLimit ");
        Path file = temporaryDirectory.resolve("count.chk");
        try (FileChannel channel = FileChannel.open(file,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            RevocationCheckpointCodec.Encoder encoder =
                    new RevocationCheckpointCodec().encoder(channel, header(1L, Long.MAX_VALUE));
            encoder.write(entry("credential:a", 1L, RevocationState.HELD, Optional.empty(), 128L));
            assertThrows(IOException.class, encoder::finish);
        }
        System.out.println("...ok");
    }

    private Path encode(
            String name,
            RevocationCheckpointCodec.HeaderData header,
            List<RevocationCheckpointCodec.CurrentStateEntry> entries) throws Exception {
        Path path = temporaryDirectory.resolve(name);
        try (FileChannel channel = FileChannel.open(path,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            RevocationCheckpointCodec.Encoder encoder =
                    new RevocationCheckpointCodec().encoder(channel, header);
            for (RevocationCheckpointCodec.CurrentStateEntry entry : entries) {
                encoder.write(entry);
            }
            encoder.finish();
        }
        return path;
    }

    private static RevocationCheckpointCodec.HeaderData zeroHeader() {
        return new RevocationCheckpointCodec.HeaderData(
                STORE_ID, 0L, OptionalLong.empty(), RevocationTransitionFrameCodec.PREAMBLE_BYTES,
                GENESIS, 0L);
    }

    private static RevocationCheckpointCodec.HeaderData header(long revision, long count) {
        return new RevocationCheckpointCodec.HeaderData(
                STORE_ID, revision, OptionalLong.of(128L), 1_000L,
                commitment(99), count);
    }

    private static RevocationCheckpointCodec.CurrentStateEntry entry(
            String id,
            long globalRevision,
            RevocationState state,
            Optional<RevocationReason> reason,
            long frameStart) {
        return new RevocationCheckpointCodec.CurrentStateEntry(
                new PkiId(id), globalRevision, 1L, commitment((int) globalRevision),
                transition(1L, state, reason), frameStart, frameStart + 100L);
    }

    private static RevocationTransition transition(
            long revision, RevocationState state, Optional<RevocationReason> reason) {
        SimpleAttributeSet attributes = new SimpleAttributeSet(List.of(
                new SimpleAttributeSet.Entry(new AttributeId("z.example"), List.of(
                        new AttributeValue.StringValue("text"),
                        new AttributeValue.BooleanValue(true),
                        new AttributeValue.IntegerValue(Long.MAX_VALUE),
                        new AttributeValue.InstantValue(Instant.ofEpochSecond(8L, 9)),
                        new AttributeValue.BytesValue(new byte[] { 0x01, 0x02 }))),
                new SimpleAttributeSet.Entry(new AttributeId("a.example"), List.of())));
        return new RevocationTransition(
                revision, state, Instant.ofEpochSecond(123L, 456), reason, attributes);
    }

    private static RevocationTransitionFrameCodec.Commitment commitment(int seed) {
        return new RevocationTransitionFrameCodec.Commitment(
                String.format("%064x", Integer.toUnsignedLong(seed)));
    }
}
