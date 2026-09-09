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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
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

final class RevocationTransitionFrameCodecTest {

    private static final MetadataStoreId STORE_ID =
            new MetadataStoreId("00112233445566778899aabbccddeeff");
    private static final PkiId CREDENTIAL = new PkiId("credential:canonical:1");
    private static final byte[] DOMAIN = "ZeroEcho revocation transition record v1"
            .getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    @TempDir
    Path temporaryDirectory;

    @Test
    void decodeScratchHasExactCapacityAndDropsStorageOnClose() {
        RevocationTransitionFrameCodec.DecodeScratch scratch =
                new RevocationTransitionFrameCodec.DecodeScratch();
        assertEquals(16 * 1024, scratch.capacity());
        scratch.close();
        assertThrows(IllegalStateException.class, scratch::capacity);
        scratch.close();
    }

    @Test
    void canonicalRoundTripPreservesEveryTransitionField() throws Exception {
        System.out.print("canonicalRoundTripPreservesEveryTransitionField ");
        SimpleAttributeSet attributes = new SimpleAttributeSet(List.of(
                new SimpleAttributeSet.Entry(new AttributeId("z.example"), List.of(
                        new AttributeValue.StringValue("value"),
                        new AttributeValue.BooleanValue(true),
                        new AttributeValue.IntegerValue(Long.MAX_VALUE),
                        new AttributeValue.InstantValue(Instant.ofEpochSecond(55L, 42)),
                        new AttributeValue.BytesValue(new byte[] { 0x01, 0x02 }))),
                new SimpleAttributeSet.Entry(new AttributeId("a.example"), List.of())));
        RevocationTransition transition = new RevocationTransition(
                1L, RevocationState.PERMANENTLY_REVOKED,
                Instant.ofEpochSecond(123_456L, 789),
                Optional.of(RevocationReason.KEY_COMPROMISE), attributes);
        RevocationTransitionFrameCodec.TransitionData data = firstData(1L, transition);
        Path path = temporaryDirectory.resolve("round-trip.log");
        RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
        try (FileChannel channel = newChannel(path)) {
            codec.writePreamble(channel, STORE_ID);
            RevocationTransitionFrameCodec.CompleteRecord written = codec.write(channel, data);
            RevocationTransitionFrameCodec.ReadResult decoded =
                    codec.read(channel, RevocationTransitionFrameCodec.PREAMBLE_BYTES);
            assertEquals(RevocationTransitionFrameCodec.Classification.COMPLETE_RECORD,
                    decoded.classification());
            RevocationTransitionFrameCodec.CompleteRecord record = decoded.record().orElseThrow();
            assertEquals(written.commitment(), record.commitment());
            assertEquals(data.globalRevision(), record.data().globalRevision());
            assertEquals(data.credentialId(), record.data().credentialId());
            assertEquals(transition.revision(), record.data().transition().revision());
            assertEquals(transition.state(), record.data().transition().state());
            assertEquals(transition.time(), record.data().transition().time());
            assertEquals(transition.permanentReason(), record.data().transition().permanentReason());
            assertEquals(List.of(), record.data().transition().attributes()
                    .getAll(new AttributeId("a.example")));
            assertArrayEquals(new byte[] { 0x01, 0x02 },
                    ((AttributeValue.BytesValue) record.data().transition().attributes()
                            .getAll(new AttributeId("z.example")).get(4)).value());
            assertEquals(RevocationTransitionFrameCodec.Classification.END_OF_INPUT,
                    codec.read(channel, record.recordEnd()).classification());
        }
        System.out.println("...ok");
    }

    @Test
    void preambleAndSuccessorLinksRoundTripCanonically() throws Exception {
        System.out.print("preambleAndSuccessorLinksRoundTripCanonically ");
        Path path = temporaryDirectory.resolve("links.log");
        RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
        try (FileChannel channel = newChannel(path)) {
            codec.writePreamble(channel, STORE_ID);
            assertEquals(STORE_ID, codec.readPreamble(channel));
            channel.position(RevocationTransitionFrameCodec.PREAMBLE_BYTES);
            RevocationTransitionFrameCodec.CompleteRecord first = codec.write(
                    channel, firstData(1L, held(1L, 10L)));
            RevocationTransitionFrameCodec.TransitionData second =
                    new RevocationTransitionFrameCodec.TransitionData(
                            2L, first.commitment(), CREDENTIAL,
                            OptionalLong.of(1L), Optional.of(first.commitment()), clear(2L, 11L));
            RevocationTransitionFrameCodec.CompleteRecord written = codec.write(channel, second);
            RevocationTransitionFrameCodec.CompleteRecord decoded =
                    codec.read(channel, first.recordEnd()).record().orElseThrow();
            assertEquals(written, decoded);
            assertEquals(OptionalLong.of(1L), decoded.data().previousCredentialGlobalRevision());
            assertEquals(Optional.of(first.commitment()), decoded.data().previousCredentialCommitment());
        }
        System.out.println("...ok");
    }

    @Test
    void everyPartialFixedHeaderIsAnIncompleteTail() throws Exception {
        System.out.print("everyPartialFixedHeaderIsAnIncompleteTail ");
        byte[] complete = encodedLog(firstData(1L, held(1L, 10L)));
        RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
        for (int bytes = 1; bytes < RevocationTransitionFrameCodec.HEADER_BYTES; bytes++) {
            Path path = temporaryDirectory.resolve("header-" + bytes + ".log");
            Files.write(path, java.util.Arrays.copyOf(complete,
                    RevocationTransitionFrameCodec.PREAMBLE_BYTES + bytes));
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
                assertEquals(RevocationTransitionFrameCodec.Classification.INCOMPLETE_TAIL,
                        codec.read(channel, RevocationTransitionFrameCodec.PREAMBLE_BYTES).classification());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void partialPayloadAndCommitmentAreIncompleteButAuthenticatedLengthCorruptionIsCorrupt() throws Exception {
        System.out.print("partialPayloadAndCommitmentAreIncompleteButAuthenticatedLengthCorruptionIsCorrupt ");
        byte[] complete = encodedLog(firstData(1L, held(1L, 10L)));
        int recordStart = RevocationTransitionFrameCodec.PREAMBLE_BYTES;
        long payloadLength = ByteBuffer.wrap(complete, recordStart + 48, Long.BYTES)
                .order(ByteOrder.BIG_ENDIAN).getLong();
        int payloadStart = recordStart + RevocationTransitionFrameCodec.HEADER_BYTES;
        int footerStart = Math.toIntExact(payloadStart + payloadLength);
        int[] cuts = { payloadStart, payloadStart + 1, footerStart, footerStart + 1, complete.length - 1 };
        RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
        for (int cut : cuts) {
            Path path = temporaryDirectory.resolve("tail-" + cut + ".log");
            Files.write(path, java.util.Arrays.copyOf(complete, cut));
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
                assertEquals(RevocationTransitionFrameCodec.Classification.INCOMPLETE_TAIL,
                        codec.read(channel, recordStart).classification());
            }
        }
        complete[recordStart + 55] ^= 0x01;
        Path corrupt = temporaryDirectory.resolve("length-corrupt.log");
        Files.write(corrupt, complete);
        try (FileChannel channel = FileChannel.open(corrupt, StandardOpenOption.READ)) {
            assertEquals(RevocationTransitionFrameCodec.Classification.CORRUPT_RECORD,
                    codec.read(channel, recordStart).classification());
        }
        System.out.println("...ok");
    }

    @Test
    void malformedSemanticFieldsAndTrailingPayloadAreCorrupt() throws Exception {
        System.out.print("malformedSemanticFieldsAndTrailingPayloadAreCorrupt ");
        byte[] original = encodedLog(firstData(1L, held(1L, 10L)));
        int payloadStart = RevocationTransitionFrameCodec.PREAMBLE_BYTES
                + RevocationTransitionFrameCodec.HEADER_BYTES;
        byte[][] corruptions = new byte[4][];
        corruptions[0] = original.clone();
        corruptions[0][payloadStart] = 0x02;
        corruptions[1] = original.clone();
        corruptions[1][payloadStart + 2] = 0x01;
        corruptions[2] = original.clone();
        int credentialStart = payloadStart + 8;
        corruptions[2][credentialStart] = (byte) 0xC0;
        corruptions[3] = appendSemanticTrailingByte(original);
        RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
        for (int index = 0; index < corruptions.length; index++) {
            refreshDigests(corruptions[index]);
            Path path = temporaryDirectory.resolve("semantic-" + index + ".log");
            Files.write(path, corruptions[index]);
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
                assertEquals(RevocationTransitionFrameCodec.Classification.CORRUPT_RECORD,
                        codec.read(channel, RevocationTransitionFrameCodec.PREAMBLE_BYTES).classification());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void commitmentMismatchAndUnknownHeaderFieldsAreCorrupt() throws Exception {
        System.out.print("commitmentMismatchAndUnknownHeaderFieldsAreCorrupt ");
        byte[] commitmentMismatch = encodedLog(firstData(1L, held(1L, 10L)));
        commitmentMismatch[commitmentMismatch.length - 1] ^= 0x01;
        byte[] unknownVersion = encodedLog(firstData(1L, held(1L, 10L)));
        int header = RevocationTransitionFrameCodec.PREAMBLE_BYTES;
        unknownVersion[header + 5] = 0x02;
        refreshHeaderDigest(unknownVersion);
        byte[] nonzeroFlags = encodedLog(firstData(1L, held(1L, 10L)));
        nonzeroFlags[header + 7] = 0x01;
        refreshHeaderDigest(nonzeroFlags);
        RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
        List<byte[]> values = List.of(commitmentMismatch, unknownVersion, nonzeroFlags);
        for (int index = 0; index < values.size(); index++) {
            Path path = temporaryDirectory.resolve("header-corrupt-" + index + ".log");
            Files.write(path, values.get(index));
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
                assertEquals(RevocationTransitionFrameCodec.Classification.CORRUPT_RECORD,
                        codec.read(channel, header).classification());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void invalidLengthsRevisionsAndIdentityAreRejectedBeforeWriting() throws Exception {
        System.out.print("invalidLengthsRevisionsAndIdentityAreRejectedBeforeWriting ");
        RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
        Path path = temporaryDirectory.resolve("rejected.log");
        try (FileChannel channel = newChannel(path)) {
            codec.writePreamble(channel, STORE_ID);
            assertThrows(IllegalArgumentException.class, () -> codec.write(channel,
                    new RevocationTransitionFrameCodec.TransitionData(
                            0L, RevocationTransitionFrameCodec.initialCommitment(STORE_ID), CREDENTIAL,
                            OptionalLong.empty(), Optional.empty(), held(1L, 1L))));
            String excessive = "x".repeat(RevocationTransitionFrameCodec.MAX_COMPONENT_BYTES + 1);
            assertThrows(IllegalArgumentException.class, () -> codec.write(channel,
                    firstData(1L, new RevocationTransition(
                            1L, RevocationState.HELD, Instant.EPOCH, Optional.empty(),
                            new SimpleAttributeSet(List.of(new SimpleAttributeSet.Entry(
                                    new AttributeId(excessive), List.of())))))));
            assertEquals(RevocationTransitionFrameCodec.PREAMBLE_BYTES, channel.size());
        }
        assertThrows(IllegalArgumentException.class, () -> new RevocationTransitionFrameCodec.Commitment("00"));
        System.out.println("...ok");
    }

    @Test
    void invalidStateReasonCombinationsAreRejectedOnEncodeAndDecode() throws Exception {
        System.out.print("invalidStateReasonCombinationsAreRejectedOnEncodeAndDecode ");
        RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
        Path encodePath = temporaryDirectory.resolve("invalid-state-reason-encode.log");
        List<RevocationTransition> invalid = List.of(
                transition(RevocationState.HELD, Optional.of(RevocationReason.KEY_COMPROMISE)),
                transition(RevocationState.CLEAR, Optional.of(RevocationReason.UNSPECIFIED)),
                transition(RevocationState.PERMANENTLY_REVOKED, Optional.empty()),
                transition(RevocationState.PERMANENTLY_REVOKED,
                        Optional.of(RevocationReason.CERTIFICATE_HOLD)),
                transition(RevocationState.PERMANENTLY_REVOKED,
                        Optional.of(RevocationReason.REMOVE_FROM_CRL)));
        try (FileChannel channel = newChannel(encodePath)) {
            codec.writePreamble(channel, STORE_ID);
            for (RevocationTransition transition : invalid) {
                assertThrows(IllegalArgumentException.class,
                        () -> codec.write(channel, firstData(1L, transition)));
            }
            assertEquals(RevocationTransitionFrameCodec.PREAMBLE_BYTES, channel.size());
        }

        byte[] malformed = encodedLog(firstData(1L, held(1L, 10L)));
        int reasonOffset = reasonOffset(malformed);
        malformed[reasonOffset] = 2;
        refreshDigests(malformed);
        Path decodePath = temporaryDirectory.resolve("invalid-state-reason-decode.log");
        Files.write(decodePath, malformed);
        try (FileChannel channel = FileChannel.open(decodePath, StandardOpenOption.READ)) {
            assertEquals(RevocationTransitionFrameCodec.Classification.CORRUPT_RECORD,
                    codec.read(channel, RevocationTransitionFrameCodec.PREAMBLE_BYTES).classification());
        }
        System.out.println("...ok");
    }

    @Test
    void malformedUtf16IsRejectedBeforeAnyRecordHeaderByteIsWritten() throws Exception {
        System.out.print("malformedUtf16IsRejectedBeforeAnyRecordHeaderByteIsWritten ");
        RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
        Path path = temporaryDirectory.resolve("malformed-utf16.log");
        List<RevocationTransitionFrameCodec.TransitionData> malformed = List.of(
                new RevocationTransitionFrameCodec.TransitionData(
                        1L, RevocationTransitionFrameCodec.initialCommitment(STORE_ID),
                        new PkiId("credential:\uD800"), OptionalLong.empty(), Optional.empty(),
                        held(1L, 1L)),
                firstData(1L, transitionWithAttributes(new SimpleAttributeSet(List.of(
                        new SimpleAttributeSet.Entry(new AttributeId("attribute.\uD800"), List.of()))))),
                firstData(1L, transitionWithAttributes(new SimpleAttributeSet(List.of(
                        new SimpleAttributeSet.Entry(new AttributeId("attribute.string"), List.of(
                                new AttributeValue.StringValue("value\uD800"))))))));
        try (FileChannel channel = newChannel(path)) {
            codec.writePreamble(channel, STORE_ID);
            for (RevocationTransitionFrameCodec.TransitionData data : malformed) {
                assertThrows(IllegalArgumentException.class, () -> codec.write(channel, data));
                assertEquals(RevocationTransitionFrameCodec.PREAMBLE_BYTES, channel.size());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void repeatedDecodeIsDeterministicAndRetainsOnlyOneFiniteRecord() throws Exception {
        System.out.print("repeatedDecodeIsDeterministicAndRetainsOnlyOneFiniteRecord ");
        Path path = temporaryDirectory.resolve("deterministic.log");
        Files.write(path, encodedLog(firstData(1L, held(1L, 10L))));
        RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            RevocationTransitionFrameCodec.ReadResult first =
                    codec.read(channel, RevocationTransitionFrameCodec.PREAMBLE_BYTES);
            RevocationTransitionFrameCodec.ReadResult second =
                    codec.read(channel, RevocationTransitionFrameCodec.PREAMBLE_BYTES);
            assertEquals(first, second);
            assertTrue(first.record().isPresent());
            assertFalse(RevocationTransitionFrameCodec.CompleteRecord.class
                    .getRecordComponents()[0].getType().isArray());
        }
        System.out.println("...ok");
    }

    private byte[] encodedLog(RevocationTransitionFrameCodec.TransitionData data) throws IOException {
        Path path = Files.createTempFile(temporaryDirectory, "encoded-", ".log");
        RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
        try (FileChannel channel = newChannel(path)) {
            codec.writePreamble(channel, STORE_ID);
            codec.write(channel, data);
        }
        return Files.readAllBytes(path);
    }

    private static RevocationTransitionFrameCodec.TransitionData firstData(
            long globalRevision, RevocationTransition transition) {
        return new RevocationTransitionFrameCodec.TransitionData(
                globalRevision, RevocationTransitionFrameCodec.initialCommitment(STORE_ID), CREDENTIAL,
                OptionalLong.empty(), Optional.empty(), transition);
    }

    private static RevocationTransition held(long revision, long second) {
        return new RevocationTransition(revision, RevocationState.HELD,
                Instant.ofEpochSecond(second), Optional.empty(), new SimpleAttributeSet());
    }

    private static RevocationTransition clear(long revision, long second) {
        return new RevocationTransition(revision, RevocationState.CLEAR,
                Instant.ofEpochSecond(second), Optional.empty(), new SimpleAttributeSet());
    }

    private static RevocationTransition transition(
            RevocationState state, Optional<RevocationReason> reason) {
        return new RevocationTransition(
                1L, state, Instant.EPOCH, reason, new SimpleAttributeSet());
    }

    private static RevocationTransition transitionWithAttributes(SimpleAttributeSet attributes) {
        return new RevocationTransition(
                1L, RevocationState.HELD, Instant.EPOCH, Optional.empty(), attributes);
    }

    private static FileChannel newChannel(Path path) throws IOException {
        return FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.READ, StandardOpenOption.WRITE);
    }

    private static byte[] appendSemanticTrailingByte(byte[] original) {
        int header = RevocationTransitionFrameCodec.PREAMBLE_BYTES;
        long oldLength = ByteBuffer.wrap(original, header + 48, Long.BYTES)
                .order(ByteOrder.BIG_ENDIAN).getLong();
        int footer = Math.toIntExact(header + RevocationTransitionFrameCodec.HEADER_BYTES + oldLength);
        byte[] expanded = new byte[original.length + 1];
        System.arraycopy(original, 0, expanded, 0, footer);
        expanded[footer] = 0x00;
        System.arraycopy(original, footer, expanded, footer + 1,
                RevocationTransitionFrameCodec.COMMITMENT_BYTES);
        ByteBuffer.wrap(expanded, header + 48, Long.BYTES)
                .order(ByteOrder.BIG_ENDIAN).putLong(oldLength + 1L);
        return expanded;
    }

    private static int reasonOffset(byte[] encoded) {
        int payload = RevocationTransitionFrameCodec.PREAMBLE_BYTES
                + RevocationTransitionFrameCodec.HEADER_BYTES;
        int credentialLength = ByteBuffer.wrap(encoded, payload + 4, Integer.BYTES)
                .order(ByteOrder.BIG_ENDIAN).getInt();
        int state = payload + 4 + Integer.BYTES + credentialLength
                + Long.BYTES + 1 + Long.BYTES + Integer.BYTES;
        return state + 1;
    }

    private static void refreshDigests(byte[] encoded) throws NoSuchAlgorithmException {
        refreshHeaderDigest(encoded);
        int header = RevocationTransitionFrameCodec.PREAMBLE_BYTES;
        long payloadLength = ByteBuffer.wrap(encoded, header + 48, Long.BYTES)
                .order(ByteOrder.BIG_ENDIAN).getLong();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(DOMAIN);
        digest.update(encoded, header, RevocationTransitionFrameCodec.HEADER_BYTES);
        digest.update(encoded, header + RevocationTransitionFrameCodec.HEADER_BYTES,
                Math.toIntExact(payloadLength));
        byte[] commitment = digest.digest();
        System.arraycopy(commitment, 0, encoded,
                header + RevocationTransitionFrameCodec.HEADER_BYTES + Math.toIntExact(payloadLength),
                commitment.length);
    }

    private static void refreshHeaderDigest(byte[] encoded) throws NoSuchAlgorithmException {
        int header = RevocationTransitionFrameCodec.PREAMBLE_BYTES;
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(encoded, header, 56);
        byte[] headerDigest = digest.digest();
        System.arraycopy(headerDigest, 0, encoded, header + 56, headerDigest.length);
    }
}
