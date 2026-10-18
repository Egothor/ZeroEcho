/* *****************************************************************************
 * Copyright (C) 2025, Leo Galambos
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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;

final class SigningTransactionPayloadCodecTest {
    @Test
    void roundTripsOneAtomicMultiKeyTransaction() throws Exception {
        List<SigningTransactionPayloadCodec.Mutation> mutations = List.of(
                new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.CREATE,
                        new MetadataKey("io.zeroecho.test", "a"), -1L, new byte[] { 1 }),
                new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.REPLACE,
                        new MetadataKey("io.zeroecho.test", "b"), 7L, new byte[] { 2, 3 }),
                new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.DELETE,
                        new MetadataKey("io.zeroecho.test", "c"), 8L, null));

        SigningTransactionPayloadCodec.Payload decoded = SigningTransactionPayloadCodec.decode(
                SigningTransactionPayloadCodec.commit(mutations));

        assertEquals(SigningTransactionPayloadCodec.Kind.COMMIT, decoded.kind());
        assertEquals(3, decoded.mutations().size());
        assertArrayEquals(new byte[] { 2, 3 }, decoded.mutations().get(1).content());
    }

    @Test
    void roundTripsDirectCommitWithFoldedWatermark() throws Exception {
        SigningTransactionPayloadCodec.Mutation mutation = new SigningTransactionPayloadCodec.Mutation(
                SigningTransactionPayloadCodec.MutationKind.CREATE,
                new MetadataKey("io.zeroecho.test", "direct"), -1L, new byte[] { 4, 5 });

        SigningTransactionPayloadCodec.Payload decoded = SigningTransactionPayloadCodec.decode(
                SigningTransactionPayloadCodec.directCommit(List.of(mutation), 1234L));

        assertEquals(SigningTransactionPayloadCodec.Kind.DIRECT_COMMIT, decoded.kind());
        assertEquals(1234L, decoded.watermark());
        assertArrayEquals(new byte[] { 4, 5 }, decoded.mutations().getFirst().content());
    }

    @Test
    void directCommitRejectsNonCanonicalShapesAtEncodeAndDecode() {
        MetadataKey key = new MetadataKey("io.zeroecho.test", "canonical");
        SigningTransactionPayloadCodec.Mutation create = new SigningTransactionPayloadCodec.Mutation(
                SigningTransactionPayloadCodec.MutationKind.CREATE, key, -1L, new byte[] { 1 });
        assertThrows(IllegalArgumentException.class,
                () -> SigningTransactionPayloadCodec.directCommit(List.of(), -1L));
        assertThrows(IllegalArgumentException.class,
                () -> SigningTransactionPayloadCodec.directCommit(List.of(create, create), -1L));
        assertThrows(IllegalArgumentException.class,
                () -> SigningTransactionPayloadCodec.directCommit(List.of(create), -2L));
        assertThrows(IOException.class,
                () -> SigningTransactionPayloadCodec.decode(rawDirect(List.of(), -1L)));
        assertThrows(IOException.class,
                () -> SigningTransactionPayloadCodec.decode(rawDirect(List.of(
                        rawMutation(1, -1L, key, 0), rawMutation(1, -1L, key, 0)), -1L)));
        assertThrows(IOException.class,
                () -> SigningTransactionPayloadCodec.decode(rawDirect(List.of(
                        rawMutation(3, 1L, key, -2)), -1L)));
        assertThrows(IOException.class,
                () -> SigningTransactionPayloadCodec.decode(rawDirect(List.of(
                        rawMutation(1, -1L, key, 0)), -2L)));
    }

    @Test
    void enforcesMutationAndPayloadBoundsAndRejectsTruncation() {
        List<SigningTransactionPayloadCodec.Mutation> mutations = new ArrayList<>();
        for (int index = 0; index <= SigningTransactionPayloadCodec.MAXIMUM_MUTATIONS; index++) {
            mutations.add(new SigningTransactionPayloadCodec.Mutation(
                    SigningTransactionPayloadCodec.MutationKind.CREATE,
                    new MetadataKey("io.zeroecho.test", "k" + index), -1L, new byte[0]));
        }
        assertThrows(IllegalArgumentException.class,
                () -> SigningTransactionPayloadCodec.commit(mutations));
        assertThrows(IllegalArgumentException.class,
                () -> SigningTransactionPayloadCodec.commit(List.of(
                        new SigningTransactionPayloadCodec.Mutation(
                                SigningTransactionPayloadCodec.MutationKind.CREATE,
                                new MetadataKey("io.zeroecho.test", "large"), -1L,
                                new byte[SigningWalFrameCodec.MAX_PAYLOAD_BYTES]))));
        assertThrows(IOException.class,
                () -> SigningTransactionPayloadCodec.decode(new byte[] { 1, 2, 3 }));
    }

    @Test
    void roundTripsRetainedOutcomeAndWatermarkFrames() throws Exception {
        assertEquals(MetadataCommitResult.FailureCategory.CONFLICT,
                SigningTransactionPayloadCodec.decode(SigningTransactionPayloadCodec.reject(
                        MetadataCommitResult.FailureCategory.CONFLICT)).failure());
        assertEquals(1234L, SigningTransactionPayloadCodec.decode(
                SigningTransactionPayloadCodec.watermark(1234L)).watermark());
        assertEquals(SigningTransactionPayloadCodec.Kind.ACK,
                SigningTransactionPayloadCodec.decode(
                        SigningTransactionPayloadCodec.acknowledge()).kind());
    }

    @Test
    void acceptsExactTwoMibPayloadAndAccountsDetachedBytes() {
        MetadataKey key = new MetadataKey("io.zeroecho.test", "exact-limit");
        SigningTransactionPayloadCodec.Mutation empty =
                new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.CREATE, key, -1L, new byte[0]);
        int overhead = SigningTransactionPayloadCodec.encodedCommitSize(List.of(empty));
        byte[] value = new byte[SigningWalFrameCodec.MAX_PAYLOAD_BYTES - overhead];
        SigningTransactionPayloadCodec.Mutation exact =
                new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.CREATE, key, -1L, value);
        assertEquals(SigningWalFrameCodec.MAX_PAYLOAD_BYTES,
                SigningTransactionPayloadCodec.commit(List.of(exact)).length);
        assertEquals((long) value.length,
                SigningTransactionPayloadCodec.retainedMutationBytes(List.of(exact)));
    }

    @Test
    void sizingAndEncodingDoNotDefensivelyCopyMutationContent() {
        SigningTransactionPayloadCodec.Mutation mutation =
                new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.CREATE,
                        new MetadataKey("io.zeroecho.test", "copy-count"), -1L,
                        new byte[1024]);
        SigningTransactionPayloadCodec.resetContentCopyCount();
        int size = SigningTransactionPayloadCodec.encodedCommitSize(List.of(mutation));
        byte[] encoded = SigningTransactionPayloadCodec.commit(List.of(mutation));
        assertEquals(size, encoded.length);
        assertEquals(0L, SigningTransactionPayloadCodec.contentCopyCount());
    }

    private static byte[] rawMutation(int kind, long expected, MetadataKey key, int contentLength) {
        byte[] canonical = key.canonical().getBytes(StandardCharsets.US_ASCII);
        ByteBuffer output = ByteBuffer.allocate(1 + Long.BYTES + Integer.BYTES + canonical.length
                + Integer.BYTES + Math.max(0, contentLength)).order(ByteOrder.BIG_ENDIAN);
        output.put((byte) kind).putLong(expected).putInt(canonical.length).put(canonical)
                .putInt(contentLength);
        if (contentLength > 0) output.put(new byte[contentLength]);
        return output.array();
    }

    private static byte[] rawDirect(List<byte[]> mutations, long watermark) {
        int size = 12 + Long.BYTES;
        for (byte[] mutation : mutations) size += mutation.length;
        ByteBuffer output = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        output.putInt(0x5A455458).putShort((short) 1).putShort((short) 0)
                .put((byte) 6).put((byte) mutations.size()).putShort((short) 0);
        mutations.forEach(output::put);
        return output.putLong(watermark).array();
    }
}
