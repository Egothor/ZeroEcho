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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

final class SigningManifestCodecTest {

    @Test
    void canonicalRoundTripCopiesMutableInputs() throws Exception {
        byte[] checkpointDigest = digest(1);
        byte[] segmentDigest = digest(2);
        SigningManifestCodec.Manifest value = new SigningManifestCodec.Manifest(9L, 12L,
                Optional.of(new SigningManifestCodec.Checkpoint(30L, 8L, 4L, 100L, checkpointDigest,
                        SigningManifestCodec.checkpointName(8L, 4L))),
                List.of(new SigningManifestCodec.Segment(31L, 5L, 8L, 200L, segmentDigest,
                        SigningManifestCodec.segmentName(5L, 12L))),
                active(3L, 13L, 9L));
        byte[] encoded = SigningManifestCodec.encode(value);
        checkpointDigest[0] = 99;
        SigningManifestCodec.Manifest decoded = SigningManifestCodec.decode(encoded);
        assertEquals(value.committedRevision(), decoded.committedRevision());
        assertEquals(value.committedSequence(), decoded.committedSequence());
        assertEquals(value.checkpoint().orElseThrow().name(), decoded.checkpoint().orElseThrow().name());
        assertArrayEquals(digest(1), decoded.checkpoint().orElseThrow().commitment());
        assertArrayEquals(encoded, SigningManifestCodec.encode(decoded));
    }

    @Test
    void malformedEnvelopeAndLengthsFailBeforeAllocation() {
        byte[] valid = SigningManifestCodec.encode(genesis());
        for (int offset : List.of(0, 4, 6, 8, valid.length - 1)) {
            byte[] malformed = valid.clone();
            malformed[offset] ^= 1;
            assertThrows(IOException.class, () -> SigningManifestCodec.decode(malformed));
        }
        byte[] excessiveCount = valid.clone();
        ByteBuffer.wrap(excessiveCount).putInt(32, SigningManifestCodec.MAX_SEGMENTS + 1);
        resign(excessiveCount);
        assertThrows(IOException.class, () -> SigningManifestCodec.decode(excessiveCount));
        assertThrows(IOException.class, () -> SigningManifestCodec.decode(Arrays.copyOf(valid, valid.length - 1)));
        assertThrows(IOException.class, () -> SigningManifestCodec.decode(Arrays.copyOf(valid, valid.length + 1)));
    }

    @Test
    void namesRangesCommitmentsAndRevisionMustBeConsistent() {
        SigningManifestCodec.ActiveWal active = genesis().activeWal();
        assertThrows(IllegalArgumentException.class, () -> SigningManifestCodec.encode(
                new SigningManifestCodec.Manifest(0L, 1L, Optional.empty(), List.of(), active)));
        assertThrows(IllegalArgumentException.class, () -> SigningManifestCodec.encode(
                new SigningManifestCodec.Manifest(0L, 0L, Optional.empty(), List.of(
                        new SigningManifestCodec.Segment(2L, 1L, 1L, 1L, digest(1),
                                SigningManifestCodec.segmentName(1L, 1L))), active)));
        assertThrows(IllegalArgumentException.class, () -> SigningManifestCodec.encode(
                new SigningManifestCodec.Manifest(0L, 0L, Optional.empty(), List.of(),
                        new SigningManifestCodec.ActiveWal(0L, 0L, 0L, 1L, new byte[31],
                                SigningManifestCodec.activeName(0L)))));
        assertThrows(IllegalArgumentException.class, () -> SigningManifestCodec.encode(
                new SigningManifestCodec.Manifest(0L, 0L, Optional.empty(), List.of(),
                        new SigningManifestCodec.ActiveWal(0L, 0L, 0L, 1L, digest(1), "../active"))));
        for (String invalid : new String[] { "wal-high\ud800.zew", "wal-low\udc00.zew" }) {
            assertThrows(IllegalArgumentException.class, () -> new SigningManifestCodec.ActiveWal(
                    0L, 0L, 0L, 1L, digest(1), invalid));
        }
    }

    @Test
    void generationIdentitiesMustBeUniqueAcrossEveryArtifactKind() {
        SigningManifestCodec.ActiveWal active = active(7L, 1L, 1L);
        SigningManifestCodec.Checkpoint checkpoint = new SigningManifestCodec.Checkpoint(
                7L, 1L, 0L, 100L, digest(1),
                SigningManifestCodec.checkpointName(1L, 0L));
        assertThrows(IllegalArgumentException.class, () -> SigningManifestCodec.encode(
                new SigningManifestCodec.Manifest(1L, 0L, Optional.of(checkpoint),
                        List.of(), active)));

        SigningManifestCodec.Segment first = new SigningManifestCodec.Segment(
                2L, 0L, 1L, 100L, digest(2), SigningManifestCodec.segmentName(0L, 0L));
        SigningManifestCodec.Segment duplicate = new SigningManifestCodec.Segment(
                2L, 1L, 1L, 100L, digest(3), SigningManifestCodec.segmentName(1L, 1L));
        assertThrows(IllegalArgumentException.class, () -> SigningManifestCodec.encode(
                new SigningManifestCodec.Manifest(1L, 1L, Optional.empty(),
                        List.of(first, duplicate), active(7L, 2L, 1L))));
    }

    private static SigningManifestCodec.Manifest genesis() {
        return new SigningManifestCodec.Manifest(0L, 0L, Optional.empty(), List.of(),
                active(0L, 0L, 0L));
    }

    private static SigningManifestCodec.ActiveWal active(long identity, long first, long revision) {
        byte[] header = SigningWalContainerCodec.encode(
                new SigningWalContainerCodec.Header(identity, first, revision));
        return new SigningManifestCodec.ActiveWal(identity, first, revision, header.length,
                SigningFormatSupport.sha256().digest(header), SigningManifestCodec.activeName(identity));
    }

    private static byte[] digest(int seed) {
        byte[] value = new byte[32];
        Arrays.fill(value, (byte) seed);
        return value;
    }

    private static void resign(byte[] encoded) {
        byte[] digest = SigningFormatSupport.sha256().digest(Arrays.copyOf(encoded, encoded.length - 32));
        System.arraycopy(digest, 0, encoded, encoded.length - 32, 32);
    }
}
