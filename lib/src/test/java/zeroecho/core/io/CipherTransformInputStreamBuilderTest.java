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
package zeroecho.core.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.crypto.Cipher;

import org.junit.jupiter.api.Test;

class CipherTransformInputStreamBuilderTest {
    @Test
    void validatesEveryGeometryBoundaryWithoutAssertions() {
        System.out.print("ChunkTransform/geometry...");
        assertThrows(IllegalArgumentException.class, () -> new TestStream(1, 1, 1, 0));
        assertThrows(IllegalArgumentException.class, () -> new TestStream(0, 1, 1, 0));
        assertThrows(IllegalArgumentException.class, () -> new TestStream(2, 0, 1, 0));
        assertThrows(IllegalArgumentException.class, () -> new TestStream(2, 1, 0, 0));
        assertThrows(IllegalArgumentException.class, () -> new TestStream(2, 1, 1, -1));
        assertThrows(IllegalArgumentException.class, () -> new TestStream(Integer.MAX_VALUE, 1, 2, 0));
        assertThrows(IllegalArgumentException.class, () -> new TestStream(2, 1, Integer.MAX_VALUE, 1));
        assertThrows(IllegalArgumentException.class, () -> new TestStream(2, Integer.MAX_VALUE, 1, 1));

        new TestStream(2, 1, 1, 0);
        new TestStream(2, 1, 1, 1);
        System.out.println("ok");
    }

    @Test
    void rejectsInvalidTransformOutputCounts() {
        System.out.print("ChunkTransform/counts...");
        TestStream negative = new TestStream(2, 2, 1, 0);
        negative.transformCount = -1;
        assertThrows(IllegalStateException.class, negative::read);

        TestStream excessive = new TestStream(2, 2, 1, 0);
        excessive.transformCount = 3;
        assertThrows(IllegalStateException.class, excessive::read);

        TestStream finalExcessive = new TestStream(2, 2, 1, 0, new byte[0]);
        finalExcessive.finalCount = 3;
        assertThrows(IllegalStateException.class, finalExcessive::read);
        System.out.println("ok");
    }

    @Test
    void rejectsAesIndependentBlocksBeforeReadingUpstream() throws Exception {
        System.out.print("CipherBuilder/algorithm-guard...");
        CountingInputStream gcmInput = new CountingInputStream();
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        assertThrows(IllegalArgumentException.class, () -> CipherTransformInputStreamBuilder.builder()
                .withUpstream(gcmInput).withCipher(gcm).withIndependentBlocks().build());
        assertEquals(0, gcmInput.reads);

        CountingInputStream cbcInput = new CountingInputStream();
        Cipher cbc = Cipher.getInstance("AES/CBC/PKCS5Padding");
        assertThrows(IllegalArgumentException.class, () -> CipherTransformInputStreamBuilder.builder()
                .withUpstream(cbcInput).withCipher(cbc).withLeftZeroPadding(true).withIndependentBlocks().build());
        assertEquals(0, cbcInput.reads);
        System.out.println("ok");
    }

    private static final class TestStream extends AbstractChunkTransformInputStream {
        private int transformCount;
        private int finalCount;

        private TestStream(int inputChunk, int outputChunk, int chunks, int finalChunks) {
            this(inputChunk, outputChunk, chunks, finalChunks, new byte[] { 1, 2 });
        }

        private TestStream(int inputChunk, int outputChunk, int chunks, int finalChunks, byte[] input) {
            super(new ByteArrayInputStream(input), inputChunk, outputChunk, chunks, finalChunks);
            transformCount = outputChunk;
        }

        @Override
        protected int transform(byte[] input, int inputOffset, int inputChunks, byte[] output) {
            return transformCount;
        }

        @Override
        protected int doFinal(byte[] input, int inputOffset, int length, byte[] output, int outputOffset) {
            return finalCount;
        }
    }

    private static final class CountingInputStream extends InputStream {
        private int reads;

        @Override
        public int read() throws IOException {
            reads++;
            return -1;
        }
    }
}
