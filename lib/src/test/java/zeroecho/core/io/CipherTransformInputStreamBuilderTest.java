/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
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
        assertThrows(IllegalArgumentException.class,
                () -> new TestStream(2, 1, Integer.MAX_VALUE, 1));
        assertThrows(IllegalArgumentException.class,
                () -> new TestStream(2, Integer.MAX_VALUE, 1, 1));

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
        assertThrows(IllegalArgumentException.class,
                () -> CipherTransformInputStreamBuilder.builder().withUpstream(gcmInput).withCipher(gcm)
                        .withIndependentBlocks().build());
        assertEquals(0, gcmInput.reads);

        CountingInputStream cbcInput = new CountingInputStream();
        Cipher cbc = Cipher.getInstance("AES/CBC/PKCS5Padding");
        assertThrows(IllegalArgumentException.class,
                () -> CipherTransformInputStreamBuilder.builder().withUpstream(cbcInput).withCipher(cbc)
                        .withLeftZeroPadding(true).withIndependentBlocks().build());
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
