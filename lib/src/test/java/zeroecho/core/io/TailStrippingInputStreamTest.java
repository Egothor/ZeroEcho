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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.random.RandomGenerator;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class TailStrippingInputStreamTest {

    private static final int TAIL_LEN = 64;
    private static final int IO_BUF = 4096;

    @Test
    @DisplayName("Short stream (<64 bytes) → body=0, tail=all")
    void testShortStream() throws Exception {
        final String method = "testShortStream(tailLen=" + TAIL_LEN + ", ioBuf=" + IO_BUF + ")";
        System.out.println(method);

        final byte[] input = randomBytes(37); // < 64
        System.out.println("... input size: " + input.length);

        final CapturingTailStream ts = new CapturingTailStream(new ByteArrayInputStream(input), TAIL_LEN, IO_BUF);
        final byte[] body;
        try (InputStream in = ts) {
            body = in.readAllBytes();
            System.out.println("... body size: " + body.length);
        }
        final byte[] tail = ts.getTail(); // printed at processTail() time

        // Assertions
        assertEquals(0, body.length, "Body must be empty when input < tailLen");
        assertArrayEquals(input, tail, "Tail must equal the entire short input");

        System.out.println("...ok");
    }

    @Test
    @DisplayName("Large stream (>64 KiB) → body=input[0..n-tailLen), tail=last tailLen")
    void testLargeStream() throws Exception {
        final int size = 128 * 1024 + 5; // > 64 KiB
        final String method = "testLargeStream(size=" + size + ", tailLen=" + TAIL_LEN + ", ioBuf=" + IO_BUF + ")";
        System.out.println(method);

        final byte[] input = randomBytes(size);
        System.out.println("... input size: " + input.length);

        final CapturingTailStream ts = new CapturingTailStream(new ByteArrayInputStream(input), TAIL_LEN, IO_BUF);
        final byte[] body;
        try (InputStream in = ts) {
            body = in.readAllBytes();
            System.out.println("... body size: " + body.length);
        }
        final byte[] tail = ts.getTail(); // printed at processTail() time

        // Expected splits
        final int bodyLen = input.length - TAIL_LEN;
        final byte[] expectedBody = new byte[bodyLen];
        final byte[] expectedTail = new byte[TAIL_LEN];
        System.arraycopy(input, 0, expectedBody, 0, bodyLen);
        System.arraycopy(input, bodyLen, expectedTail, 0, TAIL_LEN);

        // Assertions
        assertEquals(bodyLen, body.length, "Body length mismatch");
        assertArrayEquals(expectedBody, body, "Body payload mismatch");
        assertEquals(TAIL_LEN, tail.length, "Tail length mismatch");
        assertArrayEquals(expectedTail, tail, "Tail payload mismatch");

        System.out.println("...ok");
    }

    // ---------- Helpers ----------

    private static byte[] randomBytes(int size) {
        byte[] data = new byte[size];
        RandomGenerator rng = RandomGenerator.of("L64X256MixRandom");
        rng.nextBytes(data);
        return data;
    }

    /**
     * Test adapter that captures and prints the tail immediately when available.
     */
    private static final class CapturingTailStream extends TailStrippingInputStream {
        private byte[] tail;

        CapturingTailStream(InputStream upstream, int tailLen, int ioBuffer) {
            super(upstream, tailLen, ioBuffer);
        }

        @Override
        protected void processTail(byte[] tail) throws IOException {
            this.tail = tail;
            System.out.println("... tail size: " + tail.length);
        }

        byte[] getTail() {
            return tail == null ? new byte[0] : tail.clone();
        }
    }
}
