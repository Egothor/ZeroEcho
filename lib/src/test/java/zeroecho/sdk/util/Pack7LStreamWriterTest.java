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
package zeroecho.sdk.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Random;

import org.junit.jupiter.api.Test;

class Pack7LStreamWriterTest {

    @Test
    void testSingleWriteCompletePayload() throws IOException {
        System.out.println("testSingleWriteCompletePayload");

        byte[] payload = new byte[50];
        new Random().nextBytes(payload);

        byte[] prefix = encodePack7L(payload.length);
        byte[] full = new byte[prefix.length + payload.length];
        System.arraycopy(prefix, 0, full, 0, prefix.length);
        System.arraycopy(payload, 0, full, prefix.length, payload.length);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Pack7LStreamWriter writer = new Pack7LStreamWriter(out);

        int consumed = writer.write(full);

        assertEquals(full.length, consumed);
        assertArrayEquals(payload, out.toByteArray());
        assertTrue(writer.isComplete());

        System.out.println("...ok");
    }

    @Test
    void testPartialLengthPrefixThenPayload() throws IOException {
        System.out.println("testPartialLengthPrefixThenPayload");

        byte[] payload = new byte[123];
        new Random().nextBytes(payload);

        byte[] prefix = encodePack7L(payload.length);
        byte[] all = new byte[prefix.length + payload.length];
        System.arraycopy(prefix, 0, all, 0, prefix.length);
        System.arraycopy(payload, 0, all, prefix.length, payload.length);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Pack7LStreamWriter writer = new Pack7LStreamWriter(out);

        int partialPrefixLen = 2;
        int consumed1 = writer.write(all, 0, partialPrefixLen);
        assertEquals(partialPrefixLen, consumed1);
        assertFalse(writer.isComplete());

        int consumed2 = writer.write(all, consumed1, all.length - consumed1);
        assertEquals(all.length - consumed1, consumed2);
        assertTrue(writer.isComplete());
        assertArrayEquals(payload, out.toByteArray());

        System.out.println("...ok");
    }

    @Test
    void testExtraDataTruncated() throws IOException {
        System.out.println("testExtraDataTruncated");

        byte[] payload = new byte[100];
        new Random().nextBytes(payload);
        byte[] extra = new byte[20];
        new Random().nextBytes(extra);

        byte[] prefix = encodePack7L(payload.length);
        byte[] full = new byte[prefix.length + payload.length + extra.length];

        System.arraycopy(prefix, 0, full, 0, prefix.length);
        System.arraycopy(payload, 0, full, prefix.length, payload.length);
        System.arraycopy(extra, 0, full, prefix.length + payload.length, extra.length);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Pack7LStreamWriter writer = new Pack7LStreamWriter(out);

        int consumed = writer.write(full);

        assertEquals(prefix.length + payload.length, consumed);
        assertArrayEquals(payload, out.toByteArray());
        assertTrue(writer.isComplete());

        System.out.println("...ok");
    }

    @Test
    void testChunkedPayload() throws IOException {
        System.out.println("testChunkedPayload");

        byte[] payload = new byte[2048];
        new Random().nextBytes(payload);
        byte[] prefix = encodePack7L(payload.length);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Pack7LStreamWriter writer = new Pack7LStreamWriter(out);

        writer.write(prefix);

        int totalConsumed = 0;
        for (int i = 0; i < payload.length; i += 512) {
            int chunkSize = Math.min(512, payload.length - i);
            int consumed = writer.write(payload, i, chunkSize);
            totalConsumed += consumed;
        }

        assertEquals(payload.length, totalConsumed);
        assertArrayEquals(payload, out.toByteArray());
        assertTrue(writer.isComplete());

        System.out.println("...ok");
    }

    @Test
    void testChunkedPayloadCycle() throws IOException {
        System.out.println("testChunkedPayloadCycle");

        byte[] payload = new byte[2048];
        new Random().nextBytes(payload);
        byte[] prefix = encodePack7L(payload.length);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Pack7LStreamWriter writer = new Pack7LStreamWriter(out);

        int prefix_consumed;

        // prefix is also controlled with "consumed" counter
        prefix_consumed = writer.write(prefix, 0, 1);
        assertEquals(1, prefix_consumed);

        prefix_consumed = writer.write(prefix, 1, prefix.length - 1);
        assertEquals(prefix.length - 1, prefix_consumed);

        int totalConsumed = 0;
        for (int i = 0; i < payload.length * 10; i += 512) {
            int chunkSize = Math.min(512, payload.length - i);
            int consumed = writer.write(payload, i, chunkSize);
            totalConsumed += consumed;

            if (consumed < chunkSize) {
                // the full block was not accepted
                break;
            }
        }

        assertEquals(payload.length, totalConsumed);
        assertArrayEquals(payload, out.toByteArray());
        assertTrue(writer.isComplete());

        System.out.println("...ok");
    }

    @Test
    void testWriteReturnsPartialIfTooMuchProvided() throws IOException {
        System.out.println("testWriteReturnsPartialIfTooMuchProvided");

        int payloadLen = 64;
        byte[] payload = new byte[payloadLen];
        new Random().nextBytes(payload);
        byte[] extra = new byte[10];
        new Random().nextBytes(extra);

        byte[] prefix = encodePack7L(payloadLen);
        byte[] full = new byte[prefix.length + payloadLen + extra.length];
        System.arraycopy(prefix, 0, full, 0, prefix.length);
        System.arraycopy(payload, 0, full, prefix.length, payloadLen);
        System.arraycopy(extra, 0, full, prefix.length + payloadLen, extra.length);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Pack7LStreamWriter writer = new Pack7LStreamWriter(out);

        int consumed = writer.write(full);

        assertEquals(prefix.length + payloadLen, consumed);
        assertArrayEquals(payload, out.toByteArray());
        assertTrue(writer.isComplete());

        System.out.println("...ok");
    }

    /**
     * Helper method to encode a long using 7-bit packed encoding.
     */
    private static byte[] encodePack7L(long val) {
        byte[] buf = new byte[10];
        int idx = buf.length;
        while ((val & ~0x7fL) != 0) {
            buf[--idx] = (byte) (val & 0x7f);
            val >>>= 7;
        }
        buf[--idx] = (byte) val;
        buf[buf.length - 1] = (byte) (buf[buf.length - 1] | 0x80);
        return Arrays.copyOfRange(buf, idx, buf.length);
    }
}
