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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.UUID;

import org.junit.jupiter.api.Test;

public class UtilTest {

    @Test
    public void testWriteAndReadUUID() throws IOException {
        System.out.println("testWriteAndReadUUID");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        UUID original = UUID.randomUUID();
        Util.write(baos, original);
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        UUID result = Util.readUUID(bais);
        assertEquals(original, result, "UUID should be preserved");
        System.out.println("...ok");
    }

    @Test
    public void testWriteAndReadUTF8() throws IOException {
        System.out.println("testWriteAndReadUTF8");
        String str = "Hello, world! こんにちは世界 🌍";
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Util.writeUTF8(baos, str);
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        String result = Util.readUTF8(bais, 1000);
        assertEquals(str, result, "UTF8 string should be preserved");
        System.out.println("...ok");
    }

    @Test
    public void testWriteAndReadLong() throws IOException {
        System.out.println("testWriteAndReadLong");
        long value = 1234567890123456789L;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Util.writeLong(baos, value);
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        long result = Util.readLong(bais);
        assertEquals(value, result, "Long value should be preserved");
        System.out.println("...ok");
    }

    @Test
    public void testWriteAndReadByteArray() throws IOException {
        System.out.println("testWriteAndReadByteArray");
        byte[] data = new byte[256];
        new Random().nextBytes(data);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Util.write(baos, data);
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        byte[] result = Util.read(bais, 1000);
        assertArrayEquals(data, result, "Byte array should be preserved");
        System.out.println("...ok");
    }

    @Test
    public void testReadWithMaxLengthExceeded() throws IOException {
        System.out.println("testReadWithMaxLengthExceeded");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // Write a packed integer length that's too large (e.g., 10_000_000)
        Util.writePack7I(baos, 10_000_000);
        baos.write(new byte[10]); // Minimal dummy data
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        IOException e = assertThrows(IOException.class, () -> Util.read(bais, 1000));
        assertTrue(e.getMessage().contains("exceeds maximum allowed length"), "Expected length limit exception");
        System.out.println("...ok");
    }

    @Test
    public void testReadUTF8WithMaxLengthExceeded() throws IOException {
        System.out.println("testReadUTF8WithMaxLengthExceeded");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Util.writePack7I(baos, 10_000_000);
        baos.write("dummy".getBytes(StandardCharsets.UTF_8));
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        IOException e = assertThrows(IOException.class, () -> Util.readUTF8(bais, 1000));
        assertTrue(e.getMessage().contains("exceeds maximum allowed length"), "Expected length limit exception");
        System.out.println("...ok");
    }

    @Test
    public void testPackedIntegerEncodingDecoding() throws IOException {
        System.out.println("testPackedIntegerEncodingDecoding");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int original = 987654;
        Util.writePack7I(baos, original);
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        int result = Util.readPack7I(bais);
        assertEquals(original, result, "Packed 7-bit integer should be preserved");

        baos.reset();
        long originalL = 9876543210L;
        Util.writePack7L(baos, originalL);
        bais = new ByteArrayInputStream(baos.toByteArray());
        long resultL = Util.readPack7L(bais);
        assertEquals(originalL, resultL, "Packed 7-bit long should be preserved");
        System.out.println("...ok");
    }

    @Test
    public void packedWritersPreserveWireBytesAtSignBitBoundaries() throws IOException {
        System.out.println("packedWritersPreserveWireBytesAtSignBitBoundaries");
        long[] values = { 0, 127, 128, 16383, 16384 };
        byte[][] encodings = { { (byte) 0x80 }, { (byte) 0xff }, { 1, (byte) 0x80 },
                { 127, (byte) 0xff }, { 1, 0, (byte) 0x80 } };
        for (int i = 0; i < values.length; i++) {
            ByteArrayOutputStream integer = new ByteArrayOutputStream();
            Util.writePack7I(integer, (int) values[i]);
            assertArrayEquals(encodings[i], integer.toByteArray());
            assertArrayEquals(encodings[i], encodePackedLong(values[i]));
            byte[] payload = new byte[(int) values[i]];
            byte[] framed = Util.readWithPackedLengthPrefix(new ByteArrayInputStream(payload), payload.length);
            byte[] expected = new byte[encodings[i].length + payload.length];
            System.arraycopy(encodings[i], 0, expected, 0, encodings[i].length);
            assertArrayEquals(expected, framed);
        }
        System.out.println("...ok");
    }

    @Test
    public void packedLongBoundaryRoundTripsAndConsumesExactly() throws IOException {
        System.out.println("packedLongBoundaryRoundTripsAndConsumesExactly");
        List<Long> values = packedLongBoundaryValues();
        for (long value : values) {
            byte[] encoded = encodePackedLong(value);
            assertEquals(canonicalPackedLongWidth(value), encoded.length, "Writer must use the canonical width");

            byte[] framed = new byte[encoded.length + 2];
            System.arraycopy(encoded, 0, framed, 0, encoded.length);
            framed[encoded.length] = 0x55;
            framed[encoded.length + 1] = (byte) 0xaa;
            ByteArrayInputStream input = new ByteArrayInputStream(framed);
            assertEquals(value, Util.readPack7L(input), "Packed long boundary value should round trip");
            assertEquals(0x55, input.read(), "Decoder must leave the first sentinel unread");
            assertEquals(0xaa, input.read(), "Decoder must leave the second sentinel unread");
        }

        ByteArrayInputStream nonCanonicalZero = new ByteArrayInputStream(new byte[] { 0x00, (byte) 0x80, 0x33 });
        assertEquals(0L, Util.readPack7L(nonCanonicalZero), "Existing non-minimal encodings must remain readable");
        assertEquals(0x33, nonCanonicalZero.read(), "Non-minimal decoding must consume exactly one value");
        System.out.println("...boundary values=" + values.size());
        System.out.println("...ok");
    }

    @Test
    public void packedLongRejectsInitialAndContinuationEof() throws IOException {
        System.out.println("packedLongRejectsInitialAndContinuationEof");
        EOFException initial = assertThrows(EOFException.class,
                () -> Util.readPack7L(new GuardedInputStream(new byte[0], 1)));
        assertEquals("read packed long EOF", initial.getMessage());

        byte[] maximumWidth = encodePackedLong(-1L);
        for (int length = 1; length < maximumWidth.length; length++) {
            byte[] truncated = new byte[length];
            System.arraycopy(maximumWidth, 0, truncated, 0, length);
            EOFException failure = assertThrows(EOFException.class,
                    () -> Util.readPack7L(new GuardedInputStream(truncated, truncated.length + 1)));
            assertEquals("read packed long EOF", failure.getMessage());
        }

        byte[] maximumUnterminated = new byte[10];
        IOException width = assertThrows(IOException.class,
                () -> Util.readPack7L(new GuardedInputStream(maximumUnterminated, maximumUnterminated.length)));
        assertEquals("packed long exceeds ten bytes", width.getMessage());
        System.out.println("...truncated prefixes=10");
        System.out.println("...ok");
    }

    @Test
    public void packedLongRejectsWidthAndOverflowWithinTenReads() throws IOException {
        System.out.println("packedLongRejectsWidthAndOverflowWithinTenReads");
        byte[] overflow = new byte[10];
        overflow[0] = 0x02;
        overflow[overflow.length - 1] = (byte) 0xff;
        GuardedInputStream overflowInput = new GuardedInputStream(overflow, 10);
        IOException overflowFailure = assertThrows(IOException.class, () -> Util.readPack7L(overflowInput));
        assertEquals("packed long exceeds 64 bits", overflowFailure.getMessage());
        assertEquals(10, overflowInput.readCount(), "Overflow rejection must use the fixed read bound");

        byte[] overWidth = new byte[11];
        overWidth[overWidth.length - 1] = (byte) 0x80;
        GuardedInputStream overWidthInput = new GuardedInputStream(overWidth, 10);
        IOException widthFailure = assertThrows(IOException.class, () -> Util.readPack7L(overWidthInput));
        assertEquals("packed long exceeds ten bytes", widthFailure.getMessage());
        assertEquals(10, overWidthInput.readCount(), "Decoder must not consume an eleventh byte");
        assertEquals(10, overWidthInput.position(), "The following byte must remain unread");

        byte[] oldWraparound = new byte[] { 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
                (byte) 0xff };
        IOException wrapFailure = assertThrows(IOException.class,
                () -> Util.readPack7L(new GuardedInputStream(oldWraparound, 10)));
        assertEquals("packed long exceeds 64 bits", wrapFailure.getMessage());
        System.out.println("...maximum decoder reads=10");
        System.out.println("...ok");
    }

    @Test
    public void testReadEOFHandling() throws IOException {
        System.out.println("testReadEOFHandling");
        ByteArrayInputStream bais = new ByteArrayInputStream(new byte[3]);
        assertThrows(EOFException.class, () -> Util.readLong(bais), "Expected EOFException for readLong");
        System.out.println("...ok");
    }

    @Test
    public void testWriteAndReadLargeData() throws IOException {
        System.out.println("testWriteAndReadLargeData");
        byte[] data = new byte[1024 * 1024]; // 1 MB
        new Random().nextBytes(data);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Util.write(baos, data);
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        byte[] result = Util.read(bais, data.length);
        assertArrayEquals(data, result, "Large byte array should be preserved");
        System.out.println("...ok");
    }

    private static List<Long> packedLongBoundaryValues() {
        List<Long> values = new ArrayList<>();
        values.add(Long.MIN_VALUE);
        values.add(Long.MIN_VALUE + 1);
        values.add(-1L);
        values.add(0L);
        values.add(1L);
        for (int bits = 7; bits <= 56; bits += 7) {
            long transition = 1L << bits;
            values.add(transition - 1);
            values.add(transition);
            values.add(transition + 1);
        }
        values.add(Long.MAX_VALUE);
        return values;
    }

    private static byte[] encodePackedLong(long value) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Util.writePack7L(output, value);
        return output.toByteArray();
    }

    private static int canonicalPackedLongWidth(long value) {
        int width = 1;
        while ((value & ~0x7fL) != 0) {
            width++;
            value >>>= 7;
        }
        return width;
    }

    private static final class GuardedInputStream extends InputStream {
        private final byte[] data;
        private final int maximumReads;
        private int position;
        private int readCount;

        private GuardedInputStream(byte[] data, int maximumReads) {
            this.data = data.clone();
            this.maximumReads = maximumReads;
        }

        @Override
        public int read() {
            if (readCount >= maximumReads) {
                throw new AssertionError("decoder exceeded the permitted read bound");
            }
            readCount++;
            if (position >= data.length) {
                return -1;
            }
            return data[position++] & 0xff;
        }

        private int position() {
            return position;
        }

        private int readCount() {
            return readCount;
        }
    }
}
