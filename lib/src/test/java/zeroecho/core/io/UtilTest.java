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
package zeroecho.core.io;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
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
}
