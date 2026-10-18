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
package zeroecho.ext.integrations.stegano;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import javax.imageio.ImageIO;

import org.junit.jupiter.api.Test;

class LSBSteganographyMethodLengthTest {
    private static final int PREFIX_BITS = Integer.SIZE;

    @Test
    void validBoundaryPayloadsRoundTrip() throws Exception {
        System.out.println("validBoundaryPayloadsRoundTrip");
        int[] lengths = { 0, 1, 127, 128, 256 };
        LSBSteganographyMethod method = new LSBSteganographyMethod();

        for (int length : lengths) {
            byte[] payload = payload(length);
            int carrierBits = PREFIX_BITS + length * Byte.SIZE;
            InputStream encoded = method.embed(image(carrierBits + Byte.SIZE), ImageFormat.PNG,
                    new ByteArrayInputStream(payload));
            byte[] decoded = method.extract(encoded).readAllBytes();
            assertArrayEquals(payload, decoded);
        }

        System.out.println("...boundary lengths: " + lengths.length);
        System.out.println("...ok");
    }

    @Test
    void exactCapacityAndInsufficientCapacityFailClosed() throws Exception {
        System.out.println("exactCapacityAndInsufficientCapacityFailClosed");
        LSBSteganographyMethod method = new LSBSteganographyMethod();
        byte[] payload = payload(16);
        int exactBits = PREFIX_BITS + payload.length * Byte.SIZE;

        InputStream encoded = method.embed(image(exactBits), ImageFormat.PNG, new ByteArrayInputStream(payload));
        assertArrayEquals(payload, method.extract(encoded).readAllBytes());

        IOException failure = assertThrows(IOException.class,
                () -> method.embed(image(exactBits - 1), ImageFormat.PNG, new ByteArrayInputStream(payload)));
        assertEquals("LSB payload exceeds carrier capacity.", failure.getMessage());
        System.out.println("...exact carrier bits: " + exactBits);
        System.out.println("...ok");
    }

    @Test
    void malformedPrefixesAndTruncatedPayloadsFailClosed() throws Exception {
        System.out.println("malformedPrefixesAndTruncatedPayloadsFailClosed");
        LSBSteganographyMethod method = new LSBSteganographyMethod();

        assertThrows(IOException.class, () -> method.extract(new ByteArrayInputStream(new byte[0])));
        assertThrows(EOFException.class, () -> method.extract(imageWithDeclaredLength(31, 0)));

        IOException negative = assertThrows(IOException.class,
                () -> method.extract(imageWithDeclaredLength(PREFIX_BITS, -1)));
        assertEquals("LSB payload length is invalid.", negative.getMessage());

        EOFException truncated = assertThrows(EOFException.class,
                () -> method.extract(imageWithDeclaredLength(PREFIX_BITS + Byte.SIZE, 2)));
        assertEquals("LSB carrier payload is truncated.", truncated.getMessage());
        assertFalse(truncated.getMessage().contains("PAYLOAD_SENTINEL"));
        System.out.println("...hostile prefix cases: 4");
        System.out.println("...ok");
    }

    @Test
    void everyIncompletePrefixAndRepresentativePayloadTruncationFailsClosed() throws Exception {
        System.out.println("everyIncompletePrefixAndRepresentativePayloadTruncationFailsClosed");
        LSBSteganographyMethod method = new LSBSteganographyMethod();

        IOException empty = assertThrows(IOException.class,
                () -> method.extract(new ByteArrayInputStream(new byte[0])));
        assertFalse(empty.getMessage().contains("PAYLOAD_SENTINEL"));
        for (int availablePrefixBits = 1; availablePrefixBits < PREFIX_BITS; availablePrefixBits++) {
            int testedPrefixBits = availablePrefixBits;
            EOFException failure = assertThrows(EOFException.class,
                    () -> method.extract(imageWithDeclaredLength(testedPrefixBits, 0)));
            assertEquals("LSB carrier length prefix is truncated.", failure.getMessage());
            assertFalse(failure.getMessage().contains("PAYLOAD_SENTINEL"));
        }

        assertArrayEquals(new byte[0],
                method.extract(imageWithDeclaredLength(PREFIX_BITS, 0)).readAllBytes());

        int declaredPayloadBytes = 4;
        int[] availablePayloadBits = { 0, 16, 31 };
        for (int payloadBits : availablePayloadBits) {
            EOFException failure = assertThrows(EOFException.class,
                    () -> method.extract(
                            imageWithDeclaredLength(PREFIX_BITS + payloadBits, declaredPayloadBytes)));
            assertEquals("LSB carrier payload is truncated.", failure.getMessage());
            assertFalse(failure.getMessage().contains("PAYLOAD_SENTINEL"));
        }

        System.out.println("...incomplete prefix positions: 32");
        System.out.println("...payload truncation positions: " + availablePayloadBits.length);
        System.out.println("...ok");
    }

    @Test
    void overCapacityMessageReadIsDeterministicallyBounded() throws Exception {
        System.out.println("overCapacityMessageReadIsDeterministicallyBounded");
        LSBSteganographyMethod method = new LSBSteganographyMethod();
        CountingInfiniteInputStream message = new CountingInfiniteInputStream();
        int payloadCapacity = 8;

        IOException failure = assertThrows(IOException.class,
                () -> method.embed(image(PREFIX_BITS + payloadCapacity * Byte.SIZE), ImageFormat.PNG, message));

        assertEquals("LSB payload exceeds carrier capacity.", failure.getMessage());
        assertEquals(payloadCapacity + 1, message.readCount);
        System.out.println("...bounded message reads: " + message.readCount);
        System.out.println("...ok");
    }

    private static byte[] payload(int length) {
        byte[] payload = new byte[length];
        for (int index = 0; index < payload.length; index++) {
            payload[index] = (byte) index;
        }
        return payload;
    }

    private static InputStream image(int pixels) throws IOException {
        BufferedImage image = new BufferedImage(pixels, 1, BufferedImage.TYPE_INT_RGB);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ImageIO.write(image, "png", output);
        return new ByteArrayInputStream(output.toByteArray());
    }

    private static InputStream imageWithDeclaredLength(int pixels, int declaredLength) throws IOException {
        BufferedImage image = new BufferedImage(pixels, 1, BufferedImage.TYPE_INT_RGB);
        int prefixBits = Math.min(pixels, PREFIX_BITS);
        for (int bitIndex = 0; bitIndex < prefixBits; bitIndex++) {
            int bit = (declaredLength >>> (PREFIX_BITS - 1 - bitIndex)) & 1;
            image.setRGB(bitIndex, 0, bit);
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ImageIO.write(image, "png", output);
        return new ByteArrayInputStream(output.toByteArray());
    }

    private static final class CountingInfiniteInputStream extends InputStream {
        private int readCount;

        @Override
        public int read() {
            readCount++;
            return 0x5a;
        }
    }
}
