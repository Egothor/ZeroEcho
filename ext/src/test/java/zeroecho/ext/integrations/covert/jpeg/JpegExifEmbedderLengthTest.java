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
package zeroecho.ext.integrations.covert.jpeg;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.Util;

class JpegExifEmbedderLengthTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void validPackedPayloadBoundariesDecodeExactly() throws Exception {
        System.out.println("validPackedPayloadBoundariesDecodeExactly");
        int[] lengths = { 0, 1, 127, 128, 16_384, JpegExifEmbedder.MAXIMUM_PAYLOAD_BYTES };

        for (int length : lengths) {
            byte[] payload = payload(length);
            byte[] framed = frame(payload);
            List<byte[]> chunks = split(framed, 1, Math.min(97, framed.length));
            assertArrayEquals(payload, JpegExifEmbedder.decodePayloadChunks(chunks));
        }

        System.out.println("...packed boundary lengths: " + lengths.length);
        System.out.println("...ok");
    }

    @Test
    void malformedPackedLengthsAndTruncationFailClosed() throws Exception {
        System.out.println("malformedPackedLengthsAndTruncationFailClosed");

        for (int prefixBytes = 0; prefixBytes < 10; prefixBytes++) {
            byte[] incompletePrefix = new byte[prefixBytes];
            EOFException incomplete = assertThrows(EOFException.class,
                    () -> JpegExifEmbedder.decodePayloadChunks(List.of(incompletePrefix)));
            assertFalse(incomplete.getMessage().contains("PAYLOAD_SENTINEL"));
        }
        assertThrows(IOException.class, () -> JpegExifEmbedder.decodePayloadChunks(List.of(new byte[10])));

        byte[] excessive = packedLength(JpegExifEmbedder.MAXIMUM_PAYLOAD_BYTES + 1L);
        IOException overLimit = assertThrows(IOException.class,
                () -> JpegExifEmbedder.decodePayloadChunks(List.of(excessive)));
        assertEquals("JPEG EXIF payload length exceeds maximum.", overLimit.getMessage());

        byte[] negative = packedLength(-1L);
        assertThrows(IOException.class, () -> JpegExifEmbedder.decodePayloadChunks(List.of(negative)));

        byte[] illegalHighTerminal = new byte[10];
        illegalHighTerminal[0] = 0x02;
        illegalHighTerminal[9] = (byte) 0x80;
        assertThrows(IOException.class,
                () -> JpegExifEmbedder.decodePayloadChunks(List.of(illegalHighTerminal)));

        byte[] framed = frame(payload(12));
        int prefixLength = packedLength(12).length;
        int[] retainedPayloadBytes = { 0, 6, 11 };
        for (int retained : retainedPayloadBytes) {
            byte[] truncated = Arrays.copyOf(framed, prefixLength + retained);
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            EOFException incomplete = assertThrows(EOFException.class,
                    () -> output.write(JpegExifEmbedder.decodePayloadChunks(List.of(truncated))));
            assertEquals(0, output.size());
            assertEquals("JPEG EXIF payload is truncated.", incomplete.getMessage());
        }

        byte[] surplus = Arrays.copyOf(frame(payload(3)), frame(payload(3)).length + 4);
        assertArrayEquals(payload(3), JpegExifEmbedder.decodePayloadChunks(List.of(surplus)));
        byte[] firstResult = JpegExifEmbedder.decodePayloadChunks(List.of(frame(payload(3))));
        firstResult[0] ^= 0x7f;
        assertArrayEquals(payload(3), JpegExifEmbedder.decodePayloadChunks(List.of(frame(payload(3)))));
        System.out.println("...hostile packed cases: 18");
        System.out.println("...ok");
    }

    @Test
    void realJpegRoundTripPreservesPayload() throws Exception {
        System.out.println("realJpegRoundTripPreservesPayload");
        URL carrierResource = Objects.requireNonNull(
                getClass().getClassLoader().getResource("test.jpg"));
        Path carrier = Path.of(carrierResource.toURI());
        Path encoded = temporaryDirectory.resolve("encoded.jpg");
        byte[] payload = payload(512);

        JpegExifEmbedder embedder = new JpegExifEmbedder();
        embedder.setSlots(Slot.defaults());
        try (ByteArrayOutputStream jpegOutput = new ByteArrayOutputStream()) {
            int framedBytes = embedder.embed(carrier, new ByteArrayInputStream(payload), jpegOutput);
            Files.write(encoded, jpegOutput.toByteArray());
            assertEquals(frame(payload).length, framedBytes);
        }

        ByteArrayOutputStream extracted = new ByteArrayOutputStream();
        embedder.extract(encoded, extracted);
        assertArrayEquals(payload, extracted.toByteArray());
        System.out.println("...round-trip payload bytes: " + payload.length);
        System.out.println("...ok");
    }

    @Test
    void embeddingRejectsOverCapacityBeforeOutput() throws Exception {
        System.out.println("embeddingRejectsOverCapacityBeforeOutput");
        JpegExifEmbedder embedder = new JpegExifEmbedder();
        embedder.setSlots(Slot.defaults());
        byte[] payload = payload(20_000);
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        IOException failure = assertThrows(IOException.class,
                () -> embedder.embed(temporaryDirectory.resolve("unused.jpg"), new ByteArrayInputStream(payload),
                        output));

        assertEquals(0, output.size());
        assertEquals("Input exceeds maximum allowed size: 10238", failure.getMessage());
        System.out.println("...rejected payload bytes: " + payload.length);
        System.out.println("...ok");
    }

    @Test
    void allConstructionPathsRequireValidSlots() {
        System.out.println("allConstructionPathsRequireValidSlots");
        JpegExifEmbedder embedder = new JpegExifEmbedder();
        Slot duplicate = customRawSlot(50_100, 64);

        assertThrows(IllegalArgumentException.class, () -> embedder.setSlots(List.of()));
        assertThrows(IllegalArgumentException.class, () -> embedder.setSlots(List.of(duplicate, duplicate)));
        assertThrows(IllegalStateException.class,
                () -> embedder.extract(temporaryDirectory.resolve("unused.jpg"), new ByteArrayOutputStream()));
        System.out.println("...slot validation paths: 3");
        System.out.println("...ok");
    }

    @Test
    void parsedExifPayloadBoundariesFailWithoutOutput() throws Exception {
        System.out.println("parsedExifPayloadBoundariesFailWithoutOutput");
        Slot first = customRawSlot(50_110, 8);
        Slot second = customRawSlot(50_111, 64);
        byte[] expected = payload(24);
        byte[] jpeg = embeddedJpeg(expected, List.of(first, second));

        assertExtractionFails(jpeg, List.of(first));
        assertArrayEquals(expected, extractPayload(jpeg, List.of(first, second)));
        System.out.println("...validated EXIF slots: 2");
        System.out.println("...ok");
    }

    @Test
    void hostileExifSlotsFailClosedWithoutPartialOutput() throws Exception {
        System.out.println("hostileExifSlotsFailClosedWithoutPartialOutput");
        Slot raw = customRawSlot(50_120, 64);
        Slot anotherRaw = customRawSlot(50_121, 64);
        byte[] validRaw = embeddedJpeg(payload(20), List.of(raw));

        assertExtractionFails(validRaw, List.of(anotherRaw));
        assertExtractionFails(validRaw, List.of(customRawSlot(50_120, 8)));

        Slot first = customRawSlot(50_122, 8);
        Slot second = customRawSlot(50_123, 64);
        byte[] splitPayload = embeddedJpeg(payload(24), List.of(first, second));
        assertExtractionFails(splitPayload, List.of(first));
        assertExtractionFails(splitPayload, List.of(second, first));

        System.out.println("...bounded EXIF slot cases: 4");
        System.out.println("...ok");
    }

    @Test
    void configuredCapacityAndMaximumAreEnforcedBeforeCallerOutput() throws Exception {
        System.out.println("configuredCapacityAndMaximumAreEnforcedBeforeCallerOutput");
        byte[] excessive = packedLength(JpegExifEmbedder.MAXIMUM_PAYLOAD_BYTES + 1L);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        assertThrows(IOException.class,
                () -> output.write(JpegExifEmbedder.decodePayloadChunks(List.of(excessive))));
        assertEquals(0, output.size());

        Slot largeText = customTextSlot(50_130, Integer.MAX_VALUE);
        JpegExifEmbedder embedder = new JpegExifEmbedder();
        embedder.setSlots(List.of(largeText));
        IOException missingCarrier = assertThrows(IOException.class,
                () -> embedder.embed(temporaryDirectory.resolve("missing.jpg"),
                        new ByteArrayInputStream(payload(1)), new ByteArrayOutputStream()));
        assertFalse(missingCarrier.getMessage().contains("PAYLOAD_SENTINEL"));
        System.out.println("...maximum payload bytes: " + JpegExifEmbedder.MAXIMUM_PAYLOAD_BYTES);
        System.out.println("...ok");
    }

    private static byte[] payload(int length) {
        byte[] payload = new byte[length];
        for (int index = 0; index < payload.length; index++) {
            payload[index] = (byte) index;
        }
        return payload;
    }

    private static byte[] frame(byte[] payload) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Util.writePack7L(output, payload.length);
        output.write(payload);
        return output.toByteArray();
    }

    private static byte[] packedLength(long length) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Util.writePack7L(output, length);
        return output.toByteArray();
    }

    private static List<byte[]> split(byte[] value, int firstLength, int nextLength) {
        if (value.length <= firstLength) {
            return List.of(value);
        }
        byte[] first = Arrays.copyOfRange(value, 0, firstLength);
        byte[] remaining = Arrays.copyOfRange(value, firstLength, value.length);
        if (remaining.length <= nextLength) {
            return List.of(first, remaining);
        }
        byte[] second = Arrays.copyOfRange(remaining, 0, nextLength);
        byte[] third = Arrays.copyOfRange(remaining, nextLength, remaining.length);
        return List.of(first, second, third);
    }

    private Path carrierPath() throws Exception {
        URL carrierResource = Objects.requireNonNull(getClass().getClassLoader().getResource("test.jpg"));
        return Path.of(carrierResource.toURI());
    }

    private byte[] embeddedJpeg(byte[] payload, List<Slot> slots) throws Exception {
        JpegExifEmbedder embedder = new JpegExifEmbedder();
        embedder.setSlots(slots);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        embedder.embed(carrierPath(), new ByteArrayInputStream(payload), output);
        return output.toByteArray();
    }

    private void assertExtractionFails(byte[] jpeg, List<Slot> slots) throws Exception {
        Path path = temporaryDirectory.resolve("hostile-" + Math.abs(Arrays.hashCode(jpeg)) + ".jpg");
        Files.write(path, jpeg);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        JpegExifEmbedder embedder = new JpegExifEmbedder();
        embedder.setSlots(slots);
        IOException failure = assertThrows(IOException.class, () -> embedder.extract(path, output));
        assertEquals(0, output.size());
        assertFalse(failure.getMessage().contains("PAYLOAD_SENTINEL"));
    }

    private byte[] extractPayload(byte[] jpeg, List<Slot> slots) throws Exception {
        Path path = temporaryDirectory.resolve("valid-" + Math.abs(Arrays.hashCode(jpeg)) + ".jpg");
        Files.write(path, jpeg);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        JpegExifEmbedder embedder = new JpegExifEmbedder();
        embedder.setSlots(slots);
        embedder.extract(path, output);
        return output.toByteArray();
    }

    private static Slot customRawSlot(int tag, int capacity) {
        return Slot.parse("EXIF.raw/tag=" + tag + ",undefined,1,exif:" + capacity);
    }

    private static Slot customTextSlot(int tag, int capacity) {
        return Slot.parse("EXIF.text/tag=" + tag + ",ascii,1,exif:" + capacity);
    }

}
