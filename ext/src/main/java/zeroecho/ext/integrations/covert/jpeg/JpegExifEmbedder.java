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
package zeroecho.ext.integrations.covert.jpeg;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import org.apache.commons.imaging.Imaging;
import org.apache.commons.imaging.ImagingException;
import org.apache.commons.imaging.common.ImageMetadata;
import org.apache.commons.imaging.formats.jpeg.JpegImageMetadata;
import org.apache.commons.imaging.formats.jpeg.exif.ExifRewriter;
import org.apache.commons.imaging.formats.tiff.TiffField;
import org.apache.commons.imaging.formats.tiff.TiffImageMetadata;
import org.apache.commons.imaging.formats.tiff.write.TiffOutputDirectory;
import org.apache.commons.imaging.formats.tiff.write.TiffOutputField;
import org.apache.commons.imaging.formats.tiff.write.TiffOutputSet;

import zeroecho.core.io.Util;

/**
 * Utility class for embedding and extracting binary payloads across multiple
 * EXIF slots in JPEG files.
 * <p>
 * The configured slot list defines both the location and chunking order of the
 * embedded payload. Slot types are respected — for example, ASCII fields
 * automatically use Base64 encoding to ensure compatibility with textual EXIF
 * constraints.
 * </p>
 * <p>
 * The original JPEG EXIF metadata is preserved, except for any overwritten
 * fields defined via slot configuration.
 * </p>
 *
 * <p>
 * This is an incubating integration, not a general-purpose parser for hostile
 * JPEG input. Structural JPEG and TIFF/EXIF parsing is delegated to Apache
 * Commons Imaging. This class independently validates its covert Pack7 framing,
 * configured slot order and capacity, duplicate slots, payload completeness, and
 * the one-MiB covert-payload limit. Successful parsing by the underlying library
 * does not guarantee rejection of every malformed JPEG marker or APP1 boundary.
 * Callers accepting fully untrusted images should perform separate structural
 * validation or process them in an appropriate sandbox.
 * </p>
 *
 * <p>
 * No partial covert payload is written when the declared ZeroEcho payload is
 * incomplete. Covert-payload memory is bounded by configured slot capacity and
 * one MiB, subject to the independent resource behavior of Apache Commons
 * Imaging while parsing the carrier. The existing EXIF-slot and Pack7 on-wire
 * representation is unchanged.
 * </p>
 */
public final class JpegExifEmbedder {
    /* package */ static final int MAXIMUM_PAYLOAD_BYTES = 1024 * 1024;
    private static final int MAXIMUM_PACKED_PREFIX_BYTES = 10;

    private final List<Slot> slots = new ArrayList<>();

    /**
     * Creates an embedder with no configured EXIF slots.
     *
     * <p>{@link #setSlots(List)} must be called before embedding or extraction.</p>
     */
    public JpegExifEmbedder() {
        // Slot configuration is supplied explicitly by the caller.
    }

    /**
     * Configures the list of EXIF slots to be used for payload embedding and
     * extraction. The order determines the splitting/joining order of the payload.
     * Slots must be unique and have positive capacities.
     *
     * @param slots nonempty list of positive-capacity slot configurations
     * @throws IllegalArgumentException if the list is empty or contains a
     *                                  {@code null} or nonpositive-capacity slot
     */
    public void setSlots(List<Slot> slots) {
        requireValidSlots(slots);
        this.slots.clear();
        this.slots.addAll(slots);
    }

    /**
     * Embeds a binary payload into a JPEG file by spreading the data across a
     * series of pre-configured EXIF slots.
     * <p>
     * The payload is read from the provided {@code InputStream}, prefixed using
     * 7-bit variable-length encoding, and split across EXIF fields based on their
     * capacity and type. Fields that accept only text data will store the payload
     * encoded as Base64. The modified JPEG is then written to the given output
     * stream using a lossless EXIF update.
     * </p>
     *
     * <p>
     * Apache Commons Imaging owns structural JPEG and TIFF/EXIF parsing. This
     * method limits the covert payload to one MiB and configured slot capacity,
     * but it is not an independent validator for arbitrary outer JPEG corruption.
     * </p>
     *
     * @param jpegPath     the path to the input JPEG file; must not be {@code null}
     * @param payloadInput the input stream containing the binary payload to embed;
     *                     it must be prefixed using 7-bit length encoding (e.g.
     *                     {@code writePack7L})
     * @param jpegOutput   the output stream where the modified JPEG will be written
     * @return the total number of bytes read from {@code payloadInput}, including
     *         the prefix
     * @throws IOException              if an I/O error occurs, the payload exceeds
     *                                  one MiB or configured slot capacity, or EXIF
     *                                  processing fails
     * @throws IllegalStateException    if no slots have been configured
     */
    public int embed(Path jpegPath, InputStream payloadInput, OutputStream jpegOutput) throws IOException {
        requireConfiguredSlots();
        int maximumPayloadBytes = maximumPayloadBytesForSlots();
        byte[] allBytes = Util.readWithPackedLengthPrefix(payloadInput, maximumPayloadBytes);
        long totalCapacity = totalRawCapacity();
        if (allBytes.length > totalCapacity) {
            throw new IOException("JPEG EXIF payload exceeds configured slot capacity.");
        }

        try {
            ImageMetadata metadata = Imaging.getMetadata(jpegPath.toFile());
            TiffImageMetadata exif = (metadata instanceof JpegImageMetadata jmeta) ? jmeta.getExif() : null;

            TiffOutputSet outputSet = (exif != null) ? exif.getOutputSet() : new TiffOutputSet(ByteOrder.BIG_ENDIAN);

            int offset = 0;

            for (Slot slot : slots) {
                if (offset >= allBytes.length) {
                    break;
                }
                boolean useBase64 = slot.tagInfo.isText();
                int chunkLimit = rawCapacity(slot);

                byte[] encoded;
                if (useBase64) {
                    int size = Math.min(chunkLimit, allBytes.length - offset);
                    byte[] raw = new byte[size]; // NOPMD
                    System.arraycopy(allBytes, offset, raw, 0, size);
                    offset += size;

                    byte[] base64Bytes = Base64.getEncoder().encode(raw);
                    String base64String = new String(base64Bytes, StandardCharsets.US_ASCII); // NOPMD

                    encoded = slot.tagInfo.encodeValue(slot.tagInfo.dataTypes.get(0), base64String,
                            outputSet.byteOrder);
                } else {
                    int size = Math.min(chunkLimit, allBytes.length - offset);
                    byte[] chunk = new byte[size]; // NOPMD
                    System.arraycopy(allBytes, offset, chunk, 0, size);
                    offset += size;

                    encoded = slot.tagInfo.encodeValue(slot.tagInfo.dataTypes.get(0), chunk, outputSet.byteOrder);
                }

                int directoryType = slot.tagInfo.directoryType.directoryType;
                TiffOutputDirectory directory = outputSet.findDirectory(directoryType);
                if (directory == null) {
                    directory = new TiffOutputDirectory(directoryType, outputSet.byteOrder); // NOPMD
                    outputSet.addDirectory(directory);
                }

                TiffOutputField field = new TiffOutputField(slot.tagInfo, slot.tagInfo.dataTypes.get(0), encoded.length, // NOPMD
                        encoded);

                directory.removeField(slot.tagInfo); // Remove only if collides
                directory.add(field);

            }

            if (offset != allBytes.length) {
                throw new IOException("JPEG EXIF payload exceeds configured slot capacity.");
            }
            new ExifRewriter().updateExifMetadataLossless(jpegPath.toFile(), jpegOutput, outputSet);

            return allBytes.length;
        } catch (ImagingException e) {
            throw new IOException("Failed to process EXIF data", e);
        }
    }

    /**
     * Extracts a binary payload that was previously embedded into the JPEG via EXIF
     * slots.
     *
     * <p>
     * Apache Commons Imaging parses the carrier structure. ZeroEcho validates the
     * selected EXIF fields, Pack7 length, configured capacity, and complete
     * availability of the declared covert payload before writing caller output.
     * Outer marker and APP1 corruption accepted by the underlying parser is outside
     * this method's independent guarantees.
     * </p>
     *
     * @param jpegPath      input JPEG path
     * @param payloadOutput stream to write the reconstructed binary payload
     * @throws EOFException          if the packed length prefix or declared
     *                               payload is incomplete
     * @throws IOException           if supported carrier parsing fails or the
     *                               payload length or configured slot data is
     *                               malformed or exceeds one MiB
     * @throws IllegalStateException if no slots have been configured
     */
    public void extract(Path jpegPath, OutputStream payloadOutput) throws IOException {
        requireConfiguredSlots();
        try {
            ImageMetadata metadata = Imaging.getMetadata(jpegPath.toFile());
            TiffImageMetadata exif = (metadata instanceof JpegImageMetadata jmeta) ? jmeta.getExif() : null;

            if (exif == null) {
                throw new EOFException("JPEG EXIF covert payload is missing.");
            }

            PackedPayloadCollector collector = new PackedPayloadCollector();

            for (Slot slot : slots) {
                TiffField field = exif.findField(slot.tagInfo);
                if (field == null) {
                    continue;
                }
                requireBoundedField(field, slot);

                Object value = slot.tagInfo.getValue(field);
                byte[] chunk = decodeChunk(value, slot);
                if (chunk.length > rawCapacity(slot)) {
                    throw new IOException("JPEG EXIF covert chunk exceeds slot capacity.");
                }
                collector.accept(chunk);
                if (collector.isComplete()) {
                    break;
                }
            }
            byte[] payload = collector.finish();
            payloadOutput.write(payload);
        } catch (ImagingException e) {
            throw new IOException("Failed to read EXIF from JPEG", e);
        }
    }

    private void requireConfiguredSlots() {
        if (slots.isEmpty()) {
            throw new IllegalStateException("JPEG EXIF slots are not configured.");
        }
    }

    private static void requireValidSlots(List<Slot> configuredSlots) {
        if (configuredSlots == null || configuredSlots.isEmpty()) {
            throw new IllegalArgumentException("JPEG EXIF slots must not be empty.");
        }
        for (int index = 0; index < configuredSlots.size(); index++) {
            Slot slot = configuredSlots.get(index);
            if (slot == null || slot.defaultCapacity <= 0) {
                throw new IllegalArgumentException("JPEG EXIF slot capacity must be positive.");
            }
            if (configuredSlots.subList(0, index).contains(slot)) {
                throw new IllegalArgumentException("JPEG EXIF slots must be unique.");
            }
        }
    }

    private int maximumPayloadBytesForSlots() throws IOException {
        long capacity = totalRawCapacity();
        int candidate = (int) Math.min(MAXIMUM_PAYLOAD_BYTES, capacity);
        while (candidate > 0 && candidate + packedLengthBytes(candidate) > capacity) {
            candidate--;
        }
        if (packedLengthBytes(candidate) > capacity) {
            throw new IOException("JPEG EXIF slot capacity cannot contain a payload prefix.");
        }
        return candidate;
    }

    private long totalRawCapacity() throws IOException {
        long capacity = 0;
        try {
            for (Slot slot : slots) {
                capacity = Math.addExact(capacity, rawCapacity(slot));
            }
            return capacity;
        } catch (ArithmeticException exception) {
            throw new IOException("JPEG EXIF slot capacity is invalid.", exception);
        }
    }

    private static int rawCapacity(Slot slot) {
        return slot.tagInfo.isText() ? slot.defaultCapacity / 4 * 3 : slot.defaultCapacity;
    }

    private static int packedLengthBytes(long value) {
        int bytes = 1;
        long remaining = value;
        while ((remaining & ~0x7fL) != 0) {
            remaining >>>= 7;
            bytes++;
        }
        return bytes;
    }

    private static void requireBoundedField(TiffField field, Slot slot) throws IOException {
        final long encodedLength;
        try {
            encodedLength = Math.multiplyExact(field.getCount(), field.getFieldType().getSize());
        } catch (ArithmeticException exception) {
            throw new IOException("JPEG EXIF covert field length is invalid.", exception);
        }
        long maximumStoredBytes = slot.tagInfo.isText()
                ? Math.min((long) slot.defaultCapacity + 1, encodedLimitForPayload())
                : Math.min((long) slot.defaultCapacity, MAXIMUM_PAYLOAD_BYTES + MAXIMUM_PACKED_PREFIX_BYTES);
        if (encodedLength < 0 || encodedLength > maximumStoredBytes) {
            throw new IOException("JPEG EXIF covert field exceeds slot capacity.");
        }
    }

    private static long encodedLimitForPayload() {
        long rawBytes = MAXIMUM_PAYLOAD_BYTES + MAXIMUM_PACKED_PREFIX_BYTES;
        return (rawBytes + 2) / 3 * 4 + 1;
    }

    private static byte[] decodeChunk(Object value, Slot slot) throws IOException {
        byte[] chunk = null;
        try {
            if (value instanceof byte[] binary) {
                chunk = slot.tagInfo.isText() ? Base64.getDecoder().decode(binary) : binary;
            } else if (value instanceof String string) {
                chunk = slot.tagInfo.isText()
                        ? Base64.getDecoder().decode(string.getBytes(StandardCharsets.US_ASCII))
                        : string.getBytes(StandardCharsets.UTF_8);
            }
        } catch (IllegalArgumentException exception) {
            chunk = null;
        }
        if (chunk == null) {
            throw new IOException("JPEG EXIF covert chunk is malformed.");
        }
        return chunk;
    }

    /* package */ static byte[] decodePayloadChunks(List<byte[]> chunks) throws IOException {
        PackedPayloadCollector collector = new PackedPayloadCollector();
        for (byte[] chunk : chunks) {
            collector.accept(chunk);
            if (collector.isComplete()) {
                break;
            }
        }
        return collector.finish();
    }

    /**
     * Accumulates one bounded Pack7-framed payload across configured EXIF slots.
     */
    private static final class PackedPayloadCollector {
        private final byte[] prefix = new byte[MAXIMUM_PACKED_PREFIX_BYTES];
        private int prefixLength;
        private byte[] payload;
        private int payloadLength;

        /* package */ void accept(byte[] chunk) throws IOException {
            int offset = 0;
            boolean prefixComplete = false;
            while (payload == null && offset < chunk.length) {
                if (prefixLength == prefix.length) {
                    throw new IOException("JPEG EXIF packed payload length is malformed.");
                }
                byte current = chunk[offset++];
                prefix[prefixLength++] = current;
                if ((current & 0x80) != 0) {
                    prefixComplete = true;
                    break;
                }
            }
            if (prefixComplete) {
                long declaredLength = Util.readPack7L(new ByteArrayInputStream(prefix, 0, prefixLength));
                if (declaredLength < 0 || declaredLength > MAXIMUM_PAYLOAD_BYTES) {
                    throw new IOException("JPEG EXIF payload length exceeds maximum.");
                }
                payload = new byte[(int) declaredLength];
            }
            if (payload != null && offset < chunk.length && payloadLength < payload.length) {
                int remaining = payload.length - payloadLength;
                int copied = Math.min(remaining, chunk.length - offset);
                System.arraycopy(chunk, offset, payload, payloadLength, copied);
                payloadLength += copied;
            }
        }

        /* package */ boolean isComplete() {
            return payload != null && payloadLength == payload.length;
        }

        /* package */ byte[] finish() throws EOFException {
            if (payload == null) {
                throw new EOFException("JPEG EXIF payload length prefix is truncated.");
            }
            if (payloadLength != payload.length) {
                throw new EOFException("JPEG EXIF payload is truncated.");
            }
            return Arrays.copyOf(payload, payload.length);
        }
    }
}
