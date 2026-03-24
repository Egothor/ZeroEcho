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
package zeroecho.sdk.integrations.covert.jpeg;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

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
import zeroecho.sdk.util.Pack7LStreamWriter;

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
 */
public final class JpegExifEmbedder {
    private static final Logger LOG = Logger.getLogger(JpegExifEmbedder.class.getName());

    private final List<Slot> slots = new ArrayList<>();

    /**
     * Configures the list of EXIF slots to be used for payload embedding and
     * extraction. The order determines the splitting/joining order of the payload.
     *
     * @param slots List of slot configurations
     */
    public void setSlots(List<Slot> slots) {
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
     * @param jpegPath     the path to the input JPEG file; must not be {@code null}
     * @param payloadInput the input stream containing the binary payload to embed;
     *                     it must be prefixed using 7-bit length encoding (e.g.
     *                     {@code writePack7L})
     * @param jpegOutput   the output stream where the modified JPEG will be written
     * @return the total number of bytes read from {@code payloadInput}, including
     *         the prefix
     * @throws IOException if an I/O error occurs while reading the payload,
     *                     processing EXIF metadata, or writing the output JPEG
     */
    public int embed(Path jpegPath, InputStream payloadInput, OutputStream jpegOutput) throws IOException {
        try {
            ImageMetadata metadata = Imaging.getMetadata(jpegPath.toFile());
            TiffImageMetadata exif = (metadata instanceof JpegImageMetadata jmeta) ? jmeta.getExif() : null;

            TiffOutputSet outputSet = (exif != null) ? exif.getOutputSet() : new TiffOutputSet(ByteOrder.BIG_ENDIAN);

            byte[] allBytes = Util.readWithPackedLengthPrefix(payloadInput, 1024 * 1024);
            int offset = 0;

            for (Slot slot : slots) {
                boolean useBase64 = slot.tagInfo.isText();
                int chunkLimit = slot.defaultCapacity;

                byte[] encoded;
                if (useBase64) {
                    // base64 expands ~33%, so reduce raw chunk size
                    int safeRawSize = chunkLimit * 3 / 4;
                    int size = Math.min(safeRawSize, allBytes.length - offset);
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

                if (offset >= allBytes.length) {
                    break;
                }
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
     * @param jpegPath      input JPEG path
     * @param payloadOutput stream to write the reconstructed binary payload
     * @throws IOException if the extraction fails
     */
    public void extract(Path jpegPath, OutputStream payloadOutput) throws IOException {
        try {
            ImageMetadata metadata = Imaging.getMetadata(jpegPath.toFile());
            TiffImageMetadata exif = (metadata instanceof JpegImageMetadata jmeta) ? jmeta.getExif() : null;

            if (exif == null) {
                LOG.warning("EXIF metadata not found in image.");
                return;
            }

            Pack7LStreamWriter output = new Pack7LStreamWriter(payloadOutput);

            for (Slot slot : slots) {
                TiffField field = exif.findField(slot.tagInfo);
                if (field == null) {
                    continue;
                }

                Object value = slot.tagInfo.getValue(field);
                byte[] chunk;

                if (value instanceof byte[] binary) {
                    chunk = slot.tagInfo.isText() ? Base64.getDecoder().decode(binary) : binary;

                } else if (value instanceof String str) {
                    chunk = slot.tagInfo.isText() ? Base64.getDecoder().decode(str.getBytes(StandardCharsets.US_ASCII))
                            : str.getBytes(StandardCharsets.UTF_8);

                } else {
                    LOG.log(Level.WARNING, "Unsupported EXIF field value type for tag: {0}", slot.tagInfo.name);
                    continue;
                }

                if (chunk.length > output.write(chunk)) {
                    // all data has been read
                    break;
                }
            }

        } catch (ImagingException e) {
            throw new IOException("Failed to read EXIF from JPEG", e);
        }
    }
}
