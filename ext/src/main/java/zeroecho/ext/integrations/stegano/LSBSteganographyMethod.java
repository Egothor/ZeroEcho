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
package zeroecho.ext.integrations.stegano;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.imageio.ImageIO;

/**
 * Least Significant Bit steganography implementation operating in the spatial
 * domain.
 *
 * <p>
 * This class embeds and extracts message bits from image pixels by manipulating
 * the least significant bit of each grayscale value. The implementation uses
 * stream-based I/O to support large inputs without loading everything into
 * memory at once.
 * </p>
 *
 * <h2>Algorithm and characteristics</h2>
 * <p>
 * Embedding proceeds left-to-right, top-to-bottom across pixels. The message is
 * prefixed with a 4-byte length header (big-endian) and then written bit-by-bit
 * into the LSB of each pixel's grayscale value. During embedding the image
 * content is converted to grayscale and written back to all color channels,
 * which discards original chroma.
 * </p>
 * <p>
 * Extraction reads the first 32 bits to recover the message length and then
 * continues to read that many message bytes from subsequent pixel LSBs.
 * </p>
 *
 * <h2>Capacity</h2>
 * <p>
 * Effective capacity is {@code width * height - 32} bits, where 32 bits are
 * reserved for the length header. The caller must ensure that the message
 * length in bits does not exceed the available capacity; otherwise the embedded
 * payload will be incomplete.
 * </p>
 *
 * <h2>Format support</h2>
 * <p>
 * Output must be a lossless format such as PNG or BMP. JPEG is not supported
 * because its lossy compression would destroy LSB-embedded payloads.
 * </p>
 *
 * <h2>Usage</h2> <pre>{@code
 * SteganographyMethod method = new LSBSteganographyMethod();
 * try (InputStream carrier = Files.newInputStream(Path.of("cover.png"));
 *      InputStream secret  = new ByteArrayInputStream("hello".getBytes(StandardCharsets.UTF_8));
 *      InputStream stego   = method.embed(carrier, ImageFormat.PNG, secret)) {
 *     Files.write(Path.of("stego.png"), stego.readAllBytes());
 * }
 *
 * try (InputStream stego = Files.newInputStream(Path.of("stego.png"));
 *      InputStream recovered = method.extract(stego)) {
 *     String text = new String(recovered.readAllBytes(), StandardCharsets.UTF_8);
 * }
 * }</pre>
 */
public class LSBSteganographyMethod implements SteganographyMethod {
    private static final Logger LOG = Logger.getLogger(LSBSteganographyMethod.class.getName());

    /**
     * Embeds the provided message into the least significant bits of the image and
     * returns a new image stream in the requested lossless format.
     *
     * <p>
     * The output image is grayscale and may differ visually from the input because
     * the algorithm writes identical gray values to all RGB channels. The message
     * is stored as a 4-byte big-endian length prefix followed by the raw message
     * bytes.
     * </p>
     *
     * @param inputImage   the source image stream to use as the cover image
     * @param outputFormat the desired output format; must be lossless (for example,
     *                     {@code PNG} or {@code BMP})
     * @param message      the message stream to embed
     * @return an {@code InputStream} containing the stego image encoded in
     *         {@code outputFormat}
     * @throws IOException              if an I/O error occurs while reading the
     *                                  image or message, or while writing the
     *                                  output image
     * @throws IllegalArgumentException if {@code outputFormat} is unsupported for
     *                                  this method (for example, {@code JPEG})
     */
    @Override
    public InputStream embed(InputStream inputImage, ImageFormat outputFormat, InputStream message) throws IOException {
        if (outputFormat == ImageFormat.JPEG) {
            throw new IllegalArgumentException("LSB does not support lossy formats like JPEG.");
        }

        BufferedImage img = ImageIO.read(inputImage);
        if (img == null) {
            throw new IOException("Failed to read input image.");
        }

        byte[] messageBytes = message.readAllBytes();
        ByteArrayOutputStream fullData = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(fullData);
        dos.writeInt(messageBytes.length);
        dos.write(messageBytes);
        byte[] fullMessage = fullData.toByteArray();

        final int width = img.getWidth();
        final int height = img.getHeight();
        int msgBitIndex = 0;

        if (LOG.isLoggable(Level.INFO)) {
            LOG.log(Level.INFO, "embed to {2} picture w={0} x h={1}", new Object[] { width, height, outputFormat });
        }

        outer: for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                if (msgBitIndex >= fullMessage.length * 8) {
                    break outer;
                }

                int rgb = img.getRGB(x, y);
                int gray = rgb & 0xFF;
                int bit = (fullMessage[msgBitIndex / 8] >> (7 - (msgBitIndex % 8))) & 1;
                gray = (gray & 0xFE) | bit;
                int newRgb = (gray << 16) | (gray << 8) | gray;
                img.setRGB(x, y, newRgb);
                msgBitIndex++;
            }
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(img, outputFormat.name().toLowerCase(Locale.ROOT), out);
        return new ByteArrayInputStream(out.toByteArray());
    }

    /**
     * Extracts the embedded message from the least significant bits of the provided
     * image.
     *
     * <p>
     * This method expects the message to be stored as a 4-byte big-endian length
     * prefix followed by exactly that many message bytes. The input should be a
     * lossless image produced by
     * {@link #embed(InputStream, ImageFormat, InputStream)} or an equivalent LSB
     * spatial-domain encoder.
     * </p>
     *
     * @param inputImage the stego image stream that contains an embedded message
     * @return an {@code InputStream} of the extracted message bytes
     * @throws IOException if an I/O error occurs while reading the image or if the
     *                     image cannot be decoded
     */
    @Override
    public InputStream extract(InputStream inputImage) throws IOException {
        BufferedImage img = ImageIO.read(inputImage);
        if (img == null) {
            throw new IOException("Failed to read input image.");
        }

        final int width = img.getWidth();
        final int height = img.getHeight();
        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();

        if (LOG.isLoggable(Level.INFO)) {
            LOG.log(Level.INFO, "extract from picture w={0} x h={1}", new Object[] { width, height });
        }

        int byteVal = 0;
        int messageLength = -1;
        int bitsCollected = 0;

        outer: for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int gray = img.getRGB(x, y) & 0xFF;
                int bit = gray & 1;
                byteVal = (byteVal << 1) | bit;
                bitsCollected++;

                if (bitsCollected == 8) { // NOPMD
                    messageBytes.write(byteVal);
                    byteVal = 0;
                    bitsCollected = 0;

                    if (messageLength == -1 && messageBytes.size() == 4) {
                        byte[] lenBytes = messageBytes.toByteArray();
                        messageBytes.reset();
                        messageLength = ByteBuffer.wrap(lenBytes).getInt();
                    }

                    if (messageLength != -1 && messageBytes.size() == messageLength) {
                        break outer;
                    }
                }
            }
        }

        return new ByteArrayInputStream(messageBytes.toByteArray());
    }

    /**
     * Returns metadata describing this LSB spatial-domain steganography method.
     *
     * <p>
     * The metadata includes a short identifier, a descriptive long name, and a
     * concise description of the embedding approach.
     * </p>
     *
     * @return method metadata for LSB spatial-domain steganography
     */
    @Override
    public StegoMetadata getMetadata() {
        return new StegoMetadata("LSB", "Least Significant Bit Spatial Domain Image Steganography",
                "Embeds message bits into the least significant bits of grayscale pixel values.");
    }
}
