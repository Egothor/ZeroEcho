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

import java.io.IOException;
import java.io.OutputStream;

/**
 * A streaming writer that reads a variable-length 7-bit encoded length prefix
 * from the input data and writes the subsequent payload to a target
 * {@link OutputStream}.
 * <p>
 * The {@link #write(byte[])} method can be called multiple times, even with
 * partial data. It will return how many bytes from the input array were
 * consumed.
 */
public class Pack7LStreamWriter {
    private final OutputStream out;
    private boolean lengthDecoded;
    private long expectedLength = -1;
    private long written;

    // Buffer for partially-read length prefix (max 10 bytes)
    private final byte[] lengthBuf = new byte[10];
    private int lengthBufSize;

    /**
     * Constructs a new {@code Pack7LStreamWriter}.
     *
     * @param out the {@link OutputStream} where the payload will be written after
     *            decoding the length
     */
    public Pack7LStreamWriter(OutputStream out) {
        if (out == null) {
            throw new IllegalArgumentException("OutputStream cannot be null");
        }
        this.out = out;
    }

    /**
     * Writes the given data to the internal buffer or to the output stream once the
     * length prefix has been fully decoded. Returns how many bytes from
     * {@code data} were consumed.
     *
     * @param data the input byte array, possibly containing a length prefix and/or
     *             payload
     * @return the number of bytes consumed from {@code data}
     * @throws IOException if an I/O error occurs while writing to the output stream
     */
    public int write(byte[] data) throws IOException {
        return write(data, 0, data.length);
    }

    /**
     * Processes a chunk of input data starting at the specified offset and up to
     * the specified length.
     * <p>
     * On the first call(s), this method reads a variable-length 7-bit encoded
     * prefix from the input data, which specifies how many total bytes are expected
     * to follow. Once the prefix is fully read, the method writes up to the
     * remaining number of payload bytes to the underlying {@link OutputStream}.
     * </p>
     *
     * <p>
     * This method is designed to be called repeatedly with partial or complete
     * input buffers. It maintains internal state and will continue consuming input
     * until the expected number of payload bytes are written.
     * </p>
     *
     * @param data   the input byte array containing part of the length prefix
     *               and/or payload; must not be {@code null}
     * @param offset the starting position in the array to read from
     * @param length the number of bytes to read from the array
     * @return the number of bytes consumed from the input buffer
     * @throws IOException               if an I/O error occurs during writing or if
     *                                   the length prefix is malformed
     * @throws IndexOutOfBoundsException if {@code offset} or {@code length} are
     *                                   invalid for the given array
     */
    public int write(byte[] data, int offset, int length) throws IOException {
        int consumed = 0;

        // Step 1: Decode the length prefix
        if (!lengthDecoded) {
            while (consumed < length) {
                byte b = data[offset + consumed];
                lengthBuf[lengthBufSize++] = b;
                consumed++;

                if ((b & 0x80) != 0 || lengthBufSize >= 10) {
                    expectedLength = decodePack7L(lengthBuf, 0, lengthBufSize);
                    lengthDecoded = true;
                    break;
                }
            }

            // If length still not fully read, return now
            if (!lengthDecoded) {
                return consumed;
            }
        }

        // Step 2: Write payload
        long remaining = expectedLength - written;
        int writable = (int) Math.min(remaining, length - consumed);

        if (writable > 0) {
            out.write(data, offset + consumed, writable);
            consumed += writable;
            written += writable;
        }

        return consumed;
    }

    /**
     * Checks whether the payload has been fully written.
     *
     * @return {@code true} if all expected payload bytes have been written and the
     *         length has been decoded; {@code false} otherwise.
     */
    public boolean isComplete() {
        return lengthDecoded && written == expectedLength;
    }

    /**
     * Decodes a packed 7-bit encoded long from the given byte array.
     *
     * @param buf    the byte array containing the encoded value
     * @param offset the offset in the array
     * @param length the number of bytes to read
     * @return the decoded long value
     * @throws IOException if the encoding is malformed
     */
    private static long decodePack7L(byte[] buf, int offset, int length) throws IOException {
        if (length == 0) {
            throw new IOException("Empty length buffer");
        }

        long result = buf[offset] & 0xFF;
        if ((buf[offset] & 0x80) != 0) {
            return result & 0x7F;
        }

        for (int i = 1; i < length; i++) {
            int b = buf[offset + i] & 0xFF;
            if (b >= 0x80) { // NOPMD
                result = (result << 7) | (b & 0x7F);
                return result;
            }
            result = (result << 7) | b;
        }

        throw new IOException("Incomplete packed length encoding");
    }
}
