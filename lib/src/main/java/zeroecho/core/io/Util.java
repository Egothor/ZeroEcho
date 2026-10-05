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

import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * Utility class for performing efficient I/O operations with support for packed
 * integers. This class provides static methods to write and read data with a
 * compact variable-length encoding ("Pack7") and custom handling of UUIDs and
 * UTF-8 strings.
 * <p>
 * <b>Design rationale:</b> Using static methods allows developers to perform
 * encoding and decoding operations directly on existing {@link InputStream} and
 * {@link OutputStream} instances without the need for additional stream
 * wrappers such as {@link FilterInputStream} or {@link FilterOutputStream}.
 * This approach eliminates extra object creation and method call overhead,
 * potentially improving performance, especially in high-throughput scenarios.
 * </p>
 * <p>
 * <b>Usage:</b> These methods can be used independently with any I/O stream to
 * achieve custom serialization formats, such as length-prefixed UTF-8 strings,
 * packed integers, or custom binary structures.
 * </p>
 */
public final class Util { // NOPMD
    /**
     * The default buffer size (in bytes) used when reading from an
     * {@link InputStream}.
     * <p>
     * This value is chosen to balance throughput and memory efficiency during I/O
     * operations. It is large enough to provide good performance for most
     * workloads, while avoiding excessive memory allocation for small streams.
     * </p>
     *
     * <p>
     * The value is set to 32768 bytes (32 KB).
     * </p>
     */
    private static final int DEFAULT_BUFFER_SIZE = 32 * 1024;
    /** Largest unsigned 32-bit value accepted by the packed integer decoder. */
    private static final long MAX_PACKED_INTEGER = 0xffff_ffffL;
    /** Maximum number of bytes in a packed 64-bit value. */
    private static final int MAX_PACKED_LONG_BYTES = 10;
    /** One-based position of the high-order packed payload group. */
    private static final int PACKED_HIGH_PAYLOAD_POSITION = 1;
    /** Largest high-order payload permitted in a ten-byte packed long. */
    private static final int MAX_PACKED_LONG_HIGH_PAYLOAD = 1;
    /** Bit marking the final byte of a packed value. */
    private static final int PACKED_TERMINATION_BIT = 0x80;
    /** Mask selecting the seven payload bits of a packed byte. */
    private static final int PACKED_PAYLOAD_MASK = 0x7f;

    /**
     * Private constructor to prevent instantiation of this utility class.
     */
    private Util() {
        // this is a utility class
    }

    /**
     * Writes a byte array to the output stream with its length encoded as a packed
     * 7-bit integer.
     *
     * @param out the output stream
     * @param buf the byte array to write
     * @throws IOException if an I/O error occurs
     */
    public static void write(final OutputStream out, final byte[] buf) throws IOException {
        writePack7I(out, buf.length);
        out.write(buf);
    }

    /**
     * Writes a UUID to the output stream as two big-endian long values.
     *
     * @param out  the output stream
     * @param uuid the UUID to write
     * @throws IOException if an I/O error occurs
     */
    public static void write(final OutputStream out, final UUID uuid) throws IOException {
        writeLong(out, uuid.getMostSignificantBits());
        writeLong(out, uuid.getLeastSignificantBits());
    }

    /**
     * Writes a UTF-8 encoded string to the output stream with its length as a
     * packed 7-bit integer.
     *
     * @param out the output stream
     * @param str the string to write
     * @throws IOException if an I/O error occurs
     */
    public static void writeUTF8(final OutputStream out, final String str) throws IOException {
        final byte[] buf = str.getBytes(StandardCharsets.UTF_8);
        writePack7I(out, buf.length);
        out.write(buf);
    }

    /**
     * Writes a long value to the output stream in big-endian order (8 bytes).
     *
     * @param out the output stream
     * @param val the long value to write
     * @throws IOException if an I/O error occurs
     */
    public static void writeLong(final OutputStream out, long val) throws IOException {
        final byte[] buf = new byte[8];
        for (int i = buf.length; --i >= 0;) { // NOPMD
            buf[i] = (byte) (val & 0xff);
            val = val >>> 8; // NOPMD
        }
        out.write(buf);
    }

    /**
     * Reads a UUID from the input stream, composed of two big-endian long values.
     *
     * @param in the input stream
     * @return the UUID read from the stream
     * @throws IOException if an I/O error occurs or if the stream ends prematurely
     */
    public static UUID readUUID(final InputStream in) throws IOException {
        final long msb = readLong(in);
        final long lsb = readLong(in);

        return new UUID(msb, lsb);
    }

    /**
     * Reads a UTF-8 encoded string from the input stream. The string is prefixed
     * with a packed 7-bit integer indicating its length. To prevent excessive
     * allocation, the maximum allowable length must be specified.
     *
     * @param in        the input stream
     * @param maxLength the maximum allowable length of the string in bytes
     * @return the string read from the stream
     * @throws IOException if an I/O error occurs, the length exceeds maxLength, or
     *                     if the stream ends prematurely
     */
    public static String readUTF8(final InputStream in, final int maxLength) throws IOException {
        final int len = readPack7I(in);
        if (len > maxLength) {
            throw new IOException("readUTF8 length " + len + " exceeds maximum allowed length " + maxLength);
        }
        final byte[] buf = new byte[len];
        if (in.readNBytes(buf, 0, buf.length) != buf.length) {
            throw new EOFException("readUTF8 EOF");
        }
        return new String(buf, StandardCharsets.UTF_8);
    }

    /**
     * Reads a long value from the input stream in big-endian order (8 bytes).
     *
     * @param in the input stream
     * @return the long value read
     * @throws IOException if an I/O error occurs or if the stream ends prematurely
     */
    public static long readLong(final InputStream in) throws IOException {
        final byte[] buff = new byte[8];
        if (in.readNBytes(buff, 0, buff.length) != buff.length) {
            throw new EOFException("readLong EOF");
        }

        long result = 0;
        for (final byte b : buff) {
            result = (result << 8) | (b & 0xffL);
        }
        return result;
    }

    /**
     * Writes an integer to the output stream using packed 7-bit encoding (variable
     * length).
     *
     * @param out the output stream
     * @param val the integer value to write
     * @throws IOException if an I/O error occurs
     */
    public static void writePack7I(final OutputStream out, int val) throws IOException {
        final byte[] buff = new byte[5];
        int idx = buff.length;
        while ((val & ~0x7f) != 0) {
            buff[--idx] = (byte) (val & 0x7f);
            val = val >>> 7; // NOPMD
        }
        buff[--idx] = (byte) val;
        buff[buff.length - 1] |= 0x80;
        out.write(buff, idx, buff.length - idx);
    }

    /**
     * Writes a long value to the output stream using packed 7-bit encoding
     * (variable length).
     *
     * @param out the output stream
     * @param val the long value to write
     * @throws IOException if an I/O error occurs
     */
    public static void writePack7L(final OutputStream out, long val) throws IOException {
        final byte[] buff = new byte[10];
        int idx = buff.length;
        while ((val & ~0x7fL) != 0) {
            buff[--idx] = (byte) (val & 0x7f);
            val = val >>> 7; // NOPMD
        }
        buff[--idx] = (byte) val;
        buff[buff.length - 1] |= 0x80;
        out.write(buff, idx, buff.length - idx);
    }

    /**
     * Reads a byte array from the input stream. The length of the array is
     * specified as a packed 7-bit integer prefix. To prevent excessive allocation,
     * the maximum allowable length must be specified.
     *
     * @param in        the input stream
     * @param maxLength the maximum allowable length of the byte array
     * @return the byte array read
     * @throws IOException if an I/O error occurs, the length exceeds maxLength, or
     *                     if the stream ends prematurely
     */
    public static byte[] read(final InputStream in, final int maxLength) throws IOException {
        final int len = readPack7I(in);
        if (len > maxLength || len < 0) {
            throw new IOException("read length " + len + " exceeds maximum allowed length " + maxLength);
        }
        final byte[] result = new byte[len];
        if (in.readNBytes(result, 0, result.length) != result.length) {
            throw new EOFException("read EOF");
        }
        return result;
    }

    /**
     * Reads an integer from the input stream using packed 7-bit encoding (variable
     * length).
     *
     * @param in the input stream
     * @return the integer value read
     * @throws IOException if an I/O error occurs or if the stream ends prematurely
     */
    public static int readPack7I(final InputStream in) throws IOException {
        int current = in.read();
        if (current < 0) {
            throw new EOFException("read packed integer EOF");
        }
        if (current > 0x7f) { // NOPMD
            return current & 0x7f;
        }

        long result = current;
        for (int bytes = 1; bytes < 5; bytes++) {
            current = in.read();
            if (current < 0) {
                throw new EOFException("read packed integer EOF");
            }
            result = (result << 7) | (current & 0x7f);
            if (current > 0x7f) { // NOPMD
                if (result > MAX_PACKED_INTEGER) {
                    throw new IOException("packed integer exceeds 32 bits");
                }
                return (int) result;
            }
        }
        throw new IOException("packed integer exceeds five bytes");
    }

    /**
     * Reads a long value from the input stream using packed 7-bit encoding
     * (variable length). Payload groups are stored most-significant first, and the
     * high bit marks the final byte. At most ten bytes are accepted. In a ten-byte
     * representation, the first payload group is limited to one bit so that the
     * encoded value fits exactly in the 64-bit {@code long} bit pattern.
     *
     * <p>
     * Both non-negative and negative {@code long} values produced by
     * {@link #writePack7L(OutputStream, long)} are supported. The method consumes
     * exactly one complete packed value and performs at most ten stream reads.
     *
     * @param in the input stream
     * @return the long value read
     * @throws EOFException if the stream ends before a terminating byte
     * @throws IOException  if an I/O error occurs, the encoding exceeds ten bytes,
     *                      or the payload exceeds 64 bits
     */
    public static long readPack7L(final InputStream in) throws IOException {
        long result = 0;
        int highPayload = 0;
        for (int bytes = PACKED_HIGH_PAYLOAD_POSITION; bytes <= MAX_PACKED_LONG_BYTES; bytes++) {
            int current = in.read();
            if (current < 0) {
                throw new EOFException("read packed long EOF");
            }
            int payload = current & PACKED_PAYLOAD_MASK;
            if (bytes == PACKED_HIGH_PAYLOAD_POSITION) {
                highPayload = payload;
            }
            boolean terminated = (current & PACKED_TERMINATION_BIT) != 0;
            if (bytes == MAX_PACKED_LONG_BYTES) {
                if (!terminated) {
                    throw new IOException("packed long exceeds ten bytes");
                }
                if (highPayload > MAX_PACKED_LONG_HIGH_PAYLOAD) {
                    throw new IOException("packed long exceeds 64 bits");
                }
            }
            result = (result << 7) | payload;
            if (terminated) {
                return result;
            }
        }
        throw new IOException("packed long exceeds ten bytes");
    }

    /**
     * Reads up to {@code maxSize} bytes from the given {@link InputStream}, encodes
     * the total number of bytes using 7-bit variable-length encoding (similar to
     * {@link #writePack7L}), and returns a single byte array containing the encoded
     * length prefix followed by the actual data read.
     *
     * <p>
     * Input is retained in chunks until the full size is known, then copied into
     * one result array. For n input bytes, time and auxiliary memory are O(n);
     * the retained chunks coexist with the result during the final copy. The
     * size limit bounds accepted input, not peak allocation to a single buffer.
     *
     * <p>
     * The size prefix uses a packed 7-bit encoding, where the most significant bit
     * of the last byte is set to 1. This format is useful for compactly
     * representing lengths in binary protocols.
     *
     * @param in      the {@link InputStream} to read data from; must not be
     *                {@code null}
     * @param maxSize the maximum number of bytes allowed to be read from the
     *                stream; must be non-negative and less than or equal to
     *                {@code Integer.MAX_VALUE - 10}
     * @return a {@code byte[]} array where the first bytes are the encoded length,
     *         followed by the data read
     * @throws IOException              if an I/O error occurs or if the data read
     *                                  exceeds {@code maxSize}
     * @throws IllegalArgumentException if {@code maxSize} is negative or too large
     */
    public static byte[] readWithPackedLengthPrefix(InputStream in, int maxSize) throws IOException {
        // complexity
        if (maxSize < 0 || maxSize > Integer.MAX_VALUE - 10) {
            throw new IllegalArgumentException("Invalid maxSize: " + maxSize);
        }

        List<byte[]> bufs = new ArrayList<>();
        int total = 0;

        byte[] buf;
        int n;
        while ((n = in.read(buf = new byte[DEFAULT_BUFFER_SIZE])) > 0) { // NOPMD
            if (n < buf.length) {
                buf = Arrays.copyOf(buf, n);
            }

            if (total > maxSize - n) {
                throw new IOException("Input exceeds maximum allowed size: " + maxSize);
            }

            bufs.add(buf);
            total += n;
        }

        // Encode total size using writePack7L logic
        byte[] prefixBuf = new byte[10];
        long len = total;
        int idx = prefixBuf.length;
        while ((len & ~0x7fL) != 0) {
            prefixBuf[--idx] = (byte) (len & 0x7f);
            len >>>= 7;
        }
        prefixBuf[--idx] = (byte) len;
        prefixBuf[prefixBuf.length - 1] |= 0x80;
        int prefixLen = prefixBuf.length - idx;

        // Allocate result array
        int finalSize = prefixLen + total;
        byte[] result = new byte[finalSize];

        // Copy prefix
        System.arraycopy(prefixBuf, idx, result, 0, prefixLen);

        // Copy content
        int offset = prefixLen;
        for (byte[] b : bufs) {
            System.arraycopy(b, 0, result, offset, b.length);
            offset += b.length;
        }

        return result;
    }
}
