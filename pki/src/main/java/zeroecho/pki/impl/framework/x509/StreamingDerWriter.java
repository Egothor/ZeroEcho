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
package zeroecho.pki.impl.framework.x509;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import zeroecho.core.io.CancellationSignal;

/**
 * Focused canonical DER streaming primitives used by signed-object adapters.
 *
 * <p>
 * This is deliberately not a general ASN.1 framework. It writes already
 * validated current X.509 child encodings into definite-length containers while
 * accounting in {@code long}. ZeroEcho core imposes no arbitrary product-wide
 * aggregate CRL-size or revocation-entry limit; completion remains subject to
 * storage, I/O, technical representability, cancellation, and deployment
 * policy.
 * </p>
 */
public final class StreamingDerWriter {

    /** DER universal SEQUENCE tag. */
    public static final int SEQUENCE_TAG = 0x30;
    /** DER universal BIT STRING tag. */
    public static final int BIT_STRING_TAG = 0x03;

    private static final int BUFFER_SIZE = 16 * 1024;
    private static final long EMPTY_LENGTH = 0L;
    private static final long SHORT_FORM_LIMIT = 128L;

    private StreamingDerWriter() {
    }

    /**
     * Returns the encoded size of one tag-length-value object.
     *
     * @param valueLength non-negative value length
     * @return complete encoded length
     * @throws IllegalArgumentException if the length is negative
     * @throws ArithmeticException if the result overflows {@code long}
     */
    public static long encodedLength(long valueLength) {
        if (valueLength < EMPTY_LENGTH) {
            throw new IllegalArgumentException("DER value length must not be negative");
        }
        return Math.addExact(Math.addExact(1L, lengthOctets(valueLength)), valueLength);
    }

    /**
     * Writes one canonical DER tag and definite length.
     *
     * @param output target stream
     * @param tag one-octet tag
     * @param valueLength non-negative value length
     * @throws IOException if writing fails
     * @throws IllegalArgumentException if the tag or length is invalid
     */
    public static void writeTagAndLength(OutputStream output, int tag, long valueLength) throws IOException {
        if (output == null) {
            throw new IllegalArgumentException("output must not be null");
        }
        if (tag < 0 || tag > 0xff) {
            throw new IllegalArgumentException("DER tag must fit one octet");
        }
        if (valueLength < EMPTY_LENGTH) {
            throw new IllegalArgumentException("DER value length must not be negative");
        }
        output.write(tag);
        if (valueLength < SHORT_FORM_LIMIT) {
            output.write((int) valueLength);
            return;
        }
        int octets = significantOctets(valueLength);
        output.write(0x80 | octets);
        for (int shift = (octets - 1) * Byte.SIZE; shift >= 0; shift -= Byte.SIZE) {
            output.write((int) (valueLength >>> shift) & 0xff);
        }
    }

    /**
     * Copies content incrementally and returns the exact byte count.
     *
     * @param input source
     * @param output destination
     * @param cancellation cancellation signal
     * @return copied byte count
     * @throws IOException if reading or writing fails
     * @throws ArithmeticException if the count overflows
     */
    public static long copy(InputStream input, OutputStream output, CancellationSignal cancellation)
            throws IOException {
        if (input == null || output == null || cancellation == null) {
            throw new IllegalArgumentException("DER copy arguments must not be null");
        }
        byte[] buffer = new byte[BUFFER_SIZE];
        long count = 0L;
        int read;
        while ((read = input.read(buffer)) >= 0) {
            cancellation.throwIfCancelled();
            if (read != 0) {
                output.write(buffer, 0, read);
                count = Math.addExact(count, read);
            }
        }
        return count;
    }

    private static long lengthOctets(long valueLength) {
        return valueLength < 128L ? 1L : Math.addExact(1L, significantOctets(valueLength));
    }

    private static int significantOctets(long valueLength) {
        int octets = 0;
        long remaining = valueLength;
        while (remaining != 0L) {
            octets++;
            remaining >>>= Byte.SIZE;
        }
        return octets;
    }
}
