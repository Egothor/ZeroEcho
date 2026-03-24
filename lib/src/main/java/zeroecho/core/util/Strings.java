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
package zeroecho.core.util;

/**
 * Utility class providing string conversion helpers for debugging and logging.
 * 
 * <p>
 * This class focuses on safe and concise representations of binary data and
 * other values that are commonly needed in diagnostic messages. It is not
 * intended for cryptographic formatting or encoding tasks such as Base64 or
 * hexadecimal.
 * </p>
 */
public final class Strings {

    private Strings() {
        // empty
    }

    /**
     * Converts a byte array into a short, human-readable string representation.
     * 
     * <p>
     * The representation is a comma-separated list of decimal byte values enclosed
     * in square brackets. For arrays longer than 32 elements, the output is
     * truncated after 32 elements, followed by an ellipsis marker: {@code [...]}.
     * </p>
     * 
     * <h4>Examples</h4> <pre>{@code
     * Strings.toShortString(null)        -> "null"
     * Strings.toShortString(new byte[0]) -> "[]"
     * Strings.toShortString(new byte[]{1, 2, 3})
     *     -> "[1, 2, 3]"
     * Strings.toShortString(new byte[40])
     *     -> "[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0...]"
     * }
     * </pre>
     * 
     * @param a the byte array to format, may be {@code null}
     * @return a short string representation of the byte array, never {@code null}
     */
    public static String toShortString(byte[] a) {
        if (a == null) {
            return "null";
        }
        int iMax = a.length - 1;
        if (iMax == -1) {
            return "[]";
        }

        StringBuilder b = new StringBuilder();
        b.append('[');
        for (int i = 0;; i++) {
            if (i == 32) { // NOPMD
                return b.append("...]").toString();
            }
            b.append(a[i]);
            if (i == iMax) {
                return b.append(']').toString();
            }
            b.append(", ");
        }
    }

    /**
     * Converts a byte array into a compact hexadecimal string representation.
     *
     * <p>
     * The output starts with {@code "[0x"}, concatenates each byte as a two-digit
     * lowercase hexadecimal value with no separators, and ends with {@code "]"}. If
     * the array contains more than 32 bytes, only the first 32 are included,
     * followed by {@code "...]"} to indicate truncation.
     * </p>
     *
     * <p>
     * Special cases:
     * </p>
     * <ul>
     * <li>If {@code a} is {@code null}, the string {@code "null"} is returned.</li>
     * <li>If {@code a} is empty, the string {@code "[]"} is returned.</li>
     * </ul>
     *
     * <h4>Examples</h4> <pre>{@code
     * toShortHexString(null)                   -> "null"
     * toShortHexString(new byte[0])            -> "[]"
     * toShortHexString(new byte[]{0x01})       -> "[0x01]"
     * toShortHexString(new byte[]{0x01,0x2a})  -> "[0x012a]"
     * }</pre>
     *
     * @param a the byte array to convert, may be {@code null}
     * @return a compact hexadecimal string representation
     */
    public static String toShortHexString(byte[] a) {
        if (a == null) {
            return "null";
        }
        int iMax = a.length - 1;
        if (iMax == -1) {
            return "[]";
        }

        final char[] hexArray = "0123456789abcdef".toCharArray();
        StringBuilder b = new StringBuilder("[0x");
        for (int i = 0;; i++) {
            if (i == 32) { // NOPMD
                return b.append("...]").toString();
            }
            b.append(hexArray[(a[i] >> 4) & 0xf]).append(hexArray[a[i] & 0xf]);
            if (i == iMax) {
                return b.append(']').toString();
            }
        }
    }
}
