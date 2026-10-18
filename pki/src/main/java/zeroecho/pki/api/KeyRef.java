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
package zeroecho.pki.api;

/**
 * Opaque reference to private key material.
 *
 * <p>
 * The PKI module never handles private key bytes. A {@link KeyRef} is resolved
 * by runtime wiring, e.g., by a crypto component, an HSM adapter, or a remote
 * signer. Implementations must treat this reference as sensitive metadata and
 * avoid logging it unnecessarily.
 * </p>
 *
 * @param value non-empty key reference token
 */
public record KeyRef(String value) {
    private static final int UTF8_ASCII_MAX = 0x7f;
    private static final int UTF8_TWO_BYTE_MAX = 0x7ff;

    /**
     * Creates a key reference.
     *
     * @param value non-empty key reference token
     * @throws IllegalArgumentException if {@code value} is null or blank
     */
    public KeyRef {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("value must not be null/blank");
        }
    }

    /**
     * Returns the exact byte length produced by UTF-8 encoding without allocating
     * an encoded byte array. Malformed surrogate code units use the JDK encoder's
     * one-byte replacement representation.
     *
     * @return exact UTF-8 byte length
     */
    public long utf8Length() {
        long bytes = 0L;
        int index = 0;
        while (index < value.length()) {
            char unit = value.charAt(index);
            if (unit <= UTF8_ASCII_MAX) {
                bytes++;
            } else if (unit <= UTF8_TWO_BYTE_MAX) {
                bytes += 2L;
            } else if (Character.isHighSurrogate(unit)
                    && index + 1 < value.length()
                    && Character.isLowSurrogate(value.charAt(index + 1))) {
                bytes += 4L;
                index++;
            } else if (Character.isSurrogate(unit)) {
                bytes++;
            } else {
                bytes += 3L;
            }
            index++;
        }
        return bytes;
    }
}
