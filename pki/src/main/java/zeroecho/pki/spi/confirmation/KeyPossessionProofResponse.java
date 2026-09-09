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
package zeroecho.pki.spi.confirmation;

import java.util.Arrays;

/**
 * Immutable globally bounded client response to a key-possession challenge.
 *
 * <p>Input and output arrays are defensively copied, and proof bytes are never
 * included in {@link #toString()}.</p>
 *
 * @param bytes non-empty suite-defined response bytes
 */
public record KeyPossessionProofResponse(byte[] bytes) {
    /** Global maximum response length in bytes. */
    public static final int MAXIMUM_BYTES = 16_384;

    /**
     * Validates and defensively owns the response.
     *
     * @throws IllegalArgumentException if the payload is null, empty, or exceeds 16384 bytes
     */
    public KeyPossessionProofResponse {
        if (bytes == null || bytes.length == 0 || bytes.length > MAXIMUM_BYTES) {
            throw new IllegalArgumentException("Proof response length is outside the supported range");
        }
        bytes = bytes.clone();
    }

    /**
     * Returns a defensive copy of the response.
     *
     * @return proof-response bytes
     */
    @Override
    public byte[] bytes() {
        return bytes.clone();
    }

    /** Compares proof response bytes by content. */
    @Override
    public boolean equals(Object other) {
        return this == other || other instanceof KeyPossessionProofResponse candidate
                && Arrays.equals(bytes, candidate.bytes);
    }

    /** Returns a content-based hash code. */
    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    /** Returns a redacted structural description. */
    @Override
    public String toString() {
        return "KeyPossessionProofResponse[bytes=<" + bytes.length + " bytes>]";
    }
}
