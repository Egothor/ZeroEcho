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
package zeroecho.sdk.guard;

/**
 * Defines the KEK sizes supported by recipient entries without an encoded size
 * discriminator.
 *
 * <p>
 * The current recipient format permits AES-128 and AES-256 wrapping only.
 * Validation must occur before an entry is registered so every emitted entry
 * remains openable by the corresponding recipient opener.
 * </p>
 *
 * @since 1.0
 */
public final class RecipientKekSizes {
    /** AES-128 key size in bytes. */
    public static final int AES_128_BYTES = 16;
    /** AES-256 key size in bytes. */
    public static final int AES_256_BYTES = 32;

    private RecipientKekSizes() {
    }

    /**
     * Validates and returns a supported recipient KEK size.
     *
     * @param kekBytes requested KEK size in bytes
     * @return {@code kekBytes} when it is exactly 16 or 32
     * @throws IllegalArgumentException if the size is not exactly 16 or 32
     */
    public static int requireSupported(int kekBytes) {
        if (kekBytes != AES_128_BYTES && kekBytes != AES_256_BYTES) {
            throw new IllegalArgumentException("Recipient KEK size must be exactly 16 or 32 bytes: " + kekBytes);
        }
        return kekBytes;
    }
}
