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

import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HKDF utilities for deriving symmetric keys from a KEM shared secret. This
 * class provides an RFC 5869 compliant HKDF-SHA256 implementation.
 *
 * <h2>Notes</h2> The function implements HKDF-Extract followed by HKDF-Expand
 * with SHA-256. If {@code salt} is {@code null} or empty, a zero-filled salt of
 * length 32 is used as recommended by RFC 5869. If {@code info} is
 * {@code null}, it is treated as an empty byte array.
 *
 * <pre>{@code
 * // Example: derive 32 bytes for AES-256 or ChaCha20-Poly1305
 * byte[] ikm   = kemSharedSecret;          // input keying material from KEM
 * byte[] salt  = null;                     // or a KEM-specific salt
 * byte[] info  = "ZeroEcho-KEM".getBytes(StandardCharsets.US_ASCII);
 * int    len   = 32;
 * byte[] key   = Kdf.hkdfSha256(ikm, salt, info, len);
 * }</pre>
 */
public final class Kdf { // NOPMD

    private static final String HMAC = "HmacSHA256";
    private static final int HASH_LEN = 32; // bytes

    private Kdf() {
        // utility
    }

    /**
     * Derives {@code length} bytes of key material using HKDF-SHA256 as specified
     * in RFC 5869.
     *
     * <p>
     * HKDF-Extract: {@code PRK = HMAC(salt, IKM)} where {@code salt} defaults to
     * {@code HashLen} zeros if {@code salt} is {@code null} or empty.
     * </p>
     *
     * <p>
     * HKDF-Expand: {@code T(0)=empty}, {@code T(i)=HMAC(PRK, T(i-1) || info || i)},
     * and the output key material is the first {@code length} bytes of
     * {@code T(1)||...||T(N)}, where {@code N = ceil(length / HashLen)} and
     * {@code i} is a single octet counter.
     * </p>
     *
     * @param ikm    input keying material; must not be {@code null} or empty
     * @param salt   optional salt; if {@code null} or empty, a zero salt of 32
     *               bytes is used
     * @param info   optional context/application info; if {@code null}, treated as
     *               empty
     * @param length number of output bytes to produce; must be in range 1..(255*32)
     * @return derived keying material of exactly {@code length} bytes
     * @throws GeneralSecurityException if the MAC operation fails
     * @throws IllegalArgumentException if {@code ikm} is empty or {@code length} is
     *                                  out of range
     * @since 1.0
     */
    public static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) throws GeneralSecurityException {

        if (ikm == null || ikm.length == 0) {
            throw new IllegalArgumentException("ikm must not be null or empty");
        }
        if (length < 1 || length > 255 * HASH_LEN) {
            throw new IllegalArgumentException("length must be in range 1.." + (255 * HASH_LEN));
        }
        final byte[] saltUse;
        if (salt == null || salt.length == 0) {
            saltUse = new byte[HASH_LEN]; // all zeros
        } else {
            saltUse = salt.clone();
        }
        final byte[] infoUse = (info == null) ? new byte[0] : info.clone();

        byte[] prk = null;
        byte[] t = new byte[0];
        byte[] okm = null;
        boolean returned = false;
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(saltUse, HMAC));
            prk = mac.doFinal(ikm);

            final int n = (length + HASH_LEN - 1) / HASH_LEN;
            okm = new byte[length];
            int pos = 0;
            for (int i = 1; i <= n; i++) {
                mac.init(new SecretKeySpec(prk, HMAC)); // NOPMD
                mac.update(t, 0, t.length);
                mac.update(infoUse, 0, infoUse.length);
                mac.update((byte) i);
                byte[] next = mac.doFinal();
                Arrays.fill(t, (byte) 0);
                t = next;

                final int toCopy = Math.min(HASH_LEN, length - pos);
                System.arraycopy(t, 0, okm, pos, toCopy);
                pos += toCopy;
            }
            returned = true;
            return okm;
        } finally {
            Arrays.fill(saltUse, (byte) 0);
            Arrays.fill(infoUse, (byte) 0);
            if (prk != null) {
                Arrays.fill(prk, (byte) 0);
            }
            Arrays.fill(t, (byte) 0);
            if (!returned && okm != null) {
                Arrays.fill(okm, (byte) 0);
            }
        }
    }
}
