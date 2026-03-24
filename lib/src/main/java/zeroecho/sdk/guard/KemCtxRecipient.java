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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import zeroecho.core.context.KemContext;
import zeroecho.core.context.KemContext.KemResult;
import zeroecho.core.io.Util;
import zeroecho.sdk.util.Kdf;
import zeroecho.sdk.util.RandomSupport;

/**
 * Recipient implementation that derives a key-encryption key (KEK) via a
 * {@link KemContext} encapsulation and uses it to wrap a content-encryption key
 * (CEK).
 *
 * <p>
 * The workflow performed by this class is:
 * </p>
 * <ol>
 * <li>Encapsulate with the given {@link KemContext} to obtain a ciphertext and
 * a shared secret.</li>
 * <li>Derive a KEK from the shared secret using HKDF-SHA256 with a random salt
 * and an {@code info} string bound to the algorithm identifier.</li>
 * <li>Generate a fresh IV and wrap the CEK under AES-GCM with the derived
 * KEK.</li>
 * <li>Serialize the components (KEM ciphertext, salt, IV, wrapped CEK) into a
 * single byte array suitable for inclusion in a recipient entry.</li>
 * </ol>
 *
 * <h2>Thread-safety</h2> This class is not thread-safe. Each instance binds to
 * a single {@code KemContext} and must not be reused concurrently.
 *
 * @since 1.0
 */
public final class KemCtxRecipient implements Recipient {
    private final KemContext ctx;
    private final int kekBytes;
    private final int saltLen;
    private final boolean decoy;

    /**
     * Constructs a recipient that uses the given KEM context and parameters.
     *
     * @param ctx      the KEM context providing encapsulation
     * @param kekBytes number of bytes of KEK material to derive via HKDF
     * @param saltLen  length of the random salt to apply during HKDF
     */
    public KemCtxRecipient(KemContext ctx, int kekBytes, int saltLen) {
        this(ctx, kekBytes, saltLen, false);
    }

    /**
     * Constructs a recipient that wraps content-encryption keys (CEKs) using the
     * given KEM context and HKDF-based key derivation parameters.
     *
     * <p>
     * The KEM context performs encapsulation to derive a shared secret, which is
     * expanded with HKDF into key-encryption key (KEK) material. The KEK is then
     * used to wrap the CEK for this recipient. A recipient may also be flagged as a
     * decoy to obscure the actual number of usable recipients.
     * </p>
     *
     * @param ctx      the KEM context responsible for performing encapsulation;
     *                 must not be {@code null}
     * @param kekBytes number of bytes of KEK material to derive via HKDF
     * @param saltLen  length in bytes of the random salt applied during HKDF
     * @param decoy    {@code true} if this recipient is a decoy (fake entry that
     *                 cannot unwrap a CEK); {@code false} if it is a real recipient
     */
    public KemCtxRecipient(KemContext ctx, int kekBytes, int saltLen, boolean decoy) {
        this.ctx = ctx;
        this.kekBytes = kekBytes;
        this.saltLen = saltLen;
        this.decoy = decoy;
    }

    /**
     * Returns the identifier string for this recipient mechanism.
     *
     * <p>
     * The format is {@code "KEM:<algoId>:GCM-WRAP"} where {@code <algoId>} is taken
     * from the underlying {@link KemContext} algorithm.
     * </p>
     *
     * @return identifier string for this recipient type
     */
    @Override
    public String id() {
        return "KEM:" + ctx.algorithm().id() + ":GCM-WRAP";
    }

    /**
     * Builds a recipient entry for the given content-encryption key (CEK).
     *
     * <p>
     * Encapsulates with the KEM context, derives a KEK, wraps the CEK, and
     * serializes the structure into a binary entry. The returned value contains all
     * material required for the recipient to later decapsulate and unwrap.
     * </p>
     *
     * @param cek the content-encryption key to be wrapped
     * @return encoded recipient entry containing encapsulation, salt, IV, and
     *         wrapped CEK
     * @throws GeneralSecurityException if encapsulation, KDF, or wrapping fails
     * @throws IOException              if an I/O error occurs during encoding
     */
    @Override
    public byte[] buildRecipientEntry(byte[] cek) throws GeneralSecurityException, IOException {
        try (ctx) {
            KemResult kr = ctx.encapsulate();
            byte[] kemCt = kr.ciphertext();
            byte[] ss = kr.sharedSecret();

            byte[] salt = RandomSupport.generateRandom(saltLen);
            byte[] info = ("KDF:" + ctx.algorithm().id()).getBytes(StandardCharsets.US_ASCII);
            byte[] kek = Kdf.hkdfSha256(ss, salt, info, kekBytes);

            byte[] iv = RandomSupport.generateRandom(12);
            byte[] wrapped = MultiRecipientDataSourceBuilder.aesGcmWrap(kek, iv, null, cek);

            ByteArrayOutputStream out = new ByteArrayOutputStream(
                    kemCt.length + salt.length + iv.length + wrapped.length + 8);
            Util.write(out, kemCt);
            Util.write(out, salt);
            Util.write(out, iv);
            Util.write(out, wrapped);
            return out.toByteArray();
        }
    }

    /**
     * Returns whether this recipient entry is marked as a decoy.
     *
     * <p>
     * A decoy recipient is syntactically valid but intentionally unusable for
     * recovering the content-encryption key (CEK). Such entries are included to
     * conceal the number and identity of real recipients within a multi-recipient
     * envelope.
     * </p>
     *
     * @return {@code true} if this recipient is a decoy (fake recipient that cannot
     *         unwrap a CEK); {@code false} if it is a real recipient
     */
    @Override
    public boolean decoy() {
        return decoy;
    }
}
