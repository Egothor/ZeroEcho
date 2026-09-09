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
package zeroecho.core.alg.aes;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import conflux.CtxInterface;
import zeroecho.core.ConfluxKeys;
import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.SymmetricHeaderCodec;
import zeroecho.core.io.Util;
import zeroecho.core.util.Strings;

/**
 * Minimal AES header codec that persists runtime parameters only:
 * <pre>IV | tagBits(pack7) | aadFlag(1) | [aadHash(32)]</pre>
 *
 * <ul>
 * <li><b>IV</b>: 12 bytes for GCM; 16 bytes for CBC/CTR.</li>
 * <li><b>tagBits</b>: 0 for non‑GCM; otherwise 96..128.</li>
 * <li><b>aadFlag</b>: 1 when AAD is present; the header then includes a SHA‑256
 * of the AAD.</li>
 * </ul>
 *
 * <p>
 * No algorithm magic is written. On decrypt, the codec hydrates the Conflux
 * context with IV and tag bits and enforces AAD consistency if an AAD hash is
 * present.
 * </p>
 *
 * @since 1.0
 */
public final class AesHeaderCodec implements SymmetricHeaderCodec {
    private static final Logger LOG = Logger.getLogger(AesHeaderCodec.class.getName());

    /**
     * Creates a stateless AES stream-header codec.
     */
    public AesHeaderCodec() {
        // Stateless codec.
    }

    /**
     * Writes the header to {@code out} using values from the provided context.
     *
     * @param out       destination stream
     * @param algorithm owning algorithm (ID {@code "AES"})
     * @param ctx       source of IV, optional tag bits, and optional AAD
     * @throws IOException if IV is missing or an I/O error occurs
     */
    @Override
    public void writeHeader(OutputStream out, CryptoAlgorithm algorithm, CtxInterface ctx) throws IOException {
        final String id = algorithm.id(); // e.g., "AES"

        LOG.log(Level.FINE, "writeHeader={0}", id);

        byte[] iv = ctx.get(ConfluxKeys.iv(id));
        if (iv == null) {
            throw new IOException("AesHeaderCodec: IV missing in Ctx");
        }

        // Optional AAD (hash only)
        byte[] aad = ctx.get(ConfluxKeys.aad(id));
        byte[] aadHash = (aad == null || aad.length == 0) ? null : sha256(aad);

        // Optional tag bits hint for GCM (store if caller put it there)
        Integer tb = ctx.get(ConfluxKeys.tagBits(id));
        int tagBits = tb == null ? 0 : tb;

        if (LOG.isLoggable(Level.FINE)) {
            LOG.log(Level.FINE, "{4} header aad={0} aadHash={1} tagBits={2} iv={3}",
                    new Object[] { Strings.toShortHexString(aad), Strings.toShortHexString(aadHash), tagBits,
                            Strings.toShortHexString(iv), id });
        }

        Util.write(out, iv); // IV
        Util.writePack7I(out, tagBits); // 0 for non-GCM
        if (aadHash == null) {
            out.write(0);
        } else {
            out.write(1);
            out.write(aadHash); // 32 bytes
        }
        out.flush();
    }

    /**
     * Reads a header from {@code in}, updates the context with IV (and tag bits),
     * and verifies AAD if present.
     *
     * @param in        source stream positioned at header
     * @param algorithm owning algorithm (ID {@code "AES"})
     * @param ctx       destination for IV/tag bits and AAD verification
     * @return the same {@code InputStream}, positioned after the header
     * @throws IOException on malformed header, missing AAD when required, or AAD
     *                     hash mismatch
     */
    @Override
    public InputStream readHeader(InputStream in, CryptoAlgorithm algorithm, CtxInterface ctx) throws IOException {
        final String id = algorithm.id();

        byte[] iv = Util.read(in, 32);
        int tagBits = Util.readPack7I(in);
        int aadFlag = in.read();

        byte[] aadHash = null;
        if (aadFlag == 1) { // NOPMD
            aadHash = in.readNBytes(32);
        }

        // Hydrate Ctx
        ctx.put(ConfluxKeys.iv(id), iv);
        if (tagBits != 0) {
            ctx.put(ConfluxKeys.tagBits(id), tagBits);
        }
        byte[] aad = ctx.get(ConfluxKeys.aad(id));
        if (aadHash != null) {
            if (aad == null || aad.length == 0) {
                throw new IOException("AES header expects AAD, but none provided in Ctx");
            }
            if (!Arrays.equals(aadHash, sha256(aad))) {
                throw new IOException("AES header: AAD hash mismatch");
            }
        }

        if (LOG.isLoggable(Level.FINE)) {
            LOG.log(Level.FINE, "{4} header aad={0} aadHash={1} tagBits={2} iv={3}",
                    new Object[] { Strings.toShortHexString(aad), Strings.toShortHexString(aadHash), tagBits,
                            Strings.toShortHexString(iv), id });
        }

        return in; // positioned after header
    }

    private static byte[] sha256(byte[] a) throws IOException {
        try {
            return MessageDigest.getInstance("SHA-256").digest(a);
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 unavailable", e);
        }
    }
}
