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
package zeroecho.core.alg.chacha;

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

/**
 * <h2>ChaCha20-Poly1305 streaming header codec</h2>
 *
 * Implements {@link SymmetricHeaderCodec} for the ChaCha20-Poly1305 AEAD mode.
 * Encodes a compact header that precedes the ciphertext stream and conveys:
 * <ul>
 * <li>a 12-byte nonce (IV) required by ChaCha20-Poly1305, and</li>
 * <li>an optional SHA-256 hash of AAD to assert integrity of externally
 * supplied AAD.</li>
 * </ul>
 *
 * <p>
 * The nonce and AAD are exchanged via the bound {@link CtxInterface} using
 * {@link ConfluxKeys#iv(String)} and {@link ConfluxKeys#aad(String)} keys,
 * respectively. On encryption, the codec reads these values from the context
 * and writes the header. On decryption, it restores the nonce into the context
 * and, when present, verifies the supplied AAD by comparing its hash to the
 * header.
 * </p>
 *
 * <h3>Header layout</h3> <pre>
 *  [0..11]  : 12-byte nonce (IV)
 *  [12]     : 1-byte AAD flag (0 = none, 1 = present)
 *  [13..44] : 32-byte SHA-256(AAD) if flag == 1
 * </pre>
 *
 * <h3>Failure modes</h3>
 * <ul>
 * <li>Missing/invalid nonce in context when writing the header.</li>
 * <li>AAD expected by header but not provided in context during read.</li>
 * <li>AAD hash mismatch when verifying during read.</li>
 * </ul>
 *
 * @since 1.0
 */
public final class ChaCha20Poly1305HeaderCodec implements SymmetricHeaderCodec {
    /**
     * Logger for debug-level diagnostics of header encode/decode operations.
     */
    private static final Logger LOG = Logger.getLogger(ChaCha20Poly1305HeaderCodec.class.getName());
    /**
     * Required nonce length for ChaCha20-Poly1305 headers (12 bytes).
     */
    private static final int NONCE_LEN = 12;

    /**
     * Creates a stateless ChaCha20-Poly1305 stream-header codec.
     */
    public ChaCha20Poly1305HeaderCodec() {
        // Stateless codec.
    }

    /**
     * Writes the ChaCha20-Poly1305 header to the provided stream.
     *
     * <p>
     * Reads the 12-byte nonce and optional AAD from {@code ctx}. If AAD is
     * non-empty, its SHA-256 is written after a presence flag. Flushes the output
     * upon completion.
     * </p>
     *
     * @param out       destination stream to receive the header
     * @param algorithm the algorithm instance (used for context key scoping)
     * @param ctx       operation context carrying nonce and optional AAD
     * @throws java.io.IOException if the nonce is missing/invalid or I/O fails
     */
    @Override
    public void writeHeader(OutputStream out, CryptoAlgorithm algorithm, CtxInterface ctx) throws IOException {
        final String id = algorithm.id(); // "CHACHA20-POLY1305"
        LOG.log(Level.FINE, "writeHeader={0}", id);

        byte[] nonce = ctx.get(ConfluxKeys.iv(id));
        if (nonce == null || nonce.length != NONCE_LEN) {
            throw new IOException("ChaCha20-Poly1305 header: nonce missing/invalid in Ctx");
        }
        byte[] aad = ctx.get(ConfluxKeys.aad(id));
        byte[] aadHash = (aad == null || aad.length == 0) ? null : sha256(aad);

        Util.write(out, nonce); // 12 bytes
        out.write(aadHash == null ? 0 : 1);
        if (aadHash != null) {
            out.write(aadHash);
        }
        out.flush();
    }

    /**
     * Reads and validates the ChaCha20-Poly1305 header from the provided stream.
     *
     * <p>
     * Restores the 12-byte nonce into {@code ctx}. If the header signals AAD
     * presence, computes SHA-256 over the AAD obtained from {@code ctx} and
     * verifies it against the header hash.
     * </p>
     *
     * @param in        source stream containing the header and subsequent payload
     * @param algorithm the algorithm instance (used for context key scoping)
     * @param ctx       operation context to populate (nonce) and validate (AAD)
     * @return the same {@code in} stream positioned after the header
     * @throws java.io.IOException if the header is malformed, AAD is missing when
     *                             required, the AAD hash mismatches, or I/O fails
     */
    @Override
    public InputStream readHeader(InputStream in, CryptoAlgorithm algorithm, CtxInterface ctx) throws IOException {
        final String id = algorithm.id();
        LOG.log(Level.FINE, "readHeader={0}", id);

        byte[] nonce = Util.read(in, NONCE_LEN);
        int aadFlag = in.read();
        byte[] aadHash = null;
        if (aadFlag == 1) { // NOPMD
            aadHash = in.readNBytes(32);
        }

        // hydrate Ctx
        ctx.put(ConfluxKeys.iv(id), nonce);
        if (aadHash != null) {
            byte[] aad = ctx.get(ConfluxKeys.aad(id));
            if (aad == null || aad.length == 0) {
                throw new IOException("ChaCha20-Poly1305 header expects AAD, but none provided in Ctx");
            }
            if (!Arrays.equals(aadHash, sha256(aad))) {
                throw new IOException("ChaCha20-Poly1305 header: AAD hash mismatch");
            }
        }
        return in;
    }

    private static byte[] sha256(byte[] a) throws IOException {
        try {
            return MessageDigest.getInstance("SHA-256").digest(a);
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 unavailable", e);
        }
    }
}
