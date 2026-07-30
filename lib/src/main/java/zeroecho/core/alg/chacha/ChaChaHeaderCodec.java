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
package zeroecho.core.alg.chacha;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import conflux.CtxInterface;
import zeroecho.core.ConfluxKeys;
import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.SymmetricHeaderCodec;
import zeroecho.core.io.Util;

/**
 * <h2>ChaCha20 streaming header codec</h2>
 *
 * Implements {@link SymmetricHeaderCodec} for the {@code ChaCha20} stream
 * cipher. Encodes a compact header containing:
 * <ul>
 * <li>a 12-byte nonce (IV), and</li>
 * <li>the stream counter as a 7-bit packed integer.</li>
 * </ul>
 *
 * <p>
 * The nonce and counter are exchanged through the bound {@link CtxInterface}
 * using {@link ConfluxKeys#iv(String)} and {@link ConfluxKeys#tagBits(String)}
 * keys, namespaced by the algorithm id (e.g., {@code "CHACHA20"}).
 * </p>
 *
 * <h3>Header layout</h3> <pre>
 *  [0..11]   : 12-byte nonce (IV)
 *  [12..N]   : counter encoded via 7-bit packed integer
 * </pre>
 *
 * <h3>Behavior</h3>
 * <ul>
 * <li><b>writeHeader</b>: requires {@code iv(id)} in context (12 bytes). Writes
 * the nonce, then the counter from {@code tagBits(id)} if present, otherwise
 * uses {@code 1}.</li>
 * <li><b>readHeader</b>: reads nonce and counter and stores them into the
 * context under the same keys.</li>
 * </ul>
 *
 * @since 1.0
 */
public final class ChaChaHeaderCodec implements SymmetricHeaderCodec {
    /**
     * Required nonce length for ChaCha20 headers (12 bytes).
     */
    private static final int NONCE_LEN = 12;

    /**
     * Writes the ChaCha20 header to the provided output.
     *
     * <p>
     * Reads a 12-byte nonce from {@link ConfluxKeys#iv(String)} and a stream
     * counter from {@link ConfluxKeys#tagBits(String)} (defaulting to {@code 1} if
     * absent). Emits the nonce followed by the counter encoded as a 7-bit packed
     * integer, then flushes.
     * </p>
     *
     * @param out       destination stream
     * @param algorithm algorithm instance used for context key scoping
     * @param ctx       operation context carrying nonce and optional counter
     * @throws java.io.IOException if the nonce is missing/invalid or I/O fails
     */
    @Override
    public void writeHeader(OutputStream out, CryptoAlgorithm algorithm, CtxInterface ctx) throws IOException {
        final String id = algorithm.id(); // "CHACHA20"
        byte[] nonce = ctx.get(ConfluxKeys.iv(id));
        if (nonce == null || nonce.length != NONCE_LEN) {
            throw new IOException("ChaChaHeaderCodec: nonce missing/invalid in Ctx");
        }
        Integer ctr = ctx.get(ConfluxKeys.tagBits(id));
        int counter = ctr == null ? 1 : ctr;
        Util.write(out, nonce);
        Util.writePack7I(out, counter);
        out.flush();
    }

    /**
     * Reads a ChaCha20 header from the input and hydrates the context.
     *
     * <p>
     * Consumes a 12-byte nonce and a 7-bit packed counter, then stores them into
     * {@code ctx} under {@link ConfluxKeys#iv(String)} and
     * {@link ConfluxKeys#tagBits(String)}, respectively. Returns the same input
     * stream positioned after the header.
     * </p>
     *
     * @param in        source stream
     * @param algorithm algorithm instance used for context key scoping
     * @param ctx       context to populate with nonce and counter
     * @return the input stream positioned after the header
     * @throws java.io.IOException if the header is malformed or I/O fails
     */
    @Override
    public InputStream readHeader(InputStream in, CryptoAlgorithm algorithm, CtxInterface ctx) throws IOException {
        final String id = algorithm.id();
        byte[] nonce = Util.read(in, NONCE_LEN);
        int counter = Util.readPack7I(in);
        ctx.put(ConfluxKeys.iv(id), nonce);
        ctx.put(ConfluxKeys.tagBits(id), counter);
        return in;
    }
}
