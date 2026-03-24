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
package zeroecho.core.io;

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

/**
 * Chunk-transforming stream that applies a cipher to each full input block and
 * forwards the produced bytes without extra padding.
 *
 * <p>
 * Full blocks are processed via
 * {@link Cipher#doFinal(byte[], int, int, byte[], int)} in a loop. If the final
 * read yields a partial block, it is finalized through a single {@code doFinal}
 * and end-of-stream is marked.
 * </p>
 */
final class SmartBlockStream extends AbstractChunkTransformInputStream {
    private static final Logger LOG = Logger.getLogger(SmartBlockStream.class.getName());

    private final Cipher cipher;
    private boolean doFinalCalled;

    /* package */ SmartBlockStream(InputStream upstream, Cipher cipher, int inChunkSize, int outChunkSize,
            int bufferedBlocks) {
        super(upstream, inChunkSize, outChunkSize, bufferedBlocks);
        this.cipher = cipher;
    }

    /**
     * Applies the cipher to {@code inChunks} complete input blocks and writes
     * results contiguously to {@code out}.
     *
     * @param in       the input buffer
     * @param inOff    offset of the first complete block
     * @param inChunks number of full blocks to process
     * @param out      destination buffer for output bytes
     * @return number of bytes written to {@code out}
     * @throws IOException if the cipher reports a processing error
     */
    @Override
    protected int transform(byte[] in, int inOff, int inChunks, byte[] out) throws IOException {
        try {
            int output = 0;
            doFinalCalled = inChunks > 0;
            for (int i = 0; i < inChunks; i++) {
                int outOne = cipher.doFinal(in, inOff, inChunkSize, out, output);
                output = output + outOne;
                inOff += inChunkSize; // NOPMD
            }
            return output;
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException e) {
            LOG.logp(Level.WARNING, "SmartBlockStream", "transform", "Exception", e);
            throw new IOException(e);
        }
    }

    /**
     * Finalizes processing of a trailing partial block, if present.
     *
     * @param in     input buffer containing the remainder
     * @param inOff  offset of the remainder
     * @param len    number of bytes in the remainder
     * @param out    destination buffer for output bytes
     * @param outOff offset in {@code out} where bytes are written
     * @return number of bytes written to {@code out}
     * @throws IOException if the cipher reports a processing error
     */
    @Override
    protected int doFinal(byte[] in, int inOff, int len, byte[] out, int outOff) throws IOException {
        try {
            if (doFinalCalled && len == 0) {
                return 0;
            }

            doFinalCalled = true;
            return cipher.doFinal(in, inOff, len, out, outOff);
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException e) {
            LOG.logp(Level.WARNING, "SmartBlockStream", "transform", "Exception", e);
            throw new IOException(e);
        }
    }

}
