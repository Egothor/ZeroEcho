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
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

/**
 * Chunk-transforming stream that applies a cipher to each full input block and
 * left-pads each produced block with zeros to {@code outChunkSize}.
 *
 * <p>
 * For each complete input block, the method shifts the produced bytes to the
 * right and fills the left region with zeros when the cipher output is shorter
 * than {@code outChunkSize}. A final block must be complete; partial remainders
 * are rejected with {@link IllegalStateException}.
 * </p>
 */
final class SmartPaddedBlockStream extends AbstractChunkTransformInputStream {
    private static final Logger LOG = Logger.getLogger(SmartPaddedBlockStream.class.getName());

    private final Cipher cipher;

    /* package */ SmartPaddedBlockStream(InputStream upstream, Cipher cipher, int inChunkSize, int outChunkSize,
            int bufferedBlocks) {
        super(upstream, inChunkSize, outChunkSize, bufferedBlocks);
        this.cipher = cipher;
    }

    /**
     * Applies the cipher to {@code inChunks} complete input blocks and pads each
     * result on the left with zeros to exactly {@code outChunkSize} bytes.
     *
     * @param in       the input buffer
     * @param inOff    offset of the first complete block
     * @param inChunks number of full blocks to process
     * @param out      destination buffer for padded output blocks
     * @return number of bytes written to {@code out}
     * @throws IOException if the cipher reports a processing error
     */
    @Override
    protected int transform(byte[] in, int inOff, int inChunks, byte[] out) throws IOException {
        try {
            // return cipher.doFinal(in, inOff, inChunks * g.inputBlockSize(), out);
            int output = 0;
            for (int i = 0; i < inChunks; i++) {
                int outOne = cipher.doFinal(in, inOff, inChunkSize, out, output);
                if (outOne < 0 || outOne > outChunkSize) {
                    throw new IOException("Cipher output exceeds the configured block size");
                }
                int diff = outChunkSize - outOne;
                if (diff > 0) {
                    System.arraycopy(out, output, out, output + diff, outOne);
                    Arrays.fill(out, output, output + diff, (byte) 0);
                    outOne = outChunkSize;
                }
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
     * Finalization requires a complete final block; partial tails are not
     * supported.
     *
     * @param in     input buffer
     * @param inOff  offset of the final block
     * @param len    length of the final block; must equal {@code inChunkSize}
     * @param out    destination buffer for output bytes
     * @param outOff offset in {@code out} where bytes are written
     * @return number of bytes written to {@code out}
     * @throws IllegalStateException if {@code len != inChunkSize}
     * @throws IOException           if the cipher reports a processing error
     */
    @Override
    protected int doFinal(byte[] in, int inOff, int len, byte[] out, int outOff) throws IOException {
        if (len == 0) {
            return 0;
        }

        if (len != inChunkSize) {
            throw new IllegalStateException("Cannot process incomplete blocks: " + len + " instead of " + inChunkSize);
        }
        try {
            return cipher.doFinal(in, inOff, len, out, outOff);
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException e) {
            LOG.logp(Level.WARNING, "SmartBlockStream", "transform", "Exception", e);
            throw new IOException(e);
        }
    }
}
