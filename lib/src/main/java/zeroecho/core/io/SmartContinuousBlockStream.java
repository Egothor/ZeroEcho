/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
 * Passthrough stream that transforms input with a {@link javax.crypto.Cipher}
 * in continuous streaming mode.
 *
 * <p>
 * This class extends {@link AbstractChunkTransformInputStream} to adapt block
 * sizes into calls to {@link Cipher#update(byte[], int, int, byte[], int)} and
 * {@link Cipher#doFinal(byte[], int, int, byte[], int)}. It is suitable for
 * symmetric ciphers in modes that support continuous streaming (e.g., CBC, GCM,
 * CTR).
 * </p>
 *
 * <h2>Operation</h2>
 * <ul>
 * <li><b>Transform phase:</b> chunks of {@code inChunkSize} bytes are grouped
 * and passed to the cipher in a single bulk {@code update} call. The provider
 * may accept arbitrary multiples of the block size.</li>
 * <li><b>Finalization phase:</b> when EOF is reached, any trailing bytes are
 * processed (if present) and {@code doFinal} is invoked exactly once to flush
 * buffered state and produce final output (padding, tag, etc.).</li>
 * </ul>
 *
 * <h2>Buffer expansion</h2>
 * <p>
 * Before calling {@code doFinal}, the required output length is queried via
 * {@link Cipher#getOutputSize(int)}. If the current buffer is too small, it is
 * expanded using {@link Arrays#copyOf(byte[], int)}. A warning is logged via
 * {@link Logger} when expansion occurs.
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances are not thread-safe and must be confined to a single consuming
 * thread.
 * </p>
 *
 * @since 1.0
 */
final class SmartContinuousBlockStream extends AbstractChunkTransformInputStream {
    private static final Logger LOG = Logger.getLogger(SmartContinuousBlockStream.class.getName());
    /** Underlying cipher used for streaming updates and finalization. */
    private final Cipher cipher;

    /**
     * Creates a new continuous block stream wrapper around a {@link Cipher}.
     *
     * @param upstream                 upstream source stream to transform
     * @param cipher                   initialized cipher instance
     * @param inChunkSize              number of input bytes per chunk
     * @param outChunkSize             maximum output bytes per chunk
     * @param bufferedBlocks           number of input blocks buffered internally
     * @param finalizationOutputChunks number of additional output chunks expected
     *                                 during finalization
     * @throws NullPointerException if {@code upstream} or {@code cipher} is
     *                              {@code null}
     */
    /* package */ SmartContinuousBlockStream(InputStream upstream, Cipher cipher, int inChunkSize, int outChunkSize,
            int bufferedBlocks, int finalizationOutputChunks) {
        super(upstream, inChunkSize, outChunkSize, bufferedBlocks, finalizationOutputChunks);
        this.cipher = cipher;
    }

    /**
     * Performs the streaming transform using
     * {@link Cipher#update(byte[], int, int, byte[], int)}.
     *
     * <p>
     * Processes {@code inChunks * inChunkSize} bytes from {@code in} starting at
     * {@code inOff}, and writes results into {@code out} starting at offset 0.
     * </p>
     *
     * @param in       source buffer with plaintext or ciphertext
     * @param inOff    offset in {@code in} to start reading
     * @param inChunks number of input chunks to process
     * @param out      destination buffer to receive transformed bytes
     * @return number of output bytes written
     * @throws IOException if the cipher signals a short buffer or provider error
     */
    @Override
    protected int transform(byte[] in, int inOff, int inChunks, byte[] out) throws IOException {
        try {
            int toProcess = inChunks * inChunkSize;
            // Single bulk update; providers handle arbitrary sizes in streaming modes.
            return cipher.update(in, inOff, toProcess, out, 0);
        } catch (ShortBufferException e) {
            LOG.logp(Level.WARNING, "SmartContinuousBlockStream", "transform", "Short buffer", e);
            throw new IOException(e);
        }
    }

    /**
     * Finalizes the cipher by processing any trailing input and calling
     * {@link Cipher#doFinal(byte[], int, int, byte[], int)}.
     *
     * <p>
     * If the provided output buffer is too small for the final block (as reported
     * by {@link Cipher#getOutputSize(int)}), the internal buffer is expanded and a
     * warning is logged. This ensures complete final output is not truncated.
     * </p>
     *
     * @param in     buffer containing final input bytes
     * @param inOff  offset in {@code in} where valid data starts
     * @param len    number of final input bytes
     * @param out    destination buffer for output
     * @param outOff offset in {@code out} to begin writing
     * @return number of bytes written to {@code out}
     * @throws IOException if finalization fails (short buffer, bad padding, illegal
     *                     block size)
     */
    @Override
    protected int doFinal(byte[] in, int inOff, int len, byte[] out, int outOff) throws IOException {
        try {
            int finBlockSize = cipher.getOutputSize(len);
            if (out.length < outOff + finBlockSize) {
                if (LOG.isLoggable(Level.WARNING)) {
                    LOG.log(Level.WARNING, "Expanding buffer of {0} from {1} bytes to {2} bytes",
                            new Object[] { cipher.getAlgorithm(), outBuf.length, outOff + finBlockSize });
                }
                out = outBuf = Arrays.copyOf(outBuf, outOff + finBlockSize); // NOPMD
            }

            int written = cipher.doFinal(in, inOff, len, out, outOff);
            return written;

            // return cipher.doFinal(in, inOff, len, out, outOff);
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException e) {
            LOG.logp(Level.WARNING, "SmartContinuousBlockStream", "doFinal", "Exception", e);
            throw new IOException(e);
        }
    }
}