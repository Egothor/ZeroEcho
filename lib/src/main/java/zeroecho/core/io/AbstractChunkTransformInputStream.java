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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * InputStream that transforms data in fixed-size chunks with optional
 * finalization.
 *
 * <p>
 * This abstract class provides a framework for streaming transformations where
 * the input is processed in aligned blocks of {@code inChunkSize} bytes,
 * producing corresponding output blocks of {@code outChunkSize} bytes.
 * Subclasses implement the transformation logic in
 * {@link #transform(byte[], int, int, byte[])} and handle any trailing input in
 * {@link #doFinal(byte[], int, int, byte[], int)}.
 * </p>
 *
 * <h2>Design and invariants</h2>
 * <ul>
 * <li>Input bytes are read from the wrapped {@link InputStream} into
 * {@code inBuf}, preferably in multiples of {@code inChunkSize}.</li>
 * <li>{@link #transform(byte[], int, int, byte[])} is invoked for all complete
 * chunks. Its contract is to consume {@code inChunks * inChunkSize} bytes from
 * {@code in} and produce contiguous output bytes into {@code out}.</li>
 * <li>If the final read yields a partial chunk smaller than
 * {@code inChunkSize}, {@link #doFinal(byte[], int, int, byte[], int)} is
 * invoked to process the remainder and emit any trailer (e.g., padding block or
 * authentication tag).</li>
 * <li>Output bytes are staged in {@code outBuf} and consumed by {@link #read()}
 * and {@link #read(byte[], int, int)}.</li>
 * </ul>
 *
 * <h2>Buffer sizing and finalization headroom</h2>
 * <p>
 * The primary constructor sizes both input and output buffers to
 * {@code chunks * inChunkSize} and {@code chunks * outChunkSize}, respectively.
 * An overloaded constructor adds {@code finalizationOutputChunks} to the
 * output-side capacity only, resulting in
 * {@code outChunkSize * (chunks + finalizationOutputChunks)}. This headroom
 * guarantees that the last {@code doFinal(...)} call can emit trailer bytes
 * (for example, a padding block or AEAD tag) even when the steady-state output
 * window is full.
 * </p>
 * <p>
 * Typical values when {@code outChunkSize == 16} (AES-sized):
 * </p>
 * <ul>
 * <li>No padding modes (e.g., AES/CBC/NOPADDING):
 * {@code finalizationOutputChunks = 0}.</li>
 * <li>Padding modes (e.g., AES/CBC/PKCS5PADDING): {@code 1} to cover a full
 * padding block.</li>
 * <li>AEAD modes (e.g., AES/GCM/NOPADDING with 16-byte tag): {@code 2} to cover
 * tail bytes (up to 15) plus the tag (commonly 16).</li>
 * </ul>
 *
 * <h2>Thread-safety</h2> Instances are not thread-safe. If a single instance is
 * shared across threads, external synchronization is required.
 *
 * <h2>Example</h2> <pre>{@code
 * // Example subclass wiring (pseudocode)
 * final class MyCipherStream extends AbstractChunkTransformInputStream {
 *     private final Cipher cipher;
 *     MyCipherStream(InputStream in, Cipher c) {
 *         super(in, 16, 16, 256, 2); // +2 output chunks headroom (e.g., AES-GCM)
 *         this.cipher = c;
 *     }
 *     &#64;Override protected int transform(byte[] src, int off, int chunks, byte[] dst) throws IOException {
 *         try {
 *             return cipher.update(src, off, chunks * 16, dst, 0);
 *         } catch (ShortBufferException e) {
 *             throw new IOException(e);
 *         }
 *     }
 *     &#64;Override protected int doFinal(byte[] src, int off, int len, byte[] dst, int dstOff) throws IOException {
 *         try {
 *             int out = 0;
 *             if (len > 0) { out = cipher.update(src, off, len, dst, dstOff); dstOff += out; }
 *             out += cipher.doFinal(dst, dstOff);
 *             return out;
 *         } catch (GeneralSecurityException | ShortBufferException e) {
 *             throw new IOException(e);
 *         }
 *     }
 * }
 * }</pre>
 *
 * @author Leo Galambos
 * @since 1.0
 */
public abstract class AbstractChunkTransformInputStream extends FilterInputStream {
    /** Input buffer storing data read from the upstream stream. */
    protected final byte[] inBuf;
    /** Output buffer storing transformed bytes awaiting consumption. */
    protected byte[] outBuf;
    /** Number of valid bytes currently in {@code inBuf}. */
    protected int inLen;
    /** Current read position within {@code outBuf}. */
    protected int outPtr;
    /** Number of valid bytes currently in {@code outBuf}. */
    protected int outLen;
    /** Flag indicating that end-of-stream has been reached. */
    protected boolean eofSeen; // = false;
    /** Size of one logical input chunk. */
    protected final int inChunkSize;
    /** Size of one logical output chunk. */
    protected final int outChunkSize;

    /**
     * Constructs a new chunk-transforming input stream with symmetric input and
     * output capacities.
     *
     * <p>
     * The input buffer is sized to {@code inChunkSize * chunks} and the output
     * buffer to {@code outChunkSize * chunks}. No extra output headroom is reserved
     * for finalization.
     * </p>
     *
     * @param upstream     the underlying input stream
     * @param inChunkSize  size of input chunks expected by the transform (must be >
     *                     1)
     * @param outChunkSize size of output chunks produced by the transform (must be
     *                     > 0)
     * @param chunks       number of chunks buffered at once (must be > 0)
     * @throws AssertionError if {@code chunks <= 0}, {@code inChunkSize <= 1}, or
     *                        {@code outChunkSize <= 0}
     */
    protected AbstractChunkTransformInputStream(InputStream upstream, int inChunkSize, int outChunkSize, int chunks) {
        super(upstream);
        assert chunks > 0 && inChunkSize > 1 && outChunkSize > 0;

        this.inBuf = new byte[inChunkSize * chunks];
        this.outBuf = new byte[outChunkSize * chunks];

        this.inChunkSize = inChunkSize;
        this.outChunkSize = outChunkSize;
    }

    /**
     * Constructs a new chunk-transforming input stream with extra output headroom
     * for finalization.
     *
     * <p>
     * The input buffer is sized to {@code inChunkSize * chunks}. The output buffer
     * is sized to {@code outChunkSize * (chunks + finalizationOutputChunks)} so
     * that the last call to {@link #doFinal(byte[], int, int, byte[], int)} can
     * emit trailer bytes even when the steady-state output region is full.
     * </p>
     *
     * @param upstream                 the underlying input stream
     * @param inChunkSize              size of input chunks expected by the
     *                                 transform (must be > 1)
     * @param outChunkSize             size of output chunks produced by the
     *                                 transform (must be > 0)
     * @param chunks                   number of chunks buffered at once for
     *                                 steady-state (must be > 0)
     * @param finalizationOutputChunks number of extra output chunks reserved for
     *                                 finalization (must be >= 0)
     * @throws AssertionError if {@code chunks <= 0}, {@code inChunkSize <= 1}, or
     *                        {@code outChunkSize <= 0}
     */
    protected AbstractChunkTransformInputStream(InputStream upstream, int inChunkSize, int outChunkSize, int chunks,
            int finalizationOutputChunks) {
        super(upstream);
        assert chunks > 0 && inChunkSize > 1 && outChunkSize > 0;

        this.inBuf = new byte[inChunkSize * chunks];
        this.outBuf = new byte[outChunkSize * (chunks + finalizationOutputChunks)];

        this.inChunkSize = inChunkSize;
        this.outChunkSize = outChunkSize;
    }

    /**
     * Transforms one or more full input chunks into output bytes.
     *
     * @param in       buffer containing input data
     * @param inOff    offset in {@code in} where chunks begin
     * @param inChunks number of complete input chunks available
     * @param out      destination buffer for transformed bytes
     * @return number of bytes written to {@code out}
     * @throws IOException if transformation fails
     */
    protected abstract int transform(byte[] in, int inOff, int inChunks, byte[] out) throws IOException;

    /**
     * Finalizes the transformation with an optional trailing incomplete chunk.
     *
     * <p>
     * Invoked at EOF if the last read produced fewer than {@code inChunkSize}
     * bytes. Implementations may perform padding, compute an authentication tag, or
     * flush any provider-internal state. The {@code outOff} argument specifies
     * where to start writing the final bytes in {@code out}.
     * </p>
     *
     * @param in     buffer containing the final partial chunk (may be empty)
     * @param inOff  offset of the partial data
     * @param len    number of available bytes (&lt; {@code inChunkSize})
     * @param out    destination buffer for transformed bytes
     * @param outOff offset in {@code out} where bytes should be written
     * @return number of bytes written to {@code out}
     * @throws IOException if finalization fails or the provider reports an error
     */
    protected abstract int doFinal(byte[] in, int inOff, int len, byte[] out, int outOff) throws IOException;

    /**
     * Fills the output buffer by reading from the upstream and applying the
     * transformation.
     *
     * <p>
     * On EOF, {@link #doFinal(byte[], int, int, byte[], int)} is executed exactly
     * once (even if {@code len == 0}) and any produced bytes are exposed to the
     * caller.
     * </p>
     *
     * @return {@code true} if new output is available, {@code false} if EOF reached
     *         and no output produced
     * @throws IOException if the upstream read or the transformation fails
     */
    private boolean fillBuffers() throws IOException {
        assert outPtr == outLen;

        inLen = in.readNBytes(inBuf, 0, inBuf.length);
        if (inLen == 0) {
            // EOF: run finalization exactly once, even if there's no remainder,
            // and surface any produced bytes (e.g., padding block, GCM tag).
            if (!eofSeen) {
                int finalOut = doFinal(inBuf, 0, 0, outBuf, 0);
                outPtr = 0;
                outLen = finalOut;
                eofSeen = true;
                return finalOut > 0; // allow the caller to drain final bytes
            }
            return false;
        }

        // all chunks are aligned to the specified boundary (inChunkSize) -> transform
        // can be simply invoked
        outLen = transform(inBuf, 0, inLen / inChunkSize, outBuf);
        outPtr = 0;

        int left = inLen % inChunkSize;

        if (left > 0) {
            int finalOutChunkSize = doFinal(inBuf, inLen - left, left, outBuf, outLen);
            outLen = outLen + finalOutChunkSize;
            // we ask for whole inBufSize chunks, if readNBytes returns a partial chunk, it
            // must be eof
            eofSeen = true;
        }

        return true;
    }

    /**
     * Reads the next transformed byte.
     *
     * @return the next byte as an unsigned int in the range {@code 0-255}, or
     *         {@code -1} if end-of-stream has been reached
     * @throws IOException if an I/O error occurs
     */
    @Override
    public int read() throws IOException {
        if (outPtr < outLen) {
            return outBuf[outPtr++] & 0xff;
        }

        return fillBuffers() ? outBuf[outPtr++] & 0xff : -1 /* eof */;
    }

    /**
     * Reads transformed bytes into the given array.
     *
     * <p>
     * This implementation delegates to {@link #read(byte[], int, int)}.
     * </p>
     *
     * @param b target buffer
     * @return number of bytes read, or {@code -1} at EOF
     * @throws IOException if an I/O error occurs
     */
    @Override
    public int read(byte[] b) throws IOException {
        return read(b, 0, b.length);
    }

    /**
     * Reads up to {@code len} transformed bytes into the target buffer.
     *
     * <p>
     * Blocks until at least one byte is available or EOF is reached.
     * </p>
     *
     * @param b   target buffer
     * @param off offset in {@code b} where data should be stored
     * @param len maximum number of bytes to read
     * @return number of bytes read, or {@code -1} if EOF and no data returned
     * @throws IOException if an I/O error occurs
     */
    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int total = 0;
        while (len > 0) {
            if (outPtr >= outLen) {
                // we have not more, let us try to prepare new buffers
                if (!fillBuffers()) { // NOPMD
                    return (total == 0) ? -1 : total;
                }
            }

            int available = Math.min(outLen - outPtr, len);
            System.arraycopy(outBuf, outPtr, b, off, available);
            off += available; // NOPMD
            outPtr += available;
            total += available;
            len -= available; // NOPMD
        }
        return total;
    }
}
