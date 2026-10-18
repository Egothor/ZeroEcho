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
package zeroecho.core.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.util.Strings;

/**
 * InputStream that withholds the last N bytes from the upstream stream and
 * emits everything before that tail, delivering the withheld tail to a callback
 * at EOF.
 *
 * <h2>Overview</h2> This stream is useful when the final bytes carry
 * out-of-band metadata such as checksums, MAC tags, or trailers that must not
 * appear in the payload. During normal reads it buffers enough data to ensure
 * the last {@code tailLen} bytes are never exposed. When the upstream reaches
 * EOF, the accumulated tail is passed to {@link #processTail(byte[])} exactly
 * once.
 *
 * <h2>How it works</h2>
 * <ul>
 * <li>A sliding window of size {@code tailLen + ioBuffer} is maintained.</li>
 * <li>While reading, any overflow beyond {@code tailLen} is immediately emitted
 * to the caller; the final {@code tailLen} bytes are withheld in the
 * window.</li>
 * <li>On EOF, the remaining bytes in the window (length {@code <= tailLen}) are
 * delivered to {@code processTail(byte[])} and never returned from
 * {@code read()}.</li>
 * </ul>
 *
 * <h2>Behavioral notes</h2>
 * <ul>
 * <li>If the entire stream is shorter than {@code tailLen}, no payload bytes
 * are ever emitted; the complete content is provided to
 * {@code processTail(byte[])}.</li>
 * <li>{@link #close()} drains the upstream to ensure tail processing happens
 * even if the caller stops reading early.</li>
 * <li>Mark/reset is not supported.</li>
 * </ul>
 *
 * <h2>Typical use</h2> <pre>{@code
 * InputStream raw = ...; // e.g., file or network
 * int tagBytes = 16;     // withhold a 16-byte authentication tag at the end
 * TailStrippingInputStream in = new TailStrippingInputStream(raw, tagBytes, 4096) {
 *     &#64;Override
 *     protected void processTail(byte[] tail) throws IOException {
 *         // verify MAC, parse footer, etc.
 *     }
 * };
 *
 * // Read payload only (tag withheld and never exposed here)
 * byte[] buf = in.readAllBytes();
 * in.close(); // ensures processTail(...) is invoked if not already
 * }</pre>
 *
 * <h2>Thread-safety</h2> Instances are not thread-safe. Use a separate instance
 * per stream.
 *
 * @since 1.0
 */
public abstract class TailStrippingInputStream extends InputStream {
    private static final Logger LOG = Logger.getLogger(TailStrippingInputStream.class.getName());

    private final InputStream upstream;
    private final int tailLen;
    private final byte[] window; // capacity = tailLen + ioBuf
    private final byte[] oneByte = new byte[1];

    // State
    private int accLen; // = 0; // valid bytes in window (includes emit+tail)
    private int emitPos; // = 0; // current emission index
    private int emitLen; // = 0; // prepared bytes to emit (the overflow beyond tail)
    private boolean needCompactAfterEmit; // = false;
    private boolean upstreamEof; // = false;
    private boolean tailProcessed; // = false;
    private boolean closed; // = false;

    /**
     * Creates a new tail-stripping stream around an upstream source.
     *
     * <p>
     * The internal sliding window is allocated with capacity
     * {@code tailLen + max(1024, ioBuffer)}. The parameter {@code ioBuffer}
     * controls incremental emission granularity; {@code tailLen} controls how many
     * bytes are withheld until EOF.
     * </p>
     *
     * @param upstream non-null source stream
     * @param tailLen  number of bytes to strip and deliver to
     *                 {@link #processTail(byte[])}; must be >= 1
     * @param ioBuffer additional working buffer size; must be >= 1 (actual
     *                 allocation is {@code max(1024, ioBuffer)})
     * @throws NullPointerException     if {@code upstream} is null
     * @throws IllegalArgumentException if {@code tailLen < 1} or
     *                                  {@code ioBuffer < 1}
     */
    public TailStrippingInputStream(InputStream upstream, int tailLen, int ioBuffer) {
        super();

        this.upstream = Objects.requireNonNull(upstream, "upstream");
        if (tailLen < 1) { // NOPMD
            throw new IllegalArgumentException("tailLen must be >= 1");
        }
        if (ioBuffer < 1) { // NOPMD
            throw new IllegalArgumentException("ioBuffer must be >= 1");
        }
        this.tailLen = tailLen;
        this.window = new byte[tailLen + Math.max(1024, ioBuffer)];
    }

    /**
     * Hook invoked exactly once at end of stream with the withheld tail bytes.
     *
     * <p>
     * The provided array contains the last {@code min(totalBytesRead, tailLen)}
     * bytes of the upstream stream. For short streams, this may be smaller than
     * {@code tailLen} and can even contain the entire stream contents.
     * Implementations typically verify or parse the trailer here.
     * </p>
     *
     * <p>
     * This method is called from the reading thread either upon the first read that
     * observes upstream EOF or during {@link #close()} if the stream was not fully
     * consumed. It is never called more than once.
     * </p>
     *
     * @param tail the withheld tail bytes (never null; length in [0, tailLen])
     * @throws IOException if processing the tail fails
     */
    protected abstract void processTail(byte[] tail) throws IOException;

    /**
     * Reads and returns a single byte of payload data.
     *
     * <p>
     * This method never returns bytes belonging to the tail. On end of stream,
     * {@code -1} is returned and {@link #processTail(byte[])} is invoked if not
     * already processed.
     * </p>
     *
     * @return the next payload byte (0..255) or {@code -1} if no more payload is
     *         available
     * @throws IOException if an I/O error occurs, if the stream is closed, or if
     *                     tail processing fails
     */
    @Override
    public int read() throws IOException {
        int n = read(oneByte, 0, 1);
        return (n == -1) ? -1 : (oneByte[0] & 0xFF);
    }

    /**
     * Reads up to {@code len} bytes of payload into the provided buffer.
     *
     * <p>
     * The bytes returned exclude the last {@code tailLen} bytes of the upstream
     * stream. When EOF is reached, this method returns {@code -1} and ensures
     * {@link #processTail(byte[])} is invoked exactly once with the withheld tail.
     * If the stream is shorter than {@code tailLen}, this method returns {@code -1}
     * immediately once EOF is known and the entire content is reported via
     * {@code processTail}.
     * </p>
     *
     * @param b   destination buffer; must not be null
     * @param off start offset in {@code b}
     * @param len maximum number of bytes to read
     * @return the number of payload bytes read, or {@code -1} if the payload is
     *         finished
     * @throws NullPointerException      if {@code b} is null
     * @throws IndexOutOfBoundsException if {@code off} or {@code len} are invalid
     *                                   for {@code b}
     * @throws IOException               if an I/O error occurs or if the stream is
     *                                   closed
     */
    // The branches preserve InputStream zero-length, EOF, withheld-tail, and buffered-output semantics.
    @SuppressWarnings("PMD.CyclomaticComplexity")
    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (closed) {
            throw new IOException("stream closed");
        }
        Objects.requireNonNull(b, "b");
        Objects.checkFromIndexSize(off, len, b.length);
        if (len == 0) {
            return 0;
        }

        // If we already have prepared output, serve it first.
        if (emitPos < emitLen) {
            int chunk = Math.min(len, emitLen - emitPos);
            System.arraycopy(window, emitPos, b, off, chunk);
            emitPos += chunk;
            if (emitPos == emitLen) {
                // Emission finished; now it's safe to compact tail to start.
                if (needCompactAfterEmit) { // NOPMD
                    int remaining = accLen - emitLen; // this is the withheld tail (<= tailLen)
                    if (remaining > 0) {
                        System.arraycopy(window, emitLen, window, 0, remaining);
                    }
                    accLen = remaining;
                    emitPos = emitLen = 0;
                    needCompactAfterEmit = false;
                } else {
                    emitPos = emitLen = 0;
                }
            }
            return chunk;
        }

        // Prepare more output if possible.
        while (emitLen == 0) {
            if (upstreamEof) {
                if (!tailProcessed) {
                    // Whatever remains in window are the final tail bytes (<= tailLen).
                    byte[] tail = Arrays.copyOf(window, accLen);

                    if (LOG.isLoggable(Level.FINE)) { // NOPMD
                        LOG.log(Level.FINE, "tail found {0}", Strings.toShortString(tail));
                    }
                    tailProcessed = true;
                    processTail(tail);
                }
                return -1;
            }

            int free = window.length - accLen;
            int n = upstream.read(window, accLen, free);
            if (n == -1) {
                upstreamEof = true;
                // loop again to process tail
                continue;
            }
            accLen += n;

            // If we hold more than tailLen, the overflow is safe to emit.
            if (accLen > tailLen) {
                emitPos = 0;
                emitLen = accLen - tailLen; // bytes to emit now from window[0..emitLen)
                needCompactAfterEmit = true; // compact tail after emission completes
                // Do NOT compact now—would overwrite the bytes we’re about to emit.
                break;
            }
            // else: still not enough to emit (all could be tail); read more.
        }

        // Emit what we prepared (if any).
        if (emitLen > 0) {
            int chunk = Math.min(len, emitLen - emitPos);
            System.arraycopy(window, emitPos, b, off, chunk);
            emitPos += chunk;
            if (emitPos == emitLen) {
                if (needCompactAfterEmit) { // NOPMD
                    int remaining = accLen - emitLen;
                    if (remaining > 0) {
                        System.arraycopy(window, emitLen, window, 0, remaining);
                    }
                    accLen = remaining;
                    emitPos = emitLen = 0;
                    needCompactAfterEmit = false;
                } else {
                    emitPos = emitLen = 0;
                }
            }
            return chunk;
        }

        // Could not prepare any output (short stream < tailLen); read() must
        // block/continue.
        // Since we read at least once above, try again recursively to respect 'len'
        // contract.
        return read(b, off, len);
    }

    /**
     * Closes this stream and the underlying upstream stream.
     *
     * <p>
     * If the upstream has not yet reached EOF, this method drains it to force tail
     * detection and ensures {@link #processTail(byte[])} is invoked exactly once.
     * Subsequent calls are ignored.
     * </p>
     *
     * @throws IOException if an I/O error occurs while draining or closing
     */
    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        try { // NOPMD
            if (!upstreamEof) {
                transferTo(OutputStream.nullOutputStream());
            }
        } finally {
            closed = true;
            upstream.close();
        }
    }

    /**
     * Returns an estimate of the number of bytes that can be read without blocking.
     *
     * <p>
     * This includes any previously prepared payload bytes and the upstream's
     * reported availability. Note that upstream availability may over-report
     * relative to payload because the last {@code tailLen} bytes are withheld.
     * </p>
     *
     * @return the number of bytes that can be read without blocking
     * @throws IOException if an I/O error occurs in the upstream
     */
    @Override
    public int available() throws IOException {
        int ready = emitLen - emitPos;
        int up = upstream.available();
        return ready + up;
    }

    /**
     * Indicates that mark/reset is not supported.
     *
     * @return always {@code false}
     */
    @Override
    public boolean markSupported() {
        return false;
    }

    /**
     * Unsupported operation; always throws.
     *
     * @throws IOException always thrown because mark/reset is not supported
     */
    @Override
    public void reset() throws IOException {
        throw new IOException("mark/reset not supported");
    }

    /**
     * Returns the number of bytes stripped from the end of the stream.
     *
     * @return the configured tail length in bytes
     */
    public int tailLength() {
        return tailLen;
    }
}
