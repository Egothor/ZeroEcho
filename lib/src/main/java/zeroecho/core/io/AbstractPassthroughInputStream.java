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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

/**
 * Passthrough {@link InputStream} that forwards body bytes and optionally emits
 * a trailer at EOF.
 *
 * <p>
 * This abstract helper implements a two-phase read pipeline suitable for
 * tag-producing or verifying stages. During the BODY phase, bytes are pulled
 * from the wrapped upstream stream and immediately exposed to the caller while
 * {@link #update(byte[], int, int)} is invoked so subclasses can maintain
 * running state (for example, hash, MAC, or signature update). After upstream
 * EOF, the TRAILER phase runs once: {@link #produceTrailer(byte[])} may write a
 * finite trailer into an internal buffer, and {@link #onCompleted()} is called
 * exactly once.
 * </p>
 *
 * <h2>Phases</h2>
 * <ul>
 * <li><b>BODY</b>: bytes are read from {@link #in}, passed through to the
 * caller, and fed to {@link #update(byte[], int, int)}.</li>
 * <li><b>TRAILER</b>: after EOF from upstream, {@link #produceTrailer(byte[])}
 * is invoked once to optionally emit a trailer; then {@link #onCompleted()} is
 * called and the stream becomes exhausted.</li>
 * </ul>
 *
 * <h2>Subclassing contract</h2>
 * <ul>
 * <li>{@link #update(byte[], int, int)} must be side-effect free with respect
 * to the bytes already returned to the caller; it is for state maintenance
 * only.</li>
 * <li>{@link #produceTrailer(byte[])} must write at most {@code buf.length}
 * bytes and return the count, or return {@code 0} to produce no trailer. If
 * more space is required, it must throw {@link IOException}.</li>
 * <li>{@link #onCompleted()} is invoked exactly once after
 * {@code produceTrailer} returns, regardless of whether a trailer was produced;
 * it should release resources and may perform final checks. It must not attempt
 * to emit more bytes.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances are not thread-safe. Use a separate instance per stream pipeline.
 * </p>
 *
 * <h2>Example</h2> <pre>
 * {@code
 * final class DigestingStream extends AbstractPassthroughInputStream {
 *     private final MessageDigest md;
 *     DigestingStream(InputStream upstream, MessageDigest md) {
 *         super(upstream, 8192);
 *         this.md = md;
 *     }
 *     &#64;Override protected void update(byte[] buf, int off, int len) { md.update(buf, off, len); }
 *     &#64;Override protected int produceTrailer(byte[] buf) {
 *         byte[] tag = md.digest();
 *         System.arraycopy(tag, 0, buf, 0, tag.length);
 *         return tag.length; // append digest at EOF
 *     }
 *     &#64;Override protected void onCompleted() { /* publish metrics, close resources, etc. *\/ }
 * }
 * }
 * </pre>
 */
public abstract class AbstractPassthroughInputStream extends FilterInputStream {
    /**
     * Scratch buffer used to read from {@link #in}. Also used once to hold the
     * trailer, if any.
     */
    protected final byte[] inBuf;
    /**
     * Current read position within the buffered output window {@link #outBuf()}
     * (modeled by {@link #inBuf}).
     */
    private int outPos;
    /**
     * Number of valid bytes currently buffered for output within {@link #inBuf}.
     */
    private int outLen;

    /**
     * True once EOF was observed on the upstream stream.
     */
    private boolean eofSeen;
    /**
     * True once the trailer producer has completed (whether or not a trailer was
     * emitted).
     */
    private boolean trailerDone;

    /**
     * Constructs a new passthrough stream with an internal buffer sized for body
     * reads.
     *
     * <p>
     * The buffer is allocated as the maximum of {@code 1024} and the requested
     * {@code bodyBufSize}, ensuring a reasonable minimum size even if the caller
     * specifies a very small value. The buffer is reused both for normal body reads
     * and, if applicable, for the single trailer emission.
     * </p>
     *
     * @param upstream    source input stream to wrap
     * @param bodyBufSize requested size of the body buffer, in bytes
     * @throws NullPointerException if {@code upstream} is {@code null}
     */
    protected AbstractPassthroughInputStream(InputStream upstream, int bodyBufSize) {
        super(upstream);
        this.inBuf = new byte[Math.max(1024, bodyBufSize)];
        this.outPos = 0;
        this.outLen = 0;
    }

    /**
     * Called for each body chunk just read from the upstream.
     *
     * <p>
     * Implementations may update running state (e.g., hash or MAC) using the bytes
     * in {@code buf[off..off+len)}. Implementations must not modify the visible
     * output of the current chunk.
     * </p>
     *
     * @param buf buffer containing the newly read bytes
     * @param off start offset
     * @param len number of bytes read
     * @throws IOException if processing the chunk fails
     */
    protected abstract void update(byte[] buf, int off, int len) throws IOException;

    /**
     * Produces an optional trailer after upstream EOF.
     *
     * <p>
     * This method is called at most once, after the BODY phase has ended.
     * Implementations should write the trailer bytes (if any) into the provided
     * buffer and return the number of bytes written. A return value of 0 means no
     * trailer will be emitted.
     * </p>
     *
     * <p>
     * <b>Contract:</b> This method must be side-effect free with respect to
     * subsequent reads; it is followed immediately by a call to
     * {@link #onCompleted()}. If a trailer cannot fit into {@code buf},
     * implementations should throw {@link IOException} to avoid truncation.
     * </p>
     *
     * @param buf destination buffer to receive the trailer
     * @return number of bytes written to {@code buf}; 0 to emit no trailer
     * @throws IOException if trailer production fails or the trailer does not fit
     *                     into {@code buf}
     */
    protected abstract int produceTrailer(byte[] buf) throws IOException;

    /**
     * Notifies that the stream has fully completed.
     *
     * <p>
     * This method is invoked exactly once, immediately after
     * {@link #produceTrailer(byte[])} returns, regardless of whether a trailer was
     * produced. Implementations typically perform final verification, publish
     * flags, and/or release resources here. This method should be idempotent and
     * must not attempt to write further bytes.
     * </p>
     *
     * @throws IOException if final verification or resource release fails
     */
    protected abstract void onCompleted() throws IOException;

    private boolean ensureData() throws IOException {
        while (outPos >= outLen) {
            if (!eofSeen) { // NOPMD
                // BODY phase: read from upstream
                int n = in.readNBytes(inBuf, 0, inBuf.length);
                if (n <= 0) {
                    eofSeen = true;
                    outPos = 0;
                    outLen = 0; // fall through to trailer production below
                } else {
                    update(inBuf, 0, n);
                    outPos = 0;
                    outLen = n;
                    if (outLen > 0) {
                        return true;
                    }
                    // zero-length read should not happen for positive n, but keep the loop safe
                }
            } else {
                // TRAILER phase: keep asking until it returns 0
                if (trailerDone) {
                    return false;
                }
                int trailerLen = produceTrailer(inBuf);
                trailerDone = true; // produceTrailer can be asked just once
                onCompleted();
                if (trailerLen <= 0) {
                    return false;
                }
                outPos = 0;
                outLen = trailerLen;
                return true;
            }
        }
        return true;
    }

    /**
     * Reads the next byte from this stream.
     *
     * @return next byte as an unsigned int (0..255), or -1 if no more data is
     *         available
     * @throws IOException if an I/O error occurs
     */
    @Override
    public int read() throws IOException {
        if (!ensureData()) {
            return -1;
        }
        return inBuf[outPos++] & 0xFF;
    }

    /**
     * Reads some bytes from this stream into the specified array.
     *
     * @param b   target buffer; must not be null
     * @param off start offset within {@code b}
     * @param len maximum number of bytes to read
     * @return number of bytes read, or -1 if end-of-stream is reached
     * @throws IOException               if an I/O error occurs
     * @throws NullPointerException      if {@code b} is null
     * @throws IndexOutOfBoundsException if {@code off} or {@code len} are invalid
     *                                   for {@code b}
     */
    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        Objects.checkFromIndexSize(off, len, b.length);

        if (len == 0) {
            return 0;
        }
        if (!ensureData()) {
            return -1;
        }
        int n = Math.min(len, outLen - outPos);
        System.arraycopy(inBuf, outPos, b, off, n);
        outPos += n;
        return n;
    }

    /**
     * Drains remaining data (including any trailer) and then closes the upstream
     * stream.
     *
     * <p>
     * This method transfers all remaining bytes to
     * {@link OutputStream#nullOutputStream()}, which guarantees that the trailer
     * (if any) is produced and {@link #onCompleted()} is invoked, and finally calls
     * {@code super.close()}.
     * </p>
     *
     * @throws IOException if an I/O error occurs while draining or closing
     */
    @Override
    public void close() throws IOException {
        transferTo(OutputStream.nullOutputStream());
        super.close();
    }
}
