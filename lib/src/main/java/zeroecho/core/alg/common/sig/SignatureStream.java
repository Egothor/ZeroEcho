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
package zeroecho.core.alg.common.sig;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.err.VerificationException;
import zeroecho.core.io.AbstractPassthroughInputStream;
import zeroecho.core.tag.ThrowingBiPredicate.VerificationBiPredicate;
import zeroecho.core.util.Strings;

/**
 * Passthrough stream that feeds a {@link java.security.Signature} for streaming
 * sign or verify.
 *
 * <p>
 * All bytes read from the wrapped upstream are forwarded unchanged to the
 * caller and are also passed to the signature engine via
 * {@link Signature#update(byte[], int, int)}. At EOF the behavior depends on
 * mode:
 * </p>
 * <ul>
 * <li><b>Sign mode</b>: compute the signature once via {@link Signature#sign()}
 * and append it as a trailer by returning it from
 * {@link #produceTrailer(byte[])}.</li>
 * <li><b>Verify mode</b>: compute and compare the signature at completion using
 * the provided {@link VerificationBiPredicate}, surfacing the result according
 * to that strategy.</li>
 * </ul>
 *
 * <h2>Lifecycle</h2>
 * <ul>
 * <li>{@link #update(byte[], int, int)} - feed each chunk into the engine.</li>
 * <li>{@link #produceTrailer(byte[])} - sign mode only: emit the computed
 * signature once; verify mode: return 0 (no trailer).</li>
 * <li>{@link #onCompleted()} - verify mode only: invoke the verification
 * strategy and translate any {@link VerificationException} to
 * {@link java.io.IOException}.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Not thread-safe. Bound to a single {@link java.security.Signature} engine and
 * upstream stream.
 * </p>
 */
final class SignatureStream extends AbstractPassthroughInputStream {
    private static final Logger LOG = Logger.getLogger(SignatureStream.class.getName());

    /** Cached trailer in sign mode: computed once from {@link Signature#sign()}. */
    private byte[] signature;
    /** Underlying JCA signature engine used for streaming updates. */
    private final Signature engine;
    /** True if this stream signs, false if it verifies. */
    private final boolean signMode;
    /** Expected signature to verify against (verify mode only). */
    private byte[] expectedTag;
    /** Verification strategy controlling how results are surfaced. */
    private final VerificationBiPredicate<Signature> strategy;

    /**
     * Creates a streaming signature passthrough.
     *
     * @param engine      initialized {@link Signature} engine; must not be
     *                    {@code null}
     * @param signMode    {@code true} for signing, {@code false} for verifying
     * @param upstream    upstream input to wrap; must not be {@code null}
     * @param bodyBufSize body buffer size for passthrough
     * @param expectedTag expected signature in verify mode; may be {@code null} to
     *                    disable verification
     * @param strategy    verification predicate used in verify mode; ignored in
     *                    sign mode; must not be {@code null} in verify mode
     */
    /* package */ SignatureStream(final Signature engine, final boolean signMode, final InputStream upstream,
            final int bodyBufSize, final byte[] expectedTag, final VerificationBiPredicate<Signature> strategy) {
        super(upstream, bodyBufSize);
        this.engine = engine;
        this.signMode = signMode;
        this.expectedTag = expectedTag;
        this.strategy = strategy;
    }

    /**
     * Feeds a chunk of bytes into the underlying signature engine.
     *
     * @param buf input buffer
     * @param off start offset within {@code buf}
     * @param len number of bytes to process
     * @throws IOException if {@link Signature#update(byte[], int, int)} fails
     */
    @Override
    protected void update(final byte[] buf, final int off, final int len) throws IOException {
        try {
            LOG.log(Level.FINEST, "update with {0} bytes block", len);

            engine.update(buf, off, len);
        } catch (SignatureException e) {
            throw new IOException("Signature.update failed", e);
        }
    }

    /**
     * Emits the signature trailer exactly once in sign mode; emits nothing in
     * verify mode.
     *
     * <p>
     * In sign mode this computes the signature if needed, copies it to {@code buf},
     * and returns its length. If the signature does not fit, an {@link IOException}
     * is thrown. In verify mode the method returns {@code 0}.
     * </p>
     *
     * @param buf destination buffer
     * @return number of bytes written, or {@code 0} if no trailer is emitted
     * @throws IOException if signature computation fails or the trailer does not
     *                     fit in {@code buf}
     */
    @Override
    protected int produceTrailer(byte[] buf) throws IOException {
        LOG.log(Level.FINE, "trailer (length={0}) production started", buf.length);

        if (!signMode) {
            LOG.log(Level.FINE, "signature will not be appended to the stream: not in the signing mode");
            return 0; // VERIFY mode never emits a trailer
        }

        if (signature == null) {
            try {
                signature = engine.sign();
            } catch (GeneralSecurityException e) {
                throw new IOException("Signature finalize failed", e);
            }
        }
        if (LOG.isLoggable(Level.FINE)) {
            LOG.log(Level.FINE, "signature produced: length={0} signature={1}",
                    new Object[] { signature.length, Strings.toShortString(signature) });
        }

        if (signature.length == 0) {
            return 0;
        }
        if (signature.length > buf.length) {
            throw new IOException(
                    "Trailer does not fit into buffer have: " + buf.length + " but need: " + signature.length);
        }
        System.arraycopy(signature, 0, buf, 0, signature.length);
        return signature.length;
    }

    /**
     * Finalizes verification on stream completion (verify mode only).
     *
     * <p>
     * Compares the computed signature against {@code expectedTag} using
     * {@link #strategy}. Any {@link VerificationException} raised by the strategy
     * is translated to {@link IOException}. In sign mode this method does nothing.
     * </p>
     *
     * @throws IOException if the verification strategy signals failure
     */
    @Override
    protected void onCompleted() throws IOException {
        if (signMode) {
            LOG.log(Level.FINE, "Signature verification is not executed during signing");
            return; // nothing to do for signing
        }
        try {
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "verification {0}", Strings.toShortString(expectedTag));
            }
            strategy.verify(engine, expectedTag);
        } catch (VerificationException e) {
            throw new IOException(e);
        }
    }

    /**
     * Replaces the expected verification tag.
     *
     * @param expectedTag new expected tag; may be {@code null} to clear
     */
    /* default */ void setExpectedTag(byte[] expectedTag) {
        if (LOG.isLoggable(Level.FINE)) {
            LOG.log(Level.FINE, "resetting expectedTag to {0}", Strings.toShortString(expectedTag));
        }
        this.expectedTag = expectedTag;
    }
}
