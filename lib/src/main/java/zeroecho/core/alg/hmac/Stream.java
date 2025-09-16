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
package zeroecho.core.alg.hmac;

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Mac;

import zeroecho.core.err.VerificationException;
import zeroecho.core.io.AbstractPassthroughInputStream;
import zeroecho.core.tag.ThrowingBiPredicate.VerificationBiPredicate;
import zeroecho.core.util.Strings;

/**
 * Passthrough input stream that computes or verifies a MAC while bytes are
 * read.
 *
 * <p>
 * The stream forwards all bytes from the wrapped {@link InputStream} unchanged
 * while updating a running {@link javax.crypto.Mac}. Behavior depends on
 * whether an expected tag is provided and on the chosen verification strategy:
 * </p>
 * <ul>
 * <li><b>Produce mode</b> (no expected tag): the computed MAC is emitted once
 * as a trailer via {@link #produceTrailer(byte[])}, after all body bytes have
 * been read.</li>
 * <li><b>Verify mode</b> (with expected tag): no trailer is emitted; at
 * completion the computed MAC is compared to the expected tag using the
 * supplied {@link VerificationBiPredicate}. The strategy may throw, record
 * flags elsewhere, or simply return a boolean, depending on its implementation
 * or decorators.</li>
 * </ul>
 *
 * <h2>Lifecycle</h2>
 * <ul>
 * <li>{@link #update(byte[], int, int)} feeds each pulled chunk to the
 * MAC.</li>
 * <li>{@link #produceTrailer(byte[])} emits the MAC bytes once in produce mode;
 * returns 0 in verify mode.</li>
 * <li>{@link #onCompleted()} finalizes and applies the verification strategy in
 * verify mode.</li>
 * </ul>
 *
 * <h2>Example</h2>
 * <h3>Produce mode: append HMAC-SHA256 as trailer</h3> <pre>
 * {@code
 * Mac mac = Mac.getInstance("HmacSHA256");
 * mac.init(secretKey);
 * try (InputStream in = Files.newInputStream(path);
 *      InputStream s  = new Stream(in, mac, "HmacSHA256", null,
 *                                  new ByteVerificationStrategy())) {
 *     // read from 's' to consume body; trailer is produced automatically
 * }
 * }
 * </pre>
 *
 * <h3>Verify mode: check expected tag and throw on mismatch</h3> <pre>
 * {@code
 * Mac macV = Mac.getInstance("HmacSHA256");
 * macV.init(secretKey);
 * byte[] expected = ...; // received/authenticated out-of-band
 *
 * VerificationBiPredicate<byte[]> strategy =
 *     new ByteVerificationStrategy().getThrowOnMismatch();
 *
 * try (InputStream in = Files.newInputStream(path);
 *      InputStream s  = new Stream(in, macV, "HmacSHA256", expected, strategy)) {
 *     // read from 's'; exception is thrown at EOF if verification fails
 * }
 * }
 * </pre>
 */
final class Stream extends AbstractPassthroughInputStream {
    private static final Logger LOG = Logger.getLogger(Stream.class.getName());

    private final Mac mac;
    private final String macName;
    private byte[] expectedTag;
    private final VerificationBiPredicate<byte[]> verificationStrategy;

    /**
     * Creates a MAC-enabled passthrough stream with an 8192-byte body buffer.
     *
     * <p>
     * If {@code expectedTag} is {@code null}, the instance works in produce mode
     * and will emit the computed MAC as a trailer. Otherwise it works in verify
     * mode and will not emit a trailer; instead it verifies the computed tag at
     * completion by applying {@code verificationStrategy}.
     * </p>
     *
     * @param upstream             source stream to wrap; must not be {@code null}
     * @param mac                  initialized MAC instance updated by the stream;
     *                             must not be {@code null}
     * @param macName              display name used for diagnostics (for example,
     *                             {@code "HmacSHA256"}); must not be {@code null}
     * @param expectedTag          expected MAC bytes for verification; {@code null}
     *                             enables produce mode
     * @param verificationStrategy strategy used in verify mode to compare expected
     *                             and computed tags; must not be {@code null} in
     *                             verify mode
     * @throws NullPointerException if {@code upstream}, {@code mac}, or
     *                              {@code macName} is {@code null}
     */
    /* package */ Stream(final InputStream upstream, final Mac mac, final String macName, final byte[] expectedTag,
            final VerificationBiPredicate<byte[]> verificationStrategy) {
        super(upstream, 8192);
        this.mac = mac;
        this.macName = macName;
        this.expectedTag = expectedTag;
        this.verificationStrategy = verificationStrategy;
    }

    /**
     * Updates the running MAC with the bytes just read from upstream.
     *
     * @param buf buffer containing the read bytes
     * @param off offset in {@code buf}
     * @param len number of valid bytes
     */
    @Override
    protected void update(final byte[] buf, final int off, final int len) {
        mac.update(buf, off, len);
    }

    /**
     * Produces the MAC trailer once in produce mode; emits nothing in verify mode.
     *
     * <p>
     * In produce mode, this method finalizes the MAC, copies it into {@code buf},
     * and returns the number of bytes written. If the finalized tag is empty, zero
     * is returned. In verify mode, this method always returns zero.
     * </p>
     *
     * @param buf destination buffer to receive the trailer
     * @return number of bytes written to {@code buf}, or {@code 0} if no trailer is
     *         emitted
     * @throws IOException if {@code Mac#doFinal()} fails or the tag does not fit
     *                     {@code buf}
     */
    @Override
    protected int produceTrailer(byte[] buf) throws IOException {
        if (expectedTag != null) {
            // Verify mode: trailer is never emitted.
            return 0;
        }
        final byte[] tag;
        try {
            tag = mac.doFinal();
        } catch (RuntimeException ex) { // NOPMD
            throw new IOException("HMAC finalize failed (" + macName + ")", ex);
        }
        if (tag.length == 0) {
            return 0;
        }
        if (tag.length > buf.length) {
            throw new IOException("Trailer does not fit into buffer");
        }
        System.arraycopy(tag, 0, buf, 0, tag.length);
        return tag.length;
    }

    /**
     * Finalizes the MAC and applies the verification strategy in verify mode.
     *
     * <p>
     * When {@code expectedTag} is non-null, this method computes {@code doFinal()},
     * compares it to {@code expectedTag} using {@code verificationStrategy}, and
     * propagates any strategy-defined signaling (for example, throwing on
     * mismatch). In produce mode, the method returns immediately.
     * </p>
     *
     * @throws IOException if the verification strategy signals a failure (for
     *                     example, via {@link VerificationException})
     */
    @Override
    protected void onCompleted() throws IOException {
        if (expectedTag == null) {
            // Produce mode: nothing to verify.
            return;
        }
        try {
            final byte[] out = mac.doFinal();
            verificationStrategy.verify(expectedTag, out);
        } catch (VerificationException e) {
            throw new IOException(e);
        }
    }

    /**
     * Sets or replaces the expected tag for subsequent verification.
     *
     * <p>
     * If called in produce mode, this switches the instance to verify mode for the
     * remainder of the stream.
     * </p>
     *
     * @param expectedTag the expected MAC bytes; may be {@code null} to clear
     */
    /* package */ void setExpectedTag(byte[] expectedTag) {
        if (LOG.isLoggable(Level.FINE)) {
            LOG.log(Level.FINE, "resetting expectedTag to {0}", Strings.toShortString(expectedTag));
        }

        this.expectedTag = expectedTag;
    }
}
