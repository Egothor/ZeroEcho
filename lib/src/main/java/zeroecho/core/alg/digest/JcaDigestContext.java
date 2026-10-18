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
package zeroecho.core.alg.digest;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.DigestContext;
import zeroecho.core.err.VerificationException;
import zeroecho.core.io.AbstractPassthroughInputStream;
import zeroecho.core.tag.ByteVerificationStrategy;
import zeroecho.core.tag.TagEngine;
import zeroecho.core.tag.ThrowingBiPredicate;
import zeroecho.core.tag.ThrowingBiPredicate.VerificationBiPredicate;

/**
 * Digest context that adapts a JCA {@link java.security.MessageDigest} to a
 * pull-based streaming pipeline.
 *
 * <p>
 * {@code JcaDigestContext} implements {@link DigestContext} for
 * {@link Sha2Sha3Algorithm} by delegating to a JCA
 * {@link java.security.MessageDigest} and exposing the {@link TagEngine}
 * contract. As data is read from the wrapped stream the digest state is
 * updated; at end-of-stream the digest is finalized and either appended as a
 * trailer (produce mode) or compared against an expected tag (verify mode).
 * </p>
 *
 * <h2>Features</h2>
 * <ul>
 * <li>Supports SHA-2, SHA-3, and SHAKE digests as defined by
 * {@link DigestSpec}.</li>
 * <li>Provides pull-stream semantics via
 * {@link #wrap(java.io.InputStream)}.</li>
 * <li>Two modes:
 * <ul>
 * <li><b>Produce mode</b>: appends the computed digest as a trailer.</li>
 * <li><b>Verify mode</b>: computes the digest and compares it to an expected
 * tag using a pluggable verification approach (see
 * {@link #setVerificationApproach(ThrowingBiPredicate.VerificationBiPredicate)}).</li>
 * </ul>
 * </li>
 * <li>For XOFs (SHAKE), the output length is explicitly controlled by
 * {@link DigestSpec}.</li>
 * </ul>
 *
 * <h2>Verification approach</h2>
 * <p>
 * Verification is delegated to a
 * {@link ThrowingBiPredicate.VerificationBiPredicate} over {@code byte[]}. The
 * default core returned by {@link #getVerificationCore()} performs
 * constant-time byte comparison ({@link ByteVerificationStrategy}). If no
 * strategy is set explicitly, the effective verifier defaults to
 * {@code getVerificationCore().getThrowOnMismatch()}, causing a mismatch to be
 * signaled as an I/O error at end-of-stream.
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances are stateful and not thread-safe. Each context may wrap exactly one
 * stream; subsequent calls to {@link #wrap(java.io.InputStream)} are rejected.
 * </p>
 *
 * @since 1.0
 */
public final class JcaDigestContext implements DigestContext {
    private static final Logger LOG = Logger.getLogger(JcaDigestContext.class.getName());

    /** Algorithm descriptor that owns this context. */
    private final CryptoAlgorithm algorithm;
    /** JCA message digest engine used for computation. */
    private final MessageDigest md; // NOPMD
    /** Digest parameters (algorithm choice, output length for XOFs). */
    private final DigestSpec spec;
    /** JCA algorithm name string, cached for diagnostics. */
    private final String algorithmName;

    /** Trailer length in bytes (digest size or requested XOF length). */
    private final int outLen;

    /** Whether this context is operating in verification mode. */
    private boolean verifyMode; // = false;
    /** Expected digest/tag value provided by caller. */
    private byte[] expectedTag;
    /** Verification failure handling policy. */
    private VerificationBiPredicate<byte[]> strategy;

    /** Whether {@link #wrap(InputStream)} has already been called. */
    private boolean wrapped; // = false;
    /** Active digesting stream, if {@link #wrap(InputStream)} was invoked. */
    private Stream activeStream;
    private boolean autoCloseActiveStream;

    /**
     * Creates a new digest context bound to a JCA {@link MessageDigest}.
     *
     * <p>
     * This constructor is normally invoked by {@link Sha2Sha3Algorithm}:
     * </p>
     *
     * <pre>{@code
     * MessageDigest md = MessageDigest.getInstance(spec.algorithm().jca());
     * return new JcaDigestContext(algo, md, spec);
     * }</pre>
     *
     * @param algorithm the owning algorithm descriptor
     * @param md        JCA message digest implementation
     * @param spec      digest parameters (algorithm, output length for XOFs)
     * @throws NullPointerException     if any parameter is null
     * @throws IllegalArgumentException if the output length for an XOF is invalid
     */
    public JcaDigestContext(final CryptoAlgorithm algorithm, final MessageDigest md, final DigestSpec spec) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.md = Objects.requireNonNull(md, "md");
        this.spec = Objects.requireNonNull(spec, "spec");
        this.algorithmName = md.getAlgorithm();
        this.outLen = resolveOutputLength(md, spec);
    }

    /**
     * Returns the {@link CryptoAlgorithm} definition that created this context.
     *
     * @return algorithm descriptor
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the key associated with this context.
     *
     * <p>
     * Digests are unkeyed; this method always returns {@code null}.
     * </p>
     *
     * @return always {@code null}
     */
    @Override
    public java.security.Key key() {
        return null; // digest is keyless
    }

    /**
     * Closes the active digest stream if one was opened.
     *
     * <p>
     * The close operation is non-throwing; any underlying {@link IOException} is
     * suppressed to preserve pipeline robustness.
     * </p>
     */
    @Override
    public void close() {
        LOG.log(Level.INFO, "close()");

        if (autoCloseActiveStream) {
            try {
                if (activeStream != null) {
                    activeStream.close();
                }
            } catch (IOException ignore) {
                LOG.log(Level.INFO, "exception ignored on close", ignore);
            }
        }
    }

    /**
     * Wraps an upstream {@link InputStream} in a digesting pipeline stage.
     *
     * <p>
     * Data read from the returned stream is passed through unchanged while being
     * accumulated into the underlying {@link MessageDigest}. At end-of-stream the
     * digest is finalized and either emitted as a trailer (produce mode) or
     * compared to the expected tag (verify mode).
     * </p>
     *
     * <p>
     * This method may be called at most once per context instance.
     * </p>
     *
     * @param upstream the input stream to wrap; must not be {@code null}
     * @return a stream that transparently digests data
     * @throws IOException           if stream initialization fails
     * @throws IllegalStateException if {@code wrap} was already invoked on this
     *                               instance
     * @throws NullPointerException  if {@code upstream} is {@code null}
     */
    @Override
    public InputStream wrap(final InputStream upstream) throws IOException {
        Objects.requireNonNull(upstream, "upstream");
        if (wrapped) {
            throw new IllegalStateException(
                    "This JcaDigestContext instance was already used; create a new one per stream.");
        }
        wrapped = true;

        md.reset();

        Stream s = new Stream(upstream);
        this.activeStream = s;
        return s;
    }

    /**
     * Returns the digest length in bytes.
     *
     * @return output length of the digest or XOF
     */
    @Override
    public int tagLength() {
        return outLen;
    }

    /**
     * Installs an expected digest tag for verification mode.
     *
     * <p>
     * When provided, the context operates in verification mode: at end-of-stream
     * the computed digest is compared against this tag using the effective
     * verification strategy. Passing {@code null} clears the tag and leaves the
     * mode unchanged.
     * </p>
     *
     * @param expected expected digest bytes; copied defensively (may be
     *                 {@code null} to clear)
     */
    @Override
    public void setExpectedTag(final byte[] expected) {
        this.expectedTag = (expected == null) ? null : Arrays.copyOf(expected, expected.length);
        this.verifyMode = true;
    }

    /**
     * Internal pass-through stream that updates the digest as data flows and
     * finalizes at EOF.
     *
     * <p>
     * In produce mode, the finalized digest is emitted as a trailer. In verify
     * mode, the finalized digest is compared to the expected tag using the
     * configured verification strategy.
     * </p>
     */
    private final class Stream extends AbstractPassthroughInputStream {
        /** Produce mode: cached digest to emit as a trailer. */
        private byte[] trailer; // NOPMD

        /**
         * Creates a new digesting stream.
         *
         * @param upstream underlying input stream to wrap
         */
        private Stream(final InputStream upstream) {
            super(upstream, 8192);
        }

        /**
         * Updates the digest with newly read bytes.
         *
         * @param buf buffer containing input
         * @param off offset into buffer
         * @param len number of bytes to process
         */
        @Override
        protected void update(final byte[] buf, final int off, final int len) {
            md.update(buf, off, len);
        }

        /**
         * Produces the digest trailer once in produce mode; emits nothing in verify
         * mode.
         *
         * <p>
         * In produce mode this finalizes the digest and copies it into {@code buf}. For
         * XOFs or when the provider's reported digest length differs from the
         * configured output length, exactly {@code outLen} bytes are requested. In
         * verify mode the method returns {@code 0}.
         * </p>
         *
         * @param buf destination buffer to receive the trailer
         * @return number of bytes written, or {@code 0} if no trailer is emitted
         * @throws IOException if digest finalization fails or the trailer does not fit
         *                     in {@code buf}
         */
        @Override
        protected int produceTrailer(byte[] buf) throws IOException {
            if (verifyMode) {
                return 0; // verification path handled in onCompleted()
            }

            // Compute the digest output once for trailer emission.
            final byte[] out;
            try {
                // For XOFs or unknown/size-mismatch digests, request exactly outLen bytes into
                // a fresh array.
                if (spec.algorithm().isXof() || md.getDigestLength() == 0 || md.getDigestLength() != outLen) {
                    out = new byte[outLen];
                    md.digest(out, 0, outLen);
                } else {
                    out = md.digest();
                }
            } catch (java.security.DigestException e) {
                throw new IOException("Digest finalize failed (" + algorithmName + ")", e);
            }

            trailer = out;
            if (trailer.length == 0) {
                return 0;
            }
            if (trailer.length > buf.length) {
                throw new IOException("Trailer does not fit into buffer");
            }
            System.arraycopy(trailer, 0, buf, 0, trailer.length);
            return trailer.length;
        }

        /**
         * Completes verification in verify mode; no-op in produce mode.
         *
         * <p>
         * Finalizes the digest and compares it to {@code expectedTag} using the
         * configured verification strategy. Any {@link VerificationException} is
         * translated to {@link IOException}.
         * </p>
         *
         * @throws IOException if verification fails and the strategy signals failure
         */
        @Override
        protected void onCompleted() throws IOException {
            if (!verifyMode) {
                return; // nothing to do for produce mode; trailer already emitted (if any)
            }
            try {
                // Compute the digest output for verification.
                final byte[] out;
                if (spec.algorithm().isXof() || md.getDigestLength() == 0 || md.getDigestLength() != outLen) {
                    out = new byte[outLen];
                    md.digest(out, 0, outLen);
                } else {
                    out = md.digest();
                }

                strategy.verify(expectedTag, out);
            } catch (java.security.DigestException e) {
                throw new IllegalStateException("Digest finalize failed (" + algorithmName + ")", e);
            } catch (VerificationException e) {
                throw new IOException(e);
            }
        }
    }

    /**
     * Resolves the digest output length for the given algorithm.
     *
     * <p>
     * For XOFs, uses the explicit length from {@link DigestSpec}. For fixed-length
     * digests, queries the provider via {@link MessageDigest#getDigestLength()}.
     * Falls back to the hint in {@link DigestSpec} or 32 bytes if the provider
     * reports zero.
     * </p>
     *
     * @param md   JCA message digest; must not be {@code null}
     * @param spec digest specification; must not be {@code null}
     * @return output length in bytes
     * @throws IllegalArgumentException if an XOF output length is non-positive
     */
    private static int resolveOutputLength(final MessageDigest md, final DigestSpec spec) {
        Objects.requireNonNull(md, "md");
        Objects.requireNonNull(spec, "spec");
        if (spec.algorithm().isXof()) {
            int out = spec.outputLenBytes();
            if (out < 1) { // NOPMD
                throw new IllegalArgumentException("XOF requires positive output length");
            }
            return out;
        }
        int dl = md.getDigestLength();
        if (dl > 0) {
            return dl;
        }
        int hinted = spec.outputLenBytes();
        return hinted > 0 ? hinted : 32; // conservative default if provider doesn't report length
    }

    /**
     * Sets the verification approach used to compare computed and expected digests.
     *
     * <p>
     * If no strategy is set explicitly, the effective verifier defaults to
     * {@code getVerificationCore().getThrowOnMismatch()}.
     * </p>
     *
     * @param strategy verification predicate; may be {@code null} to keep the
     *                 default behavior
     */
    @Override
    public void setVerificationApproach(VerificationBiPredicate<byte[]> strategy) {
        this.strategy = strategy;
    }

    /**
     * Returns the core verification predicate for digest tags.
     *
     * <p>
     * The default core is a constant-time byte-array comparison implemented by
     * {@link ByteVerificationStrategy}.
     * </p>
     *
     * @return base verification predicate (never {@code null})
     */
    @Override
    public VerificationBiPredicate<byte[]> getVerificationCore() {
        return new ByteVerificationStrategy();
    }
}
