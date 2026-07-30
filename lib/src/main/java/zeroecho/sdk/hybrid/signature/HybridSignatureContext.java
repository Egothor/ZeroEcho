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
package zeroecho.sdk.hybrid.signature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.err.VerificationException;
import zeroecho.core.io.TailStrippingInputStream;
import zeroecho.core.spec.ContextSpec;
import zeroecho.core.tag.ThrowingBiPredicate.VerificationBiPredicate;
import zeroecho.sdk.ZeroEchoSession;

/**
 * Package-private {@link SignatureContext} that composes two signature engines.
 *
 * <p>
 * The signature trailer is {@code sigClassic || sigPqc} in the fixed order
 * defined by the {@link HybridSignatureProfile}. The trailer carries no
 * algorithm identifiers; the profile is the source of truth.
 * </p>
 *
 * <h3>Streaming semantics</h3>
 * <p>
 * This context is compatible with the existing ZeroEcho signing/verification
 * pipelines: callers wrap an {@link InputStream} and read until EOF. At EOF,
 * the underlying engines produce/verify the trailer.
 * </p>
 *
 * <p>
 * Implementation note: the wrapper buffers the message body and runs the
 * component engines at EOF. This avoids any need for changes in core contracts
 * while keeping the same external streaming behavior.
 * </p>
 *
 * <h3>Verification aggregation</h3>
 * <p>
 * Verification is performed for both component signatures and aggregated by the
 * profile rule (AND / OR). The final decision is applied via this context's
 * {@link #setVerificationApproach(VerificationBiPredicate)} predicate, enabling
 * the standard ZeroEcho behavior (throw-on-mismatch, flagging, etc.).
 * </p>
 *
 * @since 1.0
 */
final class HybridSignatureContext implements SignatureContext {

    private final ZeroEchoSession session;
    private final HybridSignatureProfile profile;

    private final boolean produceMode;
    private final PrivateKey classicPrivate;
    private final PrivateKey pqcPrivate;
    private final PublicKey classicPublic;
    private final PublicKey pqcPublic;

    private final int maxBufferedBytes;

    private final AtomicBoolean lastOk;
    private final VerificationBiPredicate<Signature> hybridCore;

    private VerificationBiPredicate<Signature> verificationApproach;
    private byte[] expectedTag;

    /**
     * Creates a signing hybrid signature context.
     *
     * @param profile          hybrid signature profile
     * @param classicPrivate   private key for classical engine
     * @param pqcPrivate       private key for PQC engine
     * @param maxBufferedBytes maximum buffered bytes (DoS guard)
     * @throws NullPointerException     if {@code profile}, {@code classicPrivate},
     *                                  or {@code pqcPrivate} is {@code null}
     * @throws IllegalArgumentException if {@code maxBufferedBytes <= 0}
     */
    /* default */ HybridSignatureContext(ZeroEchoSession session, HybridSignatureProfile profile,
            PrivateKey classicPrivate, PrivateKey pqcPrivate, int maxBufferedBytes) {
        this.session = Objects.requireNonNull(session, "session");
        this.profile = Objects.requireNonNull(profile, "profile");
        this.classicPrivate = Objects.requireNonNull(classicPrivate, "classicPrivate");
        this.pqcPrivate = Objects.requireNonNull(pqcPrivate, "pqcPrivate");
        this.classicPublic = null;
        this.pqcPublic = null;
        this.produceMode = true;

        if (maxBufferedBytes <= 0) {
            throw new IllegalArgumentException("maxBufferedBytes must be positive");
        }
        this.maxBufferedBytes = maxBufferedBytes;

        this.lastOk = new AtomicBoolean(false);
        this.hybridCore = new HybridCorePredicate(this.lastOk);
        this.verificationApproach = this.hybridCore;
        this.expectedTag = null;
    }

    /**
     * Creates a verifying hybrid signature context.
     *
     * @param profile          hybrid signature profile
     * @param classicPublic    public key for classical engine
     * @param pqcPublic        public key for PQC engine
     * @param maxBufferedBytes maximum buffered bytes (DoS guard)
     * @throws NullPointerException     if {@code profile}, {@code classicPublic},
     *                                  or {@code pqcPublic} is {@code null}
     * @throws IllegalArgumentException if {@code maxBufferedBytes <= 0}
     */
    /* default */ HybridSignatureContext(ZeroEchoSession session, HybridSignatureProfile profile,
            PublicKey classicPublic, PublicKey pqcPublic, int maxBufferedBytes) {
        this.session = Objects.requireNonNull(session, "session");
        this.profile = Objects.requireNonNull(profile, "profile");
        this.classicPublic = Objects.requireNonNull(classicPublic, "classicPublic");
        this.pqcPublic = Objects.requireNonNull(pqcPublic, "pqcPublic");
        this.classicPrivate = null;
        this.pqcPrivate = null;
        this.produceMode = false;

        if (maxBufferedBytes <= 0) {
            throw new IllegalArgumentException("maxBufferedBytes must be positive");
        }
        this.maxBufferedBytes = maxBufferedBytes;

        this.lastOk = new AtomicBoolean(false);
        this.hybridCore = new HybridCorePredicate(this.lastOk);
        this.verificationApproach = this.hybridCore;
        this.expectedTag = null;
    }

    @Override
    public InputStream wrap(InputStream upstream) throws IOException {
        Objects.requireNonNull(upstream, "upstream");
        return new HybridStream(upstream);
    }

    @Override
    public int tagLength() {
        try (SignatureContext classic = createClassic(produceMode ? KeyUsage.SIGN : KeyUsage.VERIFY);
                SignatureContext pqc = createPqc(produceMode ? KeyUsage.SIGN : KeyUsage.VERIFY)) {
            return classic.tagLength() + pqc.tagLength();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to determine hybrid tag length", e);
        }
    }

    @Override
    public void setExpectedTag(byte[] expected) {
        if (produceMode) {
            throw new UnsupportedOperationException("Expected tag is not used in sign mode");
        }
        Objects.requireNonNull(expected, "expected");
        this.expectedTag = expected.clone();
    }

    @Override
    public void setVerificationApproach(VerificationBiPredicate<Signature> approach) {
        this.verificationApproach = Objects.requireNonNull(approach, "approach");
    }

    @Override
    public VerificationBiPredicate<Signature> getVerificationCore() {
        return hybridCore;
    }

    @Override
    public CryptoAlgorithm algorithm() {
        return CryptoAlgorithms.require(profile.classicSigId());
    }

    @Override
    public Key key() {
        return produceMode ? classicPrivate : classicPublic;
    }

    @Override
    public void close() {
        // Stateless at context level; per-stream resources are closed by the stream.
    }

    private SignatureContext createClassic(KeyUsage usage) throws IOException {
        ContextSpec spec = profile.classicSpec();
        if (usage == KeyUsage.SIGN) {
            return session.createContext(profile.classicSigId(), usage, classicPrivate, spec);
        }
        return session.createContext(profile.classicSigId(), usage, classicPublic, spec);
    }

    private SignatureContext createPqc(KeyUsage usage) throws IOException {
        ContextSpec spec = profile.pqcSpec();
        if (usage == KeyUsage.SIGN) {
            return session.createContext(profile.pqcSigId(), usage, pqcPrivate, spec);
        }
        return session.createContext(profile.pqcSigId(), usage, pqcPublic, spec);
    }

    /**
     * Internal {@link InputStream} wrapper that transparently appends or validates
     * a hybrid-signature trailer at end-of-stream.
     *
     * <p>
     * The stream proxies reads from an underlying upstream {@link InputStream}.
     * While reading, it buffers the payload body (bounded by
     * {@code maxBufferedBytes}) to enable hybrid signature processing at EOF:
     * </p>
     *
     * <ul>
     * <li><b>Produce mode</b> ({@code produceMode == true}): on upstream EOF, two
     * signatures are computed (classic + PQC) over the buffered body and then
     * emitted as a trailer appended to the stream.</li>
     * <li><b>Verify mode</b> ({@code produceMode == false}): on upstream EOF, the
     * expected tag is split into classic/PQC components based on tag lengths, both
     * signatures are verified against the buffered body, and the final verification
     * result is stored into {@code lastOk}. No trailer bytes are emitted in verify
     * mode.</li>
     * </ul>
     *
     * <h2>Lifecycle and invariants</h2>
     * <ul>
     * <li>EOF finalization ({@link #finishAtEof()}) is executed at most once,
     * guarded by {@link #eofSeen}.</li>
     * <li>In produce mode, the trailer is emitted strictly after all upstream
     * bytes.</li>
     * <li>In verify mode, the stream ends immediately after the upstream ends.</li>
     * <li>This class is not thread-safe and assumes sequential consumption.</li>
     * </ul>
     *
     * <p>
     * Security note: this implementation must not expose sensitive materials (keys,
     * seeds, plaintext, signatures, or intermediate state) via logging or exception
     * messages. Exceptions raised by this stream are limited to generic error
     * descriptions and non-sensitive metadata (e.g., length and limits).
     * </p>
     */
    private final class HybridStream extends InputStream {
        /** The wrapped upstream stream providing the primary data. */
        private final InputStream upstream;

        /**
         * Buffer accumulating upstream bytes required for hybrid signature processing.
         * The buffer is bounded to mitigate unbounded memory growth.
         */
        private final ByteArrayOutputStream buffer;

        /**
         * Indicates whether end-of-stream has already been observed on the upstream.
         * Ensures EOF finalization logic executes exactly once.
         */
        private boolean eofSeen;

        /**
         * Trailer bytes to be emitted after upstream exhaustion in produce mode, or
         * {@code null} when no trailer is present (e.g., verify mode).
         */
        private byte[] trailer;

        /**
         * Current emission position within {@link #trailer}.
         */
        private int trailerPos;

        /**
         * Creates a new hybrid stream wrapping the provided upstream.
         *
         * @param upstream the underlying input stream supplying the primary data; must
         *                 not be {@code null}
         */
        private HybridStream(InputStream upstream) {
            super();
            this.upstream = upstream;
            this.buffer = new ByteArrayOutputStream(Math.min(8192, maxBufferedBytes));
            this.eofSeen = false;
            this.trailer = null;
            this.trailerPos = 0;
        }

        /**
         * Reads a single byte from this stream.
         *
         * <p>
         * Delegates to {@link #read(byte[], int, int)} and follows the standard
         * {@link InputStream} contract.
         * </p>
         *
         * @return the next byte of data as an unsigned value in the range
         *         {@code 0–255}, or {@code -1} if the stream is exhausted (including
         *         any trailer)
         * @throws IOException if an I/O error occurs or EOF finalization fails
         */
        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int r = read(one, 0, 1);
            if (r == -1) {
                return -1;
            }
            return one[0] & 0xff;
        }

        /**
         * Reads up to {@code len} bytes of data into {@code b}, starting at
         * {@code off}.
         *
         * <p>
         * The method first serves any pending trailer bytes (produce mode). Otherwise
         * it reads from the upstream stream, buffering all successfully read bytes for
         * later hybrid signature processing at EOF. When the upstream stream returns
         * {@code -1} for the first time, {@link #finishAtEof()} is invoked and may
         * either prepare a trailer for emission (produce mode) or perform verification
         * (verify mode).
         * </p>
         *
         * @param b   destination buffer
         * @param off offset at which to start storing bytes
         * @param len maximum number of bytes to read
         * @return the number of bytes read, or {@code -1} if the stream is exhausted
         * @throws IOException               if an I/O error occurs, the internal buffer
         *                                   limit is exceeded, or EOF finalization
         *                                   (signature creation/verification) fails
         * @throws IndexOutOfBoundsException if {@code off} or {@code len} are invalid
         */
        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            Objects.checkFromIndexSize(off, len, b.length);

            if (trailer != null) {
                if (trailerPos >= trailer.length) {
                    return -1;
                }
                int n = Math.min(len, trailer.length - trailerPos);
                System.arraycopy(trailer, trailerPos, b, off, n);
                trailerPos += n;
                return n;
            }

            int r = upstream.read(b, off, len);
            if (r == -1) {
                if (!eofSeen) {
                    eofSeen = true;
                    finishAtEof();
                }
                if (trailer != null && trailer.length > 0) {
                    return read(b, off, len);
                }
                return -1;
            }

            if (r > 0) {
                writeToBuffer(b, off, r);
            }
            return r;
        }

        /**
         * Closes this stream and releases the underlying upstream resource.
         *
         * <p>
         * Note: closing this stream closes the wrapped {@code upstream} stream.
         * </p>
         *
         * @throws IOException if closing the upstream fails
         */
        @Override
        public void close() throws IOException {
            upstream.close();
        }

        /**
         * Appends the specified slice of bytes into the internal body buffer.
         *
         * <p>
         * The buffer is bounded by {@code maxBufferedBytes}. If appending would exceed
         * the configured limit, the method fails fast with an {@link IOException}.
         * </p>
         *
         * @param b   source buffer
         * @param off offset within {@code b}
         * @param len number of bytes to append
         * @throws IOException if the buffer limit would be exceeded
         */
        private void writeToBuffer(byte[] b, int off, int len) throws IOException {
            if (buffer.size() + len > maxBufferedBytes) {
                throw new IOException("Hybrid signature buffer limit exceeded: " + maxBufferedBytes);
            }
            buffer.write(b, off, len);
        }

        /**
         * Finalizes processing when upstream EOF is reached.
         *
         * <p>
         * This method is invoked exactly once upon the first observation of upstream
         * EOF. It uses the buffered body to either:
         * </p>
         *
         * <ul>
         * <li><b>Produce mode</b>: compute the classic and PQC signatures over the
         * body, concatenate them, and expose them as a trailer to be emitted by
         * subsequent {@code read(...)} calls.</li>
         * <li><b>Verify mode</b>: split the expected tag into classic/PQC signature
         * components, verify each against the body, combine results using the profile
         * verify rule, update {@code lastOk}, and delegate to
         * {@code verificationApproach} for any additional policy enforcement. No
         * trailer is produced.</li>
         * </ul>
         *
         * @throws IOException if required inputs are missing, if signature
         *                     creation/verification fails, if the expected tag has an
         *                     invalid length, or if the verification approach rejects
         *                     the tag
         */
        private void finishAtEof() throws IOException {
            byte[] body = buffer.toByteArray();

            if (produceMode) {
                byte[] sigClassic = signOne(profile.classicSigId(), classicPrivate, profile.classicSpec(), body);
                byte[] sigPqc = signOne(profile.pqcSigId(), pqcPrivate, profile.pqcSpec(), body);
                trailer = concat(sigClassic, sigPqc);
                trailerPos = 0;
                return;
            }

            byte[] exp = expectedTag;
            if (exp == null) {
                throw new IOException("Expected tag not set");
            }

            VerificationSplit split = splitExpected(exp);

            boolean okClassic = verifyOne(profile.classicSigId(), classicPublic, profile.classicSpec(), body,
                    split.expectedClassic);
            boolean okPqc = verifyOne(profile.pqcSigId(), pqcPublic, profile.pqcSpec(), body, split.expectedPqc);

            boolean finalOk = (profile.verifyRule() == HybridSignatureProfile.VerifyRule.OR) ? (okClassic || okPqc)
                    : (okClassic && okPqc);

            lastOk.set(finalOk);

            try {
                verificationApproach.verify(null, exp);
            } catch (VerificationException e) {
                throw new IOException("Hybrid signature verification failed", e);
            }

            trailer = null;
            trailerPos = 0;
        }

        /**
         * Splits the expected hybrid tag into classic and PQC signature components.
         *
         * <p>
         * The split is determined by querying tag lengths from freshly created
         * verification contexts (classic and PQC). The expected tag must match the
         * exact combined length {@code classicLen + pqcLen}; otherwise an
         * {@link IOException} is thrown.
         * </p>
         *
         * @param exp expected hybrid tag bytes containing concatenated classic and PQC
         *            signatures
         * @return a value object holding the classic and PQC expected signatures
         * @throws IOException if context initialization fails or {@code exp} has an
         *                     invalid length
         */
        private VerificationSplit splitExpected(byte[] exp) throws IOException {
            int classicLen;
            int pqcLen;

            try (SignatureContext classic = createClassic(KeyUsage.VERIFY);
                    SignatureContext pqc = createPqc(KeyUsage.VERIFY)) {
                classicLen = classic.tagLength();
                pqcLen = pqc.tagLength();
            }

            int total = classicLen + pqcLen;
            if (exp.length != total) {
                throw new IOException("Invalid expected tag length: " + exp.length + ", expected " + total);
            }

            byte[] eClassic = new byte[classicLen];
            byte[] ePqc = new byte[pqcLen];

            System.arraycopy(exp, 0, eClassic, 0, classicLen);
            System.arraycopy(exp, classicLen, ePqc, 0, pqcLen);

            return new VerificationSplit(eClassic, ePqc);
        }
    }

    /**
     * Simple value object holding the classic and PQC portions of an expected
     * hybrid signature tag.
     *
     * <p>
     * Instances are created only after the expected tag length is validated and
     * then used to feed the per-algorithm verification routines.
     * </p>
     *
     * <p>
     * Security note: this structure stores signature bytes; it must not be logged
     * or exposed outside the narrow verification flow.
     * </p>
     */
    private static final class VerificationSplit {
        /** Expected signature bytes for the classic algorithm. */
        private final byte[] expectedClassic;

        /** Expected signature bytes for the PQC algorithm. */
        private final byte[] expectedPqc;

        /**
         * Constructs the split expected-tag view.
         *
         * @param expectedClassic expected classic signature bytes; must not be
         *                        {@code null}
         * @param expectedPqc     expected PQC signature bytes; must not be {@code null}
         */
        private VerificationSplit(byte[] expectedClassic, byte[] expectedPqc) {
            this.expectedClassic = expectedClassic;
            this.expectedPqc = expectedPqc;
        }
    }

    private byte[] signOne(String id, PrivateKey key, ContextSpec spec, byte[] body) throws IOException {
        final byte[][] sigHolder = new byte[1][];

        try (SignatureContext signer = session.createContext(id, KeyUsage.SIGN, key, spec);
                InputStream in = new TailStrippingInputStream(signer.wrap(new ByteArrayInputStream(body)),
                        signer.tagLength(), 8192) {
                    @Override
                    protected void processTail(byte[] tail) throws IOException {
                        if (tail == null || tail.length == 0) {
                            throw new IOException("Empty signature trailer for " + id);
                        }
                        sigHolder[0] = tail.clone();
                    }
                }) {

            in.transferTo(OutputStream.nullOutputStream());

            byte[] sig = sigHolder[0];
            if (sig == null) {
                throw new IOException("Signature trailer missing for " + id);
            }
            return sig;
        }
    }

    private boolean verifyOne(String id, PublicKey key, ContextSpec spec, byte[] body, byte[] expected)
            throws IOException {

        AtomicBoolean ok = new AtomicBoolean(false);

        try (SignatureContext verifier = session.createContext(id, KeyUsage.VERIFY, key, spec)) {
            verifier.setVerificationApproach(new CapturePredicate(verifier.getVerificationCore(), ok));
            verifier.setExpectedTag(expected);

            try (InputStream in = verifier.wrap(new ByteArrayInputStream(body))) {
                in.transferTo(OutputStream.nullOutputStream());
            }
        }

        return ok.get();
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
