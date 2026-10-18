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
package zeroecho.core.alg.rsa;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.err.VerificationException;
import zeroecho.core.io.AbstractPassthroughInputStream;
import zeroecho.core.tag.ByteVerificationStrategy;
import zeroecho.core.tag.SignatureVerificationStrategy;
import zeroecho.core.tag.ThrowingBiPredicate;
import zeroecho.core.tag.ThrowingBiPredicate.VerificationBiPredicate;

/**
 * Streaming RSA signature context for signing or verifying data in a pull
 * pipeline.
 *
 * <p>
 * This context binds an RSA key and a signature specification, exposes a
 * passthrough view via {@link #wrap(java.io.InputStream)}, and finalizes at
 * end-of-stream. In produce (SIGN) mode the signature is emitted as a trailer.
 * In verify (VERIFY) mode the computed signature is compared against an
 * expected tag using a configured verification approach.
 * </p>
 *
 * <h2>Modes</h2>
 * <ul>
 * <li><b>SIGN</b> - consumes body bytes and appends the computed signature as a
 * trailer after the original data has been read.</li>
 * <li><b>VERIFY</b> - consumes body bytes and compares the computed signature
 * at EOF to the value provided via {@link #setExpectedTag(byte[])}. The outcome
 * is handled by the verification approach set with
 * {@link #setVerificationApproach(ThrowingBiPredicate.VerificationBiPredicate)}.</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <h3>Sign with RSASSA-PSS (SHA-256, salt 32)</h3> <pre>
 * {@code
 * RsaSigSpec spec = RsaSigSpec.pss(RsaSigSpec.Hash.SHA256, 32);
 * try (RsaSignatureContext ctx = new RsaSignatureContext(algo, privateKey, spec);
 *      InputStream in  = Files.newInputStream(msgPath);
 *      InputStream out = ctx.wrap(in)) {
 *     // out yields message bytes, then signature trailer of length ctx.tagLength()
 *     Files.copy(out, signedPayloadPath);
 * }
 * }
 * </pre>
 *
 * <h3>Verify a detached RSA signature</h3> <pre>
 * {@code
 * byte[] sig = Files.readAllBytes(sigPath);
 * RsaSigSpec spec = RsaSigSpec.pss(RsaSigSpec.Hash.SHA256, 32);
 * try (RsaSignatureContext ctx = new RsaSignatureContext(algo, publicKey, spec);
 *      InputStream in  = Files.newInputStream(bodyWithoutTrailer);
 *      InputStream out = ctx.wrap(in)) {
 *     ctx.setExpectedTag(sig);
 *     // Throw on mismatch at EOF:
 *     ctx.setVerificationApproach(ctx.getVerificationCore().getThrowOnMismatch());
 *     Files.copy(out, recoveredMsgPath);
 * }
 * }
 * </pre>
 *
 * <h2>Notes</h2>
 * <ul>
 * <li>Supported modes: PKCS#1 v1.5 and RSASSA-PSS. If {@code pssSaltLen} in the
 * spec is -1, the salt length defaults to the digest size.</li>
 * <li>{@link #tagLength()} equals the RSA modulus length in bytes.</li>
 * <li>Instances are single-use and not thread-safe. Calling
 * {@link #wrap(InputStream)} more than once throws
 * {@link IllegalStateException}.</li>
 * </ul>
 */
public final class RsaSignatureContext implements SignatureContext {
    private static final Logger LOG = Logger.getLogger(RsaSignatureContext.class.getName());

    private final CryptoAlgorithm algorithm;
    private final Key key; // java.security.Key (PrivateKey or PublicKey)
    private final boolean signMode; // true = SIGN, false = VERIFY
    private final Signature engine;
    private final int tagLen; // signature length in bytes (modulus size)

    // verification configuration (VERIFY mode)
    private byte[] expectedTag;
    private VerificationBiPredicate<Signature> verificationStrategy;

    // lifecycle
    private boolean wrapped; // = false;
    private Stream activeStream;
    private boolean autoCloseActiveStream;

    /**
     * Constructs a signing context using the given private key and signature
     * specification.
     *
     * <p>
     * The context operates in SIGN mode. At end-of-stream, a signature of length
     * {@link #tagLength()} is produced and emitted as a trailer by the wrapped
     * stream.
     * </p>
     *
     * @param alg  algorithm descriptor owning this context; must not be
     *             {@code null}
     * @param k    private key used for signing; must not be {@code null}
     * @param spec RSA signature specification (PKCS#1 v1.5 or PSS); must not be
     *             {@code null}
     * @throws GeneralSecurityException if the JCA signature engine cannot be
     *                                  initialized
     * @throws NullPointerException     if any argument is {@code null}
     */
    public RsaSignatureContext(final CryptoAlgorithm alg, final java.security.PrivateKey k, final RsaSigSpec spec)
            throws GeneralSecurityException {
        this.algorithm = Objects.requireNonNull(alg, "algorithm");
        this.key = Objects.requireNonNull(k, "private key");
        this.signMode = true;
        this.engine = initEngine(spec, true, k);
        this.tagLen = modulusBytes(k);
    }

    /**
     * Constructs a verification context using the given public key and signature
     * specification.
     *
     * <p>
     * The context operates in VERIFY mode. Provide the expected signature via
     * {@link #setExpectedTag(byte[])} before the wrapped stream reaches EOF. Final
     * verification occurs at EOF using the configured verification approach.
     * </p>
     *
     * @param alg  algorithm descriptor owning this context; must not be
     *             {@code null}
     * @param k    public key used for verification; must not be {@code null}
     * @param spec RSA signature specification (PKCS#1 v1.5 or PSS); must not be
     *             {@code null}
     * @throws GeneralSecurityException if the JCA signature engine cannot be
     *                                  initialized
     * @throws NullPointerException     if any argument is {@code null}
     */
    public RsaSignatureContext(final CryptoAlgorithm alg, final java.security.PublicKey k, final RsaSigSpec spec)
            throws GeneralSecurityException {
        this.algorithm = Objects.requireNonNull(alg, "algorithm");
        this.key = Objects.requireNonNull(k, "public key");
        this.signMode = false;
        this.engine = initEngine(spec, false, k);
        this.tagLen = modulusBytes(k);
    }

    private static Signature initEngine(final RsaSigSpec spec, final boolean sign, final Key k)
            throws GeneralSecurityException {
        Signature s = newEngine(spec);
        if (sign) {
            s.initSign((java.security.PrivateKey) k);
        } else {
            s.initVerify((java.security.PublicKey) k);
        }
        configurePssIfNeeded(s, spec);
        return s;
    }

    private static Signature newEngine(final RsaSigSpec spec) throws NoSuchAlgorithmException {
        if (spec.mode() == RsaSigSpec.Mode.PKCS1V15) {
            return Signature.getInstance(jcaSigName(spec.hash()));
        }
        return Signature.getInstance("RSASSA-PSS");
    }

    private static String jcaSigName(final RsaSigSpec.Hash h) {
        return switch (h) {
            case SHA256 -> "SHA256withRSA";
            case SHA384 -> "SHA384withRSA";
            case SHA512 -> "SHA512withRSA";
        };
    }

    private static String jcaHash(final RsaSigSpec.Hash h) {
        return switch (h) {
            case SHA256 -> "SHA-256";
            case SHA384 -> "SHA-384";
            case SHA512 -> "SHA-512";
        };
    }

    private static MGF1ParameterSpec mgf1(final RsaSigSpec.Hash h) {
        return switch (h) {
            case SHA256 -> MGF1ParameterSpec.SHA256;
            case SHA384 -> MGF1ParameterSpec.SHA384;
            case SHA512 -> MGF1ParameterSpec.SHA512;
        };
    }

    private static void configurePssIfNeeded(final Signature s, final RsaSigSpec spec)
            throws InvalidAlgorithmParameterException {
        if (spec.mode() == RsaSigSpec.Mode.PSS) {
            final int salt = (spec.pssSaltLen() == -1) ? digestLen(spec.hash()) : spec.pssSaltLen();
            final PSSParameterSpec pss = new PSSParameterSpec(jcaHash(spec.hash()), "MGF1", mgf1(spec.hash()), salt, 1);
            s.setParameter(pss);
        }
    }

    private static int digestLen(final RsaSigSpec.Hash h) {
        return switch (h) {
            case SHA256 -> 32;
            case SHA384 -> 48;
            case SHA512 -> 64;
        };
    }

    private static int modulusBytes(final Key k) {
        return switch (k) {
            case RSAPrivateKey rk -> (rk.getModulus().bitLength() + 7) / 8;
            case RSAPublicKey rk -> (rk.getModulus().bitLength() + 7) / 8;
            default -> throw new IllegalArgumentException("Not an RSA key: " + k.getClass().getName());
        };
    }

    /**
     * Returns the algorithm descriptor associated with this context.
     *
     * @return the owning algorithm
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the key bound to this context.
     *
     * <p>
     * This is a private key in SIGN mode and a public key in VERIFY mode.
     * </p>
     *
     * @return the RSA key used by this context
     */
    @Override
    public Key key() {
        return key;
    }

    /**
     * Closes the context and its active stream if present.
     *
     * <p>
     * If a wrapped stream is active, this method attempts to close it, which
     * triggers finalization of signing or verification.
     * </p>
     */
    @Override
    public void close() {
        if (autoCloseActiveStream) {
            try {
                if (activeStream != null) {
                    activeStream.close();
                }
            } catch (IOException ignore) {
                LOG.log(Level.WARNING, "RSA signature stream close failed; failure suppressed", ignore);
            }
        }
    }

    /**
     * Wraps an upstream stream and returns a passthrough stream that performs
     * signing or verification.
     *
     * <p>
     * The returned stream relays bytes from {@code upstream} while updating the
     * signature engine. On end-of-stream:
     * </p>
     * <ul>
     * <li><b>SIGN</b>: computes the signature and emits it as a trailer.</li>
     * <li><b>VERIFY</b>: verifies against the {@linkplain #setExpectedTag(byte[])
     * expected tag} and signals the outcome according to
     * {@link #setVerificationApproach(VerificationBiPredicate)}.</li>
     * </ul>
     *
     * <p>
     * A context instance is single-use; calling this method twice throws
     * {@link IllegalStateException}.
     * </p>
     *
     * @param upstream source stream to wrap
     * @return a new input stream that performs signing or verification as data is
     *         read
     * @throws NullPointerException  if {@code upstream} is {@code null}
     * @throws IllegalStateException if this context was already used for a previous
     *                               stream
     * @throws IOException           if the signature engine update or finalization
     *                               fails
     */
    @Override
    public InputStream wrap(final InputStream upstream) throws IOException {
        Objects.requireNonNull(upstream, "upstream");
        if (wrapped) {
            throw new IllegalStateException(
                    "This RsaSignatureContext instance was already used; create a new one per stream.");
        }
        wrapped = true;
        Stream s = new Stream(upstream, verifier());
        this.activeStream = s;
        return s;
    }

    /**
     * Returns the signature length in bytes.
     *
     * <p>
     * This equals the RSA modulus size in bytes and is the length of the trailer
     * emitted in SIGN mode or the expected tag length in VERIFY mode.
     * </p>
     *
     * @return signature length in bytes
     */
    @Override
    public int tagLength() {
        return tagLen;
    }

    /**
     * Sets the expected signature for verification mode.
     *
     * <p>
     * Only meaningful in VERIFY mode. The array is copied defensively. If set to
     * {@code null}, verification will fail unless the chosen verification approach
     * records and ignores failures.
     * </p>
     *
     * @param expected expected signature bytes or {@code null} to clear
     */
    @Override
    public void setExpectedTag(final byte[] expected) {
        if (!signMode) {
            this.expectedTag = (expected == null) ? null : Arrays.copyOf(expected, expected.length);
        }
    }

    /**
     * Passthrough stream that feeds data into the RSA {@link Signature} engine and
     * finalizes signing or verification at EOF (or on draining {@link #close()} in
     * the base).
     *
     * <p>
     * <b>Modes</b>
     * </p>
     * <ul>
     * <li><b>SIGN</b>: relays data unchanged and, after EOF, emits the computed
     * signature as a single trailer.</li>
     * <li><b>VERIFY</b>: relays data unchanged and, after EOF, verifies against the
     * expected tag according to policy; no trailer is emitted.</li>
     * </ul>
     *
     * <h2>Lifecycle mapping</h2>
     * <ul>
     * <li>{@link #update(byte[], int, int)} - feeds chunks into the
     * {@code Signature} engine.</li>
     * <li>{@link #produceTrailer(byte[])} - SIGN only: computes and emits the
     * signature once; VERIFY: returns 0.</li>
     * <li>{@link #onCompleted()} - runs exactly once immediately after the trailer
     * attempt; VERIFY-only verification.</li>
     * </ul>
     */
    private final class Stream extends AbstractPassthroughInputStream {
        /** Cached signature for trailer emission in SIGN mode. */
        private byte[] signature;

        /* default */ final VerificationBiPredicate<Signature> verifier;

        private Stream(final InputStream upstream, final VerificationBiPredicate<Signature> verifier) {
            super(upstream, 8192);
            this.verifier = verifier;
        }

        /**
         * Feeds the provided buffer segment into the signature engine.
         *
         * @param buf input buffer containing data to sign/verify
         * @param off offset of first byte
         * @param len number of bytes
         * @throws IOException if the signature engine rejects the update
         */
        @Override
        protected void update(final byte[] buf, final int off, final int len) throws IOException {
            try {
                engine.update(buf, off, len);
            } catch (SignatureException e) {
                throw new IOException("RSA update failed", e);
            }
        }

        /**
         * Single-shot trailer production.
         *
         * <p>
         * SIGN mode: compute signature and emit it. VERIFY mode: do not emit a trailer.
         * </p>
         *
         * @param buf destination buffer to receive the trailer
         * @return number of bytes written; 0 to emit no trailer
         * @throws IOException if signature generation fails or the trailer does not fit
         */
        @Override
        protected int produceTrailer(byte[] buf) throws IOException {
            if (!signMode) {
                return 0; // VERIFY mode never emits a trailer
            }
            if (signature == null) {
                try {
                    signature = engine.sign();
                } catch (GeneralSecurityException e) {
                    throw new IOException("RSA finalize failed", e);
                }
            }
            if (signature.length == 0) {
                return 0;
            }
            if (signature.length > buf.length) {
                throw new IOException("Trailer does not fit into buffer");
            }
            System.arraycopy(signature, 0, buf, 0, signature.length);
            return signature.length;
        }

        /**
         * Verification routine; invoked exactly once after trailer production attempt.
         * Returns immediately in SIGN mode.
         */
        @Override
        protected void onCompleted() throws IOException {
            if (signMode) {
                return; // nothing to do for signing
            }
            try {
                verifier.verify(engine, expectedTag);
            } catch (VerificationException e) {
                throw new IOException(e);
            }
        }
    }

    /**
     * Sets the verification approach used to handle comparison outcomes in VERIFY
     * mode.
     *
     * <p>
     * Common strategies include constant-time byte comparison via
     * {@link ByteVerificationStrategy} and JCA-signature-based checks via
     * {@link SignatureVerificationStrategy}. Decorators such as
     * {@link ThrowingBiPredicate.VerificationBiPredicate#getThrowOnMismatch()} and
     * {@link ThrowingBiPredicate.VerificationBiPredicate#getFlagOkInCtx(conflux.CtxInterface, conflux.Key)}
     * can be used to throw on mismatch or to record a boolean in a context.
     * </p>
     *
     * @param strategy verification predicate; may be {@code null} to keep the
     *                 default
     */
    @Override
    public void setVerificationApproach(VerificationBiPredicate<Signature> strategy) {
        verificationStrategy = strategy;
    }

    /**
     * Returns the core verification predicate for RSA signatures.
     *
     * <p>
     * The default behavior is to throw on mismatch, implemented by decorating the
     * returned predicate with {@code getThrowOnMismatch()} when the context is used
     * and no custom strategy has been supplied.
     * </p>
     *
     * @return a predicate that delegates to {@link Signature#verify(byte[])}
     */
    @Override
    public VerificationBiPredicate<Signature> getVerificationCore() {
        return new SignatureVerificationStrategy();
    }

    private VerificationBiPredicate<Signature> verifier() {
        return verificationStrategy == null ? getVerificationCore().getThrowOnMismatch() : verificationStrategy;
    }
}
