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
package zeroecho.core.alg.common.sig;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.tag.SignatureVerificationStrategy;
import zeroecho.core.tag.TagEngine;
import zeroecho.core.tag.ThrowingBiPredicate;
import zeroecho.core.tag.ThrowingBiPredicate.VerificationBiPredicate;

/**
 * Adapts a JCA {@link java.security.Signature} to the streaming
 * {@link SignatureContext}/{@link TagEngine} model.
 *
 * <p>
 * {@code GenericJcaSignatureContext} binds a key and a
 * {@link java.security.Signature} engine to a pull-based pipeline: the wrapped
 * stream forwards bytes unchanged while updating the engine. In SIGN mode a
 * fixed-length trailer containing the signature is appended at end-of-stream;
 * in VERIFY mode the computed signature is compared at end-of-stream to an
 * expected tag supplied by the caller. The trailer length is determined up
 * front so pipelines can append or strip trailers without buffering the whole
 * stream.
 * </p>
 *
 * <h2>Modes and usage</h2>
 * <ul>
 * <li><b>SIGN</b>: consume body bytes; on EOF call
 * {@link java.security.Signature#sign()} and append a trailer of
 * {@link #tagLength()} bytes.</li>
 * <li><b>VERIFY</b>: consume body bytes; on EOF compare against the expected
 * tag set via {@link #setExpectedTag(byte[])} using the verification approach
 * configured with
 * {@link #setVerificationApproach(ThrowingBiPredicate.VerificationBiPredicate)}.</li>
 * </ul>
 *
 * <h2>Length resolvers</h2>
 * <p>
 * A fixed tag length is required in both modes. For SIGN, a
 * {@link SignLengthResolver} supplies the produced length (either a constant or
 * by probing a provider). For VERIFY, a {@link VerifyLengthResolver} supplies
 * the expected length derived from key parameters or a known constant.
 * </p>
 *
 * <h2>Examples</h2>
 * <h3>Sign with RSA-PSS</h3> <pre>
 * {@code
 * GenericJcaSignatureContext ctx = new GenericJcaSignatureContext(
 *     algorithm,
 *     privateKey,
 *     GenericJcaSignatureContext.jcaFactory("RSASSA-PSS", null),
 *     GenericJcaSignatureContext.SignLengthResolver.probeWith("RSASSA-PSS", null));
 *
 * try (InputStream in = ctx.wrap(sourceStream)) {
 *     in.transferTo(out); // body, then trailer of ctx.tagLength() bytes
 * }
 * }
 * </pre>
 *
 * <h3>Verify detached RSA signature</h3> <pre>
 * {@code
 * GenericJcaSignatureContext vctx = new GenericJcaSignatureContext(
 *     algorithm,
 *     publicKey,
 *     GenericJcaSignatureContext.jcaFactory("SHA256withRSA", null),
 *     GenericJcaSignatureContext.VerifyLengthResolver.fixed(256)); // 2048-bit modulus
 *
 * vctx.setVerificationApproach(vctx.getVerificationCore().getThrowOnMismatch());
 * vctx.setExpectedTag(signatureBytes);
 *
 * try (InputStream verified = vctx.wrap(bodyWithoutTrailer)) {
 *     verified.transferTo(java.io.OutputStream.nullOutputStream()); // throws on mismatch at EOF
 * }
 * }
 * </pre>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances are stateful, single-use, and not thread-safe. Call
 * {@link #wrap(InputStream)} at most once per instance.
 * </p>
 */
public final class GenericJcaSignatureContext implements SignatureContext {
    private static final Logger LOG = Logger.getLogger(GenericJcaSignatureContext.class.getName());

    private final CryptoAlgorithm algorithm;
    private final Key key;
    private final boolean signMode;
    private final Signature engine;
    /**
     * Declared tag length used by {@link TagEngine#tagLength()} in both modes.
     *
     * <p>
     * Determined during construction by the provided resolver and constant for this
     * context's lifetime.
     * </p>
     */
    private final int declaredTagLen;
    private byte[] expectedTag;
    private VerificationBiPredicate<Signature> verificationStrategy;

    // lifecycle
    private boolean wrapped; // = false;
    private Stream activeStream;
    private boolean autoCloseActiveStream;

    /**
     * Factory of initialized {@link java.security.Signature} engines.
     *
     * <p>
     * Implementations must return a ready-to-use {@code Signature} configured for
     * signing or verifying with the given key.
     * </p>
     */
    @FunctionalInterface
    public interface EngineFactory {
        /**
         * Creates and initializes a {@link java.security.Signature} for the given key
         * and mode.
         *
         * @param key      key to initialize the engine with;
         *                 {@link java.security.PrivateKey} for sign mode,
         *                 {@link java.security.PublicKey} for verify mode
         * @param signMode {@code true} for signing, {@code false} for verifying
         * @return initialized {@code Signature} ready for incremental
         *         {@code update(...)} calls
         * @throws GeneralSecurityException if engine creation or initialization fails
         */
        Signature create(Key key, boolean signMode) throws GeneralSecurityException;
    }

    /**
     * Strategy for determining the signature trailer length in SIGN mode.
     *
     * <p>
     * The resolver is evaluated before the signing engine is created and may probe
     * a provider when the length is not fixed by specification.
     * </p>
     */
    @FunctionalInterface
    public interface SignLengthResolver {
        /**
         * Resolves the signature length for a given private key in SIGN mode.
         *
         * @param privateKey private key used for signing
         * @return exact number of bytes {@link java.security.Signature#sign()} will
         *         produce
         * @throws GeneralSecurityException if the length cannot be determined
         */
        int resolve(PrivateKey privateKey) throws GeneralSecurityException;

        /**
         * Returns a resolver that always reports a fixed length.
         *
         * @param len positive length in bytes
         * @return resolver returning {@code len}
         * @throws IllegalArgumentException if {@code len} &lt;= 0
         */
        static SignLengthResolver fixed(int len) {
            LOG.log(Level.FINE, "SignLengthResolver.len={0}", len);

            if (len <= 0) {
                throw new IllegalArgumentException("fixed signature length must be > 0");
            }
            return pk -> len;
        }

        /**
         * Returns a resolver that probes a JCA {@link java.security.Signature} by
         * signing an empty message.
         *
         * <p>
         * Useful for algorithms/providers where the produced length is not trivially
         * known from parameters.
         * </p>
         *
         * @param jcaAlg       JCA signature name (for example, {@code "SHA256withRSA"},
         *                     {@code "Ed25519"})
         * @param providerName optional provider name; {@code null} selects the
         *                     highest-priority provider
         * @return resolver that initializes a {@code Signature} for signing and returns
         *         {@code sign().length}
         */
        static SignLengthResolver probeWith(final String jcaAlg, final String providerName) {
            return privateKey -> {
                final Signature s = (providerName == null) ? Signature.getInstance(jcaAlg)
                        : Signature.getInstance(jcaAlg, providerName);
                s.initSign(privateKey);
                return s.sign().length; // empty-message probe
            };
        }
    }

    /**
     * Strategy for determining the expected signature length in VERIFY mode.
     *
     * <p>
     * The resolver is evaluated during construction and should return the fixed tag
     * length for verification.
     * </p>
     */
    @FunctionalInterface
    public interface VerifyLengthResolver {
        /**
         * Resolves the expected signature length for a given public key in VERIFY mode.
         *
         * @param publicKey public key used for verification
         * @return exact number of bytes expected in the verification tag
         * @throws GeneralSecurityException if the length cannot be determined
         */
        int resolve(PublicKey publicKey) throws GeneralSecurityException;

        /**
         * Returns a resolver that always reports a fixed length.
         *
         * @param len positive length in bytes
         * @return resolver returning {@code len}
         * @throws IllegalArgumentException if {@code len} &lt;= 0
         */
        static VerifyLengthResolver fixed(int len) {
            LOG.log(Level.FINE, "VerifyLengthResolver.len={0}", len);

            if (len <= 0) {
                throw new IllegalArgumentException("fixed signature length must be > 0");
            }
            return pk -> len;
        }
    }

    /**
     * Convenience factory that produces a JCA {@link java.security.Signature}
     * initialized for sign or verify.
     *
     * <p>
     * The returned factory performs {@link Signature#getInstance(String)}
     * (optionally with a provider) and then calls
     * {@link Signature#initSign(PrivateKey)} or
     * {@link Signature#initVerify(PublicKey)}.
     * </p>
     *
     * <pre>
     * {@code
     * EngineFactory f = GenericJcaSignatureContext.jcaFactory("SHA256withRSA", null);
     * Signature signer = f.create(privateKey, true);
     * }
     * </pre>
     *
     * @param jcaAlg   JCA signature algorithm name; must not be {@code null}
     * @param provider optional provider name; {@code null} selects the
     *                 highest-priority provider
     * @return factory creating initialized {@code Signature} engines for the
     *         specified algorithm/provider
     */
    public static EngineFactory jcaFactory(final String jcaAlg, final String provider) {
        return (key, signMode) -> {
            final Signature s = (provider == null) ? Signature.getInstance(jcaAlg)
                    : Signature.getInstance(jcaAlg, provider);
            if (signMode) {
                s.initSign((PrivateKey) key);
            } else {
                s.initVerify((PublicKey) key);
            }
            return s;
        };
    }

    /**
     * Constructs a SIGN-mode context.
     *
     * <p>
     * First resolves the produced signature length via {@code lengthResolver}, then
     * creates and initializes the signing engine via {@code engineFactory}.
     * </p>
     *
     * @param algorithm      logical algorithm descriptor associated with this
     *                       context; must not be {@code null}
     * @param privateKey     private key used for signing; must not be {@code null}
     * @param engineFactory  factory creating an initialized
     *                       {@link java.security.Signature} in sign mode; must not
     *                       be {@code null}
     * @param lengthResolver strategy to resolve the produced signature length up
     *                       front; must not be {@code null}
     * @throws GeneralSecurityException if length resolution or engine
     *                                  initialization fails
     * @throws NullPointerException     if any required argument is {@code null}
     */
    public GenericJcaSignatureContext(final CryptoAlgorithm algorithm, final PrivateKey privateKey,
            final EngineFactory engineFactory, final SignLengthResolver lengthResolver)
            throws GeneralSecurityException {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.key = Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(engineFactory, "engineFactory");
        Objects.requireNonNull(lengthResolver, "lengthResolver");
        // compute trailer length first (with an independent probe if needed)
        this.declaredTagLen = lengthResolver.resolve(privateKey);
        this.engine = engineFactory.create(privateKey, true);
        this.signMode = true;
    }

    /**
     * Constructs a VERIFY-mode context.
     *
     * <p>
     * First resolves the expected tag length via {@code verifyLengthResolver}, then
     * creates and initializes the verifying engine via {@code engineFactory}.
     * </p>
     *
     * @param algorithm            logical algorithm descriptor associated with this
     *                             context; must not be {@code null}
     * @param publicKey            public key used for verification; must not be
     *                             {@code null}
     * @param engineFactory        factory creating an initialized
     *                             {@link java.security.Signature} in verify mode;
     *                             must not be {@code null}
     * @param verifyLengthResolver strategy to resolve the expected signature length
     *                             up front; must not be {@code null}
     * @throws GeneralSecurityException if length resolution or engine
     *                                  initialization fails
     * @throws NullPointerException     if any required argument is {@code null}
     */
    public GenericJcaSignatureContext(final CryptoAlgorithm algorithm, final PublicKey publicKey,
            final EngineFactory engineFactory, final VerifyLengthResolver verifyLengthResolver)
            throws GeneralSecurityException {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.key = Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(engineFactory, "engineFactory");
        Objects.requireNonNull(verifyLengthResolver, "verifyLengthResolver");
        this.engine = engineFactory.create(publicKey, false);
        this.signMode = false;
        this.declaredTagLen = verifyLengthResolver.resolve(publicKey);
    }

    /**
     * Returns the logical algorithm associated with this context.
     *
     * @return the algorithm descriptor
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the key bound to this context.
     *
     * @return the signing key in SIGN mode or the verification key in VERIFY mode
     */
    @Override
    public Key key() {
        return key;
    }

    /**
     * Closes the active wrapped stream, if any, suppressing
     * {@link java.io.IOException}.
     *
     * <p>
     * Keeping {@code close()} non-throwing simplifies pipeline cleanup.
     * </p>
     */
    @Override
    public void close() {
        LOG.log(Level.FINE, "close");

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
     * Wraps the supplied upstream stream so the underlying
     * {@link java.security.Signature} is updated as data flows.
     *
     * <p>
     * This method may be called only once per instance. In SIGN mode the returned
     * stream appends a trailer of {@link #tagLength()} bytes when the upstream
     * finishes. In VERIFY mode the returned stream performs verification at EOF
     * against the expected tag configured via {@link #setExpectedTag(byte[])} and
     * surfaces the outcome using the verification approach set via
     * {@link #setVerificationApproach(ThrowingBiPredicate.VerificationBiPredicate)}.
     * </p>
     *
     * @param upstream source stream whose bytes will be fed into the signature;
     *                 must not be {@code null}
     * @return stream that must be fully consumed to trigger signing or verification
     * @throws NullPointerException  if {@code upstream} is {@code null}
     * @throws IllegalStateException if this context has already wrapped a stream
     * @throws IOException           if signing or verification fails during
     *                               processing or finalization
     */
    @Override
    public InputStream wrap(final InputStream upstream) throws IOException {
        Objects.requireNonNull(upstream, "upstream");
        if (wrapped) {
            throw new IllegalStateException(
                    "This SignatureContext instance was already used; create a new one per stream.");
        }
        wrapped = true;

        LOG.log(Level.INFO, "wrap for signing, tagLength={0}", declaredTagLen);

        Stream s = new Stream(engine, signMode, upstream, tagLength(), expectedTag, verifier());
        this.activeStream = s;
        return s;
    }

    /**
     * Returns the declared tag length in bytes.
     *
     * <p>
     * Computed during construction by the configured resolver and constant for the
     * lifetime of this context.
     * </p>
     *
     * @return fixed signature trailer length
     */
    @Override
    public int tagLength() {
        // Always advertise a concrete length so callers (like TagTrailer) can strip
        // trailers.
        return declaredTagLen;
    }

    /**
     * Sets the expected verification tag to be checked when the wrapped stream
     * finishes.
     *
     * <p>
     * Applicable only in VERIFY mode. Passing {@code null} clears the tag. The
     * array is defensively copied. If a wrapped stream is already active, its
     * expected tag is updated as well.
     * </p>
     *
     * @param expected expected signature bytes or {@code null} to clear
     * @throws UnsupportedOperationException if called in SIGN mode
     */
    @Override
    public void setExpectedTag(final byte[] expected) {
        if (signMode) {
            throw new UnsupportedOperationException("setExpectedTag is only applicable in VERIFY mode");
        }
        this.expectedTag = (expected == null) ? null : Arrays.copyOf(expected, expected.length);

        if (activeStream != null) {
            activeStream.setExpectedTag(expected);
        }
    }

    /**
     * Sets the verification approach used in VERIFY mode to compare the expected
     * and computed signatures.
     *
     * @param strategy verification predicate; may be decorated to throw or to flag
     *                 into a context; {@code null} keeps the default
     */
    @Override
    public void setVerificationApproach(VerificationBiPredicate<Signature> strategy) {
        verificationStrategy = strategy;
    }

    /**
     * Returns the core verification predicate for signature comparison.
     *
     * @return predicate that delegates to {@link Signature#verify(byte[])}
     */
    @Override
    public VerificationBiPredicate<Signature> getVerificationCore() {
        return new SignatureVerificationStrategy();
    }

    /**
     * Selects the effective verification predicate: the user-supplied strategy if
     * present, otherwise the default core with throw-on-mismatch decoration.
     *
     * @return effective verification predicate
     */
    private VerificationBiPredicate<Signature> verifier() {
        return verificationStrategy == null ? getVerificationCore().getThrowOnMismatch() : verificationStrategy;
    }
}
