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
package zeroecho.core.alg.common.eddsa;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.alg.common.sig.GenericJcaSignatureContext;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.tag.TagEngine;
import zeroecho.core.tag.ThrowingBiPredicate.VerificationBiPredicate;

/**
 * Base class for EdDSA signature contexts that adapts a JCA {@code Signature}
 * for streaming sign and verify.
 *
 * <p>
 * This class is a thin adapter over {@link GenericJcaSignatureContext}: it
 * wires the JCA signature name (for example, {@code "Ed25519"} or
 * {@code "Ed448"}) and a fixed tag length, then delegates all
 * {@link SignatureContext} operations to the internal delegate. Concrete
 * subclasses such as {@code Ed25519SignatureContext} and
 * {@code Ed448SignatureContext} expose role-specific contexts for signing or
 * verifying.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Bind an EdDSA variant to a {@link CryptoAlgorithm} and a key
 * ({@link PrivateKey} for signing, {@link PublicKey} for verifying).</li>
 * <li>Delegate {@link SignatureContext} and {@link TagEngine} behavior to the
 * {@link GenericJcaSignatureContext} instance.</li>
 * <li>Enforce a fixed tag length appropriate for the algorithm (64 bytes for
 * Ed25519, 114 bytes for Ed448).</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances are stateful and not guaranteed to be thread-safe. Use one context
 * per signing or verification pipeline.
 * </p>
 *
 * @since 1.0
 */
public class CommonEdDSASignatureContext implements SignatureContext {
    private final GenericJcaSignatureContext delegate;

    /**
     * Constructs a signing context for the given EdDSA algorithm.
     *
     * <p>
     * The created context operates in SIGN mode. The JCA engine is obtained using
     * the supplied {@code jcaSignatureName}, and the produced signature length is
     * fixed to {@code tagLength}.
     * </p>
     *
     * @param algorithm        associated algorithm descriptor; must not be
     *                         {@code null}
     * @param privateKey       private key used for signing; must not be
     *                         {@code null}
     * @param jcaSignatureName JCA signature name (for example, {@code "Ed25519"} or
     *                         {@code "Ed448"}); must not be {@code null}
     * @param tagLength        fixed signature length in bytes (64 for Ed25519, 114
     *                         for Ed448)
     * @throws GeneralSecurityException if the JCA provider cannot initialize the
     *                                  signature engine
     * @throws NullPointerException     if any argument is {@code null}
     */
    protected CommonEdDSASignatureContext(final CryptoAlgorithm algorithm, final PrivateKey privateKey,
            final String jcaSignatureName, final int tagLength) throws GeneralSecurityException {
        this.delegate = new GenericJcaSignatureContext(algorithm, privateKey,
                GenericJcaSignatureContext.jcaFactory(jcaSignatureName, null),
                GenericJcaSignatureContext.SignLengthResolver.fixed(tagLength));
    }

    /**
     * Constructs a verification context for the given EdDSA algorithm.
     *
     * <p>
     * The created context operates in VERIFY mode. The JCA engine is obtained using
     * the supplied {@code jcaSignatureName}, and the expected signature length is
     * fixed to {@code tagLength}.
     * </p>
     *
     * @param algorithm        associated algorithm descriptor; must not be
     *                         {@code null}
     * @param publicKey        public key used for verification; must not be
     *                         {@code null}
     * @param jcaSignatureName JCA signature name (for example, {@code "Ed25519"} or
     *                         {@code "Ed448"}); must not be {@code null}
     * @param tagLength        fixed signature length in bytes (64 for Ed25519, 114
     *                         for Ed448)
     * @throws GeneralSecurityException if the JCA provider cannot initialize the
     *                                  signature engine
     * @throws NullPointerException     if any argument is {@code null}
     */
    protected CommonEdDSASignatureContext(final CryptoAlgorithm algorithm, final PublicKey publicKey,
            final String jcaSignatureName, final int tagLength) throws GeneralSecurityException {
        this.delegate = new GenericJcaSignatureContext(algorithm, publicKey,
                GenericJcaSignatureContext.jcaFactory(jcaSignatureName, null),
                GenericJcaSignatureContext.VerifyLengthResolver.fixed(tagLength));
    }

    /**
     * Returns the algorithm associated with this context.
     *
     * @return the {@link CryptoAlgorithm} descriptor
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return delegate.algorithm();
    }

    /**
     * Returns the signing or verification key bound to this context.
     *
     * @return the {@link java.security.Key} in use
     */
    @Override
    public java.security.Key key() {
        return delegate.key();
    }

    /**
     * Releases resources associated with this context.
     *
     * <p>
     * After calling {@code close()}, further use of this context is undefined.
     * </p>
     */
    @Override
    public void close() {
        delegate.close();
    }

    /**
     * Wraps an upstream {@link InputStream} so that all data read from it is
     * processed by the underlying signature engine.
     *
     * <p>
     * In SIGN mode the wrapped stream emits the original data followed by a
     * detached signature trailer at end-of-stream. In VERIFY mode the wrapped
     * stream emits only the body and performs verification at end-of-stream against
     * the expected tag.
     * </p>
     *
     * @param upstream input stream supplying data to be signed or verified; must
     *                 not be {@code null}
     * @return a wrapped stream that updates the signature engine on read
     * @throws IOException if stream wrapping fails
     */
    @Override
    public InputStream wrap(InputStream upstream) throws IOException {
        return delegate.wrap(upstream);
    }

    /**
     * Returns the fixed tag (signature) length in bytes for this algorithm.
     *
     * @return the signature length in bytes
     */
    @Override
    public int tagLength() {
        return delegate.tagLength();
    }

    /**
     * Sets the expected signature (tag) used in VERIFY mode.
     *
     * <p>
     * Passing {@code null} clears the expected tag.
     * </p>
     *
     * @param expected the signature bytes to verify against, or {@code null} to
     *                 clear
     */
    @Override
    public void setExpectedTag(byte[] expected) {
        delegate.setExpectedTag(expected);
    }

    /**
     * Sets the verification approach used to compare the computed and expected
     * signatures.
     *
     * @param strategy verification predicate to apply in VERIFY mode; may be
     *                 decorated to throw or flag
     */
    @Override
    public void setVerificationApproach(VerificationBiPredicate<Signature> strategy) {
        delegate.setVerificationApproach(strategy);
    }

    /**
     * Returns the core verification predicate used by this context.
     *
     * <p>
     * The returned predicate typically delegates to
     * {@link Signature#verify(byte[])}.
     * </p>
     *
     * @return the base verification predicate
     */
    @Override
    public VerificationBiPredicate<Signature> getVerificationCore() {
        return delegate.getVerificationCore();
    }

}
