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
package zeroecho.sdk.builders.alg;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;
import java.util.function.Supplier;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.alg.common.sig.GenericJcaSignatureContext;
import zeroecho.core.alg.ecdsa.EcdsaCurveSpec;
import zeroecho.core.alg.ecdsa.EcdsaPrivateKeySpec;
import zeroecho.core.alg.ecdsa.EcdsaPublicKeySpec;
import zeroecho.core.context.SignatureContext;

/**
 * EcdsaDataContentBuilder configures and builds streaming ECDSA signature
 * pipelines over an InputStream.
 *
 * <h2>Overview</h2> This builder specializes
 * {@link AbstractStreamingSignatureDataBuilder} for ECDSA and lets callers
 * choose a named curve before constructing a signing or verification pipeline.
 * The actual signing and verification work is performed by
 * {@link SignatureContext} instances created via JCA-backed factories.
 *
 * <h2>Typical usage</h2> <pre>{@code
 * // Sign while passing the original bytes through:
 * PlainContent signed = EcdsaDataContentBuilder.builder()
 *     .withCurveP256()
 *     .sign()
 *     .withPrivateKey(privateKey)
 *     .passThrough()
 *     .build(true);
 *
 * // Emit a detached Base64 signature:
 * PlainContent sigOut = EcdsaDataContentBuilder.builder()
 *     .withCurve(EcdsaCurveSpec.P384)
 *     .sign()
 *     .withPrivateKey(privateKey)
 *     .emitBase64Signature()
 *     .build(true);
 *
 * // Verify while passing the original bytes through:
 * PlainContent verified = EcdsaDataContentBuilder.builder()
 *     .withCurveP256()
 *     .verify()
 *     .withPublicKey(publicKey)
 *     .expectedSignature(rawSig)
 *     .passThrough()
 *     .build(true);
 * }</pre>
 *
 * <h2>Curve selection</h2> If no curve is selected explicitly, {@code P256} is
 * used. Convenience methods are provided for P-256, P-384, and P-512
 * (implementation-specific name used by {@link EcdsaCurveSpec}).
 *
 * <h2>Thread-safety</h2> Instances are mutable and not thread-safe. Configure
 * and use each builder instance from a single thread.
 *
 * @see AbstractStreamingSignatureDataBuilder
 * @see EcdsaCurveSpec
 * @see EcdsaPublicKeySpec
 * @see EcdsaPrivateKeySpec
 * @see SignatureContext
 * @see GenericJcaSignatureContext
 */
public final class EcdsaDataContentBuilder
        extends AbstractStreamingSignatureDataBuilder<EcdsaCurveSpec, EcdsaPublicKeySpec, EcdsaPrivateKeySpec> {

    private final static EcdsaCurveSpec DEFAULT = EcdsaCurveSpec.P256;

    private EcdsaCurveSpec selected = DEFAULT;

    /**
     * Creates a new builder instance with the default curve selection.
     *
     * <h4>Example</h4> <pre>{@code
     * EcdsaDataContentBuilder b = EcdsaDataContentBuilder.builder();
     * }</pre>
     *
     * @return a new {@code EcdsaDataContentBuilder}
     */
    public static EcdsaDataContentBuilder builder() {
        return new EcdsaDataContentBuilder();
    }

    /**
     * Selects the curve to be used for key generation and signature processing.
     *
     * @param spec the ECDSA curve specification; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code spec} is null
     */
    public EcdsaDataContentBuilder withCurve(final EcdsaCurveSpec spec) {
        Objects.requireNonNull(spec, "EcdsaCurveSpec cannot be null");
        this.selected = spec;
        return this;
    }

    /**
     * Selects the P-256 curve.
     *
     * @return {@code this} builder for chaining
     */
    public EcdsaDataContentBuilder withCurveP256() {
        this.selected = EcdsaCurveSpec.P256;
        return this;
    }

    /**
     * Selects the P-384 curve.
     *
     * @return {@code this} builder for chaining
     */
    public EcdsaDataContentBuilder withCurveP384() {
        this.selected = EcdsaCurveSpec.P384;
        return this;
    }

    /**
     * Selects the P-512 curve as defined by {@link EcdsaCurveSpec}.
     *
     * @return {@code this} builder for chaining
     */
    public EcdsaDataContentBuilder withCurveP512() {
        this.selected = EcdsaCurveSpec.P512;
        return this;
    }

    /**
     * Returns the algorithm name used to resolve an implementation from
     * {@link CryptoAlgorithms}.
     *
     * @return the string {@code "ECDSA"}
     */
    @Override
    protected String algorithmName() {
        return "ECDSA";
    }

    private EcdsaCurveSpec activeSpec() {
        return selected;
    }

    /**
     * Creates a signing {@link SignatureContext} for the active curve using the
     * provided algorithm and key.
     *
     * <p>
     * The returned context is configured with a JCA signature factory derived from
     * the curve's {@link EcdsaCurveSpec#jcaFactory()} and a fixed-length resolver
     * based on {@link EcdsaCurveSpec#signFixedLength()}.
     * </p>
     *
     * @param alg the resolved crypto algorithm
     * @param key the private key to use for signing
     * @return a new signature context in sign mode
     * @throws GeneralSecurityException if the context cannot be created
     */
    @Override
    protected SignatureContext newSignContext(final CryptoAlgorithm alg, final PrivateKey key)
            throws GeneralSecurityException {
        EcdsaCurveSpec s = activeSpec();
        return new GenericJcaSignatureContext(alg, key, GenericJcaSignatureContext.jcaFactory(s.jcaFactory(), null),
                GenericJcaSignatureContext.SignLengthResolver.fixed(s.signFixedLength()));
    }

    /**
     * Creates a verification {@link SignatureContext} for the active curve using
     * the provided algorithm and key.
     *
     * <p>
     * The returned context is configured with a JCA signature factory derived from
     * the curve's {@link EcdsaCurveSpec#jcaFactory()} and a fixed-length resolver
     * based on {@link EcdsaCurveSpec#signFixedLength()}.
     * </p>
     *
     * @param alg the resolved crypto algorithm
     * @param key the public key to use for verification
     * @return a new signature context in verify mode
     * @throws GeneralSecurityException if the context cannot be created
     */
    @Override
    protected SignatureContext newVerifyContext(final CryptoAlgorithm alg, final PublicKey key)
            throws GeneralSecurityException {
        EcdsaCurveSpec s = activeSpec();
        return new GenericJcaSignatureContext(alg, key, GenericJcaSignatureContext.jcaFactory(s.jcaFactory(), null),
                GenericJcaSignatureContext.VerifyLengthResolver.fixed(s.signFixedLength()));
    }

    /**
     * Returns the class object of the key generation specification used by this
     * builder.
     *
     * @return {@code EcdsaCurveSpec.class}
     */
    @Override
    protected Class<EcdsaCurveSpec> keyGenSpecClass() {
        return EcdsaCurveSpec.class;
    }

    /**
     * Returns the class object of the public key import specification used by this
     * builder.
     *
     * @return {@code EcdsaPublicKeySpec.class}
     */
    @Override
    protected Class<EcdsaPublicKeySpec> publicKeySpecClass() {
        return EcdsaPublicKeySpec.class;
    }

    /**
     * Returns the class object of the private key import specification used by this
     * builder.
     *
     * @return {@code EcdsaPrivateKeySpec.class}
     */
    @Override
    protected Class<EcdsaPrivateKeySpec> privateKeySpecClass() {
        return EcdsaPrivateKeySpec.class;
    }

    /**
     * Supplies the default key generation specification for this builder.
     *
     * @return a supplier that returns {@link EcdsaCurveSpec#P256}
     */
    @Override
    protected Supplier<EcdsaCurveSpec> defaultKeyGenSpecSupplier() {
        return () -> DEFAULT;
    }

    /**
     * Returns the currently selected key generation specification, or null to
     * indicate that the default should be used.
     *
     * @return the active {@link EcdsaCurveSpec} or {@code null}
     */
    @Override
    protected EcdsaCurveSpec currentKeyGenSpecOrNull() {
        return selected;
    }

    /**
     * Creates a public key import specification from X.509-encoded bytes.
     *
     * @param x509     the SubjectPublicKeyInfo bytes
     * @param provider an optional provider name hint, ignored by this
     *                 implementation
     * @return a new {@link EcdsaPublicKeySpec} wrapping the provided bytes
     */
    @Override
    protected EcdsaPublicKeySpec makePublicKeySpec(final byte[] x509, final String provider) {
        return new EcdsaPublicKeySpec(x509);
    }

    /**
     * Creates a private key import specification from PKCS#8-encoded bytes.
     *
     * @param pkcs8    the PrivateKeyInfo bytes
     * @param provider an optional provider name hint, ignored by this
     *                 implementation
     * @return a new {@link EcdsaPrivateKeySpec} wrapping the provided bytes
     */
    @Override
    protected EcdsaPrivateKeySpec makePrivateKeySpec(final byte[] pkcs8, final String provider) {
        return new EcdsaPrivateKeySpec(pkcs8);
    }

    /**
     * Returns the default provider hint to use when importing keys if none is
     * explicitly set.
     *
     * @return {@code null} to indicate no preference
     */
    @Override
    protected String defaultProviderHint() {
        return null;
    }
}
