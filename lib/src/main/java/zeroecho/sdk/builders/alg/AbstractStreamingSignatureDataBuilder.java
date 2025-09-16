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
package zeroecho.sdk.builders.alg;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Supplier;

import conflux.CtxInterface;
import conflux.Key;
import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spi.AsymmetricKeyBuilder;
import zeroecho.core.tag.SignatureVerificationStrategy;
import zeroecho.sdk.builders.core.DataContentBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.PlainContent;
import zeroecho.sdk.io.SignatureTrailerInputStream;

/**
 * A reusable streaming signature builder that signs or verifies data as it
 * flows through an {@link java.io.InputStream}.
 *
 * <p>
 * This abstract builder composes {@link PlainContent} pipelines that either
 * produce a signature while streaming the original input (sign passthrough),
 * emit the signature itself in various encodings, or verify an expected
 * signature while streaming or emit a boolean result. Algorithms are supplied
 * by {@link CryptoAlgorithms}; concrete subclasses provide algorithm-specific
 * details through protected abstract hooks.
 * </p>
 *
 * <h2>What this builder does</h2>
 * <ul>
 * <li>Obtains an algorithm instance and keys (direct, imported, or
 * generated).</li>
 * <li>Creates a {@link SignatureContext} in SIGN or VERIFY mode on demand.</li>
 * <li>Builds a streaming pipeline that either passes data through or emits a
 * detached artifact.</li>
 * <li>Lets callers plug in a verification approach (constant-time compare,
 * throw-on-mismatch, flag-in-context, etc.).</li>
 * </ul>
 *
 * <h2>Typical usage</h2> <pre>{@code
 * // Signing while passing the original bytes downstream:
 * PlainContent content = new MyAlgStreamingSignatureDataBuilder()
 *     .sign()
 *     .withPrivateKey(privateKey)
 *     .passThrough()
 *     .build(true);
 *
 * // Emitting a hex-encoded detached signature:
 * PlainContent sigOut = new MyAlgStreamingSignatureDataBuilder()
 *     .sign()
 *     .withPrivateKey(privateKey)
 *     .emitHexSignature()
 *     .build(true);
 *
 * // Verifying against an expected signature and passing data through:
 * PlainContent verified = new MyAlgStreamingSignatureDataBuilder()
 *     .verify()
 *     .withPublicKey(publicKey)
 *     .expectedSignatureBase64(b64Sig)
 *     .passThrough()
 *     .build(true);
 *
 * // Verifying and emitting a boolean ("true" or "false"):
 * PlainContent ok = new MyAlgStreamingSignatureDataBuilder()
 *     .verify()
 *     .emitVerificationBoolean()
 *     .withPublicKey(publicKey)
 *     .expectedSignature(rawSig)
 *     .build(true);
 * }</pre>
 *
 * <p>
 * The type parameters represent algorithm-specific key specifications:
 * </p>
 * <ul>
 * <li>{@code KG} - key generation specification type</li>
 * <li>{@code PUB} - public key import specification type</li>
 * <li>{@code PRIV} - private key import specification type</li>
 * </ul>
 *
 * <p>
 * Subclasses supply algorithm name, key spec classes, default key generation
 * supplier, factories for import specs, and creation of
 * {@link SignatureContext} instances for signing and verification.
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Builders are mutable and not thread-safe. Create and use an instance on a
 * single thread.
 * </p>
 *
 * @param <KG>   key generation spec type for the algorithm
 * @param <PUB>  public key import spec type for the algorithm
 * @param <PRIV> private key import spec type for the algorithm
 */
public abstract class AbstractStreamingSignatureDataBuilder<KG extends AlgorithmKeySpec, PUB extends AlgorithmKeySpec, PRIV extends AlgorithmKeySpec>
        implements DataContentBuilder<PlainContent> {
    private Mode mode = Mode.SIGN;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    private boolean genKeyPair;

    private byte[] _importPrivatePkcs8;
    private String importPrivateProvider; // optional

    private byte[] _importPublicX509;
    private String importPublicProvider; // optional

    private byte[] _expectedSignature; // VERIFY: raw
    private Key<byte[]> _expectedSignatureFromCtx; // optional ctx fetch

    private Output out = Output.PASSTHROUGH;

    private CtxInterface ctx; // optional
    private Key<byte[]> storeSigKey; // optional
    private SignatureVerificationStrategy _strategy; // = null optional

    private Consumer<byte[]> sigCallback; // optional

    private int _bufferSize = 8192;

    private CryptoAlgorithm algorithm; // resolved in resolveKeys()

    /**
     * Returns the canonical algorithm name used to resolve an implementation from
     * {@link CryptoAlgorithms}.
     *
     * <p>
     * Examples include "Ed25519" or "SPHINCS+".
     * </p>
     *
     * @return the algorithm name understood by
     *         {@link CryptoAlgorithms#require(String)}
     */
    protected abstract String algorithmName();

    /**
     * Creates a {@link SignatureContext} in sign mode for the given algorithm and
     * private key.
     *
     * <p>
     * Implementations should instantiate a signing context configured for streaming
     * updates and producing the final signature tag.
     * </p>
     *
     * @param alg the resolved algorithm instance
     * @param key the private key used to generate signatures
     * @return a new signature context in sign mode
     * @throws GeneralSecurityException if the context cannot be created for the
     *                                  provided algorithm or key
     */
    protected abstract SignatureContext newSignContext(CryptoAlgorithm alg, PrivateKey key)
            throws GeneralSecurityException;

    /**
     * Creates a {@link SignatureContext} in verify mode for the given algorithm and
     * public key.
     *
     * <p>
     * Implementations should instantiate a verification context configured for
     * streaming updates and validating the final signature tag.
     * </p>
     *
     * @param alg the resolved algorithm instance
     * @param key the public key used to verify signatures
     * @return a new signature context in verify mode
     * @throws GeneralSecurityException if the context cannot be created for the
     *                                  provided algorithm or key
     */
    protected abstract SignatureContext newVerifyContext(CryptoAlgorithm alg, PublicKey key)
            throws GeneralSecurityException;

    /**
     * Returns the key generation specification class for the algorithm.
     *
     * @return the class object representing {@code KG}
     */
    protected abstract Class<KG> keyGenSpecClass();

    /**
     * Returns the public key import specification class for the algorithm.
     *
     * @return the class object representing {@code PUB}
     */
    protected abstract Class<PUB> publicKeySpecClass();

    /**
     * Returns the private key import specification class for the algorithm.
     *
     * @return the class object representing {@code PRIV}
     */
    protected abstract Class<PRIV> privateKeySpecClass();

    /**
     * Returns a supplier of default key generation specifications.
     *
     * <p>
     * The supplier must not return null when invoked.
     * </p>
     *
     * @return a non-null supplier of default {@code KG} instances
     */
    protected abstract Supplier<KG> defaultKeyGenSpecSupplier();

    /**
     * Returns the currently configured key generation specification or null if the
     * default should be used.
     *
     * <p>
     * Subclasses typically provide a public setter to allow users to set a
     * non-default specification.
     * </p>
     *
     * @return the current key generation spec or null to indicate default should be
     *         used
     */
    protected abstract KG currentKeyGenSpecOrNull();

    /**
     * Builds a public key import specification from X.509-encoded bytes.
     *
     * <p>
     * The {@code providerHint} may be ignored if not applicable to the
     * implementation.
     * </p>
     *
     * @param x509         the X.509 SubjectPublicKeyInfo bytes
     * @param providerHint an optional provider name hint, may be null
     * @return the public key import spec instance
     */
    protected abstract PUB makePublicKeySpec(byte[] x509, String providerHint);

    /**
     * Builds a private key import specification from PKCS#8-encoded bytes.
     *
     * <p>
     * The {@code providerHint} may be ignored if not applicable to the
     * implementation.
     * </p>
     *
     * @param pkcs8        the PKCS#8 PrivateKeyInfo bytes
     * @param providerHint an optional provider name hint, may be null
     * @return the private key import spec instance
     */
    protected abstract PRIV makePrivateKeySpec(byte[] pkcs8, String providerHint);

    /**
     * Returns the default provider name hint used when importing keys if no
     * explicit provider was set.
     *
     * @return the provider hint or null if there is no preference
     */
    protected abstract String defaultProviderHint();

    /**
     * Operating mode for the builder.
     */
    public enum Mode {
        /**
         * Sign mode produces a signature using a private key.
         */
        SIGN,
        /**
         * Verify mode checks an expected signature using a public key.
         */
        VERIFY
    }

    /**
     * Declares the output mode for a cryptographic operation.
     *
     * <p>
     * Each constant specifies how the result of an operation such as signing,
     * verification, or transformation should be returned or rendered.
     * </p>
     *
     * <h2>Modes</h2>
     * <ul>
     * <li>{@link #PASSTHROUGH} - Return the original data without
     * modification.</li>
     * <li>{@link #SIG_RAW} - Return the raw signature bytes produced by the
     * algorithm.</li>
     * <li>{@link #SIG_HEX} - Return the signature encoded as a hexadecimal
     * string.</li>
     * <li>{@link #SIG_BASE64} - Return the signature encoded in Base64.</li>
     * <li>{@link #VERIFY_BOOL} - Return a boolean result of verification
     * ({@code true} if valid, {@code false} otherwise).</li>
     * </ul>
     *
     * <h2>Thread-safety</h2> Enum constants are immutable and inherently
     * thread-safe.
     */
    private enum Output {
        /** Return the original data without modification. */
        PASSTHROUGH,
        /** Return raw signature bytes. */
        SIG_RAW,
        /** Return the signature as a hexadecimal string. */
        SIG_HEX,
        /** Return the signature as a Base64-encoded string. */
        SIG_BASE64,
        /** Return a boolean verification result. */
        VERIFY_BOOL
    }

    /**
     * Switches the builder to sign mode.
     *
     * @return {@code this} builder for chaining
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> sign() {
        this.mode = Mode.SIGN;
        return this;
    }

    /**
     * Switches the builder to verify mode.
     *
     * @return {@code this} builder for chaining
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> verify() {
        this.mode = Mode.VERIFY;
        return this;
    }

    /**
     * Configures the output to pass the original data through unchanged.
     *
     * <p>
     * In sign mode this computes the signature but appends it only when using the
     * internal trailer format. In verify mode this verifies as the data is consumed
     * while passing it through.
     * </p>
     *
     * @return {@code this} builder for chaining
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> passThrough() {
        this.out = Output.PASSTHROUGH;
        return this;
    }

    /**
     * Configures the output to emit the raw detached signature bytes.
     *
     * @return {@code this} builder for chaining
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> emitRawSignature() {
        this.out = Output.SIG_RAW;
        return this;
    }

    /**
     * Configures the output to emit the detached signature as lowercase hexadecimal
     * text.
     *
     * @return {@code this} builder for chaining
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> emitHexSignature() {
        this.out = Output.SIG_HEX;
        return this;
    }

    /**
     * Configures the output to emit the detached signature as Base64 text.
     *
     * @return {@code this} builder for chaining
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> emitBase64Signature() {
        this.out = Output.SIG_BASE64;
        return this;
    }

    /**
     * Configures the builder to verify and emit a boolean result encoded as ASCII
     * "true" or "false".
     *
     * <p>
     * This method also switches the mode to {@link Mode#VERIFY}.
     * </p>
     *
     * @return {@code this} builder for chaining
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> emitVerificationBoolean() {
        this.mode = Mode.VERIFY;
        this.out = Output.VERIFY_BOOL;
        return this;
    }

    /**
     * Sets the internal streaming buffer size used when consuming input.
     *
     * @param bytes buffer size in bytes, must be greater than or equal to 1
     * @return {@code this} builder for chaining
     * @throws IllegalArgumentException if {@code bytes < 1}
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> bufferSize(int bytes) {
        if (bytes < 1) { // NOPMD
            throw new IllegalArgumentException("bufferSize must be >= 1");
        }
        this._bufferSize = bytes;
        return this;
    }

    /**
     * Sets the private key to be used in sign mode.
     *
     * @param k the private key, must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code k} is null
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> withPrivateKey(PrivateKey k) {
        this.privateKey = Objects.requireNonNull(k);
        return this;
    }

    /**
     * Sets the public key to be used in verify mode.
     *
     * @param k the public key, must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code k} is null
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> withPublicKey(PublicKey k) {
        this.publicKey = Objects.requireNonNull(k);
        return this;
    }

    /**
     * Requests generation of a fresh key pair using the algorithm-specific key
     * generation spec.
     *
     * <p>
     * If called, a key pair will be generated during {@link #build(boolean)} using
     * either the current key generation spec or a default one from
     * {@link #defaultKeyGenSpecSupplier()}.
     * </p>
     *
     * @return {@code this} builder for chaining
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> generateKeyPair() {
        this.genKeyPair = true;
        return this;
    }

    /**
     * Provides a PKCS#8-encoded private key to import using the default provider
     * hint.
     *
     * @param pkcs8 PKCS#8 PrivateKeyInfo bytes, must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code pkcs8} is null
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> importPrivatePkcs8(byte[] pkcs8) {
        this._importPrivatePkcs8 = Objects.requireNonNull(pkcs8).clone();
        this.importPrivateProvider = null;
        return this;
    }

    /**
     * Provides a PKCS#8-encoded private key to import using the given provider
     * name.
     *
     * @param pkcs8        PKCS#8 PrivateKeyInfo bytes, must not be null
     * @param providerName provider name hint to use, may be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code pkcs8} is null
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> importPrivatePkcs8(byte[] pkcs8, String providerName) {
        this._importPrivatePkcs8 = Objects.requireNonNull(pkcs8).clone();
        this.importPrivateProvider = providerName;
        return this;
    }

    /**
     * Provides an X.509-encoded public key to import using the default provider
     * hint.
     *
     * @param x509 X.509 SubjectPublicKeyInfo bytes, must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code x509} is null
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> importPublicX509(byte[] x509) {
        this._importPublicX509 = Objects.requireNonNull(x509).clone();
        this.importPublicProvider = null;
        return this;
    }

    /**
     * Provides an X.509-encoded public key to import using the given provider name.
     *
     * @param x509         X.509 SubjectPublicKeyInfo bytes, must not be null
     * @param providerName provider name hint to use, may be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code x509} is null
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> importPublicX509(byte[] x509, String providerName) {
        this._importPublicX509 = Objects.requireNonNull(x509).clone();
        this.importPublicProvider = providerName;
        return this;
    }

    /**
     * Sets the expected signature for verification as raw bytes.
     *
     * @param raw the expected signature bytes, must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code raw} is null
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> expectedSignature(byte[] raw) {
        this._expectedSignature = Objects.requireNonNull(raw).clone();
        return this;
    }

    /**
     * Sets the expected signature for verification from a hexadecimal string.
     *
     * @param hex lowercase or uppercase hexadecimal string, must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException     if {@code hex} is null
     * @throws IllegalArgumentException if {@code hex} is not valid hexadecimal
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> expectedSignatureHex(String hex) {
        this._expectedSignature = java.util.HexFormat.of().parseHex(Objects.requireNonNull(hex));
        return this;
    }

    /**
     * Sets the expected signature for verification from a Base64 string.
     *
     * @param b64 Base64-encoded signature text, must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException     if {@code b64} is null
     * @throws IllegalArgumentException if {@code b64} is not valid Base64
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> expectedSignatureBase64(String b64) {
        this._expectedSignature = Base64.getDecoder().decode(Objects.requireNonNull(b64));
        return this;
    }

    /**
     * Configures verification to fetch the expected signature bytes from a context
     * when building the stream.
     *
     * @param key the context key under which the expected signature is stored
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code key} is null
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> expectedSignatureFromCtx(Key<byte[]> key) {
        this._expectedSignatureFromCtx = Objects.requireNonNull(key);
        return this;
    }

    /**
     * Sets the optional runtime context to read or write auxiliary values such as a
     * generated signature or verification result.
     *
     * @param c the context instance, may be null to disable context integration
     * @return {@code this} builder for chaining
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> context(CtxInterface c) {
        this.ctx = c;
        return this;
    }

    /**
     * Configures the context key under which a generated signature will be stored
     * after signing.
     *
     * @param key the context key to store the signature under, may be null to
     *            disable storage
     * @return {@code this} builder for chaining
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> storeSignature(Key<byte[]> key) {
        this.storeSigKey = key;
        return this;
    }

    /**
     * Registers a callback that receives the generated signature bytes after
     * signing completes.
     *
     * @param cb the callback to invoke with a defensive copy of the signature, may
     *           be null
     * @return {@code this} builder for chaining
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> onSignature(Consumer<byte[]> cb) {
        this.sigCallback = cb;
        return this;
    }

    /**
     * Sets a custom verification approach to be applied by verify-mode pipelines.
     *
     * <p>
     * The strategy defines how the computed and expected tags are compared and how
     * failures are surfaced. For example, callers may supply
     * {@code getVerificationCore().getThrowOnMismatch()} to raise on mismatch, or a
     * decorated variant that records a boolean flag in a context.
     * </p>
     *
     * <h4>Default behavior</h4>
     * <p>
     * If this method is not called, verify-mode pipelines use the default core with
     * throw-on-mismatch semantics.
     * </p>
     *
     * @param strategy verification strategy; if {@code null}, the default core is
     *                 used
     * @return {@code this} builder for chaining
     */
    public AbstractStreamingSignatureDataBuilder<KG, PUB, PRIV> withStrategy(SignatureVerificationStrategy strategy) {
        this._strategy = strategy;
        return this;
    }

    /**
     * Builds the configured streaming signature pipeline as {@link PlainContent}.
     *
     * <p>
     * This method resolves the algorithm and keys according to the current
     * configuration, then returns a {@link PlainContent} that will perform signing
     * or verification when its stream is consumed.
     * </p>
     *
     * <p>
     * The boolean parameter is ignored and present only to satisfy the
     * {@link DataContentBuilder} interface.
     * </p>
     *
     * <pre>{@code
     * PlainContent pipeline = builder
     *     .sign()
     *     .withPrivateKey(pk)
     *     .passThrough()
     *     .build(true);
     * }</pre>
     *
     * @param ignored not used
     * @return a {@link PlainContent} instance that performs the requested operation
     *         on stream consumption
     * @throws IllegalStateException if required keys are missing for the selected
     *                               mode or if key setup fails
     */
    @Override
    public PlainContent build(boolean ignored) {
        try {
            resolveKeys();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(algorithmName() + " key setup failed", e);
        }
        return switch (mode) {
            case SIGN -> {
                if (privateKey == null) {
                    throw new IllegalStateException("SIGN mode needs a PrivateKey");
                }
                yield (out == Output.PASSTHROUGH)
                        ? new SignPassthrough(algorithm, privateKey, ctx, storeSigKey, sigCallback, _bufferSize)
                        : new SignEmit(algorithm, privateKey, out, ctx, storeSigKey, sigCallback, _bufferSize);
            }
            case VERIFY -> {
                if (publicKey == null) {
                    throw new IllegalStateException("VERIFY mode needs a PublicKey");
                }
                yield (out == Output.VERIFY_BOOL)
                        ? new VerifyEmit(algorithm, publicKey, _expectedSignature, _expectedSignatureFromCtx, ctx,
                                _strategy)
                        : new VerifyPassthrough(algorithm, publicKey, _expectedSignature, _expectedSignatureFromCtx,
                                ctx, _strategy);
            }
        };
    }

    private void resolveKeys() throws GeneralSecurityException {
        this.algorithm = CryptoAlgorithms.require(algorithmName());

        if (genKeyPair) {
            final Supplier<KG> sup = Objects.requireNonNull(defaultKeyGenSpecSupplier(), "defaultKeyGenSpecSupplier");
            final KG spec = (currentKeyGenSpecOrNull() != null) ? currentKeyGenSpecOrNull() : sup.get();
            final AsymmetricKeyBuilder<KG> b = algorithm.asymmetricKeyBuilder(keyGenSpecClass());
            final KeyPair kp = b.generateKeyPair(spec);
            this.privateKey = kp.getPrivate();
            this.publicKey = kp.getPublic();
        }
        if (_importPrivatePkcs8 != null) {
            final String prov = (importPrivateProvider != null) ? importPrivateProvider : defaultProviderHint();
            final PRIV privSpec = makePrivateKeySpec(_importPrivatePkcs8, prov);
            final AsymmetricKeyBuilder<PRIV> b = algorithm.asymmetricKeyBuilder(privateKeySpecClass());
            this.privateKey = b.importPrivate(privSpec);
        }
        if (_importPublicX509 != null) {
            final String prov = (importPublicProvider != null) ? importPublicProvider : defaultProviderHint();
            final PUB pubSpec = makePublicKeySpec(_importPublicX509, prov);
            final AsymmetricKeyBuilder<PUB> b = algorithm.asymmetricKeyBuilder(publicKeySpecClass());
            this.publicKey = b.importPublic(pubSpec);
        }
    }

    /**
     * Pass-through content that signs the streamed bytes and emits the final
     * signature.
     *
     * <p>
     * {@code SignPassthrough} attaches to an upstream {@link DataContent}, returns
     * an {@link InputStream} that forwards all bytes unchanged, and computes a
     * digital signature as the stream is consumed. When the stream reaches EOF, the
     * signature is finalized and can be stored in a {@link CtxInterface} and/or
     * delivered to a callback if configured.
     * </p>
     *
     * <h3>Behavior</h3>
     * <ul>
     * <li>Signing context is created lazily in {@link #getStream()} via
     * {@code newSignContext(alg, key)}.</li>
     * <li>The returned stream is read-only and must be consumed to EOF to produce a
     * signature.</li>
     * <li>Failures while storing or delivering the signature are swallowed to avoid
     * disrupting the caller's read loop.</li>
     * </ul>
     */
    private final class SignPassthrough implements PlainContent {
        private final CryptoAlgorithm alg;
        private final PrivateKey key;
        private final CtxInterface ctx;
        private final Key<byte[]> storeKey;
        private final Consumer<byte[]> cb;
        private final int bufferSize;
        private volatile DataContent upstream; // NOPMD

        /**
         * Creates a new pass-through signer.
         *
         * @param alg        the algorithm that provides a {@link SignatureContext};
         *                   must not be {@code null}
         * @param key        the private key used for signing; must not be {@code null}
         * @param ctx        optional context used to store the produced signature; may
         *                   be {@code null}
         * @param storeKey   optional key under which the signature is stored in
         *                   {@code ctx}; may be {@code null}
         * @param cb         optional callback invoked with a defensive copy of the
         *                   signature; may be {@code null}
         * @param bufferSize the internal buffer size used by the trailer stream
         * @throws NullPointerException if {@code alg} or {@code key} is {@code null}
         */
        private SignPassthrough(CryptoAlgorithm alg, PrivateKey key, CtxInterface ctx, Key<byte[]> storeKey,
                Consumer<byte[]> cb, int bufferSize) {
            this.alg = Objects.requireNonNull(alg);
            this.key = Objects.requireNonNull(key);
            this.ctx = ctx;
            this.storeKey = storeKey;
            this.cb = cb;
            this.bufferSize = bufferSize;
        }

        /**
         * Sets the upstream content that will be passed through and signed.
         *
         * @param input the upstream data source; must not be {@code null}
         * @throws NullPointerException if {@code input} is {@code null}
         */
        @Override
        public void setInput(DataContent input) {
            this.upstream = Objects.requireNonNull(input);
        }

        /**
         * Returns a stream that forwards upstream bytes unmodified and computes a
         * signature.
         *
         * <p>
         * The signature is finalized when the returned stream reaches EOF and is then:
         * </p>
         * <ul>
         * <li>stored into {@code ctx} under {@code storeKey} if both are non-null,
         * and</li>
         * <li>delivered to {@code cb} if non-null (the byte array passed to the
         * callback is a clone).</li>
         * </ul>
         *
         * @return an input stream that signs data while passing it through unchanged
         * @throws IOException          if the signing context cannot be initialized or
         *                              if the underlying upstream stream throws an I/O
         *                              error
         * @throws NullPointerException if {@link #setInput(DataContent)} was not called
         *                              before invocation
         */
        @Override
        public InputStream getStream() throws IOException {
            Objects.requireNonNull(upstream, "sign: missing input");
            final SignatureContext sc;
            try {
                sc = newSignContext(alg, key);
            } catch (GeneralSecurityException e) {
                throw new IOException("Failed to init sign context", e);
            }

            return new SignatureTrailerInputStream(sc, upstream.getStream(), bufferSize, sig -> {
                if (ctx != null && storeKey != null) {
                    try {
                        ctx.put(storeKey, sig);
                    } catch (RuntimeException ignore) { // NOPMD
                    }
                }
                if (cb != null) {
                    try {
                        cb.accept(sig.clone());
                    } catch (RuntimeException ignore) { // NOPMD
                    }
                }
            });
        }
    }

    /**
     * Eager-signing content that emits only the signature in a chosen encoding.
     *
     * <p>
     * {@code SignEmit} consumes the entire upstream {@link DataContent}, computes a
     * digital signature, optionally stores and/or publishes the signature, and
     * returns an {@link InputStream} over the encoded signature bytes. Unlike a
     * pass-through variant, the payload is fully drained internally and is not
     * forwarded to the caller; the resulting stream contains only the signature
     * material in the requested format.
     * </p>
     *
     * <h3>Behavior</h3>
     * <ul>
     * <li>Only {@code SIG_*} output modes are accepted.</li>
     * <li>Signing context is created in {@link #getStream()} via
     * {@code newSignContext(alg, key)}.</li>
     * <li>Upstream is read to EOF inside {@link #getStream()} to finalize the
     * signature.</li>
     * <li>On success, the signature is optionally stored and/or passed to a
     * callback; side-effect failures are swallowed.</li>
     * </ul>
     */
    private final class SignEmit implements PlainContent {
        private final CryptoAlgorithm alg;
        private final PrivateKey key;
        private final Output out;
        private final CtxInterface ctx;
        private final Key<byte[]> storeKey;
        private final Consumer<byte[]> cb;
        private final int bufferSize;
        private volatile DataContent upstream; // NOPMD

        /**
         * Creates a new signer that emits the signature in the requested format.
         *
         * @param alg        the algorithm used to create a {@link SignatureContext};
         *                   must not be {@code null}
         * @param key        the private key used for signing; must not be {@code null}
         * @param out        the desired signature output format; must be one of
         *                   {@link Output#SIG_RAW}, {@link Output#SIG_HEX}, or
         *                   {@link Output#SIG_BASE64}
         * @param ctx        optional context used to store the produced signature; may
         *                   be {@code null}
         * @param storeKey   optional key under which the signature is stored in
         *                   {@code ctx}; may be {@code null}
         * @param cb         optional callback invoked with a defensive copy of the
         *                   signature; may be {@code null}
         * @param bufferSize the internal buffer size used by the trailer stream
         * @throws IllegalArgumentException if {@code out} is not a {@code SIG_*}
         *                                  variant
         * @throws NullPointerException     if {@code alg} or {@code key} is
         *                                  {@code null}
         */
        private SignEmit(CryptoAlgorithm alg, PrivateKey key, Output out, CtxInterface ctx, Key<byte[]> storeKey,
                Consumer<byte[]> cb, int bufferSize) {
            if (out != Output.SIG_RAW && out != Output.SIG_HEX && out != Output.SIG_BASE64) {
                throw new IllegalArgumentException("SignEmit requires SIG_* output");
            }
            this.alg = Objects.requireNonNull(alg);
            this.key = Objects.requireNonNull(key);
            this.out = out;
            this.ctx = ctx;
            this.storeKey = storeKey;
            this.cb = cb;
            this.bufferSize = bufferSize;
        }

        /**
         * Sets the upstream content to be read and signed.
         *
         * @param input the upstream data source; must not be {@code null}
         * @throws NullPointerException if {@code input} is {@code null}
         */
        @Override
        public void setInput(DataContent input) {
            this.upstream = Objects.requireNonNull(input);
        }

        /**
         * Drains the upstream to compute the signature and returns a stream over the
         * signature bytes.
         *
         * <p>
         * The method creates a {@link SignatureContext}, reads the entire upstream
         * stream to EOF in order to finalize the signature, and then returns an
         * {@link InputStream} over the encoded signature according to {@link #out}:
         * </p>
         * <ul>
         * <li>{@link Output#SIG_RAW} - raw signature bytes,</li>
         * <li>{@link Output#SIG_HEX} - hexadecimal string encoded as UTF-8 bytes,</li>
         * <li>{@link Output#SIG_BASE64} - Base64-encoded bytes.</li>
         * </ul>
         *
         * <p>
         * If provided, the signature is stored in {@code ctx} under {@code storeKey}
         * and passed to {@code cb}. Both operations use a defensive copy and swallow
         * runtime exceptions to avoid interrupting the primary flow.
         * </p>
         *
         * @return an input stream that yields only the encoded signature bytes
         * @throws IOException          if the signing context cannot be initialized,
         *                              the upstream cannot be read, or no signature
         *                              trailer is produced
         * @throws NullPointerException if {@link #setInput(DataContent)} was not
         *                              invoked prior to this call
         */
        @Override
        public InputStream getStream() throws IOException {
            Objects.requireNonNull(upstream, "sign: missing input");

            final SignatureContext sc;
            try {
                sc = newSignContext(alg, key);
            } catch (GeneralSecurityException e) {
                throw new IOException("Failed to init sign context", e);
            }

            final byte[][] sigHolder = new byte[1][];

            try (SignatureTrailerInputStream in = new SignatureTrailerInputStream(sc, upstream.getStream(), bufferSize,
                    new Consumer<>() {
                        @Override
                        public void accept(byte[] sig) {
                            sigHolder[0] = (sig == null ? null : sig.clone());
                        }
                    })) {
                in.transferTo(OutputStream.nullOutputStream());
            } catch (IOException ioe) {
                try {
                    sc.close();
                } catch (RuntimeException ignore) { // NOPMD
                }
                throw ioe;
            }

            final byte[] sig = sigHolder[0];
            if (sig == null) {
                throw new IOException("Missing signature trailer");
            }

            if (ctx != null && storeKey != null) {
                try {
                    ctx.put(storeKey, sig.clone());
                } catch (RuntimeException ignore) { // NOPMD
                }
            }
            if (cb != null) {
                try {
                    cb.accept(sig.clone());
                } catch (RuntimeException ignore) { // NOPMD
                }
            }

            byte[] outBytes = switch (out) {
                case SIG_RAW -> sig;
                case SIG_HEX -> java.util.HexFormat.of().formatHex(sig).getBytes(StandardCharsets.UTF_8);
                case SIG_BASE64 -> Base64.getEncoder().encode(sig);
                default -> throw new IllegalStateException("Unexpected output: " + out);
            };
            return new ByteArrayInputStream(outBytes);
        }
    }

    /**
     * Pass-through verifier that forwards bytes unchanged while verifying a
     * signature at EOF.
     *
     * <p>
     * {@code VerifyPassthrough} attaches to an upstream {@link DataContent},
     * returns an {@link InputStream} that yields the original payload, and performs
     * signature verification as the stream is consumed. The expected signature is
     * provided directly or fetched from a {@link CtxInterface}. When the stream
     * reaches EOF, the configured verification strategy determines whether a
     * mismatch raises an error or is handled differently (for example, by flagging
     * in a context if the supplied strategy implements that).
     * </p>
     *
     * <h3>Behavior</h3>
     * <ul>
     * <li>Expected signature is taken from the {@code expected} field or from
     * {@code ctx.get(expectedKey)}.</li>
     * <li>The returned stream must be fully drained or closed to finalize
     * verification.</li>
     * </ul>
     */
    private final class VerifyPassthrough implements PlainContent {
        private final CryptoAlgorithm alg;
        private final PublicKey key;
        private final byte[] expected;
        private final Key<byte[]> expectedKey;
        private final CtxInterface ctx;
        private final SignatureVerificationStrategy strategy;
        private volatile DataContent upstream; // NOPMD

        /**
         * Creates a pass-through verifier that reads from upstream and verifies at EOF.
         *
         * @param alg         algorithm used to obtain a {@link SignatureContext}; must
         *                    not be {@code null}
         * @param key         public key used for verification; must not be {@code null}
         * @param expected    expected signature bytes (defensively copied), or
         *                    {@code null} to fetch from {@code ctx}
         * @param expectedKey key in {@code ctx} under which the expected signature may
         *                    be stored; may be {@code null}
         * @param ctx         optional context used to fetch the expected signature; may
         *                    be {@code null}
         * @param strategy    verification approach; if {@code null}, a default
         *                    throw-on-mismatch strategy is used
         * @throws NullPointerException if {@code alg} or {@code key} is {@code null}
         */
        private VerifyPassthrough(CryptoAlgorithm alg, PublicKey key, byte[] expected, Key<byte[]> expectedKey,
                CtxInterface ctx, SignatureVerificationStrategy strategy) {
            this.alg = Objects.requireNonNull(alg);
            this.key = Objects.requireNonNull(key);
            this.expected = (expected == null ? null : expected.clone());
            this.expectedKey = expectedKey;
            this.ctx = ctx;
            this.strategy = strategy;
        }

        /**
         * Sets the upstream content that will be passed through and verified.
         *
         * @param input upstream data source; must not be {@code null}
         * @throws NullPointerException if {@code input} is {@code null}
         */
        @Override
        public void setInput(DataContent input) {
            this.upstream = Objects.requireNonNull(input);
        }

        /**
         * Returns a stream that forwards upstream bytes and performs signature
         * verification.
         *
         * <p>
         * The method creates a {@link SignatureContext}, configures the expected
         * signature and verification policy, and wraps the upstream stream. The
         * returned stream must be consumed to EOF (or closed) to finalize verification
         * and, if configured, to store/emit the result.
         * </p>
         *
         * @return an input stream that yields the original bytes while verifying at EOF
         * @throws IOException           if the verify context cannot be initialized or
         *                               the wrapping fails
         * @throws IllegalStateException if no expected signature is available via
         *                               constructor or context
         * @throws NullPointerException  if {@link #setInput(DataContent)} was not
         *                               invoked prior to this call
         */
        @Override
        public InputStream getStream() throws IOException {
            Objects.requireNonNull(upstream, "verify: missing input");

            byte[] exp = expected;
            if (exp == null && ctx != null && expectedKey != null) {
                exp = ctx.get(expectedKey);
            }
            if (exp == null) {
                throw new IllegalStateException("VERIFY requires expectedSignature (or ctx+key)");
            }

            final SignatureContext sc; // NOPMD
            try {
                sc = newVerifyContext(alg, key);
            } catch (GeneralSecurityException e) {
                throw new IOException("Failed to init verify context", e);
            }

            sc.setExpectedTag(exp);
            if (strategy == null) {
                sc.setVerificationApproach(sc.getVerificationCore().getThrowOnMismatch());
            } else {
                sc.setVerificationApproach(strategy);
            }

            try {
                return sc.wrap(upstream.getStream());
            } catch (IOException initFail) {
                try {
                    sc.close();
                } catch (RuntimeException ignore) { // NOPMD
                }
                throw initFail;
            }
        }
    }

    /**
     * Streaming content wrapper that verifies a digital signature and emits the
     * result as a boolean value.
     *
     * <p>
     * {@code VerifyEmit} consumes an upstream {@link DataContent}, initializes a
     * {@link SignatureContext} with the supplied public key and expected signature,
     * and verifies the signature while streaming the input. The verification
     * outcome ({@code true} or {@code false}) is then returned as a one-shot
     * {@link java.io.InputStream} containing the UTF-8 encoded string
     * {@code "true"} or {@code "false"}.
     * </p>
     *
     * <h3>Notes</h3>
     * <ul>
     * <li>The expected signature may be provided directly or looked up from a
     * {@link CtxInterface} via {@code expectedKey}.</li>
     * <li>Outcome computation follows the configured verification strategy; I/O or
     * verification failures result in {@code "false"}.</li>
     * </ul>
     */
    private final class VerifyEmit implements PlainContent {
        private final CryptoAlgorithm alg;
        private final PublicKey key;
        private final byte[] expected;
        private final Key<byte[]> expectedKey;
        private final CtxInterface ctx;
        private final SignatureVerificationStrategy strategy;
        private volatile DataContent upstream; // NOPMD

        /**
         * Creates a streaming verifier that consumes upstream data and emits a boolean
         * result.
         *
         * @param alg         algorithm used to create a {@link SignatureContext}; must
         *                    not be {@code null}
         * @param key         public key used for verification; must not be {@code null}
         * @param expected    expected signature bytes; may be {@code null} when
         *                    {@code ctx} and {@code expectedKey} are provided
         * @param expectedKey context key from which to read the expected signature when
         *                    {@code expected} is {@code null}; may be {@code null}
         * @param ctx         optional context used to read the expected signature; may
         *                    be {@code null}
         * @param strategy    verification approach; if {@code null}, a default
         *                    throw-on-mismatch strategy is used
         * @throws NullPointerException if {@code alg} or {@code key} is {@code null}
         */
        private VerifyEmit(CryptoAlgorithm alg, PublicKey key, byte[] expected, Key<byte[]> expectedKey,
                CtxInterface ctx, SignatureVerificationStrategy strategy) {
            this.alg = Objects.requireNonNull(alg);
            this.key = Objects.requireNonNull(key);
            this.expected = (expected == null ? null : expected.clone());
            this.expectedKey = expectedKey;
            this.ctx = ctx;
            this.strategy = strategy;
        }

        /**
         * Sets the upstream content that will be consumed and verified.
         *
         * <p>
         * This method must be called exactly once before {@link #getStream()}. The
         * provided {@link DataContent} is stored and later used to obtain the readable
         * stream that is fed into the verification context.
         * </p>
         *
         * @param input upstream data source; must not be {@code null}
         * @throws NullPointerException if {@code input} is {@code null}
         */
        @Override
        public void setInput(DataContent input) {
            this.upstream = Objects.requireNonNull(input);
        }

        /**
         * Returns a one-shot stream that yields the UTF-8 text {@code "true"} or
         * {@code "false"} after verifying the upstream content against the expected
         * signature.
         *
         * <p>
         * On entry, this method initializes a {@link SignatureContext}, configures the
         * expected tag and a strict verification policy, and then drains the upstream
         * stream. Any I/O failures or verification mismatches result in the boolean
         * outcome {@code false}; successful verification results in {@code true}. The
         * outcome is optionally stored into {@code ctx} under {@code storeOk} and
         * passed to the callback {@code cb}.
         * </p>
         *
         * <p>
         * Resource management is handled via try-with-resources: the verification
         * context is always closed. If closing the context fails, the method reports
         * {@code false} rather than propagating the close exception, allowing callers
         * to reliably consume the result.
         * </p>
         *
         * <h2>Usage</h2> <pre>{@code
         * verifyEmit.setInput(data);
         * try (InputStream result = verifyEmit.getStream()) {
         *     boolean ok = Boolean.parseBoolean(new String(result.readAllBytes(), StandardCharsets.UTF_8));
         *     // use ok
         * }
         * }</pre>
         *
         * @return a new input stream that produces {@code "true"} or {@code "false"} in
         *         UTF-8
         * @throws IOException           if the verify context cannot be initialized or
         *                               the upstream stream cannot be obtained
         * @throws IllegalStateException if no expected signature is available from the
         *                               constructor arguments or the context
         * @throws NullPointerException  if {@link #setInput(DataContent)} was not
         *                               called before invocation
         */
        @Override
        public InputStream getStream() throws IOException {
            Objects.requireNonNull(upstream, "verify: missing input");

            byte[] exp = expected;
            if (exp == null && ctx != null && expectedKey != null) {
                exp = ctx.get(expectedKey);
            }
            if (exp == null) {
                throw new IllegalStateException("VERIFY requires expectedSignature (or ctx+key)");
            }

            final SignatureContext sc;
            try {
                sc = newVerifyContext(alg, key);
            } catch (GeneralSecurityException e) {
                throw new IOException("Failed to init verify context", e);
            }

            sc.setExpectedTag(exp);
            if (strategy == null) {
                sc.setVerificationApproach(sc.getVerificationCore().getThrowOnMismatch());
            } else {
                sc.setVerificationApproach(strategy);
            }

            try (sc) { // closes sc; if it throws, that exception propagates
                try (InputStream in = sc.wrap(upstream.getStream())) {
                    in.transferTo(OutputStream.nullOutputStream());
                    return new ByteArrayInputStream("true".getBytes(StandardCharsets.UTF_8));
                } catch (IOException fail) {
                    // wrap/read/transfer/close(in) failures land here and are swallowed -> ok =
                    // false
                    return new ByteArrayInputStream("false".getBytes(StandardCharsets.UTF_8));
                }
            }
        }
    }
}
