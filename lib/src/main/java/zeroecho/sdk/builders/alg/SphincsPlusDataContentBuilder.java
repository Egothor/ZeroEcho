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
import zeroecho.core.alg.sphincsplus.SphincsPlusKeyGenSpec;
import zeroecho.core.alg.sphincsplus.SphincsPlusPrivateKeySpec;
import zeroecho.core.alg.sphincsplus.SphincsPlusPublicKeySpec;
import zeroecho.core.alg.sphincsplus.SphincsPlusSignatureContext;
import zeroecho.core.context.SignatureContext;

/**
 * Builder for streaming signature operations using the SPHINCS+ post-quantum
 * signature scheme.
 *
 * <p>
 * This builder follows the {@link AbstractStreamingSignatureDataBuilder}
 * pattern and provides configuration options to generate keys, import keys, and
 * perform signing or verification in a streaming pipeline. SPHINCS+ is a
 * hash-based, stateless signature scheme designed for post-quantum security,
 * standardized by NIST PQC Round 3.
 * </p>
 *
 * <h2>Key management</h2>
 * <ul>
 * <li>Keys can be generated using a custom {@link SphincsPlusKeyGenSpec}
 * supplied via {@link #withKeyGenSpec(SphincsPlusKeyGenSpec)}, or with the
 * algorithm's default specification.</li>
 * <li>Public and private keys may be imported from encoded formats
 * ({@code X.509} and {@code PKCS#8}, respectively).</li>
 * <li>A provider hint may optionally be given. If not provided, the builder
 * will prefer the provider specified in {@link SphincsPlusKeyGenSpec}, or fall
 * back to {@link #defaultProviderHint()}.</li>
 * </ul>
 *
 * <h2>Contexts</h2>
 * <ul>
 * <li>{@link #newSignContext(CryptoAlgorithm, java.security.PrivateKey)}
 * produces a {@link SphincsPlusSignatureContext} in sign mode.</li>
 * <li>{@link #newVerifyContext(CryptoAlgorithm, java.security.PublicKey)}
 * produces a {@link SphincsPlusSignatureContext} in verify mode.</li>
 * <li>Contexts are bound to the {@link CryptoAlgorithm} instance returned by
 * {@link CryptoAlgorithms#require(String)} with id {@code "SPHINCS+"}.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2> Instances of this builder are not thread-safe. Each
 * builder should be configured and built within a single thread or with
 * external synchronization.
 *
 * <h2>Example</h2> <pre>{@code
 * // Signing with SPHINCS+
 * SphincsPlusDataContentBuilder builder = SphincsPlusDataContentBuilder.builder()
 *      .sign()
 *      .withKeyGenSpec(SphincsPlusKeyGenSpec.sphincsSha256128s());
 *
 * PlainContent content = builder.build(true);
 * content.setInput(new FileContent("document.txt"));
 * try (InputStream in = content.getStream()) {
 *     // Consume input to trigger signing
 * }
 * }</pre>
 *
 * @see SphincsPlusKeyGenSpec
 * @see SphincsPlusPublicKeySpec
 * @see SphincsPlusPrivateKeySpec
 * @see SphincsPlusSignatureContext
 * @since 1.0
 */
public final class SphincsPlusDataContentBuilder extends
        AbstractStreamingSignatureDataBuilder<SphincsPlusKeyGenSpec, SphincsPlusPublicKeySpec, SphincsPlusPrivateKeySpec> {
    /**
     * Optional custom key generation specification to be used when
     * {@link #generateKeyPair()} is selected in the superclass API.
     */
    private SphincsPlusKeyGenSpec keyGenSpec; // optional custom spec

    /**
     * Creates a new builder for constructing SPHINCS+ streaming signature
     * pipelines.
     *
     * <h4>Example</h4> <pre>{@code
     * SphincsPlusDataContentBuilder b = SphincsPlusDataContentBuilder.builder();
     * }</pre>
     *
     * @return a new {@code SphincsPlusDataContentBuilder} instance
     */
    public static SphincsPlusDataContentBuilder builder() {
        return new SphincsPlusDataContentBuilder();
    }

    /**
     * Sets a custom key generation specification to be used for SPHINCS+ key pair
     * generation.
     *
     * <p>
     * If no specification is provided, the builder falls back to the supplier
     * returned by {@link #defaultKeyGenSpecSupplier()}.
     * </p>
     *
     * @param spec the SPHINCS+ key generation specification; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code spec} is null
     */
    public SphincsPlusDataContentBuilder withKeyGenSpec(SphincsPlusKeyGenSpec spec) {
        this.keyGenSpec = Objects.requireNonNull(spec);
        return this;
    }

    /**
     * Returns the algorithm identifier used to resolve the implementation from
     * {@link zeroecho.core.CryptoAlgorithms}.
     *
     * @return the string {@code "SPHINCS+"}
     */
    @Override
    protected String algorithmName() {
        return "SPHINCS+";
    }

    /**
     * Creates a signing {@link zeroecho.core.context.SignatureContext} for SPHINCS+
     * using the provided algorithm instance and private key.
     *
     * @param alg the resolved algorithm instance used to create the context
     * @param key the private key for signing
     * @return a new {@link SphincsPlusSignatureContext} configured for signing
     * @throws GeneralSecurityException if the context cannot be created for the
     *                                  given key or algorithm
     */
    @Override
    protected SignatureContext newSignContext(CryptoAlgorithm alg, PrivateKey key) throws GeneralSecurityException {
        return new SphincsPlusSignatureContext(alg, key);
    }

    /**
     * Creates a verification {@link zeroecho.core.context.SignatureContext} for
     * SPHINCS+ using the provided algorithm instance and public key.
     *
     * @param alg the resolved algorithm instance used to create the context
     * @param key the public key for verification
     * @return a new {@link SphincsPlusSignatureContext} configured for verification
     * @throws GeneralSecurityException if the context cannot be created for the
     *                                  given key or algorithm
     */
    @Override
    protected SignatureContext newVerifyContext(CryptoAlgorithm alg, PublicKey key) throws GeneralSecurityException {
        return new SphincsPlusSignatureContext(alg, key);
    }

    /**
     * Returns the key generation specification class used by this builder.
     *
     * @return {@code SphincsPlusKeyGenSpec.class}
     */
    @Override
    protected Class<SphincsPlusKeyGenSpec> keyGenSpecClass() {
        return SphincsPlusKeyGenSpec.class;
    }

    /**
     * Returns the public key import specification class used by this builder.
     *
     * @return {@code SphincsPlusPublicKeySpec.class}
     */
    @Override
    protected Class<SphincsPlusPublicKeySpec> publicKeySpecClass() {
        return SphincsPlusPublicKeySpec.class;
    }

    /**
     * Returns the private key import specification class used by this builder.
     *
     * @return {@code SphincsPlusPrivateKeySpec.class}
     */
    @Override
    protected Class<SphincsPlusPrivateKeySpec> privateKeySpecClass() {
        return SphincsPlusPrivateKeySpec.class;
    }

    /**
     * Supplies a default key generation specification for SPHINCS+.
     *
     * @return a supplier returning {@link SphincsPlusKeyGenSpec#defaultSpec()}
     */
    @Override
    protected Supplier<SphincsPlusKeyGenSpec> defaultKeyGenSpecSupplier() {
        return SphincsPlusKeyGenSpec::defaultSpec;
    }

    /**
     * Returns the currently configured key generation specification or null to
     * indicate that the default should be used.
     *
     * @return the active {@link SphincsPlusKeyGenSpec} or {@code null} if none has
     *         been set
     */
    @Override
    protected SphincsPlusKeyGenSpec currentKeyGenSpecOrNull() {
        return keyGenSpec;
    }

    /**
     * Builds a public key import specification from X.509-encoded
     * SubjectPublicKeyInfo bytes and an optional provider hint.
     *
     * <p>
     * Provider selection follows this precedence:
     * <ol>
     * <li>Use {@code providerHint} if non-null.</li>
     * <li>Else, if a custom key generation spec is present, use
     * {@link SphincsPlusKeyGenSpec#providerName()}.</li>
     * <li>Else, use {@link #defaultProviderHint()}.</li>
     * </ol>
     *
     * @param x509         the X.509 public key bytes
     * @param providerHint an optional provider name hint; may be null
     * @return a new {@link SphincsPlusPublicKeySpec} wrapping the provided bytes
     *         and provider choice
     */
    @Override
    protected SphincsPlusPublicKeySpec makePublicKeySpec(byte[] x509, String providerHint) {
        String p = providerHint != null ? providerHint
                : keyGenSpec != null ? keyGenSpec.providerName() : defaultProviderHint();
        return new SphincsPlusPublicKeySpec(x509, p);
    }

    /**
     * Builds a private key import specification from PKCS#8-encoded PrivateKeyInfo
     * bytes and an optional provider hint.
     *
     * <p>
     * Provider selection follows this precedence:
     * <ol>
     * <li>Use {@code providerHint} if non-null.</li>
     * <li>Else, if a custom key generation spec is present, use
     * {@link SphincsPlusKeyGenSpec#providerName()}.</li>
     * <li>Else, use {@link #defaultProviderHint()}.</li>
     * </ol>
     *
     * @param pkcs8        the PKCS#8 private key bytes
     * @param providerHint an optional provider name hint; may be null
     * @return a new {@link SphincsPlusPrivateKeySpec} wrapping the provided bytes
     *         and provider choice
     */
    @Override
    protected SphincsPlusPrivateKeySpec makePrivateKeySpec(byte[] pkcs8, String providerHint) {
        String p = providerHint != null ? providerHint
                : keyGenSpec != null ? keyGenSpec.providerName() : defaultProviderHint();
        return new SphincsPlusPrivateKeySpec(pkcs8, p);
    }

    /**
     * Returns the default provider hint to use when importing SPHINCS+ keys if none
     * is explicitly specified.
     *
     * @return the default provider hint string, typically {@code "BCPQC"}
     */
    @Override
    protected String defaultProviderHint() {
        return "BCPQC";
    }
}
