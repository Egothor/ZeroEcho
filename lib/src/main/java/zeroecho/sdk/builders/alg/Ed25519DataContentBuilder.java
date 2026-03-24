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
import java.util.function.Supplier;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.alg.ed25519.Ed25519KeyGenSpec;
import zeroecho.core.alg.ed25519.Ed25519PrivateKeySpec;
import zeroecho.core.alg.ed25519.Ed25519PublicKeySpec;
import zeroecho.core.alg.ed25519.Ed25519SignatureContext;
import zeroecho.core.context.SignatureContext;

/**
 * Ed25519DataContentBuilder builds streaming Ed25519 signature pipelines that
 * sign or verify as an InputStream is consumed.
 *
 * <h2>Overview</h2> This builder specializes
 * {@link AbstractStreamingSignatureDataBuilder} for the Ed25519 algorithm. It
 * constructs {@link zeroecho.sdk.content.api.PlainContent} that either passes
 * the original bytes through while computing or checking a detached signature,
 * or emits the signature or verification result directly, depending on the
 * configuration provided by the fluent API defined in the superclass.
 *
 * <h2>Typical usage</h2> <pre>{@code
 * // Sign while passing the original bytes through:
 * PlainContent signed = Ed25519DataContentBuilder.builder()
 *     .sign()
 *     .withPrivateKey(privateKey)
 *     .passThrough()
 *     .build(true);
 *
 * // Emit a Base64 detached signature:
 * PlainContent sigOut = Ed25519DataContentBuilder.builder()
 *     .sign()
 *     .withPrivateKey(privateKey)
 *     .emitBase64Signature()
 *     .build(true);
 *
 * // Verify against an expected signature while passing data through:
 * PlainContent verified = Ed25519DataContentBuilder.builder()
 *     .verify()
 *     .withPublicKey(publicKey)
 *     .expectedSignature(rawSig)
 *     .passThrough()
 *     .build(true);
 * }</pre>
 *
 * <h2>Key handling</h2> Ed25519 has no tunable parameters for key generation in
 * this builder. A default generation supplier is provided, and imports from
 * X.509 (public) and PKCS#8 (private) encodings are supported.
 *
 * <h2>Thread-safety</h2> Instances are mutable and not thread-safe. Configure
 * and use each builder instance from a single thread.
 *
 * @see AbstractStreamingSignatureDataBuilder
 * @see zeroecho.core.CryptoAlgorithms
 * @see zeroecho.core.context.SignatureContext
 */
public final class Ed25519DataContentBuilder
        extends AbstractStreamingSignatureDataBuilder<Ed25519KeyGenSpec, Ed25519PublicKeySpec, Ed25519PrivateKeySpec> {

    private static final Supplier<Ed25519KeyGenSpec> DEFAULT_GEN = Ed25519KeyGenSpec::defaultSpec;

    /**
     * Creates a new builder instance for constructing Ed25519 streaming signature
     * pipelines.
     *
     * <h4>Example</h4> <pre>{@code
     * Ed25519DataContentBuilder b = Ed25519DataContentBuilder.builder();
     * }</pre>
     *
     * @return a new {@code Ed25519DataContentBuilder}
     */
    public static Ed25519DataContentBuilder builder() {
        return new Ed25519DataContentBuilder();
    }

    /**
     * Returns the canonical algorithm name used to resolve an implementation from
     * {@link zeroecho.core.CryptoAlgorithms}.
     *
     * @return the string {@code "Ed25519"}
     */
    @Override
    protected String algorithmName() {
        return "Ed25519";
    }

    /**
     * Creates a signing {@link SignatureContext} for Ed25519 using the provided
     * algorithm instance and private key.
     *
     * @param alg the resolved algorithm instance used to create the context
     * @param key the private key for signing
     * @return a new {@link SignatureContext} configured for Ed25519 signing
     * @throws GeneralSecurityException if the context cannot be created for the
     *                                  given key or algorithm
     */
    @Override
    protected SignatureContext newSignContext(final CryptoAlgorithm alg, final PrivateKey key)
            throws GeneralSecurityException {
        return new Ed25519SignatureContext(alg, key);
    }

    /**
     * Creates a verification {@link SignatureContext} for Ed25519 using the
     * provided algorithm instance and public key.
     *
     * @param alg the resolved algorithm instance used to create the context
     * @param key the public key for verification
     * @return a new {@link SignatureContext} configured for Ed25519 verification
     * @throws GeneralSecurityException if the context cannot be created for the
     *                                  given key or algorithm
     */
    @Override
    protected SignatureContext newVerifyContext(final CryptoAlgorithm alg, final PublicKey key)
            throws GeneralSecurityException {
        return new Ed25519SignatureContext(alg, key);
    }

    /**
     * Returns the key generation specification class used by this builder.
     *
     * @return {@code Ed25519KeyGenSpec.class}
     */
    @Override
    protected Class<Ed25519KeyGenSpec> keyGenSpecClass() {
        return Ed25519KeyGenSpec.class;
    }

    /**
     * Returns the public key import specification class used by this builder.
     *
     * @return {@code Ed25519PublicKeySpec.class}
     */
    @Override
    protected Class<Ed25519PublicKeySpec> publicKeySpecClass() {
        return Ed25519PublicKeySpec.class;
    }

    /**
     * Returns the private key import specification class used by this builder.
     *
     * @return {@code Ed25519PrivateKeySpec.class}
     */
    @Override
    protected Class<Ed25519PrivateKeySpec> privateKeySpecClass() {
        return Ed25519PrivateKeySpec.class;
    }

    /**
     * Supplies a default key generation specification for Ed25519.
     *
     * @return a supplier returning {@link Ed25519KeyGenSpec#defaultSpec()}
     */
    @Override
    protected Supplier<Ed25519KeyGenSpec> defaultKeyGenSpecSupplier() {
        return DEFAULT_GEN;
    }

    /**
     * Returns the currently configured key generation specification or null to
     * indicate the default should be used.
     *
     * <p>
     * Ed25519 has no tunables in this builder, so this method returns {@code null}.
     * </p>
     *
     * @return {@code null}
     */
    @Override
    protected Ed25519KeyGenSpec currentKeyGenSpecOrNull() {
        return null; // no tunables for Ed25519
    }

    /**
     * Builds a public key import specification from X.509-encoded
     * SubjectPublicKeyInfo bytes.
     *
     * @param x509            the X.509 public key bytes
     * @param ignoredProvider an optional provider hint, ignored by this
     *                        implementation
     * @return a new {@link Ed25519PublicKeySpec} wrapping the provided bytes
     */
    @Override
    protected Ed25519PublicKeySpec makePublicKeySpec(final byte[] x509, final String ignoredProvider) {
        return new Ed25519PublicKeySpec(x509);
    }

    /**
     * Builds a private key import specification from PKCS#8-encoded PrivateKeyInfo
     * bytes.
     *
     * @param pkcs8           the PKCS#8 private key bytes
     * @param ignoredProvider an optional provider hint, ignored by this
     *                        implementation
     * @return a new {@link Ed25519PrivateKeySpec} wrapping the provided bytes
     */
    @Override
    protected Ed25519PrivateKeySpec makePrivateKeySpec(final byte[] pkcs8, final String ignoredProvider) {
        return new Ed25519PrivateKeySpec(pkcs8);
    }

    /**
     * Returns the default provider hint used for key imports when none is
     * explicitly supplied.
     *
     * <p>
     * This builder relies on the JDK default provider for Ed25519.
     * </p>
     *
     * @return {@code null} to indicate no provider preference
     */
    @Override
    protected String defaultProviderHint() {
        return null; // use JDK default provider
    }
}
