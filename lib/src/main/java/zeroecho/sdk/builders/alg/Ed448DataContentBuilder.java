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
import zeroecho.core.alg.ed448.Ed448KeyGenSpec;
import zeroecho.core.alg.ed448.Ed448PrivateKeySpec;
import zeroecho.core.alg.ed448.Ed448PublicKeySpec;
import zeroecho.core.alg.ed448.Ed448SignatureContext;
import zeroecho.core.context.SignatureContext;

/**
 * Builder for constructing streaming Ed448 signature and verification
 * {@link zeroecho.sdk.content.api.DataContent} pipelines.
 *
 * <p>
 * {@code Ed448DataContentBuilder} is a thin adapter around
 * {@link AbstractStreamingSignatureDataBuilder} that binds the generic
 * streaming signature framework to the Ed448 algorithm. It supports both
 * signing and verification flows, with key material provided via
 * {@link Ed448KeyGenSpec}, {@link Ed448PublicKeySpec}, and
 * {@link Ed448PrivateKeySpec}.
 * </p>
 *
 * <h2>Usage example</h2> <pre>{@code
 * // Create a builder for signing
 * Ed448DataContentBuilder builder = Ed448DataContentBuilder.builder()
 *     .sign()
 *     .generateKeyPair()
 *     .emitBase64Signature();
 *
 * // Build a content pipeline
 * PlainContent content = builder.build(true);
 * content.setInput(originalContent);
 *
 * try (InputStream in = content.getStream()) {
 *     byte[] signature = in.readAllBytes();
 * }
 * }</pre>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Uses {@link Ed448SignatureContext} for both signing and
 * verification.</li>
 * <li>Key generation is parameterized by {@link Ed448KeyGenSpec}, but Ed448
 * exposes no runtime tunables; the default is always used.</li>
 * <li>Public/private key imports are supported via X.509 and PKCS#8 wrappers
 * respectively.</li>
 * <li>No provider hints are necessary; the JDK default is assumed.</li>
 * </ul>
 *
 * @see Ed448SignatureContext
 * @see Ed448KeyGenSpec
 * @see Ed448PublicKeySpec
 * @see Ed448PrivateKeySpec
 * @since 1.0
 */
public final class Ed448DataContentBuilder
        extends AbstractStreamingSignatureDataBuilder<Ed448KeyGenSpec, Ed448PublicKeySpec, Ed448PrivateKeySpec> {

    private static final Supplier<Ed448KeyGenSpec> DEFAULT_GEN = Ed448KeyGenSpec::defaultSpec;

    /**
     * Creates a new builder instance for constructing Ed448 streaming signature
     * pipelines.
     *
     * <h4>Example</h4> <pre>{@code
     * Ed448DataContentBuilder b = Ed448DataContentBuilder.builder();
     * }</pre>
     *
     * @return a new {@code Ed448DataContentBuilder}
     */
    public static Ed448DataContentBuilder builder() {
        return new Ed448DataContentBuilder();
    }

    /**
     * Returns the canonical algorithm name used to resolve an implementation from
     * {@link zeroecho.core.CryptoAlgorithms}.
     *
     * @return the string {@code "Ed448"}
     */
    @Override
    protected String algorithmName() {
        return "Ed448";
    }

    /**
     * Creates a signing {@link SignatureContext} for Ed448 using the provided
     * algorithm instance and private key.
     *
     * <p>
     * The returned context is configured to accept streaming updates and to produce
     * a detached signature tag at end-of-stream.
     * </p>
     *
     * <h4>Example</h4> <pre>{@code
     * SignatureContext sc = newSignContext(alg, privateKey);
     * try (InputStream in = sc.wrap(upstream)) {
     *     in.transferTo(OutputStream.nullOutputStream());
     * }
     * }</pre>
     *
     * @param alg the resolved algorithm instance
     * @param key the private key used for signing
     * @return a new signature context in sign mode
     * @throws GeneralSecurityException if the context cannot be created for the
     *                                  given key or algorithm
     */
    @Override
    protected SignatureContext newSignContext(CryptoAlgorithm alg, PrivateKey key) throws GeneralSecurityException {
        return new Ed448SignatureContext(alg, key);
    }

    /**
     * Creates a verification {@link SignatureContext} for Ed448 using the provided
     * algorithm instance and public key.
     *
     * <p>
     * The returned context is configured to accept streaming updates and to
     * validate the expected detached signature tag at end-of-stream.
     * </p>
     *
     * @param alg the resolved algorithm instance
     * @param key the public key used for verification
     * @return a new signature context in verify mode
     * @throws GeneralSecurityException if the context cannot be created for the
     *                                  given key or algorithm
     */
    @Override
    protected SignatureContext newVerifyContext(CryptoAlgorithm alg, PublicKey key) throws GeneralSecurityException {
        return new Ed448SignatureContext(alg, key);
    }

    /**
     * Returns the key generation specification class used by this builder.
     *
     * @return {@code Ed448KeyGenSpec.class}
     */
    @Override
    protected Class<Ed448KeyGenSpec> keyGenSpecClass() {
        return Ed448KeyGenSpec.class;
    }

    /**
     * Returns the public key import specification class used by this builder.
     *
     * @return {@code Ed448PublicKeySpec.class}
     */
    @Override
    protected Class<Ed448PublicKeySpec> publicKeySpecClass() {
        return Ed448PublicKeySpec.class;
    }

    /**
     * Returns the private key import specification class used by this builder.
     *
     * @return {@code Ed448PrivateKeySpec.class}
     */
    @Override
    protected Class<Ed448PrivateKeySpec> privateKeySpecClass() {
        return Ed448PrivateKeySpec.class;
    }

    /**
     * Supplies the default key generation specification for Ed448.
     *
     * @return a supplier returning {@link Ed448KeyGenSpec#defaultSpec()}
     */
    @Override
    protected Supplier<Ed448KeyGenSpec> defaultKeyGenSpecSupplier() {
        return DEFAULT_GEN;
    }

    /**
     * Returns the currently configured key generation specification or null to
     * indicate that the default should be used.
     *
     * <p>
     * Ed448 has no tunables in this builder, so this method returns {@code null}.
     * </p>
     *
     * @return {@code null}
     */
    @Override
    protected Ed448KeyGenSpec currentKeyGenSpecOrNull() {
        return null; // no options
    }

    /**
     * Builds a public key import specification from X.509-encoded
     * SubjectPublicKeyInfo bytes.
     *
     * <h4>Example</h4> <pre>{@code
     * Ed448PublicKeySpec spec = makePublicKeySpec(spkiBytes, null);
     * }</pre>
     *
     * @param x509            X.509 public key bytes (SubjectPublicKeyInfo)
     * @param ignoredProvider optional provider hint, ignored by this implementation
     * @return a new {@link Ed448PublicKeySpec} wrapping the provided bytes
     */
    @Override
    protected Ed448PublicKeySpec makePublicKeySpec(byte[] x509, String ignoredProvider) {
        return new Ed448PublicKeySpec(x509);
    }

    /**
     * Builds a private key import specification from PKCS#8-encoded PrivateKeyInfo
     * bytes.
     *
     * <h4>Example</h4> <pre>{@code
     * Ed448PrivateKeySpec spec = makePrivateKeySpec(pkcs8Bytes, null);
     * }</pre>
     *
     * @param pkcs8           PKCS#8 private key bytes (PrivateKeyInfo)
     * @param ignoredProvider optional provider hint, ignored by this implementation
     * @return a new {@link Ed448PrivateKeySpec} wrapping the provided bytes
     */
    @Override
    protected Ed448PrivateKeySpec makePrivateKeySpec(byte[] pkcs8, String ignoredProvider) {
        return new Ed448PrivateKeySpec(pkcs8);
    }

    /**
     * Returns the default provider hint used for key imports when none is
     * explicitly supplied.
     *
     * <p>
     * This builder relies on the JDK default provider for Ed448.
     * </p>
     *
     * @return {@code null} to indicate no provider preference
     */
    @Override
    protected String defaultProviderHint() {
        return null; // JDK default
    }
}
