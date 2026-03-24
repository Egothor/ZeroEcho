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
import zeroecho.core.alg.mldsa.MldsaKeyGenSpec;
import zeroecho.core.alg.mldsa.MldsaPrivateKeySpec;
import zeroecho.core.alg.mldsa.MldsaPublicKeySpec;
import zeroecho.core.alg.mldsa.MldsaSignatureContext;
import zeroecho.core.context.SignatureContext;

/**
 * Streaming signature builder for ML-DSA (FIPS 204).
 *
 * <p>
 * This builder integrates ML-DSA with the reusable streaming pipeline provided
 * by {@link AbstractStreamingSignatureDataBuilder}. It supports signing or
 * verifying data while it flows through an {@link java.io.InputStream}, as well
 * as emitting detached signature artifacts in raw, hex or Base64 encodings.
 * </p>
 *
 * <p>
 * Key material may be provided directly, imported (X.509 / PKCS#8), or
 * generated on demand using an algorithm-specific {@link MldsaKeyGenSpec}.
 * </p>
 *
 * @since 1.0
 */
public final class MldsaDataContentBuilder
        extends AbstractStreamingSignatureDataBuilder<MldsaKeyGenSpec, MldsaPublicKeySpec, MldsaPrivateKeySpec> {

    private MldsaKeyGenSpec keyGenSpec;

    /**
     * Creates a new ML-DSA streaming builder instance.
     *
     * @return new builder
     */
    public static MldsaDataContentBuilder builder() {
        return new MldsaDataContentBuilder();
    }

    /**
     * Sets a non-default key generation specification used when
     * {@link #generateKeyPair()} is requested.
     *
     * @param spec key generation spec; must not be {@code null}
     * @return {@code this} for chaining
     * @throws NullPointerException if {@code spec} is {@code null}
     */
    public MldsaDataContentBuilder withKeyGenSpec(MldsaKeyGenSpec spec) {
        this.keyGenSpec = Objects.requireNonNull(spec);
        return this;
    }

    @Override
    protected String algorithmName() {
        return "ML-DSA";
    }

    @Override
    protected SignatureContext newSignContext(CryptoAlgorithm alg, PrivateKey key) throws GeneralSecurityException {
        return new MldsaSignatureContext(alg, key);
    }

    @Override
    protected SignatureContext newVerifyContext(CryptoAlgorithm alg, PublicKey key) throws GeneralSecurityException {
        return new MldsaSignatureContext(alg, key);
    }

    @Override
    protected Class<MldsaKeyGenSpec> keyGenSpecClass() {
        return MldsaKeyGenSpec.class;
    }

    @Override
    protected Class<MldsaPublicKeySpec> publicKeySpecClass() {
        return MldsaPublicKeySpec.class;
    }

    @Override
    protected Class<MldsaPrivateKeySpec> privateKeySpecClass() {
        return MldsaPrivateKeySpec.class;
    }

    @Override
    protected Supplier<MldsaKeyGenSpec> defaultKeyGenSpecSupplier() {
        return MldsaKeyGenSpec::defaultSpec;
    }

    @Override
    protected MldsaKeyGenSpec currentKeyGenSpecOrNull() {
        return keyGenSpec;
    }

    @Override
    protected MldsaPublicKeySpec makePublicKeySpec(byte[] x509, String providerHint) {
        return (providerHint == null) ? new MldsaPublicKeySpec(x509) : new MldsaPublicKeySpec(x509, providerHint);
    }

    @Override
    protected MldsaPrivateKeySpec makePrivateKeySpec(byte[] pkcs8, String providerHint) {
        return (providerHint == null) ? new MldsaPrivateKeySpec(pkcs8) : new MldsaPrivateKeySpec(pkcs8, providerHint);
    }

    @Override
    protected String defaultProviderHint() {
        return "BC";
    }

    // Optional: covariant fluent overrides for better chaining ergonomics.

    @Override
    public MldsaDataContentBuilder sign() {
        super.sign();
        return this;
    }

    @Override
    public MldsaDataContentBuilder verify() {
        super.verify();
        return this;
    }

    @Override
    public MldsaDataContentBuilder passThrough() {
        super.passThrough();
        return this;
    }

    @Override
    public MldsaDataContentBuilder emitRawSignature() {
        super.emitRawSignature();
        return this;
    }

    @Override
    public MldsaDataContentBuilder emitHexSignature() {
        super.emitHexSignature();
        return this;
    }

    @Override
    public MldsaDataContentBuilder emitBase64Signature() {
        super.emitBase64Signature();
        return this;
    }

    @Override
    public MldsaDataContentBuilder emitVerificationBoolean() {
        super.emitVerificationBoolean();
        return this;
    }

    @Override
    public MldsaDataContentBuilder bufferSize(int bytes) {
        super.bufferSize(bytes);
        return this;
    }

    @Override
    public MldsaDataContentBuilder withPrivateKey(PrivateKey k) {
        super.withPrivateKey(k);
        return this;
    }

    @Override
    public MldsaDataContentBuilder withPublicKey(PublicKey k) {
        super.withPublicKey(k);
        return this;
    }

    @Override
    public MldsaDataContentBuilder generateKeyPair() {
        super.generateKeyPair();
        return this;
    }

    @Override
    public MldsaDataContentBuilder importPrivatePkcs8(byte[] pkcs8) {
        super.importPrivatePkcs8(pkcs8);
        return this;
    }

    @Override
    public MldsaDataContentBuilder importPrivatePkcs8(byte[] pkcs8, String providerName) {
        super.importPrivatePkcs8(pkcs8, providerName);
        return this;
    }

    @Override
    public MldsaDataContentBuilder importPublicX509(byte[] x509) {
        super.importPublicX509(x509);
        return this;
    }

    @Override
    public MldsaDataContentBuilder importPublicX509(byte[] x509, String providerName) {
        super.importPublicX509(x509, providerName);
        return this;
    }

    @Override
    public MldsaDataContentBuilder expectedSignature(byte[] raw) {
        super.expectedSignature(raw);
        return this;
    }

    @Override
    public MldsaDataContentBuilder expectedSignatureHex(String hex) {
        super.expectedSignatureHex(hex);
        return this;
    }

    @Override
    public MldsaDataContentBuilder expectedSignatureBase64(String b64) {
        super.expectedSignatureBase64(b64);
        return this;
    }
}
