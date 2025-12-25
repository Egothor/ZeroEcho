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

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;
import java.util.function.Supplier;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.alg.slhdsa.SlhDsaKeyGenSpec;
import zeroecho.core.alg.slhdsa.SlhDsaPrivateKeySpec;
import zeroecho.core.alg.slhdsa.SlhDsaPublicKeySpec;
import zeroecho.core.alg.slhdsa.SlhDsaSignatureContext;
import zeroecho.core.context.SignatureContext;

/**
 * Streaming signature builder for SLH-DSA (FIPS 205).
 *
 * <p>
 * This builder integrates SLH-DSA with the reusable streaming pipeline provided
 * by {@link AbstractStreamingSignatureDataBuilder}. It supports signing or
 * verifying data while it flows through an {@link java.io.InputStream}, as well
 * as emitting detached signature artifacts in raw, hex or Base64 encodings.
 * </p>
 *
 * <p>
 * Key material may be provided directly, imported (X.509 / PKCS#8), or
 * generated on demand using an algorithm-specific {@link SlhDsaKeyGenSpec}.
 * </p>
 *
 * @since 1.0
 */
public final class SlhDsaDataContentBuilder
        extends AbstractStreamingSignatureDataBuilder<SlhDsaKeyGenSpec, SlhDsaPublicKeySpec, SlhDsaPrivateKeySpec> {

    private SlhDsaKeyGenSpec keyGenSpec;

    /**
     * Creates a new SLH-DSA streaming builder instance.
     *
     * @return new builder
     */
    public static SlhDsaDataContentBuilder builder() {
        return new SlhDsaDataContentBuilder();
    }

    /**
     * Sets a non-default key generation specification used when
     * {@link #generateKeyPair()} is requested.
     *
     * @param spec key generation spec; must not be {@code null}
     * @return {@code this} for chaining
     * @throws NullPointerException if {@code spec} is {@code null}
     */
    public SlhDsaDataContentBuilder withKeyGenSpec(SlhDsaKeyGenSpec spec) {
        this.keyGenSpec = Objects.requireNonNull(spec);
        return this;
    }

    @Override
    protected String algorithmName() {
        return "SLH-DSA";
    }

    @Override
    protected SignatureContext newSignContext(CryptoAlgorithm alg, PrivateKey key) throws GeneralSecurityException {
        return new SlhDsaSignatureContext(alg, key);
    }

    @Override
    protected SignatureContext newVerifyContext(CryptoAlgorithm alg, PublicKey key) throws GeneralSecurityException {
        return new SlhDsaSignatureContext(alg, key);
    }

    @Override
    protected Class<SlhDsaKeyGenSpec> keyGenSpecClass() {
        return SlhDsaKeyGenSpec.class;
    }

    @Override
    protected Class<SlhDsaPublicKeySpec> publicKeySpecClass() {
        return SlhDsaPublicKeySpec.class;
    }

    @Override
    protected Class<SlhDsaPrivateKeySpec> privateKeySpecClass() {
        return SlhDsaPrivateKeySpec.class;
    }

    @Override
    protected Supplier<SlhDsaKeyGenSpec> defaultKeyGenSpecSupplier() {
        return SlhDsaKeyGenSpec::defaultSpec;
    }

    @Override
    protected SlhDsaKeyGenSpec currentKeyGenSpecOrNull() {
        return keyGenSpec;
    }

    @Override
    protected SlhDsaPublicKeySpec makePublicKeySpec(byte[] x509, String providerHint) {
        return (providerHint == null) ? new SlhDsaPublicKeySpec(x509) : new SlhDsaPublicKeySpec(x509, providerHint);
    }

    @Override
    protected SlhDsaPrivateKeySpec makePrivateKeySpec(byte[] pkcs8, String providerHint) {
        return (providerHint == null) ? new SlhDsaPrivateKeySpec(pkcs8) : new SlhDsaPrivateKeySpec(pkcs8, providerHint);
    }

    @Override
    protected String defaultProviderHint() {
        return "BC";
    }

    // Optional: covariant fluent overrides for better chaining ergonomics.

    @Override
    public SlhDsaDataContentBuilder sign() {
        super.sign();
        return this;
    }

    @Override
    public SlhDsaDataContentBuilder verify() {
        super.verify();
        return this;
    }

    @Override
    public SlhDsaDataContentBuilder passThrough() {
        super.passThrough();
        return this;
    }

    @Override
    public SlhDsaDataContentBuilder emitRawSignature() {
        super.emitRawSignature();
        return this;
    }

    @Override
    public SlhDsaDataContentBuilder emitHexSignature() {
        super.emitHexSignature();
        return this;
    }

    @Override
    public SlhDsaDataContentBuilder emitBase64Signature() {
        super.emitBase64Signature();
        return this;
    }

    @Override
    public SlhDsaDataContentBuilder emitVerificationBoolean() {
        super.emitVerificationBoolean();
        return this;
    }

    @Override
    public SlhDsaDataContentBuilder bufferSize(int bytes) {
        super.bufferSize(bytes);
        return this;
    }

    @Override
    public SlhDsaDataContentBuilder withPrivateKey(PrivateKey k) {
        super.withPrivateKey(k);
        return this;
    }

    @Override
    public SlhDsaDataContentBuilder withPublicKey(PublicKey k) {
        super.withPublicKey(k);
        return this;
    }

    @Override
    public SlhDsaDataContentBuilder generateKeyPair() {
        super.generateKeyPair();
        return this;
    }

    @Override
    public SlhDsaDataContentBuilder importPrivatePkcs8(byte[] pkcs8) {
        super.importPrivatePkcs8(pkcs8);
        return this;
    }

    @Override
    public SlhDsaDataContentBuilder importPrivatePkcs8(byte[] pkcs8, String providerName) {
        super.importPrivatePkcs8(pkcs8, providerName);
        return this;
    }

    @Override
    public SlhDsaDataContentBuilder importPublicX509(byte[] x509) {
        super.importPublicX509(x509);
        return this;
    }

    @Override
    public SlhDsaDataContentBuilder importPublicX509(byte[] x509, String providerName) {
        super.importPublicX509(x509, providerName);
        return this;
    }

    @Override
    public SlhDsaDataContentBuilder expectedSignature(byte[] raw) {
        super.expectedSignature(raw);
        return this;
    }

    @Override
    public SlhDsaDataContentBuilder expectedSignatureHex(String hex) {
        super.expectedSignatureHex(hex);
        return this;
    }

    @Override
    public SlhDsaDataContentBuilder expectedSignatureBase64(String b64) {
        super.expectedSignatureBase64(b64);
        return this;
    }
}
