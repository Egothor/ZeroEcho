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
package zeroecho.core.alg.sphincsplus;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;

import zeroecho.core.spi.AsymmetricKeyBuilder;

/**
 * Builder for importing SPHINCS+ private keys from encoded specifications.
 *
 * <p>
 * {@code SphincsPlusPrivateKeyBuilder} integrates with the JCA
 * {@link KeyFactory} to parse PKCS#8-encoded SPHINCS+ private keys. Unlike
 * {@link SphincsPlusKeyGenBuilder}, this builder does not generate new key
 * pairs but focuses solely on importing private key material.
 * </p>
 *
 * <h2>Supported flows</h2>
 * <ul>
 * <li>{@link #importPrivate(SphincsPlusPrivateKeySpec)}: imports a SPHINCS+
 * private key from its encoded PKCS#8 representation.</li>
 * <li>{@link #generateKeyPair(SphincsPlusPrivateKeySpec)}: not supported.</li>
 * <li>{@link #importPublic(SphincsPlusPrivateKeySpec)}: not supported; use
 * {@link SphincsPlusPublicKeySpec} and its builder instead.</li>
 * </ul>
 *
 * <h2>Example</h2> <pre>{@code
 * // Assuming bytes contain a PKCS#8-encoded SPHINCS+ private key:
 * SphincsPlusPrivateKeySpec spec =
 *     new SphincsPlusPrivateKeySpec("BCPQC", encodedBytes);
 *
 * PrivateKey priv =
 *     new SphincsPlusPrivateKeyBuilder().importPrivate(spec);
 * }</pre>
 *
 * @since 1.0
 */
public final class SphincsPlusPrivateKeyBuilder implements AsymmetricKeyBuilder<SphincsPlusPrivateKeySpec> {
    /**
     * Not supported for this builder.
     *
     * <p>
     * Key pair generation requires a parameter set and is handled by
     * {@link SphincsPlusKeyGenBuilder}. This method always throws.
     * </p>
     *
     * @param spec ignored
     * @return never returns normally
     * @throws UnsupportedOperationException always
     */
    @Override
    public KeyPair generateKeyPair(SphincsPlusPrivateKeySpec spec) {
        throw new UnsupportedOperationException("Generation not supported by this spec.");
    }

    /**
     * Not supported for this builder.
     *
     * <p>
     * Public key import should be performed via {@link SphincsPlusPublicKeySpec}
     * and its associated builder.
     * </p>
     *
     * @param spec ignored
     * @return never returns normally
     * @throws UnsupportedOperationException always
     */
    @Override
    public PublicKey importPublic(SphincsPlusPrivateKeySpec spec) {
        throw new UnsupportedOperationException("Use SphincsPlusPublicKeySpec for public keys.");
    }

    /**
     * Imports a SPHINCS+ private key from PKCS#8 encoding.
     *
     * <p>
     * The method uses {@link KeyFactory} with algorithm {@code "SPHINCSPlus"} and
     * the provider specified in the {@code spec}. If no provider name is given, the
     * default provider resolution is used.
     * </p>
     *
     * @param spec private key specification containing PKCS#8-encoded key material
     *             and optional provider name
     * @return the imported SPHINCS+ {@link PrivateKey}
     * @throws NullPointerException     if {@code spec} or its encoded bytes are
     *                                  null
     * @throws GeneralSecurityException if the key factory cannot be initialized or
     *                                  the encoded key is invalid
     */
    @Override
    public PrivateKey importPrivate(SphincsPlusPrivateKeySpec spec) throws GeneralSecurityException {
        KeyFactory kf = (spec.providerName() == null) ? KeyFactory.getInstance("SPHINCSPlus")
                : KeyFactory.getInstance("SPHINCSPlus", spec.providerName());
        return kf.generatePrivate(new PKCS8EncodedKeySpec(spec.encoded()));
    }
}
