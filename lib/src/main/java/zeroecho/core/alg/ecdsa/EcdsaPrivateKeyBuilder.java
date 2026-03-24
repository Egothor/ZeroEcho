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
package zeroecho.core.alg.ecdsa;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.spi.AsymmetricKeyBuilder;

/**
 * <h2>ECDSA Private Key Builder</h2>
 *
 * Implementation of {@link AsymmetricKeyBuilder} for
 * {@link EcdsaPrivateKeySpec}. This builder is responsible for importing ECDSA
 * private keys from encoded representations.
 *
 * <h2>Supported operations</h2>
 * <ul>
 * <li>{@link #importPrivate(EcdsaPrivateKeySpec)} - construct a
 * {@link PrivateKey} instance from a PKCS#8 encoded key.</li>
 * <li>{@link #generateKeyPair(EcdsaPrivateKeySpec)} - unsupported; use
 * {@link EcdsaKeyGenBuilder} instead.</li>
 * <li>{@link #importPublic(EcdsaPrivateKeySpec)} - unsupported; use
 * {@link EcdsaPublicKeySpec} with {@link EcdsaPublicKeyBuilder} instead.</li>
 * </ul>
 *
 * <h2>Encoding</h2> The {@link EcdsaPrivateKeySpec} stores the private key in
 * PKCS#8 DER format. This builder delegates to a JCA {@link KeyFactory} for the
 * {@code "EC"} algorithm to reconstruct a usable {@link PrivateKey}.
 *
 * <h2>Usage</h2> Typically accessed indirectly through
 * {@link CryptoAlgorithms#privateKey(String, zeroecho.core.spec.AlgorithmKeySpec)}
 * or
 * {@link CryptoAlgorithm#importPrivate(zeroecho.core.spec.AlgorithmKeySpec)}.
 *
 * <pre>{@code
 * // Example: Import an ECDSA private key
 * byte[] pkcs8 = ...; // load PKCS#8 DER data
 * EcdsaPrivateKeySpec spec = new EcdsaPrivateKeySpec(pkcs8);
 * PrivateKey priv = new EcdsaPrivateKeyBuilder().importPrivate(spec);
 * }</pre>
 *
 * @since 1.0
 */
public final class EcdsaPrivateKeyBuilder implements AsymmetricKeyBuilder<EcdsaPrivateKeySpec> {
    /**
     * Unsupported operation for this builder.
     *
     * <p>
     * ECDSA key pair generation should be performed using
     * {@link EcdsaKeyGenBuilder}, not from a private key specification.
     * </p>
     *
     * @param spec unused private key specification
     * @return never returns normally
     * @throws UnsupportedOperationException always thrown
     */
    @Override
    public java.security.KeyPair generateKeyPair(EcdsaPrivateKeySpec spec) {
        throw new UnsupportedOperationException("Use EcdsaKeyGenBuilder for keypair generation.");
    }

    /**
     * Unsupported operation for this builder.
     *
     * <p>
     * Public key import should be performed using {@link EcdsaPublicKeySpec} with
     * {@link EcdsaPublicKeyBuilder}.
     * </p>
     *
     * @param spec unused private key specification
     * @return never returns normally
     * @throws UnsupportedOperationException always thrown
     */
    @Override
    public java.security.PublicKey importPublic(EcdsaPrivateKeySpec spec) {
        throw new UnsupportedOperationException("Use EcdsaPublicKeySpec with EcdsaPublicKeyBuilder.");
    }

    /**
     * Imports a private key from a PKCS#8 encoded specification.
     *
     * <p>
     * Uses a JCA {@link KeyFactory} instance for {@code "EC"} to parse the given
     * {@link EcdsaPrivateKeySpec} and construct a {@link PrivateKey}.
     * </p>
     *
     * @param spec private key specification containing PKCS#8 DER encoding
     * @return reconstructed {@link PrivateKey} instance
     * @throws GeneralSecurityException if the encoding is invalid or the key cannot
     *                                  be reconstructed
     */
    @Override
    public PrivateKey importPrivate(EcdsaPrivateKeySpec spec) throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(spec.encoded()));
    }
}
