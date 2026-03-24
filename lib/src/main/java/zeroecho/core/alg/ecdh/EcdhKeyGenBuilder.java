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
package zeroecho.core.alg.ecdh;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

import zeroecho.core.alg.ecdsa.EcdsaPrivateKeyBuilder;
import zeroecho.core.alg.ecdsa.EcdsaPrivateKeySpec;
import zeroecho.core.alg.ecdsa.EcdsaPublicKeyBuilder;
import zeroecho.core.alg.ecdsa.EcdsaPublicKeySpec;
import zeroecho.core.spi.AsymmetricKeyBuilder;

/**
 * <h2>ECDH Key Pair Generator</h2>
 *
 * Implementation of {@link AsymmetricKeyBuilder} for elliptic curve
 * Diffie-Hellman (ECDH) key pairs.
 *
 * <p>
 * This builder generates fresh EC key pairs suitable for ECDH key agreement. It
 * accepts an {@link EcdhCurveSpec} that defines the named curve to use (e.g.,
 * {@code P-256}, {@code P-384}, {@code P-521}).
 * </p>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Generate a key pair on P-256
 * KeyPair kp = new EcdhKeyGenBuilder().generateKeyPair(EcdhCurveSpec.P256);
 * }</pre>
 *
 * <p>
 * Import of existing keys is not supported by this builder. Instead, use
 * {@link EcdsaPublicKeyBuilder} and {@link EcdsaPrivateKeyBuilder} together
 * with {@code EcdsaPublicKeySpec} or {@code EcdsaPrivateKeySpec} when importing
 * encoded elliptic curve keys.
 * </p>
 *
 * @since 1.0
 */
public final class EcdhKeyGenBuilder implements AsymmetricKeyBuilder<EcdhCurveSpec> {
    /**
     * Generates a new elliptic curve key pair for use in ECDH key agreement.
     *
     * <p>
     * The curve is determined from the provided {@link EcdhCurveSpec}. Internally,
     * a standard JCA {@link KeyPairGenerator} for {@code "EC"} is initialized with
     * the corresponding {@link ECGenParameterSpec}.
     * </p>
     *
     * @param spec curve specification selecting the named curve
     * @return a freshly generated {@link KeyPair} suitable for ECDH
     * @throws GeneralSecurityException if the curve is not supported by the
     *                                  underlying JCA provider or if key generation
     *                                  fails
     */
    @Override
    public KeyPair generateKeyPair(EcdhCurveSpec spec) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(spec.curveName()));
        return kpg.generateKeyPair();
    }

    /**
     * Unsupported operation for this builder.
     *
     * <p>
     * Importing existing ECDH public keys should be performed via
     * {@link EcdsaPublicKeyBuilder} with an {@link EcdsaPublicKeySpec}. This method
     * will always throw an {@link UnsupportedOperationException}.
     * </p>
     *
     * @param spec ignored
     * @return never returns normally
     * @throws UnsupportedOperationException always
     */
    @Override
    public java.security.PublicKey importPublic(EcdhCurveSpec spec) {
        throw new UnsupportedOperationException("Use EcdhPublicKeySpec with EcdsaPublicKeyBuilder.");
    }

    /**
     * Unsupported operation for this builder.
     *
     * <p>
     * Importing existing ECDH private keys should be performed via
     * {@link EcdsaPrivateKeyBuilder} with an {@link EcdsaPrivateKeySpec}. This
     * method will always throw an {@link UnsupportedOperationException}.
     * </p>
     *
     * @param spec ignored
     * @return never returns normally
     * @throws UnsupportedOperationException always
     */
    @Override
    public java.security.PrivateKey importPrivate(EcdhCurveSpec spec) {
        throw new UnsupportedOperationException("Use EcdhPrivateKeySpec with EcdsaPrivateKeyBuilder.");
    }
}
